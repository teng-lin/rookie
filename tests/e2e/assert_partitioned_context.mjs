// Assert detailed partition identity and header isolation through the Node API.

import { readFile, writeFile } from "node:fs/promises";
import process from "node:process";

import * as rookieCookies from "../../bindings/node/index.js";
import { verifyCookieRecords } from "./cookie_manifest.mjs";

const [
  engine,
  database,
  browserId,
  topOrigin,
  otherTopOrigin,
  thirdOrigin,
  sourcePortArg,
  output,
] = process.argv.slice(2);

if (
  !["chromium", "firefox"].includes(engine) ||
  !database ||
  !topOrigin ||
  !otherTopOrigin ||
  !thirdOrigin ||
  !sourcePortArg
) {
  console.error(
    "usage: node assert_partitioned_context.mjs <chromium|firefox> <db> <browser-id-or-dash> <top-origin> <other-top-origin> <third-origin> <source-port> [output]",
  );
  process.exit(2);
}

const sourcePort = Number(sourcePortArg);
if (!Number.isSafeInteger(sourcePort) || sourcePort <= 0) {
  throw new Error(`invalid source port ${sourcePortArg}`);
}

function schemefulSite(origin) {
  const parsed = new URL(origin);
  const labels = parsed.hostname.split(".");
  if (labels.length !== 3 || !["top", "other"].includes(labels[0])) {
    throw new Error(`unexpected controlled top-level origin ${origin}`);
  }
  return `${parsed.protocol}//${labels.slice(1).join(".")}`;
}

const options = { path: database };
if (engine === "chromium") options.browserId = browserId;
const snapshot = await rookieCookies.fromPath(options);
const detailed = snapshot.detailedCookies.filter(({ cookie }) =>
  cookie.name.startsWith("rookie_"),
);

const byName = new Map();
for (const record of detailed) {
  const values = byName.get(record.cookie.name) || [];
  values.push(record);
  byName.set(record.cookie.name, values);
}
const expectedCounts = new Map([
  ["rookie_top", 2],
  ["rookie_chips", 3],
]);
if (engine === "firefox") expectedCounts.set("rookie_dfpi", 2);
if (
  byName.size !== expectedCounts.size ||
  [...expectedCounts].some(
    ([name, count]) => (byName.get(name) || []).length !== count,
  )
) {
  throw new Error(
    `context corpus mismatch: expected ${JSON.stringify(Object.fromEntries(expectedCounts))}, got ${JSON.stringify(Object.fromEntries([...byName].map(([name, records]) => [name, records.length])))}`,
  );
}
const rawManifestPath = process.env.ROOKIE_E2E_CONTEXT_MANIFEST;
const rawManifest = rawManifestPath
  ? JSON.parse(await readFile(rawManifestPath, "utf8"))
  : null;
if (rawManifestPath) {
  verifyCookieRecords(
    rawManifestPath,
    "detailed",
    detailed,
    `Node ${engine} raw context`,
  );
}

function exactlyTwo(name) {
  const records = byName.get(name) || [];
  if (records.length !== 2) {
    throw new Error(
      `expected exactly two colliding ${name} identities, got ${records.length}`,
    );
  }
  return records;
}

const top = exactlyTwo("rookie_top");
const chips = byName.get("rookie_chips");
if (engine === "chromium") {
  if (
    top.some(
      ({ context }) =>
        context.topFrameSiteKey != null && context.topFrameSiteKey !== "",
    )
  ) {
    throw new Error("first-party top cookie became partitioned");
  }
  const unpartitioned = chips.filter(
    ({ context }) =>
      context.topFrameSiteKey == null || context.topFrameSiteKey === "",
  );
  if (
    unpartitioned.length !== 1 ||
    unpartitioned[0].cookie.value !== "unpartitioned"
  ) {
    throw new Error(
      "Chromium lost the unpartitioned cookie sharing the CHIPS flat identity",
    );
  }
  const labels = new Set();
  for (const record of chips) {
    const key = record.context.topFrameSiteKey;
    if (key == null || key === "") continue;
    const label = ["a", "c"].find((candidate) =>
      String(key).includes(`rookie-${candidate}.test`),
    );
    if (!label || labels.has(label)) {
      throw new Error(`unexpected Chromium partition key ${key}`);
    }
    labels.add(label);
    if (record.cookie.value !== `partition-${label}`) {
      throw new Error(
        `Chromium partition ${label} carried ${record.cookie.value}`,
      );
    }
    if (record.context.hasCrossSiteAncestor !== true) {
      throw new Error("CHIPS row lost its cross-site ancestor bit");
    }
    if (record.context.sourcePort !== sourcePort) {
      throw new Error(`CHIPS source port was ${record.context.sourcePort}`);
    }
    if (record.context.sourceScheme !== 2) {
      throw new Error("CHIPS HTTPS source scheme was not 2");
    }
    if (record.context.isPersistent !== true) {
      throw new Error("CHIPS persistence bit was not true");
    }
  }
} else {
  const dfpi = exactlyTwo("rookie_dfpi");
  const unpartitioned = chips.filter(
    ({ context }) =>
      context.partitionKey == null || context.partitionKey === "",
  );
  if (
    unpartitioned.length !== 1 ||
    unpartitioned[0].cookie.value !== "unpartitioned"
  ) {
    throw new Error(
      "Firefox lost the unpartitioned cookie sharing the partitioned flat identity",
    );
  }
  for (const records of [chips, dfpi]) {
    const labels = new Set();
    for (const record of records) {
      if (
        record.cookie.name === "rookie_chips" &&
        (record.context.partitionKey == null ||
          record.context.partitionKey === "")
      ) {
        continue;
      }
      const label = ["a", "c"].find((candidate) =>
        String(record.context.partitionKey).includes(
          `rookie-${candidate}.test`,
        ),
      );
      if (!label || labels.has(label)) {
        throw new Error(
          `${record.cookie.name} has unexpected partition key ${record.context.partitionKey}`,
        );
      }
      labels.add(label);
      if (
        typeof record.context.originAttributes !== "string" ||
        !record.context.originAttributes.includes("partitionKey=")
      ) {
        throw new Error(
          `${record.cookie.name} lacks partitioned originAttributes`,
        );
      }
      if (![null, 0].includes(record.context.userContextId)) {
        throw new Error(
          `${record.cookie.name} unexpectedly entered a container`,
        );
      }
      if (![null, 0].includes(record.context.privateBrowsingId)) {
        throw new Error(
          `${record.cookie.name} unexpectedly entered private browsing`,
        );
      }
      const expected =
        record.cookie.name === "rookie_chips"
          ? `partition-${label}`
          : `dfpi-${label}`;
      if (record.cookie.value !== expected) {
        throw new Error(
          `${record.cookie.name} partition ${label} carried ${record.cookie.value}`,
        );
      }
    }
  }
}

const matchingContext = {
  url: `${thirdOrigin}/echo`,
  topLevelSite: schemefulSite(topOrigin),
  resource: "subresource",
  method: "safe",
};
const matching = snapshot.header(matchingContext);
const other = snapshot.header({
  ...matchingContext,
  topLevelSite: schemefulSite(otherTopOrigin),
});
const tokens = (header) =>
  header
    .split(";")
    .map((token) => token.trim())
    .filter(Boolean)
    .sort();
let expectedMatching = [
  "rookie_chips=partition-a",
  "rookie_chips=unpartitioned",
];
let expectedOther = ["rookie_chips=partition-c", "rookie_chips=unpartitioned"];
if (engine === "firefox") {
  expectedMatching.push("rookie_dfpi=dfpi-a");
  expectedOther.push("rookie_dfpi=dfpi-c");
}
if (rawManifest) {
  expectedMatching = rawManifest.expected_headers.matching;
  expectedOther = rawManifest.expected_headers.other_top_level_site;
}
if (
  JSON.stringify(tokens(matching)) !==
  JSON.stringify([...expectedMatching].sort())
) {
  throw new Error(
    `matching header set mismatch: expected ${JSON.stringify([...expectedMatching].sort())}, got ${JSON.stringify(tokens(matching))}`,
  );
}
if (
  JSON.stringify(tokens(other)) !== JSON.stringify([...expectedOther].sort())
) {
  throw new Error(
    `other header set mismatch: expected ${JSON.stringify([...expectedOther].sort())}, got ${JSON.stringify(tokens(other))}`,
  );
}

let missingSelector;
try {
  snapshot.header({
    url: `${thirdOrigin}/echo`,
    resource: "subresource",
    method: "safe",
  });
  throw new Error("partitioned snapshot accepted an incomplete context");
} catch (error) {
  if (error.rookieCode !== "incomplete_send_context") throw error;
  missingSelector = error.rookieCode;
}

const result = {
  engine,
  detailed: detailed.sort((left, right) =>
    JSON.stringify(left).localeCompare(JSON.stringify(right)),
  ),
  headers: {
    matching,
    otherTopLevelSite: other,
    missingSelector,
  },
};
const encoded = `${JSON.stringify(result, null, 2)}\n`;
if (output) {
  await writeFile(output, encoded, { encoding: "utf8", flag: "wx" });
} else {
  process.stdout.write(encoded);
}
