// Assert detailed partition identity and header isolation through the Node API.

import { readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

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
  nestedOrigin,
  output,
] = process.argv.slice(2);

if (
  !["chromium", "firefox"].includes(engine) ||
  !database ||
  !topOrigin ||
  !otherTopOrigin ||
  !thirdOrigin ||
  !sourcePortArg ||
  !nestedOrigin
) {
  console.error(
    "usage: node assert_partitioned_context.mjs <chromium|firefox> <db> <browser-id-or-dash> <top-origin> <other-top-origin> <third-origin> <source-port> <nested-origin> [output]",
  );
  process.exit(2);
}

const inventory = JSON.parse(
  await readFile(
    join(
      dirname(fileURLToPath(import.meta.url)),
      "partition_context_inventory.json",
    ),
    "utf8",
  ),
).engines[engine];
if (!inventory) {
  throw new Error(`partition_context_inventory.json has no ${engine} entry`);
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
const expectedCounts = new Map(Object.entries(inventory.raw_rows_by_name));
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
  // The manifest carries the send contexts, so this is the one place the
  // runner's idea of the nested origin and the oracle's can be compared.
  const nested = rawManifest.expected_send_views.find(
    (view) => view.name === "nested_derived",
  ).context.url;
  if (!String(nested).startsWith(`${nestedOrigin}/`)) {
    throw new Error(
      `manifest nested context ${nested} is not on ${nestedOrigin}`,
    );
  }
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
let missingRequired;
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
  // The tokens, not just the code: `required` is what a caller reads to know
  // which selector it has to obtain before retrying.
  missingRequired = error.required;
}
if (rawManifest) {
  const expected = rawManifest.expected_missing_selector;
  if (
    missingSelector !== expected.code ||
    JSON.stringify(missingRequired ?? []) !== JSON.stringify(expected.required)
  ) {
    throw new Error(
      `missing selector named ${missingSelector}/${JSON.stringify(missingRequired)}, expected ${expected.code}/${JSON.stringify(expected.required)}`,
    );
  }
}

// The two A-site rows share a name, host, and path; only the ancestor bit can
// separate them, so the binding losing that field is invisible anywhere else.
const ancestors = byName.get("rookie_ancestor") || [];
const ancestorValues = ancestors.map(({ cookie }) => cookie.value).sort();
if (
  JSON.stringify(ancestorValues) !==
  JSON.stringify(["ancestor-cross_site", "ancestor-same_site"])
) {
  throw new Error(
    `the two ancestor-chain rows did not survive as distinct values: ${JSON.stringify(ancestorValues)}`,
  );
}
for (const record of ancestors) {
  const isCross = record.cookie.value === "ancestor-cross_site";
  if (engine === "chromium") {
    if (record.context.hasCrossSiteAncestor !== isCross) {
      throw new Error(
        `${record.cookie.value} carried hasCrossSiteAncestor=${record.context.hasCrossSiteAncestor}`,
      );
    }
  } else if (String(record.context.partitionKey ?? "").endsWith(",f)") !== isCross) {
    throw new Error(
      `${record.cookie.value} carried partitionKey ${record.context.partitionKey}`,
    );
  }
}

function toSendContext(context) {
  const camel = (key) =>
    key.replace(/_([a-z])/g, (_match, letter) => letter.toUpperCase());
  return Object.fromEntries(
    Object.entries(context).map(([key, value]) => [camel(key), value]),
  );
}

function omissionCount(omitted, reason) {
  const camel = reason.replace(/_([a-z])/g, (_match, letter) =>
    letter.toUpperCase(),
  );
  const value = omitted[camel];
  if (!Number.isInteger(value)) {
    throw new Error(`send view omission ${reason} was ${value}`);
  }
  return value;
}

const sendViews = {};
if (rawManifest) {
  const crossSite = rawManifest.expected_send_views.find(
    (view) => view.name === "top_cross_site",
  );
  if ((crossSite.expected_omitted_min.same_site ?? 0) < 1) {
    throw new Error(
      "the explicit cross-site context must have a SameSite=Lax row to omit",
    );
  }
  for (const view of rawManifest.expected_send_views) {
    const actual = snapshot.sendView(toSendContext(view.context));
    const records = actual.cookies.filter(({ cookie }) =>
      cookie.name.startsWith("rookie_"),
    );
    verifyCookieRecords(
      rawManifestPath,
      "detailed",
      records,
      `Node ${engine} send view`,
      view.name,
    );
    const rendered = tokens(actual.header);
    if (JSON.stringify(rendered) !== JSON.stringify([...view.header_tokens].sort())) {
      throw new Error(
        `send view ${view.name} rendered ${JSON.stringify(rendered)}, expected ${JSON.stringify([...view.header_tokens].sort())}`,
      );
    }
    for (const [reason, minimum] of Object.entries(view.expected_omitted_min)) {
      const counted = omissionCount(actual.omitted, reason);
      if (counted < minimum) {
        throw new Error(
          `send view ${view.name} counted ${counted} ${reason} omissions, expected at least ${minimum}`,
        );
      }
    }
    sendViews[view.name] = rendered;
  }
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
  sendViews,
};
const encoded = `${JSON.stringify(result, null, 2)}\n`;
if (output) {
  await writeFile(output, encoded, { encoding: "utf8", flag: "wx" });
} else {
  process.stdout.write(encoded);
}
