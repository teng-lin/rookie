// Assert detailed partition identity and header isolation through the Node API.

import { writeFile } from "node:fs/promises";
import process from "node:process";

import * as rookieCookies from "../../bindings/node/index.js";

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
  ["rookie_chips", 2],
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

function exactlyTwo(name) {
  const records = byName.get(name) || [];
  if (records.length !== 2) {
    throw new Error(`expected exactly two colliding ${name} identities, got ${records.length}`);
  }
  return records;
}

const top = exactlyTwo("rookie_top");
const chips = exactlyTwo("rookie_chips");
if (engine === "chromium") {
  if (top.some(({ context }) => context.topFrameSiteKey != null && context.topFrameSiteKey !== "")) {
    throw new Error("first-party top cookie became partitioned");
  }
  const labels = new Set();
  for (const record of chips) {
    const key = record.context.topFrameSiteKey;
    const label = ["a", "c"].find((candidate) =>
      String(key).includes(`rookie-${candidate}.test`),
    );
    if (!label || labels.has(label)) {
      throw new Error(`unexpected Chromium partition key ${key}`);
    }
    labels.add(label);
    if (record.cookie.value !== `partition-${label}`) {
      throw new Error(`Chromium partition ${label} carried ${record.cookie.value}`);
    }
    if (record.context.hasCrossSiteAncestor !== true) {
      throw new Error("CHIPS row lost its cross-site ancestor bit");
    }
    if (record.context.sourcePort !== sourcePort) {
      throw new Error(`CHIPS source port was ${record.context.sourcePort}`);
    }
    if (record.context.sourceScheme == null) {
      throw new Error("CHIPS source scheme was not observed");
    }
    if (record.context.isPersistent !== true) {
      throw new Error("CHIPS persistence bit was not true");
    }
  }
} else {
  const dfpi = exactlyTwo("rookie_dfpi");
  for (const records of [chips, dfpi]) {
    const labels = new Set();
    for (const record of records) {
      const label = ["a", "c"].find((candidate) =>
        String(record.context.partitionKey).includes(`rookie-${candidate}.test`),
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
        throw new Error(`${record.cookie.name} lacks partitioned originAttributes`);
      }
      if (![null, 0].includes(record.context.userContextId)) {
        throw new Error(`${record.cookie.name} unexpectedly entered a container`);
      }
      if (![null, 0].includes(record.context.privateBrowsingId)) {
        throw new Error(`${record.cookie.name} unexpectedly entered private browsing`);
      }
      const expected = record.cookie.name === "rookie_chips" ? `partition-${label}` : `dfpi-${label}`;
      if (record.cookie.value !== expected) {
        throw new Error(`${record.cookie.name} partition ${label} carried ${record.cookie.value}`);
      }
    }
  }
}

const matchingContext = {
  url: `${thirdOrigin}/echo`,
  topLevelSite: topOrigin,
  resource: "subresource",
  method: "safe",
};
const matching = snapshot.header(matchingContext);
const other = snapshot.header({
  ...matchingContext,
  topLevelSite: otherTopOrigin,
});
if (!matching.includes("rookie_chips=partition-a")) {
  throw new Error(`matching context omitted CHIPS cookie: ${matching}`);
}
if (matching.includes("rookie_chips=partition-c")) {
  throw new Error(`top A received top C CHIPS cookie: ${matching}`);
}
if (!other.includes("rookie_chips=partition-c") || other.includes("rookie_chips=partition-a")) {
  throw new Error(`top C selected the wrong CHIPS cookie: ${other}`);
}
if (engine === "firefox") {
  if (!matching.includes("rookie_dfpi=dfpi-a") || matching.includes("rookie_dfpi=dfpi-c")) {
    throw new Error(`matching context omitted dFPI cookie: ${matching}`);
  }
  if (!other.includes("rookie_dfpi=dfpi-c") || other.includes("rookie_dfpi=dfpi-a")) {
    throw new Error(`other context selected the wrong dFPI cookie: ${other}`);
  }
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
  if (error.code !== "incomplete_send_context") throw error;
  missingSelector = error.code;
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
