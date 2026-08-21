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

function exactlyOne(name) {
  const records = byName.get(name) || [];
  if (records.length !== 1) {
    throw new Error(`expected exactly one ${name}, got ${records.length}`);
  }
  return records[0];
}

const top = exactlyOne("rookie_top");
const chips = exactlyOne("rookie_chips");
if (engine === "chromium") {
  if (top.context.topFrameSiteKey != null && top.context.topFrameSiteKey !== "") {
    throw new Error("first-party top cookie became partitioned");
  }
  if (
    typeof chips.context.topFrameSiteKey !== "string" ||
    !chips.context.topFrameSiteKey.includes("rookie-a.test")
  ) {
    throw new Error(
      `unexpected Chromium partition key ${chips.context.topFrameSiteKey}`,
    );
  }
  if (chips.context.hasCrossSiteAncestor !== true) {
    throw new Error("CHIPS row lost its cross-site ancestor bit");
  }
  if (chips.context.sourcePort !== sourcePort) {
    throw new Error(`CHIPS source port was ${chips.context.sourcePort}`);
  }
  if (chips.context.sourceScheme == null) {
    throw new Error("CHIPS source scheme was not observed");
  }
  if (chips.context.isPersistent !== true) {
    throw new Error("CHIPS persistence bit was not true");
  }
} else {
  const dfpi = exactlyOne("rookie_dfpi");
  for (const record of [chips, dfpi]) {
    if (
      typeof record.context.originAttributes !== "string" ||
      !record.context.originAttributes.includes("partitionKey=")
    ) {
      throw new Error(`${record.cookie.name} lacks partitioned originAttributes`);
    }
    if (
      typeof record.context.partitionKey !== "string" ||
      !record.context.partitionKey.includes("rookie-a.test")
    ) {
      throw new Error(
        `${record.cookie.name} has unexpected partition key ${record.context.partitionKey}`,
      );
    }
    if (![null, 0].includes(record.context.userContextId)) {
      throw new Error(`${record.cookie.name} unexpectedly entered a container`);
    }
    if (![null, 0].includes(record.context.privateBrowsingId)) {
      throw new Error(`${record.cookie.name} unexpectedly entered private browsing`);
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
if (!matching.includes("rookie_chips=partitioned")) {
  throw new Error(`matching context omitted CHIPS cookie: ${matching}`);
}
if (other.includes("rookie_chips=partitioned")) {
  throw new Error(`different top-level site received CHIPS cookie: ${other}`);
}
if (engine === "firefox") {
  if (!matching.includes("rookie_dfpi=partitioned-by-context")) {
    throw new Error(`matching context omitted dFPI cookie: ${matching}`);
  }
  if (other.includes("rookie_dfpi=partitioned-by-context")) {
    throw new Error(`different top-level site received dFPI cookie: ${other}`);
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
