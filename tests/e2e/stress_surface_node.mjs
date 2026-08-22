// Emit one explicit-path snapshot as JSON for the stress verifier.

import process from "node:process";

import * as rookieCookies from "../../bindings/node/index.js";

const [engine, database, browserId, projection, localStatePath] = process.argv.slice(2);
if (
  !["chromium", "firefox"].includes(engine) ||
  !database ||
  !["unfiltered_flat", "detailed"].includes(projection)
) {
  console.error(
    "usage: node stress_surface_node.mjs <chromium|firefox> <database> <browser-id> <unfiltered_flat|detailed>",
  );
  process.exit(2);
}
const options = { path: database };
if (engine === "chromium") {
  if (localStatePath) options.localStatePath = localStatePath;
  else options.browserId = browserId;
}
const snapshot = await rookieCookies.fromPath(options);
process.stdout.write(
  `${JSON.stringify(projection === "detailed" ? snapshot.detailedCookies : snapshot.cookies)}\n`,
);
