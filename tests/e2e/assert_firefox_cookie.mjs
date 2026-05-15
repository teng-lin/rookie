// Assert that @rookie-rs/api extracts the seeded `rookie_ci=bar` cookie
// from the Firefox profile just seeded.
//
// Env vars:
//   ROOKIE_E2E_FIREFOX_PROFILE  required — same path passed to the seed step
//   ROOKIE_E2E_DOMAIN           optional — default 127.0.0.1

import { existsSync } from "node:fs";
import { join } from "node:path";
import process from "node:process";

import * as rookie from "../../bindings/node/index.js";

const profileDir = process.env.ROOKIE_E2E_FIREFOX_PROFILE;
if (!profileDir) {
  console.error("ROOKIE_E2E_FIREFOX_PROFILE must be set");
  process.exit(2);
}
const domain = process.env.ROOKIE_E2E_DOMAIN ?? "127.0.0.1";

const dbPath = join(profileDir, "cookies.sqlite");
if (!existsSync(dbPath)) {
  console.error(`no cookies.sqlite under ${profileDir}`);
  process.exit(1);
}

const cookies = rookie.firefoxBased(dbPath, [domain]);

const seeded = cookies.find((c) => c.name === "rookie_ci");
if (!seeded) {
  console.error(
    `seeded cookie 'rookie_ci' not found among ${cookies.length} cookies for ${domain}`,
  );
  process.exit(1);
}
if (seeded.value !== "bar") {
  console.error(`cookie value mismatch: expected 'bar', got '${seeded.value}'`);
  process.exit(1);
}

console.log(
  `@rookie-rs/api (${process.platform}, firefox): rookie_ci=bar verified (${cookies.length} cookies for ${domain})`,
);
