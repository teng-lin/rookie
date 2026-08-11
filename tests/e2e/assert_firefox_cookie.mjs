// Assert that rookie-cookies extracts the seeded `rookie_ci=bar` cookie
// from the Firefox profile just seeded.
//
// Env vars:
//   ROOKIE_E2E_FIREFOX_PROFILE  required — same path passed to the seed step
//   ROOKIE_E2E_DOMAIN           optional — default 127.0.0.1
//   ROOKIE_E2E_COOKIE_NAME      optional — expected name (default: rookie_ci)
//   ROOKIE_E2E_COOKIE_VALUE     optional — expected value (default: bar)

import { existsSync } from "node:fs";
import { join } from "node:path";
import process from "node:process";

import * as rookieCookies from "../../bindings/node/index.js";

const profileDir = process.env.ROOKIE_E2E_FIREFOX_PROFILE;
if (!profileDir) {
  console.error("ROOKIE_E2E_FIREFOX_PROFILE must be set");
  process.exit(2);
}
const domain = process.env.ROOKIE_E2E_DOMAIN ?? "127.0.0.1";
const expectedName = process.env.ROOKIE_E2E_COOKIE_NAME ?? "rookie_ci";
const expectedValue = process.env.ROOKIE_E2E_COOKIE_VALUE ?? "bar";

const dbPath = join(profileDir, "cookies.sqlite");
if (!existsSync(dbPath)) {
  console.error(`no cookies.sqlite under ${profileDir}`);
  process.exit(1);
}

const cookies = await rookieCookies.firefoxBased(dbPath, [domain]);

const seeded = cookies.find((c) => c.name === expectedName);
if (!seeded) {
  console.error(
    `seeded cookie '${expectedName}' not found among ${cookies.length} cookies for ${domain}`,
  );
  process.exit(1);
}
if (seeded.value !== expectedValue) {
  console.error(
    `cookie value mismatch: expected '${expectedValue}', got '${seeded.value}'`,
  );
  process.exit(1);
}

console.log(
  `rookie-cookies (${process.platform}, firefox): ${expectedName}=${expectedValue} verified (${cookies.length} cookies for ${domain})`,
);
