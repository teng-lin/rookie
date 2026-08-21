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
import { findManifest, verifyCookieRecords } from "./cookie_manifest.mjs";

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

const cookies = await rookieCookies.cookiesFromPath(dbPath, [domain]);
const legacy = await rookieCookies.firefoxBased(dbPath, [domain]);
const detailed = await rookieCookies.firefoxBasedDetailed(dbPath);

const manifestPath = findManifest(profileDir, expectedName);
if (manifestPath) {
  verifyCookieRecords(
    manifestPath,
    "filtered_flat",
    cookies,
    "Node cookiesFromPath",
  );
  verifyCookieRecords(
    manifestPath,
    "filtered_flat",
    legacy,
    "Node firefoxBased",
  );
  verifyCookieRecords(
    manifestPath,
    "detailed",
    detailed,
    "Node firefoxBasedDetailed",
  );
  console.log(
    `rookie-cookies (${process.platform}, firefox): exact cookie corpus verified (${cookies.length} filtered cookies)`,
  );
  process.exit(0);
}

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
if (JSON.stringify(legacy) !== JSON.stringify(cookies)) {
  console.error("legacy firefoxBased disagrees with cookiesFromPath");
  process.exit(1);
}
const now = Math.floor(Date.now() / 1000);
if (
  !Number.isInteger(seeded.expires) ||
  seeded.expires <= now ||
  seeded.expires > now + 7_200
) {
  console.error(
    `Firefox expiry must be Unix seconds near the seeded Max-Age: got ${seeded.expires} at ${now}`,
  );
  process.exit(1);
}

const detailedSeeded = detailed.find(({ cookie }) => cookie.name === expectedName);
if (!detailedSeeded || !("originAttributes" in detailedSeeded.context)) {
  console.error("detailed Firefox binding omitted the seeded cookie context");
  process.exit(1);
}

console.log(
  `rookie-cookies (${process.platform}, firefox): ${expectedName}=${expectedValue} verified (${cookies.length} cookies for ${domain})`,
);
