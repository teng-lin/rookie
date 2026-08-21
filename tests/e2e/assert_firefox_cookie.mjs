// Assert that rookie-cookies extracts the seeded `rookie_ci=bar` cookie
// from the Firefox profile just seeded.
//
// Env vars:
//   ROOKIE_E2E_FIREFOX_PROFILE  required — same path passed to the seed step
//   ROOKIE_E2E_DOMAIN           optional — default 127.0.0.1
//   ROOKIE_E2E_COOKIE_NAME      optional — expected name (default: rookie_ci)
//   ROOKIE_E2E_COOKIE_VALUE     optional — expected value (default: bar)

import { existsSync, realpathSync } from "node:fs";
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
const directSnapshot = await rookieCookies.fromPath({ path: dbPath });
if (directSnapshot.browserId !== null || directSnapshot.profileId !== null) {
  console.error("fromPath unexpectedly reported a discovered identity");
  process.exit(1);
}

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
  verifyCookieRecords(
    manifestPath,
    "detailed",
    directSnapshot.detailedCookies,
    "Node fromPath.detailedCookies",
  );
} else {
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

  const detailedSeeded = detailed.find(
    ({ cookie }) => cookie.name === expectedName,
  );
  if (!detailedSeeded || !("originAttributes" in detailedSeeded.context)) {
    console.error("detailed Firefox binding omitted the seeded cookie context");
    process.exit(1);
  }

  const directSeeded = directSnapshot.detailedCookies.find(
    ({ cookie }) => cookie.name === expectedName,
  );
  if (!directSeeded || directSeeded.cookie.value !== expectedValue) {
    console.error("fromPath.detailedCookies omitted the seeded cookie");
    process.exit(1);
  }
}

const recommendedChecked =
  process.env.ROOKIE_E2E_CHECK_RECOMMENDED_READ === "1";
let recommendedSnapshot;
if (recommendedChecked) {
  const browserId = process.env.ROOKIE_E2E_BROWSER_ID ?? "firefox";
  const profiles = await rookieCookies.profiles(browserId);
  const matchingProfiles = profiles.filter(({ sources }) =>
    sources.some(({ path }) => realpathSync(path) === realpathSync(dbPath)),
  );
  if (matchingProfiles.length !== 1) {
    console.error(
      `${browserId} discovery found ${matchingProfiles.length} profiles for source ${dbPath}; profiles=${JSON.stringify(profiles)}`,
    );
    process.exit(1);
  }
  const identity = matchingProfiles[0].profile;
  recommendedSnapshot = await rookieCookies.read({
    browser: browserId,
    profile: identity.profileId,
  });
  if (
    recommendedSnapshot.browserId !== browserId ||
    recommendedSnapshot.profileId !== identity.profileId
  ) {
    console.error("recommended read returned the wrong browser/profile identity");
    process.exit(1);
  }
  const recommended = recommendedSnapshot.detailedCookies.find(
    ({ cookie }) => cookie.name === expectedName,
  );
  if (!recommended || recommended.cookie.value !== expectedValue) {
    console.error("recommended read detailed output omitted the seeded cookie");
    process.exit(1);
  }
  if (manifestPath) {
    verifyCookieRecords(
      manifestPath,
      "detailed",
      recommendedSnapshot.detailedCookies,
      "Node read(profile).detailedCookies",
    );
  }
}

console.log(
  `rookie-cookies (${process.platform}, firefox): ${manifestPath ? "exact cookie corpus" : `${expectedName}=${expectedValue}`} verified (${cookies.length} cookies for ${domain}; explicit detailed verified${recommendedChecked ? "; recommended read verified" : ""})`,
);
