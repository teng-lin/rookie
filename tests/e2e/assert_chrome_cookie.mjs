// Assert that rookie-cookies (Node binding) extracts the seeded
// `rookie_ci=bar` cookie from the Chrome profile that was just seeded.
//
// Env vars:
//   ROOKIE_E2E_USER_DATA_DIR  required — same path passed to the seed step
//   ROOKIE_E2E_COOKIE_DB      optional — explicit DB override
//   ROOKIE_E2E_DOMAIN         optional — domain filter (default: 127.0.0.1)
//   ROOKIE_E2E_COOKIE_NAME    optional — expected name (default: rookie_ci)
//   ROOKIE_E2E_COOKIE_VALUE   optional — expected value (default: bar)
//   ROOKIE_E2E_DISCOVERY_*    optional — separate name/value for chrome discovery
//
// Requires `npm run build` to have produced the
// platform-specific .node binary alongside bindings/node/index.js.

import { existsSync } from "node:fs";
import { join } from "node:path";
import process from "node:process";

import * as rookieCookies from "../../bindings/node/index.js";

const userDataDir = process.env.ROOKIE_E2E_USER_DATA_DIR;
if (!userDataDir) {
  console.error("ROOKIE_E2E_USER_DATA_DIR must be set");
  process.exit(2);
}
const domain = process.env.ROOKIE_E2E_DOMAIN ?? "127.0.0.1";
const expectedName = process.env.ROOKIE_E2E_COOKIE_NAME ?? "rookie_ci";
const expectedValue = process.env.ROOKIE_E2E_COOKIE_VALUE ?? "bar";

let dbPath = process.env.ROOKIE_E2E_COOKIE_DB;
if (!dbPath) {
  const defaultDir = join(userDataDir, "Default");
  for (const rel of ["Network/Cookies", "Cookies"]) {
    const p = join(defaultDir, rel);
    if (existsSync(p)) {
      dbPath = p;
      break;
    }
  }
  if (!dbPath) {
    console.error(`no cookie db under ${defaultDir}`);
    process.exit(1);
  }
}

// The explicit allow_elevated_fallback is deliberate and is NOT what the
// default does. The 0.6 default is injection_only, so these calls would
// decrypt v20 without it; pinning the most permissive policy is what keeps
// this canary a test of *elevated* recovery specifically, on a runner where
// unprivileged injection may not be enough. chromiumBased is the deprecated
// bridge and keeps allow_elevated_fallback unconditionally.
//
// Consequence worth knowing: because this pins a policy, nothing here
// exercises the default. That is covered by a Rust unit test. This Windows
// branch remains trusted-ref-only even though Linux Chrome now gates pull
// requests. See CHANGELOG.md.
let results;
if (process.platform === "win32") {
  const keyPath = join(userDataDir, "Local State");
  results = [
    [
      "extractFromPath(LocalStateFile)",
      await rookieCookies.extractFromPath(dbPath, {
        domains: [domain],
        localStatePath: keyPath,
        appBound: "allow_elevated_fallback",
      }),
    ],
    ["chromiumBased", await rookieCookies.chromiumBased(keyPath, dbPath, [domain])],
  ];
} else {
  results = [
    [
      "extractFromPath(BrowserId)",
      await rookieCookies.extractFromPath(dbPath, {
        domains: [domain],
        browserId: process.env.ROOKIE_E2E_BROWSER_ID ?? "chrome",
        appBound: "allow_elevated_fallback",
      }),
    ],
    [
      "chromiumBased",
      await rookieCookies.chromiumBased(
        dbPath,
        [domain],
        process.env.ROOKIE_E2E_BROWSER_ID ?? "chrome",
      ),
    ],
  ];
}

results = results.map(([surface, cookies]) => [surface, cookies, expectedName, expectedValue]);
if (process.env.ROOKIE_E2E_CHECK_BROWSER_DISCOVERY === "1") {
  const browserName = (process.env.ROOKIE_E2E_TARGET_BROWSER ?? "chrome").toLowerCase();
  const browserFns = {
    chrome: rookieCookies.chrome,
    "google-chrome": rookieCookies.chrome,
    edge: rookieCookies.edge,
    msedge: rookieCookies.edge,
    brave: rookieCookies.brave,
  };
  const browserFn = browserFns[browserName];
  if (!browserFn) {
    console.error(`unsupported ROOKIE_E2E_TARGET_BROWSER '${browserName}'`);
    process.exit(2);
  }
  results.push([
    browserName,
    await browserFn([domain]),
    process.env.ROOKIE_E2E_DISCOVERY_COOKIE_NAME ?? expectedName,
    process.env.ROOKIE_E2E_DISCOVERY_COOKIE_VALUE ?? expectedValue,
  ]);
}

for (const [surface, result, surfaceName, surfaceValue] of results) {
  const seeded = result.find((c) => c.name === surfaceName);
  if (!seeded) {
    console.error(
      `${surface}: seeded cookie '${surfaceName}' not found among ${result.length} cookies for ${domain}`,
    );
    process.exit(1);
  }
  if (seeded.value !== surfaceValue) {
    console.error(
      `${surface}: cookie value mismatch: expected '${surfaceValue}', got '${seeded.value}'`,
    );
    process.exit(1);
  }
}

console.log(
  `rookie-cookies (${process.platform}): ${expectedName}=${expectedValue} verified (${results[0][1].length} cookies for ${domain}; surfaces: ${results.map(([surface]) => surface).join(", ")})`,
);
