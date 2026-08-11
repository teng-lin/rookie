// Assert that rookie-cookies (Node binding) extracts the seeded
// `rookie_ci=bar` cookie from the Chrome profile that was just seeded.
//
// Env vars:
//   ROOKIE_E2E_USER_DATA_DIR  required — same path passed to the seed step
//   ROOKIE_E2E_DOMAIN         optional — domain filter (default: 127.0.0.1)
//   ROOKIE_E2E_COOKIE_NAME    optional — expected name (default: rookie_ci)
//   ROOKIE_E2E_COOKIE_VALUE   optional — expected value (default: bar)
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

const defaultDir = join(userDataDir, "Default");
let dbPath;
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

let cookies;
if (process.platform === "win32") {
  // Windows binding takes (keyPath, dbPath, domains)
  const keyPath = join(userDataDir, "Local State");
  cookies = await rookieCookies.chromiumBased(keyPath, dbPath, [domain]);
} else {
  // Unix binding takes (dbPath, domains)
  cookies = await rookieCookies.chromiumBased(dbPath, [domain]);
}

const results = [["chromiumBased", cookies]];
if (process.env.ROOKIE_E2E_CHECK_BROWSER_DISCOVERY === "1") {
  results.push(["chrome", await rookieCookies.chrome([domain])]);
}

for (const [surface, result] of results) {
  const seeded = result.find((c) => c.name === expectedName);
  if (!seeded) {
    console.error(
      `${surface}: seeded cookie '${expectedName}' not found among ${result.length} cookies for ${domain}`,
    );
    process.exit(1);
  }
  if (seeded.value !== expectedValue) {
    console.error(
      `${surface}: cookie value mismatch: expected '${expectedValue}', got '${seeded.value}'`,
    );
    process.exit(1);
  }
}

console.log(
  `rookie-cookies (${process.platform}): ${expectedName}=${expectedValue} verified (${cookies.length} cookies for ${domain}; surfaces: ${results.map(([surface]) => surface).join(", ")})`,
);
