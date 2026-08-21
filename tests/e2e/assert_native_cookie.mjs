// Assert a Safari BinaryCookies or IE WebCache seed through Node.

import { existsSync } from "node:fs";
import process from "node:process";

import * as rookieCookies from "../../bindings/node/index.js";

const browser = process.env.ROOKIE_E2E_BROWSER_ID ?? "";
const dbPath = process.env.ROOKIE_E2E_COOKIE_DB ?? "";
if (!["safari", "internet_explorer"].includes(browser) || !existsSync(dbPath)) {
  console.error(
    "ROOKIE_E2E_BROWSER_ID and ROOKIE_E2E_COOKIE_DB must identify Safari or IE",
  );
  process.exit(2);
}

const domain = process.env.ROOKIE_E2E_DOMAIN ?? "127.0.0.1";
const expectedName = process.env.ROOKIE_E2E_COOKIE_NAME ?? "rookie_ci";
const expectedValue = process.env.ROOKIE_E2E_COOKIE_VALUE ?? "bar";
const explicit = await rookieCookies.extractFromPath(dbPath, {
  domains: [domain],
});
const surfaces = [["extractFromPath", explicit]];
if (browser === "safari") {
  surfaces.push([browser, await rookieCookies.safari([domain])]);
}

for (const [surface, cookies] of surfaces) {
  const seeded = cookies.find(({ name }) => name === expectedName);
  if (!seeded) {
    throw new Error(
      `${surface}: '${expectedName}' missing from ${cookies.length} cookies`,
    );
  }
  if (seeded.value !== expectedValue) {
    throw new Error(
      `${surface}: expected ${expectedName}='${expectedValue}', got '${seeded.value}'`,
    );
  }
}

console.log(
  `rookie-cookies (${process.platform}, ${browser}): ${expectedName}=${expectedValue} verified ` +
    `(explicit=${explicit.length}` +
    (browser === "safari" ? `, discovered=${surfaces[1][1].length})` : ")"),
);
