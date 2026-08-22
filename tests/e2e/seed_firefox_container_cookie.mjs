// Launch a disposable Firefox profile whose checked-in test extension creates
// one Multi-Account Container and one persistent cookie through WebExtensions.

import { readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import process from "node:process";

import { firefox } from "playwright";

const [profileArg, observedArg] = process.argv.slice(2);
if (!profileArg || !observedArg) {
  console.error(
    "usage: node seed_firefox_container_cookie.mjs <profile> <observed-manifest>",
  );
  process.exit(2);
}

const profile = resolve(profileArg);
const observed = resolve(observedArg);
if (observed === profile || observed.startsWith(`${profile}/`)) {
  throw new Error("container observation must stay outside the disposable profile");
}
const marker = JSON.parse(
  await readFile(join(profile, ".rookie-cookie-fixture-source.json"), "utf8"),
);
if (
  marker.schema_version !== 1 ||
  marker.kind !== "rookie-cookie-fixture-source"
) {
  throw new Error("container profile lacks the disposable E2E marker");
}

const timeout = Number(process.env.ROOKIE_E2E_PLAYWRIGHT_TIMEOUT_MS || 120000);
const context = await firefox.launchPersistentContext(profile, {
  headless: false,
  timeout,
  firefoxUserPrefs: {
    "xpinstall.signatures.required": false,
    "extensions.autoDisableScopes": 0,
    "extensions.enabledScopes": 15,
    "extensions.startupScanScopes": 15,
  },
});
try {
  const page = await context.newPage();
  await page.goto("about:blank", { waitUntil: "domcontentloaded", timeout });
  // Firefox's Playwright protocol view is scoped to the default container on
  // some versions. Give the extension time to run, but use the persisted raw
  // moz_cookies row as the authoritative proof in the coordinator.
  await new Promise((accept) => setTimeout(accept, 3000));
  const protocolCookies = (await context.cookies()).filter(
    ({ name }) => name === "rookie_container",
  );
  await writeFile(
    observed,
    `${JSON.stringify(
      {
        schema_version: 1,
        engine: "firefox",
        browser_version: context.browser()?.version() ?? "unknown",
        protocol_cookie_count: protocolCookies.length,
      },
      null,
      2,
    )}\n`,
    { encoding: "utf8", flag: "wx" },
  );
} finally {
  await context.close();
}
