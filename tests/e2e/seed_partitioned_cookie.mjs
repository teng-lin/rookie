// Seed browser-produced CHIPS/dFPI context in a disposable persistent profile.
//
// Usage:
//   node seed_partitioned_cookie.mjs <chromium|firefox> <profile> <top-url> <observed-manifest>
//
// This script never discovers a normal browser profile. The profile path is
// mandatory and must contain the disposable-capture marker created by CI.

import { readFile, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import process from "node:process";

import { chromium, firefox } from "playwright";

const MARKER = ".rookie-cookie-fixture-source.json";
const [engine, profileArg, topUrl, observedManifestArg] = process.argv.slice(2);

if (
  !["chromium", "firefox"].includes(engine) ||
  !profileArg ||
  !topUrl ||
  !observedManifestArg
) {
  console.error(
    "usage: node seed_partitioned_cookie.mjs <chromium|firefox> <profile> <top-url> <observed-manifest>",
  );
  process.exit(2);
}

const profile = resolve(profileArg);
const observedManifest = resolve(observedManifestArg);
if (observedManifest === profile || observedManifest.startsWith(`${profile}/`)) {
  throw new Error("observed manifest must be outside the disposable profile");
}

const markerPath = join(profile, MARKER);
const marker = JSON.parse(await readFile(markerPath, "utf8"));
if (
  marker.schema_version !== 1 ||
  marker.kind !== "rookie-cookie-fixture-source"
) {
  throw new Error(`${markerPath} is not a disposable E2E profile marker`);
}

const top = new URL(topUrl);
if (
  top.protocol !== "https:" ||
  !["top.rookie-a.test", "other.rookie-c.test"].includes(top.hostname)
) {
  throw new Error(`unexpected top-level test origin: ${top.origin}`);
}
const otherTop = new URL(topUrl);
otherTop.hostname =
  top.hostname === "top.rookie-a.test"
    ? "other.rookie-c.test"
    : "top.rookie-a.test";

const timeout = Number(process.env.ROOKIE_E2E_PLAYWRIGHT_TIMEOUT_MS || 120000);
const hostRules = [
  "MAP top.rookie-a.test 127.0.0.1",
  "MAP other.rookie-c.test 127.0.0.1",
  "MAP third.rookie-b.test 127.0.0.1",
].join(",");

let browserType;
let launchOptions;
if (engine === "chromium") {
  browserType = chromium;
  launchOptions = {
    headless: false,
    ignoreHTTPSErrors: true,
    timeout,
    args: [
      "--no-first-run",
      "--disable-default-apps",
      "--disable-background-networking",
      "--disable-component-update",
      "--no-sandbox",
      "--disable-gpu",
      "--disable-dev-shm-usage",
      `--host-resolver-rules=${hostRules}`,
      `--password-store=${process.env.ROOKIE_E2E_PASSWORD_STORE || "basic"}`,
    ],
  };
  if (process.env.ROOKIE_E2E_BROWSER_PATH) {
    launchOptions.executablePath = process.env.ROOKIE_E2E_BROWSER_PATH;
  } else if (process.env.ROOKIE_E2E_BROWSER_CHANNEL) {
    launchOptions.channel = process.env.ROOKIE_E2E_BROWSER_CHANNEL;
  }
} else {
  browserType = firefox;
  launchOptions = {
    headless: false,
    ignoreHTTPSErrors: true,
    timeout,
    firefoxUserPrefs: {
      "network.dns.localDomains": [
        "top.rookie-a.test",
        "other.rookie-c.test",
        "third.rookie-b.test",
      ].join(","),
      "network.cookie.cookieBehavior": 5,
      "network.cookie.CHIPS.enabled": true,
    },
  };
}

const context = await browserType.launchPersistentContext(profile, launchOptions);
try {
  const page = await context.newPage();
  for (const target of [topUrl, otherTop.href]) {
    await page.goto(target, { waitUntil: "domcontentloaded", timeout });
    await page.waitForFunction(() => document.title === "partition-seeded", null, {
      timeout,
    });
  }

  const cookies = (await context.cookies()).filter(({ name }) =>
    name.startsWith("rookie_"),
  );
  const names = cookies.map(({ name }) => name);
  for (const [required, minimum] of [["rookie_top", 2], ["rookie_chips", 2]]) {
    if (names.filter((name) => name === required).length < minimum) {
      throw new Error(
        `${engine} did not expose both ${required} identities; observed ${names.sort().join(", ")}`,
      );
    }
  }
  if (
    engine === "firefox" &&
    names.filter((name) => name === "rookie_dfpi").length < 2
  ) {
    throw new Error("Firefox did not expose both dFPI partition identities");
  }

  let chromiumStorage = [];
  if (engine === "chromium") {
    const cdp = await context.newCDPSession(page);
    const response = await cdp.send("Storage.getCookies");
    chromiumStorage = (response.cookies || []).filter(({ name }) =>
      name.startsWith("rookie_"),
    );
  }

  const manifest = {
    schema_version: 1,
    kind: "browser-observed-cookie-manifest",
    engine,
    browser_version: await context.browser()?.version?.(),
    top_level_origins: [top.origin, otherTop.origin],
    cookies,
    chromium_storage: chromiumStorage,
  };
  await writeFile(observedManifest, `${JSON.stringify(manifest, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
  });
  console.log(
    `seeded ${cookies.length} ${engine} context cookies in disposable profile ${basename(profile)}; manifest ${basename(observedManifest)} under ${basename(dirname(observedManifest))}`,
  );
} finally {
  await context.close();
}
