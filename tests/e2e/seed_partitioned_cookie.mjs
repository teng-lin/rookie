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
import { fileURLToPath } from "node:url";

import { chromium, firefox } from "playwright";

const MARKER = ".rookie-cookie-fixture-source.json";
const INVENTORY = JSON.parse(
  await readFile(
    join(dirname(fileURLToPath(import.meta.url)), "partition_context_inventory.json"),
    "utf8",
  ),
);
// Every host this lane resolves to the disposable HTTPS origin. nested is on
// the same registrable site as top, which is what makes an A -> B -> A chain
// expressible at all.
const TEST_HOSTS = [
  "top.rookie-a.test",
  "other.rookie-c.test",
  "third.rookie-b.test",
  "nested.rookie-a.test",
];
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
if (
  observedManifest === profile ||
  observedManifest.startsWith(`${profile}/`)
) {
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
const hostRules = TEST_HOSTS.map((host) => `MAP ${host} 127.0.0.1`).join(",");

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
  if (
    process.platform === "darwin" &&
    process.env.ROOKIE_E2E_DISABLE_MOCK_KEYCHAIN === "1"
  ) {
    launchOptions.ignoreDefaultArgs = [
      "--use-mock-keychain",
      "--password-store=basic",
    ];
  }
  if (process.env.ROOKIE_E2E_BROWSER_CHANNEL) {
    launchOptions.channel = process.env.ROOKIE_E2E_BROWSER_CHANNEL;
  }
} else {
  browserType = firefox;
  launchOptions = {
    headless: false,
    ignoreHTTPSErrors: true,
    timeout,
    firefoxUserPrefs: {
      "network.dns.localDomains": TEST_HOSTS.join(","),
      "network.cookie.cookieBehavior": 5,
      "network.cookie.CHIPS.enabled": true,
    },
  };
}

if (process.env.ROOKIE_E2E_BROWSER_PATH) {
  launchOptions.executablePath = process.env.ROOKIE_E2E_BROWSER_PATH;
}

const context = await browserType.launchPersistentContext(
  profile,
  launchOptions,
);
try {
  const page = await context.newPage();
  const thirdOrigin = new URL(top.searchParams.get("third_origin"));
  await page.goto(`${thirdOrigin.origin}/set-unpartitioned?engine=${engine}`, {
    waitUntil: "domcontentloaded",
    timeout,
  });
  await page.waitForFunction(
    () => document.title === "unpartitioned-seeded",
    null,
    { timeout },
  );
  for (const target of [topUrl, otherTop.href]) {
    await page.goto(target, { waitUntil: "domcontentloaded", timeout });
    await page.waitForFunction(
      () => document.title === "partition-seeded",
      null,
      {
        timeout,
      },
    );
  }

  // Both ancestor chains onto one host of the A site: the direct iframe is
  // A -> A, the relayed one is A -> B -> A. Same cookie name, host, and path
  // in both, so only the ancestor bit can keep the two rows apart.
  const chainTop = new URL(topUrl);
  if (chainTop.hostname !== "top.rookie-a.test") {
    throw new Error(
      `the ancestor-chain page is hosted on the A site only, not ${chainTop.hostname}`,
    );
  }
  chainTop.pathname = "/chain-top";
  chainTop.search = "";
  await page.goto(chainTop.href, { waitUntil: "domcontentloaded", timeout });
  await page.waitForFunction(
    () => document.title === "ancestor-seeded",
    null,
    { timeout },
  );

  const cookies = (await context.cookies()).filter(({ name }) =>
    name.startsWith("rookie_"),
  );
  const names = cookies.map(({ name }) => name);
  const minimums = INVENTORY.engines[engine]?.browser_visible_minimums;
  if (!minimums) {
    throw new Error(`partition_context_inventory.json has no ${engine} entry`);
  }
  for (const [required, minimum] of Object.entries(minimums)) {
    if (names.filter((name) => name === required).length < minimum) {
      throw new Error(
        `${engine} exposed fewer than ${minimum} ${required} identities; observed ${names.sort().join(", ")}`,
      );
    }
  }

  let chromiumStorage = [];
  if (engine === "chromium") {
    const cdp = await context.newCDPSession(page);
    const response = await cdp.send("Storage.getCookies");
    chromiumStorage = (response.cookies || []).filter(({ name }) =>
      name.startsWith("rookie_"),
    );
    // A browser-side oracle for the ancestor bit, independent of the SQLite
    // store the assertions read. CDP has spelled `partitionKey` both as a bare
    // site string and as an object carrying the bit; only the object form can
    // answer this, so a string form is reported rather than silently accepted.
    const ancestors = chromiumStorage.filter(
      ({ name }) => name === "rookie_ancestor",
    );
    if (ancestors.length !== 2) {
      throw new Error(
        `Chromium Storage.getCookies exposed ${ancestors.length} rookie_ancestor rows, expected 2`,
      );
    }
    const bits = ancestors.map(({ partitionKey }) =>
      partitionKey && typeof partitionKey === "object"
        ? partitionKey.hasCrossSiteAncestor
        : undefined,
    );
    if (bits.some((bit) => bit === undefined)) {
      throw new Error(
        `Chromium ${await context.browser()?.version?.()} did not report partitionKey.hasCrossSiteAncestor; got ${JSON.stringify(ancestors.map((cookie) => cookie.partitionKey))}`,
      );
    }
    if (!bits.includes(true) || !bits.includes(false)) {
      throw new Error(
        `Chromium collapsed the two ancestor chains into ${JSON.stringify(bits)}`,
      );
    }
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
