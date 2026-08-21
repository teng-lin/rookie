// Seed or mutate a 320+ cookie corpus across eight registrable test domains.
// The browser profile must be explicitly marked disposable; no discovery is
// performed and no default profile is ever opened.

import { readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import process from "node:process";

import { chromium, firefox } from "playwright";

const [engine, profileArg, portArg, manifestArg, mode = "seed", roundArg = "0"] =
  process.argv.slice(2);
if (
  !["chromium", "firefox"].includes(engine) ||
  !profileArg ||
  !portArg ||
  !manifestArg ||
  !["seed", "mutate"].includes(mode)
) {
  console.error(
    "usage: node seed_cookie_stress.mjs <chromium|firefox> <profile> <https-port> <manifest> [seed|mutate] [round]",
  );
  process.exit(2);
}

const port = Number(portArg);
const round = Number(roundArg);
if (!Number.isSafeInteger(port) || port <= 0 || port > 65535) {
  throw new Error(`invalid HTTPS port ${portArg}`);
}
if (!Number.isSafeInteger(round) || round < 0 || round > 38) {
  throw new Error(`invalid stress mutation round ${roundArg}; expected 0..38`);
}

const profile = resolve(profileArg);
const manifestPath = resolve(manifestArg);
if (manifestPath === profile || manifestPath.startsWith(`${profile}/`)) {
  throw new Error("stress manifest must be outside the disposable profile");
}
const markerPath = join(profile, ".rookie-cookie-fixture-source.json");
const marker = JSON.parse(await readFile(markerPath, "utf8"));
if (
  marker.schema_version !== 1 ||
  marker.kind !== "rookie-cookie-fixture-source"
) {
  throw new Error(`${markerPath} is not a disposable E2E profile marker`);
}

const hosts = Array.from({ length: 8 }, (_, index) =>
  `seed.rookie-${index}.test`,
);
const hostRules = hosts.map((host) => `MAP ${host} 127.0.0.1`).join(",");
const timeout = Number(process.env.ROOKIE_E2E_PLAYWRIGHT_TIMEOUT_MS || 120000);
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
      "network.dns.localDomains": hosts.join(","),
    },
  };
}

const context = await browserType.launchPersistentContext(profile, launchOptions);
try {
  const page = await context.newPage();
  for (const host of hosts) {
    const target =
      mode === "seed"
        ? `https://${host}:${port}/stress/seed?count=40`
        : `https://${host}:${port}/stress/mutate?round=${round}`;
    await page.goto(target, { waitUntil: "domcontentloaded", timeout });
  }

  const accepted = (await context.cookies())
    .filter(({ name }) => name.startsWith("stress_"))
    .map((cookie) => ({
      domain: cookie.domain,
      path: cookie.path,
      secure: cookie.secure,
      expires: cookie.expires < 0 ? null : Math.trunc(cookie.expires),
      name: cookie.name,
      value: cookie.value,
      http_only: cookie.httpOnly,
      same_site: { None: 0, Lax: 1, Strict: 2 }[cookie.sameSite] ?? -1,
    }))
    .sort((left, right) =>
      `${left.domain}\0${left.path}\0${left.name}`.localeCompare(
        `${right.domain}\0${right.path}\0${right.name}`,
      ),
    );

  const expectedCount = hosts.length * 40;
  if (accepted.length !== expectedCount) {
    throw new Error(
      `${engine} retained ${accepted.length} stress cookies, expected ${expectedCount}`,
    );
  }
  const manifest = {
    schema_version: 1,
    kind: "rookie-cookie-extraction-manifest",
    engine,
    tier: "stress",
    mode,
    round: mode === "mutate" ? round : null,
    identity: ["domain", "path", "name"],
    cookies: accepted,
  };
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
  });
  console.log(
    `${engine} ${mode} retained ${accepted.length} stress cookies across ${hosts.length} registrable domains`,
  );
} finally {
  await context.close();
}
