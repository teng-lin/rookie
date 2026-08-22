// Seed or mutate a 320+ cookie corpus across eight registrable test domains.
// The browser profile must be explicitly marked disposable; no discovery is
// performed and no default profile is ever opened.

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import process from "node:process";

import { chromium, firefox } from "playwright";

const [
  engine,
  profileArg,
  portArg,
  manifestArg,
  mode = "seed",
  roundArg = "0",
  controlArg,
] = process.argv.slice(2);
if (
  !["chromium", "firefox"].includes(engine) ||
  !profileArg ||
  !portArg ||
  !manifestArg ||
  !["seed", "mutate"].includes(mode)
) {
  console.error(
    "usage: node seed_cookie_stress.mjs <chromium|firefox> <profile> <https-port> <manifest> [seed|mutate] [round] [control-dir]",
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
const controlDir = controlArg ? resolve(controlArg) : null;
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

const delay = (milliseconds) =>
  new Promise((accept) => setTimeout(accept, milliseconds));

async function waitForCommand(sequence) {
  const path = join(controlDir, `command-${sequence}.json`);
  const deadline = Date.now() + Number(
    process.env.ROOKIE_E2E_STRESS_TIMEOUT_MS || 300000,
  );
  while (Date.now() < deadline) {
    try {
      return JSON.parse(await readFile(path, "utf8"));
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    await delay(100);
  }
  throw new Error(`timed out waiting for ${path}`);
}

async function writeControl(name, payload) {
  const target = join(controlDir, name);
  const temporary = `${target}.tmp-${process.pid}`;
  await writeFile(
    temporary,
    `${JSON.stringify(payload, null, 2)}\n`,
    { encoding: "utf8", flag: "wx" },
  );
  await rename(temporary, target);
}

async function navigateAndCapture(context, page, captureMode, captureRound, output) {
  for (const host of hosts) {
    const target =
      captureMode === "seed"
        ? `https://${host}:${port}/stress/seed?count=40`
        : `https://${host}:${port}/stress/mutate?round=${captureRound}`;
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
    corpus_schema_version: 1,
    engine,
    platform: process.platform,
    tiers: ["stress"],
    browser: {
      version: context.browser()?.version() ?? "unknown",
      user_agent: await page.evaluate(() => navigator.userAgent),
    },
    domain_filter: hosts,
    identities: {
      filtered_flat: ["domain", "path", "name"],
      unfiltered_flat: ["domain", "path", "name"],
      detailed: [
        "cookie.domain",
        "cookie.path",
        "cookie.name",
        "context.top_frame_site_key",
        "context.has_cross_site_ancestor",
        "context.source_scheme",
        "context.source_port",
        "context.is_persistent",
        "context.origin_attributes",
        "context.user_context_id",
        "context.partition_key",
        "context.private_browsing_id",
      ],
    },
    expected: {
      filtered_flat: accepted,
      unfiltered_flat: accepted,
      detailed: accepted.map((cookie) => ({
        cookie,
        context:
          engine === "chromium"
            ? {
                top_frame_site_key: null,
                has_cross_site_ancestor: false,
                source_scheme: 2,
                source_port: port,
                is_persistent: true,
                origin_attributes: null,
                user_context_id: null,
                partition_key: null,
                private_browsing_id: null,
              }
            : {
                top_frame_site_key: null,
                has_cross_site_ancestor: null,
                source_scheme: null,
                source_port: null,
                is_persistent: null,
                origin_attributes: "",
                user_context_id: null,
                partition_key: null,
                private_browsing_id: null,
              },
      })),
    },
    excluded: [],
    observations: [
      {
        scenario_id: "distributed_stress",
        stored: true,
        mode: captureMode,
        round: captureMode === "mutate" ? captureRound : null,
        domains: hosts.length,
        cookies: accepted.length,
      },
    ],
  };
  await writeFile(output, `${JSON.stringify(manifest, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
  });
  console.log(
    `${engine} ${captureMode} retained ${accepted.length} stress cookies across ${hosts.length} registrable domains`,
  );
  return manifest;
}

const context = await browserType.launchPersistentContext(profile, launchOptions);
try {
  const page = await context.newPage();
  const initial = await navigateAndCapture(context, page, mode, round, manifestPath);
  if (controlDir) {
    await mkdir(controlDir, { recursive: true });
    await writeControl("ack-0.json", {
      protocol_version: 1,
      sequence: 0,
      phase: "ready",
      engine,
      seeder_pid: process.pid,
      profile,
      browser_version: initial.browser.version,
      manifest: manifestPath,
      cookie_count: initial.expected.unfiltered_flat.length,
    });
    let sequence = 1;
    while (true) {
      const command = await waitForCommand(sequence);
      if (command.sequence !== sequence) {
        throw new Error(`stress command sequence mismatch: ${JSON.stringify(command)}`);
      }
      if (command.action === "close") {
        await writeControl(`ack-${sequence}.json`, {
          protocol_version: 1,
          sequence,
          phase: "closing",
          engine,
          seeder_pid: process.pid,
        });
        break;
      }
      if (command.action !== "mutate" || !Number.isSafeInteger(command.round)) {
        throw new Error(`invalid stress command: ${JSON.stringify(command)}`);
      }
      const nextManifest = resolve(String(command.manifest));
      if (nextManifest === profile || nextManifest.startsWith(`${profile}/`)) {
        throw new Error("stress mutation manifest must remain outside the profile");
      }
      const captured = await navigateAndCapture(
        context,
        page,
        "mutate",
        command.round,
        nextManifest,
      );
      await writeControl(`ack-${sequence}.json`, {
        protocol_version: 1,
        sequence,
        phase: "mutated",
        round: command.round,
        engine,
        seeder_pid: process.pid,
        profile,
        manifest: nextManifest,
        cookie_count: captured.expected.unfiltered_flat.length,
      });
      sequence += 1;
    }
  }
} finally {
  await context.close();
}
