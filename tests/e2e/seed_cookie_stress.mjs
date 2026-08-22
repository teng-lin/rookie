// Seed or mutate a 320+ cookie corpus across eight registrable test domains.
// The browser profile must be explicitly marked disposable; no discovery is
// performed and no default profile is ever opened.

import {
  access,
  mkdir,
  readFile,
  realpath,
  rename,
  writeFile,
} from "node:fs/promises";
import { join, resolve } from "node:path";
import process from "node:process";

import { chromium, firefox } from "playwright";

import { processIdsForProfile } from "./active_writer_protocol.mjs";

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

const hosts = Array.from(
  { length: 8 },
  (_, index) => `seed.rookie-${index}.test`,
);
const hostRules = hosts.map((host) => `MAP ${host} 127.0.0.1`).join(",");
const timeout = Number(process.env.ROOKIE_E2E_PLAYWRIGHT_TIMEOUT_MS || 120000);
let browserType;
let launchOptions;
if (engine === "chromium") {
  browserType = chromium;
  const chromiumArgs = [
    "--no-first-run",
    "--disable-default-apps",
    "--disable-background-networking",
    "--disable-component-update",
    "--no-sandbox",
    "--disable-gpu",
    "--disable-dev-shm-usage",
    `--host-resolver-rules=${hostRules}`,
  ];
  const passwordStore = process.env.ROOKIE_E2E_PASSWORD_STORE || "basic";
  if (passwordStore !== "keychain") {
    chromiumArgs.push(`--password-store=${passwordStore}`);
  }
  launchOptions = {
    headless: false,
    ignoreHTTPSErrors: true,
    timeout,
    args: chromiumArgs,
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
      "network.dns.localDomains": hosts.join(","),
    },
  };
}

if (process.env.ROOKIE_E2E_BROWSER_PATH) {
  launchOptions.executablePath = process.env.ROOKIE_E2E_BROWSER_PATH;
}

const delay = (milliseconds) =>
  new Promise((accept) => setTimeout(accept, milliseconds));

async function waitForCommand(sequence) {
  const path = join(controlDir, `command-${sequence}.json`);
  const deadline =
    Date.now() + Number(process.env.ROOKIE_E2E_STRESS_TIMEOUT_MS || 300000);
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
  await writeFile(temporary, `${JSON.stringify(payload, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
  });
  await rename(temporary, target);
}

async function databaseForProfile() {
  const candidates =
    engine === "firefox"
      ? [join(profile, "cookies.sqlite")]
      : [
          join(profile, "Default", "Network", "Cookies"),
          join(profile, "Default", "Cookies"),
        ];
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    for (const candidate of candidates) {
      try {
        await access(candidate);
        return resolve(candidate);
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
    }
    await delay(50);
  }
  throw new Error(
    `timed out locating ${engine} cookie database below ${profile}`,
  );
}

async function browserLiveness(context, page) {
  const cookieCount = (await context.cookies()).filter(({ name }) =>
    name.startsWith("stress_"),
  ).length;
  if (cookieCount !== 320) {
    throw new Error(
      `browser liveness probe saw ${cookieCount} stress cookies, expected 320`,
    );
  }
  return {
    readyState: await page.evaluate(() => document.readyState),
    cookieCount,
  };
}

function acknowledgement({
  sequence,
  phase,
  browserVersion,
  resolvedProfile,
  databasePath,
  manifest,
  liveness,
}) {
  return {
    protocolVersion: 1,
    sequence,
    phase,
    engine,
    seederPid: process.pid,
    browserProcessIds: processIdsForProfile(resolvedProfile),
    browserVersion,
    profileDir: resolvedProfile,
    databasePath,
    manifest,
    liveness,
    timestamp: new Date().toISOString(),
  };
}

async function startWriteChurn(context, manifest) {
  const states = manifest.expected.unfiltered_flat
    .filter(({ name }) => /^stress_[0-7]_0$/.test(name))
    .map(({ domain, expires, value }) => ({
      host: domain.replace(/^\./, ""),
      expires,
      value,
    }))
    .sort((left, right) => left.host.localeCompare(right.host));
  if (states.length !== hosts.length) {
    throw new Error(
      `write churn expected ${hosts.length} stable rows, got ${states.length}`,
    );
  }
  const churnPage = await context.newPage();
  let active = true;
  let requests = 0;
  let churnError;
  const work = (async () => {
    while (active) {
      for (const state of states) {
        if (!active) break;
        const target = new URL(`https://${state.host}:${port}/stress/churn`);
        target.searchParams.set("value", state.value);
        target.searchParams.set("expiry", String(state.expires));
        await churnPage.goto(target.href, {
          waitUntil: "domcontentloaded",
          timeout,
        });
        requests += 1;
      }
    }
  })().catch((error) => {
    churnError = error;
    active = false;
  });
  const warmupDeadline = Date.now() + timeout;
  while (requests < states.length && churnError === undefined) {
    if (Date.now() >= warmupDeadline) {
      active = false;
      await churnPage.close();
      await work;
      throw new Error("timed out warming stress-cookie write churn");
    }
    await delay(10);
  }
  if (churnError !== undefined) {
    await churnPage.close();
    throw churnError;
  }
  return {
    proof: () => ({ active, requests }),
    stop: async () => {
      active = false;
      await work;
      await churnPage.close();
      if (churnError !== undefined) throw churnError;
      return { active: false, requests };
    },
  };
}

async function navigateAndCapture(
  context,
  page,
  captureMode,
  captureRound,
  output,
) {
  for (const host of hosts) {
    const target =
      captureMode === "seed"
        ? `https://${host}:${port}/stress/seed?count=40`
        : `https://${host}:${port}/stress/mutate?round=${captureRound}`;
    await page.goto(target, { waitUntil: "domcontentloaded", timeout });
  }

  const expected = new Map();
  for (let hostIndex = 0; hostIndex < hosts.length; hostIndex += 1) {
    const host = hosts[hostIndex];
    for (let cookieIndex = 0; cookieIndex < 39; cookieIndex += 1) {
      if (
        captureMode === "mutate" &&
        cookieIndex >= 1 &&
        cookieIndex <= captureRound + 1
      ) {
        continue;
      }
      const name = `stress_${hostIndex}_${cookieIndex}`;
      const value =
        cookieIndex === 0 && captureMode === "mutate"
          ? `updated-${captureRound}`
          : `seed-${hostIndex}-${cookieIndex}`;
      expected.set(`${host}\0${name}`, value);
    }
    expected.set(`${host}\0stress_shared`, `seed-${hostIndex}-39`);
    if (captureMode === "mutate") {
      for (let priorRound = 0; priorRound <= captureRound; priorRound += 1) {
        expected.set(
          `${host}\0stress_${hostIndex}_round_${priorRound}`,
          `added-${priorRound}`,
        );
      }
    }
  }

  const accepted = (await context.cookies())
    .filter(({ name }) => name.startsWith("stress_"))
    .map((cookie) => {
      const host = cookie.domain.replace(/^\./, "");
      const key = `${host}\0${cookie.name}`;
      const expectedValue = expected.get(key);
      if (expectedValue === undefined) {
        throw new Error(
          `browser retained an unexpected stress identity ${key}`,
        );
      }
      if (cookie.value !== expectedValue) {
        throw new Error(
          `${key} expected independent value ${expectedValue}, got ${cookie.value}`,
        );
      }
      if (
        cookie.path !== "/" ||
        cookie.secure !== true ||
        cookie.httpOnly !== true ||
        cookie.sameSite !== "Lax" ||
        cookie.expires <= 0
      ) {
        throw new Error(
          `browser attributes disagreed for ${key}: ${JSON.stringify(cookie)}`,
        );
      }
      expected.delete(key);
      return {
        domain: cookie.domain,
        path: "/",
        secure: true,
        expires: Math.trunc(cookie.expires),
        name: cookie.name,
        value: expectedValue,
        http_only: true,
        same_site: 1,
      };
    })
    .sort((left, right) =>
      `${left.domain}\0${left.path}\0${left.name}`.localeCompare(
        `${right.domain}\0${right.path}\0${right.name}`,
      ),
    );

  const expectedCount = hosts.length * 40;
  if (accepted.length !== expectedCount || expected.size !== 0) {
    throw new Error(
      `${engine} retained ${accepted.length} stress cookies, expected ${expectedCount}; ` +
        `missing=${JSON.stringify([...expected.keys()].sort())}`,
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
                // These cookies are set by top-level navigations initiated
                // from a different test site (including about:blank for the
                // first navigation). Current Chromium persists that browser-
                // observed ancestor-chain bit as true.
                has_cross_site_ancestor: true,
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

async function writeQuiescentManifest(context, template, output) {
  const expected = new Map(
    template.expected.unfiltered_flat.map((cookie) => [
      `${cookie.domain}\0${cookie.path}\0${cookie.name}`,
      cookie,
    ]),
  );
  const detailed = new Map(
    template.expected.detailed.map((record) => [
      `${record.cookie.domain}\0${record.cookie.path}\0${record.cookie.name}`,
      record.context,
    ]),
  );
  const accepted = (await context.cookies())
    .filter(({ name }) => name.startsWith("stress_"))
    .map((cookie) => {
      const identity = `${cookie.domain}\0${cookie.path}\0${cookie.name}`;
      const prior = expected.get(identity);
      if (!prior || prior.value !== cookie.value) {
        throw new Error(
          `quiescent browser identity/value drifted: ${identity}`,
        );
      }
      if (
        cookie.secure !== true ||
        cookie.httpOnly !== true ||
        cookie.sameSite !== "Lax" ||
        cookie.expires <= 0
      ) {
        throw new Error(
          `quiescent browser attributes drifted: ${JSON.stringify(cookie)}`,
        );
      }
      expected.delete(identity);
      return {
        domain: cookie.domain,
        path: cookie.path,
        secure: true,
        expires: Math.trunc(cookie.expires),
        name: cookie.name,
        value: cookie.value,
        http_only: true,
        same_site: 1,
      };
    })
    .sort((left, right) =>
      `${left.domain}\0${left.path}\0${left.name}`.localeCompare(
        `${right.domain}\0${right.path}\0${right.name}`,
      ),
    );
  if (accepted.length !== 320 || expected.size !== 0) {
    throw new Error(
      `quiescent browser retained ${accepted.length} rows; missing=${JSON.stringify([...expected.keys()].sort())}`,
    );
  }
  const manifest = structuredClone(template);
  manifest.expected.filtered_flat = accepted;
  manifest.expected.unfiltered_flat = accepted;
  manifest.expected.detailed = accepted.map((cookie) => ({
    cookie,
    context: detailed.get(`${cookie.domain}\0${cookie.path}\0${cookie.name}`),
  }));
  manifest.observations.push({
    scenario_id: "quiescent_browser_snapshot",
    stored: true,
    cookies: accepted.length,
  });
  await writeFile(output, `${JSON.stringify(manifest, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
  });
  return manifest;
}

const context = await browserType.launchPersistentContext(
  profile,
  launchOptions,
);
try {
  const page = await context.newPage();
  const initial = await navigateAndCapture(
    context,
    page,
    mode,
    round,
    manifestPath,
  );
  if (controlDir) {
    await mkdir(controlDir, { recursive: true });
    const resolvedProfile = await realpath(profile);
    const databasePath = await databaseForProfile();
    const browserVersion = initial.browser.version;
    let currentManifest = initial;
    let churn = await startWriteChurn(context, initial);
    await writeControl(
      "ack-0.json",
      acknowledgement({
        sequence: 0,
        phase: "ready",
        browserVersion,
        resolvedProfile,
        databasePath,
        manifest: manifestPath,
        liveness: {
          ...(await browserLiveness(context, page)),
          writeChurn: churn.proof(),
        },
      }),
    );
    let sequence = 1;
    while (true) {
      const command = await waitForCommand(sequence);
      if (command.sequence !== sequence) {
        throw new Error(
          `stress command sequence mismatch: ${JSON.stringify(command)}`,
        );
      }
      if (command.action === "close") {
        const stoppedChurn = await churn.stop();
        const closedManifestPath = resolve(String(command.manifest));
        if (
          closedManifestPath === profile ||
          closedManifestPath.startsWith(`${profile}/`)
        ) {
          throw new Error("quiescent manifest must remain outside the profile");
        }
        await delay(250);
        currentManifest = await writeQuiescentManifest(
          context,
          currentManifest,
          closedManifestPath,
        );
        await writeControl(
          `ack-${sequence}.json`,
          acknowledgement({
            sequence,
            phase: "closing",
            browserVersion,
            resolvedProfile,
            databasePath,
            manifest: closedManifestPath,
            liveness: {
              ...(await browserLiveness(context, page)),
              writeChurn: stoppedChurn,
            },
          }),
        );
        break;
      }
      if (command.action !== "mutate" || !Number.isSafeInteger(command.round)) {
        throw new Error(`invalid stress command: ${JSON.stringify(command)}`);
      }
      await churn.stop();
      const nextManifest = resolve(String(command.manifest));
      if (nextManifest === profile || nextManifest.startsWith(`${profile}/`)) {
        throw new Error(
          "stress mutation manifest must remain outside the profile",
        );
      }
      const captured = await navigateAndCapture(
        context,
        page,
        "mutate",
        command.round,
        nextManifest,
      );
      currentManifest = captured;
      churn = await startWriteChurn(context, captured);
      await writeControl(
        `ack-${sequence}.json`,
        acknowledgement({
          sequence,
          phase: "mutated",
          browserVersion,
          resolvedProfile,
          databasePath,
          manifest: nextManifest,
          liveness: {
            ...(await browserLiveness(context, page)),
            writeChurn: churn.proof(),
          },
        }),
      );
      sequence += 1;
    }
  }
} finally {
  await context.close();
}
