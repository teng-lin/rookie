// File-based control protocol shared by the Playwright Chromium and Firefox
// seeders. The immutable command/ack files make orchestration portable across
// bash, PowerShell, and hosted runner filesystems without depending on signals.

import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { execFileSync } from "node:child_process";
import { join, resolve } from "node:path";
import process from "node:process";

export const ACTIVE_WRITER_REQUIRED_BASELINE = {
  rookie_ci: "before",
  rookie_remove: "present",
};
export const ACTIVE_WRITER_REQUIRED_MUTATED = {
  rookie_added: "present",
  rookie_ci: "after",
};

const delay = (milliseconds) =>
  new Promise((accept) => setTimeout(accept, milliseconds));

function atomicWriteJson(path, payload) {
  const temporary = `${path}.tmp-${process.pid}`;
  writeFileSync(temporary, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  renameSync(temporary, path);
}

function processIdsForProfile(profileDir) {
  try {
    if (process.platform === "win32") {
      const output = execFileSync(
        "powershell.exe",
        [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "Get-CimInstance Win32_Process | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress",
        ],
        { encoding: "utf8" },
      );
      const decoded = JSON.parse(output);
      const processes = Array.isArray(decoded) ? decoded : [decoded];
      return processes
        .filter((entry) => entry?.CommandLine?.includes(profileDir))
        .map((entry) => entry.ProcessId)
        .filter((pid) => Number.isInteger(pid) && pid !== process.pid);
    }
    const output = execFileSync("ps", ["-axo", "pid=,command="], {
      encoding: "utf8",
    });
    return output
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.includes(profileDir))
      .map((line) => Number.parseInt(line, 10))
      .filter((pid) => Number.isInteger(pid) && pid !== process.pid);
  } catch {
    return [];
  }
}

async function waitForFile(path, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (existsSync(path)) return;
    await delay(100);
  }
  throw new Error(`timed out waiting for ${path}`);
}

async function waitForCommand(controlDir, sequence, timeoutMs) {
  const path = join(controlDir, `command-${sequence}.json`);
  await waitForFile(path, timeoutMs);
  const command = JSON.parse(readFileSync(path, "utf8"));
  if (command.sequence !== sequence) {
    throw new Error(
      `command sequence mismatch: expected ${sequence}, got ${command.sequence}`,
    );
  }
  return command;
}

async function probe(context, page, origin, expected, forbidden) {
  const readyState = await page.evaluate(() => document.readyState);
  const cookies = await context.cookies(origin);
  for (const [name, value] of Object.entries(expected)) {
    const matches = cookies.filter((cookie) => cookie.name === name);
    if (matches.length !== 1 || matches[0].value !== value) {
      throw new Error(
        `browser state mismatch for ${name}: expected one ${value}, got ${JSON.stringify(matches)}`,
      );
    }
  }
  for (const name of forbidden) {
    if (cookies.some((cookie) => cookie.name === name)) {
      throw new Error(`browser retained forbidden cookie ${name}`);
    }
  }
  return { cookieCount: cookies.length, readyState };
}

function ackPayload({
  sequence,
  phase,
  engine,
  profileDir,
  databasePath,
  browserVersion,
  userAgent,
  liveness,
}) {
  return {
    protocolVersion: 1,
    sequence,
    phase,
    engine,
    seederPid: process.pid,
    browserProcessIds: processIdsForProfile(profileDir),
    browserVersion,
    userAgent,
    profileDir,
    databasePath,
    liveness,
    timestamp: new Date().toISOString(),
  };
}

export async function runActiveWriterProtocol({
  context,
  page,
  controlDir,
  baselineUrl,
  engine,
  profileDir,
  databasePath,
}) {
  mkdirSync(controlDir, { recursive: true });
  for (const entry of readdirSync(controlDir)) {
    if (/^(ack|command)-\d+\.json$/.test(entry) || entry === "error.json") {
      rmSync(join(controlDir, entry), { force: true });
    }
  }

  const resolvedProfile = realpathSync(resolve(profileDir));
  const resolvedDatabase = resolve(databasePath);
  const origin = new URL(baselineUrl).origin;
  const commandTimeoutMs = Number(
    process.env.ROOKIE_E2E_ACTIVE_WRITER_TIMEOUT_MS || 300000,
  );

  try {
    await page.goto(baselineUrl, { waitUntil: "networkidle" });
    await waitForFile(resolvedDatabase, commandTimeoutMs);
    const userAgent = await page.evaluate(() => navigator.userAgent);
    const browser = context.browser();
    const browserVersion = browser?.version() ?? "unknown";
    const liveness = await probe(
      context,
      page,
      origin,
      ACTIVE_WRITER_REQUIRED_BASELINE,
      ["rookie_added"],
    );
    atomicWriteJson(
      join(controlDir, "ack-0.json"),
      ackPayload({
        sequence: 0,
        phase: "ready",
        engine,
        profileDir: resolvedProfile,
        databasePath: resolvedDatabase,
        browserVersion,
        userAgent,
        liveness,
      }),
    );

    const mutate = await waitForCommand(controlDir, 1, commandTimeoutMs);
    if (mutate.action !== "mutate") {
      throw new Error(`expected mutate command, got ${mutate.action}`);
    }
    const mutateUrl = new URL("/active-writer/mutate", baselineUrl).href;
    await page.goto(mutateUrl, { waitUntil: "networkidle" });
    const mutatedLiveness = await probe(
      context,
      page,
      origin,
      ACTIVE_WRITER_REQUIRED_MUTATED,
      ["rookie_remove"],
    );
    atomicWriteJson(
      join(controlDir, "ack-1.json"),
      ackPayload({
        sequence: 1,
        phase: "mutated",
        engine,
        profileDir: resolvedProfile,
        databasePath: resolvedDatabase,
        browserVersion,
        userAgent,
        liveness: mutatedLiveness,
      }),
    );

    const probeCommand = await waitForCommand(controlDir, 2, commandTimeoutMs);
    if (probeCommand.action !== "probe") {
      throw new Error(`expected probe command, got ${probeCommand.action}`);
    }
    const probeLiveness = await probe(
      context,
      page,
      origin,
      ACTIVE_WRITER_REQUIRED_MUTATED,
      ["rookie_remove"],
    );
    atomicWriteJson(
      join(controlDir, "ack-2.json"),
      ackPayload({
        sequence: 2,
        phase: "probed",
        engine,
        profileDir: resolvedProfile,
        databasePath: resolvedDatabase,
        browserVersion,
        userAgent,
        liveness: probeLiveness,
      }),
    );

    const close = await waitForCommand(controlDir, 3, commandTimeoutMs);
    if (close.action !== "close") {
      throw new Error(`expected close command, got ${close.action}`);
    }
    await context.close();
    atomicWriteJson(
      join(controlDir, "ack-3.json"),
      ackPayload({
        sequence: 3,
        phase: "closed",
        engine,
        profileDir: resolvedProfile,
        databasePath: resolvedDatabase,
        browserVersion,
        userAgent,
        liveness: { browserClosed: true },
      }),
    );
  } catch (error) {
    atomicWriteJson(join(controlDir, "error.json"), {
      protocolVersion: 1,
      seederPid: process.pid,
      message: error instanceof Error ? error.stack : String(error),
      timestamp: new Date().toISOString(),
    });
    throw error;
  }
}
