// Launches system Chrome directly — no Playwright, no CDP — so OS-crypt
// runs on its normal path without test-mode flag interference.
//
// Usage:
//   node tests/e2e/seed_chromium_cookie_native.mjs <user-data-dir> <url>
//
// Why this exists: Playwright's `chromium.launchPersistentContext` adds
// `--use-mock-keychain` on macOS and `--password-store=basic` (or similar)
// on Windows by default. Those flags coerce Chrome onto an OS-crypt path
// that produces cookie blobs rookie can't unseal from the outside. See
// https://github.com/teng-lin/rookie/issues/8 for the full triage.
//
// Per-platform strategy
//
//   macOS — pass `--password-store=basic`. Chrome encrypts cookies with
//           a key derived from the hardcoded "peanuts" password, which
//           rookie's macOS chromium fallback chain already tries. No
//           Keychain access → no TCC prompt → no need for Playwright.
//
//   Windows — no `--password-store` flag. Stock Chrome on Windows uses
//             DPAPI, writes the wrapped key to Local State, and rookie's
//             Windows path can DPAPI-unseal it directly. The Playwright-
//             driven path is what breaks this; the native launch keeps
//             Chrome on its default cookie-sealing flow.

import { spawn } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { join } from "node:path";

const [userDataDir, url] = process.argv.slice(2);

if (!userDataDir || !url) {
  console.error(
    "usage: node seed_chromium_cookie_native.mjs <user-data-dir> <url>",
  );
  process.exit(2);
}

function chromePath() {
  switch (process.platform) {
    case "darwin":
      return "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
    case "win32":
      return "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
    case "linux":
      return "google-chrome";
    default:
      throw new Error(`unsupported platform: ${process.platform}`);
  }
}

// Flags shared across every platform. Keep this list minimal — anything
// test-mode-ish risks the same kind of OS-crypt divergence that the
// Playwright path produces. `--headless=new` is the modern headless
// mode (Chrome 109+); it still runs full Chrome with persistent profile
// IO, just without putting a window on screen.
const baseArgs = [
  `--user-data-dir=${userDataDir}`,
  "--headless=new",
  "--no-first-run",
  "--no-default-browser-check",
  "--disable-default-apps",
  "--disable-background-networking",
  "--disable-component-update",
  "--disable-sync",
];

// macOS gets `--password-store=basic` so Chrome encrypts cookies with
// the "peanuts" fallback — see header for why. Windows gets nothing
// extra: stock Chrome's DPAPI flow is the actual code path rookie
// supports on that OS.
const platformArgs =
  process.platform === "darwin" ? ["--password-store=basic"] : [];

const args = [...baseArgs, ...platformArgs, url];

console.log(`launching: ${chromePath()} ${args.join(" ")}`);

const child = spawn(chromePath(), args, { stdio: "inherit" });

const cookiePaths = [
  join(userDataDir, "Default", "Network", "Cookies"),
  join(userDataDir, "Default", "Cookies"),
];

function findCookieDb() {
  for (const p of cookiePaths) {
    if (existsSync(p) && statSync(p).size > 0) return p;
  }
  return null;
}

async function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitForCookieDb(timeoutMs) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const p = findCookieDb();
    if (p) return p;
    await sleep(500);
  }
  throw new Error(
    `no cookie file under ${userDataDir} after ${timeoutMs}ms; ` +
      `child pid=${child.pid} exitCode=${child.exitCode}`,
  );
}

try {
  const db = await waitForCookieDb(60_000);
  console.log(`cookie db ready: ${db}`);
  // Chrome batches cookie writes. Even after the file appears we need
  // to give Chrome a few seconds to actually flush the cookie row that
  // /set produced. Empirically 5s is enough on the GitHub runners.
  await sleep(5_000);
} finally {
  // Send SIGTERM (or Win32 equivalent) and wait briefly for Chrome to
  // exit cleanly so any in-flight writes are flushed to the SQLite file.
  child.kill("SIGTERM");
  await sleep(3_000);
  if (child.exitCode === null) {
    child.kill("SIGKILL");
  }
}
