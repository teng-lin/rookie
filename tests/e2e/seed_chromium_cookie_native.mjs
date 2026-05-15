// Launches system Chrome directly — no Playwright, no CDP — so OS-crypt
// runs on its normal path without test-mode flag interference.
//
// Usage:
//   node tests/e2e/seed_chromium_cookie_native.mjs <user-data-dir> <url>
//
// Why this exists: Playwright's `chromium.launchPersistentContext` adds
// `--use-mock-keychain` on macOS and `--password-store=basic` on every
// platform by default. Those flags coerce Chrome onto OS-crypt paths
// that produce cookie blobs rookie can't unseal from the outside. See
// https://github.com/teng-lin/rookie/issues/8 for the full triage.
//
// Per-platform strategy
//
//   macOS — pass `--password-store=basic` so Chrome encrypts cookies
//           with the hardcoded "peanuts" key. rookie's macOS chromium
//           fallback chain already tries "peanuts". Chrome lifecycle is
//           SIGTERM-driven: macOS Chrome catches SIGTERM, flushes
//           cookies, exits. `--headless=new --screenshot` hangs on
//           macos-15 GitHub runners (~90s timeouts) so we avoid it.
//
//   Windows — no `--password-store` flag. Stock Chrome on Windows uses
//             DPAPI, writes the wrapped key to Local State, and rookie's
//             Windows path DPAPI-unseals it. Chrome lifecycle is
//             screenshot-driven: `--headless=new --screenshot=<path>`
//             makes Chrome navigate, screenshot, and exit on its own.
//             Required because Node's `child.kill('SIGTERM')` on
//             Windows is TerminateProcess (force-kill) — Chrome
//             wouldn't get a chance to flush cookies.

import { spawn } from "node:child_process";
import { existsSync, statSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const isWindows = process.platform === "win32";
const isMac = process.platform === "darwin";

// On Windows `--screenshot=<path>` works as a Chrome-driven exit signal.
// On macOS the same combo hangs, so we omit it and SIGTERM Chrome ourselves.
const screenshotDir = mkdtempSync(join(tmpdir(), "rookie-chrome-shot-"));
const screenshotArg = isWindows
  ? [`--screenshot=${join(screenshotDir, "seed.png")}`]
  : [];

const baseArgs = [
  `--user-data-dir=${userDataDir}`,
  "--headless=new",
  "--no-first-run",
  "--no-default-browser-check",
  "--disable-default-apps",
  "--disable-background-networking",
  "--disable-component-update",
  "--disable-sync",
  ...screenshotArg,
];

// On Windows, Chrome v127+ defaults to App-Bound Encryption (v20) which
// requires the Elevation Service to register on first launch. On a fresh
// CI profile the service often doesn't register; Chrome then writes
// undecryptable v20 cookies anyway. Force the legacy v10 / pure-DPAPI
// path with --disable-features so rookie's existing Windows decrypt code
// can read the result. Production users on a stable profile hit the
// AppBound path normally — this opt-out exists for CI only.
const platformArgs = isMac
  ? ["--password-store=basic"]
  : isWindows
    ? ["--disable-features=ChromeAppBoundEncryption"]
    : [];

const args = [...baseArgs, ...platformArgs, url];

console.log(`launching: ${chromePath()} ${args.join(" ")}`);

const child = spawn(chromePath(), args, { stdio: "inherit" });

if (isWindows) {
  // Chrome exits itself once the screenshot is written. Wait.
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("chrome did not exit within 90s"));
    }, 90_000);
    child.on("exit", (code, signal) => {
      clearTimeout(timer);
      console.log(`chrome exited: code=${code} signal=${signal}`);
      resolve();
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
} else {
  // macOS: wait for the cookie file to appear, give Chrome time to flush
  // the actual cookie row, then SIGTERM cleanly. Chrome's SIGTERM
  // handler flushes the SQLite before exit.
  const start = Date.now();
  while (Date.now() - start < 60_000) {
    if (findCookieDb()) break;
    await sleep(500);
  }
  await sleep(5_000);
  child.kill("SIGTERM");
  await new Promise((resolve) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      resolve();
    }, 10_000);
    child.on("exit", () => {
      clearTimeout(timer);
      resolve();
    });
  });
}

const cookieDb = findCookieDb();
if (!cookieDb) {
  throw new Error(
    `no cookie file under ${userDataDir} after chrome exit; tried ${cookiePaths.join(", ")}`,
  );
}
console.log(`cookie db ready: ${cookieDb}`);
