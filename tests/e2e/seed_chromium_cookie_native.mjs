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

// Cross-platform Chrome lifecycle: `--screenshot=<file>` instructs
// Chrome to navigate to the URL, take a screenshot, then exit on its
// own. This is critical on Windows — `child.kill('SIGTERM')` there
// resolves to TerminateProcess (force-kill), which doesn't give Chrome
// a chance to flush cookies to the SQLite. By making Chrome exit
// itself, we get a clean shutdown + cookie flush on every platform.
const screenshotDir = mkdtempSync(join(tmpdir(), "rookie-chrome-shot-"));
const screenshotPath = join(screenshotDir, "seed.png");

const baseArgs = [
  `--user-data-dir=${userDataDir}`,
  "--headless=new",
  "--no-first-run",
  "--no-default-browser-check",
  "--disable-default-apps",
  "--disable-background-networking",
  "--disable-component-update",
  "--disable-sync",
  `--screenshot=${screenshotPath}`,
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

await new Promise((resolve, reject) => {
  const timer = setTimeout(() => {
    child.kill();
    reject(new Error("chrome did not exit within 90s"));
  }, 90_000);
  child.on("exit", (code, signal) => {
    clearTimeout(timer);
    // Chrome occasionally prints non-fatal errors and still exits with
    // a non-zero code while having written the cookie. We treat that
    // as success and let the caller check the cookie SQLite directly.
    console.log(`chrome exited: code=${code} signal=${signal}`);
    resolve();
  });
  child.on("error", (err) => {
    clearTimeout(timer);
    reject(err);
  });
});

const cookiePaths = [
  join(userDataDir, "Default", "Network", "Cookies"),
  join(userDataDir, "Default", "Cookies"),
];
const cookieDb = cookiePaths.find(
  (p) => existsSync(p) && statSync(p).size > 0,
);
if (!cookieDb) {
  throw new Error(
    `no cookie file under ${userDataDir} after chrome exit; tried ${cookiePaths.join(", ")}`,
  );
}
console.log(`cookie db ready: ${cookieDb}`);
