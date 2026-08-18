// Launches a real Chromium-family browser via Playwright, navigates to the
// cookie-seeding URL, and closes — leaving a persistent profile that
// rookie-cookies' tests extract from.
//
// Usage:
//   node tests/e2e/seed_chromium_cookie.mjs <channel> <user-data-dir> <url>
//
// channel: "chrome" | "msedge" | "chromium" | "chrome-beta" | etc.
//   "chromium" uses Playwright's bundled Chromium (no channel).
//   ROOKIE_E2E_BROWSER_PATH overrides the executable when set (Brave, …).
// user-data-dir: persistent profile path; matches rookie-cookies' default lookup
// url: e.g. "http://127.0.0.1:8765/set"
//
// Linux requires --password-store=gnome-libsecret to push the OS-encrypted
// key into libsecret (otherwise Chrome falls back to a basic XOR scheme).
//
// Playwright passes --use-mock-keychain by default on macOS. Chromium's fake
// keychain uses the deterministic `mock_password`, which rookie-cookies tries before
// falling back to older default keys.

import { chromium } from "playwright";

const [channelArg, userDataDir, url] = process.argv.slice(2);

if (!channelArg || !userDataDir || !url) {
  console.error(
    "usage: node seed_chromium_cookie.mjs <channel> <user-data-dir> <url>",
  );
  process.exit(2);
}

const channel = channelArg === "edge" ? "msedge" : channelArg;
const linuxArgs =
  process.platform === "linux" ? ["--password-store=gnome-libsecret"] : [];

const launchOptions = {
  headless: false,
  args: [
    "--no-first-run",
    "--disable-default-apps",
    "--disable-background-networking",
    "--disable-component-update",
    ...linuxArgs,
  ],
};
if (process.env.ROOKIE_E2E_BROWSER_PATH) {
  launchOptions.executablePath = process.env.ROOKIE_E2E_BROWSER_PATH;
} else if (channel && channel !== "chromium") {
  launchOptions.channel = channel;
}

const context = await chromium.launchPersistentContext(userDataDir, launchOptions);

try {
  const page = await context.newPage();
  await page.goto(url, { waitUntil: "networkidle" });
  const userAgent = await page.evaluate(() => navigator.userAgent);
  const seeded = (await context.cookies(url)).find(
    (cookie) => cookie.name === "rookie_ci",
  );
  if (!seeded || seeded.value !== "bar") {
    throw new Error("Chrome did not accept the expected rookie_ci=bar cookie");
  }
  console.log(`seeded Chrome cookie; user agent: ${userAgent}`);
} finally {
  await context.close();
}
