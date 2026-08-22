// Launches a real Chromium-family browser via Playwright, navigates to the
// declarative cookie-corpus routes and writes an independent manifest. With a
// control directory, it instead remains open for the active-writer protocol.
//
// Usage:
//   node tests/e2e/seed_chromium_cookie.mjs <channel> <user-data-dir> <url> [control-dir]
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
import { join } from "node:path";
import { seedCookieCorpus } from "./seed_cookie_corpus.mjs";

import { runActiveWriterProtocol } from "./active_writer_protocol.mjs";

const [channelArg, userDataDir, url, controlDir] = process.argv.slice(2);

if (!channelArg || !userDataDir || !url) {
  console.error(
    "usage: node seed_chromium_cookie.mjs <channel> <user-data-dir> <url> [control-dir]",
  );
  process.exit(2);
}

const channel = channelArg === "edge" ? "msedge" : channelArg;
const linuxArgs =
  process.platform === "linux"
    ? [`--password-store=${process.env.ROOKIE_E2E_PASSWORD_STORE || "gnome-libsecret"}`]
    : [];

const launchOptions = {
  headless: false,
  args: [
    "--no-first-run",
    "--disable-default-apps",
    "--disable-background-networking",
    "--disable-component-update",
    "--no-sandbox",
    "--disable-gpu",
    "--disable-dev-shm-usage",
    ...linuxArgs,
  ],
};
if (process.env.ROOKIE_E2E_BROWSER_PATH) {
  launchOptions.executablePath = process.env.ROOKIE_E2E_BROWSER_PATH;
} else if (channel && channel !== "chromium") {
  launchOptions.channel = channel;
}

const timeout = Number(process.env.ROOKIE_E2E_PLAYWRIGHT_TIMEOUT_MS || 30000);
const context = await chromium.launchPersistentContext(userDataDir, {
  ...launchOptions,
  timeout,
});

try {
  const page = await context.newPage();
  if (controlDir) {
    await runActiveWriterProtocol({
      context,
      page,
      controlDir,
      baselineUrl: url,
      engine: "chromium",
      profileDir: userDataDir,
      databasePath: join(userDataDir, "Default", "Network", "Cookies"),
    });
  } else {
    const { manifest, manifestPath, userAgent } = await seedCookieCorpus({
      context,
      page,
      engine: "chromium",
      profileDir: userDataDir,
      baseUrl: url,
    });
    console.log(
      `seeded ${manifest.expected.unfiltered_flat.length} Chromium corpus cookies; ` +
        `manifest: ${manifestPath}; user agent: ${userAgent}`,
    );
  }
} finally {
  await context.close().catch(() => {});
}
