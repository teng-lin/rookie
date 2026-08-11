// Launches Firefox via Playwright, navigates to the cookie-seeding URL,
// and closes — leaving a persistent profile that rookie-cookies' tests extract from.
//
// Usage:
//   node tests/e2e/seed_firefox_cookie.mjs <user-data-dir> <url>
//
// Firefox stores cookies unencrypted in <user-data-dir>/cookies.sqlite, so no
// keyring / Keychain / DPAPI dance is needed on any platform — rookie-cookies reads
// the SQLite directly.

import { firefox } from "playwright";

const [userDataDir, url] = process.argv.slice(2);

if (!userDataDir || !url) {
  console.error("usage: node seed_firefox_cookie.mjs <user-data-dir> <url>");
  process.exit(2);
}

const context = await firefox.launchPersistentContext(userDataDir, {
  headless: false,
});

try {
  const page = await context.newPage();
  await page.goto(url, { waitUntil: "networkidle" });
  const userAgent = await page.evaluate(() => navigator.userAgent);
  const seeded = (await context.cookies(url)).find(
    (cookie) => cookie.name === "rookie_ci",
  );
  if (!seeded || seeded.value !== "bar") {
    throw new Error("Firefox did not accept the expected rookie_ci=bar cookie");
  }
  console.log(`seeded Firefox cookie; user agent: ${userAgent}`);
} finally {
  await context.close();
}
