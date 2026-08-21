// Launches Firefox via Playwright, seeds the declarative cookie corpus, writes
// an independent expected manifest, and closes the persistent profile.
//
// Usage:
//   node tests/e2e/seed_firefox_cookie.mjs <user-data-dir> <url>
//
// Firefox stores cookies unencrypted in <user-data-dir>/cookies.sqlite, so no
// keyring / Keychain / DPAPI dance is needed on any platform — rookie-cookies reads
// the SQLite directly.

import { firefox } from "playwright";
import { seedCookieCorpus } from "./seed_cookie_corpus.mjs";

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
  const { manifest, manifestPath, userAgent } = await seedCookieCorpus({
    context,
    page,
    engine: "firefox",
    profileDir: userDataDir,
    baseUrl: url,
  });
  console.log(
    `seeded ${manifest.expected.unfiltered_flat.length} Firefox corpus cookies; ` +
      `manifest: ${manifestPath}; user agent: ${userAgent}`,
  );
} finally {
  await context.close();
}
