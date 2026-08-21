// Launches Firefox via Playwright and seeds the declarative cookie corpus. With
// a control directory, it instead remains open for the active-writer protocol.
//
// Usage:
//   node tests/e2e/seed_firefox_cookie.mjs <user-data-dir> <url> [control-dir]
//
// Firefox stores cookies unencrypted in <user-data-dir>/cookies.sqlite, so no
// keyring / Keychain / DPAPI dance is needed on any platform — rookie-cookies reads
// the SQLite directly.

import { firefox } from "playwright";
import { join } from "node:path";
import { seedCookieCorpus } from "./seed_cookie_corpus.mjs";

import { runActiveWriterProtocol } from "./active_writer_protocol.mjs";

const [userDataDir, url, controlDir] = process.argv.slice(2);

if (!userDataDir || !url) {
  console.error(
    "usage: node seed_firefox_cookie.mjs <user-data-dir> <url> [control-dir]",
  );
  process.exit(2);
}

const context = await firefox.launchPersistentContext(userDataDir, {
  headless: false,
});

try {
  const page = await context.newPage();
  if (controlDir) {
    await runActiveWriterProtocol({
      context,
      page,
      controlDir,
      baselineUrl: url,
      engine: "firefox",
      profileDir: userDataDir,
      databasePath: join(userDataDir, "cookies.sqlite"),
    });
  } else {
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
  }
} finally {
  await context.close().catch(() => {});
}
