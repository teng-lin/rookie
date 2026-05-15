// Minimal example: read cookies from an explicit Firefox-style
// `cookies.sqlite` and print each one.
//
// Run with:
//   node examples/javascript/from_path.mjs /path/to/cookies.sqlite
//
// On CI this is invoked against the seeded Firefox profile that the
// e2e workflow creates, so it doubles as a regression test for the
// `@rookie-rs/api` `firefoxBased` public API drifting.

import { firefoxBased } from "@rookie-rs/api";

const dbPath = process.argv[2];
if (!dbPath) {
  console.error("usage: from_path.mjs <cookies.sqlite>");
  process.exit(2);
}

for (const cookie of firefoxBased(dbPath, null)) {
  console.log(cookie);
}
