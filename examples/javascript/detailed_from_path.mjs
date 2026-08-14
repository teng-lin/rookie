// Print Firefox cookies together with container/origin context.

import { firefoxBasedDetailed } from "rookie-cookies";

const dbPath = process.argv[2];
if (!dbPath) {
  console.error("usage: detailed_from_path.mjs <cookies.sqlite>");
  process.exit(2);
}

for (const record of await firefoxBasedDetailed(dbPath)) {
  console.log(record.cookie.name, record.context);
}
