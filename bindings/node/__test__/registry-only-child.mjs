import { browserReport, supportedBrowsers } from "../index.js";

const registered = new Set((await supportedBrowsers()).map(({ id }) => id));
const results = {};
for (const browser of ["coccoc", "duckduckgo", "yandex"]) {
  if (registered.has(browser)) {
    results[browser] = (await browserReport(browser)).status;
  }
}
process.stdout.write(JSON.stringify(results));
