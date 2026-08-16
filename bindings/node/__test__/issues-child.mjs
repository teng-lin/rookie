import { browserReport } from "../index.js";

// Key sets must be captured in-process. JSON.stringify silently drops keys
// whose value is undefined, which is exactly how a missing camelCase rename on
// an optional field such as `browserId` would escape a serialized snapshot.
function collectKeys(value, keys = new Set()) {
  if (Array.isArray(value)) {
    for (const entry of value) {
      collectKeys(entry, keys);
    }
  } else if (value !== null && typeof value === "object") {
    for (const [key, entry] of Object.entries(value)) {
      keys.add(key);
      collectKeys(entry, keys);
    }
  }
  return keys;
}

// One profile in the fixture has a corrupt cookie source, producing a
// source-scoped issue; the uninstalled browser produces a request-scoped issue
// carrying browser context.
const firefox = await browserReport("firefox");
const absent = await browserReport("chrome");

const sourceIssue = firefox.profiles
  .flatMap((profile) => profile.sources)
  .flatMap((source) => source.issues)[0];
const requestIssue = absent.issues[0];

process.stdout.write(
  JSON.stringify({
    firefoxKeys: [...collectKeys(firefox)].sort(),
    absentKeys: [...collectKeys(absent)].sort(),
    reportKeys: Object.keys(firefox),
    sourceIssue: sourceIssue ?? null,
    sourceIssueKeys: sourceIssue ? Object.keys(sourceIssue) : null,
    requestIssue: requestIssue ?? null,
    requestIssueKeys: requestIssue ? Object.keys(requestIssue) : null,
    absentStatus: absent.status,
  }),
);
