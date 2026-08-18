# rookie-cookies (Node.js)

Extract cookies from local browsers on Linux, macOS, and Windows.

This file is the **JavaScript guide** (npm landing page and repo tutorial).
Rust stays in [`rookie-rs/README.md`](https://github.com/teng-lin/rookie-cookies/blob/main/rookie-rs/README.md).
The tree may still publish as `0.6.0-alpha.x`. The recommended 0.6 entry is
`read` ([ADR 0004](https://github.com/teng-lin/rookie-cookies/blob/main/docs/adr/0004-read-is-the-recommended-entry.md)).

**Node.js ≥ 22** (tested 22, 24, 26). Every extraction export returns a
**Promise** — always `await`. `version()` is synchronous.

```console
npm install rookie-cookies
```

## Recommended 0.6.0 usage

```js
import { read } from "rookie-cookies";

const snapshot = await read({ browser: "chrome", profile: "Default" });
console.log(snapshot.cookies, snapshot.warnings);
console.log(snapshot.header("https://example.com/"));
```

Pass `profile` for session cookies. `read` never URL-filters. There is **no**
top-level `header()` — call `ReadResult.header(url)` on the snapshot.

- No-profile `await read({ browser: "chrome" })` matches legacy `chrome()`
  (persistent / legacy-eligible cookies).
- Naming `profile` includes session cookies.

Named helpers (`chrome()`, `brave()`, `load()`) still work and also return
Promises. They are the compatibility bridge from
[`thewh1teagle/rookie`](https://github.com/thewh1teagle/rookie) / `@rookie-rs/api`
and will break in a later major version. Prefer `read` for new code.

## Reports

Named helpers return a flat `CookieObject[]` from one source. Report APIs cover
every installation and profile and keep failures on the object (camelCase
fields).

```js
import { browserProfiles, browserReport, loadReport, supportedBrowsers } from "rookie-cookies";

for (const browser of await supportedBrowsers()) {
  console.log(browser.id, browser.displayName, browser.capabilities.availableDecryptionTiers);
}

const profiles = await browserProfiles("chrome");
if (profiles.length === 0) {
  // absent browser — not an exception
} else {
  // Pass an explicit profileId. `undefined` means every profile, so do not
  // use `profiles[0]?.profile.profileId` on an empty list.
  const report = await browserReport("chrome", profiles[0].profile.profileId, ["example.com"]);
  if (report.schemaVersion !== 1) throw new Error("unsupported report schema");
  console.log(report.status, report.summary.cookiesEmitted);
  for (const profile of report.profiles) {
    for (const source of profile.sources) {
      if (source.selected && source.status === "succeeded") {
        console.log(profile.profile.displayName, source.source.path, source.cookies.length);
      }
    }
  }
}
```

Job-layer aliases:

```js
import { profiles, report } from "rookie-cookies";

const listed = await profiles("chrome");
const viaJob = await report({ browser: "chrome", profile: listed[0]?.profile.profileId });
```

A profile's cookie stream is its **selected** sources whose `status` is
`succeeded`, in listed order. A rejected candidate can still be `succeeded`,
so status-only filtering double-counts.

`schemaVersion` versions the DTO. `termination` (`completed`, `timed_out`,
`cancelled`, `resource_exhausted`) is independent of `status`. Counters are
ordinary numbers (never `BigInt`); overflow sets `countersSaturated`.

`supportedBrowsers()` is registration, not detection. `profiles(id)` aliases
`browserProfiles`. `report({ browser, profile })` is the job-layer name for
`browserReport`. `loadReport()` is the report-shaped `load()`.

These reject only on a **bad request** (`InvalidArg`): unknown browser, or a
`profileId` that browser did not yield. `browserProfiles` also rejects when
every installation root failed enumeration. An absent registered browser
resolves to `[]` or `status: "no_sources"`. Other failures are
`GenericFailure`.

`chrome()` stays default-first. `chromeProfiles()` / `chromeProfile()` add
activity-hint order and a grouped report; lossy `pathLossy` selectors need
`profileId`.

## Explicit paths

```js
import { chromiumCookiesFromPath, cookiesFromPath } from "rookie-cookies";

const firefox = await cookiesFromPath("/path/to/cookies.sqlite", ["example.com"]);
const chrome = await chromiumCookiesFromPath(
  "/path/to/Chrome/Default/Network/Cookies",
  { browserId: "chrome", domains: ["example.com"] },
);
```

At most one of `browserId`, `localStatePath`, `plaintextOnly: true`. Invalid
option shapes reject with `TypeError` before I/O. Process shutdown is not
exposed. Windows Chromium paths without a selector reject
`missing_local_state_file`.

`anyBrowser()`, `chromiumBased*`, and flat `firefoxBased()` are deprecated
until ≥ 0.7. `firefoxBasedDetailed()` stays for container context.

```js
import { chromiumBasedDetailed } from "rookie-cookies";

const records = await chromiumBasedDetailed(
  "/path/to/Brave/Default/Network/Cookies",
  ["example.com"],
  "brave",
);
for (const { cookie, context } of records) {
  console.log(cookie.name, context.topFrameSiteKey);
}
```

## Timeouts and cancellation

`cookiesFromPath`, `chromiumCookiesFromPath` /
`chromiumCookiesFromPathDetailed`, every single-browser export, and `read` /
`fromPath` accept `timeoutMs` and/or a `CancellationHandle`.

```js
import { chrome, CancellationHandle } from "rookie-cookies";

const cancellation = new CancellationHandle();
const timer = setTimeout(() => cancellation.cancel(), 5000);

try {
  const cookies = await chrome(undefined, 30000, cancellation);
  console.log(cookies);
} catch (error) {
  if (error.message.includes("operation deadline expired")) {
    console.log("timed out");
  } else if (error.message.includes("operation cancelled")) {
    console.log("cancelled");
  } else {
    throw error;
  }
} finally {
  clearTimeout(timer);
}
```

## Netscape

```js
import { chrome, toNetscape } from "rookie-cookies";

const output = toNetscape(await chrome());
```

Tabs / CR / LF become `%09` / `%0D` / `%0A`. Same encoding as Rust, CLI, and
Python.

## 0.5.6 API

In the 0.5.6 line extraction was **synchronous**. There was no `read` /
`fromPath` job API. Node 18/20 were still supported. Upstream published
`@rookie-rs/api`.

```js historical
import { brave, chrome, load } from "rookie-cookies";

// Synchronous in 0.5.6 — returns CookieObject[] directly (do not copy for 0.6)
const cookies = brave();
const filtered = chrome(["example.com"]);
const all = load();
```

## Migrate 0.5.6 → 0.6.0

| Area | 0.5.6 / early 0.5.x | 0.6.0 |
| --- | --- | --- |
| Recommended entry | `chrome()` / `brave()` (sync) | `await read({ browser, profile })` |
| Async contract | Sync return values | **Every** extraction export is a Promise (since 0.5.8) |
| Node.js | 18 / 20 accepted | **≥ 22** (tested 22 / 24 / 26) |
| Session cookies | Not a first-class `profile` | Pass `profile` in `read({ … })` |
| Path APIs | `firefoxBased`, `chromiumBased`, `anyBrowser` | `cookiesFromPath` / `chromiumCookiesFromPath` (legacy deprecated until ≥ 0.7) |
| Errors | Flat `Unknown` | Request faults → `InvalidArg`; else `GenericFailure` |
| Header view | Manual | `snapshot.header(url)` — **no** top-level `header()` |
| Reports | Not in 0.5.6 | `report({ browser, profile })` / `browserReport(...)` |

1. Bump Node.js to 22+.
2. Add `await` (or `.then`) to every extraction call.
3. Prefer `read`; pass `profile` for session cookies.
4. Move explicit DB paths off `*Based` / `anyBrowser`.
5. Inspect `.status` / `.code` for `InvalidArg` vs `GenericFailure`.
6. Do not invent a top-level `header()`.

See [CHANGELOG.md](https://github.com/teng-lin/rookie-cookies/blob/main/CHANGELOG.md).

## More

- [docs/building.md](https://github.com/teng-lin/rookie-cookies/blob/main/docs/building.md)
- [docs/testing.md](https://github.com/teng-lin/rookie-cookies/blob/main/docs/testing.md)
- [teng-lin/rookie-cookies](https://github.com/teng-lin/rookie-cookies)
