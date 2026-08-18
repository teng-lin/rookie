# rookie-cookies (Node.js)

Extract cookies from local browsers on Linux, macOS, and Windows.

This file is the **npm landing page**. The canonical JavaScript guide —
recommended 0.6 `read`, the 0.5.6 sync helpers, and **migrate 0.5.6 → 0.6.0** —
is
[`docs/javascript.md`](https://github.com/teng-lin/rookie-cookies/blob/main/docs/javascript.md)
in the repo. Report object shapes in this file are the binding-specific
reference that page links to.

**Node.js ≥ 22** (tested 22, 24, 26). Extraction exports return **Promises** —
always `await`. `version()` is synchronous.

```console
npm install rookie-cookies
```

## Recommended 0.6 entry

```js
import { read } from "rookie-cookies";

const snapshot = await read({ browser: "chrome", profile: "Default" });
console.log(snapshot.cookies, snapshot.warnings);
console.log(snapshot.header("https://example.com/"));
```

Pass `profile` for session cookies. `read` never URL-filters. There is no
top-level `header()`. Named helpers (`chrome()`, `brave()`, `load()`) still
work and also return Promises; they are the compatibility bridge from
[`thewh1teagle/rookie`](https://github.com/thewh1teagle/rookie) / `@rookie-rs/api`
and will break in a later major version.

Coming from 0.5.6 sync `chrome()`? Use the
[migration section](https://github.com/teng-lin/rookie-cookies/blob/main/docs/javascript.md#migrate-056--060).

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
every installation root failed enumeration (empty would look like “not
installed”). An absent registered browser resolves to `[]` or
`status: "no_sources"`. Other failures are `GenericFailure`.

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

## Netscape

```js
import { chrome, toNetscape } from "rookie-cookies";

const output = toNetscape(await chrome());
```

Tabs / CR / LF become `%09` / `%0D` / `%0A`. Same encoding as Rust, CLI, and
Python.

## More

- Guide + 0.5.6 migration: [docs/javascript.md](https://github.com/teng-lin/rookie-cookies/blob/main/docs/javascript.md)
- Build / test: [docs/building.md](https://github.com/teng-lin/rookie-cookies/blob/main/docs/building.md),
  [docs/testing.md](https://github.com/teng-lin/rookie-cookies/blob/main/docs/testing.md)
- Source: [teng-lin/rookie-cookies](https://github.com/teng-lin/rookie-cookies)
