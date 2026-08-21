# rookie-cookies (Node.js)

Extract cookies from local browsers on Linux, macOS, and Windows.

This file is the **JavaScript guide** (npm landing page and repo tutorial).
Rust stays in [`rookie-rs/README.md`](https://github.com/teng-lin/rookie-cookies/blob/main/rookie-rs/README.md).
The workspace is currently `0.6.0-beta.1`. The recommended 0.6 entry is
`read` ([ADR 0004](https://github.com/teng-lin/rookie-cookies/blob/main/docs/adr/0004-read-is-the-recommended-entry.md)).

**Node.js ≥ 22** (tested 22, 24, 26). Every extraction export returns a
**Promise** — always `await`. `version()` is synchronous.

```console
npm install rookie-cookies
```

## Recommended 0.6.0 usage

```js
import { read } from "rookie-cookies";

const snapshot = await read({
  browser: "firefox",
  profile: "default-release",
  includeSession: true,
});
console.log(snapshot.cookies, snapshot.warnings);
console.log(snapshot.header("https://example.com/"));
```

Pass `profile` to select one discovered profile. `read` never URL-filters.
There is **no** top-level `header()` — call `ReadResult.header(url)` on the
snapshot.

- No-profile `await read({ browser: "chrome" })` matches legacy `chrome()`
  (persistent / legacy-eligible cookies).
- `includeSession: true` also acquires a Gecko-family profile's separately
  declared session JSON source. **Migration trap:** in 0.6-beta, naming a
  Gecko `profile` alone imported session cookies; in 0.6.0 it does not — pass
  `includeSession: true` explicitly. This fails *silently*: a smaller
  snapshot, no error. Chromium registrations declare no separate session
  source and cannot recover session state that exists only in browser memory,
  so `includeSession` is a no-op there.
- `select` accepts only `"legacy_first"` (the default) on `read`; a caller
  cannot ask for every profile here (`report`/`browserReport` do that). Any
  other value, including `"all"`, rejects with `kind === "request"`,
  `rookieCode === "conflicting_profile_selection"`, before any I/O runs.

`snapshot.warnings` items carry a stable `code`: `decrypt_failed`,
`row_read_failed`, `invalid_octets`, `malformed_host_identity` (a row's host
could not be parsed as a valid domain), and `unparsable_partition_key` (a
Firefox `partitionKey` value did not match the expected shape). Branch on
`code`, not `message`, which is diagnostic text only.

Named helpers (`chrome()`, `brave()`, `load()`) still work and also return
Promises. They are the compatibility bridge from
[`thewh1teagle/rookie`](https://github.com/thewh1teagle/rookie) / `@rookie-rs/api`
and will break in a later major version. Prefer `read` for new code.

## Isolation: detailed cookies and the header view

`snapshot.cookies` is the legacy eight-field projection, which merges every
partition/container of a domain into one answer. `snapshot.detailedCookies`
keeps that identity instead: the same eight `Cookie` fields plus a `context`
object (`topFrameSiteKey`, `hasCrossSiteAncestor`, `sourceScheme`,
`sourcePort`, `isPersistent`, `originAttributes`, `userContextId`,
`partitionKey`, `privateBrowsingId`; every field nullable, since cookie
schemas vary by browser).

`ReadResult.header` takes either a bare URL string (sugar for `{ url }`,
matching the conservative `Subresource`/`Safe` defaults) or a `SendContext`:

```js
import { read } from "rookie-cookies";

const snapshot = await read({ browser: "chrome", profile: "Default" });
const value = snapshot.header({
  url: "https://example.com/",
  topLevelSite: "https://example.com",
  resource: "navigation",
  method: "safe",
});
```

A snapshot holding any CHIPS-partitioned or Firefox-container cookie rejects
with `rookieCode === "incomplete_send_context"` (its `required` array names
the missing selector: `top_level_site`, `user_context_id`, or
`private_browsing_id`) instead of silently merging isolated cookies into one
answer. `invalid_top_level_site` and `clock_unrepresentable` are the other
two `header`-specific request faults.

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
  const report = await browserReport({
    browserId: "chrome",
    profileId: profiles[0].profile.profileId,
    domains: ["example.com"],
  });
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
if (listed.length === 0) {
  console.log("Chrome is not installed");
} else {
  // Never use optional chaining here: `undefined` means every profile.
  const viaJob = await report({
    browser: "chrome",
    profile: listed[0].profile.profileId,
  });
  console.log(viaJob.status);
}
```

A profile's cookie stream is its **selected** sources whose `status` is
`succeeded`, in listed order. A rejected candidate can still be `succeeded`,
so status-only filtering double-counts.

`schemaVersion` versions the DTO. `termination` (`completed`, `timed_out`,
`cancelled`, `resource_exhausted`) is independent of `status`. Counters are
ordinary numbers (never `BigInt`); overflow sets `countersSaturated`.

`supportedBrowsers()` is registration, not detection, and takes no execution
control — it is a static catalog lookup with no disk I/O. `profiles(id,
options?)` aliases `browserProfiles(id, options?)`; both take a
`ProfilesOptions` with only `timeoutMs` (listing does no App-Bound work).
`report({ browser, profile, ... })` is the job-layer name for
`browserReport(options)`; `loadReport(options?)` is the report-shaped
`load()`. `browserReport`, unlike `report`, takes its browser/profile
selection as `browserId`/`profileId` fields on one `BrowserReportOptions`
object rather than positional arguments.

These reject only on a bad request (`kind === "request"`): unknown browser, or
a `profileId` that browser did not yield. The stable `rookieCode` identifies
the exact request fault; the existing N-API `code` remains `InvalidArg` or
`GenericFailure`. `browserProfiles` also rejects when every installation root
failed enumeration. An absent registered browser resolves to `[]` or `status:
"no_sources"`. `report`/`browserReport`/`loadReport`'s `timeoutMs` can also
reject with `kind === "stopped"`; every other failure is `kind === "engine"`.

`report`, `browserReport`, and `loadReport` also take `appBound` (see
[App-Bound recovery](#app-bound-v20-recovery) below); `profiles` /
`browserProfiles` do not.

`report` also takes `select?: "legacy_first" | "all"` (default `"all"`).
Naming `profile` already narrows the report to it regardless of `select`;
`select: "all"` together with an explicit `profile` is the one contradiction
bindings must catch (Rust's `ReportScope` makes it unrepresentable, so this
is the runtime equivalent) — it rejects with `rookieCode ===
"conflicting_profile_selection"` before any I/O. `browserReport` has no
`select`: an absent `profileId` means every profile, exactly as it always
has.

`chrome()` stays default-first. `chromeProfiles()` / `chromeProfile()` add
activity-hint order and a grouped report; lossy `pathLossy` selectors need
`profileId`.

## Explicit paths

`extractFromPath` is the canonical flat, domain-filtered path-extract job
(matching Rust/Python `extract_from_path`):

```js
import { extractFromPath } from "rookie-cookies";

const firefox = await extractFromPath("/path/to/cookies.sqlite", {
  domains: ["example.com"],
});
const chrome = await extractFromPath("/path/to/Chrome/Default/Network/Cookies", {
  browserId: "chrome",
  domains: ["example.com"],
});
```

`options` bundles `domains`; at most one of `browserId`, `localStatePath`,
`plaintextOnly: true`; `timeoutMs`; `appBound` (same three values, same
`"disabled"` default — see [App-Bound recovery](#app-bound-v20-recovery)).
Invalid option shapes reject with `TypeError` before I/O. Process shutdown is
not exposed. With no selector at all, the source is sniffed from its
signature and schema: a Chromium database found this way is plaintext-capable
only (an encrypted row is `missing_chromium_credentials`) — on Unix this is a
narrowing from 0.6-beta, which probed every registered browser identity in
turn; on Windows it is a widening, since a fully plaintext database used to
reject with `missing_local_state_file` before attempting extraction.

For isolation-carrying (detailed) path extraction, use
`fromPath(...).detailedCookies` instead — `fromPath`, like `read`, never
URL/domain-slices its snapshot:

```js
import { fromPath } from "rookie-cookies";

const snapshot = await fromPath({ path: "/path/to/Chrome/Default/Network/Cookies" });
for (const { cookie, context } of snapshot.detailedCookies) {
  console.log(cookie.name, context.topFrameSiteKey);
}
```

**`cookiesFromPath`, `chromiumCookiesFromPath`, and
`chromiumCookiesFromPathDetailed` are deprecated aliases** onto
`extractFromPath` (the first two) and `fromPath(...).detailedCookies` (the
third), kept until ≥ 0.7. `chromiumCookiesFromPathDetailed` additionally no
longer supports `domains`: passing a non-empty `domains` to it rejects rather
than silently ignoring it, since the seam it now routes through can't filter.
`anyBrowser()`, `chromiumBased*`, and flat `firefoxBased()` are likewise
deprecated onto `extractFromPath` until ≥ 0.7. `firefoxBasedDetailed()` stays
for container context.

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

`extractFromPath` (and its deprecated aliases `cookiesFromPath` /
`chromiumCookiesFromPath` / `chromiumCookiesFromPathDetailed`), every
single-browser export, and `read` / `fromPath` accept `timeoutMs` and/or a
`CancellationHandle`. `report` /
`browserReport` / `loadReport` accept `timeoutMs` (no `CancellationHandle` yet);
`profiles` / `browserProfiles` accept `timeoutMs` only. `supportedBrowsers()`
takes neither — it does no disk I/O.

```js
import { chrome, CancellationHandle } from "rookie-cookies";

const cancellation = new CancellationHandle();
const timer = setTimeout(() => cancellation.cancel(), 5000);

try {
  const cookies = await chrome(undefined, 30000, cancellation);
  console.log(cookies);
} catch (error) {
  if (error.stopReason === "timed_out") {
    console.log("timed out");
  } else if (error.stopReason === "cancelled") {
    console.log("cancelled");
  } else {
    throw error;
  }
} finally {
  clearTimeout(timer);
}
```

Native rejections expose stable `kind`, `rookieCode`, and `stopReason`
properties while retaining the N-API status in `code`. `kind` is one of
`"request"` (bad caller input — unknown browser, ambiguous profile, invalid
URL, conflicting selectors; `code` is `InvalidArg`), `"stopped"` (the request's
`timeoutMs` elapsed or a `CancellationHandle` fired; `code` is `Cancelled` for
a cancellation and `GenericFailure` for a timeout or resource-exhaustion
stop), `"source"` (a direct-path caller-supplied path or path option was
invalid; `code` is `InvalidArg`), or `"engine"` (discovery, acquisition, or
decryption failed for a reason other than caller input; `code` is
`GenericFailure`). Treat `kind` as an open string for forward compatibility —
`rookie_cookies::Error` is `#[non_exhaustive]`, so a newer core release can
add a variant this binding folds into `"engine"` until it is given its own
bucket.
Current `stopReason` values are `timed_out`, `cancelled`, and
`resource_exhausted`; treat the property as an open string for forward
compatibility.
Ambiguous profile errors also carry opaque `profileIds`; direct-path errors
carry `sourceKind`, `targetOs`, and a `pathRedacted` flag. An
`incomplete_send_context` error additionally carries `required: string[]` —
the missing `SendContext` selector names (`top_level_site`,
`user_context_id`, `private_browsing_id`); empty on every other error.
Human-readable `message` text remains diagnostic only. A `ReadResult`
warning whose Rust `u64` count exceeds JavaScript's `Number.MAX_SAFE_INTEGER`
sets `countersSaturated: true` while clamping `count` (an IEEE-754 `number`,
never `BigInt`) to `Number.MAX_SAFE_INTEGER`. Facade validation errors carry
the same fields with safe empty/null metadata; because they do not cross
N-API, their `code` is absent and `rookieCode` is `null`.

## App-Bound (v20) recovery

`read`, `fromPath`, `report`, `browserReport`, `loadReport`, and
`extractFromPath` all take an `appBound` option: `"disabled"` (the default),
`"injection_only"`, or `"allow_elevated_fallback"`. It is a no-op outside
Windows. An unrecognized string rejects with `kind === "request"` before any
I/O runs.

**`appBound` defaults to `"disabled"`.** Unlike the deprecated v0.5.9 bridge
(`chrome()`, `chromiumBased()`, ...), which keeps its old
`allow_elevated_fallback`-equivalent behavior unconditionally, this job
surface never injects, spawns a browser process, enumerates processes, or
impersonates SYSTEM unless a caller opts in. On Windows this means `read` /
`report` / etc. no longer recover Chrome v20 App-Bound cookies out of the
box — pass `appBound: "injection_only"` (unprivileged reflective COM
injection, Chrome 127+) or `appBound: "allow_elevated_fallback"` (adds
elevated SYSTEM impersonation fallback for Chrome 133+ when injection alone
cannot recover the key) to restore it:

```js
import { read } from "rookie-cookies";

const snapshot = await read({
  browser: "chrome",
  profile: "Default",
  appBound: "allow_elevated_fallback",
});
```

`profiles` / `browserProfiles` / `supportedBrowsers` take no `appBound`:
listing does no App-Bound work.

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
| Gecko session cookies | Not a first-class `profile` | `read({ browser: geckoId, profile, includeSession: true })` — `profile` alone no longer imports session cookies (see the migration trap above) |
| Path APIs | `firefoxBased`, `chromiumBased`, `anyBrowser` | `extractFromPath` (`cookiesFromPath` / `chromiumCookiesFromPath` / `chromiumCookiesFromPathDetailed` are deprecated aliases until ≥ 0.7) |
| Errors | Flat `Unknown` | `kind` is `request`/`stopped`/`source`/`engine`; `code` is `InvalidArg` for request/source, `Cancelled` for a stopped cancellation, else `GenericFailure` |
| Header view | Manual | `snapshot.header(url \| SendContext)` — **no** top-level `header()`; a partitioned/container snapshot needs a `SendContext`, not a bare URL |
| Cookie identity | Flat only | `snapshot.detailedCookies` adds CHIPS partition / Firefox container `context`; `snapshot.browserId` is now `string \| null` |
| Reports | Not in 0.5.6 | `report({ browser, profile, select })` / `browserReport({ browserId, profileId })` |
| App-Bound (v20) recovery | Always attempted (bridge behavior) | `appBound` defaults to `"disabled"` on `read`/`report`/`browserReport`/`loadReport`/`fromPath` — pass `"injection_only"` or `"allow_elevated_fallback"` to restore it; the deprecated bridge is unaffected |

1. Bump Node.js to 22+.
2. Add `await` (or `.then`) to every extraction call.
3. Prefer `read`; pass `includeSession: true` when a Gecko profile's session source is wanted.
4. Move explicit DB paths off `*Based` / `anyBrowser`.
5. Inspect `.status` / `.code` for `InvalidArg` vs `GenericFailure`.
6. Do not invent a top-level `header()`; pass a `SendContext` once any snapshot might hold isolated cookies.

See [CHANGELOG.md](https://github.com/teng-lin/rookie-cookies/blob/main/CHANGELOG.md).

## More

- [docs/building.md](https://github.com/teng-lin/rookie-cookies/blob/main/docs/building.md)
- [docs/testing.md](https://github.com/teng-lin/rookie-cookies/blob/main/docs/testing.md)
- [teng-lin/rookie-cookies](https://github.com/teng-lin/rookie-cookies)
