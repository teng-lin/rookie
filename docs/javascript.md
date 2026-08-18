# rookie-cookies JavaScript Docs

This is the **canonical JavaScript guide** in the git repo (tutorial, 0.5.6
API, migrate 0.5.6 → 0.6.0). The [npm README](../bindings/node/README.md) is
the registry landing page: short `read` plus camelCase report object shapes.

This tree may still publish as `0.6.0-alpha.x`. The recommended entry is `read`
per [ADR 0004](adr/0004-read-is-the-recommended-entry.md).

## Install (0.6.0)

Use **Node.js 22 or newer**. The supported and tested release lines are Node.js
22, 24, and 26. Node.js 18 and 20 are no longer supported.

```console
npm install rookie-cookies
```

## Recommended 0.6.0 usage

Every extraction export returns a **Promise**. Always `await` (or `.then`).

```js
import { read } from "rookie-cookies";

// Pass profile to include session cookies.
const snapshot = await read({ browser: "chrome", profile: "Default" });
const header = snapshot.header("https://example.com/");
console.log(snapshot.cookies, snapshot.warnings, header);
```

`read` never URL-filters the snapshot. There is **no** top-level `header()`
export — call `ReadResult.header(url)` on the snapshot.

### Profile selection and session cookies

- No-profile `await read({ browser: "chrome" })` matches the legacy
  `chrome()` compatibility set (persistent / legacy-eligible cookies).
- Naming `profile` includes session cookies, so a profile-aware `read` can
  return more cookies than omitting `profile`.
- Session import should pass `profile`.

Named helpers such as `brave()`, `chrome()`, and `load()` remain supported and
also return Promises. Prefer `read` for new code. `version()` remains
synchronous.

### Explicit paths

```js
import { chromiumCookiesFromPath, cookiesFromPath } from "rookie-cookies";

const firefox = await cookiesFromPath("/path/to/cookies.sqlite", ["example.com"]);
const chrome = await chromiumCookiesFromPath(
  "/path/to/Chrome/Default/Network/Cookies",
  { browserId: "chrome", domains: ["example.com"] },
);
```

Chromium options accept at most one of `browserId`, `localStatePath`, or
`plaintextOnly: true`. Invalid option shapes reject their Promise with
`TypeError` before database I/O. Process shutdown is not exposed by the Node
binding.

### Reports and profiles

```js
import { browserProfiles, browserReport, profiles, report } from "rookie-cookies";

const listed = await profiles("chrome");
const viaJob = await report({ browser: "chrome", profile: listed[0]?.profile.profileId });

const profilesList = await browserProfiles("chrome");
const viaCompat = await browserReport("chrome", profilesList[0]?.profile.profileId);
```

Cookies stay attached to the source they came from, alongside that source's
status, acquisition strategy, counters, and diagnostics. CamelCase object
shapes, `schemaVersion`, and selected-source rules:
[bindings/node/README.md#reports](../bindings/node/README.md#reports).

### Timeouts and cancellation

`cookiesFromPath`, `chromiumCookiesFromPath` /
`chromiumCookiesFromPathDetailed`, every single-browser export (`firefox`,
`chrome`, `brave`, …), and `read` / `fromPath` accept `timeoutMs` and/or a
`CancellationHandle`:

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

### Deprecated path helpers (still present in 0.6)

`anyBrowser()`, the Chromium `*Based` pair, and flat `firefoxBased()` are
deprecated in 0.6 for removal no earlier than 0.7. Prefer `cookiesFromPath` /
`chromiumCookiesFromPath`. `firefoxBasedDetailed()` is not deprecated.

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

## 0.5.6 API

In the 0.5.6 line (and the early maintained-fork docs), the JavaScript surface
was the flat named-browser helpers. Extraction was **synchronous** (no
`Promise`), there was no `read` / `fromPath` job API, and Node 18/20 were still
in the supported set.

Typical 0.5.6-style usage:

```js
import { brave, chrome, load } from "rookie-cookies";

// Synchronous in 0.5.6 — returns CookieObject[] directly
const cookies = brave();
const filtered = chrome(["example.com"]);
const all = load();

for (const cookie of cookies) {
  console.log(cookie.domain, cookie.name);
}
```

Package install at that era:

```console
npm install rookie-cookies
```

(Upstream 0.5.6 used `@rookie-rs/api`; the maintained fork publishes
`rookie-cookies`.)

## Migrate 0.5.6 → 0.6.0

| Area | 0.5.6 / early 0.5.x | 0.6.0 |
| --- | --- | --- |
| Recommended entry | `chrome()` / `brave()` (sync) | `await read({ browser, profile })` |
| Async contract | Sync return values | **Every** extraction export returns a Promise — always `await` (changed in 0.5.8; required in 0.6) |
| Node.js version | 18 / 20 accepted | **≥ 22** (tested 22 / 24 / 26) |
| Session cookies | Not a first-class `profile` on a job API | Pass `profile` in `read({ … })` |
| Path APIs | `firefoxBased`, `chromiumBased`, `anyBrowser` | Prefer `cookiesFromPath` / `chromiumCookiesFromPath`; legacy helpers deprecated until ≥ 0.7 |
| Errors | Flat `Unknown` status | Request faults → `InvalidArg`; other failures → `GenericFailure` |
| Header view | Build manually | `snapshot.header(url)` — **no** top-level `header()` |
| Reports | Not in 0.5.6 | `report({ browser, profile })` / `browserReport(...)`, `profiles(...)` |

Concrete migration steps:

1. **Bump Node.js** to 22+.
2. **Add `await`** (or `.then`) to every extraction call, including named
   helpers you keep for compatibility.
3. **Prefer `read`** for session import; pass `profile` when you need session
   cookies.
4. **Move explicit DB paths** from `*Based` / `anyBrowser` to
   `cookiesFromPath` / `chromiumCookiesFromPath`.
5. **Update error handling** to inspect `.status` / `.code` for `InvalidArg`
   vs `GenericFailure` instead of assuming a single `Unknown` status.
6. Do **not** invent a top-level `header()` — use `(await read(...)).header(url)`.

See [CHANGELOG.md](../CHANGELOG.md) for the full 0.6.0 breaking/compat list.
