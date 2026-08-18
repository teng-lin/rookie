# rookie-cookies JavaScript Docs

## Install

Use Node.js 22 or newer. The supported and tested release lines are Node.js 22,
24, and 26; Node.js 18 and 20 are no longer supported.

```console
npm install rookie-cookies
```

## Basic Usage

```js
import { read } from "rookie-cookies";

// Pass profile to include session cookies.
const snapshot = await read({ browser: "chrome", profile: "Default" });
const header = snapshot.header("https://example.com/");
console.log(snapshot.cookies, snapshot.warnings, header);
```

Named helpers such as `brave()` remain supported. `read` never URL-filters
the snapshot. There is no top-level `header()` export.

Browser extraction functions return Promises and must be awaited. When migrating
from v0.5.7 or earlier, add `await` (or use `.then(...)`) for every extraction
call. `version()` remains synchronous.

## Reports

`supportedBrowsers()`, `browserProfiles()`, `browserReport()`, and
`loadReport()` cover every installation and profile of a browser and keep
failures visible, instead of returning one source's cookies as a flat array.

```js
import { browserProfiles, browserReport } from "rookie-cookies";

const profiles = await browserProfiles("chrome");
// An explicit profile ID restricts the report to that profile; passing
// `undefined` means every profile, so guard the empty case rather than
// reaching for `profiles[0]?.profile.profileId`.
const report = await browserReport("chrome", profiles[0].profile.profileId);
```

Cookies stay attached to the source they came from, alongside that source's
status, acquisition strategy, counters, and diagnostics. See
[the Node binding README](../bindings/node/README.md#reports) for the object
shapes and the rules for reading them.

For Chrome, `chromeProfiles()` puts the preferred active profile first without
changing `browserProfiles("chrome")` or legacy `chrome()`. Missing or invalid
activity hints safely fall back to default-first order. Pass a returned profile
ID, display name, directory name, or a full path whose descriptor has
`profile.pathLossy === false` to `chromeProfile()`; lossy paths require the
profile ID. It returns the grouped report so source provenance and typed issues
remain visible.

The CLI keeps the generic contract: list with
`--list-profiles --browser chrome`, then select by opaque ID with
`--report --browser chrome --profile PROFILE_ID`.

## Explicit paths and cookie context

Use `cookiesFromPath(path, domains)` for a path that may be Firefox or
Chromium. Use the Chromium-specific API to select credentials explicitly:

```js
import { chromiumCookiesFromPath, cookiesFromPath } from "rookie-cookies";

const firefox = await cookiesFromPath("/path/to/cookies.sqlite", ["example.com"]);
const chrome = await chromiumCookiesFromPath(
  "/path/to/Chrome/Default/Network/Cookies",
  { browserId: "chrome", domains: ["example.com"] },
);
```

Chromium options accept at most one of `browserId`, `localStatePath`, or
`plaintextOnly: true`. `null`, omitted fields, and `plaintextOnly: false` mean
omission; zero selectors selects Automatic. Automatic probes platform
credentials on Linux and macOS; on Windows an explicit Chromium path rejects
with `missing_local_state_file` because it does not guess a browser
installation. Invalid option shapes reject their Promise with `TypeError`
before database I/O; the functions never throw synchronously. Process shutdown
is not exposed by the Node binding.

### Timeouts and cancellation

`cookiesFromPath`, `chromiumCookiesFromPath`/`chromiumCookiesFromPathDetailed`,
and every single-browser export (`firefox`, `chrome`, `brave`, ...) accept
extra `timeoutMs` and `cancellation` arguments. `cancellation` is a
`CancellationHandle`, safe to `cancel()` from the JS main thread while
extraction runs on the worker threadpool:

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

Cancellation and timeouts are checked cooperatively, so they take effect
mid-extraction rather than only before it starts, but a single long-running
step is not interrupted mid-step.

`anyBrowser()`, the Chromium `*Based` pair, and flat `firefoxBased()` are
deprecated in 0.6 for removal no earlier than 0.7. Their 0.6 behavior remains
unchanged, and `firefoxBasedDetailed()` is not deprecated.

Use `firefoxBasedDetailed()` or `chromiumBasedDetailed()` when partition or
container identity matters. Detailed records contain the unchanged legacy
cookie object and a separate context object:

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

The third Unix argument is a canonical browser ID from `supportedBrowsers()`.
It resolves the correct Linux keyring crypt name or macOS Keychain
service/account. It may be omitted only for a plaintext-only database;
encrypted rows reject explicitly.
