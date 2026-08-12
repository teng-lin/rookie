# rookie-cookies

Extract cookies from web browsers
Bindings for [rookie-cookies](https://github.com/teng-lin/rookie-cookies)

Browser extraction functions return Promises and must be awaited. When migrating
from v0.5.7 or earlier, add `await` (or use `.then(...)`) for every extraction
call. `version()` remains synchronous.

## Usage

```typescript
import { chrome } from "rookie-cookies";

const cookies = await chrome();
for (const cookie of cookies) {
  console.log(cookie);
}
```

## Firefox profiles

```typescript
import { firefoxProfile, firefoxProfiles } from "rookie-cookies";

for (const profile of await firefoxProfiles()) {
  console.log(profile.name, profile.path, profile.isDefault);
}

const cookies = await firefoxProfile("work", ["example.com"]);
```

## Reports

The named functions above return a flat cookie array from one source. The
report APIs instead cover every installation and profile of a browser and keep
failures visible: cookies stay attached to the source they came from, alongside
that source's status, acquisition strategy, counters, and diagnostics.

```typescript
import { browserProfiles, browserReport, loadReport, supportedBrowsers } from "rookie-cookies";

for (const browser of await supportedBrowsers()) {
  console.log(browser.id, browser.displayName, browser.capabilities.availableDecryptionTiers);
}

const profiles = await browserProfiles("chrome");
const report = await browserReport("chrome", profiles[0]?.profile.profileId, ["example.com"]);

console.log(report.status, report.summary.cookiesEmitted);
for (const profile of report.profiles) {
  for (const source of profile.sources) {
    if (source.selected && source.status === "succeeded") {
      console.log(profile.profile.displayName, source.source.path, source.cookies.length);
    }
  }
}
```

A profile's cookie stream is its `selected` sources whose `status` is
`succeeded`, concatenated in the order they appear. Both halves matter: a source
that was attempted and rejected in favour of another candidate can still report
`succeeded`, so filtering on status alone would double-count a profile whose
engine tried more than one candidate.

`supportedBrowsers()` lists what is registered for the running OS, which is not
the same as what is installed. `browserProfiles()` and `browserReport()` reject
an unknown browser ID, but a registered browser that is simply absent is not an
error: it resolves to an empty profile list, or to a report whose `status` is
`no_sources`. `loadReport()` is the report-shaped counterpart to `load()` and
covers every registered browser rather than `load()`'s historical set.

Every identifier and code — `status`, `role`, `format`, `acquisitionStrategy`,
issue `code`/`stage`/`severity` — is an open string, so compare against a known
value and keep a fallback branch rather than switching exhaustively. Every
counter is an ordinary JavaScript number, never a `BigInt`; a count that would
overflow is clamped and sets `countersSaturated`.

## Netscape export

```typescript
import { chrome, toNetscape } from "rookie-cookies";

const output = toNetscape(await chrome());
```

The serializer prevents extra columns or forged records by encoding tabs,
carriage returns, and line feeds in cookie-controlled fields as `%09`, `%0D`,
and `%0A`. Every other character is preserved.
