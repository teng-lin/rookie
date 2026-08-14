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

## Chrome profiles

`chrome()` keeps its legacy default-first selection. `chromeProfiles()` instead
uses Chrome's advisory activity hints and safely falls back to generic order
when they are missing or invalid. `chromeProfile()` returns a grouped report,
so profile/source provenance and typed issues remain visible.

```typescript
import { chromeProfile, chromeProfiles } from "rookie-cookies";

const profiles = await chromeProfiles();
if (profiles.length > 0) {
  const report = await chromeProfile(profiles[0].profile.profileId, ["example.com"]);
  console.log(report.status);
}
```

Profile IDs and full paths are unambiguous. A repeated display or directory
name rejects instead of silently choosing a channel.

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
if (profiles.length === 0) {
  return;
}

// Passing an explicit profile ID restricts the report to that profile. Do not
// reach for `profiles[0]?.profile.profileId` here: on an empty list that yields
// `undefined`, which is the "every profile" argument, so the query silently
// widens instead of returning nothing.
const report = await browserReport("chrome", profiles[0].profile.profileId, ["example.com"]);

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
the same as what is installed. `loadReport()` is the report-shaped counterpart
to `load()` and covers every registered browser rather than `load()`'s
historical set.

The two browser-scoped functions reject only on a bad request:

- `browserProfiles(browserId)` rejects an unknown ID or alias, and also rejects
  when every detected installation root failed enumeration — an empty list there
  would be indistinguishable from "not installed", and `browserReport` carries
  the per-root diagnostics for that case. One failing root among several does
  not hide the profiles the others yielded.
- `browserReport(browserId, profileId)` rejects an unknown ID or alias, and a
  `profileId` this browser did not yield.

A registered browser that is simply absent is not an error: it resolves to an
empty profile list, or to a report whose `status` is `no_sources`. Extraction
failures are likewise not errors — they arrive as a resolved report whose
`status` and `issues` describe them.

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
