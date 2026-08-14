# rookie-cookies JavaScript Docs

## Install

```console
npm install rookie-cookies
```

## Basic Usage

```js
import { brave } from "rookie-cookies";
const cookies = await brave();
```

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
