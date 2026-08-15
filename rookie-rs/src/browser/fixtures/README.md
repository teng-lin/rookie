# Firefox sessionstore captures

These are exact base64 encodings of `sessionstore-backups/recovery.jsonlz4`
files emitted by clean, disposable Firefox profiles. The profiles were never
signed in and visited only a loopback cookie test page. No fixture field was
edited after capture.

| Fixture | Official build | Build ID | Raw bytes | SHA-256 |
| --- | --- | --- | ---: | --- |
| `firefox-141.0-recovery.jsonlz4.base64` | [Firefox 141.0 macOS en-US](https://archive.mozilla.org/pub/firefox/releases/141.0/mac/en-US/Firefox%20141.0.dmg) | `20250717180000` | 1,111 | `359602096db47f6d54a0a1d454844abdb604df99c1b26973f22c9dda6ea8bc2d` |
| `firefox-142.0-recovery.jsonlz4.base64` | [Firefox 142.0 macOS en-US](https://archive.mozilla.org/pub/firefox/releases/142.0/mac/en-US/Firefox%20142.0.dmg) | `20250811145442` | 1,091 | `07e4925c9bb594204cafb652cf8f451eda09ad4877173767b81d5d4163434062` |

Capture date: 2026-08-14. Each official DMG was mounted read-only and its
Firefox binary was launched headless with `--no-remote --profile <new-temp-dir>`
against the loopback page. The fixture was copied only after Firefox wrote a
non-empty recovery file. Checksums above cover the decoded raw mozLz4 bytes.

The captures establish the modern root-level `cookies` layout independently of
generated unit data. Firefox 141 also emitted a 13-digit session-cookie expiry
while its schema-15 `cookies.sqlite` persistent expiries remained seconds;
Firefox 142 emitted the same root layout with those session expiry fields
absent. This is why session expiry is classified conservatively by magnitude
and is not keyed to the persistent database schema.

Relevant upstream implementation:

- [Firefox 141 SessionStore assigns `state.cookies`](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_141_0_RELEASE/browser/components/sessionstore/SessionStore.sys.mjs)
- [Firefox 142 SessionStore assigns `state.cookies`](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_142_0_RELEASE/browser/components/sessionstore/SessionStore.sys.mjs)
- [Firefox 141 `nsICookie.expiry` contract](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_141_0_RELEASE/netwerk/cookie/nsICookie.idl)
- [Firefox 142 `nsICookie.expiry` contract](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_142_0_RELEASE/netwerk/cookie/nsICookie.idl)
- [Mozilla bug 1972757: persistent-cookie millisecond migration](https://bugzilla.mozilla.org/show_bug.cgi?id=1972757)
