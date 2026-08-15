# rookie-cookies Python Docs

## Install

CPython 3.11 or newer is required. Wheels use the `cp311-abi3` stable ABI and
are tested on CPython 3.11–3.14.

```console
pip3 install -U rookie-cookies
```

## Basic Usage

```python
import rookie_cookies
cookies = rookie_cookies.chrome() # Load cookies from Chrome
```

## Reports

`chrome()` and its siblings return a flat cookie list and raise on failure.
The report API instead covers every installation and profile of a browser and
keeps failures visible:

```python
import rookie_cookies

report = rookie_cookies.browser_report("chrome")  # or load_report() for all browsers
print(report["status"], report["summary"]["cookies_emitted"])

for profile in report["profiles"]:
    for source in profile["sources"]:
        if source["selected"] and source["status"] == "succeeded":
            print(source["source"]["path"], len(source["cookies"]))
```

`supported_browsers()` lists what this build knows about (registration, not
detection) and `browser_profiles(browser_id)` lists what is actually installed,
including the `profile_id` that `browser_report(browser_id, profile_id)` takes.

For Chrome, `chrome_profiles()` lists the preferred active profile first while
leaving `browser_profiles("chrome")` and the legacy `chrome()` selector
unchanged. Activity hints are advisory and safely fall back to default-first
ordering. `chrome_profile(profile, domains=None)` accepts an ID, display name,
directory name, or a full path when
`descriptor["profile"]["path_lossy"]` is false; lossy paths require the opaque
ID. It returns the same provenance-preserving report shape as `browser_report`.

The CLI intentionally keeps the generic frozen grammar: use
`--list-profiles --browser chrome`, then pass its opaque `profile_id` to
`--report --browser chrome --profile PROFILE_ID`.

Every DTO is a dictionary with snake_case keys, and every identifier or code is
an open snake_case string rather than a closed set, so keep a fallback when
matching one.

## Explicit paths and cookie context

For a path whose browser engine is not known in advance, use
`cookies_from_path(path, domains=None)`. For Chromium, the canonical options
dictionary accepts `domains` and at most one optional credential selector:
`browser_id`, `local_state_path`, or `plaintext_only=True`. Zero selectors
selects Automatic. Automatic probes platform credentials on Linux and macOS;
on Windows an explicit Chromium path raises the core
`missing_local_state_file` error because it does not guess a browser
installation.

```python
import rookie_cookies

cookies = rookie_cookies.cookies_from_path("/path/to/cookies.sqlite")
records = rookie_cookies.chromium_cookies_from_path_detailed(
    "/path/to/Chrome/Default/Network/Cookies",
    {"browser_id": "chrome", "domains": ["example.com"]},
)
```

Unknown options, wrong types, or competing selectors raise `ValueError` before
the database is touched. Extraction failures raise `RuntimeError` with the Rust
error chain preserved.

The older functions below remain behavior-compatible in 0.6.x, but
`any_browser()`, the Chromium `*_based` pair, and flat `firefox_based()` are
deprecated for removal no earlier than 0.7. `firefox_based_detailed()` is not
deprecated.

`firefox_based_detailed()` and `chromium_based_detailed()` return an unchanged
cookie dictionary under `cookie` plus a separate `context` dictionary. Context
retains Chromium partition and source fields and Firefox's raw
`originAttributes` plus parsed container, partition, and private-browsing IDs.

```python
import rookie_cookies

records = rookie_cookies.chromium_based_detailed(
    "/path/to/Brave/Default/Network/Cookies",
    ["example.com"],
    browser_id="brave",
)
for record in records:
    print(record["cookie"]["name"], record["context"]["top_frame_site_key"])
```

On Linux and macOS, pass a canonical `browser_id` from
`supported_browsers()`. It selects the correct Linux keyring crypt name or
macOS Keychain service/account. The argument may be omitted only for a
plaintext-only database; encrypted rows raise an explicit error.

## Logging

Logging level can be controlled by using the `logging` module

```python
import logging
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
```

To fully disable `rookie_cookies` logging you can set the level to `CRITICAL`

```python
import logging
logging.getLogger().setLevel(logging.CRITICAL)
```
