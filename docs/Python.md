# rookie-cookies Python Docs

## Install

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
