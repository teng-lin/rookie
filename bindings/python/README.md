# rookie-cookies

Extract cookies from web browsers
Bindings for [rookie-cookies](https://github.com/teng-lin/rookie-cookies)

CPython 3.11 or newer is required. Published wheels use the `cp311-abi3`
stable ABI and are tested on CPython 3.11–3.14.

## Usage

```python
from rookie_cookies import chrome
cookies = chrome()
for cookie in cookies:
    print(cookie['domain'], cookie['name'])
```

## Firefox profiles

```python
from rookie_cookies import firefox_profile, firefox_profiles

for profile in firefox_profiles():
    print(profile["name"], profile["path"], profile["is_default"])

cookies = firefox_profile("work", ["example.com"])
```

## Chrome profiles

`chrome()` keeps its legacy default-first selection. Use the additive APIs to
prefer Chrome's advisory active-profile hints while retaining report metadata:

```python
from rookie_cookies import chrome_profile, chrome_profiles

profiles = chrome_profiles()
if profiles:
    report = chrome_profile(profiles[0]["profile"]["profile_id"], ["example.com"])
    print(report["status"])
```

Missing or malformed hints fall back to the generic order. A selector may also
be a display name, directory name, or a full path when
`descriptor["profile"]["path_lossy"]` is false; lossy paths require the profile
ID. Ambiguous names raise instead of silently choosing a channel.

## Browser registry and reports

```python
from rookie_cookies import browser_profiles, browser_report, supported_browsers

for browser in supported_browsers():
    print(browser["id"], browser["display_name"], browser["engine"])

for profile in browser_profiles("chrome"):
    print(profile["profile"]["profile_id"], profile["profile"]["display_name"])

report = browser_report("chrome", domains=["example.com"])
assert report["schema_version"] == 1
for profile in report["profiles"]:
    for source in profile["sources"]:
        if source["selected"] and source["status"] == "succeeded":
            print(source["source"]["path"], len(source["cookies"]))
```

Reports keep failures visible instead of raising: a registered browser that is
not installed is a report with status `no_sources`, and problems arrive as
`issues` on the report, a profile, or a source. Only a bad request — an unknown
browser ID or a profile ID this browser did not yield — raises, as a
`RuntimeError` whose message is a diagnostic rather than a stable contract.
`load_report()` covers every registered browser in one report.

An issue counts every occurrence in `occurrences` but keeps at most
`MAX_ISSUE_SAMPLES` entries in `samples`; comparing the two tells a truncated
excerpt from a complete one.

Every identifier and code (`status`, `engine`, `role`, `format`, `severity`, …)
is an open snake_case string, so compare against a known value and keep a
fallback: a build newer than your code can return one you have not seen.

## Explicit paths

Use `cookies_from_path()` when the file may be Firefox or Chromium. Use the
Chromium-specific functions when selecting credentials explicitly:

```python
from rookie_cookies import chromium_cookies_from_path, cookies_from_path

firefox = cookies_from_path("/path/to/cookies.sqlite", ["example.com"])
chrome = chromium_cookies_from_path(
    "/path/to/Chrome/Default/Network/Cookies",
    {"browser_id": "chrome", "domains": ["example.com"]},
)
```

Chromium options accept at most one credential selector: `browser_id`,
`local_state_path`, or `plaintext_only=True`. Omitting all three selects
Automatic credentials. Automatic probes platform credentials on Linux and
macOS; on Windows an explicit Chromium path raises `RuntimeError` with the core
`missing_local_state_file` diagnostic because it does not guess a browser
installation.
`chromium_cookies_from_path_detailed()` returns the same cookies with
partition/source context.

## Compatibility direct-path functions

```python
from rookie_cookies import chromium_based_detailed, firefox_based_detailed

chromium_records = chromium_based_detailed(
    "/path/to/Brave/Default/Network/Cookies",
    ["example.com"],
    browser_id="brave",
)
firefox_records = firefox_based_detailed("/path/to/cookies.sqlite")
```

Each record contains the familiar cookie dictionary under `cookie` and a
separate `context` dictionary. Existing functions and cookie dictionaries are
unchanged. On Unix, `chromium_based()` also accepts `browser_id` as its third
argument. Omit it only for plaintext-only databases; encrypted rows fail rather
than using an assumed Chrome identity.

`any_browser()`, `chromium_based()` and its detailed twin, and flat
`firefox_based()` are deprecated in 0.6 for removal no earlier than 0.7. Their
runtime behavior remains unchanged throughout 0.6.x. The detailed Firefox API
is not deprecated because there is no generic detailed Mozilla replacement.

## Netscape export

```python
from rookie_cookies import chrome, to_netscape

output = to_netscape(chrome())
```

The serializer prevents extra columns or forged records by encoding tabs,
carriage returns, and line feeds in cookie-controlled fields as `%09`, `%0D`,
and `%0A`. Every other character is preserved. Its output is byte-identical to
the Rust, CLI, and Node serializers for the same cookies.
