# rookie-cookies

Extract cookies from web browsers
Bindings for [rookie-cookies](https://github.com/teng-lin/rookie-cookies)

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
be a display name, directory name, or full path; ambiguous names raise instead
of silently choosing a channel.

## Browser registry and reports

```python
from rookie_cookies import browser_profiles, browser_report, supported_browsers

for browser in supported_browsers():
    print(browser["id"], browser["display_name"], browser["engine"])

for profile in browser_profiles("chrome"):
    print(profile["profile"]["profile_id"], profile["profile"]["display_name"])

report = browser_report("chrome", domains=["example.com"])
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

## Netscape export

```python
from rookie_cookies import chrome, to_netscape

output = to_netscape(chrome())
```

The serializer prevents extra columns or forged records by encoding tabs,
carriage returns, and line feeds in cookie-controlled fields as `%09`, `%0D`,
and `%0A`. Every other character is preserved. Its output is byte-identical to
the Rust, CLI, and Node serializers for the same cookies.
