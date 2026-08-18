# rookie-cookies (Python)

Extract cookies from local browsers on Linux, macOS, and Windows.

This file is the **PyPI landing page**. The canonical Python guide — recommended
0.6 `jar` / `read`, the 0.5.6 call shape, and **migrate 0.5.6 → 0.6.0** — is
[`docs/python.md`](https://github.com/teng-lin/rookie-cookies/blob/main/docs/python.md)
in the repo. Report field semantics below are the binding-specific detail that
page points at.

CPython **≥ 3.11**. Wheels are `cp311-abi3` (tested 3.11–3.14).

```console
pip install rookie-cookies
```

## Recommended 0.6 entry

```python
import rookie_cookies as cookies

# Session import — pass profile= for session cookies
session_jar = cookies.jar(browser="chrome", profile="Default")

# Domain-intact records (storage_state / allowlists)
rows = cookies.read(browser="chrome", profile="Work").as_list()
header = cookies.read(browser="chrome", profile="Default").header(
    "https://example.com/"
)
```

`jar` is `read(...).as_jar()`. `read` never URL-filters. There is no module-level
`header()`. Named helpers (`chrome()`, `firefox()`, `load()`) still work; they
are the compatibility bridge from
[`thewh1teagle/rookie`](https://github.com/thewh1teagle/rookie) and will break
in a later major version.

Coming from 0.5.6 `chrome()` / `to_cookiejar`? Use the
[migration section](https://github.com/teng-lin/rookie-cookies/blob/main/docs/python.md#migrate-056--060).

## Reports

`read` / `chrome()` flatten one source. Reports keep every profile and failure
visible. Identifiers and codes are open snake_case strings.

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

A missing install is `status == "no_sources"`, not an empty success. Bad
requests (unknown browser / profile) raise `RookieRequestError`. Engine
failures raise `RookieEngineError`. `schema_version` versions the DTO; reject
unknown values. `termination` (`completed`, `timed_out`, `cancelled`,
`resource_exhausted`) is independent of `status`. Issues count every hit in
`occurrences` but keep at most `MAX_ISSUE_SAMPLES` in `samples`.

`profiles(browser_id)` aliases `browser_profiles`. `report(browser=..., profile=...)`
is the job-layer name for `browser_report`. `load_report()` covers every
registered browser.

`chrome()` stays default-first. `chrome_profiles()` / `chrome_profile()` add
activity-hint order and a grouped report; lossy paths need the opaque
`profile_id`.

## Explicit paths

```python
from rookie_cookies import chromium_cookies_from_path, cookies_from_path

firefox = cookies_from_path("/path/to/cookies.sqlite", ["example.com"])
chrome = chromium_cookies_from_path(
    "/path/to/Chrome/Default/Network/Cookies",
    {"browser_id": "chrome", "domains": ["example.com"]},
)
```

At most one of `browser_id`, `local_state_path`, `plaintext_only=True`. Zero
selectors is Automatic (Linux/macOS platform keys; Windows Chromium paths raise
`missing_local_state_file` instead of guessing). Request faults on these three
path APIs are `RookieRequestError`, not a bare `RuntimeError`.

`any_browser()`, `chromium_based*`, and flat `firefox_based()` are deprecated
until ≥ 0.7. `firefox_based_detailed()` stays for container context.

## Netscape

```python
from rookie_cookies import chrome, to_netscape

output = to_netscape(chrome())
```

Tabs / CR / LF in cookie fields become `%09` / `%0D` / `%0A`. Same bytes as
Rust, CLI, and Node for the same cookies.

## More

- Guide + 0.5.6 migration: [docs/python.md](https://github.com/teng-lin/rookie-cookies/blob/main/docs/python.md)
- Build / test: [docs/building.md](https://github.com/teng-lin/rookie-cookies/blob/main/docs/building.md),
  [docs/testing.md](https://github.com/teng-lin/rookie-cookies/blob/main/docs/testing.md)
- Source: [teng-lin/rookie-cookies](https://github.com/teng-lin/rookie-cookies)
