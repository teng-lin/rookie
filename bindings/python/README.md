# rookie-cookies (Python)

Extract cookies from local browsers on Linux, macOS, and Windows.

This file is the **Python guide** (PyPI landing page and repo tutorial). Rust
stays in [`rookie-rs/README.md`](https://github.com/teng-lin/rookie-cookies/blob/main/rookie-rs/README.md).
The workspace is currently `0.6.0-beta.1`. The recommended 0.6 entry is
`jar` / `read` ([ADR 0004](https://github.com/teng-lin/rookie-cookies/blob/main/docs/adr/0004-read-is-the-recommended-entry.md)).

CPython **≥ 3.11**. Wheels are `cp311-abi3` (tested 3.11–3.14). CPython 3.8–3.10
and PyPy are not supported in 0.6.

```console
pip install rookie-cookies
```

## Recommended 0.6.0 usage

```python
import rookie_cookies as cookies

# Gecko session import — select the profile whose session JSON should be read
session_jar = cookies.jar(browser="firefox", profile="default-release")

# Domain-intact records (storage_state / allowlists)
rows = cookies.read(browser="chrome", profile="Work").as_list()
header = cookies.read(browser="chrome", profile="Default").header(
    "https://example.com/"
)
```

`jar` is `read(...).as_jar()`. `read` never URL-filters; `http.cookiejar` owns
send-match. There is **no** module-level `header()` — call
`ReadResult.header(url)` on a snapshot you already took.

- No-profile `read(browser="chrome")` matches `chrome()` (persistent /
  legacy-eligible cookies).
- A Gecko profile includes its separately declared session JSON source.
- Chromium registrations have no separate session source; selecting a Chrome
  profile cannot recover session state that exists only in browser memory.

Named helpers (`chrome()`, `firefox()`, `load()`) still work. They are the
compatibility bridge from
[`thewh1teagle/rookie`](https://github.com/thewh1teagle/rookie) and will break
in a later major version. Prefer `read` / `jar` for new code.

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

Job-layer aliases (same DTO):

```python
import rookie_cookies

descriptors = rookie_cookies.profiles("chrome")
report = rookie_cookies.report(browser="chrome", profile="Default")
```

A missing install is `status == "no_sources"`, not an empty success. Bad
requests raise `RookieRequestError`. Engine failures raise `RookieEngineError`.
`schema_version` versions the DTO; reject unknown values. `termination`
(`completed`, `timed_out`, `cancelled`, `resource_exhausted`) is independent of
`status`. Issues count every hit in `occurrences` but keep at most
`MAX_ISSUE_SAMPLES` in `samples`.

`supported_browsers()` is registration, not detection.
`chrome()` stays default-first. `chrome_profiles()` / `chrome_profile()` add
activity-hint order and a grouped report; lossy paths need the opaque
`profile_id`. `load_report()` covers every registered browser.

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

## Timeouts and cancellation

`read` / `jar` / `cookies_from_path` take `timeout` (seconds) and
`cancellation`. Chromium path options accept the same keys.

```python
import threading
import rookie_cookies

cancellation = rookie_cookies.CancellationHandle()
timer = threading.Timer(5, cancellation.cancel)
timer.start()

try:
    rows = rookie_cookies.read(
        browser="chrome",
        profile="Default",
        timeout=30,
        cancellation=cancellation,
    ).as_list()
except RuntimeError as error:
    if "operation deadline expired" in str(error):
        print("timed out")
    elif "operation cancelled" in str(error):
        print("cancelled")
    else:
        raise
finally:
    timer.cancel()
```

## Netscape

```python
from rookie_cookies import chrome, to_netscape

output = to_netscape(chrome())
```

Tabs / CR / LF in cookie fields become `%09` / `%0D` / `%0A`. Same bytes as
Rust, CLI, and Node for the same cookies.

## 0.5.6 API

In the 0.5.6 line the public surface was the flat named-browser helpers. There
was no `read` / `jar` job API, no typed `RookieRequestError` /
`RookieEngineError` split, and no canonical path builders.

```python
import rookie_cookies

cookies = rookie_cookies.chrome()
cookies = rookie_cookies.firefox(["example.com"])
all_cookies = rookie_cookies.load()
jar = rookie_cookies.to_cookiejar(cookies)
path_cookies = rookie_cookies.firefox_based("/path/to/cookies.sqlite")
```

Wheels were `cp38-abi3` until the 0.6 break.

## Migrate 0.5.6 → 0.6.0

| Area | 0.5.6 / early 0.5.x | 0.6.0 |
| --- | --- | --- |
| Recommended entry | `chrome()` / `to_cookiejar(...)` | `jar(browser=..., profile=...)` or `read(...).as_list()` |
| Gecko session cookies | Not a first-class `profile=` | Pass `profile=` to `read` / `jar` for a Gecko browser |
| CPython | 3.8-era / `cp38-abi3` | **≥ 3.11**, `cp311-abi3` |
| Path APIs | `firefox_based`, `chromium_based`, `any_browser` | `cookies_from_path` / `chromium_cookies_from_path` (legacy deprecated until ≥ 0.7) |
| Path request faults | Flat `RuntimeError` | `RookieRequestError` (`ValueError` subclass) |
| Header view | Manual / `to_cookiejar` | `ReadResult.header(url)` — **no** module-level `header()` |
| Reports | Not in 0.5.6 | `report(...)` / `browser_report(...)`, `profiles(...)` |

1. Bump to CPython 3.11+.
2. For Gecko session import, use `jar(browser="firefox", profile="default-release")`.
3. Keep named helpers only for the frozen compatibility set.
4. Move explicit DB paths off `*_based` / `any_browser`.
5. Catch `RookieRequestError` (and optionally `RookieEngineError`).
6. Do not invent a top-level `header()`.

See [CHANGELOG.md](https://github.com/teng-lin/rookie-cookies/blob/main/CHANGELOG.md).

## Logging

```python
import logging
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
```

Disable with `logging.CRITICAL`.

## More

- [docs/building.md](https://github.com/teng-lin/rookie-cookies/blob/main/docs/building.md)
- [docs/testing.md](https://github.com/teng-lin/rookie-cookies/blob/main/docs/testing.md)
- [teng-lin/rookie-cookies](https://github.com/teng-lin/rookie-cookies)
