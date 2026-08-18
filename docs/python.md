# rookie-cookies Python Docs

This is the **canonical Python guide** in the git repo (tutorial, 0.5.6 API,
migrate 0.5.6 → 0.6.0). The [PyPI README](../bindings/python/README.md) is the
registry landing page: short `jar` / `read` plus report-DTO field notes.

This tree may still publish as `0.6.0-alpha.x`. The recommended entry is `jar`
/ `read` per [ADR 0004](adr/0004-read-is-the-recommended-entry.md).

## Install (0.6.0)

CPython **3.11 or newer** is required. Wheels use the `cp311-abi3` stable ABI and
are tested on CPython 3.11–3.14. CPython 3.8–3.10 and PyPy are not supported in
0.6.

```console
pip3 install -U rookie-cookies
```

## Recommended 0.6.0 usage

```python
import http.cookiejar
import requests
import rookie_cookies as cookies

# Session import. Pass profile= so session cookies are included.
session = requests.Session()
session.cookies = cookies.jar(browser="chrome", profile="Default")

# Domain-intact records for storage_state / allowlists
rows = cookies.read(browser="chrome", profile="Work").as_list()

# Cookie request-header *view* over an unfiltered snapshot
header = cookies.read(browser="chrome", profile="Default").header(
    "https://example.com/"
)
```

`read` never URL-filters the snapshot. `jar` is sugar for `read(...).as_jar()`
and loads every acquired record into `http.cookiejar`; the stdlib owns
send-match. There is **no** top-level `header()` export — call
`ReadResult.header(url)` on a snapshot you already took.

### Profile selection and session cookies

- No-profile `read(browser="chrome")` matches `chrome()` (persistent /
  legacy-eligible cookies only).
- Naming a profile includes session cookies, so
  `read(browser="chrome", profile="Default")` can return more cookies than
  omitting the profile.
- Session import (including NotebookLM-style flows) should pass `profile=`.

Named helpers such as `chrome()`, `firefox()`, and `load()` remain supported
compatibility APIs. Prefer `read` / `jar` for new code.

### Explicit paths

For a path whose browser engine is not known in advance, use
`cookies_from_path`. For Chromium, use `chromium_cookies_from_path` with at most
one credential selector (`browser_id`, `local_state_path`, or
`plaintext_only=True`):

```python
import rookie_cookies

cookies = rookie_cookies.cookies_from_path("/path/to/cookies.sqlite")
records = rookie_cookies.chromium_cookies_from_path_detailed(
    "/path/to/Chrome/Default/Network/Cookies",
    {"browser_id": "chrome", "domains": ["example.com"]},
)
```

Request faults on these path APIs raise `RookieRequestError` (a `ValueError`
subclass). Engine failures raise `RookieEngineError` (a `RuntimeError`
subclass).

### Reports and profiles

```python
import rookie_cookies

# Job-layer aliases
descriptors = rookie_cookies.profiles("chrome")
report = rookie_cookies.report(browser="chrome", profile="Default")

# Compatibility report surface (same DTO shape)
legacy = rookie_cookies.browser_report("chrome")
print(legacy["status"], legacy["summary"]["cookies_emitted"])
```

`supported_browsers()` lists registration (not detection).
`browser_profiles(browser_id)` / `profiles(browser_id)` list what is installed.
Snake_case report keys, `schema_version`, `termination`, and issue sampling:
[bindings/python/README.md](../bindings/python/README.md#reports).

### Timeouts and cancellation

`cookies_from_path` accepts optional `timeout` (seconds) and `cancellation`
keyword arguments; Chromium path options accept the same keys. `read` / `jar`
also accept `timeout` and `cancellation`:

```python
import threading
import rookie_cookies

cancellation = rookie_cookies.CancellationHandle()
threading.Timer(5, cancellation.cancel).start()

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
```

### Deprecated path helpers (still present in 0.6)

`any_browser()`, the Chromium `*_based` pair, and flat `firefox_based()` are
deprecated for removal no earlier than 0.7. Prefer `cookies_from_path` /
`chromium_cookies_from_path`. `firefox_based_detailed()` remains supported for
container context.

## 0.5.6 API

In the 0.5.6 line (and the early maintained-fork 0.5.7 docs), the public Python
surface was the flat named-browser helpers. There was no `read` / `jar` job API,
no typed `RookieRequestError` / `RookieEngineError` split on path APIs, and no
canonical `cookies_from_path` / `chromium_cookies_from_path` builders.

Typical 0.5.6-style usage:

```python
import rookie_cookies

# Flat first-profile selection; domain filter optional
cookies = rookie_cookies.chrome()
cookies = rookie_cookies.firefox(["example.com"])
cookies = rookie_cookies.brave(["github.com"])

# Merge every registered browser the loader knows about
all_cookies = rookie_cookies.load()

# Convert to http.cookiejar for requests / urllib
jar = rookie_cookies.to_cookiejar(cookies)

# Explicit legacy path helpers (still present, now deprecated in 0.6)
path_cookies = rookie_cookies.firefox_based("/path/to/cookies.sqlite")
```

Install at that era required a much older Python floor than 0.6 (`requires-python`
went as low as 3.7 upstream; the fork’s 0.5.7 line already tested 3.11+, but
wheels were still `cp38-abi3` until the 0.6 break).

## Migrate 0.5.6 → 0.6.0

| Area | 0.5.6 / early 0.5.x | 0.6.0 |
| --- | --- | --- |
| Recommended entry | `chrome()` / `firefox()` / `to_cookiejar(...)` | `jar(browser=..., profile=...)` or `read(...).as_list()` |
| Session cookies | Not a first-class `profile=` switch on a job API | Pass `profile=` to `read` / `jar` |
| CPython | 3.8-era / `cp38-abi3` wheels | **≥ 3.11**, `cp311-abi3` wheels |
| Path APIs | `firefox_based`, `chromium_based`, `any_browser` | Prefer `cookies_from_path` / `chromium_cookies_from_path`; legacy helpers deprecated until ≥ 0.7 |
| Path request faults | Often a flat `RuntimeError` | `RookieRequestError` (`ValueError` subclass) for bad input on the three path APIs; `except RuntimeError` alone no longer catches those |
| Header view | Build manually / `to_cookiejar` | `ReadResult.header(url)` — **no** module-level `header()` |
| Reports | Not in 0.5.6 | `report(...)` / `browser_report(...)`, `profiles(...)` |

Concrete migration steps:

1. **Bump the runtime** to CPython 3.11+.
2. **Replace session-import call sites** that did
   `to_cookiejar(chrome())` with `jar(browser="chrome", profile="Default")`
   (or another discovered profile name / id / path).
3. **Keep named helpers** (`chrome()`, `load()`, …) only where you truly want
   the frozen compatibility set (no-profile, persistent / legacy-eligible).
4. **Move explicit DB paths** from `*_based` / `any_browser` to
   `cookies_from_path` or `chromium_cookies_from_path`.
5. **Update exception handlers** around path APIs to catch
   `RookieRequestError` (and optionally `RookieEngineError`) instead of only
   `RuntimeError`.
6. Do **not** invent a top-level `header()` — use `read(...).header(url)`.

See [CHANGELOG.md](../CHANGELOG.md) for the full 0.6.0 breaking/compat list.

## Logging

```python
import logging
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
```

To fully disable `rookie_cookies` logging set the level to `CRITICAL`:

```python
import logging
logging.getLogger().setLevel(logging.CRITICAL)
```
