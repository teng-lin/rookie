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

# Gecko session import — select the profile AND opt into its session JSON
session_jar = cookies.jar(
    browser="firefox", profile="default-release", include_session=True
)

# Domain-intact records (storage_state / allowlists)
rows = cookies.read(browser="chrome", profile="Work").as_list()
header = cookies.read(browser="chrome", profile="Default").header(
    "https://example.com/"
)
```

`jar` is `read(...).as_jar()`. `read` never URL-filters; `http.cookiejar` owns
send-match. There is **no** module-level `header()` — call
`ReadResult.header(...)` on a snapshot you already took.

- No-profile `read(browser="chrome")` matches `chrome()` (persistent /
  legacy-eligible cookies).
- **`include_session` defaults to `False`.** Naming a Gecko `profile` alone no
  longer also acquires its separately declared session JSON source — pass
  `include_session=True` to `read()` / `jar()` for that. **Breaking change
  from 0.6-beta**, where naming a profile always included session cookies;
  this fails quietly (a smaller result, no error) — see CHANGELOG.md.
- Chromium registrations have no separate session source; `include_session`
  is a no-op there regardless.

Named helpers (`chrome()`, `firefox()`, `load()`) still work. They are the
compatibility bridge from
[`thewh1teagle/rookie`](https://github.com/thewh1teagle/rookie) and will break
in a later major version. Prefer `read` / `jar` for new code.

## Isolation-aware cookies

`ReadResult.as_list()` / `.cookies()` return the frozen eight-field
compatibility projection, which cannot represent a Chromium CHIPS partition
key or a Firefox Multi-Account Containers identity. `detailed_cookies()`
returns the native, isolation-intact records instead:

```python
snapshot = cookies.read(browser="firefox", profile="default-release")
for record in snapshot.detailed_cookies():
    cookie, context = record["cookie"], record["context"]
    print(cookie["domain"], cookie["name"], context["user_context_id"])
```

Each item is `{"cookie": <the same 8-field dict>, "context": {...}}`, where
`context` carries `top_frame_site_key`, `has_cross_site_ancestor`,
`source_scheme`, `source_port`, `is_persistent`, `origin_attributes`,
`user_context_id`, `partition_key`, and `private_browsing_id` — every field
optional, since browser schemas vary and a missing field means the source
never exposed it (not that the cookie has some default value).

Snapshot warnings (`ReadResult.warnings`, each `{"code": ..., "count": ...}`)
include two isolation-related codes: `malformed_host_identity` (a row whose
host did not survive decode was omitted from the snapshot, not emitted as
`domain: ""`) and `unparsable_partition_key` (retained in the snapshot, but
never matched by `header()` since its partition can't be identified).

## Sending cookies (`header`)

`ReadResult.header(...)` builds a send-safe `Cookie` request-header value. A
bare URL string covers the common case:

```python
header = snapshot.header("https://example.com/")
```

Partitioned or containered cookies need a `SendContext` shaped mapping, or the
equivalent keyword arguments, to say which browsing context the request is
from — otherwise `header()` would have to guess, and it refuses to:

```python
header = snapshot.header(
    "https://example.com/",
    top_level_site="https://example.com/",
    resource="navigation",   # or "subresource" (default)
    method="safe",           # or "unsafe" (default "safe")
    user_context_id=0,
    private_browsing_id=0,
)
```

The positional argument and the keyword arguments compose (an explicit keyword
wins over the same-named mapping entry), so
`header({"url": u, "top_level_site": t}, method="unsafe")` is also valid.
`now` overrides the send-time clock with epoch seconds, mainly for tests.

A snapshot that positively observes a partitioned or containered cookie
*demands* the matching selector rather than silently merging it with
unpartitioned/default-container cookies: omitting one raises
`RookieRequestError` with `code == "incomplete_send_context"` and a
`required` attribute naming exactly which selectors (e.g.
`["top_level_site"]`) were missing.

## Selecting profiles (`select`)

`read` / `jar` take `select: Literal["legacy_first"] = "legacy_first"` — the
only value they can express, since a snapshot has exactly one `profile_id`.
`browser_report` takes `select: Literal["legacy_first", "all"] = "all"`,
matching what `browser_report(id, None, domains)` has always meant. Passing
`profile=`/`profile_id=` together with `select="all"` (or passing
`select="all"` to `read`/`jar` at all) is a request error with
`code == "conflicting_profile_selection"`, raised before any I/O — naming one
profile and asking for every profile contradict each other.

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
requests raise `RookieRequestError`; other failures land in the report itself
rather than an exception (see [Errors](#errors)). `schema_version` versions
the DTO; reject unknown values. `termination`
(`completed`, `timed_out`, `cancelled`, `resource_exhausted`) is independent of
`status`. Issues count every hit in `occurrences` but keep at most
`MAX_ISSUE_SAMPLES` in `samples`.

`supported_browsers()` is registration, not detection.
`chrome()` stays default-first. `chrome_profiles()` / `chrome_profile()` add
activity-hint order and a grouped report; lossy paths need the opaque
`profile_id`. `load_report()` covers every registered browser.

## Explicit paths

`extract_from_path` is the canonical name for this job (Rust
`direct_path::extract_from_path`, Node `extractFromPath`, CLI
`from-path --domains`):

```python
from rookie_cookies import extract_from_path

firefox = extract_from_path("/path/to/cookies.sqlite", domains=["example.com"])
chrome = extract_from_path(
    "/path/to/Chrome/Default/Network/Cookies",
    domains=["example.com"],
    browser_id="chrome",
)
```

At most one of `browser_id`, `local_state_path`, `plaintext_only=True`. Zero
selectors identifies the source from its signature and schema, with an
encrypted Chromium row rejected (`missing_chromium_credentials`) rather than
guessed at — on every platform, including Windows, which previously required
`local_state_path` even for an all-plaintext database. Request faults on
this API are `RookieRequestError`, not a bare `RuntimeError`. `from_path`
accepts the same three credential selectors directly (as keyword arguments)
for a Chromium path.

`cookies_from_path` (positional `domains`, no credential selectors) and
`chromium_cookies_from_path` (an options dict) are deprecated aliases onto
`extract_from_path` — same behavior, kept for 0.6-beta callers, not removed
outright since deleting them this late buys nothing.

**`chromium_cookies_from_path_detailed` has no replacement of the same shape
and no longer accepts a `domains` option.** Isolation-aware output now comes
from the core's `from_path(..).detailed_cookies()`, which has no domain
filter of its own — a real narrowing, not a binding limitation. Passing
`domains` to `chromium_cookies_from_path_detailed` raises
`RookieRequestError`; use `extract_from_path` for a domain-filtered flat
list, or filter `from_path(..).detailed_cookies()`'s output yourself.

`any_browser()`, `chromium_based*`, and flat `firefox_based()` are deprecated
until ≥ 0.7. `firefox_based_detailed()` stays for container context.

## Timeouts and cancellation

`read` / `jar` / `extract_from_path` take `timeout` (seconds) and
`cancellation`.

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
except rookie_cookies.RookieStoppedError as error:
    if error.stop_reason == "timed_out":
        print("timed out")
    elif error.stop_reason == "cancelled":
        print("cancelled")
    else:
        raise
finally:
    timer.cancel()
```

## Windows App-Bound (v20) recovery

`read`, `from_path`, `browser_report`, and `load_report` all take an
`app_bound` keyword. It defaults to `"injection_only"`, because Chrome has
written App-Bound (v20) cookies on Windows since Chrome 127 — on a current
profile essentially every row is v20, so a policy that refused to recover them
would return an **empty** list for the most common Windows case.

```python
import rookie_cookies

# The default already recovers v20 on Windows.
rows = rookie_cookies.read(browser="chrome", profile="Default").as_list()

# Opt out if injection is unwanted; v20 rows are then skipped.
rows = rookie_cookies.read(
    browser="chrome",
    profile="Default",
    app_bound="disabled",
).as_list()
```

`app_bound` accepts:

| Value | What it does |
| --- | --- |
| `"injection_only"` (default) | Unprivileged reflective COM injection into a spawned browser process (Chrome 127+). |
| `"disabled"` | No injection, no spawned process, no process enumeration, no SYSTEM impersonation. v20 rows are skipped and counted as `decrypt_failed` warnings. |
| `"allow_elevated_fallback"` | Injection, then permits elevated SYSTEM impersonation as a fallback (Chrome 133+). Never a default. |

**`"injection_only"` is not free of consequence.** It spawns a browser process
and reflectively injects into it, which endpoint security products can flag.
On a managed machine where that matters, pass `"disabled"` explicitly and
expect v20 rows to be omitted.

It is a no-op off Windows — macOS and Linux Chrome use the Keychain and Secret
Service, which this policy has nothing to do with. An unrecognized string is a
`RookieRequestError` raised before any I/O. `browser_profiles` /
`chrome_profiles` do no App-Bound work and take no `app_bound` parameter at
all.

The deprecated v0.5.9 bridge functions (`chrome()`, `chromium_based()`, and
friends) keep `allow_elevated_fallback`, unchanged from 0.5.8. See
CHANGELOG.md.

## Errors

Every exception this module raises is a `RookieError`, and every one also
keeps a second, pre-existing base so old `except ValueError` / `except
RuntimeError` code keeps working:

| Class | Also subclasses | `kind` | Raised when |
| --- | --- | --- | --- |
| `RookieRequestError` | `ValueError` | `"request"` | Caller input was invalid (unknown browser/profile, bad option) |
| `RookieSourceError` (subclasses `RookieRequestError`) | `ValueError` | `"source"` | An explicit path/option did not identify a valid, supported cookie source |
| `RookieStoppedError` | `RuntimeError` | `"stopped"` | A `timeout` elapsed, `cancellation` fired, or an internal resource limit was hit |
| `RookieEngineError` | `RuntimeError` | `"engine"` | Discovery, acquisition, or decryption failed |

`RookieSourceError` subclasses `RookieRequestError` rather than sitting beside
it under `RookieError`, so `except RookieRequestError` (or `except
ValueError`) written before this class existed keeps catching an invalid
explicit path. **Breaking change from the earlier two-class split:** a
timeout or cancellation used to raise `RookieEngineError` (there was no
`"stopped"` kind yet); it now raises `RookieStoppedError`, so code that caught
`RookieEngineError` to inspect `stop_reason` must catch `RookieStoppedError`
instead — see CHANGELOG.md.

Every class exposes stable `kind`, `code`, and `stop_reason` attributes.
Current `stop_reason` values are `timed_out`, `cancelled`, and
`resource_exhausted`, only ever set on `RookieStoppedError`; treat the
attribute as an open string for forward compatibility.
Ambiguous profile errors also carry opaque `profile_ids`; direct-path errors
carry `source_kind`, `target_os`, and a `path_redacted` flag; an incomplete
`header()` context (`code == "incomplete_send_context"`) carries a `required`
list naming the missing selectors, e.g. `["top_level_site"]` — empty on every
other error. Human-readable exception text remains diagnostic only.

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
| Gecko session cookies | Not a first-class `profile=` | Pass `profile=` **and** `include_session=True` to `read` / `jar` for a Gecko browser |
| CPython | 3.8-era / `cp38-abi3` | **≥ 3.11**, `cp311-abi3` |
| Path APIs | `firefox_based`, `chromium_based`, `any_browser` | `extract_from_path` (`cookies_from_path` / `chromium_cookies_from_path` are deprecated aliases onto it, kept until ≥ 0.7) |
| Path request faults | Flat `RuntimeError` | `RookieRequestError` (`ValueError` subclass) |
| Header view | Manual / `to_cookiejar` | `ReadResult.header(url)` or `header(context, ...)` — **no** module-level `header()` |
| Isolation (CHIPS / containers) | Not in 0.5.6 | `ReadResult.detailed_cookies()` |
| Reports | Not in 0.5.6 | `report(...)` / `browser_report(...)`, `profiles(...)` |
| Windows App-Bound (v20) | Always `allow_elevated_fallback` (named helpers only) | Opt-in: `app_bound="injection_only"` / `"allow_elevated_fallback"` on `read` / `from_path` / `browser_report` / `load_report`; disabled by default |

1. Bump to CPython 3.11+.
2. For Gecko session import, use `jar(browser="firefox", profile="default-release", include_session=True)`.
3. Keep named helpers only for the frozen compatibility set.
4. Move explicit DB paths off `*_based` / `any_browser` and onto `extract_from_path`.
5. Catch `RookieRequestError` (and optionally `RookieEngineError`).
6. Do not invent a top-level `header()`.
7. Use `detailed_cookies()` where a CHIPS partition or Firefox container matters.

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
