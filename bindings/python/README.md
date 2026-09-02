# rookie-cookies (Python)

Extract cookies from local browsers on Linux, macOS, and Windows.

This file is the **Python guide** (PyPI landing page and repo tutorial). Rust
stays in [`rookie-rs/README.md`](https://github.com/teng-lin/rookie-cookies/blob/main/rookie-rs/README.md).
The recommended entry is `read`, then `send_view` for anything you intend
to send
([ADR 0004](https://github.com/teng-lin/rookie-cookies/blob/main/docs/adr/0004-read-is-the-recommended-entry.md),
[ADR 0006](https://github.com/teng-lin/rookie-cookies/blob/main/docs/adr/0006-isolation-safe-send-selection-and-explicit-isolation-loss.md)).
Package metadata and `version()` identify the installed build.

CPython **≥ 3.11**. Wheels are `cp311-abi3` (tested 3.11–3.14). CPython 3.8–3.10
and PyPy are not supported in 0.6.

```console
pip install rookie-cookies
```

> **Windows App-Bound security note:** jobs default to unprivileged reflective
> injection into a spawned browser process, which endpoint security can flag.
> Pass `app_bound="disabled"` to `read`, `jar`, `from_path`, or report jobs to
> perform no App-Bound process work; `v20` rows will then be omitted with a
> warning.

## Recommended usage (0.6 series)

```python
import rookie_cookies as cookies

# Gecko session import — profile selection and session policy are independent
snapshot = cookies.read(
    browser="firefox", profile="default-release", include_session=True
)

# A browsing context in; the cookies it selects, the header they render to,
# and a count of what was left out and why.
view = snapshot.send_view(
    "https://app.example.com/",
    top_level_site="https://example.com",
)
print(view["header"], view["omitted"]["partition"])

# Isolation-intact records (storage_state / allowlists / auditing)
rows = cookies.read(browser="chrome", profile="Work").detailed_cookies()
```

`read` never URL-filters. `ReadResult.send_view` is where isolation-aware
send-match happens, and `ReadResult.header` renders that same selection as a
`Cookie` request-header string (see [ADR
0006](https://github.com/teng-lin/rookie-cookies/blob/main/docs/adr/0006-isolation-safe-send-selection-and-explicit-isolation-loss.md)).
There is **no** module-level `header()` or `send_view()` — call them on a
snapshot you already took.

`jar` is `read(...).as_jar()`, the *compatibility* projection rather than the
send path: `http.cookiejar` cannot own send-match for a Chromium CHIPS
partition or a Firefox container cookie, because no field its send-match
consults can carry that identity through. So `jar` / `as_jar` **fail closed**:
an isolated snapshot raises `isolation_loss_refused` rather than flattening
scoped credentials into unscoped ones. Pass `allow_isolation_loss=True` to
accept the loss — the output is then byte-for-byte what 0.6 returned.
Unisolated snapshots are unaffected.

- No-profile `read(browser="chrome")` matches `chrome()` (persistent /
  legacy-eligible cookies).
- **`include_session` defaults to `False`.** Naming a Gecko `profile` alone no
  longer also acquires its separately declared session JSON source — pass
  `include_session=True` to `read()` / `jar()` for that. **Breaking change
  from earlier 0.6 prereleases**, where naming a profile always included
  session cookies; this fails quietly (a smaller result, no error) — see
  CHANGELOG.md.
- Chromium registrations have no separate session source; `include_session`
  is a no-op there regardless.

Named helpers (`chrome()`, `firefox()`, `load()`) still work. They are the
compatibility bridge from
[`thewh1teagle/rookie`](https://github.com/thewh1teagle/rookie) and will break
in a later major version. Prefer `read` plus `send_view` for new code.

## Isolation-aware cookies

`ReadResult.as_list()` returns the frozen eight-field
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
include three isolation-related codes: `malformed_host_identity` (a row whose
host did not survive decode was omitted from the snapshot, not emitted as
`domain: ""`), `unparsable_partition_key` (retained in the snapshot, but never
selected by `send_view()` / `header()` since its partition can't be
identified), and `unknown_ancestor_chain` (a partitioned Chromium row whose
`has_cross_site_ancestor` bit the store did not record; retained, never
selected). Warning text reads `N rows affected (code)` — deliberately not
"skipped", since the last two count rows the snapshot keeps. Branch on `code`;
the text is diagnostic only.

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

### Isolation selectors (0.7)

Four selectors describe a browsing context a top-level site alone cannot
identify. Each is a keyword argument of `header` / `send_view`, and equally a
key of the mapping form:

| Selector | Type | What it names |
| --- | --- | --- |
| `ancestor_chain` | `"same_site"` \| `"cross_site"` | Whether the request's frame tree contains a cross-site ancestor. Defaults to derived — same-site when the request site is within `top_level_site`, cross-site otherwise. Set it to describe an `A → B → A` embed, which the derived rule cannot see. |
| `first_party_domain` | `str` | Firefox `firstPartyDomain` origin attribute |
| `gecko_view_session_context_id` | `str` | Firefox `geckoViewSessionContextId` origin attribute |
| `origin_attributes` | `str` | The exact raw Firefox origin-attribute suffix, e.g. `"^userContextId=2"` |

`origin_attributes` is the only way to reach a row carrying an attribute this
build does not recognize — a future Firefox field, say. It is *necessary but
not sufficient*: such a row still passes through the partition gate and the
typed selectors, so naming a suffix says which context a row is in, never that
it may be sent from some other one.

```python
# An A → B → A embed: the request's own site is the top-level site, but a
# cross-site frame sits between them.
nested = snapshot.header(
    "https://example.com/",
    top_level_site="https://example.com",
    ancestor_chain="cross_site",
)
```

## Explaining a selection (`send_view`)

`header` renders a string, which is all you need to make one request and not
enough to explain anything. `ReadResult.send_view(...)` takes exactly
`header`'s arguments and returns the same selection before it is flattened:

```python
view = snapshot.send_view(
    "https://example.com/",
    top_level_site="https://example.com",
)
print(view["header"])
for record in view["cookies"]:
    print(record["cookie"]["name"], record["context"]["partition_key"])
print(view["omitted"]["partition"], view["omitted"]["origin"])
```

- `view["cookies"]` — the selected records in header order (longest path
  first, then by name), each the isolation-intact
  `{"cookie": ..., "context": ...}` shape `detailed_cookies()` returns.
- `view["header"]` — those same records rendered; byte-identical to
  `header(...)` for the same context, because both delegate to one core
  selection rather than matching twice.
- `view["omitted"]` — a count per reason: `expired`, `not_applicable`,
  `same_site`, `partition`, `ancestor_chain_unknown`,
  `unparsable_partition_key`, `origin`. Every key is always present, zero
  included, so indexing one needs no guard. A row is counted exactly once,
  under the first reason it failed.

An empty `view["cookies"]` is a legitimate answer, not an error. `omitted` is
how you tell "this context has no cookies" apart from "everything was
excluded, and here is what excluded it".

## Compatibility projections and isolation loss

The eight-field cookie dict, a `CookieJar`, and a Netscape file have no cell
for a CHIPS partition key, a Firefox `partitionKey` tuple, or container
identity. Producing one from an isolated snapshot converts context-scoped
credentials into unscoped ones — silently, since the result looks correct. So
the names that promise send-safety refuse:

```python
snapshot = cookies.read(browser="chrome")

try:
    jar = snapshot.as_jar()
except cookies.RookieRequestError as error:
    if error.code == "isolation_loss_refused":
        # error.required names the selectors send_view() would need instead.
        view = snapshot.send_view("https://example.com/", top_level_site="https://example.com")
    else:
        raise

# Or accept the loss explicitly, once you have decided it is acceptable:
flat = snapshot.compatibility_cookies(allow_isolation_loss=True)
jar = snapshot.as_jar(allow_isolation_loss=True)
```

| Name | Tier | Isolated snapshot |
| --- | --- | --- |
| `as_list()` | Inventory | Succeeds. Raw rows for display or auditing, collisions included — it never promised send-safety. |
| `compatibility_cookies()` | Send-safe | Raises `isolation_loss_refused`; same rows and bytes as `as_list()` when it succeeds |
| `as_jar()` / `jar(...)` | Send-safe | Raises `isolation_loss_refused` |
| `to_cookiejar()` / `to_netscape()` | Pure functions | No policy of their own — feed them `compatibility_cookies()` |

`allow_isolation_loss=True` changes *whether* the projection is produced, never
what it contains: the output is byte-for-byte what these returned before the
refusal existed.

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

Caller-correctable path/source/option failures raise `RookieSourceError`.
Operational inspection failures—such as an I/O, SQLite, locked, or corrupt
file failure—raise `RookieEngineError`/`RuntimeError` with
`code == "source_inspection_failed"`; diagnostics remain path-sanitized.

`cookies_from_path` (positional `domains`, no credential selectors) and
`chromium_cookies_from_path` (an options dict) are deprecated aliases onto
`extract_from_path` — same behavior, kept for earlier 0.6 prerelease callers,
not removed outright since deleting them this late buys nothing.

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

`read`, `jar`, `from_path`, `extract_from_path`, report jobs, and profile-listing
jobs accept `timeout` (seconds) and `cancellation`. The deprecated named
browser helpers keep their old signatures and do not expose those controls.

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

`read`, `jar`, `from_path`, `extract_from_path`, `report`, `browser_report`,
and `load_report` all take an `app_bound` keyword. It defaults to
`"injection_only"`, because Chrome has
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
| `RookieSourceError` (subclasses `RookieRequestError`) | `ValueError` | `"source"` | A caller-correctable explicit path/source/option was invalid |
| `RookieStoppedError` | `RuntimeError` | `"stopped"` | A `timeout` elapsed, `cancellation` fired, or an internal resource limit was hit |
| `RookieEngineError` | `RuntimeError` | `"engine"` | Discovery, acquisition, decryption, or source inspection failed |

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
`header()` / `send_view()` context (`code == "incomplete_send_context"`) and a
refused jar projection (`code == "isolation_loss_refused"`) both carry a
`required` list naming selectors, e.g. `["top_level_site"]` — empty on every
other error. The two codes draw on **one** vocabulary, so code that already
branches on one's `required` needs no second one: for
`incomplete_send_context` it is the selectors the call did not receive, and
for `isolation_loss_refused` it is the selectors a `send_view()` / `header()`
call would need for that snapshot instead. Human-readable exception text
remains diagnostic only.

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

## Migrating to 0.7

Nothing is renamed. `jar`, `as_jar`, `header`, `as_list`,
`detailed_cookies`, and every named helper keep their names and their
meanings. Two things change, and both are additions:

| Change | What breaks | What to do |
| --- | --- | --- |
| `jar` / `as_jar` fail closed on isolation loss | Only a call against a snapshot that holds a partitioned or containered cookie. It now raises `RookieRequestError` with `code == "isolation_loss_refused"` instead of silently flattening. Unisolated snapshots are unaffected. | Move to `send_view()` / `header()` if you were going to *send* those cookies, or pass `allow_isolation_loss=True` if you were not. |
| `header()` matches on full partition identity | A `header()` call that previously merged two contexts' cookies now splits them, and a row carrying an origin attribute this build does not recognize is omitted until you name it with `origin_attributes`. | Supply the selectors the error's `required` list names. Use `send_view()`'s `omitted` counts to see what a context excluded and why. |

1. Wherever you called `jar(...)` / `as_jar()` in order to send cookies,
   call `send_view(url, top_level_site=...)` instead and use its `"header"`.
2. Wherever you called them to *export* cookies (a Netscape file, a
   `storage_state`, an audit listing), decide explicitly: pass
   `allow_isolation_loss=True`, or switch to `detailed_cookies()` and keep
   the isolation identity.
3. Catch `isolation_loss_refused` alongside `incomplete_send_context` — they
   share the `required` vocabulary, so one handler covers both.
4. Prefer `send_view()` over `header()` when you need to explain an empty or
   surprising result; `header()` alone cannot tell "no cookies here" from
   "everything was excluded".

## Migrate 0.5.6 → 0.6.0

| Area | 0.5.6 / early 0.5.x | 0.6.0 |
| --- | --- | --- |
| Recommended entry | `chrome()` / `to_cookiejar(...)` | `read(browser=..., profile=...)`, then `send_view(...)` to send or `as_list()` to inspect |
| Gecko session cookies | Not a first-class policy | Pass `include_session=True` to `read` / `jar`; `profile=` is optional and only selects which profile |
| CPython | 3.8-era / `cp38-abi3` | **≥ 3.11**, `cp311-abi3` |
| Path APIs | `firefox_based`, `chromium_based`, `any_browser` | `extract_from_path` (`cookies_from_path` / `chromium_cookies_from_path` are deprecated aliases onto it, kept until ≥ 0.7) |
| Path request faults | Flat `RuntimeError` | `RookieRequestError` (`ValueError` subclass) |
| Header view | Manual / `to_cookiejar` | `ReadResult.header(url)` or `header(context, ...)` — **no** module-level `header()` |
| Isolation (CHIPS / containers) | Not in 0.5.6 | `ReadResult.detailed_cookies()`; from 0.7, `ReadResult.send_view(...)` for the send-side view |
| Reports | Not in 0.5.6 | `report(...)` / `browser_report(...)`, `profiles(...)` |
| Windows App-Bound (v20) | Always `allow_elevated_fallback` (named helpers only) | `app_bound="injection_only"` by default on jobs; pass `"disabled"` to opt out or `"allow_elevated_fallback"` to permit SYSTEM fallback |

1. Bump to CPython 3.11+.
2. For Gecko session import, pass `include_session=True`; add `profile=` only
   when you need a profile other than the legacy-first choice.
3. Keep named helpers only for the frozen compatibility set.
4. Move explicit DB paths off `*_based` / `any_browser` and onto `extract_from_path`.
5. Catch `RookieError` for every library failure, or catch the specific
   request/source/stopped/engine subclass you intend to handle.
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
