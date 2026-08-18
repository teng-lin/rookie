# Clean Job API (`get` / `profiles` / `report` / `from_path`)

> **Superseded (product).** Consumer-facing `get` / `CookieResult` / URL-on-`get` is superseded by [consolidated-implementation-plan.md](consolidated-implementation-plan.md) rev 3 (`read` / `ReadResult` / `jar`). Keep this file as historical rationale and for the URL-match table (still used by `header()`). Do not treat this document as the recommended product.

- **Author:** Grok (design)
- **Date:** 2026-08-18
- **Status:** Draft (rev 2 — review issues 1–9); **product superseded** by consolidated plan rev 3
- **Scope:** Consumer-facing extract surface across Rust, Python, Node, and CLI. Design only.
- **Workspace:** `/Users/blackmyth/src/rookie-cookies`
- **Supersedes:** consumer-facing parts of [unified-extract-api.md](unified-extract-api.md) (`Request.profile` + `extract_report` as the thing a new user learns). That document remains the spec for the **store** layer this job API sits on.
- **Keeps from that document:** one crate-private resolver, `ProfileSelection`, #261 thin `browser(id)` first, `RequestError` conversion site, [ADR 0003](../adr/0003-unified-profile-query.md), two-arg Rust `browser()`, no all-profile flatten into `Vec<Cookie>`, no `Request.channel`.
- **Does not redo:** [modularize-oversized-browser-modules.md](modularize-oversized-browser-modules.md) (structure-only; non-blocking).
- **Related ADRs:** [0001](../adr/0001-cookie-extraction-compatibility-and-report-contracts.md), [0002](../adr/0002-authoritative-browser-registry.md), [0003](../adr/0003-unified-profile-query.md). This series **adds ADR 0004** (recommended entry is `get`).
- **Related issue:** GitHub **#261** (Python/Node thin `browser(id)`).

---

## From scratch (one page)

A new user learns **four names** (Python, Node, CLI). Rust cannot reuse the identifier `report` (it already owns `pub mod report`); there the power verb stays `extract_report`.

```text
get(...)          # the job: cookies I can send
profiles(id)      # list, no decrypt
report(...)       # power: labeled extract (Python / Node / CLI)
                  # Rust: extract_report(Request) — same verb, legal name
from_path(...)    # a file, not a profile
```

No engine verbs. No `chrome_profile` vs `firefox_profile` shape split. No mixing a report dict with a cookie list.

```python
import rookie_cookies as cookies
from rookie_cookies import RookieRequestError, RookieEngineError

# get always returns CookieResult — not a jar, not a list, not a report
result = cookies.get("https://github.com", browser="chrome")
session.cookies = result.as_jar()          # 90% path
print(result.header())                     # Cookie request header
print(result.warnings)                     # codes/counts, never values

session_cookie = cookies.get(
    "https://github.com", browser="chrome", names=["user_session"]
)

work = cookies.get("https://github.com", browser="chrome", profile="Work")

rows = cookies.get(browser="chrome").as_list()   # no URL: that store, minus expired

for p in cookies.profiles("chrome"):             # no decrypt
    print(p["profile"]["profile_id"], p["profile"]["display_name"], p["profile"]["path"])

rep = cookies.report("chrome", profile="Work")   # labeled extract
print(rep["status"], rep["summary"]["cookies_emitted"])

file_result = cookies.from_path(
    "/path/to/cookies.sqlite", url="https://github.com"
)
```

`get` **always** returns a `CookieResult`. It never returns a raw `list` sometimes and a report sometimes. `browser` is **required** on `get`; `get("https://github.com")` is a request error (`TypeError` in Python — missing keyword — before any URL parse).

| I want | Call |
| --- | --- |
| Cookies I can send to a URL | `get(url, browser=)` then `.as_jar()` / `.header()` |
| One named cookie | `get(url, browser=, names=[...])` |
| A specific profile | `get(..., profile="Work")` |
| Who is installed, no decrypt | `profiles("chrome")` |
| What failed, per source | `report("chrome")` (Rust: `extract_report`) |
| A file I already have | `from_path(path, url=...)` |

`chrome()`, `browser()`, `browser_report`, `cookies_from_path`, `chrome_profile`, CLI `--browser chrome` stay as aliases.

---

## Overview

`rookie-cookies` already has a working **store** model: registry `canonical_id`, `ProfileSelection` (`LegacyFirstProfile` / `ProfileId` / `AllProfiles`), two projections (`Vec<Cookie>` vs `ExtractionReport`), two origins (discovery vs `direct_path`). [unified-extract-api.md](unified-extract-api.md) unifies the **selectors** so any registered browser × one named profile can yield flat cookies or a report.

That is necessary and not sufficient. A from-scratch user still starts at a **store** (`browser("chrome")`, `chrome()`, `--browser chrome`) and then filters with a host-list (`domains=["github.com"]`) that is not “cookies I can send to this URL.” Mature packages people enjoy are **job-oriented**:

| Package | Primary call |
| --- | --- |
| pycookiecheat | `get_cookies(url, browser=BrowserType.CHROME)` |
| get-cookie | `getCookie({name, domain})` / `get-cookie sessionid github.com --profile Work` |
| sweet-cookie | `getCookies({url, browsers, chromeProfile, names, mode, origins})` → `{cookies, warnings}` |
| kooky | `TraverseCookies(ctx, Valid, DomainHasSuffix, Name)` + `CookieStore` is a `CookieJar` |
| chrome.cookies | `getAll({url, name, domain, path, storeId, partitionKey})` |
| Playwright | `context.cookies(urls)` ; SameSite enum strings |

This design adds a **job** layer on top of the store layer. It does not replace `Request` / `extract` / `extract_report`. It does not change `chrome()` / `load()` / `Cookie` / the report DTO. It makes `get` the documented default (ADR 0004) and leaves every previous name as an alias.

---

## Background

### What the user sees today

```python
# three shapes, three selectors, none of them is "cookies for this URL"
rookie_cookies.chrome(["github.com"])                 # list[dict], first profile, host-list
rookie_cookies.chrome_profile("Work")                 # report dict
rookie_cookies.firefox_profile("Work")                # list[dict], different keys, sqlite only
rookie_cookies.browser_report("chrome", opaque_id)    # report; names were not keys
rookie_cookies.cookies_from_path("/tmp/Cookies")      # list[dict], path universe
# Python/Node: no browser(id) until #261
# then, after unified-extract-api: browser(id, profile=) still starts at a store
```

```text
# CLI today
rookie-cookies --browser chrome --domains github.com
rookie-cookies --list-profiles --browser chrome
rookie-cookies --report --browser chrome --profile <opaque-id>
```

Internals (WAL snapshot, v20, reports, `browser_registry.json`, `ProfileSelection`) are ahead of this surface. The previous design closed the **selector** hole. This design closes the **job** hole.

### What already exists (do not reinvent)

| Piece | Where | Role after this design |
| --- | --- | --- |
| `Request` | [`rookie-rs/src/lib.rs`](../../rookie-rs/src/lib.rs) L241–285 | Store operation: browser, (soon) profile, `domains` host-list, timeout, cancel |
| `extract` | `lib.rs` L309–320 | `LegacyFirstProfile` → `Vec<Cookie>`, unsorted, includes expired. Compatibility projection. |
| `browser(id, domains)` | `lib.rs` L350–352 | Two-arg sugar over `extract`. **Arity frozen.** |
| `pub mod report` | `lib.rs` L11 | DTO home (`ExtractionReport`, `ProfileDescriptor`). **Owns the identifier `report`.** |
| `browser_report` / `browser_profiles` | `lib.rs` L468–568 | Power listing / labeled extract |
| `ProfileSelection` | [`registry.rs` L348–352](../../rookie-rs/src/browser/registry.rs) | `AllProfiles` · `ProfileId` · `LegacyFirstProfile` |
| Chromium `LegacyFirstProfile` | [`registry/chromium.rs` L921–1030](../../rookie-rs/src/browser/registry/chromium.rs) | `legacy_priority` × Default/`Profile*` group × source precedence × installation priority × path; `add_legacy_flat_chromium_profiles`; `legacy_windows_local_state` |
| Gecko `LegacyFirstProfile` | [`registry/gecko.rs` L589–613](../../rookie-rs/src/browser/registry/gecko.rs) | `select_legacy_gecko_profile`: default-with-sqlite, then `profiles.ini` order — **not** `browser_profiles` display-name order |
| Compatibility flatten | [`report_build.rs` L1266–1280](../../rookie-rs/src/browser/report_build.rs), [`legacy.rs` L198](../../rookie-rs/src/browser/legacy.rs) | Chromium: **persistent only**, drop non-legacy-compatible rows |
| `host_matches_domain` / `some_domain_in_host` | [`common/utils.rs` L12–59](../../rookie-rs/src/common/utils.rs) | **Host-list** store filter. Not RFC 6265 send-matching. |
| `DomainScope::from_stored` | [`cookie_record.rs` L143–151](../../rookie-rs/src/browser/cookie_record.rs) | Leading `.` ⇒ domain cookie; absence ⇒ host-only. Compare after stripping the dot. |
| SQL `LIKE %domain%` + host matcher | [`chromium_decoder.rs` L283–304](../../rookie-rs/src/browser/chromium_decoder.rs) | Candidate reducer for store `domains=` only. **Not used by `get` in this series.** |
| `Cookie.same_site: i64` | [`enums.rs` L19–30](../../rookie-rs/src/common/enums.rs) | Frozen raw encoding. **No `Clone`.** |
| `CookieToString` | `enums.rs` L116–127 | Frozen `name=value;name2=value2` (**no space**). Not the new header. |
| `format::netscape` | [`common/format.rs`](../../rookie-rs/src/common/format.rs) L13 | Takes `Vec<Cookie>` **by value**. Do not change the signature. |
| `to_cookiejar` / `create_cookie` | [`bindings/python/rookie_cookies/__init__.py`](../../bindings/python/rookie_cookies/__init__.py) L130–193 | Python jar projection. Job `as_jar()` filters first. |
| `url` crate | `rookie-rs/Cargo.toml` already depends on `url = "2"` | Parse job URLs |
| `cookies_from_path` / `DirectPathRequest` | [`direct_path/mod.rs`](../../rookie-rs/src/direct_path/mod.rs) | Path universe; `Result<Vec<Cookie>>`; **no issue stream** |
| `RookieRequestError` / `RookieEngineError` | [`bindings/python/src/errors.rs`](../../bindings/python/src/errors.rs) | Bindings fault split via `fault_kind` |
| `select_chromium_profile` | [`registry/chromium.rs` L1356–1403](../../rookie-rs/src/browser/registry/chromium.rs) | Algorithm the unified resolver generalizes |

### Before (vomit) vs after (four names)

```text
BEFORE                                          AFTER (what we document)
─────────────────────────────────────────────   ──────────────────────────────────
chrome() / firefox() / brave() / …              get(..., browser="chrome")
browser("chrome")          (#261, store)        get(..., browser="chrome")
browser("chrome", profile=) (unification)       get(..., browser="chrome", profile=)
chrome(["github.com"])     (host-list)          get("https://github.com", browser=)
chrome_profile("Work")     (report!)            get(..., profile="Work")  or report(...)
firefox_profile("Work")    (flat, sqlite only)  get(..., browser="firefox", profile=)
browser_profiles("chrome")                      profiles("chrome")
browser_report("chrome", id)                    report("chrome", profile=)
                                                Rust: extract_report(Request)
cookies_from_path(path)                         from_path(path, url=...)
load()                     (concat, frozen)     (alias; not recommended)
CLI --browser / --list-profiles / --report      get / profiles / report
```

The left column stays compiled and tested. The right column is what README, `docs/Python.md`, `docs/Rust.md`, `docs/JavaScript.md`, and the CLI `--help` lead with.

---

## Goals & Non-Goals

### Goals

1. Documented job names: `get`, `profiles`, `report` (bindings/CLI), `from_path`. Rust power verb is `extract_report` (see KD 1).
2. `get` is job-oriented: URL (optional) + required browser + optional profile/names. One return type (`CookieResult`) on every path.
3. URL matching is RFC 6265 / chrome.cookies **send** matching (host + path + secure), not only today’s host-list `domains=`.
4. One resolver, extended with **cookie database path** as a key. `from_path` stays the path universe.
5. `get` defaults `include_expired=false`. `extract` / `chrome()` stay unsorted-all-rows including expired.
6. SameSite projects to `Lax` / `Strict` / `None` via `same_site_label` (all languages). Frozen `Cookie.same_site: i64` is untouched.
7. `get` without `browser` is a request error. No `load()`-style magic concat.
8. `profiles(id)` is a short alias of `browser_profiles(id)`. Do not break the long name.
9. On `get`: partial row skip → warning; total decrypt fail → engine error. Never silent empty on failure. `from_path` does **not** harvest row-level issues (no path-universe issue stream this series).
10. Additive on top of the unification series. #261 still thin. Then resolver + `Request.profile`. Then `get` as the documented default.
11. ADR 0004: `get` is the recommended entry.
12. No-profile `get` uses `ProfileSelection::LegacyFirstProfile` and the **compatibility cookie projection** (`extract` / `chrome()`), not listing-first `ProfileId`.

### Non-goals (frozen)

- No change to `chrome()` / `firefox()` / `load()` signatures or first-profile / historical-set behavior (ADR 0001).
- No third argument on Rust `browser(&str, Option<Vec<String>>)` (unification KD 3).
- No flattening all profiles into `Vec<Cookie>` (ADR 0001 / 0003).
- No `Request.channel`. Two `Default` directories stay two `profile_id`s.
- No `Cookie` field change and **no `Clone` on `Cookie`** (this series). No report DTO / `schema_version` change. No `directory_name` on `ProfileIdentity`.
- No `browser_registry.json` schema change.
- No set/delete. No object-graph `Browser` type. No public `Engine` trait.
- No engine-specific verbs on the recommended path (`yandex_profile`, …).
- No changing `CookieToString` (no-space join), `format::netscape(Vec<Cookie>)` by-value, or Python `to_netscape` / Node `toNetscape` bytes.
- No crate-root `fn report` (collides with `pub mod report`).
- No path-universe diagnostics channel (would be required for `from_path` row-level warnings).
- Modularization of `registry.rs` / `report_build.rs` is out of scope here.

`public-api/*.txt` **will** change when `get` / `GetRequest` / `CookieResult` / `profiles` / `from_path` (job) are added. That change is **additive**.

---

## Key Decisions

1. **Four names on bindings/CLI; Rust is `get` / `profiles` / `extract_report` / `from_path`.** The product a new user learns (Python/Node/CLI) is `get` / `profiles` / `report` / `from_path`. Rust cannot add `pub fn report` next to `pub mod report` ([`lib.rs` L11](../../rookie-rs/src/lib.rs)); renaming the module is a breaking public-api change and is out of scope. The Rust power verb is the unification name `extract_report`. `chrome`, `browser`, `browser_report`, `cookies_from_path`, `chrome_profile`, CLI `--browser` stay compatibility aliases.

2. **`get` always returns `CookieResult`, never a list or a report.** Python `CookieResult` iterates cookie dicts and exposes `.as_jar()` / `.header()` / `.netscape()` / `.warnings`. It is not a `CookieJar` subclass, has no `.jar` alias, and is not sometimes a report dict. There is **no** module-level `header()` sugar (that would be a fifth verb). Rationale: one type; jars cannot carry warnings; mixing shapes is the vomit this design deletes. See [CookieResult](#cookieresult).

3. **`GetRequest` is a facade, not a kitchen-sink `Request`.** `Request` stays the store operation (browser, profile, host-list `domains`, timeout, cancel). `GetRequest` builds a store selection plus a `GetFilter` (`url`, `names`, `include_expired`). `extract` / `extract_report` ignore job filters because those fields are not on `Request`. Rationale: folding `url` onto `Request` makes `extract(Request::browser("chrome").url(...))` either a trap (url ignored) or a silent change to frozen unsorted-all-rows semantics.

4. **`browser` is required on `get`.** `get(url)` without `browser` is `RequestError::MissingBrowser`. No auto-scan, no first-successful-among-a-list, no `load()` concat. Rationale: silent cross-browser concat is how you send the wrong account’s session; pycookiecheat and chrome.cookies both require a store identity; `load()` exists for the people who want that and stays frozen. See KD 4 defense below.

5. **URL match is send-matching; `get` does not pass `Request.domains`.** `get(url)` does **not** take `domains`. `extract` / `chrome()` / binding `report(..., domains=)` keep `some_domain_in_host`. This series decrypts the selected profile (or the path-universe file) and applies RFC 6265 domain + path + secure as a **post-filter only**. A two-label suffix-chain (`www.github.com` → `["www.github.com", "github.com"]`) is **not** a superset of “no PSL on read”: it would drop a stored `.com` cookie the post-filter would keep. Walking every DNS label (`…, "com"`) would be a true superset but decrypts every `.com` host; that is alt H / a follow-on, not a silent eTLD+1. Required test: stored `.com` + `https://www.example.com/` is **kept**.

6. **Default `include_expired=false` on `get` / job `from_path` only.** Session cookies (`Cookie.expires == None`, including Chromium `expires_utc == 0` via [`date::chromium_timestamp`](../../rookie-rs/src/common/date.rs)) stay. Persistent rows with `expires < now` drop. `extract` / `chrome()` / `cookies_from_path` still emit them.

7. **SameSite projection is `same_site_label`, not a `Cookie` field.** `header()` is a Cookie **request** header and does not include SameSite. `same_site_label(i64) -> Option<Lax|Strict|None>` ships in Rust, Python, and Node. Unspecified (`-1`) and unknown integers map to `None` (the Option). Frozen `Cookie.same_site: i64` unchanged.

8. **`profiles` is an alias; `browser_profiles` does not break.** Same return type (`Vec<ProfileDescriptor>` / binding dicts). No decrypt, no keys (already true of `browser_profiles`).

9. **Binding/CLI `report` is the power verb; it is not URL-filtered.** Python/Node/CLI `report(...)` is `extract_report` / `browser_report`. Rust callers write `extract_report`. Counters and issues stay extraction-shaped. A send filter would lie about `rows_seen`. Callers who want “what would I send?” use `get`.

10. **Cookie DB path is a resolver key; `from_path` is a different universe.** `profile="/…/Default/Cookies"` resolves to the registered profile that lists that persistent source, then extracts the **whole profile** (persistent + selected session) with installation keys. `from_path` opens **that file only**, sniffs format, and does not require the file to belong to a registered browser (HackBrowserData RFC-013 lesson, already in unification). Session files (`recovery.jsonlz4`) are not resolver keys.

11. **Warnings vs throw are split by verb.** `get` harvests row-level issues from a `LegacyFirstProfile` or `ProfileId` report-shaped outcome. `from_path` has no issue stream (`cookies_from_path` → `Result<Vec<Cookie>>`): filter miss → `Ok` empty + warning; classify/decrypt failure → existing `DirectPathError` / engine error; **no** `"skipped N rows (decrypt_failed)"` harvest this series. Zero selected sources succeeded on `get` → `FaultKind::Engine`, not `Ok` empty. Never collapse a failure into a plausible empty jar.

12. **No-profile `get` is `LegacyFirstProfile` + the compatibility cookie projection.** It is **not** “list descriptors → first id → `extract_report(ProfileId)`.” Chromium ranks `legacy_priority` × Default-vs-`Profile*` group × source precedence × installation priority × path, adds Opera flat sources only on that policy, and applies `legacy_windows_local_state` ([`chromium.rs` L921–1030](../../rookie-rs/src/browser/registry/chromium.rs)). Gecko uses `select_legacy_gecko_profile` ([`gecko.rs` L589–613](../../rookie-rs/src/browser/registry/gecko.rs)), not `browser_profiles` order. Chromium compatibility emit is **persistent only** and drops non-legacy-compatible rows ([`report_build.rs` L1266–1280](../../rookie-rs/src/browser/report_build.rs), [`legacy.rs` L198](../../rookie-rs/src/browser/legacy.rs)). Empty listing / not installed → the same engine/`BrowserNotInstalled` error `extract` already raises, **not** `UnknownProfile`. With-profile `get` uses `ProfileId` + report flatten (persistent **and** selected session) as unification specified; that set is **not** claimed equal to no-profile `extract`.

13. **Sendable set is built once.** Empty name, CTL, or forbidden Cookie-octet bytes omit the cookie from `CookieResult` (warning, no throw) **before** any projection. `header()`, `as_jar()`, `netscape()`, `as_list()` / `cookies()`, Node `.cookies`, and CLI `--format header` share that set. Do not filter only in `header()`.

14. **Landing order.** `#261` thin `browser(id)` → `RequestError` → `resolve_profile_query` (include cookie-DB path if that PR has not merged) → `Request.profile` + `extract_report` → shims/CLI/bindings from unification → **then** this series (`GetFilter`, `get`, aliases, CLI subcommands, ADR 0004). This series is additive on that stack.

15. **ADR 0004, do not amend 0003’s grammar.** 0003 stays the selector/CLI-flag contract. 0004 adds: recommended entry is `get`; resolver gains cookie-DB path; `get` requires `browser`; `include_expired` default only on the job API; Rust power name is `extract_report`. 0001’s frozen `chrome()` / `load()` / `Cookie` / no all-profile flatten stay.

**KD 4, at length (require `browser`).** Rejected alternative: `get(url)` walks a documented order and returns the first non-empty success (pycookiecheat-without-browser, browser_cookie3, today’s `load()`). That is how you (a) send a Firefox cookie to a site you are Chrome-logged-in on, (b) hide a decrypt failure behind another browser’s empty filter match, (c) make CI non-deterministic when a laptop has both. sweet-cookie’s `browsers: [...]` is explicit multi-store and still not “guess.” chrome.cookies requires `storeId` or uses the current context — we have no current context. `load()` remains for concat; it is not the default. `get(url)` without `browser` is therefore `RequestError::MissingBrowser`, not a scan.

**KD 2, at length (`CookieResult` vs default `CookieJar`).** 90% of Python callers want a jar for `requests`. Returning a jar from `get` forces warnings, header, netscape, and store metadata onto a second object or onto mutations of a stdlib type. `http.cookiejar.CookieJar` is mutable, has no SameSite, and `isinstance(..., CookieJar)` would lie if we subclassed. `CookieResult` with `__iter__` over the **sendable** dicts plus `.as_jar()` is one extra attribute for the 90% path and a single type for everyone else. Node returns a plain object `{cookies, header, netscape, warnings}` for the same reason (no class hierarchy). The first documented line is `session.cookies = cookies.get(...).as_jar()`, never `jar = cookies.get(...)`.

---

## Proposed Design

### Architecture

```mermaid
flowchart TB
  subgraph job [Job API]
    getFn["get(GetRequest)"]
    profilesFn["profiles(id)"]
    extractReportFn["extract_report(Request)<br/>bindings/CLI: report(...)"]
    fromPathFn["from_path(FromPathRequest)"]
  end

  subgraph aliases [Compatibility aliases]
    named["chrome() / firefox() / load()"]
    browserFn["browser(id, domains)"]
    extractFn["extract(Request)"]
    browserReportFn["browser_report"]
    listFn["browser_profiles"]
    pathFn["cookies_from_path"]
  end

  subgraph facade [GetRequest facade]
    selMode["no profile → LegacyFirstProfile<br/>profile=q → ProfileId"]
    filt["GetFilter: url, names, include_expired"]
  end

  subgraph store [Store layer — unified-extract-api]
    rb["resolve_registered_browser"]
    rp["resolve_profile_query<br/>id · name · dir · profile path · cookie DB path"]
    ps["ProfileSelection<br/>never AllProfiles on get"]
  end

  subgraph engine [Existing engine]
    disc[Discovery]
    sel[Select before keys]
    acq[Acquire / parse / decrypt]
    canon[Canonical Outcome]
  end

  subgraph project [Job projection]
    compat["no profile: compatibility flatten<br/>= extract / chrome()"]
    reportFlat["profile set: selected+succeeded"]
    sendable["omit CTL / empty name / bad octets"]
    urlMatch["RFC 6265 domain + path + secure"]
    nameExp["names + include_expired"]
    result["CookieResult + warnings"]
  end

  getFn --> facade
  selMode --> rb
  rb --> rp
  rb --> ps
  rp --> ps
  ps --> sel
  disc --> sel --> acq --> canon
  canon --> compat
  canon --> reportFlat
  compat --> sendable
  reportFlat --> sendable
  sendable --> urlMatch --> nameExp --> result
  extractReportFn --> rb
  profilesFn --> listFn
  fromPathFn --> pathFn
  pathFn --> sendable
  named --> extractFn
  browserFn --> extractFn
  extractFn -.->|no job filter| canon
```

### `get` pipeline

```mermaid
sequenceDiagram
  participant C as Caller
  participant G as get
  participant R as resolve
  participant E as engine
  participant F as GetFilter

  C->>G: GetRequest browser+profile?+url?+names?
  alt browser missing
    G-->>C: RequestError::MissingBrowser
  end
  G->>R: resolve_registered_browser
  alt profile query present
    R-->>G: ProfileId or RequestError
    G->>E: ProfileSelection::ProfileId + report flatten
  else profile omitted
    Note over G,E: no listing-first id
    G->>E: ProfileSelection::LegacyFirstProfile<br/>+ compatibility projection
  end
  alt not installed / no selected source succeeded
    E-->>C: same engine error as extract (never Ok empty)
  else at least one source succeeded
    E-->>G: cookies + optional issues
    G->>G: harvest warnings if a report-shaped outcome exists
    G->>F: sendable octets + RFC 6265 + names + expiry
    F-->>C: CookieResult
  end
```

Implementation constraint: prefer a **crate-private** engine/report entry that accepts `ProfileSelection::LegacyFirstProfile` over “resolve an id from `browser_profiles` then `ProfileId`.” Unification already forbids rerouting no-profile `extract` through `extract_report` (`AllProfiles` / report flatten). `get` without `profile=` must not invent that reroute.

Empty listing (known browser, nothing installed): `browser_profiles` is `Ok([])`. `get` does **not** turn that into `UnknownProfile`. It returns the same not-installed / no-cookie-database error `extract` / `chrome()` already raise (`BrowserNotInstalled` / engine fault).

### CookieResult

One result type on every `get` / job-`from_path` path. `cookies` is the **sendable** set (filters already applied).

```text
CookieResult
  cookies: Vec<Cookie>          # frozen 8-field Cookie; sendable only
  warnings: Vec<String>         # owned; no cookie values, no key bytes
  browser_id: String            # canonical id actually used (from_path: sniffed/declared)
  profile_id: Option<String>    # opaque id; None for from_path
```

Projections (all see the same `cookies` vec):

| Method | Bytes / object | Notes |
| --- | --- | --- |
| `cookies()` / `as_list()` | frozen `Cookie` / dicts | `same_site` stays `i64` |
| `header()` | `name=value; name2=value2` | RFC 6265 Cookie **request** header: semicolon **+ space**. Not `CookieToString` (no space). |
| `netscape()` | same escaping as `format::netscape` | Implemented via a crate-private `&[Cookie]` formatter. Do **not** change `format::netscape(Vec<Cookie>)`. |
| `as_jar()` (Python only) | `http.cookiejar.CookieJar` | Same sendable set. No `.jar` property. |
| `same_site_label` | free function, all languages | Not in the Cookie header |

**Sendable-set rule (applied once, when building `CookieResult`):**

Omit a cookie and append a warning (do not throw) when any of:

- `name` is empty
- `name` or `value` contains a CTL (U+0000–U+001F, U+007F), including CR / LF / TAB
- `name` is not an RFC 6265 `token`, or `value` is not a `cookie-octet` sequence (same allow-list as [`examples/javascript/cookie-header.js`](../../examples/javascript/cookie-header.js))

Do not percent-decode values. SameSite is **not** a sendability criterion.

Header join: `"; "` (space), matching the JS helper and RFC 6265 §4.2.1. Order after the send filter: longer path first, then name (RFC 6265 §5.4 approximation). We do not have creation time.

Python usability (not a jar, not a list):

```python
class CookieResult:
    warnings: list[str]
    browser_id: str
    profile_id: str | None

    def as_list(self) -> list[CookieObject]: ...
    def as_jar(self) -> http.cookiejar.CookieJar: ...
    def header(self) -> str: ...
    def netscape(self) -> str: ...
    def __iter__(self): ...          # over sendable cookie dicts
    def __len__(self) -> int: ...
    def __bool__(self) -> bool: ...  # False if no cookies
```

`requests` usage is `session.cookies = result.as_jar()`. Do not make `CookieResult` a `CookieJar` or a `Mapping`. Do not add `.jar`.

Node:

```ts
interface CookieResultObject {
  cookies: CookieObject[]      // sendable; sameSite: number
  header: string
  netscape: string
  warnings: string[]
  browserId: string
  profileId: string | null
}
```

Rust: `CookieResult` is `Debug` (cookie values redacted via existing `Cookie` debug; warnings contain no values). **Not `Clone`.** Public `Cookie` has no `Clone` ([`enums.rs` L17–30](../../rookie-rs/src/common/enums.rs)); this series does not add one. Not `PartialEq` in public docs; tests compare `cookies()` field-wise.

`GetRequest` / `FromPathRequest`: **do not `#[derive(Debug)]`**. Manual `Debug` redacts the URL field with the same function as `InvalidUrl` (see below). Other fields (`browser`, profile query, name list, flags) may appear.

### SameSite projection

```rust
/// Playwright / Fetch-style label. Not a Cookie field.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSiteLabel {
  None,   // stored 0
  Lax,    // stored 1
  Strict, // stored 2
}

pub fn same_site_label(same_site: i64) -> Option<SameSiteLabel> {
  match same_site {
    0 => Some(SameSiteLabel::None),
    1 => Some(SameSiteLabel::Lax),
    2 => Some(SameSiteLabel::Strict),
    _ => None, // -1 unspecified, and any future/unknown i64
  }
}
```

Python exports the same function (`same_site_label(same_site: int) -> Literal["None", "Lax", "Strict"] | None`). Node: `sameSiteLabel`. Bindings/CLI `report` does not grow a string SameSite on the frozen cookie object.

- Frozen `Cookie.same_site: i64` and `SAME_SITE_UNSPECIFIED = -1` stay ([`enums.rs` L15–29](../../rookie-rs/src/common/enums.rs)).
- `header()` does not emit SameSite (request header has no such attribute).
- `get` does **not** filter by SameSite. We have no navigation context. chrome.cookies `getAll({url})` and Playwright `context.cookies(urls)` likewise return matching cookies regardless of SameSite.
- CHIPS / partition / container identity stay on `DetailedCookie` / report context. The job API uses the compatibility `Cookie` projection, same as `chrome()` today. Document as a known limit, not a DTO change.

### URL matching (RFC 6265 / chrome.cookies)

Today’s filter is a **store host-list**:

```12:32:rookie-rs/src/common/utils.rs
pub fn host_matches_domain(host: &str, target_domain: &str) -> bool {
  // request for example.com includes cookies whose host is example.com
  // or a subdomain. request for sub.example.com does NOT include parent.
  // ...
}
```

That is the right filter for `chrome(["example.com"])` (“dump this family’s cookies”). It is the **wrong** filter for “cookies the browser would send to `https://www.example.com/settings`”:

| Cookie | `chrome(domains=["example.com"])` | `get("https://www.example.com/")` |
| --- | --- | --- |
| `Domain=.example.com; Path=/` | yes | yes |
| host-only `www.example.com` | yes | yes |
| host-only `api.example.com` | yes | **no** |
| `Domain=.example.com; Path=/admin` | yes | **no** (path) |
| `Secure` on `http://www.example.com/` | yes | **no** |
| `Domain=.com; Path=/` | yes (host-list) | **yes** (no PSL on read) |

`get` does **not** accept `domains=`. Composition with `some_domain_in_host` this series:

1. Parse the URL with `url::Url` (already in `rookie-rs` deps).
2. Accept only `http` and `https`. Everything else, including relative refs, `file:`, `about:`, `ftp:`, is `RequestError::InvalidUrl`.
3. Canonical host: WHATWG host; strip one trailing dot; IPv6 without brackets for compare. Userinfo and port are ignored (cookies are not port-keyed).
4. Default path: empty or missing path → `/`.
5. **No `Request.domains` reducer.** Decrypt the selected profile (or the path-universe file) unfiltered at the host-list layer. Apply steps 6–8 as a post-filter. This is how “no PSL on read” stays true. A follow-on may add a **complete** suffix-chain including the TLD (`www.example.com` → `["www.example.com", "example.com", "com"]`) or a dedicated SQL send-predicate (alt H). Do **not** implement the two-label / eTLD+1 example.
6. **Post-filter (normative):** keep a cookie iff all of:
   - **Domain-match (RFC 6265 §5.1.3 / §5.4), using `DomainScope::from_stored`:**
     - Host-only-flag = stored `Cookie.domain` has **no** leading `.` ([`cookie_record.rs` L143–151](../../rookie-rs/src/browser/cookie_record.rs)).
     - Compare-host = stored domain with **at most one leading `.` stripped**, plus the request-host trailing-dot strip already specified. ASCII case-fold.
     - Host-only → request-host equals compare-host.
     - Domain cookie → request-host equals compare-host **or** request-host is a subdomain of compare-host (suffix + dot boundary). This is why `.example.com` is sent to `https://example.com/` (apex) **and** `https://www.example.com/`.
     - IPs match exact only (no suffix).
   - **Path-match (RFC 6265 §5.1.4):** cookie-path (empty → `/`) is a prefix of request-path, and either they are equal, or cookie-path ends in `/`, or the next request-path character is `/`.
   - **Secure:** if `cookie.secure`, the origin must be potentially trustworthy: `https`, or `http` to `localhost` / `*.localhost` / `127.0.0.1` / `::1`. `http://example.com` does not receive `Secure` cookies. (Chrome’s localhost exception, not raw RFC 6265. Documented difference from a strict RFC-only reader.)
7. No public-suffix check on **read**. If a `.com` cookie is in the store, and it domain-matches, emit it. Required test 16.
8. No SameSite / CHIPS / `__Host-` prefix re-validation on read.

`get` without a URL skips steps 1–7. It still applies sendable-octet, `names`, and `include_expired`.

Binding `report(..., domains=)` and `extract(Request::….domains(…))` stay on `some_domain_in_host` only. Do not sneak RFC 6265 into those verbs.

Required URL-match tests (table-driven, no browser):

| # | Cookie | URL | Keep? |
| --- | --- | --- | --- |
| 1 | `.example.com` `/` | `https://www.example.com/` | yes |
| 1b | `.example.com` `/` | `https://example.com/` | **yes** (apex; strip the stored `.` before compare) |
| 2 | host-only `www.example.com` | `https://example.com/` | no |
| 2b | host-only `example.com` | `https://www.example.com/` | **no** |
| 3 | host-only `api.example.com` | `https://www.example.com/` | no |
| 4 | `.example.com` `/admin` | `https://www.example.com/` | no |
| 5 | `.example.com` `/admin` | `https://www.example.com/admin` | yes |
| 6 | `.example.com` `/admin` | `https://www.example.com/admin/` | yes |
| 7 | `.example.com` `/admin` | `https://www.example.com/administration` | no |
| 8 | `Secure` + `.example.com` | `http://www.example.com/` | no |
| 9 | `Secure` + `.example.com` | `https://www.example.com/` | yes |
| 10 | `Secure` + `localhost` | `http://localhost/` | yes |
| 11 | IPv4 host-only `127.0.0.1` | `http://127.0.0.1/` | yes |
| 12 | `.example.com` | `http://example.com.evil.net/` | no |
| 13 | empty / missing cookie path | `https://example.com/x` | treat as `/`, yes |
| 14 | `EXAMPLE.COM` vs `example.com` | https | yes (ASCII case-fold) |
| 15 | `ftp://example.com/` | — | `InvalidUrl` before match |
| 16 | `.com` `/` | `https://www.example.com/` | **yes** (no PSL on read; no reducer to drop it) |
| 17 | name or value contains `\\r` / `\\n` | any | omit + warning (sendable set) |

### Expiry and names

- `include_expired` default **false** on `GetRequest` / `FromPathRequest` / Python / Node / CLI `get`.
- Drop when `cookie.expires == Some(ts)` and `ts < now_unix` (`SystemClock`, same clock `extract` already uses). Equality (`ts == now`) stays.
- `expires == None` is a session cookie and is **never** expired. This matches Chromium `expires_utc == 0` → `None` (`date.rs` L1–4).
- `names`: case-sensitive exact match on `cookie.name`; multiple names are OR. `names=[]` (empty vec) matches nothing, same contract as empty `domains` on extract (ADR 0001). A `names` entry that is `""` is `RequestError::EmptyNameSelector`.
- `extract` / `chrome()` / `cookies_from_path` do not grow these filters.

### Profile resolver (cookie database path)

Unification already specified one crate-private resolver in `registry`, listing drafts only, no keys ([unified-extract-api.md](unified-extract-api.md) “Profile resolver”). This design **adds one key**.

Match order after the empty-string and opaque-id and lossy-display checks:

1. `profile_id` (exclusive, first)
2. Lossy display of **profile directory or persistent source path** → `LossyProfilePath` (even if a name would also match)
3. Unique among:
   - `display_name`
   - `directory_name`
   - profile directory `Path` equality (std `Path`, same Unix/Windows rules as unification)
   - **any non-lossy persistent source path** on that profile (`EngineProfileDraft.sources` where `role == persistent`, or `ChromiumProfile.persistent_candidates[].path`)

Persistent sources only: Chromium `Cookies` / `Network/Cookies`, Mozilla `cookies.sqlite`, Safari `Cookies.binarycookies`, IE `WebCacheV01.dat`. Session files (`sessionstore`, `recovery.jsonlz4`) are **not** keys.

| Query | `get(..., profile=q)` | `from_path(q)` |
| --- | --- | --- |
| Display name `Work` | that profile, if unique | n/a (not a file) |
| Profile dir | that profile | n/a unless it is a cookie file |
| `…/Default/Network/Cookies` listed for Chrome | that **profile** (persistent **and** session), installation keys | **that file only**; credentials via path-universe options; browser need not be registered |
| Copied `Cookies` on a USB stick | `UnknownProfile` (not listed) | works if the file is classifiable |
| Lossy source path | `LossyProfilePath`; use opaque id | path universe uses the real `Path`, not the display string |

`from_path` must not call `resolve_profile_query`. A file that happens to sit inside a Chrome profile is still path-universe if the caller used `from_path`.

Add resolver tests 20–23 to the unification table:

| # | Setup | Query | Result |
| --- | --- | --- | --- |
| 20 | Unique Chrome profile, selected `Network/Cookies` | that absolute path | that `profile_id` |
| 21 | Same, lower-precedence `Cookies` candidate that exists | that path | that `profile_id` |
| 22 | Two channels, identical relative `Default/Cookies` (different absolute paths) | one absolute path | the one whose source path equals |
| 23 | Known browser, file is not a listed source | that path | `UnknownProfile` (caller wanted `from_path`) |

Still: zero `SystemKeyProvider` hits during resolve.

### Warnings vs throw

| Situation | `get` | job `from_path` | `extract` / `chrome()` (frozen) |
| --- | --- | --- | --- |
| Missing `browser` | `RequestError::MissingBrowser` | n/a | n/a |
| Unknown / empty / ambiguous / lossy profile | `RequestError` (unification) | n/a | n/a / shim |
| Invalid URL / empty name selector | `RequestError` | `RequestError` | n/a |
| Browser not installed / no selected source succeeded | **Engine error** (same as `extract`) | n/a | already error / not-installed |
| Classify / total decrypt fail | **Engine error** | existing `DirectPathError` / engine (no new harvest) | error or empty depending on path |
| Some rows skipped (`decrypt_failed`, v20, decode) | **Ok** + warning `"skipped N rows (decrypt_failed)"` | **no warning** — those rows are already dropped by `cookies_from_path`; `warnings` may be empty or only filter/octet lines | cookies that were emitted; no warnings channel |
| Successful read, URL/names/expiry match nothing | **Ok** empty + warning `"url matched 0 of N cookies"` | **Ok** empty + same filter warning | `Ok([])` for domain miss |
| CTL / empty name omitted | **Ok** + sendable-set warning | **Ok** + sendable-set warning | emitted (frozen) |
| Timeout / cancel | Engine + `stop_reason` | Engine + `stop_reason` | same |

Warning text is **not** a stable contract (ADR 0001). Branch on emptiness + exception type, not on the string. Never put a cookie value, key byte, unretracted home path, or raw URL (see `InvalidUrl`) in a warning. Issue **codes** and counts are fine. `REDACTED_PATH` if a path must appear.

“Never silent empty” means: a **failure** is not `Ok([])`. A **filter miss** is `Ok([])` with a warning so it is not silent in logs.

`get` harvests row-level warnings from a report-shaped outcome of the **same** `ProfileSelection` it used (`LegacyFirstProfile` or `ProfileId`). That is a crate-private seam, not `extract_report(Request)` without a profile (`AllProfiles`). `status == partial` is still `Ok`. `status == failed` or `no_sources` with zero selected successes is `Err`.

`from_path` does **not** grow a path-universe issue stream in this series. Follow-on if those warnings matter.

### Interaction with the unification series

```text
#261 thin browser(id)          bindings only; no profile; Node options bag
PR1 RequestError               unknown browser on resolve_registered_browser
PR2 resolve_profile_query      + cookie DB path if not already in that PR
PR3 Request.profile
    extract_report
PR4 shims / deprecations       chrome_profile, firefox_profile retarget
PR5 CLI --profile without --report
PR6 binding profile= kwargs
── this series ────────────────────────────────────────────
PR-G1 GetFilter + URL matcher  crate-private tests, no public API
PR-G2 get + CookieResult       Rust public, additive public-api snapshot
                               NO crate-root fn report
PR-G3 from_path job wrapper    Rust; no row-level warning harvest
PR-G4 Python four names
PR-G5 Node four names          patch-loader.js + EXPECTED_EXPORTS
PR-G6 CLI subcommands
PR-G7 ADR 0004 + user docs
```

`#261` still must not invent profile. This series must not invent a third `browser()` arity. `extract(Request::browser(id))` without profile remains `LegacyFirstProfile` and unsorted-all-rows.

If PR2 has not merged when this series starts, fold tests 20–23 into PR2 rather than landing a resolver twice.

### Module placement

New code lives in `rookie-rs/src/get.rs` (job types + URL matcher + flatten/filter + redacted URL debug). Re-export from `lib.rs`. Do not grow `lib.rs` or `report_build.rs` with URL rules. Do not add `fn report` to `lib.rs`. Resolver cookie-DB matching stays in `registry` listing drafts (unification placement). This is a new file for a new feature, not a modularization of the oversized modules.

A crate-private `LegacyFirstProfile` report/engine helper (selection + compatibility projection + issues) may live next to existing `legacy::browser_cookies_with_runtime` rather than inventing a second ranker.

---

## API / Interface Changes

### Rust

```rust
// rookie-rs/src/get.rs — additive, re-exported from lib.rs

/// Job request. Builds a store selection plus a send/name/expiry filter.
/// Fields are private. Absence is “not called.”
/// Manual Debug: URL is redacted (never the raw caller string).
#[derive(Clone, PartialEq, Eq)]
pub struct GetRequest { /* private */ }

impl std::fmt::Debug for GetRequest { /* redact url */ }

impl GetRequest {
  /// Start from a browser id or alias. `url` remains optional.
  pub fn browser(id: impl Into<String>) -> Self;

  /// Start from a URL. `browser` is still required before [`get`].
  /// The raw string is not stored; see `InvalidUrl` redaction.
  pub fn url(url: impl Into<String>) -> Self;

  pub fn profile(self, query: impl Into<String>) -> Self;
  pub fn names(self, names: impl Into<Vec<String>>) -> Self;
  pub fn include_expired(self, yes: bool) -> Self; // default false
  pub fn timeout(self, timeout: std::time::Duration) -> Self;
  pub fn cancellation(self, handle: CancellationHandle) -> Self;
}

pub struct CookieResult { /* private; not Clone */ }

impl CookieResult {
  pub fn cookies(&self) -> &[Cookie];
  pub fn warnings(&self) -> &[String];
  pub fn browser_id(&self) -> &str;
  pub fn profile_id(&self) -> Option<&str>;
  pub fn header(&self) -> String;
  pub fn netscape(&self) -> String;
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSiteLabel { None, Lax, Strict }

pub fn same_site_label(same_site: i64) -> Option<SameSiteLabel>;

pub fn get(request: GetRequest) -> Result<CookieResult>;

/// Alias of [`browser_profiles`]. No decrypt.
pub fn profiles(browser_id: &str) -> Result<Vec<report::ProfileDescriptor>> {
  browser_profiles(browser_id)
}

// NO crate-root `pub fn report`.
// Power verb remains unification's extract_report:
//   pub fn extract_report(request: Request) -> Result<report::ExtractionReport>;

#[derive(Clone, PartialEq, Eq)]
pub struct FromPathRequest { /* private; manual Debug, redacted url */ }

impl FromPathRequest {
  pub fn new(path: impl Into<std::path::PathBuf>) -> Self;
  pub fn url(self, url: impl Into<String>) -> Self;
  pub fn names(self, names: impl Into<Vec<String>>) -> Self;
  pub fn include_expired(self, yes: bool) -> Self;
  pub fn timeout(self, timeout: std::time::Duration) -> Self;
  pub fn cancellation(self, handle: CancellationHandle) -> Self;
  /// Chromium credentials when the file is a Chromium DB.
  /// Omitted → same Automatic / DirectPathRequest rules as today.
  pub fn chromium_credentials(self, source: direct_path::ChromiumCredentialSource) -> Self;
}

pub fn from_path(request: FromPathRequest) -> Result<CookieResult>;
```

`Request` **does not** gain `url`, `names`, or `include_expired`. After unification it gains only `profile`:

```rust
// already specified in unified-extract-api.md — unchanged here
impl Request {
  pub fn profile(self, query: impl Into<String>) -> Self;
}
pub fn extract(request: Request) -> Result<Vec<Cookie>>;
pub fn extract_report(request: Request) -> Result<report::ExtractionReport>;
pub fn browser(id: &str, domains: Option<Vec<String>>) -> Result<Vec<Cookie>>;
```

Rejected:

```rust
// DO NOT — collides with `pub mod report`
pub fn report(request: Request) -> Result<report::ExtractionReport>;
// DO NOT — source-breaking
pub fn browser(id: &str, domains: Option<Vec<String>>, profile: Option<&str>) -> Result<Vec<Cookie>>;
// DO NOT — kitchen sink; extract would have to ignore or honor url
impl Request {
  pub fn url(self, url: impl Into<String>) -> Self;
}
// DO NOT — frozen
pub fn chrome(domains: Option<Vec<String>>, url: Option<&str>) -> Result<Vec<Cookie>>;
// DO NOT — frozen type; this series does not add Clone
impl Clone for Cookie { ... }
// DO NOT — illegal Rust
impl CookieResult {
  pub fn warnings(&self) -> &[str];
}
```

Rust call shape:

```rust
let result = rookie_cookies::get(
  rookie_cookies::GetRequest::url("https://github.com")
    .browser("chrome")
    .profile("Work")
    .names(vec!["user_session".into()]),
)?;
let header = result.header();
let report = rookie_cookies::extract_report(
  rookie_cookies::Request::browser("chrome").profile("Work"),
)?;
```

`GetRequest::url` and `GetRequest::browser` are both constructors; either order works; last write wins. `get` without a browser field set is `RequestError::MissingBrowser`. `profile("")` is stored and rejected by the resolver (`EmptyProfileSelector`), same as unification.

`RequestError` gains (same module as unification PR1):

| Variant | `code()` | Stored payload |
| --- | --- | --- |
| `MissingBrowser` | `missing_browser` | none |
| `InvalidUrl { display: String }` | `invalid_url` | **redacted only** — never the raw caller string |
| `EmptyNameSelector` | `empty_name_selector` | none |

**URL redaction (normative, one helper used by `InvalidUrl`, `GetRequest`/`FromPathRequest` `Debug`, and tracing):**

1. If `url::Url::parse` succeeds: store `scheme` + `://` + host (no userinfo) + path. Drop query, fragment, password, username.
2. If parse fails: do **not** store the caller string. Apply a heuristic that deletes `user:pass@` (the last `@` before the first `/` after an optional scheme) and then store either `"<unparseable>"` or `scheme://<unparseable>` when a scheme is visible. Credentials must not survive either arm.
3. Required test: `https://user:secret@example.com/` does not appear in `InvalidUrl` `Debug`/`Display`, `GetRequest` `Debug`, or the tracing fields for that call. Same for unparseable `https://user:secret@%zz`.

Human `Display` of `RequestError` is not stable.

### Python

```python
# bindings/python/rookie_cookies/rookie_cookies.pyi  +  __init__.py

def get(
    url: Optional[str] = None,
    *,
    browser: str,
    profile: Optional[str] = None,
    names: Optional[List[str]] = None,
    include_expired: bool = False,
    timeout: Optional[float] = None,
    cancellation: Optional[CancellationHandle] = None,
) -> CookieResult: ...

def same_site_label(same_site: int) -> Optional[Literal["None", "Lax", "Strict"]]: ...

def profiles(browser_id: str) -> ProfileDescriptorList: ...
# profiles is an alias of browser_profiles; both names stay exported.

def report(
    browser: str,
    *,
    profile: Optional[str] = None,
    domains: Optional[List[str]] = None,   # host-list, power only
    timeout: Optional[float] = None,
    cancellation: Optional[CancellationHandle] = None,
) -> ExtractionReport: ...

def from_path(
    path: str,
    *,
    url: Optional[str] = None,
    names: Optional[List[str]] = None,
    include_expired: bool = False,
    browser_id: Optional[str] = None,
    local_state_path: Optional[str] = None,
    plaintext_only: bool = False,
    timeout: Optional[float] = None,
    cancellation: Optional[CancellationHandle] = None,
) -> CookieResult: ...
```

No module-level `header()`. Call `get(...).header()`.

`browser` on `get` is **keyword-only and required**. `get("https://github.com")` is `TypeError` (missing `browser`) at the Python layer; we do not parse the positional as a browser id. `get("chrome")` is therefore also `TypeError`, not a surprising URL parse.

`profiles` is assigned to the same function object as `browser_profiles` (or a one-line wrapper with an identical signature). `browser_profiles` stays in `__all__`.

`report(...)` returns the same dict `browser_report` returns. It is not a `CookieResult`. Timeout/cancel on `report` go through `extract_report(Request)` once unification lands; until then, `report` may omit those kwargs rather than fake them.

`from_path` credential kwargs match today’s Chromium path options (at most one of `browser_id` / `local_state_path` / `plaintext_only`). Competing selectors stay `RookieRequestError`. `cookies_from_path` remains the frozen list-returning alias (includes expired, no URL match, no octet filter).

`CookieResult` is a pure-Python class in `__init__.py` wrapping the rust `(cookies, warnings, browser_id, profile_id)` tuple. `.as_jar()` builds a jar from the **already filtered** list (do not call raw `to_cookiejar` on unfiltered rows). Export `CookieResult` and `same_site_label` from `__all__`.

`#261` `browser(id, domains=None)` and this series’ `browser(..., profile=)` stay. They are store aliases.

Errors: request faults → `RookieRequestError` (`ValueError`). Engine faults → `RookieEngineError` (`RuntimeError`). Same `classify_fault` path as [`errors.rs`](../../bindings/python/src/errors.rs).

### Node

One options bag (the `#261` constraint). Update `bindings/node/scripts/patch-loader.js` destructure list, `module.exports.*`, `canonicalDeclarationPatterns`, and `EXPECTED_EXPORTS` in [`index.spec.mjs`](../../bindings/node/__test__/index.spec.mjs). Do **not** hand-edit `index.d.ts` without a loader change.

```ts
export interface GetOptions {
  url?: string | null
  browser: string
  profile?: string | null
  names?: string[] | null
  includeExpired?: boolean | null   // default false
  timeoutMs?: number | null
  cancellation?: CancellationHandle | null
}

export interface CookieResultObject {
  cookies: CookieObject[]     // sendable
  header: string
  netscape: string
  warnings: string[]
  browserId: string
  profileId: string | null
}

export declare function get(options: GetOptions): Promise<CookieResultObject>

export declare function profiles(
  browserId: string,
): Promise<ProfileDescriptorObject[]>  // alias of browserProfiles

export interface ReportOptions {
  browser: string
  profile?: string | null
  domains?: string[] | null
  timeoutMs?: number | null
  cancellation?: CancellationHandle | null
}

export declare function report(
  options: ReportOptions,
): Promise<ExtractionReportObject>

export interface FromPathOptions {
  path: string
  url?: string | null
  names?: string[] | null
  includeExpired?: boolean | null
  browserId?: string | null
  localStatePath?: string | null
  plaintextOnly?: boolean | null
  timeoutMs?: number | null
  cancellation?: CancellationHandle | null
}

export declare function fromPath(
  options: FromPathOptions,
): Promise<CookieResultObject>

export type SameSiteLabel = "None" | "Lax" | "Strict"
export declare function sameSiteLabel(sameSite: number): SameSiteLabel | null
```

Missing `browser` on `get` is `InvalidArg` (`FaultKind::Request`). Named functions (`chrome`, …) stay positional as shipped. `browserProfiles` / `browserReport` / `cookiesFromPath` stay.

`CookieObject.sameSite` remains `number`. Do not add a string field to the frozen cookie object.

### CLI

New users see subcommands. Existing flags stay.

```text
rookie-cookies get https://github.com -b chrome -p Work
rookie-cookies get https://github.com --name user_session --format header
rookie-cookies get -b chrome                          # no URL: that store, minus expired
rookie-cookies profiles chrome
rookie-cookies report chrome -p Work
rookie-cookies from-path /path/to/cookies.sqlite --url https://github.com

# compatibility (unchanged grammar)
rookie-cookies --browser chrome
rookie-cookies --list-profiles --browser chrome
rookie-cookies --report --browser chrome
rookie-cookies --path FILE
```

Clap shape: existing `Args` gains `#[command(subcommand)] command: Option<JobCommand>`. When `command` is `Some`, the legacy default-`load()` path does not run.

```text
get [URL] -b/--browser <ID> [-p/--profile <Q>]
          [--name <NAME>]... [--include-expired]
          [--format json|netscape|header]     # default json
          [--timeout-secs N]

profiles <BROWSER>

report <BROWSER> [-p/--profile <Q>] [-d/--domains <D>]...
       [--format json]                        # netscape still rejected

from-path <PATH> [--url URL] [--name NAME]... [--include-expired]
          [--browser-id ID | --key-path FILE | --plaintext-only]
          [--format json|netscape|header]
```

Rules:

- `get` **requires** `--browser` / `-b`. No URL is legal (dump that store, minus expired, sendable set).
- `get` without `-b` is a clap usage error (exit 2), not an engine scan.
- `--name` is repeatable. `--format header` is legal only on `get` / `from-path`.
- Unification’s `--browser ID --profile Q` (flat extract, **includes expired**, host-list `--domains`) stays for compatibility. New users are told to use `get`.
- `profiles chrome` is `--list-profiles --browser chrome`.
- `report chrome` is `--report --browser chrome` (all profiles). `report chrome -p Work` is one-profile report. CLI `report` does not collide with a Rust module.
- Netscape remains forbidden on `report` / `profiles` / `--list-*` / `--report`.
- `--include-expired` exists only on `get` / `from-path`. Legacy `--browser chrome` does not grow it.

JSON output of `get` is the **sendable** cookie-object array (not the `CookieResult` wrapper). Warnings go to **stderr** (one line each), so `jq` still works on stdout. Non-zero exit + empty stdout on request/engine failure, same as today (`report_with_an_unknown_profile_id_fails_without_machine_output`).

### Public sugar (aliases)

| Documented name | Alias of / definition |
| --- | --- |
| `get` | new |
| `profiles(id)` | `browser_profiles(id)` |
| Python/Node/CLI `report(...)` | `extract_report(Request)` / `browser_report` |
| Rust power verb | `extract_report` (**not** `fn report`) |
| `from_path` (job) | `cookies_from_path` + `GetFilter` → `CookieResult` (no row-issue harvest) |
| Rust `browser(id, domains)` | `extract(Request::browser(id).domains(domains))` |
| Python/Node `browser` | store extract; `#261` + unification `profile=` |
| `chrome()` / `firefox()` / `load()` | frozen first-profile / historical concat |
| `chrome_profile` / `firefox_profile` | unification shims |
| `cookies_from_path` | frozen list, no URL match, includes expired, no octet filter |
| CLI `--browser` / `--list-profiles` / `--report` / `--path` | frozen flag grammar |

---

## Data Model

**None** to persisted or wire types.

- `Cookie` unchanged (eight fields, raw `same_site: i64`, **no `Clone`**).
- `ExtractionReport` / `ProfileIdentity` / `schema_version: 1` unchanged. Still no `directory_name` on the DTO. The resolver reads listing drafts, including persistent source paths, not the public DTO.
- `browser_registry.json` unchanged.
- Python `dto` / `schema/report-dto.schema.json` unchanged. `CookieResult` is not a report DTO and is not schema-generated.
- In-memory only: `GetRequest`, `GetFilter`, `FromPathRequest`, `CookieResult` (not `Clone`), `SameSiteLabel`.

No migration.

---

## Alternatives

### A. Only ship `Request.profile` (previous design, no `get`)

- **Pros:** Smaller series; unification already fills “any browser × one profile × flat cookies.”
- **Cons:** A new user still starts at a store and a host-list. `chrome(["github.com"])` still is not “cookies for this URL.” No warnings channel on the happy path. The packages in the research table are job-oriented; we would remain the awkward one.
- **Decision:** Reject as the *product*. Keep as the *store layer*.

### B. Make `chrome()` take `url=`

- **Pros:** Zero new names for the 90% Chrome caller.
- **Cons:** Frozen signature (ADR 0001). Every named function would need the same kwargs. Return type cannot grow warnings without breaking `list[dict]`. Firefox/Yandex stay second-class.
- **Decision:** Reject. `chrome()` stays `domains=None` only.

### C. Fold `url` / `names` / `include_expired` onto `Request` (one request type)

- **Pros:** One builder in Rust; `extract` and `get` share a type.
- **Cons:** `extract(Request::browser("chrome").url(...))` either ignores `url` (trap) or changes frozen unsorted-all-rows / include-expired semantics. `Request` becomes a kitchen sink (`domains` host-list **and** `url` send-filter on one struct). Bindings would have to explain which fields which verb honors.
- **Decision:** Reject. `GetRequest` is a facade that builds a store selection + `GetFilter`.

### D. `get` returns `CookieJar` / a raw list by default

- **Pros:** Smallest Python 90% line (`requests.get(url, cookies=get(...))`).
- **Cons:** Warnings, header, netscape, profile id have nowhere honest to live. A list vs report split is the vomit. Subclassing `CookieJar` lies to `isinstance`.
- **Decision:** Reject. `CookieResult` + `.as_jar()`. First example shows `.as_jar()`.

### E. `get(url)` without `browser` walks a documented order

- **Pros:** One-liner; matches folklore `browser_cookie3` / unadorned pycookiecheat.
- **Cons:** Wrong-account cookies; hides engine failure behind another browser’s empty match; non-deterministic CI. We already have `load()` for concat and it is the most-complained-about verb in this crate’s history.
- **Decision:** Reject. `MissingBrowser`.

### F. Third positional on Rust `browser(id, domains, profile)` plus `url` later

- **Pros:** One function everywhere.
- **Cons:** Already rejected in unification (source-breaking). Adding `url` as a fourth would be worse.
- **Decision:** Reject. Still.

### G. Public `Browser` / `Profile` object graph

- **Pros:** `browser("chrome").profile("Work").get(url)`.
- **Cons:** Explicit non-goal (ADR 0001 deferred trait, unification alt C). Lifetime/ownership across bindings is expensive.
- **Decision:** Reject.

### H. Engine-specific SQL send-predicate, or a full-label `Request.domains` reducer

- **Pros:** Avoid decrypting sibling / TLD hosts; still a superset of send-matching if the chain includes every DNS label (`…, "com"`).
- **Cons:** Touches every decoder and the `domains=` contract, or decrypts every `.com` row. A two-label chain is a silent PSL/eTLD+1 and **contradicts** “no PSL on read.”
- **Decision:** Defer. This series: no `Request.domains` on `get`; post-filter only. Required test 16 locks the `.com` case.

### I. Crate-root `pub fn report` next to `pub mod report`

- **Pros:** Same four identifiers in every language.
- **Cons:** Does not compile. `pub mod report` is the DTO home (`ExtractionReport`, `ProfileDescriptor`, `public-api/*.txt`, bindings, `generate-dto-schema`). Renaming the module is a breaking public-api change and is out of scope. A function named `report` would also shadow `report::ExtractionReport` at the crate root.
- **Decision:** Reject. Rust power verb is `extract_report`. Bindings and CLI keep `report()`.

---

## Security & Privacy

| Threat | Severity | Mitigation |
| --- | --- | --- |
| `get(url)` without browser concat sends the wrong account | **High** | `MissingBrowser`; no scan |
| Ambiguous `Default` / two cookie DBs named similarly | **High** | existing `AmbiguousProfile`; cookie-DB path uses `Path` equality, not basename |
| `profile=/…/Cookies` decrypts the whole profile including session | **Medium** (intended) | document vs `from_path`; same local-user trust model |
| URL with embedded credentials in `InvalidUrl` / `GetRequest` Debug | **High** | never persist raw caller string; redaction helper; test `user:secret` absent from Debug/Display |
| Warnings leak cookie values or key bytes | **Medium** | codes + counts only; reuse `REDACTED_PATH` |
| `header()` / `as_jar()` / netscape emit CTL / CR-LF (header injection) | **High** | omit + warn **once** when building `CookieResult`; all projections share the sendable set |
| Secure cookie sent to `http://example.com` | **High** | RFC/Chrome secure rule; tests 8–10 |
| Resolver prompts Keychain just to match a Cookies path | **High** | listing seams only; zero key-provider test still applies |
| `from_path` of an unregistered DB vs `profile=` of a registered one confused | **Medium** | table in docs; `from_path` never calls the resolver |
| Decrypting the whole profile for a URL filter | **Low** | same process already allowed to read the profile; extra rows not emitted; follow-on alt H |

Auth: none. Local library. Job URL is not interpolated into SQL (`get` does not pass `Request.domains`).

`get` is read-only. No set/delete (non-goal).

---

## Observability

No new telemetry backend. Existing `tracing` targets plus:

| Event | Level | Fields (no secrets) |
| --- | --- | --- |
| `get` start | debug | `canonical_id`, `has_url`, `has_profile`, `name_count`, `include_expired`, `selection=legacy_first\|profile_id` |
| `get` url parse fail | info | `code=invalid_url` (redacted display only) |
| `get` empty after filter | info | `prefilter_count`, `reason=url\|names\|expired\|octet` |
| `get` warnings harvested | debug | `issue_codes`, `skipped_rows` |
| `resolve_profile_query` ok | debug | existing + `query_kind=cookie_db` |
| Key provider during resolve | — | must not fire |

Metrics (optional, not required to land):

- `get_total{result=ok|empty|request|engine}`
- `get_filter_drop{reason=url|name|expired|octet}`

Human warning text is not stable. CLI: warnings on stderr; machine cookies on stdout.

---

## Rollout

This is 0.6.0-alpha. No feature flag. Additive API + new CLI subcommands + a new ADR. No data migration.

1. Land unification PRs 1–6 (or fold cookie-DB path into PR2).
2. Land PR-G1…G7 below. Each independently reviewable and green.
3. Update `rookie-rs/public-api/{linux,macos,windows}-{all,no-default}-features.txt` in PR-G2 (and G3 if `FromPathRequest` is a distinct public type). `temporary-exceptions.json` stays empty. Snapshots must **not** grow `pub fn report`.
4. Changelog `[Unreleased]` / next 0.6.0-alpha: **Added** `get` / `profiles` / binding `report` / `from_path` (job) and CLI subcommands; **Changed** “recommended entry is `get` (ADR 0004)”; **Not changed** `chrome()` / `load()` / `Cookie` / report DTO / `pub mod report`.
5. Point README “Which API” and `docs/{Python,Rust,JavaScript}.md` at the job names. Rust docs lead with `get` + `extract_report`. Leave the old examples working.
6. **Rollback:** revert the PR. Callers that never called `get` are unaffected. `browser_report` name/path widening remains a unification concern, not this series’.

Docs PR (G7) also writes [`docs/adr/0004-get-is-the-recommended-entry.md`](../adr/0004-get-is-the-recommended-entry.md) using the text in [ADR 0004](#adr-0004-get-is-the-recommended-entry).

---

## ADR 0004: `get` is the recommended entry

Drop this file in as `docs/adr/0004-get-is-the-recommended-entry.md` in PR-G7.

```markdown
# ADR 0004: `get` is the recommended entry

- Status: Accepted
- Date: 2026-08-18
- Scope: documented default extract API across Rust, Python, Node, and CLI
- Amends: the *recommended* entry implied by ADR 0001 named functions and
  by docs that currently lead with `browser()` / `chrome()`
- Does not amend: ADR 0001 frozen `chrome()` / `load()` / `Cookie` / report
  DTO / no all-profile flatten; ADR 0002 registry; ADR 0003 selector grammar
  (except adding cookie-database path as a resolver key)

## Context

ADR 0003 unified profile *queries* so any registered browser can select one
profile by id, name, directory, or path. The public verbs remained
store-oriented (`browser("chrome")`, `extract(Request)`, `chrome()`).
Callers who wanted “cookies I can send to this URL” still used a host-list
`domains=` filter that is not RFC 6265 send-matching, and still received a
bare `Vec<Cookie>` with no warnings channel.

## Decision

1. The recommended entry is `get`. It requires a browser id or alias,
   accepts an optional URL, optional profile query, and optional cookie
   names, defaults `include_expired` to false, and returns a
   `CookieResult` (sendable cookies + warnings + header/netscape/jar
   projections). `get` without a browser is a request error. No-profile
   `get` uses `ProfileSelection::LegacyFirstProfile` and the
   compatibility cookie projection (`extract` / `chrome()`), not a
   listing-first `ProfileId`.
2. The other documented names are `profiles` (alias of
   `browser_profiles`), binding/CLI `report` (alias of `extract_report` /
   `browser_report`), and `from_path` (path universe + the same
   send/name/expiry filter). Rust does not add `fn report`; the crate
   already has `pub mod report`.
3. The unified resolver also matches a non-lossy **persistent cookie
   database path**. That is not `from_path`: `from_path` does not require
   the file to belong to a registered browser and extracts that file only.
4. `Request` remains the store operation. Job filters (URL, names,
   include_expired) do not live on `Request`. Rust `browser(id, domains)`
   stays two arguments. `get` does not pass a host-list reducer that
   would drop PSL parents the post-filter would keep.

## Consequences

New examples and README lead with `get`. Existing named functions and
`extract` stay source-compatible and unsorted-all-rows. Downstream that
never calls `get` does not move.
```

0003’s three decisions (one resolver, `browser_report` middle arg is a query, CLI `--profile` requires `--browser` only) stand. Cookie-DB path is an additional key under 0003’s “one resolver,” recorded here so 0003 does not get rewritten in place.

---

## Open Questions

None that block implementation. Follow-ons, not this series:

1. Full-label `Request.domains` reducer or a dedicated SQL send-predicate (alt H), so `get(url)` need not decrypt the whole profile.
2. `CancellationHandle` on CLI `--report` (already a unification follow-on).
3. Partition / CHIPS-aware `get` (would need a `Cookie` or result-side field; frozen `Cookie` forbids sneaking it onto the eight-field struct).
4. `get(..., browser="auto")` as an **explicit** opt-in scan. Not implied by omitting `browser`.
5. Path-universe issue stream so job `from_path` can harvest row-level decrypt skips.

---

## Risks

| Risk | Severity | Mitigation |
| --- | --- | --- |
| Users treat `get("https://example.com/", browser="chrome")` as today’s `chrome(["example.com"])` and miss sibling-host cookies | **Medium** | Docs table; `domains=` stays on `extract` / binding `report`; changelog “send vs dump” |
| `CookieResult` instead of a list breaks the “it just returns cookies” reflex | **Low** | `__iter__` / Node `.cookies`; first example is `.as_jar()` |
| Unification has not landed; this series is stacked | **Medium** | PR plan states the gate; G1 (matcher) can land first with no public API |
| CLI subcommands + legacy flags confuse clap (`report` vs `--report`) | **Medium** | Tests for both; `--help` lists subcommands first |
| `header()` `"; "` differs from `CookieToString` `";"` | **Low** | Document; do not change the trait; examples/http migrate to `get().header()` in G7 |
| Node `patch-loader.js` forgets `get` / `fromPath` | **Medium** | `EXPECTED_EXPORTS` + loader patterns in the same PR (lesson from #261) |
| `get` without profile uses listing-first `ProfileId` and diverges from `chrome()` | **High** | Crate-private `LegacyFirstProfile`; G2 two-profile fixture: set-equality with `extract` / `chrome()`, **not** `browser_profiles()[0]`, **not** the union |
| Implementer copies a two-label suffix-chain and drops `.com` cookies | **High** | This series forbids `Request.domains` on `get`; test 16 |
| Cookie-DB path matches a session file or a copied DB | **Low** | Persistent sources only; unknown path → `UnknownProfile`, point at `from_path` |
| Someone adds crate-root `fn report` in G2 | **High** | Explicit reject I; public-api snapshot must not grow that symbol |

---

## References

- [unified-extract-api.md](unified-extract-api.md) — store layer; resolver algorithm; `RequestError` site; CLI `--profile` matrix; #261 constraints
- [modularize-oversized-browser-modules.md](modularize-oversized-browser-modules.md) — file splits; do not redo here
- [ADR 0001](../adr/0001-cookie-extraction-compatibility-and-report-contracts.md) — frozen `Cookie`, `chrome()`, `load()`, no all-profile flatten, report DTO
- [ADR 0002](../adr/0002-authoritative-browser-registry.md) — registry, `ProfileSelection`, selection before keys
- [ADR 0003](../adr/0003-unified-profile-query.md) — one resolver; `browser_report` query; CLI `--profile` + `--browser`
- RFC 6265 §5.1.3 (domain-match), §5.1.4 (path-match), §5.4 (send), §4.2.1 (Cookie header)
- [chrome.cookies.getAll](https://developer.chrome.com/docs/extensions/reference/api/cookies#method-getAll)
- Playwright `BrowserContext.cookies(urls)`
- [`rookie-rs/src/lib.rs`](../../rookie-rs/src/lib.rs) `Request` / `extract` / `browser` / `pub mod report`
- [`rookie-rs/src/common/utils.rs`](../../rookie-rs/src/common/utils.rs) `host_matches_domain`
- [`rookie-rs/src/browser/cookie_record.rs`](../../rookie-rs/src/browser/cookie_record.rs) `DomainScope::from_stored`
- [`rookie-rs/src/browser/registry/chromium.rs`](../../rookie-rs/src/browser/registry/chromium.rs) `LegacyFirstProfile` rank
- [`rookie-rs/src/browser/registry/gecko.rs`](../../rookie-rs/src/browser/registry/gecko.rs) `select_legacy_gecko_profile`
- [`bindings/python/rookie_cookies/__init__.py`](../../bindings/python/rookie_cookies/__init__.py) `to_cookiejar`
- [`bindings/python/rookie_cookies/rookie_cookies.pyi`](../../bindings/python/rookie_cookies/rookie_cookies.pyi)
- [`cli/src/args.rs`](../../cli/src/args.rs), [`cli/src/main.rs`](../../cli/src/main.rs)
- [`bindings/node/scripts/patch-loader.js`](../../bindings/node/scripts/patch-loader.js)

---

## PR Plan

Independently mergeable. Each PR is green alone. Do not combine “new matcher” with “rewrite the CLI” in one review.

| PR | Title | Depends on | Ships | Tests that must exist |
| --- | --- | --- | --- | --- |
| **Gate** | Unification through `extract_report` + resolver + `RequestError` + #261 thin `browser` | — | store layer | as specified in unified-extract-api.md |
| **G0** | Resolver: cookie-DB path key | Gate PR2 (or fold into it) | no public API | table rows 20–23; zero key-provider hits |
| **G1** | `GetFilter` URL / name / expiry / octet matcher | none (crate-private) | `rookie-rs/src/get.rs` matcher + unit tests | URL table 1–17 including **1b apex**, **2b host-only parent**, **16 `.com`**, **17 CTL**; expiry `None` vs `Some(past)`; names case; empty names; redaction helper (`user:secret` absent) |
| **G2** | Rust `get` + `GetRequest` + `CookieResult` + `same_site_label` | Gate, G1, G0 | public symbols; `public-api/*.txt` | **no** `pub fn report`; `warnings() -> &[String]`; `CookieResult` is not `Clone`; no-profile `get(include_expired=true)` **set-equals** `extract`/`chrome()` on a two-profile fixture (not `browser_profiles()[0]`, not the union); with-profile path is report flatten (session may appear); missing browser; `InvalidUrl`/`GetRequest` Debug hide secrets; not-installed → extract’s error, not `UnknownProfile`; partial decrypt → warnings + cookies; total fail → `Err`; `header()` uses `"; "` |
| **G3** | Rust `from_path` job wrapper | G2 | `FromPathRequest` / `from_path` | unregistered file works; `profile=` of the same path goes through resolver (contrast test); URL filter applied; **no** claim of decrypt-skip warnings; filter miss → warning; classify fail → existing `DirectPathError` |
| **G4** | Python `get` / `profiles` / `report` / `from_path` / `CookieResult` / `same_site_label` | G2, G3 | `pyi`, `__init__.__all__` | `get(url)` TypeError without `browser`; first example shape `.as_jar()`; `as_jar()` drops CR-LF names (shared sendable set); `profiles is browser_profiles` or same results; `except RookieRequestError`; no module-level `header`; no `.jar` |
| **G5** | Node `get` / `profiles` / `report` / `fromPath` / `sameSiteLabel` | G2, G3 | `patch-loader.js`, `EXPECTED_EXPORTS`, `index.spec.mjs` | missing `browser` → `InvalidArg`; `await get({url, browser})` shape; loader still generates `index.d.ts`; `.cookies` is the sendable set |
| **G6** | CLI subcommands `get` / `profiles` / `report` / `from-path` | G2, G3 | `cli/src/args.rs`, `main.rs` | `get URL` without `-b` usage error; `get URL -b chrome --format header`; `--browser chrome` still dumps including expired; `profiles chrome` JSON; netscape rejected on `report`; warnings on stderr, JSON on stdout |
| **G7** | ADR 0004 + README + `docs/{Python,Rust,JavaScript}.md` + CHANGELOG | G4–G6 | docs only | `scripts/check-public-api.py` already green from G2; no DTO schema change; Rust docs say `extract_report` not `fn report` |

Recommended merge order: **G1** (no API risk) while unification finishes → **G0** if not folded → **G2** → **G3** → **G4** and **G5** in parallel → **G6** → **G7**.

Out of scope for every PR above: `registry.rs` / `report_build.rs` file splits, `Request.channel`, `chrome()` signature, report DTO, all-profile flatten, set/delete, `Clone` on `Cookie`, crate-root `fn report`, path-universe issue stream.
