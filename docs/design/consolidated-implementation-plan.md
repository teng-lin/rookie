# Consolidated implementation plan: store unification + job `read` / `jar`

- **Author:** Grok (design)
- **Date:** 2026-08-18
- **Status:** Draft (rev 3.2 — review issues 1–8; API review: `into_cookies`, pinned `as_list()` schema, structured `ReadWarning`, header consolidated to method + CLI)
- **Kind:** Execution contract (not a new architecture)
- **Specs (source of truth):** [unified-extract-api.md](unified-extract-api.md) (store layer — still valid); this document (job layer — **replaces** consumer-facing `get` / `CookieResult` from [clean-get-api.md](clean-get-api.md))
- **ADRs:** [0001](../adr/0001-cookie-extraction-compatibility-and-report-contracts.md), [0002](../adr/0002-authoritative-browser-registry.md), [0003](../adr/0003-unified-profile-query.md) (Accepted — do not rewrite); this program **adds [0004](../adr/0004-read-is-the-recommended-entry.md)** in PR 3
- **Hard product constraints:** Ignore GitHub **#260** (no module splits). Ignore GitHub **#261** (no thin Python/Node `browser(id)`). Three PRs only. Additive public-api only.

This document **replaces** rev 2 of the same path (store unification + job `get`). Rev 2’s recommended product — `get(url) → CookieResult` as a send-filtered set — is **rejected**. Implementers must not blend that design back in.

---

## Overview

`rookie-cookies` already has one internal model — registry `canonical_id`, `ProfileSelection` (`LegacyFirstProfile` / `ProfileId` / `AllProfiles`), two projections (`Vec<Cookie>` vs `ExtractionReport`), two origins (registry discovery vs `direct_path`). The public surface still forces new users through store verbs (`chrome()`, host-list `domains=`) rather than a clear job.

This program lands **two layers** in **three independently reviewable PRs**:

1. **PR 1** — crate-private resolver + public `RequestError` + crate-private `GetFilter` (for **`header(url)` later**; no `Request::profile`, no `read`, no CLI change).
2. **PR 2** — store API: `Request::profile`, `extract_report`, widen `browser_report` query, CLI `--profile` without `--report`. Bindings only widen existing `browser_report` / `browserReport` (no new `browser()`). **No** `read` / `jar`.
3. **PR 3** — job API: `read` / `ReadResult` (+`into_cookies`) / `ReadWarning` / Python `jar` / `ReadResult.header` + CLI `header` / `from_path` / binding+CLI names / ADR 0004 / README / language docs / CHANGELOG.

**Product identity:** a **session importer** that can also dump records. Not a `chrome.cookies` clone. Not a forensic dumper as the default.

Frozen throughout: `chrome()` / `load()` / two-arg Rust `browser()` / eight-field `Cookie` (no `Clone`) / report DTO / `schema_version` / `browser_registry.json` / no all-profile flatten into `Vec<Cookie>` (ADR 0001 / 0002 / 0003). No crate-root `pub fn report` next to `pub mod report`. **No public `pub fn get`.**

---

## Why `get(url) → CookieResult` was rejected

| Problem | Detail |
| --- | --- |
| Fake noun | `CookieResult` sits between Profile and Jar without a clear ontology. |
| Split type meaning | Optional `url` on `get` made the same type mean “whole store” or “send-filtered set.” |
| Double send-match | Send-match lived in `GetFilter` / `for_url` **and** again in `http.cookiejar` after `as_jar()`. |
| School-B name, School-A semantics | `get` is a pycookiecheat-shaped name on browser_cookie3 / Playwright snapshot semantics. |
| NotebookLM breakage | NotebookLM persists `storage_state` (records with `Domain` intact). `get(url)` drops `accounts.google.com` / regional SID cookies the allowlist still needs. |

---

## Glossary (locked nouns)

**On disk**

| Noun | Meaning |
| --- | --- |
| **Browser** | Registry id (`chrome`) |
| **Installation** | Stable vs Beta (internal; two `Default` directories stay two `profile_id`s) |
| **Profile** | User-data identity (`ProfileIdentity` / `ProfileDescriptor`) |
| **Source** | One file/role inside a profile; `from_path` names a source with no profile |
| **Cookie** | Frozen eight-field record (`Domain` intact) |

**After copy**

| Noun | Meaning |
| --- | --- |
| **ReadResult** (not CookieResult) | Unfiltered snapshot of one profile or one file |
| **Jar** | Stdlib `http.cookiejar` / client object; **owns send-match** |
| **Report** | `ExtractionReport` diagnostic; not a bag of cookies |

**World 2 (orthogonal — never on `read` / `jar` / `report`)**

| Noun | Meaning |
| --- | --- |
| **URL** | A request target. Allowed only on `header(url)` as a *view* |
| **Family / allowlist** | Caller policy on `Cookie.domain` (NotebookLM keeps its Google ccTLD list) |

---

## Background & Motivation

### Current tree (verified)

| Piece | Path | Role |
| --- | --- | --- |
| `Request` / `extract` / `browser` | [`rookie-rs/src/lib.rs`](../../rookie-rs/src/lib.rs) (`Request` ~L242, `extract` ~L309, `browser` ~L350) | Store operation; no profile field today; `extract` always `legacy::browser_cookies_with_runtime` → `LegacyFirstProfile` |
| `pub mod report` | `lib.rs` L11 | Owns the identifier `report`; DTO home |
| `browser_report` / `browser_profiles` | `lib.rs` ~L468–568 | Opaque-id-only report today; listing |
| `fault_kind` | `lib.rs` ~L198 | Today: `DirectPathError` → Request; else Engine |
| `ProfileSelection` | [`registry.rs`](../../rookie-rs/src/browser/registry.rs) ~L348 | `AllProfiles` · `ProfileId` · `LegacyFirstProfile` |
| `resolve_registered_browser` / `_for` | `registry.rs` ~L186 / ~L191 | Alias → canonical; conversion site for unknown browser |
| `browser_definition` | `registry.rs` ~L710 / `anyhow!` ~L725 | **Do not change** the `anyhow!`; `chromium_based_with_browser_id` stays Engine |
| Chrome fuzzy select | [`registry/chromium.rs`](../../rookie-rs/src/browser/registry/chromium.rs) `select_chromium_profile` ~L1356 | Algorithm to generalize |
| Chromium `LegacyFirstProfile` | `chromium.rs` ~L921–1030 | Ranking; do not reinvent |
| Gecko legacy first | [`registry/gecko.rs`](../../rookie-rs/src/browser/registry/gecko.rs) `select_legacy_gecko_profile` ~L610 | Not `browser_profiles` order |
| Listing seams | `chromium_listing_with_runtime` (~L1474), `gecko_profiles_with_runtime` (`gecko.rs` ~L95), Safari/IE registry modules | extract=false; no keys |
| Compatibility flatten | [`legacy.rs`](../../rookie-rs/src/browser/legacy.rs) `project_canonical_outcome*` (~L122+), [`report_build.rs`](../../rookie-rs/src/browser/report_build.rs) | Chromium persistent / legacy-compatible rows |
| Report assembly | `report_build.rs` `collect_report` ~L562, `browser_extraction_report` ~L1764 | One-id / all-profile reports |
| Host-list filter | [`common/utils.rs`](../../rookie-rs/src/common/utils.rs) `host_matches_domain` ~L12 | Store `domains=`; **not** send-match |
| Domain vs host-only | [`cookie_record.rs`](../../rookie-rs/src/browser/cookie_record.rs) `DomainScope::from_stored` ~L143 | Leading `.` ⇒ domain cookie |
| `Cookie` / `CookieToString` | [`common/enums.rs`](../../rookie-rs/src/common/enums.rs) | Eight fields, no `Clone`; no-space join frozen |
| `format::netscape` | [`common/format.rs`](../../rookie-rs/src/common/format.rs) L13 | `Vec<Cookie>` **by value** — do not change |
| Path universe | [`direct_path/`](../../rookie-rs/src/direct_path/) | `cookies_from_path`; no issue stream |
| public-api | [`rookie-rs/public-api/*.txt`](../../rookie-rs/public-api/) | cargo-public-api field-per-line; [`rookie-rs/public-api/temporary-exceptions.json`](../../rookie-rs/public-api/temporary-exceptions.json) empty |
| CLI `--profile` | [`cli/src/args.rs`](../../cli/src/args.rs) L113–115 `requires_all = ["report", "browser"]` | Pin rewritten in PR 2 |
| Node d.ts | [`bindings/node/scripts/patch-loader.js`](../../bindings/node/scripts/patch-loader.js) (loader/d.ts patching; derives `LEGACY_PLATFORM_FUNCTIONS` from `browser_registry.json`); `EXPECTED_EXPORTS` lives in [`bindings/node/__test__/index.spec.mjs`](../../bindings/node/__test__/index.spec.mjs) ~L29 | Never hand-edit `index.d.ts` |
| Python jar helper | [`bindings/python/rookie_cookies/__init__.py`](../../bindings/python/rookie_cookies/__init__.py) `to_cookiejar` | `ReadResult.as_jar()` loads **all** acquired records (no GetFilter) |
| Octet allow-list | [`examples/javascript/cookie-header.js`](../../examples/javascript/cookie-header.js) | Token / cookie-octet allow-list patterns (example **throws** `TypeError`; `ReadResult` **omits + warns**) |
| Python unknown-browser tests | [`tests/python/test_report_api.py`](../../tests/python/test_report_api.py) | `RuntimeError` → `RookieRequestError` in PR 1 |
| LegacyFirst draft seams | [`legacy.rs`](../../rookie-rs/src/browser/legacy.rs) `browser_cookies_with_runtime` ~L260; [`chromium.rs`](../../rookie-rs/src/browser/registry/chromium.rs) `legacy_chromium_outcome_with_runtime` ~L1535; gecko twin `legacy_gecko_outcome_with_runtime` | No-profile `read` must reuse these `LegacyFirstProfile` drafts — **not** `collect_report(..., None)` |

Notes on this table:

- **Line anchors (`~L…`) are hints, not contracts.** Symbol names are authoritative; anchors drift as the tree moves (e.g. `legacy_gecko_outcome_with_runtime` is already at `gecko.rs` ~L627). Implementers navigate by symbol.
- `resolve_registered_browser_for` is a **private** `fn` today (not `pub(crate)`); PR 1 touches it and may widen visibility as needed.

### Pain points this series closes

1. Three disagreeing profile selectors (`browser_report` opaque-id-only, `chrome_profile` name/dir/path → report, `firefox_profile` name/dir/path → flat sqlite-only).
2. CLI `--profile` illegal without `--report`.
3. Unknown browser on `resolve_registered_browser` is unstructured `bail!` → `FaultKind::Engine`.
4. No honest job verb for “import this browser profile into my HTTP client / storage_state,” without pretending URL send-match is the snapshot.
5. New users learn `read` / `jar` / `profiles` / `report` / `from_path` — **not** a thin binding `browser(id)` (#261 dropped).

---

## Goals & Non-Goals

### Goals

1. One crate-private resolver (id / name / dir / profile path / persistent cookie-DB path).
2. One `Request` with optional profile query; two store projections (`extract` / `extract_report`).
3. Widen `browser_report`’s middle arg to that query without arity change (ADR 0003).
4. CLI `--profile` requires `--browser` only (flat extract **and** report).
5. Job API: every `read` / `from_path` returns the **same** kind of `ReadResult` (never URL-pre-sliced); Python `jar` = `read(...).as_jar()`; `header(url)` is a computed view; send-match authority is the jar (and Playwright/httpx after `storage_state`).
6. Classify unknown/ambiguous/empty/lossy profile and unknown browser on the resolve path as `FaultKind::Request`.
7. ADR 0004 in PR 3; docs lead with `jar(browser=…)` / `read(…).as_list()`, **not** `get(url).as_jar()`.

### Non-goals (do not violate)

- **#260:** do not split oversized modules. Tests stay in-file.
- **#261:** do not add Python/Node `browser(id)`.
- Fourth “cleanup” PR; resurrecting the old 7+14 PR DAG.
- Third arg on Rust `browser()`; crate-root `fn report` / `fn get`; fold `url` onto `Request`.
- `Request.channel`; all-profile flatten into `Vec<Cookie>`; `Clone` on `Cookie` / `ReadResult`.
- Change `chrome()` / `load()` / report DTO / `schema_version` / `browser_registry.json` / `CookieToString` / `format::netscape` by-value.
- `family=` / `hosts=` / `domains=` / `names=` on `read`.
- `CookieResult`, `for_url`, remembered URL on the result, `get` as alias that URL-filters the snapshot.
- Return `CookieJar` from `read` itself.
- Object graph `browser("chrome").profile("Work").cookies()`.
- Rewrite ADR 0003 in place (cookie-DB path is recorded in ADR 0004).
- Expose `netscape` on `ReadResult` unless a later need appears — prefer thin `as_list` + `as_jar` + `header` only.

---

## Key Decisions

| # | Decision | Rationale |
| --- | --- | --- |
| KD-P1 | **Three PRs only.** Mapping: U1+U2+G0+header-matcher → PR 1; U3–U6 → PR 2; job `read`/`jar`/`header`/docs → PR 3. #260 / #261 dropped. | Minimize PRs; independently reviewable. |
| KD-P2 | **Ignore #260 / #261 completely.** | Explicit hard constraints. |
| KD-P3 | **Landing order is strict on `lib.rs`.** PR 1 → PR 2 → PR 3. | Avoid merge fights on the public surface. |
| KD-P4 | **`RequestError` lands fully in PR 1**, variants: `UnknownBrowser`, `EmptyProfileSelector`, `UnknownProfile`, `AmbiguousProfile`, `LossyProfilePath`, `MissingBrowser`, `InvalidUrl`. **Do not add `EmptyNameSelector`** (no `names=` on `read`). | One public-api snapshot; PR 3 does not reopen variants. |
| KD-P5 | **`GetFilter` is crate-private in PR 1** (`mod header_filter;` / `rookie-rs/src/header_filter.rs`). Exists **only** to implement `header(url)` later. Must not change what `ReadResult` contains. Do **not** name the module `get` (rejected product verb). | Matcher independently testable; no public `get`. |
| KD-P6 | **Docs / ADR 0004 / README / CHANGELOG only in PR 3.** | One doc pass. |
| KD-P7 | **Unknown browser converts only in `resolve_registered_browser` / `_for`.** Leave `browser_definition`’s `anyhow!` alone. | Keeps `chromium_based_with_browser_id` as Engine. |
| KD-P8 | **Absent profile means different things on the two store verbs.** `extract` → `LegacyFirstProfile`; `extract_report` → `AllProfiles`. | ADR 0001 vs today’s `browser_report(id, None)`. |
| KD-P9 | **`browser_report` widens in place.** Opaque-id successes unchanged; name/dir/non-lossy-path/cookie-DB may flip `Err` → `Ok`. | ADR 0003. |
| KD-P10 | **Documented job names:** `read` / `jar` (Python) / `profiles` / `report` (bindings/CLI) / `from_path` / `header` (**CLI subcommand + `ReadResult.header` method only** — see KD-P20). Rust: `read` / `profiles` / `extract_report` / `from_path`. **No** crate-root `report` or `get`. **No** Rust `CookieJar` type. Docs lead with `profiles`; `browser_profiles` stays supported and is **not** deprecated in this series. | `pub mod report` owns `report` at crate root. |
| KD-P11 | **One snapshot, one matcher.** Every `read`/`from_path` returns the same kind of `ReadResult`. Jar owns send-match. `header(url)` is a view over the already-built snapshot. | Fixes double send-match and NotebookLM Domain loss. |
| KD-P12 | **No-profile `read` = `LegacyFirstProfile` + compatibility flatten** (same set as `chrome()` / `extract` when `include_expired=true`). With-profile = resolve → `ProfileId` + report flatten (session included). | Do not reinvent ranking via listing-first. |
| KD-P13 | **`read` does not take URL / hosts / domains / family / names.** Caller filters `as_list()`. | World-2 policy stays with the caller. |
| KD-P14 | **Cookie-DB path is a resolver key in PR 1; `from_path` is a different universe.** | ADR 0004 records the key; do not rewrite 0003. |
| KD-P15 | **Node `index.d.ts` is generated.** Update `scripts/patch-loader.js` **and** `EXPECTED_EXPORTS` in `bindings/node/__test__/index.spec.mjs` in the same commit. | Existing loader pipeline; the export list lives in the spec, not the loader. |
| KD-P16 | **`firefox_profile` deprecation retargets to `extract(Request::browser("firefox").profile(q))` + `browser_profiles` — not `browser("firefox", domains)`.** | Shape bug in today’s note; Rust `browser` stays two-arg. |
| KD-P17 | **Thin `ReadResult`, language-split.** **Rust:** `cookies` / `into_cookies` / `warnings` / `browser_id` / `profile_id` / `header(&str) -> Result<String>` only — no `as_list`, no `as_jar`, no `CookieJar` type, no netscape. **Python bindings:** `as_list` / `as_jar` / `header(url)` / `__iter__` / `__len__` / `__bool__`. **Both:** no `for_url`, no remembered url, no `.jar` alias. | Avoid false Rust/Python parity; keep Rust surface thin. |
| KD-P18 | **Rust `ReadResult::into_cookies(self) -> Vec<Cookie>` (consuming).** `Cookie` has no `Clone` and `ReadResult` fields are private, so without a consuming accessor no external Rust caller can ever obtain owned records (e.g. for by-value `format::netscape`). CLI `read --format netscape` uses this public path — no crate-private formatter. | Preserves the no-`Clone` freeze; unblocks owned-cookie use. |
| KD-P19 | **Structured warnings: `ReadWarning { code, count }`.** `code` (stable snake_case, e.g. `decrypt_failed`, `invalid_octets`) + `count` are the machine contract; `Display` / `str()` / `message` text stays diagnostic-only (ADR 0001). Never a bare `Vec<String>` — the old “strings you must not parse” shape gave callers no actionable channel. | Codes were already the intended branch point; give them a type. |
| KD-P20 | **`header` is `ReadResult.header(url)` + the CLI `header` subcommand only.** No top-level `header()` function in Python or Node bindings — a one-liner that hides a full profile decrypt, and a second spelling of the same job. | One path per job; the method makes the snapshot cost visible. |
| KD-P21 | **`as_list()` / `__iter__` element schema is pinned** to the frozen eight-field cookie dict `chrome()` / `load()` emit today (`domain`, `path`, `secure`, `http_only`, `same_site`, `expires`, `name`, `value`; see normative schema in PR 3). `__iter__` yields exactly those dicts. `same_site` stays the raw stored integer; label mapping is caller policy. | This dict is the NotebookLM / `storage_state` contract; it must not float. |
| KD-P22 | **Source-policy asymmetry on `read` is deliberate and recorded.** No-profile `read` = compatibility flatten (set-equals `chrome()` / `extract`, persistent/legacy-eligible only); with-profile `read` = report flatten **including session cookies** — so naming the legacy-first profile can return *more* cookies than omitting it. ADR 0004 and user docs must carry the “why did the count change?” explanation. Session-import guidance (incl. NotebookLM): pass `profile=` when you want session cookies. | Reuses proven `LegacyFirstProfile` drafts and keeps the anti-divergence set-equality test; the wart is documented, not accidental. |

---

## Proposed Design

### Architecture

```mermaid
flowchart TB
  subgraph pr1 [PR 1 — private + RequestError]
    RE[RequestError]
    RP["resolve_profile_query<br/>id · name · dir · path · cookie DB"]
    GF["GetFilter crate-private<br/>for header later"]
  end

  subgraph pr2 [PR 2 — store API]
    Req["Request::profile"]
    Ex["extract + ProfileId flatten"]
    ER[extract_report]
    BR["browser_report wrapper"]
    CLI2["CLI --profile requires --browser"]
  end

  subgraph pr3 [PR 3 — job API]
    Read[read / ReadResult]
    Jar["jar Python = read.as_jar"]
    Hdr["header url view"]
    Prof[profiles alias]
    Rep["bindings/CLI report"]
    FP[from_path]
    Docs[ADR 0004 + README]
  end

  subgraph engine [Existing engine — unchanged ranking]
    PS[ProfileSelection]
    Legacy[LegacyFirstProfile paths]
    Report[collect_report / assemble]
  end

  RE --> RP
  RP --> Req
  Req --> Ex
  Req --> ER
  ER --> BR
  ER --> CLI2
  GF --> Hdr
  RP --> Read
  Ex --> Legacy
  ER --> Report
  Read --> PS
  Read --> Jar
  Read --> Hdr
  FP --> Read
  Prof --> BR
  Rep --> ER
  Docs --> Read
```

### One snapshot, one matcher

```mermaid
sequenceDiagram
  participant C as Caller
  participant R as read / from_path
  participant Res as resolve_profile_query
  participant E as engine
  participant RR as ReadResult
  participant J as CookieJar / client
  participant H as header(url)
  participant F as GetFilter

  C->>R: browser required; optional profile
  alt missing browser
    R-->>C: MissingBrowser
  end
  opt profile set
    R->>Res: query
    Res-->>R: ProfileId or RequestError
  end
  R->>E: LegacyFirst+compat OR ProfileId+report flatten
  E-->>R: acquired cookies + row issues
  Note over R: drop expired unless include_expired<br/>omit CTL/empty name/bad octets + warning
  R-->>RR: ReadResult snapshot NEVER URL-sliced
  alt session import
    C->>RR: as_jar / as_list
    RR-->>J: ALL acquired records
    Note over J: stdlib / Playwright send-match
  else Cookie header view
    C->>H: url
    H->>F: send-match on snapshot
    F-->>C: "; " joined header
  end
```

### Documented verbs

```text
profiles(browser)              → [ProfileDescriptor]     # no decrypt
read(browser, profile?)        → ReadResult              # decrypt once
jar(browser, profile?)         → CookieJar               # Python only = read(...).as_jar()
from_path(path)                → ReadResult              # file universe
report(browser, profile?)      → ExtractionReport        # bindings/CLI; Rust: extract_report
ReadResult.header(url)         → str                     # view over the snapshot (KD-P20)
```

`header` exists as a **method on `ReadResult`** and as a **CLI subcommand** (which runs `read` then the method). There is **no** top-level `header()` function in Python or Node bindings (KD-P20).

Rust crate-root surface for the job layer: `read` / `profiles` / `extract_report` / `from_path`. **No** `pub fn report`. **No** `pub fn get`. **No** `CookieJar` type in Rust.

---

## API / Interface Changes

### `RequestError` (PR 1 public; `mod request_error` private)

```rust
// rookie-rs/src/request_error.rs — re-exported from lib.rs
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
  UnknownBrowser { browser_id: String },
  EmptyProfileSelector,
  UnknownProfile { browser_id: String, query: String },
  AmbiguousProfile {
    browser_id: String,
    query: String,
    /// Opaque ids only, in generic `browser_profiles` order. Never paths.
    profile_ids: Vec<String>,
  },
  LossyProfilePath { browser_id: String, query: String },
  MissingBrowser,                 // read / jar / header without browser (PR 3)
  InvalidUrl { display: String }, // redacted only; never raw URL (header PR 3)
  // Do NOT add EmptyNameSelector — names= is not on read.
}

impl RequestError {
  pub fn code(&self) -> &'static str;
  pub fn kind(&self) -> &'static str; // always "request"
  pub fn browser_id(&self) -> Option<&str>;
  pub fn profile_query(&self) -> Option<&str>;
  pub fn profile_ids(&self) -> &[String];
}

/// Human text is diagnostic only and **not** a stable contract (ADR 0001).
impl std::fmt::Display for RequestError { /* diagnostic, not stable */ }
impl std::error::Error for RequestError {}
```

| Variant | `code()` |
| --- | --- |
| `UnknownBrowser` | `unknown_browser` |
| `EmptyProfileSelector` | `empty_profile_selector` |
| `UnknownProfile` | `unknown_profile` |
| `AmbiguousProfile` | `ambiguous_profile` |
| `LossyProfilePath` | `lossy_profile_path` |
| `MissingBrowser` | `missing_browser` |
| `InvalidUrl` | `invalid_url` |

`fault_kind` (after `stop_reason`, beside `DirectPathError`):

```rust
if error.downcast_ref::<RequestError>().is_some() {
  return FaultKind::Request;
}
```

### Resolver (PR 1; crate-private)

```text
resolve_profile_query(browser_id, query, runtime) -> Result<profile_id>
  empty query (no trim) → EmptyProfileSelector
  unique profile_id == query → that id
  any path_lossy && to_string_lossy(path) == query → LossyProfilePath
      # also if lossy persistent source path display equals query
  else unique among:
      display_name
      directory_name (UTF-8)
      path == Path::new(query)                    # std Path eq
      persistent Cookie source path == Path::new(query)   # not session files
  0 → UnknownProfile; n>1 → AmbiguousProfile
```

Normative rules:

- Case-sensitive. No trim. `""` → `EmptyProfileSelector`; `"  "` → `UnknownProfile`.
- No last-used / `is_default` / channel tie-break.
- Session-only Gecko rows from `browser_profiles` **are** name/dir/path candidates.
- Listing uses extract=false seams only (assert zero `SystemKeyProvider` / Keychain / DPAPI hits).
- Failed listing = existing `browser_profiles` error, not `UnknownProfile`.
- Persistent sources only for DB-path key: Chromium `Cookies` / `Network/Cookies`, Mozilla `cookies.sqlite`, Safari `Cookies.binarycookies`, IE `WebCacheV01.dat`. Session files (`recovery.jsonlz4`, sessionstore) are **not** keys.
- Lives in `registry.rs`, not `report_build`. Reads listing drafts, not public `ProfileIdentity` (no `directory_name` on DTO).

### Store verb table (PR 2) — UNCHANGED from previous plan

| Call | Profile policy | Projection |
| --- | --- | --- |
| `extract(Request::browser(id))` | `LegacyFirstProfile` via existing `browser_cookies_with_runtime` | compatibility flatten |
| `extract(Request::browser(id).profile(q))` | resolve → `ProfileId` | flatten selected sources (persistent **and** session) |
| `extract_report(Request::browser(id))` | `AllProfiles` | **exactly** today’s `browser_report(id, None)` |
| `extract_report(Request::browser(id).profile(q))` | resolve → `ProfileId` | one-profile report |
| `browser_report(id, Some(q), domains)` | same resolver | same as `extract_report` |
| `browser(id, domains)` | n/a (2-arg sugar) | `extract(Request::browser(id).domains(domains))` |

Widen honesty: opaque-id successes unchanged. Name / directory / non-lossy path / cookie-DB path that used to `Err` may now `Ok` (or `AmbiguousProfile` / `LossyProfilePath`). Changelog: *if you treated a non-id `profile_id` as a guaranteed error, stop.*

Bindings in PR 2: widen existing `browser_report` only. **No** Python/Node `browser()`. **No** `read`/`jar` in PR 2.

### `GetFilter` (crate-private PR 1; used **only** by `header(url)` in PR 3)

Post-filter for the Cookie **request header** view. **Must not** run inside `as_jar()` or change `ReadResult.cookies`.

**Do not** pass `Request.domains` (would drop stored `.com` via host-list / eTLD+1 reducer).

**URL parse:**

1. Parse with `url::Url` (already in `rookie-rs` deps).
2. Accept only `http` and `https`. Everything else — relative refs, `file:`, `about:`, `ftp:` — is `RequestError::InvalidUrl`.
3. Canonical host: WHATWG host; strip **one** trailing dot; IPv6 without brackets for compare. Userinfo and port ignored.
4. Default path: empty or missing path → `/`.

**Keep a cookie iff all of:**

- **Domain-match (RFC 6265 §5.1.3 / §5.4), using `DomainScope::from_stored`:**
  - Host-only-flag = stored `Cookie.domain` has **no** leading `.` ([`cookie_record.rs`](../../rookie-rs/src/browser/cookie_record.rs) `DomainScope::from_stored` ~L143–151).
  - Compare-host = stored domain with **at most one leading `.` stripped**, plus the request-host trailing-dot strip above. ASCII case-fold.
  - Host-only → request-host equals compare-host.
  - Domain cookie → request-host equals compare-host **or** request-host is a subdomain of compare-host (suffix + dot boundary). Stored `.example.com` **is** sent to apex `https://example.com/` **and** `https://www.example.com/`.
  - IPs match exact only (no suffix).
- **Path-match (RFC 6265 §5.1.4):** cookie-path (empty → `/`) is a prefix of request-path, **and** either they are equal, **or** cookie-path ends in `/`, **or** the next request-path character is `/`.
- **Secure:** if `cookie.secure`, origin must be potentially trustworthy: `https`, **or** `http` to `localhost` / `*.localhost` / `127.0.0.1` / `::1`. `http://example.com` does **not** receive `Secure` cookies.

**Also:**

5. No public-suffix check on **read/header**. Stored `.com` + `https://www.example.com/` is **kept** (required test 16).
6. No SameSite / CHIPS / `__Host-` prefix re-validation.
7. Expiry and CTL/empty-name/forbidden-octet omission happen when **building `ReadResult`** (PR 3), not as a second policy inside `as_jar()`. PR 1 GetFilter unit tests still assert row-17 omit from the matcher keep-set (header must not reintroduce CTL into a header string if called on a hand-built test vector).
8. **No `names=`** on the product path. Do not add `EmptyNameSelector`.

`header(url)`: parse URL → GetFilter send-match on the **already built** snapshot → `"; "` join (not `CookieToString`). InvalidUrl redaction as specified below.

### `read` pipeline (PR 3)

```text
read(ReadRequest):
  no browser → MissingBrowser
  resolve_registered_browser
  if profile set:
      resolve_profile_query → ProfileId
      run ProfileId report draft (collect_report(..., Some(id), extract=true, ...)
          / same path extract_report uses for one profile)
      flatten succeeded sources (persistent then session, report order)
      map that draft’s row issue codes/counts → warnings
      do NOT claim equality with no-profile extract
  else:
      # NORMATIVE seam — same LegacyFirstProfile drafts as extract/chrome():
      #   legacy::browser_cookies_with_runtime path, which today calls
      #   registry::legacy_chromium_outcome_with_runtime /
      #   registry::legacy_gecko_outcome_with_runtime (ProfileSelection::LegacyFirstProfile)
      #   then project_chromium_outcome* / project_engine_outcome* (compatibility flatten)
      run that LegacyFirstProfile engine draft ONCE
      project compatibility cookies from the draft (persistent / legacy-eligible)
      map the SAME draft’s row_issues / rows_skipped codes+counts → warnings
      (= chrome() / extract set when include_expired=true; NOT listing-first)
      # FORBIDDEN: collect_report(..., None, ...)  → that is AllProfiles
      # FORBIDDEN: extract_report(Request::browser(id)) without profile
      # FORBIDDEN: browser_profiles()[0] → ProfileId as a stand-in for LegacyFirst
  empty listing / not installed → same engine / BrowserNotInstalled as extract
      NOT UnknownProfile
  drop expired unless include_expired (session expires=None stays)
  omit CTL / empty name / bad octets + warning  (once, when building ReadResult)
  return ReadResult { cookies: acquired set, warnings, browser_id, profile_id }
```

**Warning harvest (normative):** no-profile `read` must not double-extract. Prefer a crate-private helper next to `legacy::browser_cookies_with_runtime` that returns `(Vec<Cookie>, warning codes/counts)` from one `LegacyFirstProfile` draft. With-profile `read` uses the `ProfileId` report draft + flatten. Do **not** call `collect_report(..., None, ...)` for no-profile `read`.

`as_jar()` puts **that whole set** into a `CookieJar`. Stdlib send-matches later. **Do not** run `GetFilter` in `as_jar()`.

`from_path`: sniff + existing path extract → same `ReadResult` shape. No issue harvest. Does **not** call `resolve_profile_query`. No URL argument.

### Exact public signatures

**PR 2 additive:**

```rust
impl Request {
  pub fn profile(self, query: impl Into<String>) -> Self;
}
pub fn extract_report(request: Request) -> Result<report::ExtractionReport>;
// extract / browser / browser_report arities UNCHANGED
```

**PR 3 additive** (prefer `rookie-rs/src/read.rs` re-exported from `lib.rs`; keep private `GetFilter` in `rookie-rs/src/header_filter.rs`):

```rust
/// Snapshot request. No URL. No names. No hosts/domains/family.
/// Fields private. Absence is “not called.”
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReadRequest { /* private */ }

impl ReadRequest {
  pub fn browser(id: impl Into<String>) -> Self;
  pub fn profile(self, query: impl Into<String>) -> Self;
  pub fn include_expired(self, yes: bool) -> Self; // default false
  pub fn timeout(self, timeout: std::time::Duration) -> Self;
  pub fn cancellation(self, handle: CancellationHandle) -> Self;
}

/// Structured snapshot warning (KD-P19). `code` + `count` are the stable
/// machine contract; `Display` text is diagnostic only (ADR 0001).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadWarning { /* private */ }

impl ReadWarning {
  /// Stable snake_case code, e.g. "decrypt_failed", "invalid_octets".
  /// Reuses the report row-issue vocabulary where harvested from a draft;
  /// snapshot-build omissions (CTL / empty name / forbidden octets) use
  /// "invalid_octets". The set may grow (treat like #[non_exhaustive]).
  pub fn code(&self) -> &str;
  pub fn count(&self) -> u64;
}
impl std::fmt::Display for ReadWarning { /* "skipped N rows (decrypt_failed)" — NOT stable */ }

/// Acquired cookies + warnings. **Not `Clone`.** Never URL-pre-sliced.
/// Rust surface is accessors + `into_cookies` + `header` only (KD-P17/P18).
/// Python adds `as_list` / `as_jar` / dunders in bindings — do **not** mirror
/// those on the Rust type.
pub struct ReadResult { /* private; not Clone */ }

impl ReadResult {
  pub fn cookies(&self) -> &[Cookie];
  /// Consuming accessor (KD-P18): the only way to get owned `Cookie`s
  /// (no `Clone` on `Cookie`), e.g. for by-value `format::netscape`.
  pub fn into_cookies(self) -> Vec<Cookie>;
  pub fn warnings(&self) -> &[ReadWarning]; // NOT Vec<String> (KD-P19)
  pub fn browser_id(&self) -> &str;
  pub fn profile_id(&self) -> Option<&str>;
  /// View: GetFilter send-match + "; " join. Does not mutate the snapshot.
  pub fn header(&self, url: &str) -> Result<String>;
  // No as_list / as_jar / netscape on the Rust type.
}

pub fn read(request: ReadRequest) -> Result<ReadResult>;

/// Alias of [`browser_profiles`]. No decrypt.
pub fn profiles(browser_id: &str) -> Result<Vec<report::ProfileDescriptor>> {
  browser_profiles(browser_id)
}

// NO crate-root `pub fn report`.
// NO crate-root `pub fn get`.
// Power verb remains `extract_report(Request)`.

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FromPathRequest { /* private */ }

impl FromPathRequest {
  pub fn new(path: impl Into<std::path::PathBuf>) -> Self;
  pub fn include_expired(self, yes: bool) -> Self;
  pub fn timeout(self, timeout: std::time::Duration) -> Self;
  pub fn cancellation(self, handle: CancellationHandle) -> Self;
  pub fn chromium_credentials(self, source: direct_path::ChromiumCredentialSource) -> Self;
}

pub fn from_path(request: FromPathRequest) -> Result<ReadResult>;
```

Rejected:

```rust
pub fn get(...);                                // rejected product verb
pub fn report(...);                             // collides with pub mod report
pub fn browser(id, domains, profile);           // arity break
impl Request { pub fn url(...); }               // kitchen sink
impl Clone for Cookie { ... }                   // frozen
impl Clone for ReadResult { ... }
impl ReadResult { pub fn for_url(...); }
impl ReadResult { pub fn warnings(&self) -> &[str]; }
impl ReadResult { pub fn warnings(&self) -> &[String]; } // superseded by ReadWarning (KD-P19)
pub fn header(url, browser, profile) in bindings; // method + CLI subcommand only (KD-P20)
```

**Python:**

```python
def read(*, browser: str, profile: str | None = None, include_expired: bool = False,
         timeout: float | None = None, cancellation: CancellationHandle | None = None) -> ReadResult: ...

def jar(*, browser: str, profile: str | None = None, include_expired: bool = False, ...) -> http.cookiejar.CookieJar:
    """Sugar: read(...).as_jar(). Warnings are discarded; use read() if you need them."""

# NO top-level header() (KD-P20) — use read(...).header(url).

def profiles(browser_id: str) -> ProfileDescriptorList: ...  # alias of browser_profiles

def report(browser: str, *, profile: str | None = None, domains: list[str] | None = None, ...) -> ExtractionReport: ...

def from_path(path: str, *, include_expired: bool = False, ...) -> ReadResult: ...

class ReadWarning:
    code: str    # stable machine contract (KD-P19): "decrypt_failed", "invalid_octets", ...
    count: int
    def __str__(self) -> str: ...  # diagnostic text; NOT stable (ADR 0001)

class ReadResult:
    warnings: list[ReadWarning]
    browser_id: str
    profile_id: str | None
    def as_list(self) -> list[dict]: ...                # schema pinned below (KD-P21)
    def as_jar(self) -> http.cookiejar.CookieJar: ...   # ALL acquired records
    def header(self, url: str) -> str: ...              # view; does not mutate
    def __iter__(self): ...                             # yields the SAME dicts as as_list()
    def __len__(self) -> int: ...
    def __bool__(self) -> bool: ...
    # NO for_url. NO remembered url. NO .jar alias.
```

**`as_list()` element schema (normative, KD-P21).** Each element is exactly the eight-key cookie dict today's `to_dict` (`bindings/python/src/lib.rs` ~L154) emits for `chrome()` / `load()` — same key names, same types:

```python
{
  "domain": str,          # stored Domain, leading "." preserved (host-only ⇔ no leading ".")
  "path": str,
  "secure": bool,
  "http_only": bool,
  "same_site": int,       # raw stored value; Lax/Strict/None label mapping is caller policy
  "expires": int | None,  # unix seconds; None = session cookie
  "name": str,
  "value": str,
}
```

No extra keys, no renames, no derived fields. Callers building Playwright `storage_state` map `same_site` themselves (a `same_site_label` helper stays a follow-on, not this series).

`browser` is required on `read` / `jar`. Missing `browser` is `TypeError` **before** any other work.

**Node:** no CookieJar. Export `read` → `{ cookies, warnings, browserId, profileId, header(url) }`. **No** top-level `header()` export (KD-P20) — the view lives on the result object. Update `scripts/patch-loader.js` and `EXPECTED_EXPORTS` in `__test__/index.spec.mjs`. Never hand-edit `index.d.ts`.

```ts
export interface ReadOptions {
  browser: string
  profile?: string | null
  includeExpired?: boolean | null
  timeoutMs?: number | null
  cancellation?: CancellationHandle | null
}

export interface ReportOptions {
  browser: string
  profile?: string | null
  domains?: string[] | null   // host-list dump on the power verb only
  timeoutMs?: number | null
  cancellation?: CancellationHandle | null
}

export interface FromPathOptions {
  path: string
  includeExpired?: boolean | null
  timeoutMs?: number | null
  cancellation?: CancellationHandle | null
  // Chromium credential options mirror the existing fromPath/direct-path flags:
  browserId?: string | null
  keyPath?: string | null
  plaintextOnly?: boolean | null
}

export interface ReadWarningObject {
  code: string      // stable (KD-P19)
  count: number
  message: string   // diagnostic; NOT stable
}

export interface ReadResultObject {
  cookies: CookieObject[]   // acquired snapshot; NOT URL-filtered
  warnings: ReadWarningObject[]
  browserId: string
  profileId: string | null
  header(url: string): string
}

export declare function read(options: ReadOptions): Promise<ReadResultObject>
export declare function profiles(browserId: string): Promise<ProfileDescriptorObject[]>
export declare function report(options: ReportOptions): Promise<ExtractionReportObject>
export declare function fromPath(options: FromPathOptions): Promise<ReadResultObject>
// NO top-level header() (KD-P20)
```

Missing `browser` on `read` → `InvalidArg` (`FaultKind::Request`).

**CLI:**

```text
rookie-cookies read -b chrome [-p Work]
rookie-cookies profiles chrome
rookie-cookies report chrome -p Work
rookie-cookies from-path FILE
rookie-cookies header https://github.com -b chrome
# compatibility (flat flags; no subcommand):
rookie-cookies --browser chrome
```

`read` without `-b` → clap exit 2. JSON stdout = cookie-object **array** (the snapshot, not a wrapper). Warnings on stderr.

#### PR 3 CLI coexistence (normative)

Today’s CLI is a single flat `Args` derive (`cli/src/args.rs`); `validate_modes` in `cli/src/main.rs` ~L182 widens `--browser` only when `is_generic_mode()` (list/report). PR 2 already changes `--profile` to `requires = "browser"` and splits structured-output vs registry-widening. PR 3 **adds** optional subcommands beside that flat surface.

| Mode | Argv shape | Selection / verb | Output | Notes |
| --- | --- | --- | --- | --- |
| **(a) Flat compatibility** | no subcommand; today’s flags (`--browser`, `--load`, `--path`, `--list-*`, `--report`, PR 2 `--profile`) | unchanged after PR 2 | unchanged | `validate_modes` / `widens_browser_to_registry` apply as in PR 2. Default no-arg `load()` path unchanged when `command` is `None`. |
| **(b) `read`** | `read -b ID [-p Q] [--include-expired] [--format json\|netscape] [--timeout-secs N]` | `read(ReadRequest)` | cookie-object **array** on stdout (or netscape); warnings stderr | `-b` required (clap exit 2). Registry-wide `-b` (any registered id/alias). Does **not** pass host-list `--domains`. |
| **(b) `profiles`** | `profiles <BROWSER>` | `browser_profiles` / `profiles` alias | JSON profile descriptor array | ≡ flat `--list-profiles --browser …`. Netscape rejected. |
| **(b) `report`** | `report <BROWSER> [-p Q] [-d D]…` | `extract_report` / `browser_report` | JSON `ExtractionReport` | ≡ flat `--report --browser …`. Netscape rejected. Top-level `--report` **retained**. |
| **(b) `from-path`** | `from-path <PATH> [--include-expired] [credential flags] [--format json\|netscape]` | job `from_path` | cookie-object array / netscape; warnings stderr | Path universe; no profile query. |
| **(b) `header`** | `header <URL> -b ID [-p Q]` | `read` then `ReadResult::header(url)` | Cookie request header string on stdout; warnings stderr | `-b` required. Format fixed to header body (no `--format`). |

**Conflict rule:** when `command: Some(…)`, treat top-level job/list/report flags as clap **conflicts** with the subcommand (do not silently prefer one). Concretely: `read`/`profiles`/`report`/`from-path`/`header` conflict with top-level `--browser` / `--load` / `--path` / `--list-browsers` / `--list-profiles` / `--report` / `--profile` / `--domains` (except where a flag is redefined **on the subcommand**). Mixing `rookie-cookies report chrome` with top-level `--report` is a usage error. Flat `--report --browser chrome` and subcommand `report chrome` both remain legal **separately**.

**Shared vs per-subcommand flags:**

- Top-level `--format` / legacy timeout behavior remain on the **flat** path only.
- Job subcommands that need format/timeout declare **their own** `--format` / `--timeout-secs` (do not read top-level `--format` when a subcommand is selected).
- `profiles` / `report`: JSON only (netscape → usage error, same class as today’s structured modes).
- `read` / `from-path`: `--format json|netscape` (default json).
- `header`: no `--format`; stdout is the `"; "`-joined Cookie header.

**Registry widening when a subcommand is selected:** `read` / `profiles` / `report` / `header` accept any registered browser id/alias on their browser argument (same as PR 2 `widens_browser_to_registry`). `from-path` has no browser selector (credential flags only). Flat `validate_modes` is skipped when `command` is `Some` — each subcommand validates its own browser arg.

**Clap skeleton (PR 3):**

```rust
// cli/src/args.rs — illustrative; keep flat fields for compatibility
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, disable_version_flag = true)]
pub struct Args {
  // --- retained flat compatibility fields (PR 2 rules for --profile) ---
  pub path: Option<String>,
  pub browser: Option<String>,
  pub load: bool,
  pub format: String, // PossibleValuesParser ["netscape","json"] — flat path only
  pub list_browsers: bool,
  pub list_profiles: bool,
  pub report: bool,
  #[arg(long, requires = "browser")]
  pub profile: Option<String>,
  pub domains: Option<Vec<String>>,
  // … key_path / browser_id / plaintext_only / version …

  /// Job API. When Some, flat dump / list / --report paths do not run.
  #[command(subcommand)]
  pub command: Option<JobCommand>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum JobCommand {
  /// Unfiltered snapshot (JSON cookie array). Requires -b.
  Read {
    #[arg(short = 'b', long)]
    browser: String,
    #[arg(short = 'p', long)]
    profile: Option<String>,
    #[arg(long)]
    include_expired: bool,
    #[arg(short, long, value_parser = PossibleValuesParser::new(["netscape", "json"]), default_value = "json")]
    format: String,
    #[arg(long)]
    timeout_secs: Option<u64>,
  },
  Profiles { browser: String },
  Report {
    browser: String,
    #[arg(short = 'p', long)]
    profile: Option<String>,
    #[arg(short = 'd', long)]
    domains: Option<Vec<String>>,
  },
  FromPath {
    path: String,
    #[arg(long)]
    include_expired: bool,
    #[arg(long)]
    browser_id: Option<String>,
    #[arg(long)]
    key_path: Option<String>,
    #[arg(long)]
    plaintext_only: bool,
    #[arg(short, long, value_parser = PossibleValuesParser::new(["netscape", "json"]), default_value = "json")]
    format: String,
  },
  Header {
    url: String,
    #[arg(short = 'b', long)]
    browser: String,
    #[arg(short = 'p', long)]
    profile: Option<String>,
  },
}
```

In `main`: if `args.command.is_some()`, dispatch the subcommand and **return** (do not fall through to flat `load()` / `--browser` dump). Flat-path `validate_modes` runs only when `command` is `None`.

Format parser reference: today’s top-level flag is `PossibleValuesParser::new(["netscape", "json"])` in [`cli/src/args.rs`](../../cli/src/args.rs) L88.

---

## Data Model Changes

**None** to persisted or wire types.

- `Cookie` unchanged (eight fields, raw `same_site: i64`, no `Clone`).
- `ExtractionReport` / `ProfileIdentity` / `schema_version: 1` unchanged — still no `directory_name` on the DTO.
- `browser_registry.json` unchanged.
- In-memory only: `Request.profile: Option<String>`; `RequestError`; `GetFilter`; `ReadRequest` / `FromPathRequest` / `ReadResult`.
- No migration. [`rookie-rs/public-api/temporary-exceptions.json`](../../rookie-rs/public-api/temporary-exceptions.json) stays `{ "schema_version": 1, "exceptions": [] }`.

---

## PR 1 — `RequestError` + resolver + header send-filter

**Title:** `feat: RequestError, profile resolver, and header send-filter`

**Theme:** Crate-private machinery plus the one small public type `RequestError`. No `Request::profile`, no public `read`, no CLI flag change.

**Depends on:** nothing.

### Files / components

| Path | Change |
| --- | --- |
| `rookie-rs/src/request_error.rs` | **New.** `#[non_exhaustive] pub enum RequestError` + helpers (**no** `EmptyNameSelector`) |
| `rookie-rs/src/lib.rs` | `mod request_error; pub use request_error::RequestError;`; map in `fault_kind`; rewrite Engine-fallback rustdoc; keep Engine pin on `chromium_based_with_browser_id` |
| `rookie-rs/src/browser/registry.rs` | `resolve_registered_browser` / `_for` map unknown id → `RequestError::UnknownBrowser`. **Do not** change `browser_definition`. Add `pub(crate) fn resolve_profile_query(...)` including cookie-DB path key |
| `rookie-rs/src/browser/registry/{chromium,gecko,safari,internet_explorer}.rs` | Listing-draft accessors only if the resolver cannot see candidates / persistent source paths today |
| `rookie-rs/src/header_filter.rs` | **New.** Crate-private `GetFilter` + URL/octet matcher + URL redaction helper. `mod header_filter;` is **private**. File banner: “not a public `get` API.” **No** `pub fn get` ever |
| `rookie-rs/public-api/*.txt` | Additive `RequestError` lines only (all six snapshots); [`temporary-exceptions.json`](../../rookie-rs/public-api/temporary-exceptions.json) untouched / empty |
| `rookie-rs/tests/public_contract.rs` | `RequestError` downcast; `chromium_based_with_browser_id` stays Engine |
| `tests/python/test_report_api.py` | unknown-browser: `RuntimeError` → `RookieRequestError` (still accept `ValueError`) |
| `bindings/python/rookie_cookies/rookie_cookies.pyi` | Update `:raises …` on `browser_profiles` / `browser_report` (and any resolve-path stubs) from `RuntimeError` → `RookieRequestError` for unknown browser |
| `bindings/node/__test__/*` (report / profiles child or `index.spec.mjs`) | Assert unknown browser → `InvalidArg` (`FaultKind::Request`), not a generic engine failure. Message-only assert is OK if status is already `InvalidArg` |

### Tests that must be green

**Resolver table (1–19 + 20–23):**

| # | Setup | Query | Result |
| --- | --- | --- | --- |
| 1 | Unique display name `"Personal"` | `"Personal"` | that `profile_id` |
| 2 | Unique directory `"Profile 1"` | `"Profile 1"` | that `profile_id` |
| 3 | Unique non-lossy full path | that path as stored (`Path ==`). On Windows only, the other separator also matches. On Unix, `\` vs `/` do **not** match | that `profile_id` |
| 4 | Two channels, both directory `Default`, distinct display names | `"Default"` | `AmbiguousProfile` (2 ids) |
| 5 | Same as 4 | unique display name of one | that one |
| 6 | Same as 4 | that profile’s opaque id | that one |
| 7 | Unix lossy path (`0xFF` byte), `to_string_lossy` queried | lossy display | `LossyProfilePath` |
| 8 | Same as 7 | opaque id | that one |
| 9 | Seeded profiles | `"nope"` | `UnknownProfile` |
| 10 | Any | `""` | `EmptyProfileSelector` |
| 11 | Any | `"  "` | `UnknownProfile` |
| 12 | Valid 64-hex that no profile has | `"0"*64` | `UnknownProfile` |
| 13 | Alias `"ie"` / `"360"` / `"opera-gx"` with one profile | unique name | that id under the **canonical** browser |
| 14 | `"not-a-browser"` | anything | `UnknownBrowser` (no listing) |
| 15 | One profile whose display_name equals its directory (`Default`/`Default`) | `"Default"` | unique (one candidate, not 2) |
| 16 | Profile A display `"Profile 1"`, profile B directory `"Profile 1"` | `"Profile 1"` | `AmbiguousProfile` |
| 17 | Gecko session-only profile with unique `Name=` | that name | that id (visible to `browser_profiles`) |
| 18 | Known browser, nothing installed | `"Default"` | `UnknownProfile` (not `no_sources`) |
| 19 | `browser_id = "firefox"` | a `browser_profiles` opaque id | that id |
| 20 | Unique Chrome profile, selected `Network/Cookies` | that absolute path | that `profile_id` |
| 21 | Same, lower-precedence `Cookies` candidate that exists | that path | that `profile_id` |
| 22 | Two channels, identical relative `Default/Cookies` (different absolute paths) | one absolute path | the one whose source path equals |
| 23 | Known browser, file is not a listed source | that path | `UnknownProfile` (caller wanted `from_path`) |

Also: zero `SystemKeyProvider` / Keychain / DPAPI on resolver tests.

**GetFilter URL table (1–17 with 1b/2b/16/17) — for `header()` later:**

| # | Cookie | URL | Keep? |
| --- | --- | --- | --- |
| 1 | `.example.com` `/` | `https://www.example.com/` | yes |
| 1b | `.example.com` `/` | `https://example.com/` | **yes** (apex) |
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
| 16 | `.com` `/` | `https://www.example.com/` | **yes** (no PSL on read) |
| 17 | name or value contains `\r` / `\n` | any | **PR 1:** omit from matcher keep-set. **PR 3:** omit + warning when building `ReadResult` |

Footnote: row 17’s warning is **PR 3-only**. PR 1 GetFilter unit tests assert omit only.

Additional matcher unit tests: redaction — `https://user:secret@example.com/` and unparseable `https://user:secret@%zz` absent from `InvalidUrl` Debug/Display and the redaction helper output. Expiry handling for ReadResult is PR 3 (not names / EmptyNameSelector).

**Fault classification:**

- `fault_kind(&unknown_browser)` is `Request` for `browser_profiles` / `browser_report` / `extract(Request::browser("nope"))`.
- `chromium_based(..., browser_id="nope")` remains `FaultKind::Engine` / Python `RuntimeError`.

### public-api snapshot expectations (PR 1)

Additive only — field-per-line like `DirectPathError` in `rookie-rs/public-api/linux-all-features.txt`. Include variants now (`MissingBrowser`, `InvalidUrl::display`). **No** `EmptyNameSelector`. `mod request_error` private; only `rookie_cookies::RequestError` is public. No `Request::profile`, no `extract_report`, no `read`, no `get`.

Expect trait impl lines mirroring `DirectPathError`: `impl Display`, `impl Error`, `impl Debug`, `Clone`, `Eq`/`PartialEq`, `Send`/`Sync`/`Unpin`, unwind-safe markers, plus the `code` / `kind` / `browser_id` / `profile_query` / `profile_ids` methods. Brace-syntax variant listings will fail `scripts/check-public-api.py` — use field-per-line.

### Acceptance commands

```bash
cargo test -p rookie-cookies --lib
scripts/check-public-api.py
python -m unittest tests.python.test_report_api
# Node: unknown-browser profiles/report assert InvalidArg (FaultKind::Request)
# e.g. bindings/node/__test__/report-child.mjs or index.spec.mjs coverage
```

### Do not (PR 1)

- Add `Request.profile` or change `extract` behavior.
- Touch CLI flags.
- Export `get` / `read` / make `mod header_filter` public.
- Add `EmptyNameSelector`.
- Name the private matcher module `get` / `get.rs` (use `header_filter`).
- Hand-edit Node `index.d.ts`.
- Change `browser_definition`’s `anyhow!`.
- Split modules (#260).
- Add Python/Node `browser()`.

### Implementation notes

- Generalize `select_chromium_profile` (`registry/chromium.rs` ~L1356); do not invent a second ranker.
- Listing: reuse `chromium_listing_with_runtime`, `gecko_profiles_with_runtime`, Safari/IE listing seams used by `browser_profile_descriptors` (`report_build.rs` ~L1909).
- **Binding exception-class change (this PR, not only PR 3 CHANGELOG):** unknown browser on `resolve_registered_browser` becomes `RequestError` → `FaultKind::Request`. Python `browser_profiles` / `browser_report` raise `RookieRequestError` (`ValueError` subclass) instead of `RookieEngineError`/`RuntimeError`. Node maps to `InvalidArg` (already the Request mapping in `bindings/node/src/lib.rs` ~L27–29; ensure tests assert that status). Leave a one-line **Changed** note in the PR 1 description / draft CHANGELOG fragment; PR 3’s published CHANGELOG still carries the user-facing bullet.
- **URL redaction (normative, one helper used by `InvalidUrl`, later header/`ReadResult::header` error paths, and tracing):**
  1. If `url::Url::parse` succeeds: store `scheme` + `://` + host (no userinfo) + path. Drop query, fragment, password, username.
  2. If parse fails: do **not** store the caller string. Apply a heuristic that deletes `user:pass@` (the last `@` before the first `/` after an optional scheme) and then store either `"<unparseable>"` or `scheme://<unparseable>` when a scheme is visible. Credentials must not survive either arm.
  3. Required tests: `https://user:secret@example.com/` and unparseable `https://user:secret@%zz` do not appear in `InvalidUrl` `Debug`/`Display`.
- Path display in other errors may still use `common::diagnostic::REDACTED_PATH` (`common/diagnostic.rs`).
- GetFilter unit tests live in `header_filter.rs`; they do not call extract. Octet/CTL cases assert **omit** only in PR 1.

---

## PR 2 — `Request::profile` + `extract_report` + CLI `--profile`

**Title:** `feat: Request::profile, extract_report, and query-aware browser_report`

**Theme:** One profile query on the store verbs. Still no `read` / `jar` / `get`.

**Depends on:** PR 1.

### Files / components

| Path | Change |
| --- | --- |
| `rookie-rs/src/lib.rs` | `Request.profile`; `Request::profile`; `extract` honors it; **new** `extract_report`; `browser_report` wraps `extract_report`; rustdoc; shim bodies + deprecations for `chrome_profile` / `firefox_profile` / `firefox_profiles` |
| `rookie-rs/src/browser/legacy.rs` | Flatten selected `ProfileId` report → `Vec<Cookie>` if not already a helper |
| `rookie-rs/src/browser/report_build.rs` | `extract_report` → existing `browser_extraction_report_with_runtime` / `collect_report` |
| `cli/src/args.rs`, `cli/src/main.rs` | `--profile` `requires = "browser"` only; split structured-output vs registry-widening predicates; wire flat + report paths |
| `cli/tests/generic_modes.rs` | Rewrite `profile_requires_both_report_and_browser`; add flat `--browser chrome --profile …` |
| `bindings/python/src/report.rs` | `browser_report` middle arg is a query (same string). **No** new `browser()` |
| `bindings/node/src/lib.rs` | Same for `browserReport`. **No** new `browser()` export |
| `rookie-rs/public-api/*.txt` | `Request::profile`, `extract_report` only |
| `rookie-rs/tests/public_report_api.rs` | Path **is** a key; `extract_report(Request::browser(id))` ≡ `browser_report(id, None)` |
| `rookie-rs/tests/public_contract.rs` | `BrowserReportFn` arity unchanged |

### Exact signatures

```rust
impl Request {
  /// Empty string stored; rejected at extract time as EmptyProfileSelector.
  pub fn profile(mut self, query: impl Into<String>) -> Self {
    self.profile = Some(query.into());
    self
  }
}

pub fn extract_report(request: Request) -> Result<report::ExtractionReport>;

pub fn browser_report(
  browser_id: &str,
  profile_id: Option<&str>, // now a query; name kept for rustdoc continuity
  domains: Option<Vec<String>>,
) -> Result<report::ExtractionReport> {
  let mut request = Request::browser(browser_id).domains(domains);
  if let Some(query) = profile_id {
    request = request.profile(query);
  }
  extract_report(request)
}
```

`extract` with profile:

1. Resolve (listing, no keys).
2. Generic `ProfileId` engine path (same `collect_report(..., Some(id), true, ...)` as report).
3. Flatten selected + succeeded sources (persistent then session, report order).
4. Zero selected sources succeeded → `Err` (not `Ok([])`). Domain filter miss on a successful source → `Ok([])`.
5. Honor timeout/cancellation via `boundary_runtime` as today.

`extract` without profile: **unchanged** path through `legacy::browser_cookies_with_runtime`. Do **not** reroute through `extract_report`.

### Deprecations

- `chrome_profile` → `#[deprecated]` toward `extract_report(Request::browser("chrome").profile(q))` / `browser_report("chrome", Some(q), domains)`.
- `firefox_profile` — **replace** note: use `extract(Request::browser("firefox").profile(q))`; list with `browser_profiles("firefox")`. **Not** `browser("firefox", domains)` and **not** `browser_report`.
- `firefox_profiles` newly deprecated toward `browser_profiles("firefox")` (signature + persistent-only filter unchanged).
- `chrome_profiles` stays (last-used sugar).

`firefox_profile` body becomes the generic profile extract (opaque id accepted; persistent + selected session). Intentional source-set widening — changelog it.

### CLI matrix (normative)

```rust
#[arg(long, requires = "browser")]
pub profile: Option<String>,
```

| Predicate | Flags | Effect |
| --- | --- | --- |
| `is_structured_output_mode` | `--list-browsers` \| `--list-profiles` \| `--report` | reject Netscape; JSON DTO |
| `widens_browser_to_registry` | structured **or** `--profile` is `Some` | `--browser` accepts any registered id/alias |

| Invocation | Legal? | Selection | Output |
| --- | --- | --- | --- |
| `--browser chrome --profile Default` | **yes (new)** | resolver | cookies |
| `--browser yandex --profile Default` | **yes (new)** | resolver | cookies |
| `--report --browser ID --profile Q` | yes | resolver | JSON report |
| `--report --profile Q` | **no** | — | usage error |
| `--browser chrome --profile Q --format netscape` | **yes** | resolver | netscape |
| `--report --browser chrome --format netscape` | no | — | usage error |

`--browser ID --profile Q` → `extract(Request::browser(&id).profile(q)…)`. Do **not** force `BROWSERS_MAP` once `--profile` is present. `--browser yandex` without `--profile` stays the existing usage error.

### Bindings in this PR

Only widen existing `browser_report` / `browserReport` query semantics. **Do not** add Python/Node `browser()`. Optional docstring pointers toward upcoming `read(..., profile=)`.

### Tests that must be green

- Two-profile Chrome fixture: `extract(Request::browser("chrome"))` **set-equals** `chrome()`; **not** `browser_profiles()[0]`; **not** the union.
- `extract_report` no profile ≡ `browser_report(id, None)` (status, profile count, issue codes).
- Unique `"Work"` / `"Profile 1"` / profile dir / `…/Network/Cookies` selects that profile.
- Two `Default`s → `RequestError::AmbiguousProfile`.
- `public_report_api.rs`: real display path **is** a key (stop asserting it is not).
- CLI: `rookie-cookies --browser chrome --profile Work` exits 0 (json cookies); `--profile` without `--browser` usage error; `--report --browser chrome --profile Work` report JSON; Netscape rejected on `--report`, allowed on flat `--profile`.
- `public-api`: no arity change on `browser` or `browser_report`.
- `BrowserReportFn` in `public_contract.rs` still type-checks.

### Acceptance commands

```bash
cargo test -p rookie-cookies
cargo test -p rookie-cookies-cli
# binary package name is rookie-cookies-cli; bin target is --bin rookie-cookies
scripts/check-public-api.py
```

### Do not (PR 2)

- Implement `read` / `ReadResult` / `jar` / `get` / `CookieResult`.
- Split modules.
- Add crate-root `fn report` / `fn get`.
- Add Python/Node `browser()`.
- Change `load()` browser set.
- Claim “existing callers keep working” for non-id `browser_report` queries — only opaque-id callers do.

### Implementation notes

- Prefer existing `collect_report` / `browser_extraction_report_with_runtime` for `extract_report`.
- Flatten helper may live next to `legacy::project_canonical_outcome` rather than inventing a second path.
- `browser_report` convenience keeps today’s implicit 30s `BoundaryRuntime::standard` (no new timeout params on the convenience).

---

## PR 3 — Job API (`read` / `jar` / `header` / `from_path`) + docs

**Title:** `feat: read/jar/profiles/report/from_path job API`

**Theme:** The names a new user learns. Product PR + ADR 0004 + docs.

**Depends on:** PR 2.

### Files / components

| Path | Change |
| --- | --- |
| `rookie-rs/src/read.rs` | `ReadRequest` / `ReadResult` / `read` / `FromPathRequest` / `from_path`; no-profile warning harvest from LegacyFirst draft |
| `rookie-rs/src/header_filter.rs` | Wire `ReadResult::header` / convenience header to private `GetFilter` |
| `rookie-rs/src/lib.rs` | Re-export public job symbols; `pub fn profiles` alias; **no** `pub fn report`; **no** `pub fn get` |
| `rookie-rs/src/direct_path/` | Job `from_path` wraps existing path extract only (no issue harvest; no URL filter) |
| `rookie-rs/public-api/*.txt` | Additive `read`, `ReadRequest`, `ReadResult`, `ReadWarning`, `from_path`, `FromPathRequest`, `profiles` |
| `bindings/python/src/*.rs`, `rookie_cookies.pyi`, `__init__.py` | `read`, `jar`, `profiles`, `report`, `from_path`, `ReadResult`, `ReadWarning` (**no** top-level `header` — KD-P20) |
| `bindings/node/src/lib.rs`, **`scripts/patch-loader.js`**, `EXPECTED_EXPORTS` in `__test__/index.spec.mjs`, regenerated `index.d.ts` | `read`, `profiles`, `report`, `fromPath` (**no** top-level `header` — KD-P20) |
| `cli/src/args.rs`, `main.rs` | Subcommands `read` / `profiles` / `report` / `from-path` / `header`; keep `--browser chrome` dump |
| `cli/tests/*` | Subcommand snapshots |
| `tests/python/test_*.py`, `bindings/node/__test__/*` | Job API tests |
| `docs/adr/0004-read-is-the-recommended-entry.md` | **New** |
| `README.md`, `docs/{Python,Rust,JavaScript}.md`, `CHANGELOG.md` | From-scratch = `jar(browser=…)` / NotebookLM `read().as_list()`; **do not** document `get(url).as_jar()` |

### Behavior contract for `read`

| Input | Store selection | Then |
| --- | --- | --- |
| `browser`, no `profile` | `LegacyFirstProfile` + compatibility flatten | build `ReadResult` (expiry / octet omit) |
| `browser` + `profile` | resolve → `ProfileId` + report flatten | build `ReadResult` |
| no `browser` | `MissingBrowser` | — |

### Warnings vs throw (normative)

| Situation | `read` | job `from_path` | `header(url)` view | `extract` / `chrome()` (frozen) |
| --- | --- | --- | --- | --- |
| Missing `browser` | `RequestError::MissingBrowser` | n/a | clap exit 2 (CLI subcommand); bindings method needs a `ReadResult` already (KD-P20) | n/a |
| Unknown / empty / ambiguous / lossy profile | `RequestError` | n/a | same if it decrypts via read | n/a / shim |
| Invalid URL | n/a | n/a | `RequestError::InvalidUrl` | n/a |
| Browser not installed / no selected source succeeded | **Engine error** (same as `extract`) | n/a | engine via read | already error / not-installed |
| Classify / total decrypt fail | **Engine error** | existing `DirectPathError` / engine | engine via read | error or empty depending on path |
| Some rows skipped (`decrypt_failed`, v20, decode) | **Ok** + `ReadWarning { code: "decrypt_failed", count: N }` | **no warning** — rows already dropped by `cookies_from_path` | n/a (uses snapshot) | cookies that were emitted; no warnings channel |
| Successful read, no expiry/octet survivors | **Ok** empty possible | **Ok** empty possible | empty string if filter miss | `Ok([])` for domain miss |
| CTL / empty name omitted | **Ok** + warning on `ReadResult` | **Ok** + warning on `ReadResult` | never reintroduces omitted rows | emitted (frozen) |
| Timeout / cancel | Engine + `stop_reason` | Engine + `stop_reason` | same | same |

Warnings are structured `ReadWarning { code, count }` (KD-P19): `code` + `count` are stable and are the branch point; `Display` / `str()` / `message` text is **not** a stable contract (ADR 0001). Never put a cookie value, key byte, unretracted home path, or raw URL in warning text. `REDACTED_PATH` if a path must appear.

“Never silent empty” means: a **failure** is not `Ok([])`. A **filter miss on `header`** is an empty string (view); the snapshot itself is unchanged.

`read` harvests row-level warnings from the **same** `ProfileSelection` draft it used:

- **No profile:** one pass through the `LegacyFirstProfile` engine drafts already used by `legacy::browser_cookies_with_runtime` — namely `registry::legacy_chromium_outcome_with_runtime` / `registry::legacy_gecko_outcome_with_runtime` (and the remaining-engine dispatch those helpers sit behind), then compatibility projection. Map that draft’s `row_issues` / `rows_skipped` codes and counts into `ReadResult.warnings` as `ReadWarning { code, count }` (Display example: `"skipped N rows (decrypt_failed)"`). **Do not** call `collect_report(..., None, …)` (that is `AllProfiles` via `ProfileSelection::from_profile_id`). **Do not** call `extract_report(Request::browser(id))` without a profile. **Do not** listing-first `browser_profiles()[0]` → `ProfileId`.
- **With profile:** resolve → `ProfileId` report draft (`collect_report(..., Some(id), true, …)` / same path as one-profile `extract_report`) + flatten; harvest from that draft.

`status == partial` is still `Ok`. `status == failed` or `no_sources` with zero selected successes is `Err`.

`from_path` does **not** grow a path-universe issue stream in this series.

`ReadResult.header(url)` does **not** mutate `warnings`.

### Tests that must be green

- Resolver 1–23 (already PR 1; remain green).
- URL table 1–17 for `header` / `GetFilter`.
- Two-profile fixture: `read(browser="chrome", include_expired=true)` set-equals `extract` / `chrome()` (not listing-first, not union).
- With-profile `read` may include session cookies `chrome()` lacks — do **not** assert equality with no-profile extract.
- Python `read()` without `browser=` → `TypeError`.
- `jar()` returns `http.cookiejar.CookieJar` and includes cookies for multiple hosts from the same profile (e.g. host-only `accounts.google.com` **and** `Domain=.google.com` if present in fixture).
- **Contrast test:** do **not** claim `header("https://notebooklm.google.com/")` contains `accounts.google.com` host-only cookies.
- `from_path` on an unregistered file works; `read(..., profile=that_path)` is `UnknownProfile` unless listed.
- `check-public-api.py`: no `pub fn get`; no `pub fn report`; no `Clone` on `Cookie` or `ReadResult` (`Clone` on `ReadWarning` is fine).
- Loader generates `index.d.ts`; `EXPECTED_EXPORTS` (in `__test__/index.spec.mjs`) includes `read`, `profiles`, `report`, `fromPath` — no `get`, **no top-level `header`** (KD-P20).
- **Schema pin (KD-P21):** `as_list()` elements have exactly the eight documented keys (`domain`, `path`, `secure`, `http_only`, `same_site`, `expires`, `name`, `value`); a session cookie has `expires is None`; `__iter__` yields the same dicts.
- **Warnings contract (KD-P19):** a fixture with undecryptable rows yields a `ReadWarning` with `code == "decrypt_failed"` and the row count; CTL/empty-name/forbidden-octet fixture yields `code == "invalid_octets"`. Tests branch on `code`, never on message text.
- **Owned cookies (KD-P18):** `read(...)?.into_cookies()` feeds `format::netscape(Vec<Cookie>)` (this is the CLI `read --format netscape` path).
- Python/Node: importing/accessing a top-level `header` fails (not exported).
- Redaction: `https://user:secret@example.com/` absent from `InvalidUrl` Debug/Display.
- Python `test_report_api` unknown-browser remains `RookieRequestError` (landed in PR 1).

### ADR 0004 (new file in PR 3)

**Path:** `docs/adr/0004-read-is-the-recommended-entry.md`

**Title:** `read` is the recommended entry (NOT `get`).

Decision points:

1. Recommended read is `read` (bindings also `jar` = `read().as_jar()`).
2. Snapshot is never URL-filtered.
3. Jar owns send-match; `header(url)` is a view (crate-private `GetFilter` implements only that view), exposed as `ReadResult.header` + CLI subcommand only — no top-level binding function (KD-P20).
4. Resolver cookie-DB path recorded here; do not rewrite ADR 0003.
5. Frozen `chrome()` / `load()` / `Cookie` / no all-profile flatten stay.
6. Do not add crate-root `fn report` or `fn get`.
7. **Source-policy asymmetry (KD-P22):** no-profile `read` is the compatibility flatten (set-equals `chrome()`); with-profile `read` includes session cookies — naming the legacy-first profile can return more cookies than omitting it. Record the why (reuse of proven `LegacyFirstProfile` drafts; anti-divergence guarantee) and the guidance (pass `profile=` for session import).
8. Warnings are structured `ReadWarning { code, count }`; codes stable, text diagnostic (KD-P19).
9. `as_list()` / `__iter__` element schema is the frozen eight-key cookie dict (KD-P21).

### First documented examples (README / Python.md)

```python
import rookie_cookies as cookies

# Happy path — session import
session.cookies = cookies.jar(browser="chrome")

# NotebookLM / storage_state — need Domain-intact records
rows = cookies.read(browser="chrome", profile="Work").as_list()
# then caller allowlist (_is_allowed_cookie_domain), storage_state, PSIDTS…
```

Explicitly **do not** document `get(url).as_jar()` as the happy path.

### Acceptance commands

```bash
cargo test -p rookie-cookies
cargo test -p rookie-cookies-cli
scripts/check-public-api.py
# Python job tests + Node index.spec.mjs (EXPECTED_EXPORTS)
# CLI subcommand tests (read / profiles / report / from-path / header)
```

Done when:

```python
import rookie_cookies as cookies
session.cookies = cookies.jar(browser="chrome")
rows = cookies.read(browser="chrome", profile="Work").as_list()
```

`chrome()` unchanged. `browser_report("chrome", "Work")` works. No #260 moves. No #261 `browser()` export. No public `get`.

### Do not (PR 3)

- Add Python/Node `browser()`.
- Split `registry.rs` / `report_build.rs`.
- Fold `url` onto `Request`.
- Make `read` return a `CookieJar`, raw list, or report dict.
- Add crate-root `fn report` / `fn get`.
- Ship `CookieResult` / `for_url` / remembered URL.
- Run `GetFilter` inside `as_jar()`.
- Put `hosts=` / `domains=` / `family=` / `names=` on `read`.
- Add a top-level `header()` function to Python or Node bindings (KD-P20).
- Return warnings as bare strings / `Vec<String>` (KD-P19).
- Add, rename, or derive keys on the `as_list()` dict (KD-P21).
- Add `Clone` to `Cookie` / `ReadResult` as a shortcut around `into_cookies` (KD-P18).
- Document `get(url).as_jar()` as the happy path.
- Claim `from_path` harvests decrypt-skip warnings.
- Rewrite ADR 0003.

### Implementation notes

- **No-profile warning harvest seam (required):** extend or wrap `legacy::browser_cookies_with_runtime` so one `LegacyFirstProfile` draft yields both compatibility cookies and row issue codes/counts. Named entry points today: `legacy_chromium_outcome_with_runtime` (`registry/chromium.rs` ~L1535), `legacy_gecko_outcome_with_runtime`, then `project_chromium_outcome*` / `project_engine_outcome*`. Do **not** invent a second ranker; do **not** route through `collect_report(..., None)`.
- With-profile: existing `collect_report(..., Some(id), true, …)` + flatten next to `legacy::project_canonical_outcome`.
- CLI: implement the coexistence matrix + skeleton under [PR 3 CLI coexistence](#pr-3-cli-coexistence-normative); tests for flat `--report` vs subcommand `report`, and for “subcommand + conflicting top-level flag → usage error.”
- Netscape from a snapshot = `into_cookies()` + existing `format::netscape(Vec<Cookie>)` (KD-P18) — no crate-private formatter, and do **not** change `format::netscape`'s by-value signature. Still no `netscape` method on `ReadResult`.
- Header order after send filter: longer path first, then name (RFC 6265 §5.4 approximation). We do not have creation time.
- URL redaction helper from PR 1 (`header_filter.rs`) is reused by `InvalidUrl` and header error paths.

---

## NotebookLM

Short, concrete migration:

1. Call `cookies.read(browser=…, profile=…).as_list()` (Domain-intact records). **Always pass `profile=`** — the with-profile path includes session cookies the no-profile compatibility flatten omits (KD-P22), and login import wants them.
2. Keep their `_is_allowed_cookie_domain` / `storage_state` / `PSIDTS` logic. `as_list()` keys are pinned (KD-P21); `same_site` stays the raw integer, so the Playwright `sameSite` label mapping stays on their side.
3. Stop passing `domains=` into the extractor for login import.
4. Replace `any_browser(Cookies)` with `profile=` (or `from_path` only when they truly have a file, not a profile identity).
5. Do **not** use `jar()` or `header()` for login / `storage_state` construction — those lose or hide host-only / multi-host records they need.
6. Firefox containers stay on their existing sqlite reader.

---

## Alternatives Considered (must reject)

| Alternative | Pros | Cons | Decision |
| --- | --- | --- | --- |
| Keep `get(url)` as recommended entry (old clean-get) | Familiar from rev 2 | Fake noun; double send-match; NotebookLM Domain loss; School-B/A mismatch | **Reject** |
| `CookieResult` as send-filtered set + `for_url` | One object for header+jar | Same type means two things; jar re-filters | **Reject** |
| `family="google"` / `hosts=` on `read` | Convenient for one app | World-2 policy in World-1 API; wrong default for everyone else | **Reject** — caller filters `as_list()` |
| `get` as alias that accepts url and filters the snapshot | Soft migration | Reintroduces the rejected product | **Reject** |
| Return `CookieJar` from `read` | Short Python line | NotebookLM needs records; warnings have nowhere honest to live | **Reject** |
| Object graph `browser("chrome").profile("Work").cookies()` | Fluent | #261-shaped; not the documented verbs | **Reject** |
| Crate-root `fn report` / `fn get` | Same identifiers everywhere | `report` does not compile next to `pub mod report`; `get` is rejected | **Reject** |
| #260 splits / #261 `browser()` | Structure / early store verb | Explicit ignore | **Reject** |
| Fold `url` onto `Request` | One builder | Trap for `extract`; kitchen sink with host-list `domains` | **Reject** |
| Making `CookieJar` the only return | Session-import one-liner | NotebookLM / storage_state need records | **Reject** |
| 7–14 small PRs / one mega-PR | — | Unreviewable or too many merges | **Reject** — three PRs |

---

## Security & Privacy Considerations

| Threat | Severity | Mitigation |
| --- | --- | --- |
| Ambiguous `Default` silently picks wrong account | **High** | `AmbiguousProfile`; no first-match / last-used tie-break |
| Omitting `browser` and scanning | **High** | `MissingBrowser`; TypeError / InvalidArg / clap exit 2; no scan |
| Resolver prompts Keychain/DPAPI just to list/match | **High** | extract=false seams; zero key-provider tests |
| URL credentials in `InvalidUrl` / header errors | **High** | Never persist raw caller string; `user:secret` test |
| CTL / CR-LF in `header()` (header injection) | **High** | Omit once when building `ReadResult`; header view cannot see omitted rows |
| Secure cookie on plain `http://example.com` | **High** | Secure rule + localhost exception; URL tests 8–10 |
| Lossy path round-trip wrong directory | **Medium** | `LossyProfilePath`; require opaque id |
| Warnings leak cookie values / key bytes | **Medium** | Codes + counts only; `REDACTED_PATH` |
| `profile=/…/Cookies` decrypts whole profile incl. session | **Medium** (intended) | Document vs `from_path` |
| Error messages leak home paths | **Medium** | `REDACTED_PATH`; ids allowed; no row samples |

Auth: none (local library). Header URL is not interpolated into SQL. Job verbs are read-only (no set/delete).

---

## Observability

Existing `tracing` targets plus:

| Event | Level | Fields (no secrets) |
| --- | --- | --- |
| `resolve_registered_browser` ok | debug | `input_id`, `canonical_id` |
| `resolve_profile_query` ok/fail | debug/info | `query_kind` (`profile_id`\|`display_name`\|`directory`\|`path`\|`cookie_db`), `code`, `match_count` |
| `extract` / `extract_report` | debug | `verb`, `selection` |
| `read` start / empty snapshot | debug/info | `has_profile`, `selection`, `include_expired` |
| `header` view | debug | `matched`, `snapshot_len` (no raw URL) |
| Key provider during resolve | — | must not fire |

Human `RequestError` / warning text is **not** stable (ADR 0001). Branch on `code()` / `fault_kind` / exception type. CLI: warnings on stderr; machine output on stdout.

Optional metrics (not required to land): `profile_resolve_total{code=…}`, `read_total{result=…}`, `header_filter_drop{reason=…}`.

---

## Rollout Plan

0.6.0-alpha. No feature flag. Additive API + classification change + CLI grammar widening + job API + ADR 0004.

1. Land PR 1 → PR 2 → PR 3 sequentially (shared `lib.rs`).
2. Update all six `rookie-rs/public-api/*.txt` snapshots in the PR that first exports each symbol. [`rookie-rs/public-api/temporary-exceptions.json`](../../rookie-rs/public-api/temporary-exceptions.json) stays empty.
3. CHANGELOG in PR 3: Added (`extract_report`, `Request::profile`, `read`, `ReadResult` (+`into_cookies`), `ReadWarning`, `jar`, `ReadResult.header`, `profiles`, `from_path`, CLI subcommands); Changed (`browser_report` query widening; `fault_kind` for unknown browser on resolve path only — also noted in PR 1; `firefox_profile` sources; recommended entry is `read`/`jar`); Deprecated (`chrome_profile`, `firefox_profiles`, retargeted `firefox_profile`).
4. Docs chain: keep [clean-get-api.md](clean-get-api.md) **Superseded** banner (already present). In PR 3 (docs pass), retarget [unified-extract-api.md](unified-extract-api.md) status so the **job-layer** pointer names this consolidated plan (`read` / `ReadResult` / `jar`), not `clean-get-api.md`’s `get`. Leave unified-extract **store-layer** decisions intact.
5. **Rollback:** revert the PR. No data migration. Callers that never called `read` / never passed non-id `browser_report` queries are unaffected.

---

## Mapping from older plans

| Old | Now |
| --- | --- |
| #260 M1–M11 | **Dropped** |
| #261 / U0 | **Dropped** (no binding `browser()`) |
| U1 + U2 + G0 + G1 (matcher) | **PR 1** (matcher retargeted to `header`, not `get`) |
| U3–U6 | **PR 2** (unchanged store layer) |
| G2–G7 `get` / `CookieResult` | **PR 3** rewritten as `read` / `ReadResult` / `jar` / `header` |
| U7 store docs | Folded into **PR 3** README / language docs / CHANGELOG |
| ADR 0004 “get is recommended” | **Rewritten** as “read is recommended” |

---

## Risks

| Risk | Severity | Mitigation |
| --- | --- | --- |
| PR 2 is large (profile on all store surfaces) | Medium | One theme; matcher/`read` stay in PR 1/3. If it balloons, cleave the CLI (`args.rs` / `main.rs` / `generic_modes.rs`) into its own commit-stack **inside** PR 2 — not a fourth PR. |
| Huge files without #260 splits | Medium | Reviewers use the tables in this plan; tests in-file |
| `extract` accidentally routed through `extract_report` | High | Two-profile fixture vs `chrome()` |
| Listing-first `read` diverges from `chrome()` | High | Crate-private `LegacyFirstProfile`; set-equality test |
| Someone reintroduces URL-on-read / `CookieResult` | High | This document’s reject list; PR 3 checklist; contrast test |
| `GetFilter` accidentally runs in `as_jar()` | High | Explicit test: multi-host cookies present in jar |
| Someone adds `pub fn report` / `pub fn get` | High | PR 3 checklist; snapshot must not grow them |
| Node d.ts drift | Medium | `patch-loader.js` + `EXPECTED_EXPORTS` same commit |
| Python `except RuntimeError` around unknown browser stops matching | Medium | PR 1 updates `test_report_api.py`; changelog |
| `browser_report(path)` starts succeeding | Medium | Update `public_report_api.rs`; widen honesty in CHANGELOG |
| CLI clap confusion (`report` vs `--report`; subcommand + flat flags) | Medium | Normative coexistence matrix + clap skeleton; conflict when both styles mixed; tests for both legal forms and illegal mixes |
| No-profile `read` routes through `collect_report(..., None)` / AllProfiles | High | Named LegacyFirst draft seam; forbid list in pipeline; set-equality vs `chrome()` |
| Callers branch on warning message text | Medium | `ReadWarning.code` + `count` are the contract (KD-P19); tests branch on `code`; text documented unstable |
| `profile=` returning more cookies than no-profile read confuses users | Medium | KD-P22 recorded in ADR 0004 + user docs; NotebookLM guidance: always pass `profile=` |
| `as_list()` dict shape drifts from `chrome()` / `load()` dicts | Medium | KD-P21 normative schema; key-set test in PR 3 |

---

## Open Questions

None that block implementation.

**Follow-ons (not this series):**

- #260 module splits later
- #261 thin binding `browser(id)` later (if still desired as a store alias)
- Typed `RequestError` fields on Python (`e.code`)
- `directory_name` on public DTO
- Path-universe issue stream for `from_path` row-level warnings
- Optional `same_site_label` helper (not required for thin `ReadResult`)
- Explicit `browser="auto"` opt-in scan (not implied by omitting `browser`)

---

## References

- [unified-extract-api.md](unified-extract-api.md) — store layer SoT; resolver 1–19; `RequestError` site; CLI matrix; shims. Job-layer pointer retargets to **this** plan in PR 3 (not `get` via clean-get).
- [clean-get-api.md](clean-get-api.md) — **superseded** as product; retained for URL-match table (still used by `header()`) and historical rationale
- [ADR 0001](../adr/0001-cookie-extraction-compatibility-and-report-contracts.md) — frozen `Cookie` / `chrome()` / `load()` / no all-profile flatten
- [ADR 0002](../adr/0002-authoritative-browser-registry.md) — registry; `ProfileSelection`; selection before keys
- [ADR 0003](../adr/0003-unified-profile-query.md) — one resolver; `browser_report` query; CLI `--profile` + `--browser`
- RFC 6265 §5.1.3 / §5.1.4 / §5.4 / §4.2.1; Playwright `storage_state` / `context.cookies`
- Verified tree paths listed in Background

---

## PR Plan

### PR 1 — `feat: RequestError, profile resolver, and header send-filter`

- **Files/components:** `rookie-rs/src/request_error.rs` (new); `rookie-rs/src/lib.rs` (`fault_kind`, re-export); `rookie-rs/src/browser/registry.rs` + optional listing hooks in `registry/{chromium,gecko,safari,internet_explorer}.rs`; `rookie-rs/src/header_filter.rs` (private `GetFilter` for header later); `rookie-rs/public-api/*.txt` + `temporary-exceptions.json` untouched; `rookie-rs/tests/public_contract.rs`; `tests/python/test_report_api.py`; `bindings/python/rookie_cookies/rookie_cookies.pyi` raises text; Node unknown-browser `InvalidArg` assert
- **Depends on:** none
- **Description:** Public `RequestError` (no `EmptyNameSelector`). Map unknown browser only in `resolve_registered_browser` / `_for` (Python → `RookieRequestError`; Node → `InvalidArg`). Crate-private `resolve_profile_query` with keys 1–23 (including cookie-DB path). Crate-private send-match/`GetFilter` in `header_filter.rs` + redaction helper with URL table tests aimed at `header()`. No `Request::profile`, no public `read`/`get`, no CLI change, no binding `browser()`.

### PR 2 — `feat: Request::profile, extract_report, and query-aware browser_report`

- **Files/components:** `rookie-rs/src/lib.rs`; `legacy.rs` / `report_build.rs` as needed for ProfileId flatten + `extract_report`; `cli/src/args.rs`, `cli/src/main.rs`, `cli/tests/generic_modes.rs`; Python/Node `browser_report` / `browserReport` query widening only; `public-api/*.txt`; `public_report_api.rs`, `public_contract.rs`
- **Depends on:** PR 1
- **Description:** Additive `Request::profile` and `extract_report`. Honor profile on `extract` via resolve → `ProfileId` flatten. No-profile paths unchanged (`LegacyFirstProfile` / `AllProfiles`). Widen `browser_report` middle arg. CLI `--profile` requires `--browser` only. Shim/deprecate `chrome_profile` / `firefox_profile` / `firefox_profiles` with retargeted notes. **No** `read`/`jar`/`get`. **No** Python/Node `browser()`.

### PR 3 — `feat: read/jar/profiles/report/from_path job API`

- **Files/components:** `rookie-rs/src/read.rs` + `header_filter.rs` header wiring + `lib.rs` re-exports; LegacyFirst draft harvest helper beside `browser_cookies_with_runtime`; `direct_path/` job wrapper; `public-api/*.txt`; Python (`pyi`, `__init__.py`, bindings — including `jar`); Node (`lib.rs`, **`patch-loader.js`**, `EXPECTED_EXPORTS` in `__test__/index.spec.mjs`, regenerated `index.d.ts`); CLI subcommands per coexistence matrix; tests; `docs/adr/0004-read-is-the-recommended-entry.md`; `README.md`; `docs/{Python,Rust,JavaScript}.md`; `CHANGELOG.md`; retarget job-layer pointer in `unified-extract-api.md`; keep banner on `clean-get-api.md`
- **Depends on:** PR 2
- **Description:** Public `read` / `ReadResult` (with `into_cookies`) / `ReadWarning` / `from_path` / `profiles`; Python `jar`; Node/CLI mirrors. Snapshot never URL-filtered; jar owns send-match; `header(url)` is a view exposed as `ReadResult.header` + CLI subcommand only (no top-level binding `header`). Warnings are structured `ReadWarning { code, count }`; `as_list()` schema pinned to the eight-key cookie dict. No-profile warnings from LegacyFirst drafts (not `collect_report(..., None)`); with-profile session-inclusion asymmetry recorded in ADR 0004. Docs lead with `jar(browser=…)` and NotebookLM `read(profile=…).as_list()`. No crate-root `fn report` / `fn get`. No #260/#261 leakage.

---

## Key Decisions

(See full [Key Decisions](#key-decisions) table above.) Hard pins for implementers:

1. **Product = session importer** (`read` / `ReadResult` / `jar`), not `get(url)` / `CookieResult`.
2. **One snapshot, one matcher** — jar owns send-match; `GetFilter` only for `header(url)` (`header_filter.rs`).
3. **Three PRs**; ignore #260 / #261; additive public-api; field-per-line snapshots; `rookie-rs/public-api/temporary-exceptions.json` empty.
4. **`RequestError` without `EmptyNameSelector`**; convert unknown browser only in `resolve_registered_browser` / `_for` (pyi + Node `InvalidArg` in PR 1).
5. **PR 2 store layer unchanged** from previous plan; no `read`/`jar` until PR 3.
6. **No** crate-root `pub fn report` / `pub fn get`; no `Clone` on `Cookie` / `ReadResult`; `warnings() -> &[ReadWarning]` (structured, KD-P19); `into_cookies(self) -> Vec<Cookie>` is the only owned-cookie path (KD-P18).
7. **Docs must not** teach `get(url).as_jar()`; first examples are `jar(browser=…)` and NotebookLM `read().as_list()`.
8. **No-profile `read`** uses `legacy_*_outcome_with_runtime` / `browser_cookies_with_runtime` drafts — never `collect_report(..., None)`. The with-profile session-inclusion asymmetry is deliberate and documented (KD-P22).
9. **CLI:** subcommand vs flat coexistence matrix is normative; mixed styles are clap conflicts.
10. **`header` is method + CLI only** (KD-P20); **`as_list()` schema is pinned** to the eight-key cookie dict (KD-P21).

---

*End of execution contract. Implementation starts at PR 1 when asked; this document is design-only.*
