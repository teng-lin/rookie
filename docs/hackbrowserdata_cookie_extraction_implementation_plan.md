# HackBrowserData-inspired cookie extraction implementation plan

This plan implements the findings in [Cookie extraction lessons from HackBrowserData](hackbrowserdata_cookie_extraction_lessons.md). Its fixed contracts are recorded in [ADR 0001](adr/0001-cookie-extraction-compatibility-and-report-contracts.md).

## 1. Objective

Broaden and harden cookie-only browser extraction using the reusable architecture demonstrated by HackBrowserData while preserving all existing Rust, Python, Node, and CLI contracts.

The target pipeline is:

```text
private ordered registry
  -> installations
       -> profiles and role-aware cookie sources
            -> request-scoped, installation-scoped key outcomes
                 -> acquired/readable source
                      -> engine extraction outcome
                           -> grouped report
                                -> additive bindings/CLI surface

legacy named selector
  -> same existing source
       -> shared row extraction core
            -> unchanged Vec<Cookie> projection
```

The second branch is deliberate: in the current release line, legacy named functions keep their existing path selectors. Corrected installation discovery belongs to new generic/report APIs so that adding profiles and roots does not silently change existing results.

## 2. Rebased baseline

The findings document predates recent work. The implementation must preserve, not redo, these merged changes:

- `d918a90`: WAL-aware `SqliteReader`, private RAII snapshots, DB+WAL copying, exact main-file verification across the copy window, bounded checkpoint-race retries, stale-WAL cleanup, and held-WAL/exclusive-lock tests.
- `SqliteReader` deliberately does not copy `-shm`; SQLite rebuilds this derived wal-index in the writable temporary directory. Copying SHM is explicitly rejected.
- `99ca297`: Firefox profile enumeration/selection in Rust through `firefox_profiles()` and `firefox_profile()`.
- `d0ea87a`: IE cookie security flags are read from the ESE flags column.
- Parameterized domain filtering, row-level malformed/decrypt failure isolation, aggregate total-failure reporting from `load()`, asynchronous Node browser tasks, Python GIL release, stderr-only CLI diagnostics, and explicit opt-in browser termination are already present.

Remaining gaps are Chromium multi-profile discovery, cross-binding Firefox profile parity, independent Chromium cipher tiers, verified host hashes, structured partial results, a canonical internal browser registry, additional browser definitions, Firefox session semantics, and Safari named profiles.

IE parsing is not being redesigned. It receives only a registry descriptor and a minimal `EngineExtractionOutcome` adapter when the generic report pipeline reaches it.

## 3. Scope

### Included

- Cookies only.
- Existing Chromium, Firefox-family, Safari, and IE extraction.
- Additive profile, registry, and grouped-report APIs.
- Standard Chromium-family browser definitions borrowed from HackBrowserData when their cookie path and claimed key tiers are verified.
- Correct source acquisition, version routing, domain-hash decoding, diagnostics, tests, bindings, CLI, packaging, and support documentation.

### Excluded or deferred

- Passwords, cards, history, downloads, bookmarks, extensions, and browser storage.
- Replacing the current Windows app-bound implementation with HackBrowserData's injection implementation.
- A broad security-hardening workstream. Keep short implementation notes for key lifetime, temporary files, permission failures, and explicit browser termination.
- Rich cookie metadata and CookieEditor output. These are follow-up roadmap items, not completion gates for this project.
- A new non-terminating Windows locked-handle provider. It is future work; registry/browser expansion does not depend on it.

## 4. Fixed compatibility contract

The following are release gates:

1. Existing Rust function signatures remain unchanged, including platform-specific `chromium_based` signatures.
2. Public `config::Browser`, `Config`, `CONFIG`, and `get_browser_config` remain source compatible. Downstream code can continue constructing `Browser` by struct literal.
3. Public `Cookie` remains the exact existing eight-field constructible type.
4. Existing Python cookie dictionaries, Node `CookieObject`, CLI JSON, Netscape output, and sync/async behavior remain unchanged.
5. Legacy `load()` retains the same browser set, concatenation order, and per-browser selectors.
6. Existing named browser functions retain their current source-selection priority and first/default-profile semantics.
7. Legacy named functions continue to use legacy `find_*_paths` selectors throughout this release line. They may share query/decryption internals, but do not switch to registry discovery.
8. Existing source-specific domain filtering and parameter binding remain unchanged. Persistent Chromium/Mozilla SQLite sources retain their parameterized `LIKE '%<requested-domain>%'` behavior; Safari and Firefox session sources retain their boundary-aware, case-insensitive host matcher. Initial generic/report adapters use the semantics of their source, not one silently unified matcher.
9. New browsers are not added to legacy `load()`.
10. New all-profile behavior is not placed behind existing functions.
11. Duplicate cookie keys from different profiles remain separated by profile group in new reports.
12. `same_site: i64` remains unchanged in `Cookie`.
13. Legacy cookie row order remains unspecified and unsorted. Compatibility tests compare normalized cookie rows while separately pinning source and browser concatenation order.
14. Human error strings may evolve, but failures must not collapse into successful empty output.

Required compatibility fixtures:

- External Rust compile fixture using `Cookie` and `config::Browser` struct literals.
- Exact Python dict, Node object, CLI JSON, and Netscape snapshots.
- Per-browser/channel legacy source-selection fixtures.
- Per-OS legacy `load()` browser-set and concatenation-order snapshots.
- Filtered and unfiltered wrapper parity cases, including separate SQLite-`LIKE` and Safari/session-boundary matrices.

## 5. Fixed design decisions

### 5.1 Registry source of truth

Create `rookie-rs/browser_registry.json` as the canonical source for the new generic pipeline. It is private implementation data with a schema version. Keep `rookie-rs/config.json` frozen as the compatibility artifact for public `CONFIG` and legacy selectors.

Registry data is compile-time embedded with `include_str!`, deserialized once through
`once_cell::Lazy`, and never opened from the consumer's runtime filesystem. Definitions are
grouped by target OS because discovery roots and usable cipher tiers are platform-specific:

```rust
struct Registry {
  schema_version: u32,
  platforms: BTreeMap<PlatformId, Vec<BrowserDefinition>>,
}

struct BrowserDefinition {
  canonical_id: String,
  aliases: Vec<String>,
  display_name: String,
  engine: BrowserEngine,
  roots: Vec<InstallationRoot>,
  capabilities: BrowserCapabilities,
}

struct BrowserCapabilities {
  declared_persistent_formats: Vec<CookieSourceFormatId>,
  declared_session_formats: Vec<CookieSourceFormatId>,
  declared_decryption_tiers: Vec<CipherTierId>,
}

struct InstallationRoot {
  root_id: String,
  template: String,
  channel: String,
  discovery: DiscoveryStrategy,
  priority: u16,
}
```

`BrowserEngine` and `DiscoveryStrategy` are separate. Safari and IE are engines, not Chromium profile layouts. Registry fields use `String`/`Vec`, not static references.

Only the current platform's ordered definitions are loaded. Platform IDs, format IDs, and
cipher-tier IDs are validated open string identifiers. A declared format/tier is a capability
claim, not evidence that a particular installation is accessible or decryptable.

Add `browser_registry.json` to the crate package `include`; CI verifies it appears in `cargo package -p rookie-cookies --list` and a packaged-crate smoke test verifies it loads.

Every legacy browser represented in both files has a parity invariant. New generic-only browsers are added only to the new registry unless a convenience legacy wrapper is intentionally added.

### 5.2 Canonical browser IDs and aliases

Freeze these existing canonical IDs:

```text
arc, brave, cachy, chrome, chromium, edge, firefox,
internet_explorer, librewolf, octo_browser, opera, opera_gx,
safari, vivaldi, zen
```

Preserve `ie`, `opera gx`, and `opera-gx` as aliases. New canonical IDs include:

```text
yandex, speed_360, speed_360x, qq_browser, dc_browser,
sogou, browser_from_vought, duckduckgo, coccoc
```

Preserve HackBrowserData-style short keys such as `360`, `360x`, `qq`, `dc`, and `vought` as aliases. “Browser from Vought” is the product label present in the reference registry; its canonical ID is `browser_from_vought`.

Do not expose a single ambiguous `supported` boolean. Capability vocabulary is:

- `registered`: definition exists for this target OS;
- `detected`: a matching installation/profile exists;
- `readable`: the declared cookie source can be parsed, including plaintext rows;
- `decryptable`: verified cipher-tier set such as `legacy_dpapi`, `v10`, `v11`, or `v20`.

`supported_browsers()` means registered on the running OS; it does not scan the filesystem.

### 5.3 Discovery context and test seams

Add a private injected context:

```rust
trait DiscoveryFs { /* stat/read_dir/glob/canonicalize */ }

struct DiscoveryContext<F> {
  platform: Platform,
  home: PathBuf,
  env: BTreeMap<OsString, OsString>,
  fs: F,
}

trait ChromiumKeyProvider {
  fn retrieve(&self, installation: &BrowserInstallation) -> ChromiumKeyOutcomes;
}
```

Production builds the context from the process environment. Tests use temporary roots without mutating global `HOME`, `APPDATA`, or `LOCALAPPDATA`. Key-provider injection enables exact tier-outcome fixtures and call-count assertions.

Sort glob results before canonicalization/deduplication. Expand only a leading `~`. Profile fallback order is fixed:

1. marked profile directories;
2. if none, a flat installation root containing a cookie source;
3. if neither, source-bearing markerless subdirectories for copied/restored trees.

Generic profile listing includes profiles with at least one cookie-bearing source: persistent or supported session state. Marker directories with no cookie-bearing source appear only as report discovery issues. Existing Firefox listing keeps its documented database-bearing behavior.

### 5.4 Role-aware sources

One optional `cookie_source` is insufficient. Use:

```rust
struct ProfileSources {
  persistent_candidates: Vec<CookieSourceCandidate>,
  session_candidates: Vec<CookieSourceCandidate>,
}

struct CookieSourceCandidate {
  role: CookieSourceRole,
  path: PathBuf,
  precedence: u16,
  format: CookieSourceFormat,
}
```

Candidate vectors are ordered. Chromium usually resolves `Network/Cookies`, then `Cookies`; Safari has modern and legacy persistent candidates; Firefox has one persisted database and ordered session candidates.

Selection semantics are fixed by role:

- persistent alternatives: the first existing candidate is authoritative; if it cannot be
  acquired, parsed, or queried, record a typed failure and do not silently fall through to a
  lower-priority, potentially stale copy;
- session alternatives: use Section 7's lifecycle-tier, first-valid fallback;
- a profile may combine the one authoritative persistent source with the one selected session
  source, but it never merges two persistent alternatives.

Pin fixtures with both `Network/Cookies` and `Cookies` present, with the preferred persistent
file unreadable/corrupt, and with invalid-then-valid Firefox session candidates. Safari's
`SafariTabs.db`-to-directory behavior chooses profile-discovery metadata; it is not a fallback
between two cookie stores.

### 5.5 Deterministic installation/profile IDs

Add unconditional `sha2 = "0.10"` to the core crate for IDs and verified host hashes.

Each registry root has a stable textual `root_id`. IDs use a versioned, length-prefixed SHA-256 encoding over OS-native normalized path bytes. A profile locator is tagged so Firefox `IsRelative=0` profiles outside a registered root remain representable:

```text
installation_id = sha256(
  "rookie-install-v1", canonical_browser_id, root_id, channel,
  normalized_canonical_installation_path
)

profile_id = sha256(
  "rookie-profile-v1", installation_id,
  ("relative", normalized_relative_path)
    or ("absolute", normalized_canonical_profile_path)
)
```

Expose lowercase 64-character hex strings. IDs are opaque and case-sensitive. They are deterministic while registry `root_id` and installed paths remain stable, but are not portable across machines. Selectors accept only IDs returned by discovery; legacy Firefox name/path matching remains on its legacy API.

Before assigning IDs, deduplicate browser-wide by normalized canonical profile directory, falling
back to the selected persistent-source path for a flat layout. The first installation in
deterministic registry order owns the profile; later references become bounded discovery notes
rather than duplicate extraction. This preserves multi-source/external Firefox profile handling
and prevents two installation roots from extracting the same physical profile.

Ordering is fixed:

1. installations by registry priority, then normalized resolved path;
2. profiles default-first, then locale-independent lowercase display name, raw display name, normalized path;
3. source outcomes by role and declared precedence;
4. cookies within each source outcome by `(domain, path, name, expires, secure, http_only, same_site, value)`; exact duplicates retain extraction order.

Legacy results are not sorted.

### 5.6 Versioned Chromium key/decryption model

```rust
struct ChromiumKeys {
  v10: Vec<KeyCandidate>,
  v11: Vec<KeyCandidate>,
  v20: Vec<KeyCandidate>,
}

enum ChromiumCipherVersion {
  V10,
  V11,
  V12SecretPortal,
  V20,
  LegacyDpapi,
  Unknown([u8; 3]),
}
```

Legacy raw DPAPI is row-scoped and uses the OS DPAPI operation directly; it does not require a stored key bucket. V12 is detection-only until a provider exists. Every configured key tier records success, not-applicable, or failure, and partial success is preserved.
Encrypted blobs shorter than three bytes are classified as malformed rows before version
detection; `Unknown([u8; 3])` never relies on unchecked slicing.

Windows retrieves the legacy v10 key even when APPB metadata exists. A v20 failure does not suppress v10 rows. Linux keeps v10 default candidates distinct from v11 keyring candidates. A row dispatches only to its matching tier.

Decryption returns bytes. Cookie decoding receives `host_key` and strips exactly 32 bytes only when the prefix equals `SHA256(host_key)`. Policy is fixed:

- exact match: strip;
- hash-only plaintext: emit an empty cookie value;
- UTF-8 mismatch: preserve bytes/value unstripped;
- non-UTF-8 mismatch: emit a typed decode issue and skip the row;
- short/unprefixed valid UTF-8: preserve unchanged.

Plaintext `value` fallback and row-level failure isolation remain intact.

### 5.7 Engine outcomes and report contract

Before publishing reports, each engine adapts each attempted source and its enclosing profile into:

```rust
struct SourceExtractionOutcome {
  source: CookieSourceIdentity,
  cookies: Vec<Cookie>,
  stats: ExtractionStats,
  issues: Vec<ExtractionIssue>,
}

struct EngineExtractionOutcome {
  profile: ProfileIdentity,
  sources: Vec<SourceExtractionOutcome>,
  issues: Vec<ExtractionIssue>,
}
```

The public wire model is additive. Public descriptors/reports are serde-serializable and
`#[non_exhaustive]`. Every extensible identifier/code field—including browser, installation,
profile, engine, source role/format/status, cipher tier, report status, acquisition strategy,
issue code/stage/severity—is a validated string newtype serialized as an open-ended snake_case
string, not a closed exhaustive enum. Initial severities are `info`, `warning`, and `error`;
status computation treats only `error` as a partial/failure signal.
Rust newtypes implement `Display`, `AsRef<str>`, and validated `FromStr` for ordinary downstream
ergonomics.

```rust
#[non_exhaustive]
struct BrowserCapabilitiesDescriptor {
  persistent_formats: Vec<CookieSourceFormatId>,
  session_formats: Vec<CookieSourceFormatId>,
  declared_decryption_tiers: Vec<CipherTierId>,
  available_decryption_tiers: Vec<CipherTierId>,
}

#[non_exhaustive]
struct BrowserDescriptor {
  id: BrowserId,
  aliases: Vec<String>,
  display_name: String,
  engine: EngineId,
  capabilities: BrowserCapabilitiesDescriptor,
}

#[non_exhaustive]
struct ProfileIdentity {
  browser_id: BrowserId,
  installation_id: InstallationId,
  profile_id: ProfileId,
  display_name: String,
  path: String,
  path_lossy: bool,
}

#[non_exhaustive]
struct CookieSourceDescriptor {
  role: CookieSourceRoleId,
  format: CookieSourceFormatId,
  path: String,
  path_lossy: bool,
  precedence: u16,
}

#[non_exhaustive]
struct ProfileDescriptor {
  profile: ProfileIdentity,
  is_default: bool,
  sources: Vec<CookieSourceDescriptor>,
}

#[non_exhaustive]
struct ExtractionReport {
  status: ReportStatusCode,
  summary: ReportStats,
  profiles: Vec<ProfileExtraction>,
  issues: Vec<ExtractionIssue>,
}

#[non_exhaustive]
struct ProfileExtraction {
  profile: ProfileIdentity,
  sources: Vec<SourceExtraction>,
  stats: ExtractionStats,
  issues: Vec<ExtractionIssue>,
}

#[non_exhaustive]
struct SourceExtraction {
  source: CookieSourceIdentity,
  status: SourceStatusCode,
  selected: bool,
  acquisition_strategy: AcquisitionStrategyCode,
  cookies: Vec<Cookie>,
  stats: ExtractionStats,
  issues: Vec<ExtractionIssue>,
}

#[non_exhaustive]
struct CookieSourceIdentity {
  role: CookieSourceRoleId,
  format: CookieSourceFormatId,
  path: String,
  path_lossy: bool,
  precedence: u16,
}

#[non_exhaustive]
struct ExtractionStats {
  rows_seen: u32,
  cookies_emitted: u32,
  rows_skipped: u32,
  acquisition_attempts: u32,
  counters_saturated: bool,
}

#[non_exhaustive]
struct ReportStats {
  registered_browsers: u32,
  browsers_detected: u32,
  browsers_not_detected: u32,
  installations_discovered: u32,
  profiles_discovered: u32,
  sources_succeeded: u32,
  sources_failed: u32,
  rows_seen: u32,
  cookies_emitted: u32,
  rows_skipped: u32,
  counters_saturated: bool,
}

#[non_exhaustive]
struct ExtractionIssue {
  code: IssueCode,
  stage: ExtractionStageCode,
  severity: IssueSeverityCode,
  occurrences: u32,
  samples: Vec<String>,
  browser_id: Option<BrowserId>,
  installation_id: Option<InstallationId>,
  profile_id: Option<ProfileId>,
  message: String,
}
```

All public counters are `u32` so Node/TypeScript can represent them exactly. Internally count with
wider integers, saturate at `u32::MAX`, and set `counters_saturated`; never allow a generated N-API
binding to choose an implicit `u64` representation. Bound issue samples to a named constant and
aggregate repeated row issues inside engine outcomes. Top-level issues contain only request-wide,
registry, discovery, and installation problems. Profile issues occur only under that profile;
source-specific issues occur on the corresponding `SourceExtraction`.

Registry capability tiers are declarations for a browser/platform. Public descriptors compute
`available_decryption_tiers` by intersecting declared tiers with key providers compiled and enabled
in the running build. The `decryptable` support claim refers to this effective set, not merely the
registry declaration. A row using a declared but unavailable tier produces a typed
`provider_unavailable` source issue; it is never advertised as currently decryptable.

A source is `succeeded` when acquisition, parsing/schema validation, and its filtered query
complete, even if zero rows match. `rows_skipped` is the number of relevant rows rejected after
being seen because parsing, decryption, or decoding failed. Cookies are serialized on their
`SourceExtraction`, beside source identity, strategy, attempts, and failure details. A consumer
forms a profile-wide stream by concatenating successful selected source outcomes in role/precedence
order. Do not duplicate an aggregate cookie vector at profile level and do not add provenance
fields to the legacy `Cookie` type.
For a persistent source, `selected=true` means the first existing authoritative candidate even if
that candidate later fails. For session sources, invalid attempted candidates have
`selected=false` and the first valid candidate has `selected=true`.

Status definitions:

- `complete`: at least one source succeeded and no error-severity issue occurred;
- `partial`: at least one source succeeded and any relevant installation, profile, or source had an error-severity issue;
- `failed`: no source succeeded and either a detected source was attempted or a detected
  installation/root had an error-severity discovery failure that prevented source enumeration;
- `no_sources`: discovery completed without an error-severity discovery failure and found no
  cookie-bearing sources for the known request.

Request/report semantics:

- unknown browser ID/alias: top-level `Err`, never a report issue;
- unknown profile ID: top-level `Err`;
- known explicitly requested browser with no installation: `Ok(report)` with `no_sources` and `browser_not_detected`;
- `load_report()`: uninstalled registered browsers are summarized in counters, not emitted as warnings; installed-but-failing installations/profiles emit issues;
- a detected installation whose every applicable root fails enumeration: `Ok(report)` with
  `failed` and the root discovery issues; the bare `browser_profiles()` call still returns `Err`;
- total extraction failure remains a report with `failed`, unless request/registry invariants prevented report creation.

`browser_profiles()` semantics are also fixed:

- unknown browser ID/alias: `Err`;
- known browser with no detected installation/profile: `Ok([])`;
- one root fails but another yields profiles: return the profiles; complete discovery diagnostics
  are available through `browser_report()`;
- every applicable detected root fails enumeration: `Err` rather than an indistinguishable empty
  list.

Rust uses internal `PathBuf`; public wire identities expose a UTF-8 display path plus `path_lossy: bool`. Opaque IDs, not display paths, are selection keys. Python/CLI wire keys use snake_case; Node exposes equivalent camelCase object fields.

### 5.8 Public APIs and CLI grammar

Final additive Rust surface:

```rust
supported_browsers() -> Vec<BrowserDescriptor>
browser_profiles(browser_id: &str) -> Result<Vec<ProfileDescriptor>>
browser_report(
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<Vec<String>>,
) -> Result<ExtractionReport>
load_report(domains: Option<Vec<String>>) -> Result<ExtractionReport>
```

`browser_report(..., Some(profile_id), ...)` is the profile-selected structured call; do not add a generic bare-cookie function that loses issues. Existing `firefox_profile()` remains for compatibility.

Chrome vertical-slice entry points remain crate-private until the report model is final. All public generic/report APIs ship across Rust, Python, Node, and CLI in one release gate, though they are implemented in separate PRs.

CLI grammar is fixed:

- `--list-browsers` is standalone and emits registered descriptors as JSON;
- `--list-profiles --browser ID` emits profile descriptors as JSON and conflicts with extraction
  modes;
- `--report [--browser ID]` emits structured report JSON; absent browser means `load_report()`;
- `--profile PROFILE_ID` requires both `--report` and `--browser ID`;
- report/list modes reject `--format netscape`; `--report` conflicts with existing `--load`,
  `--path`, and `--key-path`; list modes additionally conflict with domains;
- remove the closed `PossibleValuesParser` from `--browser` and validate after parsing according to
  mode: without a new mode it accepts only historical `BROWSERS_MAP` keys/aliases and preserves
  legacy flat output; with list/report modes it accepts registered IDs/aliases;
- a registry-only browser ID without `--report` is a usage error that points to `--report`;
- new browser IDs dispatch through the registry/report API, never
  `BROWSERS_MAP.get(...).unwrap()`;
- pre-existing invocations, including no-selector default `load()`, retain their current precedence
  and output.

## 6. Acquisition decisions

### 6.1 Live database policy

Split live and already-acquired reads:

- nonempty WAL: preserve the current verified DB+WAL snapshot, open the pair with `mode=ro` (never `immutable=1`), and let SQLite rebuild SHM in the writable private directory;
- no WAL on a discovered live browser DB: open normal `mode=ro`, execute `BEGIN`, and perform a schema read to establish the SQLite read snapshot before returning; do not use `immutable` for live mutable databases;
- active rollback journal/writer: SQLite either provides a coherent locked read snapshot or returns typed `busy`/`locked`; do not raw-copy a rollback-journal database and do not use immutable through it;
- already-acquired/static copy: an explicit crate-private immutable path is eligible only for a single database file whose acquisition proved it was WAL-free across the copy window, or proved that a prior checkpoint completely drained the WAL before copying. A copied DB+WAL pair always uses `mode=ro`; static lifetime alone is not proof of immutable eligibility.

Keep public `sqlite::connect` source compatible. Add an internal `with_browser_database(path, closure)` boundary that can reacquire and rerun the whole query only for classified snapshot-origin `CORRUPT`, `NOTADB`, or selected `IOERR` failures. Never retry schema incompatibility, SQL errors, or decryption errors. Never fall back to stale immutable reads.

### 6.2 Windows behavior

Try ordinary acquisition first. Only a classified sharing violation enters platform fallbacks.
Existing raw-copy/shadow-copy fallback is permitted only for a positively identified WAL source
whose DB+WAL pair passes the existing coherence verification, or for a verified WAL-free/checkpointed
single-file source already made static. A verified DB+WAL fallback is opened with `mode=ro`, never
immutable.
It must never raw-copy a share-denied, live no-WAL/rollback-journal database. Such a source returns
typed `locked` unless explicit opt-in shutdown first makes it static. Browser termination is
last-resort and never used by normal all-profile/report extraction. Preserve the public
`force_kill` boolean by adapting it to the internal policy.

This project does not claim guaranteed extraction from a real actively share-deny-locked Windows browser under a standard account. Without a verified non-terminating provider, the correct result is a typed `locked` profile issue. Synthetic SQLite lock/WAL success and real browser share-deny behavior are separate tests. Any future claim of live locked-browser success requires its own provider and E2E gate.

RAII attempts snapshot cleanup only after owned SQLite readers/connections are dropped on normal
return or unwind. Filesystem cleanup can fail: emit a bounded warning naming the private snapshot
directory and state that manual removal is required, without replacing the extraction outcome from
a destructor. Process abort/crash makes no cleanup attempt and carries no cleanup guarantee.

## 7. Firefox session policy

Every existing Mozilla-family entry point that reaches `firefox_based` preserves the current merge
in this release: `firefox`, `librewolf`, `zen`, Linux `cachy`, `firefox_profile`, direct
`firefox_based`, and the Mozilla-success path of `any_browser`, including calls routed through
`load`, CLI, Python, or Node. Generic Mozilla report adapters do not call that legacy merge path;
they use this authoritative-source policy:

1. running tier: `sessionstore-backups/recovery.jsonlz4`, then `recovery.baklz4` if supported and valid;
2. clean-shutdown tier: `sessionstore.jsonlz4`, then legacy `sessionstore.js`;
3. stale tier (`previous.jsonlz4`, upgrade files): disabled by default and reserved for a future explicit recovery option.

Select lifecycle tier before mtime; within a tier use the declared order, taking the first valid source. Do not merge across tiers. Missing is silent. An existing invalid higher-priority source produces a bounded warning and falls through. If all session sources are invalid, persisted cookies remain successful.

Generic discovery includes a session-only profile once its session format is supported. Existing `firefox_profiles()` retains database-bearing-only behavior. New reports preserve duplicates until full identity includes container/origin/partition attributes; never deduplicate only `(host, path, name)`.

## 8. Delivery work packages and dependencies

“Phase” is a release milestone, not one PR. Each package below is independently reviewable and revertible.

### Milestone 0 — Contracts, CI, and existing Firefox binding parity

#### 0A — Rebaseline and ADR

- Correct stale WAL, SHM, Firefox-profile, and IE statements in the findings document.
- Add an ADR containing Sections 4–7 decisions.
- Add canonical IDs, aliases, support vocabulary, report status, and CLI grammar.

#### 0B — Compatibility and CI gates

- Add Rust compile and wire-shape fixtures, legacy selectors/load order, and domain-filter parity.
- Fix `.github/workflows/lint.yml` path filters for CLI/bindings.
- Run `cargo fmt --all -- --check`.
- Run `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- Run `cargo test --workspace --all-targets`.
- Run `cargo test -p rookie-cookies --no-default-features --all-targets` on each native OS.
- Maintain a public-surface manifest with declared temporary exceptions until the generic release gate.

#### 0C — Existing Firefox Python/Node parity

- Expose the already-public Rust `firefox_profiles()` and `firefox_profile()` through Python and Node without inventing the future generic report DTO.
- Python updates extension registration, `__init__.py`, `__all__`, `.pyi`, README, and tests while retaining Python 3.7-compatible typing.
- Node updates N-API tasks/objects, `scripts/patch-loader.js`, generated `index.js`, generated `index.d.ts`, README, and export/type tests. Calls remain async.
- Do not add a Firefox-only CLI grammar; CLI profile selection arrives through the final generic flags.

Acceptance:

- Secondary Firefox profile extraction works in Rust, Python, and Node from one controlled fixture.
- Legacy cookie shapes remain exact.
- Binding-only/CLI-only changes trigger CI.

### Milestone 1 — Chromium row and tier correctness

#### 1A — Classifier/router and test injection

- Add unconditional `sha2`.
- Add cipher-version detection, typed key outcomes, injected key provider, and synthetic tier fixtures.

#### 1B — Independent platform tier retrieval

- Windows: retain v10 and v20 outcomes independently.
- Linux: separate v10 and v11 outcomes.
- macOS: adapt current v10 candidates without public API change.

#### 1C — Host-bound cookie decoding and row outcomes

- Separate decrypt-bytes from decode-cookie-value.
- Verify `SHA256(host_key)` exactly with the fixed mismatch policy.
- Capture bounded row issues in `EngineExtractionOutcome` while legacy callers project `Vec<Cookie>`.

Acceptance:

- Mixed v10/v20 and v10/v11 fixtures decrypt all available tiers in one extraction.
- One tier failure preserves another tier's cookies.
- Raw DPAPI and known-unsupported v12 are explicit.
- Host hash match, hash-only, valid UTF-8 mismatch, non-UTF-8 mismatch, short, and old unprefixed cases are exact.
- Plaintext `value`, malformed-row tolerance, domains, default/no-default features remain green.

### Milestone 2 — Acquisition residuals before multi-profile work

#### 2A — No-WAL live read policy

- Implement normal read-only transaction/schema pinning for live no-WAL DBs.
- Add an explicit immutable open path that requires proof of a verified WAL-free/checkpointed single-file static copy; keep every DB+WAL copy on `mode=ro`.
- Add rollback-journal writer tests proving coherent read or typed busy/locked, never immutable/raw-copy hybrid.

#### 2B — Query-level reacquisition

- Add `with_browser_database` closure boundary.
- Classify only snapshot-origin corrupt/not-a-db/selected I/O errors for whole-query reacquisition.
- Record strategy and attempt count.

#### 2C — Windows ordinary-first ordering

- Attempt ordinary acquisition before platform fallbacks.
- Enter fallbacks only on classified sharing violations.
- Adapt `force_kill` to policy and verify no termination without opt-in.
- Treat unresolved real share-deny locks as a typed issue, not stale success.

Acceptance:

- Current WAL behavior and no-SHM recovery remain intact.
- Snapshot/query retry exhaustion is typed and never falls back stale.
- Synthetic WAL/exclusive SQLite matrix passes on three OSes.
- Real Windows share-deny fixture either succeeds through an already-approved non-disruptive path or returns typed `locked`; shutdown does not count as default success.

### Milestone 3 — Private registry and Chrome vertical slice

#### 3A — Registry schema/resolver

- Add the versioned, platform-grouped `browser_registry.json`, owned serde models, compile-time
  `include_str!`/`Lazy` loader, package inclusion/smoke test, invariants, canonical IDs, aliases,
  root IDs, declared persistent/session formats, declared cipher tiers, and `DiscoveryContext`.
- Add deterministic path expansion, sorted globs, deduplication, leading-tilde handling, and root-resolution fixtures.
- Derive effective capability descriptors from declared tiers intersected with compiled/enabled
  providers.

#### 3B — Generic Chromium discoverer

- Add standard candidates `Network/Cookies`, then `Cookies`.
- Add generic unit fixtures for marked, flat, alternate-marker, copied markerless, skipped directories, duplicate roots, Unicode, and channel collisions.
- Chrome integration fixtures cover Chrome's real standard layout only.

#### 3C — Chrome installation/profile vertical slice

- Discover all Chrome installations/channels and profiles.
- Generate deterministic IDs.
- Group Local State correctly and retrieve key outcomes once per installation.
- Add crate-private list/select/report entry points and integration tests; do not export them from `lib.rs` yet.

Acceptance:

- Two roots/channels with same-named profiles receive stable unique IDs.
- Duplicate cookie keys remain separate by profile.
- One broken profile does not erase good profiles.
- Key provider is called once per installation.
- Legacy `chrome()` still uses and passes its legacy selector/shape tests.
- Default-feature and `--no-default-features` descriptor fixtures prove unavailable v20 is absent
  from `available_decryption_tiers`; a v20 row without the provider yields `provider_unavailable`.

### Milestone 4 — Existing engines and final source semantics, still crate-private

#### 4A — Register existing Chromium-family browsers

- Add every existing browser/root/channel to the private registry without changing named wrappers.
- Corrected generic roots are allowed to differ from legacy selectors and are tested independently.

#### 4B — Gecko/Safari/IE registry and outcome adapters

- Register current Firefox-family, Safari, and IE definitions.
- Adapt each engine to the nested profile/source `EngineExtractionOutcome` with real stats/issues.
- Keep all cross-engine generic/report entry points crate-private.

#### 4C — Firefox authoritative session semantics

- Implement Section 7 lifecycle order, first-valid fallback, stable read/retry, and bounded
  warnings.
- Generic outcomes include session-only profiles and preserve duplicates.
- Every legacy Mozilla-family wrapper/direct path through `firefox_based` retains legacy merge behavior; authoritative selection is generic-report-only.

Acceptance:

- Running recovery, clean shutdown, invalid-current fallback with warning, all-invalid persisted
  success, and session-only discovery fixtures pass.
- Missing state is silent and no cross-tier merge occurs in generic outcomes.

#### 4D — Safari parser and named-profile semantics

- Read `Cookies.binarycookies` into a stable whole-file image.
- Detect atomic replacement and in-place metadata/identity changes with bounded retry.
- Use checked arithmetic, structural bounds relative to input, and `try_reserve`; name and test
  each derived limit and one-over-limit case rather than imposing an unexplained arbitrary cap.
- Read `SafariTabs.db` through WAL-aware acquisition; default is first, followed by named UUID
  profiles.
- Treat a readable zero-row acquired snapshot as authoritative. Fall back to directory discovery
  only when the profile DB is absent, unreadable, or schema-incompatible, with a stage-specific
  warning including permission/FDA failures.
- Resolve modern default, legacy default, and named WebKit paths deterministically.
- Reuse generic outcomes and preserve legacy `safari()` first-match selection.

Acceptance:

- Legacy/default/named fixtures, UUID case, duplicate names, database-to-directory fallback,
  malformed input, and one-profile partial failure pass.
- Real-host validation records cover macOS <=13 legacy and 14+ default/named profiles; hosted CI
  covers parser and discovery behavior.

#### 4E — Private cross-engine contract freeze

- Freeze every field shown in Section 5.7, per-source cookie provenance, open identifier vocabulary, counter conversion,
  candidate selection, status computation, and deterministic ordering.
- Exercise Chrome, Firefox persisted+session, Safari default+named, and IE through crate-private
  reports.
- Prove first-existing persistent selection, multi-source provenance, successful zero-row source,
  partial root discovery, and external Firefox profile IDs.

Acceptance:

- All existing registered engines are reachable through crate-private generic outcomes on
  applicable platforms.
- Unknown ID errors, known-not-detected, partial, failed, and no-sources cases are exact.
- Report ordering is stable; legacy selection/output remains unchanged.
- No public generic report symbol has shipped before this acceptance gate passes.

### Milestone 5 — Simultaneous public API and binding release gate

#### 5A — Public Rust DTOs/APIs

- Publish non-exhaustive report/descriptor structs and open string newtypes.
- Publish `supported_browsers`, `browser_profiles`, `browser_report`, and `load_report`.
- Unknown/absent/discovery-failure semantics and ordering follow Section 5 exactly.

#### 5B — Python bindings

- Add generic/report functions, snake_case DTO dictionaries, registration/imports/stubs/docs/tests.
- Keep Python 3.7 compatibility.

#### 5C — Node bindings

- Add async generic/report functions and camelCase N-API objects using the fixed `u32` counter
  contract.
- Update `scripts/patch-loader.js`, generated loader/types, docs, and tests proving every export
  and declaration survives patching.

#### 5D — CLI and cross-surface gate

- Implement the exact post-parse mode validation and JSON report/list grammar from Section 5.8.
- Add Clap conflict/usage tests and ensure legacy invocation precedence is unchanged.
- Pin the invalid legacy `--browser` exit code/error class after moving validation out of Clap's
  possible-values parser; message text may evolve.
- Run one synthetic multi-profile tree through Rust, Python, Node, and CLI as separate processes
  with controlled per-process environment.
- Enable the no-exceptions public-surface inventory gate.

Acceptance:

- Existing registered engines and their finalized source semantics are reachable through all
  applicable public surfaces.
- New report DTOs have identical semantics across languages and casing-appropriate wire names.
- Unknown ID, known-absent, partial-discovery, failed, no-sources, and selected-profile cases are
  exact.
- Node patching cannot truncate declarations/exports; legacy selectors and wire shapes remain
  unchanged.

### Milestone 6 — Additional browsers in OS-scoped batches

New browsers use generic APIs first and never enter legacy `load()`. Convenience wrappers are optional and must ship across every language surface together.

#### 6A — Windows standard/legacy layouts

- Standard: Yandex, 360 (`speed_360`), 360X (`speed_360x`), DC Browser.
- Marker variant: QQ Browser and Sogou; `Preferences_02` becomes a generic Chromium marker alongside `Preferences`.
- Flat fallback: Browser from Vought (`browser_from_vought`).

#### 6B — Packaging and platform variants

- Windows DuckDuckGo dynamic MSIX/EBWebView roots.
- Windows CocCoc discovery and plaintext/v10 claim only.
- macOS Yandex after keychain account/service validation.
- macOS CocCoc after keychain account/service validation.
- Corrected roots/channels for existing browsers land in separate PRs.

#### 6C — Vendor-specific tier upgrades

- Upgrade Windows CocCoc or another fork to a v20 capability only with a verified provider and target-host validation record.

Per-browser gates:

- registry/alias/root/profile invariants;
- applicable discovery fixture and correct Local State/key metadata;
- plaintext cookie fixture on each claimed OS;
- engine-level encrypted fixture for each shared tier;
- per-browser live evidence only where its credential provider differs;
- generic Rust/Python/Node/CLI reachability;
- absent install does not fail unrelated extraction;
- support matrix names exact readable/decryptable tiers.

A validation record includes OS/browser versions, root/layout, observed cipher prefixes, APIs exercised, and pass/fail result.

## 9. Cross-cutting CI and release matrix

Required commands where applicable:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
cargo test -p rookie-cookies --no-default-features --all-targets
cargo test -p rookie-cookies-cli
npm test --prefix bindings/node
python -m unittest discover -s tests/python -p 'test_*.py' -v  # after maturin develop/install
cargo package -p rookie-cookies --list
```

Native matrix:

- Linux/macOS/Windows core tests, default and no-default features.
- Python and Node platform smoke tests for platform-conditioned exports, not wheel build alone.
- Live Chrome/Firefox kept open where the environment can support it.
- Windows synthetic locks separate from real browser sharing locks.
- Current app-bound encryption and Safari named-profile validation may use self-hosted/manual records when hosted runners cannot create the required state.
- Multi-profile cross-surface fixture uses separate processes and controlled `HOME`/`APPDATA`, avoiding global environment races.

## 10. Rollout, rollback, and documentation

- Each numbered package is a small PR or short PR stack, not an entire milestone-sized change.
- Keep legacy selectors and new registry side-by-side for this release line.
- Do not delete public config fields, legacy adapters, or named functions.
- Internal vertical-slice APIs remain private until their cross-language wire model is final.
- Capability flags allow a tier claim to be downgraded without removing detection.
- A new-report/browser regression can be reverted without touching legacy extraction.
- Release notes distinguish correctness fixes, additive APIs, registered/detected browsers, readable cookies, and decryptable tiers.
- Correct the findings document, add the compatibility ADR, publish the OS/tier capability matrix, and update Rust/Python/Node/CLI examples together.
- Keep a concise platform note for permissions, temporary-file lifetime, key scope, and opt-in termination; broader security review is deferred.

## 11. Completion criteria

The project is complete when:

- compatibility fixtures prove all legacy APIs and wire shapes remain intact;
- shared row extraction/decryption/acquisition cores serve legacy and new pipelines without moving legacy source selection;
- generic grouped report/profile APIs ship across Rust, Python, Node, and CLI;
- mixed Chromium tier routing and verified host hashes pass;
- existing browsers are represented in the canonical private registry;
- each additional browser passes its declared per-OS capability gates;
- active WAL, no-WAL/rollback, retry, and typed-lock behavior pass the defined matrix;
- generic Mozilla report APIs use authoritative session semantics while every legacy `firefox_based` wrapper/direct path retains its merge;
- Safari named profiles and parser fixtures pass plus documented real-host validation;
- documentation distinguishes registry, detection, readability, and verified decryption.

Rich cookie metadata, CookieEditor output, a non-terminating Windows locked-handle provider, and a future major-release change to legacy all-profile defaults remain separate roadmap items.
