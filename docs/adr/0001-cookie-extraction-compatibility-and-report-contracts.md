# ADR 0001: Cookie extraction compatibility and report contracts

- Status: Accepted
- Date: 2026-08-11
- Scope: cookie extraction only

## Context

`rookie-cookies` needs installation-aware, multi-profile extraction and broader browser discovery, but its current Rust, Python, Node, and CLI surfaces are already consumed downstream. Routing existing named functions through new all-profile discovery would change selected credentials, counts, duplicates, ordering, and errors even if function signatures stayed the same.

Recent work is baseline:

- `d918a90` added WAL-aware `SqliteReader` snapshots and deliberately rebuilds rather than copies `-shm`.
- `99ca297` added Rust Firefox profile listing and selection.
- `d0ea87a` corrected IE security flags and unspecified SameSite handling.

This ADR freezes the compatibility boundary and the contracts for the additive registry/profile/report pipeline.

## Decision

### 1. Legacy APIs remain legacy selectors

For the current release line:

- Every existing Rust function signature remains unchanged, including platform-specific `chromium_based` signatures.
- Public `config::Browser`, `Config`, `CONFIG`, and `get_browser_config` remain source compatible; `Browser` remains constructible by struct literal.
- Public `Cookie` remains the exact existing eight-field constructible type, including raw `same_site: i64`.
- Existing Python cookie dictionaries, Node `CookieObject`, CLI JSON and Netscape fields, and synchronous/asynchronous behavior remain unchanged.
- Existing named browser functions continue to use their current `find_*_paths` selectors and first/default-profile priorities.
- `load()` retains its browser set, per-browser selectors, and concatenation order.
- New browsers do not enter legacy `load()`.
- New all-profile discovery is never flattened behind an existing function.
- Existing SQL parameter binding remains unchanged. Persistent
  Chromium/Mozilla SQLite sources keep parameterized `LIKE` queries as
  candidate reducers, then enforce the same boundary-aware, case-insensitive
  host matcher used by Safari and Firefox session sources. This announced
  release-boundary security correction makes `None` unfiltered while an
  explicit empty filter matches nothing.
- Legacy cookie row order remains unspecified and unsorted.
- Failures must not collapse into plausible successful empty output. Human error text is not stable.

Legacy wrappers may share acquisition, row parsing, and decryption internals with the new pipeline as long as their source selection and wire results remain compatible.

### 2. Registry and capability vocabulary

`rookie-rs/browser_registry.json` is the versioned source of truth for the public generic pipeline. It is grouped by target OS, embedded at compile time with `include_str!`, and deserialized once. `rookie-rs/config.json` remains frozen as the public compatibility artifact used by legacy selectors.

The files therefore have a directional, not byte-for-byte, parity contract.
The registry owns corrected installation roots, channels, XDG-aware locations,
and registry-only browsers. The legacy config owns the historical paths that
existing named selectors still probe. A union-based test normalizes legacy
cookie-file templates to installation roots, covers all three platforms, and
requires every config-only browser, registry-only browser, path difference,
and channel difference to appear in an exact reviewed inventory. This prevents
new drift without copying known-bad legacy spellings (for example
`Chrome-nightly`, `Edge-nightly`, or `google-chrome-dev`) into the registry.
Linux `opera_gx` remains an explicit config-only exemption: its legacy entry
has no paths and is not advertised by generic discovery.

Canonical existing IDs are:

```text
arc, brave, cachy, chrome, chromium, edge, firefox,
internet_explorer, librewolf, octo_browser, opera, opera_gx,
safari, vivaldi, zen
```

Aliases include:

```text
ie, opera gx, opera-gx
```

Canonical new IDs are:

```text
yandex, speed_360, speed_360x, qq_browser, dc_browser,
sogou, browser_from_vought, duckduckgo, coccoc
```

Short aliases include `360`, `360x`, `qq`, `dc`, and `vought`.

Capability terms have distinct meanings:

- `registered`: a definition exists for the running OS.
- `detected`: a matching installation/profile exists.
- `readable`: the selected cookie source can be acquired and parsed, including plaintext rows.
- `decryptable`: a cipher tier is both declared for that browser/OS and backed by a provider compiled and enabled in the running build.

`supported_browsers()` returns registered definitions for the running OS; it does not scan the filesystem. Descriptors expose declared and currently available decryption tiers separately. Finding a cookie path is not evidence that encrypted rows are usable.

### 3. Installation and profile identity

Registry roots have stable `root_id` values. IDs use versioned, length-prefixed SHA-256 encodings:

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

IDs are lowercase 64-character hexadecimal strings. They are opaque, case-sensitive, deterministic while registry roots and installed paths remain stable, and not portable across machines. Generic selectors accept only IDs returned by discovery. The legacy Firefox API retains name/directory/path matching.

Before IDs are assigned, profiles are deduplicated browser-wide by normalized canonical profile directory, falling back to the selected persistent source for flat layouts. The first ordered installation owns a physical profile.

Generic profile ordering is:

1. installation registry priority, then normalized path;
2. default profile first;
3. locale-independent lowercase display name, raw display name, then normalized path.

The additive Chrome convenience listing is the only ordering exception. It
places `Local State.profile.last_used` first, then the remaining entries in
`last_active_profiles` order, while preserving generic order for profiles with
no usable hint. The hints are advisory: missing, stale, or malformed metadata
falls back to the generic default-first result, and ambiguous human-readable
selectors remain errors rather than silently choosing a channel.

Generic report cookies sort by `(domain, path, name, expires, secure, http_only, same_site, value)`. Exact duplicates retain extraction order. Duplicate cookie keys from different profiles remain in separate profile groups.

### 4. Role-aware cookie sources

Profiles hold ordered persistent and session source candidates.

- Persistent alternatives use the first existing candidate as authoritative. If it cannot be acquired, parsed, or queried, the report records failure and does not silently fall through to a potentially stale lower-priority copy.
- Chromium persistent precedence is `Network/Cookies`, then `Cookies`.
- Session candidates use the Firefox lifecycle policy below and fall through to the first valid candidate.
- A profile may combine one authoritative persistent source and one selected session source, but never two persistent alternatives.

Reports retain source role, format, path, precedence, selection state, acquisition strategy,
cookies, statistics, and issues. Cookies are serialized on the source outcome that emitted them;
there is no duplicate aggregate cookie vector at profile level. A profile-wide stream is the
deterministic concatenation of successful selected source outcomes.

### 5. Report model and errors

New descriptors and reports are additive, serde-serializable, and non-exhaustive. Extensible IDs and codes are validated open string newtypes, not closed enums. Rust newtypes implement `Display`, `AsRef<str>`, and validated `FromStr`. Python and CLI use snake_case wire keys; Node uses equivalent camelCase fields.

Reports group data as:

```text
ExtractionReport
  -> ProfileExtraction
       -> SourceExtraction
```

Each profile includes its identity, source outcomes, aggregate statistics, and profile issues.
Each source outcome contains its own cookies, so persistent/session provenance remains recoverable
even for duplicate rows. Source-specific failures remain on the relevant source. Top-level issues
are reserved for request-wide, registry, discovery, and installation problems.

Public counters are `u32`. Wider internal counts saturate at `u32::MAX` and set `counters_saturated`, which avoids implicit Node `u64`/BigInt contracts.

A source succeeds when acquisition, parsing/schema validation, and its filtered query finish, even if zero rows match. `rows_skipped` counts seen rows rejected during parsing, decryption, or decoding.

Report statuses are:

- `complete`: at least one source succeeded and no relevant error-severity issue occurred.
- `partial`: at least one source succeeded and a relevant installation, profile, or source has an error-severity issue.
- `failed`: no source succeeded and either a detected source was attempted or a detected
  installation/root had an error-severity discovery failure that prevented source enumeration.
- `no_sources`: discovery completed without an error-severity discovery failure and found no
  cookie-bearing source for the known request.

Request behavior is:

- unknown browser ID/alias: top-level `Err`;
- unknown profile ID: top-level `Err`;
- known explicitly requested browser with no installation: `Ok` with `no_sources` and `browser_not_detected`;
- `load_report()`: uninstalled registered browsers are counted, not warned; installed failures are reported;
- every applicable root of a detected installation fails enumeration: `Ok` report with `failed`
  and discovery issues; the bare `browser_profiles()` call returns `Err`;
- total extraction failure: a `failed` report unless request or registry invariants prevented report creation.

`browser_profiles()` returns `Err` for an unknown browser, `Ok([])` for a known but absent browser, partial discoveries when at least one root succeeds, and `Err` when every detected applicable root fails enumeration. Full partial-discovery diagnostics are available from `browser_report()`.

Repeated row issues are aggregated with bounded samples. Cookie values and key bytes are never included in diagnostics.

### 6. Chromium decryption semantics

Chromium keys are retained independently for v10, v11, and v20. All applicable providers run once per installation/request. Failure of one tier does not discard another tier. Rows dispatch only to their detected tier; raw legacy DPAPI is row-scoped; v12 SecretPortal is a known unsupported tier until a provider exists. Blobs shorter than three bytes are malformed before version detection.

Decryption returns bytes. Cookie decoding receives `host_key`:

- an exact `SHA256(host_key)` prefix is stripped;
- a hash-only plaintext becomes an empty value;
- a mismatched but valid UTF-8 plaintext remains unchanged;
- a mismatched non-UTF-8 plaintext is a typed decode issue and the row is skipped;
- short or older unprefixed valid UTF-8 remains unchanged.

Plaintext Chromium `value` rows and row-level fault isolation remain supported.

### 7. SQLite acquisition

The acquisition policy is:

- A nonempty WAL uses the existing verified DB+WAL snapshot and always opens with `mode=ro`, never `immutable=1`. `-shm` is not copied; SQLite rebuilds it in the writable private directory.
- A discovered live no-WAL database opens in normal read-only mode and establishes a SQLite read transaction. It is not opened immutable.
- An active rollback-journal writer must yield a coherent SQLite read or a typed busy/locked result. The implementation does not raw-copy or immutably read through it.
- The private immutable path accepts only an already-acquired static **single-file** copy whose acquisition verified no nonempty WAL across the copy window, or verified that a checkpoint completely drained the WAL before copying. A static DB+WAL pair still opens with `mode=ro`; static lifetime by itself is not immutable eligibility.
- Whole-query reacquisition is bounded and restricted to classified snapshot-origin corruption or selected I/O failures. Schema, SQL, and decryption failures are not retried.
- Windows attempts ordinary acquisition first. Platform fallbacks run only for classified sharing violations.
- Browser termination remains explicit opt-in and is never used by normal generic/report extraction.

RAII attempts cleanup only after owned SQLite readers/connections are dropped on normal return or unwind. Cleanup failure produces a bounded warning naming the private directory and requiring manual removal; a destructor does not replace the extraction outcome. Process abort/crash makes no cleanup attempt and has no cleanup guarantee.

### 8. Firefox session sources

Every Mozilla-family entry point that reaches `firefox_based` selects one authoritative session
source: `firefox`, `librewolf`, `zen`, Linux `cachy`, `firefox_profile`, direct `firefox_based`, and
the Mozilla-success path of `any_browser`, including `load`, CLI, Python, and Node calls routed
through them. Generic Mozilla report adapters reuse the same lifecycle order while preserving
source-level diagnostics:

1. running tier: `sessionstore-backups/recovery.jsonlz4`, then supported valid `recovery.baklz4`;
2. clean-shutdown tier: `sessionstore.jsonlz4`, then legacy `sessionstore.js`;
3. stale recovery fallback: `previous.jsonlz4`; upgrade files remain disabled.

Lifecycle tier precedes modification time. Within a tier, the first valid source wins. Sources are not merged across tiers. Missing files are silent. An invalid higher-priority file produces a bounded warning and falls through; persisted cookies remain successful if all session sources are invalid.

Generic discovery may include a session-only profile once its format is supported. Existing `firefox_profiles()` remains database-bearing only. Reports preserve duplicates until cookie identity includes container, origin, and partition attributes.

### 9. Public APIs and CLI grammar

The additive Rust API is:

```rust
supported_browsers() -> Vec<BrowserDescriptor>
browser_profiles(browser_id: &str) -> Result<Vec<ProfileDescriptor>>
browser_report(
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<Vec<String>>,
) -> Result<ExtractionReport>
load_report(domains: Option<Vec<String>>) -> Result<ExtractionReport>
chrome_profiles() -> Result<Vec<ProfileDescriptor>>
chrome_profile(
  profile: &str,
  domains: Option<Vec<String>>,
) -> Result<ExtractionReport>
```

`chrome_profiles()` uses the Chrome-specific active preference above without
changing `browser_profiles("chrome")`. `chrome_profile()` accepts the opaque
profile ID, display name, directory name, or a full path whose `path_lossy` flag
is false; a lossy display path requires the opaque ID. It returns the grouped
report so profile/source provenance and typed partial failures are retained.
The existing flat `chrome()` function is unchanged.

The complete report/profile surface ships through Rust, Python, Node, and CLI together on the frozen cross-engine semantics.

CLI rules are:

- `--list-browsers` is standalone and emits registered descriptors as JSON.
- `--list-profiles --browser ID` emits profile descriptors as JSON.
- `--report [--browser ID]` emits report JSON; no browser means `load_report()`.
- `--profile PROFILE_ID` requires both `--report` and `--browser ID`.
- Report/list modes reject Netscape; report conflicts with `--load`, `--path`, and `--key-path`; list modes also conflict with domains.
- Without a new report/list mode, `--browser` accepts only historical keys/aliases and preserves flat output.
- A registry-only browser without `--report` is a usage error.
- Existing no-selector behavior remains legacy `load()`.

## Consequences

Positive consequences:

- Browser and profile coverage can expand without changing existing selectors.
- Mixed Chromium encryption tiers and partial profile failures become visible.
- Reports carry provenance without changing `Cookie`.
- Capability documentation distinguishes discovery from actual decryption.

Costs and constraints:

- The legacy config/selectors and private registry coexist for this release line.
- Legacy and generic Mozilla paths share authoritative first-valid session semantics; generic reports additionally retain source-level diagnostics.
- Every new public DTO must ship consistently across all bindings.
- New browser support requires OS- and tier-specific evidence, not path recognition alone.

Rich cookie metadata, CookieEditor output, a non-terminating Windows locked-handle provider, and changing legacy functions to all-profile defaults remain deferred.
