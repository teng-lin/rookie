# Changelog

All notable changes to this maintained fork are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Three path request types become two.** `DirectPathRequest` and
  `ChromiumPathRequest` are replaced by `PathExtractRequest` +
  `extract_from_path`; `DirectPathRequest` was `ChromiumPathRequest` minus
  credentials minus the locked-database policy, so the pair was one type split
  by whether the caller happened to know the file was Chromium. Constructors:
  `plaintext`, `sniff`, and the platform-gated `unix_identity` (Unix) /
  `windows_local_state` (Windows).
  `ChromiumCredentialSource::Automatic` is gone: it was the default and it
  could never succeed on Windows. Isolation-carrying path output now comes
  from `from_path(..).detailed_cookies()`, so the Rust free function backing
  `chromium_cookies_from_path_detailed` is gone too — a real narrowing at that
  layer, since a domain-filtered *detailed* path list is no longer expressible
  through it. **Python keeps the function** (now backed by
  `from_path(..).into_detailed_cookies()`) but drops its `domains` option:
  passing `domains` raises `RookieRequestError` rather than the binding
  reimplementing the core's `pub(crate)` matching rule to fake the filter
  back. Python's `from_path()` gains `plaintext_only` / `browser_id` /
  `local_state_path` keyword arguments (mutually exclusive, validated with
  the now-wired-up `conflicting_credential_selectors` code before any I/O)
  for the same credential selection `chromium_cookies_from_path`'s options
  dict already offered.
- Sniffing a Chromium database is plaintext-capable only; an encrypted row is
  the new `missing_chromium_credentials`. On Unix that is a narrowing (the
  ordered identity probe is gone). On Windows it is a widening: the old call
  returned `missing_local_state_file` before attempting extraction, so even a
  fully plaintext database failed.
- **`ProfileSelection` and `ReportScope` make an illegal selection
  unrepresentable.** `Request` is renamed `ExtractRequest` (prerelease-only)
  and joined by `ReportRequest`, whose scope may widen to every profile
  because only a report can describe more than one. `ExtractRequest::browser`
  selects the first legacy-eligible profile; `ReportRequest::browser` reports
  every profile, matching v0.5.9's `browser_report(id, None, ..)`.
  `From<ExtractRequest> for ReportRequest` narrows, never widens.
- **`ReadResult::header` takes a `SendContext`** instead of a bare URL, and is
  send-safe: it never merges two isolated browsing contexts. A snapshot holding
  a partitioned or containered cookie demands the selector that identifies it
  and raises `RequestError::IncompleteSendContext` (with a stable `required`
  token list) rather than guessing. New `SendContext`, `ResourceKind`, and
  `MethodClass`; `SameSite` is now applied, with `Site` defined as
  (scheme, host). Firefox `partitionKey` tuples and Chromium
  `top_frame_site_key` values are normalized into that one space, so a Firefox
  dFPI cookie is matched rather than silently absent from every header. New
  warning `unparsable_partition_key` for a key neither parser understands —
  such a row is a non-match everywhere, never treated as unpartitioned.
- **`ReadResult` is isolation-aware on both source axes.** Its native
  representation is `DetailedCookie`, so a CHIPS partition key or a Firefox
  container survives to `header()`. New: `detailed_cookies()`,
  `into_detailed_cookies()`, `common::format::detailed_json`, and CLI
  `--format detailed`. `cookies()` keeps its `&[Cookie]` signature, backed by a
  projection built once at construction. `Cookie` gains `Clone`/`PartialEq`/
  `Eq`/`Hash`; `DetailedCookie` gains `Clone`/`PartialEq`/`Eq`.
- `SessionPolicy` and `ReadRequest::include_session()`. Session cookies used to
  be an accident of naming a profile; they are now their own question, and
  `read(ReadRequest::browser("firefox").include_session())` is expressible for
  the first time.
- Rust: `ExecutionControl` (timeout, cancellation, and the new
  `AppBoundPolicy`) composed once into every request type instead of copied
  per type, plus `execution(..)` setters and `load_report_with`,
  `browser_profiles_with`, `chrome_profiles_with`, `profiles_with`, and
  `LoadReportRequest` so the stable v0.5.9 listing and aggregate signatures can
  stay unchanged while still taking control.
- Rust: one typed public `Error` (`Request` / `Stopped` / `Source` / `Engine`)
  with a stable `code()` on every variant, plus `EngineError` carrying the
  `no_selected_source`, `no_discovered_source`, `discovery_failed`, and
  `engine_failure` codes. Those codes were previously unrecoverable: the sites
  that produce them raised formatted strings. Python gains `RookieError`,
  `RookieStoppedError`, and `RookieSourceError` beside the existing request and
  engine exceptions; Node's `kind` is now `request` / `stopped` / `source` /
  `engine`.
- Native linux-arm64 artifacts: PyPI manylinux aarch64 wheel, npm
  `rookie-cookies-linux-arm64-gnu`, and a CLI
  `aarch64-unknown-linux-gnu` binary, all built on `ubuntu-24.04-arm`.
- Node and Python errors expose stable request/engine identity, library fault
  codes, stop reasons, ambiguous-profile IDs, and redacted direct-path
  metadata. Node read warnings also report when their count was saturated to
  the binding's `u32` range.
- The generated report JSON Schema now enforces the same lexical constraints
  as Rust for open vocabulary identifiers and opaque installation/profile IDs.
- Python `ReadResult` gains `detailed_cookies()`: isolation-intact records,
  each `{"cookie": <8-field dict>, "context": {...}}`, backed by the core's
  `detailed_cookies()`. New warning codes `malformed_host_identity` and
  `unparsable_partition_key` surface through the existing `ReadWarning.code`
  string, no binding change needed.
- Python `read()` / `jar()` gain `include_session: bool = False` and
  `select: Literal["legacy_first"] = "legacy_first"`; `browser_report()` gains
  `select: Literal["legacy_first", "all"] = "all"`. Passing `profile=`/
  `profile_id=` together with `select="all"` (or `select="all"` to
  `read`/`jar` at all, which cannot express it) raises `RookieRequestError`
  with `code == "conflicting_profile_selection"` before any I/O.
- Python `ReadResult.header()` accepts a `SendContext`-shaped mapping or
  keyword arguments (`top_level_site`, `resource`, `method`,
  `user_context_id`, `private_browsing_id`, `now`) in addition to a bare URL
  string, mirroring Rust's `SendContext`. `RookieRequestError` gains a
  `required: list[str]` attribute naming the selectors an
  `incomplete_send_context` fault was missing (empty for every other kind).

### Removed

- PyPI wheels for linux i686, armv7, s390x, and ppc64le. Those arches have
  no desktop browser cookie store this project can honestly support.

### Changed

- **Breaking (Rust):** `rookie_cookies::Result<T>` is now
  `Result<T, rookie_cookies::Error>`. It was `anyhow::Result<T>` through
  v0.5.9. A caller who wrote `rookie_cookies::Result<T>` around a bridge
  function should use `rookie_cookies::anyhow::Result<T>`, which still
  resolves. The deprecated v0.5.9 bridge functions are unaffected: they keep
  returning `anyhow::Result`, spelled explicitly. `Error` implements
  `std::error::Error + Send + Sync`, so `?` from the new surface into an
  `anyhow` call site keeps working.
- **Breaking (Python):** a timeout, cancellation, or resource-exhaustion stop
  now raises `RookieStoppedError`, not `RookieEngineError`. The two-way
  request/engine split had no separate bucket for a cooperative stop, so it
  fell under the engine class; the new four-way split gives it its own class.
  Code that caught `RookieEngineError` to read `stop_reason` must catch
  `RookieStoppedError` instead. `kind` is `request` / `stopped` / `source` /
  `engine` (was `request` / `engine`).
- **One `Request` value no longer selects differently depending on which
  function it is passed to.** In 0.6-beta the same value meant "the first
  legacy-eligible profile" to `extract` and "every profile" to
  `extract_report` — two calls that looked identical and read different
  profiles. That is now a type-level distinction.
- Engine extraction seams take the typed internal `ProfileSelection` instead
  of `Option<&str>`, which could only express "one profile" or "all" and made
  the legacy-first scope inexpressible on the report path.
- **A profile-scoped `read` no longer flows through the report builder.** The
  report DTO is frozen at `schema_version: 1` and carries the eight-field
  `Cookie`, so a snapshot flattened out of it had already lost
  `CookieContext` — `header()` would have seen no isolated cookies and merged
  partitions on the recommended path. `read` now stops at the finalized record
  and projects `DetailedCookie` for both single-profile selections.
- **Breaking:** `ReadResult::browser_id()` returns `Option<&str>` instead of
  `&str`. It was the empty string for `from_path`, an in-band sentinel a caller
  had to know about. Python exposes `Optional[str]`, Node `string | null`.
- **Breaking (Gecko):** `.profile(q)` alone no longer imports session cookies.
  `SessionPolicy` defaults to `PersistentOnly`, enforced before lookup, so the
  crate does not open `sessionstore.js` or `recovery.jsonlz4` unless asked.
  Pass `include_session()` (Rust), `include_session=True` (Python),
  `includeSession: true` (Node), or `--include-session` (CLI). This fails
  quietly — a smaller list, no error. Report jobs are unaffected: they always
  retain session sources.
- A row whose required host identity did not survive decode is omitted rather
  than emitted as `domain: ""`, which matches nothing and belongs to no site.
  Snapshots count it under the new `malformed_host_identity` warning; reports
  record it as a source issue of the same name; `extract` inherits the omission
  and not the count, because a bare `Vec<Cookie>` has nowhere to put it — use
  `read` or `extract_report` when the count matters. Unknown *optional*
  isolation fields stay `None` and never drop a row.
- **Windows App-Bound (v20) recovery is now an explicit per-request policy.**
  `AppBoundPolicy` defaults to `InjectionOnly`: unprivileged reflective COM
  injection (Chrome 127+), but **never** the elevated SYSTEM impersonation
  that `AllowElevatedFallback` permits — that now has to be asked for out
  loud. `Disabled` performs no injection, no browser spawn, no process
  enumeration and no impersonation at all; v20 rows are then skipped and
  surface as `decrypt_failed` read warnings with a `provider_failed` report
  issue naming the policy as the cause.
  The default is `InjectionOnly` rather than `Disabled` because Chrome has
  written v20 cookies on Windows since Chrome 127, so on a current profile
  essentially every row is v20 — a `Disabled` default would return an empty
  list for the most common Windows case, and would leave the deprecated
  v0.5.9 bridge *more* capable than the recommended API. Injection is still
  not free of consequence: it spawns a browser process and writes into it,
  which endpoint security products can flag, so pass `Disabled` where that
  matters.
  The deprecated v0.5.9 bridge keeps `AllowElevatedFallback`, so its 0.5.8
  capability is unchanged. Python's `read`, `from_path`, `browser_report`, and
  `load_report` take `app_bound: str = "injection_only"` (`"disabled"` /
  `"injection_only"` / `"allow_elevated_fallback"`); an unrecognized string
  raises `RookieRequestError` before any I/O. Node's `appBound` and the CLI's
  `--app-bound` follow the same default. `browser_profiles` and
  `chrome_profiles` take no `app_bound` parameter, since listing does no
  App-Bound work.
- `ROOKIE_E2E_APPBOUND_MODE` no longer steers a published build. It is compiled
  in only under `cfg(test)` or the off-by-default `e2e-appbound-steering`
  feature, and even there it can only narrow what the request policy already
  permits -- it can never widen one or override `Disabled`.
- Internal stop classification no longer round-trips a typed value through the
  report DTO's `termination` string. `TerminationCode` exists only at the wire
  edge; the flatten seam behind `extract` reads the enum.
- Single-browser compatibility APIs now return typed timeout, cancellation,
  and resource-exhaustion errors instead of silently returning partial
  cookies. Flat Rust `load()` retains its documented best-effort behavior for
  cookies committed by browsers already in flight when the shared job stops.
- Profile-scoped `extract()` and `read()` resolve the profile once and share
  one absolute deadline across resolution and extraction.
- `ReadResult::header()` now re-checks expiration at send time and excludes a
  cookie whose expiry equals the current second. `include_expired` controls
  snapshot inventory only. Profile-scoped and compatibility reads now project
  the same decrypt and row-read warning categories.
- Node `fromPath` and the CLI `from-path` command reject every combination of
  conflicting Chromium credential selectors before source I/O. Python option
  shape failures consistently use `RookieRequestError`.
- Stopped report work now carries a typed request issue and cannot be reported
  as ordinary `no_sources`; completed source data remains available with a
  partial status. Finalization issues preserve causes including decrypt,
  decode, encrypted, provider-unavailable, and provider-failed.
- CI is split into PR, nightly, and release lanes. Pull requests run one
  `check` job per OS (fmt, package, metadata, cargo-audit, rust lint+test,
  public API), and stagger Node build+test (22/24/26)
  plus Python build+tests (3.12/3.13/3.14)
  across Ubuntu/macOS/Windows. The full Node and Python version product,
  FreeBSD, packaging wheels/sdist, Chrome/Firefox e2e, and artifact smoke
  move to nightly / `main`. Extra hosted browsers (Edge, Chromium, Windows
  Brave, Opera, Opera GX, LibreWolf, Zen)
  are installed on the runner when a silent installer exists. Claimed-browser
  fixtures remain for products we cannot install. Extra hosted browsers run on
  nightly and again on release. Claimed-browser fixtures run on
  `v*` tags, GitHub Releases, or `workflow_dispatch`.
- `docs/testing.md` lists every registry browser against hosted CI, release
  fixtures, or manual (Safari / Internet Explorer).

### Deprecated

- Rust `load()` is superseded by `read(ReadRequest::browser(...))` for
  snapshots and `load_report()` for grouped diagnostics. `CookieToString` is
  an unfiltered compatibility formatter; use `ReadResult::header(url)` for a
  URL-scoped header view.
- The free `stop_reason` / `fault_kind` functions and `Error::fault_kind`.
  `FaultKind` is a two-way FFI split that collapses three of `Error`'s four
  variants; match on `Error`, or compare `Error::code()`.
- Rust `browser(id, domains)`, superseded by
  `extract(ExtractRequest::browser(id).domains(..))`. It was missing a
  `#[deprecated]` and is scheduled for deletion in 0.7.0.
- The crate-root `pub use anyhow` re-export, superseded by
  `rookie_cookies::Error` / `rookie_cookies::Result`. **The compiler cannot
  warn on this one:** `#[deprecated]` on a `pub use` of an external crate root
  does not fire for `rookie_cookies::anyhow::Result<T>`. The attribute is
  present so rustdoc shows the banner, and this entry is the notice. It is
  also, deliberately, the escape hatch for the `Result` alias break above, so
  it stays working for the whole 0.6.x line.

### Fixed

- Artifact smoke on Ubuntu ARM64: maturin-action's manylinux container left
  `RUSTC_WRAPPER=sccache` in the host job environment, so the native Node
  binding build failed looking for a host `sccache`.

## [0.6.0-beta.1] - 2026-08-18

### Added

- Rust `RequestError` classifies unknown browser / empty / unknown / ambiguous /
  lossy profile selectors, missing browser, and invalid header URLs as request
  faults. Unknown browser on `resolve_registered_browser` is `FaultKind::Request`.
- `Request::profile` and `extract_report`. `browser_report`'s middle argument
  now accepts the same profile query (id, name, directory, non-lossy path, or
  persistent cookie-DB path). CLI `--profile` requires `--browser` only.
- Job API: `read` / `ReadResult` (`into_cookies`, `header`) / `ReadWarning`
  (`code`, `count`) / `from_path` / `profiles`. Python also exports `jar` and
  `report`. Node exports `read`, `profiles`, `report`, `fromPath`. CLI
  subcommands `read`, `profiles`, `report`, `from-path`, `header`.
- ADR 0004: `read` is the recommended entry.

### Changed

- Documentation rehaul for 0.6: package-owned language guides (`read` / `jar`),
  Chrome/Edge/Brave App-Bound v20 coverage notes, and migration from 0.5.6.
- `browser_report` widens non-id profile queries that previously always failed.
- `firefox_profile` now resolves through `extract(Request::browser("firefox").profile(q))`.
- Recommended docs entry is `jar(browser=…)` / `read(…).as_list()`.

### Deprecated

- `chrome_profile`, `firefox_profiles`, and the `firefox_profile` selector
  retarget to `extract` / `extract_report` / `browser_profiles`.

## [0.6.0-alpha.3] - 2026-08-18

### Added

- Windows Chrome-family browsers (Chrome, Brave, Edge, CocCoc, and Avast) can
  decrypt App-Bound (v20) cookies via reflective COM injection into a spawned
  browser process, without administrator privilege. Elevated SYSTEM
  impersonation remains available as a fallback when injection is unavailable.

## [0.6.0-alpha.2] - 2026-08-17

### Added

- Rust gains `FaultKind`/`fault_kind(&anyhow::Error)`, classifying an error as
  a request fault (bad input, e.g. an invalid explicit source) or an engine
  fault, alongside the existing `stop_reason()`. Python's `RookieRequestError`
  (a `ValueError` subclass) and `RookieEngineError` (a `RuntimeError`
  subclass) and Node's `InvalidArg`/`GenericFailure` error statuses now use
  this classification instead of one flat error type for every failure.
- Python gains `rookie_cookies.dto`, typed dataclasses for the canonical
  report/descriptor shapes (`ExtractionReport`, `BrowserDescriptor`, `Cookie`,
  etc.) generated from a new `schema/report-dto.schema.json`, with a
  `from_dict()` classmethod converting the existing dict-shaped return values.
  This is additive; every function's existing dict return type is unchanged.
- Python and Node.js now expose canonical `cookies_from_path` / `cookiesFromPath`
  and explicit Chromium path APIs with credential options matching Rust's typed
  direct-path builders. The CLI adds `--browser-id` and `--plaintext-only`.
- Rust's `Request`, `DirectPathRequest`, and `ChromiumPathRequest` gain
  `.timeout(Duration)` and a new `CancellationHandle`/`.cancellation(...)` for
  cooperative, cross-thread cancellation of an in-flight extraction, plus a
  `stop_reason()` helper reporting why an extraction stopped early --
  `TimedOut`, `Cancelled`, or `ResourceExhausted`. Node's
  `cookiesFromPath`, `chromiumCookiesFromPath(Detailed)`, and every
  single-browser export (`firefox`, `chrome`, `safari`, etc.) accept matching
  `timeoutMs`/`cancellation` parameters, via a new `CancellationHandle` class.
  Python's `cookies_from_path` gains matching `timeout`/`cancellation` keyword
  arguments, and `chromium_cookies_from_path(_detailed)` gain matching
  `timeout`/`cancellation` options-dict keys, via a new `CancellationHandle`
  class; Python's other named-browser functions (`firefox`, `chrome`, etc.)
  are unchanged. The CLI's `--browser` and `--path` modes now cancel cleanly
  on `SIGINT`/`SIGTERM` instead of aborting mid-extraction (a second signal
  forces an immediate exit), and no longer panics on a closed downstream pipe
  (e.g. `rookie-cookies --load | head -1`).

### Changed

- **Breaking (0.6.0):** Python's `cookies_from_path` and
  `chromium_cookies_from_path(_detailed)` now raise `RookieRequestError` (a
  `ValueError` subclass) instead of `RuntimeError` for a request fault (e.g. a
  missing or malformed explicit source, or mutually exclusive options); an
  `except RuntimeError` around one of these three functions no longer catches
  that case. Every other function's error type is unchanged. Node's thrown
  error `.status`/`.code` moves from always `Unknown` to `InvalidArg` (request
  faults) or `GenericFailure` (everything else) across every export.
- Rust's `load()` and `load_report()` now probe registered browsers
  concurrently on a small bounded worker pool sharing one deadline/
  cancellation budget, instead of one browser at a time. A slow or hung
  source no longer starves every other source's share of the shared budget.
  Results are always grouped by browser in the same fixed registry order
  regardless of completion order, and a per-source timeout or cancellation
  stops not-yet-started browsers without discarding results already
  completed by browsers that were in flight at that moment.
- **Breaking (0.6.0):** The Python package now requires CPython 3.11 or newer.
  CPython 3.8–3.10 and PyPy are no longer supported, and published wheels move
  from the `cp38-abi3` tag to `cp311-abi3`.
- **Breaking (0.6.0):** CLI `--key-path` is now always a Chromium Windows
  `Local State` credential selector. It requires `--path`, is mutually exclusive
  with `--browser-id` and `--plaintext-only`, and no longer remains silently
  ignored on Unix or beside a Firefox database. Inapplicable combinations now
  fail with the typed direct-path diagnostic.
- **Breaking (0.6.0):** The npm packages now require Node.js 22 or newer and
  are tested on Node.js 22, 24, and 26. Node.js 18 and 20 are no longer
  supported. The Node-API v4 ABI target is unchanged.
- `browser_registry.json` is now the single browser discovery and credential
  source for named APIs, profile/report APIs, bindings, and CLI modes. Named
  functions keep their flat first-profile behavior through an explicit
  compatibility selection policy, while `CONFIG` remains available as a
  registry-derived public compatibility view.
- In the Python and Node bindings, `any_browser`/`anyBrowser`, Chromium
  `*_based` functions, and flat Firefox `firefox_based`/`firefoxBased`
  functions are deprecated for removal no earlier than 0.7. Their 0.6 runtime
  signatures and behavior remain unchanged; detailed Firefox functions remain
  supported in those bindings.
- Rust's `internet_explorer()` and `internet_explorer_based()` are deprecated
  for removal, not just superseded by a newer call shape: their ESE-format
  cookie database is read through an unmodified native C library with no
  process isolation, and containing that is not worth building now that the
  Internet Explorer browser app is discontinued (2022). Their 0.6 behavior is
  unchanged.

### Removed

- Removed the duplicate internal `config.json` + `common/paths.rs` discovery
  stack. No public browser function or configuration type was removed.

## [0.5.9] - 2026-08-15

### Added

- Structured browser, profile, and extraction-report APIs now reach Rust,
  Python, Node.js, and the CLI with matching status, issue, counter, and cookie
  provenance semantics.
- The private browser registry now exposes the maintained platform variants,
  including Cốc Cốc and Yandex on macOS, Cốc Cốc, DuckDuckGo, Yandex, and Octo
  Browser on Windows, and Cachy Browser on Linux. Legacy named selectors remain
  source compatible.
- Detailed extraction preserves Chromium partition keys and Firefox container
  identities without changing the legacy `Cookie` wire shape.

### Changed

- Browser discovery is installation- and profile-aware across Chromium, Gecko,
  Safari, and Internet Explorer sources. Active Chromium profiles are preferred
  without hiding other discovered profiles.
- Extraction failures now remain typed and visible through reports and legacy
  APIs instead of collapsing into successful empty results.

### Fixed

- WAL-mode cookie databases with no pending WAL are now read through the
  verified private DB+WAL snapshot path. Read-only extraction no longer creates
  `-wal`/`-shm` sidecars in a live profile and works when the source directory
  is genuinely read-only, without hiding WAL frames behind an unsafe immutable
  open.
- Node extraction now converts native worker panics and invalid JavaScript
  arguments into rejected Promises instead of aborting Node or throwing before
  callers can attach Promise handlers. JavaScript examples now consistently
  await the asynchronous extraction API.
- Firefox session recovery accepts the browser-produced root cookie layout,
  bounds raw and decompressed session files, retains failed candidates, and
  handles seconds and milliseconds without coupling session data to the SQLite
  schema version.
- Chromium and Firefox schema-aware decoding now preserves valid metadata while
  counting and reporting malformed rows. Chromium v24 host-bound values are
  verified before their digest prefix is stripped.
- Safari and Internet Explorer parsing now retains partial results, reports
  malformed pages or records, and preserves security and SameSite semantics.
- macOS Keychain and Linux Secret Service/KWallet failures are explicit; KDE 6
  is supported and successful passwords are not discarded by cleanup errors.

### Security

- Persistent Chromium and Mozilla domain filters now enforce exact-host and
  subdomain boundaries after their SQL candidate query. Explicitly empty
  filters and blank domain entries no longer expose the entire cookie store.
- Chromium key candidates remain zeroizing from derivation through final use,
  and profile extraction no longer multiplies ordinary heap copies of master
  keys.
- Windows App-Bound impersonation restores any pre-existing thread identity and
  treats restoration failure as fatal.
- Release workflows bind every published artifact to one reviewed tag commit,
  recheck that tag immediately before publication, and require the tagged
  commit to be part of `main` history.
- Pull-request revalidation builds untrusted code without write credentials and
  reports statuses from a separate trusted job bound to the exact reviewed
  head SHA.

## [0.5.8] - 2026-08-11

### Added

- Windows App-Bound (v20) cookie decryption for Chrome 133+: the
  ChaCha20-Poly1305 (flag 2) and CNG-wrapped AES-256-GCM (flag 3) key-wrapping
  schemes, ported from the `runassu/chrome_v20_decryption` reference.
- `firefox_profiles()` and `firefox_profile()` in the Rust API, which enumerate
  every Firefox profile holding a cookie database and read cookies from a
  specific one selected by name, directory name, or path.

### Changed

- Python extraction releases the GIL, and Node.js extraction functions now run
  as asynchronous tasks so cookie reads do not block their host runtimes.
- Domain filtering now has consistent matching behavior across browser
  backends, including mixed SQL filters.
- Extraction now returns an aggregate error when every requested browser fails,
  while retaining the individual browser failures for diagnosis. Linux keyring
  and D-Bus failures are also surfaced instead of silently discarded.

### Fixed

- SQLite-backed browsers now copy active `-wal` and `-shm` files with the main
  database, preventing recently committed cookies from disappearing while the
  browser is open.
- Internet Explorer cookies now report `secure` and `http_only` from the ESE
  `Flags` column instead of always `false`, so a Secure cookie is no longer
  extracted as one safe to replay over plain HTTP. Flags that cannot be read
  fail closed: an unrecognised cookie table is an error, and an individual
  cookie whose flags do not decode is skipped rather than reported as
  insecure. Their `same_site` is now `-1` (unspecified) rather than `0`, which
  had claimed `SameSite=None` for a store that records no SameSite attribute
  at all.
- Firefox `profiles.ini` resolution no longer returns whichever `[Install...]`
  section comes first in the file. A single unambiguous install still wins, but
  competing installs (a release and a nightly sharing one `profiles.ini`) are
  now broken by the `[ProfileN] Default=1` marker, and an install section
  without a `Default=` key falls through to that marker instead of resolving to
  an empty path.
- Firefox cookie discovery now falls through to secondary profiles when the
  default profile has no `cookies.sqlite`, instead of giving up.
- Firefox `profiles.ini` is parsed with escape processing disabled, so an
  `IsRelative=0` profile storing an absolute Windows path such as
  `C:\Users\me\Profiles\work` is no longer mangled into
  `C:UsersmeProfileswork`.
- Windows App-Bound key derivation now parses the key-blob framing header
  instead of slicing a fixed trailing window, so Chrome 133+'s 93-byte flag-3
  key layout is decoded correctly (its scheme flag was previously read from the
  middle of the blob, leaving flag 3 unsupported).
- The CLI now sends tracing and log output to stderr so redirected stdout
  remains a valid cookie export.
- Chromium discovery includes the modern `Network/Cookies` location on macOS
  and Linux, and valid unencrypted plaintext cookies are preserved.
- Malformed cookie rows, truncated binary data, and out-of-range timestamps no
  longer discard an entire database or panic. Safari expiry timestamps are
  decoded as 64-bit floating-point values, and CBC decryption continues trying
  candidate keys after an invalid UTF-8 result.
- Source builds no longer fail when `git` is unavailable, watch the repository's
  actual `HEAD` for rebuilds, and include the packaged Rust examples.

### Security

- SQLite domain filters are parameterized rather than interpolated into SQL.
- Windows App-Bound extraction restores SYSTEM impersonation and
  `SeDebugPrivilege` on every path, removes shadow-copy temporary directories,
  and only force-closes a browser when explicitly enabled.

## [0.5.7] - 2026-08-09

### Added

- A maintained fork published as `rookie-cookies` across crates.io, PyPI, and
  npm, with matching Rust, Python, Node.js, and CLI names.
- CPython 3.11–3.14 module tests and ABI3 wheel validation.
- Rust parser and helper tests, Python and Node.js module tests, CLI snapshot
  tests, and seeded Chrome/Firefox end-to-end coverage on Linux, macOS, and
  Windows.
- A release metadata validator and guarded first-release workflows for the
  Rust crate, Python wheels/source distribution, and five npm packages.
- Release, build, and maintained-fork documentation for downstream users such
  as `notebooklm-py`.

### Changed

- Browser extraction failures now emit per-browser warnings instead of being
  silently discarded.
- Python error handling uses `anyhow`, enabling current PyO3 and Python 3.13+
  builds.
- Node development, testing, and publication use npm consistently.
- Repository and package metadata now point to the maintained fork.

### Fixed

- Broken Rust doctests and CI coverage gaps.
- Python package version discovery with current Maturin releases.
- Chrome OS-crypt end-to-end setup on Linux, macOS, and Windows, including the
  Windows App-Bound Encryption path.
