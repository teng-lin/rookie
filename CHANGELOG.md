# Changelog

All notable changes to this maintained fork are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Native linux-arm64 artifacts: PyPI manylinux aarch64 wheel, npm
  `rookie-cookies-linux-arm64-gnu`, and a CLI
  `aarch64-unknown-linux-gnu` binary, all built on `ubuntu-24.04-arm`.

### Removed

- PyPI wheels for linux i686, armv7, s390x, and ppc64le. Those arches have
  no desktop browser cookie store this project can honestly support.

### Changed

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
