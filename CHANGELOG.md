# Changelog

All notable changes to this maintained fork are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Node extraction now converts native worker panics and invalid JavaScript
  arguments into rejected Promises instead of aborting Node or throwing before
  callers can attach Promise handlers. JavaScript examples now consistently
  await the asynchronous extraction API.

### Security

- Persistent Chromium and Mozilla domain filters now enforce exact-host and
  subdomain boundaries after their SQL candidate query. Explicitly empty
  filters and blank domain entries no longer expose the entire cookie store.

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
