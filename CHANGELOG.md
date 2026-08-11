# Changelog

All notable changes to this maintained fork are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Windows App-Bound (v20) cookie decryption for Chrome 133+: the
  ChaCha20-Poly1305 (flag 2) and CNG-wrapped AES-256-GCM (flag 3) key-wrapping
  schemes, ported from the `runassu/chrome_v20_decryption` reference.

### Fixed

- Internet Explorer cookies now report `secure` and `http_only` from the ESE
  `Flags` column instead of always `false`, so a Secure cookie is no longer
  extracted as one safe to replay over plain HTTP. Their `same_site` is now
  `-1` (unspecified) rather than `0`, which had claimed `SameSite=None` for a
  store that records no SameSite attribute at all.
- Windows App-Bound key derivation now parses the key-blob framing header
  instead of slicing a fixed trailing window, so Chrome 133+'s 93-byte flag-3
  key layout is decoded correctly (its scheme flag was previously read from the
  middle of the blob, leaving flag 3 unsupported).

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
