# Changelog

All notable changes to this maintained fork are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
