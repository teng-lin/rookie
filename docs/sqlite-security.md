# Bundled SQLite security inventory

`rookie-cookies` deliberately enables rusqlite's `bundled` feature. Release
artifacts therefore ship the SQLite amalgamation selected by the locked
`libsqlite3-sys` dependency rather than the target host's SQLite library.

Release operators should re-check this inventory as part of the steps in
[releasing.md](releasing.md).

## Current inventory

| Component | Locked version | Security-relevant payload |
|---|---:|---|
| `rusqlite` | 0.40.2 | Enables `libsqlite3-sys/bundled` and integer conversion support; default features disabled |
| `libsqlite3-sys` | 0.38.2 | SQLite 3.53.2, source ID `d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24` |

This replaces `rusqlite` 0.31.0 / `libsqlite3-sys` 0.28.0, which bundled
SQLite 3.45.0. `cargo audit` reported no known RustSec vulnerability in either
the pre-upgrade or updated lockfile when checked against advisory database
commit `69f93e1d081d8b6fbee010e48f0b5e0d13661415` (updated 2026-08-12).
The upgrade is nevertheless preferred to accepting indefinite exposure to an
unmanaged native parser version.

The published library directly constrains both `rusqlite` 0.40.2 and
`libsqlite3-sys` 0.38.2 exactly. The rusqlite requirement is repeated in CLI
fixture tests and the standalone direct-path consumer. This prevents a
consumer's fresh resolver from silently selecting a different bundled SQLite
payload than the one audited here. Default features are disabled to preserve
the previous native-only dependency set and avoid adding the optional
WebAssembly backend to native release dependency graphs. `fallible_uint`
retains the unsigned-integer fixture conversions supported by the previous
release.

## Maintenance policy

The maintainers are the security owner. They must re-check this inventory:

- before each release;
- when RustSec, SQLite, or rusqlite publishes a security notice; and
- at least every 90 days, with the next review due 2026-11-13.

The review first changes the exact `rusqlite` and `libsqlite3-sys` requirements
in `rookie-rs/Cargo.toml` (and the fixture-only rusqlite requirements in
`cli/Cargo.toml` and `tests/direct_path_consumer/Cargo.toml`). It then runs
`cargo update -p rusqlite --precise <version>` and
`cargo update -p libsqlite3-sys --precise <version>`, verifies both
`sqlite3_libversion()` and `sqlite3_sourceid()` against the selected
amalgamation, updates the expected SQLite version and full source ID in
`scripts/check-packaged-rust-consumer.py`, runs `cargo audit` and
`python3 scripts/check-packaged-rust-consumer.py`, and executes the SQLite
snapshot and extraction test suites. It updates the table and review date in
this document in the same commit as `Cargo.lock`.

A known advisory may be deferred only with a documented exploitability
assessment, named owner, compensating controls, and an expiry no more than 90
days away. Expired exceptions block a release. Unknown or unreviewed bundled
versions are not accepted release inputs.

Last reviewed: 2026-08-15.
