# Testing rookie-cookies

The suite separates deterministic contracts, real-browser integration, and
installed release artifacts. A passing job should identify the exact path it
exercised; a missing encryption prerequisite must not be reported as crypto
coverage.

## Deterministic tests

```console
cargo test --workspace --all-targets
cargo test --workspace --doc
python3 -m unittest discover -s tests/e2e -p 'test_*.py' -v
python3 -m unittest discover -s tests/release -p 'test_*.py' -v
```

After building the Python extension locally, also run:

```console
python -m unittest discover -s tests/python -p 'test_*.py' -v
```

Documentation fenced samples are checked against shipped public exports:

```console
python3 scripts/check-doc-snippets.py
python3 -m unittest tests.release.test_check_doc_snippets -v
```

The lint workflow also enforces the authoritative-discovery boundary: the old
`config.json` and `common/paths.rs` files must stay absent, production code may
not add `paths::find_*` calls, and the packaged crate must contain
`browser_registry.json`.

A separate `cargo run -p xtask -- check-cfg-locations` step enforces platform
`cfg` containment: every `target_os` / `windows` / `unix` (etc.) `cfg` /
`cfg_attr` under `rookie-rs/src` must be listed in
`cfg-location-allowlist.toml`.

The CLI integration suite uses a generated Firefox database and covers JSON and
Netscape output, logs on stderr, errors, help/version output, profile discovery,
and paths containing spaces and Unicode. On Windows, the Rust Chrome e2e target
also generates a `v10` AES-GCM Cookies database and a `Local State` key protected
at runtime with the current user's DPAPI. That test is deterministic and does
not require Chrome.

Windows additionally compiles and tests the core crate without default features
so the legacy non-App-Bound branch cannot silently rot.

Node bindings are built once per OS on the minimum supported Node.js **22**
runtime, then tested without rebuilding on Node.js 22, 24, and 26.

## Real-browser tests

`.github/workflows/e2e.yml` seeds fake cookies from a loopback HTTP server. The
ordinary pull-request matrix is:

| Runner | Browser and crypto path | Surfaces |
| --- | --- | --- |
| Ubuntu 24.04 | Chrome with libsecret | Rust, Python, Node, CLI |
| Ubuntu 24.04 | Firefox | Rust, Python, Node, CLI, examples |
| macOS 15 | Chrome with Playwright's mock keychain | Rust, Python, Node, CLI |
| macOS 15 | Firefox | Rust, Python, Node, CLI |
| Windows 2025 | Chrome custom profile with legacy DPAPI `v10` | Rust, Python, Node, CLI |
| Windows 2025 | Firefox | Rust, Python, Node, CLI |

The Windows App-Bound canary is a separate main-push, scheduled, or explicitly
dispatched trusted-ref job. It launches the machine-wide Chrome installation
against the real default user-data directory without Playwright, CDP, or a
custom profile. Before extraction it requires all of the following:

- an elevated runner under the same user that launches Chrome;
- `Local State.os_crypt.app_bound_encrypted_key` with the `APPB` prefix;
- a seeded cookie whose encrypted value has the `v20` prefix;
- a copy of that real `v20` encrypted row staged under a new name in a synthetic
  WAL fixture, absent from its main-database-only copy and validated through a
  lock-free raw snapshot of the DB+WAL pair;
- explicit-path WAL extraction while Chrome is live, with Chrome remaining
  alive after each Rust, Python, Node, and CLI extraction;
- default Chrome profile/key discovery on all four surfaces after the canary
  closes Chrome gracefully through its main window.

The canary fails when a prerequisite is absent. It never uploads the disposable
profile, Cookies database, WAL, or `Local State`.

Cross-platform CLI checker:

```console
python3 tests/e2e/assert_cli_cookie.py path/to/cookies.sqlite
python3 tests/e2e/assert_cli_cookie.py path/to/Cookies \
  --key-path 'path/to/Local State'
python3 tests/e2e/assert_cli_cookie.py --browser chrome
```

CLI credential selectors (`--key-path`, `--browser-id`, and `--plaintext-only`)
require an explicit `--path` and are mutually exclusive. `--key-path` means a
Windows Chromium `Local State` file on every host.

Set `ROOKIE_E2E_CLI` to test a binary outside `target/release`. Override the
expected cookie with `ROOKIE_E2E_COOKIE_NAME` and `ROOKIE_E2E_COOKIE_VALUE`.

## Installed artifact smoke tests

`.github/workflows/artifact-smoke.yml` builds an immutable package set, uploads
it, downloads it in a separate job, and tests it from a clean consumer directory
outside the checkout. Each native lane exercises:

- the copied release CLI executable;
- a wheel installed into a fresh virtual environment with `pip --no-index`;
- the packed npm root and native-platform tarballs installed offline.

The native npm module is built on Node.js 22, release-shaped tarballs are
assembled with Node.js 24, and clean consumers install those same tarballs on
Node.js 22, 24, and 26.

Provenance records and independently verifies the source commit, target, runner,
exact package paths, byte length, and SHA-256 digest of every consumed artifact.

## Diagnosing failures

Real-browser jobs print the OS image, browser version, user identity, database
location, key prefix, and encrypted-value prefix without printing key material
or real cookies. Retry browser startup/readiness only; do not retry a failed
extraction assertion, because that would hide crypto or packaging regressions.
