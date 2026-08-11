# Testing rookie-cookies

The test suite separates deterministic contracts, real-browser integration,
and installed release artifacts. A passing job should identify the exact path
it exercised; a missing encryption prerequisite must not be reported as crypto
coverage.

## Deterministic tests

Run the Rust workspace and CLI contract tests with:

```console
cargo test --workspace --all-targets
cargo test --workspace --doc
python3 -m unittest tests/e2e/test_assert_cli_cookie.py -v
```

The CLI integration suite uses a generated Firefox database and covers JSON and
Netscape output, logs on stderr, errors, help/version output, profile discovery,
and paths containing spaces and Unicode. On Windows, the Rust Chrome e2e target
also generates a `v10` AES-GCM Cookies database and a `Local State` key protected
at runtime with the current user's DPAPI. This test is deterministic and does
not require Chrome.

Windows additionally compiles and tests the core crate without default features
so the legacy non-App-Bound branch cannot silently rot.

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

The Windows App-Bound canary is a separate trusted-main, scheduled, or manual
job. It launches the machine-wide Chrome installation directly against the
real default user-data directory without Playwright, CDP, or a custom profile.
Before extraction it requires all of the following:

- an elevated runner under the same user that launches Chrome;
- `Local State.os_crypt.app_bound_encrypted_key` with the `APPB` prefix;
- a seeded cookie whose encrypted value has the `v20` prefix;
- a second fake cookie committed to a live, non-empty Cookies WAL;
- Chrome remaining alive after each Rust, Python, Node, and CLI extraction.

The canary fails when a prerequisite is absent. It never uploads the disposable
profile, Cookies database, WAL, or `Local State`.

The cross-platform CLI checker can be run directly:

```console
python3 tests/e2e/assert_cli_cookie.py path/to/cookies.sqlite
python3 tests/e2e/assert_cli_cookie.py path/to/Cookies \
  --key-path 'path/to/Local State'
```

Set `ROOKIE_E2E_CLI` to test a binary outside `target/release`. The expected
cookie can be changed with `ROOKIE_E2E_COOKIE_NAME` and
`ROOKIE_E2E_COOKIE_VALUE`.

## Installed artifact smoke tests

`.github/workflows/artifact-smoke.yml` builds an immutable package set, uploads
it, downloads it in a separate job, and tests it from a clean consumer directory
outside the checkout. Each native lane exercises:

- the copied release CLI executable;
- a wheel installed into a fresh virtual environment with `pip --no-index`;
- the packed npm root and native-platform tarballs installed offline.

Pull requests cover Ubuntu x64, Windows x64, and macOS ARM64. The scheduled and
manual matrix also runs the shipped macOS Intel artifacts on a native Intel
runner. Provenance records the source commit, target, runner, byte length, and
SHA-256 digest of every consumed artifact.

## Diagnosing failures

Real-browser jobs print the OS image, browser version, user identity, database
location, key prefix, and encrypted-value prefix without printing key material
or real cookies. Retry browser startup/readiness only; do not retry a failed
extraction assertion, because that would hide crypto or packaging regressions.
