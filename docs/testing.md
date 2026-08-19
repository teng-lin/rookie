# Testing rookie-cookies

The suite has three layers. A passing job should name the path it actually
exercised. A missing encryption prerequisite is a failed prerequisite, not
crypto coverage.

| Layer | What it proves | Where |
| --- | --- | --- |
| Deterministic | Contracts, fixtures, lint, public API, packaged consumers | `test-rust.yml` (`check` job), local `cargo test` |
| Real browsers | Seeded profiles plus Windows App-Bound **v20** | `e2e.yml` (Chrome/Firefox), `e2e-release.yml` (Edge/Chromium/Brave nightly + claimed fixtures on release) |
| Installed artifacts | Shipped CLI, wheel, and npm tarballs in a clean directory | `artifact-smoke.yml` (main / nightly / manual; not PRs) |

CI has three lanes. A pull request is not the full product.

| Lane | Trigger | What runs |
| --- | --- | --- |
| **PR** | `pull_request`, push to `main` | One `check` job per OS (fmt/package/metadata/audit on Ubuntu; rust lint+test and public API on Linux, macOS, and Windows). Node **build+test** staggered (Ubuntu 22 / macOS 24 / Windows 26). Python **build+tests** staggered (Ubuntu 3.12 / macOS 3.13 / Windows 3.14). Completeness check for `tests/e2e/browser_coverage.json` lives in the Ubuntu `check` job. |
| **Nightly** | `test-rust.yml` / `e2e.yml` / `e2e-release.yml` schedule, or `workflow_dispatch` suite=nightly | Full Node 3 OS × 22/24/26, full Python 3 OS × 3.11–3.14, FreeBSD VM, manylinux/Windows/macOS Intel wheels, sdist, Chrome/Firefox/Edge/Chromium e2e, plus installed Brave/Opera/Opera GX/LibreWolf/Zen when the installer yields a launchable browser we can seed. Artifact smoke. |
| **Release** | `v*` tag, GitHub Release, or `workflow_dispatch` on `e2e-release.yml` | Nightly hosted browsers again, plus engine fixtures for every other claimed id. App-Bound Chrome+Edge+Brave. macOS Intel artifact smoke (schedule/manual). Safari and Internet Explorer stay **manual** (FDA / ESE). |

## Local commands

```console
cargo test --workspace --all-targets --locked
cargo test --workspace --doc --locked
cargo test -p rookie-cookies --no-default-features --all-targets --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo run -p xtask --locked -- check-cfg-locations

python3 -m unittest discover -s tests/e2e -p 'test_*.py' -v
python3 -m unittest discover -s tests/release -p 'test_*.py' -v
python3 scripts/check-doc-snippets.py
python3 scripts/check-release.py
```

After `maturin develop --release --locked` in `bindings/python`:

```console
python -m unittest discover -s tests/python -p 'test_*.py' -v
```

After `npm ci --omit=optional && npm run build` in `bindings/node`
(omit published platform prebuilds so they cannot shadow the local addon):

```console
npm test
npm run typecheck
```

Ignored real-browser Rust tests (`rookie-rs/tests/e2e_chrome.rs`,
`e2e_firefox.rs`) only run when CI (or you) seeds a profile and passes
`--ignored`. Do not treat a local `cargo test` as Chrome/Firefox coverage.

## Deterministic CI

`.github/workflows/test-rust.yml` runs on every pull request and on push to
`main`. The **nightly** schedule (or `workflow_dispatch` with suite `nightly`)
expands the language matrix.

**Every pull request** — one `check (${{ os }})` job per OS.

- **fmt**, Clippy (`-D warnings`), workspace tests, **and**
  `--no-default-features` so the non-`appbound` Windows branch cannot rot.
- **cargo-audit** against `security/audit-exceptions.toml` (blocking; Ubuntu).
- **Public API snapshots** (`scripts/check-public-api.py`) on Linux, macOS, and
  Windows.
- **Authoritative discovery:** `config.json` and `common/paths.rs` must stay
  gone; packaged crate must contain `browser_registry.json`.
- **cfg allowlist:** `cargo run -p xtask -- check-cfg-locations`.
- **DTO schema + generated Python dataclasses** must match `report_core.rs`.
- **Release metadata** (`check-release.py`, platform contract, consumer
  harness coverage) and `tests/e2e/test_browser_coverage.py`.
- **Node:** native module **built and tested** on a staggered trio (Ubuntu 22,
  macOS 24, Windows 26) so a PR compiles on every supported Node line. Loader
  `index.js` / `index.d.ts` must match `patch-loader.js`.
- **Python:** `cp311-abi3` wheel built and `tests/python` run on Ubuntu 3.12,
  macOS 3.13, and Windows 3.14.

**Nightly only**

- Node: addon built on **22** on all three OSes, then tests on the full
  3 OS × 22/24/26 product (proves a 22-built addon loads on 24 and 26).
- Python build+tests on the full 3 OS × 3.11–3.14 product.
- **FreeBSD VM:** Mozilla `--path` works; Chromium SQLite is unsupported there
  (typed error). No `--allow-process-shutdown`.
- manylinux / Windows / macOS Intel wheel packaging jobs and the Python sdist.

On Windows, `cargo test` also generates a current-user **DPAPI `v10`** Cookies
+ `Local State` fixture. That is deterministic and does **not** require Chrome.

CLI snapshot tests use a generated Firefox database (JSON/Netscape, stderr
logs, errors, help/version, profiles, spaces/Unicode paths).

## Real-browser E2E (nightly / main)

`.github/workflows/e2e.yml` is **not** a pull-request job. It runs on push to
`main`, the nightly schedule, and `workflow_dispatch`. It starts a loopback
cookie server, seeds a disposable profile, then asserts the same cookie
through **Rust, Python, Node, and CLI**.

| Runner | Browser and crypto | Surfaces |
| --- | --- | --- |
| Ubuntu 24.04 | Chrome + session **libsecret** | Rust, Python, Node, CLI |
| Ubuntu 24.04 | Firefox (Playwright-bundled) | Rust, Python, Node, CLI, examples, report-surface parity |
| macOS 15 | Chrome via **real Keychain** (`/usr/bin/security`). Playwright still writes `mock_password`; the job plants that value in an ephemeral Keychain item. There is no production mock-keychain fallback. | Rust, Python, Node, CLI |
| macOS 15 | Firefox | Rust, Python, Node, CLI |
| Windows 2025 | Chrome custom profile, **legacy DPAPI `v10`** (workspace user-data-dir; App-Bound is not expected) | Rust, Python, Node, CLI |
| Windows 2025 | Firefox | Rust, Python, Node, CLI |

These jobs never inspect the operator’s real default profile.

CLI checker (same contract as CI):

```console
python3 tests/e2e/assert_cli_cookie.py path/to/cookies.sqlite
python3 tests/e2e/assert_cli_cookie.py path/to/Cookies \
  --key-path 'path/to/Local State'
python3 tests/e2e/assert_cli_cookie.py --browser chrome
```

`--key-path`, `--browser-id`, and `--plaintext-only` require `--path` and are
mutually exclusive. `--key-path` is always a Windows Chromium `Local State`
file.

`ROOKIE_E2E_CLI` points at a binary outside `target/release`.
`ROOKIE_E2E_COOKIE_NAME` / `ROOKIE_E2E_COOKIE_VALUE` override the expected
cookie.

## Windows App-Bound v20 (Chrome, Edge, Brave)

Hosted **v20 / App-Bound** coverage is the `windows-chrome-appbound` job in
`e2e.yml` (`e2e windows × {chrome,edge,brave} (App-Bound v20 canary)`). It is
**not** a pull-request job.

| When | Browsers |
| --- | --- |
| Push to `main` | **Chrome** only |
| Nightly schedule, `v*` tag / release, or `workflow_dispatch` with **multi_browser** | **Chrome, Edge, and Brave** |
| `workflow_dispatch` with **appbound_only** | Canary only (skips the Chrome/Firefox matrix) |
| Pull requests | **Never** (elevated, default-profile, trusted-ref) |

Chrome and Edge come from the `windows-2025` image. Brave is installed
machine-wide in the job (winget / Chocolatey / standalone). **Cốc Cốc and
Avast** can decrypt App-Bound v20 in the library (COM injection, SYSTEM
impersonation fallback) and the canary script accepts them, but they are
**not** in the hosted matrix.

The canary launches the **machine-wide** browser against the **real default**
user-data directory. No Playwright, CDP, or custom profile. Driver:
`tests/e2e/run_windows_appbound_canary.ps1`.

It fails closed unless all of this holds:

- runner process is elevated as the same user that starts the browser;
- browser was not already running, and the default profile has no Cookies DB
  yet;
- `Local State.os_crypt.app_bound_encrypted_key` has the `APPB` prefix;
- the seeded cookie’s `encrypted_value` has the **`v20`** prefix;
- a copy of that v20 row is staged under a new name in a synthetic WAL,
  absent from a main-database-only copy, and checked through a lock-free
  DB+WAL snapshot;
- explicit-path WAL extraction while the browser is live — Chrome / Edge /
  Brave must stay alive through Rust, Python, Node, and CLI;
- after a graceful main-window close, default profile/key discovery works on
  all four surfaces.

Missing prerequisites fail the job. The canary never uploads the profile,
Cookies, WAL, or `Local State`.

To re-run locally on an authorized Windows host you control, set
`ROOKIE_E2E_TARGET_BROWSER` to `chrome`, `edge`, or `brave` and invoke
`tests/e2e/run_windows_appbound_canary.ps1` after building the four surfaces
the same way the workflow does (`maturin develop --locked`,
`cargo build -p rookie-cookies-cli --release --locked`, Node
`npm ci --omit=optional && npm run build`).

## Claimed-browser E2E (release / manual)

`.github/workflows/e2e-release.yml` covers every cell in
`tests/e2e/browser_coverage.json`, which must stay 1:1 with
`rookie-rs/browser_registry.json`. A new registry browser that is missing
from that file fails PR metadata tests.

| Lane in the matrix | What it is |
| --- | --- |
| `nightly_hosted` | Image or silent-install real browsers. Catalog: `tests/e2e/install_claimed_browser.py`. |
| `release_fixture` | No silent installer on GitHub runners (Cachy — deprecated; Cốc Cốc, Avast, QQ, Sogou, 360, Octo, Vought, DC Browser). Engine fixture + `supported_browsers()`. |
| `manual` | Safari (Full Disk Access) and Internet Explorer (ESE). Not GitHub-hosted. |

`e2e-release.yml` runs extra hosted browsers on the nightly schedule. The fixture matrix is tag / GitHub Release / `workflow_dispatch` only. It is never a required pull-request check.

## Installed artifact smoke

`.github/workflows/artifact-smoke.yml` (main / schedule / dispatch). Not a
pull-request job.

| Lane | When |
| --- | --- |
| Ubuntu x64, Windows x64 (`--features appbound` on the CLI), macOS ARM64 | push to `main`, nightly-adjacent schedule, manual |
| macOS Intel | schedule / manual only |

Build once, upload, download in a clean consumer directory, then install:

- the copied release CLI;
- the wheel with `pip --no-index`;
- npm root + native-platform tarballs offline.

Node native module is built on **22**; tarballs assembled on **24**; consumers
load them on **22 / 24 / 26**. Provenance records commit, runner, paths,
length, and SHA-256. Windows also decrypts a generated current-user DPAPI
fixture through the installed CLI, wheel, and npm packages.

## Diagnosing failures

Real-browser jobs print OS image, browser version, user identity, database
path, key prefix, and encrypted-value prefix. They do **not** print key
material or real cookie values.

Retry browser startup/readiness only. Do not retry a failed extraction
assertion — that hides crypto and packaging regressions.

If the App-Bound canary is red, check which **matrix.browser** failed (Chrome
vs Edge vs Brave) before treating it as a generic Windows problem. A green
legacy DPAPI `v10` job does not imply v20 works.
