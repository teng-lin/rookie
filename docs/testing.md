# Testing rookie-cookies

The suite has three layers. A passing job should name the path it actually
exercised. A missing encryption prerequisite is a failed prerequisite, not
crypto coverage.

| Layer | What it proves | Where |
| --- | --- | --- |
| Deterministic | Contracts, fixtures, lint, public API, packaged consumers | `test-rust.yml` (`check` job), local `cargo test` |
| Real browsers | Seeded profiles plus Windows App-Bound **v20** | `e2e.yml` (Chrome/Firefox + App-Bound canary), `e2e-release.yml` (Edge/Chromium, silent-install catalog, release fixtures) |
| Installed artifacts | Shipped CLI, wheel, and npm tarballs in a clean directory | `artifact-smoke.yml` (main / nightly / manual; not PRs) |
| Assurance | Dependency/secret/code scanning, branch coverage, sanitizer-backed parser fuzzing | `security.yml`, `assurance.yml` |

CI has three lanes. A pull request is not the full product.

| Lane | Trigger | What runs |
| --- | --- | --- |
| **PR** | `pull_request`, push to `main` | One `check` job per OS (fmt/package/metadata/audit on Ubuntu; rust lint+test and public API on Linux, macOS, and Windows). Node **build+test** staggered (Ubuntu 22 / macOS 24 / Windows 26). Python **build+tests** staggered (Ubuntu 3.12 / macOS 3.13 / Windows 3.14). Real Ubuntu Chrome + Firefox gate every PR. Completeness check for `tests/e2e/browser_coverage.json` lives in the Ubuntu `check` job. |
| **Nightly** | Scheduled test/E2E workflows, plus manual dispatch | Full Node 3 OS × 22/24/26, full Python 3 OS × 3.11–3.14, FreeBSD VM, manylinux/Windows/macOS Intel wheels, sdist. `security.yml` runs dependency, secret, and code scanning; `assurance.yml` runs measured coverage and sanitizer-backed fuzzing. Real Chrome/Firefox (`e2e.yml`). The installer matrix in `e2e-release.yml` adds Chromium, Edge, Brave, Opera, Opera GX, Vivaldi, Yandex, LibreWolf, Zen, and Safari on their supported hosted images. App-Bound Chrome+Edge+Brave. Artifact smoke. **Not** the fixture matrix. |
| **Release** | `v*` tag, GitHub Release, `workflow_dispatch` on `e2e-release.yml`, or a PR labeled `e2e-release` | The hosted installer matrix again, plus engine fixtures for every `release_fixture` cell. A labeled PR stays opted in across later `synchronize` events. App-Bound Edge+Brave is the `e2e.yml` nightly / `multi_browser` dispatch, not this workflow. macOS Intel artifact smoke (schedule/manual). |

## Local commands

```console
cargo test --workspace --all-targets --locked
cargo test --workspace --doc --locked
cargo test -p rookie-cookies --no-default-features --all-targets --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo run -p xtask --locked -- check-cfg-locations
cargo run -p xtask --locked -- check-stage-boundary

python3 -m unittest discover -s tests/e2e -p 'test_*.py' -v
python3 -m unittest discover -s tests/release -p 'test_*.py' -v
python3 scripts/check-doc-snippets.py
python3 scripts/check-release.py
python3 scripts/check-coverage.py --report coverage.json
```

Generate the report consumed by the last command with the pinned nightly and
coverage tool used by CI:

```console
cargo install cargo-llvm-cov --version 0.9.0 --locked
cargo +nightly-2025-11-23 llvm-cov \
  --workspace --all-features --all-targets --branch \
  --json --output-path coverage.json
```

`coverage.toml` holds aggregate and critical-file floors. A floor is a ratchet:
raise it after sustained improvement; lowering it requires explicit review.

After `maturin develop --release --locked` in `bindings/python`:

```console
python -m unittest discover -s tests/python -p 'test_*.py' -v
python scripts/check-python-stubs.py --python "$(command -v python)"
```

### Python binding coverage

The workspace run above measures `bindings/python/src/*.rs` only through that
crate's own `#[test]`s, which reach roughly half of it: everything else is
behind the PyO3 boundary and runs only when Python calls it. One command
measures what `tests/python` actually reaches, on both sides of the boundary:

```console
python -m pip install maturin==1.14.1
python scripts/run-python-coverage.py --out-dir target/python-coverage
```

It instruments the extension with the pinned nightly, builds a wheel from the
instrumented objects, installs it into a throwaway venv, and runs the suite
once under `coverage.py` — so `native-coverage.json` (cargo-llvm-cov) and
`pure-coverage.json` (coverage.py) always describe the same execution. Both
are then held to `coverage.toml`'s `[python-binding-native]` and
`[python-binding-pure]` floors. Pass `--no-check` to write the reports without
enforcing them.

This command exports `ROOKIE_COOKIES_INSTRUMENTED=1` to the suite, and one
measurement stands down when it sees it.
`test_parallel_extractions_overlap_rather_than_queueing` still runs four
concurrent extractions and still asserts they all succeed, but skips its
wall-clock speedup bound: instrumentation replaces every basic block with a
shared atomic counter increment, so threads on one extraction path contend on
the same counters and real parallelism reads as ~1x. The bound keeps its full
strength in every uninstrumented lane, which is where a binding that held the
GIL or funnelled extractions through one mutex would be caught. Any other lane
that instruments the extension must export the same variable.

The floors are single values that must hold on Linux, macOS, and Windows, so
each sits at the lowest platform's observed value rounded down. Pull requests
run this on Ubuntu; the nightly schedule runs all three, because a
`#[cfg]`-gated entry point that exists on one platform cannot be seen by the
others.

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

**Every pull request** — one `check (${{ os }})` job per OS, plus a
standalone `msrv` job (`cargo check --workspace --all-targets --all-features
--locked` pinned to Rust 1.88.0 on Ubuntu) that runs unconditionally on every
trigger, not staggered by OS.

- **fmt**, Clippy (`-D warnings`), workspace tests, **and**
  `--no-default-features` so the non-`appbound` Windows branch cannot rot.
- **cargo-audit** against `security/audit-exceptions.toml` (blocking; Ubuntu).
- **Public API snapshots** (`scripts/check-public-api.py`) on Linux, macOS, and
  Windows.
- **Authoritative discovery:** `config.json` and `common/paths.rs` must stay
  gone; packaged crate must contain `browser_registry.json`.
- **cfg allowlist:** `cargo run -p xtask --locked -- check-cfg-locations`.
- **Stage boundary:** `cargo run -p xtask --locked -- check-stage-boundary` — listing types
  must have nowhere to put an extraction result (ADR 0005).
- **DTO schema + generated Python dataclasses** must match `report_core.rs`.
- **Release metadata** (`check-release.py`, platform contract, consumer
  harness coverage) and `tests/e2e/test_browser_coverage.py`.
- **Node:** native module **built and tested** on a staggered trio (Ubuntu 22,
  macOS 24, Windows 26) so a PR compiles on every supported Node line. Loader
  `index.js` / `index.d.ts` must match `patch-loader.js`.
- **Python:** `cp311-abi3` wheel built and `tests/python` run on Ubuntu 3.12,
  macOS 3.13, and Windows 3.14.

**Nightly only**

- **OSV-Scanner** recursively covers committed manifests and lockfiles and
  fails on a reported advisory; Gitleaks scans committed history; CodeQL
  analyzes Rust, Python, and JavaScript/TypeScript (`security.yml`).
- **Measured coverage** uses nightly branch instrumentation and enforces the
  checked-in floors in `coverage.toml` (`assurance.yml`).
- **Parser fuzzing** runs the three targets documented in `fuzz/README.md`
  under bounded libFuzzer sanitizer instrumentation (`assurance.yml`).
- Node: build+tests on the full 3 OS × 22/24/26 product.
- Python build+tests on the full 3 OS × 3.11–3.14 product.
- **FreeBSD VM:** Mozilla `from-path` works; Chromium SQLite is unsupported there
  (typed error). No `--allow-process-shutdown`.
- manylinux / Windows / macOS Intel wheel packaging jobs and the Python sdist.

On Windows, `cargo test` also generates a current-user **DPAPI `v10`** Cookies
+ `Local State` fixture. That is deterministic and does **not** require Chrome.

CLI snapshot tests use a generated Firefox database (JSON/Netscape, stderr
logs, errors, help/version, profiles, spaces/Unicode paths).

### Synthetic isolation corpus

`tests/isolation_corpus/` (top level, deliberately not under `tests/e2e/`) is
a hand-authored oracle for the isolation-safe send-selection semantics ADR
0006 defines: `corpus.json` names four synthetic stores (Chromium/Firefox,
isolated/plain) and a set of `SendContext` cases, each with an expected
selected set, header, omission counts, or a structured `incomplete_send_context`
error, plus a per-store `jar` verdict. `build_isolation_corpus.py` (stdlib
only) materializes the stores as real Chromium `Cookies`/Firefox
`cookies.sqlite` databases; `test_build_isolation_corpus.py` validates the
corpus shape and checks a fresh build against the committed Node base64
fixtures under `bindings/node/__test__/fixtures/`. It is **not** browser
evidence: it exercises the shared Rust selection algorithm against synthetic,
hand-computed rows, not a real browser's own cookie jar. Real-browser
partition/container coverage is the `e2e-depth.yml` lane described below.

```console
python3 -m unittest discover -s tests/isolation_corpus -p 'test_*.py' -v
```

## Real-browser E2E (PR subset / nightly / main)

`.github/workflows/e2e.yml` gates pull requests with real Ubuntu Chrome and
Firefox. Pushes to `main`, the nightly schedule, and `workflow_dispatch` also
run the macOS and Windows jobs. Every job starts a loopback cookie server,
seeds a disposable profile with the declarative cookie corpus, and requires
**Rust, Python, Node, and CLI** to match its independent manifest exactly. The
portable corpus covers all eight flat fields, host/domain and path collisions,
session/persistent cookies, SameSite variants, empty/large values, prefix
rules, expiration boundaries, update/delete behavior, and a second-host decoy
that the domain filter must exclude.

Each core job then launches a second disposable profile and leaves that browser
open while the same four surfaces read the browser-owned database. The runner
replaces one cookie, adds another, deletes a third, requires the complete
active-writer set (including no excess rows), probes browser liveness, closes
gracefully, and verifies that the closed snapshot matches the final open state.
Each checkpoint logs resolved profile/database paths, browser and seeder
process evidence, browser/schema versions, SQLite journal mode, and sidecar
presence. The elevated Windows App-Bound and shadow-copy jobs remain
trusted-ref-only.

| Runner | Browser and crypto | Surfaces |
| --- | --- | --- |
| Ubuntu 24.04 | Chrome + session **libsecret** | Rust, Python, Node, CLI |
| Ubuntu 24.04 | Firefox (Playwright-bundled) | Rust, Python, Node, CLI, examples, report-surface parity |
| macOS 15 | Chrome via **real Keychain** (`/usr/bin/security`). Playwright still writes `mock_password`; the job plants that value in an ephemeral Keychain item. There is no production mock-keychain fallback. | Rust, Python, Node, CLI |
| macOS 15 | Firefox | Rust, Python, Node, CLI |
| Windows 2025 | Chrome custom profile, **legacy DPAPI `v10`** (workspace user-data-dir; App-Bound is not expected) | Rust, Python, Node, CLI |
| Windows 2025 | Firefox | Rust, Python, Node, CLI |

These jobs pass explicit workspace-scoped profiles to Playwright and never
discover or inspect the operator’s real default profile. Exact corpus execution
is implemented by `tests/e2e/run_exact_corpus_e2e.py`; the open-store protocol
is implemented by `tests/e2e/run_active_writer_e2e.py` and the two
`seed_*_cookie.mjs` seeders. Its file-based commands make the same
ready/hold/mutate/probe/close contract portable across all three runner OSes.

Current CLI job shapes to use when reproducing an E2E assertion:

```console
rookie-cookies from-path path/to/cookies.sqlite --domains 127.0.0.1
rookie-cookies from-path path/to/Cookies \
  --local-state-path 'path/to/Local State' --domains 127.0.0.1
rookie-cookies read --browser chrome
```

`--local-state-path`, `--browser-id`, and `--plaintext-only` belong to the
`from-path` subcommand and are mutually exclusive. `--local-state-path` is a
Windows Chromium `Local State` file. The former top-level `--path` /
`--browser` grammar and `--key-path` spelling are no longer public CLI syntax.

The cross-platform `tests/e2e/assert_cli_cookie.py` wrapper is the CI assertion
driver. `ROOKIE_E2E_CLI` points it at a binary outside `target/release`.
`ROOKIE_E2E_COOKIE_NAME` / `ROOKIE_E2E_COOKIE_VALUE` override the expected
cookie.

## Partition, fixture provenance, and stress depth

`.github/workflows/e2e-depth.yml` supplies the representative deep lanes that
would be too expensive or too specialized to repeat across the full installed
browser matrix:

- Chromium creates two CHIPS rows with the same flat identity under distinct
  HTTPS top-level sites. Firefox creates the corresponding two dFPI identities.
  Rust, Python, Node, and CLI assert the browser-produced context strings and
  prove that `header(SendContext)` selects one partition without merging the
  other. Omitting the top-level selector must fail.
- The Firefox half also installs a checked-in test-only WebExtension into the
  disposable profile. The extension creates a real Multi-Account Container
  cookie; the runner reads its exact `originAttributes` and positive
  `userContextId` from `moz_cookies`, verifies detailed output on all four
  surfaces, and proves matching, mismatched, and missing container selectors.
- The nightly Chromium/Firefox stress jobs retain 320 cookies across eight
  registrable test domains in each of two independent Linux profiles,
  including same-name collisions. A macOS Chrome lane repeats the work through
  the real Keychain route. They keep the browser open through three
  add/update/delete rounds while a Set-Cookie loop advances the raw database
  write generation, launch concurrent extractor processes on every public
  surface, enforce the exact detailed manifest after every round, and compare
  the final closed snapshot. A locked rollback-journal copy must produce typed
  timeout and in-flight cancellation failures, then recover to the exact set
  after the lock is released.

Both runners fail unless `CI=true` and their marked disposable profiles are
below `RUNNER_TEMP`. They do not support local/default-profile discovery.

### HTTP, HTTPS, and public-site coverage

The installed browser-by-OS matrix seeds Chromium and Gecko products from
`http://127.0.0.1` and `http://localhost`. That keeps the broad product matrix
deterministic and proves host filtering, but loopback is a trustworthy-origin
exception and is not the HTTPS oracle. Safari is deliberately different: its
full corpus runs over local HTTPS with a one-day certificate trusted only in
the disposable hosted VM, because Safari rejects `Secure` cookies delivered
over loopback HTTP. The runner refuses this trust operation outside a fresh
GitHub-hosted account and a scratch path below `RUNNER_TEMP`.

HTTPS is exercised independently by the live depth lanes. The partition runner
uses a generated certificate and three named local sites
(`top.rookie-a.test`, `other.rookie-c.test`, and `third.rookie-b.test`) to
produce Secure/SameSite=None CHIPS and dFPI cookies. It asserts Chromium
`source_scheme=2`, the real source port, cross-site ancestry, two top-frame
keys, Firefox partition keys, and send-time isolation on Rust, Python, Node,
and CLI. The 320-cookie active-writer stress lane also uses named local HTTPS
origins. Thus scheme/context depth and browser-product breadth are orthogonal
contracts. Safari's HTTPS corpus additionally proves the product-specific
cookie-acceptance boundary; it does not replace the named-site context lane.

The suite does not seed arbitrary public websites. Extraction never makes an
origin request, so a public host would not enter a distinct decoder or crypto
path; it would add DNS, certificate, consent, rate-limit, and third-party state
failures while making the expected cookie set uncontrollable. Real browser
schema drift is covered instead by disposable browser-produced profiles and
the sanitized, versioned fixture-capture workflow.

`.github/workflows/capture-browser-cookie-fixtures.yml` is manual-only and has
read-only repository permission. It launches a requested Playwright browser in
a marked temporary profile, sanitizes its cookie database down to the known
corpus identities with secure deletion and `VACUUM`, and uploads only the
sanitized database, expected manifest, and provenance JSON. The artifact never
contains a complete profile, `Local State`, credential material, history,
cache, or telemetry. The workflow accepts a Playwright version so current and
previous redistributable schema generations can be captured and reviewed
without automatically changing committed fixtures.

## Windows App-Bound v20 (Chrome, Edge, Brave)

Hosted **v20 / App-Bound** coverage is the `windows-chrome-appbound` job in
`e2e.yml` (`e2e windows × {chrome,edge,brave}` with the
`App-Bound v20 staged-WAL recovery + liveness` suffix). It is
**not** a pull-request job.

| When | Browsers |
| --- | --- |
| Push to `main` | **Chrome** only |
| Nightly schedule, or `workflow_dispatch` with **multi_browser** | **Chrome, Edge, and Brave** |
| `workflow_dispatch` with **appbound_only** | Canary only (skips the Chrome/Firefox matrix) |
| Pull requests | **Never** (elevated, default-profile, trusted-ref) |

`e2e.yml` does not trigger on `v*` tags or GitHub Releases. The job condition
mentions those refs, but the only ways to get Edge/Brave App-Bound in CI are
the nightly schedule or an explicit `workflow_dispatch` with **multi_browser**.

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
- explicit-path staged-WAL extraction while the browser is live — Chrome /
  Edge / Brave must stay alive while Rust, Python, Node, and CLI read the
  separately staged fixture. This proves recovery and browser liveness, not
  active-writer behavior against the browser-owned database;
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

## Browser coverage matrix

`tests/e2e/browser_coverage.json` is 1:1 with `rookie-rs/browser_registry.json`.
A new registry browser missing from that file fails PR metadata tests
(`tests/e2e/test_browser_coverage.py`), and the matrix table below must stay
in lockstep with those lanes. Every registered (OS, browser) pair has
exactly one lane.

The manifest's `depth_profile` is a second, independent contract. It classifies
each cell's registry identity, browser launch, explicit-path, detailed,
discovery, recommended-read, crypto, exact-set, active-writer, and partitioned
coverage as `none`, `fixture`, or `live`. Hosted and fixture runners record a
capability only after its assertion succeeds and compare that record with the
declared profile. A new claim therefore fails until its harness assertion
exists and passes.

`cookie_context_fields` separately classifies all nine `CookieContext` fields
as `live`, `fixture_only`, or `non_persistable`, with engine applicability and
a rationale. A detailed-output smoke test therefore cannot be mistaken for
semantic CHIPS/container coverage. CHIPS keys/ancestry/source metadata and
Firefox dFPI origin attributes/partition keys and Multi-Account Container IDs
are live; private-browsing IDs are non-persistable.

`convenience_functions` maps each registry browser onto the per-browser
convenience export the Python and Node bindings publish for it — its name in
each binding, which assert-script family dispatches it, the platforms it
exists on, and any alternate `ROOKIE_E2E_TARGET_BROWSER` spellings. The
assert scripts dispatch from this table rather than a hardcoded list, so a
browser cannot gain a convenience wrapper without also gaining an exact-corpus
assertion. `convenience_function_exceptions` carries the other direction:
every registry browser with no such assertion, each with a concrete reason —
either the binding exports no wrapper, or the browser has only fixture cells.
The two sets partition the registry, and nothing may appear in both.

`representative_depth_lanes` records the exact-corpus, active-writer,
partition, stress, and manual-capture runners independently of the broad
per-browser cells. Metadata tests require each claimed workflow and runner to
exist, constrain its engine/platform/surface vocabulary, and require the core
Chrome/Firefox lanes to cover all three desktop OSes and all four public
surfaces. Each representative runner emits a machine-readable depth receipt
only after its declared assertions succeed; a missing or excess capability or
surface fails the job.

| Lane | What it proves | When it runs |
| --- | --- | --- |
| **hosted** (`nightly_hosted`) | Real browser, seed the complete portable corpus, and require exact filtered/unfiltered/detailed equality on Rust / Python / Node / CLI | Chrome/Firefox in `e2e.yml` (push to `main`, nightly, `workflow_dispatch`). Extra products in `e2e-release.yml` (nightly, `v*` tags, GitHub Releases, `workflow_dispatch`, or a PR labeled `e2e-release`). |
| **fixture** (`release_fixture`) | Deterministic full portable corpus, exact filtered/unfiltered/detailed equality, registry discovery, and `supported_browsers()` identity coverage for feasible Chromium/Gecko rows. **Does not launch a browser or claim platform crypto.** | `e2e-release.yml` `fixtures` job on `v*` tags, GitHub Releases, `workflow_dispatch`, or a labeled PR. **Skipped on the nightly schedule.** |
| **manual** | Operator-owned fallback | No current registry cell uses this lane. |

`—` means the browser is not registered on that OS. This table is the live
registry, not the shorter README support grid (Avast, Vought, DC, QQ, Sogou,
360, and 360X are Windows-only registry ids).

| Browser | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Arc | — | fixture | fixture |
| Avast Secure Browser | — | — | fixture |
| Brave | hosted | hosted | hosted |
| Browser from Vought | — | — | fixture |
| Cachy Browser | fixture | — | — |
| Chrome | hosted | hosted | hosted |
| Chromium | hosted | hosted | hosted |
| Cốc Cốc | — | fixture | fixture |
| DC Browser | — | — | fixture |
| DuckDuckGo | — | — | fixture |
| Edge | hosted | hosted | hosted |
| Firefox | hosted | hosted | hosted |
| Internet Explorer | — | — | fixture |
| LibreWolf | hosted | hosted | hosted |
| Octo Browser | — | — | fixture |
| Opera | hosted | hosted | hosted |
| Opera GX | — | hosted | hosted |
| QQ Browser | — | — | fixture |
| Safari | — | hosted | — |
| Sogou Explorer | — | — | fixture |
| 360 Browser | — | — | fixture |
| 360X Browser | — | — | fixture |
| Vivaldi | hosted | hosted | hosted |
| Yandex Browser | — | hosted | hosted |
| Zen Browser | hosted | hosted | hosted |

### How hosted cells actually run

Every installed Chromium-family and Gecko-family cell below uses a newly
created registry-correct profile below an isolated home. It persists the full
portable corpus: 19 total Chromium/Safari rows or 20 total Gecko rows, each
including one second-host decoy. The domain-filtered primary-origin sets are
therefore 18 Chromium/Safari rows or 19 Gecko rows, and all four public surfaces
compare the applicable exact set.
Some products, notably Yandex, preload vendor-domain cookies even in a new
profile; the manifest records their count but excludes those unowned domains
from value equality. Missing, duplicate, or excess rows on `127.0.0.1` or
`localhost` still fail. Safari uses the same 19-row portable contract. Because
Safari cannot select an arbitrary persistent profile directory, that lane
refuses to run anywhere except a fresh GitHub-hosted account and keeps all
harness scratch state below `RUNNER_TEMP`; it must never inspect a developer's
normal Safari profile.

| Cells | Workflow / job | How the browser gets on the runner |
| --- | --- | --- |
| Chrome × Linux / macOS / Windows | `e2e.yml` | Image Chrome, custom profile. Crypto: Ubuntu libsecret, macOS real Keychain, Windows legacy DPAPI `v10`. |
| Firefox × Linux / macOS / Windows | `e2e.yml` | Playwright-bundled Firefox. |
| Chromium × Linux / macOS / Windows | `e2e-release.yml` `hosted-claimed` | Official `npx playwright install chromium` distribution, then native DevTools launch. |
| Edge × Linux / macOS / Windows | `e2e-release.yml` `hosted-claimed` | Runner image Edge; official `npx playwright install msedge` fallback; native DevTools launch. |
| Brave, Opera, Vivaldi, LibreWolf, Zen on each OS they support; Opera GX and Yandex on macOS and Windows | `e2e-release.yml` `hosted-claimed` | Silent-install catalog: `tests/e2e/install_claimed_browser.py`; native browser launch. Chromium forks publish an explicit DevTools port, then a post-launch CDP client seeds the persistent default context instead of using Playwright's persistent-context launch pipe. |
| Safari × macOS | `e2e-release.yml` `hosted-claimed` | Image Safari normal application store in the one-use hosted account; 19-row exact BinaryCookies extraction. SafariDriver is deliberately not used because Apple isolates and destroys its automation-session storage. |

Chrome and Firefox stay outside that install catalog because `e2e.yml` owns
them. Playwright remains a distribution mechanism for Chromium and a documented
Edge-install fallback; arbitrary branded executables are not controlled through
Playwright. The native launcher polls the cookie database, so a browser that
crashes after persisting the seed can still prove extraction without hiding a
failed extraction assertion.

Arc on macOS/Windows and Windows DuckDuckGo stay on **fixture** because their
packaged/custom application startup does not expose an unattended profile +
DevTools path on hosted runners. Cachy is a deprecated Gecko fork. Everything
else on fixture has no maintained silent installer for GitHub runners (Cốc Cốc,
Avast, QQ, Sogou, 360, 360X, Octo, Vought, DC Browser). Internet Explorer is a
storage-format constraint: current hosted images expose only Edge IE mode, and
that mode does not persist the legacy `CookieEntryEx` ESE format supported by
the deprecated decoder.

The fixture exceptions are deliberate and machine-checked in
`browser_coverage.json`:

| Browser cells | Why a real hosted browser is not claimed |
| --- | --- |
| Arc on macOS | Its custom application startup has no stable unattended profile + DevTools contract. |
| Arc on Windows | The MSIX package is application-activated, not a flag-controllable browser executable. |
| DuckDuckGo on Windows | The MSIX app owns an embedded WebView profile and exposes no custom-user-data browser CLI. |
| Internet Explorer on Windows | Current hosted images expose only Edge IE mode, which cannot produce the supported legacy `CookieEntryEx` ESE store. |
| Cachy on Linux | The browser is deprecated and has no maintained release channel. |
| Cốc Cốc on macOS/Windows; Avast on Windows | No maintained silent package-manager installer is available on the hosted images. |
| Octo on Windows | Commercial account and anti-detect profile provisioning are operator-owned. |
| QQ, Sogou, 360, 360X, Vought, DC on Windows | No stable unattended vendor or package-manager installer is available to the runner. |

### Fixtures

`tests/e2e/run_claimed_browser_fixtures.py` on Ubuntu, macOS, and Windows:

- every claimed id on that OS must appear in `supported_browsers()`;
- feasible fixture-lane Chromium and Gecko ids get a registry-correct root
  below a temporary, isolated home;
- each such id receives the same declarative portable final state as the live
  lane: 19 total / 18 filtered Chromium rows or 20 total / 19 filtered Gecko
  rows, including attribute, path-collision, value, expiry, update/delete, and
  second-host decoy cases;
- filtered, unfiltered, and detailed Python output must equal the complete
  manifest; missing, duplicate, excess, or attribute-mismatched rows fail;
- discovery must identify the exact generated profile and source path;
- Chromium fixtures exercise plaintext explicit-path and detailed reads;
- Gecko fixtures additionally exercise a profile-scoped recommended `read`;
- Windows extracts one current-user DPAPI fixture once (no per-id `browser_id`);
- no generated discovery fixture claims a real platform crypto path;
- deprecated Internet Explorer remains registry/format coverage only because
  current hosted Windows cannot produce the legacy ESE store its decoder reads.

The live hosted Chromium/Gecko harness uses the same registry-root discipline:
it launches the browser only against a profile below an isolated CI home, then
asserts explicit-path detailed output, discovered browser/profile/source
identity, and profile-scoped recommended reads. Explicit-path coverage remains
because it is a separate supported contract.

### Native hosted constraints

| Browser | Runner constraint |
| --- | --- | --- |
| Safari | The hosted canary opens the normal Safari app because SafariDriver uses private-like isolated storage and destroys it at session teardown. GitHub's macOS image build preapproves `kTCCServiceSystemPolicyAllFiles` for `/bin/bash` and its runner launch scripts, plus AppleEvents from the job shell/agent to Safari ([runner image TCC configuration](https://github.com/actions/runner-images/blob/main/images/macos/scripts/build/configure-tccdb-macos.sh)). The harness verifies the `Cookies.binarycookies` signature and treats any TCC `PermissionError` as an immediate prerequisite failure. |

The native-engine job is not an automatic pull-request check. Applying the
`e2e-release` label opts a PR into the full matrix and later pushes keep running
it. The `manual` coverage lane remains available for future registry additions,
but currently has no cells.

## Installed artifact smoke

`.github/workflows/artifact-smoke.yml` (main / schedule / dispatch). Not a
pull-request job.

| Lane | When |
| --- | --- |
| Ubuntu x64, Ubuntu ARM64, Windows x64 (`--features appbound` on the CLI), macOS ARM64 | push to `main`, nightly-adjacent schedule, manual |
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
