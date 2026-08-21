# Codebase evaluation — 2026-08-21

## Executive assessment

**Overall: 7.5 / 10.** The codebase is well designed, unusually well documented,
and backed by a broad multi-platform test strategy. It is not release-ready at
the reviewed commit, however: the npm release workflow has a deterministic
packaging failure and omits an advertised Linux ARM64 package, while the
repository's required Clippy command fails on two warnings.

| Dimension | Rating | Summary |
| --- | ---: | --- |
| API design & documentation | 8 / 10 | Strong canonical API, typed errors, and extensive guides; the 0.6 compatibility bridge and weak binding types still create surface-area debt. |
| Code quality | 7 / 10 | Clear domain vocabulary and mechanical architecture fences, but the required lint gate is red and several modules remain very large. |
| Security | 8 / 10 | Deliberate secret handling, redaction, non-mutating acquisition, and dependency controls; injection, hand-written crypto, and undocumented `unsafe` invariants keep it below exceptional. |
| Testing | 8 / 10 | Deep unit, contract, binding, browser, and artifact layers; no measured coverage/fuzzing, a newly expanded DevTools path is lightly unit-tested, and HEAD is not fully green. |
| Release engineering | 6 / 10 | Sophisticated provenance and verification machinery, but the npm channel cannot currently complete and some proof gates remain advisory. |
| Architecture | 8 / 10 | A coherent Rust core, authoritative registry, explicit pipeline stages, and ADRs; large adapters, manual cross-language translation, and an internal `anyhow` bridge remain. |

The overall score is the equal-weight mean of the six dimensions. It describes
engineering maturity, not release readiness. **Release decision: no-go until
the two blockers below are fixed and the exact CI commands pass.**

## Scope and method

- Reviewed detached commit `899cb28caa7f63d0e828b8f9cf41e0990e0ac6f1`
  (`fix(ci): exercise viable claimed browser forks`).
- Review ran in the isolated worktree
  `/Users/blackmyth/src/rookie-cookies-evaluation-899cb28`; uncommitted files in
  the original worktree were excluded.
- Three specialist agents independently covered API/docs + architecture,
  code quality + testing, and security + release engineering. The lead review
  reproduced the decisive Clippy and npm-workflow findings and reconciled the
  scores.
- Scoring rubric: 9–10 exceptional and fully enforced; 7–8 production-grade
  with bounded debt; 5–6 useful but carrying material operational gaps; 3–4
  fragile or mostly manual; 1–2 critical and uncontrolled.

## Blocking findings

### 1. The npm release workflow cannot complete

This is a deterministic release blocker, not a theoretical risk:

1. Five checked-in native package directories exist.
2. `scripts/package-npm-tarballs.py:64-94` packs every native directory and
   then appends the root package, producing **six** tarballs.
3. `.github/workflows/publish-npm.yml:449-456` asserts that the package job
   produced exactly **five**, so the workflow stops before manifest creation,
   artifact upload, or publication.
4. The downstream check correctly expects six tarballs at
   `.github/workflows/publish-npm.yml:538-548`, confirming the contradiction.

There is a second defect behind that first failure. The final publish array at
`.github/workflows/publish-npm.yml:593-598` omits
`rookie-cookies-linux-arm64-gnu`, even though it is advertised by
`bindings/node/package.json:44-49` and marked `build`, `advertise`, and `publish`
in `release/platform-contract.json:153-176`. Merely changing the count from
five to six would therefore still leave Linux ARM64 consumers pointing at an
unpublished optional package.

Required action: derive the expected tarball set and native publish order from
`release/platform-contract.json`, then add a test that cross-validates the
contract, native manifests, root `optionalDependencies`, packed tarballs, and
workflow publish set.

### 2. The required Clippy gate fails

`.github/workflows/test-rust.yml:155-157` runs Clippy with `-D warnings`. The
same command fails at HEAD on two one-element loops left after the Yandex test
matrix was narrowed:

- `rookie-rs/src/browser/registry/chromium/tests.rs:733-763`
- `rookie-rs/src/browser/registry/chromium/tests.rs:773-847`

The failure is `clippy::single-element-loop`; runtime tests pass. Replace the
loops with direct bindings/blocks and rerun the exact all-features workspace
command before merge or release.

## Dimension reviews

### API design & documentation — 8 / 10

Strengths:

- `read(ReadRequest)` is clearly identified as the canonical 0.6 entry point,
  while named browser helpers are explicitly deprecated compatibility bridges
  (`rookie-rs/src/lib.rs:1-19`, `:79-96`). Root and binding guides align on the
  recommended flow.
- Private request fields and builders preserve omitted-versus-empty semantics,
  profile selection, timeout, cancellation, and session policy
  (`rookie-rs/src/read.rs:62-135`).
- The non-exhaustive public error hierarchy provides stable machine codes and
  sanitized engine diagnostics (`rookie-rs/src/error.rs:8-75`).
- `ReadResult::header` treats isolation context conservatively and documents
  its limitations and failure modes in detail (`rookie-rs/src/read.rs:286-335`).
- Doctests, public-API snapshots, generated DTO/schema checks, examples,
  migration guides, ADRs, and the documentation snippet checker provide
  meaningful automated drift resistance.
- The reviewed commit keeps registry truth aligned with user docs for Linux
  Arc and macOS Yandex (`README.md:43-62`, `:97-100`;
  `docs/architecture.md:275-285`; `rookie-rs/browser_registry.json:1255-1282`).

Gaps:

- The transition still exposes overlapping concepts: `read` versus `extract`,
  snapshot versus report, multiple path APIs, and numerous deprecated aliases
  (`docs/architecture.md:333-348`).
- Node selection/App-Bound options are broad strings rather than literal
  unions, while parts of the Python surface use `Dict[str, Any]`; runtime
  validation is stronger than editor/type-checker guidance.
- Deprecated `arc()` remains visible without clear platform qualification in
  binding types even though Linux no longer supports it.
- The snippet checker validates exported names, not binding-example semantics.

Recommendations: execute the documented 0.7 compatibility removal, generate
or centralize binding enums/DTO types, platform-qualify compatibility helpers,
and compile/type-check binding examples in CI.

### Code quality — 7 / 10

Strengths:

- The code uses explicit domain stages—resolve, discover, select, lookup,
  acquire, decode, unseal, finalize, project—and documents ownership at each
  boundary (`docs/architecture.md:257-273`).
- `xtask/src/stage_boundary.rs:1-113` and `cfg-location-allowlist.toml` turn
  architecture and conditional-compilation expectations into ratcheted checks.
- Typed requests, outcome types, error codes, secret wrappers, and the
  authoritative registry reduce stringly typed flow inside the core.
- Formatting passes, stage and cfg-location fences pass, and the final change
  consistently updates registry, dispatch, documentation, and coverage data.

Gaps:

- The required Clippy gate currently fails, which caps this score at 7.
- Review-heavy modules remain: `registry/gecko.rs` (2,572 lines),
  `bindings/node/src/lib.rs` (2,440), `registry/safari.rs` (2,141),
  `report_build.rs` (1,892), and the Chromium registry test module (over 3,300).
- `tests/e2e/run_hosted_claimed_e2e.py:4-7` still describes a native headless
  launch although the implementation now uses a DevTools port.
- No Ruff or mypy/pyright policy was found for the substantial authored Python
  release and E2E tooling.

Recommendations: fix the lint blocker, split the largest core and FFI modules
along existing domain boundaries, correct the stale helper documentation, and
add lightweight Python lint/type gates.

### Security — 8 / 10

Strengths:

- Secret buffers redact `Debug` and zeroize on success, error, and unwind paths
  (`rookie-rs/src/common/secret.rs:6-15`, `:56-66`, `:122-202`).
- Central diagnostics redact paths and bound messages; cookie DB acquisition
  uses private snapshots and read-only SQLite access
  (`rookie-rs/src/common/diagnostic.rs:1-103`;
  `rookie-rs/src/common/sqlite.rs:153-184`, `:1021-1027`).
- Destructive locked-database behavior and elevated App-Bound fallback require
  explicit policy; the default is non-elevated injection rather than SYSTEM
  fallback (`rookie-rs/src/execution.rs:12-43`, `:73-97`).
- CI installs a pinned `cargo-audit` and fails closed against owned,
  justified, expiring exceptions (`.github/workflows/test-rust.yml:146-153`;
  `security/audit-exceptions.toml:1-11`). There are currently no exceptions.
- Bundled SQLite is exactly pinned and governed by a 90-day review inventory
  (`rookie-rs/Cargo.toml:35-36`; `docs/sqlite-security.md:12-17`, `:36-61`).
- Actions are full-SHA pinned and general workflow permissions are read-only.

Gaps:

- Windows App-Bound recovery reflectively injects into a spawned browser by
  default. The path allocates executable remote memory and creates a remote
  thread (`rookie-rs/src/windows/appbound/injector.rs:337-395`); the elevated
  fallback acquires `SeDebugPrivilege`
  (`rookie-rs/src/windows/appbound/impersonate.rs:39-75`).
- The workspace contains 69 `unsafe` blocks but only 10 `SAFETY:` comments.
  The two highest-risk files above contain 37 blocks and no `SAFETY:` comments,
  leaving important pointer, lifetime, privilege, and cleanup invariants implicit.
- Linux DH and HKDF/SHA/HMAC primitives are hand-written in-tree without a
  visible independent audit or fuzz/sanitizer lane.
- Automated advisory coverage is Rust-centric; no blocking OSV/npm audit,
  CodeQL, or secret-scanning gate was found.
- There is no conventional `SECURITY.md`; `docs/security.md:1-15` explicitly
  says it is not a vulnerability-reporting policy.

Recommendations: document every `unsafe` invariant and isolate FFI wrappers,
obtain independent crypto/native-parser review with fuzzing/sanitizers, add
blocking multi-ecosystem advisory and secret scanning, publish a real
`SECURITY.md`, and reconsider whether injection should require explicit opt-in
at the next breaking release.

### Testing — 8 / 10

Strengths:

- The strategy separates deterministic contract tests, real-browser tests, and
  installed-artifact tests (`docs/testing.md:3-19`).
- PR CI covers Linux, macOS, and Windows; Rust, Node, and Python; no-default
  features; docs; public API; generated DTOs; architectural fences; dependency
  audit; and real Chrome/Firefox (`.github/workflows/test-rust.yml:63-195`).
- Artifact smoke installs release-shaped outputs outside the checkout. Golden
  reports and public contract tests protect serialization and compatibility.
- The reviewed commit expands hosted coverage to Vivaldi on three OSes and
  Yandex on macOS/Windows, with machine-checked explanations for fixture-only
  products (`docs/testing.md:187-269`; `tests/e2e/test_browser_coverage.py:117-182`).
- Local results were strong: 930 workspace tests passed, with three real-browser
  tests intentionally ignored; 67 E2E-helper tests and 152 release-tool tests
  passed; no-default-feature tests, doctests, and architecture fences passed.

Gaps:

- HEAD is not fully green because the required Clippy job fails.
- New DevTools lifecycle behavior—port polling, HTTP retries/validation, target
  close, process termination/kill, and persistence checks—has only command
  construction coverage in `tests/e2e/test_hosted_browser_runner.py:12-38`.
- No code/branch coverage tool or ratcheted threshold was found.
- The expanded Vivaldi/Yandex matrix is nightly/release-only; fixture lanes do
  not launch browsers.
- No fuzz/property harness was found for untrusted Safari, Mozilla session/LZ4,
  PE/App-Bound, or SQLite schema inputs.
- The 152 passing release-tool tests did not detect the npm workflow's
  contradictory count and publish set.

Recommendations: unit-test the DevTools lifecycle with a fake process and local
HTTP server, add a release-contract cross-check, introduce ratcheted
`cargo llvm-cov` reporting, and fuzz the untrusted parsers and classifiers.

### Release engineering — 6 / 10

Strengths:

- Release metadata and an 18-cell platform contract are centrally validated.
- Publish workflows verify tag identity/ancestry and live controls before
  mutation, use least-privilege permissions, and pin actions by commit SHA.
- PyPI and npm use OIDC trusted publishing. npm publishes prepared tarballs
  with provenance and verifies registry integrity for safe retries.
- Python, npm, and CLI flows generate digest-bound scan manifests and run a
  consumer harness against release-shaped artifacts; candidate bundles reuse
  much of that path.
- The release runbook is detailed and candid about multi-registry partial
  failure and residual trust gaps.

Gaps:

- The npm release channel is deterministically blocked and Linux ARM64 is
  missing from the publish set, as described above.
- Non-spoofable CI proof remains advisory and candidate evidence is not yet a
  load-bearing publish input (`docs/releasing.md:278-308`).
- The crates.io flow still uses a long-lived token and lacks the manifest,
  consumer-harness, provenance, and CI-proof depth used by npm/PyPI.
- Mutable `stable` toolchains and hosted-runner labels limit reproducibility.

Recommendations: fix and de-duplicate the npm contract first; add a test that
fails on the current workflow; then promote proven CI evidence to blocking,
bind candidate evidence to publication, extend artifact proof to crates.io,
move crates.io to OIDC, and pin release toolchains more tightly.

### Architecture — 8 / 10

Strengths:

- One Rust core feeds thin CLI, Python, and Node consumers
  (`Cargo.toml:1-10`; `docs/architecture.md:352-380`).
- `browser_registry.json` is the authoritative browser/discovery catalog, and
  the reviewed commit demonstrates that registry, dispatch, support tables,
  coverage lanes, and limitation reasons can move together.
- Source candidates/results, finalized outcomes, and snapshot/report
  projections make stage ownership explicit; AST-based fences guard against
  regrowth across key boundaries.
- ADRs state accepted debt and revisit triggers rather than hiding them.

Gaps:

- Several core and adapter modules remain large enough to increase review and
  change blast radius.
- The internal error bridge still depends on `anyhow` chains and load-bearing
  downcast order before conversion to typed public errors
  (`rookie-rs/src/error.rs:152-277`).
- Rust DTOs generate schema/Python dataclasses, but public Python dict and Node
  N-API conversion surfaces remain partly manual.
- Chromium retains multiple inventory/dispatch shapes, and high-privilege
  credential helpers remain in-process rather than behind a supervised process
  boundary.

Recommendations: remove the `anyhow` classification bridge with the 0.7 API
cleanup, split FFI adapters by job/domain, increase schema-driven generation,
and retain the documented revisit trigger for a future engine/process-isolation
boundary instead of adding abstraction prematurely.

## Prioritized remediation

| Priority | Action | Exit criterion |
| --- | --- | --- |
| P0 | Repair npm tarball count and publish Linux ARM64; derive both from the platform contract. | A static contract test fails on old HEAD and the release-shaped npm package/publish dry run passes with six artifacts. |
| P0 | Fix the two Clippy findings. | Exact CI Clippy command exits 0. |
| P1 | Test the new DevTools lifecycle and npm workflow contract. | Deterministic success, malformed response, timeout, early-exit, close-failure, and terminate/kill cases are covered. |
| P1 | Document/isolate `unsafe` and strengthen security process. | Every production unsafe block has an auditable invariant; `SECURITY.md` and multi-ecosystem scanning exist. |
| P2 | Complete the 0.7 API/internal-error cleanup and improve binding types. | Deprecated bridges/downcast classification are removed and finite binding options are generated typed unions. |
| P2 | Add measured coverage and parser fuzzing; split oversized modules. | Ratcheted critical-module branch coverage and parser fuzz targets run in CI; module-size debt trends down. |
| P2 | Promote proven release evidence to blocking and extend it to crates.io. | All publish channels bind artifacts to required CI and provenance before mutation. |

## Verification record

| Check | Result |
| --- | --- |
| `cargo fmt --manifest-path Cargo.toml --all -- --check` | Pass |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | **Fail:** two `single_element_loop` findings at lines 733 and 773 of the Chromium registry tests |
| `cargo test --workspace --all-targets --locked` | Pass: 930 passed, 3 intentionally ignored real-browser tests |
| `cargo test -p rookie-cookies --no-default-features --all-targets --locked` | Pass |
| `cargo test --workspace --doc --locked` | Pass: 40 doctests |
| `python3 -m unittest discover -s tests/e2e -p 'test_*.py'` | Pass: 67 tests |
| `python3 -m unittest discover -s tests/release -p 'test_*.py'` | Pass: 152 tests |
| `python3 scripts/check-doc-snippets.py` | Pass: 37 language fences |
| `python3 scripts/check-public-api.py --platform macos` | Pass |
| `cargo run -p xtask --locked -- check-stage-boundary` | Pass |
| `cargo run -p xtask --locked -- check-cfg-locations` | Pass, with the existing Chromium ratchet below its ceiling |
| `python3 scripts/check-release.py` | Pass for `0.6.0-beta.1` |
| `python3 scripts/platform_contract.py --validate` | Pass: 18 cells |
| Static npm package/workflow cross-check | **Fail:** six produced versus five asserted; Linux ARM64 omitted from publish list |

Limitations: this was a source and local macOS review, not a live registry
publish or a real Windows/Linux browser run. The three real-browser Rust tests
were ignored locally as designed. A fresh local RustSec audit was not claimed
because `cargo-audit` was unavailable; CI installs a pinned version and runs
the fail-closed exception checker.

No commit was created by the review.
