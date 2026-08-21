# Consolidated codebase audit — August 2026

This document consolidates and revalidates the findings from:

- `docs/codebase-audit-2026-08-claude.md`, originally reviewed at `ce6103b`;
- `docs/codebase-audit-2026-08-codex.md`, originally reviewed at `899cb28`.

The source audits remain unchanged. Remediation was implemented and validation
was repeated on 2026-08-21 on branch `fix/audit-remediation-2026-08`, based on
`c98dc88` and including changes through `e2aca13`. This report distinguishes
fixed findings, partial mitigations, accepted/deferred work, and the one finding
explicitly excluded from this remediation.

## Current assessment

| Dimension | Rating | Current basis |
| --- | ---: | --- |
| API design & documentation | 8 / 10 | Canonical jobs, typed errors, finite binding options, shared policy parsing, and extensive checked docs; the 0.6 compatibility bridge and incomplete workspace-wide documentation policy remain. |
| Code quality | 8 / 10 | Formatting, strict Clippy, tests, public-API snapshots, and architecture fences pass; several very large modules and broad lint-policy debt remain. |
| Security | 8 / 10 | Strong secret handling plus new vulnerability policy, dependency/secret/code scanning, fuzzing, and prominent injection warnings; the excluded unsafe-invariant gap and external crypto/native-parser review remain. |
| Testing | 9 / 10 | Broad multi-language tests now include ratcheted branch coverage, sanitizer-backed fuzz jobs, and deterministic CDP lifecycle failure tests; real vendor/browser and platform-only paths remain scheduled rather than ordinary local tests. |
| Release engineering | 8 / 10 | The npm blocker is fixed, artifact contracts are cross-validated, and CI proofs now fail closed for every channel; registry-side OIDC/state reconciliation still requires external setup. |
| Architecture | 8 / 10 | Central policy construction, typed selected-source failure, and removal of the report/Chromium cycle improve dependency direction; large adapters and some manual cross-language projection remain. |
| **Overall** | **8.2 / 10** | Equal-weight mean; final release authorization still depends on the normal protected CI and release checklist. |

**Release decision: implementation-ready, subject to protected CI.** The
deterministic npm publication blocker is resolved. This assessment does not
claim that a live registry release, Windows App-Bound canary, or the full
scheduled real-browser matrix was executed locally.

## Findings and current disposition

### P0 — npm packaging and publication were internally inconsistent

Status: **resolved**.

The original workflow produced five native packages plus the root package but
asserted five tarballs, and its publish list omitted Linux ARM64. The release
path now derives expected npm package names, tarball names, count, and native
publish order from `release/platform-contract.json`. Linux ARM64 is published
before the root package, and the root remains last.

Repository tests now cross-check the platform contract against checked-in
native manifests, root `optionalDependencies`, packed tarballs, and workflow
use. The package assertion is contract-derived rather than another hard-coded
list.

Validation:

- `python3 scripts/platform_contract.py --validate` passes for all 18 cells;
- npm repository validation passes;
- 158 release-tool tests pass; and
- the packaged Rust consumer succeeds both from `cargo package` output and an
  exact `.crate` archive.

Recommendation: keep the platform contract authoritative and require the
release-tool suite for every workflow change.

### P1 — high-risk `unsafe` invariants are undocumented

Status: **confirmed, explicitly excluded from this remediation**.

Both source audits found that the most privileged Windows App-Bound injection,
impersonation, DPAPI, NCrypt, and secret-memory paths contain many production
`unsafe` blocks without local `SAFETY:` arguments. The risk and recommendation
remain unchanged: document each invariant, minimize raw FFI wrappers, and only
then enforce `clippy::undocumented_unsafe_blocks` as a workspace lint. Where
feasible, remote memory should transition from writable to executable rather
than remain RWX.

No file was changed to address or suppress this finding in the remediation
branch, by explicit scope decision.

### P1 — adversarial parsers and custom cryptography lacked independent assurance

Status: **partially resolved**.

Implemented:

- a standalone `cargo-fuzz` workspace with portable decoder, Mozilla session,
  and source-classifier targets;
- sanitizer-backed pull-request and scheduled fuzz jobs with both per-input and
  whole-process deadlines;
- ratcheted line and branch coverage for the workspace and critical parser,
  secret, and error-policy files; and
- an explicit cryptography review record that defines required evidence and
  does not misrepresent CI as an independent specialist review.

The integrated coverage run measured **85.98% lines** and **77.45% branches**;
the enforced workspace floors are 80% and 70%, with higher file-specific floors
for critical modules. All three fuzz targets built with sanitizers, and each
completed a 100-run local smoke test without sanitizers. The latter mode was
used because Apple macOS 26's ASan runtime deadlocked during allocator startup
before reaching the harness; CI runs the sanitizer jobs on Ubuntu and bounds
startup or runtime hangs.

Remaining:

- no independent specialist review of the in-tree DH/HKDF implementation has
  occurred; and
- deprecated Internet Explorer support still parses ESE through `libesedb`
  in-process. The portable ESE-record fuzz facade does not sandbox or exercise
  the native C parser itself.

Recommendation: commission and record an independent crypto review, and make a
compatibility decision to remove IE support or place `libesedb` behind a crash
boundary.

### P1 — adapter policy and error projection were duplicated or lossy

Status: **substantially resolved**.

`AppBoundPolicy` now owns its stable string representation and typed parsing.
Core constructors own flattened profile/report selection and Chromium
credential-selector conflict rules; Node, Python, and the CLI use those core
rules rather than maintaining separate match tables.

Flat extraction now preserves a selected source failure as the stable
`source_extraction_failed` class instead of incorrectly converting it to
`no_selected_source`. Detailed report issues continue to retain the underlying
source diagnostic without exposing paths or secrets.

Finite Node selection literals and Python policy/selection aliases were added,
along with typed Python DTO views for report, profile, and browser results.

Recommendation: preserve the single-core-policy pattern when adding variants.
If consumers later require more granular flat error codes, evolve that public
contract deliberately rather than leaking report internals through adapters.

### P1 — security governance was narrower than the threat surface

Status: **implemented in the repository; one external enforcement step remains**.

The repository now has:

- a root `SECURITY.md` with supported versions, private reporting, response
  targets, disclosure guidance, and safe-research scope;
- pinned, fail-closed OSV dependency scanning;
- a full-history pinned Gitleaks job;
- CodeQL for Rust, JavaScript/TypeScript, and Python;
- weekly Dependabot coverage for Actions, Cargo, npm, and Python tooling; and
- front-page App-Bound process-injection warnings plus the `Disabled` opt-out in
  Rust, Python, Node, and root quick-start documentation.

Local OSV and Gitleaks validation reported no known dependency issue or secret
in the scanned tree/history. The workflows themselves fail closed. Repository
administrators must add the new assurance/security job names to branch
protection if policy requires them as named merge gates.

Recommendation: make those contexts required after their first successful
protected run, and keep scanner exceptions owned, justified, and time-bounded.

### P2 — release proof was not load-bearing end to end

Status: **substantially resolved; registry-side work remains**.

The advisory R5 mode was removed. npm, Python, CLI, and crates.io publication
now require CI proof and proof artifacts before mutation. Crate publication now
also creates a SHA-bound scan manifest and exercises the exact `.crate` archive
from outside the checkout before upload.

Remaining external constraints:

- crates.io still uses `CARGO_REGISTRY_TOKEN`; OIDC trusted publishing requires
  account-side configuration after an eligible release exists;
- candidate-to-release lineage is not yet durably bound to publish inputs; and
- post-publication registry digest reconciliation still needs durable external
  state and retry semantics.

Recommendation: configure crates.io trusted publishing, then implement durable
candidate lineage and digest reconciliation without weakening the current
fail-closed artifact proof.

### P2 — API and documentation quality relied partly on convention

Status: **partially resolved**.

Finite binding vocabularies, typed Python DTO views, and the legacy `Cookie`
shape's compatibility contract are now documented or typed. Public-API
snapshots for all supported targets were updated and native checks pass.

Still deferred:

- removal of the 0.6 compatibility bridge remains a planned 0.7 breaking
  change;
- several large binding conversions remain hand-written; and
- workspace-wide `missing_docs` and shared manifest lint expansion would be a
  broad policy change beyond this beta remediation.

Recommendation: finish compatibility removal on the documented 0.7 schedule,
increase schema-generated binding surface, and introduce stricter shared lints
as a ratcheted migration rather than a one-step flag day.

### P2 — large modules and a report/Chromium dependency cycle increased blast radius

Status: **cycle resolved; module-size debt remains**.

Legacy Chromium projection moved to `chromium_projection.rs`, removing the
`report_build` → registry → Chromium → `report_build` cycle. Shared selection
and credential construction also reduce adapter-to-core policy edges. The
architecture guide was corrected to match the cfg checker, and its existing
ceiling was ratcheted downward.

Large registry and adapter modules remain a maintainability cost, particularly
the Node binding and Gecko/Safari registry implementations.

Recommendation: split those modules by job and concern while preserving the
now-enforced stage boundaries and generated public surfaces. Track size and cfg
allowances as downward-only ratchets.

### P2 — testing was broad but not quantitatively measured

Status: **resolved for the identified gap**.

The assurance workflow measures workspace and critical-file line/branch
coverage and rejects regressions below checked-in floors. It also runs three
bounded sanitizer-backed fuzz targets.

The raw Chromium DevTools lifecycle now has deterministic coverage for retry,
malformed payload, missing target ID, close failure, timeout, process early
exit, and terminate-to-kill cleanup paths. The hosted-runner documentation was
corrected to describe the foreground DevTools flow.

Recommendation: raise floors when sustained measurements improve, add new fuzz
targets at newly introduced untrusted byte boundaries, and preserve the
distinction between fixture coverage and live seed-and-extract evidence.

## Remaining prioritized roadmap

| Priority | Action | Exit criterion |
| --- | --- | --- |
| Excluded P1 | Document and isolate production `unsafe`. | Every production block has a specific safety argument and CI rejects new undocumented blocks. |
| P1 external | Complete independent crypto review and decide the `libesedb` crash boundary. | Review evidence is recorded; native ESE parsing is removed or isolated. |
| P1 operational | Add new security/assurance contexts to branch protection. | Protected branches require the successful scanner, coverage, and fuzz contexts. |
| P2 external | Configure crates.io OIDC and durable release lineage/reconciliation. | Every channel uses short-lived identity and reconciles published digests to reviewed inputs. |
| P2 planned | Complete the 0.7 compatibility cleanup and lint ratchets. | Deprecated bridges are removed and documentation/lint coverage increases without suppressions. |
| P2 ongoing | Reduce oversized binding and registry modules. | Module-size and cfg allowances trend downward while stage/API gates remain green. |

## Integrated validation record

| Check | Result |
| --- | --- |
| `cargo fmt --manifest-path Cargo.toml --all -- --check` | Pass |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | Pass |
| `cargo test --workspace --all-targets --locked` | Pass; 3 real-browser cases intentionally ignored locally |
| `cargo test -p rookie-cookies --no-default-features --all-targets --locked` | Pass |
| `cargo test --workspace --doc --locked` | Pass; 40 doctests |
| Full `cargo llvm-cov` workspace/all-feature/all-target run | Pass; 85.98% lines, 77.45% branches, 752 core tests in the instrumented run |
| `python3 -m unittest discover -s tests/e2e -p 'test_*.py'` | Pass; 87 tests |
| `python3 -m unittest discover -s tests/release -p 'test_*.py'` | Pass; 158 tests |
| Raw CDP Node lifecycle suite | Pass; 6 tests |
| Node build, typecheck, and AVA suite | Pass; 49 tests; package audit reported zero vulnerabilities |
| Python release wheel and binding suite | Pass; 66 tests |
| `python3 scripts/check-doc-snippets.py` | Pass; 37 language fences |
| macOS public-API snapshot check | Pass for both feature sets |
| Stage-boundary and cfg-location checks | Pass; cfg ceiling ratcheted |
| Release metadata, platform contract, npm repository, and native execution checks | Pass; 18 platform cells |
| Packaged Rust consumer from generated package and exact archive | Pass |
| Local OSV and Gitleaks scans | Pass; no known issue or leak reported |
| Fuzz target build and 100-run target smokes | Pass; sanitizer build on macOS, smoke execution without sanitizer due host ASan startup deadlock |
| Workflow YAML parse and changed-diff whitespace validation | Pass |

Limitations: validation ran locally on macOS except where the isolated audit
worktrees or workflow definitions explicitly target Ubuntu. It did not execute
the real Windows/Linux browser matrix, App-Bound v20 canary, live registry
publication, or branch-protection configuration. Platform-specific behavior is
therefore additionally subject to the protected hosted CI and scheduled release
checks.
