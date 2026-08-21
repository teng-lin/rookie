# Codebase audit — August 2026

Multi-agent review of the workspace at `ce6103b` (v0.6.0-beta.1). Six specialists
reviewed independently, without visibility into each other's findings, across
architecture, code quality, security, testing, release engineering, and API
design.

Counts for `unsafe` blocks, `SAFETY:` comments, module sizes, and lint
configuration were re-verified directly against the working tree after the
agents reported.

## Ratings

| Dimension | Rating |
| --- | --- |
| API design & documentation | 9 / 10 |
| Code quality | 8 / 10 |
| Security | 8 / 10 |
| Testing | 8 / 10 |
| Release engineering | 8 / 10 |
| Architecture | 7 / 10 |
| **Overall** | **8.0 / 10** |

No dimension scored below 7, and the spread is narrow. That is itself a finding:
quality here is even rather than patchy. The weak seam is not craft but
*consistency at the edges* — where core policy meets the bindings, and where
`unsafe` meets the Windows injection path.

## Convergent findings

Findings that surfaced in more than one independent review. These carry more
weight than any single agent's opinion.

### 1. Undocumented `unsafe` in the process-injection path

Found independently by the security and code-quality reviews; counts confirmed
directly.

The workspace has **68 `unsafe` blocks and 6 `SAFETY:` comments**. The gap
concentrates precisely where the stakes are highest:

```
rookie-rs/src/windows/appbound/injector.rs      20 unsafe · 0 SAFETY
rookie-rs/src/windows/appbound/impersonate.rs   18 unsafe · 0 SAFETY
rookie-rs/src/windows/appbound/browser_path.rs   7 unsafe · 0 SAFETY
rookie-rs/src/windows/dpapi.rs                   5 unsafe · 0 SAFETY
rookie-rs/src/windows/ncrypt.rs                  4 unsafe · 0 SAFETY
rookie-rs/src/common/secret.rs                   3 unsafe · 0 SAFETY
```

`SAFETY:` comments exist only in `macos/mod.rs`,
`browser/chromium_database_acquisition/windows.rs`, `windows/restart_manager.rs`,
and `bindings/python/src/errors.rs`.

`injector.rs` allocates RWX memory in a suspended Chrome process
(`VirtualAllocEx` + `PAGE_EXECUTE_READWRITE`, `injector.rs:337`), writes a
payload (`WriteProcessMemory`, `:352`), resolves imports by name, and starts a
remote thread through a transmuted raw function pointer (`:390-393`).
`impersonate.rs:45` acquires `SeDebugPrivilege` and performs token duplication.
None of the invariants — bounds on `remote_base + bootstrap_offset`, correctness
of the transmuted signature, trust in the suspended process — are written down.

The code appears correct: RAII guards for process and thread handles, deadline
checks throughout. But correctness that lives only in the author's head is not
reviewable, and nothing in CI would catch it regressing.
`clippy::undocumented_unsafe_blocks` is not enabled.

### 2. No fuzz or property testing on adversarial binary formats

Found independently by the security, testing, and architecture reviews.

The library's core job is parsing binary formats produced by other people's
software: SQLite WAL, DPAPI blobs, App-Bound v20 payloads, ESE databases.
Robustness against malformed input rests entirely on hand-picked fixtures —
zero hits for `proptest`, `quickcheck`, or `arbitrary` anywhere in the
workspace, and no `fuzz/` directory.

The sharpest edge is the ESE path (`compatibility_dispatch/named.rs:371-386`),
which links `libesedb` — a C library — in-process with no sandboxing or crash
boundary. A malformed or crafted ESE database can crash the host process rather
than surfacing as a typed error. This is self-disclosed in a maintainer doc
comment and IE support is already `#[deprecated]`, so it is a known gap rather
than a blind spot, but it remains live today.

### 3. Rules are enforced mechanically, not socially — a genuine strength

Confirmed across four reviews. This is the codebase's defining trait.

- `xtask/src/stage_boundary.rs:36+` parses the real token tree and fails the
  build if a fenced type grows a forbidden field. Its own doc comment states the
  rationale: *"the moment it does the compiler stops being the reviewer."*
- `xtask/src/cfg_scan.rs:66-95` uses `syn` rather than regex, including macro
  bodies, and fails closed on scan errors.
- Public API is snapshotted across three OSes and two feature sets
  (`rookie-rs/public-api/`), gated by `scripts/check-public-api.py`.
- Goldens are byte-identical and cross-verified on macOS.
- Every third-party GitHub Action across all 13 workflows is pinned to a full
  40-character commit SHA — zero floating tags.
- `cargo audit` exceptions require a named owner, a rationale, and a
  non-expired date (`scripts/check-audit-exceptions.py`).

## By dimension

### API design & documentation — 9/10

Unusually disciplined for a pre-1.0 crate.

**Strengths.** Illegal states are unrepresentable by construction:
`ExtractRequest` and `ReportRequest` were split (`lib.rs:308-321`, `:419-426`)
specifically because one `Request` type meant "first profile" to `extract` and
"every profile" to `extract_report`. Every extensible surface is
`#[non_exhaustive]`. `read`/`report`/`profiles` line up 1:1 across Rust, Python,
Node, and the CLI, with a generated JSON schema pinning the wire format.
Deprecations name their exact replacement. The CHANGELOG is genuine
Keep-a-Changelog quality, with rationale and migration snippets for breaking
changes.

**Gaps.** `Cookie` (`common/enums.rs:27-38`) is the one public struct without
`#[non_exhaustive]` and with fully public fields — almost certainly deliberate
as the frozen legacy projection, but undocumented as a permanent decision. No
`#![warn(missing_docs)]` anywhere; coverage is excellent today by discipline
alone. Roughly 20 deprecated functions still return `anyhow::Result`, keeping a
third-party error type in the public surface until 0.7.

**Pre-1.0 decisions worth settling now.** Document `Cookie`'s frozen shape so the
asymmetry reads as intentional. Turn on `missing_docs` while it costs nothing.
Put the `anyhow` bridge and `config::{Browser, Config}` removal version in one
canonical, greppable place.

### Code quality — 8/10

**Strengths.** `cargo clippy --workspace --all-targets --all-features --locked --
-D warnings` (the exact CI invocation) returns **zero warnings**;
`cargo fmt --check` is clean. Only 22 `unwrap`/`expect` calls in production code
across ~75k lines, nearly all naming the invariant that makes them safe. Eight
functions exceed 60 lines workspace-wide. Zero `TODO`, `FIXME`, or `HACK`
comments. Every `#[allow(dead_code)]` carries a comment explaining why the
compiler cannot see the usage. Recent history is dominated by intentional
`refactor:` commits rather than firefighting.

**Gaps.** The `SAFETY:` deficit above. Lint strictness lives only in the CI
invocation string — no `[lints]` table in any `Cargo.toml`, so a local
`cargo clippy` does not match CI. A `macro_rules!` defined inline inside a
138-line function body (`chromium_decoder.rs:369-382`) is off-idiom for this
codebase. Test-support code uses four naming conventions (`tests.rs`,
`*_tests.rs`, `test_seams.rs`, inline `#[cfg(test)] mod tests`), making
production complexity hard to separate from test complexity. Two bare
`.try_into().unwrap()` calls in `windows/appbound/pe.rs:17,24` break the
descriptive-message convention used everywhere else.

### Security — 8/10

**Strengths.** Zeroization is structural, not opt-in: `common/secret.rs:13-203`
wipes on `Drop`, so every early return, `?`, and panic-unwind path is covered.
A child-process test (`secret.rs:365-389`) panics mid-secret-lifetime and asserts
captured stdout and stderr never contain plaintext. `Cookie` has no derived
`Debug`; a manual impl substitutes `<redacted>` (`enums.rs:40-54`). macOS
Keychain stderr is never captured as text, only counted in bytes
(`macos/mod.rs:16-27`). GCM nonces are read from ciphertext and never reused,
with a flipped-tag known-answer test (`windows.rs:66-71`); CBC padding failures
return `Err` before any truncation (`unix.rs:30-37`,
`linux/confidential.rs:88-92`). SQLite is opened `READ_ONLY | URI` universally
(`common/sqlite.rs:1021-1022`), enforced through a `ReadOnlySource` marker trait.
The Windows shadow-copy path double-copies and byte-compares to fail closed on a
checkpoint race. No delete-cookie feature exists in the CLI or bindings.
`pull_request_target` is not used anywhere; publish workflows are
`workflow_dispatch`-only with least-privilege `permissions:` blocks.

**Findings.**

| Severity | Finding |
| --- | --- |
| High | Undocumented `unsafe` in `appbound/{injector,impersonate}.rs` (see above) |
| Med | `libesedb` runs unsandboxed in-process on the legacy IE/Edge path |
| Low | `publish-crate.yml:65` still uses a long-lived `CARGO_REGISTRY_TOKEN` while npm and PyPI use OIDC trusted publishing |
| Low | No fuzz targets or property-based tests anywhere |

**Unverified concern.** The Linux confidential-session path
(`linux/zeroizing_dh.rs`, `linux/zeroizing_hkdf.rs`) hand-rolls DH modexp,
SHA-256, HMAC, and HKDF rather than using audited RustCrypto crates, because
those crates do not implement `Zeroize`. It is validated against RFC 2409/4231/
5869 vectors and uses branchless modexp, and nothing was found wrong — but
custom primitives carry standing risk and would benefit from external review.

Also worth noting: `no_destructive_acquisition.rs` in both bindings is a static
source-text grep for forbidden literals, not a runtime test. It proves the
binding surface cannot syntactically reach the destructive opt-in; it does not
exercise the shadow-copy path.

### Testing — 8/10

**Inventory.** 902 `#[test]` occurrences across 88 files in `rookie-rs/src`; 746
run on macOS/arm64 (the remainder are `#[cfg(target_os)]`-gated at the `mod`
declaration — 43 Windows-only, 38 Linux-only). `cargo test --workspace`
executed **970 tests, every target `ok`, 0 failed** — run and confirmed, not
assumed. 40 doc-tests, all passing. 47 xtask self-tests. Python tests total 1,767
lines; the Node JS-side spec is 1,627 lines.

**Strengths.** `docs/testing.md` is unusually honest about what each CI lane
proves versus does not. Golden design normalizes only the two genuinely
non-deterministic fields and documents why the third needs none. The locked-
database recovery path pairs an always-on test asserting the safety property
(never terminates the holder) with an elevation-gated canary proving actual
recovery — added in `d487d4a` precisely because the mechanism previously had
only injected-closure routing tests. Zero tautological tests; every `#[ignore]`
is justified in a comment.

**Gaps.** No fuzz or property testing (above). App-Bound v20 — the newest and
most complex crypto path — gets no real-browser signal on PRs; only nightly and
manual runs exercise it. The Node binding has one Rust-side integration test
against Python's dedicated layer. Cross-platform code cannot be locally verified
from a single OS, so a contributor's local green is never the full picture. No
coverage tooling in CI, so gaps surface only through manual audits.

### Release engineering — 8/10

**Strengths.** Tag immutability is enforced structurally: rulesets with no bypass
actors (including admins), plus each publish workflow re-verifying that
`git rev-parse "v$VERSION^{}"` equals `GITHUB_SHA` and descends from
`origin/main`. `publish-cli.yml` and `publish-npm.yml` each re-resolve the tag a
second time immediately before upload, closing the TOCTOU window between build
and write. CLI uploads deliberately omit `--clobber` because it is not atomic —
a failed retry could permanently destroy a good asset — with a dedicated
`retry-cli-asset.yml` rebuilding only the missing target.
`revalidate-open-prs.yml` exists because three breakages landed in one day on
stale green checks.

**Gaps.** npm publishes six packages non-atomically and recovery is fully manual:
check each package with `npm view`, download a workflow artifact, hand-publish
the missing tarball. PyPI recovery is similarly manual. There is no automated
reconciliation across the four registries. The strongest anti-spoofing control
in the pipeline (`write-ci-proof.py`) is advisory-only — a verification failure
prints `::warning::` and never blocks. The R4 candidate-bundle evidence gates
nothing. No pre-commit hook matches CI, so contributors discover missed steps in
CI. A standing manual AV-scan gate on Windows artifacts (issue #191) sits on the
release critical path.

### Architecture — 7/10

The lowest score, and the one with the most actionable structural work.

**Strengths.** Adding a browser is a data-only edit: `browser_registry.json`
holds 48 definitions and engine dispatch is confined to about six production
`match browser.engine` sites. Crypto layering genuinely holds — decoders take no
key dependency at all, and key *identity* is separated from key *material*. Both
entry paths converge on `Outcome::finalize` (`browser/outcome.rs:313`), with the
three public result types as projections of one value. Redaction is structural:
`EngineError`'s fields are private with no public constructor
(`error.rs:16-40`).

**Gaps, most to least serious.**

1. **No shared request-validation layer, so consumers hand-duplicate policy.**
   The `select=all` conflict rule is written three times in three shapes
   (`bindings/node/src/lib.rs:779-800`, `cli/src/main.rs:139-149`,
   `bindings/python/src/job.rs:392-395`). The Chromium credential
   mutual-exclusion check appears four times. This is *forced*:
   `AppBoundPolicy::as_str` is `pub(crate)` (`execution.rs:47`) while the enum is
   `#[non_exhaustive]` (`:29`), so every binding must hand-write the string→enum
   inverse. Python's own comment concedes it: *"this hand-written inverse is the
   one place that must be kept in sync with them by hand"*
   (`bindings/python/src/lib.rs:65-67`). Core anticipates growth and gives
   consumers no supported way to track it.
2. **The main entry point discards detail it already computed.** `extract()`
   builds a full `ExtractionReport` internally, whose per-source `Failure`
   carries `{code, stage, scope, cause, severity, retryability, diagnostic}`
   (`outcome.rs:112-123`) — then `flatten_selected_report_cookies`
   (`lib.rs:686-706`) discards all of it for one fixed
   `EngineCause::NoSelectedSource`. A locked database, a wrong keychain password,
   and a corrupt SQLite file are indistinguishable to the caller.
3. **A production module cycle.** `report_build.rs:706` → `registry/chromium.rs`
   → `browser/chromium.rs:554` → back to `report_build::finalize_singleton_source`.
   Legal in Rust, but it means the declared stage order is not the dependency
   order, and nothing structurally prevents out-of-order re-entry.
4. **`report_build.rs` is 1,892 lines holding four concerns** — discovery-issue
   mapping, orchestration, projection, and Chrome-specific profile logic.
   `docs/architecture.md:60` explicitly declares splitting it a non-goal, so this
   is accepted debt rather than accident.
5. **The docs misstate the code on their own flagship constraint.**
   `docs/architecture.md:464` states "`registry.rs` itself stays target-agnostic";
   it carries 8 cfg attributes, exactly at its allowlist ceiling. The claimed
   `linux/macos/windows/unsupported` leaf pattern holds in 2 of 8 leaves, and
   `direct_path/mod.rs` carries 40 platform-cfg hits — the highest in the crate.
6. **Some abstractions do not pay for themselves.** `common/boundary.rs`'s
   `Acquire` is `#[cfg(test)]`-only by its own admission;
   `automatic_chromium_with` takes 7 type parameters and 4 closures for 2 call
   sites.

## Recommended next steps

Ranked by value per unit of effort.

1. **Document every `unsafe` block, then enforce it.** Write the precondition at
   each call site — buffer bounds, pointer validity, handle ownership, the
   transmuted signature — then enable `clippy::undocumented_unsafe_blocks`.
   Highest-leverage fix in the audit, and it changes no behavior.
2. **Turn on `#![warn(missing_docs)]` while coverage is still complete.** Costs
   nothing today; doing it later means first fixing whatever drifted. Same
   argument for moving lint config into a `[lints]` table so local `clippy`
   matches CI.
3. **Give consumers a real projection layer in core.** Public `FromStr` on the
   policy enums, plus constructors owning the conflict rules. Deletes the
   duplicated blocks in both bindings and the CLI, and removes the standing risk
   that a new `#[non_exhaustive]` variant becomes unreachable from every binding
   at once.
4. **Stop discarding error detail at the boundary.** Carry the selected source's
   `Failure` into `EngineError` instead of a fixed placeholder, and downcast
   `BrowserDatabaseFailure` in `map_job_error`. The data already exists and is
   already stable in the report contract.
5. **Fuzz the parsers that consume third-party bytes** — SQLite/WAL, App-Bound
   PE and payload, the Chromium AEAD decoder, ESE. Pair with sandboxing the
   `libesedb` call behind a crash boundary, or accelerate its deprecation.
6. **Promote the CI-proof gate from advisory to blocking** once one real release
   exercises it cleanly, and move crates.io to OIDC trusted publishing to retire
   the last long-lived registry token.

Optionally, 3 and 4 could be folded into the existing stage-boundary refactor
program rather than run as separate work, since both touch the same boundary the
program is already reshaping.

## Caveats

- Platform findings rest on reading cfg gates, not compiling on Windows and
  Linux. The `windows/appbound/injector.rs` unreachable-branch claim
  (`#[cfg(not(windows))]` inside a tree already excluded at `lib.rs:104`) is
  static reasoning — cheap to confirm with a `cargo check` per target before
  acting on it.
- The Windows App-Bound v20 key-unwrap step was not traced end to end; only the
  GCM decrypt itself was verified. Given finding 1, the injector's output
  deserves particular scrutiny.
