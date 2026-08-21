# Cross-compile hardening plan

Status: implemented except for the upstream-release-dependent Phase 4 follow-up
Branch: `codex/cross-compile-hardening`  
Baseline: `d360e0be455cb87c119c9a9682fa94b037d835be`

## Implementation record

As of 2026-08-21, the repository-side work is implemented and validated in
the integration branch:

- #315 adds the optional, default-on Internet Explorer capability boundary and
  preserves the disabled-feature API surface.
- #314 adds the reusable macOS-hosted Linux and Windows source gate.
- #316 contains platform cfgs behind shared facades and lowers the cfg-location
  ceilings.
- #313 hardens native release artifacts and corrects the architecture, build,
  test, release, and troubleshooting documentation.
- sunsetkookaburra/rust-libesedb#30 fixes target selection in
  `libesedb-sys`, tests the selector from the packaged sys crate, and has been
  validated with a full `cargo-xwin` MSVC build.

The upstream fix is not yet released. Consequently, this branch deliberately
does not commit a root-only `[patch.crates-io]` or claim that published
consumers can resolve the fix. After a consumable upstream release exists,
finish Phase 4 by updating the normal dependency graph and adding the pinned
full-feature `cargo-xwin` lane. The new macOS Intel publish lanes are tag-only
release workflows and still require their first controlled release rehearsal.

## Problem statement

Windows-only Rust code can remain unchecked on a macOS or Linux development
host until native Windows CI runs. The intended cross-check is currently
blocked before it reaches that Rust code by `libesedb-sys 0.2.1`.

That crate's `build.rs` selects its bundled C configuration with
`cfg!(windows)`, `cfg!(unix)`, and `cfg!(target_os = "macos")`. A build script
is compiled for and runs on the host, so those expressions describe the host,
not Cargo's requested target. A macOS-to-Windows build consequently applies
the POSIX and macOS configuration to Windows C sources. The resulting failures
mention `sys/ioctl.h`, `langinfo.h`, `strerror_r`, and the POSIX two-argument
form of `mkdir`, but those diagnostics are consequences rather than the root
cause.

Editing an extracted `config.h` cannot fix this reliably because the build
script copies a fresh bundled source tree into `OUT_DIR` on each run. Changing
the Windows target from MSVC to GNU also does not fix host/target selection.
After correcting the selection logic, Windows GNU exposes additional bundled-C
portability gaps, so GNU must not be treated as proof of the shipped MSVC
artifact.

The verification record in `docs/architecture_api_gap_consolidated.md`
currently calls the Windows cross-build inconclusive because a toolchain or
sysroot was missing. That is incomplete: Windows MSVC does require an SDK or
sysroot for bundled C dependencies, but the Windows GNU + Zig reproduction
proves a deterministic host/target defect in `libesedb-sys` independently.

## Goals

1. Give developers one fast command that type-checks the native host, Linux,
   and nearly the complete Windows Rust source surface.
2. Keep the legacy Internet Explorer capability enabled in normal 0.6 builds
   while allowing the problematic native dependency to be excluded from the
   fast cross-target lane.
3. Preserve the existing Windows public function signatures when the IE
   feature is disabled, so disabling one backend does not hide stale call
   sites or silently change the no-default public API.
4. Retain native Windows MSVC CI as the authority for the complete Windows C,
   link, test, and runtime surface.
5. Establish a durable path for a fully featured macOS-to-MSVC check without
   relying on a root-only Cargo patch that published consumers cannot use.
6. Reduce the number of core locations where platform-specific signatures can
   drift without being selected by the developer's host.

## Non-goals

- Do not claim support for a Windows GNU release artifact. The release contract
  ships `x86_64-pc-windows-msvc`; GNU + Zig is a fast Rust source check.
- Do not use `DOCS_RS=1` as a permanent workaround. It can suppress native
  builds in dependencies for reasons unrelated to the capability being tested.
- Do not make a developer-local Git hook the only gate. Hooks are optional and
  do not keep the command itself working.
- Do not remove the deprecated Internet Explorer public API during 0.6.
- Do not block the immediate feature boundary and checks on a broad cfg
  refactor.

## Phase 1: isolate the Internet Explorer native backend

### Core feature

Change `rookie-rs/Cargo.toml` to express IE as a capability rather than an
unconditional Windows dependency:

```toml
[features]
default = ["appbound", "internet-explorer"]
appbound = []
internet-explorer = ["dep:libesedb"]

[target.'cfg(windows)'.dependencies]
libesedb = { version = "0.2", optional = true }
```

The feature is default-on to preserve 0.6 behavior for direct crates.io
consumers. The feature name describes the user-visible capability; callers
should not need to know which FFI crate implements it.

### Backend boundary

Replace the single `browser/internet_explorer.rs` implementation with a small
shared facade and two feature-selected backends:

```text
browser/internet_explorer/
├── mod.rs       shared public and crate-private entry points
├── esedb.rs     current libesedb traversal and Windows lock handling
└── disabled.rs  capability-disabled backend with the same query signature
```

`mod.rs` retains these existing interfaces:

- `internet_explorer_based`
- `internet_explorer_based_with_runtime`
- `internet_explorer_based_detailed_with_runtime`
- `internet_explorer_outcome_with_runtime`

Only the low-level operation that turns a `SourceCandidate` into a `Source`
is feature-selected. Candidate construction, projection, and the
platform-neutral decoder remain shared. This minimizes the signature that the
two backends must implement and keeps all Windows call sites type-checked when
the native backend is absent.

The disabled backend must fail before filesystem access or native acquisition
with an actionable error naming the `internet-explorer` feature. It must not
return an empty cookie set, omit IE from discovery silently, or masquerade as a
missing profile.

### Workspace feature forwarding

The root workspace dependency sets `default-features = false`, so adding a
default-on core feature does not preserve artifact behavior by itself. Update
all Windows artifact manifests explicitly:

- `cli/Cargo.toml`: add a forwarding `internet-explorer` feature and include it
  in the CLI defaults alongside `appbound`.
- `bindings/node/Cargo.toml`: enable `internet-explorer` in the Windows target
  dependency.
- `bindings/python/Cargo.toml`: enable `internet-explorer` in the Windows
  target dependency.
- `scripts/check-release.py`: update the expected manifest feature sets.
- `release/platform-contract.json` and generated release commands: record the
  capability wherever a Windows artifact currently records `appbound` and
  relies on IE remaining available.

Cargo features are additive across a dependency graph. Tests must therefore
verify both the isolated core package configuration and the feature-unified
workspace artifacts.

### Phase 1 tests

- On native Windows with `--no-default-features`, call every retained IE entry
  point with a dummy path and assert the capability-disabled error is returned
  before any path or lock operation.
- Assert the disabled and enabled facade entry points keep the existing public
  signatures. The committed Windows public-API snapshots should not change.
- Inspect the Windows feature-off dependency graph and assert neither
  `libesedb` nor `libesedb-sys` is present.
- Run the release metadata tests so CLI, Node, Python, and the platform contract
  cannot accidentally stop forwarding the capability.

## Phase 2: add the fast cross-target developer gate

Add `check-platforms` to `xtask`. It should run commands with
`std::process::Command`, echo each exact command before execution, stop on the
first failure, and report missing prerequisites with installation instructions.

The local command runs:

```console
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

cargo-zigbuild clippy \
  --target x86_64-unknown-linux-gnu \
  --workspace --all-targets --all-features --locked -- -D warnings

cargo-zigbuild clippy \
  --target x86_64-pc-windows-gnu \
  -p rookie-cookies --all-targets \
  --no-default-features --features appbound \
  --locked -- -D warnings
```

The Windows command deliberately enables `appbound` while leaving
`internet-explorer` disabled. It therefore checks the Windows feature-rich
Rust tree without compiling the ESE C backend. There are currently no
production `target_env`, `target_abi`, or `target_vendor` branches, so the GNU
target covers the source-level Windows branches well; it is still not an MSVC
link or runtime guarantee.

Support a `--skip-host` option so CI can reuse the cross-target commands after
the existing native Clippy step without compiling the host twice.

Document and install tested tool versions. The versions present during this
investigation are:

- `cargo-zigbuild 0.23.0`
- Zig `0.16.0`

Pin them in CI after the implementation proves those exact versions from a
clean runner. Follow the repository convention of pinning third-party actions
by commit SHA.

## Phase 3: make the gate mandatory in CI

Update `.github/workflows/test-rust.yml` so a macOS runner installs the pinned
Zig and `cargo-zigbuild` versions, adds the Linux GNU and Windows GNU Rust
targets, and runs:

```console
cargo run -p xtask --locked -- check-platforms --skip-host
```

Using macOS retains the original host/target shape that exposed the dependency
bug. The job must be required for pull requests; an undocumented local helper
will otherwise decay.

Keep the existing `check (windows-latest)` job unchanged in authority:

- all-feature Clippy compiles the real `libesedb` backend with MSVC;
- workspace tests exercise the complete Windows feature set;
- no-default tests exercise the disabled backend;
- public-API snapshots verify both feature configurations.

The fast cross-target lane catches hidden Rust renames and signature drift.
The native lane catches native C, SDK, linker, ABI, and runtime problems.
Neither lane substitutes for the other.

## Phase 4: repair `libesedb-sys` for full MSVC cross-builds

Prepare an upstream change to `libesedb-sys` that reads Cargo's target
environment rather than Rust host cfg expressions:

- `CARGO_CFG_TARGET_OS`
- `CARGO_CFG_TARGET_FAMILY`
- `CARGO_CFG_TARGET_ENV`

Extract configuration selection into a pure function and unit-test at least:

- macOS host to `x86_64-pc-windows-msvc` selects Windows/MSVC configuration;
- macOS host to `x86_64-pc-windows-gnu` selects Windows/GNU configuration;
- macOS host to macOS retains the current Unix and macOS adjustments;
- Linux host to Linux retains the Unix configuration.

The first supported project outcome is Windows MSVC. For Windows GNU, either
add the missing bundled-C definitions and header behavior or fail early with a
clear unsupported-target diagnostic. Merely selecting the Windows branch is
not sufficient for GNU today.

Validate the candidate fork temporarily with `[patch.crates-io]`, but do not
treat that patch as the shipped solution. A workspace patch is not propagated
to crates.io consumers. Completion requires one of:

1. an upstream `libesedb-sys` release consumed through the normal dependency
   graph; or
2. separately published, maintained forks of the safe wrapper and sys crate.

Because IE support is already deprecated for removal, establish a decision
deadline before taking permanent ownership of two native crates. If upstream
cannot release in that window, retain the feature-off fast gate and native
Windows authority, and schedule removal rather than silently carrying a
root-only patch.

Once a consumable fix exists, add a full macOS-to-MSVC verification using a
pinned `cargo-xwin` and Windows SDK cache:

```console
cargo xwin check \
  --target x86_64-pc-windows-msvc \
  -p rookie-cookies --all-targets --all-features --locked
```

This check includes `libesedb`; it is the full cross-build complement to the
fast Windows GNU feature-off check. Native Windows CI remains the final
authority.

## Phase 5: correct documentation and diagnostics

Update the following together with the implementation:

- `docs/architecture_api_gap_consolidated.md`: replace the “inconclusive;
  missing toolchain/sysroot” conclusion with the verified host/target defect
  and the separate MSVC sysroot requirement.
- `docs/building.md`: document `internet-explorer`, its default-on behavior,
  workspace forwarding, and the feature-off command.
- `docs/testing.md`: document `xtask check-platforms` and the distinction
  between source checks, full cross-builds, and native execution.
- `docs/architecture.md`: update the feature topology and IE backend boundary.
- `docs/troubleshooting.md`: explain how host-selected `build.rs` branches can
  be recognized and why editing `OUT_DIR` is temporary.
- Release documentation and contract tests: show the complete Windows feature
  set rather than mentioning only `appbound`.

Do not recommend `DOCS_RS`, manual edits under Cargo's registry/cache, or
switching to MinGW as fixes.

## Phase 6: reduce cfg-driven signature drift

The current AST-based inventory is 292 platform cfg attributes across 38
files. The largest files are:

| File | Attributes | Treatment |
| --- | ---: | --- |
| `direct_path/mod.rs` | 40 | Primary production containment target |
| `browser/chromium_projection.rs` | 25 | Split shared projection from platform leaves |
| `browser/chromium/tests.rs` | 16 | Test-only; lower priority |
| `browser/chromium_crypto/mod.rs` | 16 | Existing capability selector |
| `compatibility_dispatch/mod.rs` | 15 | Intentional allowlisted selection leaf |
| `browser/chromium_platform_keys/mod.rs` | 14 | Existing capability selector |
| `browser/unseal.rs` | 12 | Predominantly platform-specific tests |
| `lib.rs` | 11 | Public OS-specific exports; change only deliberately |

Raw count is not the goal: cfg in a small capability selector is desirable.
Prioritize cfg mixed into shared production logic where only one target sees a
function call or type.

After phases 1–4 are green:

1. Move `direct_path/mod.rs` inline tests to a dedicated test module, then
   separate remaining platform-dependent production decisions behind its
   existing `platform` facade.
2. Split `chromium_projection.rs` into shared projection logic and small
   target-selected credential/projection adapters.
3. Keep one platform-identical facade signature per capability. Where a leaf
   must expose several functions, add function-pointer type assertions or a
   crate-private trait so changing a parameter or return type requires updating
   the common contract.
4. Lower `cfg-location-allowlist.toml` ceilings in the same commits. Never
   raise a ceiling merely to land unrelated work.

Cross-target compilation remains necessary even with shared signatures:
Rust does not compile an unselected target module, so a facade alone cannot
prove every implementation body still compiles.

## Adjacent artifact hardening

Source cross-checks do not prove packaged artifacts. Track these as a separate
follow-up rather than conflating them with phases 1–4:

- Build macOS x64 release artifacts on the existing `macos-15-intel` runner
  instead of cross-building them on an ARM runner.
- Execute the exact Windows CLI artifact produced by the publish workflow; its
  platform-contract cell is currently `untested` because the workflow tests a
  separate development build.
- Promote a platform-contract cell to `native` only when the exact packaged
  output is executed on matching hardware.

## Delivery sequence

### PR 1: feature boundary and fast gate

- Optional default-on `internet-explorer` feature.
- Shared IE facade plus disabled backend.
- CLI/Node/Python/release feature forwarding.
- `xtask check-platforms` and required cross-target CI.
- Documentation correction and tests.

This PR removes the day-to-day blocker without waiting for an external crate
release.

### PR 2: full MSVC cross-build

- Upstream or published dependency release.
- Lockfile update without a permanent root-only patch.
- Pinned `cargo-xwin` full-feature check.
- Native Windows all-feature regression coverage.

### PR 3 and later: cfg and artifact ratchets

- `direct_path` and `chromium_projection` containment.
- Lower cfg ceilings.
- Native macOS Intel builds and exact Windows release-artifact smoke tests.

## Acceptance matrix

| Check | Expected guarantee |
| --- | --- |
| Native host workspace Clippy, all features | Current host remains warning-free |
| macOS/Linux to Linux GNU via Zig | Linux target-specific Rust and C compile |
| macOS to Windows GNU, IE disabled | Windows Rust call sites and signatures compile quickly |
| Windows MSVC, no defaults | Retained IE APIs fail explicitly without linking libesedb |
| Windows MSVC, all features | Complete shipped Windows implementation compiles and tests |
| macOS to Windows MSVC, all features via xwin | Full supported cross-build, including bundled C |
| Windows public-API snapshots | Existing IE function signatures remain available in both feature sets |
| Dependency-tree assertion | Feature-off Windows core has no `libesedb` or `libesedb-sys` |
| Release metadata tests | Every shipped Windows artifact explicitly enables IE |
| Exact artifact smoke | Published binary/package, rather than a dev rebuild, executes natively |

## Definition of done

The cross-compile hardening work is complete when:

1. `cargo run -p xtask --locked -- check-platforms` passes from a clean macOS
   checkout with documented prerequisites.
2. The same cross-target checks are required in pull-request CI.
3. The native Windows matrix passes both no-default and all-feature builds.
4. Disabling IE removes `libesedb-sys` without removing or silently bypassing
   the existing IE API surface.
5. A full-feature MSVC cross-check consumes a dependency fix that published
   crates.io users can also resolve.
6. The architecture verification record no longer attributes the confirmed
   `libesedb-sys` defect solely to a missing toolchain or sysroot.
