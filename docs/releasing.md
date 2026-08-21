# Releasing

Operator runbook for cutting a `rookie-cookies` version. Language guides live
with the packages ([python](../bindings/python/README.md),
[javascript](../bindings/node/README.md), [rust](../rookie-rs/README.md)).
Build and test: [building.md](building.md), [testing.md](testing.md).
Security record: [security.md](security.md) (re-check
[sqlite-security.md](sqlite-security.md) before each release).

One version across three ecosystems:

- crates.io: `rookie-cookies` (`publish-crate.yml`, crate README is
  `rookie-rs/README.md`)
- PyPI: `rookie-cookies` wheels and sdist (`publish-py.yml`)
- npm: `rookie-cookies` plus five native platform packages (`publish-npm.yml`)

CLI GitHub-release assets: `publish-cli.yml`. Retry one missing CLI target
from `main` with `retry-cli-asset.yml`.

Exact release versions come from workspace metadata and are verified by
`scripts/check-release.py`; this runbook does not hard-code the current version.

Registry releases are immutable and the npm publication is not atomic. Every
release workflow therefore runs only by manual dispatch, and every one refuses
to publish unless it can verify the `v<version>` tag first. The ref you dispatch
from is *not* the same for all of them:

- `publish-crate.yml` and `publish-py.yml` are dispatched from the `v<version>`
  tag and fail unless the run's ref is that tag.
- `publish-npm.yml` is dispatched from reviewed `main` and fails unless the
  run's ref is `main`. Every source-consuming job explicitly checks out
  `refs/tags/v<version>`, and the preflight job asserts that the tag is an
  ancestor of `origin/main`.
- `publish-cli.yml` is dispatched from the `v<version>` tag, like the crate and
  PyPI workflows. See "Publish CLI binaries" for the extra check it needs.

Dispatching from the wrong ref fails the run rather than publishing anything, so
copy the exact commands from the sections below instead of assuming one
convention covers every workflow. Publish each registry in the order below and
verify it before starting the next one.

## One-time setup

Create a protected GitHub Actions environment named `release`, with admin
bypass disabled and its deployment branch/tag policy restricted to exactly
`main` and `v*` (the only refs any publish workflow legitimately dispatches
from — see the ref table above). There is deliberately no required reviewer
here: the gate is fully automated — the SemVer floor, blocking RustSec,
required CI checks, and the tag ruleset below are the
whole stop, not a backstop to a human approval step. The judgment call already
happened when the operator chose to dispatch the workflow; publishing then
proceeds unattended once those checks pass.

Create two repository tag rulesets for `v*` release tags: one restricting tag
*creation* to authorized release maintainers (admins), and a separate one
blocking `v*` tag *update* and *deletion* for everyone, with no bypass actors
at all — not even repo admins. Splitting these into two rulesets matters:
GitHub ruleset bypass actors apply to every rule in that ruleset, so a single
combined ruleset with an admin-creation bypass would also let an admin bypass
the deletion/update block, defeating the point. The workflows verify the tag
name and package version, while the immutability ruleset keeps that reviewed
tag commit immutable between creation and manual dispatch — including against
the person dispatching it.

Configure these publishers and credentials without committing or pasting any
secret values into an issue, pull request, or workflow log:

1. Configure crates.io trusted publishing for owner `teng-lin`, repository
   `rookie-cookies`, workflow `publish-crate.yml`, and environment `release`.
   The workflow exchanges GitHub's OIDC identity for a temporary crates.io
   token and revokes it when the job ends; it does not use a stored
   `CARGO_REGISTRY_TOKEN` secret. Delete that legacy environment secret if it
   still exists.
2. On PyPI, create a pending GitHub Trusted Publisher for project
   `rookie-cookies`, owner `teng-lin`, repository `rookie-cookies`, workflow
   `publish-py.yml`, and environment `release`. No PyPI token is needed by the
   workflow.
3. Configure npm trusted publishing for `rookie-cookies` and every native
   platform package that already exists. For each package, use owner
   `teng-lin`, repository `rookie-cookies`, workflow `publish-npm.yml`,
   environment `release`, and allow the `npm publish` operation. Normal
   releases use OIDC and do not need an npm token.
4. npm cannot configure a trusted publisher for a package that has never been
   published. To add a new contract package without a manual upload, create a
   granular npm token that is allowed to create/publish it and add that token
   to the `release` environment as `NPM_TOKEN`. Use the guarded one-time
   `bootstrap_package` dispatch described below. After that workflow creates
   the package, immediately configure its trusted publisher and delete the
   `NPM_TOKEN` environment secret.

Local `~/.pypirc`, `~/.npmrc`, and Cargo credential files are not available to
GitHub Actions. crates.io, PyPI, and established npm packages use OIDC and need
no copied credential; only the guarded first-package npm bootstrap uses a
stored token. Enter that token through GitHub's encrypted secret form, never
through command-line history or repository files.

## Prepare a release

Author the release-note prose under the single `## [Unreleased]` heading in
`CHANGELOG.md`, then set the target version once and run the deterministic bump
command. It updates the workspace version and internal dependency requirement,
synchronizes all six npm manifests and exact optional-dependency pins,
promotes the authored changelog prose to a dated release section, and asks
Cargo and npm to regenerate their lockfiles. It never generates release-note
prose or replaces unrelated dependency versions that happen to match the old
project version.

The next native npm versions do not exist in the registry during preparation,
so npm can omit their optional resolution records. The command restores only
those minimal records from the structurally parsed local manifests, then runs
`npm ci --dry-run` against both npm lockfiles to prove they are installable.

```console
export VERSION=0.6.0
python3 scripts/bump-version.py "$VERSION"
```

The default release date is today's UTC date. Pass an explicit date when
preparing reproducible metadata or working across a UTC date boundary:

```console
python3 scripts/bump-version.py "$VERSION" --date 2026-08-20
```

The command requires Python 3.11 or newer and reports every changed field and
regenerated file. It rolls metadata back if a package manager or the independent
release verifier fails. An exact rerun of an already prepared version is a
no-op; an ambiguous changelog or a pre-existing target release heading fails
without creating another release section.

Review the resulting release notes and generated metadata, then run the full
release checks. `check-release.py` reads `workspace.package.version` when no
argument is supplied; release workflows still pass an explicit version to bind
their check to the requested tag.

```console
python3 scripts/check-release.py
python3 scripts/check-release.py "$VERSION"
cargo test --workspace --all-targets --locked
cargo test --workspace --doc --locked
cargo publish --dry-run -p rookie-cookies --features appbound
(
  cd bindings/node
  npm ci --ignore-scripts
  npm run build
  npm test
  npm pack --dry-run --ignore-scripts
)
```

Use `--ignore-scripts` for the npm preview. The release workflow builds and
tests every native binary. Native builds run on Node.js 22; macOS, Windows, and
Linux Docker tests load them on Node.js 22, 24, and 26; and packaging plus
trusted publishing run on Node.js 24. The workflow creates all six immutable
tarballs without running publish lifecycle scripts and saves them as a workflow
artifact before any registry write.

Do not treat skipped jobs on the release pull request as release evidence.
The `pull_request` event intentionally runs only Ubuntu Chrome/Firefox in
`e2e.yml` and staggers one Node and one Python version per OS in
`test-rust.yml`. Before merging a release PR, manually dispatch both complete
suites against its branch and require every job to pass:

```console
export VERSION=0.6.0-beta.3
export RELEASE_BRANCH="release/$VERSION"
gh workflow run e2e.yml --ref "$RELEASE_BRANCH" \
  -f appbound_only=false -f multi_browser=true
gh workflow run test-rust.yml --ref "$RELEASE_BRANCH" -f suite=nightly
```

The first command adds macOS Chrome/Firefox, Windows Firefox, legacy DPAPI,
NonDisruptive shadow-copy recovery, and Chrome/Edge/Brave App-Bound v20 to the
Ubuntu browser lanes. The second runs the complete Node and Python products on
every supported CI OS—including macOS Node 22/24/26 and Python
3.11/3.12/3.13/3.14—plus FreeBSD, wheels, and sdist. These branch runs catch a
problem before merge, but do not replace the exact-`main` release gates below.

Merge the release pull request and wait for all automatic main-branch checks
to pass. Then run every full CI and browser suite against the exact commit that
will be tagged. The aggregate `release gate: ...` jobs exist only for these
manual release-mode dispatches and are required by every publish workflow's CI
proof:

```console
git fetch origin main
export RELEASE_SHA="$(git rev-parse origin/main)"

gh workflow run test-rust.yml --ref main -f suite=nightly
gh workflow run e2e.yml --ref main -f appbound_only=false -f multi_browser=true
gh workflow run e2e-release.yml --ref main
gh workflow run artifact-smoke.yml --ref main
gh workflow run assurance.yml --ref main
gh workflow run security.yml --ref main
```

These cover the full Rust/Node/Python runtime and OS matrix, FreeBSD and wheel/
sdist packaging, every installed-artifact platform including Linux ARM64 and
macOS Intel, coverage and sanitizer-backed fuzzing, dependency/secret/CodeQL
security scans, the complete claimed-browser installer plus fixture matrices,
and the real-browser matrix including Chrome, Edge, and Brave App-Bound v20.
Wait for all six workflows. Verify that each run's `headSha` is
`$RELEASE_SHA`, that all six aggregate release gates succeeded, and that
`origin/main` still points to `$RELEASE_SHA`; if `main` moved during the gate,
restart the gate against its new tip. The authenticated preflight performs the
same fail-closed check used by the publish workflows:

```console
python3 scripts/check-release-controls.py \
  --repo teng-lin/rookie-cookies \
  --commit-sha "$RELEASE_SHA"
git fetch origin main
test "$(git rev-parse origin/main)" = "$RELEASE_SHA"
```

Only after that exact-commit gate passes, create an annotated tag from the
resulting main commit:

```console
git switch main
git pull --ff-only
git tag -a "v$VERSION" -m "rookie-cookies $VERSION"
git push origin "v$VERSION"
```

## Publish

Dispatch the crates.io and PyPI workflows from the immutable tag and provide
the version without the `v` prefix. Dispatch the npm workflow from reviewed
`main`; it explicitly checks out and verifies the matching immutable tag for
every build and packaging job:

```console
gh workflow run publish-crate.yml --ref "v$VERSION" -f version="$VERSION"
gh workflow run publish-py.yml --ref "v$VERSION" -f version="$VERSION"
gh workflow run publish-npm.yml --ref main -f version="$VERSION"
```

Do not start all three commands together. Wait for each workflow to finish and
verify its registry before dispatching the next one.

For pre-releases (such as `1.2.3-alpha.1`), `publish-npm.yml` derives the npm
dist-tag from the version's pre-release identifier (e.g., `alpha`) and refuses
to publish a pre-release under `latest`. An explicit tag can be supplied
instead via `-f tag=`:

```console
gh workflow run publish-npm.yml --ref main -f version="$VERSION" -f tag="alpha"
```

### One-time npm package bootstrap

Trusted publishing cannot be configured for a package name until npm has a
package record. `bootstrap_package` solves that first-publication cycle inside
the normal release workflow; it is not a manual upload. The workflow accepts
only a package emitted by `release/platform-contract.json`, proves the package
returns npm `E404`, publishes its already-packaged release tarball with the
`release` environment's `NPM_TOKEN`, and then lets the ordinary OIDC publish
loop verify the same tarball by integrity before continuing.

Use this only when a future platform-contract package has no npm package record.
First prove that `npm view <new-package> name` returns `E404`, then dispatch:

```console
gh workflow run publish-npm.yml --ref main \
  -f version="$VERSION" \
  -f bootstrap_package="<new-package>"
```

Use this command *instead of* the ordinary npm command for that package's first
release. Do not pass `bootstrap_package` for an established package: the guarded
step refuses it. After the run creates the package, configure its trusted
publisher with the same owner/repository/workflow/environment settings listed
above, delete `NPM_TOKEN`, and omit the bootstrap input from every later
release.

`rookie-cookies-linux-arm64-gnu` completed this bootstrap in `v0.6.0-beta.2`.
Its trusted publisher is configured and `NPM_TOKEN` was deleted on 2026-08-21;
never pass it as `bootstrap_package` again.

pip and cargo skip pre-release versions by default, so PyPI and crates.io
need no equivalent tag handling.

The npm workflow builds and tests five native targets, verifies every expected
binary, and publishes these prepared native tarballs before the root package:

- `rookie-cookies-darwin-arm64`
- `rookie-cookies-darwin-x64`
- `rookie-cookies-linux-arm64-gnu`
- `rookie-cookies-linux-x64-gnu`
- `rookie-cookies-win32-x64-msvc`

### Optional checksum-identified Windows scan evidence

Issue [#191](https://github.com/teng-lin/rookie-cookies/issues/191) tracks a
historical ESET detection. The npm package job places these additional files in
its `npm-release-<version>` workflow artifact for optional incident analysis:

- `scan/rookie_cookies.win32-x64-msvc.node`, copied byte-for-byte from the
  Windows package assembled by the workflow;
- `scan/release-scan-manifest.json`, recording the release version, immutable
  tag commit, byte length, and SHA-256 for that native module and all six npm
  tarballs.

This scan is not a release gate or publication precondition. If investigating a
detection, download the workflow artifact onto a disposable, fully patched
Windows VM, verify every manifest digest, and scan the `.node` file without
loading or executing it. Record the disposition as structured evidence bound
to the artifact's SHA-256, rather than as free-form issue prose, using
`scripts/record-scan-disposition.py` against the downloaded
`release-scan-manifest.json`:

```console
python3 scripts/record-scan-disposition.py \
  --manifest release-scan-manifest.json \
  --artifact scan/rookie_cookies.win32-x64-msvc.node \
  --scanner-product "ESET Endpoint Antivirus" \
  --scanner-engine-version <engine version> \
  --scanner-signature-version <signature/database version> \
  --result clean \
  --reviewer <your GitHub username>
# or, if detected:
#   --result detected --detection-name "<exact detection name>"
```

The script appends the recording to the manifest's `scan_evidence` array —
bound to that exact artifact's SHA-256, so the record can't silently drift
onto a different build — and prints the entry as JSON. Paste that JSON, plus
any ESET false-positive submission and final vendor disposition, onto #191.

Do not claim the historical detection is cleared, or close #191, without
checksum-identified evidence for the sample under investigation or an ESET
reclassification of that exact sample.

## Packaging-proof: what the release pipeline actually verifies

Each publish workflow (`publish-crate.yml`, `publish-cli.yml`,
`publish-npm.yml`, `publish-py.yml`) writes a `release-scan-manifest.json`
(`scripts/write-release-scan-manifest.py`) before its publishing step, then runs
`scripts/run-consumer-harness.py` against it. Together these give every
shipped artifact:

- **A verified whole-manifest binding.** Every consumer-harness invocation
  recomputes `release.manifest_digest` over the manifest's release metadata and
  artifact records before it exercises an artifact. `write-ci-proof.py`
  independently recomputes the same digest before binding required checks to
  it, so a stale or hand-edited digest stops publication even when no separate
  consumer-evidence output was requested.

- **A digest tied to its declared helper roles.** Each manifest record's
  `helper_roles` is matched against the artifact's cell in
  `release/platform-contract.json` (by filename — CLI binary target triple,
  npm package/addon platform, wheel platform tag, or `.crate` package type)
  at write time, and
  re-checked against the *current* contract at verify time — so "client plus
  every enabled helper role" is one digest-identified, cross-checked unit,
  not an implicit assumption. `scripts/run-consumer-harness.py
  --check-native-coverage` (wired into `test-rust.yml`'s per-commit CI) fails
  if a contract cell claims `execute: "native"` for an artifact type the
  harness has no real exercise routine for.
- **Real execution outside the checkout**, where the artifact's declared
  platform matches the verifying host: the CLI binary's `--version`, an
  isolated `pip install` + `import` + `version()` for a Python wheel, and a
  compiled and executed external consumer for the packaged Rust crate. An
  npm tarball is checked structurally (package layout, declared entry point);
  a native `.node` addon and a Python sdist stay checksum-verified only — see
  `run-consumer-harness.py`'s module docstring for why.

**What this does not cover**, and why it's out of scope here rather than
silently skipped: the original PR6 spec (tracked through #225 and #230 R3)
also called for "each advertised supervised cell passes a parent-death
canary on its real installed host" and "inability to arm containment rejects
before spawn." Every helper role (`keychain`, `keyring`, `dpapi`, `appbound`)
runs in-process today — nothing in this codebase spawns one as a separately
supervised child process, so there is no containment surface to arm and no
parent boundary for a canary to watch. That is not something this pipeline
can honestly claim to check. Building the process-isolation architecture
that language actually requires is tracked separately in
[#244](https://github.com/teng-lin/rookie-cookies/issues/244).

## Candidate bundles and CI proof (release-hardening program R4/R5)

Two pieces of release-hardening program #230's "PR 2": R4 (candidate-bundle
evidence) is implemented and tested but still not load-bearing — it doesn't
gate any `publish-*.yml` workflow. R5 (`write-ci-proof.py`) is a
**blocking gate** in all four publish workflows. The npm, CLI, PyPI, and
crates.io workflows call it after writing the release manifest and running
the R3 consumer harness, and before their registry or GitHub release
mutation. Any missing required check, untrusted producing workflow, stale
manifest binding, API failure, or malformed response exits nonzero and stops
publication. The proof artifact upload also uses `if-no-files-found: error`,
so a workflow cannot continue with a silently absent proof.

The crates.io path packages the actual `.crate`, records it in a release scan
manifest, and compiles and executes an isolated consumer against that archive
before producing its CI proof. `cargo publish --dry-run` remains an additional
registry-shaped validation; the final `cargo publish` still repackages from
the same clean, SHA-pinned checkout because Cargo does not publish a supplied
archive directly.

**R4 — candidate-bundle evidence** (`.github/workflows/candidate-bundle.yml`).
A PR that adds or changes a cell in `release/platform-contract.json` (checked
via `scripts/platform_contract.py --diff-cells`) triggers the same build
pipeline `artifact-smoke.yml` already runs, assembles a *candidate* bundle
the same way a real release would (`write-release-scan-manifest.py --kind
candidate`), and runs the R3 consumer harness against it with `--output`,
producing a structured evidence file bound to that candidate manifest's
digest. The bundle is never published anywhere; the evidence is uploaded as
a 7-day build artifact for review. This exists to eventually let a release's
evidence be traced back to what was actually reviewed on the PR that
introduced a cell, closing the gap where a release build and a PR's smoke
test are today two independent, unlinked builds of the same code.

**R5 — non-spoofable CI proof** (`scripts/write-ci-proof.py`).
`scripts/check-release-controls.py`'s existing required-checks preflight
verifies a commit's checks by name alone against `commits/{sha}/check-runs`
— it doesn't verify which workflow, run, or repository actually produced
each one, and the GitHub Checks API doesn't tie a check-run's name to any
particular workflow: any token or App with `checks:write` on the repo can
post a check-run under an arbitrary name for an arbitrary commit.
`write-ci-proof.py` resolves every required check to its exact producing job
and run (`check_run.id == job.id`, then `actions/jobs/{id}` →
`actions/runs/{run_id}`) and verifies the run's repository, workflow file
path, trigger event, and `head_sha` all genuinely match — not just the
check-run's name. It writes a JCS-hashed (RFC 8785) `ci-proof.json` bound to
a release manifest digest. Real cryptographic attestation (Sigstore/OIDC
signing) beyond that digest is out of scope here, same as PR 1's R3 already
deferred full attestation — this is a digest binding, not a signature.

Both scripts have full unit test coverage (`tests/release/test_jcs.py`,
`tests/release/test_write_ci_proof.py`, and the extended
`tests/e2e/test_release_scan_manifest.py` /
`tests/e2e/test_run_consumer_harness.py` / `tests/release/test_platform_contract.py`).
`write-ci-proof.py`'s tests mock every `gh_api` response; anyone changing its
verification logic should re-run it by hand against a real commit as part of
that review, since none of the four publish workflows run on this repo's
own PR CI (`python3 scripts/write-ci-proof.py --repo <owner>/<repo>
--commit-sha <sha> --manifest-digest <64 hex chars> --output
/tmp/ci-proof.json`, read-only against the GitHub API — or `--manifest
<path to a release-scan-manifest.json>` instead of `--manifest-digest` to
read the digest from a real manifest file directly, matching what the
publish workflows themselves do).

What's still open: R4's evidence gate (it produces a standalone review
artifact on qualifying PRs but is not yet bound to a later release), plus
R6's post-publication registry-digest reconciliation/state machine and R7's
controlled cutover. Those require durable candidate lineage and registry
state that this repository does not currently record.

## Verify

Confirm the exact versions on each registry, then smoke-test clean installs:

```console
cargo info "rookie-cookies@$VERSION"
python -m pip install --no-cache-dir "rookie-cookies==$VERSION"
python -c "import rookie_cookies; print(rookie_cookies.version())"
npm view "rookie-cookies@$VERSION" version
npm view "rookie-cookies-darwin-arm64@$VERSION" version
npm view "rookie-cookies-darwin-x64@$VERSION" version
npm view "rookie-cookies-linux-arm64-gnu@$VERSION" version
npm view "rookie-cookies-linux-x64-gnu@$VERSION" version
npm view "rookie-cookies-win32-x64-msvc@$VERSION" version
```

Create the GitHub release only after all three registry checks pass.

## Publish CLI binaries

After the GitHub release exists, dispatch `publish-cli.yml` from the matching
tag to build and attach the `rookie-cookies` CLI binary for macOS (arm64 and
x86_64), Linux (x86_64 and aarch64), and Windows x86_64. A later failed matrix leg is
retried with `retry-cli-asset.yml`, not by re-dispatching the whole workflow
(see "A failed platform leg does not auto-retry").

Each CLI asset is uploaded with a same-named `.sha256` sidecar. Each matrix leg
also uploads a `cli-scan-manifest-<target>` workflow artifact containing a
`release-scan-manifest.json` scoped to that leg's one binary (source SHA,
controller SHA, platform-contract digest, byte length, SHA-256) — the same
manifest shape `publish-npm.yml` produces, applied per CLI target instead of
once for all six npm packages. For optional incident analysis, verify the
Windows executable against its sidecar before scanning, then record the
disposition against the Windows leg's own manifest:

```console
python3 scripts/record-scan-disposition.py \
  --manifest release-scan-manifest.json \
  --artifact rookie-cookies-cli-x86_64-pc-windows-msvc.exe \
  --scanner-product "ESET Endpoint Antivirus" \
  --scanner-engine-version <engine version> \
  --scanner-signature-version <signature/database version> \
  --result clean \
  --reviewer <your GitHub username>
```

When relevant to #191, paste the printed entry there. The npm native module and
CLI executable are distinct artifacts and neither scan stands in for the other.

`workflow_dispatch` runs the copy of the workflow file stored *at the dispatched
ref*. Dispatching from `v$VERSION` therefore runs that tag's own copy of
`publish-cli.yml`, not the copy on `main`. Confirm the tag's copy is a hardened
one before dispatching, by looking for the re-verification step that only the
hardened definition carries:

```console
git fetch origin "+refs/tags/v$VERSION:refs/tags/v$VERSION"
git grep "Re-verify release tag" "v$VERSION" -- .github/workflows/publish-cli.yml
```

The explicit `refs/tags/...:refs/tags/...` destination is what creates the local
tag; a source-only refspec leaves it in `FETCH_HEAD` only, so the `git grep`
against `v$VERSION` would fail in a fresh clone. The leading `+` forces the
local tag to match the remote, so a stale local tag cannot make this check read
the wrong workflow copy for the tag `gh workflow run --ref` will actually
dispatch.

Check for that marker rather than diffing the tag's copy against `main`'s. CLI
publishing is the last step of a release, often days after the tag was cut, so
any unrelated later commit to `publish-cli.yml` on `main` makes such a diff
non-empty even for a fully hardened tag — a byte-identity check would route
operators to the manual path for no reason. The marker is the newest piece of
hardening, so a tag that carries it also carries the tag verification step, the
`release` environment gate, and the SHA-pinned action references.

If the grep prints a match, dispatch the run:

```console
gh workflow run publish-cli.yml --ref "v$VERSION" -f tag="v$VERSION"
```

If it prints nothing, do not dispatch — follow "Retrying a tag that predates
the hardened workflow" below.

Always dispatch with `--ref "v$VERSION"` so the run's ref is the immutable
tag. The workflow's first step after checkout verifies that `GITHUB_REF_TYPE`
is `tag` and `GITHUB_REF_NAME` matches the `tag` input, and fails fast before
any build if the dispatch ref does not match the requested tag — this closes
off dispatching from `main` (or any other ref) with an arbitrary `tag` value
and having binaries built from unreviewed source silently overwrite that
release's assets.

That same step also asserts the tag is shaped `v<major>.<minor>.<patch>`, with
an optional pre-release suffix. This workflow takes the tag verbatim, where
`publish-crate.yml` and `publish-py.yml` build `v$VERSION` from a version input
and so enforce the prefix by construction. Matching the dispatch ref alone
would not: dispatching from a tag named `nightly` with `tag=nightly` satisfies
it, and every later check — including the re-verification below — would agree,
because they only ever compare the tag against itself. A tag outside `v*` is
also outside the ruleset that blocks tag updates, which is precisely what holds
the residual window described below shut.

The checkout states `ref: ${{ github.sha }}`, the commit the dispatch ref
resolved to. That is what `actions/checkout` already uses when given no `ref:`
— it fetches the run's `github.sha` directly rather than re-resolving the ref
name — so the line closes no gap; it makes the existing pinning explicit and
auditable in the workflow file. What it must *not* become is `refs/tags/${{
inputs.tag }}`: checking out the input would make the verification step that
follows a tautology.

Pinning the source is not the same as pinning the upload target. A step
immediately before the uploads re-resolves `v$VERSION` through the API and fails
the job if it no longer points at that same commit.

Residual limitations: `gh release upload` addresses a release by tag name, not
by commit, so nothing in the upload itself carries the verified commit. The
binding rests on that re-check, which cannot see a tag moved in the window
between the re-check and the upload. The `v*` tag ruleset from "One-time setup"
— block updates, block deletion — is what actually keeps that window closed. Do
not relax it. The re-check also binds the tag to a commit, not the *release* to
the tag: a release's `tag_name` is separately editable through the API, so a
release retargeted to a different tag would still receive these binaries. Both
gaps need repository write access, the access the tag ruleset already assumes is
limited to release maintainers.

### A failed platform leg does not auto-retry

The upload steps do **not** pass `--clobber`. Earlier revisions did, so one
failed platform leg could be rebuilt and re-attached by just re-running the
matrix — but `--clobber` is not an atomic replace: `gh release upload` deletes
the existing asset first and uploads the new one afterwards, so a network
error, expired token, cancelled run, or truncated build on the *retry* would
have permanently destroyed the original, already-good asset. GitHub keeps no
copy of a deleted release asset and does not roll the deletion back. That risk
is why it's gone: re-dispatching the whole workflow after a partial failure now
fails loudly on every leg that already succeeded, instead of silently risking
them.

To retry only the leg that actually failed, dispatch
`.github/workflows/retry-cli-asset.yml` from **reviewed `main`** (so you get
today's retry definition) and pass the immutable tag plus the missing target.
That workflow builds the binary from the **tag commit**, not from `main`, and
does not `--clobber`.

```console
gh workflow run retry-cli-asset.yml --ref main \
  -f tag="v$VERSION" \
  -f target=x86_64-pc-windows-msvc
```

Valid `target` values: `x86_64-pc-windows-msvc`, `aarch64-apple-darwin`,
`x86_64-apple-darwin`, `x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu`. Windows still adds `--features appbound`.

If that workflow is unavailable (or you must attach to a pre-hardened tag
without using Actions), build and upload that one target by hand — see
"Retrying a tag that predates the hardened workflow" below. Automatic
digest-safe retry (`present_identical` vs `present_mismatch`) is still
tracked with the release-hardening program's R6 phase.

### Retrying a tag that predates the hardened workflow

If the marker grep above found nothing, the tag stores an older definition of
`publish-cli.yml`. Dispatching from that tag runs the *old* definition: its tag
verification step, the `release` environment's live controls, and the
SHA-pinned action references now on `main` do not apply to that run, whatever
`main` contains today. Nothing in the dispatch surfaces this — the run simply
looks like a normal one.

Handle it one of two ways:

1. Preferred: cut a new patch release from current `main`, so the new tag
   carries the hardened workflow, and publish the CLI binaries from that tag.
2. If binaries must be attached to the existing release, build them locally from
   the exact tag and upload them by hand. Read the `--clobber` warning above
   first; the manual upload below deliberately omits `--clobber`, so it fails
   loudly instead of destroying an existing asset.

```console
git fetch origin "+refs/tags/v$VERSION:refs/tags/v$VERSION"
git switch --detach "v$VERSION"
git status --porcelain # must print nothing
export TARGET=x86_64-unknown-linux-gnu
cargo build --release --locked --target "$TARGET" \
  --package rookie-cookies-cli --bin rookie-cookies
# Windows: add --features appbound and the .exe suffix on the asset name.
mv "target/$TARGET/release/rookie-cookies" "rookie-cookies-cli-$TARGET"
python3 scripts/write-sha256-sidecar.py "rookie-cookies-cli-$TARGET"
gh release upload "v$VERSION" \
  "rookie-cookies-cli-$TARGET" "rookie-cookies-cli-$TARGET.sha256"
```

Each platform binary must be built on its own host. Use the workflow's matrix as
the reference for target names, for the `.exe` suffix on Windows asset names,
and for the `--features appbound` flag the Windows build adds. For optional
incident analysis after upload, record the Windows scan disposition against
that target's `release-scan-manifest.json` the same way as in "Publish CLI
binaries" — the npm native module scan does not cover the CLI executable. Prefer
`retry-cli-asset.yml` when Actions is available; it writes the sidecar and
uploads both files.

This workflow only triggers on `workflow_dispatch`, so it cannot be exercised
by normal pull request CI. Review its YAML carefully and dispatch-test it
against a real tag before relying on it for a release.

## Partial failures

Never blindly rerun a failed publish job. First check the registry because an
upload can succeed before the workflow reports a timeout.

For npm, inspect all six package names at the requested version. The workflow
is integrity-idempotent: it accepts an already-published package only when the
registry integrity matches the rebuilt immutable tarball, then continues with
the missing packages. If a future one-time bootstrap package is created before
a later failure, configure its trusted publisher and re-dispatch without
`bootstrap_package`. Do not rebuild by hand or attempt to overwrite any
package version; npm, PyPI, and crates.io versions are immutable.

For PyPI, recover through the same trusted-publisher workflow by passing the
failed Actions run ID. Dispatch from the same immutable release tag used by the
failed run:

```console
gh workflow run publish-py.yml --ref "v$VERSION" \
  -f version="$VERSION" -f recovery_run_id=<failed-run-id>
```

Recovery never rebuilds a wheel or sdist. It verifies that the source run was a
completed failed `publish-py.yml` dispatch for the same tag and source SHA,
downloads that run's exact distributions and release manifest, reruns the
consumer harness and CI proof, and compares each local SHA-256 with PyPI. An
existing identical file is accepted, a digest mismatch or unexpected file
fails closed, and only absent files are submitted through PyPI trusted
publishing. The workflow performs the same digest comparison again after the
upload. Python release artifacts and proofs are retained for 30 days so this
recovery path does not depend on rebuilding immutable release files.

If the failed run has no `python-scan-manifest` artifact, it failed before the
publish job reached any registry mutation; fix the pre-publication failure and
run a normal dispatch without `recovery_run_id`.
