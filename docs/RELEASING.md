# Releasing

`rookie-cookies` uses one version across three ecosystems:

- crates.io: `rookie-cookies`
- PyPI: `rookie-cookies` wheels and source distribution
- npm: `rookie-cookies` plus four native platform packages

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
here: the gate is fully automated — the SemVer floor, blocking RustSec, the
scan-evidence records, required CI checks, and the tag ruleset below are the
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

Configure these credentials without committing or pasting their values into an
issue, pull request, or workflow log:

1. Add a crates.io API token as the `CARGO_REGISTRY_TOKEN` secret in the
   `release` environment. crates.io requires a token-authenticated first
   release before trusted publishing can be configured.
2. On PyPI, create a pending GitHub Trusted Publisher for project
   `rookie-cookies`, owner `teng-lin`, repository `rookie-cookies`, workflow
   `publish-py.yml`, and environment `release`. No PyPI token is needed by the
   workflow.
3. Configure npm trusted publishing for `rookie-cookies` and all four native
   platform packages. For each package, use owner `teng-lin`, repository
   `rookie-cookies`, workflow `publish-npm.yml`, environment `release`, and
   allow the `npm publish` operation. The workflow uses OIDC and does not need
   an npm token.

Local `~/.pypirc`, `~/.npmrc`, and Cargo credential files are not automatically
available to GitHub Actions. Keep them owner-readable only and transfer tokens
through GitHub's encrypted secret form, never through the command line history
or repository files.

## Prepare a release

Author the release-note prose under the single `## [Unreleased]` heading in
`CHANGELOG.md`, then set the target version once and run the deterministic bump
command. It updates the workspace version and internal dependency requirement,
synchronizes all five npm manifests and exact optional-dependency pins,
promotes the authored changelog prose to a dated release section, and asks
Cargo and npm to regenerate their lockfiles. It never generates release-note
prose or replaces unrelated dependency versions that happen to match the old
project version.

The next native npm versions do not exist in the registry during preparation,
so npm can omit their optional resolution records. The command restores only
those minimal records from the structurally parsed local manifests, then runs
`npm ci --dry-run` against both npm lockfiles to prove they are installable.

```console
export VERSION=0.5.10
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
trusted publishing run on Node.js 24. The workflow creates all five immutable
tarballs without running publish lifecycle scripts and saves them as a workflow
artifact before any registry write.

Merge the release pull request and wait for all main-branch checks to pass.
Create an annotated tag from the resulting main commit:

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

The npm workflow builds and tests four native targets, verifies every expected
binary, and publishes these prepared native tarballs before the root package:

- `rookie-cookies-darwin-arm64`
- `rookie-cookies-darwin-x64`
- `rookie-cookies-linux-x64-gnu`
- `rookie-cookies-win32-x64-msvc`

### Checksum-identified Windows scan

Issue [#191](https://github.com/teng-lin/rookie-cookies/issues/191) tracks an
unresolved historical ESET detection. The npm package job now places these
additional files in its `npm-release-<version>` workflow artifact before the
`publish` job runs:

- `scan/rookie_cookies.win32-x64-msvc.node`, copied byte-for-byte from the
  Windows package assembled by the workflow;
- `scan/release-scan-manifest.json`, recording the release version, immutable
  tag commit, byte length, and SHA-256 for that native module and all five npm
  tarballs.

There is no reviewer gate between the package job and `publish` — do not
dispatch or let the `publish` job proceed until the scan below is complete and
recorded; nothing else stops it. For a checksum-identified scan, download that
workflow artifact onto a disposable, fully patched Windows VM before the
`publish` job runs, and verify every manifest digest before scanning the
`.node` file. Do not load or execute the native module during this check.
Record the disposition as structured evidence bound to the artifact's
SHA-256, rather than as free-form issue prose, using
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

This repository cannot substitute a different antivirus result for that ESET
evidence. Do not claim the historical detection is cleared, or close #191,
until a current checksum-identified scan is recorded or ESET has reclassified
the exact sample.

## Packaging-proof: what the release pipeline actually verifies

Each publish workflow (`publish-cli.yml`, `publish-npm.yml`, `publish-py.yml`)
writes a `release-scan-manifest.json` (`scripts/write-release-scan-manifest.py`)
before its registry-writing step, then runs
`scripts/run-consumer-harness.py` against it. Together these give every
shipped artifact:

- **A digest tied to its declared helper roles.** Each manifest record's
  `helper_roles` is matched against the artifact's cell in
  `release/platform-contract.json` (by filename — CLI binary target triple,
  npm package/addon platform, or wheel platform tag) at write time, and
  re-checked against the *current* contract at verify time — so "client plus
  every enabled helper role" is one digest-identified, cross-checked unit,
  not an implicit assumption. `scripts/run-consumer-harness.py
  --check-native-coverage` (wired into `test-rust.yml`'s per-commit CI) fails
  if a contract cell claims `execute: "native"` for an artifact type the
  harness has no real exercise routine for.
- **Real execution outside the checkout**, where the artifact's declared
  platform matches the verifying host: the CLI binary's `--version`, and an
  isolated `pip install` + `import` + `version()` for a Python wheel. An npm
  tarball is checked structurally (package layout, declared entry point);
  a native `.node` addon and a Python sdist stay checksum-verified only —
  see `run-consumer-harness.py`'s module docstring for why.

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

Two pieces of release-hardening program #230's "PR 2" are implemented and
tested, but neither is load-bearing yet — they don't gate any
`publish-*.yml` workflow, and nothing here changes what publishing requires
today. They exist to be reviewed and iterated on independently before that
wiring happens.

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
verification logic should re-run it by hand against a real commit
(`python3 scripts/write-ci-proof.py --commit-sha <sha> --manifest-digest <64
hex chars> --output /tmp/ci-proof.json`, read-only against the GitHub API) as
part of that review, since no CI job currently re-exercises it against live
data. What's still open: wiring either script into a publish workflow as an
actual gate, and the rest of #230's PR 2 (R6's digest-safe publication state
machine and R7's controlled cutover), neither of which is started.

## Verify

Confirm the exact versions on each registry, then smoke-test clean installs:

```console
cargo info "rookie-cookies@$VERSION"
python -m pip install --no-cache-dir "rookie-cookies==$VERSION"
python -c "import rookie_cookies; print(rookie_cookies.version())"
npm view "rookie-cookies@$VERSION" version
npm view "rookie-cookies-darwin-arm64@$VERSION" version
npm view "rookie-cookies-darwin-x64@$VERSION" version
npm view "rookie-cookies-linux-x64-gnu@$VERSION" version
npm view "rookie-cookies-win32-x64-msvc@$VERSION" version
```

Create the GitHub release only after all three registry checks pass.

## Publish CLI binaries

After the GitHub release exists, dispatch `publish-cli.yml` from the matching
tag to build and attach the `rookie-cookies` CLI binary for macOS (arm64 and
x86_64), Linux x86_64, and Windows x86_64.

Each CLI asset is uploaded with a same-named `.sha256` sidecar. Each matrix leg
also uploads a `cli-scan-manifest-<target>` workflow artifact containing a
`release-scan-manifest.json` scoped to that leg's one binary (source SHA,
controller SHA, platform-contract digest, byte length, SHA-256) — the same
manifest shape `publish-npm.yml` produces, applied per CLI target instead of
once for all five npm packages. Verify the Windows executable against its
sidecar before its separate ESET scan, then record the disposition the same
way as the npm scan, against the Windows leg's own manifest:

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

Paste the printed entry onto #191; the npm native module and CLI executable
are distinct artifacts and neither scan stands in for the other.

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

To retry only the leg that actually failed, build and attach it by hand for
that one target instead of re-dispatching the workflow — see "Retrying a tag
that predates the hardened workflow" below for the exact commands (the same
manual per-target build-and-upload path, whatever the reason for the retry).
Automatic digest-safe retry — detecting `present_identical` vs.
`present_mismatch` per artifact and skipping/failing accordingly instead of
requiring a manual fallback — is out of scope for this PR; it lands with the
release-hardening program's R6 phase.

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
mv "target/$TARGET/release/rookie-cookies" "rookie-cookies-cli-$TARGET"
gh release upload "v$VERSION" "rookie-cookies-cli-$TARGET"
```

Each platform binary must be built on its own host. Use the workflow's matrix as
the reference for target names, for the `.exe` suffix on Windows asset names,
and for the `--features appbound` flag the Windows build adds.

This workflow only triggers on `workflow_dispatch`, so it cannot be exercised
by normal pull request CI. Review its YAML carefully and dispatch-test it
against a real tag before relying on it for a release.

## After the first crates.io release

Configure crates.io trusted publishing for `publish-crate.yml`. Then update the
crate workflow to use crates.io's OIDC authentication action and delete the
long-lived `CARGO_REGISTRY_TOKEN` GitHub secret.

The pending PyPI publisher becomes a normal trusted publisher automatically
after its first successful run.

## Partial failures

Never blindly rerun a failed publish job. First check the registry because an
upload can succeed before the workflow reports a timeout.

For npm, inspect all five package names at the requested version. If the native
packages exist but the root package does not, download the failed run's
`npm-release-<version>` artifact and publish its unchanged root tarball with
lifecycle scripts disabled. Do not rebuild or attempt to overwrite any package
version; npm, PyPI, and crates.io versions are immutable.

For PyPI, `publish-py.yml` no longer passes `skip-existing: true` to
`pypa/gh-action-pypi-publish`: a partial failure (say, 6 of 9 files uploaded
before a timeout) means re-dispatching the whole workflow now hits PyPI's hard
"File already exists" rejection on every already-uploaded file, rather than
those being silently treated as already-there. Check `pypi.org/project/
rookie-cookies/<version>/#files` first to see which files actually made it.
If some are missing, download the failed run's `python-sdist`/
`python-linux-*`/`python-windows-*`/`python-macos-*` workflow artifacts and
publish only the missing files by hand with `twine upload <missing files>`
rather than re-dispatching the workflow against a distribution set that
partially already exists.
