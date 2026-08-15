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

Create a protected GitHub Actions environment named `release`. Requiring a
reviewer for this environment adds a final confirmation before any registry
write.

Create a repository tag ruleset for `v*` release tags. Block updates and
deletion, and restrict tag creation to authorized release maintainers. The
workflows verify the tag name and package version, while the ruleset keeps that
reviewed tag commit immutable between creation and manual dispatch.

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
tests every native binary, creates all five immutable tarballs without running
publish lifecycle scripts, and saves them as a workflow artifact before any
registry write.

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
environment-gated publish job runs:

- `scan/rookie_cookies.win32-x64-msvc.node`, copied byte-for-byte from the
  Windows package assembled by the workflow;
- `scan/release-scan-manifest.json`, recording the release version, immutable
  tag commit, byte length, and SHA-256 for that native module and all five npm
  tarballs.

For a checksum-identified scan, pause before approving the npm `publish` job,
download that workflow artifact onto a disposable, fully patched Windows VM,
and verify every manifest digest before scanning the `.node` file. Do not load
or execute the native module during this check. Record the following on #191:

- workflow run, version, tag commit, artifact filename, byte length, and
  SHA-256 from the manifest;
- ESET product, engine, and signature/database versions;
- the exact detection name, or an explicit clean result;
- any ESET false-positive submission and final vendor disposition.

This repository cannot substitute a different antivirus result for that ESET
evidence. Do not claim the historical detection is cleared, or close #191,
until a current checksum-identified scan is recorded or ESET has reclassified
the exact sample.

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

Each CLI asset is uploaded with a same-named `.sha256` sidecar. Verify the
Windows executable against that sidecar before its separate ESET scan and add
the result to #191; the npm native module and CLI executable are distinct
artifacts and neither scan stands in for the other.

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

### `--clobber` deletes the existing asset before uploading

The upload steps pass `--clobber` so one failed platform leg can be rebuilt and
re-attached without regenerating the others. `--clobber` is **not** an atomic
replace: `gh release upload` deletes the existing asset first and uploads the
new one afterwards. If that upload then fails — network error, expired token,
cancelled run, a build that produced a truncated file — the original asset is
permanently gone. GitHub keeps no copy of a deleted release asset and does not
roll the deletion back.

Before re-running a leg against a release that already carries assets, download
the current ones so a failed re-upload stays recoverable:

```console
gh release download "v$VERSION" --dir "release-assets-v$VERSION"
```

`gh release download` fails rather than overwriting when a target file already
exists, so download into a fresh directory; add `--clobber` only when you mean
to replace an earlier copy of that backup.

### Retrying a tag that predates the hardened workflow

If the marker grep above found nothing, the tag stores an older definition of
`publish-cli.yml`. Dispatching from that tag runs the *old* definition: its tag
verification step, the `release` environment approval gate, and the SHA-pinned
action references now on `main` do not apply to that run, whatever `main`
contains today. Nothing in the dispatch surfaces this — the run simply looks
like a normal one.

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
