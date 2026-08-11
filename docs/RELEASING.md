# Releasing

`rookie-cookies` uses one version across three ecosystems:

- crates.io: `rookie-cookies`
- PyPI: `rookie-cookies` wheels and source distribution
- npm: `rookie-cookies` plus four native platform packages

Registry releases are immutable and the npm publication is not atomic. The
release workflows therefore run only by manual dispatch from an existing
`v<version>` tag. The npm workflow definition is dispatched from reviewed
`main` and explicitly checks out that tag for every source-consuming job.
Publish each registry in the order below and verify it before starting the
next one.

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

Update `CHANGELOG.md`, every package, and every internal dependency constraint
to the same version. Set that version once for the current shell session, then
run the checks below. The release metadata checker requires Python 3.11 or
newer.

```console
export VERSION=0.5.8
python3 scripts/check-release.py "$VERSION"
cargo test --workspace --all-targets
cargo test --workspace --doc
cargo publish --dry-run -p rookie-cookies --features appbound
cd bindings/node
npm ci --ignore-scripts
npm pack --dry-run --ignore-scripts
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
x86_64), Linux x86_64, and Windows x86_64:

```console
gh workflow run publish-cli.yml --ref "v$VERSION" -f tag="v$VERSION"
```

Always dispatch with `--ref "v$VERSION"` so the run's ref is the immutable
tag. The workflow's first step after checkout verifies that `GITHUB_REF_TYPE`
is `tag` and `GITHUB_REF_NAME` matches the `tag` input, and fails fast before
any build if the dispatch ref does not match the requested tag — this closes
off dispatching from `main` (or any other ref) with an arbitrary `tag` value
and having binaries built from unreviewed source silently overwrite that
release's assets. Because that check makes it structurally impossible for the
upload steps to run against anything other than the verified tag's commit,
the existing `--clobber` on those uploads is safe: it only ever re-uploads a
binary rebuilt from that same tag, e.g. to retry a single failed platform leg
without regenerating the others.

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
