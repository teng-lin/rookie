# Documentation map

This directory separates maintained operating guidance from durable decisions
and historical implementation records. Package metadata and the relevant
language's `version()` function are authoritative for an installed version;
the guides intentionally do not hard-code the current prerelease number.

## Start here

| Need | Document |
| --- | --- |
| Understand the current system | [Architecture](architecture.md) |
| Build the workspace | [Building](building.md) |
| Run local, hosted-browser, and artifact tests | [Testing](testing.md) |
| Cut and verify a release | [Releasing](releasing.md) |
| Diagnose platform failures | [Troubleshooting](troubleshooting.md) |
| Report a vulnerability | [Security policy](../SECURITY.md) |

Language-specific installation, API, and migration guidance lives with each
package: [Rust](../rookie-rs/README.md),
[Python](../bindings/python/README.md), and
[Node.js](../bindings/node/README.md). The repository overview and browser
support matrix live in the [root README](../README.md).

## Security and assurance

[security.md](security.md) is the engineering index for security corrections,
SQLite inventory, cryptography-review status, and parser/fuzzing boundaries.
It complements, but does not replace, the vulnerability-reporting policy in
[SECURITY.md](../SECURITY.md).

The test and release guides describe which checks run on pull requests, which
run nightly, and which release proofs fail closed. Workflow files and their
pinned tool versions remain authoritative when operating CI.

## Durable contracts

- [Architecture Decision Records](adr/) define accepted design constraints.
- [Report DTO schema](../schema/README.md) defines generated cross-language
  report data.
- [Browser registry](../rookie-rs/browser_registry.json) is the source of
  truth for discovery and declared decryption capabilities.
- [Platform contract](../release/platform-contract.json) defines build,
  advertise, test, and publish support.
- [Fuzzing guide](../fuzz/README.md) documents parser targets and local runs.

Generated schemas, public-API snapshots, registry data, package manifests, and
workflow definitions take precedence over descriptive prose if they conflict.
Treat such a conflict as documentation drift and update the prose or its
validator in the same change.

## Historical records

[architecture_api_gap_consolidated.md](architecture_api_gap_consolidated.md)
and the files under [design/](design/) preserve point-in-time reviews and
implementation programs. They are useful provenance, not current operating
guidance. Dates, versions, line numbers, future-tense steps, and intermediate
API shapes in those files describe the recorded baseline unless a maintained
guide explicitly adopts them.

Exact prior release versions belong in the [changelog](../CHANGELOG.md), not in
maintained guides.
