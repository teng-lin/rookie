# ADR 0002: Authoritative browser registry

- Status: Accepted
- Date: 2026-08-15
- Scope: browser discovery and extraction composition
- Supersedes: ADR 0001's current-release constraint on the internal discovery implementation

## Context

The crate maintained two complete discovery stacks. Named APIs used
`config.json` plus `common/paths.rs`; profile and report APIs used
`browser_registry.json` plus `browser/registry.rs`. Paths, channels, profile
selection, credentials, and failure classification could therefore diverge.

The public compatibility commitments in ADR 0001 remain valid. Familiar named
APIs and their flat cookie results do not need to disappear merely because
their internal discovery implementation was duplicated.

## Decision

`rookie-rs/browser_registry.json` is the only hand-maintained browser discovery
source on Linux, macOS, and Windows.

The registry engine separates discovery from profile selection with three
explicit policies:

- `AllProfiles` for full browser and load reports;
- `ProfileId` for an explicitly selected report profile;
- `LegacyFirstProfile` for named compatibility wrappers.

Selection happens before credential retrieval and source acquisition. Named
wrappers therefore do not extract profiles they will discard, and the policy
does not reimplement paths, profile enumeration, or engine parsing.

Platform differences enter through narrow existing boundaries: environment
and filesystem resolution in the discovery context, platform Chromium key
providers, SQLite/file/ESE acquisition, and platform-only Safari or Internet
Explorer composition. Browser ordering, parsing, filtering, and report
assembly remain platform-neutral.

The public `config::Browser`, `Config`, `CONFIG`, `get_browser_config`, and
`try_get_browser_config` symbols remain source compatible. `CONFIG` is now a
read-only compatibility projection built from `browser_registry.json`; it is
not consulted for discovery. The former `config.json` data file and
`common/paths.rs` implementation are removed.

Direct-path `any_browser` remains supported. It continues to sniff the source
format before choosing an engine, while Chromium identity credentials now come
from the registry.

## Compatibility contracts

- Named Rust functions, Python and Node named exports, and legacy CLI modes
  retain their public shapes and flat cookie results.
- `load()` retains its historical browser list and concatenation order.
- Compatibility selectors use deterministic registry priority and
  default-first profile order.
- Legacy cookie row order remains unsorted; grouped reports retain their
  documented deterministic sorting.
- Browser absence remains distinct from discovery or extraction failure.
- `firefox_profiles()` remains persistent-database-only even though report
  discovery can expose session-only profiles.
- No public named API is deprecated by this migration.

## Enforcement

Tests characterize first-profile selection, report/all-profile selection,
source precedence, flat load ordering, filters, and failure projection. CI also
rejects restoration of `config.json`, `common/paths.rs`, or a production
`paths::find_*` call.

Cross-platform CI compiles and tests the registry composition on Linux, macOS,
and Windows, including no-default-feature builds and all bindings.

## Consequences

Browser roots, channels, aliases, profile discovery, and key identities now
have one implementation location. Fixes automatically reach named, report,
binding, and CLI surfaces.

The compatibility projection may contain more descriptive path candidates than
the old data file because it is derived from explicit installation roots. It is
retained for source compatibility only; callers should use
`supported_browsers()` and `browser_profiles()` for discovery.
