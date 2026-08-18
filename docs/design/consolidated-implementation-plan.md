# Consolidated implementation plan (historical)

- **Status:** Completed / archived
- **Date:** 2026-08-18
- **Superseded by:** the accepted ADRs below (the three-PR program has landed)

This file previously held the execution contract for store unification plus the
job-layer `read` / `jar` API. The long-form draft specs it pointed at
(`clean-get-api.md`, `unified-extract-api.md`) have been removed.

## Current source of truth

| Topic | Document |
| --- | --- |
| Compatibility + report contracts | [ADR 0001](../adr/0001-cookie-extraction-compatibility-and-report-contracts.md) |
| Browser registry | [ADR 0002](../adr/0002-authoritative-browser-registry.md) |
| Unified profile query | [ADR 0003](../adr/0003-unified-profile-query.md) |
| Recommended entry (`read` / `jar`) | [ADR 0004](../adr/0004-read-is-the-recommended-entry.md) |

User-facing guides: [bindings/python/README.md](../../bindings/python/README.md),
[bindings/node/README.md](../../bindings/node/README.md),
[rookie-rs/README.md](../../rookie-rs/README.md), and the root
[README.md](../../README.md).
