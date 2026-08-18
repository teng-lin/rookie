# 0004. `read` is the recommended entry

- **Status:** Accepted
- **Date:** 2026-08-18
- **Deciders:** maintainers
- **Related:** [0001](0001-cookie-extraction-compatibility-and-report-contracts.md), [0002](0002-authoritative-browser-registry.md), [0003](0003-unified-profile-query.md)

## Context

Named store verbs (`chrome()`, `load()`, two-arg Rust `browser()`) remain the compatibility surface. New callers need one job for “import this browser profile into my HTTP client / `storage_state`” that does not pretend URL send-match is the snapshot.

## Decision

1. The recommended entry is `read` (Python also `jar` = `read().as_jar()`).
2. Every `read` / `from_path` snapshot is unfiltered. URL send-match is not applied to the snapshot.
3. The jar owns send-match. `header(url)` is a view (crate-private `GetFilter`) exposed as `ReadResult.header` and the CLI `header` subcommand only. There is no top-level binding `header()`.
4. A persistent cookie-database path is a resolver key (see ADR 0003’s query set plus this addition). `from_path` is a different universe and does not call the profile resolver.
5. Frozen `chrome()` / `load()` / eight-field `Cookie` / no all-profile flatten stay.
6. Do not add crate-root `fn report` or `fn get`.
7. **Source-policy asymmetry:** no-profile `read` uses the compatibility flatten (set-equals `chrome()` / `extract` when `include_expired=true`, persistent / legacy-eligible only). With-profile `read` uses the report flatten **including session cookies**. Naming the legacy-first profile can therefore return more cookies than omitting it. Session import (including NotebookLM) should pass `profile=`.
8. Warnings are structured `ReadWarning { code, count }`. Codes are stable; `Display` / `message` text is diagnostic only (ADR 0001).
9. `as_list()` / `__iter__` elements are the frozen eight-key cookie dict (`domain`, `path`, `secure`, `http_only`, `same_site`, `expires`, `name`, `value`). `same_site` stays the raw stored integer.

## Consequences

- Docs lead with `jar(browser=…)` and `read(…).as_list()`, not `get(url).as_jar()`.
- Callers who want session cookies must pass `profile=`.
- `chrome()` remains the compatibility set; `read` is the session-importer when a profile is named.
