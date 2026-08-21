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
3. The jar owns send-match. `header` is a view (crate-private `GetFilter`) exposed as `ReadResult.header` and the CLI `header` subcommand only. There is no top-level binding `header()`. **Amended in 0.6.0:** it takes a `SendContext`, not a bare URL. A URL cannot say which browsing context a request is made from, so `header(url)` had no way to distinguish a CHIPS-partitioned cookie from an unpartitioned one and merged them. A snapshot holding an isolated cookie now *demands* the selector that identifies it.
4. A persistent cookie-database path is a resolver key (see ADR 0003’s query set plus this addition). `from_path` is a different universe and does not call the profile resolver.
5. Frozen `chrome()` / `load()` / eight-field `Cookie` / no all-profile flatten stay. **Amended in 0.6.0:** `Cookie` keeps its eight fields and gains derives only; it is now a *projection* of the snapshot, whose native representation is `DetailedCookie`. "No all-profile flatten" is now a type fact rather than a rule — `ProfileSelection` cannot express it (ADR 0003).
6. Do not add crate-root `fn report` or `fn get`.
7. **Session policy is orthogonal to profile selection.** *(Amended in 0.6.0; superseding text below.)* Both `read` routes stop at the finalized record and project `DetailedCookie`; neither goes through the report flatten. Whether the profile's declared session store is opened is a separate question, answered by `SessionPolicy` (`PersistentOnly` by default) and enforced **before lookup**, so the crate does not open `sessionstore.js` or `recovery.jsonlz4` unless asked. Session import passes `include_session()` / `include_session=True`, and no longer needs to name a profile to get it.

   The superseded prerelease text read: *"no-profile `read` uses the compatibility flatten … With-profile `read` uses the report flatten **including session cookies**. Naming the legacy-first profile can therefore return more cookies than omitting it. Session import should pass `profile=`."* That coupling had two defects. Reaching cookies through `ExtractionReport` discarded `CookieContext`, because the DTO is frozen at `schema_version: 1` and carries the eight-field `Cookie` — so the recommended path was the one that lost isolation. And it made "I want that profile" and "I want session cookies" inexpressible separately: `read(ReadRequest::browser("firefox").include_session())` could not be written at all.

   The changelog records this ADR in the 0.6 prerelease history. It describes behavior that was never stable, so it is amended in place rather than superseded by a new ADR.
8. Warnings are structured `ReadWarning { code, count }`. Codes are stable; `Display` / `message` text is diagnostic only (ADR 0001).
9. `as_list()` / `__iter__` elements are the frozen eight-key cookie dict (`domain`, `path`, `secure`, `http_only`, `same_site`, `expires`, `name`, `value`). `same_site` stays the raw stored integer.

## Consequences

- Docs lead with `jar(browser=…)` and `read(…).as_list()`, not `get(url).as_jar()`.
- Callers who want session cookies pass `include_session` (0.6.0). Before 0.6.0 they passed `profile=`, which is the migration trap: `jar(profile="Default")` returns a smaller jar in 0.6.0, with no error.
- `chrome()` remains the compatibility set; `read` is the session-importer when `include_session` is passed, with or without a profile.
