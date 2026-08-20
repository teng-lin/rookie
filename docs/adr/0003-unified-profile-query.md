# ADR 0003: Unified profile query

- Status: Accepted
- Date: 2026-08-18
- Scope: generic profile selection keys and CLI `--profile` grammar
- Amends: [ADR 0001](0001-cookie-extraction-compatibility-and-report-contracts.md) §3 (installation and profile identity) and §9 (public APIs and CLI grammar)
- Does not amend: ADR 0001 first-profile / `load()` / `Cookie` / report DTO contracts; [ADR 0002](0002-authoritative-browser-registry.md)

## Context

ADR 0001 froze two rules that the unified extract API must change:

1. §3: “Generic selectors accept only IDs returned by discovery. The legacy Firefox API retains name/directory/path matching.”
2. §9: “`--profile PROFILE_ID` requires both `--report` and `--browser ID`.”

Those rules produced three disagreeing selectors (`browser_report` opaque-id-only, `chrome_profile` name/dir/path → report, `firefox_profile` name/dir/path → flat cookies) and blocked `--browser ID --profile Q` flat extract. The rest of ADR 0001 (no all-profile flatten behind named functions, `Cookie`, report DTO, `load()` historical set) remains the compatibility boundary.

## Decision

1. **One resolver.** Generic profile *queries* share one crate-private resolver. A query matches uniquely against, in order: opaque `profile_id`, display name, directory name, non-lossy full path. Zero or more than one match is a request error. A lossy display path is not a key. Last-used / channel / `is_default` are not tie-breaks. Two `Default` directories stay two `profile_id`s.
2. **`browser_report`’s middle argument is that query.** The signature stays `(browser_id, Option<&str>, Option<Vec<String>>)`. Opaque-id successes are unchanged. A unique name, directory name, or non-lossy path that used to fail as “unknown profile id” now selects that profile (or fails as ambiguous / lossy).
3. **CLI `--profile` requires `--browser` only.** It is legal with `--report` (one-profile report) and with `--browser` without `--report` (flat cookies). `--profile` without `--browser` remains a usage error. Netscape stays forbidden in list/report modes and remains allowed on flat `--browser --profile`.

`chrome_profile` / `firefox_profile` become shims onto this resolver. `firefox_profiles()` remains persistent-only `MozillaProfile` (ADR 0002). `extract` without a profile remains `LegacyFirstProfile`. Flattening every profile into a bare cookie list remains forbidden.

### Amendment (0.6.0): scope is a separate type

The query vocabulary above is unchanged. What changed is *who may decline to name a profile*: `ProfileSelection` (snapshot and flat extract) has `LegacyFirst` and `Query(String)` and no "every profile" arm, while `ReportScope` adds `AllProfiles`. Before 0.6.0 one request value carried both meanings, and which one applied depended on the function it was passed to — `extract` read the first legacy-eligible profile and `extract_report` read every profile from the same value.

## Consequences

Callers who passed a non-id string to `browser_report` and depended on a request error must stop; that path can now succeed. Downstream that already passed opaque ids needs no change. Implementers treat this file, not ADR 0001 §3/§9 as originally written, as the selector/CLI contract.

## References

- Follow-up job API: [ADR 0004](0004-read-is-the-recommended-entry.md)
