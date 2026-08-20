# ADR 0005: Stage-boundary types and extraction vocabulary

- Status: Accepted
- Date: 2026-08-19
- Scope: internal structure and domain language of the browser / registry /
  report extraction pipeline
- Does not amend: ADR 0001–0004 behavior, the public API and
  `rookie-rs/public-api/*.txt`, the report DTO and
  `schema/report-dto.schema.json`, or `browser_registry.json`
- Program record: [stage-boundary refactor](../design/stage-boundary-refactor.md)
  — motivation in full, alternatives with trade-offs, and the PR plan

## Context

ADRs 0001–0004 record externally observable contracts. This one records an
internal rule, for two reasons: it is mechanically checked, so a contributor
who trips the check needs a durable statement of why; and the document that
introduced it is a program record whose line references and PR tracking are
explicitly expected to rot.

The oversized modules under `rookie-rs/src/browser/` were a symptom of
domain-language leakage, not of file length. One extraction pipeline was
described with four vocabularies, so each stage grew its own types and its
neighbour translated. A cookie source existed as five successive bags. The
word `Draft` named parse scratch, a per-file engine result, a whole-browser
adapter result, and report adaptation. The word `query` named SQL, "extract
this file", and ADR 0003 profile matching.

Translators diverge. Listing `selected` and `acquisition` disagreed between
engines, and one bag type served as both an empty candidate and a filled
result — so nothing could reject a listing that carried cookies. Carving
those files into smaller ones would have left every translator in place. The
missing abstraction was a data type, not a module layout.

## Decision

### 1. Listing values cannot hold extract data

Discovery and extraction return different types, and the difference is
structural rather than conventional. A value produced by discovery has
nowhere to put what reading it produced:

- `SourceCandidate` — what discovery found on disk — has no `records`,
  `cookies`, `stats`, `issues`, `sources`, or `failure`.
- `Source` — what reading a candidate produced — has no `cookies`,
  `profile_id`, `installation_id`, or `display_name`. Records are the only
  supply of finalized rows, and report identity belongs to the profile that
  owns the source.
- `DiscoveredProfile` and `EngineListing` have no `sources`, `cookies`, or
  `records`. `ExtractedProfile` and `EngineExtract` are never listing return
  types.
- `ChromiumProfile` is inventory and has no `cookies`, `records`, or
  `sources`. `ChromiumExtractedProfile` owns sources, not their contents: no
  `records`, `stats`, `row_issues`, `issues`, `legacy_error`, or
  `acquisition` restated beside the profile.

`Source` embeds `origin: SourceIdentity` -- the join keys path, role, format,
and precedence, as one type rather than four loose copies -- so its provenance
cannot drift from what discovery found. `selected` and `acquisition` are
effective fields on `Source`, stated as constructor arguments rather than
inherited from a candidate, so an engine that forgets to state one gets a
compile error instead of a wrong wire value. A `Source` cannot name a listing
`selected`, `acquisition`, or `exists` at all: those live on `SourceCandidate`,
which is the only stage that has them, and no consumer ever read them through
`origin`. `failure: Option<SourceFailure>` replaces an `error` plus sibling
`error_stage` pair, making a failure stage without a failure unrepresentable.
`failed` is derived from it, never stored.

The rule holds under `#[cfg(test)]`. Characterization tests project cookies
from records through a `#[cfg(test)] fn cookies()` method; a field would let
a fixture assert on rows the pipeline never produced.

### 2. The boundary is fenced mechanically

`cargo run -p xtask --locked -- check-stage-boundary` parses the token tree of
the files that define the types above and fails if a fenced type declares a
forbidden field, including under `#[cfg(test)]`. Each fence is bound to its
defining file, so an unrelated type of the same name elsewhere neither
satisfies nor trips it, and each violation quotes the reason the field was
forbidden.

This is an identifier lint on named struct fields. It does not look at line
counts, file lengths, or how many types a module holds. No size lint is
added: success here is conceptual, not a line budget.

### 3. Internal verbs and nouns

The internal stages are resolve, discover, select, lookup, acquire, decode,
unseal, finalize, project. `extract` remains the *public* name (`lib.rs`
`extract` and `extract_report`).

Deleted as internal *vocabulary*: `query` for anything but SQL, `populate`,
`canonical_*_extraction`, and `Draft` for anything that is already a result.
New code does not reach for these words, and prose in this repository does not
use them for those meanings.

This governs the words, not today's identifiers. `populate_gecko_sources`,
`populate_safari_sources`, `populate_internet_explorer_sources`,
`query_cookies_engine_outcome_with_runtime`, `query_cookies_from_connection`,
and `query_cookies_with_key_outcomes` are live production functions and keep
their spellings as historical identifiers until a later, deliberate, mechanical
rename. An ADR that a single `rg` disproves teaches contributors to skip
ADRs.
Profile matching is `select` / `ProfileQuery` (ADR 0003). Engine work is
`acquire`. Finalization is `Outcome::finalize`. Projection is the last stage
only — `Outcome` to `ExtractionReport`, `Cookie[]`, or `ReadResult`; mapping
key credentials to a key identity is `lookup` input, not a projection.

Engine-private parse scratch may keep a local name containing `Draft` so long
as it never crosses a module boundary.

Frozen wire identifiers are not renamed. `ExtractionStageCode::query()`,
issue codes, and `browser_registry.json` keys including `key_credentials`
keep their spellings. The internal vocabulary stops at the wire.

### 4. Only source-level types are unified

`SourceCandidate` and `Source` are the shared data types this decision
introduces. There is no shared `Installation` or `Profile` type: Chromium
keeps its own inventory shapes, while Gecko, Safari, and Internet Explorer
carry identity on `DiscoveredProfile` / `ExtractedProfile`. Selection policy
is split out into `LegacyRank`, so ADR 0002 ranking inputs do not ride in a
type named identity.

There is no engine-plugin trait. The engines share no useful behavioural
abstraction, and ADR 0002 already separated discovery from selection with
policies rather than plugins. Four `match` arms on `RegisteredBrowser.engine`
are acceptable and are not a defect to be abstracted away.

### 5. Identifier types

Ids are the existing public `report_core::{InstallationId, ProfileId}`, reused
internally rather than duplicated by crate-private twins. A signature must not
carry two adjacent same-typed id strings, so that a transposition is a compile
error. One signature still violates this: `source_identity(path, role: &str,
format: &str, precedence)` in `report_build.rs`, which the `SourceIdentity`
argument of Decision 1 removes. `outcome::source_digest` is not an instance --
it already takes typed arguments, and it hashes the browser, installation, and
profile ids on purpose.
`SourceCandidate.role` and `format` use the public `CookieSourceRoleId` /
`CookieSourceFormatId` vocabulary from construction; bare strings appear only
at the wire.

A direct-path read is "this path is the only candidate": one profile, no
discovery to consult, finalized through a single seam rather than by per-engine
identity construction. Its synthetic identity is frozen byte for byte — an
installation id of `"0"` repeated 64 times, a profile id of `"1"` repeated 64
times, and the display name `direct`. These feed `source_digest`, so changing
them is a public behavioural change, not a cleanup.

### 6. Module ownership

| Module | Owns | Must not own |
| --- | --- | --- |
| `browser/source.rs` | `SourceIdentity`, `SourceCandidate`, `Source`, `SourceFailure`, `SourceIssue`, `SourceStats`, `SourceAcquisition`, `SourceFailureStage` | profile identity, catalog, listing/extract bags, `DiscoveryIssue` |
| `browser/registry.rs` | catalog, `DiscoveryFs`, ids, `ProfileSelection`, discovery diagnostics and counters, `EngineProfileIdentity`, `LegacyRank`, listing/extract bags | source-leaf definitions, report mapping |
| `browser/registry/*.rs` | per-engine inventory; discover, select, lookup, acquire | cookie format decode and parsing |
| `browser/outcome.rs` | `Outcome`, `SourceOutcome`, finalize, `source_digest`, and the `CompatibilityDisposition` / `CompatibilityDecision` vocabulary any projection may name | engine bags, discovery, the compatibility *policy* that produces those values |
| `browser/compatibility.rs` | which browser families exist, which source-set rule each takes, which product string each emits | extraction `status`, assembly |
| `browser/report_core.rs` | the wire DTO and its ordering and aggregation helpers | engine types |
| `browser/report_build.rs` | dispatch arms, orchestration, finalize hand-off, wire projection, the single direct-path finalize seam | per-engine bag mappers, per-engine direct-path identity construction, compatibility disposition and its product strings |
| `browser/legacy.rs` | `LegacyFirstProfile` application and `Cookie` projection | paths, credentials, discovery |
| engine modules (`chromium.rs`, `mozilla.rs`, `safari.rs`, `internet_explorer.rs`) | path plus keys to `Source`; format decode; public `MozillaProfile` as an ADR 0002 projection | report identity, profile listing types |
| `browser/cookie_record.rs` | `CookieRecord`, `FinalizedCookieRecord` | — |

Crate-visible source representations are exactly `SourceCandidate`, then
`Source`, then the wire DTO. The draft hop that builds the wire report is
private to the module that projects it; it is an implementation detail of
projection, not a fourth representation for engines to target.

`common/sqlite.rs` is deliberately absent from the table. It is long, but it
has one job — acquisition capability — and is not split for architecture.

## Enforcement

- `cargo run -p xtask --locked -- check-stage-boundary` fences the types in
  Decision 1, in the same family as `check-cfg-locations` (issue #218). It
  runs in CI in the same job as that check, because a fence only a contributor
  remembers to run by hand is the social rule it exists to replace.
- Per-engine golden report snapshots pin listing and extract bytes, over
  normalized JSON so that temp-dir paths and path-derived opaque ids compare.
  A golden change requires an explicit re-golden commit stating the reason.
- Characterization tests remain the ADR 0001–0004 behavioural freeze. They
  migrate with the production code they pin; they are not deleted to make
  files smaller, and not rewritten in ways that weaken assertions.
- `scripts/check-public-api.py` stays green without editing snapshots.

Goldens are the belt over the characterization braces, and both are needed.
When a derivation moves between files, break it deliberately and confirm the
suite goes red before trusting that a green suite means it survived: four
invariants were found unpinned exactly that way, each closed with a test in
the PR that moved it.

## Amendments

This ADR was amended once, on 2026-08-19, from the follow-on program record
[after the type program](../design/after-the-type-program.md):

- **Decision 1** now says `Source` embeds `origin: SourceIdentity`, not
  `origin: SourceCandidate`. Auditing the one engine that had not adopted the
  original rule showed that a `Source`'s listing fields had no reader anywhere
  in the crate, while the same fields on a `SourceCandidate` have several. The
  fix was to narrow the position rather than to finish propagating the rule,
  which also turns the inherited-effective-value hazard into a compile error.
- **Decision 3** distinguishes the deleted *words* from today's identifiers,
  which keep their spellings.
- **Decision 5** states the two-adjacent-ids rule as a requirement with one
  known outstanding violation, rather than as an accomplished fact.
- **Decision 6** moves compatibility disposition out of `report_build.rs` to a
  new `browser/compatibility.rs`, on the line that `outcome.rs` owns values
  every projection may name while `compatibility.rs` owns the rule one
  projection applies.

## Alternatives rejected

1. **Carve files to a line budget** (GitHub #260, closed `NOT_PLANNED`).
   Treats length as the defect. After the carve, one bag type would still be
   both a candidate and a result, and every translator would remain.
2. **An engine-plugin trait** over Chromium, Gecko, Safari, and Internet
   Explorer. The engines have no shared behaviour worth abstracting; the
   missing abstraction was a data type.
3. **Test extraction alone** (`#[cfg(test)] #[path]` on the oversized files).
   Makes files scrollable while leaving the stage leak invisible to rustc.
   Available afterwards as a workbench when a production file is
   unreviewable; not a substitute for the type boundary.
4. **One profile bag with `candidates` beside `sources`.** A listing type
   that can name `Vec<Source>` still accepts a push into it; the absence of a
   `Default` impl does not prevent construction.
5. **One enum, `EngineSource { Candidate, Acquired }`.** Listing can still
   hold the acquired variant. Two types are the enforcement; an enum on a
   shared bag is not.

## Consequences

CI is the reviewer for stage leaks, so the boundary stays mechanical instead
of decaying into a social rule that survives only while its authors remember
it. Where a new field, engine, or source type belongs is answered by the
ownership table rather than re-argued per pull request.

The cost is that a genuinely source-level addition now requires editing the
fence in `xtask/src/stage_boundary.rs` along with the type. That friction is
the point: the edit is where a reviewer is asked whether the new field really
belongs to this stage.

Some files remain long, and that is accepted. A future proposal to shrink
them by carving, by an engine trait, or by a size lint should read the
rejected alternatives above before reopening the question.

## References

- Program record, with the full alternatives analysis and PR plan:
  [stage-boundary refactor](../design/stage-boundary-refactor.md)
- Fence implementation: `xtask/src/stage_boundary.rs`
- [ADR 0001](0001-cookie-extraction-compatibility-and-report-contracts.md) —
  the behavioural contract this decision leaves untouched
- [ADR 0002](0002-authoritative-browser-registry.md) — discovery and
  selection policies, and `LegacyFirstProfile`
- [ADR 0003](0003-unified-profile-query.md) — `select` / `ProfileQuery`
