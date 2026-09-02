# Isolation-safe send selection and explicit isolation loss

- **Author:** maintainers
- **Date:** 2026-09-01
- **Status:** Program complete. PRs 0–6 are merged on
  `worktree-issue-331` and delivered as one pull request against `main`.
  See the PR plan and acceptance mapping below for the commits that carried
  each one.
- **Crate/packages:** `rookie-rs`, `bindings/python` (`rookie_cookies`),
  `bindings/node` (`rookie-cookies`), `cli`
- **Release context:** 0.7
- **Durable decisions live in [ADR
  0006](../adr/0006-isolation-safe-send-selection-and-explicit-isolation-loss.md).**
  This document is the program record: background, engine encoding detail,
  per-language signatures, the collision corpus, the e2e plan, and the PR
  plan. Where the two disagree about a rule, the ADR wins; where the ADR is
  silent about *how* a PR gets there, this document is the reference.
- **Tracking issue:** #331

---

## Overview

Issue #331 is the 0.7 successor to architecture gap A1 (#177 → PR #299 →
#333, see Background). Two gaps survive #299: `header()` matches on an
incomplete partition/origin identity, and the compatibility jar family
(`jar`/`as_jar`/`cookies` in Rust/Python/Node, `--format json|netscape` on
the CLI) silently flattens isolated cookies with no error and no count. This
program closes both, across Rust, Python, Node, and the CLI, with one shared
Rust selection implementation, a synthetic collision-test corpus, and an
extended real-browser e2e lane.

## Background

### A1 history

- **#177 / early architecture review** first named "header collapses through
  the frozen `Cookie` projection before matching" as a gap.
- **PR #299** fixed the primary defect: `ReadResult` retains
  `Vec<DetailedCookie>` natively, `header(&SendContext)` matches against
  those detailed records instead of the eight-field projection, and a
  missing selector produces typed `RequestError::IncompleteSendContext`
  instead of merging every observed partition. This is why the issue
  describes the "header collapses through `Cookie`" language as already
  stale — it is, and the Phase 0 doc corrections in this PR remove the last
  places that still implied otherwise.
- **#333** deleted `docs/architecture_api_gap_consolidated.md`, the document
  the issue names as its Phase 0 target. There is nothing left to strike
  through in that file; Phase 0 is prose corrections elsewhere plus this ADR
  and program record.
- **#331** (this program) is scoped to what #299 left open: partition/origin
  identity completeness, and the jar-family loss policy.

### What is already safe

- `ReadResult::header` (`rookie-rs/src/read.rs:286-414`) iterates detailed
  records, resolves the clock, demands selectors via `missing_selectors`
  before matching anything, applies domain/path/Secure/expiry, and calls
  `isolation_matches` before formatting.
- Python and Node both expose `detailed_cookies()`/`detailedCookies` and a
  structured `SendContext`/context object.
- The README's explanation that a bare URL fails when selectors are required
  is accurate as written.

### The two residual gaps, with evidence

**Gap 1 — partition/origin identity is incomplete.**

| Where | What it does today | What it misses |
| --- | --- | --- |
| `rookie-rs/src/header_filter.rs:132-166` (`PartitionIdentity`, `partition_identity`) | Reduces both engines' partition key to `(scheme, host)` via `Site` | Chromium ancestor bit; Firefox port and foreign-ancestor bit |
| `rookie-rs/src/browser/chromium_decoder.rs:143-149` | Captures `has_cross_site_ancestor` into `CookieContext` at decode time | Never read by selection |
| `rookie-rs/src/read.rs:453-490` (`isolation_matches`) | Compares `PartitionIdentity::Site` values | Does not consult `has_cross_site_ancestor` at all |
| `rookie-rs/src/read.rs:296-304` (doc comment) | Already discloses the limitation | — |
| `rookie-rs/src/header_filter.rs:90-102` (`site_from_firefox_partition_key`) | Parses `(scheme,host)` and stops | Discards any trailing port / `f` field; test `a_firefox_partition_tuple_with_extra_fields_still_matches` currently blesses this |
| `rookie-rs/src/browser/mozilla.rs:133-155` (`firefox_cookie_context`) | Parses `userContextId`, `partitionKey`, `privateBrowsingId` | `firstPartyDomain`, `geckoViewSessionContextId`, and any unrecognized name fall into `_ => {}` and read as default during selection |

**Gap 2 — the compatibility jar is a silent lossy projection.**

| Where | What it does today |
| --- | --- |
| Rust `jar()`, `read.rs:559` | `read(request)?.into_cookies()` — unconditional, infallible |
| Python `ReadResult.as_jar()` / free `jar()`, `bindings/python/rookie_cookies/__init__.py:204-208` | Calls `as_list()`, builds a stdlib `CookieJar`, no error path |
| Node `jar`, `bindings/node/src/lib.rs:1846` | Resolves `ReadResult::into_cookies()` to `CookieObject[]` |
| CLI `--format json\|netscape` | Same flatten, no count, no warning |

None of `http.cookiejar.CookieJar`, Netscape rows, or a flat `CookieObject[]`
has a field for a CHIPS partition key, a Firefox `partitionKey` tuple, or
Firefox container/private-browsing identity, so there is structurally no way
to extend those formats to preserve it. The fix is not "add fields" — it is
making the jar refuse when it would need to drop something, and giving the
caller an explicit, named way to accept that loss.

## Goals / non-goals

**Goals**

- Match on the complete Chromium partition key (site + ancestor bit) and the
  complete Firefox partition tuple (scheme, host, port, foreign-ancestor
  bit) plus every `OriginAttributes` equality field.
- Fail closed on an unrecognized origin-attribute name rather than treating
  it as default.
- One Rust selection implementation (`send_view`) that `header()` and every
  binding/CLI surface renders from, never reimplements.
- A `jar` family that cannot silently return a context-collapsed result
  after observing isolation-bound cookies, with byte-identical output
  preserved behind an explicit opt-in.
- Equivalent selector semantics and structured failures across Rust, Python,
  Node, and the CLI, proven by one shared collision corpus.

**Non-goals** (see ADR 0006 "Out of scope" for the durable statement)

- A public-suffix list or registrable-domain dataset.
- Browser policy heuristics: storage-access grants, First-Party Sets,
  related-site sets.
- Nonce-keyed/ephemeral partitions.
- A live-browser e2e lane for Firefox port-partitioning (a top-level page on
  a non-default port under the default configuration; no pref is involved).
- Extending `from-path --domains` with the new selector surface (stays
  compatibility-only; open question below).

## Engine encoding

### Chromium (`Cookies` SQLite, `top_frame_site_key` / `has_cross_site_ancestor`)

| Stored state | Verdict rule |
| --- | --- |
| `top_frame_site_key` empty/absent | Unpartitioned: sent in every top-level context |
| `top_frame_site_key` parses to a site, `has_cross_site_ancestor` is `0`/`1` | Matches iff `site == top_level_site` and stored bit `== (ancestor_chain == CrossSite)` |
| `top_frame_site_key` parses to a site, `has_cross_site_ancestor` is `NULL` | Never sent; counted `SendOmissions::ancestor_chain_unknown`; `ReadWarning` code `unknown_ancestor_chain` |
| `top_frame_site_key` present but unparsable | Never sent, regardless of the selector supplied; demands `top_level_site` so the snapshot's other, parsable partitioned rows are not silently sent as if this row were absent; counted `unparsable_partition_key` |

A store last written by a Chromium that predates the `has_cross_site_ancestor`
column is the practical source of the unknown-bit case above (absent column,
`NULL`, or a value other than `0`/`1` all count as unknown). Chromium's own
schema migration may backfill a value when it next opens the store; the crate
deliberately does not infer one. The stored key's optional port is identity
and must equal the `top_level_site` URL's explicit port; the former
port-stripping is retired.

### Firefox persistent store (`cookies.sqlite`, `originAttributes` suffix)

`originAttributes` is a `^`-prefixed `key=value&key=value` suffix (or empty).
Known keys and their selector mapping:

| Key | Selector field | Default when absent from a present suffix |
| --- | --- | --- |
| `userContextId` | `user_context_id` | `0` |
| `privateBrowsingId` | `private_browsing_id` | `0` |
| `firstPartyDomain` | `first_party_domain` | `""` (Firefox omits the default empty value) |
| `geckoViewSessionContextId` | `gecko_view_session_context_id` | `""` |
| `partitionKey` | derived into `PartitionIdentity` (see below) | none (unpartitioned) |
| any other key, or an unreadable value under a known key | only reachable via the raw `origin_attributes` selector | fails closed — never treated as default |

The raw `origin_attributes` selector governs only *opaque* rows (an
unrecognized attribute name, an unreadable value under a known name, or an
unparsable `partitionKey`): such a row is selected iff the selector equals
its stored suffix byte-for-byte. Non-opaque rows ignore it and are governed
by the typed selectors and the partition verdict, so one future-Firefox row
never prevents unpartitioned and partitioned rows from combining.

`partitionKey` grammar: `(scheme,host[,port][,f])`, strict. Anything else is
`Unparsable`. Verdict, given a parsed tuple:

- A non-empty `partitionKey` never matches a first-party context
  (`same_site_context`, i.e. `sites_match && resolved_ancestor == SameSite`).
- Otherwise: `site == top_level_site && port == derived_port(top_level_site) && f == (sites_match && resolved_ancestor == CrossSite)` — the `f` bit marks the A→B→A shape (sites match, chain cross-site); note the first term is the raw site comparison, not the SameSite gate, which is false whenever the chain is cross-site.

`derived_port` is `Url::port()` on the caller's `top_level_site` — `None` for
the scheme's default port, matching how Firefox omits the port field for a
default-port partition.

### Firefox session store (`sessionstore.js` / `recovery.jsonlz4`)

Same `originAttributes` suffix grammar, parsed by the same shared
`parse_firefox_origin_attributes` function the persistent-store decoder
uses (`rookie-rs/src/browser/mozilla_session.rs:800-831` today duplicates
logic that PR 1 consolidates into `isolation.rs`). No separate verdict rule:
a session-store row is evaluated identically to a persistent-store row once
its `CookieContext.origin_attributes` is populated.

## Selector and token table

| `SendContext` field | Type | Demanded when |
| --- | --- | --- |
| `top_level_site` | `Option<String>` (existing) | Any row has a non-`Unpartitioned` partition identity |
| `user_context_id` | `Option<u32>` (existing) | A row has a non-`None`, non-`Some(0)` value |
| `private_browsing_id` | `Option<u32>` (existing) | A row has a non-`None`, non-`Some(0)` value |
| `first_party_domain` | `Option<String>` (new) | A row has a stored, non-empty value (the filled `""` default never demands) |
| `gecko_view_session_context_id` | `Option<String>` (new) | A row has a stored, non-empty value (the filled `""` default never demands) |
| `origin_attributes` | `Option<String>` (new; exact raw suffix) | A row has an unrecognized attribute name, or an unreadable value under a known name |
| `ancestor_chain` | `Option<AncestorChain>` (new) | Never demanded — derived from `top_level_site` when absent |
| Firefox partition port | *(no field)* | Never demanded — derived from `top_level_site`'s explicit port |

The `ancestor_chain` derivation (request host equals or is a subdomain of
the caller-normalized top-level site host, same scheme, ⇒ `SameSite`;
otherwise `CrossSite`) has one exemption: when either host is an IPv4 or
IPv6 literal, site membership is exact host equality, never a subdomain
check — an IPv6 host is compared without its brackets, matching
`site_from_url`'s existing normalization. The same exemption applies to
`same_site_context` (ADR 0006 Decision 1).

Canonical `required` order (fixed, append-only):
`top_level_site`, `user_context_id`, `private_browsing_id`,
`first_party_domain`, `gecko_view_session_context_id`, `origin_attributes`.

`SendOmissions` has two independent orders (ADR 0006 Decision 2). Attribution
— which reason a row is counted under — follows row evaluation order:
expired, then `not_applicable` (domain/path/Secure), then the isolation
verdict (`partition` / `ancestor_chain_unknown` / `unparsable_partition_key`
/ `origin`), then `same_site`; each row is counted once, under its first
failing reason. Serialization — the order `SendOmissions::entries()` yields,
which bindings surface verbatim — is fixed separately as: `expired`,
`not_applicable`, `same_site`, `partition`, `ancestor_chain_unknown`,
`unparsable_partition_key`, `origin`. The two orders disagree on where
`same_site` sits and that is intentional, not an inconsistency to fix.

## API changes per language

### Rust (`rookie-rs`)

```rust
// send_context.rs
impl SendContext {
    pub fn ancestor_chain(self, chain: AncestorChain) -> Self;
    pub fn first_party_domain(self, domain: impl Into<String>) -> Self;
    pub fn gecko_view_session_context_id(self, id: impl Into<String>) -> Self;
    pub fn origin_attributes(self, raw: impl Into<String>) -> Self;
}

#[non_exhaustive]
pub enum AncestorChain { SameSite, CrossSite }

// send_view.rs
impl<'a> SendView<'a> {
    pub fn cookies(&self) -> &[&'a DetailedCookie];
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn header(&self) -> String;
    pub fn omitted(&self) -> &SendOmissions;
    pub fn to_detailed_cookies(&self) -> Vec<DetailedCookie>;
}

#[non_exhaustive]
pub struct SendOmissions { /* getters + entries() + total() */ }

impl ReadResult {
    pub fn send_view(&self, context: &SendContext) -> Result<SendView<'_>>;
    // header() unchanged in signature; renders from send_view internally.

    pub fn jar(&self) -> Result<&[Cookie]>;
    pub fn into_jar(self) -> Result<Vec<Cookie>>;
    pub fn jar_with(&self, policy: IsolationLoss) -> Result<&[Cookie]>;
    pub fn into_jar_with(self, policy: IsolationLoss) -> Result<Vec<Cookie>>;
}

#[non_exhaustive]
pub enum IsolationLoss { Refuse, Allow }
```

`RequestError::IsolationLossRefused { isolated_rows: u64, required: Vec<String> }`,
code `isolation_loss_refused`. Free `jar(request)` is
`read(request)?.into_jar()`.

### Python (`bindings/python`)

```python
class ReadResult:
    def send_view(self, context: SendContextMapping | str) -> SendViewDict: ...
    def compatibility_cookies(self, *, allow_isolation_loss: bool = False) -> list[Cookie]: ...
    def as_jar(self, *, allow_isolation_loss: bool = False) -> http.cookiejar.CookieJar: ...

def jar(*, allow_isolation_loss: bool = False, **read_kwargs) -> http.cookiejar.CookieJar: ...
```

`SendContextMapping` gains `ancestor_chain: Literal["same_site", "cross_site"]`,
`first_party_domain: str`, `gecko_view_session_context_id: str`,
`origin_attributes: str`. `RookieError.required` gains coverage for
`isolation_loss_refused` in `bindings/python/src/errors.rs:278-281`.

### Node (`bindings/node`)

```ts
interface SendContextObject {
  // existing fields …
  ancestorChain?: AncestorChain;
  firstPartyDomain?: string;
  geckoViewSessionContextId?: string;
  originAttributes?: string;
}
type AncestorChain = "same_site" | "cross_site";

interface JarOptions extends ReadOptions {
  allowIsolationLoss?: boolean;
}

class ReadResult {
  sendView(context: SendContextObject | string): SendViewObject;
  // header() unchanged in signature; renders from sendView internally.
}
```

`allowIsolationLoss` lives on `JarOptions`, not `ReadOptions`, so it cannot
be silently ignored by a non-jar call. `binding_error_details` (sync and
async paths) gains a `required` arm for `IsolationLossRefused`.

### CLI

New `send-view` subcommand: prints
`{"cookies": [...detailed...], "header": "...", "omitted": {...}}`. New
flags on `header`/`send-view`: `--ancestor-chain same-site|cross-site`,
`--first-party-domain`, `--gecko-view-session-context-id`,
`--origin-attributes`, `--now <epoch>`. New `--allow-isolation-loss` on
`read`/`from-path` for `--format json|netscape`. `render_cli_error` gains a
`required` field — the CLI does not emit it today for any code, including
`incomplete_send_context` — and adds it for both `incomplete_send_context`
and the new `isolation_loss_refused`; both arms land together in PR 3, each
with its own CLI test.

## Isolation collision corpus

- **Location:** `tests/isolation_corpus/` (top level, deliberately not under
  `tests/e2e/`, whose discovery and `browser_coverage.json` contract concern
  real browsers, not synthetic collision fixtures).
- **Shape:** `corpus.json` with four named stores (`chromium_isolated`,
  `chromium_plain`, `firefox_isolated`, `firefox_plain`), a fixed
  `clock_epoch_seconds`, and `cases[]`. Every seeded row's `value == id` so a
  case can assert identity by id alone. Each case names a snake_case
  `context` and an `expect` — either ordered `selected` ids plus `header`
  plus `omitted` counts, or `error { code, required }` — plus a per-store
  `jar` verdict.
- **Generator:** `build_isolation_corpus.py` (stdlib only). Writes a
  Chromium `Cookies` database at schema 24 with `top_frame_site_key`,
  `has_cross_site_ancestor`, `source_scheme`, `source_port`, `is_persistent`,
  and plaintext `value`; a Firefox `cookies.sqlite` at `user_version` 16 with
  `originAttributes`. `--write-node-fixtures` emits the same stores as
  base64 for the Node corpus test.
- **Validator:** `test_build_isolation_corpus.py` checks the generated
  schema, the token vocabulary and order against ADR 0006 Decision 5, and
  byte equality between a fresh generation and the committed Node base64
  fixtures.
- **Case inventory:** Chromium ancestor bit `0`/`1`/`NULL`; Firefox port
  present/default/absent; Firefox `f` bit both values; Firefox origin
  attributes across six suffixes (`''`, `userContextId=2`,
  `privateBrowsingId=1`, `firstPartyDomain=...`,
  `geckoViewSessionContextId=...`, `futureAttr=1`); site cases (sibling
  subdomain, child subdomain, explicit port, IDN, IPv4, IPv6); a structural
  `header == send_view.header` check per case; jar verdicts including
  opt-in byte-identity against the pre-ADR flatten.
- **Per-language consumption:** `rookie-rs/tests/isolation_corpus.rs` seeds
  via `rusqlite`; `cli/tests/isolation_corpus.rs` drives the CLI;
  `tests/python/test_isolation_corpus.py` and
  `__test__/isolation-corpus.spec.mjs` drive Python and Node against the
  same `corpus.json`/fixtures so all four surfaces are checked against one
  source of truth.

## E2E extension plan

- New host `nested.rookie-a.test` and routes `/chain-top` (a direct
  same-site iframe and an A→B→A relay through `third.rookie-b.test`) and
  `/set-ancestor` (sets a `Partitioned`, `SameSite=None`, `Secure`
  `rookie_ancestor` cookie) in `tests/e2e/context_cookie_server.py`.
- `seed_partitioned_cookie.mjs` navigates `/chain-top`, waits for both
  ancestor identities to be seeded, and reads Chromium's own
  `Storage.getCookies` `partitionKey.hasCrossSiteAncestor` as a browser-side
  oracle to compare against what this crate parses from the persisted row.
- `run_partition_context_e2e.py`'s raw manifest becomes the single source of
  row-count expectations (5/7 → 7/9) that
  `assert_partitioned_context.py`/`run_partition_context_e2e.py`/
  `seed_partitioned_cookie.mjs` all read, instead of three independently
  maintained literals.
- Four surfaces (`assert_partitioned_context.py`/`.mjs`,
  `rookie-rs/tests/e2e_context.rs`, `assert_partitioned_context_cli.py`)
  assert an exact `send_view` selected set per context (nested-under-self
  explicit same/cross, derived, and B-under-A) and exact `required` tokens
  on a refusal.
- `run_firefox_container_e2e.py` gains an exact-set assertion for
  `send-view --user-context-id` and an `--origin-attributes "<exact
  suffix>"` round-trip that selects the same record two ways.
- `tests/e2e/browser_coverage.json` gains a `send_selection` depth
  capability that every `depth_profiles` entry must declare.

## PR plan

The plan below is the shape the program was designed in; the commits that
carried each item are the record of how it actually landed. PR 3 was split in
two — the corpus and generator (3a) landed before the Rust core so PR 1 could
be written against a fixed oracle, and the Rust/CLI consumers (3b) landed
after it. PRs 1 and 2 landed as one branch, because `jar`'s refusal predicate
is the same "demanded selectors would be non-empty" computation PR 1
introduces and splitting them would have meant shipping a half-wired
`IsolationLoss`.

- [x] **PR 0** — ADR 0006, this program record, Phase-0 doc corrections.
      `6f5d624`, `299bc7a`, `4f15aad`, plus the review follow-ups `16c8762`,
      `975f5b6`, `dbce572`, `473d3d4`, `f0dbfc1`.
- [x] **PR 3a** — Isolation collision corpus and store generator, landed
      first as the oracle PR 1 is written against. `489faa8`, `d89c66f`,
      `b213da2`, merged as `5227018`.
- [x] **PR 1** — Rust core: `isolation.rs`, `send_view.rs`, `SendContext`
      selector fields, `ReadResult::send_view`, `header()` delegation,
      `unknown_ancestor_chain` warning, public-API snapshots, unit and
      collision tests, `CHANGELOG.md`. `4955ff5`.
- [x] **PR 2** — Rust jar policy: `IsolationLoss`, `jar`/`into_jar`/
      `jar_with`/`into_jar_with`, `RequestError::IsolationLossRefused`.
      `c14c2ca`, merged with PR 1 as `4b7af91`.
- [x] **PR 3b** — `rookie-rs/tests/isolation_corpus.rs`, CLI `send-view`
      subcommand and selector flags, `--allow-isolation-loss`,
      `render_cli_error`'s new `required` field for `incomplete_send_context`
      and `isolation_loss_refused`, with a CLI test for each, and the
      `from-path --domains` policy gate. `0ac0714`, `6eb1219`, `7770ec3`,
      merged as `623da20`. `b61477d`, which made the
      `isolation_loss_refused` message language-neutral, landed on this lane
      after the PR 1+2 merge even though its subject belongs to PR 2.
- [x] **PR 4** — Python binding: `send_view`, `compatibility_cookies`,
      `as_jar`/`jar` opt-in kwargs, stub and typing updates. `e0a1eea`,
      `9170aa3`, merged as `614ee11`.
- [x] **PR 5** — Node binding: `sendView`, `JarOptions.allowIsolationLoss`,
      generated `.d.ts`/`.js` updates. `1ec0e0b`, `0bcde24`, merged as
      `d9ee18f`.
PR 6 was split along its two independent halves so the documentation sweep
did not have to wait on a real-browser lane:

- [x] **PR 6a** — E2E depth extension and the `browser_coverage.json`
      `send_selection` capability contract (`bd1d128`, `3f591e8`): the
      partition lane seeds an A→B→A ancestor chain, derives every send view
      from the browsers' own SQLite rows, enforces literal positive floors on
      all four surfaces, and passed `e2e-depth.yml` on both engines.
- [x] **PR 6b** — Final documentation sweep: the four package READMEs,
      `docs/architecture.md`, `docs/testing.md`, the ADR 0004/0006 status
      wording, this record, and the consolidated `CHANGELOG.md` Unreleased
      section. `079274e`, plus the review follow-up that landed on top of it.

## Acceptance mapping (issue #331 checklist → PR)

- Docs no longer claim `header()` collapses through `Cookie` → PR 0
  (`6f5d624`), finished by PR 6b's documentation sweep (`079274e`).
- Chromium ancestor bit gated; Firefox scheme/base domain/port/foreign bit;
  all Firefox `OriginAttributes` equality fields; unknown attributes fail
  closed → PR 1 (`4955ff5`).
- One core selection producing both the detailed set and the header → PR 1
  (`4955ff5`): `ReadResult::send_view`, with `header()` rendering from it.
- Equivalent selector semantics and structured failures on Rust/Python/
  Node/CLI → PRs 3a/3b, 4, 5 (`489faa8`, `0ac0714`, `6eb1219`, `e0a1eea`,
  `1ec0e0b`); the corpus asserts identical selected sets and identical
  `code`/`required` from all four surfaces.
- `jar`/`as_jar` cannot silently flatten; eight-field output byte-stable
  behind opt-in → PR 2 (`c14c2ca`), CLI in PR 3b (`6eb1219`, `7770ec3`),
  Python in PR 4 (`e0a1eea`), Node in PR 5 (`1ec0e0b`).
- Synthetic collision tests and real-browser context tests green → PR 3a
  (`489faa8`) for the synthetic half; the real-browser half is PR 6a.

## Open questions

- Should `from-path --domains` gain the new selector surface, or stay
  documented as compatibility-only indefinitely? Still deferred (ADR 0006
  "Out of scope"), but the route is no longer an isolation-loss bypass:
  PR 3b (`7770ec3`) made it open the path a second time through `from_path`
  and call `into_jar_with` purely as a policy gate, discarding that snapshot
  before running the flat job. Its printed bytes are unchanged; what changes
  is that an isolated store is now refused there too unless
  `--allow-isolation-loss` is passed. The open question is only whether the
  route should gain selectors, not whether it should be gated.
- Should the Firefox port-partitioning lane (a non-default-port top-level
  page under the default configuration) get a real-browser e2e test in a
  later program, or stay covered only by the synthetic corpus? Still open:
  the port rule shipped in PR 1 and is unit- and corpus-tested, and no
  live-browser lane exercises it.
- Should a pre-2024 Chromium store missing `has_cross_site_ancestor`
  entirely (not just `NULL` on a partitioned row) get a softer rule than
  "every partitioned row in it is omitted from every send view"? Still open,
  and the shipped behavior is the strict one: an unknown ancestor bit fails
  closed, counted under `SendOmissions::ancestor_chain_unknown` per view and
  as the `unknown_ancestor_chain` read warning. Revisit if this turns out to
  affect a meaningfully large population of still-active Chromium installs.
- Should a Firefox CHIPS cookie set in a first-party context be selectable
  from that context? The real-browser lane (PR 6a) showed Firefox stores a
  `Partitioned` cookie set by a direct same-site iframe with
  `partitionKey=(https,site)`, exactly like a third-party partition, and
  would send it to a first-party request under that site. ADR 0006's
  "a partitioned Firefox row never matches a first-party context" rule
  withholds it, so the Firefox `nested_derived`/`nested_same_site` send views
  in that lane select nothing while Chromium's select the bit-0 row. This is
  the conservative direction (a withheld cookie, never an over-sent one) and
  the lane pins both engine shapes; the candidate relaxation is to drop the
  first-party guard and rely on `site == top_level_site && port && f ==
  (sites_match && resolved == CrossSite)` alone, which in a first-party
  context matches only a row whose partition is the request's own site with
  `f` unset. Deferred to a follow-up because it changes the corpus, the
  binding suites, and the e2e oracle together.

## Risks

- The ancestor-chain derivation and its subdomain widening are the one
  semantic change to already-shipped `SameSite` behavior in this program;
  flagged for ADR review in PR 0 (ADR 0006 Decision 1), landed in PR 1, and
  called out as breaking in the changelog.
- Old Chromium stores lose partitioned cookies from `header()`/`send_view`
  (counted and warned) by design, not by omission.
- Public-API Windows snapshots in PR 1/2 were hand-derived from the
  macOS/Linux diff; CI on Windows is the real check.
- Node header errors use the sync path; the shared `binding_error_details`
  keeps both paths aligned, and PR 5 added the sync-path `required` assertion
  explicitly rather than inheriting the async path's coverage.
- The e2e row inventory and send-view floors live in one table
  (`tests/e2e/partition_context_inventory.json`, PR 6a); a change to the
  seeded cookies must update that file, or the lane asserts stale counts
  against a real browser.

## References

- [ADR 0006](../adr/0006-isolation-safe-send-selection-and-explicit-isolation-loss.md)
  — durable decisions this program implements
- [ADR 0004](../adr/0004-read-is-the-recommended-entry.md) — `read`/`header`
  contract this program amends
- Issue #331; predecessors #177, #299, #325, #333
- `docs/design/stage-boundary-refactor.md` — the program-record format this
  document follows
