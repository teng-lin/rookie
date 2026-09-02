# Isolation-safe send selection and explicit isolation loss

- **Author:** maintainers
- **Date:** 2026-09-01
- **Status:** Active program record (PR 0 of 7 landed; PRs 1–6 open)
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
- A live-browser e2e lane for Firefox port-partitioning
  (`privacy.dynamic_firstparty.use_site=false`).
- Extending `from-path --domains` with the new selector surface (stays
  compatibility-only; open question below).

## Engine encoding

### Chromium (`Cookies` SQLite, `top_frame_site_key` / `has_cross_site_ancestor`)

| Stored state | Verdict rule |
| --- | --- |
| `top_frame_site_key` empty/absent | Unpartitioned: sent in every top-level context |
| `top_frame_site_key` parses to a site, `has_cross_site_ancestor` is `0`/`1` | Matches iff `site == top_level_site` and stored bit `== (ancestor_chain == CrossSite)` |
| `top_frame_site_key` parses to a site, `has_cross_site_ancestor` is `NULL` | Never sent; counted `SendOmissions::ancestor_chain_unknown`; `ReadWarning` code `unknown_ancestor_chain` |
| `top_frame_site_key` present but unparsable | Never sent unless the selector supplies `top_level_site` matching nothing else parses it against; counted `unparsable_partition_key` |

Only pre-2024 Chromium schemas lack the `has_cross_site_ancestor` column at
all, which is the practical source of the `NULL` case above.

### Firefox persistent store (`cookies.sqlite`, `originAttributes` suffix)

`originAttributes` is a `^`-prefixed `key=value&key=value` suffix (or empty).
Known keys and their selector mapping:

| Key | Selector field | Default when absent from a present suffix |
| --- | --- | --- |
| `userContextId` | `user_context_id` | `0` |
| `privateBrowsingId` | `private_browsing_id` | `0` |
| `firstPartyDomain` | `first_party_domain` | none (absent = unset, not empty string) |
| `geckoViewSessionContextId` | `gecko_view_session_context_id` | none |
| `partitionKey` | derived into `PartitionIdentity` (see below) | none |
| any other key | only reachable via the raw `origin_attributes` selector | fails closed — never treated as default |

`partitionKey` grammar: `(scheme,host[,port][,f])`, strict. Anything else is
`Unparsable`. Verdict, given a parsed tuple:

- A non-empty `partitionKey` never matches a first-party context
  (`same_site_context && ancestor_chain == SameSite`).
- Otherwise: `site == top_level_site && port == derived_port(top_level_site) && f == (same_site_context && ancestor_chain == CrossSite)`.

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
| `first_party_domain` | `Option<String>` (new) | A row has a stored value |
| `gecko_view_session_context_id` | `Option<String>` (new) | A row has a stored value |
| `origin_attributes` | `Option<String>` (new; exact raw suffix) | A row has an unrecognized attribute name |
| `ancestor_chain` | `Option<AncestorChain>` (new) | Never demanded — derived from `top_level_site` when absent |
| Firefox partition port | *(no field)* | Never demanded — derived from `top_level_site`'s explicit port |

Canonical `required` order (fixed, append-only):
`top_level_site`, `user_context_id`, `private_browsing_id`,
`first_party_domain`, `gecko_view_session_context_id`, `origin_attributes`.

`SendOmissions` count order (fixed, first-failing-reason-wins):
`expired`, `not_applicable`, `same_site`, `partition`,
`ancestor_chain_unknown`, `unparsable_partition_key`, `origin`.

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
`read`/`from-path` for `--format json|netscape`. `render_cli_error` adds
`required` for `isolation_loss_refused` alongside the existing
`incomplete_send_context` case.

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

- [x] **PR 0** — ADR 0006, this program record, Phase-0 doc corrections
      (this change).
- [ ] **PR 1** — Rust core: `isolation.rs`, `send_view.rs`, `SendContext`
      selector fields, `ReadResult::send_view`, `header()` delegation,
      `unknown_ancestor_chain` warning, public-API snapshots, unit and
      collision tests.
- [ ] **PR 2** — Rust jar policy: `IsolationLoss`, `jar`/`into_jar`/
      `jar_with`/`into_jar_with`, `RequestError::IsolationLossRefused`.
- [ ] **PR 3** — Isolation collision corpus, `rookie-rs/tests/isolation_corpus.rs`,
      CLI `send-view` subcommand and selector flags, `--allow-isolation-loss`.
- [ ] **PR 4** — Python binding: `send_view`, `compatibility_cookies`,
      `as_jar`/`jar` opt-in kwargs, stub and typing updates.
- [ ] **PR 5** — Node binding: `sendView`, `JarOptions.allowIsolationLoss`,
      generated `.d.ts`/`.js` updates.
- [ ] **PR 6** — E2E depth extension, `browser_coverage.json` contract,
      final docs sweep (README/architecture/testing finalization beyond the
      PR 0 prose corrections).

## Open questions

- Should `from-path --domains` gain the new selector surface, or stay
  documented as compatibility-only indefinitely? Deferred; see ADR 0006 "Out
  of scope."
- Should the Firefox port-partitioning lane
  (`privacy.dynamic_firstparty.use_site=false`) get a real-browser e2e test
  in a later program, or stay covered only by the synthetic corpus?
- Should a pre-2024 Chromium store missing `has_cross_site_ancestor`
  entirely (not just `NULL` on a partitioned row) get a softer rule than
  "every partitioned row in it is omitted from every send view"? Current
  design treats it identically to a `NULL` value on the column; revisit if
  this turns out to affect a meaningfully large population of still-active
  Chromium installs.

## Risks

- The ancestor-chain derivation and its subdomain widening are the one
  semantic change to already-shipped `SameSite` behavior in this program;
  flagged for ADR review in PR 0 (ADR 0006 Decision 1), landing in PR 1.
- Old Chromium stores lose partitioned cookies from `header()`/`send_view`
  (counted and warned) by design, not by omission.
- Public-API Windows snapshots in PR 1/2 are hand-derived from the macOS/Linux
  diff; CI on Windows is the real check.
- Node header errors use the sync path; the shared `binding_error_details`
  keeps both paths aligned, but the sync-path `required` assertion needs to
  be added explicitly in PR 5, not assumed from the async path's coverage.
- `expected_counts` literals across three e2e files (PR 6) must change
  together or the lane will assert stale row counts against a real browser.

## References

- [ADR 0006](../adr/0006-isolation-safe-send-selection-and-explicit-isolation-loss.md)
  — durable decisions this program implements
- [ADR 0004](../adr/0004-read-is-the-recommended-entry.md) — `read`/`header`
  contract this program amends
- Issue #331; predecessors #177, #299, #325, #333
- `docs/design/stage-boundary-refactor.md` — the program-record format this
  document follows
