# ADR 0006: Isolation-safe send selection and explicit isolation loss

- Status: Accepted
- Date: 2026-09-01
- Scope: the send-context selector shape, the single send-selection
  operation, and the jar/compatibility-projection loss policy across Rust,
  Python, Node, and the CLI
- Amends: ADR 0004 §1, §3, §5, and Consequences
- Does not amend: ADR 0001–0003 behavior, ADR 0005 (internal extraction
  vocabulary; untouched by this ADR), the public API baseline beyond the
  additions listed under Consequences, the report DTO and
  `schema/report-dto.schema.json`, or `rookie-rs/browser_registry.json`
- Program record: [isolation-safe send
  selection](../design/isolation-safe-send-selection.md) — engine encoding
  tables, per-language signatures, the collision corpus, the e2e plan, and
  the PR plan

## Context

Issue #177 and PR #299 (ADR 0004 §3 and §5, amended in 0.6.0) already fixed
the primary defect in the original architecture-gap note: `header()` no
longer collapses the snapshot through the frozen eight-field `Cookie` before
matching. `ReadResult` retains `Vec<DetailedCookie>` natively, `header(&SendContext)`
demands a selector rather than silently merging observed partitions, and that
demand is typed (`RequestError::IncompleteSendContext`). Issue #331 is the
0.7 successor, scoped to the two gaps that survived #299 — both re-verified
against this tree rather than assumed from the issue text:

1. **The partition key `header()` matches on is incomplete.**
   `PartitionIdentity` (`rookie-rs/src/header_filter.rs:132-166`) reduces both
   engines' partition identity to `(scheme, host)`. Chromium's
   `has_cross_site_ancestor` bit is captured at decode time
   (`rookie-rs/src/browser/chromium_decoder.rs:143-149`) but never consulted
   by `isolation_matches` (`rookie-rs/src/read.rs:453-490`; the limitation is
   already disclosed in the `header` doc comment at `read.rs:296-304`). Two
   Chromium rows with the same top-level site and different ancestor-chain
   bits therefore both match one `SendContext`. The Firefox tuple parser
   (`site_from_firefox_partition_key`, `header_filter.rs:90-102`) reads only
   scheme and host and discards any trailing port or foreign-ancestor `f`
   field; the existing test
   `a_firefox_partition_tuple_with_extra_fields_still_matches` blesses that
   as current behavior, and this ADR retires it. Firefox origin-attribute
   parsing (`firefox_cookie_context`, `rookie-rs/src/browser/mozilla.rs:133-155`)
   recognizes only `userContextId`, `partitionKey`, and `privateBrowsingId`;
   `firstPartyDomain`, `geckoViewSessionContextId`, and any attribute name it
   does not recognize fall into a `_ => {}` arm and are retained on
   `CookieContext.origin_attributes` for inventory but behave like the
   default context during selection — a stored non-default value is
   indistinguishable from an unset one at the point `header()` matches.
2. **The compatibility jar is a silent lossy projection.** Rust `jar()`
   (`read.rs:559`, `read(request)?.into_cookies()`), Python
   `ReadResult.as_jar()` / free `jar()` (`bindings/python/rookie_cookies/__init__.py:204-208`,
   via `as_list()`), Node `jar` (`bindings/node/src/lib.rs:1846`, resolving
   `into_cookies()`), and the CLI's `--format json|netscape` all flatten to
   the eight-field compatibility shape unconditionally, with no error and no
   count. `http.cookiejar.CookieJar`, Netscape-format rows, and a flat
   `CookieObject[]`/`Cookie[]` have no field for a Chromium CHIPS partition
   key, a Firefox `partitionKey` tuple, or Firefox container/private-browsing
   identity — there is no cell in any of those shapes to put that state, so
   no encoding of it, however clever, would let a caller round-trip it back
   into a request. A successful jar call is therefore currently
   indistinguishable from one that dropped isolation-bound credentials into
   an unscoped bag.

`docs/architecture_api_gap_consolidated.md`, the document issue #331 names as
its Phase 0 target, was deleted by PR #333; the "header collapses through
`Cookie`" claim it recorded is already absent from the README and
`docs/architecture.md`. Phase 0 (this PR) therefore reduces to this ADR, the
program record, and a small number of residual prose corrections that
predate this ADR's decisions (stale `.cookies()` naming, an `http.cookiejar`
send-match claim ADR 0004 §3 never actually made this precisely, and one
"merges" sentence in the Node README that should say "discards").

## Decision

### 1. One canonical flat selector on `SendContext`

`SendContext` gains four new fields, flat — no nested `IsolationSelector`
struct (see Rejected alternatives): `ancestor_chain: Option<AncestorChain>`,
`first_party_domain: Option<String>`,
`gecko_view_session_context_id: Option<String>`, and
`origin_attributes: Option<String>`. `AncestorChain` is `SameSite | CrossSite`,
public and `#[non_exhaustive]`. `user_context_id` and `private_browsing_id`
are already flat fields on `SendContext`; the new fields join them as peers,
and every binding maps its context mapping/dict/object keys onto this set
1:1 — bindings never introduce a nested selector object.

**Firefox partition port.** There is no separate port selector and no demand
token for it. The port is derived from the explicit port of the caller's
`top_level_site` URL (`Url::port()`; `None` for the scheme's default port),
because the port a Firefox `partitionKey` records is exactly the top-level
URL's port and asking the caller to state it twice invites the two copies to
disagree.

**Engine encodings this selector must resolve to, at match time:**

- **Chromium.** The persisted key is a schemeful site plus the
  `has_cross_site_ancestor` bit. A stored row matches when its site equals
  the request's normalized `top_level_site` and its stored bit equals
  `ancestor_chain == CrossSite` (`Some(true)` for `CrossSite`, `Some(false)`
  for `SameSite`). Port-stripping on the site key is retained: Chromium
  serializes a *site* (no port), and the origin-with-port spelling some
  versions persist is a migrated older schema, not a second identity.
- **Firefox `partitionKey`.** The tuple grammar is strict:
  `(scheme,host[,port][,f])`. Anything else — extra fields, a malformed
  bracket, a non-numeric port — is `Unparsable`, not "ignore the tail and
  match on scheme+host" (the behavior this ADR retires). A partitioned
  Firefox row (non-empty `partitionKey`) never matches a first-party context
  (`same_site_context && ancestor_chain == SameSite`) — a partition, by
  construction, is not the unpartitioned default context. Otherwise the row
  matches when `site == top_level_site`, `port == derived top-level port`,
  and `f == (same_site_context && ancestor_chain == CrossSite)`.
- **Firefox `OriginAttributes` equality.** Every field Mozilla's
  `OriginAttributes` includes in equality is represented:
  `userContextId`, `privateBrowsingId`, `partitionKey` (via the partition
  rule above), `firstPartyDomain`, and `geckoViewSessionContextId`. A stored
  value for one of these attributes is either present (parsed and compared
  exactly against the corresponding selector field) or genuinely absent —
  never silently coerced to a default.

**Unknown stored value is never a default match.** A crate-internal
`StoredIsolation`, computed once per row, parses `origin_attributes` fully:
the five known attribute names plus a catch-all "this attribute name is
present but this build does not know it" fact. Firefox omits
default-valued attributes from the serialized suffix, so
`StoredIsolation` fills `user_context_id = 0` and `private_browsing_id = 0`
only when an `origin_attributes` value is present at all (an empty suffix
`^` or a wholly absent one) — a row with no origin-attributes information at
all stays genuinely unknown rather than assumed-default. A stored `None`
(unknown) never matches a supplied selector, and a supplied selector never
matches a stored unrecognized attribute name: an unrecognized name can only
be reached by the exact `origin_attributes` raw-suffix selector (Decision 5),
never inferred from the five typed fields.

**Missing selector is demanded only when observed.** A token is added to
`required` if and only if some row in the snapshot positively observes a
non-default value for that dimension. `None` and `Some(0)` container ids
never demand a token — that would make `header()` unusable against every
store that lacks the column. An `Unparsable` partition key demands
`top_level_site` (there is no other way to disambiguate it). Any
unrecognized attribute name demands `origin_attributes`.

**Ancestor chain when the caller does not supply one.** Derived as: the
request host equals or is a subdomain of the caller-normalized top-level
site host, on the same scheme, is `SameSite`; otherwise `CrossSite`. An
explicit `ancestor_chain` selector overrides this derivation, which is what
lets a caller express an A→B→A embed (browser-observed same-site host,
cross-site ancestry) that the derivation alone cannot distinguish. The same
subdomain rule now governs `same_site_context`, the SameSite=Strict/Lax gate
`header()` already applied before this ADR — previously a literal host
comparison. This is the one semantic change to already-shipped SameSite
behavior this ADR makes: a request to `www.example.com` with
`top_level_site=https://example.com` was `CrossSite` before this ADR and is
`SameSite` after it; two sibling subdomains (`a.example.com` embedded under
`b.example.com`) stay `CrossSite` either way, because neither is a subdomain
of the other. The widened case only adds matches (a same-site cookie a
browser would send is no longer omitted); it never sends a cookie a strict
comparison would have withheld. It replaces the retired test
`a_sibling_subdomain_is_cross_site_because_there_is_no_public_suffix_list`
with sibling-stays-cross-site and child-becomes-same-site cases (see
Decision 4 for why this remains sound without a public-suffix list).

**Stored Chromium ancestor bit `None` on a partitioned row fails closed.** A
Chromium row that declares a partition (`top_frame_site_key` is present) but
whose `has_cross_site_ancestor` column is `NULL` — only pre-2024 Chromium
schemas lack the column — is omitted from every send view regardless of the
requested `ancestor_chain`, counted under `SendOmissions::ancestor_chain_unknown`,
and counted at read time as the new `ReadWarning` code
`unknown_ancestor_chain` (mirroring `unparsable_partition_key`). A caller
cannot supply a selector that resolves this ambiguity — there is no
"unknown" value on `AncestorChain` to select — because the row's own stored
identity, not the caller's context, is what is missing.

### 2. `send_view` is the single selection operation

`ReadResult::send_view(&self, &SendContext) -> Result<SendView<'_>>` is the
one place that walks the snapshot and decides, per row, whether it is sent.
`header()` becomes a thin renderer over `send_view`'s result — it does not
reimplement matching, and neither do the Python, Node, or CLI surfaces.
Every binding's send-selecting entry point (`send_view`/`sendView`/
`send-view`, and `header`/`header` for all of them) is documented as calling
through this one operation, so a collision case that passes in Rust cannot
silently diverge in a binding that grew its own copy of the predicate.

`SendOmissions` counts a fixed, ordered set of reasons a row is not sent:
`expired`, `not_applicable` (fails `GetFilter`, i.e. domain/path/Secure),
`same_site`, `partition` (isolation mismatch other than an unknown ancestor
bit), `ancestor_chain_unknown`, `unparsable_partition_key`, and `origin`
(Firefox origin-attributes mismatch other than partition/ancestor). Each row
is counted under its first failing reason in that order, never double-counted.
The order is part of the contract: it is the order `SendOmissions::entries()`
yields, and bindings surface it verbatim rather than re-deriving it.

### 3. Fail-closed jar, explicit opt-in for isolation loss

`IsolationLoss` is a new public, `#[non_exhaustive]` enum:
`Refuse` (the default) or `Allow`. `ReadResult::jar(&self) -> Result<&[Cookie]>`
and `into_jar(self) -> Result<Vec<Cookie>>` are the new fail-closed default
entry points; they succeed exactly when the snapshot has no positively
isolated row (the same "demanded selectors would be non-empty" predicate
Decision 1 defines — a jar refuses whenever *some* context would need a
selector to disambiguate what it holds, without asking which context). The
explicit opt-in is `jar_with(&self, IsolationLoss)` /
`into_jar_with(self, IsolationLoss)`. The free function `jar(request)` is
sugar for `read(request)?.into_jar()` — it inherits the fail-closed default,
not the old always-succeeds behavior. A refusal is a new typed error,
`RequestError::IsolationLossRefused { isolated_rows: u64, required: Vec<String> }`,
code `isolation_loss_refused`, whose `required` reuses the exact selector
tokens `IncompleteSendContext` already defines (Decision 5) — a caller
branching on `required` does not need a second vocabulary.

`cookies()` / `into_cookies()` (Rust), `as_list()` (Python), and the `cookies`
getter (Node) are unaffected by this decision: they remain infallible and
are the *inventory* projection — a caller explicitly asking to see the raw
eight-field rows, isolation collisions included, for display or auditing
rather than for sending. Only the names that promise send-safety (`jar`,
`as_jar`) gain the fail-closed contract. Opted-in output
(`jar_with(IsolationLoss::Allow)` and its binding equivalents) is byte-for-byte
identical to the pre-ADR always-succeeding output for the same snapshot —
this ADR changes when a request can fail, never what a successful jar
contains.

### 4. No public-suffix list; caller-normalized `top_level_site`

`Site` remains `(scheme, literal host)`, not an eTLD+1/registrable-domain
comparison, and this ADR does not add a public-suffix dataset. The e2e
lane's own context construction already normalizes `top_level_site` to a
schemeful site before calling in
(`tests/e2e/assert_partitioned_context.py:46`), which is the shape this
decision formalizes as the contract rather than an incidental test detail:
the caller supplies an already-normalized site, and the library never
attempts to infer a registrable boundary from a bare hostname. This keeps
`SameSite` conservative in the direction that matters for a security-facing
crate — Decision 1's subdomain widening only ever adds matches a
caller-normalized site says are legitimately same-site, and a caller who
under-normalizes (passes a host one level too specific) gets *fewer* matches,
never more.

### 5. Stable token vocabulary and canonical order

Demand tokens are appended, never reordered, and never removed:
`top_level_site`, `user_context_id`, `private_browsing_id`,
`first_party_domain`, `gecko_view_session_context_id`, `origin_attributes`.
`ancestor_chain` and the Firefox partition port are never demanded — both
are derived (Decision 1), so there is no selector-shaped hole for a caller to
fill for them. This is the same list `IncompleteSendContext.required` and
the new `IsolationLossRefused.required` both draw from, so a caller who
handles one error's `required` field already knows the vocabulary for the
other.

### 6. CLI structured error object rule

The documented rule for a CLI JSON error object is: every error object
carries `code` and `message`; a given `code` may define additional
documented fields. `required` is defined for exactly two codes:
`incomplete_send_context` (already shipped) and the new
`isolation_loss_refused`. A consumer parsing CLI error JSON must ignore
unknown keys rather than reject them, so this rule can add a field to a
`code` in the future without breaking existing consumers.

## Consequences

### Migration, per language

- **Rust.** `SendContext` gains the four builder methods from Decision 1.
  `send_view` is new. `header` is unchanged in signature and continues to
  work with existing calls; its behavior changes only for the collision
  cases Decision 1 newly disambiguates (previously-merged rows now split, or
  a previously-silent-default unknown attribute now demands
  `origin_attributes`). `jar()`/`into_jar()` change from infallible to
  `Result`-returning — this is a breaking signature change, called out in
  the 0.7 changelog; existing unpartitioned-snapshot callers see `Ok` exactly
  as before. `jar_with`/`into_jar_with` and the `IsolationLoss` enum are new.
- **Python.** `ReadResult.send_view(...)` is new, returning the detailed
  selected set, header string, and omission counts. `as_jar()` and the free
  `jar()` both gain `allow_isolation_loss: bool = False`; the default keeps
  today's call sites working for unpartitioned snapshots and raises the new
  structured error otherwise. `ReadResult.compatibility_cookies(*, allow_isolation_loss=False)`
  is the new named escape hatch that make the fail-closed/opt-in policy
  explicit without going through the jar-shaped API. `as_list()` is
  unaffected.
- **Node.** `ReadResult.sendView(context)` is new. `jar` gains a
  `JarOptions` with `allowIsolationLoss` (not added to `ReadOptions`, where
  it would be silently ignored by every non-jar call). `snapshot.cookies` is
  unaffected.
- **CLI.** New `send-view` subcommand, printing the selected detailed set,
  header, and omission counts as one JSON object. New `--allow-isolation-loss`
  flag on `read`/`from-path` for `--format json|netscape`. New selector flags
  (`--ancestor-chain`, `--first-party-domain`,
  `--gecko-view-session-context-id`, `--origin-attributes`) on `header` and
  `send-view`.

None of the above renames an existing name. `jar`/`as_jar`/`jar()` keep their
names in every language; what changes is that they can now fail, and that an
explicit, named opt-in exists for the caller who has already decided
isolation loss is acceptable.

## Out of scope

- A public-suffix list or any registrable-domain dataset (Decision 4).
- Browser-side policy heuristics: storage-access grants, First-Party Sets,
  and any related-site-set membership.
- Nonce-keyed / ephemeral partitions that do not persist to disk.
- A Firefox port-partitioning e2e lane exercising
  `privacy.dynamic_firstparty.use_site=false` — the port rule in Decision 1
  is unit- and corpus-tested, not exercised against a live browser toggle in
  this program.
- `from-path --domains`: it stays a flat, compatibility-only route and is not
  extended with the new selector surface. Whether it should gain one is an
  open question in the program record, not a decision this ADR makes.

## Rejected alternatives

1. **A nested `IsolationSelector` struct on `SendContext`**, as the original
   issue's Phase 1 sketch proposed. `SendContext` already has flat
   `user_context_id`/`private_browsing_id` fields from the 0.6.0 selector
   work; nesting the four new fields under a second struct would give the
   type two different shapes for what is, to a caller, one flat list of
   "what I know about this request." Every binding's context mapping would
   also need a nested-object convention with no existing precedent in this
   crate. Rejected in favor of Decision 1's flat fields.
2. **Renaming `jar`/`as_jar` to an explicitly lossy name** (e.g. `flat_jar`,
   `lossy_jar`) instead of making them fail closed. This was one of the two
   options the issue's Phase 3 left open. A rename changes every existing
   call site's spelling for no behavioral gain to an unpartitioned-snapshot
   caller, and it does not stop a partitioned-snapshot caller from getting a
   silently wrong answer — it only renames the trap. Fail-closed-by-default
   (Decision 3) is strictly safer: the common case (no isolation in the
   snapshot) is unaffected, and the dangerous case now requires an
   affirmative, named choice instead of an affirmative, differently-named
   function call that looks just as safe as the old one.
3. **A tri-state public `CookieContext`** (`Some(value)` / `Some(default)` /
   `Unknown`) to represent Decision 1's unknown-vs-default distinction on the
   public snapshot type directly. `CookieContext` is unchanged by this ADR:
   the unknown/default distinction is computed once, crate-internally, by
   `StoredIsolation`, and never promoted to a third public state. Widening
   the public type would be a larger, harder-to-reverse public API change for
   a distinction only the selection algorithm needs to see.
4. **Adding new public fields to `CookieContext`** to carry the parsed
   `AncestorChain`, parsed Firefox tuple parts, or parsed origin-attribute
   values directly. Rejected for the same reason as alternative 3: this is
   derived, selection-time state, not additional inventory a caller
   inspecting `detailed_cookies()` needs, and adding fields there would grow
   the public snapshot surface for every language without a caller-facing
   use beyond what `send_view`'s omission counts already answer.
5. **Putting isolation-loss policy on `ReadRequest`** (an option on `read`
   itself, deciding at snapshot-construction time whether isolated rows are
   even retained). Rejected because it would make the same snapshot behave
   differently depending on a flag chosen before the caller knows what the
   snapshot contains, and it would prevent a caller from inspecting isolated
   rows via `detailed_cookies()`/`send_view` while still refusing to jar them
   — the two questions ("what did the browser store" and "am I willing to
   flatten it") are answered by different call sites, not one.

## References

- [Program record: isolation-safe send
  selection](../design/isolation-safe-send-selection.md) — engine encoding
  tables, per-language signatures, corpus and e2e plan, PR checklist
- [ADR 0004](0004-read-is-the-recommended-entry.md) — `read`/snapshot/`header`
  contract this ADR amends
- [ADR 0005](0005-stage-boundary-types-and-extraction-vocabulary.md) — header
  format this document follows; unrelated in scope
- Issue #331; predecessors #177, #299, #325
- `rookie-rs/src/header_filter.rs`, `rookie-rs/src/read.rs`,
  `rookie-rs/src/send_context.rs`, `rookie-rs/src/browser/mozilla.rs`,
  `rookie-rs/src/browser/chromium_decoder.rs`
