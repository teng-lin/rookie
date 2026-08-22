# Browser E2E Depth Audit and Remediation Plan

- **Author:** Codex
- **Date:** 2026-08-21
- **Status:** Implemented in `codex/browser-e2e-depth`; remote browser jobs pending
  CI execution
- **Baseline:** `f0df3d1`
- **Scope:** Browser-generated cookie fixtures, hosted live-browser extraction,
  Rust/Python/Node/CLI assertions, cookie isolation context, discovery, and
  locked-store behavior

## Executive conclusion

The browser E2E suite has exceptional platform and decryption breadth, but its
success predicate is too shallow. It proves that many platform, browser, and
credential combinations can recover one known encrypted value. It does not yet
prove that extraction returns the exact cookie set, preserves all cookie
attributes, preserves partition/container identity, excludes unrelated rows,
or behaves correctly against a database being actively modified by a browser.

This is a critical test-quality gap, not a claim that the crypto matrix has no
value. The current suite provides strong confidence in basic discovery and
decryption reachability. It provides substantially less confidence in semantic
correctness and almost no conventional stress coverage such as volume,
concurrency, mutation, or active-writer recovery.

The highest-priority repair is an independent, manifest-driven cookie corpus
with exact full-set assertions across all four public surfaces. Active-writer
and partition/container tests should follow. Increasing the number of cookies
or browser cells before exact assertions exist would mostly repeat the current
weakness at a larger scale.

## Verified baseline state

The declarative coverage matrix contains 47 platform-by-browser cells:

- 32 `nightly_hosted` cells that launch a browser and seed a real profile;
- 15 `release_fixture` cells that do not launch a browser.

The distinction is defined in
[`browser_coverage.json`](../../tests/e2e/browser_coverage.json) and documented
in the [testing guide](../testing.md#browser-coverage-matrix). The fixture
runner explicitly describes its work as browser-ID/engine coverage rather than
per-browser crypto coverage in
[`run_claimed_browser_fixtures.py`](../../tests/e2e/run_claimed_browser_fixtures.py).

The normal hosted seeder returns one cookie:

```text
rookie_ci=bar; Path=/; Max-Age=3600; SameSite=Lax
```

See [`cookie_server.py`](../../tests/e2e/cookie_server.py). Chromium and Firefox
seeders verify that the browser accepted this one cookie and then close their
persistent context before the Unix extraction harness proceeds:

- [`seed_chromium_cookie.mjs`](../../tests/e2e/seed_chromium_cookie.mjs)
- [`seed_firefox_cookie.mjs`](../../tests/e2e/seed_firefox_cookie.mjs)
- [`run_hosted_chromium_e2e.sh`](../../tests/e2e/run_hosted_chromium_e2e.sh)

The Rust, Python, Node, and CLI checks generally search the returned collection
for a cookie named `rookie_ci` and compare its value with `bar`. Representative
examples are:

- [`rookie-rs/tests/e2e_chrome.rs`](../../rookie-rs/tests/e2e_chrome.rs)
- [`assert_chrome_cookie.py`](../../tests/e2e/assert_chrome_cookie.py)
- [`assert_chrome_cookie.mjs`](../../tests/e2e/assert_chrome_cookie.mjs)
- [`assert_cli_cookie.py`](../../tests/e2e/assert_cli_cookie.py)

Firefox is a limited exception. Its live assertions also check that expiration
is near the seeded `Max-Age` and that detailed extraction contains an
`origin_attributes` key. They do not validate the value or semantics of that
context. See
[`assert_firefox_cookie.py`](../../tests/e2e/assert_firefox_cookie.py) and
[`assert_firefox_cookie.mjs`](../../tests/e2e/assert_firefox_cookie.mjs).

## Prioritized findings

| ID | Finding | Priority | Consequence |
| --- | --- | --- | --- |
| E1 | Live assertions accept any result containing one matching name/value pair | Critical | Extra rows, duplicates, wrong-domain rows, and filtering leaks can pass |
| E2 | Six of the eight flat `Cookie` fields lack general live semantic assertions | Critical | Attribute mapping and epoch/schema regressions can ship unnoticed |
| E3 | Detailed partition/container context is almost entirely fixture-only | Critical | Real CHIPS, dFPI, and header-isolation behavior are unproven |
| E4 | Unix extraction starts only after the browser context closes | High | Active locks, journals, concurrent writes, and checkpoint races are not tested |
| E5 | The Windows live-browser WAL test extracts a separately staged fixture | High | Browser liveness and WAL recovery are tested, but not against the active browser database |
| E6 | Persistent-cookie fixtures are mostly self-authored and weakly version-provenanced | High | Fixture builders can encode the same mistaken schema assumption as the extractor |
| E7 | Recommended `read`/detailed/discovery paths receive less live coverage than explicit-path compatibility APIs | High | The path users are directed toward can diverge from the path the matrix proves |
| E8 | There is little volume, concurrency, mutation, or repeated extraction coverage | Medium | Ordering, snapshot, resource, and race failures remain largely unexplored |

### E1. The tests do not prove the exact output

The current `find`/`next`/`any` pattern succeeds when one matching cookie is
present. It does not fail if extraction also returns hundreds of unrelated
cookies, duplicate logical identities, both raw and decrypted representations,
or a row that should have been rejected by the domain filter. Cookie counts are
printed in several places but are not part of the success predicate.

The report E2E harness already demonstrates a useful cross-surface normalization
pattern in
[`check_report_surfaces.py`](../../tests/e2e/check_report_surfaces.py). Cookie
verification should adopt that structural comparison style, with one important
addition: every surface must be compared with an independent expected manifest,
not merely with Rust as the reference. A shared core defect can make all four
surfaces agree on the same wrong answer.

### E2. Flat cookie semantics are shallow

The compatibility `Cookie` projection contains eight fields: `domain`, `path`,
`secure`, `expires`, `name`, `value`, `http_only`, and `same_site`. See
[`enums.rs`](../../rookie-rs/src/common/enums.rs).

The ordinary live Chromium path proves only `name` and `value`. Firefox adds a
loose expiration check. Secure, HttpOnly, SameSite encoding, host/domain
identity, nested paths, session-versus-persistent behavior, and expiration
boundaries are otherwise supported mainly by fixtures written by this project.

This should be described as “browser-generated but not semantically asserted,”
not “never round-tripped.” The fields flow through the extraction result, but
the test does not determine whether their values are correct.

### E3. CookieContext is not validated against real browser semantics

`CookieContext` has nine optional fields:

1. `top_frame_site_key`
2. `has_cross_site_ancestor`
3. `source_scheme`
4. `source_port`
5. `is_persistent`
6. `origin_attributes`
7. `user_context_id`
8. `partition_key`
9. `private_browsing_id`

The live Firefox check verifies only that the `origin_attributes` key exists.
No live test asserts a browser-produced Chromium partition key, Firefox dFPI
partition key, container identity, or the inclusion/exclusion behavior of
`ReadResult::header(SendContext)`.

Consequently, the formats parsed by
[`header_filter.rs`](../../rookie-rs/src/header_filter.rs) are validated mostly
against project-authored literals rather than values obtained from live browser
profiles.

Not every context field applies to every engine or persistent store. In
particular, private browsing may deliberately avoid persistent storage. The
coverage contract should identify fields as live-tested, captured-fixture-only,
or not persistable instead of forcing synthetic “live” coverage.

### E4–E5. A browser-open test is not yet an active-writer test

On Linux and macOS, the Playwright context is closed before extraction begins.
Those jobs use genuine encrypted browser output, but normally read a cleanly
closed or checkpointed store.

The Windows App-Bound canary reopens a browser and verifies that extraction does
not terminate it. However, its WAL-only row lives in a copied database whose
WAL was staged by
[`stage_sqlite_wal_fixture.py`](../../tests/e2e/stage_sqlite_wal_fixture.py).
The browser being kept alive is not writing to the database used for the WAL
assertion. This is valuable App-Bound, snapshot, and liveness coverage, but it
does not reproduce an extractor racing the active browser store.

### E6. Fixture provenance is uneven

Most persistent Chromium/Firefox schema fixtures are generated by repository
scripts and target a small number of schema shapes. Such fixtures are useful
for deterministic failures and platform-bound encryption, but they cannot
independently reveal a mistaken schema assumption shared by the generator and
extractor.

The notable exception is the real Firefox 141/142 sessionstore corpus. Its
browser versions, build IDs, capture process, sizes, and checksums are recorded
in [`browser/fixtures/README.md`](../../rookie-rs/src/browser/fixtures/README.md).
That provenance model should be generalized to persistent cookie stores.

### E7. Public-path coverage does not match public guidance

Live Chromium assertions concentrate on explicit-path and compatibility
functions. Firefox exercises one detailed compatibility function, but real
partition context is absent. Browser discovery is optional and concentrated in
selected Windows lanes. Fixture-only IDs often prove only that the ID is
registered or accepted by an engine-specific function.

The suite should separately prove:

- explicit-path flat compatibility output;
- explicit-path detailed output;
- recommended `read` output and profile selection;
- CLI `read`, `from-path --format detailed`, and `header` behavior;
- registry discovery and the selected browser/profile/source identity.

## Remediation program

### PR 1 — Independent corpus and exact-set verifier

Add a declarative `tests/e2e/cookie_corpus.json` and a shared verifier. Each
scenario should define its seed operation, expected browser acceptance, expected
flat fields, expected detailed context when applicable, and whether it belongs
to the portable smoke or engine-specific deep corpus.

The seeder should also write a browser-observed manifest for facts that are
dynamic or browser-normalized, such as the accepted expiration time. That
manifest must not become circular ground truth for raw storage semantics. The
declarative scenario remains authoritative for properties such as the expected
raw SameSite encoding, while browser observation confirms acceptance and
provides bounded dynamic values.

Normalize every surface into a stable JSON representation and compare it with
the independent expected manifest using sorted full-set equality. Use the
following identities:

- flat: `(domain, path, name)`;
- detailed: `(domain, path, name, partition/container identity)`.

Run two related assertions:

1. filtered flat extraction, proving all eight compatibility fields and domain
   filtering;
2. unfiltered detailed extraction, proving the full stored set and isolation
   context without silently flattening distinct identities.

The first portable corpus should include:

- Secure and HttpOnly combinations;
- SameSite unspecified, None, Lax, and Strict;
- host-only and `Domain=` cookies;
- root and nested paths, including same-name/path collisions;
- session and persistent cookies;
- empty values and values containing `=`;
- percent-encoded UTF-8;
- a portable large value around 3.5 KiB;
- expiration beyond 2038 and a value subject to the browser's 400-day clamp;
- `__Host-` and `__Secure-` prefixes;
- an updated cookie and a deleted cookie that must leave no stale row;
- a decoy on another host that must be excluded by the filtered result.

Raw non-ASCII/emoji values should be browser-rejection cases rather than
portable positive cases: RFC 6265 cookie values use a restricted cookie-octet
grammar. An exact 4 KiB boundary should also be engine-specific because browser
size accounting differs.

Test the verifier by deliberately injecting an extra row, duplicate identity,
wrong-domain row, missing row, wrong attribute, and wrong context. Every
mutation must fail. A plaintext-sentinel mismatch should remain an adversarial
fixture test because a real browser does not naturally create conflicting raw
and encrypted value columns.

**Acceptance criteria**

- All eight flat fields have genuine Chromium and Firefox coverage.
- Rust, Python, Node, and CLI match the independent manifest exactly.
- Excess, duplicate, missing, and wrong-domain rows fail deterministically.
- No live success assertion consists only of a name/value lookup.

### PR 2 — Recommended API and discovery coverage

Extend the exact verifier to the supported public paths rather than treating
legacy and recommended calls as interchangeable.

- Exercise `read` and `from_path(...).detailed_cookies` in Rust, Python, and
  Node.
- Exercise CLI `read`, `from-path --format detailed`, and filtered flat output.
- Under isolated test homes, place profiles at registry-correct roots and
  assert the detected browser ID, profile ID, and selected source path.
- Upgrade feasible `release_fixture` cells from ID-presence checks to real
  root/profile discovery using the appropriate engine fixture.
- Preserve explicit-path coverage because it validates a separate supported
  contract.

Add machine-readable depth claims to the coverage manifest, for example:
`exact_set`, `detailed`, `discovery`, `active_writer`, `partitioned`, and
`crypto`. A validator should fail when a cell claims a capability without
running its corresponding assertion.

**Acceptance criteria**

- Core Chrome/Firefox lanes prove both explicit-path and recommended reads.
- Discovery tests assert which browser, profile, and source were selected.
- The documented coverage level for every matrix cell is mechanically checked.

### PR 3 — True active-writer extraction

Introduce a ready/hold protocol in the browser seeders:

1. launch a persistent context;
2. seed the corpus and signal readiness;
3. leave the browser and seeder alive;
4. extract from that exact active profile database;
5. add, update, and delete cookies;
6. extract again and assert the state transition;
7. close the browser normally and compare the final snapshot.

Record the browser PID, browser version, actual database path, database schema
version, SQLite journal mode, and presence of journal/WAL sidecars in job logs.
Do not require every browser to use WAL; the behavior under the store's actual
journal mode is the contract being tested.

Start with representative Chrome and Firefox lanes on Linux, macOS, and
Windows. Retain the synthetic Windows App-Bound WAL case, but label it as a
staged-WAL recovery test rather than an active-writer test.

**Acceptance criteria**

- The extracted database is the database owned by the live browser profile.
- The browser remains alive and is not force-killed by extraction.
- Repeated extraction observes additions, replacements, and deletions without
  duplicates or stale state.
- The closed-profile result matches the final open-profile result.

### PR 4 — Browser-produced partition and container semantics

Use local HTTPS and distinct test hosts. Loopback HTTP is sufficient for some
Secure-cookie cases, but hostname aliases and cross-site partition scenarios
should not rely on browser-specific insecure-origin exceptions.

- Chromium: seed unpartitioned and CHIPS cookies with colliding flat identities
  under different top-level sites.
- Firefox: seed real dynamic first-party isolation partition keys.
- Assert `top_frame_site_key`, `has_cross_site_ancestor`, `source_scheme`,
  `source_port`, `is_persistent`, full `origin_attributes`, and `partition_key`
  wherever the engine exposes them.
- Use a small test-only Firefox extension or equivalent supported harness if
  live Multi-Account Container coverage is required for `user_context_id`.
- Treat `private_browsing_id` as live only if a genuine source artifact exists;
  otherwise document it as non-persistable or captured-fixture-only.
- Feed real extracted contexts into `ReadResult::header(SendContext)` and assert
  both inclusion and exclusion across top-level site and container selectors.
- Assert that an incomplete send context fails rather than merging isolated
  cookies.

**Acceptance criteria**

- Partition parsers consume browser-produced strings rather than only authored
  literals.
- Colliding partition identities survive detailed extraction without merging.
- Header generation selects only the cookie allowed by the supplied context.
- Each of the nine context fields has an explicit live, fixture-only, or
  non-persistable classification.

### PR 5 — Version-provenanced browser fixtures

Create a manual capture workflow that produces reviewable, sanitized fixture
candidates rather than uploading complete profiles.

Each candidate should include:

- browser product, channel, version, and build ID;
- platform and architecture;
- cookie database/session schema version;
- `sqlite_master`, `PRAGMA table_xinfo`, and relevant meta rows;
- only known synthetic canary cookie rows;
- the independent expected manifest;
- byte sizes and cryptographic hashes;
- the exact capture command and sanitization procedure.

Use portable browser-generated stores where possible, such as Firefox SQLite
and sessionstore files or a Linux Chromium profile created with a deterministic
test password-store mode. Platform-bound DPAPI, Keychain, libsecret, and
App-Bound material should continue to be generated or exercised on the target
CI host. Do not upload full browser profiles, `Local State`, OS credential keys,
history, cache, telemetry, or real user data.

Nightly jobs may report or upload sanitized schema signatures for inspection,
but committed fixture updates should remain manual and reviewed.

**Acceptance criteria**

- Persistent-cookie fixtures have the same provenance quality as the existing
  Firefox sessionstore captures.
- The retained corpus covers at least the current and previous relevant schema
  generation per engine where artifacts are redistributable.
- A browser schema change produces an intentional fixture/decoder failure or a
  visible schema-signature change.

### PR 6 — Nightly stress and soak

Add load only after the exact semantic contract is enforced.

- Seed 300 or more cookies across multiple registrable domains. Do not place
  them all on one site, where browser eviction limits would dominate the test.
- Use multiple profiles and same-name collisions.
- Run repeated add/update/delete cycles while the browser stays active.
- Start concurrent extractor processes against the same profile.
- Exercise timeout and cancellation during snapshot/locked-store recovery.
- Compare the exact set after every completed cycle.

This should run on representative engine-by-OS-by-crypto combinations, not on
all 32 hosted cells. The broad matrix should retain a smaller exact smoke
corpus to control runtime and flake risk.

## CI placement

| Trigger | Required depth |
| --- | --- |
| Pull request | Portable exact corpus on Linux Chromium and Firefox; verifier mutation tests; deterministic adversarial fixtures |
| Push to `main` | Exact corpus on Chrome and Firefox across Linux, macOS, and Windows |
| Nightly | Exact smoke corpus across all hosted cells; representative active-writer, partition, concurrency, and volume lanes |
| Release/manual | Full registry/discovery matrix and versioned fixture validation/capture |

Every browser job should log at least:

- browser product and version;
- seeded, browser-accepted, and extracted row counts;
- flat and detailed exact-comparison result;
- source database path and schema version;
- journal mode and live/closed state;
- context-bearing row count;
- public surfaces exercised.

## Implementation outcome

The remediation is implemented on the integration branch as executable test
contracts, not only as additional matrix metadata. No developer-machine
Chrome, Safari, or Brave profile was opened or extracted while doing this
work. The partition/container and stress runners refuse to run outside CI and
require their disposable profile below `RUNNER_TEMP`; core runners accept only
the explicit profile paths supplied by their workflows.

| Program | Implemented outcome |
| --- | --- |
| PR 1: exact corpus | A declarative portable/deep corpus now covers all eight flat fields, collisions, update/delete, expiration boundaries, large and unusual values, and a second-host decoy. Rust, Python, Node, and CLI compare sorted complete output with an independent manifest; verifier mutation tests prove excess, duplicate, missing, wrong-domain, wrong-attribute, and wrong-context rows fail. |
| PR 2: public paths and discovery | Core profiles are staged below isolated registry roots. Explicit flat/detailed reads, recommended reads, CLI reads, and discovery assert the independently computed browser/profile/source identity. Broad hosted and fixture lanes validate their declared depth profiles at runtime. |
| PR 3: active writer | Chrome and Firefox core jobs on Linux, macOS, and Windows run a ready/hold/mutate/probe/close protocol against the exact database owned by a live disposable browser. All surfaces assert complete open states and the final open/closed structural equality while process, schema, journal, and sidecar evidence is logged. |
| PR 4: isolation context | A local-HTTPS lane creates two Chromium CHIPS and two Firefox dFPI partitions plus colliding unpartitioned rows. Raw SQLite context is the oracle for exact detailed extraction and positive/negative `SendContext` selection. A disposable Firefox WebExtension adds a real Multi-Account Container row and exact `userContextId` checks. All nine context fields are classified; private browsing is explicitly non-persistable. |
| PR 5: provenance | The manual, read-only capture workflow first decodes the disposable source through the public CLI and exact manifest, then retains only expected rows. Provenance records product/channel/version/build, capture command, sanitizer revision, schema metadata, byte sizes, row counts, and hashes. Full profiles, `Local State`, secrets, and unrelated tables are excluded. |
| PR 6: stress | Nightly jobs run two Linux profiles per engine plus macOS Chrome through Keychain. Each keeps 320 cookies across eight registrable domains under continual browser writes, mutates state for three rounds, runs four public surfaces concurrently, and exact-checks every completed state. A locked rollback-journal control proves typed request timeout, in-flight cancellation, and exact recovery after unlock. |

Representative lanes now emit a machine-readable `E2E_DEPTH_RECEIPT` only
after their declared capabilities and surfaces have succeeded. Contract tests
reject a missing or excess claim, preventing the coverage manifest from
silently getting ahead of its harness.

### Validation boundary

The repository changes can be syntax-, unit-, compile-, and fixture-tested
without touching an installed browser profile. Genuine encryption,
browser-owned database, CHIPS/dFPI/container, and schema-capture assertions are
deliberately executable only on isolated CI runners. Those jobs still need to
run on the branch before merge. In particular, the capture workflow and
sanitizer are complete, but current and previous browser-generated persistent
cookie candidates cannot honestly be called retained fixtures until the
manual workflow has run and its artifacts have been reviewed. The workflow
does not commit or trust those artifacts automatically.

## Definition of done

The critical gap is considered closed when all of the following are true:

1. Live success is based on exact equality with an independent manifest, not a
   matching-cookie lookup.
2. All eight flat cookie fields have real Chromium and Firefox coverage,
   including decoy exclusion and colliding identities.
3. Every `CookieContext` field has an explicit applicability classification,
   and browser-produced partition/container formats are tested wherever they
   can persist.
4. At least one Chromium and one Firefox lane per supported desktop OS extract
   from the actual profile while the browser remains active.
5. Recommended `read`/detailed/discovery behavior is proven independently of
   explicit-path compatibility functions.
6. Persistent fixture provenance includes browser/schema versions and hashes,
   while platform secrets and complete profiles are never retained.
7. Nightly stress runs use exact postcondition checks, so load cannot hide
   semantic corruption.

## Recommended implementation order

1. Land PR 1 and make exact-set correctness a required pull-request check.
2. Apply the verifier to recommended APIs and discovery in PR 2.
3. Add the active-writer protocol in PR 3.
4. Add real isolation contexts and header-selection tests in PR 4.
5. Establish the browser-generated fixture capture process in PR 5.
6. Add volume and concurrency soak only after the preceding contracts are
   stable.

PRs 1 and 3 produce the largest immediate risk reduction. PR 1 prevents false
positives in every existing cell; PR 3 covers the real-world locked-store state
most likely to differ from a clean fixture. PR 4 then closes the most important
unverified semantic surface introduced by detailed cookies and `SendContext`.
