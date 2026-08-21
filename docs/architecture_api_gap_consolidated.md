# Consolidated Architecture and API Gap Review

- **Author:** Codex
- **Date:** 2026-08-20
- **Status:** Validated consolidation and remediation plan
- **Revision:** 3
- **Scope:** Rust core, CLI, Python binding, Node binding, generated report schema, public documentation, and CI contracts
- **Inputs:** [`architecture_api_gap_claude.md`](architecture_api_gap_claude.md), [`architecture_api_gap_codex.md`](architecture_api_gap_codex.md), and [`architecture_api_gap_grok.md`](architecture_api_gap_grok.md)
- **Baseline:** workspace version `0.6.0-beta.1`
- **Does not amend:** ADR 0001–0005, public API snapshots, the report DTO schema, or `browser_registry.json`

---

## Purpose and validation standard

This document is not a concatenation of the three source reviews. Every material claim was treated as untrusted and checked against the current tree. Overlapping findings were merged, severity was recalibrated, and contradictory or overstated claims are recorded explicitly near the end.

The classifications used here are:

- **Confirmed defect:** current behavior contradicts a documented contract, loses required information, or silently performs the wrong operation.
- **Confirmed API gap:** the implementation matches its current shape, but callers cannot express a necessary policy or recover necessary state.
- **Maintenance debt:** a real drift or enforcement weakness without a demonstrated user-visible failure.
- **Not substantiated:** source evidence does not support the original conclusion, or the behavior is an explicit and coherent decision.

All platform-neutral claims were checked by direct source reading. Windows-only behavior was checked by source reading but was not executed on Windows during this consolidation. The full native workspace test suite passed on macOS. Chrome's historical App-Bound rollout was checked against the [official Chrome Security announcement](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html), which dates cookie App-Bound Encryption to Chrome 127, not 133.

## Overall conclusion

The internal staged extraction architecture is sound and should be retained. The important defects occur at runtime-control and public-projection boundaries:

1. A timed-out or cancelled partial outcome becomes ordinary `Ok(cookies)` — through the compatibility projection, and independently through the report flatten that the recommended profile-scoped path uses.
2. Profile-scoped `read()` creates a second deadline and repeats discovery.
3. Windows App-Bound work can outlive the caller's deadline, mutates process-global environment during fan-out, and has no caller-selected policy.
4. Node and CLI `from_path` option parsing silently chooses one of several conflicting credential selectors.
5. Header generation does not enforce send-time expiration and cannot preserve browser partition/container isolation.
6. Recommended read warnings, binding errors, and stopped-report semantics omit actionable state.

The architectural response should not be an engine trait, a typestate lattice, or a sixth ad hoc request type. The core pipeline is already strong. Fix deadline propagation and result semantics first, retain detailed cookie context through the recommended path, and simplify the public job model deliberately in 0.7.

## Prioritized findings

| ID | Finding | Classification | Priority | Release target |
| --- | --- | --- | --- | --- |
| C1 | Mid-flight stop is discarded — on the compatibility `Emit` arm **and** on the report flatten used by profile-scoped `extract`/`read` | Confirmed defect, two routes | Critical | Before 0.6 final |
| C2 | Profile-scoped `read()` resets its deadline and repeats discovery | Confirmed defect | High | Before 0.6 final (with C1 route 2) |
| C3 | App-Bound native work ignores the active deadline | Confirmed defect, Windows | High | **Blocks Windows 0.6 final** |
| C4 | App-Bound injection mutates one process-global environment key from concurrent workers | Confirmed concurrency defect, Windows | High | **Blocks Windows 0.6 final** |
| C5 | Node/CLI `from_path` silently accept conflicting credential selectors | Confirmed defect | High | Before 0.6 final |
| C6 | `header()` omits send-time expiry, retains `expires == now`, and does not define how `include_expired` interacts with send-match | Confirmed defect plus contract gap | Medium | Before 0.6 final |
| C7 | Profile-scoped warnings omit multiple row-loss categories | Confirmed diagnostics defect | Medium | Before 0.6 final |
| A1 | Recommended read/report/header surfaces discard isolation identity | Confirmed API gap | High | Document in 0.6; solve in 0.7 |
| A2 | Rust and binding error surfaces lose stable codes and stop reasons | Confirmed API gap | High | Additive binding fix; typed Rust error in 0.7 |
| A3 | One `Request` has different no-profile selection semantics in `extract` and `extract_report` | Confirmed API defect | Medium | Document in 0.6; split in 0.7 |
| A4 | Aggregate/listing operations expose no caller timeout or cancellation | Confirmed API gap | Medium | 0.7 request redesign |
| A5 | Direct-path Chromium credential defaults are not portable | Confirmed API gap | Medium | Document in 0.6; redesign in 0.7 |
| A6 | Stopped report work is counted as not detected/no sources | Confirmed semantic gap | Medium | Schema-compatible mitigation in 0.6; full model in v2 |
| A7 | Malformed required host identity can become an empty-domain cookie | Confirmed behavior, compatibility-sensitive | Medium | Add diagnostics now; change projection deliberately |
| A8 | App-Bound injection/elevated fallback has no caller-selected runtime policy | Confirmed API gap, Windows | Medium | Document in 0.6; solve in 0.7 |
| D1 | Recommended API rustdoc and several public docs are incorrect or incomplete | Confirmed documentation defect | Medium | Before 0.6 final |
| D2 | Report JSON Schema omits identifier lexical validation | Confirmed validation gap | Medium | Before schema publication |
| M1 | Typed compatibility evidence can fall back to comparing English text | Confirmed maintenance debt | Low | Opportunistic internal cleanup |
| M2 | Stage fence omits some extract-side bags | Confirmed enforcement gap | Low | Opportunistic internal cleanup |

---

## C1. Mid-flight stop is returned as ordinary partial success

**Evidence**

[`browser/legacy.rs`](../rookie-rs/src/browser/legacy.rs#L175) converts a non-completed `Outcome.termination` into a `BoundaryStop`, then deliberately disables further runtime checks. The `Absent` and `Failed` dispositions consume the stop, but `CompatibilityDisposition::Emit` returns selected records without consuming it.

This is reachable when one source has already produced records and a later source or stage times out or is cancelled. `acquire_by_policy` and the engine completion policies retain committed work, and compatibility policy emits as soon as an eligible source has records.

The behavior contradicts the public contract on [`extract()`](../rookie-rs/src/lib.rs#L324), which says timeout or cancellation returns an error detectable through `stop_reason()`.

**Affected surfaces — two independent code routes**

The compatibility `Emit` path is only half of it. A second, structurally different route reaches the same failure on the *recommended* surface.

*Route 1 — compatibility projection (`selected_records`):*

- `extract()` without a profile;
- no-profile `read()`;
- named compatibility helpers;
- aggregate compatibility paths that use the same projection.

*Route 2 — report flatten (`flatten_selected_report_cookies`, [`lib.rs`](../rookie-rs/src/lib.rs#L402)):*

- `extract()` **with** a profile ([`lib.rs`](../rookie-rs/src/lib.rs#L360));
- profile-scoped `read()` ([`read.rs`](../rookie-rs/src/read.rs#L184)).

`flatten_selected_report_cookies` never reads `report.termination` — verified, zero occurrences in the function body. It selects on `source.selected && source.status == "succeeded"` and returns `Ok(cookies)`. A timed-out or cancelled profile-scoped job therefore returns ordinary success with `stop_reason()` reporting `None`, by a completely different mechanism than the `Emit` arm.

**A fix confined to `selected_records` leaves the recommended path broken.** Both routes must be closed in the same change, and C2's suggested patch below still terminates in this flatten, so C2 does not incidentally fix it either.

**The fix must be per-surface, not global**

A blind `if let Some(stop) = boundary_stop { return Err(stop.into()); }` on every `Emit` contradicts a second documented contract. [`load()`](../rookie-rs/src/compatibility_dispatch/named.rs#L494) states: *"Once the shared deadline or cancellation trips, no not-yet-started browser is attempted, but a browser already in flight at that moment still runs to completion and its cookies are kept."* Under a global `Err(stop)`, an in-flight browser would instead return `Err`, and `aggregate_load_results` ([`named.rs`](../rookie-rs/src/compatibility_dispatch/named.rs#L435)) logs such an error and keeps no cookies from it — the opposite of the documented behavior.

The rule needs three cases:

| Surface | On a stop with records already collected |
| --- | --- |
| `extract`, `read`, named single-browser helpers | Return the typed stop as `Err`. This is the contract at [`lib.rs`](../rookie-rs/src/lib.rs#L336). |
| Flat `load()` aggregation | Keep cookies already collected by an in-flight browser, per `load()`'s own rustdoc. The aggregate tracks `terminal_stop` separately. |
| Report APIs (`extract_report`, `browser_report`, `load_report`) | Unchanged. The DTO already carries independent `status` and `termination`. |

Implement this by passing the stop policy down rather than deciding it inside the projection, so each caller states which contract it is under. Do not change compatibility APIs to partial-success semantics unless `ReadResult` first gains an explicit termination field and the contract is revised.

**Required tests**

- Construct an outcome containing a selected successful source plus `Termination::TimedOut`; the single-browser projection must return a typed stop.
- The same for a *profile-scoped* `read` and `extract` through the report flatten — this is the case a `selected_records`-only fix would miss.
- Repeat both for cancellation and resource exhaustion.
- Assert `stop_reason(&error)` returns the exact variant.
- Assert `load()` still returns the in-flight browser's cookies when the deadline trips mid-fan-out.
- Preserve report behavior: a report may retain completed sources and non-completed termination.

---

## C2. Profile-scoped `read()` creates a fresh deadline

**Evidence**

[`read()`](../rookie-rs/src/read.rs#L152) creates a runtime, resolves a profile using it, reconstructs a public `Request` with the original duration, and calls [`extract_report()`](../rookie-rs/src/lib.rs#L376). `extract_report()` creates a second runtime and resolves the already-resolved profile again.

The no-profile path and `extract()` correctly keep one runtime. The bug is specific to the recommended profile-scoped read path.

**Recommended fix**

Call the existing internal report seam with the resolved ID and original runtime:

```rust
let profile_id = registry::resolve_profile_query(&browser_id, &query, &runtime)?;
let report = browser::report_build::browser_extraction_report_with_runtime(
    &browser_id,
    Some(&profile_id),
    None,
    &runtime,
)?;
```

This removes both the deadline reset and duplicate discovery. If module visibility makes this awkward, add one crate-private helper accepting `&BoundaryRuntime`; do not reconstruct a public request internally.

**Interaction with C1 — do not land this alone**

The snippet above still ends in `flatten_selected_report_cookies`, which ignores `report.termination` (see C1, Route 2). Applying C2 by itself gives profile-scoped `read` a correct single deadline and *still* returns `Ok(cookies)` when that deadline expires. C1's Route 2 fix and C2 must ship together, or the recommended path trades one silent failure for another.

**Required tests**

- Use `ManualClock` to spend part of the budget during resolution and prove extraction receives only the remainder.
- Count profile-listing calls and prove the profile branch resolves only once.
- Test zero-duration and cancellation behavior before and after resolution.

---

## C3–C4. Windows App-Bound runtime and concurrency defects

### Confirmed behavior

The default `appbound` feature automatically attempts v20 recovery when `Local State` contains `app_bound_encrypted_key`.

[`retrieve_v20()`](../rookie-rs/src/browser/chromium_platform_keys/windows.rs#L105) checks the runtime before and after `get_keys()`, but the App-Bound call itself receives no runtime. Reflective injection waits on a remote thread for a fixed 30 seconds in [`injector.rs`](../rookie-rs/src/windows/appbound/injector.rs#L300), followed by cleanup that can wait longer. Cancellation cannot be observed during that wait.

The injection path sets `HBD_ABE_ENC_B64` through `std::env::set_var` before spawning the child. `load()` and `load_report()` can run multiple Chromium-family browsers concurrently, all using the same process-global key.

### Correction to the source reports

The environment value is the stripped, base64-encoded **encrypted App-Bound blob**, not the decrypted 32-byte master key. The Claude report's claim that a plaintext master key can remain in the parent environment is incorrect.

The concurrency bug remains real:

- one worker can cause another child to inherit the wrong encrypted blob;
- nested guard restoration can leave an encrypted blob in the parent environment;
- subsequent child processes can inherit that stale value;
- process-global environment mutation from worker threads is an avoidable shared-state hazard.

### Recommended fix

1. Change `get_keys`, `retrieve_via_injection`, and `inject_and_extract_key` to receive the active runtime or a derived native deadline.
2. Poll `WaitForSingleObject` in short bounded intervals, checking cancellation and remaining deadline between waits, or use a cancellation event included in a Windows multi-object wait.
3. Pass `HBD_ABE_ENC_B64` in an explicit environment block to that child process. Never mutate the parent environment.
4. Thread runtime checks through the elevated process enumeration/fallback path.

**Do not add a public `AppBoundPolicy` enum in 0.6 solely to fix C3 or C4.** The environment mutation and deadline plumbing are internal defects and can be corrected without expanding the public surface. Preserve current compatibility behavior for 0.6, document it, and track caller-selected policy separately as A8 for the 0.7 request-model redesign.

`ROOKIE_E2E_APPBOUND_MODE` remains an internal test control. It is process-global, cannot disable App-Bound work, and must not be documented or relied on as an operational safety escape hatch.

**Required Windows tests**

- Two parallel fake injection attempts receive their own encrypted blob.
- Parent `HBD_ABE_ENC_B64` is unchanged before and after success, failure, panic, and cancellation.
- A two-second request cannot remain in the remote-thread wait for 30 seconds.
- The internal `ROOKIE_E2E_APPBOUND_MODE=injection_only` test mode performs no impersonation or elevation attempt.

---

## C5. Conflicting `from_path` credential selectors are silently prioritized

**Evidence**

The Rust API is safe because `FromPathRequest::chromium_credentials` accepts one enum value. The Node and CLI option shapes flatten that enum into `plaintext_only`, `browser_id`, and `key_path`.

Both implementations use `if`/`else if`, silently selecting the first present option:

- [`bindings/node/src/lib.rs`](../bindings/node/src/lib.rs#L1395)
- [`cli/src/main.rs`](../cli/src/main.rs#L162)

The explicit Chromium path option parser already rejects more than one selector, proving the intended rule. The top-level CLI flags also declare mutual conflicts; the `from-path` subcommand does not.

**Recommended fix**

- Add a shared selector-count validator in each binding layer.
- Add `conflicts_with_all` declarations to all three CLI subcommand options.
- Retain runtime validation even with clap constraints so programmatic construction cannot bypass the rule.
- Return `InvalidArg`/usage error before opening the source.

**Required tests**

Cover all three pairwise conflicts and the all-three case in Node and CLI. Assert no extraction function is called.

---

## C6. Header generation omits send-time expiration

**Evidence**

[`filter_snapshot()`](../rookie-rs/src/read.rs#L284) checks expiration once when constructing `ReadResult`. [`header()`](../rookie-rs/src/read.rs#L116) later applies only octet, domain, path, and Secure checks.

**Three distinct cases: two defects and one unresolved contract gap**

An earlier revision classified the `include_expired` interaction as settled product behavior. ADR 0004 does not settle it: it says the snapshot is unfiltered and the jar owns send-match, but it does not say retaining expired cookies in inventory authorizes sending them.

| Case | Classification |
| --- | --- |
| A cookie expires between snapshot creation and `header()` | **Confirmed defect.** A send-time view emitting a cookie that expired after the snapshot was taken is wrong under any reading. |
| Snapshot comparison uses `expires < now`, so `expires == now` is retained ([`read.rs`](../rookie-rs/src/read.rs#L299)) | **Confirmed defect**, minor. RFC 6265 §5.3 treats expiry-time ≤ current-time as expired. |
| `include_expired(true)` then `header()` emits those cookies | **Unresolved contract gap with an unsafe default.** `include_expired` is an inventory choice; `header()` is the component ADR 0004 says owns send-match. The ADR does not state that inventory retention changes send eligibility. |

Auditing and diffing workflows explain why expired cookies belong in a snapshot. They do not establish that a method producing an HTTP `Cookie` request header should send them. If maintainers need a raw serialization of every snapshot member, it should have a name that does not imply send-safe header selection.

**Recommended fix**

Apply one send-time rule inside the header view: a cookie with an expiry is eligible only while `expires > now`. This excludes cookies that expired after snapshot creation and expired cookies retained in inventory through `include_expired(true)`. Also correct the snapshot boundary comparison to treat `expires == now` as expired when `include_expired` is false.

```rust
fn is_unexpired(cookie: &Cookie, now_epoch: u64) -> bool {
    cookie.expires.is_none_or(|expires| expires > now_epoch)
}
```

Add this as a crate-private clock-aware helper and keep the public method on `SystemTime`.

Document that `include_expired` changes snapshot retention only. If a raw formatter is required, add a separately named compatibility formatter; do not overload `header()` with both raw-inventory and send-match semantics.

Two sequencing constraints:

- **Do not silently change `filter_snapshot` in the same PR.** The `<` to `<=` correction changes the snapshot contents, not just the header view; if both move at once, state which behavior changed where and re-check any golden that pins expiry boundaries.
- Do not silently map a pre-Unix-epoch clock to epoch zero ([`read.rs`](../rookie-rs/src/read.rs#L285), currently `.unwrap_or(0)`, which disables expiry filtering entirely); return a typed clock error or an explicitly documented fallback.

**Required tests**

- expired before snapshot;
- expiry exactly equal to current time;
- expiry falling between snapshot creation and header generation;
- `include_expired(true)`: retain the cookie in `cookies()` but omit it from `header()`.

---

## C7. Profile-scoped read warnings lose row-loss categories

**Evidence**

[`harvest_report_warnings()`](../rookie-rs/src/read.rs#L310) uses a substring match for `"decrypt"`. It misses `decode_failed`, `provider_failed`, `provider_unavailable`, and non-Chromium row-read failures. The no-profile legacy path uses the authoritative `CHROMIUM_UNSEAL_ISSUE_CODES` set and emits `row_read_failed` separately.

**Recommended fix**

Create one typed warning fold shared by both read paths. It should map:

- all `CHROMIUM_UNSEAL_ISSUE_CODES` to `decrypt_failed`, if that compatibility warning code is intentionally retained;
- skipped non-unseal rows to `row_read_failed`;
- invalid header octets to `invalid_octets`;
- a non-completed operation to an error, per C1, rather than an ordinary warning under the current contract.

Avoid substring matching. Keep issue-code constants close to the emitters and use them from the projection.

**Required tests**

Test every Chromium unseal code and at least one Gecko row-read failure through profile and no-profile reads. Their `ReadWarning` results must be equivalent.

---

## A1. Isolation metadata is discarded before the recommended header view

**Evidence**

`CookieContext` explicitly states that CHIPS partition keys and Firefox container/origin attributes participate in identity. `DetailedCookie` preserves that context. Report construction and `ReadResult`, however, project finalized records into the frozen eight-field compatibility `Cookie` before header generation:

- [`common/enums.rs`](../rookie-rs/src/common/enums.rs#L48)
- [`report_build.rs`](../rookie-rs/src/browser/report_build.rs#L978)
- [`read.rs`](../rookie-rs/src/read.rs#L87)

A URL alone also lacks the top-level-site, method, navigation, and container context needed for browser-equivalent SameSite and partition decisions.

**Immediate 0.6 action**

Document `header(url)` as a legacy RFC-domain/path/Secure view, not a browser-equivalent cookie jar. State that it is isolation-unaware. Do the same for Python `as_jar()` and any binding helper that consumes `Cookie`.

**0.7 design recommendation**

- Retain `DetailedCookie` internally in the recommended snapshot.
- Expose `detailed_cookies()` alongside a compatibility `cookies()` projection, or introduce `DetailedReadResult`.
- Replace or supplement `header(url)` with `header(SendContext)`.
- Require enough context to select a partition/container; do not merge isolated cookies when context is absent.

At minimum, `SendContext` should include request URL, top-level site, method class, navigation/subresource context, and optional Firefox container/private identity.

**Required tests**

- Same name/domain/path in two CHIPS partitions.
- Same name/domain/path in two Firefox containers.
- SameSite Lax/Strict behavior under cross-site top-level and subresource contexts.
- Compatibility projection remains byte-for-byte stable.

---

## A2. Error identity and stop reasons disappear across public boundaries

### Rust

The public return alias is `anyhow::Result`. Callers must downcast `RequestError` or `DirectPathError`, then separately call `stop_reason()` and `fault_kind()`. Some paths are unstructured and therefore classify inconsistently.

### Python and Node

Both bindings reduce errors to request-vs-engine plus formatted text. Stable `RequestError::code()`, direct-path reason fields, ambiguous profile candidates, and `StopReason` are unavailable. This is especially harmful because both bindings expose timeout and cancellation.

### Recommended fixes

**0.6 additive binding fix:** expose structured fields on binding exceptions/errors:

- `kind`;
- `code`;
- `stopReason` / `stop_reason`;
- ambiguous `profileIds` / `profile_ids`;
- direct-path `sourceKind`, `targetOs`, and redacted path metadata where appropriate.

Do not require callers to parse `Display` or `Debug` strings.

**0.7 Rust fix:** introduce a `#[non_exhaustive]` public error enum with stable top-level variants such as `Request`, `Stopped`, `Source`, and `Engine`. Preserve internal context as error sources. Derive `fault_kind()` and `stop_reason()` from that enum for compatibility, then deprecate them as separate taxonomies.

Also make Python option-shape failures use `RookieRequestError`, matching the documented exception contract.

---

## A3. `Request` means different selection policies in different functions

`extract(Request::browser(id))` uses the first legacy-compatible profile. `extract_report(Request::browser(id))` uses all profiles. The same request value therefore has function-dependent meaning.

This cannot be corrected silently in 0.6 because both behaviors are compatibility-sensitive.

**0.6 action**

- Put the difference in both functions' rustdoc and the job-selection table.
- Prefer `browser_report()` for explicit report semantics.
- Correct `browser_report` rustdoc: its middle argument is the unified ADR 0003 profile query, not opaque-ID-only.

**0.7 action**

- Rename `Request` to `ExtractRequest`.
- Introduce a report-specific request only if necessary, or put an explicit `ProfileSelection` on the job so selection is data rather than an implicit function policy.
- Preserve `ReadRequest` as the unfiltered snapshot job; its lack of `.domains()` is intentional.
- Do not collapse report and snapshot failure philosophies: reports may return structured failed/partial results, snapshots return a usable result or error.

---

## A4–A5. Runtime control and direct-path portability

### Aggregate and listing operations

`load_report`, `browser_profiles`, and related listing/report helpers create a standard internal runtime. Callers cannot supply timeout or cancellation.

Avoid adding several unrelated request types immediately. In the 0.7 API design, introduce one reusable execution-control value containing timeout and cancellation, then compose it into read, extract, report, load, and listing jobs. Keep current simple functions as default-policy wrappers.

### Chromium explicit-path credentials

`ChromiumPathRequest::new()` defaults to `Automatic`. Automatic works on Unix but always errors on Windows because Windows requires an explicit `Local State` file. `BrowserId` is rejected on Windows, while `LocalStateFile` is rejected on Unix. `PlaintextOnly` is the only variant accepted everywhere.

**0.6 action:** document the platform matrix on `ChromiumCredentialSource`, fix Unix-only README examples, and make the invalid Windows default explicit in rustdoc.

**0.7 action:** require credentials at construction, or provide platform-specific constructors whose names encode the supported source.

Scope the claim precisely when writing that rustdoc: what always fails on Windows is a *default-constructed `ChromiumPathRequest`* left on `Automatic`. It is not true that direct-path extraction generally fails on Windows — `PlaintextOnly` works everywhere, `LocalStateFile` is the supported Windows form, and `from_path` on a non-Chromium source never reaches this code. The defect is a default that cannot succeed on one tier-one target, which is narrower and more accurate than "the constructor is broken on Windows."

The platform-divergent deprecated `chromium_based` signatures should be documented, not redesigned; remove them as planned in 0.7.

---

## A6. Stopped report work is classified as absence

`stopped_browser_draft()` sets `detected: false`, supplies no error issue, and carries only a non-completed termination. Aggregation then increments `browsers_not_detected`; if no source succeeded, status can be `no_sources`.

The termination field lets careful callers infer what happened, but the status and counters still state that the browser was absent even though discovery may never have run.

**Recommended fix**

- In 0.6, attach a typed request/browser-scoped stop issue so status cannot become ordinary `no_sources` after work stopped.
- In the next report schema version, add an `unattempted` or `unknown` browser count rather than forcing stopped work into detected/not-detected.
- Preserve the independent termination field.
- Add golden cases for stop-before-discovery, stop-after-detection, and stop-after-one-source.

---

## A7. Malformed required host identity is coerced to an empty domain

Chromium maps a SQL `NULL host_key` to `""`; Firefox session JSON maps a missing or non-string `host` to `""`. The Chromium behavior is explicitly pinned by a compatibility test, so it is not safe to label this an accidental one-line bug.

An empty domain is still not a meaningful cookie identity. The safe migration is:

1. Add a typed row issue and count the malformed identity.
2. Preserve raw unknown metadata on detailed/report paths where possible.
3. Keep the legacy projection behavior through the compatibility window if required by ADR 0001.
4. In 0.7, reject rows missing required identity rather than emitting an unattributable cookie.

Malformed optional context should continue to be preserved as unknown rather than causing the whole row to be lost.

---

## A8. App-Bound behavior has no caller-selected runtime policy

The default [`appbound` feature](../rookie-rs/Cargo.toml#L57) makes Windows v20 recovery automatic when App-Bound metadata is present. [`get_keys()`](../rookie-rs/src/windows/appbound/mod.rs#L218) first attempts reflective COM injection and can then attempt an elevated SYSTEM-impersonation fallback. Callers can neither disable App-Bound recovery for a request nor limit it to the non-elevated path. The compile-time Cargo feature is deployment-wide, not a per-operation policy.

This is distinct from C3 and C4. Deadline propagation and removal of parent-environment mutation are correctness fixes and must land in 0.6 without requiring a public API expansion. Caller control over whether native injection or elevated fallback is permissible is an API gap.

`ROOKIE_E2E_APPBOUND_MODE` is not a solution. It is an undocumented, process-global test switch, offers only injection-only/elevated-only routing, and cannot disable App-Bound recovery. Exposing it operationally would reproduce the same shared-state and composability problems identified in C4.

**0.6 action**

- Document that App-Bound recovery is automatic when compiled in and that it may attempt injection followed by an elevated fallback.
- Document the compile-time feature boundary and the privilege/security implications.
- Keep the E2E switch test-only. Do not advertise an environment variable as request policy.

**0.7 design recommendation**

Add a caller-selected policy to the redesigned execution/credential configuration rather than creating another standalone job type. A minimal shape is:

```rust
#[non_exhaustive]
pub enum AppBoundPolicy {
    Disabled,
    InjectionOnly,
    AllowElevatedFallback,
}
```

The new API should use a conservative, explicit default; compatibility wrappers may preserve today's automatic fallback during their deprecation window. Bindings must expose the same three states without boolean combinations. Policy must be request-local and immutable after job construction.

**Required Windows tests**

- `Disabled` performs no injection, process spawn, process enumeration, or impersonation.
- `InjectionOnly` never enters the elevated fallback after injection failure.
- `AllowElevatedFallback` preserves the documented attempt order and still obeys the shared deadline/cancellation control.
- Concurrent jobs with different policies do not affect one another.
- Rust, Node, Python, and CLI policy values map to the same internal enum.

---

## D1. Documentation corrections required before 0.6 final

The following are directly verified:

1. `read`, `from_path`, `ReadRequest`, `FromPathRequest`, and most builders have little or no rustdoc, despite being the recommended surface.
2. Strict rustdoc fails on a private `fan_out` link and an unresolved `load_report` link in `load()` documentation.
3. `browser_report` incorrectly says names and paths are not selection keys; implementation uses the ADR 0003 unified resolver.
4. `load()` is listed as deprecated in architecture guidance but lacks `#[deprecated]`.
5. All four READMEs still advertise `0.6.0-alpha.x` while the workspace is `0.6.0-beta.1`.
6. Session-cookie guidance is demonstrated with Chrome, but all 36 Chromium registry entries declare no separate session source. Only Gecko-family entries declare session JSON formats.
7. The architecture class catalog names a nonexistent `KeyPath` credential variant and omits `Automatic` and `LocalStateFile`.
8. Root documentation says all macOS Chromium uses Keychain v10 despite registry exceptions for Cốc Cốc and Yandex.
9. Chrome's official announcement dates cookie App-Bound Encryption to Chrome 127, and documentation saying only `133+` is too narrow. **The correction is to adopt the code's existing two-tier wording, not to replace 133 with 127 globally** — the implementation is already precise and the README is the only coarse statement. [`windows/appbound/mod.rs`](../rookie-rs/src/windows/appbound/mod.rs#L3) records reflective COM injection as *unprivileged, Chrome 127+* and the DPAPI/CNG SYSTEM impersonation fallback as *elevated, Chrome 127–133+*; [`windows/ncrypt.rs`](../rookie-rs/src/windows/ncrypt.rs#L19) scopes 133+ specifically to *"the App-Bound v20 key flag 3 introduced in Chrome 133+."* Copy that distinction into the README rather than flattening it in either direction.
10. The Node README warns against optional access on an empty profile list, then later passes `listed[0]?.profile.profileId`, where `undefined` means all profiles.
11. The root README's CLI examples lead with legacy flags instead of the documented 0.6 job subcommands.
12. `CookieToString` is public and produces unfiltered `name=value` pairs, but its name can be mistaken for the safe `ReadResult::header()` view.

**Recommended documentation/CI fix**

- Bring recommended API rustdoc up to the standard already used by `Request` and `extract`, including errors, selection semantics, timeout behavior, and examples.
- Fix the two broken links and add strict `cargo doc` to CI.
- Add `#![warn(missing_docs)]` only after establishing a manageable baseline; do not hide hundreds of warnings behind a permanent blanket allow.
- Correct all README and architecture items above in one documentation PR.
- Mark `load()` deprecated consistently and extend API-contract checks to detect deprecation attributes if the current snapshot tool does not.
- Deprecate `CookieToString` in 0.6 with a note that it is an unfiltered compatibility formatter. Remove or rename it in 0.7; callers needing a safe header must use the context-aware API.

---

## D2. Generated schema does not express identifier validation

Rust deserialization validates open identifiers as `^[a-z][a-z0-9_]*$` and opaque installation/profile IDs as 64 lowercase hexadecimal characters. The generated JSON Schema represents them as plain strings.

**Recommended fix**

- Supply a custom `schemars::JsonSchema` implementation or schema annotation for the transparent newtypes.
- Keep vocabularies open; add lexical `pattern` and length constraints only.
- Add schema tests that reject invalid examples accepted by the current schema and accept unknown-but-well-formed values.
- Regenerate the schema and Python DTO artifacts in the same change.

Producer-side `known()` currently validates only through `debug_assert!`. Since invalid crate-produced values would create wire data the crate itself rejects, use unconditional validation at construction or a compile/test-time generated vocabulary validation that covers every producer path.

**Ship these as two changes, not one.** The schema `pattern` work and the `known()` producer hole are separate failure modes with separate blast radii: the schema change regenerates published artifacts and can gate release, while the producer change is an internal assertion strengthening that may surface latent bad codes in platform-specific paths. Coupling them means a producer-side surprise blocks schema publication. If schema publication is the 0.6 gate, land the schema constraints first and the producer validation independently.

---

## Additional confirmed improvements

These are real but should not displace the priority defects.

### Public type ergonomics

- Add `Clone`, `PartialEq`, `Eq`, and `Hash` to the frozen `Cookie`; then derive applicable traits on `DetailedCookie` and report containers. This is additive and removes hand-copying already present in both bindings. Severity is ergonomic, not critical.
- Re-export `Cookie`, `CookieContext`, and `DetailedCookie` at the crate root. `Cookie` is not currently root-re-exported: `lib.rs` does `pub use common::enums`, which republishes the *module*, so callers must write `rookie_cookies::enums::Cookie` or `rookie_cookies::common::enums::Cookie`. (An earlier draft attributed a contrary claim to the Grok report. That was a mis-citation — Grok described `Cookie` as public in the crate-visibility sense, not as a crate-root re-export. The ergonomic recommendation stands on its own.)
- Change direct-path `ReadResult::browser_id()` from the empty-string sentinel to `Option<&str>` in 0.7. Add a non-breaking `browser_id_opt()` first if callers need a migration path.

### Diagnostics

- Preserve `UnavailableCode::{Decrypt, Decode, ProviderUnavailable, ProviderFailed}` when finalization rejects a record instead of collapsing all four to `"unavailable"`.
- Replace `flatten_selected_report_cookies`' single unstructured error with distinct typed causes: no selected source, selected sources failed, and no discovered source.
- Expose issue-sample truncation constants/flags consistently in bindings.
- Node's `ReadWarning.count` clips a Rust `u64` to `u32` without a saturation flag. Either expose a JavaScript-safe integer representation with a saturation flag or document and type the bound explicitly.

### CLI and binding lifecycle

- Install cooperative signal cancellation for `read`, `header`, and `from-path`, all of which already accept cancellation handles. Immediate Ctrl-C termination bypasses Rust `Drop` and can leave private cookie DB snapshots in the temp directory.
- The separate claim that CLI `log::warn!` cleanup messages are invisible is not supported: the resolved `tracing-subscriber` feature set includes `tracing-log`/`log-tracer`.
- Route Python Netscape serialization through the Rust formatter or add byte-for-byte shared fixtures. The current Python reimplementation duplicates security-relevant escaping rules.
- The Node panic-guard observation is hardening advice, not a confirmed defect: no reachable panic was demonstrated outside guarded worker paths.

---

## Internal architecture maintenance

The following claims from the Grok report are confirmed as maintenance debt, not release-blocking defects:

1. Compatibility fallback can compare a generated English diagnostic to decide which product wording to use. Replace it with typed `CompatibilityEvidence`; prose must never drive policy.
2. `xtask check-stage-boundary` does run in CI, but it does not fence `ExtractedProfile`, `EngineExtract`, `SourceDraft`, or `ProfileDraft`. Add only the invariants those types actually promise.
3. Gecko and Safari/IE retain two acquisition frames with slightly different stop sampling. Unify only if one typed outcome can preserve both policies; do not flatten behavior for aesthetic symmetry.
4. Registry and direct-path Chromium extraction have two entry towers over the same decoder. Centralize key acquisition/unseal policy where practical, while retaining distinct discovery and explicit-path boundaries.
5. `_with_runtime` is a naming convention rather than a type-level guarantee. Prefer making runtime-taking production seams the only non-test path and keep unsuffixed helpers under `#[cfg(test)]` where possible.
6. **Resolved 2026-08-20:** the dedicated mechanical pass aligned adapter and engine functions with `acquire` / `decode` / `extract`. Engine-private parse scratch may still use `*Draft`, as ADR 0005 permits.
7. Listing DTOs omit discovery-time `selected` and acquisition hints, so report goldens cannot detect their drift. Add characterization tests unless those fields are intentionally added to the wire.
8. Discovery filesystem walks and the Chromium cursor contain cooperative-cancellation blind spots. Add checkpoints at bounded iteration intervals; do not claim hard cancellation around OS calls that cannot be interrupted.

Do not introduce a generic engine trait, merge the Chromium and Gecko inventory towers, add URL filtering to `ReadRequest`, or carve files by line count. Those were considered and explicitly closed by the current ADRs.

---

## Recommended implementation sequence

The order below was revised after review: the previous sequence placed the Windows App-Bound work at PR 4, behind header expiry and option validation, while the severity table rated it High and before-0.6-final. On Windows, environment mutation under `load()` fan-out and a 30-second wait that ignores a 2-second timeout outrank both. App-Bound now sits at PR 2, and **Windows 0.6 final is blocked on it**.

### PR 1 — Stop and deadline correctness

- Fix C1 on **both** routes — the compatibility `Emit` arm and the report flatten — and C2. Landing either alone leaves the recommended profile-scoped path silently truncating.
- Implement the per-surface stop rule; assert `load()`'s in-flight-cookies contract still holds.
- Add typed-stop projection tests and `ManualClock` budget tests.
- Do not change report partial-result semantics.

### PR 2 — Windows App-Bound control *(blocks Windows 0.6 final)*

- Fix C3 and C4.
- Remove parent-environment mutation; pass the encrypted blob in an explicit child environment block.
- Thread runtime into injection and the elevated fallback; replace the fixed 30-second wait with bounded, checked intervals.
- Add Windows concurrency tests. No new public policy type in this release.

### PR 3 — Read/header correctness

- Fix C7 and all C6 behavior: enforce send-time expiry, correct the `expires == now` boundary, and make `include_expired` affect inventory retention only.
- Add a shared warning projector and a clock-aware header seam.
- Document the inventory/send-match distinction explicitly; if `filter_snapshot` boundary behavior moves, say so and re-check expiry goldens.

### PR 4 — Credential option validation

- Fix C5 in Node and CLI.
- Share test vectors for mutually exclusive selectors.
- Align Python option-shape failures with `RookieRequestError`.

### PR 5 — Documentation and contract gates

- Apply every D1 correction.
- Fix strict rustdoc and add it to CI.
- Add recommended API rustdoc and deprecation-state checking.
- Update session and platform matrices.

### PR 6 — Binding diagnostics

- Expose stable request/direct-path codes and stop reasons.
- Preserve ambiguous profile candidates.
- Add warning saturation semantics.

### PR 7 — Report semantics and schema

- Fix A6 and D2.
- Preserve finalization cause codes.
- Decide whether new report counters require schema version 2.

### 0.7 design — Public projection and job cleanup

- Make detailed/isolation-aware cookies the recommended snapshot representation.
- Introduce `SendContext` for browser-equivalent header selection.
- Introduce one typed public error hierarchy.
- Make profile selection explicit rather than function-dependent.
- Rename `Request` to `ExtractRequest`; keep `ReadRequest` for unfiltered snapshots.
- Compose one execution-control value into aggregate/listing jobs rather than adding unrelated builders.
- Compose caller-selected `AppBoundPolicy` into that configuration; do not use a process-global environment switch as policy.
- Require a valid platform credential strategy when constructing a Chromium path request.
- Replace empty-string result identity with `Option`.
- Hide or remove deprecated compatibility modules/functions as already planned.

---

## Reconciliation of the three source reports

### Codex report

All eight principal observations were confirmed. The App-Bound item is best split into three concerns: deadline cooperation, process-global environment mutation, and missing caller policy. Its severity is higher on Windows than the original consolidated table stated.

### Claude report

Confirmed directly: A1–A6; the behavior in A7; the race portion of B1; the signal portion of B2; B3; C1–C2; D1–D4; E1–E3; E4 items 1, 3, 5, 7, and 8; F1–F4; G1, G4, and G5; H1–H2.

Corrections and qualifications:

- **B1:** the environment contains the encrypted App-Bound blob, not the decrypted master key.
- **B2:** missing signal installation is confirmed; the claim that `log::warn!` is not bridged is false for the resolved CLI features.
- **A7:** empty-host coercion is real but Chromium compatibility behavior is pinned by a test, so it requires a deliberate migration.
- **C1 and D1:** facts are correct; “High” severity was overstated for type ergonomics and rustdoc coverage.
- **E4.2:** the frozen `Cookie` not being `#[non_exhaustive]` is intentional. Documentation should make the distinction clear, but the type itself is not defective.
- **E4.4:** Chrome 127 is externally confirmed as the App-Bound cookie rollout; implementation-specific claims about which fallback requires 133 must remain precise.
- **E4.6:** the resolver checks opaque ID first, then treats the human-readable keys as one ambiguity set. That is consistent with the ADR's zero-or-more-than-one rule; it is not a demonstrated resolver bug.
- **G2:** seconds in Python/CLI and explicitly named milliseconds in Node are an idiomatic difference, not inherently a defect. Coverage and stop classification are the real gaps.
- **G3:** no reachable unguarded panic was demonstrated; retain as hardening only.
- **G6:** it combines several independent observations and should not be scheduled as one issue.

### Grok report

Its deadline, request-semantics, rustdoc, `CookieToString`, isolation, and internal-maintenance observations are confirmed. Most internal items are accepted debt rather than defects.

Corrections and qualifications:

- The stage fence is CI-enforced; only its type coverage is incomplete.
- `Cookie` is **not** re-exported at the crate root. Grok's architecture catalog described it as public in the crate-visibility sense, which is correct; this consolidation's earlier draft over-read that as a claim about `pub use rookie_cookies::Cookie` and recorded a correction Grok had not earned. The underlying fact — callers must name `rookie_cookies::enums::Cookie` — is unchanged.
- The snapshot/report/extract split is intentional; the defect is implicit, function-dependent selection and insufficient documentation, not the existence of distinct jobs.
- Open string newtypes are intentional wire design; schema lexical constraints and Rust ergonomics can improve without closing the vocabularies.
- `CookieToString` is compatibility-pinned, so deprecate first rather than deleting it in 0.6.

---

## Verification record

**Baseline:** commit `e6199b0a7b22a0b22e3d6efb1b5d449b3cf06cd1`, workspace version `0.6.0-beta.1`, host `darwin` (macOS), recorded `2026-08-20`. Working tree clean apart from untracked `docs/architecture*.md`.

Runs from the first consolidation pass are listed with the exact command line so they can be reproduced or challenged. They were **not** re-executed during the review round below; treat any row not marked as re-verified as a first-pass claim against the same commit.

| Check | Command | Result |
| --- | --- | --- |
| Read all three `docs/architecture_api_gap_*.md` source reports | — | Completed |
| Direct source validation of core, CLI, Python, Node, schema, registry, and CI claims | — | Completed (extended in the review round below) |
| Workspace tests | `cargo test --workspace --all-targets --locked` | Passed (first pass; not re-run) |
| All-feature lint | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Passed (first pass; not re-run) |
| No-default-feature tests | `cargo test -p rookie-cookies --no-default-features --all-targets --locked` | Passed (first pass; not re-run) |
| Stage-boundary and cfg-location fences | `cargo run -p xtask --locked -- check-cfg-locations` / `cargo run -p xtask --locked -- check-stage-boundary` | Passed (first pass; not re-run) |
| Public API snapshot | `python3 scripts/check-public-api.py --platform macos` | Passed (first pass; not re-run) |
| Doctests | `cargo test --workspace --doc --locked` | Passed (first pass; not re-run) |
| Strict rustdoc | `RUSTDOCFLAGS="-D warnings" cargo doc -p rookie-cookies --all-features --no-deps --locked` | Fails on the two confirmed `load()` links |
| Windows execution | — | Not performed; Windows-only conclusions are source-validated |
| Windows cross-compilation from macOS | — | Inconclusive; bundled C dependencies lacked a configured Windows toolchain/sysroot |

---

## Review rounds: incorporation of external review comments

An initial review challenged parts of this document. Each point below was re-checked against commit `e6199b0` by direct source reading before the document was amended. Every listed point was accepted; several changed a recommendation rather than only its wording. A follow-up review then revisited C6, the verification commands, App-Bound policy, C1's surface taxonomy, and source-report scope; those revision 3 changes are recorded in the table and revision history.

| Point | Disposition | Re-verified at |
| --- | --- | --- |
| C1's fix is too narrow — profile-scoped `extract`/`read` reach the same defect through `flatten_selected_report_cookies`, which never reads `termination` | **Accepted; C1 widened.** This was the most consequential correction: PR 1 as previously written would have shipped with the recommended path still broken. | `lib.rs:402-419` (no `termination` reference), `lib.rs:360-370`, `read.rs:184-186` |
| A blind `Err(stop)` on every `Emit` contradicts `load()`'s documented in-flight contract | **Accepted; per-surface rule added.** | `named.rs:494-497` rustdoc vs `named.rs:435-442` error handling |
| C6 bundles a real send-time gap, an RFC boundary error, and an `include_expired` interaction claimed to be settled by ADR 0004 | **Revisited in revision 3.** The three cases remain separate, but the third is an unresolved contract gap with an unsafe default, not a settled product decision. Inventory retention does not authorize sending an expired cookie; `header()` should always apply send-time expiry. | ADR 0004 Decision 3; `read.rs:116`, `read.rs:284-299` |
| PR sequence under-ranked C3/C4 relative to the severity table; `AppBoundPolicy` contradicts this document's own "no new request-model surface in 0.6" guidance | **Accepted.** App-Bound moved to PR 2 and marked as blocking Windows 0.6 final; the public policy enum deferred to 0.7. | Severity table vs prior sequence |
| D1.9 should adopt the code's existing two-tier Chrome version wording rather than replacing 133 with 127 | **Accepted.** The implementation is already precise; only the README is coarse. | `windows/appbound/mod.rs:3-4`, `windows/ncrypt.rs:19-21` |
| A5's "guaranteed to fail on a tier-one target" over-scopes to all Windows direct-path use | **Accepted; scoped to a default-constructed `ChromiumPathRequest` left on `Automatic`.** | `direct_path/mod.rs:354-363`, `direct_path/windows.rs:336-345` |
| Grok attribution on the `Cookie` crate-root re-export was a mis-citation | **Accepted; attribution corrected**, recommendation retained. | `lib.rs:24`, `lib.rs:29` |
| Verification record is unauditable without a commit and command lines | **Accepted; record pinned above** and first-pass rows marked as not re-run. | — |
| D2 should not couple schema regeneration to the `known()` producer fix | **Accepted; split into two changes.** | — |

The reviewer also confirmed C1–C5, C7, A3, A5, and D1 items 3–4 independently against source, and endorsed the closed-on-purpose list (no engine trait, no Chromium inventory merge, no URL-filtered `ReadRequest`, no line-budget carve, and retention of the snapshot/report/extract split). Those require no change here.

Three corrections propagated back into [`architecture_api_gap_claude.md`](architecture_api_gap_claude.md), which has been amended in place with each change recorded in its own verification record:

- **§B1** described a plaintext master key persisting in the parent environment. `retrieve_via_injection` decodes `app_bound_encrypted_key`, strips the `APPB` prefix, and passes that still-encrypted blob to the child; the decrypted key is returned as `Zeroizing<Vec<u8>>` and never reaches the environment. The concurrency defect is real; the credential-exposure framing was not.
- **§B2** claimed CLI cleanup warnings are never printed because no `log`↔`tracing` bridge is installed. `cli/Cargo.toml` does not disable default features, so `tracing-subscriber`'s `tracing-log` is active and `fmt()…init()` installs the bridge. The primary finding — Ctrl-C kills the process before `Drop` runs at all — is unaffected.
- **§A1** was scoped to the compatibility `Emit` arm only, and has been widened to the report-flatten route and the per-surface fix rule described in C1 above.

The consolidated document is authoritative where a source report's summary or implementation ordering remains stale. In particular, Claude's suggested order still contains the superseded recommendation to bridge `log` into `tracing`; the resolved CLI feature set already installs that bridge.

## Revision history

| Revision | Date | Summary |
| --- | --- | --- |
| 1 | 2026-08-20 | Initial consolidation and source validation of the Claude, Codex, and Grok reports. |
| 2 | 2026-08-20 | Incorporated the first review round: widened C1 to both projection routes, defined per-surface stop behavior, raised and reordered Windows App-Bound fixes, corrected Chrome version wording and A5 scope, split D2, and pinned the verification baseline. |
| 3 | 2026-08-20 | Incorporated the follow-up review: made `header()` unconditionally send-safe with respect to expiry, corrected the recorded command lines, added A8 for caller-selected App-Bound policy, rejected the E2E environment switch as operational policy, separated flat `load()` from report APIs, and reconciled source-report scope. |

## Scope note

This is a validated review and implementation recommendation, not an implementation. It intentionally preserves the existing ADR decisions and distinguishes 0.6-safe changes from breaking 0.7 work. Revision 3 modifies only this consolidated document. Production source, schemas, and public API snapshots were not modified. The Claude input was amended during revision 2 as recorded above; the Codex and Grok inputs were left unchanged.
