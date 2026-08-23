# Security notes

This is the in-repo security record for shipped behavior, pinned native
parsers, and cryptography review status. To report a vulnerability privately,
follow the root [`SECURITY.md`](../SECURITY.md) policy — do not report a new
vulnerability by editing this file.

This file merges what used to be three separate short documents (security
corrections, SQLite inventory, cryptography review): they overlapped in
scope and were easy to lose track of split up. Each section below still has
its own update trigger, noted at its start, since that did not change with
the merge.

- [Security corrections](#security-corrections) — append-only ledger,
  updated when a correction ships.
- [Bundled SQLite inventory](#bundled-sqlite-inventory) — calendar/release
  cadence, next review date at the bottom of that section.
- [Linux confidential-session cryptography review](#linux-confidential-session-cryptography-review)
  — updated when a specialist review completes or the reviewed code changes.

See also [troubleshooting.md](troubleshooting.md) for platform-specific
quirks (Keychain prompts, Safari Full Disk Access, empty session-cookie
results), and [ADR 0001](adr/0001-cookie-extraction-compatibility-and-report-contracts.md)
for the compatibility contract the corrections below amend.

## Security corrections

Intentional security behavior changes, recorded even when they differ from
the compatibility contract in
[ADR 0001](adr/0001-cookie-extraction-compatibility-and-report-contracts.md).
Append-only: add a new row when a correction ships, do not edit history.
Bundled SQLite version pins are tracked separately in
[Bundled SQLite inventory](#bundled-sqlite-inventory) below, on its own
calendar-driven cadence — do not merge that table with this one.

| Correction | Affected surfaces | Prior behavior | Replacement behavior | Stable code and counters | All-row behavior | Migration | Owner and rationale | Regression |
|---|---|---|---|---|---|---|---|---|
| C4a: confidential Linux Secret Service session | Rust, Python, Node, and CLI Chromium extraction on Linux for `v11` cookies | Secret Service passwords were requested through a `plain` session and crossed D-Bus without session encryption. | Passwords are requested only after negotiating `dh-ietf1024-sha256-aes128-cbc-pkcs7`; failed negotiation never retries `plain`. Other independently configured keyring backends may still be attempted. | If every candidate provider fails, encrypted `v11` rows use `provider_failed` at the `decrypt` stage. Discovery counters are unchanged; each affected selected row increments `rows_seen` and `rows_skipped`, and emits no cookie. | A source containing only affected rows remains a succeeded source with zero cookies and an error-severity row issue, so report status is `partial`; legacy Chromium extraction preserves its existing empty-result behavior. | No API migration. Ensure the desktop Secret Service supports confidential sessions or configure a supported KWallet backend. | Security owner: maintainers. Plaintext credential transport on the session bus is not an acceptable fallback. | `linux::confidential::tests::negotiation_uses_only_the_confidential_algorithm_and_never_retries_plain`; `linux::tests::confidential_session_negotiation_failure_remains_a_provider_error`; `report_build::engine_chain_tests::a_confidential_provider_failure_keeps_its_exact_report_code` |
| C4b: secret-boundary zeroization and diagnostic redaction | Rust, Python, Node, and CLI Chromium extraction on Linux, macOS, and Windows | Credential results, D-Bus/native copies, confidential-session private/shared/AES material, and decrypted row frames could be dropped without first wiping their backing storage; macOS Keychain stderr was copied into diagnostics. | Secret values are owned by zeroizing wrappers at extraction/native boundaries. The Linux DH private exponent, shared secret, padded derivation input, session AES key, and decrypted confidential payload are wiped on success and every error path. Decoded cookie text stays protected through context validation and is transferred to a public `String` only on successful projection. DPAPI memory is wiped before `LocalFree`; discarded CNG, Keychain, candidate-plaintext, and cloned frames are likewise wiped. Keychain stderr content is fully redacted, retaining only its byte count. | Extraction codes and counters are unchanged. | Source and all-row behavior are unchanged. | Diagnostics no longer contain `/usr/bin/security` stderr text; use the exit classification and code for troubleshooting. | Security owner: maintainers. Request-scoped secret copies must not survive cleanup or appear in error/crash formatting. | `common::secret::tests::secret_frames_wipe_sentinel_allocations_on_success_and_failure_cleanup`; `common::secret::tests::panic_output_never_formats_a_live_secret`; `chromium::tests::discarded_detailed_ciphertext_result_is_wiped_without_reading_plaintext`; `linux::confidential::tests::invalid_padding_never_returns_a_partial_plaintext`; `windows::dpapi::tests::native_plaintext_is_wiped_before_its_buffer_can_be_released`; `macos::tests::keychain_errors_preserve_status_and_redact_stderr` |
| C4c: reject embedded NUL in Safari cookie strings | Rust, Python, Node, and CLI Safari extraction on macOS | A domain, name, path, or value containing a NUL before its final terminator was accepted into a cookie, where NUL-aware consumers could silently observe only a prefix. | The whole record is rejected as malformed; no field prefix is emitted. | The existing `row_read_failed` code at the `parse` stage is retained. Discovery is unchanged; each rejected record increments `rows_seen` and `rows_skipped` once and emits no cookie. | Valid records in the source are retained and its report is `partial`. A source whose records are all malformed follows the existing parse-failure rule: report extraction fails and legacy Safari extraction returns an error. | Repair or remove the malformed Safari record; no API migration is required. | Security owner: maintainers. Embedded terminators make the value observed by downstream C-compatible consumers ambiguous. | `safari::tests::embedded_nul_fields_are_rejected_as_malformed_records`; `safari::tests::embedded_nul_record_does_not_discard_a_valid_cookie`; `legacy::tests::legacy_safari_projection_errors_when_every_embedded_nul_record_is_malformed`; `report_build::engine_chain_tests::mixed_safari_embedded_nul_fixture_is_partial_with_exact_row_accounting`; `report_build::engine_chain_tests::all_malformed_safari_embedded_nul_fixture_fails_with_counted_row` |
| `chromium_ciphertext_precedence` | Every legacy and detailed Chromium extraction surface; a row with both a non-empty `value` and `encrypted_value` | Extraction returned the plaintext `value` without inspecting the ciphertext. | Ciphertext is authoritative. The plaintext column is not decoded or allocated when ciphertext is present; the row is streamed immediately to unseal and becomes either available or unavailable without a plaintext fallback. This covers v10, v11, v20/App-Bound, and legacy DPAPI routes. | Every affected unavailable row increments `rows_skipped`. Malformed, unauthentic, or undecodable ciphertext also increments `rows_rejected`. An applicable provider failure increments `provider_failures` once per relevant cipher tier, not `rows_rejected`. | A source containing only affected unavailable rows preserves the existing total-row-failure behavior. Mixed sources retain valid cookies and report the affected rows through the existing partial-result contract. | Callers that relied on the inconsistent plaintext column must repair or re-export the browser data; no API migration is required. | Security owner: maintainers. Returning an unauthenticated alternate value bypassed the browser ciphertext's integrity decision. | `decoder_retains_ciphertext_and_discards_dual_populated_plaintext`; `authoritative_ciphertext_bypasses_null_blob_and_invalid_text_plaintext_columns`; `every_corrected_cipher_tier_uses_ciphertext_on_legacy_detailed_and_report_surfaces`; `chromium_decoder::tests::cursor_is_pull_based_and_never_reads_ahead`; `late_missing_identity_error_wipes_staged_plaintext_before_returning`; `unwind_during_later_unseal_wipes_every_staged_success`; `plaintext_value_failure_precedes_later_metadata_but_ciphertext_bypasses_value`; `injected_provider_routes_mixed_tiers_once_and_isolates_a_failed_tier`; `dual_populated_v20_provider_failure_is_reportable_but_legacy_errors`; `dual_populated_v20_pipeline_decrypts_with_app_bound_tier`; `dual_populated_legacy_dpapi_pipeline_never_projects_plaintext`; `detailed_pipeline_unseals_dual_populated_ciphertext_before_projection`; `extracts_deterministic_legacy_v10_fixture_with_current_user_dpapi`; `provider_failures_are_counted_once_per_distinct_tier_and_not_as_rejected_rows`; `an_undecryptable_row_does_not_fail_the_chromium_source` |
| C4e: redact cookie values from `Debug` | Rust callers and any diagnostic or test output that formats `Cookie`, `DetailedCookie`, extraction reports, or internal decoded records with `Debug` | Derived `Debug` implementations printed plaintext cookie values, unavailable-reason messages, ciphertext buffers, and unknown cipher prefixes transitively through nested report and decoder structures. | Manual `Debug` implementations retain cookie metadata, safe unavailable code, cipher tier, record structure, and partition/container context while rendering value/message fields as `<redacted>`; unknown cipher prefixes are classified without printing their raw bytes. Explicit field access, Serde wire output, and user-requested cookie formatting remain unchanged. | Extraction codes, counters, and row behavior are unchanged. | Source and all-row behavior are unchanged. | Code must not use `Debug` output as a cookie-value transport. Read the public `value` field or serialize the result explicitly when value output is intended. | Security owner: maintainers. Accidental logs, panic diagnostics, and assertion failures must not disclose authentication material merely because a report is formatted for debugging. | `common::enums::tests::public_cookie_debug_redacts_only_the_value`; `common::enums::tests::detailed_cookie_debug_redacts_nested_value_and_keeps_context`; `common::enums::tests::cookie_serde_and_explicit_field_access_retain_the_value`; `cookie_record::tests::internal_record_debug_redacts_plain_and_encrypted_values_transitively`; `chromium_crypto::tests::unknown_cipher_and_route_debug_do_not_expose_raw_prefix_bytes`; `internet_explorer_model::tests::raw_record_debug_redacts_value_bytes_before_decoding`; `report_core::tests::public_report_debug_redacts_nested_cookie_values_without_changing_wire_output` |
| C4f: canonical outcomes and absolute extraction deadlines | Rust, Python, Node, and CLI report extraction; Chromium credential providers; SQLite, Firefox session, Safari, Internet Explorer, macOS Keychain, and Linux Secret Service/KWallet boundaries | Engines assembled divergent outcomes and diagnostics, optional source metadata was collapsed, and provider/native waits or retry chains could start a fresh or unbounded budget. A Firefox persistent-source failure could also suppress a usable session source on compatibility paths. | Every report and compatibility projection is derived after one canonical outcome finalizes source-owned rich records, a structured failure ledger, independent result/termination states, and provenance. Diagnostics are centrally path/secret-redacted and bounded. One absolute monotonic deadline crosses provider, acquisition, decoder, retry, and fallback work. The macOS Keychain child and Linux D-Bus reply waits are enforceable; SQLite/filesystem/Safari/Firefox/IE native work is truthfully cooperative, with checkpoints preventing new chunks, rows, retries, or fallbacks after expiry. Firefox still attempts ordered session recovery after persistent failure while budget remains. | Issue aggregation keys now include code, stage, scope, cause, severity, and retryability. Provider/tier cause and retryability survive report bindings. `ExtractionReport.termination` is independent of status; a discovered zero-row source is `complete`, not `no_sources`. | Partial source data survives later source failure. A usable Firefox session source produces partial output when persistent acquisition fails. Timeout/cancellation/resource exhaustion no longer imply a particular result status. | Report consumers should inspect `termination`, `cause`, `provider`, `tier`, and `retryability`. These are additive report fields with deserialization defaults; legacy cookie structs and flat APIs are unchanged. | Security owner: maintainers. Bounded in-flight secrets and loss-preserving diagnostics require one finalization model and one non-resetting time budget. | `outcome::tests`; `deadline::tests`; `boundary::tests::decoder_emits_nothing_after_the_absolute_deadline_without_sleeping`; `sqlite::tests::query_retries_share_one_decreasing_budget_without_wall_clock_sleep`; `linux::tests::fallbacks_share_one_decreasing_absolute_budget_without_wall_clock_sleep`; `macos::tests::hung_keychain_child_is_killed_and_reaped_with_one_absolute_grace`; `mozilla::tests::persistent_failure_still_returns_selected_session_cookies`; `safari::tests::stable_read_starts_no_verification_or_retry_after_deadline` |

## Bundled SQLite inventory

`rookie-cookies` deliberately enables rusqlite's `bundled` feature. Release
artifacts therefore ship the SQLite amalgamation selected by the locked
`libsqlite3-sys` dependency rather than the target host's SQLite library.

Release operators should re-check this inventory as part of the steps in
[releasing.md](releasing.md). This section updates on a calendar/release
cadence, not when extraction semantics change — do not merge it with the
[Security corrections](#security-corrections) ledger above.

### Current inventory

| Component | Locked version | Security-relevant payload |
|---|---:|---|
| `rusqlite` | 0.40.2 | Enables `libsqlite3-sys/bundled` and integer conversion support; default features disabled |
| `libsqlite3-sys` | 0.38.2 | SQLite 3.53.2, source ID `d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24` |

This replaces `rusqlite` 0.31.0 / `libsqlite3-sys` 0.28.0, which bundled
SQLite 3.45.0. `cargo audit` reported no known RustSec vulnerability in either
the pre-upgrade or updated lockfile when checked against advisory database
commit `69f93e1d081d8b6fbee010e48f0b5e0d13661415` (updated 2026-08-12).
The upgrade is nevertheless preferred to accepting indefinite exposure to an
unmanaged native parser version.

The published library directly constrains both `rusqlite` 0.40.2 and
`libsqlite3-sys` 0.38.2 exactly. The rusqlite requirement is repeated in CLI
fixture tests and the standalone direct-path consumer. This prevents a
consumer's fresh resolver from silently selecting a different bundled SQLite
payload than the one audited here. Default features are disabled to preserve
the previous native-only dependency set and avoid adding the optional
WebAssembly backend to native release dependency graphs. `fallible_uint`
retains the unsigned-integer fixture conversions supported by the previous
release.

### Maintenance policy

The maintainers are the security owner. They must re-check this inventory:

- before each release;
- when RustSec, SQLite, or rusqlite publishes a security notice; and
- at least every 90 days, with the next review due 2026-11-13.

The review first changes the exact `rusqlite` and `libsqlite3-sys` requirements
in `rookie-rs/Cargo.toml` (and the fixture-only rusqlite requirements in
`cli/Cargo.toml` and `tests/direct_path_consumer/Cargo.toml`). It then runs
`cargo update -p rusqlite --precise <version>` and
`cargo update -p libsqlite3-sys --precise <version>`, verifies both
`sqlite3_libversion()` and `sqlite3_sourceid()` against the selected
amalgamation, updates the expected SQLite version and full source ID in
`scripts/check-packaged-rust-consumer.py`, runs `cargo audit` and
`python3 scripts/check-packaged-rust-consumer.py`, and executes the SQLite
snapshot and extraction test suites. It updates the table and review date in
this document in the same commit as `Cargo.lock`.

A known advisory may be deferred only with a documented exploitability
assessment, named owner, compensating controls, and an expiry no more than 90
days away. Expired exceptions block a release. Unknown or unreviewed bundled
versions are not accepted release inputs.

Last reviewed: 2026-08-15.

## Linux confidential-session cryptography review

### Current status

The Linux Secret Service confidential-session path contains fixed-width MODP
Diffie-Hellman arithmetic and a zeroizing SHA-256/HMAC/HKDF implementation in
`rookie-rs/src/linux/zeroizing_dh.rs` and `zeroizing_hkdf.rs`. The code has
known-answer and independent-reference tests, but **no independent specialist
review has been completed or claimed**.

The in-tree implementation exists because keyed state and intermediate values
must be wiped, while the otherwise suitable general-purpose contexts did not
provide the required zeroization guarantees when this code was written. That
tradeoff does not make custom cryptography self-validating.

### Required review record

Before describing these primitives as independently reviewed, add a dated
record to this section containing all of the following:

- reviewer identity, relevant expertise, and independence from the author;
- exact commit and files reviewed;
- protocol references and threat model used;
- checks performed for arithmetic correctness, peer-key validation,
  constant-time behavior, memory cleanup, and interoperability;
- every finding, its severity, and its resolution commit; and
- any residual risks or conditions that require re-review.

A substantive change to the arithmetic, key validation, SHA-256/HMAC/HKDF
logic, or confidential-session transcript invalidates the prior scope and must
be reviewed again. Formatting, tests, and comments alone do not.

### Continuous evidence

CI runs known-answer tests and independent arithmetic reference cases. Nightly
assurance adds coverage ratchets for security/error-policy code and
sanitizer-backed fuzz targets for the untrusted parser boundaries. Those
controls can find regressions; they are not a substitute for the independent
review above.

The deprecated Internet Explorer path remains a separate native-parser risk:
`libesedb` executes in the caller's process on Windows. The portable ESE record
fuzzer intentionally does not claim to sandbox or fuzz that C parser. Removal
or a real subprocess boundary requires a compatibility decision for a future
release.
