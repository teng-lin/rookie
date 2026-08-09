# rookie-cookies — Verified Consolidated Codebase Audit

**Verification date:** 2026-08-09<br>
**Audited commit:** `7f888c6cbd623c6472caf290a6d8e0e32abc97e9` (`main`, clean tracked tree)<br>
**Status:** findings and recommendations only; no product-code fixes were made.

## Scope and evidence labels

This report reconciles the three source audits with the current tree and with the archived upstream issue tracker:

| Label | Source | What it establishes |
| --- | --- | --- |
| **AGY** | `docs/audit_findings_agy.md` | Antigravity source review across core, bindings, CLI, tests, and CI |
| **CLAUDE** | `docs/audit_findings_claude.md` | Five-lens review with local reproductions and static replicas for platform-specific code |
| **CODEX** | `docs/audit_findings_codex.md` | Correctness/reliability/product review with local reproductions; security was out of scope |
| **CURRENT** | This verification pass | Direct inspection or execution against commit `7f888c6` |
| **UPSTREAM** | [`thewh1teagle/rookie` issues](https://github.com/thewh1teagle/rookie/issues) | Historical user reports; these corroborate a finding only when the issue body supports the same symptom or cause |

The previous draft described `bc206ec` plus uncommitted release changes and mislabeled the Claude audit as a separate “T” source. That metadata is obsolete. Corroboration below means that the named audit contains the finding; it does not substitute for the **CURRENT** disposition.

Platform-specific Windows and Safari findings were source-verified in this Linux environment unless a reproduction is explicitly listed. The earlier blanket statement that all cryptography and FFI were independently verified is too broad for this pass; no counterexample was found, but those positive claims were not re-proven against current browser source.

## Verification baseline

| Check | Result | Evidence |
| --- | --- | --- |
| `cargo test --workspace --all-targets` | **Pass** | 29 core tests and 2 CLI integration tests passed; 2 real-browser tests were ignored by default |
| `cargo clippy --workspace --all-targets -- -D warnings` | **Fail** | `cli/src/browsers_map.rs:5`: unused `BrowserFn` |
| `cargo package -p rookie-cookies --allow-dirty` | **Pass with warnings** | 33 files packaged and the packaged crate compiled; both external-path examples were omitted |
| Build script with no `git` executable on `PATH` | **Fail, reproduced** | `rookie-rs/build.rs:5` panicked with OS error 2 |
| Held-WAL SQLite comparison | **Defect reproduced** | normal read returned 1 row; `mode=ro&immutable=1` returned 0 |
| CLI redirection | **Defect reproduced** | `--load` emitted tracing and cookie output to stdout; stderr had 0 lines |
| `RUST_LOG=debug` | **Works** | debug run emitted 83 DEBUG lines; the prior “RUST_LOG does nothing” claim is false |
| `python3 scripts/check-release.py 0.5.7` | **Pass** | release metadata is consistent at current `HEAD` |

## Executive summary

The dominant current failure mode is still silent omission or wrong output: modern Chromium discovery misses `Network/Cookies` on Linux/macOS, immutable SQLite reads omit active WAL rows, plaintext Chromium cookies are dropped, one malformed row aborts a browser extraction, only one profile is selected, and broad domain filters can return unrelated sites.

There are also reproducible or source-proven crash boundaries in timestamp arithmetic and byte slicing, a wrong Safari timestamp representation, SQL injection in both SQLite domain filters, and serious Windows lifecycle problems around impersonation, privileges, temporary copies, and forced application shutdown.

Several release claims in the previous draft are now stale. The retired PyPI artifact actions, old repository URLs, version-consistency gap, and misplaced Cargo `include` entry were fixed before `7f888c6`. The Python package README omission remains in open fork PR [#27](https://github.com/teng-lin/rookie-cookies/pull/27).

Severity used here: **Critical** = cross-site secret disclosure or equivalent security boundary failure; **High** = crash, destructive side effect, or materially wrong/missing data on a realistic path; **Medium** = narrower wrong behavior, diagnosability, compatibility, or release-quality defect; **Low** = hardening or polish.

---

## Open release-blocking findings

Original finding IDs are retained for traceability. Missing IDs are in the resolved section; the old T3-3 contained only cross-references to T1-2 and T3-4 and is not a separate finding.

### T1-1. Unchecked slicing and timestamp arithmetic can panic — **High** · AGY + CLAUDE + CODEX + CURRENT

The following sites remain in the current tree:

| Site | Current defect |
| --- | --- |
| `rookie-rs/src/common/date.rs:5` | `u64` subtraction underflows below the Chromium epoch; debug panics and release wraps to a bogus large timestamp |
| `rookie-rs/src/common/date.rs:36` | same underflow shape for IE FILETIME |
| `rookie-rs/src/browser/chromium.rs:208,216-218` | Windows reads a 3-byte prefix and 12-byte nonce without sufficient length checks |
| `rookie-rs/src/browser/chromium.rs:256,287` | Unix reads a 3-byte prefix after checking only empty and slices a short decoded plaintext at byte 32 |
| `rookie-rs/src/browser/mozilla.rs:125` | `compressed[8..]` panics on a truncated `recovery.jsonlz4`; magic is not checked |
| `rookie-rs/src/browser/safari.rs:150-153,157-162,169-174` | unchecked addition/multiplication and `to - off` inside the negative-length error path can overflow |
| `rookie-rs/src/windows/appbound/mod.rs:38` | `len() - 61` underflows for a short app-bound payload |

Use `checked_*` arithmetic and `slice.get(...)`, validate the `mozLz40\0` header, and return a row/file error instead of panicking. PyO3 exposes Rust panics as `PanicException`; Node behavior should not be relied on to contain an unwind.

Upstream [#25](https://github.com/thewh1teagle/rookie/issues/25) reported the formerly unguarded **empty** encrypted blob. The current empty check fixes that exact trigger, but 1–2 byte blobs still panic. Upstream [#15](https://github.com/thewh1teagle/rookie/issues/15) is a caller calling `.unwrap()` on a returned decryption error, not evidence of an internal parser panic.

### T1-2. Safari expiry is read as `u64`, but the file stores a little-endian `f64` — **High** · CLAUDE + CODEX + CURRENT

`rookie-rs/src/browser/safari.rs:92` calls `read_u64` on the eight bytes at offset `0x28`; `rookie-rs/src/common/date.rs:22-29` then adds the Apple epoch before dividing the bit pattern by one billion. A maintained independent parser reads the same field with [`struct.unpack('<d')`](https://github.com/borisbabic/browser_cookie3/blob/03895797e48dd107806db171d8392c562151807d/browser_cookie3/__init__.py#L1186-L1190) and adds 978,307,200 seconds.

The bug makes Safari expiries wrong, but it does not corrupt the source database; **High** is more accurate than the previous **Critical**. Upstream [#7](https://github.com/thewh1teagle/rookie/issues/7) concerns an old Firefox seconds-versus-milliseconds bug and is not corroboration for this finding.

### T1-3. Linux/macOS Chromium discovery omits modern `Network/Cookies` paths — **High** · CODEX + CURRENT

Windows entries in `rookie-rs/config.json` include both legacy and `Network/Cookies` locations. Every Linux/macOS Chromium-family entry still lists only `Default/Cookies`, `Profile */Cookies`, or browser-specific legacy paths. Explicit-path e2e helpers try `Network/Cookies`, but automatic APIs call `find_chrome_based_paths`; current e2e jobs pass an explicit database path and therefore do not test discovery.

Add `Default/Network/Cookies` and `Profile */Network/Cookies` before legacy candidates for each applicable browser and add controlled-`HOME` discovery tests. Upstream [#5](https://github.com/thewh1teagle/rookie/issues/5) is a nonspecific Firefox missing-cookie report, and [#48](https://github.com/thewh1teagle/rookie/issues/48) describes the old aggregate-loader behavior; neither proves this root cause.

### T1-4. One bad database row aborts the entire browser extraction — **High** · CLAUDE + CODEX + CURRENT

- Chromium row conversions and `decrypt_encrypted_value(...)?` occur directly inside the loop at `rookie-rs/src/browser/chromium.rs:363-391`.
- Firefox row conversions do the same at `rookie-rs/src/browser/mozilla.rs:37-67`; only a NULL host is explicitly skipped.
- A negative expiry, unexpected SQLite type, invalid UTF-8, or undecryptable value therefore discards cookies already accumulated from valid rows.

Handle conversion/decryption per row, log a redacted diagnostic, and continue; optionally expose a strict mode. Upstream [#84](https://github.com/thewh1teagle/rookie/issues/84) and [#95](https://github.com/thewh1teagle/rookie/issues/95) corroborate whole-call decryption failures. [#55](https://github.com/thewh1teagle/rookie/issues/55) and [#85](https://github.com/thewh1teagle/rookie/issues/85) reported a Text-typed `encrypted_value`; current `CAST(encrypted_value AS BLOB)` addresses that specific historical failure and does not support the previous draft’s Mozilla claim.

### T1-5. Plaintext Chromium rows with an empty encrypted blob are discarded — **High** · CLAUDE + CODEX + CURRENT

`rookie-rs/src/browser/chromium.rs:371-376` reads both `value` and `encrypted_value`, then `continue`s whenever the encrypted blob is empty. This makes the plaintext passthrough inside `decrypt_encrypted_value` unreachable for a valid plaintext-only row. The current test `query_cookies_skips_rows_with_empty_encrypted_value` at lines 490-512 explicitly locks in the loss.

Pass the row to the decrypt/passthrough function and replace that test with one asserting the plaintext value survives.

### T1-6. Rust/CLI Netscape output computes the HttpOnly subdomain flag from the prefixed domain — **Medium** · AGY + CLAUDE + CODEX + CURRENT

`rookie-rs/src/common/format.rs:15-20` adds `#HttpOnly_` before checking `starts_with('.')`, so every HttpOnly cookie gets `FALSE` in column 2. The Python formatter correctly checks the raw domain at `bindings/python/rookie_cookies/__init__.py:147-153`.

Compute the flag before prefixing and share one formatter or golden file across Rust and Python. Upstream [#34](https://github.com/thewh1teagle/rookie/issues/34) requested Netscape export support; it did not report this flag bug.

### T1-7. `build.rs` panics when the `git` executable is absent — **High** · AGY + CLAUDE + CODEX + CURRENT

`rookie-rs/build.rs:2-6` unwraps both `Command::output` and UTF-8 conversion. An isolated run with an empty `PATH` reproduced OS error 2 and exit 101. Merely building outside a Git checkout does **not** panic when `git` exists; it produces an empty commit hash because exit status and stderr are ignored.

Treat commit metadata as optional, check command status, trim output, use `"unknown"` as fallback, and emit appropriate `cargo:rerun-if-*` directives.

---

## Security and destructive-side-effect findings

### T2-1. SYSTEM impersonation is not reverted on error — **High** · AGY + CLAUDE + CURRENT

`rookie-rs/src/windows/appbound/mod.rs:15-24` starts impersonation, then uses `?` on DPAPI decrypt before `stop_impersonate`. A decrypt error therefore leaves the current thread impersonating until an explicit revert or thread exit. `stop_impersonate` also closes the token before calling `RevertToSelf`, creating another error path that can skip the revert.

Use an RAII guard that reverts first and closes handles in `Drop`. Upstream [#72](https://github.com/thewh1teagle/rookie/issues/72) reports failure to locate `lsass.exe`; it does not corroborate the impersonation leak.

### T2-2. Domain filters are SQL-injectable — **Critical when filter input is untrusted** · AGY + CLAUDE + CURRENT

`rookie-rs/src/browser/chromium.rs:346-355` and `rookie-rs/src/browser/mozilla.rs:19-28` interpolate caller-controlled strings into `LIKE '%...%'`. Quotes can alter the predicate; `%` and `_` also change matching semantics. In an application that accepts a site/domain from an untrusted caller, this can bypass cookie scoping and expose other sites’ session values.

Generate placeholders and bind values. Parameterization must be paired with the exact host-boundary semantics in T3-4; merely binding `%domain%` preserves the cross-site overmatch.

### T2-3. `SeDebugPrivilege` is enabled process-wide and not restored — **Medium** · CLAUDE + CURRENT

`rookie-rs/src/windows/appbound/impersonate.rs:24-32` calls `RtlAdjustPrivilege` with `current_thread = FALSE`, captures `previous_value`, and discards it. Restore the previous state after the system token is acquired, including all error paths.

### T2-4. Shadow-copied cookie databases are never deleted — **Medium** · CLAUDE + CURRENT

`rookie-rs/src/windows/shadow_copy.rs:8-20` creates a random temp directory, and `rookie-rs/src/browser/chromium.rs:306-313` redirects the read to the raw copy. Production code contains no matching deletion. This leaves a durable extra cookie database accessible to the same account and administrators. The previous assertions about shared-temp ACLs were not reproduced and have been removed.

Return a temp-file guard whose destructor removes the copied file and directory on success and error.

### T2-5. Unix CBC decryption stops at the first key with valid padding — **Medium** · CLAUDE + CURRENT

At `rookie-rs/src/browser/chromium.rs:272-295`, a wrong AES-CBC key can satisfy PKCS#7 padding by chance. The function then returns decoded data, an empty string, or panics on `[32..]` instead of trying later keys. Keep iterating on decode/format failure and apply any 32-byte host-hash handling only after validating length and expected plaintext shape.

### T2-6. A read API requests forced shutdown of locking applications — **High** · AGY + CLAUDE + CURRENT

`rookie-rs/src/windows/restart_manager.rs:38-46` calls `RmShutdown(..., RmForceShutdown)` and never calls `RmRestart`. Chromium uses it whenever shadow copy does not succeed (`rookie-rs/src/browser/chromium.rs:316-322`); IE uses it unconditionally (`rookie-rs/src/browser/internet_explorer.rs:11-15`), including the speculative IE probe in `any_browser` (`rookie-rs/src/lib.rs:516-522`). The log message does not disclose that applications may be closed, and there is no opt-out.

Upstream [#47](https://github.com/thewh1teagle/rookie/issues/47) reports recent Chrome cookie changes disappearing after a read, and [#8](https://github.com/thewh1teagle/rookie/issues/8) reports a session expiring after retrieval. Both are consistent with this destructive path, but neither issue proves the precise root cause. Make shutdown explicit opt-in and never invoke it during parser probing.

---

## Wrong-result and observability findings

### T3-1. `immutable=1` hides committed WAL rows — **High** · CLAUDE + CODEX + CURRENT

`rookie-rs/src/common/sqlite.rs:6-13` opens every browser database with `mode=ro&immutable=1`. The held-WAL reproduction returned one row through a normal read-only connection and zero through the current immutable URI.

Snapshot the database together with `-wal`/`-shm` and read the snapshot, or use a normal read-only connection with busy handling. Do not attribute upstream [#5](https://github.com/thewh1teagle/rookie/issues/5), [#8](https://github.com/thewh1teagle/rookie/issues/8), or [#10](https://github.com/thewh1teagle/rookie/issues/10) to WAL without evidence; #10 specifically describes cookies that are never persisted.

### T3-2. IE filtering and flags are wrong — **Medium** · AGY + CLAUDE + CODEX + CURRENT

`rookie-rs/src/browser/internet_explorer.rs:47` iterates `Option<Vec<String>>`, so `d` is the entire vector and `.contains(host)` performs exact vector membership. It is not the intended host/domain match. The parser also hardcodes `secure = false`, `http_only = false`, and `same_site = 0` at lines 36-44.

Use the shared matcher from T3-4. Map ESE flags only after verifying their schema and semantics; otherwise represent them as unknown rather than inventing false values.

### T3-4. Domain matching is inconsistent and crosses site boundaries — **High** · CODEX + CURRENT

- Chromium and Firefox SQL use unescaped `LIKE '%domain%'`.
- Firefox session parsing uses `host.contains(domain)` in `rookie-rs/src/common/utils.rs:1-9`.
- Safari uses unbounded `ends_with` at `rookie-rs/src/browser/safari.rs:30-40`.
- IE reverses the relationship as described in T3-2.

Filtering `example.com` can therefore include `notexample.com` or `example.com.invalid`, depending on backend. Normalize ASCII case and a leading dot, then require an exact host or dot-boundary suffix. Share one acceptance matrix across all backends.

### T3-5. `load()` cannot distinguish total failure from an empty result — **Medium design gap** · CLAUDE + CODEX + CURRENT

`rookie-rs/src/lib.rs:383-443` explicitly documents `load()` as best-effort and always returns `Ok(cookies)` after warning on individual failures. The behavior is intentional, so the previous draft overstated it as an implementation bug. It is still an observability gap: callers cannot distinguish no installed browser, no matching cookies, and every backend failing; Node installs no logger by default.

Preserve compatibility with a diagnostic/strict API that returns per-browser status and an aggregate error when no backend succeeded.

### T3-6. Firefox selects one profile and may select the wrong install — **Medium** · CLAUDE + CODEX + CURRENT

`rookie-rs/src/browser/mozilla.rs:199-226` returns the first `[Install...]` block and does not fall through if it lacks `Default`; `rookie-rs/src/common/paths.rs:51-69` returns the first existing default-profile database. Additional profiles are never enumerated, and results contain no source profile.

Upstream [#18](https://github.com/thewh1teagle/rookie/issues/18) motivated `[Install...]` parsing and is partly resolved. Upstream [#89](https://github.com/thewh1teagle/rookie/issues/89) directly requests selecting or dumping other profiles and remains relevant.

### T3-7. Unknown Chromium encryption prefixes become empty values — **Medium** · CLAUDE + CURRENT

The Unix decryptor at `rookie-rs/src/browser/chromium.rs:248-260` returns the existing `value` for an unknown prefix. On the encrypted path that value is normally empty, making an unsupported/corrupt scheme indistinguishable from a real empty cookie. Return a typed unsupported-scheme error and let row-level resilience decide whether to skip it.

### T3-8. Linux keyring failures are discarded — **Medium** · CLAUDE + CURRENT

`rookie-rs/src/linux/mod.rs:8-24` ignores both libsecret schemas and KWallet errors; `rookie-rs/src/browser/chromium.rs:131-146` ignores the aggregate keyring result and adds fallback keys. At least debug-log redacted failure categories and expose diagnostics through bindings. Upstream [#4](https://github.com/thewh1teagle/rookie/issues/4) is only a generic Arch Linux decrypt failure and does not establish a keyring cause.

---

## Bindings, packaging, CI, and API surface

### T4-1. Python holds the GIL and Node blocks the event loop — **High/Medium** · AGY + CLAUDE + CODEX + CURRENT

No Python wrapper in `bindings/python/src/browsers.rs` releases the GIL around SQLite, D-Bus, Keychain, DPAPI, shadow-copy, or Restart Manager work. Every Node export in `bindings/node/src/lib.rs` is synchronous. Release the GIL around the Rust call and expose N-API async tasks/Promises for I/O-heavy operations.

### T4-2. Manual macOS `chromium_based` is broken in both bindings — **Medium** · AGY + CURRENT

The Unix wrappers in `bindings/python/src/browsers.rs:230-249` and `bindings/node/src/lib.rs:195-210` construct a `Browser` with both macOS keychain fields set to `None`. On macOS the core therefore cannot retrieve the real Safe Storage password and only tries fallback passwords. Accept browser/keychain metadata or route the manual path through a config-backed API.

### T4-3. Node types advertise both OS-specific `chromiumBased` signatures — **Medium** · CLAUDE + CURRENT

`bindings/node/index.d.ts:38-40` exposes Unix and Windows overloads on every platform, although only one native signature exists. A Windows-shaped call can type-check on Unix and fail argument conversion at runtime. Provide platform-specific type entry points or one stable cross-platform options object.

### T4-4. Workspace Clippy fails and the lint workflow misses relevant PRs — **Medium** · AGY + CLAUDE + CODEX + CURRENT

The full workspace command fails on the unused `BrowserFn`. `.github/workflows/lint.yml:7-10` watches a nonexistent `.github/workflows/lint-cli.yml` and only `rookie-rs/src/**`; its Clippy command omits `--workspace`, so workspace `default-members` exclude the CLI and Node binding. Expand triggers to all Rust sources/manifests/workflows and run the verified workspace command.

### T4-6. CLI tracing corrupts stdout exports; `RUST_LOG` itself works — **High** · CLAUDE + CURRENT + UPSTREAM #93

`cli/src/main.rs:33` calls `tracing_subscriber::fmt::init()`, whose default writer is stdout. A live `--load` run emitted all tracing and output to stdout, with zero stderr lines. Upstream [#93](https://github.com/thewh1teagle/rookie/issues/93) contains the same contamination in a redirected Netscape file.

The previous claim that `RUST_LOG` is inert without an explicit `env-filter` feature is false: `RUST_LOG=debug` enabled debug records in the current binary. The required fix is to route tracing to stderr; richer filtering is a separate optional enhancement.

### T4-7. Node’s package-local release profile is ignored — **Medium** · CODEX + CURRENT

Cargo warns on every workspace command that `[profile.release]` in `bindings/node/Cargo.toml:26-28` is ignored because profiles must be declared at the workspace root. Move the intended LTO/strip policy to the root or use another artifact-specific mechanism.

### T4-8. Browser support differs across Rust, Python, Node, CLI, config, and docs — **Medium** · AGY + CLAUDE + CODEX + CURRENT

- `cachy` exists in Rust and CLI but not either binding; `examples/python/multi_import.py` imports it and fails on Linux.
- `octo_browser` exists in Rust/Python/Node on Windows but is absent from CLI, `load()`, and the README support table.
- `opera_gx` is exported on Linux despite an empty config entry; `load()` and README correctly omit it.
- CLI uses a nondeterministic `HashMap` for help choices and spells the key `"opera gx"` instead of `opera_gx`.

Upstream [#38](https://github.com/thewh1teagle/rookie/issues/38) concerns Opera’s Linux Snap/Flatpak paths, which are present now; it is not evidence for Opera GX drift. Upstream [#3](https://github.com/thewh1teagle/rookie/issues/3) concerned a missing Python cookie-domain field, which is also fixed now.

### T4-9. Bindings collapse errors into untyped failures — **Medium** · CLAUDE + CURRENT

Node repeatedly maps all failures to `Status::Unknown`; Python surfaces core failures as generic runtime errors. Define stable error kinds for not installed, locked/unavailable, malformed data, unsupported encryption, and decryption failure, while preserving redaction.

### T4-11. The Node postprocessor can silently drop new exports — **Medium** · CLAUDE + CURRENT

`bindings/node/scripts/patch-loader.js:74-91` truncates generated types immediately after `load`, then appends a hardcoded block. Lines 38-40 also replace the runtime destructure with a hardcoded function list. Add a structural assertion or generate the platform facade from a single manifest instead of rewriting generated output by string matching.

---

## Resolved or materially changed since the source audits

| Original ID | Current disposition |
| --- | --- |
| **T1-8 — misplaced `[package] include`** | **Resolved at `HEAD`.** The inert key was removed. `cargo package` now includes `rookie-rs/build.rs`, `rookie-rs/config.json`, README, and license and successfully verifies the packaged crate. Residual: Cargo warns that `simple` and `from_path` are omitted because their sources live outside `rookie-rs/`. |
| **T4-5 — PyPI workflow uses retired artifact actions** | **Resolved at `HEAD`.** Publish workflows use pinned v4 artifact actions and `scripts/check-release.py` preflights version/tag consistency. Residual: PyPI/crate publication is not gated on the test workflow. |
| **T4-10 — old fork URLs and missing dynamic version** | **Resolved at `HEAD`.** No tracked product/doc reference still points to `teng-lin/rookie`, and `bindings/python/pyproject.toml` declares `dynamic = ["version"]`. The Python `readme` field is still absent; fork PR [#27](https://github.com/teng-lin/rookie-cookies/pull/27) is open, not merged. |
| **AGY — Node package-version mismatch** | **Resolved at `HEAD`.** The root package, four published optional dependencies, platform subpackages, and Cargo manifests are aligned at `0.5.7`; the release metadata check passes. |
| **Upstream #48 — `load()` returns after the first browser** | **Resolved.** Current `load()` iterates all configured browsers and concatenates successes. Its remaining observability gap is T3-5. |
| **Upstream #55/#85 — Text `encrypted_value` conversion** | **Resolved for that shape.** Chromium selects `CAST(encrypted_value AS BLOB)`. Other per-row failures still trigger T1-4. |
| **Upstream #72 — `lsass.exe` not found** | **Partly addressed.** Current process lookup also accepts `winlogon.exe`; this does not fix T2-1/T2-3 lifecycle issues. |
| **Upstream #3/#7/#38/#52/#105** | **Resolved in the current fork** for domain field mapping, Firefox expiry units, Opera Linux paths, Zen support, and PEP 621 dynamic version metadata respectively. |

## Archived-upstream issue verification

The earlier draft attached several issue links to unrelated root causes. This table records what the issue bodies actually support:

| Issues | Verified relationship to current report |
| --- | --- |
| [#18](https://github.com/thewh1teagle/rookie/issues/18), [#89](https://github.com/thewh1teagle/rookie/issues/89) | Directly relevant to Firefox default/profile selection; #18’s original empty-Profile0 bug is partly fixed, while multi-profile selection remains. |
| [#25](https://github.com/thewh1teagle/rookie/issues/25) | Historical empty-blob slice panic. The exact empty case is guarded; adjacent 1–2 byte cases remain. |
| [#47](https://github.com/thewh1teagle/rookie/issues/47), [#8](https://github.com/thewh1teagle/rookie/issues/8) | Report cookie/session loss after a Windows read. Consistent with the forced-shutdown/live-database design, but not proof of WAL or temp-file root causes. |
| [#82](https://github.com/thewh1teagle/rookie/issues/82) | Current Python logging-scope request remains applicable: the binding initializes the default `pyo3_log` integration globally. |
| [#93](https://github.com/thewh1teagle/rookie/issues/93) | Direct reproduction of CLI stdout contamination; confirmed locally. |
| [#99](https://github.com/thewh1teagle/rookie/issues/99) | External ESET heuristic report for the archived package’s Windows binary. Not locally reproducible here; code signing would improve provenance but is not proven to eliminate the alert. |
| [#4](https://github.com/thewh1teagle/rookie/issues/4), [#84](https://github.com/thewh1teagle/rookie/issues/84), [#95](https://github.com/thewh1teagle/rookie/issues/95) | Generic decryption failures. #84/#95 support whole-call failure; none proves the keyring or CBC root cause assigned in the earlier draft. |
| [#5](https://github.com/thewh1teagle/rookie/issues/5) | Nonspecific Firefox missing-cookie count. It does not establish Chromium discovery or immutable-WAL behavior. |
| [#10](https://github.com/thewh1teagle/rookie/issues/10) | Describes memory-only Chromium session cookies that are never persisted; this is a product limitation, not evidence for T3-1. |
| [#15](https://github.com/thewh1teagle/rookie/issues/15) | Caller `.unwrap()` on a returned macOS decrypt error, not an internal library panic. |
| [#22](https://github.com/thewh1teagle/rookie/issues/22) | Feature request for reading locked/live Windows databases; it motivated shadow copy but does not report the temp-copy leak. |
| [#34](https://github.com/thewh1teagle/rookie/issues/34) | Feature request for Netscape export, not evidence for the HttpOnly/subdomain defect. |
| [#48](https://github.com/thewh1teagle/rookie/issues/48) | Historical first-browser aggregate behavior, now fixed. |
| [#54](https://github.com/thewh1teagle/rookie/issues/54) | Windows C compilation failure in `libesedb-sys`; the dependency is still unconditional on Windows. |
| [#92](https://github.com/thewh1teagle/rookie/issues/92) | MSYS environment selects an incompatible `link.exe` while using the MSVC target; it is not specifically a `libesedb` failure. Windows/MSVC prerequisites remain undocumented. |
| [#3](https://github.com/thewh1teagle/rookie/issues/3), [#7](https://github.com/thewh1teagle/rookie/issues/7), [#38](https://github.com/thewh1teagle/rookie/issues/38), [#52](https://github.com/thewh1teagle/rookie/issues/52), [#55](https://github.com/thewh1teagle/rookie/issues/55), [#72](https://github.com/thewh1teagle/rookie/issues/72), [#85](https://github.com/thewh1teagle/rookie/issues/85), [#105](https://github.com/thewh1teagle/rookie/issues/105) | Historical reports whose exact reported condition is resolved or materially mitigated in this fork; see the resolved table above. |

## Corrections and downgraded source-audit claims

- **`RUST_LOG` is functional.** The missing explicit `env-filter` feature does not make `tracing_subscriber::fmt::init()` ignore `RUST_LOG`; the current run proved debug activation. Only stdout routing remains defective.
- **`EnumProcesses` does not exceed the vector capacity in the current code.** The Win32 buffer is 4096 bytes and the vector capacity is 1024 `u32`s. The code is fragile and silently truncates a full buffer, but the claimed memory-corruption/UB path was not established.
- **Missing `Local State` is a narrower discovery defect.** Normal Chrome profiles do contain it. If absent, `rookie-rs/src/common/paths.rs:30-36` aborts after finding a readable Cookies DB even though Unix callers discard the key path; that is Low/Medium, not a general discovery failure.
- **The macOS manual `chromium_based` limitation affects both bindings**, not only Python (T4-2).
- **Python’s OS-specific `chromium_based` signatures are modeled correctly in the `.pyi` stub.** They remain a portability/API-design inconvenience, not the cross-platform type-advertising defect present in Node.
- **The JavaScript default imports in `examples/javascript/simple.js` and `examples/javascript/fetch.js` are valid CommonJS-to-ESM interop.** The AGY “named exports only” claim is rejected.
- **The Node `u64 as i64` expiry cast is unchecked but no valid current ingestion path producing `> i64::MAX` was demonstrated.** Keep it as Low hardening rather than a release blocker.
- **CLI option precedence is deterministic but undocumented.** Conflicting `--load`, `--browser`, and `--path` options should use Clap conflicts, but the current order is not data corruption.
- **The Python Netscape formatter’s repeated string concatenation and uncleaned test temp directories are real Low-severity maintenance items.**

## Testing and CI gaps still present

- Automatic discovery is not exercised; current real-browser jobs pass explicit database paths, so T1-3 and profile selection can remain green.
- The advertised E2E matrix is not a full Cartesian product: Windows Firefox is absent; macOS Firefox covers Rust/Python/Node/CLI, while macOS Chrome and Windows Chrome run only the Rust assertion. App-Bound v20 is not exercised.
- The macOS Chrome job intentionally uses Playwright’s mock keychain fallback, so it does not test Keychain retrieval. The Linux libsecret job starts a real secret service, but does not assert which key source succeeded and could become a fallback false-green.
- Boundary tests stop immediately before current panic cases: below-epoch timestamps, 1–2 byte encrypted blobs, sub-8-byte `jsonlz4`, inverted Safari offsets, and short app-bound keys are absent.
- Safari, IE, Windows privilege/shadow-copy/Restart Manager, and successful Mozilla session-store parsing lack focused unit coverage.
- No config-to-export contract test ensures every platform-exposed browser has a valid config entry and consistent Rust/Python/Node/CLI/docs support.
- Ignored-test workflow commands can succeed with zero matched tests; jobs should assert the expected test name/count.
- Python unit tests run on Ubuntu only even though wheels build on three operating systems; `--no-default-features` is not built.
- Package verification now passes but explicitly drops both Rust examples. Publish workflows validate release metadata, but PyPI/crate publishing is not gated on the full test suite.

## Recommended implementation order

1. **Stop omission and cross-site leakage:** fix `Network/Cookies` discovery, snapshot live SQLite with WAL, parameterize SQL, and implement one exact domain matcher.
2. **Make rows resilient:** preserve plaintext values, convert/decrypt per row, and expose structured diagnostics/strict mode.
3. **Remove crash and wrong-result boundaries:** checked slicing/arithmetic, correct Safari `f64` time decoding, CBC key-loop validation, and the Netscape flag fix.
4. **Fix Windows lifecycle safety:** RAII impersonation, privilege restoration, temp-copy cleanup, and explicit opt-in for application shutdown.
5. **Repair blocking APIs and surface drift:** release the Python GIL, add async Node APIs, fix both macOS manual wrappers and Node types, then align the browser matrix.
6. **Close release-quality gaps:** make `build.rs` git-optional, fix workspace Clippy/lint routing, move the release profile, package or remove examples, merge the Python README metadata fix, and gate publication on tests.

The highest-value regression fixtures are: a held-WAL snapshot, controlled-`HOME` modern discovery, mixed valid/invalid/plaintext rows, a shared domain-boundary matrix, a known-answer Safari binary cookie, truncated-input boundaries, and a byte-exact Netscape golden file shared by Rust and Python.
