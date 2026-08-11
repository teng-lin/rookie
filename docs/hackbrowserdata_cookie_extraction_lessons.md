# Cookie extraction lessons from HackBrowserData

Related documents:

- [Converged implementation plan](hackbrowserdata_cookie_extraction_implementation_plan.md)
- [ADR 0001: compatibility and report contracts](adr/0001-cookie-extraction-compatibility-and-report-contracts.md)

## Executive summary

HackBrowserData's most valuable ideas are architectural rather than its larger feature scope. It separates browser discovery, profile discovery, source-file acquisition, key retrieval, decryption, extraction, and output formatting. That separation makes multi-profile extraction, locked-file handling, and support for mixed Chromium encryption versions substantially easier to reason about and test.

The highest-value lessons for `rookie` are:

1. Preserve and extend the WAL-aware `SqliteReader` that has already replaced stale immutable reads for active WAL databases.
2. Generalize the existing Firefox profile support into an installation/profile model for Chromium, Safari, and the new report APIs.
3. Retrieve and retain independent Chromium keys for v10, v11, and v20 ciphertexts.
4. Return browser/profile provenance and structured partial failures from additive APIs while keeping every legacy selector and output shape intact.
5. Verify Chromium's domain-hash prefix instead of stripping 32 bytes heuristically.
6. Configure browser installation roots and engine metadata rather than enumerating every possible cookie-file path.

HackBrowserData should not be copied wholesale. Its Chromium cookie extractor ignores plaintext `value` rows and suppresses decryption errors, and its sequential copying of the database, WAL, and SHM files is not an atomic snapshot. `rookie` also has useful behavior that HackBrowserData lacks, notably Firefox session-cookie recovery and domain-filtered extraction.

This document is rebased to the current repository. WAL-aware DB+WAL acquisition, Rust Firefox profile enumeration/selection, and IE security-flag parsing have already landed. They are baseline behavior, not future work.

## Scope and methodology

This review compares the cookie-specific portions of:

- `rookie-rs/src/browser`, `rookie-rs/src/common`, `rookie-rs/config.json`, and the public Rust API.
- HackBrowserData's `browser`, `filemanager`, `masterkey`, `crypto`, `types`, and cookie-output packages.

HackBrowserData extracts many categories besides cookies. Those categories are outside `rookie`'s purpose, so this report focuses on reusable architecture and cookie correctness rather than recommending that `rookie` become a general browser-data extraction tool.

The comparison now treats these merged changes as fixed inputs:

- `d918a90`: WAL-aware `SqliteReader` snapshots, DB+WAL coherence checks, retry, cleanup, and held-WAL/exclusive-lock tests.
- `99ca297`: Rust `firefox_profiles()` and `firefox_profile()` APIs with corrected `profiles.ini` resolution.
- `d0ea87a`: IE `secure` and `http_only` values derived from the ESE flags column, with unspecified SameSite represented as `-1`.

## Findings

### 1. Installation and profile modeling

HackBrowserData models three distinct levels:

```text
browser installation
  -> one or more profiles
       -> resolved source files
```

For Chromium, an installation owns the user-data directory and a set of master keys shared by its profiles. Each profile resolves its own cookie database. Firefox profiles are also enumerated individually, with per-profile cryptographic state where needed.

This produces several useful properties:

- Every discovered profile can be extracted instead of silently selecting one.
- A Chromium key is retrieved once and reused for every profile in the installation.
- Results retain profile name and directory.
- Flat-layout browsers such as older Opera can be handled without pretending that the installation root is a conventional `Default` profile.
- Copied or restored profiles that lack a `Preferences` marker can fall back to source-based detection.

`rookie`'s Chromium path search still returns as soon as it sees the first existing cookie file. Although Chromium configuration contains `Profile *` globs, a present `Default` database normally wins before those globs are reached. Firefox is further ahead: the Rust core now resolves `profiles.ini`, lists every database-bearing Firefox profile, and lets callers select one. That support is Firefox-specific, is not yet exposed consistently through Python, Node, and the CLI, and does not attach browser/profile identity to the returned `Cookie` values.

#### Recommendation

Introduce internal types along these lines:

```rust
struct BrowserInstallation {
  id: BrowserId,
  kind: BrowserKind,
  user_data_dir: PathBuf,
  profiles: Vec<BrowserProfile>,
}

struct BrowserProfile {
  name: String,
  path: PathBuf,
  sources: ProfileSources,
}

struct ProfileCookies {
  browser: BrowserId,
  profile: ProfileIdentity,
  cookies: Vec<Cookie>,
  warnings: Vec<ExtractionWarning>,
}
```

Keep the existing `chrome()`, `firefox()`, and `load()` selectors unchanged. They must continue using their current first/default path priorities instead of flattening new discovery results. Add new profile/report APIs for callers that need all profiles, provenance, and partial-failure details.

New results should be grouped by profile. Duplicate `(domain, path, name)` cookies from different profiles remain separate; legacy functions keep their current output and ordering behavior.

### 2. Browser source configuration

HackBrowserData browser configuration usually declares one installation root plus an engine/fork kind. Generic engine code then discovers profiles and resolves ordered candidate locations. For Chromium cookies, `Network/Cookies` is preferred and root-level `Cookies` is the legacy fallback.

This is easier to maintain than `rookie-rs/config.json`, where every browser repeats combinations of:

- local versus roaming roots;
- stable, beta, dev, and nightly channels;
- `Default` versus `Profile *`;
- `Network/Cookies` versus `Cookies`;
- native versus sandboxed packaging paths.

The current `rookie` representation also couples browser recognition to cookie-file layout. Adding a new source candidate requires editing every applicable browser entry instead of changing a shared engine definition.

#### Recommendation

Add a private, platform-grouped installation registry for the generic pipeline while keeping `rookie-rs/config.json` frozen as the public compatibility artifact used by legacy selectors. Separate the new registry into:

1. Browser installation roots and browser-specific keychain/ABE metadata.
2. Engine-level profile discovery.
3. Engine-level ordered cookie source candidates.
4. Narrow fork-specific overrides where the layout or encryption really differs.

A possible declarative shape is:

```rust
struct BrowserDefinition {
  id: BrowserId,
  kind: BrowserKind,
  installation_roots: Vec<PathTemplate>,
  channels: Vec<ChannelDefinition>,
  crypt: CryptMetadata,
}

const CHROMIUM_COOKIE_SOURCES: &[&str] = &[
  "Network/Cookies",
  "Cookies",
];
```

This change should preserve `rookie`'s broader channel coverage rather than replacing it with HackBrowserData's smaller Linux table. Existing browsers represented in both files need priority-parity tests; new generic-only browsers belong only in the private registry.

### 3. Live SQLite and WAL acquisition

This was the report's highest-priority correctness gap, and it is now substantially closed. Commit `d918a90` introduced `SqliteReader`:

- a database with a nonempty WAL is copied with its WAL into a private RAII temporary directory;
- the main database is compared byte-for-byte across the copy window, and checkpoint races receive bounded retries;
- a stale WAL from a discarded attempt is removed;
- every copied DB+WAL pair is opened with `mode=ro`, without `immutable=1`, so SQLite replays the copied WAL and rebuilds `-shm`;
- after the connection drops, RAII attempts to remove temporary files; cleanup failure must warn with the private directory and require manual deletion rather than claiming cleanup succeeded; and
- regression tests cover held WAL rows, exclusive SQLite locks, checkpoint races, WAL disappearance, immutable omission, and cleanup attempts.

HackBrowserData introduces a temporary acquisition session. It copies the primary database and any `-wal` and `-shm` companions, queries the temporary copy, and removes the session directory afterward. On Windows it attempts an ordinary copy first and has a duplicated-handle/file-mapping fallback for an exclusively locked database.

The abstraction is the important lesson:

```text
discover source
  -> acquire readable snapshot
       -> query snapshot
            -> clean up snapshot
```

It avoids mixing operating-system lock workarounds into cookie SQL and decryption code. It is also less disruptive than restarting or terminating the browser merely to release a lock.

HackBrowserData's exact implementation is not fully sufficient, however. It copies the database, WAL, and SHM sequentially, so a browser can write between those operations. `rookie` deliberately does **not** copy `-shm`: that file is a derived wal-index, and SQLite safely rebuilds it beside the copied WAL in the writable temporary directory. Copying it would risk reusing a stale frame index and would regress the current design.

#### Remaining recommendation

Preserve the current DB+WAL snapshot and no-SHM behavior. The residual work is narrower:

1. Treat discovered no-WAL browser databases as live: use a normal read-only SQLite transaction rather than `immutable=1`.
2. Let active rollback-journal locking yield a coherent SQLite snapshot or a typed busy/locked result; do not raw-copy or immutably read through it.
3. Retry the whole query only for classified snapshot-origin corruption or I/O failures.
4. On Windows, attempt ordinary acquisition before fallbacks. Browser termination remains explicit opt-in and is never used by normal all-profile extraction.
5. Keep a separate immutable open path only for an already-acquired, static **single-file** copy whose acquisition verified that no nonempty WAL existed across the copy window, or whose WAL was completely checkpointed before that verification. A static DB+WAL pair still uses `mode=ro` and SHM rebuild; merely calling a copy "static" is not sufficient proof for `immutable=1`.
6. Attempt cleanup only after owned readers/connections are dropped on return or unwind. If filesystem removal fails, preserve the extraction outcome but emit a bounded warning with the private directory and manual-removal guidance. Abort/crash cleanup is not promised.

### 4. Chromium encryption tiers

HackBrowserData represents Chromium keys explicitly:

```text
MasterKeys
  v10 -> legacy/platform key
  v11 -> Linux keyring key
  v20 -> Windows app-bound key
```

Each applicable retriever runs independently. Ciphertext dispatch is based on the row's version prefix, not on whichever key happened to be retrieved first. This matters because one profile can contain mixed ciphertext:

- A Windows profile upgraded from older Chrome can contain both v10 and v20 rows.
- A Linux profile can contain both v10 and v11 rows after key-provider or session-mode changes.

`rookie` handles Unix candidates reasonably by trying keyring, `peanuts`, and empty-password candidates, but it does not preserve the meaning of each tier. On Windows, when `app_bound_encrypted_key` exists, the app-bound feature branch chooses app-bound candidates instead of also retrieving the legacy DPAPI key. This can drop decryptable v10 rows in a mixed profile.

HackBrowserData also recognizes:

- legacy raw-DPAPI ciphertext without a version prefix;
- v12 SecretPortal ciphertext as a known but unsupported format, producing a targeted error;
- v10 cipher differences by key length for cross-host decoding.

#### Recommendation

Replace the undifferentiated `Vec<Vec<u8>>` with an internal key structure:

```rust
struct ChromiumKeys {
  v10: Vec<KeyCandidate>,
  v11: Vec<KeyCandidate>,
  v20: Vec<KeyCandidate>,
}

enum ChromiumCipherVersion {
  V10,
  V11,
  V12SecretPortal,
  V20,
  LegacyDpapi,
  Unknown([u8; 3]),
}
```

All applicable key retrievers should run once per installation, with partial success preserved. A v20 retrieval failure must not discard a successfully retrieved v10 key, and vice versa. Each row should be dispatched only to candidates appropriate for its detected version.

This architecture is more important than adopting HackBrowserData's exact Windows ABE mechanism. Its reflective-injection implementation adds significant platform complexity and should be evaluated separately against `rookie`'s security, compatibility, maintenance, and packaging requirements.

### 5. Chromium domain-hash handling

Newer Chromium cookie schemas prepend `SHA256(host_key)` to the value before encryption. HackBrowserData removes that prefix only when the decrypted first 32 bytes match the hash of the actual row's `host_key`. This distinguishes a genuine domain-bound prefix from:

- an older unprefixed value;
- arbitrary binary or malformed plaintext;
- a prefix bound to a different host;
- tampered data.

`rookie` currently strips the first 32 bytes unconditionally for v20 and uses invalid UTF-8 as a heuristic for other supported prefixes. That normally works because a SHA-256 digest is unlikely to be valid UTF-8, but it does not verify the security invariant and cannot distinguish a mismatched host hash.

#### Recommendation

Pass `host_key` into the plaintext-decoding step and implement:

```rust
fn strip_verified_host_hash<'a>(host: &str, plaintext: &'a [u8]) -> &'a [u8] {
  let expected = sha256(host.as_bytes());
  plaintext
    .strip_prefix(expected.as_slice())
    .unwrap_or(plaintext)
}
```

The logic should be based on the verified bytes, not the encryption prefix. Add tests for matching hashes, mismatches, short values, empty original values, and older unprefixed values.

### 6. Cookie model and deterministic output

HackBrowserData's cookie model includes:

- creation timestamp;
- expiration timestamp;
- `has_expire` and `is_persistent`;
- secure and HTTP-only flags;
- normalized SameSite text;
- deterministic sorting by creation time;
- CookieEditor-compatible output with host-only and session semantics derived at formatting time.

`rookie`'s smaller `Cookie` model is sufficient for many HTTP clients, but raw integer SameSite values are not self-describing, and the lack of creation time and persistence flags limits accurate export and deterministic conflict resolution.

#### Recommendation

Avoid immediately breaking the public Rust, Python, and Node representations. Introduce an internal or versioned richer model first:

```rust
struct CookieRecord {
  cookie: Cookie,
  created_at: Option<SystemTime>,
  persistent: bool,
  same_site: SameSite,
  source: CookieSourceIdentity,
}
```

The existing `Cookie` can remain the compatibility projection. A future major release can decide whether the richer fields belong in the main public type.

Output formatting should remain separate from extraction. Adding a CookieEditor formatter is reasonable, but it is lower priority than extraction completeness and provenance.

### 7. Modern Safari profiles

HackBrowserData contains a detailed model for Safari's newer profile layout:

- The default profile is implicit.
- Named profiles are read from `SafariTabs.db` using their external UUIDs.
- Profile titles are sanitized and duplicate names are disambiguated.
- A directory scan provides a fallback when the profile database cannot be read.
- Default and named profiles use different binary-cookie paths under the Safari container and WebKit website-data store.

`rookie` currently searches for the modern default `Cookies.binarycookies` location and the older legacy location, then returns the first existing file. It does not enumerate named Safari profiles.

#### Recommendation

Implement Safari profile discovery after the common installation/profile API exists. Keep path knowledge in a Safari-specific module rather than expanding the global JSON configuration with UUID patterns. Reuse the same provenance and partial-failure structures used by Chromium and Firefox.

Safari's binary-cookie parser should also receive golden fixtures and malformed-input tests before its supported path surface grows.

### 8. Tests and maintenance practices

HackBrowserData has extensive fixture factories and tests for:

- profile markers and false-positive directories;
- flat browser layouts;
- ordered source fallback;
- browser-kind overrides;
- independent key-tier retrieval;
- mixed encryption versions;
- cookie domain-hash verification;
- file-session cleanup and companion-file copying;
- consistency between browser configuration and ABE metadata.

The repository also records storage, encryption, key retrieval, file acquisition, and Windows ABE decisions in focused RFC documents. The exact volume of documentation is not essential, but documenting invariants close to the implementation is valuable for security-sensitive, platform-specific code.

`rookie` already has good recent tests for parameterized domain filters, malformed-row tolerance, plaintext Chromium values, key known-answer vectors, active WAL rows, exclusive locks, checkpoint races, and Firefox profile resolution/selection. The next tests should focus on the remaining cross-component behavior that unit-only parser tests cannot prove.

#### Remaining regression fixtures

1. A user-data directory containing `Default`, multiple `Profile N` directories, guest/system directories, and a false-positive cache directory.
2. A mixed v10/v20 Windows cookie database with both keys available.
3. A mixed v10/v11 Linux cookie database.
4. Chrome host-hash match and mismatch cases.
5. A copied/restored Chromium tree without `Preferences` but with a valid cookie source.
6. A flat Opera-style layout.
7. Cross-binding extraction from a selected secondary Firefox profile.
8. A Safari default profile plus at least one named-profile binary-cookie fixture.
9. A partial-success report where one profile succeeds and another is locked, malformed, or undecryptable.

## Browser coverage comparison

Raw registered browser-key counts in the current trees are:

| Platform | `rookie` | HackBrowserData |
|---|---:|---:|
| Windows | 13 | 19 |
| macOS | 12 | 13 |
| Linux | 12 | 8 |

These figures should not be treated as a simple support score:

- `rookie` groups several release channels beneath one browser key.
- HackBrowserData is broader for Windows Chromium forks such as CocCoc, Yandex, 360, QQ, DC, Sogou, DuckDuckGo, and Browser from Vought.
- `rookie` is broader on Linux and supports Firefox derivatives such as Zen, LibreWolf, and Cachy.
- `rookie` supports Internet Explorer, which HackBrowserData does not.
- IE extraction now reads `secure` and `http_only` from the ESE flags column and represents unavailable SameSite metadata as unspecified rather than `None`.
- Recognizing a browser's files does not guarantee that all modern encryption variants are supported. Several HackBrowserData Windows entries do not opt into its ABE retriever.

The reusable lesson is therefore not to copy HackBrowserData's browser table verbatim. `rookie` should make browser additions cheaper by separating installation roots, profile discovery, source resolution, and encryption capability metadata.

## Behaviors `rookie` should retain

### Plaintext Chromium cookie values

`rookie` queries both `value` and `encrypted_value` and returns the plaintext value when present. HackBrowserData's Chromium cookie query selects only `encrypted_value`, so an unencrypted row becomes an empty value.

### Row-level fault isolation with a meaningful terminal error

`rookie` skips malformed or undecryptable rows, preserves successful rows, and returns a decryption error when every otherwise relevant row failed. HackBrowserData ignores the error from its per-row decrypt call and emits an empty value. The new architecture should preserve `rookie`'s behavior and improve it with structured warnings.

### Source-specific domain filtering

`rookie` has two observable filtering contracts today. Persistent Chromium and Mozilla SQLite queries bind `LIKE` parameters containing `%<requested-domain>%`, while Safari and Firefox session-state parsing use the boundary-aware, case-insensitive host matcher. Both behaviors are public compatibility constraints, including their differences. Legacy APIs and the initial generic reports must dispatch to the matcher belonging to the source adapter; they must not silently unify the SQLite substring behavior and the Safari/session boundary behavior. HackBrowserData's category extraction does not provide an equivalent domain-filtered API.

### Firefox session-cookie recovery

`rookie` augments persisted Firefox cookies with session state from `sessionstore.js` and `sessionstore-backups/recovery.jsonlz4`. HackBrowserData reads only `cookies.sqlite`. The current merge behavior is frozen for every existing Mozilla-family entry point that reaches `firefox_based`: `firefox`, `librewolf`, `zen`, Linux `cachy`, `firefox_profile`, direct `firefox_based`, and the Mozilla-success path of `any_browser` (plus `load`, CLI, Python, and Node calls through those APIs). New generic Mozilla report adapters instead associate one authoritative session source with the correct profile and preserve duplicates until cookie identity includes container, origin, and partition attributes. They must not retrofit authoritative selection into a legacy call path.

### Internet Explorer flags

`rookie` reads IE cookie security flags from ESE and fails closed on unreadable flags. The generic registry/report pipeline only needs an adapter for this existing extractor; it should not redesign IE parsing.

### Narrow product scope

Passwords, credit cards, browsing history, local storage, and extensions do not need to be added merely because HackBrowserData supports them. A focused cookie library can reuse the same architectural seams with a much smaller security and maintenance surface.

## Recommended delivery plan

The converged sequence is documented in [the implementation plan](hackbrowserdata_cookie_extraction_implementation_plan.md). In summary:

1. Freeze legacy API, selector, filtering, ordering, ID, report, source, acquisition, session, and CLI contracts.
2. Implement independent Chromium cipher-tier routing and verified host hashes without changing public signatures.
3. Close no-WAL and platform acquisition residuals while preserving the completed DB+WAL/no-SHM design.
4. Prove a private registry and multi-profile pipeline with a Chrome vertical slice.
5. Adapt every existing engine, Firefox authoritative session sources, and Safari named profiles while all generic report APIs remain private.
6. Publish the finalized Rust, Python, Node, and CLI profile/report surfaces together.
7. Add new browser definitions in evidence-gated, OS-specific batches.

Rich cookie metadata and CookieEditor output are follow-up work, not completion gates.

## Decision summary

Adopt these HackBrowserData concepts:

- installation/profile/source separation;
- acquisition sessions and WAL-aware temporary snapshots;
- independent versioned key retrievers;
- prefix-based cipher dispatch;
- verified Chromium domain hashes;
- source provenance and metadata-only discovery;
- engine-level source candidates with narrow fork overrides;
- fixture-driven tests and cross-table invariant tests;
- modern Safari profile layout knowledge.

Do not adopt these behaviors unchanged:

- silent decryption failure represented as an empty cookie value;
- omission of Chromium's plaintext `value` column;
- sequential DB/WAL/SHM copying without a consistency check;
- broad Windows handle enumeration or reflective injection without a separate design and threat review;
- unrelated browser-data categories that expand `rookie` beyond cookie extraction.

The immediate implementation work is the compatibility/contracts package, followed by versioned Chromium key routing. The existing WAL reader and Firefox profile APIs remain foundations to preserve, while the private registry and additive reports provide the path to broader browser support without changing legacy behavior.
