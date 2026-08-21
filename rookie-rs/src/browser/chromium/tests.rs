use super::super::chromium_projection::{
  extract_cookies_with_provider, extract_detailed_cookies_with_provider, project_detailed_draft,
  project_legacy_draft,
};
use super::*;
use crate::browser::chromium_crypto::LegacySharedKeyProvider;
#[cfg(target_os = "linux")]
use crate::browser::chromium_crypto::KeyProvider;
#[cfg(target_os = "windows")]
use crate::browser::chromium_database_acquisition::{WindowsDatabaseLocked, WindowsLockedFile};
#[cfg(target_os = "windows")]
use crate::browser::chromium_test_support::encrypt_windows_gcm_cookie;
#[cfg(unix)]
use crate::browser::chromium_test_support::host_bound_plaintext;
use crate::browser::cookie_record::{Observation, RawValue};
use std::cell::Cell;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

// Per-process unique temp paths without pulling in the `tempfile` dep.
fn unique_tmpdir(tag: &str) -> PathBuf {
  static COUNTER: AtomicU64 = AtomicU64::new(0);
  let n = COUNTER.fetch_add(1, Ordering::SeqCst);
  let dir = std::env::temp_dir().join(format!("rookie-test-{}-{}-{}", tag, std::process::id(), n));
  std::fs::create_dir_all(&dir).expect("temp dir");
  dir
}

fn extract_cookies_with_legacy_keys(
  keys: Vec<Vec<u8>>,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<Cookie>> {
  let provider = LegacySharedKeyProvider::new(keys);
  extract_cookies_with_provider(&provider, &(), db_path, domains, force_kill)
}

#[test]
fn sqlite_connection_log_redacts_an_absolute_path_with_spaces() {
  let directory = unique_tmpdir("absolute-path-log-sentinel");
  let path = directory
    .join("private profile sentinel with spaces")
    .join("Cookies");
  assert_eq!(
    SQLITE_CONNECTION_LOG,
    "Creating SQLite connection to <path>"
  );
  assert!(!SQLITE_CONNECTION_LOG.contains(path.to_string_lossy().as_ref()));
}

fn query_outcome_with_legacy_keys(
  keys: Vec<Vec<u8>>,
  db_path: PathBuf,
) -> Result<ChromiumExtractionDraft> {
  let outcomes = ChromiumKeyOutcomes::from_legacy_shared(keys);
  acquire_chromium_draft(&outcomes, db_path, None, false)
}

// (host_key, path, is_secure, expires_utc, name, value, encrypted_value, is_httponly, samesite)
type ChromiumRow<'a> = (
  &'a str,
  &'a str,
  bool,
  u64,
  &'a str,
  &'a str,
  &'a [u8],
  bool,
  i64,
);

fn seed_chromium_schema_version(connection: &rusqlite::Connection, version: u32) {
  connection
    .execute(
      "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR)",
      [],
    )
    .expect("create Chromium metadata table");
  connection
    .execute(
      "INSERT INTO meta (key, value) VALUES ('version', ?1)",
      [version.to_string()],
    )
    .expect("seed Chromium schema version");
}

// Minimal `cookies` table mirroring the columns chromium_based reads.
// Real Chrome schema has many more columns, but Chromium extraction only
// selects these nine.
fn seed_chromium_cookies(db: &Path, rows: &[ChromiumRow<'_>]) {
  let conn = rusqlite::Connection::open(db).expect("open writable sqlite");
  seed_chromium_schema_version(&conn, 23);
  conn
    .execute(
      "CREATE TABLE cookies (
        host_key TEXT NOT NULL,
        path TEXT NOT NULL,
        is_secure INTEGER NOT NULL,
        expires_utc INTEGER NOT NULL,
        name TEXT NOT NULL,
        value TEXT NOT NULL,
        encrypted_value BLOB,
        is_httponly INTEGER NOT NULL,
        samesite INTEGER NOT NULL
      )",
      [],
    )
    .expect("create table");
  for r in rows {
    conn
      .execute(
        "INSERT INTO cookies (host_key, path, is_secure, expires_utc, name, value, \
          encrypted_value, is_httponly, samesite) \
          VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![r.0, r.1, r.2, r.3, r.4, r.5, r.6, r.7, r.8],
      )
      .expect("insert row");
  }
}

#[test]
fn detailed_cookies_preserve_partition_collisions() {
  let dir = unique_tmpdir("chromium-partition-collision");
  let db = dir.join("Cookies");
  let connection = rusqlite::Connection::open(&db).expect("open fixture");
  seed_chromium_schema_version(&connection, 23);
  connection
    .execute_batch(
      "CREATE TABLE cookies (
        host_key TEXT NOT NULL, path TEXT NOT NULL, is_secure INTEGER NOT NULL,
        expires_utc INTEGER NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
        encrypted_value BLOB, is_httponly INTEGER NOT NULL, samesite INTEGER NOT NULL,
        top_frame_site_key TEXT, has_cross_site_ancestor INTEGER,
        source_scheme INTEGER, source_port INTEGER, is_persistent INTEGER
      );
      INSERT INTO cookies VALUES
        ('.example.com', '/', 1, 0, 'session', 'work', X'', 1, 1,
         'https://work.example', 1, 2, 443, 1),
        ('.example.com', '/', 1, 0, 'session', 'personal', X'', 1, 1,
         'https://personal.example', 0, 2, 443, 1);",
    )
    .expect("seed partitioned cookies");
  drop(connection);

  let provider = LegacySharedKeyProvider::new(Vec::new());
  let cookies = extract_detailed_cookies_with_provider(&provider, &(), db, None, false)
    .expect("extract detailed cookies");
  assert_eq!(cookies.len(), 2);
  assert_eq!(cookies[0].cookie.name, cookies[1].cookie.name);
  assert_eq!(cookies[0].cookie.domain, cookies[1].cookie.domain);
  assert_eq!(cookies[0].cookie.path, cookies[1].cookie.path);
  let contexts = cookies
    .iter()
    .map(|cookie| {
      (
        cookie.cookie.value.as_str(),
        (
          cookie.context.top_frame_site_key.as_deref(),
          cookie.context.has_cross_site_ancestor,
        ),
      )
    })
    .collect::<std::collections::HashMap<_, _>>();
  assert_eq!(
    contexts.get("work"),
    Some(&(Some("https://work.example"), Some(true)))
  );
  assert_eq!(
    contexts.get("personal"),
    Some(&(Some("https://personal.example"), Some(false)))
  );
  assert_eq!(cookies[0].context.source_scheme, Some(2));
  assert_eq!(cookies[0].context.source_port, Some(443));
  assert_eq!(cookies[0].context.is_persistent, Some(true));
}

#[test]
fn detailed_query_keeps_legacy_schemas_readable() {
  let dir = unique_tmpdir("chromium-legacy-detailed-schema");
  let db = dir.join("Cookies");
  seed_chromium_cookies(
    &db,
    &[(
      ".example.com",
      "/",
      false,
      0,
      "legacy",
      "value",
      b"",
      false,
      0,
    )],
  );

  let provider = LegacySharedKeyProvider::new(Vec::new());
  let cookies = extract_detailed_cookies_with_provider(&provider, &(), db, None, false)
    .expect("missing optional columns remain compatible");
  assert_eq!(cookies.len(), 1);
  assert_eq!(cookies[0].context, CookieContext::default());
}

#[test]
fn malformed_optional_context_is_retained_without_projection_divergence() {
  let dir = unique_tmpdir("chromium-malformed-detailed-context");
  let db = dir.join("Cookies");
  let connection = rusqlite::Connection::open(&db).expect("open fixture");
  seed_chromium_schema_version(&connection, 23);
  connection
    .execute_batch(
      "CREATE TABLE cookies (
        host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
        name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER,
        samesite INTEGER, top_frame_site_key BLOB
      );
      INSERT INTO cookies VALUES
        ('.example.com', '/', 0, 0, 'legacy', 'value', X'', 0, 0, X'FF');",
    )
    .expect("seed malformed context");
  drop(connection);

  let provider = LegacySharedKeyProvider::new(Vec::new());
  let legacy = extract_cookies_with_provider(&provider, &(), db.clone(), None, false)
    .expect("legacy projection does not inspect detailed columns");
  assert_eq!(legacy.len(), 1);
  let detailed = extract_detailed_cookies_with_provider(&provider, &(), db, None, false)
    .expect("malformed optional context is retained as raw typed loss");
  assert_eq!(detailed.len(), 1);
  assert_eq!(detailed[0].context, CookieContext::default());
}

#[test]
fn malformed_detailed_context_skips_only_its_row() {
  let dir = unique_tmpdir("chromium-mixed-detailed-context");
  let db = dir.join("Cookies");
  let connection = rusqlite::Connection::open(&db).expect("open fixture");
  seed_chromium_schema_version(&connection, 23);
  connection
    .execute_batch(
      "CREATE TABLE cookies (
        host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
        name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER,
        samesite INTEGER, top_frame_site_key BLOB
      );
      INSERT INTO cookies VALUES
        ('.example.com', '/', 0, 0, 'before', 'first', X'', 0, 0,
         'https://before.example'),
        ('.example.com', '/', 0, 0, 'malformed', 'discarded', X'', 0, 0, X'FF'),
        ('.example.com', '/', 0, 0, 'after', 'last', X'', 0, 0,
         'https://after.example');",
    )
    .expect("seed mixed context rows");
  drop(connection);

  let provider = LegacySharedKeyProvider::new(Vec::new());
  let legacy = extract_cookies_with_provider(&provider, &(), db.clone(), None, false)
    .expect("legacy projection keeps every row");
  assert_eq!(legacy.len(), 3);

  let extraction = acquire_chromium_draft_mode(
    &ChromiumKeyOutcomes::from_legacy_shared(Vec::new()),
    db.clone(),
    None,
    false,
    CookieProjection::Detailed,
    EncryptedValuePolicy::UseKeyOutcomes,
  )
  .expect("malformed optional context remains a usable row");
  assert_eq!(
    extraction.stats,
    ChromiumExtractionStats {
      rows_seen: 3,
      cookies_emitted: 3,
      rows_skipped: 0,
      rows_rejected: 0,
      provider_failures: 0,
    }
  );
  assert!(extraction.issues.is_empty());
  assert!(extraction.legacy_error.is_none());
  let detailed = project_detailed_draft(&db, extraction)
    .expect("valid detailed rows keep the extraction successful");
  assert_eq!(
    detailed
      .iter()
      .map(|cookie| cookie.cookie.name.as_str())
      .collect::<Vec<_>>(),
    vec!["before", "malformed", "after"]
  );

  let public_result = extract_detailed_cookies_with_provider(&provider, &(), db, None, false)
    .expect("public detailed extraction returns the valid rows");
  assert_eq!(public_result.len(), 3);
}

#[test]
fn decode_unseal_preserves_row_failure_precedence_order_and_typed_source_chain() {
  let connection = rusqlite::Connection::open_in_memory().expect("open fixture");
  seed_chromium_schema_version(&connection, 23);
  connection
    .execute_batch(
      "CREATE TABLE cookies (
        host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
        name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER,
        samesite INTEGER, top_frame_site_key BLOB
      );
      INSERT INTO cookies VALUES
        ('.example.com', '/', 0, 0, 'cipher-before-context', 'must not leak',
         X'7631', 0, 0, X'FF'),
        ('.example.com', '/', 0, 0, X'FF', 'unreadable name', X'', 0, 0,
         'https://valid.example'),
        ('.example.com', '/', 0, 0, 'context-last', 'plain', X'', 0, 0,
         X'FF');",
    )
    .expect("seed compound and interleaved failures");

  let outcome = decode_chromium_connection_mode(
    &connection,
    &ChromiumKeyOutcomes::default(),
    None,
    CookieProjection::Detailed,
    EncryptedValuePolicy::UseKeyOutcomes,
  )
  .expect("row failures remain an extraction outcome");

  assert_eq!(
    outcome.stats,
    ChromiumExtractionStats {
      rows_seen: 3,
      cookies_emitted: 1,
      rows_skipped: 2,
      rows_rejected: 2,
      provider_failures: 0,
    }
  );
  assert_eq!(
    outcome
      .issues
      .iter()
      .map(|issue| (issue.code, issue.occurrences))
      .collect::<Vec<_>>(),
    vec![
      (ChromiumRowIssueCode::Decrypt, 1),
      (ChromiumRowIssueCode::ColumnRead("name"), 1),
    ],
    "malformed optional context is retained as typed raw metadata"
  );
  assert!(outcome.legacy_error.is_none());
  assert_eq!(outcome.detailed_cookies.len(), 1);
}

#[test]
fn compound_row_failure_keeps_decrypt_precedence_over_context() {
  let connection = rusqlite::Connection::open_in_memory().expect("open fixture");
  seed_chromium_schema_version(&connection, 23);
  connection
    .execute_batch(
      "CREATE TABLE cookies (
        host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
        name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER,
        samesite INTEGER, top_frame_site_key BLOB
      );
      INSERT INTO cookies VALUES
        ('.example.com', '/', 0, 0, 'compound', 'must not leak', X'7631',
         0, 0, X'FF');",
    )
    .expect("seed compound failure");

  let outcome = decode_chromium_connection_mode(
    &connection,
    &ChromiumKeyOutcomes::default(),
    None,
    CookieProjection::Detailed,
    EncryptedValuePolicy::UseKeyOutcomes,
  )
  .expect("row failure remains an extraction outcome");
  assert_eq!(outcome.issues.len(), 1);
  assert_eq!(outcome.issues[0].code, ChromiumRowIssueCode::Decrypt);
  let error = outcome
    .legacy_error
    .as_ref()
    .expect("all-row failure keeps the unseal error");
  assert!(format!("{error:#}").contains("shorter than the 3-byte cipher prefix"));
  assert!(!format!("{error:#}").contains("must not leak"));
}

#[cfg(target_os = "windows")]
fn open_without_file_sharing(path: &Path) -> std::fs::File {
  use std::os::windows::fs::OpenOptionsExt;

  std::fs::OpenOptions::new()
    .read(true)
    .share_mode(0)
    .open(path)
    .expect("open exclusive Windows fixture handle")
}

#[cfg(target_os = "windows")]
#[test]
fn windows_native_share_denied_valid_database_reaches_real_query_policy() {
  let directory = crate::utils::TempDir::new().expect("temp dir");
  let db = directory.path().join("Cookies");
  seed_chromium_cookies(
    &db,
    &[(
      ".example.com",
      "/",
      false,
      0,
      "plain",
      "fixture value",
      b"",
      false,
      0,
    )],
  );
  assert!(
    !sqlite::sidecar(&db, "-wal").exists(),
    "fixture must take the live no-WAL acquisition path"
  );

  let exclusive = open_without_file_sharing(&db);
  let error = extract_cookies_with_legacy_keys(vec![], db.clone(), None, false)
    .expect_err("real query boundary must report the native sharing denial");

  let locked = error
    .downcast_ref::<WindowsDatabaseLocked>()
    .expect("native failure retains typed Windows lock context");
  assert_eq!(locked.locked_file, WindowsLockedFile::Database);
  assert_eq!(locked.locked_path, db);
  assert!(!locked.has_verified_nonempty_wal);
  assert!(
    !locked.shutdown_allowed,
    "force_kill=false must not authorize restart-manager shutdown"
  );
  let acquisition = error
    .downcast_ref::<sqlite::BrowserDatabaseFailure>()
    .expect("real acquisition metadata remains in the final chain");
  assert_eq!(
    acquisition.kind,
    sqlite::BrowserDatabaseFailureKind::Acquisition
  );
  assert_eq!(acquisition.attempts, 1);
  assert!(
    matches!(
      acquisition.strategy,
      None | Some(sqlite::DatabaseAcquisitionStrategy::LiveReadOnly)
    ),
    "the exclusive handle can deny either canonicalization or the live open: {acquisition:?}"
  );
  assert!(
    matches!(locked.os_error, 32 | 33),
    "the typed lock must retain the native Win32 sharing code: {error:#}"
  );
  assert!(
    std::fs::File::open(&db).is_err(),
    "the library must not release or shut down the process owning the exclusive handle"
  );

  drop(exclusive);
  let cookies = extract_cookies_with_legacy_keys(vec![], db, None, false)
    .expect("the unchanged database is readable after releasing the fixture handle");
  assert_eq!(cookies.len(), 1);
  assert_eq!(cookies[0].name, "plain");
  assert_eq!(cookies[0].value, "fixture value");
}

#[cfg(unix)]
fn encrypt_unix_cbc_cookie(version: &[u8; 3], key: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
  use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

  type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

  let iv = [b' '; 16];
  let cipher = Aes128CbcEnc::new((&key[..]).into(), &iv.into());
  let mut buffer = vec![0; plaintext.len() + 16];
  buffer[..plaintext.len()].copy_from_slice(plaintext);
  let ciphertext = cipher
    .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
    .expect("encrypt synthetic Chromium cookie");
  let mut encrypted_value = version.to_vec();
  encrypted_value.extend_from_slice(ciphertext);
  encrypted_value
}
#[cfg(target_os = "linux")]
struct SyntheticTierProvider {
  calls: Cell<usize>,
  outcomes: ChromiumKeyOutcomes,
}

#[cfg(target_os = "linux")]
impl KeyProvider<str> for SyntheticTierProvider {
  type Keys = ChromiumKeyOutcomes;

  fn keys(
    &self,
    _context: &str,
    _runtime: &crate::common::deadline::BoundaryRuntime<'_>,
  ) -> ChromiumKeyOutcomes {
    self.calls.set(self.calls.get() + 1);
    self.outcomes.clone()
  }
}

#[cfg(target_os = "linux")]
#[test]
fn injected_provider_routes_mixed_tiers_once_and_isolates_a_failed_tier() {
  let dir = unique_tmpdir("chr-injected-mixed-tiers");
  let db = dir.join("Cookies");
  let v10_key = [0x10; 16];
  let v11_key = [0x11; 16];
  let v10_value = encrypt_unix_cbc_cookie(b"v10", &v10_key, b"v10 value");
  let failed_v20_value = b"v20synthetic-provider-failure".to_vec();
  let v11_value = encrypt_unix_cbc_cookie(b"v11", &v11_key, b"v11 value");

  // The rows deliberately run success/failure/success. A provider failure
  // for one tier is row-scoped and must not discard either successful CBC
  // tier or trigger another installation-scoped provider call.
  seed_chromium_cookies(
    &db,
    &[
      (
        ".example.com",
        "/",
        false,
        0,
        "v10-good",
        "attacker-controlled plaintext",
        &v10_value,
        false,
        0,
      ),
      (
        ".example.com",
        "/",
        false,
        0,
        "v20-failed-tier",
        "must not leak when provider fails",
        &failed_v20_value,
        false,
        0,
      ),
      (
        ".example.com",
        "/",
        false,
        0,
        "v11-good",
        "attacker-controlled plaintext",
        &v11_value,
        false,
        0,
      ),
    ],
  );

  let provider = SyntheticTierProvider {
    calls: Cell::new(0),
    outcomes: ChromiumKeyOutcomes {
      v10: crate::browser::chromium_crypto::ChromiumKeyOutcome::success(vec![v10_key.to_vec()])
        .expect("nonempty v10 fixture"),
      v11: crate::browser::chromium_crypto::ChromiumKeyOutcome::success(vec![v11_key.to_vec()])
        .expect("nonempty v11 fixture"),
      v20: crate::browser::chromium_crypto::ChromiumKeyOutcome::failure(
        "synthetic v20 provider failure",
      ),
    },
  };

  let mut cookies = extract_cookies_with_provider(&provider, "linux-installation", db, None, false)
    .expect("good tiers survive one failed tier");

  assert_eq!(provider.calls.get(), 1);
  cookies.sort_by(|left, right| left.name.cmp(&right.name));
  let extracted: Vec<_> = cookies
    .iter()
    .map(|cookie| (cookie.name.as_str(), cookie.value.as_str()))
    .collect();
  assert_eq!(
    extracted,
    vec![("v10-good", "v10 value"), ("v11-good", "v11 value")]
  );
  assert!(cookies
    .iter()
    .all(|cookie| cookie.value != "attacker-controlled plaintext"));
}

#[test]
fn decoder_retains_ciphertext_and_discards_dual_populated_plaintext() {
  let dir = unique_tmpdir("chr-decoder-ciphertext-record");
  let db = dir.join("Cookies");
  seed_chromium_cookies(
    &db,
    &[(
      ".example.com",
      "/",
      false,
      0,
      "dual",
      "must not survive decode",
      b"v20ciphertext",
      false,
      0,
    )],
  );
  let connection = rusqlite::Connection::open(db).expect("open fixture");
  let mut decoder = super::super::chromium_decoder::prepare_cookie_decoder(
    &connection,
    None,
    EncryptedValuePolicy::UseKeyOutcomes,
  )
  .expect("prepare decode without key material");
  let mut cursor = decoder.cursor().expect("start decoder cursor");
  let mut events = Vec::new();
  while let Some(event) = cursor.next_event().expect("decode next row") {
    events.push(event);
  }
  let summary = cursor.summary();

  assert_eq!(summary.rows_seen, 1);
  assert_eq!(events.len(), 1);
  let ChromiumDecodeEvent::Record(decoded) = events.pop().expect("one event") else {
    panic!("valid row must decode to a record")
  };
  assert_eq!(
    decoded.record.value,
    super::super::cookie_record::CookieValue::Encrypted {
      tier: super::super::cookie_record::CipherTier::V20,
      bytes: b"v20ciphertext".to_vec(),
    }
  );
}

#[test]
fn authoritative_ciphertext_bypasses_null_blob_and_invalid_text_plaintext_columns() {
  let connection = rusqlite::Connection::open_in_memory().expect("open fixture");
  seed_chromium_schema_version(&connection, 23);
  connection
    .execute_batch(
      "CREATE TABLE cookies (
         host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
         name TEXT, value, encrypted_value BLOB, is_httponly INTEGER,
         samesite INTEGER
       );
       INSERT INTO cookies VALUES
         ('.example.com', '/', 0, 0, 'null-value', NULL,
          X'76313073796E7468657469632D76616C6964', 0, 0),
         ('.example.com', '/', 0, 0, 'blob-value', X'00FF',
          X'76313073796E7468657469632D76616C6964', 0, 0),
         ('.example.com', '/', 0, 0, 'invalid-text', CAST(X'FF' AS TEXT),
          X'76313073796E7468657469632D76616C6964', 0, 0);",
    )
    .expect("seed authoritative ciphertext rows");

  let outcome = decode_and_unseal_cookie_records(
    &connection,
    None,
    EncryptedValuePolicy::UseKeyOutcomes,
    |mut record, _schema_version| {
      assert!(matches!(
        &record.value,
        super::super::cookie_record::CookieValue::Encrypted {
          tier: super::super::cookie_record::CipherTier::V10,
          ..
        }
      ));
      record.value = super::super::cookie_record::CookieValue::Plain(SecretString::new(format!(
        "decrypted-{}",
        record.name
      )));
      Ok(record)
    },
  )
  .expect("authoritative ciphertext rows are decryptable");

  assert_eq!(outcome.stats.rows_seen, 3);
  assert_eq!(outcome.stats.cookies_emitted, 3);
  assert_eq!(outcome.stats.rows_skipped, 0);
  assert!(outcome
    .issues
    .iter()
    .all(|issue| { issue.code != ChromiumRowIssueCode::ColumnRead("value") }));
  assert_eq!(
    outcome
      .cookies
      .iter()
      .map(|cookie| cookie.value.as_str())
      .collect::<Vec<_>>(),
    vec![
      "decrypted-null-value",
      "decrypted-blob-value",
      "decrypted-invalid-text"
    ]
  );
}

#[test]
fn retained_detailed_ciphertext_result_never_reads_stored_plaintext() {
  const STORED_PLAINTEXT: &str = "stored-plaintext-must-never-be-owned";
  const DECRYPTED: &str = "decrypted-value-must-be-wiped";
  let connection = rusqlite::Connection::open_in_memory().expect("open fixture");
  seed_chromium_schema_version(&connection, 23);
  connection
    .execute_batch(&format!(
      "CREATE TABLE cookies (
         host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
         name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER,
         samesite INTEGER, top_frame_site_key BLOB
       );
       INSERT INTO cookies VALUES
         ('.example.com', '/', 0, 0, 'discarded', '{STORED_PLAINTEXT}',
          X'76323073796E7468657469632D76616C6964', 0, 0, X'FF');"
    ))
    .expect("seed detailed context failure");

  let (observed, unwind) = crate::common::secret::observe_secret_string_drops(|| {
    let outcome = decode_and_unseal_cookie_records(
      &connection,
      None,
      EncryptedValuePolicy::UseKeyOutcomes,
      |mut record, _schema_version| {
        assert!(matches!(
          &record.value,
          super::super::cookie_record::CookieValue::Encrypted {
            tier: super::super::cookie_record::CipherTier::V20,
            ..
          }
        ));
        record.value =
          super::super::cookie_record::CookieValue::Plain(SecretString::new(DECRYPTED.to_owned()));
        Ok(record)
      },
    )
    .expect("unknown optional context remains a row outcome");
    assert_eq!(outcome.detailed_cookies.len(), 1);
    assert_eq!(outcome.detailed_cookies[0].cookie.value, DECRYPTED);
    assert_eq!(outcome.stats.rows_skipped, 0);
    assert!(outcome.issues.is_empty());
  });

  assert!(unwind.is_ok());
  assert!(
    observed
      .iter()
      .any(|(len, value)| *len == DECRYPTED.len() && value.iter().all(|byte| *byte == 0)),
    "the protected decrypted allocation is wiped when the draft is dropped"
  );
  assert!(
    observed
      .iter()
      .all(|(len, _)| *len != STORED_PLAINTEXT.len()),
    "authoritative ciphertext must bypass the stored plaintext"
  );
}

#[test]
fn late_missing_identity_error_wipes_staged_plaintext_before_returning() {
  const STAGED: &str = "staged-plaintext-must-be-wiped";
  let connection = rusqlite::Connection::open_in_memory().expect("open fixture");
  seed_chromium_schema_version(&connection, 23);
  connection
    .execute_batch(&format!(
      "CREATE TABLE cookies (
         host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
         name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER,
         samesite INTEGER
       );
       INSERT INTO cookies VALUES
         ('.example.com', '/', 0, 0, 'staged', '{STAGED}', X'', 0, 0),
         ('.example.com', '/', 0, 0, 'late-encrypted', 'must-not-win',
          X'76313073796E746865746963', 0, 0);"
    ))
    .expect("seed late identity failure");

  let (observed, unwind) = crate::common::secret::observe_secret_string_drops(|| {
    let error = decode_and_unseal_cookie_records(
      &connection,
      None,
      EncryptedValuePolicy::RejectMissingIdentity,
      |record, schema_version| {
        unseal_chromium_record(record, &ChromiumKeyOutcomes::default(), schema_version)
      },
    )
    .expect_err("a later encrypted row rejects the complete plaintext-only attempt");
    assert!(error.is::<MissingBrowserKeyIdentity>());
    assert!(!format!("{error:#}").contains(STAGED));
  });

  assert!(unwind.is_ok());
  assert_eq!(observed.len(), 1);
  assert_eq!(observed[0].0, STAGED.len());
  assert!(observed[0].1.iter().all(|byte| *byte == 0));
}

#[test]
fn unwind_during_later_unseal_wipes_every_staged_success() {
  const DECRYPTED: &str = "staged-decrypted-value-must-be-wiped";
  let connection = rusqlite::Connection::open_in_memory().expect("open fixture");
  seed_chromium_schema_version(&connection, 23);
  connection
    .execute_batch(
      "CREATE TABLE cookies (
         host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
         name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER,
         samesite INTEGER
       );
       INSERT INTO cookies VALUES
         ('.example.com', '/', 0, 0, 'first', 'ignored', X'7631306669727374', 0, 0),
         ('.example.com', '/', 0, 0, 'second', 'ignored', X'7631307365636F6E64', 0, 0);",
    )
    .expect("seed unwind fixture");

  let calls = Cell::new(0);
  let (observed, unwind) = crate::common::secret::observe_secret_string_drops(|| {
    let _ = decode_and_unseal_cookie_records(
      &connection,
      None,
      EncryptedValuePolicy::UseKeyOutcomes,
      |mut record, _schema_version| {
        let call = calls.get() + 1;
        calls.set(call);
        if call == 2 {
          panic!("synthetic later-row unseal panic");
        }
        record.value =
          super::super::cookie_record::CookieValue::Plain(SecretString::new(DECRYPTED.to_owned()));
        Ok(record)
      },
    );
  });

  assert!(unwind.is_err());
  assert_eq!(calls.get(), 2);
  assert_eq!(observed.len(), 1);
  assert_eq!(observed[0].0, DECRYPTED.len());
  assert!(observed[0].1.iter().all(|byte| *byte == 0));
}

fn dual_populated_tier_fixture(ciphertext: &[u8]) -> rusqlite::Connection {
  let connection = rusqlite::Connection::open_in_memory().expect("open tier fixture");
  seed_chromium_schema_version(&connection, 23);
  connection
    .execute_batch(
      "CREATE TABLE cookies (
         host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
         name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER,
         samesite INTEGER, top_frame_site_key TEXT
       );",
    )
    .expect("create tier fixture");
  connection
    .execute(
      "INSERT INTO cookies VALUES
        ('.example.com', '/', 0, 0, 'tier',
         'plaintext-fallback-must-not-escape', ?1, 0, 0,
         'https://partition.example')",
      [ciphertext],
    )
    .expect("insert tier fixture");
  connection
}

fn injected_tier_outcome(
  connection: &rusqlite::Connection,
  _projection: CookieProjection,
  expected_tier: super::super::cookie_record::CipherTier,
  succeed: bool,
) -> ChromiumExtractionDraft {
  decode_and_unseal_cookie_records(
    connection,
    None,
    EncryptedValuePolicy::UseKeyOutcomes,
    |mut record, _schema_version| {
      let actual_tier = match &record.value {
        super::super::cookie_record::CookieValue::Encrypted { tier, .. } => *tier,
        _ => panic!("dual-populated row must reach unseal as ciphertext"),
      };
      assert_eq!(actual_tier, expected_tier);
      if succeed {
        record.value = super::super::cookie_record::CookieValue::Plain(SecretString::new(format!(
          "decrypted-{expected_tier:?}"
        )));
        Ok(record)
      } else {
        Err(Box::new((
          record,
          ChromiumCookieValueError::ProviderUnavailable(anyhow!(
            "injected {expected_tier:?} unavailable"
          )),
        )))
      }
    },
  )
  .expect("tier fixture decodes")
}

#[test]
fn every_corrected_cipher_tier_uses_ciphertext_on_legacy_detailed_and_report_surfaces() {
  use super::super::cookie_record::CipherTier;

  for (ciphertext, tier) in [
    (b"v10synthetic".as_slice(), CipherTier::V10),
    (b"v11synthetic".as_slice(), CipherTier::V11),
    (b"v20synthetic".as_slice(), CipherTier::V20),
    (b"raw-dpapi-synthetic".as_slice(), CipherTier::LegacyDpapi),
  ] {
    let connection = dual_populated_tier_fixture(ciphertext);
    let expected_value = format!("decrypted-{tier:?}");

    let report = injected_tier_outcome(&connection, CookieProjection::Legacy, tier, true);
    assert_eq!(report.stats.rows_seen, 1);
    assert_eq!(report.stats.cookies_emitted, 1);
    assert_eq!(report.stats.rows_skipped, 0);
    assert_eq!(report.cookies[0].value, expected_value);
    assert_ne!(
      report.cookies[0].value,
      "plaintext-fallback-must-not-escape"
    );

    let legacy = project_legacy_draft(
      Path::new("in-memory-chromium-fixture"),
      injected_tier_outcome(&connection, CookieProjection::Legacy, tier, true),
    )
    .expect("legacy projection succeeds");
    assert_eq!(legacy[0].value, expected_value);

    let detailed = project_detailed_draft(
      Path::new("in-memory-chromium-fixture"),
      injected_tier_outcome(&connection, CookieProjection::Detailed, tier, true),
    )
    .expect("detailed projection succeeds");
    assert_eq!(detailed[0].cookie.value, expected_value);
    assert_eq!(
      detailed[0].context.top_frame_site_key.as_deref(),
      Some("https://partition.example")
    );

    let failed_report = injected_tier_outcome(&connection, CookieProjection::Legacy, tier, false);
    assert!(failed_report.cookies.is_empty());
    assert_eq!(failed_report.stats.rows_skipped, 1);
    assert_eq!(
      failed_report.issues[0].code,
      ChromiumRowIssueCode::ProviderUnavailable
    );
    assert!(
      !format!("{:#}", failed_report.legacy_error.as_ref().unwrap())
        .contains("plaintext-fallback-must-not-escape")
    );

    let legacy_error = project_legacy_draft(
      Path::new("in-memory-chromium-fixture"),
      injected_tier_outcome(&connection, CookieProjection::Legacy, tier, false),
    )
    .expect_err("legacy all-row failure remains an error");
    assert!(!format!("{legacy_error:#}").contains("plaintext-fallback-must-not-escape"));

    let detailed_error = project_detailed_draft(
      Path::new("in-memory-chromium-fixture"),
      injected_tier_outcome(&connection, CookieProjection::Detailed, tier, false),
    )
    .expect_err("detailed all-row failure remains an error");
    assert!(!format!("{detailed_error:#}").contains("plaintext-fallback-must-not-escape"));
  }
}

#[test]
fn provider_failures_are_counted_once_per_distinct_tier_and_not_as_rejected_rows() {
  let dir = unique_tmpdir("chr-provider-counter-separation");
  let db = dir.join("Cookies");
  seed_chromium_cookies(
    &db,
    &[
      (
        ".example.com",
        "/",
        false,
        0,
        "v10-first",
        "must not leak v10 first",
        b"v10ciphertext-one",
        false,
        0,
      ),
      (
        ".example.com",
        "/",
        false,
        0,
        "v10-second",
        "must not leak v10 second",
        b"v10ciphertext-two",
        false,
        0,
      ),
      (
        ".example.com",
        "/",
        false,
        0,
        "v11",
        "must not leak v11",
        b"v11ciphertext",
        false,
        0,
      ),
    ],
  );
  let outcomes = ChromiumKeyOutcomes {
    v10: crate::browser::chromium_crypto::ChromiumKeyOutcome::failure(
      "synthetic v10 provider failure",
    ),
    v11: crate::browser::chromium_crypto::ChromiumKeyOutcome::failure(
      "synthetic v11 provider failure",
    ),
    v20: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
  };
  let outcome = acquire_chromium_draft(&outcomes, db, None, false)
    .expect("provider failure remains a record-level outcome");

  assert!(outcome.cookies.is_empty());
  assert_eq!(outcome.stats.rows_seen, 3);
  assert_eq!(outcome.stats.rows_skipped, 3);
  assert_eq!(outcome.stats.rows_rejected, 0);
  assert_eq!(outcome.stats.provider_failures, 2);
  assert_eq!(
    outcome.stats.rows_seen - outcome.stats.rows_skipped,
    outcome.stats.cookies_emitted
  );
  assert_eq!(outcome.issues.len(), 2, "tiers have distinct failure keys");
  assert_eq!(outcome.issues[0].code, ChromiumRowIssueCode::ProviderFailed);
  assert_eq!(outcome.issues[0].tier.as_deref(), Some("v10"));
  assert_eq!(outcome.issues[0].occurrences, 2);
  assert_eq!(outcome.issues[1].tier.as_deref(), Some("v11"));
  assert_eq!(outcome.issues[1].occurrences, 1);
  assert!(outcome.legacy_error.is_some());
}

#[test]
fn dual_populated_v20_provider_failure_is_reportable_but_legacy_errors() {
  let dir = unique_tmpdir("chr-v20-provider-pipeline");
  let db = dir.join("Cookies");
  seed_chromium_cookies(
    &db,
    &[(
      ".example.com",
      "/",
      false,
      0,
      "v20",
      "plaintext sentinel must not escape",
      b"v20app-bound-ciphertext",
      false,
      0,
    )],
  );
  let outcomes = ChromiumKeyOutcomes {
    v10: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
    v11: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
    v20: crate::browser::chromium_crypto::ChromiumKeyOutcome::failure(
      "synthetic App-Bound provider failure",
    ),
  };

  let outcome = acquire_chromium_draft(&outcomes, db.clone(), None, false)
    .expect("provider failure remains reportable after a successful query");
  assert!(outcome.cookies.is_empty());
  assert_eq!(outcome.stats.rows_seen, 1);
  assert_eq!(outcome.stats.rows_skipped, 1);
  assert_eq!(outcome.stats.rows_rejected, 0);
  assert_eq!(outcome.stats.provider_failures, 1);
  assert_eq!(outcome.issues[0].code, ChromiumRowIssueCode::ProviderFailed);
  assert!(outcome.legacy_error.is_some());

  let error =
    super::super::chromium_projection::extract_cookies_with_key_outcomes(outcomes, db, None, false)
      .expect_err("legacy projection must fail when every row is unavailable");
  assert!(!format!("{error:#}").contains("plaintext sentinel must not escape"));
  assert!(format!("{error:#}").contains("App-Bound provider failure"));
}

#[cfg(unix)]
#[test]
fn dual_populated_legacy_dpapi_pipeline_never_projects_plaintext() {
  let dir = unique_tmpdir("chr-legacy-dpapi-pipeline");
  let db = dir.join("Cookies");
  seed_chromium_cookies(
    &db,
    &[(
      ".example.com",
      "/",
      false,
      0,
      "legacy-dpapi",
      "plaintext sentinel must not escape",
      b"raw-dpapi-envelope",
      false,
      0,
    )],
  );

  let outcome = acquire_chromium_draft(&ChromiumKeyOutcomes::default(), db, None, false)
    .expect("unsupported DPAPI remains a row-level outcome");
  assert!(outcome.cookies.is_empty());
  assert_eq!(outcome.stats.rows_skipped, 1);
  assert_eq!(outcome.stats.rows_rejected, 0);
  assert_eq!(outcome.stats.provider_failures, 0);
  assert_eq!(
    outcome.issues[0].code,
    ChromiumRowIssueCode::ProviderUnavailable
  );
}

#[cfg(unix)]
#[test]
fn detailed_pipeline_unseals_dual_populated_ciphertext_before_projection() {
  let dir = unique_tmpdir("chr-detailed-unseal-pipeline");
  let db = dir.join("Cookies");
  let key = [0x2a; 16];
  let encrypted = encrypt_unix_cbc_cookie(b"v10", &key, b"decrypted detail");
  seed_chromium_cookies(
    &db,
    &[(
      ".example.com",
      "/detail",
      true,
      0,
      "detailed",
      "plaintext sentinel must not escape",
      &encrypted,
      true,
      1,
    )],
  );
  let outcomes = ChromiumKeyOutcomes {
    v10: crate::browser::chromium_crypto::ChromiumKeyOutcome::success(vec![key.to_vec()])
      .expect("nonempty v10 fixture"),
    v11: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
    v20: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
  };

  let outcome = acquire_chromium_draft_mode(
    &outcomes,
    db,
    None,
    false,
    CookieProjection::Detailed,
    EncryptedValuePolicy::UseKeyOutcomes,
  )
  .expect("detailed extraction");
  assert_eq!(outcome.cookies.len(), 1);
  assert_eq!(outcome.cookies[0].value, "decrypted detail");
  assert_eq!(outcome.detailed_cookies.len(), 1);
  assert_eq!(outcome.detailed_cookies[0].cookie.value, "decrypted detail");
  assert_ne!(
    outcome.detailed_cookies[0].cookie.value,
    "plaintext sentinel must not escape"
  );
  assert_eq!(outcome.stats.cookies_emitted, 1);
  assert_eq!(outcome.stats.rows_skipped, 0);
}

#[cfg(windows)]
#[test]
fn dual_populated_v20_pipeline_decrypts_with_app_bound_tier() {
  let dir = unique_tmpdir("chr-v20-app-bound-pipeline");
  let db = dir.join("Cookies");
  let key = [0x20; 32];
  let encrypted = encrypt_windows_gcm_cookie(b"v20", &key, b"decrypted v20");
  seed_chromium_cookies(
    &db,
    &[(
      ".example.com",
      "/",
      false,
      0,
      "v20",
      "plaintext sentinel must not escape",
      &encrypted,
      false,
      0,
    )],
  );
  let outcomes = ChromiumKeyOutcomes {
    v10: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
    v11: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
    v20: crate::browser::chromium_crypto::ChromiumKeyOutcome::success(vec![key.to_vec()])
      .expect("nonempty App-Bound fixture"),
  };

  let outcome =
    acquire_chromium_draft(&outcomes, db, None, false).expect("v20 pipeline extraction");
  assert_eq!(outcome.cookies.len(), 1);
  assert_eq!(outcome.cookies[0].value, "decrypted v20");
  assert_ne!(
    outcome.cookies[0].value,
    "plaintext sentinel must not escape"
  );
}

#[test]
fn chromium_extraction_missing_db_errors() {
  let result = extract_cookies_with_legacy_keys(
    vec![],
    PathBuf::from("/nonexistent/cookies.db"),
    None,
    false,
  );
  assert!(
    result.is_err(),
    "expected Err for missing db, got {:?}",
    result
  );
}

#[test]
fn chromium_extraction_non_sqlite_file_errors() {
  let dir = unique_tmpdir("chr-bad-sqlite");
  let db = dir.join("Cookies");
  std::fs::write(&db, b"not a sqlite database at all").unwrap();
  let result = extract_cookies_with_legacy_keys(vec![], db, None, false);
  assert!(
    result.is_err(),
    "expected Err for bogus sqlite, got {:?}",
    result
  );
}

// This is intentionally native on Windows as well as Unix: an ordinary
// DB+WAL acquisition must succeed without consulting privilege, shadow-copy,
// or restart-manager fallbacks.
#[test]
fn chromium_extraction_reads_cookies_committed_to_an_active_wal() {
  // Self-cleaning, unlike `unique_tmpdir`; held to the end of the test.
  let dir = crate::utils::TempDir::new().expect("temp dir");
  let db = dir.path().join("Cookies");
  seed_chromium_cookies(
    &db,
    &[(
      ".example.com",
      "/",
      false,
      0,
      "checkpointed",
      "old",
      b"",
      false,
      0,
    )],
  );

  // Switch to WAL and keep the writer connected, so the second cookie stays
  // in the -wal the way it does while Chrome is running.
  let writer = rusqlite::Connection::open(&db).expect("open writable sqlite");
  let mode: String = writer
    .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
    .expect("enable WAL");
  assert_eq!(mode, "wal");
  writer
    .execute(
      "INSERT INTO cookies (host_key, path, is_secure, expires_utc, name, value, \
        encrypted_value, is_httponly, samesite) \
        VALUES ('.example.com', '/', 0, 0, 'in-wal', 'fresh', X'', 0, 0)",
      [],
    )
    .expect("insert WAL row");

  let mut cookies = extract_cookies_with_legacy_keys(vec![], db, None, false).expect("decode");

  cookies.sort_by(|a, b| a.name.cmp(&b.name));
  let names: Vec<_> = cookies.iter().map(|c| c.name.as_str()).collect();
  assert_eq!(names, vec!["checkpointed", "in-wal"], "{cookies:?}");
  let in_wal = cookies.iter().find(|c| c.name == "in-wal").expect("in-wal");
  assert_eq!(in_wal.value, "fresh");
}

#[test]
fn chromium_extraction_empty_table_returns_empty() {
  let dir = unique_tmpdir("chr-empty-table");
  let db = dir.join("Cookies");
  seed_chromium_cookies(&db, &[]);
  let cookies = extract_cookies_with_legacy_keys(vec![], db, None, false).expect("decode");
  assert!(cookies.is_empty(), "{:?}", cookies);
}

#[test]
fn chromium_extraction_errors_when_every_row_fails_to_decode() {
  let dir = unique_tmpdir("chr-all-rows-bad");
  let db = dir.join("Cookies");
  seed_chromium_cookies(&db, &[]);
  // The name is required identity data, so a row whose name cannot decode
  // must not turn a total extraction failure into an empty success.
  let conn = rusqlite::Connection::open(&db).expect("open writable sqlite");
  conn
    .execute(
      "INSERT INTO cookies (host_key, path, is_secure, expires_utc, name, value, \
        encrypted_value, is_httponly, samesite) \
        VALUES ('.example.com', '/', 1, 0, X'DEADBEEF', 'plain', X'', 1, 0)",
      [],
    )
    .expect("insert bad row");
  drop(conn);

  let outcome = query_outcome_with_legacy_keys(vec![], db.clone()).expect("source query");
  assert_eq!(outcome.stats.rows_seen, 1);
  assert_eq!(outcome.stats.cookies_emitted, 0);
  assert_eq!(outcome.stats.rows_skipped, 1);
  assert_eq!(outcome.issues.len(), 1);
  assert_eq!(
    outcome.issues[0].code,
    ChromiumRowIssueCode::ColumnRead("name")
  );
  let diagnostic = format!(
    "{:#}",
    outcome
      .legacy_error
      .as_ref()
      .expect("total row failure retains its diagnostic")
  );
  assert!(diagnostic.contains("ColumnRead(\"name\")"), "{diagnostic}");
  assert!(diagnostic.contains("row 1"), "{diagnostic}");

  let result = extract_cookies_with_legacy_keys(vec![], db, None, false);
  assert!(
    result.is_err(),
    "expected Err when no row decodes, got {:?}",
    result
  );
}

#[test]
fn chromium_extraction_emits_a_valid_empty_value() {
  let dir = unique_tmpdir("chr-valueless-plus-bad");
  let db = dir.join("Cookies");
  // An empty value is valid cookie data and must not disappear merely
  // because both the plaintext and encrypted storage columns are empty.
  seed_chromium_cookies(
    &db,
    &[(".example.com", "/", true, 0, "empty", "", b"", false, 0)],
  );
  let conn = rusqlite::Connection::open(&db).expect("open writable sqlite");
  conn
    .execute(
      "INSERT INTO cookies (host_key, path, is_secure, expires_utc, name, value, \
        encrypted_value, is_httponly, samesite) \
        VALUES ('.other.com', '/', 1, 0, X'DEADBEEF', 'plain', X'', 1, 0)",
      [],
    )
    .expect("insert bad row");
  drop(conn);

  let cookies = extract_cookies_with_legacy_keys(vec![], db, None, false)
    .expect("valueless row is not a failure");
  assert_eq!(cookies.len(), 1, "{cookies:?}");
  assert_eq!(cookies[0].name, "empty");
  assert_eq!(cookies[0].value, "");
}

#[test]
fn chromium_extraction_defaults_null_and_out_of_range_metadata() {
  let dir = unique_tmpdir("chr-null-metadata");
  let db = dir.join("Cookies");
  let connection = rusqlite::Connection::open(&db).expect("open writable sqlite");
  seed_chromium_schema_version(&connection, 23);
  connection
    .execute(
      "CREATE TABLE cookies (
        host_key TEXT,
        path TEXT,
        is_secure INTEGER,
        expires_utc INTEGER,
        name TEXT,
        value TEXT,
        encrypted_value BLOB,
        is_httponly INTEGER,
        samesite INTEGER
      )",
      [],
    )
    .expect("create table");
  connection
    .execute(
      "INSERT INTO cookies VALUES (NULL, NULL, NULL, -1, 'kept', 'value', NULL, NULL, NULL)",
      [],
    )
    .expect("insert cookie with missing metadata");
  connection
    .execute(
      "INSERT INTO cookies VALUES ('.example.com', '/', 0, 0, NULL, 'value', X'', 0, 0)",
      [],
    )
    .expect("insert cookie without name");
  connection
    .execute(
      "INSERT INTO cookies VALUES ('.example.com', '/', 0, 0, 'missing-value', NULL, X'', 0, 0)",
      [],
    )
    .expect("insert cookie without value");

  let outcomes = ChromiumKeyOutcomes::from_legacy_shared(vec![]);
  let extraction =
    decode_chromium_connection(&connection, &outcomes, None).expect("decode cookies");
  assert_eq!(extraction.cookies.len(), 1, "{:?}", extraction.cookies);
  let cookie = &extraction.cookies[0];
  assert_eq!(cookie.name, "kept");
  assert_eq!(cookie.value, "value");
  assert_eq!(cookie.domain, "");
  assert_eq!(cookie.path, "/");
  assert!(!cookie.secure);
  assert!(!cookie.http_only);
  assert_eq!(cookie.expires, None);
  assert_eq!(cookie.same_site, SAME_SITE_UNSPECIFIED);
  assert_eq!(extraction.stats.rows_seen, 3);
  assert_eq!(extraction.stats.cookies_emitted, 1);
  assert_eq!(extraction.stats.rows_skipped, 2);
}

#[test]
fn canonical_retains_malformed_booleans_while_legacy_skips_historically_unreadable_rows() {
  let dir = unique_tmpdir("chr-malformed-core-columns");
  let db = dir.join("Cookies");
  let connection = rusqlite::Connection::open(&db).expect("open writable sqlite");
  seed_chromium_schema_version(&connection, 23);
  connection
    .execute_batch(
      "CREATE TABLE cookies (
        host_key, path, is_secure, expires_utc, name, value,
        encrypted_value, is_httponly, samesite
      );
      INSERT INTO cookies VALUES
        ('.example.com', '/', 1, 0, 'good', 'value', X'', 1, 1),
        (X'FF', '/', 1, 0, 'bad-host', 'value', X'', 1, 1),
        ('.example.com', X'FF', 1, 0, 'bad-path', 'value', X'', 1, 1),
        ('.example.com', '/', X'FF', 0, 'bad-secure', 'value', X'', 1, 1),
        ('.example.com', '/', 1, X'FF', 'bad-expires', 'value', X'', 1, 1),
        ('.example.com', '/', 1, 0, X'FF', 'value', X'', 1, 1),
        ('.example.com', '/', 1, 0, 'bad-value', X'FF', X'', 1, 1),
        ('.example.com', '/', 1, 0, 'bad-http-only', 'value', X'', X'FF', 1),
        ('.example.com', '/', 1, 0, 'bad-same-site', 'value', X'', 1, X'FF');",
    )
    .expect("seed malformed core columns");

  let outcomes = ChromiumKeyOutcomes::from_legacy_shared(vec![]);
  let extraction =
    decode_chromium_connection(&connection, &outcomes, None).expect("decode cookies");
  assert_eq!(
    extraction.stats,
    ChromiumExtractionStats {
      rows_seen: 9,
      cookies_emitted: 3,
      rows_skipped: 6,
      rows_rejected: 6,
      provider_failures: 0,
    }
  );
  assert_eq!(
    extraction
      .cookies
      .iter()
      .map(|cookie| cookie.name.as_str())
      .collect::<Vec<_>>(),
    vec!["good", "bad-secure", "bad-http-only"]
  );
  assert!(matches!(
    extraction.records[1].attributes.secure,
    Observation::Unknown(RawValue::Bytes(_))
  ));
  assert!(matches!(
    extraction.records[2].attributes.http_only,
    Observation::Unknown(RawValue::Bytes(_))
  ));
  assert!(extraction.legacy_error.is_none());
  assert_eq!(
    extraction
      .issues
      .iter()
      .map(|issue| issue.code)
      .collect::<Vec<_>>(),
    vec![
      ChromiumRowIssueCode::ColumnRead("host_key"),
      ChromiumRowIssueCode::ColumnRead("path"),
      ChromiumRowIssueCode::ColumnRead("expires_utc"),
      ChromiumRowIssueCode::ColumnRead("name"),
      ChromiumRowIssueCode::ColumnRead("value"),
      ChromiumRowIssueCode::ColumnRead("samesite"),
    ]
  );
  let projected = project_legacy_draft(&db, extraction)
    .expect("legacy projection drops only historically unreadable boolean rows");
  assert_eq!(
    projected
      .iter()
      .map(|cookie| cookie.name.as_str())
      .collect::<Vec<_>>(),
    vec!["good"]
  );
}

#[test]
fn plaintext_value_failure_precedes_metadata_while_ciphertext_reaches_unseal() {
  let connection = rusqlite::Connection::open_in_memory().expect("open fixture");
  seed_chromium_schema_version(&connection, 23);
  connection
    .execute_batch(
      "CREATE TABLE cookies (
        host_key, path, is_secure, expires_utc, name, value,
        encrypted_value, is_httponly, samesite
      );
      INSERT INTO cookies VALUES
        ('.example.com', '/', 0, 0, 'plaintext-compound', X'FF', X'', X'FF', 0),
        ('.example.com', '/', 0, 0, 'ciphertext-compound', X'FF',
         X'76313073796E746865746963', X'FF', 0);",
    )
    .expect("seed compound column failures");

  let outcome = decode_chromium_connection(&connection, &ChromiumKeyOutcomes::default(), None)
    .expect("column failures remain row outcomes");
  assert_eq!(outcome.stats.rows_seen, 2);
  assert_eq!(outcome.stats.rows_skipped, 2);
  assert_eq!(
    outcome
      .issues
      .iter()
      .map(|issue| issue.code)
      .collect::<Vec<_>>(),
    vec![
      ChromiumRowIssueCode::ColumnRead("value"),
      ChromiumRowIssueCode::ProviderUnavailable,
    ],
    "plaintext reads value immediately, while ciphertext retains malformed metadata and reaches its authoritative unseal outcome"
  );
}

#[test]
fn chromium_extraction_returns_plaintext_value_when_value_is_set() {
  let dir = unique_tmpdir("chr-plaintext");
  let db = dir.join("Cookies");
  seed_chromium_cookies(
    &db,
    &[(
      ".example.com",
      "/",
      true,
      // chromium_timestamp wants microseconds since 1601-01-01.
      // 11_644_473_600_000_000 us == Unix epoch.
      11_644_473_600_000_000 + 1_700_000_000 * 1_000_000,
      "id",
      "plain",
      b"",
      true,
      1,
    )],
  );
  let cookies = extract_cookies_with_legacy_keys(vec![], db, None, false).expect("decode");
  assert_eq!(cookies.len(), 1, "{:?}", cookies);
  let c = &cookies[0];
  assert_eq!(c.domain, ".example.com");
  assert_eq!(c.name, "id");
  assert_eq!(c.value, "plain");
  assert!(c.http_only);
  assert!(c.secure);
  assert_eq!(c.same_site, 1);
  assert_eq!(c.expires, Some(1_700_000_000));
}

#[test]
fn chromium_schema_version_and_rows_come_from_the_acquired_wal_snapshot() {
  let dir = crate::utils::TempDir::new().expect("temp dir");
  let db = dir.path().join("Cookies");
  seed_chromium_cookies(
    &db,
    &[(
      ".example.com",
      "/",
      false,
      0,
      "snapshot",
      "old",
      b"",
      false,
      0,
    )],
  );

  let mut writer = rusqlite::Connection::open(&db).expect("open WAL writer");
  let mode: String = writer
    .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
    .expect("enable WAL");
  assert_eq!(mode, "wal");
  let transaction = writer.transaction().expect("begin WAL update");
  transaction
    .execute("UPDATE meta SET value = '24' WHERE key = 'version'", [])
    .expect("write version to WAL");
  transaction
    .execute(
      "UPDATE cookies SET value = 'new' WHERE name = 'snapshot'",
      [],
    )
    .expect("write cookie to WAL");
  transaction.commit().expect("commit WAL update");

  let acquired = sqlite::with_browser_database(db, |connection| {
    let version = chromium_schema_version(connection)?;
    let value = connection.query_row(
      "SELECT value FROM cookies WHERE name = 'snapshot'",
      [],
      |row| row.get::<_, String>(0),
    )?;
    Ok((version, value))
  })
  .expect("read acquired snapshot");

  assert_eq!(
    acquired.strategy(),
    sqlite::DatabaseAcquisitionStrategy::VerifiedWalSnapshot
  );
  assert_eq!(acquired.into_value(), (24, "new".to_string()));
}

#[test]
fn row_issue_aggregation_bounds_samples_without_losing_occurrences() {
  let mut outcome = ChromiumExtractionDraft::default();
  for row_number in 1..=MAX_CHROMIUM_ROW_ISSUE_SAMPLES + 3 {
    outcome.record_skipped_row(ChromiumRowIssueCode::Decode, row_number);
  }

  // Derived from the cap rather than hardcoded, so raising the bound cannot
  // leave the expectation describing a number the code no longer uses.
  let skipped = MAX_CHROMIUM_ROW_ISSUE_SAMPLES + 3;
  assert_eq!(outcome.stats.rows_skipped, skipped);
  assert_eq!(outcome.issues.len(), 1);
  assert_eq!(outcome.issues[0].occurrences, skipped);
  assert_eq!(
    outcome.issues[0].samples,
    (1..=MAX_CHROMIUM_ROW_ISSUE_SAMPLES)
      .map(|row| format!("row {row}"))
      .collect::<Vec<_>>()
  );
}

/// Name-column and value-column failures share one code, so the report merges
/// them. Qualifying each sample here is what keeps the lost column
/// recoverable from the merged issue.
#[test]
fn column_read_issues_name_their_column_in_every_sample() {
  let issue = row_issue(&ChromiumRowIssue {
    code: ChromiumRowIssueCode::ColumnRead("value"),
    provider: None,
    tier: None,
    cause: None,
    retryability: Retryability::Unknown,
    occurrences: 2,
    samples: vec!["row 1".to_owned(), "row 7".to_owned()],
  });
  assert_eq!(issue.code, "column_read_failed");
  assert_eq!(issue.message, "failed to read the value column of 2 row(s)");
  assert_eq!(
    issue.samples,
    ["value column, row 1", "value column, row 7"]
  );
}

/// The engine boundary is the only place that can name a cipher tier or a
/// credential provider, so it has to carry them across rather than leave the
/// report to re-derive what it cannot see.
#[test]
fn provider_failures_carry_their_evidence_across_the_engine_boundary() {
  let issue = row_issue(&ChromiumRowIssue {
    code: ChromiumRowIssueCode::ProviderFailed,
    provider: Some("platform_key_provider".to_owned()),
    tier: Some("v20".to_owned()),
    cause: Some("malformed App-Bound Local State".to_owned()),
    retryability: Retryability::NotRetryable,
    occurrences: 1,
    samples: vec!["row 1".to_owned()],
  });
  assert_eq!(issue.code, "provider_failed");
  assert_eq!(issue.tier.as_deref(), Some("v20"));
  assert_eq!(issue.provider.as_deref(), Some("platform_key_provider"));
  assert_eq!(issue.retryability.as_deref(), Some("not_retryable"));
  // The underlying cause replaces the generic count line, and the issue's own
  // `cause` names the class of failure instead.
  assert_eq!(issue.message, "malformed App-Bound Local State");
  assert_eq!(issue.cause.as_deref(), Some("credential_provider"));
}

/// A provider failure with no cause still has to say something countable.
#[test]
fn a_provider_failure_without_a_cause_falls_back_to_the_count_line() {
  let issue = row_issue(&ChromiumRowIssue {
    code: ChromiumRowIssueCode::ProviderUnavailable,
    provider: Some("platform_key_provider".to_owned()),
    tier: None,
    cause: None,
    retryability: Retryability::Unknown,
    occurrences: 3,
    samples: Vec::new(),
  });
  assert_eq!(
    issue.message,
    "3 row(s) unavailable because of provider_unavailable"
  );
}

/// Every code the compatibility skip count looks for must be one `row_issue`
/// actually emits. The count is a plain string match, so a rename that missed
/// one list would silently stop reporting those rows as skipped.
#[test]
fn the_unseal_issue_codes_are_the_ones_the_engine_emits() {
  let emitted = [
    ChromiumRowIssueCode::Decrypt,
    ChromiumRowIssueCode::Decode,
    ChromiumRowIssueCode::ProviderFailed,
    ChromiumRowIssueCode::ProviderUnavailable,
  ]
  .map(|code| {
    row_issue(&ChromiumRowIssue {
      code,
      provider: None,
      tier: None,
      cause: None,
      retryability: Retryability::Unknown,
      occurrences: 1,
      samples: Vec::new(),
    })
    .code
  });
  let mut emitted = emitted.to_vec();
  emitted.sort_unstable();
  let mut counted = CHROMIUM_UNSEAL_ISSUE_CODES.to_vec();
  counted.sort_unstable();
  assert_eq!(emitted, counted);
  assert!(
    !counted.contains(&"column_read_failed"),
    "a row that could not be read is not a row whose value could not be recovered"
  );
}

#[cfg(unix)]
#[test]
fn chromium_extraction_filters_by_domain() {
  let dir = unique_tmpdir("chr-domain-filter");
  let db = dir.join("Cookies");
  seed_chromium_cookies(
    &db,
    &[
      (".example.com", "/", false, 0, "keep", "yes", b"", false, 0),
      ("other.test", "/", false, 0, "drop", "no", b"", false, 0),
    ],
  );
  let mut cookies = extract_cookies_with_legacy_keys(
    vec![],
    db,
    Some(vec!["example.com".to_string(), "other.test".to_string()]),
    false,
  )
  .expect("decode");
  cookies.sort_by(|a, b| a.name.cmp(&b.name));
  let names: Vec<_> = cookies.iter().map(|c| c.name.as_str()).collect();
  assert_eq!(names, vec!["drop", "keep"], "{:?}", cookies);
}

#[test]
fn chromium_extraction_enforces_domain_boundaries_and_fail_closed_filters() {
  let dir = unique_tmpdir("chr-domain-filter-boundary");
  let db = dir.join("Cookies");
  seed_chromium_cookies(
    &db,
    &[
      ("example.com", "/", false, 0, "exact", "yes", b"", false, 0),
      (
        ".sub.example.com",
        "/",
        false,
        0,
        "subdomain",
        "yes",
        b"",
        false,
        0,
      ),
      (
        "example.com.",
        "/",
        false,
        0,
        "trailing-dot",
        "yes",
        b"",
        false,
        0,
      ),
      (
        "notexample.com",
        "/",
        false,
        0,
        "prefix",
        "no",
        b"",
        false,
        0,
      ),
      (
        "example.com.evil.net",
        "/",
        false,
        0,
        "suffix",
        "no",
        b"",
        false,
        0,
      ),
      (
        "other.test",
        "/",
        false,
        0,
        "unrelated",
        "no",
        b"",
        false,
        0,
      ),
    ],
  );

  let connection = rusqlite::Connection::open(&db).expect("open cookie database");
  connection
    .execute(
      "INSERT INTO cookies (host_key, path, is_secure, expires_utc, name, value, \
        encrypted_value, is_httponly, samesite) \
        VALUES ('notexample.com', '/', 0, 0, X'DEADBEEF', 'off-scope', X'', 0, 0)",
      [],
    )
    .expect("insert malformed off-scope candidate");
  let outcomes = ChromiumKeyOutcomes::from_legacy_shared(vec![]);
  let names = |outcome: &ChromiumExtractionDraft| {
    let mut names = outcome
      .cookies
      .iter()
      .map(|cookie| cookie.name.clone())
      .collect::<Vec<_>>();
    names.sort();
    names
  };

  let domains = vec!["example.com".to_string()];
  let outcome = decode_chromium_connection(&connection, &outcomes, Some(&domains))
    .expect("filter exact host and subdomains");
  assert_eq!(names(&outcome), vec!["exact", "subdomain", "trailing-dot"]);
  assert_eq!(outcome.stats.rows_seen, 3);
  assert_eq!(outcome.stats.rows_skipped, 0);
  assert_eq!(outcome.stats.cookies_emitted, 3);

  let dotted_domains = vec![".example.com.".to_string()];
  let dotted = decode_chromium_connection(&connection, &outcomes, Some(&dotted_domains))
    .expect("leading and trailing dots must not narrow the SQL candidate set");
  assert_eq!(names(&dotted), vec!["exact", "subdomain", "trailing-dot"]);

  let mixed_domains = vec!["".to_string(), "example.com".to_string()];
  let mixed = decode_chromium_connection(&connection, &outcomes, Some(&mixed_domains))
    .expect("a blank entry must not broaden a valid allowlist");
  assert_eq!(names(&mixed), vec!["exact", "subdomain", "trailing-dot"]);

  for invalid in ["", " \t ", ".", "%", "_"] {
    let domains = vec![invalid.to_string()];
    let outcome = decode_chromium_connection(&connection, &outcomes, Some(&domains))
      .expect("invalid filter must be a successful empty result");
    assert!(
      outcome.cookies.is_empty(),
      "filter {invalid:?} must not expose cookies: {:?}",
      outcome.cookies
    );
    assert_eq!(outcome.stats.rows_seen, 0, "filter {invalid:?}");
    assert_eq!(outcome.stats.rows_skipped, 0, "filter {invalid:?}");
  }

  let empty_domains = Vec::new();
  let empty = decode_chromium_connection(&connection, &outcomes, Some(&empty_domains))
    .expect("an explicit empty allowlist must validate the schema and match nothing");
  assert!(empty.cookies.is_empty());
  assert_eq!(empty.stats.rows_seen, 0);

  let empty_detailed = decode_chromium_connection_mode(
    &connection,
    &outcomes,
    Some(&empty_domains),
    CookieProjection::Detailed,
    EncryptedValuePolicy::UseKeyOutcomes,
  )
  .expect("a detailed empty allowlist must validate the schema and match nothing");
  assert!(empty_detailed.detailed_cookies.is_empty());
  assert_eq!(empty_detailed.stats.rows_seen, 0);

  let empty_database = rusqlite::Connection::open_in_memory().expect("open empty database");
  assert!(
    decode_chromium_connection(&empty_database, &outcomes, Some(&empty_domains)).is_err(),
    "a legacy empty allowlist must not bypass schema validation"
  );
  assert!(
    decode_chromium_connection_mode(
      &empty_database,
      &outcomes,
      Some(&empty_domains),
      CookieProjection::Detailed,
      EncryptedValuePolicy::UseKeyOutcomes,
    )
    .is_err(),
    "a detailed empty allowlist must not bypass schema validation"
  );

  let unfiltered =
    decode_chromium_connection(&connection, &outcomes, None).expect("unfiltered decode");
  assert_eq!(
    names(&unfiltered),
    vec![
      "exact",
      "prefix",
      "subdomain",
      "suffix",
      "trailing-dot",
      "unrelated"
    ]
  );
  assert_eq!(unfiltered.stats.rows_seen, 7);
  assert_eq!(unfiltered.stats.rows_skipped, 1);
}

#[cfg(unix)]
#[test]
fn chromium_extraction_domain_filter_treats_sql_as_data() {
  let dir = unique_tmpdir("chr-domain-filter-sql");
  let db = dir.join("Cookies");
  seed_chromium_cookies(
    &db,
    &[
      (
        ".example.com",
        "/",
        false,
        0,
        "first",
        "yes",
        b"x",
        false,
        0,
      ),
      ("other.test", "/", false, 0, "second", "no", b"x", false, 0),
    ],
  );

  let cookies =
    extract_cookies_with_legacy_keys(vec![], db, Some(vec!["' OR 1=1 --".to_string()]), false)
      .expect("decode");
  assert!(cookies.is_empty(), "{:?}", cookies);
}

#[test]
fn chromium_extraction_does_not_broaden_valid_domain_filter_with_sql_input() {
  let dir = unique_tmpdir("chr-domain-filter-scope");
  let db = dir.join("Cookies");
  seed_chromium_cookies(
    &db,
    &[
      (".example.com", "/", false, 0, "keep", "yes", b"", false, 0),
      ("other.test", "/", false, 0, "drop", "no", b"", false, 0),
    ],
  );

  let cookies = extract_cookies_with_legacy_keys(
    vec![],
    db,
    Some(vec!["example.com".to_string(), "') OR 1=1 --".to_string()]),
    false,
  )
  .expect("decode");
  let names: Vec<_> = cookies.iter().map(|cookie| cookie.name.as_str()).collect();
  assert_eq!(names, vec!["keep"], "{:?}", cookies);
}

#[test]
fn chromium_extraction_percent_domain_is_not_a_wildcard() {
  let dir = unique_tmpdir("chr-domain-filter-percent");
  let db = dir.join("Cookies");
  seed_chromium_cookies(
    &db,
    &[
      (".example.com", "/", false, 0, "keep", "yes", b"x", false, 0),
      ("other.test", "/", false, 0, "drop", "no", b"x", false, 0),
    ],
  );

  let cookies = extract_cookies_with_legacy_keys(vec![], db, Some(vec!["%".to_string()]), false)
    .expect("decode");
  assert!(
    cookies.is_empty(),
    "a literal '%' domain must not match every host: {:?}",
    cookies
  );
}

#[test]
fn chromium_extraction_underscore_domain_is_not_a_wildcard() {
  let dir = unique_tmpdir("chr-domain-filter-underscore");
  let db = dir.join("Cookies");
  seed_chromium_cookies(
    &db,
    &[
      (".example.com", "/", false, 0, "keep", "yes", b"x", false, 0),
      ("a.test", "/", false, 0, "drop", "no", b"x", false, 0),
    ],
  );

  let cookies = extract_cookies_with_legacy_keys(vec![], db, Some(vec!["_".to_string()]), false)
    .expect("decode");
  assert!(
    cookies.is_empty(),
    "a literal '_' domain must not match every single-character host: {:?}",
    cookies
  );
}

#[test]
fn query_outcome_tracks_row_stats_and_typed_issue_groups() {
  let dir = unique_tmpdir("chr-row-outcome");
  let db = dir.join("Cookies");
  seed_chromium_cookies(
    &db,
    &[(
      ".example.com",
      "/",
      false,
      0,
      "good",
      "plain",
      b"",
      false,
      0,
    )],
  );
  let conn = rusqlite::Connection::open(&db).expect("open writable sqlite");
  conn
    .execute(
      "INSERT INTO cookies VALUES ('.example.com', '/', 0, 0, X'DEADBEEF', 'plain', X'', 0, 0)",
      [],
    )
    .expect("insert malformed row");
  conn
    .execute(
      "INSERT INTO cookies VALUES ('.example.com', '/', 0, 0, 'bad-cipher', '', X'7631', 0, 0)",
      [],
    )
    .expect("insert malformed ciphertext");
  drop(conn);

  let outcome = query_outcome_with_legacy_keys(vec![], db).expect("source query");
  assert_eq!(
    outcome.stats,
    ChromiumExtractionStats {
      rows_seen: 3,
      cookies_emitted: 1,
      rows_skipped: 2,
      rows_rejected: 2,
      provider_failures: 0,
    }
  );
  assert_eq!(outcome.cookies[0].name, "good");
  assert!(outcome.legacy_error.is_none());
  assert_eq!(outcome.issues.len(), 2);
  assert_eq!(
    outcome.issues[0].code,
    ChromiumRowIssueCode::ColumnRead("name")
  );
  assert_eq!(outcome.issues[0].occurrences, 1);
  assert_eq!(outcome.issues[1].code, ChromiumRowIssueCode::Decrypt);
  assert_eq!(outcome.issues[1].occurrences, 1);
}

#[cfg(unix)]
#[test]
fn query_outcome_verifies_host_hashes_and_classifies_decode_failures() {
  let dir = unique_tmpdir("chr-host-hash-outcome");
  let db = dir.join("Cookies");
  let key = [0x42; 16];
  let good_plaintext = host_bound_plaintext(".example.com", b"verified value");
  let good_encrypted = encrypt_unix_cbc_cookie(b"v10", &key, &good_plaintext);
  let invalid_mismatch = b"this valid UTF-8 plaintext has a mismatched host hash".to_vec();
  let invalid_encrypted = encrypt_unix_cbc_cookie(b"v10", &key, &invalid_mismatch);
  seed_chromium_cookies(
    &db,
    &[
      (
        ".example.com",
        "/",
        false,
        0,
        "verified",
        "",
        &good_encrypted,
        false,
        0,
      ),
      (
        ".other.test",
        "/",
        false,
        0,
        "mismatch",
        "",
        &invalid_encrypted,
        false,
        0,
      ),
      (
        ".plain.test",
        "/",
        false,
        0,
        "plain",
        "fallback",
        b"",
        false,
        0,
      ),
    ],
  );
  let connection = rusqlite::Connection::open(&db).expect("open writable sqlite");
  connection
    .execute("UPDATE meta SET value = '24' WHERE key = 'version'", [])
    .expect("select strict host-hash schema");
  drop(connection);

  let mut outcome =
    query_outcome_with_legacy_keys(vec![key.to_vec()], db.clone()).expect("legacy source query");
  outcome
    .cookies
    .sort_by(|left, right| left.name.cmp(&right.name));
  assert_eq!(
    outcome.stats,
    ChromiumExtractionStats {
      rows_seen: 3,
      cookies_emitted: 2,
      rows_skipped: 1,
      rows_rejected: 1,
      provider_failures: 0,
    }
  );
  assert_eq!(
    outcome
      .cookies
      .iter()
      .map(|cookie| (cookie.name.as_str(), cookie.value.as_str()))
      .collect::<Vec<_>>(),
    vec![("plain", "fallback"), ("verified", "verified value")]
  );
  assert_eq!(outcome.issues.len(), 1);
  assert_eq!(outcome.issues[0].code, ChromiumRowIssueCode::Decode);
  assert_eq!(outcome.issues[0].occurrences, 1);

  let mut detailed = acquire_chromium_draft_mode(
    &ChromiumKeyOutcomes::from_legacy_shared(vec![key.to_vec()]),
    db,
    None,
    false,
    CookieProjection::Detailed,
    EncryptedValuePolicy::UseKeyOutcomes,
  )
  .expect("detailed source query");
  detailed
    .detailed_cookies
    .sort_by(|left, right| left.cookie.name.cmp(&right.cookie.name));
  assert_eq!(detailed.stats, outcome.stats);
  assert_eq!(detailed.issues, outcome.issues);
  assert_eq!(
    detailed
      .detailed_cookies
      .iter()
      .map(|record| (record.cookie.name.as_str(), record.cookie.value.as_str()))
      .collect::<Vec<_>>(),
    vec![("plain", "fallback"), ("verified", "verified value")]
  );
}

#[cfg(unix)]
#[test]
fn chromium_extraction_ignores_malformed_and_undecryptable_rows() {
  let dir = unique_tmpdir("chr-malformed-rows");
  let db = dir.join("Cookies");
  let conn = rusqlite::Connection::open(&db).expect("open writable sqlite");
  seed_chromium_schema_version(&conn, 23);
  conn
    .execute(
      "CREATE TABLE cookies (
        host_key TEXT NOT NULL,
        path TEXT NOT NULL,
        is_secure INTEGER NOT NULL,
        expires_utc INTEGER NOT NULL,
        name TEXT NOT NULL,
        value TEXT NOT NULL,
        encrypted_value BLOB,
        is_httponly INTEGER NOT NULL,
        samesite INTEGER NOT NULL
      )",
      [],
    )
    .expect("create table");

  // Row 1: Valid row
  conn
    .execute(
      "INSERT INTO cookies VALUES ('.example.com', '/', 1, 11644473600000000, 'valid1', 'val1', X'', 1, 1)",
      [],
    )
    .expect("insert row 1");

  // Row 2: Malformed required name column.
  conn
    .execute(
      "INSERT INTO cookies VALUES ('.example.com', '/', 1, -100, X'DEADBEEF', 'val', X'76313064756d6d79', 1, 1)",
      [],
    )
    .expect("insert row 2");

  // Row 3: Undecryptable row (encrypted_value starts with v10 but fails decryption)
  conn
    .execute(
      "INSERT INTO cookies VALUES ('.example.com', '/', 1, 11644473600000000, 'undecryptable', '', X'763130696e76616c6964', 1, 1)",
      [],
    )
    .expect("insert row 3");

  // Row 4: Valid row 2
  conn
    .execute(
      "INSERT INTO cookies VALUES ('.test.com', '/', 0, 11644473600000000, 'valid2', 'val2', X'', 0, 0)",
      [],
    )
    .expect("insert row 4");

  let mut cookies = extract_cookies_with_legacy_keys(vec![], db, None, false)
    .expect("Chromium extraction should succeed despite bad rows");
  cookies.sort_by(|a, b| a.name.cmp(&b.name));
  let names: Vec<_> = cookies.iter().map(|c| c.name.as_str()).collect();
  assert_eq!(names, vec!["valid1", "valid2"], "{:?}", cookies);
}
