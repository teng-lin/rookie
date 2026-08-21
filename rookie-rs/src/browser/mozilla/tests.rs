use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use lz4_flex::block::compress_prepend_size;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

struct TickClock {
  base: Instant,
  ticks: AtomicU64,
}

impl Default for TickClock {
  fn default() -> Self {
    Self {
      base: Instant::now(),
      ticks: AtomicU64::new(0),
    }
  }
}

impl Clock for TickClock {
  fn now(&self) -> Instant {
    self.base + Duration::from_secs(self.ticks.fetch_add(1, Ordering::SeqCst))
  }

  fn sleep(&self, _duration: Duration) {}
}

// Per-process unique temp paths without pulling in the `tempfile` dep.
// Each test gets its own subdirectory so they don't collide when run in
// parallel under `cargo test`.
fn unique_tmpdir(tag: &str) -> PathBuf {
  static COUNTER: AtomicU64 = AtomicU64::new(0);
  let n = COUNTER.fetch_add(1, Ordering::SeqCst);
  let dir = std::env::temp_dir().join(format!("rookie-test-{}-{}-{}", tag, std::process::id(), n));
  std::fs::create_dir_all(&dir).expect("temp dir");
  dir
}

#[test]
fn pure_mozilla_decoder_boundaries_are_platform_neutral() {
  fn assert_source<T: ReadOnlySource>() {}
  fn assert_persistent<T: Decoder<MozillaPersistentReadOnlySource<'static>, CookieRecord>>() {}
  fn assert_session<T: Decoder<MozillaSessionReadOnlySource<'static>, CookieRecord>>() {}
  assert_source::<MozillaPersistentReadOnlySource<'static>>();
  assert_source::<MozillaSessionReadOnlySource<'static>>();
  assert_persistent::<MozillaPersistentDecoder>();
  assert_session::<MozillaSessionDecoder>();
}

// (host, path, isSecure, expiry, name, value, isHttpOnly, sameSite)
type CookieRow<'a> = (&'a str, &'a str, bool, u64, &'a str, &'a str, bool, i64);

fn set_mozilla_schema_version(connection: &rusqlite::Connection, version: u32) {
  connection
    .pragma_update(None, "user_version", version)
    .expect("set Firefox schema version");
}

// Minimal moz_cookies fixture mirroring the columns firefox_based reads.
// Real Firefox schema has more columns, but rookie-cookies only selects these.
fn seed_moz_cookies(db: &Path, rows: &[CookieRow<'_>]) {
  let conn = rusqlite::Connection::open(db).expect("open writable sqlite");
  set_mozilla_schema_version(&conn, 15);
  conn
    .execute(
      "CREATE TABLE moz_cookies (
        host TEXT NOT NULL,
        path TEXT NOT NULL,
        isSecure INTEGER NOT NULL,
        expiry INTEGER NOT NULL,
        name TEXT NOT NULL,
        value TEXT NOT NULL,
        isHttpOnly INTEGER NOT NULL,
        sameSite INTEGER NOT NULL
      )",
      [],
    )
    .expect("create table");
  for r in rows {
    conn
      .execute(
        "INSERT INTO moz_cookies (host, path, isSecure, expiry, name, value, isHttpOnly, sameSite)
          VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![r.0, r.1, r.2, r.3, r.4, r.5, r.6, r.7],
      )
      .expect("insert row");
  }
}

#[test]
fn detailed_cookies_preserve_container_collisions() {
  let dir = unique_tmpdir("firefox-container-collision");
  let db = dir.join("cookies.sqlite");
  let connection = rusqlite::Connection::open(&db).expect("open fixture");
  connection
    .execute_batch(
      "CREATE TABLE moz_cookies (
        host TEXT NOT NULL, path TEXT NOT NULL, isSecure INTEGER NOT NULL,
        expiry INTEGER NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
        isHttpOnly INTEGER NOT NULL, sameSite INTEGER NOT NULL,
        originAttributes TEXT
      );
      INSERT INTO moz_cookies VALUES
        ('.example.com', '/', 1, 0, 'session', 'work', 1, 1,
         '^userContextId=2&partitionKey=%28https%2Cwork.example%29&privateBrowsingId=0'),
        ('.example.com', '/', 1, 0, 'session', 'personal', 1, 1,
         '^userContextId=1&partitionKey=%28https%2Cpersonal.example%29&privateBrowsingId=1');",
    )
    .expect("seed container cookies");
  drop(connection);

  let cookies = firefox_based_detailed(db, None).expect("extract detailed cookies");
  assert_eq!(cookies.len(), 2);
  assert_eq!(cookies[0].cookie.name, cookies[1].cookie.name);
  assert_eq!(cookies[0].cookie.domain, cookies[1].cookie.domain);
  assert_eq!(cookies[0].cookie.path, cookies[1].cookie.path);
  assert!(
    cookies
      .iter()
      .all(|cookie| cookie.context.top_frame_site_key.is_none()),
    "Firefox partitionKey must not populate Chromium top_frame_site_key"
  );
  let contexts = cookies
    .iter()
    .map(|cookie| {
      (
        cookie.cookie.value.as_str(),
        (
          cookie.context.user_context_id,
          cookie.context.partition_key.as_deref(),
          cookie.context.private_browsing_id,
        ),
      )
    })
    .collect::<std::collections::HashMap<_, _>>();
  assert_eq!(
    contexts.get("work"),
    Some(&(Some(2), Some("(https,work.example)"), Some(0)))
  );
  assert_eq!(
    contexts.get("personal"),
    Some(&(Some(1), Some("(https,personal.example)"), Some(1)))
  );
  assert!(cookies.iter().any(|cookie| {
    cookie.context.origin_attributes.as_deref()
      == Some("^userContextId=2&partitionKey=%28https%2Cwork.example%29&privateBrowsingId=0")
  }));
}

#[test]
fn detailed_query_keeps_legacy_firefox_schemas_readable() {
  let dir = unique_tmpdir("firefox-legacy-detailed-schema");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(
    &db,
    &[(".example.com", "/", false, 0, "legacy", "value", false, 0)],
  );

  let cookies =
    firefox_based_detailed(db, None).expect("missing originAttributes column remains compatible");
  assert_eq!(cookies.len(), 1);
  assert_eq!(cookies[0].context, CookieContext::default());
}

#[test]
fn malformed_origin_attributes_are_retained_as_unknown_metadata() {
  let dir = unique_tmpdir("firefox-malformed-detailed-context");
  let db = dir.join("cookies.sqlite");
  let connection = rusqlite::Connection::open(&db).expect("open fixture");
  connection
    .execute_batch(
      "CREATE TABLE moz_cookies (
        host TEXT, path TEXT, isSecure INTEGER, expiry INTEGER, name TEXT,
        value TEXT, isHttpOnly INTEGER, sameSite INTEGER, originAttributes BLOB
      );
      INSERT INTO moz_cookies VALUES
        ('.example.com', '/', 0, 0, 'legacy', 'value', 0, 0, X'FF');",
    )
    .expect("seed malformed context");
  drop(connection);

  let legacy = firefox_based(db.clone(), None).expect("legacy projection remains readable");
  assert_eq!(legacy.len(), 1);
  let detailed = firefox_based_detailed(db, None)
    .expect("canonical decoder retains an unrecognized optional value as typed raw metadata");
  assert_eq!(detailed.len(), 1);
  assert_eq!(detailed[0].context, CookieContext::default());
}

#[test]
fn malformed_origin_attributes_do_not_abort_or_drop_rows() {
  let dir = unique_tmpdir("firefox-mixed-detailed-context");
  let db = dir.join("cookies.sqlite");
  let connection = rusqlite::Connection::open(&db).expect("open fixture");
  connection
    .execute_batch(
      "CREATE TABLE moz_cookies (
        host TEXT, path TEXT, isSecure INTEGER, expiry INTEGER, name TEXT,
        value TEXT, isHttpOnly INTEGER, sameSite INTEGER, originAttributes BLOB
      );
      INSERT INTO moz_cookies VALUES
        ('.example.com', '/', 0, 0, 'before', 'first', 0, 0, '^userContextId=1'),
        ('.example.com', '/', 0, 0, 'malformed', 'discarded', 0, 0, X'FF'),
        ('.example.com', '/', 0, 0, 'after', 'last', 0, 0, '^userContextId=2');",
    )
    .expect("seed mixed origin attributes");
  drop(connection);

  let legacy = firefox_based(db.clone(), None).expect("legacy projection keeps every row");
  assert_eq!(legacy.len(), 3);

  let persistent = sqlite::with_browser_database(db.clone(), |connection| {
    query_persistent_cookies_mode(connection, None, true, &SystemClock, Deadline::standard())
  })
  .expect("query detailed rows")
  .into_value();
  assert_eq!(persistent.rows_seen, 3);
  assert_eq!(persistent.rows_skipped, 0);
  let detailed_cookies = persistent
    .records
    .iter()
    .cloned()
    .map(|record| record.into_detailed_cookie().unwrap())
    .collect::<Vec<_>>();
  assert_eq!(detailed_cookies.len(), 3);
  assert!(persistent.last_row_error.is_none());
  assert_eq!(
    detailed_cookies
      .iter()
      .map(|cookie| cookie.cookie.name.as_str())
      .collect::<Vec<_>>(),
    vec!["before", "malformed", "after"]
  );

  let public_result =
    firefox_based_detailed(db, None).expect("public detailed extraction returns the valid rows");
  assert_eq!(public_result.len(), 3);
}

fn write_session_jsonlz4(path: &Path, cookies: Value) {
  if let Some(parent) = path.parent() {
    std::fs::create_dir_all(parent).expect("create sessionstore directory");
  }
  let json = serde_json::json!({ "windows": [{ "tabs": [] }], "cookies": cookies }).to_string();
  let mut encoded = b"mozLz40\0".to_vec();
  encoded.extend(compress_prepend_size(json.as_bytes()));
  std::fs::write(path, encoded).expect("write sessionstore fixture");
}

fn write_session_value_jsonlz4(path: &Path, json: Value) {
  if let Some(parent) = path.parent() {
    std::fs::create_dir_all(parent).expect("create sessionstore directory");
  }
  let mut encoded = b"mozLz40\0".to_vec();
  encoded.extend(compress_prepend_size(json.to_string().as_bytes()));
  std::fs::write(path, encoded).expect("write sessionstore fixture");
}

fn write_captured_session_fixture(path: &Path, encoded: &str) -> Vec<u8> {
  if let Some(parent) = path.parent() {
    std::fs::create_dir_all(parent).expect("create captured fixture directory");
  }
  let bytes = STANDARD
    .decode(encoded.trim())
    .expect("decode captured Firefox fixture");
  std::fs::write(path, &bytes).expect("write captured Firefox fixture");
  bytes
}

fn session_cookie(name: &str) -> Value {
  serde_json::json!({
    "host": ".example.com",
    "path": "/",
    "name": name,
    "value": "fixture"
  })
}

#[test]
fn moz_lz4_rejects_u32_max_advertised_output_before_allocation() {
  let error = decompress_session_store(&u32::MAX.to_le_bytes())
    .expect_err("a corrupt size prefix must be rejected without allocating it");
  let message = format!("{error:#}");
  assert!(message.contains("4294967295"), "{message}");
  assert!(message.contains("maximum supported size"), "{message}");
}

#[test]
fn session_file_rejects_oversized_raw_input_before_reading_it() {
  let dir = unique_tmpdir("ff-oversized-session");
  let path = dir.join("sessionstore.jsonlz4");
  let file = std::fs::File::create(&path).expect("create sparse fixture");
  file
    .set_len(MAX_SESSION_STORE_BYTES as u64 + 1)
    .expect("extend sparse fixture");
  let error = read_stable_session_file(&path).expect_err("oversized source must fail");
  assert!(format!("{error:#}").contains("maximum supported size"));
}

#[test]
fn jsonlz4_and_legacy_share_one_walker_for_their_real_layouts() {
  let dir = unique_tmpdir("ff-shared-session-shape");
  let modern_state = serde_json::json!({
    "windows": [{ "tabs": [] }],
    "cookies": [session_cookie("first"), session_cookie("second")]
  });
  let legacy_state = serde_json::json!({
    "windows": [
      { "cookies": [session_cookie("first")] },
      { "tabs": [], "cookies": [session_cookie("second")] }
    ]
  });
  let lz4 = dir.join("state.jsonlz4");
  write_session_value_jsonlz4(&lz4, modern_state);
  let legacy = dir.join("sessionstore.js");
  std::fs::write(&legacy, legacy_state.to_string()).expect("write legacy state");
  for parsed in [
    parse_session_cookies_lz4(&lz4, None).expect("parse compressed Firefox window state"),
    parse_legacy_session_cookies(&legacy, None).expect("parse legacy Firefox window state"),
  ] {
    assert_eq!(parsed.rows_seen, 2);
    assert_eq!(
      parsed
        .cookies
        .iter()
        .map(|cookie| cookie.name.as_str())
        .collect::<Vec<_>>(),
      vec!["first", "second"]
    );
  }
}

#[test]
fn captured_firefox_141_session_uses_root_cookies_and_millisecond_expiry() {
  let dir = unique_tmpdir("firefox-141-captured-session");
  let path = dir.join("recovery.jsonlz4");
  let raw = write_captured_session_fixture(
    &path,
    include_str!("../fixtures/firefox-141.0-recovery.jsonlz4.base64"),
  );
  assert_eq!(raw.len(), 1_111);
  assert_eq!(
    format!("{:x}", Sha256::digest(&raw)),
    "359602096db47f6d54a0a1d454844abdb604df99c1b26973f22c9dda6ea8bc2d"
  );

  let parsed = parse_session_cookies_lz4(&path, None).expect("parse Firefox 141 capture");
  assert_eq!(parsed.rows_seen, 5);
  assert_eq!(parsed.rows_skipped, 0);
  assert_eq!(parsed.cookies.len(), 5);
  assert!(parsed
    .cookies
    .iter()
    .all(|cookie| cookie.expires == Some(1_786_763_509)));
  let mut user_context_ids = parsed
    .detailed_cookies
    .iter()
    .map(|cookie| {
      cookie
        .context
        .user_context_id
        .expect("captured container id")
    })
    .collect::<Vec<_>>();
  user_context_ids.sort_unstable();
  assert_eq!(user_context_ids, vec![0, 1, 2, 3, 4]);
}

#[test]
fn captured_firefox_142_session_uses_root_cookies_without_expiry() {
  let dir = unique_tmpdir("firefox-142-captured-session");
  let path = dir.join("recovery.jsonlz4");
  let raw = write_captured_session_fixture(
    &path,
    include_str!("../fixtures/firefox-142.0-recovery.jsonlz4.base64"),
  );
  assert_eq!(raw.len(), 1_091);
  assert_eq!(
    format!("{:x}", Sha256::digest(&raw)),
    "07e4925c9bb594204cafb652cf8f451eda09ad4877173767b81d5d4163434062"
  );

  let parsed = parse_session_cookies_lz4(&path, None).expect("parse Firefox 142 capture");
  assert_eq!(parsed.rows_seen, 5);
  assert_eq!(parsed.rows_skipped, 0);
  assert_eq!(parsed.cookies.len(), 5);
  assert!(parsed.cookies.iter().all(|cookie| cookie.expires.is_none()));
  let mut user_context_ids = parsed
    .detailed_cookies
    .iter()
    .map(|cookie| {
      cookie
        .context
        .user_context_id
        .expect("captured container id")
    })
    .collect::<Vec<_>>();
  user_context_ids.sort_unstable();
  assert_eq!(user_context_ids, vec![0, 1, 2, 3, 4]);
}

#[test]
fn jsonlz4_rejects_absent_or_ambiguous_cookie_structure() {
  let rootless = serde_json::json!({ "cookies": [session_cookie("missing-windows")] });
  assert!(parse_session_json(&rootless, None).is_err());
  assert!(parse_session_json(&serde_json::json!({ "windows": {} }), None).is_err());
  assert!(
    parse_session_json(&serde_json::json!({ "windows": [{ "cookies": {} }] }), None).is_err()
  );

  let cookie_free = serde_json::json!({ "windows": [{ "tabs": [] }] });
  let parsed = parse_session_json(&cookie_free, None).expect("cookie-free state is valid");
  assert!(parsed.cookies.is_empty());

  let ambiguous = serde_json::json!({
    "windows": [{ "cookies": [session_cookie("legacy")] }],
    "cookies": [session_cookie("ambiguous-top-level")]
  });
  assert!(parse_session_json(&ambiguous, None).is_err());
}

#[test]
fn session_expiry_classifier_preserves_seconds_converts_milliseconds_and_retains_gap() {
  let cookie = |expiry| serde_json::json!({ "expiry": expiry });
  assert!(matches!(
    session_cookie_expiry(&serde_json::json!({})).0,
    Observation::Missing
  ));
  assert!(matches!(
    session_cookie_expiry(&cookie(0)).0,
    Observation::Known(None)
  ));
  assert!(matches!(
    session_cookie_expiry(&cookie(1_800_000_000)).0,
    Observation::Known(Some(1_800_000_000))
  ));
  assert!(matches!(
    session_cookie_expiry(&cookie(1_800_000_000_999_u64)).0,
    Observation::Known(Some(1_800_000_000))
  ));
  assert!(matches!(
    session_cookie_expiry(&cookie(100_000_000_000_u64)).0,
    Observation::Unknown(RawValue::Unsigned(100_000_000_000))
  ));
}

#[test]
fn session_decoder_preserves_missing_and_unknown_optional_attributes() {
  let missing = create_cookie_record(&serde_json::json!({
    "host": ".example.test", "path": "/", "name": "missing", "value": "one"
  }))
  .expect("decode missing optional fields");
  assert!(matches!(missing.attributes.secure, Observation::Missing));
  assert!(matches!(missing.attributes.http_only, Observation::Missing));
  assert!(matches!(missing.attributes.same_site, Observation::Missing));
  assert!(matches!(missing.attributes.expires, Observation::Missing));

  let unknown = create_cookie_record(&serde_json::json!({
    "host": ".example.test", "path": "/", "name": "unknown", "value": "two",
    "secure": 2, "httponly": "sometimes", "sameSite": 9, "expiry": "later"
  }))
  .expect("retain unknown optional fields");
  assert!(matches!(
    unknown.attributes.secure,
    Observation::Unknown(RawValue::Signed(2))
  ));
  assert!(matches!(
    unknown.attributes.http_only,
    Observation::Unknown(RawValue::Text(_))
  ));
  assert!(matches!(
    unknown.attributes.same_site,
    Observation::Unknown(RawValue::Signed(9))
  ));
  assert!(matches!(
    unknown.attributes.expires,
    Observation::Unknown(RawValue::Text(_))
  ));
  let projected = unknown.into_cookie().unwrap();
  assert!(!projected.secure);
  assert!(!projected.http_only);
  assert_eq!(projected.expires, None);
}

#[test]
fn session_decoder_stages_records_and_stops_before_a_later_cookie() {
  const SENTINEL: &str = "rookie-mozilla-timeout-sentinel";
  let json = serde_json::json!({
    "windows": [],
    "cookies": [
      {"host": ".example.test", "name": "first", "value": SENTINEL},
      {"host": ".example.test", "name": "later", "value": "two"}
    ]
  });
  let clock = TickClock::default();
  let runtime = BoundaryRuntime::new(&clock, Deadline::after(&clock, Duration::from_secs(3)));
  let error = parse_session_json_with_runtime(&json, None, &runtime)
    .expect_err("second cookie begins at the deadline");
  assert_eq!(
    error.downcast_ref::<BoundaryStop>(),
    Some(&BoundaryStop::TimedOut)
  );
  assert!(!format!("{error:#}").contains(SENTINEL));
}

#[test]
fn candidate_cannot_report_success_after_its_final_deadline() {
  use crate::common::deadline::test_clock::ManualClock;

  let clock = ManualClock::default();
  let runtime = BoundaryRuntime::new(&clock, Deadline::after(&clock, Duration::from_secs(1)));
  let failure = parse_session_candidate_with_runtime(
    Path::new("recovery.jsonlz4"),
    || {
      clock.advance(Duration::from_secs(1));
      Ok(SessionCookieParseDraft {
        cookies: Vec::new(),
        detailed_cookies: Vec::new(),
        records: Vec::new(),
        rows_seen: 0,
        rows_skipped: 0,
        rows_rejected: 0,
        diagnostics: Vec::new(),
      })
    },
    &runtime,
  )
  .expect_err("final checkpoint must retain a typed timeout");
  assert_eq!(
    failure.error.downcast_ref::<BoundaryStop>(),
    Some(&BoundaryStop::TimedOut)
  );
  assert_eq!(failure.attempts, 1);
  assert!(failure.transient_errors.is_empty());
}

#[test]
fn persistent_decoder_preserves_non_boolean_sqlite_values() {
  let connection = rusqlite::Connection::open_in_memory().unwrap();
  connection
    .execute_batch(
      "CREATE TABLE moz_cookies (
         host TEXT, path TEXT, isSecure, expiry, name TEXT, value TEXT,
         isHttpOnly, sameSite, originAttributes
       );
       INSERT INTO moz_cookies VALUES
         ('.example.test', '/', 2, 1700000000, 'unknown', 'protected', -1, 9, 17),
         ('.example.test', NULL, NULL, NULL, 'missing', 'protected', NULL, NULL, NULL);",
    )
    .unwrap();
  let query = query_persistent_cookies(&connection, None).unwrap();
  assert_eq!(query.records.len(), 2);
  let unknown = &query.records[0];
  assert!(matches!(
    unknown.attributes.secure,
    Observation::Unknown(RawValue::Signed(2))
  ));
  assert!(matches!(
    unknown.attributes.http_only,
    Observation::Unknown(RawValue::Signed(-1))
  ));
  assert!(matches!(
    unknown.attributes.same_site,
    Observation::Unknown(RawValue::Signed(9))
  ));
  assert!(matches!(
    unknown.isolation.origin_attributes,
    Observation::Unknown(RawValue::Signed(17))
  ));
  let historical = unknown
    .clone()
    .into_cookie_with_semantics(
      crate::browser::cookie_record::LegacyProjectionSemantics::FirefoxPersistent,
    )
    .expect("project persistent compatibility booleans");
  assert!(historical.secure);
  assert!(historical.http_only);
  let session_semantics = unknown
    .clone()
    .into_cookie()
    .expect("project standard booleans");
  assert!(!session_semantics.secure);
  assert!(!session_semantics.http_only);
  let missing = &query.records[1];
  assert!(matches!(missing.attributes.secure, Observation::Missing));
  assert!(matches!(missing.attributes.http_only, Observation::Missing));
  assert!(matches!(missing.attributes.same_site, Observation::Missing));
  assert!(matches!(missing.attributes.expires, Observation::Missing));
  assert_eq!(unknown.origin.ordinal, 0);
  assert_eq!(missing.origin.ordinal, 1);
}

#[test]
fn detailed_session_cookies_preserve_object_origin_attribute_collisions() {
  let dir = unique_tmpdir("ff-session-origin-attribute-objects");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(&db, &[]);
  let cookies = serde_json::json!([
    {
      "host": ".example.com",
      "path": "/",
      "name": "session",
      "value": "work",
      "originAttributes": {
        "userContextId": 2,
        "partitionKey": "(https,work.example)",
        "privateBrowsingId": 0,
        "futureAttribute": "retained"
      }
    },
    {
      "host": ".example.com",
      "path": "/",
      "name": "session",
      "value": "personal",
      "originAttributes": {
        "userContextId": 1,
        "partitionKey": "(https,personal.example)",
        "privateBrowsingId": 1
      }
    }
  ]);
  write_session_jsonlz4(&dir.join("sessionstore-backups/recovery.jsonlz4"), cookies);

  let detailed = firefox_based_detailed(db, None).expect("extract detailed session cookies");
  assert_eq!(detailed.len(), 2);
  let contexts = detailed
    .iter()
    .map(|cookie| (cookie.cookie.value.as_str(), &cookie.context))
    .collect::<std::collections::HashMap<_, _>>();
  let work = contexts.get("work").expect("work container");
  assert_eq!(work.top_frame_site_key, None);
  assert_eq!(work.user_context_id, Some(2));
  assert_eq!(work.partition_key.as_deref(), Some("(https,work.example)"));
  assert_eq!(work.private_browsing_id, Some(0));
  let raw: Value = serde_json::from_str(
    work
      .origin_attributes
      .as_deref()
      .expect("raw session origin attributes"),
  )
  .expect("raw object remains JSON");
  assert_eq!(raw["futureAttribute"], "retained");

  let personal = contexts.get("personal").expect("personal container");
  assert_eq!(personal.top_frame_site_key, None);
  assert_eq!(personal.user_context_id, Some(1));
  assert_eq!(
    personal.partition_key.as_deref(),
    Some("(https,personal.example)")
  );
  assert_eq!(personal.private_browsing_id, Some(1));
}

#[test]
fn detailed_session_context_preserves_arbitrary_origin_attribute_json() {
  for origin_attributes in [
    serde_json::json!(["future", {"shape": true}]),
    serde_json::json!(42),
    serde_json::json!(false),
    Value::Null,
  ] {
    let context = firefox_session_cookie_context(Some(&origin_attributes));
    let raw = origin_attributes.to_string();
    assert_eq!(context.origin_attributes.as_deref(), Some(raw.as_str()));
    assert_eq!(context.user_context_id, None);
    assert_eq!(context.partition_key, None);
    assert_eq!(context.private_browsing_id, None);
  }
}

#[test]
fn firefox_based_errors_when_every_row_fails_to_decode() {
  let dir = unique_tmpdir("ff-all-rows-bad");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(&db, &[]);
  // The name is required identity data, so a row whose name cannot decode
  // must not turn a total extraction failure into an empty success.
  let conn = rusqlite::Connection::open(&db).expect("open writable sqlite");
  conn
    .execute(
      "INSERT INTO moz_cookies (host, path, isSecure, expiry, name, value, isHttpOnly, sameSite)
        VALUES ('.example.com', '/', 1, 0, X'DEADBEEF', 'v', 1, 0)",
      [],
    )
    .expect("insert bad row");
  drop(conn);

  let result = firefox_based(db, None);
  assert!(
    result.is_err(),
    "expected Err when no row decodes, got {:?}",
    result
  );
}

fn persistent_test_identity() -> SourceIdentity {
  SourceIdentity {
    path: PathBuf::from("cookies.sqlite"),
    role: CookieSourceRoleId::persistent(),
    format: CookieSourceFormatId::known(PERSISTENT_FORMAT_ID),
    precedence: PERSISTENT_SOURCE_PRECEDENCE,
  }
}

#[test]
fn a_rejected_persistent_row_is_not_projected_as_an_acquisition_retry() {
  let source = persistent_source(
    persistent_test_identity(),
    MozillaPersistentDraft {
      acquisition_attempts: 1,
      rows_seen: 2,
      rows_skipped: 1,
      rows_rejected: 1,
      row_error: Some("failed to read value from row: invalid utf-8".to_owned()),
      ..MozillaPersistentDraft::default()
    },
  );
  // A rejected row means cookies were lost. `diagnostics` renders as a
  // "retried, then succeeded" warning, so routing the row error there would
  // claim a recovery that never happened; it is raised as an error-severity
  // row failure instead, and the source itself is not failed.
  assert!(source.diagnostics.is_empty());
  assert!(source.failure.is_none());
  assert_eq!(source.stats.rows_skipped, 1);
  assert_eq!(source.stats.rows_rejected, 1);
  assert!(source
    .issues
    .iter()
    .any(|issue| issue.code == "row_read_failed"));
}

/// The report's `stage` is what a consumer reads to choose a remedy, so a
/// query that failed after the database opened must not be described as an
/// acquisition failure. The stage comes from the SQLite layer's typed kind;
/// flattening it to `Acquisition` used to pass the whole suite.
#[test]
fn a_persistent_failure_reports_the_stage_the_sqlite_layer_named() {
  let staged = |kind: Option<sqlite::BrowserDatabaseFailureKind>| {
    persistent_source(
      persistent_test_identity(),
      MozillaPersistentDraft {
        error: Some("boom".to_owned()),
        failure_kind: kind,
        ..MozillaPersistentDraft::default()
      },
    )
    .failure
    .expect("the source records its failure")
    .stage
  };

  assert_eq!(
    staged(Some(sqlite::BrowserDatabaseFailureKind::Query)),
    SourceFailureStage::Query
  );
  assert_eq!(
    staged(Some(sqlite::BrowserDatabaseFailureKind::Acquisition)),
    SourceFailureStage::Acquisition
  );
  // Untyped failures stay acquisition-stage: that is the conservative end of
  // the pipeline, not a claim that acquisition is what broke.
  assert_eq!(staged(None), SourceFailureStage::Acquisition);
}

/// A session candidate never keeps a row error, so an implementation that
/// raises `row_read_failed` only when one is present drops this issue
/// entirely -- and with it the report's degradation from `complete` to
/// `partial`, while cookies were in fact lost. The issue is keyed on the
/// skipped count for exactly that reason.
#[test]
fn a_session_candidate_that_skipped_rows_still_reports_a_row_issue() {
  let source = session_source(
    SourceIdentity {
      path: PathBuf::from("sessionstore.jsonlz4"),
      role: CookieSourceRoleId::session(),
      format: CookieSourceFormatId::known("mozilla_session_jsonlz4"),
      precedence: 30,
    },
    MozillaSessionDraft {
      selected: true,
      records: Vec::new(),
      rows_seen: 3,
      rows_skipped: 2,
      rows_rejected: 2,
      acquisition_attempts: 1,
      diagnostics: Vec::new(),
      error: None,
    },
  );
  assert!(
    source.failure.is_none(),
    "rejected rows do not fail the source"
  );
  let row_issue = source
    .issues
    .iter()
    .find(|issue| issue.code == "row_read_failed")
    .expect("skipped session rows must degrade the report");
  assert_eq!(row_issue.occurrences, 2);
  assert_eq!(
    row_issue.severity,
    crate::browser::report_core::IssueSeverityCode::error()
  );
}

#[test]
fn engine_outcome_counts_each_malformed_persistent_row() {
  let dir = unique_tmpdir("ff-engine-row-counts");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(
    &db,
    &[(".example.com", "/", false, 0, "kept", "value", false, 0)],
  );
  let conn = rusqlite::Connection::open(&db).expect("open writable sqlite");
  conn
    .execute(
      "INSERT INTO moz_cookies (host, path, isSecure, expiry, name, value, isHttpOnly, sameSite)
        VALUES ('.example.com', '/', 0, 0, X'DEADBEEF', 'discarded', 0, 0)",
      [],
    )
    .expect("insert malformed cookie");
  drop(conn);

  let outcome = acquire_mozilla_profile(&db, None);
  let persistent = &outcome.sources[0];
  assert_eq!(persistent.origin.role, CookieSourceRoleId::persistent());
  assert_eq!(persistent.stats.rows_seen, 2);
  assert_eq!(persistent.stats.rows_skipped, 1);
  assert_eq!(persistent.stats.rows_rejected, 1);
  assert_eq!(persistent.cookies().len(), 1);
  assert_eq!(
    persistent.acquisition,
    SourceAcquisition::Database(sqlite::DatabaseAcquisitionStrategy::LiveReadOnly)
  );
  assert_eq!(persistent.acquisition_attempts, 1);
  // A rejected row is a partial success: the source itself was readable and
  // returned its good cookies, so only the row-level issue is raised.
  assert!(persistent
    .issues
    .iter()
    .any(|issue| issue.code == "row_read_failed"));
  assert!(persistent.failure.is_none());
}

#[test]
fn persistent_optional_metadata_type_errors_are_retained_without_guessing() {
  let dir = unique_tmpdir("ff-persistent-metadata-types");
  let db = dir.join("cookies.sqlite");
  let connection = rusqlite::Connection::open(&db).expect("open fixture");
  connection
    .execute_batch(
      "CREATE TABLE moz_cookies (
        host, path, isSecure, expiry, name, value, isHttpOnly, sameSite
      );
      INSERT INTO moz_cookies VALUES (X'FF', '/', 0, 0, 'bad-host', 'v', 0, 0);
      INSERT INTO moz_cookies VALUES ('.example.com', X'FF', 0, 0, 'bad-path', 'v', 0, 0);
      INSERT INTO moz_cookies VALUES ('.example.com', '/', 'yes', 0, 'bad-secure', 'v', 0, 0);
      INSERT INTO moz_cookies VALUES ('.example.com', '/', 0, 'tomorrow', 'bad-expiry', 'v', 0, 0);
      INSERT INTO moz_cookies VALUES ('.example.com', '/', 0, 0, 'bad-http', 'v', 'yes', 0);
      INSERT INTO moz_cookies VALUES ('.example.com', '/', 0, 0, 'bad-site', 'v', 0, X'FF');
      INSERT INTO moz_cookies VALUES ('.example.com', '/', 0, 0, 'good', 'v', 0, 0);",
    )
    .expect("seed malformed metadata rows");
  drop(connection);

  let outcome = acquire_mozilla_profile(&db, None);
  let persistent = &outcome.sources[0];
  assert_eq!(persistent.stats.rows_seen, 7);
  assert_eq!(persistent.stats.rows_skipped, 1);
  assert_eq!(persistent.stats.rows_rejected, 1);
  assert_eq!(persistent.cookies().len(), 6);
  let find = |name: &str| {
    persistent
      .records
      .iter()
      .find(|record| record.name == name)
      .expect("retained optional metadata row")
  };
  assert!(matches!(
    find("bad-path").raw.get("path"),
    Some(RawValue::Bytes(_))
  ));
  assert!(matches!(
    find("bad-secure").attributes.secure,
    Observation::Unknown(RawValue::Text(_))
  ));
  assert!(matches!(
    find("bad-expiry").attributes.expires,
    Observation::Unknown(RawValue::Text(_))
  ));
  assert!(matches!(
    find("bad-http").attributes.http_only,
    Observation::Unknown(RawValue::Text(_))
  ));
  assert!(matches!(
    find("bad-site").attributes.same_site,
    Observation::Unknown(RawValue::Bytes(_))
  ));
  assert!(persistent
    .issues
    .iter()
    .any(|issue| issue.code == "row_read_failed"));
  assert!(persistent.failure.is_none());
}

#[test]
fn malformed_persistent_host_is_a_reported_total_row_failure() {
  let dir = unique_tmpdir("ff-persistent-host-type-total");
  let db = dir.join("cookies.sqlite");
  let connection = rusqlite::Connection::open(&db).expect("open fixture");
  connection
    .execute_batch(
      "CREATE TABLE moz_cookies (
        host, path, isSecure, expiry, name, value, isHttpOnly, sameSite
      );
      INSERT INTO moz_cookies VALUES (X'FF', '/', 0, 0, 'bad-host', 'v', 0, 0);",
    )
    .expect("seed malformed host");
  drop(connection);

  let outcome = acquire_mozilla_profile(&db, None);
  let persistent = &outcome.sources[0];
  assert_eq!(persistent.stats.rows_seen, 1);
  assert_eq!(persistent.stats.rows_skipped, 1);
  assert!(persistent.records.is_empty());
  // The row error is retained as the row_read_failed issue's message.
  assert!(persistent
    .issues
    .iter()
    .any(|issue| issue.code == "row_read_failed" && issue.message.contains("host")));
  let error = firefox_based(db, None).expect_err("all malformed rows must fail legacy extraction");
  assert!(format!("{error:#}").contains("host"));
}

#[test]
fn engine_outcome_separates_total_failure_from_a_rejected_row() {
  let dir = unique_tmpdir("ff-engine-total-failure");
  let db = dir.join("cookies.sqlite");
  std::fs::create_dir_all(&dir).expect("create profile dir");
  std::fs::write(&db, b"not a sqlite database").expect("write unreadable db");

  let outcome = acquire_mozilla_profile(&db, None);
  let persistent = &outcome.sources[0];
  assert!(persistent.failure.is_some());
  assert!(!persistent
    .issues
    .iter()
    .any(|issue| issue.code == "row_read_failed"));
  assert!(persistent.records.is_empty());
}

#[test]
fn persistent_failure_still_returns_selected_session_cookies() {
  let dir = unique_tmpdir("ff-persistent-failure-session-recovery");
  let db = dir.join("cookies.sqlite");
  std::fs::create_dir_all(&dir).expect("create profile dir");
  std::fs::write(&db, b"not a sqlite database").expect("write invalid database");
  let session = dir.join("sessionstore-backups/recovery.jsonlz4");
  write_session_jsonlz4(&session, serde_json::json!([session_cookie("recovered")]));

  let outcome = acquire_mozilla_profile(&db, None);
  assert!(outcome.sources[0].failure.is_some());
  assert!(outcome.sources[1..]
    .iter()
    .any(|source| source.selected && source.cookies().len() == 1));

  let cookies = firefox_based(db.clone(), None)
    .expect("a failed persistent source must not suppress a usable session source");
  assert_eq!(cookies.len(), 1);
  assert_eq!(cookies[0].name, "recovered");
  let detailed = firefox_based_detailed(db, None)
    .expect("detailed projection uses the same finalized engine outcome");
  assert_eq!(detailed.len(), 1);
  assert_eq!(detailed[0].cookie.name, "recovered");
}

#[test]
fn completed_persistent_source_retains_a_stop_observed_after_the_final_session_probe() {
  use crate::common::deadline::{test_clock::ManualClock, CancellationToken, Deadline};

  for stop in [
    BoundaryStop::TimedOut,
    BoundaryStop::Cancelled,
    BoundaryStop::ResourceExhausted,
  ] {
    let dir = unique_tmpdir("ff-final-session-probe-stop");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(
      &db,
      &[(
        ".example.com",
        "/",
        false,
        0,
        "persistent",
        "kept",
        false,
        0,
      )],
    );
    let clock = ManualClock::default();
    let token = CancellationToken::default();
    let runtime = BoundaryRuntime::with_stop(
      &clock,
      Deadline::after(&clock, Duration::from_secs(10)),
      token.clone(),
    );
    let mut probes = 0;

    let outcome = acquire_mozilla_profile_with_session_probe(&db, None, &runtime, |_, _, _, _| {
      probes += 1;
      if probes == SESSION_CANDIDATES.len() {
        match stop {
          BoundaryStop::TimedOut => clock.advance(Duration::from_secs(10)),
          BoundaryStop::Cancelled => assert!(token.cancel()),
          BoundaryStop::ResourceExhausted => assert!(token.exhaust_resources()),
        }
      }
      Err(SessionCandidateFailure {
        error: std::io::Error::from(std::io::ErrorKind::NotFound).into(),
        attempts: 1,
        transient_errors: Vec::new(),
      })
    });

    assert_eq!(probes, SESSION_CANDIDATES.len());
    assert_eq!(outcome.boundary_stop, Some(stop));
    // The persistent source was attempted and completed, so it is the one
    // source; every probed session candidate was missing and stays silent.
    assert_eq!(outcome.sources.len(), 1);
    assert_eq!(
      outcome.sources[0].origin.role,
      CookieSourceRoleId::persistent()
    );
    assert_eq!(outcome.sources[0].records.len(), 1);
  }
}

/// First-valid selection means later candidates are never *acquired*, not
/// merely never *emitted*. Emission is invisible to a probe that still runs,
/// so this counts probes: once a candidate succeeds, no further candidate may
/// be touched. An implementation that keeps walking and discards the extra
/// results passes every emission assertion while doing forbidden reads.
#[test]
fn a_successful_session_candidate_stops_the_walk_from_probing_later_ones() {
  let dir = unique_tmpdir("ff-first-valid-stops-probing");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(&db, &[]);
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);

  let mut probed = Vec::new();
  let outcome = acquire_mozilla_profile_with_session_probe(&db, None, &runtime, |path, _, _, _| {
    probed.push(path.to_path_buf());
    // The first candidate succeeds; a correct walk must not reach any other.
    Ok(SessionCandidateSuccess {
      parsed: SessionCookieParseDraft {
        #[cfg(test)]
        cookies: Vec::new(),
        #[cfg(test)]
        detailed_cookies: Vec::new(),
        records: Vec::new(),
        rows_seen: 0,
        rows_skipped: 0,
        rows_rejected: 0,
        diagnostics: Vec::new(),
      },
      attempts: 1,
      transient_errors: Vec::new(),
    })
  });

  let first = dir.join(SESSION_CANDIDATES[0].0);
  assert_eq!(
    probed,
    vec![first],
    "only the first candidate may be acquired"
  );
  assert_eq!(
    outcome
      .sources
      .iter()
      .filter(|source| source.selected && source.origin.role == CookieSourceRoleId::session())
      .count(),
    1
  );
}

#[test]
fn engine_outcome_retains_invalid_session_candidates_and_selects_first_valid_one() {
  let dir = unique_tmpdir("ff-engine-session-outcomes");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(&db, &[]);
  let invalid = dir.join("sessionstore-backups/recovery.jsonlz4");
  std::fs::create_dir_all(invalid.parent().expect("session parent")).expect("create parent");
  std::fs::write(&invalid, b"not a compressed session store").expect("write invalid session");
  let selected = dir.join("sessionstore-backups/recovery.baklz4");
  write_session_jsonlz4(&selected, serde_json::json!([session_cookie("recovered")]));

  let outcome = acquire_mozilla_profile(&db, None);
  let sessions = &outcome.sources[1..];
  assert_eq!(sessions.len(), 2);
  assert_eq!(sessions[0].origin.path, invalid);
  assert_eq!(
    sessions[0].origin.format.as_str(),
    "firefox_session_jsonlz4"
  );
  assert!(!sessions[0].selected);
  assert!(sessions[0].failure.is_some());
  assert_eq!(sessions[1].origin.path, selected);
  assert_eq!(
    sessions[1].origin.format.as_str(),
    "firefox_session_jsonlz4"
  );
  assert!(sessions[1].selected);
  assert_eq!(sessions[1].cookies()[0].name, "recovered");
  assert_eq!(
    sessions.iter().filter(|source| source.selected).count(),
    1,
    "first-valid selection admits exactly one selected session source"
  );
}

#[test]
fn engine_outcome_retains_every_existing_session_candidate_when_all_fail() {
  let dir = unique_tmpdir("ff-engine-all-session-failures");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(&db, &[]);
  for (relative, _) in SESSION_CANDIDATES {
    let path = dir.join(relative);
    if let Some(parent) = path.parent() {
      std::fs::create_dir_all(parent).expect("create session directory");
    }
    std::fs::write(path, b"invalid session candidate").expect("write invalid candidate");
  }

  let outcome = acquire_mozilla_profile(&db, None);
  let sessions = &outcome.sources[1..];
  assert_eq!(sessions.len(), SESSION_CANDIDATES.len());
  assert!(sessions.iter().all(|source| !source.selected));
  assert!(sessions.iter().all(|source| source.failure.is_some()));
  // Failed candidates stay in declared order, by declared precedence.
  assert!(sessions
    .windows(2)
    .all(|pair| pair[0].origin.precedence < pair[1].origin.precedence));
}

#[test]
fn legacy_extraction_preserves_persistent_cookies_when_every_session_candidate_fails() {
  let dir = unique_tmpdir("ff-legacy-all-session-failures");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(
    &db,
    &[(
      ".example.com",
      "/",
      false,
      0,
      "persistent",
      "still-present",
      false,
      0,
    )],
  );
  for (relative, _) in SESSION_CANDIDATES {
    let path = dir.join(relative);
    if let Some(parent) = path.parent() {
      std::fs::create_dir_all(parent).expect("create session directory");
    }
    std::fs::write(path, b"invalid session candidate").expect("write invalid candidate");
  }

  let cookies = firefox_based(db.clone(), None)
    .expect("persistent cookies remain usable when every session store fails");
  assert_eq!(cookies.len(), 1);
  assert_eq!(cookies[0].name, "persistent");

  let cookies = firefox_based_detailed(db, None)
    .expect("detailed persistent cookies remain usable when every session store fails");
  assert_eq!(cookies.len(), 1);
  assert_eq!(cookies[0].cookie.name, "persistent");
}

#[test]
fn legacy_extraction_signals_all_session_failure_without_persistent_cookies() {
  let dir = unique_tmpdir("ff-legacy-only-session-failures");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(&db, &[]);
  for (relative, _) in SESSION_CANDIDATES {
    let path = dir.join(relative);
    if let Some(parent) = path.parent() {
      std::fs::create_dir_all(parent).expect("create session directory");
    }
    std::fs::write(path, b"invalid session candidate").expect("write invalid candidate");
  }

  let error = firefox_based(db.clone(), None)
    .expect_err("total session-store failure without persistent cookies must be signaled");
  assert!(format!("{error:#}").contains("all existing Firefox session store candidates failed"));
  let error = firefox_based_detailed(db, None)
    .expect_err("detailed extraction must signal total session-store failure");
  assert!(format!("{error:#}").contains("all existing Firefox session store candidates failed"));
}

#[test]
fn ambiguous_session_expiry_is_retained_as_unknown_metadata() {
  let dir = unique_tmpdir("ff-session-expiry-scale-diagnostic");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(&db, &[]);
  let with_expiry = |name: &str, expiry: u64| {
    serde_json::json!({
      "host": ".example.com", "path": "/", "name": name,
      "value": "fixture", "expiry": expiry
    })
  };
  write_session_jsonlz4(
    &dir.join("sessionstore-backups/recovery.jsonlz4"),
    serde_json::json!([
      with_expiry("session", 0),
      with_expiry("seconds", 1_800_000_000),
      with_expiry("milliseconds", 1_800_000_000_999_u64),
      with_expiry("ambiguous", 100_000_000_000_u64)
    ]),
  );

  let outcome = acquire_mozilla_profile(&db, None);
  let source = &outcome.sources[1];
  assert!(source.selected);
  assert_eq!(source.stats.rows_seen, 4);
  assert_eq!(source.stats.rows_skipped, 0);
  assert_eq!(source.stats.rows_rejected, 0);
  let cookies = source.cookies();
  assert_eq!(cookies.len(), 4);
  assert_eq!(cookies[0].expires, None);
  assert_eq!(cookies[1].expires, Some(1_800_000_000));
  assert_eq!(cookies[2].expires, Some(1_800_000_000));
  assert_eq!(cookies[3].expires, None);
  assert!(source.diagnostics.is_empty());
  assert!(matches!(
    source.records[3].attributes.expires,
    Observation::Unknown(RawValue::Unsigned(100_000_000_000))
  ));
}

#[test]
fn engine_outcome_counts_and_bounds_malformed_session_cookies() {
  let dir = unique_tmpdir("ff-engine-session-row-counts");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(&db, &[]);
  let malformed = (0..MAX_SESSION_COOKIE_DIAGNOSTICS + 3)
    .map(|index| {
      serde_json::json!({
        "host": ".example.com",
        "path": "/",
        "name": format!("missing-value-{index}")
      })
    })
    .collect::<Vec<_>>();
  write_session_jsonlz4(
    &dir.join("sessionstore-backups/recovery.jsonlz4"),
    serde_json::Value::Array(malformed),
  );

  let outcome = acquire_mozilla_profile(&db, None);
  let source = &outcome.sources[1];
  assert!(source.selected);
  assert_eq!(source.stats.rows_seen, MAX_SESSION_COOKIE_DIAGNOSTICS + 3);
  assert_eq!(
    source.stats.rows_skipped,
    MAX_SESSION_COOKIE_DIAGNOSTICS + 3
  );
  assert_eq!(
    source.stats.rows_rejected,
    MAX_SESSION_COOKIE_DIAGNOSTICS + 3
  );
  assert!(source.records.is_empty());
  assert_eq!(source.diagnostics.len(), MAX_SESSION_COOKIE_DIAGNOSTICS);
  assert!(source.diagnostics[0].contains("cookies[0]"));
  assert!(source.diagnostics[0].contains("has no value"));
}

#[test]
fn engine_outcome_labels_legacy_json_and_counts_malformed_rows() {
  let dir = unique_tmpdir("ff-engine-legacy-row-counts");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(&db, &[]);
  std::fs::write(
    dir.join("sessionstore.js"),
    r#"{"windows":[{"cookies":[{"host":".example.com","name":"bad"},{"host":".example.com","name":"good","value":"v"}]}]}"#,
  )
  .expect("write legacy session store");

  let outcome = acquire_mozilla_profile(&db, None);
  let source = &outcome.sources[1];
  assert_eq!(source.origin.format.as_str(), "firefox_session_json");
  assert_eq!(source.stats.rows_seen, 2);
  assert_eq!(source.stats.rows_skipped, 1);
  assert_eq!(source.stats.rows_rejected, 1);
  assert_eq!(source.cookies().len(), 1);
  assert_eq!(source.diagnostics.len(), 1);
}

#[test]
fn legacy_json_row_diagnostics_are_bounded_like_the_lz4_path() {
  let dir = unique_tmpdir("ff-engine-legacy-diagnostic-bound");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(&db, &[]);
  let malformed = (0..MAX_SESSION_COOKIE_DIAGNOSTICS + 3)
    .map(|index| format!(r#"{{"host":".example.com","name":"bad-{index}"}}"#))
    .collect::<Vec<_>>()
    .join(",");
  std::fs::write(
    dir.join("sessionstore.js"),
    format!(r#"{{"windows":[{{"cookies":[{malformed}]}}]}}"#),
  )
  .expect("write legacy session store");

  let outcome = acquire_mozilla_profile(&db, None);
  let source = &outcome.sources[1];
  assert_eq!(source.origin.format.as_str(), SESSION_JSON_FORMAT_ID);
  assert_eq!(source.stats.rows_seen, MAX_SESSION_COOKIE_DIAGNOSTICS + 3);
  assert_eq!(
    source.stats.rows_skipped,
    MAX_SESSION_COOKIE_DIAGNOSTICS + 3
  );
  assert!(source.records.is_empty());
  assert_eq!(source.diagnostics.len(), MAX_SESSION_COOKIE_DIAGNOSTICS);
}

#[test]
fn failed_session_candidate_retains_its_retry_diagnostics() {
  let dir = unique_tmpdir("ff-engine-failed-retry-diagnostics");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(&db, &[]);
  std::fs::create_dir_all(dir.join("sessionstore-backups")).expect("create session dir");
  std::fs::write(
    dir.join("sessionstore-backups/recovery.jsonlz4"),
    b"not a valid lz4 session store",
  )
  .expect("write invalid session candidate");

  let outcome = acquire_mozilla_profile(&db, None);
  let source = &outcome.sources[1];
  assert!(!source.selected);
  assert!(source.failure.is_some());
  assert_eq!(
    source.acquisition_attempts,
    SESSION_STORE_READ_ATTEMPTS as u32
  );
  // Every attempt before the last one is retained; the final failure is the
  // source failure rather than a duplicate diagnostic.
  assert_eq!(source.diagnostics.len(), SESSION_STORE_READ_ATTEMPTS - 1);
  assert!(source.diagnostics[0].contains("attempt 1"));
}

#[test]
fn failure_attempt_counts_reflect_early_exits_not_the_retry_ceiling() {
  // Every *reported* failure exhausts the retry budget, so an outcome's
  // attempt count can never distinguish these. Pin them at the struct level
  // instead, where the early-exit paths are observable.
  let missing_immediately = parse_session_candidate_with(Path::new("recovery.jsonlz4"), || {
    Err(std::io::Error::from(std::io::ErrorKind::NotFound).into())
  })
  .expect_err("a missing candidate fails");
  // The discriminating case: stopping on the first attempt must report one
  // attempt, not the SESSION_STORE_READ_ATTEMPTS ceiling.
  assert_eq!(missing_immediately.attempts, 1);
  assert!(missing_immediately.transient_errors.is_empty());

  let mut attempts = 0;
  let vanished_after_retry = parse_session_candidate_with(Path::new("recovery.jsonlz4"), || {
    attempts += 1;
    if attempts == 1 {
      bail!("Firefox session store changed while it was being read")
    }
    Err(std::io::Error::from(std::io::ErrorKind::NotFound).into())
  })
  .expect_err("a vanished candidate fails");
  assert!(is_missing_session_file(&vanished_after_retry.error));
  assert_eq!(vanished_after_retry.attempts, 2);
  // The attempt-1 diagnostic survives on the failure path, even though
  // Section 7 means nothing downstream consumes it for a vanished candidate.
  assert_eq!(vanished_after_retry.transient_errors.len(), 1);
  assert!(vanished_after_retry.transient_errors[0].contains("attempt 1"));
}

#[test]
fn a_candidate_that_vanishes_after_a_transient_failure_stays_silent() {
  // The deliberate counterpart of the test above: Section 7 keeps a missing
  // candidate silent, so nothing about it reaches the outcome.
  let dir = unique_tmpdir("ff-engine-vanished-candidate");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(&db, &[]);

  let outcome = acquire_mozilla_profile(&db, None);
  assert_eq!(outcome.sources.len(), 1, "the persistent source only");
  assert_eq!(
    outcome.sources[0].origin.role,
    CookieSourceRoleId::persistent()
  );
}

#[test]
fn successful_session_retry_retains_attempt_and_transient_diagnostic() {
  let mut attempts = 0;
  let success = parse_session_candidate_with(Path::new("recovery.jsonlz4"), || {
    attempts += 1;
    if attempts == 1 {
      bail!("Firefox session store changed while it was being read")
    }
    Ok(SessionCookieParseDraft {
      cookies: Vec::new(),
      detailed_cookies: Vec::new(),
      records: Vec::new(),
      rows_seen: 0,
      rows_skipped: 0,
      rows_rejected: 0,
      diagnostics: Vec::new(),
    })
  })
  .expect("second attempt succeeds");

  assert_eq!(success.attempts, 2);
  assert_eq!(success.transient_errors.len(), 1);
  assert!(success.transient_errors[0].contains("attempt 1"));
  assert!(success.transient_errors[0].contains("changed while it was being read"));
}

#[test]
fn engine_outcome_keeps_missing_session_candidates_silent() {
  let dir = unique_tmpdir("ff-engine-missing-session");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(&db, &[]);

  let outcome = acquire_mozilla_profile(&db, None);
  assert_eq!(outcome.sources.len(), 1, "the persistent source only");
  assert_eq!(
    outcome.sources[0].origin.role,
    CookieSourceRoleId::persistent()
  );
  assert!(outcome.sources[0].failure.is_none());
}

#[test]
fn firefox_based_defaults_null_and_out_of_range_metadata() {
  let dir = unique_tmpdir("ff-null-metadata");
  let db = dir.join("cookies.sqlite");
  let conn = rusqlite::Connection::open(&db).expect("open writable sqlite");
  conn
    .execute(
      "CREATE TABLE moz_cookies (
        host TEXT,
        path TEXT,
        isSecure INTEGER,
        expiry INTEGER,
        name TEXT,
        value TEXT,
        isHttpOnly INTEGER,
        sameSite INTEGER
      )",
      [],
    )
    .expect("create table");
  conn
    .execute(
      "INSERT INTO moz_cookies VALUES ('.example.com', NULL, NULL, -1, 'kept', 'value', NULL, NULL)",
      [],
    )
    .expect("insert cookie with missing metadata");
  conn
    .execute(
      "INSERT INTO moz_cookies VALUES ('.example.com', '/', 0, 0, NULL, 'value', 0, 0)",
      [],
    )
    .expect("insert cookie without name");
  conn
    .execute(
      "INSERT INTO moz_cookies VALUES ('.example.com', '/', 0, 0, 'missing-value', NULL, 0, 0)",
      [],
    )
    .expect("insert cookie without value");
  drop(conn);

  let cookies = firefox_based(db, None).expect("metadata defaults keep usable cookie");
  assert_eq!(cookies.len(), 1, "{cookies:?}");
  let cookie = &cookies[0];
  assert_eq!(cookie.name, "kept");
  assert_eq!(cookie.value, "value");
  assert_eq!(cookie.domain, ".example.com");
  assert_eq!(cookie.path, "/");
  assert!(!cookie.secure);
  assert!(!cookie.http_only);
  assert_eq!(cookie.expires, None);
  assert_eq!(cookie.same_site, SAME_SITE_UNSPECIFIED);
}

#[test]
fn firefox_based_reads_clean_shutdown_sessionstore() {
  let dir = unique_tmpdir("ff-clean-sessionstore");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(&db, &[]);
  write_session_jsonlz4(
    &dir.join("sessionstore.jsonlz4"),
    serde_json::json!([session_cookie("clean-shutdown")]),
  );

  let cookies = firefox_based(db, None).expect("read clean-shutdown session state");
  assert_eq!(cookies.len(), 1, "{cookies:?}");
  assert_eq!(cookies[0].name, "clean-shutdown");
}

#[test]
fn firefox_sessionstore_uses_first_valid_candidate_without_merging_stale_state() {
  let dir = unique_tmpdir("ff-sessionstore-precedence");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(&db, &[]);
  let recovery = dir.join("sessionstore-backups/recovery.jsonlz4");
  let recovery_backup = dir.join("sessionstore-backups/recovery.baklz4");
  let clean = dir.join("sessionstore.jsonlz4");
  let previous = dir.join("sessionstore-backups/previous.jsonlz4");
  write_session_jsonlz4(
    &recovery,
    serde_json::json!([session_cookie("live-recovery")]),
  );
  write_session_jsonlz4(
    &recovery_backup,
    serde_json::json!([session_cookie("live-recovery-backup")]),
  );
  write_session_jsonlz4(
    &clean,
    serde_json::json!([session_cookie("clean-shutdown")]),
  );
  write_session_jsonlz4(
    &previous,
    serde_json::json!([session_cookie("stale-previous")]),
  );

  let cookies = firefox_based(db.clone(), None).expect("read live recovery");
  assert_eq!(cookies.len(), 1, "session candidates must not be merged");
  assert_eq!(cookies[0].name, "live-recovery");

  std::fs::write(&recovery, b"mozLz40\0invalid").expect("corrupt recovery fixture");
  let cookies = firefox_based(db.clone(), None).expect("fall back to recovery backup");
  assert_eq!(
    cookies.len(),
    1,
    "older lifecycle tiers must remain unselected"
  );
  assert_eq!(cookies[0].name, "live-recovery-backup");

  std::fs::write(&recovery_backup, b"mozLz40\0invalid").expect("corrupt recovery backup fixture");
  let cookies = firefox_based(db.clone(), None).expect("fall back to clean shutdown");
  assert_eq!(cookies.len(), 1, "stale state must remain unselected");
  assert_eq!(cookies[0].name, "clean-shutdown");

  std::fs::write(&clean, b"mozLz40\0invalid").expect("corrupt clean fixture");
  let cookies = firefox_based(db, None).expect("fall back to previous session");
  assert_eq!(cookies.len(), 1);
  assert_eq!(cookies[0].name, "stale-previous");
}

#[test]
fn valid_empty_recovery_does_not_resurrect_stale_session_cookies() {
  let dir = unique_tmpdir("ff-sessionstore-empty-current");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(&db, &[]);
  write_session_jsonlz4(
    &dir.join("sessionstore-backups/recovery.jsonlz4"),
    serde_json::json!([]),
  );
  write_session_jsonlz4(
    &dir.join("sessionstore.jsonlz4"),
    serde_json::json!([session_cookie("stale-clean-copy")]),
  );

  let cookies = firefox_based(db, None).expect("valid empty state is authoritative");
  assert!(cookies.is_empty(), "{cookies:?}");
}

#[test]
fn firefox_based_reads_seeded_cookies() {
  let dir = unique_tmpdir("ff-happy");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(
    &db,
    &[
      (
        ".example.com",
        "/",
        false,
        1_700_000_000,
        "id",
        "abc",
        true,
        1,
      ),
      ("foo.test", "/path", true, 0, "tok", "xyz", false, 2),
    ],
  );

  let cookies = firefox_based(db, None).expect("decode");
  assert_eq!(cookies.len(), 2, "{:?}", cookies);

  let id = cookies.iter().find(|c| c.name == "id").expect("id");
  assert_eq!(id.domain, ".example.com");
  assert_eq!(id.value, "abc");
  assert!(id.http_only);
  assert!(!id.secure);
  assert_eq!(id.same_site, 1);
  // mozilla_timestamp passes seconds through and maps 0 to None.
  assert_eq!(id.expires, Some(1_700_000_000));

  let tok = cookies.iter().find(|c| c.name == "tok").expect("tok");
  assert_eq!(tok.domain, "foo.test");
  assert!(tok.secure);
  assert!(!tok.http_only);
  assert_eq!(tok.same_site, 2);
  assert_eq!(tok.expires, None, "expiry=0 should map to None");
}

#[test]
fn persistent_expiry_uses_seconds_before_schema_16_and_milliseconds_after() {
  let old_dir = unique_tmpdir("ff-expiry-seconds-schema");
  let old_db = old_dir.join("cookies.sqlite");
  seed_moz_cookies(
    &old_db,
    &[(
      ".example.com",
      "/",
      false,
      1_700_000_000,
      "old",
      "seconds",
      false,
      0,
    )],
  );

  let new_dir = unique_tmpdir("ff-expiry-milliseconds-schema");
  let new_db = new_dir.join("cookies.sqlite");
  seed_moz_cookies(
    &new_db,
    &[(
      ".example.com",
      "/",
      false,
      1_700_000_000_999,
      "new",
      "milliseconds",
      false,
      0,
    )],
  );
  let connection = rusqlite::Connection::open(&new_db).expect("open writable sqlite");
  set_mozilla_schema_version(&connection, 16);
  drop(connection);

  let old = firefox_based(old_db.clone(), None).expect("read seconds-era profile");
  let new = firefox_based(new_db.clone(), None).expect("read milliseconds-era profile");
  assert_eq!(old[0].expires, Some(1_700_000_000));
  assert_eq!(new[0].expires, Some(1_700_000_000));

  let old_detailed =
    firefox_based_detailed(old_db, None).expect("read detailed seconds-era profile");
  let new_detailed =
    firefox_based_detailed(new_db, None).expect("read detailed milliseconds-era profile");
  assert_eq!(old_detailed[0].cookie.expires, Some(1_700_000_000));
  assert_eq!(new_detailed[0].cookie.expires, Some(1_700_000_000));
}

#[test]
fn schema_16_conversion_is_confined_to_persistent_cookies() {
  let dir = unique_tmpdir("ff-persistent-only-expiry-conversion");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(
    &db,
    &[(
      ".example.com",
      "/",
      false,
      1_700_000_000_999,
      "persistent",
      "milliseconds",
      false,
      0,
    )],
  );
  let connection = rusqlite::Connection::open(&db).expect("open writable sqlite");
  set_mozilla_schema_version(&connection, 16);
  drop(connection);
  write_session_jsonlz4(
    &dir.join("sessionstore-backups/recovery.jsonlz4"),
    serde_json::json!([{
      "host": ".example.com",
      "path": "/",
      "name": "sessionstore",
      "value": "legacy-seconds",
      "expiry": 1_800_000_000_u64
    }]),
  );

  let mut cookies = firefox_based(db.clone(), None).expect("read persistent and session cookies");
  cookies.sort_by(|left, right| left.name.cmp(&right.name));
  assert_eq!(cookies[0].name, "persistent");
  assert_eq!(cookies[0].expires, Some(1_700_000_000));
  assert_eq!(cookies[1].name, "sessionstore");
  // Sessionstore has no cookies.sqlite schema marker. Preserve its existing
  // legacy-seconds interpretation rather than applying the DB conversion.
  assert_eq!(cookies[1].value, "legacy-seconds");
  assert_eq!(cookies[1].expires, Some(1_800_000_000));

  let mut detailed =
    firefox_based_detailed(db, None).expect("read detailed persistent and session cookies");
  detailed.sort_by(|left, right| left.cookie.name.cmp(&right.cookie.name));
  assert_eq!(detailed[0].cookie.name, "persistent");
  assert_eq!(detailed[0].cookie.expires, Some(1_700_000_000));
  assert_eq!(detailed[1].cookie.name, "sessionstore");
  assert_eq!(detailed[1].cookie.value, "legacy-seconds");
  assert_eq!(detailed[1].cookie.expires, Some(1_800_000_000));
}

#[test]
fn firefox_schema_version_and_rows_come_from_the_acquired_wal_snapshot() {
  // Self-cleaning, unlike `unique_tmpdir`; held to the end of the test.
  let dir = crate::utils::TempDir::new().expect("temp dir");
  let db = dir.path().join("cookies.sqlite");
  seed_moz_cookies(
    &db,
    &[(
      ".example.com",
      "/",
      false,
      0,
      "checkpointed",
      "old",
      false,
      0,
    )],
  );

  // Switch the database to WAL and keep the writer connected, so the second
  // cookie stays in the -wal the way it does while Firefox is running.
  let mut writer = rusqlite::Connection::open(&db).expect("open writable sqlite");
  let mode: String = writer
    .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
    .expect("enable WAL");
  assert_eq!(mode, "wal");
  let transaction = writer.transaction().expect("begin WAL update");
  set_mozilla_schema_version(&transaction, 16);
  transaction
    .execute(
      "UPDATE moz_cookies SET expiry = 1700000000000 WHERE name = 'checkpointed'",
      [],
    )
    .expect("migrate checkpointed expiry to milliseconds");
  transaction
    .execute(
      "INSERT INTO moz_cookies (host, path, isSecure, expiry, name, value, isHttpOnly, sameSite)
        VALUES ('.example.com', '/', 0, 1800000000999, 'in-wal', 'fresh', 0, 0)",
      [],
    )
    .expect("insert WAL row");
  transaction.commit().expect("commit schema and row update");

  let mut cookies = firefox_based(db.clone(), None).expect("decode");

  cookies.sort_by(|a, b| a.name.cmp(&b.name));
  let names: Vec<_> = cookies.iter().map(|c| c.name.as_str()).collect();
  assert_eq!(names, vec!["checkpointed", "in-wal"], "{cookies:?}");
  let in_wal = cookies.iter().find(|c| c.name == "in-wal").expect("in-wal");
  assert_eq!(
    in_wal.value, "fresh",
    "the WAL row must decode, not just appear"
  );
  assert_eq!(in_wal.expires, Some(1_800_000_000));
  let checkpointed = cookies
    .iter()
    .find(|cookie| cookie.name == "checkpointed")
    .expect("checkpointed");
  assert_eq!(checkpointed.expires, Some(1_700_000_000));

  let outcome = acquire_mozilla_profile(&db, None);
  let persistent = &outcome.sources[0];
  assert_eq!(
    persistent.acquisition,
    SourceAcquisition::Database(sqlite::DatabaseAcquisitionStrategy::VerifiedWalSnapshot)
  );
  assert_eq!(persistent.acquisition_attempts, 1);
  assert_eq!(persistent.records.len(), 2);
}

#[test]
fn firefox_based_filters_by_domain() {
  let dir = unique_tmpdir("ff-domain-filter");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(
    &db,
    &[
      (".example.com", "/", false, 0, "keep", "yes", false, 0),
      ("other.test", "/", false, 0, "drop", "no", false, 0),
    ],
  );

  let mut cookies = firefox_based(
    db,
    Some(vec!["example.com".to_string(), "other.test".to_string()]),
  )
  .expect("decode");
  cookies.sort_by(|a, b| a.name.cmp(&b.name));
  let names: Vec<_> = cookies.iter().map(|c| c.name.as_str()).collect();
  assert_eq!(names, vec!["drop", "keep"], "{:?}", cookies);
}

#[test]
fn firefox_based_enforces_consistent_domain_boundaries_and_fail_closed_filters() {
  let dir = unique_tmpdir("ff-domain-filter-boundary");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(
    &db,
    &[
      ("example.com", "/", false, 0, "p-exact", "yes", false, 0),
      (
        ".sub.example.com",
        "/",
        false,
        0,
        "p-subdomain",
        "yes",
        false,
        0,
      ),
      (
        "example.com.",
        "/",
        false,
        0,
        "p-trailing-dot",
        "yes",
        false,
        0,
      ),
      ("notexample.com", "/", false, 0, "p-prefix", "no", false, 0),
      (
        "example.com.evil.net",
        "/",
        false,
        0,
        "p-suffix",
        "no",
        false,
        0,
      ),
      ("other.test", "/", false, 0, "p-unrelated", "no", false, 0),
    ],
  );

  let session_cookie = |host: &str, name: &str| {
    serde_json::json!({
      "host": host,
      "path": "/",
      "name": name,
      "value": "fixture"
    })
  };
  let session = serde_json::json!({
    "windows": [{
      "cookies": [
        session_cookie("example.com", "s-exact"),
        session_cookie(".sub.example.com", "s-subdomain"),
        session_cookie("example.com.", "s-trailing-dot"),
        session_cookie("notexample.com", "s-prefix"),
        session_cookie("example.com.evil.net", "s-suffix"),
        session_cookie("other.test", "s-unrelated")
      ]
    }]
  });
  std::fs::write(dir.join("sessionstore.js"), session.to_string()).expect("session fixture");

  let mut cookies =
    firefox_based(db.clone(), Some(vec!["example.com".to_string()])).expect("decode");
  cookies.sort_by(|a, b| a.name.cmp(&b.name));
  let names = cookies
    .iter()
    .map(|cookie| cookie.name.as_str())
    .collect::<Vec<_>>();
  assert_eq!(
    names,
    vec![
      "p-exact",
      "p-subdomain",
      "p-trailing-dot",
      "s-exact",
      "s-subdomain",
      "s-trailing-dot"
    ],
    "persistent and session cookies must use the same host boundary"
  );

  let connection = rusqlite::Connection::open(&db).expect("open cookie database");
  connection
    .execute(
      "INSERT INTO moz_cookies (host, path, isSecure, expiry, name, value, isHttpOnly, sameSite)
        VALUES ('notexample.com', '/', 0, 0, X'DEADBEEF', 'off-scope', 0, 0)",
      [],
    )
    .expect("insert malformed off-scope candidate");
  let dotted_domains = vec![".example.com.".to_string()];
  let dotted = query_persistent_cookies(&connection, Some(&dotted_domains))
    .expect("leading and trailing dots must not narrow the SQL candidate set");
  let mut dotted_names = dotted
    .records
    .iter()
    .map(|record| record.name.as_str())
    .collect::<Vec<_>>();
  dotted_names.sort_unstable();
  assert_eq!(
    dotted_names,
    vec!["p-exact", "p-subdomain", "p-trailing-dot"]
  );
  assert_eq!(dotted.rows_seen, 3);
  assert_eq!(dotted.rows_skipped, 0);

  let mixed_domains = vec!["".to_string(), "example.com".to_string()];
  let mixed = query_persistent_cookies(&connection, Some(&mixed_domains))
    .expect("a blank entry must not broaden a valid allowlist");
  let mut mixed_names = mixed
    .records
    .iter()
    .map(|record| record.name.as_str())
    .collect::<Vec<_>>();
  mixed_names.sort_unstable();
  assert_eq!(
    mixed_names,
    vec!["p-exact", "p-subdomain", "p-trailing-dot"]
  );

  let empty_domains = Vec::new();
  let empty_database = rusqlite::Connection::open_in_memory().expect("open empty database");
  assert!(
    query_persistent_cookies(&empty_database, Some(&empty_domains)).is_err(),
    "an empty allowlist must not bypass schema validation"
  );

  drop(connection);
  for invalid in ["", " \t ", ".", "%", "_"] {
    let cookies = firefox_based(db.clone(), Some(vec![invalid.to_string()]))
      .expect("invalid filter must be a successful empty result");
    assert!(
      cookies.is_empty(),
      "filter {invalid:?} must not expose persistent or session cookies: {cookies:?}"
    );
  }

  let empty = firefox_based(db.clone(), Some(Vec::new()))
    .expect("an explicit empty allowlist must validate sources and match nothing");
  assert!(empty.is_empty());

  let unfiltered = firefox_based(db, None).expect("unfiltered query");
  assert_eq!(unfiltered.len(), 12);
}

#[test]
fn firefox_based_domain_filter_treats_sql_as_data() {
  let dir = unique_tmpdir("ff-domain-filter-sql");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(
    &db,
    &[
      (".example.com", "/", false, 0, "first", "yes", false, 0),
      ("other.test", "/", false, 0, "second", "no", false, 0),
    ],
  );

  let cookies = firefox_based(db, Some(vec!["' OR 1=1 --".to_string()])).expect("decode");
  assert!(cookies.is_empty(), "{:?}", cookies);
}

#[test]
fn firefox_based_does_not_broaden_valid_domain_filter_with_sql_input() {
  let dir = unique_tmpdir("ff-domain-filter-scope");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(
    &db,
    &[
      (".example.com", "/", false, 0, "keep", "yes", false, 0),
      ("other.test", "/", false, 0, "drop", "no", false, 0),
    ],
  );

  let cookies = firefox_based(
    db,
    Some(vec!["example.com".to_string(), "') OR 1=1 --".to_string()]),
  )
  .expect("decode");
  let names: Vec<_> = cookies.iter().map(|cookie| cookie.name.as_str()).collect();
  assert_eq!(names, vec!["keep"], "{:?}", cookies);
}

#[test]
fn firefox_based_percent_domain_is_not_a_wildcard() {
  let dir = unique_tmpdir("ff-domain-filter-percent");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(
    &db,
    &[
      (".example.com", "/", false, 0, "keep", "yes", false, 0),
      ("other.test", "/", false, 0, "drop", "no", false, 0),
    ],
  );

  let cookies = firefox_based(db, Some(vec!["%".to_string()])).expect("decode");
  assert!(
    cookies.is_empty(),
    "a literal '%' domain must not match every host: {:?}",
    cookies
  );
}

#[test]
fn firefox_based_underscore_domain_is_not_a_wildcard() {
  let dir = unique_tmpdir("ff-domain-filter-underscore");
  let db = dir.join("cookies.sqlite");
  seed_moz_cookies(
    &db,
    &[
      (".example.com", "/", false, 0, "keep", "yes", false, 0),
      ("a.test", "/", false, 0, "drop", "no", false, 0),
    ],
  );

  let cookies = firefox_based(db, Some(vec!["_".to_string()])).expect("decode");
  assert!(
    cookies.is_empty(),
    "a literal '_' domain must not match every single-character host: {:?}",
    cookies
  );
}

#[test]
fn firefox_based_missing_db_errors() {
  let result = firefox_based(PathBuf::from("/nonexistent/rookie/cookies.sqlite"), None);
  assert!(
    result.is_err(),
    "expected Err for missing db, got {:?}",
    result
  );
}

#[test]
fn firefox_based_non_sqlite_file_errors() {
  let dir = unique_tmpdir("ff-bad-sqlite");
  let db = dir.join("cookies.sqlite");
  std::fs::write(&db, b"this is not a sqlite database").unwrap();
  let result = firefox_based(db, None);
  assert!(
    result.is_err(),
    "expected Err for bogus sqlite, got {:?}",
    result
  );
}

#[test]
fn get_session_cookies_missing_file_errors() {
  let dir = unique_tmpdir("ff-no-sessionstore");
  // sessionstore.js doesn't exist under this dir.
  let result = get_session_cookies(None, dir);
  assert!(result.is_err(), "expected Err for missing sessionstore");
}

#[test]
fn get_session_cookies_invalid_json_errors() {
  let dir = unique_tmpdir("ff-bad-sessionstore");
  std::fs::write(dir.join("sessionstore.js"), b"{not valid json").unwrap();
  let result = get_session_cookies(None, dir);
  assert!(result.is_err(), "expected Err for invalid json");
}

#[test]
fn get_session_cookies_json_without_windows_errors() {
  let dir = unique_tmpdir("ff-no-windows");
  // Valid JSON, but missing the `windows` key the parser requires.
  std::fs::write(dir.join("sessionstore.js"), b"{\"other\": []}").unwrap();
  let err = get_session_cookies(None, dir).expect_err("should fail");
  assert!(
    err.to_string().contains("has no windows array"),
    "unexpected error: {}",
    err
  );
}

#[test]
fn get_session_cookies_requires_a_domain_label_boundary() {
  let dir = unique_tmpdir("ff-session-domain-boundary");
  let cookie = |host: &str, name: &str| {
    serde_json::json!({
      "host": host,
      "path": "/",
      "name": name,
      "value": "fixture"
    })
  };
  let session = serde_json::json!({
    "windows": [{
      "cookies": [
        cookie(".example.com", "boundary"),
        cookie("sub.example.com", "subdomain"),
        cookie("notexample.com", "prefix"),
        cookie("example.com.evil", "suffix")
      ]
    }]
  });
  std::fs::write(dir.join("sessionstore.js"), session.to_string()).expect("session fixture");

  let mut cookies =
    get_session_cookies(Some(vec!["example.com".to_string()]), dir).expect("decode");
  cookies.sort_by(|a, b| a.name.cmp(&b.name));
  let names: Vec<_> = cookies.iter().map(|cookie| cookie.name.as_str()).collect();
  assert_eq!(names, vec!["boundary", "subdomain"]);
}

#[test]
fn get_session_cookies_lz4_missing_file_errors() {
  let dir = unique_tmpdir("ff-no-lz4");
  // sessionstore-backups/recovery.jsonlz4 doesn't exist.
  let result = get_session_cookies_lz4(None, dir);
  assert!(result.is_err(), "expected Err for missing lz4");
}

#[test]
fn get_session_cookies_lz4_corrupt_payload_errors() {
  let dir = unique_tmpdir("ff-bad-lz4");
  let backups = dir.join("sessionstore-backups");
  std::fs::create_dir_all(&backups).unwrap();
  // Need at least 8 bytes (the 8-byte mozLz40\0 magic is stripped before
  // lz4 decompress) plus garbage; the lz4 step should reject this.
  std::fs::write(
    backups.join("recovery.jsonlz4"),
    b"mozLz40\0this-is-not-actually-lz4-compressed",
  )
  .unwrap();
  let result = get_session_cookies_lz4(None, dir);
  assert!(result.is_err(), "expected Err for corrupt lz4");
}

#[test]
fn list_profiles_missing_ini_errors() {
  let result = list_profiles(Path::new("/nonexistent/profiles.ini"));
  assert!(result.is_err(), "expected Err for missing profiles.ini");
}

#[test]
fn list_profiles_empty_ini_yields_no_profiles() {
  let dir = unique_tmpdir("ff-empty-ini");
  let ini_path = dir.join("profiles.ini");
  std::fs::File::create(&ini_path)
    .unwrap()
    .write_all(b"")
    .unwrap();
  assert!(list_profiles(&ini_path).expect("should list").is_empty());
}

#[test]
fn default_profile_prefers_install_block() {
  let ini_path = write_ini(
    "ff-install-ini",
    "[Install4F96D1932A9F858E]\nDefault=Profiles/abc.default-release\n\
     [Profile0]\nName=default\nIsRelative=1\nPath=Profiles/abc.default-release\nDefault=1\n",
  );
  assert_eq!(
    default_profile_path(&ini_path),
    Some("Profiles/abc.default-release".to_string())
  );
}

#[test]
fn default_profile_falls_back_to_default_flag() {
  // No [Install...] block, so the resolver should walk Profiles and pick
  // the one with Default=1.
  let ini_path = write_ini(
    "ff-default-flag-ini",
    "[Profile0]\nName=other\nIsRelative=1\nPath=Profiles/other\nDefault=0\n\
     [Profile1]\nName=default\nIsRelative=1\nPath=Profiles/abc.default-release\nDefault=1\n",
  );
  assert_eq!(
    default_profile_path(&ini_path),
    Some("Profiles/abc.default-release".to_string())
  );
}

fn write_ini(tag: &str, body: &str) -> PathBuf {
  let ini_path = unique_tmpdir(tag).join("profiles.ini");
  std::fs::write(&ini_path, body).unwrap();
  ini_path
}

/// The resolved default profile's path, relative to the ini's directory where
/// possible, so assertions read like the `Path=` values in the fixture. A
/// profile resolved outside that directory is reported in full rather than
/// panicking.
fn default_profile_path(ini_path: &Path) -> Option<String> {
  let base = ini_path.parent().expect("ini has a parent");
  list_profiles(ini_path)
    .expect("should list")
    .into_iter()
    .find(|profile| profile.is_default)
    .map(|profile| {
      profile
        .path
        .strip_prefix(base)
        .unwrap_or(&profile.path)
        .to_string_lossy()
        .replace('\\', "/")
    })
}

#[test]
fn default_profile_ignores_install_without_default_key() {
  // The install section exists but names no profile, so the Default=1 marker
  // must still decide instead of the resolver returning an empty path.
  let ini_path = write_ini(
    "ff-install-no-default",
    "[Install4F96D1932A9F858E]\nLocked=1\n\
     [Profile0]\nName=default\nIsRelative=1\nPath=Profiles/abc.default-release\nDefault=1\n",
  );
  assert_eq!(
    default_profile_path(&ini_path),
    Some("Profiles/abc.default-release".to_string())
  );
}

#[test]
fn default_profile_breaks_install_ties_with_default_marker() {
  // Release and nightly share this profiles.ini. Neither install is
  // authoritative, so the Default=1 marker wins over file order.
  let ini_path = write_ini(
    "ff-two-installs",
    "[Install0000000000000001]\nDefault=Profiles/nightly\n\
     [Install0000000000000002]\nDefault=Profiles/release\n\
     [Profile0]\nName=nightly\nIsRelative=1\nPath=Profiles/nightly\n\
     [Profile1]\nName=default\nIsRelative=1\nPath=Profiles/release\nDefault=1\n",
  );
  assert_eq!(
    default_profile_path(&ini_path),
    Some("Profiles/release".to_string())
  );
}

#[test]
fn default_profile_single_install_outranks_default_marker() {
  // One unambiguous install: it is the dedicated profile Firefox opens, so it
  // takes precedence over the legacy marker on another profile.
  let ini_path = write_ini(
    "ff-install-wins",
    "[Install4F96D1932A9F858E]\nDefault=Profiles/work\n\
     [Profile0]\nName=personal\nIsRelative=1\nPath=Profiles/personal\nDefault=1\n\
     [Profile1]\nName=work\nIsRelative=1\nPath=Profiles/work\n",
  );
  assert_eq!(
    default_profile_path(&ini_path),
    Some("Profiles/work".to_string())
  );
}

#[test]
fn default_profile_prefers_an_install_claimed_profile_over_a_stale_marker() {
  // Two installs and two Default=1 markers: the first marker names a profile
  // no install claims (stale after an about:profiles switch), so the resolver
  // must pick the marker that an install actually points at.
  let ini_path = write_ini(
    "ff-stale-marker",
    "[Install0000000000000001]\nDefault=Profiles/release\n\
     [Install0000000000000002]\nDefault=Profiles/nightly\n\
     [Profile0]\nName=stale\nIsRelative=1\nPath=Profiles/stale\nDefault=1\n\
     [Profile1]\nName=nightly\nIsRelative=1\nPath=Profiles/nightly\nDefault=1\n",
  );
  assert_eq!(
    default_profile_path(&ini_path),
    Some("Profiles/nightly".to_string())
  );
}

#[test]
fn default_profile_prefers_a_claimed_profile_when_no_marker_agrees() {
  // Competing installs, no Default=1 anywhere: a profile that some install
  // opens beats the merely-first profile section.
  let ini_path = write_ini(
    "ff-no-marker-two-installs",
    "[Install0000000000000001]\nDefault=Profiles/ghost\n\
     [Install0000000000000002]\nDefault=Profiles/real\n\
     [Profile0]\nName=other\nIsRelative=1\nPath=Profiles/other\n\
     [Profile1]\nName=real\nIsRelative=1\nPath=Profiles/real\n",
  );
  assert_eq!(
    default_profile_path(&ini_path),
    Some("Profiles/real".to_string())
  );
}

#[test]
fn default_profile_ignores_an_install_naming_an_undeclared_profile() {
  // The lone install points at a profile with no section; the Default=1
  // marker is the only trustworthy signal left.
  let ini_path = write_ini(
    "ff-install-ghost",
    "[Install4F96D1932A9F858E]\nDefault=Profiles/ghost\n\
     [Profile0]\nName=other\nIsRelative=1\nPath=Profiles/other\n\
     [Profile1]\nName=default\nIsRelative=1\nPath=Profiles/real\nDefault=1\n",
  );
  assert_eq!(
    default_profile_path(&ini_path),
    Some("Profiles/real".to_string())
  );
}

#[test]
fn default_profile_treats_repeated_install_defaults_as_one() {
  // Two installs naming the SAME profile are not in conflict, so that profile
  // wins over a competing Default=1 marker just as a single install would.
  let ini_path = write_ini(
    "ff-duplicate-installs",
    "[Install0000000000000001]\nDefault=Profiles/work\n\
     [Install0000000000000002]\nDefault=Profiles/work\n\
     [Profile0]\nName=personal\nIsRelative=1\nPath=Profiles/personal\nDefault=1\n\
     [Profile1]\nName=work\nIsRelative=1\nPath=Profiles/work\n",
  );
  assert_eq!(
    default_profile_path(&ini_path),
    Some("Profiles/work".to_string())
  );
}

#[test]
fn default_profile_accepts_a_padded_default_marker() {
  let ini_path = write_ini(
    "ff-padded-marker",
    "[Profile0]\nName=other\nIsRelative=1\nPath=Profiles/other\n\
     [Profile1]\nName=default\nIsRelative=1\nPath=Profiles/real\nDefault= 1 \n",
  );
  assert_eq!(
    default_profile_path(&ini_path),
    Some("Profiles/real".to_string())
  );
}

#[test]
fn list_profiles_skips_sections_without_a_path() {
  let ini_path = write_ini(
    "ff-pathless-section",
    "[Profile0]\nName=broken\nIsRelative=1\n\
     [Profile1]\nName=ok\nIsRelative=1\nPath=Profiles/ok\nDefault=1\n",
  );
  let profiles = list_profiles(&ini_path).expect("should list");
  let names: Vec<_> = profiles.iter().map(|p| p.name.as_str()).collect();
  assert_eq!(names, vec!["ok"]);
}

#[test]
fn list_profiles_surfaces_an_install_default_with_no_section() {
  // The pre-enumeration resolver returned the install's Default verbatim and
  // discovery probed it, so it must stay reachable.
  let ini_path = write_ini(
    "ff-orphan-install",
    "[Install4F96D1932A9F858E]\nDefault=Profiles/orphan\n",
  );
  let base = ini_path.parent().unwrap();

  let profiles = list_profiles(&ini_path).expect("should list");
  assert_eq!(profiles.len(), 1);
  assert_eq!(profiles[0].path, base.join("Profiles/orphan"));
  assert!(profiles[0].is_default);
}

#[test]
fn list_profiles_surfaces_an_orphan_install_alongside_declared_profiles() {
  // The install names a profile with no section, another section exists, and
  // no Default=1 marker decides. The heuristic default is the declared
  // profile, but the orphan must still be listed so discovery can reach it.
  let ini_path = write_ini(
    "ff-orphan-plus-declared",
    "[Install4F96D1932A9F858E]\nDefault=Profiles/orphan\n\
     [Profile0]\nName=other\nIsRelative=1\nPath=Profiles/other\n",
  );
  let base = ini_path.parent().unwrap();

  let profiles = list_profiles(&ini_path).expect("should list");
  let paths: Vec<_> = profiles.iter().map(|p| p.path.clone()).collect();
  assert_eq!(
    paths,
    vec![base.join("Profiles/other"), base.join("Profiles/orphan")]
  );
  assert!(
    profiles[0].is_default,
    "declared profile is the heuristic default"
  );
  assert!(!profiles[1].is_default);
}

#[test]
fn list_profiles_flags_exactly_one_default_for_duplicate_paths() {
  // A malformed ini can declare the same Path twice; "the default" must stay
  // singular so selection does not become spuriously ambiguous.
  let ini_path = write_ini(
    "ff-duplicate-paths",
    "[Profile0]\nName=first\nIsRelative=1\nPath=Profiles/same\nDefault=1\n\
     [Profile1]\nName=second\nIsRelative=1\nPath=Profiles/same\nDefault=1\n",
  );
  let profiles = list_profiles(&ini_path).expect("should list");
  assert_eq!(profiles.len(), 2);
  assert_eq!(
    profiles.iter().filter(|p| p.is_default).count(),
    1,
    "{profiles:?}"
  );
}

#[test]
fn list_profiles_keeps_backslash_paths_verbatim() {
  // rust-ini's default parser treats `\` as an escape introducer and would
  // turn this into `C:UsersmeProfileswork`, with `\r` becoming a carriage
  // return. Asserted on every platform so Linux CI catches a regression.
  let ini_path = write_ini(
    "ff-backslash",
    "[Profile0]\nName=win\nIsRelative=0\nPath=C:\\Users\\me\\Profiles\\work\nDefault=1\n",
  );
  let base = ini_path.parent().unwrap();
  let profiles = list_profiles(&ini_path).expect("should list");
  assert_eq!(profiles.len(), 1);
  assert_eq!(
    profiles[0].path,
    base.join("C:\\Users\\me\\Profiles\\work"),
    "backslashes must survive ini parsing"
  );
}

#[test]
fn select_profile_rejects_ambiguous_and_empty_selectors() {
  let profiles = vec![
    MozillaProfile {
      name: "default-release".to_string(),
      path: PathBuf::from("/snap/Profiles/abc.default-release"),
      is_default: true,
    },
    MozillaProfile {
      name: "default-release".to_string(),
      path: PathBuf::from("/home/Profiles/xyz.default-release"),
      is_default: true,
    },
  ];

  let err = select_profile(&profiles, "default-release").expect_err("ambiguous");
  assert!(
    err.to_string().contains("2 profiles match"),
    "unexpected error: {err}"
  );
  // A full path still disambiguates.
  assert_eq!(
    select_profile(&profiles, "/snap/Profiles/abc.default-release")
      .unwrap()
      .path,
    PathBuf::from("/snap/Profiles/abc.default-release")
  );

  let err = select_profile(&profiles, "").expect_err("empty selector");
  assert!(
    err.to_string().contains("must not be empty"),
    "unexpected error: {err}"
  );
}

#[test]
fn default_profile_falls_back_to_first_profile() {
  let ini_path = write_ini(
    "ff-no-default-marker",
    "[General]\nStartWithLastProfile=1\n\
     [Profile0]\nName=first\nIsRelative=1\nPath=Profiles/first\n\
     [Profile1]\nName=second\nIsRelative=1\nPath=Profiles/second\n",
  );
  assert_eq!(
    default_profile_path(&ini_path),
    Some("Profiles/first".to_string())
  );
}

#[test]
fn list_profiles_returns_every_profile_with_absolute_paths() {
  let ini_path = write_ini(
    "ff-list",
    "[Install4F96D1932A9F858E]\nDefault=Profiles/release\n\
     [Profile0]\nName=nightly\nIsRelative=1\nPath=Profiles/nightly\n\
     [Profile1]\nName=default\nIsRelative=1\nPath=Profiles/release\nDefault=1\n",
  );
  let base = ini_path.parent().unwrap();

  let profiles = list_profiles(&ini_path).expect("should list");
  let names: Vec<_> = profiles.iter().map(|p| p.name.as_str()).collect();
  assert_eq!(names, vec!["nightly", "default"]);
  assert_eq!(profiles[0].path, base.join("Profiles/nightly"));
  assert!(!profiles[0].is_default);
  assert_eq!(profiles[1].path, base.join("Profiles/release"));
  assert!(profiles[1].is_default);
}

#[test]
fn list_profiles_keeps_absolute_profile_paths() {
  let absolute = unique_tmpdir("ff-absolute-target");
  let ini_path = write_ini(
    "ff-absolute",
    &format!(
      "[Profile0]\nName=external\nIsRelative=0\nPath={}\nDefault=1\n",
      absolute.display()
    ),
  );

  let profiles = list_profiles(&ini_path).expect("should list");
  assert_eq!(profiles.len(), 1);
  assert_eq!(profiles[0].path, absolute);
}

#[test]
fn list_profiles_without_profile_sections_is_empty() {
  let ini_path = write_ini("ff-installs-only", "[Install4F96D1932A9F858E]\nLocked=1\n");
  assert!(list_profiles(&ini_path).expect("should list").is_empty());
}

#[test]
fn select_profile_matches_name_directory_or_path() {
  let profiles = vec![
    MozillaProfile {
      name: "default".to_string(),
      path: PathBuf::from("/base/Profiles/abc.default-release"),
      is_default: true,
    },
    MozillaProfile {
      name: "work".to_string(),
      path: PathBuf::from("/base/Profiles/xyz.work"),
      is_default: false,
    },
  ];

  assert_eq!(select_profile(&profiles, "work").unwrap().name, "work");
  assert_eq!(
    select_profile(&profiles, "abc.default-release")
      .unwrap()
      .name,
    "default"
  );
  assert_eq!(
    select_profile(&profiles, "/base/Profiles/xyz.work")
      .unwrap()
      .name,
    "work"
  );

  let err = select_profile(&profiles, "missing").expect_err("should fail");
  assert!(err.to_string().contains("work"), "unexpected error: {err}");
}

#[test]
fn get_session_cookies_lz4_invalid_magic_header_errors() {
  let dir = unique_tmpdir("ff-bad-magic-lz4");
  let backups = dir.join("sessionstore-backups");
  std::fs::create_dir_all(&backups).unwrap();
  std::fs::write(backups.join("recovery.jsonlz4"), b"BADMAGICthis-is-garbage").unwrap();
  let result = get_session_cookies_lz4(None, dir);
  assert!(result.is_err(), "expected Err for invalid magic header");
}

#[test]
fn firefox_based_ignores_malformed_and_blob_rows() {
  let dir = unique_tmpdir("ff-malformed-rows");
  let db = dir.join("cookies.sqlite");
  let conn = rusqlite::Connection::open(&db).expect("open writable sqlite");
  conn
    .execute(
      "CREATE TABLE moz_cookies (
        host TEXT NOT NULL,
        path TEXT NOT NULL,
        isSecure INTEGER NOT NULL,
        expiry INTEGER NOT NULL,
        name TEXT NOT NULL,
        value TEXT NOT NULL,
        isHttpOnly INTEGER NOT NULL,
        sameSite INTEGER NOT NULL
      )",
      [],
    )
    .expect("create table");

  // Row 1: Valid row
  conn
    .execute(
      "INSERT INTO moz_cookies VALUES ('.example.com', '/', 0, 1700000000, 'valid1', 'abc', 1, 1)",
      [],
    )
    .expect("insert row 1");

  // Row 2: Negative expiry is out-of-range metadata and defaults to None.
  conn
    .execute(
      "INSERT INTO moz_cookies VALUES ('.example.com', '/', 0, -1, 'bad_expiry', 'abc', 1, 1)",
      [],
    )
    .expect("insert row 2");

  // Row 3: BLOB value column (String decoding error)
  conn
    .execute(
      "INSERT INTO moz_cookies VALUES ('.example.com', '/', 0, 1700000000, 'bad_blob_val', X'DEADBEEF', 1, 1)",
      [],
    )
    .expect("insert row 3");

  // Row 4: Valid row 2
  conn
    .execute(
      "INSERT INTO moz_cookies VALUES ('foo.test', '/path', 1, 1700000000, 'valid2', 'xyz', 0, 2)",
      [],
    )
    .expect("insert row 4");

  let mut cookies = firefox_based(db, None).expect("firefox_based should succeed despite bad rows");
  cookies.sort_by(|a, b| a.name.cmp(&b.name));
  let names: Vec<_> = cookies.iter().map(|c| c.name.as_str()).collect();
  assert_eq!(
    names,
    vec!["bad_expiry", "valid1", "valid2"],
    "{:?}",
    cookies
  );
  assert_eq!(cookies[0].expires, None);
}
