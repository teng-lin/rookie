//! Snapshot-shape unit tests for `read` / `from_path` / `ReadResult`.

use super::*;
use std::time::Duration;

fn epoch(seconds: u64) -> SystemTime {
  UNIX_EPOCH + Duration::from_secs(seconds)
}

fn cookie(name: &str, expires: Option<u64>) -> DetailedCookie {
  detailed(
    Cookie {
      domain: ".example.test".to_owned(),
      path: "/".to_owned(),
      secure: false,
      expires,
      name: name.to_owned(),
      value: "value".to_owned(),
      http_only: false,
      same_site: -1,
    },
    crate::enums::CookieContext::default(),
  )
}

fn detailed(cookie: Cookie, context: crate::enums::CookieContext) -> DetailedCookie {
  let mut detailed = DetailedCookie {
    cookie,
    context: crate::enums::CookieContext::default(),
  };
  detailed.context = context;
  detailed
}

fn result(cookies: Vec<DetailedCookie>) -> ReadResult {
  ReadResult::new(cookies, Vec::new(), Some("chrome".to_owned()), None)
}

#[test]
fn missing_browser_is_request_error() {
  let error = read(ReadRequest::browser("")).unwrap_err();
  let crate::Error::Request(request_error) = &error else {
    panic!("a missing browser is a request error, got {error:?}");
  };
  assert_eq!(request_error.code(), "missing_browser");
}

#[test]
fn header_rejects_ftp() {
  let result = result(Vec::new());
  assert!(result
    .header(&SendContext::url("ftp://example.com/"))
    .is_err());
}

#[test]
fn snapshot_omits_a_cookie_expired_before_the_snapshot() {
  let (cookies, omitted) =
    filter_snapshot_at(vec![cookie("old", Some(99))], false, epoch(100)).expect("valid clock");
  assert!(cookies.is_empty());
  assert_eq!(omitted, OmittedRows::default());
}

#[test]
fn snapshot_treats_expiry_equal_to_now_as_expired() {
  let (cookies, omitted) =
    filter_snapshot_at(vec![cookie("boundary", Some(100))], false, epoch(100))
      .expect("valid clock");
  assert!(cookies.is_empty());
  assert_eq!(omitted, OmittedRows::default());
}

#[test]
fn header_omits_a_cookie_that_expires_after_snapshot_creation() {
  let (cookies, _) = filter_snapshot_at(vec![cookie("short-lived", Some(101))], false, epoch(100))
    .expect("valid snapshot clock");
  assert_eq!(cookies.len(), 1, "cookie is live in the snapshot");

  let result = result(cookies);
  assert_eq!(
    result
      .header(&SendContext::url("https://example.test/").now(epoch(100)))
      .expect("valid header clock"),
    "short-lived=value"
  );
  assert_eq!(
    result
      .header(&SendContext::url("https://example.test/").now(epoch(101)))
      .expect("valid header clock"),
    ""
  );
}

#[test]
fn include_expired_retains_inventory_but_never_makes_it_sendable() {
  let (cookies, _) = filter_snapshot_at(vec![cookie("historical", Some(99))], true, epoch(100))
    .expect("valid snapshot clock");
  assert_eq!(cookies.len(), 1, "inventory retains the expired cookie");

  let result = result(cookies);
  assert_eq!(result.cookies().len(), 1);
  assert_eq!(
    result
      .header(&SendContext::url("https://example.test/").now(epoch(100)))
      .expect("valid header clock"),
    ""
  );
}

#[test]
fn pre_epoch_clock_is_a_typed_error_instead_of_epoch_zero() {
  let before_epoch = UNIX_EPOCH
    .checked_sub(Duration::from_secs(1))
    .expect("SystemTime represents the pre-epoch test value");
  let error =
    filter_snapshot_at(Vec::new(), false, before_epoch).expect_err("a pre-epoch clock is invalid");
  assert!(error.downcast_ref::<SystemTimeError>().is_some());

  // `header` reports the same condition as its own typed request error
  // rather than as an opaque engine failure: a pre-epoch clock is a caller
  // input problem, and mapping it to epoch 0 would disable expiry entirely.
  let error = result(Vec::new())
    .header(&SendContext::url("https://example.test/").now(before_epoch))
    .expect_err("header uses the same typed clock conversion");
  assert_eq!(error.code(), "clock_unrepresentable");
}

fn seed_firefox_db(path: &std::path::Path, name: &str, value: &str) {
  let connection = rusqlite::Connection::open(path).expect("open firefox fixture");
  connection
    .execute_batch(
      "CREATE TABLE moz_cookies (
        host TEXT NOT NULL,
        path TEXT NOT NULL,
        isSecure INTEGER NOT NULL,
        expiry INTEGER NOT NULL,
        name TEXT NOT NULL,
        value TEXT NOT NULL,
        isHttpOnly INTEGER NOT NULL,
        sameSite INTEGER NOT NULL
      );",
    )
    .expect("create moz_cookies");
  connection
    .execute(
      "INSERT INTO moz_cookies (host, path, isSecure, expiry, name, value, isHttpOnly, sameSite)
       VALUES ('.example.test', '/', 0, 4102444800, ?1, ?2, 0, 0)",
      rusqlite::params![name, value],
    )
    .expect("insert moz cookie");
}

fn seed_chromium_db(path: &std::path::Path, name: &str, value: &str, encrypted: &[u8]) {
  let connection = rusqlite::Connection::open(path).expect("open chromium fixture");
  connection
    .execute_batch(
      "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
       INSERT INTO meta VALUES ('version', '23');
       CREATE TABLE cookies (
         host_key TEXT NOT NULL, path TEXT NOT NULL, is_secure INTEGER NOT NULL,
         expires_utc INTEGER NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
         encrypted_value BLOB NOT NULL, is_httponly INTEGER NOT NULL,
         samesite INTEGER NOT NULL
       );",
    )
    .expect("create chromium cookies");
  connection
    .execute(
      "INSERT INTO cookies VALUES ('.example.test', '/', 0, 0, ?1, ?2, ?3, 0, 0)",
      rusqlite::params![name, value, encrypted],
    )
    .expect("insert chromium cookie");
}

#[test]
fn from_path_omits_ctl_name_with_invalid_octets_warning() {
  let dir = crate::utils::TempDir::new().expect("temp dir");
  let db = dir.path().join("cookies.sqlite");
  seed_firefox_db(&db, "sid\r", "x");
  let result = from_path(FromPathRequest::new(&db).include_expired(true)).expect("from_path");
  let warning = result
    .warnings()
    .iter()
    .find(|warning| warning.code() == "invalid_octets")
    .expect("invalid_octets");
  assert_eq!(warning.count(), 1);
  assert!(result.cookies().is_empty());
}

#[test]
fn from_path_omits_a_dot_only_host_with_malformed_host_identity_warning() {
  // `"."` is not an empty string, so a bare `is_empty()` check kept it while
  // the report path -- which normalizes with `trim_matches('.')` -- omitted
  // it. Both now share one predicate, and this pins the case that told them
  // apart.
  let dir = crate::utils::TempDir::new().expect("temp dir");
  let db = dir.path().join("cookies.sqlite");
  let connection = rusqlite::Connection::open(&db).expect("open firefox fixture");
  connection
    .execute_batch(
      "CREATE TABLE moz_cookies (
        host TEXT NOT NULL,
        path TEXT NOT NULL,
        isSecure INTEGER NOT NULL,
        expiry INTEGER NOT NULL,
        name TEXT NOT NULL,
        value TEXT NOT NULL,
        isHttpOnly INTEGER NOT NULL,
        sameSite INTEGER NOT NULL
      );
      INSERT INTO moz_cookies VALUES ('.', '/', 0, 4102444800, 'dotted', 'v', 0, 0);
      INSERT INTO moz_cookies VALUES ('..', '/', 0, 4102444800, 'dottier', 'v', 0, 0);
      INSERT INTO moz_cookies VALUES ('.example.test', '/', 0, 4102444800, 'kept', 'v', 0, 0);",
    )
    .expect("seed moz_cookies");
  drop(connection);

  let result = from_path(FromPathRequest::new(&db).include_expired(true)).expect("from_path");
  let warning = result
    .warnings()
    .iter()
    .find(|warning| warning.code() == "malformed_host_identity")
    .expect("malformed_host_identity");
  assert_eq!(warning.count(), 2);
  assert_eq!(result.cookies().len(), 1);
  assert_eq!(result.cookies()[0].name, "kept");
}

#[test]
fn from_path_credentials_observes_cancellation() {
  let dir = crate::utils::TempDir::new().expect("temp dir");
  let db = dir.path().join("Cookies");
  seed_chromium_db(&db, "session", "plain", &[]);
  let handle = CancellationHandle::new();
  assert!(handle.cancel());
  let error = from_path(
    FromPathRequest::new(&db)
      .chromium_credentials(ChromiumCredentialSource::PlaintextOnly)
      .cancellation(handle),
  )
  .expect_err("cancelled from_path");
  assert_eq!(error.stop_reason(), Some(crate::StopReason::Cancelled));
}
