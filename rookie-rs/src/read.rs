//! Job-layer snapshot: `read` / `from_path` / `ReadResult` / `ReadWarning`.

use crate::browser::cookie_record::CookieRecord;
use crate::browser::legacy;
use crate::browser::registry;
use crate::common::deadline::{boundary_runtime, SystemClock};
use crate::common::enums::Cookie;
use crate::direct_path::{self, cookies_from_path, ChromiumCredentialSource, DirectPathRequest};
use crate::header_filter::{sendable_octets, GetFilter};
use crate::read_warning::{ReadWarningCode, ReadWarningCounts};
use crate::report::{self, ExtractionReport};
use crate::{CancellationHandle, RequestError, Result};
use std::path::PathBuf;
use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

/// Structured snapshot warning. `code` + `count` are the machine contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadWarning {
  code: String,
  count: u64,
}

impl ReadWarning {
  pub fn code(&self) -> &str {
    &self.code
  }

  pub fn count(&self) -> u64 {
    self.count
  }

  fn new(code: impl Into<String>, count: u64) -> Self {
    Self {
      code: code.into(),
      count,
    }
  }
}

impl std::fmt::Display for ReadWarning {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(formatter, "skipped {} rows ({})", self.count, self.code)
  }
}

/// Job request. Fields are private. Absence is “not called.”
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReadRequest {
  browser_id: Option<String>,
  profile: Option<String>,
  include_expired: bool,
  timeout: Option<std::time::Duration>,
  cancellation: Option<CancellationHandle>,
}

impl ReadRequest {
  pub fn browser(id: impl Into<String>) -> Self {
    Self {
      browser_id: Some(id.into()),
      profile: None,
      include_expired: false,
      timeout: None,
      cancellation: None,
    }
  }

  pub fn profile(mut self, query: impl Into<String>) -> Self {
    self.profile = Some(query.into());
    self
  }

  /// Controls whether expired cookies remain in [`ReadResult::cookies`].
  ///
  /// This is an inventory option only. [`ReadResult::header`] always applies
  /// expiry at send time and never emits an expired cookie.
  pub fn include_expired(mut self, yes: bool) -> Self {
    self.include_expired = yes;
    self
  }

  pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
    self.timeout = Some(timeout);
    self
  }

  pub fn cancellation(mut self, handle: CancellationHandle) -> Self {
    self.cancellation = Some(handle);
    self
  }
}

/// Unfiltered snapshot of one profile or one file. Not `Clone`.
pub struct ReadResult {
  cookies: Vec<Cookie>,
  warnings: Vec<ReadWarning>,
  browser_id: String,
  profile_id: Option<String>,
}

impl ReadResult {
  pub fn cookies(&self) -> &[Cookie] {
    &self.cookies
  }

  pub fn into_cookies(self) -> Vec<Cookie> {
    self.cookies
  }

  pub fn warnings(&self) -> &[ReadWarning] {
    &self.warnings
  }

  pub fn browser_id(&self) -> &str {
    &self.browser_id
  }

  pub fn profile_id(&self) -> Option<&str> {
    self.profile_id.as_deref()
  }

  /// Builds a send-time Cookie header view for `url`.
  ///
  /// Expiry is checked when this method is called, independently of whether
  /// the snapshot was created with [`ReadRequest::include_expired`].
  pub fn header(&self, url: &str) -> Result<String> {
    self.header_at(url, SystemTime::now())
  }

  fn header_at(&self, url: &str, now: SystemTime) -> Result<String> {
    let filter = GetFilter::for_url(url)?;
    let now_epoch = unix_seconds(now)?;
    let mut kept: Vec<&Cookie> = self
      .cookies
      .iter()
      .filter(|cookie| is_unexpired(cookie, now_epoch) && filter.keeps(cookie))
      .collect();
    kept.sort_by(|left, right| {
      right
        .path
        .len()
        .cmp(&left.path.len())
        .then_with(|| left.name.cmp(&right.name))
    });
    Ok(
      kept
        .into_iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; "),
    )
  }
}

impl std::fmt::Debug for ReadResult {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("ReadResult")
      .field("cookie_count", &self.cookies.len())
      .field("warnings", &self.warnings)
      .field("browser_id", &self.browser_id)
      .field("profile_id", &self.profile_id)
      .finish()
  }
}

pub fn read(request: ReadRequest) -> Result<ReadResult> {
  let browser_id = request
    .browser_id
    .filter(|id| !id.is_empty())
    .ok_or(RequestError::MissingBrowser)?;
  let clock = SystemClock;
  let cancel_token = request
    .cancellation
    .as_ref()
    .map(|handle| handle.0.clone())
    .unwrap_or_default();
  let runtime = boundary_runtime(&clock, request.timeout, cancel_token);
  let resolved_browser = registry::resolve_registered_browser(&browser_id)?;
  let (cookies, mut warning_counts, profile_id) = match request.profile {
    None => {
      let (cookies, skips) =
        legacy::browser_cookies_and_warnings_with_runtime(&browser_id, None, &runtime)?;
      (cookies, skips, None)
    }
    Some(query) => {
      let (profile_id, report) =
        crate::profile_extraction_report_with_runtime(&browser_id, &query, None, &runtime)?;
      let warnings = harvest_report_warnings(&report);
      let cookies = crate::flatten_selected_report_cookies(report)?;
      (cookies, warnings, Some(profile_id))
    }
  };
  let (cookies, octet_count) = filter_snapshot(cookies, request.include_expired)?;
  if octet_count > 0 {
    warning_counts.record(ReadWarningCode::InvalidOctets, octet_count);
  }
  let warnings = read_warnings(warning_counts);
  Ok(ReadResult {
    cookies,
    warnings,
    browser_id: resolved_browser.canonical_id,
    profile_id,
  })
}

/// Alias of [`crate::browser_profiles`].
pub fn profiles(browser_id: &str) -> Result<Vec<report::ProfileDescriptor>> {
  crate::browser_profiles(browser_id)
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FromPathRequest {
  path: PathBuf,
  include_expired: bool,
  timeout: Option<std::time::Duration>,
  cancellation: Option<CancellationHandle>,
  credentials: Option<ChromiumCredentialSource>,
}

impl FromPathRequest {
  pub fn new(path: impl Into<PathBuf>) -> Self {
    Self {
      path: path.into(),
      include_expired: false,
      timeout: None,
      cancellation: None,
      credentials: None,
    }
  }

  /// Controls whether expired cookies remain in [`ReadResult::cookies`].
  ///
  /// This is an inventory option only. [`ReadResult::header`] always applies
  /// expiry at send time and never emits an expired cookie.
  pub fn include_expired(mut self, yes: bool) -> Self {
    self.include_expired = yes;
    self
  }

  pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
    self.timeout = Some(timeout);
    self
  }

  pub fn cancellation(mut self, handle: CancellationHandle) -> Self {
    self.cancellation = Some(handle);
    self
  }

  pub fn chromium_credentials(mut self, source: ChromiumCredentialSource) -> Self {
    self.credentials = Some(source);
    self
  }
}

pub fn from_path(request: FromPathRequest) -> Result<ReadResult> {
  let cookies = match request.credentials {
    None => {
      let mut path_request = DirectPathRequest::new(&request.path);
      if let Some(timeout) = request.timeout {
        path_request = path_request.timeout(timeout);
      }
      if let Some(handle) = request.cancellation {
        path_request = path_request.cancellation(handle);
      }
      cookies_from_path(path_request)?
    }
    Some(source) => {
      let mut chromium = direct_path::ChromiumPathRequest::new(&request.path).credentials(source);
      if let Some(timeout) = request.timeout {
        chromium = chromium.timeout(timeout);
      }
      if let Some(handle) = request.cancellation {
        chromium = chromium.cancellation(handle);
      }
      direct_path::chromium_cookies_from_path(chromium)?
    }
  };
  let (cookies, octet_count) = filter_snapshot(cookies, request.include_expired)?;
  let mut warning_counts = ReadWarningCounts::default();
  if octet_count > 0 {
    warning_counts.record(ReadWarningCode::InvalidOctets, octet_count);
  }
  let warnings = read_warnings(warning_counts);
  Ok(ReadResult {
    cookies,
    warnings,
    browser_id: String::new(),
    profile_id: None,
  })
}

fn filter_snapshot(cookies: Vec<Cookie>, include_expired: bool) -> Result<(Vec<Cookie>, u64)> {
  filter_snapshot_at(cookies, include_expired, SystemTime::now())
}

fn filter_snapshot_at(
  cookies: Vec<Cookie>,
  include_expired: bool,
  now: SystemTime,
) -> Result<(Vec<Cookie>, u64)> {
  let now = unix_seconds(now)?;
  let mut omitted = 0;
  let kept = cookies
    .into_iter()
    .filter(|cookie| {
      if !sendable_octets(&cookie.name, &cookie.value) {
        omitted += 1;
        return false;
      }
      if !include_expired {
        if let Some(expires) = cookie.expires {
          if expires <= now {
            return false;
          }
        }
      }
      true
    })
    .collect();
  Ok((kept, omitted))
}

fn unix_seconds(now: SystemTime) -> std::result::Result<u64, SystemTimeError> {
  now
    .duration_since(UNIX_EPOCH)
    .map(|duration| duration.as_secs())
}

fn is_unexpired(cookie: &Cookie, now_epoch: u64) -> bool {
  cookie.expires.is_none_or(|expires| expires > now_epoch)
}

fn harvest_report_warnings(report: &ExtractionReport) -> ReadWarningCounts {
  let mut warnings = ReadWarningCounts::default();
  for issue in &report.issues {
    warnings.record_issue(issue.code.as_str(), u64::from(issue.occurrences));
  }
  for profile in &report.profiles {
    for issue in &profile.issues {
      warnings.record_issue(issue.code.as_str(), u64::from(issue.occurrences));
    }
    for source in &profile.sources {
      for issue in &source.issues {
        warnings.record_issue(issue.code.as_str(), u64::from(issue.occurrences));
      }
    }
  }
  warnings
}

fn read_warnings(counts: ReadWarningCounts) -> Vec<ReadWarning> {
  counts
    .into_entries()
    .map(|(code, count)| ReadWarning::new(code.as_str(), count))
    .collect()
}

#[allow(dead_code)]
fn _keep_record_link(_: &CookieRecord) {}

#[cfg(test)]
mod tests {
  use super::*;
  use std::time::Duration;

  fn epoch(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
  }

  fn cookie(name: &str, expires: Option<u64>) -> Cookie {
    Cookie {
      domain: ".example.test".to_owned(),
      path: "/".to_owned(),
      secure: false,
      expires,
      name: name.to_owned(),
      value: "value".to_owned(),
      http_only: false,
      same_site: -1,
    }
  }

  fn result(cookies: Vec<Cookie>) -> ReadResult {
    ReadResult {
      cookies,
      warnings: Vec::new(),
      browser_id: "chrome".into(),
      profile_id: None,
    }
  }

  #[test]
  fn missing_browser_is_request_error() {
    let error = read(ReadRequest {
      browser_id: None,
      profile: None,
      include_expired: false,
      timeout: None,
      cancellation: None,
    })
    .unwrap_err();
    assert!(error.downcast_ref::<RequestError>().is_some());
    assert_eq!(
      error.downcast_ref::<RequestError>().unwrap().code(),
      "missing_browser"
    );
  }

  #[test]
  fn header_rejects_ftp() {
    let result = result(Vec::new());
    assert!(result.header("ftp://example.com/").is_err());
  }

  #[test]
  fn snapshot_omits_a_cookie_expired_before_the_snapshot() {
    let (cookies, omitted_octets) =
      filter_snapshot_at(vec![cookie("old", Some(99))], false, epoch(100)).expect("valid clock");
    assert!(cookies.is_empty());
    assert_eq!(omitted_octets, 0);
  }

  #[test]
  fn snapshot_treats_expiry_equal_to_now_as_expired() {
    let (cookies, omitted_octets) =
      filter_snapshot_at(vec![cookie("boundary", Some(100))], false, epoch(100))
        .expect("valid clock");
    assert!(cookies.is_empty());
    assert_eq!(omitted_octets, 0);
  }

  #[test]
  fn header_omits_a_cookie_that_expires_after_snapshot_creation() {
    let (cookies, _) =
      filter_snapshot_at(vec![cookie("short-lived", Some(101))], false, epoch(100))
        .expect("valid snapshot clock");
    assert_eq!(cookies.len(), 1, "cookie is live in the snapshot");

    let result = result(cookies);
    assert_eq!(
      result
        .header_at("https://example.test/", epoch(100))
        .expect("valid header clock"),
      "short-lived=value"
    );
    assert_eq!(
      result
        .header_at("https://example.test/", epoch(101))
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
        .header_at("https://example.test/", epoch(100))
        .expect("valid header clock"),
      ""
    );
  }

  #[test]
  fn pre_epoch_clock_is_a_typed_error_instead_of_epoch_zero() {
    let before_epoch = UNIX_EPOCH
      .checked_sub(Duration::from_secs(1))
      .expect("SystemTime represents the pre-epoch test value");
    let error = filter_snapshot_at(Vec::new(), false, before_epoch)
      .expect_err("a pre-epoch clock is invalid");
    assert!(error.downcast_ref::<SystemTimeError>().is_some());

    let error = result(Vec::new())
      .header_at("https://example.test/", before_epoch)
      .expect_err("header uses the same typed clock conversion");
    assert!(error.downcast_ref::<SystemTimeError>().is_some());
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
    assert_eq!(
      crate::stop_reason(&error),
      Some(crate::StopReason::Cancelled)
    );
  }
}
