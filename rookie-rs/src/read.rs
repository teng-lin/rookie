//! Job-layer snapshot: `read` / `from_path` / `ReadResult` / `ReadWarning`.

use crate::browser::cookie_record::CookieRecord;
use crate::browser::legacy;
use crate::browser::registry;
use crate::common::deadline::{boundary_runtime, SystemClock};
use crate::common::enums::Cookie;
use crate::direct_path::{self, cookies_from_path, ChromiumCredentialSource, DirectPathRequest};
use crate::header_filter::{sendable_octets, GetFilter};
use crate::report::{self, ExtractionReport};
use crate::{CancellationHandle, RequestError, Result};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

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

  pub fn header(&self, url: &str) -> Result<String> {
    let filter = GetFilter::for_url(url)?;
    let mut kept: Vec<&Cookie> = self
      .cookies
      .iter()
      .filter(|cookie| filter.keeps(cookie))
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
  let (cookies, mut warnings, profile_id) = match request.profile {
    None => {
      let (cookies, skips) =
        legacy::browser_cookies_and_warnings_with_runtime(&browser_id, None, &runtime)?;
      let warnings = skips
        .into_iter()
        .map(|(code, count)| ReadWarning::new(code, count))
        .collect();
      (cookies, warnings, None)
    }
    Some(query) => {
      let (profile_id, report) =
        crate::profile_extraction_report_with_runtime(&browser_id, &query, None, &runtime)?;
      let warnings = harvest_report_warnings(&report);
      let cookies = crate::flatten_selected_report_cookies(report)?;
      (cookies, warnings, Some(profile_id))
    }
  };
  let (cookies, octet_count) = filter_snapshot(cookies, request.include_expired);
  if octet_count > 0 {
    warnings.push(ReadWarning::new("invalid_octets", octet_count));
  }
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
  let (cookies, octet_count) = filter_snapshot(cookies, request.include_expired);
  let mut warnings = Vec::new();
  if octet_count > 0 {
    warnings.push(ReadWarning::new("invalid_octets", octet_count));
  }
  Ok(ReadResult {
    cookies,
    warnings,
    browser_id: String::new(),
    profile_id: None,
  })
}

fn filter_snapshot(cookies: Vec<Cookie>, include_expired: bool) -> (Vec<Cookie>, u64) {
  let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|duration| duration.as_secs())
    .unwrap_or(0);
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
          if expires < now {
            return false;
          }
        }
      }
      true
    })
    .collect();
  (kept, omitted)
}

fn harvest_report_warnings(report: &ExtractionReport) -> Vec<ReadWarning> {
  let mut decrypt = 0u64;
  for profile in &report.profiles {
    for source in &profile.sources {
      for issue in &source.issues {
        if issue.code.as_str().contains("decrypt") || issue.code.as_str() == "decrypt_failed" {
          decrypt = decrypt.saturating_add(u64::from(issue.occurrences));
        }
      }
    }
  }
  let mut warnings = Vec::new();
  if decrypt > 0 {
    warnings.push(ReadWarning::new("decrypt_failed", decrypt));
  }
  warnings
}

#[allow(dead_code)]
fn _keep_record_link(_: &CookieRecord) {}

#[cfg(test)]
mod tests {
  use super::*;

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
    let result = ReadResult {
      cookies: Vec::new(),
      warnings: Vec::new(),
      browser_id: "chrome".into(),
      profile_id: None,
    };
    assert!(result.header("ftp://example.com/").is_err());
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
