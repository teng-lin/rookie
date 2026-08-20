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

/// One aggregated warning produced while building a [`ReadResult`].
///
/// [`code`](Self::code) and [`count`](Self::count) are the stable machine
/// contract. [`Display`](std::fmt::Display) is intended for people and may
/// change; callers must not parse it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadWarning {
  code: String,
  count: u64,
}

impl ReadWarning {
  /// Returns the stable warning code.
  pub fn code(&self) -> &str {
    &self.code
  }

  /// Returns how many rows contributed to this warning.
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

/// A request for one unfiltered browser snapshot.
///
/// Construct it with [`ReadRequest::browser`]. Without
/// [`profile`](Self::profile), [`read`] preserves the legacy first-profile,
/// legacy-compatible source selection. Supplying a profile uses the unified
/// profile resolver and selects exactly one discovered profile; Gecko-family
/// profiles may then contribute their separately declared session source.
/// Chromium browsers do not declare a separate session source.
///
/// Fields are private, so not calling a builder is distinguishable from
/// passing an empty value. Snapshot reads have a 30-second default timeout;
/// [`timeout`](Self::timeout) and [`cancellation`](Self::cancellation) override
/// that execution control for this request.
///
/// # Examples
///
/// ```no_run
/// use rookie_cookies::{read, ReadRequest};
///
/// let snapshot = read(ReadRequest::browser("firefox").profile("Default"))?;
/// println!("{} cookies", snapshot.cookies().len());
/// # Ok::<(), rookie_cookies::anyhow::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReadRequest {
  browser_id: Option<String>,
  profile: Option<String>,
  include_expired: bool,
  timeout: Option<std::time::Duration>,
  cancellation: Option<CancellationHandle>,
}

impl ReadRequest {
  /// Creates a request for a canonical browser ID or registered alias.
  ///
  /// An empty, unknown, or unavailable-on-this-platform ID is rejected by
  /// [`read`], not by this builder.
  pub fn browser(id: impl Into<String>) -> Self {
    Self {
      browser_id: Some(id.into()),
      profile: None,
      include_expired: false,
      timeout: None,
      cancellation: None,
    }
  }

  /// Selects one profile by opaque profile ID, display name, directory name,
  /// or non-lossy full path.
  ///
  /// Resolution happens when [`read`] runs. Empty, unknown, ambiguous, and
  /// lossy-only selectors are structured request errors.
  pub fn profile(mut self, query: impl Into<String>) -> Self {
    self.profile = Some(query.into());
    self
  }

  /// Chooses whether the returned snapshot retains expired cookies.
  ///
  /// The default is `false`. This option controls snapshot inventory; it does
  /// not turn [`ReadResult::header`] into a raw cookie formatter: headers
  /// always apply expiry at send time and never emit an expired cookie.
  pub fn include_expired(mut self, yes: bool) -> Self {
    self.include_expired = yes;
    self
  }

  /// Overrides the default 30-second timeout for this request.
  ///
  /// Timeout enforcement is cooperative at native boundaries. When the
  /// operation observes expiry it returns an error for which
  /// [`crate::stop_reason`] is [`Some`](Option::Some).
  pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
    self.timeout = Some(timeout);
    self
  }

  /// Allows `handle` to cancel this request from another thread.
  ///
  /// Cancellation is cooperative. A cancellation observed before a usable
  /// snapshot is complete is returned as an error classified by
  /// [`crate::stop_reason`].
  pub fn cancellation(mut self, handle: CancellationHandle) -> Self {
    self.cancellation = Some(handle);
    self
  }
}

/// An unfiltered snapshot of one browser profile or one explicit cookie file.
///
/// Inspect the inventory with [`cookies`](Self::cookies), consume it with
/// [`into_cookies`](Self::into_cookies), and derive a legacy request-header
/// view with [`header`](Self::header). The value is intentionally not `Clone`
/// so large snapshots and credential-like cookie values are not duplicated by
/// accident.
pub struct ReadResult {
  cookies: Vec<Cookie>,
  warnings: Vec<ReadWarning>,
  browser_id: String,
  profile_id: Option<String>,
}

impl ReadResult {
  /// Borrows the snapshot's compatibility cookies in stable extraction order.
  pub fn cookies(&self) -> &[Cookie] {
    &self.cookies
  }

  /// Consumes the snapshot and returns its compatibility cookies.
  pub fn into_cookies(self) -> Vec<Cookie> {
    self.cookies
  }

  /// Borrows warnings accumulated while producing the snapshot.
  pub fn warnings(&self) -> &[ReadWarning] {
    &self.warnings
  }

  /// Returns the canonical registered browser ID.
  ///
  /// Direct-path snapshots currently return an empty string because they do
  /// not pass through browser discovery.
  pub fn browser_id(&self) -> &str {
    &self.browser_id
  }

  /// Returns the resolved opaque profile ID when the request selected one.
  ///
  /// Legacy no-profile reads and direct-path reads return `None`.
  pub fn profile_id(&self) -> Option<&str> {
    self.profile_id.as_deref()
  }

  /// Formats the snapshot's legacy domain/path/Secure match for `url` as a
  /// `Cookie` request-header value.
  ///
  /// Expiry is checked when this method is called, independently of whether
  /// the snapshot was created with [`ReadRequest::include_expired`].
  ///
  /// This compatibility view is not browser-equivalent: the frozen
  /// [`Cookie`] projection does not retain CHIPS partition keys or Firefox
  /// container identity, and a URL alone cannot express top-level-site,
  /// navigation, method, or SameSite context. Do not merge isolated browser
  /// contexts based on this helper.
  ///
  /// # Errors
  ///
  /// Returns an error when `url` is invalid or does not use HTTP or HTTPS, or
  /// when the system clock is earlier than the Unix epoch.
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

/// Executes one [`ReadRequest`] and returns a usable snapshot.
///
/// `read` does not URL-filter. Apply [`ReadResult::header`] later when the
/// legacy request-header view is sufficient, or inspect [`ReadResult::cookies`]
/// for the domain-intact inventory.
///
/// # Selection
///
/// Without a profile selector, this preserves the named-helper compatibility
/// policy: the first legacy-compatible profile and its legacy-eligible
/// sources. With [`ReadRequest::profile`], the unified resolver selects one
/// profile and report selection determines its sources. Gecko-family session
/// JSON is considered only on that profile-selected route.
///
/// # Errors
///
/// Returns a structured [`RequestError`] for a missing/unknown browser or an
/// invalid profile selector. Discovery, acquisition, decryption, and
/// no-usable-selected-source failures are engine errors. Timeout and
/// cancellation also return errors; inspect them with [`crate::stop_reason`]
/// and [`crate::fault_kind`]. Unlike report APIs, this function never returns a
/// failed or stopped snapshot as an ordinary success.
///
/// # Examples
///
/// ```no_run
/// use rookie_cookies::{read, ReadRequest};
///
/// let snapshot = read(ReadRequest::browser("chrome"))?;
/// for cookie in snapshot.cookies() {
///   println!("{} {}", cookie.domain, cookie.name);
/// }
/// # Ok::<(), rookie_cookies::anyhow::Error>(())
/// ```
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

/// Lists discovered profiles for one registered browser without extracting
/// cookies.
///
/// This is the job-layer alias of [`crate::browser_profiles`]. The returned
/// opaque profile IDs are safe inputs to [`ReadRequest::profile`].
///
/// # Errors
///
/// Returns an error for an unknown browser or when every installation root
/// fails enumeration. A registered browser that is not installed returns an
/// empty list.
pub fn profiles(browser_id: &str) -> Result<Vec<report::ProfileDescriptor>> {
  crate::browser_profiles(browser_id)
}

/// A request for a snapshot from one explicit cookie database path.
///
/// By default, [`from_path`] inspects the source format and uses automatic
/// Chromium credentials when applicable. Call
/// [`chromium_credentials`](Self::chromium_credentials) to declare an explicit
/// Chromium credential strategy. This request never performs registered
/// browser or profile discovery.
///
/// # Examples
///
/// ```no_run
/// use rookie_cookies::{from_path, FromPathRequest};
///
/// let snapshot = from_path(FromPathRequest::new("/path/to/cookies.sqlite"))?;
/// println!("{} cookies", snapshot.cookies().len());
/// # Ok::<(), rookie_cookies::anyhow::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FromPathRequest {
  path: PathBuf,
  include_expired: bool,
  timeout: Option<std::time::Duration>,
  cancellation: Option<CancellationHandle>,
  credentials: Option<ChromiumCredentialSource>,
}

impl FromPathRequest {
  /// Creates an automatic request for `path` with no expired-cookie retention.
  ///
  /// Source inspection and filesystem access happen in [`from_path`], not in
  /// this constructor. On Windows, a default-constructed request for a
  /// Chromium database cannot infer its `Local State` credentials and returns
  /// a structured `missing_local_state_file` request error; Mozilla paths and
  /// Chromium requests explicitly marked
  /// [`ChromiumCredentialSource::PlaintextOnly`] remain portable.
  pub fn new(path: impl Into<PathBuf>) -> Self {
    Self {
      path: path.into(),
      include_expired: false,
      timeout: None,
      cancellation: None,
      credentials: None,
    }
  }

  /// Chooses whether the returned snapshot retains expired cookies.
  ///
  /// The default is `false`. This controls snapshot inventory only;
  /// [`ReadResult::header`] still applies expiry at send time.
  pub fn include_expired(mut self, yes: bool) -> Self {
    self.include_expired = yes;
    self
  }

  /// Overrides the default 30-second timeout for this request.
  ///
  /// Timeout enforcement is cooperative at native boundaries. Inspect a
  /// returned error with [`crate::stop_reason`].
  pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
    self.timeout = Some(timeout);
    self
  }

  /// Allows `handle` to cancel this request from another thread.
  pub fn cancellation(mut self, handle: CancellationHandle) -> Self {
    self.cancellation = Some(handle);
    self
  }

  /// Treats the path as Chromium and selects its credential source.
  ///
  /// [`ChromiumCredentialSource::Automatic`] and
  /// [`ChromiumCredentialSource::BrowserId`] are supported on Linux/macOS;
  /// [`ChromiumCredentialSource::LocalStateFile`] is the Windows encrypted-row
  /// form; [`ChromiumCredentialSource::PlaintextOnly`] is portable. Invalid
  /// platform/source combinations are rejected before credential I/O.
  pub fn chromium_credentials(mut self, source: ChromiumCredentialSource) -> Self {
    self.credentials = Some(source);
    self
  }
}

/// Executes one [`FromPathRequest`] without registered-browser discovery.
///
/// The returned [`ReadResult::browser_id`] is currently the empty string and
/// [`ReadResult::profile_id`] is `None`; the explicit path, not registry
/// identity, is authoritative for this operation.
///
/// # Errors
///
/// Returns a structured [`crate::direct_path::DirectPathError`] for invalid
/// option combinations, source inspection failures, unsupported sources, or
/// platform-incompatible Chromium credentials. Acquisition, parse, and
/// decryption failures are engine errors. Timeout and cancellation are errors
/// classified by [`crate::stop_reason`].
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
