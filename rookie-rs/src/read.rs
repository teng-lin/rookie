//! Job-layer snapshot: `read` / `from_path` / `ReadResult` / `ReadWarning`.

use crate::browser::cookie_record::CookieRecord;
use crate::browser::outcome::Termination;
use crate::browser::registry;
use crate::browser::report_build::snapshot::{browser_snapshot_with_runtime, SnapshotSelection};
use crate::common::deadline::{runtime_for_control, SystemClock};
use crate::common::enums::{Cookie, DetailedCookie};
use crate::direct_path::{self, ChromiumCredentialSource, DirectPathRequest};
use crate::error::map_job_result;
use crate::execution::{AppBoundPolicy, ExecutionControl};
use crate::header_filter::{sendable_octets, GetFilter};
use crate::read_warning::{ReadWarningCode, ReadWarningCounts};
use crate::report;
use crate::session::SessionPolicy;
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
  session: SessionPolicy,
  control: ExecutionControl,
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
      session: SessionPolicy::default(),
      control: ExecutionControl::default(),
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

  /// Also acquires the browser's declared session store.
  ///
  /// **Changed in 0.6.0.** Session cookies used to be an accident of asking
  /// for a profile: 0.6-beta reached them only through
  /// [`profile`](Self::profile), and always did so. They are now their own
  /// question, so `read(ReadRequest::browser("firefox").include_session())`
  /// is expressible and `.profile(q)` alone no longer opens a session store.
  ///
  /// See [`SessionPolicy`] for why this is an acquire-time filter rather than
  /// a filter over the returned cookies.
  pub fn include_session(mut self) -> Self {
    self.session = SessionPolicy::IncludeSession;
    self
  }

  /// Selects the session policy explicitly.
  pub fn session(mut self, policy: SessionPolicy) -> Self {
    self.session = policy;
    self
  }

  /// Overrides the default 30-second timeout for this request.
  ///
  /// Timeout enforcement is cooperative at native boundaries. A stop is
  /// returned as [`crate::Error::Stopped`].
  pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
    self.control = self.control.timeout(timeout);
    self
  }

  /// Allows `handle` to cancel this request from another thread.
  ///
  /// Cancellation is cooperative. A cancellation observed before a usable
  /// snapshot is complete is returned as [`crate::Error::Stopped`].
  pub fn cancellation(mut self, handle: CancellationHandle) -> Self {
    self.control = self.control.cancellation(handle);
    self
  }

  /// Selects the Windows App-Bound (v20) recovery policy for this request.
  pub fn app_bound(mut self, policy: AppBoundPolicy) -> Self {
    self.control = self.control.app_bound(policy);
    self
  }

  /// Replaces this request's execution control **wholesale**.
  ///
  /// This discards any earlier [`timeout`](Self::timeout),
  /// [`cancellation`](Self::cancellation), or [`app_bound`](Self::app_bound)
  /// call, so call it before the individual field setters.
  pub fn execution(mut self, control: ExecutionControl) -> Self {
    self.control = control;
    self
  }
}

/// An unfiltered snapshot of one browser profile or one explicit cookie file.
///
/// The snapshot's native representation is [`DetailedCookie`], so CHIPS
/// partition keys and Firefox container identity survive to
/// [`header`](Self::header). [`cookies`](Self::cookies) is the eight-field
/// compatibility projection, built once at construction so it stays a free
/// borrow for bindings that call it on every access.
///
/// **Cost, stated plainly:** the snapshot therefore holds two copies of every
/// name and value. For a large Chrome profile that is real memory, and it is
/// the price of `cookies()` being a borrow rather than a rebuild.
/// [`into_cookies`](Self::into_cookies) and
/// [`into_detailed_cookies`](Self::into_detailed_cookies) move instead of
/// duplicating. The value is intentionally not `Clone` so large snapshots and
/// credential-like cookie values are not duplicated by accident.
pub struct ReadResult {
  cookies: Vec<DetailedCookie>,
  projected: Vec<Cookie>,
  warnings: Vec<ReadWarning>,
  browser_id: Option<String>,
  profile_id: Option<String>,
}

impl ReadResult {
  fn new(
    cookies: Vec<DetailedCookie>,
    warnings: Vec<ReadWarning>,
    browser_id: Option<String>,
    profile_id: Option<String>,
  ) -> Self {
    let projected = cookies
      .iter()
      .map(|detailed| detailed.cookie.clone())
      .collect();
    Self {
      cookies,
      projected,
      warnings,
      browser_id,
      profile_id,
    }
  }

  /// Borrows the compatibility projection in stable extraction order.
  ///
  /// Isolation is discarded here: the eight-field [`Cookie`] cannot represent
  /// a CHIPS partition or a Firefox container. Use
  /// [`detailed_cookies`](Self::detailed_cookies) when that matters, and never
  /// merge two isolated contexts on the strength of this list.
  pub fn cookies(&self) -> &[Cookie] {
    &self.projected
  }

  /// Borrows the snapshot's native records, isolation intact.
  ///
  /// This is the recommended accessor.
  pub fn detailed_cookies(&self) -> &[DetailedCookie] {
    &self.cookies
  }

  /// Consumes the snapshot and returns its compatibility projection.
  pub fn into_cookies(self) -> Vec<Cookie> {
    self.projected
  }

  /// Consumes the snapshot and returns its native records.
  pub fn into_detailed_cookies(self) -> Vec<DetailedCookie> {
    self.cookies
  }

  /// Borrows warnings accumulated while producing the snapshot.
  pub fn warnings(&self) -> &[ReadWarning] {
    &self.warnings
  }

  /// Returns the canonical registered browser ID, or `None` for a direct-path
  /// snapshot.
  ///
  /// **Changed in 0.6.0.** This was `&str` and returned the empty string for
  /// [`from_path`], which is an in-band sentinel a caller had to know about.
  /// `from_path` does not pass through browser discovery, and the explicit
  /// path — not a registry identity — is authoritative for it.
  pub fn browser_id(&self) -> Option<&str> {
    self.browser_id.as_deref()
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
  /// This compatibility view is not browser-equivalent: a URL alone cannot
  /// express top-level-site, navigation, method, or SameSite context. Do not
  /// merge isolated browser contexts based on this helper.
  ///
  /// # Errors
  ///
  /// Returns an error when `url` is invalid or does not use HTTP or HTTPS, or
  /// when the system clock is earlier than the Unix epoch.
  pub fn header(&self, url: &str) -> Result<String> {
    map_job_result(self.header_at(url, SystemTime::now()))
  }

  fn header_at(&self, url: &str, now: SystemTime) -> anyhow::Result<String> {
    let filter = GetFilter::for_url(url)?;
    let now_epoch = unix_seconds(now)?;
    let mut kept: Vec<&Cookie> = self
      .projected
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
  map_job_result(read_inner(request))
}

fn read_inner(request: ReadRequest) -> anyhow::Result<ReadResult> {
  let browser_id = request
    .browser_id
    .clone()
    .filter(|id| !id.is_empty())
    .ok_or(RequestError::MissingBrowser)?;
  let clock = SystemClock;
  let runtime = runtime_for_control(&clock, &request.control);
  let resolved_browser = registry::resolve_registered_browser(&browser_id)?;
  // Resolution and extraction share this one absolute budget. There is no
  // second request to build, so there is nothing that could reset it.
  let selection = match request.profile.as_deref() {
    None => SnapshotSelection::LegacyFirst,
    Some(query) => SnapshotSelection::Profile(&registry::resolve_profile_query(
      &browser_id,
      query,
      &runtime,
    )?),
  };
  read_snapshot(
    &resolved_browser.canonical_id,
    selection,
    &request,
    &runtime,
  )
}

fn read_snapshot(
  canonical_id: &str,
  selection: SnapshotSelection<'_>,
  request: &ReadRequest,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> anyhow::Result<ReadResult> {
  let outcome = browser_snapshot_with_runtime(canonical_id, selection, request.session, runtime)?;
  // A stop that reached the snapshot is an error, never a short list. Reports
  // return a stopped run as `Ok`; snapshots do not.
  if let Some(stop) = boundary_stop_for(outcome.termination) {
    return Err(stop.into());
  }
  let mut warning_counts = outcome.warnings;
  let (cookies, omitted) = filter_snapshot(outcome.cookies, request.include_expired)?;
  omitted.record_into(&mut warning_counts);
  Ok(ReadResult::new(
    cookies,
    read_warnings(warning_counts),
    Some(canonical_id.to_owned()),
    outcome.profile_id,
  ))
}

fn boundary_stop_for(termination: Termination) -> Option<crate::common::deadline::BoundaryStop> {
  use crate::common::deadline::BoundaryStop;
  match termination {
    Termination::Completed => None,
    Termination::TimedOut => Some(BoundaryStop::TimedOut),
    Termination::Cancelled => Some(BoundaryStop::Cancelled),
    Termination::ResourceExhausted => Some(BoundaryStop::ResourceExhausted),
  }
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

/// [`profiles`] under caller-supplied execution control.
///
/// Listing still touches the filesystem, so it takes the same timeout and
/// cancellation knobs every other I/O job takes. It has no App-Bound work to
/// do; the policy on `control` is simply unused here.
pub fn profiles_with(
  browser_id: &str,
  control: ExecutionControl,
) -> Result<Vec<report::ProfileDescriptor>> {
  crate::browser_profiles_with(browser_id, control)
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
  credentials: Option<ChromiumCredentialSource>,
  control: ExecutionControl,
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
      credentials: None,
      control: ExecutionControl::default(),
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
  /// Timeout enforcement is cooperative at native boundaries. A stop is
  /// returned as [`crate::Error::Stopped`].
  pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
    self.control = self.control.timeout(timeout);
    self
  }

  /// Allows `handle` to cancel this request from another thread.
  pub fn cancellation(mut self, handle: CancellationHandle) -> Self {
    self.control = self.control.cancellation(handle);
    self
  }

  /// Selects the Windows App-Bound (v20) recovery policy for this request.
  pub fn app_bound(mut self, policy: AppBoundPolicy) -> Self {
    self.control = self.control.app_bound(policy);
    self
  }

  /// Replaces this request's execution control **wholesale**.
  ///
  /// This discards any earlier [`timeout`](Self::timeout),
  /// [`cancellation`](Self::cancellation), or [`app_bound`](Self::app_bound)
  /// call, so call it before the individual field setters.
  pub fn execution(mut self, control: ExecutionControl) -> Self {
    self.control = control;
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
  map_job_result(from_path_inner(request))
}

fn from_path_inner(request: FromPathRequest) -> anyhow::Result<ReadResult> {
  let cookies = match request.credentials {
    None => {
      // The `_inner` seam, not the public job function: `from_path` maps the
      // chain to `Error` once, at its own edge. Going through the public
      // direct-path edge first would flatten a `BoundaryStop` into an opaque
      // `Error` and lose the stop classification here.
      direct_path::cookies_from_path_detailed_inner(
        DirectPathRequest::new(&request.path).execution(request.control),
      )?
    }
    Some(source) => direct_path::chromium_cookies_from_path_detailed_inner(
      direct_path::ChromiumPathRequest::new(&request.path)
        .credentials(source)
        .execution(request.control),
    )?,
  };
  let (cookies, omitted) = filter_snapshot(cookies, request.include_expired)?;
  let mut warning_counts = ReadWarningCounts::default();
  omitted.record_into(&mut warning_counts);
  // No browser id: this job never passed through registry discovery, and the
  // explicit path -- not a registry identity -- is what identifies it.
  Ok(ReadResult::new(
    cookies,
    read_warnings(warning_counts),
    None,
    None,
  ))
}

/// Rows a snapshot omitted, with the reason each was omitted for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct OmittedRows {
  invalid_octets: u64,
  malformed_host_identity: u64,
}

impl OmittedRows {
  fn record_into(self, warnings: &mut ReadWarningCounts) {
    if self.invalid_octets > 0 {
      warnings.record(ReadWarningCode::InvalidOctets, self.invalid_octets);
    }
    if self.malformed_host_identity > 0 {
      warnings.record(
        ReadWarningCode::MalformedHostIdentity,
        self.malformed_host_identity,
      );
    }
  }
}

fn filter_snapshot(
  cookies: Vec<DetailedCookie>,
  include_expired: bool,
) -> anyhow::Result<(Vec<DetailedCookie>, OmittedRows)> {
  filter_snapshot_at(cookies, include_expired, SystemTime::now())
}

fn filter_snapshot_at(
  cookies: Vec<DetailedCookie>,
  include_expired: bool,
  now: SystemTime,
) -> anyhow::Result<(Vec<DetailedCookie>, OmittedRows)> {
  let now = unix_seconds(now)?;
  let mut omitted = OmittedRows::default();
  let kept = cookies
    .into_iter()
    .filter(|detailed| {
      let cookie = &detailed.cookie;
      // A row whose required host identity did not survive decode is omitted
      // rather than emitted as `domain: ""`. An empty domain matches nothing
      // and belongs to no site, so keeping it would put a value in the
      // inventory no send-match rule can ever act on -- and the count is how a
      // caller learns it happened. Unknown *optional* isolation fields stay
      // `None` and never drop a row.
      if cookie.domain.is_empty() {
        omitted.malformed_host_identity += 1;
        return false;
      }
      if !sendable_octets(&cookie.name, &cookie.value) {
        omitted.invalid_octets += 1;
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
    let error = read(ReadRequest {
      browser_id: None,
      profile: None,
      include_expired: false,
      session: SessionPolicy::default(),
      control: ExecutionControl::default(),
    })
    .unwrap_err();
    let crate::Error::Request(request_error) = &error else {
      panic!("a missing browser is a request error, got {error:?}");
    };
    assert_eq!(request_error.code(), "missing_browser");
  }

  #[test]
  fn header_rejects_ftp() {
    let result = result(Vec::new());
    assert!(result.header("ftp://example.com/").is_err());
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
    assert_eq!(error.stop_reason(), Some(crate::StopReason::Cancelled));
  }
}
