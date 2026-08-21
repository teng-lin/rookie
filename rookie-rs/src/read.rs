//! Job-layer snapshot: `read` / `from_path` / `ReadResult` / `ReadWarning`.

use crate::browser::cookie_record::CookieRecord;
use crate::browser::outcome::Termination;
use crate::browser::registry;
use crate::browser::report_build::snapshot::{browser_snapshot_with_runtime, SnapshotSelection};
use crate::common::deadline::{runtime_for_control, SystemClock};
use crate::common::enums::{Cookie, DetailedCookie};
use crate::direct_path::{self, ChromiumCredentialSource, PathExtractRequest};
use crate::error::map_job_result;
use crate::execution::{AppBoundPolicy, ExecutionControl};
use crate::header_filter::{
  partition_identity, redact_url, same_site_permits, sendable_octets, site_from_url, GetFilter,
  PartitionIdentity, Site,
};
use crate::read_warning::{ReadWarningCode, ReadWarningCounts};
use crate::report;
use crate::selection::ProfileSelection;
use crate::send_context::{selector, MethodClass, ResourceKind, SendContext};
use crate::session::SessionPolicy;
use crate::target::BrowserTarget;
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
/// profile resolver and selects exactly one discovered profile. Session
/// acquisition is an independent [`SessionPolicy`]: call
/// [`include_session`](Self::include_session) with or without a profile query
/// to acquire the selected Gecko profile's declared session source. Chromium
/// browsers do not declare a separate session source.
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
  target: BrowserTarget<ProfileSelection>,
  include_expired: bool,
  control: ExecutionControl,
}

impl ReadRequest {
  /// Creates a request for a canonical browser ID or registered alias.
  ///
  /// An empty, unknown, or unavailable-on-this-platform ID is rejected by
  /// [`read`], not by this builder.
  pub fn browser(id: impl Into<String>) -> Self {
    Self {
      target: BrowserTarget::browser(id),
      include_expired: false,
      control: ExecutionControl::default(),
    }
  }

  /// Selects one profile by opaque profile ID, display name, directory name,
  /// or non-lossy full path.
  ///
  /// Resolution happens when [`read`] runs. Empty, unknown, ambiguous, and
  /// lossy-only selectors are structured request errors.
  pub fn profile(mut self, query: impl Into<String>) -> Self {
    self.target = self.target.profile(query);
    self
  }

  /// Selects the profile explicitly.
  ///
  /// [`ProfileSelection`] has no "every profile" arm, so a snapshot cannot ask
  /// for one. That is a type fact rather than a runtime rejection: a
  /// `ReadResult` has one `profile_id` and could not describe more.
  pub fn selection(mut self, selection: ProfileSelection) -> Self {
    self.target = self.target.with_selection(selection);
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
    self.target = self.target.with_session(SessionPolicy::IncludeSession);
    self
  }

  /// Selects the session policy explicitly.
  pub fn session(mut self, policy: SessionPolicy) -> Self {
    self.target = self.target.with_session(policy);
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

  /// Formats a send-safe `Cookie` request-header value for `context`.
  ///
  /// This is a **view**. It never mutates the snapshot, and it never merges
  /// two isolated browsing contexts: a snapshot holding a partitioned or
  /// containered cookie *demands* the selector that identifies it, and says so
  /// with [`RequestError::IncompleteSendContext`] rather than guessing.
  ///
  /// Expiry is applied at send time, independently of whether the snapshot was
  /// created with [`ReadRequest::include_expired`].
  ///
  /// # Stated limitations
  ///
  /// `Site` is (scheme, host), not eTLD+1, so `SameSite=Lax`/`Strict` is
  /// **conservative**: it omits cookies a browser would send to a sibling
  /// subdomain, never the reverse. CHIPS ancestor state
  /// (`has_cross_site_ancestor`) is retained on the snapshot but not gated on,
  /// so a partitioned cookie may be over-included within a matching key. There
  /// is one same-site rule, not a schemeful/legacy dual mode. A caller needing
  /// browser-exact behavior needs a browser.
  ///
  /// # Errors
  ///
  /// - [`RequestError::InvalidUrl`] — `context`'s URL is unparseable or is not
  ///   HTTP/HTTPS.
  /// - [`RequestError::InvalidTopLevelSite`] — the same, for the top-level
  ///   site. It is rejected rather than ignored: ignoring it falls back to the
  ///   first-party assumption and sends more than the caller asked for.
  /// - [`RequestError::IncompleteSendContext`] — the snapshot positively
  ///   observes an isolated value the context does not select.
  ///   `required` names the missing selectors as stable identifiers.
  /// - [`RequestError::ClockUnrepresentable`] — the resolved clock is earlier
  ///   than the Unix epoch. It is not mapped to epoch 0, which would disable
  ///   expiry entirely.
  ///
  /// # Examples
  ///
  /// ```no_run
  /// use rookie_cookies::{read, ReadRequest, SendContext};
  ///
  /// let snapshot = read(ReadRequest::browser("chrome"))?;
  /// let header = snapshot.header(
  ///   &SendContext::url("https://example.com/")
  ///     .top_level_site("https://example.com")
  ///     .navigation(),
  /// )?;
  /// println!("{header}");
  /// # Ok::<(), rookie_cookies::Error>(())
  /// ```
  pub fn header(&self, context: &SendContext) -> Result<String> {
    map_job_result(self.header_for(context))
  }

  fn header_for(&self, context: &SendContext) -> anyhow::Result<String> {
    // 1. Parse both URLs before anything else. An unparseable top-level site
    //    must not silently degrade into the first-party assumption.
    let filter = GetFilter::for_url(&context.url)?;
    let request_site = site_from_url(&context.url).ok_or_else(|| RequestError::InvalidUrl {
      display: redact_url(&context.url),
    })?;
    let top_level_site = match context.top_level_site.as_deref() {
      None => None,
      Some(raw) => Some(
        site_from_url(raw).ok_or_else(|| RequestError::InvalidTopLevelSite {
          display: redact_url(raw),
        })?,
      ),
    };

    // 2. Resolve the clock.
    let now_epoch = unix_seconds(context.now.unwrap_or_else(SystemTime::now))
      .map_err(|_| RequestError::ClockUnrepresentable)?;

    // 3-4. A snapshot demands a selector as soon as ONE cookie positively
    //      observes the corresponding isolated value. There is no
    //      "more than one identity" threshold: two cookies in the same
    //      partition are just as unmergeable with an unpartitioned one.
    let required = self.missing_selectors(context);
    if !required.is_empty() {
      return Err(
        RequestError::IncompleteSendContext {
          display: redact_url(&context.url),
          required,
        }
        .into(),
      );
    }

    // The same-site context. With no top-level site supplied (and step 4 not
    // having errored), the request is assumed first-party.
    let same_site_context = top_level_site
      .as_ref()
      .is_none_or(|site| *site == request_site);
    let navigation = context.resource == ResourceKind::Navigation;
    let safe_method = context.method == MethodClass::Safe;

    // 5.
    let mut kept: Vec<&Cookie> = self
      .cookies
      .iter()
      .filter(|detailed| {
        is_unexpired(&detailed.cookie, now_epoch)
          && filter.keeps(&detailed.cookie)
          && isolation_matches(&detailed.context, context, top_level_site.as_ref())
          && same_site_permits(
            detailed.cookie.same_site,
            same_site_context,
            navigation,
            safe_method,
          )
      })
      .map(|detailed| &detailed.cookie)
      .collect();
    // 6. The 0.6-beta header order.
    kept.sort_by(|left, right| {
      right
        .path
        .len()
        .cmp(&left.path.len())
        .then_with(|| left.name.cmp(&right.name))
    });
    // 7.
    Ok(
      kept
        .into_iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; "),
    )
  }

  /// The selector tokens this snapshot demands and `context` did not supply,
  /// in the order the contract declares them, deduplicated.
  fn missing_selectors(&self, context: &SendContext) -> Vec<String> {
    let mut required = Vec::new();
    if context.top_level_site.is_none()
      && self
        .cookies
        .iter()
        .any(|detailed| partition_identity(&detailed.context) != PartitionIdentity::Unpartitioned)
    {
      required.push(selector::TOP_LEVEL_SITE.to_owned());
    }
    // `None` and `Some(0)` never demand a selector. Gating on them would make
    // `header` unusable against every browser version whose schema lacks these
    // columns -- which is most of them.
    if context.user_context_id.is_none()
      && self
        .cookies
        .iter()
        .any(|detailed| detailed.context.user_context_id.is_some_and(|id| id > 0))
    {
      required.push(selector::USER_CONTEXT_ID.to_owned());
    }
    if context.private_browsing_id.is_none()
      && self.cookies.iter().any(|detailed| {
        detailed
          .context
          .private_browsing_id
          .is_some_and(|id| id > 0)
      })
    {
      required.push(selector::PRIVATE_BROWSING_ID.to_owned());
    }
    required
  }
}

/// Whether one stored cookie's isolation identity admits this send.
///
/// Once a selector *has* been supplied, a cookie in another partition or
/// container is simply omitted -- not an error. The error in step 4 exists
/// only for the selector that was never supplied at all.
fn isolation_matches(
  stored: &crate::enums::CookieContext,
  context: &SendContext,
  top_level_site: Option<&Site>,
) -> bool {
  match partition_identity(stored) {
    // An unpartitioned cookie is sent in every top-level context. That is what
    // "unpartitioned" means, and it is why the missing-vs-default rule below
    // applies to container identity rather than to partitions.
    PartitionIdentity::Unpartitioned => {}
    PartitionIdentity::Unparsable => return false,
    PartitionIdentity::Site(site) => {
      if top_level_site != Some(&site) {
        return false;
      }
    }
  }
  // Missing vs default: a cookie whose container field is `None` is the
  // default container ONLY when the caller supplied no selector for it. Once
  // the caller says "container 2", the crate does not know an unlabelled
  // cookie belongs there, and guessing is how containers merge.
  if let Some(selected) = context.user_context_id {
    if stored.user_context_id != Some(selected) {
      return false;
    }
  }
  if let Some(selected) = context.private_browsing_id {
    if stored.private_browsing_id != Some(selected) {
      return false;
    }
  }
  true
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
/// profile and extraction selection determines its sources. In both cases,
/// Gecko-family session JSON is considered only when the request's
/// [`SessionPolicy`] is [`SessionPolicy::IncludeSession`].
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
  let browser_id = request.target.resolve()?.to_owned();
  let clock = SystemClock;
  let runtime = runtime_for_control(&clock, &request.control);
  let resolved_browser = registry::resolve_registered_browser(&browser_id)?;
  // Resolution and extraction share this one absolute budget. There is no
  // second request to build, so there is nothing that could reset it.
  let resolved_profile = match request.target.selection() {
    ProfileSelection::LegacyFirst => None,
    ProfileSelection::Query(query) => Some(registry::resolve_profile_query(
      &browser_id,
      query,
      &runtime,
    )?),
  };
  let selection = match resolved_profile.as_deref() {
    None => SnapshotSelection::LegacyFirst,
    Some(profile_id) => SnapshotSelection::Profile(profile_id),
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
  let outcome =
    browser_snapshot_with_runtime(canonical_id, selection, request.target.session(), runtime)?;
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
  /// Unlike [`direct_path::PathExtractRequest`], this type stays **portable**:
  /// it is what the bindings and the CLI wrap, and they need one options
  /// object that compiles everywhere with runtime validation. An invalid
  /// platform/source combination is rejected before any credential I/O, not
  /// at compile time.
  pub fn chromium_credentials(mut self, source: ChromiumCredentialSource) -> Self {
    self.credentials = Some(source);
    self
  }

  /// Reads only plaintext Chromium rows. Portable.
  pub fn chromium_plaintext(self) -> Self {
    self.chromium_credentials(ChromiumCredentialSource::PlaintextOnly)
  }

  /// Uses one registry browser identity for Chromium credentials. Valid on
  /// Unix; rejected on Windows before credential I/O.
  pub fn chromium_browser_id(self, id: impl Into<String>) -> Self {
    self.chromium_credentials(ChromiumCredentialSource::BrowserId(id.into()))
  }

  /// Uses a Windows Chromium `Local State` file. Rejected on Unix before
  /// credential I/O.
  pub fn chromium_local_state(self, local_state: impl Into<PathBuf>) -> Self {
    self.chromium_credentials(ChromiumCredentialSource::LocalStateFile(local_state.into()))
  }
}

/// Executes one [`FromPathRequest`] without registered-browser discovery.
///
/// The returned [`ReadResult::browser_id`] and [`ReadResult::profile_id`] are
/// both `None`; the explicit path, not registry identity, is authoritative
/// for this operation.
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
  // The `_inner` seam, not the public job function: `from_path` maps the chain
  // to `Error` once, at its own edge. Going through the public direct-path
  // edge first would flatten a `BoundaryStop` into an opaque `Error` and lose
  // the stop classification here.
  let cookies = direct_path::detailed_from_path_inner(
    PathExtractRequest::with_credentials(&request.path, request.credentials)
      .execution(request.control),
  )?;
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
  /// Retained in the snapshot, but a non-match against every send context.
  unparsable_partition_key: u64,
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
    if self.unparsable_partition_key > 0 {
      warnings.record(
        ReadWarningCode::UnparsablePartitionKey,
        self.unparsable_partition_key,
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
      if !crate::browser::cookie_record::host_identity_survives(&cookie.domain) {
        omitted.malformed_host_identity += 1;
        return false;
      }
      if !sendable_octets(&cookie.name, &cookie.value) {
        omitted.invalid_octets += 1;
        return false;
      }
      // The row is kept -- a partition key this build cannot normalize is not
      // a reason to drop a cookie from the inventory -- but it will never
      // match a send context, so the loss has to be visible here. `header`
      // takes `&self` and cannot add a warning of its own.
      if partition_identity(&detailed.context) == PartitionIdentity::Unparsable {
        omitted.unparsable_partition_key += 1;
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
mod send_context_tests;
#[cfg(test)]
mod tests;
