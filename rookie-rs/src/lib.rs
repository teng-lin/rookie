// Compatibility APIs remain callable through 0.6 while their downstream use
// is deprecated. Internal adapters intentionally exercise those exact paths.
#![allow(deprecated)]

// Public

// Common
pub mod common;
pub mod config;
pub mod direct_path;
pub mod report;
mod utils;
pub use common::enums;

// Browser
#[cfg(target_os = "windows")]
pub use browser::internet_explorer::internet_explorer_based;
#[cfg(target_os = "macos")]
pub use browser::safari::safari_based;
pub use browser::{
  chromium::{chromium_based, chromium_based_detailed},
  mozilla::{firefox_based, firefox_based_detailed, MozillaProfile},
};

// Private
mod browser;
mod compatibility_dispatch;
mod header_filter;
mod read;
mod request_error;
#[cfg(test)]
use anyhow::bail;
pub use anyhow::{self, Result};
use enums::Cookie;
pub use read::{from_path, profiles, read, FromPathRequest, ReadRequest, ReadResult, ReadWarning};
pub use request_error::RequestError;
#[cfg(target_os = "linux")]
mod linux;
use std::fmt;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

/// A handle that can cancel an in-flight [`extract`] call from another
/// thread.
///
/// Cloning a handle shares the same cancellation state: calling
/// [`cancel`](Self::cancel) on any clone cancels the operation every clone
/// (including the one an in-flight [`Request`] is holding) observes.
///
/// This only tracks whether cancellation was *requested* through this
/// handle, not whether the operation is still running: calling
/// [`cancel`](Self::cancel) after the call already stopped for an unrelated
/// reason (it timed out, or completed) still records the request and
/// returns `true` -- there is nothing left observing it, so the request is
/// simply harmless, not rejected. Only a second cancellation *through this
/// same handle* (a repeat call, or a clone that already won the race) is a
/// no-op and returns `false`.
#[derive(Clone, Default)]
pub struct CancellationHandle(pub(crate) common::deadline::CancellationToken);

impl CancellationHandle {
  /// Creates a handle for one [`extract`] call, not yet cancelled.
  pub fn new() -> Self {
    Self::default()
  }

  /// Requests cancellation. Returns `true` the first time this handle (or
  /// any of its clones) records it, `false` on every call after that --
  /// see the type-level docs for what this does and does not tell you about
  /// whether the operation is still running.
  pub fn cancel(&self) -> bool {
    self.0.cancel()
  }

  /// Reports whether [`cancel`](Self::cancel) has already been called on
  /// this handle or any of its clones. Like `cancel`, this does not by
  /// itself imply the operation is still running -- it reports a request,
  /// not the extraction's current state.
  pub fn is_cancelled(&self) -> bool {
    self.0.is_cancelled()
  }
}

impl fmt::Debug for CancellationHandle {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("CancellationHandle")
      .field("cancelled", &self.is_cancelled())
      .finish()
  }
}

impl PartialEq for CancellationHandle {
  /// Two handles are equal exactly when they share the same underlying
  /// cancellation state (are clones of one another), not when they happen
  /// to be in the same cancelled/not-cancelled state.
  fn eq(&self, other: &Self) -> bool {
    self.0.same_as(&other.0)
  }
}

impl Eq for CancellationHandle {}

/// Why a cancellable operation in this crate (e.g. [`extract`]) stopped
/// before producing a result, when it stopped for a reason other than an
/// ordinary request, discovery, or extraction error.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
  /// The request's [`Request::timeout`] elapsed.
  TimedOut,
  /// A [`CancellationHandle`] passed to the request was cancelled.
  Cancelled,
  /// An internal resource ceiling, not caller-controlled, was reached.
  ResourceExhausted,
}

/// Reports why `error` stopped, if it stopped for a timeout, cancellation,
/// or resource-exhaustion reason rather than an ordinary request or
/// discovery error. Returns `None` for every other error this crate
/// returns.
///
/// # Examples
///
/// ```no_run
/// let request = rookie_cookies::Request::browser("chrome")
///   .timeout(std::time::Duration::from_secs(5));
/// if let Err(error) = rookie_cookies::extract(request) {
///   if rookie_cookies::stop_reason(&error) == Some(rookie_cookies::StopReason::TimedOut) {
///     eprintln!("extraction timed out");
///   }
/// }
/// ```
pub fn stop_reason(error: &anyhow::Error) -> Option<StopReason> {
  error.chain().find_map(|cause| {
    cause
      .downcast_ref::<common::deadline::BoundaryStop>()
      .map(|stop| match stop {
        common::deadline::BoundaryStop::TimedOut => StopReason::TimedOut,
        common::deadline::BoundaryStop::Cancelled => StopReason::Cancelled,
        common::deadline::BoundaryStop::ResourceExhausted => StopReason::ResourceExhausted,
      })
  })
}

/// Which side of the FFI boundary an error should be attributed to, for
/// bindings that raise distinct exception types rather than one flat error
/// class.
///
/// This is a request/engine split only -- a returned [`report::ExtractionReport`]
/// with `status: failed` is a successful *return*, not an error, and is
/// never classified here. See [`fault_kind`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
  /// The caller's input was invalid, e.g. an unsupported option or an
  /// explicit source that does not match its declared kind. A caller can
  /// fix this by changing what it passed in.
  Request,
  /// Extraction or engine failure unrelated to caller input, including a
  /// stopped-early [`StopReason`] -- [`stop_reason`] remains the finer
  /// grained tool for distinguishing those from each other.
  Engine,
}

/// Classifies `error` as a [`FaultKind::Request`] or [`FaultKind::Engine`]
/// fault, for bindings that raise distinct exception types at the FFI
/// boundary.
///
/// Only errors carrying a structured, downcastable cause classify as
/// [`FaultKind::Request`]: [`direct_path::DirectPathError`] and
/// [`RequestError`]. [`RequestError`] is produced for an unknown browser id
/// on the registered-browser resolve path and for empty / unknown /
/// ambiguous / lossy profile queries. Unstructured `bail!` on other
/// surfaces — including `chromium_based_with_browser_id` — still
/// classifies as [`FaultKind::Engine`].
///
/// This is also coarser than "caller-fixable" in one more way: every
/// [`direct_path::DirectPathError`] classifies as `Request`, including
/// [`direct_path::InvalidCookieSourceReason::SourceInspectionFailed`] --
/// which covers a genuinely corrupt/locked/unreadable source as well as a
/// caller simply pointing at the wrong file. Both currently surface the
/// same way; splitting that reason out to `Engine` is a reasonable future
/// refinement, not attempted here.
///
/// # Examples
///
/// ```no_run
/// let request = rookie_cookies::direct_path::ChromiumPathRequest::new(
///   "/nonexistent/Cookies",
/// );
/// if let Err(error) = rookie_cookies::direct_path::chromium_cookies_from_path(request) {
///   assert_eq!(rookie_cookies::fault_kind(&error), rookie_cookies::FaultKind::Request);
/// }
/// ```
pub fn fault_kind(error: &anyhow::Error) -> FaultKind {
  // A timeout or cancellation checked *during* source classification still
  // gets wrapped in a `DirectPathError` (inspection failed, for whichever
  // reason), so this must rule out an operational stop first: that is never
  // a caller input mistake, regardless of what wraps it afterward.
  if stop_reason(error).is_some() {
    return FaultKind::Engine;
  }
  // `direct_path::DirectPathError` is attached with `anyhow::Error::context`,
  // not always constructed as the root cause, so this must use
  // `anyhow::Error::downcast_ref`'s own context-aware matching rather than
  // `.chain()` -- a `.context(value)` layer's concrete stored type is an
  // anyhow-internal wrapper, which `.chain()`'s `dyn StdError::downcast_ref`
  // cannot see through, unlike `Error::downcast_ref` itself.
  if error
    .downcast_ref::<direct_path::DirectPathError>()
    .is_some()
    || error.downcast_ref::<RequestError>().is_some()
  {
    FaultKind::Request
  } else {
    FaultKind::Engine
  }
}

/// One extraction operation, expressed as data rather than a function call.
///
/// A named function such as [`chrome`] can only ever name the one browser it
/// was written for. `Request` carries that same selection as a value, so it
/// reaches any browser [`supported_browsers`] lists — including
/// registry-only entries (registered forks and alternate builds) no named
/// function can name. It does not add channel selection: like the named
/// functions, it always resolves one browser's first legacy-compatible
/// profile — see [`browser`] for that limit and how to cover every profile
/// instead.
///
/// # Examples
///
/// ```no_run
/// let request = rookie_cookies::Request::browser("chrome")
///   .domains(Some(vec!["example.com".to_string()]));
/// let cookies = rookie_cookies::extract(request)?;
/// # Ok::<(), rookie_cookies::anyhow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
  browser_id: String,
  profile: Option<String>,
  domains: Option<Vec<String>>,
  timeout: Option<std::time::Duration>,
  cancellation: Option<CancellationHandle>,
}

impl Request {
  /// Selects one browser by canonical ID or registered alias, as returned by
  /// [`supported_browsers`].
  pub fn browser(id: impl Into<String>) -> Self {
    Self {
      browser_id: id.into(),
      profile: None,
      domains: None,
      timeout: None,
      cancellation: None,
    }
  }

  /// Selects one profile by opaque `profile_id`, display name, directory
  /// name, or a non-lossy full path. Resolved at extract time, not here.
  /// An empty string is [`RequestError::EmptyProfileSelector`].
  pub fn profile(mut self, query: impl Into<String>) -> Self {
    self.profile = Some(query.into());
    self
  }

  /// Restricts extraction to the given domains, or clears a prior
  /// restriction on `None`.
  ///
  /// Takes `Option<Vec<String>>` rather than `Vec<String>` (unlike
  /// [`direct_path::ChromiumPathRequest::domains`](crate::direct_path::ChromiumPathRequest::domains)/
  /// [`direct_path::DirectPathRequest::domains`](crate::direct_path::DirectPathRequest::domains))
  /// so [`browser`]'s own `Option` parameter forwards here directly.
  pub fn domains(mut self, domains: Option<Vec<String>>) -> Self {
    self.domains = domains;
    self
  }

  /// Overrides the default 30-second extraction budget.
  pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
    self.timeout = Some(timeout);
    self
  }

  /// Lets `handle` cancel this request from another thread while it runs —
  /// see [`CancellationHandle`].
  pub fn cancellation(mut self, handle: CancellationHandle) -> Self {
    self.cancellation = Some(handle);
    self
  }
}

/// Runs one [`Request`] and returns its cookies.
///
/// `Request`/`extract` is the execution path underneath [`browser`] and
/// every named compatibility function that selects one browser by a fixed
/// string (e.g. [`chrome`], [`firefox`]) — they build a `Request` and run it
/// here rather than dispatching independently. [`firefox_profile`] (which
/// additionally selects a profile) and [`load`] (which iterates a browser
/// set) do not.
///
/// # Errors
///
/// See [`browser`], which shares this function's error and selection
/// behavior. A request that stopped because of [`Request::timeout`] or a
/// cancelled [`CancellationHandle`] returns an error [`stop_reason`] reports
/// on, rather than a plain request/discovery error.
///
/// # Examples
///
/// ```no_run
/// let cookies = rookie_cookies::extract(rookie_cookies::Request::browser("chrome"))?;
/// # Ok::<(), rookie_cookies::anyhow::Error>(())
/// ```
pub fn extract(request: Request) -> Result<Vec<Cookie>> {
  let clock = common::deadline::SystemClock;
  let runtime = common::deadline::boundary_runtime(
    &clock,
    request.timeout,
    request
      .cancellation
      .map(|handle| handle.0)
      .unwrap_or_default(),
  );
  match request.profile {
    None => {
      browser::legacy::browser_cookies_with_runtime(&request.browser_id, request.domains, &runtime)
    }
    Some(query) => {
      let profile_id =
        browser::registry::resolve_profile_query(&request.browser_id, &query, &runtime)?;
      let report = browser::report_build::browser_extraction_report_with_runtime(
        &request.browser_id,
        Some(&profile_id),
        request.domains,
        &runtime,
      )?;
      flatten_selected_report_cookies(report)
    }
  }
}

/// Labeled extract. No profile → today's [`browser_report`]`(id, None)`
/// (`AllProfiles`). With a profile query → one-profile report.
pub fn extract_report(request: Request) -> Result<report::ExtractionReport> {
  let clock = common::deadline::SystemClock;
  let runtime = common::deadline::boundary_runtime(
    &clock,
    request.timeout,
    request
      .cancellation
      .map(|handle| handle.0)
      .unwrap_or_default(),
  );
  let profile_id = match request.profile.as_deref() {
    None => None,
    Some(query) => Some(browser::registry::resolve_profile_query(
      &request.browser_id,
      query,
      &runtime,
    )?),
  };
  browser::report_build::browser_extraction_report_with_runtime(
    &request.browser_id,
    profile_id.as_deref(),
    request.domains,
    &runtime,
  )
}

pub(crate) fn flatten_selected_report_cookies(
  report: report::ExtractionReport,
) -> Result<Vec<Cookie>> {
  let mut cookies = Vec::new();
  let mut any_selected_success = false;
  for profile in report.profiles {
    for source in profile.sources {
      if source.selected && source.status.as_str() == "succeeded" {
        any_selected_success = true;
        cookies.extend(source.cookies);
      }
    }
  }
  if !any_selected_success {
    anyhow::bail!("no selected cookie source succeeded");
  }
  Ok(cookies)
}

/// Extracts cookies from one registered browser by canonical ID or alias.
///
/// This reaches every browser [`supported_browsers`] lists, including
/// registry-only entries that have no dedicated named function (e.g.
/// [`chrome`], [`firefox`]) — but, like those named selectors, it resolves
/// only the browser's first installation and first legacy-compatible
/// profile, not every profile of every installed channel. It is a
/// convenience over [`extract`]`(`[`Request::browser`]`(id).domains(domains))`.
/// Use [`browser_report`] or [`browser_profiles`] to cover every installation
/// and profile instead.
///
/// # Arguments
///
/// * `id` - A canonical browser ID or registered alias from
///   [`supported_browsers`]
/// * `domains` - An optional list for getting specific domains only
///
/// # Errors
///
/// An unknown ID or alias is a request error, matching the named selectors'
/// behavior for their one hardcoded browser.
///
/// # Examples
///
/// ```no_run
/// let cookies = rookie_cookies::browser("chrome", None)?;
/// # Ok::<(), rookie_cookies::anyhow::Error>(())
/// ```
pub fn browser(id: &str, domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  extract(Request::browser(id).domains(domains))
}

/// Thin compatibility projection over registry-backed discovery/extraction.
fn named_browser(name: &str, domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  browser(name, domains)
}

/// Extracts an explicit Chromium cookie database using registry-resolved key
/// identity on Unix.
///
/// `browser_id` should be a canonical ID (or registered alias) from
/// [`supported_browsers`]. It controls Linux keyring and macOS Keychain lookup;
/// the database path is never guessed to be Chrome. `None` is accepted only
/// for databases containing plaintext rows exclusively.
#[cfg(unix)]
#[deprecated(
  since = "0.6.0",
  note = "use direct_path::chromium_cookies_from_path with ChromiumPathRequest"
)]
pub fn chromium_based_with_browser_id(
  browser_id: Option<&str>,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<Cookie>> {
  match browser_id
    .map(browser::registry::chromium_key_credentials)
    .transpose()?
    .flatten()
  {
    Some(config) => chromium_based(&config, db_path, domains, force_kill),
    None => browser::chromium::chromium_based_plaintext_only(db_path, domains, force_kill),
  }
}

/// Detailed counterpart to [`chromium_based_with_browser_id`].
#[cfg(unix)]
#[deprecated(
  since = "0.6.0",
  note = "use direct_path::chromium_cookies_from_path_detailed with ChromiumPathRequest"
)]
pub fn chromium_based_detailed_with_browser_id(
  browser_id: Option<&str>,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<enums::DetailedCookie>> {
  match browser_id
    .map(browser::registry::chromium_key_credentials)
    .transpose()?
    .flatten()
  {
    Some(config) => chromium_based_detailed(&config, db_path, domains, force_kill),
    None => browser::chromium::chromium_based_detailed_plaintext_only(db_path, domains, force_kill),
  }
}

/// Returns the rookie-cookies version.
/// Format: `<semver>(<commit>)`
///
/// # Examples
///
/// ```
/// let version = rookie_cookies::version();
/// println!("{}", version);
/// ```
pub fn version() -> String {
  format!("{} ({})", env!("CARGO_PKG_VERSION"), env!("COMMIT_HASH"))
}

/// Returns every browser registered for the running OS.
///
/// Registration is not detection: this never touches the filesystem, so a
/// descriptor here only means rookie knows where that browser would keep its
/// cookies and which cipher tiers this build could decrypt. Use
/// [`browser_profiles`] to find out what is actually installed.
///
/// An OS with no registry entries has no registered browsers, which is an empty
/// list rather than an error. A malformed embedded registry is returned as an
/// error so callers never confuse an internal failure with an empty inventory.
///
/// # Examples
///
/// ```no_run
/// for browser in rookie_cookies::supported_browsers()? {
///   println!("{} ({})", browser.id, browser.display_name);
/// }
/// # Ok::<(), rookie_cookies::anyhow::Error>(())
/// ```
pub fn supported_browsers() -> Result<Vec<report::BrowserDescriptor>> {
  browser::report_build::supported_browser_descriptors()
}

/// Returns the discovered profiles of one registered browser.
///
/// # Arguments
///
/// * `browser_id` - A canonical browser ID or alias from [`supported_browsers`]
///
/// # Errors
///
/// An unknown ID or alias is a request error. So is a browser whose every
/// detected installation root failed enumeration, because an empty list would
/// be indistinguishable from "not installed"; [`browser_report`] carries the
/// per-root diagnostics in that case. A known browser with nothing installed
/// returns an empty list rather than an error, and one failing root does not
/// hide the profiles another root yielded.
///
/// # Examples
///
/// ```no_run
/// for profile in rookie_cookies::browser_profiles("chrome")? {
///   println!("{} {}", profile.profile.profile_id, profile.profile.display_name);
/// }
/// # Ok::<(), rookie_cookies::anyhow::Error>(())
/// ```
pub fn browser_profiles(browser_id: &str) -> Result<Vec<report::ProfileDescriptor>> {
  browser::report_build::browser_profile_descriptors(browser_id)
}

/// Returns every discovered Google Chrome profile, preferring the active one.
///
/// This is an additive registry-backed API. It does not change [`chrome`],
/// whose legacy first/default-profile selector remains frozen, or the generic
/// default-first ordering of [`browser_profiles`]. When Chrome's `Local State`
/// names a last-used profile, that profile is listed first; the remaining
/// active profiles follow in their declared order. Missing, stale, or malformed
/// activity hints safely fall back to the generic discovery order.
///
/// Each result retains its stable profile/installation IDs and ordered cookie
/// source descriptors. Pass a profile ID, display name, directory name, or a
/// full path to [`chrome_profile`]. A full path is selectable only when
/// `profile.path_lossy` is false; otherwise use the opaque profile ID. IDs are
/// also recommended when multiple installations contain same-named profiles.
///
/// # Examples
///
/// ```no_run
/// for profile in rookie_cookies::chrome_profiles()? {
///   println!("{} {}", profile.profile.profile_id, profile.profile.display_name);
/// }
/// # Ok::<(), rookie_cookies::anyhow::Error>(())
/// ```
pub fn chrome_profiles() -> Result<Vec<report::ProfileDescriptor>> {
  browser::report_build::chrome_profile_descriptors()
}

/// Extracts one selected Google Chrome profile as a grouped report.
///
/// Unlike the legacy [`chrome`] function, this registry-backed selector keeps
/// the selected profile identity, cookie-source provenance, partial failures,
/// and typed discovery issues. `profile` may be the opaque profile ID returned
/// by [`chrome_profiles`], a display name, a directory name, or a non-lossy
/// full path. When a descriptor has `profile.path_lossy == true`, its display
/// path cannot round-trip through this UTF-8 selector and its opaque ID is
/// required. Ambiguous names are rejected instead of silently selecting the
/// wrong channel or installation.
///
/// # Examples
///
/// ```no_run
/// let profiles = rookie_cookies::chrome_profiles()?;
/// if let Some(preferred) = profiles.first() {
///   let report = rookie_cookies::chrome_profile(
///     preferred.profile.profile_id.as_str(),
///     Some(vec!["example.com".to_owned()]),
///   )?;
///   println!("{}", report.status);
/// }
/// # Ok::<(), rookie_cookies::anyhow::Error>(())
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use extract_report(Request::browser(\"chrome\").profile(q)) \
          or browser_report(\"chrome\", Some(q), domains)"
)]
pub fn chrome_profile(
  profile: &str,
  domains: Option<Vec<String>>,
) -> Result<report::ExtractionReport> {
  extract_report(Request::browser("chrome").profile(profile).domains(domains))
}

/// Extracts cookies from one browser as a grouped report.
///
/// Unlike the named selectors, this covers every installation and profile of
/// the browser and keeps failures visible instead of collapsing them into an
/// error or a short list: cookies stay attached to the source they came from,
/// alongside that source's status, acquisition strategy, counters, and issues.
///
/// # Arguments
///
/// * `browser_id` - A canonical browser ID or alias from [`supported_browsers`]
/// * `profile_id` - An optional [`ProfileId`](report::ProfileId) from
///   [`browser_profiles`], restricting the report to that one profile. Display
///   paths and names are not selection keys.
/// * `domains` - An optional list for getting specific domains only
///
/// # Errors
///
/// Only a bad request fails: an unknown browser ID or alias, or a profile ID
/// that this browser did not yield. Extraction problems are reported instead —
/// a browser that is registered but not installed is an `Ok` report with
/// [`no_sources`](report::ReportStatusCode::no_sources), and a total extraction
/// failure is an `Ok` report with
/// [`failed`](report::ReportStatusCode::failed).
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let report = rookie_cookies::browser_report("chrome", None, Some(domains))?;
/// println!("{}: {} cookies", report.status, report.summary.cookies_emitted);
/// # Ok::<(), rookie_cookies::anyhow::Error>(())
/// ```
pub fn browser_report(
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<Vec<String>>,
) -> Result<report::ExtractionReport> {
  let mut request = Request::browser(browser_id).domains(domains);
  if let Some(query) = profile_id {
    request = request.profile(query);
  }
  extract_report(request)
}

/// Extracts cookies from every registered browser as one grouped report.
///
/// This is the report-shaped counterpart to [`load`], not a replacement for it:
/// `load` keeps its historical browser set and flat output, while this covers
/// every registered browser on the running OS. Registered browsers that are not
/// installed are summarized in
/// [`browsers_not_detected`](report::ReportStats::browsers_not_detected) rather
/// than emitting an issue each; installed browsers that fail do emit issues.
///
/// # Arguments
///
/// * `domains` - An optional list for getting specific domains only
///
/// # Errors
///
/// There is no browser ID to reject here, so this fails only if the registry
/// itself cannot be read. A browser that fails discovery or extraction does not
/// abort the others; it becomes an issue on the returned report.
///
/// # Examples
///
/// ```no_run
/// let report = rookie_cookies::load_report(None)?;
/// println!(
///   "{}/{} browsers detected",
///   report.summary.browsers_detected, report.summary.registered_browsers
/// );
/// # Ok::<(), rookie_cookies::anyhow::Error>(())
/// ```
pub fn load_report(domains: Option<Vec<String>>) -> Result<report::ExtractionReport> {
  browser::report_build::load_extraction_report(domains)
}

/// Returns cookies from Firefox
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::firefox(Some(domains));
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"firefox\", domains) or extract(Request::browser(\"firefox\")) instead"
)]
pub fn firefox(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("firefox", domains)
}

/// Returns every Firefox profile that holds a cookie database.
///
/// [`firefox`] returns whichever profile it finds first, preferring the default
/// one; this lists them all so a caller can choose deliberately and pass the
/// choice to [`firefox_profile`].
///
/// Defaults are per-installation, so more than one profile can report
/// `is_default` when several Firefox installations are present.
///
/// # Examples
///
/// ```no_run
/// for profile in rookie_cookies::firefox_profiles()? {
///   println!("{} {} default={}", profile.name, profile.path.display(), profile.is_default);
/// }
/// # Ok::<(), rookie_cookies::anyhow::Error>(())
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use browser_profiles(\"firefox\") for ProfileDescriptor \
          (includes session-only profiles this list hides)"
)]
pub fn firefox_profiles() -> Result<Vec<MozillaProfile>> {
  browser::legacy::gecko_profiles("firefox")
}

/// Returns cookies from a specific Firefox profile.
///
/// # Arguments
///
/// * `profile` - The profile's name, directory name, or full path, as reported
///   by [`firefox_profiles`]
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::firefox_profile("default-release", Some(domains));
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use extract(Request::browser(\"firefox\").profile(q)); \
          list with browser_profiles(\"firefox\")"
)]
pub fn firefox_profile(profile: &str, domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  extract(
    Request::browser("firefox")
      .profile(profile)
      .domains(domains),
  )
}

/// Returns cookies from LibreWolf
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::librewolf(Some(domains));
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"librewolf\", domains) or extract(Request::browser(\"librewolf\")) instead"
)]
pub fn librewolf(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("librewolf", domains)
}

/// Returns cookies from Cachy Browser (Linux only)
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::cachy(Some(domains));
/// ```
#[cfg(target_os = "linux")]
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"cachy\", domains) or extract(Request::browser(\"cachy\")) instead"
)]
pub fn cachy(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("cachy", domains)
}

/// Returns cookies from Chrome
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::chrome(Some(domains));
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"chrome\", domains) or extract(Request::browser(\"chrome\")) instead"
)]
pub fn chrome(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("chrome", domains)
}

/// Returns cookies from Chromium
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::chromium(Some(domains));
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"chromium\", domains) or extract(Request::browser(\"chromium\")) instead"
)]
pub fn chromium(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("chromium", domains)
}

/// Returns cookies from Brave
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::brave(Some(domains));
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"brave\", domains) or extract(Request::browser(\"brave\")) instead"
)]
pub fn brave(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("brave", domains)
}

/// Returns cookies from Arc
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::arc(Some(domains));
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"arc\", domains) or extract(Request::browser(\"arc\")) instead"
)]
pub fn arc(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("arc", domains)
}

/// Returns cookies from Firefox
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::zen(Some(domains));
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"zen\", domains) or extract(Request::browser(\"zen\")) instead"
)]
pub fn zen(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("zen", domains)
}

/// Returns cookies from Edge
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::edge(Some(domains));
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"edge\", domains) or extract(Request::browser(\"edge\")) instead"
)]
pub fn edge(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("edge", domains)
}

/// Returns cookies from Vivaldi
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::vivaldi(Some(domains));
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"vivaldi\", domains) or extract(Request::browser(\"vivaldi\")) instead"
)]
pub fn vivaldi(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("vivaldi", domains)
}

/// Returns cookies from Opera
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::opera(Some(domains));
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"opera\", domains) or extract(Request::browser(\"opera\")) instead"
)]
pub fn opera(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("opera", domains)
}

/// Returns cookies from Opera GX
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::opera_gx(Some(domains));
/// ```
#[cfg_attr(
  any(target_os = "macos", target_os = "windows"),
  deprecated(
    since = "0.6.0",
    note = "use browser(\"opera_gx\", domains) or extract(Request::browser(\"opera_gx\")) instead"
  )
)]
#[cfg_attr(
  not(any(target_os = "macos", target_os = "windows")),
  deprecated(
    since = "0.5.9",
    note = "Opera GX is unsupported on this target; this compatibility shim will be removed in 0.7"
  )
)]
pub fn opera_gx(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  compatibility_dispatch::opera_gx(domains)
}

/// Returns cookies from Octo Browser
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::octo_browser(Some(domains));
/// ```
#[cfg(target_os = "windows")]
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"octo_browser\", domains) or extract(Request::browser(\"octo_browser\")) instead"
)]
pub fn octo_browser(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("octo_browser", domains)
}

/// Returns cookies from Safari (macOS only)
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::safari(Some(domains));
/// ```
#[cfg(target_os = "macos")]
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"safari\", domains) or extract(Request::browser(\"safari\")) instead"
)]
pub fn safari(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("safari", domains)
}

/// Returns cookies from Internet Explorer (Windows only)
///
/// Its cookie database uses the ESE (Extensible Storage Engine) format,
/// read here by linking an unmodified native C library (`libesedb`)
/// in-process with no process isolation, so a malformed or malicious
/// database can crash the whole host process rather than fail as a typed
/// error. Unlike this crate's bundled SQLite parser — pinned to an exact
/// version with its own tracked security inventory
/// (`docs/sqlite-security.md`) — `libesedb` carries no such inventory.
/// Containing that gap would mean running the parser in a sandboxed
/// subprocess; the Internet Explorer 11 browser app was discontinued in
/// 2022, and this crate is not planning to build that containment for it.
/// Internet Explorer support is deprecated for removal in a future major
/// version instead. `browser("internet_explorer", domains)` /
/// `extract(Request::browser("internet_explorer"))` remain available for
/// the rest of the deprecation window.
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::internet_explorer(Some(domains));
/// ```
#[cfg(target_os = "windows")]
#[deprecated(
  since = "0.6.0",
  note = "Internet Explorer support is deprecated for removal; the Internet Explorer browser app was discontinued in 2022"
)]
pub fn internet_explorer(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("internet_explorer", domains)
}

#[cfg(test)]
fn load_from_browsers<F>(
  browser_types: &[(&'static str, F)],
  domains: Option<Vec<String>>,
) -> Result<Vec<Cookie>>
where
  F: Fn(Option<Vec<String>>) -> Result<Vec<Cookie>>,
{
  let mut cookies = Vec::new();
  let mut errors: Vec<String> = Vec::new();
  let mut successful_extractions = 0;

  for (browser_name, browser_fn) in browser_types.iter() {
    match browser_fn(domains.clone()) {
      Ok(browser_cookies) => {
        successful_extractions += 1;
        cookies.extend(browser_cookies);
      }
      Err(err) if browser::legacy::is_browser_not_installed(&err) => {
        log::debug!("rookie_cookies::load skipping uninstalled {browser_name}: {err}");
      }
      Err(err) => {
        log::warn!("rookie_cookies::load skipping {browser_name}: {err}");
        errors.push(format!("{browser_name}: {err}"));
      }
    }
  }

  // Missing profiles were not extraction attempts. If at least one installed
  // browser failed and none succeeded, surface the real failures; a machine
  // with no supported browser installed legitimately has no cookies.
  if successful_extractions == 0 && !errors.is_empty() {
    bail!("all browser extractions failed:\n  {}", errors.join("\n  "));
  }

  Ok(cookies)
}

fn aggregate_load_failure(
  errors: &[String],
  stop: Option<common::deadline::BoundaryStop>,
) -> anyhow::Error {
  let summary = if errors.is_empty() {
    // Reachable when the shared deadline/cancellation stopped `load()`
    // before any browser's own extraction attempt produced an error to
    // record -- e.g. every browser attempted before the stop was merely
    // uninstalled (not an "error"), and no browser was ever attempted after
    // it. `stop` (below) is always `Some` in this branch.
    "the operation stopped before any browser extraction reported an error".to_owned()
  } else {
    format!("all browser extractions failed:\n  {}", errors.join("\n  "))
  };
  match stop {
    Some(stop) => anyhow::Error::new(stop).context(summary),
    None => anyhow::anyhow!(summary),
  }
}

/// Returns cookies from all browsers
///
/// This is a best-effort aggregator: browsers are probed concurrently on a
/// small bounded worker pool (see [`common::concurrency::fan_out`], not part
/// of the public API) sharing one deadline/cancellation budget, rather than
/// one at a time -- a slow or hung source no longer starves every other
/// source's share of that budget. Individual extraction failures are
/// surfaced via [`log::warn!`] but do not abort the load (a locked profile or
/// a decrypt failure on one browser should not lose cookies from the
/// others). Browsers without a discoverable profile are skipped normally. If
/// you need to know which browsers failed, hook a logger like
/// `tracing-subscriber` and watch for `rookie_cookies::load` warnings.
///
/// The returned cookies are grouped by browser in the same fixed order every
/// call attempts browsers in ([`load_report`]'s browser ordering is tracked
/// separately, from the registry rather than this function's own list),
/// regardless of which browser's extraction actually finished first. Once
/// the shared deadline or cancellation trips, no not-yet-started browser is
/// attempted, but a browser already in flight at that moment still runs to
/// completion and its cookies are kept.
///
/// Returns `Err` only when at least one installed browser is found, every
/// attempted extraction fails, and none succeeds. The aggregate message lists
/// only genuine extraction failures. If no supported browser is installed,
/// returns an empty list.
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::load(Some(domains));
/// ```
pub fn load(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let browser_types = compatibility_dispatch::legacy_load_browsers();
  let names: Vec<&str> = browser_types.iter().map(|(name, _)| *name).collect();
  let clock = common::deadline::SystemClock;
  let runtime = common::deadline::BoundaryRuntime::standard(&clock);
  let results = common::concurrency::fan_out(
    &names,
    common::concurrency::DEFAULT_FAN_OUT_WIDTH,
    &runtime,
    |browser_name| {
      browser::legacy::browser_cookies_with_runtime(browser_name, domains.clone(), &runtime)
    },
  );
  // `fan_out` silently stops claiming further browsers once the runtime
  // trips, so a shorter-than-`names` result set is itself evidence of a
  // stop even if no individual browser's own attempt happened to observe
  // and report it (e.g. every claimed browser was merely uninstalled).
  let attempted = results.len();
  let mut cookies = Vec::new();
  let mut errors = Vec::new();
  let mut terminal_stop = None;
  let mut successful_extractions = 0;
  for (browser_name, result) in names.iter().copied().zip(results) {
    match result {
      Ok(browser_cookies) => {
        successful_extractions += 1;
        cookies.extend(browser_cookies);
      }
      Err(error) if browser::legacy::is_browser_not_installed(&error) => {
        log::debug!("rookie_cookies::load skipping uninstalled {browser_name}: {error}");
      }
      Err(error) => {
        let stopped = error.chain().find_map(|cause| {
          cause
            .downcast_ref::<common::deadline::BoundaryStop>()
            .copied()
        });
        log::warn!("rookie_cookies::load skipping {browser_name}: {error}");
        errors.push(format!("{browser_name}: {error}"));
        if stopped.is_some() && terminal_stop.is_none() {
          terminal_stop = stopped;
        }
      }
    }
  }
  if attempted < names.len() && terminal_stop.is_none() {
    terminal_stop = runtime.check().err();
  }
  if successful_extractions == 0 && (!errors.is_empty() || terminal_stop.is_some()) {
    return Err(aggregate_load_failure(&errors, terminal_stop));
  }
  Ok(cookies)
}

#[cfg(test)]
use direct_path::CookieSourceKind as AnyBrowserSource;

/// Inspects the source's on-disk signature before choosing a decoder family.
#[cfg(test)]
fn sniff_cookie_source(path: &std::path::Path) -> Result<AnyBrowserSource> {
  direct_path::classify_cookie_source_legacy(path)
}

/// Returns cookies from specific browser
/// Useful for CLI apps
///
/// # Arguments
///
/// * `cookies_path` - Absolute path for cookies file
/// * `domains` - Optional list that for getting specific domains only
/// * `key_path` - Optional absolute path for key required to decrypt the cookies (required for chrome)
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies_path = "C:\\Users\\User\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\default\\network\\Cookies";
/// let key_path = "C:\\Users\\User\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Local State";
/// let cookies = rookie_cookies::any_browser(cookies_path, None, Some(key_path)).unwrap();
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use direct_path::cookies_from_path with DirectPathRequest"
)]
pub fn any_browser(
  cookies_path: &str,
  domains: Option<Vec<String>>,
  key_path: Option<&str>,
) -> Result<Vec<Cookie>> {
  compatibility_dispatch::any_browser(cookies_path, domains, key_path)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::common::enums::SAME_SITE_UNSPECIFIED;

  type BrowserEntry = (&'static str, fn(Option<Vec<String>>) -> Result<Vec<Cookie>>);

  fn not_installed(_domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
    Err(browser::legacy::BrowserNotInstalled::CookieDatabase.into())
  }

  fn extraction_fails(_domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
    Err(anyhow::anyhow!("cookie database is corrupt"))
  }

  fn always_ok(_domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
    Ok(vec![])
  }

  #[test]
  fn zero_timeout_stops_extraction_before_any_browser_lookup() {
    // "unknown-browser-id" would otherwise fail with a request error;
    // observing TimedOut instead of that error proves the deadline check
    // runs before browser resolution, matching browser_cookies_with_runtime's
    // own ordering.
    let request = Request::browser("unknown-browser-id").timeout(std::time::Duration::ZERO);
    let error = extract(request).expect_err("a zero timeout must stop before doing any work");
    assert_eq!(stop_reason(&error), Some(StopReason::TimedOut));
  }

  #[test]
  fn a_cancelled_handle_stops_extraction_before_any_browser_lookup() {
    let handle = CancellationHandle::new();
    assert!(handle.cancel());
    assert!(handle.is_cancelled());

    let request = Request::browser("unknown-browser-id").cancellation(handle);
    let error =
      extract(request).expect_err("a pre-cancelled handle must stop before doing any work");
    assert_eq!(stop_reason(&error), Some(StopReason::Cancelled));
  }

  #[test]
  fn cancelling_from_another_thread_stops_a_running_checkpoint_loop_promptly() {
    // Proves the cross-thread claim itself: cancellation observed by a loop
    // that is *already running*, set from a second thread mid-flight, not
    // just a pre-cancelled handle checked before any work starts.
    use std::time::{Duration, Instant};

    let handle = CancellationHandle::new();
    let clock = common::deadline::SystemClock;
    let deadline = common::deadline::Deadline::after(&clock, Duration::from_secs(30));
    let token = handle.0.clone();

    let canceller = {
      let handle = handle.clone();
      std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        handle.cancel();
      })
    };

    let started = Instant::now();
    let stop = loop {
      if let Err(stop) = common::deadline::checkpoint(&clock, deadline, &token) {
        break stop;
      }
      std::thread::sleep(Duration::from_millis(5));
    };
    let elapsed = started.elapsed();
    canceller.join().expect("canceller thread must not panic");

    assert_eq!(stop, common::deadline::BoundaryStop::Cancelled);
    assert!(
      elapsed < Duration::from_secs(5),
      "a cross-thread cancellation must stop an in-progress loop promptly, took {elapsed:?}"
    );
  }

  #[test]
  fn cancelling_one_clone_cancels_every_clone() {
    let handle = CancellationHandle::new();
    let clone = handle.clone();
    assert!(!handle.is_cancelled());
    assert!(!clone.is_cancelled());

    assert!(clone.cancel());
    assert!(
      handle.is_cancelled(),
      "cancelling a clone must be visible on the original"
    );

    // A second cancellation (on either the original or another clone) is a
    // no-op: the first writer already won.
    assert!(!handle.cancel());
  }

  #[test]
  fn cancellation_handle_equality_is_shared_state_not_shared_value() {
    let handle = CancellationHandle::new();
    let clone = handle.clone();
    let independent = CancellationHandle::new();

    assert_eq!(handle, clone, "clones of the same handle are equal");
    assert_ne!(
      handle, independent,
      "two never-cancelled handles are still not equal unless they're clones"
    );

    independent.cancel();
    assert_ne!(
      handle, independent,
      "reaching the same cancelled state does not make unrelated handles equal"
    );
  }

  #[test]
  fn cancel_after_an_unrelated_timeout_still_records_and_returns_true() {
    // CancellationHandle only tracks whether cancellation was requested
    // through it, not whether the operation is still running -- timing out
    // never touches the handle's own state, so a cancel() afterward is not
    // rejected as "too late", it just has nothing left to affect.
    let handle = CancellationHandle::new();
    let request = Request::browser("unknown-browser-id")
      .timeout(std::time::Duration::ZERO)
      .cancellation(handle.clone());
    let error = extract(request).expect_err("a zero timeout must stop the request");
    assert_eq!(stop_reason(&error), Some(StopReason::TimedOut));

    assert!(
      handle.cancel(),
      "cancel() after an unrelated timeout still records the request"
    );
    assert!(handle.is_cancelled());
  }

  #[test]
  fn stop_reason_is_none_for_an_ordinary_request_error() {
    let error = extract(Request::browser("definitely-not-a-registered-browser-id"))
      .expect_err("an unknown browser id is a request error");
    assert_eq!(stop_reason(&error), None);
  }

  #[test]
  fn fault_kind_classifies_a_typed_direct_path_error_as_a_request_fault() {
    let directory = crate::utils::TempDir::new().expect("temp directory");
    let missing = directory
      .path()
      .join("no such parent directory")
      .join("missing");
    let error = direct_path::cookies_from_path(direct_path::DirectPathRequest::new(&missing))
      .expect_err("a missing explicit source is a typed DirectPathError");
    assert_eq!(fault_kind(&error), FaultKind::Request);
  }

  #[test]
  fn fault_kind_classifies_unknown_browser_on_extract_as_request() {
    let error = extract(Request::browser("definitely-not-a-registered-browser-id"))
      .expect_err("an unknown browser id is a request error");
    assert_eq!(fault_kind(&error), FaultKind::Request);
    assert!(error.downcast_ref::<RequestError>().is_some());
  }

  #[test]
  fn fault_kind_keeps_chromium_based_unknown_browser_as_engine() {
    let error = chromium_based_with_browser_id(
      Some("definitely-not-a-registered-browser-id"),
      std::env::temp_dir().join("rookie-missing-cookies"),
      None,
      false,
    )
    .expect_err("direct browser_definition path stays unstructured");
    assert_eq!(fault_kind(&error), FaultKind::Engine);
  }

  #[cfg(unix)]
  #[test]
  fn explicit_path_rejects_encrypted_rows_without_browser_identity() {
    let directory = crate::utils::TempDir::new().expect("temp directory");
    let db = directory.path().join("Cookies");
    seed_explicit_path_cookie(&db, "", b"v11encrypted");

    let error = chromium_based_with_browser_id(None, db.clone(), None, false)
      .expect_err("encrypted rows require a browser identity");
    assert!(error.to_string().contains("no browser key identity"));
    assert!(error.to_string().contains("browser_id"));

    let detailed_error = chromium_based_detailed_with_browser_id(None, db, None, false)
      .expect_err("detailed encrypted rows require a browser identity");
    assert!(detailed_error
      .to_string()
      .contains("no browser key identity"));
  }

  #[cfg(unix)]
  #[test]
  fn explicit_path_without_identity_remains_available_for_plaintext_only_databases() {
    let directory = crate::utils::TempDir::new().expect("temp directory");
    let db = directory.path().join("Cookies");
    seed_explicit_path_cookie(&db, "plaintext", b"");

    let cookies = chromium_based_with_browser_id(None, db.clone(), None, false)
      .expect("plaintext-only databases need no key identity");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].value, "plaintext");

    let detailed = chromium_based_detailed_with_browser_id(None, db, None, false)
      .expect("detailed plaintext-only databases need no key identity");
    assert_eq!(detailed.len(), 1);
    assert_eq!(detailed[0].cookie.value, "plaintext");
  }

  #[cfg(target_os = "macos")]
  #[test]
  fn registered_chromium_without_keychain_identity_is_plaintext_only() {
    for browser_id in ["coccoc", "yandex"] {
      let directory = crate::utils::TempDir::new().expect("temp directory");
      let db = directory.path().join("Cookies");
      seed_explicit_path_cookie(&db, "plaintext", b"");
      let cookies = chromium_based_with_browser_id(Some(browser_id), db, None, false)
        .expect("registered browser without credentials can read plaintext");
      assert_eq!(cookies.len(), 1);
      assert_eq!(cookies[0].value, "plaintext");
    }

    let directory = crate::utils::TempDir::new().expect("temp directory");
    let db = directory.path().join("Cookies");
    seed_explicit_path_cookie(&db, "", b"v10encrypted");
    let error = chromium_based_with_browser_id(Some("coccoc"), db, None, false)
      .expect_err("registered browser without credentials cannot read encrypted rows");
    assert!(error.to_string().contains("no browser key identity"));
  }

  /// `coccoc`/`yandex` are registered Chromium forks with no dedicated named
  /// function — unlike `chrome`, `brave`, and the rest, whose one hardcoded
  /// string can never name them. `browser`/`extract(Request::browser(..))`
  /// must resolve them through the registry instead of reporting them as an
  /// unrecognized ID, the one failure mode a named function's fixed string
  /// structurally cannot produce.
  #[cfg(any(target_os = "macos", target_os = "windows"))]
  #[test]
  fn public_browser_and_extract_reach_registry_only_browsers_no_named_function_can_name() {
    fn assert_resolved_through_registry(browser_id: &str, error: &anyhow::Error) {
      assert!(
        !error.to_string().contains("unknown browser id"),
        "{browser_id} must resolve through the registry rather than being unrecognized: {error}"
      );
    }

    for browser_id in ["coccoc", "yandex"] {
      if let Err(error) = browser(browser_id, None) {
        assert_resolved_through_registry(browser_id, &error);
      }
      if let Err(error) = extract(Request::browser(browser_id)) {
        assert_resolved_through_registry(browser_id, &error);
      }
    }
  }

  #[cfg(unix)]
  #[test]
  fn explicit_path_identity_check_covers_the_profile_before_domain_filtering() {
    let directory = crate::utils::TempDir::new().expect("temp directory");
    let db = directory.path().join("Cookies");
    seed_explicit_path_cookie(&db, "plaintext", b"");
    let connection = rusqlite::Connection::open(&db).expect("reopen fixture");
    connection
      .execute(
        "INSERT INTO cookies VALUES ('.other.test', '/', 0, 0, 'encrypted', '', ?1, 0, 0)",
        rusqlite::params![b"v11encrypted"],
      )
      .expect("seed encrypted row outside the requested domain");
    drop(connection);

    let error =
      chromium_based_with_browser_id(None, db, Some(vec!["example.test".to_string()]), false)
        .expect_err("the whole encrypted profile requires an identity");
    assert!(error.to_string().contains("no browser key identity"));
  }

  #[cfg(unix)]
  fn seed_explicit_path_cookie(db: &std::path::Path, value: &str, encrypted_value: &[u8]) {
    let connection = rusqlite::Connection::open(db).expect("open fixture");
    connection
      .execute_batch(
        "CREATE TABLE meta (
           key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR
         );
         INSERT INTO meta (key, value) VALUES ('version', '23');
         CREATE TABLE cookies (
           host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
           name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER,
           samesite INTEGER
         );",
      )
      .expect("create cookie schema");
    connection
      .execute(
        "INSERT INTO cookies VALUES ('.example.test', '/', 0, 0, 'session', ?1, ?2, 0, 0)",
        rusqlite::params![value, encrypted_value],
      )
      .expect("seed cookie row");
  }

  fn named_cookie(name: &str) -> Cookie {
    Cookie {
      domain: "example.test".to_string(),
      path: "/".to_string(),
      secure: false,
      expires: None,
      name: name.to_string(),
      value: String::new(),
      http_only: false,
      same_site: SAME_SITE_UNSPECIFIED,
    }
  }

  fn first_ok(_domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
    Ok(vec![named_cookie("first")])
  }

  fn second_ok(_domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
    Ok(vec![named_cookie("second")])
  }

  #[test]
  fn no_installed_browsers_returns_ok_empty() {
    let browsers: Vec<BrowserEntry> = vec![("firefox", not_installed), ("chrome", not_installed)];
    let result = load_from_browsers(&browsers, None).expect("absence is not an extraction failure");
    assert!(result.is_empty());
  }

  #[test]
  fn all_installed_browsers_failing_returns_aggregate_error() {
    let browsers: Vec<BrowserEntry> =
      vec![("firefox", extraction_fails), ("chrome", extraction_fails)];
    let result = load_from_browsers(&browsers, None);
    assert!(result.is_err(), "expected Err when all browsers fail");
    let msg = result.unwrap_err().to_string();
    assert!(
      msg.contains("all browser extractions failed"),
      "error should mention aggregate failure, got: {msg}"
    );
    assert!(
      msg.contains("firefox: cookie database is corrupt"),
      "error should list firefox error, got: {msg}"
    );
    assert!(
      msg.contains("chrome: cookie database is corrupt"),
      "error should list chrome error, got: {msg}"
    );
  }

  #[test]
  fn aggregate_load_stop_keeps_its_summary_and_typed_source() {
    let stop = common::deadline::BoundaryStop::TimedOut;
    let error = aggregate_load_failure(
      &["chrome: operation deadline expired".to_owned()],
      Some(stop),
    );
    assert!(error.to_string().contains("all browser extractions failed"));
    assert!(format!("{error:#}").contains("chrome: operation deadline expired"));
    assert_eq!(
      error.downcast_ref::<common::deadline::BoundaryStop>(),
      Some(&stop)
    );
  }

  #[test]
  fn partial_failure_returns_ok() {
    let browsers: Vec<BrowserEntry> = vec![("firefox", extraction_fails), ("chrome", always_ok)];
    let result = load_from_browsers(&browsers, None);
    assert!(
      result.is_ok(),
      "expected Ok when at least one browser succeeds, got: {result:?}"
    );
  }

  #[test]
  fn missing_browsers_do_not_hide_an_installed_browser_failure() {
    let browsers: Vec<BrowserEntry> =
      vec![("firefox", not_installed), ("chrome", extraction_fails)];
    let message = load_from_browsers(&browsers, None)
      .expect_err("the one installed browser failed")
      .to_string();
    assert!(message.contains("chrome: cookie database is corrupt"));
    assert!(!message.contains("firefox"));
  }

  #[test]
  fn empty_browser_list_returns_ok_empty() {
    let browsers: Vec<BrowserEntry> = vec![];
    let result = load_from_browsers(&browsers, None);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
  }

  #[test]
  fn load_from_browsers_preserves_source_order() {
    let browsers: Vec<BrowserEntry> = vec![
      ("first", first_ok),
      ("missing", not_installed),
      ("second", second_ok),
    ];
    let cookies = load_from_browsers(&browsers, None)
      .expect("successful sources survive an intervening extraction error");
    let names: Vec<_> = cookies.iter().map(|cookie| cookie.name.as_str()).collect();
    assert_eq!(names, vec!["first", "second"]);
  }

  #[cfg(target_os = "linux")]
  #[test]
  #[allow(deprecated)]
  fn opera_gx_remains_explicitly_unsupported_and_unadvertised_on_linux() {
    let error = opera_gx(None).expect_err("Opera GX has no Linux implementation");
    assert!(error
      .to_string()
      .contains("Opera GX is not supported on Linux"));
    assert!(supported_browsers()
      .expect("supported browsers")
      .iter()
      .all(|browser| browser.id.as_str() != "opera_gx"));
  }

  fn source_test_path(tag: &str) -> (crate::utils::TempDir, std::path::PathBuf) {
    let dir = crate::utils::TempDir::new().expect("temporary source directory");
    let path = dir.path().join(tag);
    (dir, path)
  }

  #[test]
  fn any_browser_sniffs_sqlite_decoder_family_from_schema() {
    let (_chromium_dir, chromium_path) = source_test_path("chromium.sqlite");
    let chromium = rusqlite::Connection::open(&chromium_path).expect("Chromium fixture");
    chromium
      .execute("CREATE TABLE cookies (name TEXT)", [])
      .expect("Chromium table");
    drop(chromium);

    let (_mozilla_dir, mozilla_path) = source_test_path("mozilla.sqlite");
    let mozilla = rusqlite::Connection::open(&mozilla_path).expect("Mozilla fixture");
    mozilla
      .execute("CREATE TABLE moz_cookies (name TEXT)", [])
      .expect("Mozilla table");
    drop(mozilla);

    assert_eq!(
      sniff_cookie_source(&chromium_path).expect("sniff Chromium"),
      AnyBrowserSource::ChromiumSqlite
    );
    assert_eq!(
      sniff_cookie_source(&mozilla_path).expect("sniff Mozilla"),
      AnyBrowserSource::MozillaSqlite
    );
  }

  #[test]
  fn any_browser_rejects_ambiguous_or_unrelated_sqlite_schemas() {
    let (_ambiguous_dir, ambiguous_path) = source_test_path("ambiguous.sqlite");
    let ambiguous = rusqlite::Connection::open(&ambiguous_path).expect("ambiguous fixture");
    ambiguous
      .execute_batch("CREATE TABLE cookies (name TEXT); CREATE TABLE moz_cookies (name TEXT);")
      .expect("ambiguous tables");
    drop(ambiguous);
    let error = sniff_cookie_source(&ambiguous_path).expect_err("ambiguous schema must fail");
    assert!(error
      .to_string()
      .contains("both `cookies` and `moz_cookies`"));

    let (_other_dir, other_path) = source_test_path("other.sqlite");
    let other = rusqlite::Connection::open(&other_path).expect("other fixture");
    other
      .execute("CREATE TABLE unrelated (value TEXT)", [])
      .expect("unrelated table");
    drop(other);
    let error = sniff_cookie_source(&other_path).expect_err("unrelated schema must fail");
    assert!(error.to_string().contains("unsupported SQLite database"));
  }

  #[test]
  fn any_browser_sniffs_binary_cookie_signature_without_decoder_probing() {
    let (_dir, path) = source_test_path("Cookies.binarycookies");
    std::fs::write(&path, b"cooksynthetic").expect("Safari header fixture");
    assert_eq!(
      sniff_cookie_source(&path).expect("sniff Safari"),
      AnyBrowserSource::SafariBinaryCookies
    );
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn any_browser_sniffs_ese_signature() {
    let (_dir, path) = source_test_path("WebCacheV01.dat");
    std::fs::write(&path, [0, 0, 0, 0, 0xef, 0xcd, 0xab, 0x89]).expect("ESE header fixture");
    assert_eq!(
      sniff_cookie_source(&path).expect("sniff ESE"),
      AnyBrowserSource::InternetExplorerEse
    );
  }

  #[cfg(unix)]
  fn seed_test_cookies(db_path: &std::path::Path, cookie_name: &str, cookie_value: &str) {
    let conn = rusqlite::Connection::open(db_path).expect("open sqlite db");
    conn
      .execute_batch(
        "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
        INSERT INTO meta (key, value) VALUES ('version', '23');
        CREATE TABLE cookies (
          host_key TEXT NOT NULL,
          path TEXT NOT NULL,
          is_secure INTEGER NOT NULL,
          expires_utc INTEGER NOT NULL,
          name TEXT NOT NULL,
          value TEXT NOT NULL,
          encrypted_value BLOB,
          is_httponly INTEGER NOT NULL,
          samesite INTEGER NOT NULL
        );",
      )
      .expect("create Chromium schema");
    conn
      .execute(
        "INSERT INTO cookies (host_key, path, is_secure, expires_utc, name, value, encrypted_value, is_httponly, samesite)
         VALUES ('.example.com', '/', 0, 0, ?1, ?2, ?3, 0, 0)",
        rusqlite::params![cookie_name, cookie_value, &b""[..]],
      )
      .expect("insert row");
  }

  #[cfg(unix)]
  #[test]
  fn test_chrome_resolves_network_cookies_on_unix() {
    let home = crate::utils::TempDir::new().expect("create temp home");
    let home_dir = home.path().to_path_buf();

    #[cfg(target_os = "macos")]
    let chrome_dir = home_dir.join("Library/Application Support/Google/Chrome");

    #[cfg(not(target_os = "macos"))]
    let chrome_dir = home_dir.join(".config/google-chrome");

    let network_dir = chrome_dir.join("Default/Network");
    let default_dir = chrome_dir.join("Default");

    std::fs::create_dir_all(&network_dir).expect("create network dir");
    std::fs::create_dir_all(&default_dir).expect("create default dir");

    let local_state = chrome_dir.join("Local State");
    std::fs::write(&local_state, b"{}").expect("create local state");

    let network_db = network_dir.join("Cookies");
    let legacy_db = default_dir.join("Cookies");

    seed_test_cookies(&network_db, "net_cookie", "net_val");
    seed_test_cookies(&legacy_db, "legacy_cookie", "legacy_val");

    // Thread-local override, not a mutated process environment: parallel
    // tests each install their own value and never observe or serialize on
    // another test's real environment (see `browser::registry::EnvOverride`).
    let env = std::collections::BTreeMap::from([(
      std::ffi::OsString::from("HOME"),
      home_dir.into_os_string(),
    )]);
    let _env_override = browser::registry::EnvOverride::install(env);

    let cookies = chrome(None).expect("chrome() should find and parse network cookies");
    assert_eq!(
      cookies.len(),
      1,
      "expected 1 cookie from Network/Cookies, got {:?}",
      cookies
    );
    assert_eq!(cookies[0].name, "net_cookie");
    assert_eq!(cookies[0].value, "net_val");
  }

  /// Complements `public_browser_and_extract_reach_registry_only_browsers_no_named_function_can_name`
  /// (which only asserts on the error path) with a positive case: `browser`/
  /// `extract(Request::browser(..))` actually resolve and read cookies from
  /// CocCoc, a registered Chromium fork with no dedicated named function.
  #[cfg(target_os = "macos")]
  #[test]
  fn browser_and_extract_read_real_cookies_from_a_registry_only_browser() {
    let home = crate::utils::TempDir::new().expect("create temp home");
    let home_dir = home.path().to_path_buf();
    let coccoc_dir = home_dir.join("Library/Application Support/Coccoc");
    let default_dir = coccoc_dir.join("Default");
    std::fs::create_dir_all(&default_dir).expect("create CocCoc default profile dir");
    std::fs::write(coccoc_dir.join("Local State"), b"{}").expect("create Local State");
    seed_test_cookies(&default_dir.join("Cookies"), "coccoc_cookie", "coccoc_val");

    let env = std::collections::BTreeMap::from([(
      std::ffi::OsString::from("HOME"),
      home_dir.into_os_string(),
    )]);
    let _env_override = browser::registry::EnvOverride::install(env);

    let cookies =
      browser("coccoc", None).expect("browser(\"coccoc\", ..) should find and parse cookies");
    assert_eq!(cookies.len(), 1, "expected 1 cookie, got {cookies:?}");
    assert_eq!(cookies[0].name, "coccoc_cookie");
    assert_eq!(cookies[0].value, "coccoc_val");

    let cookies = extract(Request::browser("coccoc"))
      .expect("extract(Request::browser(\"coccoc\")) should find and parse cookies");
    assert_eq!(cookies.len(), 1, "expected 1 cookie, got {cookies:?}");
    assert_eq!(cookies[0].name, "coccoc_cookie");
    assert_eq!(cookies[0].value, "coccoc_val");
  }
}
