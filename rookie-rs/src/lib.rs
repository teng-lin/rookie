//! Extract cookies from local browser profiles (Linux, macOS, Windows).
//!
//! The recommended 0.6 entry is [`read`] with [`ReadRequest`]:
//!
//! ```no_run
//! use rookie_cookies::{read, ReadRequest};
//!
//! let snapshot = read(ReadRequest::browser("chrome").profile("Default"))?;
//! let _header = snapshot.header("https://example.com/")?;
//! # Ok::<(), rookie_cookies::anyhow::Error>(())
//! ```
//!
//! Named helpers such as [`chrome`] stay as a compatibility bridge and are
//! deprecated. There is no crate-root `get` or `report` function. Full guide:
//! the crate `README.md` (also the crates.io landing page).
//!
//! Compatibility APIs remain callable through 0.6 while their downstream use
//! is deprecated. Internal adapters intentionally exercise those exact paths.
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

/// Folds one `fan_out` round's per-browser results into [`load`]'s answer.
///
/// Missing profiles were not extraction attempts. If at least one installed
/// browser failed and none succeeded, surface the real failures; a machine
/// with no supported browser installed legitimately has no cookies.
///
/// This is a separate function so the aggregation rules are reachable from a
/// test without a second implementation of them. The `#[cfg(test)]`
/// `load_from_browsers` that used to serve that purpose restated the rules
/// sequentially and never modelled either stop path, so its tests could stay
/// green while `load` regressed.
fn aggregate_load_results(
  names: &[&str],
  results: Vec<Result<Vec<Cookie>>>,
  runtime: &common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
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
  aggregate_load_results(&names, results, &runtime)
}

#[cfg(test)]
use direct_path::CookieSourceKind as AnyBrowserSource;

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
mod tests;
