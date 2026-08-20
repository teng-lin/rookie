//! Extract cookies from local browser profiles (Linux, macOS, Windows).
//!
//! The recommended 0.6 entry is [`read`] with [`ReadRequest`]:
//!
//! ```no_run
//! use rookie_cookies::{read, ReadRequest, SendContext};
//!
//! let snapshot = read(ReadRequest::browser("chrome").profile("Default"))?;
//! let _header = snapshot.header(&SendContext::url("https://example.com/"))?;
//! # Ok::<(), rookie_cookies::Error>(())
//! ```
//!
//! Named helpers such as [`chrome`] stay as a compatibility bridge and are
//! deprecated. There is no crate-root `get` or `report` function. Full guide:
//! the crate `README.md` (also the crates.io landing page).
//!
//! Compatibility APIs remain callable through 0.6 while their downstream use
//! is deprecated. Internal adapters intentionally exercise those exact paths.
#![allow(deprecated)]
#![allow(unknown_lints)]
#![allow(clippy::chunks_exact_to_as_chunks)]

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
#[cfg(target_os = "linux")]
pub use compatibility_dispatch::named::cachy;
#[cfg(target_os = "macos")]
pub use compatibility_dispatch::named::safari;
pub use compatibility_dispatch::named::{
  arc, brave, chrome, chromium, edge, firefox, firefox_profile, firefox_profiles, librewolf, load,
  opera, opera_gx, vivaldi, zen,
};
#[cfg(target_os = "windows")]
pub use compatibility_dispatch::named::{internet_explorer, octo_browser};
mod error;
mod execution;
mod header_filter;
mod read;
mod read_warning;
mod request_error;
mod selection;
mod send_context;
mod session;
mod target;
/// The `anyhow` crate, re-exported so the deprecated v0.5.9 bridge functions
/// (which still return [`anyhow::Result`]) can be named without a direct
/// dependency.
///
/// This is also the escape hatch for the one deliberate stable break:
/// `rookie_cookies::Result` used to be `anyhow::Result`, and
/// `rookie_cookies::anyhow::Result` still resolves.
#[deprecated(
  since = "0.6.0",
  note = "use rookie_cookies::Error and rookie_cookies::Result"
)]
pub use anyhow;
use enums::Cookie;
pub use error::{EngineError, Error};
pub use execution::{AppBoundPolicy, ExecutionControl};
pub use read::{
  from_path, profiles, profiles_with, read, FromPathRequest, ReadRequest, ReadResult, ReadWarning,
};
pub use request_error::RequestError;
pub use selection::{ProfileSelection, ReportScope};
pub use send_context::{MethodClass, ResourceKind, SendContext};
pub use session::SessionPolicy;

/// The result type of every 0.6 job function.
///
/// **Changed in 0.6.0.** This alias was `anyhow::Result<T>` through v0.5.9.
/// It now names the crate's own typed [`Error`]. A v0.5.9 caller that spelled
/// `rookie_cookies::Result<T>` around a bridge function should use
/// `rookie_cookies::anyhow::Result<T>`, which still resolves; the bridge
/// functions themselves are unchanged and still return `anyhow::Result`.
pub type Result<T> = std::result::Result<T, Error>;
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
/// Prefer [`Error::stop_reason`]: the classification is a variant match on
/// [`Error`] now, not a downcast through an opaque chain.
///
/// # Examples
///
/// ```no_run
/// let request = rookie_cookies::ExtractRequest::browser("chrome")
///   .timeout(std::time::Duration::from_secs(5));
/// if let Err(error) = rookie_cookies::extract(request) {
///   if error.stop_reason() == Some(rookie_cookies::StopReason::TimedOut) {
///     eprintln!("extraction timed out");
///   }
/// }
/// ```
#[deprecated(since = "0.6.0", note = "use Error::stop_reason")]
pub fn stop_reason(error: &Error) -> Option<StopReason> {
  error.stop_reason()
}

/// Reports why an internal `anyhow` chain stopped.
///
/// The internal seams (and the v0.5.9 bridge) still carry `anyhow::Error`, so
/// their errors are not [`Error`] values and cannot be classified by the
/// public [`stop_reason`]. Tests that exercise a seam below a job edge use
/// this; production code classifies once, at the edge, via [`Error`].
#[cfg(test)]
pub(crate) fn anyhow_stop_reason(error: &anyhow::Error) -> Option<StopReason> {
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
/// Deprecated in 0.6.0: [`Error`] already distinguishes
/// [`Request`](Error::Request) / [`Stopped`](Error::Stopped) /
/// [`Source`](Error::Source) / [`Engine`](Error::Engine), and this two-way
/// split collapses three of them. Match on [`Error`] instead.
///
/// # Examples
///
/// ```no_run
/// let request = rookie_cookies::direct_path::PathExtractRequest::sniff(
///   "/nonexistent/Cookies",
/// );
/// if let Err(error) = rookie_cookies::direct_path::extract_from_path(request) {
///   assert!(matches!(error, rookie_cookies::Error::Source(_)));
/// }
/// ```
#[deprecated(
  since = "0.6.0",
  note = "match Error; FaultKind is a two-way FFI split"
)]
pub fn fault_kind(error: &Error) -> FaultKind {
  error.fault_kind()
}

/// Classifies an internal `anyhow` chain the way the v0.5.9 bridge did.
///
/// Test-only counterpart to [`anyhow_stop_reason`], for seams below a job
/// edge that have not been mapped to [`Error`] yet.
#[cfg(test)]
pub(crate) fn anyhow_fault_kind(error: &anyhow::Error) -> FaultKind {
  // A timeout or cancellation checked *during* source classification still
  // gets wrapped in a `DirectPathError` (inspection failed, for whichever
  // reason), so this must rule out an operational stop first: that is never
  // a caller input mistake, regardless of what wraps it afterward.
  if anyhow_stop_reason(error).is_some() {
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

/// One flat extraction, expressed as data rather than a function call.
///
/// A named function such as [`chrome`] can only ever name the one browser it
/// was written for. `ExtractRequest` carries that same selection as a value,
/// so it reaches any browser [`supported_browsers`] lists — including
/// registry-only entries (registered forks and alternate builds) no named
/// function can name.
///
/// **Renamed in 0.6.0** from `Request`, which was prerelease-only. The name
/// said nothing about which of the three job shapes it belonged to, and the
/// same value meant "the first legacy-eligible profile" to [`extract`] and
/// "every profile" to `extract_report` — two calls that looked identical and
/// selected differently. [`ReportScope`] now makes that a type-level
/// distinction; see [`ReportRequest`].
///
/// # Examples
///
/// ```no_run
/// let request = rookie_cookies::ExtractRequest::browser("chrome")
///   .domains(Some(vec!["example.com".to_string()]));
/// let cookies = rookie_cookies::extract(request)?;
/// # Ok::<(), rookie_cookies::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractRequest {
  target: target::BrowserTarget<ProfileSelection>,
  domains: Option<Vec<String>>,
  control: ExecutionControl,
}

impl ExtractRequest {
  /// Selects one browser by canonical ID or registered alias, as returned by
  /// [`supported_browsers`]. An empty ID is
  /// [`RequestError::MissingBrowser`] when the job runs.
  pub fn browser(id: impl Into<String>) -> Self {
    Self {
      target: target::BrowserTarget::browser(id),
      domains: None,
      control: ExecutionControl::default(),
    }
  }

  /// Selects one profile by opaque `profile_id`, display name, directory
  /// name, or a non-lossy full path. Resolved at extract time, not here.
  /// An empty string is [`RequestError::EmptyProfileSelector`].
  pub fn profile(mut self, query: impl Into<String>) -> Self {
    self.target = self.target.profile(query);
    self
  }

  /// Selects the profile explicitly. There is no "every profile" value here;
  /// use [`ReportRequest`] for that.
  pub fn selection(mut self, selection: ProfileSelection) -> Self {
    self.target = self.target.with_selection(selection);
    self
  }

  /// Restricts extraction to the given domains, or clears a prior
  /// restriction on `None`.
  ///
  /// Takes `Option<Vec<String>>` rather than `Vec<String>` so [`browser`]'s
  /// own `Option` parameter forwards here directly.
  pub fn domains(mut self, domains: Option<Vec<String>>) -> Self {
    self.domains = domains;
    self
  }

  /// Also acquires the browser's declared session store.
  ///
  /// `extract` is where the two worlds meet: it produces a flat list, which is
  /// snapshot-shaped output, by flattening a report, which is always-session
  /// machinery. It honors this policy; report jobs always retain their session
  /// sources. See [`SessionPolicy`].
  pub fn include_session(mut self) -> Self {
    self.target = self.target.with_session(SessionPolicy::IncludeSession);
    self
  }

  /// Selects the session policy explicitly.
  pub fn session(mut self, policy: SessionPolicy) -> Self {
    self.target = self.target.with_session(policy);
    self
  }

  /// Overrides the default 30-second extraction budget.
  pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
    self.control = self.control.timeout(timeout);
    self
  }

  /// Lets `handle` cancel this request from another thread while it runs —
  /// see [`CancellationHandle`].
  pub fn cancellation(mut self, handle: CancellationHandle) -> Self {
    self.control = self.control.cancellation(handle);
    self
  }

  /// Selects the Windows App-Bound (v20) recovery policy for this request.
  pub fn app_bound(mut self, policy: AppBoundPolicy) -> Self {
    self.control = self.control.app_bound(policy);
    self
  }

  /// Replaces this request's execution control **wholesale**, discarding an
  /// earlier `timeout` / `cancellation` / `app_bound` call.
  pub fn execution(mut self, control: ExecutionControl) -> Self {
    self.control = control;
    self
  }
}

/// One grouped report, expressed as data.
///
/// The only difference from [`ExtractRequest`] is the selection type: this one
/// may widen to every profile, because a report has somewhere to put
/// per-profile provenance and failures. [`browser`](Self::browser) defaults to
/// [`ReportScope::AllProfiles`], which is exactly what v0.5.9's
/// `browser_report(id, None, domains)` has always meant.
///
/// # Examples
///
/// ```no_run
/// let report = rookie_cookies::extract_report(
///   rookie_cookies::ReportRequest::browser("chrome"),
/// )?;
/// println!("{}", report.status);
/// # Ok::<(), rookie_cookies::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportRequest {
  target: target::BrowserTarget<ReportScope>,
  domains: Option<Vec<String>>,
  control: ExecutionControl,
}

impl ReportRequest {
  /// Reports **every** installation and profile of one browser.
  pub fn browser(id: impl Into<String>) -> Self {
    Self {
      target: target::BrowserTarget::browser(id),
      domains: None,
      control: ExecutionControl::default(),
    }
  }

  /// Narrows the report to one profile.
  pub fn profile(mut self, query: impl Into<String>) -> Self {
    self.target = self.target.profile(query);
    self
  }

  /// Sets the scope explicitly.
  pub fn scope(mut self, scope: ReportScope) -> Self {
    self.target = self.target.with_selection(scope);
    self
  }

  /// Restricts the report to the given domains, or clears a prior restriction.
  pub fn domains(mut self, domains: Option<Vec<String>>) -> Self {
    self.domains = domains;
    self
  }

  /// Overrides the default 30-second extraction budget.
  pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
    self.control = self.control.timeout(timeout);
    self
  }

  /// Lets `handle` cancel this request from another thread while it runs.
  pub fn cancellation(mut self, handle: CancellationHandle) -> Self {
    self.control = self.control.cancellation(handle);
    self
  }

  /// Selects the Windows App-Bound (v20) recovery policy for this request.
  pub fn app_bound(mut self, policy: AppBoundPolicy) -> Self {
    self.control = self.control.app_bound(policy);
    self
  }

  /// Replaces this request's execution control **wholesale**, discarding an
  /// earlier `timeout` / `cancellation` / `app_bound` call.
  pub fn execution(mut self, control: ExecutionControl) -> Self {
    self.control = control;
    self
  }
}

impl From<ExtractRequest> for ReportRequest {
  /// Same browser, same profile, same domains, same control — reported rather
  /// than flattened.
  ///
  /// The scope **narrows** to one profile and never widens. Widening a
  /// `LegacyFirst` extract into an all-profiles report would silently change
  /// what the caller asked for, which is the 0.6-beta defect this type split
  /// exists to remove.
  fn from(request: ExtractRequest) -> Self {
    Self {
      target: request.target.into_report_scope(),
      domains: request.domains,
      control: request.control,
    }
  }
}

/// Runs one [`ExtractRequest`] and returns its cookies.
///
/// `ExtractRequest`/`extract` is the execution path underneath [`browser`] and
/// every named compatibility function that selects one browser by a fixed
/// string (e.g. [`chrome`], [`firefox`]) — they build a request and run it
/// here rather than dispatching independently.
///
/// # Errors
///
/// An unknown browser ID or an invalid profile query is
/// [`Error::Request`]. A request that stopped because of a timeout or a
/// cancelled [`CancellationHandle`] is [`Error::Stopped`]; unlike the report
/// APIs, this never returns a stopped run as an ordinary success.
///
/// # Examples
///
/// ```no_run
/// let cookies = rookie_cookies::extract(
///   rookie_cookies::ExtractRequest::browser("chrome"),
/// )?;
/// # Ok::<(), rookie_cookies::Error>(())
/// ```
pub fn extract(request: ExtractRequest) -> Result<Vec<Cookie>> {
  error::map_job_result(extract_inner(request))
}

pub(crate) fn extract_inner(request: ExtractRequest) -> anyhow::Result<Vec<Cookie>> {
  let clock = common::deadline::SystemClock;
  let runtime = common::deadline::runtime_for_control(&clock, &request.control);
  let browser_id = request.target.resolve()?.to_owned();
  let session = request.target.session();
  match request.target.selection() {
    ProfileSelection::LegacyFirst => {
      browser::legacy::browser_cookies_with_runtime(&browser_id, request.domains, session, &runtime)
    }
    ProfileSelection::Query(query) => {
      let (_profile_id, report, termination) = profile_extraction_report_with_runtime(
        &browser_id,
        query,
        request.domains,
        session,
        &runtime,
      )?;
      flatten_selected_report_cookies(report, termination)
    }
  }
}

/// Resolves one public profile query and runs the selected extraction under
/// the same absolute runtime. Returning the resolved ID lets `read()` expose
/// it without repeating discovery.
pub(crate) fn profile_extraction_report_with_runtime(
  browser_id: &str,
  query: &str,
  domains: Option<Vec<String>>,
  session: SessionPolicy,
  runtime: &common::deadline::BoundaryRuntime<'_>,
) -> anyhow::Result<(
  String,
  report::ExtractionReport,
  browser::outcome::Termination,
)> {
  let (profile_id, (report, termination)) = resolve_then_extract_profile_with_runtime(
    browser_id,
    query,
    runtime,
    browser::registry::resolve_profile_query,
    |resolved_browser_id, profile_id, runtime| {
      browser::report_build::browser_extraction_outcome_with_runtime(
        resolved_browser_id,
        browser::registry::ProfileSelection::ProfileId(profile_id),
        domains,
        session,
        runtime,
      )
    },
  )?;
  Ok((profile_id, report, termination))
}

fn resolve_then_extract_profile_with_runtime<T, Resolve, Extract>(
  browser_id: &str,
  query: &str,
  runtime: &common::deadline::BoundaryRuntime<'_>,
  resolve: Resolve,
  extract: Extract,
) -> anyhow::Result<(String, T)>
where
  Resolve: FnOnce(&str, &str, &common::deadline::BoundaryRuntime<'_>) -> anyhow::Result<String>,
  Extract: FnOnce(&str, &str, &common::deadline::BoundaryRuntime<'_>) -> anyhow::Result<T>,
{
  runtime.check()?;
  let profile_id = resolve(browser_id, query, runtime)?;
  let result = extract(browser_id, &profile_id, runtime)?;
  Ok((profile_id, result))
}

/// Runs one [`ReportRequest`] and returns its grouped report.
///
/// # Errors
///
/// Only a bad request fails: an unknown browser ID or an invalid profile
/// query. Extraction problems are *reported* instead — a registered but
/// uninstalled browser is an `Ok` report with `no_sources`, and a total
/// failure is an `Ok` report with `failed`. A stopped run is likewise an `Ok`
/// report whose `termination` is not `completed`, which is the one place this
/// crate deliberately differs from the snapshot and flat surfaces.
///
/// # Examples
///
/// ```no_run
/// let report = rookie_cookies::extract_report(
///   rookie_cookies::ReportRequest::browser("chrome").profile("Default"),
/// )?;
/// println!("{}", report.status);
/// # Ok::<(), rookie_cookies::Error>(())
/// ```
pub fn extract_report(request: ReportRequest) -> Result<report::ExtractionReport> {
  error::map_job_result(extract_report_inner(request))
}

fn extract_report_inner(request: ReportRequest) -> anyhow::Result<report::ExtractionReport> {
  use browser::registry::ProfileSelection as EngineSelection;

  let clock = common::deadline::SystemClock;
  let runtime = common::deadline::runtime_for_control(&clock, &request.control);
  let browser_id = request.target.resolve()?.to_owned();
  // The three scopes are three different selections, not two. Collapsing
  // `One(LegacyFirst)` into "no profile named" would silently widen a narrowed
  // request back to every profile -- exactly the shrink/widen confusion
  // `ReportScope` exists to remove.
  let resolved_query = match request.target.selection() {
    ReportScope::One(ProfileSelection::Query(query)) => Some(
      browser::registry::resolve_profile_query(&browser_id, query, &runtime)?,
    ),
    _ => None,
  };
  let selection = match (request.target.selection(), resolved_query.as_deref()) {
    (ReportScope::AllProfiles, _) => EngineSelection::AllProfiles,
    (ReportScope::One(ProfileSelection::LegacyFirst), _) => EngineSelection::LegacyFirstProfile,
    (_, Some(profile_id)) => EngineSelection::ProfileId(profile_id),
    // Unreachable: `resolved_query` is `Some` for exactly the remaining arm.
    (_, None) => EngineSelection::AllProfiles,
  };
  browser::report_build::browser_extraction_report_with_runtime(
    &browser_id,
    selection,
    request.domains,
    // Reports always retain session sources: describing every source the
    // profile declares is what a report is for.
    SessionPolicy::IncludeSession,
    &runtime,
  )
}

/// Projects a one-profile report down to the flat cookie list `extract`
/// returns.
///
/// `termination` is the **typed** value the report DTO's open-vocabulary
/// `termination` string was projected from. Classifying the stop from the enum
/// rather than re-parsing the string keeps the "never classify by parsing a
/// string" rule intact on the crate's own internal path, and removes the
/// unreachable catch-all arm the string match needed.
pub(crate) fn flatten_selected_report_cookies(
  report: report::ExtractionReport,
  termination: browser::outcome::Termination,
) -> anyhow::Result<Vec<Cookie>> {
  use browser::outcome::Termination;
  match termination {
    Termination::Completed => {}
    Termination::TimedOut => return Err(common::deadline::BoundaryStop::TimedOut.into()),
    Termination::Cancelled => return Err(common::deadline::BoundaryStop::Cancelled.into()),
    Termination::ResourceExhausted => {
      return Err(common::deadline::BoundaryStop::ResourceExhausted.into())
    }
  }
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
    return Err(
      error::EngineFailure::new(
        error::EngineCause::NoSelectedSource,
        "no selected cookie source succeeded",
      )
      .into(),
    );
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
/// convenience over [`extract`]`(`[`ExtractRequest::browser`]`(id).domains(domains))`.
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
#[deprecated(
  since = "0.6.0",
  note = "use extract(ExtractRequest::browser(id).domains(..))"
)]
pub fn browser(id: &str, domains: Option<Vec<String>>) -> anyhow::Result<Vec<Cookie>> {
  extract_inner(
    ExtractRequest::browser(id)
      .domains(domains)
      .execution(legacy_execution()),
  )
}

/// Execution control for the deprecated v0.5.9 bridge.
///
/// The new job surface defaults [`AppBoundPolicy`] to `Disabled`, because
/// unsolicited process injection should be something a caller asks for. The
/// bridge cannot ask: `chrome(None)` and `browser(id, None)` have no options
/// argument, and their Windows v20 capability shipped in 0.5.8. Defaulting
/// them to `Disabled` would silently stop decrypting rows they read today, on
/// the surface this release promises to keep working.
pub(crate) fn legacy_execution() -> ExecutionControl {
  ExecutionControl::default().app_bound(AppBoundPolicy::AllowElevatedFallback)
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
  note = "use direct_path::extract_from_path with PathExtractRequest::plaintext / unix_identity / windows_local_state"
)]
pub fn chromium_based_with_browser_id(
  browser_id: Option<&str>,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> anyhow::Result<Vec<Cookie>> {
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
  note = "use from_path(FromPathRequest::new(path).chromium_*()).detailed_cookies()"
)]
pub fn chromium_based_detailed_with_browser_id(
  browser_id: Option<&str>,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> anyhow::Result<Vec<enums::DetailedCookie>> {
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
  error::map_job_result(browser::report_build::supported_browser_descriptors())
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
  browser_profiles_with(browser_id, ExecutionControl::default())
}

/// [`browser_profiles`] under caller-supplied execution control.
///
/// The v0.5.9 signature above takes no control and cannot grow one without
/// breaking, so the knobs arrive through this twin instead.
///
/// # Examples
///
/// ```no_run
/// use std::time::Duration;
///
/// let control = rookie_cookies::ExecutionControl::default().timeout(Duration::from_secs(5));
/// let profiles = rookie_cookies::browser_profiles_with("chrome", control)?;
/// println!("{}", profiles.len());
/// # Ok::<(), rookie_cookies::Error>(())
/// ```
pub fn browser_profiles_with(
  browser_id: &str,
  control: ExecutionControl,
) -> Result<Vec<report::ProfileDescriptor>> {
  error::map_job_result(browser::report_build::browser_profile_descriptors(
    browser_id, &control,
  ))
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
  chrome_profiles_with(ExecutionControl::default())
}

/// [`chrome_profiles`] under caller-supplied execution control.
///
/// # Examples
///
/// ```no_run
/// let profiles = rookie_cookies::chrome_profiles_with(Default::default())?;
/// println!("{}", profiles.len());
/// # Ok::<(), rookie_cookies::Error>(())
/// ```
pub fn chrome_profiles_with(control: ExecutionControl) -> Result<Vec<report::ProfileDescriptor>> {
  error::map_job_result(browser::report_build::chrome_profile_descriptors(&control))
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
  note = "use extract_report(ReportRequest::browser(\"chrome\").profile(q)) \
          or browser_report(\"chrome\", Some(q), domains)"
)]
pub fn chrome_profile(
  profile: &str,
  domains: Option<Vec<String>>,
) -> anyhow::Result<report::ExtractionReport> {
  extract_report_inner(
    ReportRequest::browser("chrome")
      .profile(profile)
      .domains(domains)
      .execution(legacy_execution()),
  )
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
/// * `profile_id` - An optional profile query, restricting the report to one
///   profile. The unified resolver accepts an opaque
///   [`ProfileId`](report::ProfileId) from [`browser_profiles`], a display
///   name, a directory name, or a non-lossy full path. Empty, unknown,
///   ambiguous, and lossy-only queries are rejected.
/// * `domains` - An optional list for getting specific domains only
///
/// # Errors
///
/// Only a bad request fails: an unknown browser ID or alias, or an invalid
/// profile query. Extraction problems are reported instead —
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
  let mut request = ReportRequest::browser(browser_id).domains(domains);
  if let Some(query) = profile_id {
    request = request.profile(query);
  }
  // With no profile query the scope stays `AllProfiles`, which is what this
  // function has always meant. The 0.6-beta shape could not state that: one
  // `Request` value selected the first profile here and every profile there.
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
  load_report_with(LoadReportRequest::default().domains(domains))
}

/// The aggregate report job as data, so it can carry execution control.
///
/// There is deliberately no request type for the *listing* jobs
/// ([`browser_profiles`], [`chrome_profiles`]): listing has no selection,
/// session policy, or domain filter to carry, so an envelope struct would be
/// ceremony. This one exists because `load_report` already takes a domain
/// filter.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoadReportRequest {
  domains: Option<Vec<String>>,
  control: ExecutionControl,
}

impl LoadReportRequest {
  /// Restricts the report to the given domains, or clears a prior restriction
  /// on `None`.
  pub fn domains(mut self, domains: Option<Vec<String>>) -> Self {
    self.domains = domains;
    self
  }

  /// Overrides the default 30-second budget shared by the whole fan-out.
  pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
    self.control = self.control.timeout(timeout);
    self
  }

  /// Lets `handle` cancel the whole fan-out from another thread.
  pub fn cancellation(mut self, handle: CancellationHandle) -> Self {
    self.control = self.control.cancellation(handle);
    self
  }

  /// Selects the Windows App-Bound (v20) recovery policy for every browser in
  /// the fan-out.
  pub fn app_bound(mut self, policy: AppBoundPolicy) -> Self {
    self.control = self.control.app_bound(policy);
    self
  }

  /// Replaces this request's execution control **wholesale**, discarding an
  /// earlier `timeout` / `cancellation` / `app_bound` call.
  pub fn execution(mut self, control: ExecutionControl) -> Self {
    self.control = control;
    self
  }
}

/// [`load_report`] under caller-supplied execution control.
///
/// # Examples
///
/// ```no_run
/// use std::time::Duration;
///
/// let request = rookie_cookies::LoadReportRequest::default().timeout(Duration::from_secs(10));
/// let report = rookie_cookies::load_report_with(request)?;
/// println!("{}", report.status);
/// # Ok::<(), rookie_cookies::Error>(())
/// ```
pub fn load_report_with(request: LoadReportRequest) -> Result<report::ExtractionReport> {
  error::map_job_result(browser::report_build::load_extraction_report(
    request.domains,
    &request.control,
  ))
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
  note = "use direct_path::extract_from_path with PathExtractRequest"
)]
pub fn any_browser(
  cookies_path: &str,
  domains: Option<Vec<String>>,
  key_path: Option<&str>,
) -> anyhow::Result<Vec<Cookie>> {
  compatibility_dispatch::any_browser(cookies_path, domains, key_path)
}

#[cfg(test)]
mod tests;
