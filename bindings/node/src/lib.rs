#![allow(deprecated)]

#[macro_use]
extern crate napi_derive;

use napi::{bindgen_prelude::AsyncTask, Result, Status, Task};
use rookie_cookies::direct_path::{
  ChromiumCredentialSource, ChromiumPathRequest, DirectPathRequest,
};
use rookie_cookies::enums::{Cookie, DetailedCookie};
use rookie_cookies::report::{
  BrowserCapabilitiesDescriptor, BrowserDescriptor, CookieSourceDescriptor, CookieSourceIdentity,
  ExtractionIssue, ExtractionReport, ExtractionStats, ProfileDescriptor, ProfileExtraction,
  ProfileIdentity, ReportStats, SourceExtraction,
};
use rookie_cookies::{
  CancellationHandle, FromPathRequest, MozillaProfile, ReadRequest, ReadResult, Request,
};
use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::time::Duration;

/// Converts a `rookie_cookies` error into a `napi::Error`, picking the status
/// code from [`rookie_cookies::fault_kind`] instead of collapsing every
/// failure into `Status::Unknown`. `FaultKind` is `#[non_exhaustive]`, so the
/// match keeps a wildcard arm for kinds this binding doesn't know about yet.
fn classify_fault(error: rookie_cookies::anyhow::Error) -> napi::Error {
  match rookie_cookies::fault_kind(&error) {
    rookie_cookies::FaultKind::Request => {
      napi::Error::new(Status::InvalidArg, format!("{error:?}"))
    }
    _ => napi::Error::new(Status::GenericFailure, format!("{error:?}")),
  }
}

/// A cross-thread cancellation token for an in-flight extraction.
///
/// `cancel()` is safe to call from the JS main thread while the matching
/// extraction runs on napi's worker threadpool: it flips a shared atomic
/// flag that the extraction observes at the same deadline/cancellation
/// checkpoints a `timeoutMs` budget uses, so cancellation takes effect
/// mid-extraction rather than only before it starts.
// `js_name` keeps the Rust-side `Js`-prefixed identifier (avoiding a name
// clash with the imported `rookie_cookies::CancellationHandle`) off the
// public JS API, matching the Python binding's plain `CancellationHandle`.
#[napi(js_name = "CancellationHandle")]
pub struct JsCancellationHandle(CancellationHandle);

impl Default for JsCancellationHandle {
  fn default() -> Self {
    Self(CancellationHandle::new())
  }
}

#[napi]
impl JsCancellationHandle {
  #[napi(constructor)]
  pub fn new() -> Self {
    Self::default()
  }

  /// Requests cancellation. Returns `true` the first time it takes effect,
  /// `false` if this handle was already cancelled.
  #[napi]
  pub fn cancel(&self) -> bool {
    self.0.cancel()
  }

  #[napi(getter)]
  pub fn is_cancelled(&self) -> bool {
    self.0.is_cancelled()
  }
}

#[napi(object)]
pub struct CookieObject {
  pub domain: String,
  pub path: String,
  pub secure: bool,
  /// Unix expiry time. Source values above `i64::MAX` are omitted rather than
  /// wrapping into a negative JavaScript number.
  pub expires: Option<i64>,
  pub name: String,
  pub value: String,
  pub http_only: bool,
  pub same_site: i64,
}

/// Browser context that distinguishes partitioned/container cookies.
#[napi(object, use_nullable = true)]
pub struct CookieContextObject {
  pub top_frame_site_key: Option<String>,
  pub has_cross_site_ancestor: Option<bool>,
  pub source_scheme: Option<i64>,
  pub source_port: Option<i64>,
  pub is_persistent: Option<bool>,
  pub origin_attributes: Option<String>,
  pub user_context_id: Option<u32>,
  pub partition_key: Option<String>,
  pub private_browsing_id: Option<u32>,
}

/// Cookie plus browser-specific identity context. The nested `cookie` has the
/// unchanged legacy `CookieObject` shape.
#[napi(object)]
pub struct DetailedCookieObject {
  pub cookie: CookieObject,
  pub context: CookieContextObject,
}

/// Cross-platform options for explicit Chromium cookie databases.
#[napi(object)]
pub struct ChromiumPathOptions {
  pub domains: Option<Vec<String>>,
  pub browser_id: Option<String>,
  pub local_state_path: Option<String>,
  pub plaintext_only: Option<bool>,
}

#[napi(object)]
pub struct FirefoxProfileObject {
  pub name: String,
  pub path: String,
  pub is_default: bool,
}

// ---------------------------------------------------------------------------
// Report objects
//
// The camelCase counterparts of `rookie_cookies::report`. Every identifier and
// code stays an open string, so a value this build has never heard of is still
// representable; compare against a known string and keep a fallback branch.
//
// Every counter is declared `u32` so it arrives as an ordinary JavaScript
// number. A `u64` would be generated as a `BigInt`, which no existing consumer
// of this package expects, and the Rust contract already saturates counters
// into `u32` and reports that through `countersSaturated`.
// ---------------------------------------------------------------------------

/// What a registered browser claims it can do on this platform.
#[napi(object)]
pub struct BrowserCapabilitiesObject {
  pub persistent_formats: Vec<String>,
  pub session_formats: Vec<String>,
  pub declared_decryption_tiers: Vec<String>,
  /// The declared tiers narrowed to the key providers this build actually
  /// compiled and enabled.
  pub available_decryption_tiers: Vec<String>,
}

/// A browser registered for the running OS. Registration is not detection.
#[napi(object)]
pub struct BrowserDescriptorObject {
  pub id: String,
  pub aliases: Vec<String>,
  pub display_name: String,
  pub engine: String,
  pub capabilities: BrowserCapabilitiesObject,
}

/// Stable identity of one discovered profile.
///
/// `profileId` is the selection key; `path` is a display value that may be
/// lossy on a non-UTF-8 filesystem, which `pathLossy` reports.
#[napi(object)]
pub struct ProfileIdentityObject {
  pub browser_id: String,
  pub installation_id: String,
  pub profile_id: String,
  pub display_name: String,
  pub path: String,
  pub path_lossy: bool,
}

/// A cookie source a profile exposes, before any extraction is attempted.
#[napi(object)]
pub struct CookieSourceDescriptorObject {
  pub role: String,
  pub format: String,
  pub path: String,
  pub path_lossy: bool,
  /// Widened from the Rust `u16` so it arrives as an ordinary number.
  pub precedence: u32,
}

/// Identity of the source an extraction attempted.
#[napi(object)]
pub struct CookieSourceIdentityObject {
  pub role: String,
  pub format: String,
  pub path: String,
  pub path_lossy: bool,
  /// Widened from the Rust `u16` so it arrives as an ordinary number.
  pub precedence: u32,
}

/// One discovered profile and its cookie sources.
#[napi(object)]
pub struct ProfileDescriptorObject {
  pub profile: ProfileIdentityObject,
  pub is_default: bool,
  pub sources: Vec<CookieSourceDescriptorObject>,
}

/// Row accounting for one source or profile.
///
/// A count that exceeded `u32` is clamped and sets `countersSaturated`.
#[napi(object)]
pub struct ExtractionStatsObject {
  pub rows_seen: u32,
  pub cookies_emitted: u32,
  pub rows_skipped: u32,
  pub rows_rejected: u32,
  pub provider_failures: u32,
  pub acquisition_attempts: u32,
  pub counters_saturated: bool,
}

/// Request-wide totals, including browsers that were registered but absent.
#[napi(object)]
pub struct ReportStatsObject {
  pub registered_browsers: u32,
  pub browsers_detected: u32,
  pub browsers_not_detected: u32,
  pub installations_discovered: u32,
  pub profiles_discovered: u32,
  pub sources_succeeded: u32,
  pub sources_failed: u32,
  pub rows_seen: u32,
  pub cookies_emitted: u32,
  pub rows_skipped: u32,
  pub rows_rejected: u32,
  pub provider_failures: u32,
  pub counters_saturated: bool,
}

/// A diagnostic attached to the request, a profile, or a source.
///
/// Repeated row-level problems are aggregated by code and stage: `occurrences`
/// counts them all while `samples` keeps a bounded excerpt.
///
/// `use_nullable` keeps the optional context fields present and `null` rather
/// than absent, so an unset one reads the same here as the `None` Python emits
/// and the `null` the CLI's serde output emits. napi's default would omit the
/// key entirely and make Node the only surface where it disappears.
/// [`CookieObject`] deliberately keeps the default: its shape predates the
/// report DTOs and is frozen by the compatibility contract.
#[napi(object, use_nullable = true)]
pub struct ExtractionIssueObject {
  pub code: String,
  pub stage: String,
  pub severity: String,
  pub cause: String,
  pub provider: Option<String>,
  pub tier: Option<String>,
  pub retryability: String,
  pub occurrences: u32,
  pub samples: Vec<String>,
  pub browser_id: Option<String>,
  pub installation_id: Option<String>,
  pub profile_id: Option<String>,
  pub message: String,
}

/// One attempted cookie source and the cookies it produced.
///
/// A profile-wide cookie stream is the concatenation of its `selected` sources
/// whose `status` is `succeeded`, in the order they appear. Both halves matter:
/// a source that was attempted and rejected in favour of another candidate can
/// still report `succeeded`.
#[napi(object)]
pub struct SourceExtractionObject {
  pub source: CookieSourceIdentityObject,
  pub status: String,
  pub selected: bool,
  pub acquisition_strategy: String,
  pub cookies: Vec<CookieObject>,
  pub stats: ExtractionStatsObject,
  pub issues: Vec<ExtractionIssueObject>,
}

/// One profile's sources, totals, and profile-scoped diagnostics.
#[napi(object)]
pub struct ProfileExtractionObject {
  pub profile: ProfileIdentityObject,
  pub sources: Vec<SourceExtractionObject>,
  pub stats: ExtractionStatsObject,
  pub issues: Vec<ExtractionIssueObject>,
}

/// A grouped extraction result.
///
/// `issues` holds only request-wide, registry, discovery, and installation
/// problems; anything narrower is attached to its profile or source.
#[napi(object)]
pub struct ExtractionReportObject {
  pub schema_version: u32,
  pub status: String,
  pub termination: String,
  pub summary: ReportStatsObject,
  pub profiles: Vec<ProfileExtractionObject>,
  pub issues: Vec<ExtractionIssueObject>,
}

#[napi]
pub fn version() -> Result<String> {
  Ok(rookie_cookies::version())
}

fn cookies_to_js(cookies: Vec<Cookie>) -> Result<Vec<CookieObject>> {
  let mut js_cookies: Vec<CookieObject> = vec![];
  for cookie in cookies {
    js_cookies.push(CookieObject {
      domain: cookie.domain,
      path: cookie.path,
      secure: cookie.secure,
      http_only: cookie.http_only,
      same_site: cookie.same_site,
      expires: cookie.expires.and_then(|value| i64::try_from(value).ok()),
      name: cookie.name,
      value: cookie.value,
    });
  }

  Ok(js_cookies)
}

fn detailed_cookies_to_js(cookies: Vec<DetailedCookie>) -> Result<Vec<DetailedCookieObject>> {
  cookies
    .into_iter()
    .map(|detailed| {
      let cookie = detailed.cookie;
      Ok(DetailedCookieObject {
        cookie: CookieObject {
          domain: cookie.domain,
          path: cookie.path,
          secure: cookie.secure,
          http_only: cookie.http_only,
          same_site: cookie.same_site,
          expires: cookie.expires.and_then(|value| i64::try_from(value).ok()),
          name: cookie.name,
          value: cookie.value,
        },
        context: CookieContextObject {
          top_frame_site_key: detailed.context.top_frame_site_key,
          has_cross_site_ancestor: detailed.context.has_cross_site_ancestor,
          source_scheme: detailed.context.source_scheme,
          source_port: detailed.context.source_port,
          is_persistent: detailed.context.is_persistent,
          origin_attributes: detailed.context.origin_attributes,
          user_context_id: detailed.context.user_context_id,
          partition_key: detailed.context.partition_key,
          private_browsing_id: detailed.context.private_browsing_id,
        },
      })
    })
    .collect()
}

/// Serialize cookies in Netscape cookie-file format.
///
/// Tabs, carriage returns, and line feeds in cookie-controlled fields are
/// encoded as `%09`, `%0D`, and `%0A`, matching the Rust, CLI, and Python APIs.
#[napi]
pub fn to_netscape(cookies: Vec<CookieObject>) -> String {
  let cookies = cookies
    .into_iter()
    .map(|cookie| Cookie {
      domain: cookie.domain,
      path: cookie.path,
      secure: cookie.secure,
      expires: cookie.expires.and_then(|value| u64::try_from(value).ok()),
      name: cookie.name,
      value: cookie.value,
      http_only: cookie.http_only,
      same_site: cookie.same_site,
    })
    .collect();

  rookie_cookies::common::format::netscape(cookies)
}

fn profiles_to_js(profiles: Vec<MozillaProfile>) -> Vec<FirefoxProfileObject> {
  profiles
    .into_iter()
    .map(|profile| FirefoxProfileObject {
      name: profile.name,
      path: profile.path.to_string_lossy().into_owned(),
      is_default: profile.is_default,
    })
    .collect()
}

fn identifiers_to_js(values: Vec<impl AsRef<str>>) -> Vec<String> {
  values
    .into_iter()
    .map(|value| value.as_ref().to_owned())
    .collect()
}

fn capabilities_to_js(capabilities: BrowserCapabilitiesDescriptor) -> BrowserCapabilitiesObject {
  BrowserCapabilitiesObject {
    persistent_formats: identifiers_to_js(capabilities.persistent_formats),
    session_formats: identifiers_to_js(capabilities.session_formats),
    declared_decryption_tiers: identifiers_to_js(capabilities.declared_decryption_tiers),
    available_decryption_tiers: identifiers_to_js(capabilities.available_decryption_tiers),
  }
}

fn browser_descriptor_to_js(browser: BrowserDescriptor) -> BrowserDescriptorObject {
  BrowserDescriptorObject {
    id: browser.id.as_str().to_owned(),
    aliases: browser.aliases,
    display_name: browser.display_name,
    engine: browser.engine.as_str().to_owned(),
    capabilities: capabilities_to_js(browser.capabilities),
  }
}

fn profile_identity_to_js(profile: ProfileIdentity) -> ProfileIdentityObject {
  ProfileIdentityObject {
    browser_id: profile.browser_id.as_str().to_owned(),
    installation_id: profile.installation_id.as_str().to_owned(),
    profile_id: profile.profile_id.as_str().to_owned(),
    display_name: profile.display_name,
    path: profile.path,
    path_lossy: profile.path_lossy,
  }
}

fn source_descriptor_to_js(source: CookieSourceDescriptor) -> CookieSourceDescriptorObject {
  CookieSourceDescriptorObject {
    role: source.role.as_str().to_owned(),
    format: source.format.as_str().to_owned(),
    path: source.path,
    path_lossy: source.path_lossy,
    precedence: u32::from(source.precedence),
  }
}

fn source_identity_to_js(source: CookieSourceIdentity) -> CookieSourceIdentityObject {
  CookieSourceIdentityObject {
    role: source.role.as_str().to_owned(),
    format: source.format.as_str().to_owned(),
    path: source.path,
    path_lossy: source.path_lossy,
    precedence: u32::from(source.precedence),
  }
}

fn profile_descriptor_to_js(profile: ProfileDescriptor) -> ProfileDescriptorObject {
  ProfileDescriptorObject {
    profile: profile_identity_to_js(profile.profile),
    is_default: profile.is_default,
    sources: profile
      .sources
      .into_iter()
      .map(source_descriptor_to_js)
      .collect(),
  }
}

fn extraction_stats_to_js(stats: ExtractionStats) -> ExtractionStatsObject {
  ExtractionStatsObject {
    rows_seen: stats.rows_seen,
    cookies_emitted: stats.cookies_emitted,
    rows_skipped: stats.rows_skipped,
    rows_rejected: stats.rows_rejected,
    provider_failures: stats.provider_failures,
    acquisition_attempts: stats.acquisition_attempts,
    counters_saturated: stats.counters_saturated,
  }
}

fn report_stats_to_js(stats: ReportStats) -> ReportStatsObject {
  ReportStatsObject {
    registered_browsers: stats.registered_browsers,
    browsers_detected: stats.browsers_detected,
    browsers_not_detected: stats.browsers_not_detected,
    installations_discovered: stats.installations_discovered,
    profiles_discovered: stats.profiles_discovered,
    sources_succeeded: stats.sources_succeeded,
    sources_failed: stats.sources_failed,
    rows_seen: stats.rows_seen,
    cookies_emitted: stats.cookies_emitted,
    rows_skipped: stats.rows_skipped,
    rows_rejected: stats.rows_rejected,
    provider_failures: stats.provider_failures,
    counters_saturated: stats.counters_saturated,
  }
}

fn issues_to_js(issues: Vec<ExtractionIssue>) -> Vec<ExtractionIssueObject> {
  issues
    .into_iter()
    .map(|issue| ExtractionIssueObject {
      code: issue.code.as_str().to_owned(),
      stage: issue.stage.as_str().to_owned(),
      severity: issue.severity.as_str().to_owned(),
      cause: issue.cause,
      provider: issue.provider,
      tier: issue.tier,
      retryability: issue.retryability,
      occurrences: issue.occurrences,
      samples: issue.samples,
      browser_id: issue.browser_id.map(|id| id.as_str().to_owned()),
      installation_id: issue.installation_id.map(|id| id.as_str().to_owned()),
      profile_id: issue.profile_id.map(|id| id.as_str().to_owned()),
      message: issue.message,
    })
    .collect()
}

fn source_extraction_to_js(source: SourceExtraction) -> Result<SourceExtractionObject> {
  Ok(SourceExtractionObject {
    source: source_identity_to_js(source.source),
    status: source.status.as_str().to_owned(),
    selected: source.selected,
    acquisition_strategy: source.acquisition_strategy.as_str().to_owned(),
    cookies: cookies_to_js(source.cookies)?,
    stats: extraction_stats_to_js(source.stats),
    issues: issues_to_js(source.issues),
  })
}

fn profile_extraction_to_js(profile: ProfileExtraction) -> Result<ProfileExtractionObject> {
  Ok(ProfileExtractionObject {
    profile: profile_identity_to_js(profile.profile),
    sources: profile
      .sources
      .into_iter()
      .map(source_extraction_to_js)
      .collect::<Result<Vec<_>>>()?,
    stats: extraction_stats_to_js(profile.stats),
    issues: issues_to_js(profile.issues),
  })
}

fn report_to_js(report: ExtractionReport) -> Result<ExtractionReportObject> {
  Ok(ExtractionReportObject {
    schema_version: report.schema_version,
    status: report.status.as_str().to_owned(),
    termination: report.termination.as_str().to_owned(),
    summary: report_stats_to_js(report.summary),
    profiles: report
      .profiles
      .into_iter()
      .map(profile_extraction_to_js)
      .collect::<Result<Vec<_>>>()?,
    issues: issues_to_js(report.issues),
  })
}

fn panic_message(payload: &(dyn Any + Send)) -> &str {
  if let Some(message) = payload.downcast_ref::<&str>() {
    message
  } else if let Some(message) = payload.downcast_ref::<String>() {
    message.as_str()
  } else {
    "unknown panic payload"
  }
}

/// Keep Rust unwinds inside the worker boundary. napi-rs executes `Task::compute`
/// from an `extern "C"` callback, where an escaping panic would abort Node instead
/// of rejecting the task's Promise.
fn run_worker<T>(worker: impl FnOnce() -> Result<T>) -> Result<T> {
  match catch_unwind(AssertUnwindSafe(worker)) {
    Ok(result) => result,
    Err(payload) => Err(napi::Error::new(
      Status::GenericFailure,
      format!(
        "cookie extraction worker panicked: {}",
        panic_message(payload.as_ref())
      ),
    )),
  }
}

fn chromium_path_request(
  path: String,
  options: Option<ChromiumPathOptions>,
) -> Result<ChromiumPathRequest> {
  let mut request = ChromiumPathRequest::new(path);
  let Some(options) = options else {
    return Ok(request);
  };
  if let Some(domains) = options.domains {
    request = request.domains(domains);
  }

  let plaintext_only = options.plaintext_only.unwrap_or(false);
  let selector_count = usize::from(options.browser_id.is_some())
    + usize::from(options.local_state_path.is_some())
    + usize::from(plaintext_only);
  if selector_count > 1 {
    return Err(napi::Error::new(
      Status::InvalidArg,
      "Chromium path options browserId, localStatePath, and plaintextOnly are mutually exclusive",
    ));
  }

  let credentials = if let Some(browser_id) = options.browser_id {
    Some(ChromiumCredentialSource::BrowserId(browser_id))
  } else if let Some(local_state_path) = options.local_state_path {
    Some(ChromiumCredentialSource::LocalStateFile(PathBuf::from(
      local_state_path,
    )))
  } else if plaintext_only {
    Some(ChromiumCredentialSource::PlaintextOnly)
  } else {
    None
  };
  if let Some(credentials) = credentials {
    request = request.credentials(credentials);
  }
  Ok(request)
}

pub struct CookiesFromPathTask {
  request: DirectPathRequest,
}

impl Task for CookiesFromPathTask {
  type Output = Vec<Cookie>;
  type JsValue = Vec<CookieObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    run_worker(|| {
      rookie_cookies::direct_path::cookies_from_path(self.request.clone()).map_err(classify_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    cookies_to_js(output)
  }
}

#[napi(ts_return_type = "Promise<Array<CookieObject>>")]
pub fn cookies_from_path(
  path: String,
  domains: Option<Vec<String>>,
  timeout_ms: Option<u32>,
  cancellation: Option<&JsCancellationHandle>,
) -> AsyncTask<CookiesFromPathTask> {
  let mut request = DirectPathRequest::new(path);
  if let Some(domains) = domains {
    request = request.domains(domains);
  }
  if let Some(ms) = timeout_ms {
    request = request.timeout(Duration::from_millis(ms as u64));
  }
  if let Some(handle) = cancellation {
    request = request.cancellation(handle.0.clone());
  }
  AsyncTask::new(CookiesFromPathTask { request })
}

pub struct ChromiumCookiesFromPathTask {
  request: ChromiumPathRequest,
}

impl Task for ChromiumCookiesFromPathTask {
  type Output = Vec<Cookie>;
  type JsValue = Vec<CookieObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    run_worker(|| {
      rookie_cookies::direct_path::chromium_cookies_from_path(self.request.clone())
        .map_err(classify_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    cookies_to_js(output)
  }
}

#[napi(ts_return_type = "Promise<Array<CookieObject>>")]
pub fn chromium_cookies_from_path(
  path: String,
  options: Option<ChromiumPathOptions>,
  timeout_ms: Option<u32>,
  cancellation: Option<&JsCancellationHandle>,
) -> Result<AsyncTask<ChromiumCookiesFromPathTask>> {
  let mut request = chromium_path_request(path, options)?;
  if let Some(ms) = timeout_ms {
    request = request.timeout(Duration::from_millis(ms as u64));
  }
  if let Some(handle) = cancellation {
    request = request.cancellation(handle.0.clone());
  }
  Ok(AsyncTask::new(ChromiumCookiesFromPathTask { request }))
}

pub struct ChromiumCookiesFromPathDetailedTask {
  request: ChromiumPathRequest,
}

impl Task for ChromiumCookiesFromPathDetailedTask {
  type Output = Vec<DetailedCookie>;
  type JsValue = Vec<DetailedCookieObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    run_worker(|| {
      rookie_cookies::direct_path::chromium_cookies_from_path_detailed(self.request.clone())
        .map_err(classify_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    detailed_cookies_to_js(output)
  }
}

#[napi(ts_return_type = "Promise<Array<DetailedCookieObject>>")]
pub fn chromium_cookies_from_path_detailed(
  path: String,
  options: Option<ChromiumPathOptions>,
  timeout_ms: Option<u32>,
  cancellation: Option<&JsCancellationHandle>,
) -> Result<AsyncTask<ChromiumCookiesFromPathDetailedTask>> {
  let mut request = chromium_path_request(path, options)?;
  if let Some(ms) = timeout_ms {
    request = request.timeout(Duration::from_millis(ms as u64));
  }
  if let Some(handle) = cancellation {
    request = request.cancellation(handle.0.clone());
  }
  Ok(AsyncTask::new(ChromiumCookiesFromPathDetailedTask {
    request,
  }))
}

// ---------------------------------------------------------------------------
// AnyBrowser needs special handling (db_path, domains, key_path)
// ---------------------------------------------------------------------------

pub struct AnyBrowserTaskImpl {
  db_path: String,
  domains: Option<Vec<String>>,
  key_path: Option<String>,
}

impl Task for AnyBrowserTaskImpl {
  type Output = Vec<Cookie>;
  type JsValue = Vec<CookieObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    run_worker(|| {
      rookie_cookies::any_browser(&self.db_path, self.domains.take(), self.key_path.as_deref())
        .map_err(classify_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    cookies_to_js(output)
  }
}

/// @deprecated Use `cookiesFromPath` or `chromiumCookiesFromPath`. Earliest removal is 0.7.
#[napi(ts_return_type = "Promise<Array<CookieObject>>")]
pub fn any_browser(
  db_path: String,
  domains: Option<Vec<String>>,
  key_path: Option<String>,
) -> AsyncTask<AnyBrowserTaskImpl> {
  AsyncTask::new(AnyBrowserTaskImpl {
    db_path,
    domains,
    key_path,
  })
}

// ---------------------------------------------------------------------------
// Macro for single-arg (domains) async browser functions
// ---------------------------------------------------------------------------
macro_rules! async_browser_fn {
  ($name:ident, $task_name:ident, $core_fn:expr) => {
    pub struct $task_name {
      domains: Option<Vec<String>>,
    }

    impl Task for $task_name {
      type Output = Vec<Cookie>;
      type JsValue = Vec<CookieObject>;

      fn compute(&mut self) -> Result<Self::Output> {
        run_worker(|| $core_fn(self.domains.take()).map_err(classify_fault))
      }

      fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
        cookies_to_js(output)
      }
    }

    #[napi(ts_return_type = "Promise<Array<CookieObject>>")]
    pub fn $name(domains: Option<Vec<String>>) -> AsyncTask<$task_name> {
      AsyncTask::new($task_name { domains })
    }
  };
}

// `load` scans every registered browser and has no `Request::browser` equivalent
// to route a timeout/cancellation handle through, so it keeps the plain form.
async_browser_fn!(load, LoadTask, rookie_cookies::load);

// ---------------------------------------------------------------------------
// Macro for single-browser async functions that support `timeoutMs` and a
// `JsCancellationHandle`, routed through `extract(Request::browser(id))`
// exactly like the CLI's `--browser` mode (see `cli/src/browsers_map.rs`).
// ---------------------------------------------------------------------------
macro_rules! async_named_browser_fn {
  ($name:ident, $task_name:ident, $browser_id:literal) => {
    pub struct $task_name {
      domains: Option<Vec<String>>,
      timeout_ms: Option<u32>,
      cancellation: Option<CancellationHandle>,
    }

    impl Task for $task_name {
      type Output = Vec<Cookie>;
      type JsValue = Vec<CookieObject>;

      fn compute(&mut self) -> Result<Self::Output> {
        run_worker(|| {
          let mut request = Request::browser($browser_id).domains(self.domains.take());
          if let Some(ms) = self.timeout_ms {
            request = request.timeout(Duration::from_millis(ms as u64));
          }
          if let Some(handle) = self.cancellation.take() {
            request = request.cancellation(handle);
          }
          rookie_cookies::extract(request).map_err(classify_fault)
        })
      }

      fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
        cookies_to_js(output)
      }
    }

    #[napi(ts_return_type = "Promise<Array<CookieObject>>")]
    pub fn $name(
      domains: Option<Vec<String>>,
      timeout_ms: Option<u32>,
      cancellation: Option<&JsCancellationHandle>,
    ) -> AsyncTask<$task_name> {
      AsyncTask::new($task_name {
        domains,
        timeout_ms,
        cancellation: cancellation.map(|handle| handle.0.clone()),
      })
    }
  };
}

// Common browsers

async_named_browser_fn!(firefox, FirefoxTask, "firefox");
async_named_browser_fn!(zen, ZenTask, "zen");
async_named_browser_fn!(librewolf, LibrewolfTask, "librewolf");
#[cfg(target_os = "linux")]
async_named_browser_fn!(cachy, CachyTask, "cachy");
async_named_browser_fn!(chrome, ChromeTask, "chrome");
async_named_browser_fn!(brave, BraveTask, "brave");
async_named_browser_fn!(arc, ArcTask, "arc");
async_named_browser_fn!(edge, EdgeTask, "edge");
async_named_browser_fn!(opera, OperaTask, "opera");
#[cfg(any(target_os = "macos", target_os = "windows"))]
async_named_browser_fn!(opera_gx, OperaGxTask, "opera_gx");
async_named_browser_fn!(chromium, ChromiumTask, "chromium");
async_named_browser_fn!(vivaldi, VivaldiTask, "vivaldi");

pub struct FirefoxProfilesTask;

impl Task for FirefoxProfilesTask {
  type Output = Vec<MozillaProfile>;
  type JsValue = Vec<FirefoxProfileObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    run_worker(|| rookie_cookies::firefox_profiles().map_err(classify_fault))
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(profiles_to_js(output))
  }
}

#[napi(ts_return_type = "Promise<Array<FirefoxProfileObject>>")]
pub fn firefox_profiles() -> AsyncTask<FirefoxProfilesTask> {
  AsyncTask::new(FirefoxProfilesTask)
}

pub struct FirefoxProfileTask {
  profile: String,
  domains: Option<Vec<String>>,
}

impl Task for FirefoxProfileTask {
  type Output = Vec<Cookie>;
  type JsValue = Vec<CookieObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    run_worker(|| {
      rookie_cookies::firefox_profile(&self.profile, self.domains.take()).map_err(classify_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    cookies_to_js(output)
  }
}

#[napi(ts_return_type = "Promise<Array<CookieObject>>")]
pub fn firefox_profile(
  profile: String,
  domains: Option<Vec<String>>,
) -> AsyncTask<FirefoxProfileTask> {
  AsyncTask::new(FirefoxProfileTask { profile, domains })
}

// firefox_based takes an extra db_path argument
pub struct FirefoxBasedTask {
  db_path: String,
  domains: Option<Vec<String>>,
}

impl Task for FirefoxBasedTask {
  type Output = Vec<Cookie>;
  type JsValue = Vec<CookieObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    run_worker(|| {
      rookie_cookies::firefox_based(PathBuf::from(&self.db_path), self.domains.take())
        .map_err(classify_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    cookies_to_js(output)
  }
}

/// @deprecated Use `cookiesFromPath`. Earliest removal is 0.7.
#[napi(ts_return_type = "Promise<Array<CookieObject>>")]
pub fn firefox_based(db_path: String, domains: Option<Vec<String>>) -> AsyncTask<FirefoxBasedTask> {
  AsyncTask::new(FirefoxBasedTask { db_path, domains })
}

pub struct FirefoxBasedDetailedTask {
  db_path: String,
  domains: Option<Vec<String>>,
}

impl Task for FirefoxBasedDetailedTask {
  type Output = Vec<DetailedCookie>;
  type JsValue = Vec<DetailedCookieObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    run_worker(|| {
      rookie_cookies::firefox_based_detailed(PathBuf::from(&self.db_path), self.domains.take())
        .map_err(classify_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    detailed_cookies_to_js(output)
  }
}

/// Extracts cookies with Firefox container and origin context preserved.
#[napi(ts_return_type = "Promise<Array<DetailedCookieObject>>")]
pub fn firefox_based_detailed(
  db_path: String,
  domains: Option<Vec<String>>,
) -> AsyncTask<FirefoxBasedDetailedTask> {
  AsyncTask::new(FirefoxBasedDetailedTask { db_path, domains })
}

// ---------------------------------------------------------------------------
// Generic report APIs
//
// These cover every installation and profile of a browser and keep failures
// visible, unlike the named selectors above, which keep their historical
// single-source, flat-array behaviour.
// ---------------------------------------------------------------------------

pub struct SupportedBrowsersTask;

impl Task for SupportedBrowsersTask {
  type Output = Vec<BrowserDescriptor>;
  type JsValue = Vec<BrowserDescriptorObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    run_worker(|| rookie_cookies::supported_browsers().map_err(classify_fault))
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output.into_iter().map(browser_descriptor_to_js).collect())
  }
}

/// Lists the browsers registered for the running OS.
///
/// Registration is not detection: a listed browser need not be installed.
#[napi(ts_return_type = "Promise<Array<BrowserDescriptorObject>>")]
pub fn supported_browsers() -> AsyncTask<SupportedBrowsersTask> {
  AsyncTask::new(SupportedBrowsersTask)
}

pub struct BrowserProfilesTask {
  browser_id: String,
}

impl Task for BrowserProfilesTask {
  type Output = Vec<ProfileDescriptor>;
  type JsValue = Vec<ProfileDescriptorObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    run_worker(|| rookie_cookies::browser_profiles(&self.browser_id).map_err(classify_fault))
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output.into_iter().map(profile_descriptor_to_js).collect())
  }
}

/// Lists the discovered profiles of one registered browser.
///
/// Rejects on an unknown `browserId`, or when every detected installation root
/// failed enumeration. A known browser with nothing installed resolves to an
/// empty array.
#[napi(ts_return_type = "Promise<Array<ProfileDescriptorObject>>")]
pub fn browser_profiles(browser_id: String) -> AsyncTask<BrowserProfilesTask> {
  AsyncTask::new(BrowserProfilesTask { browser_id })
}

pub struct ChromeProfilesTask;

impl Task for ChromeProfilesTask {
  type Output = Vec<ProfileDescriptor>;
  type JsValue = Vec<ProfileDescriptorObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    run_worker(|| rookie_cookies::chrome_profiles().map_err(classify_fault))
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output.into_iter().map(profile_descriptor_to_js).collect())
  }
}

/// Lists Google Chrome profiles with the preferred active profile first.
///
/// Missing, stale, or malformed activity hints retain the generic
/// default-first discovery order.
#[napi(ts_return_type = "Promise<Array<ProfileDescriptorObject>>")]
pub fn chrome_profiles() -> AsyncTask<ChromeProfilesTask> {
  AsyncTask::new(ChromeProfilesTask)
}

pub struct ChromeProfileTask {
  profile: String,
  domains: Option<Vec<String>>,
}

impl Task for ChromeProfileTask {
  type Output = ExtractionReport;
  type JsValue = ExtractionReportObject;

  fn compute(&mut self) -> Result<Self::Output> {
    run_worker(|| {
      rookie_cookies::chrome_profile(&self.profile, self.domains.take()).map_err(classify_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    report_to_js(output)
  }
}

/// Extracts one selected Google Chrome profile as a grouped report.
///
/// `profile` accepts the opaque ID, display name, directory name, or a full
/// path returned by `chromeProfiles` when the descriptor's
/// `profile.pathLossy` is false. A lossy path requires its opaque ID. Ambiguous
/// names reject rather than silently choosing an installation or channel.
#[napi(ts_return_type = "Promise<ExtractionReportObject>")]
pub fn chrome_profile(
  profile: String,
  domains: Option<Vec<String>>,
) -> AsyncTask<ChromeProfileTask> {
  AsyncTask::new(ChromeProfileTask { profile, domains })
}

pub struct BrowserReportTask {
  browser_id: String,
  profile_id: Option<String>,
  domains: Option<Vec<String>>,
}

impl Task for BrowserReportTask {
  type Output = ExtractionReport;
  type JsValue = ExtractionReportObject;

  fn compute(&mut self) -> Result<Self::Output> {
    run_worker(|| {
      rookie_cookies::browser_report(
        &self.browser_id,
        self.profile_id.as_deref(),
        self.domains.take(),
      )
      .map_err(classify_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    report_to_js(output)
  }
}

/// Extracts cookies from one browser as a grouped report.
///
/// Only a bad request rejects: an unknown `browserId`, or a `profileId` this
/// browser did not yield. Extraction problems resolve as a report whose
/// `status` and `issues` describe them.
#[napi(ts_return_type = "Promise<ExtractionReportObject>")]
pub fn browser_report(
  browser_id: String,
  profile_id: Option<String>,
  domains: Option<Vec<String>>,
) -> AsyncTask<BrowserReportTask> {
  AsyncTask::new(BrowserReportTask {
    browser_id,
    profile_id,
    domains,
  })
}

pub struct LoadReportTask {
  domains: Option<Vec<String>>,
}

impl Task for LoadReportTask {
  type Output = ExtractionReport;
  type JsValue = ExtractionReportObject;

  fn compute(&mut self) -> Result<Self::Output> {
    run_worker(|| rookie_cookies::load_report(self.domains.take()).map_err(classify_fault))
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    report_to_js(output)
  }
}

/// Extracts cookies from every registered browser as one grouped report.
///
/// This is the report-shaped counterpart to `load`, not a replacement: `load`
/// keeps its historical browser set and flat output. A browser that fails does
/// not abort the others; it becomes an issue on the returned report.
#[napi(ts_return_type = "Promise<ExtractionReportObject>")]
pub fn load_report(domains: Option<Vec<String>>) -> AsyncTask<LoadReportTask> {
  AsyncTask::new(LoadReportTask { domains })
}

#[napi(object)]
pub struct ReadOptions {
  pub browser: String,
  pub profile: Option<String>,
  pub include_expired: Option<bool>,
  pub timeout_ms: Option<u32>,
}

#[napi(object)]
pub struct ReportOptions {
  pub browser: String,
  pub profile: Option<String>,
  pub domains: Option<Vec<String>>,
  pub timeout_ms: Option<u32>,
}

#[napi(object)]
pub struct FromPathOptions {
  pub path: String,
  pub include_expired: Option<bool>,
  pub timeout_ms: Option<u32>,
  pub browser_id: Option<String>,
  pub key_path: Option<String>,
  pub plaintext_only: Option<bool>,
}

#[napi(object)]
pub struct ReadWarningObject {
  pub code: String,
  pub count: u32,
  pub message: String,
}

fn clone_cookies(cookies: &[Cookie]) -> Vec<Cookie> {
  cookies
    .iter()
    .map(|cookie| Cookie {
      domain: cookie.domain.clone(),
      path: cookie.path.clone(),
      secure: cookie.secure,
      expires: cookie.expires,
      name: cookie.name.clone(),
      value: cookie.value.clone(),
      http_only: cookie.http_only,
      same_site: cookie.same_site,
    })
    .collect()
}

#[napi(js_name = "ReadResult")]
pub struct JsReadResult {
  inner: ReadResult,
}

#[napi]
impl JsReadResult {
  /// Not constructible from JavaScript. Use `read()` or `fromPath()`.
  #[napi(constructor)]
  pub fn new() -> Result<Self> {
    Err(napi::Error::from_reason(
      "ReadResult cannot be constructed from JavaScript; call read() or fromPath()",
    ))
  }

  #[napi(getter)]
  pub fn cookies(&self) -> Result<Vec<CookieObject>> {
    cookies_to_js(clone_cookies(self.inner.cookies()))
  }

  #[napi(getter)]
  pub fn warnings(&self) -> Vec<ReadWarningObject> {
    self
      .inner
      .warnings()
      .iter()
      .map(|warning| ReadWarningObject {
        code: warning.code().to_owned(),
        count: u32::try_from(warning.count()).unwrap_or(u32::MAX),
        message: warning.to_string(),
      })
      .collect()
  }

  #[napi(getter, js_name = "browserId")]
  pub fn browser_id(&self) -> String {
    self.inner.browser_id().to_owned()
  }

  #[napi(getter, js_name = "profileId")]
  pub fn profile_id(&self) -> Option<String> {
    self.inner.profile_id().map(str::to_owned)
  }

  #[napi]
  pub fn header(&self, url: String) -> Result<String> {
    self.inner.header(&url).map_err(classify_fault)
  }
}

pub struct ReadTask {
  options: ReadOptions,
  cancellation: Option<CancellationHandle>,
}

impl Task for ReadTask {
  type Output = ReadResult;
  type JsValue = JsReadResult;

  fn compute(&mut self) -> Result<Self::Output> {
    let options = &self.options;
    run_worker(|| {
      let mut request = ReadRequest::browser(&options.browser);
      if let Some(profile) = options.profile.as_deref() {
        request = request.profile(profile);
      }
      if options.include_expired == Some(true) {
        request = request.include_expired(true);
      }
      if let Some(ms) = options.timeout_ms {
        request = request.timeout(Duration::from_millis(u64::from(ms)));
      }
      if let Some(handle) = self.cancellation.take() {
        request = request.cancellation(handle);
      }
      rookie_cookies::read(request).map_err(classify_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(JsReadResult { inner: output })
  }
}

/// Unfiltered snapshot of one browser profile. Never URL-pre-sliced.
#[napi(js_name = "read", ts_return_type = "Promise<ReadResult>")]
pub fn read(
  options: ReadOptions,
  cancellation: Option<&JsCancellationHandle>,
) -> AsyncTask<ReadTask> {
  AsyncTask::new(ReadTask {
    options,
    cancellation: cancellation.map(|handle| handle.0.clone()),
  })
}

pub struct ProfilesTask {
  browser_id: String,
}

impl Task for ProfilesTask {
  type Output = Vec<ProfileDescriptor>;
  type JsValue = Vec<ProfileDescriptorObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    run_worker(|| rookie_cookies::profiles(&self.browser_id).map_err(classify_fault))
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output.into_iter().map(profile_descriptor_to_js).collect())
  }
}

/// Alias of `browserProfiles`. No decrypt.
#[napi(
  js_name = "profiles",
  ts_return_type = "Promise<Array<ProfileDescriptorObject>>"
)]
pub fn profiles(browser_id: String) -> AsyncTask<ProfilesTask> {
  AsyncTask::new(ProfilesTask { browser_id })
}

pub struct JobReportTask {
  options: ReportOptions,
}

impl Task for JobReportTask {
  type Output = ExtractionReport;
  type JsValue = ExtractionReportObject;

  fn compute(&mut self) -> Result<Self::Output> {
    let options = &self.options;
    run_worker(|| {
      let mut request = Request::browser(&options.browser).domains(options.domains.clone());
      if let Some(profile) = options.profile.as_deref() {
        request = request.profile(profile);
      }
      if let Some(ms) = options.timeout_ms {
        request = request.timeout(Duration::from_millis(u64::from(ms)));
      }
      rookie_cookies::extract_report(request).map_err(classify_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    report_to_js(output)
  }
}

/// Bindings name for `extract_report` / `browserReport`.
#[napi(js_name = "report", ts_return_type = "Promise<ExtractionReportObject>")]
pub fn report(options: ReportOptions) -> AsyncTask<JobReportTask> {
  AsyncTask::new(JobReportTask { options })
}

pub struct FromPathTask {
  options: FromPathOptions,
  cancellation: Option<CancellationHandle>,
}

impl Task for FromPathTask {
  type Output = ReadResult;
  type JsValue = JsReadResult;

  fn compute(&mut self) -> Result<Self::Output> {
    let options = &self.options;
    run_worker(|| {
      let mut request = FromPathRequest::new(&options.path);
      if options.include_expired == Some(true) {
        request = request.include_expired(true);
      }
      if let Some(ms) = options.timeout_ms {
        request = request.timeout(Duration::from_millis(u64::from(ms)));
      }
      if let Some(handle) = self.cancellation.take() {
        request = request.cancellation(handle);
      }
      if options.plaintext_only == Some(true) {
        request = request.chromium_credentials(
          rookie_cookies::direct_path::ChromiumCredentialSource::PlaintextOnly,
        );
      } else if let Some(browser_id) = options.browser_id.as_deref() {
        request = request.chromium_credentials(
          rookie_cookies::direct_path::ChromiumCredentialSource::BrowserId(browser_id.to_owned()),
        );
      } else if let Some(key_path) = options.key_path.as_deref() {
        request = request.chromium_credentials(
          rookie_cookies::direct_path::ChromiumCredentialSource::LocalStateFile(PathBuf::from(
            key_path,
          )),
        );
      }
      rookie_cookies::from_path(request).map_err(classify_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(JsReadResult { inner: output })
  }
}

/// Read cookies from an explicit cookie database path.
#[napi(js_name = "fromPath", ts_return_type = "Promise<ReadResult>")]
pub fn from_path(
  options: FromPathOptions,
  cancellation: Option<&JsCancellationHandle>,
) -> AsyncTask<FromPathTask> {
  AsyncTask::new(FromPathTask {
    options,
    cancellation: cancellation.map(|handle| handle.0.clone()),
  })
}

// Windows only browsers

#[cfg(target_os = "windows")]
async_named_browser_fn!(octo_browser, OctoBrowserTask, "octo_browser");
#[cfg(target_os = "windows")]
async_named_browser_fn!(internet_explorer, InternetExplorerTask, "internet_explorer");

#[cfg(target_os = "windows")]
pub struct ChromiumBasedWinTask {
  key_path: String,
  db_path: String,
  domains: Option<Vec<String>>,
}

#[cfg(target_os = "windows")]
impl Task for ChromiumBasedWinTask {
  type Output = Vec<Cookie>;
  type JsValue = Vec<CookieObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    run_worker(|| {
      rookie_cookies::chromium_based(
        PathBuf::from(&self.key_path),
        PathBuf::from(&self.db_path),
        self.domains.take(),
        false,
      )
      .map_err(classify_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    cookies_to_js(output)
  }
}

/// @deprecated Use `chromiumCookiesFromPath`. Earliest removal is 0.7.
#[napi(ts_return_type = "Promise<Array<CookieObject>>")]
#[cfg(target_os = "windows")]
pub fn chromium_based(
  key_path: String,
  db_path: String,
  domains: Option<Vec<String>>,
) -> AsyncTask<ChromiumBasedWinTask> {
  AsyncTask::new(ChromiumBasedWinTask {
    key_path,
    db_path,
    domains,
  })
}

#[cfg(target_os = "windows")]
pub struct ChromiumBasedDetailedWinTask {
  key_path: String,
  db_path: String,
  domains: Option<Vec<String>>,
}

#[cfg(target_os = "windows")]
impl Task for ChromiumBasedDetailedWinTask {
  type Output = Vec<DetailedCookie>;
  type JsValue = Vec<DetailedCookieObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    run_worker(|| {
      rookie_cookies::chromium_based_detailed(
        PathBuf::from(&self.key_path),
        PathBuf::from(&self.db_path),
        self.domains.take(),
        false,
      )
      .map_err(classify_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    detailed_cookies_to_js(output)
  }
}

/// @deprecated Use `chromiumCookiesFromPathDetailed`. Earliest removal is 0.7.
#[napi(ts_return_type = "Promise<Array<DetailedCookieObject>>")]
#[cfg(target_os = "windows")]
pub fn chromium_based_detailed(
  key_path: String,
  db_path: String,
  domains: Option<Vec<String>>,
) -> AsyncTask<ChromiumBasedDetailedWinTask> {
  AsyncTask::new(ChromiumBasedDetailedWinTask {
    key_path,
    db_path,
    domains,
  })
}

// MacOS browsers

#[cfg(target_os = "macos")]
async_named_browser_fn!(safari, SafariTask, "safari");

// Unix browsers

#[cfg(unix)]
pub struct ChromiumBasedUnixTask {
  db_path: String,
  domains: Option<Vec<String>>,
  browser_id: Option<String>,
}

#[cfg(unix)]
impl Task for ChromiumBasedUnixTask {
  type Output = Vec<Cookie>;
  type JsValue = Vec<CookieObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    run_worker(|| {
      rookie_cookies::chromium_based_with_browser_id(
        self.browser_id.as_deref(),
        PathBuf::from(&self.db_path),
        self.domains.take(),
        false,
      )
      .map_err(classify_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    cookies_to_js(output)
  }
}

/// @deprecated Use `chromiumCookiesFromPath`. Earliest removal is 0.7.
#[napi(ts_return_type = "Promise<Array<CookieObject>>")]
#[cfg(unix)]
pub fn chromium_based(
  db_path: String,
  domains: Option<Vec<String>>,
  browser_id: Option<String>,
) -> AsyncTask<ChromiumBasedUnixTask> {
  AsyncTask::new(ChromiumBasedUnixTask {
    db_path,
    domains,
    browser_id,
  })
}

#[cfg(unix)]
pub struct ChromiumBasedDetailedUnixTask {
  db_path: String,
  domains: Option<Vec<String>>,
  browser_id: Option<String>,
}

#[cfg(unix)]
impl Task for ChromiumBasedDetailedUnixTask {
  type Output = Vec<DetailedCookie>;
  type JsValue = Vec<DetailedCookieObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    run_worker(|| {
      rookie_cookies::chromium_based_detailed_with_browser_id(
        self.browser_id.as_deref(),
        PathBuf::from(&self.db_path),
        self.domains.take(),
        false,
      )
      .map_err(classify_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    detailed_cookies_to_js(output)
  }
}

/// @deprecated Use `chromiumCookiesFromPathDetailed`. Earliest removal is 0.7.
#[napi(ts_return_type = "Promise<Array<DetailedCookieObject>>")]
#[cfg(unix)]
pub fn chromium_based_detailed(
  db_path: String,
  domains: Option<Vec<String>>,
  browser_id: Option<String>,
) -> AsyncTask<ChromiumBasedDetailedUnixTask> {
  AsyncTask::new(ChromiumBasedDetailedUnixTask {
    db_path,
    domains,
    browser_id,
  })
}

// Compiled only by the Node regression-test build. Keeping this out of normal
// artifacts avoids adding a deliberate panic trigger to the package API.
#[cfg(feature = "test-support")]
pub struct TestWorkerPanicTask;

#[cfg(feature = "test-support")]
impl Task for TestWorkerPanicTask {
  type Output = ();
  type JsValue = ();

  fn compute(&mut self) -> Result<Self::Output> {
    run_worker(|| panic!("forced Node worker panic"))
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output)
  }
}

#[cfg(feature = "test-support")]
#[napi(ts_return_type = "Promise<void>")]
pub fn test_worker_panic() -> AsyncTask<TestWorkerPanicTask> {
  AsyncTask::new(TestWorkerPanicTask)
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::collections::BTreeSet;

  #[test]
  fn worker_panics_become_napi_errors() {
    let error = run_worker::<()>(|| panic!("forced unit-test panic")).unwrap_err();

    assert_eq!(error.status, Status::GenericFailure);
    assert_eq!(
      error.reason,
      "cookie extraction worker panicked: forced unit-test panic"
    );
  }

  #[test]
  fn expiry_above_i64_max_is_omitted_instead_of_wrapping() {
    let cookies = cookies_to_js(vec![Cookie {
      domain: "example.test".to_string(),
      path: "/".to_string(),
      secure: false,
      expires: Some(i64::MAX as u64 + 1),
      name: "name".to_string(),
      value: "value".to_string(),
      http_only: false,
      same_site: 0,
    }])
    .expect("cookie conversion should succeed");

    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].expires, None);
  }

  /// Schema-parity check for the hand-written `#[napi(object)]` report DTOs.
  ///
  /// napi-rs's `#[napi(object)]` is a proc-macro over a real Rust struct, not
  /// a consumer of arbitrary generated code, so unlike the Python binding --
  /// which gets `dto.py` generated straight from
  /// `schema/report-dto.schema.json` -- these structs can't themselves be
  /// generated from the schema. Node's "generated from one schema" is
  /// satisfied here instead: each struct's Rust-level field names (which
  /// match `report_core.rs`'s snake_case names 1:1, before napi-rs's own
  /// camelCase rename) are hand-listed and diffed against the schema
  /// definition's `properties` keys, so drift between the struct and
  /// `report_core.rs` fails loudly instead of silently. This mirrors the
  /// deliberate, documented AbortSignal-style spec deviation from #238 (a
  /// custom `CancellationHandle` instead of a native `AbortSignal`): the gap
  /// is called out and covered, rather than hidden.
  #[test]
  fn napi_object_structs_match_report_core_schema() {
    let schema: serde_json::Value =
      serde_json::from_str(include_str!("../../../schema/report-dto.schema.json"))
        .expect("schema/report-dto.schema.json should be valid JSON");

    let cases: &[(&str, &[&str])] = &[
      (
        "Cookie",
        &[
          "domain",
          "path",
          "secure",
          "expires",
          "name",
          "value",
          "http_only",
          "same_site",
        ],
      ),
      (
        "BrowserDescriptor",
        &["id", "aliases", "display_name", "engine", "capabilities"],
      ),
      (
        "BrowserCapabilitiesDescriptor",
        &[
          "persistent_formats",
          "session_formats",
          "declared_decryption_tiers",
          "available_decryption_tiers",
        ],
      ),
      ("ProfileDescriptor", &["profile", "is_default", "sources"]),
      (
        "ProfileIdentity",
        &[
          "browser_id",
          "installation_id",
          "profile_id",
          "display_name",
          "path",
          "path_lossy",
        ],
      ),
      (
        "CookieSourceDescriptor",
        &["role", "format", "path", "path_lossy", "precedence"],
      ),
      (
        "CookieSourceIdentity",
        &["role", "format", "path", "path_lossy", "precedence"],
      ),
      (
        "ExtractionStats",
        &[
          "rows_seen",
          "cookies_emitted",
          "rows_skipped",
          "rows_rejected",
          "provider_failures",
          "acquisition_attempts",
          "counters_saturated",
        ],
      ),
      (
        "ReportStats",
        &[
          "registered_browsers",
          "browsers_detected",
          "browsers_not_detected",
          "installations_discovered",
          "profiles_discovered",
          "sources_succeeded",
          "sources_failed",
          "rows_seen",
          "cookies_emitted",
          "rows_skipped",
          "rows_rejected",
          "provider_failures",
          "counters_saturated",
        ],
      ),
      (
        "ExtractionIssue",
        &[
          "code",
          "stage",
          "severity",
          "cause",
          "provider",
          "tier",
          "retryability",
          "occurrences",
          "samples",
          "browser_id",
          "installation_id",
          "profile_id",
          "message",
        ],
      ),
      (
        "SourceExtraction",
        &[
          "source",
          "status",
          "selected",
          "acquisition_strategy",
          "cookies",
          "stats",
          "issues",
        ],
      ),
      (
        "ProfileExtraction",
        &["profile", "sources", "stats", "issues"],
      ),
      (
        "ExtractionReport",
        &[
          "schema_version",
          "status",
          "termination",
          "summary",
          "profiles",
          "issues",
        ],
      ),
    ];

    for (type_name, expected_fields) in cases {
      let expected: BTreeSet<&str> = expected_fields.iter().copied().collect();
      let properties = schema["definitions"][type_name]["properties"]
        .as_object()
        .unwrap_or_else(|| panic!("schema definitions.{type_name}.properties should exist"));
      let actual: BTreeSet<&str> = properties.keys().map(String::as_str).collect();

      assert_eq!(
        expected, actual,
        "{type_name}: napi(object) struct fields vs schema properties diverged"
      );
    }
  }
}
