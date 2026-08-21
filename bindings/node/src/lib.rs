#![allow(deprecated)]

#[macro_use]
extern crate napi_derive;

use napi::{bindgen_prelude::AsyncTask, bindgen_prelude::Either, Env, Result, Status, Task};
// Aliased: this module's own `extract_from_path` is the `extractFromPath`
// napi export sharing the core function's name (Key Decision 15 -- bindings
// share names with Rust), so the core function needs a different Rust-side
// identifier to import alongside it.
use rookie_cookies::direct_path::{
  extract_from_path as core_extract_from_path, ChromiumCredentialSource, PathExtractRequest,
};
use rookie_cookies::enums::{Cookie, DetailedCookie};
use rookie_cookies::report::{
  BrowserCapabilitiesDescriptor, BrowserDescriptor, CookieSourceDescriptor, CookieSourceIdentity,
  ExtractionIssue, ExtractionReport, ExtractionStats, ProfileDescriptor, ProfileExtraction,
  ProfileIdentity, ReportStats, SourceExtraction,
};
use rookie_cookies::{
  AppBoundPolicy, CancellationHandle, ExecutionControl, ExtractRequest, FromPathRequest,
  LoadReportRequest, MethodClass, MozillaProfile, ProfileSelection, ReadRequest, ReadResult,
  ReportRequest, ReportScope, RequestError, ResourceKind, SendContext,
};
use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const STRUCTURED_ERROR_PREFIX: &str = "__ROOKIE_ERROR_V1__";

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BindingErrorDetails {
  message: String,
  kind: &'static str,
  rookie_code: Option<&'static str>,
  stop_reason: Option<&'static str>,
  profile_ids: Vec<String>,
  source_kind: Option<String>,
  target_os: Option<String>,
  path_redacted: bool,
  /// The `SendContext` selectors `RequestError::IncompleteSendContext` says
  /// are missing. Empty for every other error.
  required: Vec<String>,
}

fn stop_reason_name(reason: rookie_cookies::StopReason) -> &'static str {
  match reason {
    rookie_cookies::StopReason::TimedOut => "timed_out",
    rookie_cookies::StopReason::Cancelled => "cancelled",
    rookie_cookies::StopReason::ResourceExhausted => "resource_exhausted",
    _ => "unknown",
  }
}

/// Single classification site for every `rookie_cookies::Error` this binding
/// surfaces. The deprecated anyhow-returning bridge functions route through
/// [`classify_anyhow_fault`], which converts via `Error::from` and then calls
/// [`classify_fault`], so this is the only place that reads variant fields
/// out of a classified error.
fn binding_error_details(error: &rookie_cookies::Error) -> BindingErrorDetails {
  let request = match error {
    rookie_cookies::Error::Request(request) => Some(request),
    _ => None,
  };
  let source = match error {
    rookie_cookies::Error::Source(source) => Some(source),
    _ => None,
  };

  BindingErrorDetails {
    message: error.to_string(),
    kind: match error {
      rookie_cookies::Error::Request(_) => "request",
      rookie_cookies::Error::Stopped(_) => "stopped",
      rookie_cookies::Error::Source(_) => "source",
      rookie_cookies::Error::Engine(_) => "engine",
      // `Error` is `#[non_exhaustive]`: a future core release can add a
      // variant this binding doesn't know how to name yet. Fall back to the
      // broadest bucket instead of failing to compile.
      _ => "engine",
    },
    rookie_code: Some(error.code()),
    stop_reason: error.stop_reason().map(stop_reason_name),
    profile_ids: request
      .map(rookie_cookies::RequestError::profile_ids)
      .unwrap_or_default()
      .to_vec(),
    source_kind: source
      .and_then(rookie_cookies::direct_path::DirectPathError::source_kind)
      .map(|source| source.to_string()),
    target_os: source
      .and_then(rookie_cookies::direct_path::DirectPathError::target_os)
      .map(str::to_owned),
    path_redacted: source
      .and_then(rookie_cookies::direct_path::DirectPathError::path)
      .is_some(),
    required: match request {
      Some(RequestError::IncompleteSendContext { required, .. }) => required.clone(),
      _ => Vec::new(),
    },
  }
}

/// Maps a classified error to the N-API status a binding consumer sees on
/// `error.code`. Only a cancelled stop gets its own status: a timeout or
/// resource-exhaustion stop is not caller input either, but napi has no
/// dedicated status for those, so they fall through to `GenericFailure`
/// alongside engine failures.
fn status_for_error(error: &rookie_cookies::Error) -> Status {
  match error {
    rookie_cookies::Error::Stopped(rookie_cookies::StopReason::Cancelled) => Status::Cancelled,
    rookie_cookies::Error::Request(_) | rookie_cookies::Error::Source(_) => Status::InvalidArg,
    _ => Status::GenericFailure,
  }
}

fn structured_error_with_env(env: Env, error: &rookie_cookies::Error) -> napi::Error {
  let status = status_for_error(error);
  let details = binding_error_details(error);
  let mut js_error = match env.create_error(napi::Error::new(status, &details.message)) {
    Ok(error) => error,
    Err(error) => return error,
  };
  let attributes = (|| -> Result<()> {
    js_error.set_named_property("kind", details.kind)?;
    js_error.set_named_property("code", status.as_ref())?;
    js_error.set_named_property("rookieCode", details.rookie_code)?;
    js_error.set_named_property("stopReason", details.stop_reason)?;
    js_error.set_named_property("profileIds", details.profile_ids)?;
    js_error.set_named_property("sourceKind", details.source_kind)?;
    js_error.set_named_property("targetOs", details.target_os)?;
    js_error.set_named_property("pathRedacted", details.path_redacted)?;
    js_error.set_named_property("required", details.required)?;
    Ok(())
  })();
  if let Err(error) = attributes {
    return error;
  }
  napi::Error::from(js_error.into_unknown())
}

/// Converts a typed `rookie_cookies::Error` into a `napi::Error` carrying the
/// `__ROOKIE_ERROR_V1__` JSON payload the JS loader's `decorateNativeError`
/// (in `index.js`) parses back into `kind`/`rookieCode`/`stopReason`/etc.
fn classify_fault(error: rookie_cookies::Error) -> napi::Error {
  let status = status_for_error(&error);
  let details = binding_error_details(&error);
  let payload = serde_json::to_string(&details).unwrap_or_else(|serialization| {
    format!(r#"{{"message":"error diagnostic serialization failed: {serialization}"}}"#)
  });
  napi::Error::new(status, format!("{STRUCTURED_ERROR_PREFIX}{payload}"))
}

/// Entry point for the deprecated v0.5.9 bridge functions, which still
/// return `anyhow::Result` (see `rookie_cookies::Error::from(anyhow::Error)`).
/// Converting first means [`classify_fault`] stays the only site that reads
/// a classified error's fields, instead of a second copy of that match.
fn classify_anyhow_fault(error: rookie_cookies::anyhow::Error) -> napi::Error {
  classify_fault(rookie_cookies::Error::from(error))
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

/// View input for `ReadResult.header`. A bare `url` string is sugar for
/// `{ url }`; see `header`'s doc comment for why the rest matters.
///
/// Plain `#[napi(object)]`, not `use_nullable`: this is caller-constructed
/// input (like `ReadOptions`), where every field but `url` should be
/// omittable, not merely nullable -- unlike `CookieContextObject`, which this
/// binding always populates in full and where `use_nullable` keeps every
/// field present-but-`null`.
#[napi(object)]
pub struct SendContextObject {
  pub url: String,
  pub top_level_site: Option<String>,
  /// `"navigation" | "subresource"`. Defaults to `"subresource"`, the
  /// conservative choice: only a `SameSite=Lax` cross-site send depends on it.
  pub resource: Option<String>,
  /// `"safe" | "unsafe"`. Defaults to `"safe"`, same reasoning as `resource`.
  pub method: Option<String>,
  pub user_context_id: Option<u32>,
  pub private_browsing_id: Option<u32>,
  pub now_epoch_seconds: Option<i64>,
}

/// Cross-platform options for explicit Chromium cookie databases.
#[napi(object)]
#[derive(Default)]
pub struct ChromiumPathOptions {
  pub domains: Option<Vec<String>>,
  pub browser_id: Option<String>,
  pub local_state_path: Option<String>,
  pub plaintext_only: Option<bool>,
  pub app_bound: Option<String>,
}

/// Options for the canonical `extractFromPath`: `domains`; the mutually
/// exclusive `plaintextOnly` / `browserId` / `localStatePath`; `timeoutMs`;
/// `appBound`. A superset of the deprecated `ChromiumPathOptions`, which took
/// `timeoutMs` as its own positional parameter instead of a field here.
#[napi(object)]
#[derive(Default)]
pub struct ExtractFromPathOptions {
  pub domains: Option<Vec<String>>,
  pub browser_id: Option<String>,
  pub local_state_path: Option<String>,
  pub plaintext_only: Option<bool>,
  pub timeout_ms: Option<u32>,
  pub app_bound: Option<String>,
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

/// Parses the JS-facing `AppBoundPolicy` string, rejecting an unrecognized
/// value before any I/O runs -- the same before-any-I/O contract
/// `chromium_credentials` already gives conflicting Chromium selectors.
/// `None` (the option omitted) takes the crate's own default, `InjectionOnly`.
fn parse_app_bound(policy: Option<&str>) -> Result<AppBoundPolicy> {
  match policy {
    None => Ok(AppBoundPolicy::default()),
    Some("disabled") => Ok(AppBoundPolicy::Disabled),
    Some("injection_only") => Ok(AppBoundPolicy::InjectionOnly),
    Some("allow_elevated_fallback") => Ok(AppBoundPolicy::AllowElevatedFallback),
    Some(other) => Err(napi::Error::new(
      Status::InvalidArg,
      format!("unknown appBound policy: {other}"),
    )),
  }
}

/// Bindings cannot express `ReportScope` in the type system the way Rust
/// does, so a `select`/`profile` combination Rust would rule out at compile
/// time (an all-profiles report naming one profile, or `select: "all"` on a
/// job that can only ever mean one profile) becomes this one structured
/// `RequestError` instead, raised before any I/O runs.
fn conflicting_profile_selection() -> napi::Error {
  classify_fault(rookie_cookies::Error::Request(
    RequestError::ConflictingProfileSelection,
  ))
}

/// Validates `select` for a job that can only ever answer with one profile
/// (`read`). Only `"legacy_first"` (or omitted) is representable;
/// `"all"` -- which only report jobs can express -- and any other value
/// reject before any I/O runs.
fn validate_single_profile_select(select: Option<&str>) -> Result<()> {
  match select {
    None | Some("legacy_first") => Ok(()),
    Some(_) => Err(conflicting_profile_selection()),
  }
}

/// Validates a report job's `select`/`profile` combination. Naming a
/// `profile` already narrows the report to it regardless of `select`, so the
/// only real conflict is `select: "all"` paired with an explicit `profile`
/// -- asking for one profile and every profile at once, which `ReportScope`
/// cannot represent.
fn validate_report_select(select: Option<&str>, has_profile: bool) -> Result<()> {
  match select {
    None | Some("legacy_first") | Some("all") => {}
    Some(_) => return Err(conflicting_profile_selection()),
  }
  if has_profile && select == Some("all") {
    return Err(conflicting_profile_selection());
  }
  Ok(())
}

fn parse_resource_kind(kind: Option<&str>) -> Result<ResourceKind> {
  match kind {
    None => Ok(ResourceKind::default()),
    Some("navigation") => Ok(ResourceKind::Navigation),
    Some("subresource") => Ok(ResourceKind::Subresource),
    Some(other) => Err(napi::Error::new(
      Status::InvalidArg,
      format!("unknown resource kind: {other}"),
    )),
  }
}

fn parse_method_class(class: Option<&str>) -> Result<MethodClass> {
  match class {
    None => Ok(MethodClass::default()),
    Some("safe") => Ok(MethodClass::Safe),
    Some("unsafe") => Ok(MethodClass::Unsafe),
    Some(other) => Err(napi::Error::new(
      Status::InvalidArg,
      format!("unknown method class: {other}"),
    )),
  }
}

/// Converts a caller-supplied `nowEpochSeconds` into a `SystemTime`. `None`
/// on overflow (a caller-chosen second count so large `UNIX_EPOCH` can't
/// represent it) leaves `SendContext::now` unset, which falls back to the
/// real clock at header-build time -- this is a diagnostic override caller
/// input, not a value this crate depends on for correctness, so a garbage
/// magnitude is silently ignored rather than added as a new failure mode.
fn system_time_from_epoch_seconds(seconds: i64) -> Option<SystemTime> {
  if seconds >= 0 {
    UNIX_EPOCH.checked_add(Duration::from_secs(seconds as u64))
  } else {
    UNIX_EPOCH.checked_sub(Duration::from_secs(seconds.unsigned_abs()))
  }
}

fn send_context_from_object(object: SendContextObject) -> Result<SendContext> {
  let mut context = SendContext::url(object.url)
    .resource(parse_resource_kind(object.resource.as_deref())?)
    .method(parse_method_class(object.method.as_deref())?);
  if let Some(site) = object.top_level_site {
    context = context.top_level_site(site);
  }
  if let Some(id) = object.user_context_id {
    context = context.user_context_id(id);
  }
  if let Some(id) = object.private_browsing_id {
    context = context.private_browsing_id(id);
  }
  if let Some(seconds) = object.now_epoch_seconds {
    if let Some(now) = system_time_from_epoch_seconds(seconds) {
      context = context.now(now);
    }
  }
  Ok(context)
}

fn chromium_credentials(
  browser_id: Option<&str>,
  local_state_path: Option<&str>,
  plaintext_only: bool,
  option_names: &'static str,
) -> Result<Option<ChromiumCredentialSource>> {
  let selector_count = usize::from(browser_id.is_some())
    + usize::from(local_state_path.is_some())
    + usize::from(plaintext_only);
  if selector_count > 1 {
    return Err(napi::Error::new(Status::InvalidArg, option_names));
  }

  Ok(if let Some(browser_id) = browser_id {
    Some(ChromiumCredentialSource::BrowserId(browser_id.to_owned()))
  } else if let Some(local_state_path) = local_state_path {
    Some(ChromiumCredentialSource::LocalStateFile(PathBuf::from(
      local_state_path,
    )))
  } else if plaintext_only {
    Some(ChromiumCredentialSource::PlaintextOnly)
  } else {
    None
  })
}

/// Builds the flat-list `PathExtractRequest` for `credentials`, choosing
/// whichever constructor actually exists on this platform.
/// `PathExtractRequest::unix_identity` / `::windows_local_state` are
/// compile-time gated to their platform -- there is no portable constructor
/// for a `BrowserId`/`LocalStateFile` selector the way the deleted
/// `ChromiumPathRequest` had, by design (a request that cannot succeed on the
/// target it was built for cannot be built at all). A selector for the wrong
/// platform is therefore a plain pre-I/O `InvalidArg` here, the same as
/// `chromium_credentials`'s mutual-exclusion check, rather than a classified
/// `DirectPathError` this binding has no way to trigger from the new API.
fn chromium_path_extract_request(
  path: String,
  credentials: Option<ChromiumCredentialSource>,
) -> Result<PathExtractRequest> {
  match credentials {
    None => Ok(PathExtractRequest::sniff(path)),
    Some(ChromiumCredentialSource::PlaintextOnly) => Ok(PathExtractRequest::plaintext(path)),
    Some(ChromiumCredentialSource::BrowserId(browser_id)) => {
      #[cfg(unix)]
      {
        Ok(PathExtractRequest::unix_identity(path, browser_id))
      }
      #[cfg(not(unix))]
      {
        let _ = (path, browser_id);
        Err(napi::Error::new(
          Status::InvalidArg,
          "Chromium path option browserId is only supported on Linux and macOS",
        ))
      }
    }
    Some(ChromiumCredentialSource::LocalStateFile(local_state_path)) => {
      #[cfg(windows)]
      {
        Ok(PathExtractRequest::windows_local_state(
          path,
          local_state_path,
        ))
      }
      #[cfg(not(windows))]
      {
        let _ = (path, local_state_path);
        Err(napi::Error::new(
          Status::InvalidArg,
          "Chromium path option localStatePath is only supported on Windows",
        ))
      }
    }
    // `ChromiumCredentialSource` is `#[non_exhaustive]`.
    Some(_) => Err(napi::Error::new(
      Status::InvalidArg,
      "unrecognized Chromium credential source",
    )),
  }
}

pub struct ExtractFromPathTask {
  request: PathExtractRequest,
}

impl Task for ExtractFromPathTask {
  type Output = Vec<Cookie>;
  type JsValue = Vec<CookieObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    run_worker(|| core_extract_from_path(self.request.clone()).map_err(classify_fault))
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    cookies_to_js(output)
  }
}

/// Extracts cookies from one explicit cookie file as a flat, domain-filtered
/// list. The canonical flat path-extract job (Rust `extract_from_path`,
/// Python `extract_from_path`); `cookiesFromPath` / `chromiumCookiesFromPath`
/// are deprecated aliases onto this.
///
/// Sniffs the source from its signature and schema with no credentials.
/// Portable: on Unix a Chromium database found this way is plaintext-capable
/// only (this used to probe every registered browser identity in turn); on
/// Windows a plaintext Chromium database now succeeds instead of always
/// rejecting with `missing_local_state_file`. An encrypted Chromium row
/// without an explicit credential selector is `missing_chromium_credentials`.
/// `options.appBound` defaults to `"injection_only"`, same as `read`.
#[napi(ts_return_type = "Promise<Array<CookieObject>>")]
pub fn extract_from_path(
  path: String,
  options: Option<ExtractFromPathOptions>,
  cancellation: Option<&JsCancellationHandle>,
) -> Result<AsyncTask<ExtractFromPathTask>> {
  let options = options.unwrap_or_default();
  let credentials = chromium_credentials(
    options.browser_id.as_deref(),
    options.local_state_path.as_deref(),
    options.plaintext_only.unwrap_or(false),
    "extractFromPath options browserId, localStatePath, and plaintextOnly are mutually exclusive",
  )?;
  let mut request = chromium_path_extract_request(path, credentials)?
    .domains(options.domains)
    .app_bound(parse_app_bound(options.app_bound.as_deref())?);
  if let Some(ms) = options.timeout_ms {
    request = request.timeout(Duration::from_millis(u64::from(ms)));
  }
  if let Some(handle) = cancellation {
    request = request.cancellation(handle.0.clone());
  }
  Ok(AsyncTask::new(ExtractFromPathTask { request }))
}

/// @deprecated Use `extractFromPath`. Earliest removal is 0.7.
#[napi(ts_return_type = "Promise<Array<CookieObject>>")]
pub fn cookies_from_path(
  path: String,
  domains: Option<Vec<String>>,
  timeout_ms: Option<u32>,
  cancellation: Option<&JsCancellationHandle>,
) -> Result<AsyncTask<ExtractFromPathTask>> {
  extract_from_path(
    path,
    Some(ExtractFromPathOptions {
      domains,
      timeout_ms,
      ..Default::default()
    }),
    cancellation,
  )
}

/// @deprecated Use `extractFromPath`. Earliest removal is 0.7.
#[napi(ts_return_type = "Promise<Array<CookieObject>>")]
pub fn chromium_cookies_from_path(
  path: String,
  options: Option<ChromiumPathOptions>,
  timeout_ms: Option<u32>,
  cancellation: Option<&JsCancellationHandle>,
) -> Result<AsyncTask<ExtractFromPathTask>> {
  let options = options.unwrap_or_default();
  extract_from_path(
    path,
    Some(ExtractFromPathOptions {
      domains: options.domains,
      browser_id: options.browser_id,
      local_state_path: options.local_state_path,
      plaintext_only: options.plaintext_only,
      timeout_ms,
      app_bound: options.app_bound,
    }),
    cancellation,
  )
}

pub struct ChromiumCookiesFromPathDetailedTask {
  request: FromPathRequest,
}

impl Task for ChromiumCookiesFromPathDetailedTask {
  type Output = Vec<DetailedCookie>;
  type JsValue = Vec<DetailedCookieObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    // Detailed (isolation-carrying) path extraction has no flat-list core
    // function of its own -- per `direct_path::extract_from_path`'s own doc
    // comment, it comes from `from_path(..).detailed_cookies()`, the same
    // seam the browser-discovery axis uses. `FromPathRequest` is portable
    // (unlike `PathExtractRequest`'s platform-gated constructors), so this
    // needs no `#[cfg(..)]` dispatch.
    run_worker(|| {
      rookie_cookies::from_path(self.request.clone())
        .map(ReadResult::into_detailed_cookies)
        .map_err(classify_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    detailed_cookies_to_js(output)
  }
}

/// @deprecated Use `fromPath(...).detailedCookies`. Earliest removal is 0.7.
#[napi(ts_return_type = "Promise<Array<DetailedCookieObject>>")]
pub fn chromium_cookies_from_path_detailed(
  path: String,
  options: Option<ChromiumPathOptions>,
  timeout_ms: Option<u32>,
  cancellation: Option<&JsCancellationHandle>,
) -> Result<AsyncTask<ChromiumCookiesFromPathDetailedTask>> {
  let options = options.unwrap_or_default();
  // `FromPathRequest` (unlike the deleted `ChromiumPathRequest`) has no
  // domain filter -- `from_path`, like `read`, never URL/domain-slices its
  // snapshot. Rather than silently stop honoring a caller's `domains`, reject
  // before any I/O runs.
  if options
    .domains
    .as_ref()
    .is_some_and(|domains| !domains.is_empty())
  {
    return Err(napi::Error::new(
      Status::InvalidArg,
      "chromiumCookiesFromPathDetailed no longer supports domain filtering; \
       filter fromPath(...).detailedCookies yourself instead",
    ));
  }
  let credentials = chromium_credentials(
    options.browser_id.as_deref(),
    options.local_state_path.as_deref(),
    options.plaintext_only.unwrap_or(false),
    "Chromium path options browserId, localStatePath, and plaintextOnly are mutually exclusive",
  )?;
  let mut request =
    FromPathRequest::new(path).app_bound(parse_app_bound(options.app_bound.as_deref())?);
  if let Some(credentials) = credentials {
    request = request.chromium_credentials(credentials);
  }
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
        .map_err(classify_anyhow_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    cookies_to_js(output)
  }
}

/// @deprecated Use `extractFromPath`. Earliest removal is 0.7.
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
        run_worker(|| $core_fn(self.domains.take()).map_err(classify_anyhow_fault))
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

// `load` scans every registered browser and has no `ExtractRequest::browser`
// equivalent to route a timeout/cancellation handle through, so it keeps the
// plain form.
async_browser_fn!(load, LoadTask, rookie_cookies::load);

// ---------------------------------------------------------------------------
// Macro for single-browser async functions that support `timeoutMs` and a
// `JsCancellationHandle`, routed through `extract(ExtractRequest::browser(id))`
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
          let mut request = ExtractRequest::browser($browser_id).domains(self.domains.take());
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
    run_worker(|| rookie_cookies::firefox_profiles().map_err(classify_anyhow_fault))
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
      rookie_cookies::firefox_profile(&self.profile, self.domains.take())
        .map_err(classify_anyhow_fault)
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
        .map_err(classify_anyhow_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    cookies_to_js(output)
  }
}

/// @deprecated Use `extractFromPath`. Earliest removal is 0.7.
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
        .map_err(classify_anyhow_fault)
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
/// Takes no execution control: this is a static catalog lookup with no disk
/// I/O, so there is nothing for a timeout, cancellation, or `appBound` to do.
#[napi(ts_return_type = "Promise<Array<BrowserDescriptorObject>>")]
pub fn supported_browsers() -> AsyncTask<SupportedBrowsersTask> {
  AsyncTask::new(SupportedBrowsersTask)
}

pub struct BrowserProfilesTask {
  browser_id: String,
  timeout_ms: Option<u32>,
}

impl Task for BrowserProfilesTask {
  type Output = Vec<ProfileDescriptor>;
  type JsValue = Vec<ProfileDescriptorObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    let mut control = ExecutionControl::default();
    if let Some(ms) = self.timeout_ms {
      control = control.timeout(Duration::from_millis(u64::from(ms)));
    }
    run_worker(|| {
      rookie_cookies::browser_profiles_with(&self.browser_id, control).map_err(classify_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output.into_iter().map(profile_descriptor_to_js).collect())
  }
}

/// Lists the discovered profiles of one registered browser.
///
/// Rejects on an unknown `browserId`, or when every detected installation root
/// failed enumeration. A known browser with nothing installed resolves to an
/// empty array. No `appBound`: listing does no App-Bound work.
#[napi(ts_return_type = "Promise<Array<ProfileDescriptorObject>>")]
pub fn browser_profiles(
  browser_id: String,
  options: Option<ProfilesOptions>,
) -> AsyncTask<BrowserProfilesTask> {
  AsyncTask::new(BrowserProfilesTask {
    browser_id,
    timeout_ms: options.and_then(|options| options.timeout_ms),
  })
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
      rookie_cookies::chrome_profile(&self.profile, self.domains.take())
        .map_err(classify_anyhow_fault)
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
  options: BrowserReportOptions,
  app_bound: AppBoundPolicy,
}

impl Task for BrowserReportTask {
  type Output = ExtractionReport;
  type JsValue = ExtractionReportObject;

  fn compute(&mut self) -> Result<Self::Output> {
    let options = &self.options;
    let app_bound = self.app_bound;
    run_worker(|| {
      // Routed through `ReportRequest` + `extract_report` (not the core's
      // `browser_report`, which has no execution-control twin) so timeout
      // and App-Bound policy reach this job -- the same seam `report`/
      // `extractReport` already uses. `ReportRequest::browser` defaults to
      // every profile, exactly what a missing `profileId` has always meant.
      let mut request = ReportRequest::browser(&options.browser_id)
        .domains(options.domains.clone())
        .app_bound(app_bound);
      if let Some(profile) = options.profile_id.as_deref() {
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

/// Extracts cookies from one browser as a grouped report.
///
/// Only a bad request rejects: an unknown `browserId`, or a `profileId` this
/// browser did not yield. Extraction problems resolve as a report whose
/// `status` and `issues` describe them. `options.appBound` defaults to
/// `"injection_only"`, same as `read`.
#[napi(ts_return_type = "Promise<ExtractionReportObject>")]
pub fn browser_report(options: BrowserReportOptions) -> Result<AsyncTask<BrowserReportTask>> {
  let app_bound = parse_app_bound(options.app_bound.as_deref())?;
  Ok(AsyncTask::new(BrowserReportTask { options, app_bound }))
}

pub struct LoadReportTask {
  domains: Option<Vec<String>>,
  timeout_ms: Option<u32>,
  app_bound: AppBoundPolicy,
}

impl Task for LoadReportTask {
  type Output = ExtractionReport;
  type JsValue = ExtractionReportObject;

  fn compute(&mut self) -> Result<Self::Output> {
    let mut request = LoadReportRequest::default()
      .domains(self.domains.take())
      .app_bound(self.app_bound);
    if let Some(ms) = self.timeout_ms {
      request = request.timeout(Duration::from_millis(u64::from(ms)));
    }
    run_worker(|| rookie_cookies::load_report_with(request).map_err(classify_fault))
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
/// `options.appBound` defaults to `"injection_only"`, same as `read`.
#[napi(ts_return_type = "Promise<ExtractionReportObject>")]
pub fn load_report(options: Option<LoadReportOptions>) -> Result<AsyncTask<LoadReportTask>> {
  let options = options.unwrap_or_default();
  let app_bound = parse_app_bound(options.app_bound.as_deref())?;
  Ok(AsyncTask::new(LoadReportTask {
    domains: options.domains,
    timeout_ms: options.timeout_ms,
    app_bound,
  }))
}

#[napi(object)]
pub struct ReadOptions {
  pub browser: String,
  pub profile: Option<String>,
  pub include_expired: Option<bool>,
  /// Also includes the browser's declared session store (Gecko only; a
  /// no-op elsewhere). Defaults to `false` -- **unlike 0.6-beta**, naming a
  /// `profile` alone no longer imports session cookies. Omitting this on a
  /// migrated 0.6-beta caller fails silently: a smaller snapshot, no error.
  pub include_session: Option<bool>,
  pub timeout_ms: Option<u32>,
  /// `"disabled" | "injection_only" | "allow_elevated_fallback"`. Omitted
  /// means `"injection_only"`, which recovers Chrome v20 App-Bound keys
  /// without elevation. Pass `"disabled"` to skip v20 rows instead.
  pub app_bound: Option<String>,
  /// Only `"legacy_first"` (the default) is representable here: a snapshot
  /// or flat extract returns one answer, so there is no "every profile" for
  /// `select` to name. Passing `"all"` rejects with
  /// `conflicting_profile_selection` before any I/O; use `report`/
  /// `browserReport` for every profile.
  pub select: Option<String>,
}

#[napi(object)]
pub struct ReportOptions {
  pub browser: String,
  pub profile: Option<String>,
  pub domains: Option<Vec<String>>,
  pub timeout_ms: Option<u32>,
  pub app_bound: Option<String>,
  /// `"legacy_first" | "all"`. Defaults to `"all"`: naming a `profile`
  /// already narrows to it regardless of `select`, but `select: "all"`
  /// together with `profile` is a contradiction and rejects with
  /// `conflicting_profile_selection` before any I/O.
  pub select: Option<String>,
}

#[napi(object)]
pub struct FromPathOptions {
  pub path: String,
  pub include_expired: Option<bool>,
  pub timeout_ms: Option<u32>,
  pub browser_id: Option<String>,
  /// Renamed from `keyPath` in 0.6.0 (prerelease-only, so no alias kept).
  pub local_state_path: Option<String>,
  pub plaintext_only: Option<bool>,
  pub app_bound: Option<String>,
}

/// Options for `loadReport`. Every field is optional so the whole options
/// object itself can be omitted, matching `loadReport()`'s no-argument form
/// before this PR added execution control.
#[napi(object)]
#[derive(Default)]
pub struct LoadReportOptions {
  pub domains: Option<Vec<String>>,
  pub timeout_ms: Option<u32>,
  pub app_bound: Option<String>,
}

#[napi(object)]
pub struct BrowserReportOptions {
  pub browser_id: String,
  pub profile_id: Option<String>,
  pub domains: Option<Vec<String>>,
  pub timeout_ms: Option<u32>,
  pub app_bound: Option<String>,
}

/// Options for `profiles` / `browserProfiles`. No `appBound`: listing does no
/// App-Bound work.
#[napi(object)]
#[derive(Default)]
pub struct ProfilesOptions {
  pub timeout_ms: Option<u32>,
}

#[napi(object)]
pub struct ReadWarningObject {
  pub code: String,
  /// IEEE-754; saturates at `Number.MAX_SAFE_INTEGER` rather than losing
  /// precision on a Rust `u64` past that point.
  pub count: f64,
  pub counters_saturated: bool,
  pub message: String,
}

/// JavaScript's largest exactly representable integer (`2^53 - 1`). Matches
/// `ExtractionStatsObject.countersSaturated`'s saturation point.
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

fn warning_count(count: u64) -> (f64, bool) {
  if count > MAX_SAFE_INTEGER {
    (MAX_SAFE_INTEGER as f64, true)
  } else {
    (count as f64, false)
  }
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

  /// Isolation-aware projection: the eight `Cookie` fields plus a `context`
  /// object carrying CHIPS partition and Firefox container identity. Use this
  /// (not `cookies`) to inventory partitions/containers -- `cookies` discards
  /// that context by design.
  #[napi(getter, js_name = "detailedCookies")]
  pub fn detailed_cookies(&self) -> Result<Vec<DetailedCookieObject>> {
    detailed_cookies_to_js(self.inner.detailed_cookies().to_vec())
  }

  #[napi(getter)]
  pub fn warnings(&self) -> Vec<ReadWarningObject> {
    self
      .inner
      .warnings()
      .iter()
      .map(|warning| {
        let (count, counters_saturated) = warning_count(warning.count());
        ReadWarningObject {
          code: warning.code().to_owned(),
          count,
          counters_saturated,
          message: warning.to_string(),
        }
      })
      .collect()
  }

  #[napi(getter, js_name = "browserId")]
  pub fn browser_id(&self) -> Option<String> {
    self.inner.browser_id().map(str::to_owned)
  }

  #[napi(getter, js_name = "profileId")]
  pub fn profile_id(&self) -> Option<String> {
    self.inner.profile_id().map(str::to_owned)
  }

  /// Derives a legacy `Cookie` request-header value for `context`. A bare
  /// string is sugar for `{ url: context }`: the conservative
  /// (`Subresource`/`Safe`) defaults, no top-level site, no container/
  /// partition selector.
  ///
  /// A snapshot holding a CHIPS-partitioned or Firefox-container cookie
  /// rejects with `incomplete_send_context` (its `required` selector names on
  /// the error object) rather than silently merging isolated cookies into one
  /// answer -- pass `topLevelSite` / `userContextId` / `privateBrowsingId`
  /// to disambiguate.
  #[napi]
  pub fn header(&self, env: Env, context: Either<String, SendContextObject>) -> Result<String> {
    let context = match context {
      Either::A(url) => SendContext::url(url),
      Either::B(object) => send_context_from_object(object)?,
    };
    self
      .inner
      .header(&context)
      .map_err(|error| structured_error_with_env(env, &error))
  }
}

pub struct ReadTask {
  options: ReadOptions,
  app_bound: AppBoundPolicy,
  cancellation: Option<CancellationHandle>,
}

impl Task for ReadTask {
  type Output = ReadResult;
  type JsValue = JsReadResult;

  fn compute(&mut self) -> Result<Self::Output> {
    let options = &self.options;
    let app_bound = self.app_bound;
    run_worker(|| {
      let mut request = ReadRequest::browser(&options.browser).app_bound(app_bound);
      if let Some(profile) = options.profile.as_deref() {
        request = request.profile(profile);
      }
      if options.include_expired == Some(true) {
        request = request.include_expired(true);
      }
      if options.include_session == Some(true) {
        request = request.include_session();
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
///
/// `options.appBound` defaults to `"injection_only"`: Chrome has written
/// App-Bound (v20) cookies on Windows since Chrome 127, so refusing to
/// recover them would return an empty list for the common case. Injection is
/// unprivileged but spawns a browser process, which endpoint security can
/// flag -- pass `"disabled"` to skip v20 rows instead. Elevated SYSTEM
/// impersonation stays opt-in via `"allow_elevated_fallback"`.
#[napi(js_name = "read", ts_return_type = "Promise<ReadResult>")]
pub fn read(
  options: ReadOptions,
  cancellation: Option<&JsCancellationHandle>,
) -> Result<AsyncTask<ReadTask>> {
  validate_single_profile_select(options.select.as_deref())?;
  let app_bound = parse_app_bound(options.app_bound.as_deref())?;
  Ok(AsyncTask::new(ReadTask {
    options,
    app_bound,
    cancellation: cancellation.map(|handle| handle.0.clone()),
  }))
}

pub struct ProfilesTask {
  browser_id: String,
  timeout_ms: Option<u32>,
}

impl Task for ProfilesTask {
  type Output = Vec<ProfileDescriptor>;
  type JsValue = Vec<ProfileDescriptorObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    let mut control = ExecutionControl::default();
    if let Some(ms) = self.timeout_ms {
      control = control.timeout(Duration::from_millis(u64::from(ms)));
    }
    run_worker(|| rookie_cookies::profiles_with(&self.browser_id, control).map_err(classify_fault))
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output.into_iter().map(profile_descriptor_to_js).collect())
  }
}

/// Alias of `browserProfiles`. No decrypt, no `appBound`.
#[napi(
  js_name = "profiles",
  ts_return_type = "Promise<Array<ProfileDescriptorObject>>"
)]
pub fn profiles(browser_id: String, options: Option<ProfilesOptions>) -> AsyncTask<ProfilesTask> {
  AsyncTask::new(ProfilesTask {
    browser_id,
    timeout_ms: options.and_then(|options| options.timeout_ms),
  })
}

pub struct JobReportTask {
  options: ReportOptions,
  app_bound: AppBoundPolicy,
}

impl Task for JobReportTask {
  type Output = ExtractionReport;
  type JsValue = ExtractionReportObject;

  fn compute(&mut self) -> Result<Self::Output> {
    let options = &self.options;
    let app_bound = self.app_bound;
    run_worker(|| {
      let mut request = ReportRequest::browser(&options.browser)
        .domains(options.domains.clone())
        .app_bound(app_bound);
      match options.profile.as_deref() {
        Some(profile) => request = request.profile(profile),
        // No profile named: `select: "legacy_first"` narrows to one profile
        // instead of the `ReportRequest::browser` default of every profile.
        // `validate_report_select` already rejected every other `select`
        // value, so nothing else reaches this arm.
        None if options.select.as_deref() == Some("legacy_first") => {
          request = request.scope(ReportScope::from(ProfileSelection::LegacyFirst));
        }
        None => {}
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
///
/// `options.appBound` defaults to `"injection_only"`, same as `read`.
#[napi(js_name = "report", ts_return_type = "Promise<ExtractionReportObject>")]
pub fn report(options: ReportOptions) -> Result<AsyncTask<JobReportTask>> {
  validate_report_select(options.select.as_deref(), options.profile.is_some())?;
  let app_bound = parse_app_bound(options.app_bound.as_deref())?;
  Ok(AsyncTask::new(JobReportTask { options, app_bound }))
}

pub struct FromPathTask {
  options: FromPathOptions,
  app_bound: AppBoundPolicy,
  credentials: Option<ChromiumCredentialSource>,
  cancellation: Option<CancellationHandle>,
}

impl Task for FromPathTask {
  type Output = ReadResult;
  type JsValue = JsReadResult;

  fn compute(&mut self) -> Result<Self::Output> {
    let options = &self.options;
    let app_bound = self.app_bound;
    run_worker(|| {
      let mut request = FromPathRequest::new(&options.path).app_bound(app_bound);
      if options.include_expired == Some(true) {
        request = request.include_expired(true);
      }
      if let Some(ms) = options.timeout_ms {
        request = request.timeout(Duration::from_millis(u64::from(ms)));
      }
      if let Some(handle) = self.cancellation.take() {
        request = request.cancellation(handle);
      }
      if let Some(credentials) = self.credentials.take() {
        request = request.chromium_credentials(credentials);
      }
      rookie_cookies::from_path(request).map_err(classify_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(JsReadResult { inner: output })
  }
}

/// Read cookies from an explicit cookie database path.
///
/// `options.appBound` defaults to `"injection_only"`, same as `read`.
#[napi(js_name = "fromPath", ts_return_type = "Promise<ReadResult>")]
pub fn from_path(
  options: FromPathOptions,
  cancellation: Option<&JsCancellationHandle>,
) -> Result<AsyncTask<FromPathTask>> {
  let credentials = chromium_credentials(
    options.browser_id.as_deref(),
    options.local_state_path.as_deref(),
    options.plaintext_only.unwrap_or(false),
    "fromPath options browserId, localStatePath, and plaintextOnly are mutually exclusive",
  )?;
  let app_bound = parse_app_bound(options.app_bound.as_deref())?;
  Ok(AsyncTask::new(FromPathTask {
    options,
    app_bound,
    credentials,
    cancellation: cancellation.map(|handle| handle.0.clone()),
  }))
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
      .map_err(classify_anyhow_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    cookies_to_js(output)
  }
}

/// @deprecated Use `extractFromPath`. Earliest removal is 0.7.
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
      .map_err(classify_anyhow_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    detailed_cookies_to_js(output)
  }
}

/// @deprecated Use `fromPath(...).detailedCookies`. Earliest removal is 0.7.
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
      .map_err(classify_anyhow_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    cookies_to_js(output)
  }
}

/// @deprecated Use `extractFromPath`. Earliest removal is 0.7.
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
      .map_err(classify_anyhow_fault)
    })
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    detailed_cookies_to_js(output)
  }
}

/// @deprecated Use `fromPath(...).detailedCookies`. Earliest removal is 0.7.
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
  fn source_inspection_failure_is_an_engine_generic_failure() {
    let error = rookie_cookies::Error::from(
      rookie_cookies::direct_path::DirectPathError::InvalidSource {
        path: PathBuf::from("/private/secret/profile/Cookies"),
        reason: rookie_cookies::direct_path::InvalidCookieSourceReason::SourceInspectionFailed,
      },
    );
    let details = binding_error_details(&error);

    assert!(matches!(error, rookie_cookies::Error::Engine(_)));
    assert_eq!(details.kind, "engine");
    assert_eq!(details.rookie_code, Some("source_inspection_failed"));
    assert_eq!(status_for_error(&error), Status::GenericFailure);
    assert!(!details.message.contains("/private/secret"));
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

  #[test]
  fn chromium_credential_selectors_reject_every_conflicting_shape() {
    for (browser_id, key_path, plaintext_only) in [
      (Some("chrome"), Some("Local State"), false),
      (Some("chrome"), None, true),
      (None, Some("Local State"), true),
      (Some("chrome"), Some("Local State"), true),
    ] {
      let error = chromium_credentials(
        browser_id,
        key_path,
        plaintext_only,
        "selectors are mutually exclusive",
      )
      .expect_err("conflicting selectors must fail before a task is scheduled");

      assert_eq!(error.status, Status::InvalidArg);
      assert_eq!(error.reason, "selectors are mutually exclusive");
    }
  }

  #[test]
  fn warning_counts_report_saturation_instead_of_looking_exact() {
    assert_eq!(warning_count(7), (7.0, false));
    assert_eq!(
      warning_count(MAX_SAFE_INTEGER),
      (MAX_SAFE_INTEGER as f64, false)
    );
    assert_eq!(
      warning_count(MAX_SAFE_INTEGER + 1),
      (MAX_SAFE_INTEGER as f64, true)
    );
    assert_eq!(warning_count(u64::MAX), (MAX_SAFE_INTEGER as f64, true));
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
