//! Generic registry and report bindings.
//!
//! Every DTO crosses into Python as a plain dictionary whose keys are the Rust
//! field names verbatim, and every open string identifier newtype as a plain
//! `str`, so a vocabulary value this build has never seen still arrives intact.

use crate::errors::request_error;
use crate::{to_dict, PyCancellationHandle};
use ::rookie_cookies as rookie_core;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use rookie_core::report::{
  BrowserDescriptor, CookieSourceDescriptor, CookieSourceIdentity, ExtractionIssue,
  ExtractionReport, ExtractionStats, ProfileDescriptor, ProfileExtraction, ProfileIdentity,
  ReportStats, SourceExtraction,
};

/// List every browser registered for the running OS
///
/// This is registration, not detection, and does no disk I/O -- unlike every
/// other function in this module, it takes no `timeout` / `cancellation` /
/// `app_bound`.
///
/// :return: A list of browser descriptor dictionaries
#[pyfunction]
pub fn supported_browsers(py: Python<'_>) -> PyResult<Vec<Py<PyAny>>> {
  py.detach(rookie_core::supported_browsers)
    .map_err(crate::errors::classify_error)?
    .into_iter()
    .map(|browser| browser_descriptor_dict(py, browser))
    .collect()
}

/// List the discovered profiles of one registered browser
///
/// Listing touches the filesystem but does no Windows App-Bound recovery, so
/// unlike `read` / `browser_report` / `load_report` this takes no
/// `app_bound` parameter.
///
/// :param browser_id: A canonical browser ID or alias from supported_browsers
/// :param timeout: Optional timeout in seconds
/// :param cancellation: Optional CancellationHandle
/// :return: A list of profile descriptor dictionaries
#[pyfunction]
#[pyo3(signature = (browser_id, *, timeout=None, cancellation=None))]
pub fn browser_profiles(
  py: Python<'_>,
  browser_id: String,
  timeout: Option<f64>,
  cancellation: Option<PyCancellationHandle>,
) -> PyResult<Vec<Py<PyAny>>> {
  let control = crate::execution_control_without_app_bound(timeout, cancellation)?;
  py.detach(|| rookie_core::browser_profiles_with(&browser_id, control))
    .map_err(crate::errors::classify_error)?
    .into_iter()
    .map(|profile| profile_descriptor_dict(py, profile))
    .collect()
}

/// List Google Chrome profiles with the last-used/active profile first
///
/// Activity hints are advisory. Missing or invalid hints retain the generic
/// default-first discovery order. Listing does no Windows App-Bound recovery,
/// so unlike `read` / `browser_report` / `load_report` this takes no
/// `app_bound` parameter.
///
/// :param timeout: Optional timeout in seconds
/// :param cancellation: Optional CancellationHandle
/// :return: A list of profile descriptor dictionaries
#[pyfunction]
#[pyo3(signature = (*, timeout=None, cancellation=None))]
pub fn chrome_profiles(
  py: Python<'_>,
  timeout: Option<f64>,
  cancellation: Option<PyCancellationHandle>,
) -> PyResult<Vec<Py<PyAny>>> {
  let control = crate::execution_control_without_app_bound(timeout, cancellation)?;
  py.detach(|| rookie_core::chrome_profiles_with(control))
    .map_err(crate::errors::classify_error)?
    .into_iter()
    .map(|profile| profile_descriptor_dict(py, profile))
    .collect()
}

/// Extract one selected Google Chrome profile as a grouped report
///
/// :param profile: Profile ID, display name, directory name, or a full path whose path_lossy flag is false
/// :param domains: Optional list of domains to extract only from them
/// :return: An extraction report dictionary retaining source provenance and issues
#[pyfunction]
#[pyo3(signature = (profile, domains=None))]
pub fn chrome_profile(
  py: Python<'_>,
  profile: String,
  domains: Option<Vec<String>>,
) -> PyResult<Py<PyAny>> {
  let report = py
    .detach(|| rookie_core::chrome_profile(&profile, domains))
    .map_err(crate::errors::classify_fault)?;
  report_dict(py, report)
}

/// Extract cookies from one browser as a grouped report
///
/// **Windows App-Bound (v20) recovery is opt-in** -- see `read`'s docstring
/// and CHANGELOG.md; the same default and the same values apply here.
///
/// :param browser_id: A canonical browser ID or alias from supported_browsers
/// :param profile_id: Optional profile_id from browser_profiles, restricting the report to it
/// :param domains: Optional list of domains to extract only from them
/// :param select: Profile selection strategy when `profile_id` is not given:
///     "all" (default) reports every installation and profile -- what
///     `browser_report(id, None, domains)` has always meant -- or
///     "legacy_first" narrows the report to the first legacy-eligible
///     profile, same as the named v0.5.9 helpers.
/// :param timeout: Optional timeout in seconds
/// :param cancellation: Optional CancellationHandle
/// :param app_bound: Windows App-Bound (v20) recovery policy: "disabled"
///     (default), "injection_only", or "allow_elevated_fallback". A no-op
///     off Windows.
/// :return: An extraction report dictionary
/// :raises RookieRequestError: `profile_id` was given together with an
///     explicit `select="all"` (`conflicting_profile_selection`) -- naming
///     one profile and asking for every profile contradict each other. A
///     bare `profile_id` (leaving `select` at its default) is not a
///     conflict: the profile simply wins, same as before `select` existed.
#[pyfunction]
#[pyo3(signature = (
  browser_id,
  profile_id=None,
  domains=None,
  *,
  select=None,
  timeout=None,
  cancellation=None,
  app_bound="disabled".to_string(),
))]
#[allow(clippy::too_many_arguments)]
pub fn browser_report(
  py: Python<'_>,
  browser_id: String,
  profile_id: Option<String>,
  domains: Option<Vec<String>>,
  select: Option<String>,
  timeout: Option<f64>,
  cancellation: Option<PyCancellationHandle>,
  app_bound: String,
) -> PyResult<Py<PyAny>> {
  // `select`'s *effective* default is "all", but the conflict check must not
  // fire just because a caller left it at that default while also passing
  // `profile_id` -- that describes every pre-`select` call site, and denying
  // it would be a hard regression, not a validation. So `select` stays
  // `Option<String>` with a `None` default here (unlike `read`'s `select`,
  // whose only valid value already coincides with its default and has no
  // such ambiguity): only an *explicit* `select="all"` is the documented
  // conflict with `profile_id`.
  // Validate the vocabulary before anything branches on `profile_id`. The
  // scope match below only runs when no profile was named, so a typo like
  // "legacy_frst" passed alongside a profile used to be dropped silently and
  // extraction started anyway -- the same value that is a request error on the
  // profile-less call shape.
  match select.as_deref() {
    None | Some("all") | Some("legacy_first") => {}
    Some(other) => {
      return Err(request_error(format!(
        "unknown select value {other:?}; expected \"legacy_first\" or \"all\""
      )))
    }
  }
  if profile_id.is_some() && select.as_deref() == Some("all") {
    return Err(crate::conflicting_profile_selection_error());
  }
  let control = crate::execution_control(timeout, cancellation, &app_bound)?;
  let mut request = rookie_core::ReportRequest::browser(browser_id).domains(domains);
  request = match profile_id {
    Some(profile_id) => request.profile(profile_id),
    // No named profile: `select` chooses between the two scopes a report can
    // widen to. `None`/"all" is `ReportRequest::browser`'s own default, so
    // it is a no-op here rather than an explicit `.scope(..)` call.
    None => match select.as_deref() {
      Some("legacy_first") => request.scope(rookie_core::ReportScope::One(
        rookie_core::ProfileSelection::LegacyFirst,
      )),
      // Validated above, so only absent/"all" reach here, and both mean
      // `ReportRequest::browser`'s own default scope.
      _ => request,
    },
  };
  request = request.execution(control);
  // Builds a `ReportRequest` and calls `extract_report` directly rather than
  // the free `browser_report` function: that convenience wrapper predates
  // `ExecutionControl` and has no way to carry one.
  let report = py
    .detach(|| rookie_core::extract_report(request))
    .map_err(crate::errors::classify_error)?;
  report_dict(py, report)
}

/// Extract cookies from every registered browser as one grouped report
///
/// **Windows App-Bound (v20) recovery is opt-in** -- see `read`'s docstring
/// and CHANGELOG.md; the same default and the same values apply here, for
/// every browser in the fan-out.
///
/// :param domains: Optional list of domains to extract only from them
/// :param timeout: Optional timeout in seconds, shared by the whole fan-out
/// :param cancellation: Optional CancellationHandle, shared by the whole fan-out
/// :param app_bound: Windows App-Bound (v20) recovery policy: "disabled"
///     (default), "injection_only", or "allow_elevated_fallback". A no-op
///     off Windows.
/// :return: An extraction report dictionary
#[pyfunction]
#[pyo3(signature = (
  domains=None,
  *,
  timeout=None,
  cancellation=None,
  app_bound="disabled".to_string(),
))]
pub fn load_report(
  py: Python<'_>,
  domains: Option<Vec<String>>,
  timeout: Option<f64>,
  cancellation: Option<PyCancellationHandle>,
  app_bound: String,
) -> PyResult<Py<PyAny>> {
  let control = crate::execution_control(timeout, cancellation, &app_bound)?;
  let request = rookie_core::LoadReportRequest::default()
    .domains(domains)
    .execution(control);
  let report = py
    .detach(|| rookie_core::load_report_with(request))
    .map_err(crate::errors::classify_error)?;
  report_dict(py, report)
}

fn identifiers<T: AsRef<str>>(values: &[T]) -> Vec<&str> {
  values.iter().map(AsRef::as_ref).collect()
}

fn browser_descriptor_dict(py: Python<'_>, browser: BrowserDescriptor) -> PyResult<Py<PyAny>> {
  let capabilities = PyDict::new(py);
  capabilities.set_item(
    "persistent_formats",
    identifiers(&browser.capabilities.persistent_formats),
  )?;
  capabilities.set_item(
    "session_formats",
    identifiers(&browser.capabilities.session_formats),
  )?;
  capabilities.set_item(
    "declared_decryption_tiers",
    identifiers(&browser.capabilities.declared_decryption_tiers),
  )?;
  capabilities.set_item(
    "available_decryption_tiers",
    identifiers(&browser.capabilities.available_decryption_tiers),
  )?;

  let dict = PyDict::new(py);
  dict.set_item("id", browser.id.as_str())?;
  dict.set_item("aliases", browser.aliases)?;
  dict.set_item("display_name", browser.display_name)?;
  dict.set_item("engine", browser.engine.as_str())?;
  dict.set_item("capabilities", capabilities)?;
  Ok(dict.into())
}

fn profile_descriptor_dict(py: Python<'_>, profile: ProfileDescriptor) -> PyResult<Py<PyAny>> {
  let sources = profile
    .sources
    .into_iter()
    .map(|source| source_descriptor_dict(py, source))
    .collect::<PyResult<Vec<_>>>()?;

  let dict = PyDict::new(py);
  dict.set_item("profile", profile_identity_dict(py, profile.profile)?)?;
  dict.set_item("is_default", profile.is_default)?;
  dict.set_item("sources", sources)?;
  Ok(dict.into())
}

fn profile_identity_dict(py: Python<'_>, profile: ProfileIdentity) -> PyResult<Py<PyAny>> {
  let dict = PyDict::new(py);
  dict.set_item("browser_id", profile.browser_id.as_str())?;
  dict.set_item("installation_id", profile.installation_id.as_str())?;
  dict.set_item("profile_id", profile.profile_id.as_str())?;
  dict.set_item("display_name", profile.display_name)?;
  dict.set_item("path", profile.path)?;
  dict.set_item("path_lossy", profile.path_lossy)?;
  Ok(dict.into())
}

fn source_descriptor_dict(py: Python<'_>, source: CookieSourceDescriptor) -> PyResult<Py<PyAny>> {
  let dict = PyDict::new(py);
  dict.set_item("role", source.role.as_str())?;
  dict.set_item("format", source.format.as_str())?;
  dict.set_item("path", source.path)?;
  dict.set_item("path_lossy", source.path_lossy)?;
  dict.set_item("precedence", source.precedence)?;
  Ok(dict.into())
}

fn source_identity_dict(py: Python<'_>, source: CookieSourceIdentity) -> PyResult<Py<PyAny>> {
  let dict = PyDict::new(py);
  dict.set_item("role", source.role.as_str())?;
  dict.set_item("format", source.format.as_str())?;
  dict.set_item("path", source.path)?;
  dict.set_item("path_lossy", source.path_lossy)?;
  dict.set_item("precedence", source.precedence)?;
  Ok(dict.into())
}

fn report_dict(py: Python<'_>, report: ExtractionReport) -> PyResult<Py<PyAny>> {
  let profiles = report
    .profiles
    .into_iter()
    .map(|profile| profile_extraction_dict(py, profile))
    .collect::<PyResult<Vec<_>>>()?;

  let dict = PyDict::new(py);
  dict.set_item("schema_version", report.schema_version)?;
  dict.set_item("status", report.status.as_str())?;
  dict.set_item("termination", report.termination.as_str())?;
  dict.set_item("summary", report_stats_dict(py, report.summary)?)?;
  dict.set_item("profiles", profiles)?;
  dict.set_item("issues", issue_dicts(py, report.issues)?)?;
  Ok(dict.into())
}

fn profile_extraction_dict(py: Python<'_>, profile: ProfileExtraction) -> PyResult<Py<PyAny>> {
  let sources = profile
    .sources
    .into_iter()
    .map(|source| source_extraction_dict(py, source))
    .collect::<PyResult<Vec<_>>>()?;

  let dict = PyDict::new(py);
  dict.set_item("profile", profile_identity_dict(py, profile.profile)?)?;
  dict.set_item("sources", sources)?;
  dict.set_item("stats", extraction_stats_dict(py, profile.stats)?)?;
  dict.set_item("issues", issue_dicts(py, profile.issues)?)?;
  Ok(dict.into())
}

fn source_extraction_dict(py: Python<'_>, source: SourceExtraction) -> PyResult<Py<PyAny>> {
  let dict = PyDict::new(py);
  dict.set_item("source", source_identity_dict(py, source.source)?)?;
  dict.set_item("status", source.status.as_str())?;
  dict.set_item("selected", source.selected)?;
  dict.set_item("acquisition_strategy", source.acquisition_strategy.as_str())?;
  dict.set_item("cookies", to_dict(py, source.cookies)?)?;
  dict.set_item("stats", extraction_stats_dict(py, source.stats)?)?;
  dict.set_item("issues", issue_dicts(py, source.issues)?)?;
  Ok(dict.into())
}

fn extraction_stats_dict(py: Python<'_>, stats: ExtractionStats) -> PyResult<Py<PyAny>> {
  let dict = PyDict::new(py);
  dict.set_item("rows_seen", stats.rows_seen)?;
  dict.set_item("cookies_emitted", stats.cookies_emitted)?;
  dict.set_item("rows_skipped", stats.rows_skipped)?;
  dict.set_item("rows_rejected", stats.rows_rejected)?;
  dict.set_item("provider_failures", stats.provider_failures)?;
  dict.set_item("acquisition_attempts", stats.acquisition_attempts)?;
  dict.set_item("counters_saturated", stats.counters_saturated)?;
  Ok(dict.into())
}

fn report_stats_dict(py: Python<'_>, stats: ReportStats) -> PyResult<Py<PyAny>> {
  let dict = PyDict::new(py);
  dict.set_item("registered_browsers", stats.registered_browsers)?;
  dict.set_item("browsers_detected", stats.browsers_detected)?;
  dict.set_item("browsers_not_detected", stats.browsers_not_detected)?;
  dict.set_item("installations_discovered", stats.installations_discovered)?;
  dict.set_item("profiles_discovered", stats.profiles_discovered)?;
  dict.set_item("sources_succeeded", stats.sources_succeeded)?;
  dict.set_item("sources_failed", stats.sources_failed)?;
  dict.set_item("rows_seen", stats.rows_seen)?;
  dict.set_item("cookies_emitted", stats.cookies_emitted)?;
  dict.set_item("rows_skipped", stats.rows_skipped)?;
  dict.set_item("rows_rejected", stats.rows_rejected)?;
  dict.set_item("provider_failures", stats.provider_failures)?;
  dict.set_item("counters_saturated", stats.counters_saturated)?;
  Ok(dict.into())
}

fn issue_dicts(py: Python<'_>, issues: Vec<ExtractionIssue>) -> PyResult<Vec<Py<PyAny>>> {
  issues
    .into_iter()
    .map(|issue| issue_dict(py, issue))
    .collect()
}

fn issue_dict(py: Python<'_>, issue: ExtractionIssue) -> PyResult<Py<PyAny>> {
  let dict = PyDict::new(py);
  dict.set_item("code", issue.code.as_str())?;
  dict.set_item("stage", issue.stage.as_str())?;
  dict.set_item("severity", issue.severity.as_str())?;
  dict.set_item("cause", issue.cause)?;
  dict.set_item("provider", issue.provider)?;
  dict.set_item("tier", issue.tier)?;
  dict.set_item("retryability", issue.retryability)?;
  dict.set_item("occurrences", issue.occurrences)?;
  dict.set_item("samples", issue.samples)?;
  dict.set_item(
    "browser_id",
    issue.browser_id.as_ref().map(|id| id.as_str()),
  )?;
  dict.set_item(
    "installation_id",
    issue.installation_id.as_ref().map(|id| id.as_str()),
  )?;
  dict.set_item(
    "profile_id",
    issue.profile_id.as_ref().map(|id| id.as_str()),
  )?;
  dict.set_item("message", issue.message)?;
  Ok(dict.into())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::errors::RookieRequestError;

  #[test]
  fn browser_report_rejects_an_unknown_select_even_alongside_a_profile() {
    Python::initialize();
    Python::attach(|py| {
      // The scope match only runs when no profile is named, so a typo passed
      // with a profile used to be dropped and extraction started anyway. The
      // browser id is deliberately nonexistent: this must be caught before
      // browser resolution.
      let error = browser_report(
        py,
        "not-a-real-browser".to_owned(),
        Some("Default".to_owned()),
        None,
        Some("legacy_frst".to_owned()),
        None,
        None,
        "disabled".to_owned(),
      )
      .expect_err("an unknown select value must be rejected on every call shape");
      assert!(error.is_instance_of::<RookieRequestError>(py));
      assert!(
        error.value(py).to_string().contains("legacy_frst"),
        "the message names the offending value: {error}"
      );
    });
  }

  #[test]
  fn browser_report_rejects_a_profile_id_with_select_all_before_any_io() {
    Python::initialize();
    Python::attach(|py| {
      // The browser id is deliberately nonexistent: this conflict must be
      // caught before browser resolution, so the error must be about the
      // conflict, not the browser.
      let error = browser_report(
        py,
        "not-a-real-browser".to_owned(),
        Some("Default".to_owned()),
        None,
        Some("all".to_owned()),
        None,
        None,
        "disabled".to_owned(),
      )
      .expect_err("profile_id + select=\"all\" must be rejected before I/O");
      assert!(error.is_instance_of::<RookieRequestError>(py));
      let value = error.value(py);
      assert_eq!(
        value.getattr("code").unwrap().extract::<String>().unwrap(),
        "conflicting_profile_selection"
      );
    });
  }

  #[test]
  fn browser_report_allows_a_profile_id_with_selects_default_left_unset() {
    Python::initialize();
    Python::attach(|py| {
      // Regression guard: `select`'s *effective* default is "all", but a
      // caller who never touches `select` at all (every pre-`select` call
      // site) must not be rejected just because that default happens to be
      // the same string the *explicit* conflict checks for. This must fail
      // on browser resolution (`unknown_browser`), never on the
      // profile+select combination.
      let error = browser_report(
        py,
        "not-a-real-browser".to_owned(),
        Some("Default".to_owned()),
        None,
        None,
        None,
        None,
        "disabled".to_owned(),
      )
      .expect_err("an unknown browser id must still fail");
      assert!(error.is_instance_of::<RookieRequestError>(py));
      let value = error.value(py);
      assert_eq!(
        value.getattr("code").unwrap().extract::<String>().unwrap(),
        "unknown_browser"
      );
    });
  }

  #[test]
  fn browser_report_allows_a_profile_id_with_a_non_all_select() {
    Python::initialize();
    Python::attach(|py| {
      // `profile_id` always wins over `select` (see `browser_report`'s
      // doc), so `select="legacy_first"` alongside a profile is not the
      // conflict: this must fail on browser resolution (`unknown_browser`),
      // proving the request reached `extract_report` instead of being
      // rejected for the profile+select combination.
      let error = browser_report(
        py,
        "not-a-real-browser".to_owned(),
        Some("Default".to_owned()),
        None,
        Some("legacy_first".to_owned()),
        None,
        None,
        "disabled".to_owned(),
      )
      .expect_err("an unknown browser id must still fail");
      assert!(error.is_instance_of::<RookieRequestError>(py));
      let value = error.value(py);
      assert_eq!(
        value.getattr("code").unwrap().extract::<String>().unwrap(),
        "unknown_browser"
      );
    });
  }

  #[test]
  fn browser_report_rejects_an_unknown_select_value() {
    Python::initialize();
    Python::attach(|py| {
      let error = browser_report(
        py,
        "not-a-real-browser".to_owned(),
        None,
        None,
        Some("sideways".to_owned()),
        None,
        None,
        "disabled".to_owned(),
      )
      .expect_err("an unrecognized select value must be rejected");
      assert!(error.is_instance_of::<RookieRequestError>(py));
    });
  }
}
