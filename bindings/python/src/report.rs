//! Generic registry and report bindings.
//!
//! Every DTO crosses into Python as a plain dictionary whose keys are the Rust
//! field names verbatim, and every open string identifier newtype as a plain
//! `str`, so a vocabulary value this build has never seen still arrives intact.

use crate::to_dict;
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
/// :return: A list of browser descriptor dictionaries
#[pyfunction]
pub fn supported_browsers(py: Python<'_>) -> PyResult<Vec<Py<PyAny>>> {
  py.detach(rookie_core::supported_browsers)?
    .into_iter()
    .map(|browser| browser_descriptor_dict(py, browser))
    .collect()
}

/// List the discovered profiles of one registered browser
///
/// :param browser_id: A canonical browser ID or alias from supported_browsers
/// :return: A list of profile descriptor dictionaries
#[pyfunction]
pub fn browser_profiles(py: Python<'_>, browser_id: String) -> PyResult<Vec<Py<PyAny>>> {
  py.detach(|| rookie_core::browser_profiles(&browser_id))?
    .into_iter()
    .map(|profile| profile_descriptor_dict(py, profile))
    .collect()
}

/// List Google Chrome profiles with the last-used/active profile first
///
/// Activity hints are advisory. Missing or invalid hints retain the generic
/// default-first discovery order.
///
/// :return: A list of profile descriptor dictionaries
#[pyfunction]
pub fn chrome_profiles(py: Python<'_>) -> PyResult<Vec<Py<PyAny>>> {
  py.detach(rookie_core::chrome_profiles)?
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
  let report = py.detach(|| rookie_core::chrome_profile(&profile, domains))?;
  report_dict(py, report)
}

/// Extract cookies from one browser as a grouped report
///
/// :param browser_id: A canonical browser ID or alias from supported_browsers
/// :param profile_id: Optional profile_id from browser_profiles, restricting the report to it
/// :param domains: Optional list of domains to extract only from them
/// :return: An extraction report dictionary
#[pyfunction]
#[pyo3(signature = (browser_id, profile_id=None, domains=None))]
pub fn browser_report(
  py: Python<'_>,
  browser_id: String,
  profile_id: Option<String>,
  domains: Option<Vec<String>>,
) -> PyResult<Py<PyAny>> {
  let report =
    py.detach(|| rookie_core::browser_report(&browser_id, profile_id.as_deref(), domains))?;
  report_dict(py, report)
}

/// Extract cookies from every registered browser as one grouped report
///
/// :param domains: Optional list of domains to extract only from them
/// :return: An extraction report dictionary
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn load_report(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Py<PyAny>> {
  let report = py.detach(|| rookie_core::load_report(domains))?;
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
  dict.set_item("status", report.status.as_str())?;
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
