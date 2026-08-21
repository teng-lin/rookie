#![allow(deprecated)]

use ::rookie_cookies as rookie_core;
use log::LevelFilter;
use pyo3::{prelude::*, types::PyDict};
use pyo3_log::{Caching, Logger};
use rookie_core::enums::{Cookie, DetailedCookie};
mod browsers;
mod errors;
mod job;
mod report;
use browsers::*;
use job::{from_path, read, PyReadResult, PyReadWarning};
use report::{
  browser_profiles, browser_report, chrome_profile, chrome_profiles, load_report,
  supported_browsers,
};

#[pyfunction]
fn version() -> PyResult<String> {
  Ok(rookie_core::version())
}

/// A shared stop signal for an in-flight extraction.
///
/// Calling `cancel()` from any thread (e.g. a signal handler, or another
/// Python thread) stops the extraction this handle was passed into at its
/// next internal checkpoint. Cloning shares the same underlying signal --
/// cancelling a clone cancels every clone.
#[pyclass(name = "CancellationHandle")]
#[derive(Clone)]
pub struct PyCancellationHandle(pub(crate) rookie_core::CancellationHandle);

#[pymethods]
impl PyCancellationHandle {
  #[new]
  fn new() -> Self {
    Self(rookie_core::CancellationHandle::new())
  }

  fn cancel(&self) -> bool {
    self.0.cancel()
  }

  fn is_cancelled(&self) -> bool {
    self.0.is_cancelled()
  }
}

/// Parses a caller-supplied seconds value into a `Duration`, rejecting
/// everything `Duration::from_secs_f64` would otherwise panic on: negative,
/// non-finite, and merely finite values too large to represent.
pub(crate) fn duration_from_seconds(seconds: f64) -> PyResult<std::time::Duration> {
  std::time::Duration::try_from_secs_f64(seconds).map_err(|_| {
    errors::request_error(
      "timeout must be a non-negative, finite number of seconds representable as a Duration",
    )
  })
}

/// Parses one of the three stable `app_bound` policy strings this binding
/// promises.
///
/// `rookie_core::AppBoundPolicy::as_str`'s values are crate-private, so this
/// hand-written inverse is the one place that must be kept in sync with them
/// by hand. An unrecognized string is a request fault raised before any I/O
/// runs, never silently downgraded to `"disabled"`.
pub(crate) fn app_bound_policy(value: &str) -> PyResult<rookie_core::AppBoundPolicy> {
  match value {
    "disabled" => Ok(rookie_core::AppBoundPolicy::Disabled),
    "injection_only" => Ok(rookie_core::AppBoundPolicy::InjectionOnly),
    "allow_elevated_fallback" => Ok(rookie_core::AppBoundPolicy::AllowElevatedFallback),
    other => Err(errors::request_error(format!(
      "unknown app_bound policy {other:?}; expected \"disabled\", \"injection_only\", \
       or \"allow_elevated_fallback\""
    ))),
  }
}

/// Builds the timeout/cancellation knobs every I/O job takes, without
/// App-Bound: used by the listing jobs (`browser_profiles`, `chrome_profiles`),
/// which touch the filesystem but do no App-Bound recovery and take no
/// `app_bound` parameter at all.
pub(crate) fn execution_control_without_app_bound(
  timeout: Option<f64>,
  cancellation: Option<PyCancellationHandle>,
) -> PyResult<rookie_core::ExecutionControl> {
  let mut control = rookie_core::ExecutionControl::default();
  if let Some(timeout) = timeout {
    control = control.timeout(duration_from_seconds(timeout)?);
  }
  if let Some(cancellation) = cancellation {
    control = control.cancellation(cancellation.0);
  }
  Ok(control)
}

/// Builds the full timeout/cancellation/app_bound execution control shared by
/// every I/O job that can recover Windows App-Bound (v20) keys.
pub(crate) fn execution_control(
  timeout: Option<f64>,
  cancellation: Option<PyCancellationHandle>,
  app_bound: &str,
) -> PyResult<rookie_core::ExecutionControl> {
  Ok(
    execution_control_without_app_bound(timeout, cancellation)?
      .app_bound(app_bound_policy(app_bound)?),
  )
}

/// The structured fault for a `profile=`/`select=` combination the type
/// system rejects in Rust but a binding must still validate at runtime.
///
/// `rookie_core::RequestError::ConflictingProfileSelection` exists for
/// exactly this: bindings cannot express `ReportScope` (or `ExtractRequest`'s
/// single-profile-only selection) in their own type systems, so the
/// constraint Rust makes unrepresentable becomes one validated code here,
/// raised before any I/O runs. See `read`'s and `browser_report`'s `select`
/// handling.
pub(crate) fn conflicting_profile_selection_error() -> PyErr {
  errors::classify_error(rookie_core::Error::from(
    rookie_core::RequestError::ConflictingProfileSelection,
  ))
}

/// The structured fault for more than one Chromium credential selector
/// (`plaintext_only` / `browser_id` / `local_state_path`) given at once.
///
/// `PathExtractRequest`'s platform-gated constructors and
/// `FromPathRequest::chromium_*` setters each pick exactly one credential
/// strategy, so a binding option set that names more than one is a request
/// fault caught here, before any source I/O.
pub(crate) fn conflicting_credential_selectors_error() -> PyErr {
  errors::classify_error(rookie_core::Error::from(
    rookie_core::RequestError::ConflictingCredentialSelectors,
  ))
}

#[pymodule]
fn rookie_cookies(m: &Bound<'_, PyModule>) -> PyResult<()> {
  // Scope log forwarding to the "rookie_cookies" Python logger instead of
  // attaching to the root logger, which would pollute host application log
  // streams. See: https://github.com/teng-lin/rookie-cookies/issues/51
  if let Ok(logger) = Logger::new(m.py(), Caching::LoggersAndLevels) {
    let _ = logger
      .filter(LevelFilter::Off)
      .filter_target("rookie_cookies".to_owned(), LevelFilter::Debug)
      .install();
  }
  m.add_function(wrap_pyfunction!(firefox, m)?)?;
  m.add_function(wrap_pyfunction!(firefox_profiles, m)?)?;
  m.add_function(wrap_pyfunction!(firefox_profile, m)?)?;
  m.add_function(wrap_pyfunction!(zen, m)?)?;

  m.add_function(wrap_pyfunction!(librewolf, m)?)?;
  m.add_function(wrap_pyfunction!(chrome, m)?)?;
  m.add_function(wrap_pyfunction!(brave, m)?)?;
  m.add_function(wrap_pyfunction!(edge, m)?)?;
  m.add_function(wrap_pyfunction!(opera, m)?)?;

  m.add_function(wrap_pyfunction!(chromium, m)?)?;
  m.add_function(wrap_pyfunction!(vivaldi, m)?)?;
  m.add_function(wrap_pyfunction!(arc, m)?)?;
  m.add_function(wrap_pyfunction!(chromium_based, m)?)?;
  m.add_function(wrap_pyfunction!(chromium_based_detailed, m)?)?;
  m.add_function(wrap_pyfunction!(extract_from_path, m)?)?;
  m.add_function(wrap_pyfunction!(cookies_from_path, m)?)?;
  m.add_function(wrap_pyfunction!(chromium_cookies_from_path, m)?)?;
  m.add_function(wrap_pyfunction!(chromium_cookies_from_path_detailed, m)?)?;
  m.add_function(wrap_pyfunction!(firefox_based, m)?)?;
  m.add_function(wrap_pyfunction!(firefox_based_detailed, m)?)?;
  m.add_function(wrap_pyfunction!(load, m)?)?;
  m.add_function(wrap_pyfunction!(any_browser, m)?)?;

  // An issue counts every occurrence but keeps at most this many samples, so a
  // caller comparing the two needs the cap to tell truncation from completeness.
  m.add("MAX_ISSUE_SAMPLES", rookie_core::report::MAX_ISSUE_SAMPLES)?;
  m.add_function(wrap_pyfunction!(supported_browsers, m)?)?;
  m.add_function(wrap_pyfunction!(browser_profiles, m)?)?;
  m.add_function(wrap_pyfunction!(chrome_profiles, m)?)?;
  m.add_function(wrap_pyfunction!(chrome_profile, m)?)?;
  m.add_function(wrap_pyfunction!(browser_report, m)?)?;
  m.add_function(wrap_pyfunction!(load_report, m)?)?;
  m.add_function(wrap_pyfunction!(read, m)?)?;
  m.add_function(wrap_pyfunction!(from_path, m)?)?;
  m.add_class::<PyReadResult>()?;
  m.add_class::<PyReadWarning>()?;

  #[cfg(target_os = "windows")]
  {
    m.add_function(wrap_pyfunction!(internet_explorer, m)?)?;
    m.add_function(wrap_pyfunction!(octo_browser, m)?)?;
    m.add_function(wrap_pyfunction!(opera_gx, m)?)?;
  }
  #[cfg(target_os = "macos")]
  {
    m.add_function(wrap_pyfunction!(opera_gx, m)?)?;
    m.add_function(wrap_pyfunction!(safari, m)?)?;
  }
  #[cfg(target_os = "linux")]
  {
    m.add_function(wrap_pyfunction!(cachy, m)?)?;
  }

  m.add_function(wrap_pyfunction!(version, m)?)?;
  m.add_class::<PyCancellationHandle>()?;
  errors::register(m)?;
  Ok(())
}

pub(crate) fn detailed_to_dict(
  py: Python<'_>,
  cookies: Vec<DetailedCookie>,
) -> PyResult<Vec<Py<PyAny>>> {
  cookies
    .into_iter()
    .map(|detailed| {
      let dict = PyDict::new(py);
      let cookie_dict = PyDict::new(py);
      let cookie = detailed.cookie;
      cookie_dict.set_item("domain", cookie.domain)?;
      cookie_dict.set_item("path", cookie.path)?;
      cookie_dict.set_item("secure", cookie.secure)?;
      cookie_dict.set_item("http_only", cookie.http_only)?;
      cookie_dict.set_item("same_site", cookie.same_site)?;
      cookie_dict.set_item("expires", cookie.expires)?;
      cookie_dict.set_item("name", cookie.name)?;
      cookie_dict.set_item("value", cookie.value)?;

      let context = PyDict::new(py);
      context.set_item("top_frame_site_key", detailed.context.top_frame_site_key)?;
      context.set_item(
        "has_cross_site_ancestor",
        detailed.context.has_cross_site_ancestor,
      )?;
      context.set_item("source_scheme", detailed.context.source_scheme)?;
      context.set_item("source_port", detailed.context.source_port)?;
      context.set_item("is_persistent", detailed.context.is_persistent)?;
      context.set_item("origin_attributes", detailed.context.origin_attributes)?;
      context.set_item("user_context_id", detailed.context.user_context_id)?;
      context.set_item("partition_key", detailed.context.partition_key)?;
      context.set_item("private_browsing_id", detailed.context.private_browsing_id)?;
      dict.set_item("cookie", cookie_dict)?;
      dict.set_item("context", context)?;
      Ok(dict.into())
    })
    .collect()
}

pub(crate) fn to_dict(py: Python<'_>, cookies: Vec<Cookie>) -> PyResult<Vec<Py<PyAny>>> {
  let mut cookie_objects: Vec<Py<PyAny>> = vec![];
  for cookie in cookies {
    let dict = PyDict::new(py);
    dict.set_item("domain", cookie.domain)?;
    dict.set_item("path", cookie.path)?;
    dict.set_item("secure", cookie.secure)?;
    dict.set_item("http_only", cookie.http_only)?;
    dict.set_item("same_site", cookie.same_site)?;
    dict.set_item("expires", cookie.expires)?;
    dict.set_item("name", cookie.name)?;
    dict.set_item("value", cookie.value)?;

    cookie_objects.push(dict.into());
  }
  Ok(cookie_objects)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn app_bound_policy_parses_the_three_stable_strings() {
    assert_eq!(
      app_bound_policy("disabled").expect("disabled"),
      rookie_core::AppBoundPolicy::Disabled
    );
    assert_eq!(
      app_bound_policy("injection_only").expect("injection_only"),
      rookie_core::AppBoundPolicy::InjectionOnly
    );
    assert_eq!(
      app_bound_policy("allow_elevated_fallback").expect("allow_elevated_fallback"),
      rookie_core::AppBoundPolicy::AllowElevatedFallback
    );
  }

  #[test]
  fn app_bound_policy_rejects_an_unrecognized_string_as_a_request_fault() {
    Python::initialize();
    Python::attach(|py| {
      let error = app_bound_policy("sometimes").expect_err("unknown policy string");
      assert!(error.is_instance_of::<errors::RookieRequestError>(py));
    });
  }

  #[test]
  fn execution_control_without_app_bound_leaves_the_default_disabled_policy() {
    let control = execution_control_without_app_bound(None, None).expect("no timeout/cancellation");
    assert_eq!(control, rookie_core::ExecutionControl::default());
  }

  #[test]
  fn execution_control_applies_the_parsed_policy_on_top() {
    let control = execution_control(None, None, "injection_only").expect("valid app_bound string");
    assert_eq!(
      control,
      rookie_core::ExecutionControl::default()
        .app_bound(rookie_core::AppBoundPolicy::InjectionOnly)
    );
  }

  #[test]
  fn duration_from_seconds_rejects_what_duration_from_secs_f64_would_panic_on() {
    assert!(duration_from_seconds(-1.0).is_err());
    assert!(duration_from_seconds(f64::NAN).is_err());
    assert!(duration_from_seconds(f64::INFINITY).is_err());
    assert_eq!(
      duration_from_seconds(1.5).expect("finite non-negative seconds"),
      std::time::Duration::from_secs_f64(1.5)
    );
  }
}
