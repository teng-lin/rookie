use crate::errors::request_error;
use crate::{detailed_to_dict, to_dict, PyCancellationHandle};
use ::rookie_cookies as rookie_core;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBool, PyDict, PyFloat, PyList, PyString};
use std::path::PathBuf;

const CHROMIUM_PATH_OPTION_KEYS: &[&str] = &[
  "domains",
  "browser_id",
  "local_state_path",
  "plaintext_only",
  "timeout",
  "cancellation",
  "app_bound",
];

#[cfg(test)]
mod tests {
  use super::*;
  use crate::errors::RookieRequestError;
  use pyo3::types::PyDict;

  /// This binding surface has no way to request a locked-database process
  /// shutdown: `validate_option_keys` rejects any key outside this fixed
  /// allowlist, and no destructive-acquisition key is in it. A caller can
  /// name only the keys listed here — never `force_kill` or
  /// `locked_database_policy` — so a destructive authorization can only be
  /// constructed by an in-crate Rust adapter, never through this binding.
  #[test]
  fn chromium_path_options_never_expose_a_destructive_acquisition_key() {
    for destructive_key in [
      "force_kill",
      "locked_database_policy",
      "allow_process_shutdown",
    ] {
      assert!(
        !CHROMIUM_PATH_OPTION_KEYS.contains(&destructive_key),
        "{destructive_key} must never become a settable Chromium path option"
      );
    }
  }

  #[test]
  fn app_bound_option_accepts_the_three_stable_strings_and_rejects_anything_else() {
    Python::initialize();
    Python::attach(|py| {
      for (value, expected) in [
        ("disabled", rookie_core::AppBoundPolicy::Disabled),
        ("injection_only", rookie_core::AppBoundPolicy::InjectionOnly),
        (
          "allow_elevated_fallback",
          rookie_core::AppBoundPolicy::AllowElevatedFallback,
        ),
      ] {
        let options = PyDict::new(py);
        options.set_item("app_bound", value).expect("set app_bound");
        assert_eq!(
          app_bound_option(&options).expect("valid app_bound string"),
          Some(expected)
        );
      }

      // Absent key stays `None` (the crate's own `AppBoundPolicy` default
      // applies further up, in `chromium_path_request`), and an unrecognized
      // string is a request fault, not a silent fallback to any policy.
      let options = PyDict::new(py);
      assert_eq!(app_bound_option(&options).expect("absent key"), None);

      let options = PyDict::new(py);
      options
        .set_item("app_bound", "sometimes")
        .expect("set app_bound");
      let error = app_bound_option(&options).expect_err("unknown policy string");
      assert!(error.is_instance_of::<RookieRequestError>(py));
    });
  }

  #[test]
  fn chromium_from_path_request_rejects_a_domains_option() {
    Python::initialize();
    Python::attach(|py| {
      let options = PyDict::new(py);
      options
        .set_item("domains", vec!["example.com"])
        .expect("set domains");
      let error = super::chromium_from_path_request(
        "/nonexistent/Cookies".to_owned(),
        Some(options.into_any()),
      )
      .expect_err("domains must be rejected for the detailed path job");
      assert!(error.is_instance_of::<RookieRequestError>(py));
    });
  }

  #[test]
  fn chromium_from_path_request_rejects_more_than_one_credential_selector() {
    Python::initialize();
    Python::attach(|py| {
      let options = PyDict::new(py);
      options
        .set_item("plaintext_only", true)
        .expect("set plaintext_only");
      options
        .set_item("browser_id", "chrome")
        .expect("set browser_id");
      let error = super::chromium_from_path_request(
        "/nonexistent/Cookies".to_owned(),
        Some(options.into_any()),
      )
      .expect_err("conflicting credential selectors must be rejected");
      assert!(error.is_instance_of::<RookieRequestError>(py));
      let value = error.value(py);
      assert_eq!(
        value.getattr("code").unwrap().extract::<String>().unwrap(),
        "conflicting_credential_selectors"
      );
    });
  }

  #[test]
  fn extract_from_path_rejects_more_than_one_credential_selector_before_any_io() {
    Python::initialize();
    Python::attach(|py| {
      // A nonexistent path is deliberate: the mutual-exclusivity check must
      // run before source I/O, so this must fail on the conflict, never on
      // the missing file.
      let error = super::extract_from_path(
        py,
        "/nonexistent/Cookies".to_owned(),
        None,
        true,
        Some("chrome".to_owned()),
        None,
        None,
        None,
        "disabled".to_owned(),
      )
      .expect_err("plaintext_only + browser_id must be rejected before I/O");
      assert!(error.is_instance_of::<RookieRequestError>(py));
      let value = error.value(py);
      assert_eq!(
        value.getattr("code").unwrap().extract::<String>().unwrap(),
        "conflicting_credential_selectors"
      );
    });
  }
}

fn option_value<'py>(
  options: &'py Bound<'py, PyDict>,
  key: &str,
) -> PyResult<Option<Bound<'py, PyAny>>> {
  Ok(options.get_item(key)?.filter(|value| !value.is_none()))
}

fn validate_option_keys(options: &Bound<'_, PyDict>) -> PyResult<()> {
  for (key, _) in options.iter() {
    let key = key
      .cast::<PyString>()
      .map_err(|_| request_error("Chromium path option keys must be strings"))?;
    let key = key.extract::<String>()?;
    if !CHROMIUM_PATH_OPTION_KEYS.contains(&key.as_str()) {
      return Err(request_error(format!(
        "unknown Chromium path option: {key}"
      )));
    }
  }
  Ok(())
}

fn string_option(options: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<String>> {
  let Some(value) = option_value(options, key)? else {
    return Ok(None);
  };
  let value = value.cast::<PyString>().map_err(|_| {
    request_error(format!(
      "Chromium path option '{key}' must be a string or None"
    ))
  })?;
  Ok(Some(value.extract::<String>()?))
}

fn domains_option(options: &Bound<'_, PyDict>) -> PyResult<Option<Vec<String>>> {
  let Some(value) = option_value(options, "domains")? else {
    return Ok(None);
  };
  let values = value.cast::<PyList>().map_err(|_| {
    request_error("Chromium path option 'domains' must be a list of strings or None")
  })?;
  values
    .iter()
    .enumerate()
    .map(|(index, value)| {
      value
        .cast::<PyString>()
        .map_err(|_| {
          request_error(format!(
            "Chromium path option 'domains' element {index} must be a string"
          ))
        })?
        .extract::<String>()
    })
    .collect::<PyResult<Vec<_>>>()
    .map(Some)
}

fn timeout_option(options: &Bound<'_, PyDict>) -> PyResult<Option<std::time::Duration>> {
  let Some(value) = option_value(options, "timeout")? else {
    return Ok(None);
  };
  let seconds = value
    .cast::<PyFloat>()
    .map(|value| value.value())
    .or_else(|_| {
      value
        .extract::<i64>()
        .map(|value| value as f64)
        .map_err(|_| {
          request_error("Chromium path option 'timeout' must be a number of seconds or None")
        })
    })?;
  duration_from_seconds(seconds).map(Some)
}

fn cancellation_option(
  options: &Bound<'_, PyDict>,
) -> PyResult<Option<rookie_core::CancellationHandle>> {
  let Some(value) = option_value(options, "cancellation")? else {
    return Ok(None);
  };
  let handle = value.extract::<PyCancellationHandle>().map_err(|_| {
    request_error("Chromium path option 'cancellation' must be a CancellationHandle or None")
  })?;
  Ok(Some(handle.0))
}

fn plaintext_only_option(options: &Bound<'_, PyDict>) -> PyResult<bool> {
  let Some(value) = option_value(options, "plaintext_only")? else {
    return Ok(false);
  };
  let value = value
    .cast::<PyBool>()
    .map_err(|_| request_error("Chromium path option 'plaintext_only' must be a bool or None"))?;
  Ok(value.is_true())
}

/// Parses the optional `app_bound` Chromium path option, defaulting to
/// `AppBoundPolicy::Disabled` (`None` here) the same way `read` / `from_path`
/// do -- every job that can request App-Bound recovery takes the same policy.
fn app_bound_option(options: &Bound<'_, PyDict>) -> PyResult<Option<rookie_core::AppBoundPolicy>> {
  let Some(value) = string_option(options, "app_bound")? else {
    return Ok(None);
  };
  crate::app_bound_policy(&value).map(Some)
}

// `direct_path::PathExtractRequest::unix_identity`/`windows_local_state` are
// themselves `#[cfg(unix)]`/`#[cfg(windows)]` constructors -- there is no
// portable way to even name them on the other platform, let alone construct
// one and have the core reject it at runtime the way the removed
// `ChromiumCredentialSource::BrowserId`/`LocalStateFile` used to. So the
// binding-level option they back is rejected here, on the platform that has
// no constructor for it, before any I/O.
#[cfg(unix)]
fn unix_identity_extract_request(
  path: String,
  browser_id: String,
) -> PyResult<rookie_core::direct_path::PathExtractRequest> {
  Ok(rookie_core::direct_path::PathExtractRequest::unix_identity(
    path, browser_id,
  ))
}
#[cfg(not(unix))]
fn unix_identity_extract_request(
  _path: String,
  _browser_id: String,
) -> PyResult<rookie_core::direct_path::PathExtractRequest> {
  Err(request_error(
    "Chromium path option 'browser_id' is only supported on Linux/macOS",
  ))
}

#[cfg(windows)]
fn windows_local_state_extract_request(
  path: String,
  local_state_path: String,
) -> PyResult<rookie_core::direct_path::PathExtractRequest> {
  Ok(rookie_core::direct_path::PathExtractRequest::windows_local_state(path, local_state_path))
}
#[cfg(not(windows))]
fn windows_local_state_extract_request(
  _path: String,
  _local_state_path: String,
) -> PyResult<rookie_core::direct_path::PathExtractRequest> {
  Err(request_error(
    "Chromium path option 'local_state_path' is only supported on Windows",
  ))
}

/// Builds the `PathExtractRequest` shared by [`extract_from_path`] -- the
/// canonical name for this job (Rust `direct_path::extract_from_path`, Node
/// `extractFromPath`) -- and the deprecated `chromium_cookies_from_path`,
/// which merely unpacks its options dict into these same flat arguments.
#[allow(clippy::too_many_arguments)]
fn build_extract_from_path_request(
  path: String,
  domains: Option<Vec<String>>,
  plaintext_only: bool,
  browser_id: Option<String>,
  local_state_path: Option<String>,
  timeout: Option<std::time::Duration>,
  cancellation: Option<rookie_core::CancellationHandle>,
  app_bound: Option<rookie_core::AppBoundPolicy>,
) -> PyResult<rookie_core::direct_path::PathExtractRequest> {
  let selector_count = usize::from(browser_id.is_some())
    + usize::from(local_state_path.is_some())
    + usize::from(plaintext_only);
  if selector_count > 1 {
    return Err(crate::conflicting_credential_selectors_error());
  }

  let mut request = if let Some(browser_id) = browser_id {
    unix_identity_extract_request(path, browser_id)?
  } else if let Some(local_state_path) = local_state_path {
    windows_local_state_extract_request(path, local_state_path)?
  } else if plaintext_only {
    rookie_core::direct_path::PathExtractRequest::plaintext(path)
  } else {
    // No selector: identifies the source from its signature and schema, with
    // an encrypted Chromium row rejected as `missing_chromium_credentials`
    // rather than guessed at -- see `PathExtractRequest::sniff`'s docs for
    // exactly how this narrows (Unix) / widens (Windows) relative to the
    // removed `Automatic` credential source.
    rookie_core::direct_path::PathExtractRequest::sniff(path)
  };
  request = request.domains(domains);
  if let Some(timeout) = timeout {
    request = request.timeout(timeout);
  }
  if let Some(cancellation) = cancellation {
    request = request.cancellation(cancellation);
  }
  if let Some(app_bound) = app_bound {
    request = request.app_bound(app_bound);
  }
  Ok(request)
}

/// Parses `chromium_cookies_from_path`'s (deprecated) options dict into the
/// same flat arguments [`build_extract_from_path_request`] takes.
fn chromium_path_request(
  path: String,
  options: Option<Bound<'_, PyAny>>,
) -> PyResult<rookie_core::direct_path::PathExtractRequest> {
  let Some(options) = options else {
    return build_extract_from_path_request(path, None, false, None, None, None, None, None);
  };
  if options.is_none() {
    return build_extract_from_path_request(path, None, false, None, None, None, None, None);
  }
  let options = options
    .cast::<PyDict>()
    .map_err(|_| request_error("Chromium path options must be a dict or None"))?;
  validate_option_keys(options)?;

  let domains = domains_option(options)?;
  let browser_id = string_option(options, "browser_id")?;
  let local_state_path = string_option(options, "local_state_path")?;
  let plaintext_only = plaintext_only_option(options)?;
  let timeout = timeout_option(options)?;
  let cancellation = cancellation_option(options)?;
  let app_bound = app_bound_option(options)?;

  build_extract_from_path_request(
    path,
    domains,
    plaintext_only,
    browser_id,
    local_state_path,
    timeout,
    cancellation,
    app_bound,
  )
}

// `FromPathRequest` (unlike `direct_path::PathExtractRequest`) is the
// portable type this binding otherwise wraps for path jobs -- see its own
// doc comment -- so its Chromium credential setters stay callable on every
// platform; only `browser_id`/`local_state_path` name a platform-specific
// credential, so those two still need the same per-platform rejection as
// `chromium_path_request`'s.
#[cfg(unix)]
fn unix_identity_from_path_request(
  request: rookie_core::FromPathRequest,
  browser_id: String,
) -> PyResult<rookie_core::FromPathRequest> {
  Ok(request.chromium_browser_id(browser_id))
}
#[cfg(not(unix))]
fn unix_identity_from_path_request(
  _request: rookie_core::FromPathRequest,
  _browser_id: String,
) -> PyResult<rookie_core::FromPathRequest> {
  Err(request_error(
    "Chromium path option 'browser_id' is only supported on Linux/macOS",
  ))
}

#[cfg(windows)]
fn windows_local_state_from_path_request(
  request: rookie_core::FromPathRequest,
  local_state_path: String,
) -> PyResult<rookie_core::FromPathRequest> {
  Ok(request.chromium_local_state(local_state_path))
}
#[cfg(not(windows))]
fn windows_local_state_from_path_request(
  _request: rookie_core::FromPathRequest,
  _local_state_path: String,
) -> PyResult<rookie_core::FromPathRequest> {
  Err(request_error(
    "Chromium path option 'local_state_path' is only supported on Windows",
  ))
}

/// Parses `chromium_cookies_from_path_detailed`'s options into a
/// [`rookie_core::FromPathRequest`].
///
/// **`domains` is rejected, not silently dropped or reimplemented.**
/// `FromPathRequest` has no `domains` filter of its own -- unlike
/// `direct_path::PathExtractRequest`, it gained isolation-aware
/// (`detailed_cookies()`) output before it gained a domain filter, and the
/// core's own matching rule
/// (`rookie_cookies::common::utils::host_matches_domain`) is `pub(crate)`,
/// unreachable from this binding crate. A domain-filtered *detailed* path
/// list is a real, upstream narrowing (see CHANGELOG.md); this makes that
/// loud at the option-shape level instead of silently ignoring the filter
/// or reimplementing the core's matching rule a second time.
fn chromium_from_path_request(
  path: String,
  options: Option<Bound<'_, PyAny>>,
) -> PyResult<rookie_core::FromPathRequest> {
  let Some(options) = options else {
    return Ok(rookie_core::FromPathRequest::new(path));
  };
  if options.is_none() {
    return Ok(rookie_core::FromPathRequest::new(path));
  }
  let options = options
    .cast::<PyDict>()
    .map_err(|_| request_error("Chromium path options must be a dict or None"))?;
  validate_option_keys(options)?;

  if domains_option(options)?.is_some() {
    return Err(request_error(
      "chromium_cookies_from_path_detailed no longer supports a 'domains' \
       filter (see CHANGELOG.md); use chromium_cookies_from_path for a \
       domain-filtered flat list, or filter this function's output yourself",
    ));
  }
  let browser_id = string_option(options, "browser_id")?;
  let local_state_path = string_option(options, "local_state_path")?;
  let plaintext_only = plaintext_only_option(options)?;
  let timeout = timeout_option(options)?;
  let cancellation = cancellation_option(options)?;
  let app_bound = app_bound_option(options)?;

  let selector_count = usize::from(browser_id.is_some())
    + usize::from(local_state_path.is_some())
    + usize::from(plaintext_only);
  if selector_count > 1 {
    return Err(crate::conflicting_credential_selectors_error());
  }

  let mut request = rookie_core::FromPathRequest::new(path);
  request = if let Some(browser_id) = browser_id {
    unix_identity_from_path_request(request, browser_id)?
  } else if let Some(local_state_path) = local_state_path {
    windows_local_state_from_path_request(request, local_state_path)?
  } else if plaintext_only {
    request.chromium_plaintext()
  } else {
    // No selector: `FromPathRequest::new`'s own default already identifies
    // the source automatically, same narrowing/widening as `sniff` above.
    request
  };
  if let Some(timeout) = timeout {
    request = request.timeout(timeout);
  }
  if let Some(cancellation) = cancellation {
    request = request.cancellation(cancellation);
  }
  if let Some(app_bound) = app_bound {
    request = request.app_bound(app_bound);
  }
  Ok(request)
}

fn duration_from_seconds(seconds: f64) -> PyResult<std::time::Duration> {
  // The fallible constructor rejects everything `Duration::from_secs_f64`
  // would otherwise panic on: negative, non-finite, and merely finite values
  // too large to represent as a `Duration`.
  std::time::Duration::try_from_secs_f64(seconds).map_err(|_| {
    request_error(
      "timeout must be a non-negative, finite number of seconds representable as a Duration",
    )
  })
}

/// Extract cookies from an explicit cookie file.
///
/// The canonical name for this job (Rust `direct_path::extract_from_path`,
/// Node `extractFromPath`, CLI `from-path --domains`). `cookies_from_path`
/// and `chromium_cookies_from_path` remain as deprecated aliases onto this
/// function.
///
/// By default the source is identified automatically: a Mozilla / Safari /
/// Internet Explorer store needs no credential, and an encrypted Chromium
/// row is `missing_chromium_credentials` rather than a guess at which
/// browser wrote it. At most one of `plaintext_only`, `browser_id`,
/// `local_state_path` may be given.
///
/// ``app_bound`` defaults to ``"injection_only"``, same as `read` -- see
/// CHANGELOG.md.
///
/// :param path: Path to a cookie database or cookies file
/// :param domains: Optional list of domains to extract only from them
/// :param plaintext_only: Reject the whole request if any Chromium row is
///     encrypted, rather than guessing a credential for it
/// :param browser_id: Registry browser identity for an encrypted Chromium
///     database (Linux keyring / macOS Keychain). Unix only.
/// :param local_state_path: Path to a Chromium `Local State` file, for an
///     encrypted Chromium database. Windows only.
/// :param timeout: Optional timeout in seconds
/// :param cancellation: Optional CancellationHandle
/// :param app_bound: Windows App-Bound (v20) recovery policy: "injection_only"
///     (default), "disabled", or "allow_elevated_fallback". A no-op
///     off Windows.
/// :return: A list of dictionaries of cookies
/// :raises RookieRequestError: More than one credential selector was given
///     (`conflicting_credential_selectors`), a platform-incompatible one, or
///     an unrecognized `app_bound` value
#[pyfunction]
#[pyo3(signature = (
  path,
  *,
  domains=None,
  plaintext_only=false,
  browser_id=None,
  local_state_path=None,
  timeout=None,
  cancellation=None,
  app_bound="injection_only".to_string(),
))]
#[allow(clippy::too_many_arguments)]
pub fn extract_from_path(
  py: Python<'_>,
  path: String,
  domains: Option<Vec<String>>,
  plaintext_only: bool,
  browser_id: Option<String>,
  local_state_path: Option<String>,
  timeout: Option<f64>,
  cancellation: Option<PyCancellationHandle>,
  app_bound: String,
) -> PyResult<Vec<Py<PyAny>>> {
  let timeout = timeout.map(duration_from_seconds).transpose()?;
  let cancellation = cancellation.map(|handle| handle.0);
  let app_bound = Some(crate::app_bound_policy(&app_bound)?);
  let request = build_extract_from_path_request(
    path,
    domains,
    plaintext_only,
    browser_id,
    local_state_path,
    timeout,
    cancellation,
    app_bound,
  )?;
  let cookies = py
    .detach(|| rookie_core::direct_path::extract_from_path(request))
    .map_err(crate::errors::classify_error)?;
  to_dict(py, cookies)
}

/// Extract cookies after identifying an explicit cookie source.
///
/// **Deprecated: use [`extract_from_path`] instead.** Identical to calling
/// it with no `plaintext_only` / `browser_id` / `local_state_path`.
#[pyfunction]
#[pyo3(signature = (path, domains=None, timeout=None, cancellation=None))]
pub fn cookies_from_path(
  py: Python<'_>,
  path: String,
  domains: Option<Vec<String>>,
  timeout: Option<f64>,
  cancellation: Option<PyCancellationHandle>,
) -> PyResult<Vec<Py<PyAny>>> {
  let timeout = timeout.map(duration_from_seconds).transpose()?;
  let cancellation = cancellation.map(|handle| handle.0);
  let request = build_extract_from_path_request(
    path,
    domains,
    false,
    None,
    None,
    timeout,
    cancellation,
    None,
  )?;
  let cookies = py
    .detach(|| rookie_core::direct_path::extract_from_path(request))
    .map_err(crate::errors::classify_error)?;
  to_dict(py, cookies)
}

/// Extract cookies from an explicit Chromium cookie database.
///
/// **Deprecated: use [`extract_from_path`] instead**, which takes the same
/// options as flat keyword arguments rather than a dict.
///
/// ``options["app_bound"]`` defaults to ``"injection_only"``, same as `read` --
/// see CHANGELOG.md.
#[pyfunction]
#[pyo3(signature = (path, options=None))]
pub fn chromium_cookies_from_path(
  py: Python<'_>,
  path: String,
  options: Option<Bound<'_, PyAny>>,
) -> PyResult<Vec<Py<PyAny>>> {
  let request = chromium_path_request(path, options)?;
  let cookies = py
    .detach(|| rookie_core::direct_path::extract_from_path(request))
    .map_err(crate::errors::classify_error)?;
  to_dict(py, cookies)
}

/// Detailed counterpart to ``chromium_cookies_from_path``.
///
/// **Deprecated: no direct replacement of the same shape.** Isolation-aware
/// path output now comes from `from_path(..).detailed_cookies()`, which has
/// no `domains` filter of its own -- see [`chromium_from_path_request`] and
/// CHANGELOG.md. Backed by ``rookie_core::from_path(..).into_detailed_cookies()``.
/// **No longer accepts a ``domains`` option.**
#[pyfunction]
#[pyo3(signature = (path, options=None))]
pub fn chromium_cookies_from_path_detailed(
  py: Python<'_>,
  path: String,
  options: Option<Bound<'_, PyAny>>,
) -> PyResult<Vec<Py<PyAny>>> {
  let request = chromium_from_path_request(path, options)?;
  let cookies = py
    .detach(|| rookie_core::from_path(request))
    .map_err(crate::errors::classify_error)?
    .into_detailed_cookies();
  detailed_to_dict(py, cookies)
}

/// Extract Cookies from any browser
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (db_path, domains=None, key_path=None))]
pub fn any_browser(
  py: Python<'_>,
  db_path: String,
  domains: Option<Vec<String>>,
  key_path: Option<String>,
) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| rookie_core::any_browser(&db_path, domains, key_path.as_deref()))
    .map_err(crate::errors::classify_fault)?;
  to_dict(py, cookies)
}

/// Extract Cookies from Firefox
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn firefox(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| rookie_core::firefox(domains))
    .map_err(crate::errors::classify_fault)?;
  to_dict(py, cookies)
}

/// List every Firefox profile that contains a cookie database
///
/// :return: A list of profile dictionaries with name, path, and is_default fields
#[pyfunction]
pub fn firefox_profiles(py: Python<'_>) -> PyResult<Vec<Py<PyAny>>> {
  let profiles = py
    .detach(rookie_core::firefox_profiles)
    .map_err(crate::errors::classify_fault)?;
  profiles
    .into_iter()
    .map(|profile| {
      let dict = PyDict::new(py);
      dict.set_item("name", profile.name)?;
      dict.set_item("path", profile.path.to_string_lossy().as_ref())?;
      dict.set_item("is_default", profile.is_default)?;
      Ok(dict.into())
    })
    .collect()
}

/// Extract Cookies from a selected Firefox profile
///
/// :param profile: Profile name, directory name, or full path from firefox_profiles
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (profile, domains=None))]
pub fn firefox_profile(
  py: Python<'_>,
  profile: String,
  domains: Option<Vec<String>>,
) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| rookie_core::firefox_profile(&profile, domains))
    .map_err(crate::errors::classify_fault)?;
  to_dict(py, cookies)
}

/// Extract Cookies from Zen
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn zen(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| rookie_core::zen(domains))
    .map_err(crate::errors::classify_fault)?;
  to_dict(py, cookies)
}

/// Extract Cookies from LibreWolf browser
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn librewolf(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| rookie_core::librewolf(domains))
    .map_err(crate::errors::classify_fault)?;
  to_dict(py, cookies)
}

/// Extract Cookies from Google Chrome browser
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn chrome(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| rookie_core::chrome(domains))
    .map_err(crate::errors::classify_fault)?;
  to_dict(py, cookies)
}

/// Extract Cookies from Arc browser
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn arc(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| rookie_core::arc(domains))
    .map_err(crate::errors::classify_fault)?;
  to_dict(py, cookies)
}

/// Extract Cookies from Brave browser
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn brave(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| rookie_core::brave(domains))
    .map_err(crate::errors::classify_fault)?;
  to_dict(py, cookies)
}

/// Extract Cookies from Microsoft Edge browser
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn edge(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| rookie_core::edge(domains))
    .map_err(crate::errors::classify_fault)?;
  to_dict(py, cookies)
}

/// Extract Cookies from Opera browser
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn opera(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| rookie_core::opera(domains))
    .map_err(crate::errors::classify_fault)?;
  to_dict(py, cookies)
}

/// Extract Cookies from Opera GX browser
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn opera_gx(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| rookie_core::opera_gx(domains))
    .map_err(crate::errors::classify_fault)?;
  to_dict(py, cookies)
}

/// Extract Cookies from Cachy Browser
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
#[cfg(target_os = "linux")]
pub fn cachy(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| rookie_core::cachy(domains))
    .map_err(crate::errors::classify_fault)?;
  to_dict(py, cookies)
}

/// Extract Cookies from Chromium browser
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn chromium(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| rookie_core::chromium(domains))
    .map_err(crate::errors::classify_fault)?;
  to_dict(py, cookies)
}

/// Extract Cookies from Vivaldi browser
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn vivaldi(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| rookie_core::vivaldi(domains))
    .map_err(crate::errors::classify_fault)?;
  to_dict(py, cookies)
}

/// Extract Cookies from Firefox-based browsers
///
/// :param key_path: Path to the key file
/// :param db_path: Path to the database file
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (db_path, domains=None))]
pub fn firefox_based(
  py: Python<'_>,
  db_path: String,
  domains: Option<Vec<String>>,
) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| rookie_core::firefox_based(PathBuf::from(&db_path), domains))
    .map_err(crate::errors::classify_fault)?;
  to_dict(py, cookies)
}

/// Extract cookies and Firefox container/origin context from an explicit path.
#[pyfunction]
#[pyo3(signature = (db_path, domains=None))]
pub fn firefox_based_detailed(
  py: Python<'_>,
  db_path: String,
  domains: Option<Vec<String>>,
) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| rookie_core::firefox_based_detailed(PathBuf::from(&db_path), domains))
    .map_err(crate::errors::classify_fault)?;
  detailed_to_dict(py, cookies)
}

/// Load Cookies from a browser
///
/// :param domains: Optional list of domains to load cookies from
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn load(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| rookie_core::load(domains))
    .map_err(crate::errors::classify_fault)?;
  to_dict(py, cookies)
}

/// Extract Cookies from Octo browser
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
#[cfg(target_os = "windows")]
pub fn octo_browser(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| rookie_core::octo_browser(domains))
    .map_err(crate::errors::classify_fault)?;
  to_dict(py, cookies)
}

/// Extract Cookies from Internet Explorer
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
#[cfg(target_os = "windows")]
pub fn internet_explorer(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| rookie_core::internet_explorer(domains))
    .map_err(crate::errors::classify_fault)?;
  to_dict(py, cookies)
}

/// Extract Cookies from Chromium-based browsers
///
/// :param db_path: Path to the database file
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (key_path, db_path, domains=None))]
#[cfg(target_os = "windows")]
pub fn chromium_based(
  py: Python<'_>,
  key_path: String,
  db_path: String,
  domains: Option<Vec<String>>,
) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| {
      rookie_core::chromium_based(
        PathBuf::from(&key_path),
        PathBuf::from(&db_path),
        domains,
        false,
      )
    })
    .map_err(crate::errors::classify_fault)?;
  to_dict(py, cookies)
}

/// Extract detailed cookies from an explicit Chromium database on Windows.
#[pyfunction]
#[pyo3(signature = (key_path, db_path, domains=None))]
#[cfg(target_os = "windows")]
pub fn chromium_based_detailed(
  py: Python<'_>,
  key_path: String,
  db_path: String,
  domains: Option<Vec<String>>,
) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| {
      rookie_core::chromium_based_detailed(
        PathBuf::from(&key_path),
        PathBuf::from(&db_path),
        domains,
        false,
      )
    })
    .map_err(crate::errors::classify_fault)?;
  detailed_to_dict(py, cookies)
}

/// Extract Cookies from Safari browser
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
#[cfg(target_os = "macos")]
pub fn safari(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| rookie_core::safari(domains))
    .map_err(crate::errors::classify_fault)?;
  to_dict(py, cookies)
}

/// Extract Cookies from Chromium-based browsers
///
/// :param db_path: Path to the database file
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (db_path, domains=None, browser_id=None))]
#[cfg(unix)]
pub fn chromium_based(
  py: Python<'_>,
  db_path: String,
  domains: Option<Vec<String>>,
  browser_id: Option<String>,
) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| {
      rookie_core::chromium_based_with_browser_id(
        browser_id.as_deref(),
        PathBuf::from(&db_path),
        domains,
        false,
      )
    })
    .map_err(crate::errors::classify_fault)?;
  to_dict(py, cookies)
}

/// Extract detailed cookies from an explicit Chromium database on Unix.
///
/// ``browser_id`` selects the Linux keyring or macOS Keychain identity. It may
/// be omitted only when every database row is plaintext.
#[pyfunction]
#[pyo3(signature = (db_path, domains=None, browser_id=None))]
#[cfg(unix)]
pub fn chromium_based_detailed(
  py: Python<'_>,
  db_path: String,
  domains: Option<Vec<String>>,
  browser_id: Option<String>,
) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py
    .detach(|| {
      rookie_core::chromium_based_detailed_with_browser_id(
        browser_id.as_deref(),
        PathBuf::from(&db_path),
        domains,
        false,
      )
    })
    .map_err(crate::errors::classify_fault)?;
  detailed_to_dict(py, cookies)
}
