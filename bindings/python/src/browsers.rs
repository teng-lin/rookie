use crate::{detailed_to_dict, to_dict, PyCancellationHandle};
use ::rookie_cookies as rookie_core;
use pyo3::exceptions::PyValueError;
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
];

#[cfg(test)]
mod tests {
  use super::CHROMIUM_PATH_OPTION_KEYS;

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
      .map_err(|_| PyValueError::new_err("Chromium path option keys must be strings"))?;
    let key = key.extract::<String>()?;
    if !CHROMIUM_PATH_OPTION_KEYS.contains(&key.as_str()) {
      return Err(PyValueError::new_err(format!(
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
    PyValueError::new_err(format!(
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
    PyValueError::new_err("Chromium path option 'domains' must be a list of strings or None")
  })?;
  values
    .iter()
    .enumerate()
    .map(|(index, value)| {
      value
        .cast::<PyString>()
        .map_err(|_| {
          PyValueError::new_err(format!(
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
          PyValueError::new_err(
            "Chromium path option 'timeout' must be a number of seconds or None",
          )
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
    PyValueError::new_err(
      "Chromium path option 'cancellation' must be a CancellationHandle or None",
    )
  })?;
  Ok(Some(handle.0))
}

fn plaintext_only_option(options: &Bound<'_, PyDict>) -> PyResult<bool> {
  let Some(value) = option_value(options, "plaintext_only")? else {
    return Ok(false);
  };
  let value = value.cast::<PyBool>().map_err(|_| {
    PyValueError::new_err("Chromium path option 'plaintext_only' must be a bool or None")
  })?;
  Ok(value.is_true())
}

fn chromium_path_request(
  path: String,
  options: Option<Bound<'_, PyAny>>,
) -> PyResult<rookie_core::direct_path::ChromiumPathRequest> {
  let Some(options) = options else {
    return Ok(rookie_core::direct_path::ChromiumPathRequest::new(path));
  };
  if options.is_none() {
    return Ok(rookie_core::direct_path::ChromiumPathRequest::new(path));
  }
  let options = options
    .cast::<PyDict>()
    .map_err(|_| PyValueError::new_err("Chromium path options must be a dict or None"))?;
  validate_option_keys(options)?;

  let domains = domains_option(options)?;
  let browser_id = string_option(options, "browser_id")?;
  let local_state_path = string_option(options, "local_state_path")?;
  let plaintext_only = plaintext_only_option(options)?;
  let timeout = timeout_option(options)?;
  let cancellation = cancellation_option(options)?;

  let selector_count = usize::from(browser_id.is_some())
    + usize::from(local_state_path.is_some())
    + usize::from(plaintext_only);
  if selector_count > 1 {
    return Err(PyValueError::new_err(
      "Chromium path options browser_id, local_state_path, and plaintext_only are mutually exclusive",
    ));
  }

  let mut request = rookie_core::direct_path::ChromiumPathRequest::new(path);
  if let Some(domains) = domains {
    request = request.domains(domains);
  }
  if let Some(timeout) = timeout {
    request = request.timeout(timeout);
  }
  if let Some(cancellation) = cancellation {
    request = request.cancellation(cancellation);
  }
  let credentials = if let Some(browser_id) = browser_id {
    Some(rookie_core::direct_path::ChromiumCredentialSource::BrowserId(browser_id))
  } else if let Some(local_state_path) = local_state_path {
    Some(
      rookie_core::direct_path::ChromiumCredentialSource::LocalStateFile(PathBuf::from(
        local_state_path,
      )),
    )
  } else if plaintext_only {
    Some(rookie_core::direct_path::ChromiumCredentialSource::PlaintextOnly)
  } else {
    None
  };
  if let Some(credentials) = credentials {
    request = request.credentials(credentials);
  }
  Ok(request)
}

fn duration_from_seconds(seconds: f64) -> PyResult<std::time::Duration> {
  // The fallible constructor rejects everything `Duration::from_secs_f64`
  // would otherwise panic on: negative, non-finite, and merely finite values
  // too large to represent as a `Duration`.
  std::time::Duration::try_from_secs_f64(seconds).map_err(|_| {
    PyValueError::new_err(
      "timeout must be a non-negative, finite number of seconds representable as a Duration",
    )
  })
}

/// Extract cookies after identifying an explicit cookie source.
#[pyfunction]
#[pyo3(signature = (path, domains=None, timeout=None, cancellation=None))]
pub fn cookies_from_path(
  py: Python<'_>,
  path: String,
  domains: Option<Vec<String>>,
  timeout: Option<f64>,
  cancellation: Option<PyCancellationHandle>,
) -> PyResult<Vec<Py<PyAny>>> {
  let mut request = rookie_core::direct_path::DirectPathRequest::new(path);
  if let Some(domains) = domains {
    request = request.domains(domains);
  }
  if let Some(timeout) = timeout {
    request = request.timeout(duration_from_seconds(timeout)?);
  }
  if let Some(cancellation) = cancellation {
    request = request.cancellation(cancellation.0);
  }
  let cookies = py
    .detach(|| rookie_core::direct_path::cookies_from_path(request))
    .map_err(crate::errors::classify_fault)?;
  to_dict(py, cookies)
}

/// Extract cookies from an explicit Chromium cookie database.
#[pyfunction]
#[pyo3(signature = (path, options=None))]
pub fn chromium_cookies_from_path(
  py: Python<'_>,
  path: String,
  options: Option<Bound<'_, PyAny>>,
) -> PyResult<Vec<Py<PyAny>>> {
  let request = chromium_path_request(path, options)?;
  let cookies = py
    .detach(|| rookie_core::direct_path::chromium_cookies_from_path(request))
    .map_err(crate::errors::classify_fault)?;
  to_dict(py, cookies)
}

/// Detailed counterpart to ``chromium_cookies_from_path``.
#[pyfunction]
#[pyo3(signature = (path, options=None))]
pub fn chromium_cookies_from_path_detailed(
  py: Python<'_>,
  path: String,
  options: Option<Bound<'_, PyAny>>,
) -> PyResult<Vec<Py<PyAny>>> {
  let request = chromium_path_request(path, options)?;
  let cookies = py
    .detach(|| rookie_core::direct_path::chromium_cookies_from_path_detailed(request))
    .map_err(crate::errors::classify_fault)?;
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
