use crate::to_dict;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::path::PathBuf;

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
  let cookies = py.detach(|| rookie_core::any_browser(&db_path, domains, key_path.as_deref()))?;
  to_dict(py, cookies)
}

/// Extract Cookies from Firefox
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn firefox(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py.detach(|| rookie_core::firefox(domains))?;
  to_dict(py, cookies)
}

/// List every Firefox profile that contains a cookie database
///
/// :return: A list of profile dictionaries with name, path, and is_default fields
#[pyfunction]
pub fn firefox_profiles(py: Python<'_>) -> PyResult<Vec<Py<PyAny>>> {
  let profiles = py.detach(rookie_core::firefox_profiles)?;
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
  let cookies = py.detach(|| rookie_core::firefox_profile(&profile, domains))?;
  to_dict(py, cookies)
}

/// Extract Cookies from Zen
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn zen(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py.detach(|| rookie_core::zen(domains))?;
  to_dict(py, cookies)
}

/// Extract Cookies from LibreWolf browser
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn librewolf(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py.detach(|| rookie_core::librewolf(domains))?;
  to_dict(py, cookies)
}

/// Extract Cookies from Google Chrome browser
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn chrome(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py.detach(|| rookie_core::chrome(domains))?;
  to_dict(py, cookies)
}

/// Extract Cookies from Arc browser
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn arc(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py.detach(|| rookie_core::arc(domains))?;
  to_dict(py, cookies)
}

/// Extract Cookies from Brave browser
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn brave(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py.detach(|| rookie_core::brave(domains))?;
  to_dict(py, cookies)
}

/// Extract Cookies from Microsoft Edge browser
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn edge(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py.detach(|| rookie_core::edge(domains))?;
  to_dict(py, cookies)
}

/// Extract Cookies from Opera browser
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn opera(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py.detach(|| rookie_core::opera(domains))?;
  to_dict(py, cookies)
}

/// Extract Cookies from Opera GX browser
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn opera_gx(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py.detach(|| rookie_core::opera_gx(domains))?;
  to_dict(py, cookies)
}

/// Extract Cookies from Chromium browser
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn chromium(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py.detach(|| rookie_core::chromium(domains))?;
  to_dict(py, cookies)
}

/// Extract Cookies from Vivaldi browser
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn vivaldi(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py.detach(|| rookie_core::vivaldi(domains))?;
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
  let cookies = py.detach(|| rookie_core::firefox_based(PathBuf::from(&db_path), domains))?;
  to_dict(py, cookies)
}

/// Load Cookies from a browser
///
/// :param domains: Optional list of domains to load cookies from
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
pub fn load(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py.detach(|| rookie_core::load(domains))?;
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
  let cookies = py.detach(|| rookie_core::octo_browser(domains))?;
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
  let cookies = py.detach(|| rookie_core::internet_explorer(domains))?;
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
  let cookies = py.detach(|| {
    rookie_core::chromium_based(
      PathBuf::from(&key_path),
      PathBuf::from(&db_path),
      domains,
      false,
    )
  })?;
  to_dict(py, cookies)
}

/// Extract Cookies from Safari browser
///
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (domains=None))]
#[cfg(target_os = "macos")]
pub fn safari(py: Python<'_>, domains: Option<Vec<String>>) -> PyResult<Vec<Py<PyAny>>> {
  let cookies = py.detach(|| rookie_core::safari(domains))?;
  to_dict(py, cookies)
}

/// Extract Cookies from Chromium-based browsers
///
/// :param db_path: Path to the database file
/// :param domains: Optional list of domains to extract only from them
/// :return: A list of dictionaries of cookies
#[pyfunction]
#[pyo3(signature = (db_path, domains=None))]
#[cfg(unix)]
pub fn chromium_based(
  py: Python<'_>,
  db_path: String,
  domains: Option<Vec<String>>,
) -> PyResult<Vec<Py<PyAny>>> {
  use rookie_core::config::Browser;

  let config = Browser {
    channels: None,
    paths: vec![db_path.clone()],
    unix_crypt_name: Some("chrome".to_string()),
    osx_key_service: None,
    osx_key_user: None,
  };
  let cookies =
    py.detach(|| rookie_core::chromium_based(&config, PathBuf::from(&db_path), domains, false))?;
  to_dict(py, cookies)
}
