use log::LevelFilter;
use pyo3::{prelude::*, types::PyDict};
use pyo3_log::{Caching, Logger};
use rookie_core::enums::Cookie;
mod browsers;
mod report;
use browsers::*;
use report::{browser_profiles, browser_report, load_report, supported_browsers};

#[pyfunction]
fn version() -> PyResult<String> {
  Ok(rookie_core::version())
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
  m.add_function(wrap_pyfunction!(opera_gx, m)?)?;

  m.add_function(wrap_pyfunction!(chromium, m)?)?;
  m.add_function(wrap_pyfunction!(vivaldi, m)?)?;
  m.add_function(wrap_pyfunction!(arc, m)?)?;
  m.add_function(wrap_pyfunction!(chromium_based, m)?)?;
  m.add_function(wrap_pyfunction!(firefox_based, m)?)?;
  m.add_function(wrap_pyfunction!(load, m)?)?;
  m.add_function(wrap_pyfunction!(any_browser, m)?)?;

  // An issue counts every occurrence but keeps at most this many samples, so a
  // caller comparing the two needs the cap to tell truncation from completeness.
  m.add("MAX_ISSUE_SAMPLES", rookie_core::report::MAX_ISSUE_SAMPLES)?;
  m.add_function(wrap_pyfunction!(supported_browsers, m)?)?;
  m.add_function(wrap_pyfunction!(browser_profiles, m)?)?;
  m.add_function(wrap_pyfunction!(browser_report, m)?)?;
  m.add_function(wrap_pyfunction!(load_report, m)?)?;

  #[cfg(target_os = "windows")]
  {
    m.add_function(wrap_pyfunction!(internet_explorer, m)?)?;
    m.add_function(wrap_pyfunction!(octo_browser, m)?)?;
  }
  #[cfg(target_os = "macos")]
  {
    m.add_function(wrap_pyfunction!(safari, m)?)?;
  }

  m.add_function(wrap_pyfunction!(version, m)?)?;
  Ok(())
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
