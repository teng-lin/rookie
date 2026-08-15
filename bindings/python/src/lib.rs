use ::rookie_cookies as rookie_core;
use log::LevelFilter;
use pyo3::{prelude::*, types::PyDict};
use pyo3_log::{Caching, Logger};
use rookie_core::enums::{Cookie, DetailedCookie};
mod browsers;
mod report;
use browsers::*;
use report::{
  browser_profiles, browser_report, chrome_profile, chrome_profiles, load_report,
  supported_browsers,
};

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

  m.add_function(wrap_pyfunction!(chromium, m)?)?;
  m.add_function(wrap_pyfunction!(vivaldi, m)?)?;
  m.add_function(wrap_pyfunction!(arc, m)?)?;
  m.add_function(wrap_pyfunction!(chromium_based, m)?)?;
  m.add_function(wrap_pyfunction!(chromium_based_detailed, m)?)?;
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
