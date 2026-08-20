use std::path::PathBuf;

use anyhow::bail;

use super::LoadFn;
use crate::Cookie;
use anyhow::Result;

pub(super) fn extend_legacy_load_browsers(browser_types: &mut Vec<(&'static str, LoadFn)>) {
  browser_types.push(("chrome", super::named::chrome));
  browser_types.push(("opera_gx", super::named::opera_gx));
  browser_types.push(("safari", super::named::safari));
}

pub(super) fn opera_gx(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  super::named::named_browser("opera_gx", domains)
}

pub(super) fn chromium_from_path(
  cookies_path: PathBuf,
  domains: Option<Vec<String>>,
  _key_path: Option<&str>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  crate::direct_path::legacy_automatic_chromium_with_runtime(cookies_path, domains, runtime)
}

#[cfg(test)]
fn chromium_from_path_with<F>(
  cookies_path: PathBuf,
  domains: Option<Vec<String>>,
  query: F,
) -> Result<Vec<Cookie>>
where
  F: FnOnce(PathBuf, Option<Vec<String>>) -> Result<Vec<Cookie>>,
{
  query(cookies_path, domains)
}

pub(super) fn safari_from_path(
  cookies_path: PathBuf,
  domains: Option<Vec<String>>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  crate::browser::safari::safari_based_with_runtime(cookies_path, domains, runtime)
}

#[cfg(test)]
fn safari_from_path_with<F>(
  cookies_path: PathBuf,
  domains: Option<Vec<String>>,
  query: F,
) -> Result<Vec<Cookie>>
where
  F: FnOnce(PathBuf, Option<Vec<String>>) -> Result<Vec<Cookie>>,
{
  query(cookies_path, domains)
}

pub(super) fn internet_explorer_from_path(
  _cookies_path: PathBuf,
  _domains: Option<Vec<String>>,
  _runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  bail!("Internet Explorer WebCache files are only supported on Windows")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn chromium_and_safari_bridges_forward_owned_inputs() {
    let chromium_path = PathBuf::from("/tmp/Cookies");
    let chromium_domains = Some(vec!["chromium.test".to_owned()]);
    chromium_from_path_with(
      chromium_path.clone(),
      chromium_domains.clone(),
      |actual_path, actual_domains| {
        assert_eq!(actual_path, chromium_path);
        assert_eq!(actual_domains, chromium_domains);
        Ok(Vec::new())
      },
    )
    .expect("injected Chromium query");

    let safari_path = PathBuf::from("/tmp/Cookies.binarycookies");
    let safari_domains = Some(vec!["safari.test".to_owned()]);
    safari_from_path_with(
      safari_path.clone(),
      safari_domains.clone(),
      |actual_path, actual_domains| {
        assert_eq!(actual_path, safari_path);
        assert_eq!(actual_domains, safari_domains);
        Ok(Vec::new())
      },
    )
    .expect("injected Safari query");
  }

  #[test]
  fn safari_from_path_reports_a_missing_file_as_an_open_failure() {
    let clock = crate::common::deadline::SystemClock;
    let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
    let directory = crate::utils::TempDir::new().unwrap();
    let missing = directory.path().join("Cookies.binarycookies");
    let error = safari_from_path(missing, None, &runtime).unwrap_err();
    let io_error = error
      .chain()
      .find_map(|cause| cause.downcast_ref::<std::io::Error>())
      .expect("a missing file must surface a std::io::Error in the chain");
    assert_eq!(io_error.kind(), std::io::ErrorKind::NotFound);
  }

  #[test]
  fn internet_explorer_from_path_is_unsupported_off_windows() {
    let clock = crate::common::deadline::SystemClock;
    let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
    let error = internet_explorer_from_path(PathBuf::from("/tmp/WebCacheV01.dat"), None, &runtime)
      .unwrap_err();
    assert_eq!(
      error.to_string(),
      "Internet Explorer WebCache files are only supported on Windows"
    );
  }
}
