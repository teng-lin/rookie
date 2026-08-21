use std::path::PathBuf;

use anyhow::{bail, Context};

use super::LoadFn;
use crate::Cookie;
use anyhow::Result;

pub(super) fn extend_legacy_load_browsers(browser_types: &mut Vec<(&'static str, LoadFn)>) {
  browser_types.push(("arc", super::named::arc));
  browser_types.push(("chrome", super::named::chrome));
  browser_types.push(("internet_explorer", super::named::internet_explorer));
  browser_types.push(("octo_browser", super::named::octo_browser));
  browser_types.push(("opera_gx", super::named::opera_gx));
}

pub(super) fn opera_gx(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  super::named::named_browser("opera_gx", domains)
}

pub(super) fn chromium_from_path(
  cookies_path: PathBuf,
  domains: Option<Vec<String>>,
  key_path: Option<&str>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  let key_path = key_path.context(
    "a Chromium Local State key file is required for a Chromium cookie database on Windows",
  )?;
  crate::direct_path::legacy_windows_chromium_with_runtime(
    PathBuf::from(key_path),
    cookies_path,
    domains,
    false,
    runtime,
  )
}

#[cfg(test)]
fn chromium_from_path_with<F>(
  cookies_path: PathBuf,
  domains: Option<Vec<String>>,
  key_path: Option<&str>,
  query: F,
) -> Result<Vec<Cookie>>
where
  F: FnOnce(PathBuf, PathBuf, Option<Vec<String>>, bool) -> Result<Vec<Cookie>>,
{
  let key_path = key_path.context(
    "a Chromium Local State key file is required for a Chromium cookie database on Windows",
  )?;
  query(PathBuf::from(key_path), cookies_path, domains, false)
}

pub(super) fn safari_from_path(
  _cookies_path: PathBuf,
  _domains: Option<Vec<String>>,
  _runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  bail!("Safari binary cookie files are only supported on macOS")
}

pub(super) fn internet_explorer_from_path(
  cookies_path: PathBuf,
  domains: Option<Vec<String>>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  crate::browser::internet_explorer::internet_explorer_based_with_runtime(
    cookies_path,
    domains,
    false,
    runtime,
  )
}

#[cfg(test)]
fn internet_explorer_from_path_with<F>(
  cookies_path: PathBuf,
  domains: Option<Vec<String>>,
  query: F,
) -> Result<Vec<Cookie>>
where
  F: FnOnce(PathBuf, Option<Vec<String>>, bool) -> Result<Vec<Cookie>>,
{
  query(cookies_path, domains, false)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn chromium_bridge_validates_key_then_forwards_inputs_non_disruptively() {
    let cookies_path = PathBuf::from(r"C:\profile\Cookies");
    let key_path = r"C:\profile\Local State";
    let domains = Some(vec!["example.test".to_owned()]);
    chromium_from_path_with(
      cookies_path.clone(),
      domains.clone(),
      Some(key_path),
      |actual_key_path, actual_cookies_path, actual_domains, force_kill| {
        assert_eq!(actual_key_path, PathBuf::from(key_path));
        assert_eq!(actual_cookies_path, cookies_path);
        assert_eq!(actual_domains, domains);
        assert!(!force_kill);
        Ok(Vec::new())
      },
    )
    .expect("injected Chromium query");

    let error = chromium_from_path_with(
      PathBuf::from(r"C:\profile\Cookies"),
      None,
      None,
      |_, _, _, _| panic!("missing key must fail before querying"),
    )
    .expect_err("Windows Chromium requires Local State");
    assert_eq!(
      error.to_string(),
      "a Chromium Local State key file is required for a Chromium cookie database on Windows"
    );
  }

  #[test]
  fn internet_explorer_bridge_forwards_inputs_non_disruptively() {
    let cookies_path = PathBuf::from(r"C:\profile\WebCacheV01.dat");
    let domains = Some(vec!["example.test".to_owned()]);
    internet_explorer_from_path_with(
      cookies_path.clone(),
      domains.clone(),
      |actual_path, actual_domains, force_kill| {
        assert_eq!(actual_path, cookies_path);
        assert_eq!(actual_domains, domains);
        assert!(!force_kill);
        Ok(Vec::new())
      },
    )
    .expect("injected Internet Explorer query");
  }
}
