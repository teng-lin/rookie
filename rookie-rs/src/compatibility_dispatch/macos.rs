use std::path::PathBuf;

use anyhow::bail;

use super::LoadFn;
use crate::{Cookie, Result};

pub(super) fn extend_legacy_load_browsers(browser_types: &mut Vec<(&'static str, LoadFn)>) {
  browser_types.push(("chrome", crate::chrome));
  browser_types.push(("opera_gx", crate::opera_gx));
  browser_types.push(("safari", crate::safari));
}

pub(super) fn opera_gx(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  crate::named_browser("opera_gx", domains)
}

pub(super) fn chromium_from_path(
  cookies_path: PathBuf,
  domains: Option<Vec<String>>,
  _key_path: Option<&str>,
) -> Result<Vec<Cookie>> {
  chromium_from_path_with(
    cookies_path,
    domains,
    crate::direct_path::legacy_automatic_chromium,
  )
}

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
) -> Result<Vec<Cookie>> {
  safari_from_path_with(cookies_path, domains, crate::safari_based)
}

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
}
