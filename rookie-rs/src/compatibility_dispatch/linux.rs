use std::path::PathBuf;

use anyhow::bail;

use super::LoadFn;
use crate::{Cookie, Result};

pub(super) fn extend_legacy_load_browsers(browser_types: &mut Vec<(&'static str, LoadFn)>) {
  browser_types.push(("chrome", super::named::chrome));
  browser_types.push(("cachy", super::named::cachy));
}

pub(super) fn opera_gx(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let _ = domains;
  bail!("Opera GX is not supported on Linux")
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
  _cookies_path: PathBuf,
  _domains: Option<Vec<String>>,
  _runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  bail!("Safari binary cookie files are only supported on macOS")
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
  fn chromium_bridge_forwards_owned_path_and_domains() {
    let path = PathBuf::from("/tmp/Cookies");
    let domains = Some(vec!["example.test".to_owned()]);
    chromium_from_path_with(
      path.clone(),
      domains.clone(),
      |actual_path, actual_domains| {
        assert_eq!(actual_path, path);
        assert_eq!(actual_domains, domains);
        Ok(Vec::new())
      },
    )
    .expect("injected Chromium query");
  }

  #[test]
  fn opera_gx_keeps_exact_linux_error() {
    assert_eq!(
      opera_gx(None).unwrap_err().to_string(),
      "Opera GX is not supported on Linux"
    );
  }
}
