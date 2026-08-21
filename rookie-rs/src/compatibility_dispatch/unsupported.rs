use std::path::PathBuf;

use anyhow::bail;

use super::LoadFn;
use crate::{common::deadline::BoundaryRuntime, Cookie};
use anyhow::Result;

pub(super) fn extend_legacy_load_browsers(_browser_types: &mut Vec<(&'static str, LoadFn)>) {}

pub(super) fn opera_gx(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let _ = domains;
  bail!("Opera GX is not supported on {}", std::env::consts::OS)
}

pub(super) fn chromium_from_path(
  _cookies_path: PathBuf,
  _domains: Option<Vec<String>>,
  _key_path: Option<&str>,
  _runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  bail!("Chromium cookie extraction is unsupported on this Unix platform")
}

pub(super) fn safari_from_path(
  _cookies_path: PathBuf,
  _domains: Option<Vec<String>>,
  _runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  bail!("Safari binary cookie files are only supported on macOS")
}

pub(super) fn internet_explorer_from_path(
  _cookies_path: PathBuf,
  _domains: Option<Vec<String>>,
  _runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  bail!("Internet Explorer WebCache files are only supported on Windows")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn unsupported_leaf_keeps_exact_legacy_errors() {
    let clock = crate::common::deadline::SystemClock;
    let runtime = BoundaryRuntime::standard(&clock);
    assert_eq!(
      opera_gx(None).unwrap_err().to_string(),
      format!("Opera GX is not supported on {}", std::env::consts::OS)
    );
    assert_eq!(
      chromium_from_path(PathBuf::from("Cookies"), None, None, &runtime)
        .unwrap_err()
        .to_string(),
      "Chromium cookie extraction is unsupported on this Unix platform"
    );
    assert_eq!(
      safari_from_path(PathBuf::from("Cookies.binarycookies"), None, &runtime)
        .unwrap_err()
        .to_string(),
      "Safari binary cookie files are only supported on macOS"
    );
    assert_eq!(
      internet_explorer_from_path(PathBuf::from("WebCacheV01.dat"), None, &runtime)
        .unwrap_err()
        .to_string(),
      "Internet Explorer WebCache files are only supported on Windows"
    );
  }
}
