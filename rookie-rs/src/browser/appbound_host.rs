use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

/// Which Windows process may call IElevator.DecryptData for an App-Bound key.
///
/// This is a required host identity, not a hint. Guessing the first installed
/// Chromium browser decrypts the wrong vendor's blob (`kValidationDidNotPass`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AppBoundHost {
  /// A known Chromium vendor: `chrome`, `brave`, `edge`, `coccoc`, or `avast`.
  Browser(String),
  /// An explicit browser executable to spawn for COM injection.
  #[allow(dead_code)] // constructed on Windows when a caller supplies an exe path
  Executable(PathBuf),
}

impl AppBoundHost {
  pub(crate) fn from_browser_id(id: &str) -> Option<Self> {
    canonical_browser_id(id).map(|id| Self::Browser(id.to_string()))
  }
}

/// Maps a caller-supplied name or alias onto a canonical App-Bound vendor id.
pub(crate) fn canonical_browser_id(name: &str) -> Option<&'static str> {
  match name.to_ascii_lowercase().as_str() {
    "google-chrome" | "google_chrome" | "chrome" | "chromium" => Some("chrome"),
    "brave" | "brave-browser" => Some("brave"),
    "edge" | "msedge" | "microsoft-edge" => Some("edge"),
    "coccoc" | "coc_coc" => Some("coccoc"),
    "avast" | "avastbrowser" => Some("avast"),
    _ => None,
  }
}

/// Infers an App-Bound host from a Local State or user-data path.
///
/// Only known vendor layouts match. Unknown directories return `None` instead
/// of defaulting to Chrome.
pub(crate) fn infer_host_from_user_data_path(path: &Path) -> Option<AppBoundHost> {
  // Split on both separators so Windows layouts can be recognized when these
  // tests (and path-only callers) run on Unix.
  let components: Vec<String> = path
    .to_string_lossy()
    .split(['/', '\\'])
    .filter(|component| !component.is_empty())
    .map(|component| component.to_ascii_lowercase())
    .collect();

  for &(vendor, product_prefix, browser_id) in LAYOUTS {
    if contains_vendor_product(&components, vendor, product_prefix) {
      return Some(AppBoundHost::Browser(browser_id.to_string()));
    }
  }
  None
}

/// Resolves the App-Bound host from an explicit browser id, then the Local
/// State path. Never walks installed browsers.
pub(crate) fn resolve_appbound_host(
  browser_id: Option<&str>,
  local_state_path: Option<&Path>,
) -> Result<AppBoundHost> {
  if let Some(id) = browser_id {
    if let Some(host) = AppBoundHost::from_browser_id(id) {
      return Ok(host);
    }
  }
  if let Some(path) = local_state_path {
    if let Some(host) = infer_host_from_user_data_path(path) {
      return Ok(host);
    }
  }
  bail!(
    "App-Bound decryption requires a browser identity; \
     could not determine one from the supplied browser id and Local State path. \
     Use a named browser API or a Local State file under a known user-data directory"
  )
}

/// `(vendor path components, product-directory prefix, canonical browser id)`.
const LAYOUTS: &[(&[&str], &str, &str)] = &[
  (&["microsoft"], "edge", "edge"),
  (&["google"], "chrome", "chrome"),
  (&["bravesoftware"], "brave-browser", "brave"),
  (&["coccoc"], "browser", "coccoc"),
  (&["avast software"], "browser", "avast"),
];

fn contains_vendor_product(components: &[String], vendor: &[&str], product_prefix: &str) -> bool {
  let window_len = vendor.len() + 1;
  if components.len() < window_len {
    return false;
  }
  components.windows(window_len).any(|window| {
    window
      .iter()
      .zip(vendor.iter())
      .all(|(actual, expected)| actual == expected)
      && product_directory_matches(&window[vendor.len()], product_prefix)
  })
}

fn product_directory_matches(component: &str, prefix: &str) -> bool {
  component == prefix
    || component.starts_with(&format!("{prefix} "))
    || component.starts_with(&format!("{prefix}-"))
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::path::PathBuf;

  fn host_browser(id: &str) -> AppBoundHost {
    AppBoundHost::Browser(id.to_string())
  }

  #[test]
  fn aliases_map_to_canonical_ids() {
    assert_eq!(canonical_browser_id("msedge"), Some("edge"));
    assert_eq!(canonical_browser_id("google-chrome"), Some("chrome"));
    assert_eq!(canonical_browser_id("brave-browser"), Some("brave"));
    assert_eq!(canonical_browser_id("direct_path"), None);
    assert_eq!(canonical_browser_id("firefox"), None);
  }

  #[test]
  fn infers_edge_from_default_user_data_layout() {
    let path =
      PathBuf::from(r"C:\Users\runneradmin\AppData\Local\Microsoft\Edge\User Data\Local State");
    assert_eq!(
      infer_host_from_user_data_path(&path),
      Some(host_browser("edge"))
    );
  }

  #[test]
  fn infers_edge_channels_and_forward_slashes() {
    let path = PathBuf::from("/Users/me/AppData/Local/Microsoft/Edge Beta/User Data/Local State");
    assert_eq!(
      infer_host_from_user_data_path(&path),
      Some(host_browser("edge"))
    );
  }

  #[test]
  fn infers_chrome_brave_coccoc_and_avast() {
    assert_eq!(
      infer_host_from_user_data_path(Path::new(
        r"C:\Users\me\AppData\Local\Google\Chrome\User Data\Local State"
      )),
      Some(host_browser("chrome"))
    );
    assert_eq!(
      infer_host_from_user_data_path(Path::new(
        r"C:\Users\me\AppData\Local\BraveSoftware\Brave-Browser-Beta\User Data\Local State"
      )),
      Some(host_browser("brave"))
    );
    assert_eq!(
      infer_host_from_user_data_path(Path::new(
        r"C:\Users\me\AppData\Local\CocCoc\Browser\User Data\Local State"
      )),
      Some(host_browser("coccoc"))
    );
    assert_eq!(
      infer_host_from_user_data_path(Path::new(
        r"C:\Users\me\AppData\Local\AVAST Software\Browser\User Data\Local State"
      )),
      Some(host_browser("avast"))
    );
  }

  #[test]
  fn does_not_infer_chrome_from_unknown_or_adjacent_paths() {
    assert_eq!(
      infer_host_from_user_data_path(Path::new(
        r"D:\a\_temp\rookie-appbound-wal-4100\Local State"
      )),
      None
    );
    assert_eq!(
      infer_host_from_user_data_path(Path::new(
        r"C:\Users\me\AppData\Local\Microsoft\Edgehood\User Data\Local State"
      )),
      None
    );
    assert_eq!(
      infer_host_from_user_data_path(Path::new(
        r"C:\Users\me\AppData\Local\Chromium\User Data\Local State"
      )),
      None
    );
  }

  #[test]
  fn explicit_browser_id_wins_over_a_conflicting_path() {
    let chrome_path = Path::new(r"C:\Users\me\AppData\Local\Google\Chrome\User Data\Local State");
    assert_eq!(
      resolve_appbound_host(Some("edge"), Some(chrome_path)).expect("host"),
      host_browser("edge")
    );
  }

  #[test]
  fn unknown_id_falls_back_to_path_inference() {
    let edge_path = Path::new(r"C:\Users\me\AppData\Local\Microsoft\Edge\User Data\Local State");
    assert_eq!(
      resolve_appbound_host(Some("direct_path"), Some(edge_path)).expect("host"),
      host_browser("edge")
    );
  }

  #[test]
  fn missing_identity_is_an_error_not_chrome() {
    let error = resolve_appbound_host(Some("direct_path"), Some(Path::new(r"D:\tmp\Local State")))
      .expect_err("must not invent a host");
    let message = error.to_string();
    assert!(message.contains("requires a browser identity"), "{message}");
    assert!(
      !message.to_ascii_lowercase().contains("chrome.exe"),
      "{message}"
    );
  }
}
