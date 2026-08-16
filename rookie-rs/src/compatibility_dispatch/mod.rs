//! Target-selected routing for deprecated crate-root compatibility APIs.

use std::path::PathBuf;

use crate::{Cookie, Result};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as platform;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as platform;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows as platform;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod unsupported;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
use unsupported as platform;

pub(super) type LoadFn = fn(Option<Vec<String>>) -> Result<Vec<Cookie>>;

/// The legacy `load` probe order is observable through cookie ordering and
/// warning output. Keep construction separate from extraction so platform CI
/// can pin the exact browser set without probing browsers installed on a host.
pub(super) fn legacy_load_browsers() -> Vec<(&'static str, LoadFn)> {
  let mut browser_types: Vec<(&'static str, LoadFn)> = vec![
    ("firefox", crate::firefox),
    ("zen", crate::zen),
    ("librewolf", crate::librewolf),
    ("opera", crate::opera),
    ("edge", crate::edge),
    ("chromium", crate::chromium),
    ("brave", crate::brave),
    ("vivaldi", crate::vivaldi),
    ("arc", crate::arc),
  ];
  platform::extend_legacy_load_browsers(&mut browser_types);
  browser_types
}

pub(super) fn opera_gx(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  platform::opera_gx(domains)
}

pub(super) fn any_browser(
  cookies_path: &str,
  domains: Option<Vec<String>>,
  key_path: Option<&str>,
) -> Result<Vec<Cookie>> {
  let cookies_path = PathBuf::from(cookies_path);
  match crate::direct_path::classify_cookie_source_legacy(&cookies_path)? {
    crate::direct_path::CookieSourceKind::MozillaSqlite => {
      crate::firefox_based(cookies_path, domains)
    }
    crate::direct_path::CookieSourceKind::ChromiumSqlite => {
      platform::chromium_from_path(cookies_path, domains, key_path)
    }
    crate::direct_path::CookieSourceKind::SafariBinaryCookies => {
      platform::safari_from_path(cookies_path, domains)
    }
    crate::direct_path::CookieSourceKind::InternetExplorerEse => {
      platform::internet_explorer_from_path(cookies_path, domains)
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn source_test_path(tag: &str) -> (crate::utils::TempDir, PathBuf) {
    let directory = crate::utils::TempDir::new().expect("temporary source directory");
    let path = directory.path().join(tag);
    (directory, path)
  }

  #[test]
  fn legacy_load_browser_set_and_order_are_stable_for_this_platform() {
    let names: Vec<_> = legacy_load_browsers()
      .into_iter()
      .map(|(name, _)| name)
      .collect();

    #[cfg(target_os = "linux")]
    assert_eq!(
      names,
      vec![
        "firefox",
        "zen",
        "librewolf",
        "opera",
        "edge",
        "chromium",
        "brave",
        "vivaldi",
        "arc",
        "chrome",
        "cachy",
      ]
    );

    #[cfg(target_os = "macos")]
    assert_eq!(
      names,
      vec![
        "firefox",
        "zen",
        "librewolf",
        "opera",
        "edge",
        "chromium",
        "brave",
        "vivaldi",
        "arc",
        "chrome",
        "opera_gx",
        "safari",
      ]
    );

    #[cfg(target_os = "windows")]
    assert_eq!(
      names,
      vec![
        "firefox",
        "zen",
        "librewolf",
        "opera",
        "edge",
        "chromium",
        "brave",
        "vivaldi",
        "arc",
        "chrome",
        "internet_explorer",
        "octo_browser",
        "opera_gx",
      ]
    );

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    assert_eq!(
      names,
      vec![
        "firefox",
        "zen",
        "librewolf",
        "opera",
        "edge",
        "chromium",
        "brave",
        "vivaldi",
        "arc",
      ]
    );
  }

  #[test]
  fn classification_precedes_platform_option_validation() {
    let (_directory, path) = source_test_path("unknown.cookies");
    std::fs::write(&path, b"not a cookie store").expect("unknown fixture");
    let error = any_browser(path.to_str().expect("UTF-8 test path"), None, None)
      .expect_err("classification fails before target-specific validation");
    assert_eq!(
      error.to_string(),
      format!("unsupported cookie source format: {}", path.display())
    );
  }

  #[test]
  fn mozilla_routing_remains_portable() {
    let (_directory, path) = source_test_path("cookies.sqlite");
    let connection = rusqlite::Connection::open(&path).expect("Mozilla fixture");
    connection
      .execute_batch(
        "CREATE TABLE moz_cookies (
           host TEXT NOT NULL, path TEXT NOT NULL, isSecure INTEGER NOT NULL,
           expiry INTEGER NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
           isHttpOnly INTEGER NOT NULL, sameSite INTEGER NOT NULL
         );
         INSERT INTO moz_cookies VALUES
           ('.example.test', '/', 1, 0, 'portable', 'mozilla', 1, 0);",
      )
      .expect("seed Mozilla fixture");
    drop(connection);

    let cookies = any_browser(path.to_str().expect("UTF-8 test path"), None, None)
      .expect("Mozilla extraction is portable");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "portable");
    assert_eq!(cookies[0].value, "mozilla");
  }

  #[cfg(not(target_os = "windows"))]
  #[test]
  fn public_ie_routing_keeps_legacy_classifier_precedence() {
    let (_directory, path) = source_test_path("WebCacheV01.dat");
    std::fs::write(&path, [0, 0, 0, 0, 0xef, 0xcd, 0xab, 0x89]).expect("ESE signature fixture");
    let error = any_browser(path.to_str().expect("UTF-8 test path"), None, None)
      .expect_err("legacy non-Windows classification rejects ESE");
    assert_eq!(
      error.to_string(),
      format!("unsupported cookie source format: {}", path.display())
    );
  }

  #[cfg(not(target_os = "macos"))]
  #[test]
  fn public_safari_routing_keeps_exact_wrong_target_error() {
    let (_directory, path) = source_test_path("Cookies.binarycookies");
    std::fs::write(&path, b"cooksynthetic").expect("Safari fixture");
    let domains = Some(vec!["example.test".to_owned()]);
    let error = any_browser(
      path.to_str().expect("UTF-8 test path"),
      domains,
      Some("ignored Local State"),
    )
    .expect_err("Safari extraction is unavailable");
    assert_eq!(
      error.to_string(),
      "Safari binary cookie files are only supported on macOS"
    );
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
  #[test]
  fn unsupported_public_routing_keeps_exact_legacy_errors() {
    let (_chromium_directory, chromium_path) = source_test_path("Cookies");
    let chromium = rusqlite::Connection::open(&chromium_path).expect("Chromium fixture");
    chromium
      .execute("CREATE TABLE cookies (name TEXT)", [])
      .expect("Chromium schema");
    drop(chromium);
    let chromium_error = any_browser(chromium_path.to_str().expect("UTF-8 test path"), None, None)
      .expect_err("Chromium extraction is unavailable");
    assert_eq!(
      chromium_error.to_string(),
      "Chromium cookie extraction is unsupported on this Unix platform"
    );

    let (_safari_directory, safari_path) = source_test_path("Cookies.binarycookies");
    std::fs::write(&safari_path, b"cooksynthetic").expect("Safari fixture");
    let safari_error = any_browser(safari_path.to_str().expect("UTF-8 test path"), None, None)
      .expect_err("Safari extraction is unavailable");
    assert_eq!(
      safari_error.to_string(),
      "Safari binary cookie files are only supported on macOS"
    );

    assert_eq!(
      crate::opera_gx(None).unwrap_err().to_string(),
      format!("Opera GX is not supported on {}", std::env::consts::OS)
    );
  }
}
