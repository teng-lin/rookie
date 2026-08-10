//! End-to-end test: extracts cookies from a real Chrome profile that was
//! seeded by `tests/e2e/seed_chromium_cookie.mjs` and asserts the seeded
//! `rookie_ci=bar` cookie is recovered with the OS-encrypted value intact.
//!
//! Driven by env vars so the seed step can hand the test a non-default
//! user-data-dir (Chrome refuses CDP/remote-debugging on its default
//! profile location, so the seed step cannot use it):
//!
//!   ROOKIE_E2E_USER_DATA_DIR  — required; absolute path passed to Chrome
//!                               via --user-data-dir
//!   ROOKIE_E2E_DOMAIN         — optional; domain filter for extraction
//!                               (default: "127.0.0.1")
//!
//! Ignored by default; CI runs them via
//! `cargo test --test e2e_chrome -- --ignored`.

mod helpers {
  use std::env;
  use std::path::PathBuf;

  pub fn resolve_db_path() -> PathBuf {
    let user_data_dir =
      env::var("ROOKIE_E2E_USER_DATA_DIR").expect("ROOKIE_E2E_USER_DATA_DIR must be set");
    // Modern Chrome writes to Default/Network/Cookies; older builds wrote
    // straight to Default/Cookies. Probe both before giving up so the test
    // is insensitive to Chrome's profile-layout migration.
    let default_dir = PathBuf::from(&user_data_dir).join("Default");
    ["Network/Cookies", "Cookies"]
      .iter()
      .map(|rel| default_dir.join(rel))
      .find(|p| p.exists())
      .unwrap_or_else(|| {
        panic!(
          "no cookie db found under {} (tried Default/Network/Cookies and Default/Cookies)",
          default_dir.display()
        )
      })
  }

  #[cfg(target_os = "windows")]
  pub fn resolve_key_path() -> PathBuf {
    let user_data_dir =
      env::var("ROOKIE_E2E_USER_DATA_DIR").expect("ROOKIE_E2E_USER_DATA_DIR must be set");
    PathBuf::from(&user_data_dir).join("Local State")
  }

  pub fn domain() -> String {
    env::var("ROOKIE_E2E_DOMAIN").unwrap_or_else(|_| "127.0.0.1".to_string())
  }

  pub fn assert_seeded(cookies: &[rookie_cookies::enums::Cookie], domain: &str) {
    let seeded = cookies
      .iter()
      .find(|c| c.name == "rookie_ci")
      .unwrap_or_else(|| {
        panic!(
          "seeded cookie `rookie_ci` not found among {} cookies for domain {}",
          cookies.len(),
          domain
        )
      });
    assert_eq!(seeded.value, "bar", "cookie value mismatch");
  }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore]
fn extracts_seeded_cookie_from_chrome_libsecret_profile() {
  let db_path = helpers::resolve_db_path();
  let domain = helpers::domain();

  let config = rookie_cookies::config::Browser {
    channels: None,
    paths: vec![db_path.to_string_lossy().into_owned()],
    unix_crypt_name: Some("chrome".to_string()),
    osx_key_service: None,
    osx_key_user: None,
  };

  let cookies =
    rookie_cookies::chromium_based(&config, db_path.clone(), Some(vec![domain.clone()]), false)
      .unwrap_or_else(|e| {
        panic!(
          "rookie_cookies::chromium_based({}) failed: {e}",
          db_path.display()
        )
      });

  helpers::assert_seeded(&cookies, &domain);
}

#[cfg(target_os = "macos")]
#[test]
#[ignore]
fn extracts_seeded_cookie_from_chrome_mock_keychain_profile() {
  let db_path = helpers::resolve_db_path();
  let domain = helpers::domain();

  let config = rookie_cookies::config::Browser {
    channels: None,
    paths: vec![db_path.to_string_lossy().into_owned()],
    unix_crypt_name: None,
    osx_key_service: None,
    osx_key_user: None,
  };

  let cookies =
    rookie_cookies::chromium_based(&config, db_path.clone(), Some(vec![domain.clone()]), false)
      .unwrap_or_else(|e| {
        panic!(
          "rookie_cookies::chromium_based({}) failed: {e}",
          db_path.display()
        )
      });

  helpers::assert_seeded(&cookies, &domain);
}

#[cfg(target_os = "windows")]
#[test]
#[ignore]
fn extracts_seeded_cookie_from_chrome_dpapi_profile() {
  let db_path = helpers::resolve_db_path();
  let key_path = helpers::resolve_key_path();
  let domain = helpers::domain();

  let cookies =
    rookie_cookies::chromium_based(key_path, db_path.clone(), Some(vec![domain.clone()]), false)
      .unwrap_or_else(|e| {
        panic!(
          "rookie_cookies::chromium_based({}) failed: {e}",
          db_path.display()
        )
      });

  helpers::assert_seeded(&cookies, &domain);
}
