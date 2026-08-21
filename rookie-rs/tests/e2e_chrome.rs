#![allow(deprecated)]

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
//!   ROOKIE_E2E_COOKIE_NAME    — optional; expected name (default: "rookie_ci")
//!   ROOKIE_E2E_COOKIE_VALUE   — optional; expected value (default: "bar")
//!
//! The real-browser tests are ignored by default; CI runs them via
//! `cargo test --test e2e_chrome -- --ignored`.
//!
//! On Windows this target also has a non-ignored, deterministic legacy-DPAPI
//! test. It creates Local State and Cookies fixtures for the current user, so
//! it needs neither Chrome nor a pre-existing profile.

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod helpers {
  use std::env;
  use std::path::PathBuf;

  pub fn resolve_db_path() -> PathBuf {
    if let Some(path) = env::var_os("ROOKIE_E2E_COOKIE_DB") {
      return PathBuf::from(path);
    }
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
    let expected_name =
      env::var("ROOKIE_E2E_COOKIE_NAME").unwrap_or_else(|_| "rookie_ci".to_string());
    let expected_value = env::var("ROOKIE_E2E_COOKIE_VALUE").unwrap_or_else(|_| "bar".to_string());
    let seeded = cookies
      .iter()
      .find(|c| c.name == expected_name)
      .unwrap_or_else(|| {
        panic!(
          "seeded cookie `{}` not found among {} cookies for domain {}",
          expected_name,
          cookies.len(),
          domain
        )
      });
    assert_eq!(seeded.value, expected_value, "cookie value mismatch");
  }

  #[cfg(target_os = "windows")]
  pub fn assert_discovered(cookies: &[rookie_cookies::enums::Cookie], domain: &str) {
    let expected_name =
      env::var("ROOKIE_E2E_DISCOVERY_COOKIE_NAME").unwrap_or_else(|_| "rookie_ci".to_string());
    let expected_value =
      env::var("ROOKIE_E2E_DISCOVERY_COOKIE_VALUE").unwrap_or_else(|_| "bar".to_string());
    let seeded = cookies
      .iter()
      .find(|cookie| cookie.name == expected_name)
      .unwrap_or_else(|| {
        panic!(
          "discovered cookie `{}` not found among {} cookies for domain {}",
          expected_name,
          cookies.len(),
          domain
        )
      });
    assert_eq!(seeded.value, expected_value, "cookie value mismatch");
  }
}

#[cfg(target_os = "windows")]
mod deterministic_dpapi {
  use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
  };
  use base64::{engine::general_purpose, Engine as _};
  use rand::RngCore;
  use std::ffi::c_void;
  use std::path::{Path, PathBuf};
  use std::ptr;
  use std::sync::atomic::{AtomicU64, Ordering};
  use windows::Win32::Security::Cryptography::{
    CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
  };

  #[link(name = "kernel32")]
  extern "system" {
    fn LocalFree(hmem: *mut c_void) -> *mut c_void;
  }

  pub struct Fixture {
    root: PathBuf,
    pub local_state: PathBuf,
    pub cookies_db: PathBuf,
  }

  impl Drop for Fixture {
    fn drop(&mut self) {
      let _ = std::fs::remove_dir_all(&self.root);
    }
  }

  fn unique_tmpdir() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
      "rookie DPAPI e2e ünicode-{}-{}",
      std::process::id(),
      n
    ));
    std::fs::create_dir_all(&dir).expect("create fixture directory");
    dir
  }

  fn protect_for_current_user(plaintext: &[u8]) -> Vec<u8> {
    let input = CRYPT_INTEGER_BLOB {
      cbData: plaintext.len() as u32,
      pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
      cbData: 0,
      pbData: ptr::null_mut(),
    };

    unsafe {
      CryptProtectData(
        &input,
        windows::core::PCWSTR::null(),
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        &mut output,
      )
      .expect("CryptProtectData for the current user");
    }
    assert!(!output.pbData.is_null(), "CryptProtectData returned null");

    let protected =
      unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    let free_result = unsafe { LocalFree(output.pbData.cast()) };
    assert!(free_result.is_null(), "LocalFree failed");
    protected
  }

  fn write_local_state(path: &Path, aes_key: &[u8; 32]) {
    let protected = protect_for_current_user(aes_key);
    let mut chrome_key = b"DPAPI".to_vec();
    chrome_key.extend_from_slice(&protected);
    let state = serde_json::json!({
      "os_crypt": {
        "encrypted_key": general_purpose::STANDARD.encode(chrome_key)
      },
      "profile": { "last_used": "Default" }
    });
    std::fs::write(path, serde_json::to_vec_pretty(&state).unwrap()).expect("write Local State");
  }

  fn write_cookie_db(path: &Path, aes_key: &[u8; 32]) {
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(aes_key).expect("32-byte AES key");
    let ciphertext = cipher
      .encrypt(Nonce::from_slice(&nonce_bytes), b"bar".as_ref())
      .expect("encrypt v10 cookie");
    let mut encrypted_value = b"v10".to_vec();
    encrypted_value.extend_from_slice(&nonce_bytes);
    encrypted_value.extend_from_slice(&ciphertext);

    let connection = rusqlite::Connection::open(path).expect("create Cookies db");
    connection
      .execute_batch(
        "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);\
         INSERT INTO meta (key, value) VALUES ('version', '23');\
         CREATE TABLE cookies (\
           host_key TEXT NOT NULL, path TEXT NOT NULL, is_secure INTEGER NOT NULL,\
           expires_utc INTEGER NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,\
           encrypted_value BLOB, is_httponly INTEGER NOT NULL, samesite INTEGER NOT NULL\
         );",
      )
      .expect("create Chromium schema");
    connection
      .execute(
        "INSERT INTO cookies (host_key, path, is_secure, expires_utc, name, value,\
          encrypted_value, is_httponly, samesite)\
         VALUES (?1, ?2, ?3, ?4, ?5, 'plaintext sentinel must not escape', ?6, ?7, ?8)",
        rusqlite::params![
          ".example.test",
          "/",
          false,
          11_644_473_600_000_000u64 + 1_900_000_000u64 * 1_000_000,
          "rookie_ci",
          encrypted_value,
          true,
          1i64,
        ],
      )
      .expect("insert encrypted cookie");
  }

  pub fn create() -> Fixture {
    let root = unique_tmpdir();
    let network = root.join("Default/Network");
    std::fs::create_dir_all(&network).expect("create Chromium profile layout");
    let local_state = root.join("Local State");
    let cookies_db = network.join("Cookies");

    let mut aes_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut aes_key);
    write_local_state(&local_state, &aes_key);
    write_cookie_db(&cookies_db, &aes_key);

    Fixture {
      root,
      local_state,
      cookies_db,
    }
  }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore]
fn extracts_seeded_cookie_from_chrome_libsecret_profile() {
  let db_path = helpers::resolve_db_path();
  let domain = helpers::domain();
  let browser_id = std::env::var("ROOKIE_E2E_BROWSER_ID").unwrap_or_else(|_| "chrome".to_owned());
  let config = rookie_cookies::config::get_browser_config(&browser_id);

  let cookies =
    rookie_cookies::chromium_based(config, db_path.clone(), Some(vec![domain.clone()]), false)
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
fn extracts_seeded_cookie_through_real_macos_keychain_provider() {
  let db_path = helpers::resolve_db_path();
  let domain = helpers::domain();
  let browser_id = std::env::var("ROOKIE_E2E_BROWSER_ID").unwrap_or_else(|_| "chrome".to_owned());
  let config = rookie_cookies::config::get_browser_config(&browser_id);

  let cookies =
    rookie_cookies::chromium_based(config, db_path.clone(), Some(vec![domain.clone()]), false)
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

#[cfg(target_os = "windows")]
#[test]
#[ignore]
fn extracts_seeded_cookie_via_injection_only() {
  // The bridge function below carries `AllowElevatedFallback`; the steering
  // variable narrows it to injection only. Narrowing is the only direction it
  // can move, and it is compiled in only for this suite (see the
  // `e2e-appbound-steering` feature).
  std::env::set_var("ROOKIE_E2E_APPBOUND_MODE", "injection_only");
  let db_path = helpers::resolve_db_path();
  let key_path = helpers::resolve_key_path();
  let domain = helpers::domain();

  let cookies =
    rookie_cookies::chromium_based(key_path, db_path.clone(), Some(vec![domain.clone()]), false)
      .unwrap_or_else(|e| panic!("rookie_cookies::chromium_based (injection_only) failed: {e}",));

  helpers::assert_seeded(&cookies, &domain);
}

#[cfg(target_os = "windows")]
#[test]
#[ignore]
fn extracts_seeded_cookie_via_elevated_fallback_only() {
  std::env::set_var("ROOKIE_E2E_APPBOUND_MODE", "elevated_only");
  let db_path = helpers::resolve_db_path();
  let key_path = helpers::resolve_key_path();
  let domain = helpers::domain();

  let cookies =
    rookie_cookies::chromium_based(key_path, db_path.clone(), Some(vec![domain.clone()]), false)
      .unwrap_or_else(|e| panic!("rookie_cookies::chromium_based (elevated_only) failed: {e}",));

  helpers::assert_seeded(&cookies, &domain);
}

#[cfg(target_os = "windows")]
#[test]
#[ignore]
fn extracts_seeded_cookie_through_default_chrome_discovery() {
  if std::env::var("ROOKIE_E2E_CHECK_BROWSER_DISCOVERY").as_deref() != Ok("1") {
    eprintln!("default browser discovery check was not requested");
    return;
  }
  let domain = helpers::domain();
  let browser_name =
    std::env::var("ROOKIE_E2E_TARGET_BROWSER").unwrap_or_else(|_| "chrome".to_string());
  let cookies = match browser_name.to_ascii_lowercase().as_str() {
    "chrome" | "google-chrome" => rookie_cookies::chrome(Some(vec![domain.clone()]))
      .unwrap_or_else(|error| panic!("rookie_cookies::chrome failed: {error}")),
    "edge" | "msedge" => rookie_cookies::edge(Some(vec![domain.clone()]))
      .unwrap_or_else(|error| panic!("rookie_cookies::edge failed: {error}")),
    "brave" => rookie_cookies::brave(Some(vec![domain.clone()]))
      .unwrap_or_else(|error| panic!("rookie_cookies::brave failed: {error}")),
    "coccoc" => rookie_cookies::browser("coccoc", Some(vec![domain.clone()]))
      .unwrap_or_else(|error| panic!("rookie_cookies::browser(coccoc) failed: {error}")),
    "avast" => rookie_cookies::browser("avast", Some(vec![domain.clone()]))
      .unwrap_or_else(|error| panic!("rookie_cookies::browser(avast) failed: {error}")),
    other => panic!("unsupported ROOKIE_E2E_TARGET_BROWSER {other:?}"),
  };
  helpers::assert_discovered(&cookies, &domain);
}

#[cfg(target_os = "windows")]
#[test]
fn extracts_deterministic_legacy_v10_fixture_with_current_user_dpapi() {
  let fixture = deterministic_dpapi::create();
  let domain = "example.test";

  let cookies = rookie_cookies::chromium_based(
    fixture.local_state.clone(),
    fixture.cookies_db.clone(),
    Some(vec![domain.to_string()]),
    false,
  )
  .unwrap_or_else(|error| {
    panic!(
      "chromium_based({}, {}) failed: {error}",
      fixture.local_state.display(),
      fixture.cookies_db.display()
    )
  });

  let cookie = cookies
    .iter()
    .find(|cookie| cookie.name == "rookie_ci")
    .expect("seeded cookie");
  assert_eq!(cookie.value, "bar");
  assert_eq!(cookie.domain, ".example.test");
  assert!(cookie.http_only);
  assert_eq!(cookie.same_site, 1);
}
