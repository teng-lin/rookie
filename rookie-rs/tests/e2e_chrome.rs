#![allow(deprecated)]

//! End-to-end test: extracts cookies from a real Chrome profile that was
//! seeded by `tests/e2e/seed_chromium_cookie.mjs`. Ordinary hosted lanes use
//! an independent manifest to assert the exact flat and detailed corpus;
//! focused App-Bound/WAL canaries retain their single-cookie assertion.
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
  use std::collections::BTreeMap;
  use std::env;
  use std::io::Write;
  use std::path::PathBuf;
  use std::process::{Command, Stdio};

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

  fn manifest_path() -> Option<PathBuf> {
    if let Some(path) = env::var_os("ROOKIE_E2E_COOKIE_MANIFEST") {
      return Some(PathBuf::from(path));
    }
    if env::var("ROOKIE_E2E_COOKIE_NAME")
      .as_deref()
      .unwrap_or("rookie_ci")
      != "rookie_ci"
    {
      return None;
    }
    let user_data_dir = env::var_os("ROOKIE_E2E_USER_DATA_DIR")?;
    let candidate = PathBuf::from(user_data_dir).join("rookie-e2e-cookie-manifest.json");
    candidate.is_file().then_some(candidate)
  }

  pub fn corpus_enabled() -> bool {
    manifest_path().is_some()
  }

  fn verifier_python(workspace: &std::path::Path) -> PathBuf {
    if let Some(path) = env::var_os("ROOKIE_E2E_PYTHON") {
      return PathBuf::from(path);
    }
    #[cfg(target_os = "windows")]
    let candidate = workspace.join(".venv/Scripts/python.exe");
    #[cfg(not(target_os = "windows"))]
    let candidate = workspace.join(".venv/bin/python");
    if candidate.is_file() {
      candidate
    } else if cfg!(target_os = "windows") {
      PathBuf::from("python")
    } else {
      PathBuf::from("python3")
    }
  }

  pub fn assert_corpus<T: serde::Serialize + ?Sized>(
    actual: &T,
    projection: &str,
    surface: &str,
  ) -> bool {
    let Some(manifest) = manifest_path() else {
      return false;
    };
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
      .parent()
      .expect("rookie-rs has workspace parent")
      .to_path_buf();
    let verifier = workspace.join("tests/e2e/verify_cookie_manifest.py");
    let mut child = Command::new(verifier_python(&workspace))
      .arg(verifier)
      .arg("--manifest")
      .arg(manifest)
      .arg("--projection")
      .arg(projection)
      .arg("--surface")
      .arg(surface)
      .stdin(Stdio::piped())
      .stdout(Stdio::piped())
      .stderr(Stdio::piped())
      .spawn()
      .expect("launch independent cookie manifest verifier");
    child
      .stdin
      .take()
      .expect("verifier stdin")
      .write_all(&serde_json::to_vec(actual).expect("serialize extracted cookies"))
      .expect("write verifier input");
    let output = child.wait_with_output().expect("wait for cookie verifier");
    assert!(
      output.status.success(),
      "{surface} failed exact cookie manifest verification: {}{}",
      String::from_utf8_lossy(&output.stderr),
      String::from_utf8_lossy(&output.stdout)
    );
    eprint!("{}", String::from_utf8_lossy(&output.stdout));
    true
  }

  pub fn assert_seeded(cookies: &[rookie_cookies::enums::Cookie], domain: &str) {
    if assert_corpus(cookies, "filtered_flat", "Rust chromium_based") {
      return;
    }
    assert_state(cookies, domain);
  }

  pub fn assert_state(cookies: &[rookie_cookies::enums::Cookie], domain: &str) {
    let expected_name =
      env::var("ROOKIE_E2E_COOKIE_NAME").unwrap_or_else(|_| "rookie_ci".to_string());
    let expected_value = env::var("ROOKIE_E2E_COOKIE_VALUE").unwrap_or_else(|_| "bar".to_string());
    let required = env::var("ROOKIE_E2E_REQUIRED_COOKIES_JSON")
      .map(|raw| {
        serde_json::from_str::<BTreeMap<String, String>>(&raw)
          .expect("ROOKIE_E2E_REQUIRED_COOKIES_JSON must be a string map")
      })
      .unwrap_or_else(|_| BTreeMap::from([(expected_name, expected_value)]));
    let forbidden = env::var("ROOKIE_E2E_FORBIDDEN_COOKIES_JSON")
      .map(|raw| {
        serde_json::from_str::<Vec<String>>(&raw)
          .expect("ROOKIE_E2E_FORBIDDEN_COOKIES_JSON must be a string array")
      })
      .unwrap_or_default();
    for (name, value) in &required {
      let matches: Vec<_> = cookies
        .iter()
        .filter(|cookie| cookie.name == *name)
        .collect();
      assert_eq!(
        matches.len(),
        1,
        "expected exactly one `{name}` among {} cookies for {domain}",
        cookies.len()
      );
      assert_eq!(&matches[0].value, value, "cookie `{name}` value mismatch");
    }
    for name in forbidden {
      assert!(
        cookies.iter().all(|cookie| cookie.name != name),
        "forbidden/deleted cookie `{name}` remained for {domain}"
      );
    }
    if env::var("ROOKIE_E2E_EXACT_COOKIE_STATE").as_deref() == Ok("1") {
      assert_eq!(
        cookies.len(),
        required.len(),
        "active-writer result contained excess or missing rows for {domain}: {cookies:#?}"
      );
      assert!(
        cookies
          .iter()
          .all(|cookie| required.contains_key(&cookie.name)),
        "active-writer result contained an unexpected cookie for {domain}: {cookies:#?}"
      );
    }
  }

  #[cfg(target_os = "windows")]
  pub fn assert_discovered(cookies: &[rookie_cookies::enums::Cookie], domain: &str) {
    if assert_corpus(cookies, "filtered_flat", "Rust browser discovery") {
      return;
    }
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

    // SAFETY: `input` references valid initialized memory and `output` receives the protected blob.
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

    // SAFETY: `output.pbData` is non-null and points to `output.cbData` initialized bytes from CryptProtectData.
    let protected =
      unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    // SAFETY: `output.pbData` is a valid allocation from CryptProtectData to be freed.
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
  if helpers::corpus_enabled() {
    let detailed = rookie_cookies::chromium_based_detailed(config, db_path, None, false)
      .unwrap_or_else(|error| panic!("chromium_based_detailed failed: {error}"));
    helpers::assert_corpus(&detailed, "detailed", "Rust chromium_based_detailed");
  }
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
  if helpers::corpus_enabled() {
    let detailed = rookie_cookies::chromium_based_detailed(config, db_path, None, false)
      .unwrap_or_else(|error| panic!("chromium_based_detailed failed: {error}"));
    helpers::assert_corpus(&detailed, "detailed", "Rust chromium_based_detailed");
  }
}

#[cfg(target_os = "windows")]
#[test]
#[ignore]
fn extracts_seeded_cookie_from_chrome_dpapi_profile() {
  let db_path = helpers::resolve_db_path();
  let key_path = helpers::resolve_key_path();
  let domain = helpers::domain();

  let cookies = rookie_cookies::chromium_based(
    key_path.clone(),
    db_path.clone(),
    Some(vec![domain.clone()]),
    false,
  )
  .unwrap_or_else(|e| {
    panic!(
      "rookie_cookies::chromium_based({}) failed: {e}",
      db_path.display()
    )
  });

  helpers::assert_seeded(&cookies, &domain);
  if helpers::corpus_enabled() {
    let detailed = rookie_cookies::chromium_based_detailed(key_path, db_path, None, false)
      .unwrap_or_else(|error| panic!("chromium_based_detailed failed: {error}"));
    helpers::assert_corpus(&detailed, "detailed", "Rust chromium_based_detailed");
  }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[test]
#[ignore]
fn canonical_detailed_and_recommended_reads_keep_the_seeded_profile_identity() {
  let db_path = helpers::resolve_db_path();
  let domain = helpers::domain();
  let browser_id = std::env::var("ROOKIE_E2E_BROWSER_ID").unwrap_or_else(|_| "chrome".to_owned());

  let direct = rookie_cookies::FromPathRequest::new(&db_path)
    .app_bound(rookie_cookies::AppBoundPolicy::AllowElevatedFallback);
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  let direct = direct.chromium_browser_id(&browser_id);
  #[cfg(target_os = "windows")]
  let direct = direct.chromium_local_state(helpers::resolve_key_path());
  let direct = rookie_cookies::from_path(direct)
    .unwrap_or_else(|error| panic!("from_path({}) failed: {error}", db_path.display()));
  assert_eq!(
    direct.browser_id(),
    None,
    "explicit paths do not run discovery"
  );
  assert_eq!(
    direct.profile_id(),
    None,
    "explicit paths do not select profiles"
  );
  if !helpers::assert_corpus(
    direct.cookies(),
    "unfiltered_flat",
    "Rust from_path cookies",
  ) {
    helpers::assert_state(direct.cookies(), &domain);
  }
  helpers::assert_corpus(
    direct.detailed_cookies(),
    "detailed",
    "Rust from_path detailed_cookies",
  );
  assert!(
    direct
      .detailed_cookies()
      .iter()
      .any(|record| record.cookie.name
        == std::env::var("ROOKIE_E2E_COOKIE_NAME").unwrap_or_else(|_| "rookie_ci".to_owned())),
    "from_path detailed output omitted the seeded cookie"
  );

  if std::env::var("ROOKIE_E2E_CHECK_RECOMMENDED_READ").as_deref() != Ok("1") {
    eprintln!("recommended read/discovery check was not requested");
    return;
  }
  let canonical_db = db_path
    .canonicalize()
    .expect("canonical cookie database path");
  let profiles = rookie_cookies::profiles(&browser_id)
    .unwrap_or_else(|error| panic!("profiles({browser_id}) failed: {error}"));
  let mut matching = profiles.iter().filter(|profile| {
    profile.sources.iter().any(|source| {
      std::fs::canonicalize(&source.path)
        .map(|path| path == canonical_db)
        .unwrap_or(false)
    })
  });
  let profile = matching.next().unwrap_or_else(|| {
    panic!(
      "discovery did not report source {}: {profiles:#?}",
      db_path.display()
    )
  });
  assert!(
    matching.next().is_none(),
    "source matched more than one discovered profile"
  );
  assert_eq!(profile.profile.browser_id.as_str(), browser_id);

  let profile_id = profile.profile.profile_id.to_string();
  let snapshot = rookie_cookies::read(
    rookie_cookies::ReadRequest::browser(&browser_id)
      .profile(&profile_id)
      .app_bound(rookie_cookies::AppBoundPolicy::AllowElevatedFallback),
  )
  .unwrap_or_else(|error| panic!("read({browser_id}, {profile_id}) failed: {error}"));
  assert_eq!(snapshot.browser_id(), Some(browser_id.as_str()));
  assert_eq!(snapshot.profile_id(), Some(profile_id.as_str()));
  if !helpers::assert_corpus(
    snapshot.cookies(),
    "unfiltered_flat",
    "Rust recommended read cookies",
  ) {
    helpers::assert_state(snapshot.cookies(), &domain);
  }
  helpers::assert_corpus(
    snapshot.detailed_cookies(),
    "detailed",
    "Rust recommended read detailed_cookies",
  );
  assert!(
    snapshot.detailed_cookies().iter().any(|record| {
      record.cookie.name
        == std::env::var("ROOKIE_E2E_COOKIE_NAME").unwrap_or_else(|_| "rookie_ci".to_owned())
    }),
    "recommended read detailed output omitted the seeded cookie"
  );
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

  let cookies = rookie_cookies::chromium_based(
    key_path.clone(),
    db_path.clone(),
    Some(vec![domain.clone()]),
    false,
  )
  .unwrap_or_else(|e| panic!("rookie_cookies::chromium_based (injection_only) failed: {e}",));

  helpers::assert_seeded(&cookies, &domain);
  if helpers::corpus_enabled() {
    let detailed = rookie_cookies::chromium_based_detailed(key_path, db_path, None, false)
      .unwrap_or_else(|error| panic!("chromium_based_detailed failed: {error}"));
    helpers::assert_corpus(&detailed, "detailed", "Rust chromium_based_detailed");
  }
}

#[cfg(target_os = "windows")]
#[test]
#[ignore]
fn extracts_seeded_cookie_via_elevated_fallback_only() {
  std::env::set_var("ROOKIE_E2E_APPBOUND_MODE", "elevated_only");
  let db_path = helpers::resolve_db_path();
  let key_path = helpers::resolve_key_path();
  let domain = helpers::domain();

  let cookies = rookie_cookies::chromium_based(
    key_path.clone(),
    db_path.clone(),
    Some(vec![domain.clone()]),
    false,
  )
  .unwrap_or_else(|e| panic!("rookie_cookies::chromium_based (elevated_only) failed: {e}",));

  helpers::assert_seeded(&cookies, &domain);
  if helpers::corpus_enabled() {
    let detailed = rookie_cookies::chromium_based_detailed(key_path, db_path, None, false)
      .unwrap_or_else(|error| panic!("chromium_based_detailed failed: {error}"));
    helpers::assert_corpus(&detailed, "detailed", "Rust chromium_based_detailed");
  }
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
