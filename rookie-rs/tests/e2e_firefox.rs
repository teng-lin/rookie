#![allow(deprecated)]

//! End-to-end test: extracts cookies from a real Firefox profile seeded
//! by `tests/e2e/seed_firefox_cookie.mjs` and asserts its exact flat and
//! detailed cookie corpus against an independent browser-observed manifest.
//!
//! Firefox stores cookies unencrypted in `<profile>/cookies.sqlite`, so this
//! is the simplest possible e2e path — no keyring/Keychain/DPAPI needed.
//!
//! Driven by env vars:
//!   ROOKIE_E2E_FIREFOX_PROFILE — required; absolute path to the Firefox
//!                                profile dir (the user-data-dir passed
//!                                to Playwright's launchPersistentContext)
//!   ROOKIE_E2E_DOMAIN          — optional; default "127.0.0.1"
//!   ROOKIE_E2E_COOKIE_NAME     — optional; expected name (default: "rookie_ci")
//!   ROOKIE_E2E_COOKIE_VALUE    — optional; expected value (default: "bar")
//!
//! Ignored by default; CI runs them via
//! `cargo test --test e2e_firefox -- --ignored`.

mod manifest {
  use std::env;
  use std::io::Write;
  use std::path::PathBuf;
  use std::process::{Command, Stdio};

  fn path(profile_dir: &str, expected_name: &str) -> Option<PathBuf> {
    env::var_os("ROOKIE_E2E_COOKIE_MANIFEST")
      .map(PathBuf::from)
      .or_else(|| {
        (expected_name == "rookie_ci")
          .then(|| PathBuf::from(profile_dir).join("rookie-e2e-cookie-manifest.json"))
          .filter(|path| path.is_file())
      })
  }

  pub fn assert_corpus<T: serde::Serialize + ?Sized>(
    actual: &T,
    projection: &str,
    surface: &str,
    profile_dir: &str,
    expected_name: &str,
  ) -> bool {
    let Some(manifest) = path(profile_dir, expected_name) else {
      return false;
    };
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
      .parent()
      .expect("rookie-rs has workspace parent")
      .to_path_buf();
    #[cfg(target_os = "windows")]
    let venv_python = workspace.join(".venv/Scripts/python.exe");
    #[cfg(not(target_os = "windows"))]
    let venv_python = workspace.join(".venv/bin/python");
    let python = env::var_os("ROOKIE_E2E_PYTHON")
      .map(PathBuf::from)
      .unwrap_or_else(|| {
        if venv_python.is_file() {
          venv_python
        } else if cfg!(target_os = "windows") {
          PathBuf::from("python")
        } else {
          PathBuf::from("python3")
        }
      });
    let mut child = Command::new(&python)
      .arg(workspace.join("tests/e2e/verify_cookie_manifest.py"))
      .arg("--manifest")
      .arg(&manifest)
      .arg("--projection")
      .arg(projection)
      .arg("--surface")
      .arg(surface)
      .stdin(Stdio::piped())
      .stdout(Stdio::piped())
      .stderr(Stdio::piped())
      .spawn()
      .expect("launch cookie manifest verifier");
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
}

mod state {
  use std::collections::BTreeMap;
  use std::env;

  pub fn assert(cookies: &[rookie_cookies::enums::Cookie], domain: &str, surface: &str) {
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
        "{surface}: expected exactly one `{name}` among {} cookies for {domain}",
        cookies.len()
      );
      assert_eq!(
        &matches[0].value, value,
        "{surface}: cookie `{name}` value mismatch"
      );
    }
    for name in forbidden {
      assert!(
        cookies.iter().all(|cookie| cookie.name != name),
        "{surface}: forbidden/deleted cookie `{name}` remained for {domain}"
      );
    }
    if env::var("ROOKIE_E2E_EXACT_COOKIE_STATE").as_deref() == Ok("1") {
      assert_eq!(
        cookies.len(),
        required.len(),
        "{surface}: result contained excess or missing rows for {domain}: {cookies:#?}"
      );
      assert!(
        cookies
          .iter()
          .all(|cookie| required.contains_key(&cookie.name)),
        "{surface}: result contained an unexpected cookie for {domain}: {cookies:#?}"
      );
    }
  }
}

#[test]
#[ignore]
fn extracts_seeded_cookie_from_firefox_profile() {
  use std::env;
  use std::path::PathBuf;
  use std::time::{SystemTime, UNIX_EPOCH};

  let profile_dir =
    env::var("ROOKIE_E2E_FIREFOX_PROFILE").expect("ROOKIE_E2E_FIREFOX_PROFILE must be set");
  let domain = env::var("ROOKIE_E2E_DOMAIN").unwrap_or_else(|_| "127.0.0.1".to_string());
  let expected_name =
    env::var("ROOKIE_E2E_COOKIE_NAME").unwrap_or_else(|_| "rookie_ci".to_string());
  let db_path = PathBuf::from(&profile_dir).join("cookies.sqlite");
  assert!(db_path.exists(), "no cookies.sqlite under {}", profile_dir);

  let cookies = rookie_cookies::firefox_based(db_path.clone(), Some(vec![domain.clone()]))
    .unwrap_or_else(|e| {
      panic!(
        "rookie_cookies::firefox_based({}) failed: {e}",
        db_path.display()
      )
    });

  if manifest::assert_corpus(
    &cookies,
    "filtered_flat",
    "Rust firefox_based",
    &profile_dir,
    &expected_name,
  ) {
    let detailed = rookie_cookies::firefox_based_detailed(db_path, None)
      .unwrap_or_else(|error| panic!("firefox_based_detailed failed: {error}"));
    manifest::assert_corpus(
      &detailed,
      "detailed",
      "Rust firefox_based_detailed",
      &profile_dir,
      &expected_name,
    );
    return;
  }

  state::assert(&cookies, &domain, "Rust firefox_based");
  let seeded = cookies
    .iter()
    .find(|cookie| cookie.name == expected_name)
    .expect("primary active-writer cookie must be required");
  let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("system time after Unix epoch")
    .as_secs();
  let expires = seeded.expires.expect("Max-Age cookie must be persistent");
  assert!(
    expires > now && expires <= now + 7_200,
    "Firefox expiry must be Unix seconds near the seeded Max-Age, got {expires} at {now}"
  );
}

#[test]
#[ignore]
fn canonical_detailed_and_recommended_reads_keep_the_seeded_profile_identity() {
  use std::env;
  use std::path::PathBuf;

  let profile_dir =
    env::var("ROOKIE_E2E_FIREFOX_PROFILE").expect("ROOKIE_E2E_FIREFOX_PROFILE must be set");
  let browser_id = env::var("ROOKIE_E2E_BROWSER_ID").unwrap_or_else(|_| "firefox".to_owned());
  let expected_name = env::var("ROOKIE_E2E_COOKIE_NAME").unwrap_or_else(|_| "rookie_ci".to_owned());
  let expected_value = env::var("ROOKIE_E2E_COOKIE_VALUE").unwrap_or_else(|_| "bar".to_owned());
  let db_path = PathBuf::from(&profile_dir).join("cookies.sqlite");

  let direct = rookie_cookies::from_path(rookie_cookies::FromPathRequest::new(&db_path))
    .unwrap_or_else(|error| panic!("from_path({}) failed: {error}", db_path.display()));
  assert_eq!(direct.browser_id(), None);
  assert_eq!(direct.profile_id(), None);
  let has_manifest = manifest::assert_corpus(
    direct.cookies(),
    "unfiltered_flat",
    "Rust Firefox from_path cookies",
    &profile_dir,
    &expected_name,
  );
  if has_manifest {
    manifest::assert_corpus(
      direct.detailed_cookies(),
      "detailed",
      "Rust Firefox from_path detailed_cookies",
      &profile_dir,
      &expected_name,
    );
  } else {
    state::assert(
      direct.cookies(),
      "unfiltered",
      "Rust Firefox from_path cookies",
    );
    let detailed_cookies: Vec<_> = direct
      .detailed_cookies()
      .iter()
      .map(|record| record.cookie.clone())
      .collect();
    state::assert(
      &detailed_cookies,
      "unfiltered",
      "Rust Firefox from_path detailed_cookies",
    );
  }
  let detailed = direct
    .detailed_cookies()
    .iter()
    .find(|record| record.cookie.name == expected_name)
    .expect("from_path detailed output omitted the seeded cookie");
  assert_eq!(detailed.cookie.value, expected_value);

  if env::var("ROOKIE_E2E_CHECK_RECOMMENDED_READ").as_deref() != Ok("1") {
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
  let snapshot =
    rookie_cookies::read(rookie_cookies::ReadRequest::browser(&browser_id).profile(&profile_id))
      .unwrap_or_else(|error| panic!("read({browser_id}, {profile_id}) failed: {error}"));
  assert_eq!(snapshot.browser_id(), Some(browser_id.as_str()));
  assert_eq!(snapshot.profile_id(), Some(profile_id.as_str()));
  let has_manifest = manifest::assert_corpus(
    snapshot.cookies(),
    "unfiltered_flat",
    "Rust Firefox recommended read cookies",
    &profile_dir,
    &expected_name,
  );
  if has_manifest {
    manifest::assert_corpus(
      snapshot.detailed_cookies(),
      "detailed",
      "Rust Firefox recommended read detailed_cookies",
      &profile_dir,
      &expected_name,
    );
  } else {
    state::assert(
      snapshot.cookies(),
      "unfiltered",
      "Rust Firefox recommended read cookies",
    );
    let detailed_cookies: Vec<_> = snapshot
      .detailed_cookies()
      .iter()
      .map(|record| record.cookie.clone())
      .collect();
    state::assert(
      &detailed_cookies,
      "unfiltered",
      "Rust Firefox recommended read detailed_cookies",
    );
  }
  let detailed = snapshot
    .detailed_cookies()
    .iter()
    .find(|record| record.cookie.name == expected_name)
    .expect("recommended read detailed output omitted the seeded cookie");
  assert_eq!(detailed.cookie.value, expected_value);
}
