#![allow(deprecated)]

//! Real Safari/Internet Explorer E2E assertion. CI seeds the native store with
//! the platform WebDriver, then supplies its path through ROOKIE_E2E_COOKIE_DB.

#[cfg(any(target_os = "macos", target_os = "windows"))]
mod manifest {
  use std::env;
  use std::io::Write;
  use std::path::PathBuf;
  use std::process::{Command, Stdio};

  pub fn assert_corpus<T: serde::Serialize + ?Sized>(
    actual: &T,
    projection: &str,
    surface: &str,
  ) -> bool {
    let Some(path) = env::var_os("ROOKIE_E2E_COOKIE_MANIFEST").map(PathBuf::from) else {
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
        } else {
          PathBuf::from("python3")
        }
      });
    let mut child = Command::new(python)
      .arg(workspace.join("tests/e2e/verify_cookie_manifest.py"))
      .arg("--manifest")
      .arg(path)
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
      .write_all(&serde_json::to_vec(actual).expect("serialize native cookies"))
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

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
#[ignore]
fn extracts_seeded_native_cookie() {
  use std::env;
  use std::path::PathBuf;

  let browser = env::var("ROOKIE_E2E_BROWSER_ID").expect("ROOKIE_E2E_BROWSER_ID must be set");
  let path =
    PathBuf::from(env::var_os("ROOKIE_E2E_COOKIE_DB").expect("ROOKIE_E2E_COOKIE_DB must be set"));
  assert!(
    path.is_file(),
    "native cookie store missing: {}",
    path.display()
  );
  let domain = env::var("ROOKIE_E2E_DOMAIN").unwrap_or_else(|_| "127.0.0.1".to_owned());
  let expected_name = env::var("ROOKIE_E2E_COOKIE_NAME").unwrap_or_else(|_| "rookie_ci".to_owned());
  let expected_value = env::var("ROOKIE_E2E_COOKIE_VALUE").unwrap_or_else(|_| "bar".to_owned());

  let cookies = rookie_cookies::direct_path::extract_from_path(
    rookie_cookies::direct_path::PathExtractRequest::sniff(&path)
      .domains(Some(vec![domain.clone()])),
  )
  .unwrap_or_else(|error| panic!("{browser} explicit-path extraction failed: {error}"));
  if manifest::assert_corpus(&cookies, "filtered_flat", "Rust native explicit path") {
    let snapshot = rookie_cookies::from_path(rookie_cookies::FromPathRequest::new(&path))
      .unwrap_or_else(|error| panic!("{browser} from_path extraction failed: {error}"));
    manifest::assert_corpus(
      snapshot.cookies(),
      "unfiltered_flat",
      "Rust native from_path cookies",
    );
    manifest::assert_corpus(
      snapshot.detailed_cookies(),
      "detailed",
      "Rust native from_path detailed_cookies",
    );
    return;
  }
  assert_eq!(
    cookies.len(),
    1,
    "{browser}: expected the exact one-cookie filtered set for {domain}: {cookies:#?}"
  );
  let seeded = cookies
    .iter()
    .find(|cookie| cookie.name == expected_name)
    .unwrap_or_else(|| {
      panic!(
        "{browser}: seeded cookie {expected_name:?} missing from {} cookies for {domain}",
        cookies.len()
      )
    });
  assert_eq!(seeded.value, expected_value, "cookie value mismatch");
  assert_eq!(seeded.domain, domain, "native domain mismatch");
  assert_eq!(seeded.path, "/", "native path mismatch");
  assert!(!seeded.secure, "native cookie unexpectedly became Secure");
  assert!(
    !seeded.http_only,
    "native cookie unexpectedly became HttpOnly"
  );
  assert_eq!(
    seeded.same_site,
    rookie_cookies::common::enums::SAME_SITE_UNSPECIFIED,
    "native stores do not encode SameSite"
  );
  let now = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .expect("system clock before Unix epoch")
    .as_secs();
  let expires = seeded
    .expires
    .expect("native persistent cookie lost expiry");
  assert!(
    (now + 1800..=now + 4500).contains(&expires),
    "native expiry {expires} was not approximately one hour after {now}"
  );
}
