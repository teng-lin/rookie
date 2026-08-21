#![allow(deprecated)]

//! Real Safari/Internet Explorer E2E assertion. CI seeds the native store with
//! the platform WebDriver, then supplies its path through ROOKIE_E2E_COOKIE_DB.

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
    rookie_cookies::direct_path::PathExtractRequest::sniff(path)
      .domains(Some(vec![domain.clone()])),
  )
  .unwrap_or_else(|error| panic!("{browser} explicit-path extraction failed: {error}"));
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
}
