//! End-to-end test: extracts cookies from a real Firefox profile seeded
//! by `tests/e2e/seed_firefox_cookie.mjs` and asserts the seeded
//! `rookie_ci=bar` cookie is recovered.
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

#[test]
#[ignore]
fn extracts_seeded_cookie_from_firefox_profile() {
  use std::env;
  use std::path::PathBuf;

  let profile_dir =
    env::var("ROOKIE_E2E_FIREFOX_PROFILE").expect("ROOKIE_E2E_FIREFOX_PROFILE must be set");
  let domain = env::var("ROOKIE_E2E_DOMAIN").unwrap_or_else(|_| "127.0.0.1".to_string());
  let expected_name =
    env::var("ROOKIE_E2E_COOKIE_NAME").unwrap_or_else(|_| "rookie_ci".to_string());
  let expected_value = env::var("ROOKIE_E2E_COOKIE_VALUE").unwrap_or_else(|_| "bar".to_string());

  let db_path = PathBuf::from(&profile_dir).join("cookies.sqlite");
  assert!(db_path.exists(), "no cookies.sqlite under {}", profile_dir);

  let cookies = rookie_cookies::firefox_based(db_path.clone(), Some(vec![domain.clone()]))
    .unwrap_or_else(|e| {
      panic!(
        "rookie_cookies::firefox_based({}) failed: {e}",
        db_path.display()
      )
    });

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
