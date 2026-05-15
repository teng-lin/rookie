//! End-to-end test: extracts cookies from a real Chrome profile that was
//! seeded by `tests/e2e/seed_chromium_cookie.mjs` and asserts the seeded
//! `rookie_ci=bar` cookie is recovered with the OS-encrypted value intact.
//!
//! These tests are `#[ignore]` because they require:
//!   - A real Chrome install on the runner
//!   - A pre-seeded user profile at the platform's default location
//!   - On Linux: an active D-Bus session + gnome-keyring with the
//!     `chrome_libsecret_os_crypt_password_v2` secret stored by Chrome
//!
//! CI invokes them via `cargo test --test e2e_chrome -- --ignored`.

#[cfg(target_os = "linux")]
#[test]
#[ignore]
fn extracts_seeded_cookie_from_chrome_libsecret_profile() {
  let cookies = rookie::chrome(Some(vec!["127.0.0.1".to_string()])).expect("rookie::chrome failed");
  let seeded = cookies
    .iter()
    .find(|c| c.name == "rookie_ci")
    .expect("seeded cookie `rookie_ci` not found in Chrome profile");
  assert_eq!(seeded.value, "bar", "cookie value mismatch");
}
