use super::chromium_crypto::{ChromiumKeyOutcome, ChromiumKeyOutcomes, ChromiumKeyProvider};
#[cfg(target_os = "windows")]
use anyhow::bail;
use anyhow::Result;

#[cfg(unix)]
use crate::config::Browser;

#[cfg(target_os = "windows")]
use base64::{engine::general_purpose, Engine as _};

use zeroize::Zeroizing;

/// Derives a Chromium v10/v11 key from a candidate password.
///
/// Wrapped in `Zeroizing` because this is the key material handed to AES-GCM
/// to decrypt cookie values; it is wiped from memory as soon as its owner
/// drops it rather than left in freed heap memory.
#[cfg(unix)]
pub(crate) fn create_pbkdf2_key(
  password: &str,
  salt: &[u8; 9],
  iterations: u32,
) -> Zeroizing<Vec<u8>> {
  use pbkdf2::pbkdf2_hmac;
  use sha1::Sha1;

  let mut output = [0u8; 16];
  pbkdf2_hmac::<Sha1>(password.as_bytes(), salt, iterations, &mut output);
  Zeroizing::new(output.to_vec())
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
fn outcome_from_result(
  result: Result<Vec<Zeroizing<Vec<u8>>>>,
  empty_failure: &'static str,
) -> ChromiumKeyOutcome {
  match result {
    Ok(candidates) => ChromiumKeyOutcome::success_zeroizing(candidates)
      .unwrap_or_else(|| ChromiumKeyOutcome::failure(empty_failure)),
    Err(error) => ChromiumKeyOutcome::failure(error.to_string()),
  }
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalStateKey<'a> {
  Missing,
  InvalidType,
  Encoded(&'a str),
}

#[cfg(target_os = "windows")]
fn local_state_key<'a>(local_state: &'a serde_json::Value, field: &str) -> LocalStateKey<'a> {
  let Some(value) = local_state
    .get("os_crypt")
    .and_then(|os_crypt| os_crypt.get(field))
  else {
    return LocalStateKey::Missing;
  };
  match value.as_str() {
    Some("") => LocalStateKey::Missing,
    Some(encoded) => LocalStateKey::Encoded(encoded),
    None => LocalStateKey::InvalidType,
  }
}

#[cfg(target_os = "windows")]
trait WindowsKeyBackend {
  fn retrieve_v10(&self, encoded_key: &str) -> Result<Vec<Zeroizing<Vec<u8>>>>;
  fn appbound_compiled(&self) -> bool;
  fn privileged(&self) -> bool;
  fn retrieve_v20(&self, encoded_key: &str) -> Result<Vec<Zeroizing<Vec<u8>>>>;
}

#[cfg(target_os = "windows")]
struct SystemWindowsKeyBackend;

#[cfg(target_os = "windows")]
impl WindowsKeyBackend for SystemWindowsKeyBackend {
  fn retrieve_v10(&self, encoded_key: &str) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    let wrapped: Vec<u8> = general_purpose::STANDARD
      .decode(encoded_key)
      .map_err(|error| {
        anyhow::anyhow!("Failed to decode Local State os_crypt.encrypted_key as base64: {error}")
      })?;
    let decoded_len = wrapped.len();
    if decoded_len <= 5 {
      bail!(
        "Local State os_crypt.encrypted_key decoded to {} bytes, expected DPAPI prefix plus payload",
        decoded_len
      );
    }
    if &wrapped[..5] != b"DPAPI" {
      bail!("Local State os_crypt.encrypted_key is missing DPAPI prefix");
    }

    let wrapped_len = decoded_len - 5;
    // Wrap the unwrapped master key immediately so it is zeroized as soon as
    // this scope ends, rather than left in freed heap memory.
    let v10_key = Zeroizing::new(crate::windows::dpapi::decrypt(&wrapped[5..]).map_err(
      |error| {
        anyhow::anyhow!(
          "Failed to unwrap DPAPI encrypted key (decoded_length={decoded_len}, wrapped_length={wrapped_len}): {error}"
        )
      },
    )?);
    if v10_key.len() != 32 {
      bail!(
        "DPAPI unwrapped key length was {}, expected 32 (decoded_length={}, wrapped_length={})",
        v10_key.len(),
        decoded_len,
        wrapped_len
      );
    }
    Ok(vec![v10_key])
  }

  fn appbound_compiled(&self) -> bool {
    cfg!(feature = "appbound")
  }

  fn privileged(&self) -> bool {
    privilege::user::privileged()
  }

  fn retrieve_v20(&self, encoded_key: &str) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    #[cfg(feature = "appbound")]
    {
      crate::windows::appbound::get_keys(encoded_key)
    }

    #[cfg(not(feature = "appbound"))]
    {
      let _ = encoded_key;
      bail!("Chromium v20 app-bound provider is unavailable in this build")
    }
  }
}

#[cfg(target_os = "windows")]
fn retrieve_windows_key_outcomes<B>(
  local_state: &serde_json::Value,
  backend: &B,
) -> ChromiumKeyOutcomes
where
  B: WindowsKeyBackend,
{
  let v10 = match local_state_key(local_state, "encrypted_key") {
    LocalStateKey::Missing => ChromiumKeyOutcome::NotApplicable,
    LocalStateKey::InvalidType => {
      ChromiumKeyOutcome::failure("Local State os_crypt.encrypted_key must be a base64 string")
    }
    LocalStateKey::Encoded(encoded) => outcome_from_result(
      backend.retrieve_v10(encoded),
      "Chromium v10 provider returned no key candidates",
    ),
  };

  let v20 = match local_state_key(local_state, "app_bound_encrypted_key") {
    LocalStateKey::Missing => ChromiumKeyOutcome::NotApplicable,
    LocalStateKey::InvalidType => ChromiumKeyOutcome::failure(
      "Local State os_crypt.app_bound_encrypted_key must be a base64 string",
    ),
    LocalStateKey::Encoded(_) if !backend.appbound_compiled() => {
      ChromiumKeyOutcome::failure("Chromium v20 app-bound provider is unavailable in this build")
    }
    LocalStateKey::Encoded(_) if !backend.privileged() => ChromiumKeyOutcome::failure(
      "Chromium v20 app-bound key retrieval requires administrator privileges",
    ),
    // The AES256/ChaCha20 elevation keys used to unwrap the app-bound master
    // key are extracted specifically from Google Chrome's elevation_service.exe
    // (see windows/appbound/mod.rs). Other Chromium-based vendors (Brave, Edge,
    // Vivaldi, Opera, ...) can also write an app_bound_encrypted_key using their
    // own vendor-specific elevation service with different keys, which will
    // safely fail to unwrap here. We don't know which named browser produced
    // this Local State at this layer, so we can't say definitively that's what
    // happened - but surface it as a possibility rather than a bare decryption
    // error, so it isn't mistaken for a generic bug.
    LocalStateKey::Encoded(encoded) => {
      // Only reassure the caller that legacy cookies are unaffected when v10
      // actually succeeded - v10 is retrieved independently and can itself have
      // failed (or been absent) for the same Local State.
      let legacy_note = if matches!(v10, ChromiumKeyOutcome::Success(_)) {
        "legacy v10/v11 cookies are unaffected"
      } else {
        "legacy v10/v11 cookies may also have failed to decrypt - check the v10 outcome separately"
      };
      match backend.retrieve_v20(encoded) {
        Ok(candidates) => ChromiumKeyOutcome::success_zeroizing(candidates).unwrap_or_else(|| {
          ChromiumKeyOutcome::failure(format!(
            "Chromium v20 provider returned no key candidates. This vendor may use \
             app-bound elevation keys rookie doesn't have (only Google Chrome's are \
             known); {legacy_note}."
          ))
        }),
        Err(error) => ChromiumKeyOutcome::failure(format!(
          "App-Bound v20 decryption failed: {error}. This vendor may use elevation \
           keys rookie doesn't have (only Google Chrome's are known); {legacy_note}."
        )),
      }
    }
  };

  ChromiumKeyOutcomes {
    v10,
    v11: ChromiumKeyOutcome::NotApplicable,
    v20,
  }
}

#[cfg(target_os = "windows")]
pub(crate) struct WindowsPlatformKeyProvider<'a> {
  local_state: &'a serde_json::Value,
}

#[cfg(target_os = "windows")]
impl<'a> WindowsPlatformKeyProvider<'a> {
  pub(crate) fn new(local_state: &'a serde_json::Value) -> Self {
    Self { local_state }
  }
}

#[cfg(target_os = "windows")]
impl ChromiumKeyProvider<()> for WindowsPlatformKeyProvider<'_> {
  fn retrieve(&self, _context: &()) -> ChromiumKeyOutcomes {
    retrieve_windows_key_outcomes(self.local_state, &SystemWindowsKeyBackend)
  }
}

#[cfg(target_os = "linux")]
trait LinuxKeyringBackend {
  fn passwords(&self, crypt_name: &str) -> Result<Vec<Zeroizing<String>>>;
}

#[cfg(target_os = "linux")]
struct SystemLinuxKeyringBackend;

#[cfg(target_os = "linux")]
impl LinuxKeyringBackend for SystemLinuxKeyringBackend {
  fn passwords(&self, crypt_name: &str) -> Result<Vec<Zeroizing<String>>> {
    crate::linux::get_passwords(crypt_name)
  }
}

#[cfg(target_os = "linux")]
fn linux_v10_outcome() -> ChromiumKeyOutcome {
  let salt = b"saltysalt";
  ChromiumKeyOutcome::success_zeroizing(vec![
    create_pbkdf2_key("peanuts", salt, 1),
    create_pbkdf2_key("", salt, 1),
  ])
  .expect("Linux v10 has two fixed candidates")
}

#[cfg(target_os = "linux")]
fn retrieve_linux_v11_outcome<B>(crypt_name: &str, backend: &B) -> ChromiumKeyOutcome
where
  B: LinuxKeyringBackend,
{
  let salt = b"saltysalt";
  let candidates = backend.passwords(crypt_name).map(|passwords| {
    passwords
      .into_iter()
      .map(|password| create_pbkdf2_key(&password, salt, 1))
      .collect()
  });
  outcome_from_result(
    candidates,
    "Chromium v11 keyring provider returned no key candidates",
  )
}

#[cfg(target_os = "linux")]
fn retrieve_linux_key_outcomes<B>(config: &Browser, backend: &B) -> ChromiumKeyOutcomes
where
  B: LinuxKeyringBackend,
{
  let v11 = match config
    .unix_crypt_name
    .as_deref()
    .filter(|name| !name.is_empty())
  {
    None => ChromiumKeyOutcome::NotApplicable,
    Some(crypt_name) => retrieve_linux_v11_outcome(crypt_name, backend),
  };

  ChromiumKeyOutcomes {
    v10: linux_v10_outcome(),
    v11,
    v20: ChromiumKeyOutcome::NotApplicable,
  }
}

/// Per-`any_browser` Linux key cache.
///
/// Several browser configurations deliberately share a `unix_crypt_name`.
/// Caching the typed outcome (including failures) prevents repeated D-Bus
/// calls and unlock prompts without discarding the diagnostics produced by the
/// hardened keyring provider.
#[cfg(target_os = "linux")]
pub(crate) struct LinuxKeyOutcomeCache {
  v11_by_crypt_name: std::collections::HashMap<String, ChromiumKeyOutcome>,
}

#[cfg(target_os = "linux")]
impl LinuxKeyOutcomeCache {
  pub(crate) fn new() -> Self {
    Self {
      v11_by_crypt_name: std::collections::HashMap::new(),
    }
  }

  pub(crate) fn outcomes_for(&mut self, config: &Browser) -> ChromiumKeyOutcomes {
    self.outcomes_for_with_backend(config, &SystemLinuxKeyringBackend)
  }

  fn outcomes_for_with_backend<B>(&mut self, config: &Browser, backend: &B) -> ChromiumKeyOutcomes
  where
    B: LinuxKeyringBackend,
  {
    let v11 = match config
      .unix_crypt_name
      .as_deref()
      .filter(|name| !name.is_empty())
    {
      None => ChromiumKeyOutcome::NotApplicable,
      Some(crypt_name) => self
        .v11_by_crypt_name
        .entry(crypt_name.to_string())
        .or_insert_with(|| retrieve_linux_v11_outcome(crypt_name, backend))
        .clone(),
    };

    ChromiumKeyOutcomes {
      v10: linux_v10_outcome(),
      v11,
      v20: ChromiumKeyOutcome::NotApplicable,
    }
  }
}

#[cfg(target_os = "linux")]
pub(crate) struct LinuxPlatformKeyProvider<'a> {
  config: &'a Browser,
}

#[cfg(target_os = "linux")]
impl<'a> LinuxPlatformKeyProvider<'a> {
  pub(crate) fn new(config: &'a Browser) -> Self {
    Self { config }
  }
}

#[cfg(target_os = "linux")]
impl ChromiumKeyProvider<()> for LinuxPlatformKeyProvider<'_> {
  fn retrieve(&self, _context: &()) -> ChromiumKeyOutcomes {
    retrieve_linux_key_outcomes(self.config, &SystemLinuxKeyringBackend)
  }
}

#[cfg(target_os = "macos")]
trait MacosKeychainBackend {
  fn password(&self, service: &str, user: &str) -> Result<Zeroizing<String>>;
}

#[cfg(target_os = "macos")]
struct SystemMacosKeychainBackend;

#[cfg(target_os = "macos")]
impl MacosKeychainBackend for SystemMacosKeychainBackend {
  fn password(&self, service: &str, user: &str) -> Result<Zeroizing<String>> {
    crate::macos::get_osx_keychain_password(service, user)
  }
}

#[cfg(target_os = "macos")]
fn retrieve_macos_key_outcomes<B>(config: &Browser, backend: &B) -> ChromiumKeyOutcomes
where
  B: MacosKeychainBackend,
{
  let v10 = match (&config.osx_key_service, &config.osx_key_user) {
    (Some(service), Some(user)) if !service.is_empty() && !user.is_empty() => {
      match backend.password(service, user) {
        Ok(password) => ChromiumKeyOutcome::success_zeroizing(vec![create_pbkdf2_key(
          &password,
          b"saltysalt",
          1003,
        )])
        .expect("a successful macOS Keychain lookup yields one candidate"),
        Err(error) => {
          let diagnostic = format!("macOS Keychain lookup failed: {error:#}");
          log::warn!("{diagnostic}");
          ChromiumKeyOutcome::failure(diagnostic)
        }
      }
    }
    (None, None) => ChromiumKeyOutcome::NotApplicable,
    _ => ChromiumKeyOutcome::failure(
      "macOS Keychain configuration requires non-empty service and account values",
    ),
  };

  ChromiumKeyOutcomes {
    v10,
    v11: ChromiumKeyOutcome::NotApplicable,
    v20: ChromiumKeyOutcome::NotApplicable,
  }
}

#[cfg(target_os = "macos")]
pub(crate) struct MacosPlatformKeyProvider<'a> {
  config: &'a Browser,
}

#[cfg(target_os = "macos")]
impl<'a> MacosPlatformKeyProvider<'a> {
  pub(crate) fn new(config: &'a Browser) -> Self {
    Self { config }
  }
}

#[cfg(target_os = "macos")]
impl ChromiumKeyProvider<()> for MacosPlatformKeyProvider<'_> {
  fn retrieve(&self, _context: &()) -> ChromiumKeyOutcomes {
    retrieve_macos_key_outcomes(self.config, &SystemMacosKeychainBackend)
  }
}

#[cfg(test)]
mod tests {
  #[cfg(any(target_os = "linux", target_os = "windows"))]
  use super::super::chromium_crypto::ChromiumKeyTier;
  use super::super::chromium_crypto::{ChromiumCipherVersion, ChromiumKeyRoute};
  use super::*;
  use std::cell::Cell;

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn candidate_bytes(
    outcomes: &ChromiumKeyOutcomes,
    cipher: ChromiumCipherVersion,
  ) -> Vec<Vec<u8>> {
    let ChromiumKeyRoute::Candidates { candidates, .. } = outcomes.route(cipher) else {
      panic!("expected candidates for {cipher:?}");
    };
    candidates
      .iter()
      .map(|candidate| candidate.as_bytes().to_vec())
      .collect()
  }

  #[cfg(target_os = "linux")]
  struct FakeLinuxBackend {
    calls: Cell<usize>,
    result: Result<Vec<Zeroizing<String>>>,
  }

  #[cfg(target_os = "linux")]
  impl LinuxKeyringBackend for FakeLinuxBackend {
    fn passwords(&self, _crypt_name: &str) -> Result<Vec<Zeroizing<String>>> {
      self.calls.set(self.calls.get() + 1);
      self
        .result
        .as_ref()
        .map(Clone::clone)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
    }
  }

  #[cfg(target_os = "linux")]
  fn linux_config(crypt_name: Option<&str>) -> Browser {
    Browser {
      paths: vec![],
      channels: None,
      unix_crypt_name: crypt_name.map(str::to_string),
      osx_key_service: None,
      osx_key_user: None,
    }
  }

  #[cfg(target_os = "linux")]
  #[test]
  fn linux_separates_fixed_v10_from_ordered_keyring_v11_candidates() {
    let backend = FakeLinuxBackend {
      calls: Cell::new(0),
      result: Ok(vec![
        Zeroizing::new("first".to_string()),
        Zeroizing::new("second".to_string()),
      ]),
    };
    let outcomes = retrieve_linux_key_outcomes(&linux_config(Some("chrome")), &backend);

    assert_eq!(backend.calls.get(), 1);
    assert_eq!(
      candidate_bytes(&outcomes, ChromiumCipherVersion::V10),
      vec![
        Vec::from(create_pbkdf2_key("peanuts", b"saltysalt", 1).as_slice()),
        Vec::from(create_pbkdf2_key("", b"saltysalt", 1).as_slice()),
      ]
    );
    assert_eq!(
      candidate_bytes(&outcomes, ChromiumCipherVersion::V11),
      vec![
        Vec::from(create_pbkdf2_key("first", b"saltysalt", 1).as_slice()),
        Vec::from(create_pbkdf2_key("second", b"saltysalt", 1).as_slice()),
      ]
    );
    assert_eq!(
      outcomes.route(ChromiumCipherVersion::V20),
      ChromiumKeyRoute::NotApplicable {
        tier: ChromiumKeyTier::V20
      }
    );
  }

  #[cfg(target_os = "linux")]
  #[test]
  fn linux_keyring_failure_preserves_v10_and_is_scoped_to_v11() {
    let backend = FakeLinuxBackend {
      calls: Cell::new(0),
      result: Err(anyhow::anyhow!("keyring unavailable")),
    };
    let outcomes = retrieve_linux_key_outcomes(&linux_config(Some("chrome")), &backend);

    assert_eq!(backend.calls.get(), 1);
    assert!(matches!(
      outcomes.route(ChromiumCipherVersion::V10),
      ChromiumKeyRoute::Candidates {
        tier: ChromiumKeyTier::V10,
        ..
      }
    ));
    let ChromiumKeyRoute::Failure { tier, failure } = outcomes.route(ChromiumCipherVersion::V11)
    else {
      panic!("expected failed v11 keyring route");
    };
    assert_eq!(tier, ChromiumKeyTier::V11);
    assert_eq!(failure.message(), "keyring unavailable");
  }

  #[cfg(target_os = "linux")]
  #[test]
  fn linux_empty_keyring_result_is_a_v11_failure() {
    let backend = FakeLinuxBackend {
      calls: Cell::new(0),
      result: Ok(vec![]),
    };
    let outcomes = retrieve_linux_key_outcomes(&linux_config(Some("chrome")), &backend);

    assert_eq!(backend.calls.get(), 1);
    assert!(matches!(
      outcomes.route(ChromiumCipherVersion::V10),
      ChromiumKeyRoute::Candidates { .. }
    ));
    assert!(matches!(
      outcomes.route(ChromiumCipherVersion::V11),
      ChromiumKeyRoute::Failure {
        tier: ChromiumKeyTier::V11,
        ..
      }
    ));
  }

  #[cfg(target_os = "linux")]
  #[test]
  fn linux_without_keyring_configuration_does_not_call_backend() {
    let backend = FakeLinuxBackend {
      calls: Cell::new(0),
      result: Ok(vec![Zeroizing::new("unused".to_string())]),
    };
    let outcomes = retrieve_linux_key_outcomes(&linux_config(None), &backend);

    assert_eq!(backend.calls.get(), 0);
    assert!(matches!(
      outcomes.route(ChromiumCipherVersion::V10),
      ChromiumKeyRoute::Candidates { .. }
    ));
    assert_eq!(
      outcomes.route(ChromiumCipherVersion::V11),
      ChromiumKeyRoute::NotApplicable {
        tier: ChromiumKeyTier::V11
      }
    );
  }

  #[cfg(target_os = "linux")]
  #[test]
  fn linux_any_browser_cache_reuses_success_per_crypt_name() {
    let backend = FakeLinuxBackend {
      calls: Cell::new(0),
      result: Ok(vec![Zeroizing::new("shared secret".to_string())]),
    };
    let mut cache = LinuxKeyOutcomeCache::new();

    let chrome = cache.outcomes_for_with_backend(&linux_config(Some("chrome")), &backend);
    let vivaldi = cache.outcomes_for_with_backend(&linux_config(Some("chrome")), &backend);
    let brave = cache.outcomes_for_with_backend(&linux_config(Some("brave")), &backend);

    assert_eq!(backend.calls.get(), 2, "one call per distinct crypt name");
    assert_eq!(
      candidate_bytes(&chrome, ChromiumCipherVersion::V11),
      candidate_bytes(&vivaldi, ChromiumCipherVersion::V11)
    );
    assert_eq!(
      candidate_bytes(&brave, ChromiumCipherVersion::V11),
      vec![Vec::from(
        create_pbkdf2_key("shared secret", b"saltysalt", 1).as_slice()
      )]
    );
  }

  #[cfg(target_os = "linux")]
  #[test]
  fn linux_any_browser_cache_reuses_explicit_failure_diagnostics() {
    let backend = FakeLinuxBackend {
      calls: Cell::new(0),
      result: Err(anyhow::anyhow!("locked keyring")),
    };
    let mut cache = LinuxKeyOutcomeCache::new();

    let first = cache.outcomes_for_with_backend(&linux_config(Some("chromium")), &backend);
    let second = cache.outcomes_for_with_backend(&linux_config(Some("chromium")), &backend);

    assert_eq!(backend.calls.get(), 1);
    for outcomes in [&first, &second] {
      let ChromiumKeyRoute::Failure { failure, .. } = outcomes.route(ChromiumCipherVersion::V11)
      else {
        panic!("cached keyring failure must stay explicit");
      };
      assert_eq!(failure.message(), "locked keyring");
    }
  }

  #[cfg(target_os = "windows")]
  struct FakeWindowsBackend {
    v10_calls: Cell<usize>,
    v20_calls: Cell<usize>,
    compiled: bool,
    privileged: bool,
    v10_result: Result<Vec<Zeroizing<Vec<u8>>>>,
    v20_result: Result<Vec<Zeroizing<Vec<u8>>>>,
  }

  #[cfg(target_os = "windows")]
  impl WindowsKeyBackend for FakeWindowsBackend {
    fn retrieve_v10(&self, _encoded_key: &str) -> Result<Vec<Zeroizing<Vec<u8>>>> {
      self.v10_calls.set(self.v10_calls.get() + 1);
      self
        .v10_result
        .as_ref()
        .map(Clone::clone)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    fn appbound_compiled(&self) -> bool {
      self.compiled
    }

    fn privileged(&self) -> bool {
      self.privileged
    }

    fn retrieve_v20(&self, _encoded_key: &str) -> Result<Vec<Zeroizing<Vec<u8>>>> {
      self.v20_calls.set(self.v20_calls.get() + 1);
      self
        .v20_result
        .as_ref()
        .map(Clone::clone)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
    }
  }

  #[cfg(target_os = "windows")]
  fn windows_backend(
    v10_result: Result<Vec<Vec<u8>>>,
    v20_result: Result<Vec<Vec<u8>>>,
  ) -> FakeWindowsBackend {
    FakeWindowsBackend {
      v10_calls: Cell::new(0),
      v20_calls: Cell::new(0),
      compiled: true,
      privileged: true,
      v10_result: v10_result.map(|candidates| candidates.into_iter().map(Zeroizing::new).collect()),
      v20_result: v20_result.map(|candidates| candidates.into_iter().map(Zeroizing::new).collect()),
    }
  }

  #[cfg(target_os = "windows")]
  fn windows_local_state(v10: serde_json::Value, v20: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
      "os_crypt": {
        "encrypted_key": v10,
        "app_bound_encrypted_key": v20
      }
    })
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn windows_v20_failure_does_not_discard_v10() {
    let backend = windows_backend(Ok(vec![vec![0x10; 32]]), Err(anyhow::anyhow!("v20 failed")));
    let outcomes = retrieve_windows_key_outcomes(
      &windows_local_state(serde_json::json!("legacy"), serde_json::json!("appbound")),
      &backend,
    );

    assert_eq!(backend.v10_calls.get(), 1);
    assert_eq!(backend.v20_calls.get(), 1);
    assert!(matches!(
      outcomes.route(ChromiumCipherVersion::V10),
      ChromiumKeyRoute::Candidates { .. }
    ));
    assert!(matches!(
      outcomes.route(ChromiumCipherVersion::V20),
      ChromiumKeyRoute::Failure { .. }
    ));
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn windows_v20_failure_message_reassures_legacy_when_v10_succeeded() {
    let backend = windows_backend(Ok(vec![vec![0x10; 32]]), Err(anyhow::anyhow!("v20 failed")));
    let outcomes = retrieve_windows_key_outcomes(
      &windows_local_state(serde_json::json!("legacy"), serde_json::json!("appbound")),
      &backend,
    );

    let ChromiumKeyRoute::Failure { failure, .. } = outcomes.route(ChromiumCipherVersion::V20)
    else {
      panic!("expected v20 failure");
    };
    assert!(failure
      .message()
      .contains("legacy v10/v11 cookies are unaffected"));
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn windows_v20_failure_message_warns_about_legacy_when_v10_also_failed() {
    let backend = windows_backend(
      Err(anyhow::anyhow!("v10 failed")),
      Err(anyhow::anyhow!("v20 failed")),
    );
    let outcomes = retrieve_windows_key_outcomes(
      &windows_local_state(serde_json::json!("legacy"), serde_json::json!("appbound")),
      &backend,
    );

    let ChromiumKeyRoute::Failure { failure, .. } = outcomes.route(ChromiumCipherVersion::V20)
    else {
      panic!("expected v20 failure");
    };
    assert!(!failure
      .message()
      .contains("legacy v10/v11 cookies are unaffected"));
    assert!(failure
      .message()
      .contains("legacy v10/v11 cookies may also have failed"));
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn windows_v10_failure_does_not_discard_v20() {
    let backend = windows_backend(Err(anyhow::anyhow!("v10 failed")), Ok(vec![vec![0x20; 32]]));
    let outcomes = retrieve_windows_key_outcomes(
      &windows_local_state(serde_json::json!("legacy"), serde_json::json!("appbound")),
      &backend,
    );

    assert_eq!(backend.v10_calls.get(), 1);
    assert_eq!(backend.v20_calls.get(), 1);
    assert!(matches!(
      outcomes.route(ChromiumCipherVersion::V10),
      ChromiumKeyRoute::Failure { .. }
    ));
    assert!(matches!(
      outcomes.route(ChromiumCipherVersion::V20),
      ChromiumKeyRoute::Candidates { .. }
    ));
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn windows_non_admin_and_unavailable_v20_preserve_v10_without_calling_v20() {
    for (compiled, privileged) in [(false, true), (true, false)] {
      let mut backend = windows_backend(Ok(vec![vec![0x10; 32]]), Ok(vec![vec![0x20; 32]]));
      backend.compiled = compiled;
      backend.privileged = privileged;
      let outcomes = retrieve_windows_key_outcomes(
        &windows_local_state(serde_json::json!("legacy"), serde_json::json!("appbound")),
        &backend,
      );

      assert_eq!(backend.v10_calls.get(), 1);
      assert_eq!(backend.v20_calls.get(), 0);
      assert!(matches!(
        outcomes.route(ChromiumCipherVersion::V10),
        ChromiumKeyRoute::Candidates { .. }
      ));
      assert!(matches!(
        outcomes.route(ChromiumCipherVersion::V20),
        ChromiumKeyRoute::Failure { .. }
      ));
    }
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn windows_invalid_one_field_preserves_the_other() {
    let backend = windows_backend(Ok(vec![vec![0x10; 32]]), Ok(vec![vec![0x20; 32]]));
    let outcomes = retrieve_windows_key_outcomes(
      &windows_local_state(serde_json::json!(false), serde_json::json!("appbound")),
      &backend,
    );
    assert_eq!(backend.v10_calls.get(), 0);
    assert_eq!(backend.v20_calls.get(), 1);
    assert!(matches!(
      outcomes.route(ChromiumCipherVersion::V10),
      ChromiumKeyRoute::Failure { .. }
    ));
    assert!(matches!(
      outcomes.route(ChromiumCipherVersion::V20),
      ChromiumKeyRoute::Candidates { .. }
    ));
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn windows_missing_appbound_metadata_does_not_call_v20() {
    let backend = windows_backend(Ok(vec![vec![0x10; 32]]), Ok(vec![vec![0x20; 32]]));
    let state = serde_json::json!({"os_crypt": {"encrypted_key": "legacy"}});
    let outcomes = retrieve_windows_key_outcomes(&state, &backend);
    assert_eq!(backend.v10_calls.get(), 1);
    assert_eq!(backend.v20_calls.get(), 0);
    assert_eq!(
      outcomes.route(ChromiumCipherVersion::V20),
      ChromiumKeyRoute::NotApplicable {
        tier: ChromiumKeyTier::V20
      }
    );
  }

  #[cfg(all(target_os = "windows", not(feature = "appbound")))]
  #[test]
  fn windows_no_appbound_build_reports_present_v20_metadata_as_failure() {
    let state = serde_json::json!({"os_crypt": {"app_bound_encrypted_key": "appbound"}});
    let outcomes = retrieve_windows_key_outcomes(&state, &SystemWindowsKeyBackend);
    assert!(matches!(
      outcomes.route(ChromiumCipherVersion::V20),
      ChromiumKeyRoute::Failure { .. }
    ));
  }

  #[cfg(target_os = "macos")]
  struct FakeMacosBackend {
    calls: Cell<usize>,
    result: Result<Zeroizing<String>>,
  }

  #[cfg(target_os = "macos")]
  impl MacosKeychainBackend for FakeMacosBackend {
    fn password(&self, _service: &str, _user: &str) -> Result<Zeroizing<String>> {
      self.calls.set(self.calls.get() + 1);
      self
        .result
        .as_ref()
        .map(Clone::clone)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
    }
  }

  #[cfg(target_os = "macos")]
  fn macos_config() -> Browser {
    Browser {
      paths: vec![],
      channels: None,
      unix_crypt_name: None,
      osx_key_service: Some("Chrome Safe Storage".to_string()),
      osx_key_user: Some("Chrome".to_string()),
    }
  }

  #[cfg(target_os = "macos")]
  #[test]
  fn macos_uses_only_the_password_returned_by_keychain() {
    let backend = FakeMacosBackend {
      calls: Cell::new(0),
      result: Ok(Zeroizing::new("keychain".to_string())),
    };
    let outcomes = retrieve_macos_key_outcomes(&macos_config(), &backend);
    assert_eq!(backend.calls.get(), 1);
    assert_eq!(
      candidate_bytes(&outcomes, ChromiumCipherVersion::V10),
      [Vec::from(
        create_pbkdf2_key("keychain", b"saltysalt", 1003).as_slice()
      )]
    );
    assert!(matches!(
      outcomes.route(ChromiumCipherVersion::V11),
      ChromiumKeyRoute::NotApplicable { .. }
    ));
    assert!(matches!(
      outcomes.route(ChromiumCipherVersion::V20),
      ChromiumKeyRoute::NotApplicable { .. }
    ));
  }

  #[cfg(target_os = "macos")]
  #[test]
  fn macos_keychain_failure_is_a_typed_provider_failure() {
    let backend = FakeMacosBackend {
      calls: Cell::new(0),
      result: Err(anyhow::anyhow!("keychain unavailable")),
    };
    let outcomes = retrieve_macos_key_outcomes(&macos_config(), &backend);
    assert_eq!(backend.calls.get(), 1);
    let ChromiumKeyRoute::Failure { failure, .. } = outcomes.route(ChromiumCipherVersion::V10)
    else {
      panic!("Keychain failure must not silently install fallback candidates");
    };
    assert!(failure.message().contains("keychain unavailable"));
  }

  #[cfg(target_os = "macos")]
  #[test]
  fn macos_mock_password_is_used_only_when_the_configured_backend_returns_it() {
    let backend = FakeMacosBackend {
      calls: Cell::new(0),
      result: Ok(Zeroizing::new("mock_password".to_string())),
    };
    let outcomes = retrieve_macos_key_outcomes(&macos_config(), &backend);
    assert_eq!(
      candidate_bytes(&outcomes, ChromiumCipherVersion::V10),
      [Vec::from(
        create_pbkdf2_key("mock_password", b"saltysalt", 1003).as_slice()
      )]
    );
  }

  #[cfg(target_os = "macos")]
  #[test]
  fn macos_without_keychain_identity_has_no_implicit_candidates() {
    let backend = FakeMacosBackend {
      calls: Cell::new(0),
      result: Ok(Zeroizing::new("must not be read".to_string())),
    };
    let config = Browser {
      osx_key_service: None,
      osx_key_user: None,
      ..macos_config()
    };
    let outcomes = retrieve_macos_key_outcomes(&config, &backend);
    assert_eq!(backend.calls.get(), 0);
    assert!(matches!(
      outcomes.route(ChromiumCipherVersion::V10),
      ChromiumKeyRoute::NotApplicable { .. }
    ));
  }
}
