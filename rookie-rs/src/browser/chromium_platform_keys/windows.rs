use super::super::chromium_crypto::{ChromiumKeyOutcome, ChromiumKeyOutcomes, KeyProvider};
use super::shared::outcome_from_result;
use super::{ChromiumKeyRequest, LocalStateInput};
use anyhow::{bail, Result};
use base64::{engine::general_purpose, Engine as _};
use zeroize::Zeroizing;

use crate::common::secret::SecretBytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalStateKey<'a> {
  Missing,
  InvalidType,
  Encoded(&'a str),
}

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

trait WindowsKeyBackend {
  fn retrieve_v10(&self, encoded_key: &str) -> Result<Vec<Zeroizing<Vec<u8>>>>;
  fn appbound_compiled(&self) -> bool;
  fn privileged(&self) -> bool;
  fn retrieve_v20(&self, encoded_key: &str) -> Result<Vec<Zeroizing<Vec<u8>>>>;
}

struct SystemWindowsKeyBackend;

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
    let v10_key = crate::windows::dpapi::decrypt(&wrapped[5..])
      .map(SecretBytes::into_zeroizing_vec)
      .map_err(|error| {
        anyhow::anyhow!(
          "Failed to unwrap DPAPI encrypted key (decoded_length={decoded_len}, wrapped_length={wrapped_len}): {error}"
        )
      })?;
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

trait LocalStateReader {
  fn read_to_string(&self, path: &std::path::Path) -> Result<String>;
}

struct SystemLocalStateReader;

impl LocalStateReader for SystemLocalStateReader {
  fn read_to_string(&self, path: &std::path::Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(anyhow::Error::from)
  }
}

fn host_key_outcomes<R>(request: ChromiumKeyRequest<'_>, reader: &R) -> ChromiumKeyOutcomes
where
  R: LocalStateReader,
{
  let parsed;
  let local_state = match request.local_state {
    LocalStateInput::Parsed(local_state) => local_state,
    LocalStateInput::Path(path) => {
      parsed = reader
        .read_to_string(path)
        .and_then(|contents| serde_json::from_str(&contents).map_err(anyhow::Error::from));
      match &parsed {
        Ok(local_state) => local_state,
        Err(error) => {
          return ChromiumKeyOutcomes {
            v10: ChromiumKeyOutcome::failure(format!(
              "failed to read installation Local State: {error}"
            )),
            v11: ChromiumKeyOutcome::NotApplicable,
            v20: ChromiumKeyOutcome::failure(format!(
              "failed to read installation Local State: {error}"
            )),
          }
        }
      }
    }
    LocalStateInput::NotApplicable => return ChromiumKeyOutcomes::default(),
  };
  retrieve_windows_key_outcomes(local_state, &SystemWindowsKeyBackend)
}

pub(crate) struct HostKeySession;

impl HostKeySession {
  pub(crate) fn new() -> Self {
    Self
  }

  pub(crate) fn retrieve(
    &mut self,
    request: ChromiumKeyRequest<'_>,
    deadline: crate::common::deadline::Deadline,
  ) -> ChromiumKeyOutcomes {
    if let Err(error) = deadline.check(&crate::common::deadline::SystemClock) {
      return ChromiumKeyOutcomes::provider_failure(error.to_string());
    }
    host_key_outcomes(request, &SystemLocalStateReader)
  }
}

pub(crate) struct WindowsPlatformKeyProvider<'a> {
  local_state: &'a serde_json::Value,
}

impl<'a> WindowsPlatformKeyProvider<'a> {
  pub(crate) fn new(local_state: &'a serde_json::Value) -> Self {
    Self { local_state }
  }
}

impl KeyProvider<()> for WindowsPlatformKeyProvider<'_> {
  type Keys = ChromiumKeyOutcomes;

  fn keys(
    &self,
    _context: &(),
    deadline: crate::common::deadline::Deadline,
  ) -> ChromiumKeyOutcomes {
    let credentials = super::ChromiumKeyCredentials::default();
    let mut session = HostKeySession::new();
    session.retrieve(
      ChromiumKeyRequest::for_parsed_local_state(&credentials, self.local_state),
      deadline,
    )
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::browser::chromium_crypto::{ChromiumCipherVersion, ChromiumKeyRoute, ChromiumKeyTier};
  use std::cell::Cell;

  struct CountingLocalStateReader {
    calls: Cell<usize>,
    result: Result<String>,
  }

  impl LocalStateReader for CountingLocalStateReader {
    fn read_to_string(&self, _path: &std::path::Path) -> Result<String> {
      self.calls.set(self.calls.get() + 1);
      self
        .result
        .as_ref()
        .map(Clone::clone)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
    }
  }

  struct FakeWindowsBackend {
    v10_calls: Cell<usize>,
    v20_calls: Cell<usize>,
    compiled: bool,
    privileged: bool,
    v10_result: Result<Vec<Zeroizing<Vec<u8>>>>,
    v20_result: Result<Vec<Zeroizing<Vec<u8>>>>,
  }

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

  fn windows_local_state(v10: serde_json::Value, v20: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
      "os_crypt": {
        "encrypted_key": v10,
        "app_bound_encrypted_key": v20
      }
    })
  }

  #[test]
  fn parsed_local_state_wins_without_a_session_read() {
    let credentials = super::super::ChromiumKeyCredentials::default();
    let local_state = serde_json::json!({});
    let reader = CountingLocalStateReader {
      calls: Cell::new(0),
      result: Err(anyhow::anyhow!("Local State path must not be read")),
    };
    let outcomes = host_key_outcomes(
      ChromiumKeyRequest::for_installation(
        "chrome",
        &credentials,
        std::path::Path::new("must-not-be-read/Local State"),
        Some(&local_state),
      ),
      &reader,
    );

    assert_eq!(reader.calls.get(), 0);
    assert_eq!(outcomes, ChromiumKeyOutcomes::default());
  }

  #[test]
  fn local_state_path_is_read_once_and_failures_keep_independent_tier_outcomes() {
    let credentials = super::super::ChromiumKeyCredentials::default();
    let path = std::path::Path::new("Local State");

    let success_reader = CountingLocalStateReader {
      calls: Cell::new(0),
      result: Ok("{}".to_string()),
    };
    let success = host_key_outcomes(
      ChromiumKeyRequest::for_installation("chrome", &credentials, path, None),
      &success_reader,
    );
    assert_eq!(success_reader.calls.get(), 1);
    assert_eq!(success, ChromiumKeyOutcomes::default());

    for (reader, expected) in [
      (
        CountingLocalStateReader {
          calls: Cell::new(0),
          result: Err(anyhow::anyhow!("read denied")),
        },
        "failed to read installation Local State: read denied",
      ),
      (
        CountingLocalStateReader {
          calls: Cell::new(0),
          result: Ok("{".to_string()),
        },
        "failed to read installation Local State: EOF while parsing an object at line 1 column 1",
      ),
    ] {
      let outcomes = host_key_outcomes(
        ChromiumKeyRequest::for_installation("chrome", &credentials, path, None),
        &reader,
      );
      assert_eq!(reader.calls.get(), 1);
      for outcome in [&outcomes.v10, &outcomes.v20] {
        let ChromiumKeyOutcome::Failure(failure) = outcome else {
          panic!("Local State failures must fail both Windows key tiers");
        };
        assert_eq!(failure.message(), expected);
      }
      assert_eq!(outcomes.v11, ChromiumKeyOutcome::NotApplicable);
    }
  }

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

  #[cfg(not(feature = "appbound"))]
  #[test]
  fn windows_no_appbound_build_reports_present_v20_metadata_as_failure() {
    let state = serde_json::json!({"os_crypt": {"app_bound_encrypted_key": "appbound"}});
    let outcomes = retrieve_windows_key_outcomes(&state, &SystemWindowsKeyBackend);
    assert!(matches!(
      outcomes.route(ChromiumCipherVersion::V20),
      ChromiumKeyRoute::Failure { .. }
    ));
  }
}
