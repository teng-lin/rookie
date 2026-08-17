use super::super::chromium_crypto::{ChromiumKeyOutcome, ChromiumKeyOutcomes};
use super::shared::outcome_from_result;
use super::{ChromiumKeyRequest, LocalStateInput};
use anyhow::{bail, Result};
use base64::{engine::general_purpose, Engine as _};
use zeroize::Zeroizing;

use crate::browser::outcome::Retryability;
use crate::common::deadline::BoundaryRuntime;
#[cfg(test)]
use crate::common::deadline::{Deadline, SystemClock};
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
  fn retrieve_v10(
    &self,
    encoded_key: &str,
    runtime: &BoundaryRuntime<'_>,
  ) -> Result<Vec<Zeroizing<Vec<u8>>>>;
  fn appbound_compiled(&self) -> bool;
  fn retrieve_v20(
    &self,
    encoded_key: &str,
    browser_hint: Option<&str>,
    runtime: &BoundaryRuntime<'_>,
  ) -> Result<Vec<Zeroizing<Vec<u8>>>>;
}

struct SystemWindowsKeyBackend;

impl WindowsKeyBackend for SystemWindowsKeyBackend {
  fn retrieve_v10(
    &self,
    encoded_key: &str,
    runtime: &BoundaryRuntime<'_>,
  ) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    runtime.check()?;
    let wrapped: Vec<u8> = general_purpose::STANDARD
      .decode(encoded_key)
      .map_err(|error| {
        anyhow::anyhow!("Failed to decode Local State os_crypt.encrypted_key as base64: {error}")
      })?;
    runtime.check()?;
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

    runtime.check()?;
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
    runtime.check()?;
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

  fn retrieve_v20(
    &self,
    encoded_key: &str,
    browser_hint: Option<&str>,
    runtime: &BoundaryRuntime<'_>,
  ) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    runtime.check()?;
    #[cfg(feature = "appbound")]
    {
      let keys = crate::windows::appbound::get_keys_with_hint(encoded_key, browser_hint)?;
      runtime.check()?;
      Ok(keys)
    }

    #[cfg(not(feature = "appbound"))]
    {
      let _ = (encoded_key, browser_hint);
      bail!("Chromium v20 app-bound provider is unavailable in this build")
    }
  }
}

#[cfg(test)]
fn retrieve_windows_key_outcomes<B>(
  local_state: &serde_json::Value,
  backend: &B,
) -> ChromiumKeyOutcomes
where
  B: WindowsKeyBackend,
{
  let clock = SystemClock;
  let runtime = BoundaryRuntime::new(&clock, Deadline::standard());
  retrieve_windows_key_outcomes_with_runtime(local_state, None, backend, &runtime)
}

fn checked_boundary<T>(
  runtime: &BoundaryRuntime<'_>,
  operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
  runtime.check()?;
  let result = operation();
  runtime.check()?;
  result
}

fn provider_failure(message: String) -> ChromiumKeyOutcomes {
  ChromiumKeyOutcomes {
    v10: ChromiumKeyOutcome::failure(message.clone()),
    v11: ChromiumKeyOutcome::NotApplicable,
    v20: ChromiumKeyOutcome::failure(message),
  }
}

fn retrieve_windows_key_outcomes_with_runtime<B>(
  local_state: &serde_json::Value,
  browser_hint: Option<&str>,
  backend: &B,
  runtime: &BoundaryRuntime<'_>,
) -> ChromiumKeyOutcomes
where
  B: WindowsKeyBackend,
{
  if let Err(error) = runtime.check() {
    return provider_failure(error.to_string());
  }
  let v10 = match local_state_key(local_state, "encrypted_key") {
    LocalStateKey::Missing => ChromiumKeyOutcome::NotApplicable,
    LocalStateKey::InvalidType => {
      ChromiumKeyOutcome::failure("Local State os_crypt.encrypted_key must be a base64 string")
    }
    LocalStateKey::Encoded(encoded) => outcome_from_result(
      checked_boundary(runtime, || backend.retrieve_v10(encoded, runtime)),
      "Chromium v10 provider returned no key candidates",
    ),
  };

  let v20 = if let Err(error) = runtime.check() {
    ChromiumKeyOutcome::failure(error.to_string())
  } else {
    match local_state_key(local_state, "app_bound_encrypted_key") {
      LocalStateKey::Missing => ChromiumKeyOutcome::NotApplicable,
      LocalStateKey::InvalidType => ChromiumKeyOutcome::failure_with_retryability(
        "Local State os_crypt.app_bound_encrypted_key must be a base64 string",
        Retryability::NotRetryable,
      ),
      LocalStateKey::Encoded(encoded) if general_purpose::STANDARD.decode(encoded).is_err() => {
        ChromiumKeyOutcome::failure_with_retryability(
          "Local State os_crypt.app_bound_encrypted_key is not valid base64",
          Retryability::NotRetryable,
        )
      }
      LocalStateKey::Encoded(_) if !backend.appbound_compiled() => {
        ChromiumKeyOutcome::failure("Chromium v20 app-bound provider is unavailable in this build")
      }
      LocalStateKey::Encoded(encoded) => {
        let legacy_note = if matches!(v10, ChromiumKeyOutcome::Success(_)) {
          "legacy v10/v11 cookies are unaffected"
        } else {
          "legacy v10/v11 cookies may also have failed to decrypt - check the v10 outcome separately"
        };
        match checked_boundary(runtime, || {
          backend.retrieve_v20(encoded, browser_hint, runtime)
        }) {
          Ok(candidates) => {
            ChromiumKeyOutcome::success_zeroizing(candidates).unwrap_or_else(|| {
              ChromiumKeyOutcome::failure(format!(
                "Chromium v20 provider returned no key candidates; {legacy_note}."
              ))
            })
          }
          Err(error) => ChromiumKeyOutcome::failure(format!(
            "App-Bound v20 decryption failed: {error}. {legacy_note}."
          )),
        }
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
  fn read_to_string(&self, path: &std::path::Path, runtime: &BoundaryRuntime<'_>)
    -> Result<String>;
}

struct SystemLocalStateReader;

impl LocalStateReader for SystemLocalStateReader {
  fn read_to_string(
    &self,
    path: &std::path::Path,
    runtime: &BoundaryRuntime<'_>,
  ) -> Result<String> {
    runtime.check()?;
    let contents = std::fs::read_to_string(path).map_err(anyhow::Error::from)?;
    runtime.check()?;
    Ok(contents)
  }
}

#[cfg(test)]
fn host_key_outcomes<R>(request: ChromiumKeyRequest<'_>, reader: &R) -> ChromiumKeyOutcomes
where
  R: LocalStateReader,
{
  let clock = SystemClock;
  let runtime = BoundaryRuntime::new(&clock, Deadline::standard());
  host_key_outcomes_with_runtime(request, reader, &SystemWindowsKeyBackend, &runtime)
}

fn host_key_outcomes_with_runtime<R, B>(
  request: ChromiumKeyRequest<'_>,
  reader: &R,
  backend: &B,
  runtime: &BoundaryRuntime<'_>,
) -> ChromiumKeyOutcomes
where
  R: LocalStateReader,
  B: WindowsKeyBackend,
{
  if let Err(error) = runtime.check() {
    return provider_failure(error.to_string());
  }
  let parsed;
  let local_state = match request.local_state {
    LocalStateInput::Parsed(local_state) => local_state,
    LocalStateInput::Path(path) => {
      parsed =
        checked_boundary(runtime, || reader.read_to_string(path, runtime)).and_then(|contents| {
          checked_boundary(runtime, || {
            serde_json::from_str(&contents).map_err(anyhow::Error::from)
          })
        });
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
  retrieve_windows_key_outcomes_with_runtime(local_state, request.browser_id, backend, runtime)
}

pub(crate) struct HostKeySession;

impl HostKeySession {
  pub(crate) fn new() -> Self {
    Self
  }

  pub(crate) fn retrieve(
    &mut self,
    request: ChromiumKeyRequest<'_>,
    runtime: &BoundaryRuntime<'_>,
  ) -> ChromiumKeyOutcomes {
    host_key_outcomes_with_runtime(
      request,
      &SystemLocalStateReader,
      &SystemWindowsKeyBackend,
      runtime,
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
    fn read_to_string(
      &self,
      _path: &std::path::Path,
      _runtime: &BoundaryRuntime<'_>,
    ) -> Result<String> {
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
    v10_result: Result<Vec<Zeroizing<Vec<u8>>>>,
    v20_result: Result<Vec<Zeroizing<Vec<u8>>>>,
  }

  impl WindowsKeyBackend for FakeWindowsBackend {
    fn retrieve_v10(
      &self,
      _encoded_key: &str,
      _runtime: &BoundaryRuntime<'_>,
    ) -> Result<Vec<Zeroizing<Vec<u8>>>> {
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

    fn retrieve_v20(
      &self,
      _encoded_key: &str,
      _browser_hint: Option<&str>,
      _runtime: &BoundaryRuntime<'_>,
    ) -> Result<Vec<Zeroizing<Vec<u8>>>> {
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
  fn windows_uncompiled_v20_preserves_v10_without_calling_v20() {
    let mut backend = windows_backend(Ok(vec![vec![0x10; 32]]), Ok(vec![vec![0x20; 32]]));
    backend.compiled = false;
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
  fn malformed_app_bound_metadata_is_typed_not_retryable_before_provider_access() {
    let backend = windows_backend(Ok(vec![vec![0x10; 32]]), Ok(vec![vec![0x20; 32]]));
    let outcomes = retrieve_windows_key_outcomes(
      &windows_local_state(serde_json::json!("legacy"), serde_json::json!("not-base64")),
      &backend,
    );

    assert_eq!(backend.v20_calls.get(), 0);
    let ChromiumKeyRoute::Failure { failure, .. } = outcomes.route(ChromiumCipherVersion::V20)
    else {
      panic!("malformed app-bound metadata must be a key failure");
    };
    assert_eq!(failure.retryability(), Retryability::NotRetryable);
    assert!(failure.message().contains("not valid base64"));
  }

  #[test]
  fn transient_app_bound_provider_failure_remains_typed_retryable() {
    let backend = windows_backend(
      Ok(vec![]),
      Err(anyhow::anyhow!("transient provider failure")),
    );
    let outcomes = retrieve_windows_key_outcomes(
      &serde_json::json!({"os_crypt": {"app_bound_encrypted_key": "YXBwYm91bmQ="}}),
      &backend,
    );

    let ChromiumKeyRoute::Failure { failure, .. } = outcomes.route(ChromiumCipherVersion::V20)
    else {
      panic!("provider failure remains typed");
    };
    assert_eq!(failure.retryability(), Retryability::Retryable);
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

  struct AdvancingLocalStateReader {
    calls: Cell<usize>,
    elapsed: std::time::Duration,
  }

  impl LocalStateReader for AdvancingLocalStateReader {
    fn read_to_string(
      &self,
      _path: &std::path::Path,
      runtime: &BoundaryRuntime<'_>,
    ) -> Result<String> {
      self.calls.set(self.calls.get() + 1);
      runtime.clock.sleep(self.elapsed);
      Ok("{}".to_string())
    }
  }

  struct AdvancingWindowsBackend {
    v10_calls: Cell<usize>,
    v20_calls: Cell<usize>,
    v10_elapsed: std::time::Duration,
    v20_elapsed: std::time::Duration,
  }

  impl AdvancingWindowsBackend {
    fn new() -> Self {
      Self {
        v10_calls: Cell::new(0),
        v20_calls: Cell::new(0),
        v10_elapsed: std::time::Duration::ZERO,
        v20_elapsed: std::time::Duration::ZERO,
      }
    }
  }

  impl WindowsKeyBackend for AdvancingWindowsBackend {
    fn retrieve_v10(
      &self,
      _encoded_key: &str,
      runtime: &BoundaryRuntime<'_>,
    ) -> Result<Vec<Zeroizing<Vec<u8>>>> {
      self.v10_calls.set(self.v10_calls.get() + 1);
      runtime.clock.sleep(self.v10_elapsed);
      Ok(vec![Zeroizing::new(vec![0x10; 32])])
    }

    fn appbound_compiled(&self) -> bool {
      true
    }

    fn retrieve_v20(
      &self,
      _encoded_key: &str,
      _browser_hint: Option<&str>,
      runtime: &BoundaryRuntime<'_>,
    ) -> Result<Vec<Zeroizing<Vec<u8>>>> {
      self.v20_calls.set(self.v20_calls.get() + 1);
      runtime.clock.sleep(self.v20_elapsed);
      Ok(vec![Zeroizing::new(vec![0x20; 32])])
    }
  }

  fn failure_message(outcome: &ChromiumKeyOutcome) -> &str {
    let ChromiumKeyOutcome::Failure(failure) = outcome else {
      panic!("expected provider failure, got {outcome:?}");
    };
    failure.message()
  }

  #[test]
  fn cancelled_runtime_starts_no_windows_key_provider_actions() {
    let clock = crate::common::deadline::test_clock::ManualClock::default();
    let stop = crate::common::deadline::CancellationToken::default();
    stop.cancel();
    let runtime = BoundaryRuntime::with_stop(
      &clock,
      Deadline::after(&clock, std::time::Duration::from_secs(1)),
      stop,
    );
    let backend = AdvancingWindowsBackend::new();
    let state = serde_json::json!({
      "os_crypt": {
        "encrypted_key": "legacy",
        "app_bound_encrypted_key": "appbound"
      }
    });

    let outcomes = retrieve_windows_key_outcomes_with_runtime(&state, None, &backend, &runtime);

    assert_eq!(backend.v10_calls.get(), 0);
    assert_eq!(backend.v20_calls.get(), 0);
    assert!(failure_message(&outcomes.v10).contains("operation cancelled"));
    assert!(failure_message(&outcomes.v20).contains("operation cancelled"));
  }

  #[test]
  fn resource_stop_after_local_state_read_prevents_all_key_provider_actions() {
    struct ResourceStoppingReader {
      calls: Cell<usize>,
      stop: crate::common::deadline::CancellationToken,
    }

    impl LocalStateReader for ResourceStoppingReader {
      fn read_to_string(
        &self,
        _path: &std::path::Path,
        _runtime: &BoundaryRuntime<'_>,
      ) -> Result<String> {
        self.calls.set(self.calls.get() + 1);
        self.stop.exhaust_resources();
        Ok(r#"{"os_crypt":{"encrypted_key":"legacy"}}"#.to_owned())
      }
    }

    let clock = crate::common::deadline::test_clock::ManualClock::default();
    let stop = crate::common::deadline::CancellationToken::default();
    let runtime = BoundaryRuntime::with_stop(
      &clock,
      Deadline::after(&clock, std::time::Duration::from_secs(1)),
      stop.clone(),
    );
    let reader = ResourceStoppingReader {
      calls: Cell::new(0),
      stop,
    };
    let backend = AdvancingWindowsBackend::new();
    let credentials = super::super::ChromiumKeyCredentials::default();

    let outcomes = host_key_outcomes_with_runtime(
      ChromiumKeyRequest::for_installation(
        "chrome",
        &credentials,
        std::path::Path::new("Local State"),
        None,
      ),
      &reader,
      &backend,
      &runtime,
    );

    assert_eq!(reader.calls.get(), 1);
    assert_eq!(backend.v10_calls.get(), 0);
    assert_eq!(backend.v20_calls.get(), 0);
    assert!(failure_message(&outcomes.v10).contains("resource budget exhausted"));
    assert!(failure_message(&outcomes.v20).contains("resource budget exhausted"));
  }

  #[test]
  fn local_state_read_completing_at_deadline_cannot_start_key_providers() {
    let clock = crate::common::deadline::test_clock::ManualClock::default();
    let deadline = Deadline::after(&clock, std::time::Duration::from_secs(1));
    let runtime = BoundaryRuntime::new(&clock, deadline);
    let reader = AdvancingLocalStateReader {
      calls: Cell::new(0),
      elapsed: std::time::Duration::from_secs(1),
    };
    let backend = AdvancingWindowsBackend::new();
    let credentials = super::super::ChromiumKeyCredentials::default();

    let outcomes = host_key_outcomes_with_runtime(
      ChromiumKeyRequest::for_installation(
        "chrome",
        &credentials,
        std::path::Path::new("Local State"),
        None,
      ),
      &reader,
      &backend,
      &runtime,
    );

    assert_eq!(reader.calls.get(), 1);
    assert_eq!(backend.v10_calls.get(), 0);
    assert!(failure_message(&outcomes.v10).contains("operation deadline expired"));
    assert!(failure_message(&outcomes.v20).contains("operation deadline expired"));
  }

  #[test]
  fn dpapi_completion_at_deadline_is_rejected_by_the_provider_checkpoint() {
    let clock = crate::common::deadline::test_clock::ManualClock::default();
    let deadline = Deadline::after(&clock, std::time::Duration::from_secs(1));
    let runtime = BoundaryRuntime::new(&clock, deadline);
    let mut backend = AdvancingWindowsBackend::new();
    backend.v10_elapsed = std::time::Duration::from_secs(1);
    let state = serde_json::json!({"os_crypt": {"encrypted_key": "legacy"}});

    let outcomes = retrieve_windows_key_outcomes_with_runtime(&state, None, &backend, &runtime);

    assert_eq!(backend.v10_calls.get(), 1);
    assert!(failure_message(&outcomes.v10).contains("operation deadline expired"));
    assert_eq!(backend.v20_calls.get(), 0);
  }

  #[test]
  fn v20_completion_at_deadline_is_rejected_by_the_provider_checkpoint() {
    let clock = crate::common::deadline::test_clock::ManualClock::default();
    let deadline = Deadline::after(&clock, std::time::Duration::from_secs(1));
    let runtime = BoundaryRuntime::new(&clock, deadline);
    let mut backend = AdvancingWindowsBackend::new();
    backend.v20_elapsed = std::time::Duration::from_secs(1);
    let state = serde_json::json!({"os_crypt": {"app_bound_encrypted_key": "appbound"}});

    let outcomes = retrieve_windows_key_outcomes_with_runtime(&state, None, &backend, &runtime);

    assert_eq!(backend.v20_calls.get(), 1);
    assert!(failure_message(&outcomes.v20).contains("operation deadline expired"));
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
