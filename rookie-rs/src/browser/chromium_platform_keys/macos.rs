use super::super::chromium_crypto::{ChromiumKeyOutcome, ChromiumKeyOutcomes, KeyProvider};
use super::create_pbkdf2_key;
use super::{ChromiumKeyCredentials, ChromiumKeyRequest};
use crate::common::deadline::{Clock, Deadline, DeadlineEnforcement, SystemClock};
use crate::common::secret::SecretString;
use crate::config::Browser;
use anyhow::Result;

trait MacosKeychainBackend {
  fn password(
    &self,
    service: &str,
    user: &str,
    clock: &dyn Clock,
    deadline: Deadline,
  ) -> Result<SecretString>;
}

struct SystemMacosKeychainBackend;

impl MacosKeychainBackend for SystemMacosKeychainBackend {
  fn password(
    &self,
    service: &str,
    user: &str,
    clock: &dyn Clock,
    deadline: Deadline,
  ) -> Result<SecretString> {
    crate::macos::get_osx_keychain_password_with_deadline(service, user, clock, deadline)
  }
}

fn retrieve_macos_key_outcomes<B>(
  request: ChromiumKeyRequest<'_>,
  backend: &B,
  clock: &dyn Clock,
  deadline: Deadline,
) -> ChromiumKeyOutcomes
where
  B: MacosKeychainBackend,
{
  let v10 = match request.credentials.macos_keychain.as_ref() {
    Some(credentials) if !credentials.service.is_empty() && !credentials.account.is_empty() => {
      match backend.password(
        &credentials.service,
        &credentials.account,
        clock,
        deadline,
      ) {
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
    None if request.browser_id.is_some() => ChromiumKeyOutcome::failure(format!(
      "no macOS keychain identity is known for browser {:?}, so its encrypted cookies cannot be decrypted",
      request.browser_id.expect("registered request has a browser ID")
    )),
    None => ChromiumKeyOutcome::NotApplicable,
    Some(_) => ChromiumKeyOutcome::failure(
      "macOS Keychain configuration requires non-empty service and account values",
    ),
  };

  ChromiumKeyOutcomes {
    v10,
    v11: ChromiumKeyOutcome::NotApplicable,
    v20: ChromiumKeyOutcome::NotApplicable,
  }
}

pub(crate) struct HostKeySession;

impl HostKeySession {
  pub(crate) fn new() -> Self {
    Self
  }

  pub(crate) fn retrieve(
    &mut self,
    request: ChromiumKeyRequest<'_>,
    deadline: Deadline,
  ) -> ChromiumKeyOutcomes {
    retrieve_macos_key_outcomes(request, &SystemMacosKeychainBackend, &SystemClock, deadline)
  }
}

pub(crate) struct MacosPlatformKeyProvider<'a> {
  config: &'a Browser,
}

impl<'a> MacosPlatformKeyProvider<'a> {
  pub(crate) fn new(config: &'a Browser) -> Self {
    Self { config }
  }
}

impl KeyProvider<()> for MacosPlatformKeyProvider<'_> {
  type Keys = ChromiumKeyOutcomes;

  fn keys(&self, _context: &(), deadline: Deadline) -> ChromiumKeyOutcomes {
    let credentials = ChromiumKeyCredentials::from_legacy_browser(self.config);
    let mut session = HostKeySession::new();
    session.retrieve(ChromiumKeyRequest::direct(&credentials), deadline)
  }

  fn deadline_enforcement(&self) -> DeadlineEnforcement {
    DeadlineEnforcement::Enforceable
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::browser::chromium_crypto::{ChromiumCipherVersion, ChromiumKeyRoute};
  use crate::browser::chromium_platform_keys::MacosKeychainCredentials;
  use std::cell::Cell;

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

  struct FakeMacosBackend {
    calls: Cell<usize>,
    result: Result<SecretString>,
  }

  impl MacosKeychainBackend for FakeMacosBackend {
    fn password(
      &self,
      _service: &str,
      _user: &str,
      _clock: &dyn Clock,
      _deadline: Deadline,
    ) -> Result<SecretString> {
      self.calls.set(self.calls.get() + 1);
      self
        .result
        .as_ref()
        .map(Clone::clone)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
    }
  }

  fn macos_credentials() -> ChromiumKeyCredentials {
    ChromiumKeyCredentials {
      linux_crypt_name: None,
      macos_keychain: Some(MacosKeychainCredentials {
        service: "Chrome Safe Storage".to_string(),
        account: "Chrome".to_string(),
      }),
    }
  }

  fn request(credentials: &ChromiumKeyCredentials) -> ChromiumKeyRequest<'_> {
    ChromiumKeyRequest::direct(credentials)
  }

  fn deadline() -> (crate::common::deadline::test_clock::ManualClock, Deadline) {
    let clock = crate::common::deadline::test_clock::ManualClock::default();
    let deadline = Deadline::after(&clock, std::time::Duration::from_secs(1));
    (clock, deadline)
  }

  #[test]
  fn macos_uses_only_the_password_returned_by_keychain() {
    let backend = FakeMacosBackend {
      calls: Cell::new(0),
      result: Ok(SecretString::new("keychain".to_string())),
    };
    let credentials = macos_credentials();
    let (clock, deadline) = deadline();
    let outcomes = retrieve_macos_key_outcomes(request(&credentials), &backend, &clock, deadline);
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

  #[test]
  fn macos_keychain_failure_is_a_typed_provider_failure() {
    let backend = FakeMacosBackend {
      calls: Cell::new(0),
      result: Err(anyhow::anyhow!("keychain unavailable")),
    };
    let credentials = macos_credentials();
    let (clock, deadline) = deadline();
    let outcomes = retrieve_macos_key_outcomes(request(&credentials), &backend, &clock, deadline);
    assert_eq!(backend.calls.get(), 1);
    let ChromiumKeyRoute::Failure { failure, .. } = outcomes.route(ChromiumCipherVersion::V10)
    else {
      panic!("Keychain failure must not silently install fallback candidates");
    };
    assert!(failure.message().contains("keychain unavailable"));
  }

  #[test]
  fn macos_mock_password_is_used_only_when_the_configured_backend_returns_it() {
    let backend = FakeMacosBackend {
      calls: Cell::new(0),
      result: Ok(SecretString::new("mock_password".to_string())),
    };
    let credentials = macos_credentials();
    let (clock, deadline) = deadline();
    let outcomes = retrieve_macos_key_outcomes(request(&credentials), &backend, &clock, deadline);
    assert_eq!(
      candidate_bytes(&outcomes, ChromiumCipherVersion::V10),
      [Vec::from(
        create_pbkdf2_key("mock_password", b"saltysalt", 1003).as_slice()
      )]
    );
  }

  #[test]
  fn macos_without_keychain_identity_has_no_implicit_candidates() {
    let backend = FakeMacosBackend {
      calls: Cell::new(0),
      result: Ok(SecretString::new("must not be read".to_string())),
    };
    let credentials = ChromiumKeyCredentials::default();
    let (clock, deadline) = deadline();
    let outcomes = retrieve_macos_key_outcomes(request(&credentials), &backend, &clock, deadline);
    assert_eq!(backend.calls.get(), 0);
    assert!(matches!(
      outcomes.route(ChromiumCipherVersion::V10),
      ChromiumKeyRoute::NotApplicable { .. }
    ));
  }

  #[test]
  fn macos_registered_missing_identity_is_failure_but_direct_empty_is_not_applicable() {
    let backend = FakeMacosBackend {
      calls: Cell::new(0),
      result: Ok(SecretString::new("must not be read".to_string())),
    };
    let credentials = ChromiumKeyCredentials::default();

    let (clock, deadline) = deadline();
    let registered = retrieve_macos_key_outcomes(
      ChromiumKeyRequest::for_installation(
        "coccoc",
        &credentials,
        std::path::Path::new("Local State"),
        None,
      ),
      &backend,
      &clock,
      deadline,
    );
    let ChromiumKeyOutcome::Failure(failure) = registered.v10 else {
      panic!("registered missing identity must fail explicitly");
    };
    assert!(failure.message().contains("coccoc"));

    let direct_config = Browser {
      paths: Vec::new(),
      channels: None,
      unix_crypt_name: None,
      osx_key_service: None,
      osx_key_user: None,
    };
    let direct = MacosPlatformKeyProvider::new(&direct_config).keys(&(), deadline);
    assert_eq!(direct.v10, ChromiumKeyOutcome::NotApplicable);
    assert_eq!(backend.calls.get(), 0);
  }

  #[test]
  fn macos_direct_partial_or_blank_identity_fails_without_calling_keychain() {
    for (service, account) in [
      (Some("Chrome Safe Storage"), None),
      (None, Some("Chrome")),
      (Some(""), Some("Chrome")),
      (Some("Chrome Safe Storage"), Some("")),
    ] {
      let config = Browser {
        paths: Vec::new(),
        channels: None,
        unix_crypt_name: None,
        osx_key_service: service.map(str::to_owned),
        osx_key_user: account.map(str::to_owned),
      };
      let credentials = ChromiumKeyCredentials::from_legacy_browser(&config);
      let backend = FakeMacosBackend {
        calls: Cell::new(0),
        result: Ok(SecretString::new("must not be read".to_string())),
      };

      let (clock, deadline) = deadline();
      let outcomes = retrieve_macos_key_outcomes(
        ChromiumKeyRequest::direct(&credentials),
        &backend,
        &clock,
        deadline,
      );
      let ChromiumKeyOutcome::Failure(failure) = outcomes.v10 else {
        panic!("partial or blank direct identity must fail explicitly");
      };
      assert_eq!(
        failure.message(),
        "macOS Keychain configuration requires non-empty service and account values"
      );
      assert_eq!(backend.calls.get(), 0);
    }
  }
}
