use super::super::chromium_crypto::{ChromiumKeyOutcome, ChromiumKeyOutcomes, ChromiumKeyProvider};
use super::create_pbkdf2_key;
use crate::config::Browser;
use anyhow::Result;
use zeroize::Zeroizing;

trait MacosKeychainBackend {
  fn password(&self, service: &str, user: &str) -> Result<Zeroizing<String>>;
}

struct SystemMacosKeychainBackend;

impl MacosKeychainBackend for SystemMacosKeychainBackend {
  fn password(&self, service: &str, user: &str) -> Result<Zeroizing<String>> {
    crate::macos::get_osx_keychain_password(service, user)
  }
}

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

pub(crate) struct MacosPlatformKeyProvider<'a> {
  config: &'a Browser,
}

impl<'a> MacosPlatformKeyProvider<'a> {
  pub(crate) fn new(config: &'a Browser) -> Self {
    Self { config }
  }
}

impl ChromiumKeyProvider<()> for MacosPlatformKeyProvider<'_> {
  fn retrieve(&self, _context: &()) -> ChromiumKeyOutcomes {
    retrieve_macos_key_outcomes(self.config, &SystemMacosKeychainBackend)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::browser::chromium_crypto::{ChromiumCipherVersion, ChromiumKeyRoute};
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
    result: Result<Zeroizing<String>>,
  }

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

  fn macos_config() -> Browser {
    Browser {
      paths: vec![],
      channels: None,
      unix_crypt_name: None,
      osx_key_service: Some("Chrome Safe Storage".to_string()),
      osx_key_user: Some("Chrome".to_string()),
    }
  }

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
