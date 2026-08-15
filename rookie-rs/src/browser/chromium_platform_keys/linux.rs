use super::super::chromium_crypto::{ChromiumKeyOutcome, ChromiumKeyOutcomes, ChromiumKeyProvider};
use super::create_pbkdf2_key;
use super::shared::outcome_from_result;
use crate::config::Browser;
use anyhow::Result;
use zeroize::Zeroizing;

trait LinuxKeyringBackend {
  fn passwords(&self, crypt_name: &str) -> Result<Vec<Zeroizing<String>>>;
}

struct SystemLinuxKeyringBackend;

impl LinuxKeyringBackend for SystemLinuxKeyringBackend {
  fn passwords(&self, crypt_name: &str) -> Result<Vec<Zeroizing<String>>> {
    crate::linux::get_passwords(crypt_name)
  }
}

fn linux_v10_outcome() -> ChromiumKeyOutcome {
  let salt = b"saltysalt";
  ChromiumKeyOutcome::success_zeroizing(vec![
    create_pbkdf2_key("peanuts", salt, 1),
    create_pbkdf2_key("", salt, 1),
  ])
  .expect("Linux v10 has two fixed candidates")
}

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
pub(crate) struct LinuxKeyOutcomeCache {
  v11_by_crypt_name: std::collections::HashMap<String, ChromiumKeyOutcome>,
}

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

pub(crate) struct LinuxPlatformKeyProvider<'a> {
  config: &'a Browser,
}

impl<'a> LinuxPlatformKeyProvider<'a> {
  pub(crate) fn new(config: &'a Browser) -> Self {
    Self { config }
  }
}

impl ChromiumKeyProvider<()> for LinuxPlatformKeyProvider<'_> {
  fn retrieve(&self, _context: &()) -> ChromiumKeyOutcomes {
    retrieve_linux_key_outcomes(self.config, &SystemLinuxKeyringBackend)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::browser::chromium_crypto::{ChromiumCipherVersion, ChromiumKeyRoute, ChromiumKeyTier};
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

  struct FakeLinuxBackend {
    calls: Cell<usize>,
    result: Result<Vec<Zeroizing<String>>>,
  }

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

  fn linux_config(crypt_name: Option<&str>) -> Browser {
    Browser {
      paths: vec![],
      channels: None,
      unix_crypt_name: crypt_name.map(str::to_string),
      osx_key_service: None,
      osx_key_user: None,
    }
  }

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
}
