use super::super::chromium_crypto::{ChromiumKeyOutcome, ChromiumKeyOutcomes, KeyProvider};
use super::create_pbkdf2_key;
use super::shared::outcome_from_result;
use super::{ChromiumKeyCredentials, ChromiumKeyRequest};
use crate::common::deadline::{BoundaryRuntime, DeadlineEnforcement};
#[cfg(test)]
use crate::common::deadline::{Clock, Deadline};
use crate::common::secret::SecretString;
use crate::config::Browser;
use anyhow::Result;

trait LinuxKeyringBackend {
  fn passwords(&self, crypt_name: &str, runtime: &BoundaryRuntime<'_>)
    -> Result<Vec<SecretString>>;
}

struct SystemLinuxKeyringBackend;

impl LinuxKeyringBackend for SystemLinuxKeyringBackend {
  fn passwords(
    &self,
    crypt_name: &str,
    runtime: &BoundaryRuntime<'_>,
  ) -> Result<Vec<SecretString>> {
    crate::linux::get_passwords_with_runtime(crypt_name, runtime)
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

fn retrieve_linux_v11_outcome<B>(
  crypt_name: &str,
  backend: &B,
  runtime: &BoundaryRuntime<'_>,
) -> ChromiumKeyOutcome
where
  B: LinuxKeyringBackend,
{
  let salt = b"saltysalt";
  let candidates = runtime
    .check()
    .map_err(anyhow::Error::from)
    .and_then(|()| backend.passwords(crypt_name, runtime))
    .and_then(|passwords| {
      runtime.check().map_err(anyhow::Error::from)?;
      Ok(passwords)
    })
    .map(|passwords| {
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

/// Per-`any_browser` Linux key cache.
///
/// Several browser configurations deliberately share a `unix_crypt_name`.
/// Caching the typed outcome (including failures) prevents repeated D-Bus
/// calls and unlock prompts without discarding the diagnostics produced by the
/// hardened keyring provider.
struct LinuxKeyOutcomeCache {
  v11_by_crypt_name: std::collections::HashMap<String, ChromiumKeyOutcome>,
}

impl LinuxKeyOutcomeCache {
  pub(crate) fn new() -> Self {
    Self {
      v11_by_crypt_name: std::collections::HashMap::new(),
    }
  }

  fn outcomes_for(
    &mut self,
    credentials: &ChromiumKeyCredentials,
    runtime: &BoundaryRuntime<'_>,
  ) -> ChromiumKeyOutcomes {
    self.outcomes_for_with_backend(credentials, &SystemLinuxKeyringBackend, runtime)
  }

  fn outcomes_for_with_backend<B>(
    &mut self,
    credentials: &ChromiumKeyCredentials,
    backend: &B,
    runtime: &BoundaryRuntime<'_>,
  ) -> ChromiumKeyOutcomes
  where
    B: LinuxKeyringBackend,
  {
    let v11 = match credentials
      .linux_crypt_name
      .as_deref()
      .filter(|name| !name.is_empty())
    {
      None => ChromiumKeyOutcome::NotApplicable,
      Some(crypt_name) => self
        .v11_by_crypt_name
        .entry(crypt_name.to_string())
        .or_insert_with(|| retrieve_linux_v11_outcome(crypt_name, backend, runtime))
        .clone(),
    };

    ChromiumKeyOutcomes {
      v10: linux_v10_outcome(),
      v11,
      v20: ChromiumKeyOutcome::NotApplicable,
    }
  }
}

/// Host-selected Linux key session. Its cache is intentionally scoped to the
/// caller-owned session so separate extraction requests cannot share keyring
/// outcomes accidentally.
pub(crate) struct HostKeySession {
  cache: LinuxKeyOutcomeCache,
}

impl HostKeySession {
  pub(crate) fn new() -> Self {
    Self {
      cache: LinuxKeyOutcomeCache::new(),
    }
  }

  pub(crate) fn retrieve(
    &mut self,
    request: ChromiumKeyRequest<'_>,
    runtime: &BoundaryRuntime<'_>,
  ) -> ChromiumKeyOutcomes {
    self.cache.outcomes_for(request.credentials, runtime)
  }

  #[cfg(test)]
  fn retrieve_with_backend<B>(
    &mut self,
    request: ChromiumKeyRequest<'_>,
    backend: &B,
    clock: &dyn Clock,
    deadline: Deadline,
  ) -> ChromiumKeyOutcomes
  where
    B: LinuxKeyringBackend,
  {
    let runtime = BoundaryRuntime::new(clock, deadline);
    self
      .cache
      .outcomes_for_with_backend(request.credentials, backend, &runtime)
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

impl KeyProvider<()> for LinuxPlatformKeyProvider<'_> {
  type Keys = ChromiumKeyOutcomes;

  fn keys(&self, _context: &(), runtime: &BoundaryRuntime<'_>) -> ChromiumKeyOutcomes {
    let credentials = ChromiumKeyCredentials::from_legacy_browser(self.config);
    let mut session = HostKeySession::new();
    session.retrieve(ChromiumKeyRequest::direct(&credentials), runtime)
  }

  fn deadline_enforcement(&self) -> DeadlineEnforcement {
    // Connection establishment and every D-Bus reply wait are raced against
    // the same remaining absolute budget.
    DeadlineEnforcement::Enforceable
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
    result: Result<Vec<SecretString>>,
  }

  impl LinuxKeyringBackend for FakeLinuxBackend {
    fn passwords(
      &self,
      _crypt_name: &str,
      _runtime: &BoundaryRuntime<'_>,
    ) -> Result<Vec<SecretString>> {
      self.calls.set(self.calls.get() + 1);
      self
        .result
        .as_ref()
        .map(Clone::clone)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
    }
  }

  fn linux_credentials(crypt_name: Option<&str>) -> ChromiumKeyCredentials {
    ChromiumKeyCredentials {
      linux_crypt_name: crypt_name.map(str::to_string),
      macos_keychain: None,
    }
  }

  fn outcomes_with_backend<B>(
    credentials: &ChromiumKeyCredentials,
    backend: &B,
  ) -> ChromiumKeyOutcomes
  where
    B: LinuxKeyringBackend,
  {
    let mut session = HostKeySession::new();
    let clock = crate::common::deadline::test_clock::ManualClock::default();
    let deadline = Deadline::after(&clock, std::time::Duration::from_secs(1));
    session.retrieve_with_backend(
      ChromiumKeyRequest::direct(credentials),
      backend,
      &clock,
      deadline,
    )
  }

  fn cached_outcomes_with_backend<B>(
    cache: &mut LinuxKeyOutcomeCache,
    credentials: &ChromiumKeyCredentials,
    backend: &B,
  ) -> ChromiumKeyOutcomes
  where
    B: LinuxKeyringBackend,
  {
    let clock = crate::common::deadline::test_clock::ManualClock::default();
    let deadline = Deadline::after(&clock, std::time::Duration::from_secs(1));
    let runtime = BoundaryRuntime::new(&clock, deadline);
    cache.outcomes_for_with_backend(credentials, backend, &runtime)
  }

  #[test]
  fn cancelled_runtime_does_not_start_the_linux_keyring_backend() {
    let backend = FakeLinuxBackend {
      calls: Cell::new(0),
      result: Ok(vec![SecretString::new("must not be read".to_owned())]),
    };
    let clock = crate::common::deadline::test_clock::ManualClock::default();
    let stop = crate::common::deadline::CancellationToken::default();
    stop.cancel();
    let runtime = BoundaryRuntime::with_stop(
      &clock,
      Deadline::after(&clock, std::time::Duration::from_secs(1)),
      stop,
    );

    let outcome = retrieve_linux_v11_outcome("chrome", &backend, &runtime);

    assert_eq!(backend.calls.get(), 0);
    let ChromiumKeyOutcome::Failure(failure) = outcome else {
      panic!("cancelled provider must be a typed key outcome failure");
    };
    assert!(failure.message().contains("operation cancelled"));
  }

  #[test]
  fn linux_separates_fixed_v10_from_ordered_keyring_v11_candidates() {
    let backend = FakeLinuxBackend {
      calls: Cell::new(0),
      result: Ok(vec![
        SecretString::new("first".to_string()),
        SecretString::new("second".to_string()),
      ]),
    };
    let outcomes = outcomes_with_backend(&linux_credentials(Some("chrome")), &backend);

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
    let outcomes = outcomes_with_backend(&linux_credentials(Some("chrome")), &backend);

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
    let outcomes = outcomes_with_backend(&linux_credentials(Some("chrome")), &backend);

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
      result: Ok(vec![SecretString::new("unused".to_string())]),
    };
    let outcomes = outcomes_with_backend(&linux_credentials(None), &backend);

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
      result: Ok(vec![SecretString::new("shared secret".to_string())]),
    };
    let mut cache = LinuxKeyOutcomeCache::new();

    let chrome =
      cached_outcomes_with_backend(&mut cache, &linux_credentials(Some("chrome")), &backend);
    let vivaldi =
      cached_outcomes_with_backend(&mut cache, &linux_credentials(Some("chrome")), &backend);
    let brave =
      cached_outcomes_with_backend(&mut cache, &linux_credentials(Some("brave")), &backend);

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

    let first =
      cached_outcomes_with_backend(&mut cache, &linux_credentials(Some("chromium")), &backend);
    let second =
      cached_outcomes_with_backend(&mut cache, &linux_credentials(Some("chromium")), &backend);

    assert_eq!(backend.calls.get(), 1);
    for outcomes in [&first, &second] {
      let ChromiumKeyRoute::Failure { failure, .. } = outcomes.route(ChromiumCipherVersion::V11)
      else {
        panic!("cached keyring failure must stay explicit");
      };
      assert_eq!(failure.message(), "locked keyring");
    }
  }

  #[test]
  fn linux_host_session_cache_is_shared_within_a_session_but_not_between_sessions() {
    let backend = FakeLinuxBackend {
      calls: Cell::new(0),
      result: Ok(vec![SecretString::new("session secret".to_string())]),
    };
    let credentials = linux_credentials(Some("chrome"));
    let request = ChromiumKeyRequest::direct(&credentials);
    let clock = crate::common::deadline::test_clock::ManualClock::default();
    let deadline = Deadline::after(&clock, std::time::Duration::from_secs(1));

    let mut first_session = HostKeySession::new();
    first_session.retrieve_with_backend(request, &backend, &clock, deadline);
    first_session.retrieve_with_backend(request, &backend, &clock, deadline);
    assert_eq!(backend.calls.get(), 1, "one lookup inside a probe session");

    let mut second_session = HostKeySession::new();
    second_session.retrieve_with_backend(request, &backend, &clock, deadline);
    assert_eq!(
      backend.calls.get(),
      2,
      "a later probe run gets a fresh host session"
    );

    let failing_backend = FakeLinuxBackend {
      calls: Cell::new(0),
      result: Err(anyhow::anyhow!("session keyring failure")),
    };
    let mut failing_session = HostKeySession::new();
    for _ in 0..2 {
      let outcomes =
        failing_session.retrieve_with_backend(request, &failing_backend, &clock, deadline);
      let ChromiumKeyRoute::Failure { failure, .. } = outcomes.route(ChromiumCipherVersion::V11)
      else {
        panic!("failed session lookup must stay typed");
      };
      assert_eq!(failure.message(), "session keyring failure");
    }
    assert_eq!(
      failing_backend.calls.get(),
      1,
      "the session caches a failed lookup"
    );

    let mut retried_session = HostKeySession::new();
    retried_session.retrieve_with_backend(request, &failing_backend, &clock, deadline);
    assert_eq!(
      failing_backend.calls.get(),
      2,
      "a fresh session retries a previously failed lookup"
    );
  }
}
