use std::fmt;
use zeroize::{Zeroize, Zeroizing};

use crate::browser::outcome::Retryability;
pub(crate) use crate::common::boundary::KeyProvider;
use crate::common::secret::SecretBytes;

#[cfg(unix)]
mod unix;
#[cfg(not(any(unix, windows)))]
mod unsupported;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix as platform;
#[cfg(not(any(unix, windows)))]
use unsupported as platform;
#[cfg(windows)]
use windows as platform;

const CIPHER_VERSION_PREFIX_LEN: usize = 3;

/// Encryption format selected by a Chromium cookie row.
///
/// This is private scaffolding for the installation-aware pipeline. In
/// particular, raw DPAPI is row-scoped and therefore has no key bucket.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChromiumCipherVersion {
  V10,
  V11,
  V12SecretPortal,
  V20,
  LegacyDpapi,
  Unknown([u8; CIPHER_VERSION_PREFIX_LEN]),
}

impl fmt::Debug for ChromiumCipherVersion {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::V10 => formatter.write_str("V10"),
      Self::V11 => formatter.write_str("V11"),
      Self::V12SecretPortal => formatter.write_str("V12SecretPortal"),
      Self::V20 => formatter.write_str("V20"),
      Self::LegacyDpapi => formatter.write_str("LegacyDpapi"),
      Self::Unknown(_) => formatter.write_str("Unknown"),
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChromiumKeyTier {
  V10,
  V11,
  V20,
}

impl fmt::Display for ChromiumKeyTier {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    let name = match self {
      Self::V10 => "v10",
      Self::V11 => "v11",
      Self::V20 => "v20",
    };
    formatter.write_str(name)
  }
}

/// A candidate key whose debug representation never contains the key bytes.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct KeyCandidate {
  bytes: Zeroizing<Vec<u8>>,
}

impl KeyCandidate {
  #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows", test))]
  pub(crate) fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Self {
    Self { bytes }
  }

  pub(crate) fn as_bytes(&self) -> &[u8] {
    &self.bytes
  }
}

impl Drop for KeyCandidate {
  fn drop(&mut self) {
    // `Zeroizing` repeats this on field drop. Doing it explicitly makes the
    // invariant directly testable and guarantees any future drop-time work
    // observes only wiped storage.
    #[cfg(test)]
    let original_len = self.bytes.len();
    self.bytes.zeroize();
    #[cfg(test)]
    KEY_DROP_OBSERVATIONS.with(|observations| {
      if let Some(observations) = observations.borrow_mut().as_mut() {
        observations.push((original_len, self.bytes.as_slice().to_vec()));
      }
    });
  }
}

#[cfg(test)]
type KeyDropObservation = (usize, Vec<u8>);

#[cfg(test)]
thread_local! {
  static KEY_DROP_OBSERVATIONS: std::cell::RefCell<Option<Vec<KeyDropObservation>>> = const {
    std::cell::RefCell::new(None)
  };
}

impl fmt::Debug for KeyCandidate {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("KeyCandidate")
      .field("length", &self.bytes.len())
      .finish()
  }
}

/// Candidate collection whose constructor enforces the `Success` invariant.
///
/// The backing vector stays private so callers cannot construct an empty
/// successful outcome by using the enum variant directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NonEmptyKeyCandidates {
  candidates: Vec<KeyCandidate>,
}

impl NonEmptyKeyCandidates {
  #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows", test))]
  fn from_candidates(candidates: Vec<KeyCandidate>) -> Option<Self> {
    if candidates.is_empty() {
      return None;
    }
    Some(Self { candidates })
  }

  #[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows", test)),
    expect(
      dead_code,
      reason = "unsupported targets cannot construct a candidate route"
    )
  )]
  fn as_slice(&self) -> &[KeyCandidate] {
    &self.candidates
  }
}

/// A provider failure scoped to one configured cipher tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChromiumKeyFailure {
  message: String,
  retryability: Retryability,
}

impl ChromiumKeyFailure {
  // Milestone 1B replaces the legacy shared provider with platform providers
  // that construct this typed failure without changing the router contract.
  #[allow(dead_code)]
  pub(crate) fn new(message: impl Into<String>) -> Self {
    Self {
      message: message.into(),
      retryability: Retryability::Retryable,
    }
  }

  #[allow(dead_code)]
  pub(crate) fn new_with_retryability(
    message: impl Into<String>,
    retryability: Retryability,
  ) -> Self {
    Self {
      message: message.into(),
      retryability,
    }
  }

  pub(crate) fn message(&self) -> &str {
    &self.message
  }

  pub(crate) fn retryability(&self) -> Retryability {
    self.retryability
  }
}

/// Retrieval state for exactly one configured key tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChromiumKeyOutcome {
  #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows", test))]
  Success(NonEmptyKeyCandidates),
  NotApplicable,
  #[allow(dead_code)]
  Failure(ChromiumKeyFailure),
}

impl ChromiumKeyOutcome {
  /// Constructs a successful outcome only when at least one candidate exists.
  ///
  /// Providers must decide explicitly whether an empty retrieval is
  /// `NotApplicable` or `Failure`; this constructor never makes that policy
  /// decision for them.
  #[cfg(test)]
  pub(crate) fn success(candidates: Vec<Vec<u8>>) -> Option<Self> {
    Self::success_zeroizing(candidates.into_iter().map(Zeroizing::new).collect())
  }

  #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows", test))]
  pub(crate) fn success_zeroizing(candidates: Vec<Zeroizing<Vec<u8>>>) -> Option<Self> {
    NonEmptyKeyCandidates::from_candidates(
      candidates
        .into_iter()
        .map(KeyCandidate::from_zeroizing)
        .collect(),
    )
    .map(Self::Success)
  }

  #[allow(dead_code)]
  pub(crate) fn failure(message: impl Into<String>) -> Self {
    Self::Failure(ChromiumKeyFailure::new(message))
  }

  #[allow(dead_code)]
  pub(crate) fn failure_with_retryability(
    message: impl Into<String>,
    retryability: Retryability,
  ) -> Self {
    Self::Failure(ChromiumKeyFailure::new_with_retryability(
      message,
      retryability,
    ))
  }
}

/// Independent retrieval outcomes for all key-backed Chromium cipher tiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChromiumKeyOutcomes {
  pub(crate) v10: ChromiumKeyOutcome,
  pub(crate) v11: ChromiumKeyOutcome,
  pub(crate) v20: ChromiumKeyOutcome,
}

impl Default for ChromiumKeyOutcomes {
  fn default() -> Self {
    Self {
      v10: ChromiumKeyOutcome::NotApplicable,
      v11: ChromiumKeyOutcome::NotApplicable,
      v20: ChromiumKeyOutcome::NotApplicable,
    }
  }
}

impl ChromiumKeyOutcomes {
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  pub(crate) fn provider_failure(message: impl Into<String>) -> Self {
    let outcome = ChromiumKeyOutcome::failure(message);
    Self {
      v10: outcome.clone(),
      v11: outcome.clone(),
      v20: outcome,
    }
  }

  /// Test adapter preserving the pre-1B shared-candidate behavior.
  #[cfg(test)]
  pub(crate) fn from_legacy_shared(candidates: Vec<Vec<u8>>) -> Self {
    // This is the only compatibility boundary where an empty historical
    // shared list maps implicitly to `NotApplicable`. New providers choose an
    // outcome explicitly for each tier.
    let outcome =
      ChromiumKeyOutcome::success(candidates).unwrap_or(ChromiumKeyOutcome::NotApplicable);
    Self {
      v10: outcome.clone(),
      v11: outcome.clone(),
      v20: outcome,
    }
  }

  fn outcome(&self, tier: ChromiumKeyTier) -> &ChromiumKeyOutcome {
    match tier {
      ChromiumKeyTier::V10 => &self.v10,
      ChromiumKeyTier::V11 => &self.v11,
      ChromiumKeyTier::V20 => &self.v20,
    }
  }

  pub(crate) fn route(&self, cipher: ChromiumCipherVersion) -> ChromiumKeyRoute<'_> {
    let tier = match cipher {
      ChromiumCipherVersion::V10 => ChromiumKeyTier::V10,
      ChromiumCipherVersion::V11 => ChromiumKeyTier::V11,
      ChromiumCipherVersion::V20 => ChromiumKeyTier::V20,
      ChromiumCipherVersion::V12SecretPortal => return ChromiumKeyRoute::V12SecretPortal,
      ChromiumCipherVersion::LegacyDpapi => return ChromiumKeyRoute::LegacyDpapi,
      ChromiumCipherVersion::Unknown(prefix) => return ChromiumKeyRoute::Unknown(prefix),
    };

    match self.outcome(tier) {
      #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows", test))]
      ChromiumKeyOutcome::Success(candidates) => ChromiumKeyRoute::Candidates {
        tier,
        candidates: candidates.as_slice(),
      },
      ChromiumKeyOutcome::NotApplicable => ChromiumKeyRoute::NotApplicable { tier },
      ChromiumKeyOutcome::Failure(failure) => ChromiumKeyRoute::Failure { tier, failure },
    }
  }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChromiumKeyRoute<'a> {
  #[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows", test)),
    expect(
      dead_code,
      reason = "unsupported targets cannot construct a candidate route"
    )
  )]
  Candidates {
    tier: ChromiumKeyTier,
    candidates: &'a [KeyCandidate],
  },
  NotApplicable {
    tier: ChromiumKeyTier,
  },
  Failure {
    tier: ChromiumKeyTier,
    failure: &'a ChromiumKeyFailure,
  },
  LegacyDpapi,
  V12SecretPortal,
  Unknown([u8; CIPHER_VERSION_PREFIX_LEN]),
}

impl fmt::Debug for ChromiumKeyRoute<'_> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Candidates { tier, candidates } => formatter
        .debug_struct("Candidates")
        .field("tier", tier)
        .field("candidates", candidates)
        .finish(),
      Self::NotApplicable { tier } => formatter
        .debug_struct("NotApplicable")
        .field("tier", tier)
        .finish(),
      Self::Failure { tier, failure } => formatter
        .debug_struct("Failure")
        .field("tier", tier)
        .field("failure", failure)
        .finish(),
      Self::LegacyDpapi => formatter.write_str("LegacyDpapi"),
      Self::V12SecretPortal => formatter.write_str("V12SecretPortal"),
      Self::Unknown(_) => formatter.write_str("Unknown"),
    }
  }
}

/// Result of asking the host cipher capability to decrypt an unversioned
/// Chromium value.
///
/// Raw DPAPI is a row-level cipher on Windows, not a key-provider tier. Other
/// targets report it as unavailable without pretending that decryption was
/// attempted and failed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LegacyCipherOutcome {
  #[cfg_attr(not(windows), allow(dead_code))]
  Plaintext(SecretBytes),
  #[cfg_attr(windows, allow(dead_code))]
  Unsupported(&'static str),
}

/// Exact candidate-key length required by the selected host cipher.
///
/// Unsupported targets deliberately expose `None`, allowing the shared row
/// loop to report that keyed cookie decryption is unavailable without
/// compiling a foreign cipher implementation.
pub(crate) const CANDIDATE_KEY_LENGTH: Option<usize> = platform::CANDIDATE_KEY_LENGTH;

/// Validates the target-specific envelope before any candidate is tried.
pub(crate) fn validate_keyed_envelope(encrypted_value: &[u8]) -> anyhow::Result<()> {
  platform::validate_keyed_envelope(encrypted_value)
}

/// Applies the selected host's keyed cipher primitive to one candidate.
pub(crate) fn decrypt_keyed_candidate(
  encrypted_value: &[u8],
  key: &[u8],
) -> anyhow::Result<SecretBytes> {
  platform::decrypt_keyed_candidate(encrypted_value, key)
}

/// Applies the selected host's unversioned legacy cipher, when one exists.
pub(crate) fn decrypt_legacy(encrypted_value: &[u8]) -> anyhow::Result<LegacyCipherOutcome> {
  platform::decrypt_legacy(encrypted_value)
}

pub(crate) fn retrieve_key_outcomes<Context: ?Sized, Provider>(
  provider: &Provider,
  context: &Context,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> anyhow::Result<ChromiumKeyOutcomes>
where
  Provider: KeyProvider<Context, Keys = ChromiumKeyOutcomes>,
{
  crate::common::boundary::keys(provider, context, runtime)
}

/// Provider used only to bridge the current untyped platform retrievers.
#[cfg(test)]
pub(crate) struct LegacySharedKeyProvider {
  outcomes: ChromiumKeyOutcomes,
}

#[cfg(test)]
impl LegacySharedKeyProvider {
  pub(crate) fn new(candidates: Vec<Vec<u8>>) -> Self {
    Self {
      outcomes: ChromiumKeyOutcomes::from_legacy_shared(candidates),
    }
  }
}

#[cfg(test)]
impl KeyProvider<()> for LegacySharedKeyProvider {
  type Keys = ChromiumKeyOutcomes;

  fn keys(
    &self,
    _context: &(),
    _runtime: &crate::common::deadline::BoundaryRuntime<'_>,
  ) -> ChromiumKeyOutcomes {
    self.outcomes.clone()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::cell::{Cell, RefCell};

  #[test]
  fn key_candidates_and_their_clones_are_wiped_on_drop() {
    KEY_DROP_OBSERVATIONS.with(|observations| {
      assert!(observations.borrow().is_none());
      *observations.borrow_mut() = Some(Vec::new());
    });

    let candidate = KeyCandidate::from_zeroizing(Zeroizing::new(vec![0x5a; 32]));
    let duplicate = candidate.clone();
    drop(candidate);
    drop(duplicate);

    let observed = KEY_DROP_OBSERVATIONS.with(|observations| {
      observations
        .borrow_mut()
        .take()
        .expect("drop observations enabled")
    });
    assert_eq!(observed.len(), 2);
    assert!(observed
      .iter()
      .all(|(original_len, bytes)| { *original_len == 32 && bytes.is_empty() }));
  }

  #[test]
  fn unknown_cipher_and_route_debug_do_not_expose_raw_prefix_bytes() {
    let cipher = ChromiumCipherVersion::Unknown(*b"v99");
    let outcomes = ChromiumKeyOutcomes::default();
    let route = outcomes.route(cipher);

    for debug in [format!("{cipher:?}"), format!("{route:?}")] {
      assert_eq!(debug, "Unknown");
      assert!(!debug.contains("v99"));
      assert!(!debug.contains("118, 57, 57"));
    }
  }

  fn synthetic_outcomes() -> ChromiumKeyOutcomes {
    ChromiumKeyOutcomes {
      v10: ChromiumKeyOutcome::success(vec![vec![0x10; 16]]).expect("nonempty v10 fixture"),
      v11: ChromiumKeyOutcome::success(vec![vec![0x11; 16]]).expect("nonempty v11 fixture"),
      v20: ChromiumKeyOutcome::success(vec![vec![0x20; 32]]).expect("nonempty v20 fixture"),
    }
  }

  #[test]
  fn success_rejects_an_empty_candidate_collection() {
    assert_eq!(ChromiumKeyOutcome::success(vec![]), None);
  }

  #[test]
  fn router_selects_only_the_matching_tier() {
    let outcomes = synthetic_outcomes();
    for (cipher, expected_tier, expected_byte) in [
      (ChromiumCipherVersion::V10, ChromiumKeyTier::V10, 0x10),
      (ChromiumCipherVersion::V11, ChromiumKeyTier::V11, 0x11),
      (ChromiumCipherVersion::V20, ChromiumKeyTier::V20, 0x20),
    ] {
      let ChromiumKeyRoute::Candidates { tier, candidates } = outcomes.route(cipher) else {
        panic!("expected candidate route for {cipher:?}");
      };
      assert_eq!(tier, expected_tier);
      assert_eq!(candidates.len(), 1);
      assert!(candidates[0]
        .as_bytes()
        .iter()
        .all(|byte| *byte == expected_byte));
    }
  }

  #[test]
  fn router_preserves_partial_tier_outcomes() {
    let outcomes = ChromiumKeyOutcomes {
      v10: ChromiumKeyOutcome::success(vec![vec![0x10; 16]]).expect("nonempty v10 fixture"),
      v11: ChromiumKeyOutcome::NotApplicable,
      v20: ChromiumKeyOutcome::failure("v20 provider failed"),
    };

    assert!(matches!(
      outcomes.route(ChromiumCipherVersion::V10),
      ChromiumKeyRoute::Candidates {
        tier: ChromiumKeyTier::V10,
        ..
      }
    ));
    assert_eq!(
      outcomes.route(ChromiumCipherVersion::V11),
      ChromiumKeyRoute::NotApplicable {
        tier: ChromiumKeyTier::V11
      }
    );
    let ChromiumKeyRoute::Failure { tier, failure } = outcomes.route(ChromiumCipherVersion::V20)
    else {
      panic!("expected failed v20 route");
    };
    assert_eq!(tier, ChromiumKeyTier::V20);
    assert_eq!(failure.message(), "v20 provider failed");

    assert_eq!(
      outcomes.route(ChromiumCipherVersion::V12SecretPortal),
      ChromiumKeyRoute::V12SecretPortal
    );
    assert_eq!(
      outcomes.route(ChromiumCipherVersion::LegacyDpapi),
      ChromiumKeyRoute::LegacyDpapi
    );
    assert_eq!(
      outcomes.route(ChromiumCipherVersion::Unknown(*b"v99")),
      ChromiumKeyRoute::Unknown(*b"v99")
    );
  }

  struct RecordingProvider {
    calls: Cell<usize>,
    contexts: RefCell<Vec<String>>,
    outcomes: ChromiumKeyOutcomes,
  }

  impl KeyProvider<str> for RecordingProvider {
    type Keys = ChromiumKeyOutcomes;

    fn keys(
      &self,
      context: &str,
      _runtime: &crate::common::deadline::BoundaryRuntime<'_>,
    ) -> ChromiumKeyOutcomes {
      self.calls.set(self.calls.get() + 1);
      self.contexts.borrow_mut().push(context.to_string());
      self.outcomes.clone()
    }
  }

  #[test]
  fn provider_is_dependency_injected_and_preserves_partial_results() {
    let provider = RecordingProvider {
      calls: Cell::new(0),
      contexts: RefCell::new(vec![]),
      outcomes: ChromiumKeyOutcomes {
        v10: ChromiumKeyOutcome::success(vec![vec![0x10; 16]]).expect("nonempty v10 fixture"),
        v11: ChromiumKeyOutcome::failure("keyring unavailable"),
        v20: ChromiumKeyOutcome::NotApplicable,
      },
    };

    let clock = crate::common::deadline::SystemClock;
    let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
    let outcomes = retrieve_key_outcomes(&provider, "installation-1", &runtime).unwrap();
    assert_eq!(provider.calls.get(), 1);
    assert_eq!(provider.contexts.borrow().as_slice(), ["installation-1"]);
    assert!(matches!(outcomes.v10, ChromiumKeyOutcome::Success(_)));
    assert!(matches!(outcomes.v11, ChromiumKeyOutcome::Failure(_)));
    assert_eq!(outcomes.v20, ChromiumKeyOutcome::NotApplicable);
  }

  #[test]
  fn legacy_provider_keeps_current_shared_candidate_behavior() {
    let provider = LegacySharedKeyProvider::new(vec![vec![0x2a; 16]]);
    let clock = crate::common::deadline::SystemClock;
    let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
    let outcomes = retrieve_key_outcomes(&provider, &(), &runtime).unwrap();
    for cipher in [
      ChromiumCipherVersion::V10,
      ChromiumCipherVersion::V11,
      ChromiumCipherVersion::V20,
    ] {
      assert!(matches!(
        outcomes.route(cipher),
        ChromiumKeyRoute::Candidates { .. }
      ));
    }
  }

  #[test]
  fn legacy_provider_maps_an_empty_historical_list_to_not_applicable() {
    let provider = LegacySharedKeyProvider::new(vec![]);
    let clock = crate::common::deadline::SystemClock;
    let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
    let outcomes = retrieve_key_outcomes(&provider, &(), &runtime).unwrap();
    assert_eq!(outcomes, ChromiumKeyOutcomes::default());
  }
}
