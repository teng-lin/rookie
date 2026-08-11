use std::fmt;

const CIPHER_VERSION_PREFIX_LEN: usize = 3;

/// Encryption format selected by a Chromium cookie row.
///
/// This is private scaffolding for the installation-aware pipeline. In
/// particular, raw DPAPI is row-scoped and therefore has no key bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChromiumCipherVersion {
  V10,
  V11,
  V12SecretPortal,
  V20,
  LegacyDpapi,
  Unknown([u8; CIPHER_VERSION_PREFIX_LEN]),
}

/// A non-empty encrypted blob that is too short to carry a version prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MalformedChromiumCiphertext {
  pub(crate) observed_len: usize,
}

impl fmt::Display for MalformedChromiumCiphertext {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      formatter,
      "Chromium encrypted value is {} bytes, shorter than the 3-byte cipher prefix",
      self.observed_len
    )
  }
}

impl std::error::Error for MalformedChromiumCiphertext {}

/// Detects a Chromium cipher without unchecked slicing.
///
/// Unknown `vXX` prefixes remain distinct from unversioned legacy DPAPI. An
/// unrecognized prefix that does not begin with `v` is the pre-Chrome-80 raw
/// DPAPI form on Windows; other platforms route it explicitly as unavailable.
pub(crate) fn detect_cipher_version(
  encrypted_value: &[u8],
) -> Result<ChromiumCipherVersion, MalformedChromiumCiphertext> {
  let [first, second, third, ..] = encrypted_value else {
    return Err(MalformedChromiumCiphertext {
      observed_len: encrypted_value.len(),
    });
  };
  let prefix = [*first, *second, *third];
  match &prefix {
    b"v10" => Ok(ChromiumCipherVersion::V10),
    b"v11" => Ok(ChromiumCipherVersion::V11),
    b"v12" => Ok(ChromiumCipherVersion::V12SecretPortal),
    b"v20" => Ok(ChromiumCipherVersion::V20),
    [b'v', _, _] => Ok(ChromiumCipherVersion::Unknown(prefix)),
    _ => Ok(ChromiumCipherVersion::LegacyDpapi),
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
  bytes: Vec<u8>,
}

impl KeyCandidate {
  pub(crate) fn new(bytes: Vec<u8>) -> Self {
    Self { bytes }
  }

  pub(crate) fn as_bytes(&self) -> &[u8] {
    &self.bytes
  }
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
  fn from_raw(candidates: Vec<Vec<u8>>) -> Option<Self> {
    if candidates.is_empty() {
      return None;
    }
    Some(Self {
      candidates: candidates.into_iter().map(KeyCandidate::new).collect(),
    })
  }

  fn as_slice(&self) -> &[KeyCandidate] {
    &self.candidates
  }
}

/// A provider failure scoped to one configured cipher tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChromiumKeyFailure {
  message: String,
}

impl ChromiumKeyFailure {
  // Milestone 1B replaces the legacy shared provider with platform providers
  // that construct this typed failure without changing the router contract.
  #[allow(dead_code)]
  pub(crate) fn new(message: impl Into<String>) -> Self {
    Self {
      message: message.into(),
    }
  }

  pub(crate) fn message(&self) -> &str {
    &self.message
  }
}

/// Retrieval state for exactly one configured key tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChromiumKeyOutcome {
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
  pub(crate) fn success(candidates: Vec<Vec<u8>>) -> Option<Self> {
    NonEmptyKeyCandidates::from_raw(candidates).map(Self::Success)
  }

  #[allow(dead_code)]
  pub(crate) fn failure(message: impl Into<String>) -> Self {
    Self::Failure(ChromiumKeyFailure::new(message))
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
  /// Migration adapter for the current platform retrievers.
  ///
  /// Before Milestone 1B, `get_keys` returns one untyped candidate list and
  /// the legacy extractor tries it for every recognized prefix. Assigning the
  /// same candidates to each bucket preserves that behavior while all row
  /// routing becomes tier-aware. Milestone 1B replaces this adapter with
  /// independent platform outcomes.
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
      ChromiumKeyOutcome::Success(candidates) => ChromiumKeyRoute::Candidates {
        tier,
        candidates: candidates.as_slice(),
      },
      ChromiumKeyOutcome::NotApplicable => ChromiumKeyRoute::NotApplicable { tier },
      ChromiumKeyOutcome::Failure(failure) => ChromiumKeyRoute::Failure { tier, failure },
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChromiumKeyRoute<'a> {
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

/// Injection seam for installation-scoped key retrieval.
///
/// The generic context lets Milestone 1B introduce its installation model
/// without making any of these types public or changing row extraction again.
pub(crate) trait ChromiumKeyProvider<Context: ?Sized> {
  fn retrieve(&self, context: &Context) -> ChromiumKeyOutcomes;
}

pub(crate) fn retrieve_key_outcomes<Context: ?Sized, Provider>(
  provider: &Provider,
  context: &Context,
) -> ChromiumKeyOutcomes
where
  Provider: ChromiumKeyProvider<Context>,
{
  provider.retrieve(context)
}

/// Provider used only to bridge the current untyped platform retrievers.
pub(crate) struct LegacySharedKeyProvider {
  outcomes: ChromiumKeyOutcomes,
}

impl LegacySharedKeyProvider {
  pub(crate) fn new(candidates: Vec<Vec<u8>>) -> Self {
    Self {
      outcomes: ChromiumKeyOutcomes::from_legacy_shared(candidates),
    }
  }
}

impl ChromiumKeyProvider<()> for LegacySharedKeyProvider {
  fn retrieve(&self, _context: &()) -> ChromiumKeyOutcomes {
    self.outcomes.clone()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::cell::{Cell, RefCell};

  #[test]
  fn classifier_recognizes_every_declared_cipher() {
    assert_eq!(
      detect_cipher_version(b"v10payload"),
      Ok(ChromiumCipherVersion::V10)
    );
    assert_eq!(
      detect_cipher_version(b"v11payload"),
      Ok(ChromiumCipherVersion::V11)
    );
    assert_eq!(
      detect_cipher_version(b"v12payload"),
      Ok(ChromiumCipherVersion::V12SecretPortal)
    );
    assert_eq!(
      detect_cipher_version(b"v20payload"),
      Ok(ChromiumCipherVersion::V20)
    );
    assert_eq!(
      detect_cipher_version(&[1, 2, 3, 4]),
      Ok(ChromiumCipherVersion::LegacyDpapi)
    );
    assert_eq!(
      detect_cipher_version(b"v99payload"),
      Ok(ChromiumCipherVersion::Unknown(*b"v99"))
    );
  }

  #[test]
  fn classifier_rejects_every_blob_shorter_than_the_prefix() {
    for length in 0..CIPHER_VERSION_PREFIX_LEN {
      let encrypted_value = vec![b'v'; length];
      assert_eq!(
        detect_cipher_version(&encrypted_value),
        Err(MalformedChromiumCiphertext {
          observed_len: length
        })
      );
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

  impl ChromiumKeyProvider<str> for RecordingProvider {
    fn retrieve(&self, context: &str) -> ChromiumKeyOutcomes {
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

    let outcomes = retrieve_key_outcomes(&provider, "installation-1");
    assert_eq!(provider.calls.get(), 1);
    assert_eq!(provider.contexts.borrow().as_slice(), ["installation-1"]);
    assert!(matches!(outcomes.v10, ChromiumKeyOutcome::Success(_)));
    assert!(matches!(outcomes.v11, ChromiumKeyOutcome::Failure(_)));
    assert_eq!(outcomes.v20, ChromiumKeyOutcome::NotApplicable);
  }

  #[test]
  fn legacy_provider_keeps_current_shared_candidate_behavior() {
    let provider = LegacySharedKeyProvider::new(vec![vec![0x2a; 16]]);
    let outcomes = retrieve_key_outcomes(&provider, &());
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
    let outcomes = retrieve_key_outcomes(&provider, &());
    assert_eq!(outcomes, ChromiumKeyOutcomes::default());
  }
}
