//! Post-decode boundary for Chromium row decryption.
//!
//! Row decoders emit `CookieRecord`s without key/provider dependencies. This is
//! the only post-decode consumer that combines those records with key outcomes;
//! provider and crypto modules still retrieve, construct, and use key material.

use super::chromium_crypto::{self, ChromiumKeyOutcomes, ChromiumKeyRoute, LegacyCipherOutcome};
use super::cookie_record::{
  CipherTier, CookieRecord, CookieValue, UnavailableCode, UnavailableReason,
};
use super::outcome::Retryability;
use crate::common::secret::{SecretBytes, SecretString};
use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use std::fmt;

const CHROMIUM_HOST_HASH_LEN: usize = 32;
const CHROMIUM_HOST_HASH_SCHEMA_VERSION: u32 = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ChromiumCookieDecodeError {
  InvalidUtf8AfterVerifiedHostHash,
  MissingRequiredHostHash,
  HostHashMismatch,
  HostHashMismatchWithInvalidUtf8,
  UnprefixedInvalidUtf8,
}

impl fmt::Display for ChromiumCookieDecodeError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::InvalidUtf8AfterVerifiedHostHash => {
        formatter.write_str("Chromium cookie value after verified host hash is not valid UTF-8")
      }
      Self::MissingRequiredHostHash => {
        formatter.write_str("Chromium cookie plaintext is missing the required v24+ host hash")
      }
      Self::HostHashMismatch => {
        formatter.write_str("Chromium cookie plaintext has a mismatched v24+ host hash")
      }
      Self::HostHashMismatchWithInvalidUtf8 => formatter
        .write_str("Chromium cookie plaintext has a mismatched host hash and is not valid UTF-8"),
      Self::UnprefixedInvalidUtf8 => {
        formatter.write_str("Chromium cookie plaintext is not valid UTF-8")
      }
    }
  }
}

impl std::error::Error for ChromiumCookieDecodeError {}

pub(super) fn decode_chromium_cookie_value(
  host_key: &str,
  plaintext: SecretBytes,
  schema_version: u32,
) -> std::result::Result<SecretString, ChromiumCookieDecodeError> {
  let host_hash_required = schema_version >= CHROMIUM_HOST_HASH_SCHEMA_VERSION;
  if host_hash_required && plaintext.len() < CHROMIUM_HOST_HASH_LEN {
    return Err(ChromiumCookieDecodeError::MissingRequiredHostHash);
  }

  if plaintext.len() >= CHROMIUM_HOST_HASH_LEN {
    let expected_host_hash = Sha256::digest(host_key.as_bytes());
    if plaintext[..CHROMIUM_HOST_HASH_LEN] == expected_host_hash[..] {
      return plaintext
        .into_secret_string_from(CHROMIUM_HOST_HASH_LEN)
        .map_err(|_| ChromiumCookieDecodeError::InvalidUtf8AfterVerifiedHostHash);
    }
    if host_hash_required {
      return Err(ChromiumCookieDecodeError::HostHashMismatch);
    }
    return plaintext
      .into_secret_string_from(0)
      .map_err(|_| ChromiumCookieDecodeError::HostHashMismatchWithInvalidUtf8);
  }

  plaintext
    .into_secret_string_from(0)
    .map_err(|_| ChromiumCookieDecodeError::UnprefixedInvalidUtf8)
}

#[derive(Debug)]
pub(super) enum ChromiumCookieValueError {
  Decrypt(anyhow::Error),
  Decode(ChromiumCookieDecodeError),
  ProviderUnavailable(anyhow::Error),
  ProviderFailed {
    error: anyhow::Error,
    retryability: Retryability,
  },
  /// A decoder or earlier unseal stage already classified this unavailable
  /// value. Preserve its taxonomy instead of laundering it through Decrypt.
  Unavailable(UnavailableReason),
}

impl ChromiumCookieValueError {
  pub(super) fn unavailable_code(&self) -> UnavailableCode {
    match self {
      Self::Decrypt(_) => UnavailableCode::Decrypt,
      Self::Decode(_) => UnavailableCode::Decode,
      Self::ProviderUnavailable(_) => UnavailableCode::ProviderUnavailable,
      Self::ProviderFailed { .. } => UnavailableCode::ProviderFailed,
      Self::Unavailable(reason) => reason.code,
    }
  }

  pub(super) fn retryability(&self) -> Retryability {
    match self {
      Self::ProviderUnavailable(_) => Retryability::NotRetryable,
      Self::ProviderFailed { retryability, .. } => *retryability,
      Self::Unavailable(reason) => match reason.code {
        UnavailableCode::ProviderUnavailable => Retryability::NotRetryable,
        UnavailableCode::ProviderFailed => Retryability::Retryable,
        UnavailableCode::Decrypt | UnavailableCode::Decode => Retryability::Unknown,
      },
      Self::Decrypt(_) | Self::Decode(_) => Retryability::Unknown,
    }
  }
}

impl fmt::Display for ChromiumCookieValueError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Decrypt(error) | Self::ProviderUnavailable(error) => error.fmt(formatter),
      Self::ProviderFailed { error, .. } => error.fmt(formatter),
      Self::Decode(error) => error.fmt(formatter),
      Self::Unavailable(reason) => reason.fmt(formatter),
    }
  }
}

impl From<anyhow::Error> for ChromiumCookieValueError {
  fn from(error: anyhow::Error) -> Self {
    Self::Decrypt(error)
  }
}

pub(super) fn unseal_chromium_record(
  mut record: CookieRecord,
  outcomes: &ChromiumKeyOutcomes,
  schema_version: u32,
) -> std::result::Result<CookieRecord, Box<(CookieRecord, ChromiumCookieValueError)>> {
  let (tier, bytes) = match std::mem::replace(
    &mut record.value,
    CookieValue::Unavailable(UnavailableReason {
      code: UnavailableCode::Decrypt,
      message: "unseal did not complete".to_owned(),
    }),
  ) {
    CookieValue::Plain(value) => {
      record.value = CookieValue::Plain(value);
      return Ok(record);
    }
    CookieValue::Unavailable(reason) => {
      record.value = CookieValue::Unavailable(reason.clone());
      return Err(Box::new((
        record,
        ChromiumCookieValueError::Unavailable(reason),
      )));
    }
    CookieValue::Encrypted { tier, bytes } => (tier, bytes),
  };

  match unseal_encrypted_value(record.domain_raw(), tier, &bytes, outcomes, schema_version) {
    Ok(value) => {
      record.value = CookieValue::Plain(value);
      Ok(record)
    }
    Err(error) => {
      record.value = CookieValue::Unavailable(UnavailableReason {
        code: error.unavailable_code(),
        message: error.to_string(),
      });
      Err(Box::new((record, error)))
    }
  }
}

fn unseal_encrypted_value(
  host_key: &str,
  tier: CipherTier,
  encrypted_value: &[u8],
  outcomes: &ChromiumKeyOutcomes,
  schema_version: u32,
) -> std::result::Result<SecretString, ChromiumCookieValueError> {
  unseal_with_cipher_adapter(
    host_key,
    tier,
    encrypted_value,
    outcomes,
    schema_version,
    CipherAdapter {
      candidate_key_length: chromium_crypto::CANDIDATE_KEY_LENGTH,
      validate_keyed_envelope: chromium_crypto::validate_keyed_envelope,
      decrypt_candidate: chromium_crypto::decrypt_keyed_candidate,
      decrypt_legacy: chromium_crypto::decrypt_legacy,
    },
  )
}

pub(super) struct CipherAdapter<Validate, Candidate, Legacy> {
  pub(super) candidate_key_length: Option<usize>,
  pub(super) validate_keyed_envelope: Validate,
  pub(super) decrypt_candidate: Candidate,
  pub(super) decrypt_legacy: Legacy,
}

fn unseal_with_cipher_adapter<Validate, Candidate, Legacy>(
  host_key: &str,
  tier: CipherTier,
  encrypted_value: &[u8],
  outcomes: &ChromiumKeyOutcomes,
  schema_version: u32,
  adapter: CipherAdapter<Validate, Candidate, Legacy>,
) -> std::result::Result<SecretString, ChromiumCookieValueError>
where
  Validate: Fn(&[u8]) -> Result<()>,
  Candidate: Fn(&[u8], &[u8]) -> Result<SecretBytes>,
  Legacy: Fn(&[u8]) -> Result<LegacyCipherOutcome>,
{
  let CipherAdapter {
    candidate_key_length,
    validate_keyed_envelope,
    decrypt_candidate,
    decrypt_legacy,
  } = adapter;
  let cipher_version = match tier {
    CipherTier::V10 => super::chromium_crypto::ChromiumCipherVersion::V10,
    CipherTier::V11 => super::chromium_crypto::ChromiumCipherVersion::V11,
    CipherTier::V12SecretPortal => super::chromium_crypto::ChromiumCipherVersion::V12SecretPortal,
    CipherTier::V20 => super::chromium_crypto::ChromiumCipherVersion::V20,
    CipherTier::LegacyDpapi => super::chromium_crypto::ChromiumCipherVersion::LegacyDpapi,
    CipherTier::Unknown(prefix) => super::chromium_crypto::ChromiumCipherVersion::Unknown(prefix),
    CipherTier::Malformed { observed_len } => {
      return Err(ChromiumCookieValueError::Decrypt(anyhow!(
        "Chromium encrypted value is {observed_len} bytes, shorter than the 3-byte cipher prefix"
      )));
    }
  };

  let (key_type, candidates, provider_fallback) = match outcomes.route(cipher_version) {
    ChromiumKeyRoute::Candidates {
      tier,
      candidates,
      fallback_failure,
    } => {
      log::debug!("Chromium cipher tier: {tier}");
      let prefix = match cipher_version {
        super::chromium_crypto::ChromiumCipherVersion::V10 => b"v10",
        super::chromium_crypto::ChromiumCipherVersion::V11 => b"v11",
        super::chromium_crypto::ChromiumCipherVersion::V20 => b"v20",
        _ => unreachable!("candidate routes are only emitted for keyed tiers"),
      };
      (
        prefix.as_slice(),
        candidates,
        fallback_failure.map(|failure| (tier, failure)),
      )
    }
    ChromiumKeyRoute::NotApplicable { tier } => {
      return Err(ChromiumCookieValueError::ProviderUnavailable(anyhow!(
        "Chromium {tier} key provider is not applicable"
      )));
    }
    ChromiumKeyRoute::Failure { tier, failure } => {
      return Err(ChromiumCookieValueError::ProviderFailed {
        error: anyhow!("Chromium {tier} key provider failed: {}", failure.message()),
        retryability: failure.retryability(),
      });
    }
    ChromiumKeyRoute::LegacyDpapi => {
      return match decrypt_legacy(encrypted_value).map_err(ChromiumCookieValueError::Decrypt)? {
        LegacyCipherOutcome::Plaintext(plaintext) => {
          decode_chromium_cookie_value(host_key, plaintext, schema_version)
            .map_err(ChromiumCookieValueError::Decode)
        }
        LegacyCipherOutcome::Unsupported(message) => Err(
          ChromiumCookieValueError::ProviderUnavailable(anyhow!(message)),
        ),
      };
    }
    ChromiumKeyRoute::V12SecretPortal => {
      return Err(ChromiumCookieValueError::ProviderUnavailable(anyhow!(
        "Chromium v12 SecretPortal encryption is recognized but unsupported"
      )));
    }
    ChromiumKeyRoute::Unknown(_) => {
      return Err(ChromiumCookieValueError::Decrypt(anyhow!(
        "Unknown Chromium cipher prefix"
      )));
    }
  };

  let candidate_key_length = candidate_key_length.ok_or_else(|| {
    ChromiumCookieValueError::ProviderUnavailable(anyhow!(
      "Chromium keyed cookie decryption is unsupported on this platform"
    ))
  })?;
  validate_keyed_envelope(encrypted_value).map_err(ChromiumCookieValueError::Decrypt)?;
  let mut last_decode_error = None;

  for key in candidates {
    if key.as_bytes().len() != candidate_key_length {
      log::warn!(
        "Skipping {key_type:?} candidate key with invalid length {}",
        key.as_bytes().len()
      );
      continue;
    }
    match decrypt_candidate(encrypted_value, key.as_bytes()) {
      Ok(plaintext) => match decode_chromium_cookie_value(host_key, plaintext, schema_version) {
        Ok(decoded) => return Ok(decoded),
        Err(error) => {
          log::debug!("Failed to decode decrypted Chromium value: {error}");
          last_decode_error = Some(error);
        }
      },
      Err(error) => log::debug!("Failed to decrypt with a key: {error}"),
    }
  }

  // Every candidate was a stand-in for a failed credential lookup, so the
  // provider failure is the actionable diagnostic rather than the decrypt or
  // decode error the substitute key happened to produce.
  if let Some((tier, failure)) = provider_fallback {
    return Err(ChromiumCookieValueError::ProviderFailed {
      error: anyhow!("Chromium {tier} key provider failed: {}", failure.message()),
      retryability: failure.retryability(),
    });
  }

  match last_decode_error {
    Some(error) => Err(ChromiumCookieValueError::Decode(error)),
    None => Err(ChromiumCookieValueError::Decrypt(anyhow!(
      "no Chromium key candidate decrypted this cookie value"
    ))),
  }
}

#[cfg(test)]
pub(super) fn decrypt_encrypted_value(
  host_key: &str,
  value: String,
  encrypted_value: &[u8],
  keys: &[Vec<u8>],
  schema_version: u32,
) -> std::result::Result<String, ChromiumCookieValueError> {
  let outcomes = ChromiumKeyOutcomes::from_legacy_shared(keys.to_vec());
  decrypt_encrypted_value_with_outcomes(host_key, value, encrypted_value, &outcomes, schema_version)
}

#[cfg(test)]
pub(super) fn decrypt_encrypted_value_with_outcomes(
  host_key: &str,
  value: String,
  encrypted_value: &[u8],
  outcomes: &ChromiumKeyOutcomes,
  schema_version: u32,
) -> std::result::Result<String, ChromiumCookieValueError> {
  decrypt_encrypted_value_with_cipher_adapter(
    host_key,
    value,
    encrypted_value,
    outcomes,
    schema_version,
    CipherAdapter {
      candidate_key_length: chromium_crypto::CANDIDATE_KEY_LENGTH,
      validate_keyed_envelope: chromium_crypto::validate_keyed_envelope,
      decrypt_candidate: chromium_crypto::decrypt_keyed_candidate,
      decrypt_legacy: chromium_crypto::decrypt_legacy,
    },
  )
}

#[cfg(test)]
pub(super) fn decrypt_encrypted_value_with_cipher_adapter<Validate, Candidate, Legacy>(
  host_key: &str,
  value: String,
  encrypted_value: &[u8],
  outcomes: &ChromiumKeyOutcomes,
  schema_version: u32,
  adapter: CipherAdapter<Validate, Candidate, Legacy>,
) -> std::result::Result<String, ChromiumCookieValueError>
where
  Validate: Fn(&[u8]) -> Result<()>,
  Candidate: Fn(&[u8], &[u8]) -> Result<SecretBytes>,
  Legacy: Fn(&[u8]) -> Result<LegacyCipherOutcome>,
{
  if encrypted_value.is_empty() {
    return Ok(value);
  }
  // A non-empty ciphertext is authoritative even when the legacy plaintext
  // column is also populated. Keeping that decision here makes every public
  // projection share the same security correction.
  unseal_with_cipher_adapter(
    host_key,
    CipherTier::detect(encrypted_value),
    encrypted_value,
    outcomes,
    schema_version,
    adapter,
  )
  .map(SecretString::into_output_string)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::browser::chromium_crypto::{ChromiumKeyFailure, ChromiumKeyOutcome};
  #[cfg(unix)]
  use crate::browser::chromium_platform_keys::create_pbkdf2_key;
  #[cfg(target_os = "windows")]
  use crate::browser::chromium_test_support::encrypt_windows_gcm_cookie;
  use crate::browser::chromium_test_support::host_bound_plaintext;
  use crate::common::enums::{CookieContext, SAME_SITE_UNSPECIFIED};
  use std::cell::{Cell, RefCell};

  #[test]
  fn shared_cipher_loop_never_prefers_plaintext_over_ciphertext() {
    let unavailable = ChromiumKeyOutcomes::default();
    let encrypted_wins = decrypt_encrypted_value_with_cipher_adapter(
      ".example.com",
      "plain".to_string(),
      b"x",
      &unavailable,
      23,
      CipherAdapter {
        candidate_key_length: Some(4),
        validate_keyed_envelope: |_: &[u8]| {
          panic!("malformed ciphertext must fail before envelope validation")
        },
        decrypt_candidate: |_: &[u8], _: &[u8]| {
          panic!("malformed ciphertext must fail before candidate decryption")
        },
        decrypt_legacy: |_: &[u8]| {
          panic!("malformed ciphertext must fail before legacy decryption")
        },
      },
    )
    .expect_err("non-empty ciphertext must be classified before plaintext is considered");
    assert!(matches!(
      encrypted_wins,
      ChromiumCookieValueError::Decrypt(_)
    ));
    assert!(encrypted_wins
      .to_string()
      .contains("shorter than the 3-byte"));

    let malformed = decrypt_encrypted_value_with_cipher_adapter(
      ".example.com",
      String::new(),
      b"v1",
      &unavailable,
      23,
      CipherAdapter {
        candidate_key_length: Some(4),
        validate_keyed_envelope: |_: &[u8]| {
          panic!("malformed prefix must fail before envelope validation")
        },
        decrypt_candidate: |_: &[u8], _: &[u8]| {
          panic!("malformed prefix must fail before candidate decryption")
        },
        decrypt_legacy: |_: &[u8]| panic!("malformed prefix must fail before legacy decryption"),
      },
    )
    .expect_err("cipher detection precedes routing");
    assert!(matches!(malformed, ChromiumCookieValueError::Decrypt(_)));
    assert!(malformed.to_string().contains("shorter than the 3-byte"));

    let no_provider = decrypt_encrypted_value_with_cipher_adapter(
      ".example.com",
      String::new(),
      b"v10payload",
      &unavailable,
      23,
      CipherAdapter {
        candidate_key_length: Some(4),
        validate_keyed_envelope: |_: &[u8]| {
          panic!("provider routing must precede envelope validation")
        },
        decrypt_candidate: |_: &[u8], _: &[u8]| {
          panic!("unavailable provider must not try a candidate")
        },
        decrypt_legacy: |_: &[u8]| panic!("keyed route must not call legacy decryption"),
      },
    )
    .expect_err("route reports the unavailable key tier");
    assert!(matches!(
      no_provider,
      ChromiumCookieValueError::ProviderUnavailable(_)
    ));

    let keyed = ChromiumKeyOutcomes {
      v10: crate::browser::chromium_crypto::ChromiumKeyOutcome::success(vec![vec![0x10; 4]])
        .expect("nonempty candidate"),
      v11: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
      v20: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
    };
    let unsupported = decrypt_encrypted_value_with_cipher_adapter(
      ".example.com",
      String::new(),
      b"v10payload",
      &keyed,
      23,
      CipherAdapter {
        candidate_key_length: None,
        validate_keyed_envelope: |_: &[u8]| {
          panic!("unsupported host must fail before envelope validation")
        },
        decrypt_candidate: |_: &[u8], _: &[u8]| panic!("unsupported host must not try a candidate"),
        decrypt_legacy: |_: &[u8]| panic!("keyed route must not call legacy decryption"),
      },
    )
    .expect_err("unsupported host rejects a keyed route before parsing its envelope");
    assert!(matches!(
      unsupported,
      ChromiumCookieValueError::ProviderUnavailable(_)
    ));
    assert_eq!(
      unsupported.to_string(),
      "Chromium keyed cookie decryption is unsupported on this platform"
    );

    let envelope_error = decrypt_encrypted_value_with_cipher_adapter(
      ".example.com",
      String::new(),
      b"v10payload",
      &keyed,
      23,
      CipherAdapter {
        candidate_key_length: Some(4),
        validate_keyed_envelope: |_: &[u8]| Err(anyhow!("synthetic envelope failure")),
        decrypt_candidate: |_: &[u8], _: &[u8]| {
          panic!("envelope validation must precede candidate decryption")
        },
        decrypt_legacy: |_: &[u8]| panic!("keyed route must not call legacy decryption"),
      },
    )
    .expect_err("invalid envelope stops before candidates");
    assert!(matches!(
      envelope_error,
      ChromiumCookieValueError::Decrypt(_)
    ));
    assert_eq!(envelope_error.to_string(), "synthetic envelope failure");
  }

  #[test]
  fn unavailable_records_preserve_their_existing_reason_taxonomy() {
    for code in [
      UnavailableCode::Decrypt,
      UnavailableCode::Decode,
      UnavailableCode::ProviderUnavailable,
      UnavailableCode::ProviderFailed,
    ] {
      let reason = super::super::cookie_record::UnavailableReason {
        code,
        message: format!("synthetic {code:?} reason"),
      };
      let record = CookieRecord::from_legacy_fields(
        ".example.com".to_owned(),
        "/".to_owned(),
        false,
        None,
        "classified".to_owned(),
        super::super::cookie_record::CookieValue::Unavailable(reason.clone()),
        false,
        SAME_SITE_UNSPECIFIED,
        CookieContext::default(),
        1,
      );

      let failure = unseal_chromium_record(record, &ChromiumKeyOutcomes::default(), 23)
        .expect_err("unavailable input remains unavailable");
      let (record, error) = *failure;
      assert_eq!(error.unavailable_code(), code);
      assert!(matches!(error, ChromiumCookieValueError::Unavailable(_)));
      let super::super::cookie_record::CookieValue::Unavailable(returned) = record.value else {
        panic!("unseal must preserve the unavailable record")
      };
      assert_eq!(returned.code, code);
      assert_eq!(returned.message, reason.message);
    }
  }

  #[test]
  fn exhausted_candidate_diagnostic_describes_the_actual_condition() {
    let outcomes = ChromiumKeyOutcomes {
      v10: crate::browser::chromium_crypto::ChromiumKeyOutcome::success(vec![vec![0x10; 4]])
        .expect("nonempty candidate"),
      v11: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
      v20: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
    };
    let error = decrypt_encrypted_value_with_cipher_adapter(
      ".example.com",
      String::new(),
      b"v10payload",
      &outcomes,
      23,
      CipherAdapter {
        candidate_key_length: Some(4),
        validate_keyed_envelope: |_: &[u8]| Ok(()),
        decrypt_candidate: |_: &[u8], _: &[u8]| Err(anyhow!("synthetic primitive failure")),
        decrypt_legacy: |_: &[u8]| panic!("keyed route must not call legacy decryption"),
      },
    )
    .expect_err("every candidate failed");
    assert_eq!(
      error.to_string(),
      "no Chromium key candidate decrypted this cookie value"
    );
  }

  #[test]
  fn shared_cipher_loop_tries_candidates_then_decodes_and_keeps_decode_precedence() {
    let outcomes = ChromiumKeyOutcomes {
      v10: crate::browser::chromium_crypto::ChromiumKeyOutcome::success(vec![
        vec![0x10; 4],
        vec![0x20; 4],
      ])
      .expect("nonempty candidates"),
      v11: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
      v20: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
    };
    let events = RefCell::new(Vec::new());
    let decoded = decrypt_encrypted_value_with_cipher_adapter(
      ".example.com",
      String::new(),
      b"v10payload",
      &outcomes,
      23,
      CipherAdapter {
        candidate_key_length: Some(4),
        validate_keyed_envelope: |_: &[u8]| {
          events.borrow_mut().push("validate");
          Ok(())
        },
        decrypt_candidate: |_: &[u8], key: &[u8]| {
          if key[0] == 0x10 {
            events.borrow_mut().push("candidate-1");
            Ok(SecretBytes::new(vec![0xff]))
          } else {
            events.borrow_mut().push("candidate-2");
            Ok(SecretBytes::new(b"decoded".to_vec()))
          }
        },
        decrypt_legacy: |_: &[u8]| panic!("keyed route must not call legacy decryption"),
      },
    )
    .expect("second candidate decodes after the first candidate's decode error");
    assert_eq!(decoded, "decoded");
    assert_eq!(
      *events.borrow(),
      vec!["validate", "candidate-1", "candidate-2"]
    );

    let calls = Cell::new(0);
    let decode_error = decrypt_encrypted_value_with_cipher_adapter(
      ".example.com",
      String::new(),
      b"v10payload",
      &outcomes,
      23,
      CipherAdapter {
        candidate_key_length: Some(4),
        validate_keyed_envelope: |_: &[u8]| Ok(()),
        decrypt_candidate: |_: &[u8], _: &[u8]| {
          let call = calls.get() + 1;
          calls.set(call);
          if call == 1 {
            Ok(SecretBytes::new(vec![0xff]))
          } else {
            Err(anyhow!("later primitive failure"))
          }
        },
        decrypt_legacy: |_: &[u8]| panic!("keyed route must not call legacy decryption"),
      },
    )
    .expect_err("a prior decode error outranks later primitive failures");
    assert!(matches!(
      decode_error,
      ChromiumCookieValueError::Decode(ChromiumCookieDecodeError::UnprefixedInvalidUtf8)
    ));
  }

  #[test]
  fn shared_cipher_loop_routes_fallible_legacy_plaintext_through_shared_decode() {
    let host = ".example.com";
    let expected = host_bound_plaintext(host, b"legacy value");
    let events = RefCell::new(Vec::new());
    let decoded = decrypt_encrypted_value_with_cipher_adapter(
      host,
      "must not win".to_owned(),
      b"raw-dpapi-envelope",
      &ChromiumKeyOutcomes::default(),
      24,
      CipherAdapter {
        candidate_key_length: Some(4),
        validate_keyed_envelope: |_: &[u8]| {
          panic!("legacy route must not validate a keyed envelope")
        },
        decrypt_candidate: |_: &[u8], _: &[u8]| {
          panic!("legacy route must not try a keyed candidate")
        },
        decrypt_legacy: |_: &[u8]| {
          events.borrow_mut().push("legacy");
          Ok(LegacyCipherOutcome::Plaintext(SecretBytes::new(
            expected.clone(),
          )))
        },
      },
    )
    .expect("legacy plaintext is decoded by the shared host-binding policy");
    assert_eq!(decoded, "legacy value");
    assert_eq!(*events.borrow(), vec!["legacy"]);
  }

  #[cfg(unix)]
  #[test]
  fn chromium_mock_keychain_known_answer() {
    let salt = b"saltysalt";
    let key = create_pbkdf2_key("mock_password", salt, 1003);
    assert_eq!(
      *key,
      vec![
        0xaf, 0x0f, 0x76, 0x2a, 0xaf, 0x6d, 0x7d, 0x11, 0x58, 0x1b, 0x7a, 0xa8, 0xce, 0x72, 0x18,
        0xde,
      ]
    );

    let ciphertext = [
      0x76, 0x31, 0x30, 0xbf, 0x08, 0x6d, 0x20, 0x56, 0x86, 0x1a, 0x80, 0xde, 0x82, 0x5f, 0xc9,
      0x35, 0x86, 0x86, 0x30, 0x64, 0x4f, 0x2c, 0xa1, 0x87, 0x45, 0x02, 0x13, 0xae, 0x66, 0x81,
      0xb4, 0xd6, 0x43, 0xd1, 0x9b, 0x25, 0x81, 0xc8, 0x5c, 0x88, 0x78, 0xc1, 0xbc, 0x97, 0xe7,
      0x26, 0xa1, 0x0e, 0x51, 0xea, 0x77,
    ];
    let plaintext = [
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
      0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
      0x1e, 0x1f,
    ];

    let decrypted = decrypt_encrypted_value(
      ".example.com",
      "".to_string(),
      &ciphertext,
      &[key.to_vec()],
      23,
    )
    .expect("decrypt vector");
    assert_eq!(decrypted.as_bytes(), plaintext);
  }

  #[test]
  fn decode_cookie_value_strips_only_the_exact_stored_host_hash() {
    let plaintext = host_bound_plaintext(".example.com", b"cookie value");
    let decoded =
      decode_chromium_cookie_value(".example.com", SecretBytes::new(plaintext.clone()), 23)
        .expect("host match");
    assert_eq!(decoded.as_str(), "cookie value");
    assert_eq!(
      decode_chromium_cookie_value("example.com", SecretBytes::new(plaintext), 23),
      Err(ChromiumCookieDecodeError::HostHashMismatchWithInvalidUtf8),
      "the leading dot in the stored host is part of the exact hash input"
    );
  }

  #[test]
  fn decode_cookie_value_maps_an_exact_hash_only_plaintext_to_empty() {
    let plaintext = host_bound_plaintext(".example.com", b"");
    let decoded = decode_chromium_cookie_value(".example.com", SecretBytes::new(plaintext), 23)
      .expect("hash only");
    assert_eq!(decoded.as_str(), "");
  }

  #[test]
  fn decode_cookie_value_preserves_valid_utf8_when_a_32_byte_prefix_mismatches() {
    let plaintext = b"this old unprefixed value is longer than thirty-two bytes".to_vec();
    let decoded =
      decode_chromium_cookie_value(".example.com", SecretBytes::new(plaintext.clone()), 23)
        .expect("old unprefixed value");
    assert_eq!(decoded.as_bytes(), plaintext);
  }

  #[test]
  fn decode_cookie_value_rejects_a_mismatched_non_utf8_prefix() {
    let mut plaintext = vec![0xff; CHROMIUM_HOST_HASH_LEN];
    plaintext.extend_from_slice(b"must not be stripped");
    assert_eq!(
      decode_chromium_cookie_value(".example.com", SecretBytes::new(plaintext), 23),
      Err(ChromiumCookieDecodeError::HostHashMismatchWithInvalidUtf8)
    );
  }

  #[test]
  fn decode_cookie_value_preserves_short_and_old_unprefixed_utf8() {
    assert_eq!(
      decode_chromium_cookie_value(".example.com", SecretBytes::new(b"short".to_vec()), 23,)
        .expect("short value")
        .as_str(),
      "short"
    );
    let old = "x".repeat(CHROMIUM_HOST_HASH_LEN + 8);
    assert_eq!(
      decode_chromium_cookie_value(
        ".example.com",
        SecretBytes::new(old.as_bytes().to_vec()),
        23,
      )
      .expect("old long value")
      .as_str(),
      old
    );
  }

  #[test]
  fn decode_cookie_value_requires_an_exact_host_hash_for_v24_and_later() {
    assert_eq!(
      decode_chromium_cookie_value(".example.com", SecretBytes::new(b"short".to_vec()), 24,),
      Err(ChromiumCookieDecodeError::MissingRequiredHostHash)
    );
    assert_eq!(
      decode_chromium_cookie_value(
        ".example.com",
        SecretBytes::new(b"this valid UTF-8 value has no matching host hash prefix".to_vec()),
        24,
      ),
      Err(ChromiumCookieDecodeError::HostHashMismatch)
    );

    let plaintext = host_bound_plaintext(".example.com", b"bound value");
    assert_eq!(
      decode_chromium_cookie_value(".example.com", SecretBytes::new(plaintext), 24)
        .expect("verified host hash")
        .as_str(),
      "bound value"
    );
  }

  #[test]
  fn decode_cookie_value_rejects_invalid_utf8_after_a_verified_hash() {
    let plaintext = host_bound_plaintext(".example.com", &[0xff]);
    assert_eq!(
      decode_chromium_cookie_value(".example.com", SecretBytes::new(plaintext), 23),
      Err(ChromiumCookieDecodeError::InvalidUtf8AfterVerifiedHostHash)
    );
  }

  #[cfg(unix)]
  #[test]
  fn decrypt_encrypted_value_short_blob_rejects_plaintext_fallback() {
    let error = decrypt_encrypted_value(".example.com", "orig".to_string(), b"v1", &[], 23)
      .expect_err("malformed ciphertext must not expose the plaintext column");
    assert!(error.to_string().contains("shorter than the 3-byte"));
  }

  /// Builds candidates that stand in for a failed credential lookup.
  fn fallback_outcome(candidate: Vec<u8>, message: &str) -> ChromiumKeyOutcome {
    let outcome = ChromiumKeyOutcome::success(vec![candidate]).expect("nonempty candidate");
    let ChromiumKeyOutcome::Success(candidates) = outcome else {
      panic!("success fixture must be a candidate outcome");
    };
    ChromiumKeyOutcome::Success(candidates.with_fallback_failure(
      ChromiumKeyFailure::new_with_retryability(message, Retryability::Retryable),
    ))
  }

  #[test]
  fn provider_fallback_candidates_keep_the_provider_failure_when_none_decrypt() {
    let outcomes = ChromiumKeyOutcomes {
      v10: ChromiumKeyOutcome::NotApplicable,
      v11: fallback_outcome(vec![0x11; 4], "all Linux keyring backends failed: locked"),
      v20: ChromiumKeyOutcome::NotApplicable,
    };

    let error = decrypt_encrypted_value_with_cipher_adapter(
      ".example.com",
      String::new(),
      b"v11payload",
      &outcomes,
      23,
      CipherAdapter {
        candidate_key_length: Some(4),
        validate_keyed_envelope: |_: &[u8]| Ok(()),
        decrypt_candidate: |_: &[u8], _: &[u8]| Err(anyhow!("candidate rejected")),
        decrypt_legacy: |_: &[u8]| panic!("keyed route must not call legacy decryption"),
      },
    )
    .expect_err("a fallback that decrypts nothing must not hide why the provider failed");

    assert!(matches!(
      error,
      ChromiumCookieValueError::ProviderFailed { .. }
    ));
    assert_eq!(error.retryability(), Retryability::Retryable);
    assert_eq!(
      error.to_string(),
      "Chromium v11 key provider failed: all Linux keyring backends failed: locked"
    );
  }

  #[test]
  fn provider_fallback_candidates_that_decrypt_are_not_a_failure() {
    let outcomes = ChromiumKeyOutcomes {
      v10: ChromiumKeyOutcome::NotApplicable,
      v11: fallback_outcome(vec![0x11; 4], "all Linux keyring backends failed: locked"),
      v20: ChromiumKeyOutcome::NotApplicable,
    };

    let decrypted = decrypt_encrypted_value_with_cipher_adapter(
      ".example.com",
      String::new(),
      b"v11payload",
      &outcomes,
      23,
      CipherAdapter {
        candidate_key_length: Some(4),
        validate_keyed_envelope: |_: &[u8]| Ok(()),
        decrypt_candidate: |_: &[u8], _: &[u8]| Ok(SecretBytes::new(b"fallback value".to_vec())),
        decrypt_legacy: |_: &[u8]| panic!("keyed route must not call legacy decryption"),
      },
    )
    .expect("a fallback key that decrypts the value is a success");

    assert_eq!(decrypted, "fallback value");
  }

  #[cfg(unix)]
  #[test]
  fn linux_keyring_failure_diagnostic_reaches_v11_decryption() {
    let outcomes = ChromiumKeyOutcomes {
      v10: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
      v11: crate::browser::chromium_crypto::ChromiumKeyOutcome::failure(
        "all Linux keyring backends failed: Secret Service locked; KWallet denied",
      ),
      v20: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
    };

    let error = decrypt_encrypted_value_with_outcomes(
      ".example.com",
      String::new(),
      b"v11encrypted",
      &outcomes,
      23,
    )
    .expect_err("v11 must preserve the provider diagnostic")
    .to_string();
    assert!(error.contains("Chromium v11 key provider failed"));
    assert!(error.contains("all Linux keyring backends failed"));
    assert!(error.contains("Secret Service locked"));
    assert!(error.contains("KWallet denied"));
  }

  #[cfg(unix)]
  #[test]
  fn decrypt_encrypted_value_invalid_utf8_returns_error() {
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let key = vec![0u8; 16];
    let iv = [b' '; 16];
    let cipher = Aes128CbcEnc::new((&key[..16]).into(), &iv.into());

    let data = vec![0xffu8; 16];
    let mut buf = vec![0u8; 32];
    buf[..16].copy_from_slice(&data);

    let ct = cipher.encrypt_padded_mut::<Pkcs7>(&mut buf, 16).unwrap();

    let mut encrypted_value = b"v10".to_vec();
    encrypted_value.extend_from_slice(ct);

    assert!(
      decrypt_encrypted_value(".example.com", "".to_string(), &encrypted_value, &[key], 23,)
        .is_err()
    );
  }

  #[cfg(unix)]
  #[test]
  fn decrypt_encrypted_value_decodes_host_hash_prefixed_plaintext() {
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let key = vec![0u8; 16];
    let iv = [b' '; 16];
    let plaintext = host_bound_plaintext(".example.com", b"cookie value");
    let mut ciphertext_buffer = vec![0u8; plaintext.len() + 16];
    ciphertext_buffer[..plaintext.len()].copy_from_slice(&plaintext);
    let cipher = Aes128CbcEnc::new((&key[..]).into(), &iv.into());
    let ciphertext = cipher
      .encrypt_padded_mut::<Pkcs7>(&mut ciphertext_buffer, plaintext.len())
      .expect("encrypt fixture");

    let mut encrypted_value = b"v10".to_vec();
    encrypted_value.extend_from_slice(ciphertext);
    let decrypted =
      decrypt_encrypted_value(".example.com", "".to_string(), &encrypted_value, &[key], 23)
        .expect("decrypt host-hash-prefixed value");

    assert_eq!(decrypted, "cookie value");
  }

  #[cfg(unix)]
  #[test]
  fn decrypt_encrypted_value_tries_next_key_after_invalid_utf8() {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let correct_key = vec![0u8; 16];
    let iv = [b' '; 16];
    let expected = b"valid cookie value";
    let mut ciphertext_buffer = vec![0u8; expected.len() + 16];
    ciphertext_buffer[..expected.len()].copy_from_slice(expected);
    let cipher = Aes128CbcEnc::new((&correct_key[..]).into(), &iv.into());
    let ciphertext = cipher
      .encrypt_padded_mut::<Pkcs7>(&mut ciphertext_buffer, expected.len())
      .expect("encrypt fixture")
      .to_vec();

    let invalid_utf8_key = (1u16..=u16::MAX)
      .find_map(|candidate| {
        let mut key = vec![0; 16];
        key[..2].copy_from_slice(&candidate.to_le_bytes());
        let cipher = Aes128CbcDec::new((&key[..]).into(), &iv.into());
        let mut candidate_ciphertext = ciphertext.clone();
        let plaintext = cipher
          .decrypt_padded_mut::<Pkcs7>(&mut candidate_ciphertext)
          .ok()?;
        String::from_utf8(plaintext.to_vec())
          .is_err()
          .then_some(key)
      })
      .expect("fixture must include a wrong key with valid padding and invalid UTF-8");

    let mut encrypted_value = b"v10".to_vec();
    encrypted_value.extend_from_slice(&ciphertext);
    let decrypted = decrypt_encrypted_value(
      ".example.com",
      "".to_string(),
      &encrypted_value,
      &[invalid_utf8_key, correct_key],
      23,
    )
    .expect("second key should decrypt the cookie");

    assert_eq!(decrypted, "valid cookie value");
  }

  #[cfg(windows)]
  #[test]
  fn decrypt_encrypted_value_windows_verifies_host_hash_and_tries_later_key() {
    let correct_key = [0x20; 32];
    let wrong_key = vec![0x10; 32];
    let plaintext = host_bound_plaintext(".example.com", b"verified value");
    let encrypted_value = encrypt_windows_gcm_cookie(b"v20", &correct_key, &plaintext);

    let decrypted = decrypt_encrypted_value(
      ".example.com",
      "must not win".to_string(),
      &encrypted_value,
      &[wrong_key, correct_key.to_vec()],
      23,
    )
    .expect("later key should authenticate and decode");
    assert_eq!(decrypted, "verified value");
  }

  #[cfg(windows)]
  #[test]
  fn decrypt_encrypted_value_windows_classifies_non_utf8_hash_mismatch_as_decode_failure() {
    let key = [0x20; 32];
    let plaintext = vec![0xff; CHROMIUM_HOST_HASH_LEN + 1];
    let encrypted_value = encrypt_windows_gcm_cookie(b"v20", &key, &plaintext);

    assert!(matches!(
      decrypt_encrypted_value(
        ".example.com",
        "".to_string(),
        &encrypted_value,
        &[key.to_vec()],
        23,
      ),
      Err(ChromiumCookieValueError::Decode(
        ChromiumCookieDecodeError::HostHashMismatchWithInvalidUtf8
      ))
    ));
  }

  #[cfg(windows)]
  #[test]
  fn decrypt_encrypted_value_windows_truncated_blob_rejects_plaintext_fallback() {
    let key = vec![0u8; 32];
    for len in 3..15 {
      let mut blob = b"v10".to_vec();
      blob.resize(len, 0);
      let error = decrypt_encrypted_value(
        ".example.com",
        "must not escape".to_string(),
        &blob,
        std::slice::from_ref(&key),
        23,
      )
      .expect_err("truncated ciphertext must be rejected without exposing plaintext");
      assert!(!error.to_string().contains("must not escape"));
    }
  }

  #[cfg(windows)]
  #[test]
  fn decrypt_encrypted_value_skips_wrong_length_key() {
    // A candidate key that isn't 32 bytes must be skipped, not panic the
    // AES-256-GCM path (Key::from_slice would have panicked). Reaching the
    // assertion at all proves there was no panic; with no usable key the
    // function falls through to an error.
    let mut blob = b"v10".to_vec();
    blob.resize(31, 0); // "v10" + 12-byte nonce + 16-byte ciphertext region
    let short_key = vec![0u8; 10];
    let res = decrypt_encrypted_value(".example.com", "".to_string(), &blob, &[short_key], 23);
    assert!(res.is_err());
  }
}
