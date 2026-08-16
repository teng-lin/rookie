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

  let (key_type, candidates) = match outcomes.route(cipher_version) {
    ChromiumKeyRoute::Candidates { tier, candidates } => {
      log::debug!("Chromium cipher tier: {tier}");
      let prefix = match cipher_version {
        super::chromium_crypto::ChromiumCipherVersion::V10 => b"v10",
        super::chromium_crypto::ChromiumCipherVersion::V11 => b"v11",
        super::chromium_crypto::ChromiumCipherVersion::V20 => b"v20",
        _ => unreachable!("candidate routes are only emitted for keyed tiers"),
      };
      (prefix.as_slice(), candidates)
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
