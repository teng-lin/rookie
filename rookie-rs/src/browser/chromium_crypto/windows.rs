use super::LegacyCipherOutcome;
use aes_gcm::{
  aead::{generic_array::GenericArray, Aead, KeyInit},
  Aes256Gcm,
};
use anyhow::{anyhow, Context, Result};

use crate::common::secret::SecretBytes;

pub(super) const CANDIDATE_KEY_LENGTH: Option<usize> = Some(32);

pub(super) fn validate_keyed_envelope(encrypted_value: &[u8]) -> Result<()> {
  if encrypted_value.len() < 15 {
    return Err(anyhow!(
      "Chromium encrypted value is {} bytes, shorter than the version and nonce header",
      encrypted_value.len()
    ));
  }
  Ok(())
}

pub(super) fn decrypt_keyed_candidate(encrypted_value: &[u8], key: &[u8]) -> Result<SecretBytes> {
  validate_keyed_envelope(encrypted_value)?;
  let cipher = Aes256Gcm::new_from_slice(key)
    .map_err(|_| anyhow!("Chromium AES-GCM candidate key has an invalid length"))?;
  let nonce = GenericArray::from_slice(&encrypted_value[3..15]);
  cipher
    .decrypt(nonce, &encrypted_value[15..])
    .map(SecretBytes::new)
    .map_err(|_| anyhow!("Chromium AES-GCM authentication failed"))
}

pub(super) fn decrypt_legacy(encrypted_value: &[u8]) -> Result<LegacyCipherOutcome> {
  crate::windows::dpapi::decrypt(encrypted_value)
    .context("Failed to decrypt legacy Chromium DPAPI cookie")
    .map(LegacyCipherOutcome::Plaintext)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn windows_gcm_known_answer_and_error_contract() {
    let key = [0x20; 32];
    let encrypted_value = [
      0x76, 0x32, 0x30, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
      0xdd, 0x4a, 0xb8, 0x99, 0x8f, 0x20, 0xd9, 0xbc, 0x48, 0x81, 0xbf, 0xb3, 0x09, 0x7d, 0xff,
      0x14, 0xbd, 0xfe, 0x57, 0x09, 0x95, 0x23, 0xa2, 0x9e, 0x7c, 0x7b, 0xad, 0x7a,
    ];

    assert_eq!(
      decrypt_keyed_candidate(&encrypted_value, &key)
        .expect("decrypt known answer")
        .as_slice(),
      b"known answer"
    );
    assert!(validate_keyed_envelope(b"v20short")
      .expect_err("truncated envelope")
      .to_string()
      .contains("version and nonce header"));
    assert!(decrypt_keyed_candidate(&encrypted_value, &[0; 31])
      .expect_err("wrong key length")
      .to_string()
      .contains("invalid length"));
    let mut corrupt = encrypted_value;
    *corrupt.last_mut().expect("tag byte") ^= 1;
    assert!(decrypt_keyed_candidate(&corrupt, &key)
      .expect_err("authentication failure")
      .to_string()
      .contains("authentication failed"));
  }

  #[test]
  fn windows_legacy_dpapi_errors_remain_fallible() {
    assert!(decrypt_legacy(b"not a DPAPI blob")
      .expect_err("invalid DPAPI input")
      .to_string()
      .contains("Failed to decrypt legacy Chromium DPAPI cookie"));
  }
}
