use super::LegacyCipherOutcome;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use anyhow::{anyhow, Result};

use crate::common::secret::SecretBytes;

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

pub(super) const CANDIDATE_KEY_LENGTH: Option<usize> = Some(16);

pub(super) fn validate_keyed_envelope(_encrypted_value: &[u8]) -> Result<()> {
  // Cipher detection already guarantees the three-byte version prefix. CBC
  // payload and padding validation remain part of the candidate primitive so
  // malformed payloads preserve their historical per-candidate behavior.
  Ok(())
}

pub(super) fn decrypt_keyed_candidate(encrypted_value: &[u8], key: &[u8]) -> Result<SecretBytes> {
  let key_array: [u8; 16] = key
    .try_into()
    .map_err(|_| anyhow!("Chromium AES-CBC candidate key has an invalid length"))?;
  let iv: [u8; 16] = [b' '; 16];
  let cipher = Aes128CbcDec::new(&key_array.into(), &iv.into());
  let mut plaintext = SecretBytes::new(
    encrypted_value
      .get(3..)
      .ok_or_else(|| anyhow!("Chromium encrypted value is shorter than its version prefix"))?
      .to_vec(),
  );
  cipher
    .decrypt_padded_mut::<Pkcs7>(plaintext.as_mut_slice())
    .map(|decrypted| decrypted.len())
    .map(|plaintext_len| {
      plaintext.truncate(plaintext_len);
      plaintext
    })
    .map_err(|_| anyhow!("Chromium AES-CBC padding validation failed"))
}

pub(super) fn decrypt_legacy(_encrypted_value: &[u8]) -> Result<LegacyCipherOutcome> {
  Ok(LegacyCipherOutcome::Unsupported(
    "Legacy Chromium DPAPI cookies are not decryptable on this platform",
  ))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn unix_cbc_known_answer_and_error_contract() {
    let key = [
      0xaf, 0x0f, 0x76, 0x2a, 0xaf, 0x6d, 0x7d, 0x11, 0x58, 0x1b, 0x7a, 0xa8, 0xce, 0x72, 0x18,
      0xde,
    ];
    let ciphertext = [
      0x76, 0x31, 0x30, 0xbf, 0x08, 0x6d, 0x20, 0x56, 0x86, 0x1a, 0x80, 0xde, 0x82, 0x5f, 0xc9,
      0x35, 0x86, 0x86, 0x30, 0x64, 0x4f, 0x2c, 0xa1, 0x87, 0x45, 0x02, 0x13, 0xae, 0x66, 0x81,
      0xb4, 0xd6, 0x43, 0xd1, 0x9b, 0x25, 0x81, 0xc8, 0x5c, 0x88, 0x78, 0xc1, 0xbc, 0x97, 0xe7,
      0x26, 0xa1, 0x0e, 0x51, 0xea, 0x77,
    ];
    let expected: Vec<u8> = (0u8..32).collect();

    assert_eq!(
      decrypt_keyed_candidate(&ciphertext, &key)
        .expect("decrypt known answer")
        .as_slice(),
      expected
    );
    assert!(decrypt_keyed_candidate(&ciphertext, &[0; 15])
      .expect_err("wrong key length")
      .to_string()
      .contains("invalid length"));
    assert!(decrypt_keyed_candidate(b"v10not-valid-cbc", &key)
      .expect_err("invalid CBC payload")
      .to_string()
      .contains("padding validation failed"));
  }

  #[test]
  fn unix_legacy_dpapi_is_explicitly_unsupported() {
    assert_eq!(
      decrypt_legacy(b"legacy").expect("legacy policy"),
      LegacyCipherOutcome::Unsupported(
        "Legacy Chromium DPAPI cookies are not decryptable on this platform"
      )
    );
  }
}
