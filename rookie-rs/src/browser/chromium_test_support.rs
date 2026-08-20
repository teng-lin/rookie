//! Test fixtures shared by the Chromium engine tests and the `unseal.rs`
//! decrypt/decode tests.
//!
//! These two helpers are the only ones both sides need after the unseal tests
//! moved next to the code they pin. They are pure byte constructions with no
//! engine dependency, so they live here instead of being duplicated.

use sha2::{Digest, Sha256};

/// Builds the `SHA-256(host_key) || value` plaintext layout Chromium uses for
/// host-bound cookie values from schema 24 on.
pub(super) fn host_bound_plaintext(host_key: &str, value: &[u8]) -> Vec<u8> {
  let mut plaintext = Sha256::digest(host_key.as_bytes()).to_vec();
  plaintext.extend_from_slice(value);
  plaintext
}
#[cfg(target_os = "windows")]
pub(super) fn encrypt_windows_gcm_cookie(
  version: &[u8; 3],
  key: &[u8; 32],
  plaintext: &[u8],
) -> Vec<u8> {
  use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    Aes256Gcm,
  };

  let nonce = [0x42; 12];
  let cipher = Aes256Gcm::new_from_slice(key).expect("fixture key");
  let ciphertext = cipher
    .encrypt(GenericArray::from_slice(&nonce), plaintext)
    .expect("encrypt synthetic Chromium cookie");
  let mut encrypted_value = version.to_vec();
  encrypted_value.extend_from_slice(&nonce);
  encrypted_value.extend_from_slice(&ciphertext);
  encrypted_value
}
