use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use super::{zeroizing_dh, zeroizing_hkdf};
use crate::common::secret::{SecretBytes, SecretString};

pub(super) const ALGORITHM: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

pub(super) struct EncryptedSecret {
  pub(super) session_path: String,
  pub(super) parameters: Vec<u8>,
  pub(super) value: Vec<u8>,
}

pub(super) trait Transport {
  fn open_session(&self, algorithm: &str, client_public_key: Vec<u8>) -> Result<(Vec<u8>, String)>;

  fn get_secret(&self, item: &str, session_path: &str) -> Result<EncryptedSecret>;
}

struct Session {
  path: String,
  aes_key: Zeroizing<[u8; 16]>,
}

pub(super) fn get_secret<T>(transport: &T, item: &str) -> Result<SecretString>
where
  T: Transport,
{
  let mut private_key = Zeroizing::new([0_u8; zeroizing_dh::KEY_BYTES]);
  getrandom::getrandom(private_key.as_mut()).map_err(|error| {
    anyhow::anyhow!("platform RNG failed during Secret Service session negotiation: {error}")
  })?;
  // Keep the exponent in the full-size range (and therefore non-zero) without
  // introducing another request-scoped allocation.
  private_key[0] |= 0x80;
  get_secret_with_private_key(transport, item, private_key)
}

fn get_secret_with_private_key<T>(
  transport: &T,
  item: &str,
  private_key_bytes: Zeroizing<[u8; zeroizing_dh::KEY_BYTES]>,
) -> Result<SecretString>
where
  T: Transport,
{
  let session = negotiate(transport, private_key_bytes)?;
  let encrypted = transport
    .get_secret(item, &session.path)
    .context("Secret Service GetSecrets failed")?;
  if encrypted.session_path != session.path {
    bail!("Secret Service returned a secret for a different confidential session");
  }
  decrypt(encrypted.value, &session.aes_key, &encrypted.parameters)?
    .into_secret_string()
    .context("Secret Service password is not valid UTF-8")
}

fn negotiate<T>(
  transport: &T,
  private_key_bytes: Zeroizing<[u8; zeroizing_dh::KEY_BYTES]>,
) -> Result<Session>
where
  T: Transport,
{
  let client_public_key = zeroizing_dh::public_key(&private_key_bytes);
  let (server_public_key, path) = transport
    .open_session(ALGORITHM, client_public_key)
    .context("Secret Service confidential-session negotiation failed")?;

  let common_secret = zeroizing_dh::shared_secret(&server_public_key, &private_key_bytes)?;
  let aes_key = derive_aes_key(common_secret)?;
  Ok(Session { path, aes_key })
}

fn derive_aes_key(
  common_secret: Zeroizing<[u8; zeroizing_dh::KEY_BYTES]>,
) -> Result<Zeroizing<[u8; 16]>> {
  Ok(zeroizing_hkdf::derive_aes128_key(common_secret.as_ref()))
}

fn decrypt(encrypted: Vec<u8>, aes_key: &[u8; 16], iv: &[u8]) -> Result<SecretBytes> {
  type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

  let mut plaintext = SecretBytes::new(encrypted);
  let plaintext_len = Aes128CbcDec::new_from_slices(aes_key, iv)
    .map_err(|_| anyhow::anyhow!("Secret Service returned an invalid AES parameter"))?
    .decrypt_padded_mut::<Pkcs7>(plaintext.as_mut_slice())
    .map_err(|_| anyhow::anyhow!("Secret Service confidential payload decryption failed"))?
    .len();
  plaintext.truncate(plaintext_len);
  Ok(plaintext)
}

#[cfg(test)]
mod tests {
  use super::*;
  use aes::cipher::BlockEncryptMut;
  use sha2::Digest;
  use std::cell::RefCell;

  #[derive(Default)]
  struct RejectingTransport {
    algorithms: RefCell<Vec<String>>,
    secret_calls: RefCell<Vec<String>>,
  }

  impl Transport for RejectingTransport {
    fn open_session(
      &self,
      algorithm: &str,
      _client_public_key: Vec<u8>,
    ) -> Result<(Vec<u8>, String)> {
      self.algorithms.borrow_mut().push(algorithm.to_owned());
      bail!("negotiation rejected")
    }

    fn get_secret(&self, item: &str, _session_path: &str) -> Result<EncryptedSecret> {
      self.secret_calls.borrow_mut().push(item.to_owned());
      unreachable!("a rejected negotiation cannot request a secret")
    }
  }

  #[test]
  fn negotiation_uses_only_the_confidential_algorithm_and_never_retries_plain() {
    let transport = RejectingTransport::default();
    let error = get_secret_with_private_key(
      &transport,
      "/item",
      Zeroizing::new([0x42; zeroizing_dh::KEY_BYTES]),
    )
    .expect_err("negotiation must fail closed");

    assert_eq!(transport.algorithms.borrow().as_slice(), [ALGORITHM]);
    assert!(transport.secret_calls.borrow().is_empty());
    assert!(error
      .to_string()
      .contains("confidential-session negotiation failed"));
  }

  #[test]
  fn invalid_padding_never_returns_a_partial_plaintext() {
    let error = decrypt(vec![0x41; 32], &[0x11; 16], &[0x22; 16])
      .expect_err("invalid padding must fail closed");
    assert_eq!(
      error.to_string(),
      "Secret Service confidential payload decryption failed"
    );
  }

  struct AcceptingTransport {
    response: RefCell<Option<EncryptedSecret>>,
  }

  impl AcceptingTransport {
    fn new() -> Self {
      Self {
        response: RefCell::new(None),
      }
    }
  }

  impl Transport for AcceptingTransport {
    fn open_session(
      &self,
      algorithm: &str,
      client_public_key: Vec<u8>,
    ) -> Result<(Vec<u8>, String)> {
      assert_eq!(algorithm, ALGORITHM);
      assert_eq!(
        sha2::Sha256::digest(&client_public_key).as_slice(),
        [
          0x27, 0xf5, 0x88, 0x59, 0xf4, 0x83, 0xe9, 0xff, 0x66, 0xd0, 0x71, 0xf7, 0x2c, 0xa5, 0x94,
          0xc0, 0x99, 0x2c, 0x9a, 0xba, 0x68, 0xc5, 0x23, 0x5e, 0xe6, 0x5f, 0x2e, 0x36, 0xcc, 0x63,
          0x48, 0x05,
        ]
      );
      let aes_key = [
        0xad, 0xfe, 0xe2, 0x0e, 0xfd, 0x47, 0x38, 0xf8, 0x5f, 0xc5, 0xf4, 0x96, 0x8d, 0x32, 0x9d,
        0x8e,
      ];
      let iv = [0x33; 16];
      let sentinel = b"confidential-success-sentinel";
      let padded_len = (sentinel.len() / 16 + 1) * 16;
      let mut plaintext = SecretBytes::new(vec![0; padded_len]);
      plaintext.as_mut_slice()[..sentinel.len()].copy_from_slice(sentinel);
      let encrypted_len = cbc::Encryptor::<aes::Aes128>::new_from_slices(&aes_key, &iv)
        .map_err(|_| anyhow::anyhow!("test encryption key or IV was invalid"))?
        .encrypt_padded_mut::<Pkcs7>(plaintext.as_mut_slice(), sentinel.len())
        .map_err(|_| anyhow::anyhow!("test encryption failed"))?
        .len();
      let encrypted = plaintext.as_slice()[..encrypted_len].to_vec();
      *self.response.borrow_mut() = Some(EncryptedSecret {
        session_path: "/session".to_owned(),
        parameters: iv.to_vec(),
        value: encrypted,
      });
      // 2^0x25 = 2^37 is the independently computed peer public key.
      Ok((vec![0x20, 0, 0, 0, 0], "/session".to_owned()))
    }

    fn get_secret(&self, _item: &str, _session_path: &str) -> Result<EncryptedSecret> {
      self
        .response
        .borrow_mut()
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing encrypted response"))
    }
  }

  #[test]
  fn negotiated_session_decrypts_without_a_plain_retry() {
    let transport = AcceptingTransport::new();
    let secret = get_secret_with_private_key(
      &transport,
      "/item",
      Zeroizing::new([0x42; zeroizing_dh::KEY_BYTES]),
    )
    .expect("confidential exchange succeeds");

    assert_eq!(secret.as_str(), "confidential-success-sentinel");
  }
}
