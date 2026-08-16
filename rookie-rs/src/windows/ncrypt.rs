use anyhow::{bail, Context, Result};
use windows::{core::w, Win32::Security::Cryptography};

use crate::common::secret::SecretBytes;

/// Frees a CNG object handle on drop so early returns don't leak it.
struct NcryptObject(Cryptography::NCRYPT_HANDLE);

impl Drop for NcryptObject {
  fn drop(&mut self) {
    if self.0 .0 != 0 {
      unsafe {
        let _ = Cryptography::NCryptFreeObject(self.0);
      }
    }
  }
}

/// Decrypt data with the CNG key Chrome stores under the "Microsoft Software
/// Key Storage Provider". Used by the App-Bound v20 key flag 3 introduced in
/// Chrome 133+.
pub(crate) fn decrypt(keydpapi: &[u8]) -> Result<SecretBytes> {
  let mut provider_handle = Cryptography::NCRYPT_PROV_HANDLE::default();
  unsafe {
    Cryptography::NCryptOpenStorageProvider(
      &mut provider_handle,
      w!("Microsoft Software Key Storage Provider"),
      0,
    )
    .context("NCryptOpenStorageProvider failed")?;
  }
  let _provider_guard = NcryptObject(provider_handle.into());

  let mut key_handle = Cryptography::NCRYPT_KEY_HANDLE::default();
  unsafe {
    Cryptography::NCryptOpenKey(
      provider_handle,
      &mut key_handle,
      w!("Google Chromekey1"),
      Cryptography::CERT_KEY_SPEC::default(),
      Cryptography::NCRYPT_FLAGS::default(),
    )
    .context("NCryptOpenKey failed")?;
  }
  let _key_guard = NcryptObject(key_handle.into());

  let mut output_buffer = SecretBytes::zeroed(keydpapi.len());
  let mut output_length = 0u32;
  unsafe {
    Cryptography::NCryptDecrypt(
      key_handle,
      Some(keydpapi),
      None,
      Some(output_buffer.as_mut_slice()),
      &mut output_length,
      Cryptography::NCRYPT_SILENT_FLAG,
    )
    .context("NCryptDecrypt failed")?;
  }
  if output_length as usize > output_buffer.len() {
    bail!("NCryptDecrypt output longer than input");
  }
  output_buffer.truncate(output_length as usize);

  Ok(output_buffer)
}
