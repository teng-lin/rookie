use std::{ffi::c_void, ptr};

use anyhow::{anyhow, bail, Result};
use windows::Win32::Security::Cryptography;
use zeroize::Zeroize;

use crate::common::secret::SecretBytes;

#[link(name = "kernel32")]
extern "system" {
  fn LocalFree(hmem: *mut c_void) -> *mut c_void;
}

unsafe fn copy_native_plaintext_and_wipe(ptr: *mut u8, len: usize) -> SecretBytes {
  let native_plaintext = std::slice::from_raw_parts_mut(ptr, len);
  let plaintext = SecretBytes::new(native_plaintext.to_vec());
  native_plaintext.zeroize();
  plaintext
}

pub(crate) fn decrypt(keydpapi: &[u8]) -> Result<SecretBytes> {
  // https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata
  // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-localfree
  // https://docs.rs/winapi/latest/winapi/um/dpapi/index.html
  // https://docs.rs/winapi/latest/winapi/um/winbase/fn.LocalFree.html

  let data_in = Cryptography::CRYPT_INTEGER_BLOB {
    cbData: keydpapi.len() as u32,
    // Safety: CryptUnprotectData does not mutate the input blob; the mutable
    // pointer is only required by the Win32 signature.
    pbData: keydpapi.as_ptr() as *mut u8,
  };
  let mut data_out = Cryptography::CRYPT_INTEGER_BLOB {
    cbData: 0,
    pbData: ptr::null_mut(),
  };

  unsafe {
    Cryptography::CryptUnprotectData(
      &data_in,
      Some(ptr::null_mut()),
      Some(ptr::null_mut()),
      Some(ptr::null_mut()),
      Some(ptr::null_mut()),
      0,
      &mut data_out,
    )
    .map_err(|err| anyhow!("CryptUnprotectData failed: {}", err))?;
  }
  if data_out.pbData.is_null() {
    bail!("CryptUnprotectData returned a null pointer");
  }

  let decrypted_data = unsafe {
    // `LocalFree` releases bytes without clearing them. Wipe the OS-owned
    // allocation before attempting the free; the Rust copy is already guarded
    // so both the success and later-error paths have explicit cleanup.
    copy_native_plaintext_and_wipe(data_out.pbData, data_out.cbData as usize)
  };
  // windows 0.51's Foundation::LocalFree wrapper treats the API's null
  // success return as an error, so call the raw Win32 function directly.
  unsafe {
    let local_free_result = LocalFree(data_out.pbData as *mut c_void);
    if !local_free_result.is_null() {
      return Err(anyhow!(
        "LocalFree failed: {}",
        windows::core::Error::from_win32()
      ));
    }
  };
  Ok(decrypted_data)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn native_plaintext_is_wiped_before_its_buffer_can_be_released() {
    let sentinel = b"rookie-secret-sentinel-7e8b";
    let mut native = sentinel.to_vec();
    let allocation_len = native.len();
    let copied = unsafe { copy_native_plaintext_and_wipe(native.as_mut_ptr(), native.len()) };
    // Checking the original length as well as its contents keeps this test from
    // accepting `Vec::clear`, which discards the logical length without wiping
    // the backing allocation.
    assert_eq!(native.len(), allocation_len);
    assert!(native.iter().all(|byte| *byte == 0));
    assert_eq!(copied.as_slice(), sentinel);
    assert!(!format!("{copied:?}").contains("rookie-secret-sentinel"));
  }
}
