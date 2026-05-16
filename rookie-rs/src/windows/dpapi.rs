use std::{ffi::c_void, ptr};

use anyhow::{anyhow, bail, Result};
use windows::Win32::{Foundation, Security::Cryptography};

pub fn decrypt(keydpapi: &mut [u8]) -> Result<Vec<u8>> {
  // https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata
  // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-localfree
  // https://docs.rs/winapi/latest/winapi/um/dpapi/index.html
  // https://docs.rs/winapi/latest/winapi/um/winbase/fn.LocalFree.html

  let data_in = Cryptography::CRYPT_INTEGER_BLOB {
    cbData: keydpapi.len() as u32,
    pbData: keydpapi.as_mut_ptr(),
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

  let decrypted_data =
    unsafe { std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec() };
  let pbdata_hlocal = Foundation::HLOCAL(data_out.pbData as *mut c_void);
  unsafe {
    Foundation::LocalFree(pbdata_hlocal).map_err(|err| anyhow!("LocalFree failed: {}", err))?;
  };
  Ok(decrypted_data)
}
