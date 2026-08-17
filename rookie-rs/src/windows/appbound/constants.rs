#![allow(dead_code)]

pub const BOOTSTRAP_MARKER_OFFSET: usize = 0x28;
pub const BOOTSTRAP_KEY_STATUS_OFFSET: usize = 0x29;
pub const BOOTSTRAP_KEY_STATUS_READY: u8 = 0x01;
pub const BOOTSTRAP_EXTRACT_ERR_CODE_OFFSET: usize = 0x2A;
pub const BOOTSTRAP_HRESULT_OFFSET: usize = 0x2C;
pub const BOOTSTRAP_COMERR_OFFSET: usize = 0x30;
pub const BOOTSTRAP_KEY_OFFSET: usize = 0x40;
pub const BOOTSTRAP_KEY_LEN: usize = 32;

pub const BOOTSTRAP_IMPORT_LOADLIBRARYA_OFFSET: usize = 0x40;
pub const BOOTSTRAP_IMPORT_GETPROCADDRESS_OFFSET: usize = 0x48;
pub const BOOTSTRAP_IMPORT_VIRTUALALLOC_OFFSET: usize = 0x50;
pub const BOOTSTRAP_IMPORT_VIRTUALPROTECT_OFFSET: usize = 0x58;
pub const BOOTSTRAP_IMPORT_NTFLUSHIC_OFFSET: usize = 0x60;

pub const BOOTSTRAP_MARK_MZ_FOUND: u8 = 0x02;
pub const BOOTSTRAP_MARK_IMPORTS_OK: u8 = 0x05;
pub const BOOTSTRAP_MARK_ALLOC_OK: u8 = 0x06;
pub const BOOTSTRAP_MARK_COPIED: u8 = 0x07;
pub const BOOTSTRAP_MARK_RELOCATED: u8 = 0x08;
pub const BOOTSTRAP_MARK_IMPORTS_FIXED: u8 = 0x09;
pub const BOOTSTRAP_MARK_PERMISSIONS: u8 = 0x0A;
pub const BOOTSTRAP_MARK_CACHE_FLUSHED: u8 = 0x0B;
pub const BOOTSTRAP_MARK_DONE: u8 = 0xFF;
pub const BOOTSTRAP_MARK_ERR_IMPORTS: u8 = 0xE3;
pub const BOOTSTRAP_MARK_ERR_ALLOC: u8 = 0xE4;

pub const ABE_ERR_OK: u8 = 0x00;
pub const ABE_ERR_BASENAME: u8 = 0x01;
pub const ABE_ERR_BROWSER_UNKNOWN: u8 = 0x02;
pub const ABE_ERR_ENV_MISSING: u8 = 0x03;
pub const ABE_ERR_BASE64: u8 = 0x04;
pub const ABE_ERR_BSTR_ALLOC: u8 = 0x05;
pub const ABE_ERR_COM_CREATE: u8 = 0x06;
pub const ABE_ERR_DECRYPT_DATA: u8 = 0x07;
pub const ABE_ERR_KEY_LEN: u8 = 0x08;

pub fn err_code_name(code: u8) -> &'static str {
  match code {
    ABE_ERR_OK => "success",
    ABE_ERR_BASENAME => "GetOwnExeBasename failed",
    ABE_ERR_BROWSER_UNKNOWN => "browser executable not recognized in COM IID table",
    ABE_ERR_ENV_MISSING => "HBD_ABE_ENC_B64 environment variable missing or oversized",
    ABE_ERR_BASE64 => "base64 decoding of encrypted key failed",
    ABE_ERR_BSTR_ALLOC => "SysAllocStringByteLen failed",
    ABE_ERR_COM_CREATE => "CoCreateInstance failed for IElevator / IElevator2 COM interface",
    ABE_ERR_DECRYPT_DATA => "IElevator.DecryptData returned failure",
    ABE_ERR_KEY_LEN => "decrypted key length mismatch (expected 32 bytes)",
    _ => "unknown error",
  }
}

pub fn hresult_name(hr: u32) -> Option<&'static str> {
  match hr {
    0x80004002 => Some("E_NOINTERFACE"),
    0x80010108 => Some("RPC_E_DISCONNECTED"),
    0x80040154 => Some("REGDB_E_CLASSNOTREG"),
    0x80070005 => Some("E_ACCESSDENIED"),
    0x800706BA => Some("RPC_S_SERVER_UNAVAILABLE"),
    _ => None,
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScratchResult {
  pub marker: u8,
  pub status: u8,
  pub err_code: u8,
  pub hresult: u32,
  pub com_err: u32,
  pub key: Option<Vec<u8>>,
}

pub fn format_abe_error(res: &ScratchResult) -> String {
  let err_name = err_code_name(res.err_code);
  let hr_str = match hresult_name(res.hresult) {
    Some(name) => format!("{name} (0x{:08x})", res.hresult),
    None => format!("0x{:08x}", res.hresult),
  };
  format!(
    "err={} (0x{:02x}), hr={}, comErr=0x{:x}, marker=0x{:02x}",
    err_name, res.err_code, hr_str, res.com_err, res.marker
  )
}
