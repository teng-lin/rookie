use crate::common::enums::{Cookie, SAME_SITE_UNSPECIFIED};
use crate::common::{date, utils};
use anyhow::Result;
use libesedb::{EseDb, Table, Value};
use std::path::PathBuf;

// WinInet cookie flag bits (`wininet.h`) as stored in the ESE `Flags` column.
const INTERNET_COOKIE_IS_SECURE: u32 = 0x0000_0001;
const INTERNET_COOKIE_HTTPONLY: u32 = 0x0000_2000;

/// Returns cookies from IE based browsers
pub fn internet_explorer_based(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<Cookie>> {
  unsafe {
    if let Some(path) = db_path.to_str() {
      crate::windows::restart_manager::release_file_lock(path, force_kill);
    }
  }
  let db = EseDb::open(db_path)?;
  let mut cookies: Vec<Cookie> = vec![];

  for table in db.iter_tables()? {
    let table = table?;
    let table_name: String = table.name()?;

    if table_name.starts_with("CookieEntry") {
      let flags_column = find_flags_column(&table)?;
      if flags_column.is_none() {
        log::warn!("{table_name}: no `Flags` column; reporting secure/http_only as false");
      }
      let mut warned_undecodable_flags = false;

      for rec in table.iter_records()? {
        let rec = rec?;
        let host = rec.value(8)?;
        let host = host.as_str().unwrap_or("");
        let path = rec.value(9)?;
        let path = path.as_str().unwrap_or("");
        let name: Vec<u8> = rec.value(10)?.as_bytes().unwrap_or(&[]).to_vec();
        let name = String::from_utf8(name)
          .unwrap_or("".to_string())
          .trim_matches('\0')
          .to_string();
        let value = rec.value(11)?;
        let value = String::from_utf8(value.as_bytes().unwrap_or(&[]).to_vec())
          .unwrap_or("".to_string())
          .trim_matches('\0')
          .to_string();
        let expires = rec.value(4)?.to_u64().unwrap_or(0);
        let expires = date::internet_explorer_timestamp(expires);
        let flags = match flags_column {
          Some(index) => match flags_from_ese_value(&rec.value(index)?) {
            Some(flags) => flags,
            None => {
              if !warned_undecodable_flags {
                warned_undecodable_flags = true;
                log::warn!("{table_name}: `Flags` holds no integer; reporting it as unset");
              }
              0
            }
          },
          None => 0,
        };
        let (secure, http_only) = security_flags(flags);

        let should_append = utils::some_domain_in_host(domains.as_deref(), host);
        if should_append {
          cookies.push(Cookie {
            domain: host.to_string(),
            path: path.to_string(),
            secure,
            expires,
            name,
            value,
            http_only,
            same_site: SAME_SITE_UNSPECIFIED,
          })
        }
      }
    }
  }
  Ok(cookies)
}

/// Locates the `Flags` column by name, since its position is not stable across
/// WebCache schema versions. Returns the record entry index, if the column exists.
///
/// An unrecognised schema yields `None` rather than an error: losing every cookie
/// is worse than losing the security flags, so extraction continues and the
/// missing flags are reported through the log instead.
fn find_flags_column(table: &Table<'_>) -> Result<Option<i32>> {
  for (index, column) in table.iter_columns()?.enumerate() {
    if column?.name()?.eq_ignore_ascii_case("Flags") {
      return Ok(Some(index as i32));
    }
  }
  Ok(None)
}

/// Reads the WinInet bitfield out of a `Flags` cell, or `None` if it holds no integer.
///
/// ESE stores the column as a signed 32-bit `Long`, so the value is read wide and
/// cast back to preserve the bit pattern of flags with the high bit set.
fn flags_from_ese_value(value: &Value) -> Option<u32> {
  value.to_i64().map(|raw| raw as u32)
}

/// Decodes the `(secure, http_only)` pair from a WinInet cookie flags bitfield.
fn security_flags(flags: u32) -> (bool, bool) {
  (
    flags & INTERNET_COOKIE_IS_SECURE != 0,
    flags & INTERNET_COOKIE_HTTPONLY != 0,
  )
}

#[cfg(test)]
mod tests {
  use super::*;

  // Literal masks, so that a regression in the constants themselves is caught
  // rather than cancelling out on both sides of the assertion.
  #[test]
  fn security_flags_decodes_wininet_bits() {
    assert_eq!(INTERNET_COOKIE_IS_SECURE, 0x0000_0001);
    assert_eq!(INTERNET_COOKIE_HTTPONLY, 0x0000_2000);
    assert_eq!(security_flags(0x0000_0000), (false, false));
    assert_eq!(security_flags(0x0000_0001), (true, false));
    assert_eq!(security_flags(0x0000_2000), (false, true));
    assert_eq!(security_flags(0x0000_2001), (true, true));
  }

  #[test]
  fn security_flags_ignores_unrelated_bits() {
    // INTERNET_COOKIE_IS_SESSION (0x2) and INTERNET_COOKIE_IS_LEGACY (0x800)
    // must not be mistaken for secure or http_only.
    assert_eq!(security_flags(0x0000_0002), (false, false));
    assert_eq!(security_flags(0x0000_0800), (false, false));
    assert_eq!(security_flags(0xFFFF_FFFF), (true, true));
  }

  #[test]
  fn flags_from_ese_value_recovers_signed_long_bit_pattern() {
    // libesedb maps ESE `Long` to a signed i32, so a flags word with the high bit
    // set arrives negative. `Value::to_u32` would reject it, dropping every flag.
    assert_eq!(flags_from_ese_value(&Value::I32(0x2001)), Some(0x0000_2001));
    assert_eq!(flags_from_ese_value(&Value::I32(-1)), Some(0xFFFF_FFFF));
    assert_eq!(
      flags_from_ese_value(&Value::I32(i32::MIN)),
      Some(0x8000_0000)
    );
    assert_eq!(
      flags_from_ese_value(&Value::U32(0x8000_0001)),
      Some(0x8000_0001)
    );
  }

  #[test]
  fn flags_from_ese_value_rejects_non_integer_cells() {
    assert_eq!(flags_from_ese_value(&Value::Null(())), None);
    assert_eq!(flags_from_ese_value(&Value::Text("Flags".into())), None);
    // Long values are fetched through a separate API, so they carry no payload here.
    assert_eq!(flags_from_ese_value(&Value::Long), None);
  }
}
