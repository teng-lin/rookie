use crate::common::enums::{Cookie, SAME_SITE_UNSPECIFIED};
use crate::common::{date, utils};
use anyhow::{bail, Result};

// WinInet cookie flag bits (`wininet.h`) as stored in the ESE `Flags` column.
const INTERNET_COOKIE_IS_SECURE: u32 = 0x0000_0001;
const INTERNET_COOKIE_HTTPONLY: u32 = 0x0000_2000;

/// Column positions for a WebCache cookie table.
///
/// ESE records are indexed by the table's column order, but that order is not
/// stable across WebCache schema versions. Resolve the positions once from the
/// column names and then use this layout for every record in the table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CookieColumnLayout {
  pub(crate) domain: i32,
  pub(crate) path: i32,
  pub(crate) name: i32,
  pub(crate) value: i32,
  pub(crate) expires: i32,
  pub(crate) flags: i32,
}

impl CookieColumnLayout {
  pub(crate) fn resolve(column_names: &[String]) -> Result<Self> {
    let resolve = |aliases: &[&str]| {
      column_names
        .iter()
        .position(|name| aliases.iter().any(|alias| name.eq_ignore_ascii_case(alias)))
        .map(|index| index as i32)
    };

    let fields = [
      (
        "domain",
        resolve(&["RDomain", "Domain", "Host", "HostName"]),
      ),
      ("path", resolve(&["Path"])),
      ("name", resolve(&["Name", "CookieName"])),
      ("value", resolve(&["Value", "CookieValue"])),
      ("expiry", resolve(&["Expires", "ExpiryTime", "ExpireTime"])),
      ("flags", resolve(&["Flags"])),
    ];
    let missing = fields
      .iter()
      .filter_map(|(field, index)| index.is_none().then_some(*field))
      .collect::<Vec<_>>();
    if !missing.is_empty() {
      bail!(
        "missing required cookie column(s): {}; available columns: {}",
        missing.join(", "),
        column_names.join(", ")
      );
    }

    Ok(Self {
      domain: fields[0].1.expect("checked above"),
      path: fields[1].1.expect("checked above"),
      name: fields[2].1.expect("checked above"),
      value: fields[3].1.expect("checked above"),
      expires: fields[4].1.expect("checked above"),
      flags: fields[5].1.expect("checked above"),
    })
  }
}

/// Owned values read from a single ESE record.
///
/// Keeping decoding independent from libesedb makes the failure semantics
/// testable on every host: malformed record data is rejected as a unit and the
/// Windows integration can skip only that record.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RawCookieRecord {
  pub(crate) domain: String,
  pub(crate) path: String,
  pub(crate) name: Vec<u8>,
  pub(crate) value: Vec<u8>,
  pub(crate) expires: u64,
  pub(crate) flags: i64,
}

impl RawCookieRecord {
  pub(crate) fn into_cookie(self, domains: Option<&[String]>) -> Result<Option<Cookie>> {
    let domain = self.domain.trim_matches('\0').to_string();
    if !utils::some_domain_in_host(domains, &domain) {
      return Ok(None);
    }

    let name = decode_cookie_text("Name", self.name)?;
    if name.is_empty() {
      bail!("`Name` is empty");
    }
    let value = decode_cookie_text("Value", self.value)?;
    let flags = self.flags as u32;

    Ok(Some(Cookie {
      domain,
      path: self.path.trim_matches('\0').to_string(),
      secure: flags & INTERNET_COOKIE_IS_SECURE != 0,
      expires: date::internet_explorer_timestamp(self.expires),
      name,
      value,
      http_only: flags & INTERNET_COOKIE_HTTPONLY != 0,
      same_site: SAME_SITE_UNSPECIFIED,
    }))
  }
}

fn decode_cookie_text(field: &str, bytes: Vec<u8>) -> Result<String> {
  let value = String::from_utf8(bytes)
    .map_err(|error| anyhow::anyhow!("`{field}` is not valid UTF-8: {error}"))?;
  Ok(value.trim_matches('\0').to_string())
}

#[cfg(test)]
mod tests {
  use super::*;

  fn columns(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_string()).collect()
  }

  fn record() -> RawCookieRecord {
    RawCookieRecord {
      domain: ".example.com".into(),
      path: "/".into(),
      name: b"session\0".to_vec(),
      value: b"secret\0".to_vec(),
      expires: 116_444_736_010_000_000,
      flags: i64::from(INTERNET_COOKIE_IS_SECURE | INTERNET_COOKIE_HTTPONLY),
    }
  }

  #[test]
  fn column_layout_is_name_based_and_order_independent() {
    let layout = CookieColumnLayout::resolve(&columns(&[
      "Value",
      "FLAGS",
      "Unrelated",
      "Path",
      "Expires",
      "RDomain",
      "Name",
    ]))
    .unwrap();

    assert_eq!(
      layout,
      CookieColumnLayout {
        domain: 5,
        path: 3,
        name: 6,
        value: 0,
        expires: 4,
        flags: 1,
      }
    );
  }

  #[test]
  fn column_layout_resolves_cookie_entry_ex_schema() {
    let layout = CookieColumnLayout::resolve(&columns(&[
      "EntryId",
      "MinimizedRDomainHash",
      "MinimizedRDomainLength",
      "Flags",
      "Expires",
      "LastModified",
      "Reserved",
      "CookieHash",
      "RDomain",
      "Path",
      "Name",
      "Value",
    ]))
    .unwrap();

    assert_eq!(
      layout,
      CookieColumnLayout {
        domain: 8,
        path: 9,
        name: 10,
        value: 11,
        expires: 4,
        flags: 3,
      }
    );
  }

  #[test]
  fn column_layout_accepts_known_webcache_name_variants() {
    let layout = CookieColumnLayout::resolve(&columns(&[
      "CookieName",
      "CookieValue",
      "Domain",
      "Path",
      "ExpiryTime",
      "Flags",
    ]))
    .unwrap();

    assert_eq!(layout.name, 0);
    assert_eq!(layout.value, 1);
    assert_eq!(layout.domain, 2);
    assert_eq!(layout.expires, 4);
  }

  #[test]
  fn column_layout_reports_every_missing_required_field() {
    let error = CookieColumnLayout::resolve(&columns(&["RDomain", "Name", "Value"]))
      .unwrap_err()
      .to_string();

    assert!(error.contains("path, expiry, flags"));
    assert!(error.contains("available columns: RDomain, Name, Value"));
  }

  #[test]
  fn record_decoding_preserves_flags_and_filetime() {
    let cookie = record().into_cookie(None).unwrap().unwrap();

    assert_eq!(cookie.domain, ".example.com");
    assert_eq!(cookie.path, "/");
    assert_eq!(cookie.name, "session");
    assert_eq!(cookie.value, "secret");
    assert_eq!(cookie.expires, Some(1));
    assert!(cookie.secure);
    assert!(cookie.http_only);
    assert_eq!(cookie.same_site, SAME_SITE_UNSPECIFIED);
  }

  #[test]
  fn malformed_record_text_is_rejected_without_a_partial_cookie() {
    let mut invalid = record();
    invalid.value = vec![0xff];

    let error = invalid.into_cookie(None).unwrap_err().to_string();
    assert!(error.contains("`Value` is not valid UTF-8"));
  }

  #[test]
  fn domain_filtering_happens_before_sensitive_value_decoding() {
    let mut invalid = record();
    invalid.value = vec![0xff];

    let domains = vec!["other.example".to_string()];
    assert!(invalid.into_cookie(Some(&domains)).unwrap().is_none());
  }
}
