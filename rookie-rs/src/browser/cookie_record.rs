use crate::common::{
  enums::{Cookie, CookieContext, DetailedCookie},
  secret::SecretString,
};
use std::fmt;

const CIPHER_VERSION_PREFIX_LEN: usize = 3;

/// The storage state of a decoded cookie value before compatibility projection.
///
/// Decoders construct this type without access to browser keys. Only the
/// `unseal` stage may turn `Encrypted` into `Plain` (or `Unavailable`).
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum CookieValue {
  Plain(SecretString),
  Encrypted { tier: CipherTier, bytes: Vec<u8> },
  Unavailable(UnavailableReason),
}

/// Cipher metadata that is safe for an untrusted row decoder to classify.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CipherTier {
  V10,
  V11,
  V12SecretPortal,
  V20,
  LegacyDpapi,
  Unknown([u8; CIPHER_VERSION_PREFIX_LEN]),
  Malformed { observed_len: usize },
}

struct RedactedCookieValue;

impl fmt::Debug for RedactedCookieValue {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("<redacted>")
  }
}

impl fmt::Debug for CookieValue {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Plain(_) => formatter
        .debug_tuple("Plain")
        .field(&RedactedCookieValue)
        .finish(),
      Self::Encrypted { tier, bytes } => formatter
        .debug_struct("Encrypted")
        .field("tier", tier)
        .field("byte_len", &bytes.len())
        .field("bytes", &RedactedCookieValue)
        .finish(),
      Self::Unavailable(reason) => formatter
        .debug_struct("Unavailable")
        .field("code", &reason.code)
        .field("message", &RedactedCookieValue)
        .finish(),
    }
  }
}

impl fmt::Debug for CipherTier {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::V10 => formatter.write_str("V10"),
      Self::V11 => formatter.write_str("V11"),
      Self::V12SecretPortal => formatter.write_str("V12SecretPortal"),
      Self::V20 => formatter.write_str("V20"),
      Self::LegacyDpapi => formatter.write_str("LegacyDpapi"),
      Self::Unknown(_) => formatter.write_str("Unknown"),
      Self::Malformed { observed_len } => formatter
        .debug_struct("Malformed")
        .field("observed_len", observed_len)
        .finish(),
    }
  }
}

impl CipherTier {
  pub(crate) fn detect(bytes: &[u8]) -> Self {
    let [first, second, third, ..] = bytes else {
      return Self::Malformed {
        observed_len: bytes.len(),
      };
    };
    let prefix = [*first, *second, *third];
    match &prefix {
      b"v10" => Self::V10,
      b"v11" => Self::V11,
      b"v12" => Self::V12SecretPortal,
      b"v20" => Self::V20,
      [b'v', _, _] => Self::Unknown(prefix),
      _ => Self::LegacyDpapi,
    }
  }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnavailableCode {
  Decrypt,
  Decode,
  ProviderUnavailable,
  ProviderFailed,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct UnavailableReason {
  pub(crate) code: UnavailableCode,
  pub(crate) message: String,
}

impl fmt::Debug for UnavailableReason {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("UnavailableReason")
      .field("code", &self.code)
      .field("message", &RedactedCookieValue)
      .finish()
  }
}

impl fmt::Display for UnavailableReason {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(&self.message)
  }
}

impl std::error::Error for UnavailableReason {}

/// Internal record passed from decode, through unseal, to public projection.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CookieRecord {
  pub(crate) domain: String,
  pub(crate) path: String,
  pub(crate) secure: bool,
  pub(crate) expires: Option<u64>,
  pub(crate) name: String,
  pub(crate) value: CookieValue,
  pub(crate) http_only: bool,
  pub(crate) same_site: i64,
  pub(crate) context: CookieContext,
}

impl fmt::Debug for CookieRecord {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("CookieRecord")
      .field("domain", &self.domain)
      .field("path", &self.path)
      .field("secure", &self.secure)
      .field("expires", &self.expires)
      .field("name", &self.name)
      .field("value", &self.value)
      .field("http_only", &self.http_only)
      .field("same_site", &self.same_site)
      .field("context", &self.context)
      .finish()
  }
}

impl CookieRecord {
  pub(crate) fn into_cookie(self) -> Result<Cookie, UnavailableReason> {
    let value = match self.value {
      CookieValue::Plain(value) => value.into_output_string(),
      CookieValue::Unavailable(reason) => return Err(reason),
      CookieValue::Encrypted { .. } => {
        return Err(UnavailableReason {
          code: UnavailableCode::ProviderUnavailable,
          message: "encrypted cookie reached projection without passing through unseal".to_owned(),
        });
      }
    };
    Ok(Cookie {
      domain: self.domain,
      path: self.path,
      secure: self.secure,
      expires: self.expires,
      name: self.name,
      value,
      http_only: self.http_only,
      same_site: self.same_site,
    })
  }

  pub(crate) fn into_detailed_cookie(self) -> Result<DetailedCookie, UnavailableReason> {
    let context = self.context.clone();
    self
      .into_cookie()
      .map(|cookie| DetailedCookie { cookie, context })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn cipher_tier_detection_is_total_for_untrusted_bytes() {
    assert_eq!(CipherTier::detect(b"v10payload"), CipherTier::V10);
    assert_eq!(CipherTier::detect(b"v11payload"), CipherTier::V11);
    assert_eq!(
      CipherTier::detect(b"v12payload"),
      CipherTier::V12SecretPortal
    );
    assert_eq!(CipherTier::detect(b"v20payload"), CipherTier::V20);
    assert_eq!(
      CipherTier::detect(b"v99payload"),
      CipherTier::Unknown(*b"v99")
    );
    assert_eq!(CipherTier::detect(b"raw dpapi"), CipherTier::LegacyDpapi);
    for observed_len in 0..CIPHER_VERSION_PREFIX_LEN {
      let bytes = vec![b'v'; observed_len];
      assert_eq!(
        CipherTier::detect(&bytes),
        CipherTier::Malformed { observed_len }
      );
    }
  }

  #[test]
  fn internal_record_debug_redacts_plain_and_encrypted_values_transitively() {
    let record = CookieRecord {
      domain: ".example.com".to_owned(),
      path: "/".to_owned(),
      secure: true,
      expires: None,
      name: "session".to_owned(),
      value: CookieValue::Plain(SecretString::new("plain-value-sentinel".to_owned())),
      http_only: true,
      same_site: 1,
      context: CookieContext {
        partition_key: Some("(https,example.com)".to_owned()),
        ..CookieContext::default()
      },
    };
    let plain_debug = format!("{record:?}");
    assert!(!plain_debug.contains("plain-value-sentinel"));
    assert!(plain_debug.contains("Plain(<redacted>)"));
    assert!(plain_debug.contains("partition_key"));

    let encrypted = CookieValue::Encrypted {
      tier: CipherTier::Unknown(*b"v99"),
      bytes: b"ciphertext-value-sentinel".to_vec(),
    };
    let encrypted_debug = format!("{encrypted:?}");
    assert!(!encrypted_debug.contains("ciphertext-value-sentinel"));
    assert!(!encrypted_debug.contains("118, 57, 57"));
    assert!(encrypted_debug.contains("tier: Unknown"));
    assert!(encrypted_debug.contains("bytes: <redacted>"));

    let unavailable = CookieValue::Unavailable(UnavailableReason {
      code: UnavailableCode::Decrypt,
      message: "unavailable-message-sentinel".to_owned(),
    });
    let unavailable_debug = format!("{unavailable:?}");
    assert!(!unavailable_debug.contains("unavailable-message-sentinel"));
    assert!(unavailable_debug.contains("code: Decrypt"));
    assert!(unavailable_debug.contains("message: <redacted>"));
  }
}
