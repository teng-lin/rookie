use crate::common::enums::{Cookie, CookieContext, DetailedCookie};
use std::fmt;

const CIPHER_VERSION_PREFIX_LEN: usize = 3;

/// The storage state of a decoded cookie value before compatibility projection.
///
/// Decoders construct this type without access to browser keys. Only the
/// `unseal` stage may turn `Encrypted` into `Plain` (or `Unavailable`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CookieValue {
  Plain(String),
  Encrypted { tier: CipherTier, bytes: Vec<u8> },
  Unavailable(UnavailableReason),
}

/// Cipher metadata that is safe for an untrusted row decoder to classify.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum CipherTier {
  V10,
  V11,
  V12SecretPortal,
  V20,
  LegacyDpapi,
  Unknown([u8; CIPHER_VERSION_PREFIX_LEN]),
  Malformed { observed_len: usize },
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnavailableReason {
  pub(crate) code: UnavailableCode,
  pub(crate) message: String,
}

impl fmt::Display for UnavailableReason {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(&self.message)
  }
}

impl std::error::Error for UnavailableReason {}

/// Internal record passed from decode, through unseal, to public projection.
#[derive(Clone, Debug, PartialEq, Eq)]
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

impl CookieRecord {
  pub(crate) fn into_cookie(self) -> Result<Cookie, UnavailableReason> {
    let value = match self.value {
      CookieValue::Plain(value) => value,
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
    assert_eq!(
      CipherTier::detect(b"v1"),
      CipherTier::Malformed { observed_len: 2 }
    );
  }
}
