use crate::common::{
  enums::{Cookie, CookieContext, DetailedCookie},
  secret::SecretString,
};
use std::{collections::BTreeMap, fmt};

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

/// The domain spelling and the matching semantics observed in the source.
///
/// The raw spelling is retained deliberately: removing a leading dot for a
/// normalized lookup must not erase whether the browser stored a domain or a
/// host-only cookie. An empty or otherwise ambiguous spelling remains
/// `Unknown` instead of being guessed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DomainScope {
  HostOnly { raw: String },
  Domain { raw: String },
  Unknown { raw: String },
}

impl DomainScope {
  pub(crate) fn from_stored(raw: String) -> Self {
    if raw.is_empty() {
      Self::Unknown { raw }
    } else if raw.starts_with('.') {
      Self::Domain { raw }
    } else {
      Self::HostOnly { raw }
    }
  }

  pub(crate) fn raw(&self) -> &str {
    match self {
      Self::HostOnly { raw } | Self::Domain { raw } | Self::Unknown { raw } => raw,
    }
  }
}

/// A source observation whose absence and unrecognized representation must
/// remain distinguishable from a known false/default value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum Observation<T> {
  #[default]
  Missing,
  Known(T),
  Unknown(RawValue),
}

fn observed<T>(value: Option<T>) -> Observation<T> {
  value.map_or(Observation::Missing, Observation::Known)
}

fn known<T: Clone>(value: &Observation<T>) -> Option<T> {
  match value {
    Observation::Known(value) => Some(value.clone()),
    Observation::Missing | Observation::Unknown(_) => None,
  }
}

/// Lossless metadata value retained by a decoder without interpreting it.
#[allow(dead_code)]
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum RawValue {
  Null,
  Bool(bool),
  Signed(i64),
  Unsigned(u64),
  Text(String),
  Bytes(Vec<u8>),
  FloatBits(u64),
}

impl fmt::Debug for RawValue {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Null => formatter.write_str("Null"),
      Self::Bool(value) => formatter.debug_tuple("Bool").field(value).finish(),
      Self::Signed(value) => formatter.debug_tuple("Signed").field(value).finish(),
      Self::Unsigned(value) => formatter.debug_tuple("Unsigned").field(value).finish(),
      // Unknown text and bytes may be secret-bearing future columns. Keep the
      // type and size visible while redacting content transitively.
      Self::Text(value) => formatter
        .debug_struct("Text")
        .field("byte_len", &value.len())
        .field("value", &RedactedCookieValue)
        .finish(),
      Self::Bytes(value) => formatter
        .debug_struct("Bytes")
        .field("byte_len", &value.len())
        .field("value", &RedactedCookieValue)
        .finish(),
      Self::FloatBits(bits) => formatter
        .debug_tuple("FloatBits")
        .field(&format_args!("{bits:#018x}"))
        .finish(),
    }
  }
}

/// Partition/container identity. `Unknown` is intentionally not the same as
/// `Unpartitioned`: an old schema that lacks the column supplied no evidence.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum PartitionState {
  Unpartitioned,
  Partitioned {
    top_frame_site_key: String,
  },
  #[default]
  Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct IsolationKey {
  pub(crate) partition: PartitionState,
  pub(crate) has_cross_site_ancestor: Observation<bool>,
  pub(crate) source_scheme: Observation<i64>,
  pub(crate) source_port: Observation<i64>,
  pub(crate) is_persistent: Observation<bool>,
  pub(crate) origin_attributes: Observation<String>,
  pub(crate) user_context_id: Observation<u32>,
  pub(crate) partition_key: Observation<String>,
  pub(crate) private_browsing_id: Observation<u32>,
}

impl IsolationKey {
  pub(crate) fn from_context(context: CookieContext) -> Self {
    let partition = match (
      context.top_frame_site_key.as_ref(),
      context.has_cross_site_ancestor,
    ) {
      (Some(key), _) if key.is_empty() => PartitionState::Unpartitioned,
      (Some(key), _) => PartitionState::Partitioned {
        top_frame_site_key: key.clone(),
      },
      (None, _) if context.partition_key.is_some() => PartitionState::Partitioned {
        top_frame_site_key: context.partition_key.clone().unwrap_or_default(),
      },
      (None, _) if context.origin_attributes.is_some() => PartitionState::Unpartitioned,
      (None, Some(_)) => PartitionState::Unpartitioned,
      (None, None) => PartitionState::Unknown,
    };
    Self {
      partition,
      has_cross_site_ancestor: observed(context.has_cross_site_ancestor),
      source_scheme: observed(context.source_scheme),
      source_port: observed(context.source_port),
      is_persistent: observed(context.is_persistent),
      origin_attributes: observed(context.origin_attributes),
      user_context_id: observed(context.user_context_id),
      partition_key: observed(context.partition_key),
      private_browsing_id: observed(context.private_browsing_id),
    }
  }

  pub(crate) fn to_context(&self) -> CookieContext {
    CookieContext {
      top_frame_site_key: match &self.partition {
        PartitionState::Partitioned { top_frame_site_key } => Some(top_frame_site_key.clone()),
        PartitionState::Unpartitioned | PartitionState::Unknown => None,
      },
      has_cross_site_ancestor: known(&self.has_cross_site_ancestor),
      source_scheme: known(&self.source_scheme),
      source_port: known(&self.source_port),
      is_persistent: known(&self.is_persistent),
      origin_attributes: known(&self.origin_attributes),
      user_context_id: known(&self.user_context_id),
      partition_key: known(&self.partition_key),
      private_browsing_id: known(&self.private_browsing_id),
    }
  }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Attributes {
  pub(crate) secure: Observation<bool>,
  pub(crate) http_only: Observation<bool>,
  pub(crate) expires: Observation<Option<u64>>,
  pub(crate) raw_expires: Observation<RawValue>,
  pub(crate) same_site: Observation<i64>,
}

impl Attributes {
  pub(crate) fn known(secure: bool, http_only: bool, expires: Option<u64>, same_site: i64) -> Self {
    Self {
      secure: Observation::Known(secure),
      http_only: Observation::Known(http_only),
      expires: Observation::Known(expires),
      raw_expires: Observation::Missing,
      same_site: match same_site {
        -1..=2 => Observation::Known(same_site),
        raw => Observation::Unknown(RawValue::Signed(raw)),
      },
    }
  }

  pub(crate) fn observed(
    secure: Option<bool>,
    raw_expires: Option<i64>,
    expires: Option<u64>,
    http_only: Option<bool>,
    same_site: Option<i64>,
  ) -> Self {
    let expires = match raw_expires {
      None => Observation::Missing,
      Some(raw) if expires.is_some() || raw == 0 => Observation::Known(expires),
      Some(raw) => Observation::Unknown(RawValue::Signed(raw)),
    };
    let same_site = match same_site {
      None => Observation::Missing,
      Some(value @ -1..=2) => Observation::Known(value),
      Some(raw) => Observation::Unknown(RawValue::Signed(raw)),
    };
    Self {
      secure: observed(secure),
      http_only: observed(http_only),
      expires,
      raw_expires: raw_expires.map_or(Observation::Missing, |raw| {
        Observation::Known(RawValue::Signed(raw))
      }),
      same_site,
    }
  }

  fn legacy_secure(&self) -> bool {
    matches!(self.secure, Observation::Known(true))
  }

  fn legacy_http_only(&self) -> bool {
    matches!(self.http_only, Observation::Known(true))
  }

  fn legacy_expires(&self) -> Option<u64> {
    match self.expires {
      Observation::Known(value) => value,
      Observation::Missing | Observation::Unknown(_) => None,
    }
  }

  fn legacy_same_site(&self) -> i64 {
    match &self.same_site {
      Observation::Known(value) => *value,
      Observation::Unknown(RawValue::Signed(value)) => *value,
      Observation::Missing | Observation::Unknown(_) => crate::common::enums::SAME_SITE_UNSPECIFIED,
    }
  }
}

/// Provenance is assigned by the decoder and finalized by the source adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SourceRef {
  pub(crate) source_digest: [u8; 32],
  pub(crate) ordinal: u64,
}

impl SourceRef {
  pub(crate) fn pending(ordinal: usize) -> Self {
    Self {
      source_digest: [0; 32],
      ordinal: u64::try_from(ordinal).unwrap_or(u64::MAX),
    }
  }

  pub(crate) fn with_digest(mut self, source_digest: [u8; 32]) -> Self {
    self.source_digest = source_digest;
    self
  }
}

/// Internal record passed from decode, through unseal, to public projection.
///
/// It intentionally has no `Eq` or `Hash` implementation. Consumers that want
/// identity or deduplication must supply a key function explicitly; provenance
/// therefore remains part of the record rather than an implicit equality rule.
#[derive(Clone)]
pub(crate) struct CookieRecord {
  pub(crate) domain: DomainScope,
  pub(crate) path: String,
  pub(crate) name: String,
  pub(crate) value: CookieValue,
  pub(crate) isolation: IsolationKey,
  pub(crate) attributes: Attributes,
  pub(crate) raw: BTreeMap<String, RawValue>,
  pub(crate) origin: SourceRef,
}

/// A record whose secret-bearing value has completed the unseal stage.
///
/// The tuple field is private so only [`CookieRecord::finalize`] can create a
/// value accepted by the canonical [`Outcome`](super::outcome::Outcome).
/// This makes an encrypted or unavailable value unrepresentable after
/// finalization instead of relying on every projector to remember to filter it.
#[derive(Clone)]
pub(crate) struct FinalizedCookieRecord(CookieRecord);

impl fmt::Debug for FinalizedCookieRecord {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    self.0.fmt(formatter)
  }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FinalizationError {
  Encrypted,
  Unavailable(UnavailableCode),
}

impl fmt::Debug for CookieRecord {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("CookieRecord")
      .field("domain", &self.domain)
      .field("path", &self.path)
      .field("name", &self.name)
      .field("value", &self.value)
      .field("isolation", &self.isolation)
      .field("attributes", &self.attributes)
      .field("raw", &self.raw)
      .field("origin", &self.origin)
      .finish()
  }
}

impl CookieRecord {
  pub(crate) fn from_cookie(cookie: Cookie, origin: SourceRef) -> Self {
    Self {
      domain: DomainScope::from_stored(cookie.domain),
      path: cookie.path,
      name: cookie.name,
      value: CookieValue::Plain(SecretString::new(cookie.value)),
      isolation: IsolationKey::default(),
      attributes: Attributes::known(
        cookie.secure,
        cookie.http_only,
        cookie.expires,
        cookie.same_site,
      ),
      raw: BTreeMap::new(),
      origin,
    }
  }

  pub(crate) fn assign_source(&mut self, source_digest: [u8; 32], ordinal: usize) {
    self.origin = SourceRef::pending(ordinal).with_digest(source_digest);
  }

  pub(crate) fn finalize(self) -> Result<FinalizedCookieRecord, FinalizationError> {
    match &self.value {
      CookieValue::Plain(_) => Ok(FinalizedCookieRecord(self)),
      CookieValue::Encrypted { .. } => Err(FinalizationError::Encrypted),
      CookieValue::Unavailable(reason) => Err(FinalizationError::Unavailable(reason.code)),
    }
  }
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn from_legacy_fields(
    domain: String,
    path: String,
    secure: bool,
    expires: Option<u64>,
    name: String,
    value: CookieValue,
    http_only: bool,
    same_site: i64,
    context: CookieContext,
    ordinal: usize,
  ) -> Self {
    Self {
      domain: DomainScope::from_stored(domain),
      path,
      name,
      value,
      isolation: IsolationKey::from_context(context),
      attributes: Attributes::known(secure, http_only, expires, same_site),
      raw: BTreeMap::new(),
      origin: SourceRef::pending(ordinal),
    }
  }

  pub(crate) fn domain_raw(&self) -> &str {
    self.domain.raw()
  }

  pub(crate) fn set_context(&mut self, context: CookieContext) {
    self.isolation = IsolationKey::from_context(context);
  }

  pub(crate) fn retain_raw(&mut self, name: impl Into<String>, value: RawValue) {
    self.raw.insert(name.into(), value);
  }

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
      domain: self.domain.raw().to_owned(),
      path: self.path,
      secure: self.attributes.legacy_secure(),
      expires: self.attributes.legacy_expires(),
      name: self.name,
      value,
      http_only: self.attributes.legacy_http_only(),
      same_site: self.attributes.legacy_same_site(),
    })
  }

  pub(crate) fn into_detailed_cookie(self) -> Result<DetailedCookie, UnavailableReason> {
    let context = self.isolation.to_context();
    self
      .into_cookie()
      .map(|cookie| DetailedCookie { cookie, context })
  }
}

impl FinalizedCookieRecord {
  pub(crate) fn assign_source(&mut self, source_digest: [u8; 32], ordinal: usize) {
    self.0.assign_source(source_digest, ordinal);
  }

  #[cfg(test)]
  pub(crate) fn source_ref(&self) -> &SourceRef {
    &self.0.origin
  }

  #[cfg(test)]
  pub(crate) fn domain_raw(&self) -> &str {
    self.0.domain_raw()
  }

  #[cfg(test)]
  pub(crate) fn name(&self) -> &str {
    &self.0.name
  }

  pub(crate) fn into_cookie(self) -> Cookie {
    // Construction proved this is Plain, so this match is exhaustive over the
    // sealed invariant and cannot silently discard a record.
    self
      .0
      .into_cookie()
      .expect("finalized cookie record must contain a plain value")
  }

  pub(crate) fn into_detailed_cookie(self) -> DetailedCookie {
    self
      .0
      .into_detailed_cookie()
      .expect("finalized cookie record must contain a plain value")
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
    let record = CookieRecord::from_legacy_fields(
      ".example.com".to_owned(),
      "/".to_owned(),
      true,
      None,
      "session".to_owned(),
      CookieValue::Plain(SecretString::new("plain-value-sentinel".to_owned())),
      true,
      1,
      CookieContext {
        partition_key: Some("(https,example.com)".to_owned()),
        ..CookieContext::default()
      },
      1,
    );
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

  #[test]
  fn canonical_record_preserves_domain_partition_and_unknown_observations() {
    let domain = DomainScope::from_stored(".example.com".to_owned());
    assert!(matches!(domain, DomainScope::Domain { .. }));

    let unknown = IsolationKey::from_context(CookieContext::default());
    assert_eq!(unknown.partition, PartitionState::Unknown);
    assert_eq!(unknown.has_cross_site_ancestor, Observation::Missing);

    let unpartitioned = IsolationKey::from_context(CookieContext {
      has_cross_site_ancestor: Some(false),
      ..CookieContext::default()
    });
    assert_eq!(unpartitioned.partition, PartitionState::Unpartitioned);
    assert_eq!(
      unpartitioned.has_cross_site_ancestor,
      Observation::Known(false)
    );
  }

  #[test]
  fn raw_metadata_debug_redacts_unknown_text_and_bytes() {
    let text = RawValue::Text("cookie-value-sentinel".to_owned());
    let bytes = RawValue::Bytes(b"binary-cookie-value-sentinel".to_vec());
    let debug = format!("{text:?} {bytes:?}");
    assert!(!debug.contains("cookie-value-sentinel"));
    assert!(!debug.contains("binary-cookie-value-sentinel"));
    assert!(debug.contains("<redacted>"));
  }
}
