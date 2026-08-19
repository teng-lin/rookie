use crate::common::{
  enums::{Cookie, CookieContext, DetailedCookie},
  secret::{SecretBytes, SecretString},
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
  Text(SecretString),
  Bytes(SecretBytes),
  FloatBits(u64),
}

impl RawValue {
  pub(crate) fn text(value: impl Into<String>) -> Self {
    Self::Text(SecretString::new(value.into()))
  }

  pub(crate) fn bytes(value: impl Into<Vec<u8>>) -> Self {
    Self::Bytes(SecretBytes::new(value.into()))
  }
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

  pub(crate) fn to_context_with_semantics(
    &self,
    semantics: LegacyProjectionSemantics,
  ) -> CookieContext {
    CookieContext {
      top_frame_site_key: match &self.partition {
        PartitionState::Partitioned { top_frame_site_key } => Some(top_frame_site_key.clone()),
        PartitionState::Unpartitioned | PartitionState::Unknown => None,
      },
      has_cross_site_ancestor: legacy_optional_boolean(&self.has_cross_site_ancestor, semantics),
      source_scheme: known(&self.source_scheme),
      source_port: known(&self.source_port),
      is_persistent: legacy_optional_boolean(&self.is_persistent, semantics),
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

  fn legacy_secure(&self, semantics: LegacyProjectionSemantics) -> bool {
    legacy_boolean(&self.secure, semantics)
  }

  fn legacy_http_only(&self, semantics: LegacyProjectionSemantics) -> bool {
    legacy_boolean(&self.http_only, semantics)
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

/// Compatibility-only interpretation selected from the finalized source.
///
/// Firefox and Chromium SQLite historically treated any nonzero integer as
/// true. A non-integer Chromium core boolean made the legacy row unreadable
/// (while an optional context boolean merely disappeared), so compatibility
/// filtering handles that row-level distinction before projection. Session
/// JSON and the other engines defaulted malformed booleans to false. Keeping
/// these choices at projection preserves history without weakening the
/// canonical `Missing`/`Known`/`Unknown` observation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum LegacyProjectionSemantics {
  #[default]
  Standard,
  ChromiumSqlite,
  FirefoxPersistent,
}

impl LegacyProjectionSemantics {
  pub(crate) fn for_source_format(format: &str) -> Self {
    match format {
      "chromium_sqlite" => Self::ChromiumSqlite,
      "mozilla_sqlite" => Self::FirefoxPersistent,
      _ => Self::Standard,
    }
  }
}

fn legacy_boolean(value: &Observation<bool>, semantics: LegacyProjectionSemantics) -> bool {
  match value {
    Observation::Known(value) => *value,
    Observation::Unknown(RawValue::Signed(value))
      if matches!(
        semantics,
        LegacyProjectionSemantics::ChromiumSqlite | LegacyProjectionSemantics::FirefoxPersistent
      ) =>
    {
      *value != 0
    }
    Observation::Missing | Observation::Unknown(_) => false,
  }
}

fn legacy_optional_boolean(
  value: &Observation<bool>,
  semantics: LegacyProjectionSemantics,
) -> Option<bool> {
  match value {
    Observation::Known(value) => Some(*value),
    Observation::Unknown(RawValue::Signed(value))
      if semantics == LegacyProjectionSemantics::ChromiumSqlite =>
    {
      Some(*value != 0)
    }
    Observation::Missing | Observation::Unknown(_) => None,
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
  /// Build a record from an already-projected [`Cookie`].
  ///
  /// Test-only: production decodes into records directly, and finalization
  /// takes its rows from `records` alone. Fixtures still need it to express
  /// "this source produced this row" without running a decoder.
  #[cfg(test)]
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

  pub(crate) fn is_legacy_compatible_with_semantics(
    &self,
    semantics: LegacyProjectionSemantics,
  ) -> bool {
    if semantics != LegacyProjectionSemantics::ChromiumSqlite {
      return true;
    }
    let historically_readable = |value: &Observation<bool>| {
      matches!(
        value,
        Observation::Missing | Observation::Known(_) | Observation::Unknown(RawValue::Signed(_))
      )
    };
    historically_readable(&self.attributes.secure)
      && historically_readable(&self.attributes.http_only)
  }

  pub(crate) fn into_cookie(self) -> Result<Cookie, UnavailableReason> {
    self.into_cookie_with_semantics(LegacyProjectionSemantics::Standard)
  }

  pub(crate) fn into_cookie_with_semantics(
    self,
    semantics: LegacyProjectionSemantics,
  ) -> Result<Cookie, UnavailableReason> {
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
      secure: self.attributes.legacy_secure(semantics),
      expires: self.attributes.legacy_expires(),
      name: self.name,
      value,
      http_only: self.attributes.legacy_http_only(semantics),
      same_site: self.attributes.legacy_same_site(),
    })
  }

  #[cfg(test)]
  pub(crate) fn into_detailed_cookie(self) -> Result<DetailedCookie, UnavailableReason> {
    self.into_detailed_cookie_with_semantics(LegacyProjectionSemantics::Standard)
  }

  pub(crate) fn into_detailed_cookie_with_semantics(
    self,
    semantics: LegacyProjectionSemantics,
  ) -> Result<DetailedCookie, UnavailableReason> {
    let context = self.isolation.to_context_with_semantics(semantics);
    self
      .into_cookie_with_semantics(semantics)
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

  pub(crate) fn into_cookie_with_semantics(self, semantics: LegacyProjectionSemantics) -> Cookie {
    // Construction proved this is Plain, so this match is exhaustive over the
    // sealed invariant and cannot silently discard a record.
    self
      .0
      .into_cookie_with_semantics(semantics)
      .expect("finalized cookie record must contain a plain value")
  }

  pub(crate) fn is_legacy_compatible_with_semantics(
    &self,
    semantics: LegacyProjectionSemantics,
  ) -> bool {
    self.0.is_legacy_compatible_with_semantics(semantics)
  }

  pub(crate) fn into_detailed_cookie_with_semantics(
    self,
    semantics: LegacyProjectionSemantics,
  ) -> DetailedCookie {
    self
      .0
      .into_detailed_cookie_with_semantics(semantics)
      .expect("finalized cookie record must contain a plain value")
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::common::{
    deadline::{BoundaryRuntime, BoundaryStop, CancellationToken, Deadline},
    secret::{observe_secret_drops, SecretKind},
  };
  use std::time::Duration;

  #[test]
  fn firefox_persistent_projection_preserves_historical_nonzero_boolean_semantics() {
    let mut record = CookieRecord::from_cookie(
      Cookie {
        domain: ".example.test".to_owned(),
        path: "/".to_owned(),
        secure: false,
        expires: None,
        name: "name".to_owned(),
        value: "value".to_owned(),
        http_only: false,
        same_site: -1,
      },
      SourceRef::pending(0),
    );
    record.attributes.secure = Observation::Unknown(RawValue::Signed(2));
    record.attributes.http_only = Observation::Unknown(RawValue::Signed(-1));

    let standard = record.clone().into_cookie().expect("standard projection");
    assert!(!standard.secure);
    assert!(!standard.http_only);

    let persistent = record
      .into_cookie_with_semantics(LegacyProjectionSemantics::FirefoxPersistent)
      .expect("Firefox persistent projection");
    assert!(persistent.secure);
    assert!(persistent.http_only);
  }

  #[test]
  fn chromium_legacy_compatibility_keeps_historical_integer_coercion_only() {
    let mut record = CookieRecord::from_cookie(
      Cookie {
        domain: ".example.test".to_owned(),
        path: "/".to_owned(),
        secure: false,
        expires: None,
        name: "name".to_owned(),
        value: "value".to_owned(),
        http_only: false,
        same_site: -1,
      },
      SourceRef::pending(0),
    );
    record.attributes.secure = Observation::Unknown(RawValue::Signed(2));
    record.attributes.http_only = Observation::Unknown(RawValue::Signed(-1));
    assert!(record.is_legacy_compatible_with_semantics(LegacyProjectionSemantics::ChromiumSqlite));

    // Context columns were historically optional reads, so their malformed
    // representations never rejected an otherwise readable legacy row.
    record.isolation.has_cross_site_ancestor = Observation::Unknown(RawValue::text("yes"));
    record.isolation.is_persistent = Observation::Unknown(RawValue::bytes(vec![1]));
    assert!(record.is_legacy_compatible_with_semantics(LegacyProjectionSemantics::ChromiumSqlite));

    for malformed in [
      RawValue::text("true"),
      RawValue::bytes(vec![1]),
      RawValue::FloatBits(1.0_f64.to_bits()),
    ] {
      record.attributes.secure = Observation::Unknown(malformed);
      assert!(
        !record.is_legacy_compatible_with_semantics(LegacyProjectionSemantics::ChromiumSqlite)
      );
    }
  }

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
  fn firefox_partition_key_never_becomes_a_chromium_top_frame_site_key() {
    for origin_attributes in [
      Some("^partitionKey=%28https%2Cexample.com%29".to_owned()),
      Some(r#"{"partitionKey":"(https,example.com)"}"#.to_owned()),
      None,
    ] {
      let context = CookieContext {
        origin_attributes,
        partition_key: Some("(https,example.com)".to_owned()),
        ..CookieContext::default()
      };
      let projected = IsolationKey::from_context(context)
        .to_context_with_semantics(LegacyProjectionSemantics::Standard);
      assert_eq!(projected.top_frame_site_key, None);
      assert_eq!(
        projected.partition_key.as_deref(),
        Some("(https,example.com)")
      );
    }
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
    let text = RawValue::text("cookie-value-sentinel");
    let bytes = RawValue::bytes(b"binary-cookie-value-sentinel".to_vec());
    let debug = format!("{text:?} {bytes:?}");
    assert!(!debug.contains("cookie-value-sentinel"));
    assert!(!debug.contains("binary-cookie-value-sentinel"));
    assert!(debug.contains("<redacted>"));
  }

  fn assert_raw_allocations_wiped(observed: &[(SecretKind, usize, Vec<u8>)], expected: usize) {
    assert_eq!(observed.len(), expected);
    assert!(observed.iter().all(|(_, original_len, wiped)| {
      *original_len > 0 && wiped.len() == *original_len && wiped.iter().all(|byte| *byte == 0)
    }));
  }

  #[test]
  fn raw_metadata_clones_retain_protected_wipe_on_drop_ownership() {
    let (observed, outcome) = observe_secret_drops(|| {
      let text = RawValue::text("raw-text-clone-sentinel");
      let bytes = RawValue::bytes(b"raw-bytes-clone-sentinel".to_vec());
      let text_clone = text.clone();
      let bytes_clone = bytes.clone();
      drop((text, bytes, text_clone, bytes_clone));
    });

    assert!(outcome.is_ok());
    assert_raw_allocations_wiped(&observed, 4);
    assert_eq!(
      observed
        .iter()
        .filter(|(kind, _, _)| *kind == SecretKind::String)
        .count(),
      2
    );
    assert_eq!(
      observed
        .iter()
        .filter(|(kind, _, _)| *kind == SecretKind::Bytes)
        .count(),
      2
    );
  }

  #[test]
  fn raw_metadata_is_wiped_during_unwind() {
    let (observed, outcome) = observe_secret_drops(|| {
      let _text = RawValue::text("raw-text-unwind-sentinel");
      let _bytes = RawValue::bytes(b"raw-bytes-unwind-sentinel".to_vec());
      panic!("intentional RawValue unwind");
    });

    assert!(outcome.is_err());
    assert_raw_allocations_wiped(&observed, 2);
  }

  #[test]
  fn raw_metadata_is_wiped_on_typed_boundary_stop() {
    use crate::common::deadline::test_clock::ManualClock;

    for expected in [
      BoundaryStop::TimedOut,
      BoundaryStop::Cancelled,
      BoundaryStop::ResourceExhausted,
    ] {
      let clock = ManualClock::default();
      let stop = CancellationToken::default();
      let deadline = match expected {
        BoundaryStop::TimedOut => Deadline::after(&clock, Duration::ZERO),
        BoundaryStop::Cancelled => {
          assert!(stop.cancel());
          Deadline::after(&clock, Duration::from_secs(1))
        }
        BoundaryStop::ResourceExhausted => {
          assert!(stop.exhaust_resources());
          Deadline::after(&clock, Duration::from_secs(1))
        }
      };
      let runtime = BoundaryRuntime::with_stop(&clock, deadline, stop);
      let (observed, outcome) = observe_secret_drops(|| {
        let result = (|| -> Result<(), BoundaryStop> {
          let _text = RawValue::text("raw-text-stop-sentinel");
          let _bytes = RawValue::bytes(b"raw-bytes-stop-sentinel".to_vec());
          runtime.check()?;
          Ok(())
        })();
        assert_eq!(result, Err(expected));
      });

      assert!(outcome.is_ok());
      assert_raw_allocations_wiped(&observed, 2);
    }
  }
}
