#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

#[cfg(test)]
use crate::common::enums::Cookie;
use crate::common::enums::{CookieContext, SAME_SITE_UNSPECIFIED};
use crate::common::{
  boundary::{Decoder, ReadOnlySource, RecordSink},
  date,
  deadline::{BoundaryRuntime, DeadlineEnforcement},
  secret::{SecretBytes, SecretString},
  utils,
};
use anyhow::{bail, Result};
use std::fmt;

use super::cookie_record::{
  Attributes, CookieRecord, CookieValue, DomainScope, Observation, RawValue,
};

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
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RawCookieRecord {
  pub(crate) domain: String,
  pub(crate) path: String,
  pub(crate) name: Vec<u8>,
  pub(crate) value: SecretBytes,
  pub(crate) expires: u64,
  pub(crate) flags: i64,
}

impl ReadOnlySource for RawCookieRecord {}

/// Platform-neutral decoder for one already-acquired ESE cookie record.
///
/// The Windows adapter owns native table traversal and materializes this
/// source. Decoding itself has no dependency on libesedb or Windows APIs, so
/// malformed inputs and deadline behavior are testable on every host.
pub(crate) struct InternetExplorerRecordDecoder<'a> {
  pub(crate) domains: Option<&'a [String]>,
}

impl Decoder<RawCookieRecord, CookieRecord> for InternetExplorerRecordDecoder<'_> {
  type Summary = bool;

  fn decode(
    &self,
    source: &RawCookieRecord,
    sink: &mut dyn RecordSink<CookieRecord>,
    runtime: &BoundaryRuntime<'_>,
  ) -> Result<Self::Summary> {
    runtime.check()?;
    let record = source.decode_record(self.domains)?;
    // Keep the protected record local until the complete row has decoded and
    // the boundary is still live. An expired row is dropped (and wiped)
    // without ever reaching the caller's sink.
    runtime.check()?;
    let Some(record) = record else {
      return Ok(false);
    };
    sink.emit(record)?;
    runtime.check()?;
    Ok(true)
  }

  fn deadline_enforcement(&self) -> DeadlineEnforcement {
    DeadlineEnforcement::Cooperative
  }
}

pub(crate) fn decode_cookie_record(
  source: &RawCookieRecord,
  domains: Option<&[String]>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Option<CookieRecord>> {
  let decoder = InternetExplorerRecordDecoder { domains };
  let mut decoded = Vec::new();
  crate::common::boundary::decode(
    &decoder,
    source,
    &mut |record| {
      decoded.push(record);
      Ok(())
    },
    runtime,
  )?;
  debug_assert!(decoded.len() <= 1, "one ESE row emits at most one cookie");
  Ok(decoded.pop())
}

impl fmt::Debug for RawCookieRecord {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("RawCookieRecord")
      .field("domain", &self.domain)
      .field("path", &self.path)
      .field("name", &self.name)
      .field("value", &"<redacted>")
      .field("value_len", &self.value.len())
      .field("expires", &self.expires)
      .field("flags", &self.flags)
      .finish()
  }
}

impl RawCookieRecord {
  #[cfg(test)]
  pub(crate) fn into_record(self, domains: Option<&[String]>) -> Result<Option<CookieRecord>> {
    self.decode_record_owned(domains)
  }

  fn decode_record(&self, domains: Option<&[String]>) -> Result<Option<CookieRecord>> {
    self.clone().decode_record_owned(domains)
  }

  fn decode_record_owned(self, domains: Option<&[String]>) -> Result<Option<CookieRecord>> {
    let domain = self.domain.trim_matches('\0').to_string();
    if !utils::some_domain_in_host(domains, &domain) {
      return Ok(None);
    }

    let name = decode_cookie_text("Name", self.name)?;
    if name.is_empty() {
      bail!("`Name` is empty");
    }
    let value = decode_cookie_secret("Value", self.value)?;
    let flags = self.flags as u32;

    let raw_expires = self.expires;
    let mut record = CookieRecord::from_legacy_fields(
      domain,
      self.path.trim_matches('\0').to_string(),
      flags & INTERNET_COOKIE_IS_SECURE != 0,
      date::internet_explorer_timestamp(self.expires),
      name,
      CookieValue::Plain(value),
      flags & INTERNET_COOKIE_HTTPONLY != 0,
      SAME_SITE_UNSPECIFIED,
      CookieContext::default(),
      0,
    );
    // `RDomain` semantics are not established by a real-format fixture yet;
    // retaining the raw spelling as unknown avoids silently choosing host-only
    // or domain matching semantics.
    record.domain = DomainScope::Unknown {
      raw: record.domain_raw().to_owned(),
    };
    record.attributes = Attributes {
      secure: Observation::Known(flags & INTERNET_COOKIE_IS_SECURE != 0),
      http_only: Observation::Known(flags & INTERNET_COOKIE_HTTPONLY != 0),
      expires: match date::internet_explorer_timestamp(raw_expires) {
        Some(expires) => Observation::Known(Some(expires)),
        None if raw_expires == 0 => Observation::Known(None),
        None => Observation::Unknown(RawValue::Unsigned(raw_expires)),
      },
      raw_expires: Observation::Known(RawValue::Unsigned(raw_expires)),
      // WebCache has no SameSite column. Missing evidence must not become a
      // decoder-authored `-1`; compatibility supplies that only on projection.
      same_site: Observation::Missing,
    };
    record.retain_raw("flags", RawValue::Signed(self.flags));
    Ok(Some(record))
  }

  #[cfg(test)]
  pub(crate) fn into_cookie(self, domains: Option<&[String]>) -> Result<Option<Cookie>> {
    self
      .into_record(domains)?
      .map(|record| record.into_cookie().map_err(anyhow::Error::from))
      .transpose()
  }
}

fn decode_cookie_text(field: &str, bytes: Vec<u8>) -> Result<String> {
  let value = String::from_utf8(bytes)
    .map_err(|error| anyhow::anyhow!("`{field}` is not valid UTF-8: {error}"))?;
  Ok(value.trim_matches('\0').to_string())
}

fn decode_cookie_secret(field: &str, mut bytes: SecretBytes) -> Result<SecretString> {
  let (start, end) = {
    let value = bytes.as_slice();
    let start = value
      .iter()
      .position(|byte| *byte != 0)
      .unwrap_or(value.len());
    let end = value
      .iter()
      .rposition(|byte| *byte != 0)
      .map_or(0, |index| index + 1);
    (start, end)
  };
  if start >= end {
    bytes.truncate(0);
    return bytes
      .into_secret_string_from(0)
      .map_err(|error| anyhow::anyhow!("`{field}` is not valid UTF-8: {error}"));
  }
  bytes.truncate(end);
  bytes
    .into_secret_string_from(start)
    .map_err(|error| anyhow::anyhow!("`{field}` is not valid UTF-8: {error}"))
}

/// Stage attached to a fatal native WebCache failure before it enters the
/// engine-agnostic report ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InternetExplorerFailureStage {
  Acquisition,
  Parse,
}

/// Typed carrier used across the native-reader/registry seam.
///
/// Row-level parse failures remain accounted in the draft and do not use this
/// type. This wrapper is for fatal failures where the report must distinguish
/// opening/enumerating the source from interpreting its schema or records.
#[derive(Debug)]
pub(crate) struct InternetExplorerFailure {
  stage: InternetExplorerFailureStage,
  source: anyhow::Error,
}

impl InternetExplorerFailure {
  pub(crate) fn new(stage: InternetExplorerFailureStage, error: anyhow::Error) -> Self {
    Self {
      stage,
      source: error,
    }
  }

  pub(crate) fn stage(&self) -> InternetExplorerFailureStage {
    self.stage
  }
}

impl fmt::Display for InternetExplorerFailure {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(formatter, "{:#}", self.source)
  }
}

impl std::error::Error for InternetExplorerFailure {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(self.source.as_ref())
  }
}

#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn malformed_decoder_gate_case(bytes: &[u8]) -> Result<()> {
  let mut numeric = [0_u8; 8];
  for (target, source) in numeric.iter_mut().zip(bytes.iter().copied()) {
    *target = source;
  }
  let source = RawCookieRecord {
    domain: ".malformed.test".to_owned(),
    path: "/".to_owned(),
    name: bytes.to_vec(),
    value: SecretBytes::new(bytes.iter().rev().copied().collect()),
    expires: u64::from_le_bytes(numeric),
    flags: i64::from_be_bytes(numeric),
  };
  let decoder = InternetExplorerRecordDecoder { domains: None };
  let clock = crate::common::deadline::SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  let mut sink = |_record| Ok(());
  let _ = decoder.decode(&source, &mut sink, &runtime);
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::common::deadline::{Clock, Deadline};
  use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
  };

  struct TickClock {
    base: Instant,
    ticks: AtomicU64,
  }

  impl Default for TickClock {
    fn default() -> Self {
      Self {
        base: Instant::now(),
        ticks: AtomicU64::new(0),
      }
    }
  }

  impl Clock for TickClock {
    fn now(&self) -> Instant {
      self.base + Duration::from_secs(self.ticks.fetch_add(1, Ordering::SeqCst))
    }

    fn sleep(&self, _duration: Duration) {}
  }

  fn columns(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_string()).collect()
  }

  fn record() -> RawCookieRecord {
    RawCookieRecord {
      domain: ".example.com".into(),
      path: "/".into(),
      name: b"session\0".to_vec(),
      value: SecretBytes::new(b"secret\0".to_vec()),
      expires: 116_444_736_010_000_000,
      flags: i64::from(INTERNET_COOKIE_IS_SECURE | INTERNET_COOKIE_HTTPONLY),
    }
  }

  #[test]
  fn raw_record_debug_redacts_value_bytes_before_decoding() {
    let record = record();
    let debug = format!("{record:?}");
    assert!(!debug.contains("secret"));
    assert!(!debug.contains("115, 101, 99, 114, 101, 116"));
    assert!(debug.contains("value: \"<redacted>\""));
    assert!(debug.contains("value_len: 7"));
  }

  #[test]
  fn pure_decoder_boundary_compiles_without_native_esedb_types() {
    fn assert_source<T: ReadOnlySource>() {}
    fn assert_decoder<T: Decoder<RawCookieRecord, CookieRecord>>() {}
    assert_source::<RawCookieRecord>();
    assert_decoder::<InternetExplorerRecordDecoder<'static>>();
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
    let canonical = record().into_record(None).unwrap().unwrap();
    assert!(matches!(canonical.domain, DomainScope::Unknown { .. }));
    assert!(matches!(
      canonical.attributes.raw_expires,
      super::super::cookie_record::Observation::Known(RawValue::Unsigned(116_444_736_010_000_000))
    ));
    assert!(matches!(
      canonical.raw.get("flags"),
      Some(RawValue::Signed(_))
    ));
    assert!(matches!(
      canonical.attributes.same_site,
      Observation::Missing
    ));
    let cookie = canonical.into_cookie().unwrap();

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
    invalid.value = SecretBytes::new(vec![0xff]);

    let error = invalid.into_cookie(None).unwrap_err().to_string();
    assert!(error.contains("`Value` is not valid UTF-8"));
  }

  #[test]
  fn platform_neutral_decoder_rejects_arbitrary_value_bytes_without_panicking() {
    for length in 0..=64 {
      let mut raw = record();
      raw.value = SecretBytes::new(
        (0..length)
          .map(|index| (index as u8).wrapping_mul(73).wrapping_add(0xff))
          .collect(),
      );
      let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let clock = crate::common::deadline::SystemClock;
        let runtime = BoundaryRuntime::standard(&clock);
        let decoder = InternetExplorerRecordDecoder { domains: None };
        let mut records = Vec::new();
        decoder.decode(
          &raw,
          &mut |record| {
            records.push(record);
            Ok(())
          },
          &runtime,
        )
      }));
      assert!(outcome.is_ok(), "value length {length} panicked");
    }
  }

  #[test]
  fn domain_filtering_happens_before_sensitive_value_decoding() {
    let mut invalid = record();
    invalid.value = SecretBytes::new(vec![0xff]);

    let domains = vec!["other.example".to_string()];
    assert!(invalid.into_cookie(Some(&domains)).unwrap().is_none());
  }

  #[test]
  fn invalid_filetime_is_unknown_until_compatibility_projection() {
    let mut raw = record();
    raw.expires = 1;
    let canonical = raw.into_record(None).unwrap().unwrap();
    assert!(matches!(
      canonical.attributes.expires,
      Observation::Unknown(RawValue::Unsigned(1))
    ));
    assert_eq!(canonical.into_cookie().unwrap().expires, None);
  }

  #[test]
  fn decoder_timeout_drops_staged_secret_before_sink_emission() {
    const SENTINEL: &str = "rookie-ie-timeout-sentinel";
    let mut raw = record();
    raw.value = SecretBytes::new([SENTINEL.as_bytes(), &[0]].concat());
    let clock = TickClock::default();
    // Deadline construction samples tick zero; decode's first checkpoint sees
    // tick one and its post-decode checkpoint sees tick two.
    let runtime = BoundaryRuntime::new(&clock, Deadline::after(&clock, Duration::from_secs(2)));
    let decoder = InternetExplorerRecordDecoder { domains: None };
    let mut emitted = Vec::new();
    let error = decoder
      .decode(
        &raw,
        &mut |record| {
          emitted.push(record);
          Ok(())
        },
        &runtime,
      )
      .expect_err("deadline expires after the protected row is staged");
    assert!(emitted.is_empty());
    assert_eq!(
      error.downcast_ref::<crate::common::deadline::BoundaryStop>(),
      Some(&crate::common::deadline::BoundaryStop::TimedOut)
    );
    assert!(!format!("{error:#}").contains(SENTINEL));
  }

  #[test]
  fn staged_native_failure_retains_typed_boundary_stop() {
    let error = anyhow::Error::new(InternetExplorerFailure::new(
      InternetExplorerFailureStage::Parse,
      anyhow::Error::new(crate::common::deadline::BoundaryStop::TimedOut),
    ));

    assert_eq!(
      error
        .chain()
        .find_map(|cause| { cause.downcast_ref::<crate::common::deadline::BoundaryStop>() }),
      Some(&crate::common::deadline::BoundaryStop::TimedOut)
    );
    assert_eq!(
      error
        .downcast_ref::<InternetExplorerFailure>()
        .map(InternetExplorerFailure::stage),
      Some(InternetExplorerFailureStage::Parse)
    );
  }
}
