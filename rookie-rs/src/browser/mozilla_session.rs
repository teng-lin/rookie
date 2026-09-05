//! Mozilla session store: acquiring, decompressing, and parsing
//! `sessionstore-backups/*.jsonlz4` (and the legacy plain-JSON form).
//!
//! Split out of `mozilla.rs` alongside `mozilla_persistent.rs`. The walk keeps
//! `SESSION_CANDIDATES`, `SessionStoreFormat`, and `select_session_sources` --
//! ADR 0001 SS8 first-valid ordering stays next to the code that depends on it --
//! and reaches this module through `parse_session_path_with_runtime` alone.

#[cfg(test)]
use crate::common::deadline::{Clock, Deadline, SystemClock};
use crate::common::{
  boundary::{Decoder, ReadOnlySource, RecordSink},
  date,
  deadline::{BoundaryRuntime, BoundaryStop, DeadlineEnforcement},
  diagnostic::{sanitize, REDACTED_PATH},
  enums::*,
  secret::{SecretBytes, SecretString},
  utils,
};
use anyhow::{anyhow, bail, Result};
use lz4_flex::block::decompress_into;
use serde_json::Value;
#[cfg(test)]
use std::path::PathBuf;
use std::{fs, io::Read, path::Path};
use zeroize::Zeroize;

use super::cookie_record::{
  Attributes, CookieRecord, CookieValue, Observation, RawValue, SourceRef,
};
use super::mozilla::{
  firefox_cookie_context, SessionCandidateFailure, SessionCandidateSuccess, SessionStoreFormat,
  MAX_PLAUSIBLE_SESSION_EXPIRY_MILLISECONDS, MAX_PLAUSIBLE_SESSION_EXPIRY_SECONDS,
  MAX_SESSION_COOKIE_DIAGNOSTICS, MAX_SESSION_STORE_BYTES,
  MIN_PLAUSIBLE_SESSION_EXPIRY_MILLISECONDS, SESSION_STORE_READ_ATTEMPTS,
};

#[derive(Debug)]
pub(crate) struct SessionCookieParseDraft {
  #[cfg(test)]
  pub(crate) cookies: Vec<Cookie>,
  #[cfg(test)]
  pub(crate) detailed_cookies: Vec<DetailedCookie>,
  pub(crate) records: Vec<CookieRecord>,
  pub(crate) rows_seen: usize,
  pub(crate) rows_skipped: usize,
  pub(crate) rows_rejected: usize,
  pub(crate) diagnostics: Vec<String>,
}

pub(crate) struct MozillaSessionReadOnlySource<'a> {
  pub(crate) bytes: &'a [u8],
  pub(crate) format: SessionStoreFormat,
  pub(crate) domains: Option<&'a [String]>,
}

impl ReadOnlySource for MozillaSessionReadOnlySource<'_> {}

pub(crate) struct MozillaSessionDecoder;

#[derive(Debug)]
pub(crate) struct MozillaSessionDecodeSummary {
  pub(crate) rows_seen: usize,
  pub(crate) rows_skipped: usize,
  pub(crate) rows_rejected: usize,
  pub(crate) diagnostics: Vec<String>,
}

impl Decoder<MozillaSessionReadOnlySource<'_>, CookieRecord> for MozillaSessionDecoder {
  type Summary = MozillaSessionDecodeSummary;

  fn decode(
    &self,
    source: &MozillaSessionReadOnlySource<'_>,
    sink: &mut dyn RecordSink<CookieRecord>,
    runtime: &BoundaryRuntime<'_>,
  ) -> Result<Self::Summary> {
    let mut parsed = decode_session_source(source, runtime)?;
    runtime.check()?;
    for (ordinal, record) in parsed.records.iter_mut().enumerate() {
      record.origin = SourceRef::pending(ordinal);
    }
    for record in parsed.records {
      runtime.check()?;
      sink.emit(record)?;
    }
    runtime.check()?;
    Ok(MozillaSessionDecodeSummary {
      rows_seen: parsed.rows_seen,
      rows_skipped: parsed.rows_skipped,
      rows_rejected: parsed.rows_rejected,
      diagnostics: parsed.diagnostics,
    })
  }

  fn deadline_enforcement(&self) -> DeadlineEnforcement {
    DeadlineEnforcement::Cooperative
  }
}

/// Exercises both session-store containers with attacker-controlled bytes.
///
/// The mozLz4 advertised length is derived from two input bytes and capped at
/// 64 KiB. Production accepts larger real profiles, but a fuzz iteration must
/// not turn four arbitrary bytes into a repeated 64 MiB allocation.
#[cfg(feature = "fuzzing")]
pub(crate) fn malformed_decoder_gate_case(bytes: &[u8]) -> Result<()> {
  fn decode(bytes: &[u8], format: SessionStoreFormat) {
    let source = MozillaSessionReadOnlySource {
      bytes,
      format,
      domains: None,
    };
    let decoder = MozillaSessionDecoder;
    let clock = crate::common::deadline::SystemClock;
    let runtime = BoundaryRuntime::standard(&clock);
    let mut sink = |_record| Ok(());
    let _ = decoder.decode(&source, &mut sink, &runtime);
  }

  decode(bytes, SessionStoreFormat::LegacyJson);

  let advertised = bytes
    .get(..2)
    .map(|prefix| u16::from_le_bytes([prefix[0], prefix[1]]))
    .unwrap_or(0);
  let mut jsonlz4 = Vec::with_capacity(12 + bytes.len());
  jsonlz4.extend_from_slice(b"mozLz40\0");
  jsonlz4.extend_from_slice(&u32::from(advertised).to_le_bytes());
  jsonlz4.extend_from_slice(bytes);
  decode(&jsonlz4, SessionStoreFormat::JsonLz4);
  Ok(())
}

pub(crate) fn parse_session_path_with_runtime(
  path: &Path,
  format: SessionStoreFormat,
  domains: Option<&[String]>,
  runtime: &BoundaryRuntime<'_>,
) -> std::result::Result<SessionCandidateSuccess, SessionCandidateFailure> {
  parse_session_candidate_with_runtime(
    path,
    || {
      let bytes = read_stable_session_file_with_runtime(path, runtime)?;
      decode_acquired_session(bytes, format, domains, runtime)
    },
    runtime,
  )
}

#[cfg(test)]
pub(crate) fn parse_session_candidate_with<F>(
  path: &Path,
  parse: F,
) -> std::result::Result<SessionCandidateSuccess, SessionCandidateFailure>
where
  F: FnMut() -> Result<SessionCookieParseDraft>,
{
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  parse_session_candidate_with_runtime(path, parse, &runtime)
}

pub(crate) fn parse_session_candidate_with_runtime<F>(
  _path: &Path,
  mut parse: F,
  runtime: &BoundaryRuntime<'_>,
) -> std::result::Result<SessionCandidateSuccess, SessionCandidateFailure>
where
  F: FnMut() -> Result<SessionCookieParseDraft>,
{
  let mut last_error = None;
  let mut attempts = 0;
  let mut transient_errors = Vec::new();
  for attempt in 1..=SESSION_STORE_READ_ATTEMPTS {
    if let Err(stop) = runtime.check() {
      return Err(SessionCandidateFailure {
        error: stop.into(),
        attempts,
        transient_errors,
      });
    }
    attempts = attempt as u32;
    match parse() {
      Ok(parsed) => {
        if let Err(stop) = runtime.check() {
          return Err(SessionCandidateFailure {
            error: stop.into(),
            attempts,
            transient_errors,
          });
        }
        return Ok(SessionCandidateSuccess {
          parsed,
          attempts,
          transient_errors,
        });
      }
      Err(error) if is_missing_session_file(&error) => {
        return Err(SessionCandidateFailure {
          error,
          attempts,
          transient_errors,
        })
      }
      Err(error) if error.downcast_ref::<BoundaryStop>().is_some() => {
        return Err(SessionCandidateFailure {
          error,
          attempts,
          transient_errors,
        })
      }
      Err(error) => {
        let diagnostic = sanitize(&format!(
          "session acquisition or parse attempt {attempt} failed: {error:#}"
        ));
        if attempt < SESSION_STORE_READ_ATTEMPTS {
          log::debug!("Retrying Firefox session store {REDACTED_PATH} after {diagnostic}");
          transient_errors.push(diagnostic);
        }
        last_error = Some(error);
      }
    }
  }

  Err(SessionCandidateFailure {
    error: last_error.expect("session store parser always attempts at least once"),
    attempts,
    transient_errors,
  })
}

pub(crate) fn is_missing_session_file(error: &anyhow::Error) -> bool {
  matches!(
    error.downcast_ref::<std::io::Error>(),
    Some(error) if error.kind() == std::io::ErrorKind::NotFound
  )
}

#[cfg(test)]
pub(crate) fn read_stable_session_file(path: &Path) -> Result<Vec<u8>> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  read_stable_session_file_with_runtime(path, &runtime).map(|bytes| bytes.as_slice().to_vec())
}

pub(crate) fn read_stable_session_file_with_runtime(
  path: &Path,
  runtime: &BoundaryRuntime<'_>,
) -> Result<SecretBytes> {
  runtime.check()?;
  let mut file = fs::File::open(path)?;
  let before = file.metadata()?;
  if before.len() > MAX_SESSION_STORE_BYTES as u64 {
    bail!(
      "Firefox session store is {} bytes; maximum supported size is {} bytes",
      before.len(),
      MAX_SESSION_STORE_BYTES
    );
  }
  let expected_length = usize::try_from(before.len())
    .map_err(|_| anyhow!("Firefox session store length does not fit in memory"))?;
  let mut bytes = Vec::new();
  bytes
    .try_reserve_exact(expected_length)
    .map_err(|error| anyhow!("Unable to allocate Firefox session store buffer: {error}"))?;
  bytes.resize(expected_length, 0);
  let mut bytes = SecretBytes::new(bytes);
  let mut filled = 0;
  while filled < bytes.len() {
    runtime.check()?;
    let read = file.read(&mut bytes.as_mut_slice()[filled..])?;
    if read == 0 {
      return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
    }
    filled += read;
  }
  runtime.check()?;
  let after = file.metadata()?;

  let length_changed =
    before.len() != after.len() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) != after.len();
  let modified_changed = before.modified().ok() != after.modified().ok();
  if length_changed || modified_changed {
    bail!("Firefox session store changed while it was being read");
  }

  runtime.check()?;
  Ok(bytes)
}

pub(crate) fn decompress_session_store(compressed: &[u8]) -> Result<SecretBytes> {
  let advertised = compressed
    .get(..4)
    .ok_or_else(|| anyhow!("Invalid compressed length prefix"))?;
  let advertised = u32::from_le_bytes(
    advertised
      .try_into()
      .expect("the slice was checked to contain four bytes"),
  ) as usize;
  if advertised > MAX_SESSION_STORE_BYTES {
    bail!(
      "Firefox mozLz4 output advertises {advertised} bytes; maximum supported size is {MAX_SESSION_STORE_BYTES} bytes"
    );
  }

  let mut decompressed = Vec::new();
  decompressed
    .try_reserve_exact(advertised)
    .map_err(|error| anyhow!("Unable to allocate Firefox mozLz4 output buffer: {error}"))?;
  decompressed.resize(advertised, 0);
  let mut decompressed = SecretBytes::new(decompressed);
  let written = decompress_into(&compressed[4..], decompressed.as_mut_slice())?;
  if written != advertised {
    bail!("Firefox mozLz4 output length {written} does not match advertised length {advertised}");
  }
  Ok(decompressed)
}

#[cfg(test)]
pub fn get_session_cookies(
  domains: Option<Vec<String>>,
  cookies_dir: PathBuf,
) -> Result<Vec<Cookie>> {
  parse_legacy_session_cookies(&cookies_dir.join("sessionstore.js"), domains.as_deref())
    .map(|outcome| outcome.cookies)
}

pub(crate) fn record_session_cookie(
  outcome: &mut SessionCookieParseDraft,
  json_cookie: &Value,
  location: &str,
  domains: Option<&[String]>,
) {
  let domain = json_cookie
    .get("host")
    .and_then(|value| value.as_str())
    .unwrap_or("");
  if !utils::some_domain_in_host(domains, domain) {
    return;
  }
  outcome.rows_seen += 1;
  match create_cookie_record(json_cookie).map(|mut record| {
    record.set_context(firefox_session_cookie_context(
      json_cookie.get("originAttributes"),
    ));
    if let Some(origin_attributes) = json_cookie.get("originAttributes") {
      match origin_attributes {
        Value::String(_) | Value::Object(_) => {}
        value => {
          let raw = raw_json_value(value);
          record.isolation.origin_attributes = Observation::Unknown(raw.clone());
          record.retain_raw("origin_attributes", raw);
        }
      }
      if let Value::Object(attributes) = origin_attributes {
        preserve_unknown_session_isolation_attributes(&mut record, attributes);
      }
    }
    record
  }) {
    Ok(record) => outcome.records.push(record),
    Err(error) => {
      outcome.rows_skipped += 1;
      outcome.rows_rejected += 1;
      if outcome.diagnostics.len() < MAX_SESSION_COOKIE_DIAGNOSTICS {
        outcome
          .diagnostics
          .push(format!("malformed session cookie at {location}: {error:#}"));
      }
    }
  }
}

fn preserve_unknown_session_isolation_attributes(
  record: &mut CookieRecord,
  attributes: &serde_json::Map<String, Value>,
) {
  let invalid_u32 = |name: &str| {
    attributes.get(name).filter(|value| {
      value
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        .is_none()
    })
  };
  if let Some(value) = invalid_u32("userContextId") {
    record.isolation.user_context_id = Observation::Unknown(raw_json_value(value));
  }
  if let Some(value) = attributes
    .get("partitionKey")
    .filter(|value| !value.is_string())
  {
    record.isolation.partition_key = Observation::Unknown(raw_json_value(value));
  }
  if let Some(value) = invalid_u32("privateBrowsingId") {
    record.isolation.private_browsing_id = Observation::Unknown(raw_json_value(value));
  }
}

#[cfg(test)]
pub(crate) fn parse_session_json(
  json: &Value,
  domains: Option<&[String]>,
) -> Result<SessionCookieParseDraft> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  let parsed = parse_session_json_with_runtime(json, domains, &runtime)?;
  Ok(project_session_records(
    parsed.records,
    parsed.rows_seen,
    parsed.rows_skipped,
    parsed.rows_rejected,
    parsed.diagnostics,
  ))
}

pub(crate) fn parse_session_json_with_runtime(
  json: &Value,
  domains: Option<&[String]>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<SessionCookieParseDraft> {
  runtime.check()?;
  let mut outcome = SessionCookieParseDraft {
    #[cfg(test)]
    cookies: Vec::new(),
    #[cfg(test)]
    detailed_cookies: Vec::new(),
    records: Vec::new(),
    rows_seen: 0,
    rows_skipped: 0,
    rows_rejected: 0,
    diagnostics: Vec::new(),
  };
  let windows = json
    .get("windows")
    .ok_or_else(|| anyhow!("Firefox session state has no windows array"))?
    .as_array()
    .ok_or_else(|| anyhow!("Firefox session state windows is not an array"))?;

  // Current Firefox stores the global SessionCookies collection at the root
  // (`state.cookies`); legacy sessionstore.js files stored cookies per window.
  // Accept exactly one layout and route both container formats through this
  // walker so record decoding cannot diverge again.
  let top_level_cookies = json
    .get("cookies")
    .map(|cookies| {
      cookies
        .as_array()
        .ok_or_else(|| anyhow!("Firefox session state top-level cookies is not an array"))
    })
    .transpose()?;
  let mut window_cookie_collections = Vec::new();
  for (window_index, window) in windows.iter().enumerate() {
    runtime.check()?;
    let window = window
      .as_object()
      .ok_or_else(|| anyhow!("Firefox session state windows[{window_index}] is not an object"))?;
    let Some(cookies) = window.get("cookies") else {
      continue;
    };
    let cookies = cookies.as_array().ok_or_else(|| {
      anyhow!("Firefox session state windows[{window_index}].cookies is not an array")
    })?;
    window_cookie_collections.push((window_index, cookies));
  }

  if top_level_cookies.is_some() && !window_cookie_collections.is_empty() {
    bail!("Firefox session state contains both top-level and per-window cookie layouts");
  }

  if let Some(cookies) = top_level_cookies {
    for (cookie_index, json_cookie) in cookies.iter().enumerate() {
      runtime.check()?;
      record_session_cookie(
        &mut outcome,
        json_cookie,
        &format!("cookies[{cookie_index}]"),
        domains,
      );
    }
    runtime.check()?;
    return Ok(outcome);
  }

  for (window_index, cookies) in window_cookie_collections {
    runtime.check()?;
    for (cookie_index, json_cookie) in cookies.iter().enumerate() {
      runtime.check()?;
      record_session_cookie(
        &mut outcome,
        json_cookie,
        &format!("windows[{window_index}].cookies[{cookie_index}]"),
        domains,
      );
    }
  }
  runtime.check()?;
  Ok(outcome)
}

#[cfg(test)]
pub(crate) fn parse_legacy_session_cookies(
  path: &Path,
  domains: Option<&[String]>,
) -> Result<SessionCookieParseDraft> {
  let clock = SystemClock;
  parse_legacy_session_cookies_with_deadline(path, domains, &clock, Deadline::standard())
}

#[cfg(test)]
pub(crate) fn parse_legacy_session_cookies_with_deadline(
  path: &Path,
  domains: Option<&[String]>,
  clock: &dyn Clock,
  deadline: Deadline,
) -> Result<SessionCookieParseDraft> {
  let runtime = BoundaryRuntime::new(clock, deadline);
  let bytes = read_stable_session_file_with_runtime(path, &runtime)?;
  decode_acquired_session(bytes, SessionStoreFormat::LegacyJson, domains, &runtime)
}

#[cfg(test)]
pub fn get_session_cookies_lz4(
  domains: Option<Vec<String>>,
  cookies_dir: PathBuf,
) -> Result<Vec<Cookie>> {
  parse_session_cookies_lz4(
    &cookies_dir.join("sessionstore-backups/recovery.jsonlz4"),
    domains.as_deref(),
  )
  .map(|outcome| outcome.cookies)
}

#[cfg(test)]
pub(crate) fn parse_session_cookies_lz4(
  path: &Path,
  domains: Option<&[String]>,
) -> Result<SessionCookieParseDraft> {
  let clock = SystemClock;
  parse_session_cookies_lz4_with_deadline(path, domains, &clock, Deadline::standard())
}

#[cfg(test)]
pub(crate) fn parse_session_cookies_lz4_with_deadline(
  path: &Path,
  domains: Option<&[String]>,
  clock: &dyn Clock,
  deadline: Deadline,
) -> Result<SessionCookieParseDraft> {
  let runtime = BoundaryRuntime::new(clock, deadline);
  let bytes = read_stable_session_file_with_runtime(path, &runtime)?;
  decode_acquired_session(bytes, SessionStoreFormat::JsonLz4, domains, &runtime)
}

pub(crate) fn decode_acquired_session(
  bytes: SecretBytes,
  format: SessionStoreFormat,
  domains: Option<&[String]>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<SessionCookieParseDraft> {
  let source = MozillaSessionReadOnlySource {
    bytes: bytes.as_slice(),
    format,
    domains,
  };
  let decoder = MozillaSessionDecoder;
  let mut records = Vec::new();
  let summary = crate::common::boundary::decode(
    &decoder,
    &source,
    &mut |record| {
      records.push(record);
      Ok(())
    },
    runtime,
  )?;
  runtime.check()?;
  Ok(project_session_records(
    records,
    summary.rows_seen,
    summary.rows_skipped,
    summary.rows_rejected,
    summary.diagnostics,
  ))
}

pub(crate) fn decode_session_source(
  source: &MozillaSessionReadOnlySource<'_>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<SessionCookieParseDraft> {
  runtime.check()?;
  let plain = match source.format {
    SessionStoreFormat::LegacyJson => SecretBytes::new(source.bytes.to_vec()),
    SessionStoreFormat::JsonLz4 => {
      if !source.bytes.starts_with(b"mozLz40\0") {
        bail!("Invalid mozLz40 header");
      }
      let compressed = source
        .bytes
        .get(8..)
        .ok_or_else(|| anyhow!("Invalid compressed length"))?;
      runtime.check()?;
      decompress_session_store(compressed)?
    }
  };
  runtime.check()?;
  let plain = plain.into_secret_string_from(0)?;
  let mut json: Value = serde_json::from_str(plain.as_str())?;
  let parsed = runtime
    .check()
    .map_err(anyhow::Error::from)
    .and_then(|_| parse_session_json_with_runtime(&json, source.domains, runtime));
  wipe_json_strings(&mut json);
  drop(json);
  drop(plain);
  let parsed = parsed?;
  runtime.check()?;
  Ok(parsed)
}

fn wipe_json_strings(value: &mut Value) {
  match value {
    Value::String(value) => value.zeroize(),
    Value::Array(values) => values.iter_mut().for_each(wipe_json_strings),
    Value::Object(values) => {
      for (mut key, mut value) in std::mem::take(values) {
        key.zeroize();
        wipe_json_strings(&mut value);
      }
    }
    Value::Null | Value::Bool(_) | Value::Number(_) => {}
  }
}

pub(crate) fn project_session_records(
  records: Vec<CookieRecord>,
  rows_seen: usize,
  rows_skipped: usize,
  rows_rejected: usize,
  diagnostics: Vec<String>,
) -> SessionCookieParseDraft {
  #[cfg(test)]
  let cookies = records
    .iter()
    .cloned()
    .map(|record| record.into_cookie().expect("session record is plaintext"))
    .collect();
  #[cfg(test)]
  let detailed_cookies = records
    .iter()
    .cloned()
    .map(|record| {
      record
        .into_detailed_cookie()
        .expect("session record is plaintext")
    })
    .collect();
  SessionCookieParseDraft {
    #[cfg(test)]
    cookies,
    #[cfg(test)]
    detailed_cookies,
    records,
    rows_seen,
    rows_skipped,
    rows_rejected,
    diagnostics,
  }
}

pub(crate) fn session_cookie_expiry(
  json_cookie: &Value,
) -> (Observation<Option<u64>>, Observation<RawValue>) {
  let Some(expiry) = json_cookie.get("expiry") else {
    return (Observation::Missing, Observation::Missing);
  };
  let Some(expiry) = expiry.as_u64() else {
    let raw = raw_json_value(expiry);
    return (Observation::Unknown(raw.clone()), Observation::Unknown(raw));
  };
  let raw = Observation::Known(RawValue::Unsigned(expiry));
  if expiry == 0 {
    (Observation::Known(None), raw)
  } else if expiry <= MAX_PLAUSIBLE_SESSION_EXPIRY_SECONDS {
    (Observation::Known(date::mozilla_timestamp(expiry)), raw)
  } else if expiry < MIN_PLAUSIBLE_SESSION_EXPIRY_MILLISECONDS {
    (Observation::Unknown(RawValue::Unsigned(expiry)), raw)
  } else if expiry <= MAX_PLAUSIBLE_SESSION_EXPIRY_MILLISECONDS {
    (
      Observation::Known(date::mozilla_timestamp(expiry / 1000)),
      raw,
    )
  } else {
    (Observation::Unknown(RawValue::Unsigned(expiry)), raw)
  }
}

fn raw_json_value(value: &Value) -> RawValue {
  match value {
    Value::Null => RawValue::Null,
    Value::Bool(value) => RawValue::Bool(*value),
    Value::Number(value) => value
      .as_i64()
      .map(RawValue::Signed)
      .or_else(|| value.as_u64().map(RawValue::Unsigned))
      .or_else(|| {
        value
          .as_f64()
          .map(|value| RawValue::FloatBits(value.to_bits()))
      })
      .unwrap_or_else(|| RawValue::text("unrepresentable number")),
    Value::String(value) => RawValue::text(value.clone()),
    // Preserve structured future forms as their canonical JSON spelling. The
    // RawValue debug implementation redacts the contents transitively.
    Value::Array(_) | Value::Object(_) => RawValue::text(value.to_string()),
  }
}

fn json_bool_observation(json_cookie: &Value, name: &str) -> Observation<bool> {
  match json_cookie.get(name) {
    None => Observation::Missing,
    Some(Value::Bool(value)) => Observation::Known(*value),
    Some(value) => Observation::Unknown(raw_json_value(value)),
  }
}

fn json_same_site_observation(json_cookie: &Value) -> Observation<i64> {
  match json_cookie.get("sameSite") {
    None => Observation::Missing,
    Some(Value::Number(value)) => match value.as_i64() {
      Some(value @ -1..=2) => Observation::Known(value),
      Some(value) => Observation::Unknown(RawValue::Signed(value)),
      None => Observation::Unknown(raw_json_value(&Value::Number(value.clone()))),
    },
    Some(value) => Observation::Unknown(raw_json_value(value)),
  }
}

pub(crate) fn create_cookie_record(json_cookie: &Value) -> Result<CookieRecord> {
  let host = json_cookie
    .get("host")
    .and_then(|v| v.as_str())
    .unwrap_or("");
  let path = json_cookie
    .get("path")
    .and_then(|v| v.as_str())
    .unwrap_or("/");
  let secure = json_bool_observation(json_cookie, "secure");
  let name = json_cookie
    .get("name")
    .and_then(|v| v.as_str())
    .ok_or_else(|| anyhow!("session cookie has no name"))?;
  let value = json_cookie
    .get("value")
    .and_then(|v| v.as_str())
    .ok_or_else(|| anyhow!("session cookie has no value"))?;
  let http_only = json_bool_observation(json_cookie, "httponly");
  let (expires, raw_expires) = session_cookie_expiry(json_cookie);
  let same_site = json_same_site_observation(json_cookie);

  let mut record = CookieRecord::from_legacy_fields(
    host.to_string(),
    path.to_string(),
    matches!(secure, Observation::Known(true)),
    match &expires {
      Observation::Known(expires) => *expires,
      Observation::Missing | Observation::Unknown(_) => None,
    },
    name.to_string(),
    CookieValue::Plain(SecretString::new(value.to_string())),
    matches!(http_only, Observation::Known(true)),
    match &same_site {
      Observation::Known(value) => *value,
      Observation::Missing | Observation::Unknown(_) => SAME_SITE_UNSPECIFIED,
    },
    CookieContext::default(),
    0,
  );
  record.attributes = Attributes {
    secure,
    http_only,
    expires,
    raw_expires,
    same_site,
  };
  Ok(record)
}

#[allow(dead_code)]
pub fn create_cookie(json_cookie: &Value) -> Result<Cookie> {
  Ok(
    create_cookie_record(json_cookie)?
      .into_cookie()
      .expect("Firefox session rows emit plaintext values"),
  )
}

/// The session store holds `originAttributes` as JSON rather than as the
/// `^name=value` suffix `moz_cookies` uses.
///
/// Both encodings go through the same parser, so an attribute name one lane
/// recognizes is recognized by the other. A value that is neither a string nor
/// an object is still retained verbatim: an encoding a future Firefox
/// introduces reaches a caller intact, and fails closed at selection time
/// rather than reading as the default context.
pub(crate) fn firefox_session_cookie_context(origin_attributes: Option<&Value>) -> CookieContext {
  let Some(origin_attributes) = origin_attributes else {
    return CookieContext::default();
  };
  match origin_attributes.as_str() {
    Some(suffix) => firefox_cookie_context(Some(suffix.to_owned())),
    None => firefox_cookie_context(Some(origin_attributes.to_string())),
  }
}
