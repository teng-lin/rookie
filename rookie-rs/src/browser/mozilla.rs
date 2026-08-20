#[cfg(test)]
use crate::common::deadline::{Clock, Deadline};
use crate::common::{
  boundary::{Decoder, ReadOnlySource, RecordSink},
  date,
  deadline::{BoundaryRuntime, BoundaryStop, DeadlineEnforcement, SystemClock},
  diagnostic::{sanitize, REDACTED_PATH},
  enums::*,
  secret::{SecretBytes, SecretString},
  sqlite, utils,
};
use anyhow::{anyhow, bail, Result};
use ini::{Ini, ParseOption};
use lz4_flex::block::decompress_into;
use serde_json::Value;
use std::{
  fs,
  io::Read,
  path::{Path, PathBuf},
};
use zeroize::Zeroize;

use super::cookie_record::{
  Attributes, CookieRecord, CookieValue, Observation, RawValue, SourceRef,
};
use super::registry::PERSISTENT_SOURCE_PRECEDENCE;
use super::report_core::{CookieSourceFormatId, CookieSourceRoleId};
use super::source::{
  Source, SourceAcquisition, SourceCandidate, SourceFailureStage, SourceIdentity, SourceStats,
};

// Firefox 142 migrated schema 15 to 16 by multiplying persistent cookie
// expiry values by 1000 (https://bugzilla.mozilla.org/show_bug.cgi?id=1972757).
const FIREFOX_MILLISECOND_EXPIRY_SCHEMA_VERSION: u32 = 16;

// Session state is untrusted profile data. Keep both the on-disk read and the
// mozLz4-advertised output below a size large enough for real Firefox profiles
// while preventing one corrupt four-byte size prefix from requesting gigabytes.
const MAX_SESSION_STORE_BYTES: usize = 64 * 1024 * 1024;

// Sessionstore has no schema/version field that identifies an expiry unit, and
// its unit cannot be inferred from cookies.sqlite: an observed Firefox 141
// profile used seconds in schema-15 SQLite rows while its recovery.jsonlz4 used
// milliseconds. Values through year 2286 remain plausible Unix seconds; values
// from 10^12 through the same upper instant are plausible Unix milliseconds.
// The scale gap is deliberately rejected instead of guessed. Missing/zero
// expiry is always a genuine session cookie.
const MAX_PLAUSIBLE_SESSION_EXPIRY_SECONDS: u64 = 9_999_999_999;
const MIN_PLAUSIBLE_SESSION_EXPIRY_MILLISECONDS: u64 = 1_000_000_000_000;
const MAX_PLAUSIBLE_SESSION_EXPIRY_MILLISECONDS: u64 =
  MAX_PLAUSIBLE_SESSION_EXPIRY_SECONDS * 1000 + 999;

/// Returns cookies from mozilla based browsers
#[deprecated(
  since = "0.6.0",
  note = "use direct_path::cookies_from_path with DirectPathRequest"
)]
pub fn firefox_based(db_path: PathBuf, domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  firefox_based_with_runtime(db_path, domains, &runtime)
}

pub(crate) fn firefox_based_with_runtime(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  let outcome = query_cookies_engine_outcome_with_runtime(&db_path, domains.as_deref(), runtime);
  super::legacy::project_canonical_outcome_with_runtime(
    "firefox",
    super::report_build::finalize_singleton_source(
      "firefox",
      db_path.parent().unwrap_or(&db_path).to_path_buf(),
      outcome.sources,
      outcome.boundary_stop,
      Some(runtime),
    )?,
    runtime,
  )
}

/// Returns cookies from a Mozilla profile with container and origin attributes
/// preserved.
#[deprecated(
  since = "0.6.0",
  note = "the canonical direct-path API returns legacy Cookie values; this compatibility function remains through 0.6"
)]
pub fn firefox_based_detailed(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
) -> Result<Vec<DetailedCookie>> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  firefox_based_detailed_with_runtime(db_path, domains, &runtime)
}

pub(crate) fn firefox_based_detailed_with_runtime(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<DetailedCookie>> {
  let outcome = query_cookies_engine_outcome_with_runtime(&db_path, domains.as_deref(), runtime);
  super::legacy::project_canonical_detailed_outcome_with_runtime(
    "firefox",
    super::report_build::finalize_singleton_source(
      "firefox",
      db_path.parent().unwrap_or(&db_path).to_path_buf(),
      outcome.sources,
      outcome.boundary_stop,
      Some(runtime),
    )?,
    runtime,
  )
}

struct PersistentCookieQuery {
  records: Vec<CookieRecord>,
  rows_seen: usize,
  rows_skipped: usize,
  rows_rejected: usize,
  last_row_error: Option<anyhow::Error>,
}

pub(crate) struct MozillaPersistentReadOnlySource<'a> {
  pub(crate) connection: &'a rusqlite::Connection,
  pub(crate) domains: Option<&'a [String]>,
}

impl ReadOnlySource for MozillaPersistentReadOnlySource<'_> {}

pub(crate) struct MozillaPersistentDecoder;

#[derive(Debug)]
pub(crate) struct MozillaPersistentDecodeSummary {
  pub(crate) rows_seen: usize,
  pub(crate) rows_skipped: usize,
  pub(crate) rows_rejected: usize,
  pub(crate) last_row_error: Option<anyhow::Error>,
}

impl Decoder<MozillaPersistentReadOnlySource<'_>, CookieRecord> for MozillaPersistentDecoder {
  type Summary = MozillaPersistentDecodeSummary;

  fn decode(
    &self,
    source: &MozillaPersistentReadOnlySource<'_>,
    sink: &mut dyn RecordSink<CookieRecord>,
    runtime: &BoundaryRuntime<'_>,
  ) -> Result<Self::Summary> {
    let query = decode_persistent_cookies(source.connection, source.domains, runtime)?;
    runtime.check()?;
    for (ordinal, mut record) in query.records.into_iter().enumerate() {
      runtime.check()?;
      record.origin = SourceRef::pending(ordinal);
      sink.emit(record)?;
    }
    runtime.check()?;
    Ok(MozillaPersistentDecodeSummary {
      rows_seen: query.rows_seen,
      rows_skipped: query.rows_skipped,
      rows_rejected: query.rows_rejected,
      last_row_error: query.last_row_error,
    })
  }

  fn deadline_enforcement(&self) -> DeadlineEnforcement {
    DeadlineEnforcement::Cooperative
  }
}

fn mozilla_schema_version(connection: &rusqlite::Connection) -> Result<u32> {
  let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
  u32::try_from(version).map_err(|_| anyhow!("Invalid Firefox cookie schema version {version}"))
}

fn persistent_cookie_expiry(timestamp: u64, schema_version: u32) -> Option<u64> {
  let timestamp = if schema_version >= FIREFOX_MILLISECOND_EXPIRY_SCHEMA_VERSION {
    timestamp / 1000
  } else {
    timestamp
  };
  date::mozilla_timestamp(timestamp)
}

#[cfg(test)]
fn query_persistent_cookies(
  connection: &rusqlite::Connection,
  domains: Option<&[String]>,
) -> Result<PersistentCookieQuery> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  query_persistent_cookies_with_runtime(connection, domains, &runtime)
}

#[cfg(test)]
fn query_persistent_cookies_mode(
  connection: &rusqlite::Connection,
  domains: Option<&[String]>,
  _detailed: bool,
  clock: &dyn Clock,
  deadline: Deadline,
) -> Result<PersistentCookieQuery> {
  let runtime = BoundaryRuntime::new(clock, deadline);
  query_persistent_cookies_with_runtime(connection, domains, &runtime)
}

fn query_persistent_cookies_with_runtime(
  connection: &rusqlite::Connection,
  domains: Option<&[String]>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<PersistentCookieQuery> {
  let source = MozillaPersistentReadOnlySource {
    connection,
    domains,
  };
  let decoder = MozillaPersistentDecoder;
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
  Ok(PersistentCookieQuery {
    records,
    rows_seen: summary.rows_seen,
    rows_skipped: summary.rows_skipped,
    rows_rejected: summary.rows_rejected,
    last_row_error: summary.last_row_error,
  })
}

fn decode_persistent_cookies(
  connection: &rusqlite::Connection,
  domains: Option<&[String]>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<PersistentCookieQuery> {
  runtime.check()?;
  let schema_version = mozilla_schema_version(connection)?;
  let columns = sqlite_table_columns(connection, "moz_cookies")?;
  let optional_column = |name: &str| {
    if columns.contains(name) {
      name.to_owned()
    } else {
      format!("NULL AS {name}")
    }
  };
  let mut query = format!(
    "SELECT host, {}, {}, {}, name, value, {}, {}, {} FROM moz_cookies ",
    optional_column("path"),
    optional_column("isSecure"),
    optional_column("expiry"),
    optional_column("isHttpOnly"),
    optional_column("sameSite"),
    optional_column("originAttributes"),
  );

  let domain_filters: Vec<String> = domains
    .map(|domains| {
      domains
        .iter()
        .filter_map(|domain| utils::normalized_domain_for_match(domain))
        .map(|domain| format!("%{}%", utils::escape_like_pattern(domain)))
        .collect()
    })
    .unwrap_or_default();

  if domains.is_some() {
    if domain_filters.is_empty() {
      query += "WHERE 0";
    } else {
      let predicates = (1..=domain_filters.len())
        .map(|index| format!("host LIKE ?{index} ESCAPE '\\'"))
        .collect::<Vec<_>>()
        .join(" OR ");
      query += &format!("WHERE ({predicates})");
    }
  }

  query += ";";

  let mut records: Vec<CookieRecord> = vec![];
  let mut last_row_error: Option<anyhow::Error> = None;
  let mut rows_seen = 0;
  let mut rows_skipped = 0;
  let mut rows_rejected = 0;
  let mut stmt = connection.prepare(query.as_str())?;
  let mut rows = stmt.query(rusqlite::params_from_iter(domain_filters.iter()))?;

  while let Some(row) = {
    runtime.check()?;
    rows.next()?
  } {
    let host = match row.get::<_, String>(0) {
      Ok(host) => host,
      Err(error) => {
        log::warn!("Failed to read host from Firefox cookie row: {error}");
        last_row_error = Some(anyhow!(
          "failed to read host from Firefox cookie row: {error}"
        ));
        rows_seen += 1;
        rows_skipped += 1;
        rows_rejected += 1;
        continue;
      }
    };
    if !utils::some_domain_in_host(domains, &host) {
      continue;
    }
    rows_seen += 1;
    let (path, raw_path) = match optional_sqlite_string(row, 1) {
      Ok((Some(value), None)) => (value, None),
      Ok((None, None)) => ("/".to_owned(), None),
      Ok((_, raw)) => ("/".to_owned(), raw),
      Err(error) => {
        log::warn!("Failed to read path from Firefox cookie row: {error}");
        last_row_error = Some(anyhow!(
          "failed to read path from Firefox cookie row: {error}"
        ));
        rows_skipped += 1;
        rows_rejected += 1;
        continue;
      }
    };
    let observed_secure = match optional_sqlite_bool(row, 2) {
      Ok(value) => value,
      Err(error) => {
        log::warn!("Failed to inspect isSecure in Firefox cookie row: {error}");
        last_row_error = Some(anyhow!(
          "failed to inspect isSecure in Firefox cookie row: {error}"
        ));
        rows_skipped += 1;
        rows_rejected += 1;
        continue;
      }
    };
    let (observed_expiry, raw_expiry) = match optional_sqlite_expiry(row, 3, schema_version) {
      Ok(value) => value,
      Err(error) => {
        log::warn!("Failed to inspect expiry in Firefox cookie row: {error}");
        last_row_error = Some(anyhow!(
          "failed to inspect expiry in Firefox cookie row: {error}"
        ));
        rows_skipped += 1;
        rows_rejected += 1;
        continue;
      }
    };

    let name: String = match row.get(4) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to read name from row: {err}");
        last_row_error = Some(anyhow!("failed to read name from row: {err}"));
        rows_skipped += 1;
        rows_rejected += 1;
        continue;
      }
    };

    let value: String = match row.get(5) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to read value from row: {err}");
        last_row_error = Some(anyhow!("failed to read value from row: {err}"));
        rows_skipped += 1;
        rows_rejected += 1;
        continue;
      }
    };
    let observed_http_only = match optional_sqlite_bool(row, 6) {
      Ok(value) => value,
      Err(error) => {
        log::warn!("Failed to read isHttpOnly from Firefox cookie row: {error}");
        last_row_error = Some(anyhow!(
          "failed to read isHttpOnly from Firefox cookie row: {error}"
        ));
        rows_skipped += 1;
        rows_rejected += 1;
        continue;
      }
    };
    let observed_same_site = match optional_sqlite_i64(row, 7, -1..=2) {
      Ok(value) => value,
      Err(error) => {
        log::warn!("Failed to read sameSite from Firefox cookie row: {error}");
        last_row_error = Some(anyhow!(
          "failed to read sameSite from Firefox cookie row: {error}"
        ));
        rows_skipped += 1;
        rows_rejected += 1;
        continue;
      }
    };
    let (origin_attributes, raw_origin_attributes) = match row.get_ref(8) {
      Ok(rusqlite::types::ValueRef::Null) => (None, None),
      Ok(rusqlite::types::ValueRef::Text(value)) => match std::str::from_utf8(value) {
        Ok(value) => (Some(value.to_owned()), None),
        Err(_) => (None, Some(RawValue::bytes(value.to_vec()))),
      },
      Ok(rusqlite::types::ValueRef::Blob(value)) => (None, Some(RawValue::bytes(value.to_vec()))),
      Ok(rusqlite::types::ValueRef::Integer(value)) => (None, Some(RawValue::Signed(value))),
      Ok(rusqlite::types::ValueRef::Real(value)) => (None, Some(RawValue::text(value.to_string()))),
      Err(error) => {
        log::warn!("Failed to inspect originAttributes in Firefox cookie row: {error}");
        (None, Some(RawValue::text("unreadable")))
      }
    };
    let mut record = CookieRecord::from_legacy_fields(
      host,
      path,
      matches!(observed_secure, Observation::Known(true)),
      match &observed_expiry {
        Observation::Known(expires) => *expires,
        Observation::Missing | Observation::Unknown(_) => None,
      },
      name,
      CookieValue::Plain(SecretString::new(value)),
      matches!(observed_http_only, Observation::Known(true)),
      match &observed_same_site {
        Observation::Known(value) => *value,
        Observation::Missing | Observation::Unknown(_) => SAME_SITE_UNSPECIFIED,
      },
      CookieContext::default(),
      rows_seen,
    );
    record.attributes = Attributes {
      secure: observed_secure,
      http_only: observed_http_only,
      expires: observed_expiry,
      raw_expires: raw_expiry,
      same_site: observed_same_site,
    };
    record.set_context(firefox_cookie_context(origin_attributes));
    if let Some(raw) = raw_path {
      record.retain_raw("path", raw);
    }
    if let Some(raw) = raw_origin_attributes {
      record.isolation.origin_attributes = Observation::Unknown(raw.clone());
      record.retain_raw("origin_attributes", raw);
    }
    records.push(record);
    runtime.check()?;
  }
  runtime.check()?;
  Ok(PersistentCookieQuery {
    records,
    rows_seen,
    rows_skipped,
    rows_rejected,
    last_row_error,
  })
}

fn sqlite_table_columns(
  connection: &rusqlite::Connection,
  table: &str,
) -> Result<std::collections::HashSet<String>> {
  let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
  let columns = statement
    .query_map([], |row| row.get::<_, String>(1))?
    .collect::<std::result::Result<std::collections::HashSet<_>, _>>()?;
  Ok(columns)
}

fn raw_sqlite_value(value: rusqlite::types::ValueRef<'_>) -> RawValue {
  match value {
    rusqlite::types::ValueRef::Null => RawValue::Null,
    rusqlite::types::ValueRef::Integer(value) => RawValue::Signed(value),
    rusqlite::types::ValueRef::Real(value) => RawValue::FloatBits(value.to_bits()),
    rusqlite::types::ValueRef::Text(value) => std::str::from_utf8(value).map_or_else(
      |_| RawValue::bytes(value.to_vec()),
      |value| RawValue::text(value.to_owned()),
    ),
    rusqlite::types::ValueRef::Blob(value) => RawValue::bytes(value.to_vec()),
  }
}

fn optional_sqlite_string(
  row: &rusqlite::Row<'_>,
  index: usize,
) -> Result<(Option<String>, Option<RawValue>)> {
  match row.get_ref(index)? {
    rusqlite::types::ValueRef::Null => Ok((None, None)),
    rusqlite::types::ValueRef::Text(value) => match std::str::from_utf8(value) {
      Ok(value) => Ok((Some(value.to_owned()), None)),
      Err(_) => Ok((None, Some(RawValue::bytes(value.to_vec())))),
    },
    value => Ok((None, Some(raw_sqlite_value(value)))),
  }
}

fn optional_sqlite_bool(row: &rusqlite::Row<'_>, index: usize) -> Result<Observation<bool>> {
  Ok(match row.get_ref(index)? {
    rusqlite::types::ValueRef::Null => Observation::Missing,
    rusqlite::types::ValueRef::Integer(0) => Observation::Known(false),
    rusqlite::types::ValueRef::Integer(1) => Observation::Known(true),
    value => Observation::Unknown(raw_sqlite_value(value)),
  })
}

fn optional_sqlite_i64(
  row: &rusqlite::Row<'_>,
  index: usize,
  known: std::ops::RangeInclusive<i64>,
) -> Result<Observation<i64>> {
  Ok(match row.get_ref(index)? {
    rusqlite::types::ValueRef::Null => Observation::Missing,
    rusqlite::types::ValueRef::Integer(value) if known.contains(&value) => {
      Observation::Known(value)
    }
    value => Observation::Unknown(raw_sqlite_value(value)),
  })
}

fn optional_sqlite_expiry(
  row: &rusqlite::Row<'_>,
  index: usize,
  schema_version: u32,
) -> Result<(Observation<Option<u64>>, Observation<RawValue>)> {
  Ok(match row.get_ref(index)? {
    rusqlite::types::ValueRef::Null => (Observation::Missing, Observation::Missing),
    rusqlite::types::ValueRef::Integer(raw) => {
      let converted = u64::try_from(raw)
        .ok()
        .and_then(|value| persistent_cookie_expiry(value, schema_version));
      let interpreted = if converted.is_some() || raw == 0 {
        Observation::Known(converted)
      } else {
        Observation::Unknown(RawValue::Signed(raw))
      };
      (interpreted, Observation::Known(RawValue::Signed(raw)))
    }
    value => {
      let raw = raw_sqlite_value(value);
      (Observation::Unknown(raw.clone()), Observation::Unknown(raw))
    }
  })
}

fn firefox_cookie_context(origin_attributes: Option<String>) -> CookieContext {
  let mut context = CookieContext {
    origin_attributes,
    ..CookieContext::default()
  };
  let Some(attributes) = context.origin_attributes.as_deref() else {
    return context;
  };
  for (name, value) in url::form_urlencoded::parse(
    attributes
      .strip_prefix('^')
      .unwrap_or(attributes)
      .as_bytes(),
  ) {
    match name.as_ref() {
      "userContextId" => context.user_context_id = value.parse().ok(),
      "partitionKey" => context.partition_key = Some(value.into_owned()),
      "privateBrowsingId" => context.private_browsing_id = value.parse().ok(),
      _ => {}
    }
  }
  context
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionStoreFormat {
  JsonLz4,
  LegacyJson,
}

/// Source-format identifiers this engine can emit. They are declared once here
/// and asserted against the registry's declared capabilities, so an emitted
/// format can never drift away from what a browser definition claims.
pub(crate) const PERSISTENT_FORMAT_ID: &str = "mozilla_sqlite";
pub(crate) const SESSION_JSONLZ4_FORMAT_ID: &str = "firefox_session_jsonlz4";
pub(crate) const SESSION_JSON_FORMAT_ID: &str = "firefox_session_json";

impl SessionStoreFormat {
  pub(crate) fn format_id(self) -> &'static str {
    match self {
      Self::JsonLz4 => SESSION_JSONLZ4_FORMAT_ID,
      Self::LegacyJson => SESSION_JSON_FORMAT_ID,
    }
  }

  /// Recovers the parse format from a planted candidate's format id, so a
  /// candidate-driven caller can hand back exactly what listing planted from
  /// [`SESSION_CANDIDATES`] without carrying a parallel enum.
  pub(crate) fn from_format_id(format_id: &str) -> Option<Self> {
    match format_id {
      SESSION_JSONLZ4_FORMAT_ID => Some(Self::JsonLz4),
      SESSION_JSON_FORMAT_ID => Some(Self::LegacyJson),
      _ => None,
    }
  }
}

/// Section 7 session candidates in authoritative order (ADR 0001 §8, frozen),
/// as profile-relative paths. This is the single source of truth: registry
/// listing plants a [`SourceCandidate`] for each existing entry in this order,
/// extraction acquires them in this order, and the direct path walks the same
/// array, so a candidate can never be added to one and missed by the other.
pub(crate) const SESSION_CANDIDATES: [(&str, SessionStoreFormat); 5] = [
  (
    "sessionstore-backups/recovery.jsonlz4",
    SessionStoreFormat::JsonLz4,
  ),
  (
    "sessionstore-backups/recovery.baklz4",
    SessionStoreFormat::JsonLz4,
  ),
  ("sessionstore.jsonlz4", SessionStoreFormat::JsonLz4),
  ("sessionstore.js", SessionStoreFormat::LegacyJson),
  (
    "sessionstore-backups/previous.jsonlz4",
    SessionStoreFormat::JsonLz4,
  ),
];

/// Declared precedence of a session candidate at `index` in
/// [`SESSION_CANDIDATES`], so reports order attempted candidates by declaration
/// rather than by which ones happened to exist.
pub(crate) fn session_candidate_precedence(index: usize) -> u16 {
  SESSION_CANDIDATE_PRECEDENCE_STEP.saturating_mul(index as u16 + 1)
}

const SESSION_STORE_READ_ATTEMPTS: usize = 2;
const SESSION_CANDIDATE_PRECEDENCE_STEP: u16 = 10;
const MAX_SESSION_COOKIE_DIAGNOSTICS: usize = 8;

#[derive(Debug)]
struct SessionCookieParseDraft {
  #[cfg(test)]
  cookies: Vec<Cookie>,
  #[cfg(test)]
  detailed_cookies: Vec<DetailedCookie>,
  records: Vec<CookieRecord>,
  rows_seen: usize,
  rows_skipped: usize,
  rows_rejected: usize,
  diagnostics: Vec<String>,
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
  rows_seen: usize,
  rows_skipped: usize,
  rows_rejected: usize,
  diagnostics: Vec<String>,
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

#[derive(Debug)]
struct SessionCandidateSuccess {
  parsed: SessionCookieParseDraft,
  attempts: u32,
  transient_errors: Vec<String>,
}

/// Failure counterpart of [`SessionCandidateSuccess`]. Retry diagnostics are
/// carried on both paths so a candidate that never succeeded still reports why
/// each attempt failed.
#[derive(Debug)]
struct SessionCandidateFailure {
  error: anyhow::Error,
  attempts: u32,
  transient_errors: Vec<String>,
}

/// File-private scratch for one acquired session candidate. It names the same
/// facts [`Source`] does, and [`session_source`] converts it at the engine
/// boundary; nothing outside this module sees it.
#[derive(Debug)]
struct MozillaSessionDraft {
  /// Declared candidate precedence from [`session_candidate_precedence`],
  /// retained so a report orders attempted candidates by declaration rather
  /// than by which ones happened to exist.
  selected: bool,
  records: Vec<CookieRecord>,
  rows_seen: usize,
  rows_skipped: usize,
  rows_rejected: usize,
  acquisition_attempts: u32,
  diagnostics: Vec<String>,
  error: Option<String>,
}

/// File-private scratch for one attempted persistent acquisition. It is
/// converted to a [`Source`] by [`persistent_source`]; a boundary stop before
/// the acquisition reached an atomic success or ordinary failure never
/// produces one of these, so a stop cannot turn into a successful zero-row
/// outcome.
#[derive(Debug, Default)]
struct MozillaPersistentDraft {
  records: Vec<CookieRecord>,
  rows_seen: usize,
  rows_skipped: usize,
  rows_rejected: usize,
  acquisition_strategy: Option<sqlite::DatabaseAcquisitionStrategy>,
  acquisition_attempts: u32,
  /// Acquisition, schema validation, or the query did not complete, so the
  /// source failed outright. A source that produced rows is never reported
  /// through this field, so a caller can tell total failure from partial
  /// success.
  error: Option<String>,
  /// Which of those it was, taken from the SQLite layer's typed failure rather
  /// than assumed.
  failure_kind: Option<sqlite::BrowserDatabaseFailureKind>,
  /// A row was seen and rejected while the source itself stayed readable.
  /// Section 5.7 counts this in `rows_skipped` and reports it as a row issue
  /// against a source that still succeeded, which is why it is deliberately
  /// separate from `error`.
  row_error: Option<String>,
}

/// The crate-visible result of acquiring one Mozilla source candidate.
///
/// `Missing` is deliberately not a `Source`: Section 7 makes a missing session
/// candidate silent, and a candidate that vanished between discovery and query
/// is missing however it got there -- its retry diagnostics are dropped on
/// purpose. Termination stays a typed boundary result rather than a fabricated
/// source or flattened diagnostic.
// One outcome exists per acquired candidate and is consumed immediately by
// selection; keeping the source inline avoids a heap allocation per source.
#[allow(clippy::large_enum_variant)]
pub(crate) enum MozillaCandidateOutcome {
  /// The candidate was read (successfully, `selected: true`) or was present
  /// but failed (`selected: false` with the failure recorded on the source).
  Source(Source),
  /// The candidate does not exist. Not an outcome: absence is normal.
  Missing,
  Stop(BoundaryStop),
}

/// The crate-visible result of extracting one Mozilla profile: the sources the
/// walk produced and any boundary stop it observed.
///
/// Sources are in walk order: the persistent source first, then each session
/// candidate in [`SESSION_CANDIDATES`] order.
///
/// The persistent source is present iff the query was attempted, which is all
/// this engine can know. It is *not* the same as "the profile has a persistent
/// store": a session-only profile with no `cookies.sqlite` still attempts the
/// query and so still gets a failed persistent source here. Whether that
/// survives into a report is the adapter's half of the decision --
/// [`super::registry::gecko::populate_gecko_sources`] drops it for a profile
/// that neither discovered a persistent store nor still has one on disk, which
/// is knowledge only the listing and the filesystem have. The direct path keeps
/// every source, because it has no discovery and "attempted" is its whole gate.
pub(crate) struct MozillaExtract {
  pub(crate) sources: Vec<Source>,
  pub(crate) boundary_stop: Option<BoundaryStop>,
}

/// Builds the persistent [`Source`] for a queried Gecko profile.
///
/// `selected: true` because a profile's authoritative persistent store is
/// always the selected source. Records are the only supply of finalized rows,
/// so `cookies_emitted` counts them rather than any cookie list.
fn persistent_source(origin: SourceIdentity, draft: MozillaPersistentDraft) -> Source {
  let acquisition: SourceAcquisition = draft.acquisition_strategy.into();
  let records = draft.records;
  let cookies_emitted = records.len();
  let mut source = Source {
    origin,
    // Effective, not inherited: a profile's authoritative persistent store is
    // always its selected source, even though the listing plants `false`.
    selected: true,
    acquisition,
    records,
    stats: SourceStats {
      rows_seen: draft.rows_seen,
      cookies_emitted,
      rows_skipped: draft.rows_skipped,
      rows_rejected: draft.rows_rejected,
      provider_failures: 0,
    },
    acquisition_attempts: draft.acquisition_attempts,
    // `diagnostics` carries acquisition retry notes, which a report renders as a
    // warning meaning "retried, then succeeded". A rejected row is neither a
    // retry nor a recovery — rows were lost — so it must not be reported that
    // way; `push_row_read_failed` raises it as an error-severity row failure.
    diagnostics: Vec::new(),
    failure: None,
    issues: Vec::new(),
  };
  if let Some(error) = draft.error {
    // The stage is taken from the SQLite layer's typed failure kind rather than
    // assumed: `stage` is a frozen report field consumers read to choose a
    // remedy, and a query that failed after the database opened is not an
    // acquisition failure.
    let stage = match draft.failure_kind {
      Some(sqlite::BrowserDatabaseFailureKind::Query) => SourceFailureStage::Query,
      _ => SourceFailureStage::Acquisition,
    };
    source.fail(stage, error);
  }
  source.push_row_read_failed(draft.row_error);
  source
}

/// Builds a session [`Source`] from one walked Mozilla session candidate.
///
/// A session candidate fails by being unreadable as JSON/LZ4, which is a parse
/// failure, not an acquisition one. Its rejected rows are already counted in
/// `rows_skipped` and described by `diagnostics`, so it carries no row error.
fn session_source(origin: SourceIdentity, session: MozillaSessionDraft) -> Source {
  let mut source = Source {
    origin,
    // Effective only: first-valid selection is decided by reading, so it must
    // never be written back as though discovery had decided it.
    selected: session.selected,
    acquisition: SourceAcquisition::StableFileImage,
    records: session.records,
    stats: SourceStats {
      rows_seen: session.rows_seen,
      cookies_emitted: 0,
      rows_skipped: session.rows_skipped,
      rows_rejected: session.rows_rejected,
      provider_failures: 0,
    },
    acquisition_attempts: session.acquisition_attempts,
    diagnostics: session.diagnostics,
    failure: None,
    issues: Vec::new(),
  };
  source.stats.cookies_emitted = source.records.len();
  // A session candidate never keeps a row error, but rows it rejected still
  // cost cookies. The issue is keyed on the count, not on the presence of an
  // error string: raising it only when an engine happened to keep one lets a
  // report claim `complete` while cookies were dropped. (invariants (b), (c))
  source.push_row_read_failed(None);
  if let Some(error) = session.error {
    source.fail(SourceFailureStage::Parse, error);
  }
  source
}

/// Extract a Mozilla profile with the same authoritative session ordering as
/// `firefox_based`, retaining diagnostics which the legacy API intentionally
/// only logs. Missing session candidates are not outcomes: absence is normal.
///
/// Production callers thread a runtime through
/// [`query_cookies_engine_outcome_with_runtime`]; this standard-runtime
/// wrapper remains for the walk's characterization tests.
#[cfg(test)]
pub(crate) fn query_cookies_engine_outcome(
  db_path: &Path,
  domains: Option<&[String]>,
) -> MozillaExtract {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  query_cookies_engine_outcome_with_runtime(db_path, domains, &runtime)
}

pub(crate) fn query_cookies_engine_outcome_with_runtime(
  db_path: &Path,
  domains: Option<&[String]>,
  runtime: &BoundaryRuntime<'_>,
) -> MozillaExtract {
  query_cookies_engine_outcome_with_session_probe(
    db_path,
    domains,
    runtime,
    parse_session_path_with_runtime,
  )
}

/// The direct-path walk: the persistent acquisition followed by first-valid
/// selection over every [`SESSION_CANDIDATES`] entry, each acquired as its own
/// [`Source`]. The registry path does not come through here -- it drives the
/// same per-candidate acquisitions from the candidates its listing planted
/// (`populate_gecko_sources`) -- but both share [`select_session_sources`], so
/// the first-valid rule cannot fork.
///
/// The persistent source is emitted first, then the session sources in
/// declared order. Both facts are load-bearing: the adapter completes the
/// persistent gate (see [`MozillaExtract`]), and the report orders sources by
/// role and precedence, so producing them out of walk order would reshuffle
/// equal keys under a stable sort.
fn query_cookies_engine_outcome_with_session_probe<P>(
  db_path: &Path,
  domains: Option<&[String]>,
  runtime: &BoundaryRuntime<'_>,
  mut probe_session: P,
) -> MozillaExtract
where
  P: FnMut(
    &Path,
    SessionStoreFormat,
    Option<&[String]>,
    &BoundaryRuntime<'_>,
  ) -> std::result::Result<SessionCandidateSuccess, SessionCandidateFailure>,
{
  let mut sources = Vec::new();
  // A direct path did no discovery, so there is no candidate to take an
  // identity from -- this states the one the named file implies. It is an
  // identity, not a synthetic candidate: there are no listing decisions to
  // invent, which is the whole reason `origin` narrowed.
  let persistent_origin = SourceIdentity {
    path: db_path.to_path_buf(),
    role: CookieSourceRoleId::persistent(),
    format: CookieSourceFormatId::known(PERSISTENT_FORMAT_ID),
    precedence: PERSISTENT_SOURCE_PRECEDENCE,
  };
  match acquire_persistent_source_with_runtime(persistent_origin, domains, runtime) {
    Ok(source) => sources.push(source),
    // A stop before the persistent acquisition reached an atomic success or
    // ordinary failure: nothing was attempted, so nothing is a source and the
    // session candidates are never reached.
    Err(stop) => {
      return MozillaExtract {
        sources,
        boundary_stop: Some(stop),
      }
    }
  }
  let cookies_dir = db_path.parent().unwrap_or_else(|| Path::new(""));
  let outcomes = SESSION_CANDIDATES
    .into_iter()
    .enumerate()
    .map(|(index, (relative, format))| {
      if let Err(stop) = runtime.check() {
        return MozillaCandidateOutcome::Stop(stop);
      }
      let path = cookies_dir.join(relative);
      let probed = probe_session(&path, format, domains, runtime);
      // Same identity keys the registry listing would have planted for this
      // relative path, so the wire join keys are unchanged.
      let origin = SourceIdentity {
        path,
        role: CookieSourceRoleId::session(),
        format: CookieSourceFormatId::known(format.format_id()),
        precedence: session_candidate_precedence(index),
      };
      session_outcome_from_probe(origin, probed)
    });
  let boundary_stop =
    select_session_sources(outcomes, &mut sources).or_else(|| runtime.check().err());
  MozillaExtract {
    sources,
    boundary_stop,
  }
}

/// The first-valid selection rule over session candidate outcomes, shared by
/// the direct-path walk and the registry's candidate-driven populate.
///
/// Failed-but-present candidates are pushed (`selected: false`) and iteration
/// continues; a missing candidate pushes nothing; the first successful
/// candidate (`selected: true`) is pushed and iteration stops **without
/// pulling further outcomes**, so later candidates are never acquired -- the
/// iterator must be lazy for that guarantee to mean anything. At most one
/// pushed source can therefore be selected. A boundary stop ends the selection
/// and is returned.
pub(crate) fn select_session_sources(
  outcomes: impl Iterator<Item = MozillaCandidateOutcome>,
  sources: &mut Vec<Source>,
) -> Option<BoundaryStop> {
  for outcome in outcomes {
    match outcome {
      MozillaCandidateOutcome::Source(source) => {
        let selected = source.selected;
        sources.push(source);
        if selected {
          return None;
        }
      }
      MozillaCandidateOutcome::Missing => {}
      MozillaCandidateOutcome::Stop(stop) => return Some(stop),
    }
  }
  None
}

/// Acquires a profile's persistent `cookies.sqlite` as its own [`Source`].
///
/// `Ok` means the acquisition was attempted -- the returned source may still
/// carry a failure. `Err` is a boundary stop observed before the attempt
/// reached an atomic success or ordinary failure; it must not become a
/// successful zero-row source.
pub(crate) fn acquire_persistent_source_with_runtime(
  origin: SourceIdentity,
  domains: Option<&[String]>,
  runtime: &BoundaryRuntime<'_>,
) -> std::result::Result<Source, BoundaryStop> {
  let db_path = origin.path.clone();
  let mut draft = MozillaPersistentDraft::default();
  match sqlite::with_browser_database_with_runtime(
    db_path.clone(),
    |connection| query_persistent_cookies_with_runtime(connection, domains, runtime),
    runtime,
  ) {
    Ok(database) => {
      draft.acquisition_strategy = Some(database.strategy());
      draft.acquisition_attempts = database.attempts();
      let persistent = database.into_value();
      draft.rows_seen = persistent.rows_seen;
      draft.rows_skipped = persistent.rows_skipped;
      draft.rows_rejected = persistent.rows_rejected;
      draft.row_error = persistent.last_row_error.map(|error| format!("{error:#}"));
      draft.records = persistent.records;
    }
    Err(error) => {
      if let Some(stop) = error.downcast_ref::<BoundaryStop>() {
        return Err(*stop);
      }
      if let Some(failure) = error.downcast_ref::<sqlite::BrowserDatabaseFailure>() {
        draft.acquisition_strategy = failure.strategy;
        draft.acquisition_attempts = failure.attempts;
        draft.failure_kind = Some(failure.kind);
      } else {
        draft.acquisition_attempts = 1;
      }
      draft.error = Some(format!("{error:#}"));
    }
  }
  Ok(persistent_source(origin, draft))
}

/// Acquires one session candidate as its own [`Source`].
///
/// The runtime is sampled before the read, matching the per-candidate check
/// the walk performs, so a stop between candidates is observed before the next
/// one is touched.
pub(crate) fn acquire_session_source_with_runtime(
  origin: SourceIdentity,
  format: SessionStoreFormat,
  domains: Option<&[String]>,
  runtime: &BoundaryRuntime<'_>,
) -> MozillaCandidateOutcome {
  if let Err(stop) = runtime.check() {
    return MozillaCandidateOutcome::Stop(stop);
  }
  let probed = parse_session_path_with_runtime(&origin.path, format, domains, runtime);
  session_outcome_from_probe(origin, probed)
}

/// Converts one probed session candidate into its [`MozillaCandidateOutcome`].
fn session_outcome_from_probe(
  origin: SourceIdentity,
  probed: std::result::Result<SessionCandidateSuccess, SessionCandidateFailure>,
) -> MozillaCandidateOutcome {
  match probed {
    Ok(success) => {
      let mut diagnostics = success.transient_errors;
      diagnostics.extend(success.parsed.diagnostics);
      MozillaCandidateOutcome::Source(session_source(
        origin,
        MozillaSessionDraft {
          selected: true,
          records: success.parsed.records,
          rows_seen: success.parsed.rows_seen,
          rows_skipped: success.parsed.rows_skipped,
          rows_rejected: success.parsed.rows_rejected,
          acquisition_attempts: success.attempts,
          diagnostics,
          error: None,
        },
      ))
    }
    // Section 7 makes a missing candidate silent, and a candidate whose final
    // state is "gone" is missing however it got there. Its retry diagnostics
    // are therefore dropped on purpose: a vanished candidate is not a source.
    Err(failure) if is_missing_session_file(&failure.error) => MozillaCandidateOutcome::Missing,
    Err(failure) => {
      if let Some(stop) = failure.error.downcast_ref::<BoundaryStop>() {
        return MozillaCandidateOutcome::Stop(*stop);
      }
      MozillaCandidateOutcome::Source(session_source(
        origin,
        MozillaSessionDraft {
          selected: false,
          records: Vec::new(),
          rows_seen: 0,
          rows_skipped: 0,
          rows_rejected: 0,
          acquisition_attempts: failure.attempts,
          diagnostics: failure.transient_errors,
          error: Some(format!("{:#}", failure.error)),
        },
      ))
    }
  }
}

/// Acquires one planted [`SourceCandidate`] as its own [`Source`], dispatching
/// on the candidate's role. This is the production query the candidate-driven
/// Gecko populate injects; only the candidate's path, role, format, and
/// precedence are read -- everything the resulting source reports is
/// re-derived from the read itself.
pub(crate) fn acquire_candidate_source(
  candidate: &SourceCandidate,
  domains: Option<&[String]>,
) -> MozillaCandidateOutcome {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  acquire_candidate_source_with_runtime(candidate, domains, &runtime)
}

pub(crate) fn acquire_candidate_source_with_runtime(
  candidate: &SourceCandidate,
  domains: Option<&[String]>,
  runtime: &BoundaryRuntime<'_>,
) -> MozillaCandidateOutcome {
  if candidate.role == CookieSourceRoleId::persistent() {
    return match acquire_persistent_source_with_runtime(candidate.identity(), domains, runtime) {
      Ok(source) => MozillaCandidateOutcome::Source(source),
      Err(stop) => MozillaCandidateOutcome::Stop(stop),
    };
  }
  match SessionStoreFormat::from_format_id(candidate.format.as_str()) {
    Some(format) => {
      acquire_session_source_with_runtime(candidate.identity(), format, domains, runtime)
    }
    // Only this crate plants Mozilla candidates, and it plants exactly the
    // SESSION_CANDIDATES formats, so this is a programming error -- surfaced
    // as a failed source rather than silently skipped or panicked on.
    None => {
      let mut source = Source::new(
        candidate.identity(),
        candidate.selected,
        candidate.acquisition,
      );
      source.fail(
        SourceFailureStage::Parse,
        format!(
          "unrecognized Mozilla session store format {:?}",
          candidate.format.as_str()
        ),
      );
      MozillaCandidateOutcome::Source(source)
    }
  }
}

fn parse_session_path_with_runtime(
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
fn parse_session_candidate_with<F>(
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

fn parse_session_candidate_with_runtime<F>(
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

fn is_missing_session_file(error: &anyhow::Error) -> bool {
  matches!(
    error.downcast_ref::<std::io::Error>(),
    Some(error) if error.kind() == std::io::ErrorKind::NotFound
  )
}

#[cfg(test)]
fn read_stable_session_file(path: &Path) -> Result<Vec<u8>> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  read_stable_session_file_with_runtime(path, &runtime).map(|bytes| bytes.as_slice().to_vec())
}

fn read_stable_session_file_with_runtime(
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

fn decompress_session_store(compressed: &[u8]) -> Result<SecretBytes> {
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

fn record_session_cookie(
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
fn parse_session_json(json: &Value, domains: Option<&[String]>) -> Result<SessionCookieParseDraft> {
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

fn parse_session_json_with_runtime(
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
fn parse_legacy_session_cookies(
  path: &Path,
  domains: Option<&[String]>,
) -> Result<SessionCookieParseDraft> {
  let clock = SystemClock;
  parse_legacy_session_cookies_with_deadline(path, domains, &clock, Deadline::standard())
}

#[cfg(test)]
fn parse_legacy_session_cookies_with_deadline(
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
fn parse_session_cookies_lz4(
  path: &Path,
  domains: Option<&[String]>,
) -> Result<SessionCookieParseDraft> {
  let clock = SystemClock;
  parse_session_cookies_lz4_with_deadline(path, domains, &clock, Deadline::standard())
}

#[cfg(test)]
fn parse_session_cookies_lz4_with_deadline(
  path: &Path,
  domains: Option<&[String]>,
  clock: &dyn Clock,
  deadline: Deadline,
) -> Result<SessionCookieParseDraft> {
  let runtime = BoundaryRuntime::new(clock, deadline);
  let bytes = read_stable_session_file_with_runtime(path, &runtime)?;
  decode_acquired_session(bytes, SessionStoreFormat::JsonLz4, domains, &runtime)
}

fn decode_acquired_session(
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

fn decode_session_source(
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

fn project_session_records(
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

fn session_cookie_expiry(json_cookie: &Value) -> (Observation<Option<u64>>, Observation<RawValue>) {
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

fn create_cookie_record(json_cookie: &Value) -> Result<CookieRecord> {
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

fn firefox_session_cookie_context(origin_attributes: Option<&Value>) -> CookieContext {
  let Some(origin_attributes) = origin_attributes else {
    return CookieContext::default();
  };
  if let Some(origin_attributes) = origin_attributes.as_str() {
    return firefox_cookie_context(Some(origin_attributes.to_owned()));
  }
  let Some(attributes) = origin_attributes.as_object() else {
    return CookieContext {
      origin_attributes: Some(origin_attributes.to_string()),
      ..CookieContext::default()
    };
  };

  let unsigned_attribute = |name: &str| {
    attributes.get(name).and_then(|value| {
      value
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
    })
  };
  CookieContext {
    origin_attributes: Some(Value::Object(attributes.clone()).to_string()),
    user_context_id: unsigned_attribute("userContextId"),
    partition_key: attributes
      .get("partitionKey")
      .and_then(Value::as_str)
      .map(str::to_owned),
    private_browsing_id: unsigned_attribute("privateBrowsingId"),
    ..CookieContext::default()
  }
}

/// A profile declared by a Mozilla-family browser's `profiles.ini`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MozillaProfile {
  /// The profile's `Name=` value, or an empty string when the section omits it.
  pub name: String,
  /// Path to the profile directory, absolute whenever the caller supplied an
  /// absolute `profiles.ini` path.
  pub path: PathBuf,
  /// Whether this is the profile that the installation owning this
  /// `profiles.ini` would open.
  ///
  /// Defaults are per-installation, so a list gathered across several
  /// installation roots (snap and distro Firefox, say) can contain more than
  /// one default.
  pub is_default: bool,
}

/// A `[Profile...]` section, with its `Path` kept exactly as written in the ini.
struct ProfileSection {
  name: String,
  path: String,
  default_flag: bool,
}

/// Reads `profiles.ini` with escape processing disabled.
///
/// The default parser treats `\` as an escape introducer, which silently
/// destroys the Windows paths that `IsRelative=0` sections store:
/// `Path=C:\Users\me\Profiles\work` would parse as `C:UsersmeProfileswork`,
/// with `\r` becoming a carriage return.
#[cfg(test)]
fn load_profiles_ini(profiles_path: &Path) -> Result<Ini> {
  Ini::load_from_file_opt(
    profiles_path,
    ParseOption {
      enabled_escape: false,
      ..Default::default()
    },
  )
  .map_err(Into::into)
}

/// Every `[Profile...]` section that declares a `Path`.
///
/// Firefox itself walks `Profile0`, `Profile1`, ... and stops at the first gap,
/// also requiring `Name` and `IsRelative`. We deliberately accept any
/// `[Profile...]` section with a `Path` instead: reading cookies from a profile
/// Firefox would skip is useful, whereas dropping a real profile is not.
fn profile_sections(conf: &Ini) -> Vec<ProfileSection> {
  conf
    .iter()
    .filter(|(section, _)| section.unwrap_or_default().starts_with("Profile"))
    .filter_map(|(_, props)| {
      let path = props.get("Path")?.trim();
      if path.is_empty() {
        return None;
      }
      Some(ProfileSection {
        name: props.get("Name").unwrap_or_default().to_string(),
        path: path.to_string(),
        default_flag: props.get("Default").unwrap_or_default().trim() == "1",
      })
    })
    .collect()
}

/// Profile paths named by `[Install...] Default=`, deduplicated in file order.
///
/// Firefox keys each section by a hash of the installation directory. Several
/// distinct entries therefore mean this file is shared — by a release and a
/// nightly, or by one live install plus debris, since sections for moved or
/// uninstalled builds are never removed.
fn install_defaults(conf: &Ini) -> Vec<String> {
  let mut defaults: Vec<String> = vec![];
  for (_, props) in conf
    .iter()
    .filter(|(section, _)| section.unwrap_or_default().starts_with("Install"))
  {
    let Some(default) = props
      .get("Default")
      .map(str::trim)
      .filter(|d| !d.is_empty())
    else {
      continue;
    };
    if !defaults.iter().any(|existing| existing == default) {
      defaults.push(default.to_string());
    }
  }
  defaults
}

/// Resolves the default profile's `Path` value, or `None` when the ini declares
/// nothing usable.
///
/// This is a heuristic, not Firefox's algorithm. Firefox picks the
/// `[Install<hash>]` section matching a hash of the *running installation's*
/// directory and honours it unconditionally; sections never compete. We cannot
/// know which installation a caller means, so we degrade in this order:
///
/// 1. a single unambiguous install default — the dedicated profile that the one
///    installation on record opens;
/// 2. with competing installs, a default that the legacy `[ProfileN] Default=1`
///    marker also names, else any profile some install claims — better a
///    profile one installation opens than one none does;
/// 3. the `Default=1` marker alone;
/// 4. the first declared profile;
/// 5. an install default naming a profile that has no section of its own.
fn resolve_default_path(profiles: &[ProfileSection], installs: &[String]) -> Option<String> {
  let is_known = |candidate: &str| profiles.iter().any(|profile| profile.path == candidate);

  if let [only] = installs {
    if is_known(only) {
      return Some(only.clone());
    }
  }

  if installs.len() > 1 {
    log::warn!(
      "profiles.ini declares {} competing [Install...] defaults; guessing which installation is meant",
      installs.len()
    );
    if let Some(profile) = profiles
      .iter()
      .find(|profile| profile.default_flag && installs.contains(&profile.path))
    {
      return Some(profile.path.clone());
    }
    if let Some(default) = installs.iter().find(|default| is_known(default)) {
      return Some(default.clone());
    }
  }

  if let Some(profile) = profiles.iter().find(|profile| profile.default_flag) {
    return Some(profile.path.clone());
  }

  profiles
    .first()
    .map(|profile| profile.path.clone())
    // An install may name a profile that has no [Profile...] section of its
    // own; trying it still beats giving up.
    .or_else(|| installs.first().cloned())
}

/// Returns every profile declared by `profiles.ini`, in file order, resolved
/// against the file's directory and with the default profile flagged.
///
/// Exposing the secondary profiles — not just the default — is what lets
/// callers read cookies from a profile the browser does not open by default.
#[cfg(test)]
pub(crate) fn list_profiles(profiles_path: &Path) -> Result<Vec<MozillaProfile>> {
  let conf = load_profiles_ini(profiles_path)?;
  Ok(profiles_from_ini(&conf, profiles_path))
}

/// [`list_profiles`] for callers that already hold the file's contents, so
/// discovery can route the read through its injected filesystem seam instead of
/// reaching for the real one.
pub(crate) fn list_profiles_from_str(
  contents: &str,
  profiles_path: &Path,
) -> Result<Vec<MozillaProfile>> {
  // `Ini::load_from_file_opt` strips a UTF-8 BOM; the string parser does not,
  // and U+FEFF is not whitespace, so a BOM would swallow every section into the
  // anonymous one and yield zero profiles with no error at all.
  let contents = contents.strip_prefix('\u{feff}').unwrap_or(contents);
  let conf = Ini::load_from_str_opt(
    contents,
    ParseOption {
      enabled_escape: false,
      ..Default::default()
    },
  )?;
  Ok(profiles_from_ini(&conf, profiles_path))
}

fn profiles_from_ini(conf: &Ini, profiles_path: &Path) -> Vec<MozillaProfile> {
  let base = profiles_path.parent().unwrap_or_else(|| Path::new(""));
  let sections = profile_sections(conf);
  let installs = install_defaults(conf);
  let default_path = resolve_default_path(&sections, &installs);

  // Exactly one entry carries the flag: two sections may declare the same
  // `Path`, and "the default" must stay singular within one profiles.ini.
  let mut default_taken = false;
  let mut claim_default = |candidate: &str| {
    let is_default = !default_taken && default_path.as_deref() == Some(candidate);
    default_taken |= is_default;
    is_default
  };

  let mut profiles: Vec<MozillaProfile> = sections
    .iter()
    .map(|profile| MozillaProfile {
      is_default: claim_default(&profile.path),
      // `IsRelative=0` sections store a full native path, which `join` passes
      // through. We trust the shape of `Path` rather than the `IsRelative`
      // flag, which browsers do not always keep in sync.
      path: base.join(&profile.path),
      name: profile.name.clone(),
    })
    .collect();

  // An [Install...] section can name a profile that has no [Profile...]
  // section, e.g. after a hand-edited or partially migrated profiles.ini. The
  // pre-enumeration resolver probed those directly, so surface every one of
  // them — not just whichever the heuristic happened to choose.
  for orphan in installs
    .iter()
    .filter(|default| !is_known_section(&sections, default))
  {
    profiles.push(MozillaProfile {
      is_default: claim_default(orphan),
      path: base.join(orphan),
      name: String::new(),
    });
  }

  profiles
}

fn is_known_section(sections: &[ProfileSection], candidate: &str) -> bool {
  sections.iter().any(|section| section.path == candidate)
}

/// Picks the profile a user asked for, matching its `Name`, its directory name,
/// or its full path.
///
/// An ambiguous selector is an error rather than a silent first-match: picking
/// the wrong profile is the failure this whole resolver exists to prevent.
#[cfg(test)]
pub(crate) fn select_profile<'a>(
  profiles: &'a [MozillaProfile],
  selector: &str,
) -> Result<&'a MozillaProfile> {
  if selector.is_empty() {
    bail!("Profile selector must not be empty");
  }
  // Comparing as a `Path` keeps selection separator-insensitive on Windows,
  // where `base.join("Profiles/work")` yields mixed separators but a user
  // naturally writes the all-backslash spelling.
  let wanted = Path::new(selector);
  let matches: Vec<&MozillaProfile> = profiles
    .iter()
    .filter(|profile| {
      profile.name == selector
        || profile.path.file_name().is_some_and(|dir| dir == selector)
        || profile.path == wanted
    })
    .collect();

  match matches[..] {
    [only] => Ok(only),
    [] => bail!(
      "No profile matching {selector:?}. Available profiles: [{}]",
      describe(profiles.iter())
    ),
    _ => bail!(
      "{} profiles match {selector:?}; select one by full path instead: [{}]",
      matches.len(),
      describe(matches.iter().copied())
    ),
  }
}

#[cfg(test)]
fn describe<'a>(profiles: impl Iterator<Item = &'a MozillaProfile>) -> String {
  profiles
    .map(|profile| format!("{} ({REDACTED_PATH})", profile.name))
    .collect::<Vec<_>>()
    .join(", ")
}

#[cfg(test)]
fn decode_persistent_gate_connection(
  connection: &rusqlite::Connection,
) -> Result<(MozillaPersistentDecodeSummary, Vec<CookieRecord>)> {
  let source = MozillaPersistentReadOnlySource {
    connection,
    domains: None,
  };
  let decoder = MozillaPersistentDecoder;
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  let mut records = Vec::new();
  let summary = decoder.decode(
    &source,
    &mut |record| {
      records.push(record);
      Ok(())
    },
    &runtime,
  )?;
  Ok((summary, records))
}

#[cfg(test)]
pub(super) fn structured_persistent_decoder_gate() -> Result<()> {
  use rusqlite::types::Value as SqlValue;

  const OPTIONAL_COLUMNS: [(&str, &str, usize); 6] = [
    ("path", "path", 1),
    ("isSecure", "secure", 2),
    ("expiry", "expiry", 3),
    ("isHttpOnly", "http_only", 6),
    ("sameSite", "same_site", 7),
    ("originAttributes", "origin_attributes", 8),
  ];
  let full_schema = "CREATE TABLE moz_cookies (
    host TEXT, path, isSecure, expiry, name TEXT, value TEXT,
    isHttpOnly, sameSite, originAttributes
  );";

  // Every row keeps the three required fields valid while exactly one
  // optional field changes shape. This reaches the raw-value branches and the
  // sink instead of having an early invalid `name` mask the rest of decoding.
  let connection = rusqlite::Connection::open_in_memory()?;
  connection.execute_batch(&format!("PRAGMA user_version = 15; {full_schema}"))?;
  let baseline = vec![
    SqlValue::Text(".example.com".to_owned()),
    SqlValue::Text("/".to_owned()),
    SqlValue::Integer(1),
    SqlValue::Integer(1_700_000_000),
    SqlValue::Text("baseline".to_owned()),
    SqlValue::Text("plain-value".to_owned()),
    SqlValue::Integer(1),
    SqlValue::Integer(1),
    SqlValue::Text("^userContextId=7".to_owned()),
  ];
  connection.execute(
    "INSERT INTO moz_cookies VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    rusqlite::params_from_iter(baseline.iter()),
  )?;
  for (index, (column, _, sqlite_index)) in OPTIONAL_COLUMNS.iter().enumerate() {
    let mut row = baseline.clone();
    row[4] = SqlValue::Text(format!("malformed-{column}"));
    row[*sqlite_index] = match *column {
      "path" | "expiry" => SqlValue::Blob(vec![0xff, index as u8]),
      "isSecure" => SqlValue::Text("sometimes".to_owned()),
      "isHttpOnly" => SqlValue::Real(0.5),
      "sameSite" => SqlValue::Integer(9),
      "originAttributes" => SqlValue::Integer(17),
      _ => unreachable!("the optional corpus is exhaustive"),
    };
    connection.execute(
      "INSERT INTO moz_cookies VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
      rusqlite::params_from_iter(row.iter()),
    )?;
  }
  let (summary, records) = decode_persistent_gate_connection(&connection)?;
  assert_eq!(summary.rows_seen, OPTIONAL_COLUMNS.len() + 1);
  assert_eq!(summary.rows_skipped, 0);
  assert_eq!(summary.rows_rejected, 0);
  assert_eq!(records.len(), OPTIONAL_COLUMNS.len() + 1);
  assert_eq!(records[0].name, "baseline");
  assert_eq!(records[0].origin.ordinal, 0);
  for (ordinal, (column, raw_key, _)) in OPTIONAL_COLUMNS.iter().enumerate() {
    let record = records
      .iter()
      .find(|record| record.name == format!("malformed-{column}"))
      .expect("each independently malformed optional field emits a record");
    assert_eq!(record.origin.ordinal, (ordinal + 1) as u64);
    match *column {
      "path" => assert!(record.raw.contains_key(*raw_key)),
      "isSecure" => assert!(matches!(record.attributes.secure, Observation::Unknown(_))),
      "expiry" => {
        assert!(matches!(record.attributes.expires, Observation::Unknown(_)));
        assert!(matches!(
          record.attributes.raw_expires,
          Observation::Unknown(_)
        ));
      }
      "isHttpOnly" => assert!(matches!(
        record.attributes.http_only,
        Observation::Unknown(_)
      )),
      "sameSite" => assert!(matches!(
        record.attributes.same_site,
        Observation::Unknown(_)
      )),
      "originAttributes" => {
        assert!(record.raw.contains_key(*raw_key));
        assert!(matches!(
          record.isolation.origin_attributes,
          Observation::Unknown(_)
        ));
      }
      _ => unreachable!("the optional corpus is exhaustive"),
    }
  }

  // Required fields never borrow the optional metadata policy. Keep one valid
  // sibling in every fixture, then vary exactly one required field through
  // NULL and a wrong SQLite storage class. The malformed row is rejected while
  // the sibling still reaches the sink.
  for (required, sqlite_index) in [("host", 0), ("name", 4), ("value", 5)] {
    for malformed in [SqlValue::Null, SqlValue::Blob(vec![0xff, 0x00])] {
      let connection = rusqlite::Connection::open_in_memory()?;
      connection.execute_batch(&format!("PRAGMA user_version = 15; {full_schema}"))?;
      connection.execute(
        "INSERT INTO moz_cookies VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params_from_iter(baseline.iter()),
      )?;
      let mut row = baseline.clone();
      row[sqlite_index] = malformed;
      if required != "name" {
        row[4] = SqlValue::Text(format!("malformed-required-{required}"));
      }
      connection.execute(
        "INSERT INTO moz_cookies VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params_from_iter(row.iter()),
      )?;

      let (summary, records) = decode_persistent_gate_connection(&connection)?;
      assert_eq!(summary.rows_seen, 2);
      assert_eq!(summary.rows_skipped, 1);
      assert_eq!(summary.rows_rejected, 1);
      assert_eq!(records.len(), 1);
      assert_eq!(records[0].name, "baseline");
      assert!(summary
        .last_row_error
        .as_ref()
        .is_some_and(|error| format!("{error:#}").contains(required)));
    }
  }

  // Omitting a required schema column is a source-level query failure, never
  // a zero-row success or an optional-column NULL projection.
  for missing in ["host", "name", "value"] {
    let connection = rusqlite::Connection::open_in_memory()?;
    let columns = [
      "host TEXT",
      "path",
      "isSecure",
      "expiry",
      "name TEXT",
      "value TEXT",
      "isHttpOnly",
      "sameSite",
      "originAttributes",
    ]
    .into_iter()
    .filter(|definition| !definition.starts_with(missing))
    .collect::<Vec<_>>()
    .join(", ");
    connection.execute_batch(&format!(
      "PRAGMA user_version = 15; CREATE TABLE moz_cookies ({columns});"
    ))?;
    let error = decode_persistent_gate_connection(&connection)
      .expect_err("a missing required SQLite column must fail the source query");
    assert!(format!("{error:#}").contains(missing));
  }

  // Probe every optional-column absence independently. Each schema still has
  // a valid host/name/value row and must reach the sink once.
  for (missing, _, _) in OPTIONAL_COLUMNS {
    let connection = rusqlite::Connection::open_in_memory()?;
    let optional_definitions = OPTIONAL_COLUMNS
      .iter()
      .filter(|(column, _, _)| *column != missing)
      .map(|(column, _, _)| *column)
      .collect::<Vec<_>>()
      .join(", ");
    connection.execute_batch(&format!(
      "PRAGMA user_version = 15;
       CREATE TABLE moz_cookies (host TEXT, name TEXT, value TEXT, {optional_definitions});
       INSERT INTO moz_cookies (host, name, value)
       VALUES ('.example.com', 'missing-{missing}', 'plain-value');"
    ))?;
    let (summary, records) = decode_persistent_gate_connection(&connection)?;
    assert_eq!(summary.rows_seen, 1);
    assert_eq!(summary.rows_rejected, 0);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].name, format!("missing-{missing}"));
  }

  // Firefox schema 15 stores seconds; schema 16 and later stores
  // milliseconds. Both paths preserve the raw integer while emitting the same
  // interpreted expiry.
  for (schema, raw_expiry) in [(15, 1_700_000_000_i64), (16, 1_700_000_000_999_i64)] {
    let connection = rusqlite::Connection::open_in_memory()?;
    connection.execute_batch(&format!("PRAGMA user_version = {schema}; {full_schema}"))?;
    connection.execute(
      "INSERT INTO moz_cookies VALUES (?1, '/', 0, ?2, ?3, ?4, 0, 0, NULL)",
      rusqlite::params![
        ".example.com",
        raw_expiry,
        format!("schema-{schema}"),
        "plain-value"
      ],
    )?;
    let (summary, records) = decode_persistent_gate_connection(&connection)?;
    assert_eq!(summary.rows_seen, 1);
    assert_eq!(records.len(), 1);
    assert_eq!(
      records[0]
        .clone()
        .into_cookie()
        .expect("persistent gate record is plaintext")
        .expires,
      Some(1_700_000_000)
    );
    assert_eq!(
      records[0].attributes.raw_expires,
      Observation::Known(RawValue::Signed(raw_expiry))
    );
  }
  Ok(())
}

#[cfg(test)]
fn encode_session_gate_case(json: &Value, format: SessionStoreFormat) -> Vec<u8> {
  let plain = serde_json::to_vec(json).expect("serialize structured session gate case");
  match format {
    SessionStoreFormat::LegacyJson => plain,
    SessionStoreFormat::JsonLz4 => {
      let mut encoded = b"mozLz40\0".to_vec();
      encoded.extend(lz4_flex::block::compress_prepend_size(&plain));
      encoded
    }
  }
}

#[cfg(test)]
fn decode_session_gate_case(
  json: &Value,
  format: SessionStoreFormat,
) -> Result<(MozillaSessionDecodeSummary, Vec<CookieRecord>)> {
  let bytes = encode_session_gate_case(json, format);
  let source = MozillaSessionReadOnlySource {
    bytes: &bytes,
    format,
    domains: None,
  };
  let decoder = MozillaSessionDecoder;
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  let mut records = Vec::new();
  let summary = decoder.decode(
    &source,
    &mut |record| {
      records.push(record);
      Ok(())
    },
    &runtime,
  )?;
  Ok((summary, records))
}

#[cfg(test)]
fn structured_session_decoder_gate(format: SessionStoreFormat) -> Result<()> {
  let valid = serde_json::json!({
    "host": ".example.com",
    "path": "/",
    "secure": true,
    "name": "valid",
    "value": "plain-value",
    "httponly": true,
    "sameSite": 1,
    "expiry": 1_700_000_000_u64,
    "originAttributes": {"userContextId": 7, "partitionKey": "(https,example.com)"}
  });
  let optional_cases = [
    ("path", serde_json::json!({"future": true})),
    ("secure", serde_json::json!(2)),
    ("httponly", serde_json::json!("sometimes")),
    ("sameSite", serde_json::json!(9)),
    ("expiry", serde_json::json!("later")),
    ("originAttributes", serde_json::json!(["future"])),
  ];
  let mut optional_records_emitted = 0;
  for (field, malformed) in optional_cases {
    let mut changed = valid.clone();
    changed
      .as_object_mut()
      .expect("cookie fixture is an object")
      .insert(field.to_owned(), malformed);
    changed
      .as_object_mut()
      .expect("cookie fixture is an object")
      .insert(
        "name".to_owned(),
        Value::String(format!("malformed-{field}")),
      );
    let envelope = serde_json::json!({"windows": [{"cookies": [valid.clone(), changed]}]});
    let (summary, records) = decode_session_gate_case(&envelope, format)?;
    assert_eq!(summary.rows_seen, 2);
    assert_eq!(summary.rows_skipped, 0);
    assert_eq!(summary.rows_rejected, 0);
    assert!(summary.diagnostics.is_empty());
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].name, "valid");
    assert_eq!(records[0].origin.ordinal, 0);
    assert_eq!(records[1].name, format!("malformed-{field}"));
    assert_eq!(records[1].origin.ordinal, 1);
    assert_eq!(records[1].domain.raw(), ".example.com");
    match field {
      "path" => assert_eq!(records[1].path, "/"),
      "secure" => assert!(matches!(
        records[1].attributes.secure,
        Observation::Unknown(_)
      )),
      "httponly" => assert!(matches!(
        records[1].attributes.http_only,
        Observation::Unknown(_)
      )),
      "sameSite" => assert!(matches!(
        records[1].attributes.same_site,
        Observation::Unknown(_)
      )),
      "expiry" => {
        assert!(matches!(
          records[1].attributes.expires,
          Observation::Unknown(_)
        ));
        assert!(matches!(
          records[1].attributes.raw_expires,
          Observation::Unknown(_)
        ));
      }
      "originAttributes" => {
        assert!(records[1].raw.contains_key("origin_attributes"));
        assert!(matches!(
          records[1].isolation.origin_attributes,
          Observation::Unknown(_)
        ));
      }
      _ => unreachable!("the session optional corpus is exhaustive"),
    }
    optional_records_emitted += 1;
  }
  assert_eq!(optional_records_emitted, 6);

  let mut required_rejections = 0;
  for field in ["name", "value"] {
    let mut changed = valid.clone();
    changed
      .as_object_mut()
      .expect("cookie fixture is an object")
      .insert(field.to_owned(), serde_json::json!({"not": "text"}));
    let envelope = serde_json::json!({"windows": [{"cookies": [valid.clone(), changed]}]});
    let (summary, records) = decode_session_gate_case(&envelope, format)?;
    assert_eq!(summary.rows_seen, 2);
    assert_eq!(summary.rows_skipped, 1);
    assert_eq!(summary.rows_rejected, 1);
    assert_eq!(summary.diagnostics.len(), 1);
    assert_eq!(records.len(), 1, "the valid sibling still reaches the sink");
    assert_eq!(records[0].name, "valid");
    required_rejections += summary.rows_rejected;
  }
  assert_eq!(required_rejections, 2);
  Ok(())
}

#[cfg(test)]
pub(super) fn structured_legacy_session_decoder_gate() -> Result<()> {
  structured_session_decoder_gate(SessionStoreFormat::LegacyJson)
}

#[cfg(test)]
pub(super) fn structured_jsonlz4_session_decoder_gate() -> Result<()> {
  structured_session_decoder_gate(SessionStoreFormat::JsonLz4)?;

  // These bounded decompression failures exercise header, advertised-size,
  // and truncated-block stages without allocation proportional to input.
  let malformed = [
    b"mozLz40\0".to_vec(),
    [b"mozLz40\0".as_slice(), &u32::MAX.to_le_bytes()].concat(),
    [b"mozLz40\0".as_slice(), &[32, 0, 0, 0], b"truncated"].concat(),
  ];
  let mut rejected = 0;
  for bytes in malformed {
    let source = MozillaSessionReadOnlySource {
      bytes: &bytes,
      format: SessionStoreFormat::JsonLz4,
      domains: None,
    };
    let decoder = MozillaSessionDecoder;
    let clock = SystemClock;
    let runtime = BoundaryRuntime::standard(&clock);
    let mut sink_calls = 0;
    let error = decoder
      .decode(
        &source,
        &mut |_| {
          sink_calls += 1;
          Ok(())
        },
        &runtime,
      )
      .expect_err("malformed mozLz4 input must be rejected before the sink");
    assert!(!error.to_string().is_empty());
    assert_eq!(sink_calls, 0);
    rejected += 1;
  }
  assert_eq!(rejected, 3);
  Ok(())
}

#[cfg(test)]
mod tests;
