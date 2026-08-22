//! Mozilla persistent cookie store: the `cookies.sqlite` decoder.
//!
//! Split out of `mozilla.rs` as the Chromium `chromium_decoder.rs` analog.
//! This half references nothing from the session-store stack; the two decoders
//! meet only at the walk in `mozilla.rs`, which owns their shared
//! `firefox_cookie_context` originAttributes parser.

#[cfg(test)]
use crate::common::deadline::{Clock, Deadline, SystemClock};
use crate::common::{
  boundary::{Decoder, ReadOnlySource, RecordSink},
  date,
  deadline::{BoundaryRuntime, DeadlineEnforcement},
  enums::*,
  secret::SecretString,
  utils,
};
use anyhow::{anyhow, Result};

use super::cookie_record::{
  Attributes, CookieRecord, CookieValue, Observation, RawValue, SourceRef,
};
use super::mozilla::{firefox_cookie_context, FIREFOX_MILLISECOND_EXPIRY_SCHEMA_VERSION};

// Firefox writes this sentinel when no SameSite attribute was present. It is
// not an additional public SameSite mode; compatibility output must use the
// cross-engine unspecified sentinel instead of leaking the storage bit.
const FIREFOX_SAME_SITE_UNSPECIFIED: i64 = 256;

pub(crate) struct PersistentCookieQuery {
  pub(crate) records: Vec<CookieRecord>,
  pub(crate) rows_seen: usize,
  pub(crate) rows_skipped: usize,
  pub(crate) rows_rejected: usize,
  pub(crate) last_row_error: Option<anyhow::Error>,
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

pub(crate) fn mozilla_schema_version(connection: &rusqlite::Connection) -> Result<u32> {
  let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
  u32::try_from(version).map_err(|_| anyhow!("Invalid Firefox cookie schema version {version}"))
}

pub(crate) fn persistent_cookie_expiry(timestamp: u64, schema_version: u32) -> Option<u64> {
  let timestamp = if schema_version >= FIREFOX_MILLISECOND_EXPIRY_SCHEMA_VERSION {
    timestamp / 1000
  } else {
    timestamp
  };
  date::mozilla_timestamp(timestamp)
}

#[cfg(test)]
pub(crate) fn query_persistent_cookies(
  connection: &rusqlite::Connection,
  domains: Option<&[String]>,
) -> Result<PersistentCookieQuery> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  query_persistent_cookies_with_runtime(connection, domains, &runtime)
}

#[cfg(test)]
pub(crate) fn query_persistent_cookies_mode(
  connection: &rusqlite::Connection,
  domains: Option<&[String]>,
  _detailed: bool,
  clock: &dyn Clock,
  deadline: Deadline,
) -> Result<PersistentCookieQuery> {
  let runtime = BoundaryRuntime::new(clock, deadline);
  query_persistent_cookies_with_runtime(connection, domains, &runtime)
}

pub(crate) fn query_persistent_cookies_with_runtime(
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

pub(crate) fn decode_persistent_cookies(
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
    let observed_same_site = match optional_firefox_same_site(row, 7) {
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

fn optional_firefox_same_site(row: &rusqlite::Row<'_>, index: usize) -> Result<Observation<i64>> {
  Ok(match row.get_ref(index)? {
    rusqlite::types::ValueRef::Null => Observation::Missing,
    rusqlite::types::ValueRef::Integer(FIREFOX_SAME_SITE_UNSPECIFIED) => {
      Observation::Known(SAME_SITE_UNSPECIFIED)
    }
    rusqlite::types::ValueRef::Integer(value) if (-1..=2).contains(&value) => {
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
