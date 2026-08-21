//! Key-free Chromium SQLite row decoder.
//!
//! This module intentionally has no key-provider or cipher-implementation
//! dependencies. It classifies stored values and emits ciphertext-bearing
//! `CookieRecord`s for the later row-decryption stage.

use super::cookie_record::{
  Attributes, CipherTier, CookieRecord, CookieValue, Observation, RawValue,
};
use crate::common::{
  boundary::{Decoder, ReadOnlySource, RecordSink},
  deadline::{BoundaryRuntime, DeadlineEnforcement},
};
use crate::common::{date, enums::*, secret::SecretString, utils};
use anyhow::{anyhow, Context, Result};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EncryptedValuePolicy {
  UseKeyOutcomes,
  RejectMissingIdentity,
}

const MISSING_BROWSER_KEY_IDENTITY_MESSAGE: &str =
  "encrypted explicit-path Chromium profile has no browser key identity; \
   pass a canonical browser_id from supported_browsers()";

#[derive(Debug)]
pub(super) struct MissingBrowserKeyIdentity;

impl fmt::Display for MissingBrowserKeyIdentity {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(MISSING_BROWSER_KEY_IDENTITY_MESSAGE)
  }
}

impl std::error::Error for MissingBrowserKeyIdentity {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ChromiumDecodeIssueCode {
  ColumnRead(&'static str),
}

#[derive(Debug)]
pub(super) struct ChromiumRowFailure {
  pub(super) row_number: usize,
  pub(super) code: ChromiumDecodeIssueCode,
  pub(super) error: anyhow::Error,
}

#[derive(Debug)]
pub(super) struct DecodedChromiumRecord {
  pub(super) row_number: usize,
  pub(super) schema_version: u32,
  pub(super) record: CookieRecord,
  /// Detailed-only context errors are read while the SQLite row is alive but
  /// applied after value opening, matching the historical decrypt-before-context
  /// failure precedence.
  pub(super) pending_context_failure: Option<ChromiumRowFailure>,
}

#[derive(Debug)]
// Events are handed synchronously to the sink and never collected. Keeping
// the record inline avoids a heap allocation for every cookie row.
#[allow(clippy::large_enum_variant)]
pub(super) enum ChromiumDecodeEvent {
  RowFailure(ChromiumRowFailure),
  Record(DecodedChromiumRecord),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ChromiumDecodeSummary {
  pub(super) rows_seen: usize,
}

fn raw_sqlite_value(value: rusqlite::types::ValueRef<'_>) -> RawValue {
  match value {
    rusqlite::types::ValueRef::Null => RawValue::Null,
    rusqlite::types::ValueRef::Integer(value) => RawValue::Signed(value),
    rusqlite::types::ValueRef::Real(value) => RawValue::FloatBits(value.to_bits()),
    rusqlite::types::ValueRef::Text(value) => std::str::from_utf8(value)
      .map(RawValue::text)
      .unwrap_or_else(|_| RawValue::bytes(value.to_vec())),
    rusqlite::types::ValueRef::Blob(value) => RawValue::bytes(value.to_vec()),
  }
}

fn chromium_bool_observation(row: &rusqlite::Row<'_>, index: usize) -> Observation<bool> {
  match row.get_ref(index) {
    Ok(rusqlite::types::ValueRef::Null) | Err(_) => Observation::Missing,
    Ok(rusqlite::types::ValueRef::Integer(0)) => Observation::Known(false),
    Ok(rusqlite::types::ValueRef::Integer(1)) => Observation::Known(true),
    Ok(value) => Observation::Unknown(raw_sqlite_value(value)),
  }
}

type ChromiumContextFields = (
  CookieContext,
  Observation<bool>,
  Observation<bool>,
  Vec<(&'static str, RawValue)>,
);

fn chromium_cookie_context(row: &rusqlite::Row<'_>) -> ChromiumContextFields {
  let mut unknown = Vec::new();
  let text = |index, name, unknown: &mut Vec<_>| match row.get_ref(index) {
    Ok(rusqlite::types::ValueRef::Null) => None,
    Ok(rusqlite::types::ValueRef::Text(value)) => match std::str::from_utf8(value) {
      Ok(value) => Some(value.to_owned()),
      Err(_) => {
        unknown.push((name, RawValue::bytes(value.to_vec())));
        None
      }
    },
    Ok(value) => {
      unknown.push((name, raw_sqlite_value(value)));
      None
    }
    Err(_) => None,
  };
  let integer = |index, name, unknown: &mut Vec<_>| match row.get_ref(index) {
    Ok(rusqlite::types::ValueRef::Null) => None,
    Ok(rusqlite::types::ValueRef::Integer(value)) => Some(value),
    Ok(value) => {
      unknown.push((name, raw_sqlite_value(value)));
      None
    }
    Err(_) => None,
  };
  let has_cross_site_ancestor = chromium_bool_observation(row, 10);
  let is_persistent = chromium_bool_observation(row, 13);
  if let Observation::Unknown(raw) = &has_cross_site_ancestor {
    unknown.push(("has_cross_site_ancestor", raw.clone()));
  }
  if let Observation::Unknown(raw) = &is_persistent {
    unknown.push(("is_persistent", raw.clone()));
  }
  let known = |value: &Observation<bool>| match value {
    Observation::Known(value) => Some(*value),
    Observation::Missing | Observation::Unknown(_) => None,
  };
  (
    CookieContext {
      top_frame_site_key: text(9, "top_frame_site_key", &mut unknown),
      has_cross_site_ancestor: known(&has_cross_site_ancestor),
      source_scheme: integer(11, "source_scheme", &mut unknown),
      source_port: integer(12, "source_port", &mut unknown),
      is_persistent: known(&is_persistent),
      ..CookieContext::default()
    },
    has_cross_site_ancestor,
    is_persistent,
    unknown,
  )
}

pub(super) fn chromium_schema_version(connection: &rusqlite::Connection) -> Result<u32> {
  let version: String = connection
    .query_row(
      "SELECT CAST(value AS TEXT) FROM meta WHERE key = 'version'",
      [],
      |row| row.get(0),
    )
    .context("Can't read Chromium cookie database schema version from meta.version")?;
  version
    .parse()
    .with_context(|| format!("Invalid Chromium cookie database schema version {version:?}"))
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

pub(super) struct ChromiumCookieDecoder<'connection> {
  statement: rusqlite::Statement<'connection>,
  domains: Option<Vec<String>>,
  query_domain_filters: Vec<String>,
  encrypted_value_policy: EncryptedValuePolicy,
  schema_version: u32,
}

pub(super) struct ChromiumCookieCursor<'decoder> {
  rows: rusqlite::Rows<'decoder>,
  domains: Option<&'decoder [String]>,
  encrypted_value_policy: EncryptedValuePolicy,
  schema_version: u32,
  rows_seen: usize,
}

pub(super) struct ChromiumReadOnlySource<'a> {
  pub(super) connection: &'a rusqlite::Connection,
  pub(super) domains: Option<&'a [String]>,
}

impl ReadOnlySource for ChromiumReadOnlySource<'_> {}

pub(super) struct ChromiumBoundaryDecoder {
  pub(super) encrypted_value_policy: EncryptedValuePolicy,
}

impl<'source> Decoder<ChromiumReadOnlySource<'source>, ChromiumDecodeEvent>
  for ChromiumBoundaryDecoder
{
  type Summary = ChromiumDecodeSummary;

  fn decode(
    &self,
    source: &ChromiumReadOnlySource<'source>,
    sink: &mut dyn RecordSink<ChromiumDecodeEvent>,
    runtime: &BoundaryRuntime<'_>,
  ) -> Result<Self::Summary> {
    runtime.check()?;
    let mut decoder = prepare_cookie_decoder(
      source.connection,
      source.domains,
      self.encrypted_value_policy,
    )?;
    let mut cursor = decoder.cursor()?;
    while let Some(event) = {
      runtime.check()?;
      cursor.next_event()?
    } {
      sink.emit(event)?;
    }
    runtime.check()?;
    Ok(cursor.summary())
  }

  fn deadline_enforcement(&self) -> DeadlineEnforcement {
    // SQLite progress is checkpointed between rows. A VFS syscall may still
    // block inside SQLite, so this remains truthfully cooperative.
    DeadlineEnforcement::Cooperative
  }
}

pub(super) fn prepare_cookie_decoder<'connection>(
  connection: &'connection rusqlite::Connection,
  domains: Option<&[String]>,
  encrypted_value_policy: EncryptedValuePolicy,
) -> Result<ChromiumCookieDecoder<'connection>> {
  let schema_version = chromium_schema_version(connection)?;
  let columns = sqlite_table_columns(connection, "cookies")?;
  let optional_column = |name: &str| {
    if columns.contains(name) {
      name.to_string()
    } else {
      format!("NULL AS {name}")
    }
  };
  let encrypted_value = if columns.contains("encrypted_value") {
    "CAST(encrypted_value AS BLOB)".to_owned()
  } else {
    "NULL AS encrypted_value".to_owned()
  };
  let mut query = format!(
    "SELECT host_key, {}, {}, {}, name, value, \
     {encrypted_value}, {}, {}, {}, {}, {}, {}, {} FROM cookies ",
    optional_column("path"),
    optional_column("is_secure"),
    optional_column("expires_utc"),
    optional_column("is_httponly"),
    optional_column("samesite"),
    optional_column("top_frame_site_key"),
    optional_column("has_cross_site_ancestor"),
    optional_column("source_scheme"),
    optional_column("source_port"),
    optional_column("is_persistent"),
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

  let apply_sql_domain_filter = encrypted_value_policy == EncryptedValuePolicy::UseKeyOutcomes;
  if domains.is_some() && apply_sql_domain_filter {
    if domain_filters.is_empty() {
      query += "WHERE 0";
    } else {
      let predicates = (1..=domain_filters.len())
        .map(|index| format!("host_key LIKE ?{index} ESCAPE '\\'"))
        .collect::<Vec<_>>()
        .join(" OR ");
      query += &format!("WHERE ({predicates})");
    }
  }
  query += ";";

  Ok(ChromiumCookieDecoder {
    statement: connection.prepare(query.as_str())?,
    domains: domains.map(<[String]>::to_vec),
    query_domain_filters: if apply_sql_domain_filter {
      domain_filters
    } else {
      Vec::new()
    },
    encrypted_value_policy,
    schema_version,
  })
}

impl ChromiumCookieDecoder<'_> {
  pub(super) fn cursor(&mut self) -> Result<ChromiumCookieCursor<'_>> {
    let rows = self
      .statement
      .query(rusqlite::params_from_iter(self.query_domain_filters.iter()))?;
    Ok(ChromiumCookieCursor {
      rows,
      domains: self.domains.as_deref(),
      encrypted_value_policy: self.encrypted_value_policy,
      schema_version: self.schema_version,
      rows_seen: 0,
    })
  }
}

impl ChromiumCookieCursor<'_> {
  pub(super) fn summary(&self) -> ChromiumDecodeSummary {
    ChromiumDecodeSummary {
      rows_seen: self.rows_seen,
    }
  }

  /// Pulls exactly one relevant decoded row. The caller owns the returned
  /// event before SQLite advances again, so ciphertext can be opened and
  /// discarded synchronously without ever being collected by the decoder.
  pub(super) fn next_event(&mut self) -> Result<Option<ChromiumDecodeEvent>> {
    loop {
      let Some(row) = self.rows.next()? else {
        return Ok(None);
      };
      let plaintext_only_encrypted =
        if self.encrypted_value_policy == EncryptedValuePolicy::RejectMissingIdentity {
          let encrypted_value = row.get::<_, Option<Vec<u8>>>(6).map_err(|error| {
            anyhow!(
              "can't prove that explicit-path Chromium cookie row is plaintext: \
             failed to read encrypted_value: {error}"
            )
          })?;
          let encrypted_value = encrypted_value.unwrap_or_default();
          if !encrypted_value.is_empty() {
            return Err(MissingBrowserKeyIdentity.into());
          }
          Some(encrypted_value)
        } else {
          None
        };
      let host_key = match row.get::<_, Option<String>>(0) {
        Ok(host_key) => host_key.unwrap_or_default(),
        Err(error) => {
          self.rows_seen += 1;
          return Ok(Some(ChromiumDecodeEvent::RowFailure(ChromiumRowFailure {
            row_number: self.rows_seen,
            code: ChromiumDecodeIssueCode::ColumnRead("host_key"),
            error: anyhow!("failed to read host_key from Chromium cookie row: {error}"),
          })));
        }
      };
      if !utils::some_domain_in_host(self.domains, &host_key) {
        continue;
      }
      self.rows_seen += 1;
      let row_number = self.rows_seen;
      macro_rules! read_optional_column {
        ($index:expr, $type:ty, $name:literal) => {
          match row.get::<_, Option<$type>>($index) {
            Ok(value) => value,
            Err(error) => {
              return Ok(Some(ChromiumDecodeEvent::RowFailure(ChromiumRowFailure {
                row_number,
                code: ChromiumDecodeIssueCode::ColumnRead($name),
                error: anyhow!("failed to read {} from Chromium cookie row: {error}", $name),
              })));
            }
          }
        };
      }

      let path = read_optional_column!(1, String, "path").unwrap_or_else(|| "/".to_string());
      let observed_secure = chromium_bool_observation(row, 2);
      let is_secure = matches!(observed_secure, Observation::Known(true));
      let raw_expires = read_optional_column!(3, i64, "expires_utc");
      let expires = raw_expires
        .and_then(|value| u64::try_from(value).ok())
        .and_then(date::chromium_timestamp);
      let name: String = match row.get(4) {
        Ok(value) => value,
        Err(error) => {
          return Ok(Some(ChromiumDecodeEvent::RowFailure(ChromiumRowFailure {
            row_number,
            code: ChromiumDecodeIssueCode::ColumnRead("name"),
            error: anyhow!("failed to read name from row: {error}"),
          })));
        }
      };
      let encrypted_value =
        if self.encrypted_value_policy == EncryptedValuePolicy::RejectMissingIdentity {
          plaintext_only_encrypted.expect("plaintext-only mode captured encrypted_value")
        } else {
          read_optional_column!(6, Vec<u8>, "encrypted_value").unwrap_or_default()
        };
      // Preserve the historical plaintext-row column failure ordering: once
      // an empty encrypted_value establishes plaintext authority, read value
      // before any later metadata. Non-empty ciphertext still bypasses value.
      let value = if encrypted_value.is_empty() {
        let plaintext: String = match row.get(5) {
          Ok(value) => value,
          Err(error) => {
            return Ok(Some(ChromiumDecodeEvent::RowFailure(ChromiumRowFailure {
              row_number,
              code: ChromiumDecodeIssueCode::ColumnRead("value"),
              error: anyhow!("failed to read value from row: {error}"),
            })));
          }
        };
        CookieValue::Plain(SecretString::new(plaintext))
      } else {
        // Non-empty ciphertext is authoritative. The plaintext column is not
        // carried forward as a fallback, so later failures cannot expose it.
        CookieValue::Encrypted {
          tier: CipherTier::detect(&encrypted_value),
          bytes: encrypted_value,
        }
      };
      let observed_http_only = chromium_bool_observation(row, 7);
      let http_only = matches!(observed_http_only, Observation::Known(true));
      let observed_same_site = read_optional_column!(8, i64, "samesite");
      let same_site = observed_same_site.unwrap_or(SAME_SITE_UNSPECIFIED);
      let (context, has_cross_site_ancestor, is_persistent, raw_context) =
        chromium_cookie_context(row);

      let mut record = CookieRecord::from_legacy_fields(
        host_key, path, is_secure, expires, name, value, http_only, same_site, context, row_number,
      );
      record.attributes =
        Attributes::observed(None, raw_expires, expires, None, observed_same_site);
      record.attributes.secure = observed_secure;
      record.attributes.http_only = observed_http_only;
      record.isolation.has_cross_site_ancestor = has_cross_site_ancestor;
      record.isolation.is_persistent = is_persistent;
      let raw_secure = match &record.attributes.secure {
        Observation::Unknown(raw) => Some(raw.clone()),
        Observation::Missing | Observation::Known(_) => None,
      };
      let raw_http_only = match &record.attributes.http_only {
        Observation::Unknown(raw) => Some(raw.clone()),
        Observation::Missing | Observation::Known(_) => None,
      };
      if let Some(raw) = raw_secure {
        record.retain_raw("is_secure", raw);
      }
      if let Some(raw) = raw_http_only {
        record.retain_raw("is_httponly", raw);
      }
      for (name, value) in raw_context {
        record.retain_raw(name, value);
      }
      return Ok(Some(ChromiumDecodeEvent::Record(DecodedChromiumRecord {
        row_number,
        schema_version: self.schema_version,
        record,
        pending_context_failure: None,
      })));
    }
  }
}

#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn malformed_decoder_gate_case(bytes: &[u8]) -> Result<()> {
  let connection = rusqlite::Connection::open_in_memory()?;
  connection.execute_batch(
    "CREATE TABLE meta (key TEXT, value TEXT);
     INSERT INTO meta VALUES ('version', '23');
     CREATE TABLE cookies (
       host_key TEXT, path TEXT, is_secure, expires_utc INTEGER,
       name, value TEXT, encrypted_value BLOB, is_httponly,
       samesite
     );",
  )?;
  let mut numeric = [0_u8; 8];
  for (target, source) in numeric.iter_mut().zip(bytes.iter().copied()) {
    *target = source;
  }
  let sqlite_value = |salt: u8| match bytes.first().copied().unwrap_or(0).wrapping_add(salt) % 5 {
    0 => rusqlite::types::Value::Null,
    1 => rusqlite::types::Value::Integer(i64::from_le_bytes(numeric)),
    2 => rusqlite::types::Value::Real(f64::from_bits(u64::from_le_bytes(numeric))),
    3 => rusqlite::types::Value::Text(String::from_utf8_lossy(bytes).into_owned()),
    _ => rusqlite::types::Value::Blob(bytes.to_vec()),
  };
  connection.execute(
    "INSERT INTO cookies VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    rusqlite::params![
      sqlite_value(0),
      sqlite_value(1),
      sqlite_value(2),
      sqlite_value(3),
      sqlite_value(4),
      sqlite_value(5),
      bytes,
      sqlite_value(6),
      sqlite_value(7),
    ],
  )?;
  let source = ChromiumReadOnlySource {
    connection: &connection,
    domains: None,
  };
  let decoder = ChromiumBoundaryDecoder {
    encrypted_value_policy: EncryptedValuePolicy::UseKeyOutcomes,
  };
  let clock = crate::common::deadline::SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  let mut sink = |_event| Ok(());
  // This cross-engine gate promises only that malformed input completes
  // without unwinding. A decoder is free to reject the generated row.
  let _ = decoder.decode(&source, &mut sink, &runtime);
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  fn rust_identifiers(source: &str) -> std::collections::HashSet<&str> {
    source
      .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
      .filter(|identifier| !identifier.is_empty())
      .collect()
  }

  #[test]
  fn decoder_signature_is_key_free() {
    type DecoderSignature = for<'connection> fn(
      &'connection rusqlite::Connection,
      Option<&[String]>,
      EncryptedValuePolicy,
    ) -> Result<ChromiumCookieDecoder<'connection>>;
    let _: DecoderSignature = prepare_cookie_decoder;

    let source = include_str!("chromium_decoder.rs");
    let production_source = source
      .split_once("#[cfg(test)]\nmod tests")
      .map(|(production, _)| production)
      .expect("decoder source keeps tests in the final cfg(test) module");
    let production_identifiers = rust_identifiers(production_source);

    // Every Rust path must spell each module segment as an identifier. Checking
    // the production token stream therefore catches direct, absolute, grouped,
    // and aliased imports as well as qualified references elsewhere in code.
    for forbidden_module in ["chromium_crypto", "chromium_platform_keys", "unseal"] {
      assert!(
        !production_identifiers.contains(forbidden_module),
        "decoder depends on forbidden secret-bearing module {forbidden_module}"
      );
    }
    for (dependency_spelling, expected_identifier) in [
      ("use super::chromium_crypto as crypto;", "chromium_crypto"),
      (
        "use crate::browser::{chromium_platform_keys as providers};",
        "chromium_platform_keys",
      ),
      (
        "use crate::browser::unseal::unseal_chromium_record as open;",
        "unseal",
      ),
    ] {
      assert!(
        rust_identifiers(dependency_spelling).contains(expected_identifier),
        "boundary scanner missed aliased dependency {dependency_spelling}"
      );
    }

    for forbidden in [
      concat!("ChromiumKey", "Outcomes"),
      concat!("ChromiumKey", "Provider"),
      concat!("Key", "Candidate"),
      concat!("decrypt_keyed", "_candidate"),
      concat!("decrypt", "_legacy"),
    ] {
      assert!(
        !production_source.contains(forbidden),
        "key-bearing symbol {forbidden} crossed into the decoder module"
      );
    }
    for forbidden_callback_marker in ["FnMut", "FnOnce"] {
      assert!(
        !production_source.contains(forbidden_callback_marker),
        "decoder API admits an external callback through {forbidden_callback_marker}"
      );
    }
    assert!(
      production_source.contains("RecordSink"),
      "decoded records must cross only the bounded sink contract"
    );
  }

  #[test]
  fn cursor_is_pull_based_and_never_reads_ahead() {
    let connection = rusqlite::Connection::open_in_memory().expect("open fixture");
    connection
      .execute_batch(
        "CREATE TABLE meta (key TEXT, value TEXT);
         INSERT INTO meta VALUES ('version', '23');
         CREATE TABLE cookies (
           host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
           name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER,
           samesite INTEGER
         );
         INSERT INTO cookies VALUES
           ('.example.com', '/', 0, 0, 'first', 'first-value', X'', 0, 0),
           ('.example.com', '/', 0, 0, 'second', 'second-value', X'', 0, 0);",
      )
      .expect("seed rows");

    let mut decoder =
      prepare_cookie_decoder(&connection, None, EncryptedValuePolicy::UseKeyOutcomes)
        .expect("prepare decoder");
    let mut cursor = decoder.cursor().expect("start cursor");

    let first = cursor.next_event().expect("read first").expect("first row");
    assert_eq!(cursor.summary().rows_seen, 1);
    let ChromiumDecodeEvent::Record(first) = first else {
      panic!("first row is valid")
    };
    assert_eq!(first.record.name, "first");

    let second = cursor
      .next_event()
      .expect("read second")
      .expect("second row");
    assert_eq!(cursor.summary().rows_seen, 2);
    let ChromiumDecodeEvent::Record(second) = second else {
      panic!("second row is valid")
    };
    assert_eq!(second.record.name, "second");
    assert!(cursor.next_event().expect("exhaust cursor").is_none());
  }

  #[test]
  fn boolean_columns_preserve_invalid_raw_values_and_decoder_provenance() {
    let connection = rusqlite::Connection::open_in_memory().expect("open fixture");
    connection
      .execute_batch(
        "CREATE TABLE meta (key TEXT, value TEXT);
         INSERT INTO meta VALUES ('version', '23');
         CREATE TABLE cookies (
           host_key TEXT, path TEXT, is_secure, expires_utc INTEGER,
           name TEXT, value TEXT, encrypted_value BLOB, is_httponly,
           samesite INTEGER, top_frame_site_key TEXT,
           has_cross_site_ancestor, source_scheme INTEGER, source_port INTEGER,
           is_persistent
         );
         INSERT INTO cookies VALUES
           ('.example.test', '/', 0, 0, 'known', 'v', X'', 1, 0, '', 0, 0, 443, 1),
           ('.example.test', '/', 2, 0, 'integer', 'v', X'', -1, 0, '', 2, 0, 443, -1),
           ('.example.test', '/', 'true', 0, 'text', 'v', X'', 'false', 0, '', 'yes', 0, 443, 'no'),
           ('.example.test', '/', X'01', 0, 'blob', 'v', X'', X'00', 0, '', X'01', 0, 443, X'00'),
           ('.example.test', '/', 1, 0, 'context-text', 'v', X'', 0, 0, '', 'yes', 0, 443, 'no'),
           ('.example.test', '/', 1, 0, 'context-blob', 'v', X'', 0, 0, '', X'01', 0, 443, X'00'),
           ('.example.test', '/', 0.5, 0, 'real', 'v', X'', -0.5, 0, '', 1.5, 0, 443, -1.5);",
      )
      .expect("seed boolean variants");

    let mut decoder =
      prepare_cookie_decoder(&connection, None, EncryptedValuePolicy::UseKeyOutcomes)
        .expect("prepare decoder");
    let mut cursor = decoder.cursor().expect("start cursor");
    let mut records = Vec::new();
    let mut failures = Vec::new();
    while let Some(event) = cursor.next_event().expect("decode row") {
      match event {
        ChromiumDecodeEvent::Record(decoded) => records.push(decoded.record),
        ChromiumDecodeEvent::RowFailure(failure) => failures.push(failure.code),
      }
    }

    assert!(failures.is_empty());
    assert_eq!(records.len(), 7);
    assert_eq!(records[0].attributes.secure, Observation::Known(false));
    assert_eq!(records[0].attributes.http_only, Observation::Known(true));
    assert_eq!(
      records[0].isolation.has_cross_site_ancestor,
      Observation::Known(false)
    );
    assert_eq!(records[0].isolation.is_persistent, Observation::Known(true));

    assert_eq!(
      records[1].attributes.secure,
      Observation::Unknown(RawValue::Signed(2))
    );
    assert_eq!(
      records[1].attributes.http_only,
      Observation::Unknown(RawValue::Signed(-1))
    );
    assert_eq!(
      records[1].isolation.has_cross_site_ancestor,
      Observation::Unknown(RawValue::Signed(2))
    );
    assert_eq!(
      records[1].isolation.is_persistent,
      Observation::Unknown(RawValue::Signed(-1))
    );
    assert_eq!(
      records[1].isolation.has_cross_site_ancestor,
      Observation::Unknown(RawValue::Signed(2))
    );
    assert_eq!(
      records[1].isolation.is_persistent,
      Observation::Unknown(RawValue::Signed(-1))
    );
    assert_eq!(records[1].raw.get("is_secure"), Some(&RawValue::Signed(2)));
    assert_eq!(
      records[2].attributes.secure,
      Observation::Unknown(RawValue::text("true"))
    );
    assert_eq!(
      records[2].attributes.http_only,
      Observation::Unknown(RawValue::text("false"))
    );
    assert_eq!(
      records[2].raw.get("has_cross_site_ancestor"),
      Some(&RawValue::text("yes"))
    );
    assert_eq!(
      records[2].isolation.is_persistent,
      Observation::Unknown(RawValue::text("no"))
    );
    assert_eq!(
      records[3].attributes.secure,
      Observation::Unknown(RawValue::bytes(vec![1]))
    );
    assert_eq!(
      records[3].attributes.http_only,
      Observation::Unknown(RawValue::bytes(vec![0]))
    );
    assert_eq!(
      records[3].raw.get("has_cross_site_ancestor"),
      Some(&RawValue::bytes(vec![1]))
    );
    assert_eq!(
      records[3].isolation.is_persistent,
      Observation::Unknown(RawValue::bytes(vec![0]))
    );
    assert_eq!(
      records[6].attributes.secure,
      Observation::Unknown(RawValue::FloatBits(0.5_f64.to_bits()))
    );
    assert_eq!(
      records[6].isolation.has_cross_site_ancestor,
      Observation::Unknown(RawValue::FloatBits(1.5_f64.to_bits()))
    );
    assert_eq!(records[0].origin.ordinal, 1);
    assert_eq!(records[1].origin.ordinal, 2);
    assert_eq!(records[2].origin.ordinal, 3);
    assert_eq!(records[3].origin.ordinal, 4);
    assert_eq!(records[4].origin.ordinal, 5);
    assert_eq!(records[5].origin.ordinal, 6);
    assert_eq!(records[6].origin.ordinal, 7);
    assert_eq!(records[0].origin.source_digest, [0; 32]);
  }

  #[test]
  fn chromium_schema_version_is_read_strictly() {
    let missing = rusqlite::Connection::open_in_memory().expect("open missing-meta database");
    assert!(chromium_schema_version(&missing).is_err());

    let malformed = rusqlite::Connection::open_in_memory().expect("open malformed-meta database");
    malformed
      .execute("CREATE TABLE meta (key TEXT, value TEXT)", [])
      .expect("create metadata table");
    malformed
      .execute("INSERT INTO meta VALUES ('version', 'v24')", [])
      .expect("seed malformed version");
    let error = chromium_schema_version(&malformed).expect_err("malformed version must fail");
    assert!(error.to_string().contains("Invalid Chromium"));
  }
}
