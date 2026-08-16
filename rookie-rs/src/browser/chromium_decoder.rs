//! Key-free Chromium SQLite row decoder.
//!
//! This module intentionally has no key-provider or cipher-implementation
//! dependencies. It classifies stored values and emits ciphertext-bearing
//! `CookieRecord`s for the later row-decryption stage.

use super::chromium::{
  ChromiumDecodeEvent, ChromiumEngineExtractionOutcome, ChromiumRowFailure, ChromiumRowIssueCode,
  CookieProjection, DecodedChromiumRecord, EncryptedValuePolicy, MissingBrowserKeyIdentity,
};
use super::cookie_record::{CipherTier, CookieRecord, CookieValue};
use crate::common::{date, enums::*, utils};
use anyhow::{anyhow, Context, Result};
use std::fmt;

#[derive(Debug)]
pub(super) struct ChromiumContextColumnError {
  pub(super) column: &'static str,
  source: rusqlite::Error,
}

impl fmt::Display for ChromiumContextColumnError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      formatter,
      "failed to read {} from Chromium cookie row: {}",
      self.column, self.source
    )
  }
}

impl std::error::Error for ChromiumContextColumnError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.source)
  }
}

fn chromium_cookie_context(
  row: &rusqlite::Row<'_>,
) -> std::result::Result<CookieContext, ChromiumContextColumnError> {
  let read = |column, source| ChromiumContextColumnError { column, source };
  Ok(CookieContext {
    top_frame_site_key: row
      .get::<_, Option<String>>(9)
      .map_err(|error| read("top_frame_site_key", error))?,
    has_cross_site_ancestor: row
      .get::<_, Option<i64>>(10)
      .map_err(|error| read("has_cross_site_ancestor", error))?
      .map(|value| value != 0),
    source_scheme: row
      .get::<_, Option<i64>>(11)
      .map_err(|error| read("source_scheme", error))?,
    source_port: row
      .get::<_, Option<i64>>(12)
      .map_err(|error| read("source_port", error))?,
    is_persistent: row
      .get::<_, Option<i64>>(13)
      .map_err(|error| read("is_persistent", error))?
      .map(|value| value != 0),
    ..CookieContext::default()
  })
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

fn escape_like_pattern(input: &str) -> String {
  input
    .replace('\\', "\\\\")
    .replace('%', "\\%")
    .replace('_', "\\_")
}

pub(super) fn decode_cookie_records(
  connection: &rusqlite::Connection,
  domains: Option<&[String]>,
  projection: CookieProjection,
  encrypted_value_policy: EncryptedValuePolicy,
) -> Result<ChromiumEngineExtractionOutcome> {
  let schema_version = chromium_schema_version(connection)?;
  let columns = sqlite_table_columns(connection, "cookies")?;
  let optional_column = |name: &str| {
    if columns.contains(name) {
      name.to_string()
    } else {
      format!("NULL AS {name}")
    }
  };
  let mut query = format!(
    "SELECT host_key, path, is_secure, expires_utc, name, value, \
     CAST(encrypted_value AS BLOB), is_httponly, samesite, {}, {}, {}, {}, {} FROM cookies ",
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
        .map(|domain| format!("%{}%", escape_like_pattern(domain)))
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

  let mut extraction = ChromiumEngineExtractionOutcome::default();
  extraction.schema_version = schema_version;
  let mut stmt = connection.prepare(query.as_str())?;
  let query_domain_filters = if apply_sql_domain_filter {
    domain_filters.as_slice()
  } else {
    &[]
  };
  let mut rows = stmt.query(rusqlite::params_from_iter(query_domain_filters.iter()))?;

  while let Some(row) = rows.next()? {
    let plaintext_only_encrypted =
      if encrypted_value_policy == EncryptedValuePolicy::RejectMissingIdentity {
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
        extraction.stats.rows_seen += 1;
        let row_number = extraction.stats.rows_seen;
        extraction
          .decoded_events
          .push(ChromiumDecodeEvent::RowFailure(ChromiumRowFailure {
            row_number,
            code: ChromiumRowIssueCode::ColumnRead("host_key"),
            error: anyhow!("failed to read host_key from Chromium cookie row: {error}"),
          }));
        continue;
      }
    };
    if !utils::some_domain_in_host(domains, &host_key) {
      continue;
    }
    extraction.stats.rows_seen += 1;
    let row_number = extraction.stats.rows_seen;
    macro_rules! read_optional_column {
      ($index:expr, $type:ty, $name:literal) => {
        match row.get::<_, Option<$type>>($index) {
          Ok(value) => value,
          Err(error) => {
            extraction
              .decoded_events
              .push(ChromiumDecodeEvent::RowFailure(ChromiumRowFailure {
                row_number,
                code: ChromiumRowIssueCode::ColumnRead($name),
                error: anyhow!("failed to read {} from Chromium cookie row: {error}", $name),
              }));
            continue;
          }
        }
      };
    }

    let path = read_optional_column!(1, String, "path").unwrap_or_else(|| "/".to_string());
    let is_secure = read_optional_column!(2, bool, "is_secure").unwrap_or(false);
    let expires = read_optional_column!(3, i64, "expires_utc")
      .and_then(|value| u64::try_from(value).ok())
      .and_then(date::chromium_timestamp);
    let name: String = match row.get(4) {
      Ok(value) => value,
      Err(error) => {
        extraction
          .decoded_events
          .push(ChromiumDecodeEvent::RowFailure(ChromiumRowFailure {
            row_number,
            code: ChromiumRowIssueCode::ColumnRead("name"),
            error: anyhow!("failed to read name from row: {error}"),
          }));
        continue;
      }
    };
    let plaintext: String = match row.get(5) {
      Ok(value) => value,
      Err(error) => {
        extraction
          .decoded_events
          .push(ChromiumDecodeEvent::RowFailure(ChromiumRowFailure {
            row_number,
            code: ChromiumRowIssueCode::ColumnRead("value"),
            error: anyhow!("failed to read value from row: {error}"),
          }));
        continue;
      }
    };
    let encrypted_value = if encrypted_value_policy == EncryptedValuePolicy::RejectMissingIdentity {
      plaintext_only_encrypted.expect("plaintext-only mode captured encrypted_value")
    } else {
      read_optional_column!(6, Vec<u8>, "encrypted_value").unwrap_or_default()
    };
    let http_only = read_optional_column!(7, bool, "is_httponly").unwrap_or(false);
    let same_site = read_optional_column!(8, i64, "samesite").unwrap_or(SAME_SITE_UNSPECIFIED);
    let (context, pending_context_failure) = if projection == CookieProjection::Detailed {
      match chromium_cookie_context(row) {
        Ok(context) => (context, None),
        Err(error) => {
          let column = error.column;
          (
            CookieContext::default(),
            Some(ChromiumRowFailure {
              row_number,
              code: ChromiumRowIssueCode::ColumnRead(column),
              error: error.into(),
            }),
          )
        }
      }
    } else {
      (CookieContext::default(), None)
    };
    let value = if encrypted_value.is_empty() {
      CookieValue::Plain(plaintext)
    } else {
      // Non-empty ciphertext is authoritative. The plaintext column is not
      // carried forward as a fallback, so later failures cannot expose it.
      CookieValue::Encrypted {
        tier: CipherTier::detect(&encrypted_value),
        bytes: encrypted_value,
      }
    };
    extraction
      .decoded_events
      .push(ChromiumDecodeEvent::Record(Box::new(
        DecodedChromiumRecord {
          row_number,
          record: CookieRecord {
            domain: host_key,
            path,
            secure: is_secure,
            expires,
            name,
            value,
            http_only,
            same_site,
            context,
          },
          pending_context_failure,
        },
      )));
  }

  Ok(extraction)
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
    type DecoderSignature = fn(
      &rusqlite::Connection,
      Option<&[String]>,
      CookieProjection,
      EncryptedValuePolicy,
    ) -> Result<ChromiumEngineExtractionOutcome>;
    let _: DecoderSignature = decode_cookie_records;

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
  }
}
