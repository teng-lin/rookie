use crate::browser::internet_explorer_model::{CookieColumnLayout, RawCookieRecord};
use crate::common::enums::Cookie;
use crate::windows::restart_manager::FileLockStatus;
use anyhow::{bail, Context, Result};
use libesedb::{EseDb, Record, Table, Value};
use std::path::{Path, PathBuf};

/// Returns cookies from IE based browsers.
pub fn internet_explorer_based(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<Cookie>> {
  internet_explorer_outcome(db_path, domains, force_kill).map(|outcome| outcome.cookies)
}

/// Record accounting for the private cross-engine report. The legacy
/// [`internet_explorer_based`] projection deliberately discards it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InternetExplorerExtractionStats {
  pub(crate) records_seen: usize,
  pub(crate) records_skipped: usize,
}

#[derive(Debug)]
pub(crate) struct InternetExplorerExtraction {
  pub(crate) cookies: Vec<Cookie>,
  pub(crate) stats: InternetExplorerExtractionStats,
}

pub(crate) fn internet_explorer_outcome(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<InternetExplorerExtraction> {
  let db = open_database(&db_path, force_kill)?;
  let mut cookies = Vec::new();
  let mut stats = InternetExplorerExtractionStats::default();

  for table in db
    .iter_tables()
    .context("Unable to enumerate WebCache tables")?
  {
    let table = table.context("Unable to read a WebCache table")?;
    let table_name = table
      .name()
      .context("Unable to read a WebCache table name")?;

    if !table_name.starts_with("CookieEntry") {
      continue;
    }

    let columns = cookie_column_layout(&table)
      .with_context(|| format!("{table_name}: unsupported WebCache cookie schema"))?;
    let records = table
      .iter_records()
      .with_context(|| format!("{table_name}: unable to enumerate cookie records"))?;
    let mut skipped_records = 0_usize;

    for (record_index, record) in records.enumerate() {
      let cookie = record
        .map_err(anyhow::Error::from)
        .and_then(|record| read_cookie_record(&record, columns))
        .and_then(|record| record.into_cookie(domains.as_deref()));

      // Section 5.7 counts rows *relevant to the request*, so a record the
      // domain filter excluded was never seen for reporting purposes. A record
      // that failed before it could be tested still counts: it might have
      // matched.
      match cookie {
        Ok(Some(cookie)) => {
          stats.records_seen += 1;
          cookies.push(cookie)
        }
        Ok(None) => {}
        Err(error) => {
          stats.records_seen += 1;
          skipped_records += 1;
          stats.records_skipped += 1;
          log::warn!("{table_name}: skipping unreadable cookie record {record_index}: {error:#}");
        }
      }
    }

    if skipped_records > 0 {
      log::warn!("{table_name}: skipped {skipped_records} unreadable cookie record(s)");
    }
  }

  Ok(InternetExplorerExtraction { cookies, stats })
}

fn open_database(db_path: &Path, force_kill: bool) -> Result<EseDb> {
  let display_path = db_path.display();
  let path = db_path
    .to_str()
    .with_context(|| format!("WebCache database path is not valid UTF-8: {display_path}"))?;

  let lock_status = unsafe {
    // `force_kill` comes from the explicitly opted-in public extraction API.
    crate::windows::restart_manager::release_file_lock(path, force_kill)
  }
  .with_context(|| format!("Unable to inspect locks on WebCache database {display_path}"))?;
  let released_processes = require_unlocked_database(db_path, lock_status)?;

  match released_processes {
    Some(process_count) => {
      EseDb::open(db_path).with_context(|| {
        format!(
          "WebCache database {display_path} still cannot be opened after Restart Manager released {process_count} locking process(es)"
        )
      })
    }
    None => EseDb::open(db_path)
      .with_context(|| format!("Unable to open unlocked WebCache database {display_path}")),
  }
}

fn require_unlocked_database(db_path: &Path, lock_status: FileLockStatus) -> Result<Option<u32>> {
  match lock_status {
    FileLockStatus::Unlocked => Ok(None),
    FileLockStatus::Released { process_count } => Ok(Some(process_count)),
    FileLockStatus::Locked { process_count } => bail!(
      "WebCache database {} is locked by {process_count} process(es). Close Internet Explorer and applications using WinINet, then retry; destructive lock release requires force_kill=true",
      db_path.display()
    ),
  }
}

fn cookie_column_layout(table: &Table<'_>) -> Result<CookieColumnLayout> {
  let column_names = table
    .iter_columns()
    .context("Unable to enumerate columns")?
    .map(|column| {
      column
        .context("Unable to read column metadata")?
        .name()
        .context("Unable to read column name")
    })
    .collect::<Result<Vec<_>>>()?;

  CookieColumnLayout::resolve(&column_names)
}

fn read_cookie_record(record: &Record<'_>, columns: CookieColumnLayout) -> Result<RawCookieRecord> {
  Ok(RawCookieRecord {
    domain: text_value(record, columns.domain, "RDomain")?,
    path: text_value(record, columns.path, "Path")?,
    name: bytes_value(record, columns.name, "Name")?,
    value: bytes_value(record, columns.value, "Value")?,
    expires: unsigned_value(record, columns.expires, "Expires")?,
    flags: integer_value(record, columns.flags, "Flags")?,
  })
}

fn record_value(record: &Record<'_>, index: i32, field: &str) -> Result<Value> {
  record
    .value(index)
    .with_context(|| format!("Unable to read `{field}`"))
}

fn text_value(record: &Record<'_>, index: i32, field: &str) -> Result<String> {
  match record_value(record, index, field)? {
    Value::Text(value) | Value::LargeText(value) => Ok(value),
    Value::Binary(value) | Value::LargeBinary(value) | Value::SuperLarge(value) => {
      String::from_utf8(value).with_context(|| format!("`{field}` is not valid UTF-8"))
    }
    Value::Long => record
      .long(index)
      .with_context(|| format!("Unable to open long `{field}` value"))?
      .utf8()
      .with_context(|| format!("Unable to decode long `{field}` value")),
    value => bail!("`{field}` has incompatible ESE value {value:?}"),
  }
}

fn bytes_value(record: &Record<'_>, index: i32, field: &str) -> Result<Vec<u8>> {
  match record_value(record, index, field)? {
    Value::Binary(value) | Value::LargeBinary(value) | Value::SuperLarge(value) => Ok(value),
    Value::Text(value) | Value::LargeText(value) => Ok(value.into_bytes()),
    Value::Long => record
      .long(index)
      .with_context(|| format!("Unable to open long `{field}` value"))?
      .vec()
      .with_context(|| format!("Unable to read long `{field}` value")),
    value => bail!("`{field}` has incompatible ESE value {value:?}"),
  }
}

fn unsigned_value(record: &Record<'_>, index: i32, field: &str) -> Result<u64> {
  let value = record_value(record, index, field)?;
  value
    .to_u64()
    .with_context(|| format!("`{field}` has incompatible ESE value {value:?}"))
}

fn integer_value(record: &Record<'_>, index: i32, field: &str) -> Result<i64> {
  let value = record_value(record, index, field)?;
  value
    .to_i64()
    .with_context(|| format!("`{field}` has incompatible ESE value {value:?}"))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn value_conversions_accept_known_webcache_representations() {
    assert_eq!(Value::DateTime(42).to_u64(), Some(42));
    assert_eq!(Value::I32(-1).to_i64(), Some(-1));
    assert_eq!(Value::U32(0x8000_0001).to_i64(), Some(0x8000_0001));
  }

  #[test]
  fn signed_flags_preserve_the_underlying_bit_pattern() {
    let flags = -1_i64 as u32;
    assert_eq!(flags, 0xffff_ffff);
  }

  #[test]
  fn locked_database_error_is_specific_and_actionable() {
    let error = require_unlocked_database(
      Path::new(r"C:\Users\rookie\WebCacheV01.dat"),
      FileLockStatus::Locked { process_count: 2 },
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains(r"C:\Users\rookie\WebCacheV01.dat"));
    assert!(error.contains("locked by 2 process(es)"));
    assert!(error.contains("Close Internet Explorer"));
    assert!(error.contains("force_kill=true"));
  }

  #[test]
  fn released_database_status_preserves_process_count_for_retry_context() {
    assert_eq!(
      require_unlocked_database(
        Path::new(r"C:\Users\rookie\WebCacheV01.dat"),
        FileLockStatus::Released { process_count: 3 },
      )
      .unwrap(),
      Some(3)
    );
  }
}
