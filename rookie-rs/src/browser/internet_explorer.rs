use crate::browser::internet_explorer_model::{
  decode_cookie_record, CookieColumnLayout, InternetExplorerFailure, InternetExplorerFailureStage,
  RawCookieRecord,
};
use crate::browser::report_core::{CookieSourceFormatId, CookieSourceRoleId};
use crate::browser::source::{Source, SourceAcquisition, SourceCandidate, SourceStats};
use crate::common::enums::Cookie;
use crate::common::{
  deadline::{BoundaryRuntime, BoundaryStop, SystemClock},
  diagnostic::REDACTED_PATH,
};
use crate::windows::restart_manager::FileLockStatus;
use anyhow::{bail, Context, Result};
use libesedb::{EseDb, Record, Table, Value};
use std::path::{Path, PathBuf};

/// Returns cookies from IE based browsers.
///
/// Deprecated for removal, not just for a newer call shape: its ESE-format
/// cookie database is read through an unmodified native C library with no
/// process isolation, and this crate is not planning to keep investing in
/// containing it. See [`crate::internet_explorer`] for the full rationale.
/// `direct_path::cookies_from_path` with `DirectPathRequest` remains
/// available for the rest of the deprecation window.
#[deprecated(
  since = "0.6.0",
  note = "Internet Explorer support is deprecated for removal; the Internet Explorer browser app was discontinued in 2022. Use direct_path::cookies_from_path with DirectPathRequest for the rest of the deprecation window"
)]
pub fn internet_explorer_based(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<Cookie>> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  internet_explorer_based_with_runtime(db_path, domains, force_kill, &runtime)
}

pub(crate) fn internet_explorer_based_with_runtime(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  let source = internet_explorer_outcome_with_runtime(
    direct_path_candidate(&db_path),
    domains,
    force_kill,
    runtime,
  )?;
  crate::browser::legacy::project_canonical_outcome_with_runtime(
    "internet_explorer",
    crate::browser::report_build::finalize_singleton_source(
      "internet_explorer",
      db_path.parent().unwrap_or(&db_path).to_path_buf(),
      vec![source],
      None,
      Some(runtime),
    )?,
    runtime,
  )
}

/// Record accounting while the WebCache walk is in progress.
///
/// File-private scratch: it is copied onto [`SourceStats`] before the walk
/// returns, so no caller ever sees this shape.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct InternetExplorerDraftStats {
  records_seen: usize,
  records_skipped: usize,
  records_rejected: usize,
}

#[derive(Debug)]
struct InternetExplorerDraft {
  records: Vec<crate::browser::cookie_record::CookieRecord>,
  stats: InternetExplorerDraftStats,
  row_error: Option<String>,
}

/// The candidate a direct-path Internet Explorer read is aimed at.
///
/// The values the direct-path report has always emitted for such a source. The
/// `EseDatabase` acquisition is the effective one: unlike Safari, IE's listing
/// candidates stay `NotAttempted` and the adapter overlays this only once a
/// WebCache query has been attempted.
pub(crate) fn direct_path_candidate(db_path: &Path) -> SourceCandidate {
  SourceCandidate {
    path: db_path.to_path_buf(),
    role: CookieSourceRoleId::persistent(),
    format: CookieSourceFormatId::known("internet_explorer_ese"),
    precedence: crate::browser::registry::PERSISTENT_SOURCE_PRECEDENCE,
    exists: true,
    selected: true,
    acquisition: SourceAcquisition::EseDatabase,
  }
}

/// Reads one WebCache database and returns it as a [`Source`].
///
/// `Err` still means no source came back at all; the adapter turns that into a
/// typed `Source.failure` using the stage tag `staged_failure` attached, which
/// this function must not flatten.
pub(crate) fn internet_explorer_outcome_with_runtime(
  origin: SourceCandidate,
  domains: Option<Vec<String>>,
  force_kill: bool,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Source> {
  let db_path = origin.path.clone();
  staged_failure(
    InternetExplorerFailureStage::Acquisition,
    runtime.check().map_err(anyhow::Error::from),
  )?;
  let db = staged_failure(
    InternetExplorerFailureStage::Acquisition,
    open_database(&db_path, force_kill, runtime),
  )?;
  staged_failure(
    InternetExplorerFailureStage::Acquisition,
    runtime.check().map_err(anyhow::Error::from),
  )?;
  let extraction = (|| -> Result<InternetExplorerDraft> {
    let mut canonical_records = Vec::new();
    let mut stats = InternetExplorerDraftStats::default();
    let mut row_error = None;

    let mut tables = db
      .iter_tables()
      .context("Unable to enumerate WebCache tables")?;
    while let Some(table) = next_with_runtime(&mut tables, runtime)? {
      let table = table.context("Unable to read a WebCache table")?;
      let table_name = table
        .name()
        .context("Unable to read a WebCache table name")?;

      if !table_name.starts_with("CookieEntry") {
        continue;
      }

      let columns = match cookie_column_layout(&table, runtime) {
        Ok(columns) => columns,
        Err(error) if error.downcast_ref::<BoundaryStop>().is_some() => return Err(error),
        Err(error) => {
          let error = error.context(format!("{table_name}: unsupported WebCache cookie schema"));
          let mut records = table.iter_records().with_context(|| {
            format!("{table_name}: unable to enumerate unsupported cookie table")
          })?;
          let mut record_count = 0_usize;
          while next_with_runtime(&mut records, runtime)?.is_some() {
            record_count += 1;
          }
          // Even an empty table is one failed extraction input when its schema
          // is unreadable. Counting that table-level failure keeps legacy and
          // report callers from mistaking an unsupported empty store for a
          // successful empty result.
          let skipped = unsupported_table_skipped_inputs(record_count);
          stats.records_seen += skipped;
          stats.records_skipped += skipped;
          stats.records_rejected += skipped;
          row_error = Some(format!("{error:#}"));
          log::warn!(
          "{table_name}: skipping unsupported cookie table containing {record_count} record(s); counted {skipped} skipped input(s): {error:#}"
        );
          continue;
        }
      };
      let mut records = table
        .iter_records()
        .with_context(|| format!("{table_name}: unable to enumerate cookie records"))?;
      let mut skipped_records = 0_usize;
      let mut record_index = 0_usize;

      while let Some(record) = next_with_runtime(&mut records, runtime)? {
        let cookie = record
          .map_err(anyhow::Error::from)
          .and_then(|record| read_cookie_record(&record, columns))
          .and_then(|record| decode_cookie_record(&record, domains.as_deref(), runtime));

        // Section 5.7 counts rows *relevant to the request*, so a record the
        // domain filter excluded was never seen for reporting purposes. A record
        // that failed before it could be tested still counts: it might have
        // matched.
        match cookie {
          Ok(Some(record)) => {
            stats.records_seen += 1;
            canonical_records.push(record);
          }
          Ok(None) => {}
          Err(error) => {
            // Cooperative boundary expiration is fatal for the source. It is
            // not a malformed row and must retain its typed cause through the
            // staged native failure wrapper below.
            if error.downcast_ref::<BoundaryStop>().is_some() {
              return Err(error);
            }
            stats.records_seen += 1;
            skipped_records += 1;
            stats.records_skipped += 1;
            stats.records_rejected += 1;
            row_error = Some(format!("{table_name}: record {record_index}: {error:#}"));
            log::warn!("{table_name}: skipping unreadable cookie record {record_index}: {error:#}");
          }
        }
        record_index += 1;
      }

      if skipped_records > 0 {
        log::warn!("{table_name}: skipped {skipped_records} unreadable cookie record(s)");
      }
    }

    runtime.check()?;
    Ok(InternetExplorerDraft {
      records: canonical_records,
      stats,
      row_error,
    })
  })();
  let draft = staged_failure(InternetExplorerFailureStage::Parse, extraction)?;
  let mut source = Source::from_candidate(origin);
  // Effective acquisition, not the candidate's. Listing freezes IE candidates
  // as `NotAttempted`; opening the WebCache database is what earns
  // `EseDatabase`, and only the engine knows the query was attempted.
  source.acquisition = SourceAcquisition::EseDatabase;
  source.stats = SourceStats {
    rows_seen: draft.stats.records_seen,
    cookies_emitted: draft.records.len(),
    rows_skipped: draft.stats.records_skipped,
    rows_rejected: draft.stats.records_rejected,
    provider_failures: 0,
  };
  source.records = draft.records;
  // The WebCache walk opens the database once; there is no stable-read retry
  // loop to report attempts from.
  source.acquisition_attempts = 1;
  // After the stats, never before: the issue is keyed on `rows_skipped`.
  source.push_row_read_failed(draft.row_error);
  Ok(source)
}

fn unsupported_table_skipped_inputs(record_count: usize) -> usize {
  record_count.max(1)
}

fn staged_failure<T>(stage: InternetExplorerFailureStage, result: Result<T>) -> Result<T> {
  result.map_err(|error| anyhow::Error::new(InternetExplorerFailure::new(stage, error)))
}

fn next_with_runtime<I>(iterator: &mut I, runtime: &BoundaryRuntime<'_>) -> Result<Option<I::Item>>
where
  I: Iterator,
{
  runtime.check()?;
  let item = iterator.next();
  runtime.check()?;
  Ok(item)
}

fn open_database(db_path: &Path, force_kill: bool, runtime: &BoundaryRuntime<'_>) -> Result<EseDb> {
  runtime.check()?;
  let lock_status = unsafe {
    // `force_kill` comes from the explicitly opted-in public extraction API.
    crate::windows::restart_manager::release_file_lock(db_path, force_kill, runtime)
  }
  .with_context(|| format!("Unable to inspect locks on WebCache database {REDACTED_PATH}"))?;
  runtime.check()?;
  let released_processes = require_unlocked_database(db_path, lock_status)?;

  runtime.check()?;
  let opened = match released_processes {
    Some(process_count) => {
      EseDb::open(db_path).with_context(|| {
        format!(
          "WebCache database {REDACTED_PATH} still cannot be opened after Restart Manager released {process_count} locking process(es)"
        )
      })
    }
    None => EseDb::open(db_path)
      .with_context(|| format!("Unable to open unlocked WebCache database {REDACTED_PATH}")),
  };
  runtime.check()?;
  opened
}

fn require_unlocked_database(_db_path: &Path, lock_status: FileLockStatus) -> Result<Option<u32>> {
  match lock_status {
    FileLockStatus::Unlocked => Ok(None),
    FileLockStatus::Released { process_count } => Ok(Some(process_count)),
    FileLockStatus::Locked { process_count } => bail!(
      "WebCache database {REDACTED_PATH} is locked by {process_count} process(es). Close Internet Explorer and applications using WinINet, then retry; destructive lock release requires force_kill=true"
    ),
  }
}

fn cookie_column_layout(
  table: &Table<'_>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<CookieColumnLayout> {
  runtime.check()?;
  let mut columns = table
    .iter_columns()
    .context("Unable to enumerate columns")?;
  let mut column_names = Vec::new();
  while let Some(column) = next_with_runtime(&mut columns, runtime)? {
    column_names.push(
      column
        .context("Unable to read column metadata")?
        .name()
        .context("Unable to read column name")?,
    );
  }

  CookieColumnLayout::resolve(&column_names)
}

fn read_cookie_record(record: &Record<'_>, columns: CookieColumnLayout) -> Result<RawCookieRecord> {
  Ok(RawCookieRecord {
    domain: text_value(record, columns.domain, "RDomain")?,
    path: text_value(record, columns.path, "Path")?,
    name: bytes_value(record, columns.name, "Name")?,
    value: crate::common::secret::SecretBytes::new(bytes_value(record, columns.value, "Value")?),
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
    value => bail!(
      "`{field}` has incompatible ESE value type {:?}",
      std::mem::discriminant(&value)
    ),
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
    value => bail!(
      "`{field}` has incompatible ESE value type {:?}",
      std::mem::discriminant(&value)
    ),
  }
}

fn unsigned_value(record: &Record<'_>, index: i32, field: &str) -> Result<u64> {
  let value = record_value(record, index, field)?;
  let value_type = std::mem::discriminant(&value);
  value
    .to_u64()
    .with_context(|| format!("`{field}` has incompatible ESE value type {value_type:?}"))
}

fn integer_value(record: &Record<'_>, index: i32, field: &str) -> Result<i64> {
  let value = record_value(record, index, field)?;
  let value_type = std::mem::discriminant(&value);
  value
    .to_i64()
    .with_context(|| format!("`{field}` has incompatible ESE value type {value_type:?}"))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::common::deadline::{test_clock::ManualClock, Deadline};
  use std::cell::Cell;

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
  fn unsupported_empty_table_counts_as_one_failed_input() {
    assert_eq!(unsupported_table_skipped_inputs(0), 1);
    assert_eq!(unsupported_table_skipped_inputs(4), 4);
  }

  #[test]
  fn expired_deadline_is_checked_before_advancing_a_native_iterator() {
    let clock = ManualClock::default();
    let deadline = Deadline::after(&clock, std::time::Duration::ZERO);
    let runtime = BoundaryRuntime::new(&clock, deadline);
    let calls = Cell::new(0_usize);
    let mut iterator = std::iter::from_fn(|| {
      calls.set(calls.get() + 1);
      Some(())
    });

    let error = next_with_runtime(&mut iterator, &runtime)
      .expect_err("iterator must not advance at the deadline");

    assert!(error
      .downcast_ref::<BoundaryStop>()
      .is_some_and(|stop| *stop == BoundaryStop::TimedOut));
    assert_eq!(calls.get(), 0);
  }

  #[test]
  fn iterator_result_observed_at_the_exact_deadline_is_rejected() {
    let clock = ManualClock::default();
    let deadline = Deadline::after(&clock, std::time::Duration::from_secs(1));
    let runtime = BoundaryRuntime::new(&clock, deadline);
    let calls = Cell::new(0_usize);
    let mut iterator = std::iter::from_fn(|| {
      calls.set(calls.get() + 1);
      clock.advance(std::time::Duration::from_secs(1));
      Some(())
    });

    let error = next_with_runtime(&mut iterator, &runtime)
      .expect_err("an exact iterator/deadline tie must time out");

    assert!(error
      .downcast_ref::<BoundaryStop>()
      .is_some_and(|stop| *stop == BoundaryStop::TimedOut));
    assert_eq!(calls.get(), 1);
  }

  #[test]
  fn cancellation_is_checked_before_advancing_a_native_iterator() {
    let clock = ManualClock::default();
    let stop = crate::common::deadline::CancellationToken::default();
    stop.cancel();
    let runtime = BoundaryRuntime::with_stop(
      &clock,
      Deadline::after(&clock, std::time::Duration::from_secs(1)),
      stop,
    );
    let calls = Cell::new(0_usize);
    let mut iterator = std::iter::from_fn(|| {
      calls.set(calls.get() + 1);
      Some(())
    });

    let error = next_with_runtime(&mut iterator, &runtime).expect_err("cancelled iterator");

    assert!(error
      .downcast_ref::<BoundaryStop>()
      .is_some_and(|stop| *stop == BoundaryStop::Cancelled));
    assert_eq!(calls.get(), 0);
  }

  #[test]
  fn resource_stop_observed_after_next_rejects_the_native_result() {
    let clock = ManualClock::default();
    let stop = crate::common::deadline::CancellationToken::default();
    let runtime = BoundaryRuntime::with_stop(
      &clock,
      Deadline::after(&clock, std::time::Duration::from_secs(1)),
      stop.clone(),
    );
    let calls = Cell::new(0_usize);
    let mut iterator = std::iter::from_fn(|| {
      calls.set(calls.get() + 1);
      stop.exhaust_resources();
      Some(())
    });

    let error = next_with_runtime(&mut iterator, &runtime).expect_err("resource stop");

    assert!(error
      .downcast_ref::<BoundaryStop>()
      .is_some_and(|stop| *stop == BoundaryStop::ResourceExhausted));
    assert_eq!(calls.get(), 1);
  }

  #[test]
  fn locked_database_error_is_specific_and_actionable() {
    let sensitive_path = r"C:\Users\rookie\WebCacheV01.dat";
    let error = require_unlocked_database(
      Path::new(sensitive_path),
      FileLockStatus::Locked { process_count: 2 },
    )
    .unwrap_err()
    .to_string();

    assert!(!error.contains(sensitive_path));
    assert!(error.contains(REDACTED_PATH));
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
