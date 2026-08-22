use super::*;
use crate::common::deadline::{test_clock::ManualClock, BoundaryStop, CancellationToken};
use std::cell::{Cell, RefCell};
use std::ffi::CStr;
use std::time::Duration;

fn compare_files(left: &Path, right: &Path) -> Result<bool> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  files_are_identical(left, right, &runtime)
}

struct StopAfterFirstRead<'a> {
  clock: &'a ManualClock,
  token: CancellationToken,
  stop: BoundaryStop,
  reads: Cell<usize>,
}

impl io::Read for StopAfterFirstRead<'_> {
  fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
    self.reads.set(self.reads.get() + 1);
    output[..4].copy_from_slice(b"data");
    match self.stop {
      BoundaryStop::TimedOut => self.clock.advance(Duration::from_secs(1)),
      BoundaryStop::Cancelled => {
        assert!(self.token.cancel());
      }
      BoundaryStop::ResourceExhausted => {
        assert!(self.token.exhaust_resources());
      }
    }
    Ok(4)
  }
}

#[test]
fn mid_copy_timeout_cancellation_and_resource_exhaustion_stay_typed() {
  for stop in [
    BoundaryStop::TimedOut,
    BoundaryStop::Cancelled,
    BoundaryStop::ResourceExhausted,
  ] {
    let clock = ManualClock::default();
    let token = CancellationToken::default();
    let runtime = BoundaryRuntime::with_stop(
      &clock,
      Deadline::after(&clock, Duration::from_secs(1)),
      token.clone(),
    );
    let mut source = StopAfterFirstRead {
      clock: &clock,
      token,
      stop,
      reads: Cell::new(0),
    };
    let mut destination = Vec::new();
    let error = copy_stream_with_runtime(&mut source, &mut destination, &runtime)
      .expect_err("the terminal stop is observed before the copied chunk is published");
    assert_eq!(
      error.downcast_ref::<BoundaryStop>(),
      Some(&stop),
      "{error:#}"
    );
    assert_eq!(source.reads.get(), 1);
    assert!(destination.is_empty());
  }
}

#[test]
fn query_retries_share_one_decreasing_budget_without_wall_clock_sleep() {
  let clock = ManualClock::default();
  let deadline = Deadline::after(&clock, Duration::from_secs(10));
  let runtime = BoundaryRuntime::new(&clock, deadline);
  let attempts = Cell::new(0_u32);
  let observed = RefCell::new(Vec::new());

  let error = with_browser_database_using_runtime(
    || {
      attempts.set(attempts.get() + 1);
      observed.borrow_mut().push(deadline.remaining(&clock));
      let elapsed = if attempts.get() == 1 { 7 } else { 3 };
      clock.advance(Duration::from_secs(elapsed));
      Err(DatabaseAcquisitionFailure {
        strategy: Some(DatabaseAcquisitionStrategy::VerifiedWalSnapshot),
        error: sqlite_failure(rusqlite::ffi::SQLITE_CORRUPT),
      })
    },
    |_| Ok(()),
    &runtime,
  )
  .expect_err("the second attempt consumes the remaining budget");

  assert_eq!(
    error.downcast_ref::<crate::common::deadline::BoundaryStop>(),
    Some(&crate::common::deadline::BoundaryStop::TimedOut)
  );
  assert_eq!(
    *observed.borrow(),
    [Duration::from_secs(10), Duration::from_secs(3)]
  );
  assert_eq!(attempts.get(), 2, "an expired third attempt must not start");
  assert_eq!(deadline.remaining(&clock), Duration::ZERO);
}

#[test]
fn bundled_sqlite_matches_the_security_inventory() {
  assert_eq!(rusqlite::version(), "3.53.2");
  assert_eq!(rusqlite::version_number(), 3_053_002);
  // SAFETY: `sqlite3_sourceid()` returns a static, null-terminated C string embedded in the SQLite library.
  let source_id = unsafe { CStr::from_ptr(rusqlite::ffi::sqlite3_sourceid()) }
    .to_str()
    .expect("SQLite source ID is UTF-8");
  assert_eq!(
    source_id,
    "2026-06-03 19:12:13 d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24"
  );
}

fn rollback_database(directory: &Path) -> (PathBuf, Connection) {
  let path = directory.join("cookies.sqlite");
  let writer = Connection::open(&path).expect("open rollback-journal database");
  let mode: String = writer
    .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
    .expect("enable rollback journal");
  assert_eq!(mode, "delete");
  writer
    .execute("CREATE TABLE cookies (name TEXT NOT NULL)", [])
    .expect("create table");
  writer
    .execute("INSERT INTO cookies (name) VALUES ('before')", [])
    .expect("insert initial row");
  (path, writer)
}

fn is_busy_or_locked(error: &rusqlite::Error) -> bool {
  matches!(
    error,
    rusqlite::Error::SqliteFailure(
      rusqlite::ffi::Error {
        code: rusqlite::ffi::ErrorCode::DatabaseBusy | rusqlite::ffi::ErrorCode::DatabaseLocked,
        ..
      },
      _
    )
  )
}

fn assert_anyhow_busy_or_locked(error: &anyhow::Error) {
  let sqlite_error = error
    .chain()
    .find_map(|cause| cause.downcast_ref::<rusqlite::Error>());
  assert!(
    sqlite_error.is_some_and(is_busy_or_locked),
    "expected typed SQLITE_BUSY/SQLITE_LOCKED, got {error:#}"
  );
}

/// Uses the production live-open sequence with a zero busy timeout so an
/// exclusive-lock fixture is deterministic and does not wait rusqlite's
/// default five seconds.
fn open_live_without_wait(path: &Path) -> Result<Connection> {
  let connection = open_read_only(path, "mode=ro")?;
  connection.busy_timeout(std::time::Duration::ZERO)?;
  pin_read_snapshot(&connection, path)?;
  Ok(connection)
}

fn sqlite_failure(result_code: i32) -> anyhow::Error {
  anyhow::Error::new(rusqlite::Error::SqliteFailure(
    rusqlite::ffi::Error::new(result_code),
    None,
  ))
}

fn test_reader(strategy: DatabaseAcquisitionStrategy) -> SqliteReader {
  SqliteReader {
    connection: Connection::open_in_memory().expect("open in-memory reader"),
    snapshot: (strategy != DatabaseAcquisitionStrategy::LiveReadOnly)
      .then(|| TempDir::new().expect("snapshot dir")),
    strategy,
  }
}

fn copied_snapshot_reader(name: &str) -> SqliteReader {
  let snapshot = TempDir::new().expect("snapshot dir");
  let path = snapshot.path().join("Cookies");
  let writer = Connection::open(&path).expect("open copied database");
  writer
    .execute("CREATE TABLE cookies (name TEXT NOT NULL)", [])
    .expect("create copied table");
  writer
    .execute("INSERT INTO cookies (name) VALUES (?1)", [name])
    .expect("insert copied row");
  drop(writer);
  SqliteReader {
    connection: open_read_only(&path, "mode=ro").expect("open copied snapshot"),
    snapshot: Some(snapshot),
    strategy: DatabaseAcquisitionStrategy::VerifiedWalSnapshot,
  }
}

fn corrupt_copied_snapshot_reader() -> SqliteReader {
  let snapshot = TempDir::new().expect("snapshot dir");
  let path = snapshot.path().join("Cookies");
  fs::write(&path, b"deterministically not a SQLite database")
    .expect("write corrupt copied database");
  SqliteReader {
    // SQLite opens lazily; the first schema/query read classifies NOTADB.
    connection: open_read_only(&path, "mode=ro").expect("open corrupt snapshot file"),
    snapshot: Some(snapshot),
    strategy: DatabaseAcquisitionStrategy::VerifiedWalSnapshot,
  }
}

/// Creates a WAL-mode database holding one checkpointed row.
fn checkpointed_database(directory: &Path) -> (PathBuf, Connection) {
  let path = directory.join("Cookies");
  let writer = Connection::open(&path).expect("open writable sqlite");

  let mode: String = writer
    .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
    .expect("enable WAL");
  assert_eq!(mode, "wal");

  writer
    .execute("CREATE TABLE cookies (name TEXT NOT NULL)", [])
    .expect("create table");
  writer
    .execute("INSERT INTO cookies (name) VALUES ('checkpointed')", [])
    .expect("insert checkpointed row");
  writer
    .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
    .expect("checkpoint");

  (path, writer)
}

fn cookie_names(reader: &SqliteReader) -> Vec<String> {
  let mut statement = reader
    .prepare("SELECT name FROM cookies ORDER BY name")
    .expect("prepare");
  statement
    .query_map([], |row| row.get::<_, String>(0))
    .expect("query")
    .collect::<rusqlite::Result<Vec<String>>>()
    .expect("collect")
}

#[test]
fn copied_snapshot_query_incoherence_reacquires_the_whole_query() {
  let acquisitions = Cell::new(0);
  let queries = Cell::new(0);
  let snapshot_paths = RefCell::new(Vec::<PathBuf>::new());

  let outcome = with_browser_database_using(
    || {
      let call = acquisitions.get() + 1;
      acquisitions.set(call);
      if let Some(previous) = snapshot_paths.borrow().last() {
        assert!(
          !previous.exists(),
          "the failed reader must be dropped before reacquisition"
        );
      }
      let reader = if call == 1 {
        corrupt_copied_snapshot_reader()
      } else {
        copied_snapshot_reader("fresh")
      };
      snapshot_paths
        .borrow_mut()
        .push(reader.snapshot_path().expect("snapshot path").to_path_buf());
      Ok(reader)
    },
    |connection| {
      queries.set(queries.get() + 1);
      connection
        .query_row("SELECT name FROM cookies", [], |row| {
          row.get::<_, String>(0)
        })
        .map_err(anyhow::Error::new)
    },
  )
  .expect("second copied snapshot is coherent");

  assert_eq!(
    outcome.strategy(),
    DatabaseAcquisitionStrategy::VerifiedWalSnapshot
  );
  assert_eq!(outcome.attempts(), 2);
  assert_eq!(outcome.into_value(), "fresh");
  assert_eq!(acquisitions.get(), 2);
  assert_eq!(queries.get(), 2, "the complete query must rerun");
  assert!(
    snapshot_paths.borrow().iter().all(|path| !path.exists()),
    "successful and failed attempt snapshots must be cleaned up"
  );
}

#[test]
fn snapshot_open_incoherence_is_reacquired_before_querying() {
  let acquisitions = Cell::new(0);
  let queries = Cell::new(0);
  let outcome = with_browser_database_using(
    || {
      let call = acquisitions.get() + 1;
      acquisitions.set(call);
      if call == 1 {
        Err(DatabaseAcquisitionFailure {
          strategy: Some(DatabaseAcquisitionStrategy::VerifiedWalSnapshot),
          error: sqlite_failure(rusqlite::ffi::SQLITE_NOTADB),
        })
      } else {
        Ok(test_reader(
          DatabaseAcquisitionStrategy::VerifiedWalSnapshot,
        ))
      }
    },
    |_| {
      queries.set(queries.get() + 1);
      Ok("queried")
    },
  )
  .expect("second acquisition succeeds");

  assert_eq!(outcome.attempts(), 2);
  assert_eq!(outcome.into_value(), "queried");
  assert_eq!(acquisitions.get(), 2);
  assert_eq!(queries.get(), 1, "failed open must not invoke the query");
}

#[test]
fn selected_snapshot_read_io_errors_are_retryable() {
  for result_code in [
    rusqlite::ffi::SQLITE_IOERR_READ,
    rusqlite::ffi::SQLITE_IOERR_SHORT_READ,
  ] {
    let queries = Cell::new(0);
    let outcome = with_browser_database_using(
      || {
        Ok(test_reader(
          DatabaseAcquisitionStrategy::VerifiedWalSnapshot,
        ))
      },
      |_| {
        let call = queries.get() + 1;
        queries.set(call);
        if call == 1 {
          Err(sqlite_failure(result_code))
        } else {
          Ok(call)
        }
      },
    )
    .expect("selected snapshot IO error retries");
    assert_eq!(outcome.attempts(), 2);
    assert_eq!(outcome.into_value(), 2);
  }
}

#[test]
fn retry_exhaustion_is_typed_and_never_returns_stale_data() {
  let acquisitions = Cell::new(0);
  let queries = Cell::new(0);
  let snapshot_paths = RefCell::new(Vec::<PathBuf>::new());
  let error = with_browser_database_using(
    || {
      acquisitions.set(acquisitions.get() + 1);
      let reader = copied_snapshot_reader("stale");
      snapshot_paths
        .borrow_mut()
        .push(reader.snapshot_path().expect("snapshot path").to_path_buf());
      Ok(reader)
    },
    |_| -> Result<String> {
      queries.set(queries.get() + 1);
      Err(sqlite_failure(rusqlite::ffi::SQLITE_CORRUPT))
    },
  )
  .expect_err("bounded retry must exhaust");

  let failure = error
    .downcast_ref::<BrowserDatabaseFailure>()
    .expect("typed browser database failure context");
  assert_eq!(failure.kind, BrowserDatabaseFailureKind::RetryExhausted);
  assert_eq!(
    failure.strategy,
    Some(DatabaseAcquisitionStrategy::VerifiedWalSnapshot)
  );
  assert_eq!(failure.attempts, BROWSER_DATABASE_ATTEMPTS);
  assert_eq!(acquisitions.get(), BROWSER_DATABASE_ATTEMPTS);
  assert_eq!(queries.get(), BROWSER_DATABASE_ATTEMPTS);
  assert!(
    snapshot_paths.borrow().iter().all(|path| !path.exists()),
    "every exhausted attempt must be cleaned up before returning"
  );
  assert!(
    error.downcast_ref::<rusqlite::Error>().is_some(),
    "last typed SQLite failure must remain in the error chain"
  );
}

#[test]
fn schema_sql_decode_and_provider_failures_are_not_retried() {
  type TestQuery = dyn Fn(&Connection) -> Result<()>;
  let cases: Vec<(&str, Box<TestQuery>)> = vec![
    (
      "schema/sql",
      Box::new(|connection| {
        connection.prepare("SELECT * FROM deliberately_absent_table")?;
        Ok(())
      }),
    ),
    (
      "decode",
      Box::new(|_| Err(anyhow!("synthetic decode failure"))),
    ),
    (
      "provider",
      Box::new(|_| Err(anyhow!("synthetic provider failure"))),
    ),
  ];

  for (label, query) in cases {
    let acquisitions = Cell::new(0);
    let error = with_browser_database_using(
      || {
        acquisitions.set(acquisitions.get() + 1);
        Ok(test_reader(
          DatabaseAcquisitionStrategy::VerifiedWalSnapshot,
        ))
      },
      |connection| query(connection),
    )
    .expect_err(label);
    assert_eq!(acquisitions.get(), 1, "{label} unexpectedly retried");
    let failure = error
      .downcast_ref::<BrowserDatabaseFailure>()
      .expect("typed non-retry failure context");
    assert_eq!(failure.kind, BrowserDatabaseFailureKind::Query);
    assert_eq!(failure.attempts, 1);
  }
}

#[test]
fn live_lock_corruption_and_unselected_io_errors_are_not_retried() {
  let cases = [
    (
      DatabaseAcquisitionStrategy::LiveReadOnly,
      rusqlite::ffi::SQLITE_CORRUPT,
    ),
    (
      DatabaseAcquisitionStrategy::LiveReadOnly,
      rusqlite::ffi::SQLITE_BUSY,
    ),
    (
      DatabaseAcquisitionStrategy::LiveReadOnly,
      rusqlite::ffi::SQLITE_LOCKED,
    ),
    (
      DatabaseAcquisitionStrategy::VerifiedWalSnapshot,
      rusqlite::ffi::SQLITE_BUSY,
    ),
    (
      DatabaseAcquisitionStrategy::VerifiedStaticSingleFile,
      rusqlite::ffi::SQLITE_CORRUPT,
    ),
    (
      DatabaseAcquisitionStrategy::VerifiedWalSnapshot,
      rusqlite::ffi::SQLITE_IOERR_WRITE,
    ),
  ];

  for (strategy, result_code) in cases {
    let acquisitions = Cell::new(0);
    let error = with_browser_database_using(
      || {
        acquisitions.set(acquisitions.get() + 1);
        Ok(test_reader(strategy))
      },
      |_| -> Result<()> { Err(sqlite_failure(result_code)) },
    )
    .expect_err("error must remain non-retryable");
    assert_eq!(acquisitions.get(), 1, "{result_code} unexpectedly retried");
    let failure = error
      .downcast_ref::<BrowserDatabaseFailure>()
      .expect("typed non-retry failure context");
    assert_eq!(failure.kind, BrowserDatabaseFailureKind::Query);
    assert_eq!(failure.attempts, 1);
  }
}

#[test]
fn live_acquisition_locks_are_not_retried() {
  for result_code in [rusqlite::ffi::SQLITE_BUSY, rusqlite::ffi::SQLITE_LOCKED] {
    let acquisitions = Cell::new(0);
    let queries = Cell::new(0);
    let error = with_browser_database_using(
      || {
        acquisitions.set(acquisitions.get() + 1);
        Err(DatabaseAcquisitionFailure {
          strategy: Some(DatabaseAcquisitionStrategy::LiveReadOnly),
          error: sqlite_failure(result_code),
        })
      },
      |_| {
        queries.set(queries.get() + 1);
        Ok(())
      },
    )
    .expect_err("live acquisition lock must remain non-retryable");

    assert_eq!(acquisitions.get(), 1);
    assert_eq!(queries.get(), 0);
    let failure = error
      .downcast_ref::<BrowserDatabaseFailure>()
      .expect("typed acquisition failure context");
    assert_eq!(failure.kind, BrowserDatabaseFailureKind::Acquisition);
    assert_eq!(
      failure.strategy,
      Some(DatabaseAcquisitionStrategy::LiveReadOnly)
    );
    assert_eq!(failure.attempts, 1);
  }
}

#[test]
fn reads_rows_committed_to_an_active_wal() {
  let directory = TempDir::new().expect("temp dir");
  let (path, writer) = checkpointed_database(directory.path());

  writer
    .execute("INSERT INTO cookies (name) VALUES ('in-wal')", [])
    .expect("insert WAL row");
  // The writer stays open and the fixture is far below the 1000-page
  // autocheckpoint threshold, so the row stays in the -wal.
  assert!(has_nonempty_wal(&path.canonicalize().expect("canonicalize")).expect("stat wal"));

  let reader = connect(path).expect("connect");

  assert_eq!(cookie_names(&reader), vec!["checkpointed", "in-wal"]);
  assert!(
    reader.snapshot_path().is_some(),
    "a WAL database must be read through a snapshot"
  );
}

/// Pins the reason the snapshot exists at all. A writer holding
/// `locking_mode=EXCLUSIVE` blocks any ordinary cross-process connection, so
/// reading the live file is not an alternative to copying it.
#[test]
fn reads_a_database_held_by_an_exclusive_writer() {
  let directory = TempDir::new().expect("temp dir");
  let (path, writer) = checkpointed_database(directory.path());
  writer
    .execute_batch("PRAGMA locking_mode=EXCLUSIVE;")
    .expect("take exclusive lock");
  writer
    .execute("INSERT INTO cookies (name) VALUES ('in-wal')", [])
    .expect("insert WAL row");

  let canonical = path.canonicalize().expect("canonicalize");
  let in_place = open_read_only(&canonical, "mode=ro").and_then(|connection| {
    let mut statement = connection.prepare("SELECT name FROM cookies")?;
    let names = statement
      .query_map([], |row| row.get::<_, String>(0))?
      .collect::<rusqlite::Result<Vec<String>>>()?;
    Ok(names)
  });
  assert!(
    in_place.is_err(),
    "an exclusive writer must block an in-place read, got {in_place:?}"
  );

  let reader = connect(path).expect("connect");

  assert_eq!(cookie_names(&reader), vec!["checkpointed", "in-wal"]);
}

/// `snapshot_database` accepts an attempt when the copied main file still
/// matches the source, so pin the premise that makes that signal mean
/// anything: ordinary WAL commits leave the main file alone, and a checkpoint
/// disturbs it.
#[test]
fn only_a_checkpoint_disturbs_the_main_file() {
  let directory = TempDir::new().expect("temp dir");
  let (path, writer) = checkpointed_database(directory.path());

  let snapshot = TempDir::new().expect("snapshot dir");
  let copy = snapshot.path().join("Cookies");
  fs::copy(&path, &copy).expect("copy database");

  writer
    .execute("INSERT INTO cookies (name) VALUES ('in-wal')", [])
    .expect("insert WAL row");
  assert!(
    compare_files(&path, &copy).expect("compare"),
    "a WAL commit must not touch the main file"
  );

  writer
    .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
    .expect("checkpoint");

  assert!(
    !compare_files(&path, &copy).expect("compare"),
    "a checkpoint must be detectable"
  );
}

/// A retry reuses the snapshot directory. If the browser checkpointed and
/// removed its WAL in between, the previous attempt's WAL must not survive to
/// be replayed over the newer main file.
#[test]
fn a_retry_discards_the_previous_attempts_wal() {
  let directory = TempDir::new().expect("temp dir");
  let (path, writer) = checkpointed_database(directory.path());
  writer
    .execute("INSERT INTO cookies (name) VALUES ('in-wal')", [])
    .expect("insert WAL row");

  let snapshot = TempDir::new().expect("snapshot dir");
  let copy = copy_database(&path, snapshot.path()).expect("first attempt");
  assert!(
    sidecar(&copy, "-wal").exists(),
    "fixture needs a copied WAL"
  );

  // The browser closes: SQLite checkpoints and removes the WAL.
  drop(writer);
  assert!(!sidecar(&path, "-wal").exists(), "fixture needs no WAL");

  copy_database(&path, snapshot.path()).expect("second attempt");

  assert!(
    !sidecar(&copy, "-wal").exists(),
    "the stale WAL must not be left beside the newer database"
  );
  let reader = SqliteReader {
    connection: open_read_only(&copy, "mode=ro").expect("open snapshot"),
    snapshot: Some(snapshot),
    strategy: DatabaseAcquisitionStrategy::VerifiedWalSnapshot,
  };
  assert_eq!(cookie_names(&reader), vec!["checkpointed", "in-wal"]);
}

#[test]
fn files_are_identical_distinguishes_content_and_length() {
  let directory = TempDir::new().expect("temp dir");
  let (a, b, c) = (
    directory.path().join("a"),
    directory.path().join("b"),
    directory.path().join("c"),
  );
  fs::write(&a, b"cookie").expect("write a");
  fs::write(&b, b"cookie").expect("write b");
  fs::write(&c, b"cookies").expect("write c");

  assert!(compare_files(&a, &b).expect("compare equal"));
  assert!(!compare_files(&a, &c).expect("compare shorter"));
  assert!(!compare_files(&c, &a).expect("compare longer"));
}

/// Cookie databases are far larger than the read buffer, so the comparison
/// has to be right across chunk boundaries, not just within the first one.
#[test]
fn files_are_identical_spans_multiple_chunks() {
  let directory = TempDir::new().expect("temp dir");
  let (a, b) = (directory.path().join("a"), directory.path().join("b"));
  let bulk = vec![b'c'; 8192 * 3 + 17];
  fs::write(&a, &bulk).expect("write a");
  fs::write(&b, &bulk).expect("write b");
  assert!(compare_files(&a, &b).expect("compare equal"));

  // Differ only in the final chunk, past several identical ones.
  let mut tail = bulk.clone();
  *tail.last_mut().expect("non-empty") = b'x';
  fs::write(&b, &tail).expect("rewrite b");

  assert!(!compare_files(&a, &b).expect("compare differing tail"));
}

#[test]
fn optional_file_comparison_distinguishes_absence_from_change() {
  let directory = TempDir::new().expect("temp dir");
  let source = directory.path().join("source-wal");
  let copy = directory.path().join("copy-wal");
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);

  assert!(optional_files_are_identical(&source, &copy, &runtime).expect("both sidecars absent"));
  fs::write(&source, b"wal").expect("write source WAL");
  assert!(!optional_files_are_identical(&source, &copy, &runtime).expect("copy sidecar absent"));
  fs::write(&copy, b"wal").expect("write copied WAL");
  assert!(optional_files_are_identical(&source, &copy, &runtime).expect("matching WALs"));
  fs::write(&source, b"new-wal").expect("change source WAL");
  assert!(!optional_files_are_identical(&source, &copy, &runtime).expect("changed source WAL"));
}

#[test]
fn snapshot_retries_when_the_source_wal_changes_after_copy() {
  let directory = TempDir::new().expect("temp dir");
  let (path, writer) = checkpointed_database(directory.path());
  writer
    .execute("INSERT INTO cookies (name) VALUES ('before-copy')", [])
    .expect("insert initial WAL row");
  let snapshot = TempDir::new().expect("snapshot dir");
  let copies = Cell::new(0_u32);
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);

  let copy = snapshot_database_with_after_copy(&path, snapshot.path(), &runtime, |attempt, _| {
    copies.set(attempt);
    if attempt == 1 {
      writer
        .execute("INSERT INTO cookies (name) VALUES ('after-copy')", [])
        .expect("change source WAL after first copy");
    }
    Ok(())
  })
  .expect("moving WAL is retried");
  let reader = SqliteReader {
    connection: open_read_only(&copy, "mode=ro").expect("open verified snapshot"),
    snapshot: Some(snapshot),
    strategy: DatabaseAcquisitionStrategy::VerifiedWalSnapshot,
  };

  assert_eq!(
    copies.get(),
    2,
    "the first moving-WAL copy must be rejected"
  );
  assert_eq!(
    cookie_names(&reader),
    vec!["after-copy", "before-copy", "checkpointed"]
  );
}

#[test]
fn snapshot_of_an_idle_database_succeeds_on_the_first_attempt() {
  let directory = TempDir::new().expect("temp dir");
  let (path, writer) = checkpointed_database(directory.path());
  writer
    .execute("INSERT INTO cookies (name) VALUES ('in-wal')", [])
    .expect("insert WAL row");

  let snapshot = TempDir::new().expect("snapshot dir");
  let copy = snapshot_database(&path, snapshot.path()).expect("snapshot");

  assert!(copy.exists());
  assert!(sidecar(&copy, "-wal").exists(), "the WAL must come along");
}

#[test]
fn verified_wal_snapshot_rejects_a_rollback_journal_main_file() {
  let directory = TempDir::new().expect("temp dir");
  let (path, _writer) = rollback_database(directory.path());
  let snapshot = TempDir::new().expect("snapshot dir");

  let error = snapshot_database(&path, snapshot.path())
    .expect_err("a rollback-journal main file cannot enter the WAL snapshot path");

  assert!(
    error.to_string().contains("copied journal mode is not WAL"),
    "unexpected error: {error:#}"
  );
}

/// Shows why [`snapshot_database`] verifies its copy rather than trusting a
/// copy order: taking the main file, letting a checkpoint land, then taking
/// the WAL silently loses rows. Characterizes SQLite, so it cannot fail from
/// a rookie regression.
#[test]
fn an_unverified_copy_loses_rows_when_a_checkpoint_intervenes() {
  let directory = TempDir::new().expect("temp dir");
  let (path, writer) = checkpointed_database(directory.path());
  writer
    .execute("INSERT INTO cookies (name) VALUES ('in-wal')", [])
    .expect("insert WAL row");

  let snapshot = TempDir::new().expect("snapshot dir");
  let copy = snapshot.path().join("Cookies");

  fs::copy(&path, &copy).expect("copy database");
  writer
    .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
    .expect("checkpoint");
  fs::copy(sidecar(&path, "-wal"), sidecar(&copy, "-wal")).expect("copy wal");

  let reader = SqliteReader {
    connection: open_read_only(&copy, "mode=ro").expect("open snapshot"),
    snapshot: Some(snapshot),
    strategy: DatabaseAcquisitionStrategy::VerifiedWalSnapshot,
  };

  // The checkpoint moved 'in-wal' into the real main file and rewound the
  // WAL, but this pair holds the pre-checkpoint main file and the rewound
  // WAL, so the row is in neither.
  assert_eq!(cookie_names(&reader), vec!["checkpointed"]);
}

/// Guards the regression this module exists to prevent: an `immutable`
/// connection silently reports the stale pre-WAL contents.
#[test]
fn immutable_connections_omit_active_wal_rows() {
  let directory = TempDir::new().expect("temp dir");
  let (path, writer) = checkpointed_database(directory.path());

  writer
    .execute("INSERT INTO cookies (name) VALUES ('in-wal')", [])
    .expect("insert WAL row");

  let immutable = SqliteReader {
    connection: open_read_only(
      &path.canonicalize().expect("canonicalize"),
      "mode=ro&immutable=1",
    )
    .expect("open immutable"),
    snapshot: None,
    strategy: DatabaseAcquisitionStrategy::VerifiedStaticSingleFile,
  };

  assert_eq!(cookie_names(&immutable), vec!["checkpointed"]);
}

#[test]
fn reads_a_database_whose_wal_is_empty() {
  let directory = TempDir::new().expect("temp dir");
  let (path, _writer) = checkpointed_database(directory.path());

  let reader = connect(path).expect("connect");

  assert_eq!(cookie_names(&reader), vec!["checkpointed"]);
  assert!(
    reader.snapshot_path().is_some(),
    "a WAL-mode database must not be opened in the live profile even when its WAL is empty"
  );
  assert_eq!(
    reader.strategy(),
    DatabaseAcquisitionStrategy::VerifiedWalSnapshot
  );
  assert!(
    reader.is_autocommit(),
    "a private WAL snapshot needs no live read transaction"
  );
}

#[test]
fn wal_mode_without_sidecars_is_read_without_mutating_the_source_directory() {
  let directory = TempDir::new().expect("temp dir");
  let (path, writer) = checkpointed_database(directory.path());
  drop(writer);
  let canonical = path.canonicalize().expect("canonicalize");

  assert!(database_uses_wal(&canonical).expect("read header"));
  for suffix in ["-wal", "-shm", "-journal"] {
    assert!(
      !sidecar(&canonical, suffix).exists(),
      "fixture must start without {suffix}"
    );
  }

  let reader = connect(path).expect("connect");

  assert_eq!(cookie_names(&reader), vec!["checkpointed"]);
  assert_eq!(
    reader.strategy(),
    DatabaseAcquisitionStrategy::VerifiedWalSnapshot
  );
  for suffix in ["-wal", "-shm", "-journal"] {
    assert!(
      !sidecar(&canonical, suffix).exists(),
      "read-only extraction created live sidecar {suffix}"
    );
  }
}

#[cfg(unix)]
#[test]
fn reads_wal_mode_database_from_a_read_only_directory() {
  use std::os::unix::fs::PermissionsExt;

  let directory = TempDir::new().expect("temp dir");
  let (path, writer) = checkpointed_database(directory.path());
  drop(writer);
  let original_permissions = fs::metadata(directory.path())
    .expect("directory metadata")
    .permissions();
  fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o555))
    .expect("make source directory read-only");

  let probe = directory.path().join("write-probe");
  let probe_result = fs::File::create(&probe);
  if probe_result.is_ok() {
    // A privileged test process can bypass mode bits, so it cannot exercise
    // the read-only-media contract meaningfully.
    drop(probe_result);
    let _ = fs::remove_file(&probe);
    fs::set_permissions(directory.path(), original_permissions)
      .expect("restore source permissions");
    return;
  }

  let result = connect(path);
  fs::set_permissions(directory.path(), original_permissions).expect("restore source permissions");
  let reader = result.expect("read private snapshot from read-only source");

  assert_eq!(cookie_names(&reader), vec!["checkpointed"]);
  assert_eq!(
    reader.strategy(),
    DatabaseAcquisitionStrategy::VerifiedWalSnapshot
  );
}

#[test]
fn reads_a_database_that_never_used_a_wal() {
  let directory = TempDir::new().expect("temp dir");
  let path = directory.path().join("cookies.sqlite");
  let writer = Connection::open(&path).expect("open writable sqlite");
  writer
    .execute("CREATE TABLE cookies (name TEXT NOT NULL)", [])
    .expect("create table");
  writer
    .execute("INSERT INTO cookies (name) VALUES ('no-wal')", [])
    .expect("insert row");
  drop(writer);

  let reader = connect(path.clone()).expect("connect");

  assert_eq!(cookie_names(&reader), vec!["no-wal"]);
  assert!(
    reader.snapshot_path().is_none(),
    "a database with no WAL is read in place"
  );
  assert!(
    !reader.is_autocommit(),
    "a live no-WAL read must return with its read transaction pinned"
  );
  assert!(!database_uses_wal(&path).expect("read rollback header"));
}

#[test]
fn rollback_to_wal_race_reacquires_without_creating_source_sidecars() {
  let directory = TempDir::new().expect("temp dir");
  let (path, writer) = rollback_database(directory.path());
  drop(writer);
  let canonical = path.canonicalize().expect("canonicalize");

  let reader = acquire_browser_database_with_before_live(path, |database| {
    let transition = Connection::open(database).expect("open mode-transition connection");
    let mode: String = transition
      .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
      .expect("switch source to WAL");
    assert_eq!(mode, "wal");
    transition
      .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
      .expect("checkpoint transition");
    drop(transition);
    assert!(database_uses_wal(database).expect("read transitioned header"));
    for suffix in ["-wal", "-shm", "-journal"] {
      assert!(
        !sidecar(database, suffix).exists(),
        "clean transition fixture retained {suffix}"
      );
    }

    // Pin the premise that makes the raced live probe safe: once the header
    // says WAL, a read-only exclusive-mode connection must fail its first
    // schema read before SQLite opens or creates either live sidecar.
    let error = open_live_read_only(database)
      .expect_err("a clean WAL database cannot be opened by the live rollback path");
    let sqlite_error = error
      .chain()
      .find_map(|cause| cause.downcast_ref::<rusqlite::Error>())
      .unwrap_or_else(|| panic!("expected a typed SQLite lock failure, got {error:#}"));
    match sqlite_error {
      rusqlite::Error::SqliteFailure(code, _) => {
        assert_eq!(code.extended_code, rusqlite::ffi::SQLITE_IOERR_LOCK);
      }
      other => panic!("expected SQLITE_IOERR_LOCK, got {other}"),
    }
    for suffix in ["-wal", "-shm", "-journal"] {
      assert!(
        !sidecar(database, suffix).exists(),
        "failed direct live probe created source sidecar {suffix}"
      );
    }
    Ok(())
  })
  .map_err(|failure| failure.error)
  .expect("reclassify the raced source");

  assert_eq!(cookie_names(&reader), vec!["before"]);
  assert_eq!(
    reader.strategy(),
    DatabaseAcquisitionStrategy::VerifiedWalSnapshot
  );
  for suffix in ["-wal", "-shm", "-journal"] {
    assert!(
      !sidecar(&canonical, suffix).exists(),
      "raced live probe created source sidecar {suffix}"
    );
  }
}

#[test]
fn rollback_journal_reader_stays_on_one_coherent_snapshot() {
  let directory = TempDir::new().expect("temp dir");
  let (path, writer) = rollback_database(directory.path());

  // Open the reader before the writer transaction and deliberately do not
  // query `cookies` yet. The schema read inside `connect` must already have
  // established the SHARED lock and the pre-write snapshot.
  let reader = connect(path.clone()).expect("open live rollback-journal reader");
  assert!(reader.snapshot_path().is_none(), "must not raw-copy");
  assert!(!reader.is_autocommit(), "read transaction must be active");

  // A RESERVED writer and SHARED reader can coexist, so the update can be
  // staged. Its commit needs an EXCLUSIVE lock and must not move the already
  // pinned reader to the post-write state.
  writer
    .execute_batch("BEGIN IMMEDIATE; UPDATE cookies SET name = 'after';")
    .expect("stage update under a reserved rollback-journal lock");

  writer
    .busy_timeout(std::time::Duration::ZERO)
    .expect("disable writer wait");
  let error = writer
    .execute_batch("COMMIT;")
    .expect_err("the pinned reader must prevent the writer's exclusive commit lock");
  assert!(
    is_busy_or_locked(&error),
    "expected typed SQLITE_BUSY/SQLITE_LOCKED, got {error}"
  );
  assert_eq!(
    cookie_names(&reader),
    vec!["before"],
    "a failed concurrent commit must not move the reader's snapshot"
  );

  drop(reader);
  writer
    .execute_batch("COMMIT;")
    .expect("commit after the reader releases its snapshot");
  let reader = connect(path).expect("open post-commit reader");
  assert_eq!(cookie_names(&reader), vec!["after"]);
}

#[test]
fn exclusive_rollback_writer_returns_typed_lock_instead_of_immutable_data() {
  let directory = TempDir::new().expect("temp dir");
  let (path, writer) = rollback_database(directory.path());
  writer
    .execute_batch("BEGIN EXCLUSIVE; UPDATE cookies SET name = 'uncommitted';")
    .expect("take exclusive rollback-journal lock");

  let canonical = path.canonicalize().expect("canonicalize");
  let error = match open_live_without_wait(&canonical) {
    Ok(_) => panic!("an exclusive rollback-journal writer must not be read through"),
    Err(error) => error,
  };
  assert_anyhow_busy_or_locked(&error);
  assert!(
    !sidecar(&canonical, "-wal").exists(),
    "fixture must exercise the no-WAL branch"
  );

  writer.execute_batch("ROLLBACK;").expect("release writer");
  let reader = connect(path).expect("open after lock release");
  assert_eq!(cookie_names(&reader), vec!["before"]);
}

#[test]
fn exclusive_rollback_writer_honors_the_request_deadline() {
  let directory = TempDir::new().expect("temp dir");
  let (path, writer) = rollback_database(directory.path());
  writer
    .execute_batch("BEGIN EXCLUSIVE; UPDATE cookies SET name = 'uncommitted';")
    .expect("take exclusive rollback-journal lock");

  let clock = ManualClock::default();
  let runtime = BoundaryRuntime::new(&clock, Deadline::after(&clock, Duration::from_millis(25)));
  let error =
    open_live_read_only_with_runtime(&path.canonicalize().expect("canonicalize"), &runtime)
      .expect_err("the request deadline must stop lock polling");
  assert_eq!(
    error.downcast_ref::<BoundaryStop>(),
    Some(&BoundaryStop::TimedOut),
    "{error:#}"
  );
  writer.execute_batch("ROLLBACK;").expect("release writer");
}

#[test]
fn exclusive_rollback_writer_honors_in_flight_cancellation() {
  let directory = TempDir::new().expect("temp dir");
  let (path, writer) = rollback_database(directory.path());
  writer
    .execute_batch("BEGIN EXCLUSIVE; UPDATE cookies SET name = 'uncommitted';")
    .expect("take exclusive rollback-journal lock");

  let clock = SystemClock;
  let token = CancellationToken::default();
  let canceller = token.clone();
  let thread = std::thread::spawn(move || {
    std::thread::sleep(Duration::from_millis(30));
    assert!(canceller.cancel());
  });
  let runtime = BoundaryRuntime::with_stop(
    &clock,
    Deadline::after(&clock, Duration::from_secs(5)),
    token,
  );
  let error =
    open_live_read_only_with_runtime(&path.canonicalize().expect("canonicalize"), &runtime)
      .expect_err("cancellation must stop an already-blocked lock poll");
  thread.join().expect("canceller thread");
  assert_eq!(
    error.downcast_ref::<BoundaryStop>(),
    Some(&BoundaryStop::Cancelled),
    "{error:#}"
  );
  writer.execute_batch("ROLLBACK;").expect("release writer");
}

#[test]
fn verified_static_single_file_is_the_only_immutable_entry_point() {
  let source_directory = TempDir::new().expect("source dir");
  let (source, writer) = rollback_database(source_directory.path());
  drop(writer);

  let snapshot = TempDir::new().expect("snapshot dir");
  let copy = snapshot.path().join("cookies.sqlite");
  fs::copy(&source, &copy).expect("copy closed single-file database");
  let verified = VerifiedStaticSingleFile {
    path: copy,
    snapshot,
  };
  let reader = open_verified_static_single_file(verified).expect("open verified static copy");

  assert_eq!(cookie_names(&reader), vec!["before"]);
  assert!(
    reader.is_autocommit(),
    "immutable copy needs no live read lock"
  );
  assert!(
    reader.snapshot_path().is_some(),
    "the reader must retain ownership of the acquired copy"
  );
}

#[test]
fn immutable_entry_point_rejects_a_static_database_and_wal_pair() {
  let source_directory = TempDir::new().expect("source dir");
  let (source, writer) = checkpointed_database(source_directory.path());
  writer
    .execute("INSERT INTO cookies (name) VALUES ('in-wal')", [])
    .expect("insert WAL row");

  let snapshot = TempDir::new().expect("snapshot dir");
  let copy = copy_database(&source, snapshot.path()).expect("copy DB+WAL pair");
  let verified = VerifiedStaticSingleFile {
    path: copy,
    snapshot,
  };
  let error = match open_verified_static_single_file(verified) {
    Ok(_) => panic!("a DB+WAL pair must never use immutable mode"),
    Err(error) => error,
  };
  assert!(
    error.to_string().contains("must contain one file"),
    "unexpected error: {error:#}"
  );
}

#[test]
fn missing_database_errors() {
  let directory = TempDir::new().expect("temp dir");
  let path = directory
    .path()
    .join("absolute path sentinel with spaces")
    .join("absent.sqlite");

  let error = match connect(path.clone()) {
    Ok(_) => panic!("missing database must error"),
    Err(error) => error,
  };
  let diagnostic = format!("{error:#}");

  assert!(!diagnostic.contains(path.to_string_lossy().as_ref()));
  assert!(diagnostic.contains(REDACTED_PATH));
}

#[test]
fn snapshot_is_removed_once_the_reader_drops() {
  let directory = TempDir::new().expect("temp dir");
  let (path, writer) = checkpointed_database(directory.path());
  writer
    .execute("INSERT INTO cookies (name) VALUES ('in-wal')", [])
    .expect("insert WAL row");

  let snapshot_directory = {
    let reader = connect(path).expect("connect");
    let snapshot_directory = reader
      .snapshot_path()
      .expect("WAL database is read through a snapshot")
      .to_path_buf();
    assert!(snapshot_directory.exists());
    snapshot_directory
  };

  assert!(!snapshot_directory.exists());
}
