#[cfg(test)]
use crate::common::boundary::Acquire;
#[cfg(test)]
use crate::common::deadline::SystemClock;
use crate::common::deadline::{BoundaryRuntime, Deadline};
#[cfg(test)]
use crate::common::deadline::{Clock, DeadlineEnforcement};
use crate::common::diagnostic::REDACTED_PATH;
use crate::utils::TempDir;
use anyhow::{anyhow, Context, Result};
use rusqlite::{Connection, ErrorCode, OpenFlags};
use std::ffi::OsString;
use std::fmt;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::{fs, io};
use url::Url;

/// How the connection used for one complete browser query was acquired.
///
/// This stays private to the crate until the report DTOs are introduced. A
/// retry can finish through a different strategy if, for example, a WAL is
/// checkpointed between attempts, so outcomes record the successful attempt's
/// strategy rather than assuming it from the first acquisition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DatabaseAcquisitionStrategy {
  LiveReadOnly,
  VerifiedWalSnapshot,
  VerifiedStaticSingleFile,
}

/// Successful value plus the acquisition details needed by future source
/// reports. Legacy browser functions project this back to their existing value.
#[derive(Debug)]
pub(crate) struct BrowserDatabaseOutcome<T> {
  value: T,
  strategy: DatabaseAcquisitionStrategy,
  attempts: u32,
}

impl<T> BrowserDatabaseOutcome<T> {
  pub(crate) fn strategy(&self) -> DatabaseAcquisitionStrategy {
    self.strategy
  }

  pub(crate) fn attempts(&self) -> u32 {
    self.attempts
  }

  pub(crate) fn into_value(self) -> T {
    self.value
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BrowserDatabaseFailureKind {
  Acquisition,
  Query,
  RetryExhausted,
}

/// Typed context retained on failures without changing the public `anyhow`
/// result aliases. Later report adapters can downcast this context to recover
/// attempt metadata, while the original SQLite error remains in the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BrowserDatabaseFailure {
  pub(crate) kind: BrowserDatabaseFailureKind,
  pub(crate) strategy: Option<DatabaseAcquisitionStrategy>,
  pub(crate) attempts: u32,
}

impl fmt::Display for BrowserDatabaseFailure {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    let stage = match self.kind {
      BrowserDatabaseFailureKind::Acquisition => "acquisition failed",
      BrowserDatabaseFailureKind::Query => "query failed",
      BrowserDatabaseFailureKind::RetryExhausted => "snapshot query retry exhausted",
    };
    match self.strategy {
      Some(strategy) => write!(
        formatter,
        "browser database {stage} after {} attempt(s) using {strategy:?}",
        self.attempts
      ),
      None => write!(
        formatter,
        "browser database {stage} after {} attempt(s)",
        self.attempts
      ),
    }
  }
}

struct DatabaseAcquisitionFailure {
  strategy: Option<DatabaseAcquisitionStrategy>,
  error: anyhow::Error,
}

/// A read-only connection to a browser database.
///
/// Dereferences to [`Connection`], so callers query it like any other
/// `rusqlite` connection. When the database had a write-ahead log, the
/// connection reads a point-in-time copy rather than the live file, so results
/// are as of the moment the query attempt acquired the reader.
pub struct SqliteReader {
  // Declaration order is load-bearing: `connection` must drop before
  // `snapshot` so the database files are closed before the directory holding
  // them is removed (Windows refuses to delete open files). POSIX allows
  // unlinking open files, so `snapshot_is_removed_once_the_reader_drops`
  // cannot catch a reordering here — only the Windows CI job can.
  connection: Connection,
  snapshot: Option<TempDir>,
  strategy: DatabaseAcquisitionStrategy,
}

impl crate::common::boundary::ReadOnlySource for SqliteReader {}

/// An already-acquired, static single-file database that was verified as
/// WAL-free across its acquisition window (or copied only after a checkpoint
/// completely drained the WAL).
///
/// The fields deliberately stay private to this module. A path being in a
/// temporary directory is not proof that `immutable=1` is safe: the
/// acquisition operation must establish the invariant before it can construct
/// this value. The first platform acquisition that can provide that proof will
/// add the constructor alongside its verification, rather than accepting an
/// arbitrary path here.
#[allow(dead_code)]
pub(crate) struct VerifiedStaticSingleFile {
  path: PathBuf,
  snapshot: TempDir,
}

impl SqliteReader {
  /// The private directory holding the snapshot, or `None` when the database
  /// was read in place.
  pub(crate) fn snapshot_path(&self) -> Option<&Path> {
    self.snapshot.as_ref().map(TempDir::path)
  }

  fn strategy(&self) -> DatabaseAcquisitionStrategy {
    self.strategy
  }
}

impl Deref for SqliteReader {
  type Target = Connection;

  fn deref(&self) -> &Connection {
    &self.connection
  }
}

/// Acquires a browser database for reading.
///
/// Firefox keeps `cookies.sqlite` in WAL mode, so recently written cookies live
/// in the `-wal` sidecar until a checkpoint folds them into the main file.
/// `immutable=1` tells SQLite the file cannot change, which makes it skip the
/// `-wal` entirely — those cookies then go missing with no error.
///
/// Dropping `immutable` and reading the live file is not a general answer,
/// because a writer holding `locking_mode=EXCLUSIVE` makes queries from another
/// process fail with `SQLITE_BUSY` for as long as the browser runs. So when a
/// `-wal` is present the database is copied beside it into a private directory
/// and the copy is read. Copying only reads bytes: it takes no SQLite locks and
/// cannot starve the writer, at the cost of a copy that is not atomic and so
/// has to be checked for a racing checkpoint (see [`snapshot_database`]).
///
/// A WAL-mode database with no pending WAL is still not opened in place:
/// SQLite may create `-wal`/`-shm` files merely to read it, which mutates a live
/// profile and fails on genuinely read-only media. Instead, every WAL-mode
/// source goes through the same verified private DB+WAL snapshot path. When no
/// WAL exists, SQLite may create empty sidecars only inside that private,
/// writable directory. The copy is never opened with `immutable=1`.
///
/// Only rollback-journal databases are opened live. Before this function
/// returns, it selects exclusive locking before the first database access,
/// begins a read transaction, and reads the schema. If a rollback-to-WAL race
/// has already won, SQLite must acquire an exclusive main-file lock before it
/// opens the WAL; a read-only connection cannot acquire that lock, so it fails
/// before creating either WAL sidecar. If rollback mode still holds, the
/// pinned transaction prevents further mode changes. An active
/// rollback-journal writer therefore either permits that coherent read or
/// returns SQLite's typed busy/locked error; this path never raw-copies or
/// immutably opens the live database.
///
/// Test-only: no production caller routes through this convenience wrapper --
/// they all supply their own runtime via
/// [`acquire_browser_database_with_runtime`]. Its eleven call sites are the
/// acquisition tests, so this is `#[cfg(test)]` rather than deleted, per the
/// rule that a wrapper with callers is gated and only a caller-less one goes.
#[cfg(test)]
pub fn connect(path: PathBuf) -> Result<SqliteReader> {
  let acquire = BrowserDatabaseAcquire;
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  super::boundary::acquire(&acquire, &path, &runtime)
}

#[cfg(test)]
struct BrowserDatabaseAcquire;

#[cfg(test)]
impl Acquire<PathBuf> for BrowserDatabaseAcquire {
  type Source = SqliteReader;

  fn open(&self, path: &PathBuf, runtime: &BoundaryRuntime<'_>) -> Result<Self::Source> {
    runtime.check()?;
    let reader = acquire_browser_database_with_runtime(path.clone(), runtime)
      .map_err(|failure| failure.error)?;
    runtime.check()?;
    Ok(reader)
  }

  fn deadline_enforcement(&self) -> DeadlineEnforcement {
    // Filesystem and VFS syscalls cannot be preempted in-process. Checks still
    // prevent retries or decoder work from starting after the budget expires.
    DeadlineEnforcement::Cooperative
  }
}

fn acquire_browser_database_with_runtime(
  path: PathBuf,
  runtime: &BoundaryRuntime<'_>,
) -> std::result::Result<SqliteReader, DatabaseAcquisitionFailure> {
  acquire_browser_database_with_before_live_runtime(path, |_| Ok(()), runtime)
}

#[cfg(test)]
fn acquire_browser_database_with_before_live<BeforeLive>(
  path: PathBuf,
  before_live: BeforeLive,
) -> std::result::Result<SqliteReader, DatabaseAcquisitionFailure>
where
  BeforeLive: FnMut(&Path) -> Result<()>,
{
  let clock = SystemClock;
  let runtime = BoundaryRuntime::new(&clock, Deadline::standard());
  acquire_browser_database_with_before_live_runtime(path, before_live, &runtime)
}

fn acquire_browser_database_with_before_live_runtime<BeforeLive>(
  path: PathBuf,
  mut before_live: BeforeLive,
  runtime: &BoundaryRuntime<'_>,
) -> std::result::Result<SqliteReader, DatabaseAcquisitionFailure>
where
  BeforeLive: FnMut(&Path) -> Result<()>,
{
  let check = || {
    runtime.check().map_err(|error| DatabaseAcquisitionFailure {
      strategy: None,
      error: error.into(),
    })
  };
  check()?;
  let path = path
    .canonicalize()
    .with_context(|| format!("Can't resolve database path {REDACTED_PATH}"))
    .map_err(|error| DatabaseAcquisitionFailure {
      strategy: None,
      error,
    })?;

  check()?;
  let uses_wal = database_requires_wal_snapshot_with_runtime(&path, runtime).map_err(|error| {
    DatabaseAcquisitionFailure {
      strategy: None,
      error,
    }
  })?;
  check()?;
  let reader = if uses_wal {
    acquire_verified_wal_snapshot(&path, runtime)?
  } else {
    let strategy = DatabaseAcquisitionStrategy::LiveReadOnly;
    before_live(&path).map_err(|error| DatabaseAcquisitionFailure {
      strategy: Some(strategy),
      error,
    })?;
    check()?;
    let connection = match open_live_read_only_with_runtime(&path, runtime) {
      Ok(connection) => connection,
      Err(error) => {
        if database_requires_wal_snapshot_with_runtime(&path, runtime).map_err(|recheck| {
          DatabaseAcquisitionFailure {
            strategy: None,
            error: recheck,
          }
        })? {
          return acquire_verified_wal_snapshot(&path, runtime);
        }
        return Err(DatabaseAcquisitionFailure {
          strategy: Some(strategy),
          error,
        });
      }
    };

    // `open_live_read_only` sets exclusive locking mode before its first
    // database access. If the source changed to WAL after the initial header
    // check, SQLite must upgrade the read-only main file to an exclusive lock
    // before opening `-wal`; that fails before either live sidecar is created.
    // If rollback mode still holds, the pinned transaction prevents another
    // journal-mode transition while this recheck runs. Discard the probe and
    // reacquire through the private DB+WAL path whenever the source changed.
    check()?;
    if database_requires_wal_snapshot_with_runtime(&path, runtime).map_err(|error| {
      DatabaseAcquisitionFailure {
        strategy: None,
        error,
      }
    })? {
      drop(connection);
      acquire_verified_wal_snapshot(&path, runtime)?
    } else {
      SqliteReader {
        connection,
        snapshot: None,
        strategy,
      }
    }
  };
  check()?;

  match reader.snapshot_path() {
    Some(_) => log::debug!("reading {REDACTED_PATH} through a private snapshot"),
    None => log::debug!("reading {REDACTED_PATH} in place"),
  }

  Ok(reader)
}

fn database_requires_wal_snapshot_with_runtime(
  path: &Path,
  runtime: &BoundaryRuntime<'_>,
) -> Result<bool> {
  runtime.check()?;
  let has_wal = has_nonempty_wal_with_runtime(path, runtime)?;
  if has_wal {
    return Ok(true);
  }
  database_uses_wal_with_runtime(path, runtime)
}

fn acquire_verified_wal_snapshot(
  path: &Path,
  runtime: &BoundaryRuntime<'_>,
) -> std::result::Result<SqliteReader, DatabaseAcquisitionFailure> {
  let strategy = DatabaseAcquisitionStrategy::VerifiedWalSnapshot;
  // A snapshot failure is deliberately fatal rather than a fall back to the
  // `immutable` read: that read silently omits the WAL cookies. `load()`
  // reports a per-browser error and carries on, so a loud failure costs one
  // browser, not the whole call.
  let snapshot = TempDir::new().map_err(|error| DatabaseAcquisitionFailure {
    strategy: Some(strategy),
    error,
  })?;
  runtime
    .check()
    .map_err(|error| DatabaseAcquisitionFailure {
      strategy: Some(strategy),
      error: error.into(),
    })?;
  let copy = snapshot_database_with_runtime(path, snapshot.path(), runtime).map_err(|error| {
    DatabaseAcquisitionFailure {
      strategy: Some(strategy),
      error,
    }
  })?;
  runtime
    .check()
    .map_err(|error| DatabaseAcquisitionFailure {
      strategy: Some(strategy),
      error: error.into(),
    })?;
  runtime
    .check()
    .map_err(|error| DatabaseAcquisitionFailure {
      strategy: Some(strategy),
      error: error.into(),
    })?;
  let connection =
    open_read_only(&copy, "mode=ro").map_err(|error| DatabaseAcquisitionFailure {
      strategy: Some(strategy),
      error,
    })?;
  runtime
    .check()
    .map_err(|error| DatabaseAcquisitionFailure {
      strategy: Some(strategy),
      error: error.into(),
    })?;
  Ok(SqliteReader {
    // Deliberately not `immutable`: that flag tells SQLite to ignore the
    // `-wal`, which is the data this snapshot exists to recover.
    connection,
    snapshot: Some(snapshot),
    strategy,
  })
}

/// Runs a complete browser query, reacquiring and rerunning it only when an
/// error can plausibly originate from a torn/corrupt verified WAL snapshot.
///
/// The closure owns all statement preparation, iteration, and row conversion;
/// retrying it therefore never resumes a partially consumed query or returns
/// cookies from an earlier attempt.
#[cfg(test)]
pub(crate) fn with_browser_database<T, Query>(
  path: PathBuf,
  query: Query,
) -> Result<BrowserDatabaseOutcome<T>>
where
  Query: FnMut(&Connection) -> Result<T>,
{
  let clock = SystemClock;
  with_browser_database_with_deadline(path, query, &clock, Deadline::standard())
}

/// Runs acquisition and every query retry under one absolute monotonic
/// deadline. Callers that also retrieve keys or decode rows pass the same
/// value through those boundaries; a retry only receives the time left.
#[cfg(test)]
pub(crate) fn with_browser_database_with_deadline<T, Query>(
  path: PathBuf,
  query: Query,
  clock: &dyn Clock,
  deadline: Deadline,
) -> Result<BrowserDatabaseOutcome<T>>
where
  Query: FnMut(&Connection) -> Result<T>,
{
  let runtime = BoundaryRuntime::new(clock, deadline);
  with_browser_database_with_runtime(path, query, &runtime)
}

pub(crate) fn with_browser_database_with_runtime<T, Query>(
  path: PathBuf,
  query: Query,
  runtime: &BoundaryRuntime<'_>,
) -> Result<BrowserDatabaseOutcome<T>>
where
  Query: FnMut(&Connection) -> Result<T>,
{
  with_browser_database_using_runtime(
    || acquire_browser_database_with_runtime(path.clone(), runtime),
    query,
    runtime,
  )
}

/// Query-level attempts are separate from the lower-level copy verification
/// attempts in `snapshot_database`: these rerun the complete SQLite query after
/// a successfully copied image proves unusable.
const BROWSER_DATABASE_ATTEMPTS: u32 = 3;

#[cfg(test)]
fn with_browser_database_using<T, Acquire, Query>(
  acquire: Acquire,
  query: Query,
) -> Result<BrowserDatabaseOutcome<T>>
where
  Acquire: FnMut() -> std::result::Result<SqliteReader, DatabaseAcquisitionFailure>,
  Query: FnMut(&Connection) -> Result<T>,
{
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  with_browser_database_using_runtime(acquire, query, &runtime)
}

fn with_browser_database_using_runtime<T, Acquire, Query>(
  mut acquire: Acquire,
  mut query: Query,
  runtime: &BoundaryRuntime<'_>,
) -> Result<BrowserDatabaseOutcome<T>>
where
  Acquire: FnMut() -> std::result::Result<SqliteReader, DatabaseAcquisitionFailure>,
  Query: FnMut(&Connection) -> Result<T>,
{
  for attempt in 1..=BROWSER_DATABASE_ATTEMPTS {
    runtime.check()?;
    let reader = match acquire() {
      Ok(reader) => reader,
      Err(failure) => {
        let retryable = is_retryable_snapshot_error(failure.strategy, &failure.error);
        if retryable && attempt < BROWSER_DATABASE_ATTEMPTS {
          runtime.check()?;
          log::debug!(
            "reacquiring browser database after snapshot acquisition attempt {attempt}: {}",
            failure.error
          );
          continue;
        }
        let kind = if retryable {
          BrowserDatabaseFailureKind::RetryExhausted
        } else {
          BrowserDatabaseFailureKind::Acquisition
        };
        return Err(failure.error.context(BrowserDatabaseFailure {
          kind,
          strategy: failure.strategy,
          attempts: attempt,
        }));
      }
    };

    let strategy = reader.strategy();
    runtime.check()?;
    match query(&reader) {
      Ok(value) => {
        // Drop the connection (then its snapshot directory) before returning a
        // value that is independent of the database attempt.
        drop(reader);
        runtime.check()?;
        return Ok(BrowserDatabaseOutcome {
          value,
          strategy,
          attempts: attempt,
        });
      }
      Err(error) => {
        let retryable = is_retryable_snapshot_error(Some(strategy), &error);
        // Explicit drop makes cleanup-before-reacquisition part of this
        // boundary rather than an incidental consequence of loop scoping.
        drop(reader);
        if retryable && attempt < BROWSER_DATABASE_ATTEMPTS {
          runtime.check()?;
          log::debug!(
            "reacquiring browser database after snapshot query attempt {attempt}: {error}"
          );
          continue;
        }
        let kind = if retryable {
          BrowserDatabaseFailureKind::RetryExhausted
        } else {
          BrowserDatabaseFailureKind::Query
        };
        return Err(error.context(BrowserDatabaseFailure {
          kind,
          strategy: Some(strategy),
          attempts: attempt,
        }));
      }
    }
  }

  unreachable!("the bounded browser database loop always returns")
}

fn is_retryable_snapshot_error(
  strategy: Option<DatabaseAcquisitionStrategy>,
  error: &anyhow::Error,
) -> bool {
  if strategy != Some(DatabaseAcquisitionStrategy::VerifiedWalSnapshot) {
    return false;
  }
  let sqlite_error = error.chain().find_map(|cause| {
    let rusqlite::Error::SqliteFailure(error, _) = cause.downcast_ref::<rusqlite::Error>()? else {
      return None;
    };
    Some(*error)
  });
  let Some(error) = sqlite_error else {
    return false;
  };
  matches!(
    error.code,
    rusqlite::ffi::ErrorCode::DatabaseCorrupt | rusqlite::ffi::ErrorCode::NotADatabase
  ) || matches!(
    error.extended_code,
    rusqlite::ffi::SQLITE_IOERR_READ | rusqlite::ffi::SQLITE_IOERR_SHORT_READ
  )
}

const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";
const SQLITE_HEADER_PREFIX_LEN: usize = 20;
const SQLITE_WAL_FORMAT_VERSION: u8 = 2;

/// Reads SQLite's persistent file-header journal-mode bytes without opening a
/// connection. Opening a WAL-mode file to ask `PRAGMA journal_mode` would be
/// circular: SQLite can create the very `-wal`/`-shm` files this check exists
/// to avoid creating in a live profile.
#[cfg(test)]
fn database_uses_wal(database: &Path) -> Result<bool> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  database_uses_wal_with_runtime(database, &runtime)
}

fn database_uses_wal_with_runtime(database: &Path, runtime: &BoundaryRuntime<'_>) -> Result<bool> {
  runtime.check()?;
  let mut file = fs::File::open(database)
    .with_context(|| format!("Can't open database header {REDACTED_PATH}"))?;
  runtime.check()?;
  let mut header = [0_u8; SQLITE_HEADER_PREFIX_LEN];
  let read = fill_with_runtime(&mut file, &mut header, runtime)
    .with_context(|| format!("Can't read database header {REDACTED_PATH}"))?;
  runtime.check()?;
  if read < header.len() || &header[..SQLITE_HEADER.len()] != SQLITE_HEADER {
    return Ok(false);
  }

  Ok(header[18] == SQLITE_WAL_FORMAT_VERSION && header[19] == SQLITE_WAL_FORMAT_VERSION)
}

/// Opens an already-acquired static single-file copy as immutable.
///
/// Taking the opaque proof by value keeps ownership of the private snapshot
/// directory with the returned reader. In particular, this function does not
/// accept a bare path and cannot be used by [`connect`]'s live no-WAL branch.
/// A DB+WAL snapshot is not eligible even when both files are static.
#[allow(dead_code)]
pub(crate) fn open_verified_static_single_file(
  verified: VerifiedStaticSingleFile,
) -> Result<SqliteReader> {
  let VerifiedStaticSingleFile { path, snapshot } = verified;
  ensure_single_file(&path)?;
  Ok(SqliteReader {
    connection: open_read_only(&path, "mode=ro&immutable=1")?,
    snapshot: Some(snapshot),
    strategy: DatabaseAcquisitionStrategy::VerifiedStaticSingleFile,
  })
}

/// Opens a live mutable database and establishes its read snapshot before the
/// connection escapes this module.
#[cfg(test)]
fn open_live_read_only(path: &Path) -> Result<Connection> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  open_live_read_only_with_runtime(path, &runtime)
}

fn open_live_read_only_with_runtime(
  path: &Path,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Connection> {
  runtime.check()?;
  let connection = open_read_only(path, "mode=ro")?;
  runtime.check()?;
  let locking_mode: String = connection
    .query_row("PRAGMA locking_mode=EXCLUSIVE", [], |row| row.get(0))
    .with_context(|| format!("Can't configure sidecar-free locking for {REDACTED_PATH}"))?;
  if !locking_mode.eq_ignore_ascii_case("exclusive") {
    return Err(anyhow!(
      "Can't configure sidecar-free locking for {REDACTED_PATH}: SQLite selected {locking_mode}"
    ));
  }
  runtime.check()?;
  pin_read_snapshot_with_runtime(&connection, path, runtime)?;
  runtime.check()?;
  Ok(connection)
}

/// `BEGIN` alone is deferred and takes no read lock. Reading `sqlite_schema`
/// is what establishes the snapshot and pins the schema for all later cookie
/// queries on this connection.
#[cfg(test)]
fn pin_read_snapshot(connection: &Connection, path: &Path) -> Result<()> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  pin_read_snapshot_with_runtime(connection, path, &runtime)
}

fn pin_read_snapshot_with_runtime(
  connection: &Connection,
  _path: &Path,
  runtime: &BoundaryRuntime<'_>,
) -> Result<()> {
  runtime.check()?;
  connection
    .execute_batch("BEGIN DEFERRED TRANSACTION;")
    .with_context(|| format!("Can't begin read transaction for {REDACTED_PATH}"))?;
  // rusqlite installs a five-second busy timeout on new connections. A
  // single opaque wait cannot observe this request's shorter deadline or a
  // cancellation signal, so turn it into bounded polling and checkpoint the
  // shared runtime between attempts. The independent five-second busy budget
  // preserves the historical maximum wait when the caller keeps the default
  // 30-second extraction deadline.
  connection
    .busy_timeout(std::time::Duration::ZERO)
    .with_context(|| format!("Can't configure lock polling for {REDACTED_PATH}"))?;
  let busy_deadline = Deadline::after(runtime.clock, std::time::Duration::from_secs(5));
  loop {
    runtime.check()?;
    match connection.query_row("SELECT count(*) FROM sqlite_schema", [], |row| {
      row.get::<_, i64>(0)
    }) {
      Ok(_) => break,
      Err(error) if sqlite_is_busy_or_locked(&error) => {
        runtime.check()?;
        let busy_remaining = busy_deadline.remaining(runtime.clock);
        if busy_remaining.is_zero() {
          return Err(
            anyhow::Error::new(error)
              .context(format!("Can't pin database schema for {REDACTED_PATH}")),
          );
        }
        let request_remaining = runtime.deadline.remaining(runtime.clock);
        let pause = std::time::Duration::from_millis(10)
          .min(busy_remaining)
          .min(request_remaining);
        if pause.is_zero() {
          runtime.check()?;
        }
        runtime.clock.sleep(pause);
      }
      Err(error) => {
        return Err(
          anyhow::Error::new(error)
            .context(format!("Can't pin database schema for {REDACTED_PATH}")),
        )
      }
    }
  }
  runtime.check()?;
  Ok(())
}

fn sqlite_is_busy_or_locked(error: &rusqlite::Error) -> bool {
  matches!(
    error.sqlite_error_code(),
    Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
  )
}

/// Rejects sidecars at the immutable boundary even though the opaque proof is
/// the primary eligibility check. This makes it impossible for a DB+WAL pair
/// to start ignoring its WAL because of an acquisition wiring mistake.
#[allow(dead_code)]
fn ensure_single_file(database: &Path) -> Result<()> {
  for suffix in ["-wal", "-shm", "-journal"] {
    let sidecar = sidecar(database, suffix);
    match fs::metadata(&sidecar) {
      Ok(_) => {
        return Err(anyhow!(
          "Immutable database acquisition must contain one file; found {REDACTED_PATH}"
        ))
      }
      Err(error) if error.kind() == io::ErrorKind::NotFound => {}
      Err(error) => {
        return Err(anyhow::Error::new(error).context(format!(
          "Can't verify static database sidecar {REDACTED_PATH}"
        )))
      }
    }
  }
  Ok(())
}

/// How many times a snapshot disturbed by a concurrent WAL write or
/// checkpoint is retaken.
const SNAPSHOT_ATTEMPTS: u32 = 3;

/// Multiplied by the attempt number to space out those retakes.
const RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(20);

/// Copies `database` and its write-ahead log into `directory`, retaking the
/// copy if a database or WAL write raced it, and returns the path of the copy.
///
/// The two files cannot be copied atomically, so a checkpoint landing in the
/// window can leave the pair incoherent: it moves pages into the main file that
/// the copied WAL cannot roll back, which surfaces as missing rows or
/// `SQLITE_CORRUPT`. No copy order avoids this, so the result is verified
/// rather than assumed.
///
/// The main file is copied first, followed by the WAL. Verification then
/// compares main, WAL, and main again. The WAL comparison rejects an append or
/// reset that crossed the copy window instead of letting SQLite silently use
/// the last complete commit in a truncated copy. The second main comparison
/// closes the window in which a checkpoint could land after the first one.
/// Query-level corruption/I/O checks remain the final retry boundary for an
/// incoherent copied pair.
///
/// The copied header must remain WAL-mode. This rejects a source that switched
/// to rollback journaling after routing but before or during copying, because a
/// raw main-file copy is not safe across a rollback-journal transaction.
///
/// The comparison is exact rather than a size and mtime check, because a
/// checkpoint can rewrite same-sized pages inside one filesystem timestamp
/// tick on coarse filesystems such as FAT. The source was just read, so it is
/// in the page cache and the second read is cheap.
#[cfg(test)]
fn snapshot_database(database: &Path, directory: &Path) -> Result<PathBuf> {
  let clock = SystemClock;
  snapshot_database_with_deadline(database, directory, &clock, Deadline::standard())
}

#[cfg(test)]
fn snapshot_database_with_deadline(
  database: &Path,
  directory: &Path,
  clock: &dyn Clock,
  deadline: Deadline,
) -> Result<PathBuf> {
  let runtime = BoundaryRuntime::new(clock, deadline);
  snapshot_database_with_runtime(database, directory, &runtime)
}

fn snapshot_database_with_runtime(
  database: &Path,
  directory: &Path,
  runtime: &BoundaryRuntime<'_>,
) -> Result<PathBuf> {
  snapshot_database_with_after_copy(database, directory, runtime, |_, _| Ok(()))
}

fn snapshot_database_with_after_copy<AfterCopy>(
  database: &Path,
  directory: &Path,
  runtime: &BoundaryRuntime<'_>,
  mut after_copy: AfterCopy,
) -> Result<PathBuf>
where
  AfterCopy: FnMut(u32, &Path) -> Result<()>,
{
  for attempt in 1..=SNAPSHOT_ATTEMPTS {
    runtime.check()?;
    let copy = copy_database_with_runtime(database, directory, runtime)?;
    after_copy(attempt, &copy)?;
    runtime.check()?;
    if !database_uses_wal_with_runtime(&copy, runtime)? {
      return Err(anyhow!(
        "Can't take a WAL snapshot of {REDACTED_PATH}: its copied journal mode is not WAL"
      ));
    }
    runtime.check()?;
    let wal = sidecar(database, "-wal");
    let wal_copy = sidecar(&copy, "-wal");
    if files_are_identical(database, &copy, runtime)?
      && optional_files_are_identical(&wal, &wal_copy, runtime)?
      && files_are_identical(database, &copy, runtime)?
    {
      return Ok(copy);
    }

    log::debug!(
      "a database or WAL write raced the snapshot of {REDACTED_PATH} (attempt {attempt} of {SNAPSHOT_ATTEMPTS})"
    );
    // Back off before retaking it. A browser that just wrote or checkpointed
    // is likely mid-burst, and copying straight back into that loses the next
    // attempt to the same race.
    let backoff = RETRY_BACKOFF * attempt;
    let remaining = runtime.deadline.remaining(runtime.clock);
    if remaining <= backoff {
      runtime.check()?;
      return Err(crate::common::deadline::BoundaryStop::TimedOut.into());
    }
    runtime.clock.sleep(backoff);
    runtime.check()?;
  }

  Err(anyhow!(
    "Can't take a coherent snapshot of {REDACTED_PATH}: its database or WAL is changing repeatedly"
  ))
}

/// Compares sidecars that may legitimately be absent from both source and
/// snapshot. A one-sided absence means the source changed during acquisition.
fn optional_files_are_identical(
  left: &Path,
  right: &Path,
  runtime: &BoundaryRuntime<'_>,
) -> Result<bool> {
  runtime.check()?;
  let open = |path: &Path| -> Result<Option<io::BufReader<fs::File>>> {
    runtime.check()?;
    match fs::File::open(path) {
      Ok(file) => {
        runtime.check()?;
        Ok(Some(io::BufReader::new(file)))
      }
      Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
      Err(error) => {
        Err(anyhow::Error::new(error).context(format!("Can't open {REDACTED_PATH} to verify it")))
      }
    }
  };
  match (open(left)?, open(right)?) {
    (None, None) => Ok(true),
    (Some(_), None) | (None, Some(_)) => Ok(false),
    (Some(left), Some(right)) => readers_are_identical(left, right, runtime),
  }
}

/// Compares two files byte for byte.
///
/// Only a genuine difference in length or content answers `false`. An I/O fault
/// is returned, so that `snapshot_database` reports it rather than retrying
/// three times and blaming a checkpoint.
pub(crate) fn files_are_identical(
  left: &Path,
  right: &Path,
  runtime: &BoundaryRuntime<'_>,
) -> Result<bool> {
  runtime.check()?;
  let open = |path: &Path| -> Result<io::BufReader<fs::File>> {
    runtime.check()?;
    let file =
      fs::File::open(path).with_context(|| format!("Can't open {REDACTED_PATH} to verify it"))?;
    runtime.check()?;
    Ok(io::BufReader::new(file))
  };
  readers_are_identical(open(left)?, open(right)?, runtime)
}

fn readers_are_identical(
  mut left_file: io::BufReader<fs::File>,
  mut right_file: io::BufReader<fs::File>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<bool> {
  let (mut left_chunk, mut right_chunk) = ([0u8; 8192], [0u8; 8192]);

  loop {
    runtime.check()?;
    let filled = fill_with_runtime(&mut left_file, &mut left_chunk, runtime)
      .with_context(|| format!("Can't read {REDACTED_PATH}"))?;
    let other = fill_with_runtime(&mut right_file, &mut right_chunk, runtime)
      .with_context(|| format!("Can't read {REDACTED_PATH}"))?;
    runtime.check()?;

    // `fill` stops short only at end of file, so unequal counts mean unequal
    // lengths.
    if filled != other || left_chunk[..filled] != right_chunk[..other] {
      return Ok(false);
    }
    if filled == 0 {
      return Ok(true);
    }
  }
}

/// Reads until `buffer` is full or the file ends, retrying interrupted reads
/// the way [`io::Read::read_exact`] does.
fn fill_with_runtime(
  source: &mut impl io::Read,
  buffer: &mut [u8],
  runtime: &BoundaryRuntime<'_>,
) -> Result<usize> {
  let mut filled = 0;

  while filled < buffer.len() {
    runtime.check()?;
    match source.read(&mut buffer[filled..]) {
      Ok(0) => {
        runtime.check()?;
        break;
      }
      Ok(read) => {
        runtime.check()?;
        filled += read;
      }
      Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
      Err(err) => return Err(err.into()),
    }
  }

  Ok(filled)
}

/// Copies `database` and its write-ahead log into `directory`, returning the
/// path of the copy.
///
/// `directory` must stay writable. A read-only connection can only open a
/// WAL-mode database if it can build the wal-index, and since no `-shm` is
/// copied, SQLite recovers one from the `-wal` by creating `<name>-shm` here
/// (<https://sqlite.org/wal.html> section 5, condition 2).
#[cfg(test)]
fn copy_database(database: &Path, directory: &Path) -> Result<PathBuf> {
  let clock = SystemClock;
  copy_database_with_deadline(database, directory, &clock, Deadline::standard())
}

#[cfg(test)]
fn copy_database_with_deadline(
  database: &Path,
  directory: &Path,
  clock: &dyn Clock,
  deadline: Deadline,
) -> Result<PathBuf> {
  let runtime = BoundaryRuntime::new(clock, deadline);
  copy_database_with_runtime(database, directory, &runtime)
}

fn copy_database_with_runtime(
  database: &Path,
  directory: &Path,
  runtime: &BoundaryRuntime<'_>,
) -> Result<PathBuf> {
  runtime.check()?;
  let name = database
    .file_name()
    .ok_or_else(|| anyhow!("Database path has no file name: {REDACTED_PATH}"))?;
  let copy = directory.join(name);

  // The main file goes first so that `snapshot_database` can bracket this whole
  // sequence by comparing it against the live source afterwards. On its own
  // this order is the unsafe one — a checkpoint in between pairs a stale main
  // file with a WAL rewound to offset 0 (<https://sqlite.org/wal.html> section
  // 2.1) and drops rows, as `an_unverified_copy_loses_rows_when_a_checkpoint_intervenes`
  // shows — so the verification is what makes it correct, not the order.
  copy_file_with_runtime(database, &copy, runtime)
    .with_context(|| format!("Can't copy database {REDACTED_PATH}"))?;

  // The `-shm` is deliberately left behind: it is a rebuildable index over the
  // WAL, absent entirely when the writer uses exclusive locking, and a copied
  // one could be believed as-is, pinning a stale frame count.
  let wal = sidecar(database, "-wal");
  let wal_copy = sidecar(&copy, "-wal");
  runtime.check()?;
  match copy_file_with_runtime(&wal, &wal_copy, runtime) {
    Ok(()) => {}
    // The browser checkpointed and removed its WAL, either before this attempt
    // or in the moment between. Discard any WAL an earlier attempt left here,
    // which would otherwise replay over a newer main file and hide rows, and
    // let the verification decide whether this attempt stands.
    Err(err)
      if err
        .downcast_ref::<io::Error>()
        .is_some_and(|error| error.kind() == io::ErrorKind::NotFound) =>
    {
      runtime.check()?;
      match fs::remove_file(&wal_copy) {
        Ok(()) => {}
        // Nothing to discard, which is the usual case on a first attempt.
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
          return Err(
            anyhow::Error::new(err)
              .context(format!("Can't discard the stale copy {REDACTED_PATH}")),
          )
        }
      }
    }
    Err(err) => return Err(err.context(format!("Can't copy write-ahead log {REDACTED_PATH}"))),
  }

  runtime.check()?;
  Ok(copy)
}

fn copy_file_with_runtime(
  source: &Path,
  destination: &Path,
  runtime: &BoundaryRuntime<'_>,
) -> Result<()> {
  runtime.check()?;
  let mut source = io::BufReader::new(fs::File::open(source)?);
  runtime.check()?;
  let mut destination = io::BufWriter::new(fs::File::create(destination)?);
  runtime.check()?;
  copy_stream_with_runtime(&mut source, &mut destination, runtime)
}

fn copy_stream_with_runtime(
  source: &mut impl io::Read,
  destination: &mut impl io::Write,
  runtime: &BoundaryRuntime<'_>,
) -> Result<()> {
  let mut chunk = [0_u8; 64 * 1024];
  loop {
    runtime.check()?;
    let read = source.read(&mut chunk)?;
    runtime.check()?;
    if read == 0 {
      break;
    }
    destination.write_all(&chunk[..read])?;
    runtime.check()?;
  }
  destination.flush()?;
  runtime.check()?;
  Ok(())
}

/// True when a non-empty `-wal` sidecar sits beside the database.
///
/// Deliberately conservative rather than exact: a checkpoint does not normally
/// truncate the `-wal`, so this over-reports pending frames and takes the
/// snapshot path for a WAL that is already fully checkpointed. Over-copying is
/// harmless; under-copying would drop cookies.
///
/// Only a missing sidecar means "no WAL". Any other stat failure is reported,
/// because answering `false` could otherwise route a WAL-mode source into the
/// live rollback-journal path.
#[cfg(test)]
pub(crate) fn has_nonempty_wal(database: &Path) -> Result<bool> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  has_nonempty_wal_with_runtime(database, &runtime)
}

pub(crate) fn has_nonempty_wal_with_runtime(
  database: &Path,
  runtime: &BoundaryRuntime<'_>,
) -> Result<bool> {
  runtime.check()?;
  let wal = sidecar(database, "-wal");
  let result = match fs::metadata(&wal) {
    Ok(metadata) => Ok(metadata.len() > 0),
    Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
    Err(err) => {
      Err(anyhow::Error::new(err).context(format!("Can't stat write-ahead log {REDACTED_PATH}")))
    }
  };
  runtime.check()?;
  result
}

/// Builds a SQLite sidecar path by appending `suffix` to the database path,
/// the same way SQLite names its own `-wal` and `-shm` files.
pub(crate) fn sidecar(database: &Path, suffix: &str) -> PathBuf {
  let mut name = OsString::from(database);
  name.push(suffix);
  PathBuf::from(name)
}

fn open_read_only(path: &Path, query: &str) -> Result<Connection> {
  let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI;
  let url =
    Url::from_file_path(path).map_err(|_| anyhow!("Can't build a file URL for {REDACTED_PATH}"))?;
  let connection = Connection::open_with_flags(format!("{url}?{query}"), flags)
    .with_context(|| format!("Can't open {REDACTED_PATH} for reading"))?;
  Ok(connection)
}

#[cfg(test)]
mod tests;
