use crate::utils::TempDir;
use anyhow::{anyhow, Context, Result};
use rusqlite::{Connection, OpenFlags};
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
/// returns, it begins a read transaction and reads the schema, pinning a
/// coherent SQLite snapshot. An active rollback-journal writer therefore
/// either permits that coherent read or returns SQLite's typed busy/locked
/// error; this path never raw-copies or immutably opens the live database.
#[allow(dead_code)]
pub fn connect(path: PathBuf) -> Result<SqliteReader> {
  acquire_browser_database(path).map_err(|failure| failure.error)
}

fn acquire_browser_database(
  path: PathBuf,
) -> std::result::Result<SqliteReader, DatabaseAcquisitionFailure> {
  let path = path
    .canonicalize()
    .with_context(|| format!("Can't resolve database path {}", path.display()))
    .map_err(|error| DatabaseAcquisitionFailure {
      strategy: None,
      error,
    })?;

  let has_wal = has_nonempty_wal(&path).map_err(|error| DatabaseAcquisitionFailure {
    strategy: None,
    error,
  })?;
  let uses_wal = has_wal
    || database_uses_wal(&path).map_err(|error| DatabaseAcquisitionFailure {
      strategy: None,
      error,
    })?;
  let reader = if uses_wal {
    acquire_verified_wal_snapshot(&path)?
  } else {
    let strategy = DatabaseAcquisitionStrategy::LiveReadOnly;
    SqliteReader {
      connection: open_live_read_only(&path).map_err(|error| DatabaseAcquisitionFailure {
        strategy: Some(strategy),
        error,
      })?,
      snapshot: None,
      strategy,
    }
  };

  match reader.snapshot_path() {
    Some(directory) => log::debug!(
      "reading {} through a snapshot in {}",
      path.display(),
      directory.display()
    ),
    None => log::debug!("reading {} in place", path.display()),
  }

  Ok(reader)
}

fn acquire_verified_wal_snapshot(
  path: &Path,
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
  let copy =
    snapshot_database(path, snapshot.path()).map_err(|error| DatabaseAcquisitionFailure {
      strategy: Some(strategy),
      error,
    })?;
  Ok(SqliteReader {
    // Deliberately not `immutable`: that flag tells SQLite to ignore the
    // `-wal`, which is the data this snapshot exists to recover.
    connection: open_read_only(&copy, "mode=ro").map_err(|error| DatabaseAcquisitionFailure {
      strategy: Some(strategy),
      error,
    })?,
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
pub(crate) fn with_browser_database<T, Query>(
  path: PathBuf,
  query: Query,
) -> Result<BrowserDatabaseOutcome<T>>
where
  Query: FnMut(&Connection) -> Result<T>,
{
  with_browser_database_using(|| acquire_browser_database(path.clone()), query)
}

/// Query-level attempts are separate from the lower-level copy verification
/// attempts in `snapshot_database`: these rerun the complete SQLite query after
/// a successfully copied image proves unusable.
const BROWSER_DATABASE_ATTEMPTS: u32 = 3;

fn with_browser_database_using<T, Acquire, Query>(
  mut acquire: Acquire,
  mut query: Query,
) -> Result<BrowserDatabaseOutcome<T>>
where
  Acquire: FnMut() -> std::result::Result<SqliteReader, DatabaseAcquisitionFailure>,
  Query: FnMut(&Connection) -> Result<T>,
{
  for attempt in 1..=BROWSER_DATABASE_ATTEMPTS {
    let reader = match acquire() {
      Ok(reader) => reader,
      Err(failure) => {
        let retryable = is_retryable_snapshot_error(failure.strategy, &failure.error);
        if retryable && attempt < BROWSER_DATABASE_ATTEMPTS {
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
    match query(&reader) {
      Ok(value) => {
        // Drop the connection (then its snapshot directory) before returning a
        // value that is independent of the database attempt.
        drop(reader);
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
fn database_uses_wal(database: &Path) -> Result<bool> {
  let mut file = fs::File::open(database)
    .with_context(|| format!("Can't open database header {}", database.display()))?;
  let mut header = [0_u8; SQLITE_HEADER_PREFIX_LEN];
  let read = fill(&mut file, &mut header)
    .with_context(|| format!("Can't read database header {}", database.display()))?;
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
fn open_live_read_only(path: &Path) -> Result<Connection> {
  let connection = open_read_only(path, "mode=ro")?;
  pin_read_snapshot(&connection, path)?;
  Ok(connection)
}

/// `BEGIN` alone is deferred and takes no read lock. Reading `sqlite_schema`
/// is what establishes the snapshot and pins the schema for all later cookie
/// queries on this connection.
fn pin_read_snapshot(connection: &Connection, path: &Path) -> Result<()> {
  connection
    .execute_batch("BEGIN DEFERRED TRANSACTION;")
    .with_context(|| format!("Can't begin read transaction for {}", path.display()))?;
  let _: i64 = connection
    .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
    .with_context(|| format!("Can't pin database schema for {}", path.display()))?;
  Ok(())
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
          "Immutable database acquisition must contain one file; found {}",
          sidecar.display()
        ))
      }
      Err(error) if error.kind() == io::ErrorKind::NotFound => {}
      Err(error) => {
        return Err(anyhow::Error::new(error).context(format!(
          "Can't verify static database sidecar {}",
          sidecar.display()
        )))
      }
    }
  }
  Ok(())
}

/// How many times a snapshot torn by a concurrent checkpoint is retaken.
const SNAPSHOT_ATTEMPTS: u32 = 3;

/// Multiplied by the attempt number to space out those retakes.
const RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(20);

/// Copies `database` and its write-ahead log into `directory`, retaking the
/// copy if a checkpoint raced it, and returns the path of the copy.
///
/// The two files cannot be copied atomically, so a checkpoint landing in the
/// window can leave the pair incoherent: it moves pages into the main file that
/// the copied WAL cannot roll back, which surfaces as missing rows or
/// `SQLITE_CORRUPT`. No copy order avoids this, so the result is verified
/// rather than assumed.
///
/// The main file is copied first and compared against the live source only
/// after the WAL copy. A checkpoint that completes across that window changes
/// the source and discards the attempt. A checkpoint paused across both reads
/// can make them agree on the same partial main file, but its WAL still exists
/// and is copied beside that file; SQLite replays the copied committed frames
/// over the partial checkpoint. If no WAL is copied, a checkpoint could not
/// have remained partial through the WAL-copy step, so an incomplete main copy
/// cannot pass the later comparison. Query-level corruption/I/O checks remain
/// the final retry boundary for an incoherent copied pair.
///
/// The copied header must remain WAL-mode. This rejects a source that switched
/// to rollback journaling after routing but before or during copying, because a
/// raw main-file copy is not safe across a rollback-journal transaction.
///
/// The comparison is exact rather than a size and mtime check, because a
/// checkpoint can rewrite same-sized pages inside one filesystem timestamp
/// tick on coarse filesystems such as FAT. The source was just read, so it is
/// in the page cache and the second read is cheap.
fn snapshot_database(database: &Path, directory: &Path) -> Result<PathBuf> {
  for attempt in 1..=SNAPSHOT_ATTEMPTS {
    let copy = copy_database(database, directory)?;
    if !database_uses_wal(&copy)? {
      return Err(anyhow!(
        "Can't take a WAL snapshot of {}: its copied journal mode is not WAL",
        database.display()
      ));
    }
    if files_are_identical(database, &copy)? {
      return Ok(copy);
    }

    log::debug!(
      "a checkpoint raced the snapshot of {} (attempt {attempt} of {SNAPSHOT_ATTEMPTS})",
      database.display()
    );
    // Back off before retaking it. A browser that just checkpointed is likely
    // mid-burst, and copying straight back into that loses the next attempt to
    // the same race.
    std::thread::sleep(RETRY_BACKOFF * attempt);
  }

  Err(anyhow!(
    "Can't take a coherent snapshot of {}: it is being checkpointed repeatedly",
    database.display()
  ))
}

/// Compares two files byte for byte.
///
/// Only a genuine difference in length or content answers `false`. An I/O fault
/// is returned, so that `snapshot_database` reports it rather than retrying
/// three times and blaming a checkpoint.
pub(crate) fn files_are_identical(left: &Path, right: &Path) -> Result<bool> {
  let open = |path: &Path| -> Result<io::BufReader<fs::File>> {
    let file = fs::File::open(path)
      .with_context(|| format!("Can't open {} to verify it", path.display()))?;
    Ok(io::BufReader::new(file))
  };
  let (mut left_file, mut right_file) = (open(left)?, open(right)?);
  let (mut left_chunk, mut right_chunk) = ([0u8; 8192], [0u8; 8192]);

  loop {
    let filled = fill(&mut left_file, &mut left_chunk)
      .with_context(|| format!("Can't read {}", left.display()))?;
    let other = fill(&mut right_file, &mut right_chunk)
      .with_context(|| format!("Can't read {}", right.display()))?;

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
fn fill(source: &mut impl io::Read, buffer: &mut [u8]) -> io::Result<usize> {
  let mut filled = 0;

  while filled < buffer.len() {
    match source.read(&mut buffer[filled..]) {
      Ok(0) => break,
      Ok(read) => filled += read,
      Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
      Err(err) => return Err(err),
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
fn copy_database(database: &Path, directory: &Path) -> Result<PathBuf> {
  let name = database
    .file_name()
    .ok_or_else(|| anyhow!("Database path has no file name: {}", database.display()))?;
  let copy = directory.join(name);

  // The main file goes first so that `snapshot_database` can bracket this whole
  // sequence by comparing it against the live source afterwards. On its own
  // this order is the unsafe one — a checkpoint in between pairs a stale main
  // file with a WAL rewound to offset 0 (<https://sqlite.org/wal.html> section
  // 2.1) and drops rows, as `an_unverified_copy_loses_rows_when_a_checkpoint_intervenes`
  // shows — so the verification is what makes it correct, not the order.
  fs::copy(database, &copy)
    .with_context(|| format!("Can't copy database {}", database.display()))?;

  // The `-shm` is deliberately left behind: it is a rebuildable index over the
  // WAL, absent entirely when the writer uses exclusive locking, and a copied
  // one could be believed as-is, pinning a stale frame count.
  let wal = sidecar(database, "-wal");
  let wal_copy = sidecar(&copy, "-wal");
  match fs::copy(&wal, &wal_copy) {
    Ok(_) => {}
    // The browser checkpointed and removed its WAL, either before this attempt
    // or in the moment between. Discard any WAL an earlier attempt left here,
    // which would otherwise replay over a newer main file and hide rows, and
    // let the verification decide whether this attempt stands.
    Err(err) if err.kind() == io::ErrorKind::NotFound => match fs::remove_file(&wal_copy) {
      Ok(()) => {}
      // Nothing to discard, which is the usual case on a first attempt.
      Err(err) if err.kind() == io::ErrorKind::NotFound => {}
      Err(err) => {
        return Err(anyhow::Error::new(err).context(format!(
          "Can't discard the stale copy {}",
          wal_copy.display()
        )))
      }
    },
    Err(err) => {
      return Err(
        anyhow::Error::new(err).context(format!("Can't copy write-ahead log {}", wal.display())),
      )
    }
  }

  Ok(copy)
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
pub(crate) fn has_nonempty_wal(database: &Path) -> Result<bool> {
  let wal = sidecar(database, "-wal");
  match fs::metadata(&wal) {
    Ok(metadata) => Ok(metadata.len() > 0),
    Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
    Err(err) => {
      Err(anyhow::Error::new(err).context(format!("Can't stat write-ahead log {}", wal.display())))
    }
  }
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
  let url = Url::from_file_path(path)
    .map_err(|_| anyhow!("Can't build a file URL for {}", path.display()))?;
  let connection = Connection::open_with_flags(format!("{url}?{query}"), flags)
    .with_context(|| format!("Can't open {} for reading", path.display()))?;
  Ok(connection)
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::cell::{Cell, RefCell};

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
      files_are_identical(&path, &copy).expect("compare"),
      "a WAL commit must not touch the main file"
    );

    writer
      .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
      .expect("checkpoint");

    assert!(
      !files_are_identical(&path, &copy).expect("compare"),
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

    assert!(files_are_identical(&a, &b).expect("compare equal"));
    assert!(!files_are_identical(&a, &c).expect("compare shorter"));
    assert!(!files_are_identical(&c, &a).expect("compare longer"));
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
    assert!(files_are_identical(&a, &b).expect("compare equal"));

    // Differ only in the final chunk, past several identical ones.
    let mut tail = bulk.clone();
    *tail.last_mut().expect("non-empty") = b'x';
    fs::write(&b, &tail).expect("rewrite b");

    assert!(!files_are_identical(&a, &b).expect("compare differing tail"));
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
    fs::set_permissions(directory.path(), original_permissions)
      .expect("restore source permissions");
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

    let result = connect(directory.path().join("absent.sqlite"));

    assert!(result.is_err(), "missing database must error");
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
}
