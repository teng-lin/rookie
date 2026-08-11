use crate::utils::TempDir;
use anyhow::{anyhow, Context, Result};
use rusqlite::{Connection, OpenFlags};
use std::ffi::OsString;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::{fs, io};
use url::Url;

/// A read-only connection to a browser database.
///
/// Dereferences to [`Connection`], so callers query it like any other
/// `rusqlite` connection. When the database had a write-ahead log, the
/// connection reads a point-in-time copy rather than the live file, so results
/// are as of the moment [`connect`] was called.
pub struct SqliteReader {
  // Declaration order is load-bearing: `connection` must drop before
  // `snapshot` so the database files are closed before the directory holding
  // them is removed (Windows refuses to delete open files). POSIX allows
  // unlinking open files, so `snapshot_is_removed_once_the_reader_drops`
  // cannot catch a reordering here — only the Windows CI job can.
  connection: Connection,
  snapshot: Option<TempDir>,
}

impl SqliteReader {
  /// The private directory holding the snapshot, or `None` when the database
  /// was read in place.
  pub(crate) fn snapshot_path(&self) -> Option<&Path> {
    self.snapshot.as_ref().map(TempDir::path)
  }
}

impl Deref for SqliteReader {
  type Target = Connection;

  fn deref(&self) -> &Connection {
    &self.connection
  }
}

/// Opens a browser database for reading.
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
/// cannot starve the writer, at the cost of a snapshot that is best-effort
/// rather than atomic (see [`copy_database`]).
///
/// Databases with no `-wal` are read in place as `immutable`, which likewise
/// takes no locks.
pub fn connect(path: PathBuf) -> Result<SqliteReader> {
  let path = path
    .canonicalize()
    .with_context(|| format!("Can't resolve database path {}", path.display()))?;

  let reader = if has_nonempty_wal(&path) {
    // A snapshot failure is deliberately fatal rather than a fall back to the
    // `immutable` read: that read silently omits the WAL cookies, which is the
    // defect this function exists to fix. `load()` reports a per-browser error
    // and carries on, so a loud failure costs one browser, not the whole call.
    let snapshot = TempDir::new()?;
    let copy = copy_database(&path, snapshot.path())?;
    SqliteReader {
      // Deliberately not `immutable`: that flag tells SQLite to ignore the
      // `-wal`, which is the data this snapshot exists to recover.
      connection: open_read_only(&copy, "mode=ro")?,
      snapshot: Some(snapshot),
    }
  } else {
    SqliteReader {
      connection: open_read_only(&path, "mode=ro&immutable=1")?,
      snapshot: None,
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

  // Copy the WAL *before* the main database. The two copies cannot be taken
  // atomically, and a checkpoint only ever moves pages out of the WAL and into
  // the main file, so pairing an older WAL with a newer main file is safe:
  // replaying a frame whose page the checkpoint already wrote just rewrites
  // identical bytes. Frames appended after this copy are simply not seen, which
  // reads as an earlier instant rather than as loss. The opposite order is not
  // safe — a checkpoint landing between the copies rewinds the WAL to offset 0
  // (<https://sqlite.org/wal.html> section 2.1), pairing a stale main file with
  // frames it has never seen, which surfaces as missing rows or SQLITE_CORRUPT.
  //
  // The `-shm` is deliberately left behind: it is a rebuildable index over the
  // WAL, absent entirely when the writer uses exclusive locking, and a copied
  // one could be believed as-is, pinning a stale frame count.
  let wal = sidecar(database, "-wal");
  if wal.exists() {
    let wal_copy = sidecar(&copy, "-wal");
    fs::copy(&wal, &wal_copy)
      .with_context(|| format!("Can't copy write-ahead log {}", wal.display()))?;
  }

  fs::copy(database, &copy)
    .with_context(|| format!("Can't copy database {}", database.display()))?;

  Ok(copy)
}

/// True when a non-empty `-wal` sidecar sits beside the database.
///
/// Deliberately conservative rather than exact: a checkpoint does not normally
/// truncate the `-wal`, so this over-reports pending frames and takes the
/// snapshot path for a WAL that is already fully checkpointed. Over-copying is
/// harmless; under-copying would drop cookies.
fn has_nonempty_wal(database: &Path) -> bool {
  let wal = sidecar(database, "-wal");
  match fs::metadata(&wal) {
    Ok(metadata) => metadata.len() > 0,
    Err(err) if err.kind() == io::ErrorKind::NotFound => false,
    Err(err) => {
      // Treating this as "no WAL" would silently fall back to the `immutable`
      // read that omits WAL cookies, so say so rather than swallowing it.
      log::warn!(
        "Can't stat {}: {err}; reading without its write-ahead log, which may omit recent cookies",
        wal.display()
      );
      false
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
  fn reads_rows_committed_to_an_active_wal() {
    let directory = TempDir::new().expect("temp dir");
    let (path, writer) = checkpointed_database(directory.path());

    writer
      .execute("INSERT INTO cookies (name) VALUES ('in-wal')", [])
      .expect("insert WAL row");
    // The writer stays open and the fixture is far below the 1000-page
    // autocheckpoint threshold, so the row stays in the -wal.
    assert!(has_nonempty_wal(
      &path.canonicalize().expect("canonicalize")
    ));

    let reader = connect(path.clone()).expect("connect");

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

  /// The counterpart to the test above: copying the main database first is the
  /// ordering that loses data, which is why [`copy_database`] takes the `-wal`
  /// first. Characterizes SQLite, so it cannot fail from a rookie regression.
  #[test]
  fn copying_the_database_before_the_wal_loses_rows() {
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
    };

    // The checkpoint moved 'in-wal' into the real main file and rewound the
    // WAL, but this pair holds the pre-checkpoint main file and the rewound
    // WAL, so the row is in neither.
    assert_eq!(cookie_names(&reader), vec!["checkpointed"]);
  }

  /// The two copies cannot be taken atomically. Copying the `-wal` first means
  /// a checkpoint landing between them leaves an older WAL paired with a newer
  /// main file, which replays without loss; the opposite order drops rows.
  #[test]
  fn snapshot_survives_a_checkpoint_between_the_two_copies() {
    let directory = TempDir::new().expect("temp dir");
    let (path, writer) = checkpointed_database(directory.path());
    writer
      .execute("INSERT INTO cookies (name) VALUES ('in-wal')", [])
      .expect("insert WAL row");

    let snapshot = TempDir::new().expect("snapshot dir");
    let copy = snapshot.path().join("Cookies");

    // First half of `copy_database`.
    fs::copy(sidecar(&path, "-wal"), sidecar(&copy, "-wal")).expect("copy wal");

    // A checkpoint races in, folding the WAL into the main file and rewinding
    // it, then the browser writes again.
    writer
      .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
      .expect("checkpoint");
    writer
      .execute("INSERT INTO cookies (name) VALUES ('after-checkpoint')", [])
      .expect("insert post-checkpoint row");

    // Second half of `copy_database`, now reading a main file the checkpoint
    // has already advanced.
    fs::copy(&path, &copy).expect("copy database");

    let reader = SqliteReader {
      connection: open_read_only(&copy, "mode=ro").expect("open snapshot"),
      snapshot: Some(snapshot),
    };

    // Nothing committed before the WAL copy may go missing. Rows written after
    // it may or may not appear, which is a read as of an earlier instant.
    let names = cookie_names(&reader);
    assert!(names.contains(&"checkpointed".to_string()), "{names:?}");
    assert!(names.contains(&"in-wal".to_string()), "{names:?}");
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
      reader.snapshot_path().is_none(),
      "a database with no pending WAL is read in place"
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

    let reader = connect(path).expect("connect");

    assert_eq!(cookie_names(&reader), vec!["no-wal"]);
    assert!(
      reader.snapshot_path().is_none(),
      "a database with no WAL is read in place"
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
