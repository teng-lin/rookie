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
/// cannot starve the writer, at the cost of a copy that is not atomic and so
/// has to be checked for a racing checkpoint (see [`snapshot_database`]).
///
/// Databases with no `-wal` are read in place as `immutable`, which likewise
/// takes no locks.
pub fn connect(path: PathBuf) -> Result<SqliteReader> {
  let path = path
    .canonicalize()
    .with_context(|| format!("Can't resolve database path {}", path.display()))?;

  let reader = if has_nonempty_wal(&path)? {
    // A snapshot failure is deliberately fatal rather than a fall back to the
    // `immutable` read: that read silently omits the WAL cookies, which is the
    // defect this function exists to fix. `load()` reports a per-browser error
    // and carries on, so a loud failure costs one browser, not the whole call.
    let snapshot = TempDir::new()?;
    let copy = snapshot_database(&path, snapshot.path())?;
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

/// How many times a snapshot torn by a concurrent checkpoint is retaken.
const SNAPSHOT_ATTEMPTS: u32 = 3;

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
/// after the WAL copy, so the comparison brackets *both* copies: a checkpoint
/// anywhere in the window leaves the source different from the image taken at
/// the start, and the attempt is discarded. In WAL mode a checkpoint is the
/// only thing that writes the main file, so a source that never moved means the
/// copied WAL is still the only thing between it and the browser's current
/// state. Ordinary commits only append to the `-wal`, and frames appended after
/// it was copied are simply unseen, which reads as an earlier instant.
///
/// The comparison is exact rather than a size and mtime check, because a
/// checkpoint can rewrite same-sized pages inside one filesystem timestamp
/// tick on coarse filesystems such as FAT. The source was just read, so it is
/// in the page cache and the second read is cheap.
fn snapshot_database(database: &Path, directory: &Path) -> Result<PathBuf> {
  for attempt in 1..=SNAPSHOT_ATTEMPTS {
    let copy = copy_database(database, directory)?;
    if files_are_identical(database, &copy)? {
      return Ok(copy);
    }

    log::debug!(
      "a checkpoint raced the snapshot of {} (attempt {attempt} of {SNAPSHOT_ATTEMPTS})",
      database.display()
    );
  }

  Err(anyhow!(
    "Can't take a coherent snapshot of {}: it is being checkpointed repeatedly",
    database.display()
  ))
}

/// Compares two files byte for byte.
pub(crate) fn files_are_identical(left: &Path, right: &Path) -> Result<bool> {
  let open = |path: &Path| -> Result<io::BufReader<fs::File>> {
    let file = fs::File::open(path)
      .with_context(|| format!("Can't open {} to verify it", path.display()))?;
    Ok(io::BufReader::new(file))
  };
  let (mut left, mut right) = (open(left)?, open(right)?);
  let (mut left_chunk, mut right_chunk) = ([0u8; 8192], [0u8; 8192]);

  loop {
    let read = io::Read::read(&mut left, &mut left_chunk)?;
    if read == 0 {
      // Equal only if the other side is also exhausted.
      return Ok(io::Read::read(&mut right, &mut right_chunk)? == 0);
    }
    if io::Read::read_exact(&mut right, &mut right_chunk[..read]).is_err()
      || left_chunk[..read] != right_chunk[..read]
    {
      return Ok(false);
    }
  }
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
    Err(err) if err.kind() == io::ErrorKind::NotFound => {
      if wal_copy.exists() {
        fs::remove_file(&wal_copy)
          .with_context(|| format!("Can't discard the stale copy {}", wal_copy.display()))?;
      }
    }
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
/// because answering `false` would route to the `immutable` read that ignores
/// the WAL and returns a short cookie list as though it were complete.
fn has_nonempty_wal(database: &Path) -> Result<bool> {
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
    assert!(has_nonempty_wal(&path.canonicalize().expect("canonicalize")).expect("stat wal"));

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
