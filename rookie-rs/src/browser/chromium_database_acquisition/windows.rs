use super::{
  classify_windows_sharing_violation_with_probe, with_windows_locked_database_policy,
  WindowsFallbackSource, WindowsLockedDatabasePolicy, WindowsLockedFile, WindowsSharingViolation,
};
use crate::common::sqlite;
use anyhow::{anyhow, Result};
use std::path::Path;

fn probe_windows_sharing_violation(
  db_path: &Path,
  include_wal: bool,
) -> Option<WindowsSharingViolation> {
  let wal_path = sqlite::sidecar(db_path, "-wal");
  let wal_metadata = std::fs::metadata(&wal_path);
  let has_verified_nonempty_wal = wal_metadata
    .as_ref()
    .is_ok_and(|metadata| metadata.len() > 0);

  if let Err(error) = std::fs::File::open(db_path) {
    if let Some(code) = super::windows_sharing_code(&error) {
      return Some(WindowsSharingViolation {
        locked_file: WindowsLockedFile::Database,
        locked_path: db_path.to_path_buf(),
        has_verified_nonempty_wal,
        os_error: code,
      });
    }
  }

  if !include_wal {
    return None;
  }

  if let Err(error) = &wal_metadata {
    if let Some(code) = super::windows_sharing_code(error) {
      return Some(WindowsSharingViolation {
        locked_file: WindowsLockedFile::WriteAheadLog,
        locked_path: wal_path,
        // A share-denied metadata lookup cannot prove that the WAL is
        // nonempty, so it is ineligible for raw-copy fallback.
        has_verified_nonempty_wal: false,
        os_error: code,
      });
    }
    return None;
  }

  if has_verified_nonempty_wal {
    if let Err(error) = std::fs::File::open(&wal_path) {
      if let Some(code) = super::windows_sharing_code(&error) {
        return Some(WindowsSharingViolation {
          locked_file: WindowsLockedFile::WriteAheadLog,
          locked_path: wal_path,
          has_verified_nonempty_wal: true,
          os_error: code,
        });
      }
    }
  }

  None
}

fn classify_windows_sharing_violation(
  db_path: &Path,
  error: &anyhow::Error,
) -> Option<WindowsSharingViolation> {
  classify_windows_sharing_violation_with_probe(db_path, error, probe_windows_sharing_violation)
}

fn create_windows_shadow_source(
  db_path: &Path,
) -> Result<WindowsFallbackSource<crate::utils::TempDir>> {
  let temp_dir = crate::utils::TempDir::new()?;
  crate::windows::shadow_copy::shadow_copy(db_path.to_path_buf(), temp_dir.path().to_path_buf())?;
  let file_name = db_path
    .file_name()
    .ok_or_else(|| anyhow!("Database path has no file name: {}", db_path.display()))?;
  let path = temp_dir.path().join(file_name);
  Ok(WindowsFallbackSource {
    path,
    _guard: temp_dir,
  })
}

fn release_windows_lock(locked_path: &Path) -> bool {
  // SAFETY: This wrapper is only called when the public `force_kill` choice
  // selected the disruptive policy. Restart Manager owns the registered path
  // for the duration of its internal session.
  unsafe {
    match crate::windows::restart_manager::release_file_lock(&locked_path.to_string_lossy(), true) {
      Ok(
        crate::windows::restart_manager::FileLockStatus::Unlocked
        | crate::windows::restart_manager::FileLockStatus::Released { .. },
      ) => true,
      Ok(crate::windows::restart_manager::FileLockStatus::Locked { .. }) => false,
      Err(error) => {
        log::warn!("Restart Manager could not release the Windows database lock: {error}");
        false
      }
    }
  }
}

/// Runs a source-inspection query through the non-disruptive locked-file
/// recovery policy used before `any_browser` selects a decoder.
pub(crate) fn with_non_disruptive_recovery<T, Query>(db_path: &Path, query: Query) -> Result<T>
where
  Query: FnMut(&Path) -> Result<T>,
{
  with_windows_locked_database_policy(
    db_path,
    WindowsLockedDatabasePolicy::NonDisruptive,
    query,
    classify_windows_sharing_violation,
    privilege::user::privileged,
    create_windows_shadow_source,
    |_| false,
  )
}

/// Runs a complete Chromium database query under the explicit lock policy
/// selected by the compatibility `force_kill` argument.
pub(crate) fn with_force_kill_recovery<T, Query>(
  db_path: &Path,
  force_kill: bool,
  query: Query,
) -> Result<T>
where
  Query: FnMut(&Path) -> Result<T>,
{
  with_windows_locked_database_policy(
    db_path,
    WindowsLockedDatabasePolicy::from_force_kill(force_kill),
    query,
    classify_windows_sharing_violation,
    privilege::user::privileged,
    create_windows_shadow_source,
    release_windows_lock,
  )
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::os::windows::fs::OpenOptionsExt;

  fn synthetic_acquisition_error(
    strategy: Option<sqlite::DatabaseAcquisitionStrategy>,
    error: impl Into<anyhow::Error>,
  ) -> anyhow::Error {
    error.into().context(sqlite::BrowserDatabaseFailure {
      kind: sqlite::BrowserDatabaseFailureKind::Acquisition,
      strategy,
      attempts: 1,
    })
  }

  fn open_without_file_sharing(path: &Path) -> std::fs::File {
    std::fs::OpenOptions::new()
      .read(true)
      .share_mode(0)
      .open(path)
      .expect("open exclusive Windows fixture handle")
  }

  #[test]
  fn production_classifier_retains_a_direct_typed_sharing_violation() {
    let directory = crate::utils::TempDir::new().expect("temp dir");
    let db = directory.path().join("Cookies");
    std::fs::write(&db, b"fixture").expect("write fixture");
    let error = synthetic_acquisition_error(
      Some(sqlite::DatabaseAcquisitionStrategy::LiveReadOnly),
      std::io::Error::from_raw_os_error(super::super::ERROR_SHARING_VIOLATION_CODE),
    );

    let violation = classify_windows_sharing_violation(&db, &error)
      .expect("direct typed sharing error remains classified after probing");
    assert_eq!(violation.locked_file, WindowsLockedFile::Database);
    assert_eq!(violation.locked_path, db);
    assert!(!violation.has_verified_nonempty_wal);
  }

  #[test]
  fn windows_native_database_sharing_violation_is_classified() {
    let directory = crate::utils::TempDir::new().expect("temp dir");
    let db = directory.path().join("Cookies");
    std::fs::write(&db, b"fixture").expect("write fixture");
    let _exclusive = open_without_file_sharing(&db);
    let os_error = std::fs::File::open(&db).expect_err("exclusive handle denies sharing");
    let error = synthetic_acquisition_error(
      Some(sqlite::DatabaseAcquisitionStrategy::LiveReadOnly),
      os_error,
    );

    let violation =
      classify_windows_sharing_violation(&db, &error).expect("native database sharing violation");
    assert_eq!(violation.locked_file, WindowsLockedFile::Database);
    assert_eq!(violation.locked_path, db);
    assert!(!violation.has_verified_nonempty_wal);
  }

  #[test]
  fn windows_native_wal_sharing_violation_retains_positive_wal_proof() {
    let directory = crate::utils::TempDir::new().expect("temp dir");
    let db = directory.path().join("Cookies");
    let wal = sqlite::sidecar(&db, "-wal");
    std::fs::write(&db, b"fixture").expect("write database fixture");
    std::fs::write(&wal, b"nonempty WAL fixture").expect("write WAL fixture");
    let _exclusive = open_without_file_sharing(&wal);
    let os_error = std::fs::File::open(&wal).expect_err("exclusive WAL handle denies sharing");
    let error = synthetic_acquisition_error(
      Some(sqlite::DatabaseAcquisitionStrategy::VerifiedWalSnapshot),
      os_error,
    );

    let violation =
      classify_windows_sharing_violation(&db, &error).expect("native WAL sharing violation");
    assert_eq!(violation.locked_file, WindowsLockedFile::WriteAheadLog);
    assert_eq!(violation.locked_path, wal);
    assert!(violation.has_verified_nonempty_wal);
  }
}
