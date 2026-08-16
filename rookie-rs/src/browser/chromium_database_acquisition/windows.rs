use super::{
  classify_windows_sharing_violation_with_fallible_probe,
  with_windows_locked_database_policy_with_runtime, WindowsFallbackSource,
  WindowsLockedDatabasePolicy, WindowsLockedFile, WindowsRecoveryRequest, WindowsSharingViolation,
};
use crate::common::deadline::{BoundaryRuntime, BoundaryStop};
use crate::common::sqlite;
use anyhow::{anyhow, Result};
use std::path::Path;

fn probe_windows_sharing_violation(
  db_path: &Path,
  include_wal: bool,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Option<WindowsSharingViolation>> {
  runtime.check()?;
  let wal_path = sqlite::sidecar(db_path, "-wal");
  let wal_metadata = std::fs::metadata(&wal_path);
  runtime.check()?;
  let has_verified_nonempty_wal = wal_metadata
    .as_ref()
    .is_ok_and(|metadata| metadata.len() > 0);

  runtime.check()?;
  let database_open = std::fs::File::open(db_path);
  runtime.check()?;
  if let Err(error) = database_open {
    if let Some(code) = super::windows_sharing_code(&error) {
      return Ok(Some(WindowsSharingViolation {
        locked_file: WindowsLockedFile::Database,
        locked_path: db_path.to_path_buf(),
        has_verified_nonempty_wal,
        os_error: code,
      }));
    }
  }

  if !include_wal {
    return Ok(None);
  }

  if let Err(error) = &wal_metadata {
    if let Some(code) = super::windows_sharing_code(error) {
      return Ok(Some(WindowsSharingViolation {
        locked_file: WindowsLockedFile::WriteAheadLog,
        locked_path: wal_path,
        // A share-denied metadata lookup cannot prove that the WAL is
        // nonempty, so it is ineligible for raw-copy fallback.
        has_verified_nonempty_wal: false,
        os_error: code,
      }));
    }
    return Ok(None);
  }

  if has_verified_nonempty_wal {
    runtime.check()?;
    let wal_open = std::fs::File::open(&wal_path);
    runtime.check()?;
    if let Err(error) = wal_open {
      if let Some(code) = super::windows_sharing_code(&error) {
        return Ok(Some(WindowsSharingViolation {
          locked_file: WindowsLockedFile::WriteAheadLog,
          locked_path: wal_path,
          has_verified_nonempty_wal: true,
          os_error: code,
        }));
      }
    }
  }

  Ok(None)
}

fn classify_windows_sharing_violation(
  db_path: &Path,
  error: &anyhow::Error,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Option<WindowsSharingViolation>> {
  classify_windows_sharing_violation_with_fallible_probe(db_path, error, |path, include_wal| {
    probe_windows_sharing_violation(path, include_wal, runtime)
  })
}

fn create_windows_shadow_source(
  db_path: &Path,
  runtime: &BoundaryRuntime<'_>,
) -> Result<WindowsFallbackSource<crate::utils::TempDir>> {
  runtime.check()?;
  let temp_dir = crate::utils::TempDir::new()?;
  runtime.check()?;
  crate::windows::shadow_copy::shadow_copy(
    db_path.to_path_buf(),
    temp_dir.path().to_path_buf(),
    runtime,
  )?;
  runtime.check()?;
  let file_name = db_path
    .file_name()
    .ok_or_else(|| anyhow!("Database path has no file name: {}", db_path.display()))?;
  let path = temp_dir.path().join(file_name);
  Ok(WindowsFallbackSource {
    path,
    _guard: temp_dir,
  })
}

fn windows_privileged(runtime: &BoundaryRuntime<'_>) -> Result<bool> {
  runtime.check()?;
  let privileged = privilege::user::privileged();
  runtime.check()?;
  Ok(privileged)
}

fn release_windows_lock(locked_path: &Path, runtime: &BoundaryRuntime<'_>) -> Result<bool> {
  // SAFETY: This wrapper is only called when the public `force_kill` choice
  // selected the disruptive policy. Restart Manager owns the registered path
  // for the duration of its internal session.
  unsafe {
    match crate::windows::restart_manager::release_file_lock(locked_path, true, runtime) {
      Ok(
        crate::windows::restart_manager::FileLockStatus::Unlocked
        | crate::windows::restart_manager::FileLockStatus::Released { .. },
      ) => Ok(true),
      Ok(crate::windows::restart_manager::FileLockStatus::Locked { .. }) => Ok(false),
      Err(error) if error.downcast_ref::<BoundaryStop>().is_some() => Err(error),
      Err(error) => {
        log::warn!("Restart Manager could not release the Windows database lock: {error}");
        Ok(false)
      }
    }
  }
}

/// Runs a source-inspection query through the non-disruptive locked-file
/// recovery policy used before `any_browser` selects a decoder.
pub(crate) fn with_non_disruptive_recovery<T, Query>(
  db_path: &Path,
  runtime: &BoundaryRuntime<'_>,
  query: Query,
) -> Result<T>
where
  Query: FnMut(&Path, &BoundaryRuntime<'_>) -> Result<T>,
{
  with_windows_locked_database_policy_with_runtime(
    WindowsRecoveryRequest {
      db_path,
      policy: WindowsLockedDatabasePolicy::NonDisruptive,
      runtime,
    },
    query,
    classify_windows_sharing_violation,
    windows_privileged,
    create_windows_shadow_source,
    |_, _| Ok(false),
  )
}

/// Runs a complete Chromium database query under the explicit lock policy
/// selected by the compatibility `force_kill` argument.
pub(crate) fn with_force_kill_recovery<T, Query>(
  db_path: &Path,
  force_kill: bool,
  runtime: &BoundaryRuntime<'_>,
  query: Query,
) -> Result<T>
where
  Query: FnMut(&Path, &BoundaryRuntime<'_>) -> Result<T>,
{
  with_windows_locked_database_policy_with_runtime(
    WindowsRecoveryRequest {
      db_path,
      policy: WindowsLockedDatabasePolicy::from_force_kill(force_kill),
      runtime,
    },
    query,
    classify_windows_sharing_violation,
    windows_privileged,
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

  fn classify_for_test(db_path: &Path, error: &anyhow::Error) -> Option<WindowsSharingViolation> {
    let clock = crate::common::deadline::SystemClock;
    let runtime = BoundaryRuntime::standard(&clock);
    classify_windows_sharing_violation(db_path, error, &runtime).expect("classification probe")
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

    let violation = classify_for_test(&db, &error)
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

    let violation = classify_for_test(&db, &error).expect("native database sharing violation");
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

    let violation = classify_for_test(&db, &error).expect("native WAL sharing violation");
    assert_eq!(violation.locked_file, WindowsLockedFile::WriteAheadLog);
    assert_eq!(violation.locked_path, wal);
    assert!(violation.has_verified_nonempty_wal);
  }
}
