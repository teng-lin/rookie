//! Chromium database acquisition policy and target-specific recovery.
//!
//! The policy is portable so its ordering and error-chain guarantees can be
//! characterized on every host. Native file probing, shadow-copy acquisition,
//! privilege inspection, and Restart Manager calls live in the Windows leaf.

use crate::common::{
  deadline::BoundaryRuntime,
  diagnostic::{sanitize, REDACTED_PATH},
  sqlite,
};
use anyhow::Result;
use std::path::{Path, PathBuf};

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub(crate) use windows::{with_force_kill_recovery, with_non_disruptive_recovery};

const ERROR_SHARING_VIOLATION_CODE: i32 = 32;
const ERROR_LOCK_VIOLATION_CODE: i32 = 33;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsLockedDatabasePolicy {
  NonDisruptive,
  AllowProcessShutdown,
}

impl WindowsLockedDatabasePolicy {
  fn from_force_kill(force_kill: bool) -> Self {
    if force_kill {
      Self::AllowProcessShutdown
    } else {
      Self::NonDisruptive
    }
  }

  fn allows_process_shutdown(self) -> bool {
    self == Self::AllowProcessShutdown
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowsLockedFile {
  Database,
  WriteAheadLog,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowsSharingViolation {
  locked_file: WindowsLockedFile,
  locked_path: PathBuf,
  has_verified_nonempty_wal: bool,
  os_error: i32,
}

/// Typed context for a Windows browser database that ordinary acquisition
/// could not read because another process denied file sharing.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct WindowsDatabaseLocked {
  pub(crate) locked_file: WindowsLockedFile,
  pub(crate) locked_path: PathBuf,
  pub(crate) has_verified_nonempty_wal: bool,
  pub(crate) shutdown_allowed: bool,
  pub(crate) os_error: i32,
}

impl std::fmt::Display for WindowsDatabaseLocked {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let file = match self.locked_file {
      WindowsLockedFile::Database => "database",
      WindowsLockedFile::WriteAheadLog => "write-ahead log",
    };
    let policy = if self.shutdown_allowed {
      "explicit process shutdown did not make it readable"
    } else {
      "process shutdown is disabled"
    };
    write!(
      formatter,
      "Windows browser {file} is share-locked at {REDACTED_PATH} (OS error {}); {policy}",
      self.os_error
    )
  }
}

impl std::fmt::Debug for WindowsDatabaseLocked {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("WindowsDatabaseLocked")
      .field("locked_file", &self.locked_file)
      .field("locked_path", &REDACTED_PATH)
      .field("has_verified_nonempty_wal", &self.has_verified_nonempty_wal)
      .field("shutdown_allowed", &self.shutdown_allowed)
      .field("os_error", &self.os_error)
      .finish()
  }
}

/// Retains diagnostics from a failed raw shadow-copy acquisition without
/// replacing the ordinary acquisition error as the source of the final error.
///
/// The ordinary error carries [`sqlite::BrowserDatabaseFailure`] metadata used
/// by source reports. Keeping this value as an `anyhow` context makes both that
/// metadata and [`WindowsDatabaseLocked`] downcastable while still explaining
/// why the non-disruptive fallback did not succeed.
#[derive(Debug)]
struct WindowsShadowFallbackFailure {
  shadow_diagnostic: String,
  retry_diagnostic: Option<String>,
}

impl WindowsShadowFallbackFailure {
  fn new(shadow_error: &anyhow::Error, retry_error: Option<&anyhow::Error>) -> Self {
    Self {
      shadow_diagnostic: sanitize(&format!("{shadow_error:#}")),
      retry_diagnostic: retry_error.map(|error| sanitize(&format!("{error:#}"))),
    }
  }
}

impl std::fmt::Display for WindowsShadowFallbackFailure {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      formatter,
      "Windows WAL shadow-copy fallback failed: {}",
      self.shadow_diagnostic
    )?;
    if let Some(retry) = &self.retry_diagnostic {
      write!(
        formatter,
        "; ordinary acquisition after explicit process shutdown also failed: {retry}"
      )?;
    }
    Ok(())
  }
}

impl std::error::Error for WindowsShadowFallbackFailure {}

struct WindowsFallbackSource<Guard> {
  path: PathBuf,
  _guard: Guard,
}

struct WindowsRecoveryRequest<'a> {
  db_path: &'a Path,
  policy: WindowsLockedDatabasePolicy,
  runtime: &'a BoundaryRuntime<'a>,
}

fn windows_locked_error(
  violation: &WindowsSharingViolation,
  policy: WindowsLockedDatabasePolicy,
) -> WindowsDatabaseLocked {
  WindowsDatabaseLocked {
    locked_file: violation.locked_file,
    locked_path: violation.locked_path.clone(),
    has_verified_nonempty_wal: violation.has_verified_nonempty_wal,
    shutdown_allowed: policy.allows_process_shutdown(),
    os_error: violation.os_error,
  }
}

fn windows_locked_after_shadow_failure(
  ordinary_error: anyhow::Error,
  violation: &WindowsSharingViolation,
  policy: WindowsLockedDatabasePolicy,
  shadow_error: &anyhow::Error,
  retry_error: Option<&anyhow::Error>,
) -> anyhow::Error {
  ordinary_error
    .context(WindowsShadowFallbackFailure::new(shadow_error, retry_error))
    .context(windows_locked_error(violation, policy))
}

fn windows_sharing_code(error: &std::io::Error) -> Option<i32> {
  error.raw_os_error().filter(|code| {
    matches!(
      *code,
      ERROR_SHARING_VIOLATION_CODE | ERROR_LOCK_VIOLATION_CODE
    )
  })
}

fn sharing_code_in_error_chain(error: &anyhow::Error) -> Option<i32> {
  error
    .chain()
    .find_map(|cause| windows_sharing_code(cause.downcast_ref::<std::io::Error>()?))
}

fn is_sqlite_cant_open(error: &anyhow::Error) -> bool {
  error.chain().any(|cause| {
    matches!(
      cause.downcast_ref::<rusqlite::Error>(),
      Some(rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error {
          code: rusqlite::ffi::ErrorCode::CannotOpen,
          ..
        },
        _
      ))
    )
  })
}

fn classify_windows_sharing_violation_with_fallible_probe<Probe>(
  db_path: &Path,
  error: &anyhow::Error,
  mut probe: Probe,
) -> Result<Option<WindowsSharingViolation>>
where
  Probe: FnMut(&Path, bool) -> Result<Option<WindowsSharingViolation>>,
{
  let Some(failure) = error.downcast_ref::<sqlite::BrowserDatabaseFailure>() else {
    return Ok(None);
  };
  if failure.kind != sqlite::BrowserDatabaseFailureKind::Acquisition {
    return Ok(None);
  }

  let direct_code = sharing_code_in_error_chain(error);
  if direct_code.is_none() && !is_sqlite_cant_open(error) {
    return Ok(None);
  }

  if let Some(mut violation) = probe(db_path, direct_code.is_some())? {
    if failure.strategy == Some(sqlite::DatabaseAcquisitionStrategy::VerifiedWalSnapshot) {
      violation.has_verified_nonempty_wal = true;
    }
    return Ok(Some(violation));
  }

  Ok(direct_code.map(|os_error| WindowsSharingViolation {
    locked_file: WindowsLockedFile::Database,
    locked_path: db_path.to_path_buf(),
    has_verified_nonempty_wal: failure.strategy
      == Some(sqlite::DatabaseAcquisitionStrategy::VerifiedWalSnapshot),
    os_error,
  }))
}

#[cfg(test)]
fn classify_windows_sharing_violation_with_probe<Probe>(
  db_path: &Path,
  error: &anyhow::Error,
  mut probe: Probe,
) -> Option<WindowsSharingViolation>
where
  Probe: FnMut(&Path, bool) -> Option<WindowsSharingViolation>,
{
  classify_windows_sharing_violation_with_fallible_probe(db_path, error, |path, include_wal| {
    Ok(probe(path, include_wal))
  })
  .expect("infallible test probe")
}

fn with_windows_locked_database_policy_with_runtime<
  T,
  Guard,
  Query,
  Classify,
  IsAdmin,
  Shadow,
  Shutdown,
>(
  request: WindowsRecoveryRequest<'_>,
  mut query: Query,
  mut classify: Classify,
  mut is_admin: IsAdmin,
  mut shadow: Shadow,
  mut shutdown: Shutdown,
) -> Result<T>
where
  Query: FnMut(&Path, &BoundaryRuntime<'_>) -> Result<T>,
  Classify:
    FnMut(&Path, &anyhow::Error, &BoundaryRuntime<'_>) -> Result<Option<WindowsSharingViolation>>,
  IsAdmin: FnMut(&BoundaryRuntime<'_>) -> Result<bool>,
  Shadow: FnMut(&Path, &BoundaryRuntime<'_>) -> Result<WindowsFallbackSource<Guard>>,
  Shutdown: FnMut(&Path, &BoundaryRuntime<'_>) -> Result<bool>,
{
  let WindowsRecoveryRequest {
    db_path,
    policy,
    runtime,
  } = request;
  runtime.check()?;
  let ordinary_error = match query(db_path, runtime) {
    Ok(value) => return Ok(value),
    Err(error) => {
      runtime.check()?;
      error
    }
  };
  let violation = classify(db_path, &ordinary_error, runtime);
  runtime.check()?;
  let Some(violation) = violation? else {
    return Err(ordinary_error);
  };

  let mut shadow_error = None;
  let is_admin = if violation.has_verified_nonempty_wal {
    runtime.check()?;
    let result = is_admin(runtime);
    runtime.check()?;
    result?
  } else {
    false
  };
  if violation.has_verified_nonempty_wal && is_admin {
    runtime.check()?;
    let shadow_result = shadow(db_path, runtime);
    runtime.check()?;
    match shadow_result {
      Ok(source) => {
        // The guard keeps the static shadow directory alive for the complete
        // query. A query/decode failure on this acquired source is final and
        // never grants permission to terminate the live browser.
        runtime.check()?;
        return match query(&source.path, runtime) {
          Ok(value) => Ok(value),
          Err(error) => {
            runtime.check()?;
            Err(error)
          }
        };
      }
      Err(error) if !policy.allows_process_shutdown() => {
        return Err(windows_locked_after_shadow_failure(
          ordinary_error,
          &violation,
          policy,
          &error,
          None,
        ));
      }
      Err(error) => {
        log::warn!("Windows WAL shadow-copy fallback failed: {error}");
        shadow_error = Some(error);
      }
    }
  }

  let shutdown_succeeded = if policy.allows_process_shutdown() {
    runtime.check()?;
    let result = shutdown(&violation.locked_path, runtime);
    runtime.check()?;
    result?
  } else {
    false
  };
  if shutdown_succeeded {
    runtime.check()?;
    let retry_error = match query(db_path, runtime) {
      Ok(value) => return Ok(value),
      Err(error) => {
        runtime.check()?;
        error
      }
    };
    let retry_violation = classify(db_path, &retry_error, runtime);
    runtime.check()?;
    let retry_violation = retry_violation?;
    if let Some(shadow_error) = &shadow_error {
      let retry_violation = retry_violation.unwrap_or_else(|| violation.clone());
      return Err(windows_locked_after_shadow_failure(
        ordinary_error,
        &retry_violation,
        policy,
        shadow_error,
        Some(&retry_error),
      ));
    }
    return if let Some(retry_violation) = retry_violation {
      Err(retry_error.context(windows_locked_error(&retry_violation, policy)))
    } else {
      Err(retry_error)
    };
  }

  if let Some(shadow_error) = &shadow_error {
    return Err(windows_locked_after_shadow_failure(
      ordinary_error,
      &violation,
      policy,
      shadow_error,
      None,
    ));
  }

  Err(ordinary_error.context(windows_locked_error(&violation, policy)))
}

#[cfg(test)]
fn with_windows_locked_database_policy<T, Guard, Query, Classify, IsAdmin, Shadow, Shutdown>(
  db_path: &Path,
  policy: WindowsLockedDatabasePolicy,
  mut query: Query,
  mut classify: Classify,
  mut is_admin: IsAdmin,
  mut shadow: Shadow,
  mut shutdown: Shutdown,
) -> Result<T>
where
  Query: FnMut(&Path) -> Result<T>,
  Classify: FnMut(&Path, &anyhow::Error) -> Option<WindowsSharingViolation>,
  IsAdmin: FnMut() -> bool,
  Shadow: FnMut(&Path) -> Result<WindowsFallbackSource<Guard>>,
  Shutdown: FnMut(&Path) -> bool,
{
  let clock = crate::common::deadline::SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  with_windows_locked_database_policy_with_runtime(
    WindowsRecoveryRequest {
      db_path,
      policy,
      runtime: &runtime,
    },
    |path, _| query(path),
    |path, error, _| Ok(classify(path, error)),
    |_| Ok(is_admin()),
    |path, _| shadow(path),
    |path, _| Ok(shutdown(path)),
  )
}

#[cfg(test)]
mod tests {
  use super::*;
  use anyhow::anyhow;
  use std::cell::{Cell, RefCell};

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

  fn synthetic_query_error(error: impl Into<anyhow::Error>) -> anyhow::Error {
    error.into().context(sqlite::BrowserDatabaseFailure {
      kind: sqlite::BrowserDatabaseFailureKind::Query,
      strategy: Some(sqlite::DatabaseAcquisitionStrategy::LiveReadOnly),
      attempts: 1,
    })
  }

  fn sharing_violation(
    db_path: &Path,
    locked_file: WindowsLockedFile,
    has_verified_nonempty_wal: bool,
  ) -> WindowsSharingViolation {
    WindowsSharingViolation {
      locked_file,
      locked_path: match locked_file {
        WindowsLockedFile::Database => db_path.to_path_buf(),
        WindowsLockedFile::WriteAheadLog => sqlite::sidecar(db_path, "-wal"),
      },
      has_verified_nonempty_wal,
      os_error: ERROR_SHARING_VIOLATION_CODE,
    }
  }

  #[test]
  fn windows_database_locked_display_and_debug_cover_every_arm() {
    let database_disallowed = WindowsDatabaseLocked {
      locked_file: WindowsLockedFile::Database,
      locked_path: PathBuf::from("/tmp/Cookies"),
      has_verified_nonempty_wal: false,
      shutdown_allowed: false,
      os_error: ERROR_SHARING_VIOLATION_CODE,
    };
    let display = database_disallowed.to_string();
    assert!(display.contains("database is share-locked"), "{display}");
    assert!(
      display.contains("process shutdown is disabled"),
      "{display}"
    );
    let debug = format!("{database_disallowed:?}");
    assert!(debug.starts_with("WindowsDatabaseLocked {"), "{debug}");
    assert!(debug.contains("locked_file: Database"), "{debug}");
    assert!(
      debug.contains("has_verified_nonempty_wal: false"),
      "{debug}"
    );
    assert!(debug.contains("shutdown_allowed: false"), "{debug}");
    assert!(
      debug.contains(&format!("os_error: {ERROR_SHARING_VIOLATION_CODE}")),
      "{debug}"
    );

    let wal_allowed = WindowsDatabaseLocked {
      locked_file: WindowsLockedFile::WriteAheadLog,
      locked_path: PathBuf::from("/tmp/Cookies-wal"),
      has_verified_nonempty_wal: true,
      shutdown_allowed: true,
      os_error: ERROR_LOCK_VIOLATION_CODE,
    };
    let display = wal_allowed.to_string();
    assert!(
      display.contains("write-ahead log is share-locked"),
      "{display}"
    );
    assert!(
      display.contains("explicit process shutdown did not make it readable"),
      "{display}"
    );
    let debug = format!("{wal_allowed:?}");
    assert!(debug.contains("locked_file: WriteAheadLog"), "{debug}");
    assert!(debug.contains("has_verified_nonempty_wal: true"), "{debug}");
    assert!(debug.contains("shutdown_allowed: true"), "{debug}");
  }

  #[test]
  fn windows_shadow_fallback_failure_display_covers_both_diagnostics() {
    let shadow_only = WindowsShadowFallbackFailure::new(&anyhow!("shadow unavailable"), None);
    assert_eq!(
      shadow_only.to_string(),
      "Windows WAL shadow-copy fallback failed: shadow unavailable"
    );

    let retry_error = anyhow!("post-shutdown retry failed");
    let both =
      WindowsShadowFallbackFailure::new(&anyhow!("shadow unavailable"), Some(&retry_error));
    let message = both.to_string();
    assert!(message.contains("shadow unavailable"), "{message}");
    assert!(
      message.contains(
        "ordinary acquisition after explicit process shutdown also failed: post-shutdown retry failed"
      ),
      "{message}"
    );
  }

  #[test]
  fn windows_sharing_code_only_recognizes_the_two_known_codes() {
    assert_eq!(
      windows_sharing_code(&std::io::Error::from_raw_os_error(
        ERROR_SHARING_VIOLATION_CODE
      )),
      Some(ERROR_SHARING_VIOLATION_CODE)
    );
    assert_eq!(
      windows_sharing_code(&std::io::Error::from_raw_os_error(
        ERROR_LOCK_VIOLATION_CODE
      )),
      Some(ERROR_LOCK_VIOLATION_CODE)
    );
    assert_eq!(
      windows_sharing_code(&std::io::Error::from_raw_os_error(5)),
      None,
      "an unrelated OS error code must not be treated as a sharing violation"
    );
    assert_eq!(
      windows_sharing_code(&std::io::Error::other("no OS error code attached")),
      None
    );
  }

  #[test]
  fn classifier_ignores_errors_without_a_typed_database_failure() {
    let db = PathBuf::from("live/Cookies");
    let plain_error = anyhow!("some unrelated failure");
    assert!(
      classify_windows_sharing_violation_with_probe(&db, &plain_error, |_, _| {
        panic!("an error without BrowserDatabaseFailure metadata must never reach the probe")
      })
      .is_none()
    );
  }

  #[test]
  fn force_kill_maps_to_an_explicit_windows_shutdown_policy() {
    assert_eq!(
      WindowsLockedDatabasePolicy::from_force_kill(false),
      WindowsLockedDatabasePolicy::NonDisruptive
    );
    assert_eq!(
      WindowsLockedDatabasePolicy::from_force_kill(true),
      WindowsLockedDatabasePolicy::AllowProcessShutdown
    );
  }

  #[test]
  fn cancelled_windows_recovery_does_not_start_any_action() {
    let clock = crate::common::deadline::test_clock::ManualClock::default();
    let stop = crate::common::deadline::CancellationToken::default();
    stop.cancel();
    let runtime = BoundaryRuntime::with_stop(
      &clock,
      crate::common::deadline::Deadline::after(&clock, std::time::Duration::from_secs(1)),
      stop,
    );
    let query_calls = Cell::new(0);

    let error = with_windows_locked_database_policy_with_runtime(
      WindowsRecoveryRequest {
        db_path: Path::new("Cookies"),
        policy: WindowsLockedDatabasePolicy::AllowProcessShutdown,
        runtime: &runtime,
      },
      |_, _| {
        query_calls.set(query_calls.get() + 1);
        Ok(())
      },
      |_, _, _| panic!("cancelled recovery must not classify"),
      |_| panic!("cancelled recovery must not inspect privilege"),
      |_, _| -> Result<WindowsFallbackSource<()>> {
        panic!("cancelled recovery must not acquire a shadow")
      },
      |_, _| panic!("cancelled recovery must not stop processes"),
    )
    .expect_err("cancelled recovery");

    assert_eq!(
      error.downcast_ref::<crate::common::deadline::BoundaryStop>(),
      Some(&crate::common::deadline::BoundaryStop::Cancelled)
    );
    assert_eq!(query_calls.get(), 0);
  }

  #[test]
  fn resource_stop_after_privilege_check_prevents_shadow_and_shutdown_actions() {
    let clock = crate::common::deadline::test_clock::ManualClock::default();
    let stop = crate::common::deadline::CancellationToken::default();
    let runtime = BoundaryRuntime::with_stop(
      &clock,
      crate::common::deadline::Deadline::after(&clock, std::time::Duration::from_secs(1)),
      stop.clone(),
    );
    let db = PathBuf::from("Cookies");
    let query_calls = Cell::new(0);
    let privilege_calls = Cell::new(0);
    let shadow_calls = Cell::new(0);
    let shutdown_calls = Cell::new(0);

    let error = with_windows_locked_database_policy_with_runtime(
      WindowsRecoveryRequest {
        db_path: &db,
        policy: WindowsLockedDatabasePolicy::AllowProcessShutdown,
        runtime: &runtime,
      },
      |_, _| {
        query_calls.set(query_calls.get() + 1);
        Err::<(), _>(anyhow!("share denied"))
      },
      |_, _, _| {
        Ok(Some(sharing_violation(
          &db,
          WindowsLockedFile::Database,
          true,
        )))
      },
      |_| {
        privilege_calls.set(privilege_calls.get() + 1);
        stop.exhaust_resources();
        Ok(true)
      },
      |_, _| {
        shadow_calls.set(shadow_calls.get() + 1);
        Ok(WindowsFallbackSource {
          path: PathBuf::from("shadow"),
          _guard: (),
        })
      },
      |_, _| {
        shutdown_calls.set(shutdown_calls.get() + 1);
        Ok(true)
      },
    )
    .expect_err("resource stop");

    assert_eq!(
      error.downcast_ref::<crate::common::deadline::BoundaryStop>(),
      Some(&crate::common::deadline::BoundaryStop::ResourceExhausted)
    );
    assert_eq!(query_calls.get(), 1);
    assert_eq!(privilege_calls.get(), 1);
    assert_eq!(shadow_calls.get(), 0);
    assert_eq!(shutdown_calls.get(), 0);
  }

  #[test]
  fn windows_policy_attempts_ordinary_query_before_any_fallback() {
    let db = PathBuf::from("ordinary/Cookies");
    let calls = RefCell::new(Vec::new());
    let value = with_windows_locked_database_policy(
      &db,
      WindowsLockedDatabasePolicy::NonDisruptive,
      |_| {
        calls.borrow_mut().push("ordinary");
        Ok("ordinary value")
      },
      |_, _| panic!("a successful ordinary query must not be classified"),
      || panic!("a successful ordinary query must not inspect privilege"),
      |_| -> Result<WindowsFallbackSource<()>> {
        panic!("a successful ordinary query must not be shadow-copied")
      },
      |_| panic!("a successful ordinary query must not stop a process"),
    )
    .expect("ordinary query succeeds");

    assert_eq!(value, "ordinary value");
    assert_eq!(*calls.borrow(), vec!["ordinary"]);
  }

  #[test]
  fn successful_ordinary_query_commits_before_a_racing_stop() {
    let clock = crate::common::deadline::test_clock::ManualClock::default();
    let stop = crate::common::deadline::CancellationToken::default();
    let runtime = BoundaryRuntime::with_stop(
      &clock,
      crate::common::deadline::Deadline::after(&clock, std::time::Duration::from_secs(1)),
      stop.clone(),
    );

    let value = with_windows_locked_database_policy_with_runtime(
      WindowsRecoveryRequest {
        db_path: Path::new("Cookies"),
        policy: WindowsLockedDatabasePolicy::AllowProcessShutdown,
        runtime: &runtime,
      },
      |_, _| {
        stop.cancel();
        Ok("ordinary value")
      },
      |_, _, _| panic!("a completed ordinary query must not be classified"),
      |_| panic!("a completed ordinary query must not inspect privilege"),
      |_, _| -> Result<WindowsFallbackSource<()>> {
        panic!("a completed ordinary query must not acquire a shadow")
      },
      |_, _| panic!("a completed ordinary query must not stop a process"),
    )
    .expect("completed ordinary result commits");

    assert_eq!(value, "ordinary value");
    assert_eq!(
      runtime.check(),
      Err(crate::common::deadline::BoundaryStop::Cancelled)
    );
  }

  #[test]
  fn successful_shadow_query_commits_before_a_racing_stop() {
    let clock = crate::common::deadline::test_clock::ManualClock::default();
    let stop = crate::common::deadline::CancellationToken::default();
    let runtime = BoundaryRuntime::with_stop(
      &clock,
      crate::common::deadline::Deadline::after(&clock, std::time::Duration::from_secs(1)),
      stop.clone(),
    );
    let db = PathBuf::from("live/Cookies");
    let query_calls = Cell::new(0);

    let value = with_windows_locked_database_policy_with_runtime(
      WindowsRecoveryRequest {
        db_path: &db,
        policy: WindowsLockedDatabasePolicy::NonDisruptive,
        runtime: &runtime,
      },
      |_, _| {
        query_calls.set(query_calls.get() + 1);
        if query_calls.get() == 1 {
          Err(anyhow!("share denied"))
        } else {
          stop.cancel();
          Ok("shadow value")
        }
      },
      |_, _, _| {
        Ok(Some(sharing_violation(
          &db,
          WindowsLockedFile::Database,
          true,
        )))
      },
      |_| Ok(true),
      |_, _| {
        Ok(WindowsFallbackSource {
          path: PathBuf::from("shadow/Cookies"),
          _guard: (),
        })
      },
      |_, _| panic!("a completed shadow query must not stop a process"),
    )
    .expect("completed shadow result commits");

    assert_eq!(value, "shadow value");
    assert_eq!(query_calls.get(), 2);
    assert_eq!(
      runtime.check(),
      Err(crate::common::deadline::BoundaryStop::Cancelled)
    );
  }

  #[test]
  fn successful_post_shutdown_retry_commits_before_a_racing_stop() {
    let clock = crate::common::deadline::test_clock::ManualClock::default();
    let stop = crate::common::deadline::CancellationToken::default();
    let runtime = BoundaryRuntime::with_stop(
      &clock,
      crate::common::deadline::Deadline::after(&clock, std::time::Duration::from_secs(1)),
      stop.clone(),
    );
    let db = PathBuf::from("live/Cookies");
    let query_calls = Cell::new(0);

    let value = with_windows_locked_database_policy_with_runtime(
      WindowsRecoveryRequest {
        db_path: &db,
        policy: WindowsLockedDatabasePolicy::AllowProcessShutdown,
        runtime: &runtime,
      },
      |_, _| {
        query_calls.set(query_calls.get() + 1);
        if query_calls.get() == 1 {
          Err(anyhow!("share denied"))
        } else {
          stop.cancel();
          Ok("retry value")
        }
      },
      |_, _, _| {
        Ok(Some(sharing_violation(
          &db,
          WindowsLockedFile::Database,
          false,
        )))
      },
      |_| Ok(false),
      |_, _| -> Result<WindowsFallbackSource<()>> {
        panic!("a no-WAL source must not acquire a shadow")
      },
      |_, _| Ok(true),
    )
    .expect("completed post-shutdown retry commits");

    assert_eq!(value, "retry value");
    assert_eq!(query_calls.get(), 2);
    assert_eq!(
      runtime.check(),
      Err(crate::common::deadline::BoundaryStop::Cancelled)
    );
  }

  #[test]
  fn windows_policy_does_not_fallback_for_non_sharing_failures() {
    let db = PathBuf::from("ordinary/Cookies");
    let calls = RefCell::new(Vec::new());
    let error = with_windows_locked_database_policy(
      &db,
      WindowsLockedDatabasePolicy::AllowProcessShutdown,
      |_| {
        calls.borrow_mut().push("ordinary");
        Err::<(), _>(anyhow!("schema mismatch"))
      },
      |_, _| None,
      || panic!("a non-sharing failure must not inspect privilege"),
      |_| -> Result<WindowsFallbackSource<()>> {
        panic!("a schema error must not be shadow-copied")
      },
      |_| panic!("a schema error must not stop a process"),
    )
    .expect_err("schema error remains final");

    assert_eq!(error.to_string(), "schema mismatch");
    assert!(error.downcast_ref::<WindowsDatabaseLocked>().is_none());
    assert_eq!(*calls.borrow(), vec!["ordinary"]);
  }

  #[test]
  fn standard_and_admin_no_wal_locks_never_raw_copy_or_shutdown_by_default() {
    let db = PathBuf::from("no-wal/Cookies");
    for is_admin in [false, true] {
      let query_calls = Cell::new(0);
      let error = with_windows_locked_database_policy(
        &db,
        WindowsLockedDatabasePolicy::NonDisruptive,
        |_| {
          query_calls.set(query_calls.get() + 1);
          Err::<&str, _>(anyhow!("share denied"))
        },
        |_, _| Some(sharing_violation(&db, WindowsLockedFile::Database, false)),
        || is_admin,
        |_| -> Result<WindowsFallbackSource<()>> {
          panic!("no-WAL sources must never enter raw-copy fallback")
        },
        |_| panic!("default policy must never stop a process"),
      )
      .expect_err("share-denied no-WAL source remains locked");

      let locked = error
        .downcast_ref::<WindowsDatabaseLocked>()
        .expect("typed locked context");
      assert_eq!(locked.locked_file, WindowsLockedFile::Database);
      assert!(!locked.has_verified_nonempty_wal);
      assert!(!locked.shutdown_allowed);
      assert_eq!(query_calls.get(), 1);
    }
  }

  #[test]
  fn standard_user_wal_lock_returns_typed_locked_without_fallback() {
    let db = PathBuf::from("wal/Cookies");
    let error = with_windows_locked_database_policy(
      &db,
      WindowsLockedDatabasePolicy::NonDisruptive,
      |_| Err::<(), _>(anyhow!("share denied")),
      |_, _| {
        Some(sharing_violation(
          &db,
          WindowsLockedFile::WriteAheadLog,
          true,
        ))
      },
      || false,
      |_| -> Result<WindowsFallbackSource<()>> {
        panic!("standard users cannot enter raw shadow-copy fallback")
      },
      |_| panic!("default policy must never stop a process"),
    )
    .expect_err("standard user cannot bypass a share-denied WAL");

    let locked = error
      .downcast_ref::<WindowsDatabaseLocked>()
      .expect("typed locked context");
    assert_eq!(locked.locked_file, WindowsLockedFile::WriteAheadLog);
    assert!(locked.has_verified_nonempty_wal);
  }

  #[test]
  fn admin_wal_lock_uses_verified_shadow_only_after_ordinary_failure() {
    let db = PathBuf::from("live/Cookies");
    let shadow_db = PathBuf::from("shadow/Cookies");
    let calls = RefCell::new(Vec::new());
    let value = with_windows_locked_database_policy(
      &db,
      WindowsLockedDatabasePolicy::NonDisruptive,
      |path| {
        if path == db {
          calls.borrow_mut().push("ordinary");
          Err::<&str, _>(anyhow!("share denied"))
        } else {
          assert_eq!(path, shadow_db);
          calls.borrow_mut().push("shadow query");
          Ok("shadow value")
        }
      },
      |_, _| Some(sharing_violation(&db, WindowsLockedFile::Database, true)),
      || true,
      |_| {
        calls.borrow_mut().push("shadow acquire");
        Ok(WindowsFallbackSource {
          path: shadow_db.clone(),
          _guard: (),
        })
      },
      |_| panic!("successful non-disruptive fallback must not stop a process"),
    )
    .expect("verified shadow succeeds");

    assert_eq!(value, "shadow value");
    assert_eq!(
      *calls.borrow(),
      vec!["ordinary", "shadow acquire", "shadow query"]
    );
  }

  #[test]
  fn failed_default_shadow_fallback_never_escalates_to_shutdown() {
    let db = PathBuf::from("live/Cookies");
    let calls = RefCell::new(Vec::new());
    let error = with_windows_locked_database_policy(
      &db,
      WindowsLockedDatabasePolicy::NonDisruptive,
      |_| {
        calls.borrow_mut().push("ordinary");
        Err::<(), _>(synthetic_acquisition_error(
          Some(sqlite::DatabaseAcquisitionStrategy::VerifiedWalSnapshot),
          anyhow!("ordinary share denied"),
        ))
      },
      |_, _| Some(sharing_violation(&db, WindowsLockedFile::Database, true)),
      || true,
      |_| {
        calls.borrow_mut().push("shadow acquire");
        Err::<WindowsFallbackSource<()>, _>(anyhow!("shadow unavailable"))
      },
      |_| panic!("default policy must never stop a process"),
    )
    .expect_err("failed non-disruptive fallback remains locked");

    let locked = error
      .downcast_ref::<WindowsDatabaseLocked>()
      .expect("typed locked context");
    assert!(locked.has_verified_nonempty_wal);
    assert!(!locked.shutdown_allowed);
    let ordinary = error
      .downcast_ref::<sqlite::BrowserDatabaseFailure>()
      .expect("ordinary acquisition metadata remains in the source chain");
    assert_eq!(
      ordinary.kind,
      sqlite::BrowserDatabaseFailureKind::Acquisition
    );
    assert_eq!(
      ordinary.strategy,
      Some(sqlite::DatabaseAcquisitionStrategy::VerifiedWalSnapshot)
    );
    assert_eq!(ordinary.attempts, 1);
    let fallback = error
      .downcast_ref::<WindowsShadowFallbackFailure>()
      .expect("shadow acquisition diagnostic remains typed");
    assert!(fallback.shadow_diagnostic.contains("shadow unavailable"));
    assert!(fallback.retry_diagnostic.is_none());
    let chain = format!("{error:#}");
    assert!(chain.contains("ordinary share denied"), "{chain}");
    assert!(chain.contains("shadow unavailable"), "{chain}");
    assert_eq!(*calls.borrow(), vec!["ordinary", "shadow acquire"]);
  }

  #[test]
  fn failed_shadow_and_shutdown_retry_preserve_original_acquisition_metadata() {
    let db = PathBuf::from("live/Cookies");
    let query_calls = Cell::new(0);
    let error = with_windows_locked_database_policy(
      &db,
      WindowsLockedDatabasePolicy::AllowProcessShutdown,
      |_| {
        let call = query_calls.get() + 1;
        query_calls.set(call);
        if call == 1 {
          Err::<(), _>(synthetic_acquisition_error(
            Some(sqlite::DatabaseAcquisitionStrategy::VerifiedWalSnapshot),
            anyhow!("original ordinary share denial"),
          ))
        } else {
          Err::<(), _>(anyhow!("post-shutdown retry failed"))
        }
      },
      |_, error| {
        (query_calls.get() == 1).then(|| {
          assert!(
            error
              .downcast_ref::<sqlite::BrowserDatabaseFailure>()
              .is_some(),
            "only the original acquisition is a classified sharing failure"
          );
          sharing_violation(&db, WindowsLockedFile::Database, true)
        })
      },
      || true,
      |_| Err::<WindowsFallbackSource<()>, _>(anyhow!("shadow acquisition failed")),
      |_| true,
    )
    .expect_err("failed retry remains a typed locked failure");

    assert!(error.downcast_ref::<WindowsDatabaseLocked>().is_some());
    let ordinary = error
      .downcast_ref::<sqlite::BrowserDatabaseFailure>()
      .expect("original ordinary acquisition metadata remains downcastable");
    assert_eq!(
      ordinary.kind,
      sqlite::BrowserDatabaseFailureKind::Acquisition
    );
    assert_eq!(
      ordinary.strategy,
      Some(sqlite::DatabaseAcquisitionStrategy::VerifiedWalSnapshot)
    );
    assert_eq!(ordinary.attempts, 1);
    let fallback = error
      .downcast_ref::<WindowsShadowFallbackFailure>()
      .expect("both fallback diagnostics remain typed");
    assert!(fallback
      .shadow_diagnostic
      .contains("shadow acquisition failed"));
    assert!(fallback
      .retry_diagnostic
      .as_deref()
      .is_some_and(|diagnostic| diagnostic.contains("post-shutdown retry failed")));
    let chain = format!("{error:#}");
    assert!(chain.contains("original ordinary share denial"), "{chain}");
    assert!(chain.contains("shadow acquisition failed"), "{chain}");
    assert!(chain.contains("post-shutdown retry failed"), "{chain}");
    assert_eq!(query_calls.get(), 2);
  }

  #[test]
  fn explicit_shutdown_retries_ordinary_acquisition_once() {
    let db = PathBuf::from("no-wal/Cookies");
    let calls = RefCell::new(Vec::new());
    let query_calls = Cell::new(0);
    let value = with_windows_locked_database_policy(
      &db,
      WindowsLockedDatabasePolicy::AllowProcessShutdown,
      |_| {
        let call = query_calls.get() + 1;
        query_calls.set(call);
        calls.borrow_mut().push("ordinary");
        if call == 1 {
          Err::<&str, _>(anyhow!("share denied"))
        } else {
          Ok("post-shutdown value")
        }
      },
      |_, _| Some(sharing_violation(&db, WindowsLockedFile::Database, false)),
      || false,
      |_| -> Result<WindowsFallbackSource<()>> { panic!("no-WAL source must not be raw-copied") },
      |path| {
        assert_eq!(path, db);
        calls.borrow_mut().push("shutdown");
        true
      },
    )
    .expect("explicit shutdown makes ordinary acquisition readable");

    assert_eq!(value, "post-shutdown value");
    assert_eq!(*calls.borrow(), vec!["ordinary", "shutdown", "ordinary"]);
  }

  #[test]
  fn failed_explicit_shutdown_returns_typed_locked_without_retrying_query() {
    let db = PathBuf::from("no-wal/Cookies");
    let query_calls = Cell::new(0);
    let shutdown_calls = Cell::new(0);
    let error = with_windows_locked_database_policy(
      &db,
      WindowsLockedDatabasePolicy::AllowProcessShutdown,
      |_| {
        query_calls.set(query_calls.get() + 1);
        Err::<(), _>(anyhow!("share denied"))
      },
      |_, _| Some(sharing_violation(&db, WindowsLockedFile::Database, false)),
      || false,
      |_| -> Result<WindowsFallbackSource<()>> { panic!("no-WAL source must not be raw-copied") },
      |_| {
        shutdown_calls.set(shutdown_calls.get() + 1);
        false
      },
    )
    .expect_err("failed explicit shutdown leaves a typed lock");

    let locked = error
      .downcast_ref::<WindowsDatabaseLocked>()
      .expect("typed locked context");
    assert!(locked.shutdown_allowed);
    assert_eq!(query_calls.get(), 1);
    assert_eq!(shutdown_calls.get(), 1);
  }

  #[test]
  fn acquired_shadow_query_failure_never_authorizes_shutdown() {
    let db = PathBuf::from("live/Cookies");
    let shadow_db = PathBuf::from("shadow/Cookies");
    let query_calls = Cell::new(0);
    let error = with_windows_locked_database_policy(
      &db,
      WindowsLockedDatabasePolicy::AllowProcessShutdown,
      |_| {
        let call = query_calls.get() + 1;
        query_calls.set(call);
        if call == 1 {
          Err::<(), _>(anyhow!("share denied"))
        } else {
          Err::<(), _>(anyhow!("shadow schema mismatch"))
        }
      },
      |_, _| Some(sharing_violation(&db, WindowsLockedFile::Database, true)),
      || true,
      |_| {
        Ok(WindowsFallbackSource {
          path: shadow_db.clone(),
          _guard: (),
        })
      },
      |_| panic!("query failures never authorize process shutdown"),
    )
    .expect_err("shadow query schema error remains final");

    assert_eq!(error.to_string(), "shadow schema mismatch");
    assert_eq!(query_calls.get(), 2);
  }

  #[test]
  fn successful_shutdown_with_a_still_failing_unclassified_retry_returns_the_retry_error_untyped() {
    let db = PathBuf::from("no-wal/Cookies");
    let query_calls = Cell::new(0);
    let classify_calls = Cell::new(0);
    let error = with_windows_locked_database_policy(
      &db,
      WindowsLockedDatabasePolicy::AllowProcessShutdown,
      |_| {
        query_calls.set(query_calls.get() + 1);
        Err::<(), _>(anyhow!("share denied"))
      },
      |_, _| {
        let call = classify_calls.get() + 1;
        classify_calls.set(call);
        if call == 1 {
          Some(sharing_violation(&db, WindowsLockedFile::Database, false))
        } else {
          None
        }
      },
      || panic!("a no-WAL source must not inspect privilege"),
      |_| -> Result<WindowsFallbackSource<()>> { panic!("a no-WAL source must not be raw-copied") },
      |_| true,
    )
    .expect_err("a retry that stays unclassified surfaces the retry error as-is");

    assert_eq!(error.to_string(), "share denied");
    assert!(error.downcast_ref::<WindowsDatabaseLocked>().is_none());
    assert_eq!(query_calls.get(), 2);
    assert_eq!(classify_calls.get(), 2);
  }

  #[test]
  fn failed_shutdown_after_a_failed_shadow_reports_the_shadow_failure_without_a_retry() {
    let db = PathBuf::from("live/Cookies");
    let shutdown_calls = Cell::new(0);
    let error = with_windows_locked_database_policy(
      &db,
      WindowsLockedDatabasePolicy::AllowProcessShutdown,
      |_| Err::<(), _>(anyhow!("share denied")),
      |_, _| Some(sharing_violation(&db, WindowsLockedFile::Database, true)),
      || true,
      |_| Err::<WindowsFallbackSource<()>, _>(anyhow!("shadow unavailable")),
      |_| {
        shutdown_calls.set(shutdown_calls.get() + 1);
        false
      },
    )
    .expect_err("a failed shadow with a failed shutdown remains a typed locked failure");

    assert_eq!(shutdown_calls.get(), 1);
    let locked = error
      .downcast_ref::<WindowsDatabaseLocked>()
      .expect("typed locked context");
    assert!(locked.shutdown_allowed);
    let fallback = error
      .downcast_ref::<WindowsShadowFallbackFailure>()
      .expect("shadow acquisition diagnostic remains typed");
    assert!(fallback.shadow_diagnostic.contains("shadow unavailable"));
    assert!(
      fallback.retry_diagnostic.is_none(),
      "shutdown never ran a retry query, so there is no retry diagnostic"
    );
  }

  #[test]
  fn classifier_requires_acquisition_stage_and_a_real_sharing_code() {
    let db = PathBuf::from("live/Cookies");
    let raw_sharing = std::io::Error::from_raw_os_error(ERROR_SHARING_VIOLATION_CODE);
    let query_error = synthetic_query_error(raw_sharing);
    assert!(
      classify_windows_sharing_violation_with_probe(&db, &query_error, |_, _| Some(
        sharing_violation(&db, WindowsLockedFile::Database, false)
      ))
      .is_none()
    );

    let busy = synthetic_acquisition_error(
      Some(sqlite::DatabaseAcquisitionStrategy::LiveReadOnly),
      rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY), None),
    );
    assert!(
      classify_windows_sharing_violation_with_probe(&db, &busy, |_, _| {
        panic!("SQLite BUSY is not a Windows sharing violation")
      })
      .is_none()
    );
  }

  #[test]
  fn classifier_preserves_db_and_wal_sharing_sites_and_wal_proof() {
    let db = PathBuf::from("live/Cookies");
    for (code, locked_file) in [
      (ERROR_SHARING_VIOLATION_CODE, WindowsLockedFile::Database),
      (ERROR_LOCK_VIOLATION_CODE, WindowsLockedFile::WriteAheadLog),
    ] {
      let error = synthetic_acquisition_error(
        Some(sqlite::DatabaseAcquisitionStrategy::VerifiedWalSnapshot),
        std::io::Error::from_raw_os_error(code),
      );
      let violation =
        classify_windows_sharing_violation_with_probe(&db, &error, |_, include_wal| {
          assert!(include_wal);
          Some(WindowsSharingViolation {
            locked_file,
            locked_path: match locked_file {
              WindowsLockedFile::Database => db.clone(),
              WindowsLockedFile::WriteAheadLog => sqlite::sidecar(&db, "-wal"),
            },
            // The acquisition strategy must retain its earlier positive WAL
            // proof even if a later probe cannot stat the share-denied sidecar.
            has_verified_nonempty_wal: false,
            os_error: code,
          })
        })
        .expect("typed sharing violation");

      assert_eq!(violation.locked_file, locked_file);
      assert_eq!(violation.os_error, code);
      assert!(violation.has_verified_nonempty_wal);
    }
  }

  #[test]
  fn direct_sharing_code_remains_classified_when_the_probe_finds_nothing() {
    let db = PathBuf::from("live/Cookies");
    let error = synthetic_acquisition_error(
      Some(sqlite::DatabaseAcquisitionStrategy::LiveReadOnly),
      std::io::Error::from_raw_os_error(ERROR_SHARING_VIOLATION_CODE),
    );

    let violation = classify_windows_sharing_violation_with_probe(&db, &error, |_, _| None)
      .expect("the direct typed code is authoritative");
    assert_eq!(violation.locked_file, WindowsLockedFile::Database);
    assert_eq!(violation.locked_path, db);
    assert!(!violation.has_verified_nonempty_wal);
    assert_eq!(violation.os_error, ERROR_SHARING_VIOLATION_CODE);
  }

  #[test]
  fn sqlite_cant_open_requires_a_probe_confirmed_database_share_lock() {
    let db = PathBuf::from("live/Cookies");
    let cant_open = synthetic_acquisition_error(
      Some(sqlite::DatabaseAcquisitionStrategy::LiveReadOnly),
      rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CANTOPEN),
        None,
      ),
    );
    let violation =
      classify_windows_sharing_violation_with_probe(&db, &cant_open, |_, include_wal| {
        assert!(!include_wal, "generic CANTOPEN must not probe the WAL");
        Some(sharing_violation(&db, WindowsLockedFile::Database, false))
      })
      .expect("database probe confirms sharing violation");
    assert_eq!(violation.locked_file, WindowsLockedFile::Database);

    assert!(
      classify_windows_sharing_violation_with_probe(&db, &cant_open, |_, _| None).is_none(),
      "CANTOPEN without a confirmed Win32 sharing violation is not a fallback trigger"
    );
  }
}
