use anyhow::{bail, Result};
use windows::{
  core::{HSTRING, PCWSTR, PWSTR},
  Win32::{
    Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS, WIN32_ERROR},
    System::RestartManager::{
      RmEndSession, RmForceShutdown, RmGetList, RmRegisterResources, RmShutdown, RmStartSession,
      CCH_RM_SESSION_KEY,
    },
  },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileLockStatus {
  /// Restart Manager found no process using the database.
  Unlocked,
  /// Restart Manager shut down the processes using the database.
  Released { process_count: u32 },
  /// Processes still hold the database because destructive shutdown was not requested.
  Locked { process_count: u32 },
}

struct RestartManagerSession(u32);

impl Drop for RestartManagerSession {
  fn drop(&mut self) {
    // SAFETY: The handle was returned by a successful `RmStartSession` call and
    // this guard is its sole owner.
    unsafe {
      let _ = RmEndSession(self.0);
    }
  }
}

fn check_restart_manager(operation: &str, result: u32) -> Result<()> {
  if WIN32_ERROR(result) == ERROR_SUCCESS {
    Ok(())
  } else {
    bail!("Restart Manager {operation} failed with Windows error {result}")
  }
}

fn affected_process_count(result: u32, needed: u32, supplied: u32) -> Result<u32> {
  if WIN32_ERROR(result) != ERROR_SUCCESS && WIN32_ERROR(result) != ERROR_MORE_DATA {
    bail!("Restart Manager RmGetList failed with Windows error {result}");
  }

  Ok(needed.max(supplied))
}

/// Inspect the processes locking `file_path` and optionally ask Restart Manager
/// to shut them down.
///
/// With `force_kill == false`, this is non-destructive and reports
/// [`FileLockStatus::Locked`] to the caller. The caller must not proceed as if
/// the file had been unlocked.
///
/// # Safety
///
/// `RmShutdown` can terminate applications when `force_kill` is true. Callers
/// must only opt in when that disruptive behavior was explicitly requested.
pub(crate) unsafe fn release_file_lock(
  file_path: &str,
  force_kill: bool,
) -> Result<FileLockStatus> {
  let file_path = HSTRING::from(file_path);
  let mut session = 0_u32;
  let mut session_key_buffer = [0_u16; (CCH_RM_SESSION_KEY as usize) + 1];
  check_restart_manager(
    "RmStartSession",
    RmStartSession(&mut session, 0, PWSTR(session_key_buffer.as_mut_ptr())),
  )?;
  let session = RestartManagerSession(session);

  check_restart_manager(
    "RmRegisterResources",
    RmRegisterResources(session.0, Some(&[PCWSTR(file_path.as_ptr())]), None, None),
  )?;

  // A count-only query avoids a fixed-size process buffer. ERROR_MORE_DATA is
  // the documented response when affected processes exist and no buffer was
  // supplied; `needed` is then the exact number of lockers.
  let mut needed = 0_u32;
  let mut supplied = 0_u32;
  let mut reboot_reasons = 0_u32;
  let query_result = RmGetList(
    session.0,
    &mut needed,
    &mut supplied,
    None,
    &mut reboot_reasons,
  );
  let process_count = affected_process_count(query_result, needed, supplied)?;
  if process_count == 0 {
    return Ok(FileLockStatus::Unlocked);
  }

  if !force_kill {
    return Ok(FileLockStatus::Locked { process_count });
  }

  check_restart_manager(
    "RmShutdown",
    RmShutdown(session.0, RmForceShutdown.0 as u32, None),
  )?;
  Ok(FileLockStatus::Released { process_count })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn affected_process_count_accepts_unlocked_query() {
    assert_eq!(affected_process_count(ERROR_SUCCESS.0, 0, 0).unwrap(), 0);
  }

  #[test]
  fn affected_process_count_uses_required_buffer_size() {
    assert_eq!(affected_process_count(ERROR_MORE_DATA.0, 3, 0).unwrap(), 3);
  }

  #[test]
  fn affected_process_count_rejects_restart_manager_errors() {
    let error = affected_process_count(5, 0, 0).unwrap_err().to_string();
    assert_eq!(
      error,
      "Restart Manager RmGetList failed with Windows error 5"
    );
  }
}
