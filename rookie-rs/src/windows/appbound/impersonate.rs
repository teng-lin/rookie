use std::{
  ffi::OsString, marker::PhantomData, os::windows::ffi::OsStringExt, path::Path, rc::Rc,
  sync::Mutex,
};

use anyhow::{bail, Result};
use windows::Win32::{
  Foundation::{CloseHandle, BOOL, ERROR_NO_TOKEN, HANDLE, NTSTATUS, WIN32_ERROR},
  Security::{
    DuplicateToken, ImpersonateLoggedOnUser, RevertToSelf, TOKEN_DUPLICATE, TOKEN_IMPERSONATE,
    TOKEN_QUERY,
  },
  System::{
    ProcessStatus::K32GetProcessImageFileNameW,
    Threading::{
      GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken, SetThreadToken,
      PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    },
  },
};

#[link(name = "ntdll")]
extern "system" {
  fn RtlAdjustPrivilege(
    privilege: i32,
    enable: BOOL,
    current_thread: BOOL,
    previous_value: *mut BOOL,
  ) -> NTSTATUS;
}

// RtlAdjustPrivilege changes the process token, so serialize its temporary use.
static DEBUG_PRIVILEGE_LOCK: Mutex<()> = Mutex::new(());

struct DebugPrivilegeGuard {
  previous_value: Option<BOOL>,
}

impl DebugPrivilegeGuard {
  fn acquire() -> Result<Self> {
    use windows::Wdk::System::SystemServices::SE_DEBUG_PRIVILEGE;

    let mut previous_value = BOOL(0);
    // SAFETY: Enabling SE_DEBUG_PRIVILEGE on the current process token; previous state is captured in `previous_value`.
    let status =
      unsafe { RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, BOOL(1), BOOL(0), &mut previous_value) };
    if status.0 != 0 {
      bail!("Failed to enable SeDebugPrivilege: {status:?}")
    }
    Ok(Self {
      previous_value: Some(previous_value),
    })
  }

  fn restore(&mut self) -> Result<()> {
    use windows::Wdk::System::SystemServices::SE_DEBUG_PRIVILEGE;

    let Some(previous_value) = self.previous_value else {
      return Ok(());
    };

    let mut ignored_previous_value = BOOL(0);
    // SAFETY: Restoring SE_DEBUG_PRIVILEGE to its previous value captured at acquisition time.
    let status = unsafe {
      RtlAdjustPrivilege(
        SE_DEBUG_PRIVILEGE,
        previous_value,
        BOOL(0),
        &mut ignored_previous_value,
      )
    };
    if status.0 != 0 {
      bail!("Failed to restore SeDebugPrivilege: {status:?}")
    }

    self.previous_value = None;
    Ok(())
  }
}

impl Drop for DebugPrivilegeGuard {
  fn drop(&mut self) {
    if let Err(err) = self.restore() {
      // Returning to the embedder with process-wide debug privilege still
      // enabled is a privilege leak. The explicit restore path already had
      // one attempt; if cleanup cannot restore it either, fail closed.
      log::error!("Failed to restore SeDebugPrivilege: {err}");
      std::process::abort();
    }
  }
}

fn enable_privilege() -> Result<DebugPrivilegeGuard> {
  DebugPrivilegeGuard::acquire()
}

fn get_process_pids(runtime: &crate::common::deadline::BoundaryRuntime<'_>) -> Result<Vec<u32>> {
  use windows::Win32::System::ProcessStatus::EnumProcesses;

  // EnumProcesses has no way to report "the buffer was too small" - it just
  // fills the buffer and returns the number of bytes written. If the byte
  // count returned equals the full capacity of the buffer, that's a strong
  // signal the list was truncated (there could be more PIDs than fit), so we
  // grow the buffer and retry rather than silently dropping processes. This
  // matters because the PID list is used to find lsass.exe/winlogon.exe for
  // SYSTEM impersonation; a truncated list on a busy machine could cause the
  // target process to be missed with no error at all.
  const MAX_CAPACITY: u32 = 65536;
  let mut capacity: u32 = 1024;

  loop {
    runtime.check()?;
    let mut a_processes: Vec<u32> = vec![0; capacity as usize];
    let mut cb_needed: u32 = 0;

    // SAFETY: `a_processes` is allocated with `capacity` u32 elements (capacity * 4 bytes),
    // and `cb_needed` receives the byte count written by EnumProcesses.
    unsafe {
      EnumProcesses(a_processes.as_mut_ptr(), capacity * 4, &mut cb_needed)?;
    }

    let count = cb_needed / 4;
    if count < capacity {
      a_processes.truncate(count as usize);
      return Ok(a_processes);
    }

    if capacity >= MAX_CAPACITY {
      bail!(
        "EnumProcesses reported at least {count} processes, filling the \
         {MAX_CAPACITY}-entry capacity cap; refusing to silently truncate the \
         process list used to locate lsass.exe/winlogon.exe for SYSTEM \
         impersonation"
      );
    }

    capacity = capacity.saturating_mul(2).min(MAX_CAPACITY);
  }
}

fn get_process_name(pid: u32) -> Result<String> {
  // SAFETY: `pid` is an active PID; OpenProcess and K32GetProcessImageFileNameW query the
  // executable name into the preallocated `buffer`.
  unsafe {
    // Open the process with permissions to query information and read VM
    let process_handle = HandleGuard(OpenProcess(
      PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
      false,
      pid,
    )?);
    if process_handle.0.is_invalid() {
      return Err(windows::core::Error::from_win32().into());
    }
    let mut buffer = vec![0u16; 260]; // 260 is the max path length in Windows

    // Get the process image file name
    let length = K32GetProcessImageFileNameW(process_handle.0, &mut buffer) as usize;

    // Convert the buffer to a Rust String and trim the null terminator
    let full_path = OsString::from_wide(&buffer[..length])
      .to_string_lossy()
      .into_owned();
    let executable_name = Path::new(&full_path)
      .file_name()
      .and_then(|name| name.to_str())
      .unwrap_or("")
      .to_string();
    Ok(executable_name)
  }
}

fn get_system_process_pid(runtime: &crate::common::deadline::BoundaryRuntime<'_>) -> Result<u32> {
  let mut fallback_pid = None;

  for pid in get_process_pids(runtime)? {
    runtime.check()?;
    let process_name = get_process_name(pid).unwrap_or_default();

    if process_name == "lsass.exe" {
      return Ok(pid);
    } else if process_name == "winlogon.exe" {
      fallback_pid = Some(pid);
    }
  }
  if let Some(pid) = fallback_pid {
    return Ok(pid);
  }
  bail!("Neither lsass.exe nor winlogon.exe found!")
}

fn get_process_handle(pid: u32) -> Result<HANDLE> {
  // SAFETY: `pid` is an existing process ID to open with query rights.
  unsafe {
    // Open the process with PROCESS_QUERY_INFORMATION permission
    let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid)?;

    // Check if the handle is valid
    if process_handle.is_invalid() {
      Err(windows::core::Error::from_win32().into())
    } else {
      Ok(process_handle)
    }
  }
}

struct HandleGuard(HANDLE);

impl HandleGuard {
  fn into_inner(mut self) -> HANDLE {
    let handle = self.0;
    self.0 = HANDLE::default();
    handle
  }
}

impl Drop for HandleGuard {
  fn drop(&mut self) {
    if !self.0.is_invalid() {
      // SAFETY: `self.0` is a valid, owned non-invalid Windows handle that must be closed.
      unsafe {
        if let Err(error) = CloseHandle(self.0) {
          log::warn!("Failed to close Windows handle: {error}");
        }
      }
    }
  }
}

fn get_system_token(lsass_handle: HANDLE) -> Result<HANDLE> {
  let mut token_handle = HandleGuard(HANDLE::default());
  // SAFETY: `lsass_handle` is a valid open process handle and `token_handle.0` receives the opened token.
  unsafe {
    OpenProcessToken(
      lsass_handle,
      TOKEN_DUPLICATE | TOKEN_QUERY,
      &mut token_handle.0,
    )?;
  }

  let mut duplicate_token = HandleGuard(HANDLE::default());
  // SAFETY: `token_handle.0` is a valid token handle and `duplicate_token.0` receives the duplicated token.
  unsafe {
    DuplicateToken(
      token_handle.0,
      windows::Win32::Security::SECURITY_IMPERSONATION_LEVEL(2), // win32security.SecurityImpersonation
      &mut duplicate_token.0,
    )?;
  }

  Ok(duplicate_token.into_inner())
}

pub struct ImpersonationGuard {
  _duplicated_token: HandleGuard,
  previous_thread_token: Option<HandleGuard>,
  _thread_affinity: PhantomData<Rc<()>>,
}

impl Drop for ImpersonationGuard {
  fn drop(&mut self) {
    let restore_result = restore_thread_identity(self.previous_thread_token.as_ref());
    if let Err(err) = restore_result {
      // Continuing under SYSTEM (or another unexpected identity) is less safe
      // than terminating. In particular, service and RPC hosts may reuse this
      // thread for an unrelated caller after the guard is dropped.
      log::error!("Failed to restore the caller's Windows thread identity: {err}");
      std::process::abort();
    }
  }
}

fn restore_thread_identity(
  previous_thread_token: Option<&HandleGuard>,
) -> windows::core::Result<()> {
  // SAFETY: `SetThreadToken` and `RevertToSelf` restore the caller's previous impersonation
  // token or revert the thread to the process identity.
  unsafe {
    match previous_thread_token {
      Some(token) => SetThreadToken(None, token.0),
      None => RevertToSelf(),
    }
  }
}

fn capture_thread_token() -> Result<Option<HandleGuard>> {
  let mut token = HandleGuard(HANDLE::default());
  // SAFETY: `GetCurrentThread()` returns the current thread pseudo-handle and `token.0` receives the token if present.
  let result = unsafe {
    OpenThreadToken(
      GetCurrentThread(),
      TOKEN_IMPERSONATE | TOKEN_QUERY,
      true,
      &mut token.0,
    )
  };
  match result {
    Ok(()) => Ok(Some(token)),
    Err(error) if WIN32_ERROR::from_error(&error) == Some(ERROR_NO_TOKEN) => Ok(None),
    Err(error) => Err(error.into()),
  }
}

/// Temporarily removes a caller's thread impersonation so privileged process
/// operations run under the process identity. If acquisition fails, dropping
/// this guard restores the captured caller token before the error escapes.
struct SuspendedThreadIdentity {
  previous_thread_token: Option<HandleGuard>,
  _thread_affinity: PhantomData<Rc<()>>,
}

impl SuspendedThreadIdentity {
  fn suspend() -> Result<Self> {
    let previous_thread_token = capture_thread_token()?;
    if previous_thread_token.is_some() {
      // SAFETY: Reverting current thread impersonation to use the process token during elevation.
      unsafe {
        RevertToSelf()?;
      }
    }
    Ok(Self {
      previous_thread_token,
      _thread_affinity: PhantomData,
    })
  }

  fn into_previous_thread_token(mut self) -> Option<HandleGuard> {
    self.previous_thread_token.take()
  }
}

impl Drop for SuspendedThreadIdentity {
  fn drop(&mut self) {
    let Some(previous_thread_token) = self.previous_thread_token.as_ref() else {
      return;
    };
    if let Err(err) = restore_thread_identity(Some(previous_thread_token)) {
      // The caller identity was removed successfully, so returning through an
      // error path without restoring it would run embedder code as the process.
      log::error!("Failed to restore a suspended Windows thread identity: {err}");
      std::process::abort();
    }
  }
}

fn impersonate_with_suspended_identity(
  duplicated_token: HandleGuard,
  suspended_identity: SuspendedThreadIdentity,
) -> Result<ImpersonationGuard> {
  // SAFETY: `duplicated_token.0` is a valid duplicated token handle with impersonation rights.
  unsafe {
    ImpersonateLoggedOnUser(duplicated_token.0)?;
  }
  let previous_thread_token = suspended_identity.into_previous_thread_token();
  Ok(ImpersonationGuard {
    _duplicated_token: duplicated_token,
    previous_thread_token,
    _thread_affinity: PhantomData,
  })
}

#[cfg(test)]
fn impersonate_with_token(duplicated_token: HandleGuard) -> Result<ImpersonationGuard> {
  let suspended_identity = SuspendedThreadIdentity::suspend()?;
  impersonate_with_suspended_identity(duplicated_token, suspended_identity)
}

fn acquire_debug_privilege_lock<'a>(
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<std::sync::MutexGuard<'a, ()>> {
  const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);
  loop {
    runtime.check()?;
    match DEBUG_PRIVILEGE_LOCK.try_lock() {
      Ok(guard) => return Ok(guard),
      Err(std::sync::TryLockError::Poisoned(poisoned)) => return Ok(poisoned.into_inner()),
      Err(std::sync::TryLockError::WouldBlock) => {
        let sleep_time = runtime.deadline.remaining(runtime.clock).min(POLL_INTERVAL);
        if sleep_time.is_zero() {
          runtime.check()?;
        }
        runtime.clock.sleep(sleep_time);
      }
    }
  }
}

pub fn start_impersonate(
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<ImpersonationGuard> {
  runtime.check()?;
  // Service and RPC threads may already impersonate an unprivileged client.
  // Suspend that identity before process enumeration and LSASS access so the
  // process token (with temporary SeDebugPrivilege) governs those checks.
  let suspended_identity = SuspendedThreadIdentity::suspend()?;
  let lsass_handle = {
    let _debug_privilege_lock = acquire_debug_privilege_lock(runtime)?;
    runtime.check()?;
    let mut debug_privilege = enable_privilege()?;
    let pid = get_system_process_pid(runtime)?;
    runtime.check()?;
    let lsass_handle = HandleGuard(get_process_handle(pid)?);
    debug_privilege.restore()?;
    lsass_handle
  };
  runtime.check()?;
  let duplicated_token = HandleGuard(get_system_token(lsass_handle.0)?);
  impersonate_with_suspended_identity(duplicated_token, suspended_identity)
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::{ffi::c_void, mem::size_of};
  use windows::Win32::{
    Foundation::LUID,
    Security::{GetTokenInformation, TokenStatistics, TOKEN_STATISTICS},
    System::Threading::GetCurrentProcess,
  };

  struct ThreadIdentityCleanup;

  impl Drop for ThreadIdentityCleanup {
    fn drop(&mut self) {
      // SAFETY: Reverting thread impersonation in test cleanup to restore test runner identity.
      unsafe {
        RevertToSelf().expect("restore process identity after nested impersonation test");
      }
    }
  }

  fn duplicate_current_process_token() -> HandleGuard {
    let mut process_token = HandleGuard(HANDLE::default());
    // SAFETY: `GetCurrentProcess()` returns the current process pseudo-handle and `process_token.0` receives the token.
    unsafe {
      OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_DUPLICATE | TOKEN_QUERY,
        &mut process_token.0,
      )
      .expect("open current process token");
    }
    let mut duplicate = HandleGuard(HANDLE::default());
    // SAFETY: `process_token.0` is a valid open token handle and `duplicate.0` receives the duplicated token.
    unsafe {
      DuplicateToken(
        process_token.0,
        windows::Win32::Security::SECURITY_IMPERSONATION_LEVEL(2),
        &mut duplicate.0,
      )
      .expect("duplicate current process token");
    }
    duplicate
  }

  fn token_id(token: HANDLE) -> LUID {
    let mut statistics = TOKEN_STATISTICS::default();
    let mut returned = 0;
    // SAFETY: `token` is a valid open token handle, `statistics` is sized to `TOKEN_STATISTICS`, and `returned` receives the byte count.
    unsafe {
      GetTokenInformation(
        token,
        TokenStatistics,
        Some((&mut statistics as *mut TOKEN_STATISTICS).cast::<c_void>()),
        u32::try_from(size_of::<TOKEN_STATISTICS>()).expect("token statistics size fits u32"),
        &mut returned,
      )
      .expect("read token statistics");
    }
    assert_eq!(
      returned as usize,
      size_of::<TOKEN_STATISTICS>(),
      "unexpected token statistics size"
    );
    statistics.TokenId
  }

  fn current_thread_token_id() -> LUID {
    let token = capture_thread_token()
      .expect("query current thread token")
      .expect("thread is impersonating");
    token_id(token.0)
  }

  #[test]
  fn nested_impersonation_restores_the_original_thread_token() {
    let original = duplicate_current_process_token();
    let replacement = duplicate_current_process_token();
    let original_id = token_id(original.0);
    let replacement_id = token_id(replacement.0);
    assert_ne!(original_id, replacement_id, "fixtures need distinct tokens");

    // SAFETY: `original.0` is a valid duplicated token with SecurityImpersonation level.
    unsafe {
      ImpersonateLoggedOnUser(original.0).expect("impersonate token A");
    }
    let _cleanup = ThreadIdentityCleanup;
    assert_eq!(current_thread_token_id(), original_id);

    let guard = impersonate_with_token(replacement).expect("impersonate token B inside token A");
    assert_eq!(current_thread_token_id(), replacement_id);
    drop(guard);

    assert_eq!(
      current_thread_token_id(),
      original_id,
      "dropping token B must restore token A, not the process identity"
    );
  }

  #[test]
  fn suspended_identity_uses_process_identity_then_restores_the_caller() {
    let original = duplicate_current_process_token();
    let original_id = token_id(original.0);

    // SAFETY: `original.0` is a valid duplicated token with SecurityImpersonation level.
    unsafe {
      ImpersonateLoggedOnUser(original.0).expect("impersonate caller token");
    }
    let _cleanup = ThreadIdentityCleanup;
    assert_eq!(current_thread_token_id(), original_id);

    let suspended = SuspendedThreadIdentity::suspend().expect("suspend caller identity");
    assert!(
      capture_thread_token()
        .expect("query suspended thread token")
        .is_none(),
      "privileged acquisition must run under the process identity"
    );
    drop(suspended);

    assert_eq!(
      current_thread_token_id(),
      original_id,
      "the suspended caller token must be restored on exit"
    );
  }

  #[test]
  fn acquire_debug_privilege_lock_honors_runtime_cancellation_and_deadline() {
    let clock = crate::common::deadline::test_clock::ManualClock::default();
    let stop = crate::common::deadline::CancellationToken::default();
    stop.cancel();
    let runtime = crate::common::deadline::BoundaryRuntime::with_stop(
      &clock,
      crate::common::deadline::Deadline::after(&clock, std::time::Duration::from_secs(10)),
      stop,
    );
    let result = acquire_debug_privilege_lock(&runtime);
    assert!(result.is_err());
  }
}
