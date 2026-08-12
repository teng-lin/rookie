use std::{
  ffi::OsString, marker::PhantomData, os::windows::ffi::OsStringExt, path::Path, rc::Rc,
  sync::Mutex,
};

use anyhow::{bail, Result};
use windows::Win32::System::Threading::OpenProcessToken;
use windows::Win32::{
  Foundation::{CloseHandle, BOOL, HANDLE, NTSTATUS},
  Security::{DuplicateToken, ImpersonateLoggedOnUser, RevertToSelf, TOKEN_DUPLICATE, TOKEN_QUERY},
  System::{
    ProcessStatus::K32GetProcessImageFileNameW,
    Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
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
      log::warn!("Failed to restore SeDebugPrivilege: {err}");
    }
  }
}

fn enable_privilege() -> Result<DebugPrivilegeGuard> {
  DebugPrivilegeGuard::acquire()
}

fn get_process_pids() -> Result<Vec<u32>> {
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
    let mut a_processes: Vec<u32> = vec![0; capacity as usize];
    let mut cb_needed: u32 = 0;

    unsafe {
      EnumProcesses(a_processes.as_mut_ptr(), capacity * 4, &mut cb_needed)?;
    }

    let count = cb_needed / 4;
    if count < capacity || capacity >= MAX_CAPACITY {
      a_processes.truncate(count as usize);
      return Ok(a_processes);
    }

    capacity *= 2;
  }
}

fn get_process_name(pid: u32) -> Result<String> {
  unsafe {
    // Open the process with permissions to query information and read VM
    let process_handle: HANDLE =
      OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)?;
    if process_handle.is_invalid() {
      return Err(windows::core::Error::from_win32().into());
    }
    let mut buffer = vec![0u16; 260]; // 260 is the max path length in Windows

    // Get the process image file name
    let length = K32GetProcessImageFileNameW(process_handle, &mut buffer) as usize;
    CloseHandle(process_handle)?;

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

fn get_system_process_pid() -> Result<u32> {
  let mut fallback_pid = None;

  for pid in get_process_pids()? {
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
      unsafe {
        let _ = CloseHandle(self.0);
      }
    }
  }
}

fn get_system_token(lsass_handle: HANDLE) -> Result<HANDLE> {
  let mut token_handle = HandleGuard(HANDLE::default());
  unsafe {
    OpenProcessToken(
      lsass_handle,
      TOKEN_DUPLICATE | TOKEN_QUERY,
      &mut token_handle.0,
    )?;
  }

  let mut duplicate_token = HandleGuard(HANDLE::default());
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
  duplicated_token: HANDLE,
  _thread_affinity: PhantomData<Rc<()>>,
}

impl Drop for ImpersonationGuard {
  fn drop(&mut self) {
    unsafe {
      let revert_result = RevertToSelf();
      if let Err(err) = CloseHandle(self.duplicated_token) {
        log::warn!("Failed to close SYSTEM impersonation token: {err}");
      }
      if let Err(err) = revert_result {
        log::warn!("Failed to revert SYSTEM impersonation: {err}");
        std::process::abort();
      }
    }
  }
}

pub fn start_impersonate() -> Result<ImpersonationGuard> {
  let lsass_handle = {
    let _debug_privilege_lock = DEBUG_PRIVILEGE_LOCK
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut debug_privilege = enable_privilege()?;
    let pid = get_system_process_pid()?;
    let lsass_handle = HandleGuard(get_process_handle(pid)?);
    debug_privilege.restore()?;
    lsass_handle
  };
  let duplicated_token = HandleGuard(get_system_token(lsass_handle.0)?);
  unsafe {
    ImpersonateLoggedOnUser(duplicated_token.0)?;
  }
  Ok(ImpersonationGuard {
    duplicated_token: duplicated_token.into_inner(),
    _thread_affinity: PhantomData,
  })
}
