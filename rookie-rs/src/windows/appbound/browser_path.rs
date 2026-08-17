use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

pub struct BrowserExeMeta {
  pub exe_name: &'static str,
  pub fallbacks: &'static [&'static str],
}

pub const KNOWN_BROWSERS: &[(&str, BrowserExeMeta)] = &[
  (
    "chrome",
    BrowserExeMeta {
      exe_name: "chrome.exe",
      fallbacks: &[
        r"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
        r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe",
        r"%LocalAppData%\Google\Chrome\Application\chrome.exe",
      ],
    },
  ),
  (
    "brave",
    BrowserExeMeta {
      exe_name: "brave.exe",
      fallbacks: &[
        r"%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe",
        r"%ProgramFiles(x86)%\BraveSoftware\Brave-Browser\Application\brave.exe",
        r"%LocalAppData%\BraveSoftware\Brave-Browser\Application\brave.exe",
      ],
    },
  ),
  (
    "edge",
    BrowserExeMeta {
      exe_name: "msedge.exe",
      fallbacks: &[
        r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe",
        r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
        r"%LocalAppData%\Microsoft\Edge\Application\msedge.exe",
      ],
    },
  ),
  (
    "coccoc",
    BrowserExeMeta {
      exe_name: "browser.exe",
      fallbacks: &[
        r"%ProgramFiles%\CocCoc\Browser\Application\browser.exe",
        r"%ProgramFiles(x86)%\CocCoc\Browser\Application\browser.exe",
        r"%LocalAppData%\CocCoc\Browser\Application\browser.exe",
      ],
    },
  ),
  (
    "avast",
    BrowserExeMeta {
      exe_name: "avastbrowser.exe",
      fallbacks: &[
        r"%ProgramFiles%\AVAST Software\Browser\Application\AvastBrowser.exe",
        r"%ProgramFiles(x86)%\AVAST Software\Browser\Application\AvastBrowser.exe",
      ],
    },
  ),
];

pub fn get_browser_meta(name: &str) -> Option<&'static BrowserExeMeta> {
  let lower = name.to_ascii_lowercase();
  let key = match lower.as_str() {
    "google-chrome" | "google_chrome" | "chrome" | "chromium" => "chrome",
    "brave" | "brave-browser" => "brave",
    "edge" | "msedge" | "microsoft-edge" => "edge",
    "coccoc" | "coc_coc" => "coccoc",
    "avast" | "avastbrowser" => "avast",
    _ => return None,
  };
  KNOWN_BROWSERS
    .iter()
    .find(|(k, _)| *k == key)
    .map(|(_, meta)| meta)
}

/// Expands `%VAR%` syntax using environment variables.
pub fn expand_env_string(input: &str) -> String {
  #[cfg(windows)]
  {
    use windows::core::PCWSTR;
    use windows::Win32::System::Environment::ExpandEnvironmentStringsW;

    let wide_input: Vec<u16> = input.encode_utf16().chain(std::iter::once(0)).collect();
    let mut buffer = vec![0u16; 32767];
    let len = unsafe { ExpandEnvironmentStringsW(PCWSTR(wide_input.as_ptr()), Some(&mut buffer)) };
    if len > 0 && (len as usize) <= buffer.len() {
      return String::from_utf16_lossy(&buffer[..(len as usize - 1)]);
    }
  }

  // Fallback string replacement for testing or non-Windows platforms
  let mut result = input.to_string();
  let mut start = 0;
  while let Some(open) = result[start..].find('%') {
    let open_idx = start + open;
    if let Some(close) = result[open_idx + 1..].find('%') {
      let close_idx = open_idx + 1 + close;
      let var_name = &result[open_idx + 1..close_idx];
      if let Ok(val) = std::env::var(var_name) {
        result.replace_range(open_idx..=close_idx, &val);
        start = open_idx + val.len();
      } else {
        start = close_idx + 1;
      }
    } else {
      break;
    }
  }
  result
}

#[cfg(windows)]
fn query_registry_app_paths(
  exe_name: &str,
  hkey_root: windows::Win32::System::Registry::HKEY,
) -> Option<PathBuf> {
  use windows::core::PCWSTR;
  use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, KEY_QUERY_VALUE, REG_SZ,
  };

  let subkey = format!("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\{exe_name}\0");
  let subkey_w: Vec<u16> = subkey.encode_utf16().collect();
  let mut key = HKEY::default();

  let status = unsafe {
    RegOpenKeyExW(
      hkey_root,
      PCWSTR(subkey_w.as_ptr()),
      0,
      KEY_QUERY_VALUE,
      &mut key,
    )
  };

  if status.is_err() || key.is_invalid() {
    return None;
  }

  let mut buf_size: u32 = 0;
  let mut value_type = REG_SZ;
  let status = unsafe {
    RegQueryValueExW(
      key,
      PCWSTR::null(),
      None,
      Some(&mut value_type),
      None,
      Some(&mut buf_size),
    )
  };

  if status.is_err() || buf_size == 0 {
    let _ = unsafe { RegCloseKey(key) };
    return None;
  }

  let mut buffer = vec![0u8; buf_size as usize];
  let status = unsafe {
    RegQueryValueExW(
      key,
      PCWSTR::null(),
      None,
      Some(&mut value_type),
      Some(buffer.as_mut_ptr()),
      Some(&mut buf_size),
    )
  };

  let _ = unsafe { RegCloseKey(key) };

  if status.is_err() {
    return None;
  }

  let u16_slice: &[u16] = unsafe {
    std::slice::from_raw_parts(
      buffer.as_ptr() as *const u16,
      (buf_size as usize) / std::mem::size_of::<u16>(),
    )
  };

  let mut path_str = String::from_utf16_lossy(u16_slice);
  if let Some(null_pos) = path_str.find('\0') {
    path_str.truncate(null_pos);
  }
  let path_str = path_str.trim().trim_matches('"');
  let path = PathBuf::from(path_str);
  if path.is_file() {
    Some(path)
  } else {
    None
  }
}

/// Resolves the full path to a browser executable by name or checks all known browsers.
pub fn find_browser_executable(browser_hint: Option<&str>) -> Result<PathBuf> {
  if let Some(hint) = browser_hint {
    if let Some(meta) = get_browser_meta(hint) {
      if let Some(path) = find_executable_by_meta(meta) {
        return Ok(path);
      }
    } else {
      // If hint is an existing file path directly
      let p = Path::new(hint);
      if p.is_file() {
        return Ok(p.to_path_buf());
      }
    }
  }

  // If no specific hint or hint failed, try all known browsers in priority order
  for (_, meta) in KNOWN_BROWSERS {
    if let Some(path) = find_executable_by_meta(meta) {
      return Ok(path);
    }
  }

  bail!(
    "Could not find any installed Chromium browser executable for App-Bound decryption (hint={:?})",
    browser_hint
  )
}

fn find_executable_by_meta(meta: &BrowserExeMeta) -> Option<PathBuf> {
  #[cfg(windows)]
  {
    use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

    // 1. Registry HKLM
    if let Some(path) = query_registry_app_paths(meta.exe_name, HKEY_LOCAL_MACHINE) {
      return Some(path);
    }
    // 2. Registry HKCU
    if let Some(path) = query_registry_app_paths(meta.exe_name, HKEY_CURRENT_USER) {
      return Some(path);
    }
  }

  // 3. Known fallback directories
  for &fallback in meta.fallbacks {
    let expanded = expand_env_string(fallback);
    let path = PathBuf::from(expanded);
    if path.is_file() {
      return Some(path);
    }
  }

  None
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn meta_lookup_recognizes_aliases() {
    assert!(get_browser_meta("chrome").is_some());
    assert!(get_browser_meta("google-chrome").is_some());
    assert!(get_browser_meta("brave").is_some());
    assert!(get_browser_meta("edge").is_some());
    assert!(get_browser_meta("unknown_browser").is_none());
  }

  #[test]
  fn env_expansion_replaces_known_variables() {
    std::env::set_var("ROOKIE_TEST_ENV_VAR", "my_custom_value");
    let expanded = expand_env_string("prefix/%ROOKIE_TEST_ENV_VAR%/suffix");
    assert_eq!(expanded, "prefix/my_custom_value/suffix");
  }
}
