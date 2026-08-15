use anyhow::{anyhow, Context, Result};

use std::process::Command;
use zeroize::Zeroizing;

const MAX_SECURITY_STDERR_CHARS: usize = 512;

fn sanitize_security_stderr(stderr: &[u8]) -> String {
  let normalized = String::from_utf8_lossy(stderr)
    .split_whitespace()
    .collect::<Vec<_>>()
    .join(" ");
  if normalized.is_empty() {
    return "<empty>".to_string();
  }

  let mut chars = normalized.chars();
  let mut sanitized: String = chars.by_ref().take(MAX_SECURITY_STDERR_CHARS).collect();
  if chars.next().is_some() {
    sanitized.push('…');
  }
  sanitized
}

fn keychain_lookup_error(exit_code: Option<i32>, stderr: &[u8]) -> anyhow::Error {
  let kind = match exit_code {
    // `security` returns errSecItemNotFound unchanged as its process status.
    Some(44) => "item not found",
    // Authorization cancellation and denial are commonly surfaced as 128.
    Some(128) => "access denied or interaction canceled",
    _ => "lookup command failed",
  };
  let status = exit_code
    .map(|code| format!("exit code {code}"))
    .unwrap_or_else(|| "terminated without an exit code".to_string());
  anyhow!(
    "macOS Keychain {kind} ({status}; sanitized stderr: {})",
    sanitize_security_stderr(stderr)
  )
}

/// Retrieves the plaintext Keychain password, wrapped so it is wiped from
/// memory when the caller drops it rather than left in freed heap memory.
pub fn get_osx_keychain_password(
  osx_key_service: &str,
  osx_key_user: &str,
) -> Result<Zeroizing<String>> {
  let output = Command::new("/usr/bin/security")
    .args([
      "-q",
      "find-generic-password",
      "-w",
      "-a",
      osx_key_user,
      "-s",
      osx_key_service,
    ])
    .output()
    .context("failed to execute /usr/bin/security for macOS Keychain lookup")?;

  if !output.status.success() {
    return Err(keychain_lookup_error(output.status.code(), &output.stderr));
  }

  // Wrap the raw output immediately: `trim().to_string()` below copies into a
  // second allocation, and without this wrapper the original (untrimmed)
  // plaintext password would be dropped unzeroized.
  let password = Zeroizing::new(
    String::from_utf8(output.stdout).context("macOS Keychain password is not valid UTF-8")?,
  );
  Ok(Zeroizing::new(password.trim().to_string()))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn keychain_errors_preserve_status_and_sanitize_stderr() {
    let error = keychain_lookup_error(Some(44), b"  first line\nsecond\tline  ").to_string();
    assert!(error.contains("item not found"));
    assert!(error.contains("exit code 44"));
    assert!(error.contains("sanitized stderr: first line second line"));
    assert!(!error.contains('\n'));
  }

  #[test]
  fn keychain_errors_distinguish_access_denial() {
    let error = keychain_lookup_error(Some(128), b"User interaction is not allowed.").to_string();
    assert!(error.contains("access denied or interaction canceled"));
    assert!(error.contains("exit code 128"));
  }

  #[test]
  fn keychain_stderr_is_bounded() {
    let stderr = vec![b'x'; MAX_SECURITY_STDERR_CHARS + 20];
    let sanitized = sanitize_security_stderr(&stderr);
    assert_eq!(sanitized.chars().count(), MAX_SECURITY_STDERR_CHARS + 1);
    assert!(sanitized.ends_with('…'));
  }
}
