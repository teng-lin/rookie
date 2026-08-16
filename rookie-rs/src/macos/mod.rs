use anyhow::{anyhow, Context, Result};

use crate::common::secret::{SecretBytes, SecretString};
use std::process::Command;

fn keychain_lookup_error(exit_code: Option<i32>, stderr_len: usize) -> anyhow::Error {
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
  anyhow!("macOS Keychain {kind} ({status}; stderr redacted, {stderr_len} byte(s))")
}

/// Retrieves the plaintext Keychain password, wrapped so it is wiped from
/// memory when the caller drops it rather than left in freed heap memory.
pub(crate) fn get_osx_keychain_password(
  osx_key_service: &str,
  osx_key_user: &str,
) -> Result<SecretString> {
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
  // Both streams may contain credential material if the native tool behaves
  // unexpectedly. Own them as secret frames before inspecting status so every
  // success and failure path wipes discarded buffers.
  let stdout = SecretBytes::new(output.stdout);
  let stderr = SecretBytes::new(output.stderr);

  if !output.status.success() {
    return Err(keychain_lookup_error(output.status.code(), stderr.len()));
  }

  let password = stdout
    .into_secret_string()
    .context("macOS Keychain password is not valid UTF-8")?;
  Ok(password.trimmed())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn keychain_errors_preserve_status_and_redact_stderr() {
    let sentinel = "rookie-secret-sentinel-7e8b";
    let error = keychain_lookup_error(Some(44), sentinel.len()).to_string();
    assert!(error.contains("item not found"));
    assert!(error.contains("exit code 44"));
    assert!(error.contains("stderr redacted"));
    assert!(!error.contains(sentinel));
  }

  #[test]
  fn keychain_errors_distinguish_access_denial() {
    let error = keychain_lookup_error(Some(128), 32).to_string();
    assert!(error.contains("access denied or interaction canceled"));
    assert!(error.contains("exit code 128"));
  }

  #[test]
  fn keychain_stderr_reports_only_bounded_metadata() {
    let error = keychain_lookup_error(None, usize::MAX).to_string();
    assert!(error.contains("stderr redacted"));
    assert!(error.contains(&usize::MAX.to_string()));
  }
}
