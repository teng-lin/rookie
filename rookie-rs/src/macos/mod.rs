use anyhow::{anyhow, bail, Result};

use std::process::Command;
use zeroize::Zeroizing;

/// Retrieves the plaintext Keychain password, wrapped so it is wiped from
/// memory when the caller drops it rather than left in freed heap memory.
pub fn get_osx_keychain_password(
  osx_key_service: &str,
  osx_key_user: &str,
) -> Result<Zeroizing<String>> {
  let cmd = Command::new("/usr/bin/security")
    .args([
      "-q",
      "find-generic-password",
      "-w",
      "-a",
      osx_key_user,
      "-s",
      osx_key_service,
    ])
    .output();

  match cmd {
    Ok(output) => {
      if output.status.success() {
        // Wrap the raw output immediately: `trim().to_string()` below copies
        // into a second allocation, and without this wrapper the original
        // (untrimmed) plaintext password would be dropped unzeroized.
        let password = Zeroizing::new(String::from_utf8(output.stdout)?);
        Ok(Zeroizing::new(password.trim().to_string()))
      } else {
        bail!("Failed to retrieve password from OSX Keychain")
      }
    }
    Err(e) => Err(anyhow!("Error executing security command: {}", e)),
  }
}
