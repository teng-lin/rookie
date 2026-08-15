#[cfg(any(target_os = "windows", target_os = "linux"))]
use super::super::chromium_crypto::ChromiumKeyOutcome;
#[cfg(any(target_os = "windows", target_os = "linux"))]
use anyhow::Result;
use zeroize::Zeroizing;

/// Derives a Chromium v10/v11 key from a candidate password.
///
/// Wrapped in `Zeroizing` because this is the key material handed to AES-GCM
/// to decrypt cookie values; it is wiped from memory as soon as its owner
/// drops it rather than left in freed heap memory.
#[cfg(unix)]
pub(crate) fn create_pbkdf2_key(
  password: &str,
  salt: &[u8; 9],
  iterations: u32,
) -> Zeroizing<Vec<u8>> {
  use pbkdf2::pbkdf2_hmac;
  use sha1::Sha1;

  let mut output = [0u8; 16];
  pbkdf2_hmac::<Sha1>(password.as_bytes(), salt, iterations, &mut output);
  Zeroizing::new(output.to_vec())
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub(super) fn outcome_from_result(
  result: Result<Vec<Zeroizing<Vec<u8>>>>,
  empty_failure: &'static str,
) -> ChromiumKeyOutcome {
  match result {
    Ok(candidates) => ChromiumKeyOutcome::success_zeroizing(candidates)
      .unwrap_or_else(|| ChromiumKeyOutcome::failure(empty_failure)),
    Err(error) => ChromiumKeyOutcome::failure(error.to_string()),
  }
}
