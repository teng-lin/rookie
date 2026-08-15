use super::LegacyCipherOutcome;
use anyhow::{bail, Result};

pub(super) const CANDIDATE_KEY_LENGTH: Option<usize> = None;

pub(super) fn validate_keyed_envelope(_encrypted_value: &[u8]) -> Result<()> {
  Ok(())
}

pub(super) fn decrypt_keyed_candidate(_encrypted_value: &[u8], _key: &[u8]) -> Result<Vec<u8>> {
  bail!("Chromium keyed cookie decryption is unsupported on this platform")
}

pub(super) fn decrypt_legacy(_encrypted_value: &[u8]) -> Result<LegacyCipherOutcome> {
  Ok(LegacyCipherOutcome::Unsupported(
    "Legacy Chromium DPAPI cookies are not decryptable on this platform",
  ))
}
