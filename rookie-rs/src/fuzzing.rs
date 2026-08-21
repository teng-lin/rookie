//! Internal entry points for the repository's libFuzzer targets.
//!
//! This module exists only with the non-default `fuzzing` feature. Its API is
//! not part of the supported crate contract.

/// Runs the portable Chromium, Safari, and ESE-record decoders over one byte
/// sequence. Parse rejection is expected; an unwind is a fuzz finding.
pub fn portable_decoders(bytes: &[u8]) {
  crate::browser::chromium_decoder::malformed_decoder_gate_case(bytes)
    .expect("the in-memory Chromium fuzz fixture is valid");
  crate::browser::safari::malformed_decoder_gate_case(bytes)
    .expect("the Safari fuzz adapter has no fallible setup");
  crate::browser::internet_explorer_model::malformed_decoder_gate_case(bytes)
    .expect("the ESE record fuzz adapter has no fallible setup");
}

/// Runs the legacy JSON and bounded mozLz4 session decoders over one byte
/// sequence. Parse rejection is expected; an unwind is a fuzz finding.
pub fn mozilla_session(bytes: &[u8]) {
  crate::browser::mozilla_session::malformed_decoder_gate_case(bytes)
    .expect("the Mozilla session fuzz adapter has no fallible setup");
}

/// Exercises the target-independent file-signature classifier.
pub fn source_classifier(bytes: &[u8]) {
  let _ = crate::direct_path::shared::classify_header(bytes);
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn adapters_accept_empty_and_malformed_inputs() {
    portable_decoders(b"");
    portable_decoders(b"not a browser store");
    mozilla_session(b"");
    mozilla_session(b"mozLz40\0\0\0\0not lz4");
    source_classifier(b"");
    source_classifier(b"SQLite format 3\0");
  }
}
