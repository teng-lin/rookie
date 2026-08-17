pub static PAYLOAD_AMD64: &[u8] = include_bytes!("native/abe_extractor_amd64.bin");

/// Returns the embedded reflective injection payload for the current architecture if supported.
pub fn get_payload() -> Option<&'static [u8]> {
  #[cfg(target_arch = "x86_64")]
  {
    Some(PAYLOAD_AMD64)
  }
  #[cfg(not(target_arch = "x86_64"))]
  {
    None
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn payload_is_non_empty() {
    assert!(!PAYLOAD_AMD64.is_empty());
    assert_eq!(&PAYLOAD_AMD64[..2], b"MZ");
  }
}
