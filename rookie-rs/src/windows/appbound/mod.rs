/*
Chrome v20 App-Bound Encryption Key Retrieval:
- Reflective COM injection into spawned browser process (unprivileged, Chrome 127+)
- In-process DPAPI/CNG SYSTEM impersonation fallback (elevated, Chrome 127-133+)
*/
use anyhow::{anyhow, bail, Result};
use base64::{prelude::BASE64_STANDARD, Engine};

use aes_gcm::{
  aead::{generic_array::GenericArray, Aead, KeyInit},
  Aes256Gcm,
};
use chacha20poly1305::ChaCha20Poly1305;
use zeroize::Zeroizing;

use crate::common::secret::SecretBytes;

pub mod browser_path;
pub mod constants;
mod impersonate;
pub mod injector;
pub mod payload;
pub mod pe;

// Keys extracted from Chrome's elevation_service.exe, used to unwrap the
// app-bound v20 master key. See the reference implementation linked above.
const AES256_ELEVATION_KEY: &[u8; 32] =
  b"\xB3\x1C\x6E\x24\x1A\xC8\x46\x72\x8D\xA9\xC1\xFA\xC4\x93\x66\x51\xCF\xFB\x94\x4D\x14\x3A\xB8\x16\x27\x6B\xCC\x6D\xA0\x28\x47\x87";
const CHACHA20_ELEVATION_KEY: &[u8; 32] =
  b"\xE9\x8F\x37\xD7\xF4\xE1\xFA\x43\x3D\x19\x30\x4D\xC2\x25\x80\x42\x09\x0E\x2D\x1D\x7E\xEA\x76\x70\xD4\x1F\x73\x8D\x08\x72\x96\x60";
const FLAG3_XOR_KEY: &[u8; 32] =
  b"\xCC\xF8\xA1\xCE\xC5\x66\x05\xB8\x51\x75\x52\xBA\x1A\x2D\x06\x1C\x03\xA2\x9E\x90\x27\x4F\xB2\xFC\xF5\x9B\xA4\xB7\x5C\x39\x23\x90";

// These unwrap layers of DPAPI/CNG encryption around the app-bound master
// key. The results are wrapped in `SecretBytes` because they hold decrypted
// key material that should be wiped from memory as soon as it is consumed,
// rather than left in freed heap memory.
fn decrypt_dpapi(key: &[u8], as_system: bool) -> Result<SecretBytes> {
  let _impersonation = as_system.then(impersonate::start_impersonate).transpose()?;
  crate::windows::dpapi::decrypt(key)
}

fn decrypt_ncrypt(key: &[u8], as_system: bool) -> Result<SecretBytes> {
  let _impersonation = as_system.then(impersonate::start_impersonate).transpose()?;
  crate::windows::ncrypt::decrypt(key)
}

/// AEAD-decrypt `[iv(12) | ciphertext | tag(16)]` with `key`.
///
/// Returns `None` if the key length is wrong for the cipher, the blob is too
/// short to hold a nonce, or authentication fails.
fn aead_decrypt<C>(key: &[u8], iv_and_ciphertext: &[u8]) -> Option<Zeroizing<Vec<u8>>>
where
  C: KeyInit + Aead,
{
  let iv = iv_and_ciphertext.get(..12)?;
  let ciphertext = iv_and_ciphertext.get(12..)?;
  let cipher = C::new_from_slice(key).ok()?;
  cipher
    .decrypt(GenericArray::from_slice(iv), ciphertext)
    .map(Zeroizing::new)
    .ok()
}

fn read_u32_le(blob: &[u8], offset: usize) -> Result<u32> {
  let end = offset
    .checked_add(4)
    .ok_or_else(|| anyhow!("app-bound key blob offset overflow"))?;
  let bytes = blob
    .get(offset..end)
    .ok_or_else(|| anyhow!("app-bound key blob truncated at offset {offset}"))?;
  Ok(u32::from_le_bytes(
    bytes.try_into().expect("slice length is 4"),
  ))
}

/// Extract the key-blob content `[flag | payload...]` from a DPAPI-decrypted
/// app-bound key blob.
///
/// Framing (little-endian): `[header_len: u32][header][content_len: u32][content]`,
/// where the content begins with the scheme flag byte and sits at the tail of
/// the blob, i.e. `8 + header_len + content_len == blob.len()`.
fn parse_key_blob_content(blob: &[u8]) -> Result<&[u8]> {
  let header_len = read_u32_le(blob, 0)? as usize;
  let content_len_offset = header_len
    .checked_add(4)
    .ok_or_else(|| anyhow!("app-bound header length overflow"))?;
  let content_len = read_u32_le(blob, content_len_offset)? as usize;
  let content_start = content_len_offset
    .checked_add(4)
    .ok_or_else(|| anyhow!("app-bound content offset overflow"))?;
  let expected_len = content_start
    .checked_add(content_len)
    .ok_or_else(|| anyhow!("app-bound content length overflow"))?;
  if expected_len != blob.len() {
    bail!(
      "app-bound key blob framing mismatch (header_len={header_len}, content_len={content_len}, blob_len={})",
      blob.len()
    );
  }
  let content = &blob[content_start..];
  if content.is_empty() {
    bail!("app-bound key blob has empty content");
  }
  Ok(content)
}

/// Derive a candidate v20 master key from parsed key-blob content, whose first
/// byte selects the wrapping scheme (see the reference implementation).
///
/// `Ok(None)` means no key was produced — empty content, an unrecognized flag,
/// or the scheme's cipher rejected the payload. `Err` means a known scheme could
/// not be attempted at all (e.g. a flag-3 payload too short to hold the wrapped
/// key, or a CNG failure).
fn derive_v20_master_key(content: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
  let Some((&flag, payload)) = content.split_first() else {
    return Ok(None);
  };
  match flag {
    // [iv(12) | ciphertext(32) | tag(16)], AES-256-GCM
    1 => Ok(aead_decrypt::<Aes256Gcm>(AES256_ELEVATION_KEY, payload)),
    // [iv(12) | ciphertext(32) | tag(16)], ChaCha20-Poly1305 (Chrome 133+)
    2 => Ok(aead_decrypt::<ChaCha20Poly1305>(
      CHACHA20_ELEVATION_KEY,
      payload,
    )),
    // [encrypted_aes_key(32) | iv(12) | ciphertext(32) | tag(16)]; the AES key
    // is unwrapped via CNG then XORed with a hardcoded key (Chrome 133+).
    3 => {
      let encrypted_aes_key = payload
        .get(..32)
        .ok_or_else(|| anyhow!("flag 3 payload too short for encrypted AES key"))?;
      let iv_and_ciphertext = &payload[32..];
      let decrypted_aes_key = decrypt_ncrypt(encrypted_aes_key, true)?;
      // XOR the CNG-unwrapped key with the hardcoded key; zipping yields a
      // 32-byte key when CNG returns the expected 32 bytes (as the reference does).
      let aes_key: Zeroizing<Vec<u8>> = Zeroizing::new(
        decrypted_aes_key
          .iter()
          .zip(FLAG3_XOR_KEY)
          .map(|(a, b)| a ^ b)
          .collect(),
      );
      Ok(aead_decrypt::<Aes256Gcm>(&aes_key, iv_and_ciphertext))
    }
    other => {
      log::warn!("Unsupported app-bound key flag: {other}");
      Ok(None)
    }
  }
}

/// Legacy fallback for blobs that lack the modern framing header: treat the
/// trailing 61 bytes as a flag-1 style `[flag | iv(12) | ciphertext(32) | tag(16)]`
/// record and AES-256-GCM decrypt the `iv | ciphertext | tag` portion.
fn derive_legacy_tail_key(user_decrypted: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
  let start = user_decrypted.len().checked_sub(61)?;
  let iv_and_ciphertext = &user_decrypted[start + 1..]; // skip the flag byte
  aead_decrypt::<Aes256Gcm>(AES256_ELEVATION_KEY, iv_and_ciphertext)
}

/// Retrieves the Chrome v20 App-Bound master key using reflective COM injection into a spawned browser process.
pub fn retrieve_via_injection(
  key64: &str,
  browser_hint: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
  let payload_bytes = payload::get_payload()
    .ok_or_else(|| anyhow!("App-Bound injection payload not available for this architecture"))?;
  let exe_path = browser_path::find_browser_executable(browser_hint)?;
  injector::inject_and_extract_key(&exe_path, payload_bytes, key64)
}

/// Unwraps the App-Bound master key using in-process DPAPI/CNG with elevated SYSTEM impersonation.
fn get_keys_elevated_fallback(key64: &str) -> Result<Vec<Zeroizing<Vec<u8>>>> {
  let mut keys: Vec<Zeroizing<Vec<u8>>> = Vec::new();

  let key_u8 = BASE64_STANDARD.decode(key64)?;
  if !key_u8.starts_with(b"APPB") {
    bail!("key does not start with APPB");
  }
  let system_decrypted = decrypt_dpapi(&key_u8[4..], true)?;
  let user_decrypted = decrypt_dpapi(&system_decrypted, false)?;

  // Candidate 1: trailing 32 bytes
  if user_decrypted.len() >= 32 {
    keys.push(Zeroizing::new(
      user_decrypted[user_decrypted.len() - 32..].to_vec(),
    ));
  }

  // Candidate 2: derive the wrapped v20 master key
  match parse_key_blob_content(&user_decrypted) {
    Ok(content) => match derive_v20_master_key(content) {
      Ok(Some(master_key)) => keys.push(master_key),
      Ok(None) => log::warn!("app-bound v20 master key derivation yielded no key"),
      Err(err) => bail!("Failed to derive app-bound v20 master key: {err}"),
    },
    Err(err) => {
      log::warn!("Failed to parse app-bound key blob framing: {err}");
      if let Some(master_key) = derive_legacy_tail_key(&user_decrypted) {
        keys.push(master_key);
      }
    }
  }

  Ok(keys)
}

/// Retrieves candidate v20 master keys, attempting non-elevated COM injection first,
/// with fallback to elevated DPAPI impersonation if available.
pub fn get_keys_with_hint(
  key64: &str,
  browser_hint: Option<&str>,
) -> Result<Vec<Zeroizing<Vec<u8>>>> {
  let mut errors: Vec<String> = Vec::new();

  // Primary: COM RPC injection into spawned browser (unprivileged)
  match retrieve_via_injection(key64, browser_hint) {
    Ok(key) => return Ok(vec![key]),
    Err(e) => {
      log::debug!("App-Bound COM reflective injection failed: {e}");
      errors.push(format!("COM injection: {e}"));
    }
  }

  // Fallback: In-process elevated SYSTEM impersonation
  match get_keys_elevated_fallback(key64) {
    Ok(keys) if !keys.is_empty() => return Ok(keys),
    Ok(_) => {}
    Err(e) => {
      log::debug!("App-Bound elevated DPAPI fallback failed: {e}");
      errors.push(format!("Elevated fallback: {e}"));
    }
  }

  bail!(
    "Failed to retrieve Chrome v20 App-Bound master key ({})",
    errors.join("; ")
  )
}

pub fn get_keys(key64: &str) -> Result<Vec<Zeroizing<Vec<u8>>>> {
  get_keys_with_hint(key64, None)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn frame(header: &[u8], content: &[u8]) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(&(header.len() as u32).to_le_bytes());
    blob.extend_from_slice(header);
    blob.extend_from_slice(&(content.len() as u32).to_le_bytes());
    blob.extend_from_slice(content);
    blob
  }

  #[test]
  fn parses_flag1_sized_content() {
    let content = [1u8; 61];
    let blob = frame(b"header", &content);
    let parsed = parse_key_blob_content(&blob).expect("parse");
    assert_eq!(parsed, &content);
    assert_eq!(parsed[0], 1);
  }

  #[test]
  fn parses_flag3_sized_content() {
    // The bug this guards against: flag 3 content is 93 bytes, so a trailing
    // fixed-61 slice would read the flag byte from the middle of the blob.
    let mut content = vec![3u8; 93];
    content[0] = 3;
    let blob = frame(&[0u8; 16], &content);
    let parsed = parse_key_blob_content(&blob).expect("parse");
    assert_eq!(parsed.len(), 93);
    assert_eq!(parsed[0], 3);
  }

  #[test]
  fn rejects_framing_length_mismatch() {
    let mut blob = frame(b"header", &[1u8; 61]);
    blob.push(0); // trailing byte violates the length invariant
    assert!(parse_key_blob_content(&blob).is_err());
  }

  #[test]
  fn rejects_truncated_blob() {
    assert!(parse_key_blob_content(&[]).is_err());
    assert!(parse_key_blob_content(&[0u8; 3]).is_err());
    assert!(parse_key_blob_content(&[0u8; 7]).is_err());
  }

  #[test]
  fn rejects_empty_content() {
    let blob = frame(b"header", &[]);
    assert!(parse_key_blob_content(&blob).is_err());
  }

  #[test]
  fn parses_zero_length_header() {
    let blob = frame(b"", &[1u8; 61]);
    let parsed = parse_key_blob_content(&blob).expect("parse");
    assert_eq!(parsed.len(), 61);
  }

  #[test]
  fn rejects_content_len_exceeding_blob() {
    let mut blob = Vec::new();
    blob.extend_from_slice(&0u32.to_le_bytes()); // header_len = 0
    blob.extend_from_slice(&100u32.to_le_bytes()); // content_len = 100
    blob.extend_from_slice(&[0u8; 10]); // only 10 content bytes actually present
    assert!(parse_key_blob_content(&blob).is_err());
  }

  #[test]
  fn flag3_short_payload_errors() {
    // Flag byte + 19-byte payload: the get(..32) guard rejects it before any CNG
    // call, so this must be Err (not None, not a panic).
    assert!(derive_v20_master_key(&[3u8; 20]).is_err());
  }

  #[test]
  fn short_payload_for_known_flag_yields_none() {
    // Payload shorter than the 12-byte nonce: aead_decrypt bails to None.
    assert!(derive_v20_master_key(&[1u8, 0, 0, 0, 0])
      .expect("no error")
      .is_none());
  }

  #[test]
  fn unknown_flag_yields_no_key() {
    assert!(derive_v20_master_key(&[9u8; 61])
      .expect("no error")
      .is_none());
    assert!(derive_v20_master_key(&[]).expect("no error").is_none());
  }

  // Encrypt a known master key with the corresponding elevation key, then check
  // that derivation recovers it. Covers the flag 1 (AES-GCM) and flag 2
  // (ChaCha20-Poly1305) schemes end to end. Flag 3 additionally needs a live CNG
  // key, so it is exercised by manual/integration testing rather than here.
  fn seal<C: KeyInit + Aead>(key: &[u8], iv: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let cipher = C::new_from_slice(key).expect("key length");
    cipher
      .encrypt(GenericArray::from_slice(iv), plaintext)
      .expect("encrypt")
  }

  fn content_for(flag: u8, iv: &[u8; 12], ciphertext_and_tag: &[u8]) -> Vec<u8> {
    let mut content = vec![flag];
    content.extend_from_slice(iv);
    content.extend_from_slice(ciphertext_and_tag);
    content
  }

  #[test]
  fn flag1_roundtrip_recovers_master_key() {
    let master = [0x42u8; 32];
    let iv = [7u8; 12];
    let sealed = seal::<Aes256Gcm>(AES256_ELEVATION_KEY, &iv, &master);
    let content = content_for(1, &iv, &sealed);
    assert_eq!(
      derive_v20_master_key(&content)
        .expect("no error")
        .expect("key")
        .as_slice(),
      master.as_slice()
    );
  }

  #[test]
  fn flag2_roundtrip_recovers_master_key() {
    let master = [0x37u8; 32];
    let iv = [9u8; 12];
    let sealed = seal::<ChaCha20Poly1305>(CHACHA20_ELEVATION_KEY, &iv, &master);
    let content = content_for(2, &iv, &sealed);
    assert_eq!(
      derive_v20_master_key(&content)
        .expect("no error")
        .expect("key")
        .as_slice(),
      master.as_slice()
    );
  }

  #[test]
  fn corrupt_ciphertext_yields_no_key() {
    let content = content_for(1, &[0u8; 12], &[0u8; 48]);
    assert!(derive_v20_master_key(&content).expect("no error").is_none());
  }

  #[test]
  fn legacy_tail_recovers_master_key() {
    let master = [0x11u8; 32];
    let iv = [5u8; 12];
    let sealed = seal::<Aes256Gcm>(AES256_ELEVATION_KEY, &iv, &master);
    // Trailing 61-byte [flag | iv | ct | tag] record behind an arbitrary prefix.
    let mut blob = vec![0xAAu8; 20];
    blob.push(1); // flag byte, skipped by the fallback
    blob.extend_from_slice(&iv);
    blob.extend_from_slice(&sealed);
    assert_eq!(
      derive_legacy_tail_key(&blob).expect("key").as_slice(),
      master.as_slice()
    );
  }

  #[test]
  fn legacy_tail_too_short_yields_none() {
    assert!(derive_legacy_tail_key(&[0u8; 60]).is_none());
  }
}
