use crate::common::{date, enums::*, sqlite};
use anyhow::{bail, Result};
use std::path::PathBuf;

#[allow(unused)]
use crate::config::Browser;

#[cfg(target_os = "windows")]
use crate::windows;

#[cfg(any(unix, windows, test))]
use anyhow::Context;

#[cfg(target_os = "macos")]
use crate::macos;

#[cfg(target_os = "windows")]
use aes_gcm::{
  aead::{generic_array::GenericArray, Aead, KeyInit},
  Aes256Gcm,
};
#[cfg(target_os = "windows")]
use base64::{engine::general_purpose, Engine as _};

/// Returns cookies from chromium based browser
#[cfg(target_os = "windows")]
pub fn chromium_based(
  key: PathBuf,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<Cookie>> {
  let content = std::fs::read_to_string(key)?;
  let key_dict: serde_json::Value =
    serde_json::from_str(content.as_str()).context("Can't read json file")?;

  let legacy_key = key_dict["os_crypt"]["encrypted_key"]
    .as_str()
    .unwrap_or_default();

  #[allow(unused)]
  let appbound_key = key_dict["os_crypt"]["app_bound_encrypted_key"]
    .as_str()
    .unwrap_or_default();

  #[cfg(feature = "appbound")]
  {
    let keys = if !appbound_key.is_empty() {
      if !privilege::user::privileged() {
        bail!("Chrome cookies from version v130 can be decrypted only when running as admin due to appbound encryption!")
      }
      crate::windows::appbound::get_keys(appbound_key)?
    } else {
      get_keys(legacy_key)?
    };
    query_cookies(keys, db_path, domains, force_kill)
  }

  #[cfg(not(feature = "appbound"))]
  {
    let keys = get_keys(legacy_key)?;
    query_cookies(keys, db_path, domains, force_kill)
  }
}

/// Returns cookies from chromium based browser
#[cfg(unix)]
pub fn chromium_based(
  config: &Browser,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<Cookie>> {
  // Simple AES

  let keys = get_keys(config)?;
  query_cookies(keys, db_path, domains, force_kill)
}

#[cfg(unix)]
fn create_pbkdf2_key(password: &str, salt: &[u8; 9], iterations: u32) -> Vec<u8> {
  use pbkdf2::pbkdf2_hmac;
  use sha1::Sha1;
  let mut output = [0u8; 16];
  pbkdf2_hmac::<Sha1>(password.as_bytes(), salt, iterations, &mut output);
  output.to_vec()
}

#[cfg(target_os = "windows")]
fn get_keys(key64: &str) -> Result<Vec<Vec<u8>>> {
  let keydpapi: Vec<u8> = general_purpose::STANDARD
    .decode(key64)
    .context("Failed to decode Local State os_crypt.encrypted_key as base64")?;
  let decoded_len = keydpapi.len();
  if decoded_len <= 5 {
    bail!(
      "Local State os_crypt.encrypted_key decoded to {} bytes, expected DPAPI prefix plus payload",
      decoded_len
    );
  }
  if &keydpapi[..5] != b"DPAPI" {
    bail!("Local State os_crypt.encrypted_key is missing DPAPI prefix");
  }

  let wrapped_len = decoded_len - 5;
  let v10_key = crate::windows::dpapi::decrypt(&keydpapi[5..]).with_context(|| {
    format!(
      "Failed to unwrap DPAPI encrypted key (decoded_length={}, wrapped_length={})",
      decoded_len, wrapped_len
    )
  })?;
  if v10_key.len() != 32 {
    bail!(
      "DPAPI unwrapped key length was {}, expected 32 (decoded_length={}, wrapped_length={})",
      v10_key.len(),
      decoded_len,
      wrapped_len
    );
  }

  let keys: Vec<Vec<u8>> = vec![v10_key];
  Ok(keys)
}

#[cfg(target_os = "linux")]
fn get_keys(config: &Browser) -> Result<Vec<Vec<u8>>> {
  // AES CBC key

  let salt = b"saltysalt";

  let iterations = 1;

  let mut keys: Vec<Vec<u8>> = vec![];
  if let Ok(passwords) =
    crate::linux::get_passwords(&config.unix_crypt_name.clone().unwrap_or("".to_owned()))
  {
    for password in passwords {
      let key = create_pbkdf2_key(password.as_str(), salt, iterations);
      keys.push(key);
    }
  }
  // default keys
  let key = create_pbkdf2_key("peanuts", salt, iterations);
  keys.push(key);
  let key = create_pbkdf2_key("", salt, iterations);
  keys.push(key);

  Ok(keys)
}

#[cfg(target_os = "macos")]
fn get_keys(config: &Browser) -> Result<Vec<Vec<u8>>> {
  let salt = b"saltysalt";
  let iterations = 1003;
  let mut passwords: Vec<String> = vec![];

  let mut push_password = |password: String| {
    if !passwords.iter().any(|existing| existing == &password) {
      passwords.push(password);
    }
  };

  if let (Some(key_service), Some(key_user)) = (&config.osx_key_service, &config.osx_key_user) {
    match macos::get_osx_keychain_password(key_service, key_user) {
      Ok(password) => push_password(password),
      Err(err) => log::debug!("Failed to retrieve password from OSX Keychain: {}", err),
    }
  }

  for password in ["mock_password", "peanuts", ""] {
    push_password(password.to_string());
  }

  Ok(
    passwords
      .iter()
      .map(|password| create_pbkdf2_key(password.as_str(), salt, iterations))
      .collect(),
  )
}

#[cfg(any(unix, windows, test))]
fn decode_after_host_hash_prefix(plaintext: Vec<u8>) -> Result<String> {
  if plaintext.len() <= 32 {
    bail!("Can't decode encrypted value");
  }

  String::from_utf8(plaintext[32..].to_vec()).context("Can't decode encrypted value")
}

#[cfg(any(unix, windows, test))]
fn decode_chromium_plaintext(key_type: &[u8], plaintext: Vec<u8>) -> Result<String> {
  if key_type == b"v20" {
    return decode_after_host_hash_prefix(plaintext);
  }

  match String::from_utf8(plaintext) {
    Ok(text) => Ok(text),
    Err(err) => decode_after_host_hash_prefix(err.into_bytes()),
  }
}

/// Decrypt cookie value using aes GCM
#[cfg(windows)]
fn decrypt_encrypted_value(
  value: String,
  encrypted_value: &[u8],
  keys: &[Vec<u8>],
) -> Result<String> {
  if encrypted_value.len() < 15 {
    return Ok(value);
  }
  let Some(key_type) = encrypted_value.get(..3) else {
    return Ok(value);
  };
  if !value.is_empty() || !(key_type == b"v11" || key_type == b"v10" || key_type == b"v20") {
    // unknown key_type or value isn't encrypted
    log::warn!("Unknown key type: {:?}", key_type);
    return Ok(value);
  }
  log::debug!("key type: {:?}", key_type);

  let nonce = &encrypted_value[3..15]; // iv
  let ciphertext = &encrypted_value[15..];

  // Create a new AES block cipher.
  for key in keys {
    // new_from_slice rejects wrong-length keys instead of panicking like
    // Key::from_slice, so a malformed candidate key just gets skipped.
    let cipher = match Aes256Gcm::new_from_slice(key) {
      Ok(cipher) => cipher,
      Err(_) => {
        log::warn!("Skipping candidate key with invalid length {}", key.len());
        continue;
      }
    };
    let nonce = GenericArray::from_slice(nonce); // 96-bits; unique per message

    match cipher.decrypt(nonce, ciphertext.as_ref()) {
      Ok(plaintext) => match decode_chromium_plaintext(key_type, plaintext) {
        Ok(text) => return Ok(text),
        Err(e) => log::warn!("Failed to decode plaintext: {}", e),
      },
      Err(e) => {
        // We'll get error anyway if decryption failed
        log::debug!("Failed to decrypt with a key: {}", e);
        continue;
      }
    }
  }
  bail!("decrypt_encrypted_value failed")
}

/// Decrypt cookie value using aes cbc
#[cfg(unix)]
fn decrypt_encrypted_value(
  value: String,
  encrypted_value: &[u8],
  keys: &[Vec<u8>],
) -> Result<String> {
  // cbc
  if !value.is_empty() {
    // unknown key_type or value isn't encrypted
    return Ok(value);
  }
  if encrypted_value.is_empty() {
    return Ok("".into());
  }
  let Some(key_type) = encrypted_value.get(..3) else {
    return Ok(value);
  };

  if !(key_type == b"v11" || key_type == b"v10" || key_type == b"v20") {
    return Ok(value);
  }
  log::debug!("key type: {:?}", key_type);

  use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};

  type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

  // Create an AES-128 cipher with the provided key.

  let encrypted_value = &mut encrypted_value.to_owned()[3..];
  let iv: [u8; 16] = [b' '; 16];

  for key in keys {
    let mut key_array: [u8; 16] = [0; 16];
    key_array.copy_from_slice(&key[..16]);
    let cipher = Aes128CbcDec::new(&key_array.into(), &iv.into());
    let mut cloned_encrypted_value: Vec<u8> = encrypted_value.to_vec();

    if let Ok(plaintext) = cipher.decrypt_padded_mut::<Pkcs7>(&mut cloned_encrypted_value) {
      match decode_chromium_plaintext(key_type, plaintext.to_vec()) {
        Ok(decoded) => return Ok(decoded),
        Err(err) => {
          // A wrong key can occasionally pass PKCS#7 validation. Do not accept
          // its bytes as a cookie value; another key may decrypt valid UTF-8.
          log::debug!("Failed to decode decrypted value as UTF-8: {err}");
        }
      }
    }
  }
  bail!("decrypt_encrypted_value failed")
}

#[cfg(target_os = "windows")]
fn unlock_file(
  mut path: PathBuf,
  force_kill: bool,
) -> Result<(PathBuf, Option<windows::shadow_copy::TempDir>)> {
  // Shadow copy cookies file so we can read session cookies
  // Admin rights required
  if privilege::user::privileged() {
    log::debug!("Admin rights detected");
    if let Ok(temp_dir) = windows::shadow_copy::TempDir::new() {
      let result = windows::shadow_copy::shadow_copy(path.clone(), temp_dir.path().to_path_buf());
      log::debug!("shadow copy result: {:?}", result);
      if result.is_ok() {
        path = temp_dir.path().join(path.file_name().unwrap());
        return Ok((path, Some(temp_dir)));
      }
    }
  }

  // Elegantly restart the process which lock the cookies file (And unlock it) using restart manager API
  log::warn!("Unlocking Chrome database... This may take a while (sometimes up to a minute)");
  unsafe {
    crate::windows::restart_manager::release_file_lock(&path.to_string_lossy(), force_kill);
  }
  Ok((path, None))
}

#[allow(unused_variables)]
pub(crate) fn query_cookies(
  keys: Vec<Vec<u8>>,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<Cookie>> {
  // In windows unlock file locking
  #[cfg(target_os = "windows")]
  let (db_path, _temp_dir) = unlock_file(db_path, force_kill)?;

  log::info!(
    "Creating SQLite connection to {}",
    db_path.to_str().unwrap_or("")
  );
  let connection = sqlite::connect(db_path)?;
  let mut query =
    "SELECT host_key, path, is_secure, expires_utc, name, value, CAST(encrypted_value AS BLOB), is_httponly, samesite FROM cookies ".to_string();
  let domain_filters: Vec<String> = domains
    .as_ref()
    .map(|domains| domains.iter().map(|domain| format!("%{domain}%")).collect())
    .unwrap_or_default();

  if !domain_filters.is_empty() {
    let predicates = (1..=domain_filters.len())
      .map(|index| format!("host_key LIKE ?{index}"))
      .collect::<Vec<_>>()
      .join(" OR ");
    query += &format!("WHERE ({predicates})");
  }
  query += ";";

  let mut cookies: Vec<Cookie> = vec![];
  let mut last_decrypt_error: Option<anyhow::Error> = None;
  let mut stmt = connection.prepare(query.as_str())?;
  let mut rows = stmt.query(rusqlite::params_from_iter(domain_filters.iter()))?;

  while let Some(row) = rows.next()? {
    let host_key: String = match row.get(0) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to read host_key from row: {err}");
        continue;
      }
    };
    let path: String = match row.get(1) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to read path from row: {err}");
        continue;
      }
    };
    let is_secure: bool = match row.get(2) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to read is_secure from row: {err}");
        continue;
      }
    };
    let expires: u64 = match row.get(3) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to read expires_utc from row: {err}");
        continue;
      }
    };
    let expires = date::chromium_timestamp(expires);
    let name: String = match row.get(4) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to read name from row: {err}");
        continue;
      }
    };

    let value: String = match row.get(5) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to read value from row: {err}");
        continue;
      }
    };
    let encrypted_value: Vec<u8> = match row.get(6) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to read encrypted_value from row: {err}");
        continue;
      }
    };
    if encrypted_value.is_empty() && value.is_empty() {
      continue;
    }
    let decrypted_value = match decrypt_encrypted_value(value, &encrypted_value, &keys) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to decrypt cookie value: {err}");
        last_decrypt_error = Some(err);
        continue;
      }
    };
    let http_only: bool = match row.get(7) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to read is_httponly from row: {err}");
        continue;
      }
    };

    let same_site: i64 = match row.get(8) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to read samesite from row: {err}");
        continue;
      }
    };
    let cookie = Cookie {
      domain: host_key.to_string(),
      path: path.to_string(),
      secure: is_secure,
      expires,
      name: name.to_string(),
      value: decrypted_value,
      http_only,
      same_site,
    };
    cookies.push(cookie);
  }
  if cookies.is_empty() {
    if let Some(err) = last_decrypt_error {
      return Err(err);
    }
  }
  Ok(cookies)
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::path::Path;
  use std::sync::atomic::{AtomicU64, Ordering};

  // Per-process unique temp paths without pulling in the `tempfile` dep.
  fn unique_tmpdir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir =
      std::env::temp_dir().join(format!("rookie-test-{}-{}-{}", tag, std::process::id(), n));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
  }

  // (host_key, path, is_secure, expires_utc, name, value, encrypted_value, is_httponly, samesite)
  type ChromiumRow<'a> = (
    &'a str,
    &'a str,
    bool,
    u64,
    &'a str,
    &'a str,
    &'a [u8],
    bool,
    i64,
  );

  // Minimal `cookies` table mirroring the columns chromium_based reads.
  // Real Chrome schema has many more columns, but query_cookies only
  // selects these nine.
  fn seed_chromium_cookies(db: &Path, rows: &[ChromiumRow<'_>]) {
    let conn = rusqlite::Connection::open(db).expect("open writable sqlite");
    conn
      .execute(
        "CREATE TABLE cookies (
          host_key TEXT NOT NULL,
          path TEXT NOT NULL,
          is_secure INTEGER NOT NULL,
          expires_utc INTEGER NOT NULL,
          name TEXT NOT NULL,
          value TEXT NOT NULL,
          encrypted_value BLOB,
          is_httponly INTEGER NOT NULL,
          samesite INTEGER NOT NULL
        )",
        [],
      )
      .expect("create table");
    for r in rows {
      conn
        .execute(
          "INSERT INTO cookies (host_key, path, is_secure, expires_utc, name, value, \
            encrypted_value, is_httponly, samesite) \
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
          rusqlite::params![r.0, r.1, r.2, r.3, r.4, r.5, r.6, r.7, r.8],
        )
        .expect("insert row");
    }
  }

  #[test]
  fn query_cookies_missing_db_errors() {
    let result = query_cookies(
      vec![],
      PathBuf::from("/nonexistent/cookies.db"),
      None,
      false,
    );
    assert!(
      result.is_err(),
      "expected Err for missing db, got {:?}",
      result
    );
  }

  #[test]
  fn query_cookies_non_sqlite_file_errors() {
    let dir = unique_tmpdir("chr-bad-sqlite");
    let db = dir.join("Cookies");
    std::fs::write(&db, b"not a sqlite database at all").unwrap();
    let result = query_cookies(vec![], db, None, false);
    assert!(
      result.is_err(),
      "expected Err for bogus sqlite, got {:?}",
      result
    );
  }

  #[test]
  fn query_cookies_empty_table_returns_empty() {
    let dir = unique_tmpdir("chr-empty-table");
    let db = dir.join("Cookies");
    seed_chromium_cookies(&db, &[]);
    let cookies = query_cookies(vec![], db, None, false).expect("decode");
    assert!(cookies.is_empty(), "{:?}", cookies);
  }

  #[test]
  fn query_cookies_returns_plaintext_value_when_value_is_set() {
    let dir = unique_tmpdir("chr-plaintext");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[(
        ".example.com",
        "/",
        true,
        // chromium_timestamp wants microseconds since 1601-01-01.
        // 11_644_473_600_000_000 us == Unix epoch.
        11_644_473_600_000_000 + 1_700_000_000 * 1_000_000,
        "id",
        "plain",
        b"",
        true,
        1,
      )],
    );
    let cookies = query_cookies(vec![], db, None, false).expect("decode");
    assert_eq!(cookies.len(), 1, "{:?}", cookies);
    let c = &cookies[0];
    assert_eq!(c.domain, ".example.com");
    assert_eq!(c.name, "id");
    assert_eq!(c.value, "plain");
    assert!(c.http_only);
    assert!(c.secure);
    assert_eq!(c.same_site, 1);
    assert_eq!(c.expires, Some(1_700_000_000));
  }

  #[cfg(unix)]
  #[test]
  fn chromium_mock_keychain_known_answer() {
    let salt = b"saltysalt";
    let key = create_pbkdf2_key("mock_password", salt, 1003);
    assert_eq!(
      key,
      vec![
        0xaf, 0x0f, 0x76, 0x2a, 0xaf, 0x6d, 0x7d, 0x11, 0x58, 0x1b, 0x7a, 0xa8, 0xce, 0x72, 0x18,
        0xde,
      ]
    );

    let ciphertext = [
      0x76, 0x31, 0x30, 0xbf, 0x08, 0x6d, 0x20, 0x56, 0x86, 0x1a, 0x80, 0xde, 0x82, 0x5f, 0xc9,
      0x35, 0x86, 0x86, 0x30, 0x64, 0x4f, 0x2c, 0xa1, 0x87, 0x45, 0x02, 0x13, 0xae, 0x66, 0x81,
      0xb4, 0xd6, 0x43, 0xd1, 0x9b, 0x25, 0x81, 0xc8, 0x5c, 0x88, 0x78, 0xc1, 0xbc, 0x97, 0xe7,
      0x26, 0xa1, 0x0e, 0x51, 0xea, 0x77,
    ];
    let plaintext = [
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
      0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
      0x1e, 0x1f,
    ];

    let decrypted =
      decrypt_encrypted_value("".to_string(), &ciphertext, &[key]).expect("decrypt vector");
    assert_eq!(decrypted.as_bytes(), plaintext);
  }

  #[test]
  fn decode_chromium_plaintext_handles_plain_and_hash_prefixed_values() {
    let plain = decode_chromium_plaintext(b"v10", b"bar".to_vec()).expect("plain v10");
    assert_eq!(plain, "bar");

    let mut hash_prefixed = vec![0xff; 32];
    hash_prefixed.extend_from_slice(b"bar");
    let prefixed = decode_chromium_plaintext(b"v10", hash_prefixed).expect("hash-prefixed v10");
    assert_eq!(prefixed, "bar");

    let mut v20 = vec![0; 32];
    v20.extend_from_slice(b"bar");
    let v20 = decode_chromium_plaintext(b"v20", v20).expect("v20");
    assert_eq!(v20, "bar");
  }

  #[cfg(unix)]
  #[test]
  fn query_cookies_filters_by_domain() {
    let dir = unique_tmpdir("chr-domain-filter");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[
        (".example.com", "/", false, 0, "keep", "yes", b"x", false, 0),
        ("other.test", "/", false, 0, "drop", "no", b"x", false, 0),
      ],
    );
    let mut cookies = query_cookies(
      vec![],
      db,
      Some(vec!["example.com".to_string(), "other.test".to_string()]),
      false,
    )
    .expect("decode");
    cookies.sort_by(|a, b| a.name.cmp(&b.name));
    let names: Vec<_> = cookies.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["drop", "keep"], "{:?}", cookies);
  }

  #[cfg(unix)]
  #[test]
  fn query_cookies_domain_filter_treats_sql_as_data() {
    let dir = unique_tmpdir("chr-domain-filter-sql");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[
        (
          ".example.com",
          "/",
          false,
          0,
          "first",
          "yes",
          b"x",
          false,
          0,
        ),
        ("other.test", "/", false, 0, "second", "no", b"x", false, 0),
      ],
    );

    let cookies =
      query_cookies(vec![], db, Some(vec!["' OR 1=1 --".to_string()]), false).expect("decode");
    assert!(cookies.is_empty(), "{:?}", cookies);
  }

  #[test]
  fn query_cookies_does_not_broaden_valid_domain_filter_with_sql_input() {
    let dir = unique_tmpdir("chr-domain-filter-scope");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[
        (".example.com", "/", false, 0, "keep", "yes", b"x", false, 0),
        ("other.test", "/", false, 0, "drop", "no", b"x", false, 0),
      ],
    );

    let cookies = query_cookies(
      vec![],
      db,
      Some(vec!["example.com".to_string(), "') OR 1=1 --".to_string()]),
    )
    .expect("decode");
    let names: Vec<_> = cookies.iter().map(|cookie| cookie.name.as_str()).collect();
    assert_eq!(names, vec!["keep"], "{:?}", cookies);
  }

  #[cfg(unix)]
  #[test]
  fn decrypt_encrypted_value_short_blob_returns_ok() {
    let res = decrypt_encrypted_value("orig".to_string(), b"v1", &[]).expect("should not panic");
    assert_eq!(res, "orig");
  }

  #[cfg(unix)]
  #[test]
  fn decrypt_encrypted_value_invalid_utf8_returns_error() {
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let key = vec![0u8; 16];
    let iv = [b' '; 16];
    let cipher = Aes128CbcEnc::new((&key[..16]).into(), &iv.into());

    let data = vec![0xffu8; 16];
    let mut buf = vec![0u8; 32];
    buf[..16].copy_from_slice(&data);

    let ct = cipher.encrypt_padded_mut::<Pkcs7>(&mut buf, 16).unwrap();

    let mut encrypted_value = b"v10".to_vec();
    encrypted_value.extend_from_slice(ct);

    assert!(decrypt_encrypted_value("".to_string(), &encrypted_value, &[key]).is_err());
  }

  #[cfg(unix)]
  #[test]
  fn decrypt_encrypted_value_decodes_host_hash_prefixed_plaintext() {
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let key = vec![0u8; 16];
    let iv = [b' '; 16];
    let mut plaintext = vec![0xff; 32];
    plaintext.extend_from_slice(b"cookie value");
    let mut ciphertext_buffer = vec![0u8; plaintext.len() + 16];
    ciphertext_buffer[..plaintext.len()].copy_from_slice(&plaintext);
    let cipher = Aes128CbcEnc::new((&key[..]).into(), &iv.into());
    let ciphertext = cipher
      .encrypt_padded_mut::<Pkcs7>(&mut ciphertext_buffer, plaintext.len())
      .expect("encrypt fixture");

    let mut encrypted_value = b"v10".to_vec();
    encrypted_value.extend_from_slice(ciphertext);
    let decrypted = decrypt_encrypted_value("".to_string(), &encrypted_value, &[key])
      .expect("decrypt host-hash-prefixed value");

    assert_eq!(decrypted, "cookie value");
  }

  #[cfg(unix)]
  #[test]
  fn decrypt_encrypted_value_tries_next_key_after_invalid_utf8() {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let correct_key = vec![0u8; 16];
    let iv = [b' '; 16];
    let expected = b"valid cookie value";
    let mut ciphertext_buffer = vec![0u8; expected.len() + 16];
    ciphertext_buffer[..expected.len()].copy_from_slice(expected);
    let cipher = Aes128CbcEnc::new((&correct_key[..]).into(), &iv.into());
    let ciphertext = cipher
      .encrypt_padded_mut::<Pkcs7>(&mut ciphertext_buffer, expected.len())
      .expect("encrypt fixture")
      .to_vec();

    let invalid_utf8_key = (1u16..=u16::MAX)
      .find_map(|candidate| {
        let mut key = vec![0; 16];
        key[..2].copy_from_slice(&candidate.to_le_bytes());
        let cipher = Aes128CbcDec::new((&key[..]).into(), &iv.into());
        let mut candidate_ciphertext = ciphertext.clone();
        let plaintext = cipher
          .decrypt_padded_mut::<Pkcs7>(&mut candidate_ciphertext)
          .ok()?;
        String::from_utf8(plaintext.to_vec())
          .is_err()
          .then_some(key)
      })
      .expect("fixture must include a wrong key with valid padding and invalid UTF-8");

    let mut encrypted_value = b"v10".to_vec();
    encrypted_value.extend_from_slice(&ciphertext);
    let decrypted = decrypt_encrypted_value(
      "".to_string(),
      &encrypted_value,
      &[invalid_utf8_key, correct_key],
    )
    .expect("second key should decrypt the cookie");

    assert_eq!(decrypted, "valid cookie value");
  }

  #[cfg(windows)]
  #[test]
  fn decrypt_encrypted_value_windows_truncated_blob_returns_ok() {
    for len in 3..15 {
      let mut blob = b"v10".to_vec();
      blob.resize(len, 0);
      let res = decrypt_encrypted_value("orig".to_string(), &blob, &[]).expect("should not panic");
      assert_eq!(res, "orig");
    }
  }

  #[cfg(windows)]
  #[test]
  fn decrypt_encrypted_value_skips_wrong_length_key() {
    // A candidate key that isn't 32 bytes must be skipped, not panic the
    // AES-256-GCM path (Key::from_slice would have panicked). Reaching the
    // assertion at all proves there was no panic; with no usable key the
    // function falls through to an error.
    let mut blob = b"v10".to_vec();
    blob.resize(31, 0); // "v10" + 12-byte nonce + 16-byte ciphertext region
    let short_key = vec![0u8; 10];
    let res = decrypt_encrypted_value("".to_string(), &blob, &[short_key]);
    assert!(res.is_err());
  }

  #[cfg(unix)]
  #[test]
  fn query_cookies_ignores_malformed_and_undecryptable_rows() {
    let dir = unique_tmpdir("chr-malformed-rows");
    let db = dir.join("Cookies");
    let conn = rusqlite::Connection::open(&db).expect("open writable sqlite");
    conn
      .execute(
        "CREATE TABLE cookies (
          host_key TEXT NOT NULL,
          path TEXT NOT NULL,
          is_secure INTEGER NOT NULL,
          expires_utc INTEGER NOT NULL,
          name TEXT NOT NULL,
          value TEXT NOT NULL,
          encrypted_value BLOB,
          is_httponly INTEGER NOT NULL,
          samesite INTEGER NOT NULL
        )",
        [],
      )
      .expect("create table");

    // Row 1: Valid row
    conn
      .execute(
        "INSERT INTO cookies VALUES ('.example.com', '/', 1, 11644473600000000, 'valid1', 'val1', X'76313064756d6d79', 1, 1)",
        [],
      )
      .expect("insert row 1");

    // Row 2: Malformed row with negative expires_utc (fails u64 decoding)
    conn
      .execute(
        "INSERT INTO cookies VALUES ('.example.com', '/', 1, -100, 'bad_expiry', 'val', X'76313064756d6d79', 1, 1)",
        [],
      )
      .expect("insert row 2");

    // Row 3: Undecryptable row (encrypted_value starts with v10 but fails decryption)
    conn
      .execute(
        "INSERT INTO cookies VALUES ('.example.com', '/', 1, 11644473600000000, 'undecryptable', '', X'763130696e76616c6964', 1, 1)",
        [],
      )
      .expect("insert row 3");

    // Row 4: Valid row 2
    conn
      .execute(
        "INSERT INTO cookies VALUES ('.test.com', '/', 0, 11644473600000000, 'valid2', 'val2', X'76313064756d6d79', 0, 0)",
        [],
      )
      .expect("insert row 4");

    let mut cookies = query_cookies(vec![], db, None, false)
      .expect("query_cookies should succeed despite bad rows");
    cookies.sort_by(|a, b| a.name.cmp(&b.name));
    let names: Vec<_> = cookies.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["valid1", "valid2"], "{:?}", cookies);
  }
}
