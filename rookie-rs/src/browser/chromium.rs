use crate::common::{date, enums::*, sqlite};
use anyhow::{bail, Result};
use std::path::PathBuf;

#[allow(unused)]
use crate::config::Browser;

#[cfg(target_os = "windows")]
use crate::windows;

#[cfg(not(target_os = "linux"))]
#[allow(unused)]
use anyhow::Context;

#[cfg(target_os = "macos")]
use crate::macos;

#[cfg(target_os = "windows")]
use aes_gcm::{
  aead::{generic_array::GenericArray, Aead, KeyInit},
  Aes256Gcm, Key,
};
#[cfg(target_os = "windows")]
use base64::{engine::general_purpose, Engine as _};

/// Returns cookies from chromium based browser
#[cfg(target_os = "windows")]
pub fn chromium_based(
  key: PathBuf,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
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
    query_cookies(keys, db_path, domains)
  }

  #[cfg(not(feature = "appbound"))]
  {
    let keys = get_keys(legacy_key)?;
    query_cookies(keys, db_path, domains)
  }
}

/// Returns cookies from chromium based browser
#[cfg(unix)]
pub fn chromium_based(
  config: &Browser,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
) -> Result<Vec<Cookie>> {
  // Simple AES

  let keys = get_keys(config)?;
  query_cookies(keys, db_path, domains)
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
  let mut keydpapi: Vec<u8> = general_purpose::STANDARD.decode(key64)?;
  let keydpapi = &mut keydpapi[5..];
  let v10_key = crate::windows::dpapi::decrypt(keydpapi)?;
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

  let mut keys: Vec<Vec<u8>> = vec![];

  let key_service = config
    .osx_key_service
    .clone()
    .context("missing osx_key_service")?;
  let key_user = config
    .osx_key_user
    .clone()
    .context("missing osx_key_user")?;
  let password =
    macos::get_osx_keychain_password(&key_service, &key_user).unwrap_or("peanuts".to_string());

  let key = create_pbkdf2_key(password.as_str(), salt, iterations);
  keys.push(key);

  let key = create_pbkdf2_key("peanuts", salt, iterations);
  keys.push(key);
  let key = create_pbkdf2_key("", salt, iterations);
  keys.push(key);

  Ok(keys)
}

/// Decrypt cookie value using aes GCM
#[cfg(windows)]
fn decrypt_encrypted_value(
  value: String,
  encrypted_value: &[u8],
  keys: Vec<Vec<u8>>,
) -> Result<String> {
  let key_type = &encrypted_value[..3];
  if !value.is_empty() || !(key_type == b"v11" || key_type == b"v10" || key_type == b"v20") {
    // unknown key_type or value isn't encrypted
    log::warn!("Unknown key type: {:?}", key_type);
    return Ok(value);
  }
  log::debug!("key type: {:?}", key_type);

  let encrypted_value = &encrypted_value[3..];
  let nonce = &encrypted_value[..12]; // iv
  let ciphertext = &encrypted_value[12..];

  // Create a new AES block cipher.
  for key in keys {
    let key = Key::<Aes256Gcm>::from_slice(key.as_slice());
    let cipher = Aes256Gcm::new(key);
    let nonce = GenericArray::from_slice(nonce); // 96-bits; unique per message

    match cipher.decrypt(nonce, ciphertext.as_ref()) {
      Ok(plaintext) => {
        // Successfully decrypted, try to convert to string
        let plaintext = if key_type == b"v20" {
          String::from_utf8(plaintext[32..].to_vec()).context("Can't decode encrypted value")
        } else {
          String::from_utf8(plaintext).context("Can't decode encrypted value")
        };

        match plaintext {
          Ok(text) => return Ok(text),
          Err(e) => log::warn!("Failed to decode plaintext: {}", e),
        }
      }
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
  keys: Vec<Vec<u8>>,
) -> Result<String> {
  // cbc
  if !value.is_empty() {
    // unknown key_type or value isn't encrypted
    return Ok(value);
  }
  if encrypted_value.is_empty() {
    return Ok("".into());
  }
  let key_type = &encrypted_value[..3];

  if !(key_type == b"v11" || key_type == b"v10" || key_type == b"v20") {
    return Ok(value);
  }
  log::debug!("key type: {:?}", key_type);

  use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};

  type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

  // Create an AES-128 cipher with the provided key.

  let encrypted_value = &mut encrypted_value.to_owned()[3..];
  let iv: [u8; 16] = [b' '; 16];

  for key in &keys {
    let mut key_array: [u8; 16] = [0; 16];
    key_array.copy_from_slice(&key[..16]);
    let cipher = Aes128CbcDec::new(&key_array.into(), &iv.into());
    let mut cloned_encrypted_value: Vec<u8> = encrypted_value.to_vec();

    if let Ok(plaintext) = cipher.decrypt_padded_mut::<Pkcs7>(&mut cloned_encrypted_value) {
      let decoded = String::from_utf8(plaintext.to_vec());
      match decoded {
        Ok(decoded) => {
          return Ok(decoded);
        }
        Err(_) => {
          log::debug!("Error in decode decrypt value with utf8. trying from index 32");

          let decoded = String::from_utf8(plaintext[32..].to_vec()).unwrap_or_else(|_| {
            log::warn!("Error decoding from index 32 with UTF-8");
            "".into()
          });
          return Ok(decoded);
        }
      }
    }
  }
  bail!("decrypt_encrypted_value failed")
}

#[cfg(target_os = "windows")]
fn unlock_file(mut path: PathBuf) -> Result<PathBuf> {
  let mut shadow_copy_success = false;
  // Shadow copy cookies file so we can read session cookies
  // Admin rights required
  if privilege::user::privileged() {
    log::debug!("Admin rights detected");
    if let Ok(temp_dir) = windows::shadow_copy::temp_folder(".tmp", "", 10) {
      let result = windows::shadow_copy::shadow_copy(path.clone(), temp_dir.clone().to_path_buf());
      log::debug!("shadow copy result: {:?}", result);
      if result.is_ok() {
        shadow_copy_success = true;
        path = temp_dir.join(path.file_name().unwrap());
      }
    }
  }

  // Elegantly restart the process which lock the cookies file (And unlock it) using restart manager API
  if !shadow_copy_success {
    log::warn!("Unlocking Chrome database... This may take a while (sometimes up to a minute)");
    unsafe {
      crate::windows::restart_manager::release_file_lock(path.to_str().unwrap());
    }
  }
  Ok(path)
}

#[allow(unused_mut)]
pub(crate) fn query_cookies(
  keys: Vec<Vec<u8>>,
  mut db_path: PathBuf,
  domains: Option<Vec<String>>,
) -> Result<Vec<Cookie>> {
  // In windows unlock file locking
  #[cfg(target_os = "windows")]
  {
    db_path = unlock_file(db_path)?;
  }

  log::info!(
    "Creating SQLite connection to {}",
    db_path.to_str().unwrap_or("")
  );
  let connection = sqlite::connect(db_path)?;
  let mut query =
        "SELECT host_key, path, is_secure, expires_utc, name, value, CAST(encrypted_value AS BLOB), is_httponly, samesite FROM cookies ".to_string();

  if let Some(domains) = domains {
    let domain_queries: Vec<String> = domains
      .iter()
      .map(|domain| format!("host_key LIKE '%{}%'", domain))
      .collect();

    if !domain_queries.is_empty() {
      let joined_queries = domain_queries.join(" OR ");
      query += &format!("WHERE ({})", joined_queries);
    }
  }
  query += ";";

  let mut cookies: Vec<Cookie> = vec![];
  let mut stmt = connection.prepare(query.as_str())?;
  let mut rows = stmt.query([])?;

  while let Some(row) = rows.next()? {
    let host_key: String = row.get(0)?;
    let path: String = row.get(1)?;
    let is_secure: bool = row.get(2)?;
    let expires: u64 = row.get(3)?;
    let expires = date::chromium_timestamp(expires);
    let name: String = row.get(4)?;

    let value: String = row.get(5)?;
    let encrypted_value: Vec<u8> = row.get(6)?;
    if encrypted_value.is_empty() {
      continue;
    }
    let decrypted_value = decrypt_encrypted_value(value, &encrypted_value, keys.to_owned())?;
    let http_only: bool = row.get(7)?;

    let same_site: i64 = row.get(8)?;
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
    let result = query_cookies(vec![], PathBuf::from("/nonexistent/cookies.db"), None);
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
    let result = query_cookies(vec![], db, None);
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
    let cookies = query_cookies(vec![], db, None).expect("decode");
    assert!(cookies.is_empty(), "{:?}", cookies);
  }

  #[test]
  fn query_cookies_skips_rows_with_empty_encrypted_value() {
    let dir = unique_tmpdir("chr-skip-empty");
    let db = dir.join("Cookies");
    // `query_cookies` short-circuits on empty encrypted_value via
    // `if encrypted_value.is_empty() { continue }`, so this row is
    // dropped even though every other column is valid.
    seed_chromium_cookies(
      &db,
      &[(
        ".example.com",
        "/",
        false,
        0,
        "skip",
        "ignored",
        b"",
        false,
        0,
      )],
    );
    let cookies = query_cookies(vec![], db, None).expect("decode");
    assert!(cookies.is_empty(), "{:?}", cookies);
  }

  // Unix-only tests: on unix `decrypt_encrypted_value` short-circuits to
  // the plain `value` field when it's non-empty OR when the encrypted
  // prefix isn't a known v10/v11/v20 marker. That lets us exercise the
  // SQL → Cookie struct mapping end-to-end without a real key.
  #[cfg(unix)]
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
        b"v10dummy", // non-empty so the row isn't skipped
        true,
        1,
      )],
    );
    let cookies = query_cookies(vec![], db, None).expect("decode");
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
    let cookies = query_cookies(vec![], db, Some(vec!["example.com".to_string()])).expect("decode");
    let names: Vec<_> = cookies.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["keep"], "{:?}", cookies);
  }
}
