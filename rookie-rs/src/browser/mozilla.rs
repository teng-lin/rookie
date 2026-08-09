use crate::common::{date, enums::*, sqlite, utils};
use anyhow::{anyhow, bail, Result};
use ini::Ini;
use lz4_flex::block::decompress_size_prepended;
use serde_json::Value;
use std::{
  fs,
  path::{Path, PathBuf},
};

/// Returns cookies from mozilla based browsers
pub fn firefox_based(db_path: PathBuf, domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let connection = sqlite::connect(db_path.clone())?;
  let mut query = "
        SELECT host, path, isSecure, expiry, name, value, isHttpOnly, sameSite from moz_cookies 
    "
  .to_string();

  if let Some(domains) = domains.clone() {
    let domain_queries: Vec<String> = domains
      .iter()
      .map(|domain| format!("host LIKE '%{}%'", domain))
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
    let host: Result<String, _> = row.get(0);
    if host.is_err() {
      // ignore null rows
      log::warn!("host is NULL in row");
      continue;
    }
    let host = host?;
    let path: String = row.get(1)?;
    let is_secure: bool = row.get(2)?;
    let expires: u64 = row.get(3)?;
    let expires = date::mozilla_timestamp(expires);

    let name: String = row.get(4)?;

    let value: String = row.get(5)?;
    let http_only: bool = row.get(6)?;

    let same_site: i64 = row.get(7)?;
    let cookie = Cookie {
      domain: host.to_string(),
      path: path.to_string(),
      secure: is_secure,
      expires,
      name: name.to_string(),
      value,
      http_only,
      same_site,
    };
    cookies.push(cookie);
  }

  let parent_path = db_path.parent().unwrap_or(&PathBuf::from("")).to_path_buf();
  if let Ok(session_cookies) = get_session_cookies_lz4(domains.to_owned(), parent_path.to_owned()) {
    cookies.extend(session_cookies);
  }

  if let Ok(session_cookies) = get_session_cookies(domains, parent_path) {
    cookies.extend(session_cookies);
  }
  Ok(cookies)
}

pub fn get_session_cookies(
  domains: Option<Vec<String>>,
  cookies_dir: PathBuf,
) -> Result<Vec<Cookie>> {
  let mut cookies: Vec<Cookie> = vec![];
  let session_file = cookies_dir.join("sessionstore.js");
  let plain = fs::read_to_string(session_file)?;
  let json: Value = serde_json::from_str(&plain)?;
  let windows = json
    .get("windows")
    .ok_or(anyhow!("no windows in json"))?
    .as_array()
    .ok_or(anyhow!("windows are not array"))?;
  for window in windows {
    let may_cookies_json = window.get("cookies");
    if let Some(cookies_json) = may_cookies_json {
      let cookies_json = cookies_json.as_array();
      if let Some(cookies_json) = cookies_json {
        for json_cookie in cookies_json {
          let domain = json_cookie
            .get("host")
            .and_then(|v| v.as_str())
            .unwrap_or("");
          let should_add = domains.is_none() || // add every domain
                        domains.is_some() && utils::some_domain_in_host(domains.to_owned(), domain); // only if some domain in host
          if !should_add {
            continue;
          }
          if let Ok(cookie) = create_cookie(json_cookie) {
            cookies.push(cookie);
          }
        }
      }
    }
  }
  Ok(cookies)
}

pub fn get_session_cookies_lz4(
  domains: Option<Vec<String>>,
  cookies_dir: PathBuf,
) -> Result<Vec<Cookie>> {
  let mut cookies: Vec<Cookie> = vec![];
  let session_file_lz4 = cookies_dir.join("sessionstore-backups/recovery.jsonlz4");
  let compressed = fs::read(session_file_lz4)?;
  if !compressed.starts_with(b"mozLz40\0") {
    bail!("Invalid mozLz40 header");
  }
  let compressed = compressed
    .get(8..)
    .ok_or_else(|| anyhow!("Invalid compressed length"))?;
  let decompressed = decompress_size_prepended(compressed)?;
  let plain = String::from_utf8(decompressed)?;
  let json: Value = serde_json::from_str(&plain)?;
  let cookies_json = json.get("cookies").ok_or(anyhow!("no cookies in json"))?;
  let cookies_json = cookies_json
    .as_array()
    .ok_or(anyhow!("cookies is not list"))?;
  for json_cookie in cookies_json {
    let domain = json_cookie
      .get("host")
      .and_then(|v| v.as_str())
      .unwrap_or("");
    let should_add = domains.is_none() || // add every domain
                        utils::some_domain_in_host(domains.to_owned(), domain); // only if some domain in host
    if !should_add {
      continue;
    }
    if let Ok(cookie) = create_cookie(json_cookie) {
      cookies.push(cookie);
    }
  }
  Ok(cookies)
}

pub fn create_cookie(json_cookie: &Value) -> Result<Cookie> {
  let host = json_cookie
    .get("host")
    .and_then(|v| v.as_str())
    .unwrap_or("");
  let path = json_cookie
    .get("path")
    .and_then(|v| v.as_str())
    .unwrap_or("");
  let secure = json_cookie
    .get("secure")
    .and_then(|v| v.as_bool())
    .unwrap_or(false);
  let name = json_cookie
    .get("name")
    .and_then(|v| v.as_str())
    .unwrap_or("");
  let value = json_cookie
    .get("value")
    .and_then(|v| v.as_str())
    .unwrap_or("");
  let http_only = json_cookie
    .get("httponly")
    .and_then(|v| v.as_bool())
    .unwrap_or(false);
  let expires = json_cookie
    .get("expiry")
    .and_then(|v| v.as_u64())
    .unwrap_or(0);
  let expires = date::mozilla_timestamp(expires);

  let same_site = json_cookie
    .get("sameSite")
    .and_then(|v| v.as_i64())
    .unwrap_or(0);

  let cookie = Cookie {
    domain: host.to_string(),
    expires,
    http_only,
    name: name.to_string(),
    value: value.to_string(),
    path: path.to_string(),
    same_site,
    secure,
  };
  Ok(cookie)
}

pub fn get_default_profile(profiles_path: &Path) -> Result<String> {
  let conf = Ini::load_from_file(profiles_path)?;
  let installs: Vec<_> = conf
    .iter()
    .filter(|(name_option, _)| name_option.unwrap_or_default().starts_with("Install"))
    .collect();
  if !installs.is_empty() {
    let (_, props) = installs.first().unwrap();
    return Ok(props.get("Default").unwrap_or_default().into());
  } else {
    let profiles: Vec<_> = conf
      .iter()
      .filter(|(name_option, _)| name_option.unwrap_or_default().starts_with("Profile"))
      .collect();
    for (_, props) in &profiles {
      if props.get("Default").unwrap_or_default() == "1" {
        return Ok(props.get("Path").unwrap_or_default().into());
      }
    }

    // still not found? last time try to get any Profile with Path.
    for (_, props) in &profiles {
      if let Some(path) = props.get("Path") {
        return Ok(path.into());
      }
    }
  }
  bail!("Can't find any profile")
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::io::Write;
  use std::sync::atomic::{AtomicU64, Ordering};

  // Per-process unique temp paths without pulling in the `tempfile` dep.
  // Each test gets its own subdirectory so they don't collide when run in
  // parallel under `cargo test`.
  fn unique_tmpdir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir =
      std::env::temp_dir().join(format!("rookie-test-{}-{}-{}", tag, std::process::id(), n));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
  }

  // (host, path, isSecure, expiry, name, value, isHttpOnly, sameSite)
  type CookieRow<'a> = (&'a str, &'a str, bool, u64, &'a str, &'a str, bool, i64);

  // Minimal moz_cookies fixture mirroring the columns firefox_based reads.
  // Real Firefox schema has more columns, but rookie-cookies only selects these.
  fn seed_moz_cookies(db: &Path, rows: &[CookieRow<'_>]) {
    let conn = rusqlite::Connection::open(db).expect("open writable sqlite");
    conn
      .execute(
        "CREATE TABLE moz_cookies (
          host TEXT NOT NULL,
          path TEXT NOT NULL,
          isSecure INTEGER NOT NULL,
          expiry INTEGER NOT NULL,
          name TEXT NOT NULL,
          value TEXT NOT NULL,
          isHttpOnly INTEGER NOT NULL,
          sameSite INTEGER NOT NULL
        )",
        [],
      )
      .expect("create table");
    for r in rows {
      conn
        .execute(
          "INSERT INTO moz_cookies (host, path, isSecure, expiry, name, value, isHttpOnly, sameSite)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
          rusqlite::params![r.0, r.1, r.2, r.3, r.4, r.5, r.6, r.7],
        )
        .expect("insert row");
    }
  }

  #[test]
  fn firefox_based_reads_seeded_cookies() {
    let dir = unique_tmpdir("ff-happy");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(
      &db,
      &[
        (
          ".example.com",
          "/",
          false,
          1_700_000_000,
          "id",
          "abc",
          true,
          1,
        ),
        ("foo.test", "/path", true, 0, "tok", "xyz", false, 2),
      ],
    );

    let cookies = firefox_based(db, None).expect("decode");
    assert_eq!(cookies.len(), 2, "{:?}", cookies);

    let id = cookies.iter().find(|c| c.name == "id").expect("id");
    assert_eq!(id.domain, ".example.com");
    assert_eq!(id.value, "abc");
    assert!(id.http_only);
    assert!(!id.secure);
    assert_eq!(id.same_site, 1);
    // mozilla_timestamp passes seconds through and maps 0 to None.
    assert_eq!(id.expires, Some(1_700_000_000));

    let tok = cookies.iter().find(|c| c.name == "tok").expect("tok");
    assert_eq!(tok.domain, "foo.test");
    assert!(tok.secure);
    assert!(!tok.http_only);
    assert_eq!(tok.same_site, 2);
    assert_eq!(tok.expires, None, "expiry=0 should map to None");
  }

  #[test]
  fn firefox_based_filters_by_domain() {
    let dir = unique_tmpdir("ff-domain-filter");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(
      &db,
      &[
        (".example.com", "/", false, 0, "keep", "yes", false, 0),
        ("other.test", "/", false, 0, "drop", "no", false, 0),
      ],
    );

    let cookies = firefox_based(db, Some(vec!["example.com".to_string()])).expect("decode");
    let names: Vec<_> = cookies.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["keep"], "{:?}", cookies);
  }

  #[test]
  fn firefox_based_missing_db_errors() {
    let result = firefox_based(PathBuf::from("/nonexistent/rookie/cookies.sqlite"), None);
    assert!(
      result.is_err(),
      "expected Err for missing db, got {:?}",
      result
    );
  }

  #[test]
  fn firefox_based_non_sqlite_file_errors() {
    let dir = unique_tmpdir("ff-bad-sqlite");
    let db = dir.join("cookies.sqlite");
    std::fs::write(&db, b"this is not a sqlite database").unwrap();
    let result = firefox_based(db, None);
    assert!(
      result.is_err(),
      "expected Err for bogus sqlite, got {:?}",
      result
    );
  }

  #[test]
  fn get_session_cookies_missing_file_errors() {
    let dir = unique_tmpdir("ff-no-sessionstore");
    // sessionstore.js doesn't exist under this dir.
    let result = get_session_cookies(None, dir);
    assert!(result.is_err(), "expected Err for missing sessionstore");
  }

  #[test]
  fn get_session_cookies_invalid_json_errors() {
    let dir = unique_tmpdir("ff-bad-sessionstore");
    std::fs::write(dir.join("sessionstore.js"), b"{not valid json").unwrap();
    let result = get_session_cookies(None, dir);
    assert!(result.is_err(), "expected Err for invalid json");
  }

  #[test]
  fn get_session_cookies_json_without_windows_errors() {
    let dir = unique_tmpdir("ff-no-windows");
    // Valid JSON, but missing the `windows` key the parser requires.
    std::fs::write(dir.join("sessionstore.js"), b"{\"other\": []}").unwrap();
    let err = get_session_cookies(None, dir).expect_err("should fail");
    assert!(
      err.to_string().contains("no windows in json"),
      "unexpected error: {}",
      err
    );
  }

  #[test]
  fn get_session_cookies_lz4_missing_file_errors() {
    let dir = unique_tmpdir("ff-no-lz4");
    // sessionstore-backups/recovery.jsonlz4 doesn't exist.
    let result = get_session_cookies_lz4(None, dir);
    assert!(result.is_err(), "expected Err for missing lz4");
  }

  #[test]
  fn get_session_cookies_lz4_corrupt_payload_errors() {
    let dir = unique_tmpdir("ff-bad-lz4");
    let backups = dir.join("sessionstore-backups");
    std::fs::create_dir_all(&backups).unwrap();
    // Need at least 8 bytes (the 8-byte mozLz40\0 magic is stripped before
    // lz4 decompress) plus garbage; the lz4 step should reject this.
    std::fs::write(
      backups.join("recovery.jsonlz4"),
      b"mozLz40\0this-is-not-actually-lz4-compressed",
    )
    .unwrap();
    let result = get_session_cookies_lz4(None, dir);
    assert!(result.is_err(), "expected Err for corrupt lz4");
  }

  #[test]
  fn get_default_profile_missing_ini_errors() {
    let result = get_default_profile(Path::new("/nonexistent/profiles.ini"));
    assert!(result.is_err(), "expected Err for missing profiles.ini");
  }

  #[test]
  fn get_default_profile_empty_ini_errors() {
    let dir = unique_tmpdir("ff-empty-ini");
    let ini_path = dir.join("profiles.ini");
    std::fs::File::create(&ini_path)
      .unwrap()
      .write_all(b"")
      .unwrap();
    let err = get_default_profile(&ini_path).expect_err("should fail");
    assert!(
      err.to_string().contains("Can't find any profile"),
      "unexpected error: {}",
      err
    );
  }

  #[test]
  fn get_default_profile_prefers_install_block() {
    let dir = unique_tmpdir("ff-install-ini");
    let ini_path = dir.join("profiles.ini");
    std::fs::write(
      &ini_path,
      b"[Install4F96D1932A9F858E]\nDefault=Profiles/abc.default-release\n\
        [Profile0]\nName=default\nIsRelative=1\nPath=Profiles/abc.default-release\nDefault=1\n",
    )
    .unwrap();
    let path = get_default_profile(&ini_path).expect("should resolve");
    assert_eq!(path, "Profiles/abc.default-release");
  }

  #[test]
  fn get_default_profile_falls_back_to_default_flag() {
    let dir = unique_tmpdir("ff-default-flag-ini");
    let ini_path = dir.join("profiles.ini");
    // No [Install...] block, so the resolver should walk Profiles and pick
    // the one with Default=1.
    std::fs::write(
      &ini_path,
      b"[Profile0]\nName=other\nIsRelative=1\nPath=Profiles/other\nDefault=0\n\
        [Profile1]\nName=default\nIsRelative=1\nPath=Profiles/abc.default-release\nDefault=1\n",
    )
    .unwrap();
    let path = get_default_profile(&ini_path).expect("should resolve");
    assert_eq!(path, "Profiles/abc.default-release");
  }

  #[test]
  fn get_session_cookies_lz4_invalid_magic_header_errors() {
    let dir = unique_tmpdir("ff-bad-magic-lz4");
    let backups = dir.join("sessionstore-backups");
    std::fs::create_dir_all(&backups).unwrap();
    std::fs::write(
      backups.join("recovery.jsonlz4"),
      b"BADMAGICthis-is-garbage",
    )
    .unwrap();
    let result = get_session_cookies_lz4(None, dir);
    assert!(result.is_err(), "expected Err for invalid magic header");
  }
}
