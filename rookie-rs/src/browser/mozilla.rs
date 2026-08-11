use crate::common::{date, enums::*, sqlite, utils};
use anyhow::{anyhow, bail, Result};
use ini::{Ini, ParseOption};
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

  let domain_filters: Vec<String> = domains
    .as_ref()
    .map(|domains| domains.iter().map(|domain| format!("%{domain}%")).collect())
    .unwrap_or_default();

  if !domain_filters.is_empty() {
    let predicates = (1..=domain_filters.len())
      .map(|index| format!("host LIKE ?{index}"))
      .collect::<Vec<_>>()
      .join(" OR ");
    query += &format!("WHERE ({predicates})");
  }

  query += ";";

  let mut cookies: Vec<Cookie> = vec![];
  let mut last_row_error: Option<anyhow::Error> = None;
  let mut stmt = connection.prepare(query.as_str())?;
  let mut rows = stmt.query(rusqlite::params_from_iter(domain_filters.iter()))?;

  while let Some(row) = rows.next()? {
    let host: String = match row.get(0) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to read host from row: {err}");
        last_row_error = Some(anyhow!("failed to read host from row: {err}"));
        continue;
      }
    };
    let path: String = match row.get(1) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to read path from row: {err}");
        last_row_error = Some(anyhow!("failed to read path from row: {err}"));
        continue;
      }
    };
    let is_secure: bool = match row.get(2) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to read isSecure from row: {err}");
        last_row_error = Some(anyhow!("failed to read isSecure from row: {err}"));
        continue;
      }
    };
    let expires: u64 = match row.get(3) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to read expiry from row: {err}");
        last_row_error = Some(anyhow!("failed to read expiry from row: {err}"));
        continue;
      }
    };
    let expires = date::mozilla_timestamp(expires);

    let name: String = match row.get(4) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to read name from row: {err}");
        last_row_error = Some(anyhow!("failed to read name from row: {err}"));
        continue;
      }
    };

    let value: String = match row.get(5) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to read value from row: {err}");
        last_row_error = Some(anyhow!("failed to read value from row: {err}"));
        continue;
      }
    };
    let http_only: bool = match row.get(6) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to read isHttpOnly from row: {err}");
        last_row_error = Some(anyhow!("failed to read isHttpOnly from row: {err}"));
        continue;
      }
    };

    let same_site: i64 = match row.get(7) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to read sameSite from row: {err}");
        last_row_error = Some(anyhow!("failed to read sameSite from row: {err}"));
        continue;
      }
    };
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

  if cookies.is_empty() {
    if let Some(err) = last_row_error {
      return Err(err);
    }
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
          let should_add = utils::some_domain_in_host(domains.as_deref(), domain);
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
    let should_add = utils::some_domain_in_host(domains.as_deref(), domain);
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

/// A profile declared by a Mozilla-family browser's `profiles.ini`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MozillaProfile {
  /// The profile's `Name=` value, or an empty string when the section omits it.
  pub name: String,
  /// Path to the profile directory, absolute whenever the caller supplied an
  /// absolute `profiles.ini` path.
  pub path: PathBuf,
  /// Whether this is the profile that the installation owning this
  /// `profiles.ini` would open.
  ///
  /// Defaults are per-installation, so a list gathered across several
  /// installation roots (snap and distro Firefox, say) can contain more than
  /// one default.
  pub is_default: bool,
}

/// A `[Profile...]` section, with its `Path` kept exactly as written in the ini.
struct ProfileSection {
  name: String,
  path: String,
  default_flag: bool,
}

/// Reads `profiles.ini` with escape processing disabled.
///
/// The default parser treats `\` as an escape introducer, which silently
/// destroys the Windows paths that `IsRelative=0` sections store:
/// `Path=C:\Users\me\Profiles\work` would parse as `C:UsersmeProfileswork`,
/// with `\r` becoming a carriage return.
fn load_profiles_ini(profiles_path: &Path) -> Result<Ini> {
  Ini::load_from_file_opt(
    profiles_path,
    ParseOption {
      enabled_escape: false,
      ..Default::default()
    },
  )
  .map_err(Into::into)
}

/// Every `[Profile...]` section that declares a `Path`.
///
/// Firefox itself walks `Profile0`, `Profile1`, ... and stops at the first gap,
/// also requiring `Name` and `IsRelative`. We deliberately accept any
/// `[Profile...]` section with a `Path` instead: reading cookies from a profile
/// Firefox would skip is useful, whereas dropping a real profile is not.
fn profile_sections(conf: &Ini) -> Vec<ProfileSection> {
  conf
    .iter()
    .filter(|(section, _)| section.unwrap_or_default().starts_with("Profile"))
    .filter_map(|(_, props)| {
      let path = props.get("Path")?.trim();
      if path.is_empty() {
        return None;
      }
      Some(ProfileSection {
        name: props.get("Name").unwrap_or_default().to_string(),
        path: path.to_string(),
        default_flag: props.get("Default").unwrap_or_default().trim() == "1",
      })
    })
    .collect()
}

/// Profile paths named by `[Install...] Default=`, deduplicated in file order.
///
/// Firefox keys each section by a hash of the installation directory. Several
/// distinct entries therefore mean this file is shared — by a release and a
/// nightly, or by one live install plus debris, since sections for moved or
/// uninstalled builds are never removed.
fn install_defaults(conf: &Ini) -> Vec<String> {
  let mut defaults: Vec<String> = vec![];
  for (_, props) in conf
    .iter()
    .filter(|(section, _)| section.unwrap_or_default().starts_with("Install"))
  {
    let Some(default) = props
      .get("Default")
      .map(str::trim)
      .filter(|d| !d.is_empty())
    else {
      continue;
    };
    if !defaults.iter().any(|existing| existing == default) {
      defaults.push(default.to_string());
    }
  }
  defaults
}

/// Resolves the default profile's `Path` value, or `None` when the ini declares
/// nothing usable.
///
/// This is a heuristic, not Firefox's algorithm. Firefox picks the
/// `[Install<hash>]` section matching a hash of the *running installation's*
/// directory and honours it unconditionally; sections never compete. We cannot
/// know which installation a caller means, so we degrade in this order:
///
/// 1. a single unambiguous install default — the dedicated profile that the one
///    installation on record opens;
/// 2. with competing installs, a default that the legacy `[ProfileN] Default=1`
///    marker also names, else any profile some install claims — better a
///    profile one installation opens than one none does;
/// 3. the `Default=1` marker alone;
/// 4. the first declared profile;
/// 5. an install default naming a profile that has no section of its own.
fn resolve_default_path(profiles: &[ProfileSection], installs: &[String]) -> Option<String> {
  let is_known = |candidate: &str| profiles.iter().any(|profile| profile.path == candidate);

  if let [only] = installs {
    if is_known(only) {
      return Some(only.clone());
    }
  }

  if installs.len() > 1 {
    log::warn!(
      "profiles.ini declares {} competing [Install...] defaults; guessing which installation is meant",
      installs.len()
    );
    if let Some(profile) = profiles
      .iter()
      .find(|profile| profile.default_flag && installs.contains(&profile.path))
    {
      return Some(profile.path.clone());
    }
    if let Some(default) = installs.iter().find(|default| is_known(default)) {
      return Some(default.clone());
    }
  }

  if let Some(profile) = profiles.iter().find(|profile| profile.default_flag) {
    return Some(profile.path.clone());
  }

  profiles
    .first()
    .map(|profile| profile.path.clone())
    // An install may name a profile that has no [Profile...] section of its
    // own; trying it still beats giving up.
    .or_else(|| installs.first().cloned())
}

/// Returns every profile declared by `profiles.ini`, in file order, resolved
/// against the file's directory and with the default profile flagged.
///
/// Exposing the secondary profiles — not just the default — is what lets
/// callers read cookies from a profile the browser does not open by default.
pub(crate) fn list_profiles(profiles_path: &Path) -> Result<Vec<MozillaProfile>> {
  let conf = load_profiles_ini(profiles_path)?;
  let base = profiles_path.parent().unwrap_or_else(|| Path::new(""));
  let sections = profile_sections(&conf);
  let installs = install_defaults(&conf);
  let default_path = resolve_default_path(&sections, &installs);

  // Exactly one entry carries the flag: two sections may declare the same
  // `Path`, and "the default" must stay singular within one profiles.ini.
  let mut default_taken = false;
  let mut claim_default = |candidate: &str| {
    let is_default = !default_taken && default_path.as_deref() == Some(candidate);
    default_taken |= is_default;
    is_default
  };

  let mut profiles: Vec<MozillaProfile> = sections
    .iter()
    .map(|profile| MozillaProfile {
      is_default: claim_default(&profile.path),
      // `IsRelative=0` sections store a full native path, which `join` passes
      // through. We trust the shape of `Path` rather than the `IsRelative`
      // flag, which browsers do not always keep in sync.
      path: base.join(&profile.path),
      name: profile.name.clone(),
    })
    .collect();

  // An [Install...] section can name a profile that has no [Profile...]
  // section, e.g. after a hand-edited or partially migrated profiles.ini. The
  // pre-enumeration resolver probed those directly, so surface every one of
  // them — not just whichever the heuristic happened to choose.
  for orphan in installs
    .iter()
    .filter(|default| !is_known_section(&sections, default))
  {
    profiles.push(MozillaProfile {
      is_default: claim_default(orphan),
      path: base.join(orphan),
      name: String::new(),
    });
  }

  Ok(profiles)
}

fn is_known_section(sections: &[ProfileSection], candidate: &str) -> bool {
  sections.iter().any(|section| section.path == candidate)
}

/// Picks the profile a user asked for, matching its `Name`, its directory name,
/// or its full path.
///
/// An ambiguous selector is an error rather than a silent first-match: picking
/// the wrong profile is the failure this whole resolver exists to prevent.
pub(crate) fn select_profile<'a>(
  profiles: &'a [MozillaProfile],
  selector: &str,
) -> Result<&'a MozillaProfile> {
  if selector.is_empty() {
    bail!("Profile selector must not be empty");
  }
  // Comparing as a `Path` keeps selection separator-insensitive on Windows,
  // where `base.join("Profiles/work")` yields mixed separators but a user
  // naturally writes the all-backslash spelling.
  let wanted = Path::new(selector);
  let matches: Vec<&MozillaProfile> = profiles
    .iter()
    .filter(|profile| {
      profile.name == selector
        || profile.path.file_name().is_some_and(|dir| dir == selector)
        || profile.path == wanted
    })
    .collect();

  match matches[..] {
    [only] => Ok(only),
    [] => bail!(
      "No profile matching {selector:?}. Available profiles: [{}]",
      describe(profiles.iter())
    ),
    _ => bail!(
      "{} profiles match {selector:?}; select one by full path instead: [{}]",
      matches.len(),
      describe(matches.iter().copied())
    ),
  }
}

fn describe<'a>(profiles: impl Iterator<Item = &'a MozillaProfile>) -> String {
  profiles
    .map(|profile| format!("{} ({})", profile.name, profile.path.display()))
    .collect::<Vec<_>>()
    .join(", ")
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
  fn firefox_based_errors_when_every_row_fails_to_decode() {
    let dir = unique_tmpdir("ff-all-rows-bad");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(&db, &[]);
    // Negative expiry does not fit the u64 the reader asks for, so every row
    // is skipped. With no usable row left, the caller must see an error rather
    // than an empty-but-successful result.
    let conn = rusqlite::Connection::open(&db).expect("open writable sqlite");
    conn
      .execute(
        "INSERT INTO moz_cookies (host, path, isSecure, expiry, name, value, isHttpOnly, sameSite)
          VALUES ('.example.com', '/', 1, -1, 'id', 'v', 1, 0)",
        [],
      )
      .expect("insert bad row");
    drop(conn);

    let result = firefox_based(db, None);
    assert!(
      result.is_err(),
      "expected Err when no row decodes, got {:?}",
      result
    );
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
  fn firefox_based_reads_cookies_committed_to_an_active_wal() {
    // Self-cleaning, unlike `unique_tmpdir`; held to the end of the test.
    let dir = crate::utils::TempDir::new().expect("temp dir");
    let db = dir.path().join("cookies.sqlite");
    seed_moz_cookies(
      &db,
      &[(
        ".example.com",
        "/",
        false,
        0,
        "checkpointed",
        "old",
        false,
        0,
      )],
    );

    // Switch the database to WAL and keep the writer connected, so the second
    // cookie stays in the -wal the way it does while Firefox is running.
    let writer = rusqlite::Connection::open(&db).expect("open writable sqlite");
    let mode: String = writer
      .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
      .expect("enable WAL");
    assert_eq!(mode, "wal");
    writer
      .execute(
        "INSERT INTO moz_cookies (host, path, isSecure, expiry, name, value, isHttpOnly, sameSite)
          VALUES ('.example.com', '/', 0, 0, 'in-wal', 'fresh', 0, 0)",
        [],
      )
      .expect("insert WAL row");

    let mut cookies = firefox_based(db, None).expect("decode");

    cookies.sort_by(|a, b| a.name.cmp(&b.name));
    let names: Vec<_> = cookies.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["checkpointed", "in-wal"], "{cookies:?}");
    let in_wal = cookies.iter().find(|c| c.name == "in-wal").expect("in-wal");
    assert_eq!(
      in_wal.value, "fresh",
      "the WAL row must decode, not just appear"
    );
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

    let mut cookies = firefox_based(
      db,
      Some(vec!["example.com".to_string(), "other.test".to_string()]),
    )
    .expect("decode");
    cookies.sort_by(|a, b| a.name.cmp(&b.name));
    let names: Vec<_> = cookies.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["drop", "keep"], "{:?}", cookies);
  }

  #[test]
  fn firefox_based_domain_filter_treats_sql_as_data() {
    let dir = unique_tmpdir("ff-domain-filter-sql");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(
      &db,
      &[
        (".example.com", "/", false, 0, "first", "yes", false, 0),
        ("other.test", "/", false, 0, "second", "no", false, 0),
      ],
    );

    let cookies = firefox_based(db, Some(vec!["' OR 1=1 --".to_string()])).expect("decode");
    assert!(cookies.is_empty(), "{:?}", cookies);
  }

  #[test]
  fn firefox_based_does_not_broaden_valid_domain_filter_with_sql_input() {
    let dir = unique_tmpdir("ff-domain-filter-scope");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(
      &db,
      &[
        (".example.com", "/", false, 0, "keep", "yes", false, 0),
        ("other.test", "/", false, 0, "drop", "no", false, 0),
      ],
    );

    let cookies = firefox_based(
      db,
      Some(vec!["example.com".to_string(), "') OR 1=1 --".to_string()]),
    )
    .expect("decode");
    let names: Vec<_> = cookies.iter().map(|cookie| cookie.name.as_str()).collect();
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
  fn list_profiles_missing_ini_errors() {
    let result = list_profiles(Path::new("/nonexistent/profiles.ini"));
    assert!(result.is_err(), "expected Err for missing profiles.ini");
  }

  #[test]
  fn list_profiles_empty_ini_yields_no_profiles() {
    let dir = unique_tmpdir("ff-empty-ini");
    let ini_path = dir.join("profiles.ini");
    std::fs::File::create(&ini_path)
      .unwrap()
      .write_all(b"")
      .unwrap();
    assert!(list_profiles(&ini_path).expect("should list").is_empty());
  }

  #[test]
  fn default_profile_prefers_install_block() {
    let ini_path = write_ini(
      "ff-install-ini",
      "[Install4F96D1932A9F858E]\nDefault=Profiles/abc.default-release\n\
       [Profile0]\nName=default\nIsRelative=1\nPath=Profiles/abc.default-release\nDefault=1\n",
    );
    assert_eq!(
      default_profile_path(&ini_path),
      Some("Profiles/abc.default-release".to_string())
    );
  }

  #[test]
  fn default_profile_falls_back_to_default_flag() {
    // No [Install...] block, so the resolver should walk Profiles and pick
    // the one with Default=1.
    let ini_path = write_ini(
      "ff-default-flag-ini",
      "[Profile0]\nName=other\nIsRelative=1\nPath=Profiles/other\nDefault=0\n\
       [Profile1]\nName=default\nIsRelative=1\nPath=Profiles/abc.default-release\nDefault=1\n",
    );
    assert_eq!(
      default_profile_path(&ini_path),
      Some("Profiles/abc.default-release".to_string())
    );
  }

  fn write_ini(tag: &str, body: &str) -> PathBuf {
    let ini_path = unique_tmpdir(tag).join("profiles.ini");
    std::fs::write(&ini_path, body).unwrap();
    ini_path
  }

  /// The resolved default profile's path, relative to the ini's directory where
  /// possible, so assertions read like the `Path=` values in the fixture. A
  /// profile resolved outside that directory is reported in full rather than
  /// panicking.
  fn default_profile_path(ini_path: &Path) -> Option<String> {
    let base = ini_path.parent().expect("ini has a parent");
    list_profiles(ini_path)
      .expect("should list")
      .into_iter()
      .find(|profile| profile.is_default)
      .map(|profile| {
        profile
          .path
          .strip_prefix(base)
          .unwrap_or(&profile.path)
          .to_string_lossy()
          .replace('\\', "/")
      })
  }

  #[test]
  fn default_profile_ignores_install_without_default_key() {
    // The install section exists but names no profile, so the Default=1 marker
    // must still decide instead of the resolver returning an empty path.
    let ini_path = write_ini(
      "ff-install-no-default",
      "[Install4F96D1932A9F858E]\nLocked=1\n\
       [Profile0]\nName=default\nIsRelative=1\nPath=Profiles/abc.default-release\nDefault=1\n",
    );
    assert_eq!(
      default_profile_path(&ini_path),
      Some("Profiles/abc.default-release".to_string())
    );
  }

  #[test]
  fn default_profile_breaks_install_ties_with_default_marker() {
    // Release and nightly share this profiles.ini. Neither install is
    // authoritative, so the Default=1 marker wins over file order.
    let ini_path = write_ini(
      "ff-two-installs",
      "[Install0000000000000001]\nDefault=Profiles/nightly\n\
       [Install0000000000000002]\nDefault=Profiles/release\n\
       [Profile0]\nName=nightly\nIsRelative=1\nPath=Profiles/nightly\n\
       [Profile1]\nName=default\nIsRelative=1\nPath=Profiles/release\nDefault=1\n",
    );
    assert_eq!(
      default_profile_path(&ini_path),
      Some("Profiles/release".to_string())
    );
  }

  #[test]
  fn default_profile_single_install_outranks_default_marker() {
    // One unambiguous install: it is the dedicated profile Firefox opens, so it
    // takes precedence over the legacy marker on another profile.
    let ini_path = write_ini(
      "ff-install-wins",
      "[Install4F96D1932A9F858E]\nDefault=Profiles/work\n\
       [Profile0]\nName=personal\nIsRelative=1\nPath=Profiles/personal\nDefault=1\n\
       [Profile1]\nName=work\nIsRelative=1\nPath=Profiles/work\n",
    );
    assert_eq!(
      default_profile_path(&ini_path),
      Some("Profiles/work".to_string())
    );
  }

  #[test]
  fn default_profile_prefers_an_install_claimed_profile_over_a_stale_marker() {
    // Two installs and two Default=1 markers: the first marker names a profile
    // no install claims (stale after an about:profiles switch), so the resolver
    // must pick the marker that an install actually points at.
    let ini_path = write_ini(
      "ff-stale-marker",
      "[Install0000000000000001]\nDefault=Profiles/release\n\
       [Install0000000000000002]\nDefault=Profiles/nightly\n\
       [Profile0]\nName=stale\nIsRelative=1\nPath=Profiles/stale\nDefault=1\n\
       [Profile1]\nName=nightly\nIsRelative=1\nPath=Profiles/nightly\nDefault=1\n",
    );
    assert_eq!(
      default_profile_path(&ini_path),
      Some("Profiles/nightly".to_string())
    );
  }

  #[test]
  fn default_profile_prefers_a_claimed_profile_when_no_marker_agrees() {
    // Competing installs, no Default=1 anywhere: a profile that some install
    // opens beats the merely-first profile section.
    let ini_path = write_ini(
      "ff-no-marker-two-installs",
      "[Install0000000000000001]\nDefault=Profiles/ghost\n\
       [Install0000000000000002]\nDefault=Profiles/real\n\
       [Profile0]\nName=other\nIsRelative=1\nPath=Profiles/other\n\
       [Profile1]\nName=real\nIsRelative=1\nPath=Profiles/real\n",
    );
    assert_eq!(
      default_profile_path(&ini_path),
      Some("Profiles/real".to_string())
    );
  }

  #[test]
  fn default_profile_ignores_an_install_naming_an_undeclared_profile() {
    // The lone install points at a profile with no section; the Default=1
    // marker is the only trustworthy signal left.
    let ini_path = write_ini(
      "ff-install-ghost",
      "[Install4F96D1932A9F858E]\nDefault=Profiles/ghost\n\
       [Profile0]\nName=other\nIsRelative=1\nPath=Profiles/other\n\
       [Profile1]\nName=default\nIsRelative=1\nPath=Profiles/real\nDefault=1\n",
    );
    assert_eq!(
      default_profile_path(&ini_path),
      Some("Profiles/real".to_string())
    );
  }

  #[test]
  fn default_profile_treats_repeated_install_defaults_as_one() {
    // Two installs naming the SAME profile are not in conflict, so that profile
    // wins over a competing Default=1 marker just as a single install would.
    let ini_path = write_ini(
      "ff-duplicate-installs",
      "[Install0000000000000001]\nDefault=Profiles/work\n\
       [Install0000000000000002]\nDefault=Profiles/work\n\
       [Profile0]\nName=personal\nIsRelative=1\nPath=Profiles/personal\nDefault=1\n\
       [Profile1]\nName=work\nIsRelative=1\nPath=Profiles/work\n",
    );
    assert_eq!(
      default_profile_path(&ini_path),
      Some("Profiles/work".to_string())
    );
  }

  #[test]
  fn default_profile_accepts_a_padded_default_marker() {
    let ini_path = write_ini(
      "ff-padded-marker",
      "[Profile0]\nName=other\nIsRelative=1\nPath=Profiles/other\n\
       [Profile1]\nName=default\nIsRelative=1\nPath=Profiles/real\nDefault= 1 \n",
    );
    assert_eq!(
      default_profile_path(&ini_path),
      Some("Profiles/real".to_string())
    );
  }

  #[test]
  fn list_profiles_skips_sections_without_a_path() {
    let ini_path = write_ini(
      "ff-pathless-section",
      "[Profile0]\nName=broken\nIsRelative=1\n\
       [Profile1]\nName=ok\nIsRelative=1\nPath=Profiles/ok\nDefault=1\n",
    );
    let profiles = list_profiles(&ini_path).expect("should list");
    let names: Vec<_> = profiles.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, vec!["ok"]);
  }

  #[test]
  fn list_profiles_surfaces_an_install_default_with_no_section() {
    // The pre-enumeration resolver returned the install's Default verbatim and
    // discovery probed it, so it must stay reachable.
    let ini_path = write_ini(
      "ff-orphan-install",
      "[Install4F96D1932A9F858E]\nDefault=Profiles/orphan\n",
    );
    let base = ini_path.parent().unwrap();

    let profiles = list_profiles(&ini_path).expect("should list");
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].path, base.join("Profiles/orphan"));
    assert!(profiles[0].is_default);
  }

  #[test]
  fn list_profiles_surfaces_an_orphan_install_alongside_declared_profiles() {
    // The install names a profile with no section, another section exists, and
    // no Default=1 marker decides. The heuristic default is the declared
    // profile, but the orphan must still be listed so discovery can reach it.
    let ini_path = write_ini(
      "ff-orphan-plus-declared",
      "[Install4F96D1932A9F858E]\nDefault=Profiles/orphan\n\
       [Profile0]\nName=other\nIsRelative=1\nPath=Profiles/other\n",
    );
    let base = ini_path.parent().unwrap();

    let profiles = list_profiles(&ini_path).expect("should list");
    let paths: Vec<_> = profiles.iter().map(|p| p.path.clone()).collect();
    assert_eq!(
      paths,
      vec![base.join("Profiles/other"), base.join("Profiles/orphan")]
    );
    assert!(
      profiles[0].is_default,
      "declared profile is the heuristic default"
    );
    assert!(!profiles[1].is_default);
  }

  #[test]
  fn list_profiles_flags_exactly_one_default_for_duplicate_paths() {
    // A malformed ini can declare the same Path twice; "the default" must stay
    // singular so selection does not become spuriously ambiguous.
    let ini_path = write_ini(
      "ff-duplicate-paths",
      "[Profile0]\nName=first\nIsRelative=1\nPath=Profiles/same\nDefault=1\n\
       [Profile1]\nName=second\nIsRelative=1\nPath=Profiles/same\nDefault=1\n",
    );
    let profiles = list_profiles(&ini_path).expect("should list");
    assert_eq!(profiles.len(), 2);
    assert_eq!(
      profiles.iter().filter(|p| p.is_default).count(),
      1,
      "{profiles:?}"
    );
  }

  #[test]
  fn list_profiles_keeps_backslash_paths_verbatim() {
    // rust-ini's default parser treats `\` as an escape introducer and would
    // turn this into `C:UsersmeProfileswork`, with `\r` becoming a carriage
    // return. Asserted on every platform so Linux CI catches a regression.
    let ini_path = write_ini(
      "ff-backslash",
      "[Profile0]\nName=win\nIsRelative=0\nPath=C:\\Users\\me\\Profiles\\work\nDefault=1\n",
    );
    let base = ini_path.parent().unwrap();
    let profiles = list_profiles(&ini_path).expect("should list");
    assert_eq!(profiles.len(), 1);
    assert_eq!(
      profiles[0].path,
      base.join("C:\\Users\\me\\Profiles\\work"),
      "backslashes must survive ini parsing"
    );
  }

  #[test]
  fn select_profile_rejects_ambiguous_and_empty_selectors() {
    let profiles = vec![
      MozillaProfile {
        name: "default-release".to_string(),
        path: PathBuf::from("/snap/Profiles/abc.default-release"),
        is_default: true,
      },
      MozillaProfile {
        name: "default-release".to_string(),
        path: PathBuf::from("/home/Profiles/xyz.default-release"),
        is_default: true,
      },
    ];

    let err = select_profile(&profiles, "default-release").expect_err("ambiguous");
    assert!(
      err.to_string().contains("2 profiles match"),
      "unexpected error: {err}"
    );
    // A full path still disambiguates.
    assert_eq!(
      select_profile(&profiles, "/snap/Profiles/abc.default-release")
        .unwrap()
        .path,
      PathBuf::from("/snap/Profiles/abc.default-release")
    );

    let err = select_profile(&profiles, "").expect_err("empty selector");
    assert!(
      err.to_string().contains("must not be empty"),
      "unexpected error: {err}"
    );
  }

  #[test]
  fn default_profile_falls_back_to_first_profile() {
    let ini_path = write_ini(
      "ff-no-default-marker",
      "[General]\nStartWithLastProfile=1\n\
       [Profile0]\nName=first\nIsRelative=1\nPath=Profiles/first\n\
       [Profile1]\nName=second\nIsRelative=1\nPath=Profiles/second\n",
    );
    assert_eq!(
      default_profile_path(&ini_path),
      Some("Profiles/first".to_string())
    );
  }

  #[test]
  fn list_profiles_returns_every_profile_with_absolute_paths() {
    let ini_path = write_ini(
      "ff-list",
      "[Install4F96D1932A9F858E]\nDefault=Profiles/release\n\
       [Profile0]\nName=nightly\nIsRelative=1\nPath=Profiles/nightly\n\
       [Profile1]\nName=default\nIsRelative=1\nPath=Profiles/release\nDefault=1\n",
    );
    let base = ini_path.parent().unwrap();

    let profiles = list_profiles(&ini_path).expect("should list");
    let names: Vec<_> = profiles.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, vec!["nightly", "default"]);
    assert_eq!(profiles[0].path, base.join("Profiles/nightly"));
    assert!(!profiles[0].is_default);
    assert_eq!(profiles[1].path, base.join("Profiles/release"));
    assert!(profiles[1].is_default);
  }

  #[test]
  fn list_profiles_keeps_absolute_profile_paths() {
    let absolute = unique_tmpdir("ff-absolute-target");
    let ini_path = write_ini(
      "ff-absolute",
      &format!(
        "[Profile0]\nName=external\nIsRelative=0\nPath={}\nDefault=1\n",
        absolute.display()
      ),
    );

    let profiles = list_profiles(&ini_path).expect("should list");
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].path, absolute);
  }

  #[test]
  fn list_profiles_without_profile_sections_is_empty() {
    let ini_path = write_ini("ff-installs-only", "[Install4F96D1932A9F858E]\nLocked=1\n");
    assert!(list_profiles(&ini_path).expect("should list").is_empty());
  }

  #[test]
  fn select_profile_matches_name_directory_or_path() {
    let profiles = vec![
      MozillaProfile {
        name: "default".to_string(),
        path: PathBuf::from("/base/Profiles/abc.default-release"),
        is_default: true,
      },
      MozillaProfile {
        name: "work".to_string(),
        path: PathBuf::from("/base/Profiles/xyz.work"),
        is_default: false,
      },
    ];

    assert_eq!(select_profile(&profiles, "work").unwrap().name, "work");
    assert_eq!(
      select_profile(&profiles, "abc.default-release")
        .unwrap()
        .name,
      "default"
    );
    assert_eq!(
      select_profile(&profiles, "/base/Profiles/xyz.work")
        .unwrap()
        .name,
      "work"
    );

    let err = select_profile(&profiles, "missing").expect_err("should fail");
    assert!(err.to_string().contains("work"), "unexpected error: {err}");
  }

  #[test]
  fn get_session_cookies_lz4_invalid_magic_header_errors() {
    let dir = unique_tmpdir("ff-bad-magic-lz4");
    let backups = dir.join("sessionstore-backups");
    std::fs::create_dir_all(&backups).unwrap();
    std::fs::write(backups.join("recovery.jsonlz4"), b"BADMAGICthis-is-garbage").unwrap();
    let result = get_session_cookies_lz4(None, dir);
    assert!(result.is_err(), "expected Err for invalid magic header");
  }

  #[test]
  fn firefox_based_ignores_malformed_and_blob_rows() {
    let dir = unique_tmpdir("ff-malformed-rows");
    let db = dir.join("cookies.sqlite");
    let conn = rusqlite::Connection::open(&db).expect("open writable sqlite");
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

    // Row 1: Valid row
    conn
      .execute(
        "INSERT INTO moz_cookies VALUES ('.example.com', '/', 0, 1700000000, 'valid1', 'abc', 1, 1)",
        [],
      )
      .expect("insert row 1");

    // Row 2: Negative expiry (u64 decoding error)
    conn
      .execute(
        "INSERT INTO moz_cookies VALUES ('.example.com', '/', 0, -1, 'bad_expiry', 'abc', 1, 1)",
        [],
      )
      .expect("insert row 2");

    // Row 3: BLOB value column (String decoding error)
    conn
      .execute(
        "INSERT INTO moz_cookies VALUES ('.example.com', '/', 0, 1700000000, 'bad_blob_val', X'DEADBEEF', 1, 1)",
        [],
      )
      .expect("insert row 3");

    // Row 4: Valid row 2
    conn
      .execute(
        "INSERT INTO moz_cookies VALUES ('foo.test', '/path', 1, 1700000000, 'valid2', 'xyz', 0, 2)",
        [],
      )
      .expect("insert row 4");

    let mut cookies =
      firefox_based(db, None).expect("firefox_based should succeed despite bad rows");
    cookies.sort_by(|a, b| a.name.cmp(&b.name));
    let names: Vec<_> = cookies.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["valid1", "valid2"], "{:?}", cookies);
  }
}
