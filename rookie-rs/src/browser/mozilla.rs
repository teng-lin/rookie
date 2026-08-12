use crate::common::{date, enums::*, sqlite, utils};
use anyhow::{anyhow, bail, Result};
use ini::{Ini, ParseOption};
use lz4_flex::block::decompress_size_prepended;
use serde_json::Value;
use std::{
  fs,
  io::Read,
  path::{Path, PathBuf},
};

/// Returns cookies from mozilla based browsers
pub fn firefox_based(db_path: PathBuf, domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let database = sqlite::with_browser_database(db_path.clone(), |connection| {
    query_persistent_cookies(connection, domains.as_deref())
  })?;
  log::debug!(
    "Mozilla database query succeeded via {:?} after {} attempt(s)",
    database.strategy(),
    database.attempts()
  );
  let persistent = database.into_value();
  let mut cookies = persistent.cookies;

  let parent_path = db_path.parent().unwrap_or(&PathBuf::from("")).to_path_buf();
  cookies.extend(get_authoritative_session_cookies(domains, &parent_path));
  if cookies.is_empty() {
    if let Some(error) = persistent.last_row_error {
      return Err(error);
    }
  }
  Ok(cookies)
}

/// Escapes SQL `LIKE` wildcard metacharacters (`%`, `_`) and the escape
/// character itself so a caller-supplied domain is matched as literal text,
/// not interpreted as a wildcard pattern. Pair with an `ESCAPE '\'` clause.
fn escape_like_pattern(input: &str) -> String {
  input
    .replace('\\', "\\\\")
    .replace('%', "\\%")
    .replace('_', "\\_")
}

struct PersistentCookieQuery {
  cookies: Vec<Cookie>,
  rows_seen: usize,
  rows_skipped: usize,
  last_row_error: Option<anyhow::Error>,
}

fn query_persistent_cookies(
  connection: &rusqlite::Connection,
  domains: Option<&[String]>,
) -> Result<PersistentCookieQuery> {
  let mut query = "
        SELECT host, path, isSecure, expiry, name, value, isHttpOnly, sameSite from moz_cookies
    "
  .to_string();

  let domain_filters: Vec<String> = domains
    .map(|domains| {
      domains
        .iter()
        .map(|domain| format!("%{}%", escape_like_pattern(domain)))
        .collect()
    })
    .unwrap_or_default();

  if !domain_filters.is_empty() {
    let predicates = (1..=domain_filters.len())
      .map(|index| format!("host LIKE ?{index} ESCAPE '\\'"))
      .collect::<Vec<_>>()
      .join(" OR ");
    query += &format!("WHERE ({predicates})");
  }

  query += ";";

  let mut cookies: Vec<Cookie> = vec![];
  let mut last_row_error: Option<anyhow::Error> = None;
  let mut rows_seen = 0;
  let mut rows_skipped = 0;
  let mut stmt = connection.prepare(query.as_str())?;
  let mut rows = stmt.query(rusqlite::params_from_iter(domain_filters.iter()))?;

  while let Some(row) = rows.next()? {
    rows_seen += 1;
    let host = row
      .get::<_, Option<String>>(0)
      .ok()
      .flatten()
      .unwrap_or_default();
    let path = row
      .get::<_, Option<String>>(1)
      .ok()
      .flatten()
      .unwrap_or_else(|| "/".to_string());
    let is_secure = row
      .get::<_, Option<bool>>(2)
      .ok()
      .flatten()
      .unwrap_or(false);
    let expires = row
      .get::<_, Option<i64>>(3)
      .ok()
      .flatten()
      .and_then(|value| u64::try_from(value).ok())
      .and_then(date::mozilla_timestamp);

    let name: String = match row.get(4) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to read name from row: {err}");
        last_row_error = Some(anyhow!("failed to read name from row: {err}"));
        rows_skipped += 1;
        continue;
      }
    };

    let value: String = match row.get(5) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to read value from row: {err}");
        last_row_error = Some(anyhow!("failed to read value from row: {err}"));
        rows_skipped += 1;
        continue;
      }
    };
    let http_only = row
      .get::<_, Option<bool>>(6)
      .ok()
      .flatten()
      .unwrap_or(false);
    let same_site = row
      .get::<_, Option<i64>>(7)
      .ok()
      .flatten()
      .unwrap_or(SAME_SITE_UNSPECIFIED);
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

  Ok(PersistentCookieQuery {
    cookies,
    rows_seen,
    rows_skipped,
    last_row_error,
  })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionStoreFormat {
  JsonLz4,
  LegacyJson,
}

/// Source-format identifiers this engine can emit. They are declared once here
/// and asserted against the registry's declared capabilities, so an emitted
/// format can never drift away from what a browser definition claims.
pub(crate) const PERSISTENT_FORMAT_ID: &str = "mozilla_sqlite";
pub(crate) const SESSION_JSONLZ4_FORMAT_ID: &str = "firefox_session_jsonlz4";
pub(crate) const SESSION_JSON_FORMAT_ID: &str = "firefox_session_json";

impl SessionStoreFormat {
  fn format_id(self) -> &'static str {
    match self {
      Self::JsonLz4 => SESSION_JSONLZ4_FORMAT_ID,
      Self::LegacyJson => SESSION_JSON_FORMAT_ID,
    }
  }
}

const SESSION_STORE_READ_ATTEMPTS: usize = 2;
const MAX_SESSION_COOKIE_DIAGNOSTICS: usize = 8;

#[derive(Debug)]
struct SessionCookieParseOutcome {
  cookies: Vec<Cookie>,
  rows_seen: usize,
  rows_skipped: usize,
  diagnostics: Vec<String>,
}

#[derive(Debug)]
struct SessionCandidateSuccess {
  parsed: SessionCookieParseOutcome,
  attempts: u32,
  transient_errors: Vec<String>,
}

/// Failure counterpart of [`SessionCandidateSuccess`]. Retry diagnostics are
/// carried on both paths so a candidate that never succeeded still reports why
/// each attempt failed.
#[derive(Debug)]
struct SessionCandidateFailure {
  error: anyhow::Error,
  attempts: u32,
  transient_errors: Vec<String>,
}

/// Crate-private source outcome for the generic registry adapter.  The legacy
/// API deliberately continues to project this to a flat `Vec<Cookie>`.
#[derive(Debug)]
pub(crate) struct MozillaSessionSourceOutcome {
  pub(crate) path: PathBuf,
  pub(crate) format: &'static str,
  pub(crate) selected: bool,
  pub(crate) cookies: Vec<Cookie>,
  pub(crate) rows_seen: usize,
  pub(crate) rows_skipped: usize,
  pub(crate) acquisition_attempts: u32,
  pub(crate) diagnostics: Vec<String>,
  pub(crate) error: Option<String>,
}

#[derive(Debug, Default)]
pub(crate) struct MozillaEngineExtractionOutcome {
  pub(crate) persistent_cookies: Vec<Cookie>,
  pub(crate) persistent_rows_seen: usize,
  pub(crate) persistent_rows_skipped: usize,
  pub(crate) persistent_acquisition_strategy: Option<sqlite::DatabaseAcquisitionStrategy>,
  pub(crate) persistent_acquisition_attempts: u32,
  /// Set only when the persistent source could not be read at all. A source
  /// that produced rows is never reported through this field, so a caller can
  /// distinguish total failure from partial success.
  pub(crate) persistent_error: Option<String>,
  /// Set when individual rows failed while the source itself was readable.
  pub(crate) persistent_row_error: Option<String>,
  pub(crate) session_sources: Vec<MozillaSessionSourceOutcome>,
}

/// Extract a Mozilla profile with the same authoritative session ordering as
/// `firefox_based`, retaining diagnostics which the legacy API intentionally
/// only logs. Missing session candidates are not outcomes: absence is normal.
pub(crate) fn query_cookies_engine_outcome(
  db_path: &Path,
  domains: Option<&[String]>,
) -> MozillaEngineExtractionOutcome {
  let mut outcome = MozillaEngineExtractionOutcome::default();
  match sqlite::with_browser_database(db_path.to_path_buf(), |connection| {
    query_persistent_cookies(connection, domains)
  }) {
    Ok(database) => {
      outcome.persistent_acquisition_strategy = Some(database.strategy());
      outcome.persistent_acquisition_attempts = database.attempts();
      let persistent = database.into_value();
      outcome.persistent_rows_seen = persistent.rows_seen;
      outcome.persistent_rows_skipped = persistent.rows_skipped;
      outcome.persistent_row_error = persistent.last_row_error.map(|error| format!("{error:#}"));
      outcome.persistent_cookies = persistent.cookies;
    }
    Err(error) => {
      if let Some(failure) = error.downcast_ref::<sqlite::BrowserDatabaseFailure>() {
        outcome.persistent_acquisition_strategy = failure.strategy;
        outcome.persistent_acquisition_attempts = failure.attempts;
      } else {
        outcome.persistent_acquisition_attempts = 1;
      }
      outcome.persistent_error = Some(format!("{error:#}"));
    }
  }

  let cookies_dir = db_path.parent().unwrap_or_else(|| Path::new(""));
  for (path, format) in session_candidates(cookies_dir) {
    match parse_session_candidate(&path, &format, domains) {
      Ok(success) => {
        let mut diagnostics = success.transient_errors;
        diagnostics.extend(success.parsed.diagnostics);
        outcome.session_sources.push(MozillaSessionSourceOutcome {
          path,
          format: format.format_id(),
          selected: true,
          cookies: success.parsed.cookies,
          rows_seen: success.parsed.rows_seen,
          rows_skipped: success.parsed.rows_skipped,
          acquisition_attempts: success.attempts,
          diagnostics,
          error: None,
        });
        break;
      }
      // Section 7 makes a missing candidate silent, and a candidate whose final
      // state is "gone" is missing however it got there. Its retry diagnostics
      // are therefore dropped on purpose: a vanished candidate is not a source.
      Err(failure) if is_missing_session_file(&failure.error) => {}
      Err(failure) => outcome.session_sources.push(MozillaSessionSourceOutcome {
        path,
        format: format.format_id(),
        selected: false,
        cookies: Vec::new(),
        rows_seen: 0,
        rows_skipped: 0,
        acquisition_attempts: failure.attempts,
        diagnostics: failure.transient_errors,
        error: Some(format!("{:#}", failure.error)),
      }),
    }
  }
  outcome
}

fn session_candidates(cookies_dir: &Path) -> [(PathBuf, SessionStoreFormat); 5] {
  [
    (
      cookies_dir.join("sessionstore-backups/recovery.jsonlz4"),
      SessionStoreFormat::JsonLz4,
    ),
    (
      cookies_dir.join("sessionstore-backups/recovery.baklz4"),
      SessionStoreFormat::JsonLz4,
    ),
    (
      cookies_dir.join("sessionstore.jsonlz4"),
      SessionStoreFormat::JsonLz4,
    ),
    (
      cookies_dir.join("sessionstore.js"),
      SessionStoreFormat::LegacyJson,
    ),
    (
      cookies_dir.join("sessionstore-backups/previous.jsonlz4"),
      SessionStoreFormat::JsonLz4,
    ),
  ]
}

fn get_authoritative_session_cookies(
  domains: Option<Vec<String>>,
  cookies_dir: &Path,
) -> Vec<Cookie> {
  for (path, format) in session_candidates(cookies_dir) {
    match parse_session_candidate(&path, &format, domains.as_deref()) {
      Ok(success) => return success.parsed.cookies,
      Err(failure) if is_missing_session_file(&failure.error) => continue,
      Err(failure) => log::warn!(
        "Failed to parse Firefox session store {:?}: {}",
        path,
        failure.error
      ),
    }
  }

  Vec::new()
}

fn parse_session_candidate(
  path: &Path,
  format: &SessionStoreFormat,
  domains: Option<&[String]>,
) -> std::result::Result<SessionCandidateSuccess, SessionCandidateFailure> {
  parse_session_candidate_with(path, || match format {
    SessionStoreFormat::JsonLz4 => parse_session_cookies_lz4(path, domains),
    SessionStoreFormat::LegacyJson => parse_legacy_session_cookies(path, domains),
  })
}

fn parse_session_candidate_with<F>(
  path: &Path,
  mut parse: F,
) -> std::result::Result<SessionCandidateSuccess, SessionCandidateFailure>
where
  F: FnMut() -> Result<SessionCookieParseOutcome>,
{
  let mut last_error = None;
  let mut attempts = 0;
  let mut transient_errors = Vec::new();
  for attempt in 1..=SESSION_STORE_READ_ATTEMPTS {
    attempts = attempt as u32;
    match parse() {
      Ok(parsed) => {
        return Ok(SessionCandidateSuccess {
          parsed,
          attempts,
          transient_errors,
        })
      }
      Err(error) if is_missing_session_file(&error) => {
        return Err(SessionCandidateFailure {
          error,
          attempts,
          transient_errors,
        })
      }
      Err(error) => {
        let diagnostic = format!("session acquisition/parse attempt {attempt} failed: {error:#}");
        if attempt < SESSION_STORE_READ_ATTEMPTS {
          log::debug!(
            "Retrying Firefox session store {} after {diagnostic}",
            path.display()
          );
          transient_errors.push(diagnostic);
        }
        last_error = Some(error);
      }
    }
  }

  Err(SessionCandidateFailure {
    error: last_error.expect("session store parser always attempts at least once"),
    attempts,
    transient_errors,
  })
}

fn is_missing_session_file(error: &anyhow::Error) -> bool {
  matches!(
    error.downcast_ref::<std::io::Error>(),
    Some(error) if error.kind() == std::io::ErrorKind::NotFound
  )
}

fn read_stable_session_file(path: &Path) -> Result<Vec<u8>> {
  let mut file = fs::File::open(path)?;
  let before = file.metadata()?;
  let mut bytes = Vec::new();
  file.read_to_end(&mut bytes)?;
  let after = file.metadata()?;

  let length_changed =
    before.len() != after.len() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) != after.len();
  let modified_changed = before.modified().ok() != after.modified().ok();
  if length_changed || modified_changed {
    bail!("Firefox session store changed while it was being read");
  }

  Ok(bytes)
}

#[cfg(test)]
pub fn get_session_cookies(
  domains: Option<Vec<String>>,
  cookies_dir: PathBuf,
) -> Result<Vec<Cookie>> {
  parse_legacy_session_cookies(&cookies_dir.join("sessionstore.js"), domains.as_deref())
    .map(|outcome| outcome.cookies)
}

fn record_session_cookie(
  outcome: &mut SessionCookieParseOutcome,
  json_cookie: &Value,
  location: &str,
  domains: Option<&[String]>,
) {
  let domain = json_cookie
    .get("host")
    .and_then(|value| value.as_str())
    .unwrap_or("");
  if !utils::some_domain_in_host(domains, domain) {
    return;
  }
  outcome.rows_seen += 1;
  match create_cookie(json_cookie) {
    Ok(cookie) => outcome.cookies.push(cookie),
    Err(error) => {
      outcome.rows_skipped += 1;
      if outcome.diagnostics.len() < MAX_SESSION_COOKIE_DIAGNOSTICS {
        outcome
          .diagnostics
          .push(format!("malformed session cookie at {location}: {error:#}"));
      }
    }
  }
}

fn parse_legacy_session_cookies(
  path: &Path,
  domains: Option<&[String]>,
) -> Result<SessionCookieParseOutcome> {
  let mut outcome = SessionCookieParseOutcome {
    cookies: Vec::new(),
    rows_seen: 0,
    rows_skipped: 0,
    diagnostics: Vec::new(),
  };
  let plain = String::from_utf8(read_stable_session_file(path)?)?;
  let json: Value = serde_json::from_str(&plain)?;
  let windows = json
    .get("windows")
    .ok_or(anyhow!("no windows in json"))?
    .as_array()
    .ok_or(anyhow!("windows are not array"))?;
  for (window_index, window) in windows.iter().enumerate() {
    let may_cookies_json = window.get("cookies");
    if let Some(cookies_json) = may_cookies_json {
      let cookies_json = cookies_json.as_array();
      if let Some(cookies_json) = cookies_json {
        for (cookie_index, json_cookie) in cookies_json.iter().enumerate() {
          record_session_cookie(
            &mut outcome,
            json_cookie,
            &format!("windows[{window_index}].cookies[{cookie_index}]"),
            domains,
          );
        }
      }
    }
  }
  Ok(outcome)
}

#[cfg(test)]
pub fn get_session_cookies_lz4(
  domains: Option<Vec<String>>,
  cookies_dir: PathBuf,
) -> Result<Vec<Cookie>> {
  parse_session_cookies_lz4(
    &cookies_dir.join("sessionstore-backups/recovery.jsonlz4"),
    domains.as_deref(),
  )
  .map(|outcome| outcome.cookies)
}

fn parse_session_cookies_lz4(
  path: &Path,
  domains: Option<&[String]>,
) -> Result<SessionCookieParseOutcome> {
  let mut outcome = SessionCookieParseOutcome {
    cookies: Vec::new(),
    rows_seen: 0,
    rows_skipped: 0,
    diagnostics: Vec::new(),
  };
  let compressed = read_stable_session_file(path)?;
  if !compressed.starts_with(b"mozLz40\0") {
    bail!("Invalid mozLz40 header");
  }
  let compressed = compressed
    .get(8..)
    .ok_or_else(|| anyhow!("Invalid compressed length"))?;
  let decompressed = decompress_size_prepended(compressed)?;
  let plain = String::from_utf8(decompressed)?;
  let json: Value = serde_json::from_str(&plain)?;
  let Some(cookies_json) = json.get("cookies") else {
    return Ok(outcome);
  };
  let cookies_json = cookies_json
    .as_array()
    .ok_or(anyhow!("cookies is not list"))?;
  for (cookie_index, json_cookie) in cookies_json.iter().enumerate() {
    record_session_cookie(
      &mut outcome,
      json_cookie,
      &format!("cookies[{cookie_index}]"),
      domains,
    );
  }
  Ok(outcome)
}

pub fn create_cookie(json_cookie: &Value) -> Result<Cookie> {
  let host = json_cookie
    .get("host")
    .and_then(|v| v.as_str())
    .unwrap_or("");
  let path = json_cookie
    .get("path")
    .and_then(|v| v.as_str())
    .unwrap_or("/");
  let secure = json_cookie
    .get("secure")
    .and_then(|v| v.as_bool())
    .unwrap_or(false);
  let name = json_cookie
    .get("name")
    .and_then(|v| v.as_str())
    .ok_or_else(|| anyhow!("session cookie has no name"))?;
  let value = json_cookie
    .get("value")
    .and_then(|v| v.as_str())
    .ok_or_else(|| anyhow!("session cookie has no value"))?;
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
    .unwrap_or(SAME_SITE_UNSPECIFIED);

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
  Ok(profiles_from_ini(&conf, profiles_path))
}

/// [`list_profiles`] for callers that already hold the file's contents, so
/// discovery can route the read through its injected filesystem seam instead of
/// reaching for the real one.
pub(crate) fn list_profiles_from_str(
  contents: &str,
  profiles_path: &Path,
) -> Result<Vec<MozillaProfile>> {
  let conf = Ini::load_from_str_opt(
    contents,
    ParseOption {
      enabled_escape: false,
      ..Default::default()
    },
  )?;
  Ok(profiles_from_ini(&conf, profiles_path))
}

fn profiles_from_ini(conf: &Ini, profiles_path: &Path) -> Vec<MozillaProfile> {
  let base = profiles_path.parent().unwrap_or_else(|| Path::new(""));
  let sections = profile_sections(conf);
  let installs = install_defaults(conf);
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

  profiles
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
  use lz4_flex::block::compress_prepend_size;
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

  fn write_session_jsonlz4(path: &Path, cookies: Value) {
    if let Some(parent) = path.parent() {
      std::fs::create_dir_all(parent).expect("create sessionstore directory");
    }
    let json = serde_json::json!({ "cookies": cookies }).to_string();
    let mut encoded = b"mozLz40\0".to_vec();
    encoded.extend(compress_prepend_size(json.as_bytes()));
    std::fs::write(path, encoded).expect("write sessionstore fixture");
  }

  fn session_cookie(name: &str) -> Value {
    serde_json::json!({
      "host": ".example.com",
      "path": "/",
      "name": name,
      "value": "fixture"
    })
  }

  #[test]
  fn firefox_based_errors_when_every_row_fails_to_decode() {
    let dir = unique_tmpdir("ff-all-rows-bad");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(&db, &[]);
    // The name is required identity data, so a row whose name cannot decode
    // must not turn a total extraction failure into an empty success.
    let conn = rusqlite::Connection::open(&db).expect("open writable sqlite");
    conn
      .execute(
        "INSERT INTO moz_cookies (host, path, isSecure, expiry, name, value, isHttpOnly, sameSite)
          VALUES ('.example.com', '/', 1, 0, X'DEADBEEF', 'v', 1, 0)",
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
  fn engine_outcome_counts_each_malformed_persistent_row() {
    let dir = unique_tmpdir("ff-engine-row-counts");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(
      &db,
      &[(".example.com", "/", false, 0, "kept", "value", false, 0)],
    );
    let conn = rusqlite::Connection::open(&db).expect("open writable sqlite");
    conn
      .execute(
        "INSERT INTO moz_cookies (host, path, isSecure, expiry, name, value, isHttpOnly, sameSite)
          VALUES ('.example.com', '/', 0, 0, X'DEADBEEF', 'discarded', 0, 0)",
        [],
      )
      .expect("insert malformed cookie");
    drop(conn);

    let outcome = query_cookies_engine_outcome(&db, None);
    assert_eq!(outcome.persistent_rows_seen, 2);
    assert_eq!(outcome.persistent_rows_skipped, 1);
    assert_eq!(outcome.persistent_cookies.len(), 1);
    assert_eq!(
      outcome.persistent_acquisition_strategy,
      Some(sqlite::DatabaseAcquisitionStrategy::LiveReadOnly)
    );
    assert_eq!(outcome.persistent_acquisition_attempts, 1);
    // A rejected row is a partial success: the source itself was readable, so
    // only the row-level field is set.
    assert!(outcome.persistent_row_error.is_some());
    assert!(outcome.persistent_error.is_none());
  }

  #[test]
  fn engine_outcome_separates_total_failure_from_a_rejected_row() {
    let dir = unique_tmpdir("ff-engine-total-failure");
    let db = dir.join("cookies.sqlite");
    std::fs::create_dir_all(&dir).expect("create profile dir");
    std::fs::write(&db, b"not a sqlite database").expect("write unreadable db");

    let outcome = query_cookies_engine_outcome(&db, None);
    assert!(outcome.persistent_error.is_some());
    assert!(outcome.persistent_row_error.is_none());
    assert!(outcome.persistent_cookies.is_empty());
  }

  #[test]
  fn engine_outcome_retains_invalid_session_candidates_and_selects_first_valid_one() {
    let dir = unique_tmpdir("ff-engine-session-outcomes");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(&db, &[]);
    let invalid = dir.join("sessionstore-backups/recovery.jsonlz4");
    std::fs::create_dir_all(invalid.parent().expect("session parent")).expect("create parent");
    std::fs::write(&invalid, b"not a compressed session store").expect("write invalid session");
    let selected = dir.join("sessionstore-backups/recovery.baklz4");
    write_session_jsonlz4(&selected, serde_json::json!([session_cookie("recovered")]));

    let outcome = query_cookies_engine_outcome(&db, None);
    assert_eq!(outcome.session_sources.len(), 2);
    assert_eq!(outcome.session_sources[0].path, invalid);
    assert_eq!(outcome.session_sources[0].format, "firefox_session_jsonlz4");
    assert!(!outcome.session_sources[0].selected);
    assert!(outcome.session_sources[0].error.is_some());
    assert_eq!(outcome.session_sources[1].path, selected);
    assert_eq!(outcome.session_sources[1].format, "firefox_session_jsonlz4");
    assert!(outcome.session_sources[1].selected);
    assert_eq!(outcome.session_sources[1].cookies[0].name, "recovered");
  }

  #[test]
  fn engine_outcome_counts_and_bounds_malformed_session_cookies() {
    let dir = unique_tmpdir("ff-engine-session-row-counts");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(&db, &[]);
    let malformed = (0..MAX_SESSION_COOKIE_DIAGNOSTICS + 3)
      .map(|index| {
        serde_json::json!({
          "host": ".example.com",
          "path": "/",
          "name": format!("missing-value-{index}")
        })
      })
      .collect::<Vec<_>>();
    write_session_jsonlz4(
      &dir.join("sessionstore-backups/recovery.jsonlz4"),
      serde_json::Value::Array(malformed),
    );

    let outcome = query_cookies_engine_outcome(&db, None);
    let source = &outcome.session_sources[0];
    assert!(source.selected);
    assert_eq!(source.rows_seen, MAX_SESSION_COOKIE_DIAGNOSTICS + 3);
    assert_eq!(source.rows_skipped, MAX_SESSION_COOKIE_DIAGNOSTICS + 3);
    assert!(source.cookies.is_empty());
    assert_eq!(source.diagnostics.len(), MAX_SESSION_COOKIE_DIAGNOSTICS);
    assert!(source.diagnostics[0].contains("cookies[0]"));
    assert!(source.diagnostics[0].contains("has no value"));
  }

  #[test]
  fn engine_outcome_labels_legacy_json_and_counts_malformed_rows() {
    let dir = unique_tmpdir("ff-engine-legacy-row-counts");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(&db, &[]);
    std::fs::write(
      dir.join("sessionstore.js"),
      r#"{"windows":[{"cookies":[{"host":".example.com","name":"bad"},{"host":".example.com","name":"good","value":"v"}]}]}"#,
    )
    .expect("write legacy session store");

    let outcome = query_cookies_engine_outcome(&db, None);
    let source = &outcome.session_sources[0];
    assert_eq!(source.format, "firefox_session_json");
    assert_eq!(source.rows_seen, 2);
    assert_eq!(source.rows_skipped, 1);
    assert_eq!(source.cookies.len(), 1);
    assert_eq!(source.diagnostics.len(), 1);
  }

  #[test]
  fn legacy_json_row_diagnostics_are_bounded_like_the_lz4_path() {
    let dir = unique_tmpdir("ff-engine-legacy-diagnostic-bound");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(&db, &[]);
    let malformed = (0..MAX_SESSION_COOKIE_DIAGNOSTICS + 3)
      .map(|index| format!(r#"{{"host":".example.com","name":"bad-{index}"}}"#))
      .collect::<Vec<_>>()
      .join(",");
    std::fs::write(
      dir.join("sessionstore.js"),
      format!(r#"{{"windows":[{{"cookies":[{malformed}]}}]}}"#),
    )
    .expect("write legacy session store");

    let outcome = query_cookies_engine_outcome(&db, None);
    let source = &outcome.session_sources[0];
    assert_eq!(source.format, SESSION_JSON_FORMAT_ID);
    assert_eq!(source.rows_seen, MAX_SESSION_COOKIE_DIAGNOSTICS + 3);
    assert_eq!(source.rows_skipped, MAX_SESSION_COOKIE_DIAGNOSTICS + 3);
    assert!(source.cookies.is_empty());
    assert_eq!(source.diagnostics.len(), MAX_SESSION_COOKIE_DIAGNOSTICS);
  }

  #[test]
  fn failed_session_candidate_retains_its_retry_diagnostics() {
    let dir = unique_tmpdir("ff-engine-failed-retry-diagnostics");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(&db, &[]);
    std::fs::create_dir_all(dir.join("sessionstore-backups")).expect("create session dir");
    std::fs::write(
      dir.join("sessionstore-backups/recovery.jsonlz4"),
      b"not a valid lz4 session store",
    )
    .expect("write invalid session candidate");

    let outcome = query_cookies_engine_outcome(&db, None);
    let source = &outcome.session_sources[0];
    assert!(!source.selected);
    assert!(source.error.is_some());
    assert_eq!(
      source.acquisition_attempts,
      SESSION_STORE_READ_ATTEMPTS as u32
    );
    // Every attempt before the last one is retained; the final failure is the
    // source error rather than a duplicate diagnostic.
    assert_eq!(source.diagnostics.len(), SESSION_STORE_READ_ATTEMPTS - 1);
    assert!(source.diagnostics[0].contains("attempt 1"));
  }

  #[test]
  fn failure_attempt_counts_reflect_early_exits_not_the_retry_ceiling() {
    // Every *reported* failure exhausts the retry budget, so an outcome's
    // attempt count can never distinguish these. Pin them at the struct level
    // instead, where the early-exit paths are observable.
    let missing_immediately = parse_session_candidate_with(Path::new("recovery.jsonlz4"), || {
      Err(std::io::Error::from(std::io::ErrorKind::NotFound).into())
    })
    .expect_err("a missing candidate fails");
    // The discriminating case: stopping on the first attempt must report one
    // attempt, not the SESSION_STORE_READ_ATTEMPTS ceiling.
    assert_eq!(missing_immediately.attempts, 1);
    assert!(missing_immediately.transient_errors.is_empty());

    let mut attempts = 0;
    let vanished_after_retry = parse_session_candidate_with(Path::new("recovery.jsonlz4"), || {
      attempts += 1;
      if attempts == 1 {
        bail!("Firefox session store changed while it was being read")
      }
      Err(std::io::Error::from(std::io::ErrorKind::NotFound).into())
    })
    .expect_err("a vanished candidate fails");
    assert!(is_missing_session_file(&vanished_after_retry.error));
    assert_eq!(vanished_after_retry.attempts, 2);
    // The attempt-1 diagnostic survives on the failure path, even though
    // Section 7 means nothing downstream consumes it for a vanished candidate.
    assert_eq!(vanished_after_retry.transient_errors.len(), 1);
    assert!(vanished_after_retry.transient_errors[0].contains("attempt 1"));
  }

  #[test]
  fn a_candidate_that_vanishes_after_a_transient_failure_stays_silent() {
    // The deliberate counterpart of the test above: Section 7 keeps a missing
    // candidate silent, so nothing about it reaches the outcome.
    let dir = unique_tmpdir("ff-engine-vanished-candidate");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(&db, &[]);

    let outcome = query_cookies_engine_outcome(&db, None);
    assert!(outcome.session_sources.is_empty());
  }

  #[test]
  fn successful_session_retry_retains_attempt_and_transient_diagnostic() {
    let mut attempts = 0;
    let success = parse_session_candidate_with(Path::new("recovery.jsonlz4"), || {
      attempts += 1;
      if attempts == 1 {
        bail!("Firefox session store changed while it was being read")
      }
      Ok(SessionCookieParseOutcome {
        cookies: Vec::new(),
        rows_seen: 0,
        rows_skipped: 0,
        diagnostics: Vec::new(),
      })
    })
    .expect("second attempt succeeds");

    assert_eq!(success.attempts, 2);
    assert_eq!(success.transient_errors.len(), 1);
    assert!(success.transient_errors[0].contains("attempt 1"));
    assert!(success.transient_errors[0].contains("changed while it was being read"));
  }

  #[test]
  fn engine_outcome_keeps_missing_session_candidates_silent() {
    let dir = unique_tmpdir("ff-engine-missing-session");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(&db, &[]);

    let outcome = query_cookies_engine_outcome(&db, None);
    assert!(outcome.persistent_error.is_none());
    assert!(outcome.session_sources.is_empty());
  }

  #[test]
  fn firefox_based_defaults_null_and_out_of_range_metadata() {
    let dir = unique_tmpdir("ff-null-metadata");
    let db = dir.join("cookies.sqlite");
    let conn = rusqlite::Connection::open(&db).expect("open writable sqlite");
    conn
      .execute(
        "CREATE TABLE moz_cookies (
          host TEXT,
          path TEXT,
          isSecure INTEGER,
          expiry INTEGER,
          name TEXT,
          value TEXT,
          isHttpOnly INTEGER,
          sameSite INTEGER
        )",
        [],
      )
      .expect("create table");
    conn
      .execute(
        "INSERT INTO moz_cookies VALUES (NULL, NULL, NULL, -1, 'kept', 'value', NULL, NULL)",
        [],
      )
      .expect("insert cookie with missing metadata");
    conn
      .execute(
        "INSERT INTO moz_cookies VALUES ('.example.com', '/', 0, 0, NULL, 'value', 0, 0)",
        [],
      )
      .expect("insert cookie without name");
    conn
      .execute(
        "INSERT INTO moz_cookies VALUES ('.example.com', '/', 0, 0, 'missing-value', NULL, 0, 0)",
        [],
      )
      .expect("insert cookie without value");
    drop(conn);

    let cookies = firefox_based(db, None).expect("metadata defaults keep usable cookie");
    assert_eq!(cookies.len(), 1, "{cookies:?}");
    let cookie = &cookies[0];
    assert_eq!(cookie.name, "kept");
    assert_eq!(cookie.value, "value");
    assert_eq!(cookie.domain, "");
    assert_eq!(cookie.path, "/");
    assert!(!cookie.secure);
    assert!(!cookie.http_only);
    assert_eq!(cookie.expires, None);
    assert_eq!(cookie.same_site, SAME_SITE_UNSPECIFIED);
  }

  #[test]
  fn firefox_based_reads_clean_shutdown_sessionstore() {
    let dir = unique_tmpdir("ff-clean-sessionstore");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(&db, &[]);
    write_session_jsonlz4(
      &dir.join("sessionstore.jsonlz4"),
      serde_json::json!([session_cookie("clean-shutdown")]),
    );

    let cookies = firefox_based(db, None).expect("read clean-shutdown session state");
    assert_eq!(cookies.len(), 1, "{cookies:?}");
    assert_eq!(cookies[0].name, "clean-shutdown");
  }

  #[test]
  fn firefox_sessionstore_uses_first_valid_candidate_without_merging_stale_state() {
    let dir = unique_tmpdir("ff-sessionstore-precedence");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(&db, &[]);
    let recovery = dir.join("sessionstore-backups/recovery.jsonlz4");
    let recovery_backup = dir.join("sessionstore-backups/recovery.baklz4");
    let clean = dir.join("sessionstore.jsonlz4");
    let previous = dir.join("sessionstore-backups/previous.jsonlz4");
    write_session_jsonlz4(
      &recovery,
      serde_json::json!([session_cookie("live-recovery")]),
    );
    write_session_jsonlz4(
      &recovery_backup,
      serde_json::json!([session_cookie("live-recovery-backup")]),
    );
    write_session_jsonlz4(
      &clean,
      serde_json::json!([session_cookie("clean-shutdown")]),
    );
    write_session_jsonlz4(
      &previous,
      serde_json::json!([session_cookie("stale-previous")]),
    );

    let cookies = firefox_based(db.clone(), None).expect("read live recovery");
    assert_eq!(cookies.len(), 1, "session candidates must not be merged");
    assert_eq!(cookies[0].name, "live-recovery");

    std::fs::write(&recovery, b"mozLz40\0invalid").expect("corrupt recovery fixture");
    let cookies = firefox_based(db.clone(), None).expect("fall back to recovery backup");
    assert_eq!(
      cookies.len(),
      1,
      "older lifecycle tiers must remain unselected"
    );
    assert_eq!(cookies[0].name, "live-recovery-backup");

    std::fs::write(&recovery_backup, b"mozLz40\0invalid").expect("corrupt recovery backup fixture");
    let cookies = firefox_based(db.clone(), None).expect("fall back to clean shutdown");
    assert_eq!(cookies.len(), 1, "stale state must remain unselected");
    assert_eq!(cookies[0].name, "clean-shutdown");

    std::fs::write(&clean, b"mozLz40\0invalid").expect("corrupt clean fixture");
    let cookies = firefox_based(db, None).expect("fall back to previous session");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "stale-previous");
  }

  #[test]
  fn valid_empty_recovery_does_not_resurrect_stale_session_cookies() {
    let dir = unique_tmpdir("ff-sessionstore-empty-current");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(&db, &[]);
    write_session_jsonlz4(
      &dir.join("sessionstore-backups/recovery.jsonlz4"),
      serde_json::json!([]),
    );
    write_session_jsonlz4(
      &dir.join("sessionstore.jsonlz4"),
      serde_json::json!([session_cookie("stale-clean-copy")]),
    );

    let cookies = firefox_based(db, None).expect("valid empty state is authoritative");
    assert!(cookies.is_empty(), "{cookies:?}");
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

    let mut cookies = firefox_based(db.clone(), None).expect("decode");

    cookies.sort_by(|a, b| a.name.cmp(&b.name));
    let names: Vec<_> = cookies.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["checkpointed", "in-wal"], "{cookies:?}");
    let in_wal = cookies.iter().find(|c| c.name == "in-wal").expect("in-wal");
    assert_eq!(
      in_wal.value, "fresh",
      "the WAL row must decode, not just appear"
    );

    let outcome = query_cookies_engine_outcome(&db, None);
    assert_eq!(
      outcome.persistent_acquisition_strategy,
      Some(sqlite::DatabaseAcquisitionStrategy::VerifiedWalSnapshot)
    );
    assert_eq!(outcome.persistent_acquisition_attempts, 1);
    assert_eq!(outcome.persistent_cookies.len(), 2);
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
  fn firefox_based_preserves_legacy_substring_domain_filtering() {
    let dir = unique_tmpdir("ff-domain-filter-substring");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(
      &db,
      &[
        (".example.com", "/", false, 0, "boundary", "yes", false, 0),
        (
          "notexample.com",
          "/",
          false,
          0,
          "prefix",
          "legacy",
          false,
          0,
        ),
        (
          "example.com.evil",
          "/",
          false,
          0,
          "suffix",
          "legacy",
          false,
          0,
        ),
        ("other.test", "/", false, 0, "unrelated", "no", false, 0),
      ],
    );

    let mut cookies = firefox_based(db, Some(vec!["example.com".to_string()])).expect("decode");
    cookies.sort_by(|a, b| a.name.cmp(&b.name));
    let names: Vec<_> = cookies.iter().map(|cookie| cookie.name.as_str()).collect();
    assert_eq!(
      names,
      vec!["boundary", "prefix", "suffix"],
      "persistent Firefox filtering is the legacy SQL LIKE %domain% contract"
    );
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
  fn firefox_based_percent_domain_is_not_a_wildcard() {
    let dir = unique_tmpdir("ff-domain-filter-percent");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(
      &db,
      &[
        (".example.com", "/", false, 0, "keep", "yes", false, 0),
        ("other.test", "/", false, 0, "drop", "no", false, 0),
      ],
    );

    let cookies = firefox_based(db, Some(vec!["%".to_string()])).expect("decode");
    assert!(
      cookies.is_empty(),
      "a literal '%' domain must not match every host: {:?}",
      cookies
    );
  }

  #[test]
  fn firefox_based_underscore_domain_is_not_a_wildcard() {
    let dir = unique_tmpdir("ff-domain-filter-underscore");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(
      &db,
      &[
        (".example.com", "/", false, 0, "keep", "yes", false, 0),
        ("a.test", "/", false, 0, "drop", "no", false, 0),
      ],
    );

    let cookies = firefox_based(db, Some(vec!["_".to_string()])).expect("decode");
    assert!(
      cookies.is_empty(),
      "a literal '_' domain must not match every single-character host: {:?}",
      cookies
    );
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
  fn get_session_cookies_requires_a_domain_label_boundary() {
    let dir = unique_tmpdir("ff-session-domain-boundary");
    let cookie = |host: &str, name: &str| {
      serde_json::json!({
        "host": host,
        "path": "/",
        "name": name,
        "value": "fixture"
      })
    };
    let session = serde_json::json!({
      "windows": [{
        "cookies": [
          cookie(".example.com", "boundary"),
          cookie("sub.example.com", "subdomain"),
          cookie("notexample.com", "prefix"),
          cookie("example.com.evil", "suffix")
        ]
      }]
    });
    std::fs::write(dir.join("sessionstore.js"), session.to_string()).expect("session fixture");

    let mut cookies =
      get_session_cookies(Some(vec!["example.com".to_string()]), dir).expect("decode");
    cookies.sort_by(|a, b| a.name.cmp(&b.name));
    let names: Vec<_> = cookies.iter().map(|cookie| cookie.name.as_str()).collect();
    assert_eq!(names, vec!["boundary", "subdomain"]);
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

    // Row 2: Negative expiry is out-of-range metadata and defaults to None.
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
    assert_eq!(
      names,
      vec!["bad_expiry", "valid1", "valid2"],
      "{:?}",
      cookies
    );
    assert_eq!(cookies[0].expires, None);
  }
}
