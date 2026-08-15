use crate::common::{date, enums::*, sqlite, utils};
use anyhow::{anyhow, bail, Result};
use ini::{Ini, ParseOption};
use lz4_flex::block::decompress_into;
use serde_json::Value;
use std::{
  fs,
  io::Read,
  path::{Path, PathBuf},
};

// Firefox 142 migrated schema 15 to 16 by multiplying persistent cookie
// expiry values by 1000 (https://bugzilla.mozilla.org/show_bug.cgi?id=1972757).
const FIREFOX_MILLISECOND_EXPIRY_SCHEMA_VERSION: u32 = 16;

// Session state is untrusted profile data. Keep both the on-disk read and the
// mozLz4-advertised output below a size large enough for real Firefox profiles
// while preventing one corrupt four-byte size prefix from requesting gigabytes.
const MAX_SESSION_STORE_BYTES: usize = 64 * 1024 * 1024;

// Sessionstore has no schema/version field that identifies an expiry unit, and
// its unit cannot be inferred from cookies.sqlite: an observed Firefox 141
// profile used seconds in schema-15 SQLite rows while its recovery.jsonlz4 used
// milliseconds. Values through year 2286 remain plausible Unix seconds; values
// from 10^12 through the same upper instant are plausible Unix milliseconds.
// The scale gap is deliberately rejected instead of guessed. Missing/zero
// expiry is always a genuine session cookie.
const MAX_PLAUSIBLE_SESSION_EXPIRY_SECONDS: u64 = 9_999_999_999;
const MIN_PLAUSIBLE_SESSION_EXPIRY_MILLISECONDS: u64 = 1_000_000_000_000;
const MAX_PLAUSIBLE_SESSION_EXPIRY_MILLISECONDS: u64 =
  MAX_PLAUSIBLE_SESSION_EXPIRY_SECONDS * 1000 + 999;

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
  match get_authoritative_session_outcome(domains.as_deref(), &parent_path) {
    Ok(session) => cookies.extend(session.cookies),
    Err(error) if cookies.is_empty() => return Err(error),
    Err(error) => {
      log::warn!("All Firefox session stores failed; returning persistent cookies only: {error:#}")
    }
  }
  if cookies.is_empty() {
    if let Some(error) = persistent.last_row_error {
      return Err(error);
    }
  }
  Ok(cookies)
}

/// Returns cookies from a Mozilla profile with container and origin attributes
/// preserved.
pub fn firefox_based_detailed(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
) -> Result<Vec<DetailedCookie>> {
  let database = sqlite::with_browser_database(db_path.clone(), |connection| {
    query_persistent_cookies_mode(connection, domains.as_deref(), true)
  })?;
  let persistent = database.into_value();
  let mut cookies = persistent.detailed_cookies;

  let parent_path = db_path.parent().unwrap_or(Path::new("")).to_path_buf();
  match get_authoritative_session_outcome(domains.as_deref(), &parent_path) {
    Ok(session) => cookies.extend(session.detailed_cookies),
    Err(error) if cookies.is_empty() => return Err(error),
    Err(error) => log::warn!(
      "All Firefox session stores failed; returning detailed persistent cookies only: {error:#}"
    ),
  }
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
  detailed_cookies: Vec<DetailedCookie>,
  rows_seen: usize,
  rows_skipped: usize,
  last_row_error: Option<anyhow::Error>,
}

fn mozilla_schema_version(connection: &rusqlite::Connection) -> Result<u32> {
  let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
  u32::try_from(version).map_err(|_| anyhow!("Invalid Firefox cookie schema version {version}"))
}

fn persistent_cookie_expiry(timestamp: u64, schema_version: u32) -> Option<u64> {
  let timestamp = if schema_version >= FIREFOX_MILLISECOND_EXPIRY_SCHEMA_VERSION {
    timestamp / 1000
  } else {
    timestamp
  };
  date::mozilla_timestamp(timestamp)
}

fn query_persistent_cookies(
  connection: &rusqlite::Connection,
  domains: Option<&[String]>,
) -> Result<PersistentCookieQuery> {
  query_persistent_cookies_mode(connection, domains, false)
}

fn query_persistent_cookies_mode(
  connection: &rusqlite::Connection,
  domains: Option<&[String]>,
  detailed: bool,
) -> Result<PersistentCookieQuery> {
  let schema_version = mozilla_schema_version(connection)?;
  let columns = sqlite_table_columns(connection, "moz_cookies")?;
  let origin_attributes = if columns.contains("originAttributes") {
    "originAttributes"
  } else {
    "NULL AS originAttributes"
  };
  let mut query = format!(
    "SELECT host, path, isSecure, expiry, name, value, isHttpOnly, sameSite, \
     {origin_attributes} FROM moz_cookies "
  );

  let domain_filters: Vec<String> = domains
    .map(|domains| {
      domains
        .iter()
        .filter_map(|domain| utils::normalized_domain_for_match(domain))
        .map(|domain| format!("%{}%", escape_like_pattern(domain)))
        .collect()
    })
    .unwrap_or_default();

  if domains.is_some() {
    if domain_filters.is_empty() {
      query += "WHERE 0";
    } else {
      let predicates = (1..=domain_filters.len())
        .map(|index| format!("host LIKE ?{index} ESCAPE '\\'"))
        .collect::<Vec<_>>()
        .join(" OR ");
      query += &format!("WHERE ({predicates})");
    }
  }

  query += ";";

  let mut cookies: Vec<Cookie> = vec![];
  let mut detailed_cookies: Vec<DetailedCookie> = vec![];
  let mut last_row_error: Option<anyhow::Error> = None;
  let mut rows_seen = 0;
  let mut rows_skipped = 0;
  let mut stmt = connection.prepare(query.as_str())?;
  let mut rows = stmt.query(rusqlite::params_from_iter(domain_filters.iter()))?;

  while let Some(row) = rows.next()? {
    macro_rules! optional_column {
      ($index:expr, $name:literal, $type:ty, $default:expr) => {
        match row.get::<_, Option<$type>>($index) {
          Ok(value) => value.unwrap_or_else($default),
          Err(error) => {
            log::warn!("Failed to read {} from Firefox cookie row: {error}", $name);
            last_row_error = Some(anyhow!(
              "failed to read {} from Firefox cookie row: {error}",
              $name
            ));
            rows_skipped += 1;
            continue;
          }
        }
      };
    }

    let host = match row.get::<_, Option<String>>(0) {
      Ok(host) => host.unwrap_or_default(),
      Err(error) => {
        log::warn!("Failed to read host from Firefox cookie row: {error}");
        last_row_error = Some(anyhow!(
          "failed to read host from Firefox cookie row: {error}"
        ));
        rows_seen += 1;
        rows_skipped += 1;
        continue;
      }
    };
    if !utils::some_domain_in_host(domains, &host) {
      continue;
    }
    rows_seen += 1;
    let path = optional_column!(1, "path", String, || "/".to_string());
    let is_secure = optional_column!(2, "isSecure", bool, || false);
    let expiry = optional_column!(3, "expiry", i64, || 0);
    let expires = Some(expiry)
      .and_then(|value| u64::try_from(value).ok())
      .and_then(|value| persistent_cookie_expiry(value, schema_version));

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
    let http_only = optional_column!(6, "isHttpOnly", bool, || false);
    let same_site = optional_column!(7, "sameSite", i64, || SAME_SITE_UNSPECIFIED);
    let cookie = Cookie {
      domain: host,
      path,
      secure: is_secure,
      expires,
      name,
      value,
      http_only,
      same_site,
    };
    if detailed {
      let origin_attributes = match row.get::<_, Option<String>>(8) {
        Ok(origin_attributes) => origin_attributes,
        Err(error) => {
          log::warn!("Failed to read originAttributes from Firefox cookie row: {error}");
          last_row_error = Some(anyhow!(
            "failed to read originAttributes from Firefox cookie row: {error}"
          ));
          rows_skipped += 1;
          continue;
        }
      };
      detailed_cookies.push(DetailedCookie {
        cookie,
        context: firefox_cookie_context(origin_attributes),
      });
    } else {
      cookies.push(cookie);
    }
  }

  Ok(PersistentCookieQuery {
    cookies,
    detailed_cookies,
    rows_seen,
    rows_skipped,
    last_row_error,
  })
}

fn sqlite_table_columns(
  connection: &rusqlite::Connection,
  table: &str,
) -> Result<std::collections::HashSet<String>> {
  let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
  let columns = statement
    .query_map([], |row| row.get::<_, String>(1))?
    .collect::<std::result::Result<std::collections::HashSet<_>, _>>()?;
  Ok(columns)
}

fn firefox_cookie_context(origin_attributes: Option<String>) -> CookieContext {
  let mut context = CookieContext {
    origin_attributes,
    ..CookieContext::default()
  };
  let Some(attributes) = context.origin_attributes.as_deref() else {
    return context;
  };
  for (name, value) in url::form_urlencoded::parse(
    attributes
      .strip_prefix('^')
      .unwrap_or(attributes)
      .as_bytes(),
  ) {
    match name.as_ref() {
      "userContextId" => context.user_context_id = value.parse().ok(),
      "partitionKey" => context.partition_key = Some(value.into_owned()),
      "privateBrowsingId" => context.private_browsing_id = value.parse().ok(),
      _ => {}
    }
  }
  context
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionStoreFormat {
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
  pub(crate) fn format_id(self) -> &'static str {
    match self {
      Self::JsonLz4 => SESSION_JSONLZ4_FORMAT_ID,
      Self::LegacyJson => SESSION_JSON_FORMAT_ID,
    }
  }
}

/// Section 7 session candidates in authoritative order, as profile-relative
/// paths. This is the single source of truth: extraction attempts them in this
/// order and registry discovery lists them in this order, so a candidate can
/// never be added to one and missed by the other.
pub(crate) const SESSION_CANDIDATES: [(&str, SessionStoreFormat); 5] = [
  (
    "sessionstore-backups/recovery.jsonlz4",
    SessionStoreFormat::JsonLz4,
  ),
  (
    "sessionstore-backups/recovery.baklz4",
    SessionStoreFormat::JsonLz4,
  ),
  ("sessionstore.jsonlz4", SessionStoreFormat::JsonLz4),
  ("sessionstore.js", SessionStoreFormat::LegacyJson),
  (
    "sessionstore-backups/previous.jsonlz4",
    SessionStoreFormat::JsonLz4,
  ),
];

/// Declared precedence of a session candidate at `index` in
/// [`SESSION_CANDIDATES`], so reports order attempted candidates by declaration
/// rather than by which ones happened to exist.
pub(crate) fn session_candidate_precedence(index: usize) -> u16 {
  SESSION_CANDIDATE_PRECEDENCE_STEP.saturating_mul(index as u16 + 1)
}

const SESSION_STORE_READ_ATTEMPTS: usize = 2;
const SESSION_CANDIDATE_PRECEDENCE_STEP: u16 = 10;
const MAX_SESSION_COOKIE_DIAGNOSTICS: usize = 8;

#[derive(Debug)]
struct SessionCookieParseOutcome {
  cookies: Vec<Cookie>,
  detailed_cookies: Vec<DetailedCookie>,
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
  /// Declared candidate precedence from [`session_candidates`], retained so a
  /// report orders attempted candidates by declaration rather than by which
  /// ones happened to exist.
  pub(crate) precedence: u16,
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
  /// Acquisition, schema validation, or the query did not complete, so the
  /// source failed outright. A source that produced rows is never reported
  /// through this field, so a caller can tell total failure from partial
  /// success.
  pub(crate) persistent_error: Option<String>,
  /// Which of those it was, taken from the SQLite layer's typed failure rather
  /// than assumed.
  pub(crate) persistent_failure_kind: Option<sqlite::BrowserDatabaseFailureKind>,
  /// A row was seen and rejected while the source itself stayed readable.
  /// Section 5.7 counts this in `rows_skipped` and reports it as a row issue
  /// against a source that still succeeded, which is why it is deliberately
  /// separate from `persistent_error`.
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
        outcome.persistent_failure_kind = Some(failure.kind);
      } else {
        outcome.persistent_acquisition_attempts = 1;
      }
      outcome.persistent_error = Some(format!("{error:#}"));
    }
  }

  let cookies_dir = db_path.parent().unwrap_or_else(|| Path::new(""));
  for (index, (path, format)) in session_candidates(cookies_dir).into_iter().enumerate() {
    let precedence = session_candidate_precedence(index);
    match parse_session_candidate(&path, &format, domains) {
      Ok(success) => {
        let mut diagnostics = success.transient_errors;
        diagnostics.extend(success.parsed.diagnostics);
        outcome.session_sources.push(MozillaSessionSourceOutcome {
          path,
          format: format.format_id(),
          precedence,
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
        precedence,
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
  SESSION_CANDIDATES.map(|(relative, format)| (cookies_dir.join(relative), format))
}

fn get_authoritative_session_outcome(
  domains: Option<&[String]>,
  cookies_dir: &Path,
) -> Result<SessionCookieParseOutcome> {
  let mut failures = Vec::new();
  for (path, format) in session_candidates(cookies_dir) {
    match parse_session_candidate(&path, &format, domains) {
      Ok(success) => return Ok(success.parsed),
      Err(failure) if is_missing_session_file(&failure.error) => continue,
      Err(failure) => {
        let diagnostic = format!("{}: {:#}", path.display(), failure.error);
        log::warn!("Failed to parse Firefox session store: {diagnostic}");
        failures.push(diagnostic);
      }
    }
  }

  if !failures.is_empty() {
    bail!(
      "all existing Firefox session store candidates failed: {}",
      failures.join("; ")
    );
  }

  Ok(SessionCookieParseOutcome {
    cookies: Vec::new(),
    detailed_cookies: Vec::new(),
    rows_seen: 0,
    rows_skipped: 0,
    diagnostics: Vec::new(),
  })
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
  if before.len() > MAX_SESSION_STORE_BYTES as u64 {
    bail!(
      "Firefox session store is {} bytes; maximum supported size is {} bytes",
      before.len(),
      MAX_SESSION_STORE_BYTES
    );
  }
  let expected_length = usize::try_from(before.len())
    .map_err(|_| anyhow!("Firefox session store length does not fit in memory"))?;
  let mut bytes = Vec::new();
  bytes
    .try_reserve_exact(expected_length)
    .map_err(|error| anyhow!("Unable to allocate Firefox session store buffer: {error}"))?;
  bytes.resize(expected_length, 0);
  file.read_exact(&mut bytes)?;
  let after = file.metadata()?;

  let length_changed =
    before.len() != after.len() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) != after.len();
  let modified_changed = before.modified().ok() != after.modified().ok();
  if length_changed || modified_changed {
    bail!("Firefox session store changed while it was being read");
  }

  Ok(bytes)
}

fn decompress_session_store(compressed: &[u8]) -> Result<Vec<u8>> {
  let advertised = compressed
    .get(..4)
    .ok_or_else(|| anyhow!("Invalid compressed length prefix"))?;
  let advertised = u32::from_le_bytes(
    advertised
      .try_into()
      .expect("the slice was checked to contain four bytes"),
  ) as usize;
  if advertised > MAX_SESSION_STORE_BYTES {
    bail!(
      "Firefox mozLz4 output advertises {advertised} bytes; maximum supported size is {MAX_SESSION_STORE_BYTES} bytes"
    );
  }

  let mut decompressed = Vec::new();
  decompressed
    .try_reserve_exact(advertised)
    .map_err(|error| anyhow!("Unable to allocate Firefox mozLz4 output buffer: {error}"))?;
  decompressed.resize(advertised, 0);
  let written = decompress_into(&compressed[4..], &mut decompressed)?;
  if written != advertised {
    bail!("Firefox mozLz4 output length {written} does not match advertised length {advertised}");
  }
  Ok(decompressed)
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
  match create_detailed_cookie(json_cookie) {
    Ok(detailed_cookie) => {
      outcome
        .cookies
        .push(clone_legacy_cookie(&detailed_cookie.cookie));
      outcome.detailed_cookies.push(detailed_cookie);
    }
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

fn clone_legacy_cookie(cookie: &Cookie) -> Cookie {
  Cookie {
    domain: cookie.domain.clone(),
    path: cookie.path.clone(),
    secure: cookie.secure,
    expires: cookie.expires,
    name: cookie.name.clone(),
    value: cookie.value.clone(),
    http_only: cookie.http_only,
    same_site: cookie.same_site,
  }
}

fn parse_session_json(
  json: &Value,
  domains: Option<&[String]>,
) -> Result<SessionCookieParseOutcome> {
  let mut outcome = SessionCookieParseOutcome {
    cookies: Vec::new(),
    detailed_cookies: Vec::new(),
    rows_seen: 0,
    rows_skipped: 0,
    diagnostics: Vec::new(),
  };
  let windows = json
    .get("windows")
    .ok_or_else(|| anyhow!("Firefox session state has no windows array"))?
    .as_array()
    .ok_or_else(|| anyhow!("Firefox session state windows is not an array"))?;

  // Current Firefox stores the global SessionCookies collection at the root
  // (`state.cookies`); legacy sessionstore.js files stored cookies per window.
  // Accept exactly one layout and route both container formats through this
  // walker so record decoding cannot diverge again.
  let top_level_cookies = json
    .get("cookies")
    .map(|cookies| {
      cookies
        .as_array()
        .ok_or_else(|| anyhow!("Firefox session state top-level cookies is not an array"))
    })
    .transpose()?;
  let mut window_cookie_collections = Vec::new();
  for (window_index, window) in windows.iter().enumerate() {
    let window = window
      .as_object()
      .ok_or_else(|| anyhow!("Firefox session state windows[{window_index}] is not an object"))?;
    let Some(cookies) = window.get("cookies") else {
      continue;
    };
    let cookies = cookies.as_array().ok_or_else(|| {
      anyhow!("Firefox session state windows[{window_index}].cookies is not an array")
    })?;
    window_cookie_collections.push((window_index, cookies));
  }

  if top_level_cookies.is_some() && !window_cookie_collections.is_empty() {
    bail!("Firefox session state contains both top-level and per-window cookie layouts");
  }

  if let Some(cookies) = top_level_cookies {
    for (cookie_index, json_cookie) in cookies.iter().enumerate() {
      record_session_cookie(
        &mut outcome,
        json_cookie,
        &format!("cookies[{cookie_index}]"),
        domains,
      );
    }
    return Ok(outcome);
  }

  for (window_index, cookies) in window_cookie_collections {
    for (cookie_index, json_cookie) in cookies.iter().enumerate() {
      record_session_cookie(
        &mut outcome,
        json_cookie,
        &format!("windows[{window_index}].cookies[{cookie_index}]"),
        domains,
      );
    }
  }
  Ok(outcome)
}

fn parse_legacy_session_cookies(
  path: &Path,
  domains: Option<&[String]>,
) -> Result<SessionCookieParseOutcome> {
  let plain = String::from_utf8(read_stable_session_file(path)?)?;
  let json: Value = serde_json::from_str(&plain)?;
  parse_session_json(&json, domains)
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
  let compressed = read_stable_session_file(path)?;
  if !compressed.starts_with(b"mozLz40\0") {
    bail!("Invalid mozLz40 header");
  }
  let compressed = compressed
    .get(8..)
    .ok_or_else(|| anyhow!("Invalid compressed length"))?;
  let decompressed = decompress_session_store(compressed)?;
  let plain = String::from_utf8(decompressed)?;
  let json: Value = serde_json::from_str(&plain)?;
  parse_session_json(&json, domains)
}

fn session_cookie_expiry(json_cookie: &Value) -> Result<Option<u64>> {
  let Some(expiry) = json_cookie.get("expiry") else {
    return Ok(None);
  };
  let expiry = expiry
    .as_u64()
    .ok_or_else(|| anyhow!("session cookie expiry is not a non-negative integer"))?;
  if expiry == 0 {
    Ok(None)
  } else if expiry <= MAX_PLAUSIBLE_SESSION_EXPIRY_SECONDS {
    Ok(date::mozilla_timestamp(expiry))
  } else if expiry < MIN_PLAUSIBLE_SESSION_EXPIRY_MILLISECONDS {
    bail!("session cookie expiry {expiry} has ambiguous seconds/milliseconds scale")
  } else if expiry <= MAX_PLAUSIBLE_SESSION_EXPIRY_MILLISECONDS {
    Ok(date::mozilla_timestamp(expiry / 1000))
  } else {
    bail!("session cookie expiry {expiry} is outside the supported timestamp range")
  }
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
  let expires = session_cookie_expiry(json_cookie)?;

  let same_site = json_cookie
    .get("sameSite")
    .and_then(|v| v.as_i64())
    .unwrap_or(SAME_SITE_UNSPECIFIED);

  Ok(Cookie {
    domain: host.to_string(),
    expires,
    http_only,
    name: name.to_string(),
    value: value.to_string(),
    path: path.to_string(),
    same_site,
    secure,
  })
}

fn create_detailed_cookie(json_cookie: &Value) -> Result<DetailedCookie> {
  let cookie = create_cookie(json_cookie)?;

  Ok(DetailedCookie {
    cookie,
    context: firefox_session_cookie_context(json_cookie.get("originAttributes")),
  })
}

fn firefox_session_cookie_context(origin_attributes: Option<&Value>) -> CookieContext {
  let Some(origin_attributes) = origin_attributes else {
    return CookieContext::default();
  };
  if let Some(origin_attributes) = origin_attributes.as_str() {
    return firefox_cookie_context(Some(origin_attributes.to_owned()));
  }
  let Some(attributes) = origin_attributes.as_object() else {
    return CookieContext {
      origin_attributes: Some(origin_attributes.to_string()),
      ..CookieContext::default()
    };
  };

  let unsigned_attribute = |name: &str| {
    attributes.get(name).and_then(|value| {
      value
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
    })
  };
  CookieContext {
    origin_attributes: Some(Value::Object(attributes.clone()).to_string()),
    user_context_id: unsigned_attribute("userContextId"),
    partition_key: attributes
      .get("partitionKey")
      .and_then(Value::as_str)
      .map(str::to_owned),
    private_browsing_id: unsigned_attribute("privateBrowsingId"),
    ..CookieContext::default()
  }
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
#[cfg(test)]
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
#[cfg(test)]
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
  // `Ini::load_from_file_opt` strips a UTF-8 BOM; the string parser does not,
  // and U+FEFF is not whitespace, so a BOM would swallow every section into the
  // anonymous one and yield zero profiles with no error at all.
  let contents = contents.strip_prefix('\u{feff}').unwrap_or(contents);
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
  use base64::{engine::general_purpose::STANDARD, Engine as _};
  use lz4_flex::block::compress_prepend_size;
  use sha2::{Digest, Sha256};
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

  fn set_mozilla_schema_version(connection: &rusqlite::Connection, version: u32) {
    connection
      .pragma_update(None, "user_version", version)
      .expect("set Firefox schema version");
  }

  // Minimal moz_cookies fixture mirroring the columns firefox_based reads.
  // Real Firefox schema has more columns, but rookie-cookies only selects these.
  fn seed_moz_cookies(db: &Path, rows: &[CookieRow<'_>]) {
    let conn = rusqlite::Connection::open(db).expect("open writable sqlite");
    set_mozilla_schema_version(&conn, 15);
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
  fn detailed_cookies_preserve_container_collisions() {
    let dir = unique_tmpdir("firefox-container-collision");
    let db = dir.join("cookies.sqlite");
    let connection = rusqlite::Connection::open(&db).expect("open fixture");
    connection
      .execute_batch(
        "CREATE TABLE moz_cookies (
          host TEXT NOT NULL, path TEXT NOT NULL, isSecure INTEGER NOT NULL,
          expiry INTEGER NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
          isHttpOnly INTEGER NOT NULL, sameSite INTEGER NOT NULL,
          originAttributes TEXT
        );
        INSERT INTO moz_cookies VALUES
          ('.example.com', '/', 1, 0, 'session', 'work', 1, 1,
           '^userContextId=2&partitionKey=%28https%2Cwork.example%29&privateBrowsingId=0'),
          ('.example.com', '/', 1, 0, 'session', 'personal', 1, 1,
           '^userContextId=1&partitionKey=%28https%2Cpersonal.example%29&privateBrowsingId=1');",
      )
      .expect("seed container cookies");
    drop(connection);

    let cookies = firefox_based_detailed(db, None).expect("extract detailed cookies");
    assert_eq!(cookies.len(), 2);
    assert_eq!(cookies[0].cookie.name, cookies[1].cookie.name);
    assert_eq!(cookies[0].cookie.domain, cookies[1].cookie.domain);
    assert_eq!(cookies[0].cookie.path, cookies[1].cookie.path);
    let contexts = cookies
      .iter()
      .map(|cookie| {
        (
          cookie.cookie.value.as_str(),
          (
            cookie.context.user_context_id,
            cookie.context.partition_key.as_deref(),
            cookie.context.private_browsing_id,
          ),
        )
      })
      .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(
      contexts.get("work"),
      Some(&(Some(2), Some("(https,work.example)"), Some(0)))
    );
    assert_eq!(
      contexts.get("personal"),
      Some(&(Some(1), Some("(https,personal.example)"), Some(1)))
    );
    assert!(cookies.iter().any(|cookie| {
      cookie.context.origin_attributes.as_deref()
        == Some("^userContextId=2&partitionKey=%28https%2Cwork.example%29&privateBrowsingId=0")
    }));
  }

  #[test]
  fn detailed_query_keeps_legacy_firefox_schemas_readable() {
    let dir = unique_tmpdir("firefox-legacy-detailed-schema");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(
      &db,
      &[(".example.com", "/", false, 0, "legacy", "value", false, 0)],
    );

    let cookies =
      firefox_based_detailed(db, None).expect("missing originAttributes column remains compatible");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].context, CookieContext::default());
  }

  #[test]
  fn malformed_origin_attributes_errors_without_changing_legacy_projection() {
    let dir = unique_tmpdir("firefox-malformed-detailed-context");
    let db = dir.join("cookies.sqlite");
    let connection = rusqlite::Connection::open(&db).expect("open fixture");
    connection
      .execute_batch(
        "CREATE TABLE moz_cookies (
          host TEXT, path TEXT, isSecure INTEGER, expiry INTEGER, name TEXT,
          value TEXT, isHttpOnly INTEGER, sameSite INTEGER, originAttributes BLOB
        );
        INSERT INTO moz_cookies VALUES
          ('.example.com', '/', 0, 0, 'legacy', 'value', 0, 0, X'FF');",
      )
      .expect("seed malformed context");
    drop(connection);

    let legacy =
      firefox_based(db.clone(), None).expect("legacy projection does not inspect detailed columns");
    assert_eq!(legacy.len(), 1);
    let error = firefox_based_detailed(db, None)
      .expect_err("malformed detailed context must not silently become absent");
    assert!(format!("{error:#}").contains("originAttributes"));
  }

  #[test]
  fn malformed_origin_attributes_skip_only_their_row() {
    let dir = unique_tmpdir("firefox-mixed-detailed-context");
    let db = dir.join("cookies.sqlite");
    let connection = rusqlite::Connection::open(&db).expect("open fixture");
    connection
      .execute_batch(
        "CREATE TABLE moz_cookies (
          host TEXT, path TEXT, isSecure INTEGER, expiry INTEGER, name TEXT,
          value TEXT, isHttpOnly INTEGER, sameSite INTEGER, originAttributes BLOB
        );
        INSERT INTO moz_cookies VALUES
          ('.example.com', '/', 0, 0, 'before', 'first', 0, 0, '^userContextId=1'),
          ('.example.com', '/', 0, 0, 'malformed', 'discarded', 0, 0, X'FF'),
          ('.example.com', '/', 0, 0, 'after', 'last', 0, 0, '^userContextId=2');",
      )
      .expect("seed mixed origin attributes");
    drop(connection);

    let legacy = firefox_based(db.clone(), None).expect("legacy projection keeps every row");
    assert_eq!(legacy.len(), 3);

    let persistent = sqlite::with_browser_database(db.clone(), |connection| {
      query_persistent_cookies_mode(connection, None, true)
    })
    .expect("query detailed rows")
    .into_value();
    assert_eq!(persistent.rows_seen, 3);
    assert_eq!(persistent.rows_skipped, 1);
    assert_eq!(persistent.detailed_cookies.len(), 2);
    assert!(persistent.last_row_error.is_some());
    assert_eq!(
      persistent
        .detailed_cookies
        .iter()
        .map(|cookie| cookie.cookie.name.as_str())
        .collect::<Vec<_>>(),
      vec!["before", "after"]
    );

    let public_result =
      firefox_based_detailed(db, None).expect("public detailed extraction returns the valid rows");
    assert_eq!(public_result.len(), 2);
  }

  fn write_session_jsonlz4(path: &Path, cookies: Value) {
    if let Some(parent) = path.parent() {
      std::fs::create_dir_all(parent).expect("create sessionstore directory");
    }
    let json = serde_json::json!({ "windows": [{ "tabs": [] }], "cookies": cookies }).to_string();
    let mut encoded = b"mozLz40\0".to_vec();
    encoded.extend(compress_prepend_size(json.as_bytes()));
    std::fs::write(path, encoded).expect("write sessionstore fixture");
  }

  fn write_session_value_jsonlz4(path: &Path, json: Value) {
    if let Some(parent) = path.parent() {
      std::fs::create_dir_all(parent).expect("create sessionstore directory");
    }
    let mut encoded = b"mozLz40\0".to_vec();
    encoded.extend(compress_prepend_size(json.to_string().as_bytes()));
    std::fs::write(path, encoded).expect("write sessionstore fixture");
  }

  fn write_captured_session_fixture(path: &Path, encoded: &str) -> Vec<u8> {
    if let Some(parent) = path.parent() {
      std::fs::create_dir_all(parent).expect("create captured fixture directory");
    }
    let bytes = STANDARD
      .decode(encoded.trim())
      .expect("decode captured Firefox fixture");
    std::fs::write(path, &bytes).expect("write captured Firefox fixture");
    bytes
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
  fn moz_lz4_rejects_u32_max_advertised_output_before_allocation() {
    let error = decompress_session_store(&u32::MAX.to_le_bytes())
      .expect_err("a corrupt size prefix must be rejected without allocating it");
    let message = format!("{error:#}");
    assert!(message.contains("4294967295"), "{message}");
    assert!(message.contains("maximum supported size"), "{message}");
  }

  #[test]
  fn session_file_rejects_oversized_raw_input_before_reading_it() {
    let dir = unique_tmpdir("ff-oversized-session");
    let path = dir.join("sessionstore.jsonlz4");
    let file = std::fs::File::create(&path).expect("create sparse fixture");
    file
      .set_len(MAX_SESSION_STORE_BYTES as u64 + 1)
      .expect("extend sparse fixture");
    let error = read_stable_session_file(&path).expect_err("oversized source must fail");
    assert!(format!("{error:#}").contains("maximum supported size"));
  }

  #[test]
  fn jsonlz4_and_legacy_share_one_walker_for_their_real_layouts() {
    let dir = unique_tmpdir("ff-shared-session-shape");
    let modern_state = serde_json::json!({
      "windows": [{ "tabs": [] }],
      "cookies": [session_cookie("first"), session_cookie("second")]
    });
    let legacy_state = serde_json::json!({
      "windows": [
        { "cookies": [session_cookie("first")] },
        { "tabs": [], "cookies": [session_cookie("second")] }
      ]
    });
    let lz4 = dir.join("state.jsonlz4");
    write_session_value_jsonlz4(&lz4, modern_state);
    let legacy = dir.join("sessionstore.js");
    std::fs::write(&legacy, legacy_state.to_string()).expect("write legacy state");
    for parsed in [
      parse_session_cookies_lz4(&lz4, None).expect("parse compressed Firefox window state"),
      parse_legacy_session_cookies(&legacy, None).expect("parse legacy Firefox window state"),
    ] {
      assert_eq!(parsed.rows_seen, 2);
      assert_eq!(
        parsed
          .cookies
          .iter()
          .map(|cookie| cookie.name.as_str())
          .collect::<Vec<_>>(),
        vec!["first", "second"]
      );
    }
  }

  #[test]
  fn captured_firefox_141_session_uses_root_cookies_and_millisecond_expiry() {
    let dir = unique_tmpdir("firefox-141-captured-session");
    let path = dir.join("recovery.jsonlz4");
    let raw = write_captured_session_fixture(
      &path,
      include_str!("fixtures/firefox-141.0-recovery.jsonlz4.base64"),
    );
    assert_eq!(raw.len(), 1_111);
    assert_eq!(
      format!("{:x}", Sha256::digest(&raw)),
      "359602096db47f6d54a0a1d454844abdb604df99c1b26973f22c9dda6ea8bc2d"
    );

    let parsed = parse_session_cookies_lz4(&path, None).expect("parse Firefox 141 capture");
    assert_eq!(parsed.rows_seen, 5);
    assert_eq!(parsed.rows_skipped, 0);
    assert_eq!(parsed.cookies.len(), 5);
    assert!(parsed
      .cookies
      .iter()
      .all(|cookie| cookie.expires == Some(1_786_763_509)));
    let mut user_context_ids = parsed
      .detailed_cookies
      .iter()
      .map(|cookie| {
        cookie
          .context
          .user_context_id
          .expect("captured container id")
      })
      .collect::<Vec<_>>();
    user_context_ids.sort_unstable();
    assert_eq!(user_context_ids, vec![0, 1, 2, 3, 4]);
  }

  #[test]
  fn captured_firefox_142_session_uses_root_cookies_without_expiry() {
    let dir = unique_tmpdir("firefox-142-captured-session");
    let path = dir.join("recovery.jsonlz4");
    let raw = write_captured_session_fixture(
      &path,
      include_str!("fixtures/firefox-142.0-recovery.jsonlz4.base64"),
    );
    assert_eq!(raw.len(), 1_091);
    assert_eq!(
      format!("{:x}", Sha256::digest(&raw)),
      "07e4925c9bb594204cafb652cf8f451eda09ad4877173767b81d5d4163434062"
    );

    let parsed = parse_session_cookies_lz4(&path, None).expect("parse Firefox 142 capture");
    assert_eq!(parsed.rows_seen, 5);
    assert_eq!(parsed.rows_skipped, 0);
    assert_eq!(parsed.cookies.len(), 5);
    assert!(parsed.cookies.iter().all(|cookie| cookie.expires.is_none()));
    let mut user_context_ids = parsed
      .detailed_cookies
      .iter()
      .map(|cookie| {
        cookie
          .context
          .user_context_id
          .expect("captured container id")
      })
      .collect::<Vec<_>>();
    user_context_ids.sort_unstable();
    assert_eq!(user_context_ids, vec![0, 1, 2, 3, 4]);
  }

  #[test]
  fn jsonlz4_rejects_absent_or_ambiguous_cookie_structure() {
    let rootless = serde_json::json!({ "cookies": [session_cookie("missing-windows")] });
    assert!(parse_session_json(&rootless, None).is_err());
    assert!(parse_session_json(&serde_json::json!({ "windows": {} }), None).is_err());
    assert!(
      parse_session_json(&serde_json::json!({ "windows": [{ "cookies": {} }] }), None).is_err()
    );

    let cookie_free = serde_json::json!({ "windows": [{ "tabs": [] }] });
    let parsed = parse_session_json(&cookie_free, None).expect("cookie-free state is valid");
    assert!(parsed.cookies.is_empty());

    let ambiguous = serde_json::json!({
      "windows": [{ "cookies": [session_cookie("legacy")] }],
      "cookies": [session_cookie("ambiguous-top-level")]
    });
    assert!(parse_session_json(&ambiguous, None).is_err());
  }

  #[test]
  fn session_expiry_classifier_preserves_seconds_converts_milliseconds_and_rejects_gap() {
    let cookie = |expiry| serde_json::json!({ "expiry": expiry });
    assert_eq!(session_cookie_expiry(&serde_json::json!({})).unwrap(), None);
    assert_eq!(session_cookie_expiry(&cookie(0)).unwrap(), None);
    assert_eq!(
      session_cookie_expiry(&cookie(1_800_000_000)).unwrap(),
      Some(1_800_000_000)
    );
    assert_eq!(
      session_cookie_expiry(&cookie(1_800_000_000_999_u64)).unwrap(),
      Some(1_800_000_000)
    );
    let ambiguous = session_cookie_expiry(&cookie(100_000_000_000_u64))
      .expect_err("the scale gap must never be guessed");
    assert!(format!("{ambiguous:#}").contains("ambiguous seconds/milliseconds scale"));
  }

  #[test]
  fn detailed_session_cookies_preserve_object_origin_attribute_collisions() {
    let dir = unique_tmpdir("ff-session-origin-attribute-objects");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(&db, &[]);
    let cookies = serde_json::json!([
      {
        "host": ".example.com",
        "path": "/",
        "name": "session",
        "value": "work",
        "originAttributes": {
          "userContextId": 2,
          "partitionKey": "(https,work.example)",
          "privateBrowsingId": 0,
          "futureAttribute": "retained"
        }
      },
      {
        "host": ".example.com",
        "path": "/",
        "name": "session",
        "value": "personal",
        "originAttributes": {
          "userContextId": 1,
          "partitionKey": "(https,personal.example)",
          "privateBrowsingId": 1
        }
      }
    ]);
    write_session_jsonlz4(&dir.join("sessionstore-backups/recovery.jsonlz4"), cookies);

    let detailed = firefox_based_detailed(db, None).expect("extract detailed session cookies");
    assert_eq!(detailed.len(), 2);
    let contexts = detailed
      .iter()
      .map(|cookie| (cookie.cookie.value.as_str(), &cookie.context))
      .collect::<std::collections::HashMap<_, _>>();
    let work = contexts.get("work").expect("work container");
    assert_eq!(work.user_context_id, Some(2));
    assert_eq!(work.partition_key.as_deref(), Some("(https,work.example)"));
    assert_eq!(work.private_browsing_id, Some(0));
    let raw: Value = serde_json::from_str(
      work
        .origin_attributes
        .as_deref()
        .expect("raw session origin attributes"),
    )
    .expect("raw object remains JSON");
    assert_eq!(raw["futureAttribute"], "retained");

    let personal = contexts.get("personal").expect("personal container");
    assert_eq!(personal.user_context_id, Some(1));
    assert_eq!(
      personal.partition_key.as_deref(),
      Some("(https,personal.example)")
    );
    assert_eq!(personal.private_browsing_id, Some(1));
  }

  #[test]
  fn detailed_session_context_preserves_arbitrary_origin_attribute_json() {
    for origin_attributes in [
      serde_json::json!(["future", {"shape": true}]),
      serde_json::json!(42),
      serde_json::json!(false),
      Value::Null,
    ] {
      let context = firefox_session_cookie_context(Some(&origin_attributes));
      let raw = origin_attributes.to_string();
      assert_eq!(context.origin_attributes.as_deref(), Some(raw.as_str()));
      assert_eq!(context.user_context_id, None);
      assert_eq!(context.partition_key, None);
      assert_eq!(context.private_browsing_id, None);
    }
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
    // A rejected row is a partial success: the source itself was readable and
    // returned its good cookies, so only the row-level field is set.
    assert!(outcome.persistent_row_error.is_some());
    assert!(outcome.persistent_error.is_none());
  }

  #[test]
  fn persistent_metadata_type_errors_are_counted_and_skipped_instead_of_defaulted() {
    let dir = unique_tmpdir("ff-persistent-metadata-types");
    let db = dir.join("cookies.sqlite");
    let connection = rusqlite::Connection::open(&db).expect("open fixture");
    connection
      .execute_batch(
        "CREATE TABLE moz_cookies (
          host, path, isSecure, expiry, name, value, isHttpOnly, sameSite
        );
        INSERT INTO moz_cookies VALUES (X'FF', '/', 0, 0, 'bad-host', 'v', 0, 0);
        INSERT INTO moz_cookies VALUES ('.example.com', X'FF', 0, 0, 'bad-path', 'v', 0, 0);
        INSERT INTO moz_cookies VALUES ('.example.com', '/', 'yes', 0, 'bad-secure', 'v', 0, 0);
        INSERT INTO moz_cookies VALUES ('.example.com', '/', 0, 'tomorrow', 'bad-expiry', 'v', 0, 0);
        INSERT INTO moz_cookies VALUES ('.example.com', '/', 0, 0, 'bad-http', 'v', 'yes', 0);
        INSERT INTO moz_cookies VALUES ('.example.com', '/', 0, 0, 'bad-site', 'v', 0, X'FF');
        INSERT INTO moz_cookies VALUES ('.example.com', '/', 0, 0, 'good', 'v', 0, 0);",
      )
      .expect("seed malformed metadata rows");
    drop(connection);

    let outcome = query_cookies_engine_outcome(&db, None);
    assert_eq!(outcome.persistent_rows_seen, 7);
    assert_eq!(outcome.persistent_rows_skipped, 6);
    assert_eq!(outcome.persistent_cookies.len(), 1);
    assert_eq!(outcome.persistent_cookies[0].name, "good");
    assert!(outcome.persistent_row_error.is_some());
    assert!(outcome.persistent_error.is_none());
  }

  #[test]
  fn malformed_persistent_host_is_a_reported_total_row_failure() {
    let dir = unique_tmpdir("ff-persistent-host-type-total");
    let db = dir.join("cookies.sqlite");
    let connection = rusqlite::Connection::open(&db).expect("open fixture");
    connection
      .execute_batch(
        "CREATE TABLE moz_cookies (
          host, path, isSecure, expiry, name, value, isHttpOnly, sameSite
        );
        INSERT INTO moz_cookies VALUES (X'FF', '/', 0, 0, 'bad-host', 'v', 0, 0);",
      )
      .expect("seed malformed host");
    drop(connection);

    let outcome = query_cookies_engine_outcome(&db, None);
    assert_eq!(outcome.persistent_rows_seen, 1);
    assert_eq!(outcome.persistent_rows_skipped, 1);
    assert!(outcome.persistent_cookies.is_empty());
    assert!(outcome
      .persistent_row_error
      .as_deref()
      .is_some_and(|error| error.contains("host")));
    let error =
      firefox_based(db, None).expect_err("all malformed rows must fail legacy extraction");
    assert!(format!("{error:#}").contains("host"));
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
  fn engine_outcome_retains_every_existing_session_candidate_when_all_fail() {
    let dir = unique_tmpdir("ff-engine-all-session-failures");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(&db, &[]);
    for (relative, _) in SESSION_CANDIDATES {
      let path = dir.join(relative);
      if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create session directory");
      }
      std::fs::write(path, b"invalid session candidate").expect("write invalid candidate");
    }

    let outcome = query_cookies_engine_outcome(&db, None);
    assert_eq!(outcome.session_sources.len(), SESSION_CANDIDATES.len());
    assert!(outcome
      .session_sources
      .iter()
      .all(|source| !source.selected));
    assert!(outcome
      .session_sources
      .iter()
      .all(|source| source.error.is_some()));
  }

  #[test]
  fn legacy_extraction_preserves_persistent_cookies_when_every_session_candidate_fails() {
    let dir = unique_tmpdir("ff-legacy-all-session-failures");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(
      &db,
      &[(
        ".example.com",
        "/",
        false,
        0,
        "persistent",
        "still-present",
        false,
        0,
      )],
    );
    for (relative, _) in SESSION_CANDIDATES {
      let path = dir.join(relative);
      if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create session directory");
      }
      std::fs::write(path, b"invalid session candidate").expect("write invalid candidate");
    }

    let cookies = firefox_based(db.clone(), None)
      .expect("persistent cookies remain usable when every session store fails");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "persistent");

    let cookies = firefox_based_detailed(db, None)
      .expect("detailed persistent cookies remain usable when every session store fails");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].cookie.name, "persistent");
  }

  #[test]
  fn legacy_extraction_signals_all_session_failure_without_persistent_cookies() {
    let dir = unique_tmpdir("ff-legacy-only-session-failures");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(&db, &[]);
    for (relative, _) in SESSION_CANDIDATES {
      let path = dir.join(relative);
      if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create session directory");
      }
      std::fs::write(path, b"invalid session candidate").expect("write invalid candidate");
    }

    let error = firefox_based(db.clone(), None)
      .expect_err("total session-store failure without persistent cookies must be signaled");
    assert!(format!("{error:#}").contains("all existing Firefox session store candidates failed"));
    let error = firefox_based_detailed(db, None)
      .expect_err("detailed extraction must signal total session-store failure");
    assert!(format!("{error:#}").contains("all existing Firefox session store candidates failed"));
  }

  #[test]
  fn ambiguous_session_expiry_is_a_skipped_row_with_a_diagnostic() {
    let dir = unique_tmpdir("ff-session-expiry-scale-diagnostic");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(&db, &[]);
    let with_expiry = |name: &str, expiry: u64| {
      serde_json::json!({
        "host": ".example.com", "path": "/", "name": name,
        "value": "fixture", "expiry": expiry
      })
    };
    write_session_jsonlz4(
      &dir.join("sessionstore-backups/recovery.jsonlz4"),
      serde_json::json!([
        with_expiry("session", 0),
        with_expiry("seconds", 1_800_000_000),
        with_expiry("milliseconds", 1_800_000_000_999_u64),
        with_expiry("ambiguous", 100_000_000_000_u64)
      ]),
    );

    let outcome = query_cookies_engine_outcome(&db, None);
    let source = &outcome.session_sources[0];
    assert!(source.selected);
    assert_eq!(source.rows_seen, 4);
    assert_eq!(source.rows_skipped, 1);
    assert_eq!(source.cookies.len(), 3);
    assert_eq!(source.cookies[0].expires, None);
    assert_eq!(source.cookies[1].expires, Some(1_800_000_000));
    assert_eq!(source.cookies[2].expires, Some(1_800_000_000));
    assert!(source.diagnostics[0].contains("ambiguous seconds/milliseconds scale"));
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
        detailed_cookies: Vec::new(),
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
  fn persistent_expiry_uses_seconds_before_schema_16_and_milliseconds_after() {
    let old_dir = unique_tmpdir("ff-expiry-seconds-schema");
    let old_db = old_dir.join("cookies.sqlite");
    seed_moz_cookies(
      &old_db,
      &[(
        ".example.com",
        "/",
        false,
        1_700_000_000,
        "old",
        "seconds",
        false,
        0,
      )],
    );

    let new_dir = unique_tmpdir("ff-expiry-milliseconds-schema");
    let new_db = new_dir.join("cookies.sqlite");
    seed_moz_cookies(
      &new_db,
      &[(
        ".example.com",
        "/",
        false,
        1_700_000_000_999,
        "new",
        "milliseconds",
        false,
        0,
      )],
    );
    let connection = rusqlite::Connection::open(&new_db).expect("open writable sqlite");
    set_mozilla_schema_version(&connection, 16);
    drop(connection);

    let old = firefox_based(old_db.clone(), None).expect("read seconds-era profile");
    let new = firefox_based(new_db.clone(), None).expect("read milliseconds-era profile");
    assert_eq!(old[0].expires, Some(1_700_000_000));
    assert_eq!(new[0].expires, Some(1_700_000_000));

    let old_detailed =
      firefox_based_detailed(old_db, None).expect("read detailed seconds-era profile");
    let new_detailed =
      firefox_based_detailed(new_db, None).expect("read detailed milliseconds-era profile");
    assert_eq!(old_detailed[0].cookie.expires, Some(1_700_000_000));
    assert_eq!(new_detailed[0].cookie.expires, Some(1_700_000_000));
  }

  #[test]
  fn schema_16_conversion_is_confined_to_persistent_cookies() {
    let dir = unique_tmpdir("ff-persistent-only-expiry-conversion");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(
      &db,
      &[(
        ".example.com",
        "/",
        false,
        1_700_000_000_999,
        "persistent",
        "milliseconds",
        false,
        0,
      )],
    );
    let connection = rusqlite::Connection::open(&db).expect("open writable sqlite");
    set_mozilla_schema_version(&connection, 16);
    drop(connection);
    write_session_jsonlz4(
      &dir.join("sessionstore-backups/recovery.jsonlz4"),
      serde_json::json!([{
        "host": ".example.com",
        "path": "/",
        "name": "sessionstore",
        "value": "legacy-seconds",
        "expiry": 1_800_000_000_u64
      }]),
    );

    let mut cookies = firefox_based(db.clone(), None).expect("read persistent and session cookies");
    cookies.sort_by(|left, right| left.name.cmp(&right.name));
    assert_eq!(cookies[0].name, "persistent");
    assert_eq!(cookies[0].expires, Some(1_700_000_000));
    assert_eq!(cookies[1].name, "sessionstore");
    // Sessionstore has no cookies.sqlite schema marker. Preserve its existing
    // legacy-seconds interpretation rather than applying the DB conversion.
    assert_eq!(cookies[1].value, "legacy-seconds");
    assert_eq!(cookies[1].expires, Some(1_800_000_000));

    let mut detailed =
      firefox_based_detailed(db, None).expect("read detailed persistent and session cookies");
    detailed.sort_by(|left, right| left.cookie.name.cmp(&right.cookie.name));
    assert_eq!(detailed[0].cookie.name, "persistent");
    assert_eq!(detailed[0].cookie.expires, Some(1_700_000_000));
    assert_eq!(detailed[1].cookie.name, "sessionstore");
    assert_eq!(detailed[1].cookie.value, "legacy-seconds");
    assert_eq!(detailed[1].cookie.expires, Some(1_800_000_000));
  }

  #[test]
  fn firefox_schema_version_and_rows_come_from_the_acquired_wal_snapshot() {
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
    let mut writer = rusqlite::Connection::open(&db).expect("open writable sqlite");
    let mode: String = writer
      .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
      .expect("enable WAL");
    assert_eq!(mode, "wal");
    let transaction = writer.transaction().expect("begin WAL update");
    set_mozilla_schema_version(&transaction, 16);
    transaction
      .execute(
        "UPDATE moz_cookies SET expiry = 1700000000000 WHERE name = 'checkpointed'",
        [],
      )
      .expect("migrate checkpointed expiry to milliseconds");
    transaction
      .execute(
        "INSERT INTO moz_cookies (host, path, isSecure, expiry, name, value, isHttpOnly, sameSite)
          VALUES ('.example.com', '/', 0, 1800000000999, 'in-wal', 'fresh', 0, 0)",
        [],
      )
      .expect("insert WAL row");
    transaction.commit().expect("commit schema and row update");

    let mut cookies = firefox_based(db.clone(), None).expect("decode");

    cookies.sort_by(|a, b| a.name.cmp(&b.name));
    let names: Vec<_> = cookies.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["checkpointed", "in-wal"], "{cookies:?}");
    let in_wal = cookies.iter().find(|c| c.name == "in-wal").expect("in-wal");
    assert_eq!(
      in_wal.value, "fresh",
      "the WAL row must decode, not just appear"
    );
    assert_eq!(in_wal.expires, Some(1_800_000_000));
    let checkpointed = cookies
      .iter()
      .find(|cookie| cookie.name == "checkpointed")
      .expect("checkpointed");
    assert_eq!(checkpointed.expires, Some(1_700_000_000));

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
  fn firefox_based_enforces_consistent_domain_boundaries_and_fail_closed_filters() {
    let dir = unique_tmpdir("ff-domain-filter-boundary");
    let db = dir.join("cookies.sqlite");
    seed_moz_cookies(
      &db,
      &[
        ("example.com", "/", false, 0, "p-exact", "yes", false, 0),
        (
          ".sub.example.com",
          "/",
          false,
          0,
          "p-subdomain",
          "yes",
          false,
          0,
        ),
        (
          "example.com.",
          "/",
          false,
          0,
          "p-trailing-dot",
          "yes",
          false,
          0,
        ),
        ("notexample.com", "/", false, 0, "p-prefix", "no", false, 0),
        (
          "example.com.evil.net",
          "/",
          false,
          0,
          "p-suffix",
          "no",
          false,
          0,
        ),
        ("other.test", "/", false, 0, "p-unrelated", "no", false, 0),
      ],
    );

    let session_cookie = |host: &str, name: &str| {
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
          session_cookie("example.com", "s-exact"),
          session_cookie(".sub.example.com", "s-subdomain"),
          session_cookie("example.com.", "s-trailing-dot"),
          session_cookie("notexample.com", "s-prefix"),
          session_cookie("example.com.evil.net", "s-suffix"),
          session_cookie("other.test", "s-unrelated")
        ]
      }]
    });
    std::fs::write(dir.join("sessionstore.js"), session.to_string()).expect("session fixture");

    let mut cookies =
      firefox_based(db.clone(), Some(vec!["example.com".to_string()])).expect("decode");
    cookies.sort_by(|a, b| a.name.cmp(&b.name));
    let names = cookies
      .iter()
      .map(|cookie| cookie.name.as_str())
      .collect::<Vec<_>>();
    assert_eq!(
      names,
      vec![
        "p-exact",
        "p-subdomain",
        "p-trailing-dot",
        "s-exact",
        "s-subdomain",
        "s-trailing-dot"
      ],
      "persistent and session cookies must use the same host boundary"
    );

    let connection = rusqlite::Connection::open(&db).expect("open cookie database");
    connection
      .execute(
        "INSERT INTO moz_cookies (host, path, isSecure, expiry, name, value, isHttpOnly, sameSite)
          VALUES ('notexample.com', '/', 0, 0, X'DEADBEEF', 'off-scope', 0, 0)",
        [],
      )
      .expect("insert malformed off-scope candidate");
    let dotted_domains = vec![".example.com.".to_string()];
    let mut dotted = query_persistent_cookies(&connection, Some(&dotted_domains))
      .expect("leading and trailing dots must not narrow the SQL candidate set");
    dotted.cookies.sort_by(|a, b| a.name.cmp(&b.name));
    let dotted_names = dotted
      .cookies
      .iter()
      .map(|cookie| cookie.name.as_str())
      .collect::<Vec<_>>();
    assert_eq!(
      dotted_names,
      vec!["p-exact", "p-subdomain", "p-trailing-dot"]
    );
    assert_eq!(dotted.rows_seen, 3);
    assert_eq!(dotted.rows_skipped, 0);

    let mixed_domains = vec!["".to_string(), "example.com".to_string()];
    let mut mixed = query_persistent_cookies(&connection, Some(&mixed_domains))
      .expect("a blank entry must not broaden a valid allowlist");
    mixed.cookies.sort_by(|a, b| a.name.cmp(&b.name));
    let mixed_names = mixed
      .cookies
      .iter()
      .map(|cookie| cookie.name.as_str())
      .collect::<Vec<_>>();
    assert_eq!(
      mixed_names,
      vec!["p-exact", "p-subdomain", "p-trailing-dot"]
    );

    let empty_domains = Vec::new();
    let empty_database = rusqlite::Connection::open_in_memory().expect("open empty database");
    assert!(
      query_persistent_cookies(&empty_database, Some(&empty_domains)).is_err(),
      "an empty allowlist must not bypass schema validation"
    );

    drop(connection);
    for invalid in ["", " \t ", ".", "%", "_"] {
      let cookies = firefox_based(db.clone(), Some(vec![invalid.to_string()]))
        .expect("invalid filter must be a successful empty result");
      assert!(
        cookies.is_empty(),
        "filter {invalid:?} must not expose persistent or session cookies: {cookies:?}"
      );
    }

    let empty = firefox_based(db.clone(), Some(Vec::new()))
      .expect("an explicit empty allowlist must validate sources and match nothing");
    assert!(empty.is_empty());

    let unfiltered = firefox_based(db, None).expect("unfiltered query");
    assert_eq!(unfiltered.len(), 12);
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
      err.to_string().contains("has no windows array"),
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
