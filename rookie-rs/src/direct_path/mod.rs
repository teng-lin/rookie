//! Typed, cross-platform extraction from an explicit browser cookie source.
//!
//! This module is the canonical Rust API for paths supplied by a caller. It
//! identifies the source before selecting a target capability, so unsupported
//! platforms and invalid options are reported as stable, downcastable errors.

mod shared;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod unsupported;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "macos")]
use macos as platform;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
use unsupported as platform;
#[cfg(target_os = "windows")]
use windows as platform;

use crate::enums::{Cookie, DetailedCookie};
use anyhow::Result;
use std::fmt;
use std::path::{Path, PathBuf};

/// A browser cookie source recognized from its on-disk signature and schema.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieSourceKind {
  /// A SQLite database containing Chromium's `cookies` table.
  ChromiumSqlite,
  /// A SQLite database containing Mozilla's `moz_cookies` table.
  MozillaSqlite,
  /// Apple's binary-cookies file format.
  SafariBinaryCookies,
  /// An Internet Explorer ESE WebCache database.
  InternetExplorerEse,
}

impl CookieSourceKind {
  fn as_str(self) -> &'static str {
    match self {
      Self::ChromiumSqlite => "chromium_sqlite",
      Self::MozillaSqlite => "mozilla_sqlite",
      Self::SafariBinaryCookies => "safari_binary_cookies",
      Self::InternetExplorerEse => "internet_explorer_ese",
    }
  }
}

impl fmt::Display for CookieSourceKind {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(self.as_str())
  }
}

/// Why an explicit cookie source could not be classified for the request.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidCookieSourceReason {
  /// The path is missing or does not identify a regular file.
  NotARegularFile,
  /// The source could not be inspected because an I/O or SQLite operation failed.
  SourceInspectionFailed,
  /// The file header does not match a recognized cookie-store format.
  UnrecognizedSignature,
  /// The SQLite schema does not contain a supported cookie table.
  UnsupportedSqliteSchema,
  /// The SQLite schema claims more than one browser family.
  AmbiguousSqliteSchema,
  /// A Chromium-specific API received another recognized source kind.
  ExpectedChromiumSqlite { actual: CookieSourceKind },
}

impl InvalidCookieSourceReason {
  fn code(&self) -> &'static str {
    match self {
      Self::NotARegularFile => "not_a_regular_file",
      Self::SourceInspectionFailed => "source_inspection_failed",
      Self::UnrecognizedSignature => "unrecognized_signature",
      Self::UnsupportedSqliteSchema => "unsupported_sqlite_schema",
      Self::AmbiguousSqliteSchema => "ambiguous_sqlite_schema",
      Self::ExpectedChromiumSqlite { .. } => "expected_chromium_sqlite",
    }
  }
}

/// Why a Chromium direct-path option is invalid for the selected target.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidDirectPathOptionsReason {
  /// A `BrowserId` credential source carried an empty identifier.
  EmptyBrowserId,
  /// Windows Chromium extraction requires an explicit Local State file.
  MissingLocalStateFile,
  /// Registry browser identities are unavailable on this target.
  BrowserIdNotSupportedOnTarget,
  /// Local State credentials are meaningful only on Windows.
  LocalStateNotSupportedOnTarget,
  /// Process shutdown is available only to explicit Windows Chromium requests.
  ProcessShutdownNotSupportedOnTarget,
  /// The registry has no exact canonical ID or alias matching the request.
  UnknownBrowserId,
  /// The requested registry identity belongs to another browser engine.
  BrowserIdIsNotChromium,
}

impl InvalidDirectPathOptionsReason {
  fn code(self) -> &'static str {
    match self {
      Self::EmptyBrowserId => "empty_browser_id",
      Self::MissingLocalStateFile => "missing_local_state_file",
      Self::BrowserIdNotSupportedOnTarget => "browser_id_not_supported_on_target",
      Self::LocalStateNotSupportedOnTarget => "local_state_not_supported_on_target",
      Self::ProcessShutdownNotSupportedOnTarget => "process_shutdown_not_supported_on_target",
      Self::UnknownBrowserId => "unknown_browser_id",
      Self::BrowserIdIsNotChromium => "browser_id_is_not_chromium",
    }
  }
}

/// A stable direct-path request error carried inside the returned
/// [`anyhow::Error`] chain.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq)]
pub enum DirectPathError {
  InvalidSource {
    path: PathBuf,
    reason: InvalidCookieSourceReason,
  },
  InvalidOptions {
    source: CookieSourceKind,
    reason: InvalidDirectPathOptionsReason,
  },
  UnsupportedTarget {
    source: CookieSourceKind,
    target_os: &'static str,
    target_arch: &'static str,
  },
}

impl fmt::Debug for DirectPathError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::InvalidSource { reason, .. } => formatter
        .debug_struct("InvalidSource")
        .field("path", &crate::common::diagnostic::REDACTED_PATH)
        .field("reason", reason)
        .finish(),
      Self::InvalidOptions { source, reason } => formatter
        .debug_struct("InvalidOptions")
        .field("source", source)
        .field("reason", reason)
        .finish(),
      Self::UnsupportedTarget {
        source,
        target_os,
        target_arch,
      } => formatter
        .debug_struct("UnsupportedTarget")
        .field("source", source)
        .field("target_os", target_os)
        .field("target_arch", target_arch)
        .finish(),
    }
  }
}

impl DirectPathError {
  /// Stable top-level category for programmatic handling.
  pub fn kind(&self) -> &'static str {
    match self {
      Self::InvalidSource { .. } => "invalid_source",
      Self::InvalidOptions { .. } => "invalid_options",
      Self::UnsupportedTarget { .. } => "unsupported_target",
    }
  }

  /// Stable, reason-specific code for programmatic handling.
  pub fn code(&self) -> &'static str {
    match self {
      Self::InvalidSource { reason, .. } => reason.code(),
      Self::InvalidOptions { reason, .. } => reason.code(),
      Self::UnsupportedTarget { .. } => "unsupported_target",
    }
  }

  /// Returns the caller-supplied cookie path for invalid-source errors.
  pub fn path(&self) -> Option<&Path> {
    match self {
      Self::InvalidSource { path, .. } => Some(path),
      _ => None,
    }
  }

  /// Returns the recognized or expected cookie-source kind when available.
  pub fn source_kind(&self) -> Option<CookieSourceKind> {
    match self {
      Self::InvalidSource {
        reason: InvalidCookieSourceReason::ExpectedChromiumSqlite { actual },
        ..
      } => Some(*actual),
      Self::InvalidSource { .. } => None,
      Self::InvalidOptions { source, .. } | Self::UnsupportedTarget { source, .. } => Some(*source),
    }
  }

  /// Returns the operating-system identifier for unsupported-target errors.
  pub fn target_os(&self) -> Option<&str> {
    match self {
      Self::UnsupportedTarget { target_os, .. } => Some(target_os),
      _ => None,
    }
  }

  /// Returns the architecture identifier for unsupported-target errors.
  pub fn target_arch(&self) -> Option<&str> {
    match self {
      Self::UnsupportedTarget { target_arch, .. } => Some(target_arch),
      _ => None,
    }
  }

  /// Returns the structured invalid-source reason when applicable.
  pub fn invalid_source_reason(&self) -> Option<&InvalidCookieSourceReason> {
    match self {
      Self::InvalidSource { reason, .. } => Some(reason),
      _ => None,
    }
  }

  /// Returns the structured invalid-options reason when applicable.
  pub fn invalid_options_reason(&self) -> Option<&InvalidDirectPathOptionsReason> {
    match self {
      Self::InvalidOptions { reason, .. } => Some(reason),
      _ => None,
    }
  }
}

impl fmt::Display for DirectPathError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::InvalidSource { path, reason } => {
        let _ = path;
        write!(
          formatter,
          "invalid cookie source {}: {}",
          crate::common::diagnostic::REDACTED_PATH,
          reason.code()
        )
      }
      Self::InvalidOptions { source, reason } => {
        write!(formatter, "invalid options for {source}: {}", reason.code())
      }
      Self::UnsupportedTarget {
        source,
        target_os,
        target_arch,
      } => write!(
        formatter,
        "{source} extraction is unsupported on {target_os}/{target_arch}"
      ),
    }
  }
}

impl std::error::Error for DirectPathError {}

/// An owned request for automatic extraction from an explicit cookie source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectPathRequest {
  path: PathBuf,
  domains: Option<Vec<String>>,
  timeout: Option<std::time::Duration>,
  cancellation: Option<crate::CancellationHandle>,
}

impl DirectPathRequest {
  /// Creates a request with no domain filter.
  pub fn new(path: impl Into<PathBuf>) -> Self {
    Self {
      path: path.into(),
      domains: None,
      timeout: None,
      cancellation: None,
    }
  }

  /// Restricts emitted cookies to the supplied domain boundaries.
  pub fn domains(mut self, domains: Vec<String>) -> Self {
    self.domains = Some(domains);
    self
  }

  /// Overrides the default 30-second extraction budget.
  pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
    self.timeout = Some(timeout);
    self
  }

  /// Lets `handle` cancel this request from another thread while it runs —
  /// see [`crate::CancellationHandle`].
  pub fn cancellation(mut self, handle: crate::CancellationHandle) -> Self {
    self.cancellation = Some(handle);
    self
  }
}

/// How an explicit Chromium request obtains decryption credentials.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChromiumCredentialSource {
  /// Uses the platform's historical ordered identity probe.
  Automatic,
  /// Rejects the entire request if any row is encrypted.
  PlaintextOnly,
  /// Uses one exact registry browser identity on supported targets.
  BrowserId(String),
  /// Uses a caller-supplied Windows Chromium Local State file.
  LocalStateFile(PathBuf),
}

/// Whether a Windows Chromium request may shut down processes holding its DB.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ChromiumLockedDatabasePolicy {
  /// Never terminates a browser process to acquire its database.
  #[default]
  NonDisruptive,
  /// Allows Windows to terminate processes that hold the selected database.
  AllowProcessShutdown,
}

/// An owned, builder-only request for an explicit Chromium cookie database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChromiumPathRequest {
  path: PathBuf,
  domains: Option<Vec<String>>,
  credentials: ChromiumCredentialSource,
  locked_database_policy: ChromiumLockedDatabasePolicy,
  timeout: Option<std::time::Duration>,
  cancellation: Option<crate::CancellationHandle>,
}

impl ChromiumPathRequest {
  /// Creates an automatic, non-disruptive request with no domain filter.
  pub fn new(path: impl Into<PathBuf>) -> Self {
    Self {
      path: path.into(),
      domains: None,
      credentials: ChromiumCredentialSource::Automatic,
      locked_database_policy: ChromiumLockedDatabasePolicy::NonDisruptive,
      timeout: None,
      cancellation: None,
    }
  }

  /// Restricts emitted cookies to the supplied domain boundaries.
  pub fn domains(mut self, domains: Vec<String>) -> Self {
    self.domains = Some(domains);
    self
  }

  /// Selects how decryption credentials are obtained.
  pub fn credentials(mut self, credentials: ChromiumCredentialSource) -> Self {
    self.credentials = credentials;
    self
  }

  /// Selects whether Windows may stop processes to acquire a locked database.
  pub fn locked_database_policy(mut self, policy: ChromiumLockedDatabasePolicy) -> Self {
    self.locked_database_policy = policy;
    self
  }

  /// Overrides the default 30-second extraction budget.
  pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
    self.timeout = Some(timeout);
    self
  }

  /// Lets `handle` cancel this request from another thread while it runs —
  /// see [`crate::CancellationHandle`].
  pub fn cancellation(mut self, handle: crate::CancellationHandle) -> Self {
    self.cancellation = Some(handle);
    self
  }
}

fn boundary_runtime_for<'a>(
  clock: &'a crate::common::deadline::SystemClock,
  timeout: Option<std::time::Duration>,
  cancellation: &Option<crate::CancellationHandle>,
) -> crate::common::deadline::BoundaryRuntime<'a> {
  crate::common::deadline::boundary_runtime(
    clock,
    timeout,
    cancellation
      .clone()
      .map(|handle| handle.0)
      .unwrap_or_default(),
  )
}

/// Extracts cookies after identifying the explicit source by signature/schema.
pub fn cookies_from_path(request: DirectPathRequest) -> Result<Vec<Cookie>> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = boundary_runtime_for(&clock, request.timeout, &request.cancellation);
  let source = classify_cookie_source(&request.path, &runtime)?;
  platform::cookies_from_path(request, source, &runtime)
}

/// Extracts cookies from an explicit Chromium SQLite database.
pub fn chromium_cookies_from_path(request: ChromiumPathRequest) -> Result<Vec<Cookie>> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = boundary_runtime_for(&clock, request.timeout, &request.cancellation);
  #[cfg(not(target_os = "windows"))]
  {
    let source = classify_cookie_source(&request.path, &runtime)?;
    require_chromium_source(&request.path, source)?;
  }
  platform::chromium_cookies_from_path(request, &runtime)
}

/// Detailed counterpart to [`chromium_cookies_from_path`].
pub fn chromium_cookies_from_path_detailed(
  request: ChromiumPathRequest,
) -> Result<Vec<DetailedCookie>> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = boundary_runtime_for(&clock, request.timeout, &request.cancellation);
  #[cfg(not(target_os = "windows"))]
  {
    let source = classify_cookie_source(&request.path, &runtime)?;
    require_chromium_source(&request.path, source)?;
  }
  platform::chromium_cookies_from_path_detailed(request, &runtime)
}

fn classify_cookie_source(
  path: &Path,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<CookieSourceKind> {
  platform::classify_cookie_source(path, runtime).map_err(|error| invalid_source_error(path, error))
}

fn invalid_source_error(path: &Path, error: anyhow::Error) -> anyhow::Error {
  let reason = shared::classification_reason(&error)
    .unwrap_or(InvalidCookieSourceReason::SourceInspectionFailed);
  error.context(DirectPathError::InvalidSource {
    path: path.to_path_buf(),
    reason,
  })
}

fn require_chromium_source(path: &Path, source: CookieSourceKind) -> Result<()> {
  if source == CookieSourceKind::ChromiumSqlite {
    return Ok(());
  }
  Err(
    DirectPathError::InvalidSource {
      path: path.to_path_buf(),
      reason: InvalidCookieSourceReason::ExpectedChromiumSqlite { actual: source },
    }
    .into(),
  )
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn invalid_options(reason: InvalidDirectPathOptionsReason) -> anyhow::Error {
  DirectPathError::InvalidOptions {
    source: CookieSourceKind::ChromiumSqlite,
    reason,
  }
  .into()
}

fn unsupported_target(source: CookieSourceKind) -> anyhow::Error {
  DirectPathError::UnsupportedTarget {
    source,
    target_os: std::env::consts::OS,
    target_arch: std::env::consts::ARCH,
  }
  .into()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn automatic_identities(
  ids: &[&'static str],
) -> Result<
  Vec<(
    &'static str,
    crate::browser::chromium_platform_keys::ChromiumKeyCredentials,
  )>,
> {
  ids
    .iter()
    .map(|id| Ok((*id, crate::browser::registry::registry_key_credentials(id)?)))
    .collect()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn automatic_chromium_cookies(
  ids: &[&'static str],
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  let identities = automatic_identities(ids)?;
  automatic_chromium_with(
    &identities,
    db_path,
    domains,
    runtime,
    crate::browser::chromium_platform_keys::HostKeySession::new,
    |session, _name, credentials, db_path, domains| {
      let outcomes = session.retrieve(
        crate::browser::chromium_platform_keys::ChromiumKeyRequest::direct(credentials),
        runtime,
      );
      crate::browser::chromium::chromium_based_probe_with_key_outcomes(
        outcomes, db_path, domains, false, runtime,
      )
    },
    |candidate| (candidate.cookie_count(), candidate.rows_skipped),
    |candidate| candidate.project_committed(),
  )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn automatic_chromium_detailed(
  ids: &[&'static str],
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<DetailedCookie>> {
  let identities = automatic_identities(ids)?;
  automatic_chromium_with(
    &identities,
    db_path,
    domains,
    runtime,
    crate::browser::chromium_platform_keys::HostKeySession::new,
    |session, _name, credentials, db_path, domains| {
      let outcomes = session.retrieve(
        crate::browser::chromium_platform_keys::ChromiumKeyRequest::direct(credentials),
        runtime,
      );
      crate::browser::chromium::chromium_based_detailed_probe_with_key_outcomes(
        outcomes, db_path, domains, false, runtime,
      )
    },
    |candidate| (candidate.cookie_count(), candidate.rows_skipped),
    |candidate| candidate.project_committed(),
  )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(clippy::too_many_arguments)]
fn automatic_chromium_with<Session, Candidate, Output, NewSession, Probe, Score, Finish>(
  identities: &[(
    &'static str,
    crate::browser::chromium_platform_keys::ChromiumKeyCredentials,
  )],
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
  new_session: NewSession,
  mut probe: Probe,
  score: Score,
  finish: Finish,
) -> Result<Output>
where
  NewSession: FnOnce() -> Session,
  Probe: FnMut(
    &mut Session,
    &'static str,
    &crate::browser::chromium_platform_keys::ChromiumKeyCredentials,
    PathBuf,
    Option<Vec<String>>,
  ) -> Result<Candidate>,
  Score: Fn(&Candidate) -> (usize, usize),
  Finish: FnOnce(Candidate) -> Result<Output>,
{
  let mut session = new_session();
  let mut best = None;
  let mut failures = Vec::new();
  for (name, credentials) in identities {
    // Before any completed candidate exists, a boundary stop is the request's
    // result. Once a candidate completes, it is committed: later probes may
    // fail or observe a stop, but cannot erase already-decoded work.
    if best.is_none() {
      runtime.check()?;
    }
    match probe(
      &mut session,
      name,
      credentials,
      db_path.clone(),
      domains.clone(),
    ) {
      Ok(candidate) => {
        let candidate_score = score(&candidate);
        let is_better = best.as_ref().is_none_or(|(_, current)| {
          let current_score = score(current);
          candidate_score.0 > current_score.0
            || (candidate_score.0 == current_score.0 && candidate_score.1 < current_score.1)
        });
        if is_better {
          best = Some((*name, candidate));
        }
      }
      Err(error) => {
        log::warn!("direct Chromium probe: {name} did not decode: {error}");
        failures.push(format!("{name}: {error}"));
      }
    }
  }
  if best.is_none() {
    runtime.check()?;
  }
  match best {
    Some((name, result)) => {
      let (cookies, rows_skipped) = score(&result);
      log::debug!(
        "direct Chromium probe selected identity {name} (cookies={}, rows_skipped={})",
        cookies,
        rows_skipped
      );
      finish(result)
    }
    None => anyhow::bail!(
      "no Chromium configuration decoded the cookie database:\n  {}",
      failures.join("\n  ")
    ),
  }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn legacy_automatic_chromium_with_runtime(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  platform::automatic_chromium(db_path, domains, runtime)
}

#[cfg(target_os = "windows")]
pub(crate) fn legacy_windows_chromium_with_runtime(
  local_state: PathBuf,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  let mut request = ChromiumPathRequest::new(db_path)
    .credentials(ChromiumCredentialSource::LocalStateFile(local_state));
  if let Some(domains) = domains {
    request = request.domains(domains);
  }
  if force_kill {
    request = request.locked_database_policy(ChromiumLockedDatabasePolicy::AllowProcessShutdown);
  }
  platform::chromium_cookies_from_path(request, runtime)
}

#[cfg(target_os = "windows")]
pub(crate) fn legacy_windows_chromium_detailed_with_runtime(
  local_state: PathBuf,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<DetailedCookie>> {
  let mut request = ChromiumPathRequest::new(db_path)
    .credentials(ChromiumCredentialSource::LocalStateFile(local_state));
  if let Some(domains) = domains {
    request = request.domains(domains);
  }
  if force_kill {
    request = request.locked_database_policy(ChromiumLockedDatabasePolicy::AllowProcessShutdown);
  }
  platform::chromium_cookies_from_path_detailed(request, runtime)
}

#[cfg(test)]
pub(crate) fn classify_cookie_source_legacy(path: &Path) -> Result<CookieSourceKind> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  classify_cookie_source_legacy_with_runtime(path, &runtime)
}

pub(crate) fn classify_cookie_source_legacy_with_runtime(
  path: &Path,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<CookieSourceKind> {
  match platform::classify_cookie_source(path, runtime) {
    #[cfg(not(target_os = "windows"))]
    Ok(CookieSourceKind::InternetExplorerEse) => {
      anyhow::bail!(
        "unsupported cookie source format: {}",
        crate::common::diagnostic::REDACTED_PATH
      )
    }
    Err(error)
      if shared::classification_reason(&error)
        == Some(InvalidCookieSourceReason::UnrecognizedSignature)
        && error.root_cause().to_string() == "unsupported cookie source signature" =>
    {
      anyhow::bail!(
        "unsupported cookie source format: {}",
        crate::common::diagnostic::REDACTED_PATH
      )
    }
    result => result,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::utils::TempDir;

  #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
  fn chromium_database(rows: &[(&str, &str, &[u8])]) -> (TempDir, PathBuf) {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("Cookies");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
      .execute_batch(
        "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT); \
         INSERT INTO meta (key, value) VALUES ('version', '23'); \
         CREATE TABLE cookies (\
           host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER, \
           name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER, \
           samesite INTEGER\
         );",
      )
      .unwrap();
    for (host, value, encrypted) in rows {
      connection
        .execute(
          "INSERT INTO cookies VALUES (?1, '/', 0, 0, 'session', ?2, ?3, 0, 0)",
          rusqlite::params![host, value, encrypted],
        )
        .unwrap();
    }
    drop(connection);
    (directory, path)
  }

  fn mozilla_database() -> (TempDir, PathBuf) {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("cookies.sqlite");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
      .execute_batch(
        "CREATE TABLE moz_cookies (
           host TEXT NOT NULL, path TEXT NOT NULL, isSecure INTEGER NOT NULL,
           expiry INTEGER NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
           isHttpOnly INTEGER NOT NULL, sameSite INTEGER NOT NULL
         );
         INSERT INTO moz_cookies VALUES
           ('.example.test', '/', 1, 0, 'portable', 'mozilla', 1, 0);",
      )
      .unwrap();
    drop(connection);
    (directory, path)
  }

  fn direct_path_error(error: &anyhow::Error) -> &DirectPathError {
    error
      .downcast_ref::<DirectPathError>()
      .expect("typed DirectPathError in anyhow chain")
  }

  #[test]
  fn invalid_source_is_typed_without_discarding_io_error() {
    let directory = TempDir::new().unwrap();
    let missing = directory
      .path()
      .join("absolute path sentinel with spaces")
      .join("missing");
    let error = cookies_from_path(DirectPathRequest::new(&missing)).unwrap_err();
    let typed = direct_path_error(&error);
    assert_eq!(typed.kind(), "invalid_source");
    assert_eq!(typed.code(), "not_a_regular_file");
    assert_eq!(typed.path(), Some(missing.as_path()));
    assert_eq!(
      typed.invalid_source_reason(),
      Some(&InvalidCookieSourceReason::NotARegularFile)
    );
    assert!(error.downcast_ref::<std::io::Error>().is_some());
    let diagnostic = format!("{error:#}");
    assert!(!diagnostic.contains(missing.to_string_lossy().as_ref()));
    assert!(diagnostic.contains(crate::common::diagnostic::REDACTED_PATH));
    assert!(!format!("{typed:?}").contains(missing.to_string_lossy().as_ref()));
  }

  #[test]
  fn operational_sqlite_failures_have_an_inspection_code_and_keep_the_cause() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("corrupt.sqlite");
    std::fs::write(&path, b"SQLite format 3\0corrupt fixture").unwrap();

    let error = cookies_from_path(DirectPathRequest::new(&path)).unwrap_err();
    let typed = direct_path_error(&error);
    assert_eq!(typed.kind(), "invalid_source");
    assert_eq!(typed.code(), "source_inspection_failed");
    assert_eq!(typed.path(), Some(path.as_path()));
    assert_eq!(
      typed.invalid_source_reason(),
      Some(&InvalidCookieSourceReason::SourceInspectionFailed)
    );
    assert!(
      error
        .downcast_ref::<crate::common::sqlite::BrowserDatabaseFailure>()
        .is_some(),
      "the SQLite acquisition/query cause remains downcastable: {error:#}"
    );
  }

  #[test]
  fn explicit_chromium_rejects_a_recognized_mozilla_source_before_options() {
    let (_directory, path) = mozilla_database();
    let request = ChromiumPathRequest::new(&path)
      .credentials(ChromiumCredentialSource::BrowserId(String::new()))
      .locked_database_policy(ChromiumLockedDatabasePolicy::AllowProcessShutdown);
    let error = chromium_cookies_from_path(request).unwrap_err();
    let typed = direct_path_error(&error);
    assert_eq!(typed.code(), "expected_chromium_sqlite");
    assert_eq!(typed.source_kind(), Some(CookieSourceKind::MozillaSqlite));
    assert_eq!(typed.target_os(), None);
  }

  #[test]
  fn mozilla_direct_path_is_available_on_every_compile_target() {
    let (_directory, path) = mozilla_database();
    let cookies = cookies_from_path(DirectPathRequest::new(path)).unwrap();
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "portable");
    assert_eq!(cookies[0].value, "mozilla");
  }

  #[test]
  fn direct_path_request_zero_timeout_stops_a_real_extraction() {
    let (_directory, path) = mozilla_database();
    let error = cookies_from_path(DirectPathRequest::new(path).timeout(std::time::Duration::ZERO))
      .expect_err("a zero timeout must stop before reading the real database");
    assert_eq!(
      crate::stop_reason(&error),
      Some(crate::StopReason::TimedOut)
    );
    // A timeout checked during source classification still gets wrapped in a
    // `DirectPathError` (inspection failed, for whichever reason); `fault_kind`
    // must not read that wrapping as a caller input mistake.
    assert_eq!(crate::fault_kind(&error), crate::FaultKind::Engine);
  }

  #[test]
  fn direct_path_request_cancelled_handle_stops_a_real_extraction() {
    let (_directory, path) = mozilla_database();
    let handle = crate::CancellationHandle::new();
    handle.cancel();
    let error = cookies_from_path(DirectPathRequest::new(path).cancellation(handle))
      .expect_err("a pre-cancelled handle must stop before reading the real database");
    assert_eq!(
      crate::stop_reason(&error),
      Some(crate::StopReason::Cancelled)
    );
  }

  #[test]
  fn direct_path_request_with_a_generous_timeout_still_succeeds() {
    let (_directory, path) = mozilla_database();
    let cookies =
      cookies_from_path(DirectPathRequest::new(path).timeout(std::time::Duration::from_secs(30)))
        .expect("a generous explicit timeout must not interfere with a real extraction");
    assert_eq!(cookies.len(), 1);
  }

  #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
  #[test]
  fn plaintext_only_rejects_any_encrypted_row_before_domain_projection() {
    let (_directory, path) = chromium_database(&[
      ("wanted.test", "plaintext", b""),
      ("outside.test", "", b"v10encrypted"),
    ]);
    let error = chromium_cookies_from_path(
      ChromiumPathRequest::new(path)
        .domains(vec!["wanted.test".to_owned()])
        .credentials(ChromiumCredentialSource::PlaintextOnly),
    )
    .expect_err("plaintext-only is a whole-request guarantee");
    assert!(error.to_string().contains("no browser key identity"));
  }

  #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
  #[test]
  fn plaintext_only_checks_encryption_before_malformed_row_projection() {
    let (_directory, path) = chromium_database(&[("wanted.test", "plaintext", b"")]);
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
      .execute(
        "INSERT INTO cookies VALUES (X'FF', '/', 0, 0, 'hidden', '', \
         X'763130656e63727970746564', 0, 0)",
        [],
      )
      .unwrap();
    drop(connection);

    for detailed in [false, true] {
      let request = ChromiumPathRequest::new(&path)
        .domains(vec!["wanted.test".to_owned()])
        .credentials(ChromiumCredentialSource::PlaintextOnly);
      let error = if detailed {
        chromium_cookies_from_path_detailed(request)
          .map(|_| ())
          .expect_err("detailed plaintext-only request must not skip an encrypted malformed row")
      } else {
        chromium_cookies_from_path(request)
          .map(|_| ())
          .expect_err("legacy plaintext-only request must not skip an encrypted malformed row")
      };
      assert!(error.to_string().contains("no browser key identity"));
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
  #[test]
  fn plaintext_only_supports_legacy_and_detailed_projection() {
    let (_directory, path) = chromium_database(&[("example.test", "value", b"")]);
    let cookies = chromium_cookies_from_path(
      ChromiumPathRequest::new(&path).credentials(ChromiumCredentialSource::PlaintextOnly),
    )
    .unwrap();
    let detailed = chromium_cookies_from_path_detailed(
      ChromiumPathRequest::new(&path).credentials(ChromiumCredentialSource::PlaintextOnly),
    )
    .unwrap();
    assert_eq!(cookies.len(), 1);
    assert_eq!(detailed.len(), 1);
    assert_eq!(cookies[0].name, detailed[0].cookie.name);
    assert_eq!(cookies[0].value, detailed[0].cookie.value);
  }

  #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
  #[test]
  fn chromium_path_request_zero_timeout_stops_a_real_extraction() {
    let (_directory, path) = chromium_database(&[("example.test", "value", b"")]);
    let request = ChromiumPathRequest::new(&path)
      .credentials(ChromiumCredentialSource::PlaintextOnly)
      .timeout(std::time::Duration::ZERO);
    let error = chromium_cookies_from_path(request)
      .expect_err("a zero timeout must stop before reading the real database");
    assert_eq!(
      crate::stop_reason(&error),
      Some(crate::StopReason::TimedOut)
    );
  }

  #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
  #[test]
  fn chromium_path_request_cancelled_handle_stops_a_real_extraction() {
    let (_directory, path) = chromium_database(&[("example.test", "value", b"")]);
    let handle = crate::CancellationHandle::new();
    handle.cancel();
    let request = ChromiumPathRequest::new(&path)
      .credentials(ChromiumCredentialSource::PlaintextOnly)
      .cancellation(handle);
    let error = chromium_cookies_from_path(request)
      .expect_err("a pre-cancelled handle must stop before reading the real database");
    assert_eq!(
      crate::stop_reason(&error),
      Some(crate::StopReason::Cancelled)
    );
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn automatic_selection_preserves_identity_order_ties_and_one_session() {
    #[derive(Debug)]
    struct Candidate {
      identity: &'static str,
      cookies: usize,
      rows_skipped: usize,
    }

    let identities = [
      (
        "first",
        crate::browser::chromium_platform_keys::ChromiumKeyCredentials::default(),
      ),
      (
        "second",
        crate::browser::chromium_platform_keys::ChromiumKeyCredentials::default(),
      ),
      (
        "third",
        crate::browser::chromium_platform_keys::ChromiumKeyCredentials::default(),
      ),
    ];
    let sessions = std::cell::Cell::new(0);
    let mut probed = Vec::new();
    let clock = crate::common::deadline::SystemClock;
    let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
    let selected = automatic_chromium_with(
      &identities,
      PathBuf::from("unused"),
      None,
      &runtime,
      || {
        sessions.set(sessions.get() + 1);
      },
      |(), name, _credentials, _path, _domains| {
        probed.push(name);
        Ok(Candidate {
          identity: name,
          cookies: if name == "first" { 1 } else { 2 },
          rows_skipped: 0,
        })
      },
      |candidate| (candidate.cookies, candidate.rows_skipped),
      |candidate| Ok(candidate.identity),
    )
    .unwrap();

    #[cfg(target_os = "linux")]
    assert_eq!(
      platform::AUTOMATIC_BROWSER_IDS,
      ["chrome", "brave", "chromium", "edge", "opera", "vivaldi", "arc"]
    );
    #[cfg(target_os = "macos")]
    assert_eq!(
      platform::AUTOMATIC_BROWSER_IDS,
      ["chrome", "brave", "chromium", "edge", "opera", "vivaldi", "arc", "opera_gx",]
    );
    assert_eq!(selected, "second", "an exact tie keeps the earlier ID");
    assert_eq!(probed, vec!["first", "second", "third"]);
    assert_eq!(sessions.get(), 1);
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn automatic_selection_preserves_a_completed_candidate_through_later_stops() {
    #[derive(Debug)]
    struct Candidate(&'static str);

    let identities = [
      (
        "first",
        crate::browser::chromium_platform_keys::ChromiumKeyCredentials::default(),
      ),
      (
        "second",
        crate::browser::chromium_platform_keys::ChromiumKeyCredentials::default(),
      ),
    ];
    let clock = crate::common::deadline::test_clock::ManualClock::default();
    let stop = crate::common::deadline::CancellationToken::default();
    let runtime = crate::common::deadline::BoundaryRuntime::with_stop(
      &clock,
      crate::common::deadline::Deadline::after(&clock, std::time::Duration::from_secs(1)),
      stop.clone(),
    );
    let mut probes = Vec::new();

    let selected = automatic_chromium_with(
      &identities,
      PathBuf::from("unused"),
      None,
      &runtime,
      || (),
      |(), name, _credentials, _path, _domains| {
        probes.push(name);
        if name == "first" {
          stop.cancel();
          Ok(Candidate(name))
        } else {
          runtime.check()?;
          unreachable!("the stopped second probe cannot produce a candidate")
        }
      },
      |_| (1, 0),
      |candidate| {
        assert_eq!(
          runtime.check(),
          Err(crate::common::deadline::BoundaryStop::Cancelled),
          "finish observes the racing stop without discarding the committed candidate"
        );
        Ok(candidate.0)
      },
    )
    .expect("completed candidate survives leading, post-loop, and finish stop checks");

    assert_eq!(selected, "first");
    assert_eq!(probes, vec!["first", "second"]);
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn automatic_selection_preserves_all_failures_and_one_session_per_projection() {
    let identities = [
      (
        "chrome",
        crate::browser::chromium_platform_keys::ChromiumKeyCredentials::default(),
      ),
      (
        "brave",
        crate::browser::chromium_platform_keys::ChromiumKeyCredentials::default(),
      ),
    ];
    let sessions = std::cell::Cell::new(0);
    let clock = crate::common::deadline::SystemClock;
    let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
    for projection in ["legacy", "detailed"] {
      let error = automatic_chromium_with(
        &identities,
        PathBuf::from("unused"),
        None,
        &runtime,
        || sessions.set(sessions.get() + 1),
        |(), name, _credentials, _path, _domains| -> Result<()> {
          anyhow::bail!("{projection} {name} keyring is locked")
        },
        |()| (0, 0),
        |()| Ok(()),
      )
      .unwrap_err();
      let diagnostic = error.to_string();
      assert!(
        diagnostic.contains(&format!("chrome: {projection} chrome keyring is locked")),
        "{diagnostic}"
      );
      assert!(
        diagnostic.contains(&format!("brave: {projection} brave keyring is locked")),
        "{diagnostic}"
      );
    }
    assert_eq!(
      sessions.get(),
      2,
      "one fresh session per projection request"
    );
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn browser_id_validation_is_typed_and_precedes_key_access() {
    let (_directory, path) = chromium_database(&[]);
    for (browser_id, expected) in [
      ("", InvalidDirectPathOptionsReason::EmptyBrowserId),
      (
        "not-a-browser",
        InvalidDirectPathOptionsReason::UnknownBrowserId,
      ),
      (
        "firefox",
        InvalidDirectPathOptionsReason::BrowserIdIsNotChromium,
      ),
    ] {
      let error = chromium_cookies_from_path(
        ChromiumPathRequest::new(&path)
          .credentials(ChromiumCredentialSource::BrowserId(browser_id.to_owned())),
      )
      .unwrap_err();
      assert_eq!(
        direct_path_error(&error).invalid_options_reason(),
        Some(&expected)
      );
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn unsupported_native_chromium_options_fail_before_credential_io() {
    let (_directory, path) = chromium_database(&[]);
    let local_state = PathBuf::from("this path must never be read");
    let local_state_error = chromium_cookies_from_path(
      ChromiumPathRequest::new(&path)
        .credentials(ChromiumCredentialSource::LocalStateFile(local_state)),
    )
    .unwrap_err();
    assert_eq!(
      direct_path_error(&local_state_error).invalid_options_reason(),
      Some(&InvalidDirectPathOptionsReason::LocalStateNotSupportedOnTarget)
    );

    let shutdown_error = chromium_cookies_from_path(
      ChromiumPathRequest::new(path)
        .credentials(ChromiumCredentialSource::BrowserId("chrome".to_owned()))
        .locked_database_policy(ChromiumLockedDatabasePolicy::AllowProcessShutdown),
    )
    .unwrap_err();
    assert_eq!(
      direct_path_error(&shutdown_error).invalid_options_reason(),
      Some(&InvalidDirectPathOptionsReason::ProcessShutdownNotSupportedOnTarget)
    );
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn windows_chromium_options_keep_the_explicit_credential_contract() {
    let (_directory, path) = chromium_database(&[]);

    let generic_error = cookies_from_path(DirectPathRequest::new(&path)).unwrap_err();
    assert_eq!(
      direct_path_error(&generic_error).invalid_options_reason(),
      Some(&InvalidDirectPathOptionsReason::MissingLocalStateFile)
    );

    for request in [
      ChromiumPathRequest::new(&path),
      ChromiumPathRequest::new(&path)
        .credentials(ChromiumCredentialSource::LocalStateFile(PathBuf::new())),
    ] {
      let error = chromium_cookies_from_path(request).unwrap_err();
      assert_eq!(
        direct_path_error(&error).invalid_options_reason(),
        Some(&InvalidDirectPathOptionsReason::MissingLocalStateFile)
      );
    }

    for (browser_id, expected) in [
      ("", InvalidDirectPathOptionsReason::EmptyBrowserId),
      (
        "chrome",
        InvalidDirectPathOptionsReason::BrowserIdNotSupportedOnTarget,
      ),
    ] {
      let error = chromium_cookies_from_path(
        ChromiumPathRequest::new(&path)
          .credentials(ChromiumCredentialSource::BrowserId(browser_id.to_owned())),
      )
      .unwrap_err();
      assert_eq!(
        direct_path_error(&error).invalid_options_reason(),
        Some(&expected)
      );
    }

    let cookies = chromium_cookies_from_path(
      ChromiumPathRequest::new(path)
        .credentials(ChromiumCredentialSource::PlaintextOnly)
        .locked_database_policy(ChromiumLockedDatabasePolicy::AllowProcessShutdown),
    )
    .unwrap();
    assert!(cookies.is_empty());
  }

  #[cfg(target_os = "macos")]
  #[test]
  fn browser_without_target_credentials_reads_plaintext_but_rejects_encrypted_rows() {
    let (_plain_directory, plain_path) = chromium_database(&[("example.test", "plaintext", b"")]);
    let cookies = chromium_cookies_from_path(
      ChromiumPathRequest::new(plain_path)
        .credentials(ChromiumCredentialSource::BrowserId("coccoc".to_owned())),
    )
    .unwrap();
    assert_eq!(cookies[0].value, "plaintext");

    let (_encrypted_directory, encrypted_path) =
      chromium_database(&[("example.test", "", b"v10encrypted")]);
    let error = chromium_cookies_from_path(
      ChromiumPathRequest::new(encrypted_path)
        .credentials(ChromiumCredentialSource::BrowserId("coccoc".to_owned())),
    )
    .unwrap_err();
    let diagnostic = format!("{error:#}");
    assert!(diagnostic.contains("has no"), "{diagnostic}");
    assert!(diagnostic.contains("identity"), "{diagnostic}");
  }

  #[test]
  fn unsupported_target_accessors_are_stable() {
    let error = DirectPathError::UnsupportedTarget {
      source: CookieSourceKind::SafariBinaryCookies,
      target_os: "freebsd",
      target_arch: "x86_64",
    };
    assert_eq!(error.kind(), "unsupported_target");
    assert_eq!(error.code(), "unsupported_target");
    assert_eq!(
      error.source_kind(),
      Some(CookieSourceKind::SafariBinaryCookies)
    );
    assert_eq!(error.target_os(), Some("freebsd"));
    assert_eq!(error.target_arch(), Some("x86_64"));
  }

  #[cfg(not(target_os = "macos"))]
  #[test]
  fn safari_signature_returns_typed_unsupported_before_parser_io() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("Cookies.binarycookies");
    std::fs::write(&path, b"cookfixture").unwrap();
    let error = cookies_from_path(DirectPathRequest::new(path)).unwrap_err();
    assert!(matches!(
      direct_path_error(&error),
      DirectPathError::UnsupportedTarget {
        source: CookieSourceKind::SafariBinaryCookies,
        ..
      }
    ));
  }

  #[cfg(not(target_os = "windows"))]
  #[test]
  fn ie_signature_returns_typed_unsupported_before_parser_io() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("WebCacheV01.dat");
    std::fs::write(&path, [0, 0, 0, 0, 0xef, 0xcd, 0xab, 0x89]).unwrap();
    let error = cookies_from_path(DirectPathRequest::new(path)).unwrap_err();
    assert!(matches!(
      direct_path_error(&error),
      DirectPathError::UnsupportedTarget {
        source: CookieSourceKind::InternetExplorerEse,
        ..
      }
    ));
  }

  #[cfg(not(target_os = "windows"))]
  #[test]
  fn legacy_classifier_keeps_ie_magic_unrecognized_off_windows() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("WebCacheV01.dat");
    std::fs::write(&path, [0, 0, 0, 0, 0xef, 0xcd, 0xab, 0x89]).unwrap();
    let error = classify_cookie_source_legacy(&path).unwrap_err();
    assert_eq!(
      error.to_string(),
      "unsupported cookie source format: <path>"
    );
  }

  #[test]
  fn legacy_classifier_keeps_the_historical_unknown_format_message() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("unknown.cookies");
    std::fs::write(&path, b"not a cookie store").unwrap();
    let error = classify_cookie_source_legacy(&path).unwrap_err();
    assert_eq!(
      error.to_string(),
      "unsupported cookie source format: <path>"
    );
  }
}
