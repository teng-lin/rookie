//! Typed, cross-platform extraction from an explicit browser cookie source.
//!
//! This module is the canonical Rust API for paths supplied by a caller. It
//! identifies the source before selecting a target capability, so unsupported
//! platforms and invalid options are reported as stable, downcastable errors.

pub(crate) mod shared;

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
use crate::execution::{AppBoundPolicy, ExecutionControl};
use crate::RequestError;
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
  /// The source could not be inspected because an I/O or SQLite operation
  /// failed. Public jobs classify this operational reason as
  /// [`crate::Error::Engine`], while preserving `source_inspection_failed` as
  /// the stable code; other invalid-source reasons remain [`crate::Error::Source`].
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
  /// A Chromium database was recognized but the request named no credential
  /// source, so only plaintext rows are readable.
  MissingChromiumCredentials,
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
      Self::MissingChromiumCredentials => "missing_chromium_credentials",
    }
  }
}

/// A stable direct-path classification error carried inside the returned
/// [`anyhow::Error`] chain.
///
/// Most variants describe caller-correctable input and become
/// [`crate::Error::Source`]. [`InvalidCookieSourceReason::SourceInspectionFailed`]
/// preserves its public typed reason here but becomes [`crate::Error::Engine`]
/// at a public job edge because changing the request cannot repair an
/// operational I/O or SQLite failure.
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

/// An owned request for one explicit cookie file.
///
/// **New in 0.6.0**, replacing `DirectPathRequest` and `ChromiumPathRequest`.
/// `DirectPathRequest` was `ChromiumPathRequest` minus credentials minus the
/// locked-database policy, so the pair was one type split by whether the
/// caller happened to know the file was Chromium -- a distinction that belongs
/// in the credential *value*, not in the type. The split also produced a live
/// asymmetry, where only one of them could ask for expired rows.
///
/// There is deliberately no `new`. A credential strategy is chosen at
/// construction, so a request that cannot succeed on the target it was
/// compiled for cannot be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathExtractRequest {
  pub(crate) target: PathTarget,
  pub(crate) domains: Option<Vec<String>>,
  pub(crate) control: ExecutionControl,
}

/// Crate-private state shared by both path jobs, so the credential check and
/// the locked-database policy are written once rather than per request type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathTarget {
  pub(crate) path: PathBuf,
  pub(crate) credentials: Option<ChromiumCredentialSource>,
  pub(crate) locked_database_policy: ChromiumLockedDatabasePolicy,
}

impl PathExtractRequest {
  /// Reads an encrypted Chromium database using one registry browser identity
  /// (Linux keyring / macOS Keychain).
  ///
  /// Unix-only, because a registry identity means nothing on Windows. The body
  /// lives in the platform leaf so `direct_path/mod.rs` gains no platform
  /// `cfg` beyond the selection gate here.
  #[cfg(unix)]
  pub fn unix_identity(path: impl Into<PathBuf>, browser_id: impl Into<String>) -> Self {
    platform::unix_identity(path, browser_id)
  }

  /// Reads an encrypted Chromium database using a caller-supplied
  /// `Local State` file. Windows-only, for the same reason in reverse.
  #[cfg(windows)]
  pub fn windows_local_state(path: impl Into<PathBuf>, local_state: impl Into<PathBuf>) -> Self {
    platform::windows_local_state(path, local_state)
  }

  /// Reads only plaintext rows. Portable, and fails the whole request if any
  /// row is encrypted.
  pub fn plaintext(path: impl Into<PathBuf>) -> Self {
    Self::with_credentials(path, Some(ChromiumCredentialSource::PlaintextOnly))
  }

  /// Identifies the source from its signature and schema, with no credentials.
  ///
  /// A Mozilla, Safari, or Internet Explorer store needs none. A Chromium
  /// store is then plaintext-capable only: an encrypted row is
  /// `missing_chromium_credentials` rather than a guess at which browser wrote
  /// it. On Unix this is a real narrowing -- `cookies_from_path` used to probe
  /// every registry identity. On Windows it is a widening: that call returned
  /// `missing_local_state_file` before attempting extraction, so even a fully
  /// plaintext database failed.
  pub fn sniff(path: impl Into<PathBuf>) -> Self {
    Self::with_credentials(path, None)
  }

  pub(crate) fn with_credentials(
    path: impl Into<PathBuf>,
    credentials: Option<ChromiumCredentialSource>,
  ) -> Self {
    Self {
      target: PathTarget {
        path: path.into(),
        credentials,
        locked_database_policy: ChromiumLockedDatabasePolicy::NonDisruptive,
      },
      domains: None,
      control: ExecutionControl::default(),
    }
  }

  /// Restricts emitted cookies to the supplied domain boundaries, or clears a
  /// prior restriction on `None`.
  pub fn domains(mut self, domains: Option<Vec<String>>) -> Self {
    self.domains = domains;
    self
  }

  /// Selects whether Windows may stop processes to acquire a locked database.
  pub fn locked_database_policy(mut self, policy: ChromiumLockedDatabasePolicy) -> Self {
    self.target.locked_database_policy = policy;
    self
  }

  /// Overrides the default 30-second extraction budget.
  pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
    self.control = self.control.timeout(timeout);
    self
  }

  /// Lets `handle` cancel this request from another thread while it runs --
  /// see [`crate::CancellationHandle`].
  pub fn cancellation(mut self, handle: crate::CancellationHandle) -> Self {
    self.control = self.control.cancellation(handle);
    self
  }

  /// Selects the Windows App-Bound (v20) recovery policy for this request.
  pub fn app_bound(mut self, policy: AppBoundPolicy) -> Self {
    self.control = self.control.app_bound(policy);
    self
  }

  /// Replaces this request's execution control **wholesale**, discarding an
  /// earlier `timeout` / `cancellation` / `app_bound` call.
  pub fn execution(mut self, control: ExecutionControl) -> Self {
    self.control = control;
    self
  }
}

/// How an explicit Chromium request obtains decryption credentials.
///
/// **`Automatic` was removed in 0.6.0.** It was the default on
/// `ChromiumPathRequest::new`, it worked on Unix through a historical ordered
/// identity probe, and it could never succeed on Windows -- every Windows
/// request built that way returned `missing_local_state_file` before
/// attempting extraction. A default that cannot work on one of three
/// platforms is a defect in the default, not a property of direct-path
/// extraction, so a strategy valid for the target is now chosen at
/// construction.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChromiumCredentialSource {
  /// Rejects the entire request if any row is encrypted.
  PlaintextOnly,
  /// Uses one exact registry browser identity. Invalid on Windows.
  BrowserId(String),
  /// Uses a caller-supplied Windows Chromium Local State file. Invalid on
  /// Unix.
  LocalStateFile(PathBuf),
}

impl ChromiumCredentialSource {
  /// Builds the one portable credential value represented by flattened
  /// binding/CLI options.
  ///
  /// The three selectors are mutually exclusive. Keeping the count and
  /// construction here prevents adapters from silently developing different
  /// priority orders when more than one is present.
  pub fn from_selectors(
    browser_id: Option<String>,
    local_state_path: Option<PathBuf>,
    plaintext_only: bool,
  ) -> Result<Option<Self>, RequestError> {
    let selector_count = usize::from(browser_id.is_some())
      + usize::from(local_state_path.is_some())
      + usize::from(plaintext_only);
    if selector_count > 1 {
      return Err(RequestError::ConflictingCredentialSelectors);
    }

    Ok(if let Some(browser_id) = browser_id {
      Some(Self::BrowserId(browser_id))
    } else if let Some(local_state_path) = local_state_path {
      Some(Self::LocalStateFile(local_state_path))
    } else if plaintext_only {
      Some(Self::PlaintextOnly)
    } else {
      None
    })
  }
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

/// Extracts cookies from one explicit cookie file.
///
/// **New in 0.6.0**, replacing `cookies_from_path`,
/// `chromium_cookies_from_path`, and `chromium_cookies_from_path_detailed`.
/// The Chromium-vs-sniff distinction is carried by the request's credential
/// value rather than by three functions.
///
/// Detailed (isolation-carrying) output from a path now comes from
/// [`crate::from_path`]`(..).detailed_cookies()`, which is the same rule the
/// browser axis already follows.
///
/// # Examples
///
/// ```no_run
/// use rookie_cookies::direct_path::{extract_from_path, PathExtractRequest};
///
/// let cookies = extract_from_path(
///   PathExtractRequest::plaintext("/path/to/Cookies")
///     .domains(Some(vec!["example.com".to_owned()])),
/// )?;
/// println!("{}", cookies.len());
/// # Ok::<(), rookie_cookies::Error>(())
/// ```
pub fn extract_from_path(request: PathExtractRequest) -> crate::Result<Vec<Cookie>> {
  crate::error::map_job_result(extract_from_path_inner(request))
}

pub(crate) fn extract_from_path_inner(request: PathExtractRequest) -> Result<Vec<Cookie>> {
  Ok(
    detailed_from_path_inner(request)?
      .into_iter()
      // A7 applies here for the same reason it applies to `extract`: a row
      // whose host did not survive decode would otherwise be handed back as
      // `Cookie { domain: "", .. }`, which matches nothing and belongs to no
      // site. The filter lives here rather than in `detailed_from_path_inner`
      // because `from_path` calls that seam and does its own omission *with*
      // a warning count; a bare `Vec<Cookie>` has no channel to report the
      // count through, which is the stated cost of this shape.
      .filter(|detailed| {
        crate::browser::cookie_record::host_identity_survives(&detailed.cookie.domain)
      })
      .map(DetailedCookie::into_cookie)
      .collect(),
  )
}

/// The detailed seam behind both [`extract_from_path`] and
/// [`crate::from_path`].
///
/// `from_path` is a snapshot job, so it must keep isolation; the flat function
/// above projects it away at its own edge rather than in the middle of the
/// pipeline, which is where the projection used to be lost.
pub(crate) fn detailed_from_path_inner(request: PathExtractRequest) -> Result<Vec<DetailedCookie>> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::runtime_for_control(&clock, &request.control);
  platform::detailed_from_path(request, &runtime)
}

type ClassifyCookieSourceFn = for<'path, 'runtime, 'clock> fn(
  &'path Path,
  &'runtime crate::common::deadline::BoundaryRuntime<'clock>,
) -> Result<CookieSourceKind>;

type DetailedFromPathFn = for<'runtime, 'clock> fn(
  PathExtractRequest,
  &'runtime crate::common::deadline::BoundaryRuntime<'clock>,
) -> Result<Vec<DetailedCookie>>;

// These coercions are the platform-facade contract: every selected leaf must
// classify and execute direct-path requests through the same signatures.
const _: ClassifyCookieSourceFn = platform::classify_cookie_source;
const _: DetailedFromPathFn = platform::detailed_from_path;

fn classify_cookie_source(
  path: &Path,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<CookieSourceKind> {
  platform::classify_cookie_source(path, runtime).map_err(|error| invalid_source_error(path, error))
}

fn classify_request_source(
  request: &PathExtractRequest,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<CookieSourceKind> {
  let source = classify_cookie_source(&request.target.path, runtime)?;
  if request.target.credentials.is_some() {
    require_chromium_source(&request.target.path, source)?;
  }
  Ok(source)
}

/// Relabel a credential-less Chromium failure as `missing_chromium_credentials`
/// only when that is genuinely the cause.
///
/// A sniffed Chromium database is attempted plaintext-only. Wrapping *every*
/// failure from that attempt told a caller to supply credentials even when the
/// database was corrupt, a column was absent, or the query itself failed --
/// advice that cannot help, on an error that is an engine fault rather than a
/// caller-fixable one. Shared by all three platform leaves, which each had
/// their own copy of the unconditional wrapper.
fn sniffed_chromium_error(error: anyhow::Error) -> anyhow::Error {
  if crate::browser::chromium::is_missing_browser_key_identity(&error) {
    error.context(DirectPathError::InvalidOptions {
      source: CookieSourceKind::ChromiumSqlite,
      reason: InvalidDirectPathOptionsReason::MissingChromiumCredentials,
    })
  } else {
    error
  }
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
    crate::browser::chromium_platform_keys::ChromiumKeyIdentity,
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
      crate::browser::chromium_projection::chromium_based_probe_with_key_outcomes(
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
    crate::browser::chromium_platform_keys::ChromiumKeyIdentity,
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
    &crate::browser::chromium_platform_keys::ChromiumKeyIdentity,
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
  Ok(
    legacy_windows_chromium_detailed_with_runtime(
      local_state,
      db_path,
      domains,
      force_kill,
      runtime,
    )?
    .into_iter()
    .map(DetailedCookie::into_cookie)
    .collect(),
  )
}

#[cfg(target_os = "windows")]
pub(crate) fn legacy_windows_chromium_detailed_with_runtime(
  local_state: PathBuf,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<DetailedCookie>> {
  let mut request = PathExtractRequest::with_credentials(
    db_path,
    Some(ChromiumCredentialSource::LocalStateFile(local_state)),
  );
  request = request.domains(domains);
  if force_kill {
    request = request.locked_database_policy(ChromiumLockedDatabasePolicy::AllowProcessShutdown);
  }
  // The uniform platform facade detects the Windows credential-bearing request
  // and delegates before classification, because a locked database has to be
  // recovered before it can be classified at all.
  platform::detailed_from_path(request, runtime)
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
mod tests;
