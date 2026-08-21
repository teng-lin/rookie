//! Typed errors returned by the 0.6 public job surface.

use crate::common::deadline::BoundaryStop;
use crate::direct_path::DirectPathError;
use crate::{FaultKind, RequestError, StopReason};
use std::fmt;

/// A stable engine-failure category with a sanitized human message.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineError {
  code: &'static str,
  message: String,
}

impl EngineError {
  /// Stable machine-readable failure code.
  pub fn code(&self) -> &'static str {
    self.code
  }

  /// Sanitized human-readable diagnostic. Callers must not parse it.
  pub fn message(&self) -> &str {
    &self.message
  }

  pub(crate) fn from_cause(cause: EngineCause, error: &anyhow::Error) -> Self {
    Self {
      code: cause.code(),
      message: crate::common::diagnostic::sanitize(&format!("{error:#}")),
    }
  }

  pub(crate) fn from_anyhow(error: anyhow::Error) -> Self {
    Self {
      code: "engine_failure",
      message: crate::common::diagnostic::sanitize(&format!("{error:#}")),
    }
  }
}

impl fmt::Display for EngineError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(&self.message)
  }
}

impl std::error::Error for EngineError {}

/// One typed error hierarchy for public snapshot, extract, report, and list jobs.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
  /// Invalid caller input.
  Request(RequestError),
  /// Cooperative timeout, cancellation, or resource stop.
  Stopped(StopReason),
  /// A caller-supplied path or path option was invalid.
  Source(DirectPathError),
  /// Discovery, acquisition, decryption, or another engine failure.
  Engine(EngineError),
}

impl Error {
  /// Stable machine-readable code for this error.
  pub fn code(&self) -> &'static str {
    match self {
      Self::Request(error) => error.code(),
      Self::Source(error) => error.code(),
      Self::Engine(error) => error.code(),
      Self::Stopped(StopReason::TimedOut) => "timed_out",
      Self::Stopped(StopReason::Cancelled) => "cancelled",
      Self::Stopped(StopReason::ResourceExhausted) => "resource_exhausted",
    }
  }

  /// Returns the cooperative stop reason, if this is a stopped job.
  pub fn stop_reason(&self) -> Option<StopReason> {
    match self {
      Self::Stopped(reason) => Some(*reason),
      _ => None,
    }
  }

  /// Returns the deprecated two-way FFI classification.
  #[deprecated(
    since = "0.6.0",
    note = "match Error; FaultKind is a two-way FFI split"
  )]
  pub fn fault_kind(&self) -> FaultKind {
    match self {
      Self::Request(_) | Self::Source(_) => FaultKind::Request,
      Self::Stopped(_) | Self::Engine(_) => FaultKind::Engine,
    }
  }

  pub(crate) fn stopped(stop: BoundaryStop) -> Self {
    Self::Stopped(match stop {
      BoundaryStop::TimedOut => StopReason::TimedOut,
      BoundaryStop::Cancelled => StopReason::Cancelled,
      BoundaryStop::ResourceExhausted => StopReason::ResourceExhausted,
    })
  }
}

impl fmt::Display for Error {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Request(error) => error.fmt(formatter),
      Self::Stopped(StopReason::TimedOut) => formatter.write_str("operation timed out"),
      Self::Stopped(StopReason::Cancelled) => formatter.write_str("operation was cancelled"),
      Self::Stopped(StopReason::ResourceExhausted) => {
        formatter.write_str("operation exhausted an internal resource limit")
      }
      Self::Source(error) => error.fmt(formatter),
      Self::Engine(error) => error.fmt(formatter),
    }
  }
}

impl std::error::Error for Error {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::Request(error) => Some(error),
      Self::Source(error) => Some(error),
      Self::Stopped(_) | Self::Engine(_) => None,
    }
  }
}

impl From<RequestError> for Error {
  fn from(error: RequestError) -> Self {
    Self::Request(error)
  }
}

impl From<DirectPathError> for Error {
  fn from(error: DirectPathError) -> Self {
    Self::Source(error)
  }
}

impl From<anyhow::Error> for Error {
  /// Classifies an `anyhow` chain into the typed hierarchy.
  ///
  /// The v0.5.9 bridge functions kept through 0.6.x still return
  /// `anyhow::Result`, so a caller (or a language binding) that mixes both
  /// surfaces needs one conversion to classify them uniformly. It is the same
  /// classification the job edges apply internally.
  ///
  /// This conversion goes away with the bridge in 0.7.0.
  fn from(error: anyhow::Error) -> Self {
    map_job_error(error)
  }
}

/// Typed internal carriers for the stable [`EngineError`] codes.
///
/// These exist because the codes are otherwise unrecoverable: the sites that
/// produce them used to `bail!` a formatted string, and classifying an error
/// by parsing its `Display` is exactly what this crate forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EngineCause {
  NoSelectedSource,
  NoDiscoveredSource,
  DiscoveryFailed,
}

impl EngineCause {
  fn code(self) -> &'static str {
    match self {
      Self::NoSelectedSource => "no_selected_source",
      Self::NoDiscoveredSource => "no_discovered_source",
      Self::DiscoveryFailed => "discovery_failed",
    }
  }
}

/// An engine failure that carries its typed cause **without** changing what
/// the error chain says.
///
/// `anyhow::Error::context` would work as a carrier, but it replaces the
/// chain's outermost `Display` with the context value's, so every existing
/// diagnostic that names the real failure would be hidden behind a generic
/// category label. This wraps the other way: the `Display` is the original
/// message verbatim, and the category rides along as a field only the job
/// edge reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EngineFailure {
  cause: EngineCause,
  message: String,
}

impl EngineFailure {
  pub(crate) fn new(cause: EngineCause, message: impl Into<String>) -> Self {
    Self {
      cause,
      message: message.into(),
    }
  }

  pub(crate) fn cause(&self) -> EngineCause {
    self.cause
  }
}

impl fmt::Display for EngineFailure {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(&self.message)
  }
}

impl std::error::Error for EngineFailure {}

/// Maps an internal anyhow chain at exactly one public job edge.
///
/// **Order is load-bearing.** A [`BoundaryStop`] can be wrapped inside a
/// [`DirectPathError`] (source classification checks the deadline while it
/// inspects the file), so the stop must win. Reordering these arms silently
/// reclassifies every timeout under a direct-path job as a source error.
pub(crate) fn map_job_error(error: anyhow::Error) -> Error {
  if let Some(stop) = error.downcast_ref::<BoundaryStop>() {
    return Error::stopped(*stop);
  }
  if let Some(request) = error.downcast_ref::<RequestError>() {
    return Error::Request(request.clone());
  }
  if let Some(source) = error.downcast_ref::<DirectPathError>() {
    return Error::Source(source.clone());
  }
  if let Some(failure) = error.downcast_ref::<EngineFailure>() {
    return Error::Engine(EngineError::from_cause(failure.cause(), &error));
  }
  // "Registered but not installed" is already a typed marker on the legacy
  // path, so it needs no separate carrier: discovery completed and found
  // nothing to acquire.
  if crate::browser::legacy::is_browser_not_installed(&error) {
    return Error::Engine(EngineError::from_cause(
      EngineCause::NoDiscoveredSource,
      &error,
    ));
  }
  Error::Engine(EngineError::from_anyhow(error))
}

pub(crate) fn map_job_result<T>(result: anyhow::Result<T>) -> Result<T, Error> {
  result.map_err(map_job_error)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::direct_path::{CookieSourceKind, InvalidCookieSourceReason};
  use std::path::PathBuf;

  fn direct_path_error() -> DirectPathError {
    DirectPathError::InvalidSource {
      path: PathBuf::from("/tmp/rookie-error-fixture/Cookies"),
      reason: InvalidCookieSourceReason::ExpectedChromiumSqlite {
        actual: CookieSourceKind::MozillaSqlite,
      },
    }
  }

  #[test]
  fn every_engine_cause_reaches_its_own_stable_code() {
    for (cause, code) in [
      (EngineCause::NoSelectedSource, "no_selected_source"),
      (EngineCause::NoDiscoveredSource, "no_discovered_source"),
      (EngineCause::DiscoveryFailed, "discovery_failed"),
    ] {
      let error = map_job_error(EngineFailure::new(cause, "diagnostic text").into());
      let Error::Engine(engine) = &error else {
        panic!("a typed engine failure classifies as Error::Engine, got {error:?}");
      };
      assert_eq!(engine.code(), code);
      assert_eq!(error.code(), code);
      assert!(
        engine.message().contains("diagnostic text"),
        "the carrier must not replace the real diagnostic: {}",
        engine.message()
      );
    }
  }

  #[test]
  fn an_unclassified_failure_falls_back_to_engine_failure() {
    let error = map_job_error(anyhow::anyhow!("something the engine did not name"));
    assert_eq!(error.code(), "engine_failure");
    assert!(matches!(error, Error::Engine(_)));
  }

  #[test]
  fn a_not_installed_browser_is_no_discovered_source_without_its_own_carrier() {
    let error =
      map_job_error(crate::browser::legacy::BrowserNotInstalled::ProfileWithCookieDatabase.into());
    assert_eq!(error.code(), "no_discovered_source");
  }

  #[test]
  fn a_stop_wrapped_inside_a_source_error_still_classifies_as_stopped() {
    // A deadline checked *during* source classification is reported as a
    // `DirectPathError` with the stop underneath. If `map_job_error` tested
    // for the source error first, every timeout on a direct-path job would be
    // reclassified as caller input. This pins the downcast order.
    let wrapped = anyhow::Error::new(BoundaryStop::TimedOut).context(direct_path_error());
    assert!(
      wrapped.downcast_ref::<DirectPathError>().is_some(),
      "fixture must actually look like a source error to the naive check"
    );
    let error = map_job_error(wrapped);
    assert_eq!(error.stop_reason(), Some(StopReason::TimedOut));
    assert_eq!(error.code(), "timed_out");
  }

  #[test]
  fn every_variant_reports_a_code_and_only_stopped_reports_a_stop_reason() {
    let cases = [
      (
        Error::Request(RequestError::MissingBrowser),
        "missing_browser",
      ),
      (Error::Stopped(StopReason::TimedOut), "timed_out"),
      (Error::Stopped(StopReason::Cancelled), "cancelled"),
      (
        Error::Stopped(StopReason::ResourceExhausted),
        "resource_exhausted",
      ),
      (
        Error::Source(direct_path_error()),
        "expected_chromium_sqlite",
      ),
      (
        Error::Engine(EngineError::from_cause(
          EngineCause::DiscoveryFailed,
          &anyhow::anyhow!("roots failed"),
        )),
        "discovery_failed",
      ),
    ];
    for (error, code) in cases {
      assert_eq!(error.code(), code);
      assert_eq!(
        error.stop_reason().is_some(),
        matches!(error, Error::Stopped(_))
      );
    }
  }

  #[test]
  fn engine_errors_expose_no_source_and_never_leak_a_path() {
    use std::error::Error as _;
    let error = map_job_error(anyhow::anyhow!(
      "acquisition failed for /private/secret/profile/Cookies"
    ));
    let Error::Engine(engine) = &error else {
      panic!("expected Error::Engine, got {error:?}");
    };
    assert!(!engine.message().contains("/private/secret"));
    assert!(engine
      .message()
      .contains(crate::common::diagnostic::REDACTED_PATH));
    // `Error::source` exposes the nested typed errors, not an anyhow chain the
    // caller cannot name.
    assert!(error.source().is_none());
    assert!(Error::Request(RequestError::MissingBrowser)
      .source()
      .is_some());
  }
}
