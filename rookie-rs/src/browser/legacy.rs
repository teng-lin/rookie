//! Compatibility projections over the authoritative registry engine.
//!
//! This module contains policy and result-shape compatibility only. It owns no
//! browser paths, credentials, discovery, acquisition, parsing, or decryption.

mod dispatch;

use super::cookie_record::{FinalizedCookieRecord, LegacyProjectionSemantics};
use super::mozilla::MozillaProfile;
use super::outcome::{CompatibilityAbsence, CompatibilityDisposition, Outcome, Termination};
use super::registry::{self, EngineExtract, EngineListing};
use super::source::SourceIssue;
use crate::common::deadline::{BoundaryRuntime, BoundaryStop};
use crate::common::enums::{Cookie, DetailedCookie};
use crate::read_warning::ReadWarningCounts;
use anyhow::{bail, Result};
use std::{error::Error, fmt};

/// Whether a compatibility projection may retain committed records after the
/// shared runtime stops.
///
/// Single-browser compatibility APIs promise a typed stop error. Flat
/// `load()` is different: an already-claimed browser runs to completion and
/// contributes any cookies it committed before observing the shared stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StopProjection {
  ReturnError,
  PreserveCommitted,
}

/// The authoritative registry found no source eligible for a named wrapper.
///
/// `load()` treats this typed outcome as ordinary absence while preserving all
/// real discovery and extraction errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BrowserNotInstalled {
  CookieDatabase,
  ProfileWithCookieDatabase,
}

impl fmt::Display for BrowserNotInstalled {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::CookieDatabase => write!(formatter, "Can't find cookies file"),
      Self::ProfileWithCookieDatabase => {
        write!(formatter, "Can't find any profile with a cookie database")
      }
    }
  }
}

impl Error for BrowserNotInstalled {}

pub(crate) fn is_browser_not_installed(error: &anyhow::Error) -> bool {
  error
    .chain()
    .any(|cause| cause.downcast_ref::<BrowserNotInstalled>().is_some())
}

/// Renders the browser-absent-vs-discovery-failed message for the Gecko
/// listing.
///
/// The Safari/IE towers reach the same policy through
/// `project_engine_outcome`; only Gecko's `firefox_profiles` needs it directly,
/// and Gecko has moved onto the listing/extract split.
fn listing_discovery_failure(listing: &EngineListing, browser_id: &str) -> Option<String> {
  discovery_failure_parts(
    listing.all_detected_roots_failed(),
    listing.profiles.is_empty(),
    &listing.discovery_issues,
    browser_id,
  )
}

fn discovery_failure_parts(
  all_detected_roots_failed: bool,
  profiles_empty: bool,
  discovery_issues: &[registry::DiscoveryIssue],
  browser_id: &str,
) -> Option<String> {
  if all_detected_roots_failed {
    return Some(format!(
      "every detected {browser_id} installation failed profile enumeration"
    ));
  }
  if !profiles_empty {
    return None;
  }
  let failures = discovery_issues
    .iter()
    .filter(|issue| !registry::is_informational_discovery_issue(issue.code))
    .map(|issue| crate::common::diagnostic::sanitize(&issue.message))
    .take(8)
    .collect::<Vec<_>>();
  (!failures.is_empty()).then(|| {
    format!(
      "every discovered {browser_id} profile failed discovery: {}",
      failures.join("; ")
    )
  })
}

#[cfg(test)]
pub(crate) fn project_engine_extract_outcome(
  browser_id: &str,
  extract: EngineExtract,
) -> Result<Vec<Cookie>> {
  project_canonical_outcome(
    browser_id,
    super::report_build::canonical_engine_extract(browser_id, extract)?,
  )
}

#[cfg(test)]
pub(crate) fn project_chromium_outcome(
  browser_id: &str,
  outcome: registry::ChromiumRegistryDraft,
) -> Result<Vec<Cookie>> {
  project_canonical_outcome(
    browser_id,
    super::report_build::canonical_chromium_extraction(browser_id, outcome)?,
  )
}

// Only reachable in production through the automatic multi-identity
// Chromium selection, which is Linux/macOS-only; Windows exercises this via
// `#[cfg(test)]`.
#[allow(dead_code)]
pub(crate) fn project_canonical_outcome(browser_id: &str, outcome: Outcome) -> Result<Vec<Cookie>> {
  let selected = selected_records(browser_id, outcome, None, StopProjection::ReturnError)?;
  Ok(
    selected
      .into_iter()
      .flat_map(|(semantics, records)| {
        records
          .into_iter()
          .map(move |record| record.into_cookie_with_semantics(semantics))
      })
      .collect(),
  )
}

pub(crate) fn project_canonical_outcome_with_runtime(
  browser_id: &str,
  outcome: Outcome,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  project_canonical_outcome_with_stop_projection(
    browser_id,
    outcome,
    runtime,
    StopProjection::ReturnError,
  )
}

pub(crate) fn project_canonical_outcome_with_stop_projection(
  browser_id: &str,
  outcome: Outcome,
  runtime: &BoundaryRuntime<'_>,
  stop_projection: StopProjection,
) -> Result<Vec<Cookie>> {
  let completed = outcome.termination == Termination::Completed;
  let selected = selected_records(browser_id, outcome, Some(runtime), stop_projection)?;
  if completed {
    runtime.check()?;
  }
  Ok(
    selected
      .into_iter()
      .flat_map(|(semantics, records)| {
        records
          .into_iter()
          .map(move |record| record.into_cookie_with_semantics(semantics))
      })
      .collect(),
  )
}

fn selected_records(
  browser_id: &str,
  outcome: Outcome,
  runtime: Option<&BoundaryRuntime<'_>>,
  stop_projection: StopProjection,
) -> Result<Vec<(LegacyProjectionSemantics, Vec<FinalizedCookieRecord>)>> {
  let boundary_stop = match outcome.termination {
    Termination::Completed => None,
    Termination::TimedOut => Some(BoundaryStop::TimedOut),
    Termination::Cancelled => Some(BoundaryStop::Cancelled),
    Termination::ResourceExhausted => Some(BoundaryStop::ResourceExhausted),
  };
  let runtime = boundary_stop.is_none().then_some(runtime).flatten();
  let Outcome {
    sources,
    compatibility,
    ..
  } = outcome;
  let disposition = compatibility
    .into_iter()
    .find(|decision| decision.browser_id.as_str() == browser_id)
    .map(|decision| decision.disposition)
    .unwrap_or(CompatibilityDisposition::Absent(
      CompatibilityAbsence::CookieDatabase,
    ));
  match disposition {
    CompatibilityDisposition::Emit { source_digests } => {
      if let (Some(stop), StopProjection::ReturnError) = (boundary_stop, stop_projection) {
        return Err(stop.into());
      }
      let mut selected = Vec::new();
      for source in sources {
        if let Some(runtime) = runtime {
          runtime.check()?;
        }
        if !source_digests.contains(&source.source_digest()) {
          continue;
        }
        let semantics = LegacyProjectionSemantics::for_source_format(source.source.format.as_str());
        let mut records = Vec::with_capacity(source.records.len());
        for record in source.records {
          if let Some(runtime) = runtime {
            runtime.check()?;
          }
          if record.is_legacy_compatible_with_semantics(semantics) {
            records.push(record);
          }
        }
        selected.push((semantics, records));
      }
      Ok(selected)
    }
    CompatibilityDisposition::Absent(CompatibilityAbsence::CookieDatabase) => {
      Err(boundary_stop.map_or_else(
        || anyhow::Error::new(BrowserNotInstalled::CookieDatabase),
        anyhow::Error::new,
      ))
    }
    CompatibilityDisposition::Failed(diagnostic) => match boundary_stop {
      Some(stop) => Err(stop.into()),
      None => bail!(diagnostic.as_str().to_owned()),
    },
  }
}

// See `project_canonical_outcome`: only reachable in production on Linux/macOS.
#[allow(dead_code)]
pub(crate) fn project_canonical_detailed_outcome(
  browser_id: &str,
  outcome: Outcome,
) -> Result<Vec<DetailedCookie>> {
  let selected = selected_records(browser_id, outcome, None, StopProjection::ReturnError)?;
  Ok(
    selected
      .into_iter()
      .flat_map(|(semantics, records)| {
        records
          .into_iter()
          .map(move |record| record.into_detailed_cookie_with_semantics(semantics))
      })
      .collect(),
  )
}

pub(crate) fn project_canonical_detailed_outcome_with_runtime(
  browser_id: &str,
  outcome: Outcome,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<DetailedCookie>> {
  let completed = outcome.termination == Termination::Completed;
  let selected = selected_records(
    browser_id,
    outcome,
    Some(runtime),
    StopProjection::ReturnError,
  )?;
  if completed {
    runtime.check()?;
  }
  Ok(
    selected
      .into_iter()
      .flat_map(|(semantics, records)| {
        records
          .into_iter()
          .map(move |record| record.into_detailed_cookie_with_semantics(semantics))
      })
      .collect(),
  )
}

pub(super) type LegacySnapshot = (Vec<Cookie>, ReadWarningCounts);

pub(crate) fn browser_cookies_with_runtime(
  browser_id: &str,
  domains: Option<Vec<String>>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  browser_cookies_and_warnings_with_stop_projection(
    browser_id,
    domains,
    runtime,
    StopProjection::ReturnError,
  )
  .map(|(cookies, _warnings)| cookies)
}

/// Flat `load()` projection. Unlike single-browser compatibility surfaces,
/// this keeps records committed by an in-flight browser before the shared
/// runtime stopped.
pub(crate) fn browser_cookies_for_load_with_runtime(
  browser_id: &str,
  domains: Option<Vec<String>>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  browser_cookies_and_warnings_with_stop_projection(
    browser_id,
    domains,
    runtime,
    StopProjection::PreserveCommitted,
  )
  .map(|(cookies, _warnings)| cookies)
}

/// One LegacyFirst extract: compatibility cookies plus skip counts from the
/// same draft. Callers must not run a second `legacy_*_outcome_with_runtime`.
pub(crate) fn browser_cookies_and_warnings_with_runtime(
  browser_id: &str,
  domains: Option<Vec<String>>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<LegacySnapshot> {
  browser_cookies_and_warnings_with_stop_projection(
    browser_id,
    domains,
    runtime,
    StopProjection::ReturnError,
  )
}

fn browser_cookies_and_warnings_with_stop_projection(
  browser_id: &str,
  domains: Option<Vec<String>>,
  runtime: &BoundaryRuntime<'_>,
  stop_projection: StopProjection,
) -> Result<LegacySnapshot> {
  runtime.check()?;
  let browser = registry::resolve_registered_browser(browser_id)?;
  match browser.engine {
    "chromium" => {
      let draft =
        registry::legacy_chromium_outcome_with_runtime(&browser.canonical_id, domains, runtime)?;
      let warnings = chromium_warning_counts(&draft);
      let outcome = super::report_build::canonical_chromium_extraction_with_runtime(
        &browser.canonical_id,
        draft,
        runtime,
      )?;
      let cookies = project_canonical_outcome_with_stop_projection(
        &browser.canonical_id,
        outcome,
        runtime,
        stop_projection,
      )?;
      Ok((cookies, warnings))
    }
    "gecko" => {
      let extract =
        registry::legacy_gecko_outcome_with_runtime(&browser.canonical_id, domains, runtime)?;
      let skipped = engine_extract_skipped_row_count(&extract);
      let outcome = super::report_build::canonical_engine_extract_with_runtime(
        &browser.canonical_id,
        extract,
        runtime,
      )?;
      let cookies = project_canonical_outcome_with_stop_projection(
        &browser.canonical_id,
        outcome,
        runtime,
        stop_projection,
      )?;
      Ok((cookies, row_read_warnings(skipped)))
    }
    engine => dispatch::remaining_engine_snapshot_with_runtime(
      &browser.canonical_id,
      engine,
      domains,
      runtime,
      stop_projection,
    ),
  }
}

// Reached only through the platform legacy dispatch: Safari on macOS and
// Internet Explorer on Windows. A Linux build compiles neither, so it has no
// caller there -- a platform gate, not dead code. Kept target-agnostic rather
// than `cfg`-gated so this module stays free of platform cfg (#218).
#[allow(dead_code)]
pub(super) fn cookies_and_skipped_from_engine_extract(
  canonical_id: &str,
  extract: EngineExtract,
  runtime: &BoundaryRuntime<'_>,
  stop_projection: StopProjection,
) -> Result<LegacySnapshot> {
  let skipped = engine_extract_skipped_row_count(&extract);
  let outcome =
    super::report_build::canonical_engine_extract_with_runtime(canonical_id, extract, runtime)?;
  let cookies = project_canonical_outcome_with_stop_projection(
    canonical_id,
    outcome,
    runtime,
    stop_projection,
  )?;
  Ok((cookies, row_read_warnings(skipped)))
}

fn row_read_warnings(skipped: u64) -> ReadWarningCounts {
  let mut warnings = ReadWarningCounts::default();
  warnings.record_issue(SourceIssue::ROW_READ_FAILED, skipped);
  warnings
}

fn chromium_warning_counts(draft: &registry::ChromiumRegistryDraft) -> ReadWarningCounts {
  let mut warnings = ReadWarningCounts::default();
  for issue in draft
    .installations
    .iter()
    .flat_map(|installation| installation.profiles.iter())
    .flat_map(|profile| profile.sources.iter())
    .flat_map(|source| source.issues.iter())
  {
    warnings.record_issue(issue.code, u64::from(issue.occurrences));
  }
  warnings
}

fn engine_extract_skipped_row_count(extract: &EngineExtract) -> u64 {
  extract
    .profiles
    .iter()
    .flat_map(|profile| profile.sources.iter())
    .map(|source| source.stats.rows_skipped as u64)
    .fold(0u64, u64::saturating_add)
}

/// Compatibility-shaped persistent Gecko profiles from registry discovery.
pub(crate) fn gecko_profiles(browser_id: &str) -> Result<Vec<MozillaProfile>> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  gecko_profiles_with_runtime(browser_id, &runtime)
}

pub(crate) fn gecko_profiles_with_runtime(
  browser_id: &str,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<MozillaProfile>> {
  let listing = registry::legacy_gecko_profiles_with_runtime(browser_id, runtime)?;
  if let Some(error) = listing_discovery_failure(&listing, browser_id) {
    bail!(error)
  }
  let profiles = listing
    .profiles
    .into_iter()
    .map(|profile| MozillaProfile {
      name: profile.legacy.name,
      path: profile.identity.path,
      is_default: profile.identity.is_default,
    })
    .collect::<Vec<_>>();
  if profiles.is_empty() {
    return Err(BrowserNotInstalled::ProfileWithCookieDatabase.into());
  }
  runtime.check()?;
  Ok(profiles)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::browser::registry::{
    test_seams, DiscoveryCounters, EngineProfileIdentity, ExtractedProfile, LegacyRank, PlatformId,
    SourceAcquisition, PERSISTENT_SOURCE_PRECEDENCE,
  };
  use crate::browser::report_core::{CookieSourceFormatId, CookieSourceRoleId};
  use crate::browser::source::{Source, SourceFailureStage, SourceIdentity, SourceStats};
  use std::path::PathBuf;

  fn profile_with(source: Option<Source>) -> EngineExtract {
    EngineExtract {
      profiles: vec![ExtractedProfile {
        identity: EngineProfileIdentity {
          profile_id: "a".repeat(64).parse().expect("valid profile id"),
          installation_id: "b".repeat(64).parse().expect("valid installation id"),
          installation_priority: 10,
          installation_path: PathBuf::from("/browser"),
          name: "default".to_owned(),
          path: PathBuf::from("/browser/default"),
          is_default: true,
          persistent_source_discovered: true,
        },
        legacy: LegacyRank {
          installation_priority: 10,
          profile_order: 0,
          is_default: true,
          eligible: true,
          installation_path: PathBuf::from("/browser"),
          name: "default".to_owned(),
        },
        // Post-populate fixture: these sources have already been queried.
        sources: source.into_iter().collect(),
      }],
      counters: DiscoveryCounters {
        installations_detected: 1,
        installations_discovered: 1,
        installations_enumerated: 1,
      },
      discovery_issues: Vec::new(),
      boundary_stop: None,
    }
  }

  fn source_from(
    path: &str,
    role: CookieSourceRoleId,
    format: &str,
    precedence: u16,
    selected: bool,
    acquisition: SourceAcquisition,
  ) -> Source {
    Source {
      origin: SourceIdentity {
        path: PathBuf::from(path),
        role,
        format: CookieSourceFormatId::known(format),
        precedence,
      },
      selected,
      acquisition,
      records: Vec::new(),
      stats: SourceStats::default(),
      acquisition_attempts: 1,
      diagnostics: Vec::new(),
      failure: None,
      issues: Vec::new(),
    }
  }

  fn persistent_source(error: Option<&str>, row_error: Option<&str>) -> Source {
    let mut source = source_from(
      "/browser/default/cookies.sqlite",
      CookieSourceRoleId::persistent(),
      "mozilla_sqlite",
      PERSISTENT_SOURCE_PRECEDENCE,
      true,
      SourceAcquisition::NotAttempted,
    );
    let rows = usize::from(row_error.is_some());
    source.stats.rows_seen = rows;
    source.stats.rows_skipped = rows;
    source.stats.rows_rejected = rows;
    if let Some(error) = error {
      source.fail(SourceFailureStage::Acquisition, error);
    }
    source.push_row_read_failed(row_error.map(str::to_owned));
    source
  }

  fn failed_session_source(path: &str, error: &str) -> Source {
    let mut source = source_from(
      path,
      CookieSourceRoleId::session(),
      "firefox_session_jsonlz4",
      20,
      false,
      SourceAcquisition::StableFileImage,
    );
    source.fail(SourceFailureStage::Parse, error);
    source
  }

  fn actual_safari_outcome(fixture: &[u8]) -> EngineExtract {
    let directory = crate::utils::TempDir::new().expect("temporary Safari fixture directory");
    let context = test_seams::context(PlatformId::Macos, directory.path().to_path_buf());
    let library = test_seams::primary_root_path(&context, "safari");
    let cookie_directory = library.join("Containers/com.apple.Safari/Data/Library/Cookies");
    std::fs::create_dir_all(&cookie_directory).expect("create Safari cookie directory");
    std::fs::write(cookie_directory.join("Cookies.binarycookies"), fixture)
      .expect("write Safari fixture");
    test_seams::safari_report(&context, "safari", None, None).expect("extract Safari fixture")
  }

  fn empty_outcome_with_issue(code: &'static str) -> EngineExtract {
    EngineExtract {
      discovery_issues: vec![registry::DiscoveryIssue {
        code,
        path: PathBuf::from("/browser/discovery"),
        message: "injected discovery failure".to_owned(),
        occurrences: 1,
      }],
      counters: DiscoveryCounters {
        installations_detected: 1,
        installations_discovered: 1,
        installations_enumerated: 1,
      },
      profiles: Vec::new(),
      boundary_stop: None,
    }
  }

  #[test]
  fn ordinary_absence_stays_typed_for_load() {
    let error =
      project_engine_extract_outcome("firefox", EngineExtract::default()).expect_err("absence");
    assert!(is_browser_not_installed(&error));
  }

  #[test]
  fn non_profile_discovery_failures_do_not_become_browser_absence() {
    for code in [
      "mozilla_profiles_ini_invalid",
      "safari_profile_enumeration_failed",
    ] {
      let error = project_engine_extract_outcome("browser", empty_outcome_with_issue(code))
        .expect_err("discovery failures must surface");
      assert!(!is_browser_not_installed(&error), "{code}");
      assert!(error.to_string().contains("injected discovery failure"));
    }
  }

  #[test]
  fn legacy_discovery_failure_sanitizes_paths_embedded_in_messages() {
    let mut outcome = empty_outcome_with_issue("profile_enumeration_failed");
    outcome.discovery_issues[0].message =
      "failed /private/secret/profile and C:\\Users\\Secret\\Profile".to_owned();
    let error =
      project_engine_extract_outcome("browser", outcome).expect_err("profile discovery failed");
    let diagnostic = error.to_string();
    assert!(!diagnostic.contains("/private/secret"));
    assert!(!diagnostic.contains(r"C:\Users\Secret"));
    assert!(
      diagnostic
        .matches(crate::common::diagnostic::REDACTED_PATH)
        .count()
        >= 2
    );
  }

  #[test]
  fn ordinary_empty_profile_diagnostics_stay_typed_as_absence() {
    for code in [
      "profile_has_no_cookie_source",
      "profile_excluded_service_directory",
      "safari_profile_discovery_degraded",
      "duplicate_installation",
      "duplicate_profile",
    ] {
      let error = project_engine_extract_outcome("browser", empty_outcome_with_issue(code))
        .expect_err("empty discovery remains absence");
      assert!(is_browser_not_installed(&error), "{code}");
    }
  }

  #[test]
  fn source_and_all_row_failures_are_not_misclassified_as_absence() {
    for source in [
      persistent_source(Some("database is corrupt"), None),
      persistent_source(None, Some("every row failed")),
    ] {
      let error = project_engine_extract_outcome("firefox", profile_with(Some(source)))
        .expect_err("real extraction failure");
      assert!(!is_browser_not_installed(&error));
    }
  }

  #[test]
  fn internet_explorer_all_row_failure_remains_an_error() {
    let error = project_engine_extract_outcome(
      "internet_explorer",
      profile_with(Some(persistent_source(
        None,
        Some("every WebCache row failed"),
      ))),
    )
    .expect_err("all rejected WebCache rows must fail the legacy projection");

    assert!(error.to_string().contains("every WebCache row failed"));
    assert!(!is_browser_not_installed(&error));

    let mut source = persistent_source(None, None);
    source.stats.rows_seen = 1;
    source.stats.rows_skipped = 1;
    // The adapter attaches the row issue from the skip count with no detailed
    // message; the projection must still treat it as a decode failure.
    source.push_row_read_failed(None);
    let error = project_engine_extract_outcome("internet_explorer", profile_with(Some(source)))
      .expect_err("skipped WebCache rows need an error even without a detailed row message");
    assert!(error
      .to_string()
      .contains("all Internet Explorer WebCache records failed to decode"));
  }

  #[test]
  fn legacy_safari_projection_errors_when_every_embedded_nul_record_is_malformed() {
    let outcome = actual_safari_outcome(&crate::browser::safari::embedded_nul_test_fixture(
      "name", false,
    ));
    assert_eq!(outcome.profiles[0].sources[0].stats.rows_seen, 1);
    assert_eq!(outcome.profiles[0].sources[0].stats.rows_skipped, 1);

    let error = project_engine_extract_outcome("safari", outcome)
      .expect_err("legacy Safari must preserve the existing all-malformed error");
    assert!(error.to_string().contains("c string contains embedded NUL"));
    assert!(!is_browser_not_installed(&error));
  }

  #[test]
  fn legacy_safari_projection_keeps_valid_rows_beside_an_embedded_nul_record() {
    let outcome = actual_safari_outcome(&crate::browser::safari::embedded_nul_test_fixture(
      "path", true,
    ));
    assert_eq!(outcome.profiles[0].sources[0].stats.rows_seen, 2);
    assert_eq!(outcome.profiles[0].sources[0].stats.rows_skipped, 1);

    let cookies = project_engine_extract_outcome("safari", outcome)
      .expect("legacy Safari keeps the valid record");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].domain, ".good.test");
    assert_eq!(cookies[0].name, "good");
    assert_eq!(cookies[0].path, "/");
    assert_eq!(cookies[0].value, "kept");
  }

  #[test]
  fn total_session_failures_surface_when_persistent_extraction_is_empty() {
    let mut outcome = profile_with(Some(persistent_source(None, None)));
    outcome.profiles[0].sources.extend([
      failed_session_source("/browser/default/recovery.jsonlz4", "invalid mozLz4"),
      failed_session_source("/browser/default/sessionstore.js", "invalid JSON"),
    ]);

    let error = project_engine_extract_outcome("firefox", outcome)
      .expect_err("all existing session candidates failed");
    let message = error.to_string();
    assert!(message.contains("all existing Firefox session store candidates failed"));
    assert!(message.contains("invalid mozLz4"));
    assert!(message.contains("invalid JSON"));
    assert!(!message.contains("/browser/default"));

    let mut selected_empty = failed_session_source("/browser/default/sessionstore.js", "unused");
    selected_empty.selected = true;
    selected_empty.failure = None;
    let mut recovered = profile_with(Some(persistent_source(None, None)));
    recovered.profiles[0].sources.extend([
      failed_session_source("/browser/default/recovery.jsonlz4", "invalid mozLz4"),
      selected_empty,
    ]);
    assert!(project_engine_extract_outcome("firefox", recovered)
      .expect("an authoritative empty session source is still a success")
      .is_empty());
  }

  #[test]
  fn valid_gecko_session_cookie_rescues_persistent_all_row_failure() {
    let mut session = failed_session_source("/browser/default/sessionstore.js", "unused");
    session.selected = true;
    session.failure = None;
    let session_cookie = || Cookie {
      domain: ".example.com".to_owned(),
      path: "/".to_owned(),
      secure: false,
      expires: None,
      name: "session".to_owned(),
      value: "value".to_owned(),
      http_only: false,
      same_site: -1,
    };
    // Finalization takes rows from `records` only; `Source` has no cookies
    // field, so a session cookie is supplied purely as a record.
    session
      .records
      .push(crate::browser::cookie_record::CookieRecord::from_cookie(
        session_cookie(),
        crate::browser::cookie_record::SourceRef::pending(0),
      ));
    let mut outcome = profile_with(Some(persistent_source(
      None,
      Some("every persistent row failed"),
    )));
    outcome.profiles[0].sources.push(session);

    let cookies = project_engine_extract_outcome("firefox", outcome)
      .expect("a valid session source is the historical fallback");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "session");

    let mut selected_empty = failed_session_source("/browser/default/sessionstore.js", "unused");
    selected_empty.selected = true;
    selected_empty.failure = None;
    let mut empty = profile_with(Some(persistent_source(
      None,
      Some("every persistent row failed"),
    )));
    empty.profiles[0].sources.push(selected_empty);
    assert!(project_engine_extract_outcome("firefox", empty)
      .expect("an authoritative empty session source rescues persistent failure")
      .is_empty());

    let mut all_sessions_failed = profile_with(Some(persistent_source(
      None,
      Some("every persistent row failed"),
    )));
    all_sessions_failed.profiles[0]
      .sources
      .push(failed_session_source(
        "/browser/default/sessionstore.js",
        "invalid JSON",
      ));
    let error = project_engine_extract_outcome("firefox", all_sessions_failed)
      .expect_err("the historical total-session failure takes precedence");
    assert!(error
      .to_string()
      .contains("all existing Firefox session store candidates failed"));
    assert!(!error.to_string().contains("every persistent row failed"));
  }
}
