//! Compatibility projections over the authoritative registry engine.
//!
//! This module contains policy and result-shape compatibility only. It owns no
//! browser paths, credentials, discovery, acquisition, parsing, or decryption.

use super::cookie_record::{FinalizedCookieRecord, LegacyProjectionSemantics};
use super::mozilla::MozillaProfile;
use super::outcome::{CompatibilityAbsence, CompatibilityDisposition, Outcome, Termination};
#[cfg(test)]
use super::registry::EngineSourceDraft;
use super::registry::{self, EngineExtractionDraft};
use crate::common::deadline::{BoundaryRuntime, BoundaryStop, SystemClock};
use crate::common::enums::{Cookie, DetailedCookie};
use anyhow::{bail, Result};
use std::{error::Error, fmt};

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

fn discovery_failure(outcome: &EngineExtractionDraft, browser_id: &str) -> Option<String> {
  if outcome.all_detected_roots_failed() {
    return Some(format!(
      "every detected {browser_id} installation failed profile enumeration"
    ));
  }
  if !outcome.profiles.is_empty() {
    return None;
  }
  let failures = outcome
    .discovery_issues
    .iter()
    .filter(|issue| !registry::is_informational_discovery_issue(issue.code))
    .map(|issue| issue.message.clone())
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
pub(crate) fn project_engine_outcome(
  browser_id: &str,
  outcome: EngineExtractionDraft,
) -> Result<Vec<Cookie>> {
  project_canonical_outcome(
    browser_id,
    super::report_build::canonical_engine_extraction(browser_id, outcome)?,
  )
}

fn project_engine_outcome_with_runtime(
  browser_id: &str,
  outcome: EngineExtractionDraft,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  project_canonical_outcome_with_runtime(
    browser_id,
    super::report_build::canonical_engine_extraction_with_runtime(browser_id, outcome, runtime)?,
    runtime,
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

fn project_chromium_outcome_with_runtime(
  browser_id: &str,
  outcome: registry::ChromiumRegistryDraft,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  project_canonical_outcome_with_runtime(
    browser_id,
    super::report_build::canonical_chromium_extraction_with_runtime(browser_id, outcome, runtime)?,
    runtime,
  )
}

#[cfg(test)]
pub(crate) fn project_canonical_outcome(browser_id: &str, outcome: Outcome) -> Result<Vec<Cookie>> {
  let selected = selected_records(browser_id, outcome, None)?;
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
  let completed = outcome.termination == Termination::Completed;
  let selected = selected_records(browser_id, outcome, Some(runtime))?;
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

#[cfg(test)]
pub(crate) fn project_canonical_detailed_outcome(
  browser_id: &str,
  outcome: Outcome,
) -> Result<Vec<DetailedCookie>> {
  let selected = selected_records(browser_id, outcome, None)?;
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
  let selected = selected_records(browser_id, outcome, Some(runtime))?;
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

/// Extracts one registered browser using the legacy first-profile projection.
pub(crate) fn browser_cookies(
  browser_id: &str,
  domains: Option<Vec<String>>,
) -> Result<Vec<Cookie>> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  browser_cookies_with_runtime(browser_id, domains, &runtime)
}

pub(crate) fn browser_cookies_with_runtime(
  browser_id: &str,
  domains: Option<Vec<String>>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  runtime.check()?;
  let browser = registry::resolve_registered_browser(browser_id)?;
  match browser.engine {
    "chromium" => project_chromium_outcome_with_runtime(
      &browser.canonical_id,
      registry::legacy_chromium_outcome_with_runtime(&browser.canonical_id, domains, runtime)?,
      runtime,
    ),
    "gecko" => project_engine_outcome_with_runtime(
      &browser.canonical_id,
      registry::legacy_gecko_outcome_with_runtime(&browser.canonical_id, domains, runtime)?,
      runtime,
    ),
    #[cfg(target_os = "macos")]
    "safari" => project_engine_outcome_with_runtime(
      &browser.canonical_id,
      registry::legacy_safari_outcome_with_runtime(&browser.canonical_id, domains, runtime)?,
      runtime,
    ),
    #[cfg(target_os = "windows")]
    "internet_explorer" => project_engine_outcome_with_runtime(
      &browser.canonical_id,
      registry::legacy_internet_explorer_outcome_with_runtime(
        &browser.canonical_id,
        domains,
        runtime,
      )?,
      runtime,
    ),
    engine => bail!(
      "browser {:?} uses unsupported engine {engine:?}",
      browser.canonical_id
    ),
  }
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
  let outcome = registry::legacy_gecko_profiles_with_runtime(browser_id, runtime)?;
  if let Some(error) = discovery_failure(&outcome, browser_id) {
    bail!(error)
  }
  let profiles = outcome
    .profiles
    .into_iter()
    .map(|profile| MozillaProfile {
      name: profile.legacy_name,
      path: profile.path,
      is_default: profile.is_default,
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
    test_seams, EngineProfileDraft, PlatformId, SourceAcquisition, SourceFailureStage,
    PERSISTENT_SOURCE_PRECEDENCE, SOURCE_ROLE_PERSISTENT, SOURCE_ROLE_SESSION,
  };
  use std::path::PathBuf;

  fn profile_with(source: Option<EngineSourceDraft>) -> EngineExtractionDraft {
    EngineExtractionDraft {
      profiles: vec![EngineProfileDraft {
        profile_id: "a".repeat(64),
        installation_id: "b".repeat(64),
        installation_priority: 10,
        legacy_installation_priority: 10,
        legacy_profile_order: 0,
        legacy_is_default: true,
        legacy_eligible: true,
        installation_path: PathBuf::from("/browser"),
        legacy_installation_path: PathBuf::from("/browser"),
        name: "default".to_owned(),
        legacy_name: "default".to_owned(),
        path: PathBuf::from("/browser/default"),
        is_default: true,
        persistent_source_discovered: true,
        sources: source.into_iter().collect(),
      }],
      installations_detected: 1,
      installations_discovered: 1,
      installations_enumerated: 1,
      ..EngineExtractionDraft::default()
    }
  }

  fn persistent_source(error: Option<&str>, row_error: Option<&str>) -> EngineSourceDraft {
    EngineSourceDraft {
      path: PathBuf::from("/browser/default/cookies.sqlite"),
      role: SOURCE_ROLE_PERSISTENT,
      format: "mozilla_sqlite",
      precedence: PERSISTENT_SOURCE_PRECEDENCE,
      selected: true,
      cookies: Vec::new(),
      records: Vec::new(),
      rows_seen: usize::from(row_error.is_some()),
      rows_skipped: usize::from(row_error.is_some()),
      rows_rejected: usize::from(row_error.is_some()),
      acquisition: SourceAcquisition::NotAttempted,
      acquisition_attempts: 1,
      diagnostics: Vec::new(),
      error: error.map(str::to_owned),
      error_stage: SourceFailureStage::Acquisition,
      row_error: row_error.map(str::to_owned),
    }
  }

  fn failed_session_source(path: &str, error: &str) -> EngineSourceDraft {
    EngineSourceDraft {
      path: PathBuf::from(path),
      role: SOURCE_ROLE_SESSION,
      format: "firefox_session_jsonlz4",
      precedence: 20,
      selected: false,
      cookies: Vec::new(),
      records: Vec::new(),
      rows_seen: 0,
      rows_skipped: 0,
      rows_rejected: 0,
      acquisition: SourceAcquisition::StableFileImage,
      acquisition_attempts: 1,
      diagnostics: Vec::new(),
      error: Some(error.to_owned()),
      error_stage: SourceFailureStage::Parse,
      row_error: None,
    }
  }

  fn actual_safari_outcome(fixture: &[u8]) -> EngineExtractionDraft {
    let directory = crate::utils::TempDir::new().expect("temporary Safari fixture directory");
    let context = test_seams::context(PlatformId::Macos, directory.path().to_path_buf());
    let library = test_seams::primary_root_path(&context, "safari");
    let cookie_directory = library.join("Containers/com.apple.Safari/Data/Library/Cookies");
    std::fs::create_dir_all(&cookie_directory).expect("create Safari cookie directory");
    std::fs::write(cookie_directory.join("Cookies.binarycookies"), fixture)
      .expect("write Safari fixture");
    test_seams::safari_report(&context, "safari", None, None).expect("extract Safari fixture")
  }

  fn empty_outcome_with_issue(code: &'static str) -> EngineExtractionDraft {
    EngineExtractionDraft {
      discovery_issues: vec![registry::DiscoveryIssue {
        code,
        path: PathBuf::from("/browser/discovery"),
        message: "injected discovery failure".to_owned(),
        occurrences: 1,
      }],
      installations_detected: 1,
      installations_discovered: 1,
      installations_enumerated: 1,
      ..EngineExtractionDraft::default()
    }
  }

  #[test]
  fn ordinary_absence_stays_typed_for_load() {
    let error =
      project_engine_outcome("firefox", EngineExtractionDraft::default()).expect_err("absence");
    assert!(is_browser_not_installed(&error));
  }

  #[test]
  fn non_profile_discovery_failures_do_not_become_browser_absence() {
    for code in [
      "mozilla_profiles_ini_invalid",
      "safari_profile_enumeration_failed",
    ] {
      let error = project_engine_outcome("browser", empty_outcome_with_issue(code))
        .expect_err("discovery failures must surface");
      assert!(!is_browser_not_installed(&error), "{code}");
      assert!(error.to_string().contains("injected discovery failure"));
    }
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
      let error = project_engine_outcome("browser", empty_outcome_with_issue(code))
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
      let error = project_engine_outcome("firefox", profile_with(Some(source)))
        .expect_err("real extraction failure");
      assert!(!is_browser_not_installed(&error));
    }
  }

  #[test]
  fn internet_explorer_all_row_failure_remains_an_error() {
    let error = project_engine_outcome(
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
    source.rows_seen = 1;
    source.rows_skipped = 1;
    let error = project_engine_outcome("internet_explorer", profile_with(Some(source)))
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
    assert_eq!(outcome.profiles[0].sources[0].rows_seen, 1);
    assert_eq!(outcome.profiles[0].sources[0].rows_skipped, 1);

    let error = project_engine_outcome("safari", outcome)
      .expect_err("legacy Safari must preserve the existing all-malformed error");
    assert!(error.to_string().contains("c string contains embedded NUL"));
    assert!(!is_browser_not_installed(&error));
  }

  #[test]
  fn legacy_safari_projection_keeps_valid_rows_beside_an_embedded_nul_record() {
    let outcome = actual_safari_outcome(&crate::browser::safari::embedded_nul_test_fixture(
      "path", true,
    ));
    assert_eq!(outcome.profiles[0].sources[0].rows_seen, 2);
    assert_eq!(outcome.profiles[0].sources[0].rows_skipped, 1);

    let cookies =
      project_engine_outcome("safari", outcome).expect("legacy Safari keeps the valid record");
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

    let error = project_engine_outcome("firefox", outcome)
      .expect_err("all existing session candidates failed");
    let message = error.to_string();
    assert!(message.contains("all existing Firefox session store candidates failed"));
    assert!(message.contains("invalid mozLz4"));
    assert!(message.contains("invalid JSON"));
    assert!(!message.contains("/browser/default"));

    let mut selected_empty = failed_session_source("/browser/default/sessionstore.js", "unused");
    selected_empty.selected = true;
    selected_empty.error = None;
    let mut recovered = profile_with(Some(persistent_source(None, None)));
    recovered.profiles[0].sources.extend([
      failed_session_source("/browser/default/recovery.jsonlz4", "invalid mozLz4"),
      selected_empty,
    ]);
    assert!(project_engine_outcome("firefox", recovered)
      .expect("an authoritative empty session source is still a success")
      .is_empty());
  }

  #[test]
  fn valid_gecko_session_cookie_rescues_persistent_all_row_failure() {
    let mut session = failed_session_source("/browser/default/sessionstore.js", "unused");
    session.selected = true;
    session.error = None;
    session.cookies.push(Cookie {
      domain: ".example.com".to_owned(),
      path: "/".to_owned(),
      secure: false,
      expires: None,
      name: "session".to_owned(),
      value: "value".to_owned(),
      http_only: false,
      same_site: -1,
    });
    let mut outcome = profile_with(Some(persistent_source(
      None,
      Some("every persistent row failed"),
    )));
    outcome.profiles[0].sources.push(session);

    let cookies = project_engine_outcome("firefox", outcome)
      .expect("a valid session source is the historical fallback");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "session");

    let mut selected_empty = failed_session_source("/browser/default/sessionstore.js", "unused");
    selected_empty.selected = true;
    selected_empty.error = None;
    let mut empty = profile_with(Some(persistent_source(
      None,
      Some("every persistent row failed"),
    )));
    empty.profiles[0].sources.push(selected_empty);
    assert!(project_engine_outcome("firefox", empty)
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
    let error = project_engine_outcome("firefox", all_sessions_failed)
      .expect_err("the historical total-session failure takes precedence");
    assert!(error
      .to_string()
      .contains("all existing Firefox session store candidates failed"));
    assert!(!error.to_string().contains("every persistent row failed"));
  }
}
