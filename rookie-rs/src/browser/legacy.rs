//! Compatibility projections over the authoritative registry engine.
//!
//! This module contains policy and result-shape compatibility only. It owns no
//! browser paths, credentials, discovery, acquisition, parsing, or decryption.

use super::mozilla::MozillaProfile;
use super::registry::{self, EngineExtractionOutcome, EngineSourceExtraction};
use crate::common::enums::Cookie;
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

fn discovery_failure(outcome: &EngineExtractionOutcome, browser_id: &str) -> Option<String> {
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
    .map(|issue| format!("{}: {}", issue.path.display(), issue.message))
    .take(8)
    .collect::<Vec<_>>();
  (!failures.is_empty()).then(|| {
    format!(
      "every discovered {browser_id} profile failed discovery: {}",
      failures.join("; ")
    )
  })
}

fn selected_source_cookies(
  source: EngineSourceExtraction,
  policy: LegacyEnginePolicy,
) -> Result<Vec<Cookie>> {
  if let Some(error) = source.error {
    bail!(error)
  }
  if policy.rejects_all_row_failures() && source.cookies.is_empty() && source.rows_skipped > 0 {
    bail!(source
      .row_error
      .unwrap_or_else(|| policy.all_rows_rejected_fallback().to_owned()))
  }
  Ok(source.cookies)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LegacyEnginePolicy {
  Gecko,
  Safari,
  #[cfg(any(target_os = "windows", test))]
  InternetExplorer,
}

impl LegacyEnginePolicy {
  fn rejects_all_row_failures(self) -> bool {
    match self {
      Self::Gecko => true,
      Self::Safari => false,
      #[cfg(any(target_os = "windows", test))]
      Self::InternetExplorer => true,
    }
  }

  fn all_rows_rejected_fallback(self) -> &'static str {
    match self {
      Self::Gecko => "all Firefox cookie database rows failed to decode",
      Self::Safari => "all Safari cookie records failed to decode",
      #[cfg(any(target_os = "windows", test))]
      Self::InternetExplorer => "all Internet Explorer WebCache records failed to decode",
    }
  }
}

fn project_engine_outcome(
  browser_id: &str,
  outcome: EngineExtractionOutcome,
  policy: LegacyEnginePolicy,
) -> Result<Vec<Cookie>> {
  if let Some(error) = discovery_failure(&outcome, browser_id) {
    bail!(error)
  }
  let Some(profile) = outcome.profiles.into_iter().next() else {
    return Err(BrowserNotInstalled::CookieDatabase.into());
  };

  let mut cookies = Vec::new();
  let mut selected_session_succeeded = false;
  let mut failed_session_sources = Vec::new();
  for source in profile.sources {
    match source.role {
      registry::SOURCE_ROLE_PERSISTENT if source.selected => {
        cookies.extend(selected_source_cookies(source, policy)?);
      }
      registry::SOURCE_ROLE_SESSION if source.selected && source.error.is_none() => {
        // Historical Firefox extraction logs an invalid session candidate and
        // continues to the first valid one; it does not fail the whole call.
        selected_session_succeeded = true;
        cookies.extend(source.cookies);
      }
      registry::SOURCE_ROLE_SESSION if policy == LegacyEnginePolicy::Gecko => {
        if let Some(error) = source.error {
          failed_session_sources.push(format!("{}: {error}", source.path.display()));
        }
      }
      _ => {}
    }
  }
  if cookies.is_empty() && !selected_session_succeeded && !failed_session_sources.is_empty() {
    bail!(
      "all existing Firefox session store candidates failed: {}",
      failed_session_sources.join("; ")
    )
  }
  Ok(cookies)
}

/// Extracts one registered browser using the legacy first-profile projection.
pub(crate) fn browser_cookies(
  browser_id: &str,
  domains: Option<Vec<String>>,
) -> Result<Vec<Cookie>> {
  let browser = registry::resolve_registered_browser(browser_id)?;
  match browser.engine {
    "chromium" => registry::legacy_chromium_cookies(&browser.canonical_id, domains)?
      .ok_or_else(|| BrowserNotInstalled::CookieDatabase.into()),
    "gecko" => project_engine_outcome(
      &browser.canonical_id,
      registry::legacy_gecko_outcome(&browser.canonical_id, domains)?,
      LegacyEnginePolicy::Gecko,
    ),
    #[cfg(target_os = "macos")]
    "safari" => project_engine_outcome(
      &browser.canonical_id,
      registry::legacy_safari_outcome(&browser.canonical_id, domains)?,
      LegacyEnginePolicy::Safari,
    ),
    #[cfg(target_os = "windows")]
    "internet_explorer" => project_engine_outcome(
      &browser.canonical_id,
      registry::legacy_internet_explorer_outcome(&browser.canonical_id, domains)?,
      LegacyEnginePolicy::InternetExplorer,
    ),
    engine => bail!(
      "browser {:?} uses unsupported engine {engine:?}",
      browser.canonical_id
    ),
  }
}

/// Compatibility-shaped persistent Gecko profiles from registry discovery.
pub(crate) fn gecko_profiles(browser_id: &str) -> Result<Vec<MozillaProfile>> {
  let outcome = registry::legacy_gecko_profiles(browser_id)?;
  if let Some(error) = discovery_failure(&outcome, browser_id) {
    bail!(error)
  }
  let profiles = outcome
    .profiles
    .into_iter()
    .map(|profile| MozillaProfile {
      name: profile.name,
      path: profile.path,
      is_default: profile.is_default,
    })
    .collect::<Vec<_>>();
  if profiles.is_empty() {
    return Err(BrowserNotInstalled::ProfileWithCookieDatabase.into());
  }
  Ok(profiles)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::browser::registry::{
    EngineProfileExtraction, SourceAcquisition, SourceFailureStage, PERSISTENT_SOURCE_PRECEDENCE,
    SOURCE_ROLE_PERSISTENT, SOURCE_ROLE_SESSION,
  };
  use std::path::PathBuf;

  fn profile_with(source: Option<EngineSourceExtraction>) -> EngineExtractionOutcome {
    EngineExtractionOutcome {
      profiles: vec![EngineProfileExtraction {
        profile_id: "a".repeat(64),
        installation_id: "b".repeat(64),
        installation_priority: 10,
        legacy_profile_order: 0,
        installation_path: PathBuf::from("/browser"),
        name: "default".to_owned(),
        path: PathBuf::from("/browser/default"),
        is_default: true,
        persistent_source_discovered: true,
        sources: source.into_iter().collect(),
      }],
      installations_detected: 1,
      installations_discovered: 1,
      installations_enumerated: 1,
      ..EngineExtractionOutcome::default()
    }
  }

  fn persistent_source(error: Option<&str>, row_error: Option<&str>) -> EngineSourceExtraction {
    EngineSourceExtraction {
      path: PathBuf::from("/browser/default/cookies.sqlite"),
      role: SOURCE_ROLE_PERSISTENT,
      format: "mozilla_sqlite",
      precedence: PERSISTENT_SOURCE_PRECEDENCE,
      selected: true,
      cookies: Vec::new(),
      rows_seen: usize::from(row_error.is_some()),
      rows_skipped: usize::from(row_error.is_some()),
      acquisition: SourceAcquisition::NotAttempted,
      acquisition_attempts: 1,
      diagnostics: Vec::new(),
      error: error.map(str::to_owned),
      error_stage: SourceFailureStage::Acquisition,
      row_error: row_error.map(str::to_owned),
    }
  }

  fn failed_session_source(path: &str, error: &str) -> EngineSourceExtraction {
    EngineSourceExtraction {
      path: PathBuf::from(path),
      role: SOURCE_ROLE_SESSION,
      format: "firefox_session_jsonlz4",
      precedence: 20,
      selected: false,
      cookies: Vec::new(),
      rows_seen: 0,
      rows_skipped: 0,
      acquisition: SourceAcquisition::StableFileImage,
      acquisition_attempts: 1,
      diagnostics: Vec::new(),
      error: Some(error.to_owned()),
      error_stage: SourceFailureStage::Parse,
      row_error: None,
    }
  }

  fn empty_outcome_with_issue(code: &'static str) -> EngineExtractionOutcome {
    EngineExtractionOutcome {
      discovery_issues: vec![registry::DiscoveryIssue {
        code,
        path: PathBuf::from("/browser/discovery"),
        message: "injected discovery failure".to_owned(),
        occurrences: 1,
      }],
      installations_detected: 1,
      installations_discovered: 1,
      installations_enumerated: 1,
      ..EngineExtractionOutcome::default()
    }
  }

  #[test]
  fn ordinary_absence_stays_typed_for_load() {
    let error = project_engine_outcome(
      "firefox",
      EngineExtractionOutcome::default(),
      LegacyEnginePolicy::Gecko,
    )
    .expect_err("absence");
    assert!(is_browser_not_installed(&error));
  }

  #[test]
  fn non_profile_discovery_failures_do_not_become_browser_absence() {
    for code in [
      "mozilla_profiles_ini_invalid",
      "safari_profile_enumeration_failed",
    ] {
      let error = project_engine_outcome(
        "browser",
        empty_outcome_with_issue(code),
        LegacyEnginePolicy::Safari,
      )
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
      let error = project_engine_outcome(
        "browser",
        empty_outcome_with_issue(code),
        LegacyEnginePolicy::Safari,
      )
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
      let error = project_engine_outcome(
        "firefox",
        profile_with(Some(source)),
        LegacyEnginePolicy::Gecko,
      )
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
      LegacyEnginePolicy::InternetExplorer,
    )
    .expect_err("all rejected WebCache rows must fail the legacy projection");

    assert!(error.to_string().contains("every WebCache row failed"));
    assert!(!is_browser_not_installed(&error));

    let mut source = persistent_source(None, None);
    source.rows_seen = 1;
    source.rows_skipped = 1;
    let error = project_engine_outcome(
      "internet_explorer",
      profile_with(Some(source)),
      LegacyEnginePolicy::InternetExplorer,
    )
    .expect_err("skipped WebCache rows need an error even without a detailed row message");
    assert!(error
      .to_string()
      .contains("all Internet Explorer WebCache records failed to decode"));
  }

  #[test]
  fn total_session_failures_surface_when_persistent_extraction_is_empty() {
    let mut outcome = profile_with(Some(persistent_source(None, None)));
    outcome.profiles[0].sources.extend([
      failed_session_source("/browser/default/recovery.jsonlz4", "invalid mozLz4"),
      failed_session_source("/browser/default/sessionstore.js", "invalid JSON"),
    ]);

    let error = project_engine_outcome("firefox", outcome, LegacyEnginePolicy::Gecko)
      .expect_err("all existing session candidates failed");
    let message = error.to_string();
    assert!(message.contains("all existing Firefox session store candidates failed"));
    assert!(message.contains("recovery.jsonlz4: invalid mozLz4"));
    assert!(message.contains("sessionstore.js: invalid JSON"));

    let mut selected_empty = failed_session_source("/browser/default/sessionstore.js", "unused");
    selected_empty.selected = true;
    selected_empty.error = None;
    let mut recovered = profile_with(Some(persistent_source(None, None)));
    recovered.profiles[0].sources.extend([
      failed_session_source("/browser/default/recovery.jsonlz4", "invalid mozLz4"),
      selected_empty,
    ]);
    assert!(
      project_engine_outcome("firefox", recovered, LegacyEnginePolicy::Gecko)
        .expect("an authoritative empty session source is still a success")
        .is_empty()
    );
  }
}
