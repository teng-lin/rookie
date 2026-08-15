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
    .filter(|issue| {
      issue.code.starts_with("profile_")
        && !matches!(
          issue.code,
          "profile_has_no_cookie_source" | "profile_excluded_service_directory"
        )
    })
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
  gecko_legacy_rows: bool,
) -> Result<Vec<Cookie>> {
  if let Some(error) = source.error {
    bail!(error)
  }
  if gecko_legacy_rows && source.cookies.is_empty() {
    if let Some(error) = source.row_error {
      bail!(error)
    }
  }
  Ok(source.cookies)
}

fn project_engine_outcome(
  browser_id: &str,
  outcome: EngineExtractionOutcome,
  gecko: bool,
) -> Result<Vec<Cookie>> {
  if let Some(error) = discovery_failure(&outcome, browser_id) {
    bail!(error)
  }
  let Some(profile) = outcome.profiles.into_iter().next() else {
    return Err(BrowserNotInstalled::CookieDatabase.into());
  };

  let mut cookies = Vec::new();
  for source in profile.sources {
    if !source.selected {
      continue;
    }
    match source.role {
      registry::SOURCE_ROLE_PERSISTENT => {
        cookies.extend(selected_source_cookies(source, gecko)?);
      }
      registry::SOURCE_ROLE_SESSION if source.error.is_none() => {
        // Historical Firefox extraction logs an invalid session candidate and
        // continues to the first valid one; it does not fail the whole call.
        cookies.extend(source.cookies);
      }
      _ => {}
    }
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
      true,
    ),
    #[cfg(target_os = "macos")]
    "safari" => project_engine_outcome(
      &browser.canonical_id,
      registry::legacy_safari_outcome(&browser.canonical_id, domains)?,
      false,
    ),
    #[cfg(target_os = "windows")]
    "internet_explorer" => project_engine_outcome(
      &browser.canonical_id,
      registry::legacy_internet_explorer_outcome(&browser.canonical_id, domains)?,
      false,
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
    SOURCE_ROLE_PERSISTENT,
  };
  use std::path::PathBuf;

  fn profile_with(source: Option<EngineSourceExtraction>) -> EngineExtractionOutcome {
    EngineExtractionOutcome {
      profiles: vec![EngineProfileExtraction {
        profile_id: "a".repeat(64),
        installation_id: "b".repeat(64),
        installation_priority: 10,
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

  #[test]
  fn ordinary_absence_stays_typed_for_load() {
    let error = project_engine_outcome("firefox", EngineExtractionOutcome::default(), true)
      .expect_err("absence");
    assert!(is_browser_not_installed(&error));
  }

  #[test]
  fn source_and_all_row_failures_are_not_misclassified_as_absence() {
    for source in [
      persistent_source(Some("database is corrupt"), None),
      persistent_source(None, Some("every row failed")),
    ] {
      let error = project_engine_outcome("firefox", profile_with(Some(source)), true)
        .expect_err("real extraction failure");
      assert!(!is_browser_not_installed(&error));
    }
  }
}
