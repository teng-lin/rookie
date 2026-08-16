//! Target-selected routing for the safari/internet_explorer arms of
//! `collect_report`. `chromium`/`gecko` are portable and stay inline; only
//! the platform-only engines are routed through here, one leaf per target
//! selected at compile time rather than inline `#[cfg(...)]` match arms.

use super::{engine_compatibility_family, BrowserDraft};
use crate::browser::outcome::Termination;
use crate::browser::report_core::BrowserId;
use crate::common::deadline::BoundaryRuntime;
use anyhow::Result;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as platform;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows as platform;

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
mod other;
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
use other as platform;

pub(super) fn remaining_engine_report(
  browser_id: &BrowserId,
  canonical_id: &str,
  engine: &str,
  profile_id: Option<&str>,
  extract: bool,
  domains: Option<Vec<String>>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<BrowserDraft> {
  platform::remaining_engine_report(
    browser_id,
    canonical_id,
    engine,
    profile_id,
    extract,
    domains,
    runtime,
  )
}

/// A registered browser whose engine has no adapter compiled into this build
/// is reported as undetected rather than silently skipped.
fn undetected(browser_id: &BrowserId) -> BrowserDraft {
  BrowserDraft {
    browser_id: browser_id.clone(),
    compatibility_family: engine_compatibility_family(browser_id),
    detected: false,
    installations_discovered: 0,
    discovery_failed: false,
    profiles: Vec::new(),
    issues: Vec::new(),
    termination: Termination::Completed,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn undetected_reports_a_clean_absence() {
    let browser_id = BrowserId::known("probe");
    let draft = undetected(&browser_id);
    assert!(!draft.detected);
    assert!(!draft.discovery_failed);
    assert!(draft.profiles.is_empty());
    assert!(draft.issues.is_empty());
    assert_eq!(draft.termination, Termination::Completed);
  }
}
