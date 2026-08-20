//! Target-selected routing for the safari/internet_explorer arms of
//! `collect_extraction`/`collect_listing`. `chromium`/`gecko` are portable and
//! stay inline; only the platform-only engines are routed through here, one
//! leaf per target selected at compile time rather than inline `#[cfg(...)]`
//! match arms.

use super::{engine_compatibility_family, BrowserDraft, BrowserListing};
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

pub(super) fn remaining_engine_extraction(
  browser_id: &BrowserId,
  canonical_id: &str,
  engine: &str,
  profile_id: Option<&str>,
  domains: Option<Vec<String>>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<BrowserDraft> {
  platform::remaining_engine_extraction(
    browser_id,
    canonical_id,
    engine,
    profile_id,
    domains,
    runtime,
  )
}

pub(super) fn remaining_engine_listing(
  browser_id: &BrowserId,
  canonical_id: &str,
  engine: &str,
  runtime: &BoundaryRuntime<'_>,
) -> Result<BrowserListing> {
  platform::remaining_engine_listing(browser_id, canonical_id, engine, runtime)
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

/// The listing counterpart of [`undetected`]: an unmapped engine looked, and
/// found nothing.
fn undetected_listing() -> BrowserListing {
  BrowserListing {
    discovery_failed: false,
    profiles: Vec::new(),
    issues: Vec::new(),
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

  #[test]
  fn undetected_listing_reports_a_clean_absence() {
    let listing = undetected_listing();
    assert!(!listing.discovery_failed);
    assert!(listing.profiles.is_empty());
    assert!(listing.issues.is_empty());
  }
}
