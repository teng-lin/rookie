use super::{undetected, undetected_listing, BrowserDraft, BrowserListing};
use crate::browser::registry;
use crate::browser::report_core::BrowserId;
use crate::common::deadline::BoundaryRuntime;
use anyhow::Result;

pub(super) fn remaining_engine_extraction(
  browser_id: &BrowserId,
  canonical_id: &str,
  engine: &str,
  profile_id: Option<&str>,
  domains: Option<Vec<String>>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<BrowserDraft> {
  if engine != "safari" {
    return Ok(undetected(browser_id));
  }
  let engine = registry::safari_report_with_runtime(canonical_id, profile_id, domains, runtime)?;
  super::super::engine_extract_outcome(browser_id, engine)
}

pub(super) fn remaining_engine_listing(
  browser_id: &BrowserId,
  canonical_id: &str,
  engine: &str,
  runtime: &BoundaryRuntime<'_>,
) -> Result<BrowserListing> {
  if engine != "safari" {
    return Ok(undetected_listing());
  }
  let listing = registry::safari_profiles_with_runtime(canonical_id, runtime)?;
  super::super::engine_listing_outcome(browser_id, listing)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn macos_leaf_reports_every_other_engine_as_undetected() {
    let clock = crate::common::deadline::SystemClock;
    let runtime = BoundaryRuntime::standard(&clock);
    let browser_id = BrowserId::known("internet_explorer");
    let draft = remaining_engine_extraction(
      &browser_id,
      "internet_explorer",
      "internet_explorer",
      None,
      None,
      &runtime,
    )
    .expect("undetected, not an error");
    assert!(!draft.detected);

    let listing = remaining_engine_listing(
      &browser_id,
      "internet_explorer",
      "internet_explorer",
      &runtime,
    )
    .expect("undetected, not an error");
    assert!(!listing.discovery_failed);
    assert!(listing.profiles.is_empty());
  }
}
