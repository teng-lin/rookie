use super::{undetected, undetected_listing, BrowserDraft, BrowserListing};
use crate::browser::registry::ProfileSelection;
use crate::browser::report_core::BrowserId;
use crate::common::deadline::BoundaryRuntime;
use anyhow::Result;

pub(super) fn remaining_engine_extraction(
  browser_id: &BrowserId,
  _canonical_id: &str,
  _engine: &str,
  _selection: crate::browser::registry::ProfileSelection<'_>,
  _domains: Option<Vec<String>>,
  _runtime: &BoundaryRuntime<'_>,
) -> Result<BrowserDraft> {
  Ok(undetected(browser_id))
}

pub(super) fn remaining_engine_listing(
  _browser_id: &BrowserId,
  _canonical_id: &str,
  _engine: &str,
  _runtime: &BoundaryRuntime<'_>,
) -> Result<BrowserListing> {
  Ok(undetected_listing())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn other_leaf_reports_platform_only_engines_as_undetected() {
    let clock = crate::common::deadline::SystemClock;
    let runtime = BoundaryRuntime::standard(&clock);
    for (canonical_id, engine) in [
      ("safari", "safari"),
      ("internet_explorer", "internet_explorer"),
    ] {
      let browser_id = BrowserId::known(canonical_id);
      let draft = remaining_engine_extraction(
        &browser_id,
        canonical_id,
        engine,
        ProfileSelection::AllProfiles,
        None,
        &runtime,
      )
      .expect("undetected, not an error");
      assert!(!draft.detected);

      let listing = remaining_engine_listing(&browser_id, canonical_id, engine, &runtime)
        .expect("undetected, not an error");
      assert!(!listing.discovery_failed);
      assert!(listing.profiles.is_empty());
    }
  }
}
