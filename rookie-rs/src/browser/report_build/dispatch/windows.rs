use super::{undetected, BrowserDraft};
use crate::browser::registry;
use crate::browser::report_core::BrowserId;
use crate::common::deadline::BoundaryRuntime;
use anyhow::Result;

pub(super) fn remaining_engine_report(
  browser_id: &BrowserId,
  canonical_id: &str,
  engine: &str,
  profile_id: Option<&str>,
  extract: bool,
  domains: Option<Vec<String>>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<BrowserDraft> {
  if engine != "internet_explorer" {
    return Ok(undetected(browser_id));
  }
  if extract {
    let engine =
      registry::internet_explorer_report_with_runtime(canonical_id, profile_id, domains, runtime)?;
    super::super::engine_extract_outcome(browser_id, engine)
  } else {
    let listing = registry::internet_explorer_profiles_with_runtime(canonical_id, runtime)?;
    super::super::engine_listing_outcome(browser_id, listing)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn windows_leaf_reports_every_other_engine_as_undetected() {
    let clock = crate::common::deadline::SystemClock;
    let runtime = BoundaryRuntime::standard(&clock);
    let browser_id = BrowserId::known("safari");
    let draft =
      remaining_engine_report(&browser_id, "safari", "safari", None, true, None, &runtime)
        .expect("undetected, not an error");
    assert!(!draft.detected);
  }
}
