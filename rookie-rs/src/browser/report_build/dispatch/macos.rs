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
  if engine != "safari" {
    return Ok(undetected(browser_id));
  }
  let engine = if extract {
    registry::safari_report_with_runtime(canonical_id, profile_id, domains, runtime)?
  } else {
    registry::safari_profiles_with_runtime(canonical_id, runtime)?
  };
  super::super::engine_browser_outcome(browser_id, engine)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn macos_leaf_reports_every_other_engine_as_undetected() {
    let clock = crate::common::deadline::SystemClock;
    let runtime = BoundaryRuntime::standard(&clock);
    let browser_id = BrowserId::known("internet_explorer");
    let draft = remaining_engine_report(
      &browser_id,
      "internet_explorer",
      "internet_explorer",
      None,
      true,
      None,
      &runtime,
    )
    .expect("undetected, not an error");
    assert!(!draft.detected);
  }
}
