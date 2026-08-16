use super::{undetected, BrowserDraft};
use crate::browser::report_core::BrowserId;
use crate::common::deadline::BoundaryRuntime;
use anyhow::Result;

pub(super) fn remaining_engine_report(
  browser_id: &BrowserId,
  _canonical_id: &str,
  _engine: &str,
  _profile_id: Option<&str>,
  _extract: bool,
  _domains: Option<Vec<String>>,
  _runtime: &BoundaryRuntime<'_>,
) -> Result<BrowserDraft> {
  Ok(undetected(browser_id))
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
      let draft = remaining_engine_report(
        &browser_id,
        canonical_id,
        engine,
        None,
        true,
        None,
        &runtime,
      )
      .expect("undetected, not an error");
      assert!(!draft.detected);
    }
  }
}
