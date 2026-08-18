use super::unsupported_engine;
use crate::common::deadline::BoundaryRuntime;
use anyhow::Result;

pub(super) fn remaining_engine_snapshot_with_runtime(
  canonical_id: &str,
  engine: &str,
  _domains: Option<Vec<String>>,
  _runtime: &BoundaryRuntime<'_>,
) -> Result<super::super::LegacySnapshot> {
  unsupported_engine(canonical_id, engine)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn other_leaf_rejects_platform_only_engines_with_exact_errors() {
    let clock = crate::common::deadline::SystemClock;
    let runtime = BoundaryRuntime::standard(&clock);
    for (canonical_id, engine) in [
      ("safari", "safari"),
      ("internet_explorer", "internet_explorer"),
    ] {
      let error = remaining_engine_snapshot_with_runtime(canonical_id, engine, None, &runtime)
        .expect_err("platform-only engine is unavailable");
      assert_eq!(
        error.to_string(),
        format!("browser {canonical_id:?} uses unsupported engine {engine:?}")
      );
    }
  }
}
