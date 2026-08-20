use super::unsupported_engine;
use crate::browser::registry;
use crate::common::deadline::BoundaryRuntime;
use anyhow::Result;

pub(super) fn remaining_engine_snapshot_with_runtime(
  canonical_id: &str,
  engine: &str,
  domains: Option<Vec<String>>,
  runtime: &BoundaryRuntime<'_>,
  stop_projection: super::super::StopProjection,
) -> Result<super::super::LegacySnapshot> {
  match engine {
    "safari" => super::super::cookies_and_skipped_from_engine_extract(
      canonical_id,
      registry::legacy_safari_outcome_with_runtime(canonical_id, domains, runtime)?,
      runtime,
      stop_projection,
    ),
    _ => unsupported_engine(canonical_id, engine),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn macos_leaf_rejects_every_other_engine_with_the_exact_error() {
    let clock = crate::common::deadline::SystemClock;
    let runtime = BoundaryRuntime::standard(&clock);
    let error = remaining_engine_snapshot_with_runtime(
      "internet_explorer",
      "internet_explorer",
      None,
      &runtime,
      crate::browser::legacy::StopProjection::ReturnError,
    )
    .expect_err("Internet Explorer is unsupported on macOS");
    assert_eq!(
      error.to_string(),
      "browser \"internet_explorer\" uses unsupported engine \"internet_explorer\""
    );
  }
}
