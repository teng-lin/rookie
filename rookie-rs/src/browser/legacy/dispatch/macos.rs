use super::unsupported_engine;
use crate::browser::registry;
use crate::common::deadline::BoundaryRuntime;
use crate::common::enums::Cookie;
use anyhow::Result;

pub(super) fn remaining_engine_cookies_with_runtime(
  canonical_id: &str,
  engine: &str,
  domains: Option<Vec<String>>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  match engine {
    "safari" => super::super::project_engine_outcome_with_runtime(
      canonical_id,
      registry::legacy_safari_outcome_with_runtime(canonical_id, domains, runtime)?,
      runtime,
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
    let error = remaining_engine_cookies_with_runtime(
      "internet_explorer",
      "internet_explorer",
      None,
      &runtime,
    )
    .expect_err("Internet Explorer is unsupported on macOS");
    assert_eq!(
      error.to_string(),
      "browser \"internet_explorer\" uses unsupported engine \"internet_explorer\""
    );
  }
}
