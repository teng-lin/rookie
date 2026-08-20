//! Target-selected routing for the legacy engines that only exist on one
//! platform (Safari, Internet Explorer). `chromium`/`gecko` are portable and
//! stay inline in `browser_cookies_with_runtime`; only the platform-only
//! engines are routed through here, one leaf per target selected at compile
//! time rather than inline `#[cfg(...)]` match arms.

use crate::common::deadline::BoundaryRuntime;
use anyhow::{bail, Result};

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

pub(super) fn remaining_engine_snapshot_with_runtime(
  canonical_id: &str,
  engine: &str,
  domains: Option<Vec<String>>,
  runtime: &BoundaryRuntime<'_>,
  stop_projection: super::StopProjection,
) -> Result<super::LegacySnapshot> {
  platform::remaining_engine_snapshot_with_runtime(
    canonical_id,
    engine,
    domains,
    runtime,
    stop_projection,
  )
}

fn unsupported_engine(canonical_id: &str, engine: &str) -> Result<super::LegacySnapshot> {
  bail!("browser {canonical_id:?} uses unsupported engine {engine:?}")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn unsupported_engine_diagnostic_is_centralized() {
    let error = unsupported_engine("probe", "unknown").expect_err("unsupported engine");
    assert_eq!(
      error.to_string(),
      "browser \"probe\" uses unsupported engine \"unknown\""
    );
  }
}
