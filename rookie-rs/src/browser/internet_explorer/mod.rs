use crate::browser::report_core::{CookieSourceFormatId, CookieSourceRoleId};
use crate::browser::source::{AcquisitionPolicy, Source, SourceAcquisition, SourceCandidate};
use crate::common::deadline::{BoundaryRuntime, SystemClock};
use crate::common::enums::Cookie;
use anyhow::Result;
use std::path::{Path, PathBuf};

#[cfg(not(feature = "internet-explorer"))]
mod disabled;
#[cfg(feature = "internet-explorer")]
mod esedb;

#[cfg(not(feature = "internet-explorer"))]
use disabled as backend;
#[cfg(feature = "internet-explorer")]
use esedb as backend;

/// Returns cookies from IE based browsers.
///
/// Deprecated for removal, not just for a newer call shape: its ESE-format
/// cookie database is read through an unmodified native C library with no
/// process isolation, and this crate is not planning to keep investing in
/// containing it. See [`crate::internet_explorer`] for the full rationale.
/// `direct_path::extract_from_path` with `PathExtractRequest` remains
/// available for the rest of the deprecation window.
#[deprecated(
  since = "0.6.0",
  note = "Internet Explorer support is deprecated for removal; the Internet Explorer browser app was discontinued in 2022. Use direct_path::extract_from_path with PathExtractRequest for the rest of the deprecation window"
)]
pub fn internet_explorer_based(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<Cookie>> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  internet_explorer_based_with_runtime(db_path, domains, force_kill, &runtime)
}

pub(crate) fn internet_explorer_based_with_runtime(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  let source = internet_explorer_outcome_with_runtime(
    direct_path_candidate(&db_path),
    domains,
    force_kill,
    runtime,
  )?;
  crate::browser::legacy::project_canonical_outcome_with_runtime(
    "internet_explorer",
    crate::browser::report_build::finalize_singleton_source(
      "internet_explorer",
      db_path.parent().unwrap_or(&db_path).to_path_buf(),
      vec![source],
      None,
      Some(runtime),
    )?,
    runtime,
  )
}

/// Detailed twin of [`internet_explorer_based_with_runtime`].
///
/// The WebCache ESE store has no partition or container columns, so every
/// record projects an empty [`crate::enums::CookieContext`].
pub(crate) fn internet_explorer_based_detailed_with_runtime(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<crate::enums::DetailedCookie>> {
  let source = internet_explorer_outcome_with_runtime(
    direct_path_candidate(&db_path),
    domains,
    force_kill,
    runtime,
  )?;
  crate::browser::legacy::project_canonical_detailed_outcome_with_runtime(
    "internet_explorer",
    crate::browser::report_build::finalize_singleton_source(
      "internet_explorer",
      db_path.parent().unwrap_or(&db_path).to_path_buf(),
      vec![source],
      None,
      Some(runtime),
    )?,
    runtime,
  )
}

/// The candidate a direct-path Internet Explorer read is aimed at.
///
/// The values the direct-path report has always emitted for such a source. The
/// `EseDatabase` acquisition is the effective one: unlike Safari, IE's listing
/// candidates stay `NotAttempted` and the adapter overlays this only once a
/// WebCache query has been attempted.
pub(crate) fn direct_path_candidate(db_path: &Path) -> SourceCandidate {
  SourceCandidate {
    path: db_path.to_path_buf(),
    role: CookieSourceRoleId::persistent(),
    format: CookieSourceFormatId::known("internet_explorer_ese"),
    precedence: crate::browser::registry::PERSISTENT_SOURCE_PRECEDENCE,
    exists: true,
    selected: true,
    acquisition: SourceAcquisition::EseDatabase,
    policy: AcquisitionPolicy::Fixed,
  }
}

/// Reads one WebCache database and returns it as a [`Source`].
///
/// The feature-selected backend owns native acquisition. Keeping this facade
/// compiled in feature-off builds ensures every Windows caller continues to
/// type-check even when the bundled ESE C library is excluded.
pub(crate) fn internet_explorer_outcome_with_runtime(
  origin: SourceCandidate,
  domains: Option<Vec<String>>,
  force_kill: bool,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Source> {
  backend::query_source(origin, domains, force_kill, runtime)
}

#[cfg(all(test, not(feature = "internet-explorer")))]
mod tests {
  use super::*;
  use crate::browser::internet_explorer_model::{
    InternetExplorerFailure, InternetExplorerFailureStage,
  };

  fn assert_disabled(error: anyhow::Error) {
    assert_eq!(error.to_string(), disabled::DISABLED_MESSAGE);
    assert_eq!(
      error
        .downcast_ref::<InternetExplorerFailure>()
        .map(InternetExplorerFailure::stage),
      Some(InternetExplorerFailureStage::Acquisition)
    );
  }

  fn dummy_path() -> PathBuf {
    PathBuf::from(r"Z:\this-path-must-not-be-opened\WebCacheV01.dat")
  }

  #[test]
  #[allow(deprecated)]
  fn public_entry_point_fails_with_the_feature_error_before_io() {
    assert_disabled(
      internet_explorer_based(dummy_path(), None, true)
        .expect_err("the disabled backend must reject the public entry point"),
    );
  }

  #[test]
  fn runtime_entry_point_fails_with_the_feature_error_before_io() {
    let clock = SystemClock;
    let runtime = BoundaryRuntime::standard(&clock);
    assert_disabled(
      internet_explorer_based_with_runtime(dummy_path(), None, true, &runtime)
        .expect_err("the disabled backend must reject the runtime entry point"),
    );
  }

  #[test]
  fn detailed_entry_point_fails_with_the_feature_error_before_io() {
    let clock = SystemClock;
    let runtime = BoundaryRuntime::standard(&clock);
    assert_disabled(
      internet_explorer_based_detailed_with_runtime(dummy_path(), None, true, &runtime)
        .expect_err("the disabled backend must reject the detailed entry point"),
    );
  }

  #[test]
  fn source_entry_point_fails_with_the_feature_error_before_io() {
    let clock = SystemClock;
    let runtime = BoundaryRuntime::standard(&clock);
    let candidate = direct_path_candidate(&dummy_path());
    assert_disabled(
      internet_explorer_outcome_with_runtime(candidate, None, true, &runtime)
        .expect_err("the disabled backend must reject the source entry point"),
    );
  }
}
