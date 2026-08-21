use super::{shared, unsupported_target, CookieSourceKind, PathExtractRequest};
use crate::enums::DetailedCookie;
use anyhow::Result;
use std::path::Path;

pub(super) fn classify_cookie_source(
  path: &Path,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<CookieSourceKind> {
  shared::classify_path_with_runtime(path, runtime)
}

pub(super) fn detailed_from_path(
  request: PathExtractRequest,
  source: CookieSourceKind,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<DetailedCookie>> {
  match source {
    CookieSourceKind::MozillaSqlite => {
      crate::browser::mozilla::firefox_based_detailed_with_runtime(
        request.target.path,
        request.domains,
        runtime,
      )
    }
    _ => Err(unsupported_target(source)),
  }
}
