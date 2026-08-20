use super::{shared, unsupported_target, ChromiumPathRequest, CookieSourceKind, DirectPathRequest};
use crate::enums::{Cookie, DetailedCookie};
use anyhow::Result;
use std::path::Path;

pub(super) fn classify_cookie_source(
  path: &Path,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<CookieSourceKind> {
  shared::classify_path_with_runtime(path, runtime)
}

pub(super) fn cookies_from_path_detailed(
  request: DirectPathRequest,
  source: CookieSourceKind,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<DetailedCookie>> {
  match source {
    CookieSourceKind::MozillaSqlite => {
      crate::browser::mozilla::firefox_based_detailed_with_runtime(
        request.path,
        request.domains,
        runtime,
      )
    }
    _ => Err(unsupported_target(source)),
  }
}

pub(super) fn chromium_cookies_from_path(
  _request: ChromiumPathRequest,
  _runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  Err(unsupported_target(CookieSourceKind::ChromiumSqlite))
}

pub(super) fn chromium_cookies_from_path_detailed(
  _request: ChromiumPathRequest,
  _runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<DetailedCookie>> {
  Err(unsupported_target(CookieSourceKind::ChromiumSqlite))
}
