use super::{shared, unsupported_target, ChromiumPathRequest, CookieSourceKind, DirectPathRequest};
use crate::enums::{Cookie, DetailedCookie};
use anyhow::Result;
use std::path::Path;

pub(super) fn classify_cookie_source(path: &Path) -> Result<CookieSourceKind> {
  shared::classify_path(path)
}

pub(super) fn cookies_from_path(
  request: DirectPathRequest,
  source: CookieSourceKind,
) -> Result<Vec<Cookie>> {
  match source {
    CookieSourceKind::MozillaSqlite => {
      crate::browser::mozilla::firefox_based(request.path, request.domains)
    }
    _ => Err(unsupported_target(source)),
  }
}

pub(super) fn chromium_cookies_from_path(_request: ChromiumPathRequest) -> Result<Vec<Cookie>> {
  Err(unsupported_target(CookieSourceKind::ChromiumSqlite))
}

pub(super) fn chromium_cookies_from_path_detailed(
  _request: ChromiumPathRequest,
) -> Result<Vec<DetailedCookie>> {
  Err(unsupported_target(CookieSourceKind::ChromiumSqlite))
}
