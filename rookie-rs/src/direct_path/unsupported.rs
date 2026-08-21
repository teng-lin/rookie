#[cfg(unix)]
use super::ChromiumCredentialSource;
use super::{shared, unsupported_target, CookieSourceKind, PathExtractRequest};
use crate::enums::DetailedCookie;
use anyhow::Result;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;

#[cfg(unix)]
pub(super) fn unix_identity(
  path: impl Into<PathBuf>,
  browser_id: impl Into<String>,
) -> PathExtractRequest {
  PathExtractRequest::with_credentials(
    path,
    Some(ChromiumCredentialSource::BrowserId(browser_id.into())),
  )
}

pub(super) fn classify_cookie_source(
  path: &Path,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<CookieSourceKind> {
  shared::classify_path_with_runtime(path, runtime)
}

pub(super) fn detailed_from_path(
  request: PathExtractRequest,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<DetailedCookie>> {
  let source = super::classify_request_source(&request, runtime)?;
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

#[cfg(all(test, unix))]
mod tests {
  use super::*;

  #[test]
  fn unix_identity_constructor_remains_available_on_unsupported_unix_targets() {
    let request = unix_identity("Cookies", "chrome");
    assert!(matches!(
      request.target.credentials,
      Some(ChromiumCredentialSource::BrowserId(ref browser_id)) if browser_id == "chrome"
    ));
  }
}
