use super::{
  automatic_chromium_cookies, automatic_chromium_detailed, invalid_options, shared,
  unsupported_target, ChromiumCredentialSource, ChromiumLockedDatabasePolicy, ChromiumPathRequest,
  CookieSourceKind, DirectPathRequest, InvalidDirectPathOptionsReason,
};
use crate::browser::chromium_crypto::ChromiumKeyOutcomes;
use crate::browser::chromium_platform_keys::{ChromiumKeyRequest, HostKeySession};
use crate::browser::registry::DirectPathChromiumIdentity;
use crate::enums::{Cookie, DetailedCookie};
use anyhow::Result;
use std::path::{Path, PathBuf};

pub(super) const AUTOMATIC_BROWSER_IDS: &[&str] = &[
  "chrome", "brave", "chromium", "edge", "opera", "vivaldi", "arc",
];

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
    CookieSourceKind::ChromiumSqlite => automatic_chromium_detailed(
      AUTOMATIC_BROWSER_IDS,
      request.path,
      request.domains,
      runtime,
    ),
    CookieSourceKind::MozillaSqlite => {
      crate::browser::mozilla::firefox_based_detailed_with_runtime(
        request.path,
        request.domains,
        runtime,
      )
    }
    CookieSourceKind::SafariBinaryCookies | CookieSourceKind::InternetExplorerEse => {
      Err(unsupported_target(source))
    }
  }
}

pub(super) fn chromium_cookies_from_path(
  request: ChromiumPathRequest,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  validate_lock_policy(request.locked_database_policy)?;
  match request.credentials {
    ChromiumCredentialSource::Automatic => {
      automatic_chromium(request.path, request.domains, runtime)
    }
    ChromiumCredentialSource::PlaintextOnly => {
      crate::browser::chromium::chromium_based_plaintext_only_with_runtime(
        request.path,
        request.domains,
        false,
        runtime,
      )
    }
    ChromiumCredentialSource::BrowserId(browser_id) => {
      let outcomes = browser_id_outcomes(&browser_id, runtime)?;
      crate::browser::chromium::query_cookies_with_key_outcomes_runtime(
        outcomes,
        request.path,
        request.domains,
        false,
        runtime,
      )
    }
    ChromiumCredentialSource::LocalStateFile(_) => Err(invalid_options(
      InvalidDirectPathOptionsReason::LocalStateNotSupportedOnTarget,
    )),
  }
}

pub(super) fn chromium_cookies_from_path_detailed(
  request: ChromiumPathRequest,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<DetailedCookie>> {
  validate_lock_policy(request.locked_database_policy)?;
  match request.credentials {
    ChromiumCredentialSource::Automatic => automatic_chromium_detailed(
      AUTOMATIC_BROWSER_IDS,
      request.path,
      request.domains,
      runtime,
    ),
    ChromiumCredentialSource::PlaintextOnly => {
      crate::browser::chromium::chromium_based_detailed_plaintext_only_with_runtime(
        request.path,
        request.domains,
        false,
        runtime,
      )
    }
    ChromiumCredentialSource::BrowserId(browser_id) => {
      let outcomes = browser_id_outcomes(&browser_id, runtime)?;
      crate::browser::chromium::query_detailed_cookies_with_key_outcomes_runtime(
        outcomes,
        request.path,
        request.domains,
        false,
        runtime,
      )
    }
    ChromiumCredentialSource::LocalStateFile(_) => Err(invalid_options(
      InvalidDirectPathOptionsReason::LocalStateNotSupportedOnTarget,
    )),
  }
}

pub(crate) fn automatic_chromium(
  path: PathBuf,
  domains: Option<Vec<String>>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  automatic_chromium_cookies(AUTOMATIC_BROWSER_IDS, path, domains, runtime)
}

fn validate_lock_policy(policy: ChromiumLockedDatabasePolicy) -> Result<()> {
  if policy == ChromiumLockedDatabasePolicy::AllowProcessShutdown {
    return Err(invalid_options(
      InvalidDirectPathOptionsReason::ProcessShutdownNotSupportedOnTarget,
    ));
  }
  Ok(())
}

fn browser_id_outcomes(
  browser_id: &str,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<ChromiumKeyOutcomes> {
  if browser_id.is_empty() {
    return Err(invalid_options(
      InvalidDirectPathOptionsReason::EmptyBrowserId,
    ));
  }
  match crate::browser::registry::direct_path_chromium_identity(browser_id)? {
    DirectPathChromiumIdentity::Unknown => Err(invalid_options(
      InvalidDirectPathOptionsReason::UnknownBrowserId,
    )),
    DirectPathChromiumIdentity::OtherEngine => Err(invalid_options(
      InvalidDirectPathOptionsReason::BrowserIdIsNotChromium,
    )),
    DirectPathChromiumIdentity::Chromium(None) => Ok(missing_identity(browser_id)),
    DirectPathChromiumIdentity::Chromium(Some(credentials))
      if credentials
        .linux_crypt_name
        .as_deref()
        .is_none_or(str::is_empty) =>
    {
      Ok(missing_identity(browser_id))
    }
    DirectPathChromiumIdentity::Chromium(Some(credentials)) => {
      let mut session = HostKeySession::new();
      Ok(session.retrieve(
        ChromiumKeyRequest::for_browser_id(browser_id, &credentials),
        runtime,
      ))
    }
  }
}

fn missing_identity(browser_id: &str) -> ChromiumKeyOutcomes {
  ChromiumKeyOutcomes::provider_failure(format!("browser {browser_id:?} has no Linux key identity"))
}
