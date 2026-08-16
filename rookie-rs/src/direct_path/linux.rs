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

pub(super) fn classify_cookie_source(path: &Path) -> Result<CookieSourceKind> {
  shared::classify_path(path)
}

pub(super) fn cookies_from_path(
  request: DirectPathRequest,
  source: CookieSourceKind,
) -> Result<Vec<Cookie>> {
  match source {
    CookieSourceKind::ChromiumSqlite => automatic_chromium(request.path, request.domains),
    CookieSourceKind::MozillaSqlite => {
      crate::browser::mozilla::firefox_based(request.path, request.domains)
    }
    CookieSourceKind::SafariBinaryCookies | CookieSourceKind::InternetExplorerEse => {
      Err(unsupported_target(source))
    }
  }
}

pub(super) fn chromium_cookies_from_path(request: ChromiumPathRequest) -> Result<Vec<Cookie>> {
  validate_lock_policy(request.locked_database_policy)?;
  match request.credentials {
    ChromiumCredentialSource::Automatic => automatic_chromium(request.path, request.domains),
    ChromiumCredentialSource::PlaintextOnly => {
      crate::browser::chromium::chromium_based_plaintext_only(request.path, request.domains, false)
    }
    ChromiumCredentialSource::BrowserId(browser_id) => {
      let clock = crate::common::deadline::SystemClock;
      let deadline = crate::common::deadline::Deadline::after(
        &clock,
        crate::common::deadline::DEFAULT_EXTRACTION_BUDGET,
      );
      let outcomes = browser_id_outcomes(&browser_id, deadline)?;
      crate::browser::chromium::query_cookies_with_key_outcomes_deadline(
        outcomes,
        request.path,
        request.domains,
        false,
        &clock,
        deadline,
      )
    }
    ChromiumCredentialSource::LocalStateFile(_) => Err(invalid_options(
      InvalidDirectPathOptionsReason::LocalStateNotSupportedOnTarget,
    )),
  }
}

pub(super) fn chromium_cookies_from_path_detailed(
  request: ChromiumPathRequest,
) -> Result<Vec<DetailedCookie>> {
  validate_lock_policy(request.locked_database_policy)?;
  match request.credentials {
    ChromiumCredentialSource::Automatic => {
      automatic_chromium_detailed(AUTOMATIC_BROWSER_IDS, request.path, request.domains)
    }
    ChromiumCredentialSource::PlaintextOnly => {
      crate::browser::chromium::chromium_based_detailed_plaintext_only(
        request.path,
        request.domains,
        false,
      )
    }
    ChromiumCredentialSource::BrowserId(browser_id) => {
      let clock = crate::common::deadline::SystemClock;
      let deadline = crate::common::deadline::Deadline::after(
        &clock,
        crate::common::deadline::DEFAULT_EXTRACTION_BUDGET,
      );
      let outcomes = browser_id_outcomes(&browser_id, deadline)?;
      crate::browser::chromium::query_detailed_cookies_with_key_outcomes_deadline(
        outcomes,
        request.path,
        request.domains,
        false,
        &clock,
        deadline,
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
) -> Result<Vec<Cookie>> {
  automatic_chromium_cookies(AUTOMATIC_BROWSER_IDS, path, domains)
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
  deadline: crate::common::deadline::Deadline,
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
        deadline,
      ))
    }
  }
}

fn missing_identity(browser_id: &str) -> ChromiumKeyOutcomes {
  ChromiumKeyOutcomes::provider_failure(format!("browser {browser_id:?} has no Linux key identity"))
}
