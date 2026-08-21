use super::{
  automatic_chromium_cookies, invalid_options, shared, unsupported_target,
  ChromiumCredentialSource, ChromiumLockedDatabasePolicy, CookieSourceKind,
  InvalidDirectPathOptionsReason, PathExtractRequest,
};
use crate::browser::chromium_crypto::ChromiumKeyOutcomes;
use crate::browser::chromium_platform_keys::{ChromiumKeyRequest, HostKeySession};
use crate::browser::registry::DirectPathChromiumIdentity;
use crate::enums::{Cookie, DetailedCookie};
use anyhow::Result;
use std::path::{Path, PathBuf};

pub(super) const AUTOMATIC_BROWSER_IDS: &[&str] = &[
  "chrome", "brave", "chromium", "edge", "opera", "vivaldi", "arc", "opera_gx",
];

/// Reads an encrypted Chromium database using one registry browser identity.
///
/// This constructor is Unix-only, and it lives in this platform leaf rather
/// than in `mod.rs` because `check-cfg-locations` pins `direct_path/mod.rs` to
/// its current platform-`cfg` count. Defining it here and re-exporting it
/// through the module's existing selection gate keeps that ceiling where it is
/// -- and it is also the honest home for a value that means nothing on
/// Windows.
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
  source: CookieSourceKind,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<DetailedCookie>> {
  let PathExtractRequest {
    target, domains, ..
  } = request;
  match target.credentials {
    Some(credentials) => {
      validate_lock_policy(target.locked_database_policy)?;
      chromium_detailed(credentials, target.path, domains, runtime)
    }
    // No credentials: the caller asked this file to be identified, not
    // decrypted. Chromium is therefore plaintext-capable only -- the ordered
    // identity probe this used to fall back to is a guess at which browser
    // wrote the file, and 0.6.0 does not guess.
    None => match source {
      CookieSourceKind::ChromiumSqlite => {
        crate::browser::chromium::chromium_based_detailed_plaintext_only_with_runtime(
          target.path,
          domains,
          false,
          runtime,
        )
        .map_err(super::sniffed_chromium_error)
      }
      CookieSourceKind::MozillaSqlite => {
        crate::browser::mozilla::firefox_based_detailed_with_runtime(target.path, domains, runtime)
      }
      CookieSourceKind::SafariBinaryCookies => {
        crate::browser::safari::safari_based_detailed_with_runtime(target.path, domains, runtime)
      }
      CookieSourceKind::InternetExplorerEse => Err(unsupported_target(source)),
    },
  }
}

fn chromium_detailed(
  credentials: ChromiumCredentialSource,
  path: PathBuf,
  domains: Option<Vec<String>>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<DetailedCookie>> {
  match credentials {
    ChromiumCredentialSource::PlaintextOnly => {
      crate::browser::chromium::chromium_based_detailed_plaintext_only_with_runtime(
        path, domains, false, runtime,
      )
    }
    ChromiumCredentialSource::BrowserId(browser_id) => {
      let outcomes = browser_id_outcomes(&browser_id, runtime)?;
      crate::browser::chromium::extract_detailed_cookies_with_key_outcomes_runtime(
        outcomes, path, domains, false, runtime,
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
        .macos_keychain
        .as_ref()
        .is_none_or(|identity| identity.service.is_empty() || identity.account.is_empty()) =>
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
  ChromiumKeyOutcomes::provider_failure(format!(
    "browser {browser_id:?} has no macOS Keychain identity"
  ))
}
