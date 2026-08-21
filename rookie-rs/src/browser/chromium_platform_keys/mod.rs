mod shared;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod unsupported;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
pub(crate) use linux::{legacy_key_outcomes, HostKeySession};
#[cfg(target_os = "macos")]
pub(crate) use macos::{legacy_key_outcomes, HostKeySession};
#[cfg(any(target_os = "linux", target_os = "macos", all(test, unix)))]
pub(crate) use shared::create_pbkdf2_key;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) use unsupported::{legacy_key_outcomes, HostKeySession};
#[cfg(target_os = "windows")]
pub(crate) use windows::HostKeySession;

use serde::Deserialize;
use std::path::Path;

#[cfg(unix)]
type LegacyKeyOutcomesFn = for<'config, 'runtime, 'clock> fn(
  &'config crate::config::Browser,
  &'runtime crate::common::deadline::BoundaryRuntime<'clock>,
) -> anyhow::Result<
  super::chromium_crypto::ChromiumKeyOutcomes,
>;

// Linux, macOS, and other Unix leaves expose one compatibility-key adapter.
// Cross-target compilation checks the selected implementation against this
// exact facade contract.
#[cfg(unix)]
const _: LegacyKeyOutcomesFn = legacy_key_outcomes;

/// Registry-resolved lookup identities, never key material.
///
/// Deserialized directly from `browser_registry.json`'s `key_credentials`
/// object (Section 5.9). Field names are wire-frozen: `browser_registry.json`
/// is not this program's to change, so this struct and
/// [`MacosKeychainCredentials`] are also the JSON DTO — there is no separate
/// registry-side projection type to keep in sync.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub(crate) struct ChromiumKeyIdentity {
  pub(crate) linux_crypt_name: Option<String>,
  pub(crate) macos_keychain: Option<MacosKeychainCredentials>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub(crate) struct MacosKeychainCredentials {
  /// Keychain generic-password service, e.g. `"Chrome Safe Storage"`.
  pub(crate) service: String,
  /// Its account name, e.g. `"Chrome"`.
  pub(crate) account: String,
}

impl ChromiumKeyIdentity {
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  pub(crate) fn from_legacy_browser(config: &crate::config::Browser) -> Self {
    let macos_keychain = match (&config.osx_key_service, &config.osx_key_user) {
      (None, None) => None,
      (service, account) => Some(MacosKeychainCredentials {
        service: service.clone().unwrap_or_default(),
        account: account.clone().unwrap_or_default(),
      }),
    };
    Self {
      linux_crypt_name: config.unix_crypt_name.clone(),
      macos_keychain,
    }
  }
}

/// Installation Local State supplied to the host key capability.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub(crate) enum LocalStateInput<'a> {
  NotApplicable,
  Path(&'a Path),
  Parsed(&'a serde_json::Value),
}

/// Borrowed input for one platform-key lookup.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct ChromiumKeyRequest<'a> {
  browser_id: Option<&'a str>,
  credentials: &'a ChromiumKeyIdentity,
  local_state: LocalStateInput<'a>,
}

impl<'a> ChromiumKeyRequest<'a> {
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  pub(crate) fn direct(credentials: &'a ChromiumKeyIdentity) -> Self {
    Self {
      browser_id: None,
      credentials,
      local_state: LocalStateInput::NotApplicable,
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  pub(crate) fn for_browser_id(browser_id: &'a str, credentials: &'a ChromiumKeyIdentity) -> Self {
    Self {
      browser_id: Some(browser_id),
      credentials,
      local_state: LocalStateInput::NotApplicable,
    }
  }

  pub(crate) fn for_installation(
    browser_id: &'a str,
    credentials: &'a ChromiumKeyIdentity,
    local_state_path: &'a Path,
    parsed_local_state: Option<&'a serde_json::Value>,
  ) -> Self {
    Self {
      browser_id: Some(browser_id),
      credentials,
      local_state: parsed_local_state.map_or(
        LocalStateInput::Path(local_state_path),
        LocalStateInput::Parsed,
      ),
    }
  }

  /// Windows path-only requests have a Local State file but no registry id.
  /// App-Bound host resolution infers the vendor from the user-data path.
  #[cfg(target_os = "windows")]
  pub(crate) fn for_local_state_file(
    credentials: &'a ChromiumKeyIdentity,
    local_state_path: &'a Path,
  ) -> Self {
    Self {
      browser_id: None,
      credentials,
      local_state: LocalStateInput::Path(local_state_path),
    }
  }

  #[cfg(target_os = "windows")]
  fn local_state_path(&self) -> Option<&'a Path> {
    match self.local_state {
      LocalStateInput::Path(path) => Some(path),
      LocalStateInput::Parsed(_) | LocalStateInput::NotApplicable => None,
    }
  }

  #[cfg(test)]
  pub(crate) fn browser_id(&self) -> Option<&'a str> {
    self.browser_id
  }

  #[cfg(test)]
  pub(crate) fn credentials(&self) -> &'a ChromiumKeyIdentity {
    self.credentials
  }

  #[cfg(test)]
  pub(crate) fn local_state(&self) -> LocalStateInput<'a> {
    self.local_state
  }
}
