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
pub(crate) use linux::{HostKeySession, LinuxPlatformKeyProvider};
#[cfg(target_os = "macos")]
pub(crate) use macos::{HostKeySession, MacosPlatformKeyProvider};
#[cfg(unix)]
pub(crate) use shared::create_pbkdf2_key;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) use unsupported::HostKeySession;
#[cfg(target_os = "windows")]
pub(crate) use windows::HostKeySession;

use std::path::Path;

/// Registry-resolved lookup identities, never key material.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ChromiumKeyCredentials {
  pub(crate) linux_crypt_name: Option<String>,
  pub(crate) macos_keychain: Option<MacosKeychainCredentials>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MacosKeychainCredentials {
  pub(crate) service: String,
  pub(crate) account: String,
}

impl ChromiumKeyCredentials {
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
  credentials: &'a ChromiumKeyCredentials,
  local_state: LocalStateInput<'a>,
}

impl<'a> ChromiumKeyRequest<'a> {
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  pub(crate) fn direct(credentials: &'a ChromiumKeyCredentials) -> Self {
    Self {
      browser_id: None,
      credentials,
      local_state: LocalStateInput::NotApplicable,
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  pub(crate) fn for_browser_id(
    browser_id: &'a str,
    credentials: &'a ChromiumKeyCredentials,
  ) -> Self {
    Self {
      browser_id: Some(browser_id),
      credentials,
      local_state: LocalStateInput::NotApplicable,
    }
  }

  pub(crate) fn for_installation(
    browser_id: &'a str,
    credentials: &'a ChromiumKeyCredentials,
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

  #[cfg(target_os = "windows")]
  pub(crate) fn for_parsed_local_state(
    credentials: &'a ChromiumKeyCredentials,
    local_state: &'a serde_json::Value,
  ) -> Self {
    Self {
      browser_id: None,
      credentials,
      local_state: LocalStateInput::Parsed(local_state),
    }
  }

  #[cfg(test)]
  pub(crate) fn browser_id(&self) -> Option<&'a str> {
    self.browser_id
  }

  #[cfg(test)]
  pub(crate) fn credentials(&self) -> &'a ChromiumKeyCredentials {
    self.credentials
  }

  #[cfg(test)]
  pub(crate) fn local_state(&self) -> LocalStateInput<'a> {
    self.local_state
  }
}
