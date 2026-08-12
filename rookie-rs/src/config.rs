use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct Browser {
  pub paths: Vec<String>,
  pub channels: Option<Vec<String>>,
  pub unix_crypt_name: Option<String>,
  pub osx_key_service: Option<String>,
  pub osx_key_user: Option<String>,
}

pub type BrowsersMap = HashMap<String, Browser>;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
  pub version: String,
  pub platforms: HashMap<String, BrowsersMap>,
}

pub static CONFIG: Lazy<Config> = Lazy::new(|| {
  serde_json::from_str(include_str!("../config.json")).expect("embedded config.json is invalid")
});

fn platform_name() -> &'static str {
  if cfg!(windows) {
    "windows"
  } else if cfg!(target_os = "macos") {
    "macos"
  } else {
    "linux"
  }
}

/// Returns the browser configuration for the current platform, if present.
///
/// Unlike [`get_browser_config`], this function is safe for browser names that
/// come from users, bindings, or other dynamic sources: an unknown browser or
/// one that is unavailable on the current platform returns `None`.
pub fn try_get_browser_config(name: &str) -> Option<&Browser> {
  CONFIG.platforms.get(platform_name())?.get(name)
}

pub fn get_browser_config(name: &str) -> &Browser {
  try_get_browser_config(name).unwrap_or_else(|| {
    panic!(
      "browser configuration {name:?} is unavailable for platform {:?}",
      platform_name()
    )
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn fallible_lookup_returns_known_browser() {
    assert!(try_get_browser_config("firefox").is_some());
  }

  #[test]
  fn fallible_lookup_returns_none_for_unknown_browser() {
    assert!(try_get_browser_config("not-a-browser").is_none());
  }

  #[test]
  fn fallible_lookup_returns_none_for_platform_absent_browser() {
    #[cfg(target_os = "linux")]
    let absent = "safari";
    #[cfg(target_os = "macos")]
    let absent = "cachy";
    #[cfg(target_os = "windows")]
    let absent = "safari";
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    let absent = "safari";

    assert!(try_get_browser_config(absent).is_none());
  }

  #[test]
  #[should_panic(expected = "browser configuration \"not-a-browser\" is unavailable for platform")]
  fn legacy_lookup_keeps_panicking_with_browser_context() {
    get_browser_config("not-a-browser");
  }
}
