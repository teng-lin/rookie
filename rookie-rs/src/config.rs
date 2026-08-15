use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Serialize, Deserialize)]
#[deprecated(
  since = "0.6.0",
  note = "legacy direct-path configuration; use direct_path request builders"
)]
pub struct Browser {
  pub paths: Vec<String>,
  pub channels: Option<Vec<String>>,
  pub unix_crypt_name: Option<String>,
  pub osx_key_service: Option<String>,
  pub osx_key_user: Option<String>,
}

pub type BrowsersMap = HashMap<String, Browser>;

#[derive(Debug, Serialize, Deserialize)]
#[deprecated(
  since = "0.6.0",
  note = "legacy direct-path configuration; use direct_path request builders"
)]
pub struct Config {
  pub platforms: HashMap<String, BrowsersMap>,
}

#[derive(Deserialize)]
struct RegistryProjection {
  platforms: HashMap<String, Vec<RegistryBrowser>>,
}

#[derive(Deserialize)]
struct RegistryBrowser {
  canonical_id: String,
  aliases: Vec<String>,
  roots: Vec<RegistryRoot>,
  key_credentials: Option<RegistryCredentials>,
}

#[derive(Deserialize)]
struct RegistryRoot {
  template: String,
  channel: String,
  discovery: String,
}

#[derive(Deserialize)]
struct RegistryCredentials {
  macos_keychain: Option<RegistryKeychain>,
  linux_crypt_name: Option<String>,
}

#[derive(Deserialize)]
struct RegistryKeychain {
  service: String,
  account: String,
}

fn compatibility_template(platform: &str, template: &str) -> String {
  let replacements = match platform {
    "windows" => [
      ("{home}", "%USERPROFILE%"),
      ("{local_app_data}", "%LOCALAPPDATA%"),
      ("{roaming_app_data}", "%APPDATA%"),
      ("{config_home}", "%LOCALAPPDATA%"),
      ("{xdg_config_home}", "%LOCALAPPDATA%"),
    ],
    _ => [
      ("{home}", "~"),
      ("{local_app_data}", "~/.local/share"),
      ("{roaming_app_data}", "~/.config"),
      ("{config_home}", "$CHROME_CONFIG_HOME"),
      ("{xdg_config_home}", "$XDG_CONFIG_HOME"),
    ],
  };
  replacements
    .into_iter()
    .find_map(|(token, replacement)| {
      template
        .strip_prefix(token)
        .map(|suffix| format!("{replacement}{suffix}"))
    })
    .unwrap_or_else(|| template.to_owned())
}

fn compatibility_paths(platform: &str, root: &RegistryRoot) -> Vec<String> {
  let template = compatibility_template(platform, &root.template);
  match root.discovery.as_str() {
    "chromium_user_data" => [
      "Default/Network/Cookies",
      "Default/Cookies",
      "Profile */Network/Cookies",
      "Profile */Cookies",
      "Network/Cookies",
      "Cookies",
    ]
    .map(|suffix| format!("{template}/{suffix}"))
    .into(),
    "safari_default_profile" => vec![
      format!("{template}/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies"),
      format!("{template}/Cookies/Cookies.binarycookies"),
    ],
    "internet_explorer_web_cache" => vec![format!("{template}/WebCacheV01.dat")],
    _ => vec![template],
  }
}

fn dedup_preserving_order(values: &mut Vec<String>) {
  let mut seen = HashSet::new();
  values.retain(|value| seen.insert(value.clone()));
}

fn compatibility_browser(platform: &str, definition: &RegistryBrowser) -> Browser {
  let credentials = definition.key_credentials.as_ref();
  let keychain = credentials.and_then(|credentials| credentials.macos_keychain.as_ref());
  let mut paths = definition
    .roots
    .iter()
    .flat_map(|root| compatibility_paths(platform, root))
    .collect::<Vec<_>>();
  dedup_preserving_order(&mut paths);
  let mut channels = definition
    .roots
    .iter()
    .map(|root| root.channel.clone())
    .collect::<Vec<_>>();
  dedup_preserving_order(&mut channels);
  Browser {
    paths,
    channels: (!channels.is_empty()).then_some(channels),
    unix_crypt_name: credentials.and_then(|credentials| credentials.linux_crypt_name.clone()),
    osx_key_service: keychain.map(|keychain| keychain.service.clone()),
    osx_key_user: keychain.map(|keychain| keychain.account.clone()),
  }
}

/// Frozen public compatibility view generated from the authoritative registry,
/// plus the historical config-only Linux Opera GX sentinel.
///
/// Discovery does not read this value. `Browser`, `Config`, and `CONFIG` remain
/// available for source compatibility, but there is no second path database to
/// update when a browser definition changes.
#[deprecated(
  since = "0.6.0",
  note = "legacy direct-path configuration; use direct_path request builders"
)]
pub static CONFIG: Lazy<Config> = Lazy::new(|| {
  let registry: RegistryProjection = serde_json::from_str(include_str!("../browser_registry.json"))
    .expect("embedded browser_registry.json is invalid");
  let platforms = registry
    .platforms
    .into_iter()
    .map(|(platform, definitions)| {
      let mut browsers = HashMap::new();
      for definition in definitions {
        let browser = compatibility_browser(&platform, &definition);
        // Preserve historical aliases such as `ie` as lookup keys without
        // making them independent discovery definitions.
        for alias in &definition.aliases {
          browsers
            .entry(alias.clone())
            .or_insert_with(|| compatibility_browser(&platform, &definition));
        }
        browsers.insert(definition.canonical_id, browser);
      }
      // Linux Opera GX has never been discoverable or extractable, but the
      // public compatibility map historically exposed an empty entry for it.
      // Keep that config-only sentinel without registering the browser in the
      // authoritative discovery registry or advertising it as supported.
      if platform == "linux" {
        browsers.insert(
          "opera_gx".to_owned(),
          Browser {
            paths: Vec::new(),
            channels: Some(vec![String::new(), String::new()]),
            unix_crypt_name: None,
            osx_key_service: None,
            osx_key_user: None,
          },
        );
      }
      (platform, browsers)
    })
    .collect();
  Config { platforms }
});

fn platform_name() -> Option<&'static str> {
  if cfg!(windows) {
    Some("windows")
  } else if cfg!(target_os = "macos") {
    Some("macos")
  } else if cfg!(target_os = "linux") {
    Some("linux")
  } else {
    None
  }
}

/// Returns the browser configuration for the current platform, if present.
///
/// Unlike [`get_browser_config`], this function is safe for browser names that
/// come from users, bindings, or other dynamic sources: an unknown browser or
/// one that is unavailable on the current platform returns `None`.
#[deprecated(
  since = "0.6.0",
  note = "legacy direct-path configuration; use direct_path request builders"
)]
pub fn try_get_browser_config(name: &str) -> Option<&Browser> {
  CONFIG.platforms.get(platform_name()?)?.get(name)
}

#[deprecated(
  since = "0.6.0",
  note = "legacy direct-path configuration; use direct_path request builders"
)]
pub fn get_browser_config(name: &str) -> &Browser {
  try_get_browser_config(name).unwrap_or_else(|| {
    panic!(
      "browser configuration {name:?} is unavailable for platform {:?}",
      platform_name().unwrap_or(std::env::consts::OS)
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

  #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
  #[test]
  fn unsupported_target_never_borrows_linux_compatibility_config() {
    assert_eq!(platform_name(), None);
    assert!(try_get_browser_config("chrome").is_none());
  }

  #[test]
  fn linux_projection_retains_config_only_opera_gx() {
    let opera_gx = CONFIG
      .platforms
      .get("linux")
      .and_then(|browsers| browsers.get("opera_gx"))
      .expect("Linux compatibility map keeps Opera GX");
    assert!(opera_gx.paths.is_empty());
    assert_eq!(
      opera_gx.channels.as_deref(),
      Some([String::new(), String::new()].as_slice())
    );
    assert!(opera_gx.unix_crypt_name.is_none());
    assert!(opera_gx.osx_key_service.is_none());
    assert!(opera_gx.osx_key_user.is_none());

    let registry: RegistryProjection =
      serde_json::from_str(include_str!("../browser_registry.json")).expect("valid registry");
    assert!(registry
      .platforms
      .get("linux")
      .expect("Linux registry")
      .iter()
      .all(|browser| browser.canonical_id != "opera_gx"));

    #[cfg(target_os = "linux")]
    assert!(std::ptr::eq(
      try_get_browser_config("opera_gx").expect("Linux lookup succeeds"),
      opera_gx
    ));
  }

  #[test]
  #[should_panic(expected = "browser configuration \"not-a-browser\" is unavailable for platform")]
  fn legacy_lookup_keeps_panicking_with_browser_context() {
    get_browser_config("not-a-browser");
  }

  #[test]
  fn compatibility_projection_deduplicates_non_adjacent_values_in_order() {
    let mut values = vec!["stable".to_owned(), "beta".to_owned(), "stable".to_owned()];
    dedup_preserving_order(&mut values);
    assert_eq!(values, ["stable", "beta"]);

    let registry: RegistryProjection =
      serde_json::from_str(include_str!("../browser_registry.json")).expect("valid registry");
    let chrome = registry.platforms["linux"]
      .iter()
      .find(|browser| browser.canonical_id == "chrome")
      .expect("Linux Chrome definition");
    let browser = compatibility_browser("linux", chrome);
    assert_eq!(
      browser.channels.expect("Chrome channels"),
      ["stable", "beta", "dev"]
    );
  }
}
