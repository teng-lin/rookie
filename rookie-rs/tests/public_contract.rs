//! Compatibility gates for the public Rust surface and legacy wire formats.
//!
//! Integration tests compile as a downstream crate, so constructing these
//! types here catches source breaks that an in-module unit test would miss.

use once_cell::sync::Lazy;
use rookie_cookies::common::format;
use rookie_cookies::config::{
  get_browser_config, try_get_browser_config, Browser, BrowsersMap, Config, CONFIG,
};
use rookie_cookies::enums::{Cookie, CookieToString, SAME_SITE_UNSPECIFIED};
use rookie_cookies::MozillaProfile;
use rookie_cookies::Result;
use std::collections::HashMap;
use std::path::PathBuf;

type BrowserFn = fn(Option<Vec<String>>) -> Result<Vec<Cookie>>;

const COMMON_BROWSER_SELECTORS: &[(&str, BrowserFn)] = &[
  ("arc", rookie_cookies::arc),
  ("brave", rookie_cookies::brave),
  ("chrome", rookie_cookies::chrome),
  ("chromium", rookie_cookies::chromium),
  ("edge", rookie_cookies::edge),
  ("firefox", rookie_cookies::firefox),
  ("librewolf", rookie_cookies::librewolf),
  ("opera", rookie_cookies::opera),
  ("opera_gx", rookie_cookies::opera_gx),
  ("vivaldi", rookie_cookies::vivaldi),
  ("zen", rookie_cookies::zen),
];

#[cfg(target_os = "linux")]
const PLATFORM_BROWSER_SELECTORS: &[(&str, BrowserFn)] = &[("cachy", rookie_cookies::cachy)];

#[cfg(target_os = "macos")]
const PLATFORM_BROWSER_SELECTORS: &[(&str, BrowserFn)] = &[("safari", rookie_cookies::safari)];

#[cfg(target_os = "windows")]
const PLATFORM_BROWSER_SELECTORS: &[(&str, BrowserFn)] = &[
  ("internet_explorer", rookie_cookies::internet_explorer),
  ("octo_browser", rookie_cookies::octo_browser),
];

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
const PLATFORM_BROWSER_SELECTORS: &[(&str, BrowserFn)] = &[];

fn read_mozilla_profile_fields(profile: &MozillaProfile) -> (&String, &PathBuf, bool) {
  (&profile.name, &profile.path, profile.is_default)
}

fn result_reexport_identity(value: rookie_cookies::anyhow::Result<()>) -> Result<()> {
  value
}

fn cookie() -> Cookie {
  Cookie {
    domain: ".example.test".to_string(),
    path: "/account".to_string(),
    secure: true,
    expires: Some(1_700_000_000),
    name: "session".to_string(),
    value: "abc123".to_string(),
    http_only: true,
    same_site: 1,
  }
}

#[test]
fn public_cookie_and_config_types_remain_constructible() {
  let sample = cookie();
  assert_eq!(sample.domain, ".example.test");
  assert_eq!(SAME_SITE_UNSPECIFIED, -1);
  assert_eq!(vec![cookie()].to_string(), "session=abc123");

  let browser = Browser {
    paths: vec!["/profiles/Default/Cookies".to_string()],
    channels: Some(vec!["stable".to_string()]),
    unix_crypt_name: Some("chrome".to_string()),
    osx_key_service: Some("Chrome Safe Storage".to_string()),
    osx_key_user: Some("Chrome".to_string()),
  };
  let mut browsers: BrowsersMap = HashMap::new();
  browsers.insert("fixture".to_string(), browser);
  let mut platforms = HashMap::new();
  platforms.insert("fixture-os".to_string(), browsers);
  let config = Config {
    version: "fixture".to_string(),
    platforms,
  };

  assert_eq!(
    config.platforms["fixture-os"]["fixture"].paths,
    ["/profiles/Default/Cookies"]
  );

  let embedded: &Lazy<Config> = &CONFIG;
  assert!(!embedded.version.is_empty());
  assert!(!get_browser_config("firefox").paths.is_empty());
  assert!(try_get_browser_config("firefox").is_some());
  assert!(try_get_browser_config("not-a-browser").is_none());
}

#[test]
fn public_function_signatures_remain_compatible() {
  type FirefoxProfileFn = fn(&str, Option<Vec<String>>) -> Result<Vec<Cookie>>;
  type AnyBrowserFn = fn(&str, Option<Vec<String>>, Option<&str>) -> Result<Vec<Cookie>>;

  #[cfg(unix)]
  type ChromiumBasedFn = fn(&Browser, PathBuf, Option<Vec<String>>, bool) -> Result<Vec<Cookie>>;
  #[cfg(target_os = "windows")]
  type InternetExplorerBasedFn = fn(PathBuf, Option<Vec<String>>, bool) -> Result<Vec<Cookie>>;
  #[cfg(target_os = "windows")]
  type ChromiumBasedFn = fn(PathBuf, PathBuf, Option<Vec<String>>, bool) -> Result<Vec<Cookie>>;

  for (_, function) in COMMON_BROWSER_SELECTORS
    .iter()
    .chain(PLATFORM_BROWSER_SELECTORS)
  {
    let _: BrowserFn = *function;
  }
  let _: BrowserFn = rookie_cookies::load;
  let _: fn() -> String = rookie_cookies::version;
  let _: fn(&str) -> &Browser = get_browser_config;
  let _: fn(&str) -> Option<&Browser> = try_get_browser_config;
  let _: fn(rookie_cookies::anyhow::Result<()>) -> Result<()> = result_reexport_identity;

  let _: FirefoxProfileFn = rookie_cookies::firefox_profile;
  let _: fn() -> Result<Vec<MozillaProfile>> = rookie_cookies::firefox_profiles;
  let _: fn(PathBuf, Option<Vec<String>>) -> Result<Vec<Cookie>> = rookie_cookies::firefox_based;
  let _: AnyBrowserFn = rookie_cookies::any_browser;
  let _: fn(&MozillaProfile) -> (&String, &PathBuf, bool) = read_mozilla_profile_fields;
  let _: fn(Vec<rookie_cookies::common::enums::Cookie>) -> String =
    rookie_cookies::common::format::json;
  let _: fn(Vec<rookie_cookies::enums::Cookie>) -> String = format::netscape;

  #[cfg(target_os = "macos")]
  let _: fn(PathBuf, Option<Vec<String>>) -> Result<Vec<Cookie>> = rookie_cookies::safari_based;

  #[cfg(target_os = "windows")]
  let _: InternetExplorerBasedFn = rookie_cookies::internet_explorer_based;

  #[cfg(unix)]
  let _: ChromiumBasedFn = rookie_cookies::chromium_based;

  #[cfg(target_os = "windows")]
  let _: ChromiumBasedFn = rookie_cookies::chromium_based;
}

#[test]
fn core_json_wire_shape_remains_exact() {
  let output = format::json(vec![cookie()]);
  assert_eq!(
    output,
    r#"[
  {
    "domain": ".example.test",
    "path": "/account",
    "secure": true,
    "expires": 1700000000,
    "name": "session",
    "value": "abc123",
    "http_only": true,
    "same_site": 1
  }
]"#
  );
}

#[test]
fn core_netscape_wire_shape_remains_exact() {
  let output = format::netscape(vec![cookie()]);
  assert_eq!(
    output,
    format!(
      "# Netscape HTTP Cookie File\n\
       # Generated by rookie-cookies {}\n\
       # Edit at your own risk.\n\n\
       #HttpOnly_.example.test\tTRUE\t/account\tTRUE\t1700000000\tsession\tabc123\n",
      rookie_cookies::version()
    )
  );
}
