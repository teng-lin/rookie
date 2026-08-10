// Public

// Common
pub mod common;
pub mod config;
mod utils;
pub use common::enums;

// Browser
#[cfg(target_os = "windows")]
pub use browser::internet_explorer::internet_explorer_based;
#[cfg(target_os = "macos")]
pub use browser::safari::safari_based;
pub use browser::{chromium::chromium_based, mozilla::firefox_based};

// Private
mod browser;
use anyhow::bail;
pub use anyhow::{self, Result};
use common::paths;
use config::get_browser_config;
use enums::Cookie;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

/// Returns the rookie-cookies version.
/// Format: <semver>(<commit>)
///
/// # Examples
///
/// ```
/// let version = rookie_cookies::version();
/// println!("{}", version);
/// ```
pub fn version() -> String {
  format!("{} ({})", env!("CARGO_PKG_VERSION"), env!("COMMIT_HASH"))
}

/// Returns cookies from Firefox
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::firefox(Some(domains));
/// ```
pub fn firefox(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let config = get_browser_config("firefox");
  let db_path = paths::find_mozilla_based_paths(config)?;
  firefox_based(db_path, domains)
}

/// Returns cookies from LibreWolf
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::librewolf(Some(domains));
/// ```
pub fn librewolf(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let config = get_browser_config("librewolf");
  let db_path = paths::find_mozilla_based_paths(config)?;
  firefox_based(db_path, domains)
}

/// Returns cookies from Cachy Browser (Linux only)
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::cachy(Some(domains));
/// ```
#[cfg(target_os = "linux")]
pub fn cachy(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let config = get_browser_config("cachy");
  let db_path = paths::find_mozilla_based_paths(config)?;
  firefox_based(db_path, domains)
}

/// Returns cookies from Chrome
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::chrome(Some(domains));
/// ```
pub fn chrome(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let config = get_browser_config("chrome");
  #[cfg(target_os = "windows")]
  {
    let (key, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(key, db_path, domains)
  }
  #[cfg(unix)]
  {
    let (_, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(config, db_path, domains)
  }
}

/// Returns cookies from Chromium
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::chromium(Some(domains));
/// ```
pub fn chromium(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let config = get_browser_config("chromium");
  #[cfg(target_os = "windows")]
  {
    let (key, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(key, db_path, domains)
  }
  #[cfg(unix)]
  {
    let (_, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(config, db_path, domains)
  }
}

/// Returns cookies from Brave
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::brave(Some(domains));
/// ```
pub fn brave(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let config = get_browser_config("brave");
  #[cfg(target_os = "windows")]
  {
    let (key, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(key, db_path, domains)
  }
  #[cfg(unix)]
  {
    let (_, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(config, db_path, domains)
  }
}

/// Returns cookies from Arc
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::arc(Some(domains));
/// ```
pub fn arc(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let config = get_browser_config("arc");
  #[cfg(target_os = "windows")]
  {
    let (key, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(key, db_path, domains)
  }
  #[cfg(unix)]
  {
    let (_, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(config, db_path, domains)
  }
}

/// Returns cookies from Firefox
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::zen(Some(domains));
/// ```
pub fn zen(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let config = get_browser_config("zen");
  let db_path = paths::find_mozilla_based_paths(config)?;
  firefox_based(db_path, domains)
}

/// Returns cookies from Edge
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::edge(Some(domains));
/// ```
pub fn edge(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let config = get_browser_config("edge");
  #[cfg(target_os = "windows")]
  {
    let (key, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(key, db_path, domains)
  }
  #[cfg(unix)]
  {
    let (_, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(config, db_path, domains)
  }
}

/// Returns cookies from Vivaldi
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::vivaldi(Some(domains));
/// ```
pub fn vivaldi(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let config = get_browser_config("vivaldi");
  #[cfg(target_os = "windows")]
  {
    let (key, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(key, db_path, domains)
  }
  #[cfg(unix)]
  {
    let (_, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(config, db_path, domains)
  }
}

/// Returns cookies from Opera
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::opera(Some(domains));
/// ```
pub fn opera(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let config = get_browser_config("opera");
  #[cfg(target_os = "windows")]
  {
    let (key, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(key, db_path, domains)
  }
  #[cfg(unix)]
  {
    let (_, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(config, db_path, domains)
  }
}

/// Returns cookies from Opera GX
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::opera_gx(Some(domains));
/// ```
pub fn opera_gx(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let config = get_browser_config("opera_gx");
  #[cfg(target_os = "windows")]
  {
    let (key, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(key, db_path, domains)
  }
  #[cfg(unix)]
  {
    let (_, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(config, db_path, domains)
  }
}

/// Returns cookies from Octo Browser
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::octo_browser(Some(domains));
/// ```
#[cfg(target_os = "windows")]
pub fn octo_browser(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let config = get_browser_config("octo_browser");
  let (key, db_path) = paths::find_chrome_based_paths(config)?;
  chromium_based(key, db_path, domains)
}

/// Returns cookies from Safari (macOS only)
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::safari(Some(domains));
/// ```
#[cfg(target_os = "macos")]
pub fn safari(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let config = get_browser_config("safari");
  let db_path = paths::find_safari_based_paths(config)?;
  safari_based(db_path, domains)
}

/// Returns cookies from Internet Explorer (Windows only)
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::internet_explorer(Some(domains));
/// ```
#[cfg(target_os = "windows")]
pub fn internet_explorer(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let config = get_browser_config("ie");
  let db_path = paths::find_ie_based_paths(config)?;
  internet_explorer_based(db_path, domains)
}

/// Returns cookies from all browsers
///
/// This is a best-effort aggregator: each browser is probed in turn and
/// individual failures are surfaced via [`log::warn!`] but do not abort
/// the load (a browser not being installed, a locked profile, or a
/// decrypt failure on one browser should not lose cookies from the
/// others). If you need to know which browsers failed, hook a logger
/// like [`tracing-subscriber`] and watch for `rookie_cookies::load` warnings.
///
/// Returns `Err` only when **every** attempted browser extraction fails,
/// containing an aggregate message listing each browser and its error.
/// This lets callers distinguish between "no cookies found" and "all
/// extractions failed".
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::load(Some(domains));
/// ```
pub fn load(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  type LoadFn = fn(Option<Vec<String>>) -> Result<Vec<Cookie>>;
  let mut cookies = Vec::new();
  let mut errors: Vec<String> = Vec::new();

  let mut browser_types: Vec<(&'static str, LoadFn)> = vec![
    ("firefox", firefox),
    ("zen", zen),
    ("librewolf", librewolf),
    ("opera", opera),
    ("edge", edge),
    ("chromium", chromium),
    ("brave", brave),
    ("vivaldi", vivaldi),
    ("arc", arc),
  ];

  #[cfg(target_os = "windows")]
  {
    browser_types.push(("chrome", chrome));
    browser_types.push(("internet_explorer", internet_explorer));
    browser_types.push(("opera_gx", opera_gx));
  }
  #[cfg(target_os = "linux")]
  {
    browser_types.push(("chrome", chrome));
    browser_types.push(("cachy", cachy));
  }
  #[cfg(target_os = "macos")]
  {
    browser_types.push(("chrome", chrome));
    browser_types.push(("opera_gx", opera_gx));
    browser_types.push(("safari", safari));
  }

  let mut total_browsers = 0;
  for (browser_name, browser_fn) in browser_types.iter() {
    total_browsers += 1;
    match browser_fn(domains.clone()) {
      Ok(browser_cookies) => cookies.extend(browser_cookies),
      Err(err) => {
        log::warn!("rookie_cookies::load skipping {browser_name}: {err}");
        errors.push(format!("{browser_name}: {err}"));
      }
    }
  }

  // If every attempted browser extraction failed, surface an aggregate error so that
  // callers can distinguish total failure from legitimately finding no cookies.
  if total_browsers > 0 && errors.len() == total_browsers {
    bail!(
      "all browser extractions failed:\n  {}",
      errors.join("\n  ")
    );
  }

  Ok(cookies)
}

/// Returns cookies from specific browser
/// Useful for CLI apps
///
/// # Arguments
///
/// * `cookies_path` - Absolute path for cookies file
/// * `domains` - Optional list that for getting specific domains only
/// * `key_path` - Optional absolute path for key required to decrypt the cookies (required for chrome)
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies_path = "C:\\Users\\User\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\default\\network\\Cookies";
/// let key_path = "C:\\Users\\User\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Local State";
/// let cookies = rookie_cookies::any_browser(cookies_path, None, Some(key_path)).unwrap();
/// ```
#[allow(unused_variables)]
pub fn any_browser(
  cookies_path: &str,
  domains: Option<Vec<String>>,
  key_path: Option<&str>,
) -> Result<Vec<Cookie>> {
  // Each parser is probed in turn; the first to succeed wins. Failed
  // probes are logged at warn level so users can see which decoders
  // were tried and why they rejected the file.
  // chromium based
  #[cfg(unix)]
  {
    let chrome_configs = &[
      ("chrome", get_browser_config("chrome")),
      ("brave", get_browser_config("brave")),
      ("chromium", get_browser_config("chromium")),
      ("edge", get_browser_config("edge")),
      ("opera", get_browser_config("opera")),
      ("opera_gx", get_browser_config("opera_gx")),
      ("vivaldi", get_browser_config("vivaldi")),
    ];
    for (name, browser_config) in chrome_configs {
      match chromium_based(browser_config, cookies_path.into(), domains.clone()) {
        Ok(cookies) => return Ok(cookies),
        Err(err) => {
          log::warn!("any_browser: {name} (chromium) did not decode {cookies_path}: {err}")
        }
      }
    }
  }
  #[cfg(target_os = "windows")]
  {
    if let Some(key_path) = key_path {
      match chromium_based(
        PathBuf::from(key_path),
        cookies_path.into(),
        domains.clone(),
      ) {
        Ok(cookies) => return Ok(cookies),
        Err(err) => {
          log::warn!("any_browser: chromium (windows) did not decode {cookies_path}: {err}")
        }
      }
    }
  }
  // Windows chromium

  // Firefox
  match firefox_based(cookies_path.into(), domains.clone()) {
    Ok(cookies) => return Ok(cookies),
    Err(err) => log::warn!("any_browser: firefox did not decode {cookies_path}: {err}"),
  }

  #[cfg(target_os = "windows")]
  {
    // Internet Explorer
    match internet_explorer_based(cookies_path.into(), domains.clone()) {
      Ok(cookies) => return Ok(cookies),
      Err(err) => log::warn!("any_browser: internet_explorer did not decode {cookies_path}: {err}"),
    }
  }
  #[cfg(target_os = "macos")]
  {
    match safari_based(cookies_path.into(), domains) {
      Ok(cookies) => return Ok(cookies),
      Err(err) => log::warn!("any_browser: safari did not decode {cookies_path}: {err}"),
    }
  }
  bail!(
    "\nNo cookies found.\n\
    If you're using a Chromium-based browser, please specify the key file \
    and run this program with administrator privileges."
  );
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Mirrors the aggregate-error logic inside `load()` so we can exercise it
  /// without needing real browser installations.
  fn load_inner(browser_types: Vec<(&'static str, fn(Option<Vec<String>>) -> Result<Vec<Cookie>>)>, domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
    let mut cookies = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let total_browsers = browser_types.len();
    for (browser_name, browser_fn) in browser_types.iter() {
      match browser_fn(domains.clone()) {
        Ok(browser_cookies) => cookies.extend(browser_cookies),
        Err(err) => errors.push(format!("{browser_name}: {err}")),
      }
    }
    if total_browsers > 0 && errors.len() == total_browsers {
      bail!("all browser extractions failed:\n  {}", errors.join("\n  "));
    }
    Ok(cookies)
  }

  fn always_err(_domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
    Err(anyhow::anyhow!("not installed"))
  }

  fn always_ok(_domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
    Ok(vec![])
  }

  #[test]
  fn all_fail_returns_aggregate_error() {
    let browsers: Vec<(&'static str, fn(Option<Vec<String>>) -> Result<Vec<Cookie>>)> = vec![
      ("firefox", always_err),
      ("chrome", always_err),
    ];
    let result = load_inner(browsers, None);
    assert!(result.is_err(), "expected Err when all browsers fail");
    let msg = result.unwrap_err().to_string();
    assert!(
      msg.contains("all browser extractions failed"),
      "error should mention aggregate failure, got: {msg}"
    );
    assert!(msg.contains("firefox"), "error should list firefox, got: {msg}");
    assert!(msg.contains("chrome"), "error should list chrome, got: {msg}");
  }

  #[test]
  fn partial_failure_returns_ok() {
    let browsers: Vec<(&'static str, fn(Option<Vec<String>>) -> Result<Vec<Cookie>>)> = vec![
      ("firefox", always_err),
      ("chrome", always_ok),
    ];
    let result = load_inner(browsers, None);
    assert!(
      result.is_ok(),
      "expected Ok when at least one browser succeeds, got: {result:?}"
    );
  }

  #[test]
  fn empty_browser_list_returns_ok_empty() {
    let browsers: Vec<(&'static str, fn(Option<Vec<String>>) -> Result<Vec<Cookie>>)> = vec![];
    let result = load_inner(browsers, None);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
  }
}
