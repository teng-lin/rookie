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

  for (browser_name, browser_fn) in browser_types.iter() {
    match browser_fn(domains.clone()) {
      Ok(browser_cookies) => cookies.extend(browser_cookies),
      Err(err) => log::warn!("rookie_cookies::load skipping {browser_name}: {err}"),
    }
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
  use std::path::PathBuf;
  use std::sync::atomic::{AtomicU64, Ordering};
  use std::sync::Mutex;

  static ENV_MUTEX: Mutex<()> = Mutex::new(());

  fn seed_test_cookies(db_path: &std::path::Path, cookie_name: &str, cookie_value: &str) {
    let conn = rusqlite::Connection::open(db_path).expect("open sqlite db");
    conn
      .execute(
        "CREATE TABLE cookies (
          host_key TEXT NOT NULL,
          path TEXT NOT NULL,
          is_secure INTEGER NOT NULL,
          expires_utc INTEGER NOT NULL,
          name TEXT NOT NULL,
          value TEXT NOT NULL,
          encrypted_value BLOB,
          is_httponly INTEGER NOT NULL,
          samesite INTEGER NOT NULL
        )",
        [],
      )
      .expect("create table cookies");
    conn
      .execute(
        "INSERT INTO cookies (host_key, path, is_secure, expires_utc, name, value, encrypted_value, is_httponly, samesite)
         VALUES ('.example.com', '/', 0, 0, ?1, ?2, ?3, 0, 0)",
        rusqlite::params![cookie_name, cookie_value, &b"x"[..]],
      )
      .expect("insert row");
  }

  #[cfg(unix)]
  #[test]
  fn test_chrome_resolves_network_cookies_on_unix() {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let home_dir =
      std::env::temp_dir().join(format!("rookie-chrome-home-{}-{}", std::process::id(), n));

    #[cfg(target_os = "macos")]
    let chrome_dir = home_dir.join("Library/Application Support/Google/Chrome");

    #[cfg(not(target_os = "macos"))]
    let chrome_dir = home_dir.join(".config/google-chrome");

    let network_dir = chrome_dir.join("Default/Network");
    let default_dir = chrome_dir.join("Default");

    std::fs::create_dir_all(&network_dir).expect("create network dir");
    std::fs::create_dir_all(&default_dir).expect("create default dir");

    let local_state = chrome_dir.join("Local State");
    std::fs::write(&local_state, b"{}").expect("create local state");

    let network_db = network_dir.join("Cookies");
    let legacy_db = default_dir.join("Cookies");

    seed_test_cookies(&network_db, "net_cookie", "net_val");
    seed_test_cookies(&legacy_db, "legacy_cookie", "legacy_val");

    let _guard = ENV_MUTEX.lock().unwrap();
    let old_home = std::env::var_os("HOME");

    std::env::set_var("HOME", &home_dir);

    let result = chrome(None);

    if let Some(old) = old_home {
      std::env::set_var("HOME", old);
    } else {
      std::env::remove_var("HOME");
    }

    let cookies = result.expect("chrome() should find and parse network cookies");
    assert_eq!(
      cookies.len(),
      1,
      "expected 1 cookie from Network/Cookies, got {:?}",
      cookies
    );
    assert_eq!(cookies[0].name, "net_cookie");
    assert_eq!(cookies[0].value, "net_val");

    let _ = std::fs::remove_dir_all(&home_dir);
  }
}
