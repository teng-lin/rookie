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
pub use browser::{
  chromium::chromium_based,
  mozilla::{firefox_based, MozillaProfile},
};

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

/// Returns every Firefox profile that holds a cookie database.
///
/// [`firefox`] only reads the default profile; this lists the secondary ones
/// too, so a caller can pick one and pass it to [`firefox_profile`].
///
/// # Examples
///
/// ```no_run
/// for profile in rookie_cookies::firefox_profiles()? {
///   println!("{} {} default={}", profile.name, profile.path.display(), profile.is_default);
/// }
/// # Ok::<(), rookie_cookies::anyhow::Error>(())
/// ```
pub fn firefox_profiles() -> Result<Vec<MozillaProfile>> {
  let config = get_browser_config("firefox");
  paths::find_mozilla_based_profiles(config)
}

/// Returns cookies from a specific Firefox profile.
///
/// # Arguments
///
/// * `profile` - The profile's name, directory name, or full path, as reported
///   by [`firefox_profiles`]
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::firefox_profile("default-release", Some(domains));
/// ```
pub fn firefox_profile(profile: &str, domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let profiles = firefox_profiles()?;
  let selected = browser::mozilla::select_profile(&profiles, profile)?;
  firefox_based(selected.path.join("cookies.sqlite"), domains)
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
    chromium_based(key, db_path, domains, false)
  }
  #[cfg(unix)]
  {
    let (_, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(config, db_path, domains, false)
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
    chromium_based(key, db_path, domains, false)
  }
  #[cfg(unix)]
  {
    let (_, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(config, db_path, domains, false)
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
    chromium_based(key, db_path, domains, false)
  }
  #[cfg(unix)]
  {
    let (_, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(config, db_path, domains, false)
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
    chromium_based(key, db_path, domains, false)
  }
  #[cfg(unix)]
  {
    let (_, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(config, db_path, domains, false)
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
    chromium_based(key, db_path, domains, false)
  }
  #[cfg(unix)]
  {
    let (_, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(config, db_path, domains, false)
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
    chromium_based(key, db_path, domains, false)
  }
  #[cfg(unix)]
  {
    let (_, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(config, db_path, domains, false)
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
    chromium_based(key, db_path, domains, false)
  }
  #[cfg(unix)]
  {
    let (_, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(config, db_path, domains, false)
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
    chromium_based(key, db_path, domains, false)
  }
  #[cfg(unix)]
  {
    let (_, db_path) = paths::find_chrome_based_paths(config)?;
    chromium_based(config, db_path, domains, false)
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
  chromium_based(key, db_path, domains, false)
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
  internet_explorer_based(db_path, domains, false)
}

fn load_from_browsers<F>(
  browser_types: &[(&'static str, F)],
  domains: Option<Vec<String>>,
) -> Result<Vec<Cookie>>
where
  F: Fn(Option<Vec<String>>) -> Result<Vec<Cookie>>,
{
  let mut cookies = Vec::new();
  let mut errors: Vec<String> = Vec::new();

  for (browser_name, browser_fn) in browser_types.iter() {
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
  if !browser_types.is_empty() && errors.len() == browser_types.len() {
    bail!("all browser extractions failed:\n  {}", errors.join("\n  "));
  }

  Ok(cookies)
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

  load_from_browsers(&browser_types, domains)
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
      match chromium_based(browser_config, cookies_path.into(), domains.clone(), false) {
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
        false,
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
    match internet_explorer_based(cookies_path.into(), domains.clone(), false) {
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

  type BrowserEntry = (&'static str, fn(Option<Vec<String>>) -> Result<Vec<Cookie>>);

  fn always_err(_domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
    Err(anyhow::anyhow!("not installed"))
  }

  fn always_ok(_domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
    Ok(vec![])
  }

  #[test]
  fn all_fail_returns_aggregate_error() {
    let browsers: Vec<BrowserEntry> = vec![("firefox", always_err), ("chrome", always_err)];
    let result = load_from_browsers(&browsers, None);
    assert!(result.is_err(), "expected Err when all browsers fail");
    let msg = result.unwrap_err().to_string();
    assert!(
      msg.contains("all browser extractions failed"),
      "error should mention aggregate failure, got: {msg}"
    );
    assert!(
      msg.contains("firefox: not installed"),
      "error should list firefox error, got: {msg}"
    );
    assert!(
      msg.contains("chrome: not installed"),
      "error should list chrome error, got: {msg}"
    );
  }

  #[test]
  fn partial_failure_returns_ok() {
    let browsers: Vec<BrowserEntry> = vec![("firefox", always_err), ("chrome", always_ok)];
    let result = load_from_browsers(&browsers, None);
    assert!(
      result.is_ok(),
      "expected Ok when at least one browser succeeds, got: {result:?}"
    );
  }

  #[test]
  fn empty_browser_list_returns_ok_empty() {
    let browsers: Vec<BrowserEntry> = vec![];
    let result = load_from_browsers(&browsers, None);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
  }

  use std::sync::atomic::{AtomicU64, Ordering};
  use std::sync::{Mutex, MutexGuard};

  static ENV_MUTEX: Mutex<()> = Mutex::new(());

  /// RAII guard that restores `HOME` to its prior value when dropped.
  ///
  /// Holds the `ENV_MUTEX` lock for its entire lifetime so that parallel
  /// tests never observe an intermediate value for `HOME`. The temp
  /// directory is also removed in `Drop`, guaranteeing cleanup even when
  /// the test panics before reaching the end of the function.
  struct HomeGuard<'a> {
    old_home: Option<std::ffi::OsString>,
    home_dir: std::path::PathBuf,
    _lock: MutexGuard<'a, ()>,
  }

  impl<'a> HomeGuard<'a> {
    /// Create a new guard: acquires `lock`, sets `HOME` to `home_dir`,
    /// and arranges to restore the old value on drop.
    fn new(lock: MutexGuard<'a, ()>, home_dir: std::path::PathBuf) -> Self {
      let old_home = std::env::var_os("HOME");
      // SAFETY: we hold ENV_MUTEX so no other test thread concurrently
      // reads or writes HOME.
      #[allow(deprecated)]
      unsafe {
        std::env::set_var("HOME", &home_dir);
      }
      HomeGuard {
        old_home,
        home_dir,
        _lock: lock,
      }
    }
  }

  impl Drop for HomeGuard<'_> {
    fn drop(&mut self) {
      // Restore HOME before releasing the mutex lock.
      #[allow(deprecated)]
      unsafe {
        match &self.old_home {
          Some(old) => std::env::set_var("HOME", old),
          None => std::env::remove_var("HOME"),
        }
      }
      // Best-effort removal of the temporary home directory.
      let _ = std::fs::remove_dir_all(&self.home_dir);
    }
  }

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

    // HomeGuard acquires ENV_MUTEX, sets HOME to `home_dir`, and restores
    // the previous value (plus removes the temp dir) in its Drop impl
    // — even if chrome() panics.
    let _guard = HomeGuard::new(ENV_MUTEX.lock().unwrap(), home_dir);

    let cookies = chrome(None).expect("chrome() should find and parse network cookies");
    assert_eq!(
      cookies.len(),
      1,
      "expected 1 cookie from Network/Cookies, got {:?}",
      cookies
    );
    assert_eq!(cookies[0].name, "net_cookie");
    assert_eq!(cookies[0].value, "net_val");
  }
}
