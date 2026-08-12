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
pub use anyhow::{self, Result};
use anyhow::{bail, Context};
use common::paths;
use config::Browser;
use enums::Cookie;
#[cfg(target_os = "linux")]
mod linux;
use std::{io::Read, path::PathBuf};
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

/// Converts the fallible configuration lookup into the crate's established
/// error channel. Public extraction functions are called from the Python and
/// Node bindings, so a missing configuration must not unwind across FFI.
fn browser_config(name: &str) -> Result<&config::Browser> {
  config::try_get_browser_config(name).ok_or_else(|| {
    anyhow::anyhow!("browser configuration {name:?} is unavailable for this platform")
  })
}

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
  let config = browser_config("firefox")?;
  let db_path = paths::find_mozilla_based_paths(config)?;
  firefox_based(db_path, domains)
}

/// Returns every Firefox profile that holds a cookie database.
///
/// [`firefox`] returns whichever profile it finds first, preferring the default
/// one; this lists them all so a caller can choose deliberately and pass the
/// choice to [`firefox_profile`].
///
/// Defaults are per-installation, so more than one profile can report
/// `is_default` when several Firefox installations are present.
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
  let config = browser_config("firefox")?;
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
  let config = browser_config("librewolf")?;
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
  let config = browser_config("cachy")?;
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
  let config = browser_config("chrome")?;
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
  let config = browser_config("chromium")?;
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
  let config = browser_config("brave")?;
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
  let config = browser_config("arc")?;
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
  let config = browser_config("zen")?;
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
  let config = browser_config("edge")?;
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
  let config = browser_config("vivaldi")?;
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
  let config = browser_config("opera")?;
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
  let config = browser_config("opera_gx")?;
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
  let config = browser_config("octo_browser")?;
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
  let config = browser_config("safari")?;
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
  let config = browser_config("ie")?;
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
  let mut successful_extractions = 0;

  for (browser_name, browser_fn) in browser_types.iter() {
    match browser_fn(domains.clone()) {
      Ok(browser_cookies) => {
        successful_extractions += 1;
        cookies.extend(browser_cookies);
      }
      Err(err) if paths::is_browser_not_installed(&err) => {
        log::debug!("rookie_cookies::load skipping uninstalled {browser_name}: {err}");
      }
      Err(err) => {
        log::warn!("rookie_cookies::load skipping {browser_name}: {err}");
        errors.push(format!("{browser_name}: {err}"));
      }
    }
  }

  // Missing profiles were not extraction attempts. If at least one installed
  // browser failed and none succeeded, surface the real failures; a machine
  // with no supported browser installed legitimately has no cookies.
  if successful_extractions == 0 && !errors.is_empty() {
    bail!("all browser extractions failed:\n  {}", errors.join("\n  "));
  }

  Ok(cookies)
}

type LoadFn = fn(Option<Vec<String>>) -> Result<Vec<Cookie>>;

/// The legacy `load` probe order is observable through cookie ordering and
/// warning output. Keep construction separate from extraction so platform CI
/// can pin the exact browser set without probing browsers installed on a host.
fn legacy_load_browsers() -> Vec<(&'static str, LoadFn)> {
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

  browser_types
}

/// Returns cookies from all browsers
///
/// This is a best-effort aggregator: each browser is probed in turn and
/// individual extraction failures are surfaced via [`log::warn!`] but do not
/// abort the load (a locked profile or a decrypt failure on one browser should
/// not lose cookies from the others). Browsers without a discoverable profile
/// are skipped normally. If you need to know which browsers failed, hook a logger
/// like [`tracing-subscriber`] and watch for `rookie_cookies::load` warnings.
///
/// Returns `Err` only when at least one installed browser is found, every
/// attempted extraction fails, and none succeeds. The aggregate message lists
/// only genuine extraction failures. If no supported browser is installed,
/// returns an empty list.
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
  let browser_types = legacy_load_browsers();
  load_from_browsers(&browser_types, domains)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnyBrowserSource {
  ChromiumSqlite,
  MozillaSqlite,
  SafariBinaryCookies,
  #[cfg(target_os = "windows")]
  InternetExplorerEse,
}

/// Classifies an SQLite cookie database from its schema before any browser
/// decoder (and, importantly, before any platform key provider) is invoked.
fn sniff_sqlite_cookie_source(path: PathBuf) -> Result<AnyBrowserSource> {
  let source = common::sqlite::with_browser_database(path, |connection| {
    let table_exists = |name: &str| -> rusqlite::Result<bool> {
      connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
        [name],
        |row| row.get(0),
      )
    };
    Ok((table_exists("cookies")?, table_exists("moz_cookies")?))
  })?
  .into_value();

  match source {
    (true, false) => Ok(AnyBrowserSource::ChromiumSqlite),
    (false, true) => Ok(AnyBrowserSource::MozillaSqlite),
    (true, true) => {
      bail!("ambiguous SQLite cookie database: both `cookies` and `moz_cookies` tables are present")
    }
    (false, false) => bail!(
      "unsupported SQLite database: expected a Chromium `cookies` or Mozilla `moz_cookies` table"
    ),
  }
}

#[cfg(not(target_os = "windows"))]
fn validate_cookie_source_file(path: &std::path::Path) -> Result<()> {
  let metadata = std::fs::metadata(path)
    .with_context(|| format!("can't inspect cookie source {}", path.display()))?;
  if !metadata.is_file() {
    bail!("cookie source is not a file: {}", path.display());
  }
  Ok(())
}

fn read_cookie_source_header(path: &std::path::Path) -> Result<Vec<u8>> {
  let file = std::fs::File::open(path)
    .with_context(|| format!("can't open cookie source {}", path.display()))?;
  let mut header = Vec::with_capacity(16);
  file
    .take(16)
    .read_to_end(&mut header)
    .with_context(|| format!("can't read cookie source header {}", path.display()))?;
  Ok(header)
}

/// Inspects the source's on-disk signature before choosing a decoder family.
#[cfg(not(target_os = "windows"))]
fn sniff_cookie_source(path: &std::path::Path) -> Result<AnyBrowserSource> {
  validate_cookie_source_file(path)?;
  let header = read_cookie_source_header(path)?;

  if header.starts_with(b"SQLite format 3\0") {
    return sniff_sqlite_cookie_source(path.to_path_buf());
  }
  if header.starts_with(b"cook") {
    return Ok(AnyBrowserSource::SafariBinaryCookies);
  }

  bail!("unsupported cookie source format: {}", path.display())
}

/// Applies a Windows SQLite acquisition policy before attempting direct magic
/// inspection. A successful recovered schema is authoritative, so a locked
/// live database never has to be reopened merely to read its header.
#[cfg(any(target_os = "windows", test))]
fn sniff_cookie_source_with_windows_recovery<Recover>(
  path: &std::path::Path,
  mut recover_sqlite_source: Recover,
) -> Result<AnyBrowserSource>
where
  Recover: FnMut(&std::path::Path) -> Result<AnyBrowserSource>,
{
  let sqlite_error = match recover_sqlite_source(path) {
    Ok(source) => return Ok(source),
    Err(error) => error,
  };

  let header = match read_cookie_source_header(path) {
    Ok(header) => header,
    Err(header_error) => {
      return Err(sqlite_error.context(format!(
        "cookie source signature fallback also failed: {header_error:#}"
      )))
    }
  };
  if header.starts_with(b"SQLite format 3\0") {
    return Err(sqlite_error);
  }
  if header.starts_with(b"cook") {
    return Ok(AnyBrowserSource::SafariBinaryCookies);
  }
  #[cfg(target_os = "windows")]
  if header.get(4..8) == Some(&[0xef, 0xcd, 0xab, 0x89]) {
    return Ok(AnyBrowserSource::InternetExplorerEse);
  }

  bail!("unsupported cookie source format: {}", path.display())
}

#[cfg(target_os = "windows")]
fn sniff_cookie_source(path: &std::path::Path) -> Result<AnyBrowserSource> {
  sniff_cookie_source_with_windows_recovery(path, |live_path| {
    browser::chromium::with_windows_locked_database_recovery(live_path, |source_path| {
      sniff_sqlite_cookie_source(source_path.to_path_buf())
    })
  })
}

#[cfg(unix)]
fn any_browser_chromium_configs() -> Result<Vec<(&'static str, &'static Browser)>> {
  let configs = vec![
    ("chrome", browser_config("chrome")?),
    ("brave", browser_config("brave")?),
    ("chromium", browser_config("chromium")?),
    ("edge", browser_config("edge")?),
    ("opera", browser_config("opera")?),
    ("vivaldi", browser_config("vivaldi")?),
    ("arc", browser_config("arc")?),
  ];
  #[cfg(target_os = "macos")]
  let configs = configs
    .into_iter()
    .chain(std::iter::once(("opera_gx", browser_config("opera_gx")?)))
    .collect();
  Ok(configs)
}

/// Tries every applicable Chromium identity and selects the most complete
/// result. A fallback-key cookie under the wrong identity is therefore not an
/// early-success signal; a later identity that emits more rows, or skips fewer
/// rows for an equal-size result, wins.
#[cfg(unix)]
fn best_chromium_probe<Probe>(
  configs: &[(&'static str, &'static Browser)],
  mut probe: Probe,
) -> Result<Vec<Cookie>>
where
  Probe: FnMut(&'static str, &'static Browser) -> Result<browser::chromium::ChromiumProbeResult>,
{
  let mut best: Option<(&'static str, browser::chromium::ChromiumProbeResult)> = None;
  let mut failures = Vec::new();

  for &(name, config) in configs {
    match probe(name, config) {
      Ok(candidate) => {
        let is_better = best.as_ref().is_none_or(|(_, current)| {
          candidate.cookies.len() > current.cookies.len()
            || (candidate.cookies.len() == current.cookies.len()
              && candidate.rows_skipped < current.rows_skipped)
        });
        if is_better {
          best = Some((name, candidate));
        }
      }
      Err(error) => {
        log::warn!("any_browser: {name} (chromium) did not decode: {error}");
        failures.push(format!("{name}: {error}"));
      }
    }
  }

  match best {
    Some((name, result)) => {
      log::debug!(
        "any_browser selected Chromium identity {name} (cookies={}, rows_skipped={})",
        result.cookies.len(),
        result.rows_skipped
      );
      Ok(result.cookies)
    }
    None => bail!(
      "no Chromium configuration decoded the cookie database:\n  {}",
      failures.join("\n  ")
    ),
  }
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
  let cookies_path = PathBuf::from(cookies_path);
  match sniff_cookie_source(&cookies_path)? {
    AnyBrowserSource::MozillaSqlite => firefox_based(cookies_path, domains),
    AnyBrowserSource::ChromiumSqlite => {
      #[cfg(target_os = "windows")]
      {
        let key_path = key_path.context(
          "a Chromium Local State key file is required for a Chromium cookie database on Windows",
        )?;
        chromium_based(PathBuf::from(key_path), cookies_path, domains, false)
      }
      #[cfg(target_os = "linux")]
      {
        let configs = any_browser_chromium_configs()?;
        let mut key_cache = browser::chromium_platform_keys::LinuxKeyOutcomeCache::new();
        best_chromium_probe(&configs, |_name, config| {
          let outcomes = key_cache.outcomes_for(config);
          browser::chromium::chromium_based_probe_with_key_outcomes(
            outcomes,
            cookies_path.clone(),
            domains.clone(),
            false,
          )
        })
      }
      #[cfg(all(unix, not(target_os = "linux")))]
      {
        let configs = any_browser_chromium_configs()?;
        best_chromium_probe(&configs, |_name, config| {
          browser::chromium::chromium_based_probe(
            config,
            cookies_path.clone(),
            domains.clone(),
            false,
          )
        })
      }
    }
    AnyBrowserSource::SafariBinaryCookies => {
      #[cfg(target_os = "macos")]
      {
        safari_based(cookies_path, domains)
      }
      #[cfg(not(target_os = "macos"))]
      {
        bail!("Safari binary cookie files are only supported on macOS")
      }
    }
    #[cfg(target_os = "windows")]
    AnyBrowserSource::InternetExplorerEse => internet_explorer_based(cookies_path, domains, false),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::common::enums::SAME_SITE_UNSPECIFIED;

  type BrowserEntry = (&'static str, fn(Option<Vec<String>>) -> Result<Vec<Cookie>>);

  fn not_installed(_domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
    Err(paths::BrowserNotInstalled::CookieDatabase.into())
  }

  fn extraction_fails(_domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
    Err(anyhow::anyhow!("cookie database is corrupt"))
  }

  fn always_ok(_domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
    Ok(vec![])
  }

  #[test]
  fn dynamic_config_lookup_uses_the_result_channel() {
    let error = browser_config("not-a-browser").expect_err("unknown names must return an error");
    assert_eq!(
      error.to_string(),
      "browser configuration \"not-a-browser\" is unavailable for this platform"
    );
  }

  fn named_cookie(name: &str) -> Cookie {
    Cookie {
      domain: "example.test".to_string(),
      path: "/".to_string(),
      secure: false,
      expires: None,
      name: name.to_string(),
      value: String::new(),
      http_only: false,
      same_site: SAME_SITE_UNSPECIFIED,
    }
  }

  fn first_ok(_domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
    Ok(vec![named_cookie("first")])
  }

  fn second_ok(_domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
    Ok(vec![named_cookie("second")])
  }

  #[test]
  fn no_installed_browsers_returns_ok_empty() {
    let browsers: Vec<BrowserEntry> = vec![("firefox", not_installed), ("chrome", not_installed)];
    let result = load_from_browsers(&browsers, None).expect("absence is not an extraction failure");
    assert!(result.is_empty());
  }

  #[test]
  fn all_installed_browsers_failing_returns_aggregate_error() {
    let browsers: Vec<BrowserEntry> =
      vec![("firefox", extraction_fails), ("chrome", extraction_fails)];
    let result = load_from_browsers(&browsers, None);
    assert!(result.is_err(), "expected Err when all browsers fail");
    let msg = result.unwrap_err().to_string();
    assert!(
      msg.contains("all browser extractions failed"),
      "error should mention aggregate failure, got: {msg}"
    );
    assert!(
      msg.contains("firefox: cookie database is corrupt"),
      "error should list firefox error, got: {msg}"
    );
    assert!(
      msg.contains("chrome: cookie database is corrupt"),
      "error should list chrome error, got: {msg}"
    );
  }

  #[test]
  fn partial_failure_returns_ok() {
    let browsers: Vec<BrowserEntry> = vec![("firefox", extraction_fails), ("chrome", always_ok)];
    let result = load_from_browsers(&browsers, None);
    assert!(
      result.is_ok(),
      "expected Ok when at least one browser succeeds, got: {result:?}"
    );
  }

  #[test]
  fn missing_browsers_do_not_hide_an_installed_browser_failure() {
    let browsers: Vec<BrowserEntry> =
      vec![("firefox", not_installed), ("chrome", extraction_fails)];
    let message = load_from_browsers(&browsers, None)
      .expect_err("the one installed browser failed")
      .to_string();
    assert!(message.contains("chrome: cookie database is corrupt"));
    assert!(!message.contains("firefox"));
  }

  #[test]
  fn empty_browser_list_returns_ok_empty() {
    let browsers: Vec<BrowserEntry> = vec![];
    let result = load_from_browsers(&browsers, None);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
  }

  #[test]
  fn load_from_browsers_preserves_source_order() {
    let browsers: Vec<BrowserEntry> = vec![
      ("first", first_ok),
      ("missing", not_installed),
      ("second", second_ok),
    ];
    let cookies = load_from_browsers(&browsers, None)
      .expect("successful sources survive an intervening extraction error");
    let names: Vec<_> = cookies.iter().map(|cookie| cookie.name.as_str()).collect();
    assert_eq!(names, vec!["first", "second"]);
  }

  #[test]
  fn legacy_load_browser_set_and_order_are_stable_for_this_platform() {
    let names: Vec<_> = legacy_load_browsers()
      .into_iter()
      .map(|(name, _)| name)
      .collect();

    #[cfg(target_os = "linux")]
    assert_eq!(
      names,
      vec![
        "firefox",
        "zen",
        "librewolf",
        "opera",
        "edge",
        "chromium",
        "brave",
        "vivaldi",
        "arc",
        "chrome",
        "cachy",
      ]
    );

    #[cfg(target_os = "macos")]
    assert_eq!(
      names,
      vec![
        "firefox",
        "zen",
        "librewolf",
        "opera",
        "edge",
        "chromium",
        "brave",
        "vivaldi",
        "arc",
        "chrome",
        "opera_gx",
        "safari",
      ]
    );

    #[cfg(target_os = "windows")]
    assert_eq!(
      names,
      vec![
        "firefox",
        "zen",
        "librewolf",
        "opera",
        "edge",
        "chromium",
        "brave",
        "vivaldi",
        "arc",
        "chrome",
        "internet_explorer",
        "opera_gx",
      ]
    );

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    assert_eq!(
      names,
      vec![
        "firefox",
        "zen",
        "librewolf",
        "opera",
        "edge",
        "chromium",
        "brave",
        "vivaldi",
        "arc",
      ]
    );
  }

  fn source_test_path(tag: &str) -> (crate::utils::TempDir, std::path::PathBuf) {
    let dir = crate::utils::TempDir::new().expect("temporary source directory");
    let path = dir.path().join(tag);
    (dir, path)
  }

  #[test]
  fn any_browser_sniffs_sqlite_decoder_family_from_schema() {
    let (_chromium_dir, chromium_path) = source_test_path("chromium.sqlite");
    let chromium = rusqlite::Connection::open(&chromium_path).expect("Chromium fixture");
    chromium
      .execute("CREATE TABLE cookies (name TEXT)", [])
      .expect("Chromium table");
    drop(chromium);

    let (_mozilla_dir, mozilla_path) = source_test_path("mozilla.sqlite");
    let mozilla = rusqlite::Connection::open(&mozilla_path).expect("Mozilla fixture");
    mozilla
      .execute("CREATE TABLE moz_cookies (name TEXT)", [])
      .expect("Mozilla table");
    drop(mozilla);

    assert_eq!(
      sniff_cookie_source(&chromium_path).expect("sniff Chromium"),
      AnyBrowserSource::ChromiumSqlite
    );
    assert_eq!(
      sniff_cookie_source(&mozilla_path).expect("sniff Mozilla"),
      AnyBrowserSource::MozillaSqlite
    );
  }

  #[test]
  fn any_browser_rejects_ambiguous_or_unrelated_sqlite_schemas() {
    let (_ambiguous_dir, ambiguous_path) = source_test_path("ambiguous.sqlite");
    let ambiguous = rusqlite::Connection::open(&ambiguous_path).expect("ambiguous fixture");
    ambiguous
      .execute_batch("CREATE TABLE cookies (name TEXT); CREATE TABLE moz_cookies (name TEXT);")
      .expect("ambiguous tables");
    drop(ambiguous);
    let error = sniff_cookie_source(&ambiguous_path).expect_err("ambiguous schema must fail");
    assert!(error
      .to_string()
      .contains("both `cookies` and `moz_cookies`"));

    let (_other_dir, other_path) = source_test_path("other.sqlite");
    let other = rusqlite::Connection::open(&other_path).expect("other fixture");
    other
      .execute("CREATE TABLE unrelated (value TEXT)", [])
      .expect("unrelated table");
    drop(other);
    let error = sniff_cookie_source(&other_path).expect_err("unrelated schema must fail");
    assert!(error.to_string().contains("unsupported SQLite database"));
  }

  #[test]
  fn any_browser_sniffs_binary_cookie_signature_without_decoder_probing() {
    let (_dir, path) = source_test_path("Cookies.binarycookies");
    std::fs::write(&path, b"cooksynthetic").expect("Safari header fixture");
    assert_eq!(
      sniff_cookie_source(&path).expect("sniff Safari"),
      AnyBrowserSource::SafariBinaryCookies
    );
  }

  #[test]
  fn any_browser_windows_sniff_uses_recovered_schema_without_reopening_live_header() {
    let (_dir, path) = source_test_path("locked-live-Cookies");
    std::fs::write(&path, b"header cannot classify this live path")
      .expect("unclassifiable live fixture");
    let calls = std::cell::Cell::new(0);

    let source = sniff_cookie_source_with_windows_recovery(&path, |_| {
      calls.set(calls.get() + 1);
      Ok(AnyBrowserSource::ChromiumSqlite)
    })
    .expect("recovered shadow schema is authoritative");

    assert_eq!(source, AnyBrowserSource::ChromiumSqlite);
    assert_eq!(calls.get(), 1);
  }

  #[test]
  fn any_browser_windows_sniff_falls_back_to_real_safari_magic_after_sqlite_rejection() {
    let (_dir, path) = source_test_path("Cookies.binarycookies");
    std::fs::write(&path, b"cooksynthetic").expect("Safari header fixture");

    let source = sniff_cookie_source_with_windows_recovery(&path, |_| {
      Err(anyhow::anyhow!("not a SQLite database"))
    })
    .expect("lowercase Safari magic is recognized after SQLite rejection");

    assert_eq!(source, AnyBrowserSource::SafariBinaryCookies);
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn any_browser_sniffs_ese_signature() {
    let (_dir, path) = source_test_path("WebCacheV01.dat");
    std::fs::write(&path, [0, 0, 0, 0, 0xef, 0xcd, 0xab, 0x89]).expect("ESE header fixture");
    assert_eq!(
      sniff_cookie_source(&path).expect("sniff ESE"),
      AnyBrowserSource::InternetExplorerEse
    );
  }

  #[cfg(unix)]
  #[test]
  fn any_browser_does_not_accept_partial_wrong_chromium_identity_early() {
    let configs = vec![
      (
        "wrong",
        browser_config("chrome").expect("Chrome configuration"),
      ),
      (
        "correct",
        browser_config("brave").expect("Brave configuration"),
      ),
    ];
    let mut probed = Vec::new();
    let cookies = best_chromium_probe(&configs, |name, _config| {
      probed.push(name);
      if name == "wrong" {
        Ok(browser::chromium::ChromiumProbeResult {
          cookies: vec![named_cookie("fallback")],
          rows_skipped: 1,
        })
      } else {
        Ok(browser::chromium::ChromiumProbeResult {
          cookies: vec![named_cookie("fallback"), named_cookie("encrypted")],
          rows_skipped: 0,
        })
      }
    })
    .expect("correct identity wins");

    assert_eq!(probed, vec!["wrong", "correct"]);
    assert_eq!(
      cookies
        .iter()
        .map(|cookie| cookie.name.as_str())
        .collect::<Vec<_>>(),
      vec!["fallback", "encrypted"]
    );
  }

  #[cfg(unix)]
  #[test]
  fn any_browser_preserves_chromium_probe_diagnostics_when_all_identities_fail() {
    let configs = vec![
      (
        "chrome",
        browser_config("chrome").expect("Chrome configuration"),
      ),
      (
        "brave",
        browser_config("brave").expect("Brave configuration"),
      ),
    ];
    let error = best_chromium_probe(&configs, |name, _config| {
      Err(anyhow::anyhow!("{name} keyring is locked"))
    })
    .expect_err("all failures must remain visible");
    let message = error.to_string();
    assert!(message.contains("chrome: chrome keyring is locked"));
    assert!(message.contains("brave: brave keyring is locked"));
  }

  #[cfg(unix)]
  #[test]
  fn any_browser_chromium_configs_include_arc_with_its_own_identity() {
    let configs = any_browser_chromium_configs().expect("Chromium configurations");
    let names = configs.iter().map(|(name, _)| *name).collect::<Vec<_>>();
    #[cfg(target_os = "linux")]
    assert_eq!(
      names,
      vec!["chrome", "brave", "chromium", "edge", "opera", "vivaldi", "arc"]
    );
    #[cfg(target_os = "macos")]
    assert_eq!(
      names,
      vec!["chrome", "brave", "chromium", "edge", "opera", "vivaldi", "arc", "opera_gx"]
    );

    let (_, arc) = configs
      .iter()
      .find(|(name, _)| *name == "arc")
      .expect("Arc configuration");
    assert_eq!(arc.unix_crypt_name.as_deref(), Some("arc"));

    #[cfg(target_os = "macos")]
    {
      assert_eq!(arc.osx_key_service.as_deref(), Some("Arc Safe Storage"));
      assert_eq!(arc.osx_key_user.as_deref(), Some("Arc"));
    }
  }

  #[cfg(unix)]
  use std::sync::atomic::{AtomicU64, Ordering};
  #[cfg(unix)]
  use std::sync::{Mutex, MutexGuard};

  #[cfg(unix)]
  static ENV_MUTEX: Mutex<()> = Mutex::new(());

  /// RAII guard that restores `HOME` to its prior value when dropped.
  ///
  /// Holds the `ENV_MUTEX` lock for its entire lifetime so that parallel
  /// tests never observe an intermediate value for `HOME`. The temp
  /// directory is also removed in `Drop`, guaranteeing cleanup even when
  /// the test panics before reaching the end of the function.
  #[cfg(unix)]
  struct HomeGuard<'a> {
    old_home: Option<std::ffi::OsString>,
    home_dir: std::path::PathBuf,
    _lock: MutexGuard<'a, ()>,
  }

  #[cfg(unix)]
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

  #[cfg(unix)]
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

  #[cfg(unix)]
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
