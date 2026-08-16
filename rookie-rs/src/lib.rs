// Compatibility APIs remain callable through 0.6 while their downstream use
// is deprecated. Internal adapters intentionally exercise those exact paths.
#![allow(deprecated)]

// Public

// Common
pub mod common;
pub mod config;
pub mod direct_path;
pub mod report;
mod utils;
pub use common::enums;

// Browser
#[cfg(target_os = "windows")]
pub use browser::internet_explorer::internet_explorer_based;
#[cfg(target_os = "macos")]
pub use browser::safari::safari_based;
pub use browser::{
  chromium::{chromium_based, chromium_based_detailed},
  mozilla::{firefox_based, firefox_based_detailed, MozillaProfile},
};

// Private
mod browser;
mod compatibility_dispatch;
use anyhow::bail;
pub use anyhow::{self, Result};
use enums::Cookie;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

/// Thin compatibility projection over registry-backed discovery/extraction.
fn named_browser(name: &str, domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  browser::legacy::browser_cookies(name, domains)
}

/// Extracts an explicit Chromium cookie database using registry-resolved key
/// identity on Unix.
///
/// `browser_id` should be a canonical ID (or registered alias) from
/// [`supported_browsers`]. It controls Linux keyring and macOS Keychain lookup;
/// the database path is never guessed to be Chrome. `None` is accepted only
/// for databases containing plaintext rows exclusively.
#[cfg(unix)]
#[deprecated(
  since = "0.6.0",
  note = "use direct_path::chromium_cookies_from_path with ChromiumPathRequest"
)]
pub fn chromium_based_with_browser_id(
  browser_id: Option<&str>,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<Cookie>> {
  match browser_id
    .map(browser::registry::chromium_key_credentials)
    .transpose()?
    .flatten()
  {
    Some(config) => chromium_based(&config, db_path, domains, force_kill),
    None => browser::chromium::chromium_based_plaintext_only(db_path, domains, force_kill),
  }
}

/// Detailed counterpart to [`chromium_based_with_browser_id`].
#[cfg(unix)]
#[deprecated(
  since = "0.6.0",
  note = "use direct_path::chromium_cookies_from_path_detailed with ChromiumPathRequest"
)]
pub fn chromium_based_detailed_with_browser_id(
  browser_id: Option<&str>,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<enums::DetailedCookie>> {
  match browser_id
    .map(browser::registry::chromium_key_credentials)
    .transpose()?
    .flatten()
  {
    Some(config) => chromium_based_detailed(&config, db_path, domains, force_kill),
    None => browser::chromium::chromium_based_detailed_plaintext_only(db_path, domains, force_kill),
  }
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

/// Returns every browser registered for the running OS.
///
/// Registration is not detection: this never touches the filesystem, so a
/// descriptor here only means rookie knows where that browser would keep its
/// cookies and which cipher tiers this build could decrypt. Use
/// [`browser_profiles`] to find out what is actually installed.
///
/// An OS with no registry entries has no registered browsers, which is an empty
/// list rather than an error. A malformed embedded registry is returned as an
/// error so callers never confuse an internal failure with an empty inventory.
///
/// # Examples
///
/// ```no_run
/// for browser in rookie_cookies::supported_browsers()? {
///   println!("{} ({})", browser.id, browser.display_name);
/// }
/// # Ok::<(), rookie_cookies::anyhow::Error>(())
/// ```
pub fn supported_browsers() -> Result<Vec<report::BrowserDescriptor>> {
  browser::report_build::supported_browser_descriptors()
}

/// Returns the discovered profiles of one registered browser.
///
/// # Arguments
///
/// * `browser_id` - A canonical browser ID or alias from [`supported_browsers`]
///
/// # Errors
///
/// An unknown ID or alias is a request error. So is a browser whose every
/// detected installation root failed enumeration, because an empty list would
/// be indistinguishable from "not installed"; [`browser_report`] carries the
/// per-root diagnostics in that case. A known browser with nothing installed
/// returns an empty list rather than an error, and one failing root does not
/// hide the profiles another root yielded.
///
/// # Examples
///
/// ```no_run
/// for profile in rookie_cookies::browser_profiles("chrome")? {
///   println!("{} {}", profile.profile.profile_id, profile.profile.display_name);
/// }
/// # Ok::<(), rookie_cookies::anyhow::Error>(())
/// ```
pub fn browser_profiles(browser_id: &str) -> Result<Vec<report::ProfileDescriptor>> {
  browser::report_build::browser_profile_descriptors(browser_id)
}

/// Returns every discovered Google Chrome profile, preferring the active one.
///
/// This is an additive registry-backed API. It does not change [`chrome`],
/// whose legacy first/default-profile selector remains frozen, or the generic
/// default-first ordering of [`browser_profiles`]. When Chrome's `Local State`
/// names a last-used profile, that profile is listed first; the remaining
/// active profiles follow in their declared order. Missing, stale, or malformed
/// activity hints safely fall back to the generic discovery order.
///
/// Each result retains its stable profile/installation IDs and ordered cookie
/// source descriptors. Pass a profile ID, display name, directory name, or a
/// full path to [`chrome_profile`]. A full path is selectable only when
/// `profile.path_lossy` is false; otherwise use the opaque profile ID. IDs are
/// also recommended when multiple installations contain same-named profiles.
///
/// # Examples
///
/// ```no_run
/// for profile in rookie_cookies::chrome_profiles()? {
///   println!("{} {}", profile.profile.profile_id, profile.profile.display_name);
/// }
/// # Ok::<(), rookie_cookies::anyhow::Error>(())
/// ```
pub fn chrome_profiles() -> Result<Vec<report::ProfileDescriptor>> {
  browser::report_build::chrome_profile_descriptors()
}

/// Extracts one selected Google Chrome profile as a grouped report.
///
/// Unlike the legacy [`chrome`] function, this registry-backed selector keeps
/// the selected profile identity, cookie-source provenance, partial failures,
/// and typed discovery issues. `profile` may be the opaque profile ID returned
/// by [`chrome_profiles`], a display name, a directory name, or a non-lossy
/// full path. When a descriptor has `profile.path_lossy == true`, its display
/// path cannot round-trip through this UTF-8 selector and its opaque ID is
/// required. Ambiguous names are rejected instead of silently selecting the
/// wrong channel or installation.
///
/// # Examples
///
/// ```no_run
/// let profiles = rookie_cookies::chrome_profiles()?;
/// if let Some(preferred) = profiles.first() {
///   let report = rookie_cookies::chrome_profile(
///     preferred.profile.profile_id.as_str(),
///     Some(vec!["example.com".to_owned()]),
///   )?;
///   println!("{}", report.status);
/// }
/// # Ok::<(), rookie_cookies::anyhow::Error>(())
/// ```
pub fn chrome_profile(
  profile: &str,
  domains: Option<Vec<String>>,
) -> Result<report::ExtractionReport> {
  browser::report_build::chrome_profile_report(profile, domains)
}

/// Extracts cookies from one browser as a grouped report.
///
/// Unlike the named selectors, this covers every installation and profile of
/// the browser and keeps failures visible instead of collapsing them into an
/// error or a short list: cookies stay attached to the source they came from,
/// alongside that source's status, acquisition strategy, counters, and issues.
///
/// # Arguments
///
/// * `browser_id` - A canonical browser ID or alias from [`supported_browsers`]
/// * `profile_id` - An optional [`ProfileId`](report::ProfileId) from
///   [`browser_profiles`], restricting the report to that one profile. Display
///   paths and names are not selection keys.
/// * `domains` - An optional list for getting specific domains only
///
/// # Errors
///
/// Only a bad request fails: an unknown browser ID or alias, or a profile ID
/// that this browser did not yield. Extraction problems are reported instead —
/// a browser that is registered but not installed is an `Ok` report with
/// [`no_sources`](report::ReportStatusCode::no_sources), and a total extraction
/// failure is an `Ok` report with
/// [`failed`](report::ReportStatusCode::failed).
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let report = rookie_cookies::browser_report("chrome", None, Some(domains))?;
/// println!("{}: {} cookies", report.status, report.summary.cookies_emitted);
/// # Ok::<(), rookie_cookies::anyhow::Error>(())
/// ```
pub fn browser_report(
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<Vec<String>>,
) -> Result<report::ExtractionReport> {
  browser::report_build::browser_extraction_report(browser_id, profile_id, domains)
}

/// Extracts cookies from every registered browser as one grouped report.
///
/// This is the report-shaped counterpart to [`load`], not a replacement for it:
/// `load` keeps its historical browser set and flat output, while this covers
/// every registered browser on the running OS. Registered browsers that are not
/// installed are summarized in
/// [`browsers_not_detected`](report::ReportStats::browsers_not_detected) rather
/// than emitting an issue each; installed browsers that fail do emit issues.
///
/// # Arguments
///
/// * `domains` - An optional list for getting specific domains only
///
/// # Errors
///
/// There is no browser ID to reject here, so this fails only if the registry
/// itself cannot be read. A browser that fails discovery or extraction does not
/// abort the others; it becomes an issue on the returned report.
///
/// # Examples
///
/// ```no_run
/// let report = rookie_cookies::load_report(None)?;
/// println!(
///   "{}/{} browsers detected",
///   report.summary.browsers_detected, report.summary.registered_browsers
/// );
/// # Ok::<(), rookie_cookies::anyhow::Error>(())
/// ```
pub fn load_report(domains: Option<Vec<String>>) -> Result<report::ExtractionReport> {
  browser::report_build::load_extraction_report(domains)
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
  named_browser("firefox", domains)
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
  browser::legacy::gecko_profiles("firefox")
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
  named_browser("librewolf", domains)
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
  named_browser("cachy", domains)
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
  named_browser("chrome", domains)
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
  named_browser("chromium", domains)
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
  named_browser("brave", domains)
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
  named_browser("arc", domains)
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
  named_browser("zen", domains)
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
  named_browser("edge", domains)
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
  named_browser("vivaldi", domains)
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
  named_browser("opera", domains)
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
#[cfg_attr(
  not(any(target_os = "macos", target_os = "windows")),
  deprecated(
    since = "0.5.9",
    note = "Opera GX is unsupported on this target; this compatibility shim will be removed in 0.7"
  )
)]
pub fn opera_gx(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  compatibility_dispatch::opera_gx(domains)
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
  named_browser("octo_browser", domains)
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
  named_browser("safari", domains)
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
  named_browser("internet_explorer", domains)
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
      Err(err) if browser::legacy::is_browser_not_installed(&err) => {
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
  let browser_types = compatibility_dispatch::legacy_load_browsers();
  load_from_browsers(&browser_types, domains)
}

#[cfg(test)]
use direct_path::CookieSourceKind as AnyBrowserSource;

/// Inspects the source's on-disk signature before choosing a decoder family.
#[cfg(test)]
fn sniff_cookie_source(path: &std::path::Path) -> Result<AnyBrowserSource> {
  direct_path::classify_cookie_source_legacy(path)
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
#[deprecated(
  since = "0.6.0",
  note = "use direct_path::cookies_from_path with DirectPathRequest"
)]
pub fn any_browser(
  cookies_path: &str,
  domains: Option<Vec<String>>,
  key_path: Option<&str>,
) -> Result<Vec<Cookie>> {
  compatibility_dispatch::any_browser(cookies_path, domains, key_path)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::common::enums::SAME_SITE_UNSPECIFIED;

  type BrowserEntry = (&'static str, fn(Option<Vec<String>>) -> Result<Vec<Cookie>>);

  fn not_installed(_domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
    Err(browser::legacy::BrowserNotInstalled::CookieDatabase.into())
  }

  fn extraction_fails(_domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
    Err(anyhow::anyhow!("cookie database is corrupt"))
  }

  fn always_ok(_domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
    Ok(vec![])
  }

  #[cfg(unix)]
  #[test]
  fn explicit_path_rejects_encrypted_rows_without_browser_identity() {
    let directory = crate::utils::TempDir::new().expect("temp directory");
    let db = directory.path().join("Cookies");
    seed_explicit_path_cookie(&db, "", b"v11encrypted");

    let error = chromium_based_with_browser_id(None, db.clone(), None, false)
      .expect_err("encrypted rows require a browser identity");
    assert!(error.to_string().contains("no browser key identity"));
    assert!(error.to_string().contains("browser_id"));

    let detailed_error = chromium_based_detailed_with_browser_id(None, db, None, false)
      .expect_err("detailed encrypted rows require a browser identity");
    assert!(detailed_error
      .to_string()
      .contains("no browser key identity"));
  }

  #[cfg(unix)]
  #[test]
  fn explicit_path_without_identity_remains_available_for_plaintext_only_databases() {
    let directory = crate::utils::TempDir::new().expect("temp directory");
    let db = directory.path().join("Cookies");
    seed_explicit_path_cookie(&db, "plaintext", b"");

    let cookies = chromium_based_with_browser_id(None, db.clone(), None, false)
      .expect("plaintext-only databases need no key identity");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].value, "plaintext");

    let detailed = chromium_based_detailed_with_browser_id(None, db, None, false)
      .expect("detailed plaintext-only databases need no key identity");
    assert_eq!(detailed.len(), 1);
    assert_eq!(detailed[0].cookie.value, "plaintext");
  }

  #[cfg(target_os = "macos")]
  #[test]
  fn registered_chromium_without_keychain_identity_is_plaintext_only() {
    for browser_id in ["coccoc", "yandex"] {
      let directory = crate::utils::TempDir::new().expect("temp directory");
      let db = directory.path().join("Cookies");
      seed_explicit_path_cookie(&db, "plaintext", b"");
      let cookies = chromium_based_with_browser_id(Some(browser_id), db, None, false)
        .expect("registered browser without credentials can read plaintext");
      assert_eq!(cookies.len(), 1);
      assert_eq!(cookies[0].value, "plaintext");
    }

    let directory = crate::utils::TempDir::new().expect("temp directory");
    let db = directory.path().join("Cookies");
    seed_explicit_path_cookie(&db, "", b"v10encrypted");
    let error = chromium_based_with_browser_id(Some("coccoc"), db, None, false)
      .expect_err("registered browser without credentials cannot read encrypted rows");
    assert!(error.to_string().contains("no browser key identity"));
  }

  #[cfg(unix)]
  #[test]
  fn explicit_path_identity_check_covers_the_profile_before_domain_filtering() {
    let directory = crate::utils::TempDir::new().expect("temp directory");
    let db = directory.path().join("Cookies");
    seed_explicit_path_cookie(&db, "plaintext", b"");
    let connection = rusqlite::Connection::open(&db).expect("reopen fixture");
    connection
      .execute(
        "INSERT INTO cookies VALUES ('.other.test', '/', 0, 0, 'encrypted', '', ?1, 0, 0)",
        rusqlite::params![b"v11encrypted"],
      )
      .expect("seed encrypted row outside the requested domain");
    drop(connection);

    let error =
      chromium_based_with_browser_id(None, db, Some(vec!["example.test".to_string()]), false)
        .expect_err("the whole encrypted profile requires an identity");
    assert!(error.to_string().contains("no browser key identity"));
  }

  #[cfg(unix)]
  fn seed_explicit_path_cookie(db: &std::path::Path, value: &str, encrypted_value: &[u8]) {
    let connection = rusqlite::Connection::open(db).expect("open fixture");
    connection
      .execute_batch(
        "CREATE TABLE meta (
           key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR
         );
         INSERT INTO meta (key, value) VALUES ('version', '23');
         CREATE TABLE cookies (
           host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
           name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER,
           samesite INTEGER
         );",
      )
      .expect("create cookie schema");
    connection
      .execute(
        "INSERT INTO cookies VALUES ('.example.test', '/', 0, 0, 'session', ?1, ?2, 0, 0)",
        rusqlite::params![value, encrypted_value],
      )
      .expect("seed cookie row");
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

  #[cfg(target_os = "linux")]
  #[test]
  #[allow(deprecated)]
  fn opera_gx_remains_explicitly_unsupported_and_unadvertised_on_linux() {
    let error = opera_gx(None).expect_err("Opera GX has no Linux implementation");
    assert!(error
      .to_string()
      .contains("Opera GX is not supported on Linux"));
    assert!(supported_browsers()
      .expect("supported browsers")
      .iter()
      .all(|browser| browser.id.as_str() != "opera_gx"));
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
  use std::sync::atomic::{AtomicU64, Ordering};
  #[cfg(unix)]
  use std::sync::{Mutex, MutexGuard};

  #[cfg(unix)]
  static ENV_MUTEX: Mutex<()> = Mutex::new(());

  /// RAII guard that restores Chromium discovery environment variables to
  /// their prior values when dropped.
  ///
  /// Holds the `ENV_MUTEX` lock for its entire lifetime so that parallel
  /// tests never observe intermediate environment values. The temp directory
  /// is also removed in `Drop`, guaranteeing cleanup even when the test panics
  /// before reaching the end of the function.
  #[cfg(unix)]
  struct HomeGuard<'a> {
    old_home: Option<std::ffi::OsString>,
    old_chrome_config_home: Option<std::ffi::OsString>,
    old_xdg_config_home: Option<std::ffi::OsString>,
    home_dir: std::path::PathBuf,
    _lock: MutexGuard<'a, ()>,
  }

  #[cfg(unix)]
  impl<'a> HomeGuard<'a> {
    /// Create a new guard: acquires `lock`, sets `HOME` to `home_dir`, clears
    /// config-home overrides, and arranges to restore the old values on drop.
    fn new(lock: MutexGuard<'a, ()>, home_dir: std::path::PathBuf) -> Self {
      let old_home = std::env::var_os("HOME");
      let old_chrome_config_home = std::env::var_os("CHROME_CONFIG_HOME");
      let old_xdg_config_home = std::env::var_os("XDG_CONFIG_HOME");
      // SAFETY: we hold ENV_MUTEX so no other test thread concurrently
      // writes these environment variables.
      #[allow(deprecated)]
      unsafe {
        std::env::set_var("HOME", &home_dir);
        std::env::remove_var("CHROME_CONFIG_HOME");
        std::env::remove_var("XDG_CONFIG_HOME");
      }
      HomeGuard {
        old_home,
        old_chrome_config_home,
        old_xdg_config_home,
        home_dir,
        _lock: lock,
      }
    }
  }

  #[cfg(unix)]
  impl Drop for HomeGuard<'_> {
    fn drop(&mut self) {
      // Restore the discovery environment before releasing the mutex lock.
      #[allow(deprecated)]
      unsafe {
        match &self.old_home {
          Some(old) => std::env::set_var("HOME", old),
          None => std::env::remove_var("HOME"),
        }
        match &self.old_chrome_config_home {
          Some(old) => std::env::set_var("CHROME_CONFIG_HOME", old),
          None => std::env::remove_var("CHROME_CONFIG_HOME"),
        }
        match &self.old_xdg_config_home {
          Some(old) => std::env::set_var("XDG_CONFIG_HOME", old),
          None => std::env::remove_var("XDG_CONFIG_HOME"),
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
      .execute_batch(
        "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
        INSERT INTO meta (key, value) VALUES ('version', '23');
        CREATE TABLE cookies (
          host_key TEXT NOT NULL,
          path TEXT NOT NULL,
          is_secure INTEGER NOT NULL,
          expires_utc INTEGER NOT NULL,
          name TEXT NOT NULL,
          value TEXT NOT NULL,
          encrypted_value BLOB,
          is_httponly INTEGER NOT NULL,
          samesite INTEGER NOT NULL
        );",
      )
      .expect("create Chromium schema");
    conn
      .execute(
        "INSERT INTO cookies (host_key, path, is_secure, expires_utc, name, value, encrypted_value, is_httponly, samesite)
         VALUES ('.example.com', '/', 0, 0, ?1, ?2, ?3, 0, 0)",
        rusqlite::params![cookie_name, cookie_value, &b""[..]],
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
