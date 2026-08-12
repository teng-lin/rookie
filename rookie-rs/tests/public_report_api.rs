//! Request and report semantics of the public generic API.
//!
//! These run against a synthetic home directory so a browser installed on the
//! host cannot decide whether an assertion passes. Discovery snapshots the
//! process environment, so every test here holds [`ENV_LOCK`] for its duration.

use rookie_cookies::report::{
  ExtractionReport, IssueSeverityCode, ProfileDescriptor, ReportStatusCode, SourceStatusCode,
};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Everything discovery reads to locate an installation root on any platform.
/// All of them are overridden together, so a variable this host happens to set
/// cannot point discovery back outside the synthetic home.
const ISOLATED_VARS: &[&str] = &[
  "HOME",
  "USERPROFILE",
  "XDG_CONFIG_HOME",
  "CHROME_CONFIG_HOME",
  "LOCALAPPDATA",
  "APPDATA",
];

/// A temporary home directory installed into the process environment.
///
/// Restores the previous values and removes the directory on drop, including
/// on unwind, and holds the environment lock until then.
struct SyntheticHome<'a> {
  home: PathBuf,
  restored: Vec<(&'static str, Option<OsString>)>,
  _lock: MutexGuard<'a, ()>,
}

impl SyntheticHome<'_> {
  fn new(tag: &str) -> Self {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let lock = ENV_LOCK
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    let home = std::env::temp_dir().join(format!(
      "rookie-public-report-{tag}-{}-{}",
      std::process::id(),
      COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&home).expect("create synthetic home");

    let restored = ISOLATED_VARS
      .iter()
      .map(|name| (*name, std::env::var_os(name)))
      .collect();
    let synthetic = SyntheticHome {
      home,
      restored,
      _lock: lock,
    };
    set_var("HOME", &synthetic.home);
    set_var("USERPROFILE", &synthetic.home);
    set_var("XDG_CONFIG_HOME", &synthetic.home.join(".config"));
    set_var("LOCALAPPDATA", &synthetic.home.join("AppData/Local"));
    set_var("APPDATA", &synthetic.home.join("AppData/Roaming"));
    remove_var("CHROME_CONFIG_HOME");
    synthetic
  }

  /// Chrome's real stable-channel user-data directory for this OS.
  fn chrome_root(&self) -> PathBuf {
    #[cfg(target_os = "linux")]
    return self.home.join(".config/google-chrome");
    #[cfg(target_os = "macos")]
    return self.home.join("Library/Application Support/Google/Chrome");
    #[cfg(target_os = "windows")]
    return self.home.join("AppData/Local/Google/Chrome/User Data");
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    return self.home.join(".config/google-chrome");
  }
}

impl Drop for SyntheticHome<'_> {
  fn drop(&mut self) {
    for (name, value) in &self.restored {
      match value {
        Some(value) => set_os_var(name, value),
        None => remove_var(name),
      }
    }
    let _ = std::fs::remove_dir_all(&self.home);
  }
}

fn set_var(name: &str, value: &Path) {
  set_os_var(name, value.as_os_str());
}

fn set_os_var(name: &str, value: &std::ffi::OsStr) {
  // SAFETY: ENV_LOCK is held, so no other test thread reads or writes the
  // environment while it changes.
  #[allow(deprecated)]
  unsafe {
    std::env::set_var(name, value)
  };
}

fn remove_var(name: &str) {
  // SAFETY: see `set_os_var`.
  #[allow(deprecated)]
  unsafe {
    std::env::remove_var(name)
  };
}

/// Writes a Chromium profile holding one plaintext cookie.
fn seed_chromium_profile(root: &Path, profile: &str, name: &str, value: &str) {
  let database = root.join(profile).join("Network/Cookies");
  std::fs::create_dir_all(database.parent().expect("profile directory"))
    .expect("create profile directory");
  let connection = rusqlite::Connection::open(&database).expect("open cookie database");
  connection
    .execute_batch(
      "CREATE TABLE cookies (
        host_key TEXT NOT NULL,
        path TEXT NOT NULL,
        is_secure INTEGER NOT NULL,
        expires_utc INTEGER NOT NULL,
        name TEXT NOT NULL,
        value TEXT NOT NULL,
        encrypted_value BLOB NOT NULL,
        is_httponly INTEGER NOT NULL,
        samesite INTEGER NOT NULL
      );",
    )
    .expect("create cookies table");
  connection
    .execute(
      "INSERT INTO cookies VALUES ('.example.test', '/', 0, 0, ?1, ?2, ?3, 0, 0)",
      rusqlite::params![name, value, Vec::<u8>::new()],
    )
    .expect("insert cookie");
  std::fs::write(root.join("Local State"), b"{}").expect("write Local State");
}

fn seeded_chrome(tag: &str) -> SyntheticHome<'static> {
  let home = SyntheticHome::new(tag);
  let root = home.chrome_root();
  seed_chromium_profile(&root, "Default", "session", "default-value");
  seed_chromium_profile(&root, "Profile 1", "session", "profile-value");
  home
}

fn is_opaque_id(value: &str) -> bool {
  value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn error_issues(report: &ExtractionReport) -> Vec<&str> {
  report
    .issues
    .iter()
    .chain(report.profiles.iter().flat_map(|profile| {
      profile
        .issues
        .iter()
        .chain(profile.sources.iter().flat_map(|source| &source.issues))
    }))
    .filter(|issue| issue.severity == IssueSeverityCode::error())
    .map(|issue| issue.code.as_str())
    .collect()
}

#[test]
fn unknown_browser_ids_are_request_errors_rather_than_report_issues() {
  let _home = SyntheticHome::new("unknown-browser");

  let report = rookie_cookies::browser_report("not-a-browser", None, None)
    .expect_err("an unknown browser id is a request error");
  assert!(
    report.to_string().contains("unknown browser id"),
    "unexpected message: {report:#}"
  );
  let profiles = rookie_cookies::browser_profiles("not-a-browser")
    .expect_err("an unknown browser id is a request error");
  assert!(
    profiles.to_string().contains("unknown browser id"),
    "unexpected message: {profiles:#}"
  );
}

#[test]
fn unknown_profile_ids_are_request_errors() {
  let home = seeded_chrome("unknown-profile");

  let error = rookie_cookies::browser_report("chrome", Some(&"0".repeat(64)), None)
    .expect_err("an unmatched profile id is a request error");
  assert!(
    error.to_string().contains("unknown chrome profile id"),
    "unexpected message: {error:#}"
  );

  // A display path is not a selection key, however real the path is.
  let path = home.chrome_root().join("Default");
  let error = rookie_cookies::browser_report("chrome", Some(&path.to_string_lossy()), None)
    .expect_err("display paths are not selection keys");
  assert!(
    error.to_string().contains("unknown chrome profile id"),
    "unexpected message: {error:#}"
  );
}

#[test]
fn a_registered_browser_with_no_installation_reports_no_sources() {
  let _home = SyntheticHome::new("absent-browser");

  let report = rookie_cookies::browser_report("chrome", None, None)
    .expect("an absent browser is not an error");
  assert_eq!(report.status, ReportStatusCode::no_sources());
  assert!(report.profiles.is_empty());
  assert_eq!(report.summary.registered_browsers, 1);
  assert_eq!(report.summary.browsers_detected, 0);
  assert_eq!(report.summary.browsers_not_detected, 1);
  assert_eq!(report.summary.profiles_discovered, 0);

  let codes = report
    .issues
    .iter()
    .map(|issue| issue.code.as_str())
    .collect::<Vec<_>>();
  assert_eq!(codes, ["browser_not_detected"]);
  let issue = &report.issues[0];
  assert_eq!(issue.severity, IssueSeverityCode::info());
  assert_eq!(
    issue.browser_id.as_ref().map(|id| id.as_str()),
    Some("chrome")
  );
}

#[test]
fn browser_profiles_returns_an_empty_list_for_a_known_absent_browser() {
  let _home = SyntheticHome::new("absent-profiles");

  let profiles: Vec<ProfileDescriptor> =
    rookie_cookies::browser_profiles("chrome").expect("absence is not an enumeration failure");
  assert!(profiles.is_empty());
}

#[test]
fn load_report_summarizes_uninstalled_browsers_in_counters_only() {
  let _home = SyntheticHome::new("load-report");

  let registered = rookie_cookies::supported_browsers().expect("registered browsers");
  let report = rookie_cookies::load_report(None).expect("an empty machine is not an error");

  assert_eq!(report.status, ReportStatusCode::no_sources());
  assert_eq!(
    report.summary.registered_browsers as usize,
    registered.len()
  );
  assert_eq!(
    report.summary.browsers_not_detected,
    report.summary.registered_browsers
  );
  assert_eq!(report.summary.browsers_detected, 0);
  assert!(
    report.issues.is_empty(),
    "uninstalled browsers belong in counters, not issues: {:?}",
    report
      .issues
      .iter()
      .map(|issue| issue.code.as_str())
      .collect::<Vec<_>>()
  );
}

#[test]
fn chrome_report_keeps_cookies_on_the_source_they_came_from() {
  let _home = seeded_chrome("chrome-report");

  let report = rookie_cookies::browser_report("chrome", None, None).expect("chrome report");
  assert!(
    error_issues(&report).is_empty(),
    "plaintext rows must not produce error issues: {:?}",
    error_issues(&report)
  );
  assert_eq!(report.status, ReportStatusCode::complete());
  assert_eq!(report.profiles.len(), 2);
  assert_eq!(report.summary.profiles_discovered, 2);
  assert_eq!(report.summary.sources_succeeded, 2);
  assert_eq!(report.summary.sources_failed, 0);
  assert_eq!(report.summary.cookies_emitted, 2);
  assert!(!report.summary.counters_saturated);

  let mut values = Vec::new();
  for profile in &report.profiles {
    assert!(is_opaque_id(profile.profile.profile_id.as_str()));
    assert!(is_opaque_id(profile.profile.installation_id.as_str()));
    assert_eq!(profile.profile.browser_id.as_str(), "chrome");
    assert!(!profile.profile.path_lossy);
    assert_eq!(profile.sources.len(), 1);

    let source = &profile.sources[0];
    assert_eq!(source.status, SourceStatusCode::succeeded());
    assert!(source.selected);
    assert_eq!(source.source.role.as_str(), "persistent");
    assert_eq!(source.source.format.as_str(), "chromium_sqlite");
    assert_eq!(source.stats.cookies_emitted, 1);
    assert_eq!(source.stats.rows_skipped, 0);
    assert_eq!(source.cookies.len(), 1);
    assert_eq!(source.cookies[0].name, "session");
    assert_eq!(source.cookies[0].domain, ".example.test");
    values.push(source.cookies[0].value.clone());
  }

  // Same cookie key in two profiles stays separated by profile group.
  values.sort();
  assert_eq!(values, ["default-value", "profile-value"]);
  let ids = report
    .profiles
    .iter()
    .map(|profile| profile.profile.profile_id.as_str())
    .collect::<BTreeSet<_>>();
  assert_eq!(ids.len(), 2);
}

#[test]
fn profile_selection_uses_the_opaque_id_from_browser_profiles() {
  let _home = seeded_chrome("chrome-selection");

  let profiles = rookie_cookies::browser_profiles("chrome").expect("chrome profiles");
  assert_eq!(profiles.len(), 2);
  let default = profiles
    .iter()
    .find(|profile| profile.is_default)
    .expect("one profile is the installation default");
  assert!(!default.sources.is_empty());
  assert_eq!(default.sources[0].role.as_str(), "persistent");

  let selected = default.profile.profile_id.as_str();
  let report = rookie_cookies::browser_report("chrome", Some(selected), None)
    .expect("selected profile report");
  assert_eq!(report.profiles.len(), 1);
  assert_eq!(report.profiles[0].profile.profile_id.as_str(), selected);
}

#[test]
fn domain_filters_reach_the_generic_report() {
  let _home = seeded_chrome("chrome-domains");

  let matched = rookie_cookies::browser_report("chrome", None, Some(vec!["example.test".into()]))
    .expect("filtered report");
  assert_eq!(matched.summary.cookies_emitted, 2);

  let unmatched = rookie_cookies::browser_report("chrome", None, Some(vec!["absent.test".into()]))
    .expect("a filter that matches nothing still succeeds");
  assert_eq!(unmatched.summary.cookies_emitted, 0);
  assert_eq!(unmatched.summary.sources_succeeded, 2);
  assert_eq!(unmatched.status, ReportStatusCode::complete());
}

#[test]
fn reports_serialize_to_snake_case_json_with_open_string_codes() {
  let _home = seeded_chrome("chrome-json");

  let report = rookie_cookies::browser_report("chrome", None, None).expect("chrome report");
  let wire = serde_json::to_value(&report).expect("serialize report");

  assert_eq!(wire["status"], "complete");
  assert_eq!(wire["summary"]["cookies_emitted"], 2);
  assert!(wire["summary"]["counters_saturated"].is_boolean());
  let source = &wire["profiles"][0]["sources"][0];
  assert_eq!(source["status"], "succeeded");
  assert_eq!(source["source"]["role"], "persistent");
  assert!(source["acquisition_strategy"].is_string());
  assert!(source["source"]["path_lossy"].is_boolean());
  // Legacy cookie rows keep their exact eight-field shape inside the report.
  let cookie = &source["cookies"][0];
  assert_eq!(
    cookie
      .as_object()
      .expect("cookie object")
      .keys()
      .map(String::as_str)
      .collect::<Vec<_>>(),
    [
      "domain",
      "path",
      "secure",
      "expires",
      "name",
      "value",
      "http_only",
      "same_site"
    ]
  );
}
