//! Request and report semantics of the public generic API.
//!
//! These run against a synthetic home directory so a browser installed on the
//! host cannot decide whether an assertion passes. Discovery snapshots the
//! process environment, so every test here holds [`ENV_LOCK`] for its duration.

#![allow(deprecated)]

use rookie_cookies::report::{
  ExtractionReport, IssueCode, IssueSeverityCode, ProfileDescriptor, ReportStatusCode,
  SourceStatusCode,
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

  fn firefox_root(&self) -> PathBuf {
    #[cfg(target_os = "macos")]
    return self.home.join("Library/Application Support/Firefox");
    #[cfg(target_os = "windows")]
    return self.home.join("AppData/Roaming/Mozilla/Firefox");
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    return self.home.join(".mozilla/firefox");
  }

  /// Chrome's real beta-channel root, a second installation root of the same
  /// browser, used to prove one failing root does not hide another.
  #[cfg(unix)]
  fn chrome_beta_root(&self) -> PathBuf {
    #[cfg(target_os = "macos")]
    return self
      .home
      .join("Library/Application Support/Google/Chrome Beta");
    #[cfg(not(target_os = "macos"))]
    return self.home.join(".config/google-chrome-beta");
  }
}

/// A directory that exists but cannot be enumerated, so discovery detects the
/// root and then fails to read it — the difference between "not installed" and
/// "installed and unreadable".
///
/// Restores the mode on drop, including on unwind, so the enclosing
/// [`SyntheticHome`] can still delete itself. Declare it *after* the
/// `SyntheticHome` it lives in: locals drop in reverse, so the mode is restored
/// before the removal runs.
#[cfg(unix)]
struct UnreadableDir(PathBuf);

#[cfg(unix)]
impl UnreadableDir {
  fn new(path: PathBuf) -> Self {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(&path).expect("create unreadable root");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
      .expect("deny access to the root");
    UnreadableDir(path)
  }
}

#[cfg(unix)]
impl Drop for UnreadableDir {
  fn drop(&mut self) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
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
fn seed_chromium_encrypted(root: &Path, profile: &str, name: &str, blob: &[u8]) {
  let database = root.join(profile).join("Network/Cookies");
  std::fs::create_dir_all(database.parent().expect("profile directory"))
    .expect("create profile directory");
  let connection = rusqlite::Connection::open(&database).expect("open cookie database");
  connection
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
        encrypted_value BLOB NOT NULL,
        is_httponly INTEGER NOT NULL,
        samesite INTEGER NOT NULL
      );",
    )
    .expect("create cookies table");
  connection
    .execute(
      "INSERT INTO cookies VALUES ('.example.test', '/', 0, 0, 'kept', 'plain', x'', 0, 0)",
      [],
    )
    .expect("insert plaintext cookie");
  connection
    .execute(
      "INSERT INTO cookies VALUES ('.example.test', '/', 0, 0, ?1, '', ?2, 0, 0)",
      rusqlite::params![name, blob],
    )
    .expect("insert encrypted cookie");
  std::fs::write(root.join("Local State"), b"{}").expect("write Local State");
}

fn seed_chromium_profile(root: &Path, profile: &str, name: &str, value: &str) {
  let database = root.join(profile).join("Network/Cookies");
  std::fs::create_dir_all(database.parent().expect("profile directory"))
    .expect("create profile directory");
  let connection = rusqlite::Connection::open(&database).expect("open cookie database");
  connection
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

fn seed_firefox_with_rejected_row(home: &SyntheticHome<'_>) {
  let root = home.firefox_root();
  let profile = root.join("Profiles/default");
  std::fs::create_dir_all(&profile).expect("create Firefox profile");
  std::fs::write(
    root.join("profiles.ini"),
    "[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/default\nDefault=1\n",
  )
  .expect("write profiles.ini");
  let connection =
    rusqlite::Connection::open(profile.join("cookies.sqlite")).expect("open Firefox database");
  connection
    .execute_batch(
      "PRAGMA user_version = 15;
       CREATE TABLE moz_cookies (
         host TEXT, path, isSecure, expiry, name TEXT, value TEXT,
         isHttpOnly, sameSite, originAttributes
       );
       INSERT INTO moz_cookies VALUES
         ('.example.test', '/', 0, 0, 'kept', 'value', 0, 0, '');
       INSERT INTO moz_cookies VALUES
         ('.example.test', '/', 0, 0, X'00ff', 'value', 0, 0, '');",
    )
    .expect("seed readable and rejected Firefox rows");
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
    error.to_string().contains("no chrome profile matches"),
    "unexpected message: {error:#}"
  );
  assert!(matches!(error, rookie_cookies::Error::Request(_)));

  // Listing stores canonicalized paths (`/private/var/...` on macOS). Query
  // with the path the listing itself published — that is the Path-eq key.
  let listed = rookie_cookies::browser_profiles("chrome").expect("listed seeded chrome");
  let listed_path = listed
    .iter()
    .find(|profile| profile.profile.path.ends_with("Default"))
    .expect("seeded Default profile")
    .profile
    .path
    .clone();
  let report = rookie_cookies::browser_report("chrome", Some(&listed_path), None)
    .expect("a non-lossy profile path is a selection key");
  assert_eq!(report.profiles.len(), 1);

  let cookie_db = listed
    .iter()
    .find(|profile| profile.profile.path == listed_path)
    .expect("Default still listed")
    .sources
    .iter()
    .find(|source| source.role.as_str() == "persistent")
    .expect("persistent Cookies source")
    .path
    .clone();
  let via_db = rookie_cookies::browser_report("chrome", Some(&cookie_db), None)
    .expect("a persistent cookie-DB path is a selection key");
  assert_eq!(via_db.profiles.len(), 1);
  let _ = home;
}

#[test]
fn extract_report_without_profile_matches_browser_report() {
  let _home = seeded_chrome("extract-report-eq");
  let via_report = rookie_cookies::browser_report("chrome", None, None).expect("report");
  let via_extract =
    rookie_cookies::extract_report(rookie_cookies::ReportRequest::browser("chrome"))
      .expect("extract_report");
  assert_eq!(via_report.status, via_extract.status);
  assert_eq!(via_report.profiles.len(), via_extract.profiles.len());
  assert_eq!(
    via_report.summary.cookies_emitted,
    via_extract.summary.cookies_emitted
  );
}

fn cookie_key(cookie: &rookie_cookies::enums::Cookie) -> (String, String, String, String) {
  (
    cookie.domain.clone(),
    cookie.path.clone(),
    cookie.name.clone(),
    cookie.value.clone(),
  )
}

#[test]
fn no_profile_extract_matches_chrome() {
  let _home = seeded_chrome("extract-eq-chrome");
  let via_chrome = rookie_cookies::chrome(None).expect("chrome");
  let via_extract =
    rookie_cookies::extract(rookie_cookies::ExtractRequest::browser("chrome")).expect("extract");
  let mut chrome_keys: Vec<_> = via_chrome.iter().map(cookie_key).collect();
  let mut extract_keys: Vec<_> = via_extract.iter().map(cookie_key).collect();
  chrome_keys.sort();
  extract_keys.sort();
  assert_eq!(chrome_keys, extract_keys);

  let via_read =
    rookie_cookies::read(rookie_cookies::ReadRequest::browser("chrome").include_expired(true))
      .expect("read");
  let mut read_keys: Vec<_> = via_read.cookies().iter().map(cookie_key).collect();
  read_keys.sort();
  assert_eq!(read_keys, chrome_keys);
}

#[test]
fn no_profile_read_reports_decrypt_failed_for_undecryptable_rows() {
  let home = SyntheticHome::new("read-decrypt");
  let mut blob = b"v10".to_vec();
  blob.extend_from_slice(&[0u8; 20]);
  seed_chromium_encrypted(&home.chrome_root(), "Default", "session", &blob);
  let result =
    rookie_cookies::read(rookie_cookies::ReadRequest::browser("chrome").include_expired(true))
      .expect("read");
  let warning = result
    .warnings()
    .iter()
    .find(|warning| warning.code() == "decrypt_failed")
    .expect("decrypt_failed");
  assert_eq!(warning.count(), 1);
  assert_eq!(result.cookies().len(), 1);
  assert_eq!(result.cookies()[0].name, "kept");

  let profile_id = rookie_cookies::profiles("chrome")
    .expect("profiles")
    .into_iter()
    .next()
    .expect("seeded profile")
    .profile
    .profile_id
    .to_string();
  let selected = rookie_cookies::read(
    rookie_cookies::ReadRequest::browser("chrome")
      .profile(profile_id)
      .include_expired(true),
  )
  .expect("profile read");
  assert_eq!(
    selected.warnings(),
    result.warnings(),
    "legacy and report-backed reads must project unseal loss identically"
  );
  let _ = home;
}

#[test]
fn gecko_row_loss_warning_matches_profile_and_no_profile_reads() {
  let home = SyntheticHome::new("read-gecko-row-loss");
  seed_firefox_with_rejected_row(&home);

  let compatibility =
    rookie_cookies::read(rookie_cookies::ReadRequest::browser("firefox").include_expired(true))
      .expect("no-profile Firefox read");
  let profile_id = rookie_cookies::profiles("firefox")
    .expect("profiles")
    .into_iter()
    .next()
    .expect("seeded profile")
    .profile
    .profile_id
    .to_string();
  let selected = rookie_cookies::read(
    rookie_cookies::ReadRequest::browser("firefox")
      .profile(profile_id)
      .include_expired(true),
  )
  .expect("profile Firefox read");

  assert_eq!(compatibility.cookies().len(), 1);
  assert_eq!(selected.cookies().len(), 1);
  assert_eq!(compatibility.warnings(), selected.warnings());
  assert_eq!(compatibility.warnings().len(), 1);
  assert_eq!(compatibility.warnings()[0].code(), "row_read_failed");
  assert_eq!(compatibility.warnings()[0].count(), 1);
  let _ = home;
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

  assert_eq!(report.issues.len(), 1);
  let issue = &report.issues[0];
  // Branch the way a consumer would, against the published vocabulary value
  // rather than a bare string.
  assert_eq!(issue.code, IssueCode::browser_not_detected());
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

  let registered = rookie_cookies::supported_browsers().expect("registered browser inventory");
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
  assert_eq!(report.summary.rows_rejected, 0);
  assert_eq!(report.summary.provider_failures, 0);
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
    assert_eq!(source.stats.rows_rejected, 0);
    assert_eq!(source.stats.provider_failures, 0);
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
  assert_eq!(wire["summary"]["rows_rejected"], 0);
  assert_eq!(wire["summary"]["provider_failures"], 0);
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

#[test]
fn reports_round_trip_through_the_wire_format() {
  let _home = seeded_chrome("chrome-round-trip");

  let report = rookie_cookies::browser_report("chrome", None, None).expect("chrome report");
  // Guard against a vacuous pass: the comparisons below are per-element loops,
  // so an empty report would satisfy every one of them.
  assert_eq!(report.profiles.len(), 2);
  assert!(report.profiles.iter().all(|profile| profile
    .sources
    .iter()
    .any(|source| !source.cookies.is_empty())));

  let encoded = serde_json::to_string(&report).expect("serialize report");
  let restored: ExtractionReport = serde_json::from_str(&encoded).expect("deserialize report");

  // Typed fields must come back as their newtypes, not degrade to strings.
  assert_eq!(restored.status, report.status);
  assert_eq!(restored.summary, report.summary);
  assert_eq!(restored.issues, report.issues);
  assert_eq!(restored.profiles.len(), report.profiles.len());

  for (original, restored) in report.profiles.iter().zip(&restored.profiles) {
    assert_eq!(restored.profile, original.profile);
    assert_eq!(restored.stats, original.stats);
    assert_eq!(restored.issues, original.issues);
    assert_eq!(restored.sources.len(), original.sources.len());

    for (original, restored) in original.sources.iter().zip(&restored.sources) {
      assert_eq!(restored.source, original.source);
      assert_eq!(restored.status, original.status);
      assert_eq!(restored.selected, original.selected);
      assert_eq!(restored.acquisition_strategy, original.acquisition_strategy);
      assert_eq!(restored.stats, original.stats);
      assert_eq!(restored.issues, original.issues);
      // `Cookie` has no `PartialEq` and this milestone does not widen it, so
      // compare the eight fields the wire format actually carries.
      assert_eq!(restored.cookies.len(), original.cookies.len());
      for (original, restored) in original.cookies.iter().zip(&restored.cookies) {
        assert_eq!(restored.domain, original.domain);
        assert_eq!(restored.path, original.path);
        assert_eq!(restored.secure, original.secure);
        assert_eq!(restored.expires, original.expires);
        assert_eq!(restored.name, original.name);
        assert_eq!(restored.value, original.value);
        assert_eq!(restored.http_only, original.http_only);
        assert_eq!(restored.same_site, original.same_site);
      }
    }
  }

  // Nothing the wire format exposes is dropped on the way back in.
  assert_eq!(
    serde_json::to_value(&restored).expect("reserialize"),
    serde_json::to_value(&report).expect("serialize")
  );
}

#[test]
fn the_wire_format_validates_identifiers_on_the_way_in() {
  let _home = seeded_chrome("chrome-wire-validation");

  let report = rookie_cookies::browser_report("chrome", None, None).expect("chrome report");
  let wire = serde_json::to_value(&report).expect("serialize report");

  // An open vocabulary still has a grammar: a decoded report cannot carry a
  // code that `FromStr` would have rejected.
  let mut tampered = wire.clone();
  tampered["status"] = serde_json::json!("Not A Status");
  assert!(
    serde_json::from_value::<ExtractionReport>(tampered).is_err(),
    "a malformed open identifier must not decode"
  );

  // Opaque IDs are selection keys, so a truncated digest must not decode into
  // something a caller would then pass back to `browser_report`.
  let mut tampered = wire.clone();
  tampered["profiles"][0]["profile"]["profile_id"] = serde_json::json!("short");
  assert!(
    serde_json::from_value::<ExtractionReport>(tampered).is_err(),
    "a malformed opaque identifier must not decode"
  );

  // A code this build never emits is not malformed; it is the open vocabulary
  // working as intended.
  let mut extended = wire;
  extended["status"] = serde_json::json!("future_status");
  let decoded =
    serde_json::from_value::<ExtractionReport>(extended).expect("unknown codes stay representable");
  assert_eq!(decoded.status.as_str(), "future_status");
}

/// A root that exists but denies enumeration is only reproducible through real
/// filesystem permissions, which Windows does not model the same way. The
/// engine-level equivalents are covered by `registry.rs` on every platform.
#[cfg(unix)]
#[test]
fn one_failing_root_does_not_hide_the_profiles_another_root_yields() {
  let home = SyntheticHome::new("chrome-partial-roots");
  seed_chromium_profile(&home.chrome_beta_root(), "Default", "session", "beta-value");
  let _denied = UnreadableDir::new(home.chrome_root());

  let profiles =
    rookie_cookies::browser_profiles("chrome").expect("a readable root still yields its profiles");
  assert_eq!(profiles.len(), 1);
  assert!(is_opaque_id(profiles[0].profile.profile_id.as_str()));

  // The same run through the report keeps the surviving cookie *and* names the
  // root that failed, which is the diagnostic `browser_profiles` cannot carry.
  let report = rookie_cookies::browser_report("chrome", None, None).expect("chrome report");
  assert_eq!(report.status, ReportStatusCode::partial());
  assert_eq!(report.summary.cookies_emitted, 1);
  assert_eq!(report.profiles.len(), 1);
  assert_eq!(report.profiles[0].sources[0].cookies[0].value, "beta-value");
  assert!(
    !error_issues(&report).is_empty(),
    "the unreadable root must surface as an error-severity issue"
  );
}

#[cfg(unix)]
#[test]
fn every_root_failing_enumeration_is_an_error_not_an_empty_profile_list() {
  let home = SyntheticHome::new("chrome-all-roots-fail");
  let _denied = UnreadableDir::new(home.chrome_root());

  let error = rookie_cookies::browser_profiles("chrome")
    .expect_err("an unreadable installation must not look like an absent one");
  assert!(
    error.to_string().contains("failed profile enumeration"),
    "unexpected message: {error:#}"
  );
}

#[cfg(unix)]
#[test]
fn a_detected_installation_whose_roots_all_fail_reports_failed() {
  let home = SyntheticHome::new("chrome-failed-status");
  let _denied = UnreadableDir::new(home.chrome_root());

  // The bare listing errors, but the report is still a report: a discovery
  // failure is not a bad request.
  let report = rookie_cookies::browser_report("chrome", None, None)
    .expect("a discovery failure is reported, not returned as a request error");
  assert_eq!(report.status, ReportStatusCode::failed());
  assert!(report.profiles.is_empty());
  assert_eq!(report.summary.sources_succeeded, 0);
  assert!(
    !error_issues(&report).is_empty(),
    "a failed report must say why"
  );
}

/// Seeds a Chromium profile whose one cookie is CHIPS-partitioned.
///
/// The `top_frame_site_key` column is optional in the Chromium schema, so a
/// fixture that omits it cannot tell a snapshot that preserves isolation from
/// one that discards it.
fn seed_partitioned_chromium_profile(root: &Path, profile: &str, partition: &str) {
  let database = root.join(profile).join("Network/Cookies");
  std::fs::create_dir_all(database.parent().expect("profile directory"))
    .expect("create profile directory");
  let connection = rusqlite::Connection::open(&database).expect("open cookie database");
  connection
    .execute_batch(
      "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
      INSERT INTO meta (key, value) VALUES ('version', '24');
      CREATE TABLE cookies (
        host_key TEXT NOT NULL,
        path TEXT NOT NULL,
        is_secure INTEGER NOT NULL,
        expires_utc INTEGER NOT NULL,
        name TEXT NOT NULL,
        value TEXT NOT NULL,
        encrypted_value BLOB NOT NULL,
        is_httponly INTEGER NOT NULL,
        samesite INTEGER NOT NULL,
        top_frame_site_key TEXT NOT NULL,
        has_cross_site_ancestor INTEGER NOT NULL
      );",
    )
    .expect("create cookies table");
  connection
    .execute(
      "INSERT INTO cookies VALUES ('.example.test', '/', 0, 0, 'chips', 'partitioned', ?1, 0, 0, ?2, 1)",
      rusqlite::params![Vec::<u8>::new(), partition],
    )
    .expect("insert partitioned cookie");
  std::fs::write(root.join("Local State"), b"{}").expect("write Local State");
}

/// The load-bearing snapshot-seam test.
///
/// A profile-scoped `read` used to route through the report builder, whose DTO
/// carries the eight-field `Cookie` — so isolation was already gone before the
/// job could return it. A test that only covered the no-profile path passes
/// against that broken implementation, because the legacy route never went
/// through the report at all. This one asserts the `Query` path.
#[test]
fn a_profile_scoped_snapshot_keeps_the_partition_key() {
  let home = SyntheticHome::new("snapshot-isolation");
  seed_partitioned_chromium_profile(&home.chrome_root(), "Default", "https://top.example");

  let profiles = rookie_cookies::browser_profiles("chrome").expect("listed seeded chrome");
  let profile_id = profiles
    .iter()
    .find(|profile| profile.profile.path.ends_with("Default"))
    .expect("seeded Default profile")
    .profile
    .profile_id
    .to_string();

  let snapshot = rookie_cookies::read(
    rookie_cookies::ReadRequest::browser("chrome")
      .profile(&profile_id)
      .include_expired(true),
  )
  .expect("profile-scoped snapshot");

  assert_eq!(snapshot.profile_id(), Some(profile_id.as_str()));
  let detailed = snapshot
    .detailed_cookies()
    .iter()
    .find(|detailed| detailed.cookie.name == "chips")
    .expect("the seeded partitioned cookie");
  assert_eq!(
    detailed.context.top_frame_site_key.as_deref(),
    Some("https://top.example"),
    "a profile-scoped snapshot must not lose the CHIPS partition key"
  );
  assert_eq!(detailed.context.has_cross_site_ancestor, Some(true));
  assert_ne!(
    detailed.context,
    rookie_cookies::enums::CookieContext::default(),
    "a default context is exactly what the report route produced"
  );

  // The eight-field projection is still there, and still discards isolation.
  assert!(snapshot
    .cookies()
    .iter()
    .any(|cookie| cookie.name == "chips"));
}

#[test]
fn a_legacy_first_snapshot_keeps_the_partition_key_too() {
  let home = SyntheticHome::new("snapshot-isolation-legacy");
  seed_partitioned_chromium_profile(&home.chrome_root(), "Default", "https://top.example");

  let snapshot =
    rookie_cookies::read(rookie_cookies::ReadRequest::browser("chrome").include_expired(true))
      .expect("legacy-first snapshot");
  assert_eq!(snapshot.browser_id(), Some("chrome"));
  assert_eq!(snapshot.profile_id(), None);
  let detailed = snapshot
    .detailed_cookies()
    .iter()
    .find(|detailed| detailed.cookie.name == "chips")
    .expect("the seeded partitioned cookie");
  assert_eq!(
    detailed.context.top_frame_site_key.as_deref(),
    Some("https://top.example")
  );
}

#[test]
fn a_direct_path_snapshot_keeps_isolation_and_has_no_browser_id() {
  let home = SyntheticHome::new("snapshot-isolation-path");
  let root = home.chrome_root();
  seed_partitioned_chromium_profile(&root, "Default", "https://top.example");

  let snapshot = rookie_cookies::from_path(
    rookie_cookies::FromPathRequest::new(root.join("Default/Network/Cookies"))
      .chromium_credentials(rookie_cookies::direct_path::ChromiumCredentialSource::PlaintextOnly)
      .include_expired(true),
  )
  .expect("direct-path snapshot");

  assert_eq!(
    snapshot.browser_id(),
    None,
    "from_path does not pass through browser discovery"
  );
  assert_eq!(snapshot.profile_id(), None);
  let detailed = snapshot
    .detailed_cookies()
    .iter()
    .find(|detailed| detailed.cookie.name == "chips")
    .expect("the seeded partitioned cookie");
  assert_eq!(
    detailed.context.top_frame_site_key.as_deref(),
    Some("https://top.example")
  );
}

/// A7: a row whose required host identity did not survive decode is omitted
/// from the inventory and counted, rather than emitted as `domain: ""`.
#[test]
fn a_row_with_an_empty_host_is_omitted_with_its_own_warning() {
  let home = SyntheticHome::new("snapshot-malformed-host");
  let root = home.chrome_root();
  let database = root.join("Default/Network/Cookies");
  std::fs::create_dir_all(database.parent().expect("profile directory"))
    .expect("create profile directory");
  let connection = rusqlite::Connection::open(&database).expect("open cookie database");
  connection
    .execute_batch(
      "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
      INSERT INTO meta (key, value) VALUES ('version', '23');
      CREATE TABLE cookies (
        host_key TEXT NOT NULL, path TEXT NOT NULL, is_secure INTEGER NOT NULL,
        expires_utc INTEGER NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
        encrypted_value BLOB NOT NULL, is_httponly INTEGER NOT NULL,
        samesite INTEGER NOT NULL
      );",
    )
    .expect("create cookies table");
  connection
    .execute(
      "INSERT INTO cookies VALUES ('', '/', 0, 0, 'hostless', 'value', ?1, 0, 0)",
      rusqlite::params![Vec::<u8>::new()],
    )
    .expect("insert hostless cookie");
  connection
    .execute(
      "INSERT INTO cookies VALUES ('.example.test', '/', 0, 0, 'kept', 'value', ?1, 0, 0)",
      rusqlite::params![Vec::<u8>::new()],
    )
    .expect("insert well-formed cookie");
  drop(connection);
  std::fs::write(root.join("Local State"), b"{}").expect("write Local State");

  let snapshot =
    rookie_cookies::read(rookie_cookies::ReadRequest::browser("chrome").include_expired(true))
      .expect("snapshot");
  assert!(
    snapshot
      .cookies()
      .iter()
      .all(|cookie| !cookie.domain.is_empty()),
    "a malformed host must never reach the inventory as an empty domain"
  );
  assert!(snapshot
    .cookies()
    .iter()
    .any(|cookie| cookie.name == "kept"));
  let warning = snapshot
    .warnings()
    .iter()
    .find(|warning| warning.code() == "malformed_host_identity")
    .expect("the omission is counted, not silent");
  assert_eq!(warning.count(), 1);
}

/// PR 5's agreement test: one target, two shapes, the same profile.
///
/// 0.6-beta could not state this. One `Request` value meant "the first
/// legacy-eligible profile" to `extract` and "every profile" to
/// `extract_report`, so the two calls below would have described different
/// profile sets while looking identical.
#[test]
fn an_extract_request_narrows_to_a_report_of_the_same_profile() {
  let _home = seeded_chrome("extract-to-report");

  let extract_request = rookie_cookies::ExtractRequest::browser("chrome");
  let report =
    rookie_cookies::extract_report(rookie_cookies::ReportRequest::from(extract_request.clone()))
      .expect("narrowed report");
  assert_eq!(
    report.profiles.len(),
    1,
    "converting an extract request narrows to its one profile, never widens to all"
  );

  // ...and the report of the same browser without a conversion is still all
  // profiles, which is what `browser_report(id, None, ..)` has always meant.
  let all = rookie_cookies::extract_report(rookie_cookies::ReportRequest::browser("chrome"))
    .expect("all-profiles report");
  assert_eq!(all.profiles.len(), 2);

  let flat = rookie_cookies::extract(extract_request).expect("flat extract");
  assert!(!flat.is_empty());
}

#[test]
fn an_empty_browser_id_is_missing_browser_on_every_browser_job() {
  for code in [
    rookie_cookies::read(rookie_cookies::ReadRequest::browser(""))
      .expect_err("read")
      .code(),
    rookie_cookies::extract(rookie_cookies::ExtractRequest::browser(""))
      .expect_err("extract")
      .code(),
    rookie_cookies::extract_report(rookie_cookies::ReportRequest::browser(""))
      .expect_err("extract_report")
      .code(),
  ] {
    assert_eq!(code, "missing_browser");
  }
}

/// A snapshot has nowhere to put "every source failed", so it must not answer
/// that with an empty list.
///
/// The route this replaced (`flatten_selected_report_cookies`) made the same
/// distinction; losing it here would turn a total failure into a silent
/// success on the path the migration guide recommends.
#[test]
fn a_profile_whose_only_source_fails_is_an_error_not_an_empty_snapshot() {
  let home = SyntheticHome::new("snapshot-total-failure");
  let root = home.chrome_root();
  seed_chromium_profile(&root, "Default", "session", "value");

  // Corrupt the database after discovery has a valid file to find, so the
  // profile is discovered and its one selected source then fails to read.
  let database = root.join("Default/Network/Cookies");
  let profiles = rookie_cookies::browser_profiles("chrome").expect("listed seeded chrome");
  let profile_id = profiles
    .iter()
    .find(|profile| profile.profile.path.ends_with("Default"))
    .expect("seeded Default profile")
    .profile
    .profile_id
    .to_string();
  std::fs::write(&database, b"SQLite format 3\0definitely not a database")
    .expect("corrupt the seeded database");

  let error =
    rookie_cookies::read(rookie_cookies::ReadRequest::browser("chrome").profile(&profile_id))
      .expect_err("a snapshot cannot report a total failure as an empty list");
  assert!(
    matches!(error, rookie_cookies::Error::Engine(_)),
    "expected an engine failure, got {error:?}"
  );
  assert!(
    matches!(error.code(), "source_extraction_failed"),
    "unexpected code {}",
    error.code()
  );
}

/// A7 reaches the report too, as a source issue rather than a warning.
///
/// A report has a channel for the loss; `extract` inherits the omission and
/// not the count, because a bare `Vec<Cookie>` has nowhere to put it. Both are
/// better than emitting `domain: ""`, which matches nothing and belongs to no
/// site.
#[test]
fn a_report_omits_an_empty_host_row_and_records_it_as_a_source_issue() {
  let home = SyntheticHome::new("report-malformed-host");
  let root = home.chrome_root();
  let database = root.join("Default/Network/Cookies");
  std::fs::create_dir_all(database.parent().expect("profile directory"))
    .expect("create profile directory");
  let connection = rusqlite::Connection::open(&database).expect("open cookie database");
  connection
    .execute_batch(
      "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
      INSERT INTO meta (key, value) VALUES ('version', '23');
      CREATE TABLE cookies (
        host_key TEXT NOT NULL, path TEXT NOT NULL, is_secure INTEGER NOT NULL,
        expires_utc INTEGER NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
        encrypted_value BLOB NOT NULL, is_httponly INTEGER NOT NULL,
        samesite INTEGER NOT NULL
      );
      INSERT INTO cookies VALUES ('', '/', 0, 0, 'hostless', 'v', X'', 0, 0);
      INSERT INTO cookies VALUES ('.example.test', '/', 0, 0, 'kept', 'v', X'', 0, 0);",
    )
    .expect("seed cookies");
  drop(connection);
  std::fs::write(root.join("Local State"), b"{}").expect("write Local State");

  let report =
    rookie_cookies::browser_report("chrome", None, None).expect("report the seeded profile");
  let source = report
    .profiles
    .iter()
    .flat_map(|profile| profile.sources.iter())
    .find(|source| source.cookies.iter().any(|cookie| cookie.name == "kept"))
    .expect("the seeded source");
  assert!(
    source
      .cookies
      .iter()
      .all(|cookie| !cookie.domain.is_empty()),
    "a malformed host must never reach the report as an empty domain"
  );
  let issue = source
    .issues
    .iter()
    .find(|issue| issue.code.as_str() == "malformed_host_identity")
    .expect("the omission is recorded, not silent");
  assert_eq!(issue.occurrences, 1);

  // A7 omits the row at projection time, after the engine already counted it
  // as emitted, so the counters have to be reconciled or the invariant the
  // schema promises silently breaks on exactly the sources this feature
  // touches.
  assert_eq!(
    source.stats.cookies_emitted as usize,
    source.cookies.len(),
    "cookies_emitted must match the rows that survived the omission"
  );
  assert!(source.stats.rows_seen >= source.stats.rows_skipped);
  assert_eq!(
    source.stats.rows_seen - source.stats.rows_skipped,
    source.stats.cookies_emitted,
    "rows_seen - rows_skipped == cookies_emitted"
  );
  assert!(
    source.stats.rows_rejected >= 1,
    "a host that did not survive decode is a rejected row"
  );

  let profile = report
    .profiles
    .iter()
    .find(|profile| {
      profile
        .sources
        .iter()
        .any(|source| source.cookies.iter().any(|cookie| cookie.name == "kept"))
    })
    .expect("the seeded profile");
  assert!(profile.stats.rows_seen >= profile.stats.rows_skipped);
  assert_eq!(
    profile.stats.rows_seen - profile.stats.rows_skipped,
    profile.stats.cookies_emitted,
    "the profile aggregate inherits the reconciled source counters"
  );

  // `extract` flattens the same projection: same omission, no channel to
  // report the count through.
  let flat = rookie_cookies::extract(rookie_cookies::ExtractRequest::browser("chrome"))
    .expect("flat extract");
  assert!(flat.iter().all(|cookie| !cookie.domain.is_empty()));
  assert!(flat.iter().any(|cookie| cookie.name == "kept"));
}
