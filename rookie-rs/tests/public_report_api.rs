//! Request and report semantics of the public generic API.
//!
//! These run against a synthetic home directory so a browser installed on the
//! host cannot decide whether an assertion passes. Discovery snapshots the
//! process environment, so every test here holds [`ENV_LOCK`] for its duration.

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
