//! CLI contract tests for the Section 5.8 list/report grammar.
//!
//! These cover only the additive `--list-browsers`, `--list-profiles`,
//! `--report`, and `--profile` modes plus the post-parse `--browser`
//! validation that replaced clap's closed `PossibleValuesParser`. The legacy
//! flat-output surface is pinned in `snapshot.rs`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const ROOKIE_BIN: &str = env!("CARGO_BIN_EXE_rookie-cookies");

/// Clap's exit code for a usage error. Post-parse mode validation must keep
/// using it now that `--browser` is no longer validated by clap itself.
const USAGE_ERROR_EXIT_CODE: i32 = 2;

/// The historical `BROWSERS_MAP` keys, in the `BTreeMap` order the invalid
/// `--browser` diagnostic renders them in.
#[cfg(target_os = "linux")]
const LEGACY_BROWSERS: &[&str] = &[
  "arc",
  "brave",
  "cachy",
  "chrome",
  "chromium",
  "edge",
  "firefox",
  "librewolf",
  "opera",
  "vivaldi",
  "zen",
];
#[cfg(target_os = "macos")]
const LEGACY_BROWSERS: &[&str] = &[
  "arc",
  "brave",
  "chrome",
  "chromium",
  "edge",
  "firefox",
  "librewolf",
  "opera",
  "opera_gx",
  "safari",
  "vivaldi",
  "zen",
];
#[cfg(target_os = "windows")]
const LEGACY_BROWSERS: &[&str] = &[
  "arc",
  "brave",
  "chrome",
  "chromium",
  "edge",
  "firefox",
  "internet_explorer",
  "librewolf",
  "octo_browser",
  "opera",
  "opera_gx",
  "vivaldi",
  "zen",
];
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
const LEGACY_BROWSERS: &[&str] = &[
  "arc",
  "brave",
  "chrome",
  "chromium",
  "edge",
  "firefox",
  "librewolf",
  "opera",
  "vivaldi",
  "zen",
];

struct TestDir(PathBuf);

impl TestDir {
  fn path(&self) -> &Path {
    &self.0
  }
}

impl Drop for TestDir {
  fn drop(&mut self) {
    let _ = std::fs::remove_dir_all(&self.0);
  }
}

fn unique_tmpdir(tag: &str) -> TestDir {
  static COUNTER: AtomicU64 = AtomicU64::new(0);
  let n = COUNTER.fetch_add(1, Ordering::SeqCst);
  let dir = std::env::temp_dir().join(format!(
    "rookie-cookies-cli-modes-{}-{}-{}",
    tag,
    std::process::id(),
    n
  ));
  std::fs::create_dir_all(&dir).expect("temp dir");
  TestDir(dir)
}

fn run_rookie(args: &[&str]) -> std::process::Output {
  Command::new(ROOKIE_BIN)
    .args(args)
    .env("RUST_LOG", "error")
    .output()
    .expect("spawn rookie-cookies")
}

/// A `rookie-cookies` invocation whose browser discovery is confined to `root`.
fn isolated_command(root: &Path) -> Command {
  let mut command = Command::new(ROOKIE_BIN);
  command.env("RUST_LOG", "error");
  #[cfg(unix)]
  command.env("HOME", root);
  #[cfg(target_os = "windows")]
  command
    .env("APPDATA", root)
    .env("LOCALAPPDATA", root)
    .env("USERPROFILE", root);
  command
}

fn run_isolated(root: &Path, args: &[&str]) -> std::process::Output {
  isolated_command(root)
    .args(args)
    .output()
    .expect("spawn rookie-cookies")
}

fn parsed_json(out: &std::process::Output) -> serde_json::Value {
  assert!(
    out.status.success(),
    "rookie-cookies exited non-zero: stdout={} stderr={}",
    String::from_utf8_lossy(&out.stdout),
    String::from_utf8_lossy(&out.stderr)
  );
  serde_json::from_slice(&out.stdout).unwrap_or_else(|err| {
    panic!(
      "CLI stdout must be valid JSON: {err}; stdout={} stderr={}",
      String::from_utf8_lossy(&out.stdout),
      String::from_utf8_lossy(&out.stderr)
    )
  })
}

/// Asserts a clap usage error: exit code 2, an `error:` diagnostic on stderr,
/// and no partial machine output on stdout.
fn assert_usage_error(out: &std::process::Output, context: &str) -> String {
  assert_eq!(
    out.status.code(),
    Some(USAGE_ERROR_EXIT_CODE),
    "{context}: unexpected exit code; stdout={} stderr={}",
    String::from_utf8_lossy(&out.stdout),
    String::from_utf8_lossy(&out.stderr)
  );
  assert!(
    out.stdout.is_empty(),
    "{context}: usage error wrote stdout: {}",
    String::from_utf8_lossy(&out.stdout)
  );
  let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
  assert!(
    stderr.contains("error:"),
    "{context}: missing clap diagnostic: {stderr}"
  );
  stderr
}

// (host, path, isSecure, expiry, name, value, isHttpOnly, sameSite)
type MozRow<'a> = (&'a str, &'a str, bool, u64, &'a str, &'a str, bool, i64);

fn seed_firefox_cookies(db: &Path, rows: &[MozRow<'_>]) {
  let conn = rusqlite::Connection::open(db).expect("open writable sqlite");
  conn
    .execute(
      "CREATE TABLE moz_cookies (
        host TEXT NOT NULL,
        path TEXT NOT NULL,
        isSecure INTEGER NOT NULL,
        expiry INTEGER NOT NULL,
        name TEXT NOT NULL,
        value TEXT NOT NULL,
        isHttpOnly INTEGER NOT NULL,
        sameSite INTEGER NOT NULL
      )",
      [],
    )
    .expect("create table");
  for r in rows {
    conn
      .execute(
        "INSERT INTO moz_cookies (host, path, isSecure, expiry, name, value, isHttpOnly, sameSite)
          VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![r.0, r.1, r.2, r.3, r.4, r.5, r.6, r.7],
      )
      .expect("insert row");
  }
}

/// Seeds a two-profile Firefox tree whose cookie values identify the profile
/// they came from, so profile selection is observable in the report.
fn seed_multi_profile_firefox(root: &Path) {
  #[cfg(target_os = "linux")]
  let firefox_root = root.join(".mozilla/firefox");
  #[cfg(target_os = "macos")]
  let firefox_root = root.join("Library/Application Support/Firefox");
  #[cfg(target_os = "windows")]
  let firefox_root = root.join("Mozilla/Firefox");

  for (dir, name, cookie) in [
    ("Profiles/rookie-a.default-release", "rookie-a", "from-a"),
    ("Profiles/rookie-b.secondary", "rookie-b", "from-b"),
  ] {
    let profile = firefox_root.join(dir);
    std::fs::create_dir_all(&profile).expect("create Firefox profile");
    seed_firefox_cookies(
      &profile.join("cookies.sqlite"),
      &[(
        ".example.com",
        "/",
        false,
        1_700_000_000,
        name,
        cookie,
        false,
        0,
      )],
    );
  }

  std::fs::write(
    firefox_root.join("profiles.ini"),
    "[Profile0]\nName=rookie-a\nIsRelative=1\n\
     Path=Profiles/rookie-a.default-release\nDefault=1\n\n\
     [Profile1]\nName=rookie-b\nIsRelative=1\n\
     Path=Profiles/rookie-b.secondary\n",
  )
  .expect("write profiles.ini");
}

fn registered_browsers() -> Vec<serde_json::Value> {
  let out = run_rookie(&["--list-browsers"]);
  parsed_json(&out)
    .as_array()
    .expect("--list-browsers must emit an array")
    .clone()
}

/// Every accepted `--browser` token in list/report mode: canonical IDs plus
/// their aliases.
fn registered_tokens() -> Vec<String> {
  let mut tokens = Vec::new();
  for browser in registered_browsers() {
    tokens.push(browser["id"].as_str().expect("browser id").to_string());
    for alias in browser["aliases"].as_array().expect("aliases") {
      tokens.push(alias.as_str().expect("alias").to_string());
    }
  }
  tokens
}

#[test]
fn list_browsers_emits_registered_descriptors_as_json() {
  let browsers = registered_browsers();
  assert!(
    !browsers.is_empty(),
    "no browsers are registered for this platform"
  );

  for browser in &browsers {
    for field in ["id", "aliases", "display_name", "engine", "capabilities"] {
      assert!(
        browser.get(field).is_some(),
        "descriptor is missing {field}: {browser}"
      );
    }
    for field in [
      "persistent_formats",
      "session_formats",
      "declared_decryption_tiers",
      "available_decryption_tiers",
    ] {
      assert!(
        browser["capabilities"].get(field).is_some(),
        "capabilities are missing {field}: {browser}"
      );
    }
  }

  let ids: Vec<&str> = browsers
    .iter()
    .map(|browser| browser["id"].as_str().expect("browser id"))
    .collect();
  assert!(ids.contains(&"firefox"), "{ids:?}");
  let mut unique = ids.clone();
  unique.sort_unstable();
  unique.dedup();
  assert_eq!(unique.len(), ids.len(), "duplicate browser IDs: {ids:?}");
}

#[test]
fn list_browsers_needs_no_installed_browser_and_touches_no_profile() {
  let root = unique_tmpdir("list-browsers-empty-home");
  let out = run_isolated(root.path(), &["--list-browsers"]);
  let browsers = parsed_json(&out);
  assert!(
    !browsers.as_array().expect("array").is_empty(),
    "registration must not depend on detection"
  );
}

#[test]
fn list_profiles_emits_every_discovered_profile() {
  let root = unique_tmpdir("list-profiles");
  seed_multi_profile_firefox(root.path());

  let out = run_isolated(root.path(), &["--list-profiles", "--browser", "firefox"]);
  let profiles = parsed_json(&out);
  let profiles = profiles.as_array().expect("profile array");
  assert_eq!(profiles.len(), 2, "{profiles:?}");

  let mut names: Vec<&str> = profiles
    .iter()
    .map(|profile| {
      profile["profile"]["display_name"]
        .as_str()
        .expect("display name")
    })
    .collect();
  names.sort_unstable();
  assert_eq!(names, ["rookie-a", "rookie-b"]);

  for profile in profiles {
    assert_eq!(profile["profile"]["browser_id"], "firefox");
    assert!(
      profile["profile"]["profile_id"]
        .as_str()
        .is_some_and(|id| !id.is_empty()),
      "profile is missing a selection key: {profile}"
    );
    assert!(profile.get("is_default").is_some(), "{profile}");
    assert!(profile["sources"].is_array(), "{profile}");
  }
}

#[test]
fn list_profiles_of_an_absent_browser_is_an_empty_array() {
  let root = unique_tmpdir("list-profiles-absent");
  let out = run_isolated(root.path(), &["--list-profiles", "--browser", "firefox"]);
  assert_eq!(parsed_json(&out), serde_json::json!([]));
}

#[test]
fn report_with_browser_covers_every_profile() {
  let root = unique_tmpdir("report-browser");
  seed_multi_profile_firefox(root.path());

  let out = run_isolated(root.path(), &["--report", "--browser", "firefox"]);
  let report = parsed_json(&out);
  assert_eq!(report["status"], "complete", "{report}");
  assert_eq!(report["summary"]["profiles_discovered"], 2, "{report}");
  assert_eq!(report["summary"]["cookies_emitted"], 2, "{report}");

  let mut cookie_names: Vec<&str> = report["profiles"]
    .as_array()
    .expect("profiles")
    .iter()
    .flat_map(|profile| profile["sources"].as_array().expect("sources"))
    .flat_map(|source| source["cookies"].as_array().expect("cookies"))
    .map(|cookie| cookie["name"].as_str().expect("cookie name"))
    .collect();
  cookie_names.sort_unstable();
  assert_eq!(cookie_names, ["rookie-a", "rookie-b"]);
}

#[test]
fn report_with_profile_selects_only_that_profile() {
  let root = unique_tmpdir("report-profile");
  seed_multi_profile_firefox(root.path());

  let listed = parsed_json(&run_isolated(
    root.path(),
    &["--list-profiles", "--browser", "firefox"],
  ));
  let wanted = listed
    .as_array()
    .expect("profiles")
    .iter()
    .find(|profile| profile["profile"]["display_name"] == "rookie-b")
    .expect("seeded secondary profile");
  let profile_id = wanted["profile"]["profile_id"]
    .as_str()
    .expect("profile id")
    .to_string();

  let out = run_isolated(
    root.path(),
    &["--report", "--browser", "firefox", "--profile", &profile_id],
  );
  let report = parsed_json(&out);
  let profiles = report["profiles"].as_array().expect("profiles");
  assert_eq!(profiles.len(), 1, "{report}");
  assert_eq!(profiles[0]["profile"]["profile_id"], profile_id.as_str());

  let cookie_names: Vec<&str> = profiles[0]["sources"]
    .as_array()
    .expect("sources")
    .iter()
    .flat_map(|source| source["cookies"].as_array().expect("cookies"))
    .map(|cookie| cookie["name"].as_str().expect("cookie name"))
    .collect();
  assert_eq!(cookie_names, ["rookie-b"]);
}

#[test]
fn report_with_an_unknown_profile_id_fails_without_machine_output() {
  let root = unique_tmpdir("report-unknown-profile");
  seed_multi_profile_firefox(root.path());

  let out = run_isolated(
    root.path(),
    &["--report", "--browser", "firefox", "--profile", "nope"],
  );
  assert!(!out.status.success(), "unknown profile ID succeeded");
  assert!(
    out.stdout.is_empty(),
    "failed report wrote partial machine output: {}",
    String::from_utf8_lossy(&out.stdout)
  );
}

#[test]
fn report_without_browser_uses_load_report() {
  let root = unique_tmpdir("report-load");
  seed_multi_profile_firefox(root.path());

  let out = run_isolated(root.path(), &["--report"]);
  let report = parsed_json(&out);

  let registered = registered_browsers().len() as u64;
  assert_eq!(
    report["summary"]["registered_browsers"].as_u64(),
    Some(registered),
    "load_report must cover every registered browser: {report}"
  );
  assert_eq!(report["summary"]["browsers_detected"], 1, "{report}");
  assert_eq!(report["summary"]["profiles_discovered"], 2, "{report}");
}

#[test]
fn report_domain_filter_narrows_the_emitted_cookies() {
  let root = unique_tmpdir("report-domains");
  seed_multi_profile_firefox(root.path());

  let matching = parsed_json(&run_isolated(
    root.path(),
    &[
      "--report",
      "--browser",
      "firefox",
      "--domains",
      "example.com",
    ],
  ));
  assert_eq!(matching["summary"]["cookies_emitted"], 2, "{matching}");

  let missing = parsed_json(&run_isolated(
    root.path(),
    &[
      "--report",
      "--browser",
      "firefox",
      "--domains",
      "absent.test",
    ],
  ));
  assert_eq!(missing["summary"]["cookies_emitted"], 0, "{missing}");
}

#[test]
fn report_and_list_modes_reject_netscape_format() {
  for args in [
    &["--list-browsers", "--format", "netscape"][..],
    &[
      "--list-profiles",
      "--browser",
      "firefox",
      "--format",
      "netscape",
    ][..],
    &["--report", "--format", "netscape"][..],
    &["--report", "--browser", "firefox", "--format", "netscape"][..],
  ] {
    let stderr = assert_usage_error(&run_rookie(args), &format!("{args:?}"));
    assert!(
      stderr.contains("--format netscape"),
      "{args:?}: unhelpful diagnostic: {stderr}"
    );
  }
}

#[test]
fn report_and_list_modes_accept_an_explicit_json_format() {
  for args in [
    &["--list-browsers", "--format", "json"][..],
    &[
      "--list-profiles",
      "--browser",
      "firefox",
      "--format",
      "json",
    ][..],
    &["--report", "--browser", "firefox", "--format", "json"][..],
  ] {
    let root = unique_tmpdir("explicit-json");
    let out = run_isolated(root.path(), args);
    assert!(
      out.status.success(),
      "{args:?} failed: {}",
      String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice::<serde_json::Value>(&out.stdout)
      .unwrap_or_else(|err| panic!("{args:?} emitted invalid JSON: {err}"));
  }
}

/// Clap evaluates conflicts before `requires`, so each declared pair can be
/// provoked on its own. Asserting that the diagnostic names *both* halves keeps
/// these honest: dropping one flag from a `conflicts_with_all` list fails here
/// rather than silently widening the grammar.
#[test]
fn profile_conflicts_with_each_list_mode_individually() {
  for (args, other) in [
    (
      &["--profile", "x", "--list-browsers"][..],
      "--list-browsers",
    ),
    (
      &["--profile", "x", "--list-profiles", "--browser", "firefox"][..],
      "--list-profiles",
    ),
  ] {
    let stderr = assert_usage_error(&run_rookie(args), &format!("{args:?}"));
    assert!(
      stderr.contains(&format!(
        "the argument '--profile <PROFILE>' cannot be used with '{other}'"
      )),
      "{args:?}: expected the --profile/{other} conflict: {stderr}"
    );
  }
}

#[test]
fn key_path_conflicts_with_each_new_mode_individually() {
  for (args, other) in [
    (
      &["--key-path", "ks", "--list-browsers"][..],
      "--list-browsers",
    ),
    // No `--browser` here: it conflicts with `--key-path` too, and a second
    // conflict switches clap to a multi-line rendering that would obscure the
    // pair under test.
    (
      &["--key-path", "ks", "--list-profiles"][..],
      "--list-profiles",
    ),
    (&["--key-path", "ks", "--report"][..], "--report"),
  ] {
    let stderr = assert_usage_error(&run_rookie(args), &format!("{args:?}"));
    assert!(
      stderr.contains(&format!(
        "the argument '--key-path <KEY_PATH>' cannot be used with '{other}'"
      )),
      "{args:?}: expected the --key-path/{other} conflict: {stderr}"
    );
  }
}

#[test]
fn new_modes_conflict_with_the_legacy_source_selectors() {
  for args in [
    &["--report", "--load"][..],
    &["--report", "--path", "cookies.sqlite"][..],
    &[
      "--report",
      "--path",
      "cookies.sqlite",
      "--key-path",
      "Local State",
    ][..],
    &["--list-browsers", "--load"][..],
    &["--list-browsers", "--path", "cookies.sqlite"][..],
    &["--list-profiles", "--browser", "firefox", "--load"][..],
    &[
      "--list-profiles",
      "--browser",
      "firefox",
      "--path",
      "cookies.sqlite",
    ][..],
  ] {
    assert_usage_error(&run_rookie(args), &format!("{args:?}"));
  }
}

#[test]
fn list_modes_conflict_with_domain_filters_and_each_other() {
  for args in [
    &["--list-browsers", "--domains", "example.com"][..],
    &[
      "--list-profiles",
      "--browser",
      "firefox",
      "--domains",
      "example.com",
    ][..],
    &["--list-browsers", "--browser", "firefox"][..],
    &["--list-browsers", "--list-profiles", "--browser", "firefox"][..],
    &["--list-browsers", "--report"][..],
    &["--list-profiles", "--browser", "firefox", "--report"][..],
  ] {
    assert_usage_error(&run_rookie(args), &format!("{args:?}"));
  }
}

#[test]
fn list_profiles_requires_a_browser() {
  let stderr = assert_usage_error(&run_rookie(&["--list-profiles"]), "--list-profiles");
  assert!(stderr.contains("--browser"), "{stderr}");
}

#[test]
fn profile_requires_both_report_and_browser() {
  for args in [
    &["--profile", "any"][..],
    &["--profile", "any", "--report"][..],
    &["--profile", "any", "--browser", "firefox"][..],
    &[
      "--profile",
      "any",
      "--list-profiles",
      "--browser",
      "firefox",
    ][..],
  ] {
    assert_usage_error(&run_rookie(args), &format!("{args:?}"));
  }
}

#[test]
fn invalid_legacy_browser_stays_a_usage_error_listing_the_legacy_set() {
  let stderr = assert_usage_error(&run_rookie(&["--browser", "nope"]), "--browser nope");
  assert!(
    stderr.contains("invalid value 'nope' for '--browser <BROWSER>'"),
    "{stderr}"
  );

  let rendered: Vec<String> = LEGACY_BROWSERS
    .iter()
    .map(|browser| {
      if browser.contains(char::is_whitespace) {
        format!("\"{browser}\"")
      } else {
        (*browser).to_string()
      }
    })
    .collect();
  assert!(
    stderr.contains(&format!("[possible values: {}]", rendered.join(", "))),
    "legacy browser values are not in deterministic order: {stderr}"
  );
}

#[test]
fn every_legacy_browser_key_is_still_accepted_without_a_new_mode() {
  let root = unique_tmpdir("legacy-keys-accepted");
  for browser in LEGACY_BROWSERS {
    let out = run_isolated(root.path(), &["--browser", browser]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
      !stderr.contains("invalid value") && !stderr.contains("only reachable through the registry"),
      "legacy key {browser} was rejected: {stderr}"
    );
  }
}

#[test]
fn a_registry_only_browser_without_report_points_at_report() {
  let legacy: Vec<&str> = LEGACY_BROWSERS.to_vec();
  let registry_only: Vec<String> = registered_tokens()
    .into_iter()
    .filter(|token| {
      !legacy.contains(&token.as_str())
        && !(legacy.contains(&"opera_gx") && matches!(token.as_str(), "opera gx" | "opera-gx"))
    })
    .collect();
  if registry_only.is_empty() {
    // Every registered ID on this platform is also a legacy key, so the
    // registry-only rejection has nothing to reject here.
    return;
  }

  for token in &registry_only {
    let stderr = assert_usage_error(&run_rookie(&["--browser", token]), token);
    assert!(
      stderr.contains("--report"),
      "{token}: diagnostic must point at --report: {stderr}"
    );

    // The same ID is accepted once a report mode is requested.
    let root = unique_tmpdir("registry-only-report");
    let out = run_isolated(root.path(), &["--report", "--browser", token]);
    assert!(
      out.status.success(),
      "{token} was rejected in report mode: {}",
      String::from_utf8_lossy(&out.stderr)
    );
  }
}

#[test]
fn report_mode_rejects_ids_that_are_not_registered() {
  let registered = registered_tokens();
  let legacy_only: Vec<&&str> = LEGACY_BROWSERS
    .iter()
    .filter(|browser| !registered.iter().any(|token| token == *browser))
    .collect();

  let mut rejected: Vec<String> = vec!["nope".to_string()];
  rejected.extend(legacy_only.iter().map(|browser| (**browser).to_string()));

  for token in &rejected {
    for args in [
      &["--report", "--browser", token][..],
      &["--list-profiles", "--browser", token][..],
    ] {
      let stderr = assert_usage_error(&run_rookie(args), &format!("{args:?}"));
      assert!(
        stderr.contains("--list-browsers"),
        "{args:?}: diagnostic must point at --list-browsers: {stderr}"
      );
    }
  }
}

#[test]
fn registry_only_browser_batch_is_reachable_when_registered() {
  let registered = registered_tokens();
  let root = unique_tmpdir("registry-only-batch");
  for browser in ["coccoc", "duckduckgo", "yandex"] {
    if registered.iter().any(|token| token == browser) {
      let report = parsed_json(&run_isolated(
        root.path(),
        &["--report", "--browser", browser],
      ));
      assert_eq!(report["status"], "no_sources", "{browser}");
    }
  }
}

#[test]
fn report_modes_keep_stdout_machine_readable_under_info_logging() {
  let root = unique_tmpdir("report-logging");
  seed_multi_profile_firefox(root.path());

  for args in [
    &["--list-browsers"][..],
    &["--list-profiles", "--browser", "firefox"][..],
    &["--report", "--browser", "firefox"][..],
  ] {
    let out = isolated_command(root.path())
      .args(args)
      .env("RUST_LOG", "info")
      .output()
      .expect("spawn rookie-cookies");
    let stdout = String::from_utf8(out.stdout.clone()).expect("utf-8 stdout");
    assert!(
      out.status.success(),
      "{args:?} failed: {}",
      String::from_utf8_lossy(&out.stderr)
    );
    assert!(
      !stdout.contains(" INFO ") && !stdout.contains(" WARN "),
      "{args:?}: log polluted stdout: {stdout}"
    );
    serde_json::from_str::<serde_json::Value>(&stdout)
      .unwrap_or_else(|err| panic!("{args:?} emitted invalid JSON: {err}"));
  }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
fn legacy_opera_gx_aliases_remain_accepted() {
  for selector in ["opera_gx", "opera-gx", "opera gx"] {
    let out = run_rookie(&["--browser", selector]);
    assert_ne!(out.status.code(), Some(USAGE_ERROR_EXIT_CODE), "{selector}");
  }
}

#[test]
fn version_still_wins_over_the_new_modes() {
  for args in [&["--version"][..], &["-v"][..]] {
    let out = run_rookie(args);
    assert!(out.status.success(), "{args:?}");
    let stdout = String::from_utf8(out.stdout).expect("utf-8 version");
    assert!(stdout.contains("CLI: "), "{stdout}");
  }

  // `--version` is exclusive, so pairing it with a new mode stays a usage error.
  assert_usage_error(
    &run_rookie(&["--version", "--list-browsers"]),
    "--version --list-browsers",
  );
}
