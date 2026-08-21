//! CLI contract tests for the structured-output job subcommands
//! (`browsers`, `profiles`, `report`) plus cross-subcommand usage-error
//! shape checks (`read`/`from-path`/`header`'s own required-flag and
//! conflicting-selector grammar). Flat/detailed extraction output is pinned
//! in `snapshot.rs`.
//!
//! The CLI used to also expose this grammar through a parallel top-level
//! flag surface (`--list-browsers`, `--list-profiles`, `--report`,
//! `--browser`, `--load`, `--path`, ...); that surface, and the legacy
//! `--browser` map it depended on, were removed once every job became a
//! subcommand (0.6.0 design PR 6/7). There is no longer a no-subcommand
//! default action.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const ROOKIE_BIN: &str = env!("CARGO_BIN_EXE_rookie-cookies");

/// Clap's exit code for a usage error.
const USAGE_ERROR_EXIT_CODE: i32 = 2;

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
  let out = run_rookie(&["browsers"]);
  parsed_json(&out)
    .as_array()
    .expect("browsers must emit an array")
    .clone()
}

#[test]
fn browsers_subcommand_emits_registered_descriptors_as_json() {
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
fn browsers_subcommand_needs_no_installed_browser_and_touches_no_profile() {
  let root = unique_tmpdir("list-browsers-empty-home");
  let out = run_isolated(root.path(), &["browsers"]);
  let browsers = parsed_json(&out);
  assert!(
    !browsers.as_array().expect("array").is_empty(),
    "registration must not depend on detection"
  );
}

#[test]
fn profiles_subcommand_emits_every_discovered_profile() {
  let root = unique_tmpdir("list-profiles");
  seed_multi_profile_firefox(root.path());

  let out = run_isolated(root.path(), &["profiles", "firefox"]);
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
fn profiles_subcommand_of_an_absent_browser_is_an_empty_array() {
  let root = unique_tmpdir("list-profiles-absent");
  let out = run_isolated(root.path(), &["profiles", "firefox"]);
  assert_eq!(parsed_json(&out), serde_json::json!([]));
}

#[test]
fn profiles_subcommand_requires_a_browser() {
  let stderr = assert_usage_error(&run_rookie(&["profiles"]), "profiles without a browser");
  assert!(
    stderr.contains("BROWSER") || stderr.contains("required"),
    "{stderr}"
  );
}

#[test]
fn report_with_browser_covers_every_profile() {
  let root = unique_tmpdir("report-browser");
  seed_multi_profile_firefox(root.path());

  let out = run_isolated(root.path(), &["report", "--browser", "firefox"]);
  let report = parsed_json(&out);
  assert_eq!(report["status"], "complete", "{report}");
  assert_eq!(report["summary"]["profiles_discovered"], 2, "{report}");
  assert_eq!(report["summary"]["cookies_emitted"], 2, "{report}");
  assert_eq!(report["summary"]["rows_rejected"], 0, "{report}");
  assert_eq!(report["summary"]["provider_failures"], 0, "{report}");
  for profile in report["profiles"].as_array().expect("profiles") {
    for source in profile["sources"].as_array().expect("sources") {
      assert!(source["stats"]["rows_rejected"].is_u64(), "{source}");
      assert!(source["stats"]["provider_failures"].is_u64(), "{source}");
    }
  }

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

  let listed = parsed_json(&run_isolated(root.path(), &["profiles", "firefox"]));
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
    &["report", "--browser", "firefox", "--profile", &profile_id],
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
    &["report", "--browser", "firefox", "--profile", "nope"],
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

  let out = run_isolated(root.path(), &["report"]);
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
    &["report", "--browser", "firefox", "--domains", "example.com"],
  ));
  assert_eq!(matching["summary"]["cookies_emitted"], 2, "{matching}");

  let missing = parsed_json(&run_isolated(
    root.path(),
    &["report", "--browser", "firefox", "--domains", "absent.test"],
  ));
  assert_eq!(missing["summary"]["cookies_emitted"], 0, "{missing}");
}

#[test]
fn report_with_unregistered_browser_fails_with_a_core_error() {
  // Unlike the removed top-level `--browser` flag, no CLI-side registry
  // pre-check exists for subcommands: an unknown ID reaches
  // `rookie_cookies::Error::Request(RequestError::UnknownBrowser)` and fails
  // at runtime (exit 1), not clap usage validation (exit 2).
  let root = unique_tmpdir("report-unregistered");
  let out = run_isolated(
    root.path(),
    &["report", "--browser", "definitely-not-a-real-browser"],
  );
  assert!(
    !out.status.success(),
    "unregistered browser id unexpectedly succeeded"
  );
  assert!(
    out.stdout.is_empty(),
    "failed report wrote partial machine output: {}",
    String::from_utf8_lossy(&out.stdout)
  );
}

#[test]
fn registry_only_browser_batch_is_reachable_when_registered() {
  let registered = registered_browsers();
  let ids: Vec<&str> = registered
    .iter()
    .map(|browser| browser["id"].as_str().expect("browser id"))
    .collect();
  let root = unique_tmpdir("registry-only-batch");
  for browser in ["coccoc", "duckduckgo", "yandex"] {
    if ids.contains(&browser) {
      let report = parsed_json(&run_isolated(
        root.path(),
        &["report", "--browser", browser],
      ));
      assert_eq!(report["status"], "no_sources", "{browser}");
    }
  }
}

#[test]
fn structured_subcommands_keep_stdout_machine_readable_under_info_logging() {
  let root = unique_tmpdir("report-logging");
  seed_multi_profile_firefox(root.path());

  for args in [
    &["browsers"][..],
    &["profiles", "firefox"][..],
    &["report", "--browser", "firefox"][..],
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

#[test]
fn version_stays_exclusive_of_subcommands() {
  for args in [&["--version"][..], &["-v"][..]] {
    let out = run_rookie(args);
    assert!(out.status.success(), "{args:?}");
    let stdout = String::from_utf8(out.stdout).expect("utf-8 version");
    assert!(stdout.contains("CLI: "), "{stdout}");
  }

  assert_usage_error(
    &run_rookie(&["--version", "browsers"]),
    "--version browsers",
  );
}

#[test]
fn no_arguments_is_a_usage_error_naming_the_subcommands() {
  let stderr = assert_usage_error(&run_rookie(&[]), "no arguments");
  assert!(stderr.contains("subcommand"), "{stderr}");
}

#[test]
fn read_subcommand_requires_browser() {
  let stderr = assert_usage_error(&run_rookie(&["read"]), "read without -b");
  assert!(
    stderr.contains("--browser") || stderr.contains("-b"),
    "{stderr}"
  );
}

#[test]
fn profiles_subcommand_lists_json() {
  let root = unique_tmpdir("job-profiles");
  let out = run_isolated(root.path(), &["profiles", "chrome"]);
  let value = parsed_json(&out);
  assert!(value.is_array(), "{value}");
}

#[test]
fn from_path_subcommand_rejects_every_credential_selector_conflict() {
  for args in [
    &[
      "from-path",
      "missing.sqlite",
      "--local-state-path",
      "Local State",
      "--browser-id",
      "chrome",
    ][..],
    &[
      "from-path",
      "missing.sqlite",
      "--local-state-path",
      "Local State",
      "--plaintext-only",
    ][..],
    &[
      "from-path",
      "missing.sqlite",
      "--browser-id",
      "chrome",
      "--plaintext-only",
    ][..],
    &[
      "from-path",
      "missing.sqlite",
      "--local-state-path",
      "Local State",
      "--browser-id",
      "chrome",
      "--plaintext-only",
    ][..],
  ] {
    let stderr = assert_usage_error(&run_rookie(args), &format!("{args:?}"));
    assert!(
      stderr.contains("cannot be used with"),
      "credential conflict reached extraction instead of clap validation: {stderr}"
    );
  }
}

#[test]
fn from_path_detailed_format_rejects_domains() {
  // This is a CLI-level dispatch rejection (a plain `io::Error`, printed and
  // exited like every other typed error -- exit 1), not a clap declarative
  // conflict: `--format`'s allowed values don't depend on `--domains`, so it
  // can't be expressed with `conflicts_with`.
  let out = run_rookie(&[
    "from-path",
    "missing.sqlite",
    "--format",
    "detailed",
    "--domains",
    "example.com",
  ]);
  assert_eq!(
    out.status.code(),
    Some(1),
    "stdout={} stderr={}",
    String::from_utf8_lossy(&out.stdout),
    String::from_utf8_lossy(&out.stderr)
  );
  assert!(out.stdout.is_empty(), "rejected request wrote stdout");
  let stderr = String::from_utf8_lossy(&out.stderr);
  assert!(
    stderr.contains("detailed") && stderr.contains("--domains"),
    "{stderr}"
  );
}

#[test]
fn header_subcommand_requires_browser() {
  let stderr = assert_usage_error(
    &run_rookie(&["header", "--url", "https://example.com/"]),
    "header without -b",
  );
  assert!(
    stderr.contains("--browser") || stderr.contains("-b"),
    "{stderr}"
  );
}

#[test]
fn read_select_all_is_a_request_error_not_a_usage_error() {
  // `read`'s `ProfileSelection` has no "every profile" arm at all -- unlike
  // `report`, `--select all` is rejected outright here, not only when
  // combined with `--profile`.
  let root = unique_tmpdir("read-select-all");
  seed_multi_profile_firefox(root.path());

  let out = run_isolated(
    root.path(),
    &["read", "--browser", "firefox", "--select", "all"],
  );
  assert_eq!(
    out.status.code(),
    Some(1),
    "must be a typed core error (exit 1), not a clap usage error (exit 2): stderr={}",
    String::from_utf8_lossy(&out.stderr)
  );
  assert!(out.stdout.is_empty(), "rejected request wrote stdout");
  let stderr = String::from_utf8_lossy(&out.stderr);
  assert!(
    stderr.contains("profile and select"),
    "missing conflicting_profile_selection diagnostic: {stderr}"
  );
}

#[test]
fn report_profile_and_select_all_conflict_is_a_request_error() {
  let root = unique_tmpdir("report-select-all-conflict");
  seed_multi_profile_firefox(root.path());

  let out = run_isolated(
    root.path(),
    &[
      "report",
      "--browser",
      "firefox",
      "--profile",
      "rookie-a",
      "--select",
      "all",
    ],
  );
  assert_eq!(
    out.status.code(),
    Some(1),
    "must be a typed core error (exit 1), not a clap usage error (exit 2): stderr={}",
    String::from_utf8_lossy(&out.stderr)
  );
  let stderr = String::from_utf8_lossy(&out.stderr);
  assert!(
    stderr.contains("profile and select"),
    "missing conflicting_profile_selection diagnostic: {stderr}"
  );
}

#[test]
fn report_select_all_alone_stays_the_default_all_profiles_scope() {
  // Unlike `read`, `--select all` alone (no `--profile`) is `report`'s
  // default -- it must succeed exactly like omitting `--select` entirely.
  let root = unique_tmpdir("report-select-all-ok");
  seed_multi_profile_firefox(root.path());

  let with_select = parsed_json(&run_isolated(
    root.path(),
    &["report", "--browser", "firefox", "--select", "all"],
  ));
  let without_select = parsed_json(&run_isolated(
    root.path(),
    &["report", "--browser", "firefox"],
  ));
  assert_eq!(
    with_select["summary"]["profiles_discovered"],
    without_select["summary"]["profiles_discovered"]
  );
  assert_eq!(
    with_select["summary"]["profiles_discovered"], 2,
    "{with_select}"
  );
}

#[test]
fn report_profile_and_select_require_browser() {
  for args in [
    &["report", "--profile", "x"][..],
    &["report", "--select", "all"][..],
  ] {
    let stderr = assert_usage_error(&run_rookie(args), &format!("{args:?}"));
    assert!(stderr.contains("--browser"), "{args:?}: {stderr}");
  }
}
