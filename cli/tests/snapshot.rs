//! End-to-end CLI contract tests.
//!
//! Builds a synthetic Firefox-style `cookies.sqlite` (moz_cookies table),
//! invokes the `rookie-cookies` binary with `--path <file> --format json`, and
//! asserts the JSON output round-trips the seeded cookies. No real
//! browser, no encryption — just exercises the CLI argument plumbing,
//! browser discovery, and the firefox_based path through `any_browser`.
//!
//! Closes audit finding C6 in `.sisyphus/plans/test-coverage-audit.md`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

/// `CARGO_BIN_EXE_rookie-cookies` is set by Cargo for integration tests in the
/// same crate that declares the `[[bin]] name = "rookie-cookies"`.
const ROOKIE_BIN: &str = env!("CARGO_BIN_EXE_rookie-cookies");

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
    "rookie-cookies-cli-test-{}-{}-{}",
    tag,
    std::process::id(),
    n
  ));
  std::fs::create_dir_all(&dir).expect("temp dir");
  TestDir(dir)
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

fn run_rookie(args: &[&str]) -> std::process::Output {
  // RUST_LOG=error silences tracing-subscriber's INFO output so it
  // doesn't pollute the JSON stdout we're asserting against.
  Command::new(ROOKIE_BIN)
    .args(args)
    .env("RUST_LOG", "error")
    .output()
    .expect("spawn rookie-cookies")
}

fn run_rookie_with_info_logs(args: &[&str]) -> std::process::Output {
  Command::new(ROOKIE_BIN)
    .args(args)
    .env("RUST_LOG", "info")
    .output()
    .expect("spawn rookie-cookies")
}

fn isolated_browser_command(root: &Path) -> Command {
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

fn assert_success(out: &std::process::Output) {
  assert!(
    out.status.success(),
    "rookie-cookies exited non-zero: stdout={} stderr={}",
    String::from_utf8_lossy(&out.stdout),
    String::from_utf8_lossy(&out.stderr)
  );
}

fn parsed_json(out: &std::process::Output) -> serde_json::Value {
  assert_success(out);
  serde_json::from_slice(&out.stdout).unwrap_or_else(|err| {
    panic!(
      "CLI stdout must be valid JSON: {err}; stdout={} stderr={}",
      String::from_utf8_lossy(&out.stdout),
      String::from_utf8_lossy(&out.stderr)
    )
  })
}

#[test]
fn default_json_output_and_domain_filter_are_exact() {
  let dir = unique_tmpdir("cli json with spaces ünicode");
  let db = dir.path().join("cookies.sqlite");
  seed_firefox_cookies(
    &db,
    &[
      (
        ".example.com",
        "/",
        false,
        1_700_000_000,
        "id",
        "abc",
        true,
        1,
      ),
      ("other.test", "/p", true, 0, "tok", "xyz", false, 2),
    ],
  );

  let default = run_rookie(&["--path", db.to_str().unwrap(), "--domains", "example.com"]);
  let explicit = run_rookie(&[
    "--path",
    db.to_str().unwrap(),
    "--domains",
    "example.com",
    "--format",
    "json",
  ]);
  for output in [&default, &explicit] {
    assert!(
      output.status.success(),
      "rookie-cookies exited non-zero: stderr={}",
      String::from_utf8_lossy(&output.stderr)
    );
  }

  assert_eq!(
    default.stdout, explicit.stdout,
    "default and explicit JSON modes must remain byte-identical"
  );
  assert_eq!(
    String::from_utf8(default.stdout).expect("UTF-8 JSON"),
    "[\n\
     \x20 {\n\
     \x20   \"domain\": \".example.com\",\n\
     \x20   \"path\": \"/\",\n\
     \x20   \"secure\": false,\n\
     \x20   \"expires\": 1700000000,\n\
     \x20   \"name\": \"id\",\n\
     \x20   \"value\": \"abc\",\n\
     \x20   \"http_only\": true,\n\
     \x20   \"same_site\": 1\n\
     \x20 }\n\
     ]\n"
  );
}

#[test]
fn netscape_output_is_exact() {
  let dir = unique_tmpdir("cli-netscape");
  let db = dir.path().join("cookies.sqlite");
  seed_firefox_cookies(
    &db,
    &[(
      ".example.com",
      "/",
      false,
      1_700_000_000,
      "id",
      "abc",
      true,
      1,
    )],
  );

  let out = run_rookie(&["--path", db.to_str().unwrap(), "--format", "netscape"]);
  assert_success(&out);

  assert_eq!(
    String::from_utf8(out.stdout).expect("UTF-8 Netscape output"),
    format!(
      "# Netscape HTTP Cookie File\n\
       # Generated by rookie-cookies {}\n\
       # Edit at your own risk.\n\n\
       #HttpOnly_.example.com\tTRUE\t/\tFALSE\t1700000000\tid\tabc\n\n",
      rookie_cookies::version()
    )
  );
}

#[test]
fn netscape_output_escapes_malicious_fields_exactly() {
  let dir = unique_tmpdir("cli-netscape-injection");
  let db = dir.path().join("cookies.sqlite");
  seed_firefox_cookies(
    &db,
    &[(
      ".exa\tmple\r.test",
      "/line\npath",
      false,
      0,
      "na\tme",
      "safe\n.evil.test\tTRUE\t/\tTRUE\t1\tforged\tvalue\r",
      true,
      0,
    )],
  );

  let out = run_rookie(&["--path", db.to_str().unwrap(), "--format", "netscape"]);
  assert_success(&out);

  assert_eq!(
    out.stdout,
    format!(
      "# Netscape HTTP Cookie File\n\
       # Generated by rookie-cookies {}\n\
       # Edit at your own risk.\n\n\
       #HttpOnly_.exa%09mple%0D.test\tTRUE\t/line%0Apath\tFALSE\t0\tna%09me\tsafe%0A.evil.test%09TRUE%09/%09TRUE%091%09forged%09value%0D\n\n",
      rookie_cookies::version()
    )
    .into_bytes()
  );
}

#[test]
fn json_stdout_stays_machine_readable_with_info_logging() {
  let dir = unique_tmpdir("stdout-stderr");
  let db = dir.path().join("cookies.sqlite");
  seed_firefox_cookies(
    &db,
    &[(
      ".example.com",
      "/",
      false,
      1_700_000_000,
      "id",
      "abc",
      false,
      0,
    )],
  );

  let out = run_rookie_with_info_logs(&["--path", db.to_str().unwrap(), "--format", "json"]);
  let parsed = parsed_json(&out);
  assert_eq!(parsed.as_array().map(Vec::len), Some(1));

  let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
  let stderr = String::from_utf8(out.stderr).expect("utf-8 stderr");
  assert!(!stdout.contains(" INFO "), "log polluted stdout: {stdout}");
  assert!(!stdout.contains(" WARN "), "log polluted stdout: {stdout}");
  assert!(!stderr.is_empty(), "INFO logging produced no stderr output");
  assert!(stderr.contains(" INFO "), "missing INFO log: {stderr}");
  assert!(
    stderr.contains("extracting cookies"),
    "unexpected INFO log: {stderr}"
  );
}

#[test]
fn conflicting_and_incomplete_source_arguments_are_parse_errors() {
  for args in [
    &["--browser", "firefox", "--load"][..],
    &["--browser", "chrome", "--key-path", "Local State"][..],
    &["--path", "cookies.sqlite", "--load"][..],
    &["--key-path", "Local State"][..],
  ] {
    let out = run_rookie(args);
    assert!(
      !out.status.success(),
      "invalid arguments succeeded: {args:?}"
    );
    assert!(
      out.stdout.is_empty(),
      "parse error wrote stdout for {args:?}: {}",
      String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
      stderr.contains("error:"),
      "parse error missing clap diagnostic for {args:?}: {stderr}"
    );
  }
}

#[test]
fn invalid_path_exits_nonzero_without_machine_output() {
  let dir = unique_tmpdir("missing-db");
  let missing = dir.path().join("does not exist.sqlite");
  let out = run_rookie(&["--path", missing.to_str().unwrap(), "--format", "json"]);

  assert!(
    !out.status.success(),
    "missing database unexpectedly succeeded"
  );
  assert!(
    out.stdout.is_empty(),
    "failed invocation wrote partial machine output: {}",
    String::from_utf8_lossy(&out.stdout)
  );
  assert!(
    !out.stderr.is_empty(),
    "failed invocation should explain the error on stderr"
  );
}

#[test]
fn load_without_an_installed_browser_returns_an_empty_array() {
  let root = unique_tmpdir("empty-browser-home");
  let out = isolated_browser_command(root.path())
    .args(["--load", "--format", "json"])
    .output()
    .expect("spawn rookie-cookies");

  assert_success(&out);
  assert_eq!(
    serde_json::from_slice::<serde_json::Value>(&out.stdout).expect("valid JSON"),
    serde_json::json!([])
  );
}

#[test]
fn load_errors_when_an_installed_browser_cannot_be_extracted() {
  let root = unique_tmpdir("broken-installed-browser");

  #[cfg(target_os = "linux")]
  let firefox_root = root.path().join(".mozilla/firefox");
  #[cfg(target_os = "macos")]
  let firefox_root = root.path().join("Library/Application Support/Firefox");
  #[cfg(target_os = "windows")]
  let firefox_root = root.path().join("Mozilla/Firefox");

  let profile = firefox_root.join("Profiles/broken.default-release");
  std::fs::create_dir_all(&profile).expect("create Firefox profile");
  std::fs::write(
    firefox_root.join("profiles.ini"),
    "[Profile0]\nName=broken\nIsRelative=1\n\
     Path=Profiles/broken.default-release\nDefault=1\n",
  )
  .expect("write profiles.ini");
  std::fs::write(profile.join("cookies.sqlite"), b"not a sqlite database")
    .expect("write corrupt cookie database");

  let out = isolated_browser_command(root.path())
    .args(["--load", "--format", "json"])
    .output()
    .expect("spawn rookie-cookies");

  assert!(
    !out.status.success(),
    "broken installed browser was ignored"
  );
  assert!(out.stdout.is_empty(), "failure emitted machine output");
  let stderr = String::from_utf8_lossy(&out.stderr);
  assert!(
    stderr.contains("all browser extractions failed") && stderr.contains("firefox:"),
    "missing aggregate extraction error: {stderr}"
  );
}

#[test]
fn help_and_version_are_successful_stdout_contracts() {
  let help = run_rookie(&["--help"]);
  assert_success(&help);
  assert!(help.stderr.is_empty(), "help wrote to stderr");
  let help_stdout = String::from_utf8(help.stdout).expect("utf-8 help");
  for flag in ["--path", "--key-path", "--browser", "--format"] {
    assert!(
      help_stdout.contains(flag),
      "help omitted {flag}: {help_stdout}"
    );
  }

  #[cfg(target_os = "linux")]
  let expected_browsers = [
    "arc",
    "brave",
    "cachy",
    "chrome",
    "chromium",
    "edge",
    "firefox",
    "librewolf",
    "opera",
    "\"opera gx\"",
    "vivaldi",
    "zen",
  ];
  #[cfg(target_os = "macos")]
  let expected_browsers = [
    "arc",
    "brave",
    "chrome",
    "chromium",
    "edge",
    "firefox",
    "librewolf",
    "opera",
    "\"opera gx\"",
    "safari",
    "vivaldi",
    "zen",
  ];
  #[cfg(target_os = "windows")]
  let expected_browsers = [
    "arc",
    "brave",
    "chrome",
    "chromium",
    "edge",
    "firefox",
    "internet_explorer",
    "librewolf",
    "opera",
    "\"opera gx\"",
    "vivaldi",
    "zen",
  ];
  #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
  let expected_browsers = [
    "arc",
    "brave",
    "chrome",
    "chromium",
    "edge",
    "firefox",
    "librewolf",
    "opera",
    "\"opera gx\"",
    "vivaldi",
    "zen",
  ];
  let browser_help = help_stdout
    .lines()
    .find(|line| line.contains("--browser"))
    .expect("browser help line");
  assert!(
    browser_help.contains(&format!(
      "[possible values: {}]",
      expected_browsers.join(", ")
    )),
    "browser values are not in deterministic order: {browser_help}"
  );

  let version = run_rookie(&["--version"]);
  assert_success(&version);
  assert!(version.stderr.is_empty(), "version wrote to stderr");
  let version_stdout = String::from_utf8(version.stdout).expect("utf-8 version");
  assert!(version_stdout.contains("CLI: "), "{version_stdout}");
  assert!(
    version_stdout.contains("rookie-cookies: "),
    "{version_stdout}"
  );
}

#[test]
fn firefox_browser_flag_discovers_a_seeded_profile() {
  let root = unique_tmpdir("discovery with spaces ünicode");

  #[cfg(target_os = "linux")]
  let firefox_root = root.path().join(".mozilla/firefox");
  #[cfg(target_os = "macos")]
  let firefox_root = root.path().join("Library/Application Support/Firefox");
  #[cfg(target_os = "windows")]
  let firefox_root = root.path().join("Mozilla/Firefox");

  let profile = firefox_root.join("Profiles/rookie-ci.default-release");
  std::fs::create_dir_all(&profile).expect("create Firefox profile");
  std::fs::write(
    firefox_root.join("profiles.ini"),
    "[Profile0]\nName=rookie-ci\nIsRelative=1\n\
     Path=Profiles/rookie-ci.default-release\nDefault=1\n",
  )
  .expect("write profiles.ini");
  seed_firefox_cookies(
    &profile.join("cookies.sqlite"),
    &[(
      ".example.com",
      "/",
      false,
      1_700_000_000,
      "discovered",
      "yes",
      false,
      0,
    )],
  );

  let mut command = Command::new(ROOKIE_BIN);
  command
    .args([
      "--browser",
      "firefox",
      "--domains",
      "example.com",
      "--format",
      "json",
    ])
    .env("RUST_LOG", "error");
  #[cfg(unix)]
  command.env("HOME", root.path());
  #[cfg(target_os = "windows")]
  command
    .env("APPDATA", root.path())
    .env("LOCALAPPDATA", root.path());

  let out = command.output().expect("spawn rookie-cookies");
  let parsed = parsed_json(&out);
  let cookies = parsed.as_array().expect("JSON array");
  assert_eq!(cookies.len(), 1, "{cookies:?}");
  assert_eq!(cookies[0]["name"], "discovered");
  assert_eq!(cookies[0]["value"], "yes");
}

#[test]
fn unfiltered_json_keeps_every_seeded_cookie() {
  let dir = unique_tmpdir("cli-json-unfiltered");
  let db = dir.path().join("cookies.sqlite");
  seed_firefox_cookies(
    &db,
    &[
      (
        ".example.com",
        "/",
        false,
        1_700_000_000,
        "id",
        "abc",
        true,
        1,
      ),
      ("other.test", "/p", true, 0, "tok", "xyz", false, 2),
    ],
  );

  let out = run_rookie(&["--path", db.to_str().unwrap()]);
  assert!(
    out.status.success(),
    "rookie-cookies exited non-zero: stderr={}",
    String::from_utf8_lossy(&out.stderr)
  );

  let parsed: serde_json::Value =
    serde_json::from_slice(&out.stdout).expect("CLI stdout must be valid JSON");
  let cookies = parsed.as_array().expect("JSON must be an array");
  assert_eq!(cookies.len(), 2);
  let mut names: Vec<&str> = cookies
    .iter()
    .map(|cookie| cookie["name"].as_str().expect("cookie name"))
    .collect();
  names.sort_unstable();
  assert_eq!(names, ["id", "tok"]);
}
