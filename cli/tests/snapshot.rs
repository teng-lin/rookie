//! End-to-end CLI contract tests.
//!
//! Builds a synthetic Firefox-style `cookies.sqlite` (moz_cookies table),
//! invokes the `rookie-cookies` binary's `from-path`/`read` subcommands, and
//! asserts the JSON/Netscape output round-trips the seeded cookies. No real
//! browser, no encryption — just exercises the CLI argument plumbing and
//! browser discovery.
//!
//! Most fixtures here pass `--include-expired`: many of their expiry
//! timestamps are old fixed reference dates, which the `from-path`/`read`
//! snapshot layer would otherwise filter out as expired by the time this
//! suite runs (unlike the removed flat `--path` mode, which never filtered
//! by expiry at all).
//!
//! Closes audit finding C6 in `.sisyphus/plans/test-coverage-audit.md`.

#[cfg(unix)]
use std::io::Read;
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
  let mut conn = rusqlite::Connection::open(db).expect("open writable sqlite");
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
  // One transaction for every row, not one autocommit per row: the SIGTERM
  // test seeds tens of thousands of rows to force a real race against
  // extraction, which would be impractically slow to set up under the
  // default per-statement autocommit.
  let tx = conn.transaction().expect("begin seed transaction");
  for r in rows {
    tx.execute(
      "INSERT INTO moz_cookies (host, path, isSecure, expiry, name, value, isHttpOnly, sameSite)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
      rusqlite::params![r.0, r.1, r.2, r.3, r.4, r.5, r.6, r.7],
    )
    .expect("insert row");
  }
  tx.commit().expect("commit seeded rows");
}

// (host_key, name, value, encrypted_value)
type ChromiumRow<'a> = (&'a str, &'a str, &'a str, &'a [u8]);

fn seed_chromium_cookies(db: &Path, rows: &[ChromiumRow<'_>]) {
  let conn = rusqlite::Connection::open(db).expect("open writable sqlite");
  conn
    .execute_batch(
      "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT); \
       INSERT INTO meta VALUES ('version', '23'); \
       CREATE TABLE cookies (\
         host_key TEXT NOT NULL, path TEXT NOT NULL, is_secure INTEGER NOT NULL, \
         expires_utc INTEGER NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL, \
         encrypted_value BLOB NOT NULL, is_httponly INTEGER NOT NULL, \
         samesite INTEGER NOT NULL\
       );",
    )
    .expect("create Chromium fixture");
  for row in rows {
    conn
      .execute(
        "INSERT INTO cookies VALUES (?1, '/', 0, 0, ?2, ?3, ?4, 0, 0)",
        rusqlite::params![row.0, row.1, row.2, row.3],
      )
      .expect("insert Chromium row");
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

  // `--domains` routes `from-path` through `extract_from_path`, which never
  // filters by expiry (unlike plain `from-path`), so no `--include-expired`
  // is needed here despite the fixture's old reference timestamp.
  let default = run_rookie(&[
    "from-path",
    db.to_str().unwrap(),
    "--domains",
    "example.com",
  ]);
  let explicit = run_rookie(&[
    "from-path",
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

  let out = run_rookie(&[
    "from-path",
    db.to_str().unwrap(),
    "--format",
    "netscape",
    "--include-expired",
  ]);
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
fn modern_firefox_expiry_is_converted_before_json_and_netscape_export() {
  let dir = unique_tmpdir("cli-firefox-millisecond-expiry");
  let db = dir.path().join("cookies.sqlite");
  seed_firefox_cookies(
    &db,
    &[(
      ".example.com",
      "/",
      false,
      1_700_000_000_999,
      "modern",
      "value",
      false,
      0,
    )],
  );
  let connection = rusqlite::Connection::open(&db).expect("open writable sqlite");
  connection
    .pragma_update(None, "user_version", 16)
    .expect("select millisecond Firefox schema");
  drop(connection);

  let json = parsed_json(&run_rookie(&[
    "from-path",
    db.to_str().unwrap(),
    "--format",
    "json",
    "--include-expired",
  ]));
  assert_eq!(json[0]["expires"], 1_700_000_000_u64);

  let netscape = run_rookie(&[
    "from-path",
    db.to_str().unwrap(),
    "--format",
    "netscape",
    "--include-expired",
  ]);
  assert_success(&netscape);
  let netscape = String::from_utf8(netscape.stdout).expect("UTF-8 Netscape output");
  assert!(
    netscape.contains("\t1700000000\tmodern\tvalue\n"),
    "unexpected Netscape output: {netscape:?}"
  );
  assert!(!netscape.contains("1700000000999"));
}

#[test]
fn netscape_output_escapes_malicious_fields_exactly() {
  let dir = unique_tmpdir("cli-netscape-injection");
  let db = dir.path().join("cookies.sqlite");
  // `name`/`value` are plain here, not malicious: a snapshot job drops any
  // row whose name/value contains a control character before it ever
  // reaches a formatter (see `from_path_snapshot_drops_a_ctl_bearing_name_as_invalid_octets`
  // below) -- a fixture that put the injection payload there would be
  // asserting on a row `from_path` never emits. `sendable_octets` only
  // inspects name/value, so the malicious payload goes in `domain`/`path`
  // instead, which still exercises the Netscape formatter's escaping.
  seed_firefox_cookies(
    &db,
    &[(
      ".exa\tmple\r.test",
      "/line\npath",
      false,
      0,
      "session",
      "value",
      true,
      0,
    )],
  );

  // `--domains` is required to reach `extract_from_path`, the only from-path
  // job that skips `sendable_octets`. Passing the exact (still-malicious)
  // host as the domain filter matches trivially -- `host_matches_domain`
  // only normalizes leading/trailing dots, not control characters -- so the
  // row survives, same as the removed flat `--path` mode did.
  let out = run_rookie(&[
    "from-path",
    db.to_str().unwrap(),
    "--format",
    "netscape",
    "--domains",
    ".exa\tmple\r.test",
  ]);
  assert_success(&out);

  assert_eq!(
    out.stdout,
    format!(
      "# Netscape HTTP Cookie File\n\
       # Generated by rookie-cookies {}\n\
       # Edit at your own risk.\n\n\
       #HttpOnly_.exa%09mple%0D.test\tTRUE\t/line%0Apath\tFALSE\t0\tsession\tvalue\n\n",
      rookie_cookies::version()
    )
    .into_bytes()
  );
}

/// Pins the behavior `netscape_output_escapes_malicious_fields_exactly` had
/// to route around: `from-path` with no `--domains` runs through
/// `rookie_cookies::from_path`, a snapshot job, which drops a row whose
/// cookie name contains a control character (never a valid HTTP token)
/// before it reaches any formatter, and counts it as `invalid_octets`
/// rather than emitting it -- see `rookie-rs/src/read/tests.rs::from_path_omits_ctl_name_with_invalid_octets_warning`
/// for the same contract pinned on the core side.
#[test]
fn from_path_snapshot_drops_a_ctl_bearing_name_as_invalid_octets() {
  let dir = unique_tmpdir("cli-invalid-octets");
  let db = dir.path().join("cookies.sqlite");
  seed_firefox_cookies(
    &db,
    &[(".example.test", "/", false, 0, "na\tme", "value", false, 0)],
  );

  let out = run_rookie(&["from-path", db.to_str().unwrap(), "--format", "json"]);
  assert_success(&out);
  let parsed: serde_json::Value =
    serde_json::from_slice(&out.stdout).expect("CLI stdout must be valid JSON");
  assert_eq!(parsed.as_array().map(Vec::len), Some(0), "{parsed}");

  let stderr = String::from_utf8_lossy(&out.stderr);
  assert!(
    stderr.contains("invalid_octets"),
    "missing invalid_octets warning: {stderr}"
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

  let out = run_rookie_with_info_logs(&[
    "from-path",
    db.to_str().unwrap(),
    "--format",
    "json",
    "--include-expired",
  ]);
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
fn process_shutdown_is_not_a_cli_option() {
  let out = run_rookie(&["--allow-process-shutdown"]);
  assert_eq!(out.status.code(), Some(2));
  assert!(out.stdout.is_empty());
  let stderr = String::from_utf8_lossy(&out.stderr);
  assert!(stderr.contains("unexpected argument"), "{stderr}");
  assert!(stderr.contains("--allow-process-shutdown"), "{stderr}");
}

#[test]
fn plaintext_only_selects_chromium_and_fails_closed_before_domain_filtering() {
  let dir = unique_tmpdir("cli-canonical-chromium");
  let db = dir.path().join("Cookies");
  seed_chromium_cookies(
    &db,
    &[
      (".example.test", "plain", "visible", b""),
      ("other.test", "encrypted", "", b"v10encrypted"),
    ],
  );

  let out = run_rookie(&[
    "from-path",
    db.to_str().unwrap(),
    "--domains",
    "example.test",
    "--plaintext-only",
  ]);
  assert_eq!(out.status.code(), Some(1));
  assert!(out.stdout.is_empty());
  let stderr = String::from_utf8_lossy(&out.stderr);
  assert!(
    stderr.contains("no browser key identity"),
    "missing plaintext-only causal diagnostic: {stderr}"
  );
}

#[test]
fn plaintext_only_extracts_an_explicit_chromium_database() {
  let dir = unique_tmpdir("cli-canonical-chromium-plain");
  let db = dir.path().join("Cookies");
  seed_chromium_cookies(
    &db,
    &[
      (".example.test", "plain", "visible", b""),
      ("other.test", "ignored", "other", b""),
    ],
  );

  let out = run_rookie(&[
    "from-path",
    db.to_str().unwrap(),
    "--domains",
    "example.test",
    "--plaintext-only",
  ]);
  let parsed = parsed_json(&out);
  assert_eq!(parsed.as_array().map(Vec::len), Some(1));
  assert_eq!(parsed[0]["name"], "plain");
}

#[test]
fn credential_selector_on_firefox_is_a_core_error_not_a_usage_error() {
  let dir = unique_tmpdir("cli-key-path-is-chromium");
  let db = dir.path().join("cookies.sqlite");
  seed_firefox_cookies(
    &db,
    &[(".example.test", "/", false, 0, "id", "value", false, 0)],
  );

  // `--plaintext-only`, not `--key-path`/`--browser-id`: those two now map to
  // `PathExtractRequest::windows_local_state`/`unix_identity`, which are
  // `#[cfg(windows)]`/`#[cfg(unix)]` -- the "wrong" one for this platform is a
  // CLI usage error (main.rs::path_extract_request), not the core diagnostic
  // this test wants. `--plaintext-only` still selects Chromium credentials
  // (just a passive one) on every platform, so it still reaches the same
  // `require_chromium_source` classification without touching a real
  // keychain/keyring/Local State file.
  let out = run_rookie(&["from-path", db.to_str().unwrap(), "--plaintext-only"]);
  assert_eq!(out.status.code(), Some(1));
  assert!(out.stdout.is_empty());
  let stderr = String::from_utf8_lossy(&out.stderr);
  assert!(
    stderr.contains("expected_chromium_sqlite") || stderr.contains("expected Chromium"),
    "missing typed source diagnostic: {stderr}"
  );
}

#[test]
fn invalid_path_exits_nonzero_without_machine_output() {
  let dir = unique_tmpdir("missing-db");
  let missing = dir.path().join("does not exist.sqlite");
  let out = run_rookie(&["from-path", missing.to_str().unwrap(), "--format", "json"]);

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

/// `--load` and its flat, hard-failing aggregate error are gone with no flat
/// replacement (per the design's PR 6/7 CLI table): `report` with no
/// `--browser` is the typed replacement for the fan-out, but it never hard
/// fails for one browser's problem -- a broken installed browser becomes
/// visible in the report instead of aborting it. This is what that looks
/// like for the same broken-Firefox-profile fixture the old `--load` test
/// used.
#[test]
fn report_without_browser_surfaces_a_broken_installed_browser() {
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
    .args(["report"])
    .output()
    .expect("spawn rookie-cookies");

  let report = parsed_json(&out);
  assert_eq!(report["summary"]["browsers_detected"], 1, "{report}");
  assert!(
    report.to_string().contains("firefox"),
    "broken browser must still be identifiable in the report: {report}"
  );
}

#[test]
fn help_and_version_are_successful_stdout_contracts() {
  let help = run_rookie(&["--help"]);
  assert_success(&help);
  assert!(help.stderr.is_empty(), "help wrote to stderr");
  let help_stdout = String::from_utf8(help.stdout).expect("utf-8 help");
  // The top-level help lists every job subcommand; each subcommand's own
  // flags (e.g. `from-path --local-state-path`) are asserted against that
  // subcommand's own `--help` output, not this top-level one.
  for subcommand in [
    "read",
    "from-path",
    "header",
    "report",
    "profiles",
    "browsers",
  ] {
    assert!(
      help_stdout.contains(subcommand),
      "help omitted the {subcommand} subcommand: {help_stdout}"
    );
  }
  assert!(
    !help_stdout.contains("allow-process-shutdown"),
    "{help_stdout}"
  );

  let from_path_help = run_rookie(&["from-path", "--help"]);
  assert_success(&from_path_help);
  let from_path_help_stdout = String::from_utf8(from_path_help.stdout).expect("utf-8 help");
  for flag in [
    "--local-state-path",
    "--browser-id",
    "--plaintext-only",
    "--format",
    "--domains",
  ] {
    assert!(
      from_path_help_stdout.contains(flag),
      "from-path help omitted {flag}: {from_path_help_stdout}"
    );
  }
  assert!(
    !from_path_help_stdout.contains("--key-path"),
    "from-path help must not offer the removed --key-path alias: {from_path_help_stdout}"
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

  // `read` has no domain filter (it is documented as an *unfiltered*
  // snapshot -- `report --browser firefox --domains ...` is the subcommand
  // that filters by domain), so this only exercises browser discovery, not
  // the old flat mode's domain narrowing.
  let mut command = Command::new(ROOKIE_BIN);
  command
    .args([
      "read",
      "--browser",
      "firefox",
      "--format",
      "json",
      "--include-expired",
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

/// Every job subcommand maps `SIGTERM` to cancellation (see
/// `install_cancel_on_signal` in `main.rs`). The fixture is large enough
/// (tens of thousands of rows) that a real extraction stays in flight for a
/// wide window, so a `SIGTERM` sent shortly after spawn reliably lands mid-
/// extraction rather than racing process startup -- unlike a single-row
/// fixture, this deterministically exercises the graceful-cancellation path,
/// not just "didn't panic". Output is discarded: on the rare timing where
/// extraction finishes first, the JSON for this many cookies would otherwise
/// overflow the stdout pipe buffer and hang the poll loop below.
#[cfg(unix)]
#[test]
fn sigterm_during_browser_extraction_does_not_panic_or_hang() {
  let root = unique_tmpdir("sigterm ünicode");
  let firefox_root = {
    #[cfg(target_os = "linux")]
    {
      root.path().join(".mozilla/firefox")
    }
    #[cfg(target_os = "macos")]
    {
      root.path().join("Library/Application Support/Firefox")
    }
  };
  let profile = firefox_root.join("Profiles/rookie-ci.default-release");
  std::fs::create_dir_all(&profile).expect("create Firefox profile");
  std::fs::write(
    firefox_root.join("profiles.ini"),
    "[Profile0]\nName=rookie-ci\nIsRelative=1\n\
     Path=Profiles/rookie-ci.default-release\nDefault=1\n",
  )
  .expect("write profiles.ini");
  let rows: Vec<MozRow> = (0..150_000)
    .map(|_| (".example.com", "/", false, 0u64, "n", "v", false, 0i64))
    .collect();
  seed_firefox_cookies(&profile.join("cookies.sqlite"), &rows);

  let mut child = isolated_browser_command(root.path())
    .args(["read", "--browser", "firefox", "--format", "json"])
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::piped())
    .spawn()
    .expect("spawn rookie-cookies");

  // Give the process a moment to parse args, install tracing, and arm the
  // signal handler before the race begins -- otherwise SIGTERM could land
  // before `install_cancel_on_signal` runs, which is a different (and
  // already OS-default-handled) scenario than the one this test targets.
  std::thread::sleep(std::time::Duration::from_millis(50));

  let pid = child.id();
  let killed = Command::new("kill")
    .args(["-TERM", &pid.to_string()])
    .status()
    .expect("send SIGTERM");
  assert!(killed.success(), "the `kill` command itself must succeed");

  let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
  let status = loop {
    if let Some(status) = child.try_wait().expect("poll rookie-cookies") {
      break status;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "rookie-cookies did not exit within 10s of SIGTERM"
    );
    std::thread::sleep(std::time::Duration::from_millis(20));
  };

  let mut stderr = String::new();
  child
    .stderr
    .take()
    .expect("stderr was piped")
    .read_to_string(&mut stderr)
    .expect("read stderr");

  assert_ne!(
    status.code(),
    Some(101),
    "SIGTERM racing a real extraction must not panic (stderr: {stderr})"
  );
  match status.code() {
    // The fixture is large enough that this is the expected outcome: the
    // signal reached the process while extraction was still running, and
    // cooperative cancellation stopped it cleanly.
    // 0.6's typed `Error::Stopped` displays as "operation was cancelled",
    // not the internal `BoundaryStop` wording ("operation cancelled") the
    // old anyhow chain surfaced here.
    Some(1) => assert!(
      stderr.contains("operation was cancelled"),
      "a graceful exit code 1 must be the cancellation path, got stderr: {stderr}"
    ),
    // Rare timing where extraction raced ahead of the signal and finished
    // first -- not a bug, just not the scenario this test targets.
    Some(0) => {}
    other => panic!("unexpected SIGTERM exit status {other:?} (stderr: {stderr})"),
  }
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

  let out = run_rookie(&["from-path", db.to_str().unwrap(), "--include-expired"]);
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

/// `--format detailed` is the only `read`/`from-path` format that carries a
/// cookie's isolation context (CHIPS partition key, Firefox container
/// identity); `json`/`netscape` stay the eight-field projection because
/// neither can represent one.
#[test]
fn from_path_detailed_format_carries_isolation_context() {
  let dir = unique_tmpdir("cli-from-path-detailed");
  let db = dir.path().join("cookies.sqlite");
  seed_firefox_cookies(
    &db,
    &[(".example.com", "/", false, 0, "id", "abc", false, 0)],
  );

  let out = run_rookie(&["from-path", db.to_str().unwrap(), "--format", "detailed"]);
  assert!(
    out.status.success(),
    "rookie-cookies exited non-zero: stderr={}",
    String::from_utf8_lossy(&out.stderr)
  );
  let parsed: serde_json::Value =
    serde_json::from_slice(&out.stdout).expect("CLI stdout must be valid JSON");
  let entries = parsed.as_array().expect("JSON must be an array");
  assert_eq!(entries.len(), 1);
  assert_eq!(entries[0]["cookie"]["name"], "id");
  assert!(
    entries[0].get("context").is_some(),
    "detailed format must carry isolation context: {entries:?}"
  );
}

/// Reproduces `rookie-cookies --load | head -1`: the reader closes its end
/// of the pipe (here, we drop it directly) before the CLI has necessarily
/// finished writing. `println!`'s internal `.unwrap()` turns that into a
/// panic (exit code 101) since Rust ignores `SIGPIPE` by default; the CLI
/// must instead exit cleanly.
#[test]
fn broken_stdout_pipe_exits_cleanly_instead_of_panicking() {
  let dir = unique_tmpdir("cli-broken-pipe");
  let db = dir.path().join("cookies.sqlite");
  // Enough rows that the JSON write is unlikely to complete in a single
  // syscall before the parent has closed its end of the pipe.
  let rows: Vec<MozRow> = (0..2000)
    .map(|_| {
      (
        ".example.com",
        "/",
        false,
        0u64,
        "name",
        "value",
        false,
        0i64,
      )
    })
    .collect();
  seed_firefox_cookies(&db, &rows);

  let mut child = Command::new(ROOKIE_BIN)
    .args([
      "from-path",
      db.to_str().unwrap(),
      "--format",
      "json",
      "--include-expired",
    ])
    .env("RUST_LOG", "error")
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped())
    .spawn()
    .expect("spawn rookie-cookies");

  // Close our end of the read pipe before reading anything -- this is what
  // `head -1` does once it already has the line it wants.
  drop(child.stdout.take());

  let status = child.wait().expect("wait for rookie-cookies");
  // Exit 0 either way: hitting the BrokenPipe branch calls `exit(0)`
  // explicitly, and racing ahead of the parent's `drop` and finishing
  // normally also exits 0 through the ordinary success path -- so this
  // assertion, unlike the SIGTERM test's, does not need to tolerate a
  // second legitimate outcome.
  assert_eq!(
    status.code(),
    Some(0),
    "a closed stdout pipe must exit cleanly, not panic (101) or fail (anything else)"
  );
}
