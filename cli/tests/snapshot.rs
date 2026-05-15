//! End-to-end CLI snapshot tests.
//!
//! Builds a synthetic Firefox-style `cookies.sqlite` (moz_cookies table),
//! invokes the `rookie` binary with `--path <file> --format json`, and
//! asserts the JSON output round-trips the seeded cookies. No real
//! browser, no encryption — just exercises the CLI argument plumbing
//! plus the firefox_based path through `any_browser`.
//!
//! Closes audit finding C6 in `.sisyphus/plans/test-coverage-audit.md`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

/// `CARGO_BIN_EXE_rookie` is set by Cargo for integration tests in the
/// same crate that declares the `[[bin]] name = "rookie"`.
const ROOKIE_BIN: &str = env!("CARGO_BIN_EXE_rookie");

fn unique_tmpdir(tag: &str) -> PathBuf {
  static COUNTER: AtomicU64 = AtomicU64::new(0);
  let n = COUNTER.fetch_add(1, Ordering::SeqCst);
  let dir = std::env::temp_dir().join(format!(
    "rookie-cli-test-{}-{}-{}",
    tag,
    std::process::id(),
    n
  ));
  std::fs::create_dir_all(&dir).expect("temp dir");
  dir
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
    .expect("spawn rookie")
}

#[test]
fn json_output_contains_seeded_cookie() {
  let dir = unique_tmpdir("cli-json");
  let db = dir.join("cookies.sqlite");
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

  let out = run_rookie(&[
    "--path",
    db.to_str().unwrap(),
    "--format",
    "json",
    "--domains",
    "example.com",
  ]);
  assert!(
    out.status.success(),
    "rookie exited non-zero: stderr={}",
    String::from_utf8_lossy(&out.stderr)
  );

  let parsed: serde_json::Value =
    serde_json::from_slice(&out.stdout).expect("CLI stdout must be valid JSON");
  let arr = parsed.as_array().expect("JSON must be an array");
  assert_eq!(
    arr.len(),
    1,
    "domain filter should drop other.test: {:?}",
    arr
  );
  let c = &arr[0];
  assert_eq!(c["name"], "id");
  assert_eq!(c["value"], "abc");
  assert_eq!(c["domain"], ".example.com");
  assert_eq!(c["path"], "/");
  assert_eq!(c["http_only"], true);
  assert_eq!(c["secure"], false);
  assert_eq!(c["same_site"], 1);
}

#[test]
fn netscape_output_includes_seeded_cookie() {
  let dir = unique_tmpdir("cli-netscape");
  let db = dir.join("cookies.sqlite");
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
  assert!(
    out.status.success(),
    "rookie exited non-zero: stderr={}",
    String::from_utf8_lossy(&out.stderr)
  );

  let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
  // Netscape format is tab-separated; we just confirm the seeded cookie
  // name + value made it through, regardless of exact column padding.
  assert!(
    stdout.contains("id") && stdout.contains("abc"),
    "expected name=id value=abc in netscape output: {}",
    stdout
  );
}
