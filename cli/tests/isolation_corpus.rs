//! The CLI consumer of the cross-language isolation collision corpus.
//!
//! `rookie-rs/tests/isolation_corpus.rs` proves the core selects what
//! `tests/isolation_corpus/corpus.json` declares. This file proves the CLI
//! *surfaces* that selection unchanged: the same oracle, driven through the
//! built binary, so a flag that silently drops a selector or a formatter that
//! reorders the selected set fails here rather than in a user's script.
//!
//! Two routes are exercised, for the reason each exists:
//!
//! - `send-view` and `header` read a discovered profile, so the Firefox
//!   stores are seeded as a real Firefox profile under an isolated `HOME`.
//!   Chromium discovery would reach the platform keychain/DPAPI, which a unit
//!   test must not do, so the Chromium stores are driven through `from-path`
//!   instead -- their selection is already pinned in the core's own corpus
//!   test, and what this file adds for them is the flat-format loss policy.
//! - `from-path --format json|netscape` is the fail-closed flat projection,
//!   checked against each store's declared jar verdict with and without
//!   `--allow-isolation-loss`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

const ROOKIE_BIN: &str = env!("CARGO_BIN_EXE_rookie-cookies");

/// `SendOmissions::entries()` order, which the `send-view` object must
/// reproduce verbatim -- zeroes included -- so a consumer can index it
/// without first asking which keys are present.
const OMISSION_ORDER: [&str; 7] = [
  "expired",
  "not_applicable",
  "same_site",
  "partition",
  "ancestor_chain_unknown",
  "unparsable_partition_key",
  "origin",
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
    "rookie-cli-isolation-corpus-{}-{}-{}",
    tag,
    std::process::id(),
    n
  ));
  std::fs::create_dir_all(&dir).expect("temp dir");
  TestDir(dir)
}

fn load_corpus() -> Value {
  let path = Path::new(env!("CARGO_MANIFEST_DIR"))
    .parent()
    .expect("cli has a workspace parent")
    .join("tests")
    .join("isolation_corpus")
    .join("corpus.json");
  let text = std::fs::read_to_string(&path)
    .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
  serde_json::from_str(&text).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

/// Binds one corpus row cell, keeping a JSON null a genuine SQL `NULL`.
fn cell(row: &Value, column: &str) -> rusqlite::types::Value {
  match row.get(column) {
    None | Some(Value::Null) => rusqlite::types::Value::Null,
    Some(Value::String(text)) => rusqlite::types::Value::Text(text.clone()),
    Some(Value::Number(number)) => rusqlite::types::Value::Integer(
      number
        .as_i64()
        .unwrap_or_else(|| panic!("corpus column {column} must be an integer: {number}")),
    ),
    Some(other) => panic!("corpus column {column} has an unsupported type: {other}"),
  }
}

fn insert_rows(connection: &rusqlite::Connection, table: &str, columns: &[&str], rows: &[Value]) {
  let placeholders = (1..=columns.len())
    .map(|index| format!("?{index}"))
    .collect::<Vec<_>>()
    .join(", ");
  let statement = format!(
    "INSERT INTO {table} ({}) VALUES ({placeholders})",
    columns.join(", ")
  );
  for row in rows {
    let values = columns
      .iter()
      .map(|column| cell(row, column))
      .collect::<Vec<_>>();
    connection
      .execute(&statement, rusqlite::params_from_iter(values))
      .expect("insert corpus row");
  }
}

/// Writes a Chromium `Cookies` database (schema 24), matching
/// `tests/isolation_corpus/build_isolation_corpus.py`. `encrypted_value` is
/// always empty and `value` always plaintext, so no keychain is reachable.
fn build_chromium_store(rows: &[Value], path: &Path) {
  let connection = rusqlite::Connection::open(path).expect("open chromium corpus store");
  connection
    .execute_batch(
      "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
       CREATE TABLE cookies (
         host_key TEXT NOT NULL,
         name TEXT NOT NULL,
         value TEXT NOT NULL,
         path TEXT NOT NULL,
         is_secure INTEGER NOT NULL,
         is_httponly INTEGER NOT NULL,
         samesite INTEGER NOT NULL,
         expires_utc INTEGER NOT NULL,
         top_frame_site_key TEXT,
         has_cross_site_ancestor INTEGER,
         source_scheme INTEGER,
         source_port INTEGER,
         is_persistent INTEGER,
         encrypted_value BLOB NOT NULL DEFAULT x''
       );
       INSERT INTO meta (key, value) VALUES ('version', '24');
       INSERT INTO meta (key, value) VALUES ('last_compatible_version', '24');",
    )
    .expect("create chromium schema");
  insert_rows(
    &connection,
    "cookies",
    &[
      "host_key",
      "name",
      "value",
      "path",
      "is_secure",
      "is_httponly",
      "samesite",
      "expires_utc",
      "top_frame_site_key",
      "has_cross_site_ancestor",
      "source_scheme",
      "source_port",
      "is_persistent",
    ],
    rows,
  );
}

/// Writes a Firefox `cookies.sqlite` database (`user_version` 16).
fn build_firefox_store(rows: &[Value], path: &Path) {
  let connection = rusqlite::Connection::open(path).expect("open firefox corpus store");
  connection
    .execute_batch(
      "PRAGMA user_version = 16;
       CREATE TABLE moz_cookies (
         host TEXT NOT NULL,
         name TEXT NOT NULL,
         value TEXT NOT NULL,
         path TEXT NOT NULL,
         isSecure INTEGER NOT NULL,
         isHttpOnly INTEGER NOT NULL,
         sameSite INTEGER NOT NULL,
         expiry INTEGER NOT NULL,
         originAttributes TEXT NOT NULL
       );",
    )
    .expect("create firefox schema");
  insert_rows(
    &connection,
    "moz_cookies",
    &[
      "host",
      "name",
      "value",
      "path",
      "isSecure",
      "isHttpOnly",
      "sameSite",
      "expiry",
      "originAttributes",
    ],
    rows,
  );
}

fn build_store(store: &Value, path: &Path) {
  let rows = store["rows"].as_array().expect("store rows");
  match store["engine"].as_str() {
    Some("chromium") => build_chromium_store(rows, path),
    Some("firefox") => build_firefox_store(rows, path),
    other => panic!("unknown corpus engine: {other:?}"),
  }
}

/// Seeds one Firefox store as a discoverable default profile under `home`.
fn seed_firefox_profile(home: &Path, store: &Value) {
  #[cfg(target_os = "linux")]
  let firefox_root = home.join(".mozilla/firefox");
  #[cfg(target_os = "macos")]
  let firefox_root = home.join("Library/Application Support/Firefox");
  #[cfg(target_os = "windows")]
  let firefox_root = home.join("Mozilla/Firefox");

  let profile = firefox_root.join("Profiles/rookie-corpus.default-release");
  std::fs::create_dir_all(&profile).expect("create Firefox profile");
  std::fs::write(
    firefox_root.join("profiles.ini"),
    "[Profile0]\nName=rookie-corpus\nIsRelative=1\n\
     Path=Profiles/rookie-corpus.default-release\nDefault=1\n",
  )
  .expect("write profiles.ini");
  build_store(store, &profile.join("cookies.sqlite"));
}

fn isolated_command(home: &Path) -> Command {
  let mut command = Command::new(ROOKIE_BIN);
  command.env("RUST_LOG", "error");
  #[cfg(unix)]
  command.env("HOME", home);
  #[cfg(target_os = "windows")]
  command
    .env("APPDATA", home)
    .env("LOCALAPPDATA", home)
    .env("USERPROFILE", home);
  command
}

fn run(command: &mut Command, args: &[String]) -> std::process::Output {
  command.args(args).output().expect("spawn rookie-cookies")
}

fn stdout_of(context: &str, out: &std::process::Output) -> String {
  assert!(
    out.status.success(),
    "{context}: exited {:?}; stderr={}",
    out.status.code(),
    String::from_utf8_lossy(&out.stderr)
  );
  String::from_utf8(out.stdout.clone()).expect("utf-8 stdout")
}

/// Asserts the documented CLI error object: exit 1, no stdout, and a JSON
/// object on stderr carrying `code`, `message`, and -- for the two selector
/// codes -- `required`.
fn assert_selector_error(
  context: &str,
  out: &std::process::Output,
  code: &str,
  required: &[String],
) {
  assert_eq!(
    out.status.code(),
    Some(1),
    "{context}: a typed core failure is exit 1, not a usage error; stderr={}",
    String::from_utf8_lossy(&out.stderr)
  );
  assert!(
    out.stdout.is_empty(),
    "{context}: a refused request wrote stdout: {}",
    String::from_utf8_lossy(&out.stdout)
  );
  // Read warnings share stderr with the error object, so the object is the
  // last line rather than the whole stream.
  let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
  let last = stderr
    .lines()
    .next_back()
    .unwrap_or_else(|| panic!("{context}: empty stderr"));
  let document: Value = serde_json::from_str(last)
    .unwrap_or_else(|error| panic!("{context}: stderr is not JSON ({error}): {stderr}"));
  let fields = document
    .as_object()
    .unwrap_or_else(|| panic!("{context}: stderr JSON is not an object: {document}"));
  assert_eq!(
    fields.len(),
    3,
    "{context}: a selector failure carries exactly code, message, and required: {document}"
  );
  assert_eq!(document["code"], code, "{context}: wrong code");
  assert!(
    document["message"].as_str().is_some_and(|m| !m.is_empty()),
    "{context}: missing message: {document}"
  );
  let actual = document["required"]
    .as_array()
    .unwrap_or_else(|| panic!("{context}: required must be an array: {document}"))
    .iter()
    .map(|token| token.as_str().expect("required holds strings").to_owned())
    .collect::<Vec<_>>();
  assert_eq!(actual, required, "{context}: wrong required tokens");
}

/// Maps a corpus case context onto the `send-view`/`header` selector flags.
fn selector_args(context: &Value) -> Vec<String> {
  let mut args = vec![
    "--url".to_owned(),
    context["url"].as_str().expect("case url").to_owned(),
  ];
  for (key, flag) in [
    ("top_level_site", "--top-level-site"),
    ("first_party_domain", "--first-party-domain"),
    (
      "gecko_view_session_context_id",
      "--gecko-view-session-context-id",
    ),
    ("origin_attributes", "--origin-attributes"),
  ] {
    if let Some(value) = context.get(key) {
      args.push(flag.to_owned());
      args.push(value.as_str().expect("string selector").to_owned());
    }
  }
  for (key, flag) in [
    ("user_context_id", "--user-context-id"),
    ("private_browsing_id", "--private-browsing-id"),
    ("now", "--now"),
  ] {
    if let Some(value) = context.get(key) {
      args.push(flag.to_owned());
      args.push(value.as_u64().expect("numeric selector").to_string());
    }
  }
  if let Some(chain) = context.get("ancestor_chain") {
    args.push("--ancestor-chain".to_owned());
    // The corpus speaks the snake_case token vocabulary; the CLI spells its
    // values kebab-case, like every other enumerated flag.
    args.push(chain.as_str().expect("ancestor_chain").replace('_', "-"));
  }
  args
}

fn expected_ids(expect: &Value, field: &str) -> Vec<String> {
  expect[field]
    .as_array()
    .unwrap_or_else(|| panic!("{field} must be an array"))
    .iter()
    .map(|entry| entry.as_str().expect("id strings").to_owned())
    .collect()
}

/// The full omission table a case implies: its declared non-zero counts,
/// with every other reason explicitly zero.
fn expected_omissions(expect: &Value) -> BTreeMap<String, u64> {
  let declared = expect
    .get("omitted")
    .and_then(Value::as_object)
    .cloned()
    .unwrap_or_default();
  OMISSION_ORDER
    .iter()
    .map(|reason| {
      let count = declared
        .get(*reason)
        .map(|value| value.as_u64().expect("omission counts are integers"))
        .unwrap_or(0);
      ((*reason).to_owned(), count)
    })
    .collect()
}

fn assert_send_view(case_id: &str, home: &Path, case: &Value) {
  let context = &case["context"];
  let expect = &case["expect"];
  let mut args = vec!["send-view".to_owned()];
  args.extend(selector_args(context));
  args.extend(["--browser".to_owned(), "firefox".to_owned()]);
  let out = run(&mut isolated_command(home), &args);

  if let Some(error) = expect.get("error") {
    assert_selector_error(
      &format!("send-view {case_id}"),
      &out,
      error["code"].as_str().expect("error code"),
      &expected_ids(error, "required"),
    );
    return;
  }

  let document: Value = serde_json::from_str(&stdout_of(&format!("send-view {case_id}"), &out))
    .unwrap_or_else(|error| panic!("send-view {case_id}: stdout is not JSON: {error}"));

  let selected = document["cookies"]
    .as_array()
    .unwrap_or_else(|| panic!("send-view {case_id}: cookies must be an array"))
    .iter()
    .map(|record| {
      record["cookie"]["value"]
        .as_str()
        .expect("every corpus row's value is its id")
        .to_owned()
    })
    .collect::<Vec<_>>();
  assert_eq!(
    selected,
    expected_ids(expect, "selected"),
    "send-view {case_id}: wrong selected set or order"
  );
  assert_eq!(
    document["header"],
    *expect["header"].as_str().expect("case header"),
    "send-view {case_id}: wrong header"
  );

  let omitted = document["omitted"]
    .as_object()
    .unwrap_or_else(|| panic!("send-view {case_id}: omitted must be an object"));
  assert_eq!(
    omitted.keys().map(String::as_str).collect::<Vec<_>>(),
    OMISSION_ORDER,
    "send-view {case_id}: omitted must carry every reason in entries() order"
  );
  assert_eq!(
    omitted
      .iter()
      .map(|(reason, count)| (reason.clone(), count.as_u64().expect("counts are integers")))
      .collect::<BTreeMap<_, _>>(),
    expected_omissions(expect),
    "send-view {case_id}: wrong omission counts"
  );
}

fn assert_header(case_id: &str, home: &Path, case: &Value) {
  let expect = &case["expect"];
  let mut args = vec!["header".to_owned()];
  args.extend(selector_args(&case["context"]));
  args.extend(["--browser".to_owned(), "firefox".to_owned()]);
  let out = run(&mut isolated_command(home), &args);

  if let Some(error) = expect.get("error") {
    assert_selector_error(
      &format!("header {case_id}"),
      &out,
      error["code"].as_str().expect("error code"),
      &expected_ids(error, "required"),
    );
    return;
  }

  assert_eq!(
    stdout_of(&format!("header {case_id}"), &out).trim_end_matches('\n'),
    expect["header"].as_str().expect("case header"),
    "header {case_id}: wrong header"
  );
}

#[test]
fn send_view_and_header_reproduce_the_corpus_for_every_firefox_case() {
  let corpus = load_corpus();
  let stores = corpus["stores"].as_object().expect("corpus.stores");
  let mut ran = 0usize;

  for (name, store) in stores {
    if store["engine"] != "firefox" {
      continue;
    }
    let home = unique_tmpdir(name);
    seed_firefox_profile(home.path(), store);

    for case in corpus["cases"].as_array().expect("corpus.cases") {
      if case["store"] != *name {
        continue;
      }
      let case_id = case["id"].as_str().expect("case id");
      assert_send_view(case_id, home.path(), case);
      assert_header(case_id, home.path(), case);
      ran += 1;
    }
  }

  assert!(
    ran > 0,
    "the corpus declares no Firefox cases; this test would pass vacuously"
  );
}

#[test]
fn flat_formats_fail_closed_and_opt_in_per_store() {
  let corpus = load_corpus();
  let dir = unique_tmpdir("flat");

  for (name, store) in corpus["stores"].as_object().expect("corpus.stores") {
    let path = dir.path().join(format!("{name}.sqlite"));
    build_store(store, &path);
    let path = path.to_str().expect("utf-8 path").to_owned();
    let values = store["rows"]
      .as_array()
      .expect("store rows")
      .iter()
      .map(|row| row["value"].as_str().expect("row value").to_owned())
      .collect::<Vec<_>>();

    for format in ["json", "netscape"] {
      let base = vec![
        "from-path".to_owned(),
        path.clone(),
        "--format".to_owned(),
        format.to_owned(),
      ];
      let refused = run(&mut Command::new(ROOKIE_BIN), &base);
      let expect = &store["jar"]["expect"];

      if expect == "ok" {
        // Nothing isolated: the flat projection is already send-safe, so the
        // default must succeed without the opt-in.
        let text = stdout_of(&format!("{name} {format}"), &refused);
        for value in &values {
          assert!(
            text.contains(value),
            "{name} {format}: missing {value} in {text}"
          );
        }
      } else {
        let error = &expect["error"];
        assert_selector_error(
          &format!("{name} {format}"),
          &refused,
          error["code"].as_str().expect("jar error code"),
          &expected_ids(error, "required"),
        );
      }

      // The named opt-in always succeeds, and always holds every row: ADR
      // 0006 Decision 3 changes when a flat projection can fail, never what
      // a successful one contains.
      let mut allowed_args = base.clone();
      allowed_args.push("--allow-isolation-loss".to_owned());
      let allowed = run(&mut Command::new(ROOKIE_BIN), &allowed_args);
      let text = stdout_of(&format!("{name} {format} --allow-isolation-loss"), &allowed);
      for value in &values {
        assert!(
          text.contains(value),
          "{name} {format} --allow-isolation-loss: missing {value} in {text}"
        );
      }
    }

    // `detailed` carries the isolation the flat formats cannot, so it is
    // never refused and never needs the flag.
    let detailed = run(
      &mut Command::new(ROOKIE_BIN),
      &[
        "from-path".to_owned(),
        path.clone(),
        "--format".to_owned(),
        "detailed".to_owned(),
      ],
    );
    let text = stdout_of(&format!("{name} detailed"), &detailed);
    for value in &values {
      assert!(
        text.contains(value),
        "{name} detailed: missing {value} in {text}"
      );
    }
  }
}
