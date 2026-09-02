//! The Rust consumer of the cross-language isolation collision corpus.
//!
//! `tests/isolation_corpus/corpus.json` is the hand-authored oracle for ADR
//! 0006's send selection: per store, the rows a browser would have written;
//! per case, the `SendContext` a caller supplies and exactly which rows that
//! context selects, in header order, with the reason every other row was left
//! out. This file materializes those stores as real browser-shaped SQLite
//! databases -- the same schemas `tests/isolation_corpus/build_isolation_corpus.py`
//! writes, restated in Rust so the Rust lane has no Python dependency -- reads
//! them back through the public `from_path` entry point, and asserts the
//! corpus verdicts against `send_view`, `header`, `jar`, and `jar_with`.
//!
//! The point of a shared oracle is that Python, Node, and Rust cannot drift:
//! a case that passes here and fails in a binding is a binding that grew its
//! own copy of the predicate, which ADR 0006 Decision 2 exists to prevent.
//! Keeping the store construction in Rust and the expectations in JSON is
//! what makes that comparison meaningful -- only the expectations are shared.

use rookie_cookies::enums::Cookie;
use rookie_cookies::{
  from_path, AncestorChain, Error, FromPathRequest, IsolationLoss, ReadResult, RequestError,
  SendContext, SendView,
};
use rusqlite::types::Value as SqlValue;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, UNIX_EPOCH};

/// Mirrors `build_isolation_corpus.py`'s `CHROMIUM_COLUMNS`, minus the
/// `encrypted_value` blob it appends by hand (always empty here, so no
/// keychain or DPAPI is reachable from this test).
const CHROMIUM_COLUMNS: [&str; 13] = [
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
];

/// Mirrors `build_isolation_corpus.py`'s `FIREFOX_COLUMNS`.
const FIREFOX_COLUMNS: [&str; 9] = [
  "host",
  "name",
  "value",
  "path",
  "isSecure",
  "isHttpOnly",
  "sameSite",
  "expiry",
  "originAttributes",
];

const CHROMIUM_SCHEMA_VERSION: i64 = 24;
const FIREFOX_USER_VERSION: i64 = 16;

/// Every key a case's `context` may set.
///
/// A case naming anything else is a corpus this consumer does not fully
/// understand, and silently dropping the key would make the case pass while
/// testing the wrong context -- the exact failure a shared oracle exists to
/// prevent.
const HANDLED_CONTEXT_KEYS: [&str; 9] = [
  "url",
  "top_level_site",
  "ancestor_chain",
  "user_context_id",
  "private_browsing_id",
  "first_party_domain",
  "gecko_view_session_context_id",
  "origin_attributes",
  "now",
];

/// A temp directory removed when the test that made it ends.
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
    "rookie-isolation-corpus-{}-{}-{}",
    tag,
    std::process::id(),
    n
  ));
  std::fs::create_dir_all(&dir).expect("temp dir");
  TestDir(dir)
}

fn corpus_path() -> PathBuf {
  Path::new(env!("CARGO_MANIFEST_DIR"))
    .parent()
    .expect("rookie-rs has a workspace parent")
    .join("tests")
    .join("isolation_corpus")
    .join("corpus.json")
}

fn read_json(path: &Path) -> Value {
  let text = std::fs::read_to_string(path)
    .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
  serde_json::from_str(&text).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn load_corpus() -> Value {
  read_json(&corpus_path())
}

/// Asserts the schemas restated above still match the generator's.
///
/// `build_isolation_corpus.py` writes `schema.json` next to the corpus; the
/// Rust lane duplicates those `CREATE TABLE`s so it needs no Python, and this
/// is what keeps the duplicate honest. A column added to the generator and
/// forgotten here would otherwise produce a store that reads back short
/// rather than a failure that names the drift.
fn assert_store_schema_matches_generator() {
  let schema = read_json(
    &corpus_path()
      .parent()
      .expect("corpus.json has a parent")
      .join("schema.json"),
  );

  // The generator lists `encrypted_value` with the rest; this file binds it
  // by hand as an empty blob, so it is appended for the comparison.
  let mut chromium = CHROMIUM_COLUMNS.map(str::to_owned).to_vec();
  chromium.push("encrypted_value".to_owned());
  assert_eq!(
    schema["chromium"]["columns"],
    serde_json::json!(chromium),
    "Chromium columns drifted from build_isolation_corpus.py"
  );
  assert_eq!(schema["chromium"]["table"], "cookies");
  assert_eq!(schema["chromium"]["meta_version"], CHROMIUM_SCHEMA_VERSION);
  assert_eq!(
    schema["chromium"]["meta_last_compatible_version"],
    CHROMIUM_SCHEMA_VERSION
  );

  assert_eq!(
    schema["firefox"]["columns"],
    serde_json::json!(FIREFOX_COLUMNS.map(str::to_owned).to_vec()),
    "Firefox columns drifted from build_isolation_corpus.py"
  );
  assert_eq!(schema["firefox"]["table"], "moz_cookies");
  assert_eq!(schema["firefox"]["user_version"], FIREFOX_USER_VERSION);
}

/// Binds one corpus row cell, preserving the JSON null that makes a Chromium
/// `has_cross_site_ancestor` genuinely absent rather than zero -- the whole
/// point of the `chromium_ancestor_unknown` row.
fn cell(row: &Value, column: &str) -> SqlValue {
  match row.get(column) {
    None | Some(Value::Null) => SqlValue::Null,
    Some(Value::String(text)) => SqlValue::Text(text.clone()),
    Some(Value::Number(number)) => SqlValue::Integer(
      number
        .as_i64()
        .unwrap_or_else(|| panic!("corpus column {column} must be an integer: {number}")),
    ),
    Some(other) => panic!("corpus column {column} has an unsupported type: {other}"),
  }
}

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
         encrypted_value BLOB NOT NULL
       );",
    )
    .expect("create chromium schema");
  for (key, value) in [
    ("version", CHROMIUM_SCHEMA_VERSION),
    ("last_compatible_version", CHROMIUM_SCHEMA_VERSION),
  ] {
    connection
      .execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)",
        rusqlite::params![key, value.to_string()],
      )
      .expect("write chromium meta");
  }
  let insert = format!(
    "INSERT INTO cookies ({}, encrypted_value) VALUES ({}, ?{})",
    CHROMIUM_COLUMNS.join(", "),
    (1..=CHROMIUM_COLUMNS.len())
      .map(|index| format!("?{index}"))
      .collect::<Vec<_>>()
      .join(", "),
    CHROMIUM_COLUMNS.len() + 1
  );
  for row in rows {
    let mut values = CHROMIUM_COLUMNS
      .iter()
      .map(|column| cell(row, column))
      .collect::<Vec<_>>();
    values.push(SqlValue::Blob(Vec::new()));
    connection
      .execute(&insert, rusqlite::params_from_iter(values))
      .expect("insert chromium corpus row");
  }
}

fn build_firefox_store(rows: &[Value], path: &Path) {
  let connection = rusqlite::Connection::open(path).expect("open firefox corpus store");
  connection
    .execute_batch(&format!(
      "PRAGMA user_version = {FIREFOX_USER_VERSION};
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
       );"
    ))
    .expect("create firefox schema");
  let insert = format!(
    "INSERT INTO moz_cookies ({}) VALUES ({})",
    FIREFOX_COLUMNS.join(", "),
    (1..=FIREFOX_COLUMNS.len())
      .map(|index| format!("?{index}"))
      .collect::<Vec<_>>()
      .join(", ")
  );
  for row in rows {
    let values = FIREFOX_COLUMNS
      .iter()
      .map(|column| cell(row, column))
      .collect::<Vec<_>>();
    connection
      .execute(&insert, rusqlite::params_from_iter(values))
      .expect("insert firefox corpus row");
  }
}

/// Materializes every corpus store into `dir`, keeping each one's path so a
/// consuming projection (`into_jar`) can re-open it.
fn build_stores(corpus: &Value, dir: &Path) -> BTreeMap<String, PathBuf> {
  let stores = corpus["stores"]
    .as_object()
    .expect("corpus.stores must be an object");
  let mut built = BTreeMap::new();
  for (name, store) in stores {
    let rows = store["rows"]
      .as_array()
      .unwrap_or_else(|| panic!("store {name} has no rows"));
    let path = dir.join(format!("{name}.sqlite"));
    match store["engine"].as_str() {
      Some("chromium") => build_chromium_store(rows, &path),
      Some("firefox") => build_firefox_store(rows, &path),
      other => panic!("store {name} has an unknown engine: {other:?}"),
    }
    built.insert(name.clone(), path);
  }
  built
}

/// Reads one materialized store back through the public portable entry point.
///
/// A store declaring `include_expired` is opened that way, because its rows
/// are the point: expiry at *read* time is what decides whether a row reaches
/// the snapshot, and expiry at *send* time drops it again regardless. The row
/// count is asserted so a store whose flag is wrong fails here rather than
/// silently short.
fn open_store(name: &str, path: &Path, expected_rows: usize, include_expired: bool) -> ReadResult {
  let result = from_path(FromPathRequest::new(path).include_expired(include_expired))
    .unwrap_or_else(|error| panic!("read corpus store {name}: {error}"));
  assert_eq!(
    result.detailed_cookies().len(),
    expected_rows,
    "store {name} lost rows between the corpus and the snapshot"
  );
  result
}

/// Whether the named store must be read with expired rows retained.
fn include_expired(corpus: &Value, name: &str) -> bool {
  corpus["stores"][name]
    .get("include_expired")
    .map(|flag| {
      flag
        .as_bool()
        .unwrap_or_else(|| panic!("store {name}: include_expired must be a boolean"))
    })
    .unwrap_or(false)
}

fn store_rows(corpus: &Value, name: &str) -> usize {
  corpus["stores"][name]["rows"]
    .as_array()
    .expect("store rows")
    .len()
}

fn open_stores(corpus: &Value, paths: &BTreeMap<String, PathBuf>) -> BTreeMap<String, ReadResult> {
  paths
    .iter()
    .map(|(name, path)| {
      let result = open_store(
        name,
        path,
        store_rows(corpus, name),
        include_expired(corpus, name),
      );
      (name.clone(), result)
    })
    .collect()
}

fn send_context(case_id: &str, context: &Value) -> SendContext {
  for key in context
    .as_object()
    .unwrap_or_else(|| panic!("case {case_id}: context must be an object"))
    .keys()
  {
    assert!(
      HANDLED_CONTEXT_KEYS.contains(&key.as_str()),
      "case {case_id}: context key {key} is not one this consumer applies; \
       a dropped selector would make the case pass against the wrong context"
    );
  }
  let url = context["url"]
    .as_str()
    .unwrap_or_else(|| panic!("case {case_id} has no url"));
  let mut send = SendContext::url(url);
  if let Some(site) = context.get("top_level_site") {
    send = send.top_level_site(
      site
        .as_str()
        .unwrap_or_else(|| panic!("case {case_id}: top_level_site must be a string")),
    );
  }
  if let Some(chain) = context.get("ancestor_chain") {
    send = send.ancestor_chain(match chain.as_str() {
      Some("same_site") => AncestorChain::SameSite,
      Some("cross_site") => AncestorChain::CrossSite,
      other => panic!("case {case_id}: unknown ancestor_chain {other:?}"),
    });
  }
  if let Some(id) = context.get("user_context_id") {
    send = send.user_context_id(unsigned(case_id, "user_context_id", id));
  }
  if let Some(id) = context.get("private_browsing_id") {
    send = send.private_browsing_id(unsigned(case_id, "private_browsing_id", id));
  }
  if let Some(domain) = context.get("first_party_domain") {
    send = send.first_party_domain(
      domain
        .as_str()
        .unwrap_or_else(|| panic!("case {case_id}: first_party_domain must be a string")),
    );
  }
  if let Some(id) = context.get("gecko_view_session_context_id") {
    send =
      send.gecko_view_session_context_id(id.as_str().unwrap_or_else(|| {
        panic!("case {case_id}: gecko_view_session_context_id must be a string")
      }));
  }
  if let Some(attributes) = context.get("origin_attributes") {
    send = send.origin_attributes(
      attributes
        .as_str()
        .unwrap_or_else(|| panic!("case {case_id}: origin_attributes must be a string")),
    );
  }
  if let Some(now) = context.get("now") {
    let seconds = now
      .as_u64()
      .unwrap_or_else(|| panic!("case {case_id}: now must be epoch seconds"));
    send = send.now(UNIX_EPOCH + Duration::from_secs(seconds));
  }
  send
}

fn unsigned(case_id: &str, field: &str, value: &Value) -> u32 {
  u32::try_from(
    value
      .as_u64()
      .unwrap_or_else(|| panic!("case {case_id}: {field} must be a non-negative integer")),
  )
  .unwrap_or_else(|_| panic!("case {case_id}: {field} does not fit in u32"))
}

/// The corpus identifies each row by its value, which every store sets equal
/// to the row's `id`, so a selected set reads back as the corpus id list.
fn selected_values(view: &SendView<'_>) -> Vec<String> {
  view
    .cookies()
    .iter()
    .map(|record| record.cookie.value.clone())
    .collect()
}

fn expected_strings(case_id: &str, field: &str, value: &Value) -> Vec<String> {
  value
    .as_array()
    .unwrap_or_else(|| panic!("case {case_id}: {field} must be an array"))
    .iter()
    .map(|entry| {
      entry
        .as_str()
        .unwrap_or_else(|| panic!("case {case_id}: {field} must hold strings"))
        .to_owned()
    })
    .collect()
}

/// The omission counts a case declares, which name only the non-zero buckets.
fn expected_omissions(case_id: &str, expect: &Value) -> BTreeMap<String, u64> {
  let Some(omitted) = expect.get("omitted") else {
    return BTreeMap::new();
  };
  omitted
    .as_object()
    .unwrap_or_else(|| panic!("case {case_id}: omitted must be an object"))
    .iter()
    .map(|(reason, count)| {
      (
        reason.clone(),
        count
          .as_u64()
          .unwrap_or_else(|| panic!("case {case_id}: omitted.{reason} must be a count")),
      )
    })
    .collect()
}

fn actual_omissions(view: &SendView<'_>) -> BTreeMap<String, u64> {
  view
    .omitted()
    .entries()
    .filter(|(_, count)| *count > 0)
    .map(|(reason, count)| (reason.to_owned(), count))
    .collect()
}

/// The `required` list of the two selector errors, which ADR 0006 Decision 5
/// draws from one shared token vocabulary.
fn required_tokens(case_id: &str, error: &Error) -> Vec<String> {
  match error {
    Error::Request(RequestError::IncompleteSendContext { required, .. })
    | Error::Request(RequestError::IsolationLossRefused { required, .. }) => required.clone(),
    other => panic!("case {case_id}: expected a selector error, got {other:?}"),
  }
}

fn assert_case(case: &Value, stores: &BTreeMap<String, ReadResult>) {
  let case_id = case["id"].as_str().expect("case id");
  let store_name = case["store"].as_str().expect("case store");
  let result = stores
    .get(store_name)
    .unwrap_or_else(|| panic!("case {case_id} names an unknown store {store_name}"));
  let context = send_context(case_id, &case["context"]);
  let expect = &case["expect"];

  if let Some(error) = expect.get("error") {
    let code = error["code"].as_str().expect("error code");
    let required = expected_strings(case_id, "error.required", &error["required"]);

    let failure = result
      .send_view(&context)
      .err()
      .unwrap_or_else(|| panic!("case {case_id}: send_view must refuse an incomplete selector"));
    assert_eq!(failure.code(), code, "case {case_id}: wrong error code");
    assert_eq!(
      required_tokens(case_id, &failure),
      required,
      "case {case_id}: wrong required tokens"
    );

    // `header` is a renderer over `send_view`, so it must fail identically
    // rather than reaching a second, more permissive predicate.
    let header_failure = result
      .header(&context)
      .err()
      .unwrap_or_else(|| panic!("case {case_id}: header must refuse the same selector"));
    assert_eq!(
      header_failure.code(),
      code,
      "case {case_id}: header disagreed with send_view"
    );
    assert_eq!(
      required_tokens(case_id, &header_failure),
      required,
      "case {case_id}: header demanded different tokens than send_view"
    );
    return;
  }

  let view = result
    .send_view(&context)
    .unwrap_or_else(|error| panic!("case {case_id}: send_view failed: {error}"));

  assert_eq!(
    selected_values(&view),
    expected_strings(case_id, "selected", &expect["selected"]),
    "case {case_id}: wrong selected set or order"
  );
  assert_eq!(
    view.header(),
    expect["header"].as_str().expect("case header"),
    "case {case_id}: wrong header"
  );
  assert_eq!(
    actual_omissions(&view),
    expected_omissions(case_id, expect),
    "case {case_id}: wrong omission counts"
  );

  // Structural: the string `header()` returns is exactly what the view it
  // renders would render, for the same context (ADR 0006 Decision 2).
  let rendered = result
    .header(&context)
    .unwrap_or_else(|error| panic!("case {case_id}: header failed: {error}"));
  assert_eq!(
    rendered,
    view.header(),
    "case {case_id}: header diverged from send_view().header()"
  );
}

fn assert_jar(store_name: &str, store: &Value, result: &ReadResult, consuming: ReadResult) {
  // The opt-in is byte-for-byte the inventory projection, in every store:
  // ADR 0006 Decision 3 changes when a jar can fail, never what a successful
  // one holds.
  let allowed = result
    .jar_with(IsolationLoss::Allow)
    .unwrap_or_else(|error| {
      panic!("store {store_name}: the explicit opt-in must succeed: {error}")
    });
  assert_eq!(
    allowed,
    result.cookies(),
    "store {store_name}: jar_with(Allow) is not the inventory projection"
  );

  let expect = &store["jar"]["expect"];
  if expect == "ok" {
    let jar = result
      .jar()
      .unwrap_or_else(|error| panic!("store {store_name}: unisolated jar must succeed: {error}"));
    assert_eq!(
      jar,
      result.cookies(),
      "store {store_name}: a successful jar is the inventory projection"
    );
    let owned: Vec<Cookie> = jar.to_vec();
    assert_eq!(
      consuming
        .into_jar()
        .unwrap_or_else(|error| panic!("store {store_name}: into_jar must agree: {error}")),
      owned,
      "store {store_name}: into_jar disagreed with jar"
    );
    return;
  }

  let error = &expect["error"];
  let code = error["code"].as_str().expect("jar error code");
  let required = expected_strings(store_name, "jar.error.required", &error["required"]);
  let failure = result
    .jar()
    .err()
    .unwrap_or_else(|| panic!("store {store_name}: an isolated jar must refuse"));
  assert_eq!(
    failure.code(),
    code,
    "store {store_name}: wrong jar error code"
  );
  assert_eq!(
    required_tokens(store_name, &failure),
    required,
    "store {store_name}: wrong jar required tokens"
  );

  // The owning twin refuses on the same predicate, not a looser one.
  let owning_failure = consuming
    .into_jar()
    .err()
    .unwrap_or_else(|| panic!("store {store_name}: into_jar must refuse too"));
  assert_eq!(
    owning_failure.code(),
    code,
    "store {store_name}: into_jar disagreed with jar"
  );
  assert_eq!(
    required_tokens(store_name, &owning_failure),
    required,
    "store {store_name}: into_jar demanded different tokens than jar"
  );
}

#[test]
fn corpus_cases_select_exactly_what_the_oracle_declares() {
  let corpus = load_corpus();
  assert_eq!(
    corpus["kind"], "isolation-collision-corpus",
    "corpus.json is not the isolation corpus"
  );
  assert_store_schema_matches_generator();
  let dir = unique_tmpdir("cases");
  let paths = build_stores(&corpus, dir.path());
  let stores = open_stores(&corpus, &paths);

  let cases = corpus["cases"].as_array().expect("corpus.cases");
  assert!(!cases.is_empty(), "the corpus declares no cases");

  // Every case is run even after one fails. A corpus is a table, and the
  // useful signal when the selector changes is which rows of that table moved
  // -- not the first one alphabetically. Each failure still prints its own
  // panic message; this collects the ids so the summary names all of them.
  let mut failed = Vec::new();
  for case in cases {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      assert_case(case, &stores);
    }));
    if outcome.is_err() {
      failed.push(case["id"].as_str().unwrap_or("<unnamed>").to_owned());
    }
  }
  assert!(
    failed.is_empty(),
    "{} of {} corpus cases failed: {}",
    failed.len(),
    cases.len(),
    failed.join(", ")
  );

  // Every omission reason must be non-zero somewhere in the corpus. A reason
  // no case ever reaches is a reason no consumer is actually checked against,
  // so the oracle would keep passing if that bucket were mis-attributed.
  let mut seen = BTreeMap::new();
  for case in cases {
    for (reason, count) in
      expected_omissions(case["id"].as_str().unwrap_or("<unnamed>"), &case["expect"])
    {
      *seen.entry(reason).or_insert(0u64) += count;
    }
  }
  for reason in [
    "expired",
    "not_applicable",
    "same_site",
    "partition",
    "ancestor_chain_unknown",
    "unparsable_partition_key",
    "origin",
  ] {
    assert!(
      seen.get(reason).copied().unwrap_or(0) > 0,
      "no corpus case exercises the {reason} omission; \
       that bucket is unverified in every language"
    );
  }
}

#[test]
fn corpus_stores_agree_on_the_jar_verdict() {
  let corpus = load_corpus();
  let dir = unique_tmpdir("jars");
  let paths = build_stores(&corpus, dir.path());
  let stores = open_stores(&corpus, &paths);

  for (name, store) in corpus["stores"].as_object().expect("corpus.stores") {
    let result = stores.get(name).expect("every store was opened");
    let consuming = open_store(
      name,
      &paths[name],
      store_rows(&corpus, name),
      include_expired(&corpus, name),
    );
    assert_jar(name, store, result, consuming);
  }
}
