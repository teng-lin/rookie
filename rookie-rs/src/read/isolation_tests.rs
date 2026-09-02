//! Isolation identity as it arrives from a real store.
//!
//! The unit tests in `crate::isolation` cover the parsers against strings.
//! These go through `from_path` against actual SQLite files, because the cases
//! that matter most are *schema* variants: a column an older browser never
//! wrote, or one whose value is not the type the column claims. Those cannot
//! be expressed by constructing a `CookieContext` by hand.

use super::*;
use crate::direct_path::ChromiumCredentialSource;
use crate::AncestorChain;
use std::path::Path;
use std::time::Duration;

fn epoch(seconds: u64) -> SystemTime {
  UNIX_EPOCH + Duration::from_secs(seconds)
}

fn context(url: &str) -> SendContext {
  SendContext::url(url).now(epoch(1_000))
}

/// Seeds one partitioned Chromium row.
///
/// `ancestor` is the SQL literal stored in `has_cross_site_ancestor`, or
/// `None` to omit the column entirely the way a pre-2024 schema does.
fn seed_chromium(path: &Path, key: &str, ancestor: Option<&str>) {
  let connection = rusqlite::Connection::open(path).expect("open chromium fixture");
  let (declaration, value) = match ancestor {
    None => (String::new(), String::new()),
    Some(literal) => (
      ", has_cross_site_ancestor INTEGER".to_owned(),
      format!(", {literal}"),
    ),
  };
  connection
    .execute_batch(&format!(
      "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
       INSERT INTO meta VALUES ('version', '24');
       CREATE TABLE cookies (
         host_key TEXT NOT NULL, path TEXT NOT NULL, is_secure INTEGER NOT NULL,
         expires_utc INTEGER NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
         encrypted_value BLOB NOT NULL, is_httponly INTEGER NOT NULL,
         samesite INTEGER NOT NULL, top_frame_site_key TEXT NOT NULL{declaration}
       );
       INSERT INTO cookies VALUES ('.example.test', '/', 0, 0, 'chips', 'partitioned',
         X'', 0, 0, '{key}'{value});"
    ))
    .expect("create chromium cookies");
}

fn chromium_snapshot(
  name: &str,
  key: &str,
  ancestor: Option<&str>,
) -> (crate::utils::TempDir, ReadResult) {
  let dir = crate::utils::TempDir::new().expect("temp dir");
  let database = dir.path().join(format!("{name}.sqlite"));
  seed_chromium(&database, key, ancestor);
  let snapshot = from_path(
    FromPathRequest::new(&database)
      .chromium_credentials(ChromiumCredentialSource::PlaintextOnly)
      .include_expired(true),
  )
  .expect("chromium snapshot");
  (dir, snapshot)
}

/// Seeds one Firefox row. `origin_attributes` of `None` omits the column,
/// which is what a schema older than origin attributes looks like.
fn seed_firefox(path: &Path, origin_attributes: Option<&str>) {
  let connection = rusqlite::Connection::open(path).expect("open firefox fixture");
  let (declaration, value) = match origin_attributes {
    None => (String::new(), String::new()),
    Some(raw) => (
      ", originAttributes TEXT NOT NULL".to_owned(),
      format!(", '{raw}'"),
    ),
  };
  connection
    .execute_batch(&format!(
      "CREATE TABLE moz_cookies (
        host TEXT NOT NULL, path TEXT NOT NULL, isSecure INTEGER NOT NULL,
        expiry INTEGER NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
        isHttpOnly INTEGER NOT NULL, sameSite INTEGER NOT NULL{declaration}
      );
      INSERT INTO moz_cookies VALUES ('.example.test', '/', 0, 4102444800,
        'sid', 'value', 0, 0{value});"
    ))
    .expect("create moz_cookies");
}

fn firefox_snapshot(
  name: &str,
  origin_attributes: Option<&str>,
) -> (crate::utils::TempDir, ReadResult) {
  let dir = crate::utils::TempDir::new().expect("temp dir");
  let database = dir.path().join(format!("{name}.sqlite"));
  seed_firefox(&database, origin_attributes);
  let snapshot =
    from_path(FromPathRequest::new(&database).include_expired(true)).expect("firefox snapshot");
  (dir, snapshot)
}

fn warning(snapshot: &ReadResult, code: &str) -> u64 {
  snapshot
    .warnings()
    .iter()
    .find(|warning| warning.code() == code)
    .map(ReadWarning::count)
    .unwrap_or(0)
}

#[test]
fn a_stored_ancestor_bit_of_one_is_the_embedded_third_party_row() {
  let (_dir, snapshot) = chromium_snapshot("cross", "https://top.example", Some("1"));
  assert_eq!(warning(&snapshot, "unknown_ancestor_chain"), 0);

  // Embedded under another site: cross-site by derivation.
  let embedded = context("https://example.test/").top_level_site("https://top.example/");
  assert_eq!(
    snapshot.header(&embedded.clone()).expect("valid context"),
    "chips=partitioned"
  );

  // An explicit `SameSite` cannot make a cross-site request same-site, so it
  // does not turn this into the other identity.
  assert_eq!(
    snapshot
      .header(&embedded.ancestor_chain(AncestorChain::SameSite))
      .expect("valid context"),
    "chips=partitioned",
    "the selector has no force on a cross-site request"
  );

  // A first-party request is a different partition entirely.
  let view = snapshot
    .send_view(&context("https://example.test/").top_level_site("https://example.test/"))
    .expect("valid context");
  assert!(view.is_empty());
  assert_eq!(view.omitted().partition(), 1);
}

#[test]
fn a_stored_ancestor_bit_of_zero_is_the_first_party_row() {
  // A bit of 0 means the partition was set with no cross-site ancestor, which
  // only happens under the site's own top level.
  let (_dir, snapshot) = chromium_snapshot("same", "https://example.test", Some("0"));
  let first_party = context("https://example.test/").top_level_site("https://example.test/");

  assert_eq!(
    snapshot
      .header(&first_party.clone())
      .expect("valid context"),
    "chips=partitioned"
  );
  assert_eq!(
    snapshot
      .header(&first_party.ancestor_chain(AncestorChain::CrossSite))
      .expect("valid context"),
    "",
    "an A->B->A embed is the other identity"
  );

  // And it is never reachable from a third-party send, which is the whole
  // point of gating on the bit.
  assert_eq!(
    snapshot
      .header(
        &context("https://example.test/")
          .top_level_site("https://top.example/")
          .ancestor_chain(AncestorChain::SameSite)
      )
      .expect("valid context"),
    "",
    "an explicit SameSite must not admit a first-party row into a third-party send"
  );
}

#[test]
fn an_ancestor_bit_the_store_never_recorded_fails_closed_and_is_warned_about() {
  // Three ways a store can fail to state the bit: no column at all (pre-2024),
  // an explicit NULL, and a value that is not an integer.
  for (name, ancestor) in [
    ("absent", None),
    ("null", Some("NULL")),
    ("text", Some("'yes'")),
    // An integer that is neither 0 nor 1 is not "truthy" here: it is a value
    // the schema never defined, and reading it as `true` would invent an
    // ancestor state the browser never recorded.
    ("two", Some("2")),
  ] {
    let (_dir, snapshot) = chromium_snapshot(name, "https://top.example", ancestor);
    assert_eq!(
      snapshot.detailed_cookies().len(),
      1,
      "{name}: the row stays in the inventory"
    );
    assert_eq!(
      snapshot.detailed_cookies()[0]
        .context
        .has_cross_site_ancestor,
      None,
      "{name}: unknown, not false"
    );
    assert_eq!(
      warning(&snapshot, "unknown_ancestor_chain"),
      1,
      "{name}: the loss is counted at read time"
    );

    for chain in [AncestorChain::SameSite, AncestorChain::CrossSite] {
      let view = snapshot
        .send_view(
          &context("https://example.test/")
            .top_level_site("https://top.example/")
            .ancestor_chain(chain),
        )
        .expect("valid context");
      assert!(view.is_empty(), "{name}: {chain:?} must not resolve it");
      assert_eq!(view.omitted().ancestor_chain_unknown(), 1);
    }
  }
}

#[test]
fn an_empty_firefox_suffix_is_every_attribute_at_its_default() {
  for raw in ["", "^"] {
    let (_dir, snapshot) = firefox_snapshot("defaults", Some(raw));
    assert_eq!(
      snapshot
        .header(&context("https://example.test/").user_context_id(0))
        .expect("valid context"),
      "sid=value",
      "{raw:?} is every attribute at its default"
    );
    assert_eq!(
      snapshot
        .header(&context("https://example.test/").first_party_domain(""))
        .expect("valid context"),
      "sid=value",
      "{raw:?} covers the string attributes too"
    );
  }

  let (_dir, snapshot) = firefox_snapshot("defaults", Some(""));
  assert_eq!(
    snapshot.detailed_cookies()[0].context.origin_attributes,
    Some(String::new())
  );
  // Nothing is demanded, and the default container selects it.
  assert_eq!(
    snapshot
      .header(&context("https://example.test/"))
      .expect("valid context"),
    "sid=value"
  );
  assert_eq!(
    snapshot
      .header(&context("https://example.test/").user_context_id(0))
      .expect("valid context"),
    "sid=value"
  );
  assert_eq!(
    snapshot
      .header(&context("https://example.test/").user_context_id(2))
      .expect("valid context"),
    ""
  );
}

#[test]
fn a_store_with_no_origin_attributes_column_stays_unknown_rather_than_default() {
  let (_dir, snapshot) = firefox_snapshot("nocolumn", None);
  assert_eq!(
    snapshot.detailed_cookies()[0].context.origin_attributes,
    None
  );
  assert_eq!(
    snapshot
      .header(&context("https://example.test/"))
      .expect("valid context"),
    "sid=value",
    "an unknown value demands nothing"
  );
  assert_eq!(
    snapshot
      .header(&context("https://example.test/").user_context_id(0))
      .expect("valid context"),
    "",
    "but a supplied selector never matches it"
  );
}

#[test]
fn a_firefox_container_suffix_demands_and_then_selects_its_container() {
  let (_dir, snapshot) = firefox_snapshot("container", Some("^userContextId=2"));
  let error = snapshot
    .header(&context("https://example.test/"))
    .expect_err("a non-default container demands its selector");
  assert_eq!(error.code(), "incomplete_send_context");
  assert_eq!(
    snapshot
      .header(&context("https://example.test/").user_context_id(2))
      .expect("valid context"),
    "sid=value"
  );
}

#[test]
fn a_firefox_partition_suffix_is_read_out_of_the_origin_attributes() {
  let (_dir, snapshot) =
    firefox_snapshot("partition", Some("^partitionKey=%28https%2Ctop.example%29"));
  assert_eq!(
    snapshot.detailed_cookies()[0]
      .context
      .partition_key
      .as_deref(),
    Some("(https,top.example)")
  );
  assert_eq!(
    snapshot
      .header(&context("https://example.test/").top_level_site("https://top.example/"))
      .expect("valid context"),
    "sid=value"
  );
  assert_eq!(
    snapshot
      .header(&context("https://example.test/").top_level_site("https://other.example/"))
      .expect("valid context"),
    ""
  );
}

#[test]
fn an_unknown_firefox_attribute_survives_extraction_and_fails_closed_at_selection() {
  let suffix = "^futureAttr=1";
  let (_dir, snapshot) = firefox_snapshot("future", Some(suffix));
  assert_eq!(
    snapshot.detailed_cookies()[0]
      .context
      .origin_attributes
      .as_deref(),
    Some(suffix),
    "the raw value is retained for inventory"
  );
  let error = snapshot
    .header(&context("https://example.test/"))
    .expect_err("an unknown attribute is not the default context");
  assert_eq!(error.code(), "incomplete_send_context");
  assert_eq!(
    snapshot
      .header(&context("https://example.test/").origin_attributes(suffix))
      .expect("valid context"),
    "sid=value",
    "naming the stored value exactly is the only way in"
  );
}
