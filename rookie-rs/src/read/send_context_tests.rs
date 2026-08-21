//! `ReadResult::header` send-match tests.
//!
//! Kept beside the snapshot tests rather than in `header_filter.rs` because
//! every case here is about what a *snapshot* demands and emits, not about the
//! RFC 6265 predicates `header_filter` owns.

use super::*;
use crate::enums::CookieContext;
use std::time::Duration;

fn epoch(seconds: u64) -> SystemTime {
  UNIX_EPOCH + Duration::from_secs(seconds)
}

fn cookie(name: &str, same_site: i64) -> Cookie {
  Cookie {
    domain: ".example.test".to_owned(),
    path: "/".to_owned(),
    secure: false,
    expires: None,
    name: name.to_owned(),
    value: "value".to_owned(),
    http_only: false,
    same_site,
  }
}

fn snapshot(cookies: Vec<(Cookie, CookieContext)>) -> ReadResult {
  ReadResult::new(
    cookies
      .into_iter()
      .map(|(cookie, context)| DetailedCookie { cookie, context })
      .collect(),
    Vec::new(),
    Some("chrome".to_owned()),
    None,
  )
}

fn context(url: &str) -> SendContext {
  SendContext::url(url).now(epoch(1_000))
}

fn chips(key: &str) -> CookieContext {
  CookieContext {
    top_frame_site_key: Some(key.to_owned()),
    ..CookieContext::default()
  }
}

fn firefox_partition(key: &str) -> CookieContext {
  CookieContext {
    partition_key: Some(key.to_owned()),
    ..CookieContext::default()
  }
}

fn required(error: &crate::Error) -> Vec<String> {
  match error {
    crate::Error::Request(RequestError::IncompleteSendContext { required, .. }) => required.clone(),
    other => panic!("expected IncompleteSendContext, got {other:?}"),
  }
}

#[test]
fn one_partitioned_cookie_demands_the_top_level_site() {
  // One is enough. There is deliberately no "more than one identity"
  // threshold: a single partitioned cookie beside unpartitioned ones is
  // exactly the case where a merge would be silent.
  let result = snapshot(vec![
    (cookie("plain", 0), CookieContext::default()),
    (cookie("chips", 0), chips("https://top.example")),
  ]);
  let error = result
    .header(&context("https://example.test/"))
    .expect_err("a partitioned cookie with no selector cannot be sent safely");
  assert_eq!(error.code(), "incomplete_send_context");
  assert_eq!(required(&error), vec!["top_level_site"]);
}

#[test]
fn one_container_cookie_demands_the_user_context_id() {
  let result = snapshot(vec![(
    cookie("contained", 0),
    CookieContext {
      user_context_id: Some(2),
      ..CookieContext::default()
    },
  )]);
  let error = result
    .header(&context("https://example.test/"))
    .expect_err("a container cookie with no selector cannot be sent safely");
  assert_eq!(required(&error), vec!["user_context_id"]);
}

#[test]
fn none_and_zero_never_demand_a_selector() {
  // Gating on `None` or `Some(0)` would make `header` unusable against every
  // browser version whose schema predates these columns.
  let result = snapshot(vec![
    (
      cookie("absent", 0),
      CookieContext {
        user_context_id: None,
        private_browsing_id: None,
        ..CookieContext::default()
      },
    ),
    (
      cookie("default", 0),
      CookieContext {
        user_context_id: Some(0),
        private_browsing_id: Some(0),
        ..CookieContext::default()
      },
    ),
  ]);
  let header = result
    .header(&context("https://example.test/"))
    .expect("no selector is demanded");
  assert!(header.contains("absent=value"));
  assert!(header.contains("default=value"));
}

#[test]
fn required_tokens_come_back_in_contract_order() {
  let result = snapshot(vec![(
    cookie("everything", 0),
    CookieContext {
      top_frame_site_key: Some("https://top.example".to_owned()),
      user_context_id: Some(3),
      private_browsing_id: Some(1),
      ..CookieContext::default()
    },
  )]);
  let error = result
    .header(&context("https://example.test/"))
    .expect_err("three selectors are demanded");
  assert_eq!(
    required(&error),
    vec!["top_level_site", "user_context_id", "private_browsing_id"]
  );
}

#[test]
fn a_supplied_selector_omits_other_partitions_without_erroring() {
  let result = snapshot(vec![
    (cookie("here", 0), chips("https://top.example")),
    (cookie("elsewhere", 0), chips("https://other.example")),
    (cookie("plain", 0), CookieContext::default()),
  ]);
  let header = result
    .header(&context("https://example.test/").top_level_site("https://top.example/"))
    .expect("a supplied selector is not an error");
  assert!(header.contains("here=value"));
  assert!(
    !header.contains("elsewhere=value"),
    "another partition is omitted, not merged: {header}"
  );
  assert!(
    header.contains("plain=value"),
    "an unpartitioned cookie is sent in every top-level context: {header}"
  );
}

#[test]
fn a_firefox_partition_tuple_with_extra_fields_still_matches() {
  // The tuple is an open vocabulary. A trailing port, foreign-ancestor bit,
  // or anything a future Firefox adds must not make every dFPI cookie vanish
  // from every header.
  for key in [
    "(https,top.example)",
    "(https,top.example,8443)",
    "(https,top.example,,f)",
  ] {
    let result = snapshot(vec![(cookie("dfpi", 0), firefox_partition(key))]);
    let header = result
      .header(&context("https://example.test/").top_level_site("https://top.example/"))
      .expect("valid context");
    assert_eq!(header, "dfpi=value", "key {key} did not match");
  }
}

#[test]
fn a_chromium_key_matches_whether_it_is_stored_as_a_site_or_an_origin() {
  for key in [
    "https://top.example",
    "https://top.example/",
    "https://top.example:443",
    "https://TOP.example",
  ] {
    let result = snapshot(vec![(cookie("chips", 0), chips(key))]);
    let header = result
      .header(&context("https://example.test/").top_level_site("https://top.example/"))
      .expect("valid context");
    assert_eq!(header, "chips=value", "key {key} did not match");
  }
}

#[test]
fn an_unparsable_partition_key_is_omitted_and_counted_not_treated_as_unpartitioned() {
  let (kept, omitted) = filter_snapshot_at(
    vec![DetailedCookie {
      cookie: cookie("mystery", 0),
      context: firefox_partition("something-a-future-firefox-invented"),
    }],
    true,
    epoch(1_000),
  )
  .expect("valid clock");
  assert_eq!(kept.len(), 1, "the row stays in the inventory");
  assert_eq!(omitted.unparsable_partition_key, 1);

  // It demands a selector (it is not unpartitioned) and then matches nothing.
  let result = snapshot(vec![(
    cookie("mystery", 0),
    firefox_partition("something-a-future-firefox-invented"),
  )]);
  assert_eq!(
    required(
      &result
        .header(&context("https://example.test/"))
        .expect_err("an unrecognized key is not 'unpartitioned'")
    ),
    vec!["top_level_site"]
  );
  assert_eq!(
    result
      .header(&context("https://example.test/").top_level_site("https://top.example/"))
      .expect("valid context"),
    "",
    "an unrecognized key must not be sent into an arbitrary context"
  );
}

#[test]
fn a_container_selector_excludes_an_unlabelled_cookie() {
  let result = snapshot(vec![
    (
      cookie("labelled", 0),
      CookieContext {
        user_context_id: Some(2),
        ..CookieContext::default()
      },
    ),
    (cookie("unlabelled", 0), CookieContext::default()),
  ]);
  let header = result
    .header(&context("https://example.test/").user_context_id(2))
    .expect("valid context");
  assert_eq!(
    header, "labelled=value",
    "the crate does not know an unlabelled cookie belongs to container 2"
  );
}

#[test]
fn lax_and_strict_are_cross_site_under_the_site_rule() {
  let result = snapshot(vec![
    (cookie("strict", 2), CookieContext::default()),
    (cookie("lax", 1), CookieContext::default()),
    (cookie("unspecified", -1), CookieContext::default()),
    (cookie("none", 0), CookieContext::default()),
  ]);

  // Same site: everything is sent.
  let same_site = result
    .header(&context("https://example.test/").top_level_site("https://example.test/"))
    .expect("valid context");
  for name in ["strict", "lax", "unspecified", "none"] {
    assert!(same_site.contains(name), "{name} missing: {same_site}");
  }

  // Cross-site subresource: only SameSite=None survives.
  let cross_site = result
    .header(&context("https://example.test/").top_level_site("https://other.example/"))
    .expect("valid context");
  assert_eq!(cross_site, "none=value");

  // Cross-site safe navigation: Lax (and unspecified, which is Lax) return.
  let navigation = result
    .header(
      &context("https://example.test/")
        .top_level_site("https://other.example/")
        .navigation(),
    )
    .expect("valid context");
  assert!(navigation.contains("lax=value"));
  assert!(navigation.contains("unspecified=value"));
  assert!(navigation.contains("none=value"));
  assert!(
    !navigation.contains("strict=value"),
    "Strict never crosses a site boundary: {navigation}"
  );

  // ...but not an unsafe one.
  let unsafe_navigation = result
    .header(
      &context("https://example.test/")
        .top_level_site("https://other.example/")
        .navigation()
        .method(MethodClass::Unsafe),
    )
    .expect("valid context");
  assert_eq!(unsafe_navigation, "none=value");
}

#[test]
fn a_sibling_subdomain_is_cross_site_because_there_is_no_public_suffix_list() {
  // Conservative, and stated as a limitation rather than hidden behind the
  // word "schemeful": a browser would call these same-site.
  let result = snapshot(vec![(cookie("strict", 2), CookieContext::default())]);
  assert_eq!(
    result
      .header(&context("https://example.test/").top_level_site("https://cdn.example.test/"))
      .expect("valid context"),
    ""
  );
}

#[test]
fn same_site_none_over_http_is_unreachable_because_secure_already_filtered_it() {
  let mut secure_none = cookie("none", 0);
  secure_none.secure = true;
  let result = snapshot(vec![(secure_none, CookieContext::default())]);
  assert_eq!(
    result
      .header(&context("http://example.test/").top_level_site("https://other.example/"))
      .expect("valid context"),
    "",
    "the RFC 6265 Secure stage runs before SameSite"
  );
}

#[test]
fn an_expired_cookie_retained_by_include_expired_is_still_omitted_from_the_header() {
  let mut expired = cookie("stale", 0);
  expired.expires = Some(999);
  let result = snapshot(vec![(expired, CookieContext::default())]);
  assert_eq!(result.cookies().len(), 1, "inventory keeps it");
  assert_eq!(
    result
      .header(&context("https://example.test/"))
      .expect("valid context"),
    ""
  );
}

#[test]
fn an_invalid_top_level_site_is_rejected_rather_than_ignored() {
  // Ignoring it would fall back to the first-party assumption and send more
  // than the caller asked for.
  let result = snapshot(vec![(cookie("strict", 2), CookieContext::default())]);
  for raw in ["not a url", "ftp://top.example/"] {
    let error = result
      .header(&context("https://example.test/").top_level_site(raw))
      .expect_err("an unparseable top-level site is a request error");
    assert_eq!(error.code(), "invalid_top_level_site");
    assert!(!error.to_string().contains("not a url") || raw == "not a url");
  }
}

#[test]
fn an_omitted_top_level_site_assumes_first_party() {
  let result = snapshot(vec![(cookie("strict", 2), CookieContext::default())]);
  assert_eq!(
    result
      .header(&context("https://example.test/"))
      .expect("valid context"),
    "strict=value"
  );
}
