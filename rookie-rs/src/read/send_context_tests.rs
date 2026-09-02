//! `ReadResult::header` send-match tests.
//!
//! Kept beside the snapshot tests rather than in `header_filter.rs` because
//! every case here is about what a *snapshot* demands and emits, not about the
//! RFC 6265 predicates `header_filter` owns.

use super::*;
use crate::enums::CookieContext;
use crate::AncestorChain;
use std::time::Duration;

fn epoch(seconds: u64) -> SystemTime {
  UNIX_EPOCH + Duration::from_secs(seconds)
}

fn cookie(name: &str, same_site: i64) -> Cookie {
  cookie_for(".example.test", name, same_site)
}

fn cookie_for(domain: &str, name: &str, same_site: i64) -> Cookie {
  Cookie {
    domain: domain.to_owned(),
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

/// An ordinary CHIPS row: partitioned, embedded in a cross-site top level.
fn chips(key: &str) -> CookieContext {
  chips_with_ancestor(key, true)
}

fn chips_with_ancestor(key: &str, cross_site_ancestor: bool) -> CookieContext {
  CookieContext {
    top_frame_site_key: Some(key.to_owned()),
    has_cross_site_ancestor: Some(cross_site_ancestor),
    ..CookieContext::default()
  }
}

/// A row from a store written before Chromium added the ancestor column.
fn chips_without_ancestor(key: &str) -> CookieContext {
  CookieContext {
    top_frame_site_key: Some(key.to_owned()),
    has_cross_site_ancestor: None,
    ..CookieContext::default()
  }
}

/// A Firefox row exactly as the persistent lane decodes it, so a suffix that
/// carries `partitionKey` sets the partition too.
fn firefox_attributes(origin_attributes: &str) -> CookieContext {
  crate::browser::mozilla::firefox_cookie_context(Some(origin_attributes.to_owned()))
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
fn a_firefox_partition_tuple_matches_on_its_port_and_foreign_ancestor_fields() {
  // Through 0.6 every field after the host was discarded, so partitions
  // differing only by port or by the foreign-ancestor bit collided. Each
  // field is now part of the identity.
  let dfpi = |key: &str| snapshot(vec![(cookie("dfpi", 0), firefox_partition(key))]);
  let embedded = context("https://example.test/").top_level_site("https://top.example/");

  assert_eq!(
    dfpi("(https,top.example)")
      .header(&embedded)
      .expect("valid"),
    "dfpi=value"
  );

  // A tuple carrying a port only matches a top-level site with that port.
  assert_eq!(
    dfpi("(https,top.example,8443)")
      .header(&embedded)
      .expect("valid"),
    "",
    "a ported partition must not match a default-port top-level site"
  );
  assert_eq!(
    dfpi("(https,top.example,8443)")
      .header(&context("https://example.test/").top_level_site("https://top.example:8443/"))
      .expect("valid"),
    "dfpi=value"
  );

  // `f` is foreignByAncestorContext: the top level is the request's own site,
  // reached through a cross-site ancestor. That is not the embedded case.
  assert_eq!(
    dfpi("(https,top.example,f)")
      .header(&embedded)
      .expect("valid"),
    "",
  );
  assert_eq!(
    dfpi("(https,example.test,f)")
      .header(
        &context("https://example.test/")
          .top_level_site("https://example.test/")
          .ancestor_chain(AncestorChain::CrossSite)
      )
      .expect("valid"),
    "dfpi=value",
    "an A->B->A embed is what the foreign-ancestor bit records"
  );
}

#[test]
fn the_firefox_tuple_grammar_is_strict_and_anything_else_matches_nothing() {
  // An unrecognized tuple is `Unparsable`: it still demands `top_level_site`
  // and then matches nothing, rather than matching on the fields that
  // happened to parse.
  for key in [
    "(https,top.example,,f)",
    "(https,top.example,8443,x)",
    "(https,top.example,http)",
    "(https,top.example,8443,f,extra)",
    "(ftp,top.example)",
    "(https,)",
    "https,top.example",
  ] {
    let result = snapshot(vec![(cookie("dfpi", 0), firefox_partition(key))]);
    assert_eq!(
      required(
        &result
          .header(&context("https://example.test/"))
          .expect_err("an unparsable key is not unpartitioned")
      ),
      vec!["top_level_site"],
      "key {key} should still demand a selector"
    );
    assert_eq!(
      result
        .header(&context("https://example.test/").top_level_site("https://top.example/"))
        .expect("valid context"),
      "",
      "key {key} must not be sent into an arbitrary context"
    );
  }
}

#[test]
fn a_partitioned_firefox_row_never_matches_a_first_party_context() {
  // A partition is, by construction, not the unpartitioned default context.
  let result = snapshot(vec![
    (cookie("dfpi", 0), firefox_partition("(https,example.test)")),
    (cookie("plain", 0), CookieContext::default()),
  ]);
  assert_eq!(
    result
      .header(&context("https://example.test/").top_level_site("https://example.test/"))
      .expect("valid context"),
    "plain=value"
  );
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
fn a_child_subdomain_is_same_site_but_a_sibling_is_not() {
  // The rule is "equal host, or a subdomain of it, on the same scheme".
  // Siblings stay cross-site because neither is a suffix of the other, which
  // is what keeps this sound without a public-suffix list.
  let strict = |url: &str, top: &str| {
    snapshot(vec![(cookie("strict", 2), CookieContext::default())])
      .header(&context(url).top_level_site(top))
      .expect("valid context")
  };

  assert_eq!(
    strict("https://www.example.test/", "https://example.test/"),
    "strict=value",
    "a child subdomain under its parent site is same-site"
  );
  assert_eq!(
    strict("https://example.test/", "https://example.test/"),
    "strict=value"
  );
  assert_eq!(
    strict("https://a.example.test/", "https://b.example.test/"),
    "",
    "siblings are cross-site: neither is a subdomain of the other"
  );
  assert_eq!(
    strict("https://example.test/", "https://www.example.test/"),
    "",
    "a parent under its own child is not within it"
  );
  assert_eq!(
    strict("https://www.example.test/", "http://example.test/"),
    "",
    "the scheme is part of the site"
  );
  assert_eq!(
    strict("https://evilexample.test/", "https://example.test/"),
    "",
    "a suffix that is not at a dot boundary is a different site"
  );
}

#[test]
fn ip_literals_and_idn_hosts_compare_exactly() {
  let strict = |domain: &str, url: &str, top: &str| {
    snapshot(vec![(
      cookie_for(domain, "strict", 2),
      CookieContext::default(),
    )])
    .header(&context(url).top_level_site(top))
    .expect("valid context")
  };

  // An IP literal requires exact equality; see `isolation::tests` for the
  // dot-boundary hazard this guards against.
  assert_eq!(
    strict("127.0.0.1", "http://127.0.0.1/", "http://127.0.0.1/"),
    "strict=value"
  );
  assert_eq!(
    strict("127.0.0.1", "http://127.0.0.1/", "http://0.0.1/"),
    ""
  );
  assert_eq!(
    strict("::1", "http://[::1]/", "http://[::1]/"),
    "strict=value"
  );
  assert_eq!(strict("::1", "http://[::1]/", "http://[::2]/"), "");

  // An IDN host is compared in its normalized (punycode) form on both sides.
  assert_eq!(
    strict(
      "xn--bcher-kva.test",
      "https://xn--bcher-kva.test/",
      "https://b\u{fc}cher.test/"
    ),
    "strict=value"
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

#[test]
fn the_chromium_ancestor_bit_splits_two_rows_that_used_to_collide() {
  // The whole point of gating on the bit: same top-level site, different
  // ancestor chains, previously both matched one context.
  let result = snapshot(vec![
    (
      cookie("cross", 0),
      chips_with_ancestor("https://top.example", true),
    ),
    (
      cookie("same", 0),
      chips_with_ancestor("https://example.test", false),
    ),
    (
      cookie("nested", 0),
      chips_with_ancestor("https://example.test", true),
    ),
  ]);

  // Embedded under a different top-level site: cross-site by derivation.
  assert_eq!(
    result
      .header(&context("https://example.test/").top_level_site("https://top.example/"))
      .expect("valid context"),
    "cross=value"
  );
  // First-party under its own site: same-site by derivation.
  assert_eq!(
    result
      .header(&context("https://example.test/").top_level_site("https://example.test/"))
      .expect("valid context"),
    "same=value"
  );
  // Same top-level site, but reached through a cross-site ancestor. Only an
  // explicit selector can express this, and it selects the other row.
  assert_eq!(
    result
      .header(
        &context("https://example.test/")
          .top_level_site("https://example.test/")
          .ancestor_chain(AncestorChain::CrossSite)
      )
      .expect("valid context"),
    "nested=value"
  );
}

#[test]
fn a_chromium_row_without_an_ancestor_bit_fails_closed_and_is_counted() {
  // Only pre-2024 stores lack the column. The row's own identity is what is
  // missing, so no selector can rescue it.
  let result = snapshot(vec![(
    cookie("legacy", 0),
    chips_without_ancestor("https://top.example"),
  )]);
  for chain in [AncestorChain::SameSite, AncestorChain::CrossSite] {
    let view = result
      .send_view(
        &context("https://example.test/")
          .top_level_site("https://top.example/")
          .ancestor_chain(chain),
      )
      .expect("valid context");
    assert!(view.is_empty(), "{chain:?} must not resolve a missing bit");
    assert_eq!(view.omitted().ancestor_chain_unknown(), 1);
  }

  // And it is counted at read time, the way an unparsable key is.
  let (kept, omitted) = filter_snapshot_at(
    vec![DetailedCookie {
      cookie: cookie("legacy", 0),
      context: chips_without_ancestor("https://top.example"),
    }],
    true,
    epoch(1_000),
  )
  .expect("valid clock");
  assert_eq!(kept.len(), 1, "the row stays in the inventory");
  assert_eq!(omitted.unknown_ancestor_chain, 1);
}

#[test]
fn first_party_domain_and_gecko_view_session_are_demanded_and_matched() {
  for (attribute, token, value) in [
    ("firstPartyDomain", "first_party_domain", "example.org"),
    (
      "geckoViewSessionContextId",
      "gecko_view_session_context_id",
      "session-7",
    ),
  ] {
    let result = snapshot(vec![
      (
        cookie("labelled", 0),
        firefox_attributes(&format!("^{attribute}={value}")),
      ),
      (cookie("plain", 0), firefox_attributes("")),
    ]);

    let error = result
      .header(&context("https://example.test/"))
      .expect_err("a non-default origin attribute demands its selector");
    assert_eq!(required(&error), vec![token.to_owned()]);

    let selected = if token == "first_party_domain" {
      context("https://example.test/").first_party_domain(value)
    } else {
      context("https://example.test/").gecko_view_session_context_id(value)
    };
    assert_eq!(
      result.header(&selected).expect("valid context"),
      "labelled=value",
      "a row without the attribute is not in this context"
    );
  }
}

#[test]
fn an_unrecognized_origin_attribute_fails_closed_until_it_is_named_exactly() {
  let suffix = "^futureAttr=1";
  let result = snapshot(vec![
    (cookie("future", 0), firefox_attributes(suffix)),
    (cookie("plain", 0), firefox_attributes("")),
  ]);

  let error = result
    .header(&context("https://example.test/"))
    .expect_err("an unknown attribute is not the default context");
  assert_eq!(required(&error), vec!["origin_attributes"]);

  // The verbatim value is the only way in for the opaque row, and it leaves
  // every readable row alone: the raw selector governs opaque rows only.
  assert_eq!(
    result
      .header(&context("https://example.test/").origin_attributes(suffix))
      .expect("valid context"),
    "future=value; plain=value"
  );
  assert_eq!(
    result
      .header(&context("https://example.test/").origin_attributes("^futureAttr=2"))
      .expect("valid context"),
    "plain=value",
    "a different value is a different context for the opaque row only"
  );
}

#[test]
fn an_empty_origin_attributes_suffix_means_every_attribute_is_default() {
  // Firefox omits default-valued attributes, so an empty suffix is a positive
  // statement that the row is in container 0 -- not an unknown.
  let result = snapshot(vec![(cookie("plain", 0), firefox_attributes(""))]);
  assert_eq!(
    result
      .header(&context("https://example.test/").user_context_id(0))
      .expect("valid context"),
    "plain=value"
  );
  assert_eq!(
    result
      .header(&context("https://example.test/").user_context_id(2))
      .expect("valid context"),
    ""
  );

  // A row with no origin-attributes value at all stays genuinely unknown.
  let unknown = snapshot(vec![(cookie("unlabelled", 0), CookieContext::default())]);
  assert_eq!(
    unknown
      .header(&context("https://example.test/").user_context_id(0))
      .expect("valid context"),
    "",
    "a supplied selector never matches an unknown stored value"
  );
}

#[test]
fn every_demand_token_comes_back_in_the_declared_order() {
  let result = snapshot(vec![(
    cookie("everything", 0),
    CookieContext {
      partition_key: Some("(https,top.example)".to_owned()),
      user_context_id: Some(3),
      private_browsing_id: Some(1),
      origin_attributes: Some(
        "^userContextId=3&privateBrowsingId=1&firstPartyDomain=example.org&geckoViewSessionContextId=session-7&futureAttr=1"
          .to_owned(),
      ),
      ..CookieContext::default()
    },
  )]);
  let error = result
    .header(&context("https://example.test/"))
    .expect_err("six selectors are demanded");
  assert_eq!(
    required(&error),
    vec![
      "top_level_site",
      "user_context_id",
      "private_browsing_id",
      "first_party_domain",
      "gecko_view_session_context_id",
      "origin_attributes",
    ]
  );
}

#[test]
fn send_view_and_header_are_the_same_selection_in_the_same_order() {
  let mut deep = cookie("deep", 0);
  deep.path = "/admin/panel".to_owned();
  let mut shallow = cookie("shallow", 0);
  shallow.path = "/".to_owned();
  let result = snapshot(vec![
    (shallow, CookieContext::default()),
    (deep, CookieContext::default()),
    (cookie("alpha", 0), CookieContext::default()),
  ]);
  let context = context("https://example.test/admin/panel");

  let view = result.send_view(&context).expect("valid context");
  assert_eq!(
    view
      .cookies()
      .iter()
      .map(|detailed| detailed.cookie.name.as_str())
      .collect::<Vec<_>>(),
    vec!["deep", "alpha", "shallow"],
    "longest path first, then by name"
  );
  assert_eq!(view.header(), result.header(&context).expect("valid"));
  assert_eq!(view.len(), 3);
  assert!(!view.is_empty());
  assert_eq!(view.to_detailed_cookies().len(), 3);
}

#[test]
fn each_omitted_row_is_counted_once_under_the_stage_it_failed() {
  let mut expired = cookie("expired", 0);
  expired.expires = Some(999);
  // Expiry runs before the isolation verdict, so a stale row in a foreign
  // partition is counted as expired rather than as a partition mismatch.
  let mut expired_partitioned = cookie("expired_partitioned", 0);
  expired_partitioned.expires = Some(999);
  let result = snapshot(vec![
    (expired, CookieContext::default()),
    (expired_partitioned, chips("https://other.example")),
    // ...and the isolation verdict runs before SameSite, so a Strict row in a
    // foreign partition is a partition mismatch, not a SameSite omission.
    (
      cookie("strict_partitioned", 2),
      chips("https://other.example"),
    ),
    (
      cookie_for(".other.test", "elsewhere", 0),
      CookieContext::default(),
    ),
    (cookie("strict", 2), CookieContext::default()),
    (cookie("otherpartition", 0), chips("https://other.example")),
    (
      cookie("legacy", 0),
      chips_without_ancestor("https://top.example"),
    ),
    (cookie("mystery", 0), firefox_partition("not-a-tuple")),
    (cookie("sent", 0), chips("https://top.example")),
  ]);

  let view = result
    .send_view(&context("https://example.test/").top_level_site("https://top.example/"))
    .expect("valid context");

  assert_eq!(view.header(), "sent=value");
  let omitted = view.omitted();
  assert_eq!(omitted.expired(), 2);
  assert_eq!(omitted.not_applicable(), 1);
  assert_eq!(omitted.same_site(), 1);
  assert_eq!(omitted.partition(), 2);
  assert_eq!(omitted.ancestor_chain_unknown(), 1);
  assert_eq!(omitted.unparsable_partition_key(), 1);
  assert_eq!(omitted.origin(), 0);
  assert_eq!(omitted.total(), 8);
  assert_eq!(
    omitted.entries().map(|(code, _)| code).collect::<Vec<_>>(),
    vec![
      "expired",
      "not_applicable",
      "same_site",
      "partition",
      "ancestor_chain_unknown",
      "unparsable_partition_key",
      "origin",
    ]
  );
}

#[test]
fn a_send_view_debug_never_prints_a_cookie_value() {
  let result = snapshot(vec![(cookie("sid", 0), CookieContext::default())]);
  let view = result
    .send_view(&context("https://example.test/"))
    .expect("valid context");
  let rendered = format!("{view:?}");
  assert!(!rendered.contains("value"), "{rendered}");
  assert!(!rendered.contains("sid"), "{rendered}");
  assert!(rendered.contains("selected: 1"), "{rendered}");
}

#[test]
fn an_explicit_cross_site_ancestor_is_cross_site_for_same_site_too() {
  // Both engines' site-for-cookies walks the ancestor chain, so an A->B->A
  // frame is cross-site to a browser even though its two sites are equal.
  // Treating it as same-site here would send a `Strict` cookie a browser
  // withholds, and this crate is never less conservative than a browser.
  let result = snapshot(vec![
    (cookie("strict", 2), CookieContext::default()),
    (cookie("lax", 1), CookieContext::default()),
    (cookie("none", 0), CookieContext::default()),
    (
      cookie("nested", 0),
      chips_with_ancestor("https://example.test", true),
    ),
  ]);
  let first_party = context("https://example.test/").top_level_site("https://example.test/");

  let nested = result
    .send_view(&first_party.clone().ancestor_chain(AncestorChain::CrossSite))
    .expect("valid context");
  assert_eq!(
    nested.header(),
    "nested=value; none=value",
    "SameSite=None and the nested partition survive; Lax and Strict do not"
  );
  assert_eq!(
    nested.omitted().same_site(),
    2,
    "Strict and Lax are withheld, and counted as the same-site omission"
  );

  // The same context without the selector is an ordinary first-party request,
  // where they return. Derived behavior is unchanged.
  let derived = result.send_view(&first_party).expect("valid context");
  assert_eq!(derived.header(), "lax=value; none=value; strict=value");
  assert_eq!(derived.omitted().same_site(), 0);

  // Explicit SameSite on a cross-site pair stays cross-site: the sites have to
  // match first, and no selector can assert them equal.
  let cross = result
    .send_view(
      &context("https://example.test/")
        .top_level_site("https://other.example/")
        .ancestor_chain(AncestorChain::SameSite),
    )
    .expect("valid context");
  assert_eq!(cross.header(), "none=value");
  assert_eq!(cross.omitted().same_site(), 2);
}

#[test]
fn an_explicit_cross_site_ancestor_selects_the_nested_first_party_rows() {
  // The A->B->A shape: the top-level site is the request's own site, reached
  // through a cross-site ancestor. It is same-site *and* cross-ancestor, which
  // is exactly the pair no derivation can produce on its own.
  let result = snapshot(vec![
    (
      cookie("chromium_nested", 0),
      chips_with_ancestor("https://example.test", true),
    ),
    (
      cookie("firefox_nested", 0),
      firefox_partition("(https,example.test,f)"),
    ),
    (
      cookie("chromium_first_party", 0),
      chips_with_ancestor("https://example.test", false),
    ),
    (
      cookie("firefox_first_party", 0),
      firefox_partition("(https,example.test)"),
    ),
  ]);
  let first_party = context("https://example.test/").top_level_site("https://example.test/");

  assert_eq!(
    result
      .header(&first_party.clone().ancestor_chain(AncestorChain::CrossSite))
      .expect("valid context"),
    "chromium_nested=value; firefox_nested=value",
    "both engines record the nested shape, and only those rows match it"
  );

  // Without the selector the same context derives SameSite, which is the
  // ordinary first-party partition and a different pair of rows. A partitioned
  // Firefox row is never first-party, so only the Chromium one comes back.
  assert_eq!(
    result.header(&first_party).expect("valid context"),
    "chromium_first_party=value"
  );
}

#[test]
fn a_partitioned_row_still_demands_the_top_level_site_however_the_chain_is_set() {
  // `ancestor_chain` is not a substitute for the site half of the key. With no
  // top-level site there is nothing to compare a partition against, so the
  // snapshot demands one rather than letting an explicit chain stand in.
  let result = snapshot(vec![(
    cookie("chips", 0),
    chips_with_ancestor("https://example.test", true),
  )]);
  for chain in [AncestorChain::SameSite, AncestorChain::CrossSite] {
    assert_eq!(
      required(
        &result
          .header(&context("https://example.test/").ancestor_chain(chain))
          .expect_err("the site half of the key is still missing")
      ),
      vec!["top_level_site"]
    );
  }
}

#[test]
fn a_supplied_selector_that_matches_nothing_omits_rows_without_erroring() {
  // The error is for a selector that was never supplied at all. Once a caller
  // has named a context, a row in a different one is simply not in it, and an
  // empty header is the honest answer rather than a failure.
  let cases: Vec<(&str, CookieContext, SendContext)> = vec![
    (
      // A genuine ancestor mismatch: the sites match, so the selector has
      // force, and the row's stored bit disagrees with it.
      "ancestor_chain",
      chips_with_ancestor("https://example.test", true),
      context("https://example.test/")
        .top_level_site("https://example.test/")
        .ancestor_chain(AncestorChain::SameSite),
    ),
    (
      "first_party_domain",
      firefox_attributes("^firstPartyDomain=example.org"),
      context("https://example.test/").first_party_domain("other.example"),
    ),
    (
      "gecko_view_session_context_id",
      firefox_attributes("^geckoViewSessionContextId=session-7"),
      context("https://example.test/").gecko_view_session_context_id("session-9"),
    ),
    (
      "origin_attributes",
      firefox_attributes("^futureAttr=1"),
      context("https://example.test/").origin_attributes("^futureAttr=2"),
    ),
  ];

  for (selector, stored, send_context) in cases {
    let result = snapshot(vec![(cookie("scoped", 0), stored)]);
    let view = result
      .send_view(&send_context)
      .unwrap_or_else(|error| panic!("{selector} must not error, got {error:?}"));
    assert!(view.is_empty(), "{selector} selected a foreign row");
    assert_eq!(view.omitted().total(), 1, "{selector}");
  }
}

#[test]
fn an_explicit_same_site_chain_has_no_force_on_a_cross_site_request() {
  // A cross-site request has a cross-site ancestor by construction: the
  // top-level document is itself the foreign ancestor. Honouring an explicit
  // `SameSite` here would admit site A's own first-party rows -- its key with
  // ancestor bit 0 -- into a third-party send from B.
  let result = snapshot(vec![
    (
      cookie("first_party_of_a", 0),
      chips_with_ancestor("https://top.example", false),
    ),
    (
      cookie("embedded_under_a", 0),
      chips_with_ancestor("https://top.example", true),
    ),
  ]);

  for chain in [
    None,
    Some(AncestorChain::SameSite),
    Some(AncestorChain::CrossSite),
  ] {
    let mut send = context("https://example.test/").top_level_site("https://top.example/");
    if let Some(chain) = chain {
      send = send.ancestor_chain(chain);
    }
    assert_eq!(
      result.header(&send).expect("valid context"),
      "embedded_under_a=value",
      "{chain:?} must resolve to cross-site on a cross-site request"
    );
  }
}

#[test]
fn a_default_first_party_domain_selects_firefox_rows_that_omit_it() {
  // Firefox omits a default-valued attribute, so the empty string is a real
  // value a caller can select. A Chromium row carries no origin attributes at
  // all and stays unknown, so no Firefox selector reaches it.
  let result = snapshot(vec![
    (cookie("firefox_default", 0), firefox_attributes("")),
    (
      cookie("firefox_labelled", 0),
      firefox_attributes("^firstPartyDomain=example.org"),
    ),
    (cookie("chromium", 0), CookieContext::default()),
  ]);

  assert_eq!(
    result
      .header(&context("https://example.test/").first_party_domain(""))
      .expect("valid context"),
    "firefox_default=value",
    "the empty default selects the row that omits the attribute, and nothing else"
  );
  assert_eq!(
    result
      .header(&context("https://example.test/").first_party_domain("example.org"))
      .expect("valid context"),
    "firefox_labelled=value"
  );
  // A row that omits `geckoViewSessionContextId` is at its default too. This
  // uses its own snapshot because the labelled row above demands
  // `first_party_domain`, which is a separate question.
  let gecko = snapshot(vec![
    (cookie("firefox_default", 0), firefox_attributes("")),
    (cookie("chromium", 0), CookieContext::default()),
  ]);
  assert_eq!(
    gecko
      .header(&context("https://example.test/").gecko_view_session_context_id(""))
      .expect("valid context"),
    "firefox_default=value"
  );
}

#[test]
fn a_private_browsing_id_selects_exactly_its_own_rows() {
  let result = snapshot(vec![
    (
      cookie("private", 0),
      firefox_attributes("^privateBrowsingId=1"),
    ),
    (cookie("normal", 0), firefox_attributes("")),
  ]);

  assert_eq!(
    required(
      &result
        .header(&context("https://example.test/"))
        .expect_err("a non-default private-browsing id demands its selector")
    ),
    vec!["private_browsing_id"]
  );
  assert_eq!(
    result
      .header(&context("https://example.test/").private_browsing_id(1))
      .expect("valid context"),
    "private=value"
  );
  assert_eq!(
    result
      .header(&context("https://example.test/").private_browsing_id(0))
      .expect("valid context"),
    "normal=value"
  );

  // A third identity selects neither, and says so as omissions rather than as
  // an error: the selector was supplied, it simply matches nothing.
  let view = result
    .send_view(&context("https://example.test/").private_browsing_id(2))
    .expect("a supplied selector is not an error");
  assert!(view.is_empty());
  assert_eq!(
    view.omitted().origin(),
    2,
    "both rows are in other sessions"
  );
}

#[test]
fn two_labelled_containers_never_merge() {
  let result = snapshot(vec![
    (cookie("work", 0), firefox_attributes("^userContextId=2")),
    (
      cookie("personal", 0),
      firefox_attributes("^userContextId=3"),
    ),
  ]);

  assert_eq!(
    required(
      &result
        .header(&context("https://example.test/"))
        .expect_err("two containers cannot be merged")
    ),
    vec!["user_context_id"]
  );
  assert_eq!(
    result
      .header(&context("https://example.test/").user_context_id(2))
      .expect("valid context"),
    "work=value"
  );
  assert_eq!(
    result
      .header(&context("https://example.test/").user_context_id(3))
      .expect("valid context"),
    "personal=value"
  );
  let view = result
    .send_view(&context("https://example.test/").user_context_id(4))
    .expect("valid context");
  assert!(view.is_empty());
  assert_eq!(view.omitted().origin(), 2);
}

#[test]
fn a_session_store_row_selects_the_same_way_a_persistent_row_does() {
  // The session store holds origin attributes as JSON rather than as the
  // `^name=value` suffix. Both encodings go through one parser, so the same
  // context selects the same identity either way.
  use crate::browser::mozilla_session::firefox_session_cookie_context;

  let contained = firefox_session_cookie_context(Some(&serde_json::json!({ "userContextId": 2 })));
  let future = firefox_session_cookie_context(Some(&serde_json::json!({ "futureAttr": 1 })));
  let future_raw = future
    .origin_attributes
    .clone()
    .expect("the raw JSON is retained verbatim");

  let result = snapshot(vec![
    (cookie("contained", 0), contained),
    (cookie("future", 0), future),
  ]);

  assert_eq!(
    required(
      &result
        .header(&context("https://example.test/"))
        .expect_err("both rows are isolated")
    ),
    vec!["user_context_id", "origin_attributes"]
  );
  assert_eq!(
    result
      .header(
        &context("https://example.test/")
          .user_context_id(2)
          .origin_attributes("never-matches")
      )
      .expect("valid context"),
    "contained=value",
    "a readable row is governed by its typed selector; the raw one does not touch it"
  );
  assert_eq!(
    result
      .header(
        &context("https://example.test/")
          .user_context_id(0)
          .origin_attributes(&future_raw)
      )
      .expect("valid context"),
    "future=value",
    "the verbatim JSON is what reaches the unknown-attribute row"
  );
}

#[test]
fn a_chromium_partition_key_with_a_port_matches_only_that_port() {
  let result = snapshot(vec![(
    cookie("ported", 0),
    chips("https://top.example:8443"),
  )]);
  assert_eq!(
    result
      .header(&context("https://example.test/").top_level_site("https://top.example:8443/"))
      .expect("valid context"),
    "ported=value"
  );
  assert_eq!(
    result
      .header(&context("https://example.test/").top_level_site("https://top.example/"))
      .expect("valid context"),
    "",
    "the port is part of the identity and is no longer stripped"
  );
}

#[test]
fn two_firefox_partitions_differing_only_by_port_do_not_collide() {
  let result = snapshot(vec![
    (
      cookie("default_port", 0),
      firefox_partition("(https,top.example)"),
    ),
    (
      cookie("alt_port", 0),
      firefox_partition("(https,top.example,8443)"),
    ),
  ]);
  assert_eq!(
    result
      .header(&context("https://example.test/").top_level_site("https://top.example/"))
      .expect("valid context"),
    "default_port=value"
  );
  assert_eq!(
    result
      .header(&context("https://example.test/").top_level_site("https://top.example:8443/"))
      .expect("valid context"),
    "alt_port=value"
  );
}

#[test]
fn an_exact_origin_attributes_selector_reaches_an_unparsable_partition_key() {
  // A legacy bare-baseDomain key and a `moz-extension` partition are both
  // keys no parser here understands. The raw suffix names the partition
  // verbatim, so a caller who supplies it exactly has identified the context.
  for suffix in [
    "^partitionKey=example.test",
    "^partitionKey=%28moz-extension%2C7a8b9c%29",
  ] {
    let result = snapshot(vec![(cookie("legacy", 0), firefox_attributes(suffix))]);
    let send = context("https://example.test/").top_level_site("https://top.example/");

    let view = result.send_view(&send.clone()).expect("valid context");
    assert!(view.is_empty(), "{suffix} must not be sent by default");
    assert_eq!(view.omitted().unparsable_partition_key(), 1, "{suffix}");

    assert_eq!(
      result
        .header(&send.origin_attributes(suffix))
        .expect("valid context"),
      "legacy=value",
      "{suffix} is reachable only by naming it verbatim"
    );
  }
}

#[test]
fn a_chromium_unparsable_key_stays_unreachable() {
  // It has no raw origin-attributes suffix, so there is nothing to name.
  let result = snapshot(vec![(
    cookie("mystery", 0),
    CookieContext {
      top_frame_site_key: Some("not-a-url".to_owned()),
      has_cross_site_ancestor: Some(true),
      ..CookieContext::default()
    },
  )]);
  for send in [
    context("https://example.test/").top_level_site("https://top.example/"),
    context("https://example.test/")
      .top_level_site("https://top.example/")
      .origin_attributes("not-a-url"),
  ] {
    let view = result.send_view(&send).expect("valid context");
    assert!(view.is_empty());
    assert_eq!(view.omitted().unparsable_partition_key(), 1);
  }
}

#[test]
fn a_request_port_does_not_change_the_site_it_belongs_to() {
  // A site is (scheme, host). A request to an explicit port under a
  // portless top-level site of the same host is still first-party.
  let result = snapshot(vec![(cookie("strict", 2), CookieContext::default())]);
  assert_eq!(
    result
      .header(&context("https://example.test:8443/").top_level_site("https://example.test/"))
      .expect("valid context"),
    "strict=value"
  );
}

#[test]
fn the_raw_selector_governs_opaque_rows_only() {
  // One cookie written by a future Firefox must not collapse the whole store
  // to a single stored suffix. Rows this build can read keep combining
  // normally, and only the opaque row waits to be named verbatim.
  let result = snapshot(vec![
    (cookie("plain", 0), firefox_attributes("")),
    (
      cookie("partitioned", 0),
      firefox_attributes("^partitionKey=%28https%2Ca.example%29"),
    ),
    (cookie("future", 0), firefox_attributes("^futureAttr=1")),
  ]);
  let embedded = context("https://example.test/").top_level_site("https://a.example/");

  let view = result
    .send_view(&embedded.clone().origin_attributes(""))
    .expect("valid context");
  assert_eq!(
    view.header(),
    "partitioned=value; plain=value",
    "the unpartitioned and partitioned rows still combine"
  );
  assert_eq!(
    view.omitted().origin(),
    1,
    "only the opaque row is held back"
  );

  assert_eq!(
    result
      .header(&embedded.origin_attributes("^futureAttr=1"))
      .expect("valid context"),
    "future=value; partitioned=value; plain=value",
    "naming the opaque row adds it without excluding the others"
  );
}
