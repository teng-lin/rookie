//! The fail-closed compatibility projection.
//!
//! `cookies()` answers "what did the browser store". `jar()` answers "what may
//! I send". Those were the same list through 0.6, which is what made the loss
//! silent. These tests pin the split.

use super::*;
use crate::enums::CookieContext;
use crate::IsolationLoss;

fn cookie(name: &str) -> Cookie {
  Cookie {
    domain: ".example.test".to_owned(),
    path: "/".to_owned(),
    secure: false,
    expires: None,
    name: name.to_owned(),
    value: "value".to_owned(),
    http_only: false,
    same_site: 0,
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

fn chips(key: &str) -> CookieContext {
  CookieContext {
    top_frame_site_key: Some(key.to_owned()),
    has_cross_site_ancestor: Some(true),
    ..CookieContext::default()
  }
}

fn refusal(error: &crate::Error) -> (u64, Vec<String>) {
  match error {
    crate::Error::Request(RequestError::IsolationLossRefused {
      isolated_rows,
      required,
    }) => (*isolated_rows, required.clone()),
    other => panic!("expected IsolationLossRefused, got {other:?}"),
  }
}

#[test]
fn jar_is_infallible_for_an_unisolated_snapshot() {
  // The common case is unaffected: nothing in this snapshot needs a context to
  // disambiguate it, so there is nothing to lose by flattening it.
  let result = snapshot(vec![
    (cookie("a"), CookieContext::default()),
    (
      cookie("b"),
      CookieContext {
        user_context_id: Some(0),
        private_browsing_id: Some(0),
        origin_attributes: Some(String::new()),
        ..CookieContext::default()
      },
    ),
  ]);
  assert_eq!(result.jar().expect("no isolation to lose").len(), 2);
  assert_eq!(result.jar().expect("borrow"), result.cookies());
  assert_eq!(result.into_jar().expect("owned").len(), 2);
}

#[test]
fn jar_refuses_an_isolated_snapshot_by_default() {
  let result = snapshot(vec![
    (cookie("plain"), CookieContext::default()),
    (cookie("chips"), chips("https://top.example")),
  ]);

  let error = result
    .jar()
    .expect_err("a flat list cannot hold a partition");
  assert_eq!(error.code(), "isolation_loss_refused");
  let (isolated_rows, required) = refusal(&error);
  assert_eq!(isolated_rows, 1, "only the partitioned row is isolated");
  assert_eq!(required, vec!["top_level_site"]);

  // The message names the way out rather than only the problem.
  let message = error.to_string();
  assert!(message.contains("top_level_site"), "{message}");
  assert!(message.contains("IsolationLoss::Allow"), "{message}");

  // The inventory projection is unaffected: asking to see the rows is not the
  // same question as asking for something send-safe.
  assert_eq!(result.cookies().len(), 2);
  assert_eq!(result.detailed_cookies().len(), 2);
}

#[test]
fn jar_allows_loss_when_opted_in_and_is_byte_identical_to_cookies() {
  // The opt-in changes when a call can fail, never what a successful call
  // returns. This is what lets an existing consumer keep its output exactly.
  let result = snapshot(vec![
    (cookie("plain"), CookieContext::default()),
    (cookie("chips"), chips("https://top.example")),
  ]);
  assert_eq!(
    result.jar_with(IsolationLoss::Allow).expect("opted in"),
    result.cookies()
  );
  let expected = result.cookies().to_vec();
  assert_eq!(
    result
      .into_jar_with(IsolationLoss::Allow)
      .expect("opted in"),
    expected
  );
}

#[test]
fn jar_refusal_lists_the_same_tokens_header_demands() {
  // One vocabulary for both errors, so a caller that already branches on
  // `required` needs no second table.
  let result = snapshot(vec![(
    cookie("everything"),
    CookieContext {
      partition_key: Some("(https,top.example)".to_owned()),
      user_context_id: Some(3),
      private_browsing_id: Some(1),
      origin_attributes: Some(
        "^userContextId=3&privateBrowsingId=1&firstPartyDomain=example.org\
         &geckoViewSessionContextId=session-7&futureAttr=1"
          .to_owned(),
      ),
      ..CookieContext::default()
    },
  )]);

  let (_, from_jar) = refusal(&result.jar().expect_err("isolated"));
  let from_header = match result
    .header(&SendContext::url("https://example.test/"))
    .expect_err("isolated")
  {
    crate::Error::Request(RequestError::IncompleteSendContext { required, .. }) => required,
    other => panic!("expected IncompleteSendContext, got {other:?}"),
  };
  assert_eq!(from_jar, from_header);
  assert_eq!(
    from_jar,
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
fn an_unparsable_partition_key_counts_as_isolated() {
  // It is not unpartitioned, so flattening it merges a partition this build
  // could not even name into the unpartitioned bag.
  let result = snapshot(vec![(
    cookie("mystery"),
    CookieContext {
      partition_key: Some("not-a-tuple".to_owned()),
      ..CookieContext::default()
    },
  )]);
  let (isolated_rows, required) = refusal(&result.jar().expect_err("isolated"));
  assert_eq!(isolated_rows, 1);
  assert_eq!(required, vec!["top_level_site"]);
}

#[test]
fn a_row_with_unknown_isolation_is_not_treated_as_isolated() {
  // A store that never recorded container columns supplies no evidence of
  // isolation, and refusing on that would make `jar` unusable against most
  // browser versions. `None` is unknown, not "isolated".
  let result = snapshot(vec![(
    cookie("legacy"),
    CookieContext {
      user_context_id: None,
      private_browsing_id: None,
      ..CookieContext::default()
    },
  )]);
  assert_eq!(result.jar().expect("nothing observed").len(), 1);
}

#[test]
fn into_jar_reports_the_same_refusal_as_jar() {
  let result = snapshot(vec![(cookie("chips"), chips("https://top.example"))]);
  let error = result
    .into_jar()
    .expect_err("an isolated snapshot cannot be flattened");
  assert_eq!(error.code(), "isolation_loss_refused");
}

#[test]
fn a_row_whose_origin_attributes_cannot_be_read_counts_as_isolated() {
  // A known attribute name with an unreadable value is not the default
  // context, so flattening it would merge a row this build cannot identify
  // into the unisolated bag.
  for suffix in [
    "^userContextId=abc",
    "^userContextId=4294967296",
    "^userContextId",
    "^futureAttr=1",
  ] {
    let result = snapshot(vec![(
      cookie("mystery"),
      CookieContext {
        origin_attributes: Some(suffix.to_owned()),
        ..CookieContext::default()
      },
    )]);
    let error = result.jar().expect_err("{suffix} is isolated");
    assert_eq!(error.code(), "isolation_loss_refused", "{suffix}");
    let (isolated_rows, required) = refusal(&error);
    assert_eq!(isolated_rows, 1, "{suffix}");
    assert_eq!(required, vec!["origin_attributes"], "{suffix}");

    // And it is not reachable as the default container.
    assert_eq!(
      result
        .header(&SendContext::url("https://example.test/").user_context_id(0))
        .expect_err("unreadable is not container 0")
        .code(),
      "incomplete_send_context",
      "{suffix}"
    );
  }
}
