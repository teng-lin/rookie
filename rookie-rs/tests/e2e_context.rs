//! Real-browser partition/container context canary.
//!
//! The test is ignored by default. CI supplies an explicitly disposable
//! browser database; this test never performs browser discovery.

use rookie_cookies::{from_path, FromPathRequest, RequestError, SendContext};
use std::env;
use std::path::PathBuf;

fn required(name: &str) -> String {
  env::var(name).unwrap_or_else(|_| panic!("{name} must be set by the context E2E harness"))
}

fn one<'a>(
  records: &'a [rookie_cookies::enums::DetailedCookie],
  name: &str,
) -> &'a rookie_cookies::enums::DetailedCookie {
  let matches = records
    .iter()
    .filter(|record| record.cookie.name == name)
    .collect::<Vec<_>>();
  assert_eq!(matches.len(), 1, "expected exactly one {name}");
  matches[0]
}

#[test]
#[ignore = "requires a disposable real-browser profile seeded by CI"]
fn browser_produced_partition_context_survives_snapshot_and_header_filter() {
  let engine = required("ROOKIE_E2E_CONTEXT_ENGINE");
  let database = PathBuf::from(required("ROOKIE_E2E_CONTEXT_DB"));
  let top_origin = required("ROOKIE_E2E_CONTEXT_TOP_ORIGIN");
  let other_top_origin = required("ROOKIE_E2E_CONTEXT_OTHER_TOP_ORIGIN");
  let third_origin = required("ROOKIE_E2E_CONTEXT_THIRD_ORIGIN");
  let source_port = required("ROOKIE_E2E_CONTEXT_SOURCE_PORT")
    .parse::<i64>()
    .expect("ROOKIE_E2E_CONTEXT_SOURCE_PORT must be an integer");

  let mut request = FromPathRequest::new(database);
  if engine == "chromium" {
    #[cfg(unix)]
    {
      request = request.chromium_browser_id(
        env::var("ROOKIE_E2E_BROWSER_ID").unwrap_or_else(|_| "chromium".to_owned()),
      );
    }
    #[cfg(windows)]
    {
      request = request.chromium_local_state(required("ROOKIE_E2E_LOCAL_STATE"));
    }
  } else {
    assert_eq!(engine, "firefox", "unsupported context engine");
  }

  let snapshot = from_path(request).expect("context database extraction must succeed");
  let records = snapshot
    .detailed_cookies()
    .iter()
    .filter(|record| record.cookie.name.starts_with("rookie_"))
    .cloned()
    .collect::<Vec<_>>();
  let top = one(&records, "rookie_top");
  let chips = one(&records, "rookie_chips");

  if engine == "chromium" {
    assert!(
      top.context.top_frame_site_key.as_deref().unwrap_or("").is_empty(),
      "first-party top cookie became partitioned"
    );
    assert!(
      chips
        .context
        .top_frame_site_key
        .as_deref()
        .is_some_and(|key| key.contains("rookie-a.test")),
      "CHIPS row lost its top-frame site: {:?}",
      chips.context.top_frame_site_key
    );
    assert_eq!(chips.context.has_cross_site_ancestor, Some(true));
    assert_eq!(chips.context.source_port, Some(source_port));
    assert!(chips.context.source_scheme.is_some());
    assert_eq!(chips.context.is_persistent, Some(true));
  } else {
    for record in [chips, one(&records, "rookie_dfpi")] {
      assert!(
        record
          .context
          .origin_attributes
          .as_deref()
          .is_some_and(|value| value.contains("partitionKey=")),
        "{} lost complete originAttributes",
        record.cookie.name
      );
      assert!(
        record
          .context
          .partition_key
          .as_deref()
          .is_some_and(|value| value.contains("rookie-a.test")),
        "{} has an unexpected partition key: {:?}",
        record.cookie.name,
        record.context.partition_key
      );
      assert!(record.context.user_context_id.is_none_or(|id| id == 0));
      assert!(record.context.private_browsing_id.is_none_or(|id| id == 0));
    }
  }

  let request_url = format!("{third_origin}/echo");
  let matching = snapshot
    .header(
      &SendContext::url(&request_url)
        .top_level_site(&top_origin)
        .subresource(),
    )
    .expect("complete matching context must build a header");
  let other = snapshot
    .header(
      &SendContext::url(&request_url)
        .top_level_site(&other_top_origin)
        .subresource(),
    )
    .expect("complete non-matching context must build a header");
  assert!(matching.contains("rookie_chips=partitioned"));
  assert!(!other.contains("rookie_chips=partitioned"));
  if engine == "firefox" {
    assert!(matching.contains("rookie_dfpi=partitioned-by-context"));
    assert!(!other.contains("rookie_dfpi=partitioned-by-context"));
  }

  let error = snapshot
    .header(&SendContext::url(request_url).subresource())
    .expect_err("partitioned snapshot must reject an incomplete send context");
  match error {
    rookie_cookies::Error::Request(RequestError::IncompleteSendContext { required, .. }) => {
      assert!(required.iter().any(|name| name == "top_level_site"));
    }
    other => panic!("missing selector returned the wrong error: {other:?}"),
  }
}
