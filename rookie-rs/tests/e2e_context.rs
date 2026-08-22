//! Real-browser partition/container context canary.
//!
//! The test is ignored by default. CI supplies an explicitly disposable
//! browser database; this test never performs browser discovery.

use rookie_cookies::{from_path, FromPathRequest, RequestError, SendContext};
use std::env;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn required(name: &str) -> String {
  env::var(name).unwrap_or_else(|_| panic!("{name} must be set by the context E2E harness"))
}

fn exactly_two<'a>(
  records: &'a [rookie_cookies::enums::DetailedCookie],
  name: &str,
) -> Vec<&'a rookie_cookies::enums::DetailedCookie> {
  let matches = records
    .iter()
    .filter(|record| record.cookie.name == name)
    .collect::<Vec<_>>();
  assert_eq!(
    matches.len(),
    2,
    "expected exactly two colliding {name} identities"
  );
  matches
}

fn assert_raw_manifest(records: &[rookie_cookies::enums::DetailedCookie]) {
  let Ok(manifest) = env::var("ROOKIE_E2E_CONTEXT_MANIFEST") else {
    return;
  };
  let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    .parent()
    .expect("rookie-rs has workspace parent")
    .to_path_buf();
  #[cfg(target_os = "windows")]
  let python = workspace.join(".venv/Scripts/python.exe");
  #[cfg(not(target_os = "windows"))]
  let python = workspace.join(".venv/bin/python");
  let mut child = Command::new(python)
    .arg(workspace.join("tests/e2e/verify_cookie_manifest.py"))
    .arg("--manifest")
    .arg(manifest)
    .arg("--projection")
    .arg("detailed")
    .arg("--surface")
    .arg("Rust raw partition context")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .expect("launch raw context manifest verifier");
  child
    .stdin
    .take()
    .expect("context verifier stdin")
    .write_all(&serde_json::to_vec(records).expect("serialize context records"))
    .expect("write context verifier input");
  let output = child.wait_with_output().expect("wait for context verifier");
  assert!(
    output.status.success(),
    "raw context manifest mismatch: {}{}",
    String::from_utf8_lossy(&output.stderr),
    String::from_utf8_lossy(&output.stdout)
  );
}

fn header_tokens(header: &str) -> Vec<String> {
  let mut tokens = header
    .split(';')
    .map(str::trim)
    .filter(|token| !token.is_empty())
    .map(str::to_owned)
    .collect::<Vec<_>>();
  tokens.sort();
  tokens
}

fn controlled_schemeful_site(origin: &str) -> String {
  let parsed = url::Url::parse(origin).expect("controlled top-level origin must be a URL");
  let host = parsed
    .host_str()
    .expect("controlled top-level origin must have a host");
  let site = host
    .strip_prefix("top.")
    .or_else(|| host.strip_prefix("other."))
    .expect("controlled top-level origin must use the top/other alias");
  format!("{}://{site}", parsed.scheme())
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
  assert_raw_manifest(&records);
  let top = exactly_two(&records, "rookie_top");
  let chips = records
    .iter()
    .filter(|record| record.cookie.name == "rookie_chips")
    .collect::<Vec<_>>();
  assert_eq!(chips.len(), 3, "expected three colliding CHIPS identities");
  let expected_names = if engine == "chromium" {
    vec!["rookie_chips", "rookie_top"]
  } else {
    vec!["rookie_chips", "rookie_dfpi", "rookie_top"]
  };
  assert_eq!(
    records.len(),
    if engine == "chromium" { 5 } else { 7 },
    "context corpus contained excess or missing records: {records:#?}"
  );
  assert!(
    records
      .iter()
      .all(|record| expected_names.contains(&record.cookie.name.as_str())),
    "context corpus contained an unexpected rookie cookie: {records:#?}"
  );

  if engine == "chromium" {
    assert!(
      top.iter().all(|record| record
        .context
        .top_frame_site_key
        .as_deref()
        .unwrap_or("")
        .is_empty()),
      "first-party top cookie became partitioned"
    );
    let unpartitioned = chips
      .iter()
      .filter(|record| {
        record
          .context
          .top_frame_site_key
          .as_deref()
          .unwrap_or("")
          .is_empty()
      })
      .collect::<Vec<_>>();
    assert_eq!(
      unpartitioned.len(),
      1,
      "unpartitioned cookie sharing the CHIPS flat identity was lost"
    );
    assert_eq!(unpartitioned[0].cookie.value, "unpartitioned");
    for label in ["a", "c"] {
      let expected_key = format!("rookie-{label}.test");
      let matches = chips
        .iter()
        .filter(|record| {
          record
            .context
            .top_frame_site_key
            .as_deref()
            .is_some_and(|key| key.contains(&expected_key))
        })
        .collect::<Vec<_>>();
      assert_eq!(matches.len(), 1, "expected one Chromium partition {label}");
      let record = matches[0];
      assert_eq!(record.cookie.value, format!("partition-{label}"));
      assert_eq!(record.context.has_cross_site_ancestor, Some(true));
      assert_eq!(record.context.source_port, Some(source_port));
      assert_eq!(record.context.source_scheme, Some(2));
      assert_eq!(record.context.is_persistent, Some(true));
    }
  } else {
    let dfpi = exactly_two(&records, "rookie_dfpi");
    let unpartitioned = chips
      .iter()
      .filter(|record| {
        record
          .context
          .partition_key
          .as_deref()
          .unwrap_or("")
          .is_empty()
      })
      .collect::<Vec<_>>();
    assert_eq!(
      unpartitioned.len(),
      1,
      "unpartitioned cookie sharing the Firefox flat identity was lost"
    );
    assert_eq!(unpartitioned[0].cookie.value, "unpartitioned");
    for (name, collisions) in [("rookie_chips", chips), ("rookie_dfpi", dfpi)] {
      for label in ["a", "c"] {
        let expected_key = format!("rookie-{label}.test");
        let matches = collisions
          .iter()
          .filter(|record| {
            record
              .context
              .partition_key
              .as_deref()
              .is_some_and(|value| value.contains(&expected_key))
          })
          .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "expected one {name} partition {label}");
        let record = matches[0];
        assert!(
          record
            .context
            .origin_attributes
            .as_deref()
            .is_some_and(|value| value.contains("partitionKey=")),
          "{} lost complete originAttributes",
          record.cookie.name
        );
        assert!(record.context.user_context_id.is_none_or(|id| id == 0));
        assert!(record.context.private_browsing_id.is_none_or(|id| id == 0));
        let expected_value = if name == "rookie_chips" {
          format!("partition-{label}")
        } else {
          format!("dfpi-{label}")
        };
        assert_eq!(record.cookie.value, expected_value);
      }
    }
  }

  let request_url = format!("{third_origin}/echo");
  let top_site = controlled_schemeful_site(&top_origin);
  let other_top_site = controlled_schemeful_site(&other_top_origin);
  let matching = snapshot
    .header(
      &SendContext::url(&request_url)
        .top_level_site(&top_site)
        .subresource(),
    )
    .expect("complete matching context must build a header");
  let other = snapshot
    .header(
      &SendContext::url(&request_url)
        .top_level_site(&other_top_site)
        .subresource(),
    )
    .expect("complete non-matching context must build a header");
  let mut expected_matching = vec![
    "rookie_chips=partition-a".to_owned(),
    "rookie_chips=unpartitioned".to_owned(),
  ];
  let mut expected_other = vec![
    "rookie_chips=partition-c".to_owned(),
    "rookie_chips=unpartitioned".to_owned(),
  ];
  if engine == "firefox" {
    expected_matching.push("rookie_dfpi=dfpi-a".to_owned());
    expected_other.push("rookie_dfpi=dfpi-c".to_owned());
  }
  expected_matching.sort();
  expected_other.sort();
  assert_eq!(header_tokens(&matching), expected_matching);
  assert_eq!(header_tokens(&other), expected_other);

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

#[test]
#[ignore = "requires a disposable Firefox profile seeded by the test extension"]
fn browser_produced_firefox_container_survives_snapshot_and_header_filter() {
  let database = PathBuf::from(required("ROOKIE_E2E_CONTEXT_DB"));
  let user_context_id = required("ROOKIE_E2E_USER_CONTEXT_ID")
    .parse::<u32>()
    .expect("ROOKIE_E2E_USER_CONTEXT_ID must be positive");
  assert!(user_context_id > 0);
  let snapshot = from_path(FromPathRequest::new(database))
    .expect("Firefox container database extraction must succeed");
  let records = snapshot
    .detailed_cookies()
    .iter()
    .filter(|record| record.cookie.name == "rookie_container")
    .cloned()
    .collect::<Vec<_>>();
  assert_eq!(
    records.len(),
    1,
    "container corpus must have exactly one row"
  );
  assert_raw_manifest(&records);
  assert_eq!(records[0].context.user_context_id, Some(user_context_id));
  assert_eq!(records[0].context.partition_key, None);
  assert!(records[0]
    .context
    .private_browsing_id
    .is_none_or(|id| id == 0));

  let origin = "https://container.rookie.test/";
  let matching = snapshot
    .header(
      &SendContext::url(origin)
        .top_level_site(origin)
        .user_context_id(user_context_id),
    )
    .expect("complete Firefox container selector");
  assert_eq!(matching, "rookie_container=container-1");
  let other = snapshot
    .header(
      &SendContext::url(origin)
        .top_level_site(origin)
        .user_context_id(user_context_id + 1),
    )
    .expect("different Firefox container selector");
  assert!(other.is_empty(), "a different container leaked: {other}");

  let error = snapshot
    .header(&SendContext::url(origin).top_level_site(origin))
    .expect_err("container snapshot must reject a missing user-context selector");
  match error {
    rookie_cookies::Error::Request(RequestError::IncompleteSendContext { required, .. }) => {
      assert!(required.iter().any(|name| name == "user_context_id"));
    }
    other => panic!("missing container selector returned the wrong error: {other:?}"),
  }
}
