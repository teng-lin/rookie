//! Real-browser partition/container context canary.
//!
//! The test is ignored by default. CI supplies an explicitly disposable
//! browser database; this test never performs browser discovery.

use rookie_cookies::{from_path, AncestorChain, FromPathRequest, RequestError, SendContext};
use std::env;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn required(name: &str) -> String {
  env::var(name).unwrap_or_else(|_| panic!("{name} must be set by the context E2E harness"))
}

fn workspace_root() -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    .parent()
    .expect("rookie-rs has workspace parent")
    .to_path_buf()
}

fn venv_python() -> PathBuf {
  #[cfg(target_os = "windows")]
  let python = workspace_root().join(".venv/Scripts/python.exe");
  #[cfg(not(target_os = "windows"))]
  let python = workspace_root().join(".venv/bin/python");
  python
}

fn read_json(path: PathBuf) -> serde_json::Value {
  let text = std::fs::read_to_string(&path)
    .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
  serde_json::from_str(&text)
    .unwrap_or_else(|error| panic!("cannot parse {}: {error}", path.display()))
}

/// The one expected-row table the runner, the seeder, and every surface read.
///
/// Keeping the counts in a file rather than in four literals is what stops a
/// corpus change from landing in some of these actors and being forgotten in
/// the rest.
fn row_inventory(engine: &str) -> serde_json::Value {
  let inventory = read_json(workspace_root().join("tests/e2e/partition_context_inventory.json"));
  inventory["engines"][engine].clone()
}

/// Builds a [`SendContext`] from one manifest send context.
///
/// The manifest spells every selector in the snake_case the Python and CLI
/// surfaces also read, so all four surfaces are demonstrably answering the
/// same question rather than four similar ones.
fn send_context_from(context: &serde_json::Value) -> SendContext {
  let mut built = SendContext::url(
    context["url"]
      .as_str()
      .expect("a manifest send context must carry a url"),
  );
  if let Some(site) = context
    .get("top_level_site")
    .and_then(|value| value.as_str())
  {
    built = built.top_level_site(site);
  }
  match context.get("resource").and_then(|value| value.as_str()) {
    Some("navigation") => built = built.navigation(),
    Some("subresource") | None => built = built.subresource(),
    Some(other) => panic!("unsupported manifest resource kind {other}"),
  }
  match context.get("method").and_then(|value| value.as_str()) {
    Some("unsafe") => built = built.method(rookie_cookies::MethodClass::Unsafe),
    Some("safe") | None => built = built.method(rookie_cookies::MethodClass::Safe),
    Some(other) => panic!("unsupported manifest method class {other}"),
  }
  match context
    .get("ancestor_chain")
    .and_then(|value| value.as_str())
  {
    Some("same_site") => built = built.ancestor_chain(AncestorChain::SameSite),
    Some("cross_site") => built = built.ancestor_chain(AncestorChain::CrossSite),
    None => {}
    Some(other) => panic!("unsupported manifest ancestor chain {other}"),
  }
  if let Some(id) = context
    .get("user_context_id")
    .and_then(|value| value.as_u64())
  {
    built = built.user_context_id(id as u32);
  }
  if let Some(attributes) = context
    .get("origin_attributes")
    .and_then(|value| value.as_str())
  {
    built = built.origin_attributes(attributes);
  }
  built
}

/// Compares one selected set against the manifest's independently derived one.
fn assert_send_view_records(
  manifest: &str,
  view: &str,
  records: &[rookie_cookies::enums::DetailedCookie],
) {
  let mut child = Command::new(venv_python())
    .arg(workspace_root().join("tests/e2e/verify_cookie_manifest.py"))
    .arg("--manifest")
    .arg(manifest)
    .arg("--projection")
    .arg("detailed")
    .arg("--surface")
    .arg(format!("Rust send view {view}"))
    .arg("--send-view")
    .arg(view)
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .expect("launch send view manifest verifier");
  child
    .stdin
    .take()
    .expect("send view verifier stdin")
    .write_all(&serde_json::to_vec(records).expect("serialize send view records"))
    .expect("write send view verifier input");
  let output = child
    .wait_with_output()
    .expect("wait for send view verifier");
  assert!(
    output.status.success(),
    "send view {view} mismatch: {}{}",
    String::from_utf8_lossy(&output.stderr),
    String::from_utf8_lossy(&output.stdout)
  );
}

fn omission_count(omitted: &rookie_cookies::SendOmissions, reason: &str) -> u64 {
  omitted
    .entries()
    .find(|(name, _)| *name == reason)
    .unwrap_or_else(|| panic!("SendOmissions has no {reason} counter"))
    .1
}

/// Drives every manifest send context through `send_view` and checks all three
/// halves of the answer: the selected set, the header it renders, and the
/// omission counters.
fn assert_manifest_send_views(snapshot: &rookie_cookies::ReadResult) {
  let Ok(manifest_path) = env::var("ROOKIE_E2E_CONTEXT_MANIFEST") else {
    return;
  };
  let manifest = read_json(PathBuf::from(&manifest_path));
  let views = manifest["expected_send_views"]
    .as_array()
    .expect("the manifest must carry expected_send_views");
  assert!(!views.is_empty(), "expected_send_views must not be empty");
  for expected in views {
    let name = expected["name"].as_str().expect("send view name");
    let view = snapshot
      .send_view(&send_context_from(&expected["context"]))
      .unwrap_or_else(|error| panic!("send view {name} failed: {error:?}"));
    let selected = view
      .to_detailed_cookies()
      .into_iter()
      .filter(|record| record.cookie.name.starts_with("rookie_"))
      .collect::<Vec<_>>();
    assert_send_view_records(&manifest_path, name, &selected);

    let mut expected_tokens = expected["header_tokens"]
      .as_array()
      .expect("send view header_tokens")
      .iter()
      .map(|token| token.as_str().expect("header token").to_owned())
      .collect::<Vec<_>>();
    expected_tokens.sort();
    assert_eq!(
      header_tokens(&view.header()),
      expected_tokens,
      "send view {name} rendered an unexpected header"
    );

    for (reason, minimum) in expected["expected_omitted_min"]
      .as_object()
      .expect("send view expected_omitted_min")
    {
      let minimum = minimum.as_u64().expect("omission minimum");
      let actual = omission_count(view.omitted(), reason);
      assert!(
        actual >= minimum,
        "send view {name} counted {actual} {reason} omissions, expected at least {minimum}"
      );
    }
  }
  // Declaring a same-site request cross-site must withhold its Lax rows; the
  // oracle has to contain such a row for that claim to mean anything.
  let cross = views
    .iter()
    .find(|view| view["name"] == "top_cross_site")
    .expect("the manifest must carry a top_cross_site view");
  assert!(
    cross["expected_omitted_min"]["same_site"]
      .as_u64()
      .unwrap_or(0)
      >= 1,
    "the explicit cross-site context must have a SameSite=Lax row to omit"
  );
  assert!(
    cross["expected"]
      .as_array()
      .expect("expected rows")
      .is_empty(),
    "the explicit cross-site context must select nothing"
  );
}

/// The exact selector tokens the manifest says an incomplete context demands.
fn assert_required_tokens(required: &[String]) {
  let Ok(manifest_path) = env::var("ROOKIE_E2E_CONTEXT_MANIFEST") else {
    return;
  };
  let manifest = read_json(PathBuf::from(manifest_path));
  let expected = manifest["expected_missing_selector"]["required"]
    .as_array()
    .expect("the manifest must carry expected_missing_selector.required")
    .iter()
    .map(|token| token.as_str().expect("selector token").to_owned())
    .collect::<Vec<_>>();
  assert_eq!(
    required, expected,
    "incomplete_send_context named the wrong selector tokens"
  );
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
  let mut child = Command::new(venv_python())
    .arg(workspace_root().join("tests/e2e/verify_cookie_manifest.py"))
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
  let inventory = row_inventory(&engine);
  let expected_rows = inventory["raw_rows_by_name"]
    .as_object()
    .expect("the inventory must map cookie names onto row counts");
  assert_eq!(
    records.len(),
    inventory["raw_row_total"]
      .as_u64()
      .expect("the inventory must carry a raw_row_total") as usize,
    "context corpus contained excess or missing records: {records:#?}"
  );
  for (name, count) in expected_rows {
    let observed = records
      .iter()
      .filter(|record| &record.cookie.name == name)
      .count();
    assert_eq!(
      observed as u64,
      count.as_u64().expect("row count"),
      "context corpus held {observed} {name} rows"
    );
  }
  assert!(
    records
      .iter()
      .all(|record| expected_rows.contains_key(&record.cookie.name)),
    "context corpus contained an unexpected rookie cookie: {records:#?}"
  );

  // The two A-site rows differ in nothing a flat projection can see, so a
  // library that folded them together would still look correct everywhere else.
  let ancestors = records
    .iter()
    .filter(|record| record.cookie.name == "rookie_ancestor")
    .collect::<Vec<_>>();
  assert_eq!(ancestors.len(), 2, "both ancestor chains must survive");
  for record in &ancestors {
    let cross = record.cookie.value == "ancestor-cross_site";
    assert!(
      cross || record.cookie.value == "ancestor-same_site",
      "unexpected ancestor row value {}",
      record.cookie.value
    );
    if engine == "chromium" {
      assert_eq!(
        record.context.has_cross_site_ancestor,
        Some(cross),
        "{} carried the wrong ancestor bit",
        record.cookie.value
      );
    } else {
      assert_eq!(
        record
          .context
          .partition_key
          .as_deref()
          .unwrap_or("")
          .ends_with(",f)"),
        cross,
        "{} carried partitionKey {:?}",
        record.cookie.value,
        record.context.partition_key
      );
    }
  }

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
      assert_required_tokens(&required);
    }
    other => panic!("missing selector returned the wrong error: {other:?}"),
  }

  assert_manifest_send_views(&snapshot);
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
      assert_eq!(
        required,
        vec!["user_context_id".to_owned()],
        "the container snapshot demands exactly the container selector"
      );
    }
    other => panic!("missing container selector returned the wrong error: {other:?}"),
  }

  let view = snapshot
    .send_view(
      &SendContext::url(origin)
        .top_level_site(origin)
        .user_context_id(user_context_id),
    )
    .expect("complete Firefox container selector");
  assert_eq!(view.len(), 1, "the container context selects one row");
  assert_eq!(view.cookies()[0].cookie.value, "container-1");
  assert_eq!(view.header(), matching);

  // The verbatim suffix the browser wrote. It is not a bypass -- the typed
  // container selector still has to match -- so the round trip proves the raw
  // selector narrows to the same single row rather than widening past it.
  let suffix = records[0]
    .context
    .origin_attributes
    .clone()
    .expect("a Firefox container row records its originAttributes");
  let round_trip = snapshot
    .send_view(
      &SendContext::url(origin)
        .top_level_site(origin)
        .user_context_id(user_context_id)
        .origin_attributes(&suffix),
    )
    .expect("the exact stored origin-attribute suffix is a valid selector");
  assert_eq!(
    round_trip.to_detailed_cookies(),
    view.to_detailed_cookies(),
    "the raw origin-attribute selector must select the same single record"
  );
}
