use super::*;
use crate::common::enums::SAME_SITE_UNSPECIFIED;
use crate::compatibility_dispatch::named::{aggregate_load_failure, aggregate_load_results};

fn not_installed(_domains: Option<Vec<String>>) -> anyhow::Result<Vec<Cookie>> {
  Err(browser::legacy::BrowserNotInstalled::CookieDatabase.into())
}

fn extraction_fails(_domains: Option<Vec<String>>) -> anyhow::Result<Vec<Cookie>> {
  Err(anyhow::anyhow!("cookie database is corrupt"))
}

fn always_ok(_domains: Option<Vec<String>>) -> anyhow::Result<Vec<Cookie>> {
  Ok(vec![])
}

#[test]
fn zero_timeout_stops_extraction_before_any_browser_lookup() {
  // "unknown-browser-id" would otherwise fail with a request error;
  // observing TimedOut instead of that error proves the deadline check
  // runs before browser resolution, matching browser_cookies_with_runtime's
  // own ordering.
  let request = Request::browser("unknown-browser-id").timeout(std::time::Duration::ZERO);
  let error = extract(request).expect_err("a zero timeout must stop before doing any work");
  assert_eq!(error.stop_reason(), Some(StopReason::TimedOut));
}

#[test]
fn a_cancelled_handle_stops_extraction_before_any_browser_lookup() {
  let handle = CancellationHandle::new();
  assert!(handle.cancel());
  assert!(handle.is_cancelled());

  let request = Request::browser("unknown-browser-id").cancellation(handle);
  let error = extract(request).expect_err("a pre-cancelled handle must stop before doing any work");
  assert_eq!(error.stop_reason(), Some(StopReason::Cancelled));
}

#[test]
fn cancelling_from_another_thread_stops_a_running_checkpoint_loop_promptly() {
  // Proves the cross-thread claim itself: cancellation observed by a loop
  // that is *already running*, set from a second thread mid-flight, not
  // just a pre-cancelled handle checked before any work starts.
  use std::time::{Duration, Instant};

  let handle = CancellationHandle::new();
  let clock = common::deadline::SystemClock;
  let deadline = common::deadline::Deadline::after(&clock, Duration::from_secs(30));
  let token = handle.0.clone();

  let canceller = {
    let handle = handle.clone();
    std::thread::spawn(move || {
      std::thread::sleep(Duration::from_millis(50));
      handle.cancel();
    })
  };

  let started = Instant::now();
  let stop = loop {
    if let Err(stop) = common::deadline::checkpoint(&clock, deadline, &token) {
      break stop;
    }
    std::thread::sleep(Duration::from_millis(5));
  };
  let elapsed = started.elapsed();
  canceller.join().expect("canceller thread must not panic");

  assert_eq!(stop, common::deadline::BoundaryStop::Cancelled);
  assert!(
    elapsed < Duration::from_secs(5),
    "a cross-thread cancellation must stop an in-progress loop promptly, took {elapsed:?}"
  );
}

#[test]
fn cancelling_one_clone_cancels_every_clone() {
  let handle = CancellationHandle::new();
  let clone = handle.clone();
  assert!(!handle.is_cancelled());
  assert!(!clone.is_cancelled());

  assert!(clone.cancel());
  assert!(
    handle.is_cancelled(),
    "cancelling a clone must be visible on the original"
  );

  // A second cancellation (on either the original or another clone) is a
  // no-op: the first writer already won.
  assert!(!handle.cancel());
}

#[test]
fn cancellation_handle_equality_is_shared_state_not_shared_value() {
  let handle = CancellationHandle::new();
  let clone = handle.clone();
  let independent = CancellationHandle::new();

  assert_eq!(handle, clone, "clones of the same handle are equal");
  assert_ne!(
    handle, independent,
    "two never-cancelled handles are still not equal unless they're clones"
  );

  independent.cancel();
  assert_ne!(
    handle, independent,
    "reaching the same cancelled state does not make unrelated handles equal"
  );
}

#[test]
fn cancel_after_an_unrelated_timeout_still_records_and_returns_true() {
  // CancellationHandle only tracks whether cancellation was requested
  // through it, not whether the operation is still running -- timing out
  // never touches the handle's own state, so a cancel() afterward is not
  // rejected as "too late", it just has nothing left to affect.
  let handle = CancellationHandle::new();
  let request = Request::browser("unknown-browser-id")
    .timeout(std::time::Duration::ZERO)
    .cancellation(handle.clone());
  let error = extract(request).expect_err("a zero timeout must stop the request");
  assert_eq!(error.stop_reason(), Some(StopReason::TimedOut));

  assert!(
    handle.cancel(),
    "cancel() after an unrelated timeout still records the request"
  );
  assert!(handle.is_cancelled());
}

#[test]
fn stop_reason_is_none_for_an_ordinary_request_error() {
  let error = extract(Request::browser("definitely-not-a-registered-browser-id"))
    .expect_err("an unknown browser id is a request error");
  assert_eq!(error.stop_reason(), None);
}

#[test]
fn fault_kind_classifies_a_typed_direct_path_error_as_a_request_fault() {
  let directory = crate::utils::TempDir::new().expect("temp directory");
  let missing = directory
    .path()
    .join("no such parent directory")
    .join("missing");
  let error = direct_path::cookies_from_path(direct_path::DirectPathRequest::new(&missing))
    .expect_err("a missing explicit source is a typed DirectPathError");
  assert_eq!(error.fault_kind(), FaultKind::Request);
}

#[test]
fn fault_kind_classifies_unknown_browser_on_extract_as_request() {
  let error = extract(Request::browser("definitely-not-a-registered-browser-id"))
    .expect_err("an unknown browser id is a request error");
  assert_eq!(error.fault_kind(), FaultKind::Request);
  assert!(matches!(error, Error::Request(_)));
}

#[cfg(unix)]
#[test]
fn explicit_path_rejects_encrypted_rows_without_browser_identity() {
  let directory = crate::utils::TempDir::new().expect("temp directory");
  let db = directory.path().join("Cookies");
  seed_explicit_path_cookie(&db, "", b"v11encrypted");

  let error = chromium_based_with_browser_id(None, db.clone(), None, false)
    .expect_err("encrypted rows require a browser identity");
  assert!(error.to_string().contains("no browser key identity"));
  assert!(error.to_string().contains("browser_id"));

  let detailed_error = chromium_based_detailed_with_browser_id(None, db, None, false)
    .expect_err("detailed encrypted rows require a browser identity");
  assert!(detailed_error
    .to_string()
    .contains("no browser key identity"));
}

#[cfg(unix)]
#[test]
fn explicit_path_without_identity_remains_available_for_plaintext_only_databases() {
  let directory = crate::utils::TempDir::new().expect("temp directory");
  let db = directory.path().join("Cookies");
  seed_explicit_path_cookie(&db, "plaintext", b"");

  let cookies = chromium_based_with_browser_id(None, db.clone(), None, false)
    .expect("plaintext-only databases need no key identity");
  assert_eq!(cookies.len(), 1);
  assert_eq!(cookies[0].value, "plaintext");

  let detailed = chromium_based_detailed_with_browser_id(None, db, None, false)
    .expect("detailed plaintext-only databases need no key identity");
  assert_eq!(detailed.len(), 1);
  assert_eq!(detailed[0].cookie.value, "plaintext");
}

#[cfg(target_os = "macos")]
#[test]
fn registered_chromium_without_keychain_identity_is_plaintext_only() {
  for browser_id in ["coccoc", "yandex"] {
    let directory = crate::utils::TempDir::new().expect("temp directory");
    let db = directory.path().join("Cookies");
    seed_explicit_path_cookie(&db, "plaintext", b"");
    let cookies = chromium_based_with_browser_id(Some(browser_id), db, None, false)
      .expect("registered browser without credentials can read plaintext");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].value, "plaintext");
  }

  let directory = crate::utils::TempDir::new().expect("temp directory");
  let db = directory.path().join("Cookies");
  seed_explicit_path_cookie(&db, "", b"v10encrypted");
  let error = chromium_based_with_browser_id(Some("coccoc"), db, None, false)
    .expect_err("registered browser without credentials cannot read encrypted rows");
  assert!(error.to_string().contains("no browser key identity"));
}

/// `coccoc`/`yandex` are registered Chromium forks with no dedicated named
/// function — unlike `chrome`, `brave`, and the rest, whose one hardcoded
/// string can never name them. `browser`/`extract(Request::browser(..))`
/// must resolve them through the registry instead of reporting them as an
/// unrecognized ID, the one failure mode a named function's fixed string
/// structurally cannot produce.
#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
fn public_browser_and_extract_reach_registry_only_browsers_no_named_function_can_name() {
  fn assert_resolved_through_registry(browser_id: &str, error: &dyn std::fmt::Display) {
    assert!(
      !error.to_string().contains("unknown browser id"),
      "{browser_id} must resolve through the registry rather than being unrecognized: {error}"
    );
  }

  for browser_id in ["coccoc", "yandex"] {
    if let Err(error) = browser(browser_id, None) {
      assert_resolved_through_registry(browser_id, &error);
    }
    if let Err(error) = extract(Request::browser(browser_id)) {
      assert_resolved_through_registry(browser_id, &error);
    }
  }
}

#[cfg(unix)]
#[test]
fn explicit_path_identity_check_covers_the_profile_before_domain_filtering() {
  let directory = crate::utils::TempDir::new().expect("temp directory");
  let db = directory.path().join("Cookies");
  seed_explicit_path_cookie(&db, "plaintext", b"");
  let connection = rusqlite::Connection::open(&db).expect("reopen fixture");
  connection
    .execute(
      "INSERT INTO cookies VALUES ('.other.test', '/', 0, 0, 'encrypted', '', ?1, 0, 0)",
      rusqlite::params![b"v11encrypted"],
    )
    .expect("seed encrypted row outside the requested domain");
  drop(connection);

  let error =
    chromium_based_with_browser_id(None, db, Some(vec!["example.test".to_string()]), false)
      .expect_err("the whole encrypted profile requires an identity");
  assert!(error.to_string().contains("no browser key identity"));
}

#[cfg(unix)]
fn seed_explicit_path_cookie(db: &std::path::Path, value: &str, encrypted_value: &[u8]) {
  let connection = rusqlite::Connection::open(db).expect("open fixture");
  connection
    .execute_batch(
      "CREATE TABLE meta (
         key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR
       );
       INSERT INTO meta (key, value) VALUES ('version', '23');
       CREATE TABLE cookies (
         host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
         name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER,
         samesite INTEGER
       );",
    )
    .expect("create cookie schema");
  connection
    .execute(
      "INSERT INTO cookies VALUES ('.example.test', '/', 0, 0, 'session', ?1, ?2, 0, 0)",
      rusqlite::params![value, encrypted_value],
    )
    .expect("seed cookie row");
}

fn named_cookie(name: &str) -> Cookie {
  Cookie {
    domain: "example.test".to_string(),
    path: "/".to_string(),
    secure: false,
    expires: None,
    name: name.to_string(),
    value: String::new(),
    http_only: false,
    same_site: SAME_SITE_UNSPECIFIED,
  }
}

fn selected_success_report(termination: &str) -> report::ExtractionReport {
  let opaque = "a".repeat(64);
  serde_json::from_value(serde_json::json!({
    "schema_version": 1,
    "status": "complete",
    "termination": termination,
    "summary": {
      "registered_browsers": 1,
      "browsers_detected": 1,
      "browsers_not_detected": 0,
      "installations_discovered": 1,
      "profiles_discovered": 1,
      "sources_succeeded": 1,
      "sources_failed": 0,
      "rows_seen": 1,
      "cookies_emitted": 1,
      "rows_skipped": 0,
      "rows_rejected": 0,
      "provider_failures": 0,
      "counters_saturated": false
    },
    "profiles": [{
      "profile": {
        "browser_id": "firefox",
        "installation_id": opaque,
        "profile_id": opaque,
        "display_name": "Default",
        "path": "display-only",
        "path_lossy": false
      },
      "sources": [{
        "source": {
          "role": "persistent",
          "format": "mozilla_sqlite",
          "path": "display-only/cookies.sqlite",
          "path_lossy": false,
          "precedence": 10
        },
        "status": "succeeded",
        "selected": true,
        "acquisition_strategy": "live_read_only",
        "cookies": [{
          "domain": ".example.test",
          "path": "/",
          "secure": false,
          "expires": null,
          "name": "retained",
          "value": "value",
          "http_only": false,
          "same_site": -1
        }],
        "stats": {
          "rows_seen": 1,
          "cookies_emitted": 1,
          "rows_skipped": 0,
          "rows_rejected": 0,
          "provider_failures": 0,
          "acquisition_attempts": 1,
          "counters_saturated": false
        },
        "issues": []
      }],
      "stats": {
        "rows_seen": 1,
        "cookies_emitted": 1,
        "rows_skipped": 0,
        "rows_rejected": 0,
        "provider_failures": 0,
        "acquisition_attempts": 1,
        "counters_saturated": false
      },
      "issues": []
    }],
    "issues": []
  }))
  .expect("valid stopped profile report fixture")
}

#[test]
fn profile_scoped_flatten_returns_each_exact_typed_stop_despite_selected_cookies() {
  use browser::outcome::Termination;
  // The DTO string and the typed value are supplied separately on purpose: the
  // fixture builds the wire report, and the flatten seam classifies from the
  // enum. A mismatch here would be a bug in this test, not in the seam.
  for (wire, termination, expected) in [
    ("timed_out", Termination::TimedOut, StopReason::TimedOut),
    ("cancelled", Termination::Cancelled, StopReason::Cancelled),
    (
      "resource_exhausted",
      Termination::ResourceExhausted,
      StopReason::ResourceExhausted,
    ),
  ] {
    let error = flatten_selected_report_cookies(selected_success_report(wire), termination)
      .expect_err("profile-scoped flat APIs must not turn a stop into success");
    assert_eq!(anyhow_stop_reason(&error), Some(expected));
  }

  let cookies = flatten_selected_report_cookies(
    selected_success_report("completed"),
    browser::outcome::Termination::Completed,
  )
  .expect("a completed profile report still flattens selected cookies");
  assert_eq!(cookies.len(), 1);
  assert_eq!(cookies[0].name, "retained");
}

#[test]
fn a_report_with_no_selected_success_is_the_typed_no_selected_source_code() {
  // The flatten seam is the only producer of this code, and it used to be a
  // bare `bail!` -- unrecoverable at the job edge without parsing prose.
  let mut report = selected_success_report("completed");
  for profile in &mut report.profiles {
    for source in &mut profile.sources {
      source.selected = false;
    }
  }
  let error = flatten_selected_report_cookies(report, browser::outcome::Termination::Completed)
    .expect_err("a report with nothing selected cannot flatten");
  assert_eq!(Error::from(error).code(), "no_selected_source");
}

#[test]
fn profile_resolution_and_extraction_share_one_absolute_manual_clock_budget() {
  use common::deadline::{test_clock::ManualClock, CancellationToken, Deadline};
  use std::cell::Cell;
  use std::time::Duration;

  let clock = ManualClock::default();
  let runtime = common::deadline::BoundaryRuntime::with_stop(
    &clock,
    Deadline::after(&clock, Duration::from_secs(10)),
    CancellationToken::default(),
  );
  let resolutions = Cell::new(0);
  let extractions = Cell::new(0);
  let (profile_id, remaining) = resolve_then_extract_profile_with_runtime(
    "firefox",
    "Default",
    &runtime,
    |_browser_id, _query, _runtime| {
      resolutions.set(resolutions.get() + 1);
      clock.advance(Duration::from_secs(7));
      Ok("a".repeat(64))
    },
    |_browser_id, _profile_id, extraction_runtime| {
      extractions.set(extractions.get() + 1);
      Ok(
        extraction_runtime
          .deadline
          .remaining(extraction_runtime.clock),
      )
    },
  )
  .expect("profile resolution and extraction fit within one budget");

  assert_eq!(profile_id, "a".repeat(64));
  assert_eq!(remaining, Duration::from_secs(3));
  assert_eq!(resolutions.get(), 1, "profile discovery runs exactly once");
  assert_eq!(extractions.get(), 1);
}

#[test]
fn profile_resolution_observes_stops_before_and_after_resolution() {
  use common::deadline::{test_clock::ManualClock, CancellationToken, Deadline};
  use std::cell::Cell;
  use std::time::Duration;

  for pre_stop in [StopReason::TimedOut, StopReason::Cancelled] {
    let clock = ManualClock::default();
    let token = CancellationToken::default();
    let duration = match pre_stop {
      StopReason::TimedOut => Duration::ZERO,
      StopReason::Cancelled => {
        assert!(token.cancel());
        Duration::from_secs(10)
      }
      StopReason::ResourceExhausted => unreachable!(),
    };
    let runtime = common::deadline::BoundaryRuntime::with_stop(
      &clock,
      Deadline::after(&clock, duration),
      token,
    );
    let resolutions = Cell::new(0);
    let extractions = Cell::new(0);
    let error = resolve_then_extract_profile_with_runtime(
      "firefox",
      "Default",
      &runtime,
      |_browser_id, _query, _runtime| {
        resolutions.set(resolutions.get() + 1);
        Ok("a".repeat(64))
      },
      |_browser_id, _profile_id, _runtime| {
        extractions.set(extractions.get() + 1);
        Ok(())
      },
    )
    .expect_err("a stop before resolution must win");
    assert_eq!(anyhow_stop_reason(&error), Some(pre_stop));
    assert_eq!(resolutions.get(), 0);
    assert_eq!(extractions.get(), 0);
  }

  let clock = ManualClock::default();
  let token = CancellationToken::default();
  let runtime = common::deadline::BoundaryRuntime::with_stop(
    &clock,
    Deadline::after(&clock, Duration::from_secs(10)),
    token.clone(),
  );
  let extractions = Cell::new(0);
  let error = resolve_then_extract_profile_with_runtime(
    "firefox",
    "Default",
    &runtime,
    |_browser_id, _query, _runtime| {
      assert!(token.cancel());
      Ok("a".repeat(64))
    },
    |_browser_id, _profile_id, extraction_runtime| {
      extractions.set(extractions.get() + 1);
      extraction_runtime.check()?;
      Ok(())
    },
  )
  .expect_err("cancellation after resolution must reach extraction");
  assert_eq!(anyhow_stop_reason(&error), Some(StopReason::Cancelled));
  assert_eq!(extractions.get(), 1);
}

fn first_ok(_domains: Option<Vec<String>>) -> anyhow::Result<Vec<Cookie>> {
  Ok(vec![named_cookie("first")])
}

fn second_ok(_domains: Option<Vec<String>>) -> anyhow::Result<Vec<Cookie>> {
  Ok(vec![named_cookie("second")])
}

/// Runs production `load`'s aggregation over a synthetic `fan_out` round.
///
/// The runtime is untripped and every browser is claimed, which is the state
/// `fan_out` leaves behind when nothing stops it -- so these drive exactly the
/// rules the old `load_from_browsers` twin restated, but through the code
/// `load` actually runs.
fn aggregated(entries: Vec<(&str, anyhow::Result<Vec<Cookie>>)>) -> anyhow::Result<Vec<Cookie>> {
  let clock = common::deadline::SystemClock;
  let runtime = common::deadline::BoundaryRuntime::standard(&clock);
  let names: Vec<&str> = entries.iter().map(|(name, _)| *name).collect();
  let results: Vec<_> = entries.into_iter().map(|(_, result)| result).collect();
  aggregate_load_results(&names, results, &runtime)
}

#[test]
fn no_installed_browsers_returns_ok_empty() {
  let result = aggregated(vec![
    ("firefox", not_installed(None)),
    ("chrome", not_installed(None)),
  ])
  .expect("absence is not an extraction failure");
  assert!(result.is_empty());
}

#[test]
fn all_installed_browsers_failing_returns_aggregate_error() {
  let result = aggregated(vec![
    ("firefox", extraction_fails(None)),
    ("chrome", extraction_fails(None)),
  ]);
  assert!(result.is_err(), "expected Err when all browsers fail");
  let msg = result.unwrap_err().to_string();
  assert!(
    msg.contains("all browser extractions failed"),
    "error should mention aggregate failure, got: {msg}"
  );
  assert!(
    msg.contains("firefox: cookie database is corrupt"),
    "error should list firefox error, got: {msg}"
  );
  assert!(
    msg.contains("chrome: cookie database is corrupt"),
    "error should list chrome error, got: {msg}"
  );
}

#[test]
fn aggregate_load_stop_keeps_its_summary_and_typed_source() {
  let stop = common::deadline::BoundaryStop::TimedOut;
  let error = aggregate_load_failure(
    &["chrome: operation deadline expired".to_owned()],
    Some(stop),
  );
  assert!(error.to_string().contains("all browser extractions failed"));
  assert!(format!("{error:#}").contains("chrome: operation deadline expired"));
  assert_eq!(
    error.downcast_ref::<common::deadline::BoundaryStop>(),
    Some(&stop)
  );
}

#[test]
fn partial_failure_returns_ok() {
  let result = aggregated(vec![
    ("firefox", extraction_fails(None)),
    ("chrome", always_ok(None)),
  ]);
  assert!(
    result.is_ok(),
    "expected Ok when at least one browser succeeds, got: {result:?}"
  );
}

#[test]
fn missing_browsers_do_not_hide_an_installed_browser_failure() {
  let message = aggregated(vec![
    ("firefox", not_installed(None)),
    ("chrome", extraction_fails(None)),
  ])
  .expect_err("the one installed browser failed")
  .to_string();
  assert!(message.contains("chrome: cookie database is corrupt"));
  assert!(!message.contains("firefox"));
}

#[test]
fn empty_browser_list_returns_ok_empty() {
  let result = aggregated(vec![]);
  assert!(result.is_ok());
  assert!(result.unwrap().is_empty());
}

#[test]
fn load_aggregation_preserves_source_order() {
  let cookies = aggregated(vec![
    ("first", first_ok(None)),
    ("missing", not_installed(None)),
    ("second", second_ok(None)),
  ])
  .expect("successful sources survive an intervening extraction error");
  let names: Vec<_> = cookies.iter().map(|cookie| cookie.name.as_str()).collect();
  assert_eq!(names, vec!["first", "second"]);
}

#[test]
fn load_aggregation_keeps_cookies_from_an_in_flight_browser_after_the_shared_stop() {
  let clock = common::deadline::SystemClock;
  let token = common::deadline::CancellationToken::default();
  assert!(token.cancel());
  let runtime = common::deadline::BoundaryRuntime::with_stop(
    &clock,
    common::deadline::Deadline::standard(),
    token,
  );
  let cookies = aggregate_load_results(
    &["chrome"],
    vec![Ok(vec![named_cookie("in-flight")])],
    &runtime,
  )
  .expect("a completed in-flight browser remains successful for flat load");
  assert_eq!(cookies.len(), 1);
  assert_eq!(cookies[0].name, "in-flight");
}

#[test]
fn a_browser_error_carrying_a_stop_makes_it_typed_on_the_aggregate() {
  // Previously unreachable from a test: the twin never modelled a browser
  // whose own failure carries a `BoundaryStop`.
  let stopped: anyhow::Result<Vec<Cookie>> =
    Err(anyhow::Error::new(common::deadline::BoundaryStop::TimedOut).context("chrome gave up"));
  let error = aggregated(vec![("chrome", stopped)]).expect_err("a stopped browser is a failure");
  assert_eq!(
    error.downcast_ref::<common::deadline::BoundaryStop>(),
    Some(&common::deadline::BoundaryStop::TimedOut)
  );
}

#[test]
fn an_unclaimed_browser_under_a_tripped_runtime_is_itself_the_stop() {
  // The other previously unreachable branch: `fan_out` returned fewer results
  // than names because the runtime tripped, and no individual browser
  // reported an error of its own -- every one it did claim was uninstalled.
  let clock = common::deadline::SystemClock;
  let stop = common::deadline::CancellationToken::default();
  stop.cancel();
  let runtime = common::deadline::BoundaryRuntime::with_stop(
    &clock,
    common::deadline::Deadline::standard(),
    stop,
  );
  let error = aggregate_load_results(&["firefox", "chrome"], vec![not_installed(None)], &runtime)
    .expect_err("an unclaimed browser under a tripped runtime is a stop, not an empty success");
  assert_eq!(
    error.downcast_ref::<common::deadline::BoundaryStop>(),
    Some(&common::deadline::BoundaryStop::Cancelled)
  );
}

#[cfg(target_os = "linux")]
#[test]
#[allow(deprecated)]
fn opera_gx_remains_explicitly_unsupported_and_unadvertised_on_linux() {
  let error = opera_gx(None).expect_err("Opera GX has no Linux implementation");
  assert!(error
    .to_string()
    .contains("Opera GX is not supported on Linux"));
  assert!(supported_browsers()
    .expect("supported browsers")
    .iter()
    .all(|browser| browser.id.as_str() != "opera_gx"));
}

fn source_test_path(tag: &str) -> (crate::utils::TempDir, std::path::PathBuf) {
  let dir = crate::utils::TempDir::new().expect("temporary source directory");
  let path = dir.path().join(tag);
  (dir, path)
}

#[test]
fn any_browser_sniffs_sqlite_decoder_family_from_schema() {
  let (_chromium_dir, chromium_path) = source_test_path("chromium.sqlite");
  let chromium = rusqlite::Connection::open(&chromium_path).expect("Chromium fixture");
  chromium
    .execute("CREATE TABLE cookies (name TEXT)", [])
    .expect("Chromium table");
  drop(chromium);

  let (_mozilla_dir, mozilla_path) = source_test_path("mozilla.sqlite");
  let mozilla = rusqlite::Connection::open(&mozilla_path).expect("Mozilla fixture");
  mozilla
    .execute("CREATE TABLE moz_cookies (name TEXT)", [])
    .expect("Mozilla table");
  drop(mozilla);

  assert_eq!(
    direct_path::classify_cookie_source_legacy(&chromium_path).expect("sniff Chromium"),
    AnyBrowserSource::ChromiumSqlite
  );
  assert_eq!(
    direct_path::classify_cookie_source_legacy(&mozilla_path).expect("sniff Mozilla"),
    AnyBrowserSource::MozillaSqlite
  );
}

#[test]
fn any_browser_rejects_ambiguous_or_unrelated_sqlite_schemas() {
  let (_ambiguous_dir, ambiguous_path) = source_test_path("ambiguous.sqlite");
  let ambiguous = rusqlite::Connection::open(&ambiguous_path).expect("ambiguous fixture");
  ambiguous
    .execute_batch("CREATE TABLE cookies (name TEXT); CREATE TABLE moz_cookies (name TEXT);")
    .expect("ambiguous tables");
  drop(ambiguous);
  let error = direct_path::classify_cookie_source_legacy(&ambiguous_path)
    .expect_err("ambiguous schema must fail");
  assert!(error
    .to_string()
    .contains("both `cookies` and `moz_cookies`"));

  let (_other_dir, other_path) = source_test_path("other.sqlite");
  let other = rusqlite::Connection::open(&other_path).expect("other fixture");
  other
    .execute("CREATE TABLE unrelated (value TEXT)", [])
    .expect("unrelated table");
  drop(other);
  let error = direct_path::classify_cookie_source_legacy(&other_path)
    .expect_err("unrelated schema must fail");
  assert!(error.to_string().contains("unsupported SQLite database"));
}

#[test]
fn any_browser_sniffs_binary_cookie_signature_without_decoder_probing() {
  let (_dir, path) = source_test_path("Cookies.binarycookies");
  std::fs::write(&path, b"cooksynthetic").expect("Safari header fixture");
  assert_eq!(
    direct_path::classify_cookie_source_legacy(&path).expect("sniff Safari"),
    AnyBrowserSource::SafariBinaryCookies
  );
}

#[cfg(target_os = "windows")]
#[test]
fn any_browser_sniffs_ese_signature() {
  let (_dir, path) = source_test_path("WebCacheV01.dat");
  std::fs::write(&path, [0, 0, 0, 0, 0xef, 0xcd, 0xab, 0x89]).expect("ESE header fixture");
  assert_eq!(
    direct_path::classify_cookie_source_legacy(&path).expect("sniff ESE"),
    AnyBrowserSource::InternetExplorerEse
  );
}

#[cfg(unix)]
fn seed_test_cookies(db_path: &std::path::Path, cookie_name: &str, cookie_value: &str) {
  let conn = rusqlite::Connection::open(db_path).expect("open sqlite db");
  conn
    .execute_batch(
      "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
      INSERT INTO meta (key, value) VALUES ('version', '23');
      CREATE TABLE cookies (
        host_key TEXT NOT NULL,
        path TEXT NOT NULL,
        is_secure INTEGER NOT NULL,
        expires_utc INTEGER NOT NULL,
        name TEXT NOT NULL,
        value TEXT NOT NULL,
        encrypted_value BLOB,
        is_httponly INTEGER NOT NULL,
        samesite INTEGER NOT NULL
      );",
    )
    .expect("create Chromium schema");
  conn
    .execute(
      "INSERT INTO cookies (host_key, path, is_secure, expires_utc, name, value, encrypted_value, is_httponly, samesite)
       VALUES ('.example.com', '/', 0, 0, ?1, ?2, ?3, 0, 0)",
      rusqlite::params![cookie_name, cookie_value, &b""[..]],
    )
    .expect("insert row");
}

#[cfg(unix)]
#[test]
fn test_chrome_resolves_network_cookies_on_unix() {
  let home = crate::utils::TempDir::new().expect("create temp home");
  let home_dir = home.path().to_path_buf();

  #[cfg(target_os = "macos")]
  let chrome_dir = home_dir.join("Library/Application Support/Google/Chrome");

  #[cfg(not(target_os = "macos"))]
  let chrome_dir = home_dir.join(".config/google-chrome");

  let network_dir = chrome_dir.join("Default/Network");
  let default_dir = chrome_dir.join("Default");

  std::fs::create_dir_all(&network_dir).expect("create network dir");
  std::fs::create_dir_all(&default_dir).expect("create default dir");

  let local_state = chrome_dir.join("Local State");
  std::fs::write(&local_state, b"{}").expect("create local state");

  let network_db = network_dir.join("Cookies");
  let legacy_db = default_dir.join("Cookies");

  seed_test_cookies(&network_db, "net_cookie", "net_val");
  seed_test_cookies(&legacy_db, "legacy_cookie", "legacy_val");

  // Thread-local override, not a mutated process environment: parallel
  // tests each install their own value and never observe or serialize on
  // another test's real environment (see `browser::registry::EnvOverride`).
  let env = std::collections::BTreeMap::from([(
    std::ffi::OsString::from("HOME"),
    home_dir.into_os_string(),
  )]);
  let _env_override = browser::registry::EnvOverride::install(env);

  let cookies = chrome(None).expect("chrome() should find and parse network cookies");
  assert_eq!(
    cookies.len(),
    1,
    "expected 1 cookie from Network/Cookies, got {:?}",
    cookies
  );
  assert_eq!(cookies[0].name, "net_cookie");
  assert_eq!(cookies[0].value, "net_val");
}

/// Complements `public_browser_and_extract_reach_registry_only_browsers_no_named_function_can_name`
/// (which only asserts on the error path) with a positive case: `browser`/
/// `extract(Request::browser(..))` actually resolve and read cookies from
/// CocCoc, a registered Chromium fork with no dedicated named function.
#[cfg(target_os = "macos")]
#[test]
fn browser_and_extract_read_real_cookies_from_a_registry_only_browser() {
  let home = crate::utils::TempDir::new().expect("create temp home");
  let home_dir = home.path().to_path_buf();
  let coccoc_dir = home_dir.join("Library/Application Support/Coccoc");
  let default_dir = coccoc_dir.join("Default");
  std::fs::create_dir_all(&default_dir).expect("create CocCoc default profile dir");
  std::fs::write(coccoc_dir.join("Local State"), b"{}").expect("create Local State");
  seed_test_cookies(&default_dir.join("Cookies"), "coccoc_cookie", "coccoc_val");

  let env = std::collections::BTreeMap::from([(
    std::ffi::OsString::from("HOME"),
    home_dir.into_os_string(),
  )]);
  let _env_override = browser::registry::EnvOverride::install(env);

  let cookies =
    browser("coccoc", None).expect("browser(\"coccoc\", ..) should find and parse cookies");
  assert_eq!(cookies.len(), 1, "expected 1 cookie, got {cookies:?}");
  assert_eq!(cookies[0].name, "coccoc_cookie");
  assert_eq!(cookies[0].value, "coccoc_val");

  let cookies = extract(Request::browser("coccoc"))
    .expect("extract(Request::browser(\"coccoc\")) should find and parse cookies");
  assert_eq!(cookies.len(), 1, "expected 1 cookie, got {cookies:?}");
  assert_eq!(cookies[0].name, "coccoc_cookie");
  assert_eq!(cookies[0].value, "coccoc_val");
}
