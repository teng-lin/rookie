/// Test convenience: the mechanical `from_candidate` conversion.
///
/// Production states effective `selected` / `acquisition` explicitly so a
/// forgotten overlay is a compile error; fixtures that only want "whatever
/// the candidate said" go through here rather than repeating it.
fn source_from_candidate(candidate: SourceCandidate) -> Source {
  Source::new(
    candidate.identity(),
    candidate.selected,
    candidate.acquisition,
  )
}

#[test]
fn source_outcomes_sort_persistent_before_session_then_by_precedence() {
  let mut sources = vec![
    ordering_source(CookieSourceRoleId::known("future_z"), 1),
    ordering_source(CookieSourceRoleId::session(), 20),
    ordering_source(CookieSourceRoleId::persistent(), 20),
    ordering_source(CookieSourceRoleId::known("future_a"), 2),
    ordering_source(CookieSourceRoleId::session(), 10),
    ordering_source(CookieSourceRoleId::known("future_a"), 1),
    ordering_source(CookieSourceRoleId::persistent(), 10),
    ordering_source(CookieSourceRoleId::known("future_a"), 1),
  ];
  sort_source_outcomes(&mut sources);
  let order = sources
    .iter()
    .map(|source| (source.source.role.to_string(), source.source.precedence))
    .collect::<Vec<_>>();
  assert_eq!(
    order,
    vec![
      ("persistent".to_owned(), 10),
      ("persistent".to_owned(), 20),
      ("session".to_owned(), 10),
      ("session".to_owned(), 20),
      ("future_a".to_owned(), 1),
      ("future_a".to_owned(), 1),
      ("future_a".to_owned(), 2),
      ("future_z".to_owned(), 1),
    ]
  );

  let mut descriptors = sources
    .iter()
    .rev()
    .map(|source| CookieSourceDescriptor {
      role: source.source.role.clone(),
      format: source.source.format.clone(),
      path: source.source.path.clone(),
      path_lossy: source.source.path_lossy,
      precedence: source.source.precedence,
    })
    .collect::<Vec<_>>();
  sort_source_descriptors(&mut descriptors);
  let descriptor_order = descriptors
    .iter()
    .map(|source| (source.role.to_string(), source.precedence))
    .collect::<Vec<_>>();
  assert_eq!(descriptor_order, order);
}

fn ordering_source(role: CookieSourceRoleId, precedence: u16) -> SourceDraft {
  SourceDraft::new(
    CookieSourceIdentity {
      role,
      format: CookieSourceFormatId::known("chromium_sqlite"),
      path: "/tmp/source".to_owned(),
      path_lossy: false,
      precedence,
    },
    std::path::Path::new("/tmp/source"),
    true,
    AcquisitionStrategyCode::live_read_only(),
  )
}
use super::*;
use crate::browser::registry::ProfileSelection;
use crate::browser::report_core::ReportStatusCode;
use crate::execution::ExecutionControl;
use std::path::PathBuf;

fn identity() -> ProfileIdentity {
  ProfileIdentity {
    browser_id: BrowserId::known("firefox"),
    installation_id: InstallationId::known(&"a".repeat(64)),
    profile_id: ProfileId::known(&"b".repeat(64)),
    display_name: "default".to_owned(),
    path: "/profiles/default".to_owned(),
    path_lossy: false,
  }
}

fn source(failed: bool) -> SourceDraft {
  let source_path = PathBuf::from("/profiles/default/cookies.sqlite");
  let mut source = SourceDraft::new(
    source_identity(&SourceIdentity {
      path: source_path.clone(),
      role: CookieSourceRoleId::persistent(),
      format: CookieSourceFormatId::known("mozilla_sqlite"),
      precedence: registry::PERSISTENT_SOURCE_PRECEDENCE,
    }),
    &source_path,
    true,
    AcquisitionStrategyCode::live_read_only(),
  );
  source.failed = failed;
  source
}

/// The canonical record for a fixture cookie.
///
/// `canonicalize_profile` does not synthesize records from `cookies`, so a
/// fixture that sets only `cookies` finalizes to zero rows. `Outcome::finalize`
/// re-stamps provenance through `assign_provenance`, so a pending `SourceRef`
/// is all a fixture needs here.
fn fixture_record(cookie: crate::common::enums::Cookie, ordinal: usize) -> CookieRecord {
  CookieRecord::from_cookie(
    cookie,
    crate::browser::cookie_record::SourceRef::pending(ordinal),
  )
}

fn completed_cookie(name: &str) -> crate::common::enums::Cookie {
  crate::common::enums::Cookie {
    domain: ".example.test".to_owned(),
    path: "/".to_owned(),
    secure: false,
    expires: None,
    name: name.to_owned(),
    value: format!("secret-{name}"),
    http_only: true,
    same_site: 1,
  }
}

fn completed_source(name: &str) -> SourceDraft {
  let mut source = source(false);
  source.cookies.push(completed_cookie(name));
  source
    .records
    .push(fixture_record(completed_cookie(name), 0));
  source.stats.rows_seen = 1;
  source.stats.cookies_emitted = 1;
  source
}

fn outcome(profiles: Vec<ProfileDraft>, discovery_failed: bool) -> BrowserDraft {
  BrowserDraft {
    browser_id: BrowserId::known("firefox"),
    compatibility_family: CompatibilityFamily::Gecko,
    detected: true,
    installations_discovered: 1,
    discovery_failed,
    profiles,
    issues: Vec::new(),
    termination: Termination::Completed,
  }
}

fn status(outcome: BrowserDraft) -> ReportStatusCode {
  assemble(1, vec![outcome]).status
}

#[test]
fn stop_reasons_reach_the_report_wire_as_typed_request_issues() {
  use crate::common::deadline::{test_clock::ManualClock, CancellationToken, Deadline};
  use std::time::Duration;

  for (stop, expected, issue_code) in [
    (BoundaryStop::Cancelled, "cancelled", "request_cancelled"),
    (
      BoundaryStop::ResourceExhausted,
      "resource_exhausted",
      "request_resource_exhausted",
    ),
  ] {
    let clock = ManualClock::default();
    let token = CancellationToken::default();
    match stop {
      BoundaryStop::Cancelled => assert!(token.cancel()),
      BoundaryStop::ResourceExhausted => assert!(token.exhaust_resources()),
      BoundaryStop::TimedOut => unreachable!("covered separately"),
    }
    let runtime = BoundaryRuntime::with_stop(
      &clock,
      Deadline::after(&clock, Duration::from_secs(10)),
      token,
    );
    let report = browser_extraction_report_with_runtime(
      "firefox",
      ProfileSelection::AllProfiles,
      None,
      crate::SessionPolicy::IncludeSession,
      &runtime,
    )
    .expect("typed stop becomes a report termination");
    assert_eq!(report.termination.as_str(), expected);
    assert_eq!(report.status.as_str(), "failed");
    assert_eq!(report.summary.browsers_detected, 0);
    assert_eq!(report.summary.browsers_not_detected, 0);
    assert_eq!(report.issues.len(), 1);
    assert_eq!(report.issues[0].code.as_str(), issue_code);
    assert_eq!(report.issues[0].cause, issue_code);
    assert_eq!(report.issues[0].stage.as_str(), "registry");
    assert_eq!(report.issues[0].severity.as_str(), "error");
    let wire = serde_json::to_value(report).expect("serialize stopped report");
    assert_eq!(wire["termination"], expected);
  }

  let clock = ManualClock::default();
  let runtime = BoundaryRuntime::new(&clock, Deadline::after(&clock, Duration::ZERO));
  let report = browser_extraction_report_with_runtime(
    "firefox",
    ProfileSelection::AllProfiles,
    None,
    crate::SessionPolicy::IncludeSession,
    &runtime,
  )
  .expect("expired runtime becomes a report termination");
  assert_eq!(report.termination.as_str(), "timed_out");
  assert_eq!(report.status.as_str(), "failed");
  assert_eq!(report.summary.browsers_detected, 0);
  assert_eq!(report.summary.browsers_not_detected, 0);
  assert_eq!(report.issues.len(), 1);
  assert_eq!(report.issues[0].code.as_str(), "request_timed_out");
}

#[test]
fn stopped_report_semantics_cover_before_discovery_after_detection_and_after_one_source() {
  let before_discovery = BrowserDraft {
    browser_id: BrowserId::known("firefox"),
    compatibility_family: CompatibilityFamily::Gecko,
    detected: false,
    installations_discovered: 0,
    discovery_failed: false,
    profiles: Vec::new(),
    issues: Vec::new(),
    termination: Termination::TimedOut,
  };
  let report = assemble(1, vec![before_discovery]);
  assert_eq!(
    serde_json::json!({
      "schema_version": report.schema_version,
      "status": report.status.as_str(),
      "termination": report.termination.as_str(),
      "registered": report.summary.registered_browsers,
      "detected": report.summary.browsers_detected,
      "not_detected": report.summary.browsers_not_detected,
      "issue": report.issues[0].code.as_str(),
    }),
    serde_json::json!({
      "schema_version": 1,
      "status": "failed",
      "termination": "timed_out",
      "registered": 1,
      "detected": 0,
      "not_detected": 0,
      "issue": "request_timed_out",
    })
  );

  let mut after_detection = outcome(Vec::new(), false);
  after_detection.termination = Termination::Cancelled;
  let report = assemble(1, vec![after_detection]);
  assert_eq!(
    serde_json::json!({
      "status": report.status.as_str(),
      "termination": report.termination.as_str(),
      "detected": report.summary.browsers_detected,
      "not_detected": report.summary.browsers_not_detected,
      "issue": report.issues[0].code.as_str(),
    }),
    serde_json::json!({
      "status": "failed",
      "termination": "cancelled",
      "detected": 1,
      "not_detected": 0,
      "issue": "request_cancelled",
    })
  );

  let mut profile = ProfileDraft::new(identity(), true);
  profile.sources.push(completed_source("retained"));
  let mut after_source = outcome(vec![profile], false);
  after_source.termination = Termination::ResourceExhausted;
  let report = assemble(1, vec![after_source]);
  assert_eq!(
    serde_json::json!({
      "status": report.status.as_str(),
      "termination": report.termination.as_str(),
      "sources_succeeded": report.summary.sources_succeeded,
      "cookie": report.profiles[0].sources[0].cookies[0].name.as_str(),
      "issue": report.issues[0].code.as_str(),
    }),
    serde_json::json!({
      "status": "partial",
      "termination": "resource_exhausted",
      "sources_succeeded": 1,
      "cookie": "retained",
      "issue": "request_resource_exhausted",
    })
  );
}

#[test]
fn stop_issue_follows_existing_diagnostics_without_reclassifying_detection() {
  let mut stopped = outcome(Vec::new(), false);
  stopped.issues.push(
    issue(
      "discovery_degraded",
      ExtractionStageCode::discovery(),
      IssueSeverityCode::warning(),
      "discovery recovered before cancellation",
    )
    .with_context(Some(&stopped.browser_id), None, None),
  );
  stopped.termination = Termination::Cancelled;

  let report = assemble(1, vec![stopped]);
  assert_eq!(report.summary.registered_browsers, 1);
  assert_eq!(report.summary.browsers_detected, 1);
  assert_eq!(report.summary.browsers_not_detected, 0);
  assert_eq!(report.status.as_str(), "failed");
  assert_eq!(
    report
      .issues
      .iter()
      .map(|issue| issue.code.as_str())
      .collect::<Vec<_>>(),
    vec!["discovery_degraded", "request_cancelled"]
  );
  assert_eq!(
    report.issues[0].browser_id.as_ref(),
    Some(&BrowserId::known("firefox"))
  );
  assert!(report.issues[1].browser_id.is_none());
}

#[test]
fn stopped_drafts_keep_atomic_sources_in_reports_but_single_browser_projection_returns_the_stop() {
  use crate::common::deadline::{test_clock::ManualClock, CancellationToken, Deadline};
  use std::time::Duration;

  for (stop, termination) in [
    (BoundaryStop::TimedOut, Termination::TimedOut),
    (BoundaryStop::Cancelled, Termination::Cancelled),
    (
      BoundaryStop::ResourceExhausted,
      Termination::ResourceExhausted,
    ),
  ] {
    let clock = ManualClock::default();
    let token = CancellationToken::default();
    let deadline = match stop {
      BoundaryStop::TimedOut => Deadline::after(&clock, Duration::ZERO),
      BoundaryStop::Cancelled => {
        assert!(token.cancel());
        Deadline::after(&clock, Duration::from_secs(10))
      }
      BoundaryStop::ResourceExhausted => {
        assert!(token.exhaust_resources());
        Deadline::after(&clock, Duration::from_secs(10))
      }
    };
    let runtime = BoundaryRuntime::with_stop(&clock, deadline, token);
    let stopped = || {
      let mut profile = ProfileDraft::new(identity(), true);
      profile.sources.push(completed_source("retained"));
      let mut browser = outcome(vec![profile], false);
      browser.termination = termination;
      browser
    };

    let (report, _termination) = assemble_with_runtime(1, vec![stopped()], &runtime);
    let expected_termination = match stop {
      BoundaryStop::TimedOut => "timed_out",
      BoundaryStop::Cancelled => "cancelled",
      BoundaryStop::ResourceExhausted => "resource_exhausted",
    };
    assert_eq!(report.termination.as_str(), expected_termination);
    assert_eq!(report.status.as_str(), "partial");
    assert_eq!(report.issues.len(), 1);
    assert_eq!(report.summary.sources_succeeded, 1);
    assert_eq!(report.summary.rows_seen, 1);
    assert_eq!(report.summary.cookies_emitted, 1);
    assert_eq!(report.profiles[0].sources[0].stats.rows_seen, 1);
    assert_eq!(report.profiles[0].sources[0].stats.cookies_emitted, 1);
    assert_eq!(report.profiles[0].sources[0].cookies.len(), 1);
    assert_eq!(report.profiles[0].sources[0].cookies[0].name, "retained");

    let canonical = finalize_outcomes_with_runtime(1, vec![stopped()], Some(&runtime));
    let error =
      super::super::legacy::project_canonical_outcome_with_runtime("firefox", canonical, &runtime)
        .expect_err("single-browser projection must surface a later typed stop");
    let expected_reason = match stop {
      BoundaryStop::TimedOut => crate::StopReason::TimedOut,
      BoundaryStop::Cancelled => crate::StopReason::Cancelled,
      BoundaryStop::ResourceExhausted => crate::StopReason::ResourceExhausted,
    };
    assert_eq!(crate::anyhow_stop_reason(&error), Some(expected_reason));
    assert!(error
      .chain()
      .any(|cause| cause.downcast_ref::<BoundaryStop>() == Some(&stop)));

    let canonical = finalize_outcomes_with_runtime(1, vec![stopped()], Some(&runtime));
    let cookies = super::super::legacy::project_canonical_outcome_with_stop_projection(
      "firefox",
      canonical,
      &runtime,
      super::super::legacy::StopProjection::PreserveCommitted,
    )
    .expect("flat load keeps a completed in-flight source after the stop");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "retained");
  }
}

#[test]
fn a_stopped_draft_that_is_not_last_still_keeps_every_other_drafts_completed_work() {
  // Regression test: under concurrent fan-out (see `common::concurrency`),
  // a registry-later browser can finish successfully even though a
  // registry-earlier sibling is the one that happened to observe the
  // shared stop first, so a stopped draft is no longer guaranteed to be
  // the last entry in `outcomes`. `finalize_outcomes_with_runtime` must
  // not discard already-completed drafts that appear after it.
  use crate::common::deadline::test_clock::ManualClock;

  let clock = ManualClock::default();
  let runtime = BoundaryRuntime::standard(&clock);

  let mut stopped_profile = ProfileDraft::new(identity(), true);
  stopped_profile
    .sources
    .push(completed_source("stopped-browser-source"));
  let mut stopped = outcome(vec![stopped_profile], false);
  stopped.termination = Termination::TimedOut;

  let mut later_identity = identity();
  later_identity.browser_id = BrowserId::known("chrome");
  let mut later_profile = ProfileDraft::new(later_identity, true);
  later_profile
    .sources
    .push(completed_source("later-browser-source"));
  let mut later = outcome(vec![later_profile], false);
  later.browser_id = BrowserId::known("chrome");

  let (report, _termination) = assemble_with_runtime(2, vec![stopped, later], &runtime);

  assert_eq!(
    report.summary.sources_succeeded, 2,
    "the later, fully-completed browser's source must survive being listed after a stopped draft"
  );
  assert_eq!(report.summary.cookies_emitted, 2);
  let cookie_names: Vec<&str> = report
    .profiles
    .iter()
    .flat_map(|profile| &profile.sources)
    .flat_map(|source| &source.cookies)
    .map(|cookie| cookie.name.as_str())
    .collect();
  assert!(cookie_names.contains(&"stopped-browser-source"));
  assert!(
    cookie_names.contains(&"later-browser-source"),
    "expected the later browser's cookie to survive, got: {cookie_names:?}"
  );
}

#[test]
fn stopped_empty_legacy_outcome_returns_the_typed_boundary_stop() {
  use crate::common::deadline::{test_clock::ManualClock, CancellationToken, Deadline};
  use std::time::Duration;

  for stop in [
    BoundaryStop::TimedOut,
    BoundaryStop::Cancelled,
    BoundaryStop::ResourceExhausted,
  ] {
    let clock = ManualClock::default();
    let token = CancellationToken::default();
    let deadline = match stop {
      BoundaryStop::TimedOut => Deadline::after(&clock, Duration::ZERO),
      BoundaryStop::Cancelled => {
        assert!(token.cancel());
        Deadline::after(&clock, Duration::from_secs(10))
      }
      BoundaryStop::ResourceExhausted => {
        assert!(token.exhaust_resources());
        Deadline::after(&clock, Duration::from_secs(10))
      }
    };
    let runtime = BoundaryRuntime::with_stop(&clock, deadline, token);
    let mut browser = outcome(Vec::new(), false);
    browser.termination = termination_from_stop(stop);
    let canonical = finalize_outcomes_with_runtime(1, vec![browser], Some(&runtime));
    let error =
      super::super::legacy::project_canonical_outcome_with_runtime("firefox", canonical, &runtime)
        .expect_err("a stopped empty legacy outcome remains a typed stop");
    assert!(error
      .chain()
      .any(|cause| cause.downcast_ref::<BoundaryStop>() == Some(&stop)));
  }
}

#[test]
fn finalization_and_projection_share_runtime_and_keep_completed_partial_sources() {
  use crate::common::deadline::{CancellationToken, Clock, Deadline};
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::time::{Duration, Instant};

  struct CancellingClock {
    base: Instant,
    calls: AtomicUsize,
    cancel_on_call: usize,
    token: CancellationToken,
  }

  impl Clock for CancellingClock {
    fn now(&self) -> Instant {
      let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
      if call == self.cancel_on_call {
        assert!(self.token.cancel());
      }
      self.base + Duration::from_millis(call as u64)
    }

    fn sleep(&self, _duration: Duration) {}
  }

  let token = CancellationToken::default();
  let clock = CancellingClock {
    base: Instant::now(),
    calls: AtomicUsize::new(0),
    // Finalization consumes the first eight samples. Projection completes
    // the first source on sample twelve, where cancellation must stop the
    // second source without discarding the first.
    cancel_on_call: 12,
    token: token.clone(),
  };
  let deadline = Deadline::after(&clock, Duration::from_secs(60));
  let runtime = BoundaryRuntime::with_stop(&clock, deadline, token);
  let mut profile = ProfileDraft::new(identity(), true);
  for (index, name) in ["first", "second"].into_iter().enumerate() {
    let path = PathBuf::from(format!("/profiles/default/cookies-{index}.sqlite"));
    let mut source = SourceDraft::new(
      source_identity(&SourceIdentity {
        path: path.clone(),
        role: CookieSourceRoleId::persistent(),
        format: CookieSourceFormatId::known("mozilla_sqlite"),
        precedence: registry::PERSISTENT_SOURCE_PRECEDENCE + index as u16,
      }),
      &path,
      true,
      AcquisitionStrategyCode::live_read_only(),
    );
    let partial_cookie = || crate::common::enums::Cookie {
      domain: ".example.test".to_owned(),
      path: "/".to_owned(),
      secure: false,
      expires: None,
      name: name.to_owned(),
      value: format!("secret-{name}"),
      http_only: false,
      same_site: -1,
    };
    source.cookies.push(partial_cookie());
    source.records.push(fixture_record(partial_cookie(), 0));
    source.stats.rows_seen = 1;
    source.stats.cookies_emitted = 1;
    profile.sources.push(source);
  }

  let (report, _termination) =
    assemble_with_runtime(1, vec![outcome(vec![profile], false)], &runtime);
  assert_eq!(report.termination.as_str(), "cancelled");
  assert_eq!(report.status.as_str(), "partial");
  assert_eq!(report.profiles.len(), 1);
  assert_eq!(report.profiles[0].sources.len(), 1);
  assert_eq!(report.profiles[0].sources[0].cookies[0].name, "first");
  assert_eq!(report.issues.len(), 1);
  assert_eq!(report.issues[0].code.as_str(), "request_cancelled");
  assert_eq!(report.issues[0].cause, "request_cancelled");
}

fn chromium_candidate() -> SourceCandidate {
  SourceCandidate {
    path: PathBuf::from("/chrome/Default").join("Network/Cookies"),
    role: CookieSourceRoleId::persistent(),
    format: CookieSourceFormatId::known("chromium_sqlite"),
    precedence: registry::PERSISTENT_SOURCE_PRECEDENCE,
    exists: true,
    selected: true,
    acquisition: registry::SourceAcquisition::NotAttempted,
    policy: registry::AcquisitionPolicy::Fixed,
  }
}

/// The Chromium half of what `chromium_browser_outcome` now does inline.
/// Kept so the adapter tests still drive the real mapper.
fn chromium_profile_outcome(
  browser_id: &BrowserId,
  installation_id: &str,
  extraction: registry::ChromiumExtractedProfile,
) -> Result<ProfileDraft> {
  let registry::ChromiumExtractedProfile { profile, sources } = extraction;
  let identity = profile_identity(
    browser_id,
    installation_id,
    profile.profile_id.as_str(),
    &profile.display_name,
    &profile.path,
  )?;
  Ok(profile_to_draft(
    identity,
    profile.is_default,
    sources,
    NoSources::Absent,
  ))
}

/// The engine half of what `engine_extract_outcome` now does inline.
fn extracted_profile_outcome(
  browser_id: &BrowserId,
  profile: ExtractedProfile,
) -> Result<ProfileDraft> {
  let identity = profile_identity(
    browser_id,
    profile.identity.installation_id.as_str(),
    profile.identity.profile_id.as_str(),
    &profile.identity.name,
    &profile.identity.path,
  )?;
  Ok(profile_to_draft(
    identity,
    profile.identity.is_default,
    profile.sources,
    NoSources::SourceVanished,
  ))
}

fn chromium_profile(sources: Vec<Source>) -> registry::ChromiumExtractedProfile {
  let path = PathBuf::from("/chrome/Default");
  registry::ChromiumExtractedProfile {
    profile: registry::ChromiumProfile {
      profile_id: "c".repeat(64).parse().expect("valid profile id"),
      installation_id: "d".repeat(64).parse().expect("valid installation id"),
      directory_name: "Default".to_owned(),
      display_name: "Person 1".to_owned(),
      path,
      is_default: true,
      is_active: true,
      active_order: Some(0),
      is_last_used: true,
      persistent_candidates: vec![chromium_candidate()],
    },
    sources,
  }
}

/// A Chromium profile that could not be read still reports the source it
/// tried, so the failure is never mistaken for absence.
///
/// This replaces a test that fed a profile-level `failure: Some(..)` to the
/// mapper and asserted it became `profile_extraction_failed`. No production
/// path ever built that value -- all three adapter sites set `failure: None`,
/// and the failing one attaches the failure to a `Source` instead -- so the
/// test pinned a state the engine could not reach, and the field it depended
/// on is now gone. What actually keeps failure and absence apart is asserted
/// here: the failing profile's source list is not empty.
#[test]
fn a_chromium_profile_that_could_not_be_read_reports_its_source_not_absence() {
  let browser = BrowserId::known("chrome");
  let mut source = {
    let c = chromium_candidate();
    Source::new(c.identity(), c.selected, c.acquisition)
  };
  source.fail(
    registry::SourceFailureStage::Acquisition,
    "Local State is unreadable".to_owned(),
  );
  let engine = chromium_profile_outcome(&browser, &"d".repeat(64), chromium_profile(vec![source]))
    .expect("adapt the profile");

  assert_eq!(
    engine.sources.len(),
    1,
    "a named database that failed is still a named database"
  );
  assert!(engine
    .issues
    .iter()
    .all(|issue| issue.code.as_str() != "profile_has_no_cookie_source"));
  assert_eq!(
    status(outcome(vec![engine], false)),
    ReportStatusCode::failed()
  );
}

/// An empty source list is ordinary absence, and nothing else. Chromium lists
/// only databases that exist, and a database it failed to read is still listed
/// (above), so an installed browser with no cookie store cannot be confused
/// with one that could not be read.
#[test]
fn a_chromium_profile_with_no_source_is_ordinary_absence() {
  let browser = BrowserId::known("chrome");
  let engine = chromium_profile_outcome(&browser, &"d".repeat(64), chromium_profile(Vec::new()))
    .expect("adapt the profile");
  assert!(engine.sources.is_empty());
  let issue = engine.issues.first().expect("an issue for the absence");
  assert_eq!(issue.code.as_str(), "profile_has_no_cookie_source");
  assert!(!issue.is_error());
}

#[test]
fn chromium_adapter_projects_a_selected_candidate_as_a_succeeding_source() {
  let browser = BrowserId::known("chrome");
  let mut source = {
    let c = chromium_candidate();
    Source::new(c.identity(), c.selected, c.acquisition)
  };
  source.acquisition_attempts = 1;
  let engine = chromium_profile_outcome(&browser, &"d".repeat(64), chromium_profile(vec![source]))
    .expect("adapt the profile");
  let report = assemble(1, vec![outcome(vec![engine], false)]);
  assert_eq!(report.status, ReportStatusCode::complete());
  let source = &report.profiles[0].sources[0];
  assert_eq!(source.source.format.as_str(), "chromium_sqlite");
  assert_eq!(source.source.role.as_str(), "persistent");
  assert!(source.selected);
  assert_eq!(source.status, SourceStatusCode::succeeded());
}

/// The real Gecko/Safari/IE adapter. Persistent sorts before session, and a
/// rejected session candidate keeps `selected = false` per Section 5.7.
#[test]
fn engine_adapter_orders_sources_and_preserves_session_selection() {
  let profile = extracted_profile(
    "c",
    "d",
    "default",
    "/firefox",
    "/firefox/Profiles/default",
    vec![
      engine_source(
        "sessionstore.jsonlz4",
        "session",
        20,
        false,
        Some("corrupt"),
      ),
      engine_source("cookies.sqlite", "persistent", 10, true, None),
      engine_source("recovery.baklz4", "session", 30, true, None),
    ],
  );
  let engine =
    extracted_profile_outcome(&BrowserId::known("firefox"), profile).expect("adapt the profile");
  let report = assemble(1, vec![outcome(vec![engine], false)]);
  let ordered = report.profiles[0]
    .sources
    .iter()
    .map(|source| {
      (
        source.source.role.to_string(),
        source.source.precedence,
        source.selected,
        source.status.to_string(),
      )
    })
    .collect::<Vec<_>>();
  assert_eq!(
    ordered,
    vec![
      ("persistent".to_owned(), 10, true, "succeeded".to_owned()),
      ("session".to_owned(), 20, false, "failed".to_owned()),
      ("session".to_owned(), 30, true, "succeeded".to_owned()),
    ]
  );
  // A failed candidate beside a succeeding one is exactly the `partial` case.
  assert_eq!(report.status, ReportStatusCode::partial());
}

/// `finalize_singleton_source` picks the compatibility family from the
/// browser id, so a direct-path Chromium read must not be dispositioned by
/// Gecko's session-fallback arm. The two arms agree on every other outcome a
/// single persistent source can produce, which is why this asserts the one
/// place they differ: the all-rows-rejected fallback names the engine.
#[test]
fn a_direct_path_chromium_read_is_dispositioned_as_chromium() {
  let mut source = source_from_candidate(SourceCandidate {
    path: PathBuf::from("/chrome/Default/Cookies"),
    role: CookieSourceRoleId::persistent(),
    format: CookieSourceFormatId::known("chromium_sqlite"),
    precedence: registry::PERSISTENT_SOURCE_PRECEDENCE,
    exists: true,
    selected: true,
    acquisition: registry::SourceAcquisition::NotAttempted,
    policy: registry::AcquisitionPolicy::Fixed,
  });
  source.stats.rows_seen = 2;
  source.stats.rows_skipped = 2;
  source.push_row_read_failed(None);

  let outcome = finalize_singleton_source(
    "chromium",
    PathBuf::from("/chrome/Default"),
    vec![source],
    None,
    None,
  )
  .expect("finalize the direct-path source");
  let error = crate::browser::legacy::project_canonical_outcome("chromium", outcome)
    .expect_err("every row was rejected, so the compatibility projection fails");
  assert!(
    format!("{error:#}").contains("all Chromium cookie rows failed to decode"),
    "expected the Chromium fallback, got: {error:#}"
  );
}

/// Pins the narrowing from `.ends_with` to equality.
///
/// The family fallback exists to replace the *generic* row-read message,
/// which has exactly one producer: `push_row_read_failed(None)`. A custom
/// diagnostic that merely happens to end in the same English suffix is an
/// engine telling the caller something specific, and swallowing it loses
/// that. Under the previous `.ends_with` test this message was replaced by
/// the Chromium fallback; without this test, reverting to `.ends_with`
/// leaves the whole suite green.
#[test]
fn a_custom_diagnostic_ending_in_the_generic_suffix_survives_verbatim() {
  let mut source = source_from_candidate(SourceCandidate {
    path: PathBuf::from("/chrome/Default/Cookies"),
    role: CookieSourceRoleId::persistent(),
    format: CookieSourceFormatId::known("chromium_sqlite"),
    precedence: registry::PERSISTENT_SOURCE_PRECEDENCE,
    exists: true,
    selected: true,
    acquisition: registry::SourceAcquisition::NotAttempted,
    policy: registry::AcquisitionPolicy::Fixed,
  });
  source.stats.rows_seen = 2;
  source.stats.rows_skipped = 2;
  // Ends with the generic suffix but is not equal to it: the generator for
  // this source would produce exactly "2 row(s) could not be read".
  source.push_row_read_failed(Some(
    "v20 tier unavailable, 2 row(s) could not be read".to_owned(),
  ));

  let outcome = finalize_singleton_source(
    "chromium",
    PathBuf::from("/chrome/Default"),
    vec![source],
    None,
    None,
  )
  .expect("finalize the direct-path source");
  let error = crate::browser::legacy::project_canonical_outcome("chromium", outcome)
    .expect_err("every row was rejected, so the compatibility projection fails");
  let rendered = format!("{error:#}");
  assert!(
    rendered.contains("v20 tier unavailable"),
    "the engine's own diagnostic must survive, got: {rendered}"
  );
  assert!(
    !rendered.contains("all Chromium cookie rows failed to decode"),
    "the family fallback must not replace a custom diagnostic, got: {rendered}"
  );
}

fn engine_source(
  name: &str,
  role: &'static str,
  precedence: u16,
  selected: bool,
  error: Option<&str>,
) -> Source {
  let mut source = Source {
    origin: SourceIdentity {
      path: PathBuf::from("/firefox/Profiles/default").join(name),
      role: CookieSourceRoleId::known(role),
      format: CookieSourceFormatId::known("mozilla_sqlite"),
      precedence,
    },
    selected,
    acquisition: registry::SourceAcquisition::StableFileImage,
    records: Vec::new(),
    stats: SourceStats::default(),
    acquisition_attempts: 1,
    diagnostics: Vec::new(),
    failure: None,
    issues: Vec::new(),
  };
  if let Some(error) = error {
    source.fail(SourceFailureStageNew::Acquisition, error);
  }
  source
}

/// Builds an [`ExtractedProfile`] fixture from repeated-char ids.
fn extracted_profile(
  profile_id_char: &str,
  installation_id_char: &str,
  name: &str,
  installation_path: &str,
  path: &str,
  sources: Vec<Source>,
) -> ExtractedProfile {
  ExtractedProfile {
    identity: registry::EngineProfileIdentity {
      profile_id: profile_id_char
        .repeat(64)
        .parse()
        .expect("valid profile id"),
      installation_id: installation_id_char
        .repeat(64)
        .parse()
        .expect("valid installation id"),
      installation_priority: 0,
      installation_path: PathBuf::from(installation_path),
      name: name.to_owned(),
      path: PathBuf::from(path),
      is_default: true,
      persistent_source_discovered: true,
    },
    legacy: registry::LegacyRank {
      installation_priority: 0,
      profile_order: 0,
      is_default: true,
      eligible: true,
      installation_path: PathBuf::from(installation_path),
      name: name.to_owned(),
    },
    sources,
  }
}

/// Two browsers failing the same way are two failures. Merging on code alone
/// kept the first browser's id and message and silently dropped the second's.
#[test]
fn distinct_browsers_failing_alike_stay_distinct_in_the_report() {
  let browsers = ["chrome", "firefox"];
  let outcomes = browsers
    .iter()
    .map(|id| {
      let browser = BrowserId::known(id);
      let mut browser_outcome = outcome(Vec::new(), true);
      browser_outcome.detected = false;
      browser_outcome.issues.push(
        issue(
          "browser_discovery_failed",
          ExtractionStageCode::discovery(),
          IssueSeverityCode::error(),
          format!("{id} could not be read"),
        )
        .with_context(Some(&browser), None, None),
      );
      browser_outcome
    })
    .collect::<Vec<_>>();

  let report = assemble(2, outcomes);
  let failures = report
    .issues
    .iter()
    .filter(|issue| issue.code.as_str() == "browser_discovery_failed")
    .collect::<Vec<_>>();
  assert_eq!(failures.len(), 2);
  for (issue, id) in failures.iter().zip(browsers) {
    assert_eq!(issue.browser_id.as_ref().map(BrowserId::as_str), Some(id));
    assert_eq!(issue.message, format!("{id} could not be read"));
    assert_eq!(issue.occurrences, 1);
  }
  assert_eq!(report.status, ReportStatusCode::failed());
}

#[test]
fn same_browser_repeating_an_issue_still_aggregates() {
  let browser = BrowserId::known("chrome");
  let mut browser_outcome = outcome(Vec::new(), false);
  for index in 0..3 {
    browser_outcome.issues.push(
      issue(
        "duplicate_profile",
        ExtractionStageCode::discovery(),
        IssueSeverityCode::info(),
        "already owned",
      )
      .with_samples(vec![format!("/chrome/Profile {index}")])
      .with_context(Some(&browser), None, None),
    );
  }
  let report = assemble(1, vec![browser_outcome]);
  let issue = report
    .issues
    .iter()
    .find(|issue| issue.code.as_str() == "duplicate_profile")
    .expect("aggregated issue");
  assert_eq!(issue.occurrences, 3);
  assert_eq!(issue.samples.len(), 3);
}

#[test]
fn an_unknown_browser_id_is_a_request_error_not_a_report() {
  assert!(browser_extraction_report(
    "definitely_not_a_browser",
    ProfileSelection::AllProfiles,
    None
  )
  .is_err());
  assert!(
    browser_profile_descriptors("definitely_not_a_browser", &ExecutionControl::default()).is_err()
  );
  // An alias-shaped but unregistered id must fail the same way.
  assert!(browser_extraction_report("", ProfileSelection::AllProfiles, None).is_err());
}

#[test]
fn summary_counters_record_saturation_instead_of_reading_as_exact() {
  let report = assemble(usize::MAX, Vec::new());
  assert_eq!(report.summary.registered_browsers, u32::MAX);
  assert!(report.summary.counters_saturated);
}

#[test]
fn rejecting_an_invalid_record_marks_already_maxed_row_counters_saturated() {
  use crate::{
    browser::cookie_record::{CookieValue, SourceRef, UnavailableCode, UnavailableReason},
    common::enums::Cookie,
  };

  let mut draft = source(false);
  draft.stats.rows_seen = 1;
  draft.stats.cookies_emitted = 1;
  draft.stats.rows_skipped = u32::MAX;
  draft.stats.rows_rejected = u32::MAX;
  let mut record = CookieRecord::from_cookie(
    Cookie {
      domain: ".example.test".to_owned(),
      path: "/".to_owned(),
      secure: false,
      expires: None,
      name: "invalid".to_owned(),
      value: "sentinel".to_owned(),
      http_only: false,
      same_site: 0,
    },
    SourceRef::pending(0),
  );
  record.value = CookieValue::Unavailable(UnavailableReason {
    code: UnavailableCode::Decode,
    message: "rejected".to_owned(),
  });
  draft.records.push(record);
  let mut profile = ProfileDraft::new(identity(), true);
  profile.sources.push(draft);

  let report = assemble(1, vec![outcome(vec![profile], false)]);
  assert_eq!(report.summary.rows_skipped, u32::MAX);
  assert_eq!(report.summary.rows_rejected, u32::MAX);
  assert!(report.summary.counters_saturated);
}

#[test]
fn finalization_preserves_every_rejected_value_cause_code() {
  use crate::browser::cookie_record::{
    CipherTier, CookieValue, SourceRef, UnavailableCode, UnavailableReason,
  };
  use crate::common::enums::Cookie;

  for (value, expected_cause) in [
    (
      CookieValue::Encrypted {
        tier: CipherTier::V10,
        bytes: vec![1, 2, 3],
      },
      "encrypted",
    ),
    (
      CookieValue::Unavailable(UnavailableReason {
        code: UnavailableCode::Decrypt,
        message: "rejected".to_owned(),
      }),
      "decrypt",
    ),
    (
      CookieValue::Unavailable(UnavailableReason {
        code: UnavailableCode::Decode,
        message: "rejected".to_owned(),
      }),
      "decode",
    ),
    (
      CookieValue::Unavailable(UnavailableReason {
        code: UnavailableCode::ProviderUnavailable,
        message: "rejected".to_owned(),
      }),
      "provider_unavailable",
    ),
    (
      CookieValue::Unavailable(UnavailableReason {
        code: UnavailableCode::ProviderFailed,
        message: "rejected".to_owned(),
      }),
      "provider_failed",
    ),
  ] {
    let mut draft = source(false);
    draft.stats.rows_seen = 1;
    draft.stats.cookies_emitted = 1;
    let mut record = CookieRecord::from_cookie(
      Cookie {
        domain: ".example.test".to_owned(),
        path: "/".to_owned(),
        secure: false,
        expires: None,
        name: "invalid".to_owned(),
        value: "sentinel".to_owned(),
        http_only: false,
        same_site: 0,
      },
      SourceRef::pending(0),
    );
    record.value = value;
    draft.records.push(record);
    let mut profile = ProfileDraft::new(identity(), true);
    profile.sources.push(draft);

    let report = assemble(1, vec![outcome(vec![profile], false)]);
    let issue = &report.profiles[0].sources[0].issues[0];
    assert_eq!(issue.code.as_str(), "invalid_final_record");
    assert_eq!(issue.cause, expected_cause);
    assert!(issue.message.starts_with(expected_cause));
  }
}

#[test]
fn a_profile_without_sources_is_no_sources_rather_than_failed() {
  let profile = ProfileDraft::new(identity(), true);
  assert_eq!(
    status(outcome(vec![profile], false)),
    ReportStatusCode::no_sources()
  );
}

#[test]
fn a_root_that_could_not_be_enumerated_is_failed_not_no_sources() {
  // Identical profile shape to the case above; only the discovery signal
  // separates "nothing to read" from "could not look".
  let profile = ProfileDraft::new(identity(), true);
  assert_eq!(
    status(outcome(vec![profile], true)),
    ReportStatusCode::failed()
  );
  assert_eq!(
    status(outcome(Vec::new(), true)),
    ReportStatusCode::failed()
  );
}

#[test]
fn a_profile_error_with_no_sources_is_failed_not_no_sources() {
  // Same zero-source shape as the `no_sources` case, but the profile lost
  // something. Section 5.7 reserves `no_sources` for discovery that completed
  // without an error-severity failure.
  let mut profile = ProfileDraft::new(identity(), true);
  profile.issues.push(issue(
    "profile_extraction_failed",
    ExtractionStageCode::acquisition(),
    IssueSeverityCode::error(),
    "the profile database could not be read",
  ));
  assert_eq!(
    status(outcome(vec![profile], false)),
    ReportStatusCode::failed()
  );
}

#[test]
fn an_info_issue_with_no_sources_stays_no_sources() {
  let mut profile = ProfileDraft::new(identity(), true);
  profile.issues.push(issue(
    "profile_has_no_cookie_source",
    ExtractionStageCode::discovery(),
    IssueSeverityCode::info(),
    "profile has no selected persistent source",
  ));
  assert_eq!(
    status(outcome(vec![profile], false)),
    ReportStatusCode::no_sources()
  );
}

#[test]
fn an_attempted_source_that_failed_is_failed() {
  let mut profile = ProfileDraft::new(identity(), true);
  profile.sources.push(source(true));
  assert_eq!(
    status(outcome(vec![profile], false)),
    ReportStatusCode::failed()
  );
}

#[test]
fn a_zero_row_source_still_succeeds_and_completes() {
  let mut profile = ProfileDraft::new(identity(), true);
  profile.sources.push(source(false));
  let report = assemble(1, vec![outcome(vec![profile], false)]);
  assert_eq!(report.status, ReportStatusCode::complete());
  assert_eq!(report.summary.sources_succeeded, 1);
  assert_eq!(report.summary.cookies_emitted, 0);
}

#[test]
fn an_error_issue_beside_a_succeeding_source_is_partial() {
  let mut profile = ProfileDraft::new(identity(), true);
  profile.sources.push(source(false));
  let mut browser = outcome(vec![profile], false);
  browser.issues.push(issue(
    "installation_enumeration_failed",
    ExtractionStageCode::discovery(),
    IssueSeverityCode::error(),
    "a sibling root failed",
  ));
  assert_eq!(status(browser), ReportStatusCode::partial());
}

#[test]
fn a_recovered_discovery_problem_does_not_downgrade_a_complete_report() {
  let mut profile = ProfileDraft::new(identity(), true);
  profile.sources.push(source(false));
  let mut browser = outcome(vec![profile], false);
  // Both codes fall back to another discovery strategy, so the report lost
  // nothing and must not be reported as partial.
  for code in [
    "mozilla_profiles_ini_invalid",
    "optional_profiles_enumeration_failed",
  ] {
    browser.issues.push(discovery_issue(
      &BrowserId::known("firefox"),
      &registry::DiscoveryIssue {
        code,
        path: PathBuf::from("/profiles/profiles.ini"),
        message: "unreadable".to_owned(),
        occurrences: 1,
      },
    ));
  }
  assert_eq!(status(browser), ReportStatusCode::complete());
}

#[test]
fn bounded_discovery_occurrences_survive_as_a_typed_count_with_sampled_paths() {
  let mut browser = outcome(Vec::new(), false);
  for (index, occurrences) in [(0, 4u32), (1, 1)] {
    browser.issues.push(discovery_issue(
      &BrowserId::known("firefox"),
      &registry::DiscoveryIssue {
        code: "duplicate_profile",
        path: PathBuf::from(format!("/profiles/{index}")),
        message: "already owned".to_owned(),
        occurrences,
      },
    ));
  }
  let report = assemble(1, vec![browser]);
  let issue = report
    .issues
    .iter()
    .find(|issue| issue.code.as_str() == "duplicate_profile")
    .expect("aggregated duplicate issue");
  assert_eq!(issue.occurrences, 5);
  assert_eq!(issue.samples, vec!["<path>", "<path>"]);
}

#[test]
fn public_discovery_diagnostics_sanitize_paths_embedded_in_messages() {
  let message = "failed /private/secret/profile/Cookies, also C:\\Users\\Secret\\Cookies";
  let issue = discovery_issue(
    &BrowserId::known("firefox"),
    &registry::DiscoveryIssue {
      code: "profile_enumeration_failed",
      path: PathBuf::from("/profiles/default"),
      message: message.to_owned(),
      occurrences: 1,
    },
  );
  assert!(!issue.message.contains("/private/secret"));
  assert!(!issue.message.contains(r"C:\Users\Secret"));
  assert!(
    issue
      .message
      .matches(crate::common::diagnostic::REDACTED_PATH)
      .count()
      >= 2
  );
}
/// Safari and Internet Explorer report skipped rows without keeping the
/// underlying error. Deriving the row issue from that error alone let a
/// report claim `complete` while cookies had been dropped.
#[test]
fn skipped_rows_without_a_row_error_still_degrade_the_report() {
  let mut profile = ProfileDraft::new(identity(), true);
  let mut source = engine_source("Cookies.binarycookies", "persistent", 10, true, None);
  source.stats.rows_seen = 3;
  source.stats.rows_skipped = 2;
  // The adapter attaches the row issue from the skip count alone; no row
  // error string is available. `source_to_draft` only copies it.
  source.push_row_read_failed(None);
  profile.sources.push(source_to_draft(source));

  let report = assemble(1, vec![outcome(vec![profile], false)]);
  let source = &report.profiles[0].sources[0];
  // The source itself still succeeded: acquisition and parsing completed.
  assert_eq!(source.status, SourceStatusCode::succeeded());
  let row_issue = source
    .issues
    .iter()
    .find(|issue| issue.code.as_str() == "row_read_failed")
    .expect("skipped rows must be reported");
  assert!(row_issue.is_error());
  assert_eq!(row_issue.occurrences, 2);
  assert_eq!(report.status, ReportStatusCode::partial());
}

fn assert_counter_identity(report: &ExtractionReport) {
  for profile in &report.profiles {
    for source in &profile.sources {
      assert!(source.stats.rows_seen >= source.stats.rows_skipped);
      assert_eq!(
        source.stats.rows_seen - source.stats.rows_skipped,
        source.stats.cookies_emitted,
        "source format {}",
        source.source.format
      );
      assert_eq!(
        source.stats.cookies_emitted as usize,
        source.cookies.len(),
        "source format {}",
        source.source.format
      );
    }
    assert!(profile.stats.rows_seen >= profile.stats.rows_skipped);
    assert_eq!(
      profile.stats.rows_seen - profile.stats.rows_skipped,
      profile.stats.cookies_emitted
    );
  }
  assert!(report.summary.rows_seen >= report.summary.rows_skipped);
  assert_eq!(
    report.summary.rows_seen - report.summary.rows_skipped,
    report.summary.cookies_emitted
  );
}

#[test]
fn report_row_counters_reconcile_across_every_backend_adapter() {
  let cookie = |name: &str| crate::common::enums::Cookie {
    domain: ".example.com".to_owned(),
    path: "/".to_owned(),
    secure: true,
    expires: None,
    name: name.to_owned(),
    value: String::new(),
    http_only: true,
    same_site: crate::common::enums::SAME_SITE_UNSPECIFIED,
  };

  // Chromium is built the same way as the other three now: one `Source` the
  // engine already translated. The adapter has no engine-specific counters
  // left to reconcile, only the shared ones.
  let mut chromium_source = {
    let c = chromium_candidate();
    Source::new(c.identity(), c.selected, c.acquisition)
  };
  chromium_source.records = vec![fixture_record(cookie("chromium"), 0)];
  chromium_source.stats = SourceStats {
    rows_seen: 4,
    cookies_emitted: 1,
    rows_skipped: 3,
    rows_rejected: 1,
    provider_failures: 2,
  };
  let mut provider_failed = SourceIssue::new(
    "provider_failed",
    ExtractionStageCode::decrypt(),
    IssueSeverityCode::error(),
    "keyring unavailable",
  )
  .with_occurrences(2);
  provider_failed.samples = vec!["row 3".to_owned(), "row 4".to_owned()];
  provider_failed.provider = Some("platform_key_provider".to_owned());
  provider_failed.tier = Some("v11".to_owned());
  provider_failed.cause = Some("credential_provider".to_owned());
  provider_failed.retryability = Some("retryable".to_owned());
  let mut decode_failed = SourceIssue::new(
    "decode_failed",
    ExtractionStageCode::decode(),
    IssueSeverityCode::error(),
    "1 row(s) rejected as decode_failed",
  );
  decode_failed.samples = vec!["row 2".to_owned()];
  chromium_source.issues = vec![decode_failed, provider_failed];
  let chromium = chromium_profile_outcome(
    &BrowserId::known("chrome"),
    &"d".repeat(64),
    chromium_profile(vec![chromium_source]),
  )
  .expect("adapt Chromium counters");

  let mut profiles = vec![chromium];
  for (format, name) in [
    ("mozilla_sqlite", "mozilla"),
    ("safari_binarycookies", "safari"),
    ("internet_explorer_ese", "internet-explorer"),
  ] {
    let mut source = engine_source(name, SOURCE_ROLE_PERSISTENT, 10, true, None);
    source.origin.format = CookieSourceFormatId::known(format);
    source.records = vec![fixture_record(cookie(name), 0)];
    source.stats.rows_seen = 3;
    source.stats.rows_skipped = 2;
    source.stats.cookies_emitted = source.records.len();
    source.push_row_read_failed(Some(format!("{name} rejected two records")));
    let mut profile = ProfileDraft::new(identity(), true);
    profile.sources.push(source_to_draft(source));
    profiles.push(profile);
  }

  let report = assemble(4, vec![outcome(profiles, false)]);
  let chromium_source = &report.profiles[0].sources[0];
  assert_eq!(chromium_source.stats.rows_rejected, 1);
  assert_eq!(chromium_source.stats.provider_failures, 2);
  assert_eq!(report.profiles[0].stats.rows_rejected, 1);
  assert_eq!(report.profiles[0].stats.provider_failures, 2);
  assert_eq!(report.summary.rows_seen, 13);
  assert_eq!(report.summary.rows_skipped, 9);
  assert_eq!(report.summary.cookies_emitted, 4);
  assert_eq!(report.summary.rows_rejected, 1);
  assert_eq!(report.summary.provider_failures, 2);
  assert_counter_identity(&report);
}

#[test]
fn a_source_that_skipped_nothing_reports_no_row_issue() {
  let mut profile = ProfileDraft::new(identity(), true);
  profile.sources.push(source_to_draft(engine_source(
    "cookies.sqlite",
    "persistent",
    10,
    true,
    None,
  )));
  let report = assemble(1, vec![outcome(vec![profile], false)]);
  assert!(report.profiles[0].sources[0].issues.is_empty());
  assert_eq!(report.status, ReportStatusCode::complete());
}

/// The frozen `stage` field must name where the failure happened. Flattening
/// parse and query failures into `acquisition` misdescribes them and denies
/// consumers the signal they need to choose a remedy.
#[test]
fn a_source_failure_reports_the_stage_it_actually_failed_at() {
  for (stage, expected) in [
    (SourceFailureStageNew::Acquisition, "acquisition"),
    (SourceFailureStageNew::Parse, "parse"),
    (SourceFailureStageNew::Query, "query"),
  ] {
    let mut source = engine_source("cookies.sqlite", "persistent", 10, true, None);
    source.fail(stage, "boom");
    let outcome = source_to_draft(source);
    let issue = outcome
      .issues
      .iter()
      .find(|issue| issue.code.as_str() == "source_extraction_failed")
      .expect("a failure issue");
    assert_eq!(issue.stage.as_str(), expected);
  }
}

/// Engine-authored issues that share a code merge on the way into the report,
/// keeping every sample. The engine emits one `SourceIssue` per aggregated
/// row issue, so this is where name-column and value-column failures become
/// the single `column_read_failed` a consumer sees.
#[test]
fn same_code_source_issues_merge_and_keep_every_sample() {
  let mut source = source_with_issues(vec![
    column_read_issue("name column, row 1"),
    column_read_issue("value column, row 7"),
  ]);
  source.stats.rows_skipped = 2;
  let outcome = source_to_draft(source);
  assert_eq!(outcome.issues.len(), 1);
  assert_eq!(outcome.issues[0].occurrences, 2);
  assert_eq!(
    outcome.issues[0].samples,
    vec!["name column, row 1", "value column, row 7"]
  );
}

/// The engine names the provider, tier, cause, and retryability; the mapper
/// only has to carry them. Losing any of them would leave a consumer unable
/// to tell a retryable key failure from a permanent one.
#[test]
fn provider_failure_metadata_reaches_the_canonical_report_issue() {
  let mut issue = SourceIssue::new(
    "provider_failed",
    ExtractionStageCode::decrypt(),
    IssueSeverityCode::error(),
    "malformed App-Bound Local State",
  );
  issue.provider = Some("platform_key_provider".to_owned());
  issue.tier = Some("v20".to_owned());
  issue.cause = Some("credential_provider".to_owned());
  issue.retryability = Some("not_retryable".to_owned());

  let outcome = source_to_draft(source_with_issues(vec![issue]));
  let reported = outcome.issues.first().expect("the provider issue");
  assert_eq!(reported.code.as_str(), "provider_failed");
  assert_eq!(reported.retryability, "not_retryable");
  assert_eq!(reported.tier.as_deref(), Some("v20"));
  assert_eq!(reported.cause, "credential_provider");
  assert_eq!(reported.message, "malformed App-Bound Local State");
}

/// `all_rows_rejected` is the one code that must not surface as an extraction
/// issue: Section 5.7 reports a fully-rejected source as succeeded, and only
/// the compatibility projection treats it as an error.
#[test]
fn the_all_rows_rejected_issue_becomes_evidence_rather_than_an_issue() {
  let outcome = source_to_draft(source_with_issues(vec![
    SourceIssue::all_rows_rejected("every row failed"),
    column_read_issue("name column, row 1"),
  ]));
  assert_eq!(
    outcome
      .issues
      .iter()
      .map(|issue| issue.code.as_str())
      .collect::<Vec<_>>(),
    ["column_read_failed"],
    "the evidence must not reach the report as an issue"
  );
  assert!(!outcome.failed, "a fully-rejected source still succeeded");
  assert!(matches!(
    outcome.compatibility_evidence,
    Some(CompatibilityEvidence::AllRowsRejected(message)) if message == "every row failed"
  ));
}

fn column_read_issue(sample: &str) -> SourceIssue {
  let mut issue = SourceIssue::new(
    "column_read_failed",
    ExtractionStageCode::parse(),
    IssueSeverityCode::error(),
    "failed to read the name column of 1 row(s)",
  );
  issue.samples = vec![sample.to_owned()];
  issue
}

fn source_with_issues(issues: Vec<SourceIssue>) -> Source {
  let mut source = source_from_candidate(SourceCandidate {
    path: PathBuf::from("/chrome/Default/Network/Cookies"),
    role: CookieSourceRoleId::persistent(),
    format: CookieSourceFormatId::known("chromium_sqlite"),
    precedence: registry::PERSISTENT_SOURCE_PRECEDENCE,
    exists: true,
    selected: true,
    acquisition: registry::SourceAcquisition::NotAttempted,
    policy: registry::AcquisitionPolicy::Fixed,
  });
  source.issues = issues;
  source
}
/// Profile and source issues carry no context from the engines, because the
/// enclosing profile is implied structurally. Consumers that flatten every
/// issue into one list -- the CLI and the bindings do -- lose that, so the
/// identity is stamped on before the report leaves the builder.
#[test]
fn profile_and_source_issues_carry_their_profile_context() {
  let mut profile = ProfileDraft::new(identity(), true);
  profile.issues.push(issue(
    "profile_extraction_failed",
    ExtractionStageCode::acquisition(),
    IssueSeverityCode::error(),
    "profile level",
  ));
  let mut source = engine_source("cookies.sqlite", "persistent", 10, true, None);
  source.fail(SourceFailureStageNew::Parse, "source level");
  profile.sources.push(source_to_draft(source));

  let report = assemble(1, vec![outcome(vec![profile], false)]);
  let expected = &report.profiles[0].profile;
  let (browser, installation, profile_id) = (
    expected.browser_id.clone(),
    expected.installation_id.clone(),
    expected.profile_id.clone(),
  );

  let mut checked = 0;
  for issue in report.profiles[0]
    .issues
    .iter()
    .chain(report.profiles[0].sources.iter().flat_map(|s| &s.issues))
  {
    assert_eq!(issue.browser_id.as_ref(), Some(&browser));
    assert_eq!(issue.installation_id.as_ref(), Some(&installation));
    assert_eq!(issue.profile_id.as_ref(), Some(&profile_id));
    checked += 1;
  }
  assert_eq!(checked, 2, "both the profile and source issue are stamped");

  // Top-level issues stay browser-scoped: they are raised before any
  // installation or profile identity exists.
  assert!(report
    .issues
    .iter()
    .all(|issue| issue.installation_id.is_none() && issue.profile_id.is_none()));
}
