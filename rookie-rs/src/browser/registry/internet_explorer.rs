use super::super::report_core::{CookieSourceFormatId, CookieSourceRoleId};
#[cfg(test)]
use super::super::source::SourceStats;
use super::super::source::{Source, SourceCandidate, SourceFailureStage};
use super::{
  acquire_each_candidate, canonical_installation_root, embedded_registry, engine_roots,
  installation_id, installation_root_is_directory, normalized_path_bytes, populate_engine_sources,
  profile_id, retain_engine_runtime_stop, select_listing_profiles, sort_discovered_profiles,
  AcquisitionPolicy, BrowserEngine, DiscoveredProfile, DiscoveryContext, DiscoveryFs,
  DiscoveryIssue, DiscoveryStrategy, EngineExtract, EngineListing, EngineProfileIdentity,
  ExtractCompletion, LegacyRank, ProfileLocator, ProfileSelection, SourceAcquisition,
  PERSISTENT_SOURCE_PRECEDENCE,
};
#[cfg(test)]
use super::{DiscoveryCounters, ExtractedProfile};
use crate::browser::internet_explorer_model::{
  InternetExplorerFailure, InternetExplorerFailureStage,
};
use anyhow::Result;
use std::{
  collections::HashSet,
  path::{Path, PathBuf},
};

pub(super) const INTERNET_EXPLORER_COOKIE_FILE: &str = "WebCacheV01.dat";

/// The [`Source`] the real WebCache engine would return for `origin`, built
/// from scripted rows. Test-only because the ESE reader that produces the real
/// thing only compiles on Windows, yet the adapter tests that inject a query
/// run everywhere.
#[cfg(test)]
pub(crate) fn extracted_internet_explorer_source(
  origin: SourceCandidate,
  records: Vec<crate::browser::cookie_record::CookieRecord>,
  records_seen: usize,
  records_skipped: usize,
  records_rejected: usize,
  row_error: Option<String>,
) -> Source {
  let mut source = Source::new(origin.identity(), origin.selected, origin.acquisition);
  // The engine overlays the effective acquisition once the query is attempted.
  source.acquisition = SourceAcquisition::EseDatabase;
  source.acquisition_attempts = 1;
  source.stats = SourceStats {
    rows_seen: records_seen,
    cookies_emitted: records.len(),
    rows_skipped: records_skipped,
    rows_rejected: records_rejected,
    provider_failures: 0,
  };
  source.records = records;
  // After the stats, never before: the issue is keyed on `rows_skipped`.
  source.push_row_read_failed(row_error);
  source
}

/// Crate-private generic Internet Explorer seam. The WebCache root is flat, so
/// each detected root contributes exactly one default profile.
pub(super) fn discover_internet_explorer_with_context<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
) -> Result<EngineListing> {
  let registry = embedded_registry()?;
  let (definition, roots) = engine_roots(
    registry,
    context.platform,
    browser_id,
    BrowserEngine::InternetExplorer,
  )?;
  let mut seen_installations = HashSet::new();
  let mut seen_profiles = HashSet::new();
  let mut outcome = EngineListing::default();

  for root in roots {
    if root.discovery != DiscoveryStrategy::InternetExplorerWebCache {
      continue;
    }
    let Some(resolved_root) = context.resolve_template(&root.template) else {
      continue;
    };
    // Non-Chromium registry templates never glob, so the suffix is literal.
    let root_path = resolved_root.base.join(resolved_root.suffix);
    if !installation_root_is_directory(context, &root_path, &mut outcome) {
      continue;
    }
    let Some(canonical_root) =
      canonical_installation_root(context, root_path, &mut seen_installations, &mut outcome)
    else {
      continue;
    };
    // A WebCache root is its own profile, so there is no enumeration step that
    // could fail once the root canonicalized.
    outcome.counters.installations_enumerated += 1;
    let source_path = canonical_root.join(INTERNET_EXPLORER_COOKIE_FILE);
    if !context.fs.exists(&source_path) {
      outcome.discovery_issues.push(DiscoveryIssue::new(
        "profile_has_no_cookie_source",
        canonical_root,
        "WebCache root has no cookie database".to_owned(),
      ));
      continue;
    }
    if !seen_profiles.insert(normalized_path_bytes(&canonical_root)) {
      outcome.discovery_issues.push(DiscoveryIssue::new(
        "duplicate_profile",
        canonical_root,
        "profile is already owned by an earlier registry root".to_owned(),
      ));
      continue;
    }
    let installation_id_value = installation_id(
      &definition.canonical_id,
      &root.root_id,
      &root.channel,
      &normalized_path_bytes(&canonical_root),
    );
    let candidate = internet_explorer_source_candidate(source_path);
    outcome.profiles.push(DiscoveredProfile {
      identity: EngineProfileIdentity {
        profile_id: profile_id(
          installation_id_value.as_str(),
          ProfileLocator::Relative(Path::new("")),
        ),
        installation_id: installation_id_value,
        installation_priority: root.priority,
        installation_path: canonical_root.clone(),
        name: "default".to_owned(),
        path: canonical_root.clone(),
        is_default: true,
        persistent_source_discovered: true,
      },
      legacy: LegacyRank {
        installation_priority: root.priority,
        profile_order: 0,
        is_default: true,
        eligible: true,
        installation_path: canonical_root,
        name: "default".to_owned(),
      },
      candidates: vec![candidate],
    });
  }
  sort_discovered_profiles(&mut outcome.profiles);
  Ok(outcome)
}

/// The frozen Internet Explorer listing candidate: `selected: true`,
/// `NotAttempted` (the `EseDatabase` overlay only appears after a query),
/// `exists: true`.
fn internet_explorer_source_candidate(path: PathBuf) -> SourceCandidate {
  SourceCandidate {
    path,
    role: CookieSourceRoleId::persistent(),
    format: CookieSourceFormatId::known("internet_explorer_ese"),
    precedence: PERSISTENT_SOURCE_PRECEDENCE,
    exists: true,
    selected: true,
    acquisition: SourceAcquisition::NotAttempted,
    policy: AcquisitionPolicy::Fixed,
  }
}

fn discover_internet_explorer_with_runtime<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<EngineListing> {
  runtime.check()?;
  let outcome = discover_internet_explorer_with_context(context, browser_id)?;
  runtime.check()?;
  Ok(outcome)
}

pub(super) fn internet_explorer_report_with_context<F, Q>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
  selection: ProfileSelection<'_>,
  domains: Option<&[String]>,
  query: Q,
) -> Result<EngineExtract>
where
  F: DiscoveryFs,
  Q: FnMut(SourceCandidate, Option<&[String]>) -> Result<Source>,
{
  internet_explorer_report_with_context_using_runtime(
    context, browser_id, selection, domains, None, query,
  )
}

/// The Internet Explorer report with the deadline threaded to the populate
/// walk. The production Windows callers pass a runtime; the injected-query test
/// seam passes `None` and gets the same walk with the deadline samples elided.
fn internet_explorer_report_with_context_using_runtime<F, Q>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
  selection: ProfileSelection<'_>,
  domains: Option<&[String]>,
  runtime: Option<&crate::common::deadline::BoundaryRuntime<'_>>,
  query: Q,
) -> Result<EngineExtract>
where
  F: DiscoveryFs,
  Q: FnMut(SourceCandidate, Option<&[String]>) -> Result<Source>,
{
  let mut listing = discover_internet_explorer_with_context(context, browser_id)?;
  select_listing_profiles(&mut listing, browser_id, selection)?;
  Ok(populate_internet_explorer_sources_impl(
    listing, domains, runtime, query,
  ))
}

pub(super) fn populate_internet_explorer_sources<Q>(
  listing: EngineListing,
  domains: Option<&[String]>,
  query: Q,
) -> EngineExtract
where
  Q: FnMut(SourceCandidate, Option<&[String]>) -> Result<Source>,
{
  populate_internet_explorer_sources_impl(listing, domains, None, query)
}

fn populate_internet_explorer_sources_with_runtime<Q>(
  listing: EngineListing,
  domains: Option<&[String]>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
  query: Q,
) -> EngineExtract
where
  Q: FnMut(SourceCandidate, Option<&[String]>) -> Result<Source>,
{
  populate_internet_explorer_sources_impl(listing, domains, Some(runtime), query)
}

/// Candidate-driven populate. Each candidate is acquired in turn. A successful
/// query returns the engine-built [`Source`], which already carries the
/// effective `EseDatabase` acquisition; a failed query overlays it here after
/// the attempt, matching the frozen listing-to-extract behaviour.
///
/// The envelope is [`populate_engine_sources`] and the per-candidate walk is
/// [`acquire_each_candidate`], shared with Safari; all that is left here is how
/// Internet Explorer writes a failed query onto the placeholder. Sharing the
/// walk is also how this engine acquired Safari's deadline samples: it
/// previously relied entirely on a stop surfacing through the query's error
/// chain, which is still the path a stop mid-read takes.
fn populate_internet_explorer_sources_impl<Q>(
  listing: EngineListing,
  domains: Option<&[String]>,
  runtime: Option<&crate::common::deadline::BoundaryRuntime<'_>>,
  mut query: Q,
) -> EngineExtract
where
  Q: FnMut(SourceCandidate, Option<&[String]>) -> Result<Source>,
{
  populate_engine_sources(
    listing,
    ExtractCompletion::RetainAttempted,
    |_identity, candidates| {
      acquire_each_candidate(candidates, domains, runtime, &mut query, |source, error| {
        source.acquisition = SourceAcquisition::EseDatabase;
        source.acquisition_attempts = 1;
        source.fail(
          internet_explorer_failure_stage(&error),
          format!("{error:#}"),
        );
      })
    },
  )
}

fn internet_explorer_failure_stage(error: &anyhow::Error) -> SourceFailureStage {
  match error
    .downcast_ref::<InternetExplorerFailure>()
    .map(InternetExplorerFailure::stage)
  {
    Some(InternetExplorerFailureStage::Acquisition) => SourceFailureStage::Acquisition,
    Some(InternetExplorerFailureStage::Parse) | None => SourceFailureStage::Parse,
  }
}

fn query_internet_explorer_non_disruptive<Q>(
  origin: SourceCandidate,
  domains: Option<&[String]>,
  query: Q,
) -> Result<Source>
where
  Q: FnOnce(SourceCandidate, Option<Vec<String>>, bool) -> Result<Source>,
{
  query(origin, domains.map(<[String]>::to_vec), false)
}

#[cfg(target_os = "windows")]
pub(crate) fn internet_explorer_profiles_with_runtime(
  browser_id: &str,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<EngineListing> {
  runtime.check()?;
  let context = DiscoveryContext::system()?;
  discover_internet_explorer_with_runtime(&context, browser_id, runtime)
}

#[cfg(target_os = "windows")]
pub(crate) fn internet_explorer_report(
  browser_id: &str,
  selection: ProfileSelection<'_>,
  domains: Option<Vec<String>>,
) -> Result<EngineExtract> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  internet_explorer_report_with_runtime(browser_id, selection, domains, &runtime)
}

#[cfg(target_os = "windows")]
pub(crate) fn internet_explorer_report_with_runtime(
  browser_id: &str,
  selection: ProfileSelection<'_>,
  domains: Option<Vec<String>>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<EngineExtract> {
  runtime.check()?;
  let context = DiscoveryContext::system()?;
  runtime.check()?;
  let outcome = internet_explorer_report_with_context_using_runtime(
    &context,
    browser_id,
    selection,
    domains.as_deref(),
    Some(runtime),
    |origin, domains| {
      query_internet_explorer_non_disruptive(origin, domains, |origin, domains, force_kill| {
        crate::browser::internet_explorer::internet_explorer_outcome_with_runtime(
          origin, domains, force_kill, runtime,
        )
      })
    },
  )?;
  Ok(retain_engine_runtime_stop(outcome, runtime))
}

#[cfg(target_os = "windows")]
pub(crate) fn legacy_internet_explorer_outcome(
  browser_id: &str,
  domains: Option<Vec<String>>,
) -> Result<EngineExtract> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  legacy_internet_explorer_outcome_with_runtime(browser_id, domains, &runtime)
}

#[cfg(target_os = "windows")]
pub(crate) fn legacy_internet_explorer_outcome_with_runtime(
  browser_id: &str,
  domains: Option<Vec<String>>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<EngineExtract> {
  runtime.check()?;
  let context = DiscoveryContext::system()?;
  runtime.check()?;
  let mut listing = discover_internet_explorer_with_runtime(&context, browser_id, runtime)?;
  select_listing_profiles(
    &mut listing,
    browser_id,
    ProfileSelection::LegacyFirstProfile,
  )?;
  let outcome = populate_internet_explorer_sources_with_runtime(
    listing,
    domains.as_deref(),
    runtime,
    |origin, domains| {
      query_internet_explorer_non_disruptive(origin, domains, |origin, domains, force_kill| {
        crate::browser::internet_explorer::internet_explorer_outcome_with_runtime(
          origin, domains, force_kill, runtime,
        )
      })
    },
  );
  Ok(retain_engine_runtime_stop(outcome, runtime))
}

#[cfg(test)]
mod tests {
  use super::super::test_seams::{
    self, browser_root, context_for, with_test_fs, TempDir, TestDiscoveryFs,
  };
  use super::super::PlatformId;
  use super::*;
  use anyhow::bail;
  use std::cell::Cell;
  use std::collections::BTreeMap;

  fn discovered_source_draft(path: PathBuf) -> SourceCandidate {
    internet_explorer_source_candidate(path)
  }

  fn discovered_sources() -> EngineListing {
    let installation_path = PathBuf::from(r"C:\Users\rookie\WebCache");
    EngineListing {
      counters: DiscoveryCounters {
        installations_detected: 1,
        installations_discovered: 1,
        installations_enumerated: 1,
      },
      boundary_stop: None,
      profiles: vec![DiscoveredProfile {
        identity: EngineProfileIdentity {
          profile_id: "1".repeat(64).parse().expect("valid profile id"),
          installation_id: "0".repeat(64).parse().expect("valid installation id"),
          installation_priority: 10,
          installation_path: installation_path.clone(),
          name: "default".to_owned(),
          path: installation_path.clone(),
          is_default: true,
          persistent_source_discovered: true,
        },
        legacy: LegacyRank {
          installation_priority: 10,
          profile_order: 0,
          is_default: true,
          eligible: true,
          installation_path: installation_path.clone(),
          name: "default".to_owned(),
        },
        // Discovery output: both candidates exist, neither has been queried.
        candidates: vec![
          discovered_source_draft(installation_path.join(INTERNET_EXPLORER_COOKIE_FILE)),
          discovered_source_draft(
            installation_path
              .join("secondary")
              .join(INTERNET_EXPLORER_COOKIE_FILE),
          ),
        ],
      }],
      discovery_issues: Vec::new(),
    }
  }

  #[test]
  fn non_disruptive_query_bridge_forwards_owned_inputs_and_false() {
    let path = PathBuf::from(r"C:\Users\rookie\WebCacheV01.dat");
    let domains = vec!["example.com".to_owned(), "mozilla.org".to_owned()];

    let source = query_internet_explorer_non_disruptive(
      internet_explorer_source_candidate(path.clone()),
      Some(&domains),
      |forwarded, forwarded_domains, force_kill| {
        assert_eq!(forwarded.path, path);
        assert_eq!(forwarded_domains.as_deref(), Some(domains.as_slice()));
        assert!(!force_kill);
        Ok(extracted_internet_explorer_source(
          forwarded,
          Vec::new(),
          0,
          0,
          0,
          None,
        ))
      },
    )
    .expect("non-disruptive query bridge");

    assert!(source.records.is_empty());
  }

  #[test]
  fn typed_native_failures_preserve_acquisition_and_parse_stages() {
    for (native, expected) in [
      (
        InternetExplorerFailureStage::Acquisition,
        SourceFailureStage::Acquisition,
      ),
      (
        InternetExplorerFailureStage::Parse,
        SourceFailureStage::Parse,
      ),
    ] {
      let error = anyhow::Error::new(InternetExplorerFailure::new(
        native,
        anyhow::anyhow!("scripted native failure"),
      ));
      assert_eq!(internet_explorer_failure_stage(&error), expected);
    }

    assert_eq!(
      internet_explorer_failure_stage(&anyhow::anyhow!("legacy untyped failure")),
      SourceFailureStage::Parse
    );
  }

  #[test]
  fn source_population_retains_success_before_typed_stop() {
    use crate::common::deadline::BoundaryStop;

    for stop in [
      BoundaryStop::TimedOut,
      BoundaryStop::Cancelled,
      BoundaryStop::ResourceExhausted,
    ] {
      let calls = Cell::new(0);
      let populated =
        populate_internet_explorer_sources(discovered_sources(), None, |origin, _| {
          let call = calls.get();
          calls.set(call + 1);
          if call == 0 {
            Ok(extracted_internet_explorer_source(
              origin,
              Vec::new(),
              7,
              2,
              2,
              None,
            ))
          } else {
            Err(anyhow::Error::new(InternetExplorerFailure::new(
              InternetExplorerFailureStage::Parse,
              anyhow::Error::new(stop),
            )))
          }
        });

      assert_eq!(calls.get(), 2);
      assert_eq!(populated.boundary_stop, Some(stop));
      assert_eq!(populated.profiles[0].sources[0].stats.rows_seen, 7);
      assert_eq!(populated.profiles[0].sources[0].stats.rows_skipped, 2);
      assert_eq!(populated.profiles[0].sources[0].stats.rows_rejected, 2);
      assert!(populated.profiles[0].sources[0].failure.is_none());
      assert_eq!(populated.profiles[0].sources.len(), 1);
    }
  }

  /// Sharing Safari's candidate walk gave this engine Safari's deadline
  /// samples: one before and one after every candidate. Before that it named
  /// the runtime nowhere and could only stop once a query surfaced one through
  /// its error chain -- which the production reader always does, since it
  /// checks the deadline on entry, so the stop boundary is unmoved. These two
  /// tests pin the samples themselves rather than that coupling.
  #[test]
  fn populate_stops_after_the_candidate_that_exhausted_the_deadline() {
    use crate::common::deadline::{
      test_clock::ManualClock, BoundaryStop, CancellationToken, Deadline,
    };
    use std::time::Duration;

    for stop in [
      BoundaryStop::TimedOut,
      BoundaryStop::Cancelled,
      BoundaryStop::ResourceExhausted,
    ] {
      let clock = ManualClock::default();
      let token = CancellationToken::default();
      let runtime = crate::common::deadline::BoundaryRuntime::with_stop(
        &clock,
        Deadline::after(&clock, Duration::from_secs(1)),
        token.clone(),
      );
      let calls = Cell::new(0);
      let populated = populate_internet_explorer_sources_with_runtime(
        discovered_sources(),
        None,
        &runtime,
        |origin, _| {
          calls.set(calls.get() + 1);
          let source = extracted_internet_explorer_source(origin, Vec::new(), 3, 0, 0, None);
          match stop {
            BoundaryStop::TimedOut => clock.advance(Duration::from_secs(1)),
            BoundaryStop::Cancelled => assert!(token.cancel()),
            BoundaryStop::ResourceExhausted => assert!(token.exhaust_resources()),
          }
          Ok(source)
        },
      );

      assert_eq!(calls.get(), 1, "the later candidate must never be queried");
      assert_eq!(populated.boundary_stop, Some(stop));
      assert_eq!(populated.profiles.len(), 1);
      assert_eq!(populated.profiles[0].sources.len(), 1);
      assert_eq!(populated.profiles[0].sources[0].stats.rows_seen, 3);
    }
  }

  #[test]
  fn populate_queries_nothing_when_the_deadline_is_already_spent() {
    use crate::common::deadline::{
      test_clock::ManualClock, BoundaryStop, CancellationToken, Deadline,
    };
    use std::time::Duration;

    let clock = ManualClock::default();
    let runtime = crate::common::deadline::BoundaryRuntime::with_stop(
      &clock,
      Deadline::after(&clock, Duration::from_secs(1)),
      CancellationToken::default(),
    );
    clock.advance(Duration::from_secs(1));
    let populated = populate_internet_explorer_sources_with_runtime(
      discovered_sources(),
      None,
      &runtime,
      |_origin, _| -> Result<Source> {
        unreachable!("no candidate may be queried once the deadline is spent")
      },
    );

    assert_eq!(populated.boundary_stop, Some(BoundaryStop::TimedOut));
    // The profile committed nothing, so `RetainAttempted` drops it rather than
    // leaving a zero-attempt placeholder that reads as a successful empty
    // source.
    assert!(populated.profiles.is_empty());
  }

  fn stopped_adapter_outcome(stop: crate::common::deadline::BoundaryStop) -> EngineExtract {
    let calls = Cell::new(0);
    let populated = populate_internet_explorer_sources(discovered_sources(), None, |origin, _| {
      let call = calls.get();
      calls.set(call + 1);
      if call == 0 {
        Ok(extracted_internet_explorer_source(
          origin,
          vec![crate::browser::cookie_record::CookieRecord::from_cookie(
            crate::common::enums::Cookie {
              domain: ".example.com".to_owned(),
              path: "/".to_owned(),
              secure: false,
              expires: None,
              name: "retained".to_owned(),
              value: "value".to_owned(),
              http_only: false,
              same_site: 0,
            },
            crate::browser::cookie_record::SourceRef::pending(0),
          )],
          1,
          0,
          0,
          None,
        ))
      } else {
        Err(anyhow::Error::new(InternetExplorerFailure::new(
          InternetExplorerFailureStage::Parse,
          anyhow::Error::new(stop),
        )))
      }
    });
    assert_eq!(calls.get(), 2);
    populated
  }

  #[test]
  fn adapter_report_retains_completed_work_while_legacy_returns_the_stop() {
    use crate::common::deadline::BoundaryStop;

    for (stop, expected_termination) in [
      (BoundaryStop::TimedOut, "timed_out"),
      (BoundaryStop::Cancelled, "cancelled"),
      (BoundaryStop::ResourceExhausted, "resource_exhausted"),
    ] {
      let populated = stopped_adapter_outcome(stop);
      assert_eq!(populated.boundary_stop, Some(stop));
      assert_eq!(populated.profiles.len(), 1);
      assert_eq!(populated.profiles[0].sources.len(), 1);

      let report = crate::browser::report_build::project_engine_extract(
        "internet_explorer",
        stopped_adapter_outcome(stop),
      )
      .expect("project stopped Internet Explorer report");
      assert_eq!(report.termination.as_str(), expected_termination);
      assert_eq!(report.profiles.len(), 1);
      assert_eq!(report.profiles[0].sources.len(), 1);
      assert_eq!(report.profiles[0].sources[0].cookies[0].name, "retained");
      assert!(!serde_json::to_string(&report)
        .expect("serialize report")
        .contains("profile_extraction_failed"));

      let error = crate::browser::legacy::project_engine_extract_outcome(
        "internet_explorer",
        stopped_adapter_outcome(stop),
      )
      .expect_err("single-browser legacy projection returns the typed stop");
      assert!(error
        .chain()
        .any(|cause| cause.downcast_ref::<BoundaryStop>() == Some(&stop)));
    }
  }

  #[test]
  fn final_runtime_stop_is_retained_instead_of_discarding_outcome() {
    use crate::common::deadline::{
      test_clock::ManualClock, BoundaryRuntime, BoundaryStop, CancellationToken, Deadline,
    };
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
          Deadline::after(&clock, Duration::from_secs(1))
        }
        BoundaryStop::ResourceExhausted => {
          assert!(token.exhaust_resources());
          Deadline::after(&clock, Duration::from_secs(1))
        }
      };
      let runtime = BoundaryRuntime::with_stop(&clock, deadline, token);

      // A discovery-only extract: profiles with no committed source.
      let listing = discovered_sources();
      let discovery_only = EngineExtract {
        profiles: listing
          .profiles
          .into_iter()
          .map(|profile| ExtractedProfile {
            identity: profile.identity,
            legacy: profile.legacy,
            sources: Vec::new(),
          })
          .collect(),
        discovery_issues: listing.discovery_issues,
        counters: listing.counters,
        boundary_stop: listing.boundary_stop,
      };
      let retained = retain_engine_runtime_stop(discovery_only, &runtime);

      assert_eq!(retained.boundary_stop, Some(stop));
      assert!(retained.profiles.is_empty());
    }
  }

  #[test]
  fn a_profile_selected_internet_explorer_report_reads_only_the_selected_profile() {
    let temp = TempDir::new("ie-profile-selection");
    let home = temp.path().to_path_buf();
    let context = context_for(
      PlatformId::Windows,
      home.clone(),
      [
        ("APPDATA", home.join("AppData")),
        ("LOCALAPPDATA", home.join("LocalAppData")),
      ],
    );
    // A WebCache root is its own profile, so two roots are two profiles.
    let roots = test_seams::resolvable_root_paths(&context, "internet_explorer");
    assert_eq!(roots.len(), 2, "IE must declare two WebCache roots");
    for root in &roots {
      std::fs::create_dir_all(root).expect("create WebCache root");
      std::fs::write(root.join(INTERNET_EXPLORER_COOKIE_FILE), b"ese")
        .expect("seed WebCache database");
    }
    let canonical_roots = roots
      .iter()
      .map(|root| root.canonicalize().expect("canonical WebCache root"))
      .collect::<Vec<_>>();
    let expected_installation_ids = ["ie-webcache-roaming", "ie-webcache-local"]
      .into_iter()
      .zip(&canonical_roots)
      .map(|(root_id, root)| {
        installation_id(
          "internet_explorer",
          root_id,
          "stable",
          &normalized_path_bytes(root),
        )
      })
      .collect::<Vec<_>>();
    let expected_profile_ids = expected_installation_ids
      .iter()
      .map(|installation_id| {
        profile_id(
          installation_id.as_str(),
          ProfileLocator::Relative(Path::new("")),
        )
      })
      .collect::<Vec<_>>();
    let discovery = discover_internet_explorer_with_context(&context, "internet_explorer")
      .expect("discover both WebCache roots");
    assert_eq!(discovery.counters.installations_detected, 2);
    assert_eq!(discovery.counters.installations_discovered, 2);
    assert_eq!(discovery.counters.installations_enumerated, 2);
    assert_eq!(
      discovery
        .profiles
        .iter()
        .map(|profile| profile.identity.installation_priority)
        .collect::<Vec<_>>(),
      [10, 20]
    );
    assert_eq!(
      discovery
        .profiles
        .iter()
        .map(|profile| profile.identity.installation_path.clone())
        .collect::<Vec<_>>(),
      canonical_roots
    );
    assert_eq!(
      discovery
        .profiles
        .iter()
        .map(|profile| profile.identity.installation_id.clone())
        .collect::<Vec<_>>(),
      expected_installation_ids
    );
    assert_eq!(
      discovery
        .profiles
        .iter()
        .map(|profile| profile.identity.profile_id.clone())
        .collect::<Vec<_>>(),
      expected_profile_ids
    );
    for profile in &discovery.profiles {
      for id in [
        profile.identity.installation_id.as_str(),
        profile.identity.profile_id.as_str(),
      ] {
        assert_eq!(id.len(), 64);
        assert!(id
          .bytes()
          .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
      }
      // Discovery output: a candidate that has not been queried. The frozen
      // placeholder shape (`NotAttempted`, not selected until extract) is
      // unchanged; a `SourceCandidate` is a listing leaf with no attempt count.
      assert_eq!(profile.candidates.len(), 1);
      assert_eq!(
        profile.candidates[0].acquisition,
        SourceAcquisition::NotAttempted
      );
      assert!(profile.candidates[0].exists);
    }
    let rediscovery = discover_internet_explorer_with_context(&context, "internet_explorer")
      .expect("rediscover both WebCache roots");
    assert_eq!(
      rediscovery
        .profiles
        .iter()
        .map(|profile| (
          &profile.identity.installation_id,
          &profile.identity.profile_id
        ))
        .collect::<Vec<_>>(),
      discovery
        .profiles
        .iter()
        .map(|profile| (
          &profile.identity.installation_id,
          &profile.identity.profile_id
        ))
        .collect::<Vec<_>>()
    );
    let rows = |origin: SourceCandidate, _: Option<&[String]>| {
      Ok(extracted_internet_explorer_source(
        origin,
        Vec::new(),
        0,
        0,
        0,
        None,
      ))
    };

    let all = internet_explorer_report_with_context(
      &context,
      "internet_explorer",
      ProfileSelection::AllProfiles,
      None,
      rows,
    )
    .expect("full report");
    assert_eq!(all.profiles.len(), 2);
    assert_eq!(all.counters.installations_detected, 2);
    assert_eq!(all.counters.installations_discovered, 2);
    assert_eq!(all.counters.installations_enumerated, 2);
    assert_eq!(
      all
        .profiles
        .iter()
        .map(|profile| (
          &profile.identity.installation_id,
          &profile.identity.profile_id
        ))
        .collect::<Vec<_>>(),
      discovery
        .profiles
        .iter()
        .map(|profile| (
          &profile.identity.installation_id,
          &profile.identity.profile_id
        ))
        .collect::<Vec<_>>()
    );
    assert!(all.profiles.iter().all(|profile| {
      profile.sources[0].acquisition == SourceAcquisition::EseDatabase
        && profile.sources[0].acquisition_attempts == 1
    }));
    let selected = all.profiles[1].identity.profile_id.clone();
    let selected_source = all.profiles[1].sources[0].origin.path.clone();

    let mut read = Vec::new();
    let one = internet_explorer_report_with_context(
      &context,
      "internet_explorer",
      ProfileSelection::ProfileId(selected.as_str()),
      None,
      |origin, domains| {
        read.push(origin.path.clone());
        rows(origin, domains)
      },
    )
    .expect("profile-selected report");

    assert_eq!(read, vec![selected_source]);
    assert_eq!(one.profiles.len(), 1);
    assert_eq!(one.profiles[0].identity.profile_id, selected);
    assert_eq!(
      one.counters.installations_discovered,
      all.counters.installations_discovered
    );

    let unknown = internet_explorer_report_with_context(
      &context,
      "internet_explorer",
      ProfileSelection::ProfileId("not-a-profile"),
      None,
      rows,
    )
    .expect_err("an unknown profile id is a request error");
    assert!(unknown
      .to_string()
      .contains("unknown internet_explorer profile id"));
  }

  #[test]
  fn internet_explorer_existing_root_without_webcache_is_profile_absence() {
    let temp = TempDir::new("ie-root-without-webcache");
    let home = temp.path().to_path_buf();
    let context = context_for(
      PlatformId::Windows,
      home.clone(),
      [
        ("APPDATA", home.join("AppData")),
        ("LOCALAPPDATA", home.join("LocalAppData")),
      ],
    );
    let root = test_seams::primary_root_path(&context, "internet_explorer");
    std::fs::create_dir_all(&root).expect("create WebCache root without database");
    let canonical_root = root.canonicalize().expect("canonical WebCache root");

    let discovery = discover_internet_explorer_with_context(&context, "internet_explorer")
      .expect("missing WebCache is profile absence");

    assert_eq!(discovery.counters.installations_detected, 1);
    assert_eq!(discovery.counters.installations_discovered, 1);
    assert_eq!(discovery.counters.installations_enumerated, 1);
    assert!(discovery.profiles.is_empty());
    assert!(!discovery.all_detected_roots_failed());
    assert_eq!(discovery.discovery_issues.len(), 1);
    assert_eq!(
      discovery.discovery_issues[0].code,
      "profile_has_no_cookie_source"
    );
    assert_eq!(discovery.discovery_issues[0].path, canonical_root);
  }

  #[test]
  fn internet_explorer_duplicate_canonical_root_keeps_first_registry_owner() {
    let temp = TempDir::new("ie-duplicate-canonical-root");
    let home = temp.path().to_path_buf();
    let real_context = context_for(
      PlatformId::Windows,
      home.clone(),
      [
        ("APPDATA", home.join("AppData")),
        ("LOCALAPPDATA", home.join("LocalAppData")),
      ],
    );
    let roots = test_seams::resolvable_root_paths(&real_context, "internet_explorer");
    assert_eq!(roots.len(), 2);
    for root in &roots {
      std::fs::create_dir_all(root).expect("create aliased WebCache root");
    }
    let shared = temp.path().join("shared-webcache");
    std::fs::create_dir_all(&shared).expect("create shared WebCache root");
    std::fs::write(shared.join(INTERNET_EXPLORER_COOKIE_FILE), b"ese")
      .expect("seed shared WebCache database");
    let shared = shared
      .canonicalize()
      .expect("canonical shared WebCache root");
    let context = with_test_fs(
      real_context,
      TestDiscoveryFs {
        canonical_aliases: BTreeMap::from([
          (roots[0].clone(), shared.clone()),
          (roots[1].clone(), shared.clone()),
        ]),
        ..TestDiscoveryFs::default()
      },
    );

    let discovery = discover_internet_explorer_with_context(&context, "internet_explorer")
      .expect("deduplicate canonical WebCache roots");

    assert_eq!(discovery.counters.installations_detected, 2);
    assert_eq!(discovery.counters.installations_discovered, 1);
    assert_eq!(discovery.counters.installations_enumerated, 1);
    assert_eq!(discovery.profiles.len(), 1);
    assert_eq!(discovery.profiles[0].identity.installation_priority, 10);
    assert_eq!(discovery.profiles[0].identity.installation_path, shared);
    let duplicate = discovery
      .discovery_issues
      .iter()
      .find(|issue| issue.code == "duplicate_installation")
      .expect("duplicate installation issue");
    assert_eq!(duplicate.occurrences, 1);
    assert!(!discovery
      .discovery_issues
      .iter()
      .any(|issue| issue.code == "duplicate_profile"));
  }

  #[test]
  fn internet_explorer_report_preserves_row_errors() {
    let temp = TempDir::new("ie-row-error");
    let home = temp.path().to_path_buf();
    let context = context_for(
      PlatformId::Windows,
      home.clone(),
      [
        ("APPDATA", home.join("AppData")),
        ("LOCALAPPDATA", home.join("LocalAppData")),
      ],
    );
    let root = test_seams::resolvable_root_paths(&context, "internet_explorer")
      .into_iter()
      .next()
      .expect("Internet Explorer root");
    std::fs::create_dir_all(&root).expect("create WebCache root");
    std::fs::write(root.join(INTERNET_EXPLORER_COOKIE_FILE), b"ese")
      .expect("seed WebCache database");

    let outcome = internet_explorer_report_with_context(
      &context,
      "internet_explorer",
      ProfileSelection::AllProfiles,
      None,
      |origin, _| {
        Ok(extracted_internet_explorer_source(
          origin,
          Vec::new(),
          2,
          1,
          1,
          Some("invalid WebCache record".to_owned()),
        ))
      },
    )
    .expect("Internet Explorer report");

    let source = &outcome.profiles[0].sources[0];
    assert_eq!(source.stats.rows_seen, 2);
    assert_eq!(source.stats.rows_skipped, 1);
    assert_eq!(source.stats.rows_rejected, 1);
    let row_issue = source
      .issues
      .iter()
      .find(|issue| issue.code == "row_read_failed")
      .expect("skipped rows are reported");
    assert_eq!(row_issue.message, "invalid WebCache record");
  }

  #[test]
  fn internet_explorer_query_failures_remain_parse_failures() {
    let temp = TempDir::new("ie-query-failure-stage");
    let home = temp.path().to_path_buf();
    let context = context_for(
      PlatformId::Windows,
      home.clone(),
      [
        ("APPDATA", home.join("AppData")),
        ("LOCALAPPDATA", home.join("LocalAppData")),
      ],
    );
    let root = test_seams::primary_root_path(&context, "internet_explorer");
    std::fs::create_dir_all(&root).expect("create WebCache root");
    std::fs::write(root.join(INTERNET_EXPLORER_COOKIE_FILE), b"ese")
      .expect("seed WebCache database");

    let outcome = internet_explorer_report_with_context(
      &context,
      "internet_explorer",
      ProfileSelection::AllProfiles,
      None,
      |_, _| bail!("injected WebCache query failure"),
    )
    .expect("query failures remain report data");

    let source = &outcome.profiles[0].sources[0];
    let failure = source.failure.as_ref().expect("query failure recorded");
    assert_eq!(failure.stage, SourceFailureStage::Parse);
    assert_eq!(failure.message, "injected WebCache query failure");
  }

  #[test]
  fn later_valid_ie_root_survives_an_earlier_metadata_failure() {
    let temp = TempDir::new("ie-root-metadata-partial-failure");
    let home = temp.path().join("home");
    let real_context = context_for(
      PlatformId::Windows,
      home.clone(),
      [
        ("APPDATA", home.join("AppData")),
        ("LOCALAPPDATA", home.join("LocalAppData")),
      ],
    );
    let denied = browser_root(&real_context, "internet_explorer", "ie-webcache-roaming");
    let valid = browser_root(&real_context, "internet_explorer", "ie-webcache-local");
    std::fs::create_dir_all(&valid).expect("create the later IE root");
    std::fs::write(valid.join(INTERNET_EXPLORER_COOKIE_FILE), b"ese")
      .expect("seed the later IE root");
    let context = with_test_fs(
      real_context,
      TestDiscoveryFs {
        denied_metadata: Some(denied.clone()),
        ..TestDiscoveryFs::default()
      },
    );

    let discovery = discover_internet_explorer_with_context(&context, "internet_explorer")
      .expect("retain the valid IE root");
    assert_eq!(discovery.counters.installations_detected, 2);
    assert_eq!(discovery.counters.installations_discovered, 1);
    assert_eq!(discovery.counters.installations_enumerated, 1);
    assert_eq!(discovery.profiles.len(), 1);
    assert!(!discovery.all_detected_roots_failed());
    assert!(discovery
      .discovery_issues
      .iter()
      .any(|issue| { issue.code == "installation_metadata_failed" && issue.path == denied }));
  }
}
