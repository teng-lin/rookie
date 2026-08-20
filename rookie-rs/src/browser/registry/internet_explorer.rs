use super::super::report_core::{CookieSourceFormatId, CookieSourceRoleId};
#[cfg(test)]
use super::super::source::SourceStats;
use super::super::source::{Source, SourceCandidate, SourceFailureStage};
#[cfg(test)]
use super::DiscoveryCounters;
use super::{
  boundary_stop_from_error, canonical_installation_root, embedded_registry, engine_roots,
  installation_id, installation_root_is_directory, normalized_path_bytes, profile_id,
  retain_completed_engine_extract, retain_engine_runtime_stop, select_listing_profiles,
  sort_discovered_profiles, BrowserEngine, DiscoveredProfile, DiscoveryContext, DiscoveryFs,
  DiscoveryIssue, DiscoveryStrategy, EngineExtract, EngineListing, EngineProfileIdentity,
  ExtractedProfile, LegacyRank, ProfileLocator, ProfileSelection, SourceAcquisition,
  PERSISTENT_SOURCE_PRECEDENCE,
};
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
  profile_id: Option<&str>,
  domains: Option<&[String]>,
  query: Q,
) -> Result<EngineExtract>
where
  F: DiscoveryFs,
  Q: FnMut(SourceCandidate, Option<&[String]>) -> Result<Source>,
{
  let mut listing = discover_internet_explorer_with_context(context, browser_id)?;
  select_listing_profiles(
    &mut listing,
    browser_id,
    ProfileSelection::from_profile_id(profile_id),
  )?;
  Ok(populate_internet_explorer_sources(listing, domains, query))
}

/// Candidate-driven populate. Each candidate is acquired in turn. A successful
/// query returns the engine-built [`Source`], which already carries the
/// effective `EseDatabase` acquisition; a failed query overlays it here after
/// the attempt, matching the frozen listing-to-extract behaviour.
pub(super) fn populate_internet_explorer_sources<Q>(
  listing: EngineListing,
  domains: Option<&[String]>,
  mut query: Q,
) -> EngineExtract
where
  Q: FnMut(SourceCandidate, Option<&[String]>) -> Result<Source>,
{
  let EngineListing {
    profiles,
    discovery_issues,
    counters,
    boundary_stop,
  } = listing;
  let mut extract = EngineExtract {
    profiles: Vec::with_capacity(profiles.len()),
    discovery_issues,
    counters,
    boundary_stop,
  };
  for profile in profiles {
    let DiscoveredProfile {
      identity,
      legacy,
      candidates,
    } = profile;
    let mut sources = Vec::new();
    for candidate in candidates {
      let mut source = Source::new(
        candidate.identity(),
        candidate.selected,
        candidate.acquisition,
      );
      match query(candidate, domains) {
        // The engine already built the `Source` from this candidate -- stats,
        // records, attempts, the effective acquisition, and any
        // `row_read_failed` issue -- so there is nothing to copy across.
        Ok(extraction) => source = extraction,
        Err(error) => {
          if let Some(stop) = boundary_stop_from_error(&error) {
            extract.boundary_stop.get_or_insert(stop);
            // `source` is dropped uncommitted: the query did not return, so
            // there is no outcome to report for it.
            extract.profiles.push(ExtractedProfile {
              identity,
              legacy,
              sources,
            });
            retain_completed_engine_extract(&mut extract);
            return extract;
          }
          source.acquisition = SourceAcquisition::EseDatabase;
          source.acquisition_attempts = 1;
          source.fail(
            internet_explorer_failure_stage(&error),
            format!("{error:#}"),
          );
        }
      }
      sources.push(source);
    }
    extract.profiles.push(ExtractedProfile {
      identity,
      legacy,
      sources,
    });
  }
  extract
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
  profile_id: Option<&str>,
  domains: Option<Vec<String>>,
) -> Result<EngineExtract> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  internet_explorer_report_with_runtime(browser_id, profile_id, domains, &runtime)
}

#[cfg(target_os = "windows")]
pub(crate) fn internet_explorer_report_with_runtime(
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<Vec<String>>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<EngineExtract> {
  runtime.check()?;
  let context = DiscoveryContext::system()?;
  runtime.check()?;
  let outcome = internet_explorer_report_with_context(
    &context,
    browser_id,
    profile_id,
    domains.as_deref(),
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
  let outcome =
    populate_internet_explorer_sources(listing, domains.as_deref(), |origin, domains| {
      query_internet_explorer_non_disruptive(origin, domains, |origin, domains, force_kill| {
        crate::browser::internet_explorer::internet_explorer_outcome_with_runtime(
          origin, domains, force_kill, runtime,
        )
      })
    });
  Ok(retain_engine_runtime_stop(outcome, runtime))
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::cell::Cell;

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
  fn adapter_report_and_legacy_drop_interrupted_source_placeholders() {
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

      let cookies = crate::browser::legacy::project_engine_extract_outcome(
        "internet_explorer",
        stopped_adapter_outcome(stop),
      )
      .expect("legacy projection retains completed Internet Explorer work");
      assert_eq!(cookies.len(), 1);
      assert_eq!(cookies[0].name, "retained");
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
}
