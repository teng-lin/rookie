use super::{
  canonical_installation_root, embedded_registry, engine_roots, installation_id,
  installation_root_is_directory, normalized_path_bytes, profile_id, select_engine_profiles,
  sort_engine_profiles, BrowserEngine, DiscoveryContext, DiscoveryFs, DiscoveryIssue,
  DiscoveryStrategy, EngineExtractionDraft, EngineProfileDraft, EngineSourceDraft, ProfileLocator,
  ProfileSelection, SourceAcquisition, SourceFailureStage, PERSISTENT_SOURCE_PRECEDENCE,
  SOURCE_ROLE_PERSISTENT,
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

/// Row accounting an Internet Explorer extractor must report. The extractor is
/// injected because the ESE reader only compiles on Windows.
pub(crate) struct InternetExplorerRows {
  pub(crate) records: Vec<crate::browser::cookie_record::CookieRecord>,
  pub(crate) records_seen: usize,
  pub(crate) records_skipped: usize,
  pub(crate) records_rejected: usize,
  pub(crate) row_error: Option<String>,
}

/// Crate-private generic Internet Explorer seam. The WebCache root is flat, so
/// each detected root contributes exactly one default profile.
pub(super) fn discover_internet_explorer_with_context<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
) -> Result<EngineExtractionDraft> {
  let registry = embedded_registry()?;
  let (definition, roots) = engine_roots(
    registry,
    context.platform,
    browser_id,
    BrowserEngine::InternetExplorer,
  )?;
  let mut seen_installations = HashSet::new();
  let mut seen_profiles = HashSet::new();
  let mut outcome = EngineExtractionDraft::default();

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
    outcome.installations_enumerated += 1;
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
    let installation_id = installation_id(
      &definition.canonical_id,
      &root.root_id,
      &root.channel,
      &normalized_path_bytes(&canonical_root),
    );
    let source = EngineSourceDraft {
      path: source_path,
      role: SOURCE_ROLE_PERSISTENT,
      format: "internet_explorer_ese",
      precedence: PERSISTENT_SOURCE_PRECEDENCE,
      selected: true,
      cookies: Vec::new(),
      records: Vec::new(),
      rows_seen: 0,
      rows_skipped: 0,
      rows_rejected: 0,
      acquisition: SourceAcquisition::NotAttempted,
      acquisition_attempts: 0,
      diagnostics: Vec::new(),
      error: None,
      error_stage: SourceFailureStage::Acquisition,
      row_error: None,
    };
    outcome.profiles.push(EngineProfileDraft {
      profile_id: profile_id(&installation_id, ProfileLocator::Relative(Path::new(""))),
      installation_id,
      installation_priority: root.priority,
      legacy_installation_priority: root.priority,
      legacy_profile_order: 0,
      legacy_is_default: true,
      legacy_eligible: true,
      installation_path: canonical_root.clone(),
      legacy_installation_path: canonical_root.clone(),
      legacy_name: "default".to_owned(),
      name: "default".to_owned(),
      path: canonical_root,
      is_default: true,
      persistent_source_discovered: true,
      sources: vec![source],
    });
  }
  sort_engine_profiles(&mut outcome.profiles);
  Ok(outcome)
}

fn discover_internet_explorer_with_runtime<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<EngineExtractionDraft> {
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
) -> Result<EngineExtractionDraft>
where
  F: DiscoveryFs,
  Q: FnMut(&Path, Option<&[String]>) -> Result<InternetExplorerRows>,
{
  let mut outcome = discover_internet_explorer_with_context(context, browser_id)?;
  select_engine_profiles(
    &mut outcome,
    browser_id,
    ProfileSelection::from_profile_id(profile_id),
  )?;
  Ok(populate_internet_explorer_sources(outcome, domains, query))
}

pub(super) fn populate_internet_explorer_sources<Q>(
  mut outcome: EngineExtractionDraft,
  domains: Option<&[String]>,
  mut query: Q,
) -> EngineExtractionDraft
where
  Q: FnMut(&Path, Option<&[String]>) -> Result<InternetExplorerRows>,
{
  for profile in &mut outcome.profiles {
    for source in &mut profile.sources {
      match query(&source.path, domains) {
        Ok(rows) => {
          source.acquisition = SourceAcquisition::EseDatabase;
          source.acquisition_attempts = 1;
          source.rows_seen = rows.records_seen;
          source.rows_skipped = rows.records_skipped;
          source.rows_rejected = rows.records_rejected;
          source.row_error = rows.row_error;
          source.records = rows.records;
        }
        Err(error) => {
          if let Some(stop) = boundary_stop_from_error(&error) {
            outcome.boundary_stop.get_or_insert(stop);
            super::retain_completed_engine_work(&mut outcome);
            return outcome;
          }
          source.acquisition = SourceAcquisition::EseDatabase;
          source.acquisition_attempts = 1;
          source.error_stage = internet_explorer_failure_stage(&error);
          source.error = Some(format!("{error:#}"));
        }
      }
    }
  }
  outcome
}

fn boundary_stop_from_error(
  error: &anyhow::Error,
) -> Option<crate::common::deadline::BoundaryStop> {
  error.chain().find_map(|cause| {
    cause
      .downcast_ref::<crate::common::deadline::BoundaryStop>()
      .copied()
  })
}

fn retain_internet_explorer_runtime_stop(
  mut outcome: EngineExtractionDraft,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> EngineExtractionDraft {
  if let Err(stop) = runtime.check() {
    outcome.boundary_stop.get_or_insert(stop);
  }
  if outcome.boundary_stop.is_some() {
    super::retain_completed_engine_work(&mut outcome);
  }
  outcome
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
  path: &Path,
  domains: Option<&[String]>,
  query: Q,
) -> Result<InternetExplorerRows>
where
  Q: FnOnce(PathBuf, Option<Vec<String>>, bool) -> Result<InternetExplorerRows>,
{
  query(path.to_path_buf(), domains.map(<[String]>::to_vec), false)
}

#[cfg(target_os = "windows")]
pub(crate) fn internet_explorer_profiles_with_runtime(
  browser_id: &str,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<EngineExtractionDraft> {
  runtime.check()?;
  let context = DiscoveryContext::system()?;
  discover_internet_explorer_with_runtime(&context, browser_id, runtime)
}

#[cfg(target_os = "windows")]
pub(crate) fn internet_explorer_report(
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<Vec<String>>,
) -> Result<EngineExtractionDraft> {
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
) -> Result<EngineExtractionDraft> {
  runtime.check()?;
  let context = DiscoveryContext::system()?;
  runtime.check()?;
  let outcome = internet_explorer_report_with_context(
    &context,
    browser_id,
    profile_id,
    domains.as_deref(),
    |path, domains| {
      query_internet_explorer_non_disruptive(path, domains, |path, domains, force_kill| {
        crate::browser::internet_explorer::internet_explorer_outcome_with_runtime(
          path, domains, force_kill, runtime,
        )
        .map(|extraction| InternetExplorerRows {
          records: extraction.records,
          records_seen: extraction.stats.records_seen,
          records_skipped: extraction.stats.records_skipped,
          records_rejected: extraction.stats.records_rejected,
          row_error: extraction.row_error,
        })
      })
    },
  )?;
  Ok(retain_internet_explorer_runtime_stop(outcome, runtime))
}

#[cfg(target_os = "windows")]
pub(crate) fn legacy_internet_explorer_outcome(
  browser_id: &str,
  domains: Option<Vec<String>>,
) -> Result<EngineExtractionDraft> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  legacy_internet_explorer_outcome_with_runtime(browser_id, domains, &runtime)
}

#[cfg(target_os = "windows")]
pub(crate) fn legacy_internet_explorer_outcome_with_runtime(
  browser_id: &str,
  domains: Option<Vec<String>>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<EngineExtractionDraft> {
  runtime.check()?;
  let context = DiscoveryContext::system()?;
  runtime.check()?;
  let mut outcome = discover_internet_explorer_with_runtime(&context, browser_id, runtime)?;
  select_engine_profiles(
    &mut outcome,
    browser_id,
    ProfileSelection::LegacyFirstProfile,
  )?;
  let outcome = populate_internet_explorer_sources(outcome, domains.as_deref(), |path, domains| {
    query_internet_explorer_non_disruptive(path, domains, |path, domains, force_kill| {
      crate::browser::internet_explorer::internet_explorer_outcome_with_runtime(
        path, domains, force_kill, runtime,
      )
      .map(|extraction| InternetExplorerRows {
        records: extraction.records,
        records_seen: extraction.stats.records_seen,
        records_skipped: extraction.stats.records_skipped,
        records_rejected: extraction.stats.records_rejected,
        row_error: extraction.row_error,
      })
    })
  });
  Ok(retain_internet_explorer_runtime_stop(outcome, runtime))
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::cell::Cell;

  fn discovered_source_draft(path: PathBuf) -> EngineSourceDraft {
    EngineSourceDraft {
      path,
      role: SOURCE_ROLE_PERSISTENT,
      format: "internet_explorer_ese",
      precedence: PERSISTENT_SOURCE_PRECEDENCE,
      selected: true,
      cookies: Vec::new(),
      records: Vec::new(),
      rows_seen: 0,
      rows_skipped: 0,
      rows_rejected: 0,
      acquisition: SourceAcquisition::NotAttempted,
      acquisition_attempts: 0,
      diagnostics: Vec::new(),
      error: None,
      error_stage: SourceFailureStage::Acquisition,
      row_error: None,
    }
  }

  fn discovered_sources() -> EngineExtractionDraft {
    let installation_path = PathBuf::from(r"C:\Users\rookie\WebCache");
    EngineExtractionDraft {
      installations_detected: 1,
      installations_discovered: 1,
      installations_enumerated: 1,
      boundary_stop: None,
      profiles: vec![EngineProfileDraft {
        profile_id: "1".repeat(64),
        installation_id: "0".repeat(64),
        installation_priority: 10,
        legacy_installation_priority: 10,
        legacy_profile_order: 0,
        legacy_is_default: true,
        legacy_eligible: true,
        installation_path: installation_path.clone(),
        legacy_installation_path: installation_path.clone(),
        legacy_name: "default".to_owned(),
        name: "default".to_owned(),
        path: installation_path.clone(),
        is_default: true,
        persistent_source_discovered: true,
        sources: vec![
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

    let rows = query_internet_explorer_non_disruptive(
      &path,
      Some(&domains),
      |forwarded_path, forwarded_domains, force_kill| {
        assert_eq!(forwarded_path, path);
        assert_eq!(forwarded_domains.as_deref(), Some(domains.as_slice()));
        assert!(!force_kill);
        Ok(InternetExplorerRows {
          records: Vec::new(),
          records_seen: 0,
          records_skipped: 0,
          records_rejected: 0,
          row_error: None,
        })
      },
    )
    .expect("non-disruptive query bridge");

    assert!(rows.records.is_empty());
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
      let populated = populate_internet_explorer_sources(discovered_sources(), None, |_, _| {
        let call = calls.get();
        calls.set(call + 1);
        if call == 0 {
          Ok(InternetExplorerRows {
            records: Vec::new(),
            records_seen: 7,
            records_skipped: 2,
            records_rejected: 2,
            row_error: None,
          })
        } else {
          Err(anyhow::Error::new(InternetExplorerFailure::new(
            InternetExplorerFailureStage::Parse,
            anyhow::Error::new(stop),
          )))
        }
      });

      assert_eq!(calls.get(), 2);
      assert_eq!(populated.boundary_stop, Some(stop));
      assert_eq!(populated.profiles[0].sources[0].rows_seen, 7);
      assert_eq!(populated.profiles[0].sources[0].rows_skipped, 2);
      assert_eq!(populated.profiles[0].sources[0].rows_rejected, 2);
      assert!(populated.profiles[0].sources[0].error.is_none());
      assert_eq!(populated.profiles[0].sources.len(), 1);
    }
  }

  fn stopped_adapter_outcome(stop: crate::common::deadline::BoundaryStop) -> EngineExtractionDraft {
    let calls = Cell::new(0);
    let populated = populate_internet_explorer_sources(discovered_sources(), None, |_, _| {
      let call = calls.get();
      calls.set(call + 1);
      if call == 0 {
        Ok(InternetExplorerRows {
          records: vec![crate::browser::cookie_record::CookieRecord::from_cookie(
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
          records_seen: 1,
          records_skipped: 0,
          records_rejected: 0,
          row_error: None,
        })
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

      let report = crate::browser::report_build::project_engine_report(
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

      let cookies = crate::browser::legacy::project_engine_outcome(
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

      let retained = retain_internet_explorer_runtime_stop(discovered_sources(), &runtime);

      assert_eq!(retained.boundary_stop, Some(stop));
      assert!(retained.profiles.is_empty());
    }
  }
}
