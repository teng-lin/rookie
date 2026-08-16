use super::{
  canonical_installation_root, embedded_registry, engine_roots, installation_id,
  installation_root_is_directory, normalized_path_bytes, profile_id, select_engine_profiles,
  sort_engine_profiles, BrowserEngine, DiscoveryContext, DiscoveryFs, DiscoveryIssue,
  DiscoveryStrategy, EngineExtractionDraft, EngineProfileDraft, EngineSourceDraft, ProfileLocator,
  ProfileSelection, SourceAcquisition, SourceFailureStage, PERSISTENT_SOURCE_PRECEDENCE,
  SOURCE_ROLE_PERSISTENT,
};
use anyhow::Result;
use std::{
  collections::HashSet,
  path::{Path, PathBuf},
};

pub(super) const SAFARI_COOKIE_FILE: &str = "Cookies.binarycookies";

/// Safari's registry root is `{home}/Library`, which every macOS account owns
/// whether or not Safari is installed, so the root alone proves nothing. Every
/// location profile discovery reads descends from one of these two Safari-owned
/// paths: the sandbox container for modern versions, the bare cookie jar for
/// pre-sandbox ones.
const SAFARI_INSTALLATION_MARKERS: [&str; 2] = [
  "Containers/com.apple.Safari",
  "Cookies/Cookies.binarycookies",
];

/// Only provable absence of every marker rejects the root. A marker that
/// cannot be inspected -- the usual shape of a Full Disk Access denial -- keeps
/// Safari detected so the report explains the denial instead of claiming
/// Safari is not installed.
fn has_safari_installation_marker<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  library: &Path,
) -> bool {
  SAFARI_INSTALLATION_MARKERS.iter().any(|marker| {
    !matches!(
      context.fs.metadata(&library.join(marker)),
      Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
  })
}

/// Crate-private generic Safari seam. Named profiles come from PR #137's
/// database-first discovery; this adapter only reshapes them, so legacy
/// `safari()` first-match selection is untouched.
pub(super) fn discover_safari_with_context<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
) -> Result<EngineExtractionDraft> {
  let registry = embedded_registry()?;
  let (definition, roots) = engine_roots(
    registry,
    context.platform,
    browser_id,
    BrowserEngine::Safari,
  )?;
  let mut seen_installations = HashSet::new();
  let mut seen_profiles = HashSet::new();
  let mut outcome = EngineExtractionDraft::default();

  for root in roots {
    if root.discovery != DiscoveryStrategy::SafariDefaultProfile {
      continue;
    }
    let Some(resolved_root) = context.resolve_template(&root.template) else {
      continue;
    };
    // Non-Chromium registry templates never glob, so the suffix is literal.
    let root_path = resolved_root.base.join(resolved_root.suffix);
    if !installation_root_is_directory(context, &root_path, &mut outcome)
      || !has_safari_installation_marker(context, &root_path)
    {
      continue;
    }
    let Some(canonical_root) =
      canonical_installation_root(context, root_path, &mut seen_installations, &mut outcome)
    else {
      continue;
    };
    let installation_id = installation_id(
      &definition.canonical_id,
      &root.root_id,
      &root.channel,
      &normalized_path_bytes(&canonical_root),
    );

    // Safari profile discovery degrades to the default profile instead of
    // failing, so a canonicalized root is always enumerated.
    outcome.installations_enumerated += 1;
    let (profiles, discovery_warning) =
      crate::browser::safari::discover_safari_profiles(&canonical_root);
    if let Some(warning) = discovery_warning {
      // A fallback that still enumerated named profiles is a degradation; one
      // that failed too means they were never enumerated, which is a loss and
      // must not be reported at warning severity.
      let code = match warning {
        crate::browser::safari::SafariProfileDiscoveryIssue::Degraded(_) => {
          "safari_profile_discovery_degraded"
        }
        crate::browser::safari::SafariProfileDiscoveryIssue::EnumerationFailed(_) => {
          "safari_profile_enumeration_failed"
        }
      };
      outcome.discovery_issues.push(DiscoveryIssue::new(
        code,
        canonical_root.clone(),
        warning.message(),
      ));
    }

    for (legacy_profile_order, profile) in profiles.into_iter().enumerate() {
      let selected =
        match crate::browser::safari::first_existing_cookie_candidate(&profile.cookie_candidates) {
          Ok(Some(path)) => path.clone(),
          // A discovered profile with no cookie source is normal absence, not an
          // extraction failure, so it is not listed as a report profile.
          Ok(None) => {
            outcome.discovery_issues.push(DiscoveryIssue::new(
              "profile_has_no_cookie_source",
              canonical_root.join(&profile.name),
              "Safari profile has no cookie source".to_owned(),
            ));
            continue;
          }
          Err(error) => {
            outcome.discovery_issues.push(DiscoveryIssue::new(
              "profile_source_inspection_failed",
              canonical_root.join(&profile.name),
              format!("{error:#}"),
            ));
            continue;
          }
        };
      let precedence = profile
        .cookie_candidates
        .iter()
        .position(|candidate| candidate == &selected)
        .map_or(PERSISTENT_SOURCE_PRECEDENCE, |index| {
          PERSISTENT_SOURCE_PRECEDENCE * (index as u16 + 1)
        });
      let source_directory = selected
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| canonical_root.clone());
      let profile_path = match context.fs.canonicalize(&source_directory) {
        Ok(path) => path,
        Err(error) => {
          outcome.discovery_issues.push(DiscoveryIssue::new(
            "profile_canonicalize_failed",
            source_directory,
            error.to_string(),
          ));
          continue;
        }
      };
      if !seen_profiles.insert(normalized_path_bytes(&profile_path)) {
        outcome.discovery_issues.push(DiscoveryIssue::new(
          "duplicate_profile",
          profile_path,
          "profile is already owned by an earlier registry root".to_owned(),
        ));
        continue;
      }
      let locator = profile_path
        .strip_prefix(&canonical_root)
        .map(ProfileLocator::Relative)
        .unwrap_or(ProfileLocator::Absolute(&profile_path));
      let source_path = profile_path.join(SAFARI_COOKIE_FILE);
      let source = EngineSourceDraft {
        path: source_path,
        role: SOURCE_ROLE_PERSISTENT,
        format: "safari_binarycookies",
        precedence,
        selected: true,
        cookies: Vec::new(),
        records: Vec::new(),
        rows_seen: 0,
        rows_skipped: 0,
        acquisition: SourceAcquisition::StableFileImage,
        // Replaced with the real count once acquisition runs; discovery-only
        // listings never attempt a read.
        acquisition_attempts: 0,
        diagnostics: Vec::new(),
        error: None,
        error_stage: SourceFailureStage::Acquisition,
        row_error: None,
      };
      outcome.profiles.push(EngineProfileDraft {
        profile_id: profile_id(&installation_id, locator),
        installation_id: installation_id.clone(),
        installation_priority: root.priority,
        legacy_installation_priority: root.priority,
        legacy_profile_order,
        legacy_is_default: profile.uuid.is_none(),
        legacy_eligible: true,
        installation_path: canonical_root.clone(),
        legacy_installation_path: canonical_root.clone(),
        legacy_name: profile.name.clone(),
        name: profile.name,
        path: profile_path,
        is_default: profile.uuid.is_none(),
        persistent_source_discovered: true,
        sources: vec![source],
      });
    }
  }
  sort_engine_profiles(&mut outcome.profiles);
  Ok(outcome)
}

pub(super) fn safari_report_with_context<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<&[String]>,
) -> Result<EngineExtractionDraft> {
  safari_report_with_query(context, browser_id, profile_id, domains, |path, domains| {
    query_safari_file(path, domains, crate::browser::safari::safari_based_outcome)
  })
}

/// The Safari report with its cookie reader injected, for the same reason the
/// Gecko seam takes one: a test must be able to see that a non-selected
/// profile's cookie file was never opened, which absence from the report cannot
/// show. [`safari_report_with_context`] is the production caller.
pub(super) fn safari_report_with_query<F, Q>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<&[String]>,
  query: Q,
) -> Result<EngineExtractionDraft>
where
  F: DiscoveryFs,
  Q: FnMut(&Path, Option<&[String]>) -> Result<crate::browser::safari::SafariFileDraft>,
{
  let mut outcome = discover_safari_with_context(context, browser_id)?;
  select_engine_profiles(
    &mut outcome,
    browser_id,
    ProfileSelection::from_profile_id(profile_id),
  )?;
  Ok(populate_safari_sources(outcome, domains, query))
}

pub(super) fn populate_safari_sources<Q>(
  mut outcome: EngineExtractionDraft,
  domains: Option<&[String]>,
  mut query: Q,
) -> EngineExtractionDraft
where
  Q: FnMut(&Path, Option<&[String]>) -> Result<crate::browser::safari::SafariFileDraft>,
{
  for profile in &mut outcome.profiles {
    for source in &mut profile.sources {
      match query(&source.path, domains) {
        Ok(extraction) => {
          source.rows_seen = extraction.stats.records_seen;
          source.rows_skipped = extraction.stats.records_skipped;
          source.acquisition_attempts = extraction.acquisition_attempts;
          source.row_error = extraction.row_error;
          source.cookies = extraction.cookies;
          source.records = extraction.records;
        }
        Err(error) => {
          // Exhausting the retries is itself the failure, so report the
          // attempts spent rather than the placeholder.
          source.acquisition_attempts = crate::browser::safari::STABLE_READ_ATTEMPTS as u32;
          source.error_stage =
            match error.downcast_ref::<crate::browser::safari::SafariParseFailure>() {
              Some(failure) => {
                source.rows_seen = failure.stats.records_seen;
                source.rows_skipped = failure.stats.records_skipped;
                source.row_error = Some(format!("{error:#}"));
                SourceFailureStage::Parse
              }
              None => SourceFailureStage::Acquisition,
            };
          source.error = Some(format!("{error:#}"));
        }
      }
    }
  }
  outcome
}

fn query_safari_file<Q>(
  path: &Path,
  domains: Option<&[String]>,
  query: Q,
) -> Result<crate::browser::safari::SafariFileDraft>
where
  Q: FnOnce(PathBuf, Option<Vec<String>>) -> Result<crate::browser::safari::SafariFileDraft>,
{
  query(path.to_path_buf(), domains.map(<[String]>::to_vec))
}

#[cfg(target_os = "macos")]
pub(crate) fn safari_report(
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<Vec<String>>,
) -> Result<EngineExtractionDraft> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  safari_report_with_runtime(browser_id, profile_id, domains, &runtime)
}

#[cfg(target_os = "macos")]
pub(crate) fn safari_report_with_runtime(
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<Vec<String>>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<EngineExtractionDraft> {
  runtime.check()?;
  let context = DiscoveryContext::system()?;
  runtime.check()?;
  let mut outcome = discover_safari_with_context(&context, browser_id)?;
  select_engine_profiles(
    &mut outcome,
    browser_id,
    ProfileSelection::from_profile_id(profile_id),
  )?;
  let outcome = populate_safari_sources(outcome, domains.as_deref(), |path, domains| {
    query_safari_file(path, domains, |path, domains| {
      crate::browser::safari::safari_based_outcome_with_runtime(path, domains, runtime)
    })
  });
  runtime.check()?;
  Ok(outcome)
}

pub(super) fn select_legacy_safari_profile(
  outcome: &mut EngineExtractionDraft,
  browser_id: &str,
) -> Result<()> {
  // The historical named wrapper probed only Safari's two default cookie
  // locations. Named profiles remain report-capable, but must never become a
  // fallback when both default locations are absent.
  outcome.profiles.retain(|profile| profile.is_default);
  select_engine_profiles(outcome, browser_id, ProfileSelection::LegacyFirstProfile)
}

#[cfg(target_os = "macos")]
pub(crate) fn legacy_safari_outcome(
  browser_id: &str,
  domains: Option<Vec<String>>,
) -> Result<EngineExtractionDraft> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  legacy_safari_outcome_with_runtime(browser_id, domains, &runtime)
}

#[cfg(target_os = "macos")]
pub(crate) fn legacy_safari_outcome_with_runtime(
  browser_id: &str,
  domains: Option<Vec<String>>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<EngineExtractionDraft> {
  runtime.check()?;
  let context = DiscoveryContext::system()?;
  runtime.check()?;
  let mut outcome = discover_safari_with_context(&context, browser_id)?;
  select_legacy_safari_profile(&mut outcome, browser_id)?;
  Ok(populate_safari_sources(
    outcome,
    domains.as_deref(),
    |path, domains| {
      query_safari_file(path, domains, |path, domains| {
        crate::browser::safari::safari_based_outcome_with_runtime(path, domains, runtime)
      })
    },
  ))
}

#[cfg(target_os = "macos")]
pub(crate) fn safari_profiles(browser_id: &str) -> Result<EngineExtractionDraft> {
  let context = DiscoveryContext::system()?;
  discover_safari_with_context(&context, browser_id)
}

#[cfg(test)]
mod tests {
  use super::*;
  use anyhow::anyhow;

  fn discovered_source() -> EngineExtractionDraft {
    let installation_path = PathBuf::from("/Users/rookie/Library");
    let profile_path = installation_path.join("Cookies");
    EngineExtractionDraft {
      installations_detected: 1,
      installations_discovered: 1,
      installations_enumerated: 1,
      boundary_stop: None,
      profiles: vec![EngineProfileDraft {
        profile_id: "safari-profile".to_owned(),
        installation_id: "safari-installation".to_owned(),
        installation_priority: 10,
        legacy_installation_priority: 10,
        legacy_profile_order: 0,
        legacy_is_default: true,
        legacy_eligible: true,
        installation_path: installation_path.clone(),
        legacy_installation_path: installation_path,
        legacy_name: "Default".to_owned(),
        name: "Default".to_owned(),
        path: profile_path.clone(),
        is_default: true,
        persistent_source_discovered: true,
        sources: vec![EngineSourceDraft {
          path: profile_path.join(SAFARI_COOKIE_FILE),
          role: SOURCE_ROLE_PERSISTENT,
          format: "safari_binarycookies",
          precedence: PERSISTENT_SOURCE_PRECEDENCE,
          selected: true,
          cookies: Vec::new(),
          records: Vec::new(),
          rows_seen: 0,
          rows_skipped: 0,
          acquisition: SourceAcquisition::StableFileImage,
          acquisition_attempts: 0,
          diagnostics: Vec::new(),
          error: None,
          error_stage: SourceFailureStage::Acquisition,
          row_error: None,
        }],
      }],
      discovery_issues: Vec::new(),
    }
  }

  #[test]
  fn native_query_bridge_forwards_owned_path_and_domains() {
    let path = PathBuf::from("/Users/rookie/Library/Cookies/Cookies.binarycookies");
    let domains = vec!["example.com".to_owned(), "mozilla.org".to_owned()];

    let result = query_safari_file(
      &path,
      Some(&domains),
      |forwarded_path, forwarded_domains| {
        assert_eq!(forwarded_path, path);
        assert_eq!(forwarded_domains.as_deref(), Some(domains.as_slice()));
        Err(anyhow::anyhow!("injected query"))
      },
    )
    .expect_err("injected query result is preserved");

    assert_eq!(result.to_string(), "injected query");
  }

  #[test]
  fn source_population_preserves_rows_attempts_and_failure_stage() {
    let success = populate_safari_sources(discovered_source(), None, |_, _| {
      Ok(crate::browser::safari::SafariFileDraft {
        cookies: Vec::new(),
        records: Vec::new(),
        stats: crate::browser::safari::SafariExtractionStats {
          records_seen: 7,
          records_skipped: 2,
        },
        row_error: Some("recoverable record".to_owned()),
        acquisition_attempts: 2,
      })
    });
    let success = &success.profiles[0].sources[0];
    assert_eq!(success.rows_seen, 7);
    assert_eq!(success.rows_skipped, 2);
    assert_eq!(success.row_error.as_deref(), Some("recoverable record"));
    assert_eq!(success.acquisition_attempts, 2);
    assert!(success.error.is_none());

    let parse_error =
      anyhow!("invalid Safari record").context(crate::browser::safari::SafariParseFailure {
        stats: crate::browser::safari::SafariExtractionStats {
          records_seen: 5,
          records_skipped: 3,
        },
      });
    let expected_parse_error = format!("{parse_error:#}");
    let mut parse_error = Some(parse_error);
    let parse = populate_safari_sources(discovered_source(), None, |_, _| {
      Err(parse_error.take().expect("single parse query"))
    });
    let parse = &parse.profiles[0].sources[0];
    assert_eq!(parse.error_stage, SourceFailureStage::Parse);
    assert_eq!(parse.rows_seen, 5);
    assert_eq!(parse.rows_skipped, 3);
    assert_eq!(
      parse.acquisition_attempts,
      crate::browser::safari::STABLE_READ_ATTEMPTS as u32
    );
    assert_eq!(parse.error.as_deref(), Some(expected_parse_error.as_str()));
    assert_eq!(
      parse.row_error.as_deref(),
      Some(expected_parse_error.as_str())
    );

    let acquisition_error = anyhow!("Safari source denied").context("acquire Safari cookie file");
    let expected_acquisition_error = format!("{acquisition_error:#}");
    let mut acquisition_error = Some(acquisition_error);
    let acquisition = populate_safari_sources(discovered_source(), None, |_, _| {
      Err(acquisition_error.take().expect("single acquisition query"))
    });
    let acquisition = &acquisition.profiles[0].sources[0];
    assert_eq!(acquisition.error_stage, SourceFailureStage::Acquisition);
    assert_eq!(acquisition.rows_seen, 0);
    assert_eq!(acquisition.rows_skipped, 0);
    assert!(acquisition.row_error.is_none());
    assert_eq!(
      acquisition.acquisition_attempts,
      crate::browser::safari::STABLE_READ_ATTEMPTS as u32
    );
    assert_eq!(
      acquisition.error.as_deref(),
      Some(expected_acquisition_error.as_str())
    );
  }
}
