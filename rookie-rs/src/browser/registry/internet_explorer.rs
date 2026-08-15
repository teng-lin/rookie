use super::{
  canonical_installation_root, embedded_registry, engine_roots, installation_id,
  installation_root_is_directory, normalized_path_bytes, profile_id, select_engine_profiles,
  sort_engine_profiles, BrowserEngine, DiscoveryContext, DiscoveryFs, DiscoveryIssue,
  DiscoveryStrategy, EngineExtractionOutcome, EngineProfileExtraction, EngineSourceExtraction,
  ProfileLocator, ProfileSelection, SourceAcquisition, SourceFailureStage,
  PERSISTENT_SOURCE_PRECEDENCE, SOURCE_ROLE_PERSISTENT,
};
use crate::common::enums::Cookie;
use anyhow::Result;
use std::{
  collections::HashSet,
  path::{Path, PathBuf},
};

pub(super) const INTERNET_EXPLORER_COOKIE_FILE: &str = "WebCacheV01.dat";

/// Row accounting an Internet Explorer extractor must report. The extractor is
/// injected because the ESE reader only compiles on Windows.
pub(crate) struct InternetExplorerRows {
  pub(crate) cookies: Vec<Cookie>,
  pub(crate) records_seen: usize,
  pub(crate) records_skipped: usize,
  pub(crate) row_error: Option<String>,
}

/// Crate-private generic Internet Explorer seam. The WebCache root is flat, so
/// each detected root contributes exactly one default profile.
pub(super) fn discover_internet_explorer_with_context<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
) -> Result<EngineExtractionOutcome> {
  let registry = embedded_registry()?;
  let (definition, roots) = engine_roots(
    registry,
    context.platform,
    browser_id,
    BrowserEngine::InternetExplorer,
  )?;
  let mut seen_installations = HashSet::new();
  let mut seen_profiles = HashSet::new();
  let mut outcome = EngineExtractionOutcome::default();

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
    let source = EngineSourceExtraction {
      path: source_path,
      role: SOURCE_ROLE_PERSISTENT,
      format: "internet_explorer_ese",
      precedence: PERSISTENT_SOURCE_PRECEDENCE,
      selected: true,
      cookies: Vec::new(),
      rows_seen: 0,
      rows_skipped: 0,
      acquisition: SourceAcquisition::EseDatabase,
      acquisition_attempts: 1,
      diagnostics: Vec::new(),
      error: None,
      error_stage: SourceFailureStage::Acquisition,
      row_error: None,
    };
    outcome.profiles.push(EngineProfileExtraction {
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

pub(super) fn internet_explorer_report_with_context<F, Q>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<&[String]>,
  query: Q,
) -> Result<EngineExtractionOutcome>
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
  mut outcome: EngineExtractionOutcome,
  domains: Option<&[String]>,
  mut query: Q,
) -> EngineExtractionOutcome
where
  Q: FnMut(&Path, Option<&[String]>) -> Result<InternetExplorerRows>,
{
  for profile in &mut outcome.profiles {
    for source in &mut profile.sources {
      match query(&source.path, domains) {
        Ok(rows) => {
          source.rows_seen = rows.records_seen;
          source.rows_skipped = rows.records_skipped;
          source.row_error = rows.row_error;
          source.cookies = rows.cookies;
        }
        Err(error) => {
          // WebCache failures are schema or record-enumeration problems, which
          // the ESE reader reaches only after opening the database.
          source.error_stage = SourceFailureStage::Parse;
          source.error = Some(format!("{error:#}"));
        }
      }
    }
  }
  outcome
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
pub(crate) fn internet_explorer_profiles(browser_id: &str) -> Result<EngineExtractionOutcome> {
  let context = DiscoveryContext::system()?;
  discover_internet_explorer_with_context(&context, browser_id)
}

#[cfg(target_os = "windows")]
pub(crate) fn internet_explorer_report(
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<Vec<String>>,
) -> Result<EngineExtractionOutcome> {
  let context = DiscoveryContext::system()?;
  internet_explorer_report_with_context(
    &context,
    browser_id,
    profile_id,
    domains.as_deref(),
    |path, domains| {
      query_internet_explorer_non_disruptive(path, domains, |path, domains, force_kill| {
        crate::browser::internet_explorer::internet_explorer_outcome(path, domains, force_kill).map(
          |extraction| InternetExplorerRows {
            cookies: extraction.cookies,
            records_seen: extraction.stats.records_seen,
            records_skipped: extraction.stats.records_skipped,
            row_error: extraction.row_error,
          },
        )
      })
    },
  )
}

#[cfg(target_os = "windows")]
pub(crate) fn legacy_internet_explorer_outcome(
  browser_id: &str,
  domains: Option<Vec<String>>,
) -> Result<EngineExtractionOutcome> {
  let context = DiscoveryContext::system()?;
  let mut outcome = discover_internet_explorer_with_context(&context, browser_id)?;
  select_engine_profiles(
    &mut outcome,
    browser_id,
    ProfileSelection::LegacyFirstProfile,
  )?;
  Ok(populate_internet_explorer_sources(
    outcome,
    domains.as_deref(),
    |path, domains| {
      query_internet_explorer_non_disruptive(path, domains, |path, domains, force_kill| {
        crate::browser::internet_explorer::internet_explorer_outcome(path, domains, force_kill).map(
          |extraction| InternetExplorerRows {
            cookies: extraction.cookies,
            records_seen: extraction.stats.records_seen,
            records_skipped: extraction.stats.records_skipped,
            row_error: extraction.row_error,
          },
        )
      })
    },
  ))
}

#[cfg(test)]
mod tests {
  use super::*;

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
          cookies: Vec::new(),
          records_seen: 0,
          records_skipped: 0,
          row_error: None,
        })
      },
    )
    .expect("non-disruptive query bridge");

    assert!(rows.cookies.is_empty());
  }
}
