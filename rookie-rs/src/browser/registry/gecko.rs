use super::super::mozilla;
use super::super::report_core::{CookieSourceFormatId, CookieSourceRoleId};
use super::super::source::{Source, SourceCandidate, SourceFailureStage, SourceStats};
#[cfg(test)]
use super::DiscoveryCounters;
use super::{
  browser_definition, canonical_installation_root, embedded_registry, installation_id,
  installation_root_is_directory, normalized_path_bytes, profile_id, push_bounded_discovery_issue,
  retain_completed_engine_extract, select_listing_profiles, sort_discovered_profiles,
  BrowserEngine, DiscoveredProfile, DiscoveryContext, DiscoveryFs, DiscoveryIssue,
  DiscoveryStrategy, EngineExtract, EngineListing, EngineProfileIdentity, ExtractedProfile,
  InstallationRoot, LegacyRank, ProfileLocator, ProfileSelection, SourceAcquisition,
  PERSISTENT_SOURCE_PRECEDENCE,
};
#[cfg(test)]
use super::{sort_cookies, test_seams, PlatformId, MAX_DISCOVERY_ISSUE_SAMPLES};
#[cfg(test)]
use crate::common::enums::Cookie;
#[cfg(test)]
use crate::common::sqlite::DatabaseAcquisitionStrategy;
use anyhow::{bail, Result};
#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

const GECKO_PERSISTENT_SOURCE: &str = "cookies.sqlite";

fn gecko_profile_has_source<F: DiscoveryFs>(context: &DiscoveryContext<F>, path: &Path) -> bool {
  context.fs.exists(&path.join(GECKO_PERSISTENT_SOURCE))
    || mozilla::SESSION_CANDIDATES
      .iter()
      .any(|(relative, _)| context.fs.exists(&path.join(relative)))
}

fn source_candidate(
  path: PathBuf,
  role: CookieSourceRoleId,
  format: CookieSourceFormatId,
  precedence: u16,
) -> SourceCandidate {
  SourceCandidate {
    path,
    role,
    format,
    precedence,
    // A candidate exists only because discovery found it, so listing freezes
    // `exists: true`; it is nothing yet read, so `selected` is false and
    // acquisition is `NotAttempted`.
    exists: true,
    selected: false,
    acquisition: SourceAcquisition::NotAttempted,
  }
}

/// Discovery-only Gecko listing seam: existing cookie-bearing candidates
/// without acquiring or querying any of them.
pub(super) fn gecko_profiles_with_context<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
) -> Result<EngineListing> {
  let mut listing = discover_gecko_with_context(context, browser_id)?;
  for profile in &mut listing.profiles {
    if profile.identity.persistent_source_discovered {
      profile.candidates.push(source_candidate(
        profile.identity.path.join(GECKO_PERSISTENT_SOURCE),
        CookieSourceRoleId::persistent(),
        CookieSourceFormatId::known(mozilla::PERSISTENT_FORMAT_ID),
        PERSISTENT_SOURCE_PRECEDENCE,
      ));
    }
    for (index, (relative, format)) in mozilla::SESSION_CANDIDATES.into_iter().enumerate() {
      let path = profile.identity.path.join(relative);
      if context.fs.exists(&path) {
        profile.candidates.push(source_candidate(
          path,
          CookieSourceRoleId::session(),
          CookieSourceFormatId::known(format.format_id()),
          mozilla::session_candidate_precedence(index),
        ));
      }
    }
  }
  Ok(listing)
}

fn gecko_profiles(browser_id: &str) -> Result<EngineListing> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  gecko_profiles_with_runtime(browser_id, &runtime)
}

pub(crate) fn gecko_profiles_with_runtime(
  browser_id: &str,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<EngineListing> {
  runtime.check()?;
  let context = DiscoveryContext::system()?;
  runtime.check()?;
  let profiles = gecko_profiles_with_context(&context, browser_id)?;
  runtime.check()?;
  Ok(profiles)
}

struct MarkerlessGeckoProfiles {
  profiles: Vec<mozilla::MozillaProfile>,
  optional_container_error: Option<anyhow::Error>,
}

fn markerless_gecko_profiles<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  root: &Path,
) -> Result<MarkerlessGeckoProfiles> {
  let mut candidates = context.fs.read_dir(root)?;
  let profiles_container = root.join("Profiles");
  let mut optional_container_error = None;
  if context.fs.is_dir(&profiles_container) {
    match context.fs.read_dir(&profiles_container) {
      Ok(children) => candidates.extend(children),
      Err(error) => optional_container_error = Some(error),
    }
  }
  candidates.sort_by_key(|path| normalized_path_bytes(path));
  candidates.dedup_by(|left, right| normalized_path_bytes(left) == normalized_path_bytes(right));
  Ok(MarkerlessGeckoProfiles {
    profiles: candidates
      .into_iter()
      .filter(|path| context.fs.is_dir(path) && gecko_profile_has_source(context, path))
      .map(|path| mozilla::MozillaProfile {
        name: path
          .file_name()
          .map(|name| name.to_string_lossy().into_owned())
          .unwrap_or_default(),
        path,
        is_default: false,
      })
      .collect(),
    optional_container_error,
  })
}

pub(super) fn discover_gecko_with_context<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
) -> Result<EngineListing> {
  let registry = embedded_registry()?;
  let definition = browser_definition(registry, context.platform, browser_id)?;
  if definition.engine != BrowserEngine::Gecko {
    bail!("browser {browser_id:?} is not a Gecko browser")
  }
  let mut roots: Vec<&InstallationRoot> = definition.roots.iter().collect();
  roots.sort_by_key(|root| (root.priority, root.root_id.as_str()));
  let mut seen_installations = HashSet::new();
  let mut seen_profiles: HashMap<Vec<u8>, usize> = HashMap::new();
  let mut outcome = EngineListing::default();

  for root in roots {
    if root.discovery != DiscoveryStrategy::MozillaProfilesIni {
      continue;
    }
    let Some(resolved_root) = context.resolve_template(&root.template) else {
      continue;
    };
    let root_path = resolved_root.base.join(resolved_root.suffix);
    if !installation_root_is_directory(context, &root_path, &mut outcome) {
      continue;
    }
    let Some(canonical_root) =
      canonical_installation_root(context, root_path, &mut seen_installations, &mut outcome)
    else {
      continue;
    };
    let installation_id_value = installation_id(
      &definition.canonical_id,
      &root.root_id,
      &root.channel,
      &normalized_path_bytes(&canonical_root),
    );
    let ini_path = canonical_root.join("profiles.ini");
    // A flat installation root counts as the default profile only when
    // profiles.ini told us nothing at all. An unreadable or invalid file is
    // information: it means declarations exist that we failed to interpret, so
    // the flat root is a fallback rather than a confirmed default.
    let (declared, flat_root_is_default) = if context.fs.exists(&ini_path) {
      match context
        .fs
        .read_to_string(&ini_path)
        .and_then(|contents| mozilla::list_profiles_from_str(&contents, &ini_path))
      {
        Ok(profiles) if profiles.is_empty() => (profiles, true),
        Ok(profiles) => (profiles, false),
        Err(error) => {
          outcome.discovery_issues.push(DiscoveryIssue::new(
            "mozilla_profiles_ini_invalid",
            ini_path,
            error.to_string(),
          ));
          (Vec::new(), false)
        }
      }
    } else {
      (Vec::new(), true)
    };

    // An unreadable profiles.ini is recovered from below, so enumeration only
    // fails when no strategy could list the root at all.
    let mut enumerated = true;
    let mut usable = Vec::new();
    let mut declared_persistent_source = false;
    for declared_profile in declared {
      declared_persistent_source |= context
        .fs
        .exists(&declared_profile.path.join(GECKO_PERSISTENT_SOURCE));
      if !gecko_profile_has_source(context, &declared_profile.path) {
        push_bounded_discovery_issue(
          &mut outcome.discovery_issues,
          "profile_has_no_cookie_source",
          declared_profile.path,
          "declared Gecko profile has no supported cookie source",
        );
        continue;
      }
      usable.push((declared_profile, true));
    }
    let has_usable_declaration = !usable.is_empty();
    if usable.is_empty() {
      if gecko_profile_has_source(context, &canonical_root) {
        usable.push((
          mozilla::MozillaProfile {
            name: canonical_root
              .file_name()
              .map(|name| name.to_string_lossy().into_owned())
              .unwrap_or_default(),
            path: canonical_root.clone(),
            is_default: flat_root_is_default,
          },
          true,
        ));
      } else {
        match markerless_gecko_profiles(context, &canonical_root) {
          Ok(discovery) => {
            usable = discovery
              .profiles
              .into_iter()
              .map(|profile| (profile, false))
              .collect();
            if let Some(error) = discovery.optional_container_error {
              // The container is only "optional" while something else was
              // found. If it was the last place left to look and it could not
              // be read, this installation enumerated nothing and saying so at
              // warning severity would let the report claim success.
              let code = if usable.is_empty() {
                enumerated = false;
                "installation_enumeration_failed"
              } else {
                "optional_profiles_enumeration_failed"
              };
              outcome.discovery_issues.push(DiscoveryIssue::new(
                code,
                canonical_root.join("Profiles"),
                error.to_string(),
              ));
            }
          }
          Err(error) => {
            enumerated = false;
            outcome.discovery_issues.push(DiscoveryIssue::new(
              "installation_enumeration_failed",
              canonical_root.clone(),
              error.to_string(),
            ));
          }
        }
      }
    }
    if has_usable_declaration
      && !declared_persistent_source
      && context
        .fs
        .exists(&canonical_root.join(GECKO_PERSISTENT_SOURCE))
    {
      // The old Firefox path expansion appended the installation root after
      // profiles.ini declarations when none of those declarations had a
      // persistent store. Session-only profiles must not hide that fallback.
      usable.push((
        mozilla::MozillaProfile {
          name: String::new(),
          path: canonical_root.clone(),
          is_default: false,
        },
        true,
      ));
    }
    if enumerated {
      outcome.counters.installations_enumerated += 1;
    }

    for (legacy_profile_order, (declared_profile, legacy_eligible)) in
      usable.into_iter().enumerate()
    {
      let profile_path = match context.fs.canonicalize(&declared_profile.path) {
        Ok(path) => path,
        Err(error) => {
          push_bounded_discovery_issue(
            &mut outcome.discovery_issues,
            "profile_canonicalize_failed",
            declared_profile.path,
            &error.to_string(),
          );
          continue;
        }
      };
      let profile_key = normalized_path_bytes(&profile_path);
      if let Some(&existing_index) = seen_profiles.get(&profile_key) {
        let existing = &mut outcome.profiles[existing_index];
        existing.identity.is_default |= declared_profile.is_default;
        if legacy_eligible && !existing.legacy.eligible {
          existing.legacy.eligible = true;
          existing.legacy.installation_priority = root.priority;
          existing.legacy.installation_path = canonical_root.clone();
          existing.legacy.profile_order = legacy_profile_order;
          existing.legacy.is_default = declared_profile.is_default;
          existing.legacy.name.clone_from(&declared_profile.name);
        }
        push_bounded_discovery_issue(
          &mut outcome.discovery_issues,
          "duplicate_profile",
          profile_path,
          "profile is already owned by an earlier registry root",
        );
        continue;
      }
      let locator = profile_path
        .strip_prefix(&canonical_root)
        .map(ProfileLocator::Relative)
        .unwrap_or(ProfileLocator::Absolute(&profile_path));
      let legacy_is_default = declared_profile.is_default;
      let profile_id_value = profile_id(installation_id_value.as_str(), locator);
      let persistent_source_discovered = context.fs.exists(&profile_path.join("cookies.sqlite"));
      seen_profiles.insert(profile_key, outcome.profiles.len());
      outcome.profiles.push(DiscoveredProfile {
        identity: EngineProfileIdentity {
          profile_id: profile_id_value,
          installation_id: installation_id_value.clone(),
          installation_priority: root.priority,
          installation_path: canonical_root.clone(),
          name: declared_profile.name.clone(),
          path: profile_path,
          is_default: declared_profile.is_default,
          persistent_source_discovered,
        },
        legacy: LegacyRank {
          installation_priority: root.priority,
          profile_order: legacy_profile_order,
          is_default: legacy_is_default,
          eligible: legacy_eligible,
          installation_path: canonical_root.clone(),
          name: declared_profile.name,
        },
        // Gecko populate is path-driven and does not iterate candidates.
        candidates: Vec::new(),
      });
    }
  }
  sort_discovered_profiles(&mut outcome.profiles);
  Ok(outcome)
}

/// Crate-private generic Gecko report seam. It deliberately does not call the
/// legacy wrapper, so it can retain every invalid session candidate and can
/// surface a session-only profile without changing `firefox_profiles()`.
pub(super) fn gecko_report_with_context<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<&[String]>,
) -> Result<EngineExtract> {
  gecko_report_with_query(
    context,
    browser_id,
    profile_id,
    domains,
    mozilla::query_cookies_engine_outcome,
  )
}

/// The Gecko report with its cookie query injected, so a test can observe which
/// profiles were actually read rather than only which ones survived into the
/// report. Production takes the same path through
/// [`gecko_report_with_context`], so the profile selection below is the one
/// that ships.
fn gecko_report_with_query<F: DiscoveryFs, Q>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<&[String]>,
  query: Q,
) -> Result<EngineExtract>
where
  Q: FnMut(&Path, Option<&[String]>) -> mozilla::MozillaExtractionDraft,
{
  let mut listing = discover_gecko_with_context(context, browser_id)?;
  select_listing_profiles(
    &mut listing,
    browser_id,
    ProfileSelection::from_profile_id(profile_id),
  )?;
  Ok(populate_gecko_sources(listing, domains, query, |path| {
    context.fs.exists(path)
  }))
}

/// Turns a post-select [`EngineListing`] into an [`EngineExtract`] by querying
/// each profile's cookie store.
///
/// It is deliberately **path/query-based**, not candidate-driven: discovery
/// leaves `DiscoveredProfile.candidates` empty for Gecko, so iterating them the
/// way Safari/IE populate does would query nothing and emit an empty report.
/// The persistent path is derived from the profile directory and the session
/// walk lives inside the Mozilla query; both push a [`Source`] onto the profile
/// only after that query returns.
///
/// The output is 1:1 with the post-select listing: a profile whose query
/// produced nothing still appears with `sources: vec![]`, so the report layer
/// can tell a source that vanished before extraction (`profile_extraction_failed`)
/// from a browser that was never installed.
pub(super) fn populate_gecko_sources<Q, E>(
  listing: EngineListing,
  domains: Option<&[String]>,
  mut query: Q,
  mut persistent_exists: E,
) -> EngineExtract
where
  Q: FnMut(&Path, Option<&[String]>) -> mozilla::MozillaExtractionDraft,
  E: FnMut(&Path) -> bool,
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
      candidates: _,
    } = profile;
    let persistent = identity.path.join("cookies.sqlite");
    // The Mozilla outcome also owns session fallback. A missing persistent DB
    // is normal for a session-only profile and is not projected as a source.
    //
    // Discovery's snapshot goes stale in both directions, so existence is
    // rechecked after the query rather than inferred from it: a database that
    // appeared since discovery is projected even when reading it then failed,
    // and one deleted since discovery is still projected so its failure is
    // reported instead of vanishing. Inferring from the query alone would
    // silence a database that appeared and was corrupt or locked.
    let mut extraction = query(&persistent, domains);
    let stop = extraction.boundary_stop;
    // Split the session walk off so the persistent source can consume the rest
    // of the Mozilla outcome without cloning its records.
    let session_sources = std::mem::take(&mut extraction.session_sources);
    let mut sources: Vec<Source> = Vec::new();
    if extraction.persistent_attempted
      && (identity.persistent_source_discovered || persistent_exists(&persistent))
    {
      sources.push(gecko_persistent_source(persistent, extraction));
    }
    for session in session_sources {
      sources.push(gecko_session_source(session));
    }
    extract.profiles.push(ExtractedProfile {
      identity,
      legacy,
      sources,
    });
    if stop.is_some() {
      extract.boundary_stop = stop;
      break;
    }
  }
  if extract.boundary_stop.is_some() {
    retain_completed_engine_extract(&mut extract);
  }
  extract
}

/// Builds the persistent [`Source`] for a queried Gecko profile.
///
/// `selected: true` because a profile's authoritative persistent store is
/// always the selected source. Records are the only supply of finalized rows,
/// so `cookies_emitted` counts them rather than any cookie list.
fn gecko_persistent_source(path: PathBuf, extraction: mozilla::MozillaExtractionDraft) -> Source {
  let acquisition: SourceAcquisition = extraction.persistent_acquisition_strategy.into();
  let records = extraction.persistent_records;
  let cookies_emitted = records.len();
  let mut source = Source {
    origin: SourceCandidate {
      path,
      role: CookieSourceRoleId::persistent(),
      format: CookieSourceFormatId::known(mozilla::PERSISTENT_FORMAT_ID),
      precedence: PERSISTENT_SOURCE_PRECEDENCE,
      exists: true,
      selected: true,
      acquisition,
    },
    selected: true,
    acquisition,
    records,
    stats: SourceStats {
      rows_seen: extraction.persistent_rows_seen,
      cookies_emitted,
      rows_skipped: extraction.persistent_rows_skipped,
      rows_rejected: extraction.persistent_rows_rejected,
      provider_failures: 0,
    },
    acquisition_attempts: extraction.persistent_acquisition_attempts,
    // `diagnostics` carries acquisition retry notes, which a report renders as a
    // warning meaning "retried, then succeeded". A rejected row is neither a
    // retry nor a recovery — rows were lost — so it must not be reported that
    // way; `push_row_read_failed` raises it as an error-severity row failure.
    diagnostics: Vec::new(),
    failure: None,
    issues: Vec::new(),
  };
  if let Some(error) = extraction.persistent_error {
    let stage = match extraction.persistent_failure_kind {
      Some(crate::common::sqlite::BrowserDatabaseFailureKind::Query) => SourceFailureStage::Query,
      _ => SourceFailureStage::Acquisition,
    };
    source.fail(stage, error);
  }
  source.push_row_read_failed(extraction.persistent_row_error);
  source
}

/// Builds a session [`Source`] from one walked Mozilla session candidate.
///
/// A session candidate fails by being unreadable as JSON/LZ4, which is a parse
/// failure, not an acquisition one. Its rejected rows are already counted in
/// `rows_skipped` and described by `diagnostics`, so it carries no row error.
fn gecko_session_source(session: mozilla::MozillaSessionDraft) -> Source {
  let mut source = Source {
    origin: SourceCandidate {
      path: session.path,
      role: CookieSourceRoleId::session(),
      format: CookieSourceFormatId::known(session.format),
      precedence: session.precedence,
      exists: true,
      selected: session.selected,
      acquisition: SourceAcquisition::StableFileImage,
    },
    selected: session.selected,
    acquisition: SourceAcquisition::StableFileImage,
    records: session.records,
    stats: SourceStats {
      rows_seen: session.rows_seen,
      cookies_emitted: 0,
      rows_skipped: session.rows_skipped,
      rows_rejected: session.rows_rejected,
      provider_failures: 0,
    },
    acquisition_attempts: session.acquisition_attempts,
    diagnostics: session.diagnostics,
    failure: None,
    issues: Vec::new(),
  };
  source.stats.cookies_emitted = source.records.len();
  // A session candidate never keeps a row error, but rows it rejected still
  // cost cookies. The issue is keyed on the count, not on the presence of an
  // error string: raising it only when an engine happened to keep one lets a
  // report claim `complete` while cookies were dropped.
  source.push_row_read_failed(None);
  if let Some(error) = session.error {
    source.fail(SourceFailureStage::Parse, error);
  }
  source
}

fn gecko_report(
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<Vec<String>>,
) -> Result<EngineExtract> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  gecko_report_with_runtime(browser_id, profile_id, domains, &runtime)
}

pub(crate) fn gecko_report_with_runtime(
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<Vec<String>>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<EngineExtract> {
  runtime.check()?;
  let context = DiscoveryContext::system()?;
  runtime.check()?;
  let extract = gecko_report_with_query(
    &context,
    browser_id,
    profile_id,
    domains.as_deref(),
    |path, domains| mozilla::query_cookies_engine_outcome_with_runtime(path, domains, runtime),
  )?;
  Ok(retain_gecko_runtime_stop(extract, runtime))
}

fn retain_gecko_runtime_stop(
  mut extract: EngineExtract,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> EngineExtract {
  if let Err(stop) = runtime.check() {
    extract.boundary_stop.get_or_insert(stop);
  }
  if extract.boundary_stop.is_some() {
    retain_completed_engine_extract(&mut extract);
  }
  extract
}

fn sort_legacy_gecko_profiles(listing: &mut EngineListing) {
  // Generic Gecko reports remain display-name sorted. The compatibility
  // selector instead uses the default profile when it has cookies.sqlite,
  // then falls back in profiles.ini declaration order within each root.
  listing
    .profiles
    .retain(|profile| profile.legacy.eligible && profile.identity.persistent_source_discovered);
  listing.profiles.sort_by(|left, right| {
    left
      .legacy
      .installation_priority
      .cmp(&right.legacy.installation_priority)
      .then_with(|| {
        normalized_path_bytes(&left.legacy.installation_path)
          .cmp(&normalized_path_bytes(&right.legacy.installation_path))
      })
      .then_with(|| (!left.legacy.is_default).cmp(&(!right.legacy.is_default)))
      .then_with(|| left.legacy.profile_order.cmp(&right.legacy.profile_order))
      .then_with(|| {
        normalized_path_bytes(&left.identity.path).cmp(&normalized_path_bytes(&right.identity.path))
      })
  });
}

fn select_legacy_gecko_profile(listing: &mut EngineListing) {
  sort_legacy_gecko_profiles(listing);
  listing.profiles.truncate(1);
}

/// Extracts the first persistent Gecko profile through the authoritative
/// discovery engine. Session-only profiles remain available to reports but do
/// not silently change the historical named-API contract.
fn legacy_gecko_outcome(browser_id: &str, domains: Option<Vec<String>>) -> Result<EngineExtract> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  legacy_gecko_outcome_with_runtime(browser_id, domains, &runtime)
}

pub(crate) fn legacy_gecko_outcome_with_runtime(
  browser_id: &str,
  domains: Option<Vec<String>>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<EngineExtract> {
  runtime.check()?;
  let context = DiscoveryContext::system()?;
  runtime.check()?;
  let mut listing = discover_gecko_with_context(&context, browser_id)?;
  select_legacy_gecko_profile(&mut listing);
  let extract = populate_gecko_sources(
    listing,
    domains.as_deref(),
    |path, domains| mozilla::query_cookies_engine_outcome_with_runtime(path, domains, runtime),
    |path| context.fs.exists(path),
  );
  Ok(retain_gecko_runtime_stop(extract, runtime))
}

/// Lists persistent Gecko profiles in the same deterministic registry order
/// used by the compatibility selector.
fn legacy_gecko_profiles(browser_id: &str) -> Result<EngineListing> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  legacy_gecko_profiles_with_runtime(browser_id, &runtime)
}

pub(crate) fn legacy_gecko_profiles_with_runtime(
  browser_id: &str,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<EngineListing> {
  runtime.check()?;
  let context = DiscoveryContext::system()?;
  runtime.check()?;
  let mut listing = discover_gecko_with_context(&context, browser_id)?;
  runtime.check()?;
  sort_legacy_gecko_profiles(&mut listing);
  runtime.check()?;
  Ok(listing)
}

#[cfg(test)]
mod tests {
  use super::super::test_seams::{
    browser_root, context_for, current_context, gecko_test_root, seed_empty_gecko_database,
    with_test_fs, TempDir, TestDiscoveryFs,
  };
  use super::*;

  #[test]
  fn gecko_profiles_are_default_first_then_name_and_path() {
    let temp = TempDir::new("gecko-order");
    let context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    for directory in ["z-default", "b-secondary", "a-secondary"] {
      seed_empty_gecko_database(&root.join("Profiles").join(directory));
    }
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=Zulu\nPath=Profiles/z-default\nDefault=1\n\
       [Profile1]\nName=beta\nPath=Profiles/b-secondary\n\
       [Profile2]\nName=Alpha\nPath=Profiles/a-secondary\n",
    )
    .expect("write profiles.ini");

    let report = discover_gecko_with_context(&context, "firefox").expect("discover profiles");
    assert_eq!(
      report
        .profiles
        .iter()
        .map(|profile| profile.identity.name.as_str())
        .collect::<Vec<_>>(),
      ["Zulu", "Alpha", "beta"]
    );
    assert!(report.profiles[0].identity.is_default);
  }

  #[test]
  fn linux_gecko_profiles_preserve_snap_native_flatpak_installation_priority() {
    let temp = TempDir::new("gecko-installation-order");
    let context = context_for(PlatformId::Linux, temp.path().to_path_buf(), []);
    let registry = embedded_registry().expect("registry");
    let definition = browser_definition(registry, PlatformId::Linux, "firefox").expect("Firefox");
    let names = [
      ("firefox-snap", "Zulu"),
      ("firefox-native", "Alpha"),
      ("firefox-flatpak", "Beta"),
    ];
    let mut expected = Vec::new();
    for (root_id, name) in names {
      let root = definition
        .roots
        .iter()
        .find(|root| root.root_id == root_id)
        .expect("Firefox registry root");
      let resolved = context.resolve_template(&root.template).expect("root path");
      let root_path = resolved.base.join(resolved.suffix);
      seed_empty_gecko_database(&root_path.join("Profiles/profile"));
      std::fs::write(
        root_path.join("profiles.ini"),
        format!("[Profile0]\nName={name}\nPath=Profiles/profile\nDefault=1\n"),
      )
      .expect("write profiles.ini");
      expected.push((root.priority, name));
    }

    let report = discover_gecko_with_context(&context, "firefox").expect("discover Firefox");
    assert_eq!(
      report
        .profiles
        .iter()
        .map(|profile| (
          profile.identity.installation_priority,
          profile.identity.name.as_str()
        ))
        .collect::<Vec<_>>(),
      expected
    );
  }

  #[test]
  fn gecko_unusable_declarations_fall_back_to_flat_or_markerless_sources() {
    let temp = TempDir::new("gecko-fallbacks");
    let context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    std::fs::create_dir_all(root.join("Profiles/stale")).expect("create stale declaration");
    seed_empty_gecko_database(&root);
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=stale\nPath=Profiles/stale\nDefault=1\n",
    )
    .expect("write profiles.ini");

    let flat = discover_gecko_with_context(&context, "firefox").expect("discover flat fallback");
    assert_eq!(flat.profiles.len(), 1);
    assert_eq!(flat.profiles[0].identity.path, root.canonicalize().unwrap());
    assert!(
      !flat.profiles[0].identity.is_default,
      "a stale declaration cannot transfer its default flag"
    );
    assert!(flat
      .discovery_issues
      .iter()
      .any(|issue| issue.code == "profile_has_no_cookie_source"));

    std::fs::remove_file(root.join("cookies.sqlite")).expect("remove flat source");
    seed_empty_gecko_database(&root.join("Profiles/Restored One"));
    seed_empty_gecko_database(&root.join("Restored Two"));
    let markerless =
      discover_gecko_with_context(&context, "firefox").expect("discover markerless fallbacks");
    assert_eq!(
      markerless
        .profiles
        .iter()
        .map(|profile| profile.identity.name.as_str())
        .collect::<Vec<_>>(),
      ["Restored One", "Restored Two"]
    );
    assert!(markerless
      .profiles
      .iter()
      .all(|profile| !profile.identity.is_default));
  }

  #[test]
  fn markerless_gecko_profiles_remain_generic_only() {
    let temp = TempDir::new("gecko-markerless-legacy");
    let context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    let markerless = root.join("Profiles/work");
    seed_empty_gecko_database(&markerless);

    let generic = discover_gecko_with_context(&context, "firefox")
      .expect("generic discovery retains markerless recovery");
    assert_eq!(generic.profiles.len(), 1);
    assert_eq!(
      generic.profiles[0].identity.path,
      markerless.canonicalize().unwrap()
    );
    assert!(!generic.profiles[0].legacy.eligible);

    let mut legacy = discover_gecko_with_context(&context, "firefox")
      .expect("legacy discovery completes as ordinary absence");
    sort_legacy_gecko_profiles(&mut legacy);
    assert!(legacy.profiles.is_empty());
    assert!(legacy.discovery_issues.is_empty());
  }

  #[test]
  fn invalid_gecko_profiles_ini_is_not_hidden_by_markerless_recovery() {
    let temp = TempDir::new("gecko-invalid-ini-markerless");
    let context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    seed_empty_gecko_database(&root.join("Profiles/work"));
    std::fs::write(root.join("profiles.ini"), "[Profile0\nPath=broken")
      .expect("write invalid profiles.ini");

    let mut outcome = discover_gecko_with_context(&context, "firefox")
      .expect("generic discovery retains markerless recovery and the ini error");
    assert_eq!(outcome.profiles.len(), 1);
    assert!(outcome
      .discovery_issues
      .iter()
      .any(|issue| issue.code == "mozilla_profiles_ini_invalid"));
    sort_legacy_gecko_profiles(&mut outcome);
    assert!(outcome.profiles.is_empty());
    assert!(outcome
      .discovery_issues
      .iter()
      .any(|issue| issue.code == "mozilla_profiles_ini_invalid"));
  }

  #[test]
  fn invalid_profiles_ini_does_not_mark_flat_fallback_default() {
    let temp = TempDir::new("gecko-invalid-ini-flat");
    let context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    seed_empty_gecko_database(&root);
    std::fs::write(root.join("profiles.ini"), "[Profile0\nPath=broken").expect("write invalid ini");

    let report = discover_gecko_with_context(&context, "firefox").expect("discover flat fallback");
    assert_eq!(report.profiles.len(), 1);
    assert!(!report.profiles[0].identity.is_default);
    assert!(report
      .discovery_issues
      .iter()
      .any(|issue| issue.code == "mozilla_profiles_ini_invalid"));
  }

  #[test]
  fn session_only_gecko_declaration_keeps_flat_persistent_fallback() {
    let temp = TempDir::new("gecko-session-plus-flat");
    let context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    let session_profile = root.join("Profiles/session-only");
    std::fs::create_dir_all(&session_profile).expect("create session-only profile");
    std::fs::write(session_profile.join("sessionstore.js"), r#"{"windows":[]}"#)
      .expect("seed session store");
    seed_empty_gecko_database(&root);
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=Session only\nPath=Profiles/session-only\nDefault=1\n",
    )
    .expect("write profiles.ini");

    let report = discover_gecko_with_context(&context, "firefox").expect("discover profiles");
    assert_eq!(report.profiles.len(), 2);
    assert!(report.profiles.iter().any(|profile| profile.identity.path
      == root.canonicalize().unwrap()
      && profile.identity.persistent_source_discovered
      && !profile.identity.is_default));

    let mut legacy = report;
    sort_legacy_gecko_profiles(&mut legacy);
    assert_eq!(legacy.profiles.len(), 1);
    assert_eq!(
      legacy.profiles[0].identity.path,
      root.canonicalize().unwrap()
    );
  }

  #[test]
  fn duplicate_gecko_profile_issues_are_emitted_and_bounded() {
    let temp = TempDir::new("gecko-duplicate-bound");
    let context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    seed_empty_gecko_database(&root.join("Profiles/shared"));
    let ini = (0..MAX_DISCOVERY_ISSUE_SAMPLES + 5)
      .map(|index| format!("[Profile{index}]\nName=duplicate-{index}\nPath=Profiles/shared\n"))
      .collect::<String>();
    std::fs::write(root.join("profiles.ini"), ini).expect("write duplicate declarations");

    let report = discover_gecko_with_context(&context, "firefox").expect("discover duplicates");
    assert_eq!(report.profiles.len(), 1);
    let duplicates = report
      .discovery_issues
      .iter()
      .filter(|issue| issue.code == "duplicate_profile")
      .collect::<Vec<_>>();
    // One declaration owns the profile; every later one is a bounded duplicate,
    // and the unsampled remainder survives as a typed count rather than a
    // number formatted into the message.
    assert_eq!(duplicates.len(), MAX_DISCOVERY_ISSUE_SAMPLES);
    assert_eq!(
      duplicates
        .iter()
        .map(|issue| issue.occurrences)
        .sum::<u32>(),
      MAX_DISCOVERY_ISSUE_SAMPLES as u32 + 4
    );
    assert!(duplicates
      .iter()
      .all(|issue| !issue.message.contains("additional")));
  }

  #[test]
  fn duplicate_gecko_profiles_merge_default_without_changing_legacy_rank() {
    let temp = TempDir::new("gecko-duplicate-default");
    let context = context_for(PlatformId::Linux, temp.path().join("home"), []);
    let snap = browser_root(&context, "firefox", "firefox-snap");
    let native = browser_root(&context, "firefox", "firefox-native");
    let shared = temp.path().join("shared-profile");
    seed_empty_gecko_database(&shared);
    seed_empty_gecko_database(&snap.join("Profiles/original-default"));
    std::fs::create_dir_all(&native).expect("create native root");
    std::fs::write(
      snap.join("profiles.ini"),
      format!(
        "[Profile0]\nName=Shared\nIsRelative=0\nPath={}\n\
         [Profile1]\nName=Original default\nPath=Profiles/original-default\nDefault=1\n",
        shared.display()
      ),
    )
    .expect("write snap profiles.ini");
    std::fs::write(
      native.join("profiles.ini"),
      format!(
        "[Profile0]\nName=Shared duplicate\nIsRelative=0\nPath={}\nDefault=1\n",
        shared.display()
      ),
    )
    .expect("write native profiles.ini");

    let mut report = discover_gecko_with_context(&context, "firefox").expect("discover profiles");
    let shared_profile = report
      .profiles
      .iter()
      .find(|profile| profile.identity.path == shared.canonicalize().unwrap())
      .expect("deduplicated shared profile");
    assert!(
      shared_profile.identity.is_default,
      "later default flag is merged"
    );
    assert!(report
      .discovery_issues
      .iter()
      .any(|issue| issue.code == "duplicate_profile"));

    sort_legacy_gecko_profiles(&mut report);
    assert_eq!(report.profiles[0].identity.name, "Original default");
  }

  #[test]
  fn declared_duplicate_promotes_markerless_profile_with_declaration_legacy_rank() {
    let temp = TempDir::new("gecko-markerless-duplicate-promotion");
    let context = context_for(PlatformId::Linux, temp.path().join("home"), []);
    let snap = browser_root(&context, "firefox", "firefox-snap");
    let native = browser_root(&context, "firefox", "firefox-native");
    let shared = snap.join("Profiles/work");
    seed_empty_gecko_database(&shared);
    std::fs::create_dir_all(&native).expect("create native root");
    std::fs::write(
      native.join("profiles.ini"),
      format!(
        "[Profile0]\nName=Declared\nIsRelative=0\nPath={}\nDefault=1\n",
        shared.display()
      ),
    )
    .expect("write native profiles.ini");

    let registry = embedded_registry().expect("registry");
    let firefox = browser_definition(registry, PlatformId::Linux, "firefox").expect("Firefox");
    let snap_priority = firefox
      .roots
      .iter()
      .find(|root| root.root_id == "firefox-snap")
      .expect("Snap root")
      .priority;
    let native_priority = firefox
      .roots
      .iter()
      .find(|root| root.root_id == "firefox-native")
      .expect("native root")
      .priority;

    let report = discover_gecko_with_context(&context, "firefox").expect("discover duplicate");
    assert_eq!(report.profiles.len(), 1);
    let profile = &report.profiles[0];
    assert_eq!(
      profile.identity.installation_priority, snap_priority,
      "generic ownership remains with the first markerless admission"
    );
    assert!(profile.legacy.eligible);
    assert_eq!(profile.legacy.installation_priority, native_priority);
    assert_eq!(profile.legacy.profile_order, 0);
    assert!(profile.legacy.is_default);
    assert_eq!(profile.legacy.name, "Declared");
    assert_eq!(
      profile.legacy.installation_path,
      native.canonicalize().expect("canonical native root")
    );
  }

  #[test]
  fn missing_source_gecko_issues_are_bounded_with_a_typed_occurrence_count() {
    let temp = TempDir::new("gecko-missing-source-bound");
    let context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    std::fs::create_dir_all(&root).expect("create Firefox root");
    let ini = (0..MAX_DISCOVERY_ISSUE_SAMPLES + 5)
      .map(|index| format!("[Profile{index}]\nName=stale-{index}\nPath=Profiles/stale-{index}\n"))
      .collect::<String>();
    std::fs::write(root.join("profiles.ini"), ini).expect("write stale declarations");

    let report = discover_gecko_with_context(&context, "firefox").expect("discover stale profiles");
    let issues = report
      .discovery_issues
      .iter()
      .filter(|issue| issue.code == "profile_has_no_cookie_source")
      .collect::<Vec<_>>();
    assert_eq!(issues.len(), MAX_DISCOVERY_ISSUE_SAMPLES);
    assert_eq!(
      issues.iter().map(|issue| issue.occurrences).sum::<u32>(),
      MAX_DISCOVERY_ISSUE_SAMPLES as u32 + 5
    );
    // Sampled paths keep one occurrence each; only the first carries the
    // remainder, so no sample misrepresents its own path.
    assert_eq!(issues[0].occurrences, 6);
    assert!(issues[1..].iter().all(|issue| issue.occurrences == 1));
  }

  #[test]
  fn markerless_fallback_keeps_direct_profiles_when_profiles_container_is_unreadable() {
    let temp = TempDir::new("gecko-markerless-partial-enumeration");
    let real_context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&real_context);
    seed_empty_gecko_database(&root.join("Restored Direct"));
    std::fs::create_dir_all(root.join("Profiles")).expect("create Profiles container");
    let profiles_container = root
      .canonicalize()
      .expect("canonical installation root")
      .join("Profiles");
    let context = with_test_fs(
      real_context,
      TestDiscoveryFs {
        denied_read_dir: Some(profiles_container.clone()),
        ..TestDiscoveryFs::default()
      },
    );

    let report = discover_gecko_with_context(&context, "firefox").expect("partial discovery");
    assert_eq!(report.profiles.len(), 1);
    assert_eq!(report.profiles[0].identity.name, "Restored Direct");
    assert!(report.discovery_issues.iter().any(|issue| {
      issue.code == "optional_profiles_enumeration_failed" && issue.path == profiles_container
    }));
  }

  #[test]
  fn gecko_root_whose_enumeration_fails_is_a_failure_not_an_empty_installation() {
    let temp = TempDir::new("gecko-total-enumeration-failure");
    let real_context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&real_context);
    std::fs::create_dir_all(&root).expect("create Firefox root");
    let canonical_root = root.canonicalize().expect("canonical installation root");
    let context = with_test_fs(
      real_context,
      TestDiscoveryFs {
        denied_read_dir: Some(canonical_root.clone()),
        ..TestDiscoveryFs::default()
      },
    );

    let report = discover_gecko_with_context(&context, "firefox").expect("discovery completes");
    assert!(report.profiles.is_empty());
    assert!(report
      .discovery_issues
      .iter()
      .any(|issue| issue.code == "installation_enumeration_failed"));
    // Without this the caller cannot tell "Firefox is not installed" from
    // "Firefox is installed and we could not read it".
    assert!(report.all_detected_roots_failed());
  }

  #[test]
  fn gecko_root_that_enumerates_nothing_is_not_a_discovery_failure() {
    let temp = TempDir::new("gecko-empty-root");
    let context = current_context(temp.path().to_path_buf());
    std::fs::create_dir_all(gecko_test_root(&context)).expect("create Firefox root");

    let report = discover_gecko_with_context(&context, "firefox").expect("discovery completes");
    assert!(report.profiles.is_empty());
    assert!(!report.all_detected_roots_failed());
  }

  #[cfg(unix)]
  #[test]
  fn gecko_roots_resolving_to_one_directory_report_a_single_duplicate_installation() {
    let temp = TempDir::new("gecko-duplicate-installation");
    let context = context_for(PlatformId::Linux, temp.path().to_path_buf(), []);
    let registry = embedded_registry().expect("registry");
    let definition = browser_definition(registry, PlatformId::Linux, "firefox").expect("Firefox");
    let root_path = |root_id: &str| {
      let root = definition
        .roots
        .iter()
        .find(|root| root.root_id == root_id)
        .expect("Firefox registry root");
      let resolved = context.resolve_template(&root.template).expect("root path");
      resolved.base.join(resolved.suffix)
    };

    let native = root_path("firefox-native");
    seed_empty_gecko_database(&native.join("Profiles/profile"));
    std::fs::write(
      native.join("profiles.ini"),
      "[Profile0]\nName=Shared\nPath=Profiles/profile\nDefault=1\n",
    )
    .expect("write profiles.ini");
    let snap = root_path("firefox-snap");
    std::fs::create_dir_all(snap.parent().expect("snap parent")).expect("create snap parent");
    std::os::unix::fs::symlink(&native, &snap).expect("alias the snap root onto the native one");

    let report = discover_gecko_with_context(&context, "firefox").expect("discover Firefox");
    assert_eq!(report.profiles.len(), 1);
    assert_eq!(report.counters.installations_discovered, 1);
    // The aliased root is one clear signal, not a second installation whose
    // every profile then looks like a duplicate.
    assert_eq!(
      report
        .discovery_issues
        .iter()
        .filter(|issue| issue.code == "duplicate_installation")
        .count(),
      1
    );
    assert!(!report
      .discovery_issues
      .iter()
      .any(|issue| issue.code == "duplicate_profile"));
  }

  #[test]
  fn undiscovered_persistent_source_is_projected_if_it_appears_before_query() {
    let temp = TempDir::new("gecko-persistent-appears");
    let context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    let profile = root.join("Profiles/default");
    // A session-only profile at discovery time: no cookies.sqlite yet.
    std::fs::create_dir_all(profile.join("sessionstore-backups")).expect("create profile");
    std::fs::write(profile.join("sessionstore.js"), "{}").expect("seed session candidate");
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=default\nPath=Profiles/default\nDefault=1\n",
    )
    .expect("write profiles.ini");
    let discovery = discover_gecko_with_context(&context, "firefox").expect("discover profile");
    assert!(!discovery.profiles[0].identity.persistent_source_discovered);

    let mut created = false;
    let report = populate_gecko_sources(
      discovery,
      None,
      |persistent, domains| {
        if !created {
          created = true;
          seed_empty_gecko_database(persistent.parent().expect("profile directory"));
        }
        mozilla::query_cookies_engine_outcome(persistent, domains)
      },
      |path| path.exists(),
    );
    let persistent = report.profiles[0]
      .sources
      .iter()
      .find(|source| source.origin.role == CookieSourceRoleId::persistent())
      .expect("persistent source created between discovery and query");
    assert_eq!(persistent.origin.format.as_str(), "mozilla_sqlite");
    assert!(persistent.selected);
    assert!(persistent.failure.is_none());
  }

  #[test]
  fn a_corrupt_database_appearing_before_query_is_reported_not_silently_dropped() {
    let temp = TempDir::new("gecko-persistent-appears-corrupt");
    let context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    let profile = root.join("Profiles/default");
    std::fs::create_dir_all(&profile).expect("create profile");
    std::fs::write(profile.join("sessionstore.js"), "{}").expect("seed session candidate");
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=default\nPath=Profiles/default\nDefault=1\n",
    )
    .expect("write profiles.ini");
    let discovery = discover_gecko_with_context(&context, "firefox").expect("discover profile");
    assert!(!discovery.profiles[0].identity.persistent_source_discovered);

    // Appears between discovery and query, but unreadable. Inferring existence
    // from query success alone would drop this failure entirely.
    let mut created = false;
    let report = populate_gecko_sources(
      discovery,
      None,
      |persistent, domains| {
        if !created {
          created = true;
          std::fs::write(persistent, b"not a sqlite database").expect("seed corrupt database");
        }
        mozilla::query_cookies_engine_outcome(persistent, domains)
      },
      |path| path.exists(),
    );
    let persistent = report.profiles[0]
      .sources
      .iter()
      .find(|source| source.origin.role == CookieSourceRoleId::persistent())
      .expect("corrupt persistent source is still reported");
    assert!(persistent.selected);
    assert!(persistent.failure.is_some());
  }

  #[test]
  fn session_only_profile_still_projects_no_persistent_source() {
    let temp = TempDir::new("gecko-session-only-no-persistent");
    let context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    let profile = root.join("Profiles/default");
    std::fs::create_dir_all(&profile).expect("create profile");
    std::fs::write(profile.join("sessionstore.js"), "{}").expect("seed session candidate");
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=default\nPath=Profiles/default\nDefault=1\n",
    )
    .expect("write profiles.ini");

    let discovery = discover_gecko_with_context(&context, "firefox").expect("discover profile");
    let report = populate_gecko_sources(
      discovery,
      None,
      mozilla::query_cookies_engine_outcome,
      |path| path.exists(),
    );
    assert!(!report.profiles[0]
      .sources
      .iter()
      .any(|source| source.origin.role == CookieSourceRoleId::persistent()));
  }

  #[test]
  fn discovered_persistent_source_remains_projected_if_it_disappears_before_query() {
    let temp = TempDir::new("gecko-persistent-disappears");
    let context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    let profile = root.join("Profiles/default");
    seed_empty_gecko_database(&profile);
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=default\nPath=Profiles/default\nDefault=1\n",
    )
    .expect("write profiles.ini");
    let discovery = discover_gecko_with_context(&context, "firefox").expect("discover profile");
    assert!(discovery.profiles[0].identity.persistent_source_discovered);

    let mut removed = false;
    let report = populate_gecko_sources(
      discovery,
      None,
      |persistent, domains| {
        if !removed {
          removed = true;
          std::fs::remove_file(persistent).expect("remove discovered source");
        }
        mozilla::query_cookies_engine_outcome(persistent, domains)
      },
      |path| path.exists(),
    );
    assert_eq!(report.profiles[0].sources.len(), 1);
    let source = &report.profiles[0].sources[0];
    assert_eq!(source.origin.format.as_str(), "mozilla_sqlite");
    assert!(source.selected);
    assert!(source
      .failure
      .as_ref()
      .is_some_and(|failure| failure.message.contains("Can't resolve database path")));
  }

  /// The admission gate (`gecko_profile_has_source`) guarantees a session-only
  /// profile had a session candidate on disk at discovery time. If that
  /// candidate is gone by query time, this layer intentionally leaves the
  /// profile with zero sources rather than fabricating one for a file that no
  /// longer exists - see `mozilla::a_candidate_that_vanishes_after_a_transient_failure_stays_silent`.
  /// Distinguishing "vanished" from "never existed" is therefore left to the
  /// report layer, which can see the whole profile rather than one candidate;
  /// `report_build::a_gecko_session_candidate_that_vanishes_before_query_is_failed_not_absent`
  /// pins that it does so correctly.
  #[test]
  fn session_only_profile_whose_candidate_vanishes_before_query_has_no_sources_at_this_layer() {
    let temp = TempDir::new("gecko-session-vanishes");
    let context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    let profile = root.join("Profiles/session-only");
    std::fs::create_dir_all(profile.join("sessionstore-backups")).expect("create profile");
    let session_file = profile.join("sessionstore-backups/recovery.jsonlz4");
    std::fs::write(&session_file, b"discoverable but will vanish before query")
      .expect("write session candidate");
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=session\nPath=Profiles/session-only\nDefault=1\n",
    )
    .expect("write profiles.ini");

    let discovery = discover_gecko_with_context(&context, "firefox").expect("discover profile");
    assert_eq!(
      discovery.profiles.len(),
      1,
      "profile admitted as session-only"
    );
    assert!(!discovery.profiles[0].identity.persistent_source_discovered);

    let report = populate_gecko_sources(
      discovery,
      None,
      |persistent, domains| {
        // The persistent DB never existed; the race is on the session file,
        // which we remove right before the engine would read it.
        let _ = std::fs::remove_file(&session_file);
        mozilla::query_cookies_engine_outcome(persistent, domains)
      },
      |path| path.exists(),
    );

    assert_eq!(report.profiles.len(), 1);
    assert!(report.profiles[0].sources.is_empty());
  }

  #[test]
  fn generic_gecko_discovery_includes_session_only_profiles() {
    let temp = TempDir::new("gecko-session-only");
    let platform = PlatformId::current().expect("platform");
    let context = current_context(temp.path().to_path_buf());
    let registry = embedded_registry().expect("registry");
    let definition = browser_definition(registry, platform, "firefox").expect("Firefox");
    let root = definition
      .roots
      .iter()
      .find(|root| root.root_id.contains("native") || root.root_id == "firefox")
      .unwrap_or(&definition.roots[0]);
    let resolved = context.resolve_template(&root.template).expect("root path");
    let root_path = resolved.base.join(resolved.suffix);
    let profile = root_path.join("Profiles/session-only");
    std::fs::create_dir_all(profile.join("sessionstore-backups")).expect("create profile");
    std::fs::write(
      root_path.join("profiles.ini"),
      "[Profile0]\nName=session\nIsRelative=1\nPath=Profiles/session-only\nDefault=1\n",
    )
    .expect("write profiles.ini");
    std::fs::write(
      profile.join("sessionstore-backups/recovery.jsonlz4"),
      b"invalid is still a discoverable source",
    )
    .expect("write session candidate");

    let report = discover_gecko_with_context(&context, "firefox").expect("discover Gecko");
    assert_eq!(report.profiles.len(), 1);
    assert_eq!(
      report.profiles[0].identity.path,
      profile.canonicalize().expect("canonical profile")
    );
    assert!(report.profiles[0].identity.is_default);
  }

  #[test]
  fn generic_gecko_report_preserves_persistent_and_session_source_outcomes() {
    let temp = TempDir::new("gecko-report-sources");
    let platform = PlatformId::current().expect("platform");
    let context = current_context(temp.path().to_path_buf());
    let registry = embedded_registry().expect("registry");
    let definition = browser_definition(registry, platform, "firefox").expect("Firefox");
    let root = definition
      .roots
      .iter()
      .find(|root| root.root_id.contains("native") || root.root_id == "firefox")
      .unwrap_or(&definition.roots[0]);
    let resolved = context.resolve_template(&root.template).expect("root path");
    let root_path = resolved.base.join(resolved.suffix);
    let profile = root_path.join("Profiles/default");
    std::fs::create_dir_all(profile.join("sessionstore-backups")).expect("create profile");
    std::fs::write(
      root_path.join("profiles.ini"),
      "[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/default\nDefault=1\n",
    )
    .expect("write profiles.ini");
    let db_path = profile.join("cookies.sqlite");
    let connection = rusqlite::Connection::open(&db_path).expect("open fixture database");
    connection
      .execute_batch(
        "CREATE TABLE moz_cookies (
           host TEXT, path TEXT, isSecure INTEGER, expiry INTEGER,
           name TEXT, value TEXT, isHttpOnly INTEGER, sameSite INTEGER
         );
         INSERT INTO moz_cookies VALUES ('.z.example.com', '/', 1, 0, 'persistent-z', 'value', 1, 0);
         INSERT INTO moz_cookies VALUES ('.a.example.com', '/', 1, 0, 'persistent-a', 'value', 1, 0);",
      )
      .expect("seed fixture database");
    drop(connection);
    std::fs::write(
      profile.join("sessionstore-backups/recovery.jsonlz4"),
      b"invalid session store",
    )
    .expect("write invalid session candidate");
    std::fs::write(
      profile.join("sessionstore.js"),
      r#"{"windows":[{"cookies":[{"host":".z.example.com","path":"/","name":"session-z","value":"value"},{"host":".a.example.com","path":"/","name":"session-a","value":"value"},{"host":".example.com","path":"/","name":"missing-value"}]}]}"#,
    )
    .expect("write valid session candidate");

    let report = gecko_report_with_context(&context, "firefox", None, None).expect("report");
    assert!(report.discovery_issues.is_empty());
    assert_eq!(report.profiles.len(), 1);
    let sources = &report.profiles[0].sources;
    assert_eq!(sources.len(), 3);
    assert_eq!(sources[0].origin.format.as_str(), "mozilla_sqlite");
    assert_eq!(sources[0].stats.rows_seen, 2);
    assert_eq!(
      sources[0].acquisition,
      SourceAcquisition::Database(DatabaseAcquisitionStrategy::LiveReadOnly)
    );
    assert_eq!(sources[0].acquisition_attempts, 1);
    // `Source` has no cookies field; records are projected on demand, in query
    // order, so sort them for a deterministic name assertion (the wire report
    // imposes its own order downstream).
    let mut persistent_cookies = sources[0].cookies();
    sort_cookies(&mut persistent_cookies);
    assert_eq!(persistent_cookies[0].name, "persistent-a");
    assert_eq!(persistent_cookies[1].name, "persistent-z");
    assert_eq!(sources[1].origin.format.as_str(), "firefox_session_jsonlz4");
    assert!(!sources[1].selected);
    assert!(sources[1].failure.is_some());
    assert_eq!(sources[2].origin.format.as_str(), "firefox_session_json");
    assert!(sources[2].selected);
    assert_eq!(sources[2].stats.rows_seen, 3);
    assert_eq!(sources[2].stats.rows_skipped, 1);
    assert_eq!(sources[2].diagnostics.len(), 1);
    let mut session_cookies = sources[2].cookies();
    sort_cookies(&mut session_cookies);
    assert_eq!(session_cookies[0].name, "session-a");
    assert_eq!(session_cookies[1].name, "session-z");
  }

  /// A profile-selected report must not read the profiles it was not asked
  /// for. The non-Chromium engines used to extract every profile and drop the
  /// unwanted ones from the finished report, which decrypts and materializes
  /// cookies outside the request. Absence from the report cannot tell that
  /// apart from work that never happened, so these three tests count the
  /// cookie-store reads instead.
  #[test]
  fn a_profile_selected_gecko_report_reads_only_the_selected_profile() {
    let temp = TempDir::new("gecko-profile-selection");
    let context = current_context(temp.path().to_path_buf());
    let root = test_seams::primary_root_path(&context, "firefox");
    test_seams::seed_gecko_profile(&root.join("Profiles/default"));
    test_seams::seed_gecko_profile(&root.join("Profiles/other"));
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/default\nDefault=1\n\
       [Profile1]\nName=other\nIsRelative=1\nPath=Profiles/other\n",
    )
    .expect("write profiles.ini");

    let all = gecko_report_with_context(&context, "firefox", None, None).expect("full report");
    assert_eq!(all.profiles.len(), 2);
    // Deliberately not the first profile: reading only the first one would
    // otherwise pass for the wrong reason.
    let selected = all.profiles[1].identity.profile_id.clone();
    let selected_source = all.profiles[1].identity.path.join(GECKO_PERSISTENT_SOURCE);

    let mut read = Vec::new();
    let one = gecko_report_with_query(
      &context,
      "firefox",
      Some(selected.as_str()),
      None,
      |path, domains| {
        read.push(path.to_path_buf());
        mozilla::query_cookies_engine_outcome(path, domains)
      },
    )
    .expect("profile-selected report");

    assert_eq!(read, vec![selected_source]);
    assert_eq!(one.profiles.len(), 1);
    assert_eq!(one.profiles[0].identity.profile_id, selected);
    // Discovery still ran across every installation, so the counters a
    // profile-selected report publishes are unchanged.
    assert_eq!(
      one.counters.installations_discovered,
      all.counters.installations_discovered
    );

    let unknown = gecko_report_with_context(&context, "firefox", Some("not-a-profile"), None)
      .expect_err("an unknown profile id is a request error");
    assert!(unknown.to_string().contains("unknown firefox profile id"));
  }

  #[test]
  fn legacy_gecko_policy_reads_only_the_first_persistent_profile() {
    let temp = TempDir::new("gecko-legacy-first");
    let context = current_context(temp.path().to_path_buf());
    let root = test_seams::primary_root_path(&context, "firefox");
    test_seams::seed_gecko_profile(&root.join("Profiles/default"));
    test_seams::seed_gecko_profile(&root.join("Profiles/other"));
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=other\nIsRelative=1\nPath=Profiles/other\n\
       [Profile1]\nName=default\nIsRelative=1\nPath=Profiles/default\nDefault=1\n",
    )
    .expect("write profiles.ini");

    let mut outcome = discover_gecko_with_context(&context, "firefox").expect("discover");
    select_listing_profiles(
      &mut outcome,
      "firefox",
      ProfileSelection::LegacyFirstProfile,
    )
    .expect("select first");
    assert_eq!(outcome.profiles.len(), 1);
    assert_eq!(outcome.profiles[0].identity.name, "default");
    let selected_source = outcome.profiles[0]
      .identity
      .path
      .join(GECKO_PERSISTENT_SOURCE);

    let mut read = Vec::new();
    let outcome = populate_gecko_sources(
      outcome,
      None,
      |path, domains| {
        read.push(path.to_path_buf());
        mozilla::query_cookies_engine_outcome(path, domains)
      },
      |path| context.fs.exists(path),
    );
    assert_eq!(read, [selected_source]);
    assert_eq!(outcome.profiles.len(), 1);
  }

  #[test]
  fn legacy_gecko_fallback_preserves_profiles_ini_declaration_order() {
    let temp = TempDir::new("gecko-legacy-declaration-order");
    let context = current_context(temp.path().to_path_buf());
    let root = test_seams::primary_root_path(&context, "firefox");
    std::fs::create_dir_all(root.join("Profiles/unusable-default"))
      .expect("create source-less default profile");
    test_seams::seed_gecko_profile(&root.join("Profiles/first-declared"));
    test_seams::seed_gecko_profile(&root.join("Profiles/second-declared"));
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=Default\nIsRelative=1\nPath=Profiles/unusable-default\nDefault=1\n\
       [Profile1]\nName=Zulu\nIsRelative=1\nPath=Profiles/first-declared\n\
       [Profile2]\nName=Alpha\nIsRelative=1\nPath=Profiles/second-declared\n",
    )
    .expect("write profiles.ini");

    let mut outcome = discover_gecko_with_context(&context, "firefox").expect("discover");
    assert_eq!(
      outcome
        .profiles
        .iter()
        .map(|profile| profile.identity.name.as_str())
        .collect::<Vec<_>>(),
      ["Alpha", "Zulu"],
      "generic report ordering remains display-name based"
    );

    let mut listing = discover_gecko_with_context(&context, "firefox").expect("rediscover");
    sort_legacy_gecko_profiles(&mut listing);
    assert_eq!(
      listing
        .profiles
        .iter()
        .map(|profile| profile.identity.name.as_str())
        .collect::<Vec<_>>(),
      ["Zulu", "Alpha"],
      "legacy listing follows profiles.ini declaration order"
    );

    select_legacy_gecko_profile(&mut outcome);
    assert_eq!(outcome.profiles.len(), 1);
    assert_eq!(outcome.profiles[0].identity.name, "Zulu");
    assert!(outcome.profiles[0]
      .identity
      .path
      .ends_with("Profiles/first-declared"));
  }

  #[test]
  fn gecko_emitted_source_formats_are_declared_by_every_gecko_definition() {
    let registry = embedded_registry().expect("registry");
    let mut checked = 0;
    for platform in [PlatformId::Windows, PlatformId::Macos, PlatformId::Linux] {
      let definitions = registry
        .platforms
        .get(platform.as_str())
        .expect("platform definitions");
      for definition in definitions
        .iter()
        .filter(|definition| definition.engine == BrowserEngine::Gecko)
      {
        checked += 1;
        assert!(
          definition
            .capabilities
            .declared_persistent_formats
            .iter()
            .any(|format| format == mozilla::PERSISTENT_FORMAT_ID),
          "{} on {} does not declare {}",
          definition.canonical_id,
          platform.as_str(),
          mozilla::PERSISTENT_FORMAT_ID
        );
        for emitted in [
          mozilla::SESSION_JSONLZ4_FORMAT_ID,
          mozilla::SESSION_JSON_FORMAT_ID,
        ] {
          assert!(
            definition
              .capabilities
              .declared_session_formats
              .iter()
              .any(|format| format == emitted),
            "{} on {} does not declare {emitted}",
            definition.canonical_id,
            platform.as_str()
          );
        }
      }
    }
    assert!(checked > 0, "no Gecko definitions were checked");
  }

  #[test]
  fn persistent_source_created_between_discovery_and_query_is_still_projected() {
    let temp = TempDir::new("gecko-persistent-appears");
    let context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    let profile = root.join("Profiles/session-only");
    std::fs::create_dir_all(profile.join("sessionstore-backups")).expect("create profile");
    std::fs::write(
      profile.join("sessionstore-backups/recovery.jsonlz4"),
      b"invalid is still a discoverable source",
    )
    .expect("write session candidate");
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=session\nPath=Profiles/session-only\nDefault=1\n",
    )
    .expect("write profiles.ini");

    let discovery = discover_gecko_with_context(&context, "firefox").expect("discover profile");
    assert!(!discovery.profiles[0].identity.persistent_source_discovered);

    let mut created = false;
    let report = populate_gecko_sources(
      discovery,
      None,
      |persistent, domains| {
        if !created {
          created = true;
          seed_empty_gecko_database(persistent.parent().expect("profile directory"));
        }
        mozilla::query_cookies_engine_outcome(persistent, domains)
      },
      |path| path.exists(),
    );

    let persistent = report.profiles[0]
      .sources
      .iter()
      .find(|source| source.origin.format.as_str() == mozilla::PERSISTENT_FORMAT_ID)
      .expect("persistent source created before the query must be projected");
    assert!(persistent.selected);
    assert!(persistent.failure.is_none());
  }

  #[test]
  fn gecko_profile_canonicalize_failures_are_bounded() {
    let temp = TempDir::new("gecko-canonicalize-bound");
    let real_context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&real_context);
    let declarations = MAX_DISCOVERY_ISSUE_SAMPLES + 5;
    let mut ini = String::new();
    for index in 0..declarations {
      let profile = root.join(format!("Profiles/broken-{index}"));
      std::fs::create_dir_all(profile.join("sessionstore-backups")).expect("create profile");
      std::fs::write(
        profile.join("sessionstore-backups/recovery.jsonlz4"),
        b"discoverable session source",
      )
      .expect("write session candidate");
      ini.push_str(&format!(
        "[Profile{index}]\nName=broken-{index}\nPath=Profiles/broken-{index}\n"
      ));
    }
    std::fs::write(root.join("profiles.ini"), ini).expect("write profiles.ini");

    // Discovery canonicalizes the installation root first and resolves declared
    // profiles against *that*, so the denial list has to be built the same way.
    // Windows canonicalization returns a `\\?\` verbatim path, and a symlinked
    // temporary directory diverges on Unix too, so keying off the uncanonical
    // root would silently deny nothing.
    let canonical_root = root.canonicalize().expect("canonical Firefox root");
    let denied = (0..declarations)
      .map(|index| canonical_root.join(format!("Profiles/broken-{index}")))
      .collect::<Vec<_>>();
    let context = with_test_fs(
      real_context,
      TestDiscoveryFs {
        denied_canonicalize: denied,
        ..TestDiscoveryFs::default()
      },
    );

    let report = discover_gecko_with_context(&context, "firefox").expect("discover profiles");
    assert!(report.profiles.is_empty());
    let issues = report
      .discovery_issues
      .iter()
      .filter(|issue| issue.code == "profile_canonicalize_failed")
      .collect::<Vec<_>>();
    // Bounded to the sample cap, with the unsampled remainder carried as a
    // typed count on the first retained sample rather than formatted into a
    // message and parsed back out.
    assert_eq!(issues.len(), MAX_DISCOVERY_ISSUE_SAMPLES);
    assert_eq!(
      issues.iter().map(|issue| issue.occurrences).sum::<u32>(),
      declarations as u32
    );
    assert!(issues
      .iter()
      .all(|issue| !issue.message.contains("additional")));
  }

  #[test]
  fn a_rejected_row_is_not_projected_as_an_acquisition_retry() {
    let temp = TempDir::new("gecko-row-error-not-retry");
    let context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    seed_empty_gecko_database(&root.join("Profiles/default"));
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=default\nPath=Profiles/default\nDefault=1\n",
    )
    .expect("write profiles.ini");
    let discovery = discover_gecko_with_context(&context, "firefox").expect("discover profile");

    let report = populate_gecko_sources(
      discovery,
      None,
      |_, _| mozilla::MozillaExtractionDraft {
        persistent_attempted: true,
        persistent_acquisition_attempts: 1,
        persistent_rows_seen: 2,
        persistent_rows_skipped: 1,
        persistent_rows_rejected: 1,
        persistent_row_error: Some("failed to read value from row: invalid utf-8".to_owned()),
        ..mozilla::MozillaExtractionDraft::default()
      },
      |path| path.exists(),
    );

    let source = &report.profiles[0].sources[0];
    // A rejected row means cookies were lost. `diagnostics` renders as a
    // "retried, then succeeded" warning, so routing the row error there would
    // claim a recovery that never happened; the report layer raises it as an
    // error-severity row failure instead.
    assert!(source.diagnostics.is_empty());
    assert!(source.failure.is_none());
    assert_eq!(source.stats.rows_skipped, 1);
    assert_eq!(source.stats.rows_rejected, 1);
  }

  /// A session candidate never keeps a row error, so an implementation that
  /// raises `row_read_failed` only when one is present drops this issue
  /// entirely -- and with it the report's degradation from `complete` to
  /// `partial`, while cookies were in fact lost. The issue is keyed on the
  /// skipped count for exactly that reason.
  #[test]
  fn a_session_candidate_that_skipped_rows_still_reports_a_row_issue() {
    let temp = TempDir::new("gecko-session-skipped-rows");
    let context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    seed_empty_gecko_database(&root.join("Profiles/default"));
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=default\nPath=Profiles/default\nDefault=1\n",
    )
    .expect("write profiles.ini");
    let discovery = discover_gecko_with_context(&context, "firefox").expect("discover profile");

    let report = populate_gecko_sources(
      discovery,
      None,
      |path, _| mozilla::MozillaExtractionDraft {
        persistent_attempted: false,
        session_sources: vec![mozilla::MozillaSessionDraft {
          path: path.with_file_name("sessionstore.jsonlz4"),
          format: "mozilla_session_jsonlz4",
          precedence: 30,
          selected: true,
          cookies: Vec::new(),
          records: Vec::new(),
          rows_seen: 3,
          rows_skipped: 2,
          rows_rejected: 2,
          acquisition_attempts: 1,
          diagnostics: Vec::new(),
          error: None,
        }],
        ..mozilla::MozillaExtractionDraft::default()
      },
      |path| path.exists(),
    );

    let source = &report.profiles[0].sources[0];
    assert!(
      source.failure.is_none(),
      "rejected rows do not fail the source"
    );
    let row_issue = source
      .issues
      .iter()
      .find(|issue| issue.code == "row_read_failed")
      .expect("skipped session rows must degrade the report");
    assert_eq!(row_issue.occurrences, 2);
    assert_eq!(
      row_issue.severity,
      crate::browser::report_core::IssueSeverityCode::error()
    );
  }

  fn stopped_gecko_adapter_outcome(stop: crate::common::deadline::BoundaryStop) -> EngineExtract {
    let retained_cookie = || Cookie {
      domain: ".example.com".to_owned(),
      path: "/".to_owned(),
      secure: false,
      expires: None,
      name: "retained".to_owned(),
      value: "value".to_owned(),
      http_only: false,
      same_site: 0,
    };
    let profiles = (0..3)
      .map(|index| {
        let path = PathBuf::from(format!("/profiles/gecko-{index}"));
        DiscoveredProfile {
          identity: EngineProfileIdentity {
            profile_id: format!("{index:064x}").parse().expect("valid profile id"),
            installation_id: "0".repeat(64).parse().expect("valid installation id"),
            installation_priority: 10,
            installation_path: PathBuf::from("/profiles"),
            name: format!("profile-{index}"),
            path,
            is_default: index == 0,
            persistent_source_discovered: true,
          },
          legacy: LegacyRank {
            installation_priority: 10,
            profile_order: index,
            is_default: index == 0,
            eligible: true,
            installation_path: PathBuf::from("/profiles"),
            name: format!("profile-{index}"),
          },
          candidates: Vec::new(),
        }
      })
      .collect();
    let discovered = EngineListing {
      profiles,
      discovery_issues: Vec::new(),
      counters: DiscoveryCounters {
        installations_discovered: 1,
        installations_detected: 1,
        installations_enumerated: 1,
      },
      boundary_stop: None,
    };
    let calls = std::cell::Cell::new(0);
    let populated = populate_gecko_sources(
      discovered,
      None,
      |_, _| {
        let call = calls.get();
        calls.set(call + 1);
        if call == 0 {
          mozilla::MozillaExtractionDraft {
            persistent_attempted: true,
            persistent_cookies: vec![retained_cookie()],
            // Production gecko fills `records` and leaves `cookies` empty
            // outside tests; finalization reads `records` only.
            persistent_records: vec![crate::browser::cookie_record::CookieRecord::from_cookie(
              retained_cookie(),
              crate::browser::cookie_record::SourceRef::pending(0),
            )],
            persistent_rows_seen: 1,
            persistent_acquisition_strategy: Some(
              DatabaseAcquisitionStrategy::VerifiedStaticSingleFile,
            ),
            persistent_acquisition_attempts: 1,
            ..mozilla::MozillaExtractionDraft::default()
          }
        } else {
          mozilla::MozillaExtractionDraft {
            boundary_stop: Some(stop),
            ..mozilla::MozillaExtractionDraft::default()
          }
        }
      },
      |_| true,
    );
    assert_eq!(calls.get(), 2, "later profiles must not be queried");
    populated
  }

  #[test]
  fn gecko_adapter_report_and_legacy_drop_interrupted_discovery_placeholders() {
    use crate::common::deadline::BoundaryStop;

    for (stop, expected_termination) in [
      (BoundaryStop::TimedOut, "timed_out"),
      (BoundaryStop::Cancelled, "cancelled"),
      (BoundaryStop::ResourceExhausted, "resource_exhausted"),
    ] {
      let populated = stopped_gecko_adapter_outcome(stop);
      assert_eq!(populated.boundary_stop, Some(stop));
      assert_eq!(populated.profiles.len(), 1);
      assert_eq!(populated.profiles[0].sources.len(), 1);

      let report = crate::browser::report_build::project_engine_extract(
        "firefox",
        stopped_gecko_adapter_outcome(stop),
      )
      .expect("project stopped Gecko report");
      assert_eq!(report.termination.as_str(), expected_termination);
      assert_eq!(report.profiles.len(), 1);
      assert_eq!(report.profiles[0].sources.len(), 1);
      assert_eq!(report.profiles[0].sources[0].cookies[0].name, "retained");
      assert!(!serde_json::to_string(&report)
        .expect("serialize report")
        .contains("profile_extraction_failed"));

      let cookies = crate::browser::legacy::project_engine_extract_outcome(
        "firefox",
        stopped_gecko_adapter_outcome(stop),
      )
      .expect("legacy projection retains completed Gecko work");
      assert_eq!(cookies.len(), 1);
      assert_eq!(cookies[0].name, "retained");
    }
  }

  #[test]
  fn byte_order_marked_profiles_ini_still_declares_its_profiles() {
    let temp = TempDir::new("gecko-ini-bom");
    let context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    seed_empty_gecko_database(&root.join("Profiles/work"));
    std::fs::write(
      root.join("profiles.ini"),
      "\u{feff}[Profile0]\nName=work\nPath=Profiles/work\nDefault=1\n",
    )
    .expect("write BOM-prefixed profiles.ini");

    // Driven end to end: a BOM must not collapse into a successful empty
    // discovery, which would silently claim the file declared nothing and
    // promote the flat root to default instead.
    let report = discover_gecko_with_context(&context, "firefox").expect("discover BOM profiles");
    assert_eq!(report.profiles.len(), 1);
    assert_eq!(report.profiles[0].identity.name, "work");
    assert!(report.profiles[0].identity.is_default);
    assert_eq!(
      report.profiles[0].identity.path,
      root
        .join("Profiles/work")
        .canonicalize()
        .expect("canonical profile")
    );
    assert!(report.discovery_issues.is_empty());
  }

  #[test]
  fn gecko_profiles_ini_is_read_through_the_injected_filesystem() {
    let temp = TempDir::new("gecko-ini-seam");
    let real_context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&real_context);
    seed_empty_gecko_database(&root.join("Profiles/on-disk"));
    seed_empty_gecko_database(&root.join("Profiles/injected"));
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=on-disk\nPath=Profiles/on-disk\nDefault=1\n",
    )
    .expect("write on-disk profiles.ini");
    let canonical_root = root.canonicalize().expect("canonical root");

    let context = with_test_fs(
      real_context,
      TestDiscoveryFs {
        read_to_string_overrides: BTreeMap::from([(
          canonical_root.join("profiles.ini"),
          "[Profile0]\nName=injected\nPath=Profiles/injected\nDefault=1\n".to_owned(),
        )]),
        ..TestDiscoveryFs::default()
      },
    );

    // Discovery must honour the injected contents, proving profiles.ini is read
    // through the seam rather than straight off the real filesystem.
    let report = discover_gecko_with_context(&context, "firefox").expect("discover injected");
    assert_eq!(report.profiles.len(), 1);
    assert_eq!(report.profiles[0].identity.name, "injected");
  }

  #[test]
  fn gecko_flat_fallback_profile_is_named_after_its_directory() {
    let temp = TempDir::new("gecko-flat-name");
    let context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    seed_empty_gecko_database(&root);

    let report = discover_gecko_with_context(&context, "firefox").expect("discover flat fallback");
    assert_eq!(report.profiles.len(), 1);
    let expected = root
      .canonicalize()
      .expect("canonical root")
      .file_name()
      .map(|name| name.to_string_lossy().into_owned())
      .expect("root directory name");
    assert_eq!(report.profiles[0].identity.name, expected);
    assert!(!report.profiles[0].identity.name.is_empty());
    assert!(report.profiles[0].identity.is_default);
  }

  #[test]
  fn external_absolute_gecko_profiles_are_discovered_with_absolute_locators() {
    let temp = TempDir::new("gecko-external-absolute");
    let context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    std::fs::create_dir_all(&root).expect("create Firefox root");
    let external = temp.path().join("external-profiles/work");
    seed_empty_gecko_database(&external);
    std::fs::write(
      root.join("profiles.ini"),
      format!(
        "[Profile0]\nName=work\nIsRelative=0\nPath={}\nDefault=1\n",
        external.display()
      ),
    )
    .expect("write profiles.ini");

    let report = discover_gecko_with_context(&context, "firefox").expect("discover external");
    assert_eq!(report.profiles.len(), 1);
    let profile = &report.profiles[0];
    let canonical_external = external.canonicalize().expect("canonical external profile");
    assert_eq!(profile.identity.path, canonical_external);
    assert!(profile.identity.is_default);
    assert!(profile.identity.persistent_source_discovered);
    // A profile outside the installation root must be identified by an absolute
    // locator; a relative one would not round-trip.
    assert_eq!(
      profile.identity.profile_id,
      profile_id(
        profile.identity.installation_id.as_str(),
        ProfileLocator::Absolute(&canonical_external)
      )
    );
  }

  #[test]
  fn relative_gecko_profiles_escaping_the_root_use_absolute_locators() {
    let temp = TempDir::new("gecko-relative-escape");
    let context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    std::fs::create_dir_all(&root).expect("create Firefox root");
    let escaped = root
      .parent()
      .expect("root parent")
      .join("sibling-profiles/work");
    seed_empty_gecko_database(&escaped);
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=work\nIsRelative=1\nPath=../sibling-profiles/work\nDefault=1\n",
    )
    .expect("write profiles.ini");

    let report = discover_gecko_with_context(&context, "firefox").expect("discover escaped");
    assert_eq!(report.profiles.len(), 1);
    let profile = &report.profiles[0];
    let canonical_escaped = escaped.canonicalize().expect("canonical escaped profile");
    assert_eq!(profile.identity.path, canonical_escaped);
    assert_eq!(
      profile.identity.profile_id,
      profile_id(
        profile.identity.installation_id.as_str(),
        ProfileLocator::Absolute(&canonical_escaped)
      )
    );
  }

  #[test]
  fn session_only_gecko_profiles_report_no_persistent_source() {
    let temp = TempDir::new("gecko-session-only-report");
    let context = current_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    let profile = root.join("Profiles/session-only");
    std::fs::create_dir_all(profile.join("sessionstore-backups")).expect("create profile");
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=session\nPath=Profiles/session-only\nDefault=1\n",
    )
    .expect("write profiles.ini");
    std::fs::write(
      profile.join("sessionstore.js"),
      r#"{"windows":[{"cookies":[{"host":".example.com","path":"/","name":"session-only","value":"value"}]}]}"#,
    )
    .expect("write session candidate");

    let report =
      gecko_report_with_context(&context, "firefox", None, None).expect("session-only report");
    assert_eq!(report.profiles.len(), 1);
    let sources = &report.profiles[0].sources;
    // A profile with no cookies.sqlite must not fabricate a failed persistent
    // source: absence is normal, not an error.
    assert!(sources
      .iter()
      .all(|source| source.origin.format.as_str() != mozilla::PERSISTENT_FORMAT_ID));
    assert_eq!(sources.len(), 1);
    assert_eq!(
      sources[0].origin.format.as_str(),
      mozilla::SESSION_JSON_FORMAT_ID
    );
    assert!(sources[0].selected);
    assert!(sources[0].failure.is_none());
    assert_eq!(sources[0].cookies().len(), 1);
    assert_eq!(sources[0].cookies()[0].name, "session-only");
  }

  #[test]
  fn a_non_directory_root_ancestor_is_silent_absence() {
    let temp = TempDir::new("non-directory-root-ancestor");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).expect("create home");
    std::fs::write(home.join(".mozilla"), b"not a directory")
      .expect("place a file at the expected parent directory");
    let context = context_for(PlatformId::Linux, home, []);

    let discovery =
      discover_gecko_with_context(&context, "firefox").expect("non-directory means absent");
    assert_eq!(discovery.counters.installations_detected, 0);
    assert_eq!(discovery.counters.installations_discovered, 0);
    assert_eq!(discovery.counters.installations_enumerated, 0);
    assert!(discovery.discovery_issues.is_empty());
    assert!(!discovery.all_detected_roots_failed());
  }

  #[test]
  fn later_valid_gecko_root_survives_an_earlier_metadata_failure() {
    let temp = TempDir::new("gecko-root-metadata-partial-failure");
    let real_context = context_for(PlatformId::Linux, temp.path().join("home"), []);
    let denied = browser_root(&real_context, "firefox", "firefox-snap");
    let valid = browser_root(&real_context, "firefox", "firefox-native");
    seed_empty_gecko_database(&valid.join("Profiles/default"));
    let context = with_test_fs(
      real_context,
      TestDiscoveryFs {
        denied_metadata: Some(denied.clone()),
        ..TestDiscoveryFs::default()
      },
    );

    let discovery =
      discover_gecko_with_context(&context, "firefox").expect("retain the valid Gecko root");
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
