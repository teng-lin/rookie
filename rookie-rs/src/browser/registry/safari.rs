use super::super::report_core::{CookieSourceFormatId, CookieSourceRoleId};
use super::super::source::{Source, SourceCandidate, SourceFailureStage, SourceStats};
use super::{
  acquire_each_candidate, boundary_stop_from_error, canonical_installation_root, embedded_registry,
  engine_roots, installation_id, installation_root_is_directory, normalized_path_bytes,
  populate_engine_sources, profile_id, retain_engine_runtime_stop, select_listing_profiles,
  sort_discovered_profiles, BrowserEngine, DiscoveredProfile, DiscoveryContext, DiscoveryFs,
  DiscoveryIssue, DiscoveryStrategy, EngineExtract, EngineListing, EngineProfileIdentity,
  ExtractCompletion, LegacyRank, ProfileLocator, ProfileSelection, SourceAcquisition,
  PERSISTENT_SOURCE_PRECEDENCE,
};
#[cfg(test)]
use super::{DiscoveryCounters, ExtractedProfile};
#[cfg(test)]
use crate::common::deadline::SystemClock;
use crate::common::{deadline::BoundaryRuntime, diagnostic::REDACTED_PATH, sqlite};
use anyhow::{Context, Result};
use std::{
  collections::HashSet,
  fs,
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
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<bool> {
  for marker in SAFARI_INSTALLATION_MARKERS {
    runtime.check()?;
    let metadata = context.fs.metadata(&library.join(marker));
    runtime.check()?;
    if !matches!(
      metadata,
      Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ) {
      return Ok(true);
    }
  }
  Ok(false)
}

/// Crate-private generic Safari seam. Named profiles come from PR #137's
/// database-first discovery; this adapter only reshapes them, so legacy
/// `safari()` first-match selection is untouched.
pub(super) fn discover_safari_with_context<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
) -> Result<EngineListing> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  discover_safari_with_context_using_runtime(
    context,
    browser_id,
    &runtime,
    discover_safari_profiles_with_runtime,
  )
}

fn discover_safari_with_context_using_runtime<F, Profiles>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
  mut discover_profiles: Profiles,
) -> Result<EngineListing>
where
  F: DiscoveryFs,
  Profiles: FnMut(
    &Path,
    &crate::common::deadline::BoundaryRuntime<'_>,
  ) -> Result<(Vec<SafariProfile>, Option<SafariProfileDiscoveryIssue>)>,
{
  runtime.check()?;
  let registry = embedded_registry()?;
  runtime.check()?;
  let (definition, roots) = engine_roots(
    registry,
    context.platform,
    browser_id,
    BrowserEngine::Safari,
  )?;
  runtime.check()?;
  let mut seen_installations = HashSet::new();
  let mut seen_profiles = HashSet::new();
  let mut outcome = EngineListing::default();

  for root in roots {
    runtime.check()?;
    if root.discovery != DiscoveryStrategy::SafariDefaultProfile {
      continue;
    }
    let Some(resolved_root) = context.resolve_template(&root.template) else {
      continue;
    };
    // Non-Chromium registry templates never glob, so the suffix is literal.
    let root_path = resolved_root.base.join(resolved_root.suffix);
    runtime.check()?;
    let is_directory = installation_root_is_directory(context, &root_path, &mut outcome);
    runtime.check()?;
    if !is_directory || !has_safari_installation_marker(context, &root_path, runtime)? {
      continue;
    }
    runtime.check()?;
    let canonical_root =
      canonical_installation_root(context, root_path, &mut seen_installations, &mut outcome);
    runtime.check()?;
    let Some(canonical_root) = canonical_root else {
      continue;
    };
    let installation_id_value = installation_id(
      &definition.canonical_id,
      &root.root_id,
      &root.channel,
      &normalized_path_bytes(&canonical_root),
    );

    // Safari profile discovery degrades to the default profile instead of
    // failing, so a canonicalized root is always enumerated.
    outcome.counters.installations_enumerated += 1;
    runtime.check()?;
    let profiles = discover_profiles(&canonical_root, runtime);
    // A stop reached during a provider call wins over either its ordinary
    // success or failure and cannot be reset by a listing fallback.
    runtime.check()?;
    let (profiles, discovery_warning) = profiles?;
    if let Some(warning) = discovery_warning {
      // A fallback that still enumerated named profiles is a degradation; one
      // that failed too means they were never enumerated, which is a loss and
      // must not be reported at warning severity.
      let code = match warning {
        SafariProfileDiscoveryIssue::Degraded(_) => "safari_profile_discovery_degraded",
        SafariProfileDiscoveryIssue::EnumerationFailed(_) => "safari_profile_enumeration_failed",
      };
      outcome.discovery_issues.push(DiscoveryIssue::new(
        code,
        canonical_root.clone(),
        warning.message(),
      ));
    }

    for (legacy_profile_order, profile) in profiles.into_iter().enumerate() {
      runtime.check()?;
      let selected =
        match first_existing_cookie_candidate_with_runtime(&profile.cookie_candidates, runtime) {
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
          Err(error) if boundary_stop_from_error(&error).is_some() => return Err(error),
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
      runtime.check()?;
      let profile_path = context.fs.canonicalize(&source_directory);
      runtime.check()?;
      let profile_path = match profile_path {
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
      let candidate = safari_source_candidate(source_path, precedence);
      let profile_id_value = profile_id(installation_id_value.as_str(), locator);
      let is_default = profile.uuid.is_none();
      outcome.profiles.push(DiscoveredProfile {
        identity: EngineProfileIdentity {
          profile_id: profile_id_value,
          installation_id: installation_id_value.clone(),
          installation_priority: root.priority,
          installation_path: canonical_root.clone(),
          name: profile.name.clone(),
          path: profile_path,
          is_default,
          persistent_source_discovered: true,
        },
        legacy: LegacyRank {
          installation_priority: root.priority,
          profile_order: legacy_profile_order,
          is_default,
          eligible: true,
          installation_path: canonical_root.clone(),
          name: profile.name,
        },
        candidates: vec![candidate],
      });
    }
  }
  runtime.check()?;
  sort_discovered_profiles(&mut outcome.profiles);
  runtime.check()?;
  Ok(outcome)
}

/// The frozen Safari listing candidate: `selected: true`, `StableFileImage`,
/// `exists: true` (discovery found it), and not yet attempted.
fn safari_source_candidate(path: PathBuf, precedence: u16) -> SourceCandidate {
  SourceCandidate {
    path,
    role: CookieSourceRoleId::persistent(),
    format: CookieSourceFormatId::known("safari_binarycookies"),
    precedence,
    exists: true,
    selected: true,
    acquisition: SourceAcquisition::StableFileImage,
  }
}

fn discover_safari_with_runtime<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<EngineListing> {
  discover_safari_with_context_using_runtime(
    context,
    browser_id,
    runtime,
    discover_safari_profiles_with_runtime,
  )
}

pub(super) fn safari_report_with_context<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<&[String]>,
) -> Result<EngineExtract> {
  safari_report_with_query(
    context,
    browser_id,
    profile_id,
    domains,
    |origin, domains| {
      query_safari_file(
        origin,
        domains,
        crate::browser::safari::safari_based_outcome,
      )
    },
  )
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
) -> Result<EngineExtract>
where
  F: DiscoveryFs,
  Q: FnMut(SourceCandidate, Option<&[String]>) -> Result<Source>,
{
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  safari_report_with_context_using_runtime(
    context,
    browser_id,
    profile_id,
    domains,
    &runtime,
    discover_safari_profiles_with_runtime,
    query,
  )
}

fn safari_report_with_context_using_runtime<F, Profiles, Q>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<&[String]>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
  discover_profiles: Profiles,
  query: Q,
) -> Result<EngineExtract>
where
  F: DiscoveryFs,
  Profiles: FnMut(
    &Path,
    &crate::common::deadline::BoundaryRuntime<'_>,
  ) -> Result<(Vec<SafariProfile>, Option<SafariProfileDiscoveryIssue>)>,
  Q: FnMut(SourceCandidate, Option<&[String]>) -> Result<Source>,
{
  let mut listing =
    discover_safari_with_context_using_runtime(context, browser_id, runtime, discover_profiles)?;
  runtime.check()?;
  select_listing_profiles(
    &mut listing,
    browser_id,
    ProfileSelection::from_profile_id(profile_id),
  )?;
  runtime.check()?;
  let extract = populate_safari_sources_with_runtime(listing, domains, runtime, query);
  Ok(retain_engine_runtime_stop(extract, runtime))
}

pub(super) fn populate_safari_sources<Q>(
  listing: EngineListing,
  domains: Option<&[String]>,
  query: Q,
) -> EngineExtract
where
  Q: FnMut(SourceCandidate, Option<&[String]>) -> Result<Source>,
{
  populate_safari_sources_impl(listing, domains, None, query)
}

fn populate_safari_sources_with_runtime<Q>(
  listing: EngineListing,
  domains: Option<&[String]>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
  query: Q,
) -> EngineExtract
where
  Q: FnMut(SourceCandidate, Option<&[String]>) -> Result<Source>,
{
  populate_safari_sources_impl(listing, domains, Some(runtime), query)
}

/// Candidate-driven populate (unlike Gecko's path/query walk): discovery plants
/// exactly the Safari candidates, and each is acquired in turn. Safari inherits
/// the candidate's frozen `selected: true` + `StableFileImage` through
/// [`Source::new`] from the candidate's own values; only records, attempts,
/// and failure are overlaid.
///
/// The envelope is [`populate_engine_sources`] and the per-candidate walk is
/// [`acquire_each_candidate`], shared with Internet Explorer. All that is left
/// here is how Safari writes a failed query onto the placeholder, and the
/// completion policy: on a stop, keep everything committed and drop only a
/// stopped profile that committed nothing.
fn populate_safari_sources_impl<Q>(
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
    ExtractCompletion::DropStoppedProfileIfEmpty,
    |_identity, candidates| {
      acquire_each_candidate(candidates, domains, runtime, &mut query, |source, error| {
        // Exhausting the retries is itself the failure, so report the
        // attempts spent rather than the placeholder.
        source.acquisition_attempts = crate::browser::safari::STABLE_READ_ATTEMPTS as u32;
        let message = format!("{error:#}");
        match error.downcast_ref::<crate::browser::safari::SafariParseFailure>() {
          Some(failure) => {
            source.stats = SourceStats {
              rows_seen: failure.stats.records_seen,
              cookies_emitted: 0,
              rows_skipped: failure.stats.records_skipped,
              rows_rejected: failure.stats.records_rejected,
              provider_failures: 0,
            };
            source.push_row_read_failed(Some(message.clone()));
            source.fail(SourceFailureStage::Parse, message);
          }
          None => {
            source.fail(SourceFailureStage::Acquisition, message);
          }
        }
      })
    },
  )
}

fn query_safari_file<Q>(
  origin: SourceCandidate,
  domains: Option<&[String]>,
  query: Q,
) -> Result<Source>
where
  Q: FnOnce(SourceCandidate, Option<Vec<String>>) -> Result<Source>,
{
  query(origin, domains.map(<[String]>::to_vec))
}

#[cfg(target_os = "macos")]
pub(crate) fn safari_report(
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<Vec<String>>,
) -> Result<EngineExtract> {
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
) -> Result<EngineExtract> {
  runtime.check()?;
  let context = DiscoveryContext::system()?;
  runtime.check()?;
  safari_report_with_context_using_runtime(
    &context,
    browser_id,
    profile_id,
    domains.as_deref(),
    runtime,
    discover_safari_profiles_with_runtime,
    |origin, domains| {
      query_safari_file(origin, domains, |origin, domains| {
        crate::browser::safari::safari_based_outcome_with_runtime(origin, domains, runtime)
      })
    },
  )
}

pub(super) fn select_legacy_safari_profile(
  listing: &mut EngineListing,
  browser_id: &str,
) -> Result<()> {
  // The historical named wrapper probed only Safari's two default cookie
  // locations. Named profiles remain report-capable, but must never become a
  // fallback when both default locations are absent.
  listing
    .profiles
    .retain(|profile| profile.identity.is_default);
  select_listing_profiles(listing, browser_id, ProfileSelection::LegacyFirstProfile)
}

#[cfg(target_os = "macos")]
pub(crate) fn legacy_safari_outcome(
  browser_id: &str,
  domains: Option<Vec<String>>,
) -> Result<EngineExtract> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  legacy_safari_outcome_with_runtime(browser_id, domains, &runtime)
}

#[cfg(target_os = "macos")]
pub(crate) fn legacy_safari_outcome_with_runtime(
  browser_id: &str,
  domains: Option<Vec<String>>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<EngineExtract> {
  runtime.check()?;
  let context = DiscoveryContext::system()?;
  runtime.check()?;
  let mut listing = discover_safari_with_runtime(&context, browser_id, runtime)?;
  runtime.check()?;
  select_legacy_safari_profile(&mut listing, browser_id)?;
  runtime.check()?;
  let extract = populate_safari_sources_with_runtime(
    listing,
    domains.as_deref(),
    runtime,
    |origin, domains| {
      query_safari_file(origin, domains, |origin, domains| {
        crate::browser::safari::safari_based_outcome_with_runtime(origin, domains, runtime)
      })
    },
  );
  Ok(retain_engine_runtime_stop(extract, runtime))
}

#[cfg(target_os = "macos")]
pub(crate) fn safari_profiles_with_runtime(
  browser_id: &str,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<EngineListing> {
  runtime.check()?;
  let context = DiscoveryContext::system()?;
  discover_safari_with_runtime(&context, browser_id, runtime)
}

const SAFARI_TABS_RELATIVE_PATH: &str = "Safari/SafariTabs.db";
const SAFARI_PROFILE_TYPE: i64 = 1;
const SAFARI_PROFILE_SUBTYPE: i64 = 2;
const DEFAULT_PROFILE_SENTINEL: &str = "DefaultProfile";

fn safari_tabs_database_path(library: &Path) -> PathBuf {
  library
    .join("Containers/com.apple.Safari/Data/Library")
    .join(SAFARI_TABS_RELATIVE_PATH)
}

/// Crate-private profile descriptor used by the later cross-browser report
/// adapter. It deliberately does not change the legacy `safari()` API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SafariProfile {
  pub(super) name: String,
  pub(super) uuid: Option<String>,
  pub(super) cookie_candidates: Vec<PathBuf>,
}

fn is_canonical_uuid(value: &str) -> bool {
  let bytes = value.as_bytes();
  bytes.len() == 36
    && [8, 13, 18, 23]
      .into_iter()
      .all(|index| bytes[index] == b'-')
    && bytes
      .iter()
      .enumerate()
      .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
}

fn profile_name(title: &str, uuid: &str) -> String {
  let cleaned = title
    .trim()
    .chars()
    .map(|character| match character {
      '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '\0'..='\u{1f}' => '_',
      character => character,
    })
    .collect::<String>();
  if cleaned.is_empty() {
    format!("profile-{}", uuid[..8].to_ascii_lowercase())
  } else {
    cleaned
  }
}

fn disambiguate_profile_names(profiles: &mut [SafariProfile]) {
  let mut used = std::collections::BTreeSet::new();
  for profile in profiles {
    let original = profile.name.clone();
    let mut candidate = original.clone();
    let mut suffix = 2usize;
    while used.contains(&candidate) {
      candidate = format!("{original}-{suffix}");
      suffix += 1;
    }
    used.insert(candidate.clone());
    profile.name = candidate;
  }
}

fn default_profile(library: &Path) -> SafariProfile {
  SafariProfile {
    name: "default".to_owned(),
    uuid: None,
    cookie_candidates: vec![
      library.join("Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies"),
      library.join("Cookies/Cookies.binarycookies"),
    ],
  }
}

fn named_profile(library: &Path, uuid: String, title: String) -> SafariProfile {
  let lower_uuid = uuid.to_ascii_lowercase();
  SafariProfile {
    name: profile_name(&title, &uuid),
    uuid: Some(uuid),
    cookie_candidates: vec![library.join(format!(
      "Containers/com.apple.Safari/Data/Library/WebKit/WebsiteDataStore/{lower_uuid}/WebsiteData/Cookies/Cookies.binarycookies"
    ))],
  }
}

/// Returns a successful (including zero-row) profile DB result. The common
/// SQLite acquisition layer copies a live WAL pair, avoiding the silent
/// omission of recently-created profiles that immutable reads cause.
fn named_profiles_from_database(
  library: &Path,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<(String, String)>> {
  let database = safari_tabs_database_path(library);
  sqlite::with_browser_database_with_runtime(
    database,
    |connection| {
      runtime.check()?;
      let mut statement = connection.prepare(
        "SELECT external_uuid, title FROM bookmarks \
       WHERE type = ?1 AND subtype = ?2 AND external_uuid != ?3 \
       ORDER BY external_uuid COLLATE BINARY, title COLLATE BINARY",
      )?;
      runtime.check()?;
      let mut rows = statement.query(rusqlite::params![
        SAFARI_PROFILE_TYPE,
        SAFARI_PROFILE_SUBTYPE,
        DEFAULT_PROFILE_SENTINEL
      ])?;
      runtime.check()?;
      let mut profiles = Vec::new();
      loop {
        runtime.check()?;
        let row = rows.next()?;
        runtime.check()?;
        let Some(row) = row else {
          break;
        };
        let uuid = row.get::<_, Option<String>>(0)?.unwrap_or_default();
        let title = row.get::<_, Option<String>>(1)?.unwrap_or_default();
        if is_canonical_uuid(&uuid) {
          profiles.push((uuid, title));
        } else if !uuid.is_empty() {
          log::warn!("Skipping Safari profile row with invalid external UUID {uuid:?}");
        }
      }
      runtime.check()?;
      Ok(profiles)
    },
    runtime,
  )
  .map(|outcome| outcome.into_value())
}

fn named_profiles_from_directory(
  library: &Path,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<(String, String)>> {
  let directory = library.join("Containers/com.apple.Safari/Data/Library/Safari/Profiles");
  runtime.check()?;
  let entries = fs::read_dir(&directory);
  runtime.check()?;
  let mut entries = match entries {
    Ok(entries) => entries,
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
    Err(error) => {
      return Err(error)
        .with_context(|| format!("Failed to enumerate Safari profile directory {REDACTED_PATH}"))
    }
  };
  let mut profiles = Vec::new();
  loop {
    runtime.check()?;
    let entry = entries.next();
    runtime.check()?;
    let Some(entry) = entry else {
      break;
    };
    let entry = entry.with_context(|| {
      format!("Failed to read an entry in Safari profile directory {REDACTED_PATH}")
    })?;
    runtime.check()?;
    let file_type = entry
      .file_type()
      .with_context(|| format!("Failed to inspect Safari profile entry {REDACTED_PATH}"))?
      .is_dir();
    runtime.check()?;
    if file_type {
      if let Ok(uuid) = entry.file_name().into_string() {
        if is_canonical_uuid(&uuid) {
          profiles.push((uuid, String::new()));
        }
      }
    }
  }
  runtime.check()?;
  profiles.sort_by(|left, right| left.0.cmp(&right.0));
  runtime.check()?;
  Ok(profiles)
}

/// Default profile is always first. A readable zero-row database is
/// authoritative; only absent, unreadable, or schema-incompatible databases
/// activate the deterministic directory fallback.
/// How named-profile discovery went when the profile database could not be
/// used. The distinction is load-bearing: a fallback that enumerated profiles
/// degraded gracefully, while one that also failed means named profiles were
/// never enumerated at all and the report must not call that success.
#[derive(Debug)]
pub(super) enum SafariProfileDiscoveryIssue {
  Degraded(String),
  EnumerationFailed(String),
}

impl SafariProfileDiscoveryIssue {
  pub(super) fn message(self) -> String {
    match self {
      Self::Degraded(message) | Self::EnumerationFailed(message) => message,
    }
  }
}

fn discover_safari_profiles_with<Database, Directory>(
  library: &Path,
  runtime: &BoundaryRuntime<'_>,
  database: Database,
  directory: Directory,
) -> Result<(Vec<SafariProfile>, Option<SafariProfileDiscoveryIssue>)>
where
  Database: FnOnce(&Path, &BoundaryRuntime<'_>) -> Result<Vec<(String, String)>>,
  Directory: FnOnce(&Path, &BoundaryRuntime<'_>) -> Result<Vec<(String, String)>>,
{
  runtime.check()?;
  let mut profiles = vec![default_profile(library)];
  let (named, warning) = match database(library, runtime) {
    Ok(profiles) => (profiles, None),
    Err(error) => {
      // A terminal database result must never be flattened into an ordinary
      // discovery degradation or reset into a fresh fallback budget.
      runtime.check()?;
      match directory(library, runtime) {
        Ok(profiles) => (profiles, Some(SafariProfileDiscoveryIssue::Degraded(format!(
          "Safari profile database acquisition/query failed at {REDACTED_PATH}; using directory fallback (Full Disk Access may be required): {error:#}"
        )))),
        Err(directory_error) => {
          runtime.check()?;
          (Vec::new(), Some(SafariProfileDiscoveryIssue::EnumerationFailed(format!(
            "Safari profile database acquisition/query failed at {REDACTED_PATH}; directory fallback enumeration also failed: {directory_error:#}; original database error: {error:#}"
          ))))
        }
      }
    }
  };
  runtime.check()?;
  let mut seen = std::collections::BTreeSet::new();
  for (uuid, title) in named {
    runtime.check()?;
    if seen.insert(uuid.to_ascii_uppercase()) {
      profiles.push(named_profile(library, uuid, title));
    }
  }
  runtime.check()?;
  disambiguate_profile_names(&mut profiles);
  runtime.check()?;
  Ok((profiles, warning))
}

fn discover_safari_profiles_with_runtime(
  library: &Path,
  runtime: &BoundaryRuntime<'_>,
) -> Result<(Vec<SafariProfile>, Option<SafariProfileDiscoveryIssue>)> {
  discover_safari_profiles_with(
    library,
    runtime,
    named_profiles_from_database,
    named_profiles_from_directory,
  )
}

#[cfg(test)]
pub(super) fn discover_safari_profiles(
  library: &Path,
) -> (Vec<SafariProfile>, Option<SafariProfileDiscoveryIssue>) {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  discover_safari_profiles_with_runtime(library, &runtime)
    .expect("the standard profile-discovery runtime remains active")
}

/// Crate-private generic adapter. It is intentionally separate from the
/// legacy API so a broken named profile cannot hide cookies selected by the
/// historical default-path-first `safari()` function.
fn first_existing_cookie_candidate_with_runtime<'a>(
  candidates: &'a [PathBuf],
  runtime: &BoundaryRuntime<'_>,
) -> Result<Option<&'a PathBuf>> {
  for path in candidates {
    runtime.check()?;
    let metadata = fs::metadata(path);
    runtime.check()?;
    match metadata {
      Ok(_) => return Ok(Some(path)),
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
      Err(error) => {
        return Err(error)
          .with_context(|| format!("Failed to inspect Safari cookie source {REDACTED_PATH}"))
      }
    }
  }
  runtime.check()?;
  Ok(None)
}
#[cfg(test)]
mod tests {
  use super::*;
  use anyhow::anyhow;
  use std::cell::Cell;

  const TEST_INSTALLATION_ID: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
  const TEST_PROFILE_ID: &str = "2222222222222222222222222222222222222222222222222222222222222222";

  fn discovered_source_draft(path: PathBuf) -> SourceCandidate {
    safari_source_candidate(path, PERSISTENT_SOURCE_PRECEDENCE)
  }

  fn discovered_source() -> EngineListing {
    let installation_path = PathBuf::from("/Users/rookie/Library");
    let profile_path = installation_path.join("Cookies");
    EngineListing {
      counters: DiscoveryCounters {
        installations_detected: 1,
        installations_discovered: 1,
        installations_enumerated: 1,
      },
      boundary_stop: None,
      profiles: vec![DiscoveredProfile {
        identity: EngineProfileIdentity {
          profile_id: TEST_PROFILE_ID.parse().expect("valid profile id"),
          installation_id: TEST_INSTALLATION_ID.parse().expect("valid installation id"),
          installation_priority: 10,
          installation_path: installation_path.clone(),
          name: "Default".to_owned(),
          path: profile_path.clone(),
          is_default: true,
          persistent_source_discovered: true,
        },
        legacy: LegacyRank {
          installation_priority: 10,
          profile_order: 0,
          is_default: true,
          eligible: true,
          installation_path,
          name: "Default".to_owned(),
        },
        // Discovery output: the candidate exists, nothing has been queried.
        candidates: vec![discovered_source_draft(
          profile_path.join(SAFARI_COOKIE_FILE),
        )],
      }],
      discovery_issues: Vec::new(),
    }
  }

  #[test]
  fn native_query_bridge_forwards_owned_path_and_domains() {
    let path = PathBuf::from("/Users/rookie/Library/Cookies/Cookies.binarycookies");
    let domains = vec!["example.com".to_owned(), "mozilla.org".to_owned()];

    let result = query_safari_file(
      crate::browser::safari::direct_path_candidate(&path),
      Some(&domains),
      |forwarded, forwarded_domains| {
        assert_eq!(forwarded.path, path);
        assert_eq!(forwarded_domains.as_deref(), Some(domains.as_slice()));
        Err(anyhow::anyhow!("injected query"))
      },
    )
    .expect_err("injected query result is preserved");

    assert_eq!(result.to_string(), "injected query");
  }

  #[test]
  fn discover_rejects_a_browser_id_that_is_not_the_safari_engine() {
    use std::collections::BTreeMap;

    let directory = crate::utils::TempDir::new().expect("temporary Safari discovery root");
    let home = directory.path().join("home");
    std::fs::create_dir_all(home.join("Library/Cookies")).expect("legacy Safari marker dir");
    let context = DiscoveryContext {
      platform: super::super::PlatformId::Macos,
      home: Some(home),
      env: BTreeMap::new(),
      fs: super::super::RealDiscoveryFs,
    };
    let clock = crate::common::deadline::SystemClock;
    let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);

    let error = discover_safari_with_context_using_runtime(&context, "chrome", &runtime, |_, _| {
      unreachable!("engine mismatch must fail before profile discovery starts")
    })
    .expect_err("chrome is a Chromium browser id, not a Safari one");
    let diagnostic = error.to_string();
    assert!(diagnostic.contains("chrome"), "{diagnostic}");
    assert!(diagnostic.contains("Safari"), "{diagnostic}");
  }

  struct CanonicalizeDeniedFs {
    denied: HashSet<PathBuf>,
  }

  impl DiscoveryFs for CanonicalizeDeniedFs {
    fn exists(&self, path: &Path) -> bool {
      super::super::RealDiscoveryFs.exists(path)
    }

    fn is_dir(&self, path: &Path) -> bool {
      super::super::RealDiscoveryFs.is_dir(path)
    }

    fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
      super::super::RealDiscoveryFs.metadata(path)
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>> {
      super::super::RealDiscoveryFs.read_dir(path)
    }

    fn canonicalize(&self, path: &Path) -> Result<PathBuf> {
      if self.denied.contains(path) {
        anyhow::bail!("injected canonicalize denial for {}", path.display());
      }
      super::super::RealDiscoveryFs.canonicalize(path)
    }

    fn read_to_string(&self, path: &Path) -> Result<String> {
      super::super::RealDiscoveryFs.read_to_string(path)
    }

    fn expand_registry_glob(
      &self,
      base: &Path,
      suffix: &str,
    ) -> Result<super::super::GlobExpansion> {
      super::super::RealDiscoveryFs.expand_registry_glob(base, suffix)
    }
  }

  #[test]
  fn an_installation_root_that_cannot_be_canonicalized_is_skipped_as_a_discovery_issue() {
    use std::collections::BTreeMap;

    let directory = crate::utils::TempDir::new().expect("temporary Safari discovery root");
    let home = directory.path().join("home");
    let library = home.join("Library");
    let cookie_dir = library.join("Cookies");
    std::fs::create_dir_all(&cookie_dir).expect("legacy Safari marker dir");
    std::fs::write(cookie_dir.join("Cookies.binarycookies"), b"cook").expect("cookie fixture");
    let context = DiscoveryContext {
      platform: super::super::PlatformId::Macos,
      home: Some(home),
      env: BTreeMap::new(),
      fs: CanonicalizeDeniedFs {
        denied: HashSet::from([library.clone()]),
      },
    };
    let clock = crate::common::deadline::SystemClock;
    let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);

    let outcome =
      discover_safari_with_context_using_runtime(&context, "safari", &runtime, |_, _| {
        unreachable!("a root that cannot be canonicalized must never reach profile discovery")
      })
      .expect("a canonicalize failure is a discovery issue, not a hard error");
    assert!(outcome.profiles.is_empty());
    assert_eq!(outcome.discovery_issues.len(), 1);
    assert_eq!(
      outcome.discovery_issues[0].code,
      "installation_canonicalize_failed",
    );
  }

  #[test]
  fn a_profile_source_directory_that_cannot_be_canonicalized_is_reported_and_skipped() {
    use std::collections::BTreeMap;

    let directory = crate::utils::TempDir::new().expect("temporary Safari discovery root");
    let home = directory.path().join("home");
    let library = home.join("Library");
    let cookie_dir = library.join("Cookies");
    std::fs::create_dir_all(&cookie_dir).expect("legacy Safari marker dir");
    std::fs::write(cookie_dir.join("Cookies.binarycookies"), b"cook").expect("cookie fixture");
    let context = DiscoveryContext {
      platform: super::super::PlatformId::Macos,
      home: Some(home),
      env: BTreeMap::new(),
      fs: CanonicalizeDeniedFs {
        denied: HashSet::from([cookie_dir.clone()]),
      },
    };
    let clock = crate::common::deadline::SystemClock;
    let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);

    let outcome = discover_safari_with_context_using_runtime(&context, "safari", &runtime, {
      let cookie_dir = cookie_dir.clone();
      move |_, _| {
        Ok((
          vec![SafariProfile {
            name: "Default".to_owned(),
            uuid: None,
            cookie_candidates: vec![cookie_dir.join("Cookies.binarycookies")],
          }],
          None,
        ))
      }
    })
    .expect("a profile canonicalize failure is a discovery issue, not a hard error");
    assert!(outcome.profiles.is_empty());
    assert!(
      outcome
        .discovery_issues
        .iter()
        .any(|issue| issue.code == "profile_canonicalize_failed"),
      "{:?}",
      outcome.discovery_issues
    );
  }

  #[cfg(target_os = "macos")]
  #[test]
  fn real_macos_entry_points_discover_a_legacy_safari_home_via_env_override() {
    use std::collections::BTreeMap;
    use std::ffi::OsString;

    let directory = crate::utils::TempDir::new().expect("temporary Safari home");
    let home = directory.path().join("home");
    let cookie_dir = home.join("Library/Cookies");
    std::fs::create_dir_all(&cookie_dir).expect("legacy Safari marker dir");
    std::fs::write(
      cookie_dir.join("Cookies.binarycookies"),
      crate::browser::safari::golden_binarycookies_test_fixture(),
    )
    .expect("cookie fixture");

    let env = BTreeMap::from([(OsString::from("HOME"), home.clone().into_os_string())]);
    let _env_override = super::super::EnvOverride::install(env);

    let profiles = safari_profiles_with_runtime(
      "safari",
      &crate::common::deadline::BoundaryRuntime::standard(&crate::common::deadline::SystemClock),
    )
    .expect("safari_profiles_with_runtime should discover the synthetic legacy home");
    assert_eq!(profiles.profiles.len(), 1);

    let report = safari_report("safari", None, None)
      .expect("safari_report should discover the synthetic legacy home");
    assert_eq!(report.profiles.len(), 1);
    let report_source = &report.profiles[0].sources[0];
    // The golden fixture's cookie has a fixed (long-past) expiry, so canonical
    // projection legitimately drops it as expired; `rows_seen` proves the real
    // binarycookies parser actually read and processed the fixture rather than
    // the query silently failing, which is what this test exists to catch.
    assert!(
      report_source.failure.is_none(),
      "{:?}",
      report_source.failure
    );
    assert_eq!(report_source.stats.rows_seen, 1);

    let legacy = legacy_safari_outcome("safari", None)
      .expect("legacy_safari_outcome should discover the synthetic legacy home");
    assert_eq!(legacy.profiles.len(), 1);
    let legacy_source = &legacy.profiles[0].sources[0];
    assert!(
      legacy_source.failure.is_none(),
      "{:?}",
      legacy_source.failure
    );
    assert_eq!(legacy_source.stats.rows_seen, 1);
  }

  #[test]
  fn source_population_preserves_rows_attempts_and_failure_stage() {
    let success = populate_safari_sources(discovered_source(), None, |origin, _| {
      Ok(crate::browser::safari::safari_source(
        origin,
        Vec::new(),
        crate::browser::safari::SafariExtractionStats {
          records_seen: 7,
          records_skipped: 2,
          records_rejected: 2,
        },
        Some("recoverable record".to_owned()),
        2,
      ))
    });
    let success = &success.profiles[0].sources[0];
    assert_eq!(success.stats.rows_seen, 7);
    assert_eq!(success.stats.rows_skipped, 2);
    assert_eq!(success.stats.rows_rejected, 2);
    assert_eq!(row_read_failed_message(success), Some("recoverable record"));
    assert_eq!(success.acquisition_attempts, 2);
    assert!(success.failure.is_none());

    let parse_error =
      anyhow!("invalid Safari record").context(crate::browser::safari::SafariParseFailure {
        stats: crate::browser::safari::SafariExtractionStats {
          records_seen: 5,
          records_skipped: 3,
          records_rejected: 3,
        },
      });
    let expected_parse_error = format!("{parse_error:#}");
    let mut parse_error = Some(parse_error);
    let parse = populate_safari_sources(discovered_source(), None, |_origin, _| {
      Err(parse_error.take().expect("single parse query"))
    });
    let parse = &parse.profiles[0].sources[0];
    let parse_failure = parse.failure.as_ref().expect("parse failure recorded");
    assert_eq!(parse_failure.stage, SourceFailureStage::Parse);
    assert_eq!(parse.stats.rows_seen, 5);
    assert_eq!(parse.stats.rows_skipped, 3);
    assert_eq!(parse.stats.rows_rejected, 3);
    assert_eq!(
      parse.acquisition_attempts,
      crate::browser::safari::STABLE_READ_ATTEMPTS as u32
    );
    assert_eq!(parse_failure.message, expected_parse_error);
    assert_eq!(
      row_read_failed_message(parse),
      Some(expected_parse_error.as_str())
    );

    let acquisition_error = anyhow!("Safari source denied").context("acquire Safari cookie file");
    let expected_acquisition_error = format!("{acquisition_error:#}");
    let mut acquisition_error = Some(acquisition_error);
    let acquisition = populate_safari_sources(discovered_source(), None, |_origin, _| {
      Err(acquisition_error.take().expect("single acquisition query"))
    });
    let acquisition = &acquisition.profiles[0].sources[0];
    let acquisition_failure = acquisition.failure.as_ref().expect("acquisition failure");
    assert_eq!(acquisition_failure.stage, SourceFailureStage::Acquisition);
    assert_eq!(acquisition.stats.rows_seen, 0);
    assert_eq!(acquisition.stats.rows_skipped, 0);
    assert_eq!(acquisition.stats.rows_rejected, 0);
    assert_eq!(row_read_failed_message(acquisition), None);
    assert_eq!(
      acquisition.acquisition_attempts,
      crate::browser::safari::STABLE_READ_ATTEMPTS as u32
    );
    assert_eq!(acquisition_failure.message, expected_acquisition_error);
  }

  /// The `row_read_failed` issue message an adapter attached through
  /// [`Source::push_row_read_failed`], if any.
  fn row_read_failed_message(source: &Source) -> Option<&str> {
    source
      .issues
      .iter()
      .find(|issue| issue.code == "row_read_failed")
      .map(|issue| issue.message.as_str())
  }

  #[test]
  fn source_population_retains_success_before_typed_stop() {
    use crate::common::deadline::BoundaryStop;

    for stop in [
      BoundaryStop::TimedOut,
      BoundaryStop::Cancelled,
      BoundaryStop::ResourceExhausted,
    ] {
      let mut discovered = discovered_source();
      discovered.profiles[0]
        .candidates
        .push(discovered_source_draft(PathBuf::from(
          "/Users/rookie/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies",
        )));
      let calls = Cell::new(0);

      let populated = populate_safari_sources(discovered, None, |origin, _| {
        let call = calls.get();
        calls.set(call + 1);
        if call == 0 {
          Ok(crate::browser::safari::safari_source(
            origin,
            Vec::new(),
            crate::browser::safari::SafariExtractionStats {
              records_seen: 7,
              records_skipped: 2,
              records_rejected: 2,
            },
            None,
            1,
          ))
        } else {
          Err(
            anyhow::Error::new(stop).context(crate::browser::safari::SafariParseFailure {
              stats: crate::browser::safari::SafariExtractionStats::default(),
            }),
          )
        }
      });

      assert_eq!(calls.get(), 2);
      assert_eq!(populated.boundary_stop, Some(stop));
      assert_eq!(populated.profiles[0].sources[0].stats.rows_seen, 7);
      assert_eq!(populated.profiles[0].sources[0].stats.rows_rejected, 2);
      assert!(populated.profiles[0].sources[0].failure.is_none());
      assert_eq!(
        populated.profiles[0].sources.len(),
        1,
        "the interrupted source placeholder is removed"
      );
    }
  }

  #[test]
  fn source_population_drops_the_interrupted_profile_and_later_placeholders() {
    use crate::common::deadline::BoundaryStop;

    let mut discovered = discovered_source();
    let mut interrupted = discovered_source().profiles.remove(0);
    interrupted.identity.profile_id = "a".repeat(64).parse().expect("valid profile id");
    interrupted.identity.name = "Interrupted".to_owned();
    let mut unattempted = discovered_source().profiles.remove(0);
    unattempted.identity.profile_id = "b".repeat(64).parse().expect("valid profile id");
    unattempted.identity.name = "Unattempted".to_owned();
    discovered.profiles.push(interrupted);
    discovered.profiles.push(unattempted);
    let calls = Cell::new(0);

    let populated = populate_safari_sources(discovered, None, |origin, _| {
      let call = calls.get();
      calls.set(call + 1);
      if call == 0 {
        Ok(crate::browser::safari::safari_source(
          origin,
          Vec::new(),
          crate::browser::safari::SafariExtractionStats::default(),
          None,
          1,
        ))
      } else {
        Err(anyhow::Error::new(BoundaryStop::Cancelled))
      }
    });

    assert_eq!(calls.get(), 2);
    assert_eq!(populated.boundary_stop, Some(BoundaryStop::Cancelled));
    assert_eq!(populated.profiles.len(), 1);
    assert_eq!(
      populated.profiles[0].identity.profile_id.as_str(),
      TEST_PROFILE_ID
    );
    assert_eq!(populated.profiles[0].sources.len(), 1);
  }

  fn stopped_adapter_outcome(stop: crate::common::deadline::BoundaryStop) -> EngineExtract {
    let mut discovered = discovered_source();
    let second_path = PathBuf::from(
      "/Users/rookie/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies",
    );
    discovered.profiles[0]
      .candidates
      .push(discovered_source_draft(second_path));
    let calls = Cell::new(0);
    let populated = populate_safari_sources(discovered, None, |origin, _| {
      let call = calls.get();
      calls.set(call + 1);
      if call == 0 {
        Ok(crate::browser::safari::safari_source(
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
          crate::browser::safari::SafariExtractionStats {
            records_seen: 1,
            records_skipped: 0,
            records_rejected: 0,
          },
          None,
          1,
        ))
      } else {
        Err(anyhow::Error::new(stop))
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
        "safari",
        stopped_adapter_outcome(stop),
      )
      .expect("project stopped Safari report");
      assert_eq!(report.termination.as_str(), expected_termination);
      assert_eq!(report.profiles.len(), 1);
      assert_eq!(report.profiles[0].sources.len(), 1);
      assert_eq!(report.profiles[0].sources[0].cookies[0].name, "retained");
      assert!(!serde_json::to_string(&report)
        .expect("serialize report")
        .contains("profile_extraction_failed"));

      let cookies = crate::browser::legacy::project_engine_extract_outcome(
        "safari",
        stopped_adapter_outcome(stop),
      )
      .expect("legacy projection retains completed Safari work");
      assert_eq!(cookies.len(), 1);
      assert_eq!(cookies[0].name, "retained");
    }
  }

  fn stopped_after_success_outcome(stop: crate::common::deadline::BoundaryStop) -> EngineExtract {
    use crate::common::deadline::{
      test_clock::ManualClock, BoundaryStop, CancellationToken, Deadline,
    };
    use std::time::Duration;

    let clock = ManualClock::default();
    let token = CancellationToken::default();
    let runtime = crate::common::deadline::BoundaryRuntime::with_stop(
      &clock,
      Deadline::after(&clock, Duration::from_secs(1)),
      token.clone(),
    );
    let mut discovered = discovered_source();
    discovered.profiles[0]
      .candidates
      .push(discovered_source_draft(PathBuf::from(
        "/Users/rookie/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies",
      )));
    let calls = Cell::new(0);
    let outcome = populate_safari_sources_with_runtime(discovered, None, &runtime, |origin, _| {
      calls.set(calls.get() + 1);
      let completed = crate::browser::safari::safari_source(
        origin,
        vec![crate::browser::cookie_record::CookieRecord::from_cookie(
          crate::common::enums::Cookie {
            domain: ".example.com".to_owned(),
            path: "/".to_owned(),
            secure: false,
            expires: None,
            name: "completed-before-stop".to_owned(),
            value: "value".to_owned(),
            http_only: false,
            same_site: 0,
          },
          crate::browser::cookie_record::SourceRef::pending(0),
        )],
        crate::browser::safari::SafariExtractionStats {
          records_seen: 3,
          records_skipped: 1,
          records_rejected: 1,
        },
        Some("one malformed record".to_owned()),
        2,
      );
      match stop {
        BoundaryStop::TimedOut => clock.advance(Duration::from_secs(1)),
        BoundaryStop::Cancelled => assert!(token.cancel()),
        BoundaryStop::ResourceExhausted => assert!(token.exhaust_resources()),
      }
      Ok(completed)
    });
    assert_eq!(calls.get(), 1, "later placeholders must not be queried");
    assert_eq!(outcome.boundary_stop, Some(stop));
    assert_eq!(outcome.profiles[0].sources.len(), 1);
    outcome
  }

  #[test]
  fn successful_source_racing_with_stop_reaches_report_and_legacy_atomically() {
    use crate::common::deadline::BoundaryStop;

    for (stop, expected_termination) in [
      (BoundaryStop::TimedOut, "timed_out"),
      (BoundaryStop::Cancelled, "cancelled"),
      (BoundaryStop::ResourceExhausted, "resource_exhausted"),
    ] {
      let report = crate::browser::report_build::project_engine_extract(
        "safari",
        stopped_after_success_outcome(stop),
      )
      .expect("project the atomically completed Safari source");
      assert_eq!(report.termination.as_str(), expected_termination);
      assert_eq!(report.profiles.len(), 1);
      let source = &report.profiles[0].sources[0];
      assert_eq!(source.cookies[0].name, "completed-before-stop");
      assert_eq!(source.stats.rows_seen, 3);
      assert_eq!(source.stats.rows_skipped, 1);
      assert_eq!(source.stats.rows_rejected, 1);
      assert_eq!(source.stats.cookies_emitted, 1);
      assert_eq!(source.stats.acquisition_attempts, 2);
      assert_eq!(report.summary.rows_seen, 3);
      assert_eq!(report.summary.rows_skipped, 1);
      assert_eq!(report.summary.rows_rejected, 1);
      assert_eq!(report.summary.cookies_emitted, 1);

      let cookies = crate::browser::legacy::project_engine_extract_outcome(
        "safari",
        stopped_after_success_outcome(stop),
      )
      .expect("legacy projection retains the atomically completed Safari source");
      assert_eq!(cookies.len(), 1);
      assert_eq!(cookies[0].name, "completed-before-stop");
    }
  }

  #[test]
  fn near_expired_safari_listing_uses_the_caller_runtime() {
    use crate::common::deadline::{test_clock::ManualClock, BoundaryStop, Deadline};
    use std::collections::BTreeMap;
    use std::time::Duration;

    let directory = crate::utils::TempDir::new().expect("temporary Safari listing root");
    let home = directory.path().join("home");
    let library = home.join("Library");
    std::fs::create_dir_all(library.join("Containers/com.apple.Safari"))
      .expect("Safari installation marker");
    let context = DiscoveryContext {
      platform: super::super::PlatformId::Macos,
      home: Some(home),
      env: BTreeMap::new(),
      fs: super::super::RealDiscoveryFs,
    };
    let clock = ManualClock::default();
    let deadline = Deadline::after(&clock, Duration::from_secs(1));
    let runtime = crate::common::deadline::BoundaryRuntime::new(&clock, deadline);
    let profile_calls = Cell::new(0);

    let error = discover_safari_with_context_using_runtime(
      &context,
      "safari",
      &runtime,
      |_, _| -> Result<(Vec<SafariProfile>, Option<SafariProfileDiscoveryIssue>)> {
        profile_calls.set(profile_calls.get() + 1);
        clock.advance(Duration::from_secs(1));
        Err(anyhow!("scripted profile listing failure"))
      },
    )
    .expect_err("a listing that reaches the caller deadline must stop");

    assert_eq!(profile_calls.get(), 1);
    assert_eq!(
      error.downcast_ref::<BoundaryStop>(),
      Some(&BoundaryStop::TimedOut)
    );
    assert_eq!(deadline.remaining(&clock), Duration::ZERO);
  }

  #[test]
  fn near_expired_safari_report_does_not_start_source_queries() {
    use crate::common::deadline::{test_clock::ManualClock, BoundaryStop, Deadline};
    use std::collections::BTreeMap;
    use std::time::Duration;

    let directory = crate::utils::TempDir::new().expect("temporary Safari report root");
    let home = directory.path().join("home");
    let library = home.join("Library");
    std::fs::create_dir_all(library.join("Containers/com.apple.Safari"))
      .expect("Safari installation marker");
    let context = DiscoveryContext {
      platform: super::super::PlatformId::Macos,
      home: Some(home),
      env: BTreeMap::new(),
      fs: super::super::RealDiscoveryFs,
    };
    let clock = ManualClock::default();
    let deadline = Deadline::after(&clock, Duration::from_secs(1));
    let runtime = crate::common::deadline::BoundaryRuntime::new(&clock, deadline);
    let source_calls = Cell::new(0);

    let error = safari_report_with_context_using_runtime(
      &context,
      "safari",
      None,
      None,
      &runtime,
      |library, _| {
        clock.advance(Duration::from_secs(1));
        Ok((
          vec![SafariProfile {
            name: "Default".to_owned(),
            uuid: None,
            cookie_candidates: vec![library.join("Cookies/Cookies.binarycookies")],
          }],
          None,
        ))
      },
      |_, _| {
        source_calls.set(source_calls.get() + 1);
        unreachable!("source query cannot start after listing expires the shared runtime")
      },
    )
    .expect_err("the report keeps the caller's expired listing deadline");

    assert_eq!(
      error.downcast_ref::<BoundaryStop>(),
      Some(&BoundaryStop::TimedOut)
    );
    assert_eq!(source_calls.get(), 0);
    assert_eq!(deadline.remaining(&clock), Duration::ZERO);
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
      let listing = discovered_source();
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
      assert!(
        retained.profiles.is_empty(),
        "discovery-only placeholders are not completed work"
      );
    }
  }

  fn temp_library(tag: &str) -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};

    let unique = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .expect("system clock")
      .as_nanos();
    let library = std::env::temp_dir().join(format!(
      "rookie-safari-{tag}-{}-{unique}/Library",
      std::process::id()
    ));
    fs::create_dir_all(&library).expect("create library fixture");
    library
  }

  fn write_tabs_database(library: &Path, rows: &[(&str, &str)]) {
    let database = library.join("Containers/com.apple.Safari/Data/Library/Safari/SafariTabs.db");
    fs::create_dir_all(database.parent().expect("database parent"))
      .expect("create database parent");
    let connection = rusqlite::Connection::open(&database).expect("open SafariTabs fixture");
    connection
      .execute_batch(
        "CREATE TABLE bookmarks (external_uuid TEXT, title TEXT, type INTEGER, subtype INTEGER)",
      )
      .expect("create bookmarks");
    for (uuid, title) in rows {
      connection
        .execute(
          "INSERT INTO bookmarks (external_uuid, title, type, subtype) VALUES (?1, ?2, 1, 2)",
          rusqlite::params![uuid, title],
        )
        .expect("insert bookmark profile");
    }
  }

  #[test]
  fn safari_tabs_profiles_are_default_first_lowercase_and_disambiguated() {
    let library = temp_library("tabs-profiles");
    let first = "A0B1C2D3-1111-2222-3333-444444444444";
    let second = "B0B1C2D3-1111-2222-3333-444444444444";
    let third = "C0B1C2D3-1111-2222-3333-444444444444";
    let non_profile = "D0B1C2D3-1111-2222-3333-444444444444";
    write_tabs_database(
      &library,
      &[(third, "Work-2"), (second, "Work"), (first, "Work")],
    );
    let connection = rusqlite::Connection::open(safari_tabs_database_path(&library))
      .expect("reopen SafariTabs fixture");
    connection
      .execute(
        "INSERT INTO bookmarks (external_uuid, title, type, subtype) VALUES (?1, ?2, 2, 2)",
        rusqlite::params![non_profile, "Not a profile"],
      )
      .expect("insert non-profile bookmark with matching subtype");
    drop(connection);

    let (profiles, warning) = discover_safari_profiles(&library);
    assert!(warning.is_none());
    assert_eq!(
      profiles
        .iter()
        .map(|profile| profile.name.as_str())
        .collect::<Vec<_>>(),
      vec!["default", "Work", "Work-2", "Work-2-2"]
    );
    assert_eq!(profiles[1].uuid.as_deref(), Some(first));
    assert!(profiles[1].cookie_candidates[0].ends_with(format!(
      "WebsiteDataStore/{}/WebsiteData/Cookies/Cookies.binarycookies",
      first.to_ascii_lowercase()
    )));
    fs::remove_dir_all(library.parent().expect("fixture root")).expect("remove fixture");
  }

  #[test]
  fn readable_zero_row_profile_database_is_authoritative() {
    let library = temp_library("zero-row-authority");
    write_tabs_database(&library, &[]);
    let uuid = "A0B1C2D3-1111-2222-3333-444444444444";
    fs::create_dir_all(library.join(format!(
      "Containers/com.apple.Safari/Data/Library/Safari/Profiles/{uuid}"
    )))
    .expect("create fallback profile");

    let (profiles, warning) = discover_safari_profiles(&library);
    assert!(warning.is_none());
    assert_eq!(
      profiles.len(),
      1,
      "directory fallback must not override a readable zero-row DB"
    );
    fs::remove_dir_all(library.parent().expect("fixture root")).expect("remove fixture");
  }

  #[test]
  fn expiring_profile_database_does_not_reset_the_budget_for_directory_fallback() {
    use crate::common::deadline::{test_clock::ManualClock, BoundaryStop, Deadline};
    use std::time::Duration;

    let library = temp_library("profile-runtime-fallback");
    let clock = ManualClock::default();
    let deadline = Deadline::after(&clock, Duration::from_secs(1));
    let runtime = BoundaryRuntime::new(&clock, deadline);
    let directory_calls = std::cell::Cell::new(0);

    let error = discover_safari_profiles_with(
      &library,
      &runtime,
      |_, _| {
        clock.advance(Duration::from_secs(1));
        Err(anyhow!("scripted profile database failure"))
      },
      |_, _| {
        directory_calls.set(directory_calls.get() + 1);
        Ok(Vec::new())
      },
    )
    .expect_err("the shared deadline expires with the database attempt");

    assert_eq!(
      error.downcast_ref::<BoundaryStop>(),
      Some(&BoundaryStop::TimedOut)
    );
    assert_eq!(directory_calls.get(), 0, "fallback must not start");
    fs::remove_dir_all(library.parent().expect("fixture root")).expect("remove fixture");
  }

  #[test]
  fn missing_profile_database_uses_sorted_directory_fallback_with_warning() {
    let library = temp_library("directory-fallback");
    let first = "B0B1C2D3-1111-2222-3333-444444444444";
    let second = "A0B1C2D3-1111-2222-3333-444444444444";
    for uuid in [first, second] {
      fs::create_dir_all(library.join(format!(
        "Containers/com.apple.Safari/Data/Library/Safari/Profiles/{uuid}"
      )))
      .expect("create fallback profile");
    }

    let (profiles, warning) = discover_safari_profiles(&library);
    // The fallback enumerated profiles, so this is a degradation, not a loss.
    assert!(matches!(
      warning,
      Some(SafariProfileDiscoveryIssue::Degraded(ref message))
        if message.contains("directory fallback")
    ));
    assert_eq!(profiles[0].name, "default");
    assert_eq!(profiles[1].uuid.as_deref(), Some(second));
    assert_eq!(profiles[2].uuid.as_deref(), Some(first));
    fs::remove_dir_all(library.parent().expect("fixture root")).expect("remove fixture");
  }

  /// When the database *and* the directory fallback both fail, named profiles
  /// were never enumerated. Reporting that at the same severity as a working
  /// fallback let the report claim success while profiles were missing.
  #[cfg(unix)]
  #[test]
  fn failing_database_and_directory_fallback_is_an_enumeration_failure() {
    use std::os::unix::fs::PermissionsExt;

    let library = temp_library("directory-fallback-denied");
    let profiles_directory =
      library.join("Containers/com.apple.Safari/Data/Library/Safari/Profiles");
    fs::create_dir_all(&profiles_directory).expect("create profile directory");
    fs::set_permissions(&profiles_directory, fs::Permissions::from_mode(0o000))
      .expect("deny profile directory");

    let (profiles, warning) = discover_safari_profiles(&library);
    let failed = matches!(
      warning,
      Some(SafariProfileDiscoveryIssue::EnumerationFailed(_))
    );

    fs::set_permissions(&profiles_directory, fs::Permissions::from_mode(0o700))
      .expect("restore permissions");
    fs::remove_dir_all(library.parent().expect("fixture root")).expect("remove fixture");

    assert!(failed, "both paths failed, so enumeration failed");
    // The default profile still stands; only the named ones were lost.
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].name, "default");
  }
}
