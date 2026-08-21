//! Cross-engine report assembly.
//!
//! Every registered engine reaches the frozen [`super::report_core`] contract
//! through this module. The four entry points at the bottom back the public
//! [`crate::supported_browsers`], [`crate::browser_profiles`],
//! [`crate::browser_report`], and [`crate::load_report`].

mod dispatch;
pub(crate) mod snapshot;

use super::compatibility::{
  compatibility_decision, engine_compatibility_family, CompatibilityFamily,
};
#[cfg(test)]
use super::cookie_record::CookieRecord;
use super::cookie_record::{FinalizationError, LegacyProjectionSemantics};
use super::outcome::{
  Diagnostic, Failure, FailureLedger, FailureScope, Outcome, ResultStatus, SourceOutcome,
  Termination,
};
use super::registry::{
  self, ChromiumExtractedProfile, ChromiumRegistryDraft, DiscoveredProfile, DiscoveryIssue,
  EngineExtract, EngineListing, ExtractedProfile, RegisteredBrowser, SourceAcquisition,
};
#[cfg(test)]
use super::report_core::SourceStatusCode;
use super::report_core::{
  compare_source_identity, display_path, issue, push_aggregated, sort_cookies,
  sort_source_descriptors, source_status, AcquisitionStrategyCode, BrowserCapabilitiesDescriptor,
  BrowserDescriptor, BrowserId, CipherTierId, CookieSourceDescriptor, CookieSourceFormatId,
  CookieSourceIdentity, CounterSet, EngineId, ExtractionIssue, ExtractionReport,
  ExtractionStageCode, ExtractionStats, InstallationId, IssueSeverityCode, ProfileDescriptor,
  ProfileExtraction, ProfileId, ProfileIdentity, ReportStats, ReportStatusCode, SourceExtraction,
  StatsAccumulator, TerminationCode, MAX_ISSUE_SAMPLES,
};
// Both are production-dead after `source_identity` began taking a
// `SourceIdentity`; the fixtures still need them.
#[cfg(test)]
use super::registry::SOURCE_ROLE_PERSISTENT;
#[cfg(test)]
use super::report_core::CookieSourceRoleId;
use super::source::{
  Source, SourceFailureStage as SourceFailureStageNew, SourceIdentity, SourceIssue,
};
#[cfg(test)]
use super::source::{SourceCandidate, SourceStats};
use crate::common::concurrency::{fan_out, DEFAULT_FAN_OUT_WIDTH};
use crate::common::deadline::{runtime_for_control, BoundaryRuntime, BoundaryStop, SystemClock};
use crate::common::enums::Cookie;
use crate::common::sqlite::DatabaseAcquisitionStrategy;
use crate::error::{EngineCause, EngineFailure};
use crate::execution::ExecutionControl;
use anyhow::{bail, Result};
use std::collections::BTreeMap;

/// Discovery problems that do not prevent source enumeration. Everything else
/// is an error, because it stopped an installation or profile from being read.
///
/// Severity drives status computation, so a code only earns `error` when it
/// actually cost the report a source. Codes that a fallback recovers from, or
/// that describe an optional lookup, stay warnings: promoting them would report
/// `partial` for a run that lost nothing.
fn discovery_severity(code: &str) -> IssueSeverityCode {
  match code {
    "duplicate_installation" | "duplicate_profile" | "profile_has_no_cookie_source" => {
      IssueSeverityCode::info()
    }
    "local_state_invalid"
    | "safari_profile_discovery_degraded"
    // Both fall back to flat or markerless profile discovery.
    | "mozilla_profiles_ini_invalid"
    | "optional_profiles_enumeration_failed" => IssueSeverityCode::warning(),
    _ => IssueSeverityCode::error(),
  }
}

fn discovery_issue(browser_id: &BrowserId, discovery: &DiscoveryIssue) -> ExtractionIssue {
  let (path, _) = display_path(&discovery.path);
  let message = crate::common::diagnostic::sanitize(&discovery.message);
  issue(
    discovery.code,
    ExtractionStageCode::discovery(),
    discovery_severity(discovery.code),
    format!("{path}: {message}"),
  )
  .with_occurrences(discovery.occurrences)
  // Aggregation keeps one message per code, so the path travels as a sample
  // and the offending locations survive the merge.
  .with_samples(vec![path])
  .with_context(Some(browser_id), None, None)
}

fn acquisition_code(acquisition: SourceAcquisition) -> AcquisitionStrategyCode {
  match acquisition {
    SourceAcquisition::Database(DatabaseAcquisitionStrategy::LiveReadOnly) => {
      AcquisitionStrategyCode::live_read_only()
    }
    SourceAcquisition::Database(DatabaseAcquisitionStrategy::VerifiedWalSnapshot) => {
      AcquisitionStrategyCode::verified_wal_snapshot()
    }
    SourceAcquisition::Database(DatabaseAcquisitionStrategy::VerifiedStaticSingleFile) => {
      AcquisitionStrategyCode::verified_static_single_file()
    }
    SourceAcquisition::StableFileImage => AcquisitionStrategyCode::stable_file_image(),
    SourceAcquisition::EseDatabase => AcquisitionStrategyCode::ese_database(),
    SourceAcquisition::NotAttempted => AcquisitionStrategyCode::not_attempted(),
  }
}

/// The wire identity of one cookie source.
///
/// Takes the whole [`SourceIdentity`] rather than four positional keys: the
/// previous signature put `role` and `format` adjacent as `&str`, so
/// transposing them was a silent behaviour change rather than a compile error.
fn source_identity(origin: &SourceIdentity) -> CookieSourceIdentity {
  let (path, path_lossy) = display_path(&origin.path);
  CookieSourceIdentity {
    role: origin.role.clone(),
    format: origin.format.clone(),
    path,
    path_lossy,
    precedence: origin.precedence,
  }
}

/// A row issue always means rows were skipped, so it degrades the report to
/// `partial` without demoting the source itself: acquisition and the query
/// still completed.
fn profile_identity(
  browser_id: &BrowserId,
  installation_id: &str,
  profile_id: &str,
  display_name: &str,
  path: &std::path::Path,
) -> Result<ProfileIdentity> {
  let (path, path_lossy) = display_path(path);
  Ok(ProfileIdentity {
    browser_id: browser_id.clone(),
    installation_id: installation_id.parse::<InstallationId>()?,
    profile_id: profile_id.parse::<ProfileId>()?,
    display_name: display_name.to_owned(),
    path,
    path_lossy,
  })
}

/// Adapts one extracted Chromium profile into a [`ProfileDraft`].
///
/// Extract-only, and a copy like [`extracted_profile_outcome`]: everything the
/// query learned already lives on the [`Source`]s. The one thing this mapper
/// still decides is what an empty source list means, which is engine-specific
/// -- Chromium lists only databases that exist, so having none is ordinary
/// absence rather than the failure it is for the engine listing.
/// Engine adaptation layer from Section 5.7, private to this module.
///
/// These were `pub(crate)` in `report_core` so the engine adapters could build
/// them. No adapter does any more: every engine returns a `Source`, and the two
/// copy helpers below are the only things that construct a draft. Keeping the
/// types here makes that structural -- `report_core` holds the frozen wire
/// contract, and the draft is a private hop on the way to it, so the
/// crate-visible source representations are exactly `SourceCandidate`,
/// `Source`, and the wire DTO.
#[non_exhaustive]
#[derive(Debug)]
struct SourceDraft {
  source: CookieSourceIdentity,
  /// Original platform path representation used only for provenance hashing.
  /// The public `source.path` remains the explicitly marked lossy display form.
  source_path_bytes: Vec<u8>,
  selected: bool,
  acquisition_strategy: AcquisitionStrategyCode,
  cookies: Vec<Cookie>,
  /// Canonical records retain source-native metadata which the compatibility
  /// `Cookie` projection intentionally omits.
  records: Vec<super::cookie_record::CookieRecord>,
  /// Typed evidence consumed exactly once by canonical finalization. It never
  /// reaches either projector as a second policy input.
  compatibility_evidence: Option<CompatibilityEvidence>,
  stats: ExtractionStats,
  issues: Vec<ExtractionIssue>,
  /// Acquisition, parsing, or the filtered query did not complete. Skipped rows
  /// alone never set this: a source with rejected rows still succeeded.
  failed: bool,
}

#[non_exhaustive]
#[derive(Debug)]
struct ProfileDraft {
  profile: ProfileIdentity,
  is_default: bool,
  sources: Vec<SourceDraft>,
  issues: Vec<ExtractionIssue>,
}

impl SourceDraft {
  fn new(
    source: CookieSourceIdentity,
    source_path: &std::path::Path,
    selected: bool,
    acquisition_strategy: AcquisitionStrategyCode,
  ) -> Self {
    Self {
      source_path_bytes: raw_path_bytes(source_path),
      source,
      selected,
      acquisition_strategy,
      cookies: Vec::new(),
      records: Vec::new(),
      compatibility_evidence: None,
      stats: ExtractionStats::default(),
      issues: Vec::new(),
      failed: false,
    }
  }
}

#[derive(Debug)]
enum CompatibilityEvidence {
  AllRowsRejected(String),
}

fn raw_path_bytes(path: &std::path::Path) -> Vec<u8> {
  #[cfg(unix)]
  {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
  }
  #[cfg(windows)]
  {
    use std::os::windows::ffi::OsStrExt;
    path
      .as_os_str()
      .encode_wide()
      .flat_map(u16::to_le_bytes)
      .collect()
  }
  #[cfg(not(any(unix, windows)))]
  {
    path.to_string_lossy().as_bytes().to_vec()
  }
}

impl ProfileDraft {
  fn new(profile: ProfileIdentity, is_default: bool) -> Self {
    Self {
      profile,
      is_default,
      sources: Vec::new(),
      issues: Vec::new(),
    }
  }
}
/// Section 5.5 source ordering: role first, then declared precedence. The sort
/// is stable, so equal keys keep their engine-declared candidate order.
#[cfg(test)]
fn sort_source_outcomes(sources: &mut [SourceDraft]) {
  sources.sort_by(|left, right| compare_source_identity(&left.source, &right.source));
}
/// What a profile with no sources means. The two towers disagree, because they
/// discover differently, and that disagreement is the only thing the shared
/// profile mapper cannot derive for itself.
enum NoSources {
  /// Listing admits a profile only when it found a persistent database or a
  /// session candidate, so an extract with none means whatever justified that
  /// admission is gone. Always a failure -- never the "nothing was ever there"
  /// case `no_sources` means. Discovery-only profiles on a stopped extract are
  /// pruned before the mapper and never reach this.
  SourceVanished,
  /// Chromium lists only databases that exist, so a profile with none is
  /// ordinary absence -- the `info` signal, not a failure. This engine has no
  /// profile-level failure to distinguish it from: a failure reaching a named
  /// database lands on that [`Source`], which is built even when acquisition
  /// fails, so an empty Chromium source list means exactly one thing.
  Absent,
}

/// Adapts one already-queried [`Source`] into the shared [`SourceDraft`].
///
/// A pure copy: stats, records, diagnostics, pre-built issues, and the failure
/// are transferred as-is. It does not re-derive `row_read_failed` from
/// `rows_skipped` (the engine already attached it through
/// [`Source::push_row_read_failed`]) and does not recompute `cookies_emitted`
/// from a cookie list.
fn source_to_draft(source: Source) -> SourceDraft {
  // Records are the only supply of finalized rows; `cookies` stays the
  // compatibility projection and the secrets walk. Production leaves it empty,
  // matching the pre-split adapter; characterization tests project it from
  // records so they can assert on cookie contents.
  #[cfg(test)]
  let cookies = source.cookies();
  let Source {
    origin,
    selected,
    acquisition,
    records,
    stats,
    acquisition_attempts,
    diagnostics,
    failure,
    issues,
  } = source;
  let mut outcome = SourceDraft::new(
    source_identity(&origin),
    &origin.path,
    selected,
    acquisition_code(acquisition),
  );
  outcome.stats = CounterSet {
    rows_seen: stats.rows_seen as u64,
    cookies_emitted: stats.cookies_emitted as u64,
    rows_skipped: stats.rows_skipped as u64,
    rows_rejected: stats.rows_rejected as u64,
    provider_failures: stats.provider_failures as u64,
    acquisition_attempts: u64::from(acquisition_attempts),
  }
  .into_stats();
  #[cfg(test)]
  {
    outcome.cookies = cookies;
  }
  outcome.records = records;
  for diagnostic in diagnostics {
    push_aggregated(
      &mut outcome.issues,
      issue(
        "source_read_retried",
        ExtractionStageCode::acquisition(),
        IssueSeverityCode::warning(),
        diagnostic,
      ),
    );
  }
  for source_issue in issues {
    // The one issue code that does not become an extraction issue. Section 5.7
    // reports a fully-rejected source as succeeded-with-rows-skipped, so the
    // "every row failed" error exists purely as evidence for the compatibility
    // projection, which does treat it as a failure.
    if source_issue.code == SourceIssue::ALL_ROWS_REJECTED {
      outcome.compatibility_evidence =
        Some(CompatibilityEvidence::AllRowsRejected(source_issue.message));
      continue;
    }
    push_aggregated(
      &mut outcome.issues,
      source_issue_to_extraction(source_issue),
    );
  }
  if let Some(failure) = failure {
    push_aggregated(
      &mut outcome.issues,
      issue(
        "source_extraction_failed",
        match failure.stage {
          SourceFailureStageNew::Acquisition => ExtractionStageCode::acquisition(),
          SourceFailureStageNew::Parse => ExtractionStageCode::parse(),
          SourceFailureStageNew::Query => ExtractionStageCode::query(),
        },
        IssueSeverityCode::error(),
        failure.message,
      ),
    );
    outcome.failed = true;
  }
  outcome
}

/// Copies a crate-private [`SourceIssue`] into the report's [`ExtractionIssue`].
///
/// The issue was fully formed at the engine boundary, so the report mapper only
/// transfers it and never re-reasons about counters. Optional provider/tier/
/// cause/retryability evidence is carried through when present (Chromium's row
/// issues rely on it); the other engines leave it unset, matching `issue`'s
/// defaults.
fn source_issue_to_extraction(source_issue: SourceIssue) -> ExtractionIssue {
  let SourceIssue {
    code,
    stage,
    severity,
    message,
    occurrences,
    samples,
    provider,
    tier,
    cause,
    retryability,
  } = source_issue;
  let mut outcome = issue(code, stage, severity, message).with_occurrences(occurrences);
  if !samples.is_empty() {
    outcome = outcome.with_samples(samples);
  }
  if provider.is_some() {
    outcome.provider = provider;
  }
  if tier.is_some() {
    outcome.tier = tier;
  }
  if let Some(cause) = cause {
    outcome.cause = cause;
  }
  if let Some(retryability) = retryability {
    outcome.retryability = retryability;
  }
  outcome
}

/// Adapts one extracted profile into a [`ProfileDraft`].
///
/// Extract-only: a profile whose sources are all gone after a source present at
/// discovery vanished raises `profile_extraction_failed`. Listing never reaches
/// this path, so empty candidates there stay ordinary listing emptiness.
/// Adapts one extracted profile into a [`ProfileDraft`]. The only profile
/// mapper: both towers reach the report through it.
///
/// A copy, like [`source_to_draft`]. It takes an already-built
/// [`ProfileIdentity`] rather than either engine's profile bag, which is what
/// lets one function serve both -- `EngineProfileIdentity.name` and
/// `ChromiumProfile.display_name` are both just `display_name` by the time they
/// arrive.
fn profile_to_draft(
  identity: ProfileIdentity,
  is_default: bool,
  sources: Vec<Source>,
  no_sources: NoSources,
) -> ProfileDraft {
  let mut outcome = ProfileDraft::new(identity, is_default);
  outcome
    .sources
    .extend(sources.into_iter().map(source_to_draft));
  if !outcome.sources.is_empty() {
    return outcome;
  }
  let empty = match no_sources {
    NoSources::SourceVanished => issue(
      "profile_extraction_failed",
      ExtractionStageCode::acquisition(),
      IssueSeverityCode::error(),
      "a cookie source present at discovery could not be found by the time of extraction",
    ),
    NoSources::Absent => issue(
      "profile_has_no_cookie_source",
      ExtractionStageCode::discovery(),
      IssueSeverityCode::info(),
      "profile has no selected persistent source",
    ),
  };
  push_aggregated(&mut outcome.issues, empty);
  outcome
}

/// One registered browser's contribution to a report.
struct BrowserDraft {
  browser_id: BrowserId,
  compatibility_family: CompatibilityFamily,
  detected: bool,
  installations_discovered: usize,
  /// Every detected root failed enumeration, so an empty profile list means
  /// "could not look", not "nothing installed". Section 5.7 makes this the
  /// difference between a `failed` report and a `no_sources` one.
  discovery_failed: bool,
  profiles: Vec<ProfileDraft>,
  issues: Vec<ExtractionIssue>,
  termination: Termination,
}

fn termination_from_stop(stop: BoundaryStop) -> Termination {
  match stop {
    BoundaryStop::TimedOut => Termination::TimedOut,
    BoundaryStop::Cancelled => Termination::Cancelled,
    BoundaryStop::ResourceExhausted => Termination::ResourceExhausted,
  }
}

fn stop_from_error(error: &anyhow::Error) -> Option<BoundaryStop> {
  error
    .chain()
    .find_map(|cause| cause.downcast_ref::<BoundaryStop>().copied())
}

fn chromium_browser_outcome(
  browser_id: &BrowserId,
  report: ChromiumRegistryDraft,
) -> Result<BrowserDraft> {
  let termination = report
    .boundary_stop
    .map_or(Termination::Completed, termination_from_stop);
  let mut outcome = BrowserDraft {
    browser_id: browser_id.clone(),
    compatibility_family: CompatibilityFamily::Chromium,
    // Discovery counts, not the post-selection list: a profile-selected report
    // must not claim the installations it filtered out were never there. A root
    // that existed but could not be read also counts as detected -- otherwise
    // the report says `failed` and "not detected" about the same browser.
    detected: report.installations_discovered > 0 || report.installations_detected > 0,
    installations_discovered: report.installations_discovered,
    discovery_failed: report.all_detected_roots_failed,
    profiles: Vec::new(),
    issues: Vec::new(),
    termination,
  };
  for discovery in &report.discovery_issues {
    push_aggregated(&mut outcome.issues, discovery_issue(browser_id, discovery));
  }
  for installation in report.installations {
    for extracted in installation.profiles {
      let ChromiumExtractedProfile { profile, sources } = extracted;
      let identity = profile_identity(
        browser_id,
        &installation.installation_id,
        profile.profile_id.as_str(),
        &profile.display_name,
        &profile.path,
      )?;
      outcome.profiles.push(profile_to_draft(
        identity,
        profile.is_default,
        sources,
        NoSources::Absent,
      ));
    }
  }
  Ok(outcome)
}

/// Adapts an [`EngineExtract`] bag (Gecko/Safari/IE) into a browser draft.
///
/// After a stop, drop discovery-only work before mapping, so an interrupted run
/// never fabricates a successful zero-row source.
fn engine_extract_outcome(
  browser_id: &BrowserId,
  mut extract: EngineExtract,
) -> Result<BrowserDraft> {
  if extract.boundary_stop.is_some() {
    registry::retain_completed_engine_extract(&mut extract);
  }
  let termination = extract
    .boundary_stop
    .map_or(Termination::Completed, termination_from_stop);
  let mut outcome = BrowserDraft {
    browser_id: browser_id.clone(),
    compatibility_family: engine_compatibility_family(browser_id),
    detected: extract.counters.installations_discovered > 0
      || extract.counters.installations_detected > 0,
    installations_discovered: extract.counters.installations_discovered,
    discovery_failed: extract.all_detected_roots_failed(),
    profiles: Vec::new(),
    issues: Vec::new(),
    termination,
  };
  for discovery in &extract.discovery_issues {
    push_aggregated(&mut outcome.issues, discovery_issue(browser_id, discovery));
  }
  for profile in extract.profiles {
    let identity = profile_identity(
      browser_id,
      profile.identity.installation_id.as_str(),
      profile.identity.profile_id.as_str(),
      &profile.identity.name,
      &profile.identity.path,
    )?;
    outcome.profiles.push(profile_to_draft(
      identity,
      profile.identity.is_default,
      profile.sources,
      NoSources::SourceVanished,
    ));
  }
  Ok(outcome)
}

/// One registered browser's listing contribution: the profiles and cookie
/// sources discovery found, with no read ever attempted.
///
/// Deliberately not a [`BrowserDraft`]. That type exists to carry an
/// extraction's outcome, and two of its per-source facts have nowhere
/// honest to go here: `failed` would assert something about a read that
/// never happened, and `acquisition_strategy` -- though the listing claim
/// behind it (`not_attempted` for Chromium/Gecko/IE, `stable_file_image` for
/// Safari) is real -- describes what an extraction *would* do, not one that
/// did. Listing has no draft envelope at all: it builds the wire
/// [`ProfileDescriptor`]/`CookieSourceDescriptor` directly, so those fields
/// are not just unset, they are unrepresentable.
struct BrowserListing {
  discovery_failed: bool,
  profiles: Vec<ProfileDescriptor>,
  issues: Vec<ExtractionIssue>,
  /// A typed stop the engine recorded rather than returned. Listing's public
  /// seam answers with a bare `Vec<ProfileDescriptor>`, so unlike an extract
  /// -- which has a `Termination` field to say "this is partial" -- there is
  /// nowhere honest to put a truncated list. Carrying the stop here lets
  /// [`profile_descriptors_from_outcome`] reject it instead of returning the
  /// profiles found before the stop as if discovery had finished.
  boundary_stop: Option<BoundaryStop>,
}

/// Adapts a Gecko/Safari/IE listing into a browser listing (`browser_profiles`).
///
/// Every discovered candidate becomes a source descriptor; there is no
/// `exists` filter (Gecko candidates are all `exists: true`). Empty
/// candidates are ordinary listing emptiness, never `profile_extraction_failed`
/// -- that error is extract-only.
fn engine_listing_outcome(
  browser_id: &BrowserId,
  listing: EngineListing,
) -> Result<BrowserListing> {
  let mut outcome = BrowserListing {
    discovery_failed: listing.all_detected_roots_failed(),
    profiles: Vec::new(),
    issues: Vec::new(),
    boundary_stop: listing.boundary_stop,
  };
  for discovery in &listing.discovery_issues {
    push_aggregated(&mut outcome.issues, discovery_issue(browser_id, discovery));
  }
  for profile in listing.profiles {
    outcome
      .profiles
      .push(discovered_profile_descriptor(browser_id, profile)?);
  }
  Ok(outcome)
}

fn discovered_profile_descriptor(
  browser_id: &BrowserId,
  profile: DiscoveredProfile,
) -> Result<ProfileDescriptor> {
  let identity = profile_identity(
    browser_id,
    profile.identity.installation_id.as_str(),
    profile.identity.profile_id.as_str(),
    &profile.identity.name,
    &profile.identity.path,
  )?;
  let mut sources = profile
    .candidates
    .iter()
    .map(|candidate| {
      let source = source_identity(&candidate.identity());
      CookieSourceDescriptor {
        role: source.role,
        format: source.format,
        path: source.path,
        path_lossy: source.path_lossy,
        precedence: source.precedence,
      }
    })
    .collect::<Vec<_>>();
  sort_source_descriptors(&mut sources);
  Ok(ProfileDescriptor {
    profile: identity,
    is_default: profile.identity.is_default,
    sources,
  })
}

fn capabilities(browser: &RegisteredBrowser) -> Result<BrowserCapabilitiesDescriptor> {
  let parse = |values: &[String]| -> Result<Vec<CookieSourceFormatId>> {
    values.iter().map(|value| value.parse()).collect()
  };
  let tiers = |values: &[String]| -> Result<Vec<CipherTierId>> {
    values.iter().map(|value| value.parse()).collect()
  };
  Ok(BrowserCapabilitiesDescriptor {
    persistent_formats: parse(&browser.capabilities.declared_persistent_formats)?,
    session_formats: parse(&browser.capabilities.declared_session_formats)?,
    declared_decryption_tiers: tiers(&browser.capabilities.declared_decryption_tiers)?,
    available_decryption_tiers: tiers(&browser.capabilities.available_decryption_tiers)?,
  })
}

fn browser_descriptor(browser: &RegisteredBrowser) -> Result<BrowserDescriptor> {
  Ok(BrowserDescriptor {
    id: browser.canonical_id.parse()?,
    aliases: browser.aliases.clone(),
    display_name: browser.display_name.clone(),
    engine: browser.engine.parse::<EngineId>()?,
    capabilities: capabilities(browser)?,
  })
}

/// Registered browsers for the running OS. Registration is not detection: this
/// never touches the filesystem.
pub(crate) fn supported_browser_descriptors() -> Result<Vec<BrowserDescriptor>> {
  registry::registered_browsers()?
    .iter()
    .map(browser_descriptor)
    .collect()
}

/// Acquires one browser's cookies.
///
/// `session` is an **acquire-time** filter, not a post-projection one: under
/// `PersistentOnly` the Gecko plan never plants its session candidates, so no
/// session store is opened. The other engines declare no separate session
/// source, so the parameter is a no-op for them.
fn collect_extraction(
  browser: &RegisteredBrowser,
  selection: registry::ProfileSelection<'_>,
  domains: Option<Vec<String>>,
  session: crate::SessionPolicy,
  runtime: &BoundaryRuntime<'_>,
) -> Result<BrowserDraft> {
  runtime.check()?;
  let browser_id: BrowserId = browser.canonical_id.parse()?;
  match browser.engine {
    "chromium" => {
      let report = registry::chromium_registry_report_with_runtime(
        &browser.canonical_id,
        selection,
        domains,
        runtime,
      )?;
      chromium_browser_outcome(&browser_id, report)
    }
    "gecko" => {
      let engine = registry::gecko_report_with_runtime(
        &browser.canonical_id,
        selection,
        domains,
        session,
        runtime,
      )?;
      engine_extract_outcome(&browser_id, engine)
    }
    engine => dispatch::remaining_engine_extraction(
      &browser_id,
      &browser.canonical_id,
      engine,
      selection,
      domains,
      runtime,
    ),
  }
}

/// The listing counterpart of [`collect_extraction`], serving only
/// `browser_profile_descriptors`. Never opens a source, so it returns a
/// [`BrowserListing`] rather than a [`BrowserDraft`].
fn collect_listing(
  browser: &RegisteredBrowser,
  runtime: &BoundaryRuntime<'_>,
) -> Result<BrowserListing> {
  runtime.check()?;
  let browser_id: BrowserId = browser.canonical_id.parse()?;
  match browser.engine {
    "chromium" => chromium_listing_outcome(&browser_id, &browser.canonical_id, runtime),
    "gecko" => {
      let listing = registry::gecko_profiles_with_runtime(&browser.canonical_id, runtime)?;
      engine_listing_outcome(&browser_id, listing)
    }
    engine => {
      dispatch::remaining_engine_listing(&browser_id, &browser.canonical_id, engine, runtime)
    }
  }
}

fn chromium_listing_outcome(
  browser_id: &BrowserId,
  canonical_id: &str,
  runtime: &BoundaryRuntime<'_>,
) -> Result<BrowserListing> {
  let listing = registry::chromium_listing_with_runtime(canonical_id, runtime)?;
  let mut outcome = BrowserListing {
    discovery_failed: listing.all_detected_roots_failed,
    profiles: Vec::new(),
    issues: Vec::new(),
    // Chromium listing never records a stop: `chromium_listing_with_runtime`
    // returns `Err` at each checkpoint, so a stop arrives as an error here.
    boundary_stop: None,
  };
  for discovery in &listing.discovery_issues {
    push_aggregated(&mut outcome.issues, discovery_issue(browser_id, discovery));
  }
  for profile in listing.profiles {
    let identity = profile_identity(
      browser_id,
      profile.installation_id.as_str(),
      profile.profile_id.as_str(),
      &profile.display_name,
      &profile.path,
    )?;
    let mut sources = profile
      .persistent_candidates
      .iter()
      // Chromium listing policy, not a property of `SourceCandidate`: this
      // engine stats both layouts and lists only what is on disk, while the
      // engine listing plants `exists: true` candidates that must all survive.
      .filter(|candidate| candidate.exists)
      .map(|candidate| {
        let source = source_identity(&candidate.identity());
        CookieSourceDescriptor {
          role: source.role,
          format: source.format,
          path: source.path,
          path_lossy: source.path_lossy,
          precedence: source.precedence,
        }
      })
      .collect::<Vec<_>>();
    sort_source_descriptors(&mut sources);
    outcome.profiles.push(ProfileDescriptor {
      profile: identity,
      is_default: profile.is_default,
      sources,
    });
  }
  Ok(outcome)
}

fn canonicalize_profile(
  engine: ProfileDraft,
  profiles: &mut Vec<(ProfileIdentity, bool)>,
  sources: &mut Vec<SourceOutcome>,
  ledger: &mut FailureLedger,
  compatibility_evidence: &mut BTreeMap<[u8; 32], Diagnostic>,
  runtime: Option<&BoundaryRuntime<'_>>,
) -> Option<BoundaryStop> {
  let ProfileDraft {
    profile,
    is_default,
    sources: engine_sources,
    issues,
  } = engine;
  let profile_scope = FailureScope::Profile {
    browser_id: profile.browser_id.clone(),
    installation_id: profile.installation_id.clone(),
    profile_id: profile.profile_id.clone(),
  };
  for issue in issues {
    if let Some(stop) = runtime.and_then(|runtime| runtime.check().err()) {
      profiles.push((profile, is_default));
      return Some(stop);
    }
    ledger.push(Failure::from_issue(issue, profile_scope.clone(), &[]));
  }
  for source in engine_sources {
    if let Some(stop) = runtime.and_then(|runtime| runtime.check().err()) {
      profiles.push((profile, is_default));
      return Some(stop);
    }
    let source_digest =
      super::outcome::source_digest(&profile, &source.source, &source.source_path_bytes);
    let secrets = source
      .cookies
      .iter()
      .map(|cookie| cookie.value.as_str())
      .collect::<Vec<_>>();
    let mut canonical = SourceOutcome::new(
      profile.clone(),
      is_default,
      source.source,
      source_digest,
      source.selected,
      source.acquisition_strategy,
    );
    canonical.stats = source.stats;
    canonical.failed = source.failed;
    let source_scope = FailureScope::Source {
      browser_id: profile.browser_id.clone(),
      installation_id: profile.installation_id.clone(),
      profile_id: profile.profile_id.clone(),
      source_digest: canonical.source_digest(),
    };
    for issue in source.issues {
      ledger.push(Failure::from_issue(issue, source_scope.clone(), &secrets));
    }
    if let Some(CompatibilityEvidence::AllRowsRejected(message)) = source.compatibility_evidence {
      compatibility_evidence.insert(
        source_digest,
        Diagnostic::new_with_secrets(message, &secrets),
      );
    }
    drop(secrets);
    // `records` is the only source of finalized rows. `cookies` remains the
    // compatibility projection and the secrets walk above; it is never a
    // fallback supply of records, so an adapter that emits cookies without
    // records now reports zero rows instead of silently reconstructing them.
    for record in source.records {
      match record.finalize() {
        Ok(record) => canonical.records.push(record),
        Err(error) => {
          canonical.stats.cookies_emitted = canonical.stats.cookies_emitted.saturating_sub(1);
          increment_counter(
            &mut canonical.stats.rows_skipped,
            &mut canonical.stats.counters_saturated,
          );
          increment_counter(
            &mut canonical.stats.rows_rejected,
            &mut canonical.stats.counters_saturated,
          );
          let cause = match error {
            FinalizationError::Encrypted => "encrypted",
            FinalizationError::Unavailable(super::cookie_record::UnavailableCode::Decrypt) => {
              "decrypt"
            }
            FinalizationError::Unavailable(super::cookie_record::UnavailableCode::Decode) => {
              "decode"
            }
            FinalizationError::Unavailable(
              super::cookie_record::UnavailableCode::ProviderUnavailable,
            ) => "provider_unavailable",
            FinalizationError::Unavailable(
              super::cookie_record::UnavailableCode::ProviderFailed,
            ) => "provider_failed",
          };
          let mut finalization_issue = issue(
            "invalid_final_record",
            ExtractionStageCode::decode(),
            IssueSeverityCode::error(),
            format!("{cause} cookie value rejected before canonical finalization"),
          );
          finalization_issue.cause = cause.to_owned();
          ledger.push(Failure::from_issue(
            finalization_issue,
            source_scope.clone(),
            &[],
          ));
        }
      }
    }
    sources.push(canonical);
  }
  profiles.push((profile, is_default));
  runtime.and_then(|runtime| runtime.check().err())
}

fn increment_counter(counter: &mut u32, saturated: &mut bool) {
  match counter.checked_add(1) {
    Some(value) => *counter = value,
    None => {
      *counter = u32::MAX;
      *saturated = true;
    }
  }
}

#[cfg(test)]
fn project_canonical_report(outcome: Outcome) -> ExtractionReport {
  project_canonical_report_with_runtime(outcome, None).0
}

/// Projects the canonical outcome and returns the DTO beside the *typed*
/// termination it was built from.
///
/// `ExtractionReport::termination` is a [`TerminationCode`] -- an open string
/// vocabulary for the wire. Callers inside the crate that must classify a stop
/// (the flatten seam behind `extract`) take the enum returned here instead, so
/// no internal decision is ever made by parsing a string.
fn project_canonical_report_with_runtime(
  mut outcome: Outcome,
  runtime: Option<&BoundaryRuntime<'_>>,
) -> (ExtractionReport, Termination) {
  debug_assert_eq!(outcome.counters.sources_discovered, outcome.sources.len());
  // An extraction stop belongs to work that attempted to start after these
  // sources completed. Projecting the immutable completed sources must not
  // discard them merely because the shared token is now terminal.
  let projection_runtime = (outcome.termination == Termination::Completed)
    .then_some(runtime)
    .flatten();
  let mut failures = outcome.failure_ledger.into_vec();
  let mut profiles = Vec::with_capacity(outcome.profiles.len());
  let mut projection_stop = None;
  for (identity, is_default) in outcome.profiles {
    if let Some(stop) = projection_runtime.and_then(|runtime| runtime.check().err()) {
      projection_stop = Some(stop);
      break;
    }
    let mut stats = StatsAccumulator::default();
    let mut public_sources = Vec::new();
    let mut retained_sources = Vec::new();
    for source in outcome.sources {
      if let Some(stop) = projection_runtime.and_then(|runtime| runtime.check().err()) {
        projection_stop = Some(stop);
        break;
      }
      if source.profile.browser_id != identity.browser_id
        || source.profile.installation_id != identity.installation_id
        || source.profile.profile_id != identity.profile_id
      {
        retained_sources.push(source);
        continue;
      }
      let digest = source.source_digest();
      debug_assert_eq!(source.is_default_profile, is_default);
      let semantics = LegacyProjectionSemantics::for_source_format(source.source.format.as_str());
      let mut finalized_records = Vec::with_capacity(source.records.len());
      for record in source.records {
        if let Some(stop) = projection_runtime.and_then(|runtime| runtime.check().err()) {
          projection_stop = Some(stop);
          break;
        }
        finalized_records.push(record);
      }
      if projection_stop.is_some() {
        break;
      }
      let mut source_issues = Vec::new();
      let mut retained_failures = Vec::new();
      for failure in failures {
        match &failure.scope {
          FailureScope::Source {
            browser_id,
            installation_id,
            profile_id,
            source_digest,
          } if browser_id == &identity.browser_id
            && installation_id == &identity.installation_id
            && profile_id == &identity.profile_id
            && source_digest == &digest =>
          {
            source_issues.push(failure.into_issue())
          }
          _ => retained_failures.push(failure),
        }
      }
      failures = retained_failures;
      // A7: a row whose required host identity did not survive decode is
      // omitted rather than emitted as `domain: ""`, and the loss becomes a
      // source issue so the report still accounts for it. `extract` flattens
      // this same projection and inherits the omission; it has no channel for
      // the count, which is the stated cost of returning a bare list.
      let malformed_hosts = finalized_records
        .iter()
        .filter(|record| !record.has_host_identity())
        .count();
      let mut cookies = finalized_records
        .into_iter()
        .filter(super::cookie_record::FinalizedCookieRecord::has_host_identity)
        .map(|record| record.into_cookie_with_semantics(semantics))
        .collect::<Vec<_>>();
      sort_cookies(&mut cookies);
      if malformed_hosts > 0 {
        let mut malformed = issue(
          SourceIssue::MALFORMED_HOST_IDENTITY,
          // `decode` is the stage that produced the unusable value: the row
          // was read and parsed, and it is the decoded host that is missing.
          ExtractionStageCode::decode(),
          IssueSeverityCode::warning(),
          "cookie row has no host identity after decode",
        );
        malformed.occurrences = u32::try_from(malformed_hosts).unwrap_or(u32::MAX);
        push_aggregated(&mut source_issues, malformed);
      }
      // The engine counted these rows as emitted -- `cookies_emitted` is the
      // record count, set where the records were built -- and A7 removes them
      // afterwards, at projection time. Leaving the counters alone would break
      // the invariant the wire schema promises, `rows_seen - rows_skipped ==
      // cookies_emitted`, in the source, profile, and summary totals alike.
      // This reconciles by the exact number omitted rather than recomputing
      // from the cookie list, which the counters are deliberately never
      // derived from.
      let mut source_stats = source.stats;
      if malformed_hosts > 0 {
        let dropped = u32::try_from(malformed_hosts).unwrap_or(u32::MAX);
        source_stats.cookies_emitted = source_stats.cookies_emitted.saturating_sub(dropped);
        source_stats.rows_skipped = source_stats.rows_skipped.saturating_add(dropped);
        // A host that did not survive decode is a malformed stored field, so
        // it belongs to the `rows_rejected` subset of `rows_skipped` too.
        source_stats.rows_rejected = source_stats.rows_rejected.saturating_add(dropped);
      }
      stats.add(&source_stats);
      public_sources.push(SourceExtraction {
        source: source.source,
        status: source_status(source.failed),
        selected: source.selected,
        acquisition_strategy: source.acquisition_strategy,
        cookies,
        stats: source_stats,
        issues: source_issues,
      });
      if let Some(stop) = projection_runtime.and_then(|runtime| runtime.check().err()) {
        projection_stop = Some(stop);
        break;
      }
    }
    outcome.sources = retained_sources;
    public_sources.sort_by(|left, right| compare_source_identity(&left.source, &right.source));

    let mut profile_issues = Vec::new();
    let mut retained_failures = Vec::new();
    for failure in failures {
      match &failure.scope {
        FailureScope::Profile {
          browser_id,
          installation_id,
          profile_id,
        } if browser_id == &identity.browser_id
          && installation_id == &identity.installation_id
          && profile_id == &identity.profile_id =>
        {
          profile_issues.push(failure.into_issue())
        }
        _ => retained_failures.push(failure),
      }
    }
    failures = retained_failures;
    profiles.push(ProfileExtraction {
      profile: identity,
      sources: public_sources,
      stats: stats.into_stats(),
      issues: profile_issues,
    });
    if projection_stop.is_some() {
      break;
    }
  }
  if let Some(stop) = projection_stop {
    outcome.termination = termination_from_stop(stop);
    let projected_sources = profiles
      .iter()
      .map(|profile| profile.sources.len())
      .sum::<usize>();
    if projected_sources < outcome.counters.sources_discovered {
      outcome.result_status = if projected_sources == 0 {
        ResultStatus::Failed
      } else {
        ResultStatus::Partial
      };
    }
    outcome.counters.sources_succeeded = profiles
      .iter()
      .flat_map(|profile| &profile.sources)
      .filter(|source| source.status.as_str() == "succeeded")
      .count();
    outcome.counters.sources_failed = profiles
      .iter()
      .flat_map(|profile| &profile.sources)
      .filter(|source| source.status.as_str() == "failed")
      .count();
    outcome.counters.rows_seen = profiles
      .iter()
      .flat_map(|profile| &profile.sources)
      .map(|source| u64::from(source.stats.rows_seen))
      .sum();
    outcome.counters.cookies_emitted = profiles
      .iter()
      .flat_map(|profile| &profile.sources)
      .map(|source| u64::from(source.stats.cookies_emitted))
      .sum();
    outcome.counters.rows_skipped = profiles
      .iter()
      .flat_map(|profile| &profile.sources)
      .map(|source| u64::from(source.stats.rows_skipped))
      .sum();
    outcome.counters.rows_rejected = profiles
      .iter()
      .flat_map(|profile| &profile.sources)
      .map(|source| u64::from(source.stats.rows_rejected))
      .sum();
    outcome.counters.provider_failures = profiles
      .iter()
      .flat_map(|profile| &profile.sources)
      .map(|source| u64::from(source.stats.provider_failures))
      .sum();
  }
  append_stop_failure(
    &mut failures,
    &mut outcome.result_status,
    outcome.termination,
  );
  let issues = failures.into_iter().map(Failure::into_issue).collect();
  let mut saturated = outcome.counters.counters_saturated;
  let summary = ReportStats {
    registered_browsers: narrow(outcome.counters.registered_browsers, &mut saturated),
    browsers_detected: narrow(outcome.counters.browsers_detected, &mut saturated),
    browsers_not_detected: narrow(outcome.counters.browsers_not_detected, &mut saturated),
    installations_discovered: narrow(outcome.counters.installations_discovered, &mut saturated),
    profiles_discovered: narrow(outcome.counters.profiles_discovered, &mut saturated),
    sources_succeeded: narrow(outcome.counters.sources_succeeded, &mut saturated),
    sources_failed: narrow(outcome.counters.sources_failed, &mut saturated),
    rows_seen: u32::try_from(outcome.counters.rows_seen).unwrap_or_else(|_| {
      saturated = true;
      u32::MAX
    }),
    cookies_emitted: u32::try_from(outcome.counters.cookies_emitted).unwrap_or_else(|_| {
      saturated = true;
      u32::MAX
    }),
    rows_skipped: u32::try_from(outcome.counters.rows_skipped).unwrap_or_else(|_| {
      saturated = true;
      u32::MAX
    }),
    rows_rejected: u32::try_from(outcome.counters.rows_rejected).unwrap_or_else(|_| {
      saturated = true;
      u32::MAX
    }),
    provider_failures: u32::try_from(outcome.counters.provider_failures).unwrap_or_else(|_| {
      saturated = true;
      u32::MAX
    }),
    counters_saturated: saturated,
  };
  let status = match outcome.result_status {
    ResultStatus::Complete => ReportStatusCode::complete(),
    ResultStatus::Partial => ReportStatusCode::partial(),
    ResultStatus::Failed => ReportStatusCode::failed(),
    ResultStatus::NoSources => ReportStatusCode::no_sources(),
  };
  (
    ExtractionReport {
      schema_version: super::report_core::EXTRACTION_REPORT_SCHEMA_VERSION,
      status,
      termination: match outcome.termination {
        Termination::Completed => TerminationCode::completed(),
        Termination::Cancelled => TerminationCode::cancelled(),
        Termination::TimedOut => TerminationCode::timed_out(),
        Termination::ResourceExhausted => TerminationCode::resource_exhausted(),
      },
      summary,
      profiles,
      issues,
    },
    outcome.termination,
  )
}

/// Schema-v1-compatible representation of work that stopped before the report
/// could finish. Version 1 has no `unattempted` counter, so the exact stop is
/// carried by `termination` plus an error-severity request issue. This keeps
/// an empty stopped run out of `no_sources` without adding a wire field.
fn append_stop_failure(
  failures: &mut Vec<Failure>,
  status: &mut ResultStatus,
  termination: Termination,
) {
  let (code, message) = match termination {
    Termination::Completed => return,
    Termination::TimedOut => (
      "request_timed_out",
      "cookie extraction stopped because its deadline expired",
    ),
    Termination::Cancelled => (
      "request_cancelled",
      "cookie extraction stopped because cancellation was requested",
    ),
    Termination::ResourceExhausted => (
      "request_resource_exhausted",
      "cookie extraction stopped because its resource budget was exhausted",
    ),
  };
  if !failures
    .iter()
    .any(|failure| failure.code.as_str() == code && matches!(&failure.scope, FailureScope::Request))
  {
    failures.push(Failure::from_issue(
      issue(
        code,
        ExtractionStageCode::registry(),
        IssueSeverityCode::error(),
        message,
      ),
      FailureScope::Request,
      &[],
    ));
  }
  *status = match *status {
    ResultStatus::Complete => ResultStatus::Partial,
    ResultStatus::NoSources => ResultStatus::Failed,
    ResultStatus::Partial => ResultStatus::Partial,
    ResultStatus::Failed => ResultStatus::Failed,
  };
}

/// Adds to a wire counter, recording any clamp. Every `ReportStats` counter is
/// `u32` for exact Node/TypeScript representation, so a count that hits the
/// ceiling must set `counters_saturated` rather than quietly read as exact.
fn narrow(value: usize, saturated: &mut bool) -> u32 {
  u32::try_from(value).unwrap_or_else(|_| {
    *saturated = true;
    u32::MAX
  })
}

fn finalize_outcomes(registered_browsers: usize, outcomes: Vec<BrowserDraft>) -> Outcome {
  finalize_outcomes_with_runtime(registered_browsers, outcomes, None)
}

fn finalize_outcomes_with_runtime(
  registered_browsers: usize,
  outcomes: Vec<BrowserDraft>,
  runtime: Option<&BoundaryRuntime<'_>>,
) -> Outcome {
  // A stop observed while acquiring one browser is already represented on
  // that browser's draft. Every other draft in `outcomes` -- earlier AND
  // later, since browsers are now claimed concurrently and a later-registry
  // browser can finish before an earlier one notices the shared stop -- is
  // immutable completed (or partially completed) work and must survive even
  // though the shared stop token is now terminal.
  let has_preexisting_stop = outcomes
    .iter()
    .any(|outcome| outcome.termination != Termination::Completed);
  let mut profiles = Vec::new();
  let mut sources = Vec::new();
  let mut ledger = FailureLedger::default();
  let mut browsers_detected = 0;
  let mut browsers_not_detected = 0;
  let mut installations_discovered = 0;
  let mut discovery_failed = false;
  let mut termination = Termination::Completed;
  let mut compatibility_inputs = Vec::with_capacity(outcomes.len());
  let mut compatibility_evidence = BTreeMap::new();

  'browsers: for outcome in outcomes {
    let outcome_stopped = outcome.termination != Termination::Completed;
    let finalization_runtime = (!has_preexisting_stop && !outcome_stopped)
      .then_some(runtime)
      .flatten();
    if let Some(stop) = finalization_runtime.and_then(|runtime| runtime.check().err()) {
      termination = termination_from_stop(stop);
      break;
    }
    if outcome_stopped && termination == Termination::Completed {
      termination = outcome.termination;
    }
    compatibility_inputs.push((outcome.browser_id.clone(), outcome.compatibility_family));
    discovery_failed |= outcome.discovery_failed;
    if outcome.detected {
      browsers_detected += 1;
    } else if !outcome_stopped {
      // Schema v1 has no unattempted/unknown counter. A stopped browser whose
      // discovery never established presence or absence belongs in neither
      // bucket; `append_stop_failure` makes that state explicit on the wire.
      browsers_not_detected += 1;
    }
    installations_discovered += outcome.installations_discovered;
    for issue in outcome.issues {
      if let Some(stop) = finalization_runtime.and_then(|runtime| runtime.check().err()) {
        termination = termination_from_stop(stop);
        break 'browsers;
      }
      let scope = issue
        .browser_id
        .clone()
        .map_or(FailureScope::Request, |browser_id| FailureScope::Browser {
          browser_id,
        });
      ledger.push(Failure::from_issue(issue, scope, &[]));
    }
    for engine in outcome.profiles {
      if let Some(stop) = canonicalize_profile(
        engine,
        &mut profiles,
        &mut sources,
        &mut ledger,
        &mut compatibility_evidence,
        finalization_runtime,
      ) {
        termination = termination_from_stop(stop);
        break 'browsers;
      }
    }
    // Do not `break` here: under concurrent fan-out, a stopped draft is no
    // longer guaranteed to be the last entry in `outcomes` -- a browser
    // claimed after it may have already finished successfully. Stopping the
    // loop here would silently discard that already-completed sibling work.
  }
  let discovered_any_source = !sources.is_empty() || discovery_failed;
  let mut outcome = Outcome::finalize(
    profiles,
    sources,
    ledger,
    discovered_any_source,
    termination,
  );
  outcome.counters.registered_browsers = registered_browsers;
  outcome.counters.browsers_detected = browsers_detected;
  outcome.counters.browsers_not_detected = browsers_not_detected;
  outcome.counters.installations_discovered = installations_discovered;
  let compatibility_runtime = (!has_preexisting_stop
    && outcome.termination == Termination::Completed)
    .then_some(runtime)
    .flatten();
  for (browser_id, family) in compatibility_inputs {
    if let Some(stop) = compatibility_runtime.and_then(|runtime| runtime.check().err()) {
      outcome.termination = termination_from_stop(stop);
      break;
    }
    outcome.compatibility.push(compatibility_decision(
      &outcome,
      &compatibility_evidence,
      browser_id,
      family,
    ));
  }
  outcome
}

#[cfg(test)]
fn assemble(registered_browsers: usize, outcomes: Vec<BrowserDraft>) -> ExtractionReport {
  project_canonical_report(finalize_outcomes(registered_browsers, outcomes))
}

fn assemble_with_runtime(
  registered_browsers: usize,
  outcomes: Vec<BrowserDraft>,
  runtime: &BoundaryRuntime<'_>,
) -> (ExtractionReport, Termination) {
  let outcome = finalize_outcomes_with_runtime(registered_browsers, outcomes, Some(runtime));
  project_canonical_report_with_runtime(outcome, Some(runtime))
}

/// Finalizes a single-browser [`EngineExtract`] (Gecko/Safari/IE report path and
/// direct-path).
pub(crate) fn canonical_engine_extract(
  browser_id: &str,
  extract: EngineExtract,
) -> Result<Outcome> {
  let browser_id: BrowserId = browser_id.parse()?;
  Ok(finalize_outcomes(
    1,
    vec![engine_extract_outcome(&browser_id, extract)?],
  ))
}

#[cfg(test)]
pub(crate) fn project_engine_extract(
  browser_id: &str,
  extract: EngineExtract,
) -> Result<ExtractionReport> {
  Ok(project_canonical_report(canonical_engine_extract(
    browser_id, extract,
  )?))
}

/// [`canonical_engine_extract`] with a deadline, over any engine's extract bag
/// -- Gecko, Safari, and Internet Explorer all route through it.
pub(crate) fn canonical_engine_extract_with_runtime(
  browser_id: &str,
  extract: EngineExtract,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Outcome> {
  let browser_id: BrowserId = browser_id.parse()?;
  Ok(finalize_outcomes_with_runtime(
    1,
    vec![engine_extract_outcome(&browser_id, extract)?],
    Some(runtime),
  ))
}

#[cfg(test)]
pub(crate) fn canonical_chromium_extraction(
  browser_id: &str,
  report: ChromiumRegistryDraft,
) -> Result<Outcome> {
  let browser_id: BrowserId = browser_id.parse()?;
  Ok(finalize_outcomes(
    1,
    vec![chromium_browser_outcome(&browser_id, report)?],
  ))
}

pub(crate) fn canonical_chromium_extraction_with_runtime(
  browser_id: &str,
  report: ChromiumRegistryDraft,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Outcome> {
  let browser_id: BrowserId = browser_id.parse()?;
  Ok(finalize_outcomes_with_runtime(
    1,
    vec![chromium_browser_outcome(&browser_id, report)?],
    Some(runtime),
  ))
}

/// Finalizes one direct-path read: the caller named a file, so there is exactly
/// one profile and no discovery to consult.
///
/// This replaces the four `canonical_direct_*` helpers, which had converged on
/// the same body once every engine started returning `Source`. Chromium's kept
/// a hand-built `ProfileIdentity` / `BrowserDraft` beside the shared one; both
/// produce the same report, because `profile_identity` applies the same
/// `display_path` and the synthetic counters make `all_detected_roots_failed()`
/// false either way.
///
/// `profile_path` is a parameter rather than derived from `sources`: a Gecko
/// profile whose persistent store was never attempted leads with a session
/// source, and `sessionstore-backups/recovery.baklz4` does not have the profile
/// directory as its parent.
pub(crate) fn finalize_singleton_source(
  browser_id: &str,
  profile_path: std::path::PathBuf,
  sources: Vec<Source>,
  boundary_stop: Option<BoundaryStop>,
  runtime: Option<&BoundaryRuntime<'_>>,
) -> Result<Outcome> {
  let extract = direct_engine_extract(profile_path, sources, boundary_stop);
  match runtime {
    Some(runtime) => canonical_engine_extract_with_runtime(browser_id, extract, runtime),
    None => canonical_engine_extract(browser_id, extract),
  }
}

/// The synthetic single-profile [`EngineExtract`] every direct-path helper
/// wraps its already-acquired [`Source`]s in. The frozen synthetic identity
/// (`"0"*64` installation, `"1"*64` profile, display name `direct`) is Decision
/// 10 and must not change.
fn direct_engine_extract(
  profile_path: std::path::PathBuf,
  sources: Vec<Source>,
  boundary_stop: Option<BoundaryStop>,
) -> EngineExtract {
  EngineExtract {
    profiles: vec![ExtractedProfile {
      identity: registry::EngineProfileIdentity {
        profile_id: "1"
          .repeat(64)
          .parse()
          .expect("synthetic profile id is valid"),
        installation_id: "0"
          .repeat(64)
          .parse()
          .expect("synthetic installation id is valid"),
        installation_priority: 0,
        installation_path: profile_path.clone(),
        name: "direct".to_owned(),
        path: profile_path.clone(),
        is_default: true,
        persistent_source_discovered: true,
      },
      legacy: registry::LegacyRank {
        installation_priority: 0,
        profile_order: 0,
        is_default: true,
        eligible: true,
        installation_path: profile_path,
        name: "direct".to_owned(),
      },
      sources,
    }],
    discovery_issues: Vec::new(),
    counters: registry::DiscoveryCounters {
      installations_discovered: 1,
      installations_detected: 1,
      installations_enumerated: 1,
    },
    boundary_stop,
  }
}

/// Private `browser_report` seam. An unknown browser or profile ID is a request
/// error; a known but absent browser is an `Ok` report with `no_sources`.
#[cfg(test)]
pub(crate) fn browser_extraction_report(
  browser_id: &str,
  selection: registry::ProfileSelection<'_>,
  domains: Option<Vec<String>>,
) -> Result<ExtractionReport> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  browser_extraction_report_with_runtime(
    browser_id,
    selection,
    domains,
    crate::SessionPolicy::IncludeSession,
    &runtime,
  )
}

/// Report-shaped seam. Report jobs return a stop as an `Ok` report whose
/// `termination` is not `completed`, so they never need the typed value.
pub(crate) fn browser_extraction_report_with_runtime(
  browser_id: &str,
  selection: registry::ProfileSelection<'_>,
  domains: Option<Vec<String>>,
  session: crate::SessionPolicy,
  runtime: &BoundaryRuntime<'_>,
) -> Result<ExtractionReport> {
  browser_extraction_outcome_with_runtime(browser_id, selection, domains, session, runtime)
    .map(|(report, _termination)| report)
}

/// Flatten-shaped seam: the same work, plus the typed [`Termination`] the DTO
/// string was projected from. `extract` and profile-scoped `read` must turn a
/// stop into `Error::Stopped`, and they classify it from this enum rather than
/// re-parsing `ExtractionReport::termination`.
pub(crate) fn browser_extraction_outcome_with_runtime(
  browser_id: &str,
  selection: registry::ProfileSelection<'_>,
  domains: Option<Vec<String>>,
  session: crate::SessionPolicy,
  runtime: &BoundaryRuntime<'_>,
) -> Result<(ExtractionReport, Termination)> {
  let browser = registry::resolve_registered_browser(browser_id)?;
  let canonical_id = &browser.canonical_id;
  // Report-shaped callers pass `IncludeSession`: a report's whole point is to
  // describe every source the profile declares. `extract` is the one caller
  // that passes the request's own policy, because it produces a flat list and
  // must honor a caller who asked not to touch the session store.
  let mut outcome = match collect_extraction(&browser, selection, domains, session, runtime) {
    Ok(outcome) => outcome,
    Err(error) => match stop_from_error(&error) {
      Some(stop) => stopped_browser_draft(&browser, stop)?,
      None => return Err(error),
    },
  };
  // Every engine seam now applies the selection itself, before it acquires a
  // single source, so by here the list is already narrowed. This stays as the
  // boundary check for the one case no engine covers: a registered browser
  // whose engine has no adapter compiled into this build reports no profiles at
  // all, and an unknown profile id must still be a request error there.
  if outcome.termination == Termination::Completed {
    // Only an explicit profile id needs this: `LegacyFirstProfile` and
    // `AllProfiles` are both narrowed by the engine itself, and neither can
    // name a profile that does not exist.
    if let registry::ProfileSelection::ProfileId(profile_id) = selection {
      if !outcome
        .profiles
        .iter()
        .any(|profile| profile.profile.profile_id.as_str() == profile_id)
      {
        bail!("unknown {canonical_id} profile id {profile_id:?}")
      }
      outcome
        .profiles
        .retain(|profile| profile.profile.profile_id.as_str() == profile_id);
    }
  }
  // A browser whose roots were found but could not be read is detected-and-
  // failed, not absent. Saying "not detected" beside a `failed` status would
  // describe two different worlds in one report.
  if !outcome.detected && !outcome.discovery_failed && outcome.termination == Termination::Completed
  {
    let id: BrowserId = canonical_id.parse()?;
    push_aggregated(
      &mut outcome.issues,
      issue(
        "browser_not_detected",
        ExtractionStageCode::discovery(),
        IssueSeverityCode::info(),
        format!("no {canonical_id} installation was detected"),
      )
      .with_context(Some(&id), None, None),
    );
  }
  Ok(assemble_with_runtime(1, vec![outcome], runtime))
}

/// Private `load_report` seam. Uninstalled registered browsers are summarized
/// in counters instead of emitting a per-browser warning.
pub(crate) fn load_extraction_report(
  domains: Option<Vec<String>>,
  control: &ExecutionControl,
) -> Result<ExtractionReport> {
  let clock = SystemClock;
  let runtime = runtime_for_control(&clock, control);
  load_extraction_report_with_runtime(domains, &runtime)
}

fn load_extraction_report_with_runtime(
  domains: Option<Vec<String>>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<ExtractionReport> {
  let browsers = registry::registered_browsers()?;
  // Browsers are probed concurrently on a small bounded pool sharing this
  // one deadline/cancellation budget (see `common::concurrency::fan_out`), so
  // a slow or hung browser no longer starves the others' share of it.
  // `fan_out` claims browsers in registry order and returns results only for
  // the contiguous prefix it actually claimed, in that same order -- so
  // `outcomes` below always ends up in registry order regardless of which
  // browser's collection finished first, matching the ordering contract the
  // rest of this module already relies on.
  let attempts = fan_out(&browsers, DEFAULT_FAN_OUT_WIDTH, runtime, |browser| {
    collect_extraction(
      browser,
      registry::ProfileSelection::AllProfiles,
      domains.clone(),
      crate::SessionPolicy::IncludeSession,
      runtime,
    )
  });
  // `fan_out` silently stops claiming further browsers once the runtime
  // trips, so a shorter-than-`browsers` result set is itself evidence of a
  // stop even if no individual browser's own attempt happened to observe
  // and report it. That case is folded in below, after the loop.
  let claimed = attempts.len();
  let mut outcomes = Vec::with_capacity(attempts.len());
  for (browser, attempt) in browsers.iter().zip(attempts) {
    match attempt {
      Ok(outcome) => outcomes.push(outcome),
      // A browser whose whole discovery failed must not erase the other
      // browsers' results; it is recorded as an error-severity issue.
      Err(error) => {
        if let Some(stop) = stop_from_error(&error) {
          outcomes.push(stopped_browser_draft(browser, stop)?);
          continue;
        }
        let id: BrowserId = browser.canonical_id.parse()?;
        outcomes.push(BrowserDraft {
          browser_id: id.clone(),
          compatibility_family: match browser.engine {
            "chromium" => CompatibilityFamily::Chromium,
            "safari" => CompatibilityFamily::Safari,
            "internet_explorer" => CompatibilityFamily::InternetExplorer,
            _ => CompatibilityFamily::Gecko,
          },
          detected: false,
          installations_discovered: 0,
          discovery_failed: true,
          profiles: Vec::new(),
          issues: vec![issue(
            "browser_discovery_failed",
            ExtractionStageCode::discovery(),
            IssueSeverityCode::error(),
            format!("{error:#}"),
          )
          .with_context(Some(&id), None, None)],
          termination: Termination::Completed,
        });
      }
    }
  }
  if claimed < browsers.len()
    && !outcomes
      .iter()
      .any(|outcome| outcome.termination != Termination::Completed)
  {
    if let Some(stop) = runtime.check().err() {
      outcomes.push(stopped_browser_draft(&browsers[claimed], stop)?);
    }
  }
  Ok(assemble_with_runtime(browsers.len(), outcomes, runtime).0)
}

/// Private `browser_profiles` seam. An unknown ID fails; a known browser with
/// no detected installation returns an empty list; a browser whose every
/// detected root failed enumeration fails rather than returning an
/// indistinguishable empty list.
pub(crate) fn browser_profile_descriptors(
  browser_id: &str,
  control: &ExecutionControl,
) -> Result<Vec<ProfileDescriptor>> {
  let clock = SystemClock;
  let runtime = runtime_for_control(&clock, control);
  let browser = registry::resolve_registered_browser(browser_id)?;
  let outcome = collect_listing(&browser, &runtime)?;
  profile_descriptors_from_outcome(browser_id, outcome)
}

fn stopped_browser_draft(browser: &RegisteredBrowser, stop: BoundaryStop) -> Result<BrowserDraft> {
  let browser_id: BrowserId = browser.canonical_id.parse()?;
  Ok(BrowserDraft {
    browser_id,
    compatibility_family: match browser.engine {
      "chromium" => CompatibilityFamily::Chromium,
      "safari" => CompatibilityFamily::Safari,
      "internet_explorer" => CompatibilityFamily::InternetExplorer,
      _ => CompatibilityFamily::Gecko,
    },
    detected: false,
    installations_discovered: 0,
    discovery_failed: false,
    profiles: Vec::new(),
    issues: Vec::new(),
    termination: termination_from_stop(stop),
  })
}

/// Chrome-specific listing whose first entry follows the advisory `Local
/// State` activity hints. The generic `browser_profiles("chrome")` path keeps
/// its frozen default-first order.
pub(crate) fn chrome_profile_descriptors(
  control: &ExecutionControl,
) -> Result<Vec<ProfileDescriptor>> {
  let clock = SystemClock;
  let runtime = runtime_for_control(&clock, control);
  let browser_id = BrowserId::known("chrome");
  registry::chrome_profiles_with_runtime(&runtime)?
    .into_iter()
    .map(|profile| chromium_profile_descriptor(&browser_id, profile))
    .collect()
}

/// Resolves a human-facing Chrome profile selector and then uses the same
/// report pipeline as an opaque-ID `browser_report` request. Re-discovery is
/// deliberate: the report must retain current typed discovery/source outcomes
/// rather than flattening the selected source into the legacy cookie vector.
#[allow(dead_code)]
pub(crate) fn chrome_profile_report(
  profile: &str,
  domains: Option<Vec<String>>,
) -> Result<ExtractionReport> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  let profile_id = registry::resolve_profile_query("chrome", profile, &runtime)?;
  browser_extraction_report_with_runtime(
    "chrome",
    registry::ProfileSelection::ProfileId(profile_id.as_str()),
    domains,
    crate::SessionPolicy::IncludeSession,
    &runtime,
  )
}

fn chromium_profile_descriptor(
  browser_id: &BrowserId,
  profile: registry::ChromiumProfile,
) -> Result<ProfileDescriptor> {
  let identity = profile_identity(
    browser_id,
    profile.installation_id.as_str(),
    profile.profile_id.as_str(),
    &profile.display_name,
    &profile.path,
  )?;
  let mut sources = profile
    .persistent_candidates
    .into_iter()
    .filter(|candidate| candidate.exists)
    .map(|candidate| {
      // Reads the candidate's own role and format instead of restating
      // `SOURCE_ROLE_PERSISTENT` / "chromium_sqlite": Chromium's only
      // persistent plant sets exactly those, so this is the same bytes with
      // one fewer place for them to drift.
      let source = source_identity(&candidate.identity());
      CookieSourceDescriptor {
        role: source.role,
        format: source.format,
        path: source.path,
        path_lossy: source.path_lossy,
        precedence: source.precedence,
      }
    })
    .collect::<Vec<_>>();
  sort_source_descriptors(&mut sources);
  Ok(ProfileDescriptor {
    profile: identity,
    is_default: profile.is_default,
    sources,
  })
}

fn profile_descriptors_from_outcome(
  browser_id: &str,
  outcome: BrowserListing,
) -> Result<Vec<ProfileDescriptor>> {
  // A stop the engine recorded rather than returned still ended discovery
  // early. The profiles found before it are a prefix, not a result, and this
  // seam returns a bare list with no room to say so -- so the stop is raised
  // here, matching the `runtime.check()?` checkpoints that guard the same job.
  if let Some(stop) = outcome.boundary_stop {
    return Err(stop.into());
  }
  // An empty list must mean "looked, found nothing". Roots that all failed to
  // enumerate are one way to lose everything; profiles that were all found and
  // then all failed is another, and both would otherwise be indistinguishable
  // from an uninstalled browser. The listing type cannot carry issues, so the
  // ones that caused the loss are reported in the error rather than dropped at
  // this boundary.
  let errors = |issues: &[ExtractionIssue], profile_scoped: bool| {
    issues
      .iter()
      .filter(|issue| {
        // Codes naming a profile describe losing that profile. A root-level
        // failure beside another root that enumerated cleanly is not profile
        // loss: Section 5.7 keeps that an `Ok` result.
        issue.is_error() && (!profile_scoped || issue.code.as_str().starts_with("profile_"))
      })
      .map(|issue| issue.message.clone())
      // Bounded for the same reason issue samples are: a profile tree full of
      // the same defect must not decide how long an error message is.
      .take(MAX_ISSUE_SAMPLES)
      .collect::<Vec<_>>()
  };
  if outcome.discovery_failed {
    return Err(
      EngineFailure::new(
        EngineCause::DiscoveryFailed,
        format!(
          "every detected {browser_id} installation failed profile enumeration: {}",
          errors(&outcome.issues, false).join("; ")
        ),
      )
      .into(),
    );
  }
  let lost_profiles = errors(&outcome.issues, true);
  if outcome.profiles.is_empty() && !lost_profiles.is_empty() {
    return Err(
      EngineFailure::new(
        EngineCause::DiscoveryFailed,
        format!(
          "every discovered {browser_id} profile failed discovery: {}",
          lost_profiles.join("; ")
        ),
      )
      .into(),
    );
  }
  // Every engine already builds the wire `ProfileDescriptor` (sources sorted)
  // as it lists, so there is nothing left to adapt here.
  Ok(outcome.profiles)
}

#[cfg(test)]
mod tests;

/// End-to-end coverage of the real engine chain: registry discovery and
/// extraction on a fixture tree, through each engine's adapter, into the frozen
/// report. Constructing outcomes by hand cannot prove an engine reaches the
/// contract at all, which is how a Chromium profile whose discovery failed came
/// to be reported as ordinary absence.
#[cfg(test)]
mod engine_chain_tests;
