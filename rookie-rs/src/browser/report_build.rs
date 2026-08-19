//! Cross-engine report assembly.
//!
//! Every registered engine reaches the frozen [`super::report_core`] contract
//! through this module. The four entry points at the bottom back the public
//! [`crate::supported_browsers`], [`crate::browser_profiles`],
//! [`crate::browser_report`], and [`crate::load_report`].

mod dispatch;

#[cfg(test)]
use super::cookie_record::CookieRecord;
use super::cookie_record::{FinalizationError, LegacyProjectionSemantics};
use super::outcome::{
  CompatibilityAbsence, CompatibilityDecision, CompatibilityDisposition, Diagnostic, Failure,
  FailureLedger, FailureScope, Outcome, ResultStatus, SourceOutcome, Termination,
};
use super::registry::{
  self, ChromiumExtractedProfile, ChromiumRegistryDraft, DiscoveredProfile, DiscoveryIssue,
  EngineExtract, EngineListing, ExtractedProfile, RegisteredBrowser, SourceAcquisition,
  SOURCE_ROLE_PERSISTENT,
};
#[cfg(test)]
use super::report_core::SourceStatusCode;
use super::report_core::{
  compare_source_identity, display_path, issue, push_aggregated, sort_cookies,
  sort_source_descriptors, source_status, AcquisitionStrategyCode, BrowserCapabilitiesDescriptor,
  BrowserDescriptor, BrowserId, CipherTierId, CompatibilityEvidence, CookieSourceDescriptor,
  CookieSourceFormatId, CookieSourceIdentity, CookieSourceRoleId, CounterSet, EngineId,
  ExtractionIssue, ExtractionReport, ExtractionStageCode, InstallationId, IssueSeverityCode,
  ProfileDescriptor, ProfileDraft, ProfileExtraction, ProfileId, ProfileIdentity, ReportStats,
  ReportStatusCode, SourceDraft, SourceExtraction, StatsAccumulator, TerminationCode,
  MAX_ISSUE_SAMPLES,
};
use super::source::{Source, SourceFailureStage as SourceFailureStageNew, SourceIssue};
#[cfg(test)]
use super::source::{SourceCandidate, SourceStats};
use crate::common::concurrency::{fan_out, DEFAULT_FAN_OUT_WIDTH};
use crate::common::deadline::{BoundaryRuntime, BoundaryStop, SystemClock};
use crate::common::sqlite::DatabaseAcquisitionStrategy;
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

fn source_identity(
  path: &std::path::Path,
  role: &str,
  format: &str,
  precedence: u16,
) -> CookieSourceIdentity {
  let (path, path_lossy) = display_path(path);
  CookieSourceIdentity {
    role: CookieSourceRoleId::known(role),
    format: CookieSourceFormatId::known(format),
    path,
    path_lossy,
    precedence,
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
fn chromium_profile_outcome(
  browser_id: &BrowserId,
  installation_id: &str,
  extraction: ChromiumExtractedProfile,
) -> Result<ProfileDraft> {
  let ChromiumExtractedProfile {
    profile,
    sources,
    failure,
  } = extraction;
  let identity = profile_identity(
    browser_id,
    installation_id,
    profile.profile_id.as_str(),
    &profile.display_name,
    &profile.path,
  )?;
  let mut outcome = ProfileDraft::new(identity, profile.is_default);

  if sources.is_empty() {
    // A profile that simply has no cookie database is ordinary absence, but one
    // that reports an extraction failure lost something, so it must not be
    // downgraded to the same `info` signal as an empty profile.
    outcome.issues.push(match failure {
      Some(message) => issue(
        "profile_extraction_failed",
        ExtractionStageCode::acquisition(),
        IssueSeverityCode::error(),
        message,
      ),
      None => issue(
        "profile_has_no_cookie_source",
        ExtractionStageCode::discovery(),
        IssueSeverityCode::info(),
        "profile has no selected persistent source",
      ),
    });
    return Ok(outcome);
  }

  outcome
    .sources
    .extend(sources.into_iter().map(source_to_draft));
  Ok(outcome)
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
    source_identity(
      &origin.path,
      origin.role.as_str(),
      origin.format.as_str(),
      origin.precedence,
    ),
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
  let mut outcome = ProfileDraft::new(identity, profile.identity.is_default);
  for source in profile.sources {
    outcome.sources.push(source_to_draft(source));
  }
  if outcome.sources.is_empty() {
    // Discovery only admits a profile when it found either a persistent
    // database or a session candidate, so a profile that reaches extraction
    // with zero sources means whatever justified its admission is gone by the
    // time of extraction. That is a real failure, not the "nothing was ever
    // there" case `no_sources` means. Discovery-only profiles on a stopped
    // extract are pruned before this adapter and never reach this branch.
    push_aggregated(
      &mut outcome.issues,
      issue(
        "profile_extraction_failed",
        ExtractionStageCode::acquisition(),
        IssueSeverityCode::error(),
        "a cookie source present at discovery could not be found by the time of extraction",
      ),
    );
  }
  Ok(outcome)
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompatibilityFamily {
  Chromium,
  Gecko,
  Safari,
  InternetExplorer,
}

fn engine_compatibility_family(browser_id: &BrowserId) -> CompatibilityFamily {
  match browser_id.as_str() {
    "safari" => CompatibilityFamily::Safari,
    "internet_explorer" => CompatibilityFamily::InternetExplorer,
    _ => CompatibilityFamily::Gecko,
  }
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
    for profile in installation.profiles {
      outcome.profiles.push(chromium_profile_outcome(
        browser_id,
        &installation.installation_id,
        profile,
      )?);
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
    outcome
      .profiles
      .push(extracted_profile_outcome(browser_id, profile)?);
  }
  Ok(outcome)
}

/// Adapts a Gecko listing into a browser draft (`browser_profiles`).
///
/// Every discovered candidate becomes a `not_attempted` source descriptor with
/// its frozen `selected`/`acquisition`; there is no `exists` filter (Gecko
/// candidates are all `exists: true`). Empty candidates are ordinary listing
/// emptiness, never `profile_extraction_failed` — that error is extract-only.
fn engine_listing_outcome(browser_id: &BrowserId, listing: EngineListing) -> Result<BrowserDraft> {
  let mut outcome = BrowserDraft {
    browser_id: browser_id.clone(),
    compatibility_family: engine_compatibility_family(browser_id),
    detected: listing.counters.installations_discovered > 0
      || listing.counters.installations_detected > 0,
    installations_discovered: listing.counters.installations_discovered,
    discovery_failed: listing.all_detected_roots_failed(),
    profiles: Vec::new(),
    issues: Vec::new(),
    // Listing never acquires, so a request stop during discovery is the only
    // termination it can carry.
    termination: listing
      .boundary_stop
      .map_or(Termination::Completed, termination_from_stop),
  };
  for discovery in &listing.discovery_issues {
    push_aggregated(&mut outcome.issues, discovery_issue(browser_id, discovery));
  }
  for profile in listing.profiles {
    outcome
      .profiles
      .push(discovered_profile_outcome(browser_id, profile)?);
  }
  Ok(outcome)
}

fn discovered_profile_outcome(
  browser_id: &BrowserId,
  profile: DiscoveredProfile,
) -> Result<ProfileDraft> {
  let identity = profile_identity(
    browser_id,
    profile.identity.installation_id.as_str(),
    profile.identity.profile_id.as_str(),
    &profile.identity.name,
    &profile.identity.path,
  )?;
  let mut outcome = ProfileDraft::new(identity, profile.identity.is_default);
  for candidate in profile.candidates {
    outcome.sources.push(SourceDraft::new(
      source_identity(
        &candidate.path,
        candidate.role.as_str(),
        candidate.format.as_str(),
        candidate.precedence,
      ),
      &candidate.path,
      candidate.selected,
      acquisition_code(candidate.acquisition),
    ));
  }
  Ok(outcome)
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

fn collect_report(
  browser: &RegisteredBrowser,
  profile_id: Option<&str>,
  extract: bool,
  domains: Option<Vec<String>>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<BrowserDraft> {
  runtime.check()?;
  let browser_id: BrowserId = browser.canonical_id.parse()?;
  match browser.engine {
    "chromium" => {
      let report = if extract {
        registry::chromium_registry_report_with_runtime(
          &browser.canonical_id,
          profile_id,
          domains,
          runtime,
        )?
      } else {
        return chromium_listing_outcome(&browser_id, &browser.canonical_id, runtime);
      };
      chromium_browser_outcome(&browser_id, report)
    }
    "gecko" => {
      if extract {
        let engine =
          registry::gecko_report_with_runtime(&browser.canonical_id, profile_id, domains, runtime)?;
        engine_extract_outcome(&browser_id, engine)
      } else {
        let listing = registry::gecko_profiles_with_runtime(&browser.canonical_id, runtime)?;
        engine_listing_outcome(&browser_id, listing)
      }
    }
    engine => dispatch::remaining_engine_report(
      &browser_id,
      &browser.canonical_id,
      engine,
      profile_id,
      extract,
      domains,
      runtime,
    ),
  }
}

fn chromium_listing_outcome(
  browser_id: &BrowserId,
  canonical_id: &str,
  runtime: &BoundaryRuntime<'_>,
) -> Result<BrowserDraft> {
  let listing = registry::chromium_listing_with_runtime(canonical_id, runtime)?;
  let mut outcome = BrowserDraft {
    browser_id: browser_id.clone(),
    compatibility_family: CompatibilityFamily::Chromium,
    detected: listing.installations_discovered > 0,
    installations_discovered: listing.installations_discovered,
    discovery_failed: listing.all_detected_roots_failed,
    profiles: Vec::new(),
    issues: Vec::new(),
    termination: Termination::Completed,
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
    let mut engine = ProfileDraft::new(identity, profile.is_default);
    for candidate in &profile.persistent_candidates {
      // Chromium listing policy, not a property of `SourceCandidate`: this
      // engine stats both layouts and lists only what is on disk, while the
      // engine listing plants `exists: true` candidates that must all survive.
      if !candidate.exists {
        continue;
      }
      engine.sources.push(SourceDraft::new(
        source_identity(
          &candidate.path,
          candidate.role.as_str(),
          candidate.format.as_str(),
          candidate.precedence,
        ),
        &candidate.path,
        candidate.selected,
        acquisition_code(candidate.acquisition),
      ));
    }
    outcome.profiles.push(engine);
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
          let kind = match error {
            FinalizationError::Encrypted => "encrypted",
            FinalizationError::Unavailable(_) => "unavailable",
          };
          ledger.push(Failure::from_issue(
            issue(
              "invalid_final_record",
              ExtractionStageCode::decode(),
              IssueSeverityCode::error(),
              format!("{kind} cookie value rejected before canonical finalization"),
            ),
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
  project_canonical_report_with_runtime(outcome, None)
}

fn project_canonical_report_with_runtime(
  mut outcome: Outcome,
  runtime: Option<&BoundaryRuntime<'_>>,
) -> ExtractionReport {
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
      let mut cookies = finalized_records
        .into_iter()
        .map(|record| record.into_cookie_with_semantics(semantics))
        .collect::<Vec<_>>();
      sort_cookies(&mut cookies);
      stats.add(&source.stats);
      public_sources.push(SourceExtraction {
        source: source.source,
        status: source_status(source.failed),
        selected: source.selected,
        acquisition_strategy: source.acquisition_strategy,
        cookies,
        stats: source.stats,
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
  }
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
    } else {
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

fn compatibility_decision(
  outcome: &Outcome,
  compatibility_evidence: &BTreeMap<[u8; 32], Diagnostic>,
  browser_id: BrowserId,
  family: CompatibilityFamily,
) -> CompatibilityDecision {
  let disposition = compatibility_disposition(outcome, compatibility_evidence, &browser_id, family);
  CompatibilityDecision {
    browser_id,
    disposition,
  }
}

fn compatibility_disposition(
  outcome: &Outcome,
  compatibility_evidence: &BTreeMap<[u8; 32], Diagnostic>,
  browser_id: &BrowserId,
  family: CompatibilityFamily,
) -> CompatibilityDisposition {
  let Some((profile, _)) = outcome
    .profiles
    .iter()
    .find(|(profile, _)| &profile.browser_id == browser_id)
  else {
    let failures = outcome.failure_ledger.as_slice().iter().filter(|failure| {
      failure_browser_id(failure) == Some(browser_id)
        && !registry::is_informational_discovery_issue(failure.code.as_str())
    });
    if family == CompatibilityFamily::Chromium {
      let diagnostics = failures
        .clone()
        .map(|failure| failure.diagnostic.as_str())
        .take(MAX_ISSUE_SAMPLES)
        .collect::<Vec<_>>()
        .join("; ");
      if failures
        .clone()
        .any(|failure| failure.code.as_str().starts_with("profile_"))
      {
        return CompatibilityDisposition::Failed(Diagnostic::new_with_secrets(
          format!(
            "every discovered {} profile failed discovery: {diagnostics}",
            browser_id.as_str()
          ),
          &[],
        ));
      }
      if outcome.counters.browsers_detected > 0 {
        return CompatibilityDisposition::Failed(Diagnostic::new_with_secrets(
          format!(
            "every detected {} installation failed profile enumeration: {diagnostics}",
            browser_id.as_str()
          ),
          &[],
        ));
      }
    }
    if let Some(failure) = failures.into_iter().next() {
      return CompatibilityDisposition::Failed(failure.diagnostic.clone());
    }
    return CompatibilityDisposition::Absent(CompatibilityAbsence::CookieDatabase);
  };

  let sources = outcome.sources.iter().filter(|source| {
    source.profile.browser_id == profile.browser_id
      && source.profile.installation_id == profile.installation_id
      && source.profile.profile_id == profile.profile_id
  });
  let mut persistent = None;
  let mut sessions = Vec::new();
  for source in sources {
    match source.source.role.as_str() {
      registry::SOURCE_ROLE_PERSISTENT if source.selected && persistent.is_none() => {
        persistent = Some(source)
      }
      registry::SOURCE_ROLE_SESSION => sessions.push(source),
      _ => {}
    }
  }

  let source_failure = |source: &SourceOutcome| {
    if !source.failed {
      return None;
    }
    outcome.failure_ledger.as_slice().iter().find(|failure| {
      matches!(
        &failure.scope,
        FailureScope::Source { source_digest, .. }
          if source_digest == &source.source_digest()
      ) && failure.severity == IssueSeverityCode::error()
    })
  };
  let all_rows_failure = |source: &SourceOutcome| {
    if !source.records.is_empty() || source.stats.rows_skipped == 0 {
      return None;
    }
    let scoped = |failure: &&Failure| {
      matches!(
        &failure.scope,
        FailureScope::Source { source_digest, .. }
          if source_digest == &source.source_digest()
      )
    };
    outcome
      .failure_ledger
      .as_slice()
      .iter()
      .filter(scoped)
      .find(|failure| failure.code.as_str() == "all_rows_rejected")
      .or_else(|| {
        outcome
          .failure_ledger
          .as_slice()
          .iter()
          .filter(scoped)
          .find(|failure| {
            matches!(
              failure.code.as_str(),
              "row_read_failed" | "column_read_failed" | "decode_failed" | "decrypt_failed"
            )
          })
      })
  };
  let all_rows_diagnostic = |source: &SourceOutcome, fallback: &str| {
    if let Some(diagnostic) = compatibility_evidence.get(&source.source_digest()) {
      return Some(diagnostic.clone());
    }
    all_rows_failure(source).map(|failure| {
      if failure
        .diagnostic
        .as_str()
        .ends_with("row(s) could not be read")
      {
        Diagnostic::new_with_secrets(fallback, &[])
      } else {
        failure.diagnostic.clone()
      }
    })
  };
  let failed =
    |source: &SourceOutcome| source_failure(source).map(|failure| failure.diagnostic.clone());

  match family {
    CompatibilityFamily::Chromium => {
      let Some(source) = persistent else {
        return CompatibilityDisposition::Absent(CompatibilityAbsence::CookieDatabase);
      };
      if let Some(diagnostic) =
        all_rows_diagnostic(source, "all Chromium cookie rows failed to decode")
      {
        return CompatibilityDisposition::Failed(diagnostic);
      }
      if let Some(failure) = source_failure(source) {
        return CompatibilityDisposition::Failed(failure.diagnostic.clone());
      }
      CompatibilityDisposition::Emit {
        source_digests: vec![source.source_digest()],
      }
    }
    CompatibilityFamily::Gecko => {
      let mut selected = Vec::new();
      let mut deferred = None;
      let mut persistent_succeeded = false;
      let mut persistent_has_records = false;
      if let Some(source) = persistent {
        if let Some(diagnostic) =
          all_rows_diagnostic(source, "all Firefox cookie database rows failed to decode")
        {
          deferred = Some(diagnostic);
        } else if let Some(failure) = source_failure(source) {
          deferred = Some(failure.diagnostic.clone());
        } else {
          persistent_succeeded = true;
          persistent_has_records = !source.records.is_empty();
          selected.push(source.source_digest());
        }
      }

      let mut session_failures = Vec::new();
      let mut session_succeeded = false;
      for source in sessions {
        if let Some(diagnostic) = failed(source) {
          session_failures.push(diagnostic);
        } else {
          session_succeeded = true;
          selected.push(source.source_digest());
        }
      }
      // A successfully decoded session candidate is authoritative even when
      // it contains zero cookies, and therefore rescues a failed persistent
      // source without inventing another candidate.
      if session_succeeded || persistent_has_records {
        return CompatibilityDisposition::Emit {
          source_digests: selected,
        };
      }
      if !session_failures.is_empty() {
        let details = session_failures
          .iter()
          .map(Diagnostic::as_str)
          .collect::<Vec<_>>()
          .join("; ");
        return CompatibilityDisposition::Failed(Diagnostic::new_with_secrets(
          format!("all existing Firefox session store candidates failed: {details}"),
          &[],
        ));
      }
      if let Some(diagnostic) = deferred {
        CompatibilityDisposition::Failed(diagnostic)
      } else {
        debug_assert!(persistent_succeeded || selected.is_empty());
        CompatibilityDisposition::Emit {
          source_digests: selected,
        }
      }
    }
    CompatibilityFamily::Safari => {
      let Some(source) = persistent else {
        return CompatibilityDisposition::Absent(CompatibilityAbsence::CookieDatabase);
      };
      if source.records.is_empty() {
        if let Some(failure) = source_failure(source) {
          return CompatibilityDisposition::Failed(failure.diagnostic.clone());
        }
      }
      CompatibilityDisposition::Emit {
        source_digests: vec![source.source_digest()],
      }
    }
    CompatibilityFamily::InternetExplorer => {
      let Some(source) = persistent else {
        return CompatibilityDisposition::Absent(CompatibilityAbsence::CookieDatabase);
      };
      if let Some(diagnostic) = all_rows_diagnostic(
        source,
        "all Internet Explorer WebCache records failed to decode",
      ) {
        return CompatibilityDisposition::Failed(diagnostic);
      }
      if let Some(failure) = source_failure(source) {
        return CompatibilityDisposition::Failed(failure.diagnostic.clone());
      }
      CompatibilityDisposition::Emit {
        source_digests: vec![source.source_digest()],
      }
    }
  }
}

fn failure_browser_id(failure: &Failure) -> Option<&BrowserId> {
  match &failure.scope {
    FailureScope::Request => None,
    FailureScope::Browser { browser_id }
    | FailureScope::Profile { browser_id, .. }
    | FailureScope::Source { browser_id, .. } => Some(browser_id),
  }
}

#[cfg(test)]
fn assemble(registered_browsers: usize, outcomes: Vec<BrowserDraft>) -> ExtractionReport {
  project_canonical_report(finalize_outcomes(registered_browsers, outcomes))
}

fn assemble_with_runtime(
  registered_browsers: usize,
  outcomes: Vec<BrowserDraft>,
  runtime: &BoundaryRuntime<'_>,
) -> ExtractionReport {
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

// Only reachable in production through the automatic multi-identity
// Chromium selection, which is Linux/macOS-only; Windows exercises this via
// `#[cfg(test)]`.
#[allow(dead_code)]
pub(crate) fn canonical_direct_chromium_extraction(source: Source) -> Result<Outcome> {
  canonical_direct_chromium_extraction_impl(source, None)
}

pub(crate) fn canonical_direct_chromium_extraction_with_runtime(
  source: Source,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Outcome> {
  canonical_direct_chromium_extraction_impl(source, Some(runtime))
}

fn canonical_direct_chromium_extraction_impl(
  source: Source,
  runtime: Option<&BoundaryRuntime<'_>>,
) -> Result<Outcome> {
  let browser_id = BrowserId::known("chromium");
  // The source's own path, not a second one threaded alongside it: the
  // candidate the engine queried is the only place this is recorded.
  let db_path = source.origin.path.clone();
  let db_path = db_path.as_path();
  let profile = ProfileIdentity {
    browser_id: browser_id.clone(),
    installation_id: "0".repeat(64).parse()?,
    profile_id: "1".repeat(64).parse()?,
    display_name: "direct".to_owned(),
    path: display_path(db_path.parent().unwrap_or(db_path)).0,
    path_lossy: db_path.parent().unwrap_or(db_path).to_str().is_none(),
  };
  let mut profile_draft = ProfileDraft::new(profile, true);
  profile_draft.sources.push(source_to_draft(source));
  Ok(finalize_outcomes_with_runtime(
    1,
    vec![BrowserDraft {
      browser_id,
      compatibility_family: CompatibilityFamily::Chromium,
      detected: true,
      installations_discovered: 1,
      discovery_failed: false,
      profiles: vec![profile_draft],
      issues: Vec::new(),
      termination: Termination::Completed,
    }],
    runtime,
  ))
}

pub(crate) fn canonical_direct_mozilla_extraction_with_runtime(
  db_path: &std::path::Path,
  extract: super::mozilla::MozillaExtract,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Outcome> {
  canonical_direct_mozilla_extraction_impl(db_path, extract, Some(runtime))
}

fn canonical_direct_mozilla_extraction_impl(
  db_path: &std::path::Path,
  extract: super::mozilla::MozillaExtract,
  runtime: Option<&BoundaryRuntime<'_>>,
) -> Result<Outcome> {
  // The engine already assembled every source, including its `row_read_failed`
  // issues. The direct path gates the persistent source on `persistent_attempted`
  // alone -- there is no discovery to consult -- which is exactly the engine's
  // emit condition, so the engine's `Vec<Source>` is consumed as-is.
  let profile_path = db_path.parent().unwrap_or(db_path).to_path_buf();
  let engine_extract = direct_engine_extract(profile_path, extract.sources, extract.boundary_stop);
  match runtime {
    Some(runtime) => canonical_engine_extract_with_runtime("firefox", engine_extract, runtime),
    None => canonical_engine_extract("firefox", engine_extract),
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

pub(crate) fn canonical_direct_safari_extraction_with_runtime(
  source: Source,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Outcome> {
  canonical_direct_engine_source("safari", source, Some(runtime))
}

#[cfg(target_os = "windows")]
pub(crate) fn canonical_direct_internet_explorer_extraction_with_runtime(
  source: Source,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Outcome> {
  canonical_direct_engine_source("internet_explorer", source, Some(runtime))
}

/// Wraps one already-built [`Source`] as a single-profile direct-path extract.
///
/// The engine assembled the source, including its `row_read_failed` issue, so
/// this only supplies the synthetic profile the direct path has no discovery
/// for. The profile path is read off the source's own origin rather than
/// threaded alongside it.
fn canonical_direct_engine_source(
  browser_id: &str,
  source: Source,
  runtime: Option<&BoundaryRuntime<'_>>,
) -> Result<Outcome> {
  let db_path = source.origin.path.clone();
  let profile_path = db_path.parent().unwrap_or(&db_path).to_path_buf();
  let extract = direct_engine_extract(profile_path, vec![source], None);
  match runtime {
    Some(runtime) => canonical_engine_extract_with_runtime(browser_id, extract, runtime),
    None => canonical_engine_extract(browser_id, extract),
  }
}

/// Private `browser_report` seam. An unknown browser or profile ID is a request
/// error; a known but absent browser is an `Ok` report with `no_sources`.
#[cfg(test)]
pub(crate) fn browser_extraction_report(
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<Vec<String>>,
) -> Result<ExtractionReport> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  browser_extraction_report_with_runtime(browser_id, profile_id, domains, &runtime)
}

pub(crate) fn browser_extraction_report_with_runtime(
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<Vec<String>>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<ExtractionReport> {
  let browser = registry::resolve_registered_browser(browser_id)?;
  let canonical_id = &browser.canonical_id;
  let mut outcome = match collect_report(&browser, profile_id, true, domains, runtime) {
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
    if let Some(profile_id) = profile_id {
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
pub(crate) fn load_extraction_report(domains: Option<Vec<String>>) -> Result<ExtractionReport> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
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
    collect_report(browser, None, true, domains.clone(), runtime)
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
  Ok(assemble_with_runtime(browsers.len(), outcomes, runtime))
}

/// Private `browser_profiles` seam. An unknown ID fails; a known browser with
/// no detected installation returns an empty list; a browser whose every
/// detected root failed enumeration fails rather than returning an
/// indistinguishable empty list.
pub(crate) fn browser_profile_descriptors(browser_id: &str) -> Result<Vec<ProfileDescriptor>> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  let browser = registry::resolve_registered_browser(browser_id)?;
  let outcome = collect_report(&browser, None, false, None, &runtime)?;
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
pub(crate) fn chrome_profile_descriptors() -> Result<Vec<ProfileDescriptor>> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
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
  let profile = registry::select_chrome_profile_with_runtime(profile, &runtime)?;
  browser_extraction_report_with_runtime(
    "chrome",
    Some(profile.profile_id.as_str()),
    domains,
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
      let source = source_identity(
        &candidate.path,
        SOURCE_ROLE_PERSISTENT,
        "chromium_sqlite",
        candidate.precedence,
      );
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
  outcome: BrowserDraft,
) -> Result<Vec<ProfileDescriptor>> {
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
    bail!(
      "every detected {browser_id} installation failed profile enumeration: {}",
      errors(&outcome.issues, false).join("; ")
    )
  }
  let lost_profiles = errors(&outcome.issues, true);
  if outcome.profiles.is_empty() && !lost_profiles.is_empty() {
    bail!(
      "every discovered {browser_id} profile failed discovery: {}",
      lost_profiles.join("; ")
    )
  }
  Ok(
    outcome
      .profiles
      .into_iter()
      .map(|engine| {
        let mut sources = engine
          .sources
          .into_iter()
          .map(|source| CookieSourceDescriptor {
            role: source.source.role,
            format: source.source.format,
            path: source.source.path,
            path_lossy: source.source.path_lossy,
            precedence: source.source.precedence,
          })
          .collect::<Vec<_>>();
        sort_source_descriptors(&mut sources);
        ProfileDescriptor {
          // Carried from discovery rather than inferred from position: engines
          // sort default-first, but that is presentation, and a later ordering
          // change must not silently rename which profile is the default.
          is_default: engine.is_default,
          profile: engine.profile,
          sources,
        }
      })
      .collect(),
  )
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::browser::report_core::{ReportStatusCode, SourceDraft};
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
      source_identity(
        &source_path,
        SOURCE_ROLE_PERSISTENT,
        "mozilla_sqlite",
        registry::PERSISTENT_SOURCE_PRECEDENCE,
      ),
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
  fn cancellation_and_resource_exhaustion_reach_the_report_wire_without_source_errors() {
    use crate::common::deadline::{test_clock::ManualClock, CancellationToken, Deadline};
    use std::time::Duration;

    for (stop, expected) in [
      (BoundaryStop::Cancelled, "cancelled"),
      (BoundaryStop::ResourceExhausted, "resource_exhausted"),
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
      let report = browser_extraction_report_with_runtime("firefox", None, None, &runtime)
        .expect("typed stop becomes a report termination");
      assert_eq!(report.termination.as_str(), expected);
      assert!(report.issues.is_empty());
      let wire = serde_json::to_value(report).expect("serialize stopped report");
      assert_eq!(wire["termination"], expected);
    }

    let clock = ManualClock::default();
    let runtime = BoundaryRuntime::new(&clock, Deadline::after(&clock, Duration::ZERO));
    let report = browser_extraction_report_with_runtime("firefox", None, None, &runtime)
      .expect("expired runtime becomes a report termination");
    assert_eq!(report.termination.as_str(), "timed_out");
    assert!(report.issues.is_empty());
  }

  #[test]
  fn stopped_drafts_keep_atomic_completed_sources_for_report_and_legacy_projection() {
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

      let report = assemble_with_runtime(1, vec![stopped()], &runtime);
      let expected_termination = match stop {
        BoundaryStop::TimedOut => "timed_out",
        BoundaryStop::Cancelled => "cancelled",
        BoundaryStop::ResourceExhausted => "resource_exhausted",
      };
      assert_eq!(report.termination.as_str(), expected_termination);
      assert_eq!(report.status.as_str(), "complete");
      assert_eq!(report.summary.sources_succeeded, 1);
      assert_eq!(report.summary.rows_seen, 1);
      assert_eq!(report.summary.cookies_emitted, 1);
      assert_eq!(report.profiles[0].sources[0].stats.rows_seen, 1);
      assert_eq!(report.profiles[0].sources[0].stats.cookies_emitted, 1);
      assert_eq!(report.profiles[0].sources[0].cookies.len(), 1);
      assert_eq!(report.profiles[0].sources[0].cookies[0].name, "retained");

      let canonical = finalize_outcomes_with_runtime(1, vec![stopped()], Some(&runtime));
      let cookies = super::super::legacy::project_canonical_outcome_with_runtime(
        "firefox", canonical, &runtime,
      )
      .expect("completed legacy source survives a later typed stop");
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

    let report = assemble_with_runtime(2, vec![stopped, later], &runtime);

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
      let error = super::super::legacy::project_canonical_outcome_with_runtime(
        "firefox", canonical, &runtime,
      )
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
        source_identity(
          &path,
          SOURCE_ROLE_PERSISTENT,
          "mozilla_sqlite",
          registry::PERSISTENT_SOURCE_PRECEDENCE + index as u16,
        ),
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

    let report = assemble_with_runtime(1, vec![outcome(vec![profile], false)], &runtime);
    assert_eq!(report.termination.as_str(), "cancelled");
    assert_eq!(report.status.as_str(), "partial");
    assert_eq!(report.profiles.len(), 1);
    assert_eq!(report.profiles[0].sources.len(), 1);
    assert_eq!(report.profiles[0].sources[0].cookies[0].name, "first");
    assert!(report.issues.is_empty());
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
    }
  }

  fn chromium_profile(
    sources: Vec<Source>,
    failure: Option<String>,
  ) -> registry::ChromiumExtractedProfile {
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
      failure,
    }
  }

  /// The real Chromium adapter, not a hand-built outcome. A profile whose
  /// source discovery failed must not be reported as ordinary absence -- this
  /// is the path on which that bug shipped.
  #[test]
  fn chromium_profile_that_failed_discovery_reaches_the_report_as_failed() {
    let browser = BrowserId::known("chrome");
    let engine = chromium_profile_outcome(
      &browser,
      &"d".repeat(64),
      chromium_profile(Vec::new(), Some("Local State is unreadable".to_owned())),
    )
    .expect("adapt the profile");
    assert!(engine.sources.is_empty());
    let issue = engine.issues.first().expect("an issue for the failure");
    assert_eq!(issue.code.as_str(), "profile_extraction_failed");
    assert!(issue.is_error());
    assert_eq!(issue.message, "Local State is unreadable");
    assert_eq!(
      status(outcome(vec![engine], false)),
      ReportStatusCode::failed()
    );
  }

  /// The same empty source list without a failure is ordinary absence. The two
  /// must not collapse: an installed browser with no cookie store would
  /// otherwise be indistinguishable from one that could not be read.
  #[test]
  fn a_chromium_profile_with_no_source_and_no_failure_is_ordinary_absence() {
    let browser = BrowserId::known("chrome");
    let engine = chromium_profile_outcome(
      &browser,
      &"d".repeat(64),
      chromium_profile(Vec::new(), None),
    )
    .expect("adapt the profile");
    assert!(engine.sources.is_empty());
    let issue = engine.issues.first().expect("an issue for the absence");
    assert_eq!(issue.code.as_str(), "profile_has_no_cookie_source");
    assert!(!issue.is_error());
  }

  #[test]
  fn chromium_adapter_projects_a_selected_candidate_as_a_succeeding_source() {
    let browser = BrowserId::known("chrome");
    let mut source = Source::from_candidate(chromium_candidate());
    source.acquisition_attempts = 1;
    let engine = chromium_profile_outcome(
      &browser,
      &"d".repeat(64),
      chromium_profile(vec![source], None),
    )
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

  fn engine_source(
    name: &str,
    role: &'static str,
    precedence: u16,
    selected: bool,
    error: Option<&str>,
  ) -> Source {
    let mut source = Source {
      origin: SourceCandidate {
        path: PathBuf::from("/firefox/Profiles/default").join(name),
        role: CookieSourceRoleId::known(role),
        format: CookieSourceFormatId::known("mozilla_sqlite"),
        precedence,
        exists: true,
        selected,
        acquisition: registry::SourceAcquisition::StableFileImage,
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
    assert!(browser_extraction_report("definitely_not_a_browser", None, None).is_err());
    assert!(browser_profile_descriptors("definitely_not_a_browser").is_err());
    // An alias-shaped but unregistered id must fail the same way.
    assert!(browser_extraction_report("", None, None).is_err());
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
    let mut chromium_source = Source::from_candidate(chromium_candidate());
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
      chromium_profile(vec![chromium_source], None),
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
    let mut source = Source::from_candidate(SourceCandidate {
      path: PathBuf::from("/chrome/Default/Network/Cookies"),
      role: CookieSourceRoleId::persistent(),
      format: CookieSourceFormatId::known("chromium_sqlite"),
      precedence: registry::PERSISTENT_SOURCE_PRECEDENCE,
      exists: true,
      selected: true,
      acquisition: registry::SourceAcquisition::NotAttempted,
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
}

/// End-to-end coverage of the real engine chain: registry discovery and
/// extraction on a fixture tree, through each engine's adapter, into the frozen
/// report. Constructing outcomes by hand cannot prove an engine reaches the
/// contract at all, which is how a Chromium profile whose discovery failed came
/// to be reported as ordinary absence.
#[cfg(test)]
mod engine_chain_tests {
  use super::*;
  use crate::browser::chromium_crypto::{ChromiumKeyOutcome, ChromiumKeyOutcomes};
  use crate::browser::registry::test_seams;
  use crate::browser::report_core::ReportStatusCode;
  use std::path::PathBuf;
  use std::sync::atomic::{AtomicU64, Ordering};

  struct TempDir(PathBuf);

  impl TempDir {
    fn new(tag: &str) -> Self {
      static COUNTER: AtomicU64 = AtomicU64::new(0);
      let count = COUNTER.fetch_add(1, Ordering::SeqCst);
      let path = std::env::temp_dir().join(format!(
        "rookie-report-chain-{tag}-{}-{count}",
        std::process::id()
      ));
      std::fs::create_dir_all(&path).expect("create temporary directory");
      Self(path)
    }

    fn path(&self) -> &std::path::Path {
      &self.0
    }
  }

  impl Drop for TempDir {
    fn drop(&mut self) {
      let _ = std::fs::remove_dir_all(&self.0);
    }
  }

  fn no_keys() -> ChromiumKeyOutcomes {
    ChromiumKeyOutcomes {
      v10: ChromiumKeyOutcome::NotApplicable,
      v11: ChromiumKeyOutcome::NotApplicable,
      v20: ChromiumKeyOutcome::NotApplicable,
    }
  }

  #[test]
  fn a_real_gecko_profile_reaches_the_frozen_report() {
    let temp = TempDir::new("gecko");
    let context = test_seams::current_context(temp.path().to_path_buf());
    let root = test_seams::primary_root_path(&context, "firefox");
    test_seams::seed_gecko_profile(&root.join("Profiles/default"));
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=default\nPath=Profiles/default\nDefault=1\n",
    )
    .expect("write profiles.ini");

    let engine = test_seams::gecko_report(&context, "firefox", None, None).expect("gecko report");
    let browser = BrowserId::known("firefox");
    let outcome = engine_extract_outcome(&browser, engine).expect("adapt the engine outcome");
    let report = assemble(1, vec![outcome]);

    assert_eq!(report.status, ReportStatusCode::complete());
    assert_eq!(report.summary.profiles_discovered, 1);
    assert_eq!(report.summary.installations_discovered, 1);
    assert_eq!(report.summary.sources_succeeded, 1);
    let profile = &report.profiles[0];
    assert_eq!(profile.profile.browser_id.as_str(), "firefox");
    assert_eq!(profile.profile.display_name, "default");
    // Opaque ids, not display paths, are the selection keys.
    assert_eq!(profile.profile.profile_id.as_str().len(), 64);
    assert_eq!(profile.profile.installation_id.as_str().len(), 64);
    let source = &profile.sources[0];
    assert_eq!(source.source.format.as_str(), "mozilla_sqlite");
    assert_eq!(source.source.role.as_str(), "persistent");
    assert!(source.selected);
    assert_eq!(source.status, SourceStatusCode::succeeded());
  }

  #[test]
  fn a_real_chromium_profile_reaches_the_frozen_report() {
    let temp = TempDir::new("chromium");
    let context = test_seams::current_context(temp.path().to_path_buf());
    let root = test_seams::primary_root_path(&context, "chrome");
    test_seams::seed_chromium_profile(&root, "Default", "Person 1");

    let registry_report = test_seams::chromium_report(&context, "chrome", None, None, no_keys())
      .expect("chromium report");
    let browser = BrowserId::known("chrome");
    let outcome =
      chromium_browser_outcome(&browser, registry_report).expect("adapt the chromium report");
    let report = assemble(1, vec![outcome]);

    assert_eq!(report.status, ReportStatusCode::complete());
    assert_eq!(report.summary.profiles_discovered, 1);
    assert_eq!(report.summary.sources_succeeded, 1);
    assert_eq!(report.summary.cookies_emitted, 1);
    let source = &report.profiles[0].sources[0];
    assert_eq!(source.source.format.as_str(), "chromium_sqlite");
    assert!(source.selected);
    assert_eq!(source.cookies[0].name, "seeded");
  }

  /// A registered browser with nothing on disk is `no_sources`, never `failed`.
  #[test]
  fn an_absent_installation_reaches_the_report_as_no_sources() {
    let temp = TempDir::new("absent");
    let context = test_seams::current_context(temp.path().to_path_buf());

    let engine = test_seams::gecko_report(&context, "firefox", None, None).expect("gecko report");
    assert!(engine.profiles.is_empty());
    let browser = BrowserId::known("firefox");
    let outcome = engine_extract_outcome(&browser, engine).expect("adapt the engine outcome");
    let report = assemble(1, vec![outcome]);

    assert_eq!(report.status, ReportStatusCode::no_sources());
    assert_eq!(report.summary.installations_discovered, 0);
  }

  #[test]
  fn unreadable_non_chromium_roots_are_detected_failures_at_public_boundaries() {
    use crate::browser::registry::PlatformId;

    for (name, platform, browser_id) in [
      ("gecko", PlatformId::Linux, "firefox"),
      ("safari", PlatformId::Macos, "safari"),
      (
        "internet-explorer",
        PlatformId::Windows,
        "internet_explorer",
      ),
    ] {
      let temp = TempDir::new(&format!("{name}-metadata-denied-report"));
      let context = test_seams::context(platform, temp.path().to_path_buf());
      let root = test_seams::primary_root_path(&context, browser_id);
      let browser = BrowserId::known(browser_id);

      // All three non-Chromium engines share the listing tower now, so a
      // metadata-denied root produces one browser draft the same way.
      let listing =
        test_seams::non_chromium_discovery_with_denied_root(&context, browser_id, root.clone())
          .expect("discovery retains the metadata failure");
      let counters = listing.counters;
      let all_failed = listing.all_detected_roots_failed();
      let report_outcome =
        engine_listing_outcome(&browser, listing).expect("adapt engine discovery");
      let repeat = test_seams::non_chromium_discovery_with_denied_root(&context, browser_id, root)
        .expect("repeat deterministic discovery for listing");
      let listing_outcome =
        engine_listing_outcome(&browser, repeat).expect("adapt listing discovery");

      assert_eq!(counters.installations_detected, 1, "{name}");
      assert_eq!(counters.installations_discovered, 0, "{name}");
      assert_eq!(counters.installations_enumerated, 0, "{name}");
      assert!(all_failed, "{name}");

      assert!(report_outcome.detected, "{name}");
      assert!(report_outcome.discovery_failed, "{name}");
      let report = assemble(1, vec![report_outcome]);
      assert_eq!(report.status, ReportStatusCode::failed(), "{name}");
      assert_eq!(report.summary.browsers_detected, 1, "{name}");
      let issue = report
        .issues
        .iter()
        .find(|issue| issue.code.as_str() == "installation_metadata_failed")
        .expect("stable root metadata issue");
      assert!(issue.is_error(), "{name}");
      assert_eq!(issue.samples, ["<path>"], "{name}");
      assert!(
        report
          .issues
          .iter()
          .all(|issue| issue.code.as_str() != "browser_not_detected"),
        "{name}"
      );

      let error = profile_descriptors_from_outcome(browser_id, listing_outcome)
        .expect_err("an unreadable root must not become an empty profile list");
      assert!(
        error
          .to_string()
          .contains(&format!("every detected {browser_id} installation failed")),
        "{name}: {error:#}"
      );
    }
  }

  /// A session-only profile is admitted only because a session candidate
  /// exists at discovery time (`gecko_profile_has_source`). If that candidate
  /// is gone by the time extraction runs, the profile is not "nothing was
  /// ever there" - it is "something was there and extraction failed to reach
  /// it" - and Section 5.7 reserves `no_sources` for the former. Distinct from
  /// `an_absent_installation_reaches_the_report_as_no_sources`: here the
  /// profile itself is real and was discovered, only its one source raced
  /// away, so `installations_discovered`/`profiles_discovered` stay 1.
  #[test]
  fn a_gecko_session_candidate_that_vanishes_before_query_is_failed_not_absent() {
    let temp = TempDir::new("gecko-session-vanishes-report");
    let context = test_seams::current_context(temp.path().to_path_buf());
    let root = test_seams::primary_root_path(&context, "firefox");
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

    let engine = test_seams::gecko_report_with_race(&context, "firefox", None, |_persistent| {
      let _ = std::fs::remove_file(&session_file);
    })
    .expect("gecko report");
    assert_eq!(
      engine.profiles.len(),
      1,
      "the profile itself was discovered"
    );

    let browser = BrowserId::known("firefox");
    let outcome = engine_extract_outcome(&browser, engine).expect("adapt the engine outcome");
    let report = assemble(1, vec![outcome]);

    assert_eq!(report.status, ReportStatusCode::failed());
    assert_eq!(report.summary.installations_discovered, 1);
    assert_eq!(report.summary.profiles_discovered, 1);
    let profile = &report.profiles[0];
    assert!(profile.sources.is_empty());
    let issue = profile
      .issues
      .iter()
      .find(|issue| issue.code.as_str() == "profile_extraction_failed")
      .expect("a failure signal, not silent absence");
    assert!(issue.is_error());
  }

  /// Safari and Internet Explorer are OS-gated in `collect_report`, so their
  /// adapters cannot be reached through the dispatch on a Linux CI host. These
  /// drive the same engine chain with an overridden platform context, so both
  /// engines are still proven to reach the frozen contract.
  #[test]
  fn a_real_safari_profile_reaches_the_frozen_report() {
    use crate::browser::registry::PlatformId;

    let temp = TempDir::new("safari");
    let context = test_seams::context(PlatformId::Macos, temp.path().to_path_buf());
    let library = test_seams::primary_root_path(&context, "safari");
    let cookies = library.join("Containers/com.apple.Safari/Data/Library/Cookies");
    std::fs::create_dir_all(&cookies).expect("create Safari cookie directory");
    std::fs::write(
      cookies.join("Cookies.binarycookies"),
      b"cook\x00\x00\x00\x00",
    )
    .expect("seed Safari cookie file");

    let engine = test_seams::safari_report(&context, "safari", None, None).expect("safari report");
    let browser = BrowserId::known("safari");
    let outcome = engine_extract_outcome(&browser, engine).expect("adapt the engine outcome");
    let report = assemble(1, vec![outcome]);

    assert_eq!(report.summary.installations_discovered, 1);
    assert_eq!(report.summary.profiles_discovered, 1);
    let source = &report.profiles[0].sources[0];
    assert_eq!(source.source.format.as_str(), "safari_binarycookies");
    assert_eq!(source.source.role.as_str(), "persistent");
    assert!(source.selected);
    assert_eq!(
      source.acquisition_strategy,
      AcquisitionStrategyCode::stable_file_image()
    );
    assert_eq!(report.profiles[0].profile.browser_id.as_str(), "safari");
  }

  fn safari_report_from_embedded_nul_fixture(
    tag: &str,
    field: &str,
    include_valid: bool,
  ) -> ExtractionReport {
    use crate::browser::registry::PlatformId;

    let temp = TempDir::new(tag);
    let context = test_seams::context(PlatformId::Macos, temp.path().to_path_buf());
    let library = test_seams::primary_root_path(&context, "safari");
    let cookies = library.join("Containers/com.apple.Safari/Data/Library/Cookies");
    std::fs::create_dir_all(&cookies).expect("create Safari cookie directory");
    std::fs::write(
      cookies.join("Cookies.binarycookies"),
      crate::browser::safari::embedded_nul_test_fixture(field, include_valid),
    )
    .expect("seed Safari embedded-NUL fixture");

    let engine = test_seams::safari_report(&context, "safari", None, None).expect("safari report");
    let outcome =
      engine_extract_outcome(&BrowserId::known("safari"), engine).expect("adapt the Safari report");
    assemble(1, vec![outcome])
  }

  #[test]
  fn mixed_safari_embedded_nul_fixture_is_partial_with_exact_row_accounting() {
    let report = safari_report_from_embedded_nul_fixture("safari-nul-mixed", "domain", true);
    let source = &report.profiles[0].sources[0];

    assert_eq!(report.status, ReportStatusCode::partial());
    assert_eq!(source.status, SourceStatusCode::succeeded());
    assert_eq!(source.stats.rows_seen, 2);
    assert_eq!(source.stats.rows_skipped, 1);
    assert_eq!(source.stats.cookies_emitted, 1);
    assert_eq!(source.cookies.len(), 1);
    assert_eq!(source.cookies[0].domain, ".good.test");
    assert_eq!(source.cookies[0].name, "good");
    assert_eq!(source.cookies[0].path, "/");
    assert_eq!(source.cookies[0].value, "kept");
    let issue = source
      .issues
      .iter()
      .find(|issue| issue.code.as_str() == "row_read_failed")
      .expect("malformed row issue");
    assert_eq!(issue.stage.as_str(), "parse");
    assert_eq!(issue.occurrences, 1);
  }

  #[test]
  fn all_malformed_safari_embedded_nul_fixture_fails_with_counted_row() {
    let report =
      safari_report_from_embedded_nul_fixture("safari-nul-all-malformed", "value", false);
    let source = &report.profiles[0].sources[0];

    assert_eq!(report.status, ReportStatusCode::failed());
    assert_eq!(source.status, SourceStatusCode::failed());
    assert_eq!(source.stats.rows_seen, 1);
    assert_eq!(source.stats.rows_skipped, 1);
    assert_eq!(source.stats.cookies_emitted, 0);
    assert!(source.cookies.is_empty());
    assert!(source.issues.iter().any(|issue| {
      issue.code.as_str() == "row_read_failed"
        && issue.stage.as_str() == "parse"
        && issue.occurrences == 1
    }));
    assert!(source.issues.iter().any(|issue| {
      issue.code.as_str() == "source_extraction_failed" && issue.stage.as_str() == "parse"
    }));
  }

  /// `~/Library` belongs to macOS, not to Safari. Another browser's data under
  /// it must not make Safari report itself detected and then degraded.
  #[test]
  fn a_library_without_safari_data_is_not_a_safari_installation() {
    use crate::browser::registry::PlatformId;

    let temp = TempDir::new("safari-absent");
    let context = test_seams::context(PlatformId::Macos, temp.path().to_path_buf());
    let library = test_seams::primary_root_path(&context, "safari");
    std::fs::create_dir_all(library.join("Application Support/Firefox/Profiles/other"))
      .expect("create an unrelated browser tree under the library root");

    let engine = test_seams::safari_report(&context, "safari", None, None).expect("safari report");
    let browser = BrowserId::known("safari");
    let outcome = engine_extract_outcome(&browser, engine).expect("adapt the engine outcome");
    let report = assemble(1, vec![outcome]);

    assert_eq!(report.summary.browsers_detected, 0);
    assert_eq!(report.summary.installations_discovered, 0);
    assert_eq!(report.status, ReportStatusCode::no_sources());
  }

  /// The detection gate must still admit the pre-sandbox layout, whose cookie
  /// jar sits beside the Safari container rather than inside it.
  #[test]
  fn a_pre_sandbox_cookie_jar_is_still_a_safari_installation() {
    use crate::browser::registry::PlatformId;

    let temp = TempDir::new("safari-legacy");
    let context = test_seams::context(PlatformId::Macos, temp.path().to_path_buf());
    let cookies = test_seams::primary_root_path(&context, "safari").join("Cookies");
    std::fs::create_dir_all(&cookies).expect("create the pre-sandbox cookie directory");
    std::fs::write(
      cookies.join("Cookies.binarycookies"),
      b"cook\x00\x00\x00\x00",
    )
    .expect("seed Safari cookie file");

    let engine = test_seams::safari_report(&context, "safari", None, None).expect("safari report");
    let browser = BrowserId::known("safari");
    let outcome = engine_extract_outcome(&browser, engine).expect("adapt the engine outcome");
    let report = assemble(1, vec![outcome]);

    assert_eq!(report.summary.installations_discovered, 1);
    assert_eq!(report.summary.profiles_discovered, 1);
  }

  #[test]
  fn a_real_internet_explorer_profile_reaches_the_frozen_report() {
    use crate::browser::registry::{extracted_internet_explorer_source, PlatformId};

    let temp = TempDir::new("ie");
    let context = test_seams::context(PlatformId::Windows, temp.path().to_path_buf());
    let root = test_seams::primary_root_path(&context, "internet_explorer");
    std::fs::create_dir_all(&root).expect("create WebCache root");
    std::fs::write(root.join("WebCacheV01.dat"), b"ese").expect("seed WebCache database");

    // The ESE reader is injected, so this exercises the adapter chain without
    // needing a real ESE database on a non-Windows host.
    let engine = test_seams::internet_explorer_report(
      &context,
      "internet_explorer",
      None,
      None,
      |origin, _| {
        Ok(extracted_internet_explorer_source(
          origin,
          vec![crate::browser::cookie_record::CookieRecord::from_cookie(
            crate::common::enums::Cookie {
              domain: ".example.com".to_owned(),
              path: "/".to_owned(),
              secure: false,
              expires: None,
              name: "ie-cookie".to_owned(),
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
      },
    )
    .expect("internet explorer report");

    let browser = BrowserId::known("internet_explorer");
    let outcome = engine_extract_outcome(&browser, engine).expect("adapt the engine outcome");
    let report = assemble(1, vec![outcome]);

    assert_eq!(report.status, ReportStatusCode::complete());
    assert_eq!(report.summary.cookies_emitted, 1);
    let source = &report.profiles[0].sources[0];
    assert_eq!(source.source.format.as_str(), "internet_explorer_ese");
    assert_eq!(
      source.acquisition_strategy,
      AcquisitionStrategyCode::ese_database()
    );
    assert_eq!(source.cookies[0].name, "ie-cookie");
  }

  /// Ordinary absence, driven through the real registry rather than a
  /// hand-built state. An installed browser whose profile has no cookie store
  /// is `no_sources`.
  ///
  /// Discovery, not extraction, is where this is decided: a profile with no
  /// cookie database is filtered out of the installation and recorded as an
  /// info-severity discovery issue. `ChromiumProfileFailure::NoSource` is the
  /// defensive branch for a source that vanishes after discovery selected it,
  /// which is why asserting absence against a fabricated extraction state
  /// proved nothing about production.
  #[test]
  fn an_installed_chromium_profile_without_a_cookie_store_is_no_sources() {
    let temp = TempDir::new("chromium-absent-store");
    let context = test_seams::current_context(temp.path().to_path_buf());
    let root = test_seams::primary_root_path(&context, "chrome");
    // Declares a profile in Local State, but leaves it with no cookie database.
    test_seams::seed_chromium_profile(&root, "Default", "Person 1");
    std::fs::remove_file(root.join("Default/Cookies")).expect("remove the cookie database");

    let registry_report = test_seams::chromium_report(&context, "chrome", None, None, no_keys())
      .expect("chromium report");
    assert_eq!(registry_report.installations.len(), 1);
    assert!(registry_report.installations[0].profiles.is_empty());

    let outcome = chromium_browser_outcome(&BrowserId::known("chrome"), registry_report)
      .expect("adapt the chromium report");
    let report = assemble(1, vec![outcome]);

    assert_eq!(report.status, ReportStatusCode::no_sources());
    assert_eq!(report.summary.installations_discovered, 1);
    let issue = report
      .issues
      .iter()
      .find(|issue| issue.code.as_str() == "profile_has_no_cookie_source")
      .expect("an absence signal for the sourceless profile");
    assert!(!issue.is_error());
  }

  /// Section 5.7: a rejected row is counted and reported, but acquisition,
  /// parsing, and the query all completed, so the source still succeeded. Gecko
  /// used to fail the whole source on one bad row while Chromium did not.
  #[test]
  fn a_rejected_row_keeps_the_gecko_source_succeeded_and_the_report_partial() {
    let temp = TempDir::new("gecko-bad-row");
    let context = test_seams::current_context(temp.path().to_path_buf());
    let root = test_seams::primary_root_path(&context, "firefox");
    let profile = root.join("Profiles/default");
    test_seams::seed_gecko_profile(&profile);
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=default\nPath=Profiles/default\nDefault=1\n",
    )
    .expect("write profiles.ini");

    // One readable row and one whose name column is not text.
    let connection =
      rusqlite::Connection::open(profile.join("cookies.sqlite")).expect("open Gecko database");
    connection
      .execute_batch(
        "INSERT INTO moz_cookies VALUES ('.example.com','/',0,0,'good','value',0,0);
         INSERT INTO moz_cookies VALUES ('.example.com','/',0,0,X'00ff','value',0,0);",
      )
      .expect("seed rows");
    drop(connection);

    let engine = test_seams::gecko_report(&context, "firefox", None, None).expect("gecko report");
    let outcome = engine_extract_outcome(&BrowserId::known("firefox"), engine)
      .expect("adapt the engine outcome");
    let report = assemble(1, vec![outcome]);

    let source = &report.profiles[0].sources[0];
    assert_eq!(source.status, SourceStatusCode::succeeded());
    assert_eq!(source.stats.rows_skipped, 1);
    assert_eq!(source.cookies.len(), 1);
    assert_eq!(source.cookies[0].name, "good");
    // The mapping pairs `occurrences` with `rows_skipped` and the message with
    // `persistent_row_error`, which is only sound while the counter and the
    // error move together. A future rejection site that bumped one without the
    // other would silently under-report lost cookies, so pin the invariant:
    // rows skipped implies exactly one row issue counting exactly that many.
    let row_issues = source
      .issues
      .iter()
      .filter(|issue| issue.code.as_str() == "row_read_failed")
      .collect::<Vec<_>>();
    assert_eq!(row_issues.len(), 1);
    assert!(row_issues[0].is_error());
    assert_eq!(row_issues[0].occurrences, source.stats.rows_skipped);
    // Rows were lost, so the report is degraded -- but not to `failed`.
    assert_eq!(report.status, ReportStatusCode::partial());
    assert_eq!(report.summary.sources_succeeded, 1);
    assert_eq!(report.summary.sources_failed, 0);
    let diagnostics = source
      .issues
      .iter()
      .flat_map(|issue| {
        std::iter::once(issue.message.as_str()).chain(issue.samples.iter().map(String::as_str))
      })
      .collect::<Vec<_>>();
    assert!(diagnostics
      .iter()
      .all(|text| !text.contains("plaintext sentinel must not escape")));
    assert!(diagnostics
      .iter()
      .all(|text| text.len() <= crate::browser::outcome::MAX_DIAGNOSTIC_BYTES));
  }

  /// Selecting a profile narrows which installations are extracted, but must
  /// not rewrite how many were discovered. Chromium filters installations
  /// during extraction while the other engines filter profiles afterwards, so
  /// deriving the count from the post-selection list made the same request
  /// report different totals depending on the engine.
  #[test]
  fn selecting_a_chromium_profile_keeps_the_discovered_installation_count() {
    let temp = TempDir::new("chromium-profile-selection");
    let context = test_seams::current_context(temp.path().to_path_buf());
    let roots = test_seams::resolvable_root_paths(&context, "chrome");
    assert!(
      roots.len() >= 2,
      "chrome must declare at least two roots for this fixture"
    );
    test_seams::seed_chromium_profile(&roots[0], "Default", "Person 1");
    test_seams::seed_chromium_profile(&roots[1], "Default", "Person 2");

    let all = test_seams::chromium_report(&context, "chrome", None, None, no_keys())
      .expect("chromium report");
    assert_eq!(all.installations_discovered, 2);
    let selected_profile = all.installations[0].profiles[0].profile.profile_id.clone();

    let one = test_seams::chromium_report(
      &context,
      "chrome",
      Some(selected_profile.as_str()),
      None,
      no_keys(),
    )
    .expect("profile-selected chromium report");
    assert_eq!(one.installations.len(), 1);
    assert_eq!(one.installations_discovered, 2);

    let outcome = chromium_browser_outcome(&BrowserId::known("chrome"), one)
      .expect("adapt the chromium report");
    let report = assemble(1, vec![outcome]);
    assert_eq!(report.summary.installations_discovered, 2);
    assert_eq!(report.summary.profiles_discovered, 1);
  }

  /// Section 5.7 freezes what a profile-selected report says, and pushing the
  /// selection down into the engines changes only *when* the work happens. So
  /// every one of these compares the profile-selected report against the report
  /// the old build produced -- extract every profile, then drop the unwanted
  /// ones -- and requires them to be identical field for field, issues and
  /// counters included.
  fn post_filtered_extract_report(
    browser: &BrowserId,
    extract: EngineExtract,
    profile_id: &str,
  ) -> ExtractionReport {
    let mut outcome = engine_extract_outcome(browser, extract).expect("adapt the engine outcome");
    outcome
      .profiles
      .retain(|profile| profile.profile.profile_id.as_str() == profile_id);
    assemble(1, vec![outcome])
  }

  fn selected_extract_report(browser: &BrowserId, extract: EngineExtract) -> ExtractionReport {
    assemble(
      1,
      vec![engine_extract_outcome(browser, extract).expect("adapt the engine outcome")],
    )
  }

  /// The serialized form is the observable contract, so comparing it compares
  /// every frozen field rather than the handful a hand-written assertion would
  /// remember to check.
  fn wire(report: &ExtractionReport) -> serde_json::Value {
    serde_json::to_value(report).expect("serialize the report")
  }

  #[test]
  fn a_profile_selected_gecko_report_says_what_the_post_filtered_report_said() {
    let temp = TempDir::new("gecko-profile-contract");
    let context = test_seams::current_context(temp.path().to_path_buf());
    let root = test_seams::primary_root_path(&context, "firefox");
    for (directory, rows) in [
      (
        "default",
        "INSERT INTO moz_cookies VALUES ('.example.com','/',0,0,'default-cookie','value',0,0);",
      ),
      // The selected profile loses a row, so the comparison covers a report
      // carrying an error-severity issue and a degraded status, not just a
      // clean one.
      (
        "other",
        "INSERT INTO moz_cookies VALUES ('.example.com','/',0,0,'other-cookie','value',0,0);
         INSERT INTO moz_cookies VALUES ('.example.com','/',0,0,X'00ff','value',0,0);",
      ),
    ] {
      let profile = root.join("Profiles").join(directory);
      test_seams::seed_gecko_profile(&profile);
      let connection =
        rusqlite::Connection::open(profile.join("cookies.sqlite")).expect("open Gecko database");
      connection.execute_batch(rows).expect("seed rows");
    }
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/default\nDefault=1\n\
       [Profile1]\nName=other\nIsRelative=1\nPath=Profiles/other\n",
    )
    .expect("write profiles.ini");

    let browser = BrowserId::known("firefox");
    let full = test_seams::gecko_report(&context, "firefox", None, None).expect("full report");
    assert_eq!(full.profiles.len(), 2);
    let selected = full.profiles[1].identity.profile_id.as_str().to_owned();
    let expected = post_filtered_extract_report(&browser, full, &selected);

    let engine = test_seams::gecko_report(&context, "firefox", Some(&selected), None)
      .expect("profile-selected report");
    let actual = selected_extract_report(&browser, engine);

    assert_eq!(actual.status, ReportStatusCode::partial());
    assert_eq!(actual.summary.cookies_emitted, 1);
    assert_eq!(wire(&actual), wire(&expected));
  }

  #[test]
  fn a_profile_selected_safari_report_says_what_the_post_filtered_report_said() {
    use crate::browser::registry::PlatformId;

    let temp = TempDir::new("safari-profile-contract");
    let context = test_seams::context(PlatformId::Macos, temp.path().to_path_buf());
    let data = test_seams::primary_root_path(&context, "safari")
      .join("Containers/com.apple.Safari/Data/Library");
    let uuid = "01234567-89AB-CDEF-0123-456789ABCDEF";
    for directory in [
      data.join("Cookies"),
      data.join(format!(
        "WebKit/WebsiteDataStore/{}/WebsiteData/Cookies",
        uuid.to_ascii_lowercase()
      )),
    ] {
      std::fs::create_dir_all(&directory).expect("create Safari cookie directory");
      std::fs::write(
        directory.join("Cookies.binarycookies"),
        b"cook\x00\x00\x00\x00",
      )
      .expect("seed Safari cookie file");
    }
    std::fs::create_dir_all(data.join(format!("Safari/Profiles/{uuid}")))
      .expect("create Safari profile marker directory");

    let browser = BrowserId::known("safari");
    let full = test_seams::safari_report(&context, "safari", None, None).expect("full report");
    assert_eq!(full.profiles.len(), 2);
    let selected = full.profiles[1].identity.profile_id.as_str().to_owned();
    let expected = post_filtered_extract_report(&browser, full, &selected);

    let engine = test_seams::safari_report(&context, "safari", Some(&selected), None)
      .expect("profile-selected report");
    assert_eq!(
      wire(&selected_extract_report(&browser, engine)),
      wire(&expected)
    );
  }

  #[test]
  fn a_profile_selected_internet_explorer_report_says_what_the_post_filtered_report_said() {
    use crate::browser::registry::{extracted_internet_explorer_source, PlatformId};

    let temp = TempDir::new("ie-profile-contract");
    let context = test_seams::context(PlatformId::Windows, temp.path().to_path_buf());
    let roots = test_seams::resolvable_root_paths(&context, "internet_explorer");
    assert_eq!(roots.len(), 2, "IE must declare two WebCache roots");
    for root in &roots {
      std::fs::create_dir_all(root).expect("create WebCache root");
      std::fs::write(root.join("WebCacheV01.dat"), b"ese").expect("seed WebCache database");
    }
    // Each root answers with its own cookie, so a report built from the wrong
    // profile could not pass by coincidence.
    let rows = |origin: crate::browser::registry::SourceCandidate, _: Option<&[String]>| {
      let name = format!("{}", origin.path.display());
      Ok(extracted_internet_explorer_source(
        origin,
        vec![crate::browser::cookie_record::CookieRecord::from_cookie(
          crate::common::enums::Cookie {
            domain: ".example.com".to_owned(),
            path: "/".to_owned(),
            secure: false,
            expires: None,
            name,
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
    };

    let browser = BrowserId::known("internet_explorer");
    let full =
      test_seams::internet_explorer_report(&context, "internet_explorer", None, None, rows)
        .expect("full report");
    assert_eq!(full.profiles.len(), 2);
    let selected = full.profiles[1].identity.profile_id.as_str().to_owned();
    let expected = post_filtered_extract_report(&browser, full, &selected);

    let engine = test_seams::internet_explorer_report(
      &context,
      "internet_explorer",
      Some(&selected),
      None,
      rows,
    )
    .expect("profile-selected report");
    let actual = selected_extract_report(&browser, engine);

    assert_eq!(actual.summary.cookies_emitted, 1);
    assert_eq!(wire(&actual), wire(&expected));
  }

  /// Reported against pre-round-3 4E: a Chromium row that could not be
  /// decrypted took the whole source down with it, because "no row decoded"
  /// became a source-level failure. Section 5.7 counts every seen-but-not-
  /// emitted row in `rows_skipped` against a source that still succeeded, so
  /// this pins the unavailable-provider scenario end-to-end on the real chain.
  #[test]
  fn an_undecryptable_row_does_not_fail_the_chromium_source() {
    let temp = TempDir::new("chromium-undecryptable-row");
    let context = test_seams::current_context(temp.path().to_path_buf());
    let root = test_seams::primary_root_path(&context, "chrome");
    test_seams::seed_chromium_profile(&root, "Default", "Person 1");

    // Replace the plaintext cookie with a dual-populated v10 row no provider
    // can open. The row is unavailable, and its alternate plaintext must not
    // reach the report.
    let database = root.join("Default/Cookies");
    let connection = rusqlite::Connection::open(&database).expect("open cookie database");
    connection
      .execute("DELETE FROM cookies", [])
      .expect("clear seeded cookie");
    connection
      .execute(
        "INSERT INTO cookies VALUES ('.example.com', '/', 0, 0, 'locked',
         'plaintext sentinel must not escape', ?1, 0, 0)",
        [b"v10undecryptable".to_vec()],
      )
      .expect("insert encrypted cookie");
    drop(connection);

    let registry_report = test_seams::chromium_report(&context, "chrome", None, None, no_keys())
      .expect("chromium report");
    assert!(
      registry_report.installations[0].profiles[0]
        .sources
        .iter()
        .flat_map(|source| source.issues.iter())
        .any(|issue| issue.code == SourceIssue::ALL_ROWS_REJECTED),
      "the legacy projection must retain its all-row error"
    );
    let outcome = chromium_browser_outcome(&BrowserId::known("chrome"), registry_report)
      .expect("adapt the chromium report");
    let report = assemble(1, vec![outcome]);

    let source = &report.profiles[0].sources[0];
    assert_eq!(source.status, SourceStatusCode::succeeded());
    assert_eq!(source.stats.rows_seen, 1);
    assert_eq!(source.stats.rows_skipped, 1);
    assert!(source.cookies.is_empty());
    assert!(
      source.issues.iter().any(|issue| issue.is_error()
        && matches!(
          issue.code.as_str(),
          "provider_unavailable" | "provider_failed" | "decrypt_failed"
        )),
      "the unavailable row must be reported: {:?}",
      source.issues
    );
    // Acquisition and the query completed, so nothing failed at source level.
    assert!(!source
      .issues
      .iter()
      .any(|issue| issue.code.as_str() == "source_extraction_failed"));
    assert_eq!(report.status, ReportStatusCode::partial());
    assert_eq!(report.summary.sources_succeeded, 1);
    assert_eq!(report.summary.sources_failed, 0);
  }

  /// A confidential-session provider failure is a typed row rejection. It
  /// must neither degrade to provider absence nor get relabeled as a generic
  /// decrypt failure while travelling through the registry/report adapters.
  #[test]
  fn a_confidential_provider_failure_keeps_its_exact_report_code() {
    let temp = TempDir::new("chromium-confidential-provider-failure");
    let context = test_seams::current_context(temp.path().to_path_buf());
    let root = test_seams::primary_root_path(&context, "chrome");
    test_seams::seed_chromium_profile(&root, "Default", "Person 1");

    let database = root.join("Default/Cookies");
    let connection = rusqlite::Connection::open(&database).expect("open cookie database");
    connection
      .execute("DELETE FROM cookies", [])
      .expect("clear seeded cookie");
    connection
      .execute(
        "INSERT INTO cookies VALUES ('.example.com', '/', 0, 0, 'locked', '', ?1, 0, 0)",
        [b"v11undecryptable".to_vec()],
      )
      .expect("insert encrypted cookie");
    drop(connection);

    let keys = ChromiumKeyOutcomes {
      v10: ChromiumKeyOutcome::NotApplicable,
      v11: ChromiumKeyOutcome::failure("Secret Service confidential-session negotiation failed"),
      v20: ChromiumKeyOutcome::NotApplicable,
    };
    let registry_report =
      test_seams::chromium_report(&context, "chrome", None, None, keys).expect("chromium report");
    let outcome = chromium_browser_outcome(&BrowserId::known("chrome"), registry_report)
      .expect("adapt the chromium report");
    let report = assemble(1, vec![outcome]);

    let source = &report.profiles[0].sources[0];
    assert_eq!(source.status, SourceStatusCode::succeeded());
    assert_eq!(source.stats.rows_seen, 1);
    assert_eq!(source.stats.rows_skipped, 1);
    assert!(source.cookies.is_empty());
    assert_eq!(source.issues.len(), 1);
    assert_eq!(source.issues[0].code.as_str(), "provider_failed");
    assert_eq!(source.issues[0].stage.as_str(), "decrypt");
    assert_eq!(source.issues[0].cause, "credential_provider");
    assert_eq!(
      source.issues[0].provider.as_deref(),
      Some("platform_key_provider")
    );
    assert_eq!(source.issues[0].tier.as_deref(), Some("v11"));
    assert_eq!(source.issues[0].retryability, "retryable");
    let wire = serde_json::to_value(&report).expect("provider failure serializes");
    let wire_issue = &wire["profiles"][0]["sources"][0]["issues"][0];
    for key in ["cause", "provider", "tier", "retryability"] {
      assert!(wire_issue.get(key).is_some(), "missing {key}: {wire_issue}");
    }
    assert_eq!(report.status, ReportStatusCode::partial());
  }
}
