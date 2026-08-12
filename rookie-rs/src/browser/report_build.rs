//! Cross-engine private report assembly (Milestone 4E).
//!
//! Every registered engine reaches the frozen [`super::report_core`] contract
//! through this module. Nothing here is exported from `lib.rs`: the coordinated
//! Rust/Python/Node/CLI release gate owns publication.

// The report contract is complete before its public surface ships in
// Milestone 5, so unused-until-then items are expected here.
#![allow(dead_code)]

use super::chromium::{ChromiumRowIssue, ChromiumRowIssueCode};
use super::registry::{
  self, ChromiumProfileExtraction, ChromiumRegistryReport, DiscoveryIssue, EngineProfileExtraction,
  EngineSourceExtraction, RegisteredBrowser, SourceAcquisition, SOURCE_ROLE_PERSISTENT,
};
use super::report_core::{
  display_path, issue, push_aggregated, report_status, sort_cookies, sort_source_descriptors,
  sort_source_outcomes, source_status, AcquisitionStrategyCode, BrowserCapabilitiesDescriptor,
  BrowserDescriptor, BrowserId, CipherTierId, CookieSourceDescriptor, CookieSourceFormatId,
  CookieSourceIdentity, CookieSourceRoleId, CounterSet, EngineExtractionOutcome, EngineId,
  ExtractionIssue, ExtractionReport, ExtractionStageCode, InstallationId, IssueSeverityCode,
  ProfileDescriptor, ProfileExtraction, ProfileId, ProfileIdentity, ReportStats, SourceExtraction,
  SourceExtractionOutcome, SourceStatusCode, StatsAccumulator,
};
use crate::common::sqlite::DatabaseAcquisitionStrategy;
use anyhow::{bail, Result};

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
  issue(
    discovery.code,
    ExtractionStageCode::discovery(),
    discovery_severity(discovery.code),
    format!("{path}: {}", discovery.message),
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
fn row_issue(issue_code: &ChromiumRowIssue) -> ExtractionIssue {
  let (code, stage) = match issue_code.code {
    ChromiumRowIssueCode::ColumnRead(_) => ("column_read_failed", ExtractionStageCode::parse()),
    ChromiumRowIssueCode::Decrypt => ("decrypt_failed", ExtractionStageCode::decrypt()),
    ChromiumRowIssueCode::Decode => ("decode_failed", ExtractionStageCode::decode()),
    ChromiumRowIssueCode::ProviderUnavailable => {
      ("provider_unavailable", ExtractionStageCode::decrypt())
    }
    ChromiumRowIssueCode::ProviderFailed => ("provider_failed", ExtractionStageCode::decrypt()),
  };
  let message = match issue_code.code {
    ChromiumRowIssueCode::ColumnRead(column) => {
      format!(
        "failed to read the {column} column of {} row(s)",
        issue_code.occurrences
      )
    }
    _ => format!("{} row(s) rejected as {code}", issue_code.occurrences),
  };
  issue(code, stage, IssueSeverityCode::error(), message)
    .with_occurrences(u32::try_from(issue_code.occurrences).unwrap_or(u32::MAX))
    .with_samples(issue_code.samples.clone())
}

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

fn chromium_profile_outcome(
  browser_id: &BrowserId,
  installation_id: &str,
  extraction: ChromiumProfileExtraction,
) -> Result<EngineExtractionOutcome> {
  let ChromiumProfileExtraction {
    profile,
    cookies,
    stats,
    row_issues,
    acquisition,
    acquisition_attempts,
    error,
  } = extraction;
  let identity = profile_identity(
    browser_id,
    installation_id,
    &profile.profile_id,
    &profile.display_name,
    &profile.path,
  )?;
  let mut outcome = EngineExtractionOutcome::new(identity, profile.is_default);

  let Some(candidate) = profile
    .persistent_candidates
    .iter()
    .find(|candidate| candidate.selected)
  else {
    // A profile that simply has no cookie database is ordinary absence, but one
    // that reports an extraction error lost something, so it must not be
    // downgraded to the same `info` signal as an empty profile.
    outcome.issues.push(match error {
      Some(error) => issue(
        "profile_extraction_failed",
        ExtractionStageCode::acquisition(),
        IssueSeverityCode::error(),
        error,
      ),
      None => issue(
        "profile_has_no_cookie_source",
        ExtractionStageCode::discovery(),
        IssueSeverityCode::info(),
        "profile has no selected persistent source",
      ),
    });
    return Ok(outcome);
  };

  let mut source = SourceExtractionOutcome::new(
    source_identity(
      &candidate.path,
      SOURCE_ROLE_PERSISTENT,
      "chromium_sqlite",
      candidate.precedence,
    ),
    true,
    acquisition_code(acquisition),
  );
  source.stats = CounterSet {
    rows_seen: stats.rows_seen as u64,
    cookies_emitted: stats.cookies_emitted as u64,
    rows_skipped: stats.rows_skipped as u64,
    acquisition_attempts: u64::from(acquisition_attempts),
  }
  .into_stats();
  source.cookies = cookies;
  for row in &row_issues {
    push_aggregated(&mut source.issues, row_issue(row));
  }
  if let Some(error) = error {
    push_aggregated(
      &mut source.issues,
      issue(
        "source_extraction_failed",
        ExtractionStageCode::acquisition(),
        IssueSeverityCode::error(),
        error,
      ),
    );
    source.failed = true;
  }
  outcome.sources.push(source);
  Ok(outcome)
}

fn engine_profile_outcome(
  browser_id: &BrowserId,
  profile: EngineProfileExtraction,
) -> Result<EngineExtractionOutcome> {
  let identity = profile_identity(
    browser_id,
    &profile.installation_id,
    &profile.profile_id,
    &profile.name,
    &profile.path,
  )?;
  let mut outcome = EngineExtractionOutcome::new(identity, profile.is_default);
  for source in profile.sources {
    outcome.sources.push(engine_source_outcome(source));
  }
  Ok(outcome)
}

fn engine_source_outcome(source: EngineSourceExtraction) -> SourceExtractionOutcome {
  let EngineSourceExtraction {
    path,
    role,
    format,
    precedence,
    selected,
    cookies,
    rows_seen,
    rows_skipped,
    acquisition,
    acquisition_attempts,
    diagnostics,
    error,
  } = source;
  let mut outcome = SourceExtractionOutcome::new(
    source_identity(&path, role, format, precedence),
    selected,
    acquisition_code(acquisition),
  );
  outcome.stats = CounterSet {
    rows_seen: rows_seen as u64,
    cookies_emitted: cookies.len() as u64,
    rows_skipped: rows_skipped as u64,
    acquisition_attempts: u64::from(acquisition_attempts),
  }
  .into_stats();
  outcome.cookies = cookies;
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
  if let Some(error) = error {
    push_aggregated(
      &mut outcome.issues,
      issue(
        "source_extraction_failed",
        ExtractionStageCode::acquisition(),
        IssueSeverityCode::error(),
        error,
      ),
    );
    outcome.failed = true;
  }
  outcome
}

/// One registered browser's contribution to a report.
struct BrowserOutcome {
  detected: bool,
  installations_discovered: usize,
  /// Every detected root failed enumeration, so an empty profile list means
  /// "could not look", not "nothing installed". Section 5.7 makes this the
  /// difference between a `failed` report and a `no_sources` one.
  discovery_failed: bool,
  profiles: Vec<EngineExtractionOutcome>,
  issues: Vec<ExtractionIssue>,
}

fn chromium_browser_outcome(
  browser_id: &BrowserId,
  report: ChromiumRegistryReport,
) -> Result<BrowserOutcome> {
  let mut outcome = BrowserOutcome {
    detected: !report.installations.is_empty(),
    installations_discovered: report.installations.len(),
    discovery_failed: report.all_detected_roots_failed,
    profiles: Vec::new(),
    issues: Vec::new(),
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

fn engine_browser_outcome(
  browser_id: &BrowserId,
  engine: registry::EngineExtractionOutcome,
) -> Result<BrowserOutcome> {
  let mut outcome = BrowserOutcome {
    detected: engine.installations_discovered > 0,
    installations_discovered: engine.installations_discovered,
    discovery_failed: engine.all_detected_roots_failed(),
    profiles: Vec::new(),
    issues: Vec::new(),
  };
  for discovery in &engine.discovery_issues {
    push_aggregated(&mut outcome.issues, discovery_issue(browser_id, discovery));
  }
  for profile in engine.profiles {
    outcome
      .profiles
      .push(engine_profile_outcome(browser_id, profile)?);
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
) -> Result<BrowserOutcome> {
  let browser_id: BrowserId = browser.canonical_id.parse()?;
  match browser.engine {
    "chromium" => {
      let report = if extract {
        registry::chromium_registry_report(&browser.canonical_id, profile_id, domains)?
      } else {
        return chromium_listing_outcome(&browser_id, &browser.canonical_id);
      };
      chromium_browser_outcome(&browser_id, report)
    }
    "gecko" => {
      let engine = if extract {
        registry::gecko_report(&browser.canonical_id, domains)?
      } else {
        registry::gecko_profiles(&browser.canonical_id)?
      };
      engine_browser_outcome(&browser_id, engine)
    }
    #[cfg(target_os = "macos")]
    "safari" => {
      let engine = if extract {
        registry::safari_report(&browser.canonical_id, domains)?
      } else {
        registry::safari_profiles(&browser.canonical_id)?
      };
      engine_browser_outcome(&browser_id, engine)
    }
    #[cfg(target_os = "windows")]
    "internet_explorer" => {
      let engine = if extract {
        registry::internet_explorer_report(&browser.canonical_id, domains)?
      } else {
        registry::internet_explorer_profiles(&browser.canonical_id)?
      };
      engine_browser_outcome(&browser_id, engine)
    }
    // A registered browser whose engine has no adapter compiled into this
    // build is reported as undetected rather than silently skipped.
    _ => Ok(BrowserOutcome {
      detected: false,
      installations_discovered: 0,
      discovery_failed: false,
      profiles: Vec::new(),
      issues: Vec::new(),
    }),
  }
}

fn chromium_listing_outcome(browser_id: &BrowserId, canonical_id: &str) -> Result<BrowserOutcome> {
  let listing = registry::chromium_listing(canonical_id)?;
  let mut outcome = BrowserOutcome {
    detected: listing.installations_discovered > 0,
    installations_discovered: listing.installations_discovered,
    discovery_failed: listing.all_detected_roots_failed,
    profiles: Vec::new(),
    issues: Vec::new(),
  };
  for discovery in &listing.discovery_issues {
    push_aggregated(&mut outcome.issues, discovery_issue(browser_id, discovery));
  }
  for profile in listing.profiles {
    let identity = profile_identity(
      browser_id,
      &profile.installation_id,
      &profile.profile_id,
      &profile.display_name,
      &profile.path,
    )?;
    let mut engine = EngineExtractionOutcome::new(identity, profile.is_default);
    for candidate in &profile.persistent_candidates {
      if !candidate.exists {
        continue;
      }
      engine.sources.push(SourceExtractionOutcome::new(
        source_identity(
          &candidate.path,
          SOURCE_ROLE_PERSISTENT,
          "chromium_sqlite",
          candidate.precedence,
        ),
        candidate.selected,
        AcquisitionStrategyCode::not_attempted(),
      ));
    }
    outcome.profiles.push(engine);
  }
  Ok(outcome)
}

fn finish_profile(mut engine: EngineExtractionOutcome) -> ProfileExtraction {
  sort_source_outcomes(&mut engine.sources);
  let mut stats = StatsAccumulator::default();
  let sources = engine
    .sources
    .into_iter()
    .map(|mut source| {
      sort_cookies(&mut source.cookies);
      stats.add(&source.stats);
      SourceExtraction {
        source: source.source,
        status: source_status(source.failed),
        selected: source.selected,
        acquisition_strategy: source.acquisition_strategy,
        cookies: source.cookies,
        stats: source.stats,
        issues: source.issues,
      }
    })
    .collect::<Vec<_>>();
  ProfileExtraction {
    profile: engine.profile,
    sources,
    stats: stats.into_stats(),
    issues: engine.issues,
  }
}

/// Adds to a wire counter, recording any clamp. Every `ReportStats` counter is
/// `u32` for exact Node/TypeScript representation, so a count that hits the
/// ceiling must set `counters_saturated` rather than quietly read as exact.
fn add_saturating(counter: &mut u32, amount: u32, saturated: &mut bool) {
  match counter.checked_add(amount) {
    Some(value) => *counter = value,
    None => {
      *counter = u32::MAX;
      *saturated = true;
    }
  }
}

fn narrow(value: usize, saturated: &mut bool) -> u32 {
  u32::try_from(value).unwrap_or_else(|_| {
    *saturated = true;
    u32::MAX
  })
}

fn assemble(registered_browsers: usize, outcomes: Vec<BrowserOutcome>) -> ExtractionReport {
  let mut saturated = false;
  let mut summary = ReportStats {
    registered_browsers: narrow(registered_browsers, &mut saturated),
    ..ReportStats::default()
  };
  let mut top_level = Vec::new();
  let mut profiles = Vec::new();
  let mut counters = StatsAccumulator::default();
  let mut discovery_failed = false;

  for outcome in outcomes {
    discovery_failed |= outcome.discovery_failed;
    if outcome.detected {
      add_saturating(&mut summary.browsers_detected, 1, &mut saturated);
    } else {
      add_saturating(&mut summary.browsers_not_detected, 1, &mut saturated);
    }
    let discovered = narrow(outcome.installations_discovered, &mut saturated);
    add_saturating(
      &mut summary.installations_discovered,
      discovered,
      &mut saturated,
    );
    for issue in outcome.issues {
      push_aggregated(&mut top_level, issue);
    }
    for engine in outcome.profiles {
      let profile = finish_profile(engine);
      add_saturating(&mut summary.profiles_discovered, 1, &mut saturated);
      for source in &profile.sources {
        if source.status == SourceStatusCode::succeeded() {
          add_saturating(&mut summary.sources_succeeded, 1, &mut saturated);
        } else {
          add_saturating(&mut summary.sources_failed, 1, &mut saturated);
        }
      }
      counters.add(&profile.stats);
      profiles.push(profile);
    }
  }

  let totals = counters.into_stats();
  summary.rows_seen = totals.rows_seen;
  summary.cookies_emitted = totals.cookies_emitted;
  summary.rows_skipped = totals.rows_skipped;
  summary.counters_saturated = totals.counters_saturated || saturated;

  let status = report_status(&profiles, &top_level, discovery_failed);
  ExtractionReport {
    status,
    summary,
    profiles,
    issues: top_level,
  }
}

/// Private `browser_report` seam. An unknown browser or profile ID is a request
/// error; a known but absent browser is an `Ok` report with `no_sources`.
pub(crate) fn browser_extraction_report(
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<Vec<String>>,
) -> Result<ExtractionReport> {
  let browser = registry::resolve_registered_browser(browser_id)?;
  let canonical_id = &browser.canonical_id;
  let mut outcome = collect_report(&browser, profile_id, true, domains)?;
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
  if !outcome.detected {
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
  Ok(assemble(1, vec![outcome]))
}

/// Private `load_report` seam. Uninstalled registered browsers are summarized
/// in counters instead of emitting a per-browser warning.
pub(crate) fn load_extraction_report(domains: Option<Vec<String>>) -> Result<ExtractionReport> {
  let browsers = registry::registered_browsers()?;
  let mut outcomes = Vec::with_capacity(browsers.len());
  for browser in &browsers {
    match collect_report(browser, None, true, domains.clone()) {
      Ok(outcome) => outcomes.push(outcome),
      // A browser whose whole discovery failed must not erase the other
      // browsers' results; it is recorded as an error-severity issue.
      Err(error) => {
        let id: BrowserId = browser.canonical_id.parse()?;
        outcomes.push(BrowserOutcome {
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
        });
      }
    }
  }
  Ok(assemble(browsers.len(), outcomes))
}

/// Private `browser_profiles` seam. An unknown ID fails; a known browser with
/// no detected installation returns an empty list; a browser whose every
/// detected root failed enumeration fails rather than returning an
/// indistinguishable empty list.
pub(crate) fn browser_profile_descriptors(browser_id: &str) -> Result<Vec<ProfileDescriptor>> {
  let browser = registry::resolve_registered_browser(browser_id)?;
  let outcome = collect_report(&browser, None, false, None)?;
  // An empty list must mean "looked, found nothing". Roots that all failed to
  // enumerate are one way to lose everything; profiles that were all found and
  // then all failed (canonicalization, source inspection) are another, and both
  // would otherwise be indistinguishable from an uninstalled browser. The
  // listing type cannot carry issues, so the ones that caused the loss are
  // reported in the error rather than dropped at this boundary.
  let errors = outcome
    .issues
    .iter()
    .filter(|issue| issue.is_error())
    .map(|issue| issue.message.as_str())
    .collect::<Vec<_>>();
  if outcome.discovery_failed {
    bail!(
      "every detected {browser_id} installation failed profile enumeration: {}",
      errors.join("; ")
    )
  }
  if outcome.profiles.is_empty() && !errors.is_empty() {
    bail!(
      "every discovered {browser_id} profile failed discovery: {}",
      errors.join("; ")
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
          // Default-first ordering is applied by each engine's discovery, so
          // the first profile of an installation is its default.
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
  use crate::browser::report_core::{ReportStatusCode, SourceExtractionOutcome};
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

  fn source(failed: bool) -> SourceExtractionOutcome {
    let mut source = SourceExtractionOutcome::new(
      source_identity(
        &PathBuf::from("/profiles/default/cookies.sqlite"),
        SOURCE_ROLE_PERSISTENT,
        "mozilla_sqlite",
        registry::PERSISTENT_SOURCE_PRECEDENCE,
      ),
      true,
      AcquisitionStrategyCode::live_read_only(),
    );
    source.failed = failed;
    source
  }

  fn outcome(profiles: Vec<EngineExtractionOutcome>, discovery_failed: bool) -> BrowserOutcome {
    BrowserOutcome {
      detected: true,
      installations_discovered: 1,
      discovery_failed,
      profiles,
      issues: Vec::new(),
    }
  }

  fn status(outcome: BrowserOutcome) -> ReportStatusCode {
    assemble(1, vec![outcome]).status
  }

  fn chromium_profile(
    selected_candidate: bool,
    error: Option<&str>,
  ) -> registry::ChromiumProfileExtraction {
    let path = PathBuf::from("/chrome/Default");
    registry::ChromiumProfileExtraction {
      profile: registry::ChromiumProfile {
        profile_id: "c".repeat(64),
        installation_id: "d".repeat(64),
        directory_name: "Default".to_owned(),
        display_name: "Person 1".to_owned(),
        path: path.clone(),
        is_default: true,
        is_active: true,
        active_order: Some(0),
        is_last_used: true,
        persistent_candidates: vec![registry::CookieSourceCandidate {
          path: path.join("Network/Cookies"),
          precedence: registry::PERSISTENT_SOURCE_PRECEDENCE,
          exists: selected_candidate,
          selected: selected_candidate,
        }],
      },
      cookies: Vec::new(),
      stats: crate::browser::chromium::ChromiumExtractionStats {
        rows_seen: 0,
        cookies_emitted: 0,
        rows_skipped: 0,
      },
      row_issues: Vec::new(),
      acquisition: registry::SourceAcquisition::NotAttempted,
      acquisition_attempts: 1,
      error: error.map(str::to_owned),
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
      chromium_profile(false, Some("Local State is unreadable")),
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

  #[test]
  fn chromium_profile_without_a_source_is_ordinary_absence() {
    let browser = BrowserId::known("chrome");
    let engine = chromium_profile_outcome(&browser, &"d".repeat(64), chromium_profile(false, None))
      .expect("adapt the profile");
    let issue = engine.issues.first().expect("an absence signal");
    assert_eq!(issue.code.as_str(), "profile_has_no_cookie_source");
    assert!(!issue.is_error());
    assert_eq!(
      status(outcome(vec![engine], false)),
      ReportStatusCode::no_sources()
    );
  }

  #[test]
  fn chromium_adapter_projects_a_selected_candidate_as_a_succeeding_source() {
    let browser = BrowserId::known("chrome");
    let engine = chromium_profile_outcome(&browser, &"d".repeat(64), chromium_profile(true, None))
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
    let profile = registry::EngineProfileExtraction {
      profile_id: "c".repeat(64),
      installation_id: "d".repeat(64),
      installation_priority: 0,
      installation_path: PathBuf::from("/firefox"),
      name: "default".to_owned(),
      path: PathBuf::from("/firefox/Profiles/default"),
      is_default: true,
      persistent_source_discovered: true,
      sources: vec![
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
    };
    let engine =
      engine_profile_outcome(&BrowserId::known("firefox"), profile).expect("adapt the profile");
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
  ) -> registry::EngineSourceExtraction {
    registry::EngineSourceExtraction {
      path: PathBuf::from("/firefox/Profiles/default").join(name),
      role,
      format: "mozilla_sqlite",
      precedence,
      selected,
      cookies: Vec::new(),
      rows_seen: 0,
      rows_skipped: 0,
      acquisition: registry::SourceAcquisition::StableFileImage,
      acquisition_attempts: 1,
      diagnostics: Vec::new(),
      error: error.map(str::to_owned),
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
  fn a_profile_without_sources_is_no_sources_rather_than_failed() {
    let profile = EngineExtractionOutcome::new(identity(), true);
    assert_eq!(
      status(outcome(vec![profile], false)),
      ReportStatusCode::no_sources()
    );
  }

  #[test]
  fn a_root_that_could_not_be_enumerated_is_failed_not_no_sources() {
    // Identical profile shape to the case above; only the discovery signal
    // separates "nothing to read" from "could not look".
    let profile = EngineExtractionOutcome::new(identity(), true);
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
    let mut profile = EngineExtractionOutcome::new(identity(), true);
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
    let mut profile = EngineExtractionOutcome::new(identity(), true);
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
    let mut profile = EngineExtractionOutcome::new(identity(), true);
    profile.sources.push(source(true));
    assert_eq!(
      status(outcome(vec![profile], false)),
      ReportStatusCode::failed()
    );
  }

  #[test]
  fn a_zero_row_source_still_succeeds_and_completes() {
    let mut profile = EngineExtractionOutcome::new(identity(), true);
    profile.sources.push(source(false));
    let report = assemble(1, vec![outcome(vec![profile], false)]);
    assert_eq!(report.status, ReportStatusCode::complete());
    assert_eq!(report.summary.sources_succeeded, 1);
    assert_eq!(report.summary.cookies_emitted, 0);
  }

  #[test]
  fn an_error_issue_beside_a_succeeding_source_is_partial() {
    let mut profile = EngineExtractionOutcome::new(identity(), true);
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
    let mut profile = EngineExtractionOutcome::new(identity(), true);
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
    assert_eq!(issue.samples, vec!["/profiles/0", "/profiles/1"]);
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

    let engine = test_seams::gecko_report(&context, "firefox", None).expect("gecko report");
    let browser = BrowserId::known("firefox");
    let outcome = engine_browser_outcome(&browser, engine).expect("adapt the engine outcome");
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

    let engine = test_seams::gecko_report(&context, "firefox", None).expect("gecko report");
    assert!(engine.profiles.is_empty());
    let browser = BrowserId::known("firefox");
    let outcome = engine_browser_outcome(&browser, engine).expect("adapt the engine outcome");
    let report = assemble(1, vec![outcome]);

    assert_eq!(report.status, ReportStatusCode::no_sources());
    assert_eq!(report.summary.installations_discovered, 0);
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

    let engine = test_seams::safari_report(&context, "safari", None).expect("safari report");
    let browser = BrowserId::known("safari");
    let outcome = engine_browser_outcome(&browser, engine).expect("adapt the engine outcome");
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

  #[test]
  fn a_real_internet_explorer_profile_reaches_the_frozen_report() {
    use crate::browser::registry::{InternetExplorerRows, PlatformId};

    let temp = TempDir::new("ie");
    let context = test_seams::context(PlatformId::Windows, temp.path().to_path_buf());
    let root = test_seams::primary_root_path(&context, "internet_explorer");
    std::fs::create_dir_all(&root).expect("create WebCache root");
    std::fs::write(root.join("WebCacheV01.dat"), b"ese").expect("seed WebCache database");

    // The ESE reader is injected, so this exercises the adapter chain without
    // needing a real ESE database on a non-Windows host.
    let engine =
      test_seams::internet_explorer_report(&context, "internet_explorer", None, |_, _| {
        Ok(InternetExplorerRows {
          cookies: vec![crate::common::enums::Cookie {
            domain: ".example.com".to_owned(),
            path: "/".to_owned(),
            secure: false,
            expires: None,
            name: "ie-cookie".to_owned(),
            value: "value".to_owned(),
            http_only: false,
            same_site: 0,
          }],
          records_seen: 1,
          records_skipped: 0,
        })
      })
      .expect("internet explorer report");

    let browser = BrowserId::known("internet_explorer");
    let outcome = engine_browser_outcome(&browser, engine).expect("adapt the engine outcome");
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
}
