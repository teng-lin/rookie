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
fn discovery_severity(code: &str) -> IssueSeverityCode {
  match code {
    "duplicate_installation" | "duplicate_profile" | "profile_has_no_cookie_source" => {
      IssueSeverityCode::info()
    }
    "local_state_invalid" | "safari_profile_discovery_degraded" => IssueSeverityCode::warning(),
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
    outcome.issues.push(issue(
      "profile_has_no_cookie_source",
      ExtractionStageCode::discovery(),
      IssueSeverityCode::info(),
      error.unwrap_or_else(|| "profile has no selected persistent source".to_owned()),
    ));
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
      profiles: Vec::new(),
      issues: Vec::new(),
    }),
  }
}

fn chromium_listing_outcome(browser_id: &BrowserId, canonical_id: &str) -> Result<BrowserOutcome> {
  let profiles = registry::chromium_profiles(canonical_id)?;
  let mut outcome = BrowserOutcome {
    detected: !profiles.is_empty(),
    installations_discovered: profiles
      .iter()
      .map(|profile| profile.installation_id.as_str())
      .collect::<std::collections::BTreeSet<_>>()
      .len(),
    profiles: Vec::new(),
    issues: Vec::new(),
  };
  for profile in profiles {
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

fn assemble(registered_browsers: usize, outcomes: Vec<BrowserOutcome>) -> ExtractionReport {
  let mut summary = ReportStats {
    registered_browsers: u32::try_from(registered_browsers).unwrap_or(u32::MAX),
    ..ReportStats::default()
  };
  let mut top_level = Vec::new();
  let mut profiles = Vec::new();
  let mut counters = StatsAccumulator::default();

  for outcome in outcomes {
    if outcome.detected {
      summary.browsers_detected += 1;
    } else {
      summary.browsers_not_detected += 1;
    }
    summary.installations_discovered = summary
      .installations_discovered
      .saturating_add(u32::try_from(outcome.installations_discovered).unwrap_or(u32::MAX));
    for issue in outcome.issues {
      push_aggregated(&mut top_level, issue);
    }
    for engine in outcome.profiles {
      let profile = finish_profile(engine);
      summary.profiles_discovered = summary.profiles_discovered.saturating_add(1);
      for source in &profile.sources {
        if source.status == SourceStatusCode::succeeded() {
          summary.sources_succeeded = summary.sources_succeeded.saturating_add(1);
        } else {
          summary.sources_failed = summary.sources_failed.saturating_add(1);
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
  summary.counters_saturated = totals.counters_saturated;

  let discovery_failed = top_level.iter().any(ExtractionIssue::is_error);
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
  let mut outcome = collect_report(&browser, profile_id, true, domains)?;
  if let Some(profile_id) = profile_id {
    if !outcome
      .profiles
      .iter()
      .any(|profile| profile.profile.profile_id.as_str() == profile_id)
    {
      bail!("unknown {browser_id} profile id {profile_id:?}")
    }
    outcome
      .profiles
      .retain(|profile| profile.profile.profile_id.as_str() == profile_id);
  }
  if !outcome.detected {
    let id: BrowserId = browser.canonical_id.parse()?;
    push_aggregated(
      &mut outcome.issues,
      issue(
        "browser_not_detected",
        ExtractionStageCode::discovery(),
        IssueSeverityCode::info(),
        format!("no {} installation was detected", browser.canonical_id),
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
  if outcome.profiles.is_empty()
    && outcome.installations_discovered > 0
    && outcome.issues.iter().any(ExtractionIssue::is_error)
  {
    bail!("every detected {browser_id} installation failed profile enumeration")
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
