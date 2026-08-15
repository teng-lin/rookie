//! Cross-engine report assembly.
//!
//! Every registered engine reaches the frozen [`super::report_core`] contract
//! through this module. The four entry points at the bottom back the public
//! [`crate::supported_browsers`], [`crate::browser_profiles`],
//! [`crate::browser_report`], and [`crate::load_report`].

use super::chromium::{ChromiumRowIssue, ChromiumRowIssueCode};
use super::registry::{
  self, ChromiumProfileExtraction, ChromiumProfileFailure, ChromiumRegistryReport, DiscoveryIssue,
  EngineProfileExtraction, EngineSourceExtraction, RegisteredBrowser, SourceAcquisition,
  SourceFailureStage, SOURCE_ROLE_PERSISTENT,
};
use super::report_core::{
  display_path, issue, push_aggregated, report_status, sort_cookies, sort_source_descriptors,
  sort_source_outcomes, source_status, AcquisitionStrategyCode, BrowserCapabilitiesDescriptor,
  BrowserDescriptor, BrowserId, CipherTierId, CookieSourceDescriptor, CookieSourceFormatId,
  CookieSourceIdentity, CookieSourceRoleId, CounterSet, EngineExtractionOutcome, EngineId,
  ExtractionIssue, ExtractionReport, ExtractionStageCode, InstallationId, IssueSeverityCode,
  ProfileDescriptor, ProfileExtraction, ProfileId, ProfileIdentity, ReportStats, SourceExtraction,
  SourceExtractionOutcome, SourceStatusCode, StatsAccumulator, MAX_ISSUE_SAMPLES,
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
  // Name-column and value-column failures share one code, so aggregation merges
  // them and the retained message names only whichever came first. Qualifying
  // each sample keeps the failing column recoverable from the merged issue.
  let samples = match issue_code.code {
    ChromiumRowIssueCode::ColumnRead(column) => issue_code
      .samples
      .iter()
      .map(|sample| format!("{column} column, {sample}"))
      .collect(),
    _ => issue_code.samples.clone(),
  };
  issue(code, stage, IssueSeverityCode::error(), message)
    .with_occurrences(u32::try_from(issue_code.occurrences).unwrap_or(u32::MAX))
    .with_samples(samples)
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
    failure,
    legacy_error: _,
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
    // that reports an extraction failure lost something, so it must not be
    // downgraded to the same `info` signal as an empty profile.
    outcome.issues.push(match failure {
      Some(ChromiumProfileFailure::Extraction(message)) => issue(
        "profile_extraction_failed",
        ExtractionStageCode::acquisition(),
        IssueSeverityCode::error(),
        message,
      ),
      _ => issue(
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
  // Only a failure to acquire, parse, or query demotes the source. Rejected
  // rows are already reported above and leave the source succeeded.
  if let Some(ChromiumProfileFailure::Extraction(message)) = failure {
    push_aggregated(
      &mut source.issues,
      issue(
        "source_extraction_failed",
        ExtractionStageCode::acquisition(),
        IssueSeverityCode::error(),
        message,
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
  if outcome.sources.is_empty() {
    // Discovery only admits a profile here when it found either a persistent
    // database or a session candidate (`gecko_profile_has_source`), so a
    // profile that reaches this adapter with zero sources means whatever
    // justified its admission - a Gecko session candidate, since a
    // discovered persistent source always projects into `sources` - is gone
    // by the time of extraction. That is a real failure, not the "nothing
    // was ever there" case `no_sources` means. Safari and Internet Explorer
    // profiles always carry a pre-populated source slot (see their registry
    // discovery), so this branch is unreachable for them.
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
    error_stage,
    row_error,
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
  // A rejected row costs cookies, so it is an error-severity issue that makes
  // the report `partial` -- but acquisition, parsing, and the query completed,
  // so the source itself still succeeded. This mirrors how the Chromium adapter
  // treats its row issues.
  //
  // Keyed on the count, not on whether an engine happened to keep the error:
  // Safari and Internet Explorer report skipped rows without one, and deriving
  // the issue from the error alone let a report claim `complete` while cookies
  // had been dropped.
  if rows_skipped > 0 {
    push_aggregated(
      &mut outcome.issues,
      issue(
        "row_read_failed",
        ExtractionStageCode::parse(),
        IssueSeverityCode::error(),
        row_error.unwrap_or_else(|| format!("{rows_skipped} row(s) could not be read")),
      )
      .with_occurrences(u32::try_from(rows_skipped).unwrap_or(u32::MAX)),
    );
  }
  if let Some(error) = error {
    push_aggregated(
      &mut outcome.issues,
      issue(
        "source_extraction_failed",
        match error_stage {
          SourceFailureStage::Acquisition => ExtractionStageCode::acquisition(),
          SourceFailureStage::Parse => ExtractionStageCode::parse(),
          SourceFailureStage::Query => ExtractionStageCode::query(),
        },
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
    // Discovery counts, not the post-selection list: a profile-selected report
    // must not claim the installations it filtered out were never there. A root
    // that existed but could not be read also counts as detected -- otherwise
    // the report says `failed` and "not detected" about the same browser.
    detected: report.installations_discovered > 0 || report.installations_detected > 0,
    installations_discovered: report.installations_discovered,
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
    detected: engine.installations_discovered > 0 || engine.installations_detected > 0,
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
        registry::gecko_report(&browser.canonical_id, profile_id, domains)?
      } else {
        registry::gecko_profiles(&browser.canonical_id)?
      };
      engine_browser_outcome(&browser_id, engine)
    }
    #[cfg(target_os = "macos")]
    "safari" => {
      let engine = if extract {
        registry::safari_report(&browser.canonical_id, profile_id, domains)?
      } else {
        registry::safari_profiles(&browser.canonical_id)?
      };
      engine_browser_outcome(&browser_id, engine)
    }
    #[cfg(target_os = "windows")]
    "internet_explorer" => {
      let engine = if extract {
        registry::internet_explorer_report(&browser.canonical_id, profile_id, domains)?
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
  // Engines raise profile and source issues without context because the
  // enclosing profile is implied by where they sit. That holds only while the
  // report keeps its shape: a consumer that flattens every issue into one list
  // -- which the CLI and bindings do -- cannot tell which profile an issue came
  // from. The identity is known here, so stamp it once.
  let identity = &engine.profile;
  let stamp = |issue: ExtractionIssue| {
    issue.with_context(
      Some(&identity.browser_id),
      Some(&identity.installation_id),
      Some(&identity.profile_id),
    )
  };
  let sources = engine
    .sources
    .into_iter()
    .map(|mut source| {
      sort_cookies(&mut source.cookies);
      stats.add(&source.stats);
      let issues = source.issues.into_iter().map(stamp).collect();
      SourceExtraction {
        source: source.source,
        status: source_status(source.failed),
        selected: source.selected,
        acquisition_strategy: source.acquisition_strategy,
        cookies: source.cookies,
        stats: source.stats,
        issues,
      }
    })
    .collect::<Vec<_>>();
  let issues = engine.issues.into_iter().map(stamp).collect();
  ProfileExtraction {
    profile: engine.profile,
    sources,
    stats: stats.into_stats(),
    issues,
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
  // Every engine seam now applies the selection itself, before it acquires a
  // single source, so by here the list is already narrowed. This stays as the
  // boundary check for the one case no engine covers: a registered browser
  // whose engine has no adapter compiled into this build reports no profiles at
  // all, and an unknown profile id must still be a request error there.
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
  // A browser whose roots were found but could not be read is detected-and-
  // failed, not absent. Saying "not detected" beside a `failed` status would
  // describe two different worlds in one report.
  if !outcome.detected && !outcome.discovery_failed {
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
  profile_descriptors_from_outcome(browser_id, outcome)
}

/// Chrome-specific listing whose first entry follows the advisory `Local
/// State` activity hints. The generic `browser_profiles("chrome")` path keeps
/// its frozen default-first order.
pub(crate) fn chrome_profile_descriptors() -> Result<Vec<ProfileDescriptor>> {
  let browser_id = BrowserId::known("chrome");
  registry::chrome_profiles()?
    .into_iter()
    .map(|profile| chromium_profile_descriptor(&browser_id, profile))
    .collect()
}

/// Resolves a human-facing Chrome profile selector and then uses the same
/// report pipeline as an opaque-ID `browser_report` request. Re-discovery is
/// deliberate: the report must retain current typed discovery/source outcomes
/// rather than flattening the selected source into the legacy cookie vector.
pub(crate) fn chrome_profile_report(
  profile: &str,
  domains: Option<Vec<String>>,
) -> Result<ExtractionReport> {
  let profile = registry::select_chrome_profile(profile)?;
  browser_extraction_report("chrome", Some(&profile.profile_id), domains)
}

fn chromium_profile_descriptor(
  browser_id: &BrowserId,
  profile: registry::ChromiumProfile,
) -> Result<ProfileDescriptor> {
  let identity = profile_identity(
    browser_id,
    &profile.installation_id,
    &profile.profile_id,
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
  outcome: BrowserOutcome,
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
    failure: Option<ChromiumProfileFailure>,
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
      failure,
      legacy_error: None,
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
      chromium_profile(
        false,
        Some(ChromiumProfileFailure::Extraction(
          "Local State is unreadable".to_owned(),
        )),
      ),
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
      legacy_installation_priority: 0,
      legacy_profile_order: 0,
      legacy_is_default: true,
      legacy_eligible: true,
      installation_path: PathBuf::from("/firefox"),
      legacy_installation_path: PathBuf::from("/firefox"),
      name: "default".to_owned(),
      legacy_name: "default".to_owned(),
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
      error_stage: SourceFailureStage::Acquisition,
      row_error: None,
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
  /// Safari and Internet Explorer report skipped rows without keeping the
  /// underlying error. Deriving the row issue from that error alone let a
  /// report claim `complete` while cookies had been dropped.
  #[test]
  fn skipped_rows_without_a_row_error_still_degrade_the_report() {
    let mut profile = EngineExtractionOutcome::new(identity(), true);
    let mut source = engine_source("Cookies.binarycookies", "persistent", 10, true, None);
    source.rows_seen = 3;
    source.rows_skipped = 2;
    source.row_error = None;
    profile.sources.push(engine_source_outcome(source));

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

    let mut chromium = chromium_profile(true, None);
    chromium.cookies = vec![cookie("chromium")];
    chromium.stats = crate::browser::chromium::ChromiumExtractionStats {
      rows_seen: 3,
      cookies_emitted: 1,
      rows_skipped: 2,
    };
    chromium.row_issues = vec![crate::browser::chromium::ChromiumRowIssue {
      code: crate::browser::chromium::ChromiumRowIssueCode::Decode,
      occurrences: 2,
      samples: vec!["row 2".to_owned(), "row 3".to_owned()],
    }];
    let chromium = chromium_profile_outcome(&BrowserId::known("chrome"), &"d".repeat(64), chromium)
      .expect("adapt Chromium counters");

    let mut profiles = vec![chromium];
    for (format, name) in [
      ("mozilla_sqlite", "mozilla"),
      ("safari_binarycookies", "safari"),
      ("internet_explorer_ese", "internet-explorer"),
    ] {
      let mut source = engine_source(name, SOURCE_ROLE_PERSISTENT, 10, true, None);
      source.format = format;
      source.cookies = vec![cookie(name)];
      source.rows_seen = 3;
      source.rows_skipped = 2;
      source.row_error = Some(format!("{name} rejected two records"));
      let mut profile = EngineExtractionOutcome::new(identity(), true);
      profile.sources.push(engine_source_outcome(source));
      profiles.push(profile);
    }

    let report = assemble(4, vec![outcome(profiles, false)]);
    assert_eq!(report.summary.rows_seen, 12);
    assert_eq!(report.summary.rows_skipped, 8);
    assert_eq!(report.summary.cookies_emitted, 4);
    assert_counter_identity(&report);
  }

  #[test]
  fn a_source_that_skipped_nothing_reports_no_row_issue() {
    let mut profile = EngineExtractionOutcome::new(identity(), true);
    profile.sources.push(engine_source_outcome(engine_source(
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
      (SourceFailureStage::Acquisition, "acquisition"),
      (SourceFailureStage::Parse, "parse"),
      (SourceFailureStage::Query, "query"),
    ] {
      let mut source = engine_source("cookies.sqlite", "persistent", 10, true, Some("boom"));
      source.error_stage = stage;
      let outcome = engine_source_outcome(source);
      let issue = outcome
        .issues
        .iter()
        .find(|issue| issue.code.as_str() == "source_extraction_failed")
        .expect("a failure issue");
      assert_eq!(issue.stage.as_str(), expected);
    }
  }

  /// Name-column and value-column failures share a code, so aggregation merges
  /// them; the sample must still say which column was lost.
  #[test]
  fn merged_column_failures_keep_the_column_in_their_samples() {
    use crate::browser::chromium::{ChromiumRowIssue, ChromiumRowIssueCode};

    let mut issues = Vec::new();
    for (column, row) in [("name", 1usize), ("value", 7)] {
      push_aggregated(
        &mut issues,
        row_issue(&ChromiumRowIssue {
          code: ChromiumRowIssueCode::ColumnRead(column),
          occurrences: 1,
          samples: vec![format!("row {row}")],
        }),
      );
    }
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].occurrences, 2);
    assert_eq!(
      issues[0].samples,
      vec!["name column, row 1", "value column, row 7"]
    );
  }
  /// Profile and source issues carry no context from the engines, because the
  /// enclosing profile is implied structurally. Consumers that flatten every
  /// issue into one list -- the CLI and the bindings do -- lose that, so the
  /// identity is stamped on before the report leaves the builder.
  #[test]
  fn profile_and_source_issues_carry_their_profile_context() {
    let mut profile = EngineExtractionOutcome::new(identity(), true);
    profile.issues.push(issue(
      "profile_extraction_failed",
      ExtractionStageCode::acquisition(),
      IssueSeverityCode::error(),
      "profile level",
    ));
    let mut source = engine_source(
      "cookies.sqlite",
      "persistent",
      10,
      true,
      Some("source level"),
    );
    source.error_stage = SourceFailureStage::Parse;
    profile.sources.push(engine_source_outcome(source));

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

    let engine = test_seams::gecko_report(&context, "firefox", None, None).expect("gecko report");
    assert!(engine.profiles.is_empty());
    let browser = BrowserId::known("firefox");
    let outcome = engine_browser_outcome(&browser, engine).expect("adapt the engine outcome");
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
      let engine =
        test_seams::non_chromium_discovery_with_denied_root(&context, browser_id, root.clone())
          .expect("discovery retains the metadata failure");
      assert_eq!(engine.installations_detected, 1, "{name}");
      assert_eq!(engine.installations_discovered, 0, "{name}");
      assert_eq!(engine.installations_enumerated, 0, "{name}");
      assert!(engine.all_detected_roots_failed(), "{name}");

      let browser = BrowserId::known(browser_id);
      let outcome = engine_browser_outcome(&browser, engine).expect("adapt engine discovery");
      assert!(outcome.detected, "{name}");
      assert!(outcome.discovery_failed, "{name}");
      let report = assemble(1, vec![outcome]);
      assert_eq!(report.status, ReportStatusCode::failed(), "{name}");
      assert_eq!(report.summary.browsers_detected, 1, "{name}");
      let issue = report
        .issues
        .iter()
        .find(|issue| issue.code.as_str() == "installation_metadata_failed")
        .expect("stable root metadata issue");
      assert!(issue.is_error(), "{name}");
      assert_eq!(
        issue.samples,
        [root.to_string_lossy().into_owned()],
        "{name}"
      );
      assert!(
        report
          .issues
          .iter()
          .all(|issue| issue.code.as_str() != "browser_not_detected"),
        "{name}"
      );

      let engine = test_seams::non_chromium_discovery_with_denied_root(&context, browser_id, root)
        .expect("repeat deterministic discovery for listing");
      let outcome = engine_browser_outcome(&browser, engine).expect("adapt listing discovery");
      let error = profile_descriptors_from_outcome(browser_id, outcome)
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
    let outcome = engine_browser_outcome(&browser, engine).expect("adapt the engine outcome");
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
    let outcome = engine_browser_outcome(&browser, engine).expect("adapt the engine outcome");
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
    let outcome = engine_browser_outcome(&browser, engine).expect("adapt the engine outcome");
    let report = assemble(1, vec![outcome]);

    assert_eq!(report.summary.installations_discovered, 1);
    assert_eq!(report.summary.profiles_discovered, 1);
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
      test_seams::internet_explorer_report(&context, "internet_explorer", None, None, |_, _| {
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
          row_error: None,
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
    let outcome = engine_browser_outcome(&BrowserId::known("firefox"), engine)
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

    let one =
      test_seams::chromium_report(&context, "chrome", Some(&selected_profile), None, no_keys())
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
  fn post_filtered_report(
    browser: &BrowserId,
    engine: registry::EngineExtractionOutcome,
    profile_id: &str,
  ) -> ExtractionReport {
    let mut outcome = engine_browser_outcome(browser, engine).expect("adapt the engine outcome");
    outcome
      .profiles
      .retain(|profile| profile.profile.profile_id.as_str() == profile_id);
    assemble(1, vec![outcome])
  }

  fn selected_report(
    browser: &BrowserId,
    engine: registry::EngineExtractionOutcome,
  ) -> ExtractionReport {
    assemble(
      1,
      vec![engine_browser_outcome(browser, engine).expect("adapt the engine outcome")],
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
    let selected = full.profiles[1].profile_id.clone();
    let expected = post_filtered_report(&browser, full, &selected);

    let engine = test_seams::gecko_report(&context, "firefox", Some(&selected), None)
      .expect("profile-selected report");
    let actual = selected_report(&browser, engine);

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
    let selected = full.profiles[1].profile_id.clone();
    let expected = post_filtered_report(&browser, full, &selected);

    let engine = test_seams::safari_report(&context, "safari", Some(&selected), None)
      .expect("profile-selected report");
    assert_eq!(wire(&selected_report(&browser, engine)), wire(&expected));
  }

  #[test]
  fn a_profile_selected_internet_explorer_report_says_what_the_post_filtered_report_said() {
    use crate::browser::registry::{InternetExplorerRows, PlatformId};

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
    let rows = |path: &std::path::Path, _: Option<&[String]>| {
      Ok(InternetExplorerRows {
        cookies: vec![crate::common::enums::Cookie {
          domain: ".example.com".to_owned(),
          path: "/".to_owned(),
          secure: false,
          expires: None,
          name: format!("{}", path.display()),
          value: "value".to_owned(),
          http_only: false,
          same_site: 0,
        }],
        records_seen: 1,
        records_skipped: 0,
        row_error: None,
      })
    };

    let browser = BrowserId::known("internet_explorer");
    let full =
      test_seams::internet_explorer_report(&context, "internet_explorer", None, None, rows)
        .expect("full report");
    assert_eq!(full.profiles.len(), 2);
    let selected = full.profiles[1].profile_id.clone();
    let expected = post_filtered_report(&browser, full, &selected);

    let engine = test_seams::internet_explorer_report(
      &context,
      "internet_explorer",
      Some(&selected),
      None,
      rows,
    )
    .expect("profile-selected report");
    let actual = selected_report(&browser, engine);

    assert_eq!(actual.summary.cookies_emitted, 1);
    assert_eq!(wire(&actual), wire(&expected));
  }

  /// Reported against pre-round-3 4E: a Chromium row that could not be
  /// decrypted took the whole source down with it, because "no row decoded"
  /// became a source-level failure. Section 5.7 counts a rejected row in
  /// `rows_skipped` against a source that still succeeded, so this pins the
  /// scenario end-to-end on the real chain.
  #[test]
  fn an_undecryptable_row_does_not_fail_the_chromium_source() {
    let temp = TempDir::new("chromium-undecryptable-row");
    let context = test_seams::current_context(temp.path().to_path_buf());
    let root = test_seams::primary_root_path(&context, "chrome");
    test_seams::seed_chromium_profile(&root, "Default", "Person 1");

    // Replace the plaintext cookie with a v10 blob no provider can open, so
    // every row in the profile is rejected.
    let database = root.join("Default/Cookies");
    let connection = rusqlite::Connection::open(&database).expect("open cookie database");
    connection
      .execute("DELETE FROM cookies", [])
      .expect("clear seeded cookie");
    connection
      .execute(
        "INSERT INTO cookies VALUES ('.example.com', '/', 0, 0, 'locked', '', ?1, 0, 0)",
        [b"v10undecryptable".to_vec()],
      )
      .expect("insert encrypted cookie");
    drop(connection);

    let registry_report = test_seams::chromium_report(&context, "chrome", None, None, no_keys())
      .expect("chromium report");
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
      "the rejected row must be reported: {:?}",
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
}
