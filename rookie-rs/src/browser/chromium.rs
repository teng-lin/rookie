use super::outcome::Retryability;
use crate::common::deadline::BoundaryRuntime;
#[cfg(test)]
use crate::common::secret::SecretString;
use crate::common::{enums::*, sqlite};
use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};

use super::chromium_crypto::ChromiumKeyOutcomes;
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use super::chromium_crypto::{retrieve_key_outcomes, KeyProvider};
#[cfg(test)]
use super::chromium_decoder::chromium_schema_version;
use super::chromium_decoder::{
  ChromiumBoundaryDecoder, ChromiumDecodeEvent, ChromiumDecodeIssueCode, ChromiumDecodeSummary,
  ChromiumReadOnlySource, EncryptedValuePolicy, MissingBrowserKeyIdentity,
};
/// Whether a failure is specifically "this encrypted Chromium database has no
/// browser key identity".
///
/// That is the one cause a caller can fix by naming a credential source, so it
/// is the only one a credential-less path extract may relabel as
/// `missing_chromium_credentials`. Lives here because
/// [`MissingBrowserKeyIdentity`] is `pub(super)` to `browser`, and telling
/// `direct_path` the answer is cheaper than widening the type's visibility.
pub(crate) fn is_missing_browser_key_identity(error: &anyhow::Error) -> bool {
  error.downcast_ref::<MissingBrowserKeyIdentity>().is_some()
}

/// Names the public compatibility shape a test expects after the unified
/// decoder has completed. It is deliberately never visible to the decoder
/// itself, and never steers acquisition: production code picks a projection by
/// calling `project_legacy_draft`/`project_detailed_draft`, so this label
/// survives only as test scaffolding.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CookieProjection {
  Legacy,
  Detailed,
}
use super::cookie_record::{CookieRecord, UnavailableCode};
use super::report_core::{ExtractionStageCode, IssueSeverityCode};
use super::source::{Source, SourceCandidate, SourceIssue, SourceStats};
use super::unseal::{unseal_chromium_record, ChromiumCookieValueError};

#[cfg(target_os = "linux")]
use super::chromium_platform_keys::LinuxPlatformKeyProvider;
#[cfg(target_os = "macos")]
use super::chromium_platform_keys::MacosPlatformKeyProvider;
#[allow(unused)]
use crate::config::Browser;

#[cfg(target_os = "windows")]
use super::chromium_database_acquisition;

/// Returns cookies from chromium based browser
#[cfg(target_os = "windows")]
#[deprecated(
  since = "0.6.0",
  note = "use direct_path::extract_from_path with PathExtractRequest::plaintext / unix_identity / windows_local_state"
)]
pub fn chromium_based(
  key: PathBuf,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<Cookie>> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  runtime.check()?;
  crate::direct_path::legacy_windows_chromium_with_runtime(
    key, db_path, domains, force_kill, &runtime,
  )
}

/// Returns Chromium cookies with partition and source context preserved.
#[cfg(target_os = "windows")]
#[deprecated(
  since = "0.6.0",
  note = "use from_path(FromPathRequest::new(path).chromium_*()).detailed_cookies()"
)]
pub fn chromium_based_detailed(
  key: PathBuf,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<DetailedCookie>> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  runtime.check()?;
  crate::direct_path::legacy_windows_chromium_detailed_with_runtime(
    key, db_path, domains, force_kill, &runtime,
  )
}

/// Extracts only plaintext rows without selecting or probing a key provider.
/// Encountering an encrypted row fails the request instead of degrading into
/// a partial result under an assumed browser identity.
#[cfg(unix)]
pub(crate) fn chromium_based_plaintext_only(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<Cookie>> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  chromium_based_plaintext_only_with_runtime(db_path, domains, force_kill, &runtime)
}

// Unix-only since the Windows direct-path seam stopped asking for a flat
// projection: its one remaining caller is the `#[cfg(unix)]` wrapper above.
#[cfg(unix)]
pub(crate) fn chromium_based_plaintext_only_with_runtime(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  let draft = acquire_chromium_draft_with_runtime(
    &ChromiumKeyOutcomes::default(),
    db_path.clone(),
    domains.as_deref(),
    ChromiumAcquireOptions {
      encrypted_value_policy: EncryptedValuePolicy::RejectMissingIdentity,
      acquisition: ChromiumAcquisition::WithForceKillRecovery { force_kill },
    },
    runtime,
  )?;
  project_legacy_draft_with_runtime(&db_path, draft, runtime)
}

/// Detailed counterpart to [`chromium_based_plaintext_only`].
#[cfg(unix)]
pub(crate) fn chromium_based_detailed_plaintext_only(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<DetailedCookie>> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  chromium_based_detailed_plaintext_only_with_runtime(db_path, domains, force_kill, &runtime)
}

pub(crate) fn chromium_based_detailed_plaintext_only_with_runtime(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<DetailedCookie>> {
  let draft = acquire_chromium_draft_with_runtime(
    &ChromiumKeyOutcomes::default(),
    db_path.clone(),
    domains.as_deref(),
    ChromiumAcquireOptions {
      encrypted_value_policy: EncryptedValuePolicy::RejectMissingIdentity,
      acquisition: ChromiumAcquisition::WithForceKillRecovery { force_kill },
    },
    runtime,
  )?;
  project_detailed_draft_with_runtime(&db_path, draft, runtime)
}

/// Returns cookies from chromium based browser
#[cfg(unix)]
#[deprecated(
  since = "0.6.0",
  note = "use direct_path::extract_from_path with PathExtractRequest::plaintext / unix_identity / windows_local_state"
)]
pub fn chromium_based(
  config: &Browser,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<Cookie>> {
  #[cfg(target_os = "linux")]
  {
    let provider = LinuxPlatformKeyProvider::new(config);
    extract_cookies_with_provider(&provider, &(), db_path, domains, force_kill)
  }

  #[cfg(target_os = "macos")]
  {
    let provider = MacosPlatformKeyProvider::new(config);
    extract_cookies_with_provider(&provider, &(), db_path, domains, force_kill)
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos")))]
  {
    let _ = (config, db_path, domains, force_kill);
    anyhow::bail!("Chromium cookie extraction is unsupported on this Unix platform")
  }
}

/// Returns Chromium cookies with partition and source context preserved.
#[cfg(unix)]
#[deprecated(
  since = "0.6.0",
  note = "use from_path(FromPathRequest::new(path).chromium_*()).detailed_cookies()"
)]
pub fn chromium_based_detailed(
  config: &Browser,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<DetailedCookie>> {
  #[cfg(target_os = "linux")]
  {
    let provider = LinuxPlatformKeyProvider::new(config);
    extract_detailed_cookies_with_provider(&provider, &(), db_path, domains, force_kill)
  }

  #[cfg(target_os = "macos")]
  {
    let provider = MacosPlatformKeyProvider::new(config);
    extract_detailed_cookies_with_provider(&provider, &(), db_path, domains, force_kill)
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos")))]
  {
    let _ = (config, db_path, domains, force_kill);
    anyhow::bail!("Chromium cookie extraction is unsupported on this Unix platform")
  }
}

/// Runs a Chromium probe using key outcomes already retrieved by the host key
/// session. Failures remain typed outcomes, so probing cannot turn a provider
/// error into an empty candidate list.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn chromium_based_probe_with_key_outcomes(
  outcomes: ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
  runtime: &BoundaryRuntime<'_>,
) -> Result<ChromiumProbeResult> {
  acquire_chromium_probe_with_key_outcomes(outcomes, db_path, domains, force_kill, runtime)
}

/// Row-issue samples are collected against the report contract's bound rather
/// than a separate number. Collecting fewer than the report retains silently
/// caps what a consumer can ever see below the documented limit; collecting
/// more only to have the report truncate them is wasted work.
const MAX_CHROMIUM_ROW_ISSUE_SAMPLES: usize = crate::browser::report_core::MAX_ISSUE_SAMPLES;
const SQLITE_CONNECTION_LOG: &str = "Creating SQLite connection to <path>";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChromiumRowIssueCode {
  ColumnRead(&'static str),
  Decrypt,
  Decode,
  /// The row's cipher tier has no provider compiled or enabled in this build.
  ProviderUnavailable,
  /// A compiled provider was applicable but its key retrieval failed.
  ProviderFailed,
}

#[derive(Debug, PartialEq, Eq)]
struct ChromiumRowIssue {
  pub(crate) code: ChromiumRowIssueCode,
  pub(crate) provider: Option<String>,
  pub(crate) tier: Option<String>,
  pub(crate) cause: Option<String>,
  pub(crate) retryability: Retryability,
  pub(crate) occurrences: usize,
  pub(crate) samples: Vec<String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ChromiumExtractionStats {
  pub(crate) rows_seen: usize,
  pub(crate) cookies_emitted: usize,
  pub(crate) rows_skipped: usize,
  /// Rows rejected because their stored data was malformed or could not be
  /// authenticated/decoded. Provider failures are counted separately.
  pub(crate) rows_rejected: usize,
  /// Distinct cipher tiers unavailable because an applicable provider failed.
  pub(crate) provider_failures: usize,
}

/// A successful Chromium configuration probe and its completeness signal.
///
/// `any_browser` compares all applicable identities instead of returning the
/// first configuration that happens to decrypt one fallback-key row.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug)]
pub(crate) struct ChromiumProbeResult {
  db_path: PathBuf,
  draft: ChromiumExtractionDraft,
  pub(crate) rows_skipped: usize,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl ChromiumProbeResult {
  pub(crate) fn cookie_count(&self) -> usize {
    self.draft.records.len()
  }

  pub(crate) fn project_committed(self) -> Result<Vec<Cookie>> {
    project_legacy_draft(&self.db_path, self.draft)
  }
}

#[derive(Debug, Default)]
struct ChromiumExtractionDraft {
  #[cfg(test)]
  pub(crate) cookies: Vec<Cookie>,
  #[cfg(test)]
  detailed_cookies: Vec<DetailedCookie>,
  pub(crate) records: Vec<CookieRecord>,
  pub(crate) stats: ChromiumExtractionStats,
  pub(crate) issues: Vec<ChromiumRowIssue>,
  pub(crate) acquisition_strategy: Option<sqlite::DatabaseAcquisitionStrategy>,
  pub(crate) acquisition_attempts: u32,
  pub(crate) legacy_error: Option<anyhow::Error>,
}

impl ChromiumExtractionDraft {
  pub(super) fn record_row_issue(&mut self, code: ChromiumRowIssueCode, row_number: usize) {
    self.record_row_issue_with_cause(code, row_number, None, None, None, Retryability::Unknown);
  }

  fn record_row_issue_with_cause(
    &mut self,
    code: ChromiumRowIssueCode,
    row_number: usize,
    provider: Option<String>,
    tier: Option<String>,
    cause: Option<String>,
    retryability: Retryability,
  ) {
    let issue = match self.issues.iter_mut().find(|issue| {
      issue.code == code
        && issue.provider == provider
        && issue.tier == tier
        && issue.cause == cause
        && issue.retryability == retryability
    }) {
      Some(issue) => issue,
      None => {
        self.issues.push(ChromiumRowIssue {
          code,
          provider,
          tier,
          cause,
          retryability,
          occurrences: 0,
          samples: Vec::new(),
        });
        self.issues.last_mut().expect("issue was just inserted")
      }
    };
    issue.occurrences += 1;
    if issue.samples.len() < MAX_CHROMIUM_ROW_ISSUE_SAMPLES {
      issue.samples.push(format!("row {row_number}"));
    }
  }

  pub(super) fn record_skipped_row(&mut self, code: ChromiumRowIssueCode, row_number: usize) {
    self.stats.rows_skipped += 1;
    self.stats.rows_rejected += 1;
    self.record_row_issue(code, row_number);
  }

  fn record_unseal_failure(
    &mut self,
    code: ChromiumRowIssueCode,
    row_number: usize,
    tier: Option<super::cookie_record::CipherTier>,
    cause: String,
    retryability: Retryability,
  ) {
    self.stats.rows_skipped += 1;
    match code {
      ChromiumRowIssueCode::Decrypt | ChromiumRowIssueCode::Decode => self.stats.rows_rejected += 1,
      ChromiumRowIssueCode::ColumnRead(_)
      | ChromiumRowIssueCode::ProviderUnavailable
      | ChromiumRowIssueCode::ProviderFailed => {}
    }
    let provider = matches!(
      code,
      ChromiumRowIssueCode::ProviderUnavailable | ChromiumRowIssueCode::ProviderFailed
    )
    .then(|| "platform_key_provider".to_owned());
    let tier = tier.map(|tier| match tier {
      super::cookie_record::CipherTier::V10 => "v10".to_owned(),
      super::cookie_record::CipherTier::V11 => "v11".to_owned(),
      super::cookie_record::CipherTier::V12SecretPortal => "v12_secret_portal".to_owned(),
      super::cookie_record::CipherTier::V20 => "v20".to_owned(),
      super::cookie_record::CipherTier::LegacyDpapi => "legacy_dpapi".to_owned(),
      super::cookie_record::CipherTier::Unknown(_) => "unknown".to_owned(),
      super::cookie_record::CipherTier::Malformed { .. } => "malformed".to_owned(),
    });
    self.record_row_issue_with_cause(code, row_number, provider, tier, Some(cause), retryability);
  }

  /// Converts this engine-private accumulator into the shared [`Source`].
  ///
  /// The engine boundary is the only place `ChromiumRowIssue` is translated:
  /// downstream sees `SourceIssue` like every other engine, so the report
  /// mapper stays a copy instead of a fifth vocabulary that knows what a
  /// Chromium cipher tier is.
  ///
  /// `origin` is the candidate the query was aimed at, not a rebuilt one --
  /// path, role, format, and precedence cannot drift from what discovery found
  /// because they are never copied.
  ///
  /// No `row_read_failed` is attached. Chromium describes every skipped row
  /// through a specific row issue already, so the generic fallback the
  /// candidate-driven engines need would double-report here.
  fn into_source(self, origin: SourceCandidate) -> Source {
    let Self {
      #[cfg(test)]
        cookies: _,
      #[cfg(test)]
        detailed_cookies: _,
      records,
      stats,
      issues,
      acquisition_strategy,
      acquisition_attempts,
      legacy_error,
    } = self;
    let mut source = Source::new(origin.identity(), origin.selected, origin.acquisition);
    source.acquisition = acquisition_strategy.into();
    source.acquisition_attempts = acquisition_attempts;
    source.records = records;
    source.stats = SourceStats {
      rows_seen: stats.rows_seen,
      cookies_emitted: stats.cookies_emitted,
      rows_skipped: stats.rows_skipped,
      rows_rejected: stats.rows_rejected,
      provider_failures: stats.provider_failures,
    };
    source.issues = issues.iter().map(row_issue).collect();
    if let Some(error) = legacy_error {
      source
        .issues
        .push(SourceIssue::all_rows_rejected(format!("{error:#}")));
    }
    source
  }

  pub(super) fn total_row_failure(&self, error: anyhow::Error) -> anyhow::Error {
    let issues = self
      .issues
      .iter()
      .map(|issue| {
        format!(
          "{:?}: {} occurrence(s), samples [{}]",
          issue.code,
          issue.occurrences,
          issue.samples.join(", ")
        )
      })
      .collect::<Vec<_>>()
      .join("; ");
    error.context(format!(
      "all {} Chromium cookie row(s) were skipped; row issues: {issues}",
      self.stats.rows_seen
    ))
  }
}

pub(crate) const COLUMN_READ_FAILED: &str = "column_read_failed";
const DECRYPT_FAILED: &str = "decrypt_failed";
const DECODE_FAILED: &str = "decode_failed";
const PROVIDER_FAILED: &str = "provider_failed";
const PROVIDER_UNAVAILABLE: &str = "provider_unavailable";

/// Row-issue codes that mean a row's value could not be recovered, as opposed
/// to a row that could not be read at all.
///
/// The compatibility APIs report these as `decrypt_failed` skips. Built from
/// the same constants [`row_issue`] emits, so a renamed code cannot silently
/// stop being counted.
pub(crate) const CHROMIUM_UNSEAL_ISSUE_CODES: [&str; 4] = [
  DECRYPT_FAILED,
  DECODE_FAILED,
  PROVIDER_FAILED,
  PROVIDER_UNAVAILABLE,
];

/// Translates one aggregated Chromium row issue into the shared vocabulary.
///
/// Lives here rather than in the report mapper because `ChromiumRowIssue` is
/// decoder scratch: cipher tiers, credential providers, and column names are
/// facts only this engine can name.
fn row_issue(issue: &ChromiumRowIssue) -> SourceIssue {
  let (code, stage) = match issue.code {
    ChromiumRowIssueCode::ColumnRead(_) => (COLUMN_READ_FAILED, ExtractionStageCode::parse()),
    ChromiumRowIssueCode::Decrypt => (DECRYPT_FAILED, ExtractionStageCode::decrypt()),
    ChromiumRowIssueCode::Decode => (DECODE_FAILED, ExtractionStageCode::decode()),
    ChromiumRowIssueCode::ProviderUnavailable => {
      (PROVIDER_UNAVAILABLE, ExtractionStageCode::decrypt())
    }
    ChromiumRowIssueCode::ProviderFailed => (PROVIDER_FAILED, ExtractionStageCode::decrypt()),
  };
  let provider_issue = matches!(
    issue.code,
    ChromiumRowIssueCode::ProviderUnavailable | ChromiumRowIssueCode::ProviderFailed
  );
  let message = match issue.code {
    ChromiumRowIssueCode::ColumnRead(column) => format!(
      "failed to read the {column} column of {} row(s)",
      issue.occurrences
    ),
    // A provider failure carries the underlying cause, which says more than
    // the generic count line it replaces.
    _ if provider_issue => issue
      .cause
      .clone()
      .unwrap_or_else(|| format!("{} row(s) unavailable because of {code}", issue.occurrences)),
    _ => format!("{} row(s) rejected as {code}", issue.occurrences),
  };
  // Name-column and value-column failures share one code, so aggregation merges
  // them and the retained message names only whichever came first. Qualifying
  // each sample keeps the failing column recoverable from the merged issue.
  let samples = match issue.code {
    ChromiumRowIssueCode::ColumnRead(column) => issue
      .samples
      .iter()
      .map(|sample| format!("{column} column, {sample}"))
      .collect(),
    _ => issue.samples.clone(),
  };
  let mut outcome = SourceIssue::new(code, stage, IssueSeverityCode::error(), message)
    .with_occurrences(u32::try_from(issue.occurrences).unwrap_or(u32::MAX));
  outcome.samples = samples;
  if provider_issue {
    outcome.cause = Some("credential_provider".to_owned());
    outcome.provider.clone_from(&issue.provider);
    outcome.tier.clone_from(&issue.tier);
    outcome.retryability = Some(
      match issue.retryability {
        Retryability::Retryable => "retryable",
        Retryability::NotRetryable => "not_retryable",
        Retryability::Unknown => "unknown",
      }
      .to_owned(),
    );
  }
  outcome
}

/// Finalizes one direct-path Chromium read as a single-profile outcome.
///
/// The profile is the database's parent directory; the synthetic identity is
/// supplied by `finalize_singleton_source`.
fn direct_chromium_outcome(
  db_path: &Path,
  draft: ChromiumExtractionDraft,
  runtime: Option<&BoundaryRuntime<'_>>,
) -> Result<super::outcome::Outcome> {
  super::report_build::finalize_singleton_source(
    "chromium",
    db_path.parent().unwrap_or(db_path).to_path_buf(),
    vec![draft.into_source(direct_path_candidate(db_path))],
    None,
    runtime,
  )
}

/// The candidate a direct-path query is aimed at.
///
/// A caller who names a database file has done no discovery, so there is no
/// candidate to clone; this states the one the path implies. The values match
/// what the direct-path report has always emitted for such a source.
fn direct_path_candidate(db_path: &Path) -> SourceCandidate {
  SourceCandidate {
    path: db_path.to_path_buf(),
    role: super::report_core::CookieSourceRoleId::persistent(),
    format: super::report_core::CookieSourceFormatId::known("chromium_sqlite"),
    precedence: super::registry::PERSISTENT_SOURCE_PRECEDENCE,
    exists: true,
    selected: true,
    acquisition: super::source::SourceAcquisition::NotAttempted,
    policy: super::source::AcquisitionPolicy::Fixed,
  }
}

// Only reachable in production through the automatic multi-identity
// Chromium selection, which is Linux/macOS-only; Windows exercises this via
// `#[cfg(test)]`.
#[allow(dead_code)]
fn project_legacy_draft(db_path: &Path, draft: ChromiumExtractionDraft) -> Result<Vec<Cookie>> {
  super::legacy::project_canonical_outcome(
    "chromium",
    direct_chromium_outcome(db_path, draft, None)?,
  )
}

// The flat projection is only reached on Unix now, but Windows still builds
// it under `cfg(test)` through `extract_cookies_with_key_outcomes_runtime`.
#[cfg(any(unix, test))]
fn project_legacy_draft_with_runtime(
  db_path: &Path,
  draft: ChromiumExtractionDraft,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  super::legacy::project_canonical_outcome_with_runtime(
    "chromium",
    direct_chromium_outcome(db_path, draft, Some(runtime))?,
    runtime,
  )
}

// See `project_legacy_draft`: only reachable in production on Linux/macOS.
#[allow(dead_code)]
fn project_detailed_draft(
  db_path: &Path,
  draft: ChromiumExtractionDraft,
) -> Result<Vec<DetailedCookie>> {
  super::legacy::project_canonical_detailed_outcome(
    "chromium",
    direct_chromium_outcome(db_path, draft, None)?,
  )
}

fn project_detailed_draft_with_runtime(
  db_path: &Path,
  draft: ChromiumExtractionDraft,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<DetailedCookie>> {
  super::legacy::project_canonical_detailed_outcome_with_runtime(
    "chromium",
    direct_chromium_outcome(db_path, draft, Some(runtime))?,
    runtime,
  )
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn extract_cookies_with_provider<Context: ?Sized, Provider>(
  provider: &Provider,
  context: &Context,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<Cookie>>
where
  Provider: KeyProvider<Context, Keys = ChromiumKeyOutcomes>,
{
  let clock = crate::common::deadline::SystemClock;
  let deadline = crate::common::deadline::Deadline::after(
    &clock,
    crate::common::deadline::DEFAULT_EXTRACTION_BUDGET,
  );
  let runtime = BoundaryRuntime::new(&clock, deadline);
  let outcomes = retrieve_key_outcomes(provider, context, &runtime)?;
  extract_cookies_with_key_outcomes_runtime(outcomes, db_path, domains, force_kill, &runtime)
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn extract_detailed_cookies_with_provider<Context: ?Sized, Provider>(
  provider: &Provider,
  context: &Context,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<DetailedCookie>>
where
  Provider: KeyProvider<Context, Keys = ChromiumKeyOutcomes>,
{
  let clock = crate::common::deadline::SystemClock;
  let deadline = crate::common::deadline::Deadline::after(
    &clock,
    crate::common::deadline::DEFAULT_EXTRACTION_BUDGET,
  );
  let runtime = BoundaryRuntime::new(&clock, deadline);
  let outcomes = retrieve_key_outcomes(provider, context, &runtime)?;
  extract_detailed_cookies_with_key_outcomes_runtime(
    outcomes, db_path, domains, force_kill, &runtime,
  )
}

#[cfg(test)]
pub(crate) fn extract_cookies_with_key_outcomes(
  outcomes: ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<Cookie>> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  extract_cookies_with_key_outcomes_runtime(outcomes, db_path, domains, force_kill, &runtime)
}

// `windows` dropped from this gate: Windows direct-path acquisition now goes
// through the detailed seam, so nothing outside tests asks it for flat rows.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) fn extract_cookies_with_key_outcomes_runtime(
  outcomes: ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  let draft = acquire_chromium_draft_with_runtime(
    &outcomes,
    db_path.clone(),
    domains.as_deref(),
    ChromiumAcquireOptions {
      encrypted_value_policy: EncryptedValuePolicy::UseKeyOutcomes,
      acquisition: ChromiumAcquisition::WithForceKillRecovery { force_kill },
    },
    runtime,
  )?;
  project_legacy_draft_with_runtime(&db_path, draft, runtime)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows", test))]
pub(crate) fn extract_detailed_cookies_with_key_outcomes_runtime(
  outcomes: ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<DetailedCookie>> {
  let draft = acquire_chromium_draft_with_runtime(
    &outcomes,
    db_path.clone(),
    domains.as_deref(),
    ChromiumAcquireOptions {
      encrypted_value_policy: EncryptedValuePolicy::UseKeyOutcomes,
      acquisition: ChromiumAcquisition::WithForceKillRecovery { force_kill },
    },
    runtime,
  )?;
  project_detailed_draft_with_runtime(&db_path, draft, runtime)
}

#[cfg(target_os = "windows")]
pub(crate) fn extract_detailed_cookies_with_key_outcomes_without_platform_recovery(
  outcomes: &ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<&[String]>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<DetailedCookie>> {
  let draft = acquire_chromium_draft_with_runtime(
    outcomes,
    db_path.clone(),
    domains,
    ChromiumAcquireOptions {
      encrypted_value_policy: EncryptedValuePolicy::UseKeyOutcomes,
      acquisition: ChromiumAcquisition::DirectRead,
    },
    runtime,
  )?;
  project_detailed_draft_with_runtime(&db_path, draft, runtime)
}

#[cfg(target_os = "windows")]
pub(crate) fn extract_detailed_cookies_plaintext_without_platform_recovery(
  db_path: PathBuf,
  domains: Option<&[String]>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<DetailedCookie>> {
  let draft = acquire_chromium_draft_with_runtime(
    &ChromiumKeyOutcomes::default(),
    db_path.clone(),
    domains,
    ChromiumAcquireOptions {
      encrypted_value_policy: EncryptedValuePolicy::RejectMissingIdentity,
      acquisition: ChromiumAcquisition::DirectRead,
    },
    runtime,
  )?;
  project_detailed_draft_with_runtime(&db_path, draft, runtime)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn acquire_chromium_probe_with_key_outcomes(
  outcomes: ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
  runtime: &BoundaryRuntime<'_>,
) -> Result<ChromiumProbeResult> {
  let draft = acquire_chromium_draft_with_runtime(
    &outcomes,
    db_path.clone(),
    domains.as_deref(),
    ChromiumAcquireOptions {
      encrypted_value_policy: EncryptedValuePolicy::UseKeyOutcomes,
      acquisition: ChromiumAcquisition::WithForceKillRecovery { force_kill },
    },
    runtime,
  )?;
  let rows_skipped = draft.stats.rows_skipped;
  Ok(ChromiumProbeResult {
    db_path,
    draft,
    rows_skipped,
  })
}

/// The database-acquisition strategy for a single Chromium read.
///
/// Once projection is applied by the caller, this is the only axis on which the
/// former per-projection wrappers diverged: whether the read is wrapped in the
/// Windows force-kill lock recovery, and if so whether a process holding the
/// database open may be terminated.
///
/// `DirectRead` is only ever constructed by the Windows-gated
/// `*_without_platform_recovery` callers, so it is never constructed on other
/// targets; the whole engine boundary is compiled on every platform, hence the
/// allow rather than a `cfg`.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
enum ChromiumAcquisition {
  /// Read the database directly, with no force-kill lock recovery and without
  /// re-checking the runtime deadline. This is the historical
  /// `*_without_platform_recovery` path, whose callers have already checked the
  /// deadline.
  DirectRead,
  /// Wrap the read in Windows force-kill lock recovery; `force_kill` controls
  /// whether a process holding the database open may be terminated. On non-
  /// Windows targets there is no recovery to perform, so this checks the
  /// deadline and reads directly, and `force_kill` is inert.
  WithForceKillRecovery { force_kill: bool },
}

/// Every flag that distinguishes one Chromium acquire from another, collapsed
/// into one value so callers state a policy tuple instead of picking a bespoke
/// wrapper.
///
/// Projection is deliberately absent: the draft carries every projection's data
/// and the caller selects one with `project_*`, so it never influenced the
/// acquire itself.
#[derive(Clone, Copy, Debug)]
struct ChromiumAcquireOptions {
  /// How an encrypted row is treated when no browser key identity is present.
  encrypted_value_policy: EncryptedValuePolicy,
  /// Whether the read is wrapped in platform force-kill lock recovery.
  acquisition: ChromiumAcquisition,
}

/// Acquires one Chromium cookie database into a [`ChromiumExtractionDraft`].
///
/// The single point where the acquisition strategy and encrypted-value policy
/// are resolved. `ChromiumExtractionDraft`, `ChromiumRowIssue`, and the
/// decoder's row vocabulary stop here — callers project the draft or turn it
/// into a [`Source`].
fn acquire_chromium_draft_with_runtime(
  outcomes: &ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<&[String]>,
  options: ChromiumAcquireOptions,
  runtime: &BoundaryRuntime<'_>,
) -> Result<ChromiumExtractionDraft> {
  let ChromiumAcquireOptions {
    encrypted_value_policy,
    acquisition,
  } = options;
  match acquisition {
    ChromiumAcquisition::DirectRead => decode_chromium_database_with_runtime(
      outcomes,
      db_path,
      domains,
      encrypted_value_policy,
      runtime,
    ),
    ChromiumAcquisition::WithForceKillRecovery { force_kill } => {
      runtime.check()?;
      #[cfg(target_os = "windows")]
      {
        chromium_database_acquisition::with_force_kill_recovery(
          &db_path,
          force_kill,
          runtime,
          |path, runtime| {
            decode_chromium_database_with_runtime(
              outcomes,
              path.to_path_buf(),
              domains,
              encrypted_value_policy,
              runtime,
            )
          },
        )
      }
      #[cfg(not(target_os = "windows"))]
      {
        let _ = force_kill;
        decode_chromium_database_with_runtime(
          outcomes,
          db_path,
          domains,
          encrypted_value_policy,
          runtime,
        )
      }
    }
  }
}

#[cfg(test)]
fn acquire_chromium_draft(
  outcomes: &ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<ChromiumExtractionDraft> {
  acquire_chromium_draft_mode(
    outcomes,
    db_path,
    domains,
    force_kill,
    CookieProjection::Legacy,
    EncryptedValuePolicy::UseKeyOutcomes,
  )
}

/// Acquires one Chromium cookie database and returns it as a [`Source`].
///
/// This is the engine's crate boundary: `ChromiumExtractionDraft`,
/// `ChromiumRowIssue`, and the decoder's row vocabulary stop here. The caller
/// hands over the candidate it selected, which becomes `Source::origin`.
pub(crate) fn acquire_chromium_source_with_runtime(
  outcomes: &ChromiumKeyOutcomes,
  origin: SourceCandidate,
  domains: Option<Vec<String>>,
  force_kill: bool,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Source> {
  let draft = acquire_chromium_draft_with_runtime(
    outcomes,
    origin.path.clone(),
    domains.as_deref(),
    ChromiumAcquireOptions {
      encrypted_value_policy: EncryptedValuePolicy::UseKeyOutcomes,
      acquisition: ChromiumAcquisition::WithForceKillRecovery { force_kill },
    },
    runtime,
  )?;
  Ok(draft.into_source(origin))
}

#[cfg(test)]
fn acquire_chromium_draft_mode(
  outcomes: &ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
  _projection: CookieProjection,
  encrypted_value_policy: EncryptedValuePolicy,
) -> Result<ChromiumExtractionDraft> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  acquire_chromium_draft_with_runtime(
    outcomes,
    db_path,
    domains.as_deref(),
    ChromiumAcquireOptions {
      encrypted_value_policy,
      acquisition: ChromiumAcquisition::WithForceKillRecovery { force_kill },
    },
    &runtime,
  )
}

fn decode_chromium_database_with_runtime(
  outcomes: &ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<&[String]>,
  encrypted_value_policy: EncryptedValuePolicy,
  runtime: &BoundaryRuntime<'_>,
) -> Result<ChromiumExtractionDraft> {
  log::info!("{SQLITE_CONNECTION_LOG}");
  let database = sqlite::with_browser_database_with_runtime(
    db_path,
    |connection| {
      decode_and_unseal_cookie_records_with_runtime(
        connection,
        domains,
        encrypted_value_policy,
        |record, schema_version| unseal_chromium_record(record, outcomes, schema_version),
        runtime,
      )
    },
    runtime,
  );
  let database = match database {
    Err(error)
      if error
        .chain()
        .any(|cause| cause.is::<MissingBrowserKeyIdentity>()) =>
    {
      return Err(MissingBrowserKeyIdentity.into());
    }
    result => result?,
  };
  log::debug!(
    "Chromium database query succeeded via {:?} after {} attempt(s)",
    database.strategy(),
    database.attempts()
  );
  let strategy = database.strategy();
  let attempts = database.attempts();
  let mut outcome = database.into_value();
  outcome.acquisition_strategy = Some(strategy);
  outcome.acquisition_attempts = attempts;
  Ok(outcome)
}

#[cfg(test)]
fn decode_and_unseal_cookie_records<Unseal>(
  connection: &rusqlite::Connection,
  domains: Option<&[String]>,
  encrypted_value_policy: EncryptedValuePolicy,
  unseal: Unseal,
) -> Result<ChromiumExtractionDraft>
where
  Unseal: FnMut(
    CookieRecord,
    u32,
  )
    -> std::result::Result<CookieRecord, Box<(CookieRecord, ChromiumCookieValueError)>>,
{
  let clock = crate::common::deadline::SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  decode_and_unseal_cookie_records_with_runtime(
    connection,
    domains,
    encrypted_value_policy,
    unseal,
    &runtime,
  )
}

fn decode_and_unseal_cookie_records_with_runtime<Unseal>(
  connection: &rusqlite::Connection,
  domains: Option<&[String]>,
  encrypted_value_policy: EncryptedValuePolicy,
  mut unseal: Unseal,
  runtime: &BoundaryRuntime<'_>,
) -> Result<ChromiumExtractionDraft>
where
  Unseal: FnMut(
    CookieRecord,
    u32,
  )
    -> std::result::Result<CookieRecord, Box<(CookieRecord, ChromiumCookieValueError)>>,
{
  let mut outcome = ChromiumExtractionDraft::default();
  let mut failed_provider_tiers = std::collections::HashSet::new();
  let mut last_row_error = None;
  // Successful rows stay protected until the SQLite cursor is cleanly
  // exhausted. A later iteration, identity, or retry error therefore drops
  // SecretString-backed records instead of abandoning public String values.
  let mut staged_records = Vec::new();
  let source = ChromiumReadOnlySource {
    connection,
    domains,
  };
  let decoder = ChromiumBoundaryDecoder {
    encrypted_value_policy,
  };
  let mut sink = |event| -> Result<()> {
    let decoded = match event {
      ChromiumDecodeEvent::RowFailure(failure) => {
        log::warn!("Failed to decode Chromium cookie row: {}", failure.error);
        let code = match failure.code {
          ChromiumDecodeIssueCode::ColumnRead(column) => ChromiumRowIssueCode::ColumnRead(column),
        };
        outcome.record_skipped_row(code, failure.row_number);
        last_row_error = Some(failure.error);
        return Ok(());
      }
      ChromiumDecodeEvent::Record(decoded) => decoded,
    };
    let encrypted_tier = match &decoded.record.value {
      super::cookie_record::CookieValue::Encrypted { tier, .. } => Some(*tier),
      super::cookie_record::CookieValue::Plain(_)
      | super::cookie_record::CookieValue::Unavailable(_) => None,
    };
    match unseal(decoded.record, decoded.schema_version) {
      Ok(record) => {
        if let Some(failure) = decoded.pending_context_failure {
          log::warn!(
            "Failed to decode Chromium cookie context: {}",
            failure.error
          );
          let code = match failure.code {
            ChromiumDecodeIssueCode::ColumnRead(column) => ChromiumRowIssueCode::ColumnRead(column),
          };
          outcome.record_skipped_row(code, failure.row_number);
          last_row_error = Some(failure.error);
          return Ok(());
        }
        staged_records.push(record);
      }
      Err(failure) => {
        let (_record, error) = *failure;
        log::warn!("Failed to unseal cookie value: {error}");
        let code = match error.unavailable_code() {
          UnavailableCode::Decrypt => ChromiumRowIssueCode::Decrypt,
          UnavailableCode::Decode => ChromiumRowIssueCode::Decode,
          UnavailableCode::ProviderUnavailable => ChromiumRowIssueCode::ProviderUnavailable,
          UnavailableCode::ProviderFailed => ChromiumRowIssueCode::ProviderFailed,
        };
        if code == ChromiumRowIssueCode::ProviderFailed {
          if let Some(tier) = encrypted_tier {
            failed_provider_tiers.insert(tier);
          }
        }
        let retryability = error.retryability();
        outcome.record_unseal_failure(
          code,
          decoded.row_number,
          encrypted_tier,
          error.to_string(),
          retryability,
        );
        // Preserve the historical error surface for unseal failures. Context
        // column errors remain typed because ordered events prevent an earlier
        // stringified unseal error from overwriting a later decoder error.
        last_row_error = Some(anyhow!(error.to_string()));
      }
    }
    Ok(())
  };
  let ChromiumDecodeSummary { rows_seen } =
    crate::common::boundary::decode(&decoder, &source, &mut sink, runtime)?;
  outcome.stats.rows_seen = rows_seen;
  outcome.stats.provider_failures = failed_provider_tiers.len();
  if outcome.stats.rows_seen > 0 && outcome.stats.rows_skipped == outcome.stats.rows_seen {
    if let Some(error) = last_row_error {
      outcome.legacy_error = Some(outcome.total_row_failure(error));
    }
  }
  if staged_records
    .iter()
    .any(|record| !matches!(record.value, super::cookie_record::CookieValue::Plain(_)))
  {
    return Err(anyhow!(
      "Chromium unseal stage returned a successful record without plaintext"
    ));
  }
  for record in staged_records {
    #[cfg(test)]
    {
      outcome.detailed_cookies.push(
        record
          .clone()
          .into_detailed_cookie()
          .expect("unseal produced plaintext"),
      );
      outcome.cookies.push(
        record
          .clone()
          .into_cookie()
          .expect("unseal produced plaintext"),
      );
    }
    outcome.records.push(record);
    outcome.stats.cookies_emitted += 1;
  }
  Ok(outcome)
}

#[cfg(test)]
fn decode_chromium_connection(
  connection: &rusqlite::Connection,
  outcomes: &ChromiumKeyOutcomes,
  domains: Option<&[String]>,
) -> Result<ChromiumExtractionDraft> {
  decode_chromium_connection_mode(
    connection,
    outcomes,
    domains,
    CookieProjection::Legacy,
    EncryptedValuePolicy::UseKeyOutcomes,
  )
}

#[cfg(test)]
fn decode_chromium_connection_mode(
  connection: &rusqlite::Connection,
  outcomes: &ChromiumKeyOutcomes,
  domains: Option<&[String]>,
  _projection: CookieProjection,
  encrypted_value_policy: EncryptedValuePolicy,
) -> Result<ChromiumExtractionDraft> {
  decode_and_unseal_cookie_records(
    connection,
    domains,
    encrypted_value_policy,
    |record, schema_version| unseal_chromium_record(record, outcomes, schema_version),
  )
}

#[cfg(test)]
mod tests;
