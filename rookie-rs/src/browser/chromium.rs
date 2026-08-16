use crate::common::boundary::Decoder;
use crate::common::deadline::BoundaryRuntime;
#[cfg(test)]
use crate::common::secret::{SecretBytes, SecretString};
use crate::common::{enums::*, sqlite};
#[cfg(target_os = "windows")]
use anyhow::Context;
use anyhow::{anyhow, Result};
use std::path::PathBuf;

#[cfg(test)]
use super::chromium_crypto::LegacyCipherOutcome;
use super::chromium_crypto::{retrieve_key_outcomes, ChromiumKeyOutcomes, KeyProvider};
#[cfg(test)]
use super::chromium_decoder::chromium_schema_version;
use super::chromium_decoder::{
  ChromiumBoundaryDecoder, ChromiumDecodeEvent, ChromiumDecodeIssueCode, ChromiumDecodeSummary,
  ChromiumReadOnlySource, CookieProjection, EncryptedValuePolicy, MissingBrowserKeyIdentity,
};
use super::cookie_record::{CookieRecord, UnavailableCode};
#[cfg(all(test, unix))]
use super::unseal::decrypt_encrypted_value_with_outcomes;
#[cfg(test)]
use super::unseal::{
  decode_chromium_cookie_value, decrypt_encrypted_value,
  decrypt_encrypted_value_with_cipher_adapter, ChromiumCookieDecodeError, CipherAdapter,
};
use super::unseal::{unseal_chromium_record, ChromiumCookieValueError};
#[cfg(test)]
use sha2::{Digest, Sha256};

#[cfg(test)]
const CHROMIUM_HOST_HASH_LEN: usize = 32;
#[cfg(target_os = "linux")]
use super::chromium_platform_keys::LinuxPlatformKeyProvider;
#[cfg(target_os = "macos")]
use super::chromium_platform_keys::MacosPlatformKeyProvider;
#[cfg(target_os = "windows")]
use super::chromium_platform_keys::WindowsPlatformKeyProvider;
#[allow(unused)]
use crate::config::Browser;

#[cfg(target_os = "windows")]
use super::chromium_database_acquisition;

/// Returns cookies from chromium based browser
#[cfg(target_os = "windows")]
#[deprecated(
  since = "0.6.0",
  note = "use direct_path::chromium_cookies_from_path with ChromiumPathRequest"
)]
pub fn chromium_based(
  key: PathBuf,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<Cookie>> {
  let content = std::fs::read_to_string(key)?;
  let key_dict: serde_json::Value =
    serde_json::from_str(content.as_str()).context("Can't read json file")?;
  let provider = WindowsPlatformKeyProvider::new(&key_dict);
  query_cookies(&provider, &(), db_path, domains, force_kill)
}

/// Returns Chromium cookies with partition and source context preserved.
#[cfg(target_os = "windows")]
#[deprecated(
  since = "0.6.0",
  note = "use direct_path::chromium_cookies_from_path_detailed with ChromiumPathRequest"
)]
pub fn chromium_based_detailed(
  key: PathBuf,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<DetailedCookie>> {
  let content = std::fs::read_to_string(key)?;
  let key_dict: serde_json::Value =
    serde_json::from_str(content.as_str()).context("Can't read json file")?;
  let provider = WindowsPlatformKeyProvider::new(&key_dict);
  query_detailed_cookies(&provider, &(), db_path, domains, force_kill)
}

/// Extracts only plaintext rows without selecting or probing a key provider.
/// Encountering an encrypted row fails the request instead of degrading into
/// a partial result under an assumed browser identity.
pub(crate) fn chromium_based_plaintext_only(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<Cookie>> {
  query_cookies_engine_outcome_mode(
    &ChromiumKeyOutcomes::default(),
    db_path,
    domains,
    force_kill,
    CookieProjection::Legacy,
    EncryptedValuePolicy::RejectMissingIdentity,
  )?
  .into_legacy_result()
}

/// Detailed counterpart to [`chromium_based_plaintext_only`].
pub(crate) fn chromium_based_detailed_plaintext_only(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<DetailedCookie>> {
  query_cookies_engine_outcome_mode(
    &ChromiumKeyOutcomes::default(),
    db_path,
    domains,
    force_kill,
    CookieProjection::Detailed,
    EncryptedValuePolicy::RejectMissingIdentity,
  )?
  .into_detailed_result()
}

/// Returns cookies from chromium based browser
#[cfg(unix)]
#[deprecated(
  since = "0.6.0",
  note = "use direct_path::chromium_cookies_from_path with ChromiumPathRequest"
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
    query_cookies(&provider, &(), db_path, domains, force_kill)
  }

  #[cfg(target_os = "macos")]
  {
    let provider = MacosPlatformKeyProvider::new(config);
    query_cookies(&provider, &(), db_path, domains, force_kill)
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
  note = "use direct_path::chromium_cookies_from_path_detailed with ChromiumPathRequest"
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
    query_detailed_cookies(&provider, &(), db_path, domains, force_kill)
  }

  #[cfg(target_os = "macos")]
  {
    let provider = MacosPlatformKeyProvider::new(config);
    query_detailed_cookies(&provider, &(), db_path, domains, force_kill)
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
  clock: &dyn crate::common::deadline::Clock,
  deadline: crate::common::deadline::Deadline,
) -> Result<ChromiumProbeResult> {
  query_cookies_probe_with_key_outcomes(outcomes, db_path, domains, force_kill, clock, deadline)
}

/// Row-issue samples are collected against the report contract's bound rather
/// than a separate number. Collecting fewer than the report retains silently
/// caps what a consumer can ever see below the documented limit; collecting
/// more only to have the report truncate them is wasted work.
const MAX_CHROMIUM_ROW_ISSUE_SAMPLES: usize = crate::browser::report_core::MAX_ISSUE_SAMPLES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChromiumRowIssueCode {
  ColumnRead(&'static str),
  Decrypt,
  Decode,
  /// The row's cipher tier has no provider compiled or enabled in this build.
  ProviderUnavailable,
  /// A compiled provider was applicable but its key retrieval failed.
  ProviderFailed,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ChromiumRowIssue {
  pub(crate) code: ChromiumRowIssueCode,
  pub(crate) provider: Option<String>,
  pub(crate) tier: Option<String>,
  pub(crate) cause: Option<String>,
  pub(crate) occurrences: usize,
  pub(crate) samples: Vec<String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ChromiumExtractionStats {
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
#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct ChromiumProbeResult {
  pub(crate) cookies: Vec<Cookie>,
  pub(crate) rows_skipped: usize,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug)]
pub(crate) struct ChromiumDetailedProbeResult {
  pub(crate) cookies: Vec<DetailedCookie>,
  pub(crate) rows_skipped: usize,
}

#[derive(Debug, Default)]
pub(crate) struct ChromiumExtractionDraft {
  pub(crate) cookies: Vec<Cookie>,
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
    self.record_row_issue_with_cause(code, row_number, None, None, None);
  }

  fn record_row_issue_with_cause(
    &mut self,
    code: ChromiumRowIssueCode,
    row_number: usize,
    provider: Option<String>,
    tier: Option<String>,
    cause: Option<String>,
  ) {
    let issue = match self.issues.iter_mut().find(|issue| {
      issue.code == code && issue.provider == provider && issue.tier == tier && issue.cause == cause
    }) {
      Some(issue) => issue,
      None => {
        self.issues.push(ChromiumRowIssue {
          code,
          provider,
          tier,
          cause,
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
    self.record_row_issue_with_cause(code, row_number, provider, tier, Some(cause));
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

  pub(crate) fn into_legacy_result(self) -> Result<Vec<Cookie>> {
    match self.legacy_error {
      Some(error) => Err(error),
      None => Ok(self.cookies),
    }
  }

  fn into_detailed_result(self) -> Result<Vec<DetailedCookie>> {
    match self.legacy_error {
      Some(error) => Err(error),
      None => Ok(self.detailed_cookies),
    }
  }

  #[cfg(unix)]
  fn into_probe_result(self) -> Result<ChromiumProbeResult> {
    match self.legacy_error {
      Some(error) => Err(error),
      None => Ok(ChromiumProbeResult {
        cookies: self.cookies,
        rows_skipped: self.stats.rows_skipped,
      }),
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn into_detailed_probe_result(self) -> Result<ChromiumDetailedProbeResult> {
    match self.legacy_error {
      Some(error) => Err(error),
      None => Ok(ChromiumDetailedProbeResult {
        cookies: self.detailed_cookies,
        rows_skipped: self.stats.rows_skipped,
      }),
    }
  }
}

fn query_cookies<Context: ?Sized, Provider>(
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
  let outcomes = retrieve_key_outcomes(provider, context, deadline);
  query_cookies_with_key_outcomes_deadline(outcomes, db_path, domains, force_kill, &clock, deadline)
}

fn query_detailed_cookies<Context: ?Sized, Provider>(
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
  let outcomes = retrieve_key_outcomes(provider, context, deadline);
  query_detailed_cookies_with_key_outcomes_deadline(
    outcomes, db_path, domains, force_kill, &clock, deadline,
  )
}

#[allow(unused_variables)]
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn query_cookies_with_key_outcomes(
  outcomes: ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<Cookie>> {
  let clock = crate::common::deadline::SystemClock;
  query_cookies_with_key_outcomes_deadline(
    outcomes,
    db_path,
    domains,
    force_kill,
    &clock,
    crate::common::deadline::Deadline::standard(),
  )
}

pub(crate) fn query_cookies_with_key_outcomes_deadline(
  outcomes: ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
  clock: &dyn crate::common::deadline::Clock,
  deadline: crate::common::deadline::Deadline,
) -> Result<Vec<Cookie>> {
  query_cookies_engine_outcome_mode_with_deadline(
    &outcomes,
    db_path,
    domains,
    force_kill,
    CookieProjection::Legacy,
    EncryptedValuePolicy::UseKeyOutcomes,
    BoundaryRuntime::new(clock, deadline),
  )?
  .into_legacy_result()
}

#[allow(unused_variables)]
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn query_detailed_cookies_with_key_outcomes(
  outcomes: ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<DetailedCookie>> {
  let clock = crate::common::deadline::SystemClock;
  query_detailed_cookies_with_key_outcomes_deadline(
    outcomes,
    db_path,
    domains,
    force_kill,
    &clock,
    crate::common::deadline::Deadline::standard(),
  )
}

pub(crate) fn query_detailed_cookies_with_key_outcomes_deadline(
  outcomes: ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
  clock: &dyn crate::common::deadline::Clock,
  deadline: crate::common::deadline::Deadline,
) -> Result<Vec<DetailedCookie>> {
  query_cookies_engine_outcome_mode_with_deadline(
    &outcomes,
    db_path,
    domains,
    force_kill,
    CookieProjection::Detailed,
    EncryptedValuePolicy::UseKeyOutcomes,
    BoundaryRuntime::new(clock, deadline),
  )?
  .into_detailed_result()
}

#[cfg(target_os = "windows")]
pub(crate) fn query_cookies_with_key_outcomes_without_platform_recovery(
  outcomes: &ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<&[String]>,
) -> Result<Vec<Cookie>> {
  query_cookies_from_database(
    outcomes,
    db_path,
    domains,
    CookieProjection::Legacy,
    EncryptedValuePolicy::UseKeyOutcomes,
  )?
  .into_legacy_result()
}

#[cfg(target_os = "windows")]
pub(crate) fn query_detailed_cookies_with_key_outcomes_without_platform_recovery(
  outcomes: &ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<&[String]>,
) -> Result<Vec<DetailedCookie>> {
  query_cookies_from_database(
    outcomes,
    db_path,
    domains,
    CookieProjection::Detailed,
    EncryptedValuePolicy::UseKeyOutcomes,
  )?
  .into_detailed_result()
}

#[cfg(target_os = "windows")]
pub(crate) fn query_cookies_plaintext_without_platform_recovery(
  db_path: PathBuf,
  domains: Option<&[String]>,
) -> Result<Vec<Cookie>> {
  query_cookies_from_database(
    &ChromiumKeyOutcomes::default(),
    db_path,
    domains,
    CookieProjection::Legacy,
    EncryptedValuePolicy::RejectMissingIdentity,
  )?
  .into_legacy_result()
}

#[cfg(target_os = "windows")]
pub(crate) fn query_detailed_cookies_plaintext_without_platform_recovery(
  db_path: PathBuf,
  domains: Option<&[String]>,
) -> Result<Vec<DetailedCookie>> {
  query_cookies_from_database(
    &ChromiumKeyOutcomes::default(),
    db_path,
    domains,
    CookieProjection::Detailed,
    EncryptedValuePolicy::RejectMissingIdentity,
  )?
  .into_detailed_result()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn chromium_based_detailed_probe_with_key_outcomes(
  outcomes: ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
  clock: &dyn crate::common::deadline::Clock,
  deadline: crate::common::deadline::Deadline,
) -> Result<ChromiumDetailedProbeResult> {
  query_cookies_engine_outcome_mode_with_deadline(
    &outcomes,
    db_path,
    domains,
    force_kill,
    CookieProjection::Detailed,
    EncryptedValuePolicy::UseKeyOutcomes,
    BoundaryRuntime::new(clock, deadline),
  )?
  .into_detailed_probe_result()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn query_cookies_probe_with_key_outcomes(
  outcomes: ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
  clock: &dyn crate::common::deadline::Clock,
  deadline: crate::common::deadline::Deadline,
) -> Result<ChromiumProbeResult> {
  query_cookies_engine_outcome_mode_with_deadline(
    &outcomes,
    db_path,
    domains,
    force_kill,
    CookieProjection::Legacy,
    EncryptedValuePolicy::UseKeyOutcomes,
    BoundaryRuntime::new(clock, deadline),
  )?
  .into_probe_result()
}

#[allow(unused_variables)]
pub(crate) fn query_cookies_engine_outcome(
  outcomes: &ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<ChromiumExtractionDraft> {
  query_cookies_engine_outcome_mode(
    outcomes,
    db_path,
    domains,
    force_kill,
    CookieProjection::Legacy,
    EncryptedValuePolicy::UseKeyOutcomes,
  )
}

#[allow(unused_variables)]
fn query_cookies_engine_outcome_mode(
  outcomes: &ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
  projection: CookieProjection,
  encrypted_value_policy: EncryptedValuePolicy,
) -> Result<ChromiumExtractionDraft> {
  let clock = crate::common::deadline::SystemClock;
  query_cookies_engine_outcome_mode_with_deadline(
    outcomes,
    db_path,
    domains,
    force_kill,
    projection,
    encrypted_value_policy,
    BoundaryRuntime::new(&clock, crate::common::deadline::Deadline::standard()),
  )
}

#[allow(unused_variables)]
fn query_cookies_engine_outcome_mode_with_deadline(
  outcomes: &ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
  projection: CookieProjection,
  encrypted_value_policy: EncryptedValuePolicy,
  runtime: BoundaryRuntime<'_>,
) -> Result<ChromiumExtractionDraft> {
  runtime.check()?;
  #[cfg(target_os = "windows")]
  {
    chromium_database_acquisition::with_force_kill_recovery(&db_path, force_kill, |path| {
      query_cookies_from_database_with_deadline(
        outcomes,
        path.to_path_buf(),
        domains.as_deref(),
        projection,
        encrypted_value_policy,
        runtime.clock,
        runtime.deadline,
      )
    })
  }

  #[cfg(not(target_os = "windows"))]
  query_cookies_from_database_with_deadline(
    outcomes,
    db_path,
    domains.as_deref(),
    projection,
    encrypted_value_policy,
    runtime.clock,
    runtime.deadline,
  )
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn query_cookies_from_database(
  outcomes: &ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<&[String]>,
  projection: CookieProjection,
  encrypted_value_policy: EncryptedValuePolicy,
) -> Result<ChromiumExtractionDraft> {
  let clock = crate::common::deadline::SystemClock;
  query_cookies_from_database_with_deadline(
    outcomes,
    db_path,
    domains,
    projection,
    encrypted_value_policy,
    &clock,
    crate::common::deadline::Deadline::standard(),
  )
}

fn query_cookies_from_database_with_deadline(
  outcomes: &ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<&[String]>,
  projection: CookieProjection,
  encrypted_value_policy: EncryptedValuePolicy,
  clock: &dyn crate::common::deadline::Clock,
  deadline: crate::common::deadline::Deadline,
) -> Result<ChromiumExtractionDraft> {
  log::info!(
    "Creating SQLite connection to {}",
    db_path.to_str().unwrap_or("")
  );
  let database = sqlite::with_browser_database_with_deadline(
    db_path,
    |connection| {
      decode_and_unseal_cookie_records_with_deadline(
        connection,
        domains,
        projection,
        encrypted_value_policy,
        |record, schema_version| unseal_chromium_record(record, outcomes, schema_version),
        clock,
        deadline,
      )
    },
    clock,
    deadline,
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
  projection: CookieProjection,
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
  decode_and_unseal_cookie_records_with_deadline(
    connection,
    domains,
    projection,
    encrypted_value_policy,
    unseal,
    &clock,
    crate::common::deadline::Deadline::standard(),
  )
}

fn decode_and_unseal_cookie_records_with_deadline<Unseal>(
  connection: &rusqlite::Connection,
  domains: Option<&[String]>,
  projection: CookieProjection,
  encrypted_value_policy: EncryptedValuePolicy,
  mut unseal: Unseal,
  clock: &dyn crate::common::deadline::Clock,
  deadline: crate::common::deadline::Deadline,
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
    projection,
    encrypted_value_policy,
    clock,
  };
  let _capability = decoder.deadline_enforcement();
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
        outcome.record_unseal_failure(code, decoded.row_number, encrypted_tier, error.to_string());
        // Preserve the historical error surface for unseal failures. Context
        // column errors remain typed because ordered events prevent an earlier
        // stringified unseal error from overwriting a later decoder error.
        last_row_error = Some(anyhow!(error.to_string()));
      }
    }
    Ok(())
  };
  let ChromiumDecodeSummary { rows_seen } = decoder.decode(&source, &mut sink, deadline)?;
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
    match projection {
      CookieProjection::Detailed => outcome.detailed_cookies.push(
        record
          .into_detailed_cookie()
          .expect("unseal produced plaintext"),
      ),
      CookieProjection::Legacy => {
        outcome.cookies.push(
          record
            .clone()
            .into_cookie()
            .expect("unseal produced plaintext"),
        );
        outcome.records.push(record);
      }
    }
    outcome.stats.cookies_emitted += 1;
  }
  Ok(outcome)
}

#[cfg(test)]
fn query_cookies_from_connection(
  connection: &rusqlite::Connection,
  outcomes: &ChromiumKeyOutcomes,
  domains: Option<&[String]>,
) -> Result<ChromiumExtractionDraft> {
  query_cookies_from_connection_mode(
    connection,
    outcomes,
    domains,
    CookieProjection::Legacy,
    EncryptedValuePolicy::UseKeyOutcomes,
  )
}

#[cfg(test)]
fn query_cookies_from_connection_mode(
  connection: &rusqlite::Connection,
  outcomes: &ChromiumKeyOutcomes,
  domains: Option<&[String]>,
  projection: CookieProjection,
  encrypted_value_policy: EncryptedValuePolicy,
) -> Result<ChromiumExtractionDraft> {
  decode_and_unseal_cookie_records(
    connection,
    domains,
    projection,
    encrypted_value_policy,
    |record, schema_version| unseal_chromium_record(record, outcomes, schema_version),
  )
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::browser::chromium_crypto::LegacySharedKeyProvider;
  #[cfg(target_os = "windows")]
  use crate::browser::chromium_database_acquisition::{WindowsDatabaseLocked, WindowsLockedFile};
  #[cfg(unix)]
  use crate::browser::chromium_platform_keys::create_pbkdf2_key;
  use std::cell::{Cell, RefCell};
  use std::path::Path;
  use std::sync::atomic::{AtomicU64, Ordering};

  // Per-process unique temp paths without pulling in the `tempfile` dep.
  fn unique_tmpdir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir =
      std::env::temp_dir().join(format!("rookie-test-{}-{}-{}", tag, std::process::id(), n));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
  }

  fn query_cookies_with_legacy_keys(
    keys: Vec<Vec<u8>>,
    db_path: PathBuf,
    domains: Option<Vec<String>>,
    force_kill: bool,
  ) -> Result<Vec<Cookie>> {
    let provider = LegacySharedKeyProvider::new(keys);
    query_cookies(&provider, &(), db_path, domains, force_kill)
  }

  fn query_outcome_with_legacy_keys(
    keys: Vec<Vec<u8>>,
    db_path: PathBuf,
  ) -> Result<ChromiumExtractionDraft> {
    let outcomes = ChromiumKeyOutcomes::from_legacy_shared(keys);
    query_cookies_engine_outcome(&outcomes, db_path, None, false)
  }

  fn host_bound_plaintext(host_key: &str, value: &[u8]) -> Vec<u8> {
    let mut plaintext = Sha256::digest(host_key.as_bytes()).to_vec();
    plaintext.extend_from_slice(value);
    plaintext
  }

  // (host_key, path, is_secure, expires_utc, name, value, encrypted_value, is_httponly, samesite)
  type ChromiumRow<'a> = (
    &'a str,
    &'a str,
    bool,
    u64,
    &'a str,
    &'a str,
    &'a [u8],
    bool,
    i64,
  );

  fn seed_chromium_schema_version(connection: &rusqlite::Connection, version: u32) {
    connection
      .execute(
        "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR)",
        [],
      )
      .expect("create Chromium metadata table");
    connection
      .execute(
        "INSERT INTO meta (key, value) VALUES ('version', ?1)",
        [version.to_string()],
      )
      .expect("seed Chromium schema version");
  }

  // Minimal `cookies` table mirroring the columns chromium_based reads.
  // Real Chrome schema has many more columns, but query_cookies only
  // selects these nine.
  fn seed_chromium_cookies(db: &Path, rows: &[ChromiumRow<'_>]) {
    let conn = rusqlite::Connection::open(db).expect("open writable sqlite");
    seed_chromium_schema_version(&conn, 23);
    conn
      .execute(
        "CREATE TABLE cookies (
          host_key TEXT NOT NULL,
          path TEXT NOT NULL,
          is_secure INTEGER NOT NULL,
          expires_utc INTEGER NOT NULL,
          name TEXT NOT NULL,
          value TEXT NOT NULL,
          encrypted_value BLOB,
          is_httponly INTEGER NOT NULL,
          samesite INTEGER NOT NULL
        )",
        [],
      )
      .expect("create table");
    for r in rows {
      conn
        .execute(
          "INSERT INTO cookies (host_key, path, is_secure, expires_utc, name, value, \
            encrypted_value, is_httponly, samesite) \
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
          rusqlite::params![r.0, r.1, r.2, r.3, r.4, r.5, r.6, r.7, r.8],
        )
        .expect("insert row");
    }
  }

  #[test]
  fn detailed_cookies_preserve_partition_collisions() {
    let dir = unique_tmpdir("chromium-partition-collision");
    let db = dir.join("Cookies");
    let connection = rusqlite::Connection::open(&db).expect("open fixture");
    seed_chromium_schema_version(&connection, 23);
    connection
      .execute_batch(
        "CREATE TABLE cookies (
          host_key TEXT NOT NULL, path TEXT NOT NULL, is_secure INTEGER NOT NULL,
          expires_utc INTEGER NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
          encrypted_value BLOB, is_httponly INTEGER NOT NULL, samesite INTEGER NOT NULL,
          top_frame_site_key TEXT, has_cross_site_ancestor INTEGER,
          source_scheme INTEGER, source_port INTEGER, is_persistent INTEGER
        );
        INSERT INTO cookies VALUES
          ('.example.com', '/', 1, 0, 'session', 'work', X'', 1, 1,
           'https://work.example', 1, 2, 443, 1),
          ('.example.com', '/', 1, 0, 'session', 'personal', X'', 1, 1,
           'https://personal.example', 0, 2, 443, 1);",
      )
      .expect("seed partitioned cookies");
    drop(connection);

    let provider = LegacySharedKeyProvider::new(Vec::new());
    let cookies =
      query_detailed_cookies(&provider, &(), db, None, false).expect("extract detailed cookies");
    assert_eq!(cookies.len(), 2);
    assert_eq!(cookies[0].cookie.name, cookies[1].cookie.name);
    assert_eq!(cookies[0].cookie.domain, cookies[1].cookie.domain);
    assert_eq!(cookies[0].cookie.path, cookies[1].cookie.path);
    let contexts = cookies
      .iter()
      .map(|cookie| {
        (
          cookie.cookie.value.as_str(),
          (
            cookie.context.top_frame_site_key.as_deref(),
            cookie.context.has_cross_site_ancestor,
          ),
        )
      })
      .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(
      contexts.get("work"),
      Some(&(Some("https://work.example"), Some(true)))
    );
    assert_eq!(
      contexts.get("personal"),
      Some(&(Some("https://personal.example"), Some(false)))
    );
    assert_eq!(cookies[0].context.source_scheme, Some(2));
    assert_eq!(cookies[0].context.source_port, Some(443));
    assert_eq!(cookies[0].context.is_persistent, Some(true));
  }

  #[test]
  fn detailed_query_keeps_legacy_schemas_readable() {
    let dir = unique_tmpdir("chromium-legacy-detailed-schema");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[(
        ".example.com",
        "/",
        false,
        0,
        "legacy",
        "value",
        b"",
        false,
        0,
      )],
    );

    let provider = LegacySharedKeyProvider::new(Vec::new());
    let cookies = query_detailed_cookies(&provider, &(), db, None, false)
      .expect("missing optional columns remain compatible");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].context, CookieContext::default());
  }

  #[test]
  fn malformed_optional_context_is_retained_without_projection_divergence() {
    let dir = unique_tmpdir("chromium-malformed-detailed-context");
    let db = dir.join("Cookies");
    let connection = rusqlite::Connection::open(&db).expect("open fixture");
    seed_chromium_schema_version(&connection, 23);
    connection
      .execute_batch(
        "CREATE TABLE cookies (
          host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
          name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER,
          samesite INTEGER, top_frame_site_key BLOB
        );
        INSERT INTO cookies VALUES
          ('.example.com', '/', 0, 0, 'legacy', 'value', X'', 0, 0, X'FF');",
      )
      .expect("seed malformed context");
    drop(connection);

    let provider = LegacySharedKeyProvider::new(Vec::new());
    let legacy = query_cookies(&provider, &(), db.clone(), None, false)
      .expect("legacy projection does not inspect detailed columns");
    assert_eq!(legacy.len(), 1);
    let detailed = query_detailed_cookies(&provider, &(), db, None, false)
      .expect("malformed optional context is retained as raw typed loss");
    assert_eq!(detailed.len(), 1);
    assert_eq!(detailed[0].context, CookieContext::default());
  }

  #[test]
  fn malformed_detailed_context_skips_only_its_row() {
    let dir = unique_tmpdir("chromium-mixed-detailed-context");
    let db = dir.join("Cookies");
    let connection = rusqlite::Connection::open(&db).expect("open fixture");
    seed_chromium_schema_version(&connection, 23);
    connection
      .execute_batch(
        "CREATE TABLE cookies (
          host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
          name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER,
          samesite INTEGER, top_frame_site_key BLOB
        );
        INSERT INTO cookies VALUES
          ('.example.com', '/', 0, 0, 'before', 'first', X'', 0, 0,
           'https://before.example'),
          ('.example.com', '/', 0, 0, 'malformed', 'discarded', X'', 0, 0, X'FF'),
          ('.example.com', '/', 0, 0, 'after', 'last', X'', 0, 0,
           'https://after.example');",
      )
      .expect("seed mixed context rows");
    drop(connection);

    let provider = LegacySharedKeyProvider::new(Vec::new());
    let legacy = query_cookies(&provider, &(), db.clone(), None, false)
      .expect("legacy projection keeps every row");
    assert_eq!(legacy.len(), 3);

    let extraction = query_cookies_engine_outcome_mode(
      &ChromiumKeyOutcomes::from_legacy_shared(Vec::new()),
      db.clone(),
      None,
      false,
      CookieProjection::Detailed,
      EncryptedValuePolicy::UseKeyOutcomes,
    )
    .expect("malformed optional context remains a usable row");
    assert_eq!(
      extraction.stats,
      ChromiumExtractionStats {
        rows_seen: 3,
        cookies_emitted: 3,
        rows_skipped: 0,
        rows_rejected: 0,
        provider_failures: 0,
      }
    );
    assert!(extraction.issues.is_empty());
    assert!(extraction.legacy_error.is_none());
    let detailed = extraction
      .into_detailed_result()
      .expect("valid detailed rows keep the extraction successful");
    assert_eq!(
      detailed
        .iter()
        .map(|cookie| cookie.cookie.name.as_str())
        .collect::<Vec<_>>(),
      vec!["before", "malformed", "after"]
    );

    let public_result = query_detailed_cookies(&provider, &(), db, None, false)
      .expect("public detailed extraction returns the valid rows");
    assert_eq!(public_result.len(), 3);
  }

  #[test]
  fn decode_unseal_preserves_row_failure_precedence_order_and_typed_source_chain() {
    let connection = rusqlite::Connection::open_in_memory().expect("open fixture");
    seed_chromium_schema_version(&connection, 23);
    connection
      .execute_batch(
        "CREATE TABLE cookies (
          host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
          name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER,
          samesite INTEGER, top_frame_site_key BLOB
        );
        INSERT INTO cookies VALUES
          ('.example.com', '/', 0, 0, 'cipher-before-context', 'must not leak',
           X'7631', 0, 0, X'FF'),
          ('.example.com', '/', 0, 0, X'FF', 'unreadable name', X'', 0, 0,
           'https://valid.example'),
          ('.example.com', '/', 0, 0, 'context-last', 'plain', X'', 0, 0,
           X'FF');",
      )
      .expect("seed compound and interleaved failures");

    let outcome = query_cookies_from_connection_mode(
      &connection,
      &ChromiumKeyOutcomes::default(),
      None,
      CookieProjection::Detailed,
      EncryptedValuePolicy::UseKeyOutcomes,
    )
    .expect("row failures remain an extraction outcome");

    assert_eq!(
      outcome.stats,
      ChromiumExtractionStats {
        rows_seen: 3,
        cookies_emitted: 1,
        rows_skipped: 2,
        rows_rejected: 2,
        provider_failures: 0,
      }
    );
    assert_eq!(
      outcome
        .issues
        .iter()
        .map(|issue| (issue.code, issue.occurrences))
        .collect::<Vec<_>>(),
      vec![
        (ChromiumRowIssueCode::Decrypt, 1),
        (ChromiumRowIssueCode::ColumnRead("name"), 1),
      ],
      "malformed optional context is retained as typed raw metadata"
    );
    assert!(outcome.legacy_error.is_none());
    assert_eq!(outcome.detailed_cookies.len(), 1);
  }

  #[test]
  fn compound_row_failure_keeps_decrypt_precedence_over_context() {
    let connection = rusqlite::Connection::open_in_memory().expect("open fixture");
    seed_chromium_schema_version(&connection, 23);
    connection
      .execute_batch(
        "CREATE TABLE cookies (
          host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
          name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER,
          samesite INTEGER, top_frame_site_key BLOB
        );
        INSERT INTO cookies VALUES
          ('.example.com', '/', 0, 0, 'compound', 'must not leak', X'7631',
           0, 0, X'FF');",
      )
      .expect("seed compound failure");

    let outcome = query_cookies_from_connection_mode(
      &connection,
      &ChromiumKeyOutcomes::default(),
      None,
      CookieProjection::Detailed,
      EncryptedValuePolicy::UseKeyOutcomes,
    )
    .expect("row failure remains an extraction outcome");
    assert_eq!(outcome.issues.len(), 1);
    assert_eq!(outcome.issues[0].code, ChromiumRowIssueCode::Decrypt);
    let error = outcome
      .legacy_error
      .as_ref()
      .expect("all-row failure keeps the unseal error");
    assert!(format!("{error:#}").contains("shorter than the 3-byte cipher prefix"));
    assert!(!format!("{error:#}").contains("must not leak"));
  }

  #[cfg(target_os = "windows")]
  fn open_without_file_sharing(path: &Path) -> std::fs::File {
    use std::os::windows::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
      .read(true)
      .share_mode(0)
      .open(path)
      .expect("open exclusive Windows fixture handle")
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn windows_native_share_denied_valid_database_reaches_real_query_policy() {
    let directory = crate::utils::TempDir::new().expect("temp dir");
    let db = directory.path().join("Cookies");
    seed_chromium_cookies(
      &db,
      &[(
        ".example.com",
        "/",
        false,
        0,
        "plain",
        "fixture value",
        b"",
        false,
        0,
      )],
    );
    assert!(
      !sqlite::sidecar(&db, "-wal").exists(),
      "fixture must take the live no-WAL acquisition path"
    );

    let exclusive = open_without_file_sharing(&db);
    let error = query_cookies_with_legacy_keys(vec![], db.clone(), None, false)
      .expect_err("real query boundary must report the native sharing denial");

    let locked = error
      .downcast_ref::<WindowsDatabaseLocked>()
      .expect("native failure retains typed Windows lock context");
    assert_eq!(locked.locked_file, WindowsLockedFile::Database);
    assert_eq!(locked.locked_path, db);
    assert!(!locked.has_verified_nonempty_wal);
    assert!(
      !locked.shutdown_allowed,
      "force_kill=false must not authorize restart-manager shutdown"
    );
    let acquisition = error
      .downcast_ref::<sqlite::BrowserDatabaseFailure>()
      .expect("real acquisition metadata remains in the final chain");
    assert_eq!(
      acquisition.kind,
      sqlite::BrowserDatabaseFailureKind::Acquisition
    );
    assert_eq!(acquisition.attempts, 1);
    assert!(
      matches!(
        acquisition.strategy,
        None | Some(sqlite::DatabaseAcquisitionStrategy::LiveReadOnly)
      ),
      "the exclusive handle can deny either canonicalization or the live open: {acquisition:?}"
    );
    assert!(
      matches!(locked.os_error, 32 | 33),
      "the typed lock must retain the native Win32 sharing code: {error:#}"
    );
    assert!(
      std::fs::File::open(&db).is_err(),
      "the library must not release or shut down the process owning the exclusive handle"
    );

    drop(exclusive);
    let cookies = query_cookies_with_legacy_keys(vec![], db, None, false)
      .expect("the unchanged database is readable after releasing the fixture handle");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "plain");
    assert_eq!(cookies[0].value, "fixture value");
  }

  #[cfg(unix)]
  fn encrypt_unix_cbc_cookie(version: &[u8; 3], key: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let iv = [b' '; 16];
    let cipher = Aes128CbcEnc::new((&key[..]).into(), &iv.into());
    let mut buffer = vec![0; plaintext.len() + 16];
    buffer[..plaintext.len()].copy_from_slice(plaintext);
    let ciphertext = cipher
      .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
      .expect("encrypt synthetic Chromium cookie");
    let mut encrypted_value = version.to_vec();
    encrypted_value.extend_from_slice(ciphertext);
    encrypted_value
  }

  #[cfg(target_os = "windows")]
  fn encrypt_windows_gcm_cookie(version: &[u8; 3], key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    use aes_gcm::{
      aead::{generic_array::GenericArray, Aead, KeyInit},
      Aes256Gcm,
    };

    let nonce = [0x42; 12];
    let cipher = Aes256Gcm::new_from_slice(key).expect("fixture key");
    let ciphertext = cipher
      .encrypt(GenericArray::from_slice(&nonce), plaintext)
      .expect("encrypt synthetic Chromium cookie");
    let mut encrypted_value = version.to_vec();
    encrypted_value.extend_from_slice(&nonce);
    encrypted_value.extend_from_slice(&ciphertext);
    encrypted_value
  }

  #[cfg(target_os = "linux")]
  struct SyntheticTierProvider {
    calls: Cell<usize>,
    outcomes: ChromiumKeyOutcomes,
  }

  #[cfg(target_os = "linux")]
  impl KeyProvider<str> for SyntheticTierProvider {
    type Keys = ChromiumKeyOutcomes;

    fn keys(
      &self,
      _context: &str,
      _deadline: crate::common::deadline::Deadline,
    ) -> ChromiumKeyOutcomes {
      self.calls.set(self.calls.get() + 1);
      self.outcomes.clone()
    }
  }

  #[cfg(target_os = "linux")]
  #[test]
  fn injected_provider_routes_mixed_tiers_once_and_isolates_a_failed_tier() {
    let dir = unique_tmpdir("chr-injected-mixed-tiers");
    let db = dir.join("Cookies");
    let v10_key = [0x10; 16];
    let v11_key = [0x11; 16];
    let v10_value = encrypt_unix_cbc_cookie(b"v10", &v10_key, b"v10 value");
    let failed_v20_value = b"v20synthetic-provider-failure".to_vec();
    let v11_value = encrypt_unix_cbc_cookie(b"v11", &v11_key, b"v11 value");

    // The rows deliberately run success/failure/success. A provider failure
    // for one tier is row-scoped and must not discard either successful CBC
    // tier or trigger another installation-scoped provider call.
    seed_chromium_cookies(
      &db,
      &[
        (
          ".example.com",
          "/",
          false,
          0,
          "v10-good",
          "attacker-controlled plaintext",
          &v10_value,
          false,
          0,
        ),
        (
          ".example.com",
          "/",
          false,
          0,
          "v20-failed-tier",
          "must not leak when provider fails",
          &failed_v20_value,
          false,
          0,
        ),
        (
          ".example.com",
          "/",
          false,
          0,
          "v11-good",
          "attacker-controlled plaintext",
          &v11_value,
          false,
          0,
        ),
      ],
    );

    let provider = SyntheticTierProvider {
      calls: Cell::new(0),
      outcomes: ChromiumKeyOutcomes {
        v10: crate::browser::chromium_crypto::ChromiumKeyOutcome::success(vec![v10_key.to_vec()])
          .expect("nonempty v10 fixture"),
        v11: crate::browser::chromium_crypto::ChromiumKeyOutcome::success(vec![v11_key.to_vec()])
          .expect("nonempty v11 fixture"),
        v20: crate::browser::chromium_crypto::ChromiumKeyOutcome::failure(
          "synthetic v20 provider failure",
        ),
      },
    };

    let mut cookies = query_cookies(&provider, "linux-installation", db, None, false)
      .expect("good tiers survive one failed tier");

    assert_eq!(provider.calls.get(), 1);
    cookies.sort_by(|left, right| left.name.cmp(&right.name));
    let extracted: Vec<_> = cookies
      .iter()
      .map(|cookie| (cookie.name.as_str(), cookie.value.as_str()))
      .collect();
    assert_eq!(
      extracted,
      vec![("v10-good", "v10 value"), ("v11-good", "v11 value")]
    );
    assert!(cookies
      .iter()
      .all(|cookie| cookie.value != "attacker-controlled plaintext"));
  }

  #[test]
  fn decoder_retains_ciphertext_and_discards_dual_populated_plaintext() {
    let dir = unique_tmpdir("chr-decoder-ciphertext-record");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[(
        ".example.com",
        "/",
        false,
        0,
        "dual",
        "must not survive decode",
        b"v20ciphertext",
        false,
        0,
      )],
    );
    let connection = rusqlite::Connection::open(db).expect("open fixture");
    let mut decoder = super::super::chromium_decoder::prepare_cookie_decoder(
      &connection,
      None,
      CookieProjection::Legacy,
      EncryptedValuePolicy::UseKeyOutcomes,
    )
    .expect("prepare decode without key material");
    let mut cursor = decoder.cursor().expect("start decoder cursor");
    let mut events = Vec::new();
    while let Some(event) = cursor.next_event().expect("decode next row") {
      events.push(event);
    }
    let summary = cursor.summary();

    assert_eq!(summary.rows_seen, 1);
    assert_eq!(events.len(), 1);
    let ChromiumDecodeEvent::Record(decoded) = events.pop().expect("one event") else {
      panic!("valid row must decode to a record")
    };
    assert_eq!(
      decoded.record.value,
      super::super::cookie_record::CookieValue::Encrypted {
        tier: super::super::cookie_record::CipherTier::V20,
        bytes: b"v20ciphertext".to_vec(),
      }
    );
  }

  #[test]
  fn authoritative_ciphertext_bypasses_null_blob_and_invalid_text_plaintext_columns() {
    let connection = rusqlite::Connection::open_in_memory().expect("open fixture");
    seed_chromium_schema_version(&connection, 23);
    connection
      .execute_batch(
        "CREATE TABLE cookies (
           host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
           name TEXT, value, encrypted_value BLOB, is_httponly INTEGER,
           samesite INTEGER
         );
         INSERT INTO cookies VALUES
           ('.example.com', '/', 0, 0, 'null-value', NULL,
            X'76313073796E7468657469632D76616C6964', 0, 0),
           ('.example.com', '/', 0, 0, 'blob-value', X'00FF',
            X'76313073796E7468657469632D76616C6964', 0, 0),
           ('.example.com', '/', 0, 0, 'invalid-text', CAST(X'FF' AS TEXT),
            X'76313073796E7468657469632D76616C6964', 0, 0);",
      )
      .expect("seed authoritative ciphertext rows");

    let outcome = decode_and_unseal_cookie_records(
      &connection,
      None,
      CookieProjection::Legacy,
      EncryptedValuePolicy::UseKeyOutcomes,
      |mut record, _schema_version| {
        assert!(matches!(
          &record.value,
          super::super::cookie_record::CookieValue::Encrypted {
            tier: super::super::cookie_record::CipherTier::V10,
            ..
          }
        ));
        record.value = super::super::cookie_record::CookieValue::Plain(SecretString::new(format!(
          "decrypted-{}",
          record.name
        )));
        Ok(record)
      },
    )
    .expect("authoritative ciphertext rows are decryptable");

    assert_eq!(outcome.stats.rows_seen, 3);
    assert_eq!(outcome.stats.cookies_emitted, 3);
    assert_eq!(outcome.stats.rows_skipped, 0);
    assert!(outcome
      .issues
      .iter()
      .all(|issue| { issue.code != ChromiumRowIssueCode::ColumnRead("value") }));
    assert_eq!(
      outcome
        .cookies
        .iter()
        .map(|cookie| cookie.value.as_str())
        .collect::<Vec<_>>(),
      vec![
        "decrypted-null-value",
        "decrypted-blob-value",
        "decrypted-invalid-text"
      ]
    );
  }

  #[test]
  fn retained_detailed_ciphertext_result_never_reads_stored_plaintext() {
    const STORED_PLAINTEXT: &str = "stored-plaintext-must-never-be-owned";
    const DECRYPTED: &str = "decrypted-value-must-be-wiped";
    let connection = rusqlite::Connection::open_in_memory().expect("open fixture");
    seed_chromium_schema_version(&connection, 23);
    connection
      .execute_batch(&format!(
        "CREATE TABLE cookies (
           host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
           name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER,
           samesite INTEGER, top_frame_site_key BLOB
         );
         INSERT INTO cookies VALUES
           ('.example.com', '/', 0, 0, 'discarded', '{STORED_PLAINTEXT}',
            X'76323073796E7468657469632D76616C6964', 0, 0, X'FF');"
      ))
      .expect("seed detailed context failure");

    let (observed, unwind) = crate::common::secret::observe_secret_string_drops(|| {
      let outcome = decode_and_unseal_cookie_records(
        &connection,
        None,
        CookieProjection::Detailed,
        EncryptedValuePolicy::UseKeyOutcomes,
        |mut record, _schema_version| {
          assert!(matches!(
            &record.value,
            super::super::cookie_record::CookieValue::Encrypted {
              tier: super::super::cookie_record::CipherTier::V20,
              ..
            }
          ));
          record.value = super::super::cookie_record::CookieValue::Plain(SecretString::new(
            DECRYPTED.to_owned(),
          ));
          Ok(record)
        },
      )
      .expect("unknown optional context remains a row outcome");
      assert_eq!(outcome.detailed_cookies.len(), 1);
      assert_eq!(outcome.detailed_cookies[0].cookie.value, DECRYPTED);
      assert_eq!(outcome.stats.rows_skipped, 0);
      assert!(outcome.issues.is_empty());
    });

    assert!(unwind.is_ok());
    assert!(
      observed.is_empty(),
      "the decrypted allocation moves into the public result; the stored plaintext is bypassed"
    );
  }

  #[test]
  fn late_missing_identity_error_wipes_staged_plaintext_before_returning() {
    const STAGED: &str = "staged-plaintext-must-be-wiped";
    let connection = rusqlite::Connection::open_in_memory().expect("open fixture");
    seed_chromium_schema_version(&connection, 23);
    connection
      .execute_batch(&format!(
        "CREATE TABLE cookies (
           host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
           name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER,
           samesite INTEGER
         );
         INSERT INTO cookies VALUES
           ('.example.com', '/', 0, 0, 'staged', '{STAGED}', X'', 0, 0),
           ('.example.com', '/', 0, 0, 'late-encrypted', 'must-not-win',
            X'76313073796E746865746963', 0, 0);"
      ))
      .expect("seed late identity failure");

    let (observed, unwind) = crate::common::secret::observe_secret_string_drops(|| {
      let error = decode_and_unseal_cookie_records(
        &connection,
        None,
        CookieProjection::Legacy,
        EncryptedValuePolicy::RejectMissingIdentity,
        |record, schema_version| {
          unseal_chromium_record(record, &ChromiumKeyOutcomes::default(), schema_version)
        },
      )
      .expect_err("a later encrypted row rejects the complete plaintext-only attempt");
      assert!(error.is::<MissingBrowserKeyIdentity>());
      assert!(!format!("{error:#}").contains(STAGED));
    });

    assert!(unwind.is_ok());
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].0, STAGED.len());
    assert!(observed[0].1.iter().all(|byte| *byte == 0));
  }

  #[test]
  fn unwind_during_later_unseal_wipes_every_staged_success() {
    const DECRYPTED: &str = "staged-decrypted-value-must-be-wiped";
    let connection = rusqlite::Connection::open_in_memory().expect("open fixture");
    seed_chromium_schema_version(&connection, 23);
    connection
      .execute_batch(
        "CREATE TABLE cookies (
           host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
           name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER,
           samesite INTEGER
         );
         INSERT INTO cookies VALUES
           ('.example.com', '/', 0, 0, 'first', 'ignored', X'7631306669727374', 0, 0),
           ('.example.com', '/', 0, 0, 'second', 'ignored', X'7631307365636F6E64', 0, 0);",
      )
      .expect("seed unwind fixture");

    let calls = Cell::new(0);
    let (observed, unwind) = crate::common::secret::observe_secret_string_drops(|| {
      let _ = decode_and_unseal_cookie_records(
        &connection,
        None,
        CookieProjection::Legacy,
        EncryptedValuePolicy::UseKeyOutcomes,
        |mut record, _schema_version| {
          let call = calls.get() + 1;
          calls.set(call);
          if call == 2 {
            panic!("synthetic later-row unseal panic");
          }
          record.value = super::super::cookie_record::CookieValue::Plain(SecretString::new(
            DECRYPTED.to_owned(),
          ));
          Ok(record)
        },
      );
    });

    assert!(unwind.is_err());
    assert_eq!(calls.get(), 2);
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].0, DECRYPTED.len());
    assert!(observed[0].1.iter().all(|byte| *byte == 0));
  }

  fn dual_populated_tier_fixture(ciphertext: &[u8]) -> rusqlite::Connection {
    let connection = rusqlite::Connection::open_in_memory().expect("open tier fixture");
    seed_chromium_schema_version(&connection, 23);
    connection
      .execute_batch(
        "CREATE TABLE cookies (
           host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
           name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER,
           samesite INTEGER, top_frame_site_key TEXT
         );",
      )
      .expect("create tier fixture");
    connection
      .execute(
        "INSERT INTO cookies VALUES
          ('.example.com', '/', 0, 0, 'tier',
           'plaintext-fallback-must-not-escape', ?1, 0, 0,
           'https://partition.example')",
        [ciphertext],
      )
      .expect("insert tier fixture");
    connection
  }

  fn injected_tier_outcome(
    connection: &rusqlite::Connection,
    projection: CookieProjection,
    expected_tier: super::super::cookie_record::CipherTier,
    succeed: bool,
  ) -> ChromiumExtractionDraft {
    decode_and_unseal_cookie_records(
      connection,
      None,
      projection,
      EncryptedValuePolicy::UseKeyOutcomes,
      |mut record, _schema_version| {
        let actual_tier = match &record.value {
          super::super::cookie_record::CookieValue::Encrypted { tier, .. } => *tier,
          _ => panic!("dual-populated row must reach unseal as ciphertext"),
        };
        assert_eq!(actual_tier, expected_tier);
        if succeed {
          record.value = super::super::cookie_record::CookieValue::Plain(SecretString::new(
            format!("decrypted-{expected_tier:?}"),
          ));
          Ok(record)
        } else {
          Err(Box::new((
            record,
            ChromiumCookieValueError::ProviderUnavailable(anyhow!(
              "injected {expected_tier:?} unavailable"
            )),
          )))
        }
      },
    )
    .expect("tier fixture decodes")
  }

  #[test]
  fn every_corrected_cipher_tier_uses_ciphertext_on_legacy_detailed_and_report_surfaces() {
    use super::super::cookie_record::CipherTier;

    for (ciphertext, tier) in [
      (b"v10synthetic".as_slice(), CipherTier::V10),
      (b"v11synthetic".as_slice(), CipherTier::V11),
      (b"v20synthetic".as_slice(), CipherTier::V20),
      (b"raw-dpapi-synthetic".as_slice(), CipherTier::LegacyDpapi),
    ] {
      let connection = dual_populated_tier_fixture(ciphertext);
      let expected_value = format!("decrypted-{tier:?}");

      let report = injected_tier_outcome(&connection, CookieProjection::Legacy, tier, true);
      assert_eq!(report.stats.rows_seen, 1);
      assert_eq!(report.stats.cookies_emitted, 1);
      assert_eq!(report.stats.rows_skipped, 0);
      assert_eq!(report.cookies[0].value, expected_value);
      assert_ne!(
        report.cookies[0].value,
        "plaintext-fallback-must-not-escape"
      );

      let legacy = injected_tier_outcome(&connection, CookieProjection::Legacy, tier, true)
        .into_legacy_result()
        .expect("legacy projection succeeds");
      assert_eq!(legacy[0].value, expected_value);

      let detailed = injected_tier_outcome(&connection, CookieProjection::Detailed, tier, true)
        .into_detailed_result()
        .expect("detailed projection succeeds");
      assert_eq!(detailed[0].cookie.value, expected_value);
      assert_eq!(
        detailed[0].context.top_frame_site_key.as_deref(),
        Some("https://partition.example")
      );

      let failed_report = injected_tier_outcome(&connection, CookieProjection::Legacy, tier, false);
      assert!(failed_report.cookies.is_empty());
      assert_eq!(failed_report.stats.rows_skipped, 1);
      assert_eq!(
        failed_report.issues[0].code,
        ChromiumRowIssueCode::ProviderUnavailable
      );
      assert!(
        !format!("{:#}", failed_report.legacy_error.as_ref().unwrap())
          .contains("plaintext-fallback-must-not-escape")
      );

      let legacy_error = injected_tier_outcome(&connection, CookieProjection::Legacy, tier, false)
        .into_legacy_result()
        .expect_err("legacy all-row failure remains an error");
      assert!(!format!("{legacy_error:#}").contains("plaintext-fallback-must-not-escape"));

      let detailed_error =
        injected_tier_outcome(&connection, CookieProjection::Detailed, tier, false)
          .into_detailed_result()
          .expect_err("detailed all-row failure remains an error");
      assert!(!format!("{detailed_error:#}").contains("plaintext-fallback-must-not-escape"));
    }
  }

  #[test]
  fn provider_failures_are_counted_once_per_distinct_tier_and_not_as_rejected_rows() {
    let dir = unique_tmpdir("chr-provider-counter-separation");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[
        (
          ".example.com",
          "/",
          false,
          0,
          "v10-first",
          "must not leak v10 first",
          b"v10ciphertext-one",
          false,
          0,
        ),
        (
          ".example.com",
          "/",
          false,
          0,
          "v10-second",
          "must not leak v10 second",
          b"v10ciphertext-two",
          false,
          0,
        ),
        (
          ".example.com",
          "/",
          false,
          0,
          "v11",
          "must not leak v11",
          b"v11ciphertext",
          false,
          0,
        ),
      ],
    );
    let outcomes = ChromiumKeyOutcomes {
      v10: crate::browser::chromium_crypto::ChromiumKeyOutcome::failure(
        "synthetic v10 provider failure",
      ),
      v11: crate::browser::chromium_crypto::ChromiumKeyOutcome::failure(
        "synthetic v11 provider failure",
      ),
      v20: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
    };
    let outcome = query_cookies_engine_outcome(&outcomes, db, None, false)
      .expect("provider failure remains a record-level outcome");

    assert!(outcome.cookies.is_empty());
    assert_eq!(outcome.stats.rows_seen, 3);
    assert_eq!(outcome.stats.rows_skipped, 3);
    assert_eq!(outcome.stats.rows_rejected, 0);
    assert_eq!(outcome.stats.provider_failures, 2);
    assert_eq!(
      outcome.stats.rows_seen - outcome.stats.rows_skipped,
      outcome.stats.cookies_emitted
    );
    assert_eq!(outcome.issues.len(), 2, "tiers have distinct failure keys");
    assert_eq!(outcome.issues[0].code, ChromiumRowIssueCode::ProviderFailed);
    assert_eq!(outcome.issues[0].tier.as_deref(), Some("v10"));
    assert_eq!(outcome.issues[0].occurrences, 2);
    assert_eq!(outcome.issues[1].tier.as_deref(), Some("v11"));
    assert_eq!(outcome.issues[1].occurrences, 1);
    assert!(outcome.legacy_error.is_some());
  }

  #[test]
  fn dual_populated_v20_provider_failure_is_reportable_but_legacy_errors() {
    let dir = unique_tmpdir("chr-v20-provider-pipeline");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[(
        ".example.com",
        "/",
        false,
        0,
        "v20",
        "plaintext sentinel must not escape",
        b"v20app-bound-ciphertext",
        false,
        0,
      )],
    );
    let outcomes = ChromiumKeyOutcomes {
      v10: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
      v11: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
      v20: crate::browser::chromium_crypto::ChromiumKeyOutcome::failure(
        "synthetic App-Bound provider failure",
      ),
    };

    let outcome = query_cookies_engine_outcome(&outcomes, db.clone(), None, false)
      .expect("provider failure remains reportable after a successful query");
    assert!(outcome.cookies.is_empty());
    assert_eq!(outcome.stats.rows_seen, 1);
    assert_eq!(outcome.stats.rows_skipped, 1);
    assert_eq!(outcome.stats.rows_rejected, 0);
    assert_eq!(outcome.stats.provider_failures, 1);
    assert_eq!(outcome.issues[0].code, ChromiumRowIssueCode::ProviderFailed);
    assert!(outcome.legacy_error.is_some());

    let error = query_cookies_with_key_outcomes(outcomes, db, None, false)
      .expect_err("legacy projection must fail when every row is unavailable");
    assert!(!format!("{error:#}").contains("plaintext sentinel must not escape"));
    assert!(format!("{error:#}").contains("App-Bound provider failure"));
  }

  #[cfg(unix)]
  #[test]
  fn dual_populated_legacy_dpapi_pipeline_never_projects_plaintext() {
    let dir = unique_tmpdir("chr-legacy-dpapi-pipeline");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[(
        ".example.com",
        "/",
        false,
        0,
        "legacy-dpapi",
        "plaintext sentinel must not escape",
        b"raw-dpapi-envelope",
        false,
        0,
      )],
    );

    let outcome = query_cookies_engine_outcome(&ChromiumKeyOutcomes::default(), db, None, false)
      .expect("unsupported DPAPI remains a row-level outcome");
    assert!(outcome.cookies.is_empty());
    assert_eq!(outcome.stats.rows_skipped, 1);
    assert_eq!(outcome.stats.rows_rejected, 0);
    assert_eq!(outcome.stats.provider_failures, 0);
    assert_eq!(
      outcome.issues[0].code,
      ChromiumRowIssueCode::ProviderUnavailable
    );
  }

  #[cfg(unix)]
  #[test]
  fn detailed_pipeline_unseals_dual_populated_ciphertext_before_projection() {
    let dir = unique_tmpdir("chr-detailed-unseal-pipeline");
    let db = dir.join("Cookies");
    let key = [0x2a; 16];
    let encrypted = encrypt_unix_cbc_cookie(b"v10", &key, b"decrypted detail");
    seed_chromium_cookies(
      &db,
      &[(
        ".example.com",
        "/detail",
        true,
        0,
        "detailed",
        "plaintext sentinel must not escape",
        &encrypted,
        true,
        1,
      )],
    );
    let outcomes = ChromiumKeyOutcomes {
      v10: crate::browser::chromium_crypto::ChromiumKeyOutcome::success(vec![key.to_vec()])
        .expect("nonempty v10 fixture"),
      v11: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
      v20: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
    };

    let outcome = query_cookies_engine_outcome_mode(
      &outcomes,
      db,
      None,
      false,
      CookieProjection::Detailed,
      EncryptedValuePolicy::UseKeyOutcomes,
    )
    .expect("detailed extraction");
    assert!(outcome.cookies.is_empty());
    assert_eq!(outcome.detailed_cookies.len(), 1);
    assert_eq!(outcome.detailed_cookies[0].cookie.value, "decrypted detail");
    assert_ne!(
      outcome.detailed_cookies[0].cookie.value,
      "plaintext sentinel must not escape"
    );
    assert_eq!(outcome.stats.cookies_emitted, 1);
    assert_eq!(outcome.stats.rows_skipped, 0);
  }

  #[cfg(windows)]
  #[test]
  fn dual_populated_v20_pipeline_decrypts_with_app_bound_tier() {
    let dir = unique_tmpdir("chr-v20-app-bound-pipeline");
    let db = dir.join("Cookies");
    let key = [0x20; 32];
    let encrypted = encrypt_windows_gcm_cookie(b"v20", &key, b"decrypted v20");
    seed_chromium_cookies(
      &db,
      &[(
        ".example.com",
        "/",
        false,
        0,
        "v20",
        "plaintext sentinel must not escape",
        &encrypted,
        false,
        0,
      )],
    );
    let outcomes = ChromiumKeyOutcomes {
      v10: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
      v11: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
      v20: crate::browser::chromium_crypto::ChromiumKeyOutcome::success(vec![key.to_vec()])
        .expect("nonempty App-Bound fixture"),
    };

    let outcome =
      query_cookies_engine_outcome(&outcomes, db, None, false).expect("v20 pipeline extraction");
    assert_eq!(outcome.cookies.len(), 1);
    assert_eq!(outcome.cookies[0].value, "decrypted v20");
    assert_ne!(
      outcome.cookies[0].value,
      "plaintext sentinel must not escape"
    );
  }

  #[test]
  fn query_cookies_missing_db_errors() {
    let result = query_cookies_with_legacy_keys(
      vec![],
      PathBuf::from("/nonexistent/cookies.db"),
      None,
      false,
    );
    assert!(
      result.is_err(),
      "expected Err for missing db, got {:?}",
      result
    );
  }

  #[test]
  fn query_cookies_non_sqlite_file_errors() {
    let dir = unique_tmpdir("chr-bad-sqlite");
    let db = dir.join("Cookies");
    std::fs::write(&db, b"not a sqlite database at all").unwrap();
    let result = query_cookies_with_legacy_keys(vec![], db, None, false);
    assert!(
      result.is_err(),
      "expected Err for bogus sqlite, got {:?}",
      result
    );
  }

  // This is intentionally native on Windows as well as Unix: an ordinary
  // DB+WAL acquisition must succeed without consulting privilege, shadow-copy,
  // or restart-manager fallbacks.
  #[test]
  fn query_cookies_reads_cookies_committed_to_an_active_wal() {
    // Self-cleaning, unlike `unique_tmpdir`; held to the end of the test.
    let dir = crate::utils::TempDir::new().expect("temp dir");
    let db = dir.path().join("Cookies");
    seed_chromium_cookies(
      &db,
      &[(
        ".example.com",
        "/",
        false,
        0,
        "checkpointed",
        "old",
        b"",
        false,
        0,
      )],
    );

    // Switch to WAL and keep the writer connected, so the second cookie stays
    // in the -wal the way it does while Chrome is running.
    let writer = rusqlite::Connection::open(&db).expect("open writable sqlite");
    let mode: String = writer
      .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
      .expect("enable WAL");
    assert_eq!(mode, "wal");
    writer
      .execute(
        "INSERT INTO cookies (host_key, path, is_secure, expires_utc, name, value, \
          encrypted_value, is_httponly, samesite) \
          VALUES ('.example.com', '/', 0, 0, 'in-wal', 'fresh', X'', 0, 0)",
        [],
      )
      .expect("insert WAL row");

    let mut cookies = query_cookies_with_legacy_keys(vec![], db, None, false).expect("decode");

    cookies.sort_by(|a, b| a.name.cmp(&b.name));
    let names: Vec<_> = cookies.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["checkpointed", "in-wal"], "{cookies:?}");
    let in_wal = cookies.iter().find(|c| c.name == "in-wal").expect("in-wal");
    assert_eq!(in_wal.value, "fresh");
  }

  #[test]
  fn query_cookies_empty_table_returns_empty() {
    let dir = unique_tmpdir("chr-empty-table");
    let db = dir.join("Cookies");
    seed_chromium_cookies(&db, &[]);
    let cookies = query_cookies_with_legacy_keys(vec![], db, None, false).expect("decode");
    assert!(cookies.is_empty(), "{:?}", cookies);
  }

  #[test]
  fn query_cookies_errors_when_every_row_fails_to_decode() {
    let dir = unique_tmpdir("chr-all-rows-bad");
    let db = dir.join("Cookies");
    seed_chromium_cookies(&db, &[]);
    // The name is required identity data, so a row whose name cannot decode
    // must not turn a total extraction failure into an empty success.
    let conn = rusqlite::Connection::open(&db).expect("open writable sqlite");
    conn
      .execute(
        "INSERT INTO cookies (host_key, path, is_secure, expires_utc, name, value, \
          encrypted_value, is_httponly, samesite) \
          VALUES ('.example.com', '/', 1, 0, X'DEADBEEF', 'plain', X'', 1, 0)",
        [],
      )
      .expect("insert bad row");
    drop(conn);

    let outcome = query_outcome_with_legacy_keys(vec![], db.clone()).expect("source query");
    assert_eq!(outcome.stats.rows_seen, 1);
    assert_eq!(outcome.stats.cookies_emitted, 0);
    assert_eq!(outcome.stats.rows_skipped, 1);
    assert_eq!(outcome.issues.len(), 1);
    assert_eq!(
      outcome.issues[0].code,
      ChromiumRowIssueCode::ColumnRead("name")
    );
    let diagnostic = format!(
      "{:#}",
      outcome
        .legacy_error
        .as_ref()
        .expect("total row failure retains its diagnostic")
    );
    assert!(diagnostic.contains("ColumnRead(\"name\")"), "{diagnostic}");
    assert!(diagnostic.contains("row 1"), "{diagnostic}");

    let result = query_cookies_with_legacy_keys(vec![], db, None, false);
    assert!(
      result.is_err(),
      "expected Err when no row decodes, got {:?}",
      result
    );
  }

  #[test]
  fn query_cookies_emits_a_valid_empty_value() {
    let dir = unique_tmpdir("chr-valueless-plus-bad");
    let db = dir.join("Cookies");
    // An empty value is valid cookie data and must not disappear merely
    // because both the plaintext and encrypted storage columns are empty.
    seed_chromium_cookies(
      &db,
      &[(".example.com", "/", true, 0, "empty", "", b"", false, 0)],
    );
    let conn = rusqlite::Connection::open(&db).expect("open writable sqlite");
    conn
      .execute(
        "INSERT INTO cookies (host_key, path, is_secure, expires_utc, name, value, \
          encrypted_value, is_httponly, samesite) \
          VALUES ('.other.com', '/', 1, 0, X'DEADBEEF', 'plain', X'', 1, 0)",
        [],
      )
      .expect("insert bad row");
    drop(conn);

    let cookies = query_cookies_with_legacy_keys(vec![], db, None, false)
      .expect("valueless row is not a failure");
    assert_eq!(cookies.len(), 1, "{cookies:?}");
    assert_eq!(cookies[0].name, "empty");
    assert_eq!(cookies[0].value, "");
  }

  #[test]
  fn query_cookies_defaults_null_and_out_of_range_metadata() {
    let dir = unique_tmpdir("chr-null-metadata");
    let db = dir.join("Cookies");
    let connection = rusqlite::Connection::open(&db).expect("open writable sqlite");
    seed_chromium_schema_version(&connection, 23);
    connection
      .execute(
        "CREATE TABLE cookies (
          host_key TEXT,
          path TEXT,
          is_secure INTEGER,
          expires_utc INTEGER,
          name TEXT,
          value TEXT,
          encrypted_value BLOB,
          is_httponly INTEGER,
          samesite INTEGER
        )",
        [],
      )
      .expect("create table");
    connection
      .execute(
        "INSERT INTO cookies VALUES (NULL, NULL, NULL, -1, 'kept', 'value', NULL, NULL, NULL)",
        [],
      )
      .expect("insert cookie with missing metadata");
    connection
      .execute(
        "INSERT INTO cookies VALUES ('.example.com', '/', 0, 0, NULL, 'value', X'', 0, 0)",
        [],
      )
      .expect("insert cookie without name");
    connection
      .execute(
        "INSERT INTO cookies VALUES ('.example.com', '/', 0, 0, 'missing-value', NULL, X'', 0, 0)",
        [],
      )
      .expect("insert cookie without value");

    let outcomes = ChromiumKeyOutcomes::from_legacy_shared(vec![]);
    let extraction =
      query_cookies_from_connection(&connection, &outcomes, None).expect("query cookies");
    assert_eq!(extraction.cookies.len(), 1, "{:?}", extraction.cookies);
    let cookie = &extraction.cookies[0];
    assert_eq!(cookie.name, "kept");
    assert_eq!(cookie.value, "value");
    assert_eq!(cookie.domain, "");
    assert_eq!(cookie.path, "/");
    assert!(!cookie.secure);
    assert!(!cookie.http_only);
    assert_eq!(cookie.expires, None);
    assert_eq!(cookie.same_site, SAME_SITE_UNSPECIFIED);
    assert_eq!(extraction.stats.rows_seen, 3);
    assert_eq!(extraction.stats.cookies_emitted, 1);
    assert_eq!(extraction.stats.rows_skipped, 2);
  }

  #[test]
  fn query_cookies_skips_every_malformed_core_column_without_defaulting_metadata() {
    let dir = unique_tmpdir("chr-malformed-core-columns");
    let db = dir.join("Cookies");
    let connection = rusqlite::Connection::open(&db).expect("open writable sqlite");
    seed_chromium_schema_version(&connection, 23);
    connection
      .execute_batch(
        "CREATE TABLE cookies (
          host_key, path, is_secure, expires_utc, name, value,
          encrypted_value, is_httponly, samesite
        );
        INSERT INTO cookies VALUES
          ('.example.com', '/', 1, 0, 'good', 'value', X'', 1, 1),
          (X'FF', '/', 1, 0, 'bad-host', 'value', X'', 1, 1),
          ('.example.com', X'FF', 1, 0, 'bad-path', 'value', X'', 1, 1),
          ('.example.com', '/', X'FF', 0, 'bad-secure', 'value', X'', 1, 1),
          ('.example.com', '/', 1, X'FF', 'bad-expires', 'value', X'', 1, 1),
          ('.example.com', '/', 1, 0, X'FF', 'value', X'', 1, 1),
          ('.example.com', '/', 1, 0, 'bad-value', X'FF', X'', 1, 1),
          ('.example.com', '/', 1, 0, 'bad-http-only', 'value', X'', X'FF', 1),
          ('.example.com', '/', 1, 0, 'bad-same-site', 'value', X'', 1, X'FF');",
      )
      .expect("seed malformed core columns");

    let outcomes = ChromiumKeyOutcomes::from_legacy_shared(vec![]);
    let extraction =
      query_cookies_from_connection(&connection, &outcomes, None).expect("query cookies");
    assert_eq!(
      extraction.stats,
      ChromiumExtractionStats {
        rows_seen: 9,
        cookies_emitted: 1,
        rows_skipped: 8,
        rows_rejected: 8,
        provider_failures: 0,
      }
    );
    assert_eq!(extraction.cookies[0].name, "good");
    assert!(extraction.legacy_error.is_none());
    assert_eq!(
      extraction
        .issues
        .iter()
        .map(|issue| issue.code)
        .collect::<Vec<_>>(),
      vec![
        ChromiumRowIssueCode::ColumnRead("host_key"),
        ChromiumRowIssueCode::ColumnRead("path"),
        ChromiumRowIssueCode::ColumnRead("is_secure"),
        ChromiumRowIssueCode::ColumnRead("expires_utc"),
        ChromiumRowIssueCode::ColumnRead("name"),
        ChromiumRowIssueCode::ColumnRead("value"),
        ChromiumRowIssueCode::ColumnRead("is_httponly"),
        ChromiumRowIssueCode::ColumnRead("samesite"),
      ]
    );
  }

  #[test]
  fn plaintext_value_failure_precedes_later_metadata_but_ciphertext_bypasses_value() {
    let connection = rusqlite::Connection::open_in_memory().expect("open fixture");
    seed_chromium_schema_version(&connection, 23);
    connection
      .execute_batch(
        "CREATE TABLE cookies (
          host_key, path, is_secure, expires_utc, name, value,
          encrypted_value, is_httponly, samesite
        );
        INSERT INTO cookies VALUES
          ('.example.com', '/', 0, 0, 'plaintext-compound', X'FF', X'', X'FF', 0),
          ('.example.com', '/', 0, 0, 'ciphertext-compound', X'FF',
           X'76313073796E746865746963', X'FF', 0);",
      )
      .expect("seed compound column failures");

    let outcome = query_cookies_from_connection(&connection, &ChromiumKeyOutcomes::default(), None)
      .expect("column failures remain row outcomes");
    assert_eq!(outcome.stats.rows_seen, 2);
    assert_eq!(outcome.stats.rows_skipped, 2);
    assert_eq!(
      outcome
        .issues
        .iter()
        .map(|issue| issue.code)
        .collect::<Vec<_>>(),
      vec![
        ChromiumRowIssueCode::ColumnRead("value"),
        ChromiumRowIssueCode::ColumnRead("is_httponly"),
      ],
      "plaintext reads value immediately, while authoritative ciphertext never reads it"
    );
  }

  #[test]
  fn query_cookies_returns_plaintext_value_when_value_is_set() {
    let dir = unique_tmpdir("chr-plaintext");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[(
        ".example.com",
        "/",
        true,
        // chromium_timestamp wants microseconds since 1601-01-01.
        // 11_644_473_600_000_000 us == Unix epoch.
        11_644_473_600_000_000 + 1_700_000_000 * 1_000_000,
        "id",
        "plain",
        b"",
        true,
        1,
      )],
    );
    let cookies = query_cookies_with_legacy_keys(vec![], db, None, false).expect("decode");
    assert_eq!(cookies.len(), 1, "{:?}", cookies);
    let c = &cookies[0];
    assert_eq!(c.domain, ".example.com");
    assert_eq!(c.name, "id");
    assert_eq!(c.value, "plain");
    assert!(c.http_only);
    assert!(c.secure);
    assert_eq!(c.same_site, 1);
    assert_eq!(c.expires, Some(1_700_000_000));
  }

  #[test]
  fn shared_cipher_loop_never_prefers_plaintext_over_ciphertext() {
    let unavailable = ChromiumKeyOutcomes::default();
    let encrypted_wins = decrypt_encrypted_value_with_cipher_adapter(
      ".example.com",
      "plain".to_string(),
      b"x",
      &unavailable,
      23,
      CipherAdapter {
        candidate_key_length: Some(4),
        validate_keyed_envelope: |_: &[u8]| {
          panic!("malformed ciphertext must fail before envelope validation")
        },
        decrypt_candidate: |_: &[u8], _: &[u8]| {
          panic!("malformed ciphertext must fail before candidate decryption")
        },
        decrypt_legacy: |_: &[u8]| {
          panic!("malformed ciphertext must fail before legacy decryption")
        },
      },
    )
    .expect_err("non-empty ciphertext must be classified before plaintext is considered");
    assert!(matches!(
      encrypted_wins,
      ChromiumCookieValueError::Decrypt(_)
    ));
    assert!(encrypted_wins
      .to_string()
      .contains("shorter than the 3-byte"));

    let malformed = decrypt_encrypted_value_with_cipher_adapter(
      ".example.com",
      String::new(),
      b"v1",
      &unavailable,
      23,
      CipherAdapter {
        candidate_key_length: Some(4),
        validate_keyed_envelope: |_: &[u8]| {
          panic!("malformed prefix must fail before envelope validation")
        },
        decrypt_candidate: |_: &[u8], _: &[u8]| {
          panic!("malformed prefix must fail before candidate decryption")
        },
        decrypt_legacy: |_: &[u8]| panic!("malformed prefix must fail before legacy decryption"),
      },
    )
    .expect_err("cipher detection precedes routing");
    assert!(matches!(malformed, ChromiumCookieValueError::Decrypt(_)));
    assert!(malformed.to_string().contains("shorter than the 3-byte"));

    let no_provider = decrypt_encrypted_value_with_cipher_adapter(
      ".example.com",
      String::new(),
      b"v10payload",
      &unavailable,
      23,
      CipherAdapter {
        candidate_key_length: Some(4),
        validate_keyed_envelope: |_: &[u8]| {
          panic!("provider routing must precede envelope validation")
        },
        decrypt_candidate: |_: &[u8], _: &[u8]| {
          panic!("unavailable provider must not try a candidate")
        },
        decrypt_legacy: |_: &[u8]| panic!("keyed route must not call legacy decryption"),
      },
    )
    .expect_err("route reports the unavailable key tier");
    assert!(matches!(
      no_provider,
      ChromiumCookieValueError::ProviderUnavailable(_)
    ));

    let keyed = ChromiumKeyOutcomes {
      v10: crate::browser::chromium_crypto::ChromiumKeyOutcome::success(vec![vec![0x10; 4]])
        .expect("nonempty candidate"),
      v11: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
      v20: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
    };
    let unsupported = decrypt_encrypted_value_with_cipher_adapter(
      ".example.com",
      String::new(),
      b"v10payload",
      &keyed,
      23,
      CipherAdapter {
        candidate_key_length: None,
        validate_keyed_envelope: |_: &[u8]| {
          panic!("unsupported host must fail before envelope validation")
        },
        decrypt_candidate: |_: &[u8], _: &[u8]| panic!("unsupported host must not try a candidate"),
        decrypt_legacy: |_: &[u8]| panic!("keyed route must not call legacy decryption"),
      },
    )
    .expect_err("unsupported host rejects a keyed route before parsing its envelope");
    assert!(matches!(
      unsupported,
      ChromiumCookieValueError::ProviderUnavailable(_)
    ));
    assert_eq!(
      unsupported.to_string(),
      "Chromium keyed cookie decryption is unsupported on this platform"
    );

    let envelope_error = decrypt_encrypted_value_with_cipher_adapter(
      ".example.com",
      String::new(),
      b"v10payload",
      &keyed,
      23,
      CipherAdapter {
        candidate_key_length: Some(4),
        validate_keyed_envelope: |_: &[u8]| Err(anyhow!("synthetic envelope failure")),
        decrypt_candidate: |_: &[u8], _: &[u8]| {
          panic!("envelope validation must precede candidate decryption")
        },
        decrypt_legacy: |_: &[u8]| panic!("keyed route must not call legacy decryption"),
      },
    )
    .expect_err("invalid envelope stops before candidates");
    assert!(matches!(
      envelope_error,
      ChromiumCookieValueError::Decrypt(_)
    ));
    assert_eq!(envelope_error.to_string(), "synthetic envelope failure");
  }

  #[test]
  fn unavailable_records_preserve_their_existing_reason_taxonomy() {
    for code in [
      UnavailableCode::Decrypt,
      UnavailableCode::Decode,
      UnavailableCode::ProviderUnavailable,
      UnavailableCode::ProviderFailed,
    ] {
      let reason = super::super::cookie_record::UnavailableReason {
        code,
        message: format!("synthetic {code:?} reason"),
      };
      let record = CookieRecord::from_legacy_fields(
        ".example.com".to_owned(),
        "/".to_owned(),
        false,
        None,
        "classified".to_owned(),
        super::super::cookie_record::CookieValue::Unavailable(reason.clone()),
        false,
        SAME_SITE_UNSPECIFIED,
        CookieContext::default(),
        1,
      );

      let failure = unseal_chromium_record(record, &ChromiumKeyOutcomes::default(), 23)
        .expect_err("unavailable input remains unavailable");
      let (record, error) = *failure;
      assert_eq!(error.unavailable_code(), code);
      assert!(matches!(error, ChromiumCookieValueError::Unavailable(_)));
      let super::super::cookie_record::CookieValue::Unavailable(returned) = record.value else {
        panic!("unseal must preserve the unavailable record")
      };
      assert_eq!(returned.code, code);
      assert_eq!(returned.message, reason.message);
    }
  }

  #[test]
  fn exhausted_candidate_diagnostic_describes_the_actual_condition() {
    let outcomes = ChromiumKeyOutcomes {
      v10: crate::browser::chromium_crypto::ChromiumKeyOutcome::success(vec![vec![0x10; 4]])
        .expect("nonempty candidate"),
      v11: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
      v20: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
    };
    let error = decrypt_encrypted_value_with_cipher_adapter(
      ".example.com",
      String::new(),
      b"v10payload",
      &outcomes,
      23,
      CipherAdapter {
        candidate_key_length: Some(4),
        validate_keyed_envelope: |_: &[u8]| Ok(()),
        decrypt_candidate: |_: &[u8], _: &[u8]| Err(anyhow!("synthetic primitive failure")),
        decrypt_legacy: |_: &[u8]| panic!("keyed route must not call legacy decryption"),
      },
    )
    .expect_err("every candidate failed");
    assert_eq!(
      error.to_string(),
      "no Chromium key candidate decrypted this cookie value"
    );
  }

  #[test]
  fn shared_cipher_loop_tries_candidates_then_decodes_and_keeps_decode_precedence() {
    let outcomes = ChromiumKeyOutcomes {
      v10: crate::browser::chromium_crypto::ChromiumKeyOutcome::success(vec![
        vec![0x10; 4],
        vec![0x20; 4],
      ])
      .expect("nonempty candidates"),
      v11: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
      v20: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
    };
    let events = RefCell::new(Vec::new());
    let decoded = decrypt_encrypted_value_with_cipher_adapter(
      ".example.com",
      String::new(),
      b"v10payload",
      &outcomes,
      23,
      CipherAdapter {
        candidate_key_length: Some(4),
        validate_keyed_envelope: |_: &[u8]| {
          events.borrow_mut().push("validate");
          Ok(())
        },
        decrypt_candidate: |_: &[u8], key: &[u8]| {
          if key[0] == 0x10 {
            events.borrow_mut().push("candidate-1");
            Ok(SecretBytes::new(vec![0xff]))
          } else {
            events.borrow_mut().push("candidate-2");
            Ok(SecretBytes::new(b"decoded".to_vec()))
          }
        },
        decrypt_legacy: |_: &[u8]| panic!("keyed route must not call legacy decryption"),
      },
    )
    .expect("second candidate decodes after the first candidate's decode error");
    assert_eq!(decoded, "decoded");
    assert_eq!(
      *events.borrow(),
      vec!["validate", "candidate-1", "candidate-2"]
    );

    let calls = Cell::new(0);
    let decode_error = decrypt_encrypted_value_with_cipher_adapter(
      ".example.com",
      String::new(),
      b"v10payload",
      &outcomes,
      23,
      CipherAdapter {
        candidate_key_length: Some(4),
        validate_keyed_envelope: |_: &[u8]| Ok(()),
        decrypt_candidate: |_: &[u8], _: &[u8]| {
          let call = calls.get() + 1;
          calls.set(call);
          if call == 1 {
            Ok(SecretBytes::new(vec![0xff]))
          } else {
            Err(anyhow!("later primitive failure"))
          }
        },
        decrypt_legacy: |_: &[u8]| panic!("keyed route must not call legacy decryption"),
      },
    )
    .expect_err("a prior decode error outranks later primitive failures");
    assert!(matches!(
      decode_error,
      ChromiumCookieValueError::Decode(ChromiumCookieDecodeError::UnprefixedInvalidUtf8)
    ));
  }

  #[test]
  fn shared_cipher_loop_routes_fallible_legacy_plaintext_through_shared_decode() {
    let host = ".example.com";
    let expected = host_bound_plaintext(host, b"legacy value");
    let events = RefCell::new(Vec::new());
    let decoded = decrypt_encrypted_value_with_cipher_adapter(
      host,
      "must not win".to_owned(),
      b"raw-dpapi-envelope",
      &ChromiumKeyOutcomes::default(),
      24,
      CipherAdapter {
        candidate_key_length: Some(4),
        validate_keyed_envelope: |_: &[u8]| {
          panic!("legacy route must not validate a keyed envelope")
        },
        decrypt_candidate: |_: &[u8], _: &[u8]| {
          panic!("legacy route must not try a keyed candidate")
        },
        decrypt_legacy: |_: &[u8]| {
          events.borrow_mut().push("legacy");
          Ok(LegacyCipherOutcome::Plaintext(SecretBytes::new(
            expected.clone(),
          )))
        },
      },
    )
    .expect("legacy plaintext is decoded by the shared host-binding policy");
    assert_eq!(decoded, "legacy value");
    assert_eq!(*events.borrow(), vec!["legacy"]);
  }

  #[cfg(unix)]
  #[test]
  fn chromium_mock_keychain_known_answer() {
    let salt = b"saltysalt";
    let key = create_pbkdf2_key("mock_password", salt, 1003);
    assert_eq!(
      *key,
      vec![
        0xaf, 0x0f, 0x76, 0x2a, 0xaf, 0x6d, 0x7d, 0x11, 0x58, 0x1b, 0x7a, 0xa8, 0xce, 0x72, 0x18,
        0xde,
      ]
    );

    let ciphertext = [
      0x76, 0x31, 0x30, 0xbf, 0x08, 0x6d, 0x20, 0x56, 0x86, 0x1a, 0x80, 0xde, 0x82, 0x5f, 0xc9,
      0x35, 0x86, 0x86, 0x30, 0x64, 0x4f, 0x2c, 0xa1, 0x87, 0x45, 0x02, 0x13, 0xae, 0x66, 0x81,
      0xb4, 0xd6, 0x43, 0xd1, 0x9b, 0x25, 0x81, 0xc8, 0x5c, 0x88, 0x78, 0xc1, 0xbc, 0x97, 0xe7,
      0x26, 0xa1, 0x0e, 0x51, 0xea, 0x77,
    ];
    let plaintext = [
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
      0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
      0x1e, 0x1f,
    ];

    let decrypted = decrypt_encrypted_value(
      ".example.com",
      "".to_string(),
      &ciphertext,
      &[key.to_vec()],
      23,
    )
    .expect("decrypt vector");
    assert_eq!(decrypted.as_bytes(), plaintext);
  }

  #[test]
  fn decode_cookie_value_strips_only_the_exact_stored_host_hash() {
    let plaintext = host_bound_plaintext(".example.com", b"cookie value");
    let decoded =
      decode_chromium_cookie_value(".example.com", SecretBytes::new(plaintext.clone()), 23)
        .expect("host match");
    assert_eq!(decoded.as_str(), "cookie value");
    assert_eq!(
      decode_chromium_cookie_value("example.com", SecretBytes::new(plaintext), 23),
      Err(ChromiumCookieDecodeError::HostHashMismatchWithInvalidUtf8),
      "the leading dot in the stored host is part of the exact hash input"
    );
  }

  #[test]
  fn decode_cookie_value_maps_an_exact_hash_only_plaintext_to_empty() {
    let plaintext = host_bound_plaintext(".example.com", b"");
    let decoded = decode_chromium_cookie_value(".example.com", SecretBytes::new(plaintext), 23)
      .expect("hash only");
    assert_eq!(decoded.as_str(), "");
  }

  #[test]
  fn decode_cookie_value_preserves_valid_utf8_when_a_32_byte_prefix_mismatches() {
    let plaintext = b"this old unprefixed value is longer than thirty-two bytes".to_vec();
    let decoded =
      decode_chromium_cookie_value(".example.com", SecretBytes::new(plaintext.clone()), 23)
        .expect("old unprefixed value");
    assert_eq!(decoded.as_bytes(), plaintext);
  }

  #[test]
  fn decode_cookie_value_rejects_a_mismatched_non_utf8_prefix() {
    let mut plaintext = vec![0xff; CHROMIUM_HOST_HASH_LEN];
    plaintext.extend_from_slice(b"must not be stripped");
    assert_eq!(
      decode_chromium_cookie_value(".example.com", SecretBytes::new(plaintext), 23),
      Err(ChromiumCookieDecodeError::HostHashMismatchWithInvalidUtf8)
    );
  }

  #[test]
  fn decode_cookie_value_preserves_short_and_old_unprefixed_utf8() {
    assert_eq!(
      decode_chromium_cookie_value(".example.com", SecretBytes::new(b"short".to_vec()), 23,)
        .expect("short value")
        .as_str(),
      "short"
    );
    let old = "x".repeat(CHROMIUM_HOST_HASH_LEN + 8);
    assert_eq!(
      decode_chromium_cookie_value(
        ".example.com",
        SecretBytes::new(old.as_bytes().to_vec()),
        23,
      )
      .expect("old long value")
      .as_str(),
      old
    );
  }

  #[test]
  fn decode_cookie_value_requires_an_exact_host_hash_for_v24_and_later() {
    assert_eq!(
      decode_chromium_cookie_value(".example.com", SecretBytes::new(b"short".to_vec()), 24,),
      Err(ChromiumCookieDecodeError::MissingRequiredHostHash)
    );
    assert_eq!(
      decode_chromium_cookie_value(
        ".example.com",
        SecretBytes::new(b"this valid UTF-8 value has no matching host hash prefix".to_vec()),
        24,
      ),
      Err(ChromiumCookieDecodeError::HostHashMismatch)
    );

    let plaintext = host_bound_plaintext(".example.com", b"bound value");
    assert_eq!(
      decode_chromium_cookie_value(".example.com", SecretBytes::new(plaintext), 24)
        .expect("verified host hash")
        .as_str(),
      "bound value"
    );
  }

  #[test]
  fn chromium_schema_version_is_read_strictly() {
    let missing = rusqlite::Connection::open_in_memory().expect("open missing-meta database");
    assert!(chromium_schema_version(&missing).is_err());

    let malformed = rusqlite::Connection::open_in_memory().expect("open malformed-meta database");
    malformed
      .execute("CREATE TABLE meta (key TEXT, value TEXT)", [])
      .expect("create metadata table");
    malformed
      .execute("INSERT INTO meta VALUES ('version', 'v24')", [])
      .expect("seed malformed version");
    let error = chromium_schema_version(&malformed).expect_err("malformed version must fail");
    assert!(error.to_string().contains("Invalid Chromium"));
  }

  #[test]
  fn chromium_schema_version_and_rows_come_from_the_acquired_wal_snapshot() {
    let dir = crate::utils::TempDir::new().expect("temp dir");
    let db = dir.path().join("Cookies");
    seed_chromium_cookies(
      &db,
      &[(
        ".example.com",
        "/",
        false,
        0,
        "snapshot",
        "old",
        b"",
        false,
        0,
      )],
    );

    let mut writer = rusqlite::Connection::open(&db).expect("open WAL writer");
    let mode: String = writer
      .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
      .expect("enable WAL");
    assert_eq!(mode, "wal");
    let transaction = writer.transaction().expect("begin WAL update");
    transaction
      .execute("UPDATE meta SET value = '24' WHERE key = 'version'", [])
      .expect("write version to WAL");
    transaction
      .execute(
        "UPDATE cookies SET value = 'new' WHERE name = 'snapshot'",
        [],
      )
      .expect("write cookie to WAL");
    transaction.commit().expect("commit WAL update");

    let acquired = sqlite::with_browser_database(db, |connection| {
      let version = chromium_schema_version(connection)?;
      let value = connection.query_row(
        "SELECT value FROM cookies WHERE name = 'snapshot'",
        [],
        |row| row.get::<_, String>(0),
      )?;
      Ok((version, value))
    })
    .expect("read acquired snapshot");

    assert_eq!(
      acquired.strategy(),
      sqlite::DatabaseAcquisitionStrategy::VerifiedWalSnapshot
    );
    assert_eq!(acquired.into_value(), (24, "new".to_string()));
  }

  #[test]
  fn decode_cookie_value_rejects_invalid_utf8_after_a_verified_hash() {
    let plaintext = host_bound_plaintext(".example.com", &[0xff]);
    assert_eq!(
      decode_chromium_cookie_value(".example.com", SecretBytes::new(plaintext), 23),
      Err(ChromiumCookieDecodeError::InvalidUtf8AfterVerifiedHostHash)
    );
  }

  #[test]
  fn row_issue_aggregation_bounds_samples_without_losing_occurrences() {
    let mut outcome = ChromiumExtractionDraft::default();
    for row_number in 1..=MAX_CHROMIUM_ROW_ISSUE_SAMPLES + 3 {
      outcome.record_skipped_row(ChromiumRowIssueCode::Decode, row_number);
    }

    // Derived from the cap rather than hardcoded, so raising the bound cannot
    // leave the expectation describing a number the code no longer uses.
    let skipped = MAX_CHROMIUM_ROW_ISSUE_SAMPLES + 3;
    assert_eq!(outcome.stats.rows_skipped, skipped);
    assert_eq!(outcome.issues.len(), 1);
    assert_eq!(outcome.issues[0].occurrences, skipped);
    assert_eq!(
      outcome.issues[0].samples,
      (1..=MAX_CHROMIUM_ROW_ISSUE_SAMPLES)
        .map(|row| format!("row {row}"))
        .collect::<Vec<_>>()
    );
  }

  #[cfg(unix)]
  #[test]
  fn query_cookies_filters_by_domain() {
    let dir = unique_tmpdir("chr-domain-filter");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[
        (".example.com", "/", false, 0, "keep", "yes", b"", false, 0),
        ("other.test", "/", false, 0, "drop", "no", b"", false, 0),
      ],
    );
    let mut cookies = query_cookies_with_legacy_keys(
      vec![],
      db,
      Some(vec!["example.com".to_string(), "other.test".to_string()]),
      false,
    )
    .expect("decode");
    cookies.sort_by(|a, b| a.name.cmp(&b.name));
    let names: Vec<_> = cookies.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["drop", "keep"], "{:?}", cookies);
  }

  #[test]
  fn query_cookies_enforces_domain_boundaries_and_fail_closed_filters() {
    let dir = unique_tmpdir("chr-domain-filter-boundary");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[
        ("example.com", "/", false, 0, "exact", "yes", b"", false, 0),
        (
          ".sub.example.com",
          "/",
          false,
          0,
          "subdomain",
          "yes",
          b"",
          false,
          0,
        ),
        (
          "example.com.",
          "/",
          false,
          0,
          "trailing-dot",
          "yes",
          b"",
          false,
          0,
        ),
        (
          "notexample.com",
          "/",
          false,
          0,
          "prefix",
          "no",
          b"",
          false,
          0,
        ),
        (
          "example.com.evil.net",
          "/",
          false,
          0,
          "suffix",
          "no",
          b"",
          false,
          0,
        ),
        (
          "other.test",
          "/",
          false,
          0,
          "unrelated",
          "no",
          b"",
          false,
          0,
        ),
      ],
    );

    let connection = rusqlite::Connection::open(&db).expect("open cookie database");
    connection
      .execute(
        "INSERT INTO cookies (host_key, path, is_secure, expires_utc, name, value, \
          encrypted_value, is_httponly, samesite) \
          VALUES ('notexample.com', '/', 0, 0, X'DEADBEEF', 'off-scope', X'', 0, 0)",
        [],
      )
      .expect("insert malformed off-scope candidate");
    let outcomes = ChromiumKeyOutcomes::from_legacy_shared(vec![]);
    let names = |outcome: &ChromiumExtractionDraft| {
      let mut names = outcome
        .cookies
        .iter()
        .map(|cookie| cookie.name.clone())
        .collect::<Vec<_>>();
      names.sort();
      names
    };

    let domains = vec!["example.com".to_string()];
    let outcome = query_cookies_from_connection(&connection, &outcomes, Some(&domains))
      .expect("filter exact host and subdomains");
    assert_eq!(names(&outcome), vec!["exact", "subdomain", "trailing-dot"]);
    assert_eq!(outcome.stats.rows_seen, 3);
    assert_eq!(outcome.stats.rows_skipped, 0);
    assert_eq!(outcome.stats.cookies_emitted, 3);

    let dotted_domains = vec![".example.com.".to_string()];
    let dotted = query_cookies_from_connection(&connection, &outcomes, Some(&dotted_domains))
      .expect("leading and trailing dots must not narrow the SQL candidate set");
    assert_eq!(names(&dotted), vec!["exact", "subdomain", "trailing-dot"]);

    let mixed_domains = vec!["".to_string(), "example.com".to_string()];
    let mixed = query_cookies_from_connection(&connection, &outcomes, Some(&mixed_domains))
      .expect("a blank entry must not broaden a valid allowlist");
    assert_eq!(names(&mixed), vec!["exact", "subdomain", "trailing-dot"]);

    for invalid in ["", " \t ", ".", "%", "_"] {
      let domains = vec![invalid.to_string()];
      let outcome = query_cookies_from_connection(&connection, &outcomes, Some(&domains))
        .expect("invalid filter must be a successful empty result");
      assert!(
        outcome.cookies.is_empty(),
        "filter {invalid:?} must not expose cookies: {:?}",
        outcome.cookies
      );
      assert_eq!(outcome.stats.rows_seen, 0, "filter {invalid:?}");
      assert_eq!(outcome.stats.rows_skipped, 0, "filter {invalid:?}");
    }

    let empty_domains = Vec::new();
    let empty = query_cookies_from_connection(&connection, &outcomes, Some(&empty_domains))
      .expect("an explicit empty allowlist must validate the schema and match nothing");
    assert!(empty.cookies.is_empty());
    assert_eq!(empty.stats.rows_seen, 0);

    let empty_detailed = query_cookies_from_connection_mode(
      &connection,
      &outcomes,
      Some(&empty_domains),
      CookieProjection::Detailed,
      EncryptedValuePolicy::UseKeyOutcomes,
    )
    .expect("a detailed empty allowlist must validate the schema and match nothing");
    assert!(empty_detailed.detailed_cookies.is_empty());
    assert_eq!(empty_detailed.stats.rows_seen, 0);

    let empty_database = rusqlite::Connection::open_in_memory().expect("open empty database");
    assert!(
      query_cookies_from_connection(&empty_database, &outcomes, Some(&empty_domains)).is_err(),
      "a legacy empty allowlist must not bypass schema validation"
    );
    assert!(
      query_cookies_from_connection_mode(
        &empty_database,
        &outcomes,
        Some(&empty_domains),
        CookieProjection::Detailed,
        EncryptedValuePolicy::UseKeyOutcomes,
      )
      .is_err(),
      "a detailed empty allowlist must not bypass schema validation"
    );

    let unfiltered =
      query_cookies_from_connection(&connection, &outcomes, None).expect("unfiltered query");
    assert_eq!(
      names(&unfiltered),
      vec![
        "exact",
        "prefix",
        "subdomain",
        "suffix",
        "trailing-dot",
        "unrelated"
      ]
    );
    assert_eq!(unfiltered.stats.rows_seen, 7);
    assert_eq!(unfiltered.stats.rows_skipped, 1);
  }

  #[cfg(unix)]
  #[test]
  fn query_cookies_domain_filter_treats_sql_as_data() {
    let dir = unique_tmpdir("chr-domain-filter-sql");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[
        (
          ".example.com",
          "/",
          false,
          0,
          "first",
          "yes",
          b"x",
          false,
          0,
        ),
        ("other.test", "/", false, 0, "second", "no", b"x", false, 0),
      ],
    );

    let cookies =
      query_cookies_with_legacy_keys(vec![], db, Some(vec!["' OR 1=1 --".to_string()]), false)
        .expect("decode");
    assert!(cookies.is_empty(), "{:?}", cookies);
  }

  #[test]
  fn query_cookies_does_not_broaden_valid_domain_filter_with_sql_input() {
    let dir = unique_tmpdir("chr-domain-filter-scope");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[
        (".example.com", "/", false, 0, "keep", "yes", b"", false, 0),
        ("other.test", "/", false, 0, "drop", "no", b"", false, 0),
      ],
    );

    let cookies = query_cookies_with_legacy_keys(
      vec![],
      db,
      Some(vec!["example.com".to_string(), "') OR 1=1 --".to_string()]),
      false,
    )
    .expect("decode");
    let names: Vec<_> = cookies.iter().map(|cookie| cookie.name.as_str()).collect();
    assert_eq!(names, vec!["keep"], "{:?}", cookies);
  }

  #[test]
  fn query_cookies_percent_domain_is_not_a_wildcard() {
    let dir = unique_tmpdir("chr-domain-filter-percent");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[
        (".example.com", "/", false, 0, "keep", "yes", b"x", false, 0),
        ("other.test", "/", false, 0, "drop", "no", b"x", false, 0),
      ],
    );

    let cookies = query_cookies_with_legacy_keys(vec![], db, Some(vec!["%".to_string()]), false)
      .expect("decode");
    assert!(
      cookies.is_empty(),
      "a literal '%' domain must not match every host: {:?}",
      cookies
    );
  }

  #[test]
  fn query_cookies_underscore_domain_is_not_a_wildcard() {
    let dir = unique_tmpdir("chr-domain-filter-underscore");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[
        (".example.com", "/", false, 0, "keep", "yes", b"x", false, 0),
        ("a.test", "/", false, 0, "drop", "no", b"x", false, 0),
      ],
    );

    let cookies = query_cookies_with_legacy_keys(vec![], db, Some(vec!["_".to_string()]), false)
      .expect("decode");
    assert!(
      cookies.is_empty(),
      "a literal '_' domain must not match every single-character host: {:?}",
      cookies
    );
  }

  #[cfg(unix)]
  #[test]
  fn decrypt_encrypted_value_short_blob_rejects_plaintext_fallback() {
    let error = decrypt_encrypted_value(".example.com", "orig".to_string(), b"v1", &[], 23)
      .expect_err("malformed ciphertext must not expose the plaintext column");
    assert!(error.to_string().contains("shorter than the 3-byte"));
  }

  #[cfg(unix)]
  #[test]
  fn linux_keyring_failure_diagnostic_reaches_v11_decryption() {
    let outcomes = ChromiumKeyOutcomes {
      v10: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
      v11: crate::browser::chromium_crypto::ChromiumKeyOutcome::failure(
        "all Linux keyring backends failed: Secret Service locked; KWallet denied",
      ),
      v20: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
    };

    let error = decrypt_encrypted_value_with_outcomes(
      ".example.com",
      String::new(),
      b"v11encrypted",
      &outcomes,
      23,
    )
    .expect_err("v11 must preserve the provider diagnostic")
    .to_string();
    assert!(error.contains("Chromium v11 key provider failed"));
    assert!(error.contains("all Linux keyring backends failed"));
    assert!(error.contains("Secret Service locked"));
    assert!(error.contains("KWallet denied"));
  }

  #[cfg(unix)]
  #[test]
  fn decrypt_encrypted_value_invalid_utf8_returns_error() {
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let key = vec![0u8; 16];
    let iv = [b' '; 16];
    let cipher = Aes128CbcEnc::new((&key[..16]).into(), &iv.into());

    let data = vec![0xffu8; 16];
    let mut buf = vec![0u8; 32];
    buf[..16].copy_from_slice(&data);

    let ct = cipher.encrypt_padded_mut::<Pkcs7>(&mut buf, 16).unwrap();

    let mut encrypted_value = b"v10".to_vec();
    encrypted_value.extend_from_slice(ct);

    assert!(
      decrypt_encrypted_value(".example.com", "".to_string(), &encrypted_value, &[key], 23,)
        .is_err()
    );
  }

  #[cfg(unix)]
  #[test]
  fn decrypt_encrypted_value_decodes_host_hash_prefixed_plaintext() {
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let key = vec![0u8; 16];
    let iv = [b' '; 16];
    let plaintext = host_bound_plaintext(".example.com", b"cookie value");
    let mut ciphertext_buffer = vec![0u8; plaintext.len() + 16];
    ciphertext_buffer[..plaintext.len()].copy_from_slice(&plaintext);
    let cipher = Aes128CbcEnc::new((&key[..]).into(), &iv.into());
    let ciphertext = cipher
      .encrypt_padded_mut::<Pkcs7>(&mut ciphertext_buffer, plaintext.len())
      .expect("encrypt fixture");

    let mut encrypted_value = b"v10".to_vec();
    encrypted_value.extend_from_slice(ciphertext);
    let decrypted =
      decrypt_encrypted_value(".example.com", "".to_string(), &encrypted_value, &[key], 23)
        .expect("decrypt host-hash-prefixed value");

    assert_eq!(decrypted, "cookie value");
  }

  #[cfg(unix)]
  #[test]
  fn decrypt_encrypted_value_tries_next_key_after_invalid_utf8() {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let correct_key = vec![0u8; 16];
    let iv = [b' '; 16];
    let expected = b"valid cookie value";
    let mut ciphertext_buffer = vec![0u8; expected.len() + 16];
    ciphertext_buffer[..expected.len()].copy_from_slice(expected);
    let cipher = Aes128CbcEnc::new((&correct_key[..]).into(), &iv.into());
    let ciphertext = cipher
      .encrypt_padded_mut::<Pkcs7>(&mut ciphertext_buffer, expected.len())
      .expect("encrypt fixture")
      .to_vec();

    let invalid_utf8_key = (1u16..=u16::MAX)
      .find_map(|candidate| {
        let mut key = vec![0; 16];
        key[..2].copy_from_slice(&candidate.to_le_bytes());
        let cipher = Aes128CbcDec::new((&key[..]).into(), &iv.into());
        let mut candidate_ciphertext = ciphertext.clone();
        let plaintext = cipher
          .decrypt_padded_mut::<Pkcs7>(&mut candidate_ciphertext)
          .ok()?;
        String::from_utf8(plaintext.to_vec())
          .is_err()
          .then_some(key)
      })
      .expect("fixture must include a wrong key with valid padding and invalid UTF-8");

    let mut encrypted_value = b"v10".to_vec();
    encrypted_value.extend_from_slice(&ciphertext);
    let decrypted = decrypt_encrypted_value(
      ".example.com",
      "".to_string(),
      &encrypted_value,
      &[invalid_utf8_key, correct_key],
      23,
    )
    .expect("second key should decrypt the cookie");

    assert_eq!(decrypted, "valid cookie value");
  }

  #[cfg(windows)]
  #[test]
  fn decrypt_encrypted_value_windows_verifies_host_hash_and_tries_later_key() {
    let correct_key = [0x20; 32];
    let wrong_key = vec![0x10; 32];
    let plaintext = host_bound_plaintext(".example.com", b"verified value");
    let encrypted_value = encrypt_windows_gcm_cookie(b"v20", &correct_key, &plaintext);

    let decrypted = decrypt_encrypted_value(
      ".example.com",
      "must not win".to_string(),
      &encrypted_value,
      &[wrong_key, correct_key.to_vec()],
      23,
    )
    .expect("later key should authenticate and decode");
    assert_eq!(decrypted, "verified value");
  }

  #[cfg(windows)]
  #[test]
  fn decrypt_encrypted_value_windows_classifies_non_utf8_hash_mismatch_as_decode_failure() {
    let key = [0x20; 32];
    let plaintext = vec![0xff; CHROMIUM_HOST_HASH_LEN + 1];
    let encrypted_value = encrypt_windows_gcm_cookie(b"v20", &key, &plaintext);

    assert!(matches!(
      decrypt_encrypted_value(
        ".example.com",
        "".to_string(),
        &encrypted_value,
        &[key.to_vec()],
        23,
      ),
      Err(ChromiumCookieValueError::Decode(
        ChromiumCookieDecodeError::HostHashMismatchWithInvalidUtf8
      ))
    ));
  }

  #[cfg(windows)]
  #[test]
  fn decrypt_encrypted_value_windows_truncated_blob_rejects_plaintext_fallback() {
    let key = vec![0u8; 32];
    for len in 3..15 {
      let mut blob = b"v10".to_vec();
      blob.resize(len, 0);
      let error = decrypt_encrypted_value(
        ".example.com",
        "must not escape".to_string(),
        &blob,
        std::slice::from_ref(&key),
        23,
      )
      .expect_err("truncated ciphertext must be rejected without exposing plaintext");
      assert!(!error.to_string().contains("must not escape"));
    }
  }

  #[cfg(windows)]
  #[test]
  fn decrypt_encrypted_value_skips_wrong_length_key() {
    // A candidate key that isn't 32 bytes must be skipped, not panic the
    // AES-256-GCM path (Key::from_slice would have panicked). Reaching the
    // assertion at all proves there was no panic; with no usable key the
    // function falls through to an error.
    let mut blob = b"v10".to_vec();
    blob.resize(31, 0); // "v10" + 12-byte nonce + 16-byte ciphertext region
    let short_key = vec![0u8; 10];
    let res = decrypt_encrypted_value(".example.com", "".to_string(), &blob, &[short_key], 23);
    assert!(res.is_err());
  }

  #[test]
  fn query_outcome_tracks_row_stats_and_typed_issue_groups() {
    let dir = unique_tmpdir("chr-row-outcome");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[(
        ".example.com",
        "/",
        false,
        0,
        "good",
        "plain",
        b"",
        false,
        0,
      )],
    );
    let conn = rusqlite::Connection::open(&db).expect("open writable sqlite");
    conn
      .execute(
        "INSERT INTO cookies VALUES ('.example.com', '/', 0, 0, X'DEADBEEF', 'plain', X'', 0, 0)",
        [],
      )
      .expect("insert malformed row");
    conn
      .execute(
        "INSERT INTO cookies VALUES ('.example.com', '/', 0, 0, 'bad-cipher', '', X'7631', 0, 0)",
        [],
      )
      .expect("insert malformed ciphertext");
    drop(conn);

    let outcome = query_outcome_with_legacy_keys(vec![], db).expect("source query");
    assert_eq!(
      outcome.stats,
      ChromiumExtractionStats {
        rows_seen: 3,
        cookies_emitted: 1,
        rows_skipped: 2,
        rows_rejected: 2,
        provider_failures: 0,
      }
    );
    assert_eq!(outcome.cookies[0].name, "good");
    assert!(outcome.legacy_error.is_none());
    assert_eq!(outcome.issues.len(), 2);
    assert_eq!(
      outcome.issues[0].code,
      ChromiumRowIssueCode::ColumnRead("name")
    );
    assert_eq!(outcome.issues[0].occurrences, 1);
    assert_eq!(outcome.issues[1].code, ChromiumRowIssueCode::Decrypt);
    assert_eq!(outcome.issues[1].occurrences, 1);
  }

  #[cfg(unix)]
  #[test]
  fn query_outcome_verifies_host_hashes_and_classifies_decode_failures() {
    let dir = unique_tmpdir("chr-host-hash-outcome");
    let db = dir.join("Cookies");
    let key = [0x42; 16];
    let good_plaintext = host_bound_plaintext(".example.com", b"verified value");
    let good_encrypted = encrypt_unix_cbc_cookie(b"v10", &key, &good_plaintext);
    let invalid_mismatch = b"this valid UTF-8 plaintext has a mismatched host hash".to_vec();
    let invalid_encrypted = encrypt_unix_cbc_cookie(b"v10", &key, &invalid_mismatch);
    seed_chromium_cookies(
      &db,
      &[
        (
          ".example.com",
          "/",
          false,
          0,
          "verified",
          "",
          &good_encrypted,
          false,
          0,
        ),
        (
          ".other.test",
          "/",
          false,
          0,
          "mismatch",
          "",
          &invalid_encrypted,
          false,
          0,
        ),
        (
          ".plain.test",
          "/",
          false,
          0,
          "plain",
          "fallback",
          b"",
          false,
          0,
        ),
      ],
    );
    let connection = rusqlite::Connection::open(&db).expect("open writable sqlite");
    connection
      .execute("UPDATE meta SET value = '24' WHERE key = 'version'", [])
      .expect("select strict host-hash schema");
    drop(connection);

    let mut outcome =
      query_outcome_with_legacy_keys(vec![key.to_vec()], db.clone()).expect("legacy source query");
    outcome
      .cookies
      .sort_by(|left, right| left.name.cmp(&right.name));
    assert_eq!(
      outcome.stats,
      ChromiumExtractionStats {
        rows_seen: 3,
        cookies_emitted: 2,
        rows_skipped: 1,
        rows_rejected: 1,
        provider_failures: 0,
      }
    );
    assert_eq!(
      outcome
        .cookies
        .iter()
        .map(|cookie| (cookie.name.as_str(), cookie.value.as_str()))
        .collect::<Vec<_>>(),
      vec![("plain", "fallback"), ("verified", "verified value")]
    );
    assert_eq!(outcome.issues.len(), 1);
    assert_eq!(outcome.issues[0].code, ChromiumRowIssueCode::Decode);
    assert_eq!(outcome.issues[0].occurrences, 1);

    let mut detailed = query_cookies_engine_outcome_mode(
      &ChromiumKeyOutcomes::from_legacy_shared(vec![key.to_vec()]),
      db,
      None,
      false,
      CookieProjection::Detailed,
      EncryptedValuePolicy::UseKeyOutcomes,
    )
    .expect("detailed source query");
    detailed
      .detailed_cookies
      .sort_by(|left, right| left.cookie.name.cmp(&right.cookie.name));
    assert_eq!(detailed.stats, outcome.stats);
    assert_eq!(detailed.issues, outcome.issues);
    assert_eq!(
      detailed
        .detailed_cookies
        .iter()
        .map(|record| (record.cookie.name.as_str(), record.cookie.value.as_str()))
        .collect::<Vec<_>>(),
      vec![("plain", "fallback"), ("verified", "verified value")]
    );
  }

  #[cfg(unix)]
  #[test]
  fn query_cookies_ignores_malformed_and_undecryptable_rows() {
    let dir = unique_tmpdir("chr-malformed-rows");
    let db = dir.join("Cookies");
    let conn = rusqlite::Connection::open(&db).expect("open writable sqlite");
    seed_chromium_schema_version(&conn, 23);
    conn
      .execute(
        "CREATE TABLE cookies (
          host_key TEXT NOT NULL,
          path TEXT NOT NULL,
          is_secure INTEGER NOT NULL,
          expires_utc INTEGER NOT NULL,
          name TEXT NOT NULL,
          value TEXT NOT NULL,
          encrypted_value BLOB,
          is_httponly INTEGER NOT NULL,
          samesite INTEGER NOT NULL
        )",
        [],
      )
      .expect("create table");

    // Row 1: Valid row
    conn
      .execute(
        "INSERT INTO cookies VALUES ('.example.com', '/', 1, 11644473600000000, 'valid1', 'val1', X'', 1, 1)",
        [],
      )
      .expect("insert row 1");

    // Row 2: Malformed required name column.
    conn
      .execute(
        "INSERT INTO cookies VALUES ('.example.com', '/', 1, -100, X'DEADBEEF', 'val', X'76313064756d6d79', 1, 1)",
        [],
      )
      .expect("insert row 2");

    // Row 3: Undecryptable row (encrypted_value starts with v10 but fails decryption)
    conn
      .execute(
        "INSERT INTO cookies VALUES ('.example.com', '/', 1, 11644473600000000, 'undecryptable', '', X'763130696e76616c6964', 1, 1)",
        [],
      )
      .expect("insert row 3");

    // Row 4: Valid row 2
    conn
      .execute(
        "INSERT INTO cookies VALUES ('.test.com', '/', 0, 11644473600000000, 'valid2', 'val2', X'', 0, 0)",
        [],
      )
      .expect("insert row 4");

    let mut cookies = query_cookies_with_legacy_keys(vec![], db, None, false)
      .expect("query_cookies should succeed despite bad rows");
    cookies.sort_by(|a, b| a.name.cmp(&b.name));
    let names: Vec<_> = cookies.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["valid1", "valid2"], "{:?}", cookies);
  }
}
