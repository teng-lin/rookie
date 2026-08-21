//! Compatibility and direct-path projections over the Chromium acquire engine.
//!
//! `chromium.rs` is a lower engine layer used by registry acquisition.
//! Keeping finalization here prevents the report assembly graph from cycling
//! back through `registry::chromium -> chromium -> report_build`.

use super::chromium::{
  acquire_chromium_draft_with_runtime, ChromiumAcquireOptions, ChromiumAcquisition,
  ChromiumExtractionDraft,
};
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use super::chromium_crypto::retrieve_key_outcomes;
use super::chromium_crypto::ChromiumKeyOutcomes;
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use super::chromium_crypto::KeyProvider;
use super::chromium_decoder::EncryptedValuePolicy;
use super::source::{AcquisitionPolicy, SourceAcquisition, SourceCandidate};
use crate::common::deadline::BoundaryRuntime;
use crate::common::enums::{Cookie, DetailedCookie};
#[allow(unused)]
use crate::config::Browser;
use anyhow::Result;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use super::chromium_platform_keys::LinuxPlatformKeyProvider;
#[cfg(target_os = "macos")]
use super::chromium_platform_keys::MacosPlatformKeyProvider;

/// Returns cookies from chromium based browser.
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

/// Extracts only plaintext rows without probing a key provider.
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

/// Returns cookies from chromium based browser.
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn chromium_based_probe_with_key_outcomes(
  outcomes: ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
  runtime: &BoundaryRuntime<'_>,
) -> Result<super::chromium::ChromiumProbeResult> {
  super::chromium::acquire_chromium_probe_with_key_outcomes(
    outcomes, db_path, domains, force_kill, runtime,
  )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl super::chromium::ChromiumProbeResult {
  pub(crate) fn project_committed(self) -> Result<Vec<Cookie>> {
    project_legacy_draft(&self.db_path, self.draft)
  }
}

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

fn direct_path_candidate(db_path: &Path) -> SourceCandidate {
  SourceCandidate {
    path: db_path.to_path_buf(),
    role: super::report_core::CookieSourceRoleId::persistent(),
    format: super::report_core::CookieSourceFormatId::known("chromium_sqlite"),
    precedence: super::registry::PERSISTENT_SOURCE_PRECEDENCE,
    exists: true,
    selected: true,
    acquisition: SourceAcquisition::NotAttempted,
    policy: AcquisitionPolicy::Fixed,
  }
}

#[allow(dead_code)]
pub(super) fn project_legacy_draft(
  db_path: &Path,
  draft: ChromiumExtractionDraft,
) -> Result<Vec<Cookie>> {
  super::legacy::project_canonical_outcome(
    "chromium",
    direct_chromium_outcome(db_path, draft, None)?,
  )
}

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

#[cfg(test)]
pub(super) fn project_detailed_draft(
  db_path: &Path,
  draft: ChromiumExtractionDraft,
) -> Result<Vec<DetailedCookie>> {
  super::legacy::project_canonical_detailed_outcome(
    "chromium",
    direct_chromium_outcome(db_path, draft, None)?,
  )
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(super) fn extract_cookies_with_provider<Context: ?Sized, Provider>(
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
pub(super) fn extract_detailed_cookies_with_provider<Context: ?Sized, Provider>(
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
