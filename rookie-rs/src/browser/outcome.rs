//! Canonical extraction result shared by every compatibility projection.

use super::{
  cookie_record::{FinalizedCookieRecord, SourceRef},
  report_core::{
    AcquisitionStrategyCode, BrowserId, CookieSourceIdentity, ExtractionStageCode, InstallationId,
    IssueCode, IssueSeverityCode, ProfileId, ProfileIdentity,
  },
};
use sha2::{Digest, Sha256};
use std::fmt;

#[cfg(test)]
pub(crate) use crate::common::diagnostic::MAX_DIAGNOSTIC_BYTES;

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Termination {
  #[default]
  Completed,
  Cancelled,
  TimedOut,
  ResourceExhausted,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum ResultStatus {
  Complete,
  Partial,
  Failed,
  #[default]
  NoSources,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompatibilityAbsence {
  CookieDatabase,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CompatibilityDisposition {
  Emit { source_digests: Vec<[u8; 32]> },
  Absent(CompatibilityAbsence),
  Failed(Diagnostic),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompatibilityDecision {
  pub(crate) browser_id: BrowserId,
  pub(crate) disposition: CompatibilityDisposition,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FailureScope {
  Request,
  Browser {
    browser_id: BrowserId,
  },
  Profile {
    browser_id: BrowserId,
    installation_id: InstallationId,
    profile_id: ProfileId,
  },
  Source {
    browser_id: BrowserId,
    installation_id: InstallationId,
    profile_id: ProfileId,
    source_digest: [u8; 32],
  },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct FailureCause {
  pub(crate) kind: String,
  pub(crate) provider: Option<String>,
  pub(crate) tier: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Retryability {
  Retryable,
  NotRetryable,
  #[default]
  Unknown,
}

/// Sanitized diagnostic text. Construction is the only ingress, keeping
/// truncation and path redaction identical for every engine.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Diagnostic(String);

impl Diagnostic {
  pub(crate) fn new_with_secrets(message: impl AsRef<str>, secrets: &[&str]) -> Self {
    let mut sanitized = message.as_ref().to_owned();
    for secret in secrets.iter().copied().filter(|secret| !secret.is_empty()) {
      sanitized = sanitized.replace(secret, "<cookie-value>");
    }
    Self(crate::common::diagnostic::sanitize(&sanitized))
  }

  pub(crate) fn as_str(&self) -> &str {
    &self.0
  }
}

impl fmt::Debug for Diagnostic {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.debug_tuple("Diagnostic").field(&self.0).finish()
  }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Failure {
  pub(crate) code: IssueCode,
  pub(crate) stage: ExtractionStageCode,
  pub(crate) scope: FailureScope,
  pub(crate) cause: FailureCause,
  pub(crate) severity: IssueSeverityCode,
  pub(crate) retryability: Retryability,
  pub(crate) occurrences: u32,
  pub(crate) samples: Vec<Diagnostic>,
  pub(crate) diagnostic: Diagnostic,
}

impl Failure {
  pub(crate) fn from_issue(
    issue: super::report_core::ExtractionIssue,
    scope: FailureScope,
    secrets: &[&str],
  ) -> Self {
    let retryability = match issue.retryability.as_str() {
      "retryable" => Retryability::Retryable,
      "not_retryable" => Retryability::NotRetryable,
      _ => Retryability::Unknown,
    };
    let cause = FailureCause {
      kind: issue.cause,
      provider: issue.provider,
      tier: issue.tier,
    };
    Self {
      code: issue.code,
      stage: issue.stage,
      scope,
      cause,
      severity: issue.severity,
      retryability,
      occurrences: issue.occurrences,
      samples: issue
        .samples
        .into_iter()
        .map(|sample| Diagnostic::new_with_secrets(sample, secrets))
        .collect(),
      diagnostic: Diagnostic::new_with_secrets(issue.message, secrets),
    }
  }

  pub(crate) fn into_issue(self) -> super::report_core::ExtractionIssue {
    let (browser_id, installation_id, profile_id) = match self.scope {
      FailureScope::Request => (None, None, None),
      FailureScope::Browser { browser_id } => (Some(browser_id), None, None),
      FailureScope::Profile {
        browser_id,
        installation_id,
        profile_id,
      }
      | FailureScope::Source {
        browser_id,
        installation_id,
        profile_id,
        ..
      } => (Some(browser_id), Some(installation_id), Some(profile_id)),
    };
    super::report_core::ExtractionIssue {
      code: self.code,
      stage: self.stage,
      severity: self.severity,
      cause: self.cause.kind,
      provider: self.cause.provider,
      tier: self.cause.tier,
      retryability: match self.retryability {
        Retryability::Retryable => "retryable",
        Retryability::NotRetryable => "not_retryable",
        Retryability::Unknown => "unknown",
      }
      .to_owned(),
      occurrences: self.occurrences,
      samples: self.samples.into_iter().map(|sample| sample.0).collect(),
      browser_id,
      installation_id,
      profile_id,
      message: self.diagnostic.0,
    }
  }
}

#[derive(Debug, Default)]
pub(crate) struct FailureLedger {
  failures: Vec<Failure>,
}

impl FailureLedger {
  pub(crate) fn push(&mut self, mut incoming: Failure) {
    let Some(existing) = self.failures.iter_mut().find(|failure| {
      failure.code == incoming.code
        && failure.stage == incoming.stage
        && failure.scope == incoming.scope
        && failure.cause == incoming.cause
        && failure.severity == incoming.severity
        && failure.retryability == incoming.retryability
    }) else {
      incoming
        .samples
        .truncate(super::report_core::MAX_ISSUE_SAMPLES);
      self.failures.push(incoming);
      return;
    };
    existing.occurrences = existing.occurrences.saturating_add(incoming.occurrences);
    for sample in incoming.samples {
      if existing.samples.len() == super::report_core::MAX_ISSUE_SAMPLES {
        break;
      }
      existing.samples.push(sample);
    }
  }

  pub(crate) fn as_slice(&self) -> &[Failure] {
    &self.failures
  }

  pub(crate) fn into_vec(self) -> Vec<Failure> {
    self.failures
  }
}

#[derive(Debug)]
pub(crate) struct SourceOutcome {
  pub(crate) profile: ProfileIdentity,
  pub(crate) is_default_profile: bool,
  pub(crate) source: CookieSourceIdentity,
  pub(crate) selected: bool,
  pub(crate) acquisition_strategy: AcquisitionStrategyCode,
  pub(crate) records: Vec<FinalizedCookieRecord>,
  source_digest: [u8; 32],
  pub(crate) stats: super::report_core::ExtractionStats,
  pub(crate) failed: bool,
}

impl SourceOutcome {
  pub(crate) fn new(
    profile: ProfileIdentity,
    is_default_profile: bool,
    source: CookieSourceIdentity,
    source_digest: [u8; 32],
    selected: bool,
    acquisition_strategy: AcquisitionStrategyCode,
  ) -> Self {
    Self {
      profile,
      is_default_profile,
      source,
      selected,
      acquisition_strategy,
      records: Vec::new(),
      source_digest,
      stats: super::report_core::ExtractionStats::default(),
      failed: false,
    }
  }

  pub(crate) fn source_digest(&self) -> [u8; 32] {
    self.source_digest
  }

  pub(crate) fn assign_provenance(&mut self) {
    let digest = self.source_digest();
    for (ordinal, record) in self.records.iter_mut().enumerate() {
      record.assign_source(digest, ordinal);
    }
  }
}

#[derive(Debug, Default)]
pub(crate) struct OutcomeCounters {
  pub(crate) registered_browsers: usize,
  pub(crate) browsers_detected: usize,
  pub(crate) browsers_not_detected: usize,
  pub(crate) installations_discovered: usize,
  pub(crate) profiles_discovered: usize,
  pub(crate) sources_discovered: usize,
  pub(crate) sources_succeeded: usize,
  pub(crate) sources_failed: usize,
  pub(crate) rows_seen: u64,
  pub(crate) cookies_emitted: u64,
  pub(crate) rows_skipped: u64,
  pub(crate) rows_rejected: u64,
  pub(crate) provider_failures: u64,
  pub(crate) counters_saturated: bool,
}

#[derive(Debug)]
pub(crate) struct Outcome {
  pub(crate) profiles: Vec<(ProfileIdentity, bool)>,
  pub(crate) sources: Vec<SourceOutcome>,
  pub(crate) failure_ledger: FailureLedger,
  pub(crate) counters: OutcomeCounters,
  pub(crate) result_status: ResultStatus,
  pub(crate) termination: Termination,
  pub(crate) compatibility: Vec<CompatibilityDecision>,
}

impl Outcome {
  pub(crate) fn finalize(
    profiles: Vec<(ProfileIdentity, bool)>,
    mut sources: Vec<SourceOutcome>,
    failure_ledger: FailureLedger,
    discovered_any_source: bool,
    termination: Termination,
  ) -> Self {
    let mut counters = OutcomeCounters {
      sources_discovered: sources.len(),
      profiles_discovered: profiles.len(),
      ..OutcomeCounters::default()
    };
    for source in &mut sources {
      source.assign_provenance();
      if source.failed {
        counters.sources_failed += 1;
      } else {
        counters.sources_succeeded += 1;
      }
      counters.rows_seen = counters
        .rows_seen
        .saturating_add(u64::from(source.stats.rows_seen));
      counters.cookies_emitted = counters
        .cookies_emitted
        .saturating_add(u64::from(source.stats.cookies_emitted));
      counters.rows_skipped = counters
        .rows_skipped
        .saturating_add(u64::from(source.stats.rows_skipped));
      counters.rows_rejected = counters
        .rows_rejected
        .saturating_add(u64::from(source.stats.rows_rejected));
      counters.provider_failures = counters
        .provider_failures
        .saturating_add(u64::from(source.stats.provider_failures));
      counters.counters_saturated |= source.stats.counters_saturated;
    }
    let succeeded = counters.sources_succeeded > 0;
    let has_error = failure_ledger
      .as_slice()
      .iter()
      .any(|failure| failure.severity == IssueSeverityCode::error());
    let result_status = if succeeded {
      if has_error {
        ResultStatus::Partial
      } else {
        ResultStatus::Complete
      }
    } else if discovered_any_source || has_error {
      ResultStatus::Failed
    } else {
      ResultStatus::NoSources
    };
    Self {
      profiles,
      sources,
      failure_ledger,
      counters,
      result_status,
      termination,
      compatibility: Vec::new(),
    }
  }
}

pub(crate) fn source_digest(
  profile: &ProfileIdentity,
  source: &CookieSourceIdentity,
  raw_path: &[u8],
) -> [u8; 32] {
  let mut hasher = Sha256::new();
  hasher.update(b"rookie-cookie-source\0v1");
  for field in [
    profile.browser_id.as_str(),
    profile.installation_id.as_str(),
    profile.profile_id.as_str(),
    source.role.as_str(),
    source.format.as_str(),
  ] {
    hasher.update(field.len().to_be_bytes());
    hasher.update(field.as_bytes());
  }
  hasher.update(source.precedence.to_be_bytes());
  hasher.update(raw_path.len().to_be_bytes());
  hasher.update(raw_path);
  hasher.finalize().into()
}

pub(crate) fn source_ref(source_digest: [u8; 32], ordinal: usize) -> SourceRef {
  SourceRef::pending(ordinal).with_digest(source_digest)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{
    browser::{
      cookie_record::FinalizedCookieRecord,
      report_core::{CookieSourceFormatId, CookieSourceRoleId, ExtractionStats},
    },
    common::enums::Cookie,
  };

  fn profile() -> ProfileIdentity {
    ProfileIdentity {
      browser_id: BrowserId::known("firefox"),
      installation_id: "a".repeat(64).parse().expect("installation id"),
      profile_id: "b".repeat(64).parse().expect("profile id"),
      display_name: "default".to_owned(),
      path: "profile".to_owned(),
      path_lossy: false,
    }
  }

  fn source(path: &str) -> SourceOutcome {
    let identity = CookieSourceIdentity {
      role: CookieSourceRoleId::persistent(),
      format: CookieSourceFormatId::known("mozilla_sqlite"),
      path: path.to_owned(),
      path_lossy: false,
      precedence: 10,
    };
    let mut outcome = SourceOutcome::new(
      profile(),
      true,
      identity.clone(),
      source_digest(&profile(), &identity, path.as_bytes()),
      true,
      AcquisitionStrategyCode::live_read_only(),
    );
    outcome.records.push(
      super::super::cookie_record::CookieRecord::from_cookie(
        Cookie {
          domain: ".example.com".to_owned(),
          path: "/".to_owned(),
          secure: false,
          expires: None,
          name: "sid".to_owned(),
          value: "same-value".to_owned(),
          http_only: true,
          same_site: 1,
        },
        SourceRef::pending(0),
      )
      .finalize()
      .expect("plain fixture finalizes"),
    );
    outcome.stats = ExtractionStats {
      rows_seen: 1,
      cookies_emitted: 1,
      ..ExtractionStats::default()
    };
    outcome
  }

  #[test]
  fn duplicate_records_remain_distinct_and_receive_source_local_provenance() {
    let outcome = Outcome::finalize(
      vec![(profile(), true)],
      vec![source("source-a"), source("source-b")],
      FailureLedger::default(),
      true,
      Termination::Completed,
    );
    assert_eq!(outcome.sources.len(), 2);
    assert_ne!(
      outcome.sources[0].records[0].source_ref().source_digest,
      outcome.sources[1].records[0].source_ref().source_digest
    );
    assert_eq!(outcome.sources[0].records[0].source_ref().ordinal, 0);
    // Identity is chosen by the caller. The model itself never equates or
    // deduplicates these records.
    let key =
      |record: &FinalizedCookieRecord| (record.domain_raw().to_owned(), record.name().to_owned());
    assert_eq!(
      key(&outcome.sources[0].records[0]),
      key(&outcome.sources[1].records[0])
    );
  }

  #[test]
  fn aggregation_uses_the_full_typed_failure_key() {
    let installation_id: InstallationId = "c".repeat(64).parse().expect("installation id");
    let profile_id: ProfileId = "d".repeat(64).parse().expect("profile id");
    let failure = || Failure {
      code: IssueCode::provider_failed(),
      stage: ExtractionStageCode::decrypt(),
      scope: FailureScope::Source {
        browser_id: BrowserId::known("chrome"),
        installation_id: installation_id.clone(),
        profile_id: profile_id.clone(),
        source_digest: [7; 32],
      },
      cause: FailureCause {
        kind: "credential_provider".to_owned(),
        provider: Some("secret_service".to_owned()),
        tier: Some("v10".to_owned()),
      },
      severity: IssueSeverityCode::error(),
      retryability: Retryability::Retryable,
      occurrences: 1,
      samples: Vec::new(),
      diagnostic: Diagnostic::new_with_secrets("provider failed", &[]),
    };
    let mut ledger = FailureLedger::default();
    ledger.push(failure());
    ledger.push(failure());
    let mut variants = Vec::new();
    let mut variant = failure();
    variant.code = IssueCode::provider_unavailable();
    variants.push(variant);
    let mut variant = failure();
    variant.stage = ExtractionStageCode::query();
    variants.push(variant);
    let mut variant = failure();
    variant.scope = FailureScope::Request;
    variants.push(variant);
    let mut variant = failure();
    variant.scope = FailureScope::Browser {
      browser_id: BrowserId::known("chrome"),
    };
    variants.push(variant);
    let mut variant = failure();
    variant.scope = FailureScope::Profile {
      browser_id: BrowserId::known("chrome"),
      installation_id: installation_id.clone(),
      profile_id: profile_id.clone(),
    };
    variants.push(variant);
    let mut variant = failure();
    variant.scope = FailureScope::Source {
      browser_id: BrowserId::known("firefox"),
      installation_id: installation_id.clone(),
      profile_id: profile_id.clone(),
      source_digest: [7; 32],
    };
    variants.push(variant);
    let mut variant = failure();
    variant.scope = FailureScope::Source {
      browser_id: BrowserId::known("chrome"),
      installation_id: "e".repeat(64).parse().expect("installation id"),
      profile_id: profile_id.clone(),
      source_digest: [7; 32],
    };
    variants.push(variant);
    let mut variant = failure();
    variant.scope = FailureScope::Source {
      browser_id: BrowserId::known("chrome"),
      installation_id: installation_id.clone(),
      profile_id: "f".repeat(64).parse().expect("profile id"),
      source_digest: [7; 32],
    };
    variants.push(variant);
    let mut variant = failure();
    variant.scope = FailureScope::Source {
      browser_id: BrowserId::known("chrome"),
      installation_id: installation_id.clone(),
      profile_id: profile_id.clone(),
      source_digest: [8; 32],
    };
    variants.push(variant);
    let mut variant = failure();
    variant.cause.kind = "key_parse".to_owned();
    variants.push(variant);
    let mut variant = failure();
    variant.cause.provider = Some("kwallet".to_owned());
    variants.push(variant);
    let mut variant = failure();
    variant.cause.tier = Some("v11".to_owned());
    variants.push(variant);
    let mut variant = failure();
    variant.severity = IssueSeverityCode::warning();
    variants.push(variant);
    let mut variant = failure();
    variant.retryability = Retryability::NotRetryable;
    variants.push(variant);
    for variant in variants {
      ledger.push(variant);
    }
    assert_eq!(ledger.as_slice().len(), 15);
    assert_eq!(ledger.as_slice()[0].occurrences, 2);

    let mut saturated = failure();
    saturated.occurrences = u32::MAX;
    let mut saturated_ledger = FailureLedger::default();
    saturated_ledger.push(saturated);
    saturated_ledger.push(failure());
    assert_eq!(saturated_ledger.as_slice()[0].occurrences, u32::MAX);
  }

  #[test]
  fn diagnostics_redact_absolute_paths_and_are_bounded() {
    let sentinel_path = "/Users/alice/profile/Cookies";
    let windows_path = r"C:\Users\alice\Cookies";
    let long = format!(
      "failed {sentinel_path} and {windows_path} {}",
      "x".repeat(800)
    );
    let diagnostic = Diagnostic::new_with_secrets(long, &[]);
    assert!(!diagnostic.as_str().contains(sentinel_path));
    assert!(!diagnostic.as_str().contains(windows_path));
    assert!(diagnostic.as_str().contains("<path>"));
    assert!(diagnostic.as_str().len() <= MAX_DIAGNOSTIC_BYTES);

    let variants = [
      r"UNC \\server\share\Cookie Store",
      r"device \\?\C:\Users\alice\Cookies",
      "path=/Users/alice/Profile/Cookies",
      "source='/Users/alice/Profile With Spaces/Cookies'",
      "embedded(/private/tmp/cookie-db)",
      "failed to read /Users/alice/Profile With Spaces/Cookies: permission denied",
      r"failed to read C:\Users\alice\Profile With Spaces\Cookies: access denied",
    ];
    for value in variants {
      let diagnostic = Diagnostic::new_with_secrets(value, &[]);
      assert!(diagnostic.as_str().contains("<path>"), "{value:?}");
      assert!(!diagnostic.as_str().contains("alice"), "{value:?}");
    }

    for requested in 511..=514 {
      let prefix = "é".repeat(requested / 2);
      let diagnostic = Diagnostic::new_with_secrets(format!("{prefix}界界"), &[]);
      assert!(diagnostic.as_str().len() <= MAX_DIAGNOSTIC_BYTES);
      assert!(std::str::from_utf8(diagnostic.as_str().as_bytes()).is_ok());
    }
  }

  #[cfg(unix)]
  #[test]
  fn provenance_hashes_distinct_raw_non_utf8_paths_and_identity_context() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt, path::PathBuf};

    let first = PathBuf::from(OsString::from_vec(b"/tmp/source-\x80".to_vec()));
    let second = PathBuf::from(OsString::from_vec(b"/tmp/source-\x81".to_vec()));
    assert_eq!(first.to_string_lossy(), second.to_string_lossy());
    let identity = CookieSourceIdentity {
      role: CookieSourceRoleId::persistent(),
      format: CookieSourceFormatId::known("mozilla_sqlite"),
      path: first.to_string_lossy().into_owned(),
      path_lossy: true,
      precedence: 10,
    };
    use std::os::unix::ffi::OsStrExt;
    let first_digest = source_digest(&profile(), &identity, first.as_os_str().as_bytes());
    let second_digest = source_digest(&profile(), &identity, second.as_os_str().as_bytes());
    assert_ne!(first_digest, second_digest);

    let mut other_profile = profile();
    other_profile.browser_id = BrowserId::known("librewolf");
    assert_ne!(
      first_digest,
      source_digest(&other_profile, &identity, first.as_os_str().as_bytes())
    );
  }

  #[test]
  fn result_status_is_independent_from_termination_and_zero_rows_are_complete() {
    let mut source = source("zero-row-source");
    source.records.clear();
    source.stats = ExtractionStats::default();
    let outcome = Outcome::finalize(
      vec![(profile(), true)],
      vec![source],
      FailureLedger::default(),
      true,
      Termination::TimedOut,
    );
    assert_eq!(outcome.result_status, ResultStatus::Complete);
    assert_eq!(outcome.termination, Termination::TimedOut);
  }

  #[test]
  fn already_saturated_source_marks_the_outcome_counter() {
    let mut source = source("saturated-source");
    source.stats.counters_saturated = true;
    let outcome = Outcome::finalize(
      vec![(profile(), true)],
      vec![source],
      FailureLedger::default(),
      true,
      Termination::Completed,
    );
    assert!(outcome.counters.counters_saturated);
  }

  #[test]
  fn canonical_debug_keeps_cookie_values_redacted() {
    let source = source("source");
    let outcome = Outcome::finalize(
      vec![(profile(), true)],
      vec![source],
      FailureLedger::default(),
      true,
      Termination::Completed,
    );
    assert!(!format!("{outcome:?}").contains("same-value"));
  }
}
