//! Frozen cross-engine report contract (Milestone 4E).
//!
//! Every field here is the final private shape of the Section 5.7 wire model.
//! The Milestone 5 public surface republishes these structures unchanged; until
//! that release gate, nothing in this module is exported from `lib.rs`.
//!
//! Identifier vocabularies are deliberately open: each one is a validated
//! string newtype serialized as a snake_case string, never a closed enum, so a
//! new engine, cipher tier, or issue code cannot break a downstream consumer.

// The report contract is complete before its public surface ships in
// Milestone 5, so unused-until-then items are expected here.
#![allow(dead_code)]

use crate::common::enums::Cookie;
use anyhow::{bail, Result};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::str::FromStr;

/// Upper bound on retained samples per aggregated issue.
pub(crate) const MAX_ISSUE_SAMPLES: usize = 8;

fn validate_open_identifier(kind: &str, value: &str) -> Result<()> {
  let mut bytes = value.bytes();
  let valid = match bytes.next() {
    Some(first) if first.is_ascii_lowercase() => {
      bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    }
    _ => false,
  };
  if !valid {
    bail!("invalid {kind} identifier {value:?}")
  }
  Ok(())
}

fn validate_opaque_identifier(kind: &str, value: &str) -> Result<()> {
  if value.len() != 64
    || !value
      .bytes()
      .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
  {
    bail!("invalid {kind} identifier {value:?}")
  }
  Ok(())
}

macro_rules! string_identifier {
  ($name:ident, $kind:literal, $validate:ident) => {
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
    #[serde(transparent)]
    pub(crate) struct $name(String);

    impl $name {
      /// Constructs an identifier the crate itself produces.
      ///
      /// Vocabulary values are compile-time constants, so an invalid one is a
      /// crate bug rather than a runtime condition a caller can act on.
      pub(crate) fn known(value: &str) -> Self {
        debug_assert!(
          $validate($kind, value).is_ok(),
          "crate-produced {} identifier {value:?} is invalid",
          $kind
        );
        Self(value.to_owned())
      }

      pub(crate) fn as_str(&self) -> &str {
        &self.0
      }
    }

    impl AsRef<str> for $name {
      fn as_ref(&self) -> &str {
        &self.0
      }
    }

    impl fmt::Display for $name {
      fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
      }
    }

    impl FromStr for $name {
      type Err = anyhow::Error;

      fn from_str(value: &str) -> Result<Self> {
        $validate($kind, value)?;
        Ok(Self(value.to_owned()))
      }
    }

    impl<'de> Deserialize<'de> for $name {
      fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        $validate($kind, &value).map_err(serde::de::Error::custom)?;
        Ok(Self(value))
      }
    }
  };
}

string_identifier!(BrowserId, "browser", validate_open_identifier);
string_identifier!(EngineId, "engine", validate_open_identifier);
string_identifier!(
  CookieSourceRoleId,
  "cookie source role",
  validate_open_identifier
);
string_identifier!(
  CookieSourceFormatId,
  "cookie source format",
  validate_open_identifier
);
string_identifier!(CipherTierId, "cipher tier", validate_open_identifier);
string_identifier!(ReportStatusCode, "report status", validate_open_identifier);
string_identifier!(SourceStatusCode, "source status", validate_open_identifier);
string_identifier!(
  AcquisitionStrategyCode,
  "acquisition strategy",
  validate_open_identifier
);
string_identifier!(IssueCode, "issue code", validate_open_identifier);
string_identifier!(
  ExtractionStageCode,
  "extraction stage",
  validate_open_identifier
);
string_identifier!(
  IssueSeverityCode,
  "issue severity",
  validate_open_identifier
);
string_identifier!(InstallationId, "installation", validate_opaque_identifier);
string_identifier!(ProfileId, "profile", validate_opaque_identifier);

macro_rules! vocabulary {
  ($name:ident { $($function:ident => $value:literal),+ $(,)? }) => {
    impl $name {
      $(
        pub(crate) fn $function() -> Self {
          Self::known($value)
        }
      )+
    }
  };
}

vocabulary!(CookieSourceRoleId {
  persistent => "persistent",
  session => "session",
});

vocabulary!(ReportStatusCode {
  complete => "complete",
  partial => "partial",
  failed => "failed",
  no_sources => "no_sources",
});

vocabulary!(SourceStatusCode {
  succeeded => "succeeded",
  failed => "failed",
});

vocabulary!(IssueSeverityCode {
  info => "info",
  warning => "warning",
  error => "error",
});

vocabulary!(ExtractionStageCode {
  registry => "registry",
  discovery => "discovery",
  acquisition => "acquisition",
  parse => "parse",
  decrypt => "decrypt",
  decode => "decode",
  query => "query",
});

vocabulary!(AcquisitionStrategyCode {
  live_read_only => "live_read_only",
  verified_wal_snapshot => "verified_wal_snapshot",
  verified_static_single_file => "verified_static_single_file",
  stable_file_image => "stable_file_image",
  ese_database => "ese_database",
  not_attempted => "not_attempted",
});

impl CookieSourceRoleId {
  /// Report ordering rank. Unknown future roles sort after the frozen ones and
  /// then lexicographically, so an added vocabulary value stays deterministic.
  fn order_rank(&self) -> (u8, &str) {
    match self.as_str() {
      "persistent" => (0, ""),
      "session" => (1, ""),
      other => (2, other),
    }
  }
}

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BrowserCapabilitiesDescriptor {
  pub(crate) persistent_formats: Vec<CookieSourceFormatId>,
  pub(crate) session_formats: Vec<CookieSourceFormatId>,
  pub(crate) declared_decryption_tiers: Vec<CipherTierId>,
  pub(crate) available_decryption_tiers: Vec<CipherTierId>,
}

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BrowserDescriptor {
  pub(crate) id: BrowserId,
  pub(crate) aliases: Vec<String>,
  pub(crate) display_name: String,
  pub(crate) engine: EngineId,
  pub(crate) capabilities: BrowserCapabilitiesDescriptor,
}

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProfileIdentity {
  pub(crate) browser_id: BrowserId,
  pub(crate) installation_id: InstallationId,
  pub(crate) profile_id: ProfileId,
  pub(crate) display_name: String,
  pub(crate) path: String,
  pub(crate) path_lossy: bool,
}

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CookieSourceDescriptor {
  pub(crate) role: CookieSourceRoleId,
  pub(crate) format: CookieSourceFormatId,
  pub(crate) path: String,
  pub(crate) path_lossy: bool,
  pub(crate) precedence: u16,
}

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProfileDescriptor {
  pub(crate) profile: ProfileIdentity,
  pub(crate) is_default: bool,
  pub(crate) sources: Vec<CookieSourceDescriptor>,
}

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CookieSourceIdentity {
  pub(crate) role: CookieSourceRoleId,
  pub(crate) format: CookieSourceFormatId,
  pub(crate) path: String,
  pub(crate) path_lossy: bool,
  pub(crate) precedence: u16,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ExtractionStats {
  pub(crate) rows_seen: u32,
  pub(crate) cookies_emitted: u32,
  pub(crate) rows_skipped: u32,
  pub(crate) acquisition_attempts: u32,
  pub(crate) counters_saturated: bool,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReportStats {
  pub(crate) registered_browsers: u32,
  pub(crate) browsers_detected: u32,
  pub(crate) browsers_not_detected: u32,
  pub(crate) installations_discovered: u32,
  pub(crate) profiles_discovered: u32,
  pub(crate) sources_succeeded: u32,
  pub(crate) sources_failed: u32,
  pub(crate) rows_seen: u32,
  pub(crate) cookies_emitted: u32,
  pub(crate) rows_skipped: u32,
  pub(crate) counters_saturated: bool,
}

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ExtractionIssue {
  pub(crate) code: IssueCode,
  pub(crate) stage: ExtractionStageCode,
  pub(crate) severity: IssueSeverityCode,
  pub(crate) occurrences: u32,
  pub(crate) samples: Vec<String>,
  pub(crate) browser_id: Option<BrowserId>,
  pub(crate) installation_id: Option<InstallationId>,
  pub(crate) profile_id: Option<ProfileId>,
  pub(crate) message: String,
}

#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SourceExtraction {
  pub(crate) source: CookieSourceIdentity,
  pub(crate) status: SourceStatusCode,
  pub(crate) selected: bool,
  pub(crate) acquisition_strategy: AcquisitionStrategyCode,
  pub(crate) cookies: Vec<Cookie>,
  pub(crate) stats: ExtractionStats,
  pub(crate) issues: Vec<ExtractionIssue>,
}

#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ProfileExtraction {
  pub(crate) profile: ProfileIdentity,
  pub(crate) sources: Vec<SourceExtraction>,
  pub(crate) stats: ExtractionStats,
  pub(crate) issues: Vec<ExtractionIssue>,
}

#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ExtractionReport {
  pub(crate) status: ReportStatusCode,
  pub(crate) summary: ReportStats,
  pub(crate) profiles: Vec<ProfileExtraction>,
  pub(crate) issues: Vec<ExtractionIssue>,
}

/// Engine adaptation layer from Section 5.7. Each engine converts one attempted
/// source and its enclosing profile into these shapes before the shared report
/// builder normalizes ordering, statuses, and aggregate counters.
#[non_exhaustive]
#[derive(Debug)]
pub(crate) struct SourceExtractionOutcome {
  pub(crate) source: CookieSourceIdentity,
  pub(crate) selected: bool,
  pub(crate) acquisition_strategy: AcquisitionStrategyCode,
  pub(crate) cookies: Vec<Cookie>,
  pub(crate) stats: ExtractionStats,
  pub(crate) issues: Vec<ExtractionIssue>,
  /// Acquisition, parsing, or the filtered query did not complete. Skipped rows
  /// alone never set this: a source with rejected rows still succeeded.
  pub(crate) failed: bool,
}

#[non_exhaustive]
#[derive(Debug)]
pub(crate) struct EngineExtractionOutcome {
  pub(crate) profile: ProfileIdentity,
  pub(crate) is_default: bool,
  pub(crate) sources: Vec<SourceExtractionOutcome>,
  pub(crate) issues: Vec<ExtractionIssue>,
}

impl SourceExtractionOutcome {
  pub(crate) fn new(
    source: CookieSourceIdentity,
    selected: bool,
    acquisition_strategy: AcquisitionStrategyCode,
  ) -> Self {
    Self {
      source,
      selected,
      acquisition_strategy,
      cookies: Vec::new(),
      stats: ExtractionStats::default(),
      issues: Vec::new(),
      failed: false,
    }
  }
}

impl EngineExtractionOutcome {
  pub(crate) fn new(profile: ProfileIdentity, is_default: bool) -> Self {
    Self {
      profile,
      is_default,
      sources: Vec::new(),
      issues: Vec::new(),
    }
  }
}

/// Wider-than-wire counters. Every public counter is `u32` so Node/TypeScript
/// can represent it exactly; counting happens in `u64` and saturates once.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CounterSet {
  pub(crate) rows_seen: u64,
  pub(crate) cookies_emitted: u64,
  pub(crate) rows_skipped: u64,
  pub(crate) acquisition_attempts: u64,
}

fn saturate(value: u64, saturated: &mut bool) -> u32 {
  u32::try_from(value).unwrap_or_else(|_| {
    *saturated = true;
    u32::MAX
  })
}

impl CounterSet {
  pub(crate) fn into_stats(self) -> ExtractionStats {
    let mut counters_saturated = false;
    ExtractionStats {
      rows_seen: saturate(self.rows_seen, &mut counters_saturated),
      cookies_emitted: saturate(self.cookies_emitted, &mut counters_saturated),
      rows_skipped: saturate(self.rows_skipped, &mut counters_saturated),
      acquisition_attempts: saturate(self.acquisition_attempts, &mut counters_saturated),
      counters_saturated,
    }
  }
}

/// Re-widens already-narrowed stats so an aggregate cannot lose a saturation
/// that a lower level already recorded.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct StatsAccumulator {
  counters: CounterSet,
  saturated: bool,
}

impl StatsAccumulator {
  pub(crate) fn add(&mut self, stats: &ExtractionStats) {
    self.counters.rows_seen += u64::from(stats.rows_seen);
    self.counters.cookies_emitted += u64::from(stats.cookies_emitted);
    self.counters.rows_skipped += u64::from(stats.rows_skipped);
    self.counters.acquisition_attempts += u64::from(stats.acquisition_attempts);
    self.saturated |= stats.counters_saturated;
  }

  pub(crate) fn into_stats(self) -> ExtractionStats {
    let mut stats = self.counters.into_stats();
    stats.counters_saturated |= self.saturated;
    stats
  }
}

pub(crate) fn issue(
  code: &str,
  stage: ExtractionStageCode,
  severity: IssueSeverityCode,
  message: impl Into<String>,
) -> ExtractionIssue {
  ExtractionIssue {
    code: IssueCode::known(code),
    stage,
    severity,
    occurrences: 1,
    samples: Vec::new(),
    browser_id: None,
    installation_id: None,
    profile_id: None,
    message: message.into(),
  }
}

/// Merges an issue into a bounded aggregate list, keyed by code and stage.
///
/// Row-level engine issues repeat per row; retaining every one would let a
/// corrupt database dictate report size.
pub(crate) fn push_aggregated(issues: &mut Vec<ExtractionIssue>, incoming: ExtractionIssue) {
  let Some(existing) = issues
    .iter_mut()
    .find(|issue| issue.code == incoming.code && issue.stage == incoming.stage)
  else {
    issues.push(incoming);
    return;
  };
  existing.occurrences = existing.occurrences.saturating_add(incoming.occurrences);
  if existing.severity_rank() < incoming.severity_rank() {
    existing.severity = incoming.severity;
    existing.message = incoming.message;
  }
  for sample in incoming.samples {
    if existing.samples.len() >= MAX_ISSUE_SAMPLES {
      break;
    }
    existing.samples.push(sample);
  }
}

impl ExtractionIssue {
  fn severity_rank(&self) -> u8 {
    match self.severity.as_str() {
      "error" => 2,
      "warning" => 1,
      _ => 0,
    }
  }

  pub(crate) fn is_error(&self) -> bool {
    self.severity.as_str() == "error"
  }

  pub(crate) fn with_context(
    mut self,
    browser_id: Option<&BrowserId>,
    installation_id: Option<&InstallationId>,
    profile_id: Option<&ProfileId>,
  ) -> Self {
    self.browser_id = browser_id.cloned();
    self.installation_id = installation_id.cloned();
    self.profile_id = profile_id.cloned();
    self
  }

  pub(crate) fn with_samples(mut self, samples: Vec<String>) -> Self {
    self.samples = samples.into_iter().take(MAX_ISSUE_SAMPLES).collect();
    self
  }

  pub(crate) fn with_occurrences(mut self, occurrences: u32) -> Self {
    self.occurrences = occurrences;
    self
  }
}

pub(crate) fn sort_cookies(cookies: &mut [Cookie]) {
  cookies.sort_by(|left, right| {
    left
      .domain
      .cmp(&right.domain)
      .then_with(|| left.path.cmp(&right.path))
      .then_with(|| left.name.cmp(&right.name))
      .then_with(|| left.expires.cmp(&right.expires))
      .then_with(|| left.secure.cmp(&right.secure))
      .then_with(|| left.http_only.cmp(&right.http_only))
      .then_with(|| left.same_site.cmp(&right.same_site))
      .then_with(|| left.value.cmp(&right.value))
  });
}

/// Section 5.5 source ordering: role first, then declared precedence. The sort
/// is stable, so equal keys keep their engine-declared candidate order.
pub(crate) fn sort_source_outcomes(sources: &mut [SourceExtractionOutcome]) {
  sources.sort_by(|left, right| {
    left
      .source
      .role
      .order_rank()
      .cmp(&right.source.role.order_rank())
      .then_with(|| left.source.precedence.cmp(&right.source.precedence))
  });
}

pub(crate) fn sort_source_descriptors(sources: &mut [CookieSourceDescriptor]) {
  sources.sort_by(|left, right| {
    left
      .role
      .order_rank()
      .cmp(&right.role.order_rank())
      .then_with(|| left.precedence.cmp(&right.precedence))
  });
}

/// A source succeeded when acquisition, parsing, and the filtered query all
/// completed, even when zero rows matched.
pub(crate) fn source_status(failed: bool) -> SourceStatusCode {
  if failed {
    SourceStatusCode::failed()
  } else {
    SourceStatusCode::succeeded()
  }
}

/// Section 5.7 report status. `discovery_failed` reports whether any detected
/// installation or root failed hard enough to prevent source enumeration.
///
/// An error-severity issue anywhere resolves to `partial` or `failed` and never
/// to `no_sources`, which Section 5.7 defines as discovery completing *without*
/// an error-severity failure. A profile that ended up with no sources because
/// something errored has not found "no sources"; it failed to look.
pub(crate) fn report_status(
  profiles: &[ProfileExtraction],
  top_level: &[ExtractionIssue],
  discovery_failed: bool,
) -> ReportStatusCode {
  let succeeded = profiles.iter().any(|profile| {
    profile
      .sources
      .iter()
      .any(|source| source.status == SourceStatusCode::succeeded())
  });
  let attempted = profiles.iter().any(|profile| !profile.sources.is_empty());
  let has_error = top_level.iter().any(ExtractionIssue::is_error)
    || profiles.iter().any(|profile| {
      profile.issues.iter().any(ExtractionIssue::is_error)
        || profile
          .sources
          .iter()
          .any(|source| source.issues.iter().any(ExtractionIssue::is_error))
    });

  if succeeded {
    if has_error {
      ReportStatusCode::partial()
    } else {
      ReportStatusCode::complete()
    }
  } else if attempted || discovery_failed || has_error {
    ReportStatusCode::failed()
  } else {
    ReportStatusCode::no_sources()
  }
}

/// Wire paths are UTF-8 with an explicit lossy flag; selection always uses the
/// opaque IDs instead.
pub(crate) fn display_path(path: &std::path::Path) -> (String, bool) {
  match path.to_str() {
    Some(value) => (value.to_owned(), false),
    None => (path.to_string_lossy().into_owned(), true),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn open_identifiers_validate_snake_case_and_round_trip() {
    let code = IssueCode::from_str("future_engine_issue").expect("valid identifier");
    assert_eq!(code.as_str(), "future_engine_issue");
    assert_eq!(code.to_string(), "future_engine_issue");
    assert_eq!(AsRef::<str>::as_ref(&code), "future_engine_issue");
    assert_eq!(
      serde_json::to_string(&code).expect("serialize"),
      "\"future_engine_issue\""
    );
    assert_eq!(
      serde_json::from_str::<IssueCode>("\"future_engine_issue\"").expect("deserialize"),
      code
    );

    for invalid in ["", "Uppercase", "1leading", "has-dash", "has space"] {
      assert!(
        IssueCode::from_str(invalid).is_err(),
        "{invalid:?} must be rejected"
      );
      assert!(serde_json::from_str::<IssueCode>(&format!("\"{invalid}\"")).is_err());
    }
  }

  #[test]
  fn opaque_identifiers_require_lowercase_hex_digests() {
    let digest = "a".repeat(64);
    assert!(ProfileId::from_str(&digest).is_ok());
    assert!(InstallationId::from_str(&digest).is_ok());
    for invalid in ["a".repeat(63), "A".repeat(64), "g".repeat(64)] {
      assert!(ProfileId::from_str(&invalid).is_err());
    }
  }

  #[test]
  fn counters_saturate_at_u32_max_and_propagate_through_aggregates() {
    let stats = CounterSet {
      rows_seen: u64::from(u32::MAX) + 1,
      cookies_emitted: 3,
      rows_skipped: 0,
      acquisition_attempts: 1,
    }
    .into_stats();
    assert_eq!(stats.rows_seen, u32::MAX);
    assert_eq!(stats.cookies_emitted, 3);
    assert!(stats.counters_saturated);

    let mut accumulator = StatsAccumulator::default();
    accumulator.add(&stats);
    accumulator.add(&ExtractionStats {
      rows_seen: 10,
      ..ExtractionStats::default()
    });
    let aggregate = accumulator.into_stats();
    assert_eq!(aggregate.rows_seen, u32::MAX);
    assert_eq!(aggregate.cookies_emitted, 3);
    assert!(aggregate.counters_saturated);
  }

  #[test]
  fn aggregated_issues_bound_samples_and_keep_the_highest_severity() {
    let mut issues = Vec::new();
    for index in 0..MAX_ISSUE_SAMPLES + 4 {
      push_aggregated(
        &mut issues,
        issue(
          "decrypt_failed",
          ExtractionStageCode::decrypt(),
          IssueSeverityCode::warning(),
          "warning",
        )
        .with_samples(vec![format!("row {index}")]),
      );
    }
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].occurrences, MAX_ISSUE_SAMPLES as u32 + 4);
    assert_eq!(issues[0].samples.len(), MAX_ISSUE_SAMPLES);
    assert_eq!(issues[0].severity, IssueSeverityCode::warning());

    push_aggregated(
      &mut issues,
      issue(
        "decrypt_failed",
        ExtractionStageCode::decrypt(),
        IssueSeverityCode::error(),
        "escalated",
      ),
    );
    assert_eq!(issues[0].severity, IssueSeverityCode::error());
    assert_eq!(issues[0].message, "escalated");
  }

  #[test]
  fn source_outcomes_sort_persistent_before_session_then_by_precedence() {
    let mut sources = vec![
      source(CookieSourceRoleId::session(), 20),
      source(CookieSourceRoleId::persistent(), 20),
      source(CookieSourceRoleId::session(), 10),
      source(CookieSourceRoleId::known("future_role"), 1),
      source(CookieSourceRoleId::persistent(), 10),
    ];
    sort_source_outcomes(&mut sources);
    let order = sources
      .iter()
      .map(|source| (source.source.role.to_string(), source.source.precedence))
      .collect::<Vec<_>>();
    assert_eq!(
      order,
      vec![
        ("persistent".to_owned(), 10),
        ("persistent".to_owned(), 20),
        ("session".to_owned(), 10),
        ("session".to_owned(), 20),
        ("future_role".to_owned(), 1),
      ]
    );
  }

  fn source(role: CookieSourceRoleId, precedence: u16) -> SourceExtractionOutcome {
    SourceExtractionOutcome::new(
      CookieSourceIdentity {
        role,
        format: CookieSourceFormatId::known("chromium_sqlite"),
        path: "/tmp/source".to_owned(),
        path_lossy: false,
        precedence,
      },
      true,
      AcquisitionStrategyCode::live_read_only(),
    )
  }
}
