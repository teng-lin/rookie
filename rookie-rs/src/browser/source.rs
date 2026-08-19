//! Cookie-source leaf types, shared by every engine.
//!
//! One extraction pipeline was described with four vocabularies, so each stage
//! grew its own bag and its neighbour translated. These are the two types that
//! replace that: a [`SourceCandidate`] is something discovery found on disk,
//! and a [`Source`] is what came back from reading it. Neither can stand in for
//! the other, which is the point -- a listing cannot hold records because the
//! field does not exist, and rustc says so rather than a reviewer.
//!
//! This module owns cookie-source leaves only. Profile identity, listing bags,
//! and extract bags stay in `registry.rs`: putting them here would couple these
//! leaves to catalog and discovery, or fork `DiscoveryIssue`.

use super::cookie_record::CookieRecord;
use super::report_core::{
  CookieSourceFormatId, CookieSourceRoleId, ExtractionStageCode, IssueSeverityCode,
};
use crate::common::sqlite::DatabaseAcquisitionStrategy;
use std::path::PathBuf;

/// Inventory: a cookie source that may exist on disk.
///
/// Must not carry cookies, records, stats, or issues. It is what listing
/// reports and what extract consumes; the values on it are decided before
/// anything is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceCandidate {
  pub(crate) path: PathBuf,
  pub(crate) role: CookieSourceRoleId,
  pub(crate) format: CookieSourceFormatId,
  pub(crate) precedence: u16,
  /// Chromium listing skips `!exists`. Gecko/Safari/IE planted candidates
  /// freeze `exists: true`: being listed at all already meant discovery found
  /// the path.
  pub(crate) exists: bool,
  pub(crate) selected: bool,
  /// Listing metadata, frozen per engine. Not "how the cookie DB was opened" --
  /// that is [`Source::acquisition`], and only exists after a query returns.
  pub(crate) acquisition: SourceAcquisition,
}

/// How a source was made readable.
///
/// Non-SQLite engines never acquire through the browser-database layer, so
/// their strategies are separate variants rather than an absent
/// [`DatabaseAcquisitionStrategy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceAcquisition {
  Database(DatabaseAcquisitionStrategy),
  StableFileImage,
  /// Overlaid by the Internet Explorer adapter once a WebCache query has been
  /// attempted. IE only compiles on Windows (and under `cfg(test)`), so a
  /// build for any other target sees this variant unconstructed -- a platform
  /// gate, not dead code.
  ///
  /// The allow is unconditional on purpose: expressing "unused off Windows"
  /// would put a platform `cfg` in this module, and these leaf types are
  /// deliberately target-agnostic (#218).
  #[allow(dead_code)]
  EseDatabase,
  NotAttempted,
}

impl From<Option<DatabaseAcquisitionStrategy>> for SourceAcquisition {
  fn from(strategy: Option<DatabaseAcquisitionStrategy>) -> Self {
    strategy.map_or(Self::NotAttempted, Self::Database)
  }
}

/// The stage at which a source failed, mapped onto the frozen report
/// vocabulary.
///
/// The report's `stage` is a frozen field, so flattening a parse or query
/// failure into `acquisition` would misdescribe it and rob consumers of the
/// signal they need to choose a remedy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum SourceFailureStage {
  #[default]
  Acquisition,
  Parse,
  Query,
}

/// The source could not be acquired, parsed, or queried.
///
/// Pairing the stage with the message makes a stage without a failure
/// unrepresentable, which the previous `error` + `error_stage` sibling fields
/// allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceFailure {
  pub(crate) stage: SourceFailureStage,
  pub(crate) message: String,
}

/// Row accounting for one source.
///
/// Copied into `ExtractionStats` as-is. `cookies_emitted` is set by whoever
/// built the records and is never recomputed downstream from a cookie list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SourceStats {
  pub(crate) rows_seen: usize,
  pub(crate) cookies_emitted: usize,
  pub(crate) rows_skipped: usize,
  pub(crate) rows_rejected: usize,
  pub(crate) provider_failures: usize,
}

/// Crate-private issue attached to a source by the engine or adapter that
/// found it.
///
/// Not `report_core::ExtractionIssue`: this is the pre-report shape, so the
/// report mapper only copies rather than re-deriving anything from counters.
/// The provider/tier/cause/retryability fields exist for Chromium's row issues,
/// which carry evidence the other engines have no equivalent of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceIssue {
  pub(crate) code: &'static str,
  pub(crate) stage: ExtractionStageCode,
  pub(crate) severity: IssueSeverityCode,
  pub(crate) message: String,
  pub(crate) occurrences: u32,
  pub(crate) samples: Vec<String>,
  pub(crate) provider: Option<String>,
  pub(crate) tier: Option<String>,
  pub(crate) cause: Option<String>,
  pub(crate) retryability: Option<String>,
}

impl SourceIssue {
  pub(crate) fn new(
    code: &'static str,
    stage: ExtractionStageCode,
    severity: IssueSeverityCode,
    message: impl Into<String>,
  ) -> Self {
    Self {
      code,
      stage,
      severity,
      message: message.into(),
      occurrences: 1,
      samples: Vec::new(),
      provider: None,
      tier: None,
      cause: None,
      retryability: None,
    }
  }

  pub(crate) fn with_occurrences(mut self, occurrences: u32) -> Self {
    self.occurrences = occurrences;
    self
  }
}

/// Post-unseal source work.
///
/// No `profile_id`, no `installation_id`, no `display_name`: report identity
/// belongs to the profile that owns this source, and inventing it here is what
/// the direct-path helpers used to do. No `cookies` field either -- records are
/// the only supply of finalized rows.
#[derive(Debug)]
pub(crate) struct Source {
  /// The candidate this result came from. Path, role, format and precedence
  /// are read through here so they cannot drift from what discovery found.
  pub(crate) origin: SourceCandidate,
  /// Effective values, which extract may overwrite: Gecko selects its
  /// persistent source at populate, and Internet Explorer overlays
  /// `EseDatabase` once a query has been attempted. The frozen listing values
  /// stay readable on `origin`.
  pub(crate) selected: bool,
  pub(crate) acquisition: SourceAcquisition,
  pub(crate) records: Vec<CookieRecord>,
  pub(crate) stats: SourceStats,
  pub(crate) acquisition_attempts: u32,
  /// Acquisition retry notes, reported as `source_read_retried`.
  pub(crate) diagnostics: Vec<String>,
  pub(crate) failure: Option<SourceFailure>,
  pub(crate) issues: Vec<SourceIssue>,
}

impl Source {
  /// A source whose query has been attempted but which carries no rows yet.
  ///
  /// Callers fill in what the query returned. `acquisition` starts from the
  /// candidate so an engine that does not overlay one keeps the frozen value.
  /// The candidate-driven engines (Safari/IE) build their `Source`s this way;
  /// Gecko's path/query populate builds `Source` directly. Safari compiles only
  /// on macOS and IE only on Windows, so a Linux build has neither caller -- a
  /// platform gate, not dead code.
  ///
  /// Unconditional allow for the same reason as `SourceAcquisition::EseDatabase`:
  /// naming the targets here would put a platform `cfg` in a module that is
  /// deliberately target-agnostic (#218).
  #[allow(dead_code)]
  pub(crate) fn from_candidate(origin: SourceCandidate) -> Self {
    let selected = origin.selected;
    let acquisition = origin.acquisition;
    Self {
      origin,
      selected,
      acquisition,
      records: Vec::new(),
      stats: SourceStats::default(),
      acquisition_attempts: 0,
      diagnostics: Vec::new(),
      failure: None,
      issues: Vec::new(),
    }
  }

  /// Compatibility cookies projected from `records`.
  ///
  /// `Source` has no `cookies` field -- records are the only supply of
  /// finalized rows. Characterization tests that assert on cookie contents use
  /// this instead, mapping each convertible record.
  #[cfg(test)]
  pub(crate) fn cookies(&self) -> Vec<crate::common::enums::Cookie> {
    self
      .records
      .iter()
      .cloned()
      .filter_map(|record| record.into_cookie().ok())
      .collect()
  }

  pub(crate) fn fail(&mut self, stage: SourceFailureStage, message: impl Into<String>) {
    self.failure = Some(SourceFailure {
      stage,
      message: message.into(),
    });
  }

  /// Attach the `row_read_failed` issue for rows that were seen and dropped.
  ///
  /// Keyed on the count, not on whether the engine kept an error string:
  /// Safari and Internet Explorer report skipped rows without one, and
  /// deriving the issue from the error alone let a report claim `complete`
  /// while cookies had been dropped. Producing it here keeps the report mapper
  /// a pure copy instead of a second place that reasons about counters.
  pub(crate) fn push_row_read_failed(&mut self, row_error: Option<String>) {
    let skipped = self.stats.rows_skipped;
    if skipped == 0 {
      return;
    }
    self.issues.push(
      SourceIssue::new(
        "row_read_failed",
        ExtractionStageCode::parse(),
        IssueSeverityCode::error(),
        row_error.unwrap_or_else(|| format!("{skipped} row(s) could not be read")),
      )
      .with_occurrences(u32::try_from(skipped).unwrap_or(u32::MAX)),
    );
  }
}
