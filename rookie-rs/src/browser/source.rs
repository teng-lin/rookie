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

/// The join keys of one cookie source: what identifies it, independent of
/// stage.
///
/// Carried by a [`SourceCandidate`] through [`SourceCandidate::identity`] and
/// held by a [`Source`] as its `origin`, so a result's provenance cannot drift
/// from what discovery found. This is the only part of a candidate an
/// extraction result may carry: the listing fields (`selected`, `acquisition`,
/// `exists`) belong to the stage that decided them and have no meaning on a
/// result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceIdentity {
  pub(crate) path: PathBuf,
  pub(crate) role: CookieSourceRoleId,
  pub(crate) format: CookieSourceFormatId,
  pub(crate) precedence: u16,
}

/// How a candidate is to be acquired: the rule the executor follows when it
/// reaches this entry in a profile's plan.
///
/// This is the one place the four engines genuinely disagree, and the whole
/// point of the type is that the disagreement is now a *value on the
/// candidate* rather than a control-flow fork in whichever file happened to
/// own that engine's walk. Deciding it at plant time also keeps the divergent
/// listing bytes each engine has always emitted: Chromium omits a `!exists`
/// entry from the plan altogether, while Gecko plants its persistent entry
/// with `Probe` — same mechanism, different plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcquisitionPolicy {
  /// Acquire exactly this candidate and keep whatever came back. Chromium,
  /// Safari, and Internet Explorer plant nothing else: their listing already
  /// decided the entry is real, so the read is unconditional and its outcome
  /// is the answer.
  Fixed,
  /// Acquire this candidate even if discovery planted nothing for it, and keep
  /// the resulting source only if the path exists — either because discovery
  /// vouched for it (`exists`) or because it is on disk at the moment of the
  /// recheck. Gecko's persistent `cookies.sqlite`.
  ///
  /// Both halves are load-bearing. Attempting regardless is how a database
  /// created between discovery and query is still read; rechecking existence
  /// *after* the read rather than inferring it from the read's success is how a
  /// database that appeared and was corrupt or locked is reported instead of
  /// silenced, and how one deleted since discovery still reports its failure
  /// instead of vanishing. Discovery's snapshot goes stale in both directions.
  ///
  /// The variant is unconstructed on no target — Gecko compiles everywhere —
  /// so it needs no platform allow.
  Probe,
  /// One entry of an ordered alternation: the executor acquires the run of
  /// `FirstValid` candidates in plan order and stops at the first success.
  /// Gecko's session stores, where `SESSION_CANDIDATES` order is frozen
  /// (ADR 0001 §8).
  ///
  /// A contiguous run in the plan is one group. The rule itself is not
  /// reimplemented here: the executor hands the run to
  /// `mozilla::select_session_sources`, which stays the single definition of
  /// first-valid shared with the direct-path walk.
  FirstValid,
}

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
  /// The acquisition rule for this entry, decided by whoever planted it. A
  /// listing decision like `selected` and `exists`, not a result: it says how
  /// the source will be read, never anything about the read.
  pub(crate) policy: AcquisitionPolicy,
}

impl SourceCandidate {
  /// The join keys, without the listing decisions.
  ///
  /// Fields stay flat on the candidate rather than nested behind this: the
  /// crate reads `candidate.path` / `role` / `format` / `precedence` in dozens
  /// of places, and nesting would rewrite every one of them plus every plant,
  /// for a layout preference with no semantic content.
  pub(crate) fn identity(&self) -> SourceIdentity {
    SourceIdentity {
      path: self.path.clone(),
      role: self.role.clone(),
      format: self.format.clone(),
      precedence: self.precedence,
    }
  }
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
  /// A source saw one or more rows it could not project into cookies.
  pub(crate) const ROW_READ_FAILED: &'static str = "row_read_failed";

  /// A row's required host identity did not survive decode (A7).
  ///
  /// Distinct from [`ROW_READ_FAILED`](Self::ROW_READ_FAILED): the row was
  /// read and decoded successfully, and it is the *result* that cannot be
  /// used. Folding the two together would tell a caller to retry something
  /// retrying cannot fix.
  pub(crate) const MALFORMED_HOST_IDENTITY: &'static str = "malformed_host_identity";

  /// Carries the legacy "every row was rejected" error without giving `Source`
  /// a sibling field for it.
  ///
  /// This is the one issue code that never reaches the wire: the report mapper
  /// lifts it into `CompatibilityEvidence::AllRowsRejected` instead of pushing
  /// it as an extraction issue. Section 5.7 does not treat a fully-rejected
  /// source as failed -- acquisition, parsing, and the query all completed --
  /// so the evidence exists only for the compatibility projection, which does.
  ///
  /// A `compatibility_evidence` field on [`Source`] would put a Chromium-only,
  /// legacy-only concern on the leaf every engine shares.
  pub(crate) const ALL_ROWS_REJECTED: &'static str = "all_rows_rejected";

  /// The evidence issue for [`Self::ALL_ROWS_REJECTED`].
  ///
  /// A constructor rather than two call sites spelling out the same stage and
  /// severity: the mapper matches on the code alone, so a disagreement here
  /// would be invisible until the values were ever read.
  pub(crate) fn all_rows_rejected(message: impl Into<String>) -> Self {
    Self::new(
      Self::ALL_ROWS_REJECTED,
      ExtractionStageCode::parse(),
      IssueSeverityCode::error(),
      message,
    )
  }

  /// The generic `row_read_failed` message a source with no detailed row
  /// error falls back to. The compatibility projection compares a
  /// diagnostic against this exact generator -- for that source's own skip
  /// count -- to decide whether to substitute the family fallback string, so
  /// this is the single producer both sides must agree on.
  pub(crate) fn generic_row_read_failed_message(skipped: usize) -> String {
    format!("{skipped} row(s) could not be read")
  }

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
  /// The identity of the candidate this result came from. Path, role, format
  /// and precedence are read through here so they cannot drift from what
  /// discovery found. It is deliberately not the whole candidate: a result has
  /// no business naming a listing `selected`, `acquisition`, or `exists`.
  pub(crate) origin: SourceIdentity,
  /// Effective values, stated by whoever built this source rather than
  /// inherited: Gecko selects its persistent source during acquisition, and Internet
  /// Explorer overlays `EseDatabase` once a query has been attempted. They are
  /// constructor arguments precisely so that an engine which forgets to state
  /// one gets a compile error instead of a silently wrong report field.
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
  /// Callers fill in what the query returned. The effective `selected` and
  /// `acquisition` are arguments rather than defaults inherited from a
  /// candidate: inheriting them is how an engine that forgot to overlay one
  /// used to emit a listing value as a result. A caller holding a candidate
  /// and wanting today's behaviour writes
  /// `Source::new(c.identity(), c.selected, c.acquisition)`, which says so.
  pub(crate) fn new(
    origin: SourceIdentity,
    selected: bool,
    acquisition: SourceAcquisition,
  ) -> Self {
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
        SourceIssue::ROW_READ_FAILED,
        ExtractionStageCode::parse(),
        IssueSeverityCode::error(),
        row_error.unwrap_or_else(|| SourceIssue::generic_row_read_failed_message(skipped)),
      )
      .with_occurrences(u32::try_from(skipped).unwrap_or(u32::MAX)),
    );
  }
}
