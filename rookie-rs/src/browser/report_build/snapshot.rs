//! The snapshot seam: one browser profile's cookies, without a report.
//!
//! 0.6-beta routed a profile-scoped `read` through the report builder and then
//! flattened the DTO back into cookies. That route cannot work: the report's
//! `SourceExtraction.cookies` is `Vec<Cookie>` because the DTO is frozen at
//! `schema_version: 1`, so a snapshot taken through it has **already** lost
//! `CookieContext`. `header()` would then see no isolated cookies, never raise
//! `IncompleteSendContext`, and merge partitions -- on the exact path the
//! migration guide recommends.
//!
//! This seam stops at [`FinalizedCookieRecord`] and projects
//! `DetailedCookie` for both single-profile selections. It also makes the
//! shared-deadline rule structural rather than a rule to remember: there is no
//! second request to build, so there is no second budget to reset.
//!
//! It lives under `report_build` because collection and finalization live
//! there, not because it produces a report. It never builds one.

use super::{collect_extraction, finalize_outcomes_with_runtime};
use crate::browser::cookie_record::LegacyProjectionSemantics;
use crate::browser::legacy;
use crate::browser::outcome::Termination;
use crate::browser::registry;
use crate::common::deadline::BoundaryRuntime;
use crate::common::enums::DetailedCookie;
use crate::read_warning::ReadWarningCounts;
use anyhow::Result;

/// Which single profile a snapshot reads.
///
/// There is deliberately no `AllProfiles` arm. A snapshot returns one
/// `ReadResult` with one `profile_id`, so "every profile" is not a shape it
/// can express -- and making that a type fact removes the runtime error the
/// 0.6-beta surface needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SnapshotSelection<'a> {
  /// The first legacy-eligible profile, matching the named v0.5.9 helpers.
  LegacyFirst,
  /// One already-resolved opaque profile ID.
  Profile(&'a str),
}

/// What one snapshot produced, before the job layer filters and projects it.
pub(crate) struct SnapshotOutcome {
  pub(crate) cookies: Vec<DetailedCookie>,
  pub(crate) warnings: ReadWarningCounts,
  pub(crate) profile_id: Option<String>,
  /// The typed termination. The job layer turns a non-`Completed` value into
  /// `Error::Stopped`; nothing here parses a string to decide that.
  pub(crate) termination: Termination,
}

/// Reads one profile's cookies with isolation intact.
///
/// `session` is the acquire-time source filter: under
/// [`SessionPolicy::PersistentOnly`](crate::SessionPolicy::PersistentOnly) the
/// session-role candidates are dropped before lookup, so the crate opens no
/// session store at all. That is why it is a parameter here rather than a
/// filter applied to the returned cookies -- a post-projection filter would
/// still have read the files the caller asked it not to touch.
pub(crate) fn browser_snapshot_with_runtime(
  browser_id: &str,
  selection: SnapshotSelection<'_>,
  session: crate::SessionPolicy,
  runtime: &BoundaryRuntime<'_>,
) -> Result<SnapshotOutcome> {
  runtime.check()?;
  match selection {
    SnapshotSelection::LegacyFirst => {
      // The legacy-first route already projects records, not a report. It
      // never had the defect; it only needed its richer projection to survive
      // the job boundary.
      // `LegacyFirst` never plants a session candidate: the compatibility
      // selector requires a persistent source, so `session` cannot change what
      // it acquires. The parameter is still taken so callers do not have to
      // know that, and so the seam is one function rather than two.
      let _ = session;
      let (cookies, warnings) =
        legacy::browser_detailed_and_warnings_with_runtime(browser_id, None, runtime)?;
      Ok(SnapshotOutcome {
        cookies,
        warnings,
        profile_id: None,
        termination: Termination::Completed,
      })
    }
    SnapshotSelection::Profile(profile_id) => {
      profile_snapshot_with_runtime(browser_id, profile_id, session, runtime)
    }
  }
}

fn profile_snapshot_with_runtime(
  browser_id: &str,
  profile_id: &str,
  session: crate::SessionPolicy,
  runtime: &BoundaryRuntime<'_>,
) -> Result<SnapshotOutcome> {
  let browser = registry::resolve_registered_browser(browser_id)?;
  // No domain filter: a domain-reduced snapshot makes `header()` silently
  // wrong, because it omits parent-domain cookies the browser would send.
  // `ReadRequest` has no `domains` for exactly this reason.
  let draft = collect_extraction(&browser, Some(profile_id), None, session, runtime)?;
  let warnings = draft_warnings(&draft);
  let outcome = finalize_outcomes_with_runtime(1, vec![draft], Some(runtime));
  let termination = outcome.termination;

  let mut cookies = Vec::new();
  for source in outcome.sources {
    if !source.selected || source.failed {
      continue;
    }
    if source.profile.profile_id.as_str() != profile_id {
      continue;
    }
    let semantics = LegacyProjectionSemantics::for_source_format(source.source.format.as_str());
    for record in source.records {
      cookies.push(record.into_detailed_cookie_with_semantics(semantics));
    }
  }

  Ok(SnapshotOutcome {
    cookies,
    warnings,
    profile_id: Some(profile_id.to_owned()),
    termination,
  })
}

/// Aggregates the same row-loss diagnostics `read` used to harvest from the
/// report DTO, read from the draft instead so no report is built.
fn draft_warnings(draft: &super::BrowserDraft) -> ReadWarningCounts {
  let mut warnings = ReadWarningCounts::default();
  for issue in &draft.issues {
    warnings.record_issue(issue.code.as_str(), u64::from(issue.occurrences));
  }
  for profile in &draft.profiles {
    for issue in &profile.issues {
      warnings.record_issue(issue.code.as_str(), u64::from(issue.occurrences));
    }
    for source in &profile.sources {
      for issue in &source.issues {
        warnings.record_issue(issue.code.as_str(), u64::from(issue.occurrences));
      }
    }
  }
  warnings
}
