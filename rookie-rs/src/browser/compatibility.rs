//! Legacy `Cookie[]` compatibility policy.
//!
//! `outcome.rs` owns the finalized canonical extraction and the
//! [`CompatibilityDisposition`] / [`CompatibilityDecision`] vocabulary any
//! projection of it answers in -- exactly as it owns `Termination` and
//! `ResultStatus` without owning the report that renders them. This module
//! owns one projection: which browser families exist, which source-set rule
//! each takes, and which product string each emits. That is the half that
//! changes when a browser is added, so it does not live beside the result it
//! projects.

use super::outcome::{
  CompatibilityAbsence, CompatibilityDecision, CompatibilityDisposition, Diagnostic, Failure,
  FailureScope, Outcome, SourceOutcome,
};
use super::registry;
use super::report_core::{BrowserId, IssueSeverityCode, MAX_ISSUE_SAMPLES};
use super::source::SourceIssue;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompatibilityFamily {
  Chromium,
  Gecko,
  Safari,
  InternetExplorer,
}

pub(crate) fn engine_compatibility_family(browser_id: &BrowserId) -> CompatibilityFamily {
  match browser_id.as_str() {
    "safari" => CompatibilityFamily::Safari,
    "internet_explorer" => CompatibilityFamily::InternetExplorer,
    // Only the direct path reaches this arm: registry Chromium browsers are
    // adapted by `chromium_browser_outcome`, which names the family itself.
    // Without it a direct-path Chromium read would be dispositioned as Gecko.
    "chromium" => CompatibilityFamily::Chromium,
    _ => CompatibilityFamily::Gecko,
  }
}

pub(crate) fn compatibility_decision(
  outcome: &Outcome,
  compatibility_evidence: &BTreeMap<[u8; 32], Diagnostic>,
  browser_id: BrowserId,
  family: CompatibilityFamily,
) -> CompatibilityDecision {
  let disposition = compatibility_disposition(outcome, compatibility_evidence, &browser_id, family);
  CompatibilityDecision {
    browser_id,
    disposition,
  }
}

fn compatibility_disposition(
  outcome: &Outcome,
  compatibility_evidence: &BTreeMap<[u8; 32], Diagnostic>,
  browser_id: &BrowserId,
  family: CompatibilityFamily,
) -> CompatibilityDisposition {
  let Some((profile, _)) = outcome
    .profiles
    .iter()
    .find(|(profile, _)| &profile.browser_id == browser_id)
  else {
    let failures = outcome
      .failure_ledger
      .as_slice()
      .iter()
      .filter(|failure| {
        failure_browser_id(failure) == Some(browser_id)
          && !registry::is_informational_discovery_issue(failure.code.as_str())
      })
      .collect::<Vec<_>>();
    if family == CompatibilityFamily::Chromium {
      let diagnostics = failures
        .iter()
        .map(|failure| failure.diagnostic.as_str())
        .take(MAX_ISSUE_SAMPLES)
        .collect::<Vec<_>>()
        .join("; ");
      if failures
        .iter()
        .any(|failure| failure.code.as_str().starts_with("profile_"))
      {
        return CompatibilityDisposition::Failed(Diagnostic::new_with_secrets(
          format!(
            "every discovered {} profile failed discovery: {diagnostics}",
            browser_id.as_str()
          ),
          &[],
        ));
      }
      // A detected root with no selected compatibility profile is ordinary
      // source absence unless discovery recorded a real failure. In
      // particular, an informational profile issue or a legacy-layout miss
      // must not be relabeled as failed enumeration with an empty diagnostic.
      if outcome.counters.browsers_detected > 0 && !failures.is_empty() {
        return CompatibilityDisposition::Failed(Diagnostic::new_with_secrets(
          format!(
            "every detected {} installation failed profile enumeration: {diagnostics}",
            browser_id.as_str()
          ),
          &[],
        ));
      }
    }
    if let Some(failure) = failures.first() {
      return CompatibilityDisposition::Failed(failure.diagnostic.clone());
    }
    return CompatibilityDisposition::Absent(CompatibilityAbsence::CookieDatabase);
  };

  let sources = outcome.sources.iter().filter(|source| {
    source.profile.browser_id == profile.browser_id
      && source.profile.installation_id == profile.installation_id
      && source.profile.profile_id == profile.profile_id
  });
  let mut persistent = None;
  let mut sessions = Vec::new();
  for source in sources {
    match source.source.role.as_str() {
      registry::SOURCE_ROLE_PERSISTENT if source.selected && persistent.is_none() => {
        persistent = Some(source)
      }
      registry::SOURCE_ROLE_SESSION => sessions.push(source),
      _ => {}
    }
  }

  let source_failure = |source: &SourceOutcome| {
    if !source.failed {
      return None;
    }
    outcome.failure_ledger.as_slice().iter().find(|failure| {
      matches!(
        &failure.scope,
        FailureScope::Source { source_digest, .. }
          if source_digest == &source.source_digest()
      ) && failure.severity == IssueSeverityCode::error()
    })
  };
  let all_rows_failure = |source: &SourceOutcome| {
    if !source.records.is_empty() || source.stats.rows_skipped == 0 {
      return None;
    }
    let scoped = |failure: &&Failure| {
      matches!(
        &failure.scope,
        FailureScope::Source { source_digest, .. }
          if source_digest == &source.source_digest()
      )
    };
    outcome
      .failure_ledger
      .as_slice()
      .iter()
      .filter(scoped)
      .find(|failure| failure.code.as_str() == "all_rows_rejected")
      .or_else(|| {
        outcome
          .failure_ledger
          .as_slice()
          .iter()
          .filter(scoped)
          .find(|failure| {
            matches!(
              failure.code.as_str(),
              "row_read_failed" | "column_read_failed" | "decode_failed" | "decrypt_failed"
            )
          })
      })
  };
  let all_rows_diagnostic = |source: &SourceOutcome, fallback: &str| {
    if let Some(diagnostic) = compatibility_evidence.get(&source.source_digest()) {
      return Some(diagnostic.clone());
    }
    all_rows_failure(source).map(|failure| {
      if failure.diagnostic.as_str()
        == SourceIssue::generic_row_read_failed_message(source.stats.rows_skipped as usize)
      {
        Diagnostic::new_with_secrets(fallback, &[])
      } else {
        failure.diagnostic.clone()
      }
    })
  };
  let failed =
    |source: &SourceOutcome| source_failure(source).map(|failure| failure.diagnostic.clone());

  match family {
    CompatibilityFamily::Chromium => {
      let Some(source) = persistent else {
        return CompatibilityDisposition::Absent(CompatibilityAbsence::CookieDatabase);
      };
      if let Some(diagnostic) =
        all_rows_diagnostic(source, "all Chromium cookie rows failed to decode")
      {
        return CompatibilityDisposition::Failed(diagnostic);
      }
      if let Some(failure) = source_failure(source) {
        return CompatibilityDisposition::Failed(failure.diagnostic.clone());
      }
      CompatibilityDisposition::Emit {
        source_digests: vec![source.source_digest()],
      }
    }
    CompatibilityFamily::Gecko => {
      let mut selected = Vec::new();
      let mut deferred = None;
      let mut persistent_succeeded = false;
      let mut persistent_has_records = false;
      if let Some(source) = persistent {
        if let Some(diagnostic) =
          all_rows_diagnostic(source, "all Firefox cookie database rows failed to decode")
        {
          deferred = Some(diagnostic);
        } else if let Some(failure) = source_failure(source) {
          deferred = Some(failure.diagnostic.clone());
        } else {
          persistent_succeeded = true;
          persistent_has_records = !source.records.is_empty();
          selected.push(source.source_digest());
        }
      }

      let mut session_failures = Vec::new();
      let mut session_succeeded = false;
      for source in sessions {
        if let Some(diagnostic) = failed(source) {
          session_failures.push(diagnostic);
        } else {
          session_succeeded = true;
          selected.push(source.source_digest());
        }
      }
      // A successfully decoded session candidate is authoritative even when
      // it contains zero cookies, and therefore rescues a failed persistent
      // source without inventing another candidate.
      if session_succeeded || persistent_has_records {
        return CompatibilityDisposition::Emit {
          source_digests: selected,
        };
      }
      if !session_failures.is_empty() {
        let details = session_failures
          .iter()
          .map(Diagnostic::as_str)
          .collect::<Vec<_>>()
          .join("; ");
        return CompatibilityDisposition::Failed(Diagnostic::new_with_secrets(
          format!("all existing Firefox session store candidates failed: {details}"),
          &[],
        ));
      }
      if let Some(diagnostic) = deferred {
        CompatibilityDisposition::Failed(diagnostic)
      } else {
        debug_assert!(persistent_succeeded || selected.is_empty());
        CompatibilityDisposition::Emit {
          source_digests: selected,
        }
      }
    }
    CompatibilityFamily::Safari => {
      let Some(source) = persistent else {
        return CompatibilityDisposition::Absent(CompatibilityAbsence::CookieDatabase);
      };
      if source.records.is_empty() {
        if let Some(failure) = source_failure(source) {
          return CompatibilityDisposition::Failed(failure.diagnostic.clone());
        }
      }
      CompatibilityDisposition::Emit {
        source_digests: vec![source.source_digest()],
      }
    }
    CompatibilityFamily::InternetExplorer => {
      let Some(source) = persistent else {
        return CompatibilityDisposition::Absent(CompatibilityAbsence::CookieDatabase);
      };
      if let Some(diagnostic) = all_rows_diagnostic(
        source,
        "all Internet Explorer WebCache records failed to decode",
      ) {
        return CompatibilityDisposition::Failed(diagnostic);
      }
      if let Some(failure) = source_failure(source) {
        return CompatibilityDisposition::Failed(failure.diagnostic.clone());
      }
      CompatibilityDisposition::Emit {
        source_digests: vec![source.source_digest()],
      }
    }
  }
}

fn failure_browser_id(failure: &Failure) -> Option<&BrowserId> {
  match &failure.scope {
    FailureScope::Request => None,
    FailureScope::Browser { browser_id }
    | FailureScope::Profile { browser_id, .. }
    | FailureScope::Source { browser_id, .. } => Some(browser_id),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::browser::outcome::{FailureLedger, Termination};
  use crate::browser::report_core::{issue, ExtractionStageCode};

  fn empty_chromium_outcome(failures: FailureLedger) -> Outcome {
    let mut outcome = Outcome::finalize(
      Vec::new(),
      Vec::new(),
      failures,
      false,
      Termination::Completed,
    );
    outcome.counters.browsers_detected = 1;
    outcome
  }

  fn chromium_disposition(outcome: &Outcome) -> CompatibilityDisposition {
    compatibility_decision(
      outcome,
      &BTreeMap::new(),
      BrowserId::known("opera"),
      CompatibilityFamily::Chromium,
    )
    .disposition
  }

  #[test]
  fn detected_chromium_without_a_scoped_failure_is_source_absence() {
    assert_eq!(
      chromium_disposition(&empty_chromium_outcome(FailureLedger::default())),
      CompatibilityDisposition::Absent(CompatibilityAbsence::CookieDatabase)
    );

    let browser_id = BrowserId::known("opera");
    let mut informational = FailureLedger::default();
    informational.push(Failure::from_issue(
      issue(
        "profile_has_no_cookie_source",
        ExtractionStageCode::discovery(),
        IssueSeverityCode::info(),
        "profile marker has no Chromium cookie source",
      ),
      FailureScope::Browser { browser_id },
      &[],
    ));
    assert_eq!(
      chromium_disposition(&empty_chromium_outcome(informational)),
      CompatibilityDisposition::Absent(CompatibilityAbsence::CookieDatabase)
    );
  }

  #[test]
  fn actual_chromium_enumeration_failure_keeps_a_nonempty_diagnostic() {
    let browser_id = BrowserId::known("opera");
    let mut failures = FailureLedger::default();
    failures.push(Failure::from_issue(
      issue(
        "installation_enumeration_failed",
        ExtractionStageCode::discovery(),
        IssueSeverityCode::error(),
        "permission denied",
      ),
      FailureScope::Browser { browser_id },
      &[],
    ));

    let CompatibilityDisposition::Failed(diagnostic) =
      chromium_disposition(&empty_chromium_outcome(failures))
    else {
      panic!("a real enumeration failure must remain failed");
    };
    assert_eq!(
      diagnostic.as_str(),
      "every detected opera installation failed profile enumeration: permission denied"
    );
  }
}
