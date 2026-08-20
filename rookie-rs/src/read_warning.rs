//! Typed projection from engine/report row-loss diagnostics to read warnings.

use crate::browser::chromium::{CHROMIUM_UNSEAL_ISSUE_CODES, COLUMN_READ_FAILED};
use crate::browser::source::SourceIssue;

/// Stable warning categories exposed by the snapshot API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadWarningCode {
  DecryptFailed,
  RowReadFailed,
  InvalidOctets,
  MalformedHostIdentity,
  UnparsablePartitionKey,
}

impl ReadWarningCode {
  pub(crate) const fn as_str(self) -> &'static str {
    match self {
      Self::DecryptFailed => "decrypt_failed",
      Self::RowReadFailed => "row_read_failed",
      Self::InvalidOctets => "invalid_octets",
      Self::MalformedHostIdentity => "malformed_host_identity",
      Self::UnparsablePartitionKey => "unparsable_partition_key",
    }
  }

  fn from_issue_code(code: &str) -> Option<Self> {
    if CHROMIUM_UNSEAL_ISSUE_CODES.contains(&code) {
      return Some(Self::DecryptFailed);
    }
    // Chromium gives unread columns their own issue instead of attaching the
    // generic row issue used by the other engines. Both mean that a non-unseal
    // row was omitted from the snapshot.
    if code == COLUMN_READ_FAILED || code == SourceIssue::ROW_READ_FAILED {
      return Some(Self::RowReadFailed);
    }
    None
  }
}

/// Saturating warning fold shared by compatibility and report-backed reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ReadWarningCounts {
  decrypt_failed: u64,
  row_read_failed: u64,
  invalid_octets: u64,
  malformed_host_identity: u64,
  unparsable_partition_key: u64,
}

impl ReadWarningCounts {
  pub(crate) fn record_issue(&mut self, code: &str, occurrences: u64) {
    if let Some(code) = ReadWarningCode::from_issue_code(code) {
      self.record(code, occurrences);
    }
  }

  pub(crate) fn record(&mut self, code: ReadWarningCode, occurrences: u64) {
    let count = match code {
      ReadWarningCode::DecryptFailed => &mut self.decrypt_failed,
      ReadWarningCode::RowReadFailed => &mut self.row_read_failed,
      ReadWarningCode::InvalidOctets => &mut self.invalid_octets,
      ReadWarningCode::MalformedHostIdentity => &mut self.malformed_host_identity,
      ReadWarningCode::UnparsablePartitionKey => &mut self.unparsable_partition_key,
    };
    *count = count.saturating_add(occurrences);
  }

  pub(crate) fn into_entries(self) -> impl Iterator<Item = (ReadWarningCode, u64)> {
    [
      (ReadWarningCode::DecryptFailed, self.decrypt_failed),
      (ReadWarningCode::RowReadFailed, self.row_read_failed),
      (ReadWarningCode::InvalidOctets, self.invalid_octets),
      (
        ReadWarningCode::MalformedHostIdentity,
        self.malformed_host_identity,
      ),
      (
        ReadWarningCode::UnparsablePartitionKey,
        self.unparsable_partition_key,
      ),
    ]
    .into_iter()
    .filter(|(_, count)| *count > 0)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn every_chromium_unseal_issue_has_the_same_warning_projection() {
    for code in CHROMIUM_UNSEAL_ISSUE_CODES {
      let mut warnings = ReadWarningCounts::default();
      warnings.record_issue(code, 3);
      assert_eq!(
        warnings.into_entries().collect::<Vec<_>>(),
        vec![(ReadWarningCode::DecryptFailed, 3)],
        "unseal issue {code} must retain the compatibility warning"
      );
    }
  }

  #[test]
  fn gecko_and_chromium_non_unseal_row_failures_share_the_row_warning() {
    for code in [SourceIssue::ROW_READ_FAILED, COLUMN_READ_FAILED] {
      let mut warnings = ReadWarningCounts::default();
      warnings.record_issue(code, 2);
      assert_eq!(
        warnings.into_entries().collect::<Vec<_>>(),
        vec![(ReadWarningCode::RowReadFailed, 2)]
      );
    }
  }

  #[test]
  fn unrelated_report_issues_do_not_become_row_loss_warnings() {
    let mut warnings = ReadWarningCounts::default();
    warnings.record_issue("source_read_retried", 9);
    assert!(warnings.into_entries().next().is_none());
  }
}
