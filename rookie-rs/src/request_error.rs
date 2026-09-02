//! Structured, downcastable cause for a caller-fixable extract/report request.
//!
//! Carried inside the returned `anyhow::Error`. Human [`Display`] text is not
//! a stable contract; branch on [`RequestError::code`].

use std::fmt;

use crate::execution::AppBoundPolicy;

/// Structured request fault produced on the `resolve_registered_browser` path
/// and by the unified profile resolver.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
  UnknownBrowser {
    browser_id: String,
  },
  EmptyProfileSelector,
  UnknownProfile {
    browser_id: String,
    query: String,
  },
  AmbiguousProfile {
    browser_id: String,
    query: String,
    /// Opaque ids only, in generic `browser_profiles` order. Never paths.
    profile_ids: Vec<String>,
  },
  LossyProfilePath {
    browser_id: String,
    query: String,
  },
  MissingBrowser,
  /// Never stores the raw caller URL. `display` is a redacted form only.
  InvalidUrl {
    display: String,
  },
  /// A top-level site supplied to [`crate::SendContext`] was invalid.
  InvalidTopLevelSite {
    display: String,
  },
  /// The system clock could not be represented as Unix epoch seconds.
  ClockUnrepresentable,
  /// The snapshot contains isolated cookies but the send selector is absent.
  IncompleteSendContext {
    display: String,
    required: Vec<String>,
  },
  /// A flat projection was asked for a snapshot whose isolation it cannot hold.
  IsolationLossRefused {
    isolated_rows: u64,
    required: Vec<String>,
  },
  /// App-Bound recovery was requested but is unavailable in this build.
  AppBoundUnavailable {
    policy: AppBoundPolicy,
  },
  /// Bindings supplied more than one Chromium credential selector.
  ConflictingCredentialSelectors,
  /// Bindings supplied incompatible `profile` and `select` values.
  ConflictingProfileSelection,
}

impl RequestError {
  pub fn code(&self) -> &'static str {
    match self {
      Self::UnknownBrowser { .. } => "unknown_browser",
      Self::EmptyProfileSelector => "empty_profile_selector",
      Self::UnknownProfile { .. } => "unknown_profile",
      Self::AmbiguousProfile { .. } => "ambiguous_profile",
      Self::LossyProfilePath { .. } => "lossy_profile_path",
      Self::MissingBrowser => "missing_browser",
      Self::InvalidUrl { .. } => "invalid_url",
      Self::InvalidTopLevelSite { .. } => "invalid_top_level_site",
      Self::ClockUnrepresentable => "clock_unrepresentable",
      Self::IncompleteSendContext { .. } => "incomplete_send_context",
      Self::IsolationLossRefused { .. } => "isolation_loss_refused",
      Self::AppBoundUnavailable { .. } => "app_bound_unavailable",
      Self::ConflictingCredentialSelectors => "conflicting_credential_selectors",
      Self::ConflictingProfileSelection => "conflicting_profile_selection",
    }
  }

  pub fn kind(&self) -> &'static str {
    "request"
  }

  pub fn browser_id(&self) -> Option<&str> {
    match self {
      Self::UnknownBrowser { browser_id }
      | Self::UnknownProfile { browser_id, .. }
      | Self::AmbiguousProfile { browser_id, .. }
      | Self::LossyProfilePath { browser_id, .. } => Some(browser_id.as_str()),
      Self::EmptyProfileSelector
      | Self::MissingBrowser
      | Self::InvalidUrl { .. }
      | Self::InvalidTopLevelSite { .. }
      | Self::ClockUnrepresentable
      | Self::IncompleteSendContext { .. }
      | Self::IsolationLossRefused { .. }
      | Self::AppBoundUnavailable { .. }
      | Self::ConflictingCredentialSelectors
      | Self::ConflictingProfileSelection => None,
    }
  }

  pub fn profile_query(&self) -> Option<&str> {
    match self {
      Self::UnknownProfile { query, .. }
      | Self::AmbiguousProfile { query, .. }
      | Self::LossyProfilePath { query, .. } => Some(query.as_str()),
      _ => None,
    }
  }

  pub fn profile_ids(&self) -> &[String] {
    match self {
      Self::AmbiguousProfile { profile_ids, .. } => profile_ids,
      _ => &[],
    }
  }
}

impl fmt::Display for RequestError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::UnknownBrowser { browser_id } => {
        write!(formatter, "unknown browser id {browser_id:?}")
      }
      Self::EmptyProfileSelector => formatter.write_str("profile selector must not be empty"),
      Self::UnknownProfile { browser_id, query } => {
        write!(
          formatter,
          "no {browser_id} profile matches {query:?}"
        )
      }
      Self::AmbiguousProfile {
        browser_id,
        query,
        profile_ids,
      } => write!(
        formatter,
        "{count} {browser_id} profiles match {query:?}; select one by profile ID: {profile_ids:?}",
        count = profile_ids.len()
      ),
      Self::LossyProfilePath { browser_id, query } => write!(
        formatter,
        "{browser_id} profile path {query:?} is a lossy display value and cannot be used as a selector"
      ),
      Self::MissingBrowser => formatter.write_str("browser is required"),
      Self::InvalidUrl { display } => write!(formatter, "invalid url {display}"),
      Self::InvalidTopLevelSite { display } => {
        write!(formatter, "invalid top-level site {display}")
      }
      Self::ClockUnrepresentable => {
        formatter.write_str("system time cannot be represented as Unix epoch seconds")
      }
      Self::IncompleteSendContext { display, required } => write!(
        formatter,
        "send context for {display} is missing required selectors: {}",
        required.join(", ")
      ),
      Self::IsolationLossRefused {
        isolated_rows,
        required,
      } => write!(
        formatter,
        "snapshot holds {isolated_rows} isolated cookies; select a context with `send_view`/`header` (needs: {}) or opt in with `IsolationLoss::Allow`",
        required.join(", ")
      ),
      Self::AppBoundUnavailable { policy } => write!(
        formatter,
        "App-Bound policy {} is unavailable in this build",
        policy.as_str()
      ),
      Self::ConflictingCredentialSelectors => {
        formatter.write_str("Chromium credential selectors are mutually exclusive")
      }
      Self::ConflictingProfileSelection => {
        formatter.write_str("profile and select options conflict")
      }
    }
  }
}

impl std::error::Error for RequestError {}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn the_isolation_refusal_message_reads_as_one_sentence() {
    // A lost line-continuation backslash in the format literal is invisible in
    // the source and shows up as a run of spaces in the user's terminal.
    let message = RequestError::IsolationLossRefused {
      isolated_rows: 2,
      required: vec!["top_level_site".to_owned()],
    }
    .to_string();
    assert!(!message.contains("  "), "double space in {message:?}");
    assert!(message.contains("top_level_site"));
    assert!(message.contains("IsolationLoss::Allow"));
  }

  #[test]
  fn codes_are_stable_snake_case() {
    assert_eq!(
      RequestError::UnknownBrowser {
        browser_id: "x".into()
      }
      .code(),
      "unknown_browser"
    );
    assert_eq!(
      RequestError::EmptyProfileSelector.code(),
      "empty_profile_selector"
    );
    assert_eq!(RequestError::MissingBrowser.code(), "missing_browser");
    assert_eq!(
      RequestError::InvalidUrl {
        display: "https://example.com/".into()
      }
      .code(),
      "invalid_url"
    );
  }
}
