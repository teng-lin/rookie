//! Structured, downcastable cause for a caller-fixable extract/report request.
//!
//! Carried inside the returned `anyhow::Error`. Human [`Display`] text is not
//! a stable contract; branch on [`RequestError::code`].

use std::fmt;

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
      Self::EmptyProfileSelector | Self::MissingBrowser | Self::InvalidUrl { .. } => None,
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
    }
  }
}

impl std::error::Error for RequestError {}

#[cfg(test)]
mod tests {
  use super::*;

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
