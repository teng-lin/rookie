//! Crate-private shared state for the public request types.
//!
//! Five request types each carried their own browser id, profile selector,
//! timeout, and cancellation handle, so adding a session policy and an
//! App-Bound policy would have written the same fields a sixth and seventh
//! time. This is the half that every browser job shares; `ExecutionControl` is
//! the half every I/O job shares.
//!
//! It is **not** exported. Rust has no delegation, so each public type still
//! spells out one-line forwarding methods -- that repetition is the price of
//! keeping the shared state in one place, and it is mechanical rather than
//! load-bearing.

use crate::selection::{ProfileSelection, ReportScope};
use crate::{RequestError, SessionPolicy};

/// One browser job's selection state, generic over how wide the selection may
/// be.
///
/// The type parameter is what makes `ProfileSelection::All` unrepresentable:
/// snapshot and flat-extract jobs instantiate it with [`ProfileSelection`],
/// which has no "every profile" arm, while report jobs instantiate it with
/// [`ReportScope`], which does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BrowserTarget<S> {
  /// Empty means the caller never named a browser. It is rejected at job time
  /// rather than in the builder, so a request value is always constructible
  /// and the error arrives with the rest of the job's validation.
  browser_id: String,
  selection: S,
  session: SessionPolicy,
}

impl<S: Default> BrowserTarget<S> {
  pub(crate) fn browser(id: impl Into<String>) -> Self {
    Self {
      browser_id: id.into(),
      selection: S::default(),
      session: SessionPolicy::default(),
    }
  }
}

impl<S> BrowserTarget<S> {
  #[cfg(test)]
  pub(crate) fn browser_id(&self) -> &str {
    &self.browser_id
  }

  pub(crate) fn selection(&self) -> &S {
    &self.selection
  }

  pub(crate) fn session(&self) -> SessionPolicy {
    self.session
  }

  pub(crate) fn with_selection(mut self, selection: S) -> Self {
    self.selection = selection;
    self
  }

  pub(crate) fn with_session(mut self, session: SessionPolicy) -> Self {
    self.session = session;
    self
  }

  /// The one place an empty browser id becomes an error, shared by every
  /// browser job so they cannot disagree about it.
  pub(crate) fn resolve(&self) -> Result<&str, RequestError> {
    if self.browser_id.is_empty() {
      return Err(RequestError::MissingBrowser);
    }
    Ok(&self.browser_id)
  }
}

impl BrowserTarget<ProfileSelection> {
  pub(crate) fn profile(self, query: impl Into<String>) -> Self {
    self.with_selection(ProfileSelection::Query(query.into()))
  }

  /// Narrows a single-profile target into a report scope.
  ///
  /// Scope only ever narrows here, never widens: an `ExtractRequest` that
  /// meant "the first legacy-eligible profile" becomes a report of that same
  /// profile, not of every profile.
  pub(crate) fn into_report_scope(self) -> BrowserTarget<ReportScope> {
    BrowserTarget {
      selection: ReportScope::One(self.selection),
      browser_id: self.browser_id,
      session: self.session,
    }
  }
}

impl BrowserTarget<ReportScope> {
  pub(crate) fn profile(self, query: impl Into<String>) -> Self {
    self.with_selection(ReportScope::One(ProfileSelection::Query(query.into())))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn an_empty_browser_id_is_one_shared_request_error() {
    let target = BrowserTarget::<ProfileSelection>::browser("");
    assert_eq!(target.resolve(), Err(RequestError::MissingBrowser));
    assert_eq!(
      BrowserTarget::<ReportScope>::browser("").resolve(),
      Err(RequestError::MissingBrowser)
    );
    assert_eq!(
      BrowserTarget::<ProfileSelection>::browser("chrome").resolve(),
      Ok("chrome")
    );
  }

  #[test]
  fn narrowing_to_a_report_scope_carries_the_profile_and_the_session_policy() {
    let target = BrowserTarget::<ProfileSelection>::browser("firefox")
      .profile("Default")
      .with_session(SessionPolicy::IncludeSession);
    let scope = target.into_report_scope();
    assert_eq!(scope.browser_id(), "firefox");
    assert_eq!(scope.session(), SessionPolicy::IncludeSession);
    assert_eq!(
      scope.selection(),
      &ReportScope::One(ProfileSelection::Query("Default".to_owned()))
    );
  }

  #[test]
  fn a_legacy_first_target_narrows_to_one_profile_not_to_all() {
    // The load-bearing direction. Widening here would turn
    // `ReportRequest::from(ExtractRequest::browser("chrome"))` into a report of
    // every profile, silently changing what the caller asked for.
    let scope = BrowserTarget::<ProfileSelection>::browser("chrome").into_report_scope();
    assert_eq!(
      scope.selection(),
      &ReportScope::One(ProfileSelection::LegacyFirst)
    );
  }
}
