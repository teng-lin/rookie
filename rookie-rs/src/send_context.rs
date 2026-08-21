//! View inputs for [`ReadResult::header`](crate::ReadResult::header).
//!
//! A URL alone cannot say which browsing context a request is made from, and
//! the 0.6-beta `header(url)` therefore had no way to tell a CHIPS-partitioned
//! cookie apart from an unpartitioned one, or a Firefox container cookie from
//! a default-container one. It merged them. `SendContext` is what a caller
//! supplies instead, and its absence is what makes
//! [`RequestError::IncompleteSendContext`](crate::RequestError::IncompleteSendContext)
//! raisable rather than a silent merge.
//!
//! Nothing here is ever applied to the stored snapshot. It is a view.

use crate::header_filter::redact_url;
use std::fmt;
use std::time::SystemTime;

/// Whether the request is a top-level navigation or a subresource load.
///
/// Only `SameSite=Lax` cross-site sends depend on this.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ResourceKind {
  /// A top-level navigation.
  Navigation,
  /// Any non-navigation load. The conservative default.
  #[default]
  Subresource,
}

/// Whether the request method is "safe" in the RFC 9110 sense.
///
/// Only `SameSite=Lax` cross-site sends depend on this.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MethodClass {
  /// GET, HEAD, OPTIONS, TRACE.
  #[default]
  Safe,
  /// Everything else.
  Unsafe,
}

/// The stable selector tokens [`RequestError::IncompleteSendContext`] names.
///
/// These are identifiers a caller can branch on, not prose, and they appear in
/// the order this table declares them.
///
/// [`RequestError::IncompleteSendContext`]: crate::RequestError::IncompleteSendContext
pub(crate) mod selector {
  pub(crate) const TOP_LEVEL_SITE: &str = "top_level_site";
  pub(crate) const USER_CONTEXT_ID: &str = "user_context_id";
  pub(crate) const PRIVATE_BROWSING_ID: &str = "private_browsing_id";
}

/// What a caller knows about the request a header is being built for.
///
/// `Debug` is hand-written and redacts `url` and `top_level_site`: a URL may
/// carry userinfo, and this is the type a caller is most likely to log.
#[derive(Clone, PartialEq, Eq)]
pub struct SendContext {
  pub(crate) url: String,
  pub(crate) top_level_site: Option<String>,
  pub(crate) resource: ResourceKind,
  pub(crate) method: MethodClass,
  pub(crate) user_context_id: Option<u32>,
  pub(crate) private_browsing_id: Option<u32>,
  pub(crate) now: Option<SystemTime>,
}

impl SendContext {
  /// The request URL. Only `http` and `https` are accepted, and the check
  /// happens in [`ReadResult::header`](crate::ReadResult::header), not here.
  pub fn url(url: impl Into<String>) -> Self {
    Self {
      url: url.into(),
      top_level_site: None,
      resource: ResourceKind::default(),
      method: MethodClass::default(),
      user_context_id: None,
      private_browsing_id: None,
      now: None,
    }
  }

  /// The top-level site the request is made from.
  ///
  /// Supplying this is what lets a partitioned cookie be matched instead of
  /// merged. A snapshot holding any partitioned cookie *demands* it.
  pub fn top_level_site(mut self, site: impl Into<String>) -> Self {
    self.top_level_site = Some(site.into());
    self
  }

  /// Sets the resource kind.
  pub fn resource(mut self, kind: ResourceKind) -> Self {
    self.resource = kind;
    self
  }

  /// Shorthand for [`resource`](Self::resource) with [`ResourceKind::Navigation`].
  pub fn navigation(mut self) -> Self {
    self.resource = ResourceKind::Navigation;
    self
  }

  /// Shorthand for [`resource`](Self::resource) with [`ResourceKind::Subresource`].
  pub fn subresource(mut self) -> Self {
    self.resource = ResourceKind::Subresource;
    self
  }

  /// Sets the method class.
  pub fn method(mut self, class: MethodClass) -> Self {
    self.method = class;
    self
  }

  /// Selects a Firefox Multi-Account Containers identity.
  ///
  /// Once supplied, a cookie whose `user_context_id` is `None` is **not** a
  /// match: the crate does not know it belongs to this container, and guessing
  /// is how containers merge.
  pub fn user_context_id(mut self, id: u32) -> Self {
    self.user_context_id = Some(id);
    self
  }

  /// Selects a Firefox private-browsing identity. Same missing-vs-default rule
  /// as [`user_context_id`](Self::user_context_id).
  pub fn private_browsing_id(mut self, id: u32) -> Self {
    self.private_browsing_id = Some(id);
    self
  }

  /// Overrides the clock used for send-time expiry. Defaults to
  /// `SystemTime::now()` when the header is built.
  pub fn now(mut self, now: SystemTime) -> Self {
    self.now = Some(now);
    self
  }
}

impl fmt::Debug for SendContext {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("SendContext")
      .field("url", &redact_url(&self.url))
      .field(
        "top_level_site",
        &self.top_level_site.as_deref().map(redact_url),
      )
      .field("resource", &self.resource)
      .field("method", &self.method)
      .field("user_context_id", &self.user_context_id)
      .field("private_browsing_id", &self.private_browsing_id)
      .field("now", &self.now)
      .finish()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn debug_redacts_both_urls_it_carries() {
    let context = SendContext::url("https://user:secret@example.com/path?q=1")
      .top_level_site("https://user:other@top.example/");
    let rendered = format!("{context:?}");
    assert!(!rendered.contains("secret"));
    assert!(!rendered.contains("other"));
    assert!(rendered.contains("https://example.com/path"));
    assert!(rendered.contains("https://top.example/"));
  }

  #[test]
  fn defaults_are_the_conservative_ones() {
    let context = SendContext::url("https://example.com/");
    assert_eq!(context.resource, ResourceKind::Subresource);
    assert_eq!(context.method, MethodClass::Safe);
    assert_eq!(context.top_level_site, None);
    assert_eq!(context.user_context_id, None);
    assert_eq!(context.private_browsing_id, None);
    assert_eq!(context.now, None);
  }
}
