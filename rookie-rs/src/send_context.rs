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
use crate::isolation::AncestorChain;
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
  pub(crate) const FIRST_PARTY_DOMAIN: &str = "first_party_domain";
  pub(crate) const GECKO_VIEW_SESSION_CONTEXT_ID: &str = "gecko_view_session_context_id";
  pub(crate) const ORIGIN_ATTRIBUTES: &str = "origin_attributes";
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
  pub(crate) ancestor_chain: Option<AncestorChain>,
  pub(crate) first_party_domain: Option<String>,
  pub(crate) gecko_view_session_context_id: Option<String>,
  pub(crate) origin_attributes: Option<String>,
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
      ancestor_chain: None,
      first_party_domain: None,
      gecko_view_session_context_id: None,
      origin_attributes: None,
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

  /// States whether the request's frame tree contains a cross-site ancestor.
  ///
  /// Without this, the chain is *derived*: same-site when the request site is
  /// within [`top_level_site`](Self::top_level_site), cross-site otherwise.
  /// Setting it explicitly is how a caller describes an `A -> B -> A` embed,
  /// whose request site and top-level site are equal even though an ancestor
  /// is cross-site. Both engines put this bit in the partition key, so it
  /// changes which partitioned cookies match.
  ///
  /// It also makes the request cross-site for `SameSite=Lax` and
  /// `SameSite=Strict`. Both engines' site-for-cookies walks the whole
  /// ancestor chain, so an `A -> B -> A` frame is cross-site to a browser
  /// even though its two sites are equal, and treating it as same-site here
  /// would send a `Strict` cookie a browser withholds. The partition key and
  /// the same-site decision are read off the one resolved chain, not computed
  /// separately.
  ///
  /// The selector has force only when the request site is already within the
  /// top-level site. A cross-site request has a cross-site ancestor by
  /// construction -- the top-level document is the foreign ancestor -- so
  /// [`AncestorChain::SameSite`] there describes a frame tree neither engine
  /// can produce and is ignored.
  ///
  /// # Examples
  ///
  /// An `A -> B -> A` embed: the request and the top-level site are both `A`,
  /// reached through a cross-site `B`.
  ///
  /// ```no_run
  /// use rookie_cookies::{read, AncestorChain, ReadRequest, SendContext};
  ///
  /// let snapshot = read(ReadRequest::browser("chrome"))?;
  /// let view = snapshot.send_view(
  ///   &SendContext::url("https://a.example/api")
  ///     .top_level_site("https://a.example")
  ///     .ancestor_chain(AncestorChain::CrossSite),
  /// )?;
  /// println!("{} selected", view.len());
  /// # Ok::<(), rookie_cookies::Error>(())
  /// ```
  pub fn ancestor_chain(mut self, chain: AncestorChain) -> Self {
    self.ancestor_chain = Some(chain);
    self
  }

  /// Selects a Firefox `firstPartyDomain` origin attribute.
  ///
  /// Same missing-vs-default rule as
  /// [`user_context_id`](Self::user_context_id): once supplied, a row that
  /// does not carry this attribute is not a match.
  pub fn first_party_domain(mut self, domain: impl Into<String>) -> Self {
    self.first_party_domain = Some(domain.into());
    self
  }

  /// Selects a Firefox `geckoViewSessionContextId` origin attribute.
  pub fn gecko_view_session_context_id(mut self, id: impl Into<String>) -> Self {
    self.gecko_view_session_context_id = Some(id.into());
    self
  }

  /// Selects **opaque** rows by their verbatim Firefox `originAttributes`.
  ///
  /// A row is opaque when this build cannot decompose its identity: it carries
  /// an attribute name the build does not know, a known name whose value it
  /// cannot read, or a `partitionKey` it cannot parse. Such a row is omitted
  /// from every send view -- an identity that cannot be read is never assumed
  /// to be the default context -- and naming the whole stored value exactly is
  /// the only way to select it. The comparison is byte equality against what
  /// the browser stored, so pass the value from
  /// [`CookieContext::origin_attributes`](crate::enums::CookieContext::origin_attributes)
  /// rather than reconstructing it.
  ///
  /// It has no effect on any other row. Every row this build *can* read is
  /// governed by the typed selectors and the partition key alone, so one
  /// cookie written by a future Firefox does not collapse the whole snapshot
  /// to a single stored suffix.
  pub fn origin_attributes(mut self, attributes: impl Into<String>) -> Self {
    self.origin_attributes = Some(attributes.into());
    self
  }

  /// Overrides the clock used for send-time expiry. Defaults to
  /// `SystemTime::now()` when the header is built.
  pub fn now(mut self, now: SystemTime) -> Self {
    self.now = Some(now);
    self
  }

  /// Whether this context supplies the selector `token` names.
  ///
  /// An unknown token supplies nothing, so a token added to the vocabulary in
  /// a later release cannot accidentally read as "already answered".
  pub(crate) fn supplies(&self, token: &str) -> bool {
    match token {
      selector::TOP_LEVEL_SITE => self.top_level_site.is_some(),
      selector::USER_CONTEXT_ID => self.user_context_id.is_some(),
      selector::PRIVATE_BROWSING_ID => self.private_browsing_id.is_some(),
      selector::FIRST_PARTY_DOMAIN => self.first_party_domain.is_some(),
      selector::GECKO_VIEW_SESSION_CONTEXT_ID => self.gecko_view_session_context_id.is_some(),
      selector::ORIGIN_ATTRIBUTES => self.origin_attributes.is_some(),
      _ => false,
    }
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
      .field("ancestor_chain", &self.ancestor_chain)
      .field("first_party_domain", &self.first_party_domain)
      .field(
        "gecko_view_session_context_id",
        &self.gecko_view_session_context_id,
      )
      .field("origin_attributes", &self.origin_attributes)
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
