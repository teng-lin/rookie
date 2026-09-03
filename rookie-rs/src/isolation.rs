//! The one comparison space for browser isolation identity.
//!
//! Two questions live here, and nothing else does. What browsing context does
//! a *stored* row belong to ([`StoredIsolation`])? What browsing context is a
//! *request* made from ([`RequestIsolation`])? [`RequestIsolation::verdict`] is
//! the single place that decides whether those are the same context, so
//! `header`, `send_view`, and every binding that calls them share one answer
//! rather than each re-deriving a slightly different one.
//!
//! The rule the whole module exists to enforce: an identity dimension this
//! build cannot read is **unknown**, never "the default". A stored `None` never
//! matches a supplied selector, and a row carrying an attribute this build does
//! not recognize is omitted until the caller names it exactly. Guessing in
//! either direction is how two isolated contexts merge.

use crate::enums::CookieContext;
use crate::header_filter::redact_url;
use crate::send_context::{selector, SendContext};
use crate::RequestError;
use url::Url;

/// Whether the request's frame tree contains a cross-site ancestor.
///
/// Both engines put this in the partition key: Chromium persists it as
/// `has_cross_site_ancestor`, and Firefox appends `,f` to `partitionKey` for
/// `foreignByAncestorContext`. It is what tells an `A -> B -> A` iframe apart
/// from `A` itself, which is a distinction a top-level site alone cannot make.
///
/// A [`SendContext`] that does not set one gets the derived value: same-site
/// when the request site is within the top-level site, cross-site otherwise.
/// Setting it explicitly is how a caller describes a nested chain the derived
/// rule cannot see.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AncestorChain {
  /// Every ancestor frame is within the top-level site.
  SameSite,
  /// At least one ancestor frame is cross-site.
  CrossSite,
}

/// Whether a projection that cannot represent isolation may discard it.
///
/// The eight-field [`Cookie`](crate::enums::Cookie), a Netscape cookie file,
/// and `http.cookiejar` have no cell for a CHIPS partition key, a Firefox
/// `partitionKey` tuple, or container identity. There is no encoding of that
/// state a caller could round-trip back into a request, so producing one of
/// those shapes from an isolated snapshot silently converts scoped credentials
/// into unscoped ones.
///
/// [`Refuse`](Self::Refuse) is the default because the failure it prevents is
/// invisible: a successful call returns cookies that look correct and are
/// scoped to a context the caller never asked about.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IsolationLoss {
  /// Refuse the projection when the snapshot holds any isolated row.
  #[default]
  Refuse,
  /// Produce it anyway. The caller has decided the loss is acceptable.
  Allow,
}

/// A (scheme, host) pair.
///
/// **This is not eTLD+1.** The crate has no public-suffix list and does not
/// gain one, so `https://cdn.example.com` and `https://app.example.com` are
/// different sites here and the same site to a browser. Callers supply an
/// already-normalized registrable site; see the `top_level_site` contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Site {
  scheme: String,
  host: String,
}

impl Site {
  /// Builds a site, canonicalizing the host the way a URL does.
  ///
  /// Returns `None` for a host no canonical form exists for, which makes a
  /// stored key carrying one `Unparsable` rather than a site that silently
  /// compares unequal to everything.
  fn parse(scheme: &str, host: &str) -> Option<Self> {
    Some(Self {
      scheme: scheme.to_ascii_lowercase(),
      host: canonical_host(host)?,
    })
  }

  /// Whether `self` is within `top`: same scheme, and a host that is equal to
  /// or a subdomain of `top`'s host.
  ///
  /// Sibling subdomains are *not* within each other, because neither is a
  /// suffix of the other. An IP literal on either side requires exact
  /// equality: `0.0.1` is a suffix of `127.0.0.1` at a dot boundary, and
  /// treating that as containment would be nonsense.
  pub(crate) fn is_within(&self, top: &Site) -> bool {
    if self.scheme != top.scheme {
      return false;
    }
    if self.host == top.host {
      return true;
    }
    if is_ip(&self.host) || is_ip(&top.host) {
      return false;
    }
    self.host.len() > top.host.len()
      && self.host.ends_with(&top.host)
      && self.host.as_bytes()[self.host.len() - top.host.len() - 1] == b'.'
  }
}

/// The one host spelling both sides of a comparison are reduced to.
///
/// Two things make a textual comparison wrong here. A stored key may spell a
/// host in Unicode where the request URL spells it in punycode, and one IPv6
/// address has many textual forms (`::1` and `0:0:0:0:0:0:0:1`). Both sides go
/// through this, so equal hosts compare equal however they were written.
fn canonical_host(host: &str) -> Option<String> {
  let host = host.trim_end_matches('.');
  let unbracketed = host
    .strip_prefix('[')
    .and_then(|host| host.strip_suffix(']'))
    .unwrap_or(host);
  if unbracketed.is_empty() {
    return None;
  }
  // An IP literal is compared by value, not by spelling. `Display` on the
  // parsed address is the canonical form for both families.
  if let Ok(address) = unbracketed.parse::<std::net::IpAddr>() {
    return Some(address.to_string());
  }
  // Otherwise the URL host parser applies IDNA, which is what turns a
  // Unicode-spelled stored key into the punycode a request URL carries.
  match url::Host::parse(unbracketed).ok()? {
    url::Host::Domain(domain) => Some(domain.to_ascii_lowercase()),
    url::Host::Ipv4(address) => Some(address.to_string()),
    url::Host::Ipv6(address) => Some(address.to_string()),
  }
}

/// Whether `host` is an IP literal rather than a registrable name.
pub(crate) fn is_ip(host: &str) -> bool {
  host.parse::<std::net::IpAddr>().is_ok()
}

/// Parses a caller-supplied `http`/`https` URL into a [`Site`].
pub(crate) fn site_from_url(raw: &str) -> Option<Site> {
  Some(site_and_port_from_url(raw)?.0)
}

/// The [`Site`] and the *explicit* port of a caller-supplied URL.
///
/// The port is `None` for a default port, which is what makes it comparable
/// with a Firefox `partitionKey`: Firefox omits the port field entirely when
/// the top-level site uses its scheme's default port.
fn site_and_port_from_url(raw: &str) -> Option<(Site, Option<u16>)> {
  let parsed = Url::parse(raw).ok()?;
  if parsed.scheme() != "http" && parsed.scheme() != "https" {
    return None;
  }
  let host = match parsed.host()? {
    url::Host::Domain(domain) => domain.to_owned(),
    url::Host::Ipv4(address) => address.to_string(),
    url::Host::Ipv6(address) => address.to_string(),
  };
  Some((Site::parse(parsed.scheme(), &host)?, parsed.port()))
}

/// The partition identity one stored row declares, if any.
///
/// The two engines are separate arms rather than a shared `Site` because their
/// keys are not the same shape and must not be compared as if they were:
/// Chromium's carries an ancestor-chain bit that may be absent, and Firefox's
/// carries a port and a foreign-ancestor flag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PartitionIdentity {
  /// The row declares no partition. It is sent in every top-level context.
  Unpartitioned,
  /// A Chromium CHIPS key.
  Chromium {
    site: Site,
    /// The key's explicit port, absent for a scheme's default port -- the same
    /// normalization the caller's `top_level_site` URL gets, so the two are
    /// comparable.
    port: Option<u16>,
    /// `None` on a store written before Chromium added the column. Unknown,
    /// not false: the row is omitted from every send view and counted.
    cross_site_ancestor: Option<bool>,
  },
  /// A Firefox dynamic-first-party-isolation key.
  Firefox {
    site: Site,
    /// The top-level site's explicit port, absent for a default port.
    port: Option<u16>,
    /// Firefox's `foreignByAncestorContext` flag, the `,f` tuple field.
    foreign_by_ancestor: bool,
  },
  /// The row declares a partition neither parser understood.
  ///
  /// Deliberately **not** folded into `Unpartitioned`: reading an unrecognized
  /// key as "no partition" would send a partitioned cookie into every context,
  /// which is precisely the merge this module exists to prevent. It matches
  /// nothing, and the loss is counted.
  Unparsable,
}

/// Parses Firefox's `partitionKey`.
///
/// The grammar is **strict**: `(scheme,baseDomain)`, `(scheme,baseDomain,port)`,
/// `(scheme,baseDomain,f)`, or `(scheme,baseDomain,port,f)`. Anything else is a
/// non-match everywhere rather than a partial match on the fields that happened
/// to parse. Through 0.6 the trailing fields were discarded, so two partitions
/// differing only by port or by the foreign-ancestor bit collided.
fn firefox_partition_identity(raw: &str) -> Option<PartitionIdentity> {
  let inner = raw.strip_prefix('(')?.strip_suffix(')')?;
  let fields: Vec<&str> = inner.split(',').collect();
  let scheme = *fields.first()?;
  // An IPv6 host arrives bracketed here and unbracketed from `Url::host()`, so
  // it is unwrapped on this side too or the two could never compare equal.
  let host = fields.get(1)?.trim_start_matches('[').trim_end_matches(']');
  if host.is_empty() || (scheme != "http" && scheme != "https") {
    return None;
  }
  let (port, foreign_by_ancestor) = match fields.len() {
    2 => (None, false),
    // A three-field tuple is either a port or the foreign-ancestor flag.
    // Firefox emits `,f` in the third position whenever there is no port.
    3 => match fields[2] {
      "f" => (None, true),
      port => (Some(parse_port(port)?), false),
    },
    4 => {
      if fields[3] != "f" {
        return None;
      }
      (Some(parse_port(fields[2])?), true)
    }
    _ => return None,
  };
  Some(PartitionIdentity::Firefox {
    site: Site::parse(scheme, host)?,
    port,
    foreign_by_ancestor,
  })
}

fn parse_port(raw: &str) -> Option<u16> {
  if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
    return None;
  }
  raw.parse().ok()
}

/// Parses Chromium's `top_frame_site_key`.
///
/// The key is a serialized `SchemefulSite`, which is a URL, so it goes through
/// the same parser the caller's `top_level_site` does. That is what makes the
/// two comparable: both sides drop a scheme's default port and both lowercase
/// and unbracket the host, so `https://a.test` and `https://a.test:443` are
/// one identity while `https://a.test:8443` is a different one.
///
/// A port is **not** discarded. Through 0.6 any trailing `:digits` was
/// stripped, which was the one widening step in this module: it made a key
/// naming an explicit port match a top-level site that did not.
fn chromium_partition(raw: &str, cross_site_ancestor: Option<bool>) -> PartitionIdentity {
  match site_and_port_from_url(raw.trim()) {
    Some((site, port)) => PartitionIdentity::Chromium {
      site,
      port,
      cross_site_ancestor,
    },
    None => PartitionIdentity::Unparsable,
  }
}

pub(crate) fn partition_identity(context: &CookieContext) -> PartitionIdentity {
  let chromium = context
    .top_frame_site_key
    .as_deref()
    .filter(|key| !key.is_empty());
  let firefox = context
    .partition_key
    .as_deref()
    .filter(|key| !key.is_empty());
  match (chromium, firefox) {
    (None, None) => PartitionIdentity::Unpartitioned,
    (Some(key), _) => chromium_partition(key, context.has_cross_site_ancestor),
    (None, Some(key)) => firefox_partition_identity(key).unwrap_or(PartitionIdentity::Unparsable),
  }
}

/// Every Firefox `OriginAttributes` field this build understands, plus whether
/// the value carried a name it did not.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct FirefoxOriginAttributes {
  pub(crate) user_context_id: Option<u32>,
  pub(crate) private_browsing_id: Option<u32>,
  pub(crate) partition_key: Option<String>,
  pub(crate) first_party_domain: Option<String>,
  pub(crate) gecko_view_session_context_id: Option<String>,
  /// Either a name this build does not know, or a known name whose value it
  /// could not read. Both mean the row's identity is not fully determined, so
  /// it fails closed until a caller selects its `origin_attributes` verbatim.
  pub(crate) unknown_names: bool,
  /// Known names that appeared at all, readable or not.
  ///
  /// The default fill may only claim a name that never appeared. A name that
  /// appeared with an unreadable value is *unknown*, not default: reading
  /// `userContextId=abc` as container 0 would put a row this build cannot
  /// identify into the default container.
  seen: SeenAttributes,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SeenAttributes {
  user_context_id: bool,
  private_browsing_id: bool,
  first_party_domain: bool,
  gecko_view_session_context_id: bool,
}

/// The fields current Firefox compares in `OriginAttributes::operator==`.
///
/// Not a closed set for all time: a name this build does not list -- a
/// historic one such as `inIsolatedMozBrowser`, or one a future release adds
/// -- fails closed rather than being ignored.
/// Read only by the test that keeps this list and the parser's match arms in
/// step; the parser itself names each attribute explicitly.
#[cfg(test)]
const KNOWN_ORIGIN_ATTRIBUTES: [&str; 5] = [
  "userContextId",
  "privateBrowsingId",
  "partitionKey",
  "firstPartyDomain",
  "geckoViewSessionContextId",
];

/// Parses a Firefox `originAttributes` value in either encoding it is stored in.
///
/// `moz_cookies` holds the `^name=value&name=value` suffix; the session store
/// holds a JSON object. One parser reads both, so the persistent and session
/// lanes cannot drift into recognizing different attribute sets.
pub(crate) fn parse_firefox_origin_attributes(raw: &str) -> FirefoxOriginAttributes {
  if raw.trim_start().starts_with('{') {
    if let Ok(serde_json::Value::Object(object)) = serde_json::from_str(raw) {
      return from_json_object(&object);
    }
  }
  from_suffix(raw)
}

fn from_suffix(raw: &str) -> FirefoxOriginAttributes {
  let mut parsed = FirefoxOriginAttributes::default();
  for (name, value) in url::form_urlencoded::parse(raw.strip_prefix('^').unwrap_or(raw).as_bytes())
  {
    match name.as_ref() {
      "userContextId" => {
        parsed.seen.user_context_id = true;
        match value.parse() {
          Ok(id) => parsed.user_context_id = Some(id),
          // `userContextId=abc`, an out-of-range number, or a bare name with
          // no `=`. The name is there and its value is not one this build can
          // compare, which is the definition of failing closed.
          Err(_) => parsed.unknown_names = true,
        }
      }
      "privateBrowsingId" => {
        parsed.seen.private_browsing_id = true;
        match value.parse() {
          Ok(id) => parsed.private_browsing_id = Some(id),
          Err(_) => parsed.unknown_names = true,
        }
      }
      "partitionKey" => parsed.partition_key = Some(value.into_owned()),
      "firstPartyDomain" => {
        parsed.seen.first_party_domain = true;
        parsed.first_party_domain = Some(value.into_owned());
      }
      "geckoViewSessionContextId" => {
        parsed.seen.gecko_view_session_context_id = true;
        parsed.gecko_view_session_context_id = Some(value.into_owned());
      }
      _ => parsed.unknown_names = true,
    }
  }
  parsed
}

fn from_json_object(
  object: &serde_json::Map<String, serde_json::Value>,
) -> FirefoxOriginAttributes {
  // The session store writes numbers as JSON numbers and older builds wrote
  // them as strings. Both are the same attribute; anything else -- a negative
  // number, a boolean, a number where a string belongs -- is a value this
  // build cannot compare, and is treated the same as an unknown name.
  let unsigned = |value: &serde_json::Value| {
    value
      .as_u64()
      .and_then(|value| u32::try_from(value).ok())
      .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
  };
  let mut parsed = FirefoxOriginAttributes::default();
  for (name, value) in object {
    match name.as_str() {
      "userContextId" => {
        parsed.seen.user_context_id = true;
        match unsigned(value) {
          Some(id) => parsed.user_context_id = Some(id),
          None => parsed.unknown_names = true,
        }
      }
      "privateBrowsingId" => {
        parsed.seen.private_browsing_id = true;
        match unsigned(value) {
          Some(id) => parsed.private_browsing_id = Some(id),
          None => parsed.unknown_names = true,
        }
      }
      "partitionKey" => match value.as_str() {
        Some(key) => parsed.partition_key = Some(key.to_owned()),
        None => parsed.unknown_names = true,
      },
      "firstPartyDomain" => {
        parsed.seen.first_party_domain = true;
        match value.as_str() {
          Some(domain) => parsed.first_party_domain = Some(domain.to_owned()),
          None => parsed.unknown_names = true,
        }
      }
      "geckoViewSessionContextId" => {
        parsed.seen.gecko_view_session_context_id = true;
        match value.as_str() {
          Some(id) => parsed.gecko_view_session_context_id = Some(id.to_owned()),
          None => parsed.unknown_names = true,
        }
      }
      _ => parsed.unknown_names = true,
    }
  }
  parsed
}

/// The browsing context one stored row belongs to.
///
/// Computed once per row when a snapshot is built, because every send view
/// needs it and re-parsing a partition key per row per call is the same answer
/// at a worse price.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StoredIsolation {
  pub(crate) partition: PartitionIdentity,
  user_context_id: Option<u32>,
  private_browsing_id: Option<u32>,
  first_party_domain: Option<String>,
  gecko_view_session_context_id: Option<String>,
  origin_attributes: Option<String>,
  unknown_origin_attributes: bool,
}

impl StoredIsolation {
  pub(crate) fn from_context(context: &CookieContext) -> Self {
    let partition = partition_identity(context);
    let Some(raw) = context.origin_attributes.as_deref() else {
      // Not a Firefox row, or a Firefox schema with no such column. Every
      // container dimension stays unknown.
      return Self {
        partition,
        user_context_id: context.user_context_id,
        private_browsing_id: context.private_browsing_id,
        first_party_domain: None,
        gecko_view_session_context_id: None,
        origin_attributes: None,
        unknown_origin_attributes: false,
      };
    };
    let parsed = parse_firefox_origin_attributes(raw);
    // Firefox omits every default-valued attribute from the suffix, so a row
    // that *has* an origin-attributes value and no `userContextId` is
    // positively in container 0 -- not unknown. That fill is what lets
    // `user_context_id(0)` select the default container instead of matching
    // nothing.
    Self {
      partition,
      user_context_id: fill(parsed.user_context_id, parsed.seen.user_context_id, 0),
      private_browsing_id: fill(
        parsed.private_browsing_id,
        parsed.seen.private_browsing_id,
        0,
      ),
      first_party_domain: fill(
        parsed.first_party_domain,
        parsed.seen.first_party_domain,
        String::new(),
      ),
      gecko_view_session_context_id: fill(
        parsed.gecko_view_session_context_id,
        parsed.seen.gecko_view_session_context_id,
        String::new(),
      ),
      origin_attributes: Some(raw.to_owned()),
      unknown_origin_attributes: parsed.unknown_names,
    }
  }

  /// Whether this row's identity is one this build cannot decompose.
  ///
  /// Either an attribute name it does not know, a known name whose value it
  /// cannot read, or a Firefox `partitionKey` no parser here understands. Such
  /// a row is reachable only by naming its raw `originAttributes` verbatim,
  /// and that selector applies to no other row.
  ///
  /// A Chromium row has no raw suffix, so an unparsable Chromium key is not
  /// opaque -- there is nothing to name -- and stays unreachable.
  pub(crate) fn is_opaque(&self) -> bool {
    self.unknown_origin_attributes
      || (self.origin_attributes.is_some() && self.partition == PartitionIdentity::Unparsable)
  }
}

impl StoredIsolation {
  /// Whether this row belongs to anything other than the unisolated default.
  ///
  /// This is exactly the per-row fact [`demanded_selectors`] aggregates, so
  /// "the snapshot would demand a selector" and "the snapshot holds isolated
  /// rows" cannot drift apart: a jar refuses precisely when some context would
  /// have had to name a selector to disambiguate what it holds.
  pub(crate) fn is_isolated(&self) -> bool {
    self.partition != PartitionIdentity::Unpartitioned
      || self.user_context_id.is_some_and(|id| id > 0)
      || self.private_browsing_id.is_some_and(|id| id > 0)
      || self
        .first_party_domain
        .as_deref()
        .is_some_and(is_non_default)
      || self
        .gecko_view_session_context_id
        .as_deref()
        .is_some_and(is_non_default)
      || self.unknown_origin_attributes
  }
}

/// How many rows in `stored` carry isolation a flat projection cannot hold.
pub(crate) fn isolated_rows(stored: &[StoredIsolation]) -> u64 {
  stored
    .iter()
    .filter(|row| row.is_isolated())
    .count()
    .try_into()
    .unwrap_or(u64::MAX)
}

/// Refuses a flat projection when it would discard observed isolation.
///
/// Snapshot jars and the domain-filtered direct-path compatibility job call
/// this same check. Keeping the decision here means the latter can acquire,
/// check, and project one detailed row set instead of reopening a mutable
/// browser database between its policy decision and its output.
pub(crate) fn check_isolation_loss(
  stored: &[StoredIsolation],
  loss: IsolationLoss,
) -> Result<(), RequestError> {
  if matches!(loss, IsolationLoss::Allow) {
    return Ok(());
  }
  let required = demanded_selectors(stored);
  if required.is_empty() {
    return Ok(());
  }
  Err(RequestError::IsolationLossRefused {
    isolated_rows: isolated_rows(stored),
    required: required.into_iter().map(str::to_owned).collect(),
  })
}

/// Supplies an attribute's default, but only when the name never appeared.
///
/// A name that appeared with a value this build could not read stays `None`:
/// unknown, not default.
fn fill<T>(value: Option<T>, seen: bool, default: T) -> Option<T> {
  match value {
    Some(value) => Some(value),
    None if seen => None,
    None => Some(default),
  }
}

/// Why one row was left out of a send view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OmitReason {
  /// The row's partition is a different browsing context.
  Partition,
  /// The row is partitioned but its store predates the ancestor-chain column.
  AncestorChainUnknown,
  /// The row's partition key is one no parser here understood.
  UnparsablePartitionKey,
  /// A container or origin-attribute dimension did not match.
  Origin,
}

/// The browsing context a request is made from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RequestIsolation {
  top_level_site: Option<Site>,
  top_level_port: Option<u16>,
  /// Whether the request site is within the top-level site. This is the site
  /// half of the partition comparison, and it says nothing about ancestors.
  sites_match: bool,
  /// Whether this request counts as same-site for `SameSite=Lax`/`Strict`.
  ///
  /// Strictly narrower than `sites_match`: a cross-site ancestor makes the
  /// request cross-site even when the two sites are equal.
  same_site_context: bool,
  ancestor: AncestorChain,
  user_context_id: Option<u32>,
  private_browsing_id: Option<u32>,
  first_party_domain: Option<String>,
  gecko_view_session_context_id: Option<String>,
  origin_attributes: Option<String>,
}

impl RequestIsolation {
  /// Resolves the context a [`SendContext`] describes.
  ///
  /// An unparseable top-level site is rejected rather than dropped: ignoring
  /// it falls back to the first-party assumption and sends more than the
  /// caller asked for.
  pub(crate) fn resolve(context: &SendContext) -> Result<Self, RequestError> {
    let request_site = site_from_url(&context.url).ok_or_else(|| RequestError::InvalidUrl {
      display: redact_url(&context.url),
    })?;
    let (top_level_site, top_level_port) = match context.top_level_site.as_deref() {
      None => (None, None),
      Some(raw) => {
        let (site, port) =
          site_and_port_from_url(raw).ok_or_else(|| RequestError::InvalidTopLevelSite {
            display: redact_url(raw),
          })?;
        (Some(site), port)
      }
    };
    // With no top-level site supplied, the request is assumed first-party.
    let sites_match = top_level_site
      .as_ref()
      .is_none_or(|top| request_site.is_within(top));
    // A cross-site request has a cross-site ancestor by construction: the
    // top-level document is itself the foreign ancestor. An explicit
    // `SameSite` there describes a frame tree neither engine can produce, and
    // honouring it would admit a site's own first-party rows (its key, ancestor
    // bit 0) into a third-party send. The selector only has force when the two
    // sites already match, which is the ambiguity it exists to resolve.
    let ancestor = if sites_match {
      context.ancestor_chain.unwrap_or(AncestorChain::SameSite)
    } else {
      AncestorChain::CrossSite
    };
    // Both engines' site-for-cookies walks the whole ancestor chain, so an
    // `A -> B -> A` frame is cross-site for SameSite purposes even though its
    // two sites are equal. Deriving this from the sites alone would send a
    // `SameSite=Strict` cookie a browser withholds, and this crate is never
    // less conservative than a browser. The two terms are therefore coupled
    // through the one resolved chain rather than computed separately.
    //
    // Derived contexts are unchanged: the derivation makes `ancestor`
    // `SameSite` exactly when the sites match.
    let same_site_context = sites_match && ancestor == AncestorChain::SameSite;
    Ok(Self {
      top_level_site,
      top_level_port,
      sites_match,
      same_site_context,
      ancestor,
      user_context_id: context.user_context_id,
      private_browsing_id: context.private_browsing_id,
      first_party_domain: context.first_party_domain.clone(),
      gecko_view_session_context_id: context.gecko_view_session_context_id.clone(),
      origin_attributes: context.origin_attributes.clone(),
    })
  }

  pub(crate) fn same_site_context(&self) -> bool {
    self.same_site_context
  }

  /// Whether the request has a cross-site ancestor *within* its own site,
  /// which is the state Firefox records as `foreignByAncestorContext`.
  fn foreign_by_ancestor(&self) -> bool {
    self.sites_match && self.ancestor == AncestorChain::CrossSite
  }

  /// Whether the caller named this row's raw `originAttributes` exactly.
  fn names_stored_origin_attributes(&self, stored: &StoredIsolation) -> bool {
    self.origin_attributes.is_some()
      && self.origin_attributes.as_deref() == stored.origin_attributes.as_deref()
  }

  /// The partition half of the verdict.
  fn partition_verdict(&self, stored: &StoredIsolation) -> Result<(), OmitReason> {
    match &stored.partition {
      // "Unpartitioned" means exactly this: sent in every top-level context.
      PartitionIdentity::Unpartitioned => Ok(()),
      PartitionIdentity::Unparsable => Err(OmitReason::UnparsablePartitionKey),
      PartitionIdentity::Chromium {
        site,
        port,
        cross_site_ancestor,
      } => {
        if self.top_level_site.as_ref() != Some(site) || *port != self.top_level_port {
          return Err(OmitReason::Partition);
        }
        // Chromium's partition key equality includes the ancestor bit. A store
        // that never recorded it cannot be compared, so the row fails closed.
        match cross_site_ancestor {
          None => Err(OmitReason::AncestorChainUnknown),
          Some(bit) => {
            if *bit != (self.ancestor == AncestorChain::CrossSite) {
              return Err(OmitReason::Partition);
            }
            Ok(())
          }
        }
      }
      PartitionIdentity::Firefox {
        site,
        port,
        foreign_by_ancestor,
      } => {
        // A partitioned Firefox row belongs to an embedded context. It is
        // never the right answer for a plain first-party request.
        if self.sites_match && self.ancestor == AncestorChain::SameSite {
          return Err(OmitReason::Partition);
        }
        if self.top_level_site.as_ref() != Some(site)
          || *port != self.top_level_port
          || *foreign_by_ancestor != self.foreign_by_ancestor()
        {
          return Err(OmitReason::Partition);
        }
        Ok(())
      }
    }
  }

  /// The container half of the verdict.
  ///
  /// Missing vs default: a row whose dimension is `None` is unknown, and a
  /// caller who named a value does not get unknown rows. Guessing here is how
  /// containers merge.
  fn origin_verdict(&self, stored: &StoredIsolation) -> Result<(), OmitReason> {
    if selector_excludes(self.user_context_id, stored.user_context_id)
      || selector_excludes(self.private_browsing_id, stored.private_browsing_id)
      || selector_excludes(
        self.first_party_domain.as_deref(),
        stored.first_party_domain.as_deref(),
      )
      || selector_excludes(
        self.gecko_view_session_context_id.as_deref(),
        stored.gecko_view_session_context_id.as_deref(),
      )
    {
      return Err(OmitReason::Origin);
    }
    Ok(())
  }

  /// Whether one stored row's identity admits this send.
  ///
  /// Once a selector has been supplied, a row in another context is simply
  /// omitted; it is not an error. The `incomplete_send_context` error exists
  /// only for a selector that was never supplied at all.
  pub(crate) fn verdict(&self, stored: &StoredIsolation) -> Result<(), OmitReason> {
    // An *opaque* row is one whose identity this build cannot decompose: an
    // attribute name it does not know, a known name whose value it cannot
    // read, or a partition key no parser here understands. There is nothing to
    // compare field by field, so the only way to name such a row is verbatim.
    //
    // The raw selector governs **only** these rows. Filtering every row
    // through it would mean one cookie written by a future Firefox collapsed
    // the whole store to a single stored suffix, and an unpartitioned row
    // could never be sent beside a partitioned one again.
    if stored.is_opaque() {
      if !self.names_stored_origin_attributes(stored) {
        return Err(match stored.partition {
          PartitionIdentity::Unparsable => OmitReason::UnparsablePartitionKey,
          _ => OmitReason::Origin,
        });
      }
      // Naming the suffix exactly identifies the partition too, which is the
      // only way to reach an unparsable key. Every other gate still applies:
      // an exact suffix says which context the row is in, not that the caller
      // may have it in any other one.
      if stored.partition != PartitionIdentity::Unparsable {
        self.partition_verdict(stored)?;
      }
      return self.origin_verdict(stored);
    }
    self.partition_verdict(stored)?;
    self.origin_verdict(stored)
  }
}

/// Whether a supplied selector rules a stored value out.
///
/// A selector that was not supplied excludes nothing. A supplied selector
/// requires an exactly equal stored value, so unknown (`None`) never matches.
fn selector_excludes<T: PartialEq>(selected: Option<T>, stored: Option<T>) -> bool {
  match selected {
    None => false,
    Some(selected) => stored != Some(selected),
  }
}

/// The selector tokens a snapshot demands, in contract order.
///
/// A snapshot demands a token as soon as **one** row positively observes the
/// corresponding non-default value. There is deliberately no "more than one
/// identity" threshold: two rows in the same partition are just as unmergeable
/// with an unpartitioned one as two rows in different partitions are.
pub(crate) fn demanded_selectors(stored: &[StoredIsolation]) -> Vec<&'static str> {
  let mut demanded = Vec::new();
  if stored
    .iter()
    .any(|row| row.partition != PartitionIdentity::Unpartitioned)
  {
    demanded.push(selector::TOP_LEVEL_SITE);
  }
  // `None` and `Some(0)` never demand a selector. Gating on them would make
  // `header` unusable against every browser version whose schema lacks these
  // columns -- which is most of them.
  if stored
    .iter()
    .any(|row| row.user_context_id.is_some_and(|id| id > 0))
  {
    demanded.push(selector::USER_CONTEXT_ID);
  }
  if stored
    .iter()
    .any(|row| row.private_browsing_id.is_some_and(|id| id > 0))
  {
    demanded.push(selector::PRIVATE_BROWSING_ID);
  }
  if stored.iter().any(|row| {
    row
      .first_party_domain
      .as_deref()
      .is_some_and(is_non_default)
  }) {
    demanded.push(selector::FIRST_PARTY_DOMAIN);
  }
  if stored.iter().any(|row| {
    row
      .gecko_view_session_context_id
      .as_deref()
      .is_some_and(is_non_default)
  }) {
    demanded.push(selector::GECKO_VIEW_SESSION_CONTEXT_ID);
  }
  if stored.iter().any(|row| row.unknown_origin_attributes) {
    demanded.push(selector::ORIGIN_ATTRIBUTES);
  }
  demanded
}

fn is_non_default(value: &str) -> bool {
  !value.is_empty()
}

/// The demanded tokens `context` did not supply, in contract order.
pub(crate) fn missing_selectors(stored: &[StoredIsolation], context: &SendContext) -> Vec<String> {
  demanded_selectors(stored)
    .into_iter()
    .filter(|token| !context.supplies(token))
    .map(str::to_owned)
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  fn site(scheme: &str, host: &str) -> Site {
    Site::parse(scheme, host).expect("a canonical host")
  }

  #[test]
  fn a_site_contains_its_subdomains_but_not_its_siblings_or_its_parent() {
    let parent = site("https", "example.test");
    assert!(site("https", "example.test").is_within(&parent));
    assert!(site("https", "www.example.test").is_within(&parent));
    assert!(site("https", "deep.www.example.test").is_within(&parent));

    assert!(!site("https", "a.example.test").is_within(&site("https", "b.example.test")));
    assert!(!parent.is_within(&site("https", "www.example.test")));
    // A suffix that is not at a dot boundary is a different site entirely.
    assert!(!site("https", "evilexample.test").is_within(&parent));
    // The scheme is half of the site.
    assert!(!site("http", "www.example.test").is_within(&parent));
  }

  #[test]
  fn a_site_normalizes_case_and_the_root_dot() {
    let parent = site("https", "example.test");
    assert_eq!(site("HTTPS", "EXAMPLE.test."), parent);
    assert!(site("https", "WWW.Example.Test.").is_within(&parent));
  }

  #[test]
  fn an_ip_literal_requires_exact_equality() {
    // An IP address has no subdomains, so either side being a literal forces
    // equality rather than the suffix rule.
    let loopback = site("http", "127.0.0.1");
    assert!(loopback.is_within(&site("http", "127.0.0.1")));
    assert!(!loopback.is_within(&site("http", "10.0.0.1")));

    let v6 = site("http", "::1");
    assert!(v6.is_within(&site("http", "::1")));
    assert!(!v6.is_within(&site("http", "::2")));

    // The hazard that motivated the guard is now closed twice over. `0.0.1` is
    // a dot-boundary suffix of `127.0.0.1` as text, but canonicalization
    // expands it to a four-octet address that is not a suffix of anything, and
    // the IP guard would refuse the containment even if it were.
    assert_eq!(
      Site::parse("http", "0.0.1"),
      Some(site("http", "0.0.0.1")),
      "the shorthand form is expanded, not compared as written"
    );
    assert!(!loopback.is_within(&site("http", "0.0.1")));

    // A name is never inside an address, whichever side it is on.
    assert!(!site("http", "example.test").is_within(&loopback));
    assert!(!loopback.is_within(&site("http", "example.test")));
  }

  #[test]
  fn the_firefox_tuple_grammar_accepts_exactly_four_shapes() {
    let parsed = |key: &str| firefox_partition_identity(key);
    assert_eq!(
      parsed("(https,example.test)"),
      Some(PartitionIdentity::Firefox {
        site: site("https", "example.test"),
        port: None,
        foreign_by_ancestor: false,
      })
    );
    assert_eq!(
      parsed("(https,example.test,8443)"),
      Some(PartitionIdentity::Firefox {
        site: site("https", "example.test"),
        port: Some(8443),
        foreign_by_ancestor: false,
      })
    );
    assert_eq!(
      parsed("(https,example.test,f)"),
      Some(PartitionIdentity::Firefox {
        site: site("https", "example.test"),
        port: None,
        foreign_by_ancestor: true,
      })
    );
    assert_eq!(
      parsed("(https,example.test,8443,f)"),
      Some(PartitionIdentity::Firefox {
        site: site("https", "example.test"),
        port: Some(8443),
        foreign_by_ancestor: true,
      })
    );
  }

  #[test]
  fn anything_else_is_unparsable_rather_than_a_partial_match() {
    for key in [
      "(https,example.test,,f)",
      "(https,example.test,f,f)",
      "(https,example.test,8443,x)",
      "(https,example.test,8443,f,extra)",
      "(https,example.test,99999)",
      "(https,example.test,-1)",
      "(https,example.test, 8443)",
      "(ftp,example.test)",
      "(https,)",
      "(,example.test)",
      "(https)",
      "https,example.test",
      "(https,example.test",
      "",
    ] {
      assert_eq!(firefox_partition_identity(key), None, "key {key:?}");
    }
  }

  #[test]
  fn a_chromium_key_and_a_top_level_url_normalize_the_same_way() {
    let partition = |key: &str| chromium_partition(key, Some(true));
    let chromium = |host: &str, port: Option<u16>| PartitionIdentity::Chromium {
      site: site("https", host),
      port,
      cross_site_ancestor: Some(true),
    };

    // A serialized site, the same with a trailing slash, the default port
    // spelled out, and a mixed-case host are one identity -- the same one
    // `https://top.example/` produces on the caller's side.
    for key in [
      "https://top.example",
      "https://top.example/",
      "https://top.example:443",
      "https://TOP.example",
    ] {
      assert_eq!(partition(key), chromium("top.example", None), "{key}");
    }

    // A non-default port is a *different* identity. Through 0.6 it was
    // stripped, which let a ported key match an unported top-level site.
    assert_eq!(
      partition("https://top.example:8443"),
      chromium("top.example", Some(8443))
    );
    assert_eq!(partition("https://[::1]:8443"), chromium("::1", Some(8443)));

    for key in ["", "  ", "top.example", "ftp://top.example", "https://"] {
      assert_eq!(partition(key), PartitionIdentity::Unparsable, "{key:?}");
    }
  }

  #[test]
  fn the_two_engines_never_share_a_partition_arm() {
    let chromium = CookieContext {
      top_frame_site_key: Some("https://top.example".to_owned()),
      has_cross_site_ancestor: Some(true),
      ..CookieContext::default()
    };
    assert!(matches!(
      partition_identity(&chromium),
      PartitionIdentity::Chromium { .. }
    ));
    let firefox = CookieContext {
      partition_key: Some("(https,top.example)".to_owned()),
      ..CookieContext::default()
    };
    assert!(matches!(
      partition_identity(&firefox),
      PartitionIdentity::Firefox { .. }
    ));
    // An empty key is "no partition", not a partition that failed to parse.
    let empty = CookieContext {
      top_frame_site_key: Some(String::new()),
      partition_key: Some(String::new()),
      ..CookieContext::default()
    };
    assert_eq!(partition_identity(&empty), PartitionIdentity::Unpartitioned);
  }

  #[test]
  fn one_parser_reads_the_suffix_and_the_session_json_alike() {
    let suffix = parse_firefox_origin_attributes(
      "^userContextId=2&privateBrowsingId=1&partitionKey=(https,top.example)\
       &firstPartyDomain=example.org&geckoViewSessionContextId=session-7",
    );
    let json = parse_firefox_origin_attributes(
      r#"{"userContextId":2,"privateBrowsingId":1,"partitionKey":"(https,top.example)",
          "firstPartyDomain":"example.org","geckoViewSessionContextId":"session-7"}"#,
    );
    assert_eq!(suffix, json);
    assert_eq!(suffix.user_context_id, Some(2));
    assert_eq!(suffix.private_browsing_id, Some(1));
    assert_eq!(suffix.partition_key.as_deref(), Some("(https,top.example)"));
    assert_eq!(suffix.first_party_domain.as_deref(), Some("example.org"));
    assert_eq!(
      suffix.gecko_view_session_context_id.as_deref(),
      Some("session-7")
    );
    assert!(!suffix.unknown_names);
  }

  #[test]
  fn session_json_accepts_numbers_written_as_strings() {
    let parsed = parse_firefox_origin_attributes(r#"{"userContextId":"3"}"#);
    assert_eq!(parsed.user_context_id, Some(3));
  }

  #[test]
  fn an_attribute_name_this_build_does_not_know_is_recorded_as_unknown() {
    assert!(parse_firefox_origin_attributes("^futureAttr=1").unknown_names);
    assert!(parse_firefox_origin_attributes(r#"{"futureAttr":1}"#).unknown_names);
    // A value that is neither suffix nor object still fails closed.
    assert!(parse_firefox_origin_attributes(r#"["future"]"#).unknown_names);
    assert!(!parse_firefox_origin_attributes("").unknown_names);
    assert!(!parse_firefox_origin_attributes("^").unknown_names);
  }

  #[test]
  fn container_defaults_are_filled_only_when_the_row_says_something() {
    // Firefox omits default-valued attributes, so an empty suffix positively
    // means container 0.
    for raw in ["", "^"] {
      let stored = StoredIsolation::from_context(&CookieContext {
        origin_attributes: Some(raw.to_owned()),
        ..CookieContext::default()
      });
      assert_eq!(stored.user_context_id, Some(0), "{raw:?}");
      assert_eq!(stored.private_browsing_id, Some(0), "{raw:?}");
    }
    // A row with no origin-attributes value at all stays unknown.
    let unknown = StoredIsolation::from_context(&CookieContext::default());
    assert_eq!(unknown.user_context_id, None);
    assert_eq!(unknown.private_browsing_id, None);
    assert_eq!(unknown.first_party_domain, None);
    assert_eq!(unknown.gecko_view_session_context_id, None);
    assert_eq!(unknown.origin_attributes, None);
  }

  #[test]
  fn a_present_suffix_fills_all_four_typed_attributes_with_their_defaults() {
    for raw in ["", "^", "^partitionKey=%28https%2Ctop.example%29"] {
      let stored = StoredIsolation::from_context(&CookieContext {
        origin_attributes: Some(raw.to_owned()),
        ..CookieContext::default()
      });
      assert_eq!(stored.user_context_id, Some(0), "{raw:?}");
      assert_eq!(stored.private_browsing_id, Some(0), "{raw:?}");
      assert_eq!(
        stored.first_party_domain.as_deref(),
        Some(""),
        "{raw:?}: an omitted string attribute is the empty default"
      );
      assert_eq!(
        stored.gecko_view_session_context_id.as_deref(),
        Some(""),
        "{raw:?}"
      );
    }
  }

  #[test]
  fn a_known_name_with_an_unreadable_value_is_unknown_rather_than_default() {
    // The name is present, so the default fill must not claim it: reading
    // `userContextId=abc` as container 0 would put a row this build cannot
    // identify into the default container.
    for raw in [
      "^userContextId=abc",
      "^userContextId=2x",
      "^userContextId=4294967296",
      "^userContextId",
      "^userContextId=-1",
    ] {
      let parsed = parse_firefox_origin_attributes(raw);
      assert!(parsed.unknown_names, "{raw:?} must fail closed");
      assert_eq!(parsed.user_context_id, None, "{raw:?}");

      let stored = StoredIsolation::from_context(&CookieContext {
        origin_attributes: Some(raw.to_owned()),
        ..CookieContext::default()
      });
      assert_eq!(
        stored.user_context_id, None,
        "{raw:?}: unreadable is not the default container"
      );
      assert!(stored.unknown_origin_attributes, "{raw:?}");
      assert!(stored.is_opaque(), "{raw:?}: reachable only by naming it");
      assert_eq!(
        demanded_selectors(std::slice::from_ref(&stored)),
        vec![selector::ORIGIN_ATTRIBUTES],
        "{raw:?}"
      );
    }
  }

  #[test]
  fn a_session_json_value_of_the_wrong_type_also_fails_closed() {
    for raw in [
      r#"{"userContextId":-1}"#,
      r#"{"userContextId":true}"#,
      r#"{"privateBrowsingId":[1]}"#,
      r#"{"partitionKey":123}"#,
      r#"{"firstPartyDomain":5}"#,
      r#"{"geckoViewSessionContextId":false}"#,
    ] {
      let parsed = parse_firefox_origin_attributes(raw);
      assert!(parsed.unknown_names, "{raw} must fail closed");

      let stored = StoredIsolation::from_context(&CookieContext {
        origin_attributes: Some(raw.to_owned()),
        ..CookieContext::default()
      });
      // Opaque, not `Unpartitioned`: a `partitionKey` of the wrong JSON type
      // leaves no partition to compare, and reading that as "no partition"
      // would send the row into every context.
      assert!(stored.is_opaque(), "{raw}");
      assert_eq!(
        demanded_selectors(std::slice::from_ref(&stored)),
        vec![selector::ORIGIN_ATTRIBUTES],
        "{raw}"
      );
    }
    // A readable value of either accepted spelling still parses.
    assert_eq!(
      parse_firefox_origin_attributes(r#"{"userContextId":2}"#).user_context_id,
      Some(2)
    );
    assert_eq!(
      parse_firefox_origin_attributes(r#"{"userContextId":"2"}"#).user_context_id,
      Some(2)
    );
  }

  #[test]
  fn every_name_in_the_known_set_is_one_the_parser_reads() {
    // The parser matches each name explicitly; this is what keeps that match
    // and the documented set from drifting apart.
    for name in KNOWN_ORIGIN_ATTRIBUTES {
      let parsed = parse_firefox_origin_attributes(&format!("^{name}=x"));
      assert!(
        !parsed.unknown_names || name.ends_with("ContextId") || name.ends_with("Id"),
        "{name} should be recognized"
      );
    }
    // A value each name can actually hold parses cleanly.
    let parsed = parse_firefox_origin_attributes(
      "^userContextId=1&privateBrowsingId=1&partitionKey=x&firstPartyDomain=x\
       &geckoViewSessionContextId=x",
    );
    assert!(!parsed.unknown_names);
  }

  #[test]
  fn a_unicode_stored_host_matches_the_punycode_a_url_carries() {
    // Firefox writes the tuple host as the browser spelled it, which may be
    // Unicode, while `Url` always hands back punycode. Comparing the strings
    // as written would make one site into two.
    let unicode = firefox_partition_identity("(https,b\u{fc}cher.test)")
      .expect("a Unicode host is still a valid tuple");
    let punycode = firefox_partition_identity("(https,xn--bcher-kva.test)").expect("punycode");
    assert_eq!(unicode, punycode);
    assert_eq!(
      site_from_url("https://b\u{fc}cher.test/"),
      Some(site("https", "xn--bcher-kva.test")),
      "both sides reduce to the same host"
    );
    // A host with no canonical form makes the key unparsable rather than a
    // site that silently compares unequal to everything.
    assert_eq!(firefox_partition_identity("(https,exa mple.test)"), None);
  }

  #[test]
  fn an_ipv6_host_compares_by_address_not_by_spelling() {
    // `::1` and `0:0:0:0:0:0:0:1` are one address written two ways.
    let compressed = firefox_partition_identity("(https,[::1])").expect("compressed");
    let expanded = firefox_partition_identity("(https,[0:0:0:0:0:0:0:1])").expect("fully expanded");
    assert_eq!(compressed, expanded);
    assert_eq!(
      site_from_url("https://[0:0:0:0:0:0:0:1]/"),
      Some(site("https", "::1"))
    );
    // And two different addresses stay different.
    assert_ne!(
      firefox_partition_identity("(https,[::2])"),
      Some(compressed.clone())
    );
  }

  #[test]
  fn a_bracketed_ipv6_tuple_host_matches_the_unbracketed_url_host() {
    // The tuple brackets an IPv6 literal and `Url::host()` does not, so
    // without unwrapping here the two could never compare equal.
    assert_eq!(
      firefox_partition_identity("(https,[::1])"),
      Some(PartitionIdentity::Firefox {
        site: site("https", "::1"),
        port: None,
        foreign_by_ancestor: false,
      })
    );
    assert_eq!(
      site_from_url("https://[::1]/"),
      Some(site("https", "::1")),
      "both sides land on the same host spelling"
    );
  }

  #[test]
  fn a_supplied_selector_never_matches_an_unknown_stored_value() {
    assert!(!selector_excludes(None::<u32>, None));
    assert!(!selector_excludes(None::<u32>, Some(2)));
    assert!(selector_excludes(Some(2), None));
    assert!(selector_excludes(Some(2), Some(3)));
    assert!(!selector_excludes(Some(2), Some(2)));
  }

  #[test]
  fn demanded_tokens_follow_the_declared_order_and_skip_defaults() {
    let everything = StoredIsolation::from_context(&CookieContext {
      partition_key: Some("(https,top.example)".to_owned()),
      origin_attributes: Some(
        "^userContextId=3&privateBrowsingId=1&firstPartyDomain=example.org\
         &geckoViewSessionContextId=session-7&futureAttr=1"
          .to_owned(),
      ),
      ..CookieContext::default()
    });
    assert_eq!(
      demanded_selectors(std::slice::from_ref(&everything)),
      vec![
        selector::TOP_LEVEL_SITE,
        selector::USER_CONTEXT_ID,
        selector::PRIVATE_BROWSING_ID,
        selector::FIRST_PARTY_DOMAIN,
        selector::GECKO_VIEW_SESSION_CONTEXT_ID,
        selector::ORIGIN_ATTRIBUTES,
      ]
    );

    // Defaults demand nothing, which is what keeps `header` usable against
    // the many stores that predate these columns.
    let defaults = StoredIsolation::from_context(&CookieContext {
      origin_attributes: Some(String::new()),
      ..CookieContext::default()
    });
    assert!(demanded_selectors(std::slice::from_ref(&defaults)).is_empty());
    assert!(demanded_selectors(&[]).is_empty());

    // An unparsable key still demands the top-level site: it is not
    // unpartitioned, and there is no other way to disambiguate it.
    let unparsable = StoredIsolation::from_context(&CookieContext {
      partition_key: Some("not-a-tuple".to_owned()),
      ..CookieContext::default()
    });
    assert_eq!(
      demanded_selectors(std::slice::from_ref(&unparsable)),
      vec![selector::TOP_LEVEL_SITE]
    );
  }
}
