//! Crate-private Cookie request-header send-match (RFC 6265 / chrome.cookies).
//!
//! Not a public `get` API. `GetFilter` never changes a `ReadResult` snapshot;
//! PR 3's `ReadResult::header` applies it as a view only.

use crate::browser::cookie_record::DomainScope;
use crate::common::enums::Cookie;
use crate::RequestError;
use url::Url;

/// Post-filter for `header(url)`: RFC 6265 domain + path + Secure, then
/// omit empty names / CTL / forbidden Cookie octets.
#[derive(Debug)]
pub(crate) struct GetFilter {
  parsed: ParsedRequest,
}

#[derive(Debug)]
struct ParsedRequest {
  https: bool,
  host: String,
  path: String,
  trustworthy: bool,
}

impl GetFilter {
  pub(crate) fn for_url(url: &str) -> Result<Self, RequestError> {
    let parsed = parse_request_url(url)?;
    Ok(Self { parsed })
  }

  /// Whether `cookie` belongs in the Cookie request header for this URL.
  /// Row 17 (CTL / empty name / bad octets): omit, no warning here (PR 3).
  pub(crate) fn keeps(&self, cookie: &Cookie) -> bool {
    if !sendable_octets(&cookie.name, &cookie.value) {
      return false;
    }
    domain_matches(cookie, &self.parsed.host)
      && path_matches(cookie_path(&cookie.path), &self.parsed.path)
      && secure_matches(cookie.secure, self.parsed.https, self.parsed.trustworthy)
  }
}

/// The one comparison space for partition identity.
///
/// **`Site` is (scheme, host).** This crate has no public-suffix list and does
/// not gain one, so nothing is reduced to eTLD+1: `https://cdn.example.com`
/// and `https://app.example.com` are *cross-site* here and same-site to a
/// browser. That makes `SameSite=Lax`/`Strict` conservative -- it omits
/// cookies a browser would send, never the reverse -- which is the right
/// direction for a credential library. Adding a pinned PSL later is additive:
/// it only widens what matches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Site {
  scheme: String,
  host: String,
}

impl Site {
  fn new(scheme: &str, host: &str) -> Self {
    Self {
      scheme: scheme.to_ascii_lowercase(),
      host: host.trim_end_matches('.').to_ascii_lowercase(),
    }
  }
}

/// Parses a caller-supplied `http`/`https` URL into a [`Site`].
pub(crate) fn site_from_url(raw: &str) -> Option<Site> {
  let parsed = Url::parse(raw).ok()?;
  if parsed.scheme() != "http" && parsed.scheme() != "https" {
    return None;
  }
  let host = match parsed.host()? {
    url::Host::Domain(domain) => domain.to_owned(),
    url::Host::Ipv4(addr) => addr.to_string(),
    url::Host::Ipv6(addr) => addr.to_string(),
  };
  Some(Site::new(parsed.scheme(), &host))
}

/// Parses Firefox's `partitionKey`, e.g. `"(https,example.com)"`.
///
/// Trailing fields -- a port, the foreign-ancestor bit, anything a future
/// Firefox adds -- are **ignored for matching** and never cause a parse
/// failure: the tuple is an open vocabulary, and `origin_attributes` retains
/// the verbatim value for a caller who needs it. Comparing the raw tuple
/// against a `top_level_site` URL would match nothing, so every Firefox dFPI
/// cookie would vanish from every header.
pub(crate) fn site_from_firefox_partition_key(raw: &str) -> Option<Site> {
  let inner = raw.strip_prefix('(')?.strip_suffix(')')?;
  let mut fields = inner.split(',');
  let scheme = fields.next()?.trim();
  let host = fields.next()?.trim();
  if scheme.is_empty() || host.is_empty() {
    return None;
  }
  if scheme != "http" && scheme != "https" {
    return None;
  }
  Some(Site::new(scheme, host))
}

/// Parses Chromium's `top_frame_site_key`, which is stored either as a
/// serialized site or as a bare origin with a port.
pub(crate) fn site_from_chromium_top_frame_site_key(raw: &str) -> Option<Site> {
  let trimmed = raw.trim().trim_end_matches('/');
  if trimmed.is_empty() {
    return None;
  }
  let (scheme, rest) = trimmed.split_once("://")?;
  if scheme != "http" && scheme != "https" {
    return None;
  }
  // Chromium stores this column as a serialized *site* (no port) in some
  // versions and as a serialized *origin* (with a port) in others. A site has
  // no port, so dropping any trailing `:digits` is what makes the two
  // spellings compare equal rather than silently never matching.
  let host = match rest.rsplit_once(':') {
    Some((host, port)) if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) => {
      host
    }
    _ => rest,
  };
  let host = host.trim_start_matches('[').trim_end_matches(']');
  if host.is_empty() {
    return None;
  }
  Some(Site::new(scheme, host))
}

/// The partition identity one stored cookie declares, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PartitionIdentity {
  /// The row declares no partition. It is sent in every top-level context.
  Unpartitioned,
  /// The row declares a partition this build could normalize.
  Site(Site),
  /// The row declares a partition neither parser understood.
  ///
  /// Deliberately **not** folded into `Unpartitioned`: treating an
  /// unrecognized key as "no partition" would send a partitioned cookie into
  /// every context, which is precisely the merge this design exists to
  /// prevent. It is a non-match everywhere, and the loss is counted.
  Unparsable,
}

pub(crate) fn partition_identity(context: &crate::enums::CookieContext) -> PartitionIdentity {
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
    (Some(key), _) => site_from_chromium_top_frame_site_key(key)
      .map(PartitionIdentity::Site)
      .unwrap_or(PartitionIdentity::Unparsable),
    (None, Some(key)) => site_from_firefox_partition_key(key)
      .map(PartitionIdentity::Site)
      .unwrap_or(PartitionIdentity::Unparsable),
  }
}

/// Whether a `SameSite` value permits this send.
///
/// There is one same-site rule here, not a schemeful/legacy dual mode.
pub(crate) fn same_site_permits(
  same_site: i64,
  same_site_context: bool,
  navigation: bool,
  safe_method: bool,
) -> bool {
  match same_site {
    // Strict.
    2 => same_site_context,
    // None. `Secure` was already required at the RFC 6265 stage.
    0 => true,
    // Lax, and the unspecified encoding, which browsers default to Lax.
    // An encoding this build does not recognize also lands here rather than
    // being read as permission to send more.
    _ => same_site_context || (navigation && safe_method),
  }
}

/// Redact a caller URL for `InvalidUrl` / Debug. Never retains userinfo.
pub(crate) fn redact_url(raw: &str) -> String {
  if let Ok(parsed) = Url::parse(raw) {
    if parsed.scheme() == "http" || parsed.scheme() == "https" {
      let host = parsed.host_str().unwrap_or("");
      let path = if parsed.path().is_empty() {
        "/"
      } else {
        parsed.path()
      };
      return format!("{}://{host}{path}", parsed.scheme());
    }
  }
  redact_unparseable(raw)
}

fn redact_unparseable(raw: &str) -> String {
  let after_scheme = raw.find("://").map(|index| index + 3).unwrap_or(0);
  let scheme = if after_scheme > 0 {
    Some(&raw[..after_scheme - 3])
  } else {
    None
  };
  let rest = &raw[after_scheme..];
  let authority_end = rest.find('/').unwrap_or(rest.len());
  let authority = &rest[..authority_end];
  let stripped = if let Some(at) = authority.rfind('@') {
    &authority[at + 1..]
  } else {
    authority
  };
  let _ = stripped;
  match scheme {
    Some(scheme) if !scheme.is_empty() => format!("{scheme}://<unparseable>"),
    _ => "<unparseable>".to_owned(),
  }
}

fn parse_request_url(raw: &str) -> Result<ParsedRequest, RequestError> {
  let parsed = match Url::parse(raw) {
    Ok(parsed) => parsed,
    Err(_) => {
      return Err(RequestError::InvalidUrl {
        display: redact_url(raw),
      });
    }
  };
  if parsed.scheme() != "http" && parsed.scheme() != "https" {
    return Err(RequestError::InvalidUrl {
      display: redact_url(raw),
    });
  }
  let host = match parsed.host() {
    Some(url::Host::Domain(domain)) => domain.trim_end_matches('.').to_ascii_lowercase(),
    Some(url::Host::Ipv4(addr)) => addr.to_string(),
    Some(url::Host::Ipv6(addr)) => addr.to_string(),
    None => {
      return Err(RequestError::InvalidUrl {
        display: redact_url(raw),
      });
    }
  };
  let path = if parsed.path().is_empty() {
    "/".to_owned()
  } else {
    parsed.path().to_owned()
  };
  let trustworthy = parsed.scheme() == "https" || is_potentially_trustworthy_host(&host);
  Ok(ParsedRequest {
    https: parsed.scheme() == "https",
    host,
    path,
    trustworthy,
  })
}

fn is_potentially_trustworthy_host(host: &str) -> bool {
  host == "localhost" || host.ends_with(".localhost") || host == "127.0.0.1" || host == "::1"
}

fn cookie_path(path: &str) -> &str {
  if path.is_empty() {
    "/"
  } else {
    path
  }
}

fn domain_matches(cookie: &Cookie, request_host: &str) -> bool {
  let scope = DomainScope::from_stored(cookie.domain.clone());
  let compare = scope
    .raw()
    .strip_prefix('.')
    .unwrap_or(scope.raw())
    .trim_end_matches('.')
    .to_ascii_lowercase();
  if compare.is_empty() {
    return false;
  }
  if is_ip(&compare) || is_ip(request_host) {
    return request_host == compare;
  }
  match scope {
    DomainScope::HostOnly { .. } | DomainScope::Unknown { .. } => request_host == compare,
    DomainScope::Domain { .. } => {
      request_host == compare
        || (request_host.len() > compare.len()
          && request_host.ends_with(&compare)
          && request_host.as_bytes()[request_host.len() - compare.len() - 1] == b'.')
    }
  }
}

fn is_ip(host: &str) -> bool {
  host.parse::<std::net::Ipv4Addr>().is_ok() || host.parse::<std::net::Ipv6Addr>().is_ok()
}

fn path_matches(cookie_path: &str, request_path: &str) -> bool {
  if request_path == cookie_path {
    return true;
  }
  if !request_path.starts_with(cookie_path) {
    return false;
  }
  cookie_path.ends_with('/') || request_path.as_bytes().get(cookie_path.len()) == Some(&b'/')
}

fn secure_matches(secure: bool, https: bool, trustworthy: bool) -> bool {
  if !secure {
    return true;
  }
  https || trustworthy
}

pub(crate) fn sendable_octets(name: &str, value: &str) -> bool {
  if name.is_empty() {
    return false;
  }
  if has_ctl(name) || has_ctl(value) {
    return false;
  }
  is_token(name) && is_cookie_octet_sequence(value)
}

fn has_ctl(value: &str) -> bool {
  value
    .chars()
    .any(|ch| ('\u{0000}'..='\u{001F}').contains(&ch) || ch == '\u{007F}')
}

fn is_token(name: &str) -> bool {
  !name.is_empty()
    && name.bytes().all(|byte| {
      matches!(
        byte,
        b'!'
          | b'#'..=b'\''
          | b'*'
          | b'+'
          | b'-'
          | b'.'
          | b'0'..=b'9'
          | b'A'..=b'Z'
          | b'^'..=b'z'
          | b'|'
          | b'~'
      )
    })
}

fn is_cookie_octet_sequence(value: &str) -> bool {
  value.bytes().all(|byte| {
    matches!(
      byte,
      0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E
    )
  })
}

#[cfg(test)]
fn test_cookie(domain: &str, path: &str, secure: bool, name: &str, value: &str) -> Cookie {
  Cookie {
    domain: domain.to_owned(),
    path: path.to_owned(),
    secure,
    expires: None,
    name: name.to_owned(),
    value: value.to_owned(),
    http_only: false,
    same_site: -1,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn keeps(domain: &str, path: &str, secure: bool, url: &str) -> bool {
    GetFilter::for_url(url)
      .expect("valid url")
      .keeps(&test_cookie(domain, path, secure, "sid", "x"))
  }

  #[test]
  fn url_table_domain_and_path() {
    assert!(keeps(
      ".example.com",
      "/",
      false,
      "https://www.example.com/"
    ));
    assert!(keeps(".example.com", "/", false, "https://example.com/"));
    assert!(!keeps(
      "www.example.com",
      "/",
      false,
      "https://example.com/"
    ));
    assert!(!keeps(
      "example.com",
      "/",
      false,
      "https://www.example.com/"
    ));
    assert!(!keeps(
      "api.example.com",
      "/",
      false,
      "https://www.example.com/"
    ));
    assert!(!keeps(
      ".example.com",
      "/admin",
      false,
      "https://www.example.com/"
    ));
    assert!(keeps(
      ".example.com",
      "/admin",
      false,
      "https://www.example.com/admin"
    ));
    assert!(keeps(
      ".example.com",
      "/admin",
      false,
      "https://www.example.com/admin/"
    ));
    assert!(!keeps(
      ".example.com",
      "/admin",
      false,
      "https://www.example.com/administration"
    ));
  }

  #[test]
  fn url_table_secure_and_ip() {
    assert!(!keeps(".example.com", "/", true, "http://www.example.com/"));
    assert!(keeps(".example.com", "/", true, "https://www.example.com/"));
    assert!(keeps("localhost", "/", true, "http://localhost/"));
    assert!(keeps("127.0.0.1", "/", false, "http://127.0.0.1/"));
    assert!(keeps("::1", "/", true, "http://[::1]/"));
    assert!(keeps("::1", "/", false, "http://[::1]/foo"));
    assert!(!keeps(
      ".example.com",
      "/",
      false,
      "http://example.com.evil.net/"
    ));
    assert!(
      keeps("", "/", false, "https://example.com/x")
        || keeps("example.com", "", false, "https://example.com/x")
    );
    assert!(keeps("EXAMPLE.COM", "/", false, "https://example.com/"));
    assert!(keeps(".com", "/", false, "https://www.example.com/"));
  }

  #[test]
  fn empty_cookie_path_is_root() {
    assert!(keeps("example.com", "", false, "https://example.com/x"));
  }

  #[test]
  fn ftp_is_invalid_url() {
    let error = GetFilter::for_url("ftp://example.com/").expect_err("ftp");
    assert!(matches!(error, RequestError::InvalidUrl { .. }));
  }

  #[test]
  fn ctl_and_empty_name_are_omitted() {
    let filter = GetFilter::for_url("https://example.com/").expect("url");
    let crlf = test_cookie(".example.com", "/", false, "sid\r", "x");
    let empty = test_cookie(".example.com", "/", false, "", "x");
    let bad_value = test_cookie(".example.com", "/", false, "sid", "x\n");
    assert!(!filter.keeps(&crlf));
    assert!(!filter.keeps(&empty));
    assert!(!filter.keeps(&bad_value));
  }

  #[test]
  fn redaction_strips_userinfo() {
    let display = redact_url("https://user:secret@example.com/path?q=1#f");
    assert_eq!(display, "https://example.com/path");
    assert!(!display.contains("secret"));
    assert!(!display.contains("user"));
    let unparseable = redact_url("https://user:secret@%zz");
    assert!(!unparseable.contains("secret"));
    assert!(!unparseable.contains("user"));
    let error = RequestError::InvalidUrl {
      display: redact_url("https://user:secret@example.com/"),
    };
    let shown = format!("{error:?}{error}");
    assert!(!shown.contains("secret"));
    let error2 = RequestError::InvalidUrl {
      display: redact_url("https://user:secret@%zz"),
    };
    let shown2 = format!("{error2:?}{error2}");
    assert!(!shown2.contains("secret"));
  }
}
