/// Check if a cookie host/domain matches a requested target domain.
///
/// Matching is one-directional: a request for `example.com` includes cookies
/// for that exact host and its subdomains, but a request for
/// `sub.example.com` does not include cookies for the parent. A leading cookie
/// storage dot and a single trailing absolute-DNS dot are ignored. Empty or
/// whitespace-only requested domains never match.
/// E.g.:
/// - host "example.com" or ".example.com" matches domain "example.com" or ".example.com"
/// - host "sub.example.com" or ".sub.example.com" matches domain "example.com"
/// - host "example.com.evil.net" does NOT match domain "example.com"
pub fn host_matches_domain(host: &str, target_domain: &str) -> bool {
  let Some(h) = normalized_domain_for_match(host) else {
    return false;
  };
  let Some(d) = normalized_domain_for_match(target_domain) else {
    return false;
  };

  if h.eq_ignore_ascii_case(d) {
    return true;
  }

  if h.len() > d.len() && h.as_bytes()[h.len() - d.len() - 1] == b'.' {
    let suffix = &h[h.len() - d.len()..];
    if suffix.eq_ignore_ascii_case(d) {
      return true;
    }
  }

  false
}

/// Normalize the storage markers accepted by [`host_matches_domain`].
///
/// SQL-backed adapters use this key only to reduce their candidate set; they
/// must still apply [`host_matches_domain`] to every returned row.
pub(crate) fn normalized_domain_for_match(value: &str) -> Option<&str> {
  let value = value.strip_prefix('.').unwrap_or(value);
  let value = value.strip_suffix('.').unwrap_or(value);
  if value.is_empty() || value.trim().is_empty() {
    None
  } else {
    Some(value)
  }
}

pub fn some_domain_in_host(domains: Option<&[String]>, host: &str) -> bool {
  if let Some(strings) = domains {
    for d in strings {
      if host_matches_domain(host, d) {
        return true;
      }
    }
    false
  } else {
    true
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_host_matches_domain() {
    assert!(host_matches_domain("example.com", "example.com"));
    assert!(host_matches_domain(".example.com", "example.com"));
    assert!(host_matches_domain("example.com", ".example.com"));
    assert!(host_matches_domain(".example.com", ".example.com"));
    assert!(host_matches_domain("sub.example.com", "example.com"));
    assert!(host_matches_domain(".sub.example.com", "example.com"));
    assert!(host_matches_domain("example.com.", "example.com"));
    assert!(host_matches_domain(".sub.example.com.", ".example.com."));

    // Case insensitive
    assert!(host_matches_domain("EXAMPLE.COM", "example.com"));
    assert!(host_matches_domain("sub.EXAMPLE.com", "Example.Com"));

    // False cases
    assert!(!host_matches_domain("example.com.evil.net", "example.com"));
    assert!(!host_matches_domain(
      "example.com.evil.net.",
      "example.com."
    ));
    assert!(!host_matches_domain("notexample.com", "example.com"));
    assert!(!host_matches_domain("example.com", "sub.example.com"));
    assert!(!host_matches_domain("", ""));
    assert!(!host_matches_domain("", "example.com"));
    assert!(!host_matches_domain("example.com", ""));
    assert!(!host_matches_domain("example.com", " \t "));
    assert!(!host_matches_domain(".", "."));
  }
}
