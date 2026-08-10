/// Check if a cookie host/domain matches a requested target domain.
/// Performs exact match, subdomain match (with dot boundary), or prefix match if target domain starts with dot.
/// E.g.:
/// - host "example.com" or ".example.com" matches domain "example.com" or ".example.com"
/// - host "sub.example.com" or ".sub.example.com" matches domain "example.com"
/// - host "example.com.evil.net" does NOT match domain "example.com"
pub fn host_matches_domain(host: &str, target_domain: &str) -> bool {
  let h = host.strip_prefix('.').unwrap_or(host);
  let d = target_domain.strip_prefix('.').unwrap_or(target_domain);

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

    // Case insensitive
    assert!(host_matches_domain("EXAMPLE.COM", "example.com"));
    assert!(host_matches_domain("sub.EXAMPLE.com", "Example.Com"));

    // False cases
    assert!(!host_matches_domain("example.com.evil.net", "example.com"));
    assert!(!host_matches_domain("notexample.com", "example.com"));
    assert!(!host_matches_domain("example.com", "sub.example.com"));
  }
}
