use serde::{Deserialize, Serialize};

/// Value of [`Cookie::same_site`] when the source store records no SameSite
/// attribute. Matches the encoding Chromium uses for an unspecified attribute,
/// which this crate already passes through untouched.
pub const SAME_SITE_UNSPECIFIED: i64 = -1;

#[derive(Serialize, Deserialize, Debug)]
pub struct Cookie {
  pub domain: String,
  pub path: String,
  pub secure: bool,
  pub expires: Option<u64>,
  pub name: String,
  pub value: String,
  pub http_only: bool,
  /// Raw SameSite encoding from the source browser: `0` None, `1` Lax,
  /// `2` Strict, [`SAME_SITE_UNSPECIFIED`] when the store records none.
  pub same_site: i64,
}

/// Browser context that participates in a cookie's identity but cannot be
/// represented by the compatibility [`Cookie`] type.
///
/// Every field is optional because cookie schemas vary across browser versions
/// and engines. A missing field means the source did not expose that context;
/// it must not be interpreted as the browser's default partition or container.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CookieContext {
  /// Chromium CHIPS partition key (`top_frame_site_key`).
  pub top_frame_site_key: Option<String>,
  /// Whether Chromium recorded a cross-site ancestor for this partition.
  pub has_cross_site_ancestor: Option<bool>,
  /// Chromium's raw `source_scheme` enum value.
  pub source_scheme: Option<i64>,
  /// Chromium's raw source port. Sentinel values such as `-1` are preserved.
  pub source_port: Option<i64>,
  /// Chromium's stored persistence bit, when that column exists.
  pub is_persistent: Option<bool>,
  /// Firefox's complete `originAttributes` value.
  ///
  /// Persistent-cookie suffixes are retained verbatim. Session-store objects
  /// are retained as JSON, so attributes introduced by a future Firefox
  /// release survive even when this crate does not yet parse them.
  pub origin_attributes: Option<String>,
  /// Firefox Multi-Account Containers identity (`userContextId`).
  pub user_context_id: Option<u32>,
  /// Firefox dynamic first-party partition key (`partitionKey`).
  pub partition_key: Option<String>,
  /// Firefox private-browsing identity (`privateBrowsingId`).
  pub private_browsing_id: Option<u32>,
}

/// A lossless cookie record for callers that need partition/container identity.
///
/// [`Cookie`] remains the stable compatibility projection used by all existing
/// extraction functions and formatters. Detailed extraction functions return
/// this additive type instead; [`DetailedCookie::into_cookie`] deliberately
/// discards the context and yields that legacy projection.
#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug)]
pub struct DetailedCookie {
  pub cookie: Cookie,
  pub context: CookieContext,
}

impl DetailedCookie {
  /// Borrows the unchanged compatibility cookie fields.
  pub fn cookie(&self) -> &Cookie {
    &self.cookie
  }

  /// Discards partition/container context and returns the legacy projection.
  pub fn into_cookie(self) -> Cookie {
    self.cookie
  }
}

pub trait CookieToString {
  fn to_string(&self) -> String;
}

impl CookieToString for Vec<Cookie> {
  fn to_string(&self) -> String {
    self
      .iter()
      .map(|cookie| format!("{}={}", cookie.name, cookie.value))
      .collect::<Vec<String>>()
      .join(";")
  }
}
