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
