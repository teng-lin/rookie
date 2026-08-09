#[macro_use]
extern crate napi_derive;

use napi::{Result, Status};
use rookie_cookies::enums::Cookie;
use std::path::PathBuf;

#[napi(object)]
pub struct CookieObject {
  pub domain: String,
  pub path: String,
  pub secure: bool,
  pub expires: Option<i64>,
  pub name: String,
  pub value: String,
  pub http_only: bool,
  pub same_site: i64,
}

#[napi]
pub fn version() -> Result<String> {
  Ok(rookie_cookies::version())
}

fn cookies_to_js(cookies: Vec<Cookie>) -> Result<Vec<CookieObject>> {
  let mut js_cookies: Vec<CookieObject> = vec![];
  for cookie in cookies {
    js_cookies.push(CookieObject {
      domain: cookie.domain,
      path: cookie.path,
      secure: cookie.secure,
      http_only: cookie.http_only,
      same_site: cookie.same_site,
      expires: cookie.expires.map(|v| v as i64),
      name: cookie.name,
      value: cookie.value,
    });
  }

  Ok(js_cookies)
}

#[napi]
pub fn any_browser(
  db_path: String,
  domains: Option<Vec<String>>,
  key_path: Option<&str>,
) -> Result<Vec<CookieObject>> {
  let cookies = rookie_cookies::any_browser(&db_path, domains, key_path)
    .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))?;
  cookies_to_js(cookies)
}

/// Common browsers

#[napi]
pub fn firefox(domains: Option<Vec<String>>) -> Result<Vec<CookieObject>> {
  let cookies = rookie_cookies::firefox(domains)
    .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))?;
  cookies_to_js(cookies)
}

#[napi]
pub fn zen(domains: Option<Vec<String>>) -> Result<Vec<CookieObject>> {
  let cookies = rookie_cookies::zen(domains)
    .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))?;
  cookies_to_js(cookies)
}

#[napi]
pub fn librewolf(domains: Option<Vec<String>>) -> Result<Vec<CookieObject>> {
  let cookies = rookie_cookies::librewolf(domains)
    .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))?;
  cookies_to_js(cookies)
}

#[napi]
pub fn chrome(domains: Option<Vec<String>>) -> Result<Vec<CookieObject>> {
  let cookies = rookie_cookies::chrome(domains)
    .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))?;
  cookies_to_js(cookies)
}

#[napi]
pub fn brave(domains: Option<Vec<String>>) -> Result<Vec<CookieObject>> {
  let cookies = rookie_cookies::brave(domains)
    .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))?;

  cookies_to_js(cookies)
}

#[napi]
pub fn arc(domains: Option<Vec<String>>) -> Result<Vec<CookieObject>> {
  let cookies = rookie_cookies::arc(domains)
    .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))?;

  cookies_to_js(cookies)
}

#[napi]
pub fn edge(domains: Option<Vec<String>>) -> Result<Vec<CookieObject>> {
  let cookies = rookie_cookies::edge(domains)
    .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))?;
  cookies_to_js(cookies)
}

#[napi]
pub fn opera(domains: Option<Vec<String>>) -> Result<Vec<CookieObject>> {
  let cookies = rookie_cookies::opera(domains)
    .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))?;

  cookies_to_js(cookies)
}

#[napi]
pub fn opera_gx(domains: Option<Vec<String>>) -> Result<Vec<CookieObject>> {
  let cookies = rookie_cookies::opera_gx(domains)
    .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))?;

  cookies_to_js(cookies)
}

#[napi]
pub fn chromium(domains: Option<Vec<String>>) -> Result<Vec<CookieObject>> {
  let cookies = rookie_cookies::chromium(domains)
    .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))?;
  cookies_to_js(cookies)
}

#[napi]
pub fn vivaldi(domains: Option<Vec<String>>) -> Result<Vec<CookieObject>> {
  let cookies = rookie_cookies::vivaldi(domains)
    .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))?;

  cookies_to_js(cookies)
}

#[napi]
pub fn firefox_based(db_path: String, domains: Option<Vec<String>>) -> Result<Vec<CookieObject>> {
  let cookies = rookie_cookies::firefox_based(PathBuf::from(db_path), domains)
    .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))?;
  cookies_to_js(cookies)
}

#[napi]
pub fn load(domains: Option<Vec<String>>) -> Result<Vec<CookieObject>> {
  let cookies = rookie_cookies::load(domains)
    .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))?;
  cookies_to_js(cookies)
}

/// Windows only browsers

#[napi]
#[cfg(target_os = "windows")]
pub fn octo_browser(domains: Option<Vec<String>>) -> Result<Vec<CookieObject>> {
  let cookies = rookie_cookies::octo_browser(domains)
    .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))?;

  cookies_to_js(cookies)
}

#[napi]
#[cfg(target_os = "windows")]
pub fn internet_explorer(domains: Option<Vec<String>>) -> Result<Vec<CookieObject>> {
  let cookies = rookie_cookies::internet_explorer(domains)
    .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))?;
  cookies_to_js(cookies)
}
#[napi]
#[cfg(target_os = "windows")]
pub fn chromium_based(
  key_path: String,
  db_path: String,
  domains: Option<Vec<String>>,
) -> Result<Vec<CookieObject>> {
  let cookies =
    rookie_cookies::chromium_based(PathBuf::from(key_path), PathBuf::from(db_path), domains)
      .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))?;
  cookies_to_js(cookies)
}

/// MacOS browsers

#[napi]
#[cfg(target_os = "macos")]
pub fn safari(domains: Option<Vec<String>>) -> Result<Vec<CookieObject>> {
  let cookies = rookie_cookies::safari(domains)
    .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))?;
  cookies_to_js(cookies)
}

/// Unix browsers

#[napi]
#[cfg(unix)]
pub fn chromium_based(db_path: String, domains: Option<Vec<String>>) -> Result<Vec<CookieObject>> {
  use rookie_cookies::config::Browser;

  let db_path = db_path.as_str();
  let config = Browser {
    channels: None,
    paths: vec![db_path.to_string()],
    unix_crypt_name: Some("chrome".to_string()),
    osx_key_service: None,
    osx_key_user: None,
  };
  let cookies = rookie_cookies::chromium_based(&config, PathBuf::from(db_path), domains)
    .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))?;
  cookies_to_js(cookies)
}
