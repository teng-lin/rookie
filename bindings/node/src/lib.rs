#[macro_use]
extern crate napi_derive;

use napi::{bindgen_prelude::AsyncTask, Result, Status, Task};
use rookie_cookies::enums::Cookie;
use rookie_cookies::MozillaProfile;
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

#[napi(object)]
pub struct FirefoxProfileObject {
  pub name: String,
  pub path: String,
  pub is_default: bool,
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

fn profiles_to_js(profiles: Vec<MozillaProfile>) -> Vec<FirefoxProfileObject> {
  profiles
    .into_iter()
    .map(|profile| FirefoxProfileObject {
      name: profile.name,
      path: profile.path.to_string_lossy().into_owned(),
      is_default: profile.is_default,
    })
    .collect()
}

// ---------------------------------------------------------------------------
// AnyBrowser needs special handling (db_path, domains, key_path)
// ---------------------------------------------------------------------------

pub struct AnyBrowserTaskImpl {
  db_path: String,
  domains: Option<Vec<String>>,
  key_path: Option<String>,
}

impl Task for AnyBrowserTaskImpl {
  type Output = Vec<Cookie>;
  type JsValue = Vec<CookieObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    rookie_cookies::any_browser(&self.db_path, self.domains.take(), self.key_path.as_deref())
      .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    cookies_to_js(output)
  }
}

#[napi(ts_return_type = "Promise<Array<CookieObject>>")]
pub fn any_browser(
  db_path: String,
  domains: Option<Vec<String>>,
  key_path: Option<String>,
) -> AsyncTask<AnyBrowserTaskImpl> {
  AsyncTask::new(AnyBrowserTaskImpl {
    db_path,
    domains,
    key_path,
  })
}

// ---------------------------------------------------------------------------
// Macro for single-arg (domains) async browser functions
// ---------------------------------------------------------------------------
macro_rules! async_browser_fn {
  ($name:ident, $task_name:ident, $core_fn:expr) => {
    pub struct $task_name {
      domains: Option<Vec<String>>,
    }

    impl Task for $task_name {
      type Output = Vec<Cookie>;
      type JsValue = Vec<CookieObject>;

      fn compute(&mut self) -> Result<Self::Output> {
        $core_fn(self.domains.take())
          .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))
      }

      fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
        cookies_to_js(output)
      }
    }

    #[napi(ts_return_type = "Promise<Array<CookieObject>>")]
    pub fn $name(domains: Option<Vec<String>>) -> AsyncTask<$task_name> {
      AsyncTask::new($task_name { domains })
    }
  };
}

// Common browsers

async_browser_fn!(firefox, FirefoxTask, rookie_cookies::firefox);
async_browser_fn!(zen, ZenTask, rookie_cookies::zen);
async_browser_fn!(librewolf, LibrewolfTask, rookie_cookies::librewolf);
async_browser_fn!(chrome, ChromeTask, rookie_cookies::chrome);
async_browser_fn!(brave, BraveTask, rookie_cookies::brave);
async_browser_fn!(arc, ArcTask, rookie_cookies::arc);
async_browser_fn!(edge, EdgeTask, rookie_cookies::edge);
async_browser_fn!(opera, OperaTask, rookie_cookies::opera);
async_browser_fn!(opera_gx, OperaGxTask, rookie_cookies::opera_gx);
async_browser_fn!(chromium, ChromiumTask, rookie_cookies::chromium);
async_browser_fn!(vivaldi, VivaldiTask, rookie_cookies::vivaldi);
async_browser_fn!(load, LoadTask, rookie_cookies::load);

pub struct FirefoxProfilesTask;

impl Task for FirefoxProfilesTask {
  type Output = Vec<MozillaProfile>;
  type JsValue = Vec<FirefoxProfileObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    rookie_cookies::firefox_profiles()
      .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(profiles_to_js(output))
  }
}

#[napi(ts_return_type = "Promise<Array<FirefoxProfileObject>>")]
pub fn firefox_profiles() -> AsyncTask<FirefoxProfilesTask> {
  AsyncTask::new(FirefoxProfilesTask)
}

pub struct FirefoxProfileTask {
  profile: String,
  domains: Option<Vec<String>>,
}

impl Task for FirefoxProfileTask {
  type Output = Vec<Cookie>;
  type JsValue = Vec<CookieObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    rookie_cookies::firefox_profile(&self.profile, self.domains.take())
      .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    cookies_to_js(output)
  }
}

#[napi(ts_return_type = "Promise<Array<CookieObject>>")]
pub fn firefox_profile(
  profile: String,
  domains: Option<Vec<String>>,
) -> AsyncTask<FirefoxProfileTask> {
  AsyncTask::new(FirefoxProfileTask { profile, domains })
}

// firefox_based takes an extra db_path argument
pub struct FirefoxBasedTask {
  db_path: String,
  domains: Option<Vec<String>>,
}

impl Task for FirefoxBasedTask {
  type Output = Vec<Cookie>;
  type JsValue = Vec<CookieObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    rookie_cookies::firefox_based(PathBuf::from(&self.db_path), self.domains.take())
      .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    cookies_to_js(output)
  }
}

#[napi(ts_return_type = "Promise<Array<CookieObject>>")]
pub fn firefox_based(db_path: String, domains: Option<Vec<String>>) -> AsyncTask<FirefoxBasedTask> {
  AsyncTask::new(FirefoxBasedTask { db_path, domains })
}

// Windows only browsers

#[napi(ts_return_type = "Promise<Array<CookieObject>>")]
#[cfg(target_os = "windows")]
pub fn octo_browser(domains: Option<Vec<String>>) -> AsyncTask<OctoBrowserTask> {
  AsyncTask::new(OctoBrowserTask { domains })
}

#[cfg(target_os = "windows")]
pub struct OctoBrowserTask {
  domains: Option<Vec<String>>,
}

#[cfg(target_os = "windows")]
impl Task for OctoBrowserTask {
  type Output = Vec<Cookie>;
  type JsValue = Vec<CookieObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    rookie_cookies::octo_browser(self.domains.take())
      .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    cookies_to_js(output)
  }
}

#[napi(ts_return_type = "Promise<Array<CookieObject>>")]
#[cfg(target_os = "windows")]
pub fn internet_explorer(domains: Option<Vec<String>>) -> AsyncTask<InternetExplorerTask> {
  AsyncTask::new(InternetExplorerTask { domains })
}

#[cfg(target_os = "windows")]
pub struct InternetExplorerTask {
  domains: Option<Vec<String>>,
}

#[cfg(target_os = "windows")]
impl Task for InternetExplorerTask {
  type Output = Vec<Cookie>;
  type JsValue = Vec<CookieObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    rookie_cookies::internet_explorer(self.domains.take())
      .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    cookies_to_js(output)
  }
}

#[cfg(target_os = "windows")]
pub struct ChromiumBasedWinTask {
  key_path: String,
  db_path: String,
  domains: Option<Vec<String>>,
}

#[cfg(target_os = "windows")]
impl Task for ChromiumBasedWinTask {
  type Output = Vec<Cookie>;
  type JsValue = Vec<CookieObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    rookie_cookies::chromium_based(
      PathBuf::from(&self.key_path),
      PathBuf::from(&self.db_path),
      self.domains.take(),
      false,
    )
    .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    cookies_to_js(output)
  }
}

#[napi(ts_return_type = "Promise<Array<CookieObject>>")]
#[cfg(target_os = "windows")]
pub fn chromium_based(
  key_path: String,
  db_path: String,
  domains: Option<Vec<String>>,
) -> AsyncTask<ChromiumBasedWinTask> {
  AsyncTask::new(ChromiumBasedWinTask {
    key_path,
    db_path,
    domains,
  })
}

// MacOS browsers

#[napi(ts_return_type = "Promise<Array<CookieObject>>")]
#[cfg(target_os = "macos")]
pub fn safari(domains: Option<Vec<String>>) -> AsyncTask<SafariTask> {
  AsyncTask::new(SafariTask { domains })
}

#[cfg(target_os = "macos")]
pub struct SafariTask {
  domains: Option<Vec<String>>,
}

#[cfg(target_os = "macos")]
impl Task for SafariTask {
  type Output = Vec<Cookie>;
  type JsValue = Vec<CookieObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    rookie_cookies::safari(self.domains.take())
      .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    cookies_to_js(output)
  }
}

// Unix browsers

#[cfg(unix)]
pub struct ChromiumBasedUnixTask {
  db_path: String,
  domains: Option<Vec<String>>,
}

#[cfg(unix)]
impl Task for ChromiumBasedUnixTask {
  type Output = Vec<Cookie>;
  type JsValue = Vec<CookieObject>;

  fn compute(&mut self) -> Result<Self::Output> {
    use rookie_cookies::config::Browser;

    let db_path = self.db_path.as_str();
    let config = Browser {
      channels: None,
      paths: vec![db_path.to_string()],
      unix_crypt_name: Some("chrome".to_string()),
      osx_key_service: None,
      osx_key_user: None,
    };
    rookie_cookies::chromium_based(&config, PathBuf::from(db_path), self.domains.take(), false)
      .map_err(|e| napi::Error::new(Status::Unknown, format!("{e:?}")))
  }

  fn resolve(&mut self, _: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    cookies_to_js(output)
  }
}

#[napi(ts_return_type = "Promise<Array<CookieObject>>")]
#[cfg(unix)]
pub fn chromium_based(
  db_path: String,
  domains: Option<Vec<String>>,
) -> AsyncTask<ChromiumBasedUnixTask> {
  AsyncTask::new(ChromiumBasedUnixTask { db_path, domains })
}
