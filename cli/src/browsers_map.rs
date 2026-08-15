use lazy_static::lazy_static;
use rookie_cookies::{self, enums::Cookie, Result};
use std::collections::BTreeMap;

// The binary test harness does not invoke `main`, so the otherwise-live map
// construction appears unused only when Cargo builds the bin as a test target.
#[cfg_attr(test, allow(dead_code))]
type BrowserFn = fn(Option<Vec<String>>) -> Result<Vec<Cookie>>;

#[cfg_attr(test, allow(dead_code))]
fn browsers_map() -> BTreeMap<&'static str, BrowserFn> {
  let mut map = BTreeMap::new();

  map.insert("brave", rookie_cookies::brave as BrowserFn);

  #[cfg(target_os = "linux")]
  map.insert("cachy", rookie_cookies::cachy as BrowserFn);

  map.insert("chromium", rookie_cookies::chromium as BrowserFn);
  map.insert("chrome", rookie_cookies::chrome as BrowserFn);
  map.insert("edge", rookie_cookies::edge as BrowserFn);
  map.insert("firefox", rookie_cookies::firefox as BrowserFn);
  map.insert("zen", rookie_cookies::zen as BrowserFn);

  #[cfg(target_os = "windows")]
  {
    map.insert(
      "internet_explorer",
      rookie_cookies::internet_explorer as BrowserFn,
    );
    map.insert("octo_browser", rookie_cookies::octo_browser as BrowserFn);
  }
  map.insert("librewolf", rookie_cookies::librewolf as BrowserFn);
  map.insert("opera", rookie_cookies::opera as BrowserFn);

  #[cfg(any(target_os = "macos", target_os = "windows"))]
  map.insert("opera_gx", rookie_cookies::opera_gx as BrowserFn);

  #[cfg(target_os = "macos")]
  map.insert("safari", rookie_cookies::safari as BrowserFn);

  map.insert("vivaldi", rookie_cookies::vivaldi as BrowserFn);

  map.insert("arc", rookie_cookies::arc as BrowserFn);

  map
}

lazy_static! {
  pub static ref BROWSERS_MAP: BTreeMap<&'static str, BrowserFn> = browsers_map();
}
