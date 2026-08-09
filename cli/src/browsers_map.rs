use lazy_static::lazy_static;
use rookie_cookies::{self, enums::Cookie, Result};
use std::collections::HashMap;

type BrowserFn = fn(Option<Vec<String>>) -> Result<Vec<Cookie>>;

lazy_static! {
  pub static ref BROWSERS_MAP: HashMap<String, BrowserFn> = {
    let mut map: HashMap<String, BrowserFn> = HashMap::default();

    map.insert("brave".into(), rookie_cookies::brave);

    #[cfg(target_os = "linux")]
    map.insert("cachy".into(), rookie_cookies::cachy);

    map.insert("chromium".into(), rookie_cookies::chromium);
    map.insert("chrome".into(), rookie_cookies::chrome);
    map.insert("edge".into(), rookie_cookies::edge);
    map.insert("firefox".into(), rookie_cookies::firefox);
    map.insert("zen".into(), rookie_cookies::zen);

    #[cfg(target_os = "windows")]
    map.insert(
      "internet_explorer".into(),
      rookie_cookies::internet_explorer,
    );
    map.insert("librewolf".into(), rookie_cookies::librewolf);
    map.insert("opera".into(), rookie_cookies::opera);
    map.insert("opera gx".into(), rookie_cookies::opera_gx);

    #[cfg(target_os = "macos")]
    map.insert("safari".into(), rookie_cookies::safari);

    map.insert("vivaldi".into(), rookie_cookies::vivaldi);

    map.insert("arc".into(), rookie_cookies::arc);

    map
  };
}

lazy_static! {
  pub static ref BROWSERS_MAP_KEYS: Vec<&'static str> = {
    let keys = BROWSERS_MAP.keys();
    keys.map(|s| s.as_str()).collect()
  };
}
