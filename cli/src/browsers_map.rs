use lazy_static::lazy_static;
use std::collections::BTreeSet;

/// The legacy `--browser <name>` allowlist and its exact registry IDs.
///
/// Each name here doubles as the canonical browser ID
/// `rookie_cookies::extract`/`Request::browser` resolves, so dispatch needs
/// no separate function-pointer table: `chrome()`/`firefox()`/etc. already
/// delegate to exactly that path (`named_browser` -> `browser` -> `extract`),
/// so calling `extract` directly with one of these names is behaviorally
/// identical and additionally supports a timeout and cancellation, which the
/// individual named functions' frozen signatures cannot.
// The binary test harness does not invoke `main`, so the otherwise-live set
// construction appears unused only when Cargo builds the bin as a test target.
#[cfg_attr(test, allow(dead_code))]
fn browsers_map() -> BTreeSet<&'static str> {
  let mut set = BTreeSet::new();

  set.insert("brave");

  #[cfg(target_os = "linux")]
  set.insert("cachy");

  set.insert("chromium");
  set.insert("chrome");
  set.insert("edge");
  set.insert("firefox");
  set.insert("zen");

  #[cfg(target_os = "windows")]
  {
    set.insert("internet_explorer");
    set.insert("octo_browser");
  }
  set.insert("librewolf");
  set.insert("opera");

  #[cfg(any(target_os = "macos", target_os = "windows"))]
  set.insert("opera_gx");

  #[cfg(target_os = "macos")]
  set.insert("safari");

  set.insert("vivaldi");

  set.insert("arc");

  set
}

lazy_static! {
  pub static ref BROWSERS_MAP: BTreeSet<&'static str> = browsers_map();
}
