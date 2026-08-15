//! Compatibility gates for the public Rust surface and legacy wire formats.
//!
//! Integration tests compile as a downstream crate, so constructing these
//! types here catches source breaks that an in-module unit test would miss.

use once_cell::sync::Lazy;
use rookie_cookies::common::format;
use rookie_cookies::config::{
  get_browser_config, try_get_browser_config, Browser, BrowsersMap, Config, CONFIG,
};
use rookie_cookies::enums::{
  Cookie, CookieContext, CookieToString, DetailedCookie, SAME_SITE_UNSPECIFIED,
};
use rookie_cookies::report::{
  BrowserDescriptor, ExtractionReport, IssueCode, ProfileDescriptor, ReportStatusCode,
};
use rookie_cookies::MozillaProfile;
use rookie_cookies::Result;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr;

type BrowserFn = fn(Option<Vec<String>>) -> Result<Vec<Cookie>>;

#[cfg_attr(target_os = "linux", allow(deprecated))]
const COMMON_BROWSER_SELECTORS: &[(&str, BrowserFn)] = &[
  ("arc", rookie_cookies::arc),
  ("brave", rookie_cookies::brave),
  ("chrome", rookie_cookies::chrome),
  ("chromium", rookie_cookies::chromium),
  ("edge", rookie_cookies::edge),
  ("firefox", rookie_cookies::firefox),
  ("librewolf", rookie_cookies::librewolf),
  ("opera", rookie_cookies::opera),
  ("opera_gx", rookie_cookies::opera_gx),
  ("vivaldi", rookie_cookies::vivaldi),
  ("zen", rookie_cookies::zen),
];

#[cfg(target_os = "linux")]
const PLATFORM_BROWSER_SELECTORS: &[(&str, BrowserFn)] = &[("cachy", rookie_cookies::cachy)];

#[cfg(target_os = "macos")]
const PLATFORM_BROWSER_SELECTORS: &[(&str, BrowserFn)] = &[("safari", rookie_cookies::safari)];

#[cfg(target_os = "windows")]
const PLATFORM_BROWSER_SELECTORS: &[(&str, BrowserFn)] = &[
  ("internet_explorer", rookie_cookies::internet_explorer),
  ("octo_browser", rookie_cookies::octo_browser),
];

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
const PLATFORM_BROWSER_SELECTORS: &[(&str, BrowserFn)] = &[];

fn read_mozilla_profile_fields(profile: &MozillaProfile) -> (&String, &PathBuf, bool) {
  (&profile.name, &profile.path, profile.is_default)
}

fn result_reexport_identity(value: rookie_cookies::anyhow::Result<()>) -> Result<()> {
  value
}

fn cookie() -> Cookie {
  Cookie {
    domain: ".example.test".to_string(),
    path: "/account".to_string(),
    secure: true,
    expires: Some(1_700_000_000),
    name: "session".to_string(),
    value: "abc123".to_string(),
    http_only: true,
    same_site: 1,
  }
}

#[test]
fn public_cookie_and_config_types_remain_constructible() {
  let sample = cookie();
  assert_eq!(sample.domain, ".example.test");
  assert_eq!(SAME_SITE_UNSPECIFIED, -1);
  assert_eq!(vec![cookie()].to_string(), "session=abc123");

  let browser = Browser {
    paths: vec!["/profiles/Default/Cookies".to_string()],
    channels: Some(vec!["stable".to_string()]),
    unix_crypt_name: Some("chrome".to_string()),
    osx_key_service: Some("Chrome Safe Storage".to_string()),
    osx_key_user: Some("Chrome".to_string()),
  };
  let mut browsers: BrowsersMap = HashMap::new();
  browsers.insert("fixture".to_string(), browser);
  let mut platforms = HashMap::new();
  platforms.insert("fixture-os".to_string(), browsers);
  let config = Config { platforms };

  assert_eq!(
    config.platforms["fixture-os"]["fixture"].paths,
    ["/profiles/Default/Cookies"]
  );

  let embedded: &Lazy<Config> = &CONFIG;
  assert!(!embedded.platforms.is_empty());
  assert!(!get_browser_config("firefox").paths.is_empty());
  assert!(try_get_browser_config("firefox").is_some());
  assert!(try_get_browser_config("not-a-browser").is_none());
}

#[test]
fn detailed_cookie_is_additive_and_projects_to_the_unchanged_cookie() {
  let context = CookieContext::default();
  assert_eq!(context.top_frame_site_key, None);
  assert_eq!(context.origin_attributes, None);

  let detailed: DetailedCookie = serde_json::from_value(serde_json::json!({
    "cookie": {
      "domain": ".example.test",
      "path": "/",
      "secure": false,
      "expires": null,
      "name": "session",
      "value": "value",
      "http_only": true,
      "same_site": 1
    },
    "context": {
      "top_frame_site_key": "https://top.example",
      "has_cross_site_ancestor": false,
      "source_scheme": 2,
      "source_port": 443,
      "is_persistent": true,
      "origin_attributes": null,
      "user_context_id": null,
      "partition_key": null,
      "private_browsing_id": null
    }
  }))
  .expect("deserialize detailed cookie");
  assert_eq!(detailed.cookie().name, "session");
  let projected = detailed.into_cookie();
  assert_eq!(projected.name, "session");
  assert_eq!(vec![projected].to_string(), "session=value");
}

#[test]
fn public_function_signatures_remain_compatible() {
  type FirefoxProfileFn = fn(&str, Option<Vec<String>>) -> Result<Vec<Cookie>>;
  type AnyBrowserFn = fn(&str, Option<Vec<String>>, Option<&str>) -> Result<Vec<Cookie>>;

  #[cfg(unix)]
  type ChromiumBasedFn = fn(&Browser, PathBuf, Option<Vec<String>>, bool) -> Result<Vec<Cookie>>;
  #[cfg(unix)]
  type ChromiumBasedDetailedFn =
    fn(&Browser, PathBuf, Option<Vec<String>>, bool) -> Result<Vec<DetailedCookie>>;
  #[cfg(unix)]
  type ChromiumBasedWithBrowserIdFn =
    fn(Option<&str>, PathBuf, Option<Vec<String>>, bool) -> Result<Vec<Cookie>>;
  #[cfg(unix)]
  type ChromiumBasedDetailedWithBrowserIdFn =
    fn(Option<&str>, PathBuf, Option<Vec<String>>, bool) -> Result<Vec<DetailedCookie>>;
  #[cfg(target_os = "windows")]
  type InternetExplorerBasedFn = fn(PathBuf, Option<Vec<String>>, bool) -> Result<Vec<Cookie>>;
  #[cfg(target_os = "windows")]
  type ChromiumBasedFn = fn(PathBuf, PathBuf, Option<Vec<String>>, bool) -> Result<Vec<Cookie>>;
  #[cfg(target_os = "windows")]
  type ChromiumBasedDetailedFn =
    fn(PathBuf, PathBuf, Option<Vec<String>>, bool) -> Result<Vec<DetailedCookie>>;

  for (_, function) in COMMON_BROWSER_SELECTORS
    .iter()
    .chain(PLATFORM_BROWSER_SELECTORS)
  {
    let _: BrowserFn = *function;
  }
  let _: BrowserFn = rookie_cookies::load;
  let _: fn() -> String = rookie_cookies::version;
  let _: fn(&str) -> &Browser = get_browser_config;
  let _: fn(&str) -> Option<&Browser> = try_get_browser_config;
  let _: fn(rookie_cookies::anyhow::Result<()>) -> Result<()> = result_reexport_identity;

  let _: FirefoxProfileFn = rookie_cookies::firefox_profile;
  let _: fn() -> Result<Vec<MozillaProfile>> = rookie_cookies::firefox_profiles;
  let _: fn(PathBuf, Option<Vec<String>>) -> Result<Vec<Cookie>> = rookie_cookies::firefox_based;
  let _: fn(PathBuf, Option<Vec<String>>) -> Result<Vec<DetailedCookie>> =
    rookie_cookies::firefox_based_detailed;
  let _: AnyBrowserFn = rookie_cookies::any_browser;
  let _: fn(&MozillaProfile) -> (&String, &PathBuf, bool) = read_mozilla_profile_fields;
  let _: fn(Vec<rookie_cookies::common::enums::Cookie>) -> String =
    rookie_cookies::common::format::json;
  let _: fn(Vec<rookie_cookies::enums::Cookie>) -> String = format::netscape;

  #[cfg(target_os = "macos")]
  let _: fn(PathBuf, Option<Vec<String>>) -> Result<Vec<Cookie>> = rookie_cookies::safari_based;

  #[cfg(target_os = "windows")]
  let _: InternetExplorerBasedFn = rookie_cookies::internet_explorer_based;

  #[cfg(unix)]
  let _: ChromiumBasedFn = rookie_cookies::chromium_based;

  #[cfg(unix)]
  let _: ChromiumBasedDetailedFn = rookie_cookies::chromium_based_detailed;

  #[cfg(unix)]
  let _: ChromiumBasedWithBrowserIdFn = rookie_cookies::chromium_based_with_browser_id;

  #[cfg(unix)]
  let _: ChromiumBasedDetailedWithBrowserIdFn =
    rookie_cookies::chromium_based_detailed_with_browser_id;

  #[cfg(target_os = "windows")]
  let _: ChromiumBasedFn = rookie_cookies::chromium_based;

  #[cfg(target_os = "windows")]
  let _: ChromiumBasedDetailedFn = rookie_cookies::chromium_based_detailed;
}

#[test]
fn generic_report_api_signatures_are_the_section_5_8_surface() {
  type BrowserReportFn = fn(&str, Option<&str>, Option<Vec<String>>) -> Result<ExtractionReport>;

  // Registry construction failures stay distinguishable from an empty
  // registered inventory, so every generic report API now has an error channel.
  let _: fn() -> rookie_cookies::Result<Vec<BrowserDescriptor>> =
    rookie_cookies::supported_browsers;
  let _: fn(&str) -> Result<Vec<ProfileDescriptor>> = rookie_cookies::browser_profiles;
  let _: BrowserReportFn = rookie_cookies::browser_report;
  let _: fn(Option<Vec<String>>) -> Result<ExtractionReport> = rookie_cookies::load_report;
}

#[test]
fn additive_chrome_profile_apis_do_not_change_the_legacy_selector_signature() {
  let _: BrowserFn = rookie_cookies::chrome;
  let _: fn() -> Result<Vec<ProfileDescriptor>> = rookie_cookies::chrome_profiles;
  let _: fn(&str, Option<Vec<String>>) -> Result<ExtractionReport> = rookie_cookies::chrome_profile;
}

#[test]
fn report_identifiers_are_open_string_newtypes() {
  // A code this build has never emitted still round-trips, so a downstream
  // match on a future engine's diagnostics keeps compiling and parsing.
  let code = IssueCode::from_str("future_engine_issue").expect("open vocabulary");
  assert_eq!(code.as_str(), "future_engine_issue");
  assert_eq!(code.to_string(), "future_engine_issue");
  assert_eq!(AsRef::<str>::as_ref(&code), "future_engine_issue");
  assert_eq!(
    serde_json::from_value::<IssueCode>(serde_json::json!("future_engine_issue"))
      .expect("deserialize"),
    code
  );
  assert_eq!(
    serde_json::to_value(&code).expect("serialize"),
    serde_json::json!("future_engine_issue")
  );

  for invalid in ["", "Uppercase", "1leading", "has-dash", "has space"] {
    assert!(
      IssueCode::from_str(invalid).is_err(),
      "{invalid:?} must be rejected"
    );
  }

  assert_eq!(ReportStatusCode::complete().as_str(), "complete");
  assert_eq!(ReportStatusCode::partial().as_str(), "partial");
  assert_eq!(ReportStatusCode::failed().as_str(), "failed");
  assert_eq!(ReportStatusCode::no_sources().as_str(), "no_sources");

  // The codes a consumer most often branches on need constructors too, or the
  // module docs' "compare against a frozen vocabulary value" advice is
  // unfollowable for issues.
  assert_eq!(
    IssueCode::browser_not_detected().as_str(),
    "browser_not_detected"
  );
  assert_eq!(
    IssueCode::provider_unavailable().as_str(),
    "provider_unavailable"
  );
  assert_eq!(IssueCode::provider_failed().as_str(), "provider_failed");
  assert_eq!(IssueCode::decrypt_failed().as_str(), "decrypt_failed");
  assert_eq!(IssueCode::decode_failed().as_str(), "decode_failed");
  assert_eq!(
    IssueCode::column_read_failed().as_str(),
    "column_read_failed"
  );
  assert_eq!(
    IssueCode::source_extraction_failed().as_str(),
    "source_extraction_failed"
  );
  assert_eq!(
    IssueCode::source_read_retried().as_str(),
    "source_read_retried"
  );
  assert_eq!(
    IssueCode::browser_discovery_failed().as_str(),
    "browser_discovery_failed"
  );
  assert_eq!(
    IssueCode::profile_has_no_cookie_source().as_str(),
    "profile_has_no_cookie_source"
  );

  // Bounded samples are only interpretable if the bound is public.
  assert_eq!(rookie_cookies::report::MAX_ISSUE_SAMPLES, 8);
}

#[test]
fn supported_browsers_describes_registration_without_touching_the_filesystem() {
  let browsers = rookie_cookies::supported_browsers().expect("registered browser inventory");
  assert!(
    !browsers.is_empty(),
    "every supported OS registers at least one browser"
  );

  let mut names = HashSet::new();
  for browser in &browsers {
    assert!(
      names.insert(browser.id.to_string()),
      "duplicate canonical id"
    );
    assert!(!browser.display_name.is_empty());
    assert!(!browser.engine.as_str().is_empty());
    for alias in &browser.aliases {
      assert!(names.insert(alias.clone()), "alias collides with an id");
    }
    // A declared tier is a capability claim; only a provider compiled into
    // this build makes it available.
    let declared = browser
      .capabilities
      .declared_decryption_tiers
      .iter()
      .collect::<HashSet<_>>();
    for tier in &browser.capabilities.available_decryption_tiers {
      assert!(
        declared.contains(tier),
        "{} advertises undeclared tier {tier}",
        browser.id
      );
    }
    assert!(!browser.capabilities.persistent_formats.is_empty());
    let _ = &browser.capabilities.session_formats;
  }

  assert!(browsers
    .iter()
    .any(|browser| browser.id.as_str() == "chrome"));
}

#[test]
fn core_json_wire_shape_remains_exact() {
  let output = format::json(vec![cookie()]);
  assert_eq!(
    output,
    r#"[
  {
    "domain": ".example.test",
    "path": "/account",
    "secure": true,
    "expires": 1700000000,
    "name": "session",
    "value": "abc123",
    "http_only": true,
    "same_site": 1
  }
]"#
  );
}

#[test]
fn core_netscape_wire_shape_remains_exact() {
  let output = format::netscape(vec![cookie()]);
  assert_eq!(
    output,
    format!(
      "# Netscape HTTP Cookie File\n\
       # Generated by rookie-cookies {}\n\
       # Edit at your own risk.\n\n\
       #HttpOnly_.example.test\tTRUE\t/account\tTRUE\t1700000000\tsession\tabc123\n",
      rookie_cookies::version()
    )
  );
}
