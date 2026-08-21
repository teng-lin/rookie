//! Compatibility gates for the public Rust surface and legacy wire formats.
//!
//! Integration tests compile as a downstream crate, so constructing these
//! types here catches source breaks that an in-module unit test would miss.

#![allow(deprecated)]

use once_cell::sync::Lazy;
use rookie_cookies::common::format;
use rookie_cookies::config::{
  get_browser_config, try_get_browser_config, Browser, BrowsersMap, Config, CONFIG,
};
use rookie_cookies::direct_path::{
  ChromiumLockedDatabasePolicy, CookieSourceKind, DirectPathError, InvalidCookieSourceReason,
  InvalidDirectPathOptionsReason, PathExtractRequest,
};
use rookie_cookies::enums::{
  Cookie, CookieContext, CookieToString, DetailedCookie, SAME_SITE_UNSPECIFIED,
};
use rookie_cookies::report::{
  BrowserDescriptor, ExtractionReport, IssueCode, ProfileDescriptor, ReportStatusCode,
};
use rookie_cookies::MozillaProfile;
use rookie_cookies::RequestError;
use rookie_cookies::Result;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr;

/// The v0.5.9 named selectors are the deprecated compatibility bridge, so they
/// keep returning `anyhow::Result` through 0.6.x. Only the 0.6 job surface
/// moved to `rookie_cookies::Result`.
type BrowserFn = fn(Option<Vec<String>>) -> rookie_cookies::anyhow::Result<Vec<Cookie>>;

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

/// 0.6.0's one deliberate stable break: `rookie_cookies::Result` is no longer
/// `anyhow::Result`. What replaces the old identity is that the re-export still
/// resolves, and that [`rookie_cookies::Error`] satisfies `anyhow`'s blanket
/// `From`, so `?` from the new surface into an `anyhow` call site keeps working.
fn typed_error_flows_into_an_anyhow_call_site(
  value: Result<()>,
) -> rookie_cookies::anyhow::Result<()> {
  value?;
  Ok(())
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
  // Every function pinned in this test is the deprecated v0.5.9 bridge, which
  // keeps returning `anyhow::Result` through the whole 0.6.x line. The 0.6 job
  // surface is pinned against `rookie_cookies::Result` in the tests below.
  use rookie_cookies::anyhow::Result;

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
  let _: fn(rookie_cookies::Result<()>) -> rookie_cookies::anyhow::Result<()> =
    typed_error_flows_into_an_anyhow_call_site;

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
  let _: fn(&RequestError) -> &'static str = RequestError::code;

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
fn path_request_builders_and_functions_are_unconditional() {
  // `sniff` and `plaintext` compile on every target; the credential-bearing
  // constructors are deliberately platform-gated, and are pinned separately
  // below so a cross-platform break is a compile error rather than a runtime
  // one.
  let sniffed =
    PathExtractRequest::sniff("cookies.sqlite").domains(Some(vec!["example.test".to_owned()]));
  let plaintext = PathExtractRequest::plaintext("Cookies")
    .locked_database_policy(ChromiumLockedDatabasePolicy::NonDisruptive);

  let _: fn(PathExtractRequest) -> Result<Vec<Cookie>> =
    rookie_cookies::direct_path::extract_from_path;
  let _ = (sniffed, plaintext);
}

/// The credential constructors are the one place this crate's public surface
/// deliberately differs per platform: a registry identity means nothing on
/// Windows, and a `Local State` file means nothing on Unix.
#[test]
fn platform_credential_constructors_exist_only_where_they_can_work() {
  #[cfg(unix)]
  let _ = PathExtractRequest::unix_identity("Cookies", "chrome");
  #[cfg(windows)]
  let _ = PathExtractRequest::windows_local_state("Cookies", "Local State");
}

#[test]
fn direct_path_error_accessors_are_stable_for_downstream_consumers() {
  fn inspect(error: &DirectPathError) {
    let _: &'static str = error.kind();
    let _: &'static str = error.code();
    let _: Option<&std::path::Path> = error.path();
    let _: Option<CookieSourceKind> = error.source_kind();
    let _: Option<&str> = error.target_os();
    let _: Option<&str> = error.target_arch();
    let _: Option<&InvalidCookieSourceReason> = error.invalid_source_reason();
    let _: Option<&InvalidDirectPathOptionsReason> = error.invalid_options_reason();
  }

  let missing = std::env::temp_dir().join(format!(
    "rookie-public-direct-path-missing-{}",
    std::process::id()
  ));
  let error = rookie_cookies::direct_path::extract_from_path(PathExtractRequest::sniff(missing))
    .expect_err("missing source is invalid");
  let rookie_cookies::Error::Source(typed) = &error else {
    panic!("a path fault is Error::Source, got {error:?}");
  };
  inspect(typed);
}

#[cfg(unix)]
#[test]
fn fault_kind_keeps_chromium_based_unknown_browser_as_engine() {
  let error = rookie_cookies::chromium_based_with_browser_id(
    Some("definitely-not-a-registered-browser-id"),
    std::env::temp_dir().join("rookie-missing-cookies"),
    None,
    false,
  )
  .expect_err("direct browser_definition path stays unstructured");
  assert_eq!(
    rookie_cookies::Error::from(error).fault_kind(),
    rookie_cookies::FaultKind::Engine
  );
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
  let _: fn(rookie_cookies::ReportRequest) -> Result<ExtractionReport> =
    rookie_cookies::extract_report;
  let _: fn(rookie_cookies::ExtractRequest) -> Result<Vec<Cookie>> = rookie_cookies::extract;
  let _: fn(Option<Vec<String>>) -> Result<ExtractionReport> = rookie_cookies::load_report;
  let _: fn(rookie_cookies::ReadRequest) -> Result<rookie_cookies::ReadResult> =
    rookie_cookies::read;
  let _: fn(rookie_cookies::ReadRequest) -> Result<Vec<Cookie>> = rookie_cookies::jar;
  let _: fn(rookie_cookies::FromPathRequest) -> Result<rookie_cookies::ReadResult> =
    rookie_cookies::from_path;
  let _: fn(&str) -> Result<Vec<ProfileDescriptor>> = rookie_cookies::profiles;
  let _: fn(&rookie_cookies::ReadWarning) -> &str = rookie_cookies::ReadWarning::code;
}

#[test]
fn additive_chrome_profile_apis_do_not_change_the_legacy_selector_signature() {
  let _: BrowserFn = rookie_cookies::chrome;
  let _: fn() -> Result<Vec<ProfileDescriptor>> = rookie_cookies::chrome_profiles;
  // `chrome_profile` is deprecated bridge surface and keeps `anyhow::Result`.
  let _: fn(&str, Option<Vec<String>>) -> rookie_cookies::anyhow::Result<ExtractionReport> =
    rookie_cookies::chrome_profile;
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
  assert_eq!(rookie_cookies::report::EXTRACTION_REPORT_SCHEMA_VERSION, 1);
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
