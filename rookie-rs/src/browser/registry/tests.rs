use super::super::source::SourceFailureStage;
use super::chromium::discover_browser_with_context;
use super::gecko::discover_gecko_with_context;
use super::internet_explorer::{
  discover_internet_explorer_with_context, internet_explorer_report_with_context,
  INTERNET_EXPLORER_COOKIE_FILE,
};
use super::safari::{
  discover_safari_with_context, populate_safari_sources, safari_report_with_context,
  safari_report_with_query, select_legacy_safari_profile, SAFARI_COOKIE_FILE,
};
use super::test_seams::{
  browser_root, channel_root, context_for, gecko_test_root, seed_cookie, seed_empty_gecko_database,
  with_test_fs, TempDir, TestDiscoveryFs,
};
use super::*;

#[test]
fn linux_system_context_discovers_config_roots_without_home() {
  let temp = TempDir::new("linux-context-without-home");
  let xdg_config_home = temp.path().join("xdg-config");
  let env = BTreeMap::from([(
    OsString::from("XDG_CONFIG_HOME"),
    xdg_config_home.clone().into_os_string(),
  )]);
  let context = DiscoveryContext::from_system_env(PlatformId::Linux, env)
    .expect("HOME is optional when XDG_CONFIG_HOME resolves independently");
  assert!(context.home.is_none());

  // `{config_home}`-rooted templates resolve through XDG_CONFIG_HOME alone.
  let chrome_root = channel_root(&context, "stable");
  assert!(chrome_root.starts_with(&xdg_config_home));
  seed_cookie(&chrome_root.join("Default"), true, "chrome", "value");
  assert_eq!(
    discover_browser_with_context(&context, "chrome")
      .expect("discover Chrome from XDG_CONFIG_HOME")
      .profiles()
      .len(),
    1
  );

  // A `{home}`-only template (Firefox's Linux roots) resolves to absence,
  // not a partial path rooted at nothing.
  let registry = embedded_registry().expect("registry");
  let firefox = browser_definition(registry, context.platform, "firefox").expect("Firefox");
  for root in &firefox.roots {
    assert!(
      context.resolve_template(&root.template).is_none(),
      "a {{home}}-rooted template must resolve to absence without HOME"
    );
  }
  assert!(discover_gecko_with_context(&context, "firefox")
    .expect("Firefox discovery without HOME is absence, not an error")
    .profiles
    .is_empty());
}

/// Every macOS root, for every registered browser, is `{home}`-rooted —
/// unlike Linux (which has `{config_home}` roots) or Windows (which has
/// `{local_app_data}`/`{roaming_app_data}` roots), macOS templates never
/// use `XDG_CONFIG_HOME`/`CHROME_CONFIG_HOME`. But an environment that
/// clears `HOME` while leaving one of those two variables set still counts
/// as "an alternative resolved" for `from_system_env`'s coarse per-platform
/// check (it cannot know a variable is irrelevant to every macOS
/// template), so construction still succeeds — and then every root
/// silently resolves to absence, exactly like a present-but-empty root
/// (`missing_non_chromium_roots_are_silent`).
#[test]
fn macos_system_context_without_home_resolves_every_root_to_absence() {
  let env = BTreeMap::from([(
    OsString::from("XDG_CONFIG_HOME"),
    OsString::from("/irrelevant-to-every-macos-template"),
  )]);
  let context = DiscoveryContext::from_system_env(PlatformId::Macos, env)
    .expect("an unrelated alternative variable still lets macOS discovery proceed");
  assert!(context.home.is_none());

  let registry = embedded_registry().expect("registry");
  for browser_id in ["chrome", "safari", "firefox"] {
    let definition = browser_definition(registry, PlatformId::Macos, browser_id)
      .unwrap_or_else(|_| panic!("{browser_id} is registered on macOS"));
    for root in &definition.roots {
      assert!(
        context.resolve_template(&root.template).is_none(),
        "{browser_id} root {:?} must resolve to absence without HOME",
        root.template
      );
    }
  }

  let chrome = discover_browser_with_context(&context, "chrome").expect("discover Chrome");
  assert_eq!(chrome.detected_roots, 0);
  assert!(chrome.issues.is_empty());
  assert!(!chrome.all_detected_roots_failed());

  let safari = discover_safari_with_context(&context, "safari").expect("discover Safari");
  assert_eq!(safari.counters.installations_detected, 0);
  assert!(safari.discovery_issues.is_empty());
  assert!(!safari.all_detected_roots_failed());
}

/// A fully bare environment (no `HOME`/`USERPROFILE` and none of its
/// platform alternatives) gives discovery nothing to search: every root
/// would silently resolve to absence, indistinguishable from every browser
/// being genuinely uninstalled. `from_system_env` must still error here —
/// this is the "plausible empty success" the environment-tolerance change
/// above must not introduce.
#[test]
fn completely_bare_environment_is_a_construction_error_on_every_platform() {
  for platform in [PlatformId::Linux, PlatformId::Macos, PlatformId::Windows] {
    let Err(error) = DiscoveryContext::from_system_env(platform, BTreeMap::new()) else {
      panic!("{platform:?}: no home key and no platform alternative must not silently succeed");
    };
    let message = error.to_string();
    assert!(message.contains("is not set"), "{platform:?}: {message}");
  }
}

#[test]
fn windows_system_context_discovers_registry_roots_without_userprofile() {
  let temp = TempDir::new("windows-context-without-userprofile");
  let local_app_data = temp.path().join("LocalAppData");
  let roaming_app_data = temp.path().join("AppData");
  let env = BTreeMap::from([
    (
      OsString::from("LocalAppData"),
      local_app_data.clone().into_os_string(),
    ),
    (
      OsString::from("AppData"),
      roaming_app_data.clone().into_os_string(),
    ),
  ]);
  let context = DiscoveryContext::from_system_env(PlatformId::Windows, env)
    .expect("Windows registry discovery uses case-insensitive env without USERPROFILE");
  assert!(context.home.is_none());

  let chrome_root = channel_root(&context, "stable");
  assert!(chrome_root.starts_with(&local_app_data));
  seed_cookie(&chrome_root.join("Default"), true, "chrome", "value");
  assert_eq!(
    discover_browser_with_context(&context, "chrome")
      .expect("discover Chrome from LOCALAPPDATA")
      .profiles()
      .len(),
    1
  );

  let firefox_root = gecko_test_root(&context);
  assert!(firefox_root.starts_with(&roaming_app_data));
  seed_empty_gecko_database(&firefox_root);
  assert_eq!(
    discover_gecko_with_context(&context, "firefox")
      .expect("discover Firefox from APPDATA")
      .profiles
      .len(),
    1
  );
}

#[test]
fn registry_registers_gecko_and_ie_without_widening_public_api() {
  let registry = embedded_registry().expect("registry");
  for platform in [PlatformId::Windows, PlatformId::Macos, PlatformId::Linux] {
    assert_eq!(
      browser_definition(registry, platform, "firefox")
        .expect("Firefox definition")
        .engine,
      BrowserEngine::Gecko
    );
  }
  for browser in ["librewolf", "zen"] {
    for platform in [PlatformId::Windows, PlatformId::Macos, PlatformId::Linux] {
      assert_eq!(
        browser_definition(registry, platform, browser)
          .expect("Gecko definition")
          .engine,
        BrowserEngine::Gecko
      );
    }
  }
  assert_eq!(
    browser_definition(registry, PlatformId::Linux, "cachy")
      .expect("Cachy definition")
      .engine,
    BrowserEngine::Gecko
  );
  assert_eq!(
    browser_definition(registry, PlatformId::Windows, "ie")
      .expect("IE alias")
      .engine,
    BrowserEngine::InternetExplorer
  );
  let ie =
    browser_definition(registry, PlatformId::Windows, "internet_explorer").expect("IE definition");
  assert_eq!(
    ie.roots
      .iter()
      .map(|root| (root.root_id.as_str(), root.template.as_str(), root.priority))
      .collect::<Vec<_>>(),
    vec![
      (
        "ie-webcache-roaming",
        "{roaming_app_data}/Microsoft/Windows/WebCache",
        10,
      ),
      (
        "ie-webcache-local",
        "{local_app_data}/Microsoft/Windows/WebCache",
        20,
      ),
    ]
  );
}

#[test]
fn compatibility_config_is_projected_from_every_registry_definition() {
  let registry = embedded_registry().expect("registry");
  for (platform, definitions) in &registry.platforms {
    let compatibility = crate::config::CONFIG
      .platforms
      .get(platform)
      .expect("compatibility platform");
    for definition in definitions {
      let browser = compatibility
        .get(&definition.canonical_id)
        .expect("canonical compatibility entry");
      assert_eq!(
        browser.paths.is_empty(),
        definition.roots.is_empty(),
        "{} on {platform}",
        definition.canonical_id
      );
      for alias in &definition.aliases {
        assert!(
          compatibility.contains_key(alias),
          "alias {alias:?} for {} on {platform}",
          definition.canonical_id
        );
      }

      let credentials = definition.key_credentials.as_ref();
      let keychain = credentials.and_then(|value| value.macos_keychain.as_ref());
      assert_eq!(
        browser.unix_crypt_name.as_deref(),
        credentials.and_then(|value| value.linux_crypt_name.as_deref())
      );
      assert_eq!(
        browser.osx_key_service.as_deref(),
        keychain.map(|value| value.service.as_str())
      );
      assert_eq!(
        browser.osx_key_user.as_deref(),
        keychain.map(|value| value.account.as_str())
      );
    }
  }
}

fn registry_with_credentials(platform: &str, tiers: &str, credentials: &str) -> String {
  format!(
    r#"{{
      "schema_version": 1,
      "platforms": {{
        "{platform}": [
          {{
            "canonical_id": "probe",
            "aliases": [],
            "display_name": "Probe",
            "engine": "chromium",
            "roots": [
              {{
                "root_id": "probe-root",
                "template": "{{home}}/probe",
                "channel": "stable",
                "discovery": "chromium_user_data",
                "priority": 10
              }}
            ],
            "capabilities": {{
              "declared_persistent_formats": ["chromium_sqlite"],
              "declared_session_formats": [],
              "declared_decryption_tiers": [{tiers}]
            }}{credentials}
          }}
        ]
      }}
    }}"#
  )
}

fn credential_validation_error(platform: &str, tiers: &str, credentials: &str) -> String {
  let registry: Registry =
    serde_json::from_str(&registry_with_credentials(platform, tiers, credentials))
      .expect("deserialize probe registry");
  validate_registry(&registry).expect_err("probe registry must be rejected")
}

#[test]
fn key_credentials_are_rejected_on_platforms_that_cannot_use_them() {
  let keychain = r#", "key_credentials": {"macos_keychain": {"service": "S", "account": "A"}}"#;
  let crypt = r#", "key_credentials": {"linux_crypt_name": "probe"}"#;
  for platform in ["windows", "linux"] {
    assert!(credential_validation_error(platform, "", keychain).contains("macos_keychain"));
  }
  for platform in ["windows", "macos"] {
    assert!(credential_validation_error(platform, "", crypt).contains("linux_crypt_name"));
  }
}

#[test]
fn declared_tiers_require_non_blank_credentials() {
  // A declared-but-uncredentialed tier is a registry error rather than a
  // runtime surprise, and a blank value fails exactly like an absent one.
  assert!(credential_validation_error("macos", r#""v10""#, "")
    .contains("without macos_keychain credentials"));
  assert!(
    credential_validation_error("linux", r#""v11""#, "").contains("without a linux_crypt_name")
  );
  assert!(credential_validation_error(
    "macos",
    r#""v10""#,
    r#", "key_credentials": {"macos_keychain": {"service": "  ", "account": "A"}}"#
  )
  .contains("blank macos_keychain service"));
  assert!(credential_validation_error(
    "macos",
    r#""v10""#,
    r#", "key_credentials": {"macos_keychain": {"service": "S", "account": ""}}"#
  )
  .contains("blank macos_keychain account"));
  assert!(credential_validation_error(
    "linux",
    r#""v11""#,
    r#", "key_credentials": {"linux_crypt_name": " "}"#
  )
  .contains("blank linux_crypt_name"));
}

#[test]
fn registry_rejects_engine_discovery_strategy_mismatches() {
  for (engine, discovery) in [
    ("chromium", "mozilla_profiles_ini"),
    ("gecko", "chromium_user_data"),
    ("safari", "chromium_user_data"),
    ("internet_explorer", "mozilla_profiles_ini"),
  ] {
    let json = format!(
      r#"{{
        "schema_version": 1,
        "platforms": {{
          "linux": [{{
            "canonical_id": "test",
            "aliases": [],
            "display_name": "Test",
            "engine": "{engine}",
            "roots": [{{
              "root_id": "test-root",
              "template": "{{home}}/test",
              "channel": "stable",
              "discovery": "{discovery}",
              "priority": 10
            }}],
            "capabilities": {{
              "declared_persistent_formats": [],
              "declared_session_formats": [],
              "declared_decryption_tiers": []
            }}
          }}]
        }}
      }}"#
    );
    let registry: Registry = serde_json::from_str(&json).expect("deserialize test registry");
    let error = validate_registry(&registry).expect_err("mismatched strategy must fail");
    assert!(error.contains("incompatible discovery strategy"), "{error}");
  }

  let safari: Registry = serde_json::from_str(
    r#"{
      "schema_version": 1,
      "platforms": {
        "macos": [{
          "canonical_id": "safari",
          "aliases": [],
          "display_name": "Safari",
          "engine": "safari",
          "roots": [{
            "root_id": "safari-user-default",
            "template": "{home}/Library",
            "channel": "stable",
            "discovery": "safari_default_profile",
            "priority": 10
          }],
          "capabilities": {
            "declared_persistent_formats": ["safari_binarycookies"],
            "declared_session_formats": [],
            "declared_decryption_tiers": []
          }
        }]
      }
    }"#,
  )
  .expect("deserialize valid Safari registry");
  validate_registry(&safari).expect("Safari strategy pairing is valid");
}

/// The registry's identifier grammar is looser than the report's: it accepts
/// `-` and a leading digit, which `report_core` rejects. Because descriptor
/// construction collects into a single `Result`, one registry entry that the
/// report cannot represent would fail *every* browser, on every platform, at
/// runtime. This turns that into a test failure instead.
#[test]
fn every_registered_identifier_is_representable_in_the_report_contract() {
  use crate::browser::report_core::{BrowserId, CipherTierId, CookieSourceFormatId, EngineId};
  use std::str::FromStr;

  let registry = embedded_registry().expect("registry");
  for (platform, definitions) in &registry.platforms {
    for definition in definitions {
      let id = &definition.canonical_id;
      assert!(
        BrowserId::from_str(id).is_ok(),
        "{platform} browser id {id:?} is registry-legal but not report-legal"
      );
      assert!(
        EngineId::from_str(definition.engine.as_str()).is_ok(),
        "{platform} engine for {id:?} is not report-legal"
      );
      for format in definition
        .capabilities
        .declared_persistent_formats
        .iter()
        .chain(&definition.capabilities.declared_session_formats)
      {
        assert!(
          CookieSourceFormatId::from_str(format).is_ok(),
          "{platform} format {format:?} on {id:?} is not report-legal"
        );
      }
      for tier in &definition.capabilities.declared_decryption_tiers {
        assert!(
          CipherTierId::from_str(tier).is_ok(),
          "{platform} tier {tier:?} on {id:?} is not report-legal"
        );
      }
    }
  }
}

#[test]
fn only_browsers_with_known_elevation_keys_declare_v20() {
  let registry = embedded_registry().expect("registry");
  // rookie supports Chrome, Brave, Edge, CocCoc, and Avast for Windows App-Bound v20
  // via COM reflective injection.
  let supported_v20_browsers: std::collections::BTreeSet<&str> =
    ["chrome", "brave", "edge", "coccoc", "avast"]
      .into_iter()
      .collect();
  for definitions in registry.platforms.values() {
    for definition in definitions {
      if definition
        .capabilities
        .declared_decryption_tiers
        .iter()
        .any(|tier| tier == "v20")
      {
        assert!(
          supported_v20_browsers.contains(definition.canonical_id.as_str()),
          "unexpected browser declaring v20: {}",
          definition.canonical_id
        );
      }
    }
  }
}

#[test]
fn a_profile_selected_safari_report_reads_only_the_selected_profile() {
  const NAMED_PROFILE_UUID: &str = "01234567-89AB-CDEF-0123-456789ABCDEF";

  let temp = TempDir::new("safari-profile-selection");
  let context = context_for(PlatformId::Macos, temp.path().to_path_buf(), []);
  let library = test_seams::primary_root_path(&context, "safari");
  let data = library.join("Containers/com.apple.Safari/Data/Library");
  let seed = |directory: PathBuf| {
    std::fs::create_dir_all(&directory).expect("create Safari cookie directory");
    let path = directory.join(SAFARI_COOKIE_FILE);
    std::fs::write(&path, b"cook\x00\x00\x00\x00").expect("seed Safari cookie file");
    path
  };
  let default_source = seed(data.join("Cookies"))
    .canonicalize()
    .expect("canonical default Safari source");
  // No profile database, so named profiles come from the directory fallback.
  std::fs::create_dir_all(data.join(format!("Safari/Profiles/{NAMED_PROFILE_UUID}")))
    .expect("create Safari profile marker directory");
  let named_source = seed(data.join(format!(
    "WebKit/WebsiteDataStore/{}/WebsiteData/Cookies",
    NAMED_PROFILE_UUID.to_ascii_lowercase()
  )))
  .canonicalize()
  .expect("canonical named Safari source");

  let all = safari_report_with_context(&context, "safari", None, None).expect("full report");
  let canonical_library = library.canonicalize().expect("canonical Safari root");
  let expected_installation_id = installation_id(
    "safari",
    "safari-user-library",
    "stable",
    &normalized_path_bytes(&canonical_library),
  );
  let default_profile_path = default_source
    .parent()
    .expect("default Safari source parent");
  let expected_default_profile_id = profile_id(
    expected_installation_id.as_str(),
    ProfileLocator::Relative(
      default_profile_path
        .strip_prefix(&canonical_library)
        .expect("default profile below Safari root"),
    ),
  );

  assert_eq!(all.counters.installations_detected, 1);
  assert_eq!(all.counters.installations_discovered, 1);
  assert_eq!(all.counters.installations_enumerated, 1);
  assert_eq!(all.profiles.len(), 2);
  assert_eq!(
    all.profiles[0].identity.installation_id,
    expected_installation_id
  );
  assert_eq!(
    all.profiles[0].identity.profile_id,
    expected_default_profile_id
  );
  assert_eq!(
    all.profiles[0].identity.installation_path,
    canonical_library
  );
  assert_eq!(all.profiles[0].sources[0].origin.path, default_source);
  assert_eq!(
    all.profiles[0].sources[0].acquisition,
    SourceAcquisition::StableFileImage
  );
  assert_eq!(all.profiles[0].sources[0].acquisition_attempts, 1);
  let selected = all.profiles[1].identity.profile_id.clone();
  assert_eq!(all.profiles[1].sources[0].origin.path, named_source);

  let domains = vec!["example.com".to_owned(), "mozilla.org".to_owned()];
  let mut read = Vec::new();
  let one = safari_report_with_query(
    &context,
    "safari",
    Some(selected.as_str()),
    Some(&domains),
    |origin, forwarded_domains| {
      read.push(origin.path.clone());
      assert_eq!(forwarded_domains, Some(domains.as_slice()));
      crate::browser::safari::safari_based_outcome(
        origin,
        forwarded_domains.map(<[String]>::to_vec),
      )
    },
  )
  .expect("profile-selected report");

  assert_eq!(read, vec![named_source]);
  assert_eq!(one.profiles.len(), 1);
  assert_eq!(one.profiles[0].identity.profile_id, selected);
  assert_eq!(
    one.counters.installations_discovered,
    all.counters.installations_discovered
  );

  let mut unknown_queries = 0;
  let unknown = safari_report_with_query(
    &context,
    "safari",
    Some("not-a-profile"),
    Some(&domains),
    |_, _| {
      unknown_queries += 1;
      bail!("unknown profile must fail before a source read")
    },
  )
  .expect_err("an unknown profile id is a request error");
  assert!(unknown.to_string().contains("unknown safari profile id"));
  assert_eq!(unknown_queries, 0);
}

#[test]
fn legacy_safari_does_not_fall_back_to_a_named_profile() {
  const NAMED_PROFILE_UUID: &str = "01234567-89AB-CDEF-0123-456789ABCDEF";

  let temp = TempDir::new("safari-legacy-default-only");
  let context = context_for(PlatformId::Macos, temp.path().to_path_buf(), []);
  let library = test_seams::primary_root_path(&context, "safari");
  let data = library.join("Containers/com.apple.Safari/Data/Library");
  std::fs::create_dir_all(data.join(format!("Safari/Profiles/{NAMED_PROFILE_UUID}")))
    .expect("create named Safari profile marker");
  let named_directory = data.join(format!(
    "WebKit/WebsiteDataStore/{}/WebsiteData/Cookies",
    NAMED_PROFILE_UUID.to_ascii_lowercase()
  ));
  std::fs::create_dir_all(&named_directory).expect("create named Safari cookie directory");
  std::fs::write(
    named_directory.join(SAFARI_COOKIE_FILE),
    b"cook\x00\x00\x00\x00",
  )
  .expect("seed named Safari cookie store");

  let mut outcome = discover_safari_with_context(&context, "safari").expect("discover Safari");
  assert_eq!(outcome.profiles.len(), 1);
  assert!(!outcome.profiles[0].identity.is_default);

  select_legacy_safari_profile(&mut outcome, "safari").expect("select legacy Safari profile");
  assert!(outcome.profiles.is_empty());
  let mut queries = 0;
  let outcome = populate_safari_sources(outcome, None, |_, _| {
    queries += 1;
    bail!("named Safari profile must not be queried by the legacy selector")
  });
  assert!(outcome.profiles.is_empty());
  assert_eq!(queries, 0);
}

#[test]
fn safari_library_requires_a_browser_owned_marker() {
  let temp = TempDir::new("safari-marker-absence");
  let context = context_for(PlatformId::Macos, temp.path().to_path_buf(), []);
  let library = test_seams::primary_root_path(&context, "safari");
  std::fs::create_dir_all(&library).expect("create bare Library root");

  let discovery = discover_safari_with_context(&context, "safari")
    .expect("a bare Library is not a Safari installation");

  assert_eq!(discovery.counters.installations_detected, 0);
  assert_eq!(discovery.counters.installations_discovered, 0);
  assert_eq!(discovery.counters.installations_enumerated, 0);
  assert!(discovery.profiles.is_empty());
  assert!(discovery.discovery_issues.is_empty());
}

#[test]
fn safari_profile_discovery_degradation_keeps_exact_adapter_diagnostic() {
  let temp = TempDir::new("safari-profile-discovery-degraded");
  let context = context_for(PlatformId::Macos, temp.path().to_path_buf(), []);
  let library = test_seams::primary_root_path(&context, "safari");
  let cookie_directory = library.join("Containers/com.apple.Safari/Data/Library/Cookies");
  std::fs::create_dir_all(&cookie_directory).expect("create Safari cookie directory");
  std::fs::write(cookie_directory.join(SAFARI_COOKIE_FILE), b"cook\0\0\0\0")
    .expect("seed Safari cookie source");
  let canonical_library = library.canonicalize().expect("canonical Safari root");
  let (_, warning) = crate::browser::registry::safari::discover_safari_profiles(&canonical_library);
  let warning = warning.expect("missing profile database degrades to directory fallback");
  assert!(matches!(
    &warning,
    crate::browser::registry::safari::SafariProfileDiscoveryIssue::Degraded(_)
  ));
  let expected_message = warning.message();

  let discovery = discover_safari_with_context(&context, "safari")
    .expect("degraded Safari profile discovery remains reportable");

  assert_eq!(discovery.counters.installations_detected, 1);
  assert_eq!(discovery.counters.installations_discovered, 1);
  assert_eq!(discovery.counters.installations_enumerated, 1);
  assert_eq!(discovery.profiles.len(), 1);
  assert_eq!(discovery.discovery_issues.len(), 1);
  let issue = &discovery.discovery_issues[0];
  assert_eq!(issue.code, "safari_profile_discovery_degraded");
  assert_eq!(issue.path, canonical_library);
  assert_eq!(issue.message, expected_message);
  assert_eq!(issue.occurrences, 1);
  assert!(is_informational_discovery_issue(issue.code));
}

#[test]
fn safari_profile_enumeration_failure_keeps_exact_adapter_diagnostic() {
  let temp = TempDir::new("safari-profile-enumeration-failed");
  let context = context_for(PlatformId::Macos, temp.path().to_path_buf(), []);
  let library = test_seams::primary_root_path(&context, "safari");
  let data = library.join("Containers/com.apple.Safari/Data/Library");
  let cookie_directory = data.join("Cookies");
  std::fs::create_dir_all(&cookie_directory).expect("create Safari cookie directory");
  std::fs::write(cookie_directory.join(SAFARI_COOKIE_FILE), b"cook\0\0\0\0")
    .expect("seed Safari cookie source");
  std::fs::create_dir_all(data.join("Safari")).expect("create Safari metadata directory");
  std::fs::write(data.join("Safari/Profiles"), b"not a directory")
    .expect("block Safari profile directory enumeration");
  let canonical_library = library.canonicalize().expect("canonical Safari root");
  let (_, warning) = crate::browser::registry::safari::discover_safari_profiles(&canonical_library);
  let warning = warning.expect("database and directory fallback both fail");
  assert!(matches!(
    &warning,
    crate::browser::registry::safari::SafariProfileDiscoveryIssue::EnumerationFailed(_)
  ));
  let expected_message = warning.message();

  let discovery = discover_safari_with_context(&context, "safari")
    .expect("failed named-profile enumeration retains the default profile");

  assert_eq!(discovery.counters.installations_detected, 1);
  assert_eq!(discovery.counters.installations_discovered, 1);
  assert_eq!(discovery.counters.installations_enumerated, 1);
  assert_eq!(discovery.profiles.len(), 1);
  assert_eq!(discovery.discovery_issues.len(), 1);
  let issue = &discovery.discovery_issues[0];
  assert_eq!(issue.code, "safari_profile_enumeration_failed");
  assert_eq!(issue.path, canonical_library);
  assert_eq!(issue.message, expected_message);
  assert_eq!(issue.occurrences, 1);
  assert!(!is_informational_discovery_issue(issue.code));
}

#[test]
fn safari_default_profile_preserves_modern_then_legacy_candidate_precedence() {
  let temp = TempDir::new("safari-default-candidate-precedence");
  let context = context_for(PlatformId::Macos, temp.path().to_path_buf(), []);
  let library = test_seams::primary_root_path(&context, "safari");
  let modern =
    library.join("Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies");
  let legacy = library.join("Cookies/Cookies.binarycookies");
  for source in [&modern, &legacy] {
    std::fs::create_dir_all(source.parent().expect("Safari source parent"))
      .expect("create Safari source directory");
    std::fs::write(source, b"cook\0\0\0\0").expect("seed Safari cookie source");
  }

  let both = discover_safari_with_context(&context, "safari")
    .expect("discover modern Safari default source");
  assert_eq!(both.profiles.len(), 1);
  // Discovery reports candidates; nothing is a `source` until it is queried.
  assert_eq!(
    both.profiles[0].candidates[0].path,
    modern.canonicalize().expect("canonical modern source")
  );
  assert_eq!(both.profiles[0].candidates[0].precedence, 10);

  std::fs::remove_file(&modern).expect("remove modern Safari source");
  let legacy_only = discover_safari_with_context(&context, "safari")
    .expect("fall back to pre-sandbox Safari source");
  assert_eq!(legacy_only.profiles.len(), 1);
  assert_eq!(
    legacy_only.profiles[0].candidates[0].path,
    legacy.canonicalize().expect("canonical legacy source")
  );
  assert_eq!(legacy_only.profiles[0].candidates[0].precedence, 20);
}

#[test]
fn safari_marker_inspection_failure_preserves_detected_installation() {
  let temp = TempDir::new("safari-marker-denied");
  let real_context = context_for(PlatformId::Macos, temp.path().to_path_buf(), []);
  let library = test_seams::primary_root_path(&real_context, "safari");
  std::fs::create_dir_all(&library).expect("create Library root");
  let denied_marker = library.join("Containers/com.apple.Safari");
  let context = with_test_fs(
    real_context,
    TestDiscoveryFs {
      denied_metadata: Some(denied_marker),
      ..TestDiscoveryFs::default()
    },
  );

  let discovery =
    discover_safari_with_context(&context, "safari").expect("marker denial keeps Safari detected");

  assert_eq!(discovery.counters.installations_detected, 1);
  assert_eq!(discovery.counters.installations_discovered, 1);
  assert_eq!(discovery.counters.installations_enumerated, 1);
  assert!(discovery.profiles.is_empty());
  assert!(discovery
    .discovery_issues
    .iter()
    .any(|issue| issue.code == "profile_has_no_cookie_source"));
}

#[test]
fn safari_duplicate_canonical_profile_keeps_default_owner() {
  const NAMED_PROFILE_UUID: &str = "01234567-89AB-CDEF-0123-456789ABCDEF";

  let temp = TempDir::new("safari-duplicate-profile");
  let real_context = context_for(PlatformId::Macos, temp.path().to_path_buf(), []);
  let library = test_seams::primary_root_path(&real_context, "safari");
  let data = library.join("Containers/com.apple.Safari/Data/Library");
  let default_directory = data.join("Cookies");
  let named_directory = data.join(format!(
    "WebKit/WebsiteDataStore/{}/WebsiteData/Cookies",
    NAMED_PROFILE_UUID.to_ascii_lowercase()
  ));
  for directory in [&default_directory, &named_directory] {
    std::fs::create_dir_all(directory).expect("create Safari cookie directory");
    std::fs::write(directory.join(SAFARI_COOKIE_FILE), b"cook\0\0\0\0")
      .expect("seed Safari cookie source");
  }
  std::fs::create_dir_all(data.join(format!("Safari/Profiles/{NAMED_PROFILE_UUID}")))
    .expect("create named Safari profile marker");
  let shared = temp.path().join("shared-safari-profile");
  std::fs::create_dir_all(&shared).expect("create canonical shared profile");
  let shared = shared.canonicalize().expect("canonical shared profile");
  let canonical_library = library.canonicalize().expect("canonical Safari root");
  let default_canonicalization_input =
    canonical_library.join("Containers/com.apple.Safari/Data/Library/Cookies");
  let named_canonicalization_input = canonical_library.join(format!(
    "Containers/com.apple.Safari/Data/Library/WebKit/WebsiteDataStore/{}/WebsiteData/Cookies",
    NAMED_PROFILE_UUID.to_ascii_lowercase()
  ));
  let context = with_test_fs(
    real_context,
    TestDiscoveryFs {
      canonical_aliases: BTreeMap::from([
        (default_canonicalization_input, shared.clone()),
        (named_canonicalization_input, shared.clone()),
      ]),
      ..TestDiscoveryFs::default()
    },
  );

  let discovery = discover_safari_with_context(&context, "safari")
    .expect("deduplicate canonical Safari profiles");

  assert_eq!(discovery.profiles.len(), 1);
  assert!(discovery.profiles[0].identity.is_default);
  assert_eq!(discovery.profiles[0].identity.path, shared);
  let duplicate = discovery
    .discovery_issues
    .iter()
    .find(|issue| issue.code == "duplicate_profile")
    .expect("duplicate profile issue");
  assert_eq!(duplicate.occurrences, 1);
}

#[test]
fn a_profile_selected_internet_explorer_report_reads_only_the_selected_profile() {
  let temp = TempDir::new("ie-profile-selection");
  let home = temp.path().to_path_buf();
  let context = context_for(
    PlatformId::Windows,
    home.clone(),
    [
      ("APPDATA", home.join("AppData")),
      ("LOCALAPPDATA", home.join("LocalAppData")),
    ],
  );
  // A WebCache root is its own profile, so two roots are two profiles.
  let roots = test_seams::resolvable_root_paths(&context, "internet_explorer");
  assert_eq!(roots.len(), 2, "IE must declare two WebCache roots");
  for root in &roots {
    std::fs::create_dir_all(root).expect("create WebCache root");
    std::fs::write(root.join(INTERNET_EXPLORER_COOKIE_FILE), b"ese")
      .expect("seed WebCache database");
  }
  let canonical_roots = roots
    .iter()
    .map(|root| root.canonicalize().expect("canonical WebCache root"))
    .collect::<Vec<_>>();
  let expected_installation_ids = ["ie-webcache-roaming", "ie-webcache-local"]
    .into_iter()
    .zip(&canonical_roots)
    .map(|(root_id, root)| {
      installation_id(
        "internet_explorer",
        root_id,
        "stable",
        &normalized_path_bytes(root),
      )
    })
    .collect::<Vec<_>>();
  let expected_profile_ids = expected_installation_ids
    .iter()
    .map(|installation_id| {
      profile_id(
        installation_id.as_str(),
        ProfileLocator::Relative(Path::new("")),
      )
    })
    .collect::<Vec<_>>();
  let discovery = discover_internet_explorer_with_context(&context, "internet_explorer")
    .expect("discover both WebCache roots");
  assert_eq!(discovery.counters.installations_detected, 2);
  assert_eq!(discovery.counters.installations_discovered, 2);
  assert_eq!(discovery.counters.installations_enumerated, 2);
  assert_eq!(
    discovery
      .profiles
      .iter()
      .map(|profile| profile.identity.installation_priority)
      .collect::<Vec<_>>(),
    [10, 20]
  );
  assert_eq!(
    discovery
      .profiles
      .iter()
      .map(|profile| profile.identity.installation_path.clone())
      .collect::<Vec<_>>(),
    canonical_roots
  );
  assert_eq!(
    discovery
      .profiles
      .iter()
      .map(|profile| profile.identity.installation_id.clone())
      .collect::<Vec<_>>(),
    expected_installation_ids
  );
  assert_eq!(
    discovery
      .profiles
      .iter()
      .map(|profile| profile.identity.profile_id.clone())
      .collect::<Vec<_>>(),
    expected_profile_ids
  );
  for profile in &discovery.profiles {
    for id in [
      profile.identity.installation_id.as_str(),
      profile.identity.profile_id.as_str(),
    ] {
      assert_eq!(id.len(), 64);
      assert!(id
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    }
    // Discovery output: a candidate that has not been queried. The frozen
    // placeholder shape (`NotAttempted`, not selected until extract) is
    // unchanged; a `SourceCandidate` is a listing leaf with no attempt count.
    assert_eq!(profile.candidates.len(), 1);
    assert_eq!(
      profile.candidates[0].acquisition,
      SourceAcquisition::NotAttempted
    );
    assert!(profile.candidates[0].exists);
  }
  let rediscovery = discover_internet_explorer_with_context(&context, "internet_explorer")
    .expect("rediscover both WebCache roots");
  assert_eq!(
    rediscovery
      .profiles
      .iter()
      .map(|profile| (
        &profile.identity.installation_id,
        &profile.identity.profile_id
      ))
      .collect::<Vec<_>>(),
    discovery
      .profiles
      .iter()
      .map(|profile| (
        &profile.identity.installation_id,
        &profile.identity.profile_id
      ))
      .collect::<Vec<_>>()
  );
  let rows = |origin: SourceCandidate, _: Option<&[String]>| {
    Ok(extracted_internet_explorer_source(
      origin,
      Vec::new(),
      0,
      0,
      0,
      None,
    ))
  };

  let all = internet_explorer_report_with_context(&context, "internet_explorer", None, None, rows)
    .expect("full report");
  assert_eq!(all.profiles.len(), 2);
  assert_eq!(all.counters.installations_detected, 2);
  assert_eq!(all.counters.installations_discovered, 2);
  assert_eq!(all.counters.installations_enumerated, 2);
  assert_eq!(
    all
      .profiles
      .iter()
      .map(|profile| (
        &profile.identity.installation_id,
        &profile.identity.profile_id
      ))
      .collect::<Vec<_>>(),
    discovery
      .profiles
      .iter()
      .map(|profile| (
        &profile.identity.installation_id,
        &profile.identity.profile_id
      ))
      .collect::<Vec<_>>()
  );
  assert!(all.profiles.iter().all(|profile| {
    profile.sources[0].acquisition == SourceAcquisition::EseDatabase
      && profile.sources[0].acquisition_attempts == 1
  }));
  let selected = all.profiles[1].identity.profile_id.clone();
  let selected_source = all.profiles[1].sources[0].origin.path.clone();

  let mut read = Vec::new();
  let one = internet_explorer_report_with_context(
    &context,
    "internet_explorer",
    Some(selected.as_str()),
    None,
    |origin, domains| {
      read.push(origin.path.clone());
      rows(origin, domains)
    },
  )
  .expect("profile-selected report");

  assert_eq!(read, vec![selected_source]);
  assert_eq!(one.profiles.len(), 1);
  assert_eq!(one.profiles[0].identity.profile_id, selected);
  assert_eq!(
    one.counters.installations_discovered,
    all.counters.installations_discovered
  );

  let unknown = internet_explorer_report_with_context(
    &context,
    "internet_explorer",
    Some("not-a-profile"),
    None,
    rows,
  )
  .expect_err("an unknown profile id is a request error");
  assert!(unknown
    .to_string()
    .contains("unknown internet_explorer profile id"));
}

#[test]
fn internet_explorer_existing_root_without_webcache_is_profile_absence() {
  let temp = TempDir::new("ie-root-without-webcache");
  let home = temp.path().to_path_buf();
  let context = context_for(
    PlatformId::Windows,
    home.clone(),
    [
      ("APPDATA", home.join("AppData")),
      ("LOCALAPPDATA", home.join("LocalAppData")),
    ],
  );
  let root = test_seams::primary_root_path(&context, "internet_explorer");
  std::fs::create_dir_all(&root).expect("create WebCache root without database");
  let canonical_root = root.canonicalize().expect("canonical WebCache root");

  let discovery = discover_internet_explorer_with_context(&context, "internet_explorer")
    .expect("missing WebCache is profile absence");

  assert_eq!(discovery.counters.installations_detected, 1);
  assert_eq!(discovery.counters.installations_discovered, 1);
  assert_eq!(discovery.counters.installations_enumerated, 1);
  assert!(discovery.profiles.is_empty());
  assert!(!discovery.all_detected_roots_failed());
  assert_eq!(discovery.discovery_issues.len(), 1);
  assert_eq!(
    discovery.discovery_issues[0].code,
    "profile_has_no_cookie_source"
  );
  assert_eq!(discovery.discovery_issues[0].path, canonical_root);
}

#[test]
fn internet_explorer_duplicate_canonical_root_keeps_first_registry_owner() {
  let temp = TempDir::new("ie-duplicate-canonical-root");
  let home = temp.path().to_path_buf();
  let real_context = context_for(
    PlatformId::Windows,
    home.clone(),
    [
      ("APPDATA", home.join("AppData")),
      ("LOCALAPPDATA", home.join("LocalAppData")),
    ],
  );
  let roots = test_seams::resolvable_root_paths(&real_context, "internet_explorer");
  assert_eq!(roots.len(), 2);
  for root in &roots {
    std::fs::create_dir_all(root).expect("create aliased WebCache root");
  }
  let shared = temp.path().join("shared-webcache");
  std::fs::create_dir_all(&shared).expect("create shared WebCache root");
  std::fs::write(shared.join(INTERNET_EXPLORER_COOKIE_FILE), b"ese")
    .expect("seed shared WebCache database");
  let shared = shared
    .canonicalize()
    .expect("canonical shared WebCache root");
  let context = with_test_fs(
    real_context,
    TestDiscoveryFs {
      canonical_aliases: BTreeMap::from([
        (roots[0].clone(), shared.clone()),
        (roots[1].clone(), shared.clone()),
      ]),
      ..TestDiscoveryFs::default()
    },
  );

  let discovery = discover_internet_explorer_with_context(&context, "internet_explorer")
    .expect("deduplicate canonical WebCache roots");

  assert_eq!(discovery.counters.installations_detected, 2);
  assert_eq!(discovery.counters.installations_discovered, 1);
  assert_eq!(discovery.counters.installations_enumerated, 1);
  assert_eq!(discovery.profiles.len(), 1);
  assert_eq!(discovery.profiles[0].identity.installation_priority, 10);
  assert_eq!(discovery.profiles[0].identity.installation_path, shared);
  let duplicate = discovery
    .discovery_issues
    .iter()
    .find(|issue| issue.code == "duplicate_installation")
    .expect("duplicate installation issue");
  assert_eq!(duplicate.occurrences, 1);
  assert!(!discovery
    .discovery_issues
    .iter()
    .any(|issue| issue.code == "duplicate_profile"));
}

#[test]
fn internet_explorer_report_preserves_row_errors() {
  let temp = TempDir::new("ie-row-error");
  let home = temp.path().to_path_buf();
  let context = context_for(
    PlatformId::Windows,
    home.clone(),
    [
      ("APPDATA", home.join("AppData")),
      ("LOCALAPPDATA", home.join("LocalAppData")),
    ],
  );
  let root = test_seams::resolvable_root_paths(&context, "internet_explorer")
    .into_iter()
    .next()
    .expect("Internet Explorer root");
  std::fs::create_dir_all(&root).expect("create WebCache root");
  std::fs::write(root.join(INTERNET_EXPLORER_COOKIE_FILE), b"ese").expect("seed WebCache database");

  let outcome = internet_explorer_report_with_context(
    &context,
    "internet_explorer",
    None,
    None,
    |origin, _| {
      Ok(extracted_internet_explorer_source(
        origin,
        Vec::new(),
        2,
        1,
        1,
        Some("invalid WebCache record".to_owned()),
      ))
    },
  )
  .expect("Internet Explorer report");

  let source = &outcome.profiles[0].sources[0];
  assert_eq!(source.stats.rows_seen, 2);
  assert_eq!(source.stats.rows_skipped, 1);
  assert_eq!(source.stats.rows_rejected, 1);
  let row_issue = source
    .issues
    .iter()
    .find(|issue| issue.code == "row_read_failed")
    .expect("skipped rows are reported");
  assert_eq!(row_issue.message, "invalid WebCache record");
}

#[test]
fn internet_explorer_query_failures_remain_parse_failures() {
  let temp = TempDir::new("ie-query-failure-stage");
  let home = temp.path().to_path_buf();
  let context = context_for(
    PlatformId::Windows,
    home.clone(),
    [
      ("APPDATA", home.join("AppData")),
      ("LOCALAPPDATA", home.join("LocalAppData")),
    ],
  );
  let root = test_seams::primary_root_path(&context, "internet_explorer");
  std::fs::create_dir_all(&root).expect("create WebCache root");
  std::fs::write(root.join(INTERNET_EXPLORER_COOKIE_FILE), b"ese").expect("seed WebCache database");

  let outcome =
    internet_explorer_report_with_context(&context, "internet_explorer", None, None, |_, _| {
      bail!("injected WebCache query failure")
    })
    .expect("query failures remain report data");

  let source = &outcome.profiles[0].sources[0];
  let failure = source.failure.as_ref().expect("query failure recorded");
  assert_eq!(failure.stage, SourceFailureStage::Parse);
  assert_eq!(failure.message, "injected WebCache query failure");
}

#[test]
fn embedded_registry_is_versioned_and_contains_current_chrome_definition() {
  let registry = embedded_registry().expect("valid embedded registry");
  assert_eq!(registry.schema_version, REGISTRY_SCHEMA_VERSION);
  let definition = browser_definition(registry, PlatformId::current().expect("platform"), "chrome")
    .expect("Chrome definition");
  assert_eq!(definition.engine, BrowserEngine::Chromium);
  assert!(!definition.roots.is_empty());
  assert_eq!(
    definition.capabilities.declared_persistent_formats,
    ["chromium_sqlite"]
  );
}

#[test]
fn missing_non_chromium_roots_are_silent() {
  let temp = TempDir::new("missing-non-chromium-roots");

  let gecko_context = context_for(PlatformId::Linux, temp.path().join("linux-home"), []);
  let gecko = discover_gecko_with_context(&gecko_context, "firefox").expect("missing Gecko roots");
  assert_eq!(gecko.counters.installations_detected, 0);
  assert!(gecko.discovery_issues.is_empty());
  assert!(!gecko.all_detected_roots_failed());

  let safari_context = context_for(PlatformId::Macos, temp.path().join("macos-home"), []);
  let safari =
    discover_safari_with_context(&safari_context, "safari").expect("missing Safari root");
  assert_eq!(safari.counters.installations_detected, 0);
  assert!(safari.discovery_issues.is_empty());
  assert!(!safari.all_detected_roots_failed());

  let windows_home = temp.path().join("windows-home");
  let ie_context = context_for(
    PlatformId::Windows,
    windows_home.clone(),
    [
      ("APPDATA", windows_home.join("AppData")),
      ("LOCALAPPDATA", windows_home.join("LocalAppData")),
    ],
  );
  let ie = discover_internet_explorer_with_context(&ie_context, "internet_explorer")
    .expect("missing IE roots");
  assert_eq!(ie.counters.installations_detected, 0);
  assert!(ie.discovery_issues.is_empty());
  assert!(!ie.all_detected_roots_failed());
}

#[test]
fn later_valid_ie_root_survives_an_earlier_metadata_failure() {
  let temp = TempDir::new("ie-root-metadata-partial-failure");
  let home = temp.path().join("home");
  let real_context = context_for(
    PlatformId::Windows,
    home.clone(),
    [
      ("APPDATA", home.join("AppData")),
      ("LOCALAPPDATA", home.join("LocalAppData")),
    ],
  );
  let denied = browser_root(&real_context, "internet_explorer", "ie-webcache-roaming");
  let valid = browser_root(&real_context, "internet_explorer", "ie-webcache-local");
  std::fs::create_dir_all(&valid).expect("create the later IE root");
  std::fs::write(valid.join(INTERNET_EXPLORER_COOKIE_FILE), b"ese")
    .expect("seed the later IE root");
  let context = with_test_fs(
    real_context,
    TestDiscoveryFs {
      denied_metadata: Some(denied.clone()),
      ..TestDiscoveryFs::default()
    },
  );

  let discovery = discover_internet_explorer_with_context(&context, "internet_explorer")
    .expect("retain the valid IE root");
  assert_eq!(discovery.counters.installations_detected, 2);
  assert_eq!(discovery.counters.installations_discovered, 1);
  assert_eq!(discovery.counters.installations_enumerated, 1);
  assert_eq!(discovery.profiles.len(), 1);
  assert!(!discovery.all_detected_roots_failed());
  assert!(discovery
    .discovery_issues
    .iter()
    .any(|issue| { issue.code == "installation_metadata_failed" && issue.path == denied }));
}
/// A plan entry for the interpreter tests. `policy` is the only thing under
/// test, so everything else is a fixed persistent-shaped value.
fn policy_candidate(path: &str, policy: AcquisitionPolicy) -> SourceCandidate {
  SourceCandidate {
    path: PathBuf::from(path),
    role: crate::browser::report_core::CookieSourceRoleId::persistent(),
    format: crate::browser::report_core::CookieSourceFormatId::known("mozilla_sqlite"),
    precedence: PERSISTENT_SOURCE_PRECEDENCE,
    exists: false,
    selected: false,
    acquisition: SourceAcquisition::NotAttempted,
    policy,
  }
}

fn acquired(candidate: &SourceCandidate, selected: bool) -> mozilla::MozillaCandidateOutcome {
  let mut source = Source::new(candidate.identity(), selected, candidate.acquisition);
  source.acquisition_attempts = 1;
  mozilla::MozillaCandidateOutcome::Source(source)
}

/// `Fixed` is unconditional: the listing already decided the entry is real,
/// so the executor must not spend the existence recheck that `Probe` needs.
/// A `Fixed` entry that inherited the probe gate would silently drop every
/// Safari/IE/Chromium source whose file moved after listing.
#[test]
fn acquire_by_policy_keeps_a_fixed_source_without_rechecking_the_filesystem() {
  let plan = [policy_candidate("/gone/Cookies", AcquisitionPolicy::Fixed)];
  let mut rechecks = 0;
  let (sources, stop) = acquire_by_policy(
    &plan,
    None,
    |candidate, _| acquired(candidate, true),
    |_| {
      rechecks += 1;
      false
    },
  );

  assert!(stop.is_none());
  assert_eq!(sources.len(), 1, "a fixed source is kept unconditionally");
  assert_eq!(rechecks, 0, "only a probe spends the existence recheck");
}

/// A `FirstValid` run is one alternation and ends where the run ends: the
/// entries after the first success inside the run are never acquired, and the
/// next entry outside it still is. Without this, an executor that treated
/// "first valid" as "stop the profile" would look correct for Gecko -- whose
/// alternation happens to be last -- and be wrong the moment a plan puts
/// anything after it.
#[test]
fn acquire_by_policy_resumes_after_a_first_valid_group() {
  let plan = [
    policy_candidate("/profile/recovery.jsonlz4", AcquisitionPolicy::FirstValid),
    policy_candidate("/profile/recovery.baklz4", AcquisitionPolicy::FirstValid),
    policy_candidate("/profile/after", AcquisitionPolicy::Fixed),
  ];
  let mut read = Vec::new();
  let (sources, stop) = acquire_by_policy(
    &plan,
    None,
    |candidate, _| {
      read.push(candidate.path.clone());
      acquired(candidate, candidate.policy == AcquisitionPolicy::FirstValid)
    },
    |_| true,
  );

  assert!(stop.is_none());
  assert_eq!(
    read,
    [
      PathBuf::from("/profile/recovery.jsonlz4"),
      PathBuf::from("/profile/after"),
    ],
    "the losing alternative is skipped; the entry after the group is not"
  );
  assert_eq!(sources.len(), 2);
}
