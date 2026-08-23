use super::chromium::discover_browser_with_context;
use super::gecko::discover_gecko_with_context;
use super::internet_explorer::discover_internet_explorer_with_context;
use super::safari::discover_safari_with_context;
use super::test_seams::{
  channel_root, context_for, gecko_test_root, seed_cookie, seed_empty_gecko_database, TempDir,
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

/// A one-root Chromium registry declaring `layout`, or omitting
/// `legacy_profile_layout` entirely when `layout` is `None`.
fn registry_with_layout(layout: Option<&str>) -> String {
  let declaration = layout
    .map(|layout| format!(r#", "legacy_profile_layout": "{layout}""#))
    .unwrap_or_default();
  format!(
    r#"{{
      "schema_version": 1,
      "platforms": {{
        "linux": [
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
                "priority": 10{declaration}
              }}
            ],
            "capabilities": {{
              "declared_persistent_formats": ["chromium_sqlite"],
              "declared_session_formats": [],
              "declared_decryption_tiers": []
            }}
          }}
        ]
      }}
    }}"#
  )
}

fn parse_layout(
  layout: Option<&str>,
) -> std::result::Result<chromium::LegacyChromiumProfileLayout, String> {
  serde_json::from_str::<Registry>(&registry_with_layout(layout))
    .map(|registry| registry.platforms["linux"][0].roots[0].legacy_profile_layout)
    .map_err(|error| error.to_string())
}

#[test]
fn every_supported_legacy_profile_layout_name_parses() {
  use chromium::LegacyChromiumProfileLayout as Layout;
  for (name, expected) in [
    ("default_and_profiles", Layout::DefaultAndProfiles),
    ("default_only", Layout::DefaultOnly),
    ("flat_and_default", Layout::FlatAndDefault),
    ("default_and_flat", Layout::DefaultAndFlat),
  ] {
    assert_eq!(parse_layout(Some(name)), Ok(expected), "{name}");
  }

  // Absence is the only path to the default layout; see the unknown-name test.
  assert_eq!(parse_layout(None), Ok(Layout::DefaultAndProfiles));
}

#[test]
fn retired_flat_only_layout_is_rejected_with_a_migration_pointer() {
  let error = parse_layout(Some("flat_only")).expect_err("flat_only must not parse");
  assert!(error.contains("flat_only"), "{error}");
  assert!(error.contains("was retired"), "{error}");
  assert!(error.contains("flat_and_default"), "{error}");
}

#[test]
fn unknown_legacy_profile_layout_names_fail_rather_than_defaulting() {
  // The field carries `#[serde(default)]`, so the failure mode worth pinning is
  // a bad value silently becoming `DefaultAndProfiles` instead of erroring.
  let error = parse_layout(Some("flat_and_profiles")).expect_err("unknown name must not parse");
  assert!(error.contains("unknown variant"), "{error}");
  assert!(error.contains("flat_and_profiles"), "{error}");
}

#[test]
fn embedded_registry_uses_the_migration_target_and_not_the_retired_name() {
  // Reintroducing `flat_only` would fail every registry-backed test at once
  // through the `Lazy` load; naming it here turns that cascade into one
  // readable failure. The paired assertion keeps the migration target live, so
  // this cannot pass by the layout vocabulary quietly going unused.
  assert!(
    !include_str!("../../../browser_registry.json").contains("flat_only"),
    "browser_registry.json declares the retired flat_only layout"
  );
  let registry = embedded_registry().expect("registry");
  assert!(registry
    .platforms
    .values()
    .flatten()
    .flat_map(|definition| &definition.roots)
    .any(|root| {
      root.legacy_profile_layout == chromium::LegacyChromiumProfileLayout::FlatAndDefault
    }));
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
