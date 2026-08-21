use super::super::profile_query::{chromium_match_candidate, match_profile_query};
use super::super::test_seams::{
  browser_root, channel_root, context_for, current_context, seed_cookie, with_test_fs,
  write_local_state, TempDir, TestDiscoveryFs,
};
use super::*;
use crate::browser::chromium_crypto::{ChromiumKeyOutcomes, KeyProvider};
use crate::RequestError;
use rusqlite::params;
use std::cell::RefCell;

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn registry_credentials_map_onto_the_platform_provider_input() {
  // Prove the code that reads registry credentials maps the right field onto
  // the right provider input. A swapped service/account or a wrong platform
  // branch would still break retrieval.
  let chrome = registry_key_credentials("chrome").expect("Chrome credentials");

  #[cfg(target_os = "linux")]
  {
    assert_eq!(chrome.linux_crypt_name.as_deref(), Some("chrome"));
    let brave = chromium_key_credentials("brave")
      .expect("resolve Brave")
      .expect("Brave credentials");
    assert_eq!(brave.unix_crypt_name.as_deref(), Some("brave"));
    // Linux definitions carry no Keychain credentials, so mapping the macOS
    // branch here would be a silent cross-platform leak.
    assert_eq!(chrome.macos_keychain, None);
  }

  #[cfg(target_os = "macos")]
  {
    // Distinct values, so transposing service and account fails here.
    assert_eq!(
      chrome
        .macos_keychain
        .as_ref()
        .map(|credentials| credentials.service.as_str()),
      Some("Chrome Safe Storage")
    );
    assert_eq!(
      chrome
        .macos_keychain
        .as_ref()
        .map(|credentials| credentials.account.as_str()),
      Some("Chrome")
    );
    assert_eq!(chrome.linux_crypt_name, None);
    let brave = chromium_key_credentials("brave")
      .expect("resolve Brave")
      .expect("Brave credentials");
    assert_eq!(brave.osx_key_service.as_deref(), Some("Brave Safe Storage"));
    assert_eq!(brave.osx_key_user.as_deref(), Some("Brave"));

    for browser_id in ["coccoc", "yandex"] {
      assert!(
        chromium_key_credentials(browser_id)
          .expect("resolve registered plaintext-only Chromium browser")
          .is_none(),
        "{browser_id} must resolve without inventing Keychain credentials"
      );
    }
  }

  // An unknown browser is an error rather than silently credential-less.
  assert!(chromium_key_credentials("definitely-not-a-browser").is_err());
  assert!(chromium_key_credentials("firefox")
    .expect_err("a non-Chromium browser is not a key identity")
    .to_string()
    .contains("not Chromium"));

  // A definition only carries its own platform's subfields, so drive the
  // mapping directly with both halves present. Service and account are
  // deliberately distinct, so transposing them fails here on every platform
  // rather than only on the macOS job.
  let both = ChromiumKeyIdentity {
    macos_keychain: Some(MacosKeychainCredentials {
      service: "Probe Safe Storage".to_owned(),
      account: "Probe Account".to_owned(),
    }),
    linux_crypt_name: Some("probe-crypt".to_owned()),
  };
  let mapped = provider_input(&both);
  assert_eq!(
    mapped.osx_key_service.as_deref(),
    Some("Probe Safe Storage")
  );
  assert_eq!(mapped.osx_key_user.as_deref(), Some("Probe Account"));
  assert_eq!(mapped.unix_crypt_name.as_deref(), Some("probe-crypt"));

  // No credentials maps to no credentials, never to a blank lookup.
  let empty = provider_input(&ChromiumKeyIdentity::default());
  assert_eq!(empty.osx_key_service, None);
  assert_eq!(empty.osx_key_user, None);
  assert_eq!(empty.unix_crypt_name, None);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn discovered_installations_carry_their_projected_key_credentials() {
  let temp = TempDir::new("installation-key-credentials");
  let platform = PlatformId::current().expect("supported host platform");
  let context = context_for(platform, temp.path().join("home"), []);
  let root = browser_root(&context, "chrome", "chrome-stable");
  seed_cookie(&root.join("Default"), true, "chrome", "value");

  let discovery = discover_browser_with_context(&context, "chrome").expect("discover Chrome");
  let expected = registry_key_credentials("chrome").expect("Chrome credentials");
  assert!(!discovery.installations.is_empty());
  assert!(discovery
    .installations
    .iter()
    .all(|installation| installation.key_credentials == expected));
}

#[test]
fn installation_key_request_carries_identity_and_prefers_parsed_local_state() {
  let expected = ChromiumKeyIdentity {
    linux_crypt_name: Some("carried-crypt-name".to_string()),
    macos_keychain: Some(MacosKeychainCredentials {
      service: "Carried Safe Storage".to_string(),
      account: "Carried Account".to_string(),
    }),
  };
  let installation = BrowserInstallation {
    installation_id: "carried-installation".to_string(),
    browser_id: "carried-browser".to_string(),
    root_id: "carried-root".to_string(),
    channel: "stable".to_string(),
    path: PathBuf::from("carried-installation"),
    local_state_path: PathBuf::from("must-not-be-read/Local State"),
    legacy_local_state: Some(serde_json::json!({"validated": true})),
    key_credentials: expected.clone(),
    priority: 10,
    legacy_priority: 0,
    legacy_profile_layout: LegacyChromiumProfileLayout::DefaultAndProfiles,
    profiles: Vec::new(),
  };

  let request = key_request_for_installation(&installation);
  assert_eq!(request.browser_id(), Some("carried-browser"));
  assert_eq!(request.credentials(), &expected);
  let crate::browser::chromium_platform_keys::LocalStateInput::Parsed(local_state) =
    request.local_state()
  else {
    panic!("validated legacy Local State must outrank the installation path");
  };
  assert_eq!(local_state, &serde_json::json!({"validated": true}));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn compatibility_projection_uses_registry_credentials() {
  // CONFIG is a generated compatibility view. The platform provider and the
  // public projection must therefore expose the same applicable identity.
  let platform = PlatformId::current().expect("platform");
  let registry = embedded_registry().expect("registry");
  let mut compared = 0;
  for definition in registry
    .platforms
    .get(platform.as_str())
    .expect("platform definitions")
  {
    let compatibility = crate::config::try_get_browser_config(&definition.canonical_id)
      .expect("registry browser has a compatibility projection");
    let generic = registry_key_credentials(&definition.canonical_id).expect("registry credentials");
    match platform {
      PlatformId::Macos => {
        let keychain = generic.macos_keychain.as_ref();
        assert_eq!(
          keychain.map(|credentials| &credentials.service),
          compatibility.osx_key_service.as_ref(),
          "{} keychain service",
          definition.canonical_id
        );
        assert_eq!(
          keychain.map(|credentials| &credentials.account),
          compatibility.osx_key_user.as_ref(),
          "{} keychain account",
          definition.canonical_id
        );
      }
      PlatformId::Linux => {
        assert_eq!(
          generic.linux_crypt_name, compatibility.unix_crypt_name,
          "{} crypt name",
          definition.canonical_id
        );
      }
      PlatformId::Windows => unreachable!("cfg-gated to linux and macos only"),
    }
    compared += 1;
  }
  assert!(compared > 0, "no browser credentials were compared");
}

// Glob metacharacters embedded in injected path components. Windows forbids
// `*` and `?` in file names, so only the bracket class is creatable there.
#[cfg(windows)]
const GLOB_METACHARACTERS: &str = "[meta]";

#[cfg(not(windows))]
const GLOB_METACHARACTERS: &str = "[meta]*?";

#[derive(Default)]
struct CountingProvider {
  calls: RefCell<BTreeMap<String, usize>>,
}

#[test]
fn provider_consuming_the_request_budget_prevents_profile_acquisition() {
  use crate::common::deadline::{test_clock::ManualClock, BoundaryStop, Deadline};
  use std::cell::Cell;
  use std::time::Duration;

  struct BudgetConsumer<'a> {
    clock: &'a ManualClock,
    calls: Cell<usize>,
  }

  impl KeyProvider<BrowserInstallation> for BudgetConsumer<'_> {
    type Keys = ChromiumKeyOutcomes;

    fn keys(
      &self,
      _installation: &BrowserInstallation,
      runtime: &crate::common::deadline::BoundaryRuntime<'_>,
    ) -> ChromiumKeyOutcomes {
      runtime.check().expect("provider starts inside the budget");
      self.calls.set(self.calls.get() + 1);
      self.clock.advance(Duration::from_secs(1));
      ChromiumKeyOutcomes::default()
    }
  }

  let temp = TempDir::new("provider-consumes-budget");
  let context = current_context(temp.path().join("home"));
  let root = channel_root(&context, "stable");
  write_local_state(
    &root,
    serde_json::json!({"profile": {"info_cache": {"Default": {"name": "Person 1"}}}}),
  );
  seed_cookie(&root.join("Default"), true, "must-not-decode", "value");

  let clock = ManualClock::default();
  let runtime = crate::common::deadline::BoundaryRuntime::new(
    &clock,
    Deadline::after(&clock, Duration::from_secs(1)),
  );
  let provider = BudgetConsumer {
    clock: &clock,
    calls: Cell::new(0),
  };
  let report = extract_chromium_with_provider_runtime(
    &context,
    "chrome",
    ProfileSelection::AllProfiles,
    None,
    &provider,
    &runtime,
  )
  .expect("typed stop is retained in the draft");

  assert_eq!(provider.calls.get(), 1);
  assert_eq!(report.boundary_stop, Some(BoundaryStop::TimedOut));
  assert!(
    report.installations.is_empty(),
    "no profile query may start"
  );
}

impl KeyProvider<BrowserInstallation> for CountingProvider {
  type Keys = ChromiumKeyOutcomes;

  fn keys(
    &self,
    installation: &BrowserInstallation,
    _runtime: &crate::common::deadline::BoundaryRuntime<'_>,
  ) -> ChromiumKeyOutcomes {
    *self
      .calls
      .borrow_mut()
      .entry(installation.installation_id.clone())
      .or_default() += 1;
    ChromiumKeyOutcomes::default()
  }
}

#[test]
fn registry_contains_every_supported_chromium_family_browser() {
  let registry = embedded_registry().expect("valid embedded registry");
  let cases = [
    (
      PlatformId::Windows,
      [
        "arc",
        "brave",
        "chrome",
        "chromium",
        "edge",
        "octo_browser",
        "opera",
        "opera_gx",
        "vivaldi",
      ]
      .as_slice(),
      [
        "avast",
        "browser_from_vought",
        "coccoc",
        "dc_browser",
        "duckduckgo",
        "qq_browser",
        "sogou",
        "speed_360",
        "speed_360x",
        "yandex",
      ]
      .as_slice(),
    ),
    (
      PlatformId::Macos,
      [
        "arc", "brave", "chrome", "chromium", "edge", "opera", "opera_gx", "vivaldi",
      ]
      .as_slice(),
      ["coccoc", "yandex"].as_slice(),
    ),
    (
      PlatformId::Linux,
      [
        "arc", "brave", "chrome", "chromium", "edge", "opera", "vivaldi",
      ]
      .as_slice(),
      [].as_slice(),
    ),
  ];

  for (platform, legacy_backed, registry_only) in cases {
    let definitions = registry
      .platforms
      .get(platform.as_str())
      .expect("platform definitions");
    let actual = definitions
      .iter()
      .filter(|definition| definition.engine == BrowserEngine::Chromium)
      .map(|definition| definition.canonical_id.as_str())
      .collect::<BTreeSet<_>>();
    assert_eq!(
      actual,
      legacy_backed
        .iter()
        .chain(registry_only)
        .copied()
        .collect::<BTreeSet<_>>()
    );
  }

  for platform in [PlatformId::Windows, PlatformId::Macos] {
    let opera_gx = browser_definition(registry, platform, "opera-gx").expect("Opera GX alias");
    assert_eq!(opera_gx.canonical_id, "opera_gx");
    assert_eq!(
      browser_definition(registry, platform, "opera gx")
        .expect("spaced Opera GX alias")
        .canonical_id,
      "opera_gx"
    );
  }
  assert!(browser_definition(registry, PlatformId::Linux, "opera-gx").is_err());
  assert!(registered_browsers_for(PlatformId::Linux)
    .expect("Linux browser descriptors")
    .iter()
    .all(|browser| browser.canonical_id != "opera_gx"));
}

#[test]
fn corrected_chromium_roots_and_channels_are_explicit_per_os() {
  let registry = embedded_registry().expect("valid embedded registry");
  let cases = [
    (
      PlatformId::Windows,
      "edge",
      [
        (
          "edge-stable-local",
          "stable",
          "{local_app_data}/Microsoft/Edge/User Data",
        ),
        (
          "edge-canary-local",
          "canary",
          "{local_app_data}/Microsoft/Edge SxS/User Data",
        ),
      ]
      .as_slice(),
    ),
    (
      PlatformId::Macos,
      "opera",
      [
        (
          "opera-stable",
          "stable",
          "{home}/Library/Application Support/com.operasoftware.Opera",
        ),
        (
          "opera-developer",
          "developer",
          "{home}/Library/Application Support/com.operasoftware.OperaDeveloper",
        ),
      ]
      .as_slice(),
    ),
    (
      PlatformId::Linux,
      "vivaldi",
      [
        (
          "vivaldi-stable-native",
          "stable",
          "{xdg_config_home}/vivaldi",
        ),
        (
          "vivaldi-snapshot-native",
          "snapshot",
          "{xdg_config_home}/vivaldi-snapshot",
        ),
      ]
      .as_slice(),
    ),
  ];

  for (platform, browser_id, expected_roots) in cases {
    let definition = browser_definition(registry, platform, browser_id).expect("browser");
    for (root_id, channel, template) in expected_roots {
      let root = definition
        .roots
        .iter()
        .find(|root| root.root_id == *root_id)
        .expect("root");
      assert_eq!(root.channel, *channel);
      assert_eq!(root.template, *template);
    }
  }
}

#[test]
fn packaging_and_platform_variant_roots_are_explicit_per_os() {
  let registry = embedded_registry().expect("valid embedded registry");
  let cases = [
    (
      PlatformId::Windows,
      "coccoc",
      "coccoc-local",
      "stable",
      "{local_app_data}/CocCoc/Browser/User Data",
    ),
    (
      PlatformId::Windows,
      "duckduckgo",
      "duckduckgo-package-stable",
      "stable",
      "{local_app_data}/Packages/DuckDuckGo.DesktopBrowser_*/LocalState/EBWebView",
    ),
    (
      PlatformId::Macos,
      "coccoc",
      "coccoc-stable",
      "stable",
      "{home}/Library/Application Support/Coccoc",
    ),
    (
      PlatformId::Macos,
      "yandex",
      "yandex-stable",
      "stable",
      "{home}/Library/Application Support/Yandex/YandexBrowser",
    ),
  ];

  for (platform, browser_id, root_id, channel, template) in cases {
    let definition = browser_definition(registry, platform, browser_id).expect("browser");
    assert_eq!(definition.engine, BrowserEngine::Chromium);
    assert!(definition.aliases.is_empty());
    let roots = definition
      .roots
      .iter()
      .map(|root| {
        (
          root.root_id.as_str(),
          root.channel.as_str(),
          root.template.as_str(),
        )
      })
      .collect::<Vec<_>>();
    assert_eq!(roots, [(root_id, channel, template)]);
  }

  assert!(browser_definition(registry, PlatformId::Linux, "coccoc").is_err());
  assert!(browser_definition(registry, PlatformId::Linux, "duckduckgo").is_err());
  assert!(browser_definition(registry, PlatformId::Linux, "yandex").is_err());
  assert!(browser_definition(registry, PlatformId::Macos, "duckduckgo").is_err());
}

#[test]
fn windows_coccoc_claims_decryption_tiers_including_v20() {
  let registry = embedded_registry().expect("valid embedded registry");
  let definition = browser_definition(registry, PlatformId::Windows, "coccoc").expect("CocCoc");
  let descriptor = capability_descriptor(definition, PlatformId::Windows);
  assert_eq!(descriptor.declared_persistent_formats, ["chromium_sqlite"]);
  assert!(descriptor.declared_session_formats.is_empty());
  assert_eq!(
    descriptor.declared_decryption_tiers,
    ["legacy_dpapi", "v10", "v20"]
  );
  let expected_available = if cfg!(feature = "appbound") {
    vec!["legacy_dpapi", "v10", "v20"]
  } else {
    vec!["legacy_dpapi", "v10"]
  };
  assert_eq!(
    descriptor.available_decryption_tiers,
    expected_available.as_slice()
  );
}

/// A macOS browser without registry-owned keychain credentials cannot
/// truthfully advertise an encrypted-cookie tier.
#[test]
fn macos_chromium_browsers_without_a_keychain_identity_declare_no_decryption_tier() {
  let registry = embedded_registry().expect("valid embedded registry");
  let mut without_identity = BTreeSet::new();
  for definition in registry
    .platforms
    .get(PlatformId::Macos.as_str())
    .expect("macOS definitions")
    .iter()
    .filter(|definition| definition.engine == BrowserEngine::Chromium)
  {
    if definition
      .key_credentials
      .as_ref()
      .and_then(|credentials| credentials.macos_keychain.as_ref())
      .is_some()
    {
      continue;
    }
    let descriptor = capability_descriptor(definition, PlatformId::Macos);
    assert!(
      descriptor.declared_decryption_tiers.is_empty(),
      "{} has no macOS keychain identity and must not declare {:?}",
      definition.canonical_id,
      descriptor.declared_decryption_tiers
    );
    assert!(descriptor.available_decryption_tiers.is_empty());
    assert_eq!(descriptor.declared_persistent_formats, ["chromium_sqlite"]);
    without_identity.insert(definition.canonical_id.as_str());
  }
  assert_eq!(
    without_identity,
    ["coccoc", "yandex"].into_iter().collect::<BTreeSet<_>>(),
    "a new keychain-less macOS browser must decide its tier claim deliberately"
  );
}

/// Plaintext rows never consult a key, so every claimed OS must yield them
/// even where no decryption tier is declared.
#[test]
fn packaging_variants_extract_plaintext_cookies_on_each_claimed_os() {
  fn assert_plaintext_cookie<F: DiscoveryFs>(
    context: &DiscoveryContext<F>,
    browser_id: &str,
    profile: &Path,
  ) {
    seed_cookie(profile, true, browser_id, "plaintext-value");
    let report = extract_chromium_with_provider(
      context,
      browser_id,
      ProfileSelection::AllProfiles,
      None,
      &CountingProvider::default(),
    )
    .expect("plaintext extraction needs no key material");
    let profiles = report
      .installations
      .iter()
      .flat_map(|installation| &installation.profiles)
      .collect::<Vec<_>>();
    assert_eq!(profiles.len(), 1, "{browser_id} discovers its one profile");
    let [source] = &profiles[0].sources[..] else {
      panic!("{browser_id} extracts its one selected source");
    };
    assert!(source.failure.is_none(), "{browser_id} extraction succeeds");
    assert_eq!(
      source
        .cookies()
        .iter()
        .map(|cookie| (cookie.name.clone(), cookie.value.clone()))
        .collect::<Vec<_>>(),
      [(browser_id.to_owned(), "plaintext-value".to_owned())]
    );
  }

  let temp = TempDir::new("packaging-plaintext");
  let home = temp.path().join("home");
  let local_app_data = home.join("LocalAppData");
  let windows = context_for(
    PlatformId::Windows,
    home.clone(),
    [("LOCALAPPDATA", local_app_data.clone())],
  );
  let macos = context_for(PlatformId::Macos, home, []);

  assert_plaintext_cookie(
    &windows,
    "duckduckgo",
    &local_app_data
      .join("Packages/DuckDuckGo.DesktopBrowser_ya2fgkz3nks94/LocalState/EBWebView/Default"),
  );
  assert_plaintext_cookie(
    &windows,
    "coccoc",
    &browser_root(&windows, "coccoc", "coccoc-local").join("Default"),
  );
  assert_plaintext_cookie(
    &macos,
    "coccoc",
    &browser_root(&macos, "coccoc", "coccoc-stable").join("Default"),
  );
  assert_plaintext_cookie(
    &macos,
    "yandex",
    &browser_root(&macos, "yandex", "yandex-stable").join("Default"),
  );
}

#[test]
fn windows_duckduckgo_wildcard_package_root_ignores_unrelated_msix_packages() {
  let temp = TempDir::new("duckduckgo-msix");
  let home = temp.path().join("home");
  let local_app_data = home.join("LocalAppData");
  let context = context_for(
    PlatformId::Windows,
    home,
    [("LOCALAPPDATA", local_app_data.clone())],
  );
  let packages = local_app_data.join("Packages");
  seed_cookie(
    &packages.join("DuckDuckGo.DesktopBrowser_ya2fgkz3nks94/LocalState/EBWebView/Default"),
    true,
    "duckduckgo",
    "value",
  );
  seed_cookie(
    &packages.join("Microsoft.WebView2_8wekyb3d8bbwe/LocalState/EBWebView/Default"),
    true,
    "unrelated",
    "value",
  );

  let discovery =
    discover_browser_with_context(&context, "duckduckgo").expect("discover DuckDuckGo");
  assert_eq!(discovery.installations.len(), 1);
  assert_eq!(
    discovery.installations[0].root_id,
    "duckduckgo-package-stable"
  );
  let profiles = discovery.profiles();
  assert_eq!(profiles.len(), 1);
  assert_eq!(profiles[0].directory_name, "Default");
  assert!(profiles[0].is_default);
}

#[test]
fn windows_coccoc_discovers_its_standard_user_data_root() {
  let temp = TempDir::new("coccoc-windows");
  let home = temp.path().join("home");
  let local_app_data = home.join("LocalAppData");
  let context = context_for(
    PlatformId::Windows,
    home,
    [("LOCALAPPDATA", local_app_data)],
  );
  let root = browser_root(&context, "coccoc", "coccoc-local");
  seed_cookie(&root.join("Default"), true, "coccoc", "value");
  seed_cookie(&root.join("Profile 1"), false, "coccoc-secondary", "value");

  let profiles = discover_browser_with_context(&context, "coccoc")
    .expect("discover CocCoc")
    .profiles();
  assert_eq!(
    profiles
      .iter()
      .map(|profile| profile.directory_name.as_str())
      .collect::<Vec<_>>(),
    ["Default", "Profile 1"]
  );
}

#[test]
fn macos_packaging_variants_discover_flat_and_marked_profiles() {
  let temp = TempDir::new("macos-variants");
  let home = temp.path().join("home");
  let context = context_for(PlatformId::Macos, home, []);

  let coccoc = browser_root(&context, "coccoc", "coccoc-stable");
  seed_cookie(&coccoc, false, "coccoc", "value");
  let coccoc_profiles = discover_browser_with_context(&context, "coccoc")
    .expect("discover macOS CocCoc")
    .profiles();
  assert_eq!(coccoc_profiles.len(), 1);
  assert_eq!(coccoc_profiles[0].directory_name, ".");
  assert!(coccoc_profiles[0].is_default);

  let yandex = browser_root(&context, "yandex", "yandex-stable");
  seed_cookie(&yandex.join("Default"), true, "yandex", "value");
  let yandex_profiles = discover_browser_with_context(&context, "yandex")
    .expect("discover macOS Yandex")
    .profiles();
  assert_eq!(yandex_profiles.len(), 1);
  assert_eq!(yandex_profiles[0].directory_name, "Default");
}

/// Browsers without a registry keychain identity fail the encrypted tier
/// explicitly while plaintext extraction remains available.
#[cfg(target_os = "macos")]
#[test]
fn macos_browsers_without_keychain_credentials_fail_typed_per_tier() {
  for browser_id in ["coccoc", "yandex"] {
    let installation = BrowserInstallation {
      installation_id: format!("{browser_id}-installation"),
      browser_id: browser_id.to_owned(),
      root_id: format!("{browser_id}-stable"),
      channel: "stable".to_owned(),
      path: PathBuf::from("/nonexistent"),
      local_state_path: PathBuf::from("/nonexistent/Local State"),
      legacy_local_state: None,
      key_credentials: ChromiumKeyIdentity::default(),
      priority: 10,
      legacy_priority: 0,
      legacy_profile_layout: LegacyChromiumProfileLayout::DefaultAndProfiles,
      profiles: Vec::new(),
    };

    let clock = crate::common::deadline::SystemClock;
    let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
    let outcomes = SystemKeyProvider.keys(&installation, &runtime);
    let ChromiumKeyOutcome::Failure(failure) = &outcomes.v10 else {
      panic!("{browser_id} v10 must fail typed, got {:?}", outcomes.v10);
    };
    assert!(
      failure.message().contains(browser_id),
      "{browser_id} v10 failure must name the browser, got {:?}",
      failure.message()
    );
    assert!(failure.message().contains("no macOS keychain identity"));
    assert_eq!(outcomes.v11, ChromiumKeyOutcome::NotApplicable);
    assert_eq!(outcomes.v20, ChromiumKeyOutcome::NotApplicable);
  }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_missing_key_configuration_surfaces_as_row_issue_not_silent_empty() {
  let temp = TempDir::new("macos-missing-key-config");
  let home = temp.path().join("home");
  let context = context_for(PlatformId::Macos, home, []);

  for (browser_id, root_id, profile) in [
    ("coccoc", "coccoc-stable", None),
    ("yandex", "yandex-stable", Some("Default")),
  ] {
    let root = browser_root(&context, browser_id, root_id);
    let profile_path = profile.map_or_else(|| root.clone(), |name| root.join(name));
    let db = seed_cookie(&profile_path, true, browser_id, "");
    let connection = rusqlite::Connection::open(&db).expect("open cookie db");
    let mut encrypted = b"v10".to_vec();
    encrypted.extend_from_slice(&[0u8; 28]);
    connection
      .execute(
        "UPDATE cookies SET encrypted_value = ?1 WHERE name = ?2",
        params![encrypted, browser_id],
      )
      .expect("store an encrypted cookie value");
    drop(connection);

    let report = extract_chromium_with_provider(
      &context,
      browser_id,
      ProfileSelection::AllProfiles,
      None,
      &SystemKeyProvider,
    )
    .expect("a missing keychain identity is a per-profile error, not a discovery failure");

    let profiles = report
      .installations
      .iter()
      .flat_map(|installation| &installation.profiles)
      .collect::<Vec<_>>();
    assert_eq!(profiles.len(), 1, "{browser_id} discovers its one profile");
    let [source] = &profiles[0].sources[..] else {
      panic!("{browser_id} extracts its one selected source");
    };
    assert!(
      source.cookies().is_empty(),
      "{browser_id} must not report undecryptable rows as cookies"
    );
    assert_eq!(
      source.stats,
      crate::browser::source::SourceStats {
        rows_seen: 1,
        cookies_emitted: 0,
        rows_skipped: 1,
        rows_rejected: 0,
        provider_failures: 1,
      },
      "{browser_id} must count the row unavailable through the failed provider"
    );
    assert!(
      source.failure.is_none(),
      "an unavailable row does not make the successfully queried source fail"
    );
    // Every row was rejected, so the source also carries the compatibility
    // evidence issue. That one never reaches the report; the row issue does.
    let row_issues = source
      .issues
      .iter()
      .filter(|issue| issue.code != SourceIssue::ALL_ROWS_REJECTED)
      .collect::<Vec<_>>();
    assert_eq!(
      row_issues.len(),
      1,
      "{browser_id} must surface the unavailable row instead of silently returning empty output"
    );
    assert_eq!(row_issues[0].code, "provider_failed");
    assert_eq!(row_issues[0].occurrences, 1);
    assert_eq!(row_issues[0].samples, vec!["row 1".to_owned()]);
    assert!(
      source
        .issues
        .iter()
        .any(|issue| issue.code == SourceIssue::ALL_ROWS_REJECTED),
      "{browser_id} rejected every row, which the compatibility projection reports as an error"
    );
  }
}

#[test]
fn injected_path_components_remain_literal_while_registry_wildcards_are_preserved() {
  let temp = TempDir::new("escaped-glob-components");
  let home = temp.path().join(format!("home{GLOB_METACHARACTERS}"));
  let config_home = temp.path().join(format!("config{GLOB_METACHARACTERS}"));
  let context = context_for(
    PlatformId::Linux,
    home.clone(),
    [("XDG_CONFIG_HOME", config_home.clone())],
  );
  let template = "{config_home}/google-chrome";
  let resolved = context
    .resolve_template(template)
    .expect("resolved Chrome root");
  assert_eq!(
    resolved.base.join(resolved.suffix),
    config_home.join("google-chrome")
  );
  seed_cookie(
    &config_home.join("google-chrome/Default"),
    true,
    "escaped-base",
    "value",
  );
  assert_eq!(
    discover_browser_with_context(&context, "chrome")
      .expect("discover Chrome beneath a literal metacharacter path")
      .profiles()
      .len(),
    1
  );

  let mac_context = context_for(PlatformId::Macos, home.clone(), []);
  seed_cookie(
    &home.join("Library/Application Support/Google/Chrome/Default"),
    true,
    "escaped-home",
    "value",
  );
  assert_eq!(
    discover_browser_with_context(&mac_context, "chrome")
      .expect("discover Chrome below a literal HOME path")
      .profiles()
      .len(),
    1
  );

  let local_app_data = temp.path().join(format!("Local{GLOB_METACHARACTERS}"));
  let windows_context = context_for(
    PlatformId::Windows,
    home,
    [("LOCALAPPDATA", local_app_data.clone())],
  );
  let octo_root = windows_context
    .resolve_template("{local_app_data}/Octo Browser/tmp/*")
    .expect("resolved Octo root");
  assert_eq!(octo_root.base, local_app_data);
  assert_eq!(octo_root.suffix, "Octo Browser/tmp/*");
  seed_cookie(
    &local_app_data.join("Octo Browser/tmp/literal-profile/Default"),
    true,
    "escaped-windows-base",
    "value",
  );
  assert_eq!(
    discover_browser_with_context(&windows_context, "octo_browser")
      .expect("discover wildcard root beneath a literal metacharacter path")
      .installations
      .len(),
    1
  );
}

#[test]
fn snap_roots_target_only_the_active_current_revision() {
  let registry = embedded_registry().expect("valid embedded registry");
  for (browser_id, root_id, expected) in [
    (
      "brave",
      "brave-snap",
      "{home}/snap/brave/current/.config/BraveSoftware/Brave-Browser",
    ),
    (
      "opera",
      "opera-stable-snap",
      "{home}/snap/opera/current/.config/opera",
    ),
    (
      "opera",
      "opera-beta-snap",
      "{home}/snap/opera-beta/current/.config/opera",
    ),
    (
      "opera",
      "opera-developer-snap",
      "{home}/snap/opera-developer/current/.config/opera",
    ),
  ] {
    let root = browser_definition(registry, PlatformId::Linux, browser_id)
      .expect("browser")
      .roots
      .iter()
      .find(|root| root.root_id == root_id)
      .expect("Snap root");
    assert_eq!(root.template, expected);
    assert!(!root.template.contains('*'));
  }
}

#[test]
fn snap_discovery_ignores_retained_revisions() {
  let temp = TempDir::new("snap-current");
  let home = temp.path().join("home");
  let context = context_for(PlatformId::Linux, home.clone(), []);
  seed_cookie(
    &home.join("snap/brave/current/.config/BraveSoftware/Brave-Browser/Default"),
    true,
    "current",
    "value",
  );
  seed_cookie(
    &home.join("snap/brave/retained/.config/BraveSoftware/Brave-Browser/Default"),
    true,
    "retained",
    "value",
  );

  let profiles = discover_browser_with_context(&context, "brave")
    .expect("discover active Snap revision")
    .profiles();
  assert_eq!(profiles.len(), 1);
  // Discovery reports canonical paths, so the expectation must be canonical too.
  let current = home
    .join("snap/brave/current")
    .canonicalize()
    .expect("canonical active Snap revision");
  assert!(profiles[0].path.starts_with(current));
}

#[test]
fn generic_chromium_discovery_handles_default_and_flat_existing_browser_layouts() {
  let temp = TempDir::new("generic-layouts");
  let home = temp.path().join("home");
  let context = context_for(PlatformId::Linux, home.clone(), []);

  let brave = browser_root(&context, "brave", "brave-stable-native");
  seed_cookie(&brave.join("Default"), true, "brave", "value");
  let brave_profiles = discover_browser_with_context(&context, "brave")
    .expect("discover Brave")
    .profiles();
  assert_eq!(brave_profiles.len(), 1);
  assert_eq!(brave_profiles[0].directory_name, "Default");

  let opera = browser_root(&context, "opera", "opera-stable-native");
  seed_cookie(&opera, false, "opera", "value");
  let opera_profiles = discover_browser_with_context(&context, "opera")
    .expect("discover flat Opera")
    .profiles();
  assert_eq!(opera_profiles.len(), 1);
  assert_eq!(opera_profiles[0].directory_name, ".");
  assert!(opera_profiles[0].is_default);
}

#[test]
fn wildcard_roots_are_sorted_before_generic_discovery() {
  let temp = TempDir::new("wildcard-roots");
  let home = temp.path().join("home");
  let local_app_data = home.join("LocalAppData");
  let context = context_for(
    PlatformId::Windows,
    home,
    [("LOCALAPPDATA", local_app_data.clone())],
  );
  let root_pattern = browser_root(&context, "octo_browser", "octo-local-temporary");
  let parent = root_pattern.parent().expect("Octo parent");
  seed_cookie(&parent.join("z-profile/Default"), true, "z", "value");
  seed_cookie(&parent.join("a-profile/Default"), true, "a", "value");

  let discovery = discover_browser_with_context(&context, "octo_browser").expect("discover Octo");
  assert_eq!(discovery.installations.len(), 2);
  assert_eq!(
    discovery
      .installations
      .iter()
      .map(|installation| installation.path.file_name().unwrap().to_string_lossy())
      .collect::<Vec<_>>(),
    ["a-profile", "z-profile"]
  );
}

#[test]
fn chrome_channels_use_real_side_by_side_directories_on_every_os() {
  let temp = TempDir::new("channel-roots");
  let cases = [
    (
      PlatformId::Windows,
      vec![
        ("stable", "LocalAppData/Google/Chrome/User Data"),
        ("beta", "LocalAppData/Google/Chrome Beta/User Data"),
        ("dev", "LocalAppData/Google/Chrome Dev/User Data"),
        ("canary", "LocalAppData/Google/Chrome SxS/User Data"),
      ],
    ),
    (
      PlatformId::Macos,
      vec![
        ("stable", "Library/Application Support/Google/Chrome"),
        ("beta", "Library/Application Support/Google/Chrome Beta"),
        ("dev", "Library/Application Support/Google/Chrome Dev"),
        ("canary", "Library/Application Support/Google/Chrome Canary"),
      ],
    ),
    (
      PlatformId::Linux,
      vec![
        ("stable", ".config/google-chrome"),
        ("beta", ".config/google-chrome-beta"),
        ("dev", ".config/google-chrome-unstable"),
      ],
    ),
  ];

  for (platform, expected) in cases {
    let home = temp.path().join(platform.as_str());
    let context = context_for(
      platform,
      home.clone(),
      (platform == PlatformId::Windows).then(|| ("LOCALAPPDATA", home.join("LocalAppData"))),
    );
    for (channel, relative) in &expected {
      let root = channel_root(&context, channel);
      assert_eq!(root, home.join(relative));
      seed_cookie(
        &root.join("Default"),
        true,
        &format!("{channel}-cookie"),
        "value",
      );
    }

    let discovery = discover_browser_with_context(&context, "chrome").expect("discover channels");
    assert_eq!(
      discovery
        .installations
        .iter()
        .map(|installation| installation.channel.as_str())
        .collect::<Vec<_>>(),
      expected
        .iter()
        .map(|(channel, _)| *channel)
        .collect::<Vec<_>>()
    );
  }
}

#[test]
fn linux_config_home_precedence_is_chrome_then_xdg_then_default() {
  let temp = TempDir::new("linux-config-home");
  let home = temp.path().join("home");
  let chrome_config = temp.path().join("chrome-config");
  let xdg_config = temp.path().join("xdg-config");

  let chrome_context = context_for(
    PlatformId::Linux,
    home.clone(),
    [
      ("CHROME_CONFIG_HOME", chrome_config.clone()),
      ("XDG_CONFIG_HOME", xdg_config.clone()),
    ],
  );
  let chrome_root = channel_root(&chrome_context, "stable");
  assert_eq!(chrome_root, chrome_config.join("google-chrome"));
  seed_cookie(&chrome_root.join("Default"), true, "chrome", "value");
  let discovery =
    discover_browser_with_context(&chrome_context, "chrome").expect("Chrome override");
  assert_eq!(
    discovery.profiles()[0].path,
    chrome_root.join("Default").canonicalize().unwrap()
  );

  let xdg_context = context_for(
    PlatformId::Linux,
    home.clone(),
    [("XDG_CONFIG_HOME", xdg_config.clone())],
  );
  let xdg_root = channel_root(&xdg_context, "stable");
  assert_eq!(xdg_root, xdg_config.join("google-chrome"));

  let default_context = context_for(PlatformId::Linux, home.clone(), []);
  assert_eq!(
    channel_root(&default_context, "stable"),
    home.join(".config/google-chrome")
  );

  let empty_override_context = context_for(
    PlatformId::Linux,
    home.clone(),
    [
      ("CHROME_CONFIG_HOME", PathBuf::new()),
      ("XDG_CONFIG_HOME", xdg_config.clone()),
    ],
  );
  assert_eq!(
    channel_root(&empty_override_context, "stable"),
    xdg_config.join("google-chrome")
  );
}

#[test]
fn linux_default_config_home_projects_network_cookies_through_legacy_path() {
  let temp = TempDir::new("linux-default-config-home");
  let home = temp.path().join("home");
  let context = context_for(PlatformId::Linux, home.clone(), []);
  let root = channel_root(&context, "stable");
  assert_eq!(root, home.join(".config/google-chrome"));
  seed_cookie(&root.join("Default"), true, "network-cookie", "value");

  let report = extract_chromium_with_provider_and_selection(
    &context,
    "chrome",
    ProfileSelection::LegacyFirstProfile,
    None,
    &CountingProvider::default(),
  )
  .expect("extract default Linux Chrome profile");
  let cookies = crate::browser::legacy::project_chromium_outcome("chrome", report)
    .expect("project legacy Chrome report");

  assert_eq!(cookies.len(), 1);
  assert_eq!(cookies[0].name, "network-cookie");
  assert_eq!(cookies[0].value, "value");
}

#[test]
fn linux_legacy_chromium_ignores_config_home_overrides() {
  for (index, (browser_id, root_id, default_relative)) in [
    ("chrome", "chrome-stable", ".config/google-chrome/Default"),
    (
      "brave",
      "brave-stable-native",
      ".config/BraveSoftware/Brave-Browser/Default",
    ),
  ]
  .into_iter()
  .enumerate()
  {
    let temp = TempDir::new(&format!("legacy-linux-config-home-{index}"));
    let home = temp.path().join("home");
    let chrome_config = temp.path().join("chrome-config");
    let xdg_config = temp.path().join("xdg-config");
    let context = context_for(
      PlatformId::Linux,
      home.clone(),
      [
        ("CHROME_CONFIG_HOME", chrome_config),
        ("XDG_CONFIG_HOME", xdg_config),
      ],
    );
    let override_root = browser_root(&context, browser_id, root_id);
    seed_cookie(
      &override_root.join("Default"),
      true,
      "override-cookie",
      "value",
    );
    let default_profile = home.join(default_relative);
    seed_cookie(&default_profile, true, "home-cookie", "value");

    let generic = discover_browser_with_context(&context, browser_id)
      .expect("generic discovery follows the configured override");
    assert_eq!(generic.profiles().len(), 1);
    assert_eq!(
      generic.profiles()[0].path,
      override_root.join("Default").canonicalize().unwrap()
    );

    let provider = CountingProvider::default();
    let legacy = extract_chromium_with_provider_and_selection(
      &context,
      browser_id,
      ProfileSelection::LegacyFirstProfile,
      None,
      &provider,
    )
    .expect("legacy extraction uses the historical HOME root");
    let selected = legacy
      .installations
      .iter()
      .flat_map(|installation| &installation.profiles)
      .next()
      .expect("HOME profile is selected");
    assert_eq!(selected.cookies()[0].name, "home-cookie");
    assert_eq!(provider.calls.borrow().values().copied().sum::<usize>(), 1);
  }
}

#[test]
fn linux_legacy_chromium_does_not_fall_back_to_override_only_profiles() {
  let temp = TempDir::new("legacy-linux-override-only");
  let home = temp.path().join("home");
  let config_home = temp.path().join("override");
  let context = context_for(
    PlatformId::Linux,
    home,
    [
      ("CHROME_CONFIG_HOME", config_home.clone()),
      ("XDG_CONFIG_HOME", config_home),
    ],
  );
  let override_root = browser_root(&context, "chrome", "chrome-stable");
  seed_cookie(
    &override_root.join("Default"),
    true,
    "override-only",
    "value",
  );
  assert_eq!(
    discover_browser_with_context(&context, "chrome")
      .expect("generic override discovery")
      .profiles()
      .len(),
    1
  );

  let provider = CountingProvider::default();
  let legacy = extract_chromium_with_provider_and_selection(
    &context,
    "chrome",
    ProfileSelection::LegacyFirstProfile,
    None,
    &provider,
  )
  .expect("an override-only profile is ordinary legacy absence");
  assert!(legacy
    .installations
    .iter()
    .all(|installation| installation.profiles.is_empty()));
  assert_eq!(provider.calls.borrow().values().copied().sum::<usize>(), 0);
}

#[test]
fn chrome_config_override_does_not_relocate_other_chromium_browsers() {
  let temp = TempDir::new("chrome-config-isolation");
  let home = temp.path().join("home");
  let chrome_config = temp.path().join("chrome-config");
  let xdg_config = temp.path().join("xdg-config");
  let context = context_for(
    PlatformId::Linux,
    home,
    [
      ("CHROME_CONFIG_HOME", chrome_config.clone()),
      ("XDG_CONFIG_HOME", xdg_config.clone()),
    ],
  );
  assert_eq!(
    browser_root(&context, "chrome", "chrome-stable"),
    chrome_config.join("google-chrome")
  );
  for (browser_id, root_id, relative) in [
    (
      "brave",
      "brave-stable-native",
      "BraveSoftware/Brave-Browser",
    ),
    ("chromium", "chromium-native", "chromium"),
    ("edge", "edge-stable-native", "microsoft-edge"),
    ("opera", "opera-stable-native", "opera"),
    ("vivaldi", "vivaldi-stable-native", "vivaldi"),
  ] {
    assert_eq!(
      browser_root(&context, browser_id, root_id),
      xdg_config.join(relative),
      "{browser_id} must use XDG_CONFIG_HOME rather than CHROME_CONFIG_HOME"
    );
  }
}

// macOS rejects file names that are not valid UTF-8, so the non-Unicode base
// path can only be materialised on the other supported Unix targets.
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn non_unicode_injected_base_path_is_discovered_without_glob_string_conversion() {
  use std::ffi::OsString;
  use std::os::unix::ffi::OsStringExt;

  let temp = TempDir::new("non-unicode-base");
  let config_home = temp
    .path()
    .join(OsString::from_vec(b"config-\xff".to_vec()));
  let context = context_for(
    PlatformId::Linux,
    temp.path().join("home"),
    [("XDG_CONFIG_HOME", config_home.clone())],
  );
  seed_cookie(
    &config_home.join("google-chrome/Default"),
    true,
    "non-unicode",
    "value",
  );
  assert_eq!(
    discover_browser_with_context(&context, "chrome")
      .expect("discover Chrome beneath non-Unicode XDG_CONFIG_HOME")
      .profiles()
      .len(),
    1
  );
}

#[test]
fn glob_expansion_keeps_valid_candidates_when_another_candidate_errors() {
  let temp = TempDir::new("glob-expansion-issues");
  let home = temp.path().join("home");
  let local_app_data = home.join("LocalAppData");
  let real_context = context_for(
    PlatformId::Windows,
    home,
    [("LOCALAPPDATA", local_app_data.clone())],
  );
  let valid = local_app_data.join("Octo Browser/tmp/valid");
  seed_cookie(&valid.join("Default"), true, "valid", "value");
  let injected_issue_path = local_app_data.join("Octo Browser/tmp/inaccessible");
  let mut fs = TestDiscoveryFs::default();
  fs.glob_expansions.insert(
    (local_app_data, "Octo Browser/tmp/*".to_owned()),
    GlobExpansion {
      paths: vec![valid],
      issues: vec![GlobExpansionIssue {
        path: injected_issue_path,
        message: "injected wildcard candidate failure".to_owned(),
      }],
    },
  );
  let context = with_test_fs(real_context, fs);
  let discovery =
    discover_browser_with_context(&context, "octo_browser").expect("retain valid candidate");
  assert_eq!(discovery.profiles().len(), 1);
  assert!(discovery
    .issues
    .iter()
    .any(|issue| issue.code == "installation_glob_expand_failed"));
}

#[test]
fn failed_wildcard_only_root_makes_listing_fail_but_report_keeps_issue() {
  let temp = TempDir::new("glob-expansion-only-failure");
  let home = temp.path().join("home");
  let local_app_data = home.join("LocalAppData");
  let real_context = context_for(
    PlatformId::Windows,
    home,
    [("LOCALAPPDATA", local_app_data.clone())],
  );
  let issue = GlobExpansionIssue {
    path: local_app_data.join("Octo Browser/tmp/inaccessible"),
    message: "injected wildcard candidate failure".to_owned(),
  };
  let mut fs = TestDiscoveryFs::default();
  fs.glob_expansions.insert(
    (local_app_data, "Octo Browser/tmp/*".to_owned()),
    GlobExpansion {
      paths: Vec::new(),
      issues: vec![issue],
    },
  );
  let context = with_test_fs(real_context, fs);

  let listing = discover_browser_with_context(&context, "octo_browser")
    .expect("retain wildcard expansion issue");
  let error = profiles_for_listing("octo_browser", listing)
    .expect_err("blocked wildcard root must not look like an empty installation");
  assert!(error
    .to_string()
    .contains("every detected octo_browser installation failed"));

  let report = extract_chromium_with_provider(
    &context,
    "octo_browser",
    ProfileSelection::AllProfiles,
    None,
    &CountingProvider::default(),
  )
  .expect("report retains discovery issue");
  assert!(report.installations.is_empty());
  assert!(report
    .discovery_issues
    .iter()
    .any(|issue| issue.code == "installation_glob_expand_failed"));
  let error = crate::browser::legacy::project_chromium_outcome("octo_browser", report)
    .expect_err("named projection must preserve a total discovery failure");
  assert!(error
    .to_string()
    .contains("every detected octo_browser installation failed profile enumeration"));
}

#[test]
fn failed_wildcard_with_only_unusable_matches_still_fails_listing() {
  let temp = TempDir::new("glob-expansion-unusable-match");
  let home = temp.path().join("home");
  let local_app_data = home.join("LocalAppData");
  let real_context = context_for(
    PlatformId::Windows,
    home,
    [("LOCALAPPDATA", local_app_data.clone())],
  );
  let unusable = local_app_data.join("Octo Browser/tmp/not-a-directory");
  std::fs::create_dir_all(unusable.parent().expect("match parent")).expect("create match parent");
  std::fs::write(&unusable, b"not a browser root").expect("write regular-file match");
  let mut fs = TestDiscoveryFs::default();
  fs.glob_expansions.insert(
    (local_app_data, "Octo Browser/tmp/*".to_owned()),
    GlobExpansion {
      paths: vec![unusable],
      issues: vec![GlobExpansionIssue {
        path: PathBuf::from("inaccessible-candidate"),
        message: "injected wildcard candidate failure".to_owned(),
      }],
    },
  );
  let context = with_test_fs(real_context, fs);
  let discovery = discover_browser_with_context(&context, "octo_browser")
    .expect("retain issue beside unusable match");
  assert!(profiles_for_listing("octo_browser", discovery).is_err());
}

#[test]
fn inaccessible_root_metadata_is_reported_while_not_found_is_silent() {
  let temp = TempDir::new("root-metadata-failure");
  let home = temp.path().join("home");
  let real_context = context_for(PlatformId::Linux, home, []);
  let root = browser_root(&real_context, "chrome", "chrome-stable");
  let context = with_test_fs(
    real_context,
    TestDiscoveryFs {
      denied_metadata: Some(root.clone()),
      ..TestDiscoveryFs::default()
    },
  );
  let discovery =
    discover_browser_with_context(&context, "chrome").expect("retain metadata failure");
  assert!(discovery
    .issues
    .iter()
    .any(|issue| issue.code == "installation_metadata_failed" && issue.path == root));
  assert!(profiles_for_listing("chrome", discovery).is_err());
}

#[test]
fn missing_optional_wildcard_roots_are_silent() {
  let temp = TempDir::new("missing-wildcard-roots");
  let home = temp.path().join("home");
  let local_app_data = home.join("LocalAppData");
  let context = context_for(
    PlatformId::Windows,
    home,
    [("LOCALAPPDATA", local_app_data)],
  );
  for browser_id in ["arc", "octo_browser"] {
    let discovery =
      discover_browser_with_context(&context, browser_id).expect("missing root is not an error");
    assert!(discovery.installations.is_empty());
    assert!(
      discovery.issues.is_empty(),
      "{browser_id} missing root is silent"
    );
    assert!(profiles_for_listing(browser_id, discovery).is_ok());
  }
}

#[test]
fn available_tiers_reflect_the_compiled_appbound_provider() {
  let registry = embedded_registry().expect("valid embedded registry");
  let windows =
    browser_definition(registry, PlatformId::Windows, "chrome").expect("Windows Chrome definition");
  let descriptor = capability_descriptor(windows, PlatformId::Windows);
  assert!(descriptor
    .declared_decryption_tiers
    .iter()
    .any(|tier| tier == "v20"));
  assert_eq!(
    descriptor
      .available_decryption_tiers
      .iter()
      .any(|tier| tier == "v20"),
    cfg!(feature = "appbound")
  );
  let edge = browser_definition(registry, PlatformId::Windows, "edge").expect("Windows Edge");
  let edge_descriptor = capability_descriptor(edge, PlatformId::Windows);
  assert!(edge_descriptor
    .declared_decryption_tiers
    .iter()
    .any(|tier| tier == "v20"));
  assert_eq!(
    edge_descriptor
      .available_decryption_tiers
      .iter()
      .any(|tier| tier == "v20"),
    cfg!(feature = "appbound")
  );
}

#[test]
fn local_state_marks_active_profiles_without_changing_default_first_order() {
  let temp = TempDir::new("active");
  let context = current_context(temp.path().to_path_buf());
  let root = channel_root(&context, "stable");
  seed_cookie(&root.join("Default"), true, "default", "one");
  seed_cookie(&root.join("Profile 1"), false, "active", "two");
  write_local_state(
    &root,
    serde_json::json!({
      "profile": {
        "last_used": "Profile 1",
        "last_active_profiles": ["Profile 1", "Default"],
        "info_cache": {
          "Default": {"name": "Personal"},
          "Profile 1": {"name": "Work"}
        }
      }
    }),
  );

  let discovery = discover_browser_with_context(&context, "chrome").expect("discover Chrome");
  let profiles = discovery.profiles();
  assert_eq!(profiles.len(), 2);
  assert_eq!(profiles[0].directory_name, "Default");
  assert!(profiles[0].is_default);
  assert!(profiles[0].is_active);
  assert_eq!(profiles[0].active_order, Some(1));
  assert_eq!(profiles[0].display_name, "Personal");
  assert_eq!(profiles[1].directory_name, "Profile 1");
  assert!(profiles[1].is_active);
  assert!(profiles[1].is_last_used);
  assert_eq!(profiles[1].active_order, Some(0));
  assert_eq!(profiles[1].display_name, "Work");
  assert!(profiles
    .iter()
    .all(|profile| profile.profile_id.as_str().len() == 64));
  assert!(profiles
    .iter()
    .all(|profile| profile.installation_id.as_str().len() == 64));
  assert_eq!(profiles[0].persistent_candidates[0].precedence, 10);
  assert!(profiles[0].persistent_candidates[0].selected);

  let mut preferred = profiles.clone();
  prefer_active_profiles(&mut preferred);
  assert_eq!(
    profile_directory_names(&preferred),
    ["Profile 1", "Default"]
  );
  assert!(preferred[0].is_last_used);
}

#[test]
fn last_used_outranks_active_order_even_when_absent_from_the_active_list() {
  // `last_active_profiles` only backfills the last-used profile when it is
  // itself empty (see `parse_local_state`), so a non-empty active list can
  // name a last-used profile that isn't in it at all: `active_order` is
  // then `None` while `is_last_used` is `true`. The doc contract on
  // `chrome_profiles` says the last-used profile is listed first
  // regardless, so it must still outrank profiles with a real
  // `active_order`, not just the ones with no hint at all.
  let temp = TempDir::new("last-used-outranks-active-order");
  let context = current_context(temp.path().to_path_buf());
  let root = channel_root(&context, "stable");
  seed_cookie(&root.join("Default"), true, "default", "one");
  seed_cookie(&root.join("Profile 1"), false, "one-alt", "two");
  seed_cookie(&root.join("Profile 2"), false, "two-alt", "three");
  write_local_state(
    &root,
    serde_json::json!({
      "profile": {
        "last_used": "Default",
        "last_active_profiles": ["Profile 1", "Profile 2"],
      }
    }),
  );

  let discovery = discover_browser_with_context(&context, "chrome").expect("discover Chrome");
  let profiles = discovery.profiles();
  let default_profile = profiles
    .iter()
    .find(|profile| profile.directory_name == "Default")
    .expect("Default profile discovered");
  assert!(default_profile.is_last_used);
  assert_eq!(
    default_profile.active_order, None,
    "Default is last-used but absent from last_active_profiles"
  );
  let profile_one = profiles
    .iter()
    .find(|profile| profile.directory_name == "Profile 1")
    .expect("Profile 1 discovered");
  assert_eq!(profile_one.active_order, Some(0));

  let mut preferred = profiles.clone();
  prefer_active_profiles(&mut preferred);
  assert_eq!(
    profile_directory_names(&preferred),
    ["Default", "Profile 1", "Profile 2"],
    "the last-used profile must sort first even though it carries no active_order"
  );
}

#[test]
fn missing_stale_and_malformed_activity_hints_fall_back_to_default_first() {
  for (tag, local_state) in [
    ("missing", None),
    ("stale", Some(r#"{"profile":{"last_used":"Removed"}}"#)),
    ("malformed", Some("{")),
  ] {
    let temp = TempDir::new(tag);
    let context = current_context(temp.path().to_path_buf());
    let root = channel_root(&context, "stable");
    seed_cookie(&root.join("Default"), true, "default", "one");
    seed_cookie(&root.join("Profile 1"), true, "secondary", "two");
    if let Some(local_state) = local_state {
      std::fs::write(root.join("Local State"), local_state).expect("write Local State");
    }

    let discovery = discover_browser_with_context(&context, "chrome").expect("discover Chrome");
    let mut profiles = discovery.profiles();
    assert_eq!(profile_directory_names(&profiles), ["Default", "Profile 1"]);
    prefer_active_profiles(&mut profiles);
    assert_eq!(
      profile_directory_names(&profiles),
      ["Default", "Profile 1"],
      "{tag} hint must retain the safe fallback"
    );
    if tag == "malformed" {
      assert!(discovery
        .issues
        .iter()
        .any(|issue| issue.code == "local_state_invalid"));
    }
  }
}

#[test]
fn chrome_profile_selection_requires_an_unambiguous_name_directory_or_path() {
  // Chrome profile selection is no longer its own matcher: real discovered
  // Chromium profiles are converted to `ProfileMatchCandidate`s and resolved
  // by the same `match_profile_query` every other engine uses (PR C).
  let temp = TempDir::new("profile-selection");
  let context = current_context(temp.path().to_path_buf());
  let stable = channel_root(&context, "stable");
  let beta = channel_root(&context, "beta");
  seed_cookie(&stable.join("Default"), true, "stable", "one");
  seed_cookie(&beta.join("Default"), true, "beta", "two");
  write_local_state(
    &stable,
    serde_json::json!({"profile": {"info_cache": {"Default": {"name": "Personal"}}}}),
  );
  write_local_state(
    &beta,
    serde_json::json!({
      "profile": {
        "last_used": "Default",
        "info_cache": {"Default": {"name": "Work"}}
      }
    }),
  );

  let discovery = discover_browser_with_context(&context, "chrome").expect("discover Chrome");
  let mut profiles = discovery.profiles();
  prefer_active_profiles(&mut profiles);
  assert_eq!(profiles[0].display_name, "Work");
  let work_id = profiles[0].profile_id.as_str().to_owned();
  let second_id = profiles[1].profile_id.as_str().to_owned();
  let second_path = profiles[1].path.clone();
  let personal_id = profiles
    .iter()
    .find(|profile| profile.display_name == "Personal")
    .expect("Personal profile discovered")
    .profile_id
    .as_str()
    .to_owned();
  let candidates: Vec<_> = profiles.into_iter().map(chromium_match_candidate).collect();

  assert_eq!(
    match_profile_query("chrome", "Personal", &candidates).expect("unique display name"),
    personal_id
  );
  assert_eq!(
    match_profile_query("chrome", &work_id, &candidates).expect("profile ID"),
    work_id
  );
  assert_eq!(
    match_profile_query(
      "chrome",
      second_path.to_string_lossy().as_ref(),
      &candidates
    )
    .expect("full path"),
    second_id
  );
  let ambiguous =
    match_profile_query("chrome", "Default", &candidates).expect_err("two directories");
  assert!(matches!(ambiguous, RequestError::AmbiguousProfile { .. }));
  assert_eq!(ambiguous.profile_ids().len(), 2);
  assert!(matches!(
    match_profile_query("chrome", "", &candidates),
    Err(RequestError::EmptyProfileSelector)
  ));
}

#[cfg(unix)]
#[test]
fn lossy_chrome_profile_paths_require_the_opaque_profile_id() {
  use std::ffi::OsString;
  use std::os::unix::ffi::OsStringExt;

  let temp = TempDir::new("lossy-profile-selector");
  let context = current_context(temp.path().to_path_buf());
  let root = channel_root(&context, "stable");
  seed_cookie(&root.join("Default"), true, "default", "one");
  let discovery = discover_browser_with_context(&context, "chrome").expect("discover Chrome");
  let mut profiles = discovery.profiles();
  let profile_id = profiles[0].profile_id.as_str().to_owned();
  profiles[0].path = PathBuf::from(OsString::from_vec(b"/profile/invalid-\xff".to_vec()));
  let lossy_path = profiles[0].path.to_string_lossy().into_owned();
  let candidates: Vec<_> = profiles.into_iter().map(chromium_match_candidate).collect();

  let error = match_profile_query("chrome", &lossy_path, &candidates)
    .expect_err("a lossy display path cannot round-trip");
  assert!(matches!(error, RequestError::LossyProfilePath { .. }));
  assert_eq!(
    match_profile_query("chrome", &profile_id, &candidates).expect("opaque ID remains lossless"),
    profile_id
  );
}

#[test]
fn same_named_profiles_in_two_channels_have_stable_unique_ids() {
  let temp = TempDir::new("channels");
  let context = current_context(temp.path().to_path_buf());
  let stable = channel_root(&context, "stable");
  let beta = channel_root(&context, "beta");
  seed_cookie(&stable.join("Default"), true, "same", "stable");
  seed_cookie(&beta.join("Default"), true, "same", "beta");
  write_local_state(&stable, serde_json::json!({}));
  write_local_state(&beta, serde_json::json!({}));

  let first = discover_browser_with_context(&context, "chrome").expect("first discovery");
  let second = discover_browser_with_context(&context, "chrome").expect("second discovery");
  let first_profiles = first.profiles();
  let second_profiles = second.profiles();
  assert_eq!(first_profiles.len(), 2);
  assert_ne!(
    first_profiles[0].installation_id,
    first_profiles[1].installation_id
  );
  assert_ne!(first_profiles[0].profile_id, first_profiles[1].profile_id);
  assert_eq!(
    first_profiles
      .iter()
      .map(|profile| &profile.profile_id)
      .collect::<Vec<_>>(),
    second_profiles
      .iter()
      .map(|profile| &profile.profile_id)
      .collect::<Vec<_>>()
  );
}

#[test]
fn report_keeps_profiles_separate_continues_after_failure_and_fetches_keys_once() {
  let temp = TempDir::new("report");
  let context = current_context(temp.path().to_path_buf());
  let root = channel_root(&context, "stable");
  seed_cookie(&root.join("Default"), true, "shared", "default-value");
  seed_cookie(&root.join("Profile 1"), true, "shared", "profile-value");
  let broken = root.join("Profile 2/Network/Cookies");
  std::fs::create_dir_all(broken.parent().expect("broken parent")).expect("create broken");
  std::fs::write(&broken, b"not sqlite").expect("write broken db");
  write_local_state(
    &root,
    serde_json::json!({
      "profile": {
        "last_used": "Profile 1",
        "info_cache": {
          "Default": {"name": "Default"},
          "Profile 1": {"name": "One"},
          "Profile 2": {"name": "Broken"}
        }
      }
    }),
  );
  let provider = CountingProvider::default();

  let report = extract_chromium_with_provider(
    &context,
    "chrome",
    ProfileSelection::AllProfiles,
    None,
    &provider,
  )
  .expect("extract report");
  assert_eq!(report.installations.len(), 1);
  let profiles = &report.installations[0].profiles;
  assert_eq!(profiles.len(), 3);
  assert_eq!(
    provider
      .calls
      .borrow()
      .values()
      .copied()
      .collect::<Vec<_>>(),
    [1]
  );
  let default = profiles
    .iter()
    .find(|profile| profile.profile.directory_name == "Default")
    .expect("Default extraction");
  let good = profiles
    .iter()
    .find(|profile| profile.profile.directory_name == "Profile 1")
    .expect("Profile 1 extraction");
  let broken = profiles
    .iter()
    .find(|profile| profile.profile.directory_name == "Profile 2")
    .expect("Profile 2 extraction");
  assert_eq!(default.cookies()[0].name, "shared");
  assert_eq!(default.cookies()[0].value, "default-value");
  assert_eq!(good.cookies()[0].name, "shared");
  assert_eq!(good.cookies()[0].value, "profile-value");
  assert!(broken.cookies().is_empty());
  // The database was named and reached for, so the failure belongs to the
  // source rather than to the profile.
  assert!(broken.failure.is_none());
  let [broken_source] = &broken.sources[..] else {
    panic!("the broken profile still reports the source it tried to read");
  };
  // The compatibility evidence carries the whole error chain, while the
  // failure carries only the outermost error. The chain is what the legacy
  // API surfaces, so dropping the evidence for failed sources would make its
  // message strictly less informative.
  let evidence = broken_source
    .issues
    .iter()
    .find(|issue| issue.code == SourceIssue::ALL_ROWS_REJECTED)
    .expect("a failed source still carries its compatibility evidence");
  let failure_message = broken_source
    .failure
    .as_ref()
    .map(|failure| failure.message.as_str())
    .expect("the source records its failure");
  assert!(
    evidence.message.starts_with(failure_message),
    "evidence {:?} must extend the failure {failure_message:?}",
    evidence.message
  );
  assert!(
    evidence.message.len() > failure_message.len(),
    "the evidence must add the context the failure alone drops: {:?}",
    evidence.message
  );
  assert!(matches!(
    &broken_source.failure,
    Some(failure) if failure.stage == SourceFailureStage::Acquisition
  ));
}

#[test]
fn generic_extraction_fetches_keys_once_for_each_selected_installation() {
  let temp = TempDir::new("two-installation-key-requests");
  let context = current_context(temp.path().to_path_buf());
  for channel in ["stable", "beta"] {
    let root = channel_root(&context, channel);
    seed_cookie(
      &root.join("Default"),
      true,
      channel,
      &format!("{channel}-value"),
    );
    write_local_state(&root, serde_json::json!({}));
  }
  let provider = CountingProvider::default();

  let report = extract_chromium_with_provider(
    &context,
    "chrome",
    ProfileSelection::AllProfiles,
    None,
    &provider,
  )
  .expect("extract both Chrome installations");
  assert_eq!(report.installations.len(), 2);
  let calls = provider.calls.borrow();
  assert_eq!(calls.len(), 2);
  for installation in &report.installations {
    assert_eq!(
      calls.get(&installation.installation_id),
      Some(&1),
      "each selected installation gets exactly one provider request"
    );
  }
}

#[test]
fn report_preserves_partial_row_stats_and_issues() {
  let temp = TempDir::new("partial-rows");
  let context = current_context(temp.path().to_path_buf());
  let root = channel_root(&context, "stable");
  let db = seed_cookie(&root.join("Default"), true, "readable", "value");
  let connection = rusqlite::Connection::open(db).expect("reopen cookie db");
  connection
    .execute(
      "INSERT INTO cookies VALUES ('.example.com', '/', 0, 0, 'skipped', '', ?1, 0, 0)",
      params![b"v10ciphertext".as_slice()],
    )
    .expect("insert undecryptable row");
  write_local_state(&root, serde_json::json!({}));

  let report = extract_chromium_with_provider(
    &context,
    "chrome",
    ProfileSelection::AllProfiles,
    None,
    &CountingProvider::default(),
  )
  .expect("partial report");
  let extraction = &report.installations[0].profiles[0];
  assert_eq!(extraction.cookies().len(), 1);
  assert_eq!(extraction.cookies()[0].name, "readable");
  let [source] = &extraction.sources[..] else {
    panic!("the profile extracts its one selected source");
  };
  assert_eq!(source.stats.rows_seen, 2);
  assert_eq!(source.stats.cookies_emitted, 1);
  assert_eq!(source.stats.rows_skipped, 1);
  assert_eq!(source.issues.len(), 1);
  assert_eq!(source.issues[0].occurrences, 1);
  assert!(source.failure.is_none());
  assert!(extraction.failure.is_none());
}

#[test]
fn profile_selector_uses_opaque_id_and_limits_key_retrieval() {
  let temp = TempDir::new("select");
  let context = current_context(temp.path().to_path_buf());
  let root = channel_root(&context, "stable");
  seed_cookie(&root.join("Default"), true, "default", "one");
  seed_cookie(&root.join("Profile 1"), true, "selected", "two");
  write_local_state(&root, serde_json::json!({}));
  let discovery = discover_browser_with_context(&context, "chrome").expect("discover");
  let profile_id = discovery
    .profiles()
    .into_iter()
    .find(|profile| profile.directory_name == "Profile 1")
    .expect("Profile 1")
    .profile_id;
  let provider = CountingProvider::default();

  let report = extract_chromium_with_provider(
    &context,
    "chrome",
    ProfileSelection::ProfileId(profile_id.as_str()),
    Some(vec!["example.com".to_owned()]),
    &provider,
  )
  .expect("selected report");
  assert_eq!(report.installations.len(), 1);
  assert_eq!(report.installations[0].profiles.len(), 1);
  assert_eq!(
    report.installations[0].profiles[0].profile.profile_id,
    profile_id
  );
  assert_eq!(
    report.installations[0].profiles[0].cookies()[0].name,
    "selected"
  );
  assert_eq!(
    provider
      .calls
      .borrow()
      .values()
      .copied()
      .collect::<Vec<_>>(),
    [1]
  );

  let error = extract_chromium_with_provider(
    &context,
    "chrome",
    ProfileSelection::ProfileId("not-a-profile-id"),
    None,
    &provider,
  )
  .expect_err("unknown profile must fail");
  assert!(error.to_string().contains("unknown chrome profile id"));
}

#[test]
fn legacy_chromium_policy_reads_default_only_and_preserves_row_order() {
  let temp = TempDir::new("legacy-first");
  let context = current_context(temp.path().to_path_buf());
  let root = channel_root(&context, "stable");
  let database = seed_cookie(&root.join("Default"), true, "z-cookie", "one");
  let connection = rusqlite::Connection::open(database).expect("reopen cookie db");
  connection
    .execute(
      "INSERT INTO cookies VALUES ('.example.com', '/', 0, 0, 'a-cookie', 'two', ?1, 0, 0)",
      params![Vec::<u8>::new()],
    )
    .expect("insert second cookie");
  drop(connection);
  seed_cookie(&root.join("Profile 1"), true, "secondary", "three");
  write_local_state(&root, serde_json::json!({}));
  let provider = CountingProvider::default();

  let report = extract_chromium_with_provider_and_selection(
    &context,
    "chrome",
    ProfileSelection::LegacyFirstProfile,
    None,
    &provider,
  )
  .expect("legacy extraction");
  let profiles = report
    .installations
    .iter()
    .flat_map(|installation| &installation.profiles)
    .collect::<Vec<_>>();
  assert_eq!(profiles.len(), 1);
  assert_eq!(profiles[0].profile.directory_name, "Default");
  assert_eq!(
    profiles[0]
      .cookies()
      .iter()
      .map(|cookie| cookie.name.as_str())
      .collect::<Vec<_>>(),
    ["z-cookie", "a-cookie"]
  );
  assert_eq!(provider.calls.borrow().values().copied().sum::<usize>(), 1);
}

#[test]
fn legacy_chromium_policy_exhausts_source_precedence_across_channels() {
  let temp = TempDir::new("legacy-source-precedence");
  let context = context_for(PlatformId::Linux, temp.path().join("home"), []);
  let stable = channel_root(&context, "stable");
  let beta = channel_root(&context, "beta");
  seed_cookie(&stable.join("Default"), false, "stable-legacy", "one");
  seed_cookie(&beta.join("Default"), true, "beta-network", "two");

  let provider = CountingProvider::default();
  let report = extract_chromium_with_provider_and_selection(
    &context,
    "chrome",
    ProfileSelection::LegacyFirstProfile,
    None,
    &provider,
  )
  .expect("legacy extraction");
  let extraction = report
    .installations
    .iter()
    .flat_map(|installation| &installation.profiles)
    .next()
    .expect("selected profile");

  assert_eq!(
    extraction.profile.path,
    beta.join("Default").canonicalize().unwrap()
  );
  assert_eq!(extraction.cookies().len(), 1);
  assert_eq!(extraction.cookies()[0].name, "beta-network");
  assert_eq!(provider.calls.borrow().values().copied().sum::<usize>(), 1);
}

#[test]
fn legacy_chromium_policy_prefers_default_group_before_profile_source() {
  let temp = TempDir::new("legacy-profile-group-precedence");
  let context = context_for(PlatformId::Linux, temp.path().join("home"), []);
  let stable = channel_root(&context, "stable");
  let beta = channel_root(&context, "beta");
  seed_cookie(&stable.join("Default"), false, "stable-default", "one");
  seed_cookie(&beta.join("Profile 1"), true, "beta-profile-network", "two");

  let provider = CountingProvider::default();
  let report = extract_chromium_with_provider_and_selection(
    &context,
    "chrome",
    ProfileSelection::LegacyFirstProfile,
    None,
    &provider,
  )
  .expect("legacy extraction");
  let extraction = report
    .installations
    .iter()
    .flat_map(|installation| &installation.profiles)
    .next()
    .expect("selected profile");

  assert_eq!(
    extraction.profile.path,
    stable.join("Default").canonicalize().unwrap()
  );
  assert_eq!(extraction.cookies()[0].name, "stable-default");
  assert_eq!(provider.calls.borrow().values().copied().sum::<usize>(), 1);
}

#[test]
fn legacy_chromium_policy_prefers_native_root_group_before_flatpak_source() {
  let temp = TempDir::new("legacy-root-group-precedence");
  let context = context_for(PlatformId::Linux, temp.path().join("home"), []);
  let native = channel_root(&context, "stable");
  let flatpak = browser_root(&context, "chrome", "chrome-flatpak");
  seed_cookie(&native.join("Default"), false, "native-legacy", "one");
  seed_cookie(&flatpak.join("Default"), true, "flatpak-network", "two");

  let provider = CountingProvider::default();
  let report = extract_chromium_with_provider_and_selection(
    &context,
    "chrome",
    ProfileSelection::LegacyFirstProfile,
    None,
    &provider,
  )
  .expect("legacy extraction");
  let extraction = report
    .installations
    .iter()
    .flat_map(|installation| &installation.profiles)
    .next()
    .expect("selected profile");

  assert_eq!(
    extraction.profile.path,
    native.join("Default").canonicalize().unwrap()
  );
  assert_eq!(extraction.cookies()[0].name, "native-legacy");
  assert_eq!(provider.calls.borrow().values().copied().sum::<usize>(), 1);
}

#[test]
fn legacy_chromium_profile_fallback_uses_directory_not_display_order() {
  let temp = TempDir::new("legacy-profile-directory-order");
  let context = current_context(temp.path().to_path_buf());
  let root = channel_root(&context, "stable");
  seed_cookie(&root.join("Profile 1"), true, "first-directory", "one");
  seed_cookie(&root.join("Profile 2"), true, "second-directory", "two");
  write_local_state(
    &root,
    serde_json::json!({
      "profile": {
        "info_cache": {
          "Profile 1": {"name": "Personal"},
          "Profile 2": {"name": "Business"}
        }
      }
    }),
  );

  let discovery = discover_browser_with_context(&context, "chrome").expect("discover Chrome");
  assert_eq!(
    discovery
      .profiles()
      .iter()
      .map(|profile| profile.directory_name.as_str())
      .collect::<Vec<_>>(),
    ["Profile 2", "Profile 1"],
    "generic report ordering remains display-name based"
  );

  let provider = CountingProvider::default();
  let report = extract_chromium_with_provider_and_selection(
    &context,
    "chrome",
    ProfileSelection::LegacyFirstProfile,
    None,
    &provider,
  )
  .expect("legacy extraction");
  let extraction = report
    .installations
    .iter()
    .flat_map(|installation| &installation.profiles)
    .next()
    .expect("selected profile");

  assert_eq!(extraction.profile.directory_name, "Profile 1");
  assert_eq!(extraction.cookies()[0].name, "first-directory");
  assert_eq!(provider.calls.borrow().values().copied().sum::<usize>(), 1);
}

#[test]
fn legacy_opera_wrappers_use_flat_roots_on_macos_and_windows() {
  for (platform, browser_id, root_id) in [
    (PlatformId::Macos, "opera", "opera-stable"),
    (PlatformId::Macos, "opera_gx", "opera-gx-stable"),
    (PlatformId::Windows, "opera", "opera-stable-local"),
    (PlatformId::Windows, "opera_gx", "opera-gx-stable-local"),
  ] {
    let temp = TempDir::new(&format!("legacy-{browser_id}-{platform:?}"));
    let home = temp.path().join("home");
    let local = home.join("LocalAppData");
    let roaming = home.join("AppData/Roaming");
    let context = context_for(
      platform,
      home,
      [("LOCALAPPDATA", local), ("APPDATA", roaming)],
    );
    let root = browser_root(&context, browser_id, root_id);
    seed_cookie(&root, true, "flat", "value");
    seed_cookie(&root.join("Default"), true, "default", "value");
    if platform == PlatformId::Windows {
      write_local_state(&root, serde_json::json!({}));
    }

    let generic = discover_browser_with_context(&context, browser_id).expect("generic discovery");
    assert_eq!(generic.profiles().len(), 1);
    assert_eq!(generic.profiles()[0].directory_name, "Default");

    let provider = CountingProvider::default();
    let report = extract_chromium_with_provider_and_selection(
      &context,
      browser_id,
      ProfileSelection::LegacyFirstProfile,
      None,
      &provider,
    )
    .expect("legacy extraction");
    let selected = report
      .installations
      .iter()
      .flat_map(|installation| &installation.profiles)
      .next()
      .expect("flat profile");
    assert_eq!(selected.profile.directory_name, ".");
    assert_eq!(selected.cookies()[0].name, "flat");
    assert_eq!(provider.calls.borrow().values().copied().sum::<usize>(), 1);
  }

  let temp = TempDir::new("legacy-macos-opera-root-order");
  let context = context_for(PlatformId::Macos, temp.path().join("home"), []);
  let stable = browser_root(&context, "opera", "opera-stable");
  let next = browser_root(&context, "opera", "opera-next");
  seed_cookie(&stable, false, "stable-cookies", "value");
  seed_cookie(&next, true, "next-network", "value");
  let report = extract_chromium_with_provider_and_selection(
    &context,
    "opera",
    ProfileSelection::LegacyFirstProfile,
    None,
    &CountingProvider::default(),
  )
  .expect("legacy macOS Opera extraction");
  let selected = report
    .installations
    .iter()
    .flat_map(|installation| &installation.profiles)
    .next()
    .expect("stable flat profile");
  assert_eq!(selected.cookies()[0].name, "stable-cookies");

  let temp = TempDir::new("legacy-linux-opera-default-before-flat");
  let context = context_for(PlatformId::Linux, temp.path().join("home"), []);
  let root = browser_root(&context, "opera", "opera-stable-native");
  seed_cookie(&root.join("Default"), false, "default", "value");
  seed_cookie(&root, true, "flat", "value");
  let provider = CountingProvider::default();
  let report = extract_chromium_with_provider_and_selection(
    &context,
    "opera",
    ProfileSelection::LegacyFirstProfile,
    None,
    &provider,
  )
  .expect("legacy Linux Opera extraction");
  let selected = report
    .installations
    .iter()
    .flat_map(|installation| &installation.profiles)
    .next()
    .expect("Default profile");
  assert_eq!(selected.profile.directory_name, "Default");
  assert_eq!(selected.cookies()[0].name, "default");
  assert_eq!(provider.calls.borrow().values().copied().sum::<usize>(), 1);
}

#[test]
fn legacy_linux_package_order_is_registry_metadata_not_generic_priority() {
  for (index, (browser_id, earlier_root, later_root)) in [
    ("arc", "arc-snap", "arc-native"),
    ("brave", "brave-snap", "brave-stable-native"),
    ("chromium", "chromium-snap", "chromium-native"),
    ("opera", "opera-stable-snap", "opera-stable-native"),
    ("opera", "opera-stable-native", "opera-beta-snap"),
  ]
  .into_iter()
  .enumerate()
  {
    let temp = TempDir::new(&format!("legacy-linux-package-{index}"));
    let context = context_for(PlatformId::Linux, temp.path().join("home"), []);
    let earlier = browser_root(&context, browser_id, earlier_root);
    let later = browser_root(&context, browser_id, later_root);
    seed_cookie(&earlier.join("Default"), true, earlier_root, "value");
    seed_cookie(&later.join("Default"), true, later_root, "value");

    let provider = CountingProvider::default();
    let report = extract_chromium_with_provider_and_selection(
      &context,
      browser_id,
      ProfileSelection::LegacyFirstProfile,
      None,
      &provider,
    )
    .expect("legacy extraction");
    let selected = report
      .installations
      .iter()
      .flat_map(|installation| &installation.profiles)
      .next()
      .expect("selected profile");
    assert_eq!(selected.cookies()[0].name, earlier_root);
    assert_eq!(provider.calls.borrow().values().copied().sum::<usize>(), 1);
  }
}

#[test]
fn markerless_chromium_profiles_remain_generic_only() {
  let temp = TempDir::new("legacy-markerless-profile");
  let context = context_for(PlatformId::Linux, temp.path().join("home"), []);
  let root = channel_root(&context, "stable");
  seed_cookie(&root.join("Work"), true, "work", "value");

  let generic = discover_browser_with_context(&context, "chrome").expect("generic discovery");
  assert_eq!(generic.profiles().len(), 1);
  assert_eq!(generic.profiles()[0].directory_name, "Work");

  let provider = CountingProvider::default();
  let report = extract_chromium_with_provider_and_selection(
    &context,
    "chrome",
    ProfileSelection::LegacyFirstProfile,
    None,
    &provider,
  )
  .expect("legacy projection remains ordinary absence");
  assert!(report
    .installations
    .iter()
    .all(|installation| installation.profiles.is_empty()));
  assert_eq!(provider.calls.borrow().values().copied().sum::<usize>(), 0);
}

#[test]
fn windows_legacy_chromium_requires_readable_valid_local_state_before_query() {
  let temp = TempDir::new("windows-legacy-local-state");
  let home = temp.path().join("home");
  let local_app_data = home.join("LocalAppData");
  let context = context_for(
    PlatformId::Windows,
    home,
    [("LOCALAPPDATA", local_app_data)],
  );
  let root = browser_root(&context, "chrome", "chrome-stable-local");
  seed_cookie(&root.join("Default"), true, "plaintext", "value");

  let generic_provider = CountingProvider::default();
  let generic = extract_chromium_with_provider(
    &context,
    "chrome",
    ProfileSelection::AllProfiles,
    None,
    &generic_provider,
  )
  .expect("generic reports tolerate missing Local State for plaintext rows");
  assert_eq!(generic.installations[0].profiles[0].cookies().len(), 1);
  assert_eq!(
    generic_provider
      .calls
      .borrow()
      .values()
      .copied()
      .sum::<usize>(),
    1
  );

  let missing_provider = CountingProvider::default();
  let missing = extract_chromium_with_provider_and_selection(
    &context,
    "chrome",
    ProfileSelection::LegacyFirstProfile,
    None,
    &missing_provider,
  )
  .expect_err("legacy extraction requires Local State before querying plaintext rows");
  assert!(missing.to_string().contains("can't find Local State"));
  assert_eq!(
    missing_provider
      .calls
      .borrow()
      .values()
      .copied()
      .sum::<usize>(),
    0
  );

  std::fs::write(root.join("Local State"), b"{").expect("write malformed Local State");
  let malformed_provider = CountingProvider::default();
  let malformed = extract_chromium_with_provider_and_selection(
    &context,
    "chrome",
    ProfileSelection::LegacyFirstProfile,
    None,
    &malformed_provider,
  )
  .expect_err("legacy extraction rejects malformed Local State before querying");
  assert!(malformed
    .to_string()
    .contains("Can't read Local State JSON"));
  assert_eq!(
    malformed_provider
      .calls
      .borrow()
      .values()
      .copied()
      .sum::<usize>(),
    0
  );

  std::fs::write(root.join("Local State"), b"{}").expect("write valid Local State");
  let valid_provider = CountingProvider::default();
  let valid = extract_chromium_with_provider_and_selection(
    &context,
    "chrome",
    ProfileSelection::LegacyFirstProfile,
    None,
    &valid_provider,
  )
  .expect("valid Local State allows legacy plaintext extraction");
  assert_eq!(
    valid.installations[0].profiles[0].cookies()[0].name,
    "plaintext"
  );
  assert_eq!(
    valid_provider
      .calls
      .borrow()
      .values()
      .copied()
      .sum::<usize>(),
    1
  );
  let canonical_local_state = root
    .join("Local State")
    .canonicalize()
    .expect("canonical Local State");
  let denied_context = DiscoveryContext {
    platform: context.platform,
    home: context.home.clone(),
    env: context.env.clone(),
    fs: TestDiscoveryFs {
      denied_read_to_string: Some(canonical_local_state),
      ..TestDiscoveryFs::default()
    },
  };
  let denied_provider = CountingProvider::default();
  let denied = extract_chromium_with_provider_and_selection(
    &denied_context,
    "chrome",
    ProfileSelection::LegacyFirstProfile,
    None,
    &denied_provider,
  )
  .expect_err("legacy extraction rejects unreadable Local State before querying");
  assert!(denied.to_string().contains("read Local State"));
  assert!(format!("{denied:#}").contains("injected file read denial"));
  assert_eq!(
    denied_provider
      .calls
      .borrow()
      .values()
      .copied()
      .sum::<usize>(),
    0
  );
}

#[test]
fn windows_legacy_flat_opera_uses_local_state_beside_selected_database() {
  let temp = TempDir::new("windows-legacy-flat-opera-state");
  let home = temp.path().join("home");
  let local_app_data = home.join("LocalAppData");
  let context = context_for(
    PlatformId::Windows,
    home,
    [("LOCALAPPDATA", local_app_data)],
  );
  let root = browser_root(&context, "opera", "opera-stable-local");
  seed_cookie(&root, false, "opera", "value");
  std::fs::write(root.join("Local State"), b"{}").expect("write valid Local State");

  let provider = CountingProvider::default();
  let report = extract_chromium_with_provider_and_selection(
    &context,
    "opera",
    ProfileSelection::LegacyFirstProfile,
    None,
    &provider,
  )
  .expect("flat Opera resolves Local State beside Cookies");
  let selected = report
    .installations
    .iter()
    .flat_map(|installation| &installation.profiles)
    .next()
    .expect("flat Opera profile");
  assert_eq!(selected.cookies()[0].name, "opera");
  assert_eq!(provider.calls.borrow().values().copied().sum::<usize>(), 1);
}

#[test]
fn legacy_linux_snap_roots_admit_only_default_profiles() {
  for (index, (browser_id, snap_root_id, native_root_id)) in [
    ("arc", "arc-snap", "arc-native"),
    ("brave", "brave-snap", "brave-stable-native"),
    ("chromium", "chromium-snap", "chromium-native"),
  ]
  .into_iter()
  .enumerate()
  {
    let temp = TempDir::new(&format!("legacy-snap-profile-shape-{index}"));
    let context = context_for(PlatformId::Linux, temp.path().join("home"), []);
    let snap = browser_root(&context, browser_id, snap_root_id);
    let native = browser_root(&context, browser_id, native_root_id);
    seed_cookie(&snap.join("Profile 1"), true, "snap-profile", "value");
    seed_cookie(&native.join("Default"), true, "native-default", "value");

    let provider = CountingProvider::default();
    let report = extract_chromium_with_provider_and_selection(
      &context,
      browser_id,
      ProfileSelection::LegacyFirstProfile,
      None,
      &provider,
    )
    .expect("legacy extraction");
    let selected = report
      .installations
      .iter()
      .flat_map(|installation| &installation.profiles)
      .next()
      .expect("native Default remains eligible");
    assert_eq!(selected.cookies()[0].name, "native-default");
    assert_eq!(provider.calls.borrow().values().copied().sum::<usize>(), 1);
  }
}

#[test]
fn corrupt_local_state_does_not_hide_source_bearing_profiles() {
  let temp = TempDir::new("bad-state");
  let context = current_context(temp.path().to_path_buf());
  let root = channel_root(&context, "stable");
  seed_cookie(&root.join("Default"), true, "cookie", "value");
  std::fs::write(root.join("Local State"), b"{").expect("write corrupt Local State");

  let discovery = discover_browser_with_context(&context, "chrome").expect("discover");
  assert_eq!(discovery.profiles().len(), 1);
  assert!(discovery
    .issues
    .iter()
    .any(|issue| issue.code == "local_state_invalid"));
}

#[test]
fn copied_markerless_and_flat_installations_are_discoverable() {
  let temp = TempDir::new("fallbacks");
  let context = current_context(temp.path().to_path_buf());
  let root = channel_root(&context, "stable");
  std::fs::create_dir_all(root.join("Default")).expect("create stale marker");
  seed_cookie(&root.join("Restored Account"), false, "restored", "one");
  let discovery = discover_browser_with_context(&context, "chrome").expect("markerless");
  assert_eq!(discovery.profiles()[0].directory_name, "Restored Account");
  assert!(discovery
    .issues
    .iter()
    .any(|issue| issue.code == "profile_has_no_cookie_source"));

  std::fs::remove_dir_all(&root).expect("remove markerless root");
  seed_cookie(&root, false, "flat", "two");
  std::fs::create_dir_all(root.join("Default")).expect("create stale marker");
  let discovery = discover_browser_with_context(&context, "chrome").expect("flat");
  assert_eq!(discovery.profiles()[0].directory_name, ".");
  assert!(discovery.profiles()[0].is_default);
  assert!(discovery
    .issues
    .iter()
    .any(|issue| issue.code == "profile_has_no_cookie_source"));
}

#[test]
fn report_retains_total_enumeration_failures_while_listing_errors() {
  let temp = TempDir::new("enumeration-failure");
  let real_context = current_context(temp.path().to_path_buf());
  let root = channel_root(&real_context, "stable");
  std::fs::create_dir_all(&root).expect("create detected installation");
  let canonical_root = root.canonicalize().expect("canonical installation root");
  let context = with_test_fs(
    real_context,
    TestDiscoveryFs {
      denied_read_dir: Some(canonical_root),
      ..TestDiscoveryFs::default()
    },
  );

  let listing_discovery =
    discover_browser_with_context(&context, "chrome").expect("retain discovery failure");
  let listing_error = profiles_for_listing("chrome", listing_discovery)
    .expect_err("bare listing must surface total failure");
  assert!(listing_error
    .to_string()
    .contains("every detected chrome installation failed"));

  let provider = CountingProvider::default();
  let report = extract_chromium_with_provider(
    &context,
    "chrome",
    ProfileSelection::AllProfiles,
    None,
    &provider,
  )
  .expect("failed report outcome");
  assert_eq!(report.installations.len(), 1);
  assert!(report.installations[0].profiles.is_empty());
  assert!(report
    .discovery_issues
    .iter()
    .any(|issue| issue.code == "installation_enumeration_failed"));
  assert!(provider.calls.borrow().is_empty());
}

#[test]
fn listing_fails_when_every_chromium_profile_is_lost_after_enumeration() {
  let temp = TempDir::new("profile-discovery-failure");
  let real_context = current_context(temp.path().to_path_buf());
  let root = channel_root(&real_context, "stable");
  let profile = root.join("Default");
  seed_cookie(&profile, true, "default", "value");
  let denied_profile = profile.canonicalize().expect("canonical profile");
  let context = with_test_fs(
    real_context,
    TestDiscoveryFs {
      denied_canonicalize: vec![denied_profile],
      ..TestDiscoveryFs::default()
    },
  );

  let discovery =
    discover_browser_with_context(&context, "chrome").expect("retain profile failure");
  assert!(!discovery.all_detected_roots_failed());
  assert!(discovery.profiles().is_empty());
  assert!(discovery
    .issues
    .iter()
    .any(|issue| issue.code == "profile_canonicalize_failed"));
  let error = profiles_for_listing("chrome", discovery)
    .expect_err("lost profiles must not look like an absent browser");
  assert!(error
    .to_string()
    .contains("every discovered chrome profile failed discovery"));

  let report = extract_chromium_with_provider_and_selection(
    &context,
    "chrome",
    ProfileSelection::LegacyFirstProfile,
    None,
    &CountingProvider::default(),
  )
  .expect("retain failed legacy discovery");
  let error = crate::browser::legacy::project_chromium_outcome("chrome", report)
    .expect_err("named extraction must surface lost profiles");
  assert!(error
    .to_string()
    .contains("every discovered chrome profile failed discovery"));
}

#[test]
fn generic_listing_names_the_selected_browser_when_all_roots_fail() {
  let temp = TempDir::new("edge-enumeration-failure");
  let home = temp.path().join("home");
  let local_app_data = home.join("LocalAppData");
  let real_context = context_for(
    PlatformId::Windows,
    home,
    [("LOCALAPPDATA", local_app_data)],
  );
  let root = browser_root(&real_context, "edge", "edge-stable-local");
  std::fs::create_dir_all(&root).expect("create detected Edge installation");
  let canonical_root = root.canonicalize().expect("canonical Edge installation");
  let context = with_test_fs(
    real_context,
    TestDiscoveryFs {
      denied_read_dir: Some(canonical_root),
      ..TestDiscoveryFs::default()
    },
  );
  let discovery = discover_browser_with_context(&context, "edge").expect("retain failure");
  let error = profiles_for_listing("edge", discovery).expect_err("listing must surface failure");
  assert!(error
    .to_string()
    .contains("every detected edge installation failed"));
}

#[test]
fn flat_profiles_are_deduplicated_by_selected_source() {
  let temp = TempDir::new("flat-dedup");
  let real_context = current_context(temp.path().to_path_buf());
  let stable = channel_root(&real_context, "stable");
  let beta = channel_root(&real_context, "beta");
  let stable_source = seed_cookie(&stable, false, "same", "stable");
  let beta_source = seed_cookie(&beta, false, "same", "beta");
  let stable_source = stable_source
    .canonicalize()
    .expect("canonical stable source");
  let beta_source = beta_source.canonicalize().expect("canonical beta source");
  let shared_identity = temp.path().join("canonical-shared-cookie-store");
  let context = with_test_fs(
    real_context,
    TestDiscoveryFs {
      canonical_aliases: BTreeMap::from([
        (stable_source, shared_identity.clone()),
        (beta_source, shared_identity),
      ]),
      ..TestDiscoveryFs::default()
    },
  );

  let discovery = discover_browser_with_context(&context, "chrome").expect("discover flats");
  assert_eq!(discovery.profiles().len(), 1);
  assert_eq!(discovery.profiles()[0].directory_name, ".");
  assert!(discovery
    .issues
    .iter()
    .any(|issue| issue.code == "duplicate_profile"));
}

fn windows_context(home: PathBuf) -> DiscoveryContext<RealDiscoveryFs> {
  let local_app_data = home.join("LocalAppData");
  let roaming_app_data = home.join("AppData");
  context_for(
    PlatformId::Windows,
    home,
    [
      ("LOCALAPPDATA", local_app_data),
      ("APPDATA", roaming_app_data),
    ],
  )
}

fn profile_directory_names(profiles: &[ChromiumProfile]) -> Vec<&str> {
  profiles
    .iter()
    .map(|profile| profile.directory_name.as_str())
    .collect()
}

#[test]
fn windows_batch_browsers_declare_frozen_ids_aliases_and_roots() {
  let registry = embedded_registry().expect("valid embedded registry");
  let cases = [
    (
      "browser_from_vought",
      "Browser from Vought",
      ["vought"].as_slice(),
      [
        (
          "browser-from-vought-roaming",
          "{roaming_app_data}/Browser from Vought",
        ),
        (
          "browser-from-vought-local",
          "{local_app_data}/Browser from Vought",
        ),
      ]
      .as_slice(),
    ),
    (
      "dc_browser",
      "DC Browser",
      ["dc"].as_slice(),
      [
        ("dc-browser-local", "{local_app_data}/DCBrowser/User Data"),
        (
          "dc-browser-roaming",
          "{roaming_app_data}/DCBrowser/User Data",
        ),
      ]
      .as_slice(),
    ),
    (
      "qq_browser",
      "QQ Browser",
      ["qq"].as_slice(),
      [
        (
          "qq-browser-local",
          "{local_app_data}/Tencent/QQBrowser/User Data",
        ),
        (
          "qq-browser-roaming",
          "{roaming_app_data}/Tencent/QQBrowser/User Data",
        ),
      ]
      .as_slice(),
    ),
    (
      "sogou",
      "Sogou Explorer",
      [].as_slice(),
      [
        (
          "sogou-local",
          "{local_app_data}/Sogou/SogouExplorer/User Data",
        ),
        (
          "sogou-roaming",
          "{roaming_app_data}/Sogou/SogouExplorer/User Data",
        ),
      ]
      .as_slice(),
    ),
    (
      "speed_360",
      "360 Browser",
      ["360"].as_slice(),
      [
        (
          "speed-360-local",
          "{local_app_data}/360chrome/Chrome/User Data",
        ),
        (
          "speed-360-roaming",
          "{roaming_app_data}/360chrome/Chrome/User Data",
        ),
      ]
      .as_slice(),
    ),
    (
      "speed_360x",
      "360X Browser",
      ["360x"].as_slice(),
      [
        (
          "speed-360x-local",
          "{local_app_data}/360ChromeX/Chrome/User Data",
        ),
        (
          "speed-360x-roaming",
          "{roaming_app_data}/360ChromeX/Chrome/User Data",
        ),
      ]
      .as_slice(),
    ),
    (
      "yandex",
      "Yandex Browser",
      [].as_slice(),
      [
        (
          "yandex-local",
          "{local_app_data}/Yandex/YandexBrowser/User Data",
        ),
        (
          "yandex-roaming",
          "{roaming_app_data}/Yandex/YandexBrowser/User Data",
        ),
      ]
      .as_slice(),
    ),
  ];

  for (canonical_id, display_name, aliases, roots) in cases {
    let definition = browser_definition(registry, PlatformId::Windows, canonical_id)
      .expect("Windows batch definition");
    assert_eq!(definition.canonical_id, canonical_id);
    assert_eq!(definition.display_name, display_name);
    assert_eq!(definition.engine, BrowserEngine::Chromium);
    assert_eq!(
      definition
        .aliases
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>(),
      aliases
    );
    assert_eq!(
      definition
        .roots
        .iter()
        .map(|root| (root.root_id.as_str(), root.template.as_str()))
        .collect::<Vec<_>>(),
      roots
    );
    assert!(definition.roots.iter().all(
      |root| root.channel == "stable" && root.discovery == DiscoveryStrategy::ChromiumUserData
    ));
    assert_eq!(
      definition
        .roots
        .iter()
        .map(|root| root.priority)
        .collect::<Vec<_>>(),
      [10u16, 20]
    );
    assert_eq!(
      definition.capabilities.declared_persistent_formats,
      ["chromium_sqlite"]
    );
    assert!(definition.capabilities.declared_session_formats.is_empty());
    assert_eq!(
      definition.capabilities.declared_decryption_tiers,
      ["legacy_dpapi", "v10"]
    );
    for alias in aliases {
      assert_eq!(
        browser_definition(registry, PlatformId::Windows, alias)
          .expect("alias resolves to the canonical definition")
          .canonical_id,
        canonical_id
      );
    }
    // This batch is Windows-only, except that 6B separately registered
    // Yandex on macOS. Everything else must stay absent from the other
    // platforms rather than being registered without researched roots.
    if canonical_id != "yandex" {
      for platform in [PlatformId::Macos, PlatformId::Linux] {
        assert!(
          browser_definition(registry, platform, canonical_id).is_err(),
          "{canonical_id} must stay Windows-only"
        );
      }
    }
    assert!(browser_definition(registry, PlatformId::Linux, canonical_id).is_err());
  }
}

#[test]
fn windows_batch_standard_layouts_use_local_state_profile_metadata() {
  let temp = TempDir::new("windows-batch-standard");
  let context = windows_context(temp.path().join("home"));
  for (browser_id, root_id) in [
    ("yandex", "yandex-local"),
    ("speed_360", "speed-360-local"),
    ("speed_360x", "speed-360x-local"),
    ("dc_browser", "dc-browser-local"),
    // The Tencent-derived forks need the same Local State handling as the
    // standard layouts, and are the likeliest to diverge.
    ("qq_browser", "qq-browser-local"),
    ("sogou", "sogou-local"),
  ] {
    let root = browser_root(&context, browser_id, root_id);
    seed_cookie(&root.join("Default"), true, "personal", "one");
    seed_cookie(&root.join("Profile 1"), false, "work", "two");
    write_local_state(
      &root,
      serde_json::json!({
        "profile": {
          "last_used": "Profile 1",
          "last_active_profiles": ["Profile 1"],
          "info_cache": {
            "Default": {"name": "Personal"},
            "Profile 1": {"name": "Work"}
          }
        }
      }),
    );

    let discovery = discover_browser_with_context(&context, browser_id).expect("discover");
    assert_eq!(discovery.installations.len(), 1);
    let installation = &discovery.installations[0];
    assert_eq!(installation.root_id, root_id);
    assert_eq!(
      installation.local_state_path,
      installation.path.join("Local State")
    );
    let profiles = discovery.profiles();
    assert_eq!(
      profile_directory_names(&profiles),
      ["Default", "Profile 1"],
      "{browser_id} profile order"
    );
    assert_eq!(profiles[0].display_name, "Personal");
    assert!(profiles[0].is_default);
    assert!(profiles[0].persistent_candidates[0].selected);
    assert_eq!(profiles[1].display_name, "Work");
    assert!(profiles[1].is_last_used);
    assert_eq!(profiles[1].active_order, Some(0));
    assert_eq!(profiles[1].persistent_candidates[1].precedence, 20);
    assert!(profiles[1].persistent_candidates[1].selected);
  }
}

#[test]
fn preferences_and_preferences_02_are_generic_chromium_profile_markers() {
  let temp = TempDir::new("preferences-markers");
  let context = windows_context(temp.path().join("home"));
  for (browser_id, root_id, marker) in [
    ("qq_browser", "qq-browser-local", "Preferences_02"),
    ("sogou", "sogou-local", "Preferences_02"),
    ("chrome", "chrome-stable-local", "Preferences"),
  ] {
    let root = browser_root(&context, browser_id, root_id);
    seed_cookie(&root.join("Default"), true, "default", "one");
    let vendor_profile = root.join("UserData 1");
    seed_cookie(&vendor_profile, true, "vendor", "two");
    std::fs::write(vendor_profile.join(marker), b"{}").expect("write profile marker");

    let profiles = discover_browser_with_context(&context, browser_id)
      .expect("discover marker variant")
      .profiles();
    assert_eq!(
      profile_directory_names(&profiles),
      ["Default", "UserData 1"],
      "{browser_id} marked by {marker}"
    );
  }
}

#[test]
fn marker_files_do_not_promote_chromium_service_directories() {
  let temp = TempDir::new("marker-skips");
  let context = windows_context(temp.path().join("home"));
  let root = browser_root(&context, "qq_browser", "qq-browser-local");
  seed_cookie(&root.join("Default"), true, "default", "one");
  for skipped in CHROMIUM_NON_PROFILE_DIRECTORIES {
    let path = root.join(skipped);
    seed_cookie(&path, true, "skipped", "value");
    std::fs::write(path.join("Preferences_02"), b"{}").expect("write profile marker");
  }

  let discovery = discover_browser_with_context(&context, "qq_browser").expect("discover");
  assert_eq!(profile_directory_names(&discovery.profiles()), ["Default"]);
  // Excluding a directory is still a decision the report has to account for:
  // a real profile that collides with a reserved name must not disappear
  // without any signal that something was skipped.
  let excluded = discovery
    .issues
    .iter()
    .filter(|issue| issue.code == "profile_excluded_service_directory")
    .map(|issue| {
      issue
        .path
        .file_name()
        .expect("excluded directory name")
        .to_string_lossy()
        .into_owned()
    })
    .collect::<BTreeSet<_>>();
  assert_eq!(
    excluded,
    CHROMIUM_NON_PROFILE_DIRECTORIES
      .iter()
      .map(|name| (*name).to_owned())
      .collect()
  );
  assert!(discovery
    .issues
    .iter()
    .all(|issue| issue.code == "profile_excluded_service_directory"));
}

#[test]
fn service_directory_exclusions_do_not_make_an_empty_listing_fail() {
  let temp = TempDir::new("marker-skips-only-service-directories");
  let context = windows_context(temp.path().join("home"));
  let root = browser_root(&context, "chrome", "chrome-stable-local");
  for skipped in CHROMIUM_NON_PROFILE_DIRECTORIES {
    let path = root.join(skipped);
    seed_cookie(&path, true, "skipped", "value");
    std::fs::write(path.join("Preferences_02"), b"{}").expect("write profile marker");
  }

  let discovery = discover_browser_with_context(&context, "chrome").expect("discover");
  assert!(discovery.profiles().is_empty());
  assert_eq!(
    discovery
      .issues
      .iter()
      .filter(|issue| issue.code == "profile_excluded_service_directory")
      .count(),
    CHROMIUM_NON_PROFILE_DIRECTORIES.len()
  );
  assert!(profiles_for_listing("chrome", discovery)
    .expect("reserved service directories are not lost user profiles")
    .is_empty());
}

#[test]
fn service_directories_are_excluded_from_the_markerless_fallback_too() {
  let temp = TempDir::new("marker-skips-markerless");
  let context = windows_context(temp.path().join("home"));
  let root = browser_root(&context, "chrome", "chrome-stable-local");
  // No marked profile anywhere, so discovery reaches the markerless branch.
  for skipped in CHROMIUM_NON_PROFILE_DIRECTORIES {
    seed_cookie(&root.join(skipped), true, "skipped", "value");
  }
  seed_cookie(&root.join("Restored Account"), true, "restored", "value");

  let discovery = discover_browser_with_context(&context, "chrome").expect("discover");
  assert_eq!(
    profile_directory_names(&discovery.profiles()),
    ["Restored Account"]
  );
  assert_eq!(
    discovery
      .issues
      .iter()
      .filter(|issue| issue.code == "profile_excluded_service_directory")
      .count(),
    CHROMIUM_NON_PROFILE_DIRECTORIES.len()
  );
}

#[test]
fn declared_profiles_outrank_the_service_directory_exclusion() {
  let temp = TempDir::new("marker-skips-declared");
  let context = windows_context(temp.path().join("home"));
  let root = browser_root(&context, "chrome", "chrome-stable-local");
  seed_cookie(&root.join("Guest Profile"), true, "declared", "value");
  // Local State is authoritative: if it declares a profile, the reserved-name
  // heuristic must not override it.
  write_local_state(
    &root,
    serde_json::json!({
      "profile": {"info_cache": {"Guest Profile": {"name": "Real Profile"}}}
    }),
  );

  let discovery = discover_browser_with_context(&context, "chrome").expect("discover");
  assert_eq!(
    profile_directory_names(&discovery.profiles()),
    ["Guest Profile"]
  );
  assert_eq!(discovery.profiles()[0].display_name, "Real Profile");
  assert!(discovery
    .issues
    .iter()
    .all(|issue| issue.code != "profile_excluded_service_directory"));
}

#[test]
fn file_markers_never_shadow_a_source_bearing_flat_root() {
  let temp = TempDir::new("flat-root-shadow");
  let context = windows_context(temp.path().join("home"));
  let root = browser_root(
    &context,
    "browser_from_vought",
    "browser-from-vought-roaming",
  );
  seed_cookie(&root, false, "flat", "real-profile");
  // A sibling directory carrying its own marker and cookie store must not
  // displace the flat profile that the installation root itself is.
  let vendor = root.join("Vendor Data");
  seed_cookie(&vendor, false, "vendor", "value");
  std::fs::write(vendor.join("Preferences"), b"{}").expect("write vendor marker");

  let discovery = discover_browser_with_context(&context, "vought").expect("discover flat root");
  let profiles = discovery.profiles();
  assert_eq!(profile_directory_names(&profiles), ["."]);
  assert!(profiles[0].is_default);
  assert!(profiles[0].persistent_candidates[1].selected);
}

#[test]
fn file_marked_directories_without_a_source_stay_silent() {
  let temp = TempDir::new("marker-no-source");
  let context = windows_context(temp.path().join("home"));
  let root = browser_root(&context, "qq_browser", "qq-browser-local");
  seed_cookie(&root.join("Default"), true, "default", "one");
  let cache = root.join("Some Cache");
  std::fs::create_dir_all(&cache).expect("create cache directory");
  std::fs::write(cache.join("Preferences"), b"{}").expect("write marker");

  let discovery = discover_browser_with_context(&context, "qq_browser").expect("discover");
  assert_eq!(profile_directory_names(&discovery.profiles()), ["Default"]);
  // A file marker is a heuristic; a miss must not become report noise the way
  // a declared-but-empty profile legitimately does.
  assert!(discovery.issues.is_empty());
}

#[test]
fn both_installation_roots_are_discovered_and_ordered_by_priority() {
  let temp = TempDir::new("windows-batch-two-roots");
  let context = windows_context(temp.path().join("home"));
  let local = browser_root(&context, "yandex", "yandex-local");
  let roaming = browser_root(&context, "yandex", "yandex-roaming");
  seed_cookie(&local.join("Default"), true, "local", "one");
  seed_cookie(&roaming.join("Default"), true, "roaming", "two");

  let discovery = discover_browser_with_context(&context, "yandex").expect("discover both roots");
  assert_eq!(discovery.installations.len(), 2);
  assert_eq!(
    discovery
      .installations
      .iter()
      .map(|installation| installation.root_id.as_str())
      .collect::<Vec<_>>(),
    ["yandex-local", "yandex-roaming"],
    "priority 10 must sort before priority 20"
  );
  assert_ne!(
    discovery.installations[0].installation_id,
    discovery.installations[1].installation_id
  );
  assert_eq!(discovery.profiles().len(), 2);
}

#[test]
fn browser_from_vought_falls_back_to_the_flat_installation_root() {
  let temp = TempDir::new("vought-flat");
  let context = windows_context(temp.path().join("home"));
  let root = browser_root(
    &context,
    "browser_from_vought",
    "browser-from-vought-roaming",
  );
  seed_cookie(&root, false, "vought", "value");

  let discovery = discover_browser_with_context(&context, "vought").expect("discover via alias");
  assert_eq!(discovery.installations.len(), 1);
  assert_eq!(
    discovery.installations[0].root_id,
    "browser-from-vought-roaming"
  );
  let profiles = discovery.profiles();
  assert_eq!(profile_directory_names(&profiles), ["."]);
  assert!(profiles[0].is_default);
  assert_eq!(profiles[0].display_name, "stable");
  assert!(profiles[0].persistent_candidates[1].selected);
}

#[test]
fn windows_batch_browsers_extract_plaintext_cookies_through_their_selectors() {
  let temp = TempDir::new("windows-batch-plaintext");
  let context = windows_context(temp.path().join("home"));
  let cases = [
    ("yandex", "yandex-local", "yandex", false),
    ("speed_360", "speed-360-local", "360", false),
    ("speed_360x", "speed-360x-local", "360x", false),
    ("dc_browser", "dc-browser-local", "dc", false),
    ("qq_browser", "qq-browser-local", "qq", false),
    ("sogou", "sogou-local", "sogou", false),
    (
      "browser_from_vought",
      "browser-from-vought-roaming",
      "vought",
      true,
    ),
  ];

  for (browser_id, root_id, selector, flat) in cases {
    let root = browser_root(&context, browser_id, root_id);
    let profile = if flat { root } else { root.join("Default") };
    seed_cookie(&profile, !flat, browser_id, "plaintext-value");

    let provider = CountingProvider::default();
    let report = extract_chromium_with_provider(
      &context,
      selector,
      ProfileSelection::AllProfiles,
      None,
      &provider,
    )
    .expect("plaintext report");
    assert_eq!(report.installations.len(), 1, "{browser_id} installations");
    let profiles = &report.installations[0].profiles;
    assert_eq!(profiles.len(), 1, "{browser_id} profiles");
    assert_eq!(profiles[0].cookies().len(), 1);
    assert_eq!(profiles[0].cookies()[0].name, browser_id);
    assert_eq!(profiles[0].cookies()[0].value, "plaintext-value");
    assert!(profiles[0].failure.is_none());
    let [source] = &profiles[0].sources[..] else {
      panic!("{browser_id} extracts its one selected source");
    };
    assert_eq!(source.stats.rows_seen, 1);
    assert_eq!(source.stats.cookies_emitted, 1);
    assert_eq!(source.stats.rows_skipped, 0);
    assert_eq!(
      provider
        .calls
        .borrow()
        .values()
        .copied()
        .collect::<Vec<_>>(),
      [1],
      "{browser_id} key provider calls"
    );
  }
}
