//! Private installation/profile registry scaffolding.
//!
//! The generic report API remains intentionally private until the coordinated
//! Rust/Python/Node/CLI release gate. Legacy named browser functions do not use
//! this module and therefore retain their frozen first-profile behavior.

#![allow(dead_code)]

use super::chromium::{query_cookies_engine_outcome, ChromiumExtractionStats, ChromiumRowIssue};
use super::chromium_crypto::{
  retrieve_key_outcomes, ChromiumKeyOutcome, ChromiumKeyOutcomes, ChromiumKeyProvider,
};
#[cfg(target_os = "linux")]
use super::chromium_platform_keys::LinuxPlatformKeyProvider;
#[cfg(target_os = "macos")]
use super::chromium_platform_keys::MacosPlatformKeyProvider;
#[cfg(target_os = "windows")]
use super::chromium_platform_keys::WindowsPlatformKeyProvider;
use super::mozilla;
use super::report_core::sort_cookies;
use crate::common::enums::Cookie;
use crate::common::sqlite::DatabaseAcquisitionStrategy;
use anyhow::{anyhow, bail, Context, Result};
use once_cell::sync::Lazy;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

const REGISTRY_SCHEMA_VERSION: u32 = 1;
const INSTALLATION_ID_DOMAIN: &str = "rookie-install-v1";
const PROFILE_ID_DOMAIN: &str = "rookie-profile-v1";

#[derive(Debug, Deserialize)]
struct Registry {
  schema_version: u32,
  platforms: BTreeMap<String, Vec<BrowserDefinition>>,
}

#[derive(Debug, Deserialize)]
struct BrowserDefinition {
  canonical_id: String,
  aliases: Vec<String>,
  display_name: String,
  engine: BrowserEngine,
  roots: Vec<InstallationRoot>,
  capabilities: BrowserCapabilities,
  /// Platform key-lookup metadata for the generic pipeline. Roots and tiers say
  /// nothing about *which* OS credential a key provider should read, so a
  /// registry-only browser has no other source of truth for it. Values are
  /// lookup identifiers, never key material.
  key_credentials: Option<KeyCredentials>,
}

#[derive(Debug, Default, Deserialize)]
struct KeyCredentials {
  macos_keychain: Option<MacosKeychainCredential>,
  linux_crypt_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MacosKeychainCredential {
  /// Keychain generic-password service, e.g. `"Chrome Safe Storage"`.
  service: String,
  /// Its account name, e.g. `"Chrome"`.
  account: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum BrowserEngine {
  Chromium,
  Gecko,
  Safari,
  InternetExplorer,
}

#[derive(Debug, Deserialize)]
struct BrowserCapabilities {
  declared_persistent_formats: Vec<String>,
  declared_session_formats: Vec<String>,
  declared_decryption_tiers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BrowserCapabilityDescriptor {
  pub(crate) declared_persistent_formats: Vec<String>,
  pub(crate) declared_session_formats: Vec<String>,
  pub(crate) declared_decryption_tiers: Vec<String>,
  pub(crate) available_decryption_tiers: Vec<String>,
}

/// Narrows declared tiers to the ones this build can actually attempt.
///
/// Section 5.1 makes a declared tier a capability claim rather than evidence,
/// and the registry states that claim as "a tier rookie can attempt for this
/// browser", not "a format this browser writes". The two differ for v20:
/// Edge, Brave, Vivaldi, and Opera all write `app_bound_encrypted_key`, but
/// rookie only holds Google Chrome's app-bound elevation keys, so only Chrome
/// declares v20.
///
/// That distinction is load-bearing. The filter below is keyed on platform and
/// compiled features alone, so it would happily call a tier available for any
/// browser whose declaration listed it. Restating a declaration as
/// browser-truth therefore needs a per-browser key axis added here first,
/// otherwise `available_decryption_tiers` starts overclaiming — and
/// `decryptable` is defined against that effective set.
/// `only_browsers_with_known_elevation_keys_declare_v20` pins the v20 half so
/// the change cannot land silently.
///
/// That axis is not one thing. What actually gates a tier differs by platform,
/// and a design that treats them alike will get at least one wrong:
///
/// - Windows v20 is a property of *rookie*, not of the browser: which vendors'
///   app-bound elevation keys we hold. A browser cannot declare us into having
///   its keys, so this stays embedded knowledge rather than registry data.
/// - macOS v10 and Linux v10/v11 are properties of the *browser* — its keychain
///   service and account, or its crypt name. Today those live only in the
///   legacy `config.json`, so `SystemChromiumKeyProvider` fails the tier
///   outright for a registry-only browser. Linux fails both v10 and v11 that
///   way, not just v10.
/// - Windows v10 and `legacy_dpapi` are gated by neither: that arm reads the
///   installation's `Local State` directly and never consults `config.json`.
fn capability_descriptor(
  definition: &BrowserDefinition,
  platform: PlatformId,
) -> BrowserCapabilityDescriptor {
  let available_decryption_tiers = definition
    .capabilities
    .declared_decryption_tiers
    .iter()
    .filter(|tier| match tier.as_str() {
      "legacy_dpapi" => platform == PlatformId::Windows,
      "v10" => matches!(
        platform,
        PlatformId::Windows | PlatformId::Macos | PlatformId::Linux
      ),
      "v11" => platform == PlatformId::Linux,
      "v20" => platform == PlatformId::Windows && cfg!(feature = "appbound"),
      _ => false,
    })
    .cloned()
    .collect();
  BrowserCapabilityDescriptor {
    declared_persistent_formats: definition.capabilities.declared_persistent_formats.clone(),
    declared_session_formats: definition.capabilities.declared_session_formats.clone(),
    declared_decryption_tiers: definition.capabilities.declared_decryption_tiers.clone(),
    available_decryption_tiers,
  }
}

impl BrowserEngine {
  fn as_str(self) -> &'static str {
    match self {
      Self::Chromium => "chromium",
      Self::Gecko => "gecko",
      Self::Safari => "safari",
      Self::InternetExplorer => "internet_explorer",
    }
  }
}

/// Flattened registry definition for the private report descriptors. It copies
/// owned data so the report layer never borrows from the embedded registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegisteredBrowser {
  pub(crate) canonical_id: String,
  pub(crate) aliases: Vec<String>,
  pub(crate) display_name: String,
  pub(crate) engine: &'static str,
  pub(crate) capabilities: BrowserCapabilityDescriptor,
}

fn registered_browser(definition: &BrowserDefinition, platform: PlatformId) -> RegisteredBrowser {
  RegisteredBrowser {
    canonical_id: definition.canonical_id.clone(),
    aliases: definition.aliases.clone(),
    display_name: definition.display_name.clone(),
    engine: definition.engine.as_str(),
    capabilities: capability_descriptor(definition, platform),
  }
}

/// Registered browsers for the running OS, in registry order. This never scans
/// the filesystem: registration is not detection.
pub(crate) fn registered_browsers() -> Result<Vec<RegisteredBrowser>> {
  let platform = PlatformId::current()?;
  registered_browsers_for(platform)
}

fn registered_browsers_for(platform: PlatformId) -> Result<Vec<RegisteredBrowser>> {
  let registry = embedded_registry()?;
  Ok(
    registry
      .platforms
      .get(platform.as_str())
      .map(|definitions| {
        definitions
          .iter()
          .map(|definition| registered_browser(definition, platform))
          .collect()
      })
      .unwrap_or_default(),
  )
}

/// Resolves an ID or alias to its registered browser, or fails for an unknown
/// identifier. Unknown IDs are a request error, never a report issue.
pub(crate) fn resolve_registered_browser(browser_id: &str) -> Result<RegisteredBrowser> {
  let platform = PlatformId::current()?;
  resolve_registered_browser_for(platform, browser_id)
}

fn resolve_registered_browser_for(
  platform: PlatformId,
  browser_id: &str,
) -> Result<RegisteredBrowser> {
  let registry = embedded_registry()?;
  let definition = browser_definition(registry, platform, browser_id)?;
  Ok(registered_browser(definition, platform))
}

#[derive(Debug, Deserialize)]
struct InstallationRoot {
  root_id: String,
  template: String,
  channel: String,
  discovery: DiscoveryStrategy,
  priority: u16,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DiscoveryStrategy {
  ChromiumUserData,
  MozillaProfilesIni,
  SafariDefaultProfile,
  InternetExplorerWebCache,
}

static REGISTRY: Lazy<std::result::Result<Registry, String>> = Lazy::new(|| {
  let registry: Registry = serde_json::from_str(include_str!("../../browser_registry.json"))
    .map_err(|error| format!("invalid embedded browser registry: {error}"))?;
  validate_registry(&registry)?;
  Ok(registry)
});

fn embedded_registry() -> Result<&'static Registry> {
  REGISTRY
    .as_ref()
    .map_err(|message| anyhow!(message.to_owned()))
}

fn validate_registry(registry: &Registry) -> std::result::Result<(), String> {
  if registry.schema_version != REGISTRY_SCHEMA_VERSION {
    return Err(format!(
      "unsupported browser registry schema {}, expected {REGISTRY_SCHEMA_VERSION}",
      registry.schema_version
    ));
  }

  for (platform, definitions) in &registry.platforms {
    if !matches!(platform.as_str(), "windows" | "macos" | "linux") {
      return Err(format!("unknown registry platform {platform:?}"));
    }
    let mut browser_ids = HashSet::new();
    let mut aliases = HashSet::new();
    for definition in definitions {
      let mut root_ids = HashSet::new();
      validate_identifier("browser", &definition.canonical_id)?;
      if aliases.contains(definition.canonical_id.as_str())
        || !browser_ids.insert(definition.canonical_id.as_str())
      {
        return Err(format!(
          "duplicate browser id {:?} on {platform}",
          definition.canonical_id
        ));
      }
      if definition.display_name.trim().is_empty() {
        return Err(format!(
          "browser {:?} has an empty display name",
          definition.canonical_id
        ));
      }
      for alias in &definition.aliases {
        validate_alias(alias)?;
        if browser_ids.contains(alias.as_str()) || !aliases.insert(alias.as_str()) {
          return Err(format!("duplicate browser alias {alias:?} on {platform}"));
        }
      }
      for root in &definition.roots {
        validate_identifier("root", &root.root_id)?;
        if !root_ids.insert(root.root_id.as_str()) {
          return Err(format!(
            "duplicate root id {:?} on {platform}",
            root.root_id
          ));
        }
        if root.template.trim().is_empty() || root.channel.trim().is_empty() {
          return Err(format!("root {:?} has empty required fields", root.root_id));
        }
        let expected = match definition.engine {
          BrowserEngine::Chromium => DiscoveryStrategy::ChromiumUserData,
          BrowserEngine::Gecko => DiscoveryStrategy::MozillaProfilesIni,
          BrowserEngine::Safari => DiscoveryStrategy::SafariDefaultProfile,
          BrowserEngine::InternetExplorer => DiscoveryStrategy::InternetExplorerWebCache,
        };
        if root.discovery != expected {
          return Err(format!(
            "browser {:?} uses engine {:?} but root {:?} uses incompatible discovery strategy {:?}",
            definition.canonical_id, definition.engine, root.root_id, root.discovery
          ));
        }
      }
      for identifier in definition
        .capabilities
        .declared_persistent_formats
        .iter()
        .chain(&definition.capabilities.declared_session_formats)
        .chain(&definition.capabilities.declared_decryption_tiers)
      {
        validate_identifier("capability", identifier)?;
      }
      validate_key_credentials(platform, definition)?;
    }
  }
  Ok(())
}

/// Enforces the Section 5.9 credential rules.
///
/// A registry-only browser has no `config.json` parity check to catch a missing
/// or blank credential, and a blank one fails exactly like an absent one at
/// runtime: Linux filters an empty crypt name to `NotApplicable`, and macOS
/// would issue a Keychain query with an empty service or account. Both are
/// therefore rejected at load rather than surfacing as a runtime surprise.
fn validate_key_credentials(
  platform: &str,
  definition: &BrowserDefinition,
) -> std::result::Result<(), String> {
  let browser = &definition.canonical_id;
  let credentials = definition.key_credentials.as_ref();
  let keychain = credentials.and_then(|credentials| credentials.macos_keychain.as_ref());
  let crypt_name = credentials.and_then(|credentials| credentials.linux_crypt_name.as_deref());
  let declares = |tier: &str| -> bool {
    definition
      .capabilities
      .declared_decryption_tiers
      .iter()
      .any(|declared| declared == tier)
  };

  // Only the running platform's subfields are meaningful, and definitions are
  // already platform-grouped, so a subfield the platform cannot use is a
  // registry authoring mistake rather than harmless extra data.
  if platform != "macos" && keychain.is_some() {
    return Err(format!(
      "browser {browser:?} on {platform} declares macos_keychain, which only macOS can use"
    ));
  }
  if platform != "linux" && crypt_name.is_some() {
    return Err(format!(
      "browser {browser:?} on {platform} declares linux_crypt_name, which only Linux can use"
    ));
  }

  if let Some(keychain) = keychain {
    for (field, value) in [
      ("service", &keychain.service),
      ("account", &keychain.account),
    ] {
      if value.trim().is_empty() {
        return Err(format!(
          "browser {browser:?} on {platform} has a blank macos_keychain {field}"
        ));
      }
    }
  }
  if let Some(crypt_name) = crypt_name {
    if crypt_name.trim().is_empty() {
      return Err(format!(
        "browser {browser:?} on {platform} has a blank linux_crypt_name"
      ));
    }
  }

  if platform == "macos" && declares("v10") && keychain.is_none() {
    return Err(format!(
      "browser {browser:?} declares the macOS v10 tier without macos_keychain credentials"
    ));
  }
  if platform == "linux" && declares("v11") && crypt_name.is_none() {
    return Err(format!(
      "browser {browser:?} declares the Linux v11 tier without a linux_crypt_name"
    ));
  }
  Ok(())
}

fn validate_identifier(kind: &str, value: &str) -> std::result::Result<(), String> {
  if value.is_empty()
    || !value
      .bytes()
      .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-'))
  {
    return Err(format!("invalid {kind} identifier {value:?}"));
  }
  Ok(())
}

fn validate_alias(value: &str) -> std::result::Result<(), String> {
  if value.is_empty()
    || value.trim() != value
    || !value.bytes().all(|byte| {
      byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b' ')
    })
  {
    return Err(format!("invalid alias identifier {value:?}"));
  }
  Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlatformId {
  Windows,
  Macos,
  Linux,
}

impl PlatformId {
  fn current() -> Result<Self> {
    if cfg!(target_os = "windows") {
      Ok(Self::Windows)
    } else if cfg!(target_os = "macos") {
      Ok(Self::Macos)
    } else if cfg!(target_os = "linux") {
      Ok(Self::Linux)
    } else {
      bail!("the private browser registry is unsupported on this platform")
    }
  }

  fn as_str(self) -> &'static str {
    match self {
      Self::Windows => "windows",
      Self::Macos => "macos",
      Self::Linux => "linux",
    }
  }
}

trait DiscoveryFs {
  fn exists(&self, path: &Path) -> bool;
  fn is_dir(&self, path: &Path) -> bool;
  fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata>;
  fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>>;
  fn canonicalize(&self, path: &Path) -> Result<PathBuf>;
  fn read_to_string(&self, path: &Path) -> Result<String>;
  fn expand_registry_glob(&self, base: &Path, suffix: &str) -> Result<GlobExpansion>;
}

#[derive(Debug, Clone, Default)]
struct GlobExpansion {
  paths: Vec<PathBuf>,
  issues: Vec<GlobExpansionIssue>,
}

#[derive(Debug, Clone)]
struct GlobExpansionIssue {
  path: PathBuf,
  message: String,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RealDiscoveryFs;

impl DiscoveryFs for RealDiscoveryFs {
  fn exists(&self, path: &Path) -> bool {
    path.exists()
  }

  fn is_dir(&self, path: &Path) -> bool {
    path.is_dir()
  }

  fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
    std::fs::metadata(path)
  }

  fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>> {
    let mut entries = std::fs::read_dir(path)
      .with_context(|| format!("read directory {}", path.display()))?
      .map(|entry| entry.map(|entry| entry.path()))
      .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|path| normalized_path_bytes(path));
    Ok(entries)
  }

  fn canonicalize(&self, path: &Path) -> Result<PathBuf> {
    path
      .canonicalize()
      .with_context(|| format!("canonicalize {}", path.display()))
  }

  fn read_to_string(&self, path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))
  }

  fn expand_registry_glob(&self, base: &Path, suffix: &str) -> Result<GlobExpansion> {
    let mut paths = vec![base.to_path_buf()];
    let mut issues = Vec::new();
    for component in suffix
      .split(['/', '\\'])
      .filter(|component| !component.is_empty())
    {
      let pattern = glob::Pattern::new(component)
        .with_context(|| format!("parse registry glob component {component:?}"))?;
      if !component
        .bytes()
        .any(|byte| matches!(byte, b'*' | b'?' | b'['))
      {
        paths = paths.into_iter().map(|path| path.join(component)).collect();
        continue;
      }

      let mut expanded = Vec::new();
      for parent in paths {
        match std::fs::read_dir(&parent) {
          Ok(entries) => {
            for entry in entries {
              match entry {
                Ok(entry) => {
                  let path = entry.path();
                  if path
                    .file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| pattern.matches(name))
                  {
                    expanded.push(path);
                  }
                }
                Err(error) => issues.push(GlobExpansionIssue {
                  path: parent.clone(),
                  message: format!("read registry glob entry: {error}"),
                }),
              }
            }
          }
          Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
          Err(error) => issues.push(GlobExpansionIssue {
            path: parent,
            message: format!("expand registry glob: {error}"),
          }),
        }
      }
      paths = expanded;
    }
    Ok(GlobExpansion { paths, issues })
  }
}

pub(crate) struct DiscoveryContext<F> {
  platform: PlatformId,
  home: PathBuf,
  env: BTreeMap<OsString, OsString>,
  fs: F,
}

#[derive(Debug, Clone)]
struct ResolvedRoot {
  base: PathBuf,
  suffix: String,
}

impl DiscoveryContext<RealDiscoveryFs> {
  fn system() -> Result<Self> {
    let platform = PlatformId::current()?;
    let env: BTreeMap<OsString, OsString> = std::env::vars_os().collect();
    let home_key = if platform == PlatformId::Windows {
      OsStr::new("USERPROFILE")
    } else {
      OsStr::new("HOME")
    };
    let home = env
      .get(home_key)
      .map(PathBuf::from)
      .ok_or_else(|| anyhow!("{} is not set", home_key.to_string_lossy()))?;
    Ok(Self {
      platform,
      home,
      env,
      fs: RealDiscoveryFs,
    })
  }
}

impl<F> DiscoveryContext<F> {
  fn env_path(&self, name: &str) -> Option<PathBuf> {
    self
      .env
      .get(OsStr::new(name))
      .filter(|value| !value.is_empty())
      .map(PathBuf::from)
  }

  fn xdg_config_home(&self) -> PathBuf {
    self
      .env_path("XDG_CONFIG_HOME")
      .unwrap_or_else(|| self.home.join(".config"))
  }

  fn chrome_config_home(&self) -> PathBuf {
    self
      .env_path("CHROME_CONFIG_HOME")
      .unwrap_or_else(|| self.xdg_config_home())
  }

  fn resolve_template(&self, template: &str) -> Option<ResolvedRoot> {
    let replacements = [
      ("{home}", Some(self.home.clone())),
      ("{config_home}", Some(self.chrome_config_home())),
      ("{xdg_config_home}", Some(self.xdg_config_home())),
      ("{local_app_data}", self.env_path("LOCALAPPDATA")),
      ("{roaming_app_data}", self.env_path("APPDATA")),
    ];
    for (token, replacement) in replacements {
      if let Some(suffix) = template.strip_prefix(token) {
        let replacement = replacement?;
        return Some(ResolvedRoot {
          base: replacement,
          suffix: suffix.trim_start_matches(['/', '\\']).to_owned(),
        });
      }
    }
    (!template.contains('{')).then(|| ResolvedRoot {
      base: PathBuf::from(template),
      suffix: String::new(),
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CookieSourceCandidate {
  pub(crate) path: PathBuf,
  pub(crate) precedence: u16,
  pub(crate) exists: bool,
  pub(crate) selected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChromiumProfile {
  pub(crate) profile_id: String,
  pub(crate) installation_id: String,
  pub(crate) directory_name: String,
  pub(crate) display_name: String,
  pub(crate) path: PathBuf,
  pub(crate) is_default: bool,
  pub(crate) is_active: bool,
  pub(crate) active_order: Option<u32>,
  pub(crate) is_last_used: bool,
  pub(crate) persistent_candidates: Vec<CookieSourceCandidate>,
}

impl ChromiumProfile {
  fn selected_source(&self) -> Option<&Path> {
    self
      .persistent_candidates
      .iter()
      .find(|candidate| candidate.selected)
      .map(|candidate| candidate.path.as_path())
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BrowserInstallation {
  installation_id: String,
  browser_id: String,
  root_id: String,
  channel: String,
  path: PathBuf,
  local_state_path: PathBuf,
  priority: u16,
  profiles: Vec<ChromiumProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DiscoveryIssue {
  pub(crate) code: &'static str,
  pub(crate) path: PathBuf,
  pub(crate) message: String,
  /// How many times this code occurred at or after `path`. Retained samples
  /// carry 1; a bounded code folds its unsampled remainder into the first
  /// retained sample, so the per-code total is the sum across entries.
  pub(crate) occurrences: u32,
}

impl DiscoveryIssue {
  fn new(code: &'static str, path: PathBuf, message: impl Into<String>) -> Self {
    Self {
      code,
      path,
      message: message.into(),
      occurrences: 1,
    }
  }
}

#[derive(Debug, Default)]
struct ChromiumDiscovery {
  installations: Vec<BrowserInstallation>,
  issues: Vec<DiscoveryIssue>,
  detected_roots: usize,
  enumerated_roots: usize,
}

impl ChromiumDiscovery {
  fn profiles(&self) -> Vec<ChromiumProfile> {
    self
      .installations
      .iter()
      .flat_map(|installation| installation.profiles.iter().cloned())
      .collect()
  }

  fn all_detected_roots_failed(&self) -> bool {
    self.detected_roots > 0 && self.enumerated_roots == 0
  }
}

#[derive(Debug, Default)]
struct LocalStateMetadata {
  last_used: Option<String>,
  active_profiles: Vec<String>,
  display_names: BTreeMap<String, String>,
}

fn parse_local_state(contents: &str) -> Result<LocalStateMetadata> {
  let value: serde_json::Value =
    serde_json::from_str(contents).context("parse Local State JSON")?;
  let profile = value.get("profile").and_then(serde_json::Value::as_object);
  let last_used = profile
    .and_then(|profile| profile.get("last_used"))
    .and_then(serde_json::Value::as_str)
    .map(str::to_owned);
  let mut active_profiles = profile
    .and_then(|profile| profile.get("last_active_profiles"))
    .and_then(serde_json::Value::as_array)
    .into_iter()
    .flatten()
    .filter_map(serde_json::Value::as_str)
    .map(str::to_owned)
    .collect::<Vec<_>>();
  if active_profiles.is_empty() {
    if let Some(last_used) = &last_used {
      active_profiles.push(last_used.clone());
    }
  }
  let display_names = profile
    .and_then(|profile| profile.get("info_cache"))
    .and_then(serde_json::Value::as_object)
    .into_iter()
    .flatten()
    .map(|(directory, metadata)| {
      let name = metadata
        .get("name")
        .and_then(serde_json::Value::as_str)
        .filter(|name| !name.is_empty())
        .unwrap_or(directory);
      (directory.clone(), name.to_owned())
    })
    .collect();
  Ok(LocalStateMetadata {
    last_used,
    active_profiles,
    display_names,
  })
}

fn browser_definition<'a>(
  registry: &'a Registry,
  platform: PlatformId,
  browser_id: &str,
) -> Result<&'a BrowserDefinition> {
  let definitions = registry
    .platforms
    .get(platform.as_str())
    .ok_or_else(|| anyhow!("registry has no definitions for {}", platform.as_str()))?;
  definitions
    .iter()
    .find(|definition| {
      definition.canonical_id == browser_id
        || definition.aliases.iter().any(|alias| alias == browser_id)
    })
    .ok_or_else(|| anyhow!("unknown browser id {browser_id:?}"))
}

fn persistent_candidates<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  profile_path: &Path,
) -> Vec<CookieSourceCandidate> {
  let mut candidates = vec![
    CookieSourceCandidate {
      path: profile_path.join("Network/Cookies"),
      precedence: 10,
      exists: false,
      selected: false,
    },
    CookieSourceCandidate {
      path: profile_path.join("Cookies"),
      precedence: 20,
      exists: false,
      selected: false,
    },
  ];
  let mut selected = false;
  for candidate in &mut candidates {
    candidate.exists = context.fs.exists(&candidate.path);
    candidate.selected = candidate.exists && !selected;
    selected |= candidate.selected;
  }
  candidates
}

fn profile_has_source<F: DiscoveryFs>(context: &DiscoveryContext<F>, path: &Path) -> bool {
  context.fs.exists(&path.join("Network/Cookies")) || context.fs.exists(&path.join("Cookies"))
}

fn discover_installation_profiles<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  installation: &mut BrowserInstallation,
  seen_profiles: &mut HashSet<Vec<u8>>,
  issues: &mut Vec<DiscoveryIssue>,
) -> Result<()> {
  let local_state = if context.fs.exists(&installation.local_state_path) {
    match context
      .fs
      .read_to_string(&installation.local_state_path)
      .and_then(|contents| parse_local_state(&contents))
    {
      Ok(metadata) => metadata,
      Err(error) => {
        issues.push(DiscoveryIssue::new(
          "local_state_invalid",
          installation.local_state_path.clone(),
          error.to_string(),
        ));
        LocalStateMetadata::default()
      }
    }
  } else {
    LocalStateMetadata::default()
  };

  let children = context.fs.read_dir(&installation.path)?;
  let mut marker_names: BTreeSet<String> = local_state.display_names.keys().cloned().collect();
  marker_names.insert("Default".to_owned());

  let mut marked = Vec::new();
  for child in &children {
    if !context.fs.is_dir(child) {
      continue;
    }
    let name = child
      .file_name()
      .map(|name| name.to_string_lossy().into_owned())
      .unwrap_or_default();
    if marker_names.contains(&name) || name.starts_with("Profile ") {
      marked.push(child.clone());
    }
  }

  let mut source_bearing_marked = Vec::new();
  for profile_path in marked {
    if profile_has_source(context, &profile_path) {
      source_bearing_marked.push(profile_path);
    } else {
      issues.push(DiscoveryIssue::new(
        "profile_has_no_cookie_source",
        profile_path,
        "profile marker has no Chromium cookie source".to_owned(),
      ));
    }
  }

  let profile_paths = if !source_bearing_marked.is_empty() {
    source_bearing_marked
  } else if profile_has_source(context, &installation.path) {
    vec![installation.path.clone()]
  } else {
    children
      .into_iter()
      .filter(|child| context.fs.is_dir(child) && profile_has_source(context, child))
      .collect()
  };

  for profile_path in profile_paths {
    if !profile_has_source(context, &profile_path) {
      issues.push(DiscoveryIssue::new(
        "profile_has_no_cookie_source",
        profile_path,
        "profile marker has no Chromium cookie source".to_owned(),
      ));
      continue;
    }
    let canonical_path = match context.fs.canonicalize(&profile_path) {
      Ok(path) => path,
      Err(error) => {
        issues.push(DiscoveryIssue::new(
          "profile_canonicalize_failed",
          profile_path,
          error.to_string(),
        ));
        continue;
      }
    };
    let lexical_relative_path = profile_path
      .strip_prefix(&installation.path)
      .unwrap_or(profile_path.as_path());
    let directory_name = if lexical_relative_path.as_os_str().is_empty() {
      ".".to_owned()
    } else {
      lexical_relative_path.to_string_lossy().into_owned()
    };
    let display_name = local_state
      .display_names
      .get(&directory_name)
      .cloned()
      .unwrap_or_else(|| {
        if directory_name == "." {
          installation.channel.clone()
        } else {
          directory_name.clone()
        }
      });
    let active_order = local_state
      .active_profiles
      .iter()
      .position(|active| active == &directory_name)
      .and_then(|index| u32::try_from(index).ok());
    let locator = match canonical_path.strip_prefix(&installation.path) {
      Ok(relative) if relative.as_os_str().is_empty() => ProfileLocator::Relative(Path::new(".")),
      Ok(relative) => ProfileLocator::Relative(relative),
      Err(_) => ProfileLocator::Absolute(&canonical_path),
    };
    let profile_id = profile_id(&installation.installation_id, locator);
    let persistent_candidates = persistent_candidates(context, &canonical_path);
    let canonical_key = if directory_name == "." {
      let selected_source = persistent_candidates
        .iter()
        .find(|candidate| candidate.selected)
        .expect("source-bearing profile has a selected persistent source");
      match context.fs.canonicalize(&selected_source.path) {
        Ok(path) => normalized_path_bytes(&path),
        Err(error) => {
          issues.push(DiscoveryIssue::new(
            "profile_source_canonicalize_failed",
            selected_source.path.clone(),
            error.to_string(),
          ));
          continue;
        }
      }
    } else {
      normalized_path_bytes(&canonical_path)
    };
    if !seen_profiles.insert(canonical_key) {
      issues.push(DiscoveryIssue::new(
        "duplicate_profile",
        canonical_path,
        "profile is already owned by an earlier registry root".to_owned(),
      ));
      continue;
    }
    installation.profiles.push(ChromiumProfile {
      profile_id,
      installation_id: installation.installation_id.clone(),
      directory_name: directory_name.clone(),
      display_name,
      path: canonical_path,
      is_default: directory_name == "Default" || directory_name == ".",
      is_active: active_order.is_some(),
      active_order,
      is_last_used: local_state.last_used.as_deref() == Some(directory_name.as_str()),
      persistent_candidates,
    });
  }

  installation.profiles.sort_by(|left, right| {
    (!left.is_default)
      .cmp(&(!right.is_default))
      .then_with(|| {
        left
          .display_name
          .to_lowercase()
          .cmp(&right.display_name.to_lowercase())
      })
      .then_with(|| left.display_name.cmp(&right.display_name))
      .then_with(|| normalized_path_bytes(&left.path).cmp(&normalized_path_bytes(&right.path)))
  });
  Ok(())
}

fn discover_browser_with_context<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
) -> Result<ChromiumDiscovery> {
  let registry = embedded_registry()?;
  let definition = browser_definition(registry, context.platform, browser_id)?;
  if definition.engine != BrowserEngine::Chromium {
    bail!("browser {browser_id:?} is not a Chromium browser")
  }

  let mut roots: Vec<&InstallationRoot> = definition.roots.iter().collect();
  roots.sort_by(|left, right| {
    left
      .priority
      .cmp(&right.priority)
      .then_with(|| left.root_id.cmp(&right.root_id))
  });
  let mut discovery = ChromiumDiscovery::default();
  let mut seen_installations = HashSet::new();
  let mut seen_profiles = HashSet::new();
  for root in roots {
    let Some(resolved_root) = context.resolve_template(&root.template) else {
      continue;
    };
    let mut expansion = match context
      .fs
      .expand_registry_glob(&resolved_root.base, &resolved_root.suffix)
    {
      Ok(expansion) => expansion,
      Err(error) => {
        discovery.issues.push(DiscoveryIssue::new(
          "installation_glob_failed",
          resolved_root.base.join(&resolved_root.suffix),
          error.to_string(),
        ));
        continue;
      }
    };
    let expansion_had_issues = !expansion.issues.is_empty();
    for issue in expansion.issues.drain(..) {
      discovery.issues.push(DiscoveryIssue::new(
        "installation_glob_expand_failed",
        issue.path,
        issue.message,
      ));
    }
    expansion
      .paths
      .sort_by_key(|path| normalized_path_bytes(path));
    let mut usable_roots = 0usize;
    for resolved in expansion.paths {
      match context.fs.metadata(&resolved) {
        Ok(metadata) if metadata.is_dir() => usable_roots += 1,
        Ok(_) => continue,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
        Err(error) => {
          discovery.detected_roots += 1;
          discovery.issues.push(DiscoveryIssue::new(
            "installation_metadata_failed",
            resolved,
            error.to_string(),
          ));
          continue;
        }
      }
      discovery.detected_roots += 1;
      let canonical_path = match context.fs.canonicalize(&resolved) {
        Ok(path) => path,
        Err(error) => {
          discovery.issues.push(DiscoveryIssue::new(
            "installation_canonicalize_failed",
            resolved,
            error.to_string(),
          ));
          continue;
        }
      };
      let installation_key = normalized_path_bytes(&canonical_path);
      if !seen_installations.insert(installation_key.clone()) {
        discovery.issues.push(DiscoveryIssue::new(
          "duplicate_installation",
          canonical_path,
          "installation is already owned by an earlier registry root".to_owned(),
        ));
        continue;
      }
      let id = installation_id(
        &definition.canonical_id,
        &root.root_id,
        &root.channel,
        &installation_key,
      );
      let mut installation = BrowserInstallation {
        installation_id: id,
        browser_id: definition.canonical_id.clone(),
        root_id: root.root_id.clone(),
        channel: root.channel.clone(),
        local_state_path: canonical_path.join("Local State"),
        path: canonical_path,
        priority: root.priority,
        profiles: Vec::new(),
      };
      match root.discovery {
        DiscoveryStrategy::ChromiumUserData => {
          match discover_installation_profiles(
            context,
            &mut installation,
            &mut seen_profiles,
            &mut discovery.issues,
          ) {
            Ok(()) => discovery.enumerated_roots += 1,
            Err(error) => {
              discovery.issues.push(DiscoveryIssue::new(
                "installation_enumeration_failed",
                installation.path.clone(),
                error.to_string(),
              ));
              discovery.installations.push(installation);
              continue;
            }
          }
        }
        DiscoveryStrategy::MozillaProfilesIni
        | DiscoveryStrategy::SafariDefaultProfile
        | DiscoveryStrategy::InternetExplorerWebCache => {
          bail!(
            "Chromium browser {:?} has incompatible discovery strategy",
            definition.canonical_id
          )
        }
      }
      discovery.installations.push(installation);
    }
    // Expansion can return syntactic matches that are not usable roots (for
    // example a regular file or a package path whose later suffix vanished).
    // If expansion also reported a real I/O failure and no usable directory
    // survived, preserve the detected-but-failed state for bare listing.
    if usable_roots == 0 && expansion_had_issues {
      discovery.detected_roots += 1;
    }
  }

  discovery.installations.sort_by(|left, right| {
    left
      .priority
      .cmp(&right.priority)
      .then_with(|| normalized_path_bytes(&left.path).cmp(&normalized_path_bytes(&right.path)))
  });
  Ok(discovery)
}

fn append_length_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
  hasher.update((bytes.len() as u64).to_be_bytes());
  hasher.update(bytes);
}

fn digest_fields<'a>(fields: impl IntoIterator<Item = &'a [u8]>) -> String {
  let mut hasher = Sha256::new();
  for field in fields {
    append_length_prefixed(&mut hasher, field);
  }
  format!("{:x}", hasher.finalize())
}

fn installation_id(browser_id: &str, root_id: &str, channel: &str, path: &[u8]) -> String {
  digest_fields([
    INSTALLATION_ID_DOMAIN.as_bytes(),
    browser_id.as_bytes(),
    root_id.as_bytes(),
    channel.as_bytes(),
    path,
  ])
}

enum ProfileLocator<'a> {
  Relative(&'a Path),
  Absolute(&'a Path),
}

fn profile_id(installation_id: &str, locator: ProfileLocator<'_>) -> String {
  let (kind, path) = match locator {
    ProfileLocator::Relative(path) => (b"relative".as_slice(), path),
    ProfileLocator::Absolute(path) => (b"absolute".as_slice(), path),
  };
  let normalized = normalized_path_bytes(path);
  digest_fields([
    PROFILE_ID_DOMAIN.as_bytes(),
    installation_id.as_bytes(),
    kind,
    &normalized,
  ])
}

#[cfg(unix)]
fn normalized_path_bytes(path: &Path) -> Vec<u8> {
  use std::os::unix::ffi::OsStrExt;

  let mut normalized = path.as_os_str().as_bytes().to_vec();
  while normalized.len() > 1 && normalized.last() == Some(&b'/') {
    normalized.pop();
  }
  normalized
}

#[cfg(windows)]
fn normalized_path_bytes(path: &Path) -> Vec<u8> {
  use std::os::windows::ffi::OsStrExt;

  let mut units = path
    .as_os_str()
    .encode_wide()
    .map(|unit| match unit {
      92 => 47,
      65..=90 => unit + 32,
      _ => unit,
    })
    .collect::<Vec<_>>();
  while units.len() > 1 && units.last() == Some(&(b'/' as u16)) {
    units.pop();
  }
  units
    .into_iter()
    .flat_map(u16::to_le_bytes)
    .collect::<Vec<_>>()
}

#[derive(Debug)]
pub(crate) struct ChromiumProfileExtraction {
  pub(crate) profile: ChromiumProfile,
  pub(crate) cookies: Vec<Cookie>,
  pub(crate) stats: ChromiumExtractionStats,
  pub(crate) row_issues: Vec<ChromiumRowIssue>,
  pub(crate) acquisition: SourceAcquisition,
  pub(crate) acquisition_attempts: u32,
  pub(crate) failure: Option<ChromiumProfileFailure>,
}

/// Why a profile yielded no cookies, typed so the report can tell ordinary
/// absence from a real failure.
///
/// These were once one `Option<String>` whose "no source" case was a message
/// sentinel, which made an installed browser with no cookie store
/// indistinguishable from one that could not be read.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ChromiumProfileFailure {
  /// The profile declares no cookie database. Ordinary absence, not an error.
  NoSource,
  /// Acquisition, schema validation, or the query did not complete. Rejected
  /// rows are not this: they are counted in `rows_skipped` and described by
  /// `row_issues` while the source itself still succeeds.
  Extraction(String),
}

#[derive(Debug)]
pub(crate) struct ChromiumInstallationExtraction {
  pub(crate) installation_id: String,
  pub(crate) channel: String,
  pub(crate) profiles: Vec<ChromiumProfileExtraction>,
}

#[derive(Debug, Default)]
pub(crate) struct ChromiumRegistryReport {
  pub(crate) installations: Vec<ChromiumInstallationExtraction>,
  /// Roots that existed on disk, including ones that then failed to read.
  /// A root that was found and could not be opened is detected-but-unreadable,
  /// never absent.
  pub(crate) installations_detected: usize,
  /// Installations discovered before profile selection narrowed the list.
  /// Selecting a profile must not make the other installations look absent, and
  /// the other engines discover everything and filter afterwards, so this is
  /// what keeps the summary counters comparable across engines.
  pub(crate) installations_discovered: usize,
  pub(crate) discovery_issues: Vec<DiscoveryIssue>,
  /// Every detected root failed enumeration, so an empty installation list is a
  /// failure rather than an absent browser.
  pub(crate) all_detected_roots_failed: bool,
}

fn extract_chromium_with_provider<F, P>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<Vec<String>>,
  provider: &P,
) -> Result<ChromiumRegistryReport>
where
  F: DiscoveryFs,
  P: ChromiumKeyProvider<BrowserInstallation>,
{
  let discovery = discover_browser_with_context(context, browser_id)?;
  if let Some(profile_id) = profile_id {
    let found = discovery
      .installations
      .iter()
      .flat_map(|installation| &installation.profiles)
      .any(|profile| profile.profile_id == profile_id);
    if !found {
      bail!("unknown {browser_id} profile id {profile_id:?}")
    }
  }

  let mut report = ChromiumRegistryReport {
    all_detected_roots_failed: discovery.all_detected_roots_failed(),
    installations_detected: discovery.detected_roots,
    installations_discovered: discovery.installations.len(),
    discovery_issues: discovery.issues,
    ..ChromiumRegistryReport::default()
  };
  for installation in discovery.installations {
    let selected_profiles = installation
      .profiles
      .iter()
      .filter(|profile| profile_id.is_none_or(|id| profile.profile_id == id))
      .cloned()
      .collect::<Vec<_>>();
    if selected_profiles.is_empty() {
      if profile_id.is_none() {
        report.installations.push(ChromiumInstallationExtraction {
          installation_id: installation.installation_id,
          channel: installation.channel,
          profiles: Vec::new(),
        });
      }
      continue;
    }
    // The provider is installation-scoped, so Local State/keyring work happens
    // exactly once and the independent tier outcomes are reused by every profile.
    let key_outcomes = retrieve_key_outcomes(provider, &installation);
    let mut profile_extractions = Vec::with_capacity(selected_profiles.len());
    for profile in selected_profiles {
      let Some(source) = profile.selected_source().map(Path::to_path_buf) else {
        profile_extractions.push(ChromiumProfileExtraction {
          profile,
          cookies: Vec::new(),
          stats: ChromiumExtractionStats::default(),
          row_issues: Vec::new(),
          acquisition: SourceAcquisition::NotAttempted,
          acquisition_attempts: 0,
          failure: Some(ChromiumProfileFailure::NoSource),
        });
        continue;
      };
      match query_cookies_engine_outcome(key_outcomes.clone(), source, domains.clone(), false) {
        Ok(mut outcome) => {
          sort_cookies(&mut outcome.cookies);
          profile_extractions.push(ChromiumProfileExtraction {
            profile,
            cookies: outcome.cookies,
            stats: outcome.stats,
            row_issues: outcome.issues,
            acquisition: outcome.acquisition_strategy.into(),
            acquisition_attempts: outcome.acquisition_attempts,
            // `legacy_error` reports that no row decoded, which the legacy API
            // treats as a failure. Section 5.7 does not: acquisition, parsing,
            // and the query all completed, so the source succeeded with every
            // row skipped. `row_issues` and `rows_skipped` already carry that
            // detail, so nothing is lost by not restating it as a failure.
            failure: None,
          });
        }
        Err(error) => {
          let failure = error.downcast_ref::<crate::common::sqlite::BrowserDatabaseFailure>();
          profile_extractions.push(ChromiumProfileExtraction {
            profile,
            cookies: Vec::new(),
            stats: ChromiumExtractionStats::default(),
            row_issues: Vec::new(),
            acquisition: failure.and_then(|failure| failure.strategy).into(),
            acquisition_attempts: failure.map_or(1, |failure| failure.attempts),
            failure: Some(ChromiumProfileFailure::Extraction(error.to_string())),
          });
        }
      }
    }
    report.installations.push(ChromiumInstallationExtraction {
      installation_id: installation.installation_id,
      channel: installation.channel,
      profiles: profile_extractions,
    });
  }
  Ok(report)
}

/// Resolves a browser's platform key credentials from the registry.
///
/// Section 5.9 makes the registry the single source of truth for the generic
/// pipeline, because a registry-only browser has no `config.json` entry to fall
/// back to. Legacy named wrappers keep their own `config.json` lookup, so this
/// cannot change legacy key resolution.
///
/// The credentials are carried in a `config::Browser` because that is what the
/// platform providers already consume; only its credential fields are read.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn registry_key_credentials(browser_id: &str) -> Result<crate::config::Browser> {
  let registry = embedded_registry()?;
  let platform = PlatformId::current()?;
  let definition = browser_definition(registry, platform, browser_id)?;
  Ok(provider_input(definition.key_credentials.as_ref()))
}

/// Field-for-field mapping, kept separate from the lookup so it can be
/// exercised with credentials from any platform. A definition only ever carries
/// its own platform's subfields, so testing this through the lookup alone would
/// leave the other platform's mapping unobserved.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn provider_input(credentials: Option<&KeyCredentials>) -> crate::config::Browser {
  let keychain = credentials.and_then(|credentials| credentials.macos_keychain.as_ref());
  crate::config::Browser {
    paths: Vec::new(),
    channels: None,
    unix_crypt_name: credentials.and_then(|credentials| credentials.linux_crypt_name.clone()),
    osx_key_service: keychain.map(|keychain| keychain.service.clone()),
    osx_key_user: keychain.map(|keychain| keychain.account.clone()),
  }
}

struct SystemChromiumKeyProvider;

impl ChromiumKeyProvider<BrowserInstallation> for SystemChromiumKeyProvider {
  fn retrieve(&self, installation: &BrowserInstallation) -> ChromiumKeyOutcomes {
    #[cfg(target_os = "windows")]
    {
      let local_state = std::fs::read_to_string(&installation.local_state_path)
        .map_err(anyhow::Error::from)
        .and_then(|contents| serde_json::from_str(&contents).map_err(anyhow::Error::from));
      return match local_state {
        Ok(local_state) => {
          let provider = WindowsPlatformKeyProvider::new(&local_state);
          retrieve_key_outcomes(&provider, &())
        }
        Err(error) => ChromiumKeyOutcomes {
          v10: ChromiumKeyOutcome::failure(format!(
            "failed to read installation Local State: {error}"
          )),
          v11: ChromiumKeyOutcome::NotApplicable,
          v20: ChromiumKeyOutcome::failure(format!(
            "failed to read installation Local State: {error}"
          )),
        },
      };
    }

    #[cfg(target_os = "linux")]
    {
      let credentials = match registry_key_credentials(&installation.browser_id) {
        Ok(credentials) => credentials,
        Err(error) => {
          let message = error.to_string();
          return ChromiumKeyOutcomes {
            v10: ChromiumKeyOutcome::failure(message.clone()),
            v11: ChromiumKeyOutcome::failure(message),
            v20: ChromiumKeyOutcome::NotApplicable,
          };
        }
      };
      let provider = LinuxPlatformKeyProvider::new(&credentials);
      return retrieve_key_outcomes(&provider, &());
    }

    #[cfg(target_os = "macos")]
    {
      let credentials = match registry_key_credentials(&installation.browser_id) {
        Ok(credentials) => credentials,
        Err(error) => {
          return ChromiumKeyOutcomes {
            v10: ChromiumKeyOutcome::failure(error.to_string()),
            v11: ChromiumKeyOutcome::NotApplicable,
            v20: ChromiumKeyOutcome::NotApplicable,
          };
        }
      };
      let provider = MacosPlatformKeyProvider::new(&credentials);
      return retrieve_key_outcomes(&provider, &());
    }

    #[allow(unreachable_code)]
    ChromiumKeyOutcomes {
      v10: ChromiumKeyOutcome::NotApplicable,
      v11: ChromiumKeyOutcome::NotApplicable,
      v20: ChromiumKeyOutcome::NotApplicable,
    }
  }
}

/// Private Milestone 3C profile-listing seam. This is deliberately not
/// re-exported from `lib.rs` before the coordinated public report release.
pub(crate) fn chrome_profiles() -> Result<Vec<ChromiumProfile>> {
  chromium_profiles("chrome")
}

/// Private generic Chromium listing seam. It intentionally remains crate-private
/// until the coordinated public report release; legacy named wrappers still use
/// their frozen selectors.
pub(crate) fn chromium_profiles(browser_id: &str) -> Result<Vec<ChromiumProfile>> {
  let context = DiscoveryContext::system()?;
  profiles_for_listing(
    browser_id,
    discover_browser_with_context(&context, browser_id)?,
  )
}

fn profiles_for_listing(
  browser_id: &str,
  discovery: ChromiumDiscovery,
) -> Result<Vec<ChromiumProfile>> {
  if discovery.all_detected_roots_failed() {
    bail!("every detected {browser_id} installation failed profile enumeration")
  }
  Ok(discovery.profiles())
}

/// Chromium listing that keeps its discovery diagnostics.
///
/// [`chromium_profiles`] answers only "which profiles exist", so a root that
/// failed while a sibling root succeeded leaves no trace in its result. The
/// report layer needs those partial failures and the detected/enumerated root
/// state, so it takes this seam instead.
pub(crate) struct ChromiumListing {
  pub(crate) profiles: Vec<ChromiumProfile>,
  pub(crate) discovery_issues: Vec<DiscoveryIssue>,
  pub(crate) installations_discovered: usize,
  pub(crate) all_detected_roots_failed: bool,
}

pub(crate) fn chromium_listing(browser_id: &str) -> Result<ChromiumListing> {
  let context = DiscoveryContext::system()?;
  let discovery = discover_browser_with_context(&context, browser_id)?;
  Ok(ChromiumListing {
    profiles: discovery.profiles(),
    installations_discovered: discovery.installations.len(),
    all_detected_roots_failed: discovery.all_detected_roots_failed(),
    discovery_issues: discovery.issues,
  })
}

/// Private generic Chromium report seam covering every registered
/// Chromium-family browser. Legacy named wrappers keep their frozen selectors.
pub(crate) fn chromium_registry_report(
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<Vec<String>>,
) -> Result<ChromiumRegistryReport> {
  let context = DiscoveryContext::system()?;
  extract_chromium_with_provider(
    &context,
    browser_id,
    profile_id,
    domains,
    &SystemChromiumKeyProvider,
  )
}

/// Private Milestone 3C ID-based selector/report seam.
pub(crate) fn chrome_profile(
  profile_id: &str,
  domains: Option<Vec<String>>,
) -> Result<ChromiumRegistryReport> {
  let context = DiscoveryContext::system()?;
  extract_chromium_with_provider(
    &context,
    "chrome",
    Some(profile_id),
    domains,
    &SystemChromiumKeyProvider,
  )
}

pub(crate) const SOURCE_ROLE_PERSISTENT: &str = "persistent";
pub(crate) const SOURCE_ROLE_SESSION: &str = "session";
/// A profile never merges two persistent alternatives, so the authoritative
/// persistent source always carries the first declared precedence.
pub(crate) const PERSISTENT_SOURCE_PRECEDENCE: u16 = 10;

/// Source-level outcome shared by the non-Chromium adapters. It is deliberately
/// crate-private: 4E owns the final cross-engine DTO freeze.
#[derive(Debug)]
pub(crate) struct EngineSourceExtraction {
  pub(crate) path: PathBuf,
  pub(crate) role: &'static str,
  pub(crate) format: &'static str,
  pub(crate) precedence: u16,
  pub(crate) selected: bool,
  pub(crate) cookies: Vec<Cookie>,
  pub(crate) rows_seen: usize,
  pub(crate) rows_skipped: usize,
  pub(crate) acquisition: SourceAcquisition,
  pub(crate) acquisition_attempts: u32,
  pub(crate) diagnostics: Vec<String>,
  /// The source could not be acquired, parsed, or queried, so it failed.
  pub(crate) error: Option<String>,
  /// Where `error` happened. The report's `stage` is a frozen field, so
  /// flattening a parse or query failure into `acquisition` would misdescribe
  /// it and rob consumers of the signal they need to choose a remedy.
  pub(crate) error_stage: SourceFailureStage,
  /// A row was seen and rejected. Reported as a row issue against a source
  /// that still succeeded, never as a source failure.
  pub(crate) row_error: Option<String>,
}

/// The stage at which a source failed, mapped onto the frozen report vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum SourceFailureStage {
  #[default]
  Acquisition,
  Parse,
  Query,
}

/// How a source was made readable. Non-SQLite engines never acquire through the
/// browser-database layer, so their strategies are separate variants rather
/// than an absent [`DatabaseAcquisitionStrategy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceAcquisition {
  Database(DatabaseAcquisitionStrategy),
  StableFileImage,
  EseDatabase,
  NotAttempted,
}

impl From<Option<DatabaseAcquisitionStrategy>> for SourceAcquisition {
  fn from(strategy: Option<DatabaseAcquisitionStrategy>) -> Self {
    strategy.map_or(Self::NotAttempted, Self::Database)
  }
}

#[derive(Debug)]
pub(crate) struct EngineProfileExtraction {
  pub(crate) profile_id: String,
  pub(crate) installation_id: String,
  pub(crate) installation_priority: u16,
  pub(crate) installation_path: PathBuf,
  pub(crate) name: String,
  pub(crate) path: PathBuf,
  pub(crate) is_default: bool,
  pub(crate) persistent_source_discovered: bool,
  pub(crate) sources: Vec<EngineSourceExtraction>,
}

#[derive(Debug, Default)]
pub(crate) struct EngineExtractionOutcome {
  pub(crate) profiles: Vec<EngineProfileExtraction>,
  pub(crate) discovery_issues: Vec<DiscoveryIssue>,
  /// Distinct installations that were resolved and owned by this browser.
  /// Duplicates and roots that failed to canonicalize are excluded, matching
  /// what the Chromium adapter reports.
  pub(crate) installations_discovered: usize,
  /// Roots that existed on disk, including ones that then failed to
  /// canonicalize or were owned by an earlier root.
  pub(crate) installations_detected: usize,
  /// Roots whose profile enumeration completed, even when it found nothing.
  pub(crate) installations_enumerated: usize,
}

impl EngineExtractionOutcome {
  /// Section 5.7: when every applicable detected root fails enumeration the
  /// result is `failed`/`Err`, never an empty list indistinguishable from a
  /// browser that is simply not installed.
  pub(crate) fn all_detected_roots_failed(&self) -> bool {
    self.installations_detected > 0 && self.installations_enumerated == 0
  }
}

pub(crate) const GECKO_PERSISTENT_SOURCE: &str = "cookies.sqlite";

fn gecko_profile_has_source<F: DiscoveryFs>(context: &DiscoveryContext<F>, path: &Path) -> bool {
  context.fs.exists(&path.join(GECKO_PERSISTENT_SOURCE))
    || mozilla::SESSION_CANDIDATES
      .iter()
      .any(|(relative, _)| context.fs.exists(&path.join(relative)))
}

fn source_candidate(
  path: PathBuf,
  role: &'static str,
  format: &'static str,
  precedence: u16,
) -> EngineSourceExtraction {
  EngineSourceExtraction {
    path,
    role,
    format,
    precedence,
    selected: false,
    cookies: Vec::new(),
    rows_seen: 0,
    rows_skipped: 0,
    acquisition: SourceAcquisition::NotAttempted,
    acquisition_attempts: 0,
    diagnostics: Vec::new(),
    error: None,
    error_stage: SourceFailureStage::Acquisition,
    row_error: None,
  }
}

/// Discovery-only Gecko listing seam: existing cookie-bearing candidates
/// without acquiring or querying any of them.
fn gecko_profiles_with_context<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
) -> Result<EngineExtractionOutcome> {
  let mut outcome = discover_gecko_with_context(context, browser_id)?;
  for profile in &mut outcome.profiles {
    if profile.persistent_source_discovered {
      profile.sources.push(source_candidate(
        profile.path.join(GECKO_PERSISTENT_SOURCE),
        SOURCE_ROLE_PERSISTENT,
        "mozilla_sqlite",
        PERSISTENT_SOURCE_PRECEDENCE,
      ));
    }
    for (index, (relative, format)) in mozilla::SESSION_CANDIDATES.into_iter().enumerate() {
      let path = profile.path.join(relative);
      if context.fs.exists(&path) {
        profile.sources.push(source_candidate(
          path,
          SOURCE_ROLE_SESSION,
          format.format_id(),
          mozilla::session_candidate_precedence(index),
        ));
      }
    }
  }
  Ok(outcome)
}

pub(crate) fn gecko_profiles(browser_id: &str) -> Result<EngineExtractionOutcome> {
  let context = DiscoveryContext::system()?;
  gecko_profiles_with_context(&context, browser_id)
}

const MAX_DISCOVERY_ISSUE_SAMPLES: usize = 32;

/// Retains at most [`MAX_DISCOVERY_ISSUE_SAMPLES`] paths per code so a profile
/// tree full of the same defect cannot dictate report size. Occurrences beyond
/// the sample bound are counted on the first retained sample, so the per-code
/// total survives even though its paths do not.
fn push_bounded_discovery_issue(
  issues: &mut Vec<DiscoveryIssue>,
  code: &'static str,
  path: PathBuf,
  message: &str,
) {
  let sampled = issues.iter().filter(|issue| issue.code == code).count();
  if sampled < MAX_DISCOVERY_ISSUE_SAMPLES {
    issues.push(DiscoveryIssue::new(code, path, message));
    return;
  }
  if let Some(first) = issues.iter_mut().find(|issue| issue.code == code) {
    first.occurrences = first.occurrences.saturating_add(1);
  }
}

struct MarkerlessGeckoProfiles {
  profiles: Vec<mozilla::MozillaProfile>,
  optional_container_error: Option<anyhow::Error>,
}

fn markerless_gecko_profiles<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  root: &Path,
) -> Result<MarkerlessGeckoProfiles> {
  let mut candidates = context.fs.read_dir(root)?;
  let profiles_container = root.join("Profiles");
  let mut optional_container_error = None;
  if context.fs.is_dir(&profiles_container) {
    match context.fs.read_dir(&profiles_container) {
      Ok(children) => candidates.extend(children),
      Err(error) => optional_container_error = Some(error),
    }
  }
  candidates.sort_by_key(|path| normalized_path_bytes(path));
  candidates.dedup_by(|left, right| normalized_path_bytes(left) == normalized_path_bytes(right));
  Ok(MarkerlessGeckoProfiles {
    profiles: candidates
      .into_iter()
      .filter(|path| context.fs.is_dir(path) && gecko_profile_has_source(context, path))
      .map(|path| mozilla::MozillaProfile {
        name: path
          .file_name()
          .map(|name| name.to_string_lossy().into_owned())
          .unwrap_or_default(),
        path,
        is_default: false,
      })
      .collect(),
    optional_container_error,
  })
}

/// Resolves a registry root to the canonical directory that identifies its
/// installation.
///
/// Section 5.5 gives the first installation in deterministic registry order
/// ownership of everything under it, so a later root resolving to the same
/// directory is one `duplicate_installation` signal rather than a second
/// installation whose every profile then looks like a `duplicate_profile`.
fn canonical_installation_root<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  root_path: PathBuf,
  seen_installations: &mut HashSet<Vec<u8>>,
  outcome: &mut EngineExtractionOutcome,
) -> Option<PathBuf> {
  outcome.installations_detected += 1;
  let canonical_root = match context.fs.canonicalize(&root_path) {
    Ok(path) => path,
    Err(error) => {
      outcome.discovery_issues.push(DiscoveryIssue::new(
        "installation_canonicalize_failed",
        root_path,
        error.to_string(),
      ));
      return None;
    }
  };
  if !seen_installations.insert(normalized_path_bytes(&canonical_root)) {
    push_bounded_discovery_issue(
      &mut outcome.discovery_issues,
      "duplicate_installation",
      canonical_root,
      "installation is already owned by an earlier registry root",
    );
    return None;
  }
  outcome.installations_discovered += 1;
  Some(canonical_root)
}

fn discover_gecko_with_context<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
) -> Result<EngineExtractionOutcome> {
  let registry = embedded_registry()?;
  let definition = browser_definition(registry, context.platform, browser_id)?;
  if definition.engine != BrowserEngine::Gecko {
    bail!("browser {browser_id:?} is not a Gecko browser")
  }
  let mut roots: Vec<&InstallationRoot> = definition.roots.iter().collect();
  roots.sort_by_key(|root| (root.priority, root.root_id.as_str()));
  let mut seen_installations = HashSet::new();
  let mut seen_profiles = HashSet::new();
  let mut outcome = EngineExtractionOutcome::default();

  for root in roots {
    if root.discovery != DiscoveryStrategy::MozillaProfilesIni {
      continue;
    }
    let Some(resolved_root) = context.resolve_template(&root.template) else {
      continue;
    };
    let root_path = resolved_root.base.join(resolved_root.suffix);
    if !context.fs.is_dir(&root_path) {
      continue;
    }
    let Some(canonical_root) =
      canonical_installation_root(context, root_path, &mut seen_installations, &mut outcome)
    else {
      continue;
    };
    let installation_id = installation_id(
      &definition.canonical_id,
      &root.root_id,
      &root.channel,
      &normalized_path_bytes(&canonical_root),
    );
    let ini_path = canonical_root.join("profiles.ini");
    // A flat installation root counts as the default profile only when
    // profiles.ini told us nothing at all. An unreadable or invalid file is
    // information: it means declarations exist that we failed to interpret, so
    // the flat root is a fallback rather than a confirmed default.
    let (declared, flat_root_is_default) = if context.fs.exists(&ini_path) {
      match context
        .fs
        .read_to_string(&ini_path)
        .and_then(|contents| mozilla::list_profiles_from_str(&contents, &ini_path))
      {
        Ok(profiles) if profiles.is_empty() => (profiles, true),
        Ok(profiles) => (profiles, false),
        Err(error) => {
          outcome.discovery_issues.push(DiscoveryIssue::new(
            "mozilla_profiles_ini_invalid",
            ini_path,
            error.to_string(),
          ));
          (Vec::new(), false)
        }
      }
    } else {
      (Vec::new(), true)
    };

    // An unreadable profiles.ini is recovered from below, so enumeration only
    // fails when no strategy could list the root at all.
    let mut enumerated = true;
    let mut usable = Vec::new();
    for declared_profile in declared {
      if !gecko_profile_has_source(context, &declared_profile.path) {
        push_bounded_discovery_issue(
          &mut outcome.discovery_issues,
          "profile_has_no_cookie_source",
          declared_profile.path,
          "declared Gecko profile has no supported cookie source",
        );
        continue;
      }
      usable.push(declared_profile);
    }
    if usable.is_empty() {
      if gecko_profile_has_source(context, &canonical_root) {
        usable.push(mozilla::MozillaProfile {
          name: canonical_root
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
          path: canonical_root.clone(),
          is_default: flat_root_is_default,
        });
      } else {
        match markerless_gecko_profiles(context, &canonical_root) {
          Ok(discovery) => {
            usable = discovery.profiles;
            if let Some(error) = discovery.optional_container_error {
              // The container is only "optional" while something else was
              // found. If it was the last place left to look and it could not
              // be read, this installation enumerated nothing and saying so at
              // warning severity would let the report claim success.
              let code = if usable.is_empty() {
                enumerated = false;
                "installation_enumeration_failed"
              } else {
                "optional_profiles_enumeration_failed"
              };
              outcome.discovery_issues.push(DiscoveryIssue::new(
                code,
                canonical_root.join("Profiles"),
                error.to_string(),
              ));
            }
          }
          Err(error) => {
            enumerated = false;
            outcome.discovery_issues.push(DiscoveryIssue::new(
              "installation_enumeration_failed",
              canonical_root.clone(),
              error.to_string(),
            ));
          }
        }
      }
    }
    if enumerated {
      outcome.installations_enumerated += 1;
    }

    for declared_profile in usable {
      let profile_path = match context.fs.canonicalize(&declared_profile.path) {
        Ok(path) => path,
        Err(error) => {
          push_bounded_discovery_issue(
            &mut outcome.discovery_issues,
            "profile_canonicalize_failed",
            declared_profile.path,
            &error.to_string(),
          );
          continue;
        }
      };
      if !seen_profiles.insert(normalized_path_bytes(&profile_path)) {
        push_bounded_discovery_issue(
          &mut outcome.discovery_issues,
          "duplicate_profile",
          profile_path,
          "profile is already owned by an earlier registry root",
        );
        continue;
      }
      let locator = profile_path
        .strip_prefix(&canonical_root)
        .map(ProfileLocator::Relative)
        .unwrap_or(ProfileLocator::Absolute(&profile_path));
      outcome.profiles.push(EngineProfileExtraction {
        profile_id: profile_id(&installation_id, locator),
        installation_id: installation_id.clone(),
        installation_priority: root.priority,
        installation_path: canonical_root.clone(),
        name: declared_profile.name,
        persistent_source_discovered: context.fs.exists(&profile_path.join("cookies.sqlite")),
        path: profile_path,
        is_default: declared_profile.is_default,
        sources: Vec::new(),
      });
    }
  }
  sort_engine_profiles(&mut outcome.profiles);
  Ok(outcome)
}

/// Section 5.5 ordering: installations by registry priority then normalized
/// path, then profiles default-first, by locale-independent lowercase name, raw
/// name, and finally normalized path.
fn sort_engine_profiles(profiles: &mut [EngineProfileExtraction]) {
  profiles.sort_by(|left, right| {
    left
      .installation_priority
      .cmp(&right.installation_priority)
      .then_with(|| {
        normalized_path_bytes(&left.installation_path)
          .cmp(&normalized_path_bytes(&right.installation_path))
      })
      .then_with(|| (!left.is_default).cmp(&(!right.is_default)))
      .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
      .then_with(|| left.name.cmp(&right.name))
      .then_with(|| normalized_path_bytes(&left.path).cmp(&normalized_path_bytes(&right.path)))
  });
}

/// Crate-private generic Gecko report seam. It deliberately does not call the
/// legacy wrapper, so it can retain every invalid session candidate and can
/// surface a session-only profile without changing `firefox_profiles()`.
fn gecko_report_with_context<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
  domains: Option<&[String]>,
) -> Result<EngineExtractionOutcome> {
  let outcome = discover_gecko_with_context(context, browser_id)?;
  Ok(populate_gecko_sources(
    outcome,
    domains,
    mozilla::query_cookies_engine_outcome,
    |path| context.fs.exists(path),
  ))
}

fn populate_gecko_sources<Q, E>(
  mut outcome: EngineExtractionOutcome,
  domains: Option<&[String]>,
  mut query: Q,
  mut persistent_exists: E,
) -> EngineExtractionOutcome
where
  Q: FnMut(&Path, Option<&[String]>) -> mozilla::MozillaEngineExtractionOutcome,
  E: FnMut(&Path) -> bool,
{
  for profile in &mut outcome.profiles {
    let persistent = profile.path.join("cookies.sqlite");
    // The Mozilla outcome also owns session fallback. A missing persistent DB
    // is normal for a session-only profile and is not projected as a source.
    //
    // Discovery's snapshot goes stale in both directions, so existence is
    // rechecked after the query rather than inferred from it: a database that
    // appeared since discovery is projected even when reading it then failed,
    // and one deleted since discovery is still projected so its failure is
    // reported instead of vanishing. Inferring from the query alone would
    // silence a database that appeared and was corrupt or locked.
    let mut extraction = query(&persistent, domains);
    if profile.persistent_source_discovered || persistent_exists(&persistent) {
      sort_cookies(&mut extraction.persistent_cookies);
      profile.sources.push(EngineSourceExtraction {
        path: persistent,
        role: SOURCE_ROLE_PERSISTENT,
        format: mozilla::PERSISTENT_FORMAT_ID,
        precedence: PERSISTENT_SOURCE_PRECEDENCE,
        selected: true,
        rows_seen: extraction.persistent_rows_seen,
        rows_skipped: extraction.persistent_rows_skipped,
        cookies: extraction.persistent_cookies,
        acquisition: extraction.persistent_acquisition_strategy.into(),
        acquisition_attempts: extraction.persistent_acquisition_attempts,
        // `diagnostics` carries acquisition retry notes, which a report renders
        // as a warning meaning "retried, then succeeded". A rejected row is
        // neither a retry nor a recovery — rows were lost — so it must not be
        // reported that way. The row error stays on the Mozilla outcome for the
        // report layer to raise as an error-severity row failure instead.
        diagnostics: Vec::new(),
        error: extraction.persistent_error,
        error_stage: match extraction.persistent_failure_kind {
          Some(crate::common::sqlite::BrowserDatabaseFailureKind::Query) => {
            SourceFailureStage::Query
          }
          _ => SourceFailureStage::Acquisition,
        },
        row_error: extraction.persistent_row_error,
      });
    }
    profile
      .sources
      .extend(extraction.session_sources.into_iter().map(|mut source| {
        sort_cookies(&mut source.cookies);
        EngineSourceExtraction {
          path: source.path,
          role: SOURCE_ROLE_SESSION,
          format: source.format,
          precedence: source.precedence,
          selected: source.selected,
          rows_seen: source.rows_seen,
          rows_skipped: source.rows_skipped,
          cookies: source.cookies,
          acquisition: SourceAcquisition::StableFileImage,
          acquisition_attempts: source.acquisition_attempts,
          diagnostics: source.diagnostics,
          // A session candidate's `error` means the candidate itself could not
          // be parsed, which is a real source failure. Rows it rejected are
          // already counted in `rows_skipped` and described by `diagnostics`.
          error: source.error,
          // A session candidate fails by being unreadable as JSON/LZ4, which is
          // a parse failure, not an acquisition one.
          error_stage: SourceFailureStage::Parse,
          row_error: None,
        }
      }));
  }
  outcome
}

pub(crate) fn gecko_report(
  browser_id: &str,
  domains: Option<Vec<String>>,
) -> Result<EngineExtractionOutcome> {
  let context = DiscoveryContext::system()?;
  gecko_report_with_context(&context, browser_id, domains.as_deref())
}

/// Resolves the installation roots an engine adapter should walk, in the fixed
/// registry order of priority then root ID.
fn engine_roots<'a>(
  registry: &'a Registry,
  platform: PlatformId,
  browser_id: &str,
  engine: BrowserEngine,
) -> Result<(&'a BrowserDefinition, Vec<&'a InstallationRoot>)> {
  let definition = browser_definition(registry, platform, browser_id)?;
  if definition.engine != engine {
    bail!("browser {browser_id:?} is not a {engine:?} browser")
  }
  let mut roots: Vec<&InstallationRoot> = definition.roots.iter().collect();
  roots.sort_by_key(|root| (root.priority, root.root_id.as_str()));
  Ok((definition, roots))
}

#[cfg(any(target_os = "macos", test))]
const SAFARI_COOKIE_FILE: &str = "Cookies.binarycookies";

/// Crate-private generic Safari seam. Named profiles come from PR #137's
/// database-first discovery; this adapter only reshapes them, so legacy
/// `safari()` first-match selection is untouched.
#[cfg(any(target_os = "macos", test))]
fn discover_safari_with_context<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
) -> Result<EngineExtractionOutcome> {
  use super::safari;

  let registry = embedded_registry()?;
  let (definition, roots) = engine_roots(
    registry,
    context.platform,
    browser_id,
    BrowserEngine::Safari,
  )?;
  let mut seen_installations = HashSet::new();
  let mut seen_profiles = HashSet::new();
  let mut outcome = EngineExtractionOutcome::default();

  for root in roots {
    if root.discovery != DiscoveryStrategy::SafariDefaultProfile {
      continue;
    }
    let Some(resolved_root) = context.resolve_template(&root.template) else {
      continue;
    };
    // Non-Chromium registry templates never glob, so the suffix is literal.
    let root_path = resolved_root.base.join(resolved_root.suffix);
    if !context.fs.is_dir(&root_path) {
      continue;
    }
    let Some(canonical_root) =
      canonical_installation_root(context, root_path, &mut seen_installations, &mut outcome)
    else {
      continue;
    };
    let installation_id = installation_id(
      &definition.canonical_id,
      &root.root_id,
      &root.channel,
      &normalized_path_bytes(&canonical_root),
    );

    // Safari profile discovery degrades to the default profile instead of
    // failing, so a canonicalized root is always enumerated.
    outcome.installations_enumerated += 1;
    let (profiles, discovery_warning) = safari::discover_safari_profiles(&canonical_root);
    if let Some(warning) = discovery_warning {
      // A fallback that still enumerated named profiles is a degradation; one
      // that failed too means they were never enumerated, which is a loss and
      // must not be reported at warning severity.
      let code = match warning {
        safari::SafariProfileDiscoveryIssue::Degraded(_) => "safari_profile_discovery_degraded",
        safari::SafariProfileDiscoveryIssue::EnumerationFailed(_) => {
          "safari_profile_enumeration_failed"
        }
      };
      outcome.discovery_issues.push(DiscoveryIssue::new(
        code,
        canonical_root.clone(),
        warning.message(),
      ));
    }

    for profile in profiles {
      let selected = match safari::first_existing_cookie_candidate(&profile.cookie_candidates) {
        Ok(Some(path)) => path.clone(),
        // A discovered profile with no cookie source is normal absence, not an
        // extraction failure, so it is not listed as a report profile.
        Ok(None) => {
          outcome.discovery_issues.push(DiscoveryIssue::new(
            "profile_has_no_cookie_source",
            canonical_root.join(&profile.name),
            "Safari profile has no cookie source".to_owned(),
          ));
          continue;
        }
        Err(error) => {
          outcome.discovery_issues.push(DiscoveryIssue::new(
            "profile_source_inspection_failed",
            canonical_root.join(&profile.name),
            format!("{error:#}"),
          ));
          continue;
        }
      };
      let precedence = profile
        .cookie_candidates
        .iter()
        .position(|candidate| candidate == &selected)
        .map_or(PERSISTENT_SOURCE_PRECEDENCE, |index| {
          PERSISTENT_SOURCE_PRECEDENCE * (index as u16 + 1)
        });
      let source_directory = selected
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| canonical_root.clone());
      let profile_path = match context.fs.canonicalize(&source_directory) {
        Ok(path) => path,
        Err(error) => {
          outcome.discovery_issues.push(DiscoveryIssue::new(
            "profile_canonicalize_failed",
            source_directory,
            error.to_string(),
          ));
          continue;
        }
      };
      if !seen_profiles.insert(normalized_path_bytes(&profile_path)) {
        outcome.discovery_issues.push(DiscoveryIssue::new(
          "duplicate_profile",
          profile_path,
          "profile is already owned by an earlier registry root".to_owned(),
        ));
        continue;
      }
      let locator = profile_path
        .strip_prefix(&canonical_root)
        .map(ProfileLocator::Relative)
        .unwrap_or(ProfileLocator::Absolute(&profile_path));
      let source_path = profile_path.join(SAFARI_COOKIE_FILE);
      let source = EngineSourceExtraction {
        path: source_path,
        role: SOURCE_ROLE_PERSISTENT,
        format: "safari_binarycookies",
        precedence,
        selected: true,
        cookies: Vec::new(),
        rows_seen: 0,
        rows_skipped: 0,
        acquisition: SourceAcquisition::StableFileImage,
        // Replaced with the real count once acquisition runs; discovery-only
        // listings never attempt a read.
        acquisition_attempts: 0,
        diagnostics: Vec::new(),
        error: None,
        error_stage: SourceFailureStage::Acquisition,
        row_error: None,
      };
      outcome.profiles.push(EngineProfileExtraction {
        profile_id: profile_id(&installation_id, locator),
        installation_id: installation_id.clone(),
        installation_priority: root.priority,
        installation_path: canonical_root.clone(),
        name: profile.name,
        path: profile_path,
        is_default: profile.uuid.is_none(),
        persistent_source_discovered: true,
        sources: vec![source],
      });
    }
  }
  sort_engine_profiles(&mut outcome.profiles);
  Ok(outcome)
}

#[cfg(any(target_os = "macos", test))]
fn safari_report_with_context<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
  domains: Option<&[String]>,
) -> Result<EngineExtractionOutcome> {
  let mut outcome = discover_safari_with_context(context, browser_id)?;
  for profile in &mut outcome.profiles {
    for source in &mut profile.sources {
      match super::safari::safari_based_outcome(
        source.path.clone(),
        domains.map(<[String]>::to_vec),
      ) {
        Ok(extraction) => {
          source.rows_seen = extraction.stats.records_seen;
          source.rows_skipped = extraction.stats.records_skipped;
          source.acquisition_attempts = extraction.acquisition_attempts;
          source.cookies = extraction.cookies;
        }
        Err(error) => {
          // Exhausting the retries is itself the failure, so report the
          // attempts spent rather than the placeholder.
          source.acquisition_attempts = super::safari::STABLE_READ_ATTEMPTS as u32;
          source.error_stage = if error
            .downcast_ref::<super::safari::SafariParseFailure>()
            .is_some()
          {
            SourceFailureStage::Parse
          } else {
            SourceFailureStage::Acquisition
          };
          source.error = Some(format!("{error:#}"));
        }
      }
    }
  }
  Ok(outcome)
}

#[cfg(target_os = "macos")]
pub(crate) fn safari_report(
  browser_id: &str,
  domains: Option<Vec<String>>,
) -> Result<EngineExtractionOutcome> {
  let context = DiscoveryContext::system()?;
  safari_report_with_context(&context, browser_id, domains.as_deref())
}

#[cfg(target_os = "macos")]
pub(crate) fn safari_profiles(browser_id: &str) -> Result<EngineExtractionOutcome> {
  let context = DiscoveryContext::system()?;
  discover_safari_with_context(&context, browser_id)
}

#[cfg(any(target_os = "windows", test))]
const INTERNET_EXPLORER_COOKIE_FILE: &str = "WebCacheV01.dat";

/// Row accounting an Internet Explorer extractor must report. The extractor is
/// injected because the ESE reader only compiles on Windows.
#[cfg(any(target_os = "windows", test))]
pub(crate) struct InternetExplorerRows {
  pub(crate) cookies: Vec<Cookie>,
  pub(crate) records_seen: usize,
  pub(crate) records_skipped: usize,
}

/// Crate-private generic Internet Explorer seam. The WebCache root is flat, so
/// each detected root contributes exactly one default profile.
#[cfg(any(target_os = "windows", test))]
fn discover_internet_explorer_with_context<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
) -> Result<EngineExtractionOutcome> {
  let registry = embedded_registry()?;
  let (definition, roots) = engine_roots(
    registry,
    context.platform,
    browser_id,
    BrowserEngine::InternetExplorer,
  )?;
  let mut seen_installations = HashSet::new();
  let mut seen_profiles = HashSet::new();
  let mut outcome = EngineExtractionOutcome::default();

  for root in roots {
    if root.discovery != DiscoveryStrategy::InternetExplorerWebCache {
      continue;
    }
    let Some(resolved_root) = context.resolve_template(&root.template) else {
      continue;
    };
    // Non-Chromium registry templates never glob, so the suffix is literal.
    let root_path = resolved_root.base.join(resolved_root.suffix);
    if !context.fs.is_dir(&root_path) {
      continue;
    }
    let Some(canonical_root) =
      canonical_installation_root(context, root_path, &mut seen_installations, &mut outcome)
    else {
      continue;
    };
    // A WebCache root is its own profile, so there is no enumeration step that
    // could fail once the root canonicalized.
    outcome.installations_enumerated += 1;
    let source_path = canonical_root.join(INTERNET_EXPLORER_COOKIE_FILE);
    if !context.fs.exists(&source_path) {
      outcome.discovery_issues.push(DiscoveryIssue::new(
        "profile_has_no_cookie_source",
        canonical_root,
        "WebCache root has no cookie database".to_owned(),
      ));
      continue;
    }
    if !seen_profiles.insert(normalized_path_bytes(&canonical_root)) {
      outcome.discovery_issues.push(DiscoveryIssue::new(
        "duplicate_profile",
        canonical_root,
        "profile is already owned by an earlier registry root".to_owned(),
      ));
      continue;
    }
    let installation_id = installation_id(
      &definition.canonical_id,
      &root.root_id,
      &root.channel,
      &normalized_path_bytes(&canonical_root),
    );
    let source = EngineSourceExtraction {
      path: source_path,
      role: SOURCE_ROLE_PERSISTENT,
      format: "internet_explorer_ese",
      precedence: PERSISTENT_SOURCE_PRECEDENCE,
      selected: true,
      cookies: Vec::new(),
      rows_seen: 0,
      rows_skipped: 0,
      acquisition: SourceAcquisition::EseDatabase,
      acquisition_attempts: 1,
      diagnostics: Vec::new(),
      error: None,
      error_stage: SourceFailureStage::Acquisition,
      row_error: None,
    };
    outcome.profiles.push(EngineProfileExtraction {
      profile_id: profile_id(&installation_id, ProfileLocator::Relative(Path::new(""))),
      installation_id,
      installation_priority: root.priority,
      installation_path: canonical_root.clone(),
      name: "default".to_owned(),
      path: canonical_root,
      is_default: true,
      persistent_source_discovered: true,
      sources: vec![source],
    });
  }
  sort_engine_profiles(&mut outcome.profiles);
  Ok(outcome)
}

#[cfg(any(target_os = "windows", test))]
fn internet_explorer_report_with_context<F, Q>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
  domains: Option<&[String]>,
  mut query: Q,
) -> Result<EngineExtractionOutcome>
where
  F: DiscoveryFs,
  Q: FnMut(&Path, Option<&[String]>) -> Result<InternetExplorerRows>,
{
  let mut outcome = discover_internet_explorer_with_context(context, browser_id)?;
  for profile in &mut outcome.profiles {
    for source in &mut profile.sources {
      match query(&source.path, domains) {
        Ok(rows) => {
          source.rows_seen = rows.records_seen;
          source.rows_skipped = rows.records_skipped;
          source.cookies = rows.cookies;
        }
        Err(error) => {
          // WebCache failures are schema or record-enumeration problems, which
          // the ESE reader reaches only after opening the database.
          source.error_stage = SourceFailureStage::Parse;
          source.error = Some(format!("{error:#}"));
        }
      }
    }
  }
  Ok(outcome)
}

#[cfg(target_os = "windows")]
pub(crate) fn internet_explorer_profiles(browser_id: &str) -> Result<EngineExtractionOutcome> {
  let context = DiscoveryContext::system()?;
  discover_internet_explorer_with_context(&context, browser_id)
}

#[cfg(target_os = "windows")]
pub(crate) fn internet_explorer_report(
  browser_id: &str,
  domains: Option<Vec<String>>,
) -> Result<EngineExtractionOutcome> {
  let context = DiscoveryContext::system()?;
  internet_explorer_report_with_context(
    &context,
    browser_id,
    domains.as_deref(),
    |path, domains| {
      super::internet_explorer::internet_explorer_outcome(
        path.to_path_buf(),
        domains.map(<[String]>::to_vec),
        false,
      )
      .map(|extraction| InternetExplorerRows {
        cookies: extraction.cookies,
        records_seen: extraction.stats.records_seen,
        records_skipped: extraction.stats.records_skipped,
      })
    },
  )
}

/// Context-injected engine seams for the cross-engine report tests. They keep
/// fixtures on temporary roots instead of mutating the process environment.
#[cfg(test)]
pub(crate) mod test_seams {
  use super::*;

  pub(crate) fn context(platform: PlatformId, home: PathBuf) -> DiscoveryContext<RealDiscoveryFs> {
    let mut env = BTreeMap::new();
    if platform == PlatformId::Windows {
      env.insert(
        OsString::from("LOCALAPPDATA"),
        home.join("LocalAppData").into_os_string(),
      );
      env.insert(
        OsString::from("APPDATA"),
        home.join("AppData").into_os_string(),
      );
    }
    DiscoveryContext {
      platform,
      home,
      env,
      fs: RealDiscoveryFs,
    }
  }

  pub(crate) fn current_context(home: PathBuf) -> DiscoveryContext<RealDiscoveryFs> {
    context(
      PlatformId::current().expect("supported test platform"),
      home,
    )
  }

  pub(crate) fn root_path(
    context: &DiscoveryContext<RealDiscoveryFs>,
    browser_id: &str,
    root_id: &str,
  ) -> PathBuf {
    let registry = embedded_registry().expect("registry");
    let definition =
      browser_definition(registry, context.platform, browser_id).expect("registered browser");
    let root = definition
      .roots
      .iter()
      .find(|root| root.root_id == root_id)
      .expect("registry root");
    let resolved = context
      .resolve_template(&root.template)
      .expect("resolved root");
    resolved.base.join(resolved.suffix)
  }

  /// Resolves the highest-priority installation root for a browser on the
  /// running platform, so a fixture does not have to name a platform-specific
  /// root id.
  /// Every installation root a browser can resolve on the running platform, in
  /// registry order, so a fixture does not have to name platform-specific root
  /// ids.
  pub(crate) fn resolvable_root_paths(
    context: &DiscoveryContext<RealDiscoveryFs>,
    browser_id: &str,
  ) -> Vec<PathBuf> {
    let registry = embedded_registry().expect("registry");
    let definition =
      browser_definition(registry, context.platform, browser_id).expect("registered browser");
    let mut roots: Vec<&InstallationRoot> = definition.roots.iter().collect();
    roots.sort_by_key(|root| (root.priority, root.root_id.as_str()));
    roots
      .iter()
      .filter_map(|root| context.resolve_template(&root.template))
      .map(|resolved| resolved.base.join(resolved.suffix))
      .collect()
  }

  pub(crate) fn primary_root_path(
    context: &DiscoveryContext<RealDiscoveryFs>,
    browser_id: &str,
  ) -> PathBuf {
    resolvable_root_paths(context, browser_id)
      .into_iter()
      .next()
      .expect("a resolvable installation root")
  }

  /// Seeds a Gecko profile with an empty but well-formed cookie database.
  pub(crate) fn seed_gecko_profile(profile: &Path) {
    std::fs::create_dir_all(profile).expect("create Gecko profile");
    let connection =
      rusqlite::Connection::open(profile.join("cookies.sqlite")).expect("open Gecko database");
    connection
      .execute_batch(
        "CREATE TABLE moz_cookies (
          host TEXT, path TEXT, isSecure INTEGER, expiry INTEGER,
          name TEXT, value TEXT, isHttpOnly INTEGER, sameSite INTEGER
        );",
      )
      .expect("create Gecko cookie table");
  }

  /// Seeds a Chromium installation root with a `Local State` and one profile
  /// holding a single plaintext cookie.
  pub(crate) fn seed_chromium_profile(root: &Path, directory: &str, name: &str) {
    std::fs::create_dir_all(root).expect("create installation root");
    std::fs::write(
      root.join("Local State"),
      serde_json::to_vec(&serde_json::json!({
        "profile": { "info_cache": { directory: { "name": name } } }
      }))
      .expect("serialize Local State"),
    )
    .expect("write Local State");
    let database = root.join(directory).join("Cookies");
    std::fs::create_dir_all(database.parent().expect("profile directory"))
      .expect("create profile directory");
    let connection = rusqlite::Connection::open(&database).expect("open cookie database");
    connection
      .execute_batch(
        "CREATE TABLE cookies (
          host_key TEXT NOT NULL, path TEXT NOT NULL, is_secure INTEGER NOT NULL,
          expires_utc INTEGER NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
          encrypted_value BLOB NOT NULL, is_httponly INTEGER NOT NULL,
          samesite INTEGER NOT NULL
        );",
      )
      .expect("create cookies table");
    connection
      .execute(
        "INSERT INTO cookies VALUES ('.example.com', '/', 0, 0, 'seeded', 'value', ?1, 0, 0)",
        [Vec::<u8>::new()],
      )
      .expect("insert cookie");
  }

  pub(crate) fn chromium_report(
    context: &DiscoveryContext<RealDiscoveryFs>,
    browser_id: &str,
    profile_id: Option<&str>,
    domains: Option<Vec<String>>,
    keys: ChromiumKeyOutcomes,
  ) -> Result<ChromiumRegistryReport> {
    struct FixedKeys(ChromiumKeyOutcomes);
    impl ChromiumKeyProvider<BrowserInstallation> for FixedKeys {
      fn retrieve(&self, _installation: &BrowserInstallation) -> ChromiumKeyOutcomes {
        self.0.clone()
      }
    }
    extract_chromium_with_provider(context, browser_id, profile_id, domains, &FixedKeys(keys))
  }

  pub(crate) fn chromium_profiles(
    context: &DiscoveryContext<RealDiscoveryFs>,
    browser_id: &str,
  ) -> Result<Vec<ChromiumProfile>> {
    profiles_for_listing(
      browser_id,
      discover_browser_with_context(context, browser_id)?,
    )
  }

  pub(crate) fn gecko_report(
    context: &DiscoveryContext<RealDiscoveryFs>,
    browser_id: &str,
    domains: Option<&[String]>,
  ) -> Result<EngineExtractionOutcome> {
    gecko_report_with_context(context, browser_id, domains)
  }

  pub(crate) fn gecko_profiles(
    context: &DiscoveryContext<RealDiscoveryFs>,
    browser_id: &str,
  ) -> Result<EngineExtractionOutcome> {
    gecko_profiles_with_context(context, browser_id)
  }

  pub(crate) fn safari_report(
    context: &DiscoveryContext<RealDiscoveryFs>,
    browser_id: &str,
    domains: Option<&[String]>,
  ) -> Result<EngineExtractionOutcome> {
    safari_report_with_context(context, browser_id, domains)
  }

  pub(crate) fn internet_explorer_report<Q>(
    context: &DiscoveryContext<RealDiscoveryFs>,
    browser_id: &str,
    domains: Option<&[String]>,
    query: Q,
  ) -> Result<EngineExtractionOutcome>
  where
    Q: FnMut(&Path, Option<&[String]>) -> Result<InternetExplorerRows>,
  {
    internet_explorer_report_with_context(context, browser_id, domains, query)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use rusqlite::params;
  use std::cell::RefCell;
  use std::sync::atomic::{AtomicU64, Ordering};

  struct TempDir(PathBuf);

  impl TempDir {
    fn new(tag: &str) -> Self {
      static COUNTER: AtomicU64 = AtomicU64::new(0);
      let count = COUNTER.fetch_add(1, Ordering::SeqCst);
      let path = std::env::temp_dir().join(format!(
        "rookie-registry-{tag}-{}-{count}",
        std::process::id()
      ));
      std::fs::create_dir_all(&path).expect("create temporary directory");
      Self(path)
    }

    fn path(&self) -> &Path {
      &self.0
    }
  }

  impl Drop for TempDir {
    fn drop(&mut self) {
      let _ = std::fs::remove_dir_all(&self.0);
    }
  }

  fn test_context(home: PathBuf) -> DiscoveryContext<RealDiscoveryFs> {
    let platform = PlatformId::current().expect("supported test platform");
    let mut env = BTreeMap::new();
    if platform == PlatformId::Windows {
      env.insert(
        OsString::from("LOCALAPPDATA"),
        home.join("LocalAppData").into_os_string(),
      );
      env.insert(
        OsString::from("APPDATA"),
        home.join("AppData").into_os_string(),
      );
    }
    DiscoveryContext {
      platform,
      home,
      env,
      fs: RealDiscoveryFs,
    }
  }

  fn test_context_for(
    platform: PlatformId,
    home: PathBuf,
    env: impl IntoIterator<Item = (&'static str, PathBuf)>,
  ) -> DiscoveryContext<RealDiscoveryFs> {
    DiscoveryContext {
      platform,
      home,
      env: env
        .into_iter()
        .map(|(name, value)| (OsString::from(name), value.into_os_string()))
        .collect(),
      fs: RealDiscoveryFs,
    }
  }

  fn channel_root(context: &DiscoveryContext<RealDiscoveryFs>, channel: &str) -> PathBuf {
    let registry = embedded_registry().expect("registry");
    let definition = browser_definition(registry, context.platform, "chrome").expect("chrome");
    let root = definition
      .roots
      .iter()
      .find(|root| root.channel == channel)
      .expect("channel root");
    let root = context.resolve_template(&root.template).expect("root path");
    root.base.join(root.suffix)
  }

  fn browser_root(
    context: &DiscoveryContext<RealDiscoveryFs>,
    browser_id: &str,
    root_id: &str,
  ) -> PathBuf {
    let registry = embedded_registry().expect("registry");
    let definition =
      browser_definition(registry, context.platform, browser_id).expect("browser definition");
    let root = definition
      .roots
      .iter()
      .find(|root| root.root_id == root_id)
      .expect("root definition");
    let root = context.resolve_template(&root.template).expect("root path");
    root.base.join(root.suffix)
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
    let ie = browser_definition(registry, PlatformId::Windows, "internet_explorer")
      .expect("IE definition");
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
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn registry_credentials_map_onto_the_platform_provider_input() {
    // The parity test proves the registry *data* matches config.json; this
    // proves the code that reads it maps the right field onto the right
    // provider input. A swapped service/account or a wrong platform branch
    // would satisfy parity and still break retrieval.
    let chrome = registry_key_credentials("chrome").expect("Chrome credentials");

    #[cfg(target_os = "linux")]
    {
      assert_eq!(chrome.unix_crypt_name.as_deref(), Some("chrome"));
      // Linux definitions carry no Keychain credentials, so mapping the macOS
      // branch here would be a silent cross-platform leak.
      assert_eq!(chrome.osx_key_service, None);
      assert_eq!(chrome.osx_key_user, None);
    }

    #[cfg(target_os = "macos")]
    {
      // Distinct values, so transposing service and account fails here.
      assert_eq!(
        chrome.osx_key_service.as_deref(),
        Some("Chrome Safe Storage")
      );
      assert_eq!(chrome.osx_key_user.as_deref(), Some("Chrome"));
      assert_eq!(chrome.unix_crypt_name, None);
    }

    // An unknown browser is an error rather than silently credential-less.
    assert!(registry_key_credentials("definitely-not-a-browser").is_err());

    // A definition only carries its own platform's subfields, so drive the
    // mapping directly with both halves present. Service and account are
    // deliberately distinct, so transposing them fails here on every platform
    // rather than only on the macOS job.
    let both = KeyCredentials {
      macos_keychain: Some(MacosKeychainCredential {
        service: "Probe Safe Storage".to_owned(),
        account: "Probe Account".to_owned(),
      }),
      linux_crypt_name: Some("probe-crypt".to_owned()),
    };
    let mapped = provider_input(Some(&both));
    assert_eq!(
      mapped.osx_key_service.as_deref(),
      Some("Probe Safe Storage")
    );
    assert_eq!(mapped.osx_key_user.as_deref(), Some("Probe Account"));
    assert_eq!(mapped.unix_crypt_name.as_deref(), Some("probe-crypt"));

    // No credentials maps to no credentials, never to a blank lookup.
    let empty = provider_input(None);
    assert_eq!(empty.osx_key_service, None);
    assert_eq!(empty.osx_key_user, None);
    assert_eq!(empty.unix_crypt_name, None);
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn generic_resolution_matches_legacy_resolution_for_shared_browsers() {
    // The product guarantee, stated as a relation rather than as snapshot
    // values: for a browser present in both files, the generic pipeline must
    // resolve exactly what the legacy path resolves. A future credential
    // change lands in both files and this still holds, where an assertion on
    // literal values would have to be rewritten.
    let platform = PlatformId::current().expect("platform");
    let registry = embedded_registry().expect("registry");
    let mut compared = 0;
    for definition in registry
      .platforms
      .get(platform.as_str())
      .expect("platform definitions")
    {
      let Some(legacy) = crate::config::try_get_browser_config(&definition.canonical_id) else {
        continue;
      };
      let generic =
        registry_key_credentials(&definition.canonical_id).expect("registry credentials");
      assert_eq!(
        generic.osx_key_service, legacy.osx_key_service,
        "{} keychain service",
        definition.canonical_id
      );
      assert_eq!(
        generic.osx_key_user, legacy.osx_key_user,
        "{} keychain account",
        definition.canonical_id
      );
      assert_eq!(
        generic.unix_crypt_name, legacy.unix_crypt_name,
        "{} crypt name",
        definition.canonical_id
      );
      compared += 1;
    }
    assert!(compared > 0, "no shared browsers were compared");
  }

  #[test]
  fn key_credentials_match_legacy_config_for_browsers_in_both_files() {
    let registry = embedded_registry().expect("registry");
    let mut compared = 0;
    for (platform, definitions) in &registry.platforms {
      for definition in definitions {
        let Some(legacy) = crate::config::CONFIG
          .platforms
          .get(platform)
          .and_then(|browsers| browsers.get(&definition.canonical_id))
        else {
          // Registry-only browsers have no parity obligation; the registry is
          // their only source of truth.
          continue;
        };
        let credentials = definition.key_credentials.as_ref();
        let keychain = credentials.and_then(|credentials| credentials.macos_keychain.as_ref());
        let crypt_name =
          credentials.and_then(|credentials| credentials.linux_crypt_name.as_deref());
        match platform.as_str() {
          "macos" => {
            assert_eq!(
              keychain.map(|keychain| keychain.service.as_str()),
              legacy.osx_key_service.as_deref(),
              "{}/{} keychain service",
              platform,
              definition.canonical_id
            );
            assert_eq!(
              keychain.map(|keychain| keychain.account.as_str()),
              legacy.osx_key_user.as_deref(),
              "{}/{} keychain account",
              platform,
              definition.canonical_id
            );
            compared += 1;
          }
          "linux" => {
            assert_eq!(
              crypt_name,
              legacy.unix_crypt_name.as_deref(),
              "{}/{} crypt name",
              platform,
              definition.canonical_id
            );
            compared += 1;
          }
          // Windows key material comes from the installation's own Local State,
          // so its definitions carry no credentials to compare.
          _ => assert!(credentials.is_none()),
        }
      }
    }
    assert!(compared > 0, "no shared browsers were compared");
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

  fn gecko_test_root(context: &DiscoveryContext<RealDiscoveryFs>) -> PathBuf {
    let registry = embedded_registry().expect("registry");
    let definition = browser_definition(registry, context.platform, "firefox").expect("Firefox");
    let root = definition
      .roots
      .iter()
      .find(|root| root.root_id.contains("native") || root.root_id == "firefox")
      .unwrap_or(&definition.roots[0]);
    let resolved = context.resolve_template(&root.template).expect("root path");
    resolved.base.join(resolved.suffix)
  }

  fn seed_empty_gecko_database(profile: &Path) {
    std::fs::create_dir_all(profile).expect("create Gecko profile");
    let connection =
      rusqlite::Connection::open(profile.join("cookies.sqlite")).expect("open Gecko database");
    connection
      .execute_batch(
        "CREATE TABLE moz_cookies (
          host TEXT, path TEXT, isSecure INTEGER, expiry INTEGER,
          name TEXT, value TEXT, isHttpOnly INTEGER, sameSite INTEGER
        );",
      )
      .expect("create Gecko cookie table");
  }

  #[test]
  fn gecko_profiles_are_default_first_then_name_and_path() {
    let temp = TempDir::new("gecko-order");
    let context = test_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    for directory in ["z-default", "b-secondary", "a-secondary"] {
      seed_empty_gecko_database(&root.join("Profiles").join(directory));
    }
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=Zulu\nPath=Profiles/z-default\nDefault=1\n\
       [Profile1]\nName=beta\nPath=Profiles/b-secondary\n\
       [Profile2]\nName=Alpha\nPath=Profiles/a-secondary\n",
    )
    .expect("write profiles.ini");

    let report = discover_gecko_with_context(&context, "firefox").expect("discover profiles");
    assert_eq!(
      report
        .profiles
        .iter()
        .map(|profile| profile.name.as_str())
        .collect::<Vec<_>>(),
      ["Zulu", "Alpha", "beta"]
    );
    assert!(report.profiles[0].is_default);
  }

  #[test]
  fn linux_gecko_profiles_preserve_snap_native_flatpak_installation_priority() {
    let temp = TempDir::new("gecko-installation-order");
    let context = test_context_for(PlatformId::Linux, temp.path().to_path_buf(), []);
    let registry = embedded_registry().expect("registry");
    let definition = browser_definition(registry, PlatformId::Linux, "firefox").expect("Firefox");
    let names = [
      ("firefox-snap", "Zulu"),
      ("firefox-native", "Alpha"),
      ("firefox-flatpak", "Beta"),
    ];
    let mut expected = Vec::new();
    for (root_id, name) in names {
      let root = definition
        .roots
        .iter()
        .find(|root| root.root_id == root_id)
        .expect("Firefox registry root");
      let resolved = context.resolve_template(&root.template).expect("root path");
      let root_path = resolved.base.join(resolved.suffix);
      seed_empty_gecko_database(&root_path.join("Profiles/profile"));
      std::fs::write(
        root_path.join("profiles.ini"),
        format!("[Profile0]\nName={name}\nPath=Profiles/profile\nDefault=1\n"),
      )
      .expect("write profiles.ini");
      expected.push((root.priority, name));
    }

    let report = discover_gecko_with_context(&context, "firefox").expect("discover Firefox");
    assert_eq!(
      report
        .profiles
        .iter()
        .map(|profile| (profile.installation_priority, profile.name.as_str()))
        .collect::<Vec<_>>(),
      expected
    );
  }

  #[test]
  fn gecko_unusable_declarations_fall_back_to_flat_or_markerless_sources() {
    let temp = TempDir::new("gecko-fallbacks");
    let context = test_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    std::fs::create_dir_all(root.join("Profiles/stale")).expect("create stale declaration");
    seed_empty_gecko_database(&root);
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=stale\nPath=Profiles/stale\nDefault=1\n",
    )
    .expect("write profiles.ini");

    let flat = discover_gecko_with_context(&context, "firefox").expect("discover flat fallback");
    assert_eq!(flat.profiles.len(), 1);
    assert_eq!(flat.profiles[0].path, root.canonicalize().unwrap());
    assert!(
      !flat.profiles[0].is_default,
      "a stale declaration cannot transfer its default flag"
    );
    assert!(flat
      .discovery_issues
      .iter()
      .any(|issue| issue.code == "profile_has_no_cookie_source"));

    std::fs::remove_file(root.join("cookies.sqlite")).expect("remove flat source");
    seed_empty_gecko_database(&root.join("Profiles/Restored One"));
    seed_empty_gecko_database(&root.join("Restored Two"));
    let markerless =
      discover_gecko_with_context(&context, "firefox").expect("discover markerless fallbacks");
    assert_eq!(
      markerless
        .profiles
        .iter()
        .map(|profile| profile.name.as_str())
        .collect::<Vec<_>>(),
      ["Restored One", "Restored Two"]
    );
    assert!(markerless
      .profiles
      .iter()
      .all(|profile| !profile.is_default));
  }

  #[test]
  fn invalid_profiles_ini_does_not_mark_flat_fallback_default() {
    let temp = TempDir::new("gecko-invalid-ini-flat");
    let context = test_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    seed_empty_gecko_database(&root);
    std::fs::write(root.join("profiles.ini"), "[Profile0\nPath=broken").expect("write invalid ini");

    let report = discover_gecko_with_context(&context, "firefox").expect("discover flat fallback");
    assert_eq!(report.profiles.len(), 1);
    assert!(!report.profiles[0].is_default);
    assert!(report
      .discovery_issues
      .iter()
      .any(|issue| issue.code == "mozilla_profiles_ini_invalid"));
  }

  #[test]
  fn duplicate_gecko_profile_issues_are_emitted_and_bounded() {
    let temp = TempDir::new("gecko-duplicate-bound");
    let context = test_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    seed_empty_gecko_database(&root.join("Profiles/shared"));
    let ini = (0..MAX_DISCOVERY_ISSUE_SAMPLES + 5)
      .map(|index| format!("[Profile{index}]\nName=duplicate-{index}\nPath=Profiles/shared\n"))
      .collect::<String>();
    std::fs::write(root.join("profiles.ini"), ini).expect("write duplicate declarations");

    let report = discover_gecko_with_context(&context, "firefox").expect("discover duplicates");
    assert_eq!(report.profiles.len(), 1);
    let duplicates = report
      .discovery_issues
      .iter()
      .filter(|issue| issue.code == "duplicate_profile")
      .collect::<Vec<_>>();
    // One declaration owns the profile; every later one is a bounded duplicate,
    // and the unsampled remainder survives as a typed count rather than a
    // number formatted into the message.
    assert_eq!(duplicates.len(), MAX_DISCOVERY_ISSUE_SAMPLES);
    assert_eq!(
      duplicates
        .iter()
        .map(|issue| issue.occurrences)
        .sum::<u32>(),
      MAX_DISCOVERY_ISSUE_SAMPLES as u32 + 4
    );
    assert!(duplicates
      .iter()
      .all(|issue| !issue.message.contains("additional")));
  }

  #[test]
  fn missing_source_gecko_issues_are_bounded_with_a_typed_occurrence_count() {
    let temp = TempDir::new("gecko-missing-source-bound");
    let context = test_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    std::fs::create_dir_all(&root).expect("create Firefox root");
    let ini = (0..MAX_DISCOVERY_ISSUE_SAMPLES + 5)
      .map(|index| format!("[Profile{index}]\nName=stale-{index}\nPath=Profiles/stale-{index}\n"))
      .collect::<String>();
    std::fs::write(root.join("profiles.ini"), ini).expect("write stale declarations");

    let report = discover_gecko_with_context(&context, "firefox").expect("discover stale profiles");
    let issues = report
      .discovery_issues
      .iter()
      .filter(|issue| issue.code == "profile_has_no_cookie_source")
      .collect::<Vec<_>>();
    assert_eq!(issues.len(), MAX_DISCOVERY_ISSUE_SAMPLES);
    assert_eq!(
      issues.iter().map(|issue| issue.occurrences).sum::<u32>(),
      MAX_DISCOVERY_ISSUE_SAMPLES as u32 + 5
    );
    // Sampled paths keep one occurrence each; only the first carries the
    // remainder, so no sample misrepresents its own path.
    assert_eq!(issues[0].occurrences, 6);
    assert!(issues[1..].iter().all(|issue| issue.occurrences == 1));
  }

  #[test]
  fn markerless_fallback_keeps_direct_profiles_when_profiles_container_is_unreadable() {
    let temp = TempDir::new("gecko-markerless-partial-enumeration");
    let real_context = test_context(temp.path().to_path_buf());
    let root = gecko_test_root(&real_context);
    seed_empty_gecko_database(&root.join("Restored Direct"));
    std::fs::create_dir_all(root.join("Profiles")).expect("create Profiles container");
    let profiles_container = root
      .canonicalize()
      .expect("canonical installation root")
      .join("Profiles");
    let context = with_test_fs(
      real_context,
      TestDiscoveryFs {
        denied_read_dir: Some(profiles_container.clone()),
        ..TestDiscoveryFs::default()
      },
    );

    let report = discover_gecko_with_context(&context, "firefox").expect("partial discovery");
    assert_eq!(report.profiles.len(), 1);
    assert_eq!(report.profiles[0].name, "Restored Direct");
    assert!(report.discovery_issues.iter().any(|issue| {
      issue.code == "optional_profiles_enumeration_failed" && issue.path == profiles_container
    }));
  }

  #[test]
  fn gecko_root_whose_enumeration_fails_is_a_failure_not_an_empty_installation() {
    let temp = TempDir::new("gecko-total-enumeration-failure");
    let real_context = test_context(temp.path().to_path_buf());
    let root = gecko_test_root(&real_context);
    std::fs::create_dir_all(&root).expect("create Firefox root");
    let canonical_root = root.canonicalize().expect("canonical installation root");
    let context = with_test_fs(
      real_context,
      TestDiscoveryFs {
        denied_read_dir: Some(canonical_root.clone()),
        ..TestDiscoveryFs::default()
      },
    );

    let report = discover_gecko_with_context(&context, "firefox").expect("discovery completes");
    assert!(report.profiles.is_empty());
    assert!(report
      .discovery_issues
      .iter()
      .any(|issue| issue.code == "installation_enumeration_failed"));
    // Without this the caller cannot tell "Firefox is not installed" from
    // "Firefox is installed and we could not read it".
    assert!(report.all_detected_roots_failed());
  }

  #[test]
  fn gecko_root_that_enumerates_nothing_is_not_a_discovery_failure() {
    let temp = TempDir::new("gecko-empty-root");
    let context = test_context(temp.path().to_path_buf());
    std::fs::create_dir_all(gecko_test_root(&context)).expect("create Firefox root");

    let report = discover_gecko_with_context(&context, "firefox").expect("discovery completes");
    assert!(report.profiles.is_empty());
    assert!(!report.all_detected_roots_failed());
  }

  #[cfg(unix)]
  #[test]
  fn gecko_roots_resolving_to_one_directory_report_a_single_duplicate_installation() {
    let temp = TempDir::new("gecko-duplicate-installation");
    let context = test_context_for(PlatformId::Linux, temp.path().to_path_buf(), []);
    let registry = embedded_registry().expect("registry");
    let definition = browser_definition(registry, PlatformId::Linux, "firefox").expect("Firefox");
    let root_path = |root_id: &str| {
      let root = definition
        .roots
        .iter()
        .find(|root| root.root_id == root_id)
        .expect("Firefox registry root");
      let resolved = context.resolve_template(&root.template).expect("root path");
      resolved.base.join(resolved.suffix)
    };

    let native = root_path("firefox-native");
    seed_empty_gecko_database(&native.join("Profiles/profile"));
    std::fs::write(
      native.join("profiles.ini"),
      "[Profile0]\nName=Shared\nPath=Profiles/profile\nDefault=1\n",
    )
    .expect("write profiles.ini");
    let snap = root_path("firefox-snap");
    std::fs::create_dir_all(snap.parent().expect("snap parent")).expect("create snap parent");
    std::os::unix::fs::symlink(&native, &snap).expect("alias the snap root onto the native one");

    let report = discover_gecko_with_context(&context, "firefox").expect("discover Firefox");
    assert_eq!(report.profiles.len(), 1);
    assert_eq!(report.installations_discovered, 1);
    // The aliased root is one clear signal, not a second installation whose
    // every profile then looks like a duplicate.
    assert_eq!(
      report
        .discovery_issues
        .iter()
        .filter(|issue| issue.code == "duplicate_installation")
        .count(),
      1
    );
    assert!(!report
      .discovery_issues
      .iter()
      .any(|issue| issue.code == "duplicate_profile"));
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
    // rookie holds Google Chrome's app-bound elevation keys and no other
    // vendor's, so v20 stays a Chrome-only declaration. Other Chromium
    // browsers do write `app_bound_encrypted_key`; restating declarations as
    // browser-truth means teaching `capability_descriptor` a per-browser key
    // axis first, or `available_decryption_tiers` will overclaim.
    for definitions in registry.platforms.values() {
      for definition in definitions {
        if definition
          .capabilities
          .declared_decryption_tiers
          .iter()
          .any(|tier| tier == "v20")
        {
          assert_eq!(definition.canonical_id, "chrome");
        }
      }
    }
  }

  #[test]
  fn undiscovered_persistent_source_is_projected_if_it_appears_before_query() {
    let temp = TempDir::new("gecko-persistent-appears");
    let context = test_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    let profile = root.join("Profiles/default");
    // A session-only profile at discovery time: no cookies.sqlite yet.
    std::fs::create_dir_all(profile.join("sessionstore-backups")).expect("create profile");
    std::fs::write(profile.join("sessionstore.js"), "{}").expect("seed session candidate");
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=default\nPath=Profiles/default\nDefault=1\n",
    )
    .expect("write profiles.ini");
    let discovery = discover_gecko_with_context(&context, "firefox").expect("discover profile");
    assert!(!discovery.profiles[0].persistent_source_discovered);

    let mut created = false;
    let report = populate_gecko_sources(
      discovery,
      None,
      |persistent, domains| {
        if !created {
          created = true;
          seed_empty_gecko_database(persistent.parent().expect("profile directory"));
        }
        mozilla::query_cookies_engine_outcome(persistent, domains)
      },
      |path| path.exists(),
    );
    let persistent = report.profiles[0]
      .sources
      .iter()
      .find(|source| source.role == SOURCE_ROLE_PERSISTENT)
      .expect("persistent source created between discovery and query");
    assert_eq!(persistent.format, "mozilla_sqlite");
    assert!(persistent.selected);
    assert!(persistent.error.is_none());
  }

  #[test]
  fn a_corrupt_database_appearing_before_query_is_reported_not_silently_dropped() {
    let temp = TempDir::new("gecko-persistent-appears-corrupt");
    let context = test_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    let profile = root.join("Profiles/default");
    std::fs::create_dir_all(&profile).expect("create profile");
    std::fs::write(profile.join("sessionstore.js"), "{}").expect("seed session candidate");
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=default\nPath=Profiles/default\nDefault=1\n",
    )
    .expect("write profiles.ini");
    let discovery = discover_gecko_with_context(&context, "firefox").expect("discover profile");
    assert!(!discovery.profiles[0].persistent_source_discovered);

    // Appears between discovery and query, but unreadable. Inferring existence
    // from query success alone would drop this failure entirely.
    let mut created = false;
    let report = populate_gecko_sources(
      discovery,
      None,
      |persistent, domains| {
        if !created {
          created = true;
          std::fs::write(persistent, b"not a sqlite database").expect("seed corrupt database");
        }
        mozilla::query_cookies_engine_outcome(persistent, domains)
      },
      |path| path.exists(),
    );
    let persistent = report.profiles[0]
      .sources
      .iter()
      .find(|source| source.role == SOURCE_ROLE_PERSISTENT)
      .expect("corrupt persistent source is still reported");
    assert!(persistent.selected);
    assert!(persistent.error.is_some());
  }

  #[test]
  fn session_only_profile_still_projects_no_persistent_source() {
    let temp = TempDir::new("gecko-session-only-no-persistent");
    let context = test_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    let profile = root.join("Profiles/default");
    std::fs::create_dir_all(&profile).expect("create profile");
    std::fs::write(profile.join("sessionstore.js"), "{}").expect("seed session candidate");
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=default\nPath=Profiles/default\nDefault=1\n",
    )
    .expect("write profiles.ini");

    let discovery = discover_gecko_with_context(&context, "firefox").expect("discover profile");
    let report = populate_gecko_sources(
      discovery,
      None,
      mozilla::query_cookies_engine_outcome,
      |path| path.exists(),
    );
    assert!(!report.profiles[0]
      .sources
      .iter()
      .any(|source| source.role == SOURCE_ROLE_PERSISTENT));
  }

  #[test]
  fn discovered_persistent_source_remains_projected_if_it_disappears_before_query() {
    let temp = TempDir::new("gecko-persistent-disappears");
    let context = test_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    let profile = root.join("Profiles/default");
    seed_empty_gecko_database(&profile);
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=default\nPath=Profiles/default\nDefault=1\n",
    )
    .expect("write profiles.ini");
    let discovery = discover_gecko_with_context(&context, "firefox").expect("discover profile");
    assert!(discovery.profiles[0].persistent_source_discovered);

    let mut removed = false;
    let report = populate_gecko_sources(
      discovery,
      None,
      |persistent, domains| {
        if !removed {
          removed = true;
          std::fs::remove_file(persistent).expect("remove discovered source");
        }
        mozilla::query_cookies_engine_outcome(persistent, domains)
      },
      |path| path.exists(),
    );
    assert_eq!(report.profiles[0].sources.len(), 1);
    let source = &report.profiles[0].sources[0];
    assert_eq!(source.format, "mozilla_sqlite");
    assert!(source.selected);
    assert!(source
      .error
      .as_deref()
      .is_some_and(|error| error.contains("Can't resolve database path")));
  }

  #[test]
  fn generic_gecko_discovery_includes_session_only_profiles() {
    let temp = TempDir::new("gecko-session-only");
    let platform = PlatformId::current().expect("platform");
    let context = test_context(temp.path().to_path_buf());
    let registry = embedded_registry().expect("registry");
    let definition = browser_definition(registry, platform, "firefox").expect("Firefox");
    let root = definition
      .roots
      .iter()
      .find(|root| root.root_id.contains("native") || root.root_id == "firefox")
      .unwrap_or(&definition.roots[0]);
    let resolved = context.resolve_template(&root.template).expect("root path");
    let root_path = resolved.base.join(resolved.suffix);
    let profile = root_path.join("Profiles/session-only");
    std::fs::create_dir_all(profile.join("sessionstore-backups")).expect("create profile");
    std::fs::write(
      root_path.join("profiles.ini"),
      "[Profile0]\nName=session\nIsRelative=1\nPath=Profiles/session-only\nDefault=1\n",
    )
    .expect("write profiles.ini");
    std::fs::write(
      profile.join("sessionstore-backups/recovery.jsonlz4"),
      b"invalid is still a discoverable source",
    )
    .expect("write session candidate");

    let report = discover_gecko_with_context(&context, "firefox").expect("discover Gecko");
    assert_eq!(report.profiles.len(), 1);
    assert_eq!(
      report.profiles[0].path,
      profile.canonicalize().expect("canonical profile")
    );
    assert!(report.profiles[0].is_default);
  }

  #[test]
  fn generic_gecko_report_preserves_persistent_and_session_source_outcomes() {
    let temp = TempDir::new("gecko-report-sources");
    let platform = PlatformId::current().expect("platform");
    let context = test_context(temp.path().to_path_buf());
    let registry = embedded_registry().expect("registry");
    let definition = browser_definition(registry, platform, "firefox").expect("Firefox");
    let root = definition
      .roots
      .iter()
      .find(|root| root.root_id.contains("native") || root.root_id == "firefox")
      .unwrap_or(&definition.roots[0]);
    let resolved = context.resolve_template(&root.template).expect("root path");
    let root_path = resolved.base.join(resolved.suffix);
    let profile = root_path.join("Profiles/default");
    std::fs::create_dir_all(profile.join("sessionstore-backups")).expect("create profile");
    std::fs::write(
      root_path.join("profiles.ini"),
      "[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/default\nDefault=1\n",
    )
    .expect("write profiles.ini");
    let db_path = profile.join("cookies.sqlite");
    let connection = rusqlite::Connection::open(&db_path).expect("open fixture database");
    connection
      .execute_batch(
        "CREATE TABLE moz_cookies (
           host TEXT, path TEXT, isSecure INTEGER, expiry INTEGER,
           name TEXT, value TEXT, isHttpOnly INTEGER, sameSite INTEGER
         );
         INSERT INTO moz_cookies VALUES ('.z.example.com', '/', 1, 0, 'persistent-z', 'value', 1, 0);
         INSERT INTO moz_cookies VALUES ('.a.example.com', '/', 1, 0, 'persistent-a', 'value', 1, 0);",
      )
      .expect("seed fixture database");
    drop(connection);
    std::fs::write(
      profile.join("sessionstore-backups/recovery.jsonlz4"),
      b"invalid session store",
    )
    .expect("write invalid session candidate");
    std::fs::write(
      profile.join("sessionstore.js"),
      r#"{"windows":[{"cookies":[{"host":".z.example.com","path":"/","name":"session-z","value":"value"},{"host":".a.example.com","path":"/","name":"session-a","value":"value"},{"host":".example.com","path":"/","name":"missing-value"}]}]}"#,
    )
    .expect("write valid session candidate");

    let report = gecko_report_with_context(&context, "firefox", None).expect("report");
    assert!(report.discovery_issues.is_empty());
    assert_eq!(report.profiles.len(), 1);
    let sources = &report.profiles[0].sources;
    assert_eq!(sources.len(), 3);
    assert_eq!(sources[0].format, "mozilla_sqlite");
    assert_eq!(sources[0].rows_seen, 2);
    assert_eq!(
      sources[0].acquisition,
      SourceAcquisition::Database(DatabaseAcquisitionStrategy::LiveReadOnly)
    );
    assert_eq!(sources[0].acquisition_attempts, 1);
    assert_eq!(sources[0].cookies[0].name, "persistent-a");
    assert_eq!(sources[0].cookies[1].name, "persistent-z");
    assert_eq!(sources[1].format, "firefox_session_jsonlz4");
    assert!(!sources[1].selected);
    assert!(sources[1].error.is_some());
    assert_eq!(sources[2].format, "firefox_session_json");
    assert!(sources[2].selected);
    assert_eq!(sources[2].rows_seen, 3);
    assert_eq!(sources[2].rows_skipped, 1);
    assert_eq!(sources[2].diagnostics.len(), 1);
    assert_eq!(sources[2].cookies[0].name, "session-a");
    assert_eq!(sources[2].cookies[1].name, "session-z");
  }

  #[test]
  fn gecko_emitted_source_formats_are_declared_by_every_gecko_definition() {
    let registry = embedded_registry().expect("registry");
    let mut checked = 0;
    for platform in [PlatformId::Windows, PlatformId::Macos, PlatformId::Linux] {
      let definitions = registry
        .platforms
        .get(platform.as_str())
        .expect("platform definitions");
      for definition in definitions
        .iter()
        .filter(|definition| definition.engine == BrowserEngine::Gecko)
      {
        checked += 1;
        assert!(
          definition
            .capabilities
            .declared_persistent_formats
            .iter()
            .any(|format| format == mozilla::PERSISTENT_FORMAT_ID),
          "{} on {} does not declare {}",
          definition.canonical_id,
          platform.as_str(),
          mozilla::PERSISTENT_FORMAT_ID
        );
        for emitted in [
          mozilla::SESSION_JSONLZ4_FORMAT_ID,
          mozilla::SESSION_JSON_FORMAT_ID,
        ] {
          assert!(
            definition
              .capabilities
              .declared_session_formats
              .iter()
              .any(|format| format == emitted),
            "{} on {} does not declare {emitted}",
            definition.canonical_id,
            platform.as_str()
          );
        }
      }
    }
    assert!(checked > 0, "no Gecko definitions were checked");
  }

  #[test]
  fn persistent_source_created_between_discovery_and_query_is_still_projected() {
    let temp = TempDir::new("gecko-persistent-appears");
    let context = test_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    let profile = root.join("Profiles/session-only");
    std::fs::create_dir_all(profile.join("sessionstore-backups")).expect("create profile");
    std::fs::write(
      profile.join("sessionstore-backups/recovery.jsonlz4"),
      b"invalid is still a discoverable source",
    )
    .expect("write session candidate");
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=session\nPath=Profiles/session-only\nDefault=1\n",
    )
    .expect("write profiles.ini");

    let discovery = discover_gecko_with_context(&context, "firefox").expect("discover profile");
    assert!(!discovery.profiles[0].persistent_source_discovered);

    let mut created = false;
    let report = populate_gecko_sources(
      discovery,
      None,
      |persistent, domains| {
        if !created {
          created = true;
          seed_empty_gecko_database(persistent.parent().expect("profile directory"));
        }
        mozilla::query_cookies_engine_outcome(persistent, domains)
      },
      |path| path.exists(),
    );

    let persistent = report.profiles[0]
      .sources
      .iter()
      .find(|source| source.format == mozilla::PERSISTENT_FORMAT_ID)
      .expect("persistent source created before the query must be projected");
    assert!(persistent.selected);
    assert!(persistent.error.is_none());
  }

  #[test]
  fn gecko_profile_canonicalize_failures_are_bounded() {
    let temp = TempDir::new("gecko-canonicalize-bound");
    let real_context = test_context(temp.path().to_path_buf());
    let root = gecko_test_root(&real_context);
    let declarations = MAX_DISCOVERY_ISSUE_SAMPLES + 5;
    let mut ini = String::new();
    for index in 0..declarations {
      let profile = root.join(format!("Profiles/broken-{index}"));
      std::fs::create_dir_all(profile.join("sessionstore-backups")).expect("create profile");
      std::fs::write(
        profile.join("sessionstore-backups/recovery.jsonlz4"),
        b"discoverable session source",
      )
      .expect("write session candidate");
      ini.push_str(&format!(
        "[Profile{index}]\nName=broken-{index}\nPath=Profiles/broken-{index}\n"
      ));
    }
    std::fs::write(root.join("profiles.ini"), ini).expect("write profiles.ini");

    // Discovery canonicalizes the installation root first and resolves declared
    // profiles against *that*, so the denial list has to be built the same way.
    // Windows canonicalization returns a `\\?\` verbatim path, and a symlinked
    // temporary directory diverges on Unix too, so keying off the uncanonical
    // root would silently deny nothing.
    let canonical_root = root.canonicalize().expect("canonical Firefox root");
    let denied = (0..declarations)
      .map(|index| canonical_root.join(format!("Profiles/broken-{index}")))
      .collect::<Vec<_>>();
    let context = with_test_fs(
      real_context,
      TestDiscoveryFs {
        denied_canonicalize: denied,
        ..TestDiscoveryFs::default()
      },
    );

    let report = discover_gecko_with_context(&context, "firefox").expect("discover profiles");
    assert!(report.profiles.is_empty());
    let issues = report
      .discovery_issues
      .iter()
      .filter(|issue| issue.code == "profile_canonicalize_failed")
      .collect::<Vec<_>>();
    // Bounded to the sample cap, with the unsampled remainder carried as a
    // typed count on the first retained sample rather than formatted into a
    // message and parsed back out.
    assert_eq!(issues.len(), MAX_DISCOVERY_ISSUE_SAMPLES);
    assert_eq!(
      issues.iter().map(|issue| issue.occurrences).sum::<u32>(),
      declarations as u32
    );
    assert!(issues
      .iter()
      .all(|issue| !issue.message.contains("additional")));
  }

  #[test]
  fn a_rejected_row_is_not_projected_as_an_acquisition_retry() {
    let temp = TempDir::new("gecko-row-error-not-retry");
    let context = test_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    seed_empty_gecko_database(&root.join("Profiles/default"));
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=default\nPath=Profiles/default\nDefault=1\n",
    )
    .expect("write profiles.ini");
    let discovery = discover_gecko_with_context(&context, "firefox").expect("discover profile");

    let report = populate_gecko_sources(
      discovery,
      None,
      |_, _| mozilla::MozillaEngineExtractionOutcome {
        persistent_rows_seen: 2,
        persistent_rows_skipped: 1,
        persistent_row_error: Some("failed to read value from row: invalid utf-8".to_owned()),
        ..mozilla::MozillaEngineExtractionOutcome::default()
      },
      |path| path.exists(),
    );

    let source = &report.profiles[0].sources[0];
    // A rejected row means cookies were lost. `diagnostics` renders as a
    // "retried, then succeeded" warning, so routing the row error there would
    // claim a recovery that never happened; the report layer raises it as an
    // error-severity row failure instead.
    assert!(source.diagnostics.is_empty());
    assert!(source.error.is_none());
    assert_eq!(source.rows_skipped, 1);
  }

  #[test]
  fn byte_order_marked_profiles_ini_still_declares_its_profiles() {
    let temp = TempDir::new("gecko-ini-bom");
    let context = test_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    seed_empty_gecko_database(&root.join("Profiles/work"));
    std::fs::write(
      root.join("profiles.ini"),
      "\u{feff}[Profile0]\nName=work\nPath=Profiles/work\nDefault=1\n",
    )
    .expect("write BOM-prefixed profiles.ini");

    // Driven end to end: a BOM must not collapse into a successful empty
    // discovery, which would silently claim the file declared nothing and
    // promote the flat root to default instead.
    let report = discover_gecko_with_context(&context, "firefox").expect("discover BOM profiles");
    assert_eq!(report.profiles.len(), 1);
    assert_eq!(report.profiles[0].name, "work");
    assert!(report.profiles[0].is_default);
    assert_eq!(
      report.profiles[0].path,
      root
        .join("Profiles/work")
        .canonicalize()
        .expect("canonical profile")
    );
    assert!(report.discovery_issues.is_empty());
  }

  #[test]
  fn gecko_profiles_ini_is_read_through_the_injected_filesystem() {
    let temp = TempDir::new("gecko-ini-seam");
    let real_context = test_context(temp.path().to_path_buf());
    let root = gecko_test_root(&real_context);
    seed_empty_gecko_database(&root.join("Profiles/on-disk"));
    seed_empty_gecko_database(&root.join("Profiles/injected"));
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=on-disk\nPath=Profiles/on-disk\nDefault=1\n",
    )
    .expect("write on-disk profiles.ini");
    let canonical_root = root.canonicalize().expect("canonical root");

    let context = with_test_fs(
      real_context,
      TestDiscoveryFs {
        read_to_string_overrides: BTreeMap::from([(
          canonical_root.join("profiles.ini"),
          "[Profile0]\nName=injected\nPath=Profiles/injected\nDefault=1\n".to_owned(),
        )]),
        ..TestDiscoveryFs::default()
      },
    );

    // Discovery must honour the injected contents, proving profiles.ini is read
    // through the seam rather than straight off the real filesystem.
    let report = discover_gecko_with_context(&context, "firefox").expect("discover injected");
    assert_eq!(report.profiles.len(), 1);
    assert_eq!(report.profiles[0].name, "injected");
  }

  #[test]
  fn gecko_flat_fallback_profile_is_named_after_its_directory() {
    let temp = TempDir::new("gecko-flat-name");
    let context = test_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    seed_empty_gecko_database(&root);

    let report = discover_gecko_with_context(&context, "firefox").expect("discover flat fallback");
    assert_eq!(report.profiles.len(), 1);
    let expected = root
      .canonicalize()
      .expect("canonical root")
      .file_name()
      .map(|name| name.to_string_lossy().into_owned())
      .expect("root directory name");
    assert_eq!(report.profiles[0].name, expected);
    assert!(!report.profiles[0].name.is_empty());
    assert!(report.profiles[0].is_default);
  }

  #[test]
  fn external_absolute_gecko_profiles_are_discovered_with_absolute_locators() {
    let temp = TempDir::new("gecko-external-absolute");
    let context = test_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    std::fs::create_dir_all(&root).expect("create Firefox root");
    let external = temp.path().join("external-profiles/work");
    seed_empty_gecko_database(&external);
    std::fs::write(
      root.join("profiles.ini"),
      format!(
        "[Profile0]\nName=work\nIsRelative=0\nPath={}\nDefault=1\n",
        external.display()
      ),
    )
    .expect("write profiles.ini");

    let report = discover_gecko_with_context(&context, "firefox").expect("discover external");
    assert_eq!(report.profiles.len(), 1);
    let profile = &report.profiles[0];
    let canonical_external = external.canonicalize().expect("canonical external profile");
    assert_eq!(profile.path, canonical_external);
    assert!(profile.is_default);
    assert!(profile.persistent_source_discovered);
    // A profile outside the installation root must be identified by an absolute
    // locator; a relative one would not round-trip.
    assert_eq!(
      profile.profile_id,
      profile_id(
        &profile.installation_id,
        ProfileLocator::Absolute(&canonical_external)
      )
    );
  }

  #[test]
  fn relative_gecko_profiles_escaping_the_root_use_absolute_locators() {
    let temp = TempDir::new("gecko-relative-escape");
    let context = test_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    std::fs::create_dir_all(&root).expect("create Firefox root");
    let escaped = root
      .parent()
      .expect("root parent")
      .join("sibling-profiles/work");
    seed_empty_gecko_database(&escaped);
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=work\nIsRelative=1\nPath=../sibling-profiles/work\nDefault=1\n",
    )
    .expect("write profiles.ini");

    let report = discover_gecko_with_context(&context, "firefox").expect("discover escaped");
    assert_eq!(report.profiles.len(), 1);
    let profile = &report.profiles[0];
    let canonical_escaped = escaped.canonicalize().expect("canonical escaped profile");
    assert_eq!(profile.path, canonical_escaped);
    assert_eq!(
      profile.profile_id,
      profile_id(
        &profile.installation_id,
        ProfileLocator::Absolute(&canonical_escaped)
      )
    );
  }

  #[test]
  fn session_only_gecko_profiles_report_no_persistent_source() {
    let temp = TempDir::new("gecko-session-only-report");
    let context = test_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    let profile = root.join("Profiles/session-only");
    std::fs::create_dir_all(profile.join("sessionstore-backups")).expect("create profile");
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=session\nPath=Profiles/session-only\nDefault=1\n",
    )
    .expect("write profiles.ini");
    std::fs::write(
      profile.join("sessionstore.js"),
      r#"{"windows":[{"cookies":[{"host":".example.com","path":"/","name":"session-only","value":"value"}]}]}"#,
    )
    .expect("write session candidate");

    let report = gecko_report_with_context(&context, "firefox", None).expect("session-only report");
    assert_eq!(report.profiles.len(), 1);
    let sources = &report.profiles[0].sources;
    // A profile with no cookies.sqlite must not fabricate a failed persistent
    // source: absence is normal, not an error.
    assert!(sources
      .iter()
      .all(|source| source.format != mozilla::PERSISTENT_FORMAT_ID));
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].format, mozilla::SESSION_JSON_FORMAT_ID);
    assert!(sources[0].selected);
    assert!(sources[0].error.is_none());
    assert_eq!(sources[0].cookies.len(), 1);
    assert_eq!(sources[0].cookies[0].name, "session-only");
  }

  fn write_local_state(root: &Path, value: serde_json::Value) {
    std::fs::create_dir_all(root).expect("create installation root");
    std::fs::write(
      root.join("Local State"),
      serde_json::to_vec(&value).expect("serialize Local State"),
    )
    .expect("write Local State");
  }

  fn seed_cookie(profile: &Path, network: bool, name: &str, value: &str) -> PathBuf {
    let db = if network {
      profile.join("Network/Cookies")
    } else {
      profile.join("Cookies")
    };
    std::fs::create_dir_all(db.parent().expect("cookie db parent")).expect("create profile");
    let connection = rusqlite::Connection::open(&db).expect("open cookie db");
    connection
      .execute_batch(
        "CREATE TABLE cookies (
          host_key TEXT NOT NULL,
          path TEXT NOT NULL,
          is_secure INTEGER NOT NULL,
          expires_utc INTEGER NOT NULL,
          name TEXT NOT NULL,
          value TEXT NOT NULL,
          encrypted_value BLOB NOT NULL,
          is_httponly INTEGER NOT NULL,
          samesite INTEGER NOT NULL
        );",
      )
      .expect("create cookies table");
    connection
      .execute(
        "INSERT INTO cookies VALUES ('.example.com', '/', 0, 0, ?1, ?2, ?3, 0, 0)",
        params![name, value, Vec::<u8>::new()],
      )
      .expect("insert cookie");
    db
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

  impl ChromiumKeyProvider<BrowserInstallation> for CountingProvider {
    fn retrieve(&self, installation: &BrowserInstallation) -> ChromiumKeyOutcomes {
      *self
        .calls
        .borrow_mut()
        .entry(installation.installation_id.clone())
        .or_default() += 1;
      ChromiumKeyOutcomes::default()
    }
  }

  #[derive(Default)]
  struct TestDiscoveryFs {
    denied_read_dir: Option<PathBuf>,
    denied_metadata: Option<PathBuf>,
    denied_canonicalize: Vec<PathBuf>,
    read_to_string_overrides: BTreeMap<PathBuf, String>,
    canonical_aliases: BTreeMap<PathBuf, PathBuf>,
    glob_expansions: BTreeMap<(PathBuf, String), GlobExpansion>,
  }

  impl DiscoveryFs for TestDiscoveryFs {
    fn exists(&self, path: &Path) -> bool {
      RealDiscoveryFs.exists(path)
    }

    fn is_dir(&self, path: &Path) -> bool {
      RealDiscoveryFs.is_dir(path)
    }

    fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
      if self.denied_metadata.as_deref() == Some(path) {
        return Err(std::io::Error::new(
          std::io::ErrorKind::PermissionDenied,
          "injected metadata denial",
        ));
      }
      RealDiscoveryFs.metadata(path)
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>> {
      if self.denied_read_dir.as_deref() == Some(path) {
        bail!("injected profile enumeration failure")
      }
      RealDiscoveryFs.read_dir(path)
    }

    fn canonicalize(&self, path: &Path) -> Result<PathBuf> {
      if self.denied_canonicalize.iter().any(|denied| denied == path) {
        bail!("injected canonicalization failure")
      }
      self
        .canonical_aliases
        .get(path)
        .cloned()
        .map(Ok)
        .unwrap_or_else(|| RealDiscoveryFs.canonicalize(path))
    }

    fn read_to_string(&self, path: &Path) -> Result<String> {
      self
        .read_to_string_overrides
        .get(path)
        .cloned()
        .map(Ok)
        .unwrap_or_else(|| RealDiscoveryFs.read_to_string(path))
    }

    fn expand_registry_glob(&self, base: &Path, suffix: &str) -> Result<GlobExpansion> {
      self
        .glob_expansions
        .get(&(base.to_path_buf(), suffix.to_owned()))
        .cloned()
        .map(Ok)
        .unwrap_or_else(|| RealDiscoveryFs.expand_registry_glob(base, suffix))
    }
  }

  fn with_test_fs(
    context: DiscoveryContext<RealDiscoveryFs>,
    fs: TestDiscoveryFs,
  ) -> DiscoveryContext<TestDiscoveryFs> {
    DiscoveryContext {
      platform: context.platform,
      home: context.home,
      env: context.env,
      fs,
    }
  }

  #[test]
  fn embedded_registry_is_versioned_and_contains_current_chrome_definition() {
    let registry = embedded_registry().expect("valid embedded registry");
    assert_eq!(registry.schema_version, REGISTRY_SCHEMA_VERSION);
    let definition =
      browser_definition(registry, PlatformId::current().expect("platform"), "chrome")
        .expect("Chrome definition");
    assert_eq!(definition.engine, BrowserEngine::Chromium);
    assert!(!definition.roots.is_empty());
    assert_eq!(
      definition.capabilities.declared_persistent_formats,
      ["chromium_sqlite"]
    );
  }

  #[test]
  fn registry_contains_every_existing_chromium_family_browser_without_mutating_legacy_config() {
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
      ),
      (
        PlatformId::Macos,
        [
          "arc", "brave", "chrome", "chromium", "edge", "opera", "opera_gx", "vivaldi",
        ]
        .as_slice(),
      ),
      (
        PlatformId::Linux,
        [
          "arc", "brave", "chrome", "chromium", "edge", "opera", "vivaldi",
        ]
        .as_slice(),
      ),
    ];

    for (platform, expected) in cases {
      let definitions = registry
        .platforms
        .get(platform.as_str())
        .expect("platform definitions");
      let actual = definitions
        .iter()
        .filter(|definition| definition.engine == BrowserEngine::Chromium)
        .map(|definition| definition.canonical_id.as_str())
        .collect::<BTreeSet<_>>();
      assert_eq!(actual, expected.iter().copied().collect());
      for browser_id in expected {
        assert!(crate::config::CONFIG
          .platforms
          .get(platform.as_str())
          .and_then(|browsers| browsers.get(*browser_id))
          .is_some());
      }
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
    assert!(browser_definition(registry, PlatformId::Linux, "opera_gx").is_err());
    assert!(browser_definition(registry, PlatformId::Linux, "opera-gx").is_err());
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
  fn injected_path_components_remain_literal_while_registry_wildcards_are_preserved() {
    let temp = TempDir::new("escaped-glob-components");
    let home = temp.path().join(format!("home{GLOB_METACHARACTERS}"));
    let config_home = temp.path().join(format!("config{GLOB_METACHARACTERS}"));
    let context = test_context_for(
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

    let mac_context = test_context_for(PlatformId::Macos, home.clone(), []);
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
    let windows_context = test_context_for(
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
    let context = test_context_for(PlatformId::Linux, home.clone(), []);
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
    let context = test_context_for(PlatformId::Linux, home.clone(), []);

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
    let context = test_context_for(
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
      let context = test_context_for(
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

    let chrome_context = test_context_for(
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

    let xdg_context = test_context_for(
      PlatformId::Linux,
      home.clone(),
      [("XDG_CONFIG_HOME", xdg_config.clone())],
    );
    let xdg_root = channel_root(&xdg_context, "stable");
    assert_eq!(xdg_root, xdg_config.join("google-chrome"));

    let default_context = test_context_for(PlatformId::Linux, home.clone(), []);
    assert_eq!(
      channel_root(&default_context, "stable"),
      home.join(".config/google-chrome")
    );

    let empty_override_context = test_context_for(
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
  fn chrome_config_override_does_not_relocate_other_chromium_browsers() {
    let temp = TempDir::new("chrome-config-isolation");
    let home = temp.path().join("home");
    let chrome_config = temp.path().join("chrome-config");
    let xdg_config = temp.path().join("xdg-config");
    let context = test_context_for(
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
    use std::os::unix::ffi::OsStringExt;

    let temp = TempDir::new("non-unicode-base");
    let config_home = temp
      .path()
      .join(OsString::from_vec(b"config-\xff".to_vec()));
    let context = test_context_for(
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
    let real_context = test_context_for(
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
    let real_context = test_context_for(
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
      None,
      None,
      &CountingProvider::default(),
    )
    .expect("report retains discovery issue");
    assert!(report.installations.is_empty());
    assert!(report
      .discovery_issues
      .iter()
      .any(|issue| issue.code == "installation_glob_expand_failed"));
  }

  #[test]
  fn failed_wildcard_with_only_unusable_matches_still_fails_listing() {
    let temp = TempDir::new("glob-expansion-unusable-match");
    let home = temp.path().join("home");
    let local_app_data = home.join("LocalAppData");
    let real_context = test_context_for(
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
    let real_context = test_context_for(PlatformId::Linux, home, []);
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
    let context = test_context_for(
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
    let windows = browser_definition(registry, PlatformId::Windows, "chrome")
      .expect("Windows Chrome definition");
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
    assert!(!edge_descriptor
      .declared_decryption_tiers
      .iter()
      .any(|tier| tier == "v20"));
    assert!(!edge_descriptor
      .available_decryption_tiers
      .iter()
      .any(|tier| tier == "v20"));
  }

  #[test]
  fn local_state_marks_active_profiles_without_changing_default_first_order() {
    let temp = TempDir::new("active");
    let context = test_context(temp.path().to_path_buf());
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
      .all(|profile| profile.profile_id.len() == 64));
    assert!(profiles
      .iter()
      .all(|profile| profile.installation_id.len() == 64));
    assert_eq!(profiles[0].persistent_candidates[0].precedence, 10);
    assert!(profiles[0].persistent_candidates[0].selected);
  }

  #[test]
  fn same_named_profiles_in_two_channels_have_stable_unique_ids() {
    let temp = TempDir::new("channels");
    let context = test_context(temp.path().to_path_buf());
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
    let context = test_context(temp.path().to_path_buf());
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

    let report = extract_chromium_with_provider(&context, "chrome", None, None, &provider)
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
    assert_eq!(default.cookies[0].name, "shared");
    assert_eq!(default.cookies[0].value, "default-value");
    assert_eq!(good.cookies[0].name, "shared");
    assert_eq!(good.cookies[0].value, "profile-value");
    assert!(broken.cookies.is_empty());
    assert!(matches!(
      broken.failure,
      Some(ChromiumProfileFailure::Extraction(_))
    ));
  }

  #[test]
  fn report_preserves_partial_row_stats_and_issues() {
    let temp = TempDir::new("partial-rows");
    let context = test_context(temp.path().to_path_buf());
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

    let report =
      extract_chromium_with_provider(&context, "chrome", None, None, &CountingProvider::default())
        .expect("partial report");
    let extraction = &report.installations[0].profiles[0];
    assert_eq!(extraction.cookies.len(), 1);
    assert_eq!(extraction.cookies[0].name, "readable");
    assert_eq!(extraction.stats.rows_seen, 2);
    assert_eq!(extraction.stats.cookies_emitted, 1);
    assert_eq!(extraction.stats.rows_skipped, 1);
    assert_eq!(extraction.row_issues.len(), 1);
    assert_eq!(extraction.row_issues[0].occurrences, 1);
    assert!(extraction.failure.is_none());
  }

  #[test]
  fn profile_selector_uses_opaque_id_and_limits_key_retrieval() {
    let temp = TempDir::new("select");
    let context = test_context(temp.path().to_path_buf());
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
      Some(&profile_id),
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
      report.installations[0].profiles[0].cookies[0].name,
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
      Some("not-a-profile-id"),
      None,
      &provider,
    )
    .expect_err("unknown profile must fail");
    assert!(error.to_string().contains("unknown chrome profile id"));
  }

  #[test]
  fn corrupt_local_state_does_not_hide_source_bearing_profiles() {
    let temp = TempDir::new("bad-state");
    let context = test_context(temp.path().to_path_buf());
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
    let context = test_context(temp.path().to_path_buf());
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
    let real_context = test_context(temp.path().to_path_buf());
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
    let report = extract_chromium_with_provider(&context, "chrome", None, None, &provider)
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
  fn generic_listing_names_the_selected_browser_when_all_roots_fail() {
    let temp = TempDir::new("edge-enumeration-failure");
    let home = temp.path().join("home");
    let local_app_data = home.join("LocalAppData");
    let real_context = test_context_for(
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
    let real_context = test_context(temp.path().to_path_buf());
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
}
