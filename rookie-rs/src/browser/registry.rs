//! Authoritative browser installation/profile discovery and extraction.
//!
//! Both the grouped report APIs and the compatibility named APIs use this
//! module. Their only intentional difference is selection policy: reports read
//! every discovered profile (or one explicit opaque ID), while compatibility
//! wrappers read the first legacy-compatible profile.

#![allow(dead_code)]

#[cfg(test)]
use super::report_core::sort_cookies;
use super::report_core::{InstallationId, ProfileId};
pub(crate) use super::source::{Source, SourceCandidate, SourceFailureStage, SourceIssue};
use crate::common::diagnostic::REDACTED_PATH;
use anyhow::{anyhow, bail, Context, Result};
use once_cell::sync::Lazy;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
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
  key_credentials: Option<chromium::KeyCredentials>,
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
///   service and account, or its crypt name. Those identities live beside the
///   browser's registry roots and are validated with them.
/// - Windows v10 and `legacy_dpapi` are gated by neither: that arm reads the
///   installation's `Local State` directly.
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
  let definitions = registry
    .platforms
    .get(platform.as_str())
    .ok_or_else(|| anyhow!("registry has no definitions for {}", platform.as_str()))?;
  let definition = definitions.iter().find(|definition| {
    definition.canonical_id == browser_id
      || definition.aliases.iter().any(|alias| alias == browser_id)
  });
  match definition {
    Some(definition) => Ok(registered_browser(definition, platform)),
    None => Err(
      crate::RequestError::UnknownBrowser {
        browser_id: browser_id.to_owned(),
      }
      .into(),
    ),
  }
}

#[derive(Debug, Deserialize)]
struct InstallationRoot {
  root_id: String,
  template: String,
  channel: String,
  discovery: DiscoveryStrategy,
  priority: u16,
  /// Compatibility-only ordering from the deleted named-browser path tables.
  /// Generic reports continue to use `priority`.
  legacy_priority: Option<u16>,
  /// Compatibility-only profile shapes admitted by the deleted path tables.
  #[serde(default)]
  legacy_profile_layout: chromium::LegacyChromiumProfileLayout,
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
      chromium::validate_key_credentials(platform, definition)?;
    }
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

/// Which discovered profiles an extraction request may acquire.
///
/// Keeping this decision below the engine boundary prevents a compatibility
/// wrapper from rebuilding discovery or extracting profiles it will discard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProfileSelection<'a> {
  AllProfiles,
  ProfileId(&'a str),
  LegacyFirstProfile,
}

impl<'a> ProfileSelection<'a> {
  fn from_profile_id(profile_id: Option<&'a str>) -> Self {
    match profile_id {
      Some(profile_id) => Self::ProfileId(profile_id),
      None => Self::AllProfiles,
    }
  }
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
      .with_context(|| format!("read directory {REDACTED_PATH}"))?
      .map(|entry| entry.map(|entry| entry.path()))
      .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|path| normalized_path_bytes(path));
    Ok(entries)
  }

  fn canonicalize(&self, path: &Path) -> Result<PathBuf> {
    path
      .canonicalize()
      .with_context(|| format!("canonicalize {REDACTED_PATH}"))
  }

  fn read_to_string(&self, path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("read {REDACTED_PATH}"))
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
  home: Option<PathBuf>,
  env: BTreeMap<OsString, OsString>,
  fs: F,
}

#[derive(Debug, Clone)]
struct ResolvedRoot {
  base: PathBuf,
  suffix: String,
}

fn environment_value<'a>(
  platform: PlatformId,
  env: &'a BTreeMap<OsString, OsString>,
  name: &str,
) -> Option<&'a OsString> {
  if platform == PlatformId::Windows {
    env
      .iter()
      .find(|(key, _)| key.to_string_lossy().eq_ignore_ascii_case(name))
      .map(|(_, value)| value)
  } else {
    env.get(OsStr::new(name))
  }
}

#[cfg(test)]
std::thread_local! {
  /// Test-only override for the environment `system()` would otherwise read
  /// from the real process. Thread-local rather than a mutex-guarded global:
  /// parallel tests each set their own value and never observe or serialize
  /// on another test's environment, so discovery tests inject an `Env` value
  /// directly instead of mutating real process state.
  static ENV_OVERRIDE: std::cell::RefCell<Option<BTreeMap<OsString, OsString>>> =
    const { std::cell::RefCell::new(None) };
}

/// RAII guard installing a thread-local environment override for
/// `DiscoveryContext::system()`. Dropping the guard clears the override.
#[cfg(test)]
pub(crate) struct EnvOverride;

#[cfg(test)]
impl EnvOverride {
  pub(crate) fn install(env: BTreeMap<OsString, OsString>) -> Self {
    ENV_OVERRIDE.with(|cell| *cell.borrow_mut() = Some(env));
    Self
  }
}

#[cfg(test)]
impl Drop for EnvOverride {
  fn drop(&mut self) {
    ENV_OVERRIDE.with(|cell| *cell.borrow_mut() = None);
  }
}

impl DiscoveryContext<RealDiscoveryFs> {
  fn system() -> Result<Self> {
    let platform = PlatformId::current()?;
    #[cfg(test)]
    if let Some(env) = ENV_OVERRIDE.with(|cell| cell.borrow().clone()) {
      return Self::from_system_env(platform, env);
    }
    let env: BTreeMap<OsString, OsString> = std::env::vars_os().collect();
    Self::from_system_env(platform, env)
  }

  /// `home` is optional *when an alternative discovery root resolves*: a
  /// non-Windows caller with no `HOME` but a usable `XDG_CONFIG_HOME` or
  /// `CHROME_CONFIG_HOME` still resolves `{config_home}`/`{xdg_config_home}`
  /// -rooted templates, and any `{home}`-rooted template resolves to absence
  /// rather than a partial path (`resolve_template_for_selection` treats a
  /// missing token source as "no match", not an error). But an environment
  /// with none of `HOME`/`USERPROFILE` and none of its platform alternatives
  /// gives discovery nothing to search at all — every root would silently
  /// resolve to absence, indistinguishable from every browser being
  /// genuinely uninstalled, which is exactly the "plausible empty success"
  /// this crate's discovery contract rejects. That case still errors.
  fn from_system_env(platform: PlatformId, env: BTreeMap<OsString, OsString>) -> Result<Self> {
    let home_key = if platform == PlatformId::Windows {
      "USERPROFILE"
    } else {
      "HOME"
    };
    let home = environment_value(platform, &env, home_key)
      .filter(|value| !value.is_empty())
      .map(PathBuf::from);
    if home.is_none() {
      let alternative_keys: &[&str] = if platform == PlatformId::Windows {
        &["LOCALAPPDATA", "APPDATA"]
      } else {
        &["XDG_CONFIG_HOME", "CHROME_CONFIG_HOME"]
      };
      let has_alternative = alternative_keys
        .iter()
        .any(|key| environment_value(platform, &env, key).is_some_and(|value| !value.is_empty()));
      if !has_alternative {
        bail!(
          "{home_key} is not set, and no alternative discovery root ({}) is available either",
          alternative_keys.join("/")
        );
      }
    }
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
    environment_value(self.platform, &self.env, name)
      .filter(|value| !value.is_empty())
      .map(PathBuf::from)
  }

  fn xdg_config_home(&self) -> Option<PathBuf> {
    self
      .env_path("XDG_CONFIG_HOME")
      .or_else(|| self.home.as_ref().map(|home| home.join(".config")))
  }

  fn chrome_config_home(&self) -> Option<PathBuf> {
    self
      .env_path("CHROME_CONFIG_HOME")
      .or_else(|| self.xdg_config_home())
  }

  fn resolve_template(&self, template: &str) -> Option<ResolvedRoot> {
    self.resolve_template_for_selection(template, ProfileSelection::AllProfiles)
  }

  fn resolve_template_for_selection(
    &self,
    template: &str,
    selection: ProfileSelection<'_>,
  ) -> Option<ResolvedRoot> {
    // The deleted Linux named-browser path tables always expanded `~/.config`
    // literally. Environment config roots are useful generic-discovery inputs,
    // but must not relocate compatibility wrappers away from profiles they
    // historically read.
    let legacy_linux_config_home =
      self.platform == PlatformId::Linux && selection == ProfileSelection::LegacyFirstProfile;
    let config_home = if legacy_linux_config_home {
      self.home.as_ref().map(|home| home.join(".config"))
    } else {
      self.chrome_config_home()
    };
    let xdg_config_home = if legacy_linux_config_home {
      self.home.as_ref().map(|home| home.join(".config"))
    } else {
      self.xdg_config_home()
    };
    let replacements = [
      ("{home}", self.home.clone()),
      ("{config_home}", config_home),
      ("{xdg_config_home}", xdg_config_home),
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
pub(crate) struct DiscoveryIssue {
  pub(crate) code: &'static str,
  pub(crate) path: PathBuf,
  pub(crate) message: String,
  /// How many times this code occurred at or after `path`. Retained samples
  /// carry 1; a bounded code folds its unsampled remainder into the first
  /// retained sample, so the per-code total is the sum across entries.
  pub(crate) occurrences: u32,
}

pub(crate) fn is_informational_discovery_issue(code: &str) -> bool {
  matches!(
    code,
    "duplicate_installation"
      | "duplicate_profile"
      | "profile_has_no_cookie_source"
      | "profile_excluded_service_directory"
      | "safari_profile_discovery_degraded"
  )
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

// [Rev 2] Decision 18: these produce the already-public `report_core` id
// newtypes rather than bare `String`, so a transposed installation/profile id is
// a compile error. The hex is unchanged: `known` wraps the same digest.
fn installation_id(browser_id: &str, root_id: &str, channel: &str, path: &[u8]) -> InstallationId {
  InstallationId::known(&digest_fields([
    INSTALLATION_ID_DOMAIN.as_bytes(),
    browser_id.as_bytes(),
    root_id.as_bytes(),
    channel.as_bytes(),
    path,
  ]))
}

enum ProfileLocator<'a> {
  Relative(&'a Path),
  Absolute(&'a Path),
}

fn profile_id(installation_id: &str, locator: ProfileLocator<'_>) -> ProfileId {
  let (kind, path) = match locator {
    ProfileLocator::Relative(path) => (b"relative".as_slice(), path),
    ProfileLocator::Absolute(path) => (b"absolute".as_slice(), path),
  };
  let normalized = normalized_path_bytes(path);
  ProfileId::known(&digest_fields([
    PROFILE_ID_DOMAIN.as_bytes(),
    installation_id.as_bytes(),
    kind,
    &normalized,
  ]))
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

pub(crate) const SOURCE_ROLE_PERSISTENT: &str = "persistent";
pub(crate) const SOURCE_ROLE_SESSION: &str = "session";
/// A profile never merges two persistent alternatives, so the authoritative
/// persistent source always carries the first declared precedence.
pub(crate) const PERSISTENT_SOURCE_PRECEDENCE: u16 = 10;

// The source-work leaf vocabulary lives in `browser/source.rs`. Re-exported
// here so every engine names the same `SourceAcquisition` / `SourceFailureStage`
// through `registry`, one definition with no divergence.
pub(crate) use super::source::SourceAcquisition;

/// Identity fields shared by the Gecko/Safari/IE listing and extract profile
/// types.
///
/// A field bundle, not a stage object and not a public `Profile`. Chromium
/// does not adopt it: `ChromiumProfile` keeps its own directory_name /
/// display_name / is_active / is_last_used.
#[derive(Debug, Clone)]
pub(crate) struct EngineProfileIdentity {
  pub(crate) profile_id: ProfileId,
  pub(crate) installation_id: InstallationId,
  pub(crate) installation_priority: u16,
  pub(crate) installation_path: PathBuf,
  /// Becomes `ProfileIdentity.display_name`.
  pub(crate) name: String,
  pub(crate) path: PathBuf,
  pub(crate) is_default: bool,
  pub(crate) persistent_source_discovered: bool,
}

/// ADR 0002 `LegacyFirstProfile` ranking inputs.
///
/// Selection policy, deliberately kept out of a type named `Identity`: these
/// decide which profile the compatibility wrappers pick, and the report never
/// reads them.
#[derive(Debug, Clone)]
pub(crate) struct LegacyRank {
  /// Installation rank at the first compatibility-eligible admission. This can
  /// differ from generic ownership when a markerless recovery profile is later
  /// encountered as an explicit declaration through another root.
  pub(crate) installation_priority: u16,
  /// Discovery order within one installation, retained for compatibility
  /// selectors even though generic reports use display-name ordering.
  pub(crate) profile_order: usize,
  /// Defaultness at the first compatibility-eligible admission. Duplicate
  /// registry roots may later promote `is_default` for generic reporting, but
  /// must not reorder the frozen legacy selector.
  pub(crate) is_default: bool,
  /// Whether the deleted named-browser path resolver could have admitted this
  /// profile. Markerless recovery is intentionally generic-report-only.
  pub(crate) eligible: bool,
  pub(crate) installation_path: PathBuf,
  pub(crate) name: String,
}

/// Listing return profile. rustc: there is no field here to put a [`Source`] in.
#[derive(Debug)]
pub(crate) struct DiscoveredProfile {
  pub(crate) identity: EngineProfileIdentity,
  pub(crate) legacy: LegacyRank,
  pub(crate) candidates: Vec<SourceCandidate>,
}

/// Extract return profile. Never returned by a listing function.
#[derive(Debug)]
pub(crate) struct ExtractedProfile {
  pub(crate) identity: EngineProfileIdentity,
  pub(crate) legacy: LegacyRank,
  pub(crate) sources: Vec<Source>,
}

/// Shared discover counters, embedded by both bags so listing and extract
/// cannot diverge on `all_detected_roots_failed`.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct DiscoveryCounters {
  /// Distinct installations that were resolved and owned by this browser.
  /// Duplicates and roots that failed to canonicalize are excluded, matching
  /// what the Chromium adapter reports.
  pub(crate) installations_discovered: usize,
  /// Roots that existed on disk or could not be inspected, including ones that
  /// then failed to canonicalize or were owned by an earlier root.
  pub(crate) installations_detected: usize,
  /// Roots whose profile enumeration completed, even when it found nothing.
  pub(crate) installations_enumerated: usize,
}

impl DiscoveryCounters {
  /// Section 5.7: when every applicable detected root fails enumeration the
  /// result is `failed`/`Err`, never an empty list indistinguishable from a
  /// browser that is simply not installed.
  pub(crate) fn all_detected_roots_failed(&self) -> bool {
    self.installations_detected > 0 && self.installations_enumerated == 0
  }
}

/// What discovery found. Cannot carry extraction results.
#[derive(Debug, Default)]
pub(crate) struct EngineListing {
  pub(crate) profiles: Vec<DiscoveredProfile>,
  pub(crate) discovery_issues: Vec<DiscoveryIssue>,
  pub(crate) counters: DiscoveryCounters,
  /// Typed request stop observed while populating sources. Keeping it outside
  /// source diagnostics prevents timeouts/cancellation from becoming fake
  /// source failures.
  pub(crate) boundary_stop: Option<crate::common::deadline::BoundaryStop>,
}

impl EngineListing {
  pub(crate) fn all_detected_roots_failed(&self) -> bool {
    self.counters.all_detected_roots_failed()
  }
}

/// Thin adapter extract bag. Survives past "done when": the acquire loop stays
/// in the adapters, and this is what they hand back.
#[derive(Debug, Default)]
pub(crate) struct EngineExtract {
  pub(crate) profiles: Vec<ExtractedProfile>,
  pub(crate) discovery_issues: Vec<DiscoveryIssue>,
  pub(crate) counters: DiscoveryCounters,
  pub(crate) boundary_stop: Option<crate::common::deadline::BoundaryStop>,
}

impl EngineExtract {
  pub(crate) fn all_detected_roots_failed(&self) -> bool {
    self.counters.all_detected_roots_failed()
  }
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
  outcome: &mut EngineListing,
) -> Option<PathBuf> {
  outcome.counters.installations_detected += 1;
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
  outcome.counters.installations_discovered += 1;
  Some(canonical_root)
}

/// Admits a literal non-Chromium installation root without erasing why it
/// could not be inspected. A missing path, a non-directory occupying it, or a
/// non-directory ancestor is ordinary absence; every other metadata error
/// means a root was applicable but inaccessible, so it must participate in the
/// failed-discovery counters.
///
/// Valid directories are counted later by [`canonical_installation_root`].
/// Keeping that increment in one place prevents a successfully admitted root
/// from being counted twice.
fn installation_root_is_directory<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  root_path: &Path,
  outcome: &mut EngineListing,
) -> bool {
  match context.fs.metadata(root_path) {
    Ok(metadata) => metadata.is_dir(),
    Err(error)
      if matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
      ) =>
    {
      false
    }
    Err(error) => {
      outcome.counters.installations_detected += 1;
      outcome.discovery_issues.push(DiscoveryIssue::new(
        "installation_metadata_failed",
        root_path.to_path_buf(),
        error.to_string(),
      ));
      false
    }
  }
}

/// Section 5.5 ordering over the listing profile shape: installations by
/// registry priority then normalized path, then profiles default-first, by
/// locale-independent lowercase name, raw name, and finally normalized path.
fn sort_discovered_profiles(profiles: &mut [DiscoveredProfile]) {
  profiles.sort_by(|left, right| {
    left
      .identity
      .installation_priority
      .cmp(&right.identity.installation_priority)
      .then_with(|| {
        normalized_path_bytes(&left.identity.installation_path)
          .cmp(&normalized_path_bytes(&right.identity.installation_path))
      })
      .then_with(|| (!left.identity.is_default).cmp(&(!right.identity.is_default)))
      .then_with(|| {
        left
          .identity
          .name
          .to_lowercase()
          .cmp(&right.identity.name.to_lowercase())
      })
      .then_with(|| left.identity.name.cmp(&right.identity.name))
      .then_with(|| {
        normalized_path_bytes(&left.identity.path).cmp(&normalized_path_bytes(&right.identity.path))
      })
  });
}

/// Narrows the listing to the requested profile, before any source is acquired.
/// Discovery has
/// already completed, so only the profile list is narrowed: the counters and
/// discovery issues stay exactly what an unselected run reports.
fn select_listing_profiles(
  listing: &mut EngineListing,
  browser_id: &str,
  selection: ProfileSelection<'_>,
) -> Result<()> {
  match selection {
    ProfileSelection::AllProfiles => {}
    ProfileSelection::ProfileId(profile_id) => {
      if !listing
        .profiles
        .iter()
        .any(|profile| profile.identity.profile_id.as_str() == profile_id)
      {
        bail!("unknown {browser_id} profile id {profile_id:?}")
      }
      listing
        .profiles
        .retain(|profile| profile.identity.profile_id.as_str() == profile_id);
    }
    ProfileSelection::LegacyFirstProfile => {
      // Compatibility selectors require a persistent source; session-only
      // profiles remain report-capable but are not candidates for those APIs.
      listing
        .profiles
        .retain(|profile| profile.legacy.eligible && profile.identity.persistent_source_discovered);
      listing.profiles.truncate(1);
    }
  }
  Ok(())
}

/// Drops discovery-only source slots from the extract bag after a typed request
/// stop. Drops discovery-only
/// source slots after a typed request stop: a `Source` is committed atomically
/// only once at least one acquisition attempt completes, so leaving a
/// zero-attempt slot would fabricate a successful zero-row source. Profiles that
/// then own no committed source are likewise discovery placeholders, not
/// extraction failures.
pub(crate) fn retain_completed_engine_extract(extract: &mut EngineExtract) {
  for profile in &mut extract.profiles {
    profile
      .sources
      .retain(|source| source.acquisition_attempts > 0);
  }
  extract
    .profiles
    .retain(|profile| !profile.sources.is_empty());
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

mod profile_query;
#[allow(unused_imports)]
pub(crate) use profile_query::resolve_profile_query;

mod chromium;

#[cfg(unix)]
pub(crate) use chromium::chromium_key_credentials;
pub(crate) use chromium::{
  chrome_profiles_with_runtime, chromium_listing_with_runtime,
  chromium_registry_report_with_runtime, legacy_chromium_outcome_with_runtime,
  select_chrome_profile_with_runtime, ChromiumExtractedProfile, ChromiumProfile,
  ChromiumRegistryDraft,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use chromium::{
  direct_path_chromium_identity, registry_key_credentials, DirectPathChromiumIdentity,
};

mod gecko;

pub(crate) use gecko::{
  gecko_profiles_with_runtime, gecko_report_with_runtime, legacy_gecko_outcome_with_runtime,
  legacy_gecko_profiles_with_runtime,
};

#[cfg(any(target_os = "macos", test))]
mod safari;

#[cfg(target_os = "macos")]
pub(crate) use safari::{
  legacy_safari_outcome_with_runtime, safari_profiles_with_runtime, safari_report_with_runtime,
};

#[cfg(any(target_os = "windows", test))]
mod internet_explorer;

#[cfg(test)]
pub(crate) use internet_explorer::InternetExplorerRows;
#[cfg(target_os = "windows")]
pub(crate) use internet_explorer::{
  internet_explorer_profiles_with_runtime, internet_explorer_report_with_runtime,
  legacy_internet_explorer_outcome_with_runtime,
};

/// Context-injected engine seams for the cross-engine report tests. They keep
/// fixtures on temporary roots instead of mutating the process environment.
#[cfg(test)]
pub(crate) mod test_seams {
  use super::chromium::{
    discover_browser_with_context, extract_chromium_with_provider, profiles_for_listing,
    BrowserInstallation,
  };
  use super::gecko::{
    discover_gecko_with_context, gecko_profiles_with_context, gecko_report_with_context,
    populate_gecko_sources,
  };
  use super::internet_explorer::{
    discover_internet_explorer_with_context, internet_explorer_report_with_context,
  };
  use super::safari::{discover_safari_with_context, safari_report_with_context};
  use super::*;
  use crate::browser::chromium_crypto::{ChromiumKeyOutcomes, KeyProvider};
  use crate::browser::mozilla;
  use std::sync::atomic::{AtomicU64, Ordering};

  struct MetadataDeniedFs {
    denied: PathBuf,
  }

  impl DiscoveryFs for MetadataDeniedFs {
    fn exists(&self, path: &Path) -> bool {
      RealDiscoveryFs.exists(path)
    }

    fn is_dir(&self, path: &Path) -> bool {
      RealDiscoveryFs.is_dir(path)
    }

    fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
      if path == self.denied {
        return Err(std::io::Error::new(
          std::io::ErrorKind::PermissionDenied,
          "injected installation metadata denial",
        ));
      }
      RealDiscoveryFs.metadata(path)
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>> {
      RealDiscoveryFs.read_dir(path)
    }

    fn canonicalize(&self, path: &Path) -> Result<PathBuf> {
      RealDiscoveryFs.canonicalize(path)
    }

    fn read_to_string(&self, path: &Path) -> Result<String> {
      RealDiscoveryFs.read_to_string(path)
    }

    fn expand_registry_glob(&self, base: &Path, suffix: &str) -> Result<GlobExpansion> {
      RealDiscoveryFs.expand_registry_glob(base, suffix)
    }
  }

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
      home: Some(home),
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

  /// Runs the production non-Chromium discovery adapter with one deterministic
  /// metadata denial. Cross-engine report tests use this instead of relying on
  /// host permissions, which can be bypassed by CI users with elevated access.
  pub(crate) fn non_chromium_discovery_with_denied_root(
    context: &DiscoveryContext<RealDiscoveryFs>,
    browser_id: &str,
    denied: PathBuf,
  ) -> Result<EngineListing> {
    let denied_context = DiscoveryContext {
      platform: context.platform,
      home: context.home.clone(),
      env: context.env.clone(),
      fs: MetadataDeniedFs { denied },
    };
    let registry = embedded_registry()?;
    match browser_definition(registry, context.platform, browser_id)?.engine {
      BrowserEngine::Gecko => discover_gecko_with_context(&denied_context, browser_id),
      BrowserEngine::Safari => discover_safari_with_context(&denied_context, browser_id),
      BrowserEngine::InternetExplorer => {
        discover_internet_explorer_with_context(&denied_context, browser_id)
      }
      BrowserEngine::Chromium => {
        bail!("metadata-denial seam only supports non-Chromium engines")
      }
    }
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
        "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
        INSERT INTO meta (key, value) VALUES ('version', '23');
        CREATE TABLE cookies (
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
  ) -> Result<ChromiumRegistryDraft> {
    struct FixedKeys(ChromiumKeyOutcomes);
    impl KeyProvider<BrowserInstallation> for FixedKeys {
      type Keys = ChromiumKeyOutcomes;

      fn keys(
        &self,
        _installation: &BrowserInstallation,
        _runtime: &crate::common::deadline::BoundaryRuntime<'_>,
      ) -> ChromiumKeyOutcomes {
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
    profile_id: Option<&str>,
    domains: Option<&[String]>,
  ) -> Result<EngineExtract> {
    gecko_report_with_context(context, browser_id, profile_id, domains)
  }

  /// Like `gecko_report`, but calls `on_before_query` once per profile right
  /// before its database/session read, so a test can mutate the filesystem in
  /// between discovery and query to simulate a source that vanishes in the
  /// race window - the same seam `populate_gecko_sources`'s own unit tests use,
  /// exposed for tests that need the full discover-then-query pipeline.
  pub(crate) fn gecko_report_with_race<R>(
    context: &DiscoveryContext<RealDiscoveryFs>,
    browser_id: &str,
    domains: Option<&[String]>,
    mut on_before_query: R,
  ) -> Result<EngineExtract>
  where
    R: FnMut(&Path),
  {
    let discovery = discover_gecko_with_context(context, browser_id)?;
    Ok(populate_gecko_sources(
      discovery,
      domains,
      |persistent, domains| {
        on_before_query(persistent);
        mozilla::query_cookies_engine_outcome(persistent, domains)
      },
      |path| context.fs.exists(path),
    ))
  }

  pub(crate) fn gecko_profiles(
    context: &DiscoveryContext<RealDiscoveryFs>,
    browser_id: &str,
  ) -> Result<EngineListing> {
    gecko_profiles_with_context(context, browser_id)
  }

  pub(crate) fn safari_report(
    context: &DiscoveryContext<RealDiscoveryFs>,
    browser_id: &str,
    profile_id: Option<&str>,
    domains: Option<&[String]>,
  ) -> Result<EngineExtract> {
    safari_report_with_context(context, browser_id, profile_id, domains)
  }

  pub(crate) fn internet_explorer_report<Q>(
    context: &DiscoveryContext<RealDiscoveryFs>,
    browser_id: &str,
    profile_id: Option<&str>,
    domains: Option<&[String]>,
    query: Q,
  ) -> Result<EngineExtract>
  where
    Q: FnMut(&Path, Option<&[String]>) -> Result<InternetExplorerRows>,
  {
    internet_explorer_report_with_context(context, browser_id, profile_id, domains, query)
  }

  pub(crate) struct TempDir(pub(crate) PathBuf);

  impl TempDir {
    pub(crate) fn new(tag: &str) -> Self {
      static COUNTER: AtomicU64 = AtomicU64::new(0);
      let count = COUNTER.fetch_add(1, Ordering::SeqCst);
      let path = std::env::temp_dir().join(format!(
        "rookie-registry-{tag}-{}-{count}",
        std::process::id()
      ));
      std::fs::create_dir_all(&path).expect("create temporary directory");
      Self(path)
    }

    pub(crate) fn path(&self) -> &Path {
      &self.0
    }
  }

  impl Drop for TempDir {
    fn drop(&mut self) {
      let _ = std::fs::remove_dir_all(&self.0);
    }
  }

  pub(crate) fn channel_root(
    context: &DiscoveryContext<RealDiscoveryFs>,
    channel: &str,
  ) -> PathBuf {
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

  pub(crate) fn browser_root(
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

  #[derive(Default)]
  pub(crate) struct TestDiscoveryFs {
    pub(crate) denied_read_dir: Option<PathBuf>,
    pub(crate) denied_metadata: Option<PathBuf>,
    pub(crate) denied_canonicalize: Vec<PathBuf>,
    pub(crate) denied_read_to_string: Option<PathBuf>,
    pub(crate) read_to_string_overrides: BTreeMap<PathBuf, String>,
    pub(crate) canonical_aliases: BTreeMap<PathBuf, PathBuf>,
    pub(super) glob_expansions: BTreeMap<(PathBuf, String), GlobExpansion>,
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
      if self.denied_read_to_string.as_deref() == Some(path) {
        bail!("injected file read denial for {}", path.display())
      }
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

  pub(crate) fn with_test_fs(
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

  pub(crate) fn context_for(
    platform: PlatformId,
    home: PathBuf,
    env: impl IntoIterator<Item = (&'static str, PathBuf)>,
  ) -> DiscoveryContext<RealDiscoveryFs> {
    DiscoveryContext {
      platform,
      home: Some(home),
      env: env
        .into_iter()
        .map(|(name, value)| (OsString::from(name), value.into_os_string()))
        .collect(),
      fs: RealDiscoveryFs,
    }
  }

  pub(crate) fn write_local_state(root: &Path, value: serde_json::Value) {
    std::fs::create_dir_all(root).expect("create installation root");
    std::fs::write(
      root.join("Local State"),
      serde_json::to_vec(&value).expect("serialize Local State"),
    )
    .expect("write Local State");
  }

  pub(crate) fn seed_cookie(profile: &Path, network: bool, name: &str, value: &str) -> PathBuf {
    let db = if network {
      profile.join("Network/Cookies")
    } else {
      profile.join("Cookies")
    };
    std::fs::create_dir_all(db.parent().expect("cookie db parent")).expect("create profile");
    let connection = rusqlite::Connection::open(&db).expect("open cookie db");
    connection
      .execute_batch(
        "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
        INSERT INTO meta (key, value) VALUES ('version', '23');
        CREATE TABLE cookies (
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
        rusqlite::params![name, value, Vec::<u8>::new()],
      )
      .expect("insert cookie");
    db
  }

  pub(crate) fn gecko_test_root(context: &DiscoveryContext<RealDiscoveryFs>) -> PathBuf {
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

  pub(crate) fn seed_empty_gecko_database(profile: &Path) {
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
}

#[cfg(test)]
mod tests {
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
    browser_root, channel_root, context_for, gecko_test_root, seed_cookie,
    seed_empty_gecko_database, with_test_fs, TempDir, TestDiscoveryFs,
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
    let (_, warning) = crate::browser::safari::discover_safari_profiles(&canonical_library);
    let warning = warning.expect("missing profile database degrades to directory fallback");
    assert!(matches!(
      &warning,
      crate::browser::safari::SafariProfileDiscoveryIssue::Degraded(_)
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
    let (_, warning) = crate::browser::safari::discover_safari_profiles(&canonical_library);
    let warning = warning.expect("database and directory fallback both fail");
    assert!(matches!(
      &warning,
      crate::browser::safari::SafariProfileDiscoveryIssue::EnumerationFailed(_)
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

    let discovery = discover_safari_with_context(&context, "safari")
      .expect("marker denial keeps Safari detected");

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
    let rows = |_: &Path, _: Option<&[String]>| {
      Ok(InternetExplorerRows {
        records: Vec::new(),
        records_seen: 0,
        records_skipped: 0,
        records_rejected: 0,
        row_error: None,
      })
    };

    let all =
      internet_explorer_report_with_context(&context, "internet_explorer", None, None, rows)
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
      |path, domains| {
        read.push(path.to_path_buf());
        rows(path, domains)
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
    std::fs::write(root.join(INTERNET_EXPLORER_COOKIE_FILE), b"ese")
      .expect("seed WebCache database");

    let outcome =
      internet_explorer_report_with_context(&context, "internet_explorer", None, None, |_, _| {
        Ok(InternetExplorerRows {
          records: Vec::new(),
          records_seen: 2,
          records_skipped: 1,
          records_rejected: 1,
          row_error: Some("invalid WebCache record".to_owned()),
        })
      })
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
    std::fs::write(root.join(INTERNET_EXPLORER_COOKIE_FILE), b"ese")
      .expect("seed WebCache database");

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
  fn missing_non_chromium_roots_are_silent() {
    let temp = TempDir::new("missing-non-chromium-roots");

    let gecko_context = context_for(PlatformId::Linux, temp.path().join("linux-home"), []);
    let gecko =
      discover_gecko_with_context(&gecko_context, "firefox").expect("missing Gecko roots");
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
}
