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
// `acquire_by_policy` interprets `FirstValid` by handing the run to the one
// first-valid rule, which lives in the Mozilla engine and is shared with its
// direct-path walk. The rule must not fork, so the frame borrows it rather
// than restating it; the outcome type comes along until §14b unifies it with
// the `Result<Source>` the other engines answer with.
use super::mozilla;
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
  ///
  /// This deserializes straight into `chromium_platform_keys::ChromiumKeyIdentity`
  /// (PR 7): that struct is both the registry JSON DTO and the runtime identity
  /// type, so there is no separate DTO to keep in sync in this module.
  key_credentials: Option<super::chromium_platform_keys::ChromiumKeyIdentity>,
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
pub(crate) use super::source::{AcquisitionPolicy, SourceAcquisition};

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

/// How an engine finishes an extract whose walk stopped at a boundary.
///
/// The three engines answer this differently, and the answers are frozen: no
/// golden covers a reconciliation, so making them agree would be a behaviour
/// change rather than a refactor. Naming the policy at each call site is the
/// point of this type -- the disagreement stops being an accident of which
/// file each loop happened to be written in and becomes an argument a reviewer
/// can see all three values of at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtractCompletion {
  /// Drop every source the walk never attempted, then every profile the drop
  /// left owning nothing. Gecko and Internet Explorer.
  RetainAttempted,
  /// Keep every source the walk committed; drop only the stopped profile, and
  /// only when it committed no source at all. Safari.
  DropStoppedProfileIfEmpty,
}

impl ExtractCompletion {
  /// Applies the policy to an extract whose walk has just broken on `stop`.
  /// Never called on a walk that ran to completion: the two engines that
  /// truncate do it only for a stop they observed themselves.
  fn apply(self, extract: &mut EngineExtract) {
    match self {
      Self::RetainAttempted => retain_completed_engine_extract(extract),
      // Profiles after the stop never ran and sources hold exactly the queries
      // that completed, so the only thing left to drop is a stopped profile
      // that committed nothing -- it is the profile the loop pushed on its way
      // out, not an extraction failure.
      Self::DropStoppedProfileIfEmpty => {
        if extract
          .profiles
          .last()
          .is_some_and(|profile| profile.sources.is_empty())
        {
          extract.profiles.pop();
        }
      }
    }
  }
}

/// The engine populate frame: the listing-to-extract envelope every engine
/// repeats, with the per-profile acquisition and the stop policy passed in.
///
/// `acquire_profile` is one engine's body. It gets the profile's identity and
/// the candidates discovery planted for it, and answers with the sources it
/// committed plus the boundary stop that ended it, if any. The frame commits
/// the profile *before* honouring that stop, so whatever the body acquired
/// before the boundary is a real outcome; `completion` -- not this loop --
/// decides whether it survives.
///
/// The output is 1:1 with the post-select listing up to the stop: a profile
/// whose candidates produced nothing still appears with `sources: vec![]`, so
/// the report layer can tell a source that vanished before extraction from a
/// browser that was never installed.
pub(crate) fn populate_engine_sources<A>(
  listing: EngineListing,
  completion: ExtractCompletion,
  mut acquire_profile: A,
) -> EngineExtract
where
  A: FnMut(
    &EngineProfileIdentity,
    Vec<SourceCandidate>,
  ) -> (Vec<Source>, Option<crate::common::deadline::BoundaryStop>),
{
  let EngineListing {
    profiles,
    discovery_issues,
    counters,
    boundary_stop,
  } = listing;
  let mut extract = EngineExtract {
    profiles: Vec::with_capacity(profiles.len()),
    discovery_issues,
    counters,
    boundary_stop,
  };
  for profile in profiles {
    let DiscoveredProfile {
      identity,
      legacy,
      candidates,
    } = profile;
    let (sources, stop) = acquire_profile(&identity, candidates);
    extract.profiles.push(ExtractedProfile {
      identity,
      legacy,
      sources,
    });
    if let Some(stop) = stop {
      extract.boundary_stop.get_or_insert(stop);
      completion.apply(&mut extract);
      break;
    }
  }
  extract
}

/// The policy interpreter: acquires one profile's plan in plan order, doing
/// what each entry's [`AcquisitionPolicy`] says.
///
/// This is the per-profile body that used to be Gecko's bespoke walk. Nothing
/// in it is Gecko-specific any more -- the probe and the alternation are read
/// off the candidates rather than known by the caller -- so the engine
/// difference is the plan the caller planted, not the code that runs it.
///
/// * [`AcquisitionPolicy::Fixed`] -- query and commit whatever came back.
/// * [`AcquisitionPolicy::Probe`] -- query, then commit only if the candidate's
///   listing vouched for the path (`exists`) or `exists_now` still finds it.
///   The recheck happens *after* the query and is spent only when listing did
///   not already vouch, so a store that appeared since discovery is committed
///   even when reading it then failed, and one deleted since discovery still
///   reports its failure rather than vanishing.
/// * [`AcquisitionPolicy::FirstValid`] -- the maximal contiguous run starting
///   here is one alternation, handed to [`mozilla::select_session_sources`] as
///   a **lazy** iterator. That laziness is the guarantee: the rule returns at
///   the first success without pulling another outcome, so the candidates after
///   it are never acquired (ADR 0001 §8). Collecting the run's outcomes first
///   would satisfy every content assertion and silently read them all.
///
/// A boundary stop from any entry ends the walk immediately and is returned
/// with whatever was committed before it; entries after the stop are not
/// acquired.
fn acquire_by_policy<Q, E>(
  plan: &[SourceCandidate],
  domains: Option<&[String]>,
  mut query: Q,
  mut exists_now: E,
) -> (Vec<Source>, Option<crate::common::deadline::BoundaryStop>)
where
  Q: FnMut(&SourceCandidate, Option<&[String]>) -> mozilla::MozillaCandidateOutcome,
  E: FnMut(&Path) -> bool,
{
  let mut sources = Vec::new();
  let mut index = 0;
  while let Some(candidate) = plan.get(index) {
    match candidate.policy {
      AcquisitionPolicy::FirstValid => {
        let group = index
          + plan[index..]
            .iter()
            .take_while(|entry| entry.policy == AcquisitionPolicy::FirstValid)
            .count();
        // `map` over a slice iterator, never a collected `Vec`:
        // `select_session_sources` returns on the first selected source without
        // pulling again, so the alternatives behind it are never queried.
        let stop = mozilla::select_session_sources(
          plan[index..group].iter().map(|entry| query(entry, domains)),
          &mut sources,
        );
        if stop.is_some() {
          return (sources, stop);
        }
        index = group;
      }
      AcquisitionPolicy::Fixed | AcquisitionPolicy::Probe => {
        index += 1;
        match query(candidate, domains) {
          mozilla::MozillaCandidateOutcome::Source(source) => {
            // `Fixed` commits unconditionally. `Probe` asked for the read
            // whether or not the path was planted, so it owes the existence
            // question an answer -- taken from listing when listing vouched,
            // and from the filesystem only otherwise.
            if candidate.policy == AcquisitionPolicy::Fixed
              || candidate.exists
              || exists_now(&candidate.path)
            {
              sources.push(source);
            }
          }
          // Absence is normal and silent: a candidate that is not there is not
          // an outcome, so there is nothing to commit.
          mozilla::MozillaCandidateOutcome::Missing => {}
          mozilla::MozillaCandidateOutcome::Stop(stop) => return (sources, Some(stop)),
        }
      }
    }
  }
  (sources, None)
}

/// The 1:1 per-profile body Safari and Internet Explorer share: acquire every
/// candidate in turn, and record a failed query on the candidate's own
/// placeholder rather than losing it.
///
/// This is [`AcquisitionPolicy::Fixed`] over a whole plan, spelled separately
/// because these two engines answer with `Result<Source>` rather than a
/// [`mozilla::MozillaCandidateOutcome`]; folding them into
/// [`acquire_by_policy`] is the outcome-type unification of §14b, not this
/// change. Their candidates still carry `Fixed`, so the plan says what they do.
///
/// `fill_failure` is the only difference left between those two engines -- how
/// a non-boundary `Err` is written onto the placeholder. The deadline is the
/// other half of the shape: `runtime` is sampled before and after every
/// candidate, so a stop can end the walk on its own rather than only when the
/// next query happens to surface one through its error chain. The query result
/// is committed before the trailing sample, so a stop that races with the
/// return cannot discard records and counters that already completed.
///
/// Only reachable through the safari/internet_explorer engine adapters, whose
/// modules are compiled on macOS/Windows and in tests; other targets see this
/// as dead. registry.rs's cfg ceiling (#218) keeps the gate out of this file.
#[allow(dead_code)]
fn acquire_each_candidate<Q, F>(
  candidates: Vec<SourceCandidate>,
  domains: Option<&[String]>,
  runtime: Option<&crate::common::deadline::BoundaryRuntime<'_>>,
  mut query: Q,
  mut fill_failure: F,
) -> (Vec<Source>, Option<crate::common::deadline::BoundaryStop>)
where
  Q: FnMut(SourceCandidate, Option<&[String]>) -> Result<Source>,
  F: FnMut(&mut Source, anyhow::Error),
{
  let mut sources = Vec::new();
  for candidate in candidates {
    if let Some(stop) = runtime.and_then(|runtime| runtime.check().err()) {
      return (sources, Some(stop));
    }
    let mut source = Source::new(
      candidate.identity(),
      candidate.selected,
      candidate.acquisition,
    );
    match query(candidate, domains) {
      // The engine already built the `Source` from this candidate, so there is
      // nothing to copy across.
      Ok(extraction) => source = extraction,
      Err(error) => {
        if let Some(stop) = boundary_stop_from_error(&error) {
          // `source` is dropped uncommitted: the query did not return, so
          // there is no outcome to report for it.
          return (sources, Some(stop));
        }
        fill_failure(&mut source, error);
      }
    }
    sources.push(source);
    if let Some(stop) = runtime.and_then(|runtime| runtime.check().err()) {
      return (sources, Some(stop));
    }
  }
  (sources, None)
}

// Only reachable through the safari/internet_explorer engine adapters, whose
// modules are compiled on macOS/Windows and in tests; other targets see this
// as dead. registry.rs's cfg ceiling (#218) keeps the gate out of this file.
#[allow(dead_code)]
fn boundary_stop_from_error(
  error: &anyhow::Error,
) -> Option<crate::common::deadline::BoundaryStop> {
  error.chain().find_map(|cause| {
    cause
      .downcast_ref::<crate::common::deadline::BoundaryStop>()
      .copied()
  })
}

// See `boundary_stop_from_error`: only reachable through the safari and
// internet_explorer engine adapters.
#[allow(dead_code)]
fn retain_engine_runtime_stop(
  mut extract: EngineExtract,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> EngineExtract {
  if let Err(stop) = runtime.check() {
    extract.boundary_stop.get_or_insert(stop);
  }
  if extract.boundary_stop.is_some() {
    retain_completed_engine_extract(&mut extract);
  }
  extract
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
  ChromiumExtractedProfile, ChromiumProfile, ChromiumRegistryDraft,
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
pub(crate) use internet_explorer::extracted_internet_explorer_source;
#[cfg(target_os = "windows")]
pub(crate) use internet_explorer::{
  internet_explorer_profiles_with_runtime, internet_explorer_report_with_runtime,
  legacy_internet_explorer_outcome_with_runtime,
};

/// Context-injected engine seams for the cross-engine report tests. They keep
/// fixtures on temporary roots instead of mutating the process environment.
#[cfg(test)]
pub(crate) mod test_seams;

#[cfg(test)]
mod tests;
