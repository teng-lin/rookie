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
struct BrowserCapabilityDescriptor {
  declared_persistent_formats: Vec<String>,
  declared_session_formats: Vec<String>,
  declared_decryption_tiers: Vec<String>,
  available_decryption_tiers: Vec<String>,
}

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
enum PlatformId {
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
struct RealDiscoveryFs;

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

struct DiscoveryContext<F> {
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
        issues.push(DiscoveryIssue {
          code: "local_state_invalid",
          path: installation.local_state_path.clone(),
          message: error.to_string(),
        });
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
      issues.push(DiscoveryIssue {
        code: "profile_has_no_cookie_source",
        path: profile_path,
        message: "profile marker has no Chromium cookie source".to_owned(),
      });
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
      issues.push(DiscoveryIssue {
        code: "profile_has_no_cookie_source",
        path: profile_path,
        message: "profile marker has no Chromium cookie source".to_owned(),
      });
      continue;
    }
    let canonical_path = match context.fs.canonicalize(&profile_path) {
      Ok(path) => path,
      Err(error) => {
        issues.push(DiscoveryIssue {
          code: "profile_canonicalize_failed",
          path: profile_path,
          message: error.to_string(),
        });
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
          issues.push(DiscoveryIssue {
            code: "profile_source_canonicalize_failed",
            path: selected_source.path.clone(),
            message: error.to_string(),
          });
          continue;
        }
      }
    } else {
      normalized_path_bytes(&canonical_path)
    };
    if !seen_profiles.insert(canonical_key) {
      issues.push(DiscoveryIssue {
        code: "duplicate_profile",
        path: canonical_path,
        message: "profile is already owned by an earlier registry root".to_owned(),
      });
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
        discovery.issues.push(DiscoveryIssue {
          code: "installation_glob_failed",
          path: resolved_root.base.join(&resolved_root.suffix),
          message: error.to_string(),
        });
        continue;
      }
    };
    let expansion_had_issues = !expansion.issues.is_empty();
    for issue in expansion.issues.drain(..) {
      discovery.issues.push(DiscoveryIssue {
        code: "installation_glob_expand_failed",
        path: issue.path,
        message: issue.message,
      });
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
          discovery.issues.push(DiscoveryIssue {
            code: "installation_metadata_failed",
            path: resolved,
            message: error.to_string(),
          });
          continue;
        }
      }
      discovery.detected_roots += 1;
      let canonical_path = match context.fs.canonicalize(&resolved) {
        Ok(path) => path,
        Err(error) => {
          discovery.issues.push(DiscoveryIssue {
            code: "installation_canonicalize_failed",
            path: resolved,
            message: error.to_string(),
          });
          continue;
        }
      };
      let installation_key = normalized_path_bytes(&canonical_path);
      if !seen_installations.insert(installation_key.clone()) {
        discovery.issues.push(DiscoveryIssue {
          code: "duplicate_installation",
          path: canonical_path,
          message: "installation is already owned by an earlier registry root".to_owned(),
        });
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
              discovery.issues.push(DiscoveryIssue {
                code: "installation_enumeration_failed",
                path: installation.path.clone(),
                message: error.to_string(),
              });
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
  pub(crate) error: Option<String>,
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
  pub(crate) discovery_issues: Vec<DiscoveryIssue>,
}

fn sort_cookies(cookies: &mut [Cookie]) {
  cookies.sort_by(|left, right| {
    left
      .domain
      .cmp(&right.domain)
      .then_with(|| left.path.cmp(&right.path))
      .then_with(|| left.name.cmp(&right.name))
      .then_with(|| left.expires.cmp(&right.expires))
      .then_with(|| left.secure.cmp(&right.secure))
      .then_with(|| left.http_only.cmp(&right.http_only))
      .then_with(|| left.same_site.cmp(&right.same_site))
      .then_with(|| left.value.cmp(&right.value))
  });
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
          error: Some("profile has no selected persistent source".to_owned()),
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
            error: outcome.legacy_error.map(|error| error.to_string()),
          });
        }
        Err(error) => profile_extractions.push(ChromiumProfileExtraction {
          profile,
          cookies: Vec::new(),
          stats: ChromiumExtractionStats::default(),
          row_issues: Vec::new(),
          error: Some(error.to_string()),
        }),
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
      let Some(config) = crate::config::try_get_browser_config(&installation.browser_id) else {
        return ChromiumKeyOutcomes {
          v10: ChromiumKeyOutcome::failure(format!(
            "no legacy key configuration for browser {:?}",
            installation.browser_id
          )),
          v11: ChromiumKeyOutcome::failure(format!(
            "no legacy key configuration for browser {:?}",
            installation.browser_id
          )),
          v20: ChromiumKeyOutcome::NotApplicable,
        };
      };
      let provider = LinuxPlatformKeyProvider::new(config);
      return retrieve_key_outcomes(&provider, &());
    }

    #[cfg(target_os = "macos")]
    {
      let Some(config) = crate::config::try_get_browser_config(&installation.browser_id) else {
        return ChromiumKeyOutcomes {
          v10: ChromiumKeyOutcome::failure(format!(
            "no legacy key configuration for browser {:?}",
            installation.browser_id
          )),
          v11: ChromiumKeyOutcome::NotApplicable,
          v20: ChromiumKeyOutcome::NotApplicable,
        };
      };
      let provider = MacosPlatformKeyProvider::new(config);
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

/// Source-level outcome shared by the non-Chromium adapters. It is deliberately
/// crate-private: 4E owns the final cross-engine DTO freeze.
#[derive(Debug)]
pub(crate) struct EngineSourceExtraction {
  pub(crate) path: PathBuf,
  pub(crate) format: &'static str,
  pub(crate) selected: bool,
  pub(crate) cookies: Vec<Cookie>,
  pub(crate) rows_seen: usize,
  pub(crate) rows_skipped: usize,
  pub(crate) acquisition_strategy: Option<DatabaseAcquisitionStrategy>,
  pub(crate) acquisition_attempts: u32,
  pub(crate) diagnostics: Vec<String>,
  pub(crate) error: Option<String>,
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
  /// Session candidates discovery saw on disk. Extraction needs this to tell a
  /// candidate that vanished under it from one that was never there.
  pub(crate) session_sources_discovered: Vec<PathBuf>,
  pub(crate) sources: Vec<EngineSourceExtraction>,
}

#[derive(Debug, Default)]
pub(crate) struct EngineExtractionOutcome {
  pub(crate) profiles: Vec<EngineProfileExtraction>,
  pub(crate) discovery_issues: Vec<DiscoveryIssue>,
}

fn discovered_session_sources<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  path: &Path,
) -> Vec<PathBuf> {
  mozilla::session_candidate_paths(path)
    .into_iter()
    .filter(|candidate| context.fs.exists(candidate))
    .collect()
}

fn gecko_profile_has_source<F: DiscoveryFs>(context: &DiscoveryContext<F>, path: &Path) -> bool {
  context.fs.exists(&path.join("cookies.sqlite"))
    || !discovered_session_sources(context, path).is_empty()
}

const MAX_GECKO_DISCOVERY_ISSUES_PER_CODE: usize = 32;

fn push_bounded_gecko_issue(
  issues: &mut Vec<DiscoveryIssue>,
  code: &'static str,
  path: PathBuf,
  message: &str,
) {
  if let Some(summary) = issues
    .iter_mut()
    .find(|issue| issue.code == code && issue.message.starts_with("additional "))
  {
    let omitted = summary
      .message
      .split_whitespace()
      .nth(1)
      .and_then(|count| count.parse::<usize>().ok())
      .unwrap_or(1)
      + 1;
    summary.message = format!(
      "additional {omitted} {code} diagnostics omitted after {MAX_GECKO_DISCOVERY_ISSUES_PER_CODE} samples"
    );
    return;
  }
  let sampled = issues.iter().filter(|issue| issue.code == code).count();
  if sampled < MAX_GECKO_DISCOVERY_ISSUES_PER_CODE {
    issues.push(DiscoveryIssue {
      code,
      path,
      message: message.to_owned(),
    });
  } else if sampled == MAX_GECKO_DISCOVERY_ISSUES_PER_CODE {
    issues.push(DiscoveryIssue {
      code,
      path,
      message: format!(
        "additional 1 {code} diagnostics omitted after {MAX_GECKO_DISCOVERY_ISSUES_PER_CODE} samples"
      ),
    });
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfilesIniState {
  Absent,
  Empty,
  Invalid,
  Declared,
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
    let canonical_root = match context.fs.canonicalize(&root_path) {
      Ok(path) => path,
      Err(error) => {
        outcome.discovery_issues.push(DiscoveryIssue {
          code: "installation_canonicalize_failed",
          path: root_path,
          message: error.to_string(),
        });
        continue;
      }
    };
    let installation_id = installation_id(
      &definition.canonical_id,
      &root.root_id,
      &root.channel,
      &normalized_path_bytes(&canonical_root),
    );
    let ini_path = canonical_root.join("profiles.ini");
    let (declared, ini_state) = if context.fs.exists(&ini_path) {
      match mozilla::list_profiles(&ini_path) {
        Ok(profiles) if profiles.is_empty() => (profiles, ProfilesIniState::Empty),
        Ok(profiles) => (profiles, ProfilesIniState::Declared),
        Err(error) => {
          outcome.discovery_issues.push(DiscoveryIssue {
            code: "mozilla_profiles_ini_invalid",
            path: ini_path,
            message: error.to_string(),
          });
          (Vec::new(), ProfilesIniState::Invalid)
        }
      }
    } else {
      (Vec::new(), ProfilesIniState::Absent)
    };

    let mut usable = Vec::new();
    for declared_profile in declared {
      if !gecko_profile_has_source(context, &declared_profile.path) {
        push_bounded_gecko_issue(
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
          name: String::new(),
          path: canonical_root.clone(),
          is_default: matches!(
            ini_state,
            ProfilesIniState::Absent | ProfilesIniState::Empty
          ),
        });
      } else {
        match markerless_gecko_profiles(context, &canonical_root) {
          Ok(discovery) => {
            usable = discovery.profiles;
            if let Some(error) = discovery.optional_container_error {
              outcome.discovery_issues.push(DiscoveryIssue {
                code: "optional_profiles_enumeration_failed",
                path: canonical_root.join("Profiles"),
                message: error.to_string(),
              });
            }
          }
          Err(error) => outcome.discovery_issues.push(DiscoveryIssue {
            code: "installation_enumeration_failed",
            path: canonical_root.clone(),
            message: error.to_string(),
          }),
        }
      }
    }

    for declared_profile in usable {
      let profile_path = match context.fs.canonicalize(&declared_profile.path) {
        Ok(path) => path,
        Err(error) => {
          outcome.discovery_issues.push(DiscoveryIssue {
            code: "profile_canonicalize_failed",
            path: declared_profile.path,
            message: error.to_string(),
          });
          continue;
        }
      };
      if !seen_profiles.insert(normalized_path_bytes(&profile_path)) {
        push_bounded_gecko_issue(
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
        session_sources_discovered: discovered_session_sources(context, &profile_path),
        path: profile_path,
        is_default: declared_profile.is_default,
        sources: Vec::new(),
      });
    }
  }
  outcome.profiles.sort_by(|left, right| {
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
  Ok(outcome)
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
  ))
}

fn populate_gecko_sources<Q>(
  mut outcome: EngineExtractionOutcome,
  domains: Option<&[String]>,
  mut query: Q,
) -> EngineExtractionOutcome
where
  Q: FnMut(&Path, Option<&[String]>, &[PathBuf]) -> mozilla::MozillaEngineExtractionOutcome,
{
  for profile in &mut outcome.profiles {
    let persistent = profile.path.join("cookies.sqlite");
    // The Mozilla outcome also owns session fallback. Only a persistent DB
    // that discovery never saw and that is still not on disk is an absence:
    // that is a session-only profile, not a source. One that reads back is
    // real data no matter what discovery saw a moment earlier, and one that
    // is on disk but will not open is a typed failure worth reporting rather
    // than a source to drop silently.
    let mut extraction = query(&persistent, domains, &profile.session_sources_discovered);
    if profile.persistent_source_discovered
      || extraction.persistent_error.is_none()
      || persistent.exists()
    {
      sort_cookies(&mut extraction.persistent_cookies);
      profile.sources.push(EngineSourceExtraction {
        path: persistent,
        format: "mozilla_sqlite",
        selected: true,
        rows_seen: extraction.persistent_rows_seen,
        rows_skipped: extraction.persistent_rows_skipped,
        cookies: extraction.persistent_cookies,
        acquisition_strategy: extraction.persistent_acquisition_strategy,
        acquisition_attempts: extraction.persistent_acquisition_attempts,
        diagnostics: extraction.persistent_diagnostics,
        error: extraction.persistent_error,
      });
    }
    profile
      .sources
      .extend(extraction.session_sources.into_iter().map(|mut source| {
        sort_cookies(&mut source.cookies);
        EngineSourceExtraction {
          path: source.path,
          format: source.format,
          selected: source.selected,
          rows_seen: source.rows_seen,
          rows_skipped: source.rows_skipped,
          cookies: source.cookies,
          acquisition_strategy: None,
          acquisition_attempts: source.acquisition_attempts,
          diagnostics: source.diagnostics,
          error: source.error,
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
    let ini = (0..MAX_GECKO_DISCOVERY_ISSUES_PER_CODE + 5)
      .map(|index| format!("[Profile{index}]\nName=duplicate-{index}\nPath=Profiles/shared\n"))
      .collect::<String>();
    std::fs::write(root.join("profiles.ini"), ini).expect("write duplicate declarations");

    let report = discover_gecko_with_context(&context, "firefox").expect("discover duplicates");
    assert_eq!(report.profiles.len(), 1);
    assert_eq!(
      report
        .discovery_issues
        .iter()
        .filter(|issue| issue.code == "duplicate_profile")
        .count(),
      MAX_GECKO_DISCOVERY_ISSUES_PER_CODE + 1
    );
    let summary = report
      .discovery_issues
      .iter()
      .find(|issue| issue.code == "duplicate_profile" && issue.message.starts_with("additional "))
      .expect("duplicate overflow summary");
    assert!(summary.message.contains("additional 4 duplicate_profile"));
  }

  #[test]
  fn missing_source_gecko_issues_are_bounded_with_an_overflow_summary() {
    let temp = TempDir::new("gecko-missing-source-bound");
    let context = test_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    std::fs::create_dir_all(&root).expect("create Firefox root");
    let ini = (0..MAX_GECKO_DISCOVERY_ISSUES_PER_CODE + 5)
      .map(|index| format!("[Profile{index}]\nName=stale-{index}\nPath=Profiles/stale-{index}\n"))
      .collect::<String>();
    std::fs::write(root.join("profiles.ini"), ini).expect("write stale declarations");

    let report = discover_gecko_with_context(&context, "firefox").expect("discover stale profiles");
    let issues = report
      .discovery_issues
      .iter()
      .filter(|issue| issue.code == "profile_has_no_cookie_source")
      .collect::<Vec<_>>();
    assert_eq!(issues.len(), MAX_GECKO_DISCOVERY_ISSUES_PER_CODE + 1);
    assert!(issues
      .last()
      .expect("overflow summary")
      .message
      .contains("additional 5 profile_has_no_cookie_source"));
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
    let report = populate_gecko_sources(discovery, None, |persistent, domains, sessions| {
      if !removed {
        removed = true;
        std::fs::remove_file(persistent).expect("remove discovered source");
      }
      mozilla::query_cookies_engine_outcome(persistent, domains, sessions)
    });
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
  fn discovered_session_source_remains_projected_if_it_disappears_before_extraction() {
    let temp = TempDir::new("gecko-session-disappears");
    let context = test_context(temp.path().to_path_buf());
    let root = gecko_test_root(&context);
    let profile = root.join("Profiles/session-only");
    let candidate = profile.join("sessionstore-backups/recovery.jsonlz4");
    std::fs::create_dir_all(candidate.parent().expect("session dir")).expect("create profile");
    std::fs::write(&candidate, b"a real session store lived here").expect("write session");
    std::fs::write(
      root.join("profiles.ini"),
      "[Profile0]\nName=session\nPath=Profiles/session-only\nDefault=1\n",
    )
    .expect("write profiles.ini");
    let discovery = discover_gecko_with_context(&context, "firefox").expect("discover profile");
    assert_eq!(discovery.profiles[0].session_sources_discovered.len(), 1);

    let report = populate_gecko_sources(discovery, None, |persistent, domains, sessions| {
      std::fs::remove_file(&candidate).expect("remove discovered session candidate");
      mozilla::query_cookies_engine_outcome(persistent, domains, sessions)
    });
    let sources = &report.profiles[0].sources;
    assert_eq!(
      sources.len(),
      1,
      "a profile admitted on a session candidate must not extract as sourceless: {sources:?}"
    );
    assert_eq!(sources[0].format, "firefox_session_jsonlz4");
    assert!(!sources[0].selected);
    assert!(sources[0].error.is_some());
  }

  #[test]
  fn undiscovered_persistent_source_is_projected_when_the_query_succeeds() {
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

    let report = populate_gecko_sources(discovery, None, |persistent, domains, sessions| {
      let profile = persistent.parent().expect("profile directory");
      seed_empty_gecko_database(profile);
      rusqlite::Connection::open(persistent)
        .expect("open created database")
        .execute(
          "INSERT INTO moz_cookies VALUES ('.example.com', '/', 1, 0, 'created-late', 'v', 1, 0)",
          [],
        )
        .expect("seed created database");
      mozilla::query_cookies_engine_outcome(persistent, domains, sessions)
    });
    let sources = &report.profiles[0].sources;
    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0].format, "mozilla_sqlite");
    assert!(sources[0].selected);
    assert!(sources[0].error.is_none(), "{:?}", sources[0].error);
    assert_eq!(sources[0].cookies[0].name, "created-late");
    assert_eq!(sources[1].format, "firefox_session_jsonlz4");
  }

  #[test]
  fn undiscovered_persistent_source_stays_absent_when_the_query_fails() {
    let temp = TempDir::new("gecko-persistent-absent");
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

    let report = populate_gecko_sources(discovery, None, mozilla::query_cookies_engine_outcome);
    let sources = &report.profiles[0].sources;
    assert_eq!(
      sources.len(),
      1,
      "a session-only profile must not gain a phantom persistent source: {sources:?}"
    );
    assert_eq!(sources[0].format, "firefox_session_jsonlz4");
  }

  #[test]
  fn undiscovered_persistent_source_is_projected_when_it_appears_but_will_not_open() {
    let temp = TempDir::new("gecko-persistent-appears-broken");
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

    let report = populate_gecko_sources(discovery, None, |persistent, domains, sessions| {
      std::fs::write(persistent, b"this is not a sqlite database").expect("write broken database");
      mozilla::query_cookies_engine_outcome(persistent, domains, sessions)
    });
    let sources = &report.profiles[0].sources;
    assert_eq!(
      sources.len(),
      2,
      "a source that appeared but cannot be opened is a failure, not an absence: {sources:?}"
    );
    assert_eq!(sources[0].format, "mozilla_sqlite");
    assert!(sources[0].selected);
    assert!(sources[0].error.is_some());
    assert!(sources[0].cookies.is_empty());
    assert_eq!(sources[1].format, "firefox_session_jsonlz4");
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
      sources[0].acquisition_strategy,
      Some(DatabaseAcquisitionStrategy::LiveReadOnly)
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
      self
        .canonical_aliases
        .get(path)
        .cloned()
        .map(Ok)
        .unwrap_or_else(|| RealDiscoveryFs.canonicalize(path))
    }

    fn read_to_string(&self, path: &Path) -> Result<String> {
      RealDiscoveryFs.read_to_string(path)
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
    assert!(broken.error.is_some());
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
    assert!(extraction.error.is_none());
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
