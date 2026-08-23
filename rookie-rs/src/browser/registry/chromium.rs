use super::super::chromium::acquire_chromium_source_with_runtime;
#[cfg(all(test, target_os = "macos"))]
use super::super::chromium_crypto::ChromiumKeyOutcome;
use super::super::chromium_crypto::{retrieve_key_outcomes, ChromiumKeyOutcomes, KeyProvider};
#[cfg(test)]
use super::super::chromium_platform_keys::MacosKeychainCredentials;
use super::super::chromium_platform_keys::{
  ChromiumKeyIdentity, ChromiumKeyRequest, HostKeySession,
};
use super::super::report_core::{
  CookieSourceFormatId, CookieSourceRoleId, InstallationId, ProfileId,
};
use super::{
  browser_definition, embedded_registry, installation_id, is_informational_discovery_issue,
  normalized_path_bytes, profile_id, AcquisitionPolicy, BrowserDefinition, BrowserEngine,
  DiscoveryContext, DiscoveryFs, DiscoveryIssue, DiscoveryStrategy, InstallationRoot, PlatformId,
  ProfileLocator, ProfileSelection, Source, SourceAcquisition, SourceCandidate, SourceFailureStage,
  SourceIssue, MAX_DISCOVERY_ISSUE_SAMPLES,
};
#[cfg(test)]
use super::{
  capability_descriptor, registered_browsers_for, GlobExpansion, GlobExpansionIssue,
  RealDiscoveryFs,
};
use crate::common::diagnostic::REDACTED_PATH;
#[cfg(test)]
use crate::common::enums::Cookie;
use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum LegacyChromiumProfileLayout {
  #[default]
  DefaultAndProfiles,
  DefaultOnly,
  FlatAndDefault,
  DefaultAndFlat,
}

/// The `legacy_profile_layout` names a registry root may declare.
const LEGACY_PROFILE_LAYOUT_NAMES: &[&str] = &[
  "default_and_profiles",
  "default_only",
  "flat_and_default",
  "default_and_flat",
];

/// Retired in favour of `flat_and_default`.
///
/// `flat_only` and `flat_and_default` rank the flat installation root
/// identically; they differ only in that `flat_only` refuses to fall back to a
/// sibling `Default` directory. Opera was the sole declarant, and that refusal
/// was exactly the discovery defect `e72304b` fixed -- Opera does keep a
/// `Default` profile. Because `flat_and_default` behaves identically to
/// `flat_only` whenever no `Default` directory exists, the only shape the two
/// disagree about is the one shown to be wrong, so the name is rejected rather
/// than silently accepted or silently defaulted.
const RETIRED_FLAT_ONLY: &str = "flat_only";

impl<'de> Deserialize<'de> for LegacyChromiumProfileLayout {
  fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    // Hand-written rather than derived so the retired name gets a migration
    // pointer instead of serde's bare unknown-variant list. Every other
    // unrecognized name still fails, so no value can silently become the
    // `#[serde(default)]` layout -- absence is the only path to that default.
    let name = String::deserialize(deserializer)?;
    match name.as_str() {
      "default_and_profiles" => Ok(Self::DefaultAndProfiles),
      "default_only" => Ok(Self::DefaultOnly),
      "flat_and_default" => Ok(Self::FlatAndDefault),
      "default_and_flat" => Ok(Self::DefaultAndFlat),
      RETIRED_FLAT_ONLY => Err(serde::de::Error::custom(format!(
        "legacy_profile_layout {RETIRED_FLAT_ONLY:?} was retired; declare \"flat_and_default\", \
         which ranks the flat installation root first and then falls back to \"Default\""
      ))),
      other => Err(serde::de::Error::unknown_variant(
        other,
        LEGACY_PROFILE_LAYOUT_NAMES,
      )),
    }
  }
}

/// Enforces the Section 5.9 credential rules.
///
/// A blank credential fails exactly like an absent one at runtime: Linux
/// filters an empty crypt name to `NotApplicable`, and macOS would issue a
/// Keychain query with an empty service or account. Both are therefore rejected
/// at registry load rather than surfacing as a runtime surprise.
pub(super) fn validate_key_credentials(
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChromiumProfile {
  pub(crate) profile_id: ProfileId,
  pub(crate) installation_id: InstallationId,
  pub(crate) directory_name: String,
  pub(crate) display_name: String,
  pub(crate) path: PathBuf,
  pub(crate) is_default: bool,
  pub(crate) is_active: bool,
  pub(crate) active_order: Option<u32>,
  pub(crate) is_last_used: bool,
  pub(crate) persistent_candidates: Vec<SourceCandidate>,
}

impl ChromiumProfile {
  fn selected_source(&self) -> Option<&Path> {
    self
      .persistent_candidates
      .iter()
      .find(|candidate| candidate.selected)
      .map(|candidate| candidate.path.as_path())
  }

  fn selected_source_precedence(&self) -> Option<u16> {
    self
      .persistent_candidates
      .iter()
      .find(|candidate| candidate.selected)
      .map(|candidate| candidate.precedence)
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BrowserInstallation {
  installation_id: String,
  browser_id: String,
  root_id: String,
  channel: String,
  path: PathBuf,
  local_state_path: PathBuf,
  /// Parsed by the Windows compatibility prerequisite and reused by the
  /// system provider so the query cannot race a second Local State read.
  legacy_local_state: Option<serde_json::Value>,
  key_credentials: ChromiumKeyIdentity,
  priority: u16,
  /// Registry-authored ordering used only by the compatibility named APIs.
  /// Generic reports continue to use `priority`.
  legacy_priority: u16,
  legacy_profile_layout: LegacyChromiumProfileLayout,
  profiles: Vec<ChromiumProfile>,
}

fn legacy_chromium_profile_group(
  layout: LegacyChromiumProfileLayout,
  directory_name: &str,
) -> Option<u8> {
  match (layout, directory_name) {
    (LegacyChromiumProfileLayout::DefaultAndProfiles, "Default")
    | (LegacyChromiumProfileLayout::DefaultOnly, "Default")
    | (LegacyChromiumProfileLayout::DefaultAndFlat, "Default") => Some(0),
    (LegacyChromiumProfileLayout::DefaultAndProfiles, name) if name.starts_with("Profile ") => {
      Some(1)
    }
    (LegacyChromiumProfileLayout::FlatAndDefault, ".") => Some(0),
    (LegacyChromiumProfileLayout::FlatAndDefault, "Default") => Some(1),
    (LegacyChromiumProfileLayout::DefaultAndFlat, ".") => Some(1),
    _ => None,
  }
}

fn add_legacy_flat_chromium_profiles<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  discovery: &mut ChromiumDiscovery,
) {
  for installation in &mut discovery.installations {
    if !matches!(
      installation.legacy_profile_layout,
      LegacyChromiumProfileLayout::FlatAndDefault | LegacyChromiumProfileLayout::DefaultAndFlat
    ) || installation
      .profiles
      .iter()
      .any(|profile| profile.directory_name == ".")
      || !profile_has_source(context, &installation.path)
    {
      continue;
    }

    installation.profiles.push(ChromiumProfile {
      profile_id: profile_id(
        &installation.installation_id,
        ProfileLocator::Relative(Path::new(".")),
      ),
      installation_id: InstallationId::known(&installation.installation_id),
      directory_name: ".".to_owned(),
      display_name: installation.channel.clone(),
      path: installation.path.clone(),
      is_default: true,
      is_active: false,
      active_order: None,
      is_last_used: false,
      persistent_candidates: persistent_candidates(context, &installation.path),
    });
  }
}

#[derive(Debug, Default)]
pub(super) struct ChromiumDiscovery {
  installations: Vec<BrowserInstallation>,
  pub(super) issues: Vec<DiscoveryIssue>,
  pub(super) detected_roots: usize,
  enumerated_roots: usize,
}

impl ChromiumDiscovery {
  pub(super) fn profiles(&self) -> Vec<ChromiumProfile> {
    self
      .installations
      .iter()
      .flat_map(|installation| installation.profiles.iter().cloned())
      .collect()
  }

  pub(super) fn all_detected_roots_failed(&self) -> bool {
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

fn persistent_candidates<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  profile_path: &Path,
) -> Vec<SourceCandidate> {
  let mut candidates = vec![
    persistent_candidate(profile_path.join("Network/Cookies"), 10),
    persistent_candidate(profile_path.join("Cookies"), 20),
  ];
  let mut selected = false;
  for candidate in &mut candidates {
    candidate.exists = context.fs.exists(&candidate.path);
    candidate.selected = candidate.exists && !selected;
    selected |= candidate.selected;
  }
  candidates
}

/// A Chromium persistent cookie database that discovery has not stat'd yet.
///
/// `exists` and `selected` are decided by the caller once the filesystem has
/// been read. `acquisition` is listing metadata and stays `NotAttempted` for
/// this engine: Chromium never freezes a strategy at listing time, and the
/// value a query actually used lands on `Source::acquisition`.
fn persistent_candidate(path: PathBuf, precedence: u16) -> SourceCandidate {
  SourceCandidate {
    path,
    role: CookieSourceRoleId::persistent(),
    format: CookieSourceFormatId::known("chromium_sqlite"),
    precedence,
    exists: false,
    selected: false,
    acquisition: SourceAcquisition::NotAttempted,
    // Chromium's plan holds only entries discovery stat'd and kept, so every
    // one of them is read unconditionally; the `!exists` skip happens when the
    // plan is built, not when it is executed.
    policy: AcquisitionPolicy::Fixed,
  }
}

fn profile_has_source<F: DiscoveryFs>(context: &DiscoveryContext<F>, path: &Path) -> bool {
  context.fs.exists(&path.join("Network/Cookies")) || context.fs.exists(&path.join("Cookies"))
}

/// Resolves and validates the `Local State` file the deleted Windows named
/// selector required before it attempted a cookie query.
///
/// The lookup is intentionally relative to the selected database, preserving
/// the historical Default, Network, and flat Opera layouts. Generic reports do
/// not call this gate: they may still return plaintext rows while reporting key
/// failures for encrypted rows.
fn legacy_windows_local_state<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  source: &Path,
) -> Result<Option<(PathBuf, serde_json::Value)>> {
  if context.platform != PlatformId::Windows {
    return Ok(None);
  }
  let parent = source
    .parent()
    .ok_or_else(|| anyhow!("Chromium cookie database has no parent: {REDACTED_PATH}"))?;
  let candidates =
    ["../../Local State", "../Local State", "Local State"].map(|relative| parent.join(relative));
  let local_state = candidates
    .iter()
    .find(|candidate| context.fs.exists(candidate))
    .ok_or_else(|| {
      anyhow!("can't find Local State for Chromium cookie database {REDACTED_PATH}")
    })?;
  let canonical = context
    .fs
    .canonicalize(local_state)
    .context("canonicalize Local State")?;
  let contents = context
    .fs
    .read_to_string(&canonical)
    .with_context(|| format!("read Local State {REDACTED_PATH}"))?;
  let value =
    serde_json::from_str::<serde_json::Value>(&contents).context("Can't read Local State JSON")?;
  Ok(Some((canonical, value)))
}

// Tencent-derived forks (QQ Browser, Sogou Explorer) write their profile
// settings to `Preferences_02` and never create a plain `Preferences`.
const CHROMIUM_PROFILE_MARKER_FILES: [&str; 2] = ["Preferences", "Preferences_02"];

// Names Chromium reserves next to real profiles in `profile_manager.cc`.
// Neither holds a user cookie store.
const CHROMIUM_NON_PROFILE_DIRECTORIES: [&str; 2] = ["System Profile", "Guest Profile"];

fn has_profile_marker_file<F: DiscoveryFs>(context: &DiscoveryContext<F>, path: &Path) -> bool {
  CHROMIUM_PROFILE_MARKER_FILES.iter().any(|marker| {
    let marker = path.join(marker);
    context.fs.exists(&marker) && !context.fs.is_dir(&marker)
  })
}

fn is_chromium_service_directory(name: &str) -> bool {
  CHROMIUM_NON_PROFILE_DIRECTORIES.contains(&name)
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

  // A source-bearing installation root is itself a flat profile. Name markers
  // are authoritative and keep their documented precedence over it, but a file
  // marker is only a heuristic and must never promote a sibling directory into
  // shadowing the real flat profile.
  let root_has_source = profile_has_source(context, &installation.path);

  let mut marked = Vec::new();
  let mut markerless_candidates = Vec::new();
  for child in &children {
    if !context.fs.is_dir(child) {
      continue;
    }
    let name = child
      .file_name()
      .map(|name| name.to_string_lossy().into_owned())
      .unwrap_or_default();
    if marker_names.contains(&name) || name.starts_with("Profile ") {
      marked.push((child.clone(), true));
      continue;
    }
    let has_source = profile_has_source(context, child);
    if is_chromium_service_directory(&name) {
      // Reserved names are never user profiles, but a directory that would
      // otherwise have been treated as one must not vanish without a trace.
      if has_source || has_profile_marker_file(context, child) {
        issues.push(DiscoveryIssue::new(
          "profile_excluded_service_directory",
          child.clone(),
          "reserved Chromium service directory is not treated as a profile",
        ));
      }
      continue;
    }
    if !root_has_source && has_profile_marker_file(context, child) {
      marked.push((child.clone(), false));
    }
    if has_source {
      markerless_candidates.push(child.clone());
    }
  }

  let mut source_bearing_marked = Vec::new();
  for (profile_path, name_marked) in marked {
    if profile_has_source(context, &profile_path) {
      source_bearing_marked.push(profile_path);
    } else if name_marked {
      // Only a declared profile is expected to carry a cookie source. A file
      // marker is a heuristic, so a miss must not surface as report noise.
      issues.push(DiscoveryIssue::new(
        "profile_has_no_cookie_source",
        profile_path,
        "profile marker has no Chromium cookie source",
      ));
    }
  }

  let profile_paths = if !source_bearing_marked.is_empty() {
    source_bearing_marked
  } else if root_has_source {
    vec![installation.path.clone()]
  } else {
    markerless_candidates
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
      // `profile_has_source` (above) and this fresh `persistent_candidates`
      // call are two separate filesystem reads of the same profile. Between
      // them, the selected source can vanish or lose selection under a
      // concurrent filesystem change; that is a discovery-time race, not an
      // invariant this loop is entitled to assume.
      let Some(selected_source) = persistent_candidates
        .iter()
        .find(|candidate| candidate.selected)
      else {
        issues.push(DiscoveryIssue::new(
          "profile_source_selection_race",
          canonical_path.clone(),
          "the profile's persistent cookie source changed between enumeration and canonical-key \
           computation",
        ));
        continue;
      };
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
      installation_id: InstallationId::known(&installation.installation_id),
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

pub(super) fn discover_browser_with_context<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
) -> Result<ChromiumDiscovery> {
  discover_browser_with_context_and_selection(context, browser_id, ProfileSelection::AllProfiles)
}

fn discover_browser_with_context_and_selection<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
  selection: ProfileSelection<'_>,
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
  // The legacy path tables expanded one path template over every channel
  // before moving to the next template. The registry represents that order as
  // contiguous channel groups; a repeated channel starts the next group.
  let mut legacy_root_group = 0u16;
  let mut channels_in_group = HashSet::new();
  let roots = roots
    .into_iter()
    .map(|root| {
      if !channels_in_group.insert(root.channel.as_str()) {
        legacy_root_group = legacy_root_group.saturating_add(1);
        channels_in_group.clear();
        channels_in_group.insert(root.channel.as_str());
      }
      (root, root.legacy_priority.unwrap_or(legacy_root_group))
    })
    .collect::<Vec<_>>();
  let mut discovery = ChromiumDiscovery::default();
  let mut seen_installations = HashSet::new();
  let mut seen_profiles = HashSet::new();
  for (root, legacy_priority) in roots {
    let Some(resolved_root) = context.resolve_template_for_selection(&root.template, selection)
    else {
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
        // `BrowserInstallation` keeps the opaque id as a `String`; the public
        // `ChromiumProfile` re-wraps it as the report_core newtype (Decision 18).
        installation_id: id.as_str().to_owned(),
        browser_id: definition.canonical_id.clone(),
        root_id: root.root_id.clone(),
        channel: root.channel.clone(),
        local_state_path: canonical_path.join("Local State"),
        legacy_local_state: None,
        key_credentials: definition.key_credentials.clone().unwrap_or_default(),
        path: canonical_path,
        priority: root.priority,
        legacy_priority,
        legacy_profile_layout: root.legacy_profile_layout,
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

/// One profile after extraction: its identity, plus what reading its cookie
/// databases produced.
///
/// Extract-only. The listing counterpart is [`ChromiumProfile`], whose
/// `persistent_candidates` cannot hold records; a `Source` here cannot be
/// returned from listing. Sources are the profile's whole extraction result --
/// stats, row issues, and any failure live on them, not beside them.
///
/// There is deliberately no profile-level `failure` field, because this engine
/// cannot reach one: no selected database is ordinary absence (empty
/// `sources`), and a failure reaching a named database lands on that
/// [`Source::failure`] -- which is why the acquisition `Err` arm below still
/// pushes a `Source`. An empty Chromium source list therefore means exactly
/// one thing.
///
/// This is the opposite convention from the engine listing, where an empty
/// `sources` is itself the failure. The two engines discover differently:
/// Chromium lists only databases that exist, so having none is normal.
#[derive(Debug)]
pub(crate) struct ChromiumExtractedProfile {
  pub(crate) profile: ChromiumProfile,
  pub(crate) sources: Vec<Source>,
}

impl ChromiumExtractedProfile {
  /// Compatibility cookies projected from every source's records.
  ///
  /// The mirror of [`Source::cookies`] for tests that assert on a profile's
  /// whole yield. Chromium selects one source per profile today, so this is a
  /// flatten over one element; writing it as a flatten keeps it correct if
  /// session candidates ever arrive.
  #[cfg(test)]
  pub(crate) fn cookies(&self) -> Vec<Cookie> {
    self.sources.iter().flat_map(Source::cookies).collect()
  }
}

#[derive(Debug)]
pub(crate) struct ChromiumInstallationDraft {
  pub(crate) installation_id: String,
  pub(crate) channel: String,
  pub(crate) profiles: Vec<ChromiumExtractedProfile>,
}

#[derive(Debug, Default)]
pub(crate) struct ChromiumRegistryDraft {
  pub(crate) installations: Vec<ChromiumInstallationDraft>,
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
  /// Typed request stop observed after discovery or a completed source. It is
  /// finalized independently from result status and never stringified as a
  /// profile/source failure.
  pub(crate) boundary_stop: Option<crate::common::deadline::BoundaryStop>,
}

pub(super) fn extract_chromium_with_provider<F, P>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
  selection: ProfileSelection<'_>,
  domains: Option<Vec<String>>,
  provider: &P,
) -> Result<ChromiumRegistryDraft>
where
  F: DiscoveryFs,
  P: KeyProvider<BrowserInstallation, Keys = ChromiumKeyOutcomes>,
{
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  extract_chromium_with_provider_runtime(
    context, browser_id, selection, domains, provider, &runtime,
  )
}

fn extract_chromium_with_provider_runtime<F, P>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
  selection: ProfileSelection<'_>,
  domains: Option<Vec<String>>,
  provider: &P,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<ChromiumRegistryDraft>
where
  F: DiscoveryFs,
  P: KeyProvider<BrowserInstallation, Keys = ChromiumKeyOutcomes>,
{
  extract_chromium_with_provider_and_selection_runtime(
    context, browser_id, selection, domains, provider, runtime,
  )
}

fn extract_chromium_with_provider_and_selection<F, P>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
  selection: ProfileSelection<'_>,
  domains: Option<Vec<String>>,
  provider: &P,
) -> Result<ChromiumRegistryDraft>
where
  F: DiscoveryFs,
  P: KeyProvider<BrowserInstallation, Keys = ChromiumKeyOutcomes>,
{
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  extract_chromium_with_provider_and_selection_runtime(
    context, browser_id, selection, domains, provider, &runtime,
  )
}

fn extract_chromium_with_provider_and_selection_runtime<F, P>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
  selection: ProfileSelection<'_>,
  domains: Option<Vec<String>>,
  provider: &P,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<ChromiumRegistryDraft>
where
  F: DiscoveryFs,
  P: KeyProvider<BrowserInstallation, Keys = ChromiumKeyOutcomes>,
{
  runtime.check()?;
  let mut discovery = discover_browser_with_context_and_selection(context, browser_id, selection)?;
  if selection == ProfileSelection::LegacyFirstProfile {
    // Generic discovery prefers declared profiles over a flat installation
    // root. The historical Opera selectors on macOS/Windows (and the Linux
    // Opera fallback) explicitly named that flat source, so add it only to the
    // compatibility projection.
    add_legacy_flat_chromium_profiles(context, &mut discovery);
  }
  if let ProfileSelection::ProfileId(profile_id) = selection {
    let found = discovery
      .installations
      .iter()
      .flat_map(|installation| &installation.profiles)
      .any(|profile| profile.profile_id.as_str() == profile_id);
    if !found {
      bail!("unknown {browser_id} profile id {profile_id:?}")
    }
  }

  let legacy_profile_id = match selection {
    // Historical named selectors exhausted each root/template group over its
    // channels, then Default sources, then Profile* sources. Source precedence
    // is therefore meaningful only inside those two outer compatibility
    // groups, not as a global preference over another root or profile group.
    ProfileSelection::LegacyFirstProfile => discovery
      .installations
      .iter()
      .flat_map(|installation| {
        installation
          .profiles
          .iter()
          .map(move |profile| (installation, profile))
      })
      .filter_map(|(installation, profile)| {
        legacy_chromium_profile_group(installation.legacy_profile_layout, &profile.directory_name)
          .zip(profile.selected_source_precedence())
          .map(|(profile_group, precedence)| {
            let rank = (
              installation.legacy_priority,
              profile_group,
              precedence,
              installation.priority,
              normalized_path_bytes(&profile.path),
            );
            (rank, &profile.profile_id)
          })
      })
      .min_by(|(left, _), (right, _)| left.cmp(right))
      .map(|(_, profile_id)| profile_id.clone()),
    _ => None,
  };

  let mut report = ChromiumRegistryDraft {
    all_detected_roots_failed: discovery.all_detected_roots_failed(),
    installations_detected: discovery.detected_roots,
    installations_discovered: discovery.installations.len(),
    discovery_issues: discovery.issues,
    ..ChromiumRegistryDraft::default()
  };
  for mut installation in discovery.installations {
    if let Err(stop) = runtime.check() {
      report.boundary_stop = Some(stop);
      break;
    }
    let selected_profiles = installation
      .profiles
      .iter()
      .filter(|profile| match selection {
        ProfileSelection::AllProfiles => true,
        ProfileSelection::ProfileId(profile_id) => profile.profile_id.as_str() == profile_id,
        ProfileSelection::LegacyFirstProfile => legacy_profile_id
          .as_ref()
          .is_some_and(|expected| &profile.profile_id == expected),
      })
      .cloned()
      .collect::<Vec<_>>();
    if selected_profiles.is_empty() {
      if selection == ProfileSelection::AllProfiles {
        report.installations.push(ChromiumInstallationDraft {
          installation_id: installation.installation_id,
          channel: installation.channel,
          profiles: Vec::new(),
        });
      }
      continue;
    }
    if selection == ProfileSelection::LegacyFirstProfile {
      // `legacy_profile_id` (above) was computed from this same in-memory
      // discovery snapshot and only ever selects a profile that has a
      // selected source, so `selected_source()` returning `None` here should
      // be unreachable. Record it and skip this installation — the same
      // outcome `selected_profiles.is_empty()` already produces for this
      // selection mode — rather than either trusting the invariant silently
      // or panicking if a future refactor breaks it.
      let Some(selected_source) = selected_profiles
        .first()
        .and_then(|profile| profile.selected_source())
      else {
        report.discovery_issues.push(DiscoveryIssue::new(
          "legacy_profile_missing_selected_source",
          installation.path.clone(),
          "legacy-first-profile selection picked a profile with no persistent cookie source",
        ));
        continue;
      };
      if let Some((local_state_path, local_state)) =
        legacy_windows_local_state(context, selected_source)?
      {
        installation.local_state_path = local_state_path;
        installation.legacy_local_state = Some(local_state);
      }
    }
    // The provider is installation-scoped, so Local State/keyring work happens
    // exactly once and the independent tier outcomes are reused by every profile.
    let key_outcomes = match retrieve_key_outcomes(provider, &installation, runtime) {
      Ok(outcomes) => outcomes,
      Err(error) => {
        if let Some(stop) = error.downcast_ref::<crate::common::deadline::BoundaryStop>() {
          report.boundary_stop = Some(*stop);
          break;
        }
        return Err(error);
      }
    };
    if let Err(stop) = runtime.check() {
      report.boundary_stop = Some(stop);
      break;
    }
    let mut profile_extractions = Vec::with_capacity(selected_profiles.len());
    for profile in selected_profiles {
      if let Err(stop) = runtime.check() {
        report.boundary_stop = Some(stop);
        break;
      }
      let Some(candidate) = profile
        .persistent_candidates
        .iter()
        .find(|candidate| candidate.selected)
        .cloned()
      else {
        // No selected database is ordinary absence, so the profile carries no
        // failure and no source. The report reads the empty list as such.
        profile_extractions.push(ChromiumExtractedProfile {
          profile,
          sources: Vec::new(),
        });
        continue;
      };
      match acquire_chromium_source_with_runtime(
        &key_outcomes,
        candidate.clone(),
        domains.clone(),
        false,
        runtime,
      ) {
        Ok(source) => {
          // The adapter used to re-sort the engine's separate cookie list here.
          // There is no separate list any more -- cookies are projected from
          // `records` -- so a sort would only make tests observe an order
          // production never returns.
          //
          // A source where every row was rejected is not a failed source:
          // acquisition, parsing, and the query all completed. Section 5.7
          // reports it as succeeded-with-rows-skipped, and the row issues the
          // engine attached already carry the detail. Only the compatibility
          // projection treats it as an error, through the evidence issue the
          // engine attached for it.
          profile_extractions.push(ChromiumExtractedProfile {
            profile,
            sources: vec![source],
          });
        }
        Err(error) => {
          if let Some(stop) = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<crate::common::deadline::BoundaryStop>())
          {
            report.boundary_stop = Some(*stop);
            break;
          }
          let database_failure =
            error.downcast_ref::<crate::common::sqlite::BrowserDatabaseFailure>();
          // The source was named and reached for, so the failure belongs to it
          // rather than to the profile.
          let mut source = Source::new(
            candidate.identity(),
            candidate.selected,
            candidate.acquisition,
          );
          source.acquisition = database_failure.and_then(|failure| failure.strategy).into();
          source.acquisition_attempts = database_failure.map_or(1, |failure| failure.attempts);
          // `Acquisition` unconditionally, deliberately. The Chromium report
          // has always emitted `stage: acquisition` for every database failure
          // -- the mapper hardcoded it, so `BrowserDatabaseFailure::kind` was
          // never read here. Mozilla does read it and reports `query` for a
          // query-stage failure, which makes the two engines disagree about a
          // frozen wire field. Reconciling them is a deliberate behavior change
          // with no golden covering it, not something to slip into a refactor.
          source.fail(SourceFailureStage::Acquisition, error.to_string());
          // The whole error chain, not just the outermost error the failure
          // carries. This is what the compatibility projection surfaces, and it
          // is why the evidence is attached to failed sources too.
          source
            .issues
            .push(SourceIssue::all_rows_rejected(format!("{error:#}")));
          profile_extractions.push(ChromiumExtractedProfile {
            profile,
            sources: vec![source],
          });
        }
      }
    }
    report.installations.push(ChromiumInstallationDraft {
      installation_id: installation.installation_id,
      channel: installation.channel,
      profiles: profile_extractions,
    });
    if report.boundary_stop.is_some() {
      break;
    }
  }
  if report.boundary_stop.is_none() {
    if let Err(stop) = runtime.check() {
      report.boundary_stop = Some(stop);
    }
  }
  Ok(report)
}

/// Resolves a browser's platform key credentials from the registry.
///
/// Section 5.9 makes the registry the single source of truth for both grouped
/// and compatibility extraction.
///
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn registry_key_credentials(browser_id: &str) -> Result<ChromiumKeyIdentity> {
  let registry = embedded_registry()?;
  let platform = PlatformId::current()?;
  let definition = browser_definition(registry, platform, browser_id)?;
  Ok(definition.key_credentials.clone().unwrap_or_default())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) enum DirectPathChromiumIdentity {
  Unknown,
  OtherEngine,
  Chromium(Option<ChromiumKeyIdentity>),
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn direct_path_chromium_identity(
  browser_id: &str,
) -> Result<DirectPathChromiumIdentity> {
  let registry = embedded_registry()?;
  let platform = PlatformId::current()?;
  let Some(definitions) = registry.platforms.get(platform.as_str()) else {
    return Ok(DirectPathChromiumIdentity::Unknown);
  };
  let Some(definition) = definitions.iter().find(|definition| {
    definition.canonical_id == browser_id
      || definition.aliases.iter().any(|alias| alias == browser_id)
  }) else {
    return Ok(DirectPathChromiumIdentity::Unknown);
  };
  if definition.engine != BrowserEngine::Chromium {
    return Ok(DirectPathChromiumIdentity::OtherEngine);
  }
  Ok(DirectPathChromiumIdentity::Chromium(
    definition.key_credentials.clone(),
  ))
}

pub(crate) fn chromium_key_credentials(browser_id: &str) -> Result<Option<crate::config::Browser>> {
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  {
    let registry = embedded_registry()?;
    let platform = PlatformId::current()?;
    let definition = browser_definition(registry, platform, browser_id)?;
    if definition.engine != BrowserEngine::Chromium {
      bail!(
        "browser id {browser_id:?} resolves to the {} engine, not Chromium",
        definition.engine.as_str()
      );
    }
    let Some(credentials) = definition.key_credentials.as_ref() else {
      return Ok(None);
    };
    #[cfg(target_os = "linux")]
    if credentials.linux_crypt_name.is_none() {
      bail!("browser id {browser_id:?} has no Linux crypt-name identity");
    }
    #[cfg(target_os = "macos")]
    if credentials.macos_keychain.is_none() {
      bail!("browser id {browser_id:?} has no macOS Keychain identity");
    }
    Ok(Some(provider_input(credentials)))
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos")))]
  {
    let _ = browser_id;
    bail!("Chromium key identity resolution is unsupported on this platform")
  }
}

/// Compatibility adapter for direct APIs that still accept `config::Browser`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn provider_input(credentials: &ChromiumKeyIdentity) -> crate::config::Browser {
  let keychain = credentials.macos_keychain.as_ref();
  crate::config::Browser {
    paths: Vec::new(),
    channels: None,
    unix_crypt_name: credentials.linux_crypt_name.clone(),
    osx_key_service: keychain.map(|keychain| keychain.service.clone()),
    osx_key_user: keychain.map(|keychain| keychain.account.clone()),
  }
}

struct SystemKeyProvider;

fn key_request_for_installation(installation: &BrowserInstallation) -> ChromiumKeyRequest<'_> {
  ChromiumKeyRequest::for_installation(
    &installation.browser_id,
    &installation.key_credentials,
    &installation.local_state_path,
    installation.legacy_local_state.as_ref(),
  )
}

impl KeyProvider<BrowserInstallation> for SystemKeyProvider {
  type Keys = ChromiumKeyOutcomes;

  fn keys(
    &self,
    installation: &BrowserInstallation,
    runtime: &crate::common::deadline::BoundaryRuntime<'_>,
  ) -> ChromiumKeyOutcomes {
    let request = key_request_for_installation(installation);
    let mut session = HostKeySession::new();
    session.retrieve(request, runtime)
  }
}

/// Chrome-specific profile listing in active-profile preference order.
///
/// This is separate from [`chromium_profiles`], whose default-first ordering is
/// part of the generic registry contract. `Local State` hints are advisory: a
/// last-used profile comes first, followed by the remaining active profiles in
/// their declared order. Profiles without a usable hint retain the generic
/// discovery order, so a missing, stale, or malformed hint safely falls back
/// to the default-first result.
fn chrome_profiles() -> Result<Vec<ChromiumProfile>> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  chrome_profiles_with_runtime(&runtime)
}

pub(crate) fn chrome_profiles_with_runtime(
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<ChromiumProfile>> {
  let mut profiles = chromium_profiles_with_runtime("chrome", runtime)?;
  prefer_active_profiles(&mut profiles);
  Ok(profiles)
}

/// Internal generic Chromium listing seam. Public callers reach it through the
/// cross-engine descriptor API; compatibility wrappers use the same discovery
/// with [`ProfileSelection::LegacyFirstProfile`].
fn chromium_profiles(browser_id: &str) -> Result<Vec<ChromiumProfile>> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  chromium_profiles_with_runtime(browser_id, &runtime)
}

fn chromium_profiles_with_runtime(
  browser_id: &str,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<ChromiumProfile>> {
  runtime.check()?;
  let context = DiscoveryContext::system()?;
  runtime.check()?;
  let profiles = profiles_for_listing(
    browser_id,
    discover_browser_with_context(&context, browser_id)?,
  )?;
  runtime.check()?;
  Ok(profiles)
}

fn prefer_active_profiles(profiles: &mut [ChromiumProfile]) {
  profiles.sort_by_key(|profile| {
    if profile.is_last_used {
      (0, 0)
    } else if let Some(active_order) = profile.active_order {
      (1, active_order)
    } else {
      (2, 0)
    }
  });
}

fn lost_chromium_profile_error(browser_id: &str, issues: &[DiscoveryIssue]) -> Option<String> {
  let lost_profiles = issues
    .iter()
    .filter(|issue| {
      issue.code.starts_with("profile_") && !is_informational_discovery_issue(issue.code)
    })
    .take(MAX_DISCOVERY_ISSUE_SAMPLES)
    .map(|issue| {
      format!(
        "{REDACTED_PATH}: {}",
        crate::common::diagnostic::sanitize(&issue.message)
      )
    })
    .collect::<Vec<_>>();
  (!lost_profiles.is_empty()).then(|| {
    format!(
      "every discovered {browser_id} profile failed discovery: {}",
      lost_profiles.join("; ")
    )
  })
}

pub(super) fn profiles_for_listing(
  browser_id: &str,
  discovery: ChromiumDiscovery,
) -> Result<Vec<ChromiumProfile>> {
  if discovery.all_detected_roots_failed() {
    bail!("every detected {browser_id} installation failed profile enumeration")
  }
  let profiles = discovery.profiles();
  if profiles.is_empty() {
    if let Some(error) = lost_chromium_profile_error(browser_id, &discovery.issues) {
      bail!(error)
    }
  }
  Ok(profiles)
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

pub(crate) fn chromium_listing_with_runtime(
  browser_id: &str,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<ChromiumListing> {
  runtime.check()?;
  let context = DiscoveryContext::system()?;
  runtime.check()?;
  let discovery = discover_browser_with_context(&context, browser_id)?;
  runtime.check()?;
  Ok(ChromiumListing {
    profiles: discovery.profiles(),
    installations_discovered: discovery.installations.len(),
    all_detected_roots_failed: discovery.all_detected_roots_failed(),
    discovery_issues: discovery.issues,
  })
}

/// Private generic Chromium report seam covering every registered
/// Chromium-family browser.
fn chromium_registry_report(
  browser_id: &str,
  selection: ProfileSelection<'_>,
  domains: Option<Vec<String>>,
) -> Result<ChromiumRegistryDraft> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  chromium_registry_report_with_runtime(browser_id, selection, domains, &runtime)
}

pub(crate) fn chromium_registry_report_with_runtime(
  browser_id: &str,
  selection: ProfileSelection<'_>,
  domains: Option<Vec<String>>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<ChromiumRegistryDraft> {
  runtime.check()?;
  let context = DiscoveryContext::system()?;
  runtime.check()?;
  extract_chromium_with_provider_runtime(
    &context,
    browser_id,
    selection,
    domains,
    &SystemKeyProvider,
    runtime,
  )
}

/// Registry-backed first-profile Chromium extraction for the named wrappers.
///
/// `None` means the browser has no legacy-compatible cookie source. Real
/// discovery, key-provider, acquisition, query, or row failures remain errors.
fn legacy_chromium_outcome(
  browser_id: &str,
  domains: Option<Vec<String>>,
) -> Result<ChromiumRegistryDraft> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  legacy_chromium_outcome_with_runtime(browser_id, domains, &runtime)
}

pub(crate) fn legacy_chromium_outcome_with_runtime(
  browser_id: &str,
  domains: Option<Vec<String>>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<ChromiumRegistryDraft> {
  runtime.check()?;
  let context = DiscoveryContext::system()?;
  runtime.check()?;
  extract_chromium_with_provider_and_selection_runtime(
    &context,
    browser_id,
    ProfileSelection::LegacyFirstProfile,
    domains,
    &SystemKeyProvider,
    runtime,
  )
}

/// Private Milestone 3C ID-based selector/report seam.
fn chrome_profile(profile_id: &str, domains: Option<Vec<String>>) -> Result<ChromiumRegistryDraft> {
  let context = DiscoveryContext::system()?;
  extract_chromium_with_provider(
    &context,
    "chrome",
    ProfileSelection::ProfileId(profile_id),
    domains,
    &SystemKeyProvider,
  )
}

#[cfg(test)]
mod tests;
