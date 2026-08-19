use super::super::chromium::query_cookies_engine_outcome_with_runtime;
#[cfg(all(test, target_os = "macos"))]
use super::super::chromium_crypto::ChromiumKeyOutcome;
use super::super::chromium_crypto::{retrieve_key_outcomes, ChromiumKeyOutcomes, KeyProvider};
use super::super::chromium_platform_keys::{
  ChromiumKeyCredentials, ChromiumKeyRequest, HostKeySession, MacosKeychainCredentials,
};
use super::super::report_core::{
  CookieSourceFormatId, CookieSourceRoleId, InstallationId, ProfileId,
};
use super::{
  browser_definition, embedded_registry, installation_id, is_informational_discovery_issue,
  normalized_path_bytes, profile_id, BrowserDefinition, BrowserEngine, DiscoveryContext,
  DiscoveryFs, DiscoveryIssue, DiscoveryStrategy, InstallationRoot, PlatformId, ProfileLocator,
  ProfileSelection, Source, SourceAcquisition, SourceCandidate, SourceFailureStage, SourceIssue,
  MAX_DISCOVERY_ISSUE_SAMPLES,
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

#[derive(Debug, Default, Deserialize)]
pub(super) struct KeyCredentials {
  pub(super) macos_keychain: Option<MacosKeychainCredential>,
  pub(super) linux_crypt_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct MacosKeychainCredential {
  /// Keychain generic-password service, e.g. `"Chrome Safe Storage"`.
  pub(super) service: String,
  /// Its account name, e.g. `"Chrome"`.
  pub(super) account: String,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum LegacyChromiumProfileLayout {
  #[default]
  DefaultAndProfiles,
  DefaultOnly,
  FlatOnly,
  DefaultAndFlat,
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
  key_credentials: ChromiumKeyCredentials,
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
    (LegacyChromiumProfileLayout::FlatOnly, ".") => Some(0),
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
      LegacyChromiumProfileLayout::FlatOnly | LegacyChromiumProfileLayout::DefaultAndFlat
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
        key_credentials: project_key_credentials(definition.key_credentials.as_ref()),
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
#[derive(Debug)]
pub(crate) struct ChromiumExtractedProfile {
  pub(crate) profile: ChromiumProfile,
  pub(crate) sources: Vec<Source>,
  /// Extraction failed before any source could be named.
  ///
  /// Empty `sources` on its own means the profile declares no cookie database,
  /// which is ordinary absence; this says the profile lost something instead,
  /// so the report must not downgrade it to the same `info` signal. A failure
  /// that happened *while reading* a named source lives on that
  /// [`Source::failure`] rather than here.
  ///
  /// This is the opposite convention from the engine listing, where an empty
  /// `sources` is itself the failure. The two engines discover differently:
  /// Chromium lists only databases that exist, so having none is normal.
  pub(crate) failure: Option<String>,
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
  profile_id: Option<&str>,
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
    context, browser_id, profile_id, domains, provider, &runtime,
  )
}

fn extract_chromium_with_provider_runtime<F, P>(
  context: &DiscoveryContext<F>,
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<Vec<String>>,
  provider: &P,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<ChromiumRegistryDraft>
where
  F: DiscoveryFs,
  P: KeyProvider<BrowserInstallation, Keys = ChromiumKeyOutcomes>,
{
  extract_chromium_with_provider_and_selection_runtime(
    context,
    browser_id,
    ProfileSelection::from_profile_id(profile_id),
    domains,
    provider,
    runtime,
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
          failure: None,
        });
        continue;
      };
      match query_cookies_engine_outcome_with_runtime(
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
            failure: None,
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
          let mut source = Source::from_candidate(candidate);
          source.acquisition = database_failure.and_then(|failure| failure.strategy).into();
          source.acquisition_attempts = database_failure.map_or(1, |failure| failure.attempts);
          source.fail(SourceFailureStage::Acquisition, error.to_string());
          source
            .issues
            .push(SourceIssue::all_rows_rejected(format!("{error:#}")));
          profile_extractions.push(ChromiumExtractedProfile {
            profile,
            sources: vec![source],
            failure: None,
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
pub(crate) fn registry_key_credentials(browser_id: &str) -> Result<ChromiumKeyCredentials> {
  let registry = embedded_registry()?;
  let platform = PlatformId::current()?;
  let definition = browser_definition(registry, platform, browser_id)?;
  Ok(project_key_credentials(definition.key_credentials.as_ref()))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) enum DirectPathChromiumIdentity {
  Unknown,
  OtherEngine,
  Chromium(Option<ChromiumKeyCredentials>),
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
    definition
      .key_credentials
      .as_ref()
      .map(|credentials| project_key_credentials(Some(credentials))),
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
    let Some(key_credentials) = definition.key_credentials.as_ref() else {
      return Ok(None);
    };
    let credentials = project_key_credentials(Some(key_credentials));
    #[cfg(target_os = "linux")]
    if credentials.linux_crypt_name.is_none() {
      bail!("browser id {browser_id:?} has no Linux crypt-name identity");
    }
    #[cfg(target_os = "macos")]
    if credentials.macos_keychain.is_none() {
      bail!("browser id {browser_id:?} has no macOS Keychain identity");
    }
    Ok(Some(provider_input(&credentials)))
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos")))]
  {
    let _ = browser_id;
    bail!("Chromium key identity resolution is unsupported on this platform")
  }
}

fn project_key_credentials(credentials: Option<&KeyCredentials>) -> ChromiumKeyCredentials {
  ChromiumKeyCredentials {
    linux_crypt_name: credentials.and_then(|credentials| credentials.linux_crypt_name.clone()),
    macos_keychain: credentials
      .and_then(|credentials| credentials.macos_keychain.as_ref())
      .map(|keychain| MacosKeychainCredentials {
        service: keychain.service.clone(),
        account: keychain.account.clone(),
      }),
  }
}

/// Compatibility adapter for direct APIs that still accept `config::Browser`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn provider_input(credentials: &ChromiumKeyCredentials) -> crate::config::Browser {
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

/// Selects one Chrome profile by opaque ID, display name, directory name, or
/// full path when that path is valid UTF-8.
///
/// Names can repeat across channels and installations, so an ambiguous match
/// is rejected instead of silently trusting an advisory activity hint. The
/// opaque profile ID is always lossless; callers must use it when a descriptor
/// marks its display path as lossy.
fn select_chrome_profile(profile: &str) -> Result<ChromiumProfile> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  select_chrome_profile_with_runtime(profile, &runtime)
}

pub(crate) fn select_chrome_profile_with_runtime(
  profile: &str,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<ChromiumProfile> {
  let profiles = chrome_profiles_with_runtime(runtime)?;
  runtime.check()?;
  select_chromium_profile(&profiles, profile).cloned()
}

fn select_chromium_profile<'a>(
  profiles: &'a [ChromiumProfile],
  selector: &str,
) -> Result<&'a ChromiumProfile> {
  if selector.is_empty() {
    bail!("Chrome profile selector must not be empty")
  }

  if let Some(profile) = profiles
    .iter()
    .find(|profile| profile.profile_id.as_str() == selector)
  {
    return Ok(profile);
  }

  let lossy_paths = profiles
    .iter()
    .filter(|profile| profile.path.to_str().is_none() && profile.path.to_string_lossy() == selector)
    .collect::<Vec<_>>();
  if !lossy_paths.is_empty() {
    bail!(
      "Chrome profile path {selector:?} is a lossy display value and cannot be used as a selector; select by profile ID: [{}]",
      describe_chromium_profiles(lossy_paths.into_iter())
    )
  }

  let wanted = Path::new(selector);
  let matches = profiles
    .iter()
    .filter(|profile| {
      profile.display_name == selector
        || profile.directory_name == selector
        || profile.path == wanted
    })
    .collect::<Vec<_>>();
  match matches.as_slice() {
    [profile] => Ok(profile),
    [] => bail!(
      "no Chrome profile matches {selector:?}; available profiles: [{}]",
      describe_chromium_profiles(profiles.iter())
    ),
    _ => bail!(
      "{} Chrome profiles match {selector:?}; select one by profile ID or a non-lossy full path: [{}]",
      matches.len(),
      describe_chromium_profiles(matches.iter().copied())
    ),
  }
}

fn describe_chromium_profiles<'a>(profiles: impl Iterator<Item = &'a ChromiumProfile>) -> String {
  profiles
    .map(|profile| {
      format!(
        "{} ({}, {})",
        profile.display_name, REDACTED_PATH, profile.profile_id
      )
    })
    .collect::<Vec<_>>()
    .join(", ")
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

fn chromium_listing(browser_id: &str) -> Result<ChromiumListing> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  chromium_listing_with_runtime(browser_id, &runtime)
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
  profile_id: Option<&str>,
  domains: Option<Vec<String>>,
) -> Result<ChromiumRegistryDraft> {
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  chromium_registry_report_with_runtime(browser_id, profile_id, domains, &runtime)
}

pub(crate) fn chromium_registry_report_with_runtime(
  browser_id: &str,
  profile_id: Option<&str>,
  domains: Option<Vec<String>>,
  runtime: &crate::common::deadline::BoundaryRuntime<'_>,
) -> Result<ChromiumRegistryDraft> {
  runtime.check()?;
  let context = DiscoveryContext::system()?;
  runtime.check()?;
  extract_chromium_with_provider_runtime(
    &context,
    browser_id,
    profile_id,
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
    Some(profile_id),
    domains,
    &SystemKeyProvider,
  )
}

#[cfg(test)]
mod tests {
  use super::super::test_seams::{
    browser_root, channel_root, context_for, current_context, seed_cookie, with_test_fs,
    write_local_state, TempDir, TestDiscoveryFs,
  };
  use super::*;
  use crate::browser::chromium_crypto::{ChromiumKeyOutcomes, KeyProvider};
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
    let both = KeyCredentials {
      macos_keychain: Some(MacosKeychainCredential {
        service: "Probe Safe Storage".to_owned(),
        account: "Probe Account".to_owned(),
      }),
      linux_crypt_name: Some("probe-crypt".to_owned()),
    };
    let projected = project_key_credentials(Some(&both));
    let mapped = provider_input(&projected);
    assert_eq!(
      mapped.osx_key_service.as_deref(),
      Some("Probe Safe Storage")
    );
    assert_eq!(mapped.osx_key_user.as_deref(), Some("Probe Account"));
    assert_eq!(mapped.unix_crypt_name.as_deref(), Some("probe-crypt"));

    // No credentials maps to no credentials, never to a blank lookup.
    let empty = provider_input(&ChromiumKeyCredentials::default());
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
    let expected = ChromiumKeyCredentials {
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
      let generic =
        registry_key_credentials(&definition.canonical_id).expect("registry credentials");
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
    let report =
      extract_chromium_with_provider_runtime(&context, "chrome", None, None, &provider, &runtime)
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
        None,
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
        key_credentials: ChromiumKeyCredentials::default(),
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

      let report =
        extract_chromium_with_provider(&context, browser_id, None, None, &SystemKeyProvider)
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
    assert_eq!(
      select_chromium_profile(&profiles, "Personal")
        .expect("unique display name")
        .display_name,
      "Personal"
    );
    assert_eq!(
      select_chromium_profile(&profiles, profiles[0].profile_id.as_str())
        .expect("profile ID")
        .profile_id,
      profiles[0].profile_id
    );
    assert_eq!(
      select_chromium_profile(&profiles, profiles[1].path.to_string_lossy().as_ref())
        .expect("full path")
        .profile_id,
      profiles[1].profile_id
    );
    let ambiguous = select_chromium_profile(&profiles, "Default").expect_err("two directories");
    assert!(ambiguous.to_string().contains("2 Chrome profiles match"));
    assert!(select_chromium_profile(&profiles, "").is_err());
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
    let profile_id = profiles[0].profile_id.clone();
    profiles[0].path = PathBuf::from(OsString::from_vec(b"/profile/invalid-\xff".to_vec()));
    let lossy_path = profiles[0].path.to_string_lossy().into_owned();

    let error = select_chromium_profile(&profiles, &lossy_path)
      .expect_err("a lossy display path cannot round-trip");
    assert!(error.to_string().contains("lossy display value"));
    assert!(error.to_string().contains(profile_id.as_str()));
    assert_eq!(
      select_chromium_profile(&profiles, profile_id.as_str())
        .expect("opaque ID remains lossless")
        .profile_id,
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

    let report = extract_chromium_with_provider(&context, "chrome", None, None, &provider)
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

    let report =
      extract_chromium_with_provider(&context, "chrome", None, None, &CountingProvider::default())
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
      Some(profile_id.as_str()),
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
      Some("not-a-profile-id"),
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
    let generic = extract_chromium_with_provider(&context, "chrome", None, None, &generic_provider)
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
      let report = extract_chromium_with_provider(&context, selector, None, None, &provider)
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
}
