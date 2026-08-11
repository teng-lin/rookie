//! Private, compile-time browser registry for the generic extraction pipeline.
//!
//! Legacy wrappers deliberately continue to use `config.json`. This module is
//! staged for the additive generic APIs and is not exported from the crate.

use once_cell::sync::Lazy;
use serde::{de::Error as _, Deserialize, Deserializer};
use std::{
  collections::{BTreeMap, BTreeSet},
  error::Error,
  ffi::{OsStr, OsString},
  fmt, fs, io,
  path::{Path, PathBuf},
  str::FromStr,
};

const REGISTRY_SCHEMA_VERSION: u32 = 1;
const EMBEDDED_REGISTRY: &str = include_str!("../browser_registry.json");

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IdentifierError {
  kind: &'static str,
  value: String,
}

impl IdentifierError {
  fn new(kind: &'static str, value: &str) -> Self {
    Self {
      kind,
      value: value.to_owned(),
    }
  }
}

impl fmt::Display for IdentifierError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      formatter,
      "{} must match [a-z][a-z0-9_]*, got {:?}",
      self.kind, self.value
    )
  }
}

impl Error for IdentifierError {}

fn is_open_identifier(value: &str) -> bool {
  let mut characters = value.chars();
  characters
    .next()
    .is_some_and(|first| first.is_ascii_lowercase())
    && characters.all(|character| {
      character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
    })
}

macro_rules! open_identifier {
  ($name:ident, $kind:literal) => {
    #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub(crate) struct $name(String);

    impl AsRef<str> for $name {
      fn as_ref(&self) -> &str {
        &self.0
      }
    }

    impl fmt::Display for $name {
      fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
      }
    }

    impl FromStr for $name {
      type Err = IdentifierError;

      fn from_str(value: &str) -> Result<Self, Self::Err> {
        if is_open_identifier(value) {
          Ok(Self(value.to_owned()))
        } else {
          Err(IdentifierError::new($kind, value))
        }
      }
    }

    impl<'de> Deserialize<'de> for $name {
      fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
      where
        D: Deserializer<'de>,
      {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(D::Error::custom)
      }
    }
  };
}

open_identifier!(PlatformId, "platform ID");
open_identifier!(BrowserId, "browser ID");
open_identifier!(BrowserEngine, "browser engine ID");
open_identifier!(RootId, "root ID");
open_identifier!(DiscoveryStrategy, "discovery strategy ID");
open_identifier!(CookieSourceFormatId, "cookie source format ID");
open_identifier!(CipherTierId, "cipher tier ID");

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
  schema_version: u32,
  platforms: BTreeMap<PlatformId, Vec<BrowserDefinition>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BrowserDefinition {
  pub(crate) canonical_id: BrowserId,
  pub(crate) aliases: Vec<String>,
  pub(crate) display_name: String,
  pub(crate) engine: BrowserEngine,
  pub(crate) roots: Vec<InstallationRoot>,
  pub(crate) capabilities: BrowserCapabilities,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BrowserCapabilities {
  pub(crate) declared_persistent_formats: Vec<CookieSourceFormatId>,
  pub(crate) declared_session_formats: Vec<CookieSourceFormatId>,
  pub(crate) declared_decryption_tiers: Vec<CipherTierId>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstallationRoot {
  pub(crate) root_id: RootId,
  pub(crate) template: String,
  pub(crate) channel: String,
  pub(crate) discovery: DiscoveryStrategy,
  pub(crate) priority: u16,
}

#[derive(Clone, Debug)]
pub(crate) struct PlatformRegistry {
  pub(crate) platform: Platform,
  pub(crate) definitions: Vec<BrowserDefinition>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Platform {
  Linux,
  Macos,
  Windows,
}

impl Platform {
  pub(crate) fn current() -> Result<Self, RegistryError> {
    #[cfg(target_os = "linux")]
    {
      Ok(Self::Linux)
    }
    #[cfg(target_os = "macos")]
    {
      Ok(Self::Macos)
    }
    #[cfg(target_os = "windows")]
    {
      Ok(Self::Windows)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
      Err(RegistryError::new(format!(
        "browser registry does not support target OS {}",
        std::env::consts::OS
      )))
    }
  }

  pub(crate) const fn as_str(self) -> &'static str {
    match self {
      Self::Linux => "linux",
      Self::Macos => "macos",
      Self::Windows => "windows",
    }
  }

  fn id(self) -> PlatformId {
    self
      .as_str()
      .parse()
      .expect("built-in platform identifiers are valid")
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RegistryError {
  message: String,
}

impl RegistryError {
  fn new(message: impl Into<String>) -> Self {
    Self {
      message: message.into(),
    }
  }
}

impl fmt::Display for RegistryError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(&self.message)
  }
}

impl Error for RegistryError {}

static CURRENT_REGISTRY: Lazy<Result<PlatformRegistry, RegistryError>> = Lazy::new(|| {
  let platform = Platform::current()?;
  load_platform_registry(EMBEDDED_REGISTRY, platform)
});

pub(crate) fn current_registry() -> Result<&'static PlatformRegistry, RegistryError> {
  CURRENT_REGISTRY.as_ref().map_err(Clone::clone)
}

fn load_platform_registry(
  contents: &str,
  platform: Platform,
) -> Result<PlatformRegistry, RegistryError> {
  let mut registry: Registry = serde_json::from_str(contents)
    .map_err(|error| RegistryError::new(format!("invalid embedded browser registry: {error}")))?;
  validate_registry(&registry)?;
  let definitions = registry.platforms.remove(&platform.id()).ok_or_else(|| {
    RegistryError::new(format!(
      "browser registry has no {} platform group",
      platform.as_str()
    ))
  })?;

  Ok(PlatformRegistry {
    platform,
    definitions,
  })
}

fn validate_registry(registry: &Registry) -> Result<(), RegistryError> {
  if registry.schema_version != REGISTRY_SCHEMA_VERSION {
    return Err(RegistryError::new(format!(
      "unsupported browser registry schema version {}; expected {}",
      registry.schema_version, REGISTRY_SCHEMA_VERSION
    )));
  }

  for required in [Platform::Linux, Platform::Macos, Platform::Windows] {
    if !registry.platforms.contains_key(&required.id()) {
      return Err(RegistryError::new(format!(
        "browser registry is missing required {} platform group",
        required.as_str()
      )));
    }
  }

  let mut cross_platform_definitions: BTreeMap<BrowserId, (Vec<String>, String, BrowserEngine)> =
    BTreeMap::new();
  for (platform, definitions) in &registry.platforms {
    if definitions.is_empty() {
      return Err(RegistryError::new(format!(
        "platform {platform} must contain at least one browser definition"
      )));
    }

    let mut identities = BTreeMap::<String, BrowserId>::new();
    let mut root_ids = BTreeSet::new();
    for definition in definitions {
      validate_browser_definition(platform, definition, &mut root_ids)?;
      insert_identity(
        &mut identities,
        definition.canonical_id.as_ref(),
        &definition.canonical_id,
        platform,
      )?;
      for alias in &definition.aliases {
        insert_identity(&mut identities, alias, &definition.canonical_id, platform)?;
      }

      let signature = (
        definition.aliases.clone(),
        definition.display_name.clone(),
        definition.engine.clone(),
      );
      if let Some(existing) = cross_platform_definitions.get(&definition.canonical_id) {
        if existing != &signature {
          return Err(RegistryError::new(format!(
            "browser {} changes aliases, display name, or engine across platform groups",
            definition.canonical_id
          )));
        }
      } else {
        cross_platform_definitions.insert(definition.canonical_id.clone(), signature);
      }
    }
  }

  Ok(())
}

fn validate_browser_definition(
  platform: &PlatformId,
  definition: &BrowserDefinition,
  platform_root_ids: &mut BTreeSet<RootId>,
) -> Result<(), RegistryError> {
  if !FROZEN_CANONICAL_IDS.contains(&definition.canonical_id.as_ref()) {
    return Err(RegistryError::new(format!(
      "browser canonical ID {} is not in the frozen registry ID list",
      definition.canonical_id
    )));
  }
  if definition.display_name.trim() != definition.display_name || definition.display_name.is_empty()
  {
    return Err(RegistryError::new(format!(
      "browser {} has an empty or untrimmed display name",
      definition.canonical_id
    )));
  }
  validate_aliases(definition)?;
  validate_frozen_aliases(definition)?;

  if definition.roots.is_empty() {
    return Err(RegistryError::new(format!(
      "browser {} on {platform} has no installation roots",
      definition.canonical_id
    )));
  }

  let mut priorities = BTreeSet::new();
  let mut prior_priority = None;
  for root in &definition.roots {
    if root.template.trim() != root.template || root.template.is_empty() {
      return Err(RegistryError::new(format!(
        "root {} has an empty or untrimmed template",
        root.root_id
      )));
    }
    if root.template.contains("{channel}") {
      return Err(RegistryError::new(format!(
        "root {} must use an exact channel-specific template",
        root.root_id
      )));
    }
    if !is_open_identifier(&root.channel) {
      return Err(RegistryError::new(format!(
        "root {} channel must be a validated identifier, got {:?}",
        root.root_id, root.channel
      )));
    }
    if !priorities.insert(root.priority) {
      return Err(RegistryError::new(format!(
        "browser {} on {platform} repeats root priority {}",
        definition.canonical_id, root.priority
      )));
    }
    if prior_priority.is_some_and(|priority| root.priority <= priority) {
      return Err(RegistryError::new(format!(
        "browser {} roots on {platform} are not in ascending priority order",
        definition.canonical_id
      )));
    }
    prior_priority = Some(root.priority);
    if !platform_root_ids.insert(root.root_id.clone()) {
      return Err(RegistryError::new(format!(
        "platform {platform} repeats root ID {}",
        root.root_id
      )));
    }
  }

  ensure_unique(
    &definition.capabilities.declared_persistent_formats,
    "persistent format",
    &definition.canonical_id,
    platform,
  )?;
  ensure_unique(
    &definition.capabilities.declared_session_formats,
    "session format",
    &definition.canonical_id,
    platform,
  )?;
  ensure_unique(
    &definition.capabilities.declared_decryption_tiers,
    "cipher tier",
    &definition.canonical_id,
    platform,
  )?;
  if definition
    .capabilities
    .declared_persistent_formats
    .is_empty()
    && definition.capabilities.declared_session_formats.is_empty()
  {
    return Err(RegistryError::new(format!(
      "browser {} on {platform} declares no cookie source format",
      definition.canonical_id
    )));
  }

  Ok(())
}

fn ensure_unique<T: fmt::Display + Ord>(
  values: &[T],
  kind: &str,
  browser: &BrowserId,
  platform: &PlatformId,
) -> Result<(), RegistryError> {
  let mut seen = BTreeSet::new();
  for value in values {
    if !seen.insert(value) {
      return Err(RegistryError::new(format!(
        "browser {browser} on {platform} repeats {kind} {value}"
      )));
    }
  }
  Ok(())
}

fn validate_aliases(definition: &BrowserDefinition) -> Result<(), RegistryError> {
  let mut aliases = BTreeSet::new();
  for alias in &definition.aliases {
    let valid = !alias.is_empty()
      && alias.trim() == alias
      && alias.chars().all(|character| {
        character.is_ascii_lowercase()
          || character.is_ascii_digit()
          || matches!(character, '_' | '-' | ' ')
      });
    if !valid {
      return Err(RegistryError::new(format!(
        "browser {} has invalid alias {alias:?}",
        definition.canonical_id
      )));
    }
    if alias == definition.canonical_id.as_ref() || !aliases.insert(alias) {
      return Err(RegistryError::new(format!(
        "browser {} repeats identity {alias:?}",
        definition.canonical_id
      )));
    }
  }
  Ok(())
}

const FROZEN_CANONICAL_IDS: &[&str] = &[
  "arc",
  "brave",
  "browser_from_vought",
  "cachy",
  "chrome",
  "chromium",
  "coccoc",
  "dc_browser",
  "duckduckgo",
  "edge",
  "firefox",
  "internet_explorer",
  "librewolf",
  "octo_browser",
  "opera",
  "opera_gx",
  "qq_browser",
  "safari",
  "sogou",
  "speed_360",
  "speed_360x",
  "vivaldi",
  "yandex",
  "zen",
];

fn frozen_aliases(canonical_id: &str) -> &'static [&'static str] {
  match canonical_id {
    "browser_from_vought" => &["vought"],
    "dc_browser" => &["dc"],
    "internet_explorer" => &["ie"],
    "opera_gx" => &["opera gx", "opera-gx"],
    "qq_browser" => &["qq"],
    "speed_360" => &["360"],
    "speed_360x" => &["360x"],
    _ => &[],
  }
}

fn validate_frozen_aliases(definition: &BrowserDefinition) -> Result<(), RegistryError> {
  let actual: BTreeSet<_> = definition.aliases.iter().map(String::as_str).collect();
  for required in frozen_aliases(definition.canonical_id.as_ref()) {
    if !actual.contains(required) {
      return Err(RegistryError::new(format!(
        "browser {} does not preserve required alias {required:?}",
        definition.canonical_id
      )));
    }
  }
  Ok(())
}

fn insert_identity(
  identities: &mut BTreeMap<String, BrowserId>,
  identity: &str,
  canonical_id: &BrowserId,
  platform: &PlatformId,
) -> Result<(), RegistryError> {
  if let Some(existing) = identities.insert(identity.to_owned(), canonical_id.clone()) {
    return Err(RegistryError::new(format!(
      "identity {identity:?} on {platform} is shared by {existing} and {canonical_id}"
    )));
  }
  Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EffectiveBrowserCapabilities {
  pub(crate) declared_persistent_formats: Vec<CookieSourceFormatId>,
  pub(crate) declared_session_formats: Vec<CookieSourceFormatId>,
  pub(crate) declared_decryption_tiers: Vec<CipherTierId>,
  pub(crate) available_decryption_tiers: Vec<CipherTierId>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct CompiledCipherProviders {
  tiers: BTreeSet<CipherTierId>,
}

impl CompiledCipherProviders {
  pub(crate) fn for_platform(platform: Platform) -> Self {
    if Platform::current().ok() != Some(platform) {
      return Self::default();
    }
    let names: &[&str] = match platform {
      Platform::Linux => &["v10", "v11"],
      Platform::Macos => &["v10"],
      Platform::Windows if cfg!(all(target_os = "windows", feature = "appbound")) => {
        &["legacy_dpapi", "v10", "v20"]
      }
      Platform::Windows => &["legacy_dpapi", "v10"],
    };
    Self {
      tiers: names
        .iter()
        .map(|name| {
          name
            .parse()
            .expect("built-in cipher tier identifiers are valid")
        })
        .collect(),
    }
  }
}

pub(crate) fn effective_capabilities(
  declared: &BrowserCapabilities,
  providers: &CompiledCipherProviders,
) -> EffectiveBrowserCapabilities {
  EffectiveBrowserCapabilities {
    declared_persistent_formats: declared.declared_persistent_formats.clone(),
    declared_session_formats: declared.declared_session_formats.clone(),
    declared_decryption_tiers: declared.declared_decryption_tiers.clone(),
    available_decryption_tiers: declared
      .declared_decryption_tiers
      .iter()
      .filter(|tier| providers.tiers.contains(*tier))
      .cloned()
      .collect(),
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DiscoveryMetadata {
  pub(crate) is_file: bool,
  pub(crate) is_dir: bool,
}

pub(crate) trait DiscoveryFs {
  fn stat(&self, path: &Path) -> Result<DiscoveryMetadata, DiscoveryError>;
  fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>, DiscoveryError>;
  fn glob(&self, pattern: &Path) -> Result<Vec<PathBuf>, DiscoveryError>;
  fn canonicalize(&self, path: &Path) -> Result<PathBuf, DiscoveryError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DiscoveryError {
  pub(crate) operation: &'static str,
  pub(crate) path: PathBuf,
  pub(crate) message: String,
}

impl DiscoveryError {
  fn new(operation: &'static str, path: &Path, message: impl Into<String>) -> Self {
    Self {
      operation,
      path: path.to_owned(),
      message: message.into(),
    }
  }

  fn from_io(operation: &'static str, path: &Path, error: io::Error) -> Self {
    Self::new(operation, path, error.to_string())
  }
}

impl fmt::Display for DiscoveryError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      formatter,
      "{} {}: {}",
      self.operation,
      self.path.display(),
      self.message
    )
  }
}

impl Error for DiscoveryError {}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemDiscoveryFs;

impl DiscoveryFs for SystemDiscoveryFs {
  fn stat(&self, path: &Path) -> Result<DiscoveryMetadata, DiscoveryError> {
    fs::metadata(path)
      .map(|metadata| DiscoveryMetadata {
        is_file: metadata.is_file(),
        is_dir: metadata.is_dir(),
      })
      .map_err(|error| DiscoveryError::from_io("stat", path, error))
  }

  fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>, DiscoveryError> {
    let entries =
      fs::read_dir(path).map_err(|error| DiscoveryError::from_io("read directory", path, error))?;
    entries
      .map(|entry| {
        entry
          .map(|entry| entry.path())
          .map_err(|error| DiscoveryError::from_io("read directory entry", path, error))
      })
      .collect()
  }

  fn glob(&self, pattern: &Path) -> Result<Vec<PathBuf>, DiscoveryError> {
    let Some(pattern_string) = pattern.to_str() else {
      return match fs::metadata(pattern) {
        Ok(_) => Ok(vec![pattern.to_owned()]),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(DiscoveryError::from_io("stat", pattern, error)),
      };
    };
    if !pattern_string.contains(['*', '?', '[']) {
      return match fs::metadata(pattern) {
        Ok(_) => Ok(vec![pattern.to_owned()]),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(DiscoveryError::from_io("stat", pattern, error)),
      };
    }

    let entries = glob::glob(pattern_string)
      .map_err(|error| DiscoveryError::new("parse glob", pattern, error.to_string()))?;
    entries
      .map(|entry| {
        entry.map_err(|error| {
          DiscoveryError::new("expand glob", error.path(), error.error().to_string())
        })
      })
      .collect()
  }

  fn canonicalize(&self, path: &Path) -> Result<PathBuf, DiscoveryError> {
    fs::canonicalize(path).map_err(|error| DiscoveryError::from_io("canonicalize", path, error))
  }
}

pub(crate) struct DiscoveryContext<F> {
  pub(crate) platform: Platform,
  pub(crate) home: PathBuf,
  pub(crate) env: BTreeMap<OsString, OsString>,
  pub(crate) fs: F,
}

impl DiscoveryContext<SystemDiscoveryFs> {
  pub(crate) fn from_process() -> Result<Self, DiscoveryError> {
    let platform = Platform::current().map_err(|error| {
      DiscoveryError::new(
        "select platform",
        Path::new("browser_registry.json"),
        error.to_string(),
      )
    })?;
    let env: BTreeMap<_, _> = std::env::vars_os().collect();
    let home = process_home(platform, &env)?;
    Ok(Self {
      platform,
      home,
      env,
      fs: SystemDiscoveryFs,
    })
  }
}

fn process_home(
  platform: Platform,
  env: &BTreeMap<OsString, OsString>,
) -> Result<PathBuf, DiscoveryError> {
  let candidates: &[&str] = match platform {
    Platform::Windows => &["USERPROFILE", "HOME"],
    Platform::Linux | Platform::Macos => &["HOME"],
  };
  candidates
    .iter()
    .find_map(|name| lookup_env(platform, env, name))
    .filter(|value| !value.is_empty())
    .map(PathBuf::from)
    .ok_or_else(|| {
      DiscoveryError::new(
        "resolve home",
        Path::new("~"),
        format!("none of {} is set", candidates.join(", ")),
      )
    })
}

fn lookup_env<'a>(
  platform: Platform,
  env: &'a BTreeMap<OsString, OsString>,
  name: &str,
) -> Option<&'a OsStr> {
  env
    .get(OsStr::new(name))
    .or_else(|| {
      (platform == Platform::Windows).then(|| {
        env
          .iter()
          .find(|(key, _)| {
            key
              .to_str()
              .is_some_and(|key| key.eq_ignore_ascii_case(name))
          })
          .map(|(_, value)| value)
      })?
    })
    .map(OsString::as_os_str)
}

fn expand_root_template<F>(
  context: &DiscoveryContext<F>,
  root: &InstallationRoot,
) -> Result<PathBuf, DiscoveryError> {
  let template = root.template.as_str();
  if template == "~" {
    return Ok(context.home.clone());
  }
  if let Some(remainder) = template
    .strip_prefix("~/")
    .or_else(|| template.strip_prefix("~\\"))
  {
    let expanded = expand_percent_variables(context.platform, &context.env, remainder)?;
    return Ok(context.home.join(expanded));
  }
  expand_percent_variables(context.platform, &context.env, template).map(PathBuf::from)
}

fn expand_percent_variables(
  platform: Platform,
  env: &BTreeMap<OsString, OsString>,
  template: &str,
) -> Result<OsString, DiscoveryError> {
  let mut expanded = OsString::new();
  let mut cursor = 0;
  while let Some(relative_open) = template[cursor..].find('%') {
    let open = cursor + relative_open;
    expanded.push(&template[cursor..open]);
    let after_open = open + 1;
    let Some(relative_close) = template[after_open..].find('%') else {
      return Err(DiscoveryError::new(
        "expand environment",
        Path::new(template),
        "unclosed percent-delimited variable",
      ));
    };
    let close = after_open + relative_close;
    let name = &template[after_open..close];
    if name.is_empty()
      || !name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
      return Err(DiscoveryError::new(
        "expand environment",
        Path::new(template),
        format!("invalid environment variable name {name:?}"),
      ));
    }
    let value = lookup_env(platform, env, name).ok_or_else(|| {
      DiscoveryError::new(
        "expand environment",
        Path::new(template),
        format!("environment variable {name} is not set"),
      )
    })?;
    expanded.push(value);
    cursor = close + 1;
  }
  expanded.push(&template[cursor..]);
  Ok(expanded)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedInstallationRoot {
  pub(crate) root_id: RootId,
  pub(crate) channel: String,
  pub(crate) discovery: DiscoveryStrategy,
  pub(crate) priority: u16,
  pub(crate) path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RootResolutionIssueStage {
  TemplateExpansion,
  Glob,
  Canonicalize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RootResolutionIssue {
  pub(crate) root_id: RootId,
  pub(crate) stage: RootResolutionIssueStage,
  pub(crate) error: DiscoveryError,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct BrowserRootResolution {
  pub(crate) roots: Vec<ResolvedInstallationRoot>,
  pub(crate) issues: Vec<RootResolutionIssue>,
}

pub(crate) fn resolve_browser_roots<F: DiscoveryFs>(
  context: &DiscoveryContext<F>,
  browser: &BrowserDefinition,
) -> BrowserRootResolution {
  let mut roots: Vec<_> = browser.roots.iter().collect();
  roots.sort_by(|left, right| {
    left
      .priority
      .cmp(&right.priority)
      .then_with(|| left.root_id.cmp(&right.root_id))
  });

  let mut resolution = BrowserRootResolution::default();
  let mut seen = BTreeSet::new();
  for root in roots {
    let pattern = match expand_root_template(context, root) {
      Ok(pattern) => pattern,
      Err(error) => {
        resolution.issues.push(RootResolutionIssue {
          root_id: root.root_id.clone(),
          stage: RootResolutionIssueStage::TemplateExpansion,
          error,
        });
        continue;
      }
    };
    let mut candidates = match context.fs.glob(&pattern) {
      Ok(candidates) => candidates,
      Err(error) => {
        resolution.issues.push(RootResolutionIssue {
          root_id: root.root_id.clone(),
          stage: RootResolutionIssueStage::Glob,
          error,
        });
        continue;
      }
    };
    candidates.sort();
    for candidate in candidates {
      let canonical = match context.fs.canonicalize(&candidate) {
        Ok(canonical) => canonical,
        Err(error) => {
          resolution.issues.push(RootResolutionIssue {
            root_id: root.root_id.clone(),
            stage: RootResolutionIssueStage::Canonicalize,
            error,
          });
          continue;
        }
      };
      if seen.insert(canonical.clone()) {
        resolution.roots.push(ResolvedInstallationRoot {
          root_id: root.root_id.clone(),
          channel: root.channel.clone(),
          discovery: root.discovery.clone(),
          priority: root.priority,
          path: canonical,
        });
      }
    }
  }
  resolution
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::Value;

  #[derive(Default)]
  struct FakeDiscoveryFs {
    glob_results: BTreeMap<PathBuf, Vec<PathBuf>>,
    glob_errors: BTreeMap<PathBuf, String>,
    canonical_paths: BTreeMap<PathBuf, PathBuf>,
    canonical_errors: BTreeMap<PathBuf, String>,
  }

  impl DiscoveryFs for FakeDiscoveryFs {
    fn stat(&self, path: &Path) -> Result<DiscoveryMetadata, DiscoveryError> {
      Ok(DiscoveryMetadata {
        is_file: false,
        is_dir: self
          .glob_results
          .values()
          .flatten()
          .any(|candidate| candidate == path),
      })
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>, DiscoveryError> {
      Ok(self.glob_results.get(path).cloned().unwrap_or_default())
    }

    fn glob(&self, pattern: &Path) -> Result<Vec<PathBuf>, DiscoveryError> {
      if let Some(message) = self.glob_errors.get(pattern) {
        return Err(DiscoveryError::new("glob", pattern, message));
      }
      Ok(self.glob_results.get(pattern).cloned().unwrap_or_default())
    }

    fn canonicalize(&self, path: &Path) -> Result<PathBuf, DiscoveryError> {
      if let Some(message) = self.canonical_errors.get(path) {
        return Err(DiscoveryError::new("canonicalize", path, message));
      }
      Ok(
        self
          .canonical_paths
          .get(path)
          .cloned()
          .unwrap_or_else(|| path.to_owned()),
      )
    }
  }

  fn registry() -> Registry {
    serde_json::from_str(EMBEDDED_REGISTRY).expect("embedded registry parses")
  }

  fn chrome_on(platform: Platform) -> BrowserDefinition {
    load_platform_registry(EMBEDDED_REGISTRY, platform)
      .expect("platform registry loads")
      .definitions
      .into_iter()
      .find(|definition| definition.canonical_id.as_ref() == "chrome")
      .expect("Chrome is registered")
  }

  fn fixture_root(root_id: &str, template: &str, priority: u16) -> InstallationRoot {
    InstallationRoot {
      root_id: root_id.parse().unwrap(),
      template: template.to_owned(),
      channel: "stable".to_owned(),
      discovery: "chromium_profiles".parse().unwrap(),
      priority,
    }
  }

  #[test]
  fn embedded_registry_smoke_loads_current_platform() {
    let registry = current_registry().expect("embedded current-platform registry loads");
    assert_eq!(registry.platform, Platform::current().unwrap());
    assert_eq!(registry.definitions.len(), 1);
    assert_eq!(registry.definitions[0].canonical_id.as_ref(), "chrome");
  }

  #[test]
  fn registry_has_exact_ordered_chrome_roots_and_legacy_id_parity() {
    let legacy: Value = serde_json::from_str(include_str!("../config.json")).unwrap();
    let legacy_platforms = legacy["platforms"].as_object().unwrap();
    for (platform, expected_roots, expected_tiers) in [
      (
        Platform::Linux,
        vec![
          ("chrome_stable", "~/.config/google-chrome", "stable", 0),
          ("chrome_beta", "~/.config/google-chrome-beta", "beta", 1),
          ("chrome_dev", "~/.config/google-chrome-unstable", "dev", 2),
        ],
        vec!["v10", "v11"],
      ),
      (
        Platform::Macos,
        vec![
          (
            "chrome_stable",
            "~/Library/Application Support/Google/Chrome",
            "stable",
            0,
          ),
          (
            "chrome_beta",
            "~/Library/Application Support/Google/Chrome Beta",
            "beta",
            1,
          ),
          (
            "chrome_dev",
            "~/Library/Application Support/Google/Chrome Dev",
            "dev",
            2,
          ),
          (
            "chrome_canary",
            "~/Library/Application Support/Google/Chrome Canary",
            "canary",
            3,
          ),
        ],
        vec!["v10"],
      ),
      (
        Platform::Windows,
        vec![
          (
            "chrome_local_stable",
            "%LOCALAPPDATA%/Google/Chrome/User Data",
            "stable",
            0,
          ),
          (
            "chrome_local_beta",
            "%LOCALAPPDATA%/Google/Chrome Beta/User Data",
            "beta",
            1,
          ),
          (
            "chrome_local_dev",
            "%LOCALAPPDATA%/Google/Chrome Dev/User Data",
            "dev",
            2,
          ),
          (
            "chrome_local_canary",
            "%LOCALAPPDATA%/Google/Chrome SxS/User Data",
            "canary",
            3,
          ),
        ],
        vec!["legacy_dpapi", "v10", "v20"],
      ),
    ] {
      let loaded = load_platform_registry(EMBEDDED_REGISTRY, platform).unwrap();
      let chrome = &loaded.definitions[0];
      assert_eq!(
        chrome
          .roots
          .iter()
          .map(|root| (
            root.root_id.as_ref(),
            root.template.as_str(),
            root.channel.as_str(),
            root.priority,
          ))
          .collect::<Vec<_>>(),
        expected_roots
      );
      assert_eq!(
        chrome
          .capabilities
          .declared_decryption_tiers
          .iter()
          .map(AsRef::as_ref)
          .collect::<Vec<_>>(),
        expected_tiers
      );
      assert!(legacy_platforms[platform.as_str()][chrome.canonical_id.as_ref()].is_object());
    }
  }

  #[test]
  fn registry_rejects_schema_alias_root_and_capability_invariant_breaks() {
    let mut invalid = registry();
    invalid.schema_version += 1;
    assert!(validate_registry(&invalid)
      .unwrap_err()
      .to_string()
      .contains("schema version"));

    let mut invalid = registry();
    invalid.platforms.get_mut(&Platform::Linux.id()).unwrap()[0].canonical_id =
      "chorme".parse().unwrap();
    assert!(validate_registry(&invalid)
      .unwrap_err()
      .to_string()
      .contains("not in the frozen registry ID list"));

    let mut invalid = registry();
    invalid.platforms.get_mut(&Platform::Linux.id()).unwrap()[0]
      .aliases
      .push("chrome".to_owned());
    assert!(validate_registry(&invalid)
      .unwrap_err()
      .to_string()
      .contains("repeats identity"));

    let mut invalid = registry();
    let browser = &mut invalid.platforms.get_mut(&Platform::Linux.id()).unwrap()[0];
    browser.roots[1].root_id = browser.roots[0].root_id.clone();
    assert!(validate_registry(&invalid)
      .unwrap_err()
      .to_string()
      .contains("repeats root ID"));

    let mut invalid = registry();
    invalid.platforms.get_mut(&Platform::Linux.id()).unwrap()[0].roots[0]
      .template
      .push_str("{channel}");
    assert!(validate_registry(&invalid)
      .unwrap_err()
      .to_string()
      .contains("exact channel-specific template"));

    let mut invalid = registry();
    invalid.platforms.get_mut(&Platform::Linux.id()).unwrap()[0].roots[0].channel =
      "-beta".to_owned();
    assert!(validate_registry(&invalid)
      .unwrap_err()
      .to_string()
      .contains("validated identifier"));

    let mut invalid = registry();
    let tiers = &mut invalid.platforms.get_mut(&Platform::Linux.id()).unwrap()[0]
      .capabilities
      .declared_decryption_tiers;
    tiers.push(tiers[0].clone());
    assert!(validate_registry(&invalid)
      .unwrap_err()
      .to_string()
      .contains("repeats cipher tier"));
  }

  #[test]
  fn identifiers_are_open_but_validated_and_required_aliases_are_preserved() {
    assert!("future_cipher_2".parse::<CipherTierId>().is_ok());
    assert!("V20".parse::<CipherTierId>().is_err());
    assert!("2future".parse::<CipherTierId>().is_err());
    assert!("future-tier".parse::<CipherTierId>().is_err());
    assert!(FROZEN_CANONICAL_IDS
      .iter()
      .all(|identifier| identifier.parse::<BrowserId>().is_ok()));

    let mut definition = chrome_on(Platform::Linux);
    definition.canonical_id = "opera_gx".parse().unwrap();
    definition.aliases = vec!["opera gx".to_owned()];
    assert!(validate_frozen_aliases(&definition).is_err());
    definition.aliases.push("opera-gx".to_owned());
    assert!(validate_frozen_aliases(&definition).is_ok());
  }

  #[test]
  fn effective_tiers_use_only_providers_compiled_for_the_current_target() {
    let current = Platform::current().unwrap();
    let chrome = chrome_on(current);
    let effective = effective_capabilities(
      &chrome.capabilities,
      &CompiledCipherProviders::for_platform(current),
    );
    let expected = match current {
      Platform::Linux => vec!["v10", "v11"],
      Platform::Macos => vec!["v10"],
      Platform::Windows if cfg!(feature = "appbound") => {
        vec!["legacy_dpapi", "v10", "v20"]
      }
      Platform::Windows => vec!["legacy_dpapi", "v10"],
    };
    assert_eq!(
      effective
        .available_decryption_tiers
        .iter()
        .map(AsRef::as_ref)
        .collect::<Vec<_>>(),
      expected
    );

    for other in [Platform::Linux, Platform::Macos, Platform::Windows] {
      if other != current {
        assert_eq!(
          CompiledCipherProviders::for_platform(other),
          CompiledCipherProviders::default(),
          "a build for {} must not advertise {} providers",
          current.as_str(),
          other.as_str()
        );
      }
    }

    let windows = chrome_on(Platform::Windows);
    let windows_effective = effective_capabilities(
      &windows.capabilities,
      &CompiledCipherProviders::for_platform(Platform::Windows),
    );
    let advertises_v20 = windows_effective
      .available_decryption_tiers
      .iter()
      .any(|tier| tier.as_ref() == "v20");
    assert_eq!(
      advertises_v20,
      cfg!(all(target_os = "windows", feature = "appbound")),
      "v20 is available only when its Windows app-bound provider is compiled"
    );
  }

  #[test]
  fn root_template_expands_only_leading_tilde_and_injected_environment() {
    let mut env = BTreeMap::new();
    env.insert(
      OsString::from("localappdata"),
      OsString::from("/fixtures/local"),
    );
    let context = DiscoveryContext {
      platform: Platform::Windows,
      home: PathBuf::from("/fixtures/home"),
      env,
      fs: FakeDiscoveryFs::default(),
    };
    let mut root = chrome_on(Platform::Windows).roots[1].clone();
    assert_eq!(
      expand_root_template(&context, &root).unwrap(),
      PathBuf::from("/fixtures/local/Google/Chrome Beta/User Data")
    );

    root.template = "~/prefix/~/Chrome Beta".to_owned();
    assert_eq!(
      expand_root_template(&context, &root).unwrap(),
      PathBuf::from("/fixtures/home/prefix/~/Chrome Beta")
    );
    root.template = "prefix/~/Chrome Beta".to_owned();
    assert_eq!(
      expand_root_template(&context, &root).unwrap(),
      PathBuf::from("prefix/~/Chrome Beta")
    );
  }

  #[test]
  fn missing_injected_environment_is_a_typed_root_error() {
    let context = DiscoveryContext {
      platform: Platform::Windows,
      home: PathBuf::from("/fixtures/home"),
      env: BTreeMap::new(),
      fs: FakeDiscoveryFs::default(),
    };
    let root = &chrome_on(Platform::Windows).roots[0];
    let error = expand_root_template(&context, root).unwrap_err();
    assert_eq!(error.operation, "expand environment");
    assert!(error.message.contains("LOCALAPPDATA"));
  }

  #[test]
  fn root_resolution_sorts_globs_before_canonical_deduplication() {
    let pattern = PathBuf::from("/fixtures/roots/*");
    let mut fs = FakeDiscoveryFs::default();
    fs.glob_results.insert(
      pattern.clone(),
      vec![
        PathBuf::from("/fixtures/roots/z"),
        PathBuf::from("/fixtures/roots/b-link"),
        PathBuf::from("/fixtures/roots/a-link"),
      ],
    );
    fs.canonical_paths.insert(
      PathBuf::from("/fixtures/roots/a-link"),
      PathBuf::from("/fixtures/real"),
    );
    fs.canonical_paths.insert(
      PathBuf::from("/fixtures/roots/b-link"),
      PathBuf::from("/fixtures/real"),
    );
    let context = DiscoveryContext {
      platform: Platform::Linux,
      home: PathBuf::from("/fixtures/home"),
      env: BTreeMap::new(),
      fs,
    };
    let mut browser = chrome_on(Platform::Linux);
    browser.roots = vec![InstallationRoot {
      root_id: "fixture_root".parse().unwrap(),
      template: pattern.to_string_lossy().into_owned(),
      channel: "stable".to_owned(),
      discovery: "chromium_profiles".parse().unwrap(),
      priority: 0,
    }];

    let resolution = resolve_browser_roots(&context, &browser);
    assert!(resolution.issues.is_empty());
    assert_eq!(
      resolution
        .roots
        .iter()
        .map(|root| root.path.as_path())
        .collect::<Vec<_>>(),
      vec![Path::new("/fixtures/real"), Path::new("/fixtures/roots/z")]
    );
  }

  #[test]
  fn root_resolution_preserves_successes_around_ordered_root_and_candidate_issues() {
    let mut fs = FakeDiscoveryFs::default();
    for (pattern, candidate) in [
      ("/patterns/success_a", "/resolved/a"),
      ("/patterns/success_b", "/resolved/b"),
      ("/patterns/success_c", "/resolved/c"),
      ("/patterns/success_d", "/resolved/d"),
    ] {
      fs.glob_results
        .insert(PathBuf::from(pattern), vec![PathBuf::from(candidate)]);
    }
    fs.glob_errors.insert(
      PathBuf::from("/patterns/glob_error"),
      "fixture glob failure".to_owned(),
    );
    fs.glob_results.insert(
      PathBuf::from("/patterns/canonical_error"),
      vec![PathBuf::from("/candidates/broken")],
    );
    fs.canonical_errors.insert(
      PathBuf::from("/candidates/broken"),
      "fixture canonicalize failure".to_owned(),
    );
    let context = DiscoveryContext {
      platform: Platform::Windows,
      home: PathBuf::from("/fixtures/home"),
      env: BTreeMap::new(),
      fs,
    };
    let mut browser = chrome_on(Platform::Windows);
    browser.roots = vec![
      fixture_root("success_a", "/patterns/success_a", 0),
      fixture_root("missing_env", "%MISSING%/Chrome", 1),
      fixture_root("success_b", "/patterns/success_b", 2),
      fixture_root("glob_error", "/patterns/glob_error", 3),
      fixture_root("success_c", "/patterns/success_c", 4),
      fixture_root("canonical_error", "/patterns/canonical_error", 5),
      fixture_root("success_d", "/patterns/success_d", 6),
    ];

    let resolution = resolve_browser_roots(&context, &browser);
    assert_eq!(
      resolution
        .roots
        .iter()
        .map(|root| root.root_id.as_ref())
        .collect::<Vec<_>>(),
      vec!["success_a", "success_b", "success_c", "success_d"]
    );
    assert_eq!(
      resolution
        .issues
        .iter()
        .map(|issue| (issue.root_id.as_ref(), issue.stage))
        .collect::<Vec<_>>(),
      vec![
        ("missing_env", RootResolutionIssueStage::TemplateExpansion),
        ("glob_error", RootResolutionIssueStage::Glob),
        ("canonical_error", RootResolutionIssueStage::Canonicalize),
      ]
    );
  }

  #[test]
  fn root_resolution_keeps_later_candidates_after_canonicalize_failure() {
    let pattern = PathBuf::from("/patterns/candidates/*");
    let mut fs = FakeDiscoveryFs::default();
    fs.glob_results.insert(
      pattern.clone(),
      vec![
        PathBuf::from("/candidates/c"),
        PathBuf::from("/candidates/b_broken"),
        PathBuf::from("/candidates/a"),
      ],
    );
    fs.canonical_errors.insert(
      PathBuf::from("/candidates/b_broken"),
      "fixture canonicalize failure".to_owned(),
    );
    let context = DiscoveryContext {
      platform: Platform::Linux,
      home: PathBuf::from("/fixtures/home"),
      env: BTreeMap::new(),
      fs,
    };
    let mut browser = chrome_on(Platform::Linux);
    browser.roots = vec![fixture_root(
      "candidate_fixture",
      pattern.to_str().unwrap(),
      0,
    )];

    let resolution = resolve_browser_roots(&context, &browser);
    assert_eq!(
      resolution
        .roots
        .iter()
        .map(|root| root.path.as_path())
        .collect::<Vec<_>>(),
      vec![Path::new("/candidates/a"), Path::new("/candidates/c")]
    );
    assert_eq!(resolution.issues.len(), 1);
    assert_eq!(
      resolution.issues[0].stage,
      RootResolutionIssueStage::Canonicalize
    );
    assert_eq!(
      resolution.issues[0].error.path,
      PathBuf::from("/candidates/b_broken")
    );
  }

  #[test]
  fn root_resolution_all_failures_are_retained_in_deterministic_order() {
    let mut fs = FakeDiscoveryFs::default();
    fs.glob_errors.insert(
      PathBuf::from("/patterns/glob_error"),
      "fixture glob failure".to_owned(),
    );
    fs.glob_results.insert(
      PathBuf::from("/patterns/canonical_error"),
      vec![PathBuf::from("/candidates/broken")],
    );
    fs.canonical_errors.insert(
      PathBuf::from("/candidates/broken"),
      "fixture canonicalize failure".to_owned(),
    );
    let context = DiscoveryContext {
      platform: Platform::Windows,
      home: PathBuf::from("/fixtures/home"),
      env: BTreeMap::new(),
      fs,
    };
    let mut browser = chrome_on(Platform::Windows);
    browser.roots = vec![
      fixture_root("missing_env", "%MISSING%/Chrome", 0),
      fixture_root("glob_error", "/patterns/glob_error", 1),
      fixture_root("canonical_error", "/patterns/canonical_error", 2),
    ];

    let resolution = resolve_browser_roots(&context, &browser);
    assert!(resolution.roots.is_empty());
    assert_eq!(
      resolution
        .issues
        .iter()
        .map(|issue| (issue.root_id.as_ref(), issue.stage))
        .collect::<Vec<_>>(),
      vec![
        ("missing_env", RootResolutionIssueStage::TemplateExpansion),
        ("glob_error", RootResolutionIssueStage::Glob),
        ("canonical_error", RootResolutionIssueStage::Canonicalize),
      ]
    );
  }

  #[test]
  fn discovery_fs_seam_covers_stat_and_read_dir_without_process_globals() {
    let mut fs = FakeDiscoveryFs::default();
    fs.glob_results.insert(
      PathBuf::from("/fixtures"),
      vec![PathBuf::from("/fixtures/profile")],
    );
    assert!(fs.stat(Path::new("/fixtures/profile")).unwrap().is_dir);
    assert!(!fs.stat(Path::new("/fixtures/profile")).unwrap().is_file);
    assert_eq!(
      fs.read_dir(Path::new("/fixtures")).unwrap(),
      vec![PathBuf::from("/fixtures/profile")]
    );
  }
}
