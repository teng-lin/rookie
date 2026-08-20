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
  selection: ProfileSelection<'_>,
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
  extract_chromium_with_provider(context, browser_id, selection, domains, &FixedKeys(keys))
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
  selection: ProfileSelection<'_>,
  domains: Option<&[String]>,
) -> Result<EngineExtract> {
  gecko_report_with_context(
    context,
    browser_id,
    selection,
    domains,
    crate::SessionPolicy::IncludeSession,
  )
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
  let discovery = gecko_profiles_with_context(context, browser_id)?;
  Ok(populate_gecko_sources(
    discovery,
    domains,
    crate::SessionPolicy::IncludeSession,
    |candidate, domains| {
      // The persistent probe is always the first candidate a profile
      // acquires, so gating on it fires the hook once per profile, before
      // any of that profile's reads.
      if candidate.role == crate::browser::report_core::CookieSourceRoleId::persistent() {
        on_before_query(&candidate.path);
      }
      mozilla::acquire_candidate_source(candidate, domains)
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
  selection: ProfileSelection<'_>,
  domains: Option<&[String]>,
) -> Result<EngineExtract> {
  safari_report_with_context(context, browser_id, selection, domains)
}

pub(crate) fn internet_explorer_report<Q>(
  context: &DiscoveryContext<RealDiscoveryFs>,
  browser_id: &str,
  selection: ProfileSelection<'_>,
  domains: Option<&[String]>,
  query: Q,
) -> Result<EngineExtract>
where
  Q: FnMut(SourceCandidate, Option<&[String]>) -> Result<Source>,
{
  internet_explorer_report_with_context(context, browser_id, selection, domains, query)
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

pub(crate) fn channel_root(context: &DiscoveryContext<RealDiscoveryFs>, channel: &str) -> PathBuf {
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
