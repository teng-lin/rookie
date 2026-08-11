use crate::{
  browser::mozilla::{list_profiles, MozillaProfile},
  config::Browser,
};
#[cfg(target_os = "windows")]
use anyhow::Context;
use anyhow::{anyhow, Result};
use std::{
  env,
  error::Error,
  fmt,
  path::{Path, PathBuf},
};

/// Path resolution reached every configured location without finding an
/// installed browser profile that contains a cookie database.
///
/// `load()` treats this as a normal "browser not installed" result. Keeping it
/// typed prevents genuine expansion, I/O, and extraction failures from being
/// mistaken for an absent browser based on their display text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BrowserNotInstalled {
  CookieDatabase,
  ProfileWithCookieDatabase,
}

impl fmt::Display for BrowserNotInstalled {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::CookieDatabase => write!(formatter, "Can't find cookies file"),
      Self::ProfileWithCookieDatabase => {
        write!(formatter, "Can't find any profile with a cookie database")
      }
    }
  }
}

impl Error for BrowserNotInstalled {}

pub(crate) fn is_browser_not_installed(error: &anyhow::Error) -> bool {
  error
    .chain()
    .any(|cause| cause.downcast_ref::<BrowserNotInstalled>().is_some())
}

fn expand_glob_paths(path: PathBuf) -> Result<Vec<PathBuf>> {
  let mut paths: Vec<PathBuf> = vec![];
  if let Some(path_str) = path.to_str() {
    for entry in glob::glob(path_str)? {
      match entry {
        Ok(path) => paths.push(path),
        Err(error) => {
          log::warn!("Skipping inaccessible glob candidate: {error}");
        }
      }
    }
  }
  Ok(paths)
}

pub fn find_chrome_based_paths(config: &Browser) -> Result<(PathBuf, PathBuf)> {
  for db_path in expand_config_paths(config)? {
    if db_path.exists() {
      if let Some(parent) = db_path.parent() {
        let candidates = ["../../Local State", "../Local State", "Local State"]
          .map(|candidate| parent.join(candidate));
        let existing = candidates.iter().find(|candidate| candidate.exists());

        #[cfg(target_os = "windows")]
        let key_path = existing
          .ok_or_else(|| {
            anyhow!(
              "can't find Local State for Chromium cookie database {}",
              db_path.display()
            )
          })?
          .canonicalize()
          .context("canonicalize Local State")?;

        // Unix key retrieval uses the browser/keyring metadata from `config`,
        // not Local State. Preserve the tuple-shaped legacy selector while
        // allowing copied or otherwise minimal profiles to be discovered.
        #[cfg(unix)]
        let key_path = existing
          .and_then(|candidate| candidate.canonicalize().ok())
          .unwrap_or_else(|| candidates[0].clone());

        log::debug!(
          "Found chrome path {}, {}",
          db_path.display(),
          key_path.display()
        );
        return Ok((key_path, db_path));
      }
    }
  }
  Err(BrowserNotInstalled::CookieDatabase.into())
}

/// Expands every configured base path for `config` across its channels and glob
/// patterns.
///
/// A path that cannot be expanded is logged and skipped so one bad entry does
/// not abort the whole search — but if that leaves nothing at all, the first
/// failure is returned rather than letting the caller report a misleading
/// "can't find cookies file". On Unix an unset `HOME` only invalidates entries
/// that actually reference it.
fn expand_config_paths_with(
  config: &Browser,
  mut expand: impl FnMut(&str) -> Result<PathBuf>,
) -> Result<Vec<PathBuf>> {
  let channels = config
    .channels
    .clone()
    .unwrap_or_else(|| vec![String::new()]);
  let mut bases: Vec<PathBuf> = vec![];
  let mut first_error: Option<anyhow::Error> = None;
  let mut usable_patterns = 0usize;
  for path in &config.paths {
    for channel in &channels {
      let path = path.replace("{channel}", channel);
      match expand(path.as_str()).and_then(expand_glob_paths) {
        Ok(expanded) => {
          usable_patterns += 1;
          bases.extend(expanded);
        }
        Err(err) => {
          log::warn!("Skipping unusable path {path}: {err}");
          first_error.get_or_insert(err);
        }
      }
    }
  }

  match first_error {
    Some(err) if usable_patterns == 0 => Err(err.context("no browser path could be expanded")),
    _ => Ok(bases),
  }
}

fn expand_config_paths(config: &Browser) -> Result<Vec<PathBuf>> {
  expand_config_paths_with(config, |path| expand_path(path, true))
}

/// Profiles declared under `base`, default first, so callers probe the profile
/// the browser actually opens before any secondary one.
///
/// A missing `profiles.ini` is a valid empty declaration because legacy and
/// portable layouts can store `cookies.sqlite` directly under `base`. A file
/// that exists but cannot be parsed is a real discovery failure and remains
/// typed separately from an absent browser.
fn mozilla_profiles_in(base: &Path) -> Result<Vec<MozillaProfile>> {
  let profiles_path = base.join("profiles.ini");
  let mut profiles = match list_profiles(profiles_path.as_path()) {
    Ok(profiles) => profiles,
    Err(err) => {
      if profiles_path.exists() {
        log::warn!("Failed to read {}: {err}", profiles_path.display());
        return Err(err.context(format!(
          "Failed to read Mozilla profiles from {}",
          profiles_path.display()
        )));
      }
      log::debug!("No profiles.ini at {}", profiles_path.display());
      return Ok(vec![]);
    }
  };
  profiles.sort_by_key(|profile| !profile.is_default);
  Ok(profiles)
}

pub fn find_mozilla_based_paths(config: &Browser) -> Result<PathBuf> {
  let mut first_error: Option<anyhow::Error> = None;
  for base in expand_config_paths(config)? {
    let profiles = match mozilla_profiles_in(&base) {
      Ok(profiles) => profiles,
      Err(err) => {
        first_error.get_or_insert(err);
        vec![]
      }
    };
    let candidates = profiles
      .into_iter()
      .map(|profile| profile.path)
      // Probing the base directory itself preserves the behaviour of the
      // pre-enumeration resolver, which fell back to `<base>/cookies.sqlite`
      // whenever profiles.ini was missing or unresolvable.
      .chain(std::iter::once(base));
    for candidate in candidates {
      let db_path = candidate.join("cookies.sqlite");
      if db_path.exists() {
        log::debug!("Found mozilla path {}", db_path.display());
        return Ok(db_path);
      }
    }
  }

  match first_error {
    Some(err) => Err(err),
    None => Err(BrowserNotInstalled::CookieDatabase.into()),
  }
}

/// Records `profile` unless an earlier root already yielded the same directory.
///
/// Roots are compared canonically: snap and flatpak layouts reach one profile
/// through several lexical or symlinked paths, and a duplicate would make
/// selecting that profile by name ambiguous. A duplicate still contributes its
/// `is_default` flag, since the same directory can be a secondary profile for
/// one installation and the default for another.
fn push_unique(found: &mut Vec<MozillaProfile>, seen: &mut Vec<PathBuf>, profile: MozillaProfile) {
  let key = profile
    .path
    .canonicalize()
    .unwrap_or_else(|_| profile.path.clone());
  if let Some(index) = seen.iter().position(|existing| *existing == key) {
    found[index].is_default |= profile.is_default;
    return;
  }
  seen.push(key);
  found.push(profile);
}

/// Returns every Mozilla profile for `config` that holds a cookie database.
///
/// Profiles are gathered across every configured installation root, so the
/// result can contain more than one entry with `is_default` set — see
/// [`MozillaProfile::is_default`].
pub fn find_mozilla_based_profiles(config: &Browser) -> Result<Vec<MozillaProfile>> {
  let mut found: Vec<MozillaProfile> = vec![];
  let mut seen: Vec<PathBuf> = vec![];
  let mut first_error: Option<anyhow::Error> = None;

  for base in expand_config_paths(config)? {
    let declared = match mozilla_profiles_in(&base) {
      Ok(profiles) => Some(profiles),
      Err(err) => {
        first_error.get_or_insert(err);
        None
      }
    };
    let mut usable = 0;
    for profile in declared.iter().flatten().cloned() {
      if profile.path.join("cookies.sqlite").exists() {
        usable += 1;
        push_unique(&mut found, &mut seen, profile);
      }
    }

    // Mirror the base-directory fallback in `find_mozilla_based_paths`, so a
    // layout that `firefox()` can read never looks profile-less here. It counts
    // as the default only when a readable profiles.ini named no profile at all:
    // if one was declared, the browser would still open it, and if the file
    // could not be read we have no idea what it declares.
    if usable == 0 && base.join("cookies.sqlite").exists() {
      push_unique(
        &mut found,
        &mut seen,
        MozillaProfile {
          name: String::new(),
          path: base,
          is_default: declared.is_some_and(|declared| declared.is_empty()),
        },
      );
    }
  }

  if found.is_empty() {
    return match first_error {
      Some(err) => Err(err),
      None => Err(BrowserNotInstalled::ProfileWithCookieDatabase.into()),
    };
  }
  Ok(found)
}

#[cfg(target_os = "macos")]
pub fn find_safari_based_paths(config: &Browser) -> Result<PathBuf> {
  for path in expand_config_paths(config)? {
    if path.exists() {
      log::debug!("Found safari path {}", path.display());
      return Ok(path);
    }
  }
  Err(BrowserNotInstalled::CookieDatabase.into())
}

#[cfg(target_os = "windows")]
pub fn find_ie_based_paths(config: &Browser) -> Result<PathBuf> {
  for path in expand_config_paths(config)? {
    if path.exists() {
      log::debug!("Found IE path {}", path.display());
      return Ok(path);
    }
  }

  Err(BrowserNotInstalled::CookieDatabase.into())
}

#[cfg(target_os = "windows")]
fn expand_windows_path(path: &str, escape_glob_metacharacters: bool) -> Result<PathBuf> {
  use regex::Regex;
  let re = Regex::new(r"%([^%]+)%")?;
  let mut expanded_path = path.to_owned();
  for capture in re.captures_iter(path) {
    let placeholder = &capture[1];
    if let Ok(var_value) = env::var(placeholder) {
      let replacement = if escape_glob_metacharacters {
        glob::Pattern::escape(&var_value)
      } else {
        var_value
      };
      expanded_path = expanded_path.replace(&capture[0], &replacement);
    }
  }
  Ok(PathBuf::from(expanded_path))
}

#[cfg(unix)]
fn expand_unix_path(
  path: &str,
  home: Option<&str>,
  escape_glob_metacharacters: bool,
) -> Result<PathBuf> {
  let needs_home = path == "~" || path.starts_with("~/") || path.contains("$HOME");
  if !needs_home {
    return Ok(PathBuf::from(path));
  }

  let home = home.ok_or_else(|| anyhow!("HOME is not set"))?;
  let replacement = if escape_glob_metacharacters {
    glob::Pattern::escape(home)
  } else {
    home.to_owned()
  };

  let expanded_path = if path == "~" {
    replacement
  } else if let Some(suffix) = path.strip_prefix("~/") {
    format!("{replacement}/{suffix}")
  } else {
    path.replace("$HOME", &replacement)
  };
  Ok(PathBuf::from(expanded_path))
}

#[cfg(target_os = "windows")]
fn expand_path(path: &str, escape_glob_metacharacters: bool) -> Result<PathBuf> {
  expand_windows_path(path, escape_glob_metacharacters)
}

#[cfg(unix)]
fn expand_path(path: &str, escape_glob_metacharacters: bool) -> Result<PathBuf> {
  let home = env::var("HOME").ok();
  expand_unix_path(path, home.as_deref(), escape_glob_metacharacters)
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::atomic::{AtomicU64, Ordering};

  fn unique_tmpdir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = env::temp_dir().join(format!("rookie-paths-{}-{}-{}", tag, std::process::id(), n));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
  }

  fn mozilla_config(base: &Path) -> Browser {
    mozilla_config_multi(&[base])
  }

  fn mozilla_config_multi(bases: &[&Path]) -> Browser {
    Browser {
      paths: bases
        .iter()
        .map(|base| base.to_str().expect("utf-8 temp path").to_string())
        .collect(),
      channels: None,
      unix_crypt_name: None,
      osx_key_service: None,
      osx_key_user: None,
    }
  }

  fn chromium_config(base: &Path) -> Browser {
    Browser {
      paths: vec![
        base
          .join("{channel}")
          .join("Default/Network/Cookies")
          .to_string_lossy()
          .into_owned(),
        base
          .join("{channel}")
          .join("Default/Cookies")
          .to_string_lossy()
          .into_owned(),
      ],
      channels: Some(vec!["stable".to_string(), "beta".to_string()]),
      unix_crypt_name: None,
      osx_key_service: None,
      osx_key_user: None,
    }
  }

  fn seed_chromium_source(base: &Path, channel: &str, network: bool) -> PathBuf {
    let channel_root = base.join(channel);
    let profile = channel_root.join("Default");
    let db = if network {
      profile.join("Network/Cookies")
    } else {
      profile.join("Cookies")
    };
    std::fs::create_dir_all(db.parent().expect("cookie DB parent")).expect("profile dir");
    std::fs::write(&db, b"").expect("cookie DB");
    std::fs::write(channel_root.join("Local State"), b"{}").expect("local state");
    db
  }

  #[test]
  fn find_chrome_based_paths_prefers_configured_source_before_channel() {
    let base = unique_tmpdir("chromium-source-priority");
    let beta_network = seed_chromium_source(&base, "beta", true);
    let _stable_legacy = seed_chromium_source(&base, "stable", false);

    let (key, selected) = find_chrome_based_paths(&chromium_config(&base)).expect("should find");
    assert_eq!(
      selected, beta_network,
      "the first configured path is exhausted across channels before the next path"
    );
    assert_eq!(
      key,
      base.join("beta/Local State").canonicalize().unwrap(),
      "Network/Cookies must resolve Local State at the user-data root"
    );
  }

  #[test]
  fn find_chrome_based_paths_uses_channel_order_within_one_source() {
    let base = unique_tmpdir("chromium-channel-priority");
    let stable_network = seed_chromium_source(&base, "stable", true);
    let _beta_network = seed_chromium_source(&base, "beta", true);

    let (_, selected) = find_chrome_based_paths(&chromium_config(&base)).expect("should find");
    assert_eq!(selected, stable_network);
  }

  #[test]
  fn find_chrome_based_paths_survives_an_unusable_configured_path() {
    let base = unique_tmpdir("chromium-bad-glob");
    let selected = seed_chromium_source(&base, "stable", true);
    let mut config = chromium_config(&base);
    config.paths.insert(0, "/nonexistent/***/[".to_owned());

    let (_, db) = find_chrome_based_paths(&config).expect("later candidate should be probed");
    assert_eq!(db, selected);
  }

  #[test]
  fn a_bad_pattern_does_not_replace_a_normal_not_found_result() {
    let config = Browser {
      paths: vec![
        "/nonexistent/***/[".to_owned(),
        "/also/nonexistent/Cookies".to_owned(),
      ],
      channels: None,
      unix_crypt_name: None,
      osx_key_service: None,
      osx_key_user: None,
    };

    let err = find_chrome_based_paths(&config).expect_err("no candidate exists");
    assert!(is_browser_not_installed(&err));
  }

  #[cfg(unix)]
  #[test]
  fn find_chrome_based_paths_allows_missing_unused_local_state() {
    let base = unique_tmpdir("chromium-no-local-state");
    let db = base.join("Default/Network/Cookies");
    std::fs::create_dir_all(db.parent().unwrap()).expect("profile dir");
    std::fs::write(&db, b"").expect("cookie DB");
    let config = Browser {
      paths: vec![db.to_string_lossy().into_owned()],
      channels: None,
      unix_crypt_name: Some("chrome".to_owned()),
      osx_key_service: None,
      osx_key_user: None,
    };

    let (_, selected) = find_chrome_based_paths(&config).expect("Local State is unused on Unix");
    assert_eq!(selected, db);
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn find_chrome_based_paths_requires_local_state_on_windows() {
    let base = unique_tmpdir("chromium-no-local-state");
    let db = base.join("Default/Network/Cookies");
    std::fs::create_dir_all(db.parent().unwrap()).expect("profile dir");
    std::fs::write(&db, b"").expect("cookie DB");
    let config = Browser {
      paths: vec![db.to_string_lossy().into_owned()],
      channels: None,
      unix_crypt_name: None,
      osx_key_service: None,
      osx_key_user: None,
    };

    let err = find_chrome_based_paths(&config).expect_err("Windows needs Local State");
    assert!(err.to_string().contains("can't find Local State"));
  }

  #[cfg(unix)]
  #[test]
  fn injected_home_glob_metacharacters_are_literal() {
    let root = unique_tmpdir("home-glob");
    let home = root.join("home[seed]*?");
    let db = home.join(".config/google-chrome/Profile 1/Network/Cookies");
    std::fs::create_dir_all(db.parent().unwrap()).expect("profile dir");
    std::fs::write(&db, b"").expect("cookie DB");
    let config = Browser {
      paths: vec!["~/.config/google-chrome/Profile */Network/Cookies".to_owned()],
      channels: None,
      unix_crypt_name: None,
      osx_key_service: None,
      osx_key_user: None,
    };
    let home = home.to_str().expect("UTF-8 temp path");

    let expanded =
      expand_config_paths_with(&config, |path| expand_unix_path(path, Some(home), true))
        .expect("escaped expansion");
    assert_eq!(expanded, vec![db]);
  }

  #[cfg(target_os = "macos")]
  #[test]
  fn find_safari_based_paths_survives_an_unusable_configured_path() {
    let root = unique_tmpdir("safari-bad-glob");
    let db = root.join("Cookies.binarycookies");
    std::fs::write(&db, b"").expect("cookie file");
    let config = Browser {
      paths: vec![
        "/nonexistent/***/[".to_owned(),
        db.to_string_lossy().into_owned(),
      ],
      channels: None,
      unix_crypt_name: None,
      osx_key_service: None,
      osx_key_user: None,
    };

    assert_eq!(find_safari_based_paths(&config).unwrap(), db);
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn find_ie_based_paths_survives_an_unusable_configured_path() {
    let root = unique_tmpdir("ie-bad-glob");
    let db = root.join("WebCacheV01.dat");
    std::fs::write(&db, b"").expect("cookie file");
    let config = Browser {
      paths: vec![
        "C:/nonexistent/***/[".to_owned(),
        db.to_string_lossy().into_owned(),
      ],
      channels: None,
      unix_crypt_name: None,
      osx_key_service: None,
      osx_key_user: None,
    };

    assert_eq!(find_ie_based_paths(&config).unwrap(), db);
  }

  /// Lays out `<base>/profiles.ini` plus a `cookies.sqlite` in each named
  /// profile directory listed in `with_db`.
  fn seed_profiles(base: &Path, ini: &str, with_db: &[&str]) {
    std::fs::write(base.join("profiles.ini"), ini).expect("write ini");
    for profile in with_db {
      let dir = base.join(profile);
      std::fs::create_dir_all(&dir).expect("profile dir");
      std::fs::write(dir.join("cookies.sqlite"), b"").expect("write db");
    }
  }

  const TWO_PROFILES_INI: &str =
    "[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/main\nDefault=1\n\
     [Profile1]\nName=work\nIsRelative=1\nPath=Profiles/work\n";

  #[test]
  fn find_mozilla_based_paths_prefers_the_default_profile() {
    let base = unique_tmpdir("ff-default-first");
    seed_profiles(&base, TWO_PROFILES_INI, &["Profiles/main", "Profiles/work"]);

    let db = find_mozilla_based_paths(&mozilla_config(&base)).expect("should find");
    assert_eq!(db, base.join("Profiles/main/cookies.sqlite"));
  }

  #[test]
  fn find_mozilla_based_paths_falls_through_to_secondary_profile() {
    // The default profile has no cookie database; discovery must not stop there.
    let base = unique_tmpdir("ff-secondary");
    seed_profiles(&base, TWO_PROFILES_INI, &["Profiles/work"]);

    let db = find_mozilla_based_paths(&mozilla_config(&base)).expect("should find");
    assert_eq!(db, base.join("Profiles/work/cookies.sqlite"));
  }

  #[test]
  fn find_mozilla_based_paths_falls_back_to_base_dir_without_profiles_ini() {
    let base = unique_tmpdir("ff-no-ini");
    std::fs::write(base.join("cookies.sqlite"), b"").expect("write db");

    let db = find_mozilla_based_paths(&mozilla_config(&base)).expect("should find");
    assert_eq!(db, base.join("cookies.sqlite"));
  }

  #[test]
  fn find_mozilla_based_paths_without_any_database_errors() {
    let base = unique_tmpdir("ff-empty");
    seed_profiles(&base, TWO_PROFILES_INI, &[]);

    let err = find_mozilla_based_paths(&mozilla_config(&base)).expect_err("should fail");
    assert!(
      err.to_string().contains("Can't find cookies file"),
      "unexpected error: {err}"
    );
  }

  #[test]
  fn find_mozilla_based_profiles_lists_every_profile_with_a_database() {
    let base = unique_tmpdir("ff-enumerate");
    seed_profiles(&base, TWO_PROFILES_INI, &["Profiles/main", "Profiles/work"]);

    let profiles = find_mozilla_based_profiles(&mozilla_config(&base)).expect("should list");
    let names: Vec<_> = profiles.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(
      names,
      vec!["default", "work"],
      "default profile comes first"
    );
    assert!(profiles[0].is_default);
    assert!(!profiles[1].is_default);
  }

  #[test]
  fn find_mozilla_based_profiles_skips_profiles_without_a_database() {
    let base = unique_tmpdir("ff-enumerate-partial");
    seed_profiles(&base, TWO_PROFILES_INI, &["Profiles/work"]);

    let profiles = find_mozilla_based_profiles(&mozilla_config(&base)).expect("should list");
    let names: Vec<_> = profiles.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, vec!["work"]);
  }

  #[test]
  fn find_mozilla_based_paths_prefers_the_earlier_base_path() {
    let first = unique_tmpdir("ff-base-first");
    let second = unique_tmpdir("ff-base-second");
    seed_profiles(&first, TWO_PROFILES_INI, &["Profiles/main"]);
    seed_profiles(&second, TWO_PROFILES_INI, &["Profiles/main"]);

    let config = mozilla_config_multi(&[&first, &second]);
    let db = find_mozilla_based_paths(&config).expect("should find");
    assert_eq!(db, first.join("Profiles/main/cookies.sqlite"));
  }

  #[test]
  fn find_mozilla_based_paths_falls_through_to_a_later_base_path() {
    // The first base declares profiles but holds no database at all, so the
    // search must continue to the next configured root rather than give up.
    let first = unique_tmpdir("ff-base-empty");
    let second = unique_tmpdir("ff-base-populated");
    seed_profiles(&first, TWO_PROFILES_INI, &[]);
    seed_profiles(&second, TWO_PROFILES_INI, &["Profiles/work"]);

    let config = mozilla_config_multi(&[&first, &second]);
    let db = find_mozilla_based_paths(&config).expect("should find");
    assert_eq!(db, second.join("Profiles/work/cookies.sqlite"));
  }

  #[test]
  fn find_mozilla_based_paths_survives_an_unusable_configured_path() {
    // A malformed glob must not abort the search for the remaining paths.
    let base = unique_tmpdir("ff-bad-glob");
    seed_profiles(&base, TWO_PROFILES_INI, &["Profiles/main"]);

    let mut config = mozilla_config(&base);
    config.paths.insert(0, "/nonexistent/***/[".to_string());

    let db = find_mozilla_based_paths(&config).expect("should find");
    assert_eq!(db, base.join("Profiles/main/cookies.sqlite"));
  }

  #[test]
  fn find_mozilla_based_paths_reports_why_no_path_was_usable() {
    // Every configured path is unusable, so the caller gets the real parse
    // failure instead of a misleading "Can't find cookies file".
    let config = mozilla_config_multi(&[]);
    let config = Browser {
      paths: vec!["/nonexistent/***/[".to_string()],
      ..config
    };

    let err = find_mozilla_based_paths(&config).expect_err("should fail");
    assert!(
      err
        .to_string()
        .contains("no browser path could be expanded"),
      "unexpected error: {err}"
    );
  }

  #[test]
  fn find_mozilla_based_paths_preserves_an_unreadable_profiles_error() {
    let base = unique_tmpdir("ff-unreadable-ini-no-db");
    std::fs::create_dir_all(base.join("profiles.ini")).expect("dir where a file belongs");

    let err = find_mozilla_based_paths(&mozilla_config(&base)).expect_err("should fail");
    assert!(
      err.to_string().contains("Failed to read Mozilla profiles"),
      "unexpected error: {err:#}"
    );
    assert!(!is_browser_not_installed(&err));
  }

  #[test]
  fn find_mozilla_based_paths_can_recover_after_an_unreadable_profiles_file() {
    let unreadable = unique_tmpdir("ff-unreadable-ini-first");
    std::fs::create_dir_all(unreadable.join("profiles.ini")).expect("dir where a file belongs");
    let usable = unique_tmpdir("ff-readable-ini-second");
    seed_profiles(&usable, TWO_PROFILES_INI, &["Profiles/main"]);

    let db = find_mozilla_based_paths(&mozilla_config_multi(&[&unreadable, &usable]))
      .expect("a later usable root should win");
    assert_eq!(db, usable.join("Profiles/main/cookies.sqlite"));
  }

  #[test]
  fn find_mozilla_based_profiles_dedups_repeated_base_paths() {
    // Two config entries resolving to the same directory (snap and a symlinked
    // equivalent, in the field) must not double every profile.
    let base = unique_tmpdir("ff-dedup");
    seed_profiles(&base, TWO_PROFILES_INI, &["Profiles/main", "Profiles/work"]);

    let config = mozilla_config_multi(&[&base, &base]);
    let profiles = find_mozilla_based_profiles(&config).expect("should list");
    let names: Vec<_> = profiles.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, vec!["default", "work"]);
  }

  #[test]
  fn find_mozilla_based_profiles_spans_multiple_base_paths() {
    let first = unique_tmpdir("ff-span-first");
    let second = unique_tmpdir("ff-span-second");
    seed_profiles(&first, TWO_PROFILES_INI, &["Profiles/main"]);
    seed_profiles(&second, TWO_PROFILES_INI, &["Profiles/work"]);

    let config = mozilla_config_multi(&[&first, &second]);
    let profiles = find_mozilla_based_profiles(&config).expect("should list");
    let paths: Vec<_> = profiles.iter().map(|p| p.path.clone()).collect();
    assert_eq!(
      paths,
      vec![first.join("Profiles/main"), second.join("Profiles/work")]
    );
  }

  #[test]
  fn find_mozilla_based_paths_with_empty_profiles_ini_still_probes_base_dir() {
    // An empty profiles.ini parses fine but declares nothing; the base-dir
    // fallback is what keeps such an install discoverable.
    let base = unique_tmpdir("ff-empty-ini-base");
    std::fs::write(base.join("profiles.ini"), b"").expect("write ini");
    std::fs::write(base.join("cookies.sqlite"), b"").expect("write db");

    let db = find_mozilla_based_paths(&mozilla_config(&base)).expect("should find");
    assert_eq!(db, base.join("cookies.sqlite"));
  }

  #[test]
  fn find_mozilla_based_paths_with_empty_profiles_ini_and_no_database_errors() {
    let base = unique_tmpdir("ff-empty-ini-nodb");
    std::fs::write(base.join("profiles.ini"), b"").expect("write ini");

    let err = find_mozilla_based_paths(&mozilla_config(&base)).expect_err("should fail");
    assert!(
      err.to_string().contains("Can't find cookies file"),
      "unexpected error: {err}"
    );
  }

  #[test]
  fn find_mozilla_based_profiles_includes_a_flat_base_directory_database() {
    // find_mozilla_based_paths reads this layout, so enumeration must see it
    // too — otherwise firefox() works while firefox_profiles() reports none.
    let base = unique_tmpdir("ff-flat-enumerate");
    std::fs::write(base.join("cookies.sqlite"), b"").expect("write db");

    let profiles = find_mozilla_based_profiles(&mozilla_config(&base)).expect("should list");
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].path, base);
    assert!(profiles[0].is_default);
  }

  #[test]
  fn find_mozilla_based_profiles_does_not_call_a_fallback_database_the_default() {
    // profiles.ini names a default, but no declared profile has a database yet.
    // The legacy base-directory database is where the cookies are, not the
    // profile Firefox would open, so it must not claim the default flag.
    let base = unique_tmpdir("ff-flat-not-default");
    seed_profiles(&base, TWO_PROFILES_INI, &[]);
    std::fs::write(base.join("cookies.sqlite"), b"").expect("write db");

    let profiles = find_mozilla_based_profiles(&mozilla_config(&base)).expect("should list");
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].path, base);
    assert!(
      !profiles[0].is_default,
      "profiles.ini still declares its own default"
    );
  }

  #[test]
  fn find_mozilla_based_profiles_does_not_default_a_fallback_after_an_unreadable_ini() {
    // A profiles.ini that cannot be read is not evidence that nothing was
    // declared, so the fallback database must not claim to be the default.
    let base = unique_tmpdir("ff-unreadable-ini");
    std::fs::create_dir_all(base.join("profiles.ini")).expect("dir where a file belongs");
    std::fs::write(base.join("cookies.sqlite"), b"").expect("write db");

    let profiles = find_mozilla_based_profiles(&mozilla_config(&base)).expect("should list");
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].path, base);
    assert!(
      !profiles[0].is_default,
      "an unreadable ini may still declare a default"
    );
  }

  #[cfg(unix)]
  #[test]
  fn find_mozilla_based_profiles_merges_default_flags_across_roots() {
    // The same profile directory is secondary for the first root and the
    // default for the second; deduplication must not discard that it is some
    // installation's default.
    let shared = unique_tmpdir("ff-merge-shared");
    std::fs::create_dir_all(shared.join("Profiles/work")).expect("profile dir");
    std::fs::write(shared.join("Profiles/work/cookies.sqlite"), b"").expect("write db");

    let secondary_root = unique_tmpdir("ff-merge-secondary");
    let primary_root = unique_tmpdir("ff-merge-primary");
    for root in [&secondary_root, &primary_root] {
      std::os::unix::fs::symlink(shared.join("Profiles"), root.join("Profiles")).expect("symlink");
    }
    // First root: work is secondary. Second root: work is the default.
    std::fs::write(
      secondary_root.join("profiles.ini"),
      "[Profile0]\nName=main\nIsRelative=1\nPath=Profiles/main\nDefault=1\n\
       [Profile1]\nName=work\nIsRelative=1\nPath=Profiles/work\n",
    )
    .expect("write ini");
    std::fs::write(
      primary_root.join("profiles.ini"),
      "[Profile0]\nName=work\nIsRelative=1\nPath=Profiles/work\nDefault=1\n",
    )
    .expect("write ini");

    let config = mozilla_config_multi(&[&secondary_root, &primary_root]);
    let profiles = find_mozilla_based_profiles(&config).expect("should list");
    assert_eq!(profiles.len(), 1, "{profiles:?}");
    assert!(
      profiles[0].is_default,
      "the second root opens this profile by default"
    );
  }

  #[test]
  fn find_mozilla_based_profiles_ignores_a_flat_database_beside_real_profiles() {
    let base = unique_tmpdir("ff-flat-and-declared");
    seed_profiles(&base, TWO_PROFILES_INI, &["Profiles/main"]);
    std::fs::write(base.join("cookies.sqlite"), b"").expect("write db");

    let profiles = find_mozilla_based_profiles(&mozilla_config(&base)).expect("should list");
    let paths: Vec<_> = profiles.iter().map(|p| p.path.clone()).collect();
    assert_eq!(paths, vec![base.join("Profiles/main")]);
  }

  #[cfg(unix)]
  #[test]
  fn find_mozilla_based_profiles_dedups_symlinked_roots() {
    // A symlinked root reaches the same profile by a different lexical path;
    // without canonical dedup both would be listed and selecting the profile
    // by name would become ambiguous.
    let base = unique_tmpdir("ff-symlink-real");
    seed_profiles(&base, TWO_PROFILES_INI, &["Profiles/main"]);
    let link = unique_tmpdir("ff-symlink-parent").join("link");
    std::os::unix::fs::symlink(&base, &link).expect("symlink");

    let config = mozilla_config_multi(&[&base, &link]);
    let profiles = find_mozilla_based_profiles(&config).expect("should list");
    assert_eq!(profiles.len(), 1, "{:?}", profiles);
    assert_eq!(profiles[0].path, base.join("Profiles/main"));
  }

  #[test]
  fn find_mozilla_based_paths_reaches_an_orphan_install_profile() {
    // A lone install names a profile with no [Profile...] section, and only
    // that directory holds a database. The pre-enumeration resolver probed the
    // install default directly, so discovery must still reach it.
    let base = unique_tmpdir("ff-orphan-install");
    seed_profiles(
      &base,
      "[Install4F96D1932A9F858E]\nDefault=Profiles/orphan\n\
       [Profile0]\nName=other\nIsRelative=1\nPath=Profiles/other\n",
      &["Profiles/orphan"],
    );

    let db = find_mozilla_based_paths(&mozilla_config(&base)).expect("should find");
    assert_eq!(db, base.join("Profiles/orphan/cookies.sqlite"));
  }

  #[test]
  fn find_mozilla_based_profiles_without_any_database_errors() {
    let base = unique_tmpdir("ff-enumerate-empty");
    seed_profiles(&base, TWO_PROFILES_INI, &[]);

    let err = find_mozilla_based_profiles(&mozilla_config(&base)).expect_err("should fail");
    assert!(
      err.to_string().contains("Can't find any profile"),
      "unexpected error: {err}"
    );
  }

  #[test]
  fn find_mozilla_based_profiles_preserves_an_unreadable_profiles_error() {
    let base = unique_tmpdir("ff-unreadable-enumeration-no-db");
    std::fs::create_dir_all(base.join("profiles.ini")).expect("dir where a file belongs");

    let err = find_mozilla_based_profiles(&mozilla_config(&base)).expect_err("should fail");
    assert!(
      err.to_string().contains("Failed to read Mozilla profiles"),
      "unexpected error: {err:#}"
    );
    assert!(!is_browser_not_installed(&err));
  }

  #[cfg(unix)]
  #[test]
  fn expand_path_unix_replaces_tilde_with_home() {
    let home = env::var("HOME").expect("HOME must be set on unix runners");
    let expanded = expand_path("~/.config/google-chrome/Default/Cookies", false).unwrap();
    assert_eq!(
      expanded,
      PathBuf::from(format!("{home}/.config/google-chrome/Default/Cookies"))
    );
  }

  #[cfg(unix)]
  #[test]
  fn expand_path_unix_replaces_dollar_home() {
    let home = env::var("HOME").expect("HOME must be set on unix runners");
    let expanded = expand_path("$HOME/Library/Cookies", false).unwrap();
    assert_eq!(expanded, PathBuf::from(format!("{home}/Library/Cookies")));
  }

  #[cfg(unix)]
  #[test]
  fn expand_path_unix_leaves_absolute_paths_alone() {
    let expanded = expand_path("/etc/hosts", false).unwrap();
    assert_eq!(expanded, PathBuf::from("/etc/hosts"));
  }

  #[cfg(unix)]
  #[test]
  fn expand_path_unix_only_expands_a_leading_tilde() {
    let expanded = expand_unix_path("/tmp/account~archive", None, false).unwrap();
    assert_eq!(expanded, PathBuf::from("/tmp/account~archive"));
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn expand_path_windows_substitutes_known_env_var() {
    // SAFETY: tests in the same process share env state; we use a unique key to avoid clashes.
    let key = "ROOKIE_TEST_EXPAND_PATH";
    env::set_var(key, "C:\\seeded");
    let expanded = expand_path(&format!("%{key}%\\Cookies"), false).unwrap();
    assert_eq!(expanded, PathBuf::from("C:\\seeded\\Cookies"));
    env::remove_var(key);
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn expand_path_windows_leaves_unknown_placeholders() {
    // Unknown placeholders are left literally — surface the failure to the caller instead of silently dropping.
    let expanded = expand_path("%ROOKIE_TEST_DOES_NOT_EXIST%\\Cookies", false).unwrap();
    assert_eq!(
      expanded,
      PathBuf::from("%ROOKIE_TEST_DOES_NOT_EXIST%\\Cookies")
    );
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn injected_windows_env_glob_metacharacters_are_literal() {
    let root = unique_tmpdir("windows-home-glob");
    let home = root.join("home[seed]*?");
    let db = home.join("Google/Chrome/User Data/Default/Network/Cookies");
    std::fs::create_dir_all(db.parent().unwrap()).expect("profile dir");
    std::fs::write(&db, b"").expect("cookie DB");
    let key = "ROOKIE_TEST_GLOB_HOME";
    env::set_var(key, &home);
    let config = Browser {
      paths: vec![format!(
        "%{key}%/Google/Chrome/User Data/Default/Network/Cookies"
      )],
      channels: None,
      unix_crypt_name: None,
      osx_key_service: None,
      osx_key_user: None,
    };

    let expanded = expand_config_paths(&config).expect("escaped expansion");
    env::remove_var(key);
    assert_eq!(expanded, vec![db]);
  }
}
