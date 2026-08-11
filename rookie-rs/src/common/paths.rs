use crate::{
  browser::mozilla::{list_profiles, MozillaProfile},
  config::Browser,
};
use anyhow::{anyhow, bail, Context, Result};
use std::{
  env,
  path::{Path, PathBuf},
};

fn expand_glob_paths(path: PathBuf) -> Result<Vec<PathBuf>> {
  let mut paths: Vec<PathBuf> = vec![];
  if let Some(path_str) = path.to_str() {
    for entry in glob::glob(path_str)? {
      if entry.is_ok() {
        paths.push(entry?);
      }
    }
  }
  Ok(paths)
}

pub fn find_chrome_based_paths(config: &Browser) -> Result<(PathBuf, PathBuf)> {
  for path in &config.paths {
    // base paths
    let channels = config.channels.clone().unwrap_or(vec!["".to_string()]);
    for channel in channels {
      // channels
      let path = path.replace("{channel}", &channel);
      let db_path = expand_path(path.as_str())?;
      let glob_db_paths = expand_glob_paths(db_path)?;
      for db_path in glob_db_paths {
        // glob expanded paths
        if db_path.exists() {
          if let Some(parent) = db_path.parent() {
            let key_path = ["../../Local State", "../Local State", "Local State"]
              .iter()
              .map(|p| parent.join(p))
              .find(|p| p.exists())
              .unwrap_or_else(|| parent.join("Local State"))
              .canonicalize()
              .context("canonicalize")?;
            log::debug!(
              "Found chrome path {}, {}",
              db_path.display(),
              key_path.display()
            );
            return Ok((key_path, db_path));
          }
        }
      }
    }
  }
  Err(anyhow!("can't find cookies file"))
}

/// Expands every configured base path for `config` across its channels and glob
/// patterns. A path that cannot be expanded is logged and skipped so one bad
/// entry does not abort the whole search.
fn expand_config_paths(config: &Browser) -> Vec<PathBuf> {
  let channels = config
    .channels
    .clone()
    .unwrap_or_else(|| vec![String::new()]);
  let mut bases: Vec<PathBuf> = vec![];
  for path in &config.paths {
    for channel in &channels {
      let path = path.replace("{channel}", channel);
      match expand_path(path.as_str()).and_then(expand_glob_paths) {
        Ok(expanded) => bases.extend(expanded),
        Err(err) => log::warn!("Skipping unusable path {path}: {err}"),
      }
    }
  }
  bases
}

/// Profiles declared under `base`, default first, so callers probe the profile
/// the browser actually opens before any secondary one.
fn mozilla_profiles_in(base: &Path) -> Vec<MozillaProfile> {
  let profiles_path = base.join("profiles.ini");
  let mut profiles = match list_profiles(profiles_path.as_path()) {
    Ok(profiles) => profiles,
    Err(err) => {
      log::debug!("No profiles from {}: {err}", profiles_path.display());
      return vec![];
    }
  };
  profiles.sort_by_key(|profile| !profile.is_default);
  profiles
}

pub fn find_mozilla_based_paths(config: &Browser) -> Result<PathBuf> {
  for base in expand_config_paths(config) {
    let candidates = mozilla_profiles_in(&base)
      .into_iter()
      .map(|profile| profile.path)
      // Some installs keep the database next to profiles.ini rather than in a
      // profile directory; probe that last.
      .chain(std::iter::once(base));
    for candidate in candidates {
      let db_path = candidate.join("cookies.sqlite");
      if db_path.exists() {
        log::debug!("Found mozilla path {}", db_path.display());
        return Ok(db_path);
      }
    }
  }

  bail!("Can't find cookies file")
}

/// Returns every Mozilla profile for `config` that holds a cookie database.
pub fn find_mozilla_based_profiles(config: &Browser) -> Result<Vec<MozillaProfile>> {
  let mut found: Vec<MozillaProfile> = vec![];
  for base in expand_config_paths(config) {
    for profile in mozilla_profiles_in(&base) {
      if profile.path.join("cookies.sqlite").exists()
        && !found.iter().any(|seen| seen.path == profile.path)
      {
        found.push(profile);
      }
    }
  }

  if found.is_empty() {
    bail!("Can't find any profile with a cookie database")
  }
  Ok(found)
}

#[cfg(target_os = "macos")]
pub fn find_safari_based_paths(config: &Browser) -> Result<PathBuf> {
  for path in &config.paths {
    // base paths
    let channels = config.channels.clone().unwrap_or(vec!["".to_string()]);
    for channel in channels {
      // channels
      let path = path.replace("{channel}", &channel);
      let safari_path = expand_path(path.as_str())?;
      let glob_paths = expand_glob_paths(safari_path)?;
      for path in glob_paths {
        // expanded glob paths
        if path.exists() {
          log::debug!("Found safari path {}", path.display());
          return Ok(path);
        }
      }
    }
  }
  bail!("Can't find cookies file")
}

#[cfg(target_os = "windows")]
pub fn find_ie_based_paths(config: &Browser) -> Result<PathBuf> {
  for path in &config.paths {
    // base paths
    let channels = config.channels.clone().unwrap_or(vec!["".to_string()]);
    for channel in channels {
      // channels

      let path = path.replace("{channel}", &channel);
      let path = expand_path(path.as_str())?;
      let glob_paths = expand_glob_paths(path)?;
      for path in glob_paths {
        // expanded glob paths
        if path.exists() {
          log::debug!("Found IE path {}", path.display());
          return Ok(path);
        }
      }
    }
  }

  bail!("Can't find cookies file")
}
#[cfg(target_os = "windows")]
pub fn expand_path(path: &str) -> Result<PathBuf> {
  use regex::Regex;
  // Define a regex pattern to match placeholders like %SOMETHING%
  let re = Regex::new(r"%([^%]+)%")?;

  // Clone the input path for modification
  let mut expanded_path = path.to_owned();

  // Iterate over all matches of the regex pattern in the input path
  for capture in re.captures_iter(path) {
    // Get the matched placeholder (e.g., "APPDATA" from "%APPDATA%")
    let placeholder = &capture[1];

    // Try to get the corresponding environment variable value
    if let Ok(var_value) = env::var(placeholder) {
      // Replace the placeholder with the environment variable value
      expanded_path = expanded_path.replace(&capture[0], &var_value);
    }
  }

  // Convert the expanded path to a PathBuf
  let path_buf = PathBuf::from(expanded_path);

  Ok(path_buf)
}

#[cfg(unix)]
pub fn expand_path(path: &str) -> Result<PathBuf> {
  // Get the value of the HOME environment variable
  let home = env::var("HOME")?;

  // Replace ~ or $HOME with the actual home directory path
  let expanded_path = path.replace('~', &home).replace("$HOME", &home);

  // Convert the expanded path to a PathBuf
  Ok(PathBuf::from(expanded_path))
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
    Browser {
      paths: vec![base.to_str().expect("utf-8 temp path").to_string()],
      channels: None,
      unix_crypt_name: None,
      osx_key_service: None,
      osx_key_user: None,
    }
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
  fn find_mozilla_based_profiles_without_any_database_errors() {
    let base = unique_tmpdir("ff-enumerate-empty");
    seed_profiles(&base, TWO_PROFILES_INI, &[]);

    let err = find_mozilla_based_profiles(&mozilla_config(&base)).expect_err("should fail");
    assert!(
      err.to_string().contains("Can't find any profile"),
      "unexpected error: {err}"
    );
  }

  #[cfg(unix)]
  #[test]
  fn expand_path_unix_replaces_tilde_with_home() {
    let home = env::var("HOME").expect("HOME must be set on unix runners");
    let expanded = expand_path("~/.config/google-chrome/Default/Cookies").unwrap();
    assert_eq!(
      expanded,
      PathBuf::from(format!("{home}/.config/google-chrome/Default/Cookies"))
    );
  }

  #[cfg(unix)]
  #[test]
  fn expand_path_unix_replaces_dollar_home() {
    let home = env::var("HOME").expect("HOME must be set on unix runners");
    let expanded = expand_path("$HOME/Library/Cookies").unwrap();
    assert_eq!(expanded, PathBuf::from(format!("{home}/Library/Cookies")));
  }

  #[cfg(unix)]
  #[test]
  fn expand_path_unix_leaves_absolute_paths_alone() {
    let expanded = expand_path("/etc/hosts").unwrap();
    assert_eq!(expanded, PathBuf::from("/etc/hosts"));
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn expand_path_windows_substitutes_known_env_var() {
    // SAFETY: tests in the same process share env state; we use a unique key to avoid clashes.
    let key = "ROOKIE_TEST_EXPAND_PATH";
    env::set_var(key, "C:\\seeded");
    let expanded = expand_path(&format!("%{key}%\\Cookies")).unwrap();
    assert_eq!(expanded, PathBuf::from("C:\\seeded\\Cookies"));
    env::remove_var(key);
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn expand_path_windows_leaves_unknown_placeholders() {
    // Unknown placeholders are left literally — surface the failure to the caller instead of silently dropping.
    let expanded = expand_path("%ROOKIE_TEST_DOES_NOT_EXIST%\\Cookies").unwrap();
    assert_eq!(
      expanded,
      PathBuf::from("%ROOKIE_TEST_DOES_NOT_EXIST%\\Cookies")
    );
  }
}
