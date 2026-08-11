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
/// patterns.
///
/// A path that cannot be expanded is logged and skipped so one bad entry does
/// not abort the whole search — but if that leaves nothing at all, the first
/// failure is returned rather than letting the caller report a misleading
/// "can't find cookies file". On unix an unset `HOME` fails every entry.
fn expand_config_paths(config: &Browser) -> Result<Vec<PathBuf>> {
  let channels = config
    .channels
    .clone()
    .unwrap_or_else(|| vec![String::new()]);
  let mut bases: Vec<PathBuf> = vec![];
  let mut first_error: Option<anyhow::Error> = None;
  for path in &config.paths {
    for channel in &channels {
      let path = path.replace("{channel}", channel);
      match expand_path(path.as_str()).and_then(expand_glob_paths) {
        Ok(expanded) => bases.extend(expanded),
        Err(err) => {
          log::warn!("Skipping unusable path {path}: {err}");
          first_error.get_or_insert(err);
        }
      }
    }
  }

  match first_error {
    Some(err) if bases.is_empty() => Err(err.context("no browser path could be expanded")),
    _ => Ok(bases),
  }
}

/// Profiles declared under `base`, default first, so callers probe the profile
/// the browser actually opens before any secondary one.
fn mozilla_profiles_in(base: &Path) -> Vec<MozillaProfile> {
  let profiles_path = base.join("profiles.ini");
  let mut profiles = match list_profiles(profiles_path.as_path()) {
    Ok(profiles) => profiles,
    Err(err) => {
      // A profiles.ini that exists but will not parse is a real problem worth
      // surfacing; one that is simply absent is the normal case for a base
      // path this browser does not use.
      if profiles_path.exists() {
        log::warn!("Failed to read {}: {err}", profiles_path.display());
      } else {
        log::debug!("No profiles.ini at {}", profiles_path.display());
      }
      return vec![];
    }
  };
  profiles.sort_by_key(|profile| !profile.is_default);
  profiles
}

pub fn find_mozilla_based_paths(config: &Browser) -> Result<PathBuf> {
  for base in expand_config_paths(config)? {
    let candidates = mozilla_profiles_in(&base)
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

  bail!("Can't find cookies file")
}

/// Returns every Mozilla profile for `config` that holds a cookie database.
///
/// Profiles are gathered across every configured installation root, so the
/// result can contain more than one entry with `is_default` set — see
/// [`MozillaProfile::is_default`].
pub fn find_mozilla_based_profiles(config: &Browser) -> Result<Vec<MozillaProfile>> {
  let mut found: Vec<MozillaProfile> = vec![];
  for base in expand_config_paths(config)? {
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
