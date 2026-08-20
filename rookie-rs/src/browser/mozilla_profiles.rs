//! Mozilla `profiles.ini` inventory and default-profile selection.
//!
//! Split out of `mozilla.rs`: this reads a profile catalogue and never opens a
//! cookie store, so it shares nothing with either decoder beyond the family
//! name. `registry/gecko.rs` is the only consumer. `MozillaProfile` is
//! re-exported from `mozilla.rs` so the public path is unchanged.

#[cfg(test)]
use crate::common::diagnostic::REDACTED_PATH;
#[cfg(test)]
use anyhow::bail;
use anyhow::Result;
use ini::{Ini, ParseOption};
use std::path::{Path, PathBuf};

/// A profile declared by a Mozilla-family browser's `profiles.ini`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MozillaProfile {
  /// The profile's `Name=` value, or an empty string when the section omits it.
  pub name: String,
  /// Path to the profile directory, absolute whenever the caller supplied an
  /// absolute `profiles.ini` path.
  pub path: PathBuf,
  /// Whether this is the profile that the installation owning this
  /// `profiles.ini` would open.
  ///
  /// Defaults are per-installation, so a list gathered across several
  /// installation roots (snap and distro Firefox, say) can contain more than
  /// one default.
  pub is_default: bool,
}

/// A `[Profile...]` section, with its `Path` kept exactly as written in the ini.
struct ProfileSection {
  name: String,
  path: String,
  default_flag: bool,
}

/// Reads `profiles.ini` with escape processing disabled.
///
/// The default parser treats `\` as an escape introducer, which silently
/// destroys the Windows paths that `IsRelative=0` sections store:
/// `Path=C:\Users\me\Profiles\work` would parse as `C:UsersmeProfileswork`,
/// with `\r` becoming a carriage return.
#[cfg(test)]
pub(crate) fn load_profiles_ini(profiles_path: &Path) -> Result<Ini> {
  Ini::load_from_file_opt(
    profiles_path,
    ParseOption {
      enabled_escape: false,
      ..Default::default()
    },
  )
  .map_err(Into::into)
}

/// Every `[Profile...]` section that declares a `Path`.
///
/// Firefox itself walks `Profile0`, `Profile1`, ... and stops at the first gap,
/// also requiring `Name` and `IsRelative`. We deliberately accept any
/// `[Profile...]` section with a `Path` instead: reading cookies from a profile
/// Firefox would skip is useful, whereas dropping a real profile is not.
fn profile_sections(conf: &Ini) -> Vec<ProfileSection> {
  conf
    .iter()
    .filter(|(section, _)| section.unwrap_or_default().starts_with("Profile"))
    .filter_map(|(_, props)| {
      let path = props.get("Path")?.trim();
      if path.is_empty() {
        return None;
      }
      Some(ProfileSection {
        name: props.get("Name").unwrap_or_default().to_string(),
        path: path.to_string(),
        default_flag: props.get("Default").unwrap_or_default().trim() == "1",
      })
    })
    .collect()
}

/// Profile paths named by `[Install...] Default=`, deduplicated in file order.
///
/// Firefox keys each section by a hash of the installation directory. Several
/// distinct entries therefore mean this file is shared — by a release and a
/// nightly, or by one live install plus debris, since sections for moved or
/// uninstalled builds are never removed.
fn install_defaults(conf: &Ini) -> Vec<String> {
  let mut defaults: Vec<String> = vec![];
  for (_, props) in conf
    .iter()
    .filter(|(section, _)| section.unwrap_or_default().starts_with("Install"))
  {
    let Some(default) = props
      .get("Default")
      .map(str::trim)
      .filter(|d| !d.is_empty())
    else {
      continue;
    };
    if !defaults.iter().any(|existing| existing == default) {
      defaults.push(default.to_string());
    }
  }
  defaults
}

/// Resolves the default profile's `Path` value, or `None` when the ini declares
/// nothing usable.
///
/// This is a heuristic, not Firefox's algorithm. Firefox picks the
/// `[Install<hash>]` section matching a hash of the *running installation's*
/// directory and honours it unconditionally; sections never compete. We cannot
/// know which installation a caller means, so we degrade in this order:
///
/// 1. a single unambiguous install default — the dedicated profile that the one
///    installation on record opens;
/// 2. with competing installs, a default that the legacy `[ProfileN] Default=1`
///    marker also names, else any profile some install claims — better a
///    profile one installation opens than one none does;
/// 3. the `Default=1` marker alone;
/// 4. the first declared profile;
/// 5. an install default naming a profile that has no section of its own.
fn resolve_default_path(profiles: &[ProfileSection], installs: &[String]) -> Option<String> {
  let is_known = |candidate: &str| profiles.iter().any(|profile| profile.path == candidate);

  if let [only] = installs {
    if is_known(only) {
      return Some(only.clone());
    }
  }

  if installs.len() > 1 {
    log::warn!(
      "profiles.ini declares {} competing [Install...] defaults; guessing which installation is meant",
      installs.len()
    );
    if let Some(profile) = profiles
      .iter()
      .find(|profile| profile.default_flag && installs.contains(&profile.path))
    {
      return Some(profile.path.clone());
    }
    if let Some(default) = installs.iter().find(|default| is_known(default)) {
      return Some(default.clone());
    }
  }

  if let Some(profile) = profiles.iter().find(|profile| profile.default_flag) {
    return Some(profile.path.clone());
  }

  profiles
    .first()
    .map(|profile| profile.path.clone())
    // An install may name a profile that has no [Profile...] section of its
    // own; trying it still beats giving up.
    .or_else(|| installs.first().cloned())
}

/// Returns every profile declared by `profiles.ini`, in file order, resolved
/// against the file's directory and with the default profile flagged.
///
/// Exposing the secondary profiles — not just the default — is what lets
/// callers read cookies from a profile the browser does not open by default.
#[cfg(test)]
pub(crate) fn list_profiles(profiles_path: &Path) -> Result<Vec<MozillaProfile>> {
  let conf = load_profiles_ini(profiles_path)?;
  Ok(profiles_from_ini(&conf, profiles_path))
}

/// [`list_profiles`] for callers that already hold the file's contents, so
/// discovery can route the read through its injected filesystem seam instead of
/// reaching for the real one.
pub(crate) fn list_profiles_from_str(
  contents: &str,
  profiles_path: &Path,
) -> Result<Vec<MozillaProfile>> {
  // `Ini::load_from_file_opt` strips a UTF-8 BOM; the string parser does not,
  // and U+FEFF is not whitespace, so a BOM would swallow every section into the
  // anonymous one and yield zero profiles with no error at all.
  let contents = contents.strip_prefix('\u{feff}').unwrap_or(contents);
  let conf = Ini::load_from_str_opt(
    contents,
    ParseOption {
      enabled_escape: false,
      ..Default::default()
    },
  )?;
  Ok(profiles_from_ini(&conf, profiles_path))
}

fn profiles_from_ini(conf: &Ini, profiles_path: &Path) -> Vec<MozillaProfile> {
  let base = profiles_path.parent().unwrap_or_else(|| Path::new(""));
  let sections = profile_sections(conf);
  let installs = install_defaults(conf);
  let default_path = resolve_default_path(&sections, &installs);

  // Exactly one entry carries the flag: two sections may declare the same
  // `Path`, and "the default" must stay singular within one profiles.ini.
  let mut default_taken = false;
  let mut claim_default = |candidate: &str| {
    let is_default = !default_taken && default_path.as_deref() == Some(candidate);
    default_taken |= is_default;
    is_default
  };

  let mut profiles: Vec<MozillaProfile> = sections
    .iter()
    .map(|profile| MozillaProfile {
      is_default: claim_default(&profile.path),
      // `IsRelative=0` sections store a full native path, which `join` passes
      // through. We trust the shape of `Path` rather than the `IsRelative`
      // flag, which browsers do not always keep in sync.
      path: base.join(&profile.path),
      name: profile.name.clone(),
    })
    .collect();

  // An [Install...] section can name a profile that has no [Profile...]
  // section, e.g. after a hand-edited or partially migrated profiles.ini. The
  // pre-enumeration resolver probed those directly, so surface every one of
  // them — not just whichever the heuristic happened to choose.
  for orphan in installs
    .iter()
    .filter(|default| !is_known_section(&sections, default))
  {
    profiles.push(MozillaProfile {
      is_default: claim_default(orphan),
      path: base.join(orphan),
      name: String::new(),
    });
  }

  profiles
}

fn is_known_section(sections: &[ProfileSection], candidate: &str) -> bool {
  sections.iter().any(|section| section.path == candidate)
}

/// Picks the profile a user asked for, matching its `Name`, its directory name,
/// or its full path.
///
/// An ambiguous selector is an error rather than a silent first-match: picking
/// the wrong profile is the failure this whole resolver exists to prevent.
#[cfg(test)]
pub(crate) fn select_profile<'a>(
  profiles: &'a [MozillaProfile],
  selector: &str,
) -> Result<&'a MozillaProfile> {
  if selector.is_empty() {
    bail!("Profile selector must not be empty");
  }
  // Comparing as a `Path` keeps selection separator-insensitive on Windows,
  // where `base.join("Profiles/work")` yields mixed separators but a user
  // naturally writes the all-backslash spelling.
  let wanted = Path::new(selector);
  let matches: Vec<&MozillaProfile> = profiles
    .iter()
    .filter(|profile| {
      profile.name == selector
        || profile.path.file_name().is_some_and(|dir| dir == selector)
        || profile.path == wanted
    })
    .collect();

  match matches[..] {
    [only] => Ok(only),
    [] => bail!(
      "No profile matching {selector:?}. Available profiles: [{}]",
      describe(profiles.iter())
    ),
    _ => bail!(
      "{} profiles match {selector:?}; select one by full path instead: [{}]",
      matches.len(),
      describe(matches.iter().copied())
    ),
  }
}

#[cfg(test)]
pub(crate) fn describe<'a>(profiles: impl Iterator<Item = &'a MozillaProfile>) -> String {
  profiles
    .map(|profile| format!("{} ({REDACTED_PATH})", profile.name))
    .collect::<Vec<_>>()
    .join(", ")
}
