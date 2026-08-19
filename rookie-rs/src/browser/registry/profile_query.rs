//! Crate-private profile query resolver (ADR 0003 + cookie-DB path key).
//!
//! Listing drafts only — no key providers.

use super::super::report_core::CookieSourceRoleId;
use super::{
  chromium_listing_with_runtime, gecko_profiles_with_runtime, resolve_registered_browser,
  DiscoveredProfile,
};
use crate::common::deadline::BoundaryRuntime;
use crate::RequestError;
use anyhow::Result;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub(crate) struct ProfileMatchCandidate {
  pub(crate) profile_id: String,
  pub(crate) display_name: String,
  pub(crate) directory_name: OsString,
  pub(crate) path: PathBuf,
  pub(crate) path_lossy: bool,
  pub(crate) persistent_source_paths: Vec<PathBuf>,
}

pub(crate) fn resolve_profile_query(
  browser_id: &str,
  query: &str,
  runtime: &BoundaryRuntime<'_>,
) -> Result<String> {
  runtime.check()?;
  let browser = resolve_registered_browser(browser_id)?;
  runtime.check()?;
  let candidates = list_profile_candidates(&browser.canonical_id, browser.engine, runtime)?;
  match_profile_query(&browser.canonical_id, query, &candidates).map_err(Into::into)
}

pub(crate) fn match_profile_query(
  browser_id: &str,
  query: &str,
  candidates: &[ProfileMatchCandidate],
) -> std::result::Result<String, RequestError> {
  if query.is_empty() {
    return Err(RequestError::EmptyProfileSelector);
  }
  let id_hits: Vec<_> = candidates
    .iter()
    .filter(|candidate| candidate.profile_id == query)
    .collect();
  if id_hits.len() == 1 {
    return Ok(id_hits[0].profile_id.clone());
  }
  if candidates
    .iter()
    .any(|candidate| candidate.path_lossy && candidate.path.to_string_lossy() == query)
  {
    return Err(RequestError::LossyProfilePath {
      browser_id: browser_id.to_owned(),
      query: query.to_owned(),
    });
  }
  let wanted = Path::new(query);
  let mut matches: Vec<&ProfileMatchCandidate> = candidates
    .iter()
    .filter(|candidate| {
      candidate.display_name == query
        || candidate.directory_name.to_str() == Some(query)
        || candidate.path == wanted
        || candidate
          .persistent_source_paths
          .iter()
          .any(|path| path == wanted)
    })
    .collect();
  matches.sort_by(|left, right| left.profile_id.cmp(&right.profile_id));
  matches.dedup_by(|left, right| left.profile_id == right.profile_id);
  match matches.as_slice() {
    [unique] => Ok(unique.profile_id.clone()),
    [] => Err(RequestError::UnknownProfile {
      browser_id: browser_id.to_owned(),
      query: query.to_owned(),
    }),
    several => Err(RequestError::AmbiguousProfile {
      browser_id: browser_id.to_owned(),
      query: query.to_owned(),
      profile_ids: several
        .iter()
        .map(|candidate| candidate.profile_id.clone())
        .collect(),
    }),
  }
}

fn list_profile_candidates(
  canonical_id: &str,
  engine: &str,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<ProfileMatchCandidate>> {
  match engine {
    "chromium" => {
      let listing = chromium_listing_with_runtime(canonical_id, runtime)?;
      if listing.all_detected_roots_failed {
        anyhow::bail!("every detected {canonical_id} installation failed profile enumeration");
      }
      Ok(
        listing
          .profiles
          .into_iter()
          .map(|profile| ProfileMatchCandidate {
            path_lossy: profile.path.to_str().is_none(),
            directory_name: OsString::from(profile.directory_name),
            persistent_source_paths: profile
              .persistent_candidates
              .into_iter()
              .map(|candidate| candidate.path)
              .collect(),
            profile_id: profile.profile_id.as_str().to_owned(),
            display_name: profile.display_name,
            path: profile.path,
          })
          .collect(),
      )
    }
    "gecko" => {
      let listing = gecko_profiles_with_runtime(canonical_id, runtime)?;
      if listing.all_detected_roots_failed() {
        anyhow::bail!("every detected {canonical_id} installation failed profile enumeration");
      }
      Ok(
        listing
          .profiles
          .into_iter()
          .map(discovered_candidate)
          .collect(),
      )
    }
    #[cfg(target_os = "macos")]
    "safari" => {
      let listing = super::safari_profiles_with_runtime(canonical_id, runtime)?;
      if listing.all_detected_roots_failed() {
        anyhow::bail!("every detected {canonical_id} installation failed profile enumeration");
      }
      Ok(
        listing
          .profiles
          .into_iter()
          .map(discovered_candidate)
          .collect(),
      )
    }
    #[cfg(target_os = "windows")]
    "internet_explorer" => {
      let listing = super::internet_explorer_profiles_with_runtime(canonical_id, runtime)?;
      if listing.all_detected_roots_failed() {
        anyhow::bail!("every detected {canonical_id} installation failed profile enumeration");
      }
      Ok(
        listing
          .profiles
          .into_iter()
          .map(discovered_candidate)
          .collect(),
      )
    }
    _ => Ok(Vec::new()),
  }
}

/// Maps a listing profile onto an ADR 0003 match candidate. The persistent
/// source path key (ADR 0004) comes from the listing candidates.
fn discovered_candidate(profile: DiscoveredProfile) -> ProfileMatchCandidate {
  let directory_name = profile
    .identity
    .path
    .file_name()
    .map(OsString::from)
    .unwrap_or_default();
  let persistent = CookieSourceRoleId::persistent();
  ProfileMatchCandidate {
    profile_id: profile.identity.profile_id.as_str().to_owned(),
    display_name: profile.identity.name,
    directory_name,
    path_lossy: profile.identity.path.to_str().is_none(),
    persistent_source_paths: profile
      .candidates
      .into_iter()
      .filter(|candidate| candidate.role == persistent)
      .map(|candidate| candidate.path)
      .collect(),
    path: profile.identity.path,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::browser::registry::resolve_registered_browser;
  use crate::common::deadline::{BoundaryRuntime, SystemClock};
  use crate::fault_kind;
  use crate::FaultKind;

  fn cand(
    id: &str,
    display: &str,
    dir: &str,
    path: &str,
    sources: &[&str],
  ) -> ProfileMatchCandidate {
    ProfileMatchCandidate {
      profile_id: id.to_owned(),
      display_name: display.to_owned(),
      directory_name: OsString::from(dir),
      path: PathBuf::from(path),
      path_lossy: false,
      persistent_source_paths: sources.iter().map(PathBuf::from).collect(),
    }
  }

  #[test]
  fn resolver_table_name_dir_path_id() {
    let personal = cand(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "Personal",
      "Profile 1",
      "/Users/me/Chrome/Profile 1",
      &["/Users/me/Chrome/Profile 1/Network/Cookies"],
    );
    let set = [personal];
    assert_eq!(
      match_profile_query("chrome", "Personal", &set).unwrap(),
      set[0].profile_id
    );
    assert_eq!(
      match_profile_query("chrome", "Profile 1", &set).unwrap(),
      set[0].profile_id
    );
    assert_eq!(
      match_profile_query("chrome", "/Users/me/Chrome/Profile 1", &set).unwrap(),
      set[0].profile_id
    );
    assert_eq!(
      match_profile_query("chrome", &set[0].profile_id, &set).unwrap(),
      set[0].profile_id
    );
  }

  #[test]
  fn two_defaults_are_ambiguous() {
    let a = cand(
      "aa".repeat(32).as_str(),
      "Stable",
      "Default",
      "/s/Default",
      &[],
    );
    let b = cand(
      "bb".repeat(32).as_str(),
      "Beta",
      "Default",
      "/b/Default",
      &[],
    );
    let set = [a.clone(), b.clone()];
    let error = match_profile_query("chrome", "Default", &set).unwrap_err();
    assert!(matches!(error, RequestError::AmbiguousProfile { .. }));
    assert_eq!(error.profile_ids().len(), 2);
    assert_eq!(
      match_profile_query("chrome", "Stable", &set).unwrap(),
      a.profile_id
    );
    assert_eq!(
      match_profile_query("chrome", &a.profile_id, &set).unwrap(),
      a.profile_id
    );
  }

  #[test]
  fn empty_and_unknown_and_spaces() {
    let set = [cand("aa".repeat(32).as_str(), "Work", "Default", "/d", &[])];
    assert!(matches!(
      match_profile_query("chrome", "", &set),
      Err(RequestError::EmptyProfileSelector)
    ));
    assert!(matches!(
      match_profile_query("chrome", "  ", &set),
      Err(RequestError::UnknownProfile { .. })
    ));
    assert!(matches!(
      match_profile_query("chrome", "nope", &set),
      Err(RequestError::UnknownProfile { .. })
    ));
    assert!(matches!(
      match_profile_query("chrome", &"0".repeat(64), &set),
      Err(RequestError::UnknownProfile { .. })
    ));
  }

  #[test]
  fn same_display_and_directory_is_unique() {
    let set = [cand(
      "aa".repeat(32).as_str(),
      "Default",
      "Default",
      "/Default",
      &[],
    )];
    assert_eq!(
      match_profile_query("chrome", "Default", &set).unwrap(),
      set[0].profile_id
    );
  }

  #[test]
  fn display_versus_other_directory_is_ambiguous() {
    let a = cand("aa".repeat(32).as_str(), "Profile 1", "Default", "/a", &[]);
    let b = cand("bb".repeat(32).as_str(), "Work", "Profile 1", "/b", &[]);
    let error = match_profile_query("chrome", "Profile 1", &[a, b]).unwrap_err();
    assert!(matches!(error, RequestError::AmbiguousProfile { .. }));
  }

  #[test]
  fn cookie_db_path_selects_profile() {
    let network = "/data/Default/Network/Cookies";
    let legacy = "/data/Default/Cookies";
    let set = [cand(
      "aa".repeat(32).as_str(),
      "Default",
      "Default",
      "/data/Default",
      &[network, legacy],
    )];
    assert_eq!(
      match_profile_query("chrome", network, &set).unwrap(),
      set[0].profile_id
    );
    assert_eq!(
      match_profile_query("chrome", legacy, &set).unwrap(),
      set[0].profile_id
    );
  }

  #[test]
  fn cookie_db_path_distinguishes_absolute_paths() {
    let a = cand(
      "aa".repeat(32).as_str(),
      "Default",
      "Default",
      "/stable/Default",
      &["/stable/Default/Cookies"],
    );
    let b = cand(
      "bb".repeat(32).as_str(),
      "Default",
      "Default",
      "/beta/Default",
      &["/beta/Default/Cookies"],
    );
    assert_eq!(
      match_profile_query("chrome", "/stable/Default/Cookies", &[a.clone(), b.clone()]).unwrap(),
      a.profile_id
    );
  }

  #[test]
  fn unlisted_file_is_unknown_profile() {
    let set = [cand(
      "aa".repeat(32).as_str(),
      "Default",
      "Default",
      "/data/Default",
      &["/data/Default/Cookies"],
    )];
    assert!(matches!(
      match_profile_query("chrome", "/tmp/copied/Cookies", &set),
      Err(RequestError::UnknownProfile { .. })
    ));
  }

  #[test]
  fn session_only_gecko_row_matches_name() {
    let set = [cand(
      "ff".repeat(32).as_str(),
      "scratch",
      "abc.scratch",
      "/moz/abc.scratch",
      &[],
    )];
    assert_eq!(
      match_profile_query("firefox", "scratch", &set).unwrap(),
      set[0].profile_id
    );
  }

  #[test]
  fn empty_listing_is_unknown_profile_not_no_sources() {
    assert!(matches!(
      match_profile_query("chrome", "Default", &[]),
      Err(RequestError::UnknownProfile { .. })
    ));
  }

  #[cfg(unix)]
  #[test]
  fn lossy_path_query_is_lossy_error() {
    use std::os::unix::ffi::OsStringExt;
    let mut candidate = cand("aa".repeat(32).as_str(), "Odd", "odd", "/tmp/ok", &[]);
    candidate.path = PathBuf::from(OsString::from_vec(vec![0xff, b'x']));
    candidate.path_lossy = true;
    let display = candidate.path.to_string_lossy().into_owned();
    let error = match_profile_query("chrome", &display, &[candidate.clone()]).unwrap_err();
    assert!(matches!(error, RequestError::LossyProfilePath { .. }));
    let profile_id = candidate.profile_id.clone();
    assert_eq!(
      match_profile_query("chrome", &profile_id, &[candidate]).unwrap(),
      profile_id
    );
  }

  #[test]
  fn unknown_browser_is_request_error_without_listing() {
    let clock = SystemClock;
    let runtime = BoundaryRuntime::standard(&clock);
    let error = resolve_profile_query("not-a-browser", "Default", &runtime).unwrap_err();
    assert!(error.downcast_ref::<RequestError>().is_some());
    assert_eq!(fault_kind(&error), FaultKind::Request);
  }

  #[test]
  fn alias_resolves_to_registered_canonical() {
    if let Ok(browser) = resolve_registered_browser("opera-gx") {
      assert_eq!(browser.canonical_id, "opera_gx");
    }
    if let Ok(browser) = resolve_registered_browser("ie") {
      assert_eq!(browser.canonical_id, "internet_explorer");
    }
  }
}
