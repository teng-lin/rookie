//! Which profiles a job may reach, expressed so that an illegal selection
//! cannot be built.

/// Selects exactly one profile.
///
/// There is deliberately no "every profile" arm. A snapshot returns one
/// `ReadResult` with one `profile_id`, and a flat extract returns one list, so
/// "every profile" is not a shape either can express. Making that a type fact
/// removes a class of runtime error rather than documenting it: 0.6-beta let
/// the same value mean "first profile" to `extract` and "every profile" to
/// `extract_report`, which is a silent behavior difference between two calls
/// that look identical.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ProfileSelection {
  /// The first legacy-eligible profile, matching the named v0.5.9 helpers.
  #[default]
  LegacyFirst,
  /// An ADR 0003 profile query: an opaque `profile_id`, a display name, a
  /// directory name, or a non-lossy full path. Resolved when the job runs.
  Query(String),
}

impl ProfileSelection {
  /// The query string, if this selection names one.
  pub fn query(&self) -> Option<&str> {
    match self {
      Self::Query(query) => Some(query),
      _ => None,
    }
  }

  /// Builds a single-profile selection from flattened binding/CLI options.
  ///
  /// `select` uses the cross-binding snake-case vocabulary. A snapshot cannot
  /// represent `"all"`; unknown values and contradictory shapes return the
  /// same stable [`crate::RequestError::ConflictingProfileSelection`].
  pub fn from_binding_options(
    profile: Option<&str>,
    select: Option<&str>,
  ) -> Result<Self, crate::RequestError> {
    if !matches!(select, None | Some("legacy_first")) {
      return Err(crate::RequestError::ConflictingProfileSelection);
    }
    Ok(profile.map_or(Self::LegacyFirst, |query| Self::Query(query.to_owned())))
  }
}

/// How wide a report's scope is.
///
/// Only reports may widen to every profile, because only a report has a place
/// to put per-profile provenance, status, and failures.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ReportScope {
  /// Every installation and profile. This is what v0.5.9's
  /// `browser_report(id, None, domains)` has always meant.
  #[default]
  AllProfiles,
  /// One profile, chosen the same way single-profile jobs choose.
  One(ProfileSelection),
}

impl ReportScope {
  /// The profile query, if this scope narrows to one named profile.
  pub fn query(&self) -> Option<&str> {
    match self {
      Self::One(selection) => selection.query(),
      _ => None,
    }
  }

  /// Builds a report scope from flattened binding/CLI options.
  ///
  /// Omitted `select` preserves the historical behavior: all profiles when no
  /// profile was named, or the named profile otherwise. Explicitly combining
  /// a profile with `"all"`, or supplying an unknown value, returns
  /// [`crate::RequestError::ConflictingProfileSelection`].
  pub fn from_binding_options(
    profile: Option<&str>,
    select: Option<&str>,
  ) -> Result<Self, crate::RequestError> {
    if !matches!(select, None | Some("legacy_first") | Some("all"))
      || (profile.is_some() && select == Some("all"))
    {
      return Err(crate::RequestError::ConflictingProfileSelection);
    }

    Ok(match (profile, select) {
      (Some(query), _) => Self::One(ProfileSelection::Query(query.to_owned())),
      (None, Some("legacy_first")) => Self::One(ProfileSelection::LegacyFirst),
      (None, None | Some("all")) => Self::AllProfiles,
      // The vocabulary and conflict checks above make every other shape
      // unreachable while keeping this match robust to future enum variants.
      (None, Some(_)) => unreachable!("selection vocabulary was validated"),
    })
  }
}

impl From<ProfileSelection> for ReportScope {
  fn from(selection: ProfileSelection) -> Self {
    Self::One(selection)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn the_defaults_are_the_two_different_right_answers() {
    // These deliberately differ. A snapshot or flat extract with no profile
    // named means "the first legacy-eligible profile", matching `chrome()`.
    // A report with no profile named means "every profile", matching
    // `browser_report(id, None, ..)`. Before 0.6.0 one `Request` value carried
    // both meanings, and which one you got depended on the function you passed
    // it to.
    assert_eq!(ProfileSelection::default(), ProfileSelection::LegacyFirst);
    assert_eq!(ReportScope::default(), ReportScope::AllProfiles);
  }

  #[test]
  fn a_selection_widens_to_one_profile_never_to_all() {
    let scope = ReportScope::from(ProfileSelection::Query("Default".to_owned()));
    assert_eq!(scope.query(), Some("Default"));
    assert_eq!(
      ReportScope::from(ProfileSelection::LegacyFirst),
      ReportScope::One(ProfileSelection::LegacyFirst)
    );
  }

  #[test]
  fn binding_options_share_one_profile_scope_rule() {
    assert_eq!(
      ProfileSelection::from_binding_options(Some("Default"), Some("legacy_first")),
      Ok(ProfileSelection::Query("Default".into()))
    );
    assert_eq!(
      ProfileSelection::from_binding_options(None, Some("all")),
      Err(crate::RequestError::ConflictingProfileSelection)
    );
    assert_eq!(
      ReportScope::from_binding_options(None, None),
      Ok(ReportScope::AllProfiles)
    );
    assert_eq!(
      ReportScope::from_binding_options(None, Some("legacy_first")),
      Ok(ReportScope::One(ProfileSelection::LegacyFirst))
    );
    assert_eq!(
      ReportScope::from_binding_options(Some("Default"), Some("all")),
      Err(crate::RequestError::ConflictingProfileSelection)
    );
  }
}
