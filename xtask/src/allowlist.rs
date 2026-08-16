//! Loads and validates `cfg-location-allowlist.toml` -- see that file's own
//! header comment for the two-tier `leaves`/`grandfathered` model.

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowlist {
  pub leaves: Leaves,
  pub grandfathered: BTreeMap<String, Grandfathered>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Leaves {
  pub paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grandfathered {
  pub max_cfg: usize,
  #[allow(dead_code)]
  pub reason: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
  /// Not in either table: any hit at all is a new violation.
  Unlisted,
  /// A leaf: any number of hits is fine.
  Leaf,
  /// A grandfathered core file: fine as long as the hit count doesn't
  /// exceed the pinned ceiling.
  Grandfathered { max_cfg: usize },
}

impl Allowlist {
  pub fn load(path: &Path) -> Result<Self, String> {
    let text = std::fs::read_to_string(path)
      .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    Self::parse(&text)
  }

  fn parse(text: &str) -> Result<Self, String> {
    let allowlist: Self =
      toml::from_str(text).map_err(|error| format!("failed to parse: {error}"))?;
    allowlist.validate()?;
    Ok(allowlist)
  }

  /// Rejects a `leaves`/`grandfathered` state this loader can't safely act
  /// on: a duplicate path within `leaves`, or a path listed in *both*
  /// tables. `verdict()` checks `leaves` first, so an overlap would
  /// silently make a grandfathered ceiling unenforceable -- fail loudly at
  /// load time instead of leaving that possible in the data.
  fn validate(&self) -> Result<(), String> {
    let mut seen_leaves = BTreeSet::new();
    for path in &self.leaves.paths {
      if !seen_leaves.insert(path.as_str()) {
        return Err(format!("{path:?} is listed more than once in `leaves`"));
      }
    }
    for path in &self.leaves.paths {
      if self.grandfathered.contains_key(path) {
        return Err(format!(
          "{path:?} is listed in both `leaves` and `grandfathered` -- pick one"
        ));
      }
    }
    Ok(())
  }

  pub fn verdict(&self, relative_path: &str) -> Verdict {
    if self.leaves.paths.iter().any(|path| path == relative_path) {
      return Verdict::Leaf;
    }
    if let Some(entry) = self.grandfathered.get(relative_path) {
      return Verdict::Grandfathered {
        max_cfg: entry.max_cfg,
      };
    }
    Verdict::Unlisted
  }

  /// Every allowlisted path that doesn't correspond to any file `scanned`
  /// walked -- a stale entry, most likely a rename/deletion that forgot to
  /// update this file.
  pub fn stale_paths<'a>(&'a self, scanned_paths: &[String]) -> Vec<&'a str> {
    self
      .leaves
      .paths
      .iter()
      .map(String::as_str)
      .chain(self.grandfathered.keys().map(String::as_str))
      .filter(|path| !scanned_paths.iter().any(|scanned| scanned == path))
      .collect()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const VALID: &str = r#"
    [leaves]
    paths = ["a/leaf.rs"]

    [grandfathered]
    "a/core.rs" = { max_cfg = 3, reason = "test fixture" }
  "#;

  #[test]
  fn parses_a_valid_allowlist() {
    let allowlist = Allowlist::parse(VALID).expect("valid allowlist");
    assert_eq!(allowlist.verdict("a/leaf.rs"), Verdict::Leaf);
    assert_eq!(
      allowlist.verdict("a/core.rs"),
      Verdict::Grandfathered { max_cfg: 3 }
    );
    assert_eq!(allowlist.verdict("a/unknown.rs"), Verdict::Unlisted);
  }

  #[test]
  fn load_reports_a_clean_error_for_a_missing_file() {
    let error = Allowlist::load(Path::new("/does/not/exist/allowlist.toml"))
      .expect_err("missing file must not panic");
    assert!(
      error.contains("failed to read"),
      "unexpected message: {error}"
    );
  }

  #[test]
  fn load_reports_a_clean_error_for_malformed_toml() {
    let error =
      Allowlist::parse("this is not [ valid toml").expect_err("malformed TOML must not panic");
    assert!(
      error.contains("failed to parse"),
      "unexpected message: {error}"
    );
  }

  #[test]
  fn load_reports_a_clean_error_for_a_missing_required_field() {
    let text = r#"
      [leaves]
      paths = []

      [grandfathered]
      "a/core.rs" = { max_cfg = 3 }
    "#;
    let error =
      Allowlist::parse(text).expect_err("a grandfathered entry without `reason` must fail");
    assert!(
      error.contains("failed to parse"),
      "unexpected message: {error}"
    );
  }

  #[test]
  fn rejects_an_unknown_top_level_field() {
    let text = r#"
      [leaves]
      paths = []

      [grandfathered]

      [oops]
    "#;
    let error = Allowlist::parse(text).expect_err("unknown table must be rejected");
    assert!(
      error.contains("failed to parse"),
      "unexpected message: {error}"
    );
  }

  #[test]
  fn rejects_an_unknown_grandfathered_field() {
    let text = r#"
      [leaves]
      paths = []

      [grandfathered]
      "a/core.rs" = { max_cfg = 3, reason = "test", oops = true }
    "#;
    let error = Allowlist::parse(text).expect_err("unknown field must be rejected");
    assert!(
      error.contains("failed to parse"),
      "unexpected message: {error}"
    );
  }

  #[test]
  fn rejects_a_path_duplicated_within_leaves() {
    let text = r#"
      [leaves]
      paths = ["a/leaf.rs", "a/leaf.rs"]

      [grandfathered]
    "#;
    let error = Allowlist::parse(text).expect_err("duplicate leaf path must be rejected");
    assert!(
      error.contains("more than once"),
      "unexpected message: {error}"
    );
  }

  #[test]
  fn rejects_a_path_listed_in_both_tables() {
    // This is exactly the state that would silently defeat a grandfathered
    // ceiling: verdict() checks `leaves` first, so without this rejection
    // the file would classify as an unlimited Leaf instead.
    let text = r#"
      [leaves]
      paths = ["a/both.rs"]

      [grandfathered]
      "a/both.rs" = { max_cfg = 3, reason = "should be rejected" }
    "#;
    let error = Allowlist::parse(text)
      .expect_err("overlap between leaves and grandfathered must be rejected");
    assert!(error.contains("both"), "unexpected message: {error}");
  }

  #[test]
  fn stale_paths_reports_entries_with_no_matching_scanned_file() {
    let allowlist = Allowlist::parse(VALID).expect("valid allowlist");
    let scanned = vec!["a/leaf.rs".to_owned()];
    assert_eq!(allowlist.stale_paths(&scanned), vec!["a/core.rs"]);
  }

  #[test]
  fn stale_paths_is_empty_when_every_entry_matches_a_scanned_file() {
    let allowlist = Allowlist::parse(VALID).expect("valid allowlist");
    let scanned = vec!["a/leaf.rs".to_owned(), "a/core.rs".to_owned()];
    assert!(allowlist.stale_paths(&scanned).is_empty());
  }
}
