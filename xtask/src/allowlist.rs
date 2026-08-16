//! Loads and validates `cfg-location-allowlist.toml` -- see that file's own
//! header comment for the two-tier `leaves`/`grandfathered` model.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Allowlist {
  pub leaves: Leaves,
  pub grandfathered: BTreeMap<String, Grandfathered>,
}

#[derive(Debug, Deserialize)]
pub struct Leaves {
  pub paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Grandfathered {
  pub max_cfg: usize,
  #[allow(dead_code)]
  pub reason: String,
}

#[derive(Debug)]
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
    toml::from_str(&text).map_err(|error| format!("failed to parse {}: {error}", path.display()))
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
