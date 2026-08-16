use std::fs;
use std::path::{Path, PathBuf};

use crate::common::diagnostic::REDACTED_PATH;
use anyhow::Result;
use rand::distributions::Alphanumeric;
use rand::Rng;

pub fn random_string(length: usize, prefix: &str, suffix: &str) -> String {
  let random_part: String = rand::thread_rng()
    .sample_iter(&Alphanumeric)
    .take(length)
    .map(char::from)
    .collect();

  format!("{}{}{}", prefix, random_part, suffix)
}

/// A private directory under the system temp directory, removed on drop.
///
/// Callers copy browser databases here, so on Unix the directory is created
/// with `0700` to keep cookie material out of reach of other local users.
pub struct TempDir {
  path: PathBuf,
}

impl TempDir {
  pub fn new() -> Result<Self> {
    let path = std::env::temp_dir().join(random_string(10, ".tmp", ""));
    create_private_dir(&path)?;
    log::trace!("created private directory {REDACTED_PATH}");
    Ok(Self { path })
  }

  pub fn path(&self) -> &Path {
    &self.path
  }
}

impl Drop for TempDir {
  fn drop(&mut self) {
    if let Err(err) = fs::remove_dir_all(&self.path) {
      log::warn!(
        "failed to remove temporary directory {REDACTED_PATH}: {err}. It may hold a copy of \
         browser cookie data",
      );
    }
  }
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> Result<()> {
  use anyhow::Context;
  use std::os::unix::fs::DirBuilderExt;

  fs::DirBuilder::new()
    .mode(0o700)
    .create(path)
    .with_context(|| format!("Can't create temporary directory {REDACTED_PATH}"))
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> Result<()> {
  use anyhow::Context;

  fs::create_dir(path).with_context(|| format!("Can't create temporary directory {REDACTED_PATH}"))
}

#[cfg(test)]
mod tests {
  use super::TempDir;

  #[test]
  fn temp_dir_is_removed_on_drop() {
    let path = {
      let temp_dir = TempDir::new().expect("create temp dir");
      let path = temp_dir.path().to_path_buf();
      assert!(path.exists());
      path
    };

    assert!(!path.exists());
  }

  #[cfg(unix)]
  #[test]
  fn temp_dir_is_not_readable_by_other_users() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = TempDir::new().expect("create temp dir");
    let mode = std::fs::metadata(temp_dir.path())
      .expect("stat temp dir")
      .permissions()
      .mode();

    // The umask can only clear bits, so assert the invariant that matters
    // rather than an exact 0700 that a stricter umask would fail.
    assert_eq!(mode & 0o077, 0, "mode was {:o}", mode & 0o777);
  }
}
