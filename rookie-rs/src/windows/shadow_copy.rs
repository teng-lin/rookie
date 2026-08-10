use anyhow::{bail, Context, Result};
use privilege::user::privileged;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::path::{Path, PathBuf};

pub struct TempDir {
  path: PathBuf,
}

impl TempDir {
  pub fn new() -> Result<Self> {
    let random_string: String = thread_rng()
      .sample_iter(&Alphanumeric)
      .take(10)
      .map(char::from)
      .collect();
    let path = std::env::temp_dir().join(format!(".tmp{random_string}"));
    std::fs::create_dir(&path)?;
    log::trace!("created dir {}", path.display());
    Ok(Self { path })
  }

  pub fn path(&self) -> &Path {
    &self.path
  }
}

impl Drop for TempDir {
  fn drop(&mut self) {
    if let Err(err) = std::fs::remove_dir_all(&self.path) {
      log::warn!(
        "failed to remove temporary shadow-copy directory {}: {err}",
        self.path.display()
      );
    }
  }
}

/// dst should be directory
pub fn shadow_copy(src: PathBuf, dst: PathBuf) -> Result<()> {
  if !src.exists() {
    bail!("Source file not exists: {}", src.clone().display())
  }
  if !privileged() {
    bail!("No admin rights")
  }
  log::info!(
    "Creating shadow copy to cookies file from {} to {}",
    src.display(),
    dst.display()
  );
  rawcopy_rs_next::rawcopy(src.clone().to_str().unwrap(), dst.to_str().unwrap())
    .map_err(|err| anyhow::anyhow!(Box::new(err)))
    .context(format!(
      "Can't shadow copy from {} to {}",
      src.display(),
      dst.display(),
    ))?;

  Ok(())
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
}
