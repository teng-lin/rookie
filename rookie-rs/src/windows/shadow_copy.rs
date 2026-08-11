use crate::common::sqlite;
use anyhow::{bail, Context, Result};
use privilege::user::privileged;
use std::path::{Path, PathBuf};

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
  // Copy the write-ahead log first, then the main database: a checkpoint only
  // moves pages out of the WAL, so an older WAL paired with a newer main file
  // replays safely, while the reverse order can pair a stale main file with a
  // rewound WAL. Same reasoning as `sqlite::copy_database`.
  //
  // A failure here is fatal rather than a warning. Cookies committed to the WAL
  // are not in the main database yet, so a copy without it silently omits the
  // very cookies this path exists to reach. Returning an error instead lets
  // `unlock_file` fall through to the restart-manager path, which yields a
  // checkpointed database.
  let wal = sqlite::sidecar(&src, "-wal");
  if wal.exists() {
    raw_copy(&wal, &dst)?;
  }

  raw_copy(&src, &dst)?;

  Ok(())
}

fn raw_copy(src: &Path, dst: &Path) -> Result<()> {
  let (src, dst) = (
    src
      .to_str()
      .with_context(|| format!("Non UTF-8 source path: {}", src.display()))?,
    dst
      .to_str()
      .with_context(|| format!("Non UTF-8 destination path: {}", dst.display()))?,
  );

  rawcopy_rs_next::rawcopy(src, dst)
    .map_err(|err| anyhow::anyhow!(Box::new(err)))
    .context(format!("Can't shadow copy from {src} to {dst}"))
}
