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
  let before = sqlite::main_file_fingerprint(&src)?;

  let wal = sqlite::sidecar(&src, "-wal");
  if wal.exists() {
    raw_copy(&wal, &dst)?;
  }

  raw_copy(&src, &dst)?;

  // The two raw copies are not atomic either, so a checkpoint arriving between
  // them pairs an older WAL with a newer database. `sqlite::connect` cannot
  // catch that later: by then it is fingerprinting this static copy, not the
  // live source. Unlike the portable path this cannot retry cheaply — a raw
  // copy rescans NTFS clusters — and it cannot compare against the source,
  // which is locked. So it reports the race and lets `unlock_file` fall through
  // to the restart-manager path, which yields a checkpointed database.
  if sqlite::main_file_fingerprint(&src)? != before {
    bail!(
      "A checkpoint raced the shadow copy of {}; the copy is not coherent",
      src.display()
    )
  }

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
