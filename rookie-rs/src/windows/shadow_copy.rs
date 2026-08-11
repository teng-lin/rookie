use crate::common::sqlite;
use crate::utils::TempDir;
use anyhow::{anyhow, bail, Context, Result};
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
  let name = src
    .file_name()
    .ok_or_else(|| anyhow!("Database path has no file name: {}", src.display()))?;
  raw_copy(&src, &dst)?;

  // Cookies committed to the write-ahead log are not in the main database yet,
  // so a copy without it silently omits the very cookies this path exists to
  // reach. Any failure to obtain it is therefore fatal rather than a warning,
  // which lets `unlock_file` fall through to the restart-manager path and its
  // checkpointed database. That includes a WAL that cannot be stat'd:
  // `Path::exists` would report an ACL, sharing or transient error as "no WAL".
  let wal = sqlite::sidecar(&src, "-wal");
  if sqlite::has_nonempty_wal(&src)? {
    raw_copy(&wal, &dst)?;
  }

  // These raw copies are not atomic, and `sqlite::connect` cannot cover for
  // that: by the time it runs it is inspecting this static copy, not the live
  // source, so a checkpoint that landed here is already baked in.
  //
  // Same invariant as `sqlite::snapshot_database` — the main file must not move
  // across the whole sequence — but verified differently, because this path
  // exists precisely because the source cannot be opened normally and so cannot
  // be compared against. A second raw copy of the main file stands in for
  // reading the source. Comparing main images rather than WAL images matters:
  // ordinary commits append to the WAL and leave the main file alone, so they
  // must not be mistaken for a checkpoint and rejected.
  //
  // This runs whether or not a WAL was found. A checkpoint that removed the WAL
  // between the copy above and the lookup would otherwise go unnoticed, leaving
  // a pre-checkpoint database whose newest cookies now live only in the live
  // main file, and it is also what catches a main copy torn mid-scan.
  let probe = TempDir::new()?;
  raw_copy(&src, probe.path())?;

  if !sqlite::files_are_identical(&dst.join(name), &probe.path().join(name))? {
    // Reported rather than retried: a raw copy rescans NTFS clusters, so
    // retrying against a busy database is a poor trade. `unlock_file` falls
    // through to the restart-manager path, which yields a checkpointed
    // database instead of an incoherent pair.
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
