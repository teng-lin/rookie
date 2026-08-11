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
  // Cookies committed to the write-ahead log are not in the main database yet,
  // so a copy without it silently omits the very cookies this path exists to
  // reach. Any failure to obtain it is therefore fatal rather than a warning,
  // which lets `unlock_file` fall through to the restart-manager path and its
  // checkpointed database. That includes a WAL that cannot be stat'd:
  // `Path::exists` would report an ACL, sharing or transient error as "no WAL".
  //
  // The WAL goes first here, unlike the portable path, so that the two copies
  // can be bracketed by a second WAL image below.
  let wal = sqlite::sidecar(&src, "-wal");
  let copied_wal = sqlite::has_nonempty_wal(&src)?;
  if copied_wal {
    raw_copy(&wal, &dst)?;
  }

  raw_copy(&src, &dst)?;

  // These two raw copies are not atomic either, and `sqlite::connect` cannot
  // cover for that: by the time it runs it is inspecting this static copy, not
  // the live source, so a checkpoint that landed here is already baked in.
  //
  // The portable check does not port. It compares its copy against the live
  // source, and this path exists precisely because the source cannot be opened
  // normally. So the WAL is raw-copied a second time and the two images are
  // compared instead: an unchanged WAL means no frames were appended during the
  // window, so any checkpoint in it folded only frames the first copy already
  // holds, and replaying them over the copied database rewrites identical
  // bytes. The WAL is the smaller file, which keeps the extra raw copy cheap.
  if copied_wal {
    let probe = TempDir::new()?;
    raw_copy(&wal, probe.path())?;

    let name = wal
      .file_name()
      .ok_or_else(|| anyhow!("Write-ahead log path has no file name: {}", wal.display()))?;
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
