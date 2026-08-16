use crate::common::deadline::BoundaryRuntime;
use crate::common::diagnostic::{sanitize, REDACTED_PATH};
use crate::common::sqlite;
use crate::utils::TempDir;
use anyhow::{anyhow, bail, Context, Result};
use privilege::user::privileged;
use std::path::{Path, PathBuf};

/// dst should be directory
pub fn shadow_copy(src: PathBuf, dst: PathBuf, runtime: &BoundaryRuntime<'_>) -> Result<()> {
  runtime.check()?;
  if !src.exists() {
    bail!("Source file does not exist: {REDACTED_PATH}")
  }
  runtime.check()?;
  let is_privileged = privileged();
  runtime.check()?;
  if !is_privileged {
    bail!("No admin rights")
  }
  log::info!("Creating shadow copy from {REDACTED_PATH} to {REDACTED_PATH}");
  let name = src
    .file_name()
    .ok_or_else(|| anyhow!("Database path has no file name: {REDACTED_PATH}"))?;
  raw_copy(&src, &dst, runtime)?;

  // Cookies committed to the write-ahead log are not in the main database yet,
  // so a copy without it silently omits the very cookies this path exists to
  // reach. Any failure to obtain it is therefore fatal rather than a warning,
  // which lets the Windows acquisition policy fall through to its explicit
  // restart-manager path and a subsequently checkpointed database. That
  // includes a WAL that cannot be stat'd:
  // `Path::exists` would report an ACL, sharing or transient error as "no WAL".
  let wal = sqlite::sidecar(&src, "-wal");
  runtime.check()?;
  let has_nonempty_wal = sqlite::has_nonempty_wal_with_runtime(&src, runtime);
  runtime.check()?;
  if has_nonempty_wal? {
    raw_copy(&wal, &dst, runtime)?;
  }

  // These raw copies are not atomic, and the SQLite query boundary cannot
  // cover for that: by the time it runs it is inspecting this static copy, not
  // the live source, so a checkpoint that landed here is already baked in.
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
  runtime.check()?;
  let probe = TempDir::new()?;
  runtime.check()?;
  raw_copy(&src, probe.path(), runtime)?;

  if !sqlite::files_are_identical(&dst.join(name), &probe.path().join(name), runtime)? {
    // Reported rather than retried: a raw copy rescans NTFS clusters, so
    // retrying against a busy database is a poor trade. The acquisition policy
    // can fall through to its explicitly enabled restart-manager path, which
    // yields a checkpointed database instead of an incoherent pair.
    bail!("A checkpoint raced the shadow copy of {REDACTED_PATH}; the copy is not coherent")
  }

  Ok(())
}

fn raw_copy(src: &Path, dst: &Path, runtime: &BoundaryRuntime<'_>) -> Result<()> {
  runtime.check()?;
  let (src, dst) = (
    src
      .to_str()
      .with_context(|| format!("Non UTF-8 source path: {REDACTED_PATH}"))?,
    dst
      .to_str()
      .with_context(|| format!("Non UTF-8 destination path: {REDACTED_PATH}"))?,
  );

  let result = rawcopy_rs_next::rawcopy(src, dst)
    .map_err(|error| anyhow::anyhow!(sanitize(&error.to_string())))
    .context(format!(
      "Can't shadow copy from {REDACTED_PATH} to {REDACTED_PATH}"
    ));
  runtime.check()?;
  result
}
