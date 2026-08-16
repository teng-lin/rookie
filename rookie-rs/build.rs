use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A full lowercase 40-character hex commit SHA, same shape release tooling
/// already validates elsewhere (see `COMMIT_PATTERN` in
/// `scripts/write-release-scan-manifest.py`).
fn is_full_sha(value: &str) -> bool {
  value.len() == 40
    && value
      .bytes()
      .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// The source SHA a release coordinator already verified, injected so this
/// build never needs to (re-)discover it from whatever `.git` happens to be
/// on disk. Takes precedence over any ambient git discovery below: a
/// coordinator-built artifact must embed exactly the SHA it was told to
/// build, not something a vendored/relocated checkout's git history implies.
fn injected_source_sha() -> Option<String> {
  let value = env::var("ROOKIE_COOKIES_SOURCE_SHA").ok()?;
  if is_full_sha(&value) {
    Some(value[..7].to_string())
  } else {
    None
  }
}

/// Run `git rev-parse --short HEAD` scoped to a specific, already-resolved
/// `.git` directory via `--git-dir`, never ambient discovery. Ambient
/// discovery (plain `git rev-parse` with no `--git-dir`) walks upward from
/// the process's cwd looking for *any* `.git`, so a copy of this crate
/// vendored inside an unrelated outer repository would silently embed that
/// outer repo's SHA instead of failing or reporting "unknown".
fn commit_hash_from(git_dir: &Path) -> Option<String> {
  let output = Command::new("git")
    .arg("--git-dir")
    .arg(git_dir)
    .args(["rev-parse", "--short", "HEAD"])
    .output()
    .ok()?;
  if !output.status.success() {
    return None;
  }
  let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
  if hash.is_empty() {
    None
  } else {
    Some(hash)
  }
}

/// Resolve a `.git` entry to the git directory that actually holds `HEAD`.
///
/// For an ordinary checkout `.git` is already that directory. For a linked
/// worktree, `.git` is a file containing `gitdir: <path>` pointing at the
/// worktree-specific git dir (typically `<repo>/.git/worktrees/<name>`).
fn resolve_git_dir(dot_git: &Path) -> Option<PathBuf> {
  if dot_git.is_dir() {
    return Some(dot_git.to_path_buf());
  }

  let contents = fs::read_to_string(dot_git).ok()?;
  let gitdir_line = contents.lines().next()?.trim();
  let raw_path = gitdir_line.strip_prefix("gitdir:")?.trim();
  let path = PathBuf::from(raw_path);

  Some(if path.is_absolute() {
    path
  } else {
    dot_git.parent()?.join(path)
  })
}

/// Resolve the "common" git directory where shared refs (`refs/`,
/// `packed-refs`) live. For a linked worktree this is recorded in a
/// `commondir` file inside the worktree's git dir; otherwise it's the git
/// dir itself.
fn resolve_common_dir(git_dir: &Path) -> PathBuf {
  let commondir_file = git_dir.join("commondir");
  match fs::read_to_string(&commondir_file) {
    Ok(contents) => {
      let relative = PathBuf::from(contents.trim());
      if relative.is_absolute() {
        relative
      } else {
        git_dir.join(relative)
      }
    }
    Err(_) => git_dir.to_path_buf(),
  }
}

/// Register `cargo:rerun-if-changed` for `HEAD` and whatever it currently
/// points at, so incremental rebuilds pick up new commits made on the
/// current branch (not just branch switches), and so this also works from
/// a linked worktree, not just an ordinary checkout. Returns `true` if a
/// `HEAD` file was found and watched.
fn watch_git_head(dot_git: &Path) -> bool {
  let Some(git_dir) = resolve_git_dir(dot_git) else {
    return false;
  };

  let head_path = git_dir.join("HEAD");
  if !head_path.exists() {
    return false;
  }
  println!("cargo:rerun-if-changed={}", head_path.display());

  let common_dir = resolve_common_dir(&git_dir);

  if let Ok(head_contents) = fs::read_to_string(&head_path) {
    if let Some(ref_name) = head_contents.trim().strip_prefix("ref:") {
      let ref_path = common_dir.join(ref_name.trim());
      // Register the loose ref even when it is currently represented only in
      // packed-refs. A subsequent commit creates this file; watching it
      // unconditionally ensures Cargo reruns this script for that transition.
      println!("cargo:rerun-if-changed={}", ref_path.display());
    }
  }

  let packed_refs = common_dir.join("packed-refs");
  if packed_refs.exists() {
    println!("cargo:rerun-if-changed={}", packed_refs.display());
  }

  true
}

fn main() {
  let manifest_dir = env::var("CARGO_MANIFEST_DIR").map(PathBuf::from).ok();

  // Bounded to the crate's own manifest dir and its immediate parent (the
  // workspace root) — never an unbounded upward search. A build run from
  // inside some other project's checkout (e.g. this crate vendored into a
  // consumer's repo) must not pick up that repo's `.git`.
  let candidate_dot_git_paths = [
    manifest_dir.as_ref().map(|d| d.join(".git")),
    manifest_dir.as_ref().map(|d| d.join("..").join(".git")),
    Some(PathBuf::from(".git")),
    Some(PathBuf::from("../.git")),
  ];

  let mut resolved_git_dir: Option<PathBuf> = None;
  for candidate in candidate_dot_git_paths.iter().flatten() {
    if !candidate.exists() {
      continue;
    }
    if resolved_git_dir.is_none() {
      resolved_git_dir = resolve_git_dir(candidate);
    }
    if watch_git_head(candidate) {
      break;
    }
  }

  let hash = injected_source_sha()
    .or_else(|| resolved_git_dir.as_deref().and_then(commit_hash_from))
    .unwrap_or_else(|| "unknown".to_string());
  println!("cargo:rustc-env=COMMIT_HASH={}", hash);
}
