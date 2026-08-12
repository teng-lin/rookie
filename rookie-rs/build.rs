use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn commit_hash() -> String {
  match Command::new("git")
    .args(["rev-parse", "--short", "HEAD"])
    .output()
  {
    Ok(output) if output.status.success() => {
      let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
      if hash.is_empty() {
        "unknown".to_string()
      } else {
        hash
      }
    }
    _ => "unknown".to_string(),
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
      if ref_path.exists() {
        println!("cargo:rerun-if-changed={}", ref_path.display());
      }
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

  let candidate_dot_git_paths = [
    manifest_dir.as_ref().map(|d| d.join(".git")),
    manifest_dir.as_ref().map(|d| d.join("..").join(".git")),
    Some(PathBuf::from(".git")),
    Some(PathBuf::from("../.git")),
  ];

  for candidate in candidate_dot_git_paths.iter().flatten() {
    if candidate.exists() && watch_git_head(candidate) {
      break;
    }
  }

  let hash = commit_hash();
  println!("cargo:rustc-env=COMMIT_HASH={}", hash);
}
