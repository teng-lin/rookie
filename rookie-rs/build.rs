use std::env;
use std::path::PathBuf;
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

fn main() {
  let manifest_dir = env::var("CARGO_MANIFEST_DIR").map(PathBuf::from).ok();

  let candidate_head_paths = [
    manifest_dir.as_ref().map(|d| d.join(".git").join("HEAD")),
    manifest_dir
      .as_ref()
      .map(|d| d.join("..").join(".git").join("HEAD")),
    Some(PathBuf::from(".git/HEAD")),
    Some(PathBuf::from("../.git/HEAD")),
  ];

  for candidate in candidate_head_paths.iter().flatten() {
    if candidate.exists() {
      println!("cargo:rerun-if-changed={}", candidate.display());
      break;
    }
  }

  let hash = commit_hash();
  println!("cargo:rustc-env=COMMIT_HASH={}", hash);
}
