use std::path::Path;
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
  if Path::new(".git").exists() {
    println!("cargo:rerun-if-changed=.git/HEAD");
  }
  let hash = commit_hash();
  println!("cargo:rustc-env=COMMIT_HASH={}", hash);
}
