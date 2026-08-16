//! Dev-only workspace tooling. Not a dependency of any published crate --
//! see the root `Cargo.toml`'s `members` (not `default-members`) entry.

mod allowlist;
mod cfg_scan;

use allowlist::{Allowlist, Verdict};
use cfg_scan::CfgHit;
use std::path::{Path, PathBuf};

const SCAN_ROOT: &str = "rookie-rs/src";
const ALLOWLIST_FILE: &str = "cfg-location-allowlist.toml";

fn repo_root() -> PathBuf {
  Path::new(env!("CARGO_MANIFEST_DIR"))
    .join("..")
    .canonicalize()
    .expect("xtask's parent directory is the repo root")
}

/// Walks `SCAN_ROOT` and returns, for every `.rs` file (in a stable,
/// sorted order), its path relative to the repo root and every platform
/// `cfg`/`cfg_attr` hit found in it (possibly empty).
fn scan_workspace(root: &Path) -> Vec<(String, Vec<CfgHit>)> {
  let scan_dir = root.join(SCAN_ROOT);
  let mut files: Vec<PathBuf> = walkdir::WalkDir::new(&scan_dir)
    .into_iter()
    .filter_map(Result::ok)
    .filter(|entry| entry.file_type().is_file())
    .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "rs"))
    .map(walkdir::DirEntry::into_path)
    .collect();
  files.sort();

  files
    .into_iter()
    .map(|path| {
      let relative = path
        .strip_prefix(root)
        .expect("scanned path is under repo root")
        .to_string_lossy()
        .replace('\\', "/");
      let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
      let hits = cfg_scan::scan_source(&source).unwrap_or_else(|error| {
        panic!("failed to parse {} as Rust source: {error}", path.display())
      });
      (relative, hits)
    })
    .collect()
}

fn cmd_list_cfg_locations() {
  let root = repo_root();
  let scanned = scan_workspace(&root);
  for (path, hits) in &scanned {
    if !hits.is_empty() {
      println!("{path}  ({} hit(s))", hits.len());
      for hit in hits {
        println!("  {}:{}:{}  {}", path, hit.line, hit.column, hit.snippet);
      }
    }
  }
}

fn cmd_check_cfg_locations() -> bool {
  let root = repo_root();
  let scanned = scan_workspace(&root);

  let allowlist_path = root.join(ALLOWLIST_FILE);
  let allowlist = match Allowlist::load(&allowlist_path) {
    Ok(allowlist) => allowlist,
    Err(error) => {
      eprintln!("error: {error}");
      return false;
    }
  };

  let mut ok = true;

  for (path, hits) in &scanned {
    if hits.is_empty() {
      continue;
    }
    match allowlist.verdict(path) {
      Verdict::Leaf => {}
      Verdict::Grandfathered { max_cfg } if hits.len() <= max_cfg => {
        if hits.len() < max_cfg {
          println!(
            "note: {path} now has {} cfg hit(s), below its grandfathered ceiling of {max_cfg} -- \
             consider lowering max_cfg in {ALLOWLIST_FILE}",
            hits.len()
          );
        }
      }
      Verdict::Grandfathered { max_cfg } => {
        ok = false;
        eprintln!(
          "error: {path} has {} platform cfg hit(s), exceeding its grandfathered ceiling of \
           {max_cfg} in {ALLOWLIST_FILE}. Move the new cfg into a capability leaf, or if that \
           genuinely isn't possible yet, raise max_cfg with a one-line reason in the same PR.",
          hits.len()
        );
        for hit in hits {
          eprintln!("  {}:{}:{}  {}", path, hit.line, hit.column, hit.snippet);
        }
      }
      Verdict::Unlisted => {
        ok = false;
        eprintln!(
          "error: {path} has {} platform cfg hit(s) but is not in {ALLOWLIST_FILE}'s `leaves` \
           or `grandfathered` tables. See issue #218.",
          hits.len()
        );
        for hit in hits {
          eprintln!("  {}:{}:{}  {}", path, hit.line, hit.column, hit.snippet);
        }
      }
    }
  }

  let scanned_paths: Vec<String> = scanned.iter().map(|(path, _)| path.clone()).collect();
  for stale in allowlist.stale_paths(&scanned_paths) {
    ok = false;
    eprintln!(
      "error: {ALLOWLIST_FILE} lists {stale}, which no longer exists under {SCAN_ROOT} -- \
       remove the stale entry (the file was likely renamed or deleted)."
    );
  }

  ok
}

fn main() {
  let mut args = std::env::args().skip(1);
  match args.next().as_deref() {
    Some("check-cfg-locations") => {
      if !cmd_check_cfg_locations() {
        std::process::exit(1);
      }
      println!("Every platform cfg location is accounted for in {ALLOWLIST_FILE}.");
    }
    Some("list-cfg-locations") => cmd_list_cfg_locations(),
    Some(other) => {
      eprintln!("error: unknown xtask subcommand {other:?}");
      eprintln!("usage: cargo run -p xtask -- <check-cfg-locations|list-cfg-locations>");
      std::process::exit(2);
    }
    None => {
      eprintln!("usage: cargo run -p xtask -- <check-cfg-locations|list-cfg-locations>");
      std::process::exit(2);
    }
  }
}
