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

/// Walks `scan_root` and returns, for every `.rs` file under it (in a
/// stable, sorted order, with a `/`-separated path relative to `root`),
/// every platform `cfg`/`cfg_attr` hit found in it (possibly empty).
///
/// Fails closed on every error, rather than skipping the offending file:
/// a walk error (e.g. a permission-denied subdirectory), a read error, or
/// a parse error would otherwise let a file silently drop out of the scan
/// -- exactly the kind of gap that would let an unallowlisted cfg slip
/// through undetected, in a tool whose entire purpose is to catch that.
fn scan_workspace(root: &Path, scan_root: &str) -> Result<Vec<(String, Vec<CfgHit>)>, String> {
  let scan_dir = root.join(scan_root);
  let mut files = Vec::new();
  for entry in walkdir::WalkDir::new(&scan_dir) {
    let entry = entry.map_err(|error| format!("failed to walk {}: {error}", scan_dir.display()))?;
    if entry.file_type().is_file() && entry.path().extension().is_some_and(|ext| ext == "rs") {
      files.push(entry.into_path());
    }
  }
  files.sort();

  let mut scanned = Vec::with_capacity(files.len());
  for path in files {
    let relative = path
      .strip_prefix(root)
      .map_err(|_| format!("{} is outside {}", path.display(), root.display()))?
      .to_string_lossy()
      .replace('\\', "/");
    let source = std::fs::read_to_string(&path)
      .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let hits = cfg_scan::scan_source(&source)
      .map_err(|error| format!("failed to parse {} as Rust source: {error}", path.display()))?;
    scanned.push((relative, hits));
  }

  if scanned.is_empty() {
    return Err(format!(
      "scanned zero .rs files under {} -- {scan_root} likely doesn't exist or repo_root() \
       resolved incorrectly",
      scan_dir.display()
    ));
  }

  Ok(scanned)
}

/// The result of comparing a scan against an allowlist: whether the
/// codebase is currently compliant, plus every diagnostic message to
/// print. Kept separate from `scan_workspace`/`Allowlist::load` (both of
/// which touch the filesystem) so this decision logic can be unit tested
/// against synthetic input without a real checkout on disk.
struct Report {
  ok: bool,
  notes: Vec<String>,
  errors: Vec<String>,
}

fn evaluate(
  scanned: &[(String, Vec<CfgHit>)],
  allowlist: &Allowlist,
  allowlist_file: &str,
) -> Report {
  let mut report = Report {
    ok: true,
    notes: Vec::new(),
    errors: Vec::new(),
  };

  // Every scanned file with a hit must be a Leaf, or within its
  // Grandfathered ceiling -- otherwise it's a new violation.
  for (path, hits) in scanned {
    if hits.is_empty() {
      continue;
    }
    match allowlist.verdict(path) {
      Verdict::Leaf => {}
      Verdict::Grandfathered { max_cfg } if hits.len() <= max_cfg => {}
      Verdict::Grandfathered { max_cfg } => {
        report.ok = false;
        report.errors.push(format!(
          "error: {path} has {} platform cfg hit(s), exceeding its grandfathered ceiling of \
           {max_cfg} in {allowlist_file}. Move the new cfg into a capability leaf, or if that \
           genuinely isn't possible yet, raise max_cfg with a one-line reason in the same PR.\n{}",
          hits.len(),
          render_hits(path, hits)
        ));
      }
      Verdict::Unlisted => {
        report.ok = false;
        report.errors.push(format!(
          "error: {path} has {} platform cfg hit(s) but is not in {allowlist_file}'s `leaves` \
           or `grandfathered` tables. See issue #218.\n{}",
          hits.len(),
          render_hits(path, hits)
        ));
      }
    }
  }

  // Separately, and regardless of whether a grandfathered file currently
  // has any hits at all: note every grandfathered entry whose ceiling no
  // longer matches reality, including a file that dropped to zero -- the
  // entry itself can be deleted then, which "consider lowering max_cfg"
  // alone would never say.
  for (path, entry) in &allowlist.grandfathered {
    let Some((_, hits)) = scanned
      .iter()
      .find(|(scanned_path, _)| scanned_path == path)
    else {
      continue; // stale entry, reported below
    };
    if hits.len() < entry.max_cfg {
      report.notes.push(if hits.is_empty() {
        format!(
          "note: {path} no longer has any platform cfg -- its grandfathered entry in \
           {allowlist_file} can be removed"
        )
      } else {
        format!(
          "note: {path} now has {} cfg hit(s), below its grandfathered ceiling of {} -- \
           consider lowering max_cfg in {allowlist_file}",
          hits.len(),
          entry.max_cfg
        )
      });
    }
  }

  let scanned_paths: Vec<String> = scanned.iter().map(|(path, _)| path.clone()).collect();
  for stale in allowlist.stale_paths(&scanned_paths) {
    report.ok = false;
    report.errors.push(format!(
      "error: {allowlist_file} lists {stale}, which no longer exists under {SCAN_ROOT} -- \
       remove the stale entry (the file was likely renamed or deleted)."
    ));
  }

  report
}

fn render_hits(path: &str, hits: &[CfgHit]) -> String {
  hits
    .iter()
    .map(|hit| format!("  {}:{}:{}  {}", path, hit.line, hit.column, hit.snippet))
    .collect::<Vec<_>>()
    .join("\n")
}

fn cmd_list_cfg_locations() -> Result<(), String> {
  let root = repo_root();
  let scanned = scan_workspace(&root, SCAN_ROOT)?;
  for (path, hits) in &scanned {
    if !hits.is_empty() {
      println!("{path}  ({} hit(s))", hits.len());
      println!("{}", render_hits(path, hits));
    }
  }
  Ok(())
}

fn cmd_check_cfg_locations() -> Result<bool, String> {
  let root = repo_root();
  let scanned = scan_workspace(&root, SCAN_ROOT)?;
  let allowlist = Allowlist::load(&root.join(ALLOWLIST_FILE))?;

  let report = evaluate(&scanned, &allowlist, ALLOWLIST_FILE);
  for note in &report.notes {
    println!("{note}");
  }
  for error in &report.errors {
    eprintln!("{error}");
  }
  Ok(report.ok)
}

fn main() {
  let mut args = std::env::args().skip(1);
  match args.next().as_deref() {
    Some("check-cfg-locations") => match cmd_check_cfg_locations() {
      Ok(true) => println!("Every platform cfg location is accounted for in {ALLOWLIST_FILE}."),
      Ok(false) => std::process::exit(1),
      Err(error) => {
        eprintln!("error: {error}");
        std::process::exit(1);
      }
    },
    Some("list-cfg-locations") => {
      if let Err(error) = cmd_list_cfg_locations() {
        eprintln!("error: {error}");
        std::process::exit(1);
      }
    }
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

#[cfg(test)]
mod tests {
  use super::*;

  fn hit(line: usize) -> CfgHit {
    CfgHit {
      line,
      column: 0,
      snippet: "#[cfg(target_os = \"windows\")]".to_owned(),
    }
  }

  fn allowlist(toml_text: &str) -> Allowlist {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("allowlist.toml");
    std::fs::write(&path, toml_text).expect("write fixture");
    // Leaked deliberately: the tempdir must outlive `Allowlist::load`, and
    // these are short-lived test-process-only fixtures.
    Allowlist::load(&path).expect("valid fixture allowlist")
  }

  const FIXTURE: &str = r#"
    [leaves]
    paths = ["a/leaf.rs"]

    [grandfathered]
    "a/core.rs" = { max_cfg = 2, reason = "test fixture" }
  "#;

  /// Every test below scans both `a/leaf.rs` and `a/core.rs` (FIXTURE's
  /// two allowlisted paths), even where a hit list is `[]`, so
  /// `stale_paths` doesn't fire for the one the test isn't focused on.
  #[test]
  fn leaf_passes_regardless_of_hit_count() {
    let scanned = vec![
      ("a/leaf.rs".to_owned(), vec![hit(1), hit(2), hit(3), hit(4)]),
      ("a/core.rs".to_owned(), vec![]),
    ];
    let report = evaluate(&scanned, &allowlist(FIXTURE), "allowlist.toml");
    assert!(report.ok, "errors: {:?}", report.errors);
    assert!(report.errors.is_empty());
  }

  #[test]
  fn grandfathered_at_the_ceiling_passes_without_a_note() {
    let scanned = vec![
      ("a/leaf.rs".to_owned(), vec![]),
      ("a/core.rs".to_owned(), vec![hit(1), hit(2)]),
    ];
    let report = evaluate(&scanned, &allowlist(FIXTURE), "allowlist.toml");
    assert!(report.ok, "errors: {:?}", report.errors);
    assert!(report.notes.is_empty(), "notes: {:?}", report.notes);
  }

  #[test]
  fn grandfathered_below_the_ceiling_passes_with_a_note() {
    let scanned = vec![
      ("a/leaf.rs".to_owned(), vec![]),
      ("a/core.rs".to_owned(), vec![hit(1)]),
    ];
    let report = evaluate(&scanned, &allowlist(FIXTURE), "allowlist.toml");
    assert!(report.ok, "errors: {:?}", report.errors);
    assert_eq!(report.notes.len(), 1, "notes: {:?}", report.notes);
  }

  #[test]
  fn grandfathered_at_zero_hits_suggests_removing_the_entry() {
    let scanned = vec![
      ("a/leaf.rs".to_owned(), vec![]),
      ("a/core.rs".to_owned(), vec![]),
    ];
    let report = evaluate(&scanned, &allowlist(FIXTURE), "allowlist.toml");
    assert!(report.ok, "errors: {:?}", report.errors);
    assert_eq!(report.notes.len(), 1);
    assert!(report.notes[0].contains("no longer has any platform cfg"));
  }

  #[test]
  fn grandfathered_above_the_ceiling_fails() {
    let scanned = vec![
      ("a/leaf.rs".to_owned(), vec![]),
      ("a/core.rs".to_owned(), vec![hit(1), hit(2), hit(3)]),
    ];
    let report = evaluate(&scanned, &allowlist(FIXTURE), "allowlist.toml");
    assert!(!report.ok);
    assert_eq!(report.errors.len(), 1);
    assert!(report.errors[0].contains("exceeding its grandfathered ceiling"));
  }

  #[test]
  fn unlisted_file_with_hits_fails() {
    let scanned = vec![
      ("a/leaf.rs".to_owned(), vec![]),
      ("a/core.rs".to_owned(), vec![]),
      ("a/unknown.rs".to_owned(), vec![hit(1)]),
    ];
    let report = evaluate(&scanned, &allowlist(FIXTURE), "allowlist.toml");
    assert!(!report.ok);
    assert!(report
      .errors
      .iter()
      .any(|error| error.contains("is not in")));
  }

  #[test]
  fn unlisted_file_with_no_hits_is_fine() {
    let scanned = vec![
      ("a/leaf.rs".to_owned(), vec![]),
      ("a/core.rs".to_owned(), vec![]),
      ("a/unknown.rs".to_owned(), vec![]),
    ];
    let report = evaluate(&scanned, &allowlist(FIXTURE), "allowlist.toml");
    assert!(report.ok, "errors: {:?}", report.errors);
  }

  #[test]
  fn stale_allowlist_entry_fails() {
    let scanned = vec![("a/leaf.rs".to_owned(), vec![])]; // a/core.rs missing from scan
    let report = evaluate(&scanned, &allowlist(FIXTURE), "allowlist.toml");
    assert!(!report.ok);
    assert!(report
      .errors
      .iter()
      .any(|error| error.contains("a/core.rs")));
  }

  #[test]
  fn scan_workspace_normalizes_paths_and_sorts_them() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("src/nested")).expect("mkdir");
    std::fs::write(dir.path().join("src/b.rs"), "fn b() {}").expect("write");
    std::fs::write(
      dir.path().join("src/nested/a.rs"),
      "#[cfg(unix)]\nfn a() {}",
    )
    .expect("write");
    std::fs::write(dir.path().join("src/not_rust.txt"), "ignored").expect("write");

    let scanned = scan_workspace(dir.path(), "src").expect("scan succeeds");
    let paths: Vec<&str> = scanned.iter().map(|(path, _)| path.as_str()).collect();
    assert_eq!(paths, vec!["src/b.rs", "src/nested/a.rs"]);
    assert!(scanned[1].1[0].snippet.contains("unix"));
  }

  #[test]
  fn scan_workspace_fails_closed_on_a_nonexistent_scan_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let error = scan_workspace(dir.path(), "src").expect_err("no such directory");
    assert!(
      error.contains("failed to walk"),
      "unexpected message: {error}"
    );
  }

  #[test]
  fn scan_workspace_fails_closed_on_a_scan_root_with_no_rust_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("src")).expect("mkdir");
    let error = scan_workspace(dir.path(), "src").expect_err("empty directory");
    assert!(error.contains("zero"), "unexpected message: {error}");
  }

  #[test]
  fn repo_root_resolves_to_the_workspace_root() {
    let root = repo_root();
    assert!(root.join("Cargo.toml").is_file());
    assert!(root.join(SCAN_ROOT).is_dir());
  }

  /// Exercises the full scan/load/evaluate pipeline against the real
  /// checkout. Deliberately does not assert on `report.ok`: whether the
  /// workspace currently passes the cfg-location check is a property of
  /// the checkout's current contents, not of this function -- asserting
  /// it here would make an unrelated source edit fail this test instead
  /// of `cargo run -p xtask -- check-cfg-locations`, which is where that
  /// signal belongs.
  #[test]
  fn cmd_check_cfg_locations_runs_against_the_real_repository() {
    cmd_check_cfg_locations().expect("scan and allowlist load must succeed against the real repo");
  }

  #[test]
  fn cmd_list_cfg_locations_runs_against_the_real_repository() {
    cmd_list_cfg_locations().expect("scan must succeed against the real repo");
  }

  #[test]
  fn scan_workspace_fails_closed_on_invalid_rust_source() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("src")).expect("mkdir");
    std::fs::write(dir.path().join("src/broken.rs"), "fn( invalid rust {{{").expect("write");

    let error = scan_workspace(dir.path(), "src").expect_err("unparseable file must not panic");
    assert!(
      error.contains("failed to parse"),
      "unexpected message: {error}"
    );
  }
}
