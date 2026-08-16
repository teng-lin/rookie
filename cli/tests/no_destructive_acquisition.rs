//! The CLI builds every `ChromiumPathRequest` from `--path`/`--key-path`/
//! `--browser-id`/`--plaintext-only` alone and never calls
//! `.locked_database_policy(..)`, so its requests stay at the crate's
//! non-disruptive default: no CLI flag can construct a destructive
//! (process-terminating) database acquisition. This scans every `.rs` file
//! actually present under `src/` at test time (not a hardcoded file list),
//! so a future new source file wiring up such a flag has to touch this
//! test, not silently add one.

const DESTRUCTIVE_TERMS: &[&str] = &[
  "force_kill",
  "locked_database_policy",
  "AllowProcessShutdown",
];

#[test]
fn cli_sources_never_reference_destructive_acquisition() {
  let src_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
  let entries = std::fs::read_dir(src_dir).expect("read CLI src directory");
  let mut scanned = 0;
  for entry in entries {
    let path = entry.expect("read CLI src entry").path();
    if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
      continue;
    }
    let source = std::fs::read_to_string(&path).expect("read CLI source file");
    for destructive_term in DESTRUCTIVE_TERMS {
      assert!(
        !source.contains(destructive_term),
        "{} must never reference {destructive_term}",
        path.display()
      );
    }
    scanned += 1;
  }
  assert!(scanned > 0, "expected to scan at least one CLI source file");
}
