//! No exported Node function ever selects the crate's locked-database
//! process-shutdown policy: every Chromium extraction task built here uses
//! `ChromiumPathRequest`'s non-disruptive default and never calls
//! `.locked_database_policy(..)`. This scans every `.rs` file actually
//! present under `src/` at test time (not a hardcoded file list), so a
//! future new source file wiring up such a flag has to touch this test, not
//! silently add one.

const DESTRUCTIVE_TERMS: &[&str] = &[
  "force_kill",
  "locked_database_policy",
  "AllowProcessShutdown",
];

#[test]
fn node_binding_sources_never_reference_destructive_acquisition() {
  let src_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
  let entries = std::fs::read_dir(src_dir).expect("read Node binding src directory");
  let mut scanned = 0;
  for entry in entries {
    let path = entry.expect("read Node binding src entry").path();
    if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
      continue;
    }
    let source = std::fs::read_to_string(&path).expect("read Node binding source file");
    for destructive_term in DESTRUCTIVE_TERMS {
      assert!(
        !source.contains(destructive_term),
        "{} must never reference {destructive_term}",
        path.display()
      );
    }
    scanned += 1;
  }
  assert!(
    scanned > 0,
    "expected to scan at least one Node binding source file"
  );
}
