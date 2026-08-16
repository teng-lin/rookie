//! Defense-in-depth alongside `browsers::tests::chromium_path_options_never_expose_a_destructive_acquisition_key`:
//! that test only checks the `CHROMIUM_PATH_OPTION_KEYS` allowlist, which is
//! the only gate today because `ChromiumPathRequest` is built solely in
//! `browsers.rs`. This scans every other `.rs` file actually present under
//! `src/` at test time (not a hardcoded file list) — `browsers.rs` itself is
//! excluded because it legitimately names these terms in its own doc
//! comments and allowlist test — so a future destructive-acquisition call
//! added anywhere else in this crate has to touch this test, not silently
//! add one.

const DESTRUCTIVE_TERMS: &[&str] = &[
  "force_kill",
  "locked_database_policy",
  "AllowProcessShutdown",
];

#[test]
fn python_binding_sources_never_reference_destructive_acquisition() {
  let src_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
  let entries = std::fs::read_dir(src_dir).expect("read Python binding src directory");
  let mut scanned = 0;
  for entry in entries {
    let path = entry.expect("read Python binding src entry").path();
    if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
      continue;
    }
    if path.file_name().and_then(|name| name.to_str()) == Some("browsers.rs") {
      continue;
    }
    let source = std::fs::read_to_string(&path).expect("read Python binding source file");
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
    "expected to scan at least one Python binding source file"
  );
}
