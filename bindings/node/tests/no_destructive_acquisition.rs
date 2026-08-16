//! No exported Node function ever selects the crate's locked-database
//! process-shutdown policy: every Chromium extraction task built here uses
//! `ChromiumPathRequest`'s non-disruptive default and never calls
//! `.locked_database_policy(..)`. This scans the binding's own source from a
//! separate compilation unit, so a future change that wires up such a flag
//! has to touch this test, not silently add one.

const DESTRUCTIVE_TERMS: &[&str] = &[
  "force_kill",
  "locked_database_policy",
  "AllowProcessShutdown",
];

#[test]
fn node_binding_sources_never_reference_destructive_acquisition() {
  let source = include_str!("../src/lib.rs");
  for destructive_term in DESTRUCTIVE_TERMS {
    assert!(
      !source.contains(destructive_term),
      "src/lib.rs must never reference {destructive_term}"
    );
  }
}
