//! The CLI builds every `ChromiumPathRequest` from `--path`/`--key-path`/
//! `--browser-id`/`--plaintext-only` alone and never calls
//! `.locked_database_policy(..)`, so its requests stay at the crate's
//! non-disruptive default: no CLI flag can construct a destructive
//! (process-terminating) database acquisition. This scans the CLI's own
//! sources from a separate compilation unit, so a future change that wires
//! up such a flag has to touch this test, not silently add one.

const DESTRUCTIVE_TERMS: &[&str] = &[
  "force_kill",
  "locked_database_policy",
  "AllowProcessShutdown",
];

#[test]
fn cli_sources_never_reference_destructive_acquisition() {
  for (name, source) in [
    ("main.rs", include_str!("../src/main.rs")),
    ("args.rs", include_str!("../src/args.rs")),
    ("browsers_map.rs", include_str!("../src/browsers_map.rs")),
  ] {
    for destructive_term in DESTRUCTIVE_TERMS {
      assert!(
        !source.contains(destructive_term),
        "{name} must never reference {destructive_term}"
      );
    }
  }
}
