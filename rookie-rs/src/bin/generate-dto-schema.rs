//! Dumps the JSON Schema for `rookie_cookies::report`'s wire types.
//!
//! `report_core.rs` is already the frozen cross-engine report contract; this
//! binary is the "one schema" workstream B (issue #241) generates typed
//! Python/Node DTOs from, so the schema and the Rust types it's generated
//! from can never drift apart the way Node's hand-duplicated `#[napi(object)]`
//! structs already have. Run with `cargo run --bin generate-dto-schema
//! --features dto-schema` from `rookie-rs/`; writes to
//! `../schema/report-dto.schema.json` by default, or to the path given as
//! the first argument. `dto-schema` is off by default and gates the
//! `JsonSchema` derives themselves, not just this binary, so the CLI and
//! the Python/Node bindings don't pull in `schemars` for a capability they
//! never call.

use rookie_cookies::enums::Cookie;
use rookie_cookies::report::{
  BrowserCapabilitiesDescriptor, BrowserDescriptor, CookieSourceDescriptor, CookieSourceIdentity,
  ExtractionIssue, ExtractionReport, ExtractionStats, ProfileDescriptor, ProfileExtraction,
  ProfileIdentity, ReportStats, SourceExtraction,
};
use schemars::gen::{SchemaGenerator, SchemaSettings};
use schemars::Map;
use serde_json::{json, Value};
use std::env;
use std::fs;
use std::path::PathBuf;

/// Top-level shapes a binding generates a typed class for. Every other type
/// referenced from these (identifiers, nested descriptors) lands in
/// `definitions` because `SchemaGenerator::subschema_for` collects them
/// there automatically.
fn root_definitions(generator: &mut SchemaGenerator) -> Map<String, Value> {
  let mut roots = Map::new();
  roots.insert(
    "Cookie".to_owned(),
    schema_value(generator.subschema_for::<Cookie>()),
  );
  roots.insert(
    "BrowserDescriptor".to_owned(),
    schema_value(generator.subschema_for::<BrowserDescriptor>()),
  );
  roots.insert(
    "ProfileDescriptor".to_owned(),
    schema_value(generator.subschema_for::<ProfileDescriptor>()),
  );
  roots.insert(
    "ExtractionReport".to_owned(),
    schema_value(generator.subschema_for::<ExtractionReport>()),
  );
  // Referenced from the roots above but also useful as standalone request
  // building blocks for a binding's typed layer.
  roots.insert(
    "ProfileExtraction".to_owned(),
    schema_value(generator.subschema_for::<ProfileExtraction>()),
  );
  roots.insert(
    "SourceExtraction".to_owned(),
    schema_value(generator.subschema_for::<SourceExtraction>()),
  );
  roots.insert(
    "ExtractionIssue".to_owned(),
    schema_value(generator.subschema_for::<ExtractionIssue>()),
  );
  roots.insert(
    "CookieSourceDescriptor".to_owned(),
    schema_value(generator.subschema_for::<CookieSourceDescriptor>()),
  );
  roots.insert(
    "CookieSourceIdentity".to_owned(),
    schema_value(generator.subschema_for::<CookieSourceIdentity>()),
  );
  roots.insert(
    "ProfileIdentity".to_owned(),
    schema_value(generator.subschema_for::<ProfileIdentity>()),
  );
  roots.insert(
    "BrowserCapabilitiesDescriptor".to_owned(),
    schema_value(generator.subschema_for::<BrowserCapabilitiesDescriptor>()),
  );
  roots.insert(
    "ExtractionStats".to_owned(),
    schema_value(generator.subschema_for::<ExtractionStats>()),
  );
  roots.insert(
    "ReportStats".to_owned(),
    schema_value(generator.subschema_for::<ReportStats>()),
  );
  roots
}

fn schema_value(schema: schemars::schema::Schema) -> Value {
  serde_json::to_value(schema).expect("schema serializes to JSON")
}

/// Recursively removes `enum`/`const` constraints from `schema` and every
/// nested schema reachable through `properties`, `items`, and
/// `additionalProperties`. See the call site in `main` for why.
fn strip_enum_and_const(schema: &mut Value) {
  let Some(object) = schema.as_object_mut() else {
    return;
  };
  object.remove("enum");
  object.remove("const");
  if let Some(properties) = object.get_mut("properties").and_then(Value::as_object_mut) {
    for property in properties.values_mut() {
      strip_enum_and_const(property);
    }
  }
  if let Some(items) = object.get_mut("items") {
    strip_enum_and_const(items);
  }
  if let Some(additional) = object.get_mut("additionalProperties") {
    strip_enum_and_const(additional);
  }
}

fn main() {
  let mut generator = SchemaSettings::draft07().into_generator();
  let roots = root_definitions(&mut generator);

  let mut definitions: Map<String, Value> = generator
    .definitions()
    .iter()
    .map(|(name, schema)| (name.clone(), schema_value(schema.clone())))
    .collect();
  // Open identifiers are validated snake_case strings, deliberately not a
  // closed enum -- see report_core.rs. Strip any `enum`/`const` constraint
  // schemars may have inferred so a generated DTO class stays forward
  // compatible with values this build has never heard of. Every open
  // identifier today is a `#[serde(transparent)]` newtype that schemars
  // inlines as a bare `{"type": "string"}` with nothing nested underneath,
  // so a shallow strip would happen to be enough right now -- but strip
  // recursively anyway, so a future report field backed by a real Rust
  // `enum`, or a nested inlined type, can't silently smuggle a closed
  // `enum`/`const` constraint into the generated schema.
  for schema in definitions.values_mut() {
    strip_enum_and_const(schema);
  }

  let document = json!({
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$comment": "Generated by `cargo run --bin generate-dto-schema` from rookie-rs/src/browser/report_core.rs. Do not hand-edit -- see that file for the source of truth and schema/README.md for regeneration instructions.",
    "title": "rookie-cookies report DTO schema",
    "roots": roots,
    "definitions": definitions,
  });

  let output_path = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
    // CARGO_MANIFEST_DIR (set at compile time) rather than a CWD-relative
    // path, so the default works regardless of which directory `cargo run`
    // was invoked from -- only explicit invocations from `rookie-rs/` (see
    // the module doc above) got this right before.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../schema/report-dto.schema.json")
  });
  let rendered = serde_json::to_string_pretty(&document).expect("document serializes to JSON");
  fs::write(&output_path, rendered + "\n")
    .unwrap_or_else(|error| panic!("failed to write {}: {error}", output_path.display()));
  eprintln!("wrote {}", output_path.display());
}
