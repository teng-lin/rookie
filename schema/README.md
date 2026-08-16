# schema/

`report-dto.schema.json` is the JSON Schema for `rookie-rs/src/browser/report_core.rs`'s
canonical report types (`ExtractionReport`, `BrowserDescriptor`, `Cookie`, and
friends) -- the "one schema" issue #241's typed-DTO workstream generates
Python's `bindings/python/rookie_cookies/dto.py` from, and Node's
`bindings/node/src/lib.rs` schema-parity test checks its hand-written
`#[napi(object)]` structs against.

`report_core.rs` is the source of truth; this file is generated from it, not
hand-edited. To regenerate after changing `report_core.rs`:

```console
cd rookie-rs
cargo run --bin generate-dto-schema --features dto-schema
cd ..
python3 scripts/generate-python-dto.py
```

The `dto-schema` Cargo feature is off by default (see `rookie-rs/Cargo.toml`)
so the CLI and the Python/Node bindings don't pull in `schemars` for a
capability they never call at runtime.
