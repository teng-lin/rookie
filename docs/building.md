# Build rookie-cookies

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (stable toolchain)
- CPython **3.11+** for the Python binding
- Node.js **22+** for the Node binding (use 22 for local native builds to match CI)

## Linux setup

```console
sudo apt-get install -y python3-dev
```

## Rust crate (`rookie-rs`)

```console
git clone https://github.com/teng-lin/rookie-cookies
cd rookie-cookies
cargo build -p rookie-cookies
```

## CLI

```console
cargo build -p rookie-cookies-cli --release
```

The binary lands under `target/release/` (exact crate package name follows the
workspace `cli/` manifest).

## Python bindings

Using [maturin](https://www.maturin.rs/):

```console
cd bindings/python
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip maturin
pip install .
```

For local development without packaging a wheel:

```console
cd bindings/python
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip maturin
maturin develop --release
```

## Node bindings

```console
cd bindings/node
npm ci
npm run build
```

This invokes `@napi-rs/cli` (pinned in `devDependencies`) to build the
platform-specific native module and emit `index.js` + `index.d.ts`. The
Node-API v4 module built on Node.js 22 is also tested on Node.js 24 and 26.

## Testing after a local build

```console
cargo test --workspace --all-targets
cargo test --workspace --doc
```

Python smoke after `maturin develop`:

```console
python -c "import rookie_cookies; print(rookie_cookies.version())"
```

Node smoke after `npm run build`:

```console
node -e "const r=require('./index.js'); console.log(r.version())"
```

Real-browser and artifact-smoke coverage is documented in
[testing.md](testing.md). Release publication steps live in
[releasing.md](releasing.md).
