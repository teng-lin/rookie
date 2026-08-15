# Build rookie-cookies

## Prerequisites

[Rust](https://www.rust-lang.org/tools/install)

## Linux setup

```console
sudo apt-get install -y python3-dev
```

## rookie-rs

```console
git clone https://github.com/teng-lin/rookie-cookies
cd rookie-cookies/rookie-rs
cargo build
```

## cli

```console
git clone https://github.com/teng-lin/rookie-cookies
cd rookie-cookies/cli
cargo build --release
```

## Python Bindings

Using [maturin](https://pyo3.rs/main/#usage):

```console
git clone https://github.com/teng-lin/rookie-cookies
cd rookie-cookies/bindings/python
python3 -m venv venv
source venv/bin/activate
# Install dependencies + build + install
# May take some time on first use
pip3 install .
```

For local development without an editable install:

```console
cd bindings/python
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip maturin
maturin develop --release
```

## Node Bindings

Node.js 22 or newer is required. Use Node.js 22 for local native builds to
match CI; the resulting Node-API v4 module is also tested on Node.js 24 and 26.

```console
cd bindings/node
npm ci
npm run build
```

This invokes `@napi-rs/cli` (already pinned in `devDependencies`) to build the
platform-specific native module and emit `index.js` + `index.d.ts`.

## Testing

The Rust workspace ships unit tests, integration tests, and doctests. They all
run on every PR via the `test-rust.yml` workflow:

```console
cargo test --workspace --all-targets
cargo test --workspace --doc
```

A real-browser end-to-end suite runs under `.github/workflows/e2e.yml` and
exercises rookie-cookies' Rust API, Python binding, Node binding, and CLI against
the same seeded Chrome or Firefox profile on Ubuntu, macOS, and Windows. Windows
has distinct legacy-DPAPI and strict default-profile App-Bound `v20` lanes.
Installed CLI, wheel, and npm tarballs are independently exercised by
`.github/workflows/artifact-smoke.yml`. See `docs/TESTING.md` for the exact
required/scheduled matrix, security invariants, and local commands.

Python bindings can be smoke-tested after `maturin develop`:

```console
python -c "import rookie_cookies; print(dir(rookie_cookies))"
```

Node bindings can be smoke-tested after `npm run build`:

```console
node -e "console.log(Object.keys(require('./index.js')))"
```

## Draft new release

```console
gh release create v<tag>
```
