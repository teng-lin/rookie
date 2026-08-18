# Build rookie-cookies

One workspace, four artifacts: the `rookie-cookies` crate, the
`rookie-cookies` CLI (`rookie-cookies-cli` package), the Python cdylib, and
the Node-API addon.

## Prerequisites

| You want | Need |
| --- | --- |
| Rust crate / CLI | Stable Rust ([rustup](https://www.rust-lang.org/tools/install)) |
| Python binding | CPython **≥ 3.11**, [maturin](https://www.maturin.rs/) (CI pins **1.14.1**) |
| Node binding | Node.js **≥ 22** (build the native module on **22** to match CI) |
| Linux | `python3-dev`, `libdbus-1-dev`, `dbus` (zbus / Secret Service). E2E also wants `gnome-keyring`, `libsecret-tools`, `xvfb`. |
| Windows | MSVC (`x86_64-pc-windows-msvc`). Default **`appbound`** feature pulls the App-Bound / v20 path. |
| macOS | Xcode CLT. Keychain E2E uses `/usr/bin/security`. |

```console
# Debian/Ubuntu
sudo apt-get install -y python3-dev libdbus-1-dev dbus
```

## Features

`rookie-cookies` (the crate) defaults to `appbound`. That feature only changes
Windows: Chrome-family **v20 / App-Bound** decryption (Chrome, Edge, Brave,
Cốc Cốc, Avast) via COM injection into a spawned browser process, with
elevated SYSTEM impersonation as fallback.

- **Python** and **Node** bindings enable `appbound` automatically on Windows
  (`cfg(windows)`). Unix builds leave it off.
- **CLI** default features include `appbound`. Release Windows artifacts pass
  `--features appbound` explicitly (`artifact-smoke.yml`, publish workflows).
- To compile the legacy non-App-Bound Windows branch:
  `cargo test -p rookie-cookies --no-default-features`.

`dto-schema` is only for `cargo run -p rookie-cookies --bin generate-dto-schema`.

## Rust crate

```console
git clone https://github.com/teng-lin/rookie-cookies
cd rookie-cookies
cargo build -p rookie-cookies --locked
cargo test -p rookie-cookies --all-targets --locked
```

Examples live under `rookie-rs/examples/` (`simple`, `from_path`,
`detailed_from_path`, `report_surface`). `cargo package -p rookie-cookies`
must keep shipping those plus `browser_registry.json`.

## CLI

```console
cargo build -p rookie-cookies-cli --release --locked
# binary: target/release/rookie-cookies  (target/release/rookie-cookies.exe on Windows)
```

Windows release builds that must decrypt v20 should keep default features
(or pass `--features appbound`). See [testing.md](testing.md) for the
Chrome / Edge / Brave canary that exercises that binary.

## Python binding

```console
cd bindings/python
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install --upgrade pip 'maturin==1.14.1'
maturin develop --release --locked
python -c "import rookie_cookies; print(rookie_cookies.version())"
```

Wheel (same as CI):

```console
maturin build --release --locked --out ../../dist
```

`requires-python = ">=3.11"`; the extension is `abi3-py311`.

## Node binding

Build on Node.js 22. **Omit optionalDependencies** so `npm ci` does not
install a published `rookie-cookies-<platform>` prebuild that can shadow the
addon you just compiled (those older tarballs may not export `read` /
`ReadResult`).

```console
cd bindings/node
npm ci --omit=optional
npm run build -- --cargo-flags=--locked
node -e "const m=require('./index.js'); console.log(m.version(), typeof m.read)"
```

`npm run build` uses `@napi-rs/cli` (pinned in `devDependencies`) and
`scripts/patch-loader.js`. After a generator bump, `index.js` / `index.d.ts`
must stay in lockstep (`git diff` is a CI gate).

The Node-API **v4** `.node` built on 22 is then tested on 24 and 26 without
rebuilding.

## After a local build

```console
cargo test --workspace --all-targets --locked
cargo test --workspace --doc --locked
```

Real browsers (libsecret / Keychain / DPAPI `v10`) and the elevated Windows
**v20** canary for **Chrome, Edge, and Brave** are documented in
[testing.md](testing.md). Do not assume `cargo test` covered them.

The crate **bundles** SQLite (`rusqlite` / `libsqlite3-sys`); it does not use
the host library. Locked versions, source ID, and the 90-day review policy:
[sqlite-security.md](sqlite-security.md). Do not change those pins as part of
an ordinary local build.

Publish steps: [releasing.md](releasing.md).
