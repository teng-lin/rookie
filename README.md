# rookie-cookies

[![PyPI](https://img.shields.io/pypi/v/rookie-cookies?logo=python)](https://pypi.org/project/rookie-cookies/)
[![npm](https://img.shields.io/npm/v/rookie-cookies?logo=npm&color=0076CE)](https://www.npmjs.com/package/rookie-cookies/)
[![crates.io](https://img.shields.io/crates/v/rookie-cookies?logo=rust)](https://crates.io/crates/rookie-cookies/)
[![License](https://img.shields.io/github/license/teng-lin/rookie-cookies?logo=license)](LICENSE.md)

Cross-platform libraries and a CLI for reading cookies from browsers on your
machine. One Rust engine, bindings for **Python**, **Node.js**, and **Rust**,
and a `rookie-cookies` command-line tool. Linux, macOS, and Windows.

This is a maintained fork of
[`thewh1teagle/rookie`](https://github.com/thewh1teagle/rookie), which is
archived. We still ship that project's public call shapes (`chrome()`,
`firefox()`, `load()`, and friends) so existing consumers keep working.

That compatibility is a **bridge, not a promise**. New work should use the 0.6
job API (`read` / Python `jar`). Later releases will break the old surface as we
add capabilities and clean up the design. Plan on migrating; do not take the
legacy helpers as frozen forever.

The tree may still publish as `0.6.0-alpha.x`. The snippets below are the
**0.6.0** recommended surface.

## What is different from upstream rookie

We keep the old names working while the library grows past a bag of
per-browser functions:

- One recommended job (`read` / `jar`) instead of “call `chrome()` and hope”.
- Profile queries so session cookies are a deliberate choice.
- Structured reports, explicit-path builders, timeouts, and cancellation.
- Chromium formats through **legacy DPAPI**, **`v10` / `v11`**, and **App-Bound
  `v20`** where the host and browser allow it.
- Shared tests across Rust, Python, Node, and the CLI.

Those additions are why the old API will eventually go away rather than stay
the documented default.

## Platforms and browsers

| Browser | Linux | macOS | Windows |
| --- | :---: | :---: | :---: |
| Arc | ✓ | ✓ | ✓ |
| Brave | ✓ | ✓ | ✓ |
| Cachy | ✓ | — | — |
| Chrome | ✓ | ✓ | ✓ |
| Chromium | ✓ | ✓ | ✓ |
| Cốc Cốc | — | ✓ | ✓ |
| DuckDuckGo | — | — | ✓ |
| Edge | ✓ | ✓ | ✓ |
| Firefox | ✓ | ✓ | ✓ |
| Internet Explorer | — | — | ✓ |
| LibreWolf | ✓ | ✓ | ✓ |
| Octo Browser | — | — | ✓ |
| Opera | ✓ | ✓ | ✓ |
| Opera GX | — | ✓ | ✓ |
| Safari | — | ✓ | — |
| Vivaldi | ✓ | ✓ | ✓ |
| Yandex | — | ✓ | ✓ |
| Zen | ✓ | ✓ | ✓ |

`supported_browsers()` is the live registration list for the running OS (more
Windows Chromium forks exist in the registry than this table). Registry-only
browsers (Cốc Cốc, DuckDuckGo, Yandex, Avast, …) show up through report/profile
APIs and CLI report mode, not always as a named `coccoc()` helper. `*_based` /
`any_browser` still exist in 0.6 and are deprecated for 0.7.

### Cookie crypto (what `v10` / `v20` mean)

Chromium stores a prefix on each encrypted value. The names below are the
registry **decryption tiers** (`declared_decryption_tiers`), not marketing
labels.

| Tier | Where | What it is |
| --- | --- | --- |
| **legacy DPAPI** | Windows Chromium | Oldest Windows Chromium cookies: current-user DPAPI, no App-Bound wrapping. Still declared for every Windows Chromium browser in the registry. |
| **`v10`** | Windows, macOS, Linux Chromium | AES-GCM (Windows) or AES-CBC (Unix) values prefixed `v10`. Windows unwraps the AES key from `Local State` with DPAPI. macOS uses Keychain; Linux uses the OS crypt (often paired with `v11`). |
| **`v11`** | Linux Chromium | Same family as `v10`, prefixed `v11`, typically Secret Service / KWallet. |
| **App-Bound `v20`** | Windows Chrome-family | Chrome 133+ App-Bound Encryption (`APPB` key in `Local State`, values prefixed `v20`). Needs the default `appbound` feature. Decrypts via COM injection into a spawned browser process, with elevated SYSTEM impersonation as fallback. Hosted canaries: Chrome, Edge, Brave. Also declared for Cốc Cốc and Avast. |
| **(none)** | Gecko, Safari, IE | Firefox / LibreWolf / Zen / Cachy: plaintext `cookies.sqlite` plus session JSON. Safari: `Cookies.binarycookies` (Full Disk Access). IE: ESE WebCache — functions exist in 0.6 and are deprecated. |

Windows Chromium at a glance:

| Windows browser | legacy DPAPI | `v10` | App-Bound `v20` |
| --- | :---: | :---: | :---: |
| Chrome, Edge, Brave | ✓ | ✓ | ✓ |
| Cốc Cốc, Avast | ✓ | ✓ | ✓ (library; not in the hosted canary matrix) |
| Arc, Chromium, Opera, Opera GX, Vivaldi, Yandex, DuckDuckGo, Octo, … | ✓ | ✓ | — |

A green **legacy DPAPI `v10`** extraction does **not** mean `v20` works. `v20`
may need elevation or a live host process; this project does not implement
Device Bound Session Credentials (DBSC). Coverage details:
[docs/testing.md](docs/testing.md).

Linux Chromium is `v10` + `v11` (libsecret / KWallet). macOS Chromium is `v10`
via Keychain. Gecko is the same sqlite/session layout on all three OSes.

## Install

| Language | Requirement | Command |
| --- | --- | --- |
| Python | CPython ≥ 3.11 | `pip install rookie-cookies` |
| Node.js | Node ≥ 22 | `npm install rookie-cookies` |
| Rust | edition 2021 crate | `cargo add rookie-cookies` |
| CLI | same repo / release binaries | `rookie-cookies --help` |

## Recommended 0.6 usage

Pass a **profile** when you want session cookies. Omit it to match the old
first-profile, persistent-only helpers. `read` never URL-filters the snapshot;
`ReadResult.header(url)` is a view. There is no top-level binding `header()`,
and no crate-root Rust `get` / `report`.

### Python

```python
import rookie_cookies as cookies

session_jar = cookies.jar(browser="chrome", profile="Default")
rows = cookies.read(browser="chrome", profile="Work").as_list()
```

### Node.js

```javascript
import { read } from "rookie-cookies";

const snapshot = await read({ browser: "chrome", profile: "Default" });
console.log(snapshot.cookies, snapshot.header("https://example.com/"));
```

Extraction is async. Always `await`.

### Rust

```rust
use rookie_cookies::{read, ReadRequest};

fn main() -> rookie_cookies::Result<()> {
    let snapshot = read(ReadRequest::browser("chrome").profile("Default"))?;
    println!("{}", snapshot.header("https://example.com/")?);
    Ok(())
}
```

### CLI

```console
rookie-cookies --path /path/to/cookies.sqlite
rookie-cookies --path /path/to/Cookies --browser-id chrome
```

Chromium credential flags (`--browser-id`, `--key-path`, `--plaintext-only`)
require `--path` and are mutually exclusive. `--key-path` is a Windows
`Local State` file.

Coming from 0.5.6 named helpers? Each language guide has a **0.5.6 API**
section and a **migrate 0.5.6 → 0.6.0** section:
[python](bindings/python/README.md) · [javascript](bindings/node/README.md) · [rust](rookie-rs/README.md).

## Security

Extracted cookies are credentials. Do not log them, commit them, or paste them
into issues. Use only profiles and accounts you are allowed to access.

On Windows, App-Bound `v20` may need elevated or host-process access.
This project does not implement Device Bound Session Credentials (DBSC) and
does not export browser private keys. A decrypted cookie is not always enough
to replay a protected Chrome session.

Platform quirks (Keychain prompts, Safari Full Disk Access):
[docs/troubleshooting.md](docs/troubleshooting.md).

## Documentation

| | |
| --- | --- |
| Language guides | [python](bindings/python/README.md) · [javascript](bindings/node/README.md) · [rust](rookie-rs/README.md) |
| Build / test / release | [building](docs/building.md) · [testing](docs/testing.md) · [releasing](docs/releasing.md) |
| Troubleshooting | [docs/troubleshooting.md](docs/troubleshooting.md) |
| Security | [docs/security.md](docs/security.md) (corrections + SQLite inventory) |
| Design | [ADR 0004](docs/adr/0004-read-is-the-recommended-entry.md) · [changelog](CHANGELOG.md) |
| Examples | [python](examples/python) · [javascript](examples/javascript) · [rust](examples/rust) |

```console
cargo test --workspace --all-targets
python3 scripts/check-doc-snippets.py
```

Issues and PRs: [teng-lin/rookie-cookies](https://github.com/teng-lin/rookie-cookies).
Say which OS, browser, and binding you used. Never attach real cookies or
database files.

## Credits

- [`thewh1teagle/rookie`](https://github.com/thewh1teagle/rookie) — original
  library, history, and MIT license this fork continues.
- [`moond4rk/HackBrowserData`](https://github.com/moond4rk/HackBrowserData) —
  research and implementation ideas around multi-browser cookie and credential
  extraction on Windows, macOS, and Linux.

Also indebted to [`browser_cookie3`](https://github.com/borisbabic/browser_cookie3).

## License

[MIT](LICENSE.md).
