# rookie-cookies

[![PyPI](https://img.shields.io/pypi/v/rookie-cookies?logo=python)](https://pypi.org/project/rookie-cookies/)
[![NPM Version](https://img.shields.io/npm/v/rookie-cookies?logo=npm&color=0076CE)](https://www.npmjs.com/package/rookie-cookies/)
[![Rust](https://img.shields.io/crates/v/rookie-cookies?logo=rust)](https://crates.io/crates/rookie-cookies/)
[![License](https://img.shields.io/github/license/teng-lin/rookie-cookies?logo=license)](MIT-LICENSE.txt)

`rookie-cookies` extracts cookies from local browser profiles through one shared
Rust core with first-class **Python**, **Node.js**, and **Rust** APIs (plus a
CLI). It is a maintained fork of the archived
[`thewh1teagle/rookie`](https://github.com/thewh1teagle/rookie) project.

Use it when an HTTP client, automation tool, or local script needs an authorized
browser session without asking the user to copy cookies by hand. A common
downstream consumer is
[`notebooklm-py`](https://github.com/teng-lin/notebooklm-py), which uses the
Python binding for optional browser-cookie authentication.

The tree currently builds as **0.6.0-alpha.x**. The docs below describe the
**0.6.0** API surface (recommended `read` / Python `jar`, per
[ADR 0004](docs/adr/0004-read-is-the-recommended-entry.md)).

## Security and privacy

This project reads local browser cookie databases. Cookies are credentials:
treat all output as secret, do not log it, and do not share extracted values.

On Windows, Chrome App-Bound Encryption can require elevated or host-process
access depending on the build and browser version. The library can decrypt the
local cookie database, but it does not implement Device Bound Session
Credentials (DBSC) or export browser private keys. A decrypted cookie may be
insufficient to reproduce a DBSC-protected browser session outside Chrome.

Only use this software with browser profiles and accounts you are authorized to
access.

## Install and recommended 0.6.0 entry

Pick the language binding you need. In every language the recommended job is an
unfiltered profile snapshot via `read` (Python also has `jar` =
`read(...).as_jar()`). Pass `profile` when you need **session cookies**; omitting
it keeps the legacy flat first-profile selection (persistent /
legacy-eligible cookies only).

There is **no** top-level binding `header()` and **no** crate-root Rust `get` or
`report` function. `ReadResult.header(url)` is a view over a snapshot you already
took.

### Python (CPython ≥ 3.11)

```console
pip install rookie-cookies
```

```python
import rookie_cookies as cookies

# Session import — pass profile= to include session cookies
session_jar = cookies.jar(browser="chrome", profile="Default")

# Domain-intact records (e.g. NotebookLM / Playwright storage_state)
rows = cookies.read(browser="chrome", profile="Work").as_list()
```

Named helpers such as `chrome()` remain supported compatibility APIs.
Published wheels use the `cp311-abi3` stable ABI tag (CPython 3.11–3.14 tested).

Full guide: [Python documentation](docs/python.md) (includes **0.5.6 API** and
**migrate 0.5.6 → 0.6.0**).

### Node.js (Node ≥ 22)

```console
npm install rookie-cookies
```

```javascript
import { read } from "rookie-cookies";

// Pass profile to include session cookies. Extraction is async — always await.
const snapshot = await read({ browser: "chrome", profile: "Default" });
console.log(snapshot.cookies, snapshot.warnings);
console.log(snapshot.header("https://example.com/"));
```

Named helpers such as `chrome()` remain supported and also return Promises.
CI and release artifacts are tested on Node.js 22, 24, and 26.

Full guide: [JavaScript documentation](docs/javascript.md) (includes **0.5.6
API** and **migrate 0.5.6 → 0.6.0**).

### Rust

```console
cargo add rookie-cookies
```

```rust
use rookie_cookies::{read, ReadRequest};

fn main() -> rookie_cookies::Result<()> {
    // Pass profile() to include session cookies.
    let snapshot = read(ReadRequest::browser("chrome").profile("Default"))?;
    for cookie in snapshot.cookies() {
        println!("{} {}", cookie.domain, cookie.name);
    }
    let header = snapshot.header("https://example.com/")?;
    let _ = header;
    Ok(())
}
```

Store helpers such as `browser("chrome", domains)` and `extract` remain
supported. Prefer `read` for session import jobs.

Full guide: [Rust documentation](docs/rust.md) (includes **0.5.6 API** and
**migrate 0.5.6 → 0.6.0**).

## CLI explicit paths

`--path` classifies Firefox or Chromium databases automatically. To select
Chromium credentials explicitly, add exactly one of `--browser-id`,
`--key-path`, or `--plaintext-only`. `--key-path` always means a Windows
Chromium `Local State` file in 0.6; no process-shutdown option is exposed.

```console
rookie-cookies --path /path/to/Cookies --browser-id chrome
rookie-cookies --path /path/to/cookies.sqlite
```

## Supported browsers

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

Registry-only browsers such as Cốc Cốc, DuckDuckGo, and Yandex are available
through the generic report/profile APIs and CLI report mode. Browser profile
discovery is platform-specific. Rust callers should use the typed
`direct_path::DirectPathRequest` or `direct_path::ChromiumPathRequest` builders
for explicit database paths. The legacy `*_based`, `any_browser`, and config
surfaces remain available through 0.6 and are deprecated for removal in 0.7;
see the language-specific documentation and examples.

## What this fork maintains

- Python 3.11–3.14 compatibility and automated tests.
- Rust, Python, Node.js, and CLI test coverage.
- Browser extraction tests using seeded Chrome and Firefox profiles.
- Chromium cookie formats including legacy `v10`/`v11` and newer `v20` values.
- Windows Chrome App-Bound Encryption support when built with the default
  `appbound` feature.
- Build and release documentation for downstream users.

Named browser helpers stay source-compatible with earlier 0.5.x call sites where
possible; new code should start from `read` / `jar`.

## Testing

Run the Rust workspace tests:

```console
cargo test --workspace --all-targets
cargo test --workspace --doc
```

Run the Python unit tests after building the extension in a virtual environment:

```console
python -m unittest discover -s tests/python -p 'test_*.py' -v
```

Real-browser E2E tests are defined in
[`.github/workflows/e2e.yml`](.github/workflows/e2e.yml). They seed disposable
Chrome and Firefox profiles on Ubuntu, macOS, and Windows and verify Rust,
Python, Node.js, and CLI extraction against the same cookie. See
[the testing guide](docs/testing.md) for the exact matrix and local commands.

## Documentation and examples

- [Python documentation](docs/python.md)
- [Rust documentation](docs/rust.md)
- [JavaScript documentation](docs/javascript.md)
- [Gotchas / operational notes](docs/general.md)
- [Build instructions](docs/building.md)
- [Testing guide](docs/testing.md)
- [Release instructions](docs/releasing.md)
- [Bundled SQLite security inventory](docs/sqlite-security.md)
- [Changelog](CHANGELOG.md)
- [ADR 0004: `read` is the recommended entry](docs/adr/0004-read-is-the-recommended-entry.md)
- [Python examples](examples/python)
- [Rust examples](examples/rust)
- [JavaScript examples](examples/javascript)

## Contributing

Please open issues and pull requests in
[this maintained fork](https://github.com/teng-lin/rookie-cookies). Include the
operating system, browser/version, language binding, and whether the browser was
running when the failure occurred. Never include real cookie values or browser
databases in an issue.

The project is released under the MIT license. See
[MIT-LICENSE.txt](MIT-LICENSE.txt).

## Credits

This fork preserves the original project’s history and license. It also builds
on ideas from [`browser_cookie3`](https://github.com/borisbabic/browser_cookie3).
