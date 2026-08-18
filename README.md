# rookie-cookies

[![PyPI](https://img.shields.io/pypi/v/rookie-cookies?logo=python)](https://pypi.org/project/rookie-cookies/)
[![NPM Version](https://img.shields.io/npm/v/rookie-cookies?logo=npm&color=0076CE)](https://www.npmjs.com/package/rookie-cookies/)
[![Rust](https://img.shields.io/crates/v/rookie-cookies?logo=rust)](https://crates.io/crates/rookie-cookies/)
[![License](https://img.shields.io/github/license/teng-lin/rookie-cookies?logo=license)](MIT-LICENSE.txt)


`rookie-cookies` is a maintained fork of the original [`thewh1teagle/rookie`](https://github.com/thewh1teagle/rookie) project. It extracts browser cookies through Rust, Python, and Node.js bindings under one shared package name.
This fork exists because the original repository is archived. Its immediate downstream consumer is [`notebooklm-py`](https://github.com/teng-lin/notebooklm-py), which uses the Python binding for optional browser-cookie authentication.

## What is maintained here

- Python 3.11–3.14 compatibility and automated tests.
- Rust, Python, Node.js, and CLI test coverage.
- Browser extraction tests using seeded Chrome and Firefox profiles.
- Chromium cookie formats including legacy `v10`/`v11` and newer `v20` values.
- Windows Chrome App-Bound Encryption support when built with the default `appbound` feature.
- Build and release documentation for downstream users.

The API remains compatible with the original project wherever possible.

## Security and privacy

This project reads local browser cookie databases. Cookies are credentials: treat all output as secret, do not log it, and do not share extracted values.

On Windows, Chrome App-Bound Encryption requires an elevated process for the App-Bound key path. The implementation can decrypt the local cookie database, but it does not implement Device Bound Session Credentials (DBSC) or export browser private keys. A decrypted cookie may therefore be insufficient to reproduce a DBSC-protected browser session outside Chrome.

Only use this software with browser profiles and accounts you are authorized to access.

## Python

Install the Python binding:

```console
pip install rookie-cookies
```

Use it to import a browser session, or to dump Domain-intact records:

```python
import rookie_cookies as cookies

# Happy path — session import (pass profile= to include session cookies)
session_jar = cookies.jar(browser="chrome", profile="Default")

# NotebookLM / Playwright storage_state — Domain-intact records
rows = cookies.read(browser="chrome", profile="Work").as_list()
```

Named helpers such as `chrome()` remain supported compatibility APIs.

The binding requires CPython 3.11 or newer and is tested on CPython 3.11–3.14.
Published wheels use the `cp311-abi3` stable ABI tag, so one wheel serves every
supported CPython version on each platform.

## Rust

```console
cargo add rookie-cookies anyhow
```

```rust
use rookie_cookies::browser;

fn main() -> anyhow::Result<()> {
    let cookies = browser("chrome", Some(vec!["example.com".to_string()]))?;
    for cookie in cookies {
        println!("{} {}", cookie.domain, cookie.name);
    }
    Ok(())
}
```

## Node.js

The npm packages require Node.js 22 or newer. CI and release artifacts are
tested on Node.js 22, 24, and 26; Node.js 18 and 20 are no longer supported.

```console
npm install rookie-cookies
```

```javascript
import { chrome } from "rookie-cookies";

const cookies = await chrome(["example.com"]);
console.log(cookies);
```

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

Real-browser E2E tests are defined in [`.github/workflows/e2e.yml`](.github/workflows/e2e.yml). They seed disposable Chrome and Firefox profiles on Ubuntu, macOS, and Windows and verify Rust, Python, Node.js, and CLI extraction against the same cookie. A separate strict Windows canary verifies default-profile App-Bound `v20` extraction from a live WAL, while the artifact-smoke workflow installs and runs the shipped CLI, wheel, and npm tarballs in clean consumer environments. See [the testing guide](docs/TESTING.md) for the exact matrix and local commands.

## Documentation and examples

- [Python documentation](docs/Python.md)
- [Rust documentation](docs/Rust.md)
- [JavaScript documentation](docs/JavaScript.md)
- [Build instructions](docs/BUILDING.md)
- [Testing guide](docs/TESTING.md)
- [Release instructions](docs/RELEASING.md)
- [Changelog](CHANGELOG.md)
- [Python examples](examples/python)
- [Rust examples](examples/rust)
- [JavaScript examples](examples/javascript)

## Contributing

Please open issues and pull requests in [this maintained fork](https://github.com/teng-lin/rookie-cookies). Include the operating system, browser/version, language binding, and whether the browser was running when the failure occurred. Never include real cookie values or browser databases in an issue.

The project is released under the MIT license. See [MIT-LICENSE.txt](MIT-LICENSE.txt).

## Credits

This fork preserves the original project’s history and license. It also builds on ideas from [`browser_cookie3`](https://github.com/borisbabic/browser_cookie3).
