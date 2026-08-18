# rookie-cookies

[![PyPI](https://img.shields.io/pypi/v/rookie-cookies?logo=python)](https://pypi.org/project/rookie-cookies/)
[![NPM Version](https://img.shields.io/npm/v/rookie-cookies?logo=npm&color=0076CE)](https://www.npmjs.com/package/rookie-cookies/)
[![Rust](https://img.shields.io/crates/v/rookie-cookies?logo=rust)](https://crates.io/crates/rookie-cookies/)
[![License](https://img.shields.io/github/license/teng-lin/rookie-cookies?logo=license)](MIT-LICENSE.txt)

Load cookies from local browser profiles into your HTTP client, automation
stack, or scripts — without copying values by hand.

`rookie-cookies` is a maintained fork of the archived
[`thewh1teagle/rookie`](https://github.com/thewh1teagle/rookie) project. One Rust
core powers **Python**, **Node.js**, **Rust**, and a **CLI** under the same
package name. A common downstream consumer is
[`notebooklm-py`](https://github.com/teng-lin/notebooklm-py).

> **Version note.** This tree may still build as `0.6.0-alpha.x`. The guides
> describe the **0.6.0** API surface. The recommended entry is `read` (Python
> also has `jar`), per
> [ADR 0004](docs/adr/0004-read-is-the-recommended-entry.md).

## Quick start (0.6.0)

In every language the happy path is an **unfiltered profile snapshot**:

| Goal | Do this |
| --- | --- |
| Import a browser session (incl. session cookies) | Call `read` / `jar` **with** `profile` |
| Match legacy `chrome()` / flat first-profile behavior | Call `read` **without** `profile`, or keep the named helper |
| Build a `Cookie` request header | `snapshot.header(url)` — there is **no** top-level `header()` |
| Rust crate-root helpers to avoid | Do **not** expect crate-root `get` or `report` |

### Python — CPython ≥ 3.11

```console
pip install rookie-cookies
```

```python
import rookie_cookies as cookies

# Session import (pass profile= for session cookies)
session_jar = cookies.jar(browser="chrome", profile="Default")

# Domain-intact records (NotebookLM / Playwright storage_state, allowlists)
rows = cookies.read(browser="chrome", profile="Work").as_list()
header = cookies.read(browser="chrome", profile="Default").header(
    "https://example.com/"
)
```

Wheels are `cp311-abi3` (tested on CPython 3.11–3.14). Named helpers such as
`chrome()` remain compatibility APIs.

→ Full guide: [docs/python.md](docs/python.md) (includes **0.5.6 API** and
**migrate 0.5.6 → 0.6.0**).

### Node.js — Node ≥ 22

```console
npm install rookie-cookies
```

```javascript
import { read } from "rookie-cookies";

// Always await. Pass profile for session cookies.
const snapshot = await read({ browser: "chrome", profile: "Default" });
console.log(snapshot.cookies, snapshot.warnings);
console.log(snapshot.header("https://example.com/"));
```

CI and release artifacts are tested on Node.js 22, 24, and 26. Named helpers
such as `chrome()` also return Promises.

→ Full guide: [docs/javascript.md](docs/javascript.md) (includes **0.5.6 API**
and **migrate 0.5.6 → 0.6.0**).

### Rust

```console
cargo add rookie-cookies
```

```rust
use rookie_cookies::{read, ReadRequest};

fn main() -> rookie_cookies::Result<()> {
    let snapshot = read(ReadRequest::browser("chrome").profile("Default"))?;
    for cookie in snapshot.cookies() {
        println!("{} {}", cookie.domain, cookie.name);
    }
    let header = snapshot.header("https://example.com/")?;
    let _ = header;
    Ok(())
}
```

Prefer `read` for session import. `browser(id, domains)` / `extract` remain for
flat, domain-filtered compatibility lists.

→ Full guide: [docs/rust.md](docs/rust.md) (includes **0.5.6 API** and
**migrate 0.5.6 → 0.6.0**).

## CLI

```console
# Auto-classify Firefox or Chromium databases
rookie-cookies --path /path/to/cookies.sqlite
rookie-cookies --path /path/to/Cookies --browser-id chrome
```

For Chromium credentials, pass exactly one of `--browser-id`, `--key-path`, or
`--plaintext-only` with `--path`. In 0.6, `--key-path` always means a Windows
Chromium `Local State` file. See [docs/general.md](docs/general.md) for platform
gotchas.

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

Registry-only browsers (for example Cốc Cốc, DuckDuckGo, Yandex) are reached
through the generic report/profile APIs and CLI report mode. Legacy `*_based` /
`any_browser` helpers remain through 0.6 and are deprecated for removal in 0.7.

## Security and privacy

Cookies are credentials. Treat all extracted values as secret: do not log them,
commit them, or paste them into issues.

The library reads local browser databases. On Windows, App-Bound Encryption may
require elevated or host-process access depending on browser and build. The
implementation can decrypt cookie values it is allowed to read; it does **not**
implement Device Bound Session Credentials (DBSC) or export browser private
keys. A decrypted cookie may be insufficient to reproduce a DBSC-protected
session outside Chrome.

Only use profiles and accounts you are authorized to access.

## Documentation map

| Doc | Contents |
| --- | --- |
| [docs/python.md](docs/python.md) | Python 0.6 usage, 0.5.6 API, migration |
| [docs/javascript.md](docs/javascript.md) | Node 0.6 usage, 0.5.6 API, migration |
| [docs/rust.md](docs/rust.md) | Rust 0.6 usage, 0.5.6 API, migration |
| [docs/general.md](docs/general.md) | Platform gotchas (Keychain, Safari FDA, …) |
| [docs/building.md](docs/building.md) | Local builds for crate, CLI, Python, Node |
| [docs/testing.md](docs/testing.md) | Deterministic, E2E, and artifact-smoke matrix |
| [docs/releasing.md](docs/releasing.md) | Version bump and publish workflows |
| [docs/sqlite-security.md](docs/sqlite-security.md) | Bundled SQLite inventory |
| [docs/adr/0004-read-is-the-recommended-entry.md](docs/adr/0004-read-is-the-recommended-entry.md) | Why `read` / `jar` |
| [CHANGELOG.md](CHANGELOG.md) | Breaking and compat notes |
| [examples/python](examples/python) · [examples/javascript](examples/javascript) · [examples/rust](examples/rust) | Runnable samples |

## Develop and test

```console
cargo test --workspace --all-targets
cargo test --workspace --doc
python3 scripts/check-doc-snippets.py
```

After `maturin develop` in `bindings/python`:

```console
python -m unittest discover -s tests/python -p 'test_*.py' -v
```

Real-browser E2E lives in
[`.github/workflows/e2e.yml`](.github/workflows/e2e.yml). Details:
[docs/testing.md](docs/testing.md). Build steps: [docs/building.md](docs/building.md).

## Contributing

Open issues and pull requests on
[teng-lin/rookie-cookies](https://github.com/teng-lin/rookie-cookies). Include
OS, browser/version, language binding, and whether the browser was running.
**Never** attach real cookie values or browser databases.

MIT licensed — see [MIT-LICENSE.txt](MIT-LICENSE.txt).

## Credits

This fork preserves the original project’s history and license. It also builds
on ideas from [`browser_cookie3`](https://github.com/borisbabic/browser_cookie3).
