# rookie-cookies

[![PyPI](https://img.shields.io/pypi/v/rookie-cookies?logo=python)](https://pypi.org/project/rookie-cookies/)
[![npm](https://img.shields.io/npm/v/rookie-cookies?logo=npm&color=0076CE)](https://www.npmjs.com/package/rookie-cookies/)
[![crates.io](https://img.shields.io/crates/v/rookie-cookies?logo=rust)](https://crates.io/crates/rookie-cookies/)
[![License](https://img.shields.io/github/license/teng-lin/rookie-cookies?logo=license)](LICENSE.md)

`rookie-cookies` is a fast, cross-platform cookie extraction toolkit — a Rust
core with native Python and JavaScript bindings and a CLI — that pulls cookies
from every major browser, including support for the latest Chrome v20 App-Bound
Encryption (ABE).

This is a maintained fork of
[`thewh1teagle/rookie`](https://github.com/thewh1teagle/rookie), which is
archived. We still ship that project's public call shapes (`chrome()`,
`firefox()`, `load()`, and friends) so existing consumers keep working.

That compatibility is a **bridge, not a promise**. New work should use the 0.6
job API (`read` / `jar`). Later releases will break the old surface as we
add capabilities and clean up the design. Plan on migrating; do not take the
legacy helpers as frozen forever.

The snippets below document the recommended API for the 0.6 release line.
Package metadata and `version()` are authoritative for the installed build.

## What is different from upstream rookie

We keep the old names working while the library grows past a bag of
per-browser functions:

- One recommended job (`read` / `jar`) instead of “call `chrome()` and hope”.
- Profile queries so profile and Gecko session-source selection are explicit.
- Structured reports, explicit-path builders, timeouts, and cancellation.
- Chromium formats through **legacy DPAPI**, **`v10` / `v11`**, and **App-Bound
  `v20`** where the host and browser allow it.
- Shared tests across Rust, Python, Node, and the CLI.

Those additions are why the old API will eventually go away rather than stay
the documented default.

## Platforms and browsers

| Browser | Linux | macOS | Windows |
| --- | :---: | :---: | :---: |
| Arc | — | ✓ | ✓ |
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
| **App-Bound `v20`** | Windows Chrome-family | Chrome 127+ App-Bound Encryption (`APPB` key in `Local State`, values prefixed `v20`). Needs the default `appbound` feature. The unprivileged COM-injection path targets Chrome 127+; the elevated DPAPI/CNG fallback covers the 127-era formats and the flag-3 form introduced in Chrome 133+. Hosted canaries: Chrome, Edge, Brave. Also declared for Cốc Cốc and Avast. |
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

Linux Chromium is `v10` + `v11` (libsecret / KWallet). Most macOS Chromium
registrations declare Keychain-backed `v10`; macOS Cốc Cốc declares no
encrypted tier and can emit only plaintext rows. Gecko uses the same
sqlite/session layout on all three OSes.

## Install

| Language | Requirement | Command |
| --- | --- | --- |
| Python | CPython ≥ 3.11 | `pip install rookie-cookies` |
| Node.js | Node ≥ 22 | `npm install rookie-cookies` |
| Rust | Rust ≥ 1.88, edition 2021 | `cargo add rookie-cookies` |
| CLI | same repo / release binaries | `rookie-cookies --help` |

**Windows App-Bound security note:** the recommended job APIs default to
unprivileged reflective COM injection into a spawned browser process when they
encounter `v20` cookies. Endpoint security products can flag that behavior.
Set `AppBoundPolicy::Disabled` in Rust, `app_bound="disabled"` in Python,
`appBound: "disabled"` in Node, or `--app-bound disabled` in the CLI to opt
out; App-Bound rows will then be omitted and reported as unavailable.

## Recommended usage (0.6 series)

Pass a **profile** to select one discovered profile; omit it to match the old
first-profile, legacy-compatible helpers.

**Session cookies are a separate question in the current API.** Ask for them
with `include_session` (`includeSession` in Node, `--include-session` on the
CLI). Naming a profile no longer implies them, and the change is quiet: a
Gecko `jar(profile="Default")` returns a smaller jar than it did in earlier
0.6 prereleases, with no error. Chromium registrations declare no separate
session source, so selecting a Chrome profile never recovered session state
held only in browser memory.

`read` never URL-filters the snapshot; `ReadResult.header` is a **view** over a
send context. Rust passes `&SendContext`; Python and Node also accept a bare URL
as convenience syntax for the conservative default context. A bare URL is not
enough once the snapshot contains a partitioned or container-scoped cookie, so
those calls fail with the missing selectors instead of merging isolation
boundaries. There is no top-level binding `header()`, and no crate-root Rust
`get` / `report`.

`jar` is warning-discarding projection sugar over the same `read` job. Python
returns `http.cookiejar.CookieJar`; Node returns `CookieObject[]`; Rust returns
`Vec<Cookie>`. Use `read` when warnings or partition/container context matter.

### Python

```python
import rookie_cookies as cookies

session_jar = cookies.jar(
    browser="firefox", profile="default-release", include_session=True
)
rows = cookies.read(browser="chrome", profile="Work").as_list()
```

### Node.js

```javascript
import { jar, read } from "rookie-cookies";

const sessionCookies = await jar({
  browser: "firefox",
  profile: "default-release",
  includeSession: true,
});

const snapshot = await read({
  browser: "chrome",
  profile: "Work",
});
console.log(sessionCookies, snapshot.header("https://example.com/"));
```

Extraction is async. Always `await`.

### Rust

```rust
use rookie_cookies::{jar, read, ReadRequest, SendContext};

fn main() -> rookie_cookies::Result<()> {
    let session_cookies = jar(
        ReadRequest::browser("firefox")
            .profile("default-release")
            .include_session(),
    )?;
    let snapshot = read(
        ReadRequest::browser("chrome").profile("Work"),
    )?;
    println!("{} cookies", session_cookies.len());
    println!("{}", snapshot.header(&SendContext::url("https://example.com/"))?);
    Ok(())
}
```

### CLI

```console
rookie-cookies read --browser firefox --profile default-release --include-session
rookie-cookies header --url https://example.com/ --browser chrome
rookie-cookies from-path /path/to/cookies.sqlite
rookie-cookies from-path /path/to/Cookies --browser-id chrome
rookie-cookies report --browser chrome
rookie-cookies report
```

Chromium credential flags (`--browser-id`, `--local-state-path`,
`--plaintext-only`) are mutually exclusive on `from-path`. The CLI is job
subcommands only: `header` takes `--url` rather than a positional, `report`
takes an optional `--browser` (omitting it means the aggregate report), and
the old top-level `--path` / `--browser` flags are gone.

Runtime failures from the typed `rookie_cookies::Error` hierarchy are written
to stderr as one JSON object with exactly `code` and `message` fields. Branch
on the stable `code`; `message` is a human diagnostic and may change. Clap
usage errors and wrapped or non-library failures retain their normal human
`Display` output and are not promised to be JSON. Failed jobs do not write a
partial cookie result to stdout.

Coming from the legacy named helpers? Each language guide documents the
compatibility surface and its migration to the recommended 0.6 API:
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
| Documentation index | [docs/README.md](docs/README.md) |
| Language guides | [python](bindings/python/README.md) · [javascript](bindings/node/README.md) · [rust](rookie-rs/README.md) |
| Build / test / release | [building](docs/building.md) · [testing](docs/testing.md) · [releasing](docs/releasing.md) |
| Troubleshooting | [docs/troubleshooting.md](docs/troubleshooting.md) |
| Security | [reporting policy](SECURITY.md) · [engineering index](docs/security.md) |
| Design | [architecture](docs/architecture.md) · [ADR 0004](docs/adr/0004-read-is-the-recommended-entry.md) · [changelog](CHANGELOG.md) |
| Examples | [python](examples/python) · [javascript](examples/javascript) · [rust](examples/rust) |

```console
cargo test --workspace --all-targets --locked
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
