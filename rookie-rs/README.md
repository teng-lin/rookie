# rookie-cookies (Rust)

Extract cookies from local browsers on Linux, macOS, and Windows.

This file is the **Rust crate guide** (crates.io landing page and repo
tutorial). Python and Node live in
[`bindings/python/README.md`](https://github.com/teng-lin/rookie-cookies/blob/main/bindings/python/README.md)
and
[`bindings/node/README.md`](https://github.com/teng-lin/rookie-cookies/blob/main/bindings/node/README.md).
The monorepo front door is the root
[`README.md`](https://github.com/teng-lin/rookie-cookies/blob/main/README.md).

The workspace is currently `0.6.0-beta.1`. The recommended 0.6 entry is
`read(ReadRequest::…)`
([ADR 0004](https://github.com/teng-lin/rookie-cookies/blob/main/docs/adr/0004-read-is-the-recommended-entry.md)).

```console
cargo add rookie-cookies
```

## Recommended 0.6.0 usage

```rust
use rookie_cookies::{read, ReadRequest};

fn main() -> rookie_cookies::Result<()> {
    // Gecko profile selection also includes its declared session JSON source.
    let snapshot = read(ReadRequest::browser("firefox").profile("default-release"))?;
    for cookie in snapshot.cookies() {
        println!("{} {}", cookie.domain, cookie.name);
    }
    let header = snapshot.header("https://example.com/")?;
    let owned = snapshot.into_cookies();
    let _ = (header, owned);
    Ok(())
}
```

`read` is the recommended job: one unfiltered snapshot, then `header(url)` as a
view. There is **no** crate-root `get` or `report` function. Bindings-facing
`profiles(browser_id)` exists as an alias of `browser_profiles`; structured
reports use `extract_report` / `browser_report`.

- No-profile `read(ReadRequest::browser("chrome"))` matches the compatibility
  flatten used by `chrome()` / `extract` when `include_expired` is set
  appropriately (persistent / legacy-eligible cookies).
- A profile query selects exactly one profile. For Gecko-family browsers, it
  also includes that profile's separately declared session JSON source.
- Chromium registrations declare no separate session source, so a Chrome
  profile query cannot recover session state that exists only in memory.

Named helpers (`chrome`, `firefox`, `brave`, `load`, …) are `#[deprecated]` since 0.6.0
in favor of `browser` / `extract` / `read` and remain supported through the
deprecation window. They are the compatibility bridge from
[`thewh1teagle/rookie`](https://github.com/thewh1teagle/rookie) and will break
in a later major version.

## One operation, any registered browser

`browser(id, domains)` and `extract(Request::browser(id))` remain the
compatibility / multi-id store verbs. Prefer them when you need a domain filter
on the frozen flat list; prefer `read` for profile-scoped inventory and Gecko
session import.

```rust
fn main() -> rookie_cookies::Result<()> {
    let request = rookie_cookies::Request::browser("chrome")
        .domains(Some(vec!["example.com".to_string()]));
    let cookies = rookie_cookies::extract(request)?;
    println!("{cookies:?}");
    Ok(())
}
```

## Explicit paths

```rust
use std::path::PathBuf;
use rookie_cookies::direct_path::{
    chromium_cookies_from_path_detailed, cookies_from_path, ChromiumCredentialSource,
    ChromiumPathRequest, DirectPathRequest,
};

fn main() -> rookie_cookies::Result<()> {
    let mozilla = cookies_from_path(DirectPathRequest::new(PathBuf::from(
        "/path/to/cookies.sqlite",
    )))?;
    let chromium = chromium_cookies_from_path_detailed(
        ChromiumPathRequest::new("/path/to/Network/Cookies")
            .domains(vec!["example.com".to_owned()])
            .credentials(ChromiumCredentialSource::BrowserId("brave".to_owned())),
    )?;
    println!("{} {}", mozilla.len(), chromium.len());
    Ok(())
}
```

Errors remain `anyhow::Error`; downcast to `direct_path::DirectPathError` for
stable `kind()`, `code()`, and related accessors. `*_based`, `any_browser`, and
config-based direct-path APIs remain through 0.6 and are deprecated for 0.7.

## Timeouts and cancellation

```rust
use std::time::Duration;

fn main() -> rookie_cookies::Result<()> {
    let cancellation = rookie_cookies::CancellationHandle::new();
    let watcher = cancellation.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(5));
        watcher.cancel();
    });

    let request = rookie_cookies::Request::browser("chrome")
        .timeout(Duration::from_secs(30))
        .cancellation(cancellation);
    match rookie_cookies::extract(request) {
        Ok(cookies) => println!("{cookies:?}"),
        Err(error) => match rookie_cookies::stop_reason(&error) {
            Some(rookie_cookies::StopReason::TimedOut) => println!("timed out"),
            Some(rookie_cookies::StopReason::Cancelled) => println!("cancelled"),
            _ => return Err(error),
        },
    }
    Ok(())
}
```

`ReadRequest` and `FromPathRequest` accept the same `.timeout` /
`.cancellation` builders. Classify request vs engine faults with
`fault_kind(&error)` (`FaultKind::Request` / `FaultKind::Engine`).

## Reports and profiles

```rust
fn main() -> rookie_cookies::Result<()> {
    let profiles = rookie_cookies::browser_profiles("chrome")?;
    if let Some(preferred) = profiles.first() {
        let report = rookie_cookies::browser_report(
            "chrome",
            Some(preferred.profile.profile_id.as_str()),
            None,
        )?;
        println!("{}", report.status);
    }
    Ok(())
}
```

`load()` / `load_report()` probe registered browsers concurrently on a bounded
worker pool sharing one deadline / cancellation budget.

## 0.5.6 API

In the 0.5.6 line the public surface was the flat named-browser helpers. There
was no `read` / `ReadRequest` job API, no typed `direct_path` builders, and no
`FaultKind` / `stop_reason` helpers. Upstream published the `rookie` crate.

```rust
fn main() {
    let cookies = rookie_cookies::chrome(None).unwrap();
    for cookie in cookies {
        println!("{:?}", cookie);
    }

    let domains = vec!["example.com".to_string()];
    let filtered = rookie_cookies::brave(Some(domains)).unwrap();
    println!("{}", filtered.len());
}
```

## Migrate 0.5.6 → 0.6.0

| Area | 0.5.6 / early 0.5.x | 0.6.0 |
| --- | --- | --- |
| Recommended entry | `chrome(None)` / `brave(Some(domains))` | `read(ReadRequest::browser(...).profile(...))` |
| Multi-id store verb | Named helpers only | Prefer `browser(id, domains)` / `extract(Request::…)` |
| Gecko session cookies | Not a first-class `profile()` | `ReadRequest::browser(gecko_id).profile(query)` includes the declared session source |
| Path APIs | `*_based`, `any_browser` | `direct_path::{cookies_from_path, ChromiumPathRequest, …}` (legacy deprecated until 0.7) |
| Errors | Flat `anyhow::Error` | Still `anyhow::Error`, plus `fault_kind` / `RequestError` / `stop_reason` / `DirectPathError` |
| Header / get | Not a job view | `ReadResult::header(url)` — **no** crate-root `get` or `report` |
| IE helpers | `internet_explorer` / `internet_explorer_based` | Deprecated (ESE native C library; IE discontinued) |

1. For Gecko session import, select the exact profile, for example
   `read(ReadRequest::browser("firefox").profile("default-release"))`.
2. Prefer `browser` / `extract` for flat domain-filtered lists.
3. Move explicit DB paths onto `direct_path` builders.
4. Classify failures with `fault_kind` / `stop_reason`.
5. Do not add crate-root `get` / `report`.

See [CHANGELOG.md](https://github.com/teng-lin/rookie-cookies/blob/main/CHANGELOG.md).

## Logging

```console
RUST_LOG=trace cargo run
```

## More

- [docs/building.md](https://github.com/teng-lin/rookie-cookies/blob/main/docs/building.md)
- [docs/testing.md](https://github.com/teng-lin/rookie-cookies/blob/main/docs/testing.md)
- [teng-lin/rookie-cookies](https://github.com/teng-lin/rookie-cookies)
