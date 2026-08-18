# rookie-cookies Rust Docs

This guide covers the **0.6.0** Rust crate surface (the tree may still publish
as `0.6.0-alpha.x`). The recommended entry is `read(ReadRequest::…)` per
[ADR 0004](adr/0004-read-is-the-recommended-entry.md). Later sections document
the **0.5.6 API** shape and how to **migrate 0.5.6 → 0.6.0**.

## Install (0.6.0)

```console
cargo add rookie-cookies
```

## Recommended 0.6.0 usage

```rust
use rookie_cookies::{read, ReadRequest};

fn main() -> rookie_cookies::Result<()> {
    // Pass profile() to include session cookies.
    let snapshot = read(ReadRequest::browser("chrome").profile("Default"))?;
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

### Profile selection and session cookies

- No-profile `read(ReadRequest::browser("chrome"))` matches the compatibility
  flatten used by `chrome()` / `extract` when `include_expired` is set
  appropriately (persistent / legacy-eligible cookies).
- Naming a profile includes session cookies, so a profile-aware `read` can
  return more cookies than omitting `profile()`.
- Session import should call `.profile(...)`.

### One operation, any registered browser

`browser(id, domains)` and the lower-level `extract(Request::browser(id))` remain
the compatibility / multi-id store verbs. Prefer them when you need a domain
filter on the frozen flat list; prefer `read` for session import.

```rust
fn main() -> rookie_cookies::Result<()> {
    let request = rookie_cookies::Request::browser("chrome")
        .domains(Some(vec!["example.com".to_string()]));
    let cookies = rookie_cookies::extract(request)?;
    println!("{cookies:?}");
    Ok(())
}
```

The named per-browser functions (`chrome`, `firefox`, `brave`, …) are
`#[deprecated]` since 0.6.0 in favor of `browser` / `extract` / `read` and remain
fully supported through the deprecation window.

### Explicit paths

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

Errors from the direct-path API remain `anyhow::Error`; downcast to
`direct_path::DirectPathError` for stable `kind()`, `code()`, and related
accessors. The earlier `*_based`, `any_browser`, and config-based direct-path
APIs remain available through 0.6 and are deprecated for removal in 0.7.

### Timeouts and cancellation

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

### Reports and profiles

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

In the 0.5.6 line (and the early maintained-fork docs), the Rust surface was the
flat named-browser helpers. There was no `read` / `ReadRequest` job API, no
typed `direct_path` builders, and no `FaultKind` / `stop_reason` helpers.

Typical 0.5.6-style usage:

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

Install at that era:

```console
cargo add rookie-cookies
```

(Upstream 0.5.6 used the `rookie` crate name; the maintained fork publishes
`rookie-cookies`.)

## Migrate 0.5.6 → 0.6.0

| Area | 0.5.6 / early 0.5.x | 0.6.0 |
| --- | --- | --- |
| Recommended entry | `chrome(None)` / `brave(Some(domains))` | `read(ReadRequest::browser(...).profile(...))` |
| Multi-id store verb | Named helpers only | Prefer `browser(id, domains)` / `extract(Request::…)` for flat lists; named helpers are deprecated |
| Session cookies | Not a first-class `profile()` on a job API | `ReadRequest::browser(id).profile(query)` |
| Path APIs | `*_based`, `any_browser`, config paths | Prefer `direct_path::{cookies_from_path, ChromiumPathRequest, …}`; legacy helpers deprecated until 0.7 |
| Errors | Flat `anyhow::Error` | Still `anyhow::Error`, plus `fault_kind` / `RequestError` / `stop_reason` / `DirectPathError` downcasts |
| Header / get | Not a job view | `ReadResult::header(url)` — **no** crate-root `get` or `report` |
| IE helpers | `internet_explorer` / `internet_explorer_based` | Deprecated for removal (ESE native C library; IE app discontinued) |

Concrete migration steps:

1. **Switch session-import call sites** from `chrome(None)` to
   `read(ReadRequest::browser("chrome").profile("Default"))` (or another
   discovered profile query).
2. **Prefer `browser` / `extract`** when you still need the flat domain-filtered
   compatibility list without the job snapshot.
3. **Move explicit DB paths** onto `direct_path` builders.
4. **Classify failures** with `fault_kind` / `stop_reason` instead of string
   matching alone.
5. Do **not** add or call crate-root `get` / `report` — use `ReadResult::header`
   and `extract_report` / `browser_report`.

See [CHANGELOG.md](../CHANGELOG.md) for the full 0.6.0 breaking/compat list.

## Logging

```console
RUST_LOG=trace cargo run
```
