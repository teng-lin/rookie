# rookie-cookies Rust Docs

## Install

```console
cargo add rookie-cookies
```

## Basic Usage

```rust
use rookie_cookies;

fn main() {
    let cookies = rookie_cookies::browser("chrome", None).unwrap();
    println!("{cookies:?}");
}
```

## One operation, any registered browser

`browser(id, domains)` and the lower-level `extract(Request::browser(id))` are
the canonical entry point: unlike a per-browser function, `id` can be any
canonical ID or alias `supported_browsers()` lists, including registered forks
and alternate builds with no dedicated function. Both resolve the same first
installation and first legacy-compatible profile the older named functions
(`chrome`, `firefox`, `brave`, ...) do — use `browser_report`/`browser_profiles`
to cover every installation and profile instead.

The named per-browser functions (`chrome`, `firefox`, `firefox_profile`,
`brave`, ...) are `#[deprecated]` since 0.6.0 in favor of `browser`/`extract`
and remain fully supported through the deprecation window; nothing below stops
working.

```rust
fn main() -> rookie_cookies::Result<()> {
    let request = rookie_cookies::Request::browser("chrome")
        .domains(Some(vec!["example.com".to_string()]));
    let cookies = rookie_cookies::extract(request)?;
    println!("{cookies:?}");
    Ok(())
}
```

## Timeouts and cancellation

`Request`, `DirectPathRequest`, and `ChromiumPathRequest` each accept an
optional `.timeout(Duration)` budget and an optional `.cancellation(handle)`
for cooperative, cross-thread cancellation of an in-flight extraction:

```rust
use std::time::Duration;

fn main() -> rookie_cookies::Result<()> {
    let cancellation = rookie_cookies::CancellationHandle::new();
    let watcher = cancellation.clone();
    std::thread::spawn(move || {
        // Cancel from another thread, e.g. in response to a user action.
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

`CancellationHandle` is `Clone`; every clone shares one underlying signal, so
cancelling any clone cancels all of them. Cancellation and timeouts are
checked cooperatively at the same internal boundaries, so they take effect
mid-extraction rather than only before it starts, but a single long-running
step between checkpoints is not interrupted mid-step.

## Firefox profiles

`firefox()` prefers the profile Firefox itself would open, resolved from
`profiles.ini`. If that profile has no `cookies.sqlite` it falls through to the
other profiles and finally to the profile root, so it returns cookies rather
than an error — which means the cookies it returns are not guaranteed to come
from the profile Firefox currently has open.

To know which profile you are reading, or to reach a secondary one deliberately,
list them and select by name, directory name, or full path:

```rust
use rookie_cookies;

fn main() {
    for profile in rookie_cookies::firefox_profiles().unwrap() {
        println!("{} {} default={}", profile.name, profile.path.display(), profile.is_default);
    }

    let cookies = rookie_cookies::firefox_profile("work", None).unwrap();
    println!("{cookies:?}");
}
```

## Chrome profiles

`chrome()` remains the legacy default-first selector. The additive
`chrome_profiles()` listing uses Chrome's advisory `Local State` activity hints:
the last-used profile appears first, followed by the other active profiles. If
the hints are missing, stale, or malformed, the order safely falls back to the
generic default-first registry order.

`chrome_profile()` accepts a profile ID, display name, directory name, or a full
path when `profile.path_lossy` is false. Lossy display paths require the opaque
profile ID. It returns a grouped report rather than a flat cookie vector,
preserving the profile identity, selected source, counters, and typed issues.

```rust
fn main() {
    let profiles = rookie_cookies::chrome_profiles().unwrap();
    if let Some(preferred) = profiles.first() {
        let report = rookie_cookies::chrome_profile(
            preferred.profile.profile_id.as_str(),
            Some(vec!["example.com".to_owned()]),
        )
        .unwrap();
        println!("{}", report.status);
    }
}
```

## Partition and container context

The original `Cookie` type intentionally remains a compatibility projection.
Use the additive detailed path APIs when cookies that share
`(domain, path, name)` must remain distinguishable by Chromium CHIPS partition
or Firefox container:

```rust
use std::path::PathBuf;

fn main() -> rookie_cookies::Result<()> {
    let cookies = rookie_cookies::firefox_based_detailed(
        PathBuf::from("/path/to/cookies.sqlite"),
        None,
    )?;
    for record in cookies {
        println!("{} {:?}", record.cookie.name, record.context);
    }
    Ok(())
}
```

For explicit Chromium databases, use the all-target request API. The source is
validated as Chromium before options or key providers are touched:

```rust
use rookie_cookies::direct_path::{
    chromium_cookies_from_path_detailed, ChromiumCredentialSource,
    ChromiumPathRequest,
};

fn main() -> rookie_cookies::Result<()> {
    let cookies = chromium_cookies_from_path_detailed(
        ChromiumPathRequest::new("/path/to/Network/Cookies")
            .domains(vec!["example.com".to_owned()])
            .credentials(ChromiumCredentialSource::BrowserId("brave".to_owned())),
    )?;
    println!("{}", cookies.len());
    Ok(())
}
```

`Automatic` preserves the existing ordered browser-identity probe on Linux and
macOS. Windows requires an explicit `LocalStateFile`. `PlaintextOnly` is strict:
if any row is encrypted, the complete request fails instead of returning a
partial list. `AllowProcessShutdown` is an explicit Windows-only choice; the
default `NonDisruptive` policy never terminates a browser.

For a source whose browser family is not known in advance, use
`cookies_from_path(DirectPathRequest::new(path))`. Mozilla SQLite works on every
compile target. Chromium works on Linux, macOS, and Windows; Safari binary
cookies are macOS-only and Internet Explorer WebCache is Windows-only.

The earlier `*_based`, `any_browser`, and config-based direct-path APIs remain
available through 0.6 for compatibility and are deprecated for removal in 0.7.
Errors from the new API remain `anyhow::Error`; downcast to
`direct_path::DirectPathError` for stable `kind()`, `code()`, source, target,
and reason accessors without losing the underlying I/O, SQLite, or key error.

## Logging

Logging level can be controlled by changing `RUST_LOG` ENV variable

```console
RUST_LOG=trace cargo run
```
