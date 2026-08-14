# rookie-cookies Rust Docs

## Install

```console
cargo add rookie-cookies
```

## Basic Usage

```rust
use rookie_cookies;

fn main() {
    let cookies = rookie_cookies::chrome(None).unwrap();
    println!("{cookies:?}");
}
```

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

On Unix, explicit Chromium paths should use
`chromium_based_detailed_with_browser_id(Some("brave"), ...)` (or the legacy
projection `chromium_based_with_browser_id`). The ID is resolved through the
browser registry to Brave's Linux crypt name or macOS Keychain service/account.
Omitting it is allowed only for a plaintext-only database; encrypted rows fail
explicitly instead of being attempted with Chrome's identity.

## Logging

Logging level can be controlled by changing `RUST_LOG` ENV variable

```console
RUST_LOG=trace cargo run
```
