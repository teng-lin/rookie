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

## Logging

Logging level can be controlled by changing `RUST_LOG` ENV variable

```console
RUST_LOG=trace cargo run
```
