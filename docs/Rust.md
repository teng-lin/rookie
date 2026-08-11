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

`firefox()` reads the profile Firefox itself would open, resolved from
`profiles.ini`. To reach a secondary profile, list them and select one by its
name, directory name, or full path:

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
