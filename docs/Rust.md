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

## Logging

Logging level can be controlled by changing `RUST_LOG` ENV variable

```console
RUST_LOG=trace cargo run
```
