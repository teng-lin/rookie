//! Minimal example: read cookies from an explicit Firefox-style
//! `cookies.sqlite` and print each one.
//!
//! Run with:
//!     cargo run --example from_path -- /path/to/cookies.sqlite
//!
//! On CI this is invoked against the seeded Firefox profile that the
//! e2e workflow creates, so it doubles as a regression test for the
//! canonical `direct_path` public API drifting.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let db_path: PathBuf = std::env::args()
    .nth(1)
    .ok_or("usage: from_path <cookies.sqlite>")?
    .into();

  let cookies = rookie_cookies::direct_path::cookies_from_path(
    rookie_cookies::direct_path::DirectPathRequest::new(db_path),
  )?;
  for cookie in cookies {
    println!("{:?}", cookie);
  }
  Ok(())
}
