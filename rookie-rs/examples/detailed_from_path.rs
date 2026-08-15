//! Read an explicit Firefox cookie database without discarding container or
//! partition identity.

#![allow(deprecated)]

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let db_path: PathBuf = std::env::args()
    .nth(1)
    .ok_or("usage: detailed_from_path <cookies.sqlite>")?
    .into();

  for record in rookie_cookies::firefox_based_detailed(db_path, None)? {
    println!("{} {:?}", record.cookie.name, record.context);
  }
  Ok(())
}
