//! Test-only explicit-path JSON emitter used by the nightly browser stress job.

use rookie_cookies::{from_path, FromPathRequest};
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let mut arguments = env::args().skip(1);
  let engine = arguments.next().ok_or("missing engine")?;
  let database = arguments.next().ok_or("missing database")?;
  let browser_id = arguments.next().ok_or("missing browser id")?;
  let projection = arguments.next().ok_or("missing projection")?;
  if arguments.next().is_some() {
    return Err("unexpected extra argument".into());
  }

  let request = FromPathRequest::new(database);
  #[cfg(unix)]
  let request = if engine == "chromium" {
    request.chromium_browser_id(browser_id)
  } else {
    request
  };
  #[cfg(windows)]
  let request = {
    let _ = browser_id;
    if engine == "chromium" {
      return Err("Windows Chromium stress requires an explicit Local State selector".into());
    }
    request
  };
  let snapshot = from_path(request)?;
  match projection.as_str() {
    "unfiltered_flat" => println!("{}", serde_json::to_string(snapshot.cookies())?),
    "detailed" => println!("{}", serde_json::to_string(snapshot.detailed_cookies())?),
    _ => return Err(format!("unsupported projection {projection}").into()),
  }
  Ok(())
}
