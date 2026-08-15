use anyhow::{bail, Context, Result};

fn main() -> Result<()> {
  let args: Vec<String> = std::env::args().skip(1).collect();
  let value = match args.as_slice() {
    [command, browser] if command == "profiles" => {
      serde_json::to_value(rookie_cookies::browser_profiles(browser)?)?
    }
    [command, browser] if command == "report" => {
      serde_json::to_value(rookie_cookies::browser_report(browser, None, None)?)?
    }
    [command, browser, profile] if command == "report" => serde_json::to_value(
      rookie_cookies::browser_report(browser, Some(profile), None)?,
    )?,
    [command] if command == "load-report" => {
      serde_json::to_value(rookie_cookies::load_report(None)?)?
    }
    _ => bail!("usage: report_surface profiles BROWSER | report BROWSER [PROFILE] | load-report"),
  };
  println!(
    "{}",
    serde_json::to_string(&value).context("serialize report output")?
  );
  Ok(())
}
