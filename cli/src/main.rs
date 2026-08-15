use clap::error::ErrorKind;
use clap::{Command, CommandFactory, FromArgMatches};
use rookie_cookies::{any_browser, common::enums::Cookie};
mod browsers_map;
use browsers_map::BROWSERS_MAP;
mod args;
use args::Args;
use rookie_cookies::common::format;

fn print_cookies(args: Args, cookies: Vec<Cookie>) {
  match args.format.as_str() {
    "json" => {
      let str = format::json(cookies);
      println!("{str}");
    }
    "netscape" => {
      let data = format::netscape(cookies);
      println!("{}", data);
    }
    _ => {}
  }
}

fn print_version() {
  println!(
    "CLI: {}\nrookie-cookies: {}",
    env!("CARGO_PKG_VERSION"),
    rookie_cookies::version()
  );
}

fn usage_error(
  command: &mut Command,
  kind: ErrorKind,
  message: impl std::fmt::Display,
) -> clap::Error {
  command.error(kind, message)
}

/// This is only a pre-check; `browser_profiles` and `browser_report` resolve the
/// ID themselves. Registry construction failures are surfaced instead of
/// being mistaken for an empty registered inventory.
fn registration_of(browser: &str) -> rookie_cookies::Result<bool> {
  let registered = rookie_cookies::supported_browsers()?;
  Ok(registered.iter().any(|descriptor| {
    descriptor.id.as_str() == browser || descriptor.aliases.iter().any(|alias| alias == browser)
  }))
}

fn legacy_browser_values() -> String {
  BROWSERS_MAP
    .keys()
    .map(|key| {
      if key.contains(char::is_whitespace) {
        format!("\"{key}\"")
      } else {
        (*key).to_string()
      }
    })
    .collect::<Vec<_>>()
    .join(", ")
}

/// Post-parse mode validation from Section 5.8. `--browser` no longer carries a
/// closed `PossibleValuesParser`, so the accepted set depends on the mode: the
/// historical `BROWSERS_MAP` keys alone without a list/report mode, and the
/// registered IDs and aliases with one. Every rejection stays a clap usage
/// error so the exit code and error class survive the move out of clap.
fn validate_modes(args: &Args, command: &mut Command) -> Result<(), clap::Error> {
  if args.is_generic_mode() && args.format == "netscape" {
    return Err(usage_error(
      command,
      ErrorKind::ArgumentConflict,
      "the argument '--format netscape' cannot be used with '--list-browsers', \
       '--list-profiles', or '--report'",
    ));
  }

  let Some(browser) = args.browser.as_deref() else {
    return Ok(());
  };

  if args.is_generic_mode() {
    let registered = registration_of(browser).map_err(|error| {
      usage_error(
        command,
        ErrorKind::Io,
        format!("could not read the embedded browser registry: {error:#}"),
      )
    })?;
    if registered {
      return Ok(());
    }
    return Err(usage_error(
      command,
      ErrorKind::InvalidValue,
      format!(
        "invalid value '{browser}' for '--browser <BROWSER>': \
         not a registered browser ID or alias\n  \
         run '--list-browsers' for the registered IDs"
      ),
    ));
  }

  if BROWSERS_MAP.contains_key(browser) {
    return Ok(());
  }

  if registration_of(browser).map_err(|error| {
    usage_error(
      command,
      ErrorKind::Io,
      format!("could not read the embedded browser registry: {error:#}"),
    )
  })? {
    return Err(usage_error(
      command,
      ErrorKind::InvalidValue,
      format!(
        "'{browser}' is only reachable through the registry\n  \
         use '--report --browser {browser}'"
      ),
    ));
  }

  Err(usage_error(
    command,
    ErrorKind::InvalidValue,
    format!(
      "invalid value '{browser}' for '--browser <BROWSER>'\n  [possible values: {}]",
      legacy_browser_values()
    ),
  ))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
  tracing_subscriber::fmt()
    .with_writer(std::io::stderr)
    .with_ansi(false)
    .with_env_filter(
      tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
        .from_env_lossy(),
    )
    .init();
  // Parsing through the owned `Command` keeps the post-parse usage errors below
  // rendering the same program name as clap's own parse errors.
  let mut command = Args::command();
  let matches = command.get_matches_mut();
  let args = match Args::from_arg_matches(&matches) {
    Ok(args) => args,
    Err(error) => error.format(&mut command).exit(),
  };
  if args.version {
    print_version();
    return Ok(());
  }
  if let Err(error) = validate_modes(&args, &mut command) {
    error.exit();
  }

  if args.list_browsers {
    let browsers = rookie_cookies::supported_browsers()?;
    println!("{}", serde_json::to_string_pretty(&browsers)?);
    return Ok(());
  }
  if args.list_profiles {
    let browser = args
      .browser
      .as_deref()
      .expect("clap requires --browser with --list-profiles");
    let profiles = rookie_cookies::browser_profiles(browser)?;
    println!("{}", serde_json::to_string_pretty(&profiles)?);
    return Ok(());
  }

  tracing::info!("extracting cookies");

  if args.report {
    let report = match &args.browser {
      Some(browser) => {
        rookie_cookies::browser_report(browser, args.profile.as_deref(), args.domains.clone())?
      }
      None => rookie_cookies::load_report(args.domains.clone())?,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    return Ok(());
  }

  #[allow(unused_assignments)]
  let mut cookies = vec![];
  let args_c = args.clone();
  if args.load {
    cookies = rookie_cookies::load(args.domains)?;
  } else if let Some(browser) = args.browser {
    let browser_fn = BROWSERS_MAP
      .get(browser.as_str())
      .expect("validate_modes rejects browsers outside the legacy map");
    cookies = browser_fn(args.domains)?;
  } else if let Some(path) = args.path {
    cookies = any_browser(path.as_str(), args.domains, args.key_path.as_deref())?;
  } else {
    // Default load from all
    cookies = rookie_cookies::load(args.domains)?;
  }
  print_cookies(args_c, cookies);

  Ok(())
}
