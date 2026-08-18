#![allow(deprecated)]

use clap::error::ErrorKind;
use clap::{Command, CommandFactory, FromArgMatches};
use rookie_cookies::common::enums::Cookie;
use rookie_cookies::direct_path::{
  chromium_cookies_from_path, cookies_from_path, ChromiumCredentialSource, ChromiumPathRequest,
  DirectPathRequest,
};
use rookie_cookies::CancellationHandle;
use std::path::PathBuf;
mod browsers_map;
use browsers_map::BROWSERS_MAP;
mod args;
use args::{Args, JobCommand};
use rookie_cookies::common::format;
use std::io::Write;

/// Writes `line` plus a trailing newline to stdout.
///
/// A closed downstream pipe (e.g. `rookie-cookies --load | head -1`) is
/// ordinary, expected shutdown, not a program error: Rust's `println!`
/// panics on it (exit code 101), which looks like a crash to a script
/// checking the exit code. This exits cleanly (matching how a traditional
/// Unix tool terminates on `SIGPIPE`) instead.
fn print_line_or_exit(line: &str) {
  if let Err(error) = writeln!(std::io::stdout(), "{line}") {
    if error.kind() == std::io::ErrorKind::BrokenPipe {
      std::process::exit(0);
    }
    eprintln!("error: failed to write output: {error}");
    std::process::exit(1);
  }
}

/// Creates a [`CancellationHandle`] and arms `SIGINT`/`SIGTERM` (Ctrl-C, or
/// a terminal hangup, on Unix; Ctrl-C/Ctrl-Break on Windows) to cancel it.
///
/// Cancellation is cooperative: it takes effect at the next boundary
/// checkpoint, not instantly. A signal received after the first one (the
/// caller pressing Ctrl-C again because nothing happened yet, e.g. while
/// blocked on a non-cooperative wait like a keychain prompt) exits the
/// process immediately instead of waiting for a checkpoint that may not
/// come soon -- the conventional "first signal asks nicely, second signal
/// means it now" escalation.
///
/// Only the `--browser`/`--path` extraction modes call this: those are the
/// only ones built from a [`rookie_cookies::Request`]/`DirectPathRequest`/
/// `ChromiumPathRequest`, which is what actually observes cancellation.
/// `--load`, `--report`, and the `--list-*` modes keep the process's
/// default signal disposition (immediate termination) unchanged, since
/// `rookie_cookies::load`/`load_report`/`browser_report`/`browser_profiles`/
/// `supported_browsers` have no cancellation hook to drive.
fn install_cancel_on_signal() -> CancellationHandle {
  let handle = CancellationHandle::new();
  let armed = handle.clone();
  // A signal handler that can't be installed (e.g. a second call, or a
  // hostile embedding environment) leaves the default disposition in place,
  // which still terminates the process -- less gracefully, but not silently
  // stuck -- so an install failure doesn't need to abort startup, but it is
  // logged so "Ctrl-C didn't clean up" is diagnosable instead of invisible.
  if let Err(error) = ctrlc::set_handler(move || {
    // `cancel()` returns `false` when this handle was already cancelled, so
    // a repeated signal past the first one exits immediately rather than
    // being silently ignored while cooperative cancellation is still
    // pending at its next checkpoint.
    if !armed.cancel() {
      std::process::exit(130);
    }
  }) {
    tracing::warn!(
      %error,
      "failed to install SIGINT/SIGTERM handler; Ctrl-C will terminate immediately without graceful cancellation"
    );
  }
  handle
}

fn print_cookies(args: Args, cookies: Vec<Cookie>) {
  match args.format.as_str() {
    "json" => {
      let str = format::json(cookies);
      print_line_or_exit(&str);
    }
    "netscape" => {
      let data = format::netscape(cookies);
      print_line_or_exit(&data);
    }
    _ => {}
  }
}

fn emit_warnings(warnings: &[rookie_cookies::ReadWarning]) {
  for warning in warnings {
    eprintln!("{warning}");
  }
}

fn print_job_cookies(format: &str, cookies: Vec<Cookie>) {
  match format {
    "json" => print_line_or_exit(&format::json(cookies)),
    "netscape" => print_line_or_exit(&format::netscape(cookies)),
    _ => {}
  }
}

fn apply_timeout(
  mut request: rookie_cookies::ReadRequest,
  timeout_secs: Option<u64>,
) -> rookie_cookies::ReadRequest {
  if let Some(secs) = timeout_secs {
    request = request.timeout(std::time::Duration::from_secs(secs));
  }
  request
}

fn run_job_command(command: JobCommand) -> Result<(), Box<dyn std::error::Error>> {
  match command {
    JobCommand::Read {
      browser,
      profile,
      include_expired,
      format,
      timeout_secs,
    } => {
      let mut request = apply_timeout(
        rookie_cookies::ReadRequest::browser(browser).include_expired(include_expired),
        timeout_secs,
      );
      if let Some(profile) = profile {
        request = request.profile(profile);
      }
      let result = rookie_cookies::read(request)?;
      emit_warnings(result.warnings());
      print_job_cookies(&format, result.into_cookies());
    }
    JobCommand::Profiles { browser } => {
      let profiles = rookie_cookies::profiles(&browser)?;
      print_line_or_exit(&serde_json::to_string_pretty(&profiles)?);
    }
    JobCommand::Report {
      browser,
      profile,
      domains,
    } => {
      let report = rookie_cookies::browser_report(&browser, profile.as_deref(), domains)?;
      print_line_or_exit(&serde_json::to_string_pretty(&report)?);
    }
    JobCommand::FromPath {
      path,
      include_expired,
      format,
      key_path,
      browser_id,
      plaintext_only,
      timeout_secs,
    } => {
      let mut request = rookie_cookies::FromPathRequest::new(path).include_expired(include_expired);
      if let Some(secs) = timeout_secs {
        request = request.timeout(std::time::Duration::from_secs(secs));
      }
      if plaintext_only {
        request = request.chromium_credentials(
          rookie_cookies::direct_path::ChromiumCredentialSource::PlaintextOnly,
        );
      } else if let Some(browser_id) = browser_id {
        request = request.chromium_credentials(
          rookie_cookies::direct_path::ChromiumCredentialSource::BrowserId(browser_id),
        );
      } else if let Some(key_path) = key_path {
        request = request.chromium_credentials(
          rookie_cookies::direct_path::ChromiumCredentialSource::LocalStateFile(PathBuf::from(
            key_path,
          )),
        );
      }
      let result = rookie_cookies::from_path(request)?;
      emit_warnings(result.warnings());
      print_job_cookies(&format, result.into_cookies());
    }
    JobCommand::Header {
      url,
      browser,
      profile,
    } => {
      let mut request = rookie_cookies::ReadRequest::browser(browser);
      if let Some(profile) = profile {
        request = request.profile(profile);
      }
      let result = rookie_cookies::read(request)?;
      emit_warnings(result.warnings());
      print_line_or_exit(&result.header(&url)?);
    }
  }
  Ok(())
}

fn print_version() {
  print_line_or_exit(&format!(
    "CLI: {}\nrookie-cookies: {}",
    env!("CARGO_PKG_VERSION"),
    rookie_cookies::version()
  ));
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
    .iter()
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

fn canonical_legacy_browser(browser: &str) -> &str {
  match browser {
    "opera gx" | "opera-gx" => "opera_gx",
    _ => browser,
  }
}

fn cookies_from_explicit_path(
  path: String,
  domains: Option<Vec<String>>,
  key_path: Option<String>,
  browser_id: Option<String>,
  plaintext_only: bool,
  cancellation: CancellationHandle,
) -> rookie_cookies::Result<Vec<Cookie>> {
  let credential_selector = if let Some(key_path) = key_path {
    Some(ChromiumCredentialSource::LocalStateFile(PathBuf::from(
      key_path,
    )))
  } else if let Some(browser_id) = browser_id {
    Some(ChromiumCredentialSource::BrowserId(browser_id))
  } else if plaintext_only {
    Some(ChromiumCredentialSource::PlaintextOnly)
  } else {
    None
  };

  let Some(credentials) = credential_selector else {
    let mut request = DirectPathRequest::new(path).cancellation(cancellation);
    if let Some(domains) = domains {
      request = request.domains(domains);
    }
    return cookies_from_path(request);
  };

  let mut request = ChromiumPathRequest::new(path)
    .credentials(credentials)
    .cancellation(cancellation);
  if let Some(domains) = domains {
    request = request.domains(domains);
  }
  chromium_cookies_from_path(request)
}

/// Post-parse mode validation from Section 5.8. `--browser` no longer carries a
/// closed `PossibleValuesParser`, so the accepted set depends on the mode: the
/// historical `BROWSERS_MAP` keys alone without a list/report mode, and the
/// registered IDs and aliases with one. Every rejection stays a clap usage
/// error so the exit code and error class survive the move out of clap.
fn validate_modes(args: &Args, command: &mut Command) -> Result<(), clap::Error> {
  if args.command.is_some() {
    let mixed = args.browser.is_some()
      || args.load
      || args.path.is_some()
      || args.list_browsers
      || args.list_profiles
      || args.report
      || args.profile.is_some()
      || args.domains.is_some()
      || args.key_path.is_some()
      || args.browser_id.is_some()
      || args.plaintext_only;
    if mixed {
      return Err(usage_error(
        command,
        ErrorKind::ArgumentConflict,
        "a job subcommand cannot be mixed with top-level --browser / --load / --path / \
         --list-browsers / --list-profiles / --report / --profile / --domains",
      ));
    }
    return Ok(());
  }

  if args.is_structured_output_mode() && args.format == "netscape" {
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

  if args.widens_browser_to_registry() {
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

  if BROWSERS_MAP.contains(canonical_legacy_browser(browser)) {
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

  if let Some(command) = args.command.clone() {
    return run_job_command(command);
  }

  if args.list_browsers {
    let browsers = rookie_cookies::supported_browsers()?;
    print_line_or_exit(&serde_json::to_string_pretty(&browsers)?);
    return Ok(());
  }
  if args.list_profiles {
    let browser = args
      .browser
      .as_deref()
      .expect("clap requires --browser with --list-profiles");
    let profiles = rookie_cookies::browser_profiles(browser)?;
    print_line_or_exit(&serde_json::to_string_pretty(&profiles)?);
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
    print_line_or_exit(&serde_json::to_string_pretty(&report)?);
    return Ok(());
  }

  #[allow(unused_assignments)]
  let mut cookies = vec![];
  let args_c = args.clone();
  if args.load {
    cookies = rookie_cookies::load(args.domains)?;
  } else if let Some(browser) = args.browser {
    let cancellation = install_cancel_on_signal();
    let mut request = if args.profile.is_some() {
      rookie_cookies::Request::browser(&browser)
    } else {
      let canonical = canonical_legacy_browser(&browser);
      assert!(
        BROWSERS_MAP.contains(canonical),
        "validate_modes rejects browsers outside the legacy map without --profile"
      );
      rookie_cookies::Request::browser(canonical)
    };
    if let Some(profile) = args.profile {
      request = request.profile(profile);
    }
    request = request.domains(args.domains).cancellation(cancellation);
    cookies = rookie_cookies::extract(request)?;
  } else if let Some(path) = args.path {
    let cancellation = install_cancel_on_signal();
    cookies = cookies_from_explicit_path(
      path,
      args.domains,
      args.key_path,
      args.browser_id,
      args.plaintext_only,
      cancellation,
    )?;
  } else {
    // Default load from all
    cookies = rookie_cookies::load(args.domains)?;
  }
  print_cookies(args_c, cookies);

  Ok(())
}
