use clap::error::ErrorKind;
use clap::{CommandFactory, FromArgMatches};
use rookie_cookies::common::enums::Cookie;
use rookie_cookies::direct_path::{
  extract_from_path, ChromiumCredentialSource, PathExtractRequest,
};
use rookie_cookies::CancellationHandle;
use std::path::PathBuf;
mod args;
use args::{Args, JobCommand, SendContextArgs, SnapshotArgs};
use rookie_cookies::common::format;
use std::io::Write;

/// Writes `line` plus a trailing newline to stdout.
///
/// A closed downstream pipe (for example, piping `read --browser chrome` to
/// `head`) is ordinary, expected shutdown, not a program error: Rust's `println!`
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
/// Every job subcommand except `browsers` calls this and carries the
/// resulting handle in the request or [`rookie_cookies::ExecutionControl`] it
/// builds. `browsers` wraps `supported_browsers`, which reads an embedded,
/// in-memory catalog and deliberately takes no control at all.
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

/// Emits the flat, non-detailed cookie list `extract_from_path` returns --
/// the `from-path --domains` job, which has no warnings or isolation context
/// to carry (see [`print_read_result`]).
fn print_flat_cookies(format: &str, cookies: Vec<Cookie>) {
  match format {
    "json" => print_line_or_exit(&format::json(cookies)),
    "netscape" => print_line_or_exit(&format::netscape(cookies)),
    _ => {}
  }
}

fn emit_warnings(warnings: &[rookie_cookies::ReadWarning]) {
  for warning in warnings {
    eprintln!("{warning}");
  }
}

/// Emits a snapshot job's (`read`/`from-path`) cookies in the requested
/// format.
///
/// `json` and `netscape` stay the eight-field compatibility projection:
/// neither format has a column for a CHIPS partition key or a Firefox
/// container identity, so widening them would mean inventing new columns or
/// silently dropping the isolation `detailed` exists to keep. `detailed` is
/// the only format that carries a `DetailedCookie`'s context.
///
/// Because those two formats cannot carry isolation, they route through
/// `into_jar_with` rather than `into_cookies`: an isolated snapshot is
/// refused (`isolation_loss_refused`) unless `--allow-isolation-loss` says
/// the caller has decided the loss is acceptable. `detailed` loses nothing,
/// so the flag is inert there.
fn print_read_result(
  format: &str,
  result: rookie_cookies::ReadResult,
  allow_isolation_loss: bool,
) -> Result<(), Box<dyn std::error::Error>> {
  let loss = isolation_loss(allow_isolation_loss);
  match format {
    "json" => print_line_or_exit(&format::json(result.into_jar_with(loss)?)),
    "netscape" => print_line_or_exit(&format::netscape(result.into_jar_with(loss)?)),
    "detailed" => print_line_or_exit(&format::detailed_json(result.into_detailed_cookies())),
    _ => {}
  }
  Ok(())
}

/// Maps `--allow-isolation-loss` to the typed policy.
///
/// `Refuse` is the default in the crate and here: a flat projection of an
/// isolated snapshot is wrong in a way a successful call cannot show, so the
/// opt-in has to be affirmative.
fn isolation_loss(allow: bool) -> rookie_cookies::IsolationLoss {
  if allow {
    rookie_cookies::IsolationLoss::Allow
  } else {
    rookie_cookies::IsolationLoss::Refuse
  }
}

/// Maps a validated `--resource` value to its typed kind. See
/// [`parse_app_bound`] for why an unreachable arm is safe here.
fn parse_resource(value: &str) -> rookie_cookies::ResourceKind {
  match value {
    "navigation" => rookie_cookies::ResourceKind::Navigation,
    "subresource" => rookie_cookies::ResourceKind::Subresource,
    other => unreachable!("clap already validated --resource: {other}"),
  }
}

/// Maps a validated `--method` value to its typed class. See
/// [`parse_app_bound`] for why an unreachable arm is safe here.
fn parse_method(value: &str) -> rookie_cookies::MethodClass {
  match value {
    "safe" => rookie_cookies::MethodClass::Safe,
    "unsafe" => rookie_cookies::MethodClass::Unsafe,
    other => unreachable!("clap already validated --method: {other}"),
  }
}

/// Maps a validated `--ancestor-chain` value to its typed chain. See
/// [`parse_app_bound`] for why an unreachable arm is safe here.
fn parse_ancestor_chain(value: &str) -> rookie_cookies::AncestorChain {
  match value {
    "same-site" => rookie_cookies::AncestorChain::SameSite,
    "cross-site" => rookie_cookies::AncestorChain::CrossSite,
    other => unreachable!("clap already validated --ancestor-chain: {other}"),
  }
}

/// Builds the one flat [`rookie_cookies::SendContext`] both `header` and
/// `send-view` select through.
///
/// Every flag maps 1:1 onto a builder method, in the order ADR 0006
/// Decision 1 lists them. A flag left off is genuinely absent, not a default:
/// that distinction is what stops one container's cookies from answering
/// another's request.
fn send_context(send: SendContextArgs) -> rookie_cookies::SendContext {
  let mut context = rookie_cookies::SendContext::url(send.url);
  if let Some(site) = send.top_level_site {
    context = context.top_level_site(site);
  }
  if let Some(resource) = send.resource {
    context = context.resource(parse_resource(&resource));
  }
  if let Some(method) = send.method {
    context = context.method(parse_method(&method));
  }
  if let Some(id) = send.user_context_id {
    context = context.user_context_id(id);
  }
  if let Some(id) = send.private_browsing_id {
    context = context.private_browsing_id(id);
  }
  if let Some(chain) = send.ancestor_chain {
    context = context.ancestor_chain(parse_ancestor_chain(&chain));
  }
  if let Some(domain) = send.first_party_domain {
    context = context.first_party_domain(domain);
  }
  if let Some(id) = send.gecko_view_session_context_id {
    context = context.gecko_view_session_context_id(id);
  }
  if let Some(attributes) = send.origin_attributes {
    context = context.origin_attributes(attributes);
  }
  if let Some(now) = send.now {
    context = context.now(std::time::UNIX_EPOCH + std::time::Duration::from_secs(now));
  }
  context
}

/// Reads the snapshot a send-selecting subcommand renders from, emitting its
/// read warnings to stderr first.
fn read_snapshot(
  snapshot: SnapshotArgs,
) -> Result<rookie_cookies::ReadResult, Box<dyn std::error::Error>> {
  let cancellation = install_cancel_on_signal();
  let control = execution_control(snapshot.timeout_secs, snapshot.app_bound, cancellation);
  let mut request = rookie_cookies::ReadRequest::browser(snapshot.browser)
    .include_expired(snapshot.include_expired)
    .execution(control);
  if snapshot.include_session {
    request = request.include_session();
  }
  if let Some(profile) = snapshot.profile {
    request = request.profile(profile);
  }
  let result = rookie_cookies::read(request)?;
  emit_warnings(result.warnings());
  Ok(result)
}

/// Rejects a `--profile`/`--select` combination neither request builder can
/// express.
///
/// `--select all` means "every profile"; `--profile <q>` means "this one, and
/// only this one". Combined, they contradict each other -- `ProfileSelection`
/// has no "all" arm and `ReportScope` cannot be simultaneously narrowed to one
/// query and left at `AllProfiles`. This is the same conflict a binding would
/// hit constructing the request directly, so it is raised as the typed
/// [`rookie_cookies::RequestError::ConflictingProfileSelection`] before any
/// I/O, not a bespoke CLI usage error.
///
/// `widen_to_all` is false for `read`: unlike a report, a snapshot has no
/// "every profile" shape at all (one `ReadResult` holds one `profile_id`), so
/// `--select all` is rejected there whether or not `--profile` is also given.
fn canonical_select(select: Option<&str>) -> Option<String> {
  select.map(|value| value.replace('-', "_"))
}

/// Maps a validated `--app-bound` value to its typed policy.
///
/// Clap's `PossibleValuesParser` already restricts the flag to exactly these
/// three values, so there is no fourth arm to classify by parsing here.
fn parse_app_bound(value: &str) -> rookie_cookies::AppBoundPolicy {
  value
    .replace('-', "_")
    .parse()
    .unwrap_or_else(|_| unreachable!("clap already validated --app-bound: {value}"))
}

/// Builds the [`rookie_cookies::ExecutionControl`] shared by every job
/// subcommand: `--timeout-secs`, `--app-bound`, and this invocation's
/// SIGINT/SIGTERM cancellation handle.
fn execution_control(
  timeout_secs: Option<u64>,
  app_bound: Option<String>,
  cancellation: CancellationHandle,
) -> rookie_cookies::ExecutionControl {
  let mut control = rookie_cookies::ExecutionControl::default().cancellation(cancellation);
  if let Some(secs) = timeout_secs {
    control = control.timeout(std::time::Duration::from_secs(secs));
  }
  if let Some(policy) = app_bound {
    control = control.app_bound(parse_app_bound(&policy));
  }
  control
}

fn chromium_credential_selector(
  local_state_path: Option<String>,
  browser_id: Option<String>,
  plaintext_only: bool,
) -> std::io::Result<Option<ChromiumCredentialSource>> {
  ChromiumCredentialSource::from_selectors(
    browser_id,
    local_state_path.map(PathBuf::from),
    plaintext_only,
  )
  .map_err(|_| {
    std::io::Error::new(
      std::io::ErrorKind::InvalidInput,
      "--local-state-path, --browser-id, and --plaintext-only are mutually exclusive",
    )
  })
}

fn run_job_command(command: JobCommand) -> Result<(), Box<dyn std::error::Error>> {
  // `browsers`/`profiles` are listing jobs, not extraction; the INFO log
  // stays scoped to the jobs that actually run acquisition/decryption, same
  // distinction the pre-subcommand top-level flags drew.
  if !matches!(command, JobCommand::Browsers | JobCommand::Profiles { .. }) {
    tracing::info!("extracting cookies");
  }
  match command {
    JobCommand::Read {
      browser,
      profile,
      include_expired,
      include_session,
      select,
      format,
      allow_isolation_loss,
      timeout_secs,
      app_bound,
    } => {
      let canonical_select = canonical_select(select.as_deref());
      let selection = rookie_cookies::ProfileSelection::from_binding_options(
        profile.as_deref(),
        canonical_select.as_deref(),
      )
      .map_err(rookie_cookies::Error::from)?;
      let cancellation = install_cancel_on_signal();
      let control = execution_control(timeout_secs, app_bound, cancellation);
      let mut request = rookie_cookies::ReadRequest::browser(browser)
        .selection(selection)
        .include_expired(include_expired)
        .execution(control);
      if include_session {
        request = request.include_session();
      }
      let result = rookie_cookies::read(request)?;
      emit_warnings(result.warnings());
      print_read_result(&format, result, allow_isolation_loss)?;
    }
    JobCommand::Profiles {
      browser,
      timeout_secs,
    } => {
      let cancellation = install_cancel_on_signal();
      // No `--app-bound`: listing never reaches the v20 key lookup, so
      // there's no policy for `execution_control` to apply here.
      let control = execution_control(timeout_secs, None, cancellation);
      let profiles = rookie_cookies::profiles_with(&browser, control)?;
      print_line_or_exit(&serde_json::to_string_pretty(&profiles)?);
    }
    JobCommand::Report {
      browser,
      profile,
      domains,
      select,
      timeout_secs,
      app_bound,
    } => {
      let cancellation = install_cancel_on_signal();
      let control = execution_control(timeout_secs, app_bound, cancellation);
      let report = match browser {
        Some(browser) => {
          let canonical_select = canonical_select(select.as_deref());
          let scope = rookie_cookies::ReportScope::from_binding_options(
            profile.as_deref(),
            canonical_select.as_deref(),
          )
          .map_err(rookie_cookies::Error::from)?;
          // Mirrors `browser_report`'s own request shape -- that convenience
          // function has no `_with` twin to carry a control, so it is built
          // here directly instead of through it.
          let request = rookie_cookies::ReportRequest::browser(&browser)
            .domains(domains)
            .scope(scope)
            .execution(control);
          rookie_cookies::extract_report(request)?
        }
        // No `--browser`: the `load_report` fan-out, which has no per-browser
        // selection to narrow -- clap's `requires = "browser"` on `--profile`
        // and `--select` already keeps this arm from seeing either.
        None => {
          let request = rookie_cookies::LoadReportRequest::default()
            .domains(domains)
            .execution(control);
          rookie_cookies::load_report_with(request)?
        }
      };
      print_line_or_exit(&serde_json::to_string_pretty(&report)?);
    }
    JobCommand::FromPath {
      path,
      include_expired,
      format,
      local_state_path,
      browser_id,
      plaintext_only,
      domains,
      allow_isolation_loss,
      timeout_secs,
      app_bound,
    } => {
      // `extract_from_path`/`PathExtractRequest` is the only from-path job
      // with domain filtering, and it returns a flat, non-detailed cookie
      // list with no per-row warnings -- checked before any I/O, same as
      // `ReportScope::from_binding_options`.
      if domains.is_some() && format == "detailed" {
        return Err(Box::new(std::io::Error::new(
          std::io::ErrorKind::InvalidInput,
          "--format detailed is not available together with --domains",
        )));
      }
      let cancellation = install_cancel_on_signal();
      let credentials = chromium_credential_selector(local_state_path, browser_id, plaintext_only)?;
      match domains {
        Some(domains) => {
          // `--domains` runs `extract_from_path`, which returns the flat
          // eight-field projection directly -- there is no snapshot in that
          // job for the fail-closed jar to refuse from. Rather than leave a
          // route where an isolated store prints a merged list, the same
          // path is opened a second time through `from_path` purely to ask
          // the policy question, and that snapshot is discarded. The double
          // open is deliberate and confined to this compatibility-only
          // route; the printed bytes still come from the flat job, so the
          // output is unchanged from before the gate existed.
          //
          // The gate reads with `include_expired(true)` regardless of the
          // flag: `extract_from_path` never filters by expiry, so anything
          // less would let an *expired* isolated row slip past a gate that
          // could not see it.
          let mut gate = rookie_cookies::FromPathRequest::new(path.clone())
            .include_expired(true)
            .execution(execution_control(
              timeout_secs,
              app_bound.clone(),
              cancellation.clone(),
            ));
          if let Some(credentials) = credentials.clone() {
            gate = gate.chromium_credentials(credentials);
          }
          rookie_cookies::from_path(gate)?.into_jar_with(isolation_loss(allow_isolation_loss))?;

          let request = path_extract_request(path, credentials)?
            .domains(Some(domains))
            .execution(execution_control(timeout_secs, app_bound, cancellation));
          let cookies = extract_from_path(request)?;
          print_flat_cookies(&format, cookies);
        }
        None => {
          let control = execution_control(timeout_secs, app_bound, cancellation);
          let mut request = rookie_cookies::FromPathRequest::new(path)
            .include_expired(include_expired)
            .execution(control);
          if let Some(credentials) = credentials {
            request = request.chromium_credentials(credentials);
          }
          let result = rookie_cookies::from_path(request)?;
          emit_warnings(result.warnings());
          print_read_result(&format, result, allow_isolation_loss)?;
        }
      }
    }
    JobCommand::Header { send, snapshot } => {
      let result = read_snapshot(snapshot)?;
      print_line_or_exit(&result.header(&send_context(send))?);
    }
    JobCommand::SendView { send, snapshot } => {
      let result = read_snapshot(snapshot)?;
      let view = result.send_view(&send_context(send))?;
      print_line_or_exit(&serde_json::to_string_pretty(&send_view_document(&view))?);
    }
    JobCommand::Browsers => {
      let browsers = rookie_cookies::supported_browsers()?;
      print_line_or_exit(&serde_json::to_string_pretty(&browsers)?);
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

/// Builds the [`PathExtractRequest`] for `credentials`, as selected by
/// [`chromium_credential_selector`].
///
/// `PathExtractRequest`'s browser-identity constructors are themselves
/// `#[cfg(unix)]`/`#[cfg(windows)]` -- a platform mismatch is a build-time
/// absence there, not a runtime check, because that type is the deliberately
/// non-portable half of the pair (see [`FromPathRequest`](rookie_cookies::FromPathRequest),
/// which stays portable for exactly this reason and is what plain `from-path`
/// uses instead -- this is only reached behind `from-path --domains`). The
/// CLI still accepts `--local-state-path`/`--browser-id` on every platform, so
/// a selector this binary cannot construct is turned into a plain usage error
/// here rather than failing to compile only on some targets.
fn path_extract_request(
  path: String,
  credentials: Option<ChromiumCredentialSource>,
) -> std::io::Result<PathExtractRequest> {
  Ok(match credentials {
    None => PathExtractRequest::sniff(path),
    Some(ChromiumCredentialSource::PlaintextOnly) => PathExtractRequest::plaintext(path),
    #[cfg(unix)]
    Some(ChromiumCredentialSource::BrowserId(id)) => PathExtractRequest::unix_identity(path, id),
    #[cfg(not(unix))]
    Some(ChromiumCredentialSource::BrowserId(_)) => {
      return Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "--browser-id is only supported on Unix",
      ))
    }
    #[cfg(windows)]
    Some(ChromiumCredentialSource::LocalStateFile(local_state)) => {
      PathExtractRequest::windows_local_state(path, local_state)
    }
    #[cfg(not(windows))]
    Some(ChromiumCredentialSource::LocalStateFile(_)) => {
      return Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "--local-state-path is only supported on Windows",
      ))
    }
    // `ChromiumCredentialSource` is `#[non_exhaustive]`; `chromium_credential_selector`
    // never builds a fourth variant.
    Some(_) => unreachable!("chromium_credential_selector only builds the variants matched above"),
  })
}

/// The `send-view` JSON object: the selected records, the header they render
/// to, and the full omission table.
///
/// `cookies` is the same serialization `--format detailed` emits, so a
/// consumer can hand a `send-view` record to anything that already reads a
/// detailed row. `omitted` carries **every** reason in
/// `SendOmissions::entries()` order, zeroes included -- a fixed shape is what
/// lets a consumer index it without first checking which keys exist, and the
/// order is the declared serialization order, not the attribution order rows
/// are evaluated in (ADR 0006 Decision 2).
fn send_view_document(view: &rookie_cookies::SendView<'_>) -> serde_json::Value {
  let omitted = view
    .omitted()
    .entries()
    .map(|(reason, count)| (reason.to_owned(), serde_json::Value::from(count)))
    .collect::<serde_json::Map<_, _>>();
  serde_json::json!({
    "cookies": view.to_detailed_cookies(),
    "header": view.header(),
    "omitted": omitted,
  })
}

/// The selector tokens the two send-selection failures name.
///
/// ADR 0006 Decision 5 gives `incomplete_send_context` and
/// `isolation_loss_refused` one shared vocabulary, so a caller who branches
/// on one error's `required` already knows the other's.
fn selector_required(error: &rookie_cookies::Error) -> Option<&[String]> {
  match error {
    rookie_cookies::Error::Request(rookie_cookies::RequestError::IncompleteSendContext {
      required,
      ..
    })
    | rookie_cookies::Error::Request(rookie_cookies::RequestError::IsolationLossRefused {
      required,
      ..
    }) => Some(required),
    _ => None,
  }
}

/// Preserve the human diagnostic while exposing typed library failures to
/// scripts through a stable JSON code.
///
/// Every error object carries `code` and `message`; a given `code` may define
/// further documented fields, and a consumer must ignore keys it does not
/// know rather than reject them (ADR 0006 Decision 6). `required` is the
/// first such field, defined for exactly the two selector codes.
fn render_cli_error(error: &(dyn std::error::Error + 'static)) -> String {
  match error.downcast_ref::<rookie_cookies::Error>() {
    Some(error) => {
      let mut document = serde_json::Map::new();
      document.insert("code".to_owned(), error.code().into());
      document.insert("message".to_owned(), error.to_string().into());
      if let Some(required) = selector_required(error) {
        document.insert("required".to_owned(), required.into());
      }
      serde_json::Value::Object(document).to_string()
    }
    None => error.to_string(),
  }
}

/// `main`'s `Result` return would otherwise print a failing `Err` via `Debug`.
/// Route errors through the explicit renderer so typed library failures expose
/// their stable code and every other failure retains its `Display` diagnostic.
fn main() {
  if let Err(error) = run() {
    eprintln!("{}", render_cli_error(error.as_ref()));
    std::process::exit(1);
  }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
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
    // `#[arg(exclusive = true)]` only rules out other *arguments*; clap's
    // subcommand slot is a separate mechanism it doesn't cover, so a
    // subcommand given alongside `--version` is rejected here by hand.
    if args.command.is_some() {
      command
        .error(
          ErrorKind::ArgumentConflict,
          "the argument '--version' cannot be used with a subcommand",
        )
        .exit();
    }
    print_version();
    return Ok(());
  }
  let Some(job) = args.command else {
    // No subcommand and no `--version`: there is no longer a no-subcommand
    // default action (the old `load()` fallback) to run instead, so this is
    // the same shape clap gives a genuinely required subcommand -- built by
    // hand because `--version`'s `exclusive = true` needs `command` to stay
    // optional for clap's own required-arg check.
    command
      .error(
        ErrorKind::MissingSubcommand,
        "a subcommand is required (read, from-path, header, send-view, report, profiles, browsers)",
      )
      .exit();
  };
  run_job_command(job)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn credential_selector_rejects_every_conflicting_shape() {
    for (local_state_path, browser_id, plaintext_only) in [
      (Some("Local State"), Some("chrome"), false),
      (Some("Local State"), None, true),
      (None, Some("chrome"), true),
      (Some("Local State"), Some("chrome"), true),
    ] {
      let error = chromium_credential_selector(
        local_state_path.map(str::to_owned),
        browser_id.map(str::to_owned),
        plaintext_only,
      )
      .expect_err("conflicting selectors must fail before extraction");

      assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
  }

  #[test]
  fn typed_library_errors_render_a_machine_readable_code() {
    let error = rookie_cookies::Error::from(rookie_cookies::RequestError::MissingBrowser);
    let rendered = render_cli_error(&error);
    let document: serde_json::Value = serde_json::from_str(&rendered).expect("JSON error");
    assert_eq!(document["code"], "missing_browser");
    assert_eq!(document["message"], error.to_string());
    // `required` belongs to the two selector codes only. Emitting it
    // everywhere would tell a consumer that every failure names selectors,
    // when most name nothing of the sort.
    assert_eq!(
      document.as_object().expect("error object").len(),
      2,
      "a non-selector code carries only code and message: {document}"
    );
    assert!(document.get("required").is_none(), "{document}");
  }

  #[test]
  fn the_two_selector_errors_render_their_required_tokens() {
    for error in [
      rookie_cookies::RequestError::IncompleteSendContext {
        display: "https://example.com/".to_owned(),
        required: vec!["top_level_site".to_owned(), "user_context_id".to_owned()],
      },
      rookie_cookies::RequestError::IsolationLossRefused {
        isolated_rows: 3,
        required: vec!["top_level_site".to_owned(), "user_context_id".to_owned()],
      },
    ] {
      let error = rookie_cookies::Error::from(error);
      let rendered = render_cli_error(&error);
      let document: serde_json::Value = serde_json::from_str(&rendered).expect("JSON error");
      assert_eq!(
        document.as_object().expect("error object").len(),
        3,
        "a selector code adds exactly one documented field: {document}"
      );
      assert_eq!(document["code"], error.code());
      assert_eq!(
        document["required"],
        serde_json::json!(["top_level_site", "user_context_id"]),
        "{document}"
      );
    }
  }
}
