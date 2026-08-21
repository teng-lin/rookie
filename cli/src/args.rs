use clap::{builder::PossibleValuesParser, Parser, Subcommand};

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None, disable_version_flag = true)]
pub struct Args {
  /// Get version
  #[arg(short, long, exclusive = true)]
  pub version: bool,

  /// `None` only when neither a subcommand nor `--version` was given --
  /// `main.rs::run` turns that into a clap-shaped usage error itself, since
  /// there is no longer a no-subcommand default action (`load()`) to fall
  /// back to.
  #[command(subcommand)]
  pub command: Option<JobCommand>,
}

/// Shared `--app-bound` values across every subcommand, in the CLI's
/// kebab-case spelling; `main.rs::parse_app_bound` maps these to
/// [`rookie_cookies::AppBoundPolicy`].
const APP_BOUND_VALUES: [&str; 3] = ["disabled", "injection-only", "allow-elevated-fallback"];

/// Shared `--select` values. `read` defaults to `legacy-first`; `report`
/// defaults to `all`. `all` is a report-only widening a snapshot cannot
/// express -- core `ProfileSelection::from_binding_options` /
/// `ReportScope::from_binding_options` validate the flattened CLI shape.
const SELECT_VALUES: [&str; 2] = ["legacy-first", "all"];

#[derive(Subcommand, Debug, Clone)]
pub enum JobCommand {
  /// Unfiltered snapshot of one browser profile
  Read {
    /// Canonical browser ID or registered alias
    #[arg(short, long)]
    browser: String,
    /// Profile id, display name, directory, or path
    #[arg(short, long)]
    profile: Option<String>,
    /// Keep expired cookies
    #[arg(long)]
    include_expired: bool,
    /// Also acquire the browser's declared session store
    #[arg(long)]
    include_session: bool,
    /// `all` is rejected: a snapshot has no "every profile" shape (see `report`)
    #[arg(long, value_parser = PossibleValuesParser::new(SELECT_VALUES))]
    select: Option<String>,
    #[arg(short, long, value_parser = PossibleValuesParser::new(["netscape", "json", "detailed"]), default_value = "json")]
    format: String,
    #[arg(long)]
    timeout_secs: Option<u64>,
    /// Windows App-Bound (v20) recovery policy
    #[arg(long, value_parser = PossibleValuesParser::new(APP_BOUND_VALUES))]
    app_bound: Option<String>,
  },
  /// List discovered profiles (no decrypt)
  // No `--app-bound`: listing never reaches the v20 key lookup, so the
  // design's binding table gives `browser_profiles`/`profiles` only
  // `timeout`/`cancellation` -- an App-Bound knob here would silently do
  // nothing.
  Profiles {
    browser: String,
    #[arg(long)]
    timeout_secs: Option<u64>,
  },
  /// Structured extraction report. Omitting `--browser` reports every
  /// registered browser (the `load_report` fan-out).
  Report {
    #[arg(short, long)]
    browser: Option<String>,
    #[arg(short, long, requires = "browser")]
    profile: Option<String>,
    #[arg(short, long)]
    domains: Option<Vec<String>>,
    /// Defaults to `all`: every installation and profile of `--browser`
    #[arg(long, requires = "browser", value_parser = PossibleValuesParser::new(SELECT_VALUES))]
    select: Option<String>,
    #[arg(long)]
    timeout_secs: Option<u64>,
    /// Windows App-Bound (v20) recovery policy
    #[arg(long, value_parser = PossibleValuesParser::new(APP_BOUND_VALUES))]
    app_bound: Option<String>,
  },
  /// Read cookies from an explicit cookie database path
  #[command(name = "from-path")]
  FromPath {
    path: String,
    #[arg(long)]
    include_expired: bool,
    /// `detailed` is unavailable together with `--domains`: that combination
    /// runs through `extract_from_path`'s flat, non-detailed job instead of
    /// `from_path`'s portable, isolation-carrying one -- see main.rs.
    #[arg(short, long, value_parser = PossibleValuesParser::new(["netscape", "json", "detailed"]), default_value = "json")]
    format: String,
    #[arg(long, conflicts_with_all = ["browser_id", "plaintext_only"])]
    local_state_path: Option<String>,
    #[arg(long, conflicts_with_all = ["local_state_path", "plaintext_only"])]
    browser_id: Option<String>,
    #[arg(long, conflicts_with_all = ["local_state_path", "browser_id"])]
    plaintext_only: bool,
    #[arg(short, long)]
    domains: Option<Vec<String>>,
    #[arg(long)]
    timeout_secs: Option<u64>,
    /// Windows App-Bound (v20) recovery policy
    #[arg(long, value_parser = PossibleValuesParser::new(APP_BOUND_VALUES))]
    app_bound: Option<String>,
  },
  /// Cookie request-header view over a snapshot, for one `SendContext`
  Header {
    #[arg(long)]
    url: String,
    #[arg(short, long)]
    browser: String,
    #[arg(short, long)]
    profile: Option<String>,
    /// The top-level site the request is made from; required once the
    /// snapshot holds any CHIPS-partitioned or Firefox-containered cookie
    #[arg(long)]
    top_level_site: Option<String>,
    #[arg(long, value_parser = PossibleValuesParser::new(["navigation", "subresource"]))]
    resource: Option<String>,
    #[arg(long, value_parser = PossibleValuesParser::new(["safe", "unsafe"]))]
    method: Option<String>,
    /// Firefox Multi-Account Containers identity
    #[arg(long)]
    user_context_id: Option<u32>,
    /// Firefox private-browsing identity
    #[arg(long)]
    private_browsing_id: Option<u32>,
    /// Also acquire the browser's declared session store
    #[arg(long)]
    include_session: bool,
    #[arg(long)]
    timeout_secs: Option<u64>,
    /// Windows App-Bound (v20) recovery policy
    #[arg(long, value_parser = PossibleValuesParser::new(APP_BOUND_VALUES))]
    app_bound: Option<String>,
  },
  /// List every browser registered for the running OS (no filesystem access)
  Browsers,
}
