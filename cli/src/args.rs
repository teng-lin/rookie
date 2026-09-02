use clap::{builder::PossibleValuesParser, Args as ClapArgs, Parser, Subcommand};

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

/// Shared `--ancestor-chain` values, in the CLI's kebab-case spelling;
/// `main.rs::parse_ancestor_chain` maps these to
/// [`rookie_cookies::AncestorChain`].
const ANCESTOR_CHAIN_VALUES: [&str; 2] = ["same-site", "cross-site"];

/// Every selector `header` and `send-view` accept, in one place.
///
/// ADR 0006 Decision 1 makes the send selector one flat list of "what I know
/// about this request" -- there is no nested selector object in any language,
/// so there is none here either. Sharing the struct across both subcommands is
/// what keeps them from drifting into two spellings of the same question.
#[derive(ClapArgs, Debug, Clone)]
pub struct SendContextArgs {
  /// The request URL. `http` and `https` only
  #[arg(long)]
  pub url: String,
  /// The top-level site the request is made from; required once the
  /// snapshot holds any CHIPS-partitioned or Firefox-containered cookie.
  /// Supply it already normalized to a registrable site -- the crate has no
  /// public-suffix list and never infers one
  #[arg(long)]
  pub top_level_site: Option<String>,
  #[arg(long, value_parser = PossibleValuesParser::new(["navigation", "subresource"]))]
  pub resource: Option<String>,
  #[arg(long, value_parser = PossibleValuesParser::new(["safe", "unsafe"]))]
  pub method: Option<String>,
  /// Firefox Multi-Account Containers identity
  #[arg(long)]
  pub user_context_id: Option<u32>,
  /// Firefox private-browsing identity
  #[arg(long)]
  pub private_browsing_id: Option<u32>,
  /// Whether the frame tree has a cross-site ancestor. Derived from the
  /// request and top-level sites when omitted; state it to describe an
  /// `A -> B -> A` embed, whose two sites are equal
  #[arg(long, value_parser = PossibleValuesParser::new(ANCESTOR_CHAIN_VALUES))]
  pub ancestor_chain: Option<String>,
  /// Firefox `firstPartyDomain` origin attribute
  #[arg(long)]
  pub first_party_domain: Option<String>,
  /// Firefox `geckoViewSessionContextId` origin attribute
  #[arg(long)]
  pub gecko_view_session_context_id: Option<String>,
  /// A Firefox row's verbatim `originAttributes` suffix. Selects only rows
  /// whose identity this build cannot decompose; it is never a bypass for
  /// the typed selectors or the partition key
  #[arg(long)]
  pub origin_attributes: Option<String>,
  /// Send-time expiry clock, in Unix epoch seconds. Defaults to now
  #[arg(long)]
  pub now: Option<u64>,
}

/// The snapshot half of a send-selecting subcommand: which profile to read,
/// and under what execution policy.
#[derive(ClapArgs, Debug, Clone)]
pub struct SnapshotArgs {
  /// Canonical browser ID or registered alias
  #[arg(short, long)]
  pub browser: String,
  /// Profile id, display name, directory, or path
  #[arg(short, long)]
  pub profile: Option<String>,
  /// Also acquire the browser's declared session store
  #[arg(long)]
  pub include_session: bool,
  #[arg(long)]
  pub timeout_secs: Option<u64>,
  /// Windows App-Bound (v20) recovery policy
  #[arg(long, value_parser = PossibleValuesParser::new(APP_BOUND_VALUES))]
  pub app_bound: Option<String>,
}

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
    /// Emit `--format json|netscape` even when the snapshot holds isolated
    /// cookies those flat shapes cannot carry. Without it such a snapshot is
    /// refused (`isolation_loss_refused`); `--format detailed` never needs it
    #[arg(long)]
    allow_isolation_loss: bool,
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
    /// Compatibility-only: `--domains` routes through the flat
    /// `extract_from_path` job, which carries no warnings and no isolation
    /// context, so it takes none of the send-selector surface
    #[arg(short, long)]
    domains: Option<Vec<String>>,
    /// Emit `--format json|netscape` even when the snapshot holds isolated
    /// cookies those flat shapes cannot carry. Without it such a snapshot is
    /// refused (`isolation_loss_refused`); `--format detailed` never needs it
    #[arg(long)]
    allow_isolation_loss: bool,
    #[arg(long)]
    timeout_secs: Option<u64>,
    /// Windows App-Bound (v20) recovery policy
    #[arg(long, value_parser = PossibleValuesParser::new(APP_BOUND_VALUES))]
    app_bound: Option<String>,
  },
  /// Cookie request-header value for one send context
  Header {
    #[command(flatten)]
    send: SendContextArgs,
    #[command(flatten)]
    snapshot: SnapshotArgs,
  },
  /// The selection behind `header`, as one JSON object: the selected
  /// detailed records, the rendered header, and why every other row was
  /// left out
  #[command(name = "send-view")]
  SendView {
    #[command(flatten)]
    send: SendContextArgs,
    #[command(flatten)]
    snapshot: SnapshotArgs,
  },
  /// List every browser registered for the running OS (no filesystem access)
  Browsers,
}
