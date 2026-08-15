use clap::{builder::PossibleValuesParser, Parser};

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None, disable_version_flag = true)]
pub struct Args {
  /// Path to cookies file
  #[arg(short, long, conflicts_with_all = ["browser", "load"])]
  pub path: Option<String>,

  /// Path to Chromium's Windows Local State file
  #[arg(
    short,
    long,
    requires = "path",
    conflicts_with_all = [
      "browser",
      "load",
      "browser_id",
      "plaintext_only",
      "list_browsers",
      "list_profiles",
      "report",
      "profile"
    ]
  )]
  pub key_path: Option<String>,

  /// Canonical Chromium browser identity for key lookup
  #[arg(
    long,
    requires = "path",
    conflicts_with_all = [
      "browser",
      "load",
      "key_path",
      "plaintext_only",
      "list_browsers",
      "list_profiles",
      "report",
      "profile"
    ]
  )]
  pub browser_id: Option<String>,

  /// Require every Chromium row at --path to be plaintext
  #[arg(
    long,
    requires = "path",
    conflicts_with_all = [
      "browser",
      "load",
      "key_path",
      "browser_id",
      "list_browsers",
      "list_profiles",
      "report",
      "profile"
    ]
  )]
  pub plaintext_only: bool,

  /// Domains to filter
  #[arg(short, long)]
  pub domains: Option<Vec<String>>,

  /// Get version
  #[arg(short, long, exclusive = true)]
  pub version: bool,

  /// Get cookies from specified browser (see --list-browsers)
  #[arg(
    short,
    long,
    conflicts_with_all = ["path", "key_path", "browser_id", "plaintext_only", "load"]
  )]
  pub browser: Option<String>,

  /// Get cookies from all possible browsers
  #[arg(
    short,
    long,
    default_missing_value = "true",
    conflicts_with_all = ["path", "key_path", "browser_id", "plaintext_only", "browser"]
  )]
  pub load: bool,

  /// Specify output format
  #[arg(short, long, value_parser = PossibleValuesParser::new(["netscape", "json"]), default_value = "json")]
  pub format: String,

  /// List registered browsers as JSON
  #[arg(
    long,
    conflicts_with_all = ["browser", "load", "path", "key_path", "browser_id", "plaintext_only", "domains", "list_profiles", "report", "profile"]
  )]
  pub list_browsers: bool,

  /// List the discovered profiles of --browser as JSON
  #[arg(
    long,
    requires = "browser",
    conflicts_with_all = ["load", "path", "key_path", "browser_id", "plaintext_only", "domains", "report", "profile"]
  )]
  pub list_profiles: bool,

  /// Emit a structured extraction report as JSON
  #[arg(
    long,
    conflicts_with_all = ["load", "path", "key_path", "browser_id", "plaintext_only"]
  )]
  pub report: bool,

  /// Restrict --report to one profile ID from --list-profiles
  #[arg(long, requires_all = ["report", "browser"])]
  pub profile: Option<String>,
}

impl Args {
  /// True when a Section 5.8 list/report mode is selected, which is what
  /// widens `--browser` from the legacy map to the registry.
  pub fn is_generic_mode(&self) -> bool {
    self.list_browsers || self.list_profiles || self.report
  }
}
