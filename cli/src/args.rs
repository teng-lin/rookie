use crate::browsers_map;
use clap::{builder::PossibleValuesParser, Parser};

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None, disable_version_flag = true)]
pub struct Args {
  /// Path to cookies file
  #[arg(short, long, conflicts_with_all = ["browser", "load"])]
  pub path: Option<String>,

  /// Path to cookies encryption key
  #[arg(short, long, requires = "path", conflicts_with_all = ["browser", "load"])]
  pub key_path: Option<String>,

  /// Domains to filter
  #[arg(short, long)]
  pub domains: Option<Vec<String>>,

  /// Get version
  #[arg(short, long, exclusive = true)]
  pub version: bool,

  /// Get cookies from specified browser
  #[arg(short, long, value_parser = browser_keys(), conflicts_with_all = ["path", "key_path", "load"])]
  pub browser: Option<String>,

  /// Get cookies from all possible browsers
  #[arg(short, long, default_missing_value = "true", conflicts_with_all = ["path", "key_path", "browser"])]
  pub load: bool,

  /// Specify output format
  #[arg(short, long, value_parser = PossibleValuesParser::new(["netscape", "json"]), default_value = "json")]
  pub format: String,
}

fn browser_keys() -> PossibleValuesParser {
  let keys: Vec<&str> = browsers_map::BROWSERS_MAP.keys().copied().collect();
  PossibleValuesParser::new(keys)
}
