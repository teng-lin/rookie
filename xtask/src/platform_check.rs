use std::path::Path;
use std::process::Command;

const CARGO_ZIGBUILD_VERSION: &str = "0.23.0";
const ZIG_VERSION: &str = "0.16.0";
const CROSS_TARGETS: [&str; 2] = ["x86_64-unknown-linux-gnu", "x86_64-pc-windows-gnu"];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Options {
  pub(crate) skip_host: bool,
}

impl Options {
  pub(crate) fn parse(args: &[String]) -> Result<Self, String> {
    let mut options = Self::default();
    for arg in args {
      match arg.as_str() {
        "--skip-host" if !options.skip_host => options.skip_host = true,
        "--skip-host" => return Err("--skip-host may only be supplied once".to_owned()),
        other => return Err(format!("unknown check-platforms option {other:?}")),
      }
    }
    Ok(options)
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommandSpec {
  program: &'static str,
  args: Vec<&'static str>,
}

impl CommandSpec {
  fn new(program: &'static str, args: &[&'static str]) -> Self {
    Self {
      program,
      args: args.to_vec(),
    }
  }

  fn display(&self) -> String {
    std::iter::once(self.program)
      .chain(self.args.iter().copied())
      .collect::<Vec<_>>()
      .join(" ")
  }
}

pub(crate) fn commands(options: Options) -> Vec<CommandSpec> {
  let mut commands = Vec::with_capacity(if options.skip_host { 2 } else { 3 });
  if !options.skip_host {
    commands.push(CommandSpec::new(
      "cargo",
      &[
        "clippy",
        "--workspace",
        "--all-targets",
        "--all-features",
        "--locked",
        "--",
        "-D",
        "warnings",
      ],
    ));
  }
  commands.push(CommandSpec::new(
    "cargo-zigbuild",
    &[
      "clippy",
      "--target",
      "x86_64-unknown-linux-gnu",
      "--workspace",
      "--all-targets",
      "--all-features",
      "--locked",
      "--",
      "-D",
      "warnings",
    ],
  ));
  commands.push(CommandSpec::new(
    "cargo-zigbuild",
    &[
      "clippy",
      "--target",
      "x86_64-pc-windows-gnu",
      "-p",
      "rookie-cookies",
      "--all-targets",
      "--no-default-features",
      "--features",
      "appbound",
      "--locked",
      "--",
      "-D",
      "warnings",
    ],
  ));
  commands
}

pub(crate) fn run(root: &Path, options: Options) -> Result<(), String> {
  check_prerequisites(root)?;

  for command in commands(options) {
    eprintln!("+ {}", command.display());
    let status = Command::new(command.program)
      .args(&command.args)
      .current_dir(root)
      .status()
      .map_err(|error| format!("failed to start `{}`: {error}", command.display()))?;
    if !status.success() {
      return Err(format!("`{}` failed with {status}", command.display()));
    }
  }

  Ok(())
}

fn check_prerequisites(root: &Path) -> Result<(), String> {
  require_exact_version(
    root,
    "cargo-zigbuild",
    &["--version"],
    "cargo-zigbuild",
    CARGO_ZIGBUILD_VERSION,
    "cargo install cargo-zigbuild --version 0.23.0 --locked",
  )?;
  require_exact_version(
    root,
    "zig",
    &["version"],
    "Zig",
    ZIG_VERSION,
    "install Zig 0.16.0 from https://ziglang.org/download/",
  )?;

  let clippy = command_output(
    root,
    "cargo",
    &["clippy", "--version"],
    "rustup component add clippy",
  )?;
  println!("prerequisite: {}", clippy.trim());

  let installed = command_output(
    root,
    "rustup",
    &["target", "list", "--installed"],
    "install rustup from https://rustup.rs/",
  )?;
  let installed: std::collections::BTreeSet<&str> = installed.lines().map(str::trim).collect();
  let missing: Vec<&str> = CROSS_TARGETS
    .into_iter()
    .filter(|target| !installed.contains(target))
    .collect();
  if !missing.is_empty() {
    return Err(format!(
      "missing Rust target(s): {}\ninstall them with: rustup target add {}",
      missing.join(", "),
      missing.join(" ")
    ));
  }
  println!("prerequisite: Rust targets {}", CROSS_TARGETS.join(", "));

  Ok(())
}

fn require_exact_version(
  root: &Path,
  program: &str,
  args: &[&str],
  label: &str,
  expected: &str,
  install: &str,
) -> Result<(), String> {
  let output = command_output(root, program, args, install)?;
  let actual = last_version_component(&output)
    .ok_or_else(|| format!("could not read {label} version from {output:?}"))?;
  if actual != expected {
    return Err(format!(
      "{label} {expected} is required, but found {actual}\ninstall it with: {install}"
    ));
  }
  println!("prerequisite: {label} {actual}");
  Ok(())
}

fn command_output(
  root: &Path,
  program: &str,
  args: &[&str],
  install: &str,
) -> Result<String, String> {
  let output = Command::new(program)
    .args(args)
    .current_dir(root)
    .output()
    .map_err(|error| format!("could not run `{program}`: {error}\ninstall it with: {install}"))?;
  if !output.status.success() {
    let stderr = String::from_utf8_lossy(&output.stderr);
    return Err(format!(
      "`{}` failed with {}: {}\ninstall or repair it with: {install}",
      std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" "),
      output.status,
      stderr.trim()
    ));
  }
  String::from_utf8(output.stdout)
    .map_err(|error| format!("`{program}` returned non-UTF-8 output: {error}"))
}

fn last_version_component(output: &str) -> Option<&str> {
  output.split_whitespace().last()
}

#[cfg(test)]
mod tests {
  use super::*;

  fn rendered(options: Options) -> Vec<String> {
    commands(options).iter().map(CommandSpec::display).collect()
  }

  #[test]
  fn constructs_the_exact_three_platform_commands() {
    assert_eq!(
      rendered(Options::default()),
      vec![
        "cargo clippy --workspace --all-targets --all-features --locked -- -D warnings",
        "cargo-zigbuild clippy --target x86_64-unknown-linux-gnu --workspace --all-targets \
         --all-features --locked -- -D warnings",
        "cargo-zigbuild clippy --target x86_64-pc-windows-gnu -p rookie-cookies --all-targets \
         --no-default-features --features appbound --locked -- -D warnings",
      ]
    );
  }

  #[test]
  fn skip_host_keeps_both_cross_commands_in_order() {
    let commands = rendered(Options { skip_host: true });
    assert_eq!(commands.len(), 2);
    assert!(commands[0].contains("x86_64-unknown-linux-gnu"));
    assert!(commands[1].contains("x86_64-pc-windows-gnu"));
    assert!(commands
      .iter()
      .all(|command| command.starts_with("cargo-zigbuild ")));
  }

  #[test]
  fn parses_skip_host_and_rejects_unknown_or_duplicate_options() {
    assert_eq!(Options::parse(&[]).unwrap(), Options::default());
    assert_eq!(
      Options::parse(&["--skip-host".to_owned()]).unwrap(),
      Options { skip_host: true }
    );
    assert!(Options::parse(&["--unknown".to_owned()])
      .unwrap_err()
      .contains("unknown"));
    assert!(
      Options::parse(&["--skip-host".to_owned(), "--skip-host".to_owned()])
        .unwrap_err()
        .contains("only be supplied once")
    );
  }

  #[test]
  fn reads_versions_from_supported_tool_output() {
    assert_eq!(
      last_version_component("cargo-zigbuild 0.23.0\n"),
      Some("0.23.0")
    );
    assert_eq!(last_version_component("0.16.0\n"), Some("0.16.0"));
    assert_eq!(last_version_component("  \n"), None);
  }
}
