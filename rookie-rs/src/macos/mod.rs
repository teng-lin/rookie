use anyhow::{anyhow, Context, Result};

use crate::common::deadline::{Clock, Deadline, CLEANUP_GRACE};
use crate::common::secret::{SecretBytes, SecretString};
use std::{
  io::Read,
  process::{Child, Command, ExitStatus, Stdio},
  time::Duration,
};
use zeroize::Zeroize;

const KEYCHAIN_OUTPUT_LIMIT: usize = 1024 * 1024;
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(10);

fn keychain_lookup_error(exit_code: Option<i32>, stderr_len: usize) -> anyhow::Error {
  let kind = match exit_code {
    // `security` returns errSecItemNotFound unchanged as its process status.
    Some(44) => "item not found",
    // Authorization cancellation and denial are commonly surfaced as 128.
    Some(128) => "access denied or interaction canceled",
    _ => "lookup command failed",
  };
  let status = exit_code
    .map(|code| format!("exit code {code}"))
    .unwrap_or_else(|| "terminated without an exit code".to_string());
  anyhow!("macOS Keychain {kind} ({status}; stderr redacted, {stderr_len} byte(s))")
}

pub(crate) fn get_osx_keychain_password_with_deadline(
  osx_key_service: &str,
  osx_key_user: &str,
  clock: &dyn Clock,
  deadline: Deadline,
) -> Result<SecretString> {
  deadline
    .check(clock)
    .context("macOS Keychain lookup timed out before spawn")?;
  let mut child = Command::new("/usr/bin/security")
    .args([
      "-q",
      "find-generic-password",
      "-w",
      "-a",
      osx_key_user,
      "-s",
      osx_key_service,
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .context("failed to spawn macOS Keychain helper")?;
  let stdout = child
    .stdout
    .take()
    .context("Keychain stdout pipe missing")?;
  let stderr = child
    .stderr
    .take()
    .context("Keychain stderr pipe missing")?;
  // Drain both pipes concurrently so a chatty helper cannot block before the
  // supervisor observes the deadline. Buffers are secret-owned from their
  // first retained byte and capped independently.
  let stdout = std::thread::spawn(move || drain_secret_stream(stdout));
  let stderr = std::thread::spawn(move || drain_secret_stream(stderr));
  let status = supervise_child(&mut child, clock, deadline)?;
  let stdout = stdout
    .join()
    .map_err(|_| anyhow!("macOS Keychain stdout drain failed"))??;
  let stderr = stderr
    .join()
    .map_err(|_| anyhow!("macOS Keychain stderr drain failed"))??;

  if !status.success() {
    return Err(keychain_lookup_error(status.code(), stderr.len()));
  }

  let password = stdout
    .into_secret_string()
    .context("macOS Keychain password is not valid UTF-8")?;
  Ok(password.trimmed())
}

fn drain_secret_stream(mut stream: impl Read) -> Result<SecretBytes> {
  let mut retained = SecretBytes::new(Vec::new());
  let mut buffer = [0_u8; 8192];
  loop {
    let count = stream.read(&mut buffer)?;
    if count == 0 {
      break;
    }
    retained.extend_bounded(&buffer[..count], KEYCHAIN_OUTPUT_LIMIT);
    buffer[..count].zeroize();
  }
  buffer.zeroize();
  Ok(retained)
}

trait ChildControl {
  type Status;
  fn try_wait(&mut self) -> std::io::Result<Option<Self::Status>>;
  fn kill(&mut self) -> std::io::Result<()>;
}

impl ChildControl for Child {
  type Status = ExitStatus;

  fn try_wait(&mut self) -> std::io::Result<Option<Self::Status>> {
    Child::try_wait(self)
  }

  fn kill(&mut self) -> std::io::Result<()> {
    Child::kill(self)
  }
}

fn supervise_child<C: ChildControl>(
  child: &mut C,
  clock: &dyn Clock,
  deadline: Deadline,
) -> Result<C::Status> {
  loop {
    if let Some(status) = child.try_wait().context("failed to poll Keychain helper")? {
      return Ok(status);
    }
    let remaining = deadline.remaining(clock);
    if remaining.is_zero() {
      break;
    }
    clock.sleep(remaining.min(CHILD_POLL_INTERVAL));
  }

  child
    .kill()
    .context("failed to kill timed-out Keychain helper")?;
  let cleanup_deadline = deadline.cleanup_deadline(CLEANUP_GRACE);
  loop {
    if let Some(_status) = child
      .try_wait()
      .context("failed to reap timed-out Keychain helper")?
    {
      return Err(anyhow!("macOS Keychain lookup timed out"));
    }
    let remaining = cleanup_deadline.remaining(clock);
    if remaining.is_zero() {
      return Err(anyhow!(
        "macOS Keychain helper did not exit during cleanup grace"
      ));
    }
    clock.sleep(remaining.min(CHILD_POLL_INTERVAL));
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::common::deadline::test_clock::ManualClock;
  use std::collections::VecDeque;

  struct FakeChild {
    states: VecDeque<Option<()>>,
    killed: usize,
    polls: usize,
  }

  impl ChildControl for FakeChild {
    type Status = ();

    fn try_wait(&mut self) -> std::io::Result<Option<Self::Status>> {
      self.polls += 1;
      Ok(self.states.pop_front().unwrap_or(None))
    }

    fn kill(&mut self) -> std::io::Result<()> {
      self.killed += 1;
      Ok(())
    }
  }

  #[test]
  fn keychain_errors_preserve_status_and_redact_stderr() {
    let sentinel = "rookie-secret-sentinel-7e8b";
    let error = keychain_lookup_error(Some(44), sentinel.len()).to_string();
    assert!(error.contains("item not found"));
    assert!(error.contains("exit code 44"));
    assert!(error.contains("stderr redacted"));
    assert!(!error.contains(sentinel));
  }

  #[test]
  fn keychain_errors_distinguish_access_denial() {
    let error = keychain_lookup_error(Some(128), 32).to_string();
    assert!(error.contains("access denied or interaction canceled"));
    assert!(error.contains("exit code 128"));
  }

  #[test]
  fn keychain_stderr_reports_only_bounded_metadata() {
    let error = keychain_lookup_error(None, usize::MAX).to_string();
    assert!(error.contains("stderr redacted"));
    assert!(error.contains(&usize::MAX.to_string()));
  }

  #[test]
  fn hung_keychain_child_is_killed_and_reaped_with_one_absolute_grace() {
    let clock = ManualClock::default();
    let deadline = Deadline::after(&clock, Duration::from_millis(25));
    let mut child = FakeChild {
      states: [None, None, None, None, Some(())].into(),
      killed: 0,
      polls: 0,
    };
    let error = supervise_child(&mut child, &clock, deadline).expect_err("timeout");
    assert!(error.to_string().contains("timed out"));
    assert_eq!(child.killed, 1);
    assert_eq!(child.polls, 5);
    assert!(deadline
      .cleanup_deadline(CLEANUP_GRACE)
      .check(&clock)
      .is_ok());
  }
}
