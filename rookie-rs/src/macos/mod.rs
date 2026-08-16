use anyhow::{anyhow, bail, Context, Result};

use crate::common::deadline::{BoundaryRuntime, BoundaryStop, Deadline, CLEANUP_GRACE};
use crate::common::secret::{SecretBytes, SecretString};
use std::{
  io::{self, Read},
  os::fd::AsRawFd,
  process::{Child, Command, ExitStatus, Stdio},
  time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

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

pub(crate) fn get_osx_keychain_password_with_runtime(
  osx_key_service: &str,
  osx_key_user: &str,
  runtime: &BoundaryRuntime<'_>,
) -> Result<SecretString> {
  runtime
    .check()
    .context("macOS Keychain lookup stopped before spawn")?;
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
  // Keep both pipes nonblocking and drain them in the same bounded loop that
  // supervises the helper. A descendant that inherits either descriptor can
  // therefore never strand an outer drain-thread join after the request (or
  // its cleanup ceiling) has expired.
  let (status, stdout, stderr) = supervise_keychain_child(&mut child, stdout, stderr, runtime)?;

  if !status.success() {
    return Err(keychain_lookup_error(status.code(), stderr.len()));
  }

  let password = stdout
    .into_secret_string()
    .context("macOS Keychain password is not valid UTF-8")?;
  Ok(password.trimmed())
}

struct SecretDrain<R> {
  stream: R,
  stream_name: &'static str,
  retained: SecretBytes,
  buffer: Zeroizing<[u8; 8192]>,
  total_len: usize,
  eof: bool,
}

impl<R: Read> SecretDrain<R> {
  fn new(stream: R, stream_name: &'static str) -> Self {
    Self {
      stream,
      stream_name,
      retained: SecretBytes::new(Vec::new()),
      buffer: Zeroizing::new([0_u8; 8192]),
      total_len: 0,
      eof: false,
    }
  }

  fn drain_available(&mut self) -> Result<()> {
    while !self.eof {
      // This explicit wipe makes every read start with a zeroed buffer. The
      // `Zeroizing` guard also covers panics and any return below.
      self.buffer.zeroize();
      let result = self.stream.read(self.buffer.as_mut());
      match result {
        Ok(0) => self.eof = true,
        Ok(count) => {
          self
            .retained
            .extend_bounded(&self.buffer[..count], KEYCHAIN_OUTPUT_LIMIT);
          self.total_len = self.total_len.saturating_add(count);
          self.buffer.zeroize();
          if self.total_len > KEYCHAIN_OUTPUT_LIMIT {
            bail!(
              "macOS Keychain {} exceeded the {KEYCHAIN_OUTPUT_LIMIT} byte output limit ({} byte(s)); output redacted",
              self.stream_name,
              self.total_len
            );
          }
        }
        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
        Err(error) => {
          self.buffer.zeroize();
          return Err(error)
            .with_context(|| format!("failed to drain macOS Keychain {}", self.stream_name));
        }
      }
    }
    Ok(())
  }

  fn is_eof(&self) -> bool {
    self.eof
  }

  fn into_retained(self) -> SecretBytes {
    self.retained
  }
}

#[cfg(test)]
fn drain_secret_stream(stream: impl Read, stream_name: &'static str) -> Result<SecretBytes> {
  let mut drain = SecretDrain::new(stream, stream_name);
  drain.drain_available()?;
  if !drain.is_eof() {
    bail!("macOS Keychain {stream_name} drain unexpectedly blocked");
  }
  Ok(drain.into_retained())
}

fn set_nonblocking(stream: &impl AsRawFd, stream_name: &'static str) -> Result<()> {
  let descriptor = stream.as_raw_fd();
  // SAFETY: `descriptor` is borrowed from the live child-pipe object and both
  // fcntl operations preserve ownership of it.
  let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
  if flags == -1 {
    return Err(io::Error::last_os_error())
      .with_context(|| format!("failed to inspect macOS Keychain {stream_name} pipe flags"));
  }
  // SAFETY: same live descriptor; `O_NONBLOCK` is a valid status flag.
  if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
    return Err(io::Error::last_os_error())
      .with_context(|| format!("failed to bound macOS Keychain {stream_name} pipe drain"));
  }
  Ok(())
}

fn supervise_keychain_child(
  child: &mut Child,
  stdout: std::process::ChildStdout,
  stderr: std::process::ChildStderr,
  runtime: &BoundaryRuntime<'_>,
) -> Result<(ExitStatus, SecretBytes, SecretBytes)> {
  if let Err(error) = set_nonblocking(&stdout, "stdout") {
    return Err(cleanup_keychain_child(child, runtime, error));
  }
  if let Err(error) = set_nonblocking(&stderr, "stderr") {
    return Err(cleanup_keychain_child(child, runtime, error));
  }

  let mut stdout = SecretDrain::new(stdout, "stdout");
  let mut stderr = SecretDrain::new(stderr, "stderr");
  let mut status = None;
  loop {
    if let Err(stop) = runtime.check() {
      if status.is_some() {
        return Err(stop.into());
      }
      return Err(cleanup_keychain_child(
        child,
        runtime,
        anyhow::Error::new(stop),
      ));
    }
    if let Err(error) = stdout.drain_available() {
      if status.is_some() {
        return Err(error);
      }
      return Err(cleanup_keychain_child(child, runtime, error));
    }
    if let Err(error) = stderr.drain_available() {
      if status.is_some() {
        return Err(error);
      }
      return Err(cleanup_keychain_child(child, runtime, error));
    }
    if status.is_none() {
      match child.try_wait() {
        Ok(Some(child_status)) => {
          // A terminal request observed with the native result wins the tie.
          runtime.check()?;
          status = Some(child_status);
        }
        Ok(None) => {}
        Err(error) => {
          return Err(cleanup_keychain_child(
            child,
            runtime,
            anyhow::Error::new(error).context("failed to poll Keychain helper"),
          ));
        }
      }
    }
    if stdout.is_eof() && stderr.is_eof() {
      if let Some(status) = status {
        runtime.check()?;
        return Ok((status, stdout.into_retained(), stderr.into_retained()));
      }
    }
    let remaining = runtime.deadline.remaining(runtime.clock);
    runtime.clock.sleep(remaining.min(CHILD_POLL_INTERVAL));
  }
}

fn cleanup_keychain_child(
  child: &mut Child,
  runtime: &BoundaryRuntime<'_>,
  cause: anyhow::Error,
) -> anyhow::Error {
  match stop_and_reap_child(child, runtime, cause) {
    Err(error) => error,
    Ok(_) => unreachable!("stopped Keychain cleanup cannot return a successful status"),
  }
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

#[cfg(test)]
fn supervise_child<C: ChildControl>(
  child: &mut C,
  runtime: &BoundaryRuntime<'_>,
) -> Result<C::Status> {
  loop {
    if let Err(stop) = runtime.check() {
      return stop_and_reap_child(child, runtime, anyhow::Error::new(stop));
    }
    match child.try_wait() {
      Ok(Some(status)) => {
        // A terminal request observed with the native result wins the tie.
        runtime.check()?;
        return Ok(status);
      }
      Ok(None) => {}
      Err(error) => {
        return stop_and_reap_child(
          child,
          runtime,
          anyhow::Error::new(error).context("failed to poll Keychain helper"),
        );
      }
    }
    let remaining = runtime.deadline.remaining(runtime.clock);
    runtime.clock.sleep(remaining.min(CHILD_POLL_INTERVAL));
  }
}

fn stop_and_reap_child<C: ChildControl>(
  child: &mut C,
  runtime: &BoundaryRuntime<'_>,
  cause: anyhow::Error,
) -> Result<C::Status> {
  // A process can exit between the terminal sample and `kill`. Preserve the
  // original stop/poll cause, but still poll until the child is reaped.
  let mut kill_error = child.kill().err();
  let cleanup_deadline = if cause
    .downcast_ref::<BoundaryStop>()
    .is_some_and(|stop| *stop == BoundaryStop::TimedOut)
  {
    runtime.deadline.cleanup_deadline(CLEANUP_GRACE)
  } else {
    Deadline::after(runtime.clock, CLEANUP_GRACE)
  };
  let mut reap_error = None;
  loop {
    // Cleanup is derived from the original deadline. An exit observed exactly
    // at the cleanup ceiling does not extend that ceiling by one final poll.
    if cleanup_deadline.remaining(runtime.clock).is_zero() {
      if let Some(error) = kill_error.take() {
        return Err(cause.context(format!("failed to kill stopped Keychain helper: {error}")));
      }
      if let Some(error) = reap_error {
        return Err(cause.context(format!(
          "failed to reap stopped Keychain helper during cleanup grace: {error}"
        )));
      }
      return Err(cause.context("macOS Keychain helper did not exit during cleanup grace"));
    }
    match child.try_wait() {
      Ok(Some(_status)) => return Err(cause),
      Ok(None) => {}
      Err(error) => reap_error = Some(error),
    }
    let remaining = cleanup_deadline.remaining(runtime.clock);
    runtime.clock.sleep(remaining.min(CHILD_POLL_INTERVAL));
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::common::deadline::test_clock::ManualClock;
  use std::collections::VecDeque;
  use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
  };

  struct CountingZeroCheckedReader {
    remaining: usize,
    bytes_read: Arc<AtomicUsize>,
  }

  impl Read for CountingZeroCheckedReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
      assert!(
        buffer.iter().all(|byte| *byte == 0),
        "the previous secret chunk must be wiped before the next read"
      );
      let count = self.remaining.min(buffer.len());
      buffer[..count].fill(b'x');
      self.remaining -= count;
      self.bytes_read.fetch_add(count, Ordering::SeqCst);
      Ok(count)
    }
  }

  struct ErrorAfterSecretChunk {
    returned_chunk: bool,
  }

  impl Read for ErrorAfterSecretChunk {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
      assert!(
        buffer.iter().all(|byte| *byte == 0),
        "the previous secret chunk must be wiped before an error"
      );
      if self.returned_chunk {
        buffer[..16].copy_from_slice(b"redacted-secret!");
        return Err(std::io::Error::other("scripted drain failure"));
      }
      self.returned_chunk = true;
      buffer[..16].copy_from_slice(b"redacted-secret!");
      Ok(16)
    }
  }

  struct FakeChild {
    states: VecDeque<Option<()>>,
    killed: usize,
    polls: usize,
    kill_error: Option<std::io::ErrorKind>,
  }

  impl ChildControl for FakeChild {
    type Status = ();

    fn try_wait(&mut self) -> std::io::Result<Option<Self::Status>> {
      self.polls += 1;
      Ok(self.states.pop_front().unwrap_or(None))
    }

    fn kill(&mut self) -> std::io::Result<()> {
      self.killed += 1;
      match self.kill_error {
        Some(kind) => Err(std::io::Error::new(kind, "scripted kill failure")),
        None => Ok(()),
      }
    }
  }

  fn supervise_at<C: ChildControl>(
    child: &mut C,
    clock: &dyn crate::common::deadline::Clock,
    deadline: Deadline,
  ) -> Result<C::Status> {
    let runtime = BoundaryRuntime::new(clock, deadline);
    supervise_child(child, &runtime)
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
  fn oversized_keychain_stdout_and_stderr_are_fully_drained_then_rejected() {
    for stream_name in ["stdout", "stderr"] {
      let bytes_read = Arc::new(AtomicUsize::new(0));
      let reader = CountingZeroCheckedReader {
        remaining: KEYCHAIN_OUTPUT_LIMIT + 1,
        bytes_read: Arc::clone(&bytes_read),
      };

      let error = drain_secret_stream(reader, stream_name)
        .expect_err("oversized native output must not be truncated into a credential");

      assert!(error.to_string().contains(stream_name));
      assert!(error.to_string().contains("exceeded"));
      assert!(error.to_string().contains("output redacted"));
      assert_eq!(bytes_read.load(Ordering::SeqCst), KEYCHAIN_OUTPUT_LIMIT + 1);
    }
  }

  #[test]
  fn keychain_drain_wipes_completed_chunks_and_redacts_read_errors() {
    let error = drain_secret_stream(
      ErrorAfterSecretChunk {
        returned_chunk: false,
      },
      "stdout",
    )
    .expect_err("the scripted second read fails");

    let message = format!("{error:#}");
    assert!(message.contains("scripted drain failure"));
    assert!(!message.contains("redacted-secret!"));
  }

  #[test]
  fn hung_keychain_child_is_killed_and_reaped_with_one_absolute_grace() {
    let clock = ManualClock::default();
    let deadline = Deadline::after(&clock, Duration::from_millis(25));
    let mut child = FakeChild {
      states: [None, None, None, None, Some(())].into(),
      killed: 0,
      polls: 0,
      kill_error: None,
    };
    let error = supervise_at(&mut child, &clock, deadline).expect_err("timeout");
    assert_eq!(
      error.downcast_ref::<BoundaryStop>(),
      Some(&BoundaryStop::TimedOut)
    );
    assert_eq!(child.killed, 1);
    assert_eq!(child.polls, 5);
    assert!(!deadline
      .cleanup_deadline(CLEANUP_GRACE)
      .remaining(&clock)
      .is_zero());
  }

  #[test]
  fn exact_deadline_exit_is_timeout_biased_and_still_reaped() {
    let clock = ManualClock::default();
    let deadline = Deadline::after(&clock, CHILD_POLL_INTERVAL);
    let mut child = FakeChild {
      // The second state becomes visible exactly when the first poll's sleep
      // reaches the deadline.
      states: [None, Some(())].into(),
      killed: 0,
      polls: 0,
      kill_error: None,
    };

    let error = supervise_at(&mut child, &clock, deadline).expect_err("exact tie times out");
    assert_eq!(
      error.downcast_ref::<BoundaryStop>(),
      Some(&BoundaryStop::TimedOut)
    );
    assert_eq!(child.killed, 1);
    assert_eq!(child.polls, 2);
  }

  #[test]
  fn raced_exit_after_failed_kill_is_still_reaped_as_a_timeout() {
    let clock = ManualClock::default();
    let deadline = Deadline::after(&clock, Duration::ZERO);
    let mut child = FakeChild {
      states: [Some(())].into(),
      killed: 0,
      polls: 0,
      kill_error: Some(std::io::ErrorKind::InvalidInput),
    };

    let error = supervise_at(&mut child, &clock, deadline).expect_err("lookup timed out");
    assert_eq!(
      error.downcast_ref::<BoundaryStop>(),
      Some(&BoundaryStop::TimedOut)
    );
    assert_eq!(child.killed, 1);
    assert_eq!(child.polls, 1);
  }

  #[test]
  fn genuine_kill_error_is_preserved_after_the_absolute_cleanup_grace() {
    let clock = ManualClock::default();
    let deadline = Deadline::after(&clock, Duration::ZERO);
    let mut child = FakeChild {
      states: VecDeque::new(),
      killed: 0,
      polls: 0,
      kill_error: Some(std::io::ErrorKind::PermissionDenied),
    };

    let error = supervise_at(&mut child, &clock, deadline).expect_err("kill failed");
    assert!(error
      .to_string()
      .contains("failed to kill stopped Keychain helper"));
    assert_eq!(
      error.downcast_ref::<BoundaryStop>(),
      Some(&BoundaryStop::TimedOut)
    );
    assert_eq!(child.killed, 1);
    assert_eq!(child.polls, 200);
    assert_eq!(
      deadline.cleanup_deadline(CLEANUP_GRACE).remaining(&clock),
      Duration::ZERO
    );
  }

  #[test]
  fn cleanup_exit_at_exact_grace_boundary_does_not_get_an_extra_poll() {
    let clock = ManualClock::default();
    let deadline = Deadline::after(&clock, Duration::ZERO);
    let mut states = VecDeque::from(vec![None; 200]);
    states.push_back(Some(()));
    let mut child = FakeChild {
      states,
      killed: 0,
      polls: 0,
      kill_error: None,
    };

    let error = supervise_at(&mut child, &clock, deadline).expect_err("cleanup ceiling wins");
    assert!(error
      .to_string()
      .contains("did not exit during cleanup grace"));
    assert_eq!(child.polls, 200, "no poll occurs at the exact ceiling");
  }

  #[test]
  fn cancellation_kills_and_reaps_the_keychain_child() {
    let clock = ManualClock::default();
    let stop = crate::common::deadline::CancellationToken::default();
    stop.cancel();
    let runtime = BoundaryRuntime::with_stop(
      &clock,
      Deadline::after(&clock, Duration::from_secs(1)),
      stop,
    );
    let mut child = FakeChild {
      states: [Some(())].into(),
      killed: 0,
      polls: 0,
      kill_error: None,
    };

    let error = supervise_child(&mut child, &runtime).expect_err("cancelled child");

    assert_eq!(
      error.downcast_ref::<BoundaryStop>(),
      Some(&BoundaryStop::Cancelled)
    );
    assert_eq!(child.killed, 1);
    assert_eq!(child.polls, 1);
  }

  #[test]
  fn resource_exhaustion_kills_and_reaps_the_keychain_child() {
    let clock = ManualClock::default();
    let stop = crate::common::deadline::CancellationToken::default();
    stop.exhaust_resources();
    let runtime = BoundaryRuntime::with_stop(
      &clock,
      Deadline::after(&clock, Duration::from_secs(1)),
      stop,
    );
    let mut child = FakeChild {
      states: [Some(())].into(),
      killed: 0,
      polls: 0,
      kill_error: None,
    };

    let error = supervise_child(&mut child, &runtime).expect_err("resource-stopped child");

    assert_eq!(
      error.downcast_ref::<BoundaryStop>(),
      Some(&BoundaryStop::ResourceExhausted)
    );
    assert_eq!(child.killed, 1);
    assert_eq!(child.polls, 1);
  }

  struct PollErrorChild {
    polls: usize,
    killed: usize,
  }

  impl ChildControl for PollErrorChild {
    type Status = ();

    fn try_wait(&mut self) -> std::io::Result<Option<Self::Status>> {
      self.polls += 1;
      if self.polls == 1 {
        Err(std::io::Error::other("scripted poll failure"))
      } else {
        Ok(Some(()))
      }
    }

    fn kill(&mut self) -> std::io::Result<()> {
      self.killed += 1;
      Ok(())
    }
  }

  #[test]
  fn poll_error_still_kills_and_reaps_without_losing_the_original_cause() {
    let clock = ManualClock::default();
    let runtime = BoundaryRuntime::new(&clock, Deadline::after(&clock, Duration::from_secs(1)));
    let mut child = PollErrorChild {
      polls: 0,
      killed: 0,
    };

    let error = supervise_child(&mut child, &runtime).expect_err("poll failure");

    assert!(format!("{error:#}").contains("scripted poll failure"));
    assert!(error.downcast_ref::<std::io::Error>().is_some());
    assert_eq!(child.killed, 1);
    assert_eq!(child.polls, 2);
  }

  #[test]
  fn real_hung_child_is_killed_and_reaped() {
    let mut child = Command::new("/bin/sleep")
      .arg("60")
      .stdin(Stdio::null())
      .stdout(Stdio::null())
      .stderr(Stdio::null())
      .spawn()
      .expect("spawn hung child");
    let clock = crate::common::deadline::SystemClock;
    let deadline = Deadline::after(&clock, Duration::from_millis(25));

    let error = supervise_at(&mut child, &clock, deadline).expect_err("child must time out");
    let reaped = child.try_wait().expect("child remains waitable");
    if reaped.is_none() {
      // Keep a failed assertion from leaving the real helper behind.
      let _ = child.kill();
      let _ = child.wait();
    }
    assert_eq!(
      error.downcast_ref::<BoundaryStop>(),
      Some(&BoundaryStop::TimedOut)
    );
    assert!(reaped.is_some());
  }

  #[test]
  fn inherited_keychain_pipe_cannot_extend_the_request_deadline() {
    let mut child = Command::new("/bin/sh")
      .args(["-c", "sleep 1 & exit 0"])
      .stdin(Stdio::null())
      .stdout(Stdio::piped())
      .stderr(Stdio::piped())
      .spawn()
      .expect("spawn helper with a descendant-held pipe");
    let stdout = child.stdout.take().expect("stdout pipe");
    let stderr = child.stderr.take().expect("stderr pipe");
    let clock = crate::common::deadline::SystemClock;
    let runtime = BoundaryRuntime::new(&clock, Deadline::after(&clock, Duration::from_millis(40)));
    let started = std::time::Instant::now();

    let error = supervise_keychain_child(&mut child, stdout, stderr, &runtime)
      .expect_err("an inherited pipe must not reset or outlive the request budget");

    assert_eq!(
      error.downcast_ref::<BoundaryStop>(),
      Some(&BoundaryStop::TimedOut)
    );
    assert!(
      started.elapsed() < Duration::from_millis(500),
      "the nonblocking pipe drain must not wait for the descendant"
    );
    assert!(
      child.try_wait().expect("helper remains waitable").is_some(),
      "the direct child was reaped before the inherited pipe timed out"
    );
  }
}
