//! Absolute monotonic deadlines and deterministic cancellation seams.
//!
//! A deadline is created once at the operation boundary and copied through
//! every fallback. No boundary is allowed to turn a remaining duration back
//! into a fresh budget.

use std::{
  fmt,
  sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
  },
  time::{Duration, Instant},
};

pub(crate) const DEFAULT_EXTRACTION_BUDGET: Duration = Duration::from_secs(30);
pub(crate) const CLEANUP_GRACE: Duration = Duration::from_secs(2);

pub(crate) trait Clock: Send + Sync {
  fn now(&self) -> Instant;
  fn sleep(&self, duration: Duration);
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemClock;

impl Clock for SystemClock {
  fn now(&self) -> Instant {
    Instant::now()
  }

  fn sleep(&self, duration: Duration) {
    std::thread::sleep(duration);
  }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Deadline {
  expires_at: Instant,
}

impl Deadline {
  pub(crate) fn standard() -> Self {
    Self::after(&SystemClock, DEFAULT_EXTRACTION_BUDGET)
  }

  pub(crate) fn after(clock: &dyn Clock, duration: Duration) -> Self {
    Self {
      expires_at: clock
        .now()
        .checked_add(duration)
        .unwrap_or_else(|| clock.now()),
    }
  }

  pub(crate) fn remaining(self, clock: &dyn Clock) -> Duration {
    self.expires_at.saturating_duration_since(clock.now())
  }

  pub(crate) fn check(self, clock: &dyn Clock) -> Result<(), BoundaryExpired> {
    if self.remaining(clock).is_zero() {
      Err(BoundaryExpired)
    } else {
      Ok(())
    }
  }

  /// One absolute cleanup ceiling derived from the original deadline. Calling
  /// this after expiry never grants a fresh grace period.
  pub(crate) fn cleanup_deadline(self, grace: Duration) -> Self {
    Self {
      expires_at: self
        .expires_at
        .checked_add(grace)
        .unwrap_or(self.expires_at),
    }
  }

  /// A duration ceiling for an IPC sender. This is not a transferable
  /// deadline: a receiver must also retain the parent absolute deadline (or a
  /// transport-native absolute timestamp) so transit cannot inflate budget.
  #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
  pub(crate) fn ipc_sender_ceiling(self, clock: &dyn Clock) -> Duration {
    self.remaining(clock)
  }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BoundaryExpired;

impl fmt::Display for BoundaryExpired {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("operation deadline expired")
  }
}

impl std::error::Error for BoundaryExpired {}

#[derive(Clone, Default)]
pub(crate) struct CancellationToken(Arc<AtomicU8>);

impl CancellationToken {
  #[cfg_attr(not(test), allow(dead_code))]
  pub(crate) fn cancel(&self) {
    self.0.store(1, Ordering::Release);
  }

  pub(crate) fn is_cancelled(&self) -> bool {
    self.0.load(Ordering::Acquire) == 1
  }

  #[cfg_attr(not(test), allow(dead_code))]
  pub(crate) fn exhaust_resources(&self) {
    self.0.store(2, Ordering::Release);
  }

  pub(crate) fn is_resource_exhausted(&self) -> bool {
    self.0.load(Ordering::Acquire) == 2
  }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BoundaryStop {
  TimedOut,
  Cancelled,
  ResourceExhausted,
}

impl fmt::Display for BoundaryStop {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(match self {
      Self::TimedOut => "operation deadline expired",
      Self::Cancelled => "operation cancelled",
      Self::ResourceExhausted => "operation resource budget exhausted",
    })
  }
}

impl std::error::Error for BoundaryStop {}

pub(crate) fn checkpoint(
  clock: &dyn Clock,
  deadline: Deadline,
  cancellation: &CancellationToken,
) -> Result<(), BoundaryStop> {
  // Sampling the deadline first makes an exact timeout/cancellation race
  // deterministic on every adapter.
  if deadline.remaining(clock).is_zero() {
    return Err(BoundaryStop::TimedOut);
  }
  if cancellation.is_cancelled() {
    return Err(BoundaryStop::Cancelled);
  }
  if cancellation.is_resource_exhausted() {
    return Err(BoundaryStop::ResourceExhausted);
  }
  Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeadlineEnforcement {
  Cooperative,
  Enforceable,
}

#[derive(Clone)]
pub(crate) struct BoundaryRuntime<'a> {
  pub(crate) clock: &'a dyn Clock,
  pub(crate) deadline: Deadline,
  pub(crate) stop: CancellationToken,
}

impl<'a> BoundaryRuntime<'a> {
  pub(crate) fn new(clock: &'a dyn Clock, deadline: Deadline) -> Self {
    Self {
      clock,
      deadline,
      stop: CancellationToken::default(),
    }
  }

  #[cfg(test)]
  pub(crate) fn with_stop(
    clock: &'a dyn Clock,
    deadline: Deadline,
    stop: CancellationToken,
  ) -> Self {
    Self {
      clock,
      deadline,
      stop,
    }
  }

  pub(crate) fn standard(clock: &'a dyn Clock) -> Self {
    Self::new(clock, Deadline::after(clock, DEFAULT_EXTRACTION_BUDGET))
  }

  pub(crate) fn check(&self) -> Result<(), BoundaryStop> {
    checkpoint(self.clock, self.deadline, &self.stop)
  }
}

#[cfg(test)]
pub(crate) mod test_clock {
  use super::*;
  use std::sync::Mutex;

  pub(crate) struct ManualClock {
    base: Instant,
    elapsed: Mutex<Duration>,
  }

  impl Default for ManualClock {
    fn default() -> Self {
      Self {
        base: Instant::now(),
        elapsed: Mutex::new(Duration::ZERO),
      }
    }
  }

  impl ManualClock {
    pub(crate) fn advance(&self, duration: Duration) {
      let mut elapsed = self.elapsed.lock().expect("manual clock lock");
      *elapsed = elapsed.saturating_add(duration);
    }
  }

  impl Clock for ManualClock {
    fn now(&self) -> Instant {
      self.base + *self.elapsed.lock().expect("manual clock lock")
    }

    fn sleep(&self, duration: Duration) {
      self.advance(duration);
    }
  }
}

#[cfg(test)]
mod tests {
  use super::{test_clock::ManualClock, *};

  #[test]
  fn deadline_is_absolute_across_fallbacks_and_cleanup_grace() {
    let clock = ManualClock::default();
    let deadline = Deadline::after(&clock, Duration::from_secs(10));
    clock.advance(Duration::from_secs(7));
    assert_eq!(deadline.remaining(&clock), Duration::from_secs(3));
    clock.advance(Duration::from_secs(3));
    assert_eq!(deadline.check(&clock), Err(BoundaryExpired));
    assert_eq!(
      deadline
        .cleanup_deadline(Duration::from_secs(2))
        .remaining(&clock),
      Duration::from_secs(2)
    );
    clock.advance(Duration::from_secs(1));
    assert_eq!(
      deadline
        .cleanup_deadline(Duration::from_secs(2))
        .remaining(&clock),
      Duration::from_secs(1)
    );
  }

  #[test]
  fn timeout_wins_an_exact_cancellation_race_without_wall_clock_sleep() {
    let clock = ManualClock::default();
    let cancellation = CancellationToken::default();
    let deadline = Deadline::after(&clock, Duration::from_secs(1));
    cancellation.cancel();
    clock.advance(Duration::from_secs(1));
    assert_eq!(
      checkpoint(&clock, deadline, &cancellation),
      Err(BoundaryStop::TimedOut)
    );
  }

  #[test]
  fn ipc_sender_ceiling_never_claims_to_replace_the_parent_deadline() {
    let clock = ManualClock::default();
    let deadline = Deadline::after(&clock, Duration::from_secs(9));
    let mut observed = Vec::new();
    for elapsed in [2, 3, 4] {
      clock.advance(Duration::from_secs(elapsed));
      observed.push(deadline.ipc_sender_ceiling(&clock));
    }
    assert_eq!(
      observed,
      [
        Duration::from_secs(7),
        Duration::from_secs(4),
        Duration::ZERO
      ]
    );
  }
}
