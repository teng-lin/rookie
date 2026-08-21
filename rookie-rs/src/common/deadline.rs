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
/// A century, in seconds. Every real platform's `Instant` has far more
/// headroom than this, so adding it to `now()` cannot itself overflow.
const EFFECTIVELY_UNBOUNDED_HORIZON: Duration = Duration::from_secs(60 * 60 * 24 * 365 * 100);
#[cfg(any(target_os = "linux", target_os = "macos", test))]
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
  #[cfg(test)]
  pub(crate) fn standard() -> Self {
    Self::after(&SystemClock, DEFAULT_EXTRACTION_BUDGET)
  }

  pub(crate) fn after(clock: &dyn Clock, duration: Duration) -> Self {
    let now = clock.now();
    // A caller-supplied duration near `Duration::MAX` (e.g. "no real budget,
    // just don't hang forever") can overflow `Instant` addition. Falling back
    // to `now` there would invert the caller's intent into an
    // already-expired deadline instead of an effectively unbounded one, so
    // clamp to a horizon far beyond any real extraction first.
    let expires_at = now
      .checked_add(duration)
      .or_else(|| now.checked_add(EFFECTIVELY_UNBOUNDED_HORIZON))
      .unwrap_or(now);
    Self { expires_at }
  }

  pub(crate) fn remaining(self, clock: &dyn Clock) -> Duration {
    self.expires_at.saturating_duration_since(clock.now())
  }

  /// One absolute cleanup ceiling derived from the original deadline. Calling
  /// this after expiry never grants a fresh grace period.
  #[cfg(any(target_os = "linux", target_os = "macos", test))]
  pub(crate) fn cleanup_deadline(self, grace: Duration) -> Self {
    Self {
      expires_at: self
        .expires_at
        .checked_add(grace)
        .unwrap_or(self.expires_at),
    }
  }
}

#[derive(Clone, Default)]
pub(crate) struct CancellationToken(Arc<AtomicU8>);

impl CancellationToken {
  /// Records cancellation if no terminal request reason has already won.
  ///
  /// The first writer wins, so concurrent cancellation and resource-budget
  /// exhaustion cannot change the reason observed by later boundaries.
  pub(crate) fn cancel(&self) -> bool {
    self
      .0
      .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
      .is_ok()
  }

  pub(crate) fn is_cancelled(&self) -> bool {
    self.0.load(Ordering::Acquire) == 1
  }

  /// Records resource exhaustion if no terminal request reason has won yet.
  #[allow(dead_code)] // The public request object in PR4 will drive this internal control seam.
  pub(crate) fn exhaust_resources(&self) -> bool {
    self
      .0
      .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
      .is_ok()
  }

  pub(crate) fn is_resource_exhausted(&self) -> bool {
    self.0.load(Ordering::Acquire) == 2
  }

  /// Whether `self` and `other` are clones of the same token, sharing one
  /// cancellation state, rather than two independent tokens that merely
  /// happen to be in the same state.
  pub(crate) fn same_as(&self, other: &Self) -> bool {
    Arc::ptr_eq(&self.0, &other.0)
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
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  Enforceable,
}

/// The per-job execution control every boundary already receives.
///
/// `app_bound` rides here rather than through a parallel parameter because it
/// is the same kind of value as the deadline and the stop token: created once
/// at the job boundary, immutable for the job's lifetime, and needed at a leaf
/// (the Windows v20 key lookup) many layers below the caller. Threading it
/// separately would duplicate this plumbing for one field, and storing it in a
/// process global is exactly the steering this design removes.
///
/// The constructors here default `app_bound` to
/// [`AllowElevatedFallback`](crate::AppBoundPolicy::AllowElevatedFallback),
/// **not** to the public default. They back the deprecated v0.5.9 bridge,
/// whose App-Bound capability shipped in 0.5.8 and must keep working through
/// 0.6.x. Only [`runtime_for_control`] carries the request's own policy, whose
/// default is `InjectionOnly`; callers opt out explicitly with `Disabled`, or
/// opt into this legacy elevated fallback explicitly.
#[derive(Clone)]
pub(crate) struct BoundaryRuntime<'a> {
  pub(crate) clock: &'a dyn Clock,
  pub(crate) deadline: Deadline,
  pub(crate) stop: CancellationToken,
  pub(crate) app_bound: crate::execution::AppBoundPolicy,
}

impl<'a> BoundaryRuntime<'a> {
  pub(crate) fn new(clock: &'a dyn Clock, deadline: Deadline) -> Self {
    Self {
      clock,
      deadline,
      stop: CancellationToken::default(),
      app_bound: crate::execution::AppBoundPolicy::AllowElevatedFallback,
    }
  }

  pub(crate) fn with_stop(
    clock: &'a dyn Clock,
    deadline: Deadline,
    stop: CancellationToken,
  ) -> Self {
    Self {
      clock,
      deadline,
      stop,
      app_bound: crate::execution::AppBoundPolicy::AllowElevatedFallback,
    }
  }

  pub(crate) fn standard(clock: &'a dyn Clock) -> Self {
    Self::new(clock, Deadline::after(clock, DEFAULT_EXTRACTION_BUDGET))
  }

  /// Selects the App-Bound recovery policy for this job. Callers build the
  /// runtime and then set the policy once, at the boundary.
  pub(crate) fn with_app_bound(mut self, policy: crate::execution::AppBoundPolicy) -> Self {
    self.app_bound = policy;
    self
  }

  pub(crate) fn check(&self) -> Result<(), BoundaryStop> {
    checkpoint(self.clock, self.deadline, &self.stop)
  }
}

/// Builds the runtime for one public job from its [`ExecutionControl`].
///
/// This is the single place a public request's execution knobs become the
/// internal boundary value, so a job cannot acquire a timeout, a cancellation
/// token, and an App-Bound policy from three different places.
///
/// [`ExecutionControl`]: crate::execution::ExecutionControl
pub(crate) fn runtime_for_control<'a>(
  clock: &'a dyn Clock,
  control: &crate::execution::ExecutionControl,
) -> BoundaryRuntime<'a> {
  let deadline = Deadline::after(clock, control.timeout.unwrap_or(DEFAULT_EXTRACTION_BUDGET));
  let stop = control
    .cancellation
    .as_ref()
    .map(|handle| handle.0.clone())
    .unwrap_or_default();
  BoundaryRuntime::with_stop(clock, deadline, stop).with_app_bound(control.app_bound)
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
    assert!(deadline.remaining(&clock).is_zero());
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
  fn an_overflowing_timeout_does_not_invert_into_an_already_expired_deadline() {
    let clock = ManualClock::default();
    let deadline = Deadline::after(&clock, Duration::MAX);
    // A caller passing `Duration::MAX` means "don't really bound this," not
    // "expire it instantly." Advancing by a very long, but not overflowing,
    // duration must still leave time remaining.
    clock.advance(Duration::from_secs(60 * 60 * 24 * 365 * 50));
    assert!(
      !deadline.remaining(&clock).is_zero(),
      "an overflowing timeout must clamp to a far horizon, not to `now`"
    );
  }

  #[test]
  fn timeout_wins_an_exact_cancellation_race_without_wall_clock_sleep() {
    let clock = ManualClock::default();
    let cancellation = CancellationToken::default();
    let deadline = Deadline::after(&clock, Duration::from_secs(1));
    assert!(cancellation.cancel());
    clock.advance(Duration::from_secs(1));
    assert_eq!(
      checkpoint(&clock, deadline, &cancellation),
      Err(BoundaryStop::TimedOut)
    );
  }

  #[test]
  fn first_terminal_request_reason_wins_deterministically() {
    let clock = ManualClock::default();
    let deadline = Deadline::after(&clock, Duration::from_secs(10));

    let cancellation = CancellationToken::default();
    assert!(cancellation.cancel());
    assert!(!cancellation.exhaust_resources());
    assert_eq!(
      checkpoint(&clock, deadline, &cancellation),
      Err(BoundaryStop::Cancelled)
    );

    let exhausted = CancellationToken::default();
    assert!(exhausted.exhaust_resources());
    assert!(!exhausted.cancel());
    assert_eq!(
      checkpoint(&clock, deadline, &exhausted),
      Err(BoundaryStop::ResourceExhausted)
    );
  }
}
