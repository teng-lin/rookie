//! Shared execution control for public I/O jobs.

use crate::CancellationHandle;
use std::time::Duration;

/// Per-job Windows App-Bound (v20) recovery policy.
///
/// The policy is request-local and immutable after a job starts. On
/// non-Windows targets it is a no-op: macOS and Linux Chrome use the Keychain
/// and Secret Service, which this policy has nothing to do with.
///
/// # Why the default is [`InjectionOnly`](Self::InjectionOnly)
///
/// Chrome has written App-Bound (v20) cookies on Windows since Chrome 127, so
/// on a current Windows profile essentially every row is v20.
/// [`Disabled`](Self::Disabled) leaves those unreadable, which means the
/// default would return an **empty** cookie list for the most common Windows
/// case -- and 0.5.9 read them, so that would be a silent capability
/// regression on upgrade, with the deprecated bridge ending up *more* capable
/// than the recommended API.
///
/// [`InjectionOnly`](Self::InjectionOnly) is the middle setting: unprivileged,
/// and it still refuses the elevated SYSTEM impersonation that
/// [`AllowElevatedFallback`](Self::AllowElevatedFallback) permits. It is not
/// free of consequence -- it spawns a browser process and reflectively injects
/// into it, which endpoint security products can flag -- so a caller who needs
/// none of that should set [`Disabled`](Self::Disabled) explicitly and expect
/// v20 rows to be omitted with a `app_bound_disabled` warning.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AppBoundPolicy {
  /// Never injects, spawns a browser process, enumerates processes, or
  /// impersonates SYSTEM. App-Bound v20 rows remain unreadable, and are
  /// omitted with a `app_bound_disabled` read warning rather than silently.
  Disabled,
  /// Attempts unprivileged reflective COM injection only (Chrome 127+).
  ///
  /// The default. See the type-level note for why.
  #[default]
  InjectionOnly,
  /// Attempts injection, then permits elevated SYSTEM impersonation fallback
  /// for Chrome 133+ when injection cannot recover the key.
  AllowElevatedFallback,
}

impl AppBoundPolicy {
  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::Disabled => "disabled",
      Self::InjectionOnly => "injection_only",
      Self::AllowElevatedFallback => "allow_elevated_fallback",
    }
  }
}

/// Timeout, cancellation, and App-Bound policy shared by every public I/O job.
///
/// # Equality
///
/// Equality compares cancellation-handle **identity**, not cancellation state:
/// two controls with identical timeouts and policies but different handles are
/// **not** equal, even when both handles are in the same cancelled state. This
/// is inherited from [`CancellationHandle`] and is part of this type's public
/// contract.
///
/// # Builder precedence
///
/// [`timeout`](Self::timeout), [`cancellation`](Self::cancellation), and
/// [`app_bound`](Self::app_bound) edit one field. A request's
/// `execution(control)` replaces the whole control, discarding earlier field
/// edits, so the recommended order is `execution` first and field setters
/// after.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionControl {
  pub(crate) timeout: Option<Duration>,
  pub(crate) cancellation: Option<CancellationHandle>,
  pub(crate) app_bound: AppBoundPolicy,
}

impl ExecutionControl {
  /// Overrides the default 30-second job budget.
  pub fn timeout(mut self, timeout: Duration) -> Self {
    self.timeout = Some(timeout);
    self
  }

  /// Lets `handle` cooperatively cancel the job from another thread.
  pub fn cancellation(mut self, handle: CancellationHandle) -> Self {
    self.cancellation = Some(handle);
    self
  }

  /// Selects the request-local Windows App-Bound recovery policy.
  pub fn app_bound(mut self, policy: AppBoundPolicy) -> Self {
    self.app_bound = policy;
    self
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn the_default_policy_is_unprivileged_but_not_inert() {
    // Not `Disabled`: on a current Windows profile every row is v20, so a
    // `Disabled` default returns an empty list for the common case and is a
    // capability regression from 0.5.9. Not `AllowElevatedFallback` either:
    // elevation stays something a caller asks for out loud.
    assert_eq!(
      ExecutionControl::default().app_bound,
      AppBoundPolicy::InjectionOnly
    );
  }

  #[test]
  fn equality_compares_handle_identity_not_cancellation_state() {
    let handle = CancellationHandle::new();
    let shared = ExecutionControl::default().cancellation(handle.clone());
    assert_eq!(
      shared,
      ExecutionControl::default().cancellation(handle.clone())
    );

    // Two distinct handles in the same (not yet cancelled) state are still two
    // different controls: `CancellationHandle`'s `PartialEq` is identity, and
    // this type inherits that meaning as a public contract.
    assert_ne!(
      shared,
      ExecutionControl::default().cancellation(CancellationHandle::new())
    );

    // ...and cancelling does not make a control unequal to itself.
    assert!(handle.cancel());
    assert_eq!(shared, ExecutionControl::default().cancellation(handle));
  }

  #[test]
  fn execution_replaces_wholesale_while_field_setters_edit() {
    use std::time::Duration;

    let base = ExecutionControl::default()
      .timeout(Duration::from_secs(1))
      .app_bound(AppBoundPolicy::InjectionOnly);

    // A field setter after `.execution(..)` edits the new control.
    let edited = base
      .clone()
      .app_bound(AppBoundPolicy::AllowElevatedFallback);
    assert_eq!(edited.timeout, Some(Duration::from_secs(1)));
    assert_eq!(edited.app_bound, AppBoundPolicy::AllowElevatedFallback);
  }

  #[test]
  fn concurrent_jobs_keep_their_own_policy_and_touch_no_process_state() {
    use crate::common::deadline::{runtime_for_control, SystemClock};

    const KEY: &str = "ROOKIE_E2E_APPBOUND_MODE";
    let before = std::env::var(KEY).ok();

    // The policy is a value on the job's runtime, so two jobs running at once
    // under different policies cannot observe each other's. This is the whole
    // reason it is not an environment variable: a process-global would make
    // the second job's policy depend on the first job's timing.
    let clock = SystemClock;
    let strict = runtime_for_control(
      &clock,
      &ExecutionControl::default().app_bound(AppBoundPolicy::Disabled),
    );
    let permissive = runtime_for_control(
      &clock,
      &ExecutionControl::default().app_bound(AppBoundPolicy::AllowElevatedFallback),
    );
    let handles = [std::thread::scope(|scope| {
      let strict = scope.spawn(|| strict.app_bound);
      let permissive = scope.spawn(|| permissive.app_bound);
      (
        strict.join().expect("strict job"),
        permissive.join().expect("permissive job"),
      )
    })];
    assert_eq!(
      handles[0],
      (
        AppBoundPolicy::Disabled,
        AppBoundPolicy::AllowElevatedFallback
      )
    );

    assert_eq!(
      std::env::var(KEY).ok(),
      before,
      "selecting a policy must not write to the parent environment"
    );
  }

  #[test]
  fn debug_prints_the_knobs_and_no_secrets() {
    let rendered = format!(
      "{:?}",
      ExecutionControl::default()
        .cancellation(CancellationHandle::new())
        .app_bound(AppBoundPolicy::AllowElevatedFallback)
    );
    assert!(rendered.contains("AllowElevatedFallback"));
    assert!(rendered.contains("cancelled: false"));
  }
}
