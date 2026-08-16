//! Bounded concurrent fan-out over a shared deadline/cancellation runtime.

use super::deadline::BoundaryRuntime;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Default worker count for [`fan_out`]. Kept small and fixed rather than
/// scaled to `items.len()` so a `load()`-style fan-out across many browsers
/// never fires more than this many simultaneous OS-credential-store prompts
/// (e.g. several concurrent macOS Keychain consent dialogs) at once.
pub(crate) const DEFAULT_FAN_OUT_WIDTH: usize = 4;

/// Runs `work` over `items` on a bounded pool of `pool_size.min(items.len())`
/// scoped threads, claiming items in increasing order via a shared cursor.
///
/// A worker only claims the next item after `runtime.check()` succeeds, so
/// claimed indices are always the contiguous prefix `0..cursor` -- once the
/// runtime's deadline or cancellation trips, no further item is claimed, but
/// an item already claimed still runs `work` to completion. The returned
/// `Vec` holds one result per claimed item, in original `items` order,
/// regardless of which thread finished first.
pub(crate) fn fan_out<T, R>(
  items: &[T],
  pool_size: usize,
  runtime: &BoundaryRuntime<'_>,
  work: impl Fn(&T) -> R + Sync,
) -> Vec<R>
where
  T: Sync,
  R: Send,
{
  if items.is_empty() {
    return Vec::new();
  }
  let cursor = AtomicUsize::new(0);
  let results: Mutex<Vec<Option<R>>> = Mutex::new((0..items.len()).map(|_| None).collect());
  let workers = pool_size.min(items.len()).max(1);

  std::thread::scope(|scope| {
    for _ in 0..workers {
      scope.spawn(|| loop {
        if runtime.check().is_err() {
          break;
        }
        let index = cursor.fetch_add(1, Ordering::AcqRel);
        if index >= items.len() {
          break;
        }
        let result = work(&items[index]);
        let mut guard = results.lock().expect("fan_out results mutex");
        guard[index] = Some(result);
      });
    }
  });

  results
    .into_inner()
    .expect("fan_out results mutex")
    .into_iter()
    .take_while(Option::is_some)
    .flatten()
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::common::deadline::{test_clock::ManualClock, BoundaryRuntime, CancellationToken};
  use std::sync::atomic::AtomicIsize;
  use std::time::Duration;

  #[test]
  fn results_preserve_input_order_even_when_later_items_finish_first() {
    let clock = ManualClock::default();
    let runtime = BoundaryRuntime::standard(&clock);
    let items: Vec<u32> = vec![0, 1, 2, 3, 4, 5, 6, 7];
    let results = fan_out(&items, 4, &runtime, |item| {
      // Earlier items sleep longer, so completion order is reversed
      // relative to input order.
      std::thread::sleep(Duration::from_millis(u64::from(8 - item)));
      *item
    });
    assert_eq!(results, items);
  }

  #[test]
  fn never_runs_more_than_pool_size_workers_concurrently() {
    let clock = ManualClock::default();
    let runtime = BoundaryRuntime::standard(&clock);
    let items: Vec<u32> = (0..20).collect();
    let active = AtomicIsize::new(0);
    let peak = AtomicIsize::new(0);
    fan_out(&items, 3, &runtime, |_item| {
      let now_active = active.fetch_add(1, Ordering::SeqCst) + 1;
      peak.fetch_max(now_active, Ordering::SeqCst);
      std::thread::sleep(Duration::from_millis(5));
      active.fetch_sub(1, Ordering::SeqCst);
    });
    assert!(
      peak.load(Ordering::SeqCst) <= 3,
      "observed {} concurrently active workers, expected at most 3",
      peak.load(Ordering::SeqCst)
    );
  }

  #[test]
  fn a_cancelled_runtime_stops_claiming_new_work_but_keeps_already_claimed_results() {
    let clock = ManualClock::default();
    let cancellation = CancellationToken::default();
    let runtime = BoundaryRuntime::with_stop(
      &clock,
      crate::common::deadline::Deadline::after(&clock, Duration::from_secs(10)),
      cancellation.clone(),
    );
    let items: Vec<u32> = (0..50).collect();
    let attempted = AtomicIsize::new(0);
    let results = fan_out(&items, 1, &runtime, |item| {
      attempted.fetch_add(1, Ordering::SeqCst);
      if *item == 2 {
        cancellation.cancel();
      }
      *item
    });
    // With a single worker, claiming is strictly sequential: items 0, 1, 2
    // are claimed and run (item 2 requests cancellation on its own way out),
    // and the next claim attempt observes cancellation before claiming item 3.
    assert_eq!(results, vec![0, 1, 2]);
    assert_eq!(attempted.load(Ordering::SeqCst), 3);
  }

  #[test]
  fn empty_input_returns_empty_output_without_spawning_threads() {
    let clock = ManualClock::default();
    let runtime = BoundaryRuntime::standard(&clock);
    let items: Vec<u32> = Vec::new();
    let results = fan_out(&items, 4, &runtime, |item| *item);
    assert!(results.is_empty());
  }
}
