//! Bounded concurrent fan-out over a shared deadline/cancellation runtime.

use super::deadline::BoundaryRuntime;
use anyhow::{anyhow, Result};
use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Default worker count for [`fan_out`]. Kept small and fixed, rather than
/// scaled to `items.len()`, so a `load()`-style fan-out across many browsers
/// bounds how many simultaneous OS-credential-store prompts (e.g. concurrent
/// macOS Keychain consent dialogs) a caller can see at once. This still
/// raises that count from the previous strictly-sequential code's implicit
/// bound of one at a time to `DEFAULT_FAN_OUT_WIDTH` at a time -- it caps the
/// increase, it does not eliminate it.
pub(crate) const DEFAULT_FAN_OUT_WIDTH: usize = 4;

/// Runs `work` over `items` on a bounded pool of `pool_size.min(items.len())`
/// scoped threads, claiming items in increasing order via a shared cursor.
///
/// A worker only claims the next item after `runtime.check()` succeeds, so
/// once the runtime's deadline or cancellation trips, claiming simply stops;
/// an item already claimed still runs `work` to completion. Because indices
/// are handed out by one shared, monotonically increasing cursor, the set of
/// claimed indices is always the contiguous prefix `0..cursor` of `items`,
/// with no gaps, regardless of which thread claims which index. The returned
/// `Vec` holds one result per claimed item, in that original `items` order,
/// regardless of which thread finished first.
///
/// A panic inside `work` is caught and converted into an `Err` for that one
/// item rather than being allowed to unwind across the `work`/thread
/// boundary -- otherwise one item's panic would tear down every other
/// worker's already-completed results along with it (`std::thread::scope`
/// re-panics on join, before this function ever gets to return anything).
pub(crate) fn fan_out<T, U>(
  items: &[T],
  pool_size: usize,
  runtime: &BoundaryRuntime<'_>,
  work: impl Fn(&T) -> Result<U> + Sync,
) -> Vec<Result<U>>
where
  T: Sync,
  U: Send,
{
  if items.is_empty() {
    return Vec::new();
  }
  let cursor = AtomicUsize::new(0);
  let results: Mutex<Vec<Option<Result<U>>>> = Mutex::new((0..items.len()).map(|_| None).collect());
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
        let result = catch_unwind(AssertUnwindSafe(|| work(&items[index])))
          .unwrap_or_else(|panic| Err(anyhow!("extraction panicked: {}", panic_message(&*panic))));
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

fn panic_message(payload: &(dyn Any + Send)) -> String {
  if let Some(message) = payload.downcast_ref::<&str>() {
    (*message).to_owned()
  } else if let Some(message) = payload.downcast_ref::<String>() {
    message.clone()
  } else {
    "non-string panic payload".to_owned()
  }
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
      Ok(*item)
    });
    let values: Vec<u32> = results.into_iter().map(|result| result.unwrap()).collect();
    assert_eq!(values, items);
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
      Ok(())
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
      Ok(*item)
    });
    // With a single worker, claiming is strictly sequential: items 0, 1, 2
    // are claimed and run (item 2 requests cancellation on its own way out),
    // and the next claim attempt observes cancellation before claiming item 3.
    let values: Vec<u32> = results.into_iter().map(|result| result.unwrap()).collect();
    assert_eq!(values, vec![0, 1, 2]);
    assert_eq!(attempted.load(Ordering::SeqCst), 3);
  }

  #[test]
  fn empty_input_returns_empty_output_without_spawning_threads() {
    let clock = ManualClock::default();
    let runtime = BoundaryRuntime::standard(&clock);
    let items: Vec<u32> = Vec::new();
    let results = fan_out(&items, 4, &runtime, |item| Ok(*item));
    assert!(results.is_empty());
  }

  #[test]
  fn a_panic_in_one_item_becomes_an_err_for_that_item_without_losing_siblings() {
    let clock = ManualClock::default();
    let runtime = BoundaryRuntime::standard(&clock);
    let items: Vec<u32> = (0..8).collect();
    let results = fan_out(&items, 4, &runtime, |item| {
      if *item == 3 {
        panic!("simulated deep extraction bug");
      }
      Ok(*item)
    });
    assert_eq!(results.len(), items.len());
    for (item, result) in items.iter().zip(results) {
      if *item == 3 {
        let message = result.unwrap_err().to_string();
        assert!(
          message.contains("simulated deep extraction bug"),
          "expected the panic message to survive, got: {message}"
        );
      } else {
        assert_eq!(result.unwrap(), *item);
      }
    }
  }
}
