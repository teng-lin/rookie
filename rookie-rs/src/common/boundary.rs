//! The only operations allowed to cross an extraction trust boundary.

use super::deadline::{BoundaryRuntime, DeadlineEnforcement};

pub(crate) trait ReadOnlySource {}

pub(crate) trait RecordSink<Record> {
  fn emit(&mut self, record: Record) -> anyhow::Result<()>;
}

impl<Record, F> RecordSink<Record> for F
where
  F: FnMut(Record) -> anyhow::Result<()>,
{
  fn emit(&mut self, record: Record) -> anyhow::Result<()> {
    self(record)
  }
}

/// Test-only: every production acquisition supplies its own runtime
/// directly. The single implementor, `sqlite::BrowserDatabaseAcquire`,
/// is reached only from the `#[cfg(test)]` `sqlite::connect` wrapper --
/// an `#[allow(dead_code)]` on that wrapper had been masking the fact
/// that this whole abstraction has no production caller.
#[cfg(test)]
pub(crate) trait Acquire<Id: ?Sized> {
  type Source: ReadOnlySource;

  fn open(&self, id: &Id, runtime: &BoundaryRuntime<'_>) -> anyhow::Result<Self::Source>;

  fn deadline_enforcement(&self) -> DeadlineEnforcement {
    DeadlineEnforcement::Cooperative
  }
}

pub(crate) trait KeyProvider<Request: ?Sized> {
  type Keys;

  fn keys(&self, request: &Request, runtime: &BoundaryRuntime<'_>) -> Self::Keys;

  fn deadline_enforcement(&self) -> DeadlineEnforcement {
    DeadlineEnforcement::Cooperative
  }
}

pub(crate) trait Decoder<Source: ReadOnlySource, Record> {
  type Summary;

  fn decode(
    &self,
    source: &Source,
    sink: &mut dyn RecordSink<Record>,
    runtime: &BoundaryRuntime<'_>,
  ) -> anyhow::Result<Self::Summary>;

  fn deadline_enforcement(&self) -> DeadlineEnforcement;
}

/// Runs a cooperative or enforceable acquisition according to its declared
/// capability. Cooperative adapters get an outer final checkpoint because an
/// in-process syscall can outlive the last checkpoint inside the adapter;
/// enforceable adapters are responsible for their own exact completion race.
#[cfg(test)]
pub(crate) fn acquire<Id: ?Sized, A: Acquire<Id>>(
  acquire: &A,
  id: &Id,
  runtime: &BoundaryRuntime<'_>,
) -> anyhow::Result<A::Source> {
  runtime.check()?;
  let enforcement = acquire.deadline_enforcement();
  let source = acquire.open(id, runtime)?;
  if enforcement == DeadlineEnforcement::Cooperative {
    runtime.check()?;
  }
  Ok(source)
}

/// Runs a decoder while enforcing the orchestration responsibility declared
/// by its capability metadata.
pub(crate) fn decode<Source, Record, D>(
  decoder: &D,
  source: &Source,
  sink: &mut dyn RecordSink<Record>,
  runtime: &BoundaryRuntime<'_>,
) -> anyhow::Result<D::Summary>
where
  Source: ReadOnlySource,
  D: Decoder<Source, Record>,
{
  runtime.check()?;
  let enforcement = decoder.deadline_enforcement();
  let summary = decoder.decode(source, sink, runtime)?;
  if enforcement == DeadlineEnforcement::Cooperative {
    runtime.check()?;
  }
  Ok(summary)
}

/// Key providers return a structured set of tier outcomes, so terminal request
/// state remains a separate typed result instead of becoming a provider error.
pub(crate) fn keys<Request: ?Sized, P: KeyProvider<Request>>(
  provider: &P,
  request: &Request,
  runtime: &BoundaryRuntime<'_>,
) -> anyhow::Result<P::Keys> {
  runtime.check()?;
  let enforcement = provider.deadline_enforcement();
  let keys = provider.keys(request, runtime);
  if enforcement == DeadlineEnforcement::Cooperative {
    runtime.check()?;
  }
  Ok(keys)
}

impl ReadOnlySource for rusqlite::Connection {}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::common::deadline::{
    test_clock::ManualClock, BoundaryStop, CancellationToken, Clock, Deadline, CLEANUP_GRACE,
  };
  use std::{cell::Cell, cell::RefCell, time::Duration};

  struct FakeDecoder<'a> {
    _clock: &'a dyn Clock,
  }

  impl Decoder<rusqlite::Connection, usize> for FakeDecoder<'_> {
    type Summary = usize;

    fn decode(
      &self,
      _source: &rusqlite::Connection,
      sink: &mut dyn RecordSink<usize>,
      runtime: &BoundaryRuntime<'_>,
    ) -> anyhow::Result<Self::Summary> {
      let mut emitted = 0;
      for record in 0..3 {
        runtime.check()?;
        sink.emit(record)?;
        emitted += 1;
      }
      Ok(emitted)
    }

    fn deadline_enforcement(&self) -> DeadlineEnforcement {
      DeadlineEnforcement::Cooperative
    }
  }

  struct AdvancingSink<'a> {
    clock: &'a dyn Clock,
    records: RefCell<Vec<usize>>,
  }

  impl RecordSink<usize> for AdvancingSink<'_> {
    fn emit(&mut self, record: usize) -> anyhow::Result<()> {
      self.records.borrow_mut().push(record);
      self.clock.sleep(Duration::from_secs(1));
      Ok(())
    }
  }

  #[test]
  fn decoder_emits_nothing_after_the_absolute_deadline_without_sleeping() {
    let clock = ManualClock::default();
    let deadline = Deadline::after(&clock, Duration::from_secs(2));
    let decoder = FakeDecoder { _clock: &clock };
    let mut sink = AdvancingSink {
      clock: &clock,
      records: RefCell::new(Vec::new()),
    };
    decode(
      &decoder,
      &rusqlite::Connection::open_in_memory().unwrap(),
      &mut sink,
      &BoundaryRuntime::new(&clock, deadline),
    )
    .expect_err("third emission starts at the deadline");
    assert_eq!(sink.records.into_inner(), [0, 1]);
    assert_eq!(
      decoder.deadline_enforcement(),
      DeadlineEnforcement::Cooperative
    );
  }

  #[derive(Clone, Copy)]
  struct PipelineSource;

  impl ReadOnlySource for PipelineSource {}

  struct PipelineAcquire<'a> {
    clock: &'a ManualClock,
    remaining: &'a RefCell<Vec<Duration>>,
    calls: &'a Cell<usize>,
  }

  impl Acquire<()> for PipelineAcquire<'_> {
    type Source = PipelineSource;

    fn open(&self, _id: &(), runtime: &BoundaryRuntime<'_>) -> anyhow::Result<Self::Source> {
      self.calls.set(self.calls.get() + 1);
      self
        .remaining
        .borrow_mut()
        .push(runtime.deadline.remaining(runtime.clock));
      self.clock.advance(Duration::from_secs(2));
      Ok(PipelineSource)
    }
  }

  struct PipelineProvider<'a> {
    clock: &'a ManualClock,
    remaining: &'a RefCell<Vec<Duration>>,
    calls: &'a Cell<usize>,
    stop: Option<BoundaryStop>,
  }

  impl KeyProvider<()> for PipelineProvider<'_> {
    type Keys = usize;

    fn keys(&self, _request: &(), runtime: &BoundaryRuntime<'_>) -> Self::Keys {
      self.calls.set(self.calls.get() + 1);
      self
        .remaining
        .borrow_mut()
        .push(runtime.deadline.remaining(runtime.clock));
      match self.stop {
        None => self.clock.advance(Duration::from_secs(3)),
        Some(BoundaryStop::TimedOut) => {
          self
            .clock
            .advance(runtime.deadline.remaining(runtime.clock));
          self.remaining.borrow_mut().push(Duration::ZERO);
        }
        Some(BoundaryStop::Cancelled) => assert!(runtime.stop.cancel()),
        Some(BoundaryStop::ResourceExhausted) => assert!(runtime.stop.exhaust_resources()),
      }
      if self.stop.is_some() {
        // Cleanup is bounded by both the original absolute ceiling and one
        // grace from the moment an early non-timeout stop is observed.
        let cleanup = runtime
          .deadline
          .cleanup_deadline(CLEANUP_GRACE)
          .remaining(runtime.clock)
          .min(CLEANUP_GRACE);
        self.clock.advance(cleanup);
      }
      1
    }
  }

  struct PipelineDecoder<'a> {
    clock: &'a ManualClock,
    remaining: &'a RefCell<Vec<Duration>>,
    calls: &'a Cell<usize>,
  }

  impl Decoder<PipelineSource, usize> for PipelineDecoder<'_> {
    type Summary = usize;

    fn decode(
      &self,
      _source: &PipelineSource,
      sink: &mut dyn RecordSink<usize>,
      runtime: &BoundaryRuntime<'_>,
    ) -> anyhow::Result<Self::Summary> {
      self.calls.set(self.calls.get() + 1);
      self
        .remaining
        .borrow_mut()
        .push(runtime.deadline.remaining(runtime.clock));
      self.clock.advance(Duration::from_secs(4));
      sink.emit(1)?;
      Ok(1)
    }

    fn deadline_enforcement(&self) -> DeadlineEnforcement {
      DeadlineEnforcement::Cooperative
    }
  }

  #[test]
  fn production_boundary_pipeline_shares_one_monotonic_runtime_across_all_hops() {
    let clock = ManualClock::default();
    let deadline = Deadline::after(&clock, Duration::from_secs(12));
    let runtime = BoundaryRuntime::new(&clock, deadline);
    let remaining = RefCell::new(Vec::new());
    let acquire_calls = Cell::new(0);
    let provider_calls = Cell::new(0);
    let decoder_calls = Cell::new(0);
    let source = acquire(
      &PipelineAcquire {
        clock: &clock,
        remaining: &remaining,
        calls: &acquire_calls,
      },
      &(),
      &runtime,
    )
    .expect("acquire");
    let key = keys(
      &PipelineProvider {
        clock: &clock,
        remaining: &remaining,
        calls: &provider_calls,
        stop: None,
      },
      &(),
      &runtime,
    )
    .expect("provider");
    let mut emitted = Vec::new();
    let summary = decode(
      &PipelineDecoder {
        clock: &clock,
        remaining: &remaining,
        calls: &decoder_calls,
      },
      &source,
      &mut |record| {
        emitted.push(record);
        Ok(())
      },
      &runtime,
    )
    .expect("decode");

    assert_eq!(key, 1);
    assert_eq!(summary, 1);
    assert_eq!(emitted, [1]);
    assert_eq!(
      (
        acquire_calls.get(),
        provider_calls.get(),
        decoder_calls.get()
      ),
      (1, 1, 1)
    );
    assert_eq!(
      remaining.into_inner(),
      [
        Duration::from_secs(12),
        Duration::from_secs(10),
        Duration::from_secs(7),
      ]
    );
    assert_eq!(deadline.remaining(&clock), Duration::from_secs(3));
  }

  #[test]
  fn terminal_provider_stops_prevent_decode_and_use_at_most_one_cleanup_grace() {
    for expected in [
      BoundaryStop::TimedOut,
      BoundaryStop::Cancelled,
      BoundaryStop::ResourceExhausted,
    ] {
      let clock = ManualClock::default();
      let started = clock.now();
      let deadline = Deadline::after(&clock, Duration::from_secs(10));
      let token = CancellationToken::default();
      let runtime = BoundaryRuntime::with_stop(&clock, deadline, token);
      let remaining = RefCell::new(Vec::new());
      let acquire_calls = Cell::new(0);
      let provider_calls = Cell::new(0);
      let decoder_calls = Cell::new(0);
      let source = acquire(
        &PipelineAcquire {
          clock: &clock,
          remaining: &remaining,
          calls: &acquire_calls,
        },
        &(),
        &runtime,
      )
      .expect("acquire completes before the injected stop");
      let error = keys(
        &PipelineProvider {
          clock: &clock,
          remaining: &remaining,
          calls: &provider_calls,
          stop: Some(expected),
        },
        &(),
        &runtime,
      )
      .expect_err("provider stop remains typed");
      assert_eq!(error.downcast_ref::<BoundaryStop>(), Some(&expected));

      let mut sink = Vec::new();
      let decode_error = decode(
        &PipelineDecoder {
          clock: &clock,
          remaining: &remaining,
          calls: &decoder_calls,
        },
        &source,
        &mut |record| {
          sink.push(record);
          Ok(())
        },
        &runtime,
      )
      .expect_err("no later decoder starts after a terminal provider stop");
      assert_eq!(decode_error.downcast_ref::<BoundaryStop>(), Some(&expected));
      assert!(sink.is_empty());
      assert_eq!(
        (
          acquire_calls.get(),
          provider_calls.get(),
          decoder_calls.get()
        ),
        (1, 1, 0)
      );
      assert!(
        clock.now().duration_since(started) <= Duration::from_secs(10) + CLEANUP_GRACE,
        "{expected:?} exceeded the absolute deadline plus one cleanup grace"
      );
      let samples = remaining.borrow();
      assert!(samples.windows(2).all(|pair| pair[1] <= pair[0]));
      if expected == BoundaryStop::TimedOut {
        assert!(
          samples.contains(&Duration::ZERO),
          "exact deadline boundary was not observed"
        );
      }
    }
  }
}
