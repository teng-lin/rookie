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
  use crate::common::deadline::{test_clock::ManualClock, Clock, Deadline};
  use std::{cell::RefCell, time::Duration};

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
}
