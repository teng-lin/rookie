//! The only operations allowed to cross an extraction trust boundary.

use super::deadline::{Deadline, DeadlineEnforcement};

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

  fn open(&self, id: &Id, deadline: Deadline) -> anyhow::Result<Self::Source>;

  fn deadline_enforcement(&self) -> DeadlineEnforcement {
    DeadlineEnforcement::Cooperative
  }
}

pub(crate) trait KeyProvider<Request: ?Sized> {
  type Keys;

  fn keys(&self, request: &Request, deadline: Deadline) -> Self::Keys;

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
    deadline: Deadline,
  ) -> anyhow::Result<Self::Summary>;

  fn deadline_enforcement(&self) -> DeadlineEnforcement;
}

impl ReadOnlySource for rusqlite::Connection {}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::common::deadline::{test_clock::ManualClock, Clock};
  use std::{cell::RefCell, time::Duration};

  struct FakeDecoder<'a> {
    clock: &'a dyn Clock,
  }

  impl Decoder<rusqlite::Connection, usize> for FakeDecoder<'_> {
    type Summary = usize;

    fn decode(
      &self,
      _source: &rusqlite::Connection,
      sink: &mut dyn RecordSink<usize>,
      deadline: Deadline,
    ) -> anyhow::Result<Self::Summary> {
      let mut emitted = 0;
      for record in 0..3 {
        deadline.check(self.clock)?;
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
    let decoder = FakeDecoder { clock: &clock };
    let mut sink = AdvancingSink {
      clock: &clock,
      records: RefCell::new(Vec::new()),
    };
    decoder
      .decode(
        &rusqlite::Connection::open_in_memory().unwrap(),
        &mut sink,
        deadline,
      )
      .expect_err("third emission starts at the deadline");
    assert_eq!(sink.records.into_inner(), [0, 1]);
    assert_eq!(
      decoder.deadline_enforcement(),
      DeadlineEnforcement::Cooperative
    );
  }
}
