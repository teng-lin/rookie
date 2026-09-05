//! The selected set behind [`ReadResult::header`](crate::ReadResult::header).
//!
//! `header` renders a string, which is all a caller needs to make one request
//! and not enough to explain anything. [`SendView`] is the same selection
//! before it is flattened: the rows that were chosen, still carrying their
//! isolation context, plus a count of what was left out and why. Bindings and
//! the CLI render from this rather than re-implementing the match, so every
//! language answers a given context identically by construction.

use crate::common::enums::DetailedCookie;
use crate::isolation::OmitReason;
use std::fmt;

/// Rows a send view left out, counted by the first reason each failed.
///
/// A row is counted exactly once, under the first stage it failed, so the
/// counts sum to the number of rows the snapshot held minus the number
/// selected. `Debug` prints counts only; there are no cookie values here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SendOmissions {
  expired: u64,
  not_applicable: u64,
  same_site: u64,
  partition: u64,
  ancestor_chain_unknown: u64,
  unparsable_partition_key: u64,
  origin: u64,
}

impl SendOmissions {
  /// Rows whose expiry had passed at the send-time clock.
  ///
  /// Expiry is applied here regardless of
  /// [`ReadRequest::include_expired`](crate::ReadRequest::include_expired):
  /// retaining an expired cookie in an inventory is not a licence to send it.
  pub fn expired(&self) -> u64 {
    self.expired
  }

  /// Rows the RFC 6265 domain, path, `Secure`, or octet rules excluded.
  pub fn not_applicable(&self) -> u64 {
    self.not_applicable
  }

  /// Rows a `SameSite` attribute excluded for this context.
  pub fn same_site(&self) -> u64 {
    self.same_site
  }

  /// Rows whose partition key or ancestor bit named a different context.
  ///
  /// Narrower than it sounds: a container or origin-attribute mismatch counts
  /// under [`origin`](Self::origin), and a partitioned row whose ancestor bit
  /// was never recorded counts under
  /// [`ancestor_chain_unknown`](Self::ancestor_chain_unknown).
  pub fn partition(&self) -> u64 {
    self.partition
  }

  /// Partitioned Chromium rows whose store predates `has_cross_site_ancestor`.
  ///
  /// The ancestor bit is part of Chromium's partition-key equality, so a row
  /// that never recorded it cannot be compared and is omitted rather than
  /// assumed. Chromium's own schema migration may backfill a value for such a
  /// row; this crate deliberately does not guess one, because the backfilled
  /// bit is an assumption about a frame tree nobody observed.
  pub fn ancestor_chain_unknown(&self) -> u64 {
    self.ancestor_chain_unknown
  }

  /// Rows whose partition key no parser in this build understood.
  pub fn unparsable_partition_key(&self) -> u64 {
    self.unparsable_partition_key
  }

  /// Rows excluded by a container or origin-attribute selector, including
  /// rows carrying an origin attribute this build does not recognize.
  pub fn origin(&self) -> u64 {
    self.origin
  }

  /// The total number of rows omitted.
  pub fn total(&self) -> u64 {
    self
      .entries()
      .map(|(_, count)| count)
      .fold(0, u64::saturating_add)
  }

  /// Every reason and its count, in a stable declared order.
  ///
  /// All seven are yielded, zeroes included, so a serialized form has a fixed
  /// shape a consumer can rely on across releases.
  pub fn entries(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
    [
      ("expired", self.expired),
      ("not_applicable", self.not_applicable),
      ("same_site", self.same_site),
      ("partition", self.partition),
      ("ancestor_chain_unknown", self.ancestor_chain_unknown),
      ("unparsable_partition_key", self.unparsable_partition_key),
      ("origin", self.origin),
    ]
    .into_iter()
  }

  pub(crate) fn record_expired(&mut self) {
    self.expired = self.expired.saturating_add(1);
  }

  pub(crate) fn record_not_applicable(&mut self) {
    self.not_applicable = self.not_applicable.saturating_add(1);
  }

  pub(crate) fn record_same_site(&mut self) {
    self.same_site = self.same_site.saturating_add(1);
  }

  pub(crate) fn record_isolation(&mut self, reason: OmitReason) {
    let count = match reason {
      OmitReason::Partition => &mut self.partition,
      OmitReason::AncestorChainUnknown => &mut self.ancestor_chain_unknown,
      OmitReason::UnparsablePartitionKey => &mut self.unparsable_partition_key,
      OmitReason::Origin => &mut self.origin,
    };
    *count = count.saturating_add(1);
  }
}

/// The cookies one [`SendContext`](crate::SendContext) selects, in header order.
///
/// This borrows the snapshot rather than copying it, so the selected rows keep
/// their full [`DetailedCookie`] identity at no cost.
/// [`header`](Self::header) renders the same selection as a request-header
/// value, and [`ReadResult::header`](crate::ReadResult::header) is exactly that
/// composition.
///
/// `Debug` prints the selected count and the omission counts. It never prints
/// cookie names or values, which is the same rule
/// [`ReadResult`](crate::ReadResult) follows.
pub struct SendView<'a> {
  cookies: Vec<&'a DetailedCookie>,
  omitted: SendOmissions,
}

impl<'a> SendView<'a> {
  pub(crate) fn new(cookies: Vec<&'a DetailedCookie>, omitted: SendOmissions) -> Self {
    Self { cookies, omitted }
  }

  /// The selected records, in the order [`header`](Self::header) renders them:
  /// longest path first, then by name.
  pub fn cookies(&self) -> &[&'a DetailedCookie] {
    &self.cookies
  }

  /// How many records were selected.
  pub fn len(&self) -> usize {
    self.cookies.len()
  }

  /// Whether nothing was selected.
  ///
  /// An empty view is a legitimate answer, not an error: a context may simply
  /// have no cookies. [`omitted`](Self::omitted) is how a caller tells "no
  /// cookies at all" apart from "everything was excluded".
  pub fn is_empty(&self) -> bool {
    self.cookies.is_empty()
  }

  /// Renders the selection as a `Cookie` request-header value.
  pub fn header(&self) -> String {
    self
      .cookies
      .iter()
      .map(|detailed| format!("{}={}", detailed.cookie.name, detailed.cookie.value))
      .collect::<Vec<_>>()
      .join("; ")
  }

  /// What was left out, and why.
  pub fn omitted(&self) -> &SendOmissions {
    &self.omitted
  }

  /// Clones the selected records into an owned list.
  ///
  /// The borrow is the cheap path; this exists for bindings that must hand an
  /// owned value across a language boundary.
  pub fn to_detailed_cookies(&self) -> Vec<DetailedCookie> {
    self
      .cookies
      .iter()
      .map(|record| (*record).clone())
      .collect()
  }
}

impl fmt::Debug for SendView<'_> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("SendView")
      .field("selected", &self.cookies.len())
      .field("omitted", &self.omitted)
      .finish()
  }
}
