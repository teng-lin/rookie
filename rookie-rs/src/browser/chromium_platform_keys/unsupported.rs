use super::ChromiumKeyRequest;
use crate::browser::chromium_crypto::ChromiumKeyOutcomes;

pub(crate) struct HostKeySession;

impl HostKeySession {
  pub(crate) fn new() -> Self {
    Self
  }

  pub(crate) fn retrieve(
    &mut self,
    request: ChromiumKeyRequest<'_>,
    deadline: crate::common::deadline::Deadline,
  ) -> ChromiumKeyOutcomes {
    let _ = request;
    let _ = deadline;
    ChromiumKeyOutcomes::default()
  }
}
