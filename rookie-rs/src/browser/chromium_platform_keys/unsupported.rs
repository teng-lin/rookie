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
    runtime: &crate::common::deadline::BoundaryRuntime<'_>,
  ) -> ChromiumKeyOutcomes {
    let _ = request;
    let _ = runtime;
    ChromiumKeyOutcomes::default()
  }
}
