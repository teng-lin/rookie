use super::ChromiumKeyRequest;
use crate::browser::chromium_crypto::ChromiumKeyOutcomes;
use crate::common::deadline::BoundaryRuntime;
use crate::config::Browser;
use anyhow::Result;

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

pub(crate) fn legacy_key_outcomes(
  config: &Browser,
  runtime: &BoundaryRuntime<'_>,
) -> Result<ChromiumKeyOutcomes> {
  let _ = (config, runtime);
  anyhow::bail!("Chromium cookie extraction is unsupported on this Unix platform")
}
