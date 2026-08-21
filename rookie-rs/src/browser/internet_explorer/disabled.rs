use crate::browser::internet_explorer_model::{
  InternetExplorerFailure, InternetExplorerFailureStage,
};
use crate::browser::source::{Source, SourceCandidate};
use crate::common::deadline::BoundaryRuntime;
use anyhow::{anyhow, Result};

pub(super) const DISABLED_MESSAGE: &str =
  "Internet Explorer support is disabled; rebuild with the `internet-explorer` feature";

pub(super) fn query_source(
  _origin: SourceCandidate,
  _domains: Option<Vec<String>>,
  _force_kill: bool,
  _runtime: &BoundaryRuntime<'_>,
) -> Result<Source> {
  Err(anyhow::Error::new(InternetExplorerFailure::new(
    InternetExplorerFailureStage::Acquisition,
    anyhow!(DISABLED_MESSAGE),
  )))
}
