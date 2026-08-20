//! Fault-classified exceptions raised across the FFI boundary.
//!
//! Every extraction/discovery function used to convert its `anyhow::Error`
//! into a flat [`pyo3::exceptions::PyRuntimeError`] (via pyo3's `anyhow`
//! feature's blanket `From` conversion on `?`). [`classify_fault`] replaces
//! that blanket conversion at each call site with
//! [`rookie_core::fault_kind`]'s request/engine split, so a caller can
//! `except` the two apart instead of parsing a message string.
//!
//! [`RookieRequestError`] subclasses [`pyo3::exceptions::PyValueError`] and
//! [`RookieEngineError`] subclasses [`pyo3::exceptions::PyRuntimeError`], so
//! an `except ValueError`/`except RuntimeError` around a function that
//! already raised `RuntimeError` before this change keeps catching it --
//! but this is a real behavior change where `fault_kind` newly classifies
//! something as `Request`: `cookies_from_path` and
//! `chromium_cookies_from_path(_detailed)` previously always raised
//! `RuntimeError` and now raise `RookieRequestError`/`ValueError` for a
//! request fault (e.g. a missing or malformed explicit source), so an
//! `except RuntimeError` around only those three functions no longer
//! catches that case. See CHANGELOG.md.

use ::rookie_cookies as rookie_core;
use pyo3::create_exception;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

create_exception!(
  rookie_cookies,
  RookieRequestError,
  PyValueError,
  "The caller's input was invalid -- an unsupported option or an explicit \
   source that does not match its declared kind. Fixable by changing what \
   was passed in."
);

create_exception!(
  rookie_cookies,
  RookieEngineError,
  PyRuntimeError,
  "Extraction or engine failure unrelated to caller input."
);

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
  m.add(
    "RookieRequestError",
    m.py().get_type::<RookieRequestError>(),
  )?;
  m.add("RookieEngineError", m.py().get_type::<RookieEngineError>())?;
  Ok(())
}

struct BindingErrorAttributes {
  kind: &'static str,
  code: Option<&'static str>,
  stop_reason: Option<&'static str>,
  profile_ids: Vec<String>,
  source_kind: Option<String>,
  target_os: Option<String>,
  path_redacted: bool,
}

fn attach_attributes(exception: PyErr, attributes: BindingErrorAttributes) -> PyErr {
  let attached = Python::attach(|py| -> PyResult<()> {
    let value = exception.value(py);
    value.setattr("kind", attributes.kind)?;
    value.setattr("code", attributes.code)?;
    value.setattr("stop_reason", attributes.stop_reason)?;
    value.setattr("profile_ids", attributes.profile_ids)?;
    value.setattr("source_kind", attributes.source_kind)?;
    value.setattr("target_os", attributes.target_os)?;
    value.setattr("path_redacted", attributes.path_redacted)?;
    Ok(())
  });
  if let Err(attribute_error) = attached {
    return attribute_error;
  }
  exception
}

/// Constructs a caller-fixable binding error with the complete diagnostic
/// shape. Binding-level validation that has no core error metadata should use
/// this instead of constructing [`RookieRequestError`] directly.
pub(crate) fn request_error(message: impl Into<String>) -> PyErr {
  attach_attributes(
    RookieRequestError::new_err(message.into()),
    BindingErrorAttributes {
      kind: "request",
      code: None,
      stop_reason: None,
      profile_ids: Vec::new(),
      source_kind: None,
      target_os: None,
      path_redacted: false,
    },
  )
}

/// Converts `error` into the exception [`rookie_core::fault_kind`] says it
/// is. Use this in place of the `?`-operator's blanket `anyhow` conversion
/// wherever a call site wants the request/engine split.
pub(crate) fn classify_fault(error: rookie_core::anyhow::Error) -> PyErr {
  let request = error.downcast_ref::<rookie_core::RequestError>();
  let direct = error.downcast_ref::<rookie_core::direct_path::DirectPathError>();
  let stop_reason = rookie_core::stop_reason(&error).map(|reason| match reason {
    rookie_core::StopReason::TimedOut => "timed_out",
    rookie_core::StopReason::Cancelled => "cancelled",
    rookie_core::StopReason::ResourceExhausted => "resource_exhausted",
    _ => "unknown",
  });
  let kind = rookie_core::fault_kind(&error);
  let code = stop_reason
    .or_else(|| request.map(rookie_core::RequestError::code))
    .or_else(|| direct.map(rookie_core::direct_path::DirectPathError::code));
  let profile_ids = request
    .map(rookie_core::RequestError::profile_ids)
    .unwrap_or_default()
    .to_vec();
  let source_kind = direct
    .and_then(rookie_core::direct_path::DirectPathError::source_kind)
    .map(|source| source.to_string());
  let target_os = direct
    .and_then(rookie_core::direct_path::DirectPathError::target_os)
    .map(str::to_owned);
  let path_redacted = direct
    .and_then(rookie_core::direct_path::DirectPathError::path)
    .is_some();

  let exception = match kind {
    rookie_core::FaultKind::Request => request_error(format!("{error:?}")),
    // `FaultKind` is `#[non_exhaustive]`; a future variant this binding
    // doesn't know about yet falls back to the engine-fault classification,
    // matching `fault_kind`'s own documented default.
    _ => RookieEngineError::new_err(format!("{error:?}")),
  };

  // `request_error` can itself return an attribute-assignment failure. Do not
  // hide that PyErr by decorating it as though it were the original request.
  if matches!(kind, rookie_core::FaultKind::Request)
    && !Python::attach(|py| exception.is_instance_of::<RookieRequestError>(py))
  {
    return exception;
  }

  attach_attributes(
    exception,
    BindingErrorAttributes {
      kind: match kind {
        rookie_core::FaultKind::Request => "request",
        _ => "engine",
      },
      code,
      stop_reason,
      profile_ids,
      source_kind,
      target_os,
      path_redacted,
    },
  )
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn request_error_supplies_the_complete_default_diagnostic_shape() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
      let error = request_error("invalid binding options");
      assert!(error.is_instance_of::<RookieRequestError>(py));
      let value = error.value(py);
      assert_eq!(value.getattr("kind")?.extract::<String>()?, "request");
      assert!(value.getattr("code")?.is_none());
      assert!(value.getattr("stop_reason")?.is_none());
      assert!(value
        .getattr("profile_ids")?
        .extract::<Vec<String>>()?
        .is_empty());
      assert!(value.getattr("source_kind")?.is_none());
      assert!(value.getattr("target_os")?.is_none());
      assert!(!value.getattr("path_redacted")?.extract::<bool>()?);
      Ok(())
    })
    .expect("request-error defaults must be readable from Python");
  }
}
