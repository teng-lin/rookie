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

/// Builds a caller-input exception through one binding-owned seam.
///
/// Structured diagnostic attributes are added here by the binding diagnostics
/// layer, so option parsers must not construct [`RookieRequestError`]
/// directly.
pub(crate) fn request_error(message: impl Into<String>) -> PyErr {
  RookieRequestError::new_err(message.into())
}

/// Converts `error` into the exception [`rookie_core::fault_kind`] says it
/// is. Use this in place of the `?`-operator's blanket `anyhow` conversion
/// wherever a call site wants the request/engine split.
pub(crate) fn classify_fault(error: rookie_core::anyhow::Error) -> PyErr {
  match rookie_core::fault_kind(&error) {
    rookie_core::FaultKind::Request => RookieRequestError::new_err(format!("{error:?}")),
    // `FaultKind` is `#[non_exhaustive]`; a future variant this binding
    // doesn't know about yet falls back to the engine-fault classification,
    // matching `fault_kind`'s own documented default.
    _ => RookieEngineError::new_err(format!("{error:?}")),
  }
}
