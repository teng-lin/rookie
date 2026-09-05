//! Fault-classified exceptions raised across the FFI boundary.
//!
//! Every extraction/discovery function used to convert its `anyhow::Error`
//! into a flat [`pyo3::exceptions::PyRuntimeError`] (via pyo3's `anyhow`
//! feature's blanket `From` conversion on `?`). This module replaces that
//! blanket conversion at each call site with a four-class hierarchy that
//! mirrors [`rookie_core::Error`]:
//!
//! ```text
//! RookieError (Exception)
//! +-- RookieRequestError (+ ValueError)   -- caller input was invalid
//! |   `-- RookieSourceError                -- an explicit path/option was invalid
//! +-- RookieStoppedError (+ RuntimeError)  -- cooperative timeout/cancel/resource stop
//! `-- RookieEngineError (+ RuntimeError)   -- discovery/acquisition/decryption failure
//! ```
//!
//! [`RookieRequestError`] and [`RookieEngineError`] existed before 0.6.0 and
//! kept their original bases (`ValueError`/`RuntimeError` respectively) so an
//! `except ValueError`/`except RuntimeError` written against the old
//! two-class split keeps catching exactly what it used to. [`RookieSourceError`]
//! is new in 0.6.0 but was already reachable as a `RookieRequestError`/`ValueError`
//! before this crate distinguished caller-input mistakes from bad explicit
//! paths -- it subclasses [`RookieRequestError`] (rather than sitting beside
//! it under [`RookieError`]) specifically so that old `except RookieRequestError`
//! and `except ValueError` handlers keep catching a direct-path fault too. See
//! CHANGELOG.md.
//!
//! [`classify_error`] is the primary classifier now that the core crate
//! returns a typed [`rookie_core::Error`]. [`classify_fault`] remains only for
//! the deprecated v0.5.9 bridge functions, which still return
//! `anyhow::Result` and therefore never produce an [`rookie_core::Error`]
//! directly.

use ::rookie_cookies as rookie_core;
use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyTuple, PyType};
use std::ffi::CString;

create_exception!(
  rookie_cookies,
  RookieError,
  PyException,
  "Common base for every exception this crate raises. Catch this to handle \
   any rookie_cookies failure without distinguishing its kind."
);

/// Builds a Python exception type with two independent bases.
///
/// [`pyo3::create_exception!`] only supports a single base -- its
/// `PyErr::new_type` takes `Option<&Bound<PyType>>`, not a tuple -- but
/// [`RookieRequestError`], [`RookieStoppedError`], and [`RookieEngineError`]
/// each need two bases at once: [`RookieError`] (so `except RookieError`
/// catches all four classes) *and* the pre-existing builtin
/// (`ValueError`/`RuntimeError`) that callers already `except`. CPython's C
/// API supports this directly -- `PyErr_NewExceptionWithDoc`'s `base`
/// argument accepts a tuple of bases, which is how `class Foo(Bar, Baz)` is
/// expressed underneath -- so this calls it directly rather than going
/// through pyo3's single-base wrapper.
fn new_two_base_exception_type(
  py: Python<'_>,
  qualified_name: &str,
  base_a: &Bound<'_, PyType>,
  base_b: &Bound<'_, PyType>,
  doc: &str,
) -> Py<PyType> {
  // `CString::new` only fails on an embedded NUL, which none of our static
  // names or doc strings contain.
  let qualified_name = CString::new(qualified_name).expect("exception name must not contain NUL");
  let doc = CString::new(doc).expect("exception doc must not contain NUL");
  let bases = PyTuple::new(py, [base_a.clone().into_any(), base_b.clone().into_any()])
    .expect("building a 2-element tuple from 2 elements cannot fail");
  // SAFETY: `PyErr_NewExceptionWithDoc` returns a new reference to a freshly
  // created type object on success, or null (with a Python exception set) on
  // failure. `from_owned_ptr_or_err` turns that into the usual `PyResult`.
  // The `.expect` below is sound because every call site passes a static,
  // well-formed name/doc/base set -- failure here would mean the interpreter
  // itself is out of memory, not a caller mistake.
  unsafe {
    let ptr = pyo3::ffi::PyErr_NewExceptionWithDoc(
      qualified_name.as_ptr(),
      doc.as_ptr(),
      bases.as_ptr(),
      std::ptr::null_mut(),
    );
    Bound::<PyAny>::from_owned_ptr_or_err(py, ptr)
      .expect("PyErr_NewExceptionWithDoc failed for a static, known-good definition")
      .cast_into_unchecked::<PyType>()
      .unbind()
  }
}

/// Declares an exception class with two Python bases, wired the same way
/// [`pyo3::create_exception!`] wires a single-base one (a `new_err`
/// constructor, `ToPyErr`, and a lazily created, cached type object) but
/// backed by [`new_two_base_exception_type`] instead.
macro_rules! two_base_exception {
  ($name:ident, $base_a:ty, $base_b:ty, $doc:expr) => {
    #[repr(transparent)]
    #[doc = $doc]
    pub struct $name(PyAny);

    pyo3::impl_exception_boilerplate!($name);
    pyo3::pyobject_native_type_named!($name);

    // SAFETY: `type_object_raw` returns a pointer to a type object that
    // stays alive for the process lifetime (owned by the static below), and
    // is in fact a Python type (constructed by `PyErr_NewExceptionWithDoc`).
    unsafe impl pyo3::type_object::PyTypeInfo for $name {
      const NAME: &'static str = stringify!($name);
      const MODULE: ::core::option::Option<&'static str> =
        ::core::option::Option::Some("rookie_cookies");

      #[inline]
      fn type_object_raw(py: Python<'_>) -> *mut pyo3::ffi::PyTypeObject {
        static TYPE_OBJECT: PyOnceLock<Py<PyType>> = PyOnceLock::new();
        TYPE_OBJECT
          .get_or_init(py, || {
            new_two_base_exception_type(
              py,
              concat!("rookie_cookies.", stringify!($name)),
              &py.get_type::<$base_a>(),
              &py.get_type::<$base_b>(),
              $doc,
            )
          })
          .as_ptr()
          .cast()
      }
    }
  };
}

two_base_exception!(
  RookieRequestError,
  RookieError,
  PyValueError,
  "The caller's input was invalid -- an unsupported option or an explicit \
   source that does not match its declared kind. Fixable by changing what \
   was passed in."
);

two_base_exception!(
  RookieStoppedError,
  RookieError,
  PyRuntimeError,
  "The operation stopped cooperatively before producing a result: a \
   timeout elapsed, a CancellationHandle was cancelled, or an internal \
   resource limit was reached. See the `stop_reason` attribute."
);

two_base_exception!(
  RookieEngineError,
  RookieError,
  PyRuntimeError,
  "Extraction or engine failure unrelated to caller input: discovery, \
   acquisition, or decryption failed."
);

create_exception!(
  rookie_cookies,
  RookieSourceError,
  RookieRequestError,
  "A caller-supplied path or path option was invalid -- an explicit source \
   that does not exist, does not match its declared kind, or is not \
   supported on this platform. Subclasses RookieRequestError/ValueError \
   (rather than sitting beside it under RookieError) so an `except \
   RookieRequestError` or `except ValueError` written before this class \
   existed keeps catching a direct-path fault."
);

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
  m.add("RookieError", m.py().get_type::<RookieError>())?;
  m.add(
    "RookieRequestError",
    m.py().get_type::<RookieRequestError>(),
  )?;
  m.add(
    "RookieStoppedError",
    m.py().get_type::<RookieStoppedError>(),
  )?;
  m.add("RookieSourceError", m.py().get_type::<RookieSourceError>())?;
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
  /// The `SendContext` selectors `header()` needed but did not receive.
  /// Empty for every kind except `RequestError::IncompleteSendContext`.
  required: Vec<String>,
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
    value.setattr("required", attributes.required)?;
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
      required: Vec::new(),
    },
  )
}

/// Stable string for a [`rookie_core::StopReason`], mirroring
/// [`rookie_core::Error::code`]'s own values for the `Stopped` variant.
fn stop_reason_code(reason: rookie_core::StopReason) -> &'static str {
  match reason {
    rookie_core::StopReason::TimedOut => "timed_out",
    rookie_core::StopReason::Cancelled => "cancelled",
    rookie_core::StopReason::ResourceExhausted => "resource_exhausted",
    // `StopReason` is `#[non_exhaustive]`; an unrecognized future reason
    // still needs a stable string, not a panic.
    _ => "unknown",
  }
}

/// Converts `error` into the exception its [`rookie_core::Error`] variant
/// names. This is the primary classifier: every 0.6 job function returns a
/// typed [`rookie_core::Error`] rather than an `anyhow` chain, so classifying
/// it is a variant match, not a downcast.
pub(crate) fn classify_error(error: rookie_core::Error) -> PyErr {
  // `Error`'s `Display` already delegates to whichever variant it wraps
  // (`RequestError`, the friendly stop text, `DirectPathError`, or
  // `EngineError`'s sanitized message), so this is the one place that needs
  // to format it -- never parse it back apart to classify.
  let message = error.to_string();
  match &error {
    rookie_core::Error::Request(request) => attach_attributes(
      RookieRequestError::new_err(message),
      BindingErrorAttributes {
        kind: "request",
        code: Some(request.code()),
        stop_reason: None,
        profile_ids: request.profile_ids().to_vec(),
        source_kind: None,
        target_os: None,
        path_redacted: false,
        // `IncompleteSendContext` is the only variant with no accessor
        // method of its own (unlike `profile_ids()` for `AmbiguousProfile`),
        // so this matches its field directly rather than adding one just for
        // this one binding-facing attribute.
        required: match request {
          rookie_core::RequestError::IncompleteSendContext { required, .. }
          | rookie_core::RequestError::IsolationLossRefused { required, .. } => required.clone(),
          _ => Vec::new(),
        },
      },
    ),
    rookie_core::Error::Stopped(reason) => attach_attributes(
      RookieStoppedError::new_err(message),
      BindingErrorAttributes {
        kind: "stopped",
        code: Some(error.code()),
        stop_reason: Some(stop_reason_code(*reason)),
        profile_ids: Vec::new(),
        source_kind: None,
        target_os: None,
        path_redacted: false,
        required: Vec::new(),
      },
    ),
    rookie_core::Error::Source(source) => attach_attributes(
      RookieSourceError::new_err(message),
      BindingErrorAttributes {
        kind: "source",
        code: Some(source.code()),
        stop_reason: None,
        profile_ids: Vec::new(),
        source_kind: source.source_kind().map(|kind| kind.to_string()),
        target_os: source.target_os().map(str::to_owned),
        path_redacted: source.path().is_some(),
        required: Vec::new(),
      },
    ),
    rookie_core::Error::Engine(engine) => attach_attributes(
      RookieEngineError::new_err(message),
      BindingErrorAttributes {
        kind: "engine",
        code: Some(engine.code()),
        stop_reason: None,
        profile_ids: Vec::new(),
        source_kind: None,
        target_os: None,
        path_redacted: false,
        required: Vec::new(),
      },
    ),
    // `rookie_core::Error` is `#[non_exhaustive]`; an unrecognized future
    // variant falls back to the engine classification -- the least specific,
    // least caller-actionable of the four -- matching the default the
    // deprecated `FaultKind` split itself documents.
    _ => attach_attributes(
      RookieEngineError::new_err(message),
      BindingErrorAttributes {
        kind: "engine",
        code: Some(error.code()),
        stop_reason: None,
        profile_ids: Vec::new(),
        source_kind: None,
        target_os: None,
        path_redacted: false,
        required: Vec::new(),
      },
    ),
  }
}

/// Converts a deprecated bridge function's `anyhow::Error` the same way
/// [`classify_error`] would classify the typed error it stands in for.
///
/// Kept only for the v0.5.9 bridge functions, which still return
/// `anyhow::Result` and therefore never produce an [`rookie_core::Error`]
/// directly. `rookie_core::Error`'s own `From<anyhow::Error>` applies the
/// identical classification the job edges use internally, so there is
/// exactly one classifier, not two independent ones to keep in sync.
pub(crate) fn classify_fault(error: rookie_core::anyhow::Error) -> PyErr {
  classify_error(rookie_core::Error::from(error))
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
      assert!(value
        .getattr("required")?
        .extract::<Vec<String>>()?
        .is_empty());
      Ok(())
    })
    .expect("request-error defaults must be readable from Python");
  }

  #[test]
  fn classify_error_carries_incomplete_send_context_s_required_selectors() {
    Python::initialize();
    let required = vec!["top_level_site".to_owned(), "user_context_id".to_owned()];
    let error = rookie_core::Error::from(rookie_core::RequestError::IncompleteSendContext {
      display: "https://example.com/".to_owned(),
      required: required.clone(),
    });
    let exception = classify_error(error);
    Python::attach(|py| -> PyResult<()> {
      assert!(exception.is_instance_of::<RookieRequestError>(py));
      let value = exception.value(py);
      assert_eq!(
        value.getattr("code")?.extract::<String>()?,
        "incomplete_send_context"
      );
      assert_eq!(
        value.getattr("required")?.extract::<Vec<String>>()?,
        required
      );
      Ok(())
    })
    .expect("classified IncompleteSendContext error must carry required selectors");
  }

  /// Every class in the hierarchy must satisfy *both* of its bases, not just
  /// the one it was constructed to demonstrate -- this is the load-bearing
  /// property the raw `PyErr_NewExceptionWithDoc` call above exists for.
  #[test]
  fn every_exception_class_satisfies_both_of_its_bases() {
    Python::initialize();
    Python::attach(|py| {
      let request = RookieRequestError::new_err("x");
      assert!(request.is_instance_of::<RookieError>(py));
      assert!(request.is_instance_of::<PyValueError>(py));
      assert!(request.is_instance_of::<RookieRequestError>(py));

      let stopped = RookieStoppedError::new_err("x");
      assert!(stopped.is_instance_of::<RookieError>(py));
      assert!(stopped.is_instance_of::<PyRuntimeError>(py));

      let engine = RookieEngineError::new_err("x");
      assert!(engine.is_instance_of::<RookieError>(py));
      assert!(engine.is_instance_of::<PyRuntimeError>(py));

      // The compatibility-preserving link: a source fault used to raise
      // RookieRequestError/ValueError before this class existed, so it must
      // still satisfy both.
      let source = RookieSourceError::new_err("x");
      assert!(source.is_instance_of::<RookieError>(py));
      assert!(source.is_instance_of::<RookieRequestError>(py));
      assert!(source.is_instance_of::<PyValueError>(py));
    });
  }

  #[test]
  fn classify_error_maps_request_variant_with_its_code_and_profile_ids() {
    Python::initialize();
    let profile_ids = vec!["a".to_owned(), "b".to_owned()];
    let error = rookie_core::Error::from(rookie_core::RequestError::AmbiguousProfile {
      browser_id: "chrome".to_owned(),
      query: "work".to_owned(),
      profile_ids: profile_ids.clone(),
    });
    let exception = classify_error(error);
    Python::attach(|py| -> PyResult<()> {
      assert!(exception.is_instance_of::<RookieRequestError>(py));
      assert!(exception.is_instance_of::<RookieError>(py));
      let value = exception.value(py);
      assert_eq!(value.getattr("kind")?.extract::<String>()?, "request");
      assert_eq!(
        value.getattr("code")?.extract::<String>()?,
        "ambiguous_profile"
      );
      assert_eq!(
        value.getattr("profile_ids")?.extract::<Vec<String>>()?,
        profile_ids
      );
      Ok(())
    })
    .expect("classified request error must carry request metadata");
  }

  #[test]
  fn classify_error_maps_source_variant_from_a_real_direct_path_fault() {
    Python::initialize();
    // A nonexistent path is classified identically on every platform, so
    // this needs no filesystem fixture: `extract_from_path` fails
    // classifying the source before it ever reaches platform-specific code.
    let request = rookie_core::direct_path::PathExtractRequest::sniff("/nonexistent/path/Cookies");
    let error = rookie_core::direct_path::extract_from_path(request)
      .expect_err("a nonexistent path must not classify as a valid cookie source");
    assert!(matches!(error, rookie_core::Error::Source(_)));
    let exception = classify_error(error);
    Python::attach(|py| -> PyResult<()> {
      assert!(exception.is_instance_of::<RookieSourceError>(py));
      assert!(exception.is_instance_of::<RookieRequestError>(py));
      assert!(exception.is_instance_of::<RookieError>(py));
      let value = exception.value(py);
      assert_eq!(value.getattr("kind")?.extract::<String>()?, "source");
      assert!(value.getattr("path_redacted")?.extract::<bool>()?);
      Ok(())
    })
    .expect("classified source error must carry source metadata");
  }

  #[test]
  fn classify_error_maps_source_inspection_failure_to_engine_runtime_error() {
    Python::initialize();
    let error =
      rookie_core::Error::from(rookie_core::direct_path::DirectPathError::InvalidSource {
        path: std::path::PathBuf::from("/private/secret/profile/Cookies"),
        reason: rookie_core::direct_path::InvalidCookieSourceReason::SourceInspectionFailed,
      });
    assert!(matches!(error, rookie_core::Error::Engine(_)));
    let exception = classify_error(error);
    Python::attach(|py| -> PyResult<()> {
      assert!(exception.is_instance_of::<RookieEngineError>(py));
      assert!(exception.is_instance_of::<PyRuntimeError>(py));
      assert!(!exception.is_instance_of::<RookieSourceError>(py));
      assert!(!exception.is_instance_of::<PyValueError>(py));
      let value = exception.value(py);
      assert_eq!(value.getattr("kind")?.extract::<String>()?, "engine");
      assert_eq!(
        value.getattr("code")?.extract::<String>()?,
        "source_inspection_failed"
      );
      assert!(!value.str()?.to_string_lossy().contains("/private/secret"));
      Ok(())
    })
    .expect("classified inspection failure must be an engine runtime error");
  }

  #[test]
  fn stop_reason_code_names_every_reason_including_the_unreachable_one() {
    // `timed_out` and `cancelled` are reachable from every binding, and
    // `tests/python/test_binding_runtime.py` asserts both from Python.
    // `resource_exhausted` is mapped for the internal
    // `CancellationToken::exhaust_resources` seam that no public entry point
    // drives yet, so this is the only place its string is pinned.
    assert_eq!(
      stop_reason_code(rookie_core::StopReason::TimedOut),
      "timed_out"
    );
    assert_eq!(
      stop_reason_code(rookie_core::StopReason::Cancelled),
      "cancelled"
    );
    assert_eq!(
      stop_reason_code(rookie_core::StopReason::ResourceExhausted),
      "resource_exhausted"
    );
  }

  #[test]
  fn every_stop_reason_classifies_as_a_stopped_error_carrying_its_reason() {
    Python::initialize();
    for (reason, expected) in [
      (rookie_core::StopReason::TimedOut, "timed_out"),
      (rookie_core::StopReason::Cancelled, "cancelled"),
      (
        rookie_core::StopReason::ResourceExhausted,
        "resource_exhausted",
      ),
    ] {
      let exception = classify_error(rookie_core::Error::Stopped(reason));
      Python::attach(|py| -> PyResult<()> {
        assert!(exception.is_instance_of::<RookieStoppedError>(py));
        assert!(exception.is_instance_of::<PyRuntimeError>(py));
        let value = exception.value(py);
        assert_eq!(value.getattr("kind")?.extract::<String>()?, "stopped");
        assert_eq!(value.getattr("stop_reason")?.extract::<String>()?, expected);
        assert!(value.getattr("source_kind")?.is_none());
        assert!(value
          .getattr("required")?
          .extract::<Vec<String>>()?
          .is_empty());
        Ok(())
      })
      .expect("every stop reason must classify as a stopped runtime error");
    }
  }
}
