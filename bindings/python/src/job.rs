//! Job-layer bindings: `read` / `from_path` / `ReadResult` / `ReadWarning`.

use crate::{to_dict, PyCancellationHandle};
use ::rookie_cookies as rookie_core;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyList;
use rookie_core::enums::Cookie;

#[pyclass(name = "ReadWarning")]
#[derive(Clone)]
pub struct PyReadWarning {
  #[pyo3(get)]
  code: String,
  #[pyo3(get)]
  count: u64,
}

#[pymethods]
impl PyReadWarning {
  fn __str__(&self) -> String {
    format!("skipped {} rows ({})", self.count, self.code)
  }

  fn __repr__(&self) -> String {
    format!("ReadWarning(code={:?}, count={})", self.code, self.count)
  }
}

#[pyclass(name = "ReadResult")]
pub struct PyReadResult {
  inner: rookie_core::ReadResult,
}

impl PyReadResult {
  fn from_core(inner: rookie_core::ReadResult) -> Self {
    Self { inner }
  }
}

#[pymethods]
impl PyReadResult {
  #[getter]
  fn warnings(&self) -> Vec<PyReadWarning> {
    self
      .inner
      .warnings()
      .iter()
      .map(|warning| PyReadWarning {
        code: warning.code().to_owned(),
        count: warning.count(),
      })
      .collect()
  }

  #[getter]
  fn browser_id(&self) -> String {
    self.inner.browser_id().to_owned()
  }

  #[getter]
  fn profile_id(&self) -> Option<String> {
    self.inner.profile_id().map(str::to_owned)
  }

  fn as_list(&self, py: Python<'_>) -> PyResult<Vec<Py<PyAny>>> {
    to_dict(py, clone_cookies(self.inner.cookies()))
  }

  fn header(&self, url: &str) -> PyResult<String> {
    self
      .inner
      .header(url)
      .map_err(crate::errors::classify_fault)
  }

  fn __len__(&self) -> usize {
    self.inner.cookies().len()
  }

  fn __bool__(&self) -> bool {
    !self.inner.cookies().is_empty()
  }

  fn __iter__(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
    let items = self.as_list(py)?;
    let list = PyList::new(py, items)?;
    Ok(list.getattr("__iter__")?.call0()?.unbind())
  }
}

fn clone_cookies(cookies: &[Cookie]) -> Vec<Cookie> {
  cookies
    .iter()
    .map(|cookie| Cookie {
      domain: cookie.domain.clone(),
      path: cookie.path.clone(),
      secure: cookie.secure,
      expires: cookie.expires,
      name: cookie.name.clone(),
      value: cookie.value.clone(),
      http_only: cookie.http_only,
      same_site: cookie.same_site,
    })
    .collect()
}

fn duration_from_seconds(seconds: f64) -> PyResult<std::time::Duration> {
  std::time::Duration::try_from_secs_f64(seconds).map_err(|_| {
    PyValueError::new_err(
      "timeout must be a non-negative, finite number of seconds representable as a Duration",
    )
  })
}

/// Read an unfiltered snapshot of one browser profile.
///
/// :param browser: Canonical browser ID or registered alias
/// :param profile: Optional profile id, display name, directory, or path
/// :param include_expired: Keep expired cookies (default false)
/// :param timeout: Optional timeout in seconds
/// :param cancellation: Optional CancellationHandle
/// :return: A ReadResult snapshot (never URL-filtered)
/// :raises TypeError: ``browser`` was omitted
/// :raises RookieRequestError: Unknown browser or profile selector
#[pyfunction]
#[pyo3(signature = (*, browser, profile=None, include_expired=false, timeout=None, cancellation=None))]
pub fn read(
  py: Python<'_>,
  browser: String,
  profile: Option<String>,
  include_expired: bool,
  timeout: Option<f64>,
  cancellation: Option<PyCancellationHandle>,
) -> PyResult<PyReadResult> {
  let mut request = rookie_core::ReadRequest::browser(browser);
  if let Some(profile) = profile {
    request = request.profile(profile);
  }
  request = request.include_expired(include_expired);
  if let Some(timeout) = timeout {
    request = request.timeout(duration_from_seconds(timeout)?);
  }
  if let Some(cancellation) = cancellation {
    request = request.cancellation(cancellation.0);
  }
  let result = py
    .detach(|| rookie_core::read(request))
    .map_err(crate::errors::classify_fault)?;
  Ok(PyReadResult::from_core(result))
}

/// Read cookies from an explicit cookie database path.
///
/// :param path: Path to a cookie database or cookies file
/// :param include_expired: Keep expired cookies (default false)
/// :param timeout: Optional timeout in seconds
/// :param cancellation: Optional CancellationHandle
/// :return: A ReadResult snapshot
#[pyfunction]
#[pyo3(signature = (path, *, include_expired=false, timeout=None, cancellation=None))]
pub fn from_path(
  py: Python<'_>,
  path: String,
  include_expired: bool,
  timeout: Option<f64>,
  cancellation: Option<PyCancellationHandle>,
) -> PyResult<PyReadResult> {
  let mut request = rookie_core::FromPathRequest::new(path);
  request = request.include_expired(include_expired);
  if let Some(timeout) = timeout {
    request = request.timeout(duration_from_seconds(timeout)?);
  }
  if let Some(cancellation) = cancellation {
    request = request.cancellation(cancellation.0);
  }
  let result = py
    .detach(|| rookie_core::from_path(request))
    .map_err(crate::errors::classify_fault)?;
  Ok(PyReadResult::from_core(result))
}
