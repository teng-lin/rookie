//! Job-layer bindings: `read` / `from_path` / `ReadResult` / `ReadWarning`.

use crate::errors::request_error;
use crate::{detailed_to_dict, to_dict, PyCancellationHandle};
use ::rookie_cookies as rookie_core;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
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

  /// `None` for a direct-path snapshot (`from_path`), which never passes
  /// through browser discovery and has no registry identity to report.
  #[getter]
  fn browser_id(&self) -> Option<String> {
    self.inner.browser_id().map(str::to_owned)
  }

  #[getter]
  fn profile_id(&self) -> Option<String> {
    self.inner.profile_id().map(str::to_owned)
  }

  fn as_list(&self, py: Python<'_>) -> PyResult<Vec<Py<PyAny>>> {
    to_dict(py, clone_cookies(self.inner.cookies()))
  }

  /// Isolation-intact records: each item is `{"cookie": <8-field dict>,
  /// "context": <CookieContext dict>}`. Recommended over `as_list()` /
  /// `cookies()` whenever CHIPS partitioning or a Firefox container matters,
  /// since the compatibility `Cookie` projection cannot represent either.
  fn detailed_cookies(&self, py: Python<'_>) -> PyResult<Vec<Py<PyAny>>> {
    detailed_to_dict(py, self.inner.detailed_cookies().to_vec())
  }

  /// Formats a send-safe `Cookie` request-header value.
  ///
  /// `context` is positional-only and accepts either a plain URL string
  /// (equivalent to `SendContext::url(...)` -- every other field defaults)
  /// or a mapping with the same keys the keyword arguments below take.
  /// Explicit keyword arguments always win over a same-named mapping entry,
  /// so `header({"url": u}, top_level_site=t)` composes rather than
  /// conflicting. At least one of `context` or `url=` must supply a URL.
  ///
  /// :param context: A URL string, or a mapping of the keyword arguments below
  /// :param url: The request URL (http/https only)
  /// :param top_level_site: The top-level site the request is made from.
  ///     Required as soon as the snapshot holds any CHIPS-partitioned cookie.
  /// :param resource: "navigation" or "subresource" (default)
  /// :param method: "safe" (default) or "unsafe"
  /// :param user_context_id: Firefox Multi-Account Containers identity
  /// :param private_browsing_id: Firefox private-browsing identity
  /// :param now: Epoch seconds overriding the send-time clock (default: now)
  /// :raises RookieRequestError: An invalid/missing URL or top-level site
  ///     (`invalid_url` / `invalid_top_level_site`), an unrepresentable clock
  ///     (`clock_unrepresentable`), or a snapshot that positively observes an
  ///     isolated value `context` did not select (`incomplete_send_context` --
  ///     see the `required` attribute for which selectors were missing)
  #[pyo3(signature = (
    context=None,
    /,
    *,
    url=None,
    top_level_site=None,
    resource=None,
    method=None,
    user_context_id=None,
    private_browsing_id=None,
    now=None,
  ))]
  #[allow(clippy::too_many_arguments)]
  fn header(
    &self,
    context: Option<Bound<'_, PyAny>>,
    url: Option<String>,
    top_level_site: Option<String>,
    resource: Option<String>,
    method: Option<String>,
    user_context_id: Option<u32>,
    private_browsing_id: Option<u32>,
    now: Option<f64>,
  ) -> PyResult<String> {
    let context = build_send_context(
      context,
      url,
      top_level_site,
      resource,
      method,
      user_context_id,
      private_browsing_id,
      now,
    )?;
    self
      .inner
      .header(&context)
      .map_err(crate::errors::classify_error)
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

/// The keys `header()`'s mapping form of `context` accepts -- the same names
/// as its keyword arguments.
const SEND_CONTEXT_KEYS: &[&str] = &[
  "url",
  "top_level_site",
  "resource",
  "method",
  "user_context_id",
  "private_browsing_id",
  "now",
];

fn send_context_mapping_value<'py>(
  mapping: &Bound<'py, PyDict>,
  key: &str,
) -> PyResult<Option<Bound<'py, PyAny>>> {
  Ok(mapping.get_item(key)?.filter(|value| !value.is_none()))
}

/// Merges `header()`'s positional `context` (a URL string or a mapping) with
/// its keyword arguments into one [`rookie_core::SendContext`].
///
/// `context` supplies defaults; an explicit keyword argument always wins over
/// the same-named mapping entry, so `header({"url": u}, top_level_site=t)`
/// composes instead of conflicting.
#[allow(clippy::too_many_arguments)]
fn build_send_context(
  context: Option<Bound<'_, PyAny>>,
  url: Option<String>,
  top_level_site: Option<String>,
  resource: Option<String>,
  method: Option<String>,
  user_context_id: Option<u32>,
  private_browsing_id: Option<u32>,
  now: Option<f64>,
) -> PyResult<rookie_core::SendContext> {
  let mut default_url = None;
  let mut default_top_level_site = None;
  let mut default_resource = None;
  let mut default_method = None;
  let mut default_user_context_id = None;
  let mut default_private_browsing_id = None;
  let mut default_now = None;

  if let Some(context) = context {
    if let Ok(url) = context.extract::<String>() {
      default_url = Some(url);
    } else if let Ok(mapping) = context.cast::<PyDict>() {
      for (key, _) in mapping.iter() {
        let key: String = key
          .extract()
          .map_err(|_| request_error("header() context keys must be strings"))?;
        if !SEND_CONTEXT_KEYS.contains(&key.as_str()) {
          return Err(request_error(format!(
            "unknown header() context key: {key}"
          )));
        }
      }
      default_url = send_context_mapping_value(mapping, "url")?
        .map(|value| value.extract())
        .transpose()?;
      default_top_level_site = send_context_mapping_value(mapping, "top_level_site")?
        .map(|value| value.extract())
        .transpose()?;
      default_resource = send_context_mapping_value(mapping, "resource")?
        .map(|value| value.extract())
        .transpose()?;
      default_method = send_context_mapping_value(mapping, "method")?
        .map(|value| value.extract())
        .transpose()?;
      default_user_context_id = send_context_mapping_value(mapping, "user_context_id")?
        .map(|value| value.extract())
        .transpose()?;
      default_private_browsing_id = send_context_mapping_value(mapping, "private_browsing_id")?
        .map(|value| value.extract())
        .transpose()?;
      default_now = send_context_mapping_value(mapping, "now")?
        .map(|value| value.extract())
        .transpose()?;
    } else {
      return Err(request_error(
        "header() context must be a URL string or a mapping of SendContext fields",
      ));
    }
  }

  let url = url.or(default_url).ok_or_else(|| {
    request_error(
      "header() requires a url: pass it positionally, as context[\"url\"], or as url=...",
    )
  })?;
  let top_level_site = top_level_site.or(default_top_level_site);
  let resource = resource.or(default_resource);
  let method = method.or(default_method);
  let user_context_id = user_context_id.or(default_user_context_id);
  let private_browsing_id = private_browsing_id.or(default_private_browsing_id);
  let now = now.or(default_now);

  let mut send_context = rookie_core::SendContext::url(url);
  if let Some(top_level_site) = top_level_site {
    send_context = send_context.top_level_site(top_level_site);
  }
  if let Some(resource) = resource {
    send_context = send_context.resource(match resource.as_str() {
      "navigation" => rookie_core::ResourceKind::Navigation,
      "subresource" => rookie_core::ResourceKind::Subresource,
      other => {
        return Err(request_error(format!(
          "unknown header() resource {other:?}; expected \"navigation\" or \"subresource\""
        )))
      }
    });
  }
  if let Some(method) = method {
    send_context = send_context.method(match method.as_str() {
      "safe" => rookie_core::MethodClass::Safe,
      "unsafe" => rookie_core::MethodClass::Unsafe,
      other => {
        return Err(request_error(format!(
          "unknown header() method {other:?}; expected \"safe\" or \"unsafe\""
        )))
      }
    });
  }
  if let Some(user_context_id) = user_context_id {
    send_context = send_context.user_context_id(user_context_id);
  }
  if let Some(private_browsing_id) = private_browsing_id {
    send_context = send_context.private_browsing_id(private_browsing_id);
  }
  if let Some(now) = now {
    send_context = send_context.now(system_time_from_epoch_seconds(now)?);
  }
  Ok(send_context)
}

/// Converts epoch seconds (possibly negative, for a pre-1970 clock override)
/// into a `SystemTime`. `Duration` itself cannot go negative, so the sign is
/// handled by choosing `checked_add`/`checked_sub` around the epoch rather
/// than by the duration's own value.
fn system_time_from_epoch_seconds(seconds: f64) -> PyResult<std::time::SystemTime> {
  if !seconds.is_finite() {
    return Err(request_error(
      "header() now must be a finite number of epoch seconds",
    ));
  }
  let duration = std::time::Duration::try_from_secs_f64(seconds.abs())
    .map_err(|_| request_error("header() now is too large to represent"))?;
  let system_time = if seconds >= 0.0 {
    std::time::SystemTime::UNIX_EPOCH.checked_add(duration)
  } else {
    std::time::SystemTime::UNIX_EPOCH.checked_sub(duration)
  };
  system_time.ok_or_else(|| request_error("header() now is out of range"))
}

/// Read an unfiltered snapshot of one browser profile.
///
/// **Windows App-Bound (v20):** ``app_bound`` defaults to
/// ``"injection_only"``, which recovers a Chrome v20 profile without
/// elevation by spawning a browser process and injecting into it. Endpoint
/// security products can flag that, so pass ``"disabled"`` if it is
/// unwanted -- v20 rows are then skipped and reported as ``decrypt_failed``
/// warnings. ``"allow_elevated_fallback"`` additionally permits SYSTEM
/// impersonation and is never the default. See CHANGELOG.md.
///
/// **Migration trap:** ``include_session`` defaults to ``False``. In 0.6-beta,
/// naming a Gecko ``profile`` always imported its session cookies too;
/// naming one here does not, unless ``include_session=True`` is also passed.
/// This fails quietly -- a smaller snapshot, no error -- so code upgrading
/// from 0.6-beta that relied on session cookies riding along with a profile
/// selector needs this flag added explicitly. See CHANGELOG.md.
///
/// :param browser: Canonical browser ID or registered alias
/// :param profile: Optional profile id, display name, directory, or path
/// :param include_expired: Keep expired cookies (default false)
/// :param include_session: Also acquire the browser's declared session store
///     (Gecko only; a no-op for Chromium, which declares none). Default false.
/// :param select: Profile selection strategy. Only ``"legacy_first"`` (the
///     default) is valid here -- ``"all"`` has nowhere to put more than one
///     profile in a single snapshot; see ``browser_report`` for that.
/// :param timeout: Optional timeout in seconds
/// :param cancellation: Optional CancellationHandle
/// :param app_bound: Windows App-Bound (v20) recovery policy: "injection_only"
///     (default), "disabled", or "allow_elevated_fallback". A no-op
///     off Windows.
/// :return: A ReadResult snapshot (never URL-filtered)
/// :raises TypeError: ``browser`` was omitted
/// :raises RookieRequestError: Unknown browser, profile selector, or
///     ``app_bound`` value; or ``select`` was not ``"legacy_first"``
///     (``conflicting_profile_selection``)
#[pyfunction]
#[pyo3(signature = (
  *,
  browser,
  profile=None,
  include_expired=false,
  include_session=false,
  select="legacy_first".to_string(),
  timeout=None,
  cancellation=None,
  app_bound="injection_only".to_string(),
))]
#[allow(clippy::too_many_arguments)]
pub fn read(
  py: Python<'_>,
  browser: String,
  profile: Option<String>,
  include_expired: bool,
  include_session: bool,
  select: String,
  timeout: Option<f64>,
  cancellation: Option<PyCancellationHandle>,
  app_bound: String,
) -> PyResult<PyReadResult> {
  let selection =
    rookie_core::ProfileSelection::from_binding_options(profile.as_deref(), Some(&select))
      .map_err(|_| crate::conflicting_profile_selection_error())?;
  let control = crate::execution_control(timeout, cancellation, &app_bound)?;
  let mut request = rookie_core::ReadRequest::browser(browser).selection(selection);
  if include_session {
    request = request.include_session();
  }
  request = request.include_expired(include_expired).execution(control);
  let result = py
    .detach(|| rookie_core::read(request))
    .map_err(crate::errors::classify_error)?;
  Ok(PyReadResult::from_core(result))
}

/// Read cookies from an explicit cookie database path.
///
/// **Windows App-Bound (v20):** ``app_bound`` defaults to ``"injection_only"`` -- see ``read``'s docstring
/// and CHANGELOG.md; the same default and the same values apply here.
///
/// By default the source is identified automatically (`FromPathRequest::new`'s
/// own default): a Mozilla/Safari/Internet Explorer store needs no credential,
/// and an encrypted Chromium row is `missing_chromium_credentials` rather than
/// a guess at which browser wrote it. At most one of `plaintext_only`,
/// `browser_id`, `local_state_path` may be given.
///
/// :param path: Path to a cookie database or cookies file
/// :param include_expired: Keep expired cookies (default false)
/// :param plaintext_only: Reject the whole request if any Chromium row is
///     encrypted, rather than guessing a credential for it
/// :param browser_id: Registry browser identity for an encrypted Chromium
///     database (Linux keyring / macOS Keychain). Unix only.
/// :param local_state_path: Path to a Chromium `Local State` file, for an
///     encrypted Chromium database. Windows only.
/// :param timeout: Optional timeout in seconds
/// :param cancellation: Optional CancellationHandle
/// :param app_bound: Windows App-Bound (v20) recovery policy: "injection_only"
///     (default), "disabled", or "allow_elevated_fallback". A no-op
///     off Windows.
/// :return: A ReadResult snapshot
/// :raises RookieRequestError: More than one of `plaintext_only`,
///     `browser_id`, `local_state_path` was given
///     (`conflicting_credential_selectors`), or a platform-incompatible
///     credential (`browser_id` on Windows, `local_state_path` on Unix)
#[pyfunction]
#[pyo3(signature = (
  path,
  *,
  include_expired=false,
  plaintext_only=false,
  browser_id=None,
  local_state_path=None,
  timeout=None,
  cancellation=None,
  app_bound="injection_only".to_string(),
))]
#[allow(clippy::too_many_arguments)]
pub fn from_path(
  py: Python<'_>,
  path: String,
  include_expired: bool,
  plaintext_only: bool,
  browser_id: Option<String>,
  local_state_path: Option<String>,
  timeout: Option<f64>,
  cancellation: Option<PyCancellationHandle>,
  app_bound: String,
) -> PyResult<PyReadResult> {
  // Same mutual-exclusivity contract `chromium_cookies_from_path`'s options
  // dict already enforces, upgraded here to the typed
  // `conflicting_credential_selectors` code instead of an untyped message.
  let credentials = rookie_core::direct_path::ChromiumCredentialSource::from_selectors(
    browser_id,
    local_state_path.map(Into::into),
    plaintext_only,
  )
  .map_err(|_| crate::conflicting_credential_selectors_error())?;
  let control = crate::execution_control(timeout, cancellation, &app_bound)?;
  let mut request = rookie_core::FromPathRequest::new(path).include_expired(include_expired);
  if let Some(credentials) = credentials {
    request = request.chromium_credentials(credentials);
  }
  request = request.execution(control);
  let result = py
    .detach(|| rookie_core::from_path(request))
    .map_err(crate::errors::classify_error)?;
  Ok(PyReadResult::from_core(result))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::errors::RookieRequestError;
  use pyo3::types::PyDict;

  #[test]
  fn build_send_context_treats_a_bare_string_as_the_url() {
    Python::initialize();
    Python::attach(|py| {
      let context = build_send_context(
        Some("https://example.com/".into_pyobject(py).unwrap().into_any()),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
      )
      .expect("a bare string is a valid context");
      // `SendContext`'s fields are `pub(crate)` in the core, so this compares
      // by equality against one built through the public API rather than
      // introspecting fields this crate cannot see.
      assert_eq!(
        context,
        rookie_core::SendContext::url("https://example.com/")
      );
    });
  }

  #[test]
  fn build_send_context_merges_a_mapping_with_explicit_kwargs_winning() {
    Python::initialize();
    Python::attach(|py| {
      let mapping = PyDict::new(py);
      mapping.set_item("url", "https://example.com/").unwrap();
      mapping
        .set_item("top_level_site", "https://from-mapping.example/")
        .unwrap();
      let context = build_send_context(
        Some(mapping.into_any()),
        None,
        // Explicit kwarg overrides the mapping's same-named entry.
        Some("https://from-kwarg.example/".to_owned()),
        Some("navigation".to_owned()),
        Some("unsafe".to_owned()),
        Some(2),
        Some(1),
        None,
      )
      .expect("mapping plus overriding kwargs must merge");
      let expected = rookie_core::SendContext::url("https://example.com/")
        .top_level_site("https://from-kwarg.example/")
        .navigation()
        .method(rookie_core::MethodClass::Unsafe)
        .user_context_id(2)
        .private_browsing_id(1);
      assert_eq!(context, expected);
    });
  }

  #[test]
  fn build_send_context_requires_a_url_from_somewhere() {
    Python::initialize();
    Python::attach(|py| {
      let error = build_send_context(None, None, None, None, None, None, None, None).unwrap_err();
      assert!(error.is_instance_of::<RookieRequestError>(py));
    });
  }

  #[test]
  fn build_send_context_rejects_an_unknown_mapping_key() {
    Python::initialize();
    Python::attach(|py| {
      let mapping = PyDict::new(py);
      mapping.set_item("url", "https://example.com/").unwrap();
      mapping.set_item("bogus", "value").unwrap();
      let error = build_send_context(
        Some(mapping.into_any()),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
      )
      .unwrap_err();
      assert!(error.is_instance_of::<RookieRequestError>(py));
    });
  }

  #[test]
  fn build_send_context_rejects_an_unknown_resource_or_method_string() {
    Python::initialize();
    Python::attach(|py| {
      let error = build_send_context(
        None,
        Some("https://example.com/".to_owned()),
        None,
        Some("sideways".to_owned()),
        None,
        None,
        None,
        None,
      )
      .unwrap_err();
      assert!(error.is_instance_of::<RookieRequestError>(py));

      let error = build_send_context(
        None,
        Some("https://example.com/".to_owned()),
        None,
        None,
        Some("maybe".to_owned()),
        None,
        None,
        None,
      )
      .unwrap_err();
      assert!(error.is_instance_of::<RookieRequestError>(py));
    });
  }

  #[test]
  fn system_time_from_epoch_seconds_supports_before_and_after_the_epoch() {
    let after = system_time_from_epoch_seconds(1_000.0).expect("positive seconds");
    assert_eq!(
      after,
      std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000)
    );
    let before = system_time_from_epoch_seconds(-1_000.0).expect("negative seconds");
    assert_eq!(
      before,
      std::time::SystemTime::UNIX_EPOCH - std::time::Duration::from_secs(1_000)
    );
    assert!(system_time_from_epoch_seconds(f64::NAN).is_err());
    assert!(system_time_from_epoch_seconds(f64::INFINITY).is_err());
  }

  #[test]
  fn read_rejects_any_select_value_other_than_legacy_first_before_any_io() {
    Python::initialize();
    Python::attach(|py| {
      // The browser id below is deliberately nonexistent: `select` validation
      // must run before browser resolution, so this must fail on `select`,
      // never on the browser id.
      let error = read(
        py,
        "not-a-real-browser".to_owned(),
        None,
        false,
        false,
        "all".to_owned(),
        None,
        None,
        "disabled".to_owned(),
      )
      .err()
      .expect("select=\"all\" must be rejected before browser resolution runs");
      assert!(error.is_instance_of::<RookieRequestError>(py));
      let value = error.value(py);
      assert_eq!(
        value.getattr("code").unwrap().extract::<String>().unwrap(),
        "conflicting_profile_selection"
      );
    });
  }

  #[test]
  fn from_path_rejects_more_than_one_credential_selector_before_any_io() {
    Python::initialize();
    Python::attach(|py| {
      // A nonexistent path is deliberate: the mutual-exclusivity check must
      // run before source inspection, so this must fail on the conflict,
      // never on the missing file.
      let error = from_path(
        py,
        "/nonexistent/Cookies".to_owned(),
        false,
        true,
        Some("chrome".to_owned()),
        None,
        None,
        None,
        "disabled".to_owned(),
      )
      .err()
      .expect("plaintext_only + browser_id must be rejected before I/O");
      assert!(error.is_instance_of::<RookieRequestError>(py));
      let value = error.value(py);
      assert_eq!(
        value.getattr("code").unwrap().extract::<String>().unwrap(),
        "conflicting_credential_selectors"
      );
    });
  }
}
