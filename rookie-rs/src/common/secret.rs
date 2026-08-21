use std::{fmt, ops::Deref};
use zeroize::Zeroize;
#[cfg(windows)]
use zeroize::Zeroizing;

/// Request-scoped plaintext bytes.
///
/// Constructors live at native and IPC extraction boundaries so every early
/// return wipes the owned allocation. Successful decoding may transfer the
/// allocation into the caller-visible cookie `String`; that allocation is the
/// result, not a discarded request frame.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SecretBytes {
  bytes: Option<Vec<u8>>,
}

impl SecretBytes {
  pub(crate) fn new(bytes: Vec<u8>) -> Self {
    Self { bytes: Some(bytes) }
  }

  #[cfg(all(windows, feature = "appbound"))]
  pub(crate) fn zeroed(len: usize) -> Self {
    Self::new(vec![0; len])
  }

  pub(crate) fn as_slice(&self) -> &[u8] {
    self.bytes.as_deref().unwrap_or_default()
  }

  pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
    self.bytes.as_deref_mut().unwrap_or_default()
  }

  pub(crate) fn len(&self) -> usize {
    self.as_slice().len()
  }

  pub(crate) fn extend_bounded(&mut self, bytes: &[u8], maximum: usize) {
    let Some(value) = self.bytes.as_mut() else {
      return;
    };
    let available = maximum.saturating_sub(value.len());
    value.extend_from_slice(&bytes[..bytes.len().min(available)]);
  }

  pub(crate) fn truncate(&mut self, len: usize) {
    if let Some(bytes) = self.bytes.as_mut() {
      if let Some(discarded) = bytes.get_mut(len..) {
        discarded.zeroize();
      }
      bytes.truncate(len);
    }
  }

  /// Converts an entire secret frame to a protected string. Invalid UTF-8
  /// keeps ownership in `self`, so the error path wipes the original bytes.
  #[cfg(any(target_os = "linux", target_os = "macos", test))]
  pub(crate) fn into_secret_string(mut self) -> Result<SecretString, SecretUtf8Error> {
    if std::str::from_utf8(self.as_slice()).is_err() {
      return Err(SecretUtf8Error);
    }
    let bytes = self.bytes.take().expect("secret bytes are present");
    // SAFETY: validation immediately above covered this exact byte vector.
    let value = unsafe { String::from_utf8_unchecked(bytes) };
    Ok(SecretString::new(value))
  }

  /// Converts a suffix to the caller-visible result string without leaving a
  /// second plaintext allocation behind. Bytes outside the suffix are wiped
  /// before the allocation is transferred.
  #[cfg(test)]
  pub(crate) fn into_output_string_from(self, start: usize) -> Result<String, SecretUtf8Error> {
    self
      .prepare_utf8_suffix(start)
      .map(SecretString::into_output_string)
  }

  /// Converts a suffix to protected text while retaining wipe-on-discard
  /// ownership until public cookie projection succeeds.
  pub(crate) fn into_secret_string_from(
    self,
    start: usize,
  ) -> Result<SecretString, SecretUtf8Error> {
    self.prepare_utf8_suffix(start)
  }

  fn prepare_utf8_suffix(mut self, start: usize) -> Result<SecretString, SecretUtf8Error> {
    let bytes = self.as_slice();
    let suffix = bytes.get(start..).ok_or(SecretUtf8Error)?;
    if std::str::from_utf8(suffix).is_err() {
      return Err(SecretUtf8Error);
    }

    let mut bytes = self.bytes.take().expect("secret bytes are present");
    if start > 0 {
      let suffix_len = bytes.len() - start;
      bytes.copy_within(start.., 0);
      bytes[suffix_len..].zeroize();
      bytes.truncate(suffix_len);
    }
    // SAFETY: the retained suffix was validated before the in-place move.
    Ok(SecretString::new(unsafe {
      String::from_utf8_unchecked(bytes)
    }))
  }

  #[cfg(windows)]
  pub(crate) fn into_zeroizing_vec(mut self) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(self.bytes.take().expect("secret bytes are present"))
  }
}

impl Deref for SecretBytes {
  type Target = [u8];

  fn deref(&self) -> &Self::Target {
    self.as_slice()
  }
}

impl fmt::Debug for SecretBytes {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("SecretBytes")
      .field("length", &self.len())
      .finish()
  }
}

impl Drop for SecretBytes {
  fn drop(&mut self) {
    if let Some(bytes) = self.bytes.as_mut() {
      #[cfg(test)]
      let original_len = bytes.len();
      bytes.as_mut_slice().zeroize();
      #[cfg(test)]
      record_drop(SecretKind::Bytes, original_len, bytes.as_slice());
      bytes.clear();
    }
  }
}

/// Request-scoped plaintext text returned by a credential provider.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SecretString {
  value: Option<String>,
}

impl SecretString {
  pub(crate) fn new(value: String) -> Self {
    Self { value: Some(value) }
  }

  pub(crate) fn as_str(&self) -> &str {
    self.value.as_deref().unwrap_or_default()
  }

  #[cfg(target_os = "macos")]
  pub(crate) fn trimmed(&self) -> Self {
    Self::new(self.as_str().trim().to_owned())
  }

  /// Transfers the protected allocation into an explicitly requested public
  /// cookie result. Discarded records keep ownership here and are wiped by
  /// `Drop` instead.
  pub(crate) fn into_output_string(mut self) -> String {
    self.value.take().expect("secret string is present")
  }
}

impl Deref for SecretString {
  type Target = str;

  fn deref(&self) -> &Self::Target {
    self.as_str()
  }
}

impl fmt::Debug for SecretString {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("SecretString")
      .field("length", &self.as_str().len())
      .finish()
  }
}

impl Drop for SecretString {
  fn drop(&mut self) {
    if let Some(value) = self.value.as_mut() {
      #[cfg(test)]
      let original_len = value.len();
      // SAFETY: replacing every byte with zero preserves UTF-8 validity, and
      // the vector is cleared before this method returns.
      let bytes = unsafe { value.as_mut_vec() };
      bytes.as_mut_slice().zeroize();
      #[cfg(test)]
      record_drop(SecretKind::String, original_len, bytes.as_slice());
      bytes.clear();
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SecretUtf8Error;

impl fmt::Display for SecretUtf8Error {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("secret is not valid UTF-8")
  }
}

impl std::error::Error for SecretUtf8Error {}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretKind {
  Bytes,
  String,
}

#[cfg(test)]
pub(crate) type DropObservation = (SecretKind, usize, Vec<u8>);

#[cfg(test)]
thread_local! {
  static DROP_OBSERVATIONS: std::cell::RefCell<Option<Vec<DropObservation>>> = const {
    std::cell::RefCell::new(None)
  };
}

#[cfg(test)]
fn record_drop(kind: SecretKind, original_len: usize, wiped: &[u8]) {
  DROP_OBSERVATIONS.with(|observations| {
    if let Some(observations) = observations.borrow_mut().as_mut() {
      observations.push((kind, original_len, wiped.to_vec()));
    }
  });
}

#[cfg(test)]
pub(crate) fn observe_secret_drops(
  test: impl FnOnce(),
) -> (Vec<DropObservation>, std::thread::Result<()>) {
  DROP_OBSERVATIONS.with(|observations| {
    assert!(observations.borrow().is_none());
    *observations.borrow_mut() = Some(Vec::new());
  });
  let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
  let observed = DROP_OBSERVATIONS.with(|observations| {
    observations
      .borrow_mut()
      .take()
      .expect("drop observations enabled")
  });
  (observed, outcome)
}

#[cfg(test)]
pub(crate) fn observe_secret_string_drops(
  test: impl FnOnce(),
) -> (Vec<(usize, Vec<u8>)>, std::thread::Result<()>) {
  let (observed, outcome) = observe_secret_drops(test);
  (
    observed
      .into_iter()
      .filter_map(|(kind, len, wiped)| (kind == SecretKind::String).then_some((len, wiped)))
      .collect(),
    outcome,
  )
}

#[cfg(test)]
mod tests {
  use super::*;

  const SENTINEL: &str = "rookie-secret-sentinel-7e8b";

  fn observe_drops(test: impl FnOnce()) -> (Vec<DropObservation>, std::thread::Result<()>) {
    DROP_OBSERVATIONS.with(|observations| {
      assert!(observations.borrow().is_none());
      *observations.borrow_mut() = Some(Vec::new());
    });
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
    let observed = DROP_OBSERVATIONS.with(|observations| {
      observations
        .borrow_mut()
        .take()
        .expect("drop observations enabled")
    });
    (observed, outcome)
  }

  #[test]
  fn secret_frames_wipe_sentinel_allocations_on_success_and_failure_cleanup() {
    let (observed, outcome) = observe_drops(|| {
      let password = SecretString::new(SENTINEL.to_owned());
      let password_clone = password.clone();
      drop(password);
      drop(password_clone);

      let invalid = SecretBytes::new([SENTINEL.as_bytes(), &[0xff]].concat());
      invalid
        .into_secret_string()
        .expect_err("invalid UTF-8 must retain and wipe the source frame");
    });

    assert!(outcome.is_ok());
    assert_eq!(observed.len(), 3);
    assert!(observed.iter().all(|(_, original_len, wiped)| {
      *original_len >= SENTINEL.len()
        && wiped.len() == *original_len
        && wiped.iter().all(|byte| *byte == 0)
    }));
  }

  #[test]
  fn panic_unwind_wipes_the_full_secret_allocation_before_deallocation() {
    let (observed, outcome) = observe_drops(|| {
      let _secret = SecretBytes::new(SENTINEL.as_bytes().to_vec());
      panic!("intentional unwind after allocating a secret frame");
    });

    assert!(outcome.is_err());
    assert_eq!(observed.len(), 1);
    let (kind, original_len, wiped) = &observed[0];
    assert_eq!(*kind, SecretKind::Bytes);
    assert_eq!(*original_len, SENTINEL.len());
    assert_eq!(wiped.len(), *original_len);
    assert!(wiped.iter().all(|byte| *byte == 0));
  }

  #[test]
  fn secret_debug_and_utf8_errors_never_expose_the_sentinel() {
    let bytes = SecretBytes::new(SENTINEL.as_bytes().to_vec());
    let text = SecretString::new(SENTINEL.to_owned());
    assert!(!format!("{bytes:?}").contains(SENTINEL));
    assert!(!format!("{text:?}").contains(SENTINEL));

    let error = SecretBytes::new([SENTINEL.as_bytes(), &[0xff]].concat())
      .into_secret_string()
      .expect_err("fixture is invalid UTF-8");
    assert!(!format!("{error:?}").contains(SENTINEL));
    assert!(!error.to_string().contains(SENTINEL));
  }

  #[test]
  fn mutable_secret_frame_operations_preserve_only_the_retained_bytes() {
    let mut value = SecretBytes::new(b"rookie-discarded".to_vec());
    value.as_mut_slice()[0] = b'R';
    value.truncate(6);
    assert_eq!(value.as_slice(), b"Rookie");
  }

  #[test]
  fn output_conversion_reuses_the_secret_frame_and_wipes_removed_prefix() {
    let value = SecretBytes::new(b"prefixcookie-value".to_vec())
      .into_output_string_from(6)
      .expect("valid suffix");
    assert_eq!(value, "cookie-value");
  }

  #[test]
  fn panic_output_never_formats_a_live_secret() {
    const CHILD_ENV: &str = "ROOKIE_SECRET_PANIC_CHILD";
    if std::env::var_os(CHILD_ENV).is_some() {
      let _secret = SecretString::new(SENTINEL.to_owned());
      panic!("intentional secret-cleanup panic");
    }

    let output = std::process::Command::new(std::env::current_exe().expect("current test binary"))
      .args([
        "--exact",
        "common::secret::tests::panic_output_never_formats_a_live_secret",
        "--nocapture",
      ])
      .env(CHILD_ENV, "1")
      .output()
      .expect("run panic-output child");
    assert!(
      !output.status.success(),
      "child must exercise the panic path"
    );
    let mut diagnostics = output.stdout;
    diagnostics.extend(output.stderr);
    let diagnostics = String::from_utf8_lossy(&diagnostics);
    assert!(!diagnostics.contains(SENTINEL), "{diagnostics}");
  }
}
