use crate::common::{date, enums::*, sqlite, utils};
use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::PathBuf;

use super::chromium_crypto::{
  detect_cipher_version, retrieve_key_outcomes, ChromiumCipherVersion, ChromiumKeyOutcomes,
  ChromiumKeyProvider, ChromiumKeyRoute,
};
#[cfg(target_os = "linux")]
use super::chromium_platform_keys::LinuxPlatformKeyProvider;
#[cfg(target_os = "macos")]
use super::chromium_platform_keys::MacosPlatformKeyProvider;
#[cfg(target_os = "windows")]
use super::chromium_platform_keys::WindowsPlatformKeyProvider;
#[allow(unused)]
use crate::config::Browser;

#[cfg(target_os = "windows")]
use crate::windows;

#[cfg(target_os = "windows")]
use aes_gcm::{
  aead::{generic_array::GenericArray, Aead, KeyInit},
  Aes256Gcm,
};

/// Returns cookies from chromium based browser
#[cfg(target_os = "windows")]
pub fn chromium_based(
  key: PathBuf,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<Cookie>> {
  let content = std::fs::read_to_string(key)?;
  let key_dict: serde_json::Value =
    serde_json::from_str(content.as_str()).context("Can't read json file")?;
  let provider = WindowsPlatformKeyProvider::new(&key_dict);
  query_cookies(&provider, &(), db_path, domains, force_kill)
}

/// Returns Chromium cookies with partition and source context preserved.
#[cfg(target_os = "windows")]
pub fn chromium_based_detailed(
  key: PathBuf,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<DetailedCookie>> {
  let content = std::fs::read_to_string(key)?;
  let key_dict: serde_json::Value =
    serde_json::from_str(content.as_str()).context("Can't read json file")?;
  let provider = WindowsPlatformKeyProvider::new(&key_dict);
  query_detailed_cookies(&provider, &(), db_path, domains, force_kill)
}

/// Extracts only plaintext rows without selecting or probing a key provider.
/// Encountering an encrypted row fails the request instead of degrading into
/// a partial result under an assumed browser identity.
#[cfg(unix)]
pub(crate) fn chromium_based_plaintext_only(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<Cookie>> {
  query_cookies_engine_outcome_mode(
    &ChromiumKeyOutcomes::default(),
    db_path,
    domains,
    force_kill,
    CookieProjection::Legacy,
    EncryptedValuePolicy::RejectMissingIdentity,
  )?
  .into_legacy_result()
}

/// Detailed counterpart to [`chromium_based_plaintext_only`].
#[cfg(unix)]
pub(crate) fn chromium_based_detailed_plaintext_only(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<DetailedCookie>> {
  query_cookies_engine_outcome_mode(
    &ChromiumKeyOutcomes::default(),
    db_path,
    domains,
    force_kill,
    CookieProjection::Detailed,
    EncryptedValuePolicy::RejectMissingIdentity,
  )?
  .into_detailed_result()
}

/// Returns cookies from chromium based browser
#[cfg(unix)]
pub fn chromium_based(
  config: &Browser,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<Cookie>> {
  #[cfg(target_os = "linux")]
  {
    let provider = LinuxPlatformKeyProvider::new(config);
    query_cookies(&provider, &(), db_path, domains, force_kill)
  }

  #[cfg(target_os = "macos")]
  {
    let provider = MacosPlatformKeyProvider::new(config);
    query_cookies(&provider, &(), db_path, domains, force_kill)
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos")))]
  {
    let _ = (config, db_path, domains, force_kill);
    anyhow::bail!("Chromium cookie extraction is unsupported on this Unix platform")
  }
}

/// Returns Chromium cookies with partition and source context preserved.
#[cfg(unix)]
pub fn chromium_based_detailed(
  config: &Browser,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<DetailedCookie>> {
  #[cfg(target_os = "linux")]
  {
    let provider = LinuxPlatformKeyProvider::new(config);
    query_detailed_cookies(&provider, &(), db_path, domains, force_kill)
  }

  #[cfg(target_os = "macos")]
  {
    let provider = MacosPlatformKeyProvider::new(config);
    query_detailed_cookies(&provider, &(), db_path, domains, force_kill)
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos")))]
  {
    let _ = (config, db_path, domains, force_kill);
    anyhow::bail!("Chromium cookie extraction is unsupported on this Unix platform")
  }
}

/// Runs a Chromium probe using key outcomes already retrieved by the host key
/// session. Failures remain typed outcomes, so probing cannot turn a provider
/// error into an empty candidate list.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn chromium_based_probe_with_key_outcomes(
  outcomes: ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<ChromiumProbeResult> {
  query_cookies_probe_with_key_outcomes(outcomes, db_path, domains, force_kill)
}

const CHROMIUM_HOST_HASH_LEN: usize = 32;
const CHROMIUM_HOST_HASH_SCHEMA_VERSION: u32 = 24;
/// Row-issue samples are collected against the report contract's bound rather
/// than a separate number. Collecting fewer than the report retains silently
/// caps what a consumer can ever see below the documented limit; collecting
/// more only to have the report truncate them is wasted work.
const MAX_CHROMIUM_ROW_ISSUE_SAMPLES: usize = crate::browser::report_core::MAX_ISSUE_SAMPLES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChromiumCookieDecodeError {
  InvalidUtf8AfterVerifiedHostHash,
  MissingRequiredHostHash,
  HostHashMismatch,
  HostHashMismatchWithInvalidUtf8,
  UnprefixedInvalidUtf8,
}

impl fmt::Display for ChromiumCookieDecodeError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::InvalidUtf8AfterVerifiedHostHash => {
        formatter.write_str("Chromium cookie value after verified host hash is not valid UTF-8")
      }
      Self::MissingRequiredHostHash => {
        formatter.write_str("Chromium cookie plaintext is missing the required v24+ host hash")
      }
      Self::HostHashMismatch => {
        formatter.write_str("Chromium cookie plaintext has a mismatched v24+ host hash")
      }
      Self::HostHashMismatchWithInvalidUtf8 => formatter
        .write_str("Chromium cookie plaintext has a mismatched host hash and is not valid UTF-8"),
      Self::UnprefixedInvalidUtf8 => {
        formatter.write_str("Chromium cookie plaintext is not valid UTF-8")
      }
    }
  }
}

impl std::error::Error for ChromiumCookieDecodeError {}

/// Decodes decrypted Chromium bytes without assuming that any 32-byte prefix
/// is a host binding. Newer Chromium schemas prefix the value with the exact
/// SHA-256 of the stored `host_key`; older schemas store the UTF-8 value
/// directly, including values longer than 32 bytes.
fn decode_chromium_cookie_value(
  host_key: &str,
  plaintext: Vec<u8>,
  schema_version: u32,
) -> std::result::Result<String, ChromiumCookieDecodeError> {
  let host_hash_required = schema_version >= CHROMIUM_HOST_HASH_SCHEMA_VERSION;
  if host_hash_required && plaintext.len() < CHROMIUM_HOST_HASH_LEN {
    return Err(ChromiumCookieDecodeError::MissingRequiredHostHash);
  }

  if plaintext.len() >= CHROMIUM_HOST_HASH_LEN {
    let expected_host_hash = Sha256::digest(host_key.as_bytes());
    if plaintext[..CHROMIUM_HOST_HASH_LEN] == expected_host_hash[..] {
      return String::from_utf8(plaintext[CHROMIUM_HOST_HASH_LEN..].to_vec())
        .map_err(|_| ChromiumCookieDecodeError::InvalidUtf8AfterVerifiedHostHash);
    }

    if host_hash_required {
      return Err(ChromiumCookieDecodeError::HostHashMismatch);
    }

    return String::from_utf8(plaintext)
      .map_err(|_| ChromiumCookieDecodeError::HostHashMismatchWithInvalidUtf8);
  }

  String::from_utf8(plaintext).map_err(|_| ChromiumCookieDecodeError::UnprefixedInvalidUtf8)
}

fn chromium_schema_version(connection: &rusqlite::Connection) -> Result<u32> {
  let version: String = connection
    .query_row(
      "SELECT CAST(value AS TEXT) FROM meta WHERE key = 'version'",
      [],
      |row| row.get(0),
    )
    .context("Can't read Chromium cookie database schema version from meta.version")?;
  version
    .parse()
    .with_context(|| format!("Invalid Chromium cookie database schema version {version:?}"))
}

#[derive(Debug)]
enum ChromiumCookieValueError {
  Decrypt(anyhow::Error),
  Decode(ChromiumCookieDecodeError),
  ProviderUnavailable(anyhow::Error),
  ProviderFailed(anyhow::Error),
}

impl ChromiumCookieValueError {
  fn row_issue_code(&self) -> ChromiumRowIssueCode {
    match self {
      Self::Decrypt(_) => ChromiumRowIssueCode::Decrypt,
      Self::Decode(_) => ChromiumRowIssueCode::Decode,
      Self::ProviderUnavailable(_) => ChromiumRowIssueCode::ProviderUnavailable,
      Self::ProviderFailed(_) => ChromiumRowIssueCode::ProviderFailed,
    }
  }
}

impl fmt::Display for ChromiumCookieValueError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Decrypt(error) | Self::ProviderUnavailable(error) | Self::ProviderFailed(error) => {
        error.fmt(formatter)
      }
      Self::Decode(error) => error.fmt(formatter),
    }
  }
}

impl From<anyhow::Error> for ChromiumCookieValueError {
  fn from(error: anyhow::Error) -> Self {
    Self::Decrypt(error)
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChromiumRowIssueCode {
  ColumnRead(&'static str),
  Decrypt,
  Decode,
  /// The row's cipher tier has no provider compiled or enabled in this build.
  ProviderUnavailable,
  /// A compiled provider was applicable but its key retrieval failed.
  ProviderFailed,
}

#[derive(Debug)]
struct ChromiumContextColumnError {
  column: &'static str,
  source: rusqlite::Error,
}

impl fmt::Display for ChromiumContextColumnError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      formatter,
      "failed to read {} from Chromium cookie row: {}",
      self.column, self.source
    )
  }
}

impl std::error::Error for ChromiumContextColumnError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.source)
  }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ChromiumRowIssue {
  pub(crate) code: ChromiumRowIssueCode,
  pub(crate) occurrences: usize,
  pub(crate) samples: Vec<String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ChromiumExtractionStats {
  pub(crate) rows_seen: usize,
  pub(crate) cookies_emitted: usize,
  pub(crate) rows_skipped: usize,
}

/// A successful Chromium configuration probe and its completeness signal.
///
/// `any_browser` compares all applicable identities instead of returning the
/// first configuration that happens to decrypt one fallback-key row.
#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct ChromiumProbeResult {
  pub(crate) cookies: Vec<Cookie>,
  pub(crate) rows_skipped: usize,
}

#[derive(Debug, Default)]
pub(crate) struct ChromiumEngineExtractionOutcome {
  pub(crate) cookies: Vec<Cookie>,
  detailed_cookies: Vec<DetailedCookie>,
  pub(crate) stats: ChromiumExtractionStats,
  pub(crate) issues: Vec<ChromiumRowIssue>,
  pub(crate) acquisition_strategy: Option<sqlite::DatabaseAcquisitionStrategy>,
  pub(crate) acquisition_attempts: u32,
  pub(crate) legacy_error: Option<anyhow::Error>,
}

impl ChromiumEngineExtractionOutcome {
  fn record_row_issue(&mut self, code: ChromiumRowIssueCode, row_number: usize) {
    let issue = match self.issues.iter_mut().find(|issue| issue.code == code) {
      Some(issue) => issue,
      None => {
        self.issues.push(ChromiumRowIssue {
          code,
          occurrences: 0,
          samples: Vec::new(),
        });
        self.issues.last_mut().expect("issue was just inserted")
      }
    };
    issue.occurrences += 1;
    if issue.samples.len() < MAX_CHROMIUM_ROW_ISSUE_SAMPLES {
      issue.samples.push(format!("row {row_number}"));
    }
  }

  fn record_skipped_row(&mut self, code: ChromiumRowIssueCode, row_number: usize) {
    self.stats.rows_skipped += 1;
    self.record_row_issue(code, row_number);
  }

  fn total_row_failure(&self, error: anyhow::Error) -> anyhow::Error {
    let issues = self
      .issues
      .iter()
      .map(|issue| {
        format!(
          "{:?}: {} occurrence(s), samples [{}]",
          issue.code,
          issue.occurrences,
          issue.samples.join(", ")
        )
      })
      .collect::<Vec<_>>()
      .join("; ");
    error.context(format!(
      "all {} Chromium cookie row(s) were skipped; row issues: {issues}",
      self.stats.rows_seen
    ))
  }

  pub(crate) fn into_legacy_result(self) -> Result<Vec<Cookie>> {
    match self.legacy_error {
      Some(error) => Err(error),
      None => Ok(self.cookies),
    }
  }

  fn into_detailed_result(self) -> Result<Vec<DetailedCookie>> {
    match self.legacy_error {
      Some(error) => Err(error),
      None => Ok(self.detailed_cookies),
    }
  }

  #[cfg(unix)]
  fn into_probe_result(self) -> Result<ChromiumProbeResult> {
    match self.legacy_error {
      Some(error) => Err(error),
      None => Ok(ChromiumProbeResult {
        cookies: self.cookies,
        rows_skipped: self.stats.rows_skipped,
      }),
    }
  }
}

fn chromium_cookie_context(
  row: &rusqlite::Row<'_>,
) -> std::result::Result<CookieContext, ChromiumContextColumnError> {
  let read = |column, source| ChromiumContextColumnError { column, source };
  Ok(CookieContext {
    top_frame_site_key: row
      .get::<_, Option<String>>(9)
      .map_err(|error| read("top_frame_site_key", error))?,
    has_cross_site_ancestor: row
      .get::<_, Option<i64>>(10)
      .map_err(|error| read("has_cross_site_ancestor", error))?
      .map(|value| value != 0),
    source_scheme: row
      .get::<_, Option<i64>>(11)
      .map_err(|error| read("source_scheme", error))?,
    source_port: row
      .get::<_, Option<i64>>(12)
      .map_err(|error| read("source_port", error))?,
    is_persistent: row
      .get::<_, Option<i64>>(13)
      .map_err(|error| read("is_persistent", error))?
      .map(|value| value != 0),
    ..CookieContext::default()
  })
}

/// Decrypt cookie value using aes GCM
#[cfg(all(windows, test))]
fn decrypt_encrypted_value(
  host_key: &str,
  value: String,
  encrypted_value: &[u8],
  keys: &[Vec<u8>],
  schema_version: u32,
) -> std::result::Result<String, ChromiumCookieValueError> {
  let outcomes = ChromiumKeyOutcomes::from_legacy_shared(keys.to_vec());
  decrypt_encrypted_value_with_outcomes(host_key, value, encrypted_value, &outcomes, schema_version)
}

#[cfg(windows)]
fn decrypt_windows_gcm_candidate(nonce: &[u8], ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
  let cipher = Aes256Gcm::new_from_slice(key)
    .map_err(|_| anyhow!("Chromium AES-GCM candidate key has an invalid length"))?;
  let nonce = GenericArray::from_slice(nonce);
  cipher
    .decrypt(nonce, ciphertext)
    .map_err(|_| anyhow!("Chromium AES-GCM authentication failed"))
}

#[cfg(windows)]
fn decrypt_encrypted_value_with_outcomes(
  host_key: &str,
  value: String,
  encrypted_value: &[u8],
  outcomes: &ChromiumKeyOutcomes,
  schema_version: u32,
) -> std::result::Result<String, ChromiumCookieValueError> {
  if !value.is_empty() {
    return Ok(value);
  }
  if encrypted_value.is_empty() {
    return Ok(value);
  }

  let cipher_version = detect_cipher_version(encrypted_value)
    .map_err(|error| ChromiumCookieValueError::Decrypt(anyhow!(error)))?;
  let (key_type, candidates) = match outcomes.route(cipher_version) {
    ChromiumKeyRoute::Candidates { tier, candidates } => {
      log::debug!("Chromium cipher tier: {tier}");
      let prefix = match cipher_version {
        ChromiumCipherVersion::V10 => b"v10",
        ChromiumCipherVersion::V11 => b"v11",
        ChromiumCipherVersion::V20 => b"v20",
        _ => unreachable!("candidate routes are only emitted for keyed tiers"),
      };
      (prefix.as_slice(), candidates)
    }
    ChromiumKeyRoute::NotApplicable { tier } => {
      return Err(ChromiumCookieValueError::ProviderUnavailable(anyhow!(
        "Chromium {tier} key provider is not applicable"
      )));
    }
    ChromiumKeyRoute::Failure { tier, failure } => {
      return Err(ChromiumCookieValueError::ProviderFailed(anyhow!(
        "Chromium {tier} key provider failed: {}",
        failure.message()
      )));
    }
    ChromiumKeyRoute::LegacyDpapi => {
      let plaintext = crate::windows::dpapi::decrypt(encrypted_value)
        .context("Failed to decrypt legacy Chromium DPAPI cookie")
        .map_err(ChromiumCookieValueError::Decrypt)?;
      return decode_chromium_cookie_value(host_key, plaintext, schema_version)
        .map_err(ChromiumCookieValueError::Decode);
    }
    ChromiumKeyRoute::V12SecretPortal => {
      return Err(ChromiumCookieValueError::ProviderUnavailable(anyhow!(
        "Chromium v12 SecretPortal encryption is recognized but unsupported"
      )));
    }
    ChromiumKeyRoute::Unknown(prefix) => {
      return Err(ChromiumCookieValueError::Decrypt(anyhow!(
        "Unknown Chromium cipher prefix: {prefix:?}"
      )));
    }
  };

  if encrypted_value.len() < 15 {
    return Err(ChromiumCookieValueError::Decrypt(anyhow!(
      "Chromium encrypted value is {} bytes, shorter than the version and nonce header",
      encrypted_value.len()
    )));
  }

  let nonce = &encrypted_value[3..15]; // iv
  let ciphertext = &encrypted_value[15..];
  let mut last_decode_error = None;

  for key in candidates {
    if key.as_bytes().len() != 32 {
      log::warn!(
        "Skipping {key_type:?} candidate key with invalid length {}",
        key.as_bytes().len()
      );
      continue;
    }

    match decrypt_windows_gcm_candidate(nonce, ciphertext, key.as_bytes()) {
      Ok(plaintext) => match decode_chromium_cookie_value(host_key, plaintext, schema_version) {
        Ok(text) => return Ok(text),
        Err(error) => {
          log::debug!("Failed to decode decrypted Chromium value: {error}");
          last_decode_error = Some(error);
        }
      },
      Err(error) => {
        log::debug!("Failed to decrypt with a key: {error}");
      }
    }
  }

  match last_decode_error {
    Some(error) => Err(ChromiumCookieValueError::Decode(error)),
    None => Err(ChromiumCookieValueError::Decrypt(anyhow!(
      "decrypt_encrypted_value failed"
    ))),
  }
}

/// Decrypt cookie value using aes cbc
#[cfg(all(unix, test))]
fn decrypt_encrypted_value(
  host_key: &str,
  value: String,
  encrypted_value: &[u8],
  keys: &[Vec<u8>],
  schema_version: u32,
) -> std::result::Result<String, ChromiumCookieValueError> {
  let outcomes = ChromiumKeyOutcomes::from_legacy_shared(keys.to_vec());
  decrypt_encrypted_value_with_outcomes(host_key, value, encrypted_value, &outcomes, schema_version)
}

#[cfg(unix)]
fn decrypt_unix_cbc_candidate(encrypted_value: &[u8], key: &[u8]) -> Result<Vec<u8>> {
  use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};

  type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

  let key_array: [u8; 16] = key
    .try_into()
    .map_err(|_| anyhow!("Chromium AES-CBC candidate key has an invalid length"))?;
  let iv: [u8; 16] = [b' '; 16];
  let cipher = Aes128CbcDec::new(&key_array.into(), &iv.into());
  let mut ciphertext = encrypted_value[3..].to_vec();
  cipher
    .decrypt_padded_mut::<Pkcs7>(&mut ciphertext)
    .map(|plaintext| plaintext.to_vec())
    .map_err(|_| anyhow!("Chromium AES-CBC padding validation failed"))
}

#[cfg(unix)]
fn decrypt_encrypted_value_with_outcomes(
  host_key: &str,
  value: String,
  encrypted_value: &[u8],
  outcomes: &ChromiumKeyOutcomes,
  schema_version: u32,
) -> std::result::Result<String, ChromiumCookieValueError> {
  if !value.is_empty() {
    return Ok(value);
  }
  if encrypted_value.is_empty() {
    return Ok("".into());
  }

  let cipher_version = detect_cipher_version(encrypted_value)
    .map_err(|error| ChromiumCookieValueError::Decrypt(anyhow!(error)))?;
  let (key_type, candidates) = match outcomes.route(cipher_version) {
    ChromiumKeyRoute::Candidates { tier, candidates } => {
      log::debug!("Chromium cipher tier: {tier}");
      let prefix = match cipher_version {
        ChromiumCipherVersion::V10 => b"v10",
        ChromiumCipherVersion::V11 => b"v11",
        ChromiumCipherVersion::V20 => b"v20",
        _ => unreachable!("candidate routes are only emitted for keyed tiers"),
      };
      (prefix.as_slice(), candidates)
    }
    ChromiumKeyRoute::NotApplicable { tier } => {
      return Err(ChromiumCookieValueError::ProviderUnavailable(anyhow!(
        "Chromium {tier} key provider is not applicable"
      )));
    }
    ChromiumKeyRoute::Failure { tier, failure } => {
      return Err(ChromiumCookieValueError::ProviderFailed(anyhow!(
        "Chromium {tier} key provider failed: {}",
        failure.message()
      )));
    }
    ChromiumKeyRoute::LegacyDpapi => {
      return Err(ChromiumCookieValueError::ProviderUnavailable(anyhow!(
        "Legacy Chromium DPAPI cookies are not decryptable on this platform"
      )));
    }
    ChromiumKeyRoute::V12SecretPortal => {
      return Err(ChromiumCookieValueError::ProviderUnavailable(anyhow!(
        "Chromium v12 SecretPortal encryption is recognized but unsupported"
      )));
    }
    ChromiumKeyRoute::Unknown(prefix) => {
      return Err(ChromiumCookieValueError::Decrypt(anyhow!(
        "Unknown Chromium cipher prefix: {prefix:?}"
      )));
    }
  };
  let mut last_decode_error = None;

  for key in candidates {
    if key.as_bytes().len() != 16 {
      log::warn!(
        "Skipping {key_type:?} candidate key with invalid length {}",
        key.as_bytes().len()
      );
      continue;
    }

    match decrypt_unix_cbc_candidate(encrypted_value, key.as_bytes()) {
      Ok(plaintext) => match decode_chromium_cookie_value(host_key, plaintext, schema_version) {
        Ok(decoded) => return Ok(decoded),
        Err(error) => {
          // A wrong key can occasionally pass PKCS#7 validation. Do not accept
          // its bytes as a cookie value; another key may decrypt valid UTF-8.
          log::debug!("Failed to decode decrypted Chromium value: {error}");
          last_decode_error = Some(error);
        }
      },
      Err(error) => log::debug!("Failed to decrypt with a key: {error}"),
    }
  }

  match last_decode_error {
    Some(error) => Err(ChromiumCookieValueError::Decode(error)),
    None => Err(ChromiumCookieValueError::Decrypt(anyhow!(
      "decrypt_encrypted_value failed"
    ))),
  }
}

#[cfg(any(target_os = "windows", test))]
const ERROR_SHARING_VIOLATION_CODE: i32 = 32;
#[cfg(any(target_os = "windows", test))]
const ERROR_LOCK_VIOLATION_CODE: i32 = 33;

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsLockedDatabasePolicy {
  NonDisruptive,
  AllowProcessShutdown,
}

#[cfg(any(target_os = "windows", test))]
impl WindowsLockedDatabasePolicy {
  fn from_force_kill(force_kill: bool) -> Self {
    if force_kill {
      Self::AllowProcessShutdown
    } else {
      Self::NonDisruptive
    }
  }

  fn allows_process_shutdown(self) -> bool {
    self == Self::AllowProcessShutdown
  }
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowsLockedFile {
  Database,
  WriteAheadLog,
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowsSharingViolation {
  locked_file: WindowsLockedFile,
  locked_path: PathBuf,
  has_verified_nonempty_wal: bool,
  os_error: i32,
}

/// Typed context for a Windows browser database that ordinary acquisition
/// could not read because another process denied file sharing.
#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsDatabaseLocked {
  pub(crate) locked_file: WindowsLockedFile,
  pub(crate) locked_path: PathBuf,
  pub(crate) has_verified_nonempty_wal: bool,
  pub(crate) shutdown_allowed: bool,
  pub(crate) os_error: i32,
}

#[cfg(any(target_os = "windows", test))]
impl std::fmt::Display for WindowsDatabaseLocked {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let file = match self.locked_file {
      WindowsLockedFile::Database => "database",
      WindowsLockedFile::WriteAheadLog => "write-ahead log",
    };
    let policy = if self.shutdown_allowed {
      "explicit process shutdown did not make it readable"
    } else {
      "process shutdown is disabled"
    };
    write!(
      formatter,
      "Windows browser {file} is share-locked at {} (OS error {}); {policy}",
      self.locked_path.display(),
      self.os_error
    )
  }
}

/// Retains diagnostics from a failed raw shadow-copy acquisition without
/// replacing the ordinary acquisition error as the source of the final error.
///
/// The ordinary error carries [`sqlite::BrowserDatabaseFailure`] metadata used
/// by source reports. Keeping this value as an `anyhow` context makes both that
/// metadata and [`WindowsDatabaseLocked`] downcastable while still explaining
/// why the non-disruptive fallback did not succeed.
#[cfg(any(target_os = "windows", test))]
#[derive(Debug)]
struct WindowsShadowFallbackFailure {
  shadow_diagnostic: String,
  retry_diagnostic: Option<String>,
}

#[cfg(any(target_os = "windows", test))]
impl WindowsShadowFallbackFailure {
  fn new(shadow_error: &anyhow::Error, retry_error: Option<&anyhow::Error>) -> Self {
    Self {
      shadow_diagnostic: format!("{shadow_error:#}"),
      retry_diagnostic: retry_error.map(|error| format!("{error:#}")),
    }
  }
}

#[cfg(any(target_os = "windows", test))]
impl std::fmt::Display for WindowsShadowFallbackFailure {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      formatter,
      "Windows WAL shadow-copy fallback failed: {}",
      self.shadow_diagnostic
    )?;
    if let Some(retry) = &self.retry_diagnostic {
      write!(
        formatter,
        "; ordinary acquisition after explicit process shutdown also failed: {retry}"
      )?;
    }
    Ok(())
  }
}

#[cfg(any(target_os = "windows", test))]
impl std::error::Error for WindowsShadowFallbackFailure {}

#[cfg(any(target_os = "windows", test))]
struct WindowsFallbackSource<Guard> {
  path: PathBuf,
  _guard: Guard,
}

#[cfg(any(target_os = "windows", test))]
fn windows_locked_error(
  violation: &WindowsSharingViolation,
  policy: WindowsLockedDatabasePolicy,
) -> WindowsDatabaseLocked {
  WindowsDatabaseLocked {
    locked_file: violation.locked_file,
    locked_path: violation.locked_path.clone(),
    has_verified_nonempty_wal: violation.has_verified_nonempty_wal,
    shutdown_allowed: policy.allows_process_shutdown(),
    os_error: violation.os_error,
  }
}

#[cfg(any(target_os = "windows", test))]
fn windows_locked_after_shadow_failure(
  ordinary_error: anyhow::Error,
  violation: &WindowsSharingViolation,
  policy: WindowsLockedDatabasePolicy,
  shadow_error: &anyhow::Error,
  retry_error: Option<&anyhow::Error>,
) -> anyhow::Error {
  ordinary_error
    .context(WindowsShadowFallbackFailure::new(shadow_error, retry_error))
    .context(windows_locked_error(violation, policy))
}

#[cfg(any(target_os = "windows", test))]
fn windows_sharing_code(error: &std::io::Error) -> Option<i32> {
  error.raw_os_error().filter(|code| {
    matches!(
      *code,
      ERROR_SHARING_VIOLATION_CODE | ERROR_LOCK_VIOLATION_CODE
    )
  })
}

#[cfg(any(target_os = "windows", test))]
fn sharing_code_in_error_chain(error: &anyhow::Error) -> Option<i32> {
  error
    .chain()
    .find_map(|cause| windows_sharing_code(cause.downcast_ref::<std::io::Error>()?))
}

#[cfg(any(target_os = "windows", test))]
fn is_sqlite_cant_open(error: &anyhow::Error) -> bool {
  error.chain().any(|cause| {
    matches!(
      cause.downcast_ref::<rusqlite::Error>(),
      Some(rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error {
          code: rusqlite::ffi::ErrorCode::CannotOpen,
          ..
        },
        _
      ))
    )
  })
}

#[cfg(any(target_os = "windows", test))]
fn probe_windows_sharing_violation(
  db_path: &std::path::Path,
  include_wal: bool,
) -> Option<WindowsSharingViolation> {
  let wal_path = sqlite::sidecar(db_path, "-wal");
  let wal_metadata = std::fs::metadata(&wal_path);
  let has_verified_nonempty_wal = wal_metadata
    .as_ref()
    .is_ok_and(|metadata| metadata.len() > 0);

  if let Err(error) = std::fs::File::open(db_path) {
    if let Some(code) = windows_sharing_code(&error) {
      return Some(WindowsSharingViolation {
        locked_file: WindowsLockedFile::Database,
        locked_path: db_path.to_path_buf(),
        has_verified_nonempty_wal,
        os_error: code,
      });
    }
  }

  if !include_wal {
    return None;
  }

  if let Err(error) = &wal_metadata {
    if let Some(code) = windows_sharing_code(error) {
      return Some(WindowsSharingViolation {
        locked_file: WindowsLockedFile::WriteAheadLog,
        locked_path: wal_path,
        // A share-denied metadata lookup cannot prove that the WAL is
        // nonempty, so it is ineligible for raw-copy fallback.
        has_verified_nonempty_wal: false,
        os_error: code,
      });
    }
    return None;
  }

  if has_verified_nonempty_wal {
    if let Err(error) = std::fs::File::open(&wal_path) {
      if let Some(code) = windows_sharing_code(&error) {
        return Some(WindowsSharingViolation {
          locked_file: WindowsLockedFile::WriteAheadLog,
          locked_path: wal_path,
          has_verified_nonempty_wal: true,
          os_error: code,
        });
      }
    }
  }

  None
}

#[cfg(any(target_os = "windows", test))]
fn classify_windows_sharing_violation_with_probe<Probe>(
  db_path: &std::path::Path,
  error: &anyhow::Error,
  mut probe: Probe,
) -> Option<WindowsSharingViolation>
where
  Probe: FnMut(&std::path::Path, bool) -> Option<WindowsSharingViolation>,
{
  let failure = error.downcast_ref::<sqlite::BrowserDatabaseFailure>()?;
  if failure.kind != sqlite::BrowserDatabaseFailureKind::Acquisition {
    return None;
  }

  let direct_code = sharing_code_in_error_chain(error);
  if direct_code.is_none() && !is_sqlite_cant_open(error) {
    return None;
  }

  if let Some(mut violation) = probe(db_path, direct_code.is_some()) {
    if failure.strategy == Some(sqlite::DatabaseAcquisitionStrategy::VerifiedWalSnapshot) {
      violation.has_verified_nonempty_wal = true;
    }
    return Some(violation);
  }

  direct_code.map(|os_error| WindowsSharingViolation {
    locked_file: WindowsLockedFile::Database,
    locked_path: db_path.to_path_buf(),
    has_verified_nonempty_wal: failure.strategy
      == Some(sqlite::DatabaseAcquisitionStrategy::VerifiedWalSnapshot),
    os_error,
  })
}

#[cfg(any(target_os = "windows", test))]
fn classify_windows_sharing_violation(
  db_path: &std::path::Path,
  error: &anyhow::Error,
) -> Option<WindowsSharingViolation> {
  classify_windows_sharing_violation_with_probe(db_path, error, probe_windows_sharing_violation)
}

#[cfg(any(target_os = "windows", test))]
fn with_windows_locked_database_policy<T, Guard, Query, Classify, IsAdmin, Shadow, Shutdown>(
  db_path: &std::path::Path,
  policy: WindowsLockedDatabasePolicy,
  mut query: Query,
  mut classify: Classify,
  mut is_admin: IsAdmin,
  mut shadow: Shadow,
  mut shutdown: Shutdown,
) -> Result<T>
where
  Query: FnMut(&std::path::Path) -> Result<T>,
  Classify: FnMut(&std::path::Path, &anyhow::Error) -> Option<WindowsSharingViolation>,
  IsAdmin: FnMut() -> bool,
  Shadow: FnMut(&std::path::Path) -> Result<WindowsFallbackSource<Guard>>,
  Shutdown: FnMut(&std::path::Path) -> bool,
{
  let ordinary_error = match query(db_path) {
    Ok(value) => return Ok(value),
    Err(error) => error,
  };
  let Some(violation) = classify(db_path, &ordinary_error) else {
    return Err(ordinary_error);
  };

  let mut shadow_error = None;
  if violation.has_verified_nonempty_wal && is_admin() {
    match shadow(db_path) {
      Ok(source) => {
        // The guard keeps the static shadow directory alive for the complete
        // query. A query/decode failure on this acquired source is final and
        // never grants permission to terminate the live browser.
        return query(&source.path);
      }
      Err(error) if !policy.allows_process_shutdown() => {
        return Err(windows_locked_after_shadow_failure(
          ordinary_error,
          &violation,
          policy,
          &error,
          None,
        ));
      }
      Err(error) => {
        log::warn!("Windows WAL shadow-copy fallback failed: {error}");
        shadow_error = Some(error);
      }
    }
  }

  if policy.allows_process_shutdown() && shutdown(&violation.locked_path) {
    return query(db_path).map_err(|error| {
      if let Some(shadow_error) = &shadow_error {
        let retry_violation = classify(db_path, &error).unwrap_or_else(|| violation.clone());
        return windows_locked_after_shadow_failure(
          ordinary_error,
          &retry_violation,
          policy,
          shadow_error,
          Some(&error),
        );
      }
      if let Some(retry_violation) = classify(db_path, &error) {
        error.context(windows_locked_error(&retry_violation, policy))
      } else {
        error
      }
    });
  }

  if let Some(shadow_error) = &shadow_error {
    return Err(windows_locked_after_shadow_failure(
      ordinary_error,
      &violation,
      policy,
      shadow_error,
      None,
    ));
  }

  Err(ordinary_error.context(windows_locked_error(&violation, policy)))
}

#[cfg(target_os = "windows")]
fn create_windows_shadow_source(
  db_path: &std::path::Path,
) -> Result<WindowsFallbackSource<crate::utils::TempDir>> {
  let temp_dir = crate::utils::TempDir::new()?;
  windows::shadow_copy::shadow_copy(db_path.to_path_buf(), temp_dir.path().to_path_buf())?;
  let file_name = db_path
    .file_name()
    .ok_or_else(|| anyhow!("Database path has no file name: {}", db_path.display()))?;
  let path = temp_dir.path().join(file_name);
  Ok(WindowsFallbackSource {
    path,
    _guard: temp_dir,
  })
}

/// Runs a source-inspection query through the same non-disruptive locked-file
/// recovery policy as Chromium extraction.
///
/// `any_browser` uses this before key retrieval to classify a live database by
/// schema. A share-locked DB+WAL pair can therefore be inspected through a
/// verified shadow copy without bypassing the sniff-first boundary or closing
/// the browser.
#[cfg(target_os = "windows")]
pub(crate) fn with_windows_locked_database_recovery<T, Query>(
  db_path: &std::path::Path,
  query: Query,
) -> Result<T>
where
  Query: FnMut(&std::path::Path) -> Result<T>,
{
  with_windows_locked_database_policy(
    db_path,
    WindowsLockedDatabasePolicy::NonDisruptive,
    query,
    classify_windows_sharing_violation,
    privilege::user::privileged,
    create_windows_shadow_source,
    |_| false,
  )
}

fn query_cookies<Context: ?Sized, Provider>(
  provider: &Provider,
  context: &Context,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<Cookie>>
where
  Provider: ChromiumKeyProvider<Context>,
{
  let outcomes = retrieve_key_outcomes(provider, context);
  query_cookies_with_key_outcomes(outcomes, db_path, domains, force_kill)
}

fn query_detailed_cookies<Context: ?Sized, Provider>(
  provider: &Provider,
  context: &Context,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<DetailedCookie>>
where
  Provider: ChromiumKeyProvider<Context>,
{
  let outcomes = retrieve_key_outcomes(provider, context);
  query_detailed_cookies_with_key_outcomes(outcomes, db_path, domains, force_kill)
}

#[allow(unused_variables)]
pub(crate) fn query_cookies_with_key_outcomes(
  outcomes: ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<Cookie>> {
  query_cookies_engine_outcome(&outcomes, db_path, domains, force_kill)?.into_legacy_result()
}

#[allow(unused_variables)]
fn query_detailed_cookies_with_key_outcomes(
  outcomes: ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<Vec<DetailedCookie>> {
  query_cookies_engine_outcome_mode(
    &outcomes,
    db_path,
    domains,
    force_kill,
    CookieProjection::Detailed,
    EncryptedValuePolicy::UseKeyOutcomes,
  )?
  .into_detailed_result()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn query_cookies_probe_with_key_outcomes(
  outcomes: ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<ChromiumProbeResult> {
  query_cookies_engine_outcome(&outcomes, db_path, domains, force_kill)?.into_probe_result()
}

#[allow(unused_variables)]
pub(crate) fn query_cookies_engine_outcome(
  outcomes: &ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
) -> Result<ChromiumEngineExtractionOutcome> {
  query_cookies_engine_outcome_mode(
    outcomes,
    db_path,
    domains,
    force_kill,
    CookieProjection::Legacy,
    EncryptedValuePolicy::UseKeyOutcomes,
  )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CookieProjection {
  Legacy,
  Detailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EncryptedValuePolicy {
  UseKeyOutcomes,
  RejectMissingIdentity,
}

const MISSING_BROWSER_KEY_IDENTITY_MESSAGE: &str =
  "encrypted explicit-path Chromium profile has no browser key identity; \
   pass a canonical browser_id from supported_browsers()";

#[derive(Debug)]
struct MissingBrowserKeyIdentity;

impl fmt::Display for MissingBrowserKeyIdentity {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(MISSING_BROWSER_KEY_IDENTITY_MESSAGE)
  }
}

impl std::error::Error for MissingBrowserKeyIdentity {}

#[allow(unused_variables)]
fn query_cookies_engine_outcome_mode(
  outcomes: &ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
  projection: CookieProjection,
  encrypted_value_policy: EncryptedValuePolicy,
) -> Result<ChromiumEngineExtractionOutcome> {
  #[cfg(target_os = "windows")]
  {
    let policy = WindowsLockedDatabasePolicy::from_force_kill(force_kill);
    with_windows_locked_database_policy(
      &db_path,
      policy,
      |path| {
        query_cookies_from_database(
          outcomes,
          path.to_path_buf(),
          domains.as_deref(),
          projection,
          encrypted_value_policy,
        )
      },
      classify_windows_sharing_violation,
      privilege::user::privileged,
      create_windows_shadow_source,
      |locked_path| unsafe {
        match crate::windows::restart_manager::release_file_lock(
          &locked_path.to_string_lossy(),
          true,
        ) {
          Ok(
            crate::windows::restart_manager::FileLockStatus::Unlocked
            | crate::windows::restart_manager::FileLockStatus::Released { .. },
          ) => true,
          Ok(crate::windows::restart_manager::FileLockStatus::Locked { .. }) => false,
          Err(error) => {
            log::warn!("Restart Manager could not release the Windows database lock: {error}");
            false
          }
        }
      },
    )
  }

  #[cfg(not(target_os = "windows"))]
  query_cookies_from_database(
    outcomes,
    db_path,
    domains.as_deref(),
    projection,
    encrypted_value_policy,
  )
}

fn query_cookies_from_database(
  outcomes: &ChromiumKeyOutcomes,
  db_path: PathBuf,
  domains: Option<&[String]>,
  projection: CookieProjection,
  encrypted_value_policy: EncryptedValuePolicy,
) -> Result<ChromiumEngineExtractionOutcome> {
  log::info!(
    "Creating SQLite connection to {}",
    db_path.to_str().unwrap_or("")
  );
  let database = sqlite::with_browser_database(db_path, |connection| {
    query_cookies_from_connection_mode(
      connection,
      outcomes,
      domains,
      projection,
      encrypted_value_policy,
    )
  });
  let database = match database {
    Err(error)
      if error
        .chain()
        .any(|cause| cause.is::<MissingBrowserKeyIdentity>()) =>
    {
      return Err(MissingBrowserKeyIdentity.into());
    }
    result => result?,
  };
  log::debug!(
    "Chromium database query succeeded via {:?} after {} attempt(s)",
    database.strategy(),
    database.attempts()
  );
  let strategy = database.strategy();
  let attempts = database.attempts();
  let mut outcome = database.into_value();
  outcome.acquisition_strategy = Some(strategy);
  outcome.acquisition_attempts = attempts;
  Ok(outcome)
}

/// Escapes SQL `LIKE` wildcard metacharacters (`%`, `_`) and the escape
/// character itself so a caller-supplied domain is matched as literal text,
/// not interpreted as a wildcard pattern. Pair with an `ESCAPE '\'` clause.
fn escape_like_pattern(input: &str) -> String {
  input
    .replace('\\', "\\\\")
    .replace('%', "\\%")
    .replace('_', "\\_")
}

#[cfg(test)]
fn query_cookies_from_connection(
  connection: &rusqlite::Connection,
  outcomes: &ChromiumKeyOutcomes,
  domains: Option<&[String]>,
) -> Result<ChromiumEngineExtractionOutcome> {
  query_cookies_from_connection_mode(
    connection,
    outcomes,
    domains,
    CookieProjection::Legacy,
    EncryptedValuePolicy::UseKeyOutcomes,
  )
}

fn query_cookies_from_connection_mode(
  connection: &rusqlite::Connection,
  outcomes: &ChromiumKeyOutcomes,
  domains: Option<&[String]>,
  projection: CookieProjection,
  encrypted_value_policy: EncryptedValuePolicy,
) -> Result<ChromiumEngineExtractionOutcome> {
  let schema_version = chromium_schema_version(connection)?;
  let columns = sqlite_table_columns(connection, "cookies")?;
  let optional_column = |name: &str| {
    if columns.contains(name) {
      name.to_string()
    } else {
      format!("NULL AS {name}")
    }
  };
  let mut query = format!(
    "SELECT host_key, path, is_secure, expires_utc, name, value, \
     CAST(encrypted_value AS BLOB), is_httponly, samesite, {}, {}, {}, {}, {} FROM cookies ",
    optional_column("top_frame_site_key"),
    optional_column("has_cross_site_ancestor"),
    optional_column("source_scheme"),
    optional_column("source_port"),
    optional_column("is_persistent"),
  );
  let domain_filters: Vec<String> = domains
    .map(|domains| {
      domains
        .iter()
        .filter_map(|domain| utils::normalized_domain_for_match(domain))
        .map(|domain| format!("%{}%", escape_like_pattern(domain)))
        .collect()
    })
    .unwrap_or_default();

  let apply_sql_domain_filter = encrypted_value_policy == EncryptedValuePolicy::UseKeyOutcomes;
  if domains.is_some() && apply_sql_domain_filter {
    if domain_filters.is_empty() {
      query += "WHERE 0";
    } else {
      let predicates = (1..=domain_filters.len())
        .map(|index| format!("host_key LIKE ?{index} ESCAPE '\\'"))
        .collect::<Vec<_>>()
        .join(" OR ");
      query += &format!("WHERE ({predicates})");
    }
  }
  query += ";";

  let mut extraction = ChromiumEngineExtractionOutcome::default();
  let mut last_row_error: Option<anyhow::Error> = None;
  let mut stmt = connection.prepare(query.as_str())?;
  let query_domain_filters = if apply_sql_domain_filter {
    domain_filters.as_slice()
  } else {
    &[]
  };
  let mut rows = stmt.query(rusqlite::params_from_iter(query_domain_filters.iter()))?;

  while let Some(row) = rows.next()? {
    let host_key = match row.get::<_, Option<String>>(0) {
      Ok(host_key) => host_key.unwrap_or_default(),
      Err(error) => {
        extraction.stats.rows_seen += 1;
        let row_number = extraction.stats.rows_seen;
        log::warn!("Failed to read host_key from Chromium cookie row: {error}");
        last_row_error = Some(anyhow!(
          "failed to read host_key from Chromium cookie row: {error}"
        ));
        extraction.record_skipped_row(ChromiumRowIssueCode::ColumnRead("host_key"), row_number);
        continue;
      }
    };
    let encrypted_value = if encrypted_value_policy == EncryptedValuePolicy::RejectMissingIdentity {
      match row.get::<_, Option<Vec<u8>>>(6) {
        Ok(value) => value.unwrap_or_default(),
        Err(error) => {
          extraction.stats.rows_seen += 1;
          let row_number = extraction.stats.rows_seen;
          log::warn!("Failed to read encrypted_value from Chromium cookie row: {error}");
          last_row_error = Some(anyhow!(
            "failed to read encrypted_value from Chromium cookie row: {error}"
          ));
          extraction.record_skipped_row(
            ChromiumRowIssueCode::ColumnRead("encrypted_value"),
            row_number,
          );
          continue;
        }
      }
    } else {
      Vec::new()
    };
    if encrypted_value_policy == EncryptedValuePolicy::RejectMissingIdentity
      && !encrypted_value.is_empty()
    {
      return Err(MissingBrowserKeyIdentity.into());
    }
    if !utils::some_domain_in_host(domains, &host_key) {
      continue;
    }
    extraction.stats.rows_seen += 1;
    let row_number = extraction.stats.rows_seen;
    macro_rules! read_optional_column {
      ($index:expr, $type:ty, $name:literal) => {
        match row.get::<_, Option<$type>>($index) {
          Ok(value) => value,
          Err(error) => {
            log::warn!("Failed to read {} from Chromium cookie row: {error}", $name);
            last_row_error = Some(anyhow!(
              "failed to read {} from Chromium cookie row: {error}",
              $name
            ));
            extraction.record_skipped_row(ChromiumRowIssueCode::ColumnRead($name), row_number);
            continue;
          }
        }
      };
    }

    let path = read_optional_column!(1, String, "path").unwrap_or_else(|| "/".to_string());
    let is_secure = read_optional_column!(2, bool, "is_secure").unwrap_or(false);
    let expires = read_optional_column!(3, i64, "expires_utc")
      .and_then(|value| u64::try_from(value).ok())
      .and_then(date::chromium_timestamp);
    let name: String = match row.get(4) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to read name from row: {err}");
        last_row_error = Some(anyhow!("failed to read name from row: {err}"));
        extraction.record_skipped_row(ChromiumRowIssueCode::ColumnRead("name"), row_number);
        continue;
      }
    };
    let value: String = match row.get(5) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to read value from row: {err}");
        last_row_error = Some(anyhow!("failed to read value from row: {err}"));
        extraction.record_skipped_row(ChromiumRowIssueCode::ColumnRead("value"), row_number);
        continue;
      }
    };
    let encrypted_value = if encrypted_value_policy == EncryptedValuePolicy::RejectMissingIdentity {
      encrypted_value
    } else {
      read_optional_column!(6, Vec<u8>, "encrypted_value").unwrap_or_default()
    };
    let http_only = read_optional_column!(7, bool, "is_httponly").unwrap_or(false);
    let same_site = read_optional_column!(8, i64, "samesite").unwrap_or(SAME_SITE_UNSPECIFIED);
    let decrypted_value = match decrypt_encrypted_value_with_outcomes(
      &host_key,
      value,
      &encrypted_value,
      outcomes,
      schema_version,
    ) {
      Ok(val) => val,
      Err(err) => {
        log::warn!("Failed to decrypt cookie value: {err}");
        let issue_code = err.row_issue_code();
        last_row_error = Some(anyhow!(err.to_string()));
        extraction.record_skipped_row(issue_code, row_number);
        continue;
      }
    };
    let cookie = Cookie {
      domain: host_key,
      path,
      secure: is_secure,
      expires,
      name,
      value: decrypted_value,
      http_only,
      same_site,
    };
    if projection == CookieProjection::Detailed {
      let context = match chromium_cookie_context(row) {
        Ok(context) => context,
        Err(error) => {
          log::warn!("{error}");
          let column = error.column;
          last_row_error = Some(error.into());
          extraction.record_skipped_row(ChromiumRowIssueCode::ColumnRead(column), row_number);
          continue;
        }
      };
      extraction
        .detailed_cookies
        .push(DetailedCookie { cookie, context });
    } else {
      extraction.cookies.push(cookie);
    }
    extraction.stats.cookies_emitted += 1;
  }
  if extraction.stats.rows_seen > 0 && extraction.stats.rows_skipped == extraction.stats.rows_seen {
    if let Some(error) = last_row_error {
      extraction.legacy_error = Some(extraction.total_row_failure(error));
    }
  }
  Ok(extraction)
}

fn sqlite_table_columns(
  connection: &rusqlite::Connection,
  table: &str,
) -> Result<std::collections::HashSet<String>> {
  let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
  let columns = statement
    .query_map([], |row| row.get::<_, String>(1))?
    .collect::<std::result::Result<std::collections::HashSet<_>, _>>()?;
  Ok(columns)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::browser::chromium_crypto::LegacySharedKeyProvider;
  #[cfg(unix)]
  use crate::browser::chromium_platform_keys::create_pbkdf2_key;
  use std::cell::{Cell, RefCell};
  use std::path::Path;
  use std::sync::atomic::{AtomicU64, Ordering};

  // Per-process unique temp paths without pulling in the `tempfile` dep.
  fn unique_tmpdir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir =
      std::env::temp_dir().join(format!("rookie-test-{}-{}-{}", tag, std::process::id(), n));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
  }

  fn query_cookies_with_legacy_keys(
    keys: Vec<Vec<u8>>,
    db_path: PathBuf,
    domains: Option<Vec<String>>,
    force_kill: bool,
  ) -> Result<Vec<Cookie>> {
    let provider = LegacySharedKeyProvider::new(keys);
    query_cookies(&provider, &(), db_path, domains, force_kill)
  }

  fn query_outcome_with_legacy_keys(
    keys: Vec<Vec<u8>>,
    db_path: PathBuf,
  ) -> Result<ChromiumEngineExtractionOutcome> {
    let outcomes = ChromiumKeyOutcomes::from_legacy_shared(keys);
    query_cookies_engine_outcome(&outcomes, db_path, None, false)
  }

  fn host_bound_plaintext(host_key: &str, value: &[u8]) -> Vec<u8> {
    let mut plaintext = Sha256::digest(host_key.as_bytes()).to_vec();
    plaintext.extend_from_slice(value);
    plaintext
  }

  // (host_key, path, is_secure, expires_utc, name, value, encrypted_value, is_httponly, samesite)
  type ChromiumRow<'a> = (
    &'a str,
    &'a str,
    bool,
    u64,
    &'a str,
    &'a str,
    &'a [u8],
    bool,
    i64,
  );

  fn seed_chromium_schema_version(connection: &rusqlite::Connection, version: u32) {
    connection
      .execute(
        "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR)",
        [],
      )
      .expect("create Chromium metadata table");
    connection
      .execute(
        "INSERT INTO meta (key, value) VALUES ('version', ?1)",
        [version.to_string()],
      )
      .expect("seed Chromium schema version");
  }

  // Minimal `cookies` table mirroring the columns chromium_based reads.
  // Real Chrome schema has many more columns, but query_cookies only
  // selects these nine.
  fn seed_chromium_cookies(db: &Path, rows: &[ChromiumRow<'_>]) {
    let conn = rusqlite::Connection::open(db).expect("open writable sqlite");
    seed_chromium_schema_version(&conn, 23);
    conn
      .execute(
        "CREATE TABLE cookies (
          host_key TEXT NOT NULL,
          path TEXT NOT NULL,
          is_secure INTEGER NOT NULL,
          expires_utc INTEGER NOT NULL,
          name TEXT NOT NULL,
          value TEXT NOT NULL,
          encrypted_value BLOB,
          is_httponly INTEGER NOT NULL,
          samesite INTEGER NOT NULL
        )",
        [],
      )
      .expect("create table");
    for r in rows {
      conn
        .execute(
          "INSERT INTO cookies (host_key, path, is_secure, expires_utc, name, value, \
            encrypted_value, is_httponly, samesite) \
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
          rusqlite::params![r.0, r.1, r.2, r.3, r.4, r.5, r.6, r.7, r.8],
        )
        .expect("insert row");
    }
  }

  #[test]
  fn detailed_cookies_preserve_partition_collisions() {
    let dir = unique_tmpdir("chromium-partition-collision");
    let db = dir.join("Cookies");
    let connection = rusqlite::Connection::open(&db).expect("open fixture");
    seed_chromium_schema_version(&connection, 23);
    connection
      .execute_batch(
        "CREATE TABLE cookies (
          host_key TEXT NOT NULL, path TEXT NOT NULL, is_secure INTEGER NOT NULL,
          expires_utc INTEGER NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
          encrypted_value BLOB, is_httponly INTEGER NOT NULL, samesite INTEGER NOT NULL,
          top_frame_site_key TEXT, has_cross_site_ancestor INTEGER,
          source_scheme INTEGER, source_port INTEGER, is_persistent INTEGER
        );
        INSERT INTO cookies VALUES
          ('.example.com', '/', 1, 0, 'session', 'work', X'', 1, 1,
           'https://work.example', 1, 2, 443, 1),
          ('.example.com', '/', 1, 0, 'session', 'personal', X'', 1, 1,
           'https://personal.example', 0, 2, 443, 1);",
      )
      .expect("seed partitioned cookies");
    drop(connection);

    let provider = LegacySharedKeyProvider::new(Vec::new());
    let cookies =
      query_detailed_cookies(&provider, &(), db, None, false).expect("extract detailed cookies");
    assert_eq!(cookies.len(), 2);
    assert_eq!(cookies[0].cookie.name, cookies[1].cookie.name);
    assert_eq!(cookies[0].cookie.domain, cookies[1].cookie.domain);
    assert_eq!(cookies[0].cookie.path, cookies[1].cookie.path);
    let contexts = cookies
      .iter()
      .map(|cookie| {
        (
          cookie.cookie.value.as_str(),
          (
            cookie.context.top_frame_site_key.as_deref(),
            cookie.context.has_cross_site_ancestor,
          ),
        )
      })
      .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(
      contexts.get("work"),
      Some(&(Some("https://work.example"), Some(true)))
    );
    assert_eq!(
      contexts.get("personal"),
      Some(&(Some("https://personal.example"), Some(false)))
    );
    assert_eq!(cookies[0].context.source_scheme, Some(2));
    assert_eq!(cookies[0].context.source_port, Some(443));
    assert_eq!(cookies[0].context.is_persistent, Some(true));
  }

  #[test]
  fn detailed_query_keeps_legacy_schemas_readable() {
    let dir = unique_tmpdir("chromium-legacy-detailed-schema");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[(
        ".example.com",
        "/",
        false,
        0,
        "legacy",
        "value",
        b"",
        false,
        0,
      )],
    );

    let provider = LegacySharedKeyProvider::new(Vec::new());
    let cookies = query_detailed_cookies(&provider, &(), db, None, false)
      .expect("missing optional columns remain compatible");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].context, CookieContext::default());
  }

  #[test]
  fn malformed_detailed_context_errors_without_changing_legacy_projection() {
    let dir = unique_tmpdir("chromium-malformed-detailed-context");
    let db = dir.join("Cookies");
    let connection = rusqlite::Connection::open(&db).expect("open fixture");
    seed_chromium_schema_version(&connection, 23);
    connection
      .execute_batch(
        "CREATE TABLE cookies (
          host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
          name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER,
          samesite INTEGER, top_frame_site_key BLOB
        );
        INSERT INTO cookies VALUES
          ('.example.com', '/', 0, 0, 'legacy', 'value', X'', 0, 0, X'FF');",
      )
      .expect("seed malformed context");
    drop(connection);

    let provider = LegacySharedKeyProvider::new(Vec::new());
    let legacy = query_cookies(&provider, &(), db.clone(), None, false)
      .expect("legacy projection does not inspect detailed columns");
    assert_eq!(legacy.len(), 1);
    let error = query_detailed_cookies(&provider, &(), db, None, false)
      .expect_err("malformed detailed context must not silently become absent");
    assert!(format!("{error:#}").contains("top_frame_site_key"));
  }

  #[test]
  fn malformed_detailed_context_skips_only_its_row() {
    let dir = unique_tmpdir("chromium-mixed-detailed-context");
    let db = dir.join("Cookies");
    let connection = rusqlite::Connection::open(&db).expect("open fixture");
    seed_chromium_schema_version(&connection, 23);
    connection
      .execute_batch(
        "CREATE TABLE cookies (
          host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER,
          name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER,
          samesite INTEGER, top_frame_site_key BLOB
        );
        INSERT INTO cookies VALUES
          ('.example.com', '/', 0, 0, 'before', 'first', X'', 0, 0,
           'https://before.example'),
          ('.example.com', '/', 0, 0, 'malformed', 'discarded', X'', 0, 0, X'FF'),
          ('.example.com', '/', 0, 0, 'after', 'last', X'', 0, 0,
           'https://after.example');",
      )
      .expect("seed mixed context rows");
    drop(connection);

    let provider = LegacySharedKeyProvider::new(Vec::new());
    let legacy = query_cookies(&provider, &(), db.clone(), None, false)
      .expect("legacy projection keeps every row");
    assert_eq!(legacy.len(), 3);

    let extraction = query_cookies_engine_outcome_mode(
      &ChromiumKeyOutcomes::from_legacy_shared(Vec::new()),
      db.clone(),
      None,
      false,
      CookieProjection::Detailed,
      EncryptedValuePolicy::UseKeyOutcomes,
    )
    .expect("malformed optional context remains a row-level failure");
    assert_eq!(
      extraction.stats,
      ChromiumExtractionStats {
        rows_seen: 3,
        cookies_emitted: 2,
        rows_skipped: 1,
      }
    );
    assert_eq!(extraction.issues.len(), 1);
    assert_eq!(
      extraction.issues[0].code,
      ChromiumRowIssueCode::ColumnRead("top_frame_site_key")
    );
    assert!(extraction.legacy_error.is_none());
    let detailed = extraction
      .into_detailed_result()
      .expect("valid detailed rows keep the extraction successful");
    assert_eq!(
      detailed
        .iter()
        .map(|cookie| cookie.cookie.name.as_str())
        .collect::<Vec<_>>(),
      vec!["before", "after"]
    );

    let public_result = query_detailed_cookies(&provider, &(), db, None, false)
      .expect("public detailed extraction returns the valid rows");
    assert_eq!(public_result.len(), 2);
  }

  fn synthetic_acquisition_error(
    strategy: Option<sqlite::DatabaseAcquisitionStrategy>,
    error: impl Into<anyhow::Error>,
  ) -> anyhow::Error {
    error.into().context(sqlite::BrowserDatabaseFailure {
      kind: sqlite::BrowserDatabaseFailureKind::Acquisition,
      strategy,
      attempts: 1,
    })
  }

  fn synthetic_query_error(error: impl Into<anyhow::Error>) -> anyhow::Error {
    error.into().context(sqlite::BrowserDatabaseFailure {
      kind: sqlite::BrowserDatabaseFailureKind::Query,
      strategy: Some(sqlite::DatabaseAcquisitionStrategy::LiveReadOnly),
      attempts: 1,
    })
  }

  fn sharing_violation(
    db_path: &Path,
    locked_file: WindowsLockedFile,
    has_verified_nonempty_wal: bool,
  ) -> WindowsSharingViolation {
    WindowsSharingViolation {
      locked_file,
      locked_path: match locked_file {
        WindowsLockedFile::Database => db_path.to_path_buf(),
        WindowsLockedFile::WriteAheadLog => sqlite::sidecar(db_path, "-wal"),
      },
      has_verified_nonempty_wal,
      os_error: ERROR_SHARING_VIOLATION_CODE,
    }
  }

  #[test]
  fn force_kill_maps_to_an_explicit_windows_shutdown_policy() {
    assert_eq!(
      WindowsLockedDatabasePolicy::from_force_kill(false),
      WindowsLockedDatabasePolicy::NonDisruptive
    );
    assert_eq!(
      WindowsLockedDatabasePolicy::from_force_kill(true),
      WindowsLockedDatabasePolicy::AllowProcessShutdown
    );
  }

  #[test]
  fn windows_policy_attempts_ordinary_query_before_any_fallback() {
    let db = PathBuf::from("ordinary/Cookies");
    let calls = RefCell::new(Vec::new());
    let value = with_windows_locked_database_policy(
      &db,
      WindowsLockedDatabasePolicy::NonDisruptive,
      |_| {
        calls.borrow_mut().push("ordinary");
        Ok("ordinary value")
      },
      |_, _| panic!("a successful ordinary query must not be classified"),
      || panic!("a successful ordinary query must not inspect privilege"),
      |_| -> Result<WindowsFallbackSource<()>> {
        panic!("a successful ordinary query must not be shadow-copied")
      },
      |_| panic!("a successful ordinary query must not stop a process"),
    )
    .expect("ordinary query succeeds");

    assert_eq!(value, "ordinary value");
    assert_eq!(*calls.borrow(), vec!["ordinary"]);
  }

  #[test]
  fn windows_policy_does_not_fallback_for_non_sharing_failures() {
    let db = PathBuf::from("ordinary/Cookies");
    let calls = RefCell::new(Vec::new());
    let error = with_windows_locked_database_policy(
      &db,
      WindowsLockedDatabasePolicy::AllowProcessShutdown,
      |_| {
        calls.borrow_mut().push("ordinary");
        Err::<(), _>(anyhow!("schema mismatch"))
      },
      |_, _| None,
      || panic!("a non-sharing failure must not inspect privilege"),
      |_| -> Result<WindowsFallbackSource<()>> {
        panic!("a schema error must not be shadow-copied")
      },
      |_| panic!("a schema error must not stop a process"),
    )
    .expect_err("schema error remains final");

    assert_eq!(error.to_string(), "schema mismatch");
    assert!(error.downcast_ref::<WindowsDatabaseLocked>().is_none());
    assert_eq!(*calls.borrow(), vec!["ordinary"]);
  }

  #[test]
  fn standard_and_admin_no_wal_locks_never_raw_copy_or_shutdown_by_default() {
    let db = PathBuf::from("no-wal/Cookies");
    for is_admin in [false, true] {
      let query_calls = Cell::new(0);
      let error = with_windows_locked_database_policy(
        &db,
        WindowsLockedDatabasePolicy::NonDisruptive,
        |_| {
          query_calls.set(query_calls.get() + 1);
          Err::<&str, _>(anyhow!("share denied"))
        },
        |_, _| Some(sharing_violation(&db, WindowsLockedFile::Database, false)),
        || is_admin,
        |_| -> Result<WindowsFallbackSource<()>> {
          panic!("no-WAL sources must never enter raw-copy fallback")
        },
        |_| panic!("default policy must never stop a process"),
      )
      .expect_err("share-denied no-WAL source remains locked");

      let locked = error
        .downcast_ref::<WindowsDatabaseLocked>()
        .expect("typed locked context");
      assert_eq!(locked.locked_file, WindowsLockedFile::Database);
      assert!(!locked.has_verified_nonempty_wal);
      assert!(!locked.shutdown_allowed);
      assert_eq!(query_calls.get(), 1);
    }
  }

  #[test]
  fn standard_user_wal_lock_returns_typed_locked_without_fallback() {
    let db = PathBuf::from("wal/Cookies");
    let error = with_windows_locked_database_policy(
      &db,
      WindowsLockedDatabasePolicy::NonDisruptive,
      |_| Err::<(), _>(anyhow!("share denied")),
      |_, _| {
        Some(sharing_violation(
          &db,
          WindowsLockedFile::WriteAheadLog,
          true,
        ))
      },
      || false,
      |_| -> Result<WindowsFallbackSource<()>> {
        panic!("standard users cannot enter raw shadow-copy fallback")
      },
      |_| panic!("default policy must never stop a process"),
    )
    .expect_err("standard user cannot bypass a share-denied WAL");

    let locked = error
      .downcast_ref::<WindowsDatabaseLocked>()
      .expect("typed locked context");
    assert_eq!(locked.locked_file, WindowsLockedFile::WriteAheadLog);
    assert!(locked.has_verified_nonempty_wal);
  }

  #[test]
  fn admin_wal_lock_uses_verified_shadow_only_after_ordinary_failure() {
    let db = PathBuf::from("live/Cookies");
    let shadow_db = PathBuf::from("shadow/Cookies");
    let calls = RefCell::new(Vec::new());
    let value = with_windows_locked_database_policy(
      &db,
      WindowsLockedDatabasePolicy::NonDisruptive,
      |path| {
        if path == db {
          calls.borrow_mut().push("ordinary");
          Err::<&str, _>(anyhow!("share denied"))
        } else {
          assert_eq!(path, shadow_db);
          calls.borrow_mut().push("shadow query");
          Ok("shadow value")
        }
      },
      |_, _| Some(sharing_violation(&db, WindowsLockedFile::Database, true)),
      || true,
      |_| {
        calls.borrow_mut().push("shadow acquire");
        Ok(WindowsFallbackSource {
          path: shadow_db.clone(),
          _guard: (),
        })
      },
      |_| panic!("successful non-disruptive fallback must not stop a process"),
    )
    .expect("verified shadow succeeds");

    assert_eq!(value, "shadow value");
    assert_eq!(
      *calls.borrow(),
      vec!["ordinary", "shadow acquire", "shadow query"]
    );
  }

  #[test]
  fn failed_default_shadow_fallback_never_escalates_to_shutdown() {
    let db = PathBuf::from("live/Cookies");
    let calls = RefCell::new(Vec::new());
    let error = with_windows_locked_database_policy(
      &db,
      WindowsLockedDatabasePolicy::NonDisruptive,
      |_| {
        calls.borrow_mut().push("ordinary");
        Err::<(), _>(synthetic_acquisition_error(
          Some(sqlite::DatabaseAcquisitionStrategy::VerifiedWalSnapshot),
          anyhow!("ordinary share denied"),
        ))
      },
      |_, _| Some(sharing_violation(&db, WindowsLockedFile::Database, true)),
      || true,
      |_| {
        calls.borrow_mut().push("shadow acquire");
        Err::<WindowsFallbackSource<()>, _>(anyhow!("shadow unavailable"))
      },
      |_| panic!("default policy must never stop a process"),
    )
    .expect_err("failed non-disruptive fallback remains locked");

    let locked = error
      .downcast_ref::<WindowsDatabaseLocked>()
      .expect("typed locked context");
    assert!(locked.has_verified_nonempty_wal);
    assert!(!locked.shutdown_allowed);
    let ordinary = error
      .downcast_ref::<sqlite::BrowserDatabaseFailure>()
      .expect("ordinary acquisition metadata remains in the source chain");
    assert_eq!(
      ordinary.kind,
      sqlite::BrowserDatabaseFailureKind::Acquisition
    );
    assert_eq!(
      ordinary.strategy,
      Some(sqlite::DatabaseAcquisitionStrategy::VerifiedWalSnapshot)
    );
    assert_eq!(ordinary.attempts, 1);
    let fallback = error
      .downcast_ref::<WindowsShadowFallbackFailure>()
      .expect("shadow acquisition diagnostic remains typed");
    assert!(fallback.shadow_diagnostic.contains("shadow unavailable"));
    assert!(fallback.retry_diagnostic.is_none());
    let chain = format!("{error:#}");
    assert!(chain.contains("ordinary share denied"), "{chain}");
    assert!(chain.contains("shadow unavailable"), "{chain}");
    assert_eq!(*calls.borrow(), vec!["ordinary", "shadow acquire"]);
  }

  #[test]
  fn failed_shadow_and_shutdown_retry_preserve_original_acquisition_metadata() {
    let db = PathBuf::from("live/Cookies");
    let query_calls = Cell::new(0);
    let error = with_windows_locked_database_policy(
      &db,
      WindowsLockedDatabasePolicy::AllowProcessShutdown,
      |_| {
        let call = query_calls.get() + 1;
        query_calls.set(call);
        if call == 1 {
          Err::<(), _>(synthetic_acquisition_error(
            Some(sqlite::DatabaseAcquisitionStrategy::VerifiedWalSnapshot),
            anyhow!("original ordinary share denial"),
          ))
        } else {
          Err::<(), _>(anyhow!("post-shutdown retry failed"))
        }
      },
      |_, error| {
        (query_calls.get() == 1).then(|| {
          assert!(
            error
              .downcast_ref::<sqlite::BrowserDatabaseFailure>()
              .is_some(),
            "only the original acquisition is a classified sharing failure"
          );
          sharing_violation(&db, WindowsLockedFile::Database, true)
        })
      },
      || true,
      |_| Err::<WindowsFallbackSource<()>, _>(anyhow!("shadow acquisition failed")),
      |_| true,
    )
    .expect_err("failed retry remains a typed locked failure");

    assert!(error.downcast_ref::<WindowsDatabaseLocked>().is_some());
    let ordinary = error
      .downcast_ref::<sqlite::BrowserDatabaseFailure>()
      .expect("original ordinary acquisition metadata remains downcastable");
    assert_eq!(
      ordinary.kind,
      sqlite::BrowserDatabaseFailureKind::Acquisition
    );
    assert_eq!(
      ordinary.strategy,
      Some(sqlite::DatabaseAcquisitionStrategy::VerifiedWalSnapshot)
    );
    assert_eq!(ordinary.attempts, 1);
    let fallback = error
      .downcast_ref::<WindowsShadowFallbackFailure>()
      .expect("both fallback diagnostics remain typed");
    assert!(fallback
      .shadow_diagnostic
      .contains("shadow acquisition failed"));
    assert!(fallback
      .retry_diagnostic
      .as_deref()
      .is_some_and(|diagnostic| diagnostic.contains("post-shutdown retry failed")));
    let chain = format!("{error:#}");
    assert!(chain.contains("original ordinary share denial"), "{chain}");
    assert!(chain.contains("shadow acquisition failed"), "{chain}");
    assert!(chain.contains("post-shutdown retry failed"), "{chain}");
    assert_eq!(query_calls.get(), 2);
  }

  #[test]
  fn explicit_shutdown_retries_ordinary_acquisition_once() {
    let db = PathBuf::from("no-wal/Cookies");
    let calls = RefCell::new(Vec::new());
    let query_calls = Cell::new(0);
    let value = with_windows_locked_database_policy(
      &db,
      WindowsLockedDatabasePolicy::AllowProcessShutdown,
      |_| {
        let call = query_calls.get() + 1;
        query_calls.set(call);
        calls.borrow_mut().push("ordinary");
        if call == 1 {
          Err::<&str, _>(anyhow!("share denied"))
        } else {
          Ok("post-shutdown value")
        }
      },
      |_, _| Some(sharing_violation(&db, WindowsLockedFile::Database, false)),
      || false,
      |_| -> Result<WindowsFallbackSource<()>> { panic!("no-WAL source must not be raw-copied") },
      |path| {
        assert_eq!(path, db);
        calls.borrow_mut().push("shutdown");
        true
      },
    )
    .expect("explicit shutdown makes ordinary acquisition readable");

    assert_eq!(value, "post-shutdown value");
    assert_eq!(*calls.borrow(), vec!["ordinary", "shutdown", "ordinary"]);
  }

  #[test]
  fn failed_explicit_shutdown_returns_typed_locked_without_retrying_query() {
    let db = PathBuf::from("no-wal/Cookies");
    let query_calls = Cell::new(0);
    let shutdown_calls = Cell::new(0);
    let error = with_windows_locked_database_policy(
      &db,
      WindowsLockedDatabasePolicy::AllowProcessShutdown,
      |_| {
        query_calls.set(query_calls.get() + 1);
        Err::<(), _>(anyhow!("share denied"))
      },
      |_, _| Some(sharing_violation(&db, WindowsLockedFile::Database, false)),
      || false,
      |_| -> Result<WindowsFallbackSource<()>> { panic!("no-WAL source must not be raw-copied") },
      |_| {
        shutdown_calls.set(shutdown_calls.get() + 1);
        false
      },
    )
    .expect_err("failed explicit shutdown leaves a typed lock");

    let locked = error
      .downcast_ref::<WindowsDatabaseLocked>()
      .expect("typed locked context");
    assert!(locked.shutdown_allowed);
    assert_eq!(query_calls.get(), 1);
    assert_eq!(shutdown_calls.get(), 1);
  }

  #[test]
  fn acquired_shadow_query_failure_never_authorizes_shutdown() {
    let db = PathBuf::from("live/Cookies");
    let shadow_db = PathBuf::from("shadow/Cookies");
    let query_calls = Cell::new(0);
    let error = with_windows_locked_database_policy(
      &db,
      WindowsLockedDatabasePolicy::AllowProcessShutdown,
      |_| {
        let call = query_calls.get() + 1;
        query_calls.set(call);
        if call == 1 {
          Err::<(), _>(anyhow!("share denied"))
        } else {
          Err::<(), _>(anyhow!("shadow schema mismatch"))
        }
      },
      |_, _| Some(sharing_violation(&db, WindowsLockedFile::Database, true)),
      || true,
      |_| {
        Ok(WindowsFallbackSource {
          path: shadow_db.clone(),
          _guard: (),
        })
      },
      |_| panic!("query failures never authorize process shutdown"),
    )
    .expect_err("shadow query schema error remains final");

    assert_eq!(error.to_string(), "shadow schema mismatch");
    assert_eq!(query_calls.get(), 2);
  }

  #[test]
  fn classifier_requires_acquisition_stage_and_a_real_sharing_code() {
    let db = PathBuf::from("live/Cookies");
    let raw_sharing = std::io::Error::from_raw_os_error(ERROR_SHARING_VIOLATION_CODE);
    let query_error = synthetic_query_error(raw_sharing);
    assert!(
      classify_windows_sharing_violation_with_probe(&db, &query_error, |_, _| Some(
        sharing_violation(&db, WindowsLockedFile::Database, false)
      ))
      .is_none()
    );

    let busy = synthetic_acquisition_error(
      Some(sqlite::DatabaseAcquisitionStrategy::LiveReadOnly),
      rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY), None),
    );
    assert!(
      classify_windows_sharing_violation_with_probe(&db, &busy, |_, _| {
        panic!("SQLite BUSY is not a Windows sharing violation")
      })
      .is_none()
    );
  }

  #[test]
  fn classifier_preserves_db_and_wal_sharing_sites_and_wal_proof() {
    let db = PathBuf::from("live/Cookies");
    for (code, locked_file) in [
      (ERROR_SHARING_VIOLATION_CODE, WindowsLockedFile::Database),
      (ERROR_LOCK_VIOLATION_CODE, WindowsLockedFile::WriteAheadLog),
    ] {
      let error = synthetic_acquisition_error(
        Some(sqlite::DatabaseAcquisitionStrategy::VerifiedWalSnapshot),
        std::io::Error::from_raw_os_error(code),
      );
      let violation =
        classify_windows_sharing_violation_with_probe(&db, &error, |_, include_wal| {
          assert!(include_wal);
          Some(WindowsSharingViolation {
            locked_file,
            locked_path: match locked_file {
              WindowsLockedFile::Database => db.clone(),
              WindowsLockedFile::WriteAheadLog => sqlite::sidecar(&db, "-wal"),
            },
            // The acquisition strategy must retain its earlier positive WAL
            // proof even if a later probe cannot stat the share-denied sidecar.
            has_verified_nonempty_wal: false,
            os_error: code,
          })
        })
        .expect("typed sharing violation");

      assert_eq!(violation.locked_file, locked_file);
      assert_eq!(violation.os_error, code);
      assert!(violation.has_verified_nonempty_wal);
    }
  }

  #[test]
  fn sqlite_cant_open_requires_a_probe_confirmed_database_share_lock() {
    let db = PathBuf::from("live/Cookies");
    let cant_open = synthetic_acquisition_error(
      Some(sqlite::DatabaseAcquisitionStrategy::LiveReadOnly),
      rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CANTOPEN),
        None,
      ),
    );
    let violation =
      classify_windows_sharing_violation_with_probe(&db, &cant_open, |_, include_wal| {
        assert!(!include_wal, "generic CANTOPEN must not probe the WAL");
        Some(sharing_violation(&db, WindowsLockedFile::Database, false))
      })
      .expect("database probe confirms sharing violation");
    assert_eq!(violation.locked_file, WindowsLockedFile::Database);

    assert!(
      classify_windows_sharing_violation_with_probe(&db, &cant_open, |_, _| None).is_none(),
      "CANTOPEN without a confirmed Win32 sharing violation is not a fallback trigger"
    );
  }

  #[test]
  fn production_classifier_retains_a_direct_typed_sharing_violation() {
    let directory = crate::utils::TempDir::new().expect("temp dir");
    let db = directory.path().join("Cookies");
    std::fs::write(&db, b"fixture").expect("write fixture");
    let error = synthetic_acquisition_error(
      Some(sqlite::DatabaseAcquisitionStrategy::LiveReadOnly),
      std::io::Error::from_raw_os_error(ERROR_SHARING_VIOLATION_CODE),
    );

    let violation = classify_windows_sharing_violation(&db, &error)
      .expect("direct typed sharing error remains classified after probing");
    assert_eq!(violation.locked_file, WindowsLockedFile::Database);
    assert_eq!(violation.locked_path, db);
    assert!(!violation.has_verified_nonempty_wal);
  }

  #[cfg(target_os = "windows")]
  fn open_without_file_sharing(path: &Path) -> std::fs::File {
    use std::os::windows::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
      .read(true)
      .share_mode(0)
      .open(path)
      .expect("open exclusive Windows fixture handle")
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn windows_native_database_sharing_violation_is_classified() {
    let directory = crate::utils::TempDir::new().expect("temp dir");
    let db = directory.path().join("Cookies");
    std::fs::write(&db, b"fixture").expect("write fixture");
    let _exclusive = open_without_file_sharing(&db);
    let os_error = std::fs::File::open(&db).expect_err("exclusive handle denies sharing");
    let error = synthetic_acquisition_error(
      Some(sqlite::DatabaseAcquisitionStrategy::LiveReadOnly),
      os_error,
    );

    let violation =
      classify_windows_sharing_violation(&db, &error).expect("native database sharing violation");
    assert_eq!(violation.locked_file, WindowsLockedFile::Database);
    assert_eq!(violation.locked_path, db);
    assert!(!violation.has_verified_nonempty_wal);
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn windows_native_share_denied_valid_database_reaches_real_query_policy() {
    let directory = crate::utils::TempDir::new().expect("temp dir");
    let db = directory.path().join("Cookies");
    seed_chromium_cookies(
      &db,
      &[(
        ".example.com",
        "/",
        false,
        0,
        "plain",
        "fixture value",
        b"",
        false,
        0,
      )],
    );
    assert!(
      !sqlite::sidecar(&db, "-wal").exists(),
      "fixture must take the live no-WAL acquisition path"
    );

    let exclusive = open_without_file_sharing(&db);
    let error = query_cookies_with_legacy_keys(vec![], db.clone(), None, false)
      .expect_err("real query boundary must report the native sharing denial");

    let locked = error
      .downcast_ref::<WindowsDatabaseLocked>()
      .expect("native failure retains typed Windows lock context");
    assert_eq!(locked.locked_file, WindowsLockedFile::Database);
    assert_eq!(locked.locked_path, db);
    assert!(!locked.has_verified_nonempty_wal);
    assert!(
      !locked.shutdown_allowed,
      "force_kill=false must not authorize restart-manager shutdown"
    );
    let acquisition = error
      .downcast_ref::<sqlite::BrowserDatabaseFailure>()
      .expect("real acquisition metadata remains in the final chain");
    assert_eq!(
      acquisition.kind,
      sqlite::BrowserDatabaseFailureKind::Acquisition
    );
    assert_eq!(acquisition.attempts, 1);
    assert!(
      matches!(
        acquisition.strategy,
        None | Some(sqlite::DatabaseAcquisitionStrategy::LiveReadOnly)
      ),
      "the exclusive handle can deny either canonicalization or the live open: {acquisition:?}"
    );
    assert!(
      matches!(
        locked.os_error,
        ERROR_SHARING_VIOLATION_CODE | ERROR_LOCK_VIOLATION_CODE
      ),
      "the typed lock must retain the native Win32 sharing code: {error:#}"
    );
    assert!(
      std::fs::File::open(&db).is_err(),
      "the library must not release or shut down the process owning the exclusive handle"
    );

    drop(exclusive);
    let cookies = query_cookies_with_legacy_keys(vec![], db, None, false)
      .expect("the unchanged database is readable after releasing the fixture handle");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "plain");
    assert_eq!(cookies[0].value, "fixture value");
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn windows_native_wal_sharing_violation_retains_positive_wal_proof() {
    let directory = crate::utils::TempDir::new().expect("temp dir");
    let db = directory.path().join("Cookies");
    let wal = sqlite::sidecar(&db, "-wal");
    std::fs::write(&db, b"fixture").expect("write database fixture");
    std::fs::write(&wal, b"nonempty WAL fixture").expect("write WAL fixture");
    let _exclusive = open_without_file_sharing(&wal);
    let os_error = std::fs::File::open(&wal).expect_err("exclusive WAL handle denies sharing");
    let error = synthetic_acquisition_error(
      Some(sqlite::DatabaseAcquisitionStrategy::VerifiedWalSnapshot),
      os_error,
    );

    let violation =
      classify_windows_sharing_violation(&db, &error).expect("native WAL sharing violation");
    assert_eq!(violation.locked_file, WindowsLockedFile::WriteAheadLog);
    assert_eq!(violation.locked_path, wal);
    assert!(violation.has_verified_nonempty_wal);
  }

  #[cfg(unix)]
  fn encrypt_unix_cbc_cookie(version: &[u8; 3], key: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let iv = [b' '; 16];
    let cipher = Aes128CbcEnc::new((&key[..]).into(), &iv.into());
    let mut buffer = vec![0; plaintext.len() + 16];
    buffer[..plaintext.len()].copy_from_slice(plaintext);
    let ciphertext = cipher
      .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
      .expect("encrypt synthetic Chromium cookie");
    let mut encrypted_value = version.to_vec();
    encrypted_value.extend_from_slice(ciphertext);
    encrypted_value
  }

  #[cfg(target_os = "windows")]
  fn encrypt_windows_gcm_cookie(version: &[u8; 3], key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    use aes_gcm::{
      aead::{generic_array::GenericArray, Aead, KeyInit},
      Aes256Gcm,
    };

    let nonce = [0x42; 12];
    let cipher = Aes256Gcm::new_from_slice(key).expect("fixture key");
    let ciphertext = cipher
      .encrypt(GenericArray::from_slice(&nonce), plaintext)
      .expect("encrypt synthetic Chromium cookie");
    let mut encrypted_value = version.to_vec();
    encrypted_value.extend_from_slice(&nonce);
    encrypted_value.extend_from_slice(&ciphertext);
    encrypted_value
  }

  #[cfg(target_os = "linux")]
  struct SyntheticTierProvider {
    calls: Cell<usize>,
    outcomes: ChromiumKeyOutcomes,
  }

  #[cfg(target_os = "linux")]
  impl ChromiumKeyProvider<str> for SyntheticTierProvider {
    fn retrieve(&self, _context: &str) -> ChromiumKeyOutcomes {
      self.calls.set(self.calls.get() + 1);
      self.outcomes.clone()
    }
  }

  #[cfg(target_os = "linux")]
  #[test]
  fn injected_provider_routes_mixed_tiers_once_and_isolates_a_failed_tier() {
    let dir = unique_tmpdir("chr-injected-mixed-tiers");
    let db = dir.join("Cookies");
    let v10_key = [0x10; 16];
    let v11_key = [0x11; 16];
    let v10_value = encrypt_unix_cbc_cookie(b"v10", &v10_key, b"v10 value");
    let failed_v20_value = b"v20synthetic-provider-failure".to_vec();
    let v11_value = encrypt_unix_cbc_cookie(b"v11", &v11_key, b"v11 value");

    // The rows deliberately run success/failure/success. A provider failure
    // for one tier is row-scoped and must not discard either successful CBC
    // tier or trigger another installation-scoped provider call.
    seed_chromium_cookies(
      &db,
      &[
        (
          ".example.com",
          "/",
          false,
          0,
          "v10-good",
          "",
          &v10_value,
          false,
          0,
        ),
        (
          ".example.com",
          "/",
          false,
          0,
          "v20-failed-tier",
          "",
          &failed_v20_value,
          false,
          0,
        ),
        (
          ".example.com",
          "/",
          false,
          0,
          "v11-good",
          "",
          &v11_value,
          false,
          0,
        ),
      ],
    );

    let provider = SyntheticTierProvider {
      calls: Cell::new(0),
      outcomes: ChromiumKeyOutcomes {
        v10: crate::browser::chromium_crypto::ChromiumKeyOutcome::success(vec![v10_key.to_vec()])
          .expect("nonempty v10 fixture"),
        v11: crate::browser::chromium_crypto::ChromiumKeyOutcome::success(vec![v11_key.to_vec()])
          .expect("nonempty v11 fixture"),
        v20: crate::browser::chromium_crypto::ChromiumKeyOutcome::failure(
          "synthetic v20 provider failure",
        ),
      },
    };

    let mut cookies = query_cookies(&provider, "linux-installation", db, None, false)
      .expect("good tiers survive one failed tier");

    assert_eq!(provider.calls.get(), 1);
    cookies.sort_by(|left, right| left.name.cmp(&right.name));
    let extracted: Vec<_> = cookies
      .iter()
      .map(|cookie| (cookie.name.as_str(), cookie.value.as_str()))
      .collect();
    assert_eq!(
      extracted,
      vec![("v10-good", "v10 value"), ("v11-good", "v11 value")]
    );
  }

  #[test]
  fn query_cookies_missing_db_errors() {
    let result = query_cookies_with_legacy_keys(
      vec![],
      PathBuf::from("/nonexistent/cookies.db"),
      None,
      false,
    );
    assert!(
      result.is_err(),
      "expected Err for missing db, got {:?}",
      result
    );
  }

  #[test]
  fn query_cookies_non_sqlite_file_errors() {
    let dir = unique_tmpdir("chr-bad-sqlite");
    let db = dir.join("Cookies");
    std::fs::write(&db, b"not a sqlite database at all").unwrap();
    let result = query_cookies_with_legacy_keys(vec![], db, None, false);
    assert!(
      result.is_err(),
      "expected Err for bogus sqlite, got {:?}",
      result
    );
  }

  // This is intentionally native on Windows as well as Unix: an ordinary
  // DB+WAL acquisition must succeed without consulting privilege, shadow-copy,
  // or restart-manager fallbacks.
  #[test]
  fn query_cookies_reads_cookies_committed_to_an_active_wal() {
    // Self-cleaning, unlike `unique_tmpdir`; held to the end of the test.
    let dir = crate::utils::TempDir::new().expect("temp dir");
    let db = dir.path().join("Cookies");
    seed_chromium_cookies(
      &db,
      &[(
        ".example.com",
        "/",
        false,
        0,
        "checkpointed",
        "old",
        b"",
        false,
        0,
      )],
    );

    // Switch to WAL and keep the writer connected, so the second cookie stays
    // in the -wal the way it does while Chrome is running.
    let writer = rusqlite::Connection::open(&db).expect("open writable sqlite");
    let mode: String = writer
      .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
      .expect("enable WAL");
    assert_eq!(mode, "wal");
    writer
      .execute(
        "INSERT INTO cookies (host_key, path, is_secure, expires_utc, name, value, \
          encrypted_value, is_httponly, samesite) \
          VALUES ('.example.com', '/', 0, 0, 'in-wal', 'fresh', X'', 0, 0)",
        [],
      )
      .expect("insert WAL row");

    let mut cookies = query_cookies_with_legacy_keys(vec![], db, None, false).expect("decode");

    cookies.sort_by(|a, b| a.name.cmp(&b.name));
    let names: Vec<_> = cookies.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["checkpointed", "in-wal"], "{cookies:?}");
    let in_wal = cookies.iter().find(|c| c.name == "in-wal").expect("in-wal");
    assert_eq!(in_wal.value, "fresh");
  }

  #[test]
  fn query_cookies_empty_table_returns_empty() {
    let dir = unique_tmpdir("chr-empty-table");
    let db = dir.join("Cookies");
    seed_chromium_cookies(&db, &[]);
    let cookies = query_cookies_with_legacy_keys(vec![], db, None, false).expect("decode");
    assert!(cookies.is_empty(), "{:?}", cookies);
  }

  #[test]
  fn query_cookies_errors_when_every_row_fails_to_decode() {
    let dir = unique_tmpdir("chr-all-rows-bad");
    let db = dir.join("Cookies");
    seed_chromium_cookies(&db, &[]);
    // The name is required identity data, so a row whose name cannot decode
    // must not turn a total extraction failure into an empty success.
    let conn = rusqlite::Connection::open(&db).expect("open writable sqlite");
    conn
      .execute(
        "INSERT INTO cookies (host_key, path, is_secure, expires_utc, name, value, \
          encrypted_value, is_httponly, samesite) \
          VALUES ('.example.com', '/', 1, 0, X'DEADBEEF', 'plain', X'', 1, 0)",
        [],
      )
      .expect("insert bad row");
    drop(conn);

    let outcome = query_outcome_with_legacy_keys(vec![], db.clone()).expect("source query");
    assert_eq!(outcome.stats.rows_seen, 1);
    assert_eq!(outcome.stats.cookies_emitted, 0);
    assert_eq!(outcome.stats.rows_skipped, 1);
    assert_eq!(outcome.issues.len(), 1);
    assert_eq!(
      outcome.issues[0].code,
      ChromiumRowIssueCode::ColumnRead("name")
    );
    let diagnostic = format!(
      "{:#}",
      outcome
        .legacy_error
        .as_ref()
        .expect("total row failure retains its diagnostic")
    );
    assert!(diagnostic.contains("ColumnRead(\"name\")"), "{diagnostic}");
    assert!(diagnostic.contains("row 1"), "{diagnostic}");

    let result = query_cookies_with_legacy_keys(vec![], db, None, false);
    assert!(
      result.is_err(),
      "expected Err when no row decodes, got {:?}",
      result
    );
  }

  #[test]
  fn query_cookies_emits_a_valid_empty_value() {
    let dir = unique_tmpdir("chr-valueless-plus-bad");
    let db = dir.join("Cookies");
    // An empty value is valid cookie data and must not disappear merely
    // because both the plaintext and encrypted storage columns are empty.
    seed_chromium_cookies(
      &db,
      &[(".example.com", "/", true, 0, "empty", "", b"", false, 0)],
    );
    let conn = rusqlite::Connection::open(&db).expect("open writable sqlite");
    conn
      .execute(
        "INSERT INTO cookies (host_key, path, is_secure, expires_utc, name, value, \
          encrypted_value, is_httponly, samesite) \
          VALUES ('.other.com', '/', 1, 0, X'DEADBEEF', 'plain', X'', 1, 0)",
        [],
      )
      .expect("insert bad row");
    drop(conn);

    let cookies = query_cookies_with_legacy_keys(vec![], db, None, false)
      .expect("valueless row is not a failure");
    assert_eq!(cookies.len(), 1, "{cookies:?}");
    assert_eq!(cookies[0].name, "empty");
    assert_eq!(cookies[0].value, "");
  }

  #[test]
  fn query_cookies_defaults_null_and_out_of_range_metadata() {
    let dir = unique_tmpdir("chr-null-metadata");
    let db = dir.join("Cookies");
    let connection = rusqlite::Connection::open(&db).expect("open writable sqlite");
    seed_chromium_schema_version(&connection, 23);
    connection
      .execute(
        "CREATE TABLE cookies (
          host_key TEXT,
          path TEXT,
          is_secure INTEGER,
          expires_utc INTEGER,
          name TEXT,
          value TEXT,
          encrypted_value BLOB,
          is_httponly INTEGER,
          samesite INTEGER
        )",
        [],
      )
      .expect("create table");
    connection
      .execute(
        "INSERT INTO cookies VALUES (NULL, NULL, NULL, -1, 'kept', 'value', NULL, NULL, NULL)",
        [],
      )
      .expect("insert cookie with missing metadata");
    connection
      .execute(
        "INSERT INTO cookies VALUES ('.example.com', '/', 0, 0, NULL, 'value', X'', 0, 0)",
        [],
      )
      .expect("insert cookie without name");
    connection
      .execute(
        "INSERT INTO cookies VALUES ('.example.com', '/', 0, 0, 'missing-value', NULL, X'', 0, 0)",
        [],
      )
      .expect("insert cookie without value");

    let outcomes = ChromiumKeyOutcomes::from_legacy_shared(vec![]);
    let extraction =
      query_cookies_from_connection(&connection, &outcomes, None).expect("query cookies");
    assert_eq!(extraction.cookies.len(), 1, "{:?}", extraction.cookies);
    let cookie = &extraction.cookies[0];
    assert_eq!(cookie.name, "kept");
    assert_eq!(cookie.value, "value");
    assert_eq!(cookie.domain, "");
    assert_eq!(cookie.path, "/");
    assert!(!cookie.secure);
    assert!(!cookie.http_only);
    assert_eq!(cookie.expires, None);
    assert_eq!(cookie.same_site, SAME_SITE_UNSPECIFIED);
    assert_eq!(extraction.stats.rows_seen, 3);
    assert_eq!(extraction.stats.cookies_emitted, 1);
    assert_eq!(extraction.stats.rows_skipped, 2);
  }

  #[test]
  fn query_cookies_skips_every_malformed_core_column_without_defaulting_metadata() {
    let dir = unique_tmpdir("chr-malformed-core-columns");
    let db = dir.join("Cookies");
    let connection = rusqlite::Connection::open(&db).expect("open writable sqlite");
    seed_chromium_schema_version(&connection, 23);
    connection
      .execute_batch(
        "CREATE TABLE cookies (
          host_key, path, is_secure, expires_utc, name, value,
          encrypted_value, is_httponly, samesite
        );
        INSERT INTO cookies VALUES
          ('.example.com', '/', 1, 0, 'good', 'value', X'', 1, 1),
          (X'FF', '/', 1, 0, 'bad-host', 'value', X'', 1, 1),
          ('.example.com', X'FF', 1, 0, 'bad-path', 'value', X'', 1, 1),
          ('.example.com', '/', X'FF', 0, 'bad-secure', 'value', X'', 1, 1),
          ('.example.com', '/', 1, X'FF', 'bad-expires', 'value', X'', 1, 1),
          ('.example.com', '/', 1, 0, X'FF', 'value', X'', 1, 1),
          ('.example.com', '/', 1, 0, 'bad-value', X'FF', X'', 1, 1),
          ('.example.com', '/', 1, 0, 'bad-http-only', 'value', X'', X'FF', 1),
          ('.example.com', '/', 1, 0, 'bad-same-site', 'value', X'', 1, X'FF');",
      )
      .expect("seed malformed core columns");

    let outcomes = ChromiumKeyOutcomes::from_legacy_shared(vec![]);
    let extraction =
      query_cookies_from_connection(&connection, &outcomes, None).expect("query cookies");
    assert_eq!(
      extraction.stats,
      ChromiumExtractionStats {
        rows_seen: 9,
        cookies_emitted: 1,
        rows_skipped: 8,
      }
    );
    assert_eq!(extraction.cookies[0].name, "good");
    assert!(extraction.legacy_error.is_none());
    assert_eq!(
      extraction
        .issues
        .iter()
        .map(|issue| issue.code)
        .collect::<Vec<_>>(),
      vec![
        ChromiumRowIssueCode::ColumnRead("host_key"),
        ChromiumRowIssueCode::ColumnRead("path"),
        ChromiumRowIssueCode::ColumnRead("is_secure"),
        ChromiumRowIssueCode::ColumnRead("expires_utc"),
        ChromiumRowIssueCode::ColumnRead("name"),
        ChromiumRowIssueCode::ColumnRead("value"),
        ChromiumRowIssueCode::ColumnRead("is_httponly"),
        ChromiumRowIssueCode::ColumnRead("samesite"),
      ]
    );
  }

  #[test]
  fn query_cookies_returns_plaintext_value_when_value_is_set() {
    let dir = unique_tmpdir("chr-plaintext");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[(
        ".example.com",
        "/",
        true,
        // chromium_timestamp wants microseconds since 1601-01-01.
        // 11_644_473_600_000_000 us == Unix epoch.
        11_644_473_600_000_000 + 1_700_000_000 * 1_000_000,
        "id",
        "plain",
        b"",
        true,
        1,
      )],
    );
    let cookies = query_cookies_with_legacy_keys(vec![], db, None, false).expect("decode");
    assert_eq!(cookies.len(), 1, "{:?}", cookies);
    let c = &cookies[0];
    assert_eq!(c.domain, ".example.com");
    assert_eq!(c.name, "id");
    assert_eq!(c.value, "plain");
    assert!(c.http_only);
    assert!(c.secure);
    assert_eq!(c.same_site, 1);
    assert_eq!(c.expires, Some(1_700_000_000));
  }

  #[cfg(unix)]
  #[test]
  fn chromium_mock_keychain_known_answer() {
    let salt = b"saltysalt";
    let key = create_pbkdf2_key("mock_password", salt, 1003);
    assert_eq!(
      *key,
      vec![
        0xaf, 0x0f, 0x76, 0x2a, 0xaf, 0x6d, 0x7d, 0x11, 0x58, 0x1b, 0x7a, 0xa8, 0xce, 0x72, 0x18,
        0xde,
      ]
    );

    let ciphertext = [
      0x76, 0x31, 0x30, 0xbf, 0x08, 0x6d, 0x20, 0x56, 0x86, 0x1a, 0x80, 0xde, 0x82, 0x5f, 0xc9,
      0x35, 0x86, 0x86, 0x30, 0x64, 0x4f, 0x2c, 0xa1, 0x87, 0x45, 0x02, 0x13, 0xae, 0x66, 0x81,
      0xb4, 0xd6, 0x43, 0xd1, 0x9b, 0x25, 0x81, 0xc8, 0x5c, 0x88, 0x78, 0xc1, 0xbc, 0x97, 0xe7,
      0x26, 0xa1, 0x0e, 0x51, 0xea, 0x77,
    ];
    let plaintext = [
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
      0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
      0x1e, 0x1f,
    ];

    let decrypted = decrypt_encrypted_value(
      ".example.com",
      "".to_string(),
      &ciphertext,
      &[key.to_vec()],
      23,
    )
    .expect("decrypt vector");
    assert_eq!(decrypted.as_bytes(), plaintext);
  }

  #[test]
  fn decode_cookie_value_strips_only_the_exact_stored_host_hash() {
    let plaintext = host_bound_plaintext(".example.com", b"cookie value");
    let decoded =
      decode_chromium_cookie_value(".example.com", plaintext.clone(), 23).expect("host match");
    assert_eq!(decoded, "cookie value");
    assert_eq!(
      decode_chromium_cookie_value("example.com", plaintext, 23),
      Err(ChromiumCookieDecodeError::HostHashMismatchWithInvalidUtf8),
      "the leading dot in the stored host is part of the exact hash input"
    );
  }

  #[test]
  fn decode_cookie_value_maps_an_exact_hash_only_plaintext_to_empty() {
    let plaintext = host_bound_plaintext(".example.com", b"");
    let decoded = decode_chromium_cookie_value(".example.com", plaintext, 23).expect("hash only");
    assert_eq!(decoded, "");
  }

  #[test]
  fn decode_cookie_value_preserves_valid_utf8_when_a_32_byte_prefix_mismatches() {
    let plaintext = b"this old unprefixed value is longer than thirty-two bytes".to_vec();
    let decoded = decode_chromium_cookie_value(".example.com", plaintext.clone(), 23)
      .expect("old unprefixed value");
    assert_eq!(decoded.as_bytes(), plaintext);
  }

  #[test]
  fn decode_cookie_value_rejects_a_mismatched_non_utf8_prefix() {
    let mut plaintext = vec![0xff; CHROMIUM_HOST_HASH_LEN];
    plaintext.extend_from_slice(b"must not be stripped");
    assert_eq!(
      decode_chromium_cookie_value(".example.com", plaintext, 23),
      Err(ChromiumCookieDecodeError::HostHashMismatchWithInvalidUtf8)
    );
  }

  #[test]
  fn decode_cookie_value_preserves_short_and_old_unprefixed_utf8() {
    assert_eq!(
      decode_chromium_cookie_value(".example.com", b"short".to_vec(), 23).expect("short value"),
      "short"
    );
    let old = "x".repeat(CHROMIUM_HOST_HASH_LEN + 8);
    assert_eq!(
      decode_chromium_cookie_value(".example.com", old.as_bytes().to_vec(), 23)
        .expect("old long value"),
      old
    );
  }

  #[test]
  fn decode_cookie_value_requires_an_exact_host_hash_for_v24_and_later() {
    assert_eq!(
      decode_chromium_cookie_value(".example.com", b"short".to_vec(), 24),
      Err(ChromiumCookieDecodeError::MissingRequiredHostHash)
    );
    assert_eq!(
      decode_chromium_cookie_value(
        ".example.com",
        b"this valid UTF-8 value has no matching host hash prefix".to_vec(),
        24,
      ),
      Err(ChromiumCookieDecodeError::HostHashMismatch)
    );

    let plaintext = host_bound_plaintext(".example.com", b"bound value");
    assert_eq!(
      decode_chromium_cookie_value(".example.com", plaintext, 24).expect("verified host hash"),
      "bound value"
    );
  }

  #[test]
  fn chromium_schema_version_is_read_strictly() {
    let missing = rusqlite::Connection::open_in_memory().expect("open missing-meta database");
    assert!(chromium_schema_version(&missing).is_err());

    let malformed = rusqlite::Connection::open_in_memory().expect("open malformed-meta database");
    malformed
      .execute("CREATE TABLE meta (key TEXT, value TEXT)", [])
      .expect("create metadata table");
    malformed
      .execute("INSERT INTO meta VALUES ('version', 'v24')", [])
      .expect("seed malformed version");
    let error = chromium_schema_version(&malformed).expect_err("malformed version must fail");
    assert!(error.to_string().contains("Invalid Chromium"));
  }

  #[test]
  fn chromium_schema_version_and_rows_come_from_the_acquired_wal_snapshot() {
    let dir = crate::utils::TempDir::new().expect("temp dir");
    let db = dir.path().join("Cookies");
    seed_chromium_cookies(
      &db,
      &[(
        ".example.com",
        "/",
        false,
        0,
        "snapshot",
        "old",
        b"",
        false,
        0,
      )],
    );

    let mut writer = rusqlite::Connection::open(&db).expect("open WAL writer");
    let mode: String = writer
      .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
      .expect("enable WAL");
    assert_eq!(mode, "wal");
    let transaction = writer.transaction().expect("begin WAL update");
    transaction
      .execute("UPDATE meta SET value = '24' WHERE key = 'version'", [])
      .expect("write version to WAL");
    transaction
      .execute(
        "UPDATE cookies SET value = 'new' WHERE name = 'snapshot'",
        [],
      )
      .expect("write cookie to WAL");
    transaction.commit().expect("commit WAL update");

    let acquired = sqlite::with_browser_database(db, |connection| {
      let version = chromium_schema_version(connection)?;
      let value = connection.query_row(
        "SELECT value FROM cookies WHERE name = 'snapshot'",
        [],
        |row| row.get::<_, String>(0),
      )?;
      Ok((version, value))
    })
    .expect("read acquired snapshot");

    assert_eq!(
      acquired.strategy(),
      sqlite::DatabaseAcquisitionStrategy::VerifiedWalSnapshot
    );
    assert_eq!(acquired.into_value(), (24, "new".to_string()));
  }

  #[test]
  fn decode_cookie_value_rejects_invalid_utf8_after_a_verified_hash() {
    let plaintext = host_bound_plaintext(".example.com", &[0xff]);
    assert_eq!(
      decode_chromium_cookie_value(".example.com", plaintext, 23),
      Err(ChromiumCookieDecodeError::InvalidUtf8AfterVerifiedHostHash)
    );
  }

  #[test]
  fn row_issue_aggregation_bounds_samples_without_losing_occurrences() {
    let mut outcome = ChromiumEngineExtractionOutcome::default();
    for row_number in 1..=MAX_CHROMIUM_ROW_ISSUE_SAMPLES + 3 {
      outcome.record_skipped_row(ChromiumRowIssueCode::Decode, row_number);
    }

    // Derived from the cap rather than hardcoded, so raising the bound cannot
    // leave the expectation describing a number the code no longer uses.
    let skipped = MAX_CHROMIUM_ROW_ISSUE_SAMPLES + 3;
    assert_eq!(outcome.stats.rows_skipped, skipped);
    assert_eq!(outcome.issues.len(), 1);
    assert_eq!(outcome.issues[0].occurrences, skipped);
    assert_eq!(
      outcome.issues[0].samples,
      (1..=MAX_CHROMIUM_ROW_ISSUE_SAMPLES)
        .map(|row| format!("row {row}"))
        .collect::<Vec<_>>()
    );
  }

  #[cfg(unix)]
  #[test]
  fn query_cookies_filters_by_domain() {
    let dir = unique_tmpdir("chr-domain-filter");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[
        (".example.com", "/", false, 0, "keep", "yes", b"x", false, 0),
        ("other.test", "/", false, 0, "drop", "no", b"x", false, 0),
      ],
    );
    let mut cookies = query_cookies_with_legacy_keys(
      vec![],
      db,
      Some(vec!["example.com".to_string(), "other.test".to_string()]),
      false,
    )
    .expect("decode");
    cookies.sort_by(|a, b| a.name.cmp(&b.name));
    let names: Vec<_> = cookies.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["drop", "keep"], "{:?}", cookies);
  }

  #[test]
  fn query_cookies_enforces_domain_boundaries_and_fail_closed_filters() {
    let dir = unique_tmpdir("chr-domain-filter-boundary");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[
        ("example.com", "/", false, 0, "exact", "yes", b"", false, 0),
        (
          ".sub.example.com",
          "/",
          false,
          0,
          "subdomain",
          "yes",
          b"",
          false,
          0,
        ),
        (
          "example.com.",
          "/",
          false,
          0,
          "trailing-dot",
          "yes",
          b"",
          false,
          0,
        ),
        (
          "notexample.com",
          "/",
          false,
          0,
          "prefix",
          "no",
          b"",
          false,
          0,
        ),
        (
          "example.com.evil.net",
          "/",
          false,
          0,
          "suffix",
          "no",
          b"",
          false,
          0,
        ),
        (
          "other.test",
          "/",
          false,
          0,
          "unrelated",
          "no",
          b"",
          false,
          0,
        ),
      ],
    );

    let connection = rusqlite::Connection::open(&db).expect("open cookie database");
    connection
      .execute(
        "INSERT INTO cookies (host_key, path, is_secure, expires_utc, name, value, \
          encrypted_value, is_httponly, samesite) \
          VALUES ('notexample.com', '/', 0, 0, X'DEADBEEF', 'off-scope', X'', 0, 0)",
        [],
      )
      .expect("insert malformed off-scope candidate");
    let outcomes = ChromiumKeyOutcomes::from_legacy_shared(vec![]);
    let names = |outcome: &ChromiumEngineExtractionOutcome| {
      let mut names = outcome
        .cookies
        .iter()
        .map(|cookie| cookie.name.clone())
        .collect::<Vec<_>>();
      names.sort();
      names
    };

    let domains = vec!["example.com".to_string()];
    let outcome = query_cookies_from_connection(&connection, &outcomes, Some(&domains))
      .expect("filter exact host and subdomains");
    assert_eq!(names(&outcome), vec!["exact", "subdomain", "trailing-dot"]);
    assert_eq!(outcome.stats.rows_seen, 3);
    assert_eq!(outcome.stats.rows_skipped, 0);
    assert_eq!(outcome.stats.cookies_emitted, 3);

    let dotted_domains = vec![".example.com.".to_string()];
    let dotted = query_cookies_from_connection(&connection, &outcomes, Some(&dotted_domains))
      .expect("leading and trailing dots must not narrow the SQL candidate set");
    assert_eq!(names(&dotted), vec!["exact", "subdomain", "trailing-dot"]);

    let mixed_domains = vec!["".to_string(), "example.com".to_string()];
    let mixed = query_cookies_from_connection(&connection, &outcomes, Some(&mixed_domains))
      .expect("a blank entry must not broaden a valid allowlist");
    assert_eq!(names(&mixed), vec!["exact", "subdomain", "trailing-dot"]);

    for invalid in ["", " \t ", ".", "%", "_"] {
      let domains = vec![invalid.to_string()];
      let outcome = query_cookies_from_connection(&connection, &outcomes, Some(&domains))
        .expect("invalid filter must be a successful empty result");
      assert!(
        outcome.cookies.is_empty(),
        "filter {invalid:?} must not expose cookies: {:?}",
        outcome.cookies
      );
      assert_eq!(outcome.stats.rows_seen, 0, "filter {invalid:?}");
      assert_eq!(outcome.stats.rows_skipped, 0, "filter {invalid:?}");
    }

    let empty_domains = Vec::new();
    let empty = query_cookies_from_connection(&connection, &outcomes, Some(&empty_domains))
      .expect("an explicit empty allowlist must validate the schema and match nothing");
    assert!(empty.cookies.is_empty());
    assert_eq!(empty.stats.rows_seen, 0);

    let empty_detailed = query_cookies_from_connection_mode(
      &connection,
      &outcomes,
      Some(&empty_domains),
      CookieProjection::Detailed,
      EncryptedValuePolicy::UseKeyOutcomes,
    )
    .expect("a detailed empty allowlist must validate the schema and match nothing");
    assert!(empty_detailed.detailed_cookies.is_empty());
    assert_eq!(empty_detailed.stats.rows_seen, 0);

    let empty_database = rusqlite::Connection::open_in_memory().expect("open empty database");
    assert!(
      query_cookies_from_connection(&empty_database, &outcomes, Some(&empty_domains)).is_err(),
      "a legacy empty allowlist must not bypass schema validation"
    );
    assert!(
      query_cookies_from_connection_mode(
        &empty_database,
        &outcomes,
        Some(&empty_domains),
        CookieProjection::Detailed,
        EncryptedValuePolicy::UseKeyOutcomes,
      )
      .is_err(),
      "a detailed empty allowlist must not bypass schema validation"
    );

    let unfiltered =
      query_cookies_from_connection(&connection, &outcomes, None).expect("unfiltered query");
    assert_eq!(
      names(&unfiltered),
      vec![
        "exact",
        "prefix",
        "subdomain",
        "suffix",
        "trailing-dot",
        "unrelated"
      ]
    );
    assert_eq!(unfiltered.stats.rows_seen, 7);
    assert_eq!(unfiltered.stats.rows_skipped, 1);
  }

  #[cfg(unix)]
  #[test]
  fn query_cookies_domain_filter_treats_sql_as_data() {
    let dir = unique_tmpdir("chr-domain-filter-sql");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[
        (
          ".example.com",
          "/",
          false,
          0,
          "first",
          "yes",
          b"x",
          false,
          0,
        ),
        ("other.test", "/", false, 0, "second", "no", b"x", false, 0),
      ],
    );

    let cookies =
      query_cookies_with_legacy_keys(vec![], db, Some(vec!["' OR 1=1 --".to_string()]), false)
        .expect("decode");
    assert!(cookies.is_empty(), "{:?}", cookies);
  }

  #[test]
  fn query_cookies_does_not_broaden_valid_domain_filter_with_sql_input() {
    let dir = unique_tmpdir("chr-domain-filter-scope");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[
        (".example.com", "/", false, 0, "keep", "yes", b"x", false, 0),
        ("other.test", "/", false, 0, "drop", "no", b"x", false, 0),
      ],
    );

    let cookies = query_cookies_with_legacy_keys(
      vec![],
      db,
      Some(vec!["example.com".to_string(), "') OR 1=1 --".to_string()]),
      false,
    )
    .expect("decode");
    let names: Vec<_> = cookies.iter().map(|cookie| cookie.name.as_str()).collect();
    assert_eq!(names, vec!["keep"], "{:?}", cookies);
  }

  #[test]
  fn query_cookies_percent_domain_is_not_a_wildcard() {
    let dir = unique_tmpdir("chr-domain-filter-percent");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[
        (".example.com", "/", false, 0, "keep", "yes", b"x", false, 0),
        ("other.test", "/", false, 0, "drop", "no", b"x", false, 0),
      ],
    );

    let cookies = query_cookies_with_legacy_keys(vec![], db, Some(vec!["%".to_string()]), false)
      .expect("decode");
    assert!(
      cookies.is_empty(),
      "a literal '%' domain must not match every host: {:?}",
      cookies
    );
  }

  #[test]
  fn query_cookies_underscore_domain_is_not_a_wildcard() {
    let dir = unique_tmpdir("chr-domain-filter-underscore");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[
        (".example.com", "/", false, 0, "keep", "yes", b"x", false, 0),
        ("a.test", "/", false, 0, "drop", "no", b"x", false, 0),
      ],
    );

    let cookies = query_cookies_with_legacy_keys(vec![], db, Some(vec!["_".to_string()]), false)
      .expect("decode");
    assert!(
      cookies.is_empty(),
      "a literal '_' domain must not match every single-character host: {:?}",
      cookies
    );
  }

  #[cfg(unix)]
  #[test]
  fn decrypt_encrypted_value_short_blob_returns_ok() {
    let res = decrypt_encrypted_value(".example.com", "orig".to_string(), b"v1", &[], 23)
      .expect("should not panic");
    assert_eq!(res, "orig");
  }

  #[cfg(unix)]
  #[test]
  fn linux_keyring_failure_diagnostic_reaches_v11_decryption() {
    let outcomes = ChromiumKeyOutcomes {
      v10: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
      v11: crate::browser::chromium_crypto::ChromiumKeyOutcome::failure(
        "all Linux keyring backends failed: Secret Service locked; KWallet denied",
      ),
      v20: crate::browser::chromium_crypto::ChromiumKeyOutcome::NotApplicable,
    };

    let error = decrypt_encrypted_value_with_outcomes(
      ".example.com",
      String::new(),
      b"v11encrypted",
      &outcomes,
      23,
    )
    .expect_err("v11 must preserve the provider diagnostic")
    .to_string();
    assert!(error.contains("Chromium v11 key provider failed"));
    assert!(error.contains("all Linux keyring backends failed"));
    assert!(error.contains("Secret Service locked"));
    assert!(error.contains("KWallet denied"));
  }

  #[cfg(unix)]
  #[test]
  fn decrypt_encrypted_value_invalid_utf8_returns_error() {
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let key = vec![0u8; 16];
    let iv = [b' '; 16];
    let cipher = Aes128CbcEnc::new((&key[..16]).into(), &iv.into());

    let data = vec![0xffu8; 16];
    let mut buf = vec![0u8; 32];
    buf[..16].copy_from_slice(&data);

    let ct = cipher.encrypt_padded_mut::<Pkcs7>(&mut buf, 16).unwrap();

    let mut encrypted_value = b"v10".to_vec();
    encrypted_value.extend_from_slice(ct);

    assert!(
      decrypt_encrypted_value(".example.com", "".to_string(), &encrypted_value, &[key], 23,)
        .is_err()
    );
  }

  #[cfg(unix)]
  #[test]
  fn decrypt_encrypted_value_decodes_host_hash_prefixed_plaintext() {
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let key = vec![0u8; 16];
    let iv = [b' '; 16];
    let plaintext = host_bound_plaintext(".example.com", b"cookie value");
    let mut ciphertext_buffer = vec![0u8; plaintext.len() + 16];
    ciphertext_buffer[..plaintext.len()].copy_from_slice(&plaintext);
    let cipher = Aes128CbcEnc::new((&key[..]).into(), &iv.into());
    let ciphertext = cipher
      .encrypt_padded_mut::<Pkcs7>(&mut ciphertext_buffer, plaintext.len())
      .expect("encrypt fixture");

    let mut encrypted_value = b"v10".to_vec();
    encrypted_value.extend_from_slice(ciphertext);
    let decrypted =
      decrypt_encrypted_value(".example.com", "".to_string(), &encrypted_value, &[key], 23)
        .expect("decrypt host-hash-prefixed value");

    assert_eq!(decrypted, "cookie value");
  }

  #[cfg(unix)]
  #[test]
  fn decrypt_encrypted_value_tries_next_key_after_invalid_utf8() {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let correct_key = vec![0u8; 16];
    let iv = [b' '; 16];
    let expected = b"valid cookie value";
    let mut ciphertext_buffer = vec![0u8; expected.len() + 16];
    ciphertext_buffer[..expected.len()].copy_from_slice(expected);
    let cipher = Aes128CbcEnc::new((&correct_key[..]).into(), &iv.into());
    let ciphertext = cipher
      .encrypt_padded_mut::<Pkcs7>(&mut ciphertext_buffer, expected.len())
      .expect("encrypt fixture")
      .to_vec();

    let invalid_utf8_key = (1u16..=u16::MAX)
      .find_map(|candidate| {
        let mut key = vec![0; 16];
        key[..2].copy_from_slice(&candidate.to_le_bytes());
        let cipher = Aes128CbcDec::new((&key[..]).into(), &iv.into());
        let mut candidate_ciphertext = ciphertext.clone();
        let plaintext = cipher
          .decrypt_padded_mut::<Pkcs7>(&mut candidate_ciphertext)
          .ok()?;
        String::from_utf8(plaintext.to_vec())
          .is_err()
          .then_some(key)
      })
      .expect("fixture must include a wrong key with valid padding and invalid UTF-8");

    let mut encrypted_value = b"v10".to_vec();
    encrypted_value.extend_from_slice(&ciphertext);
    let decrypted = decrypt_encrypted_value(
      ".example.com",
      "".to_string(),
      &encrypted_value,
      &[invalid_utf8_key, correct_key],
      23,
    )
    .expect("second key should decrypt the cookie");

    assert_eq!(decrypted, "valid cookie value");
  }

  #[cfg(windows)]
  #[test]
  fn decrypt_encrypted_value_windows_verifies_host_hash_and_tries_later_key() {
    let correct_key = [0x20; 32];
    let wrong_key = vec![0x10; 32];
    let plaintext = host_bound_plaintext(".example.com", b"verified value");
    let encrypted_value = encrypt_windows_gcm_cookie(b"v20", &correct_key, &plaintext);

    let decrypted = decrypt_encrypted_value(
      ".example.com",
      "".to_string(),
      &encrypted_value,
      &[wrong_key, correct_key.to_vec()],
      23,
    )
    .expect("later key should authenticate and decode");
    assert_eq!(decrypted, "verified value");
  }

  #[cfg(windows)]
  #[test]
  fn decrypt_encrypted_value_windows_classifies_non_utf8_hash_mismatch_as_decode_failure() {
    let key = [0x20; 32];
    let plaintext = vec![0xff; CHROMIUM_HOST_HASH_LEN + 1];
    let encrypted_value = encrypt_windows_gcm_cookie(b"v20", &key, &plaintext);

    assert!(matches!(
      decrypt_encrypted_value(
        ".example.com",
        "".to_string(),
        &encrypted_value,
        &[key.to_vec()],
        23,
      ),
      Err(ChromiumCookieValueError::Decode(
        ChromiumCookieDecodeError::HostHashMismatchWithInvalidUtf8
      ))
    ));
  }

  #[cfg(windows)]
  #[test]
  fn decrypt_encrypted_value_windows_truncated_blob_returns_ok() {
    for len in 3..15 {
      let mut blob = b"v10".to_vec();
      blob.resize(len, 0);
      let res = decrypt_encrypted_value(".example.com", "orig".to_string(), &blob, &[], 23)
        .expect("should not panic");
      assert_eq!(res, "orig");
    }
  }

  #[cfg(windows)]
  #[test]
  fn decrypt_encrypted_value_skips_wrong_length_key() {
    // A candidate key that isn't 32 bytes must be skipped, not panic the
    // AES-256-GCM path (Key::from_slice would have panicked). Reaching the
    // assertion at all proves there was no panic; with no usable key the
    // function falls through to an error.
    let mut blob = b"v10".to_vec();
    blob.resize(31, 0); // "v10" + 12-byte nonce + 16-byte ciphertext region
    let short_key = vec![0u8; 10];
    let res = decrypt_encrypted_value(".example.com", "".to_string(), &blob, &[short_key], 23);
    assert!(res.is_err());
  }

  #[test]
  fn query_outcome_tracks_row_stats_and_typed_issue_groups() {
    let dir = unique_tmpdir("chr-row-outcome");
    let db = dir.join("Cookies");
    seed_chromium_cookies(
      &db,
      &[(
        ".example.com",
        "/",
        false,
        0,
        "good",
        "plain",
        b"",
        false,
        0,
      )],
    );
    let conn = rusqlite::Connection::open(&db).expect("open writable sqlite");
    conn
      .execute(
        "INSERT INTO cookies VALUES ('.example.com', '/', 0, 0, X'DEADBEEF', 'plain', X'', 0, 0)",
        [],
      )
      .expect("insert malformed row");
    conn
      .execute(
        "INSERT INTO cookies VALUES ('.example.com', '/', 0, 0, 'bad-cipher', '', X'7631', 0, 0)",
        [],
      )
      .expect("insert malformed ciphertext");
    drop(conn);

    let outcome = query_outcome_with_legacy_keys(vec![], db).expect("source query");
    assert_eq!(
      outcome.stats,
      ChromiumExtractionStats {
        rows_seen: 3,
        cookies_emitted: 1,
        rows_skipped: 2,
      }
    );
    assert_eq!(outcome.cookies[0].name, "good");
    assert!(outcome.legacy_error.is_none());
    assert_eq!(outcome.issues.len(), 2);
    assert_eq!(
      outcome.issues[0].code,
      ChromiumRowIssueCode::ColumnRead("name")
    );
    assert_eq!(outcome.issues[0].occurrences, 1);
    assert_eq!(outcome.issues[1].code, ChromiumRowIssueCode::Decrypt);
    assert_eq!(outcome.issues[1].occurrences, 1);
  }

  #[cfg(unix)]
  #[test]
  fn query_outcome_verifies_host_hashes_and_classifies_decode_failures() {
    let dir = unique_tmpdir("chr-host-hash-outcome");
    let db = dir.join("Cookies");
    let key = [0x42; 16];
    let good_plaintext = host_bound_plaintext(".example.com", b"verified value");
    let good_encrypted = encrypt_unix_cbc_cookie(b"v10", &key, &good_plaintext);
    let invalid_mismatch = b"this valid UTF-8 plaintext has a mismatched host hash".to_vec();
    let invalid_encrypted = encrypt_unix_cbc_cookie(b"v10", &key, &invalid_mismatch);
    seed_chromium_cookies(
      &db,
      &[
        (
          ".example.com",
          "/",
          false,
          0,
          "verified",
          "",
          &good_encrypted,
          false,
          0,
        ),
        (
          ".other.test",
          "/",
          false,
          0,
          "mismatch",
          "",
          &invalid_encrypted,
          false,
          0,
        ),
        (
          ".plain.test",
          "/",
          false,
          0,
          "plain",
          "fallback",
          b"",
          false,
          0,
        ),
      ],
    );
    let connection = rusqlite::Connection::open(&db).expect("open writable sqlite");
    connection
      .execute("UPDATE meta SET value = '24' WHERE key = 'version'", [])
      .expect("select strict host-hash schema");
    drop(connection);

    let mut outcome =
      query_outcome_with_legacy_keys(vec![key.to_vec()], db.clone()).expect("legacy source query");
    outcome
      .cookies
      .sort_by(|left, right| left.name.cmp(&right.name));
    assert_eq!(
      outcome.stats,
      ChromiumExtractionStats {
        rows_seen: 3,
        cookies_emitted: 2,
        rows_skipped: 1,
      }
    );
    assert_eq!(
      outcome
        .cookies
        .iter()
        .map(|cookie| (cookie.name.as_str(), cookie.value.as_str()))
        .collect::<Vec<_>>(),
      vec![("plain", "fallback"), ("verified", "verified value")]
    );
    assert_eq!(outcome.issues.len(), 1);
    assert_eq!(outcome.issues[0].code, ChromiumRowIssueCode::Decode);
    assert_eq!(outcome.issues[0].occurrences, 1);

    let mut detailed = query_cookies_engine_outcome_mode(
      &ChromiumKeyOutcomes::from_legacy_shared(vec![key.to_vec()]),
      db,
      None,
      false,
      CookieProjection::Detailed,
      EncryptedValuePolicy::UseKeyOutcomes,
    )
    .expect("detailed source query");
    detailed
      .detailed_cookies
      .sort_by(|left, right| left.cookie.name.cmp(&right.cookie.name));
    assert_eq!(detailed.stats, outcome.stats);
    assert_eq!(detailed.issues, outcome.issues);
    assert_eq!(
      detailed
        .detailed_cookies
        .iter()
        .map(|record| (record.cookie.name.as_str(), record.cookie.value.as_str()))
        .collect::<Vec<_>>(),
      vec![("plain", "fallback"), ("verified", "verified value")]
    );
  }

  #[cfg(unix)]
  #[test]
  fn query_cookies_ignores_malformed_and_undecryptable_rows() {
    let dir = unique_tmpdir("chr-malformed-rows");
    let db = dir.join("Cookies");
    let conn = rusqlite::Connection::open(&db).expect("open writable sqlite");
    seed_chromium_schema_version(&conn, 23);
    conn
      .execute(
        "CREATE TABLE cookies (
          host_key TEXT NOT NULL,
          path TEXT NOT NULL,
          is_secure INTEGER NOT NULL,
          expires_utc INTEGER NOT NULL,
          name TEXT NOT NULL,
          value TEXT NOT NULL,
          encrypted_value BLOB,
          is_httponly INTEGER NOT NULL,
          samesite INTEGER NOT NULL
        )",
        [],
      )
      .expect("create table");

    // Row 1: Valid row
    conn
      .execute(
        "INSERT INTO cookies VALUES ('.example.com', '/', 1, 11644473600000000, 'valid1', 'val1', X'76313064756d6d79', 1, 1)",
        [],
      )
      .expect("insert row 1");

    // Row 2: Malformed required name column.
    conn
      .execute(
        "INSERT INTO cookies VALUES ('.example.com', '/', 1, -100, X'DEADBEEF', 'val', X'76313064756d6d79', 1, 1)",
        [],
      )
      .expect("insert row 2");

    // Row 3: Undecryptable row (encrypted_value starts with v10 but fails decryption)
    conn
      .execute(
        "INSERT INTO cookies VALUES ('.example.com', '/', 1, 11644473600000000, 'undecryptable', '', X'763130696e76616c6964', 1, 1)",
        [],
      )
      .expect("insert row 3");

    // Row 4: Valid row 2
    conn
      .execute(
        "INSERT INTO cookies VALUES ('.test.com', '/', 0, 11644473600000000, 'valid2', 'val2', X'76313064756d6d79', 0, 0)",
        [],
      )
      .expect("insert row 4");

    let mut cookies = query_cookies_with_legacy_keys(vec![], db, None, false)
      .expect("query_cookies should succeed despite bad rows");
    cookies.sort_by(|a, b| a.name.cmp(&b.name));
    let names: Vec<_> = cookies.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["valid1", "valid2"], "{:?}", cookies);
  }
}
