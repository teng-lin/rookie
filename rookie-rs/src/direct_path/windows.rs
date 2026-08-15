use super::{
  invalid_options, shared, unsupported_target, ChromiumCredentialSource,
  ChromiumLockedDatabasePolicy, ChromiumPathRequest, CookieSourceKind, DirectPathRequest,
  InvalidDirectPathOptionsReason,
};
use crate::browser::chromium_crypto::ChromiumKeyOutcomes;
use crate::browser::chromium_platform_keys::{
  ChromiumKeyCredentials, ChromiumKeyRequest, HostKeySession,
};
use crate::enums::{Cookie, DetailedCookie};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub(super) fn classify_cookie_source(path: &Path) -> Result<CookieSourceKind> {
  classify_cookie_source_with(
    path,
    |source| {
      crate::browser::chromium_database_acquisition::with_non_disruptive_recovery(
        source,
        shared::classify_sqlite,
      )
    },
    shared::read_header,
  )
}

fn classify_cookie_source_without_platform_recovery(path: &Path) -> Result<CookieSourceKind> {
  classify_cookie_source_with(path, shared::classify_sqlite, shared::read_header)
}

fn classify_cookie_source_with<Recover, ReadHeader>(
  path: &Path,
  mut recover: Recover,
  mut read_header: ReadHeader,
) -> Result<CookieSourceKind>
where
  Recover: FnMut(&Path) -> Result<CookieSourceKind>,
  ReadHeader: FnMut(&Path) -> Result<Vec<u8>>,
{
  let sqlite_error = recover(path);
  if let Ok(source) = sqlite_error {
    return Ok(source);
  }
  let sqlite_error = sqlite_error.expect_err("successful classification returned above");
  let header = match read_header(path) {
    Ok(header) => header,
    Err(header_error) if shared::classification_reason(&header_error).is_some() => {
      return Err(header_error);
    }
    Err(header_error) => {
      return Err(sqlite_error.context(format!(
        "cookie source signature fallback also failed: {header_error:#}"
      )));
    }
  };
  match shared::classify_header(&header)? {
    Some(source) => Ok(source),
    None => Err(sqlite_error),
  }
}

#[cfg(test)]
mod tests {
  use super::super::InvalidCookieSourceReason;
  use super::*;

  #[derive(Debug)]
  struct SqliteAcquisitionFailure;

  impl std::fmt::Display for SqliteAcquisitionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      formatter.write_str("SQLite acquisition failed")
    }
  }

  impl std::error::Error for SqliteAcquisitionFailure {}

  #[test]
  fn signature_fallback_failure_keeps_the_sqlite_acquisition_chain() {
    let error = classify_cookie_source_with(
      Path::new("Cookies"),
      |_| Err(SqliteAcquisitionFailure.into()),
      |_| anyhow::bail!("header read failed"),
    )
    .unwrap_err();

    assert!(error.downcast_ref::<SqliteAcquisitionFailure>().is_some());
    let diagnostic = format!("{error:#}");
    assert!(
      diagnostic.contains("cookie source signature fallback also failed: header read failed"),
      "{diagnostic}"
    );
    assert!(
      diagnostic.contains("SQLite acquisition failed"),
      "{diagnostic}"
    );
  }

  #[test]
  fn classified_header_failure_keeps_its_reason_and_io_chain() {
    let directory = crate::utils::TempDir::new().unwrap();
    let missing = directory.path().join("missing");
    let error = classify_cookie_source_with(
      &missing,
      |_| Err(SqliteAcquisitionFailure.into()),
      shared::read_header,
    )
    .unwrap_err();

    assert_eq!(
      shared::classification_reason(&error),
      Some(InvalidCookieSourceReason::NotARegularFile)
    );
    assert!(error.downcast_ref::<std::io::Error>().is_some());
    assert!(error.downcast_ref::<SqliteAcquisitionFailure>().is_none());
  }

  #[test]
  fn recovered_schema_is_authoritative_without_reading_the_live_header() {
    let header_reads = std::cell::Cell::new(0);
    let source = classify_cookie_source_with(
      Path::new("locked-live-Cookies"),
      |_| Ok(CookieSourceKind::ChromiumSqlite),
      |_| {
        header_reads.set(header_reads.get() + 1);
        anyhow::bail!("live header must not be reopened")
      },
    )
    .unwrap();

    assert_eq!(source, CookieSourceKind::ChromiumSqlite);
    assert_eq!(header_reads.get(), 0);
  }

  #[test]
  fn real_signature_is_used_after_sqlite_rejection() {
    let source = classify_cookie_source_with(
      Path::new("Cookies.binarycookies"),
      |_| anyhow::bail!("not a SQLite database"),
      |_| Ok(b"cookfixture".to_vec()),
    )
    .unwrap();

    assert_eq!(source, CookieSourceKind::SafariBinaryCookies);
  }
}

pub(super) fn cookies_from_path(
  request: DirectPathRequest,
  source: CookieSourceKind,
) -> Result<Vec<Cookie>> {
  match source {
    CookieSourceKind::ChromiumSqlite => Err(invalid_options(
      InvalidDirectPathOptionsReason::MissingLocalStateFile,
    )),
    CookieSourceKind::MozillaSqlite => {
      crate::browser::mozilla::firefox_based(request.path, request.domains)
    }
    CookieSourceKind::SafariBinaryCookies => Err(unsupported_target(source)),
    CookieSourceKind::InternetExplorerEse => {
      crate::browser::internet_explorer::internet_explorer_based(
        request.path,
        request.domains,
        false,
      )
    }
  }
}

pub(super) fn chromium_cookies_from_path(request: ChromiumPathRequest) -> Result<Vec<Cookie>> {
  match chromium_from_path(request, ChromiumProjection::Legacy)? {
    ChromiumProjectionResult::Legacy(cookies) => Ok(cookies),
    ChromiumProjectionResult::Detailed(_) => {
      unreachable!("legacy request returned detailed cookies")
    }
  }
}

pub(super) fn chromium_cookies_from_path_detailed(
  request: ChromiumPathRequest,
) -> Result<Vec<DetailedCookie>> {
  match chromium_from_path(request, ChromiumProjection::Detailed)? {
    ChromiumProjectionResult::Detailed(cookies) => Ok(cookies),
    ChromiumProjectionResult::Legacy(_) => {
      unreachable!("detailed request returned legacy cookies")
    }
  }
}

#[derive(Clone, Copy)]
enum ChromiumProjection {
  Legacy,
  Detailed,
}

enum ChromiumProjectionResult {
  Legacy(Vec<Cookie>),
  Detailed(Vec<DetailedCookie>),
}

enum PreparedCredentials {
  PlaintextOnly,
  KeyOutcomes(ChromiumKeyOutcomes),
}

fn chromium_from_path(
  request: ChromiumPathRequest,
  projection: ChromiumProjection,
) -> Result<ChromiumProjectionResult> {
  let shutdown_allowed =
    request.locked_database_policy == ChromiumLockedDatabasePolicy::AllowProcessShutdown;
  let classification_was_locked = match super::classify_cookie_source(&request.path)
    .and_then(|source| super::require_chromium_source(&request.path, source))
  {
    Ok(()) => false,
    Err(error)
      if shutdown_allowed
        && error
          .downcast_ref::<crate::browser::chromium_database_acquisition::WindowsDatabaseLocked>()
          .is_some() =>
    {
      true
    }
    Err(error) => return Err(error),
  };

  // Caller-directed credential I/O must finish before the explicitly
  // authorized recovery policy is allowed to affect another process.
  let credentials = prepare_credentials(request.credentials)?;
  if !classification_was_locked {
    return query_prepared(
      credentials,
      request.path,
      request.domains,
      projection,
      shutdown_allowed,
    );
  }

  let original_path = request.path;
  let domains = request.domains;
  crate::browser::chromium_database_acquisition::with_force_kill_recovery(
    &original_path,
    true,
    |acquired_path| {
      let source = classify_cookie_source_without_platform_recovery(acquired_path)
        .map_err(|error| super::invalid_source_error(&original_path, error))?;
      super::require_chromium_source(&original_path, source)?;
      query_prepared_without_platform_recovery(
        &credentials,
        acquired_path.to_path_buf(),
        domains.as_deref(),
        projection,
      )
    },
  )
}

fn prepare_credentials(source: ChromiumCredentialSource) -> Result<PreparedCredentials> {
  match source {
    ChromiumCredentialSource::Automatic => Err(invalid_options(
      InvalidDirectPathOptionsReason::MissingLocalStateFile,
    )),
    ChromiumCredentialSource::PlaintextOnly => Ok(PreparedCredentials::PlaintextOnly),
    ChromiumCredentialSource::BrowserId(browser_id) if browser_id.is_empty() => Err(
      invalid_options(InvalidDirectPathOptionsReason::EmptyBrowserId),
    ),
    ChromiumCredentialSource::BrowserId(_) => Err(invalid_options(
      InvalidDirectPathOptionsReason::BrowserIdNotSupportedOnTarget,
    )),
    ChromiumCredentialSource::LocalStateFile(local_state) => Ok(PreparedCredentials::KeyOutcomes(
      local_state_outcomes(&local_state)?,
    )),
  }
}

fn query_prepared(
  credentials: PreparedCredentials,
  path: PathBuf,
  domains: Option<Vec<String>>,
  projection: ChromiumProjection,
  force_kill: bool,
) -> Result<ChromiumProjectionResult> {
  match (credentials, projection) {
    (PreparedCredentials::PlaintextOnly, ChromiumProjection::Legacy) => {
      crate::browser::chromium::chromium_based_plaintext_only(path, domains, force_kill)
        .map(ChromiumProjectionResult::Legacy)
    }
    (PreparedCredentials::PlaintextOnly, ChromiumProjection::Detailed) => {
      crate::browser::chromium::chromium_based_detailed_plaintext_only(path, domains, force_kill)
        .map(ChromiumProjectionResult::Detailed)
    }
    (PreparedCredentials::KeyOutcomes(outcomes), ChromiumProjection::Legacy) => {
      crate::browser::chromium::query_cookies_with_key_outcomes(outcomes, path, domains, force_kill)
        .map(ChromiumProjectionResult::Legacy)
    }
    (PreparedCredentials::KeyOutcomes(outcomes), ChromiumProjection::Detailed) => {
      crate::browser::chromium::query_detailed_cookies_with_key_outcomes(
        outcomes, path, domains, force_kill,
      )
      .map(ChromiumProjectionResult::Detailed)
    }
  }
}

fn query_prepared_without_platform_recovery(
  credentials: &PreparedCredentials,
  path: PathBuf,
  domains: Option<&[String]>,
  projection: ChromiumProjection,
) -> Result<ChromiumProjectionResult> {
  match (credentials, projection) {
    (PreparedCredentials::PlaintextOnly, ChromiumProjection::Legacy) => {
      crate::browser::chromium::query_cookies_plaintext_without_platform_recovery(path, domains)
        .map(ChromiumProjectionResult::Legacy)
    }
    (PreparedCredentials::PlaintextOnly, ChromiumProjection::Detailed) => {
      crate::browser::chromium::query_detailed_cookies_plaintext_without_platform_recovery(
        path, domains,
      )
      .map(ChromiumProjectionResult::Detailed)
    }
    (PreparedCredentials::KeyOutcomes(outcomes), ChromiumProjection::Legacy) => {
      crate::browser::chromium::query_cookies_with_key_outcomes_without_platform_recovery(
        outcomes, path, domains,
      )
      .map(ChromiumProjectionResult::Legacy)
    }
    (PreparedCredentials::KeyOutcomes(outcomes), ChromiumProjection::Detailed) => {
      crate::browser::chromium::query_detailed_cookies_with_key_outcomes_without_platform_recovery(
        outcomes, path, domains,
      )
      .map(ChromiumProjectionResult::Detailed)
    }
  }
}

fn local_state_outcomes(
  path: &Path,
) -> Result<crate::browser::chromium_crypto::ChromiumKeyOutcomes> {
  if path.as_os_str().is_empty() {
    return Err(invalid_options(
      InvalidDirectPathOptionsReason::MissingLocalStateFile,
    ));
  }
  let contents = std::fs::read_to_string(path)
    .with_context(|| format!("failed to read Chromium Local State {}", path.display()))?;
  let parsed: serde_json::Value = serde_json::from_str(&contents)
    .with_context(|| format!("failed to parse Chromium Local State {}", path.display()))?;
  let credentials = ChromiumKeyCredentials::default();
  let mut session = HostKeySession::new();
  Ok(session.retrieve(ChromiumKeyRequest::for_parsed_local_state(
    &credentials,
    &parsed,
  )))
}

#[cfg(test)]
mod process_lock_tests {
  use super::*;
  use std::fs::OpenOptions;
  use std::os::windows::fs::OpenOptionsExt;
  use std::process::{Child, Command, Stdio};
  use std::time::{Duration, Instant};

  const CHILD_PATH_ENV: &str = "ROOKIE_DIRECT_PATH_LOCK_CHILD";
  const CHILD_READY_ENV: &str = "ROOKIE_DIRECT_PATH_LOCK_READY";
  const CHILD_TEST_NAME: &str =
    "direct_path::windows::process_lock_tests::hold_database_open_without_sharing";

  #[test]
  fn hold_database_open_without_sharing() {
    let Some(path) = std::env::var_os(CHILD_PATH_ENV) else {
      return;
    };
    let ready = std::env::var_os(CHILD_READY_ENV).expect("lock helper ready path");
    let _handle = OpenOptions::new()
      .read(true)
      .write(true)
      .share_mode(0)
      .open(PathBuf::from(path))
      .expect("open child fixture without sharing");
    std::fs::write(ready, b"ready").expect("signal exclusive handle is ready");
    std::thread::sleep(Duration::from_secs(300));
  }

  struct ChildGuard(Child);

  impl Drop for ChildGuard {
    fn drop(&mut self) {
      if self.0.try_wait().ok().flatten().is_none() {
        let _ = self.0.kill();
      }
      let _ = self.0.wait();
    }
  }

  fn spawn_lock_holder(path: &Path, ready: &Path) -> ChildGuard {
    let child = Command::new(std::env::current_exe().expect("current test executable"))
      .args(["--exact", CHILD_TEST_NAME, "--nocapture"])
      .env(CHILD_PATH_ENV, path)
      .env(CHILD_READY_ENV, ready)
      .stdin(Stdio::null())
      .stdout(Stdio::null())
      .stderr(Stdio::null())
      .spawn()
      .expect("spawn exclusive-handle helper");
    let mut child = ChildGuard(child);
    let deadline = Instant::now() + Duration::from_secs(15);
    while !ready.exists() {
      if let Some(status) = child.0.try_wait().expect("poll lock helper") {
        panic!("exclusive-handle helper exited before readiness: {status}");
      }
      assert!(
        Instant::now() < deadline,
        "exclusive-handle helper did not become ready"
      );
      std::thread::sleep(Duration::from_millis(25));
    }
    child
  }

  fn wait_for_recovery(child: &mut ChildGuard) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
      if child.0.try_wait().expect("poll recovered child").is_some() {
        return;
      }
      assert!(
        Instant::now() < deadline,
        "authorized recovery did not release the database handle"
      );
      std::thread::sleep(Duration::from_millis(25));
    }
  }

  fn plaintext_database() -> (crate::utils::TempDir, PathBuf) {
    let directory = crate::utils::TempDir::new().expect("temporary database directory");
    let path = directory.path().join("Cookies");
    let connection = rusqlite::Connection::open(&path).expect("create Chromium fixture");
    connection
      .execute_batch(
        "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT); \
         INSERT INTO meta (key, value) VALUES ('version', '23'); \
         CREATE TABLE cookies (\
           host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER, \
           name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER, \
           samesite INTEGER\
         ); \
         INSERT INTO cookies VALUES (\
           'example.test', '/', 0, 0, 'plain', 'value', X'', 0, 0\
         );",
      )
      .expect("seed Chromium fixture");
    drop(connection);
    (directory, path)
  }

  #[test]
  fn public_chromium_projections_honor_explicit_locked_database_policy() {
    let (_directory, path) = plaintext_database();
    for detailed in [false, true] {
      let ready = path.with_extension(if detailed {
        "detailed-ready"
      } else {
        "legacy-ready"
      });
      let mut child = spawn_lock_holder(&path, &ready);
      let request = ChromiumPathRequest::new(&path)
        .credentials(ChromiumCredentialSource::PlaintextOnly)
        .locked_database_policy(ChromiumLockedDatabasePolicy::AllowProcessShutdown);
      if detailed {
        let cookies = crate::direct_path::chromium_cookies_from_path_detailed(request)
          .expect("detailed request recovers the explicitly authorized database");
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].cookie.name, "plain");
      } else {
        let cookies = crate::direct_path::chromium_cookies_from_path(request)
          .expect("legacy request recovers the explicitly authorized database");
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].name, "plain");
      }
      wait_for_recovery(&mut child);
    }
  }

  #[test]
  fn invalid_request_does_not_apply_locked_database_policy() {
    let (_directory, path) = plaintext_database();
    let ready = path.with_extension("invalid-ready");
    let mut child = spawn_lock_holder(&path, &ready);
    let error = crate::direct_path::chromium_cookies_from_path(
      ChromiumPathRequest::new(&path)
        .locked_database_policy(ChromiumLockedDatabasePolicy::AllowProcessShutdown),
    )
    .expect_err("Windows automatic credentials require an explicit Local State file");
    assert_eq!(
      error
        .downcast_ref::<crate::direct_path::DirectPathError>()
        .and_then(crate::direct_path::DirectPathError::invalid_options_reason),
      Some(&InvalidDirectPathOptionsReason::MissingLocalStateFile)
    );
    assert!(
      child
        .0
        .try_wait()
        .expect("poll invalid-request child")
        .is_none(),
      "an invalid request must not affect the process holding the database"
    );
  }
}
