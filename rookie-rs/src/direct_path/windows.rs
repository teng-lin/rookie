use super::{
  invalid_options, shared, unsupported_target, ChromiumCredentialSource,
  ChromiumLockedDatabasePolicy, CookieSourceKind, InvalidDirectPathOptionsReason,
  PathExtractRequest,
};
use crate::browser::chromium_crypto::ChromiumKeyOutcomes;
use crate::browser::chromium_platform_keys::{
  ChromiumKeyIdentity, ChromiumKeyRequest, HostKeySession,
};
use crate::common::deadline::BoundaryRuntime;
use crate::enums::DetailedCookie;
use anyhow::Result;
use std::path::{Path, PathBuf};

pub(super) fn classify_cookie_source(
  path: &Path,
  runtime: &BoundaryRuntime<'_>,
) -> Result<CookieSourceKind> {
  classify_cookie_source_with_runtime(
    path,
    runtime,
    |source, runtime| {
      crate::browser::chromium_database_acquisition::with_non_disruptive_recovery(
        source,
        runtime,
        shared::classify_sqlite_with_runtime,
      )
    },
    shared::read_header_with_runtime,
  )
}

fn classify_cookie_source_without_platform_recovery(
  path: &Path,
  runtime: &BoundaryRuntime<'_>,
) -> Result<CookieSourceKind> {
  classify_cookie_source_with_runtime(
    path,
    runtime,
    shared::classify_sqlite_with_runtime,
    shared::read_header_with_runtime,
  )
}

fn classify_cookie_source_with_runtime<Recover, ReadHeader>(
  path: &Path,
  runtime: &BoundaryRuntime<'_>,
  mut recover: Recover,
  mut read_header: ReadHeader,
) -> Result<CookieSourceKind>
where
  Recover: FnMut(&Path, &BoundaryRuntime<'_>) -> Result<CookieSourceKind>,
  ReadHeader: FnMut(&Path, &BoundaryRuntime<'_>) -> Result<Vec<u8>>,
{
  runtime.check()?;
  let sqlite_result = recover(path, runtime);
  runtime.check()?;
  if let Ok(source) = sqlite_result {
    return Ok(source);
  }
  let sqlite_error = sqlite_result.expect_err("successful classification returned above");
  runtime.check()?;
  let header_result = read_header(path, runtime);
  runtime.check()?;
  let header = match header_result {
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
  runtime.check()?;
  let classified = shared::classify_header(&header);
  runtime.check()?;
  match classified? {
    Some(source) => Ok(source),
    None => Err(sqlite_error),
  }
}

#[cfg(test)]
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

  fn read_header(path: &Path) -> Result<Vec<u8>> {
    let clock = crate::common::deadline::SystemClock;
    let runtime = BoundaryRuntime::standard(&clock);
    shared::read_header_with_runtime(path, &runtime)
  }

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
      read_header,
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

/// Reads an encrypted Chromium database using a caller-supplied `Local State`
/// file.
///
/// This constructor is Windows-only, and it lives in this platform leaf
/// because `check-cfg-locations` pins `direct_path/mod.rs` to its current
/// platform-`cfg` count. It is also the honest home for a value that means
/// nothing on Unix.
pub(super) fn windows_local_state(
  path: impl Into<PathBuf>,
  local_state: impl Into<PathBuf>,
) -> PathExtractRequest {
  PathExtractRequest::with_credentials(
    path,
    Some(ChromiumCredentialSource::LocalStateFile(local_state.into())),
  )
}

pub(super) fn detailed_from_path(
  request: PathExtractRequest,
  source: CookieSourceKind,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<DetailedCookie>> {
  if request.target.credentials.is_some() {
    return chromium_from_path_detailed(request, runtime);
  }
  let PathExtractRequest {
    target, domains, ..
  } = request;
  match source {
    // A sniffed Chromium database on Windows is now attempted rather than
    // rejected outright: `cookies_from_path` used to return
    // `missing_local_state_file` before extraction, so even a fully plaintext
    // database failed. Under the 0.6.0 rule a plaintext one succeeds, and an
    // encrypted one is `missing_chromium_credentials`.
    CookieSourceKind::ChromiumSqlite => {
      crate::browser::chromium_projection::chromium_based_detailed_plaintext_only_with_runtime(
        target.path,
        domains,
        false,
        runtime,
      )
      .map_err(super::sniffed_chromium_error)
    }
    CookieSourceKind::MozillaSqlite => {
      crate::browser::mozilla::firefox_based_detailed_with_runtime(target.path, domains, runtime)
    }
    CookieSourceKind::SafariBinaryCookies => Err(unsupported_target(source)),
    CookieSourceKind::InternetExplorerEse => {
      crate::browser::internet_explorer::internet_explorer_based_detailed_with_runtime(
        target.path,
        domains,
        false,
        runtime,
      )
    }
  }
}

pub(super) fn chromium_from_path_detailed(
  request: PathExtractRequest,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<DetailedCookie>> {
  chromium_from_path(request, runtime)
}

enum PreparedCredentials {
  PlaintextOnly,
  KeyOutcomes(ChromiumKeyOutcomes),
}

fn chromium_from_path(
  request: PathExtractRequest,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<DetailedCookie>> {
  let PathExtractRequest {
    target: request,
    domains,
    ..
  } = request;
  let credentials = request
    .credentials
    .ok_or_else(|| invalid_options(InvalidDirectPathOptionsReason::MissingChromiumCredentials))?;
  let shutdown_allowed =
    request.locked_database_policy == ChromiumLockedDatabasePolicy::AllowProcessShutdown;
  let classification_was_locked = match super::classify_cookie_source(&request.path, runtime)
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
  let credentials = prepare_credentials(credentials, runtime)?;
  if !classification_was_locked {
    return query_prepared(
      credentials,
      request.path,
      domains,
      shutdown_allowed,
      runtime,
    );
  }

  let original_path = request.path;
  crate::browser::chromium_database_acquisition::with_force_kill_recovery(
    &original_path,
    true,
    runtime,
    |acquired_path, runtime| {
      let source = classify_cookie_source_without_platform_recovery(acquired_path, runtime)
        .map_err(|error| super::invalid_source_error(&original_path, error))?;
      super::require_chromium_source(&original_path, source)?;
      query_prepared_without_platform_recovery(
        &credentials,
        acquired_path.to_path_buf(),
        domains.as_deref(),
        runtime,
      )
    },
  )
}

fn prepare_credentials(
  source: ChromiumCredentialSource,
  runtime: &BoundaryRuntime<'_>,
) -> Result<PreparedCredentials> {
  runtime.check()?;
  match source {
    ChromiumCredentialSource::PlaintextOnly => Ok(PreparedCredentials::PlaintextOnly),
    ChromiumCredentialSource::BrowserId(browser_id) if browser_id.is_empty() => Err(
      invalid_options(InvalidDirectPathOptionsReason::EmptyBrowserId),
    ),
    ChromiumCredentialSource::BrowserId(_) => Err(invalid_options(
      InvalidDirectPathOptionsReason::BrowserIdNotSupportedOnTarget,
    )),
    ChromiumCredentialSource::LocalStateFile(local_state) => Ok(PreparedCredentials::KeyOutcomes(
      local_state_outcomes(&local_state, runtime)?,
    )),
  }
}

fn query_prepared(
  credentials: PreparedCredentials,
  path: PathBuf,
  domains: Option<Vec<String>>,
  force_kill: bool,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<DetailedCookie>> {
  match credentials {
    PreparedCredentials::PlaintextOnly => {
      crate::browser::chromium_projection::chromium_based_detailed_plaintext_only_with_runtime(
        path, domains, force_kill, runtime,
      )
    }
    PreparedCredentials::KeyOutcomes(outcomes) => {
      crate::browser::chromium_projection::extract_detailed_cookies_with_key_outcomes_runtime(
        outcomes, path, domains, force_kill, runtime,
      )
    }
  }
}

fn query_prepared_without_platform_recovery(
  credentials: &PreparedCredentials,
  path: PathBuf,
  domains: Option<&[String]>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<DetailedCookie>> {
  match credentials {
    PreparedCredentials::PlaintextOnly => {
      crate::browser::chromium_projection::extract_detailed_cookies_plaintext_without_platform_recovery(
        path, domains, runtime,
      )
    }
    PreparedCredentials::KeyOutcomes(outcomes) => {
      crate::browser::chromium_projection::extract_detailed_cookies_with_key_outcomes_without_platform_recovery(
        outcomes, path, domains, runtime,
      )
    }
  }
}

fn local_state_outcomes(
  path: &Path,
  runtime: &BoundaryRuntime<'_>,
) -> Result<crate::browser::chromium_crypto::ChromiumKeyOutcomes> {
  if path.as_os_str().is_empty() {
    return Err(invalid_options(
      InvalidDirectPathOptionsReason::MissingLocalStateFile,
    ));
  }
  let credentials = ChromiumKeyIdentity::default();
  let mut session = HostKeySession::new();
  Ok(session.retrieve(
    ChromiumKeyRequest::for_local_state_file(&credentials, path),
    runtime,
  ))
}

#[cfg(test)]
mod process_lock_tests {
  use super::*;
  use std::os::windows::process::CommandExt;
  use std::process::{Child, Command, Stdio};
  use std::time::{Duration, Instant};
  use windows::Win32::System::Threading::CREATE_NEW_CONSOLE;

  const CHILD_PATH_ENV: &str = "ROOKIE_DIRECT_PATH_LOCK_CHILD";
  const CHILD_READY_ENV: &str = "ROOKIE_DIRECT_PATH_LOCK_READY";

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
    let script = r#"
$ErrorActionPreference = 'Stop'
$handle = [System.IO.File]::Open(
  $env:ROOKIE_DIRECT_PATH_LOCK_CHILD,
  [System.IO.FileMode]::Open,
  [System.IO.FileAccess]::ReadWrite,
  [System.IO.FileShare]::None
)
[System.IO.File]::WriteAllText($env:ROOKIE_DIRECT_PATH_LOCK_READY, 'ready')
Start-Sleep -Seconds 300
"#;
    let child = Command::new("powershell.exe")
      .args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
      ])
      .env(CHILD_PATH_ENV, path)
      .env(CHILD_READY_ENV, ready)
      .stdin(Stdio::null())
      .stdout(Stdio::null())
      .stderr(Stdio::null())
      .creation_flags(CREATE_NEW_CONSOLE.0)
      .spawn()
      .expect("spawn exclusive-handle helper");
    let mut child = ChildGuard(child);
    let deadline = Instant::now() + Duration::from_secs(60);
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
    let deadline = Instant::now() + Duration::from_secs(60);
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
    let wal_path = crate::common::sqlite::sidecar(&path, "-wal");
    let mut connection = rusqlite::Connection::open(&path).expect("create Chromium fixture");
    connection
      .execute_batch(
        "PRAGMA journal_mode = WAL; \
         CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT); \
         INSERT INTO meta (key, value) VALUES ('version', '23'); \
         CREATE TABLE cookies (\
           host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER, \
           name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER, \
           samesite INTEGER\
         );",
      )
      .expect("seed Chromium fixture schema");
    let tx = connection.transaction().expect("begin WAL transaction");
    tx.execute(
      "INSERT INTO cookies VALUES (\
         'example.test', '/', 0, 0, 'plain', 'value', X'', 0, 0\
       );",
      [],
    )
    .expect("insert cookie in WAL");
    tx.commit().expect("commit WAL transaction");
    let wal_bytes = std::fs::read(&wal_path).unwrap_or_default();
    drop(connection);
    if !wal_bytes.is_empty() {
      let _ = std::fs::write(&wal_path, &wal_bytes);
    }
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
      let request =
        PathExtractRequest::with_credentials(&path, Some(ChromiumCredentialSource::PlaintextOnly))
          .locked_database_policy(ChromiumLockedDatabasePolicy::AllowProcessShutdown);
      if detailed {
        let cookies = crate::direct_path::detailed_from_path_inner(request)
          .expect("detailed request recovers the explicitly authorized database");
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].cookie.name, "plain");
      } else {
        let cookies = crate::direct_path::extract_from_path(request)
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
    // A *sniffed* request is no longer invalid on Windows -- as of 0.6.0 a
    // plaintext database reads without credentials there, same as on Unix --
    // so proving this needs a request that is genuinely malformed. An
    // explicitly empty Local State path is: the caller named a credential
    // source and left it blank. `chromium_from_path` classifies before it
    // validates credentials, so this pins the ordering its own comment
    // claims: caller-directed credential I/O must finish before an authorized
    // recovery policy is allowed to touch another process.
    let error = crate::direct_path::extract_from_path(
      PathExtractRequest::with_credentials(
        &path,
        Some(ChromiumCredentialSource::LocalStateFile(PathBuf::new())),
      )
      .locked_database_policy(ChromiumLockedDatabasePolicy::AllowProcessShutdown),
    )
    .expect_err("an empty Local State selector is a request fault");
    // `extract_from_path` returns the typed `Error` now, so the fault is a
    // variant to match rather than an `anyhow` payload to downcast.
    let crate::Error::Source(typed) = &error else {
      panic!("an invalid path request is Error::Source, got {error:?}");
    };
    assert_eq!(
      typed.invalid_options_reason(),
      Some(&InvalidDirectPathOptionsReason::MissingLocalStateFile),
      "credential validation must run before recovery, got {error:#}"
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

  /// Fails unless the lock helper is still running, i.e. recovery left the
  /// process holding the database untouched.
  fn assert_holder_still_running(child: &mut ChildGuard, context: &str) {
    assert!(
      child.0.try_wait().expect("poll lock holder").is_none(),
      "{context}",
    );
  }

  /// The mirror of
  /// `public_chromium_projections_honor_explicit_locked_database_policy`.
  ///
  /// That test proves `AllowProcessShutdown` terminates the process holding a
  /// locked database. This one pins the property that *defines* the default
  /// `NonDisruptive` policy: it never does. The database is genuinely locked --
  /// the helper holds an exclusive `FileShare::None` handle -- so the default
  /// path must either recover it out of band through a shadow copy or degrade
  /// to an error, but in neither case may it shut the holder down.
  ///
  /// The shadow copy's own raw NTFS read is admin-gated, so its *success*
  /// cannot be exercised on an unprivileged host; that half is asserted by the
  /// elevated, `#[ignore]`d canary below. Holder survival, by contrast, holds
  /// regardless of elevation, which is why this always-on test guards it -- and
  /// on an unprivileged host it additionally proves the recovery degrades to an
  /// error rather than silently returning no cookies.
  #[test]
  fn nondisruptive_default_never_terminates_a_locked_database_holder() {
    let (_directory, path) = plaintext_database();
    let ready = path.with_extension("nondisruptive-ready");
    let mut child = spawn_lock_holder(&path, &ready);

    // Default policy is NonDisruptive; plaintext credentials keep the read off
    // the key path so the outcome turns only on database acquisition.
    let request =
      PathExtractRequest::with_credentials(&path, Some(ChromiumCredentialSource::PlaintextOnly));
    let elevated = privilege::user::privileged();
    let result = crate::direct_path::extract_from_path(request);

    assert_holder_still_running(
      &mut child,
      "NonDisruptive recovery must never terminate the process holding the database",
    );

    if elevated {
      // Where the raw NTFS copy can run, a successful recovery must return the
      // seeded cookie rather than a silent empty read. The elevated canary
      // asserts recovery unconditionally; here we only tighten the Ok case,
      // since a raw copy can still be refused for environment reasons.
      if let Ok(cookies) = &result {
        assert_eq!(cookies.len(), 1, "recovery must return the seeded cookie");
        assert_eq!(cookies[0].name, "plain");
      }
    } else {
      // The raw copy is admin-gated, so an unprivileged host cannot recover a
      // locked database and must report that rather than silently succeed.
      assert!(
        result.is_err(),
        "NonDisruptive on a locked database without elevation must fail rather \
         than silently return cookies (got {} cookies)",
        result.as_ref().map(|cookies| cookies.len()).unwrap_or(0),
      );
    }
  }

  /// The real-mechanism companion to
  /// `nondisruptive_default_never_terminates_a_locked_database_holder`.
  ///
  /// The always-on test above can only prove the holder survives, because the
  /// shadow copy's raw NTFS read is refused without administrator rights and so
  /// cannot run on an ordinary CI host. This asserts the half that needs
  /// elevation: that the default `NonDisruptive` policy actually *recovers* a
  /// locked database out of band -- reading the seeded cookie from a shadow
  /// copy while the exclusive handle is still held -- and still leaves the
  /// holder running. It is `#[ignore]`d so it runs only where a caller has
  /// opted into an elevated lane (the Windows locked-database job in
  /// `e2e.yml`); the privilege assertion turns a non-elevated invocation into a
  /// clear failure rather than a false pass.
  #[test]
  #[ignore]
  fn recovers_a_locked_database_via_nondisruptive_shadow_copy() {
    assert!(
      privilege::user::privileged(),
      "this canary requires an elevated process; the shadow copy's raw NTFS \
       read cannot run without administrator rights",
    );

    let (_directory, path) = plaintext_database();
    let ready = path.with_extension("shadow-copy-ready");
    let mut child = spawn_lock_holder(&path, &ready);

    // Default policy is NonDisruptive: recovery must go through the shadow copy
    // rather than terminating the holder.
    let request =
      PathExtractRequest::with_credentials(&path, Some(ChromiumCredentialSource::PlaintextOnly));
    let cookies = crate::direct_path::extract_from_path(request)
      .expect("NonDisruptive recovery reads the locked database via its shadow copy");

    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "plain");

    assert_holder_still_running(
      &mut child,
      "shadow-copy recovery must leave the holder running -- that is what makes \
       it non-disruptive",
    );
  }
}
