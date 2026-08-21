use super::*;
use crate::utils::TempDir;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn chromium_database(rows: &[(&str, &str, &[u8])]) -> (TempDir, PathBuf) {
  let directory = TempDir::new().unwrap();
  let path = directory.path().join("Cookies");
  let connection = rusqlite::Connection::open(&path).unwrap();
  connection
    .execute_batch(
      "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT); \
       INSERT INTO meta (key, value) VALUES ('version', '23'); \
       CREATE TABLE cookies (\
         host_key TEXT, path TEXT, is_secure INTEGER, expires_utc INTEGER, \
         name TEXT, value TEXT, encrypted_value BLOB, is_httponly INTEGER, \
         samesite INTEGER\
       );",
    )
    .unwrap();
  for (host, value, encrypted) in rows {
    connection
      .execute(
        "INSERT INTO cookies VALUES (?1, '/', 0, 0, 'session', ?2, ?3, 0, 0)",
        rusqlite::params![host, value, encrypted],
      )
      .unwrap();
  }
  drop(connection);
  (directory, path)
}

fn mozilla_database() -> (TempDir, PathBuf) {
  let directory = TempDir::new().unwrap();
  let path = directory.path().join("cookies.sqlite");
  let connection = rusqlite::Connection::open(&path).unwrap();
  connection
    .execute_batch(
      "CREATE TABLE moz_cookies (
         host TEXT NOT NULL, path TEXT NOT NULL, isSecure INTEGER NOT NULL,
         expiry INTEGER NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
         isHttpOnly INTEGER NOT NULL, sameSite INTEGER NOT NULL
       );
       INSERT INTO moz_cookies VALUES
         ('.example.test', '/', 1, 0, 'portable', 'mozilla', 1, 0);",
    )
    .unwrap();
  drop(connection);
  (directory, path)
}

fn direct_path_error(error: &anyhow::Error) -> &DirectPathError {
  error
    .downcast_ref::<DirectPathError>()
    .expect("typed DirectPathError in anyhow chain")
}

/// Reads the typed source error a public job edge returns.
///
/// The internal `*_inner` seams still produce an `anyhow` chain, so tests
/// that assert a *cause* is preserved use `direct_path_error` against those;
/// tests that assert the public contract use this.
fn source_error(error: &crate::Error) -> &DirectPathError {
  match error {
    crate::Error::Source(source) => source,
    other => panic!("expected Error::Source, got {other:?}"),
  }
}

#[test]
fn flattened_credential_selectors_have_one_core_precedence_rule() {
  assert_eq!(
    ChromiumCredentialSource::from_selectors(Some("chrome".into()), None, false),
    Ok(Some(ChromiumCredentialSource::BrowserId("chrome".into())))
  );
  assert_eq!(
    ChromiumCredentialSource::from_selectors(None, Some(PathBuf::from("Local State")), false,),
    Ok(Some(ChromiumCredentialSource::LocalStateFile(
      PathBuf::from("Local State")
    )))
  );
  assert_eq!(
    ChromiumCredentialSource::from_selectors(None, None, true),
    Ok(Some(ChromiumCredentialSource::PlaintextOnly))
  );
  assert_eq!(
    ChromiumCredentialSource::from_selectors(None, None, false),
    Ok(None)
  );
  assert_eq!(
    ChromiumCredentialSource::from_selectors(
      Some("chrome".into()),
      Some(PathBuf::from("Local State")),
      true,
    ),
    Err(RequestError::ConflictingCredentialSelectors)
  );
}

#[test]
fn invalid_source_is_typed_without_discarding_io_error() {
  let directory = TempDir::new().unwrap();
  let missing = directory
    .path()
    .join("absolute path sentinel with spaces")
    .join("missing");
  // The inner seam, so the assertion below can prove the `io::Error` cause
  // survives classification. The public edge deliberately drops the chain.
  let error = extract_from_path_inner(PathExtractRequest::sniff(&missing)).unwrap_err();
  let typed = direct_path_error(&error);
  assert_eq!(typed.kind(), "invalid_source");
  assert_eq!(typed.code(), "not_a_regular_file");
  assert_eq!(typed.path(), Some(missing.as_path()));
  assert_eq!(
    typed.invalid_source_reason(),
    Some(&InvalidCookieSourceReason::NotARegularFile)
  );
  assert!(error.downcast_ref::<std::io::Error>().is_some());
  let diagnostic = format!("{error:#}");
  assert!(!diagnostic.contains(missing.to_string_lossy().as_ref()));
  assert!(diagnostic.contains(crate::common::diagnostic::REDACTED_PATH));
  assert!(!format!("{typed:?}").contains(missing.to_string_lossy().as_ref()));
}

#[test]
fn operational_sqlite_failures_have_an_inspection_code_and_keep_the_cause() {
  let directory = TempDir::new().unwrap();
  let path = directory.path().join("corrupt.sqlite");
  std::fs::write(&path, b"SQLite format 3\0corrupt fixture").unwrap();

  let error = extract_from_path_inner(PathExtractRequest::sniff(&path)).unwrap_err();
  let typed = direct_path_error(&error);
  assert_eq!(typed.kind(), "invalid_source");
  assert_eq!(typed.code(), "source_inspection_failed");
  assert_eq!(typed.path(), Some(path.as_path()));
  assert_eq!(
    typed.invalid_source_reason(),
    Some(&InvalidCookieSourceReason::SourceInspectionFailed)
  );
  assert!(
    error
      .downcast_ref::<crate::common::sqlite::BrowserDatabaseFailure>()
      .is_some(),
    "the SQLite acquisition/query cause remains downcastable: {error:#}"
  );

  let public_error = extract_from_path(PathExtractRequest::sniff(&path)).unwrap_err();
  assert!(
    matches!(public_error, crate::Error::Engine(_)),
    "an operational inspection failure is an engine fault: {public_error:?}"
  );
  assert_eq!(public_error.code(), "source_inspection_failed");
  assert_eq!(public_error.fault_kind(), crate::FaultKind::Engine);
}

#[test]
fn explicit_chromium_rejects_a_recognized_mozilla_source_before_options() {
  let (_directory, path) = mozilla_database();
  let request = PathExtractRequest::with_credentials(
    &path,
    Some(ChromiumCredentialSource::BrowserId(String::new())),
  )
  .locked_database_policy(ChromiumLockedDatabasePolicy::AllowProcessShutdown);
  let error = extract_from_path(request).unwrap_err();
  let typed = source_error(&error);
  assert_eq!(typed.code(), "expected_chromium_sqlite");
  assert_eq!(typed.source_kind(), Some(CookieSourceKind::MozillaSqlite));
  assert_eq!(typed.target_os(), None);
}

/// The 0.6.0 sniff rule, in both directions.
///
/// A sniffed Chromium database is plaintext-capable only. On Unix that is a
/// narrowing -- `cookies_from_path` used to probe every registry identity
/// and could decrypt. On Windows it is a widening -- that call returned
/// `missing_local_state_file` before attempting extraction, so even a fully
/// plaintext database failed. Both halves are the same rule.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[test]
fn sniffing_a_plaintext_chromium_database_succeeds_on_every_target() {
  let (_directory, path) = chromium_database(&[("wanted.test", "plaintext", b"")]);
  let cookies =
    extract_from_path(PathExtractRequest::sniff(path)).expect("a plaintext sniff must succeed");
  assert_eq!(cookies.len(), 1);
  assert_eq!(cookies[0].value, "plaintext");
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[test]
fn sniffing_an_encrypted_chromium_database_is_missing_chromium_credentials() {
  let (_directory, path) = chromium_database(&[("wanted.test", "", b"v10encrypted")]);
  let error =
    extract_from_path(PathExtractRequest::sniff(path)).expect_err("no credentials were named");
  assert_eq!(
    source_error(&error).invalid_options_reason(),
    Some(&InvalidDirectPathOptionsReason::MissingChromiumCredentials),
    "a sniffed Chromium database must not guess which browser wrote it"
  );
  assert_eq!(error.code(), "missing_chromium_credentials");
}

#[test]
fn mozilla_direct_path_is_available_on_every_compile_target() {
  let (_directory, path) = mozilla_database();
  let cookies = extract_from_path(PathExtractRequest::sniff(path)).unwrap();
  assert_eq!(cookies.len(), 1);
  assert_eq!(cookies[0].name, "portable");
  assert_eq!(cookies[0].value, "mozilla");
}

#[test]
fn direct_path_request_zero_timeout_stops_a_real_extraction() {
  let (_directory, path) = mozilla_database();
  let error = extract_from_path(PathExtractRequest::sniff(path).timeout(std::time::Duration::ZERO))
    .expect_err("a zero timeout must stop before reading the real database");
  assert_eq!(error.stop_reason(), Some(crate::StopReason::TimedOut));
  // A timeout checked during source classification still gets wrapped in a
  // `DirectPathError` (inspection failed, for whichever reason); the job edge
  // must classify the stop first and not read that wrapping as caller input.
  assert!(matches!(error, crate::Error::Stopped(_)));
}

#[test]
fn direct_path_request_cancelled_handle_stops_a_real_extraction() {
  let (_directory, path) = mozilla_database();
  let handle = crate::CancellationHandle::new();
  handle.cancel();
  let error = extract_from_path(PathExtractRequest::sniff(path).cancellation(handle))
    .expect_err("a pre-cancelled handle must stop before reading the real database");
  assert_eq!(error.stop_reason(), Some(crate::StopReason::Cancelled));
}

#[test]
fn direct_path_request_with_a_generous_timeout_still_succeeds() {
  let (_directory, path) = mozilla_database();
  let cookies =
    extract_from_path(PathExtractRequest::sniff(path).timeout(std::time::Duration::from_secs(30)))
      .expect("a generous explicit timeout must not interfere with a real extraction");
  assert_eq!(cookies.len(), 1);
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[test]
fn plaintext_only_rejects_any_encrypted_row_before_domain_projection() {
  let (_directory, path) = chromium_database(&[
    ("wanted.test", "plaintext", b""),
    ("outside.test", "", b"v10encrypted"),
  ]);
  let error = extract_from_path(
    PathExtractRequest::plaintext(path).domains(Some(vec!["wanted.test".to_owned()])),
  )
  .expect_err("plaintext-only is a whole-request guarantee");
  assert!(error.to_string().contains("no browser key identity"));
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[test]
fn plaintext_only_checks_encryption_before_malformed_row_projection() {
  let (_directory, path) = chromium_database(&[("wanted.test", "plaintext", b"")]);
  let connection = rusqlite::Connection::open(&path).unwrap();
  connection
    .execute(
      "INSERT INTO cookies VALUES (X'FF', '/', 0, 0, 'hidden', '', \
       X'763130656e63727970746564', 0, 0)",
      [],
    )
    .unwrap();
  drop(connection);

  for detailed in [false, true] {
    let request =
      PathExtractRequest::plaintext(&path).domains(Some(vec!["wanted.test".to_owned()]));
    let message = if detailed {
      detailed_from_path_inner(request)
        .expect_err("detailed plaintext-only request must not skip an encrypted malformed row")
        .to_string()
    } else {
      extract_from_path_inner(request)
        .expect_err("flat plaintext-only request must not skip an encrypted malformed row")
        .to_string()
    };
    assert!(message.contains("no browser key identity"));
  }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[test]
fn plaintext_only_supports_legacy_and_detailed_projection() {
  let (_directory, path) = chromium_database(&[("example.test", "value", b"")]);
  let cookies = extract_from_path(PathExtractRequest::plaintext(&path)).unwrap();
  let detailed = detailed_from_path_inner(PathExtractRequest::plaintext(&path)).unwrap();
  assert_eq!(cookies.len(), 1);
  assert_eq!(detailed.len(), 1);
  assert_eq!(cookies[0].name, detailed[0].cookie.name);
  assert_eq!(cookies[0].value, detailed[0].cookie.value);
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[test]
fn chromium_path_request_zero_timeout_stops_a_real_extraction() {
  let (_directory, path) = chromium_database(&[("example.test", "value", b"")]);
  let request = PathExtractRequest::plaintext(&path).timeout(std::time::Duration::ZERO);
  let error = extract_from_path(request)
    .expect_err("a zero timeout must stop before reading the real database");
  assert_eq!(error.stop_reason(), Some(crate::StopReason::TimedOut));
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[test]
fn chromium_path_request_cancelled_handle_stops_a_real_extraction() {
  let (_directory, path) = chromium_database(&[("example.test", "value", b"")]);
  let handle = crate::CancellationHandle::new();
  handle.cancel();
  let request = PathExtractRequest::plaintext(&path).cancellation(handle);
  let error = extract_from_path(request)
    .expect_err("a pre-cancelled handle must stop before reading the real database");
  assert_eq!(error.stop_reason(), Some(crate::StopReason::Cancelled));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn automatic_selection_preserves_identity_order_ties_and_one_session() {
  #[derive(Debug)]
  struct Candidate {
    identity: &'static str,
    cookies: usize,
    rows_skipped: usize,
  }

  let identities = [
    (
      "first",
      crate::browser::chromium_platform_keys::ChromiumKeyIdentity::default(),
    ),
    (
      "second",
      crate::browser::chromium_platform_keys::ChromiumKeyIdentity::default(),
    ),
    (
      "third",
      crate::browser::chromium_platform_keys::ChromiumKeyIdentity::default(),
    ),
  ];
  let sessions = std::cell::Cell::new(0);
  let mut probed = Vec::new();
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  let selected = automatic_chromium_with(
    &identities,
    PathBuf::from("unused"),
    None,
    &runtime,
    || {
      sessions.set(sessions.get() + 1);
    },
    |(), name, _credentials, _path, _domains| {
      probed.push(name);
      Ok(Candidate {
        identity: name,
        cookies: if name == "first" { 1 } else { 2 },
        rows_skipped: 0,
      })
    },
    |candidate| (candidate.cookies, candidate.rows_skipped),
    |candidate| Ok(candidate.identity),
  )
  .unwrap();

  #[cfg(target_os = "linux")]
  assert_eq!(
    platform::AUTOMATIC_BROWSER_IDS,
    ["chrome", "brave", "chromium", "edge", "opera", "vivaldi"]
  );
  #[cfg(target_os = "macos")]
  assert_eq!(
    platform::AUTOMATIC_BROWSER_IDS,
    ["chrome", "brave", "chromium", "edge", "opera", "vivaldi", "arc", "opera_gx",]
  );
  assert_eq!(selected, "second", "an exact tie keeps the earlier ID");
  assert_eq!(probed, vec!["first", "second", "third"]);
  assert_eq!(sessions.get(), 1);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn automatic_selection_preserves_a_completed_candidate_through_later_stops() {
  #[derive(Debug)]
  struct Candidate(&'static str);

  let identities = [
    (
      "first",
      crate::browser::chromium_platform_keys::ChromiumKeyIdentity::default(),
    ),
    (
      "second",
      crate::browser::chromium_platform_keys::ChromiumKeyIdentity::default(),
    ),
  ];
  let clock = crate::common::deadline::test_clock::ManualClock::default();
  let stop = crate::common::deadline::CancellationToken::default();
  let runtime = crate::common::deadline::BoundaryRuntime::with_stop(
    &clock,
    crate::common::deadline::Deadline::after(&clock, std::time::Duration::from_secs(1)),
    stop.clone(),
  );
  let mut probes = Vec::new();

  let selected = automatic_chromium_with(
    &identities,
    PathBuf::from("unused"),
    None,
    &runtime,
    || (),
    |(), name, _credentials, _path, _domains| {
      probes.push(name);
      if name == "first" {
        stop.cancel();
        Ok(Candidate(name))
      } else {
        runtime.check()?;
        unreachable!("the stopped second probe cannot produce a candidate")
      }
    },
    |_| (1, 0),
    |candidate| {
      assert_eq!(
        runtime.check(),
        Err(crate::common::deadline::BoundaryStop::Cancelled),
        "finish observes the racing stop without discarding the committed candidate"
      );
      Ok(candidate.0)
    },
  )
  .expect("completed candidate survives leading, post-loop, and finish stop checks");

  assert_eq!(selected, "first");
  assert_eq!(probes, vec!["first", "second"]);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn automatic_selection_preserves_all_failures_and_one_session_per_projection() {
  let identities = [
    (
      "chrome",
      crate::browser::chromium_platform_keys::ChromiumKeyIdentity::default(),
    ),
    (
      "brave",
      crate::browser::chromium_platform_keys::ChromiumKeyIdentity::default(),
    ),
  ];
  let sessions = std::cell::Cell::new(0);
  let clock = crate::common::deadline::SystemClock;
  let runtime = crate::common::deadline::BoundaryRuntime::standard(&clock);
  for projection in ["legacy", "detailed"] {
    let error = automatic_chromium_with(
      &identities,
      PathBuf::from("unused"),
      None,
      &runtime,
      || sessions.set(sessions.get() + 1),
      |(), name, _credentials, _path, _domains| -> Result<()> {
        anyhow::bail!("{projection} {name} keyring is locked")
      },
      |()| (0, 0),
      |()| Ok(()),
    )
    .unwrap_err();
    let diagnostic = error.to_string();
    assert!(
      diagnostic.contains(&format!("chrome: {projection} chrome keyring is locked")),
      "{diagnostic}"
    );
    assert!(
      diagnostic.contains(&format!("brave: {projection} brave keyring is locked")),
      "{diagnostic}"
    );
  }
  assert_eq!(
    sessions.get(),
    2,
    "one fresh session per projection request"
  );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn browser_id_validation_is_typed_and_precedes_key_access() {
  let (_directory, path) = chromium_database(&[]);
  for (browser_id, expected) in [
    ("", InvalidDirectPathOptionsReason::EmptyBrowserId),
    (
      "not-a-browser",
      InvalidDirectPathOptionsReason::UnknownBrowserId,
    ),
    (
      "firefox",
      InvalidDirectPathOptionsReason::BrowserIdIsNotChromium,
    ),
  ] {
    let error = extract_from_path(PathExtractRequest::with_credentials(
      &path,
      Some(ChromiumCredentialSource::BrowserId(browser_id.to_owned())),
    ))
    .unwrap_err();
    assert_eq!(
      source_error(&error).invalid_options_reason(),
      Some(&expected)
    );
  }
}

// Deliberately not platform-gated: all three leaves share
// `sniffed_chromium_error`, so all three must agree that a failure
// credentials cannot fix keeps its own cause.
#[test]
fn a_sniffed_chromium_failure_credentials_cannot_fix_is_not_missing_credentials() {
  // A sniffed Chromium database is attempted plaintext-only, and every
  // failure of that attempt used to be relabelled `missing_chromium_
  // credentials`. This database classifies as Chromium and then fails for a
  // reason no credential can repair, so the relabel would be wrong advice.
  let directory = TempDir::new().unwrap();
  let path = directory.path().join("Cookies");
  let connection = rusqlite::Connection::open(&path).unwrap();
  connection
    .execute_batch(
      "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT); \
       INSERT INTO meta (key, value) VALUES ('version', '23'); \
       CREATE TABLE cookies (host_key TEXT);",
    )
    .unwrap();
  drop(connection);

  let error = extract_from_path(PathExtractRequest::sniff(&path)).unwrap_err();
  let mislabelled = matches!(&error, crate::Error::Source(source)
    if source.invalid_options_reason()
      == Some(&InvalidDirectPathOptionsReason::MissingChromiumCredentials));
  assert!(
    !mislabelled,
    "a schema failure is an engine fault, not a missing credential: {error:#}"
  );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn unsupported_native_chromium_options_fail_before_credential_io() {
  let (_directory, path) = chromium_database(&[]);
  let local_state = PathBuf::from("this path must never be read");
  let local_state_error = extract_from_path(PathExtractRequest::with_credentials(
    &path,
    Some(ChromiumCredentialSource::LocalStateFile(
      local_state.clone(),
    )),
  ))
  .unwrap_err();
  assert_eq!(
    source_error(&local_state_error).invalid_options_reason(),
    Some(&InvalidDirectPathOptionsReason::LocalStateNotSupportedOnTarget)
  );

  let detailed_local_state_error = detailed_from_path_inner(PathExtractRequest::with_credentials(
    &path,
    Some(ChromiumCredentialSource::LocalStateFile(local_state)),
  ))
  .unwrap_err();
  assert_eq!(
    direct_path_error(&detailed_local_state_error).invalid_options_reason(),
    Some(&InvalidDirectPathOptionsReason::LocalStateNotSupportedOnTarget)
  );

  let shutdown_error = extract_from_path(
    PathExtractRequest::with_credentials(
      path,
      Some(ChromiumCredentialSource::BrowserId("chrome".to_owned())),
    )
    .locked_database_policy(ChromiumLockedDatabasePolicy::AllowProcessShutdown),
  )
  .unwrap_err();
  assert_eq!(
    source_error(&shutdown_error).invalid_options_reason(),
    Some(&InvalidDirectPathOptionsReason::ProcessShutdownNotSupportedOnTarget)
  );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_chromium_options_keep_the_explicit_credential_contract() {
  let (_directory, path) = chromium_database(&[]);

  // Sniffing a plaintext Chromium database on Windows is `Ok` as of 0.6.0.
  // `cookies_from_path` used to return `MissingLocalStateFile` for
  // `ChromiumSqlite` *before* attempting extraction, so even a fully
  // plaintext database failed on Windows while succeeding on Unix. Only a
  // row that is actually encrypted needs credentials now, which is what
  // makes the two platforms agree.
  let (_plain_directory, plain_path) = chromium_database(&[("example.test", "plaintext", b"")]);
  let sniffed = extract_from_path(PathExtractRequest::sniff(&plain_path))
    .expect("a plaintext Chromium database needs no credentials on Windows either");
  assert_eq!(sniffed[0].value, "plaintext");

  // The other half of the same rule: an encrypted row is the only thing that
  // actually demands credentials, and it says so precisely.
  let (_encrypted_directory, encrypted_path) =
    chromium_database(&[("example.test", "", b"v10encrypted")]);
  let encrypted_error = extract_from_path(PathExtractRequest::sniff(&encrypted_path)).unwrap_err();
  assert_eq!(
    source_error(&encrypted_error).invalid_options_reason(),
    Some(&InvalidDirectPathOptionsReason::MissingChromiumCredentials)
  );

  // An explicitly empty Local State selector stays a request fault: the
  // caller named a credential source and left it blank, which is a mistake
  // they can fix, not an absent selector.
  let error = extract_from_path(PathExtractRequest::with_credentials(
    &path,
    Some(ChromiumCredentialSource::LocalStateFile(PathBuf::new())),
  ))
  .unwrap_err();
  assert_eq!(
    source_error(&error).invalid_options_reason(),
    Some(&InvalidDirectPathOptionsReason::MissingLocalStateFile)
  );

  for (browser_id, expected) in [
    ("", InvalidDirectPathOptionsReason::EmptyBrowserId),
    (
      "chrome",
      InvalidDirectPathOptionsReason::BrowserIdNotSupportedOnTarget,
    ),
  ] {
    let error = extract_from_path(PathExtractRequest::with_credentials(
      &path,
      Some(ChromiumCredentialSource::BrowserId(browser_id.to_owned())),
    ))
    .unwrap_err();
    assert_eq!(
      source_error(&error).invalid_options_reason(),
      Some(&expected)
    );
  }

  let cookies = extract_from_path(
    PathExtractRequest::plaintext(path)
      .locked_database_policy(ChromiumLockedDatabasePolicy::AllowProcessShutdown),
  )
  .unwrap();
  assert!(cookies.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn browser_without_target_credentials_reads_plaintext_but_rejects_encrypted_rows() {
  let (_plain_directory, plain_path) = chromium_database(&[("example.test", "plaintext", b"")]);
  let cookies = extract_from_path(PathExtractRequest::with_credentials(
    &plain_path,
    Some(ChromiumCredentialSource::BrowserId("coccoc".to_owned())),
  ))
  .unwrap();
  assert_eq!(cookies[0].value, "plaintext");
  let detailed = detailed_from_path_inner(PathExtractRequest::with_credentials(
    plain_path,
    Some(ChromiumCredentialSource::BrowserId("coccoc".to_owned())),
  ))
  .unwrap();
  assert_eq!(detailed[0].cookie.value, "plaintext");

  let (_encrypted_directory, encrypted_path) =
    chromium_database(&[("example.test", "", b"v10encrypted")]);
  let error = extract_from_path(PathExtractRequest::with_credentials(
    &encrypted_path,
    Some(ChromiumCredentialSource::BrowserId("coccoc".to_owned())),
  ))
  .unwrap_err();
  let diagnostic = format!("{error:#}");
  assert!(diagnostic.contains("has no"), "{diagnostic}");
  assert!(diagnostic.contains("identity"), "{diagnostic}");
  let detailed_error = detailed_from_path_inner(PathExtractRequest::with_credentials(
    encrypted_path,
    Some(ChromiumCredentialSource::BrowserId("coccoc".to_owned())),
  ))
  .unwrap_err();
  let detailed_diagnostic = format!("{detailed_error:#}");
  assert!(
    detailed_diagnostic.contains("has no"),
    "{detailed_diagnostic}"
  );
  assert!(
    detailed_diagnostic.contains("identity"),
    "{detailed_diagnostic}"
  );
}

#[cfg(target_os = "macos")]
#[test]
fn a_recognized_safari_signature_dispatches_past_classification_on_macos() {
  let safari_directory = TempDir::new().unwrap();
  let safari_path = safari_directory.path().join("Cookies.binarycookies");
  std::fs::write(&safari_path, b"cookfixture-not-a-real-binarycookies-file").unwrap();
  let safari_error = extract_from_path(PathExtractRequest::sniff(&safari_path)).unwrap_err();
  assert!(
    !matches!(safari_error, crate::Error::Source(_)),
    "a recognized Safari signature must reach the real parser, not stay a classification error: {safari_error:#}"
  );
}

#[test]
fn unsupported_target_accessors_are_stable() {
  let error = DirectPathError::UnsupportedTarget {
    source: CookieSourceKind::SafariBinaryCookies,
    target_os: "freebsd",
    target_arch: "x86_64",
  };
  assert_eq!(error.kind(), "unsupported_target");
  assert_eq!(error.code(), "unsupported_target");
  assert_eq!(
    error.source_kind(),
    Some(CookieSourceKind::SafariBinaryCookies)
  );
  assert_eq!(error.target_os(), Some("freebsd"));
  assert_eq!(error.target_arch(), Some("x86_64"));
  assert_eq!(error.path(), None);
  assert_eq!(error.invalid_source_reason(), None);
  assert_eq!(
    error.to_string(),
    "safari_binary_cookies extraction is unsupported on freebsd/x86_64"
  );
  assert_eq!(
    format!("{error:?}"),
    "UnsupportedTarget { source: SafariBinaryCookies, target_os: \"freebsd\", target_arch: \"x86_64\" }"
  );
}

#[test]
fn invalid_options_accessors_are_stable() {
  let error = DirectPathError::InvalidOptions {
    source: CookieSourceKind::ChromiumSqlite,
    reason: InvalidDirectPathOptionsReason::UnknownBrowserId,
  };
  assert_eq!(error.kind(), "invalid_options");
  assert_eq!(error.code(), "unknown_browser_id");
  assert_eq!(error.path(), None);
  assert_eq!(error.source_kind(), Some(CookieSourceKind::ChromiumSqlite));
  assert_eq!(error.target_os(), None);
  assert_eq!(error.target_arch(), None);
  assert_eq!(error.invalid_source_reason(), None);
  assert_eq!(
    error.invalid_options_reason(),
    Some(&InvalidDirectPathOptionsReason::UnknownBrowserId)
  );
  assert_eq!(
    error.to_string(),
    "invalid options for chromium_sqlite: unknown_browser_id"
  );
  assert_eq!(
    format!("{error:?}"),
    "InvalidOptions { source: ChromiumSqlite, reason: UnknownBrowserId }"
  );
}

#[test]
fn cookie_source_kind_display_covers_every_variant() {
  for (source, expected) in [
    (CookieSourceKind::ChromiumSqlite, "chromium_sqlite"),
    (CookieSourceKind::MozillaSqlite, "mozilla_sqlite"),
    (
      CookieSourceKind::SafariBinaryCookies,
      "safari_binary_cookies",
    ),
    (
      CookieSourceKind::InternetExplorerEse,
      "internet_explorer_ese",
    ),
  ] {
    assert_eq!(source.to_string(), expected);
  }
}

#[test]
fn invalid_cookie_source_reason_codes_cover_every_variant() {
  for (reason, expected) in [
    (
      InvalidCookieSourceReason::NotARegularFile,
      "not_a_regular_file",
    ),
    (
      InvalidCookieSourceReason::SourceInspectionFailed,
      "source_inspection_failed",
    ),
    (
      InvalidCookieSourceReason::UnrecognizedSignature,
      "unrecognized_signature",
    ),
    (
      InvalidCookieSourceReason::UnsupportedSqliteSchema,
      "unsupported_sqlite_schema",
    ),
    (
      InvalidCookieSourceReason::AmbiguousSqliteSchema,
      "ambiguous_sqlite_schema",
    ),
    (
      InvalidCookieSourceReason::ExpectedChromiumSqlite {
        actual: CookieSourceKind::MozillaSqlite,
      },
      "expected_chromium_sqlite",
    ),
  ] {
    assert_eq!(reason.code(), expected);
  }
}

#[test]
fn invalid_direct_path_options_reason_codes_cover_every_variant() {
  for (reason, expected) in [
    (
      InvalidDirectPathOptionsReason::EmptyBrowserId,
      "empty_browser_id",
    ),
    (
      InvalidDirectPathOptionsReason::MissingLocalStateFile,
      "missing_local_state_file",
    ),
    (
      InvalidDirectPathOptionsReason::BrowserIdNotSupportedOnTarget,
      "browser_id_not_supported_on_target",
    ),
    (
      InvalidDirectPathOptionsReason::LocalStateNotSupportedOnTarget,
      "local_state_not_supported_on_target",
    ),
    (
      InvalidDirectPathOptionsReason::ProcessShutdownNotSupportedOnTarget,
      "process_shutdown_not_supported_on_target",
    ),
    (
      InvalidDirectPathOptionsReason::UnknownBrowserId,
      "unknown_browser_id",
    ),
    (
      InvalidDirectPathOptionsReason::BrowserIdIsNotChromium,
      "browser_id_is_not_chromium",
    ),
  ] {
    assert_eq!(reason.code(), expected);
  }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn safari_signature_returns_typed_unsupported_before_parser_io() {
  let directory = TempDir::new().unwrap();
  let path = directory.path().join("Cookies.binarycookies");
  std::fs::write(&path, b"cookfixture").unwrap();
  let error = extract_from_path(PathExtractRequest::sniff(path)).unwrap_err();
  assert!(matches!(
    source_error(&error),
    DirectPathError::UnsupportedTarget {
      source: CookieSourceKind::SafariBinaryCookies,
      ..
    }
  ));
}

#[cfg(not(target_os = "windows"))]
#[test]
fn ie_signature_returns_typed_unsupported_before_parser_io() {
  let directory = TempDir::new().unwrap();
  let path = directory.path().join("WebCacheV01.dat");
  std::fs::write(&path, [0, 0, 0, 0, 0xef, 0xcd, 0xab, 0x89]).unwrap();
  let error = extract_from_path(PathExtractRequest::sniff(path)).unwrap_err();
  assert!(matches!(
    source_error(&error),
    DirectPathError::UnsupportedTarget {
      source: CookieSourceKind::InternetExplorerEse,
      ..
    }
  ));
}

#[cfg(not(target_os = "windows"))]
#[test]
fn legacy_classifier_keeps_ie_magic_unrecognized_off_windows() {
  let directory = TempDir::new().unwrap();
  let path = directory.path().join("WebCacheV01.dat");
  std::fs::write(&path, [0, 0, 0, 0, 0xef, 0xcd, 0xab, 0x89]).unwrap();
  let error = classify_cookie_source_legacy(&path).unwrap_err();
  assert_eq!(
    error.to_string(),
    "unsupported cookie source format: <path>"
  );
}

#[test]
fn legacy_classifier_keeps_the_historical_unknown_format_message() {
  let directory = TempDir::new().unwrap();
  let path = directory.path().join("unknown.cookies");
  std::fs::write(&path, b"not a cookie store").unwrap();
  let error = classify_cookie_source_legacy(&path).unwrap_err();
  assert_eq!(
    error.to_string(),
    "unsupported cookie source format: <path>"
  );
}
