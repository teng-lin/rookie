#![allow(deprecated)]

use rookie_cookies::direct_path::{
  extract_from_path, ChromiumLockedDatabasePolicy, CookieSourceKind, PathExtractRequest,
};
use std::path::{Path, PathBuf};

fn unique_directory() -> PathBuf {
  let path = std::env::temp_dir().join(format!(
    "rookie-direct-path-consumer-{}",
    std::process::id()
  ));
  let _ = std::fs::remove_dir_all(&path);
  std::fs::create_dir_all(&path).expect("create consumer fixture directory");
  path
}

fn chromium_database(directory: &Path) -> PathBuf {
  let path = directory.join("Cookies");
  let connection = rusqlite::Connection::open(&path).expect("create Chromium fixture");
  connection
    .execute("CREATE TABLE cookies (name TEXT)", [])
    .expect("create Chromium marker table");
  path
}

fn mozilla_database(directory: &Path) -> PathBuf {
  let path = directory.join("cookies.sqlite");
  let connection = rusqlite::Connection::open(&path).expect("create Mozilla fixture");
  connection
    .execute_batch(
      "CREATE TABLE moz_cookies (
         host TEXT NOT NULL, path TEXT NOT NULL, isSecure INTEGER NOT NULL,
         expiry INTEGER NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
         isHttpOnly INTEGER NOT NULL, sameSite INTEGER NOT NULL
       );
       INSERT INTO moz_cookies VALUES
         ('.example.test', '/', 1, 0, 'freebsd', 'portable', 1, 0);",
    )
    .expect("seed Mozilla fixture");
  path
}

fn assert_unsupported(error: rookie_cookies::Error, source: CookieSourceKind) {
  let rookie_cookies::Error::Source(typed) = &error else {
    panic!("an unsupported target is Error::Source, got {error:?}");
  };
  assert_eq!(typed.kind(), "unsupported_target");
  assert_eq!(typed.code(), "unsupported_target");
  assert_eq!(typed.source_kind(), Some(source));
  assert_eq!(typed.target_os(), Some(std::env::consts::OS));
  assert_eq!(typed.target_arch(), Some(std::env::consts::ARCH));
  assert_eq!(typed.path(), None);
  assert_eq!(typed.invalid_source_reason(), None);
  assert_eq!(typed.invalid_options_reason(), None);
}

fn main() {
  assert!(rookie_cookies::config::try_get_browser_config("chrome").is_none());
  let opera_gx = rookie_cookies::opera_gx(None)
    .expect_err("the legacy Opera GX shim is explicit on unsupported targets");
  assert!(
    opera_gx
      .to_string()
      .contains(&format!("not supported on {}", std::env::consts::OS)),
    "{opera_gx:#}"
  );

  let directory = unique_directory();
  let chromium = chromium_database(&directory);
  let mozilla = mozilla_database(&directory);
  let safari = directory.join("Cookies.binarycookies");
  std::fs::write(&safari, b"cookfixture").expect("write Safari signature");
  let internet_explorer = directory.join("WebCacheV01.dat");
  std::fs::write(
    &internet_explorer,
    [0, 0, 0, 0, 0xef, 0xcd, 0xab, 0x89],
  )
  .expect("write ESE signature");

  assert_unsupported(
    extract_from_path(
      PathExtractRequest::sniff(&chromium).domains(Some(vec!["example.test".to_owned()])),
    )
    .expect_err("Chromium is unsupported on FreeBSD"),
    CookieSourceKind::ChromiumSqlite,
  );
  assert_unsupported(
    extract_from_path(PathExtractRequest::sniff(&safari))
      .expect_err("Safari is unsupported on FreeBSD"),
    CookieSourceKind::SafariBinaryCookies,
  );
  assert_unsupported(
    extract_from_path(PathExtractRequest::sniff(&internet_explorer))
      .expect_err("Internet Explorer is unsupported on FreeBSD"),
    CookieSourceKind::InternetExplorerEse,
  );

  let cookies = extract_from_path(PathExtractRequest::sniff(&mozilla))
    .expect("Mozilla direct-path extraction is portable");
  assert_eq!(cookies.len(), 1);
  assert_eq!(cookies[0].name, "freebsd");
  assert_eq!(cookies[0].value, "portable");

  // Target support still wins before Chromium option validation. The
  // credential-bearing constructors are platform-gated and cannot be named
  // here at all, which is the point: on a target with no Chromium capability
  // there is no valid credential strategy to ask for.
  assert_unsupported(
    extract_from_path(
      PathExtractRequest::plaintext(&chromium)
        .domains(Some(vec!["example.test".to_owned()]))
        .locked_database_policy(ChromiumLockedDatabasePolicy::AllowProcessShutdown),
    )
    .expect_err("target support wins before Chromium option validation"),
    CookieSourceKind::ChromiumSqlite,
  );
  assert_unsupported(
    extract_from_path(PathExtractRequest::sniff(chromium))
      .expect_err("a sniffed Chromium database is also all-target and typed"),
    CookieSourceKind::ChromiumSqlite,
  );
}
