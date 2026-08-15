use super::{CookieSourceKind, InvalidCookieSourceReason};
use anyhow::{anyhow, Context, Result};
use std::io::Read;
use std::path::Path;

#[derive(Debug)]
struct SourceClassificationContext {
  reason: InvalidCookieSourceReason,
  message: String,
}

impl std::fmt::Display for SourceClassificationContext {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str(&self.message)
  }
}

impl std::error::Error for SourceClassificationContext {}

fn classify_error(
  reason: InvalidCookieSourceReason,
  error: impl Into<anyhow::Error>,
) -> anyhow::Error {
  let error = error.into();
  let message = error.to_string();
  error.context(SourceClassificationContext { reason, message })
}

pub(super) fn classification_reason(error: &anyhow::Error) -> Option<InvalidCookieSourceReason> {
  error
    .downcast_ref::<SourceClassificationContext>()
    .map(|context| context.reason.clone())
}

fn validate_regular_file(path: &Path) -> Result<()> {
  let metadata = match std::fs::metadata(path) {
    Ok(metadata) => metadata,
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      return Err(classify_error(
        InvalidCookieSourceReason::NotARegularFile,
        anyhow::Error::from(error)
          .context(format!("can't inspect cookie source {}", path.display())),
      ));
    }
    Err(error) => {
      return Err(
        anyhow::Error::from(error)
          .context(format!("can't inspect cookie source {}", path.display())),
      );
    }
  };
  if !metadata.is_file() {
    return Err(classify_error(
      InvalidCookieSourceReason::NotARegularFile,
      anyhow!("cookie source is not a file: {}", path.display()),
    ));
  }
  Ok(())
}

pub(super) fn read_header(path: &Path) -> Result<Vec<u8>> {
  validate_regular_file(path)?;
  let file = std::fs::File::open(path)
    .with_context(|| format!("can't open cookie source {}", path.display()))?;
  let mut header = Vec::with_capacity(16);
  file
    .take(16)
    .read_to_end(&mut header)
    .with_context(|| format!("can't read cookie source header {}", path.display()))?;
  Ok(header)
}

pub(super) fn classify_header(header: &[u8]) -> Result<Option<CookieSourceKind>> {
  if header.starts_with(b"SQLite format 3\0") {
    return Ok(None);
  }
  if header.starts_with(b"cook") {
    return Ok(Some(CookieSourceKind::SafariBinaryCookies));
  }
  if header.get(4..8) == Some(&[0xef, 0xcd, 0xab, 0x89]) {
    return Ok(Some(CookieSourceKind::InternetExplorerEse));
  }
  Err(classify_error(
    InvalidCookieSourceReason::UnrecognizedSignature,
    anyhow!("unsupported cookie source signature"),
  ))
}

pub(super) fn classify_sqlite(path: &Path) -> Result<CookieSourceKind> {
  let source = crate::common::sqlite::with_browser_database(path.to_path_buf(), |connection| {
    let table_exists = |name: &str| -> rusqlite::Result<bool> {
      connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
        [name],
        |row| row.get(0),
      )
    };
    Ok((table_exists("cookies")?, table_exists("moz_cookies")?))
  })?
  .into_value();

  match source {
    (true, false) => Ok(CookieSourceKind::ChromiumSqlite),
    (false, true) => Ok(CookieSourceKind::MozillaSqlite),
    (true, true) => Err(classify_error(
      InvalidCookieSourceReason::AmbiguousSqliteSchema,
      anyhow!(
        "ambiguous SQLite cookie database: both `cookies` and `moz_cookies` tables are present"
      ),
    )),
    (false, false) => Err(classify_error(
      InvalidCookieSourceReason::UnsupportedSqliteSchema,
      anyhow!(
        "unsupported SQLite database: expected a Chromium `cookies` or Mozilla `moz_cookies` table"
      ),
    )),
  }
}

#[cfg_attr(target_os = "windows", allow(dead_code))]
pub(super) fn classify_path(path: &Path) -> Result<CookieSourceKind> {
  let header = read_header(path)?;
  match classify_header(&header)? {
    Some(source) => Ok(source),
    None => classify_sqlite(path),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::utils::TempDir;

  #[test]
  fn signature_classifier_is_target_independent() {
    assert_eq!(
      classify_header(b"cookfixture").unwrap(),
      Some(CookieSourceKind::SafariBinaryCookies)
    );
    assert_eq!(
      classify_header(&[0, 0, 0, 0, 0xef, 0xcd, 0xab, 0x89]).unwrap(),
      Some(CookieSourceKind::InternetExplorerEse)
    );
    assert_eq!(classify_header(b"SQLite format 3\0").unwrap(), None);
  }

  #[test]
  fn sqlite_classifier_rejects_ambiguous_schema_with_stable_reason() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("cookies.sqlite");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
      .execute("CREATE TABLE cookies (id INTEGER)", [])
      .unwrap();
    connection
      .execute("CREATE TABLE moz_cookies (id INTEGER)", [])
      .unwrap();
    drop(connection);

    let error = classify_path(&path).unwrap_err();
    assert_eq!(
      classification_reason(&error),
      Some(InvalidCookieSourceReason::AmbiguousSqliteSchema)
    );
  }
}
