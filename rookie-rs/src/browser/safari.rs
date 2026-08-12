use crate::common::{date, enums::*, sqlite, utils};
use anyhow::{anyhow, bail, Context, Result};
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use std::{
  fs::File,
  io::Read,
  path::{Path, PathBuf},
  time::SystemTime,
  vec::Vec,
};

/// `Cookies.binarycookies` is a per-user metadata store and is normally only a
/// few MiB. Keep a generous ceiling so a corrupt or replaced file cannot make
/// extraction consume unbounded memory.
const MAX_BINARY_COOKIES_FILE_SIZE: u64 = 64 * 1024 * 1024;

/// A malformed page can use nearly the entire file-size allowance for its
/// record-offset table. Stop recovery before millions of invalid offsets turn
/// a corrupt file into an unbounded CPU/logging workload.
const MAX_RECOVERABLE_RECORD_ERRORS_PER_PAGE: usize = 1024;
const MAX_LOGGED_RECORD_ERRORS_PER_PAGE: usize = 8;

/// 1. open cookies file
/// 2. parse headers
/// 3. parse pages (total from headers)
/// 4. get N cookies from each page, iterate
/// 5. parse each cookie
/// 6. add each cookie based on domain filter
pub fn safari_based(db_path: PathBuf, domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let mut file = File::open(&db_path).context(format!(
    "Failed to open {}\n\
      Make sure you have full disk access for the current process.\n\
      For example, in VSCode or Terminal:\n\
      1. Open Settings\n\
      2. Privacy & Security\n\
      3. Full Disk Access\n\
      ---\n\
      You can also open the disk access page with: \n\
      open \"x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles\"\n\
      ",
    db_path.display()
  ))?;
  let bs = read_stable_cookie_file(&mut file, &db_path)?;
  let cookies = parse_content(&bs)?;

  // Filter cookies by domain if domains are specified
  if let Some(domain_filters) = &domains {
    let filtered_cookies: Vec<Cookie> = cookies
      .into_iter()
      .filter(|cookie| utils::some_domain_in_host(Some(domain_filters), &cookie.domain))
      .collect();

    Ok(filtered_cookies)
  } else {
    Ok(cookies)
  }
}

const STABLE_READ_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileImageMetadata {
  len: u64,
  modified: Option<SystemTime>,
  #[cfg(unix)]
  device: u64,
  #[cfg(unix)]
  inode: u64,
}

fn image_metadata(file: &File, db_path: &Path) -> Result<FileImageMetadata> {
  file
    .metadata()
    .with_context(|| format!("Failed to inspect {}", db_path.display()))
    .map(file_image_metadata)
}

fn path_image_metadata(db_path: &Path) -> Result<FileImageMetadata> {
  std::fs::metadata(db_path)
    .with_context(|| format!("Failed to inspect Safari cookie path {}", db_path.display()))
    .map(file_image_metadata)
}

fn file_image_metadata(metadata: std::fs::Metadata) -> FileImageMetadata {
  #[cfg(unix)]
  use std::os::unix::fs::MetadataExt;
  FileImageMetadata {
    len: metadata.len(),
    modified: metadata.modified().ok(),
    #[cfg(unix)]
    device: metadata.dev(),
    #[cfg(unix)]
    inode: metadata.ino(),
  }
}

/// Reads a complete BinaryCookies image and verifies that the opened file was
/// not replaced or modified while its bytes were copied. Safari updates this
/// file atomically in practice, but a bounded retry prevents a half-old image
/// from silently becoming the extraction result when it does not.
fn read_stable_cookie_file(file: &mut File, db_path: &Path) -> Result<Vec<u8>> {
  read_stable_cookie_file_with(file, db_path, || {})
}

fn read_stable_cookie_file_with<F>(
  file: &mut File,
  db_path: &Path,
  mut after_read: F,
) -> Result<Vec<u8>>
where
  F: FnMut(),
{
  let mut last_change = None;
  for _ in 0..STABLE_READ_ATTEMPTS {
    let fd_before = image_metadata(file, db_path)?;
    let path_before = path_image_metadata(db_path)?;
    let bytes = read_cookie_file(file, db_path, fd_before.len)?;
    after_read();
    let fd_after = image_metadata(file, db_path)?;
    let path_after = path_image_metadata(db_path)?;
    // Comparing descriptor metadata alone misses an atomic rename: the old
    // descriptor stays unchanged while the configured path now names a new
    // image. Both snapshots must agree with each other and with the path.
    if fd_before == path_before
      && fd_after == path_after
      && fd_before == fd_after
      && path_before == path_after
    {
      return Ok(bytes);
    }
    last_change = Some((fd_before, path_before, fd_after, path_after));
    *file =
      File::open(db_path).with_context(|| format!("Failed to reopen {}", db_path.display()))?;
  }
  bail!(
    "Safari cookie file {} changed during each of {STABLE_READ_ATTEMPTS} acquisition attempts: {last_change:?}",
    db_path.display()
  )
}

fn read_cookie_file(file: &mut File, db_path: &Path, advertised_len: u64) -> Result<Vec<u8>> {
  if advertised_len > MAX_BINARY_COOKIES_FILE_SIZE {
    bail!(
      "Safari cookie file {} is too large: {advertised_len} bytes exceeds the {} byte limit",
      db_path.display(),
      MAX_BINARY_COOKIES_FILE_SIZE
    );
  }

  let initial_capacity = usize::try_from(advertised_len)
    .context("Safari cookie file size does not fit in memory address space")?;
  let mut bytes = Vec::new();
  bytes
    .try_reserve_exact(initial_capacity)
    .context("Failed to reserve memory for Safari cookie file")?;

  // `metadata` is only a snapshot. Limit the read as well in case the file is
  // replaced or grows between the size check and `read_to_end`.
  file
    .take(MAX_BINARY_COOKIES_FILE_SIZE + 1)
    .read_to_end(&mut bytes)
    .with_context(|| format!("Failed to read {}", db_path.display()))?;
  if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_BINARY_COOKIES_FILE_SIZE {
    bail!(
      "Safari cookie file {} grew beyond the {} byte limit while it was read",
      db_path.display(),
      MAX_BINARY_COOKIES_FILE_SIZE
    );
  }

  Ok(bytes)
}

/// Parse one page and retain any valid records. The optional error is the last
/// malformed record encountered and is promoted only if the whole file yields
/// no cookies.
fn parse_page(bs: &[u8]) -> Result<(Vec<Cookie>, Option<anyhow::Error>)> {
  if slice(bs, 0, 4)? != [0x00, 0x00, 0x01, 0x00] {
    bail!("bad page header");
  }

  let count = usize::try_from(slice(bs, 4, 4).map(LittleEndian::read_u32)?)
    .context("Safari page cookie count does not fit in memory address space")?;
  let parsed_table = parse_table::<LittleEndian>(&bs[8..], count)?;
  let trailer_offset = count
    .checked_mul(4)
    .and_then(|table_len| table_len.checked_add(8))
    .ok_or_else(|| anyhow!("Safari page trailer offset overflow"))?;
  if slice(bs, trailer_offset, 4)? != [0x00, 0x00, 0x00, 0x00] {
    bail!("bad page trailer");
  }

  let mut cookies: Vec<Cookie> = vec![];
  let mut last_error = None;
  let mut error_count = 0usize;
  for (index, raw_offset) in parsed_table.into_iter().enumerate() {
    let result = (|| {
      let offset = usize::try_from(raw_offset)
        .context("Safari cookie offset does not fit in memory address space")?;
      let length = usize::try_from(slice(bs, offset, 4).map(LittleEndian::read_u32)?)
        .context("Safari cookie length does not fit in memory address space")?;
      let record = slice(bs, offset, length)?;
      parse_cookie::<LittleEndian>(record)
    })()
    .with_context(|| format!("Failed to parse Safari cookie record {index}"));

    match result {
      Ok(cookie) => cookies.push(cookie),
      Err(error) => {
        error_count += 1;
        if error_count <= MAX_LOGGED_RECORD_ERRORS_PER_PAGE {
          log::warn!("Skipping malformed Safari cookie record {index}: {error:#}");
        } else if error_count == MAX_LOGGED_RECORD_ERRORS_PER_PAGE + 1 {
          log::warn!("Additional malformed Safari cookie records will be summarized for this page");
        }

        if error_count >= MAX_RECOVERABLE_RECORD_ERRORS_PER_PAGE {
          let error = error.context(format!(
            "Safari page recovery limit reached after {error_count} malformed records"
          ));
          log::warn!("Stopping malformed Safari page recovery: {error:#}");
          last_error = Some(error);
          break;
        }

        last_error = Some(error);
      }
    }
  }

  Ok((cookies, last_error))
}

fn parse_cookie<T: ByteOrder>(bs: &[u8]) -> Result<Cookie> {
  if bs.len() < 0x30 {
    bail!("cookie data underflow");
  }
  let flags = T::read_u32(&bs[0x08..0x0c]);

  let url_off = T::read_u32(&bs[0x10..0x14]) as usize;
  let name_off = T::read_u32(&bs[0x14..0x18]) as usize;
  let path_off = T::read_u32(&bs[0x18..0x1c]) as usize;
  let value_off = T::read_u32(&bs[0x1c..0x20]) as usize;

  // i/OS/X to Unix timestamp +(1 Jan 2001 epoch seconds).
  let expires = T::read_f64(&bs[0x28..0x30]);
  let expires = date::safari_timestamp(expires);

  let url = slice_to(bs, url_off, name_off).and_then(c_str)?;
  let name = slice_to(bs, name_off, path_off).and_then(c_str)?;
  let path = slice_to(bs, path_off, value_off).and_then(c_str)?;
  let value = slice_to(bs, value_off, bs.len()).and_then(c_str)?;

  let is_secure = (flags & 0x01) == 0x01;
  let is_http_only = (flags & 0x04) == 0x04;

  let cookie = Cookie {
    expires,
    domain: url,
    http_only: is_http_only,
    name,
    path,
    value,
    same_site: 0,
    secure: is_secure,
  };
  Ok(cookie)
}

fn parse_content(bs: &[u8]) -> Result<Vec<Cookie>> {
  // Magic bytes: "COOK" = 0x636F6F6B
  if slice(bs, 0, 4)? != [0x63, 0x6f, 0x6f, 0x6b] {
    bail!("not a cookie file");
  }

  let count = usize::try_from(slice(bs, 4, 4).map(BigEndian::read_u32)?)
    .context("Safari page count does not fit in memory address space")?;
  let page_lengths = parse_table::<BigEndian>(&bs[8..], count)?;
  let mut offset = count
    .checked_mul(4)
    .and_then(|table_len| table_len.checked_add(8))
    .ok_or_else(|| anyhow!("Safari page data offset overflow"))?;
  let mut cookies: Vec<Cookie> = vec![];
  let mut last_error = None;

  for (index, raw_length) in page_lengths.into_iter().enumerate() {
    let length = usize::try_from(raw_length)
      .context("Safari page length does not fit in memory address space")?;
    let next_offset = match offset.checked_add(length) {
      Some(next_offset) => next_offset,
      None => {
        let error = anyhow!("Safari page {index} end offset overflow");
        log::warn!("Skipping malformed Safari page {index}: {error:#}");
        last_error = Some(error);
        break;
      }
    };

    match slice(bs, offset, length)
      .with_context(|| format!("Failed to read Safari page {index}"))
      .and_then(parse_page)
    {
      Ok((page_cookies, page_error)) => {
        cookies.extend(page_cookies);
        if let Some(error) = page_error {
          last_error = Some(error);
        }
      }
      Err(error) => {
        log::warn!("Skipping malformed Safari page {index}: {error:#}");
        last_error = Some(error);
      }
    }
    offset = next_offset;
  }

  if cookies.is_empty() {
    if let Some(error) = last_error {
      return Err(error);
    }
  }

  Ok(cookies)
}

fn slice(bs: &[u8], off: usize, len: usize) -> Result<&[u8]> {
  let end = off
    .checked_add(len)
    .ok_or_else(|| anyhow!("data offset overflow: {off} + {len}"))?;
  bs.get(off..end)
    .ok_or_else(|| anyhow!("data underflow: range {off}..{end}, length {}", bs.len()))
}

fn parse_table<T: ByteOrder>(bs: &[u8], count: usize) -> Result<Vec<u32>> {
  let end = count
    .checked_mul(4)
    .ok_or_else(|| anyhow!("table length overflow: {count} * 4"))?;
  if end > bs.len() {
    bail!("table data underflow");
  }

  let mut data = Vec::new();
  data
    .try_reserve_exact(count)
    .context("Failed to reserve memory for Safari offset table")?;
  data.extend(bs[..end].chunks_exact(4).map(T::read_u32));
  Ok(data)
}

fn slice_to(bs: &[u8], off: usize, to: usize) -> Result<&[u8]> {
  if to < off {
    bail!("negative data length: -{}", off - to)
  } else {
    slice(bs, off, to - off)
  }
}

fn c_str(bs: &[u8]) -> Result<String> {
  bs.split_last()
    .ok_or_else(|| anyhow!("null c string"))
    .and_then(|(&last, elements)| {
      if last == 0x00 {
        Ok(elements)
      } else {
        bail!("c string non null terminator")
      }
    })
    .and_then(|elements| {
      String::from_utf8(elements.to_vec()).map_err(|err| anyhow!(err.to_string()))
    })
}

const SAFARI_TABS_RELATIVE_PATH: &str = "Safari/SafariTabs.db";
const SAFARI_PROFILE_SUBTYPE: i64 = 2;
const DEFAULT_PROFILE_SENTINEL: &str = "DefaultProfile";

/// Crate-private profile descriptor used by the later cross-browser report
/// adapter. It deliberately does not change the legacy `safari()` API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SafariProfile {
  pub(crate) name: String,
  pub(crate) uuid: Option<String>,
  pub(crate) cookie_candidates: Vec<PathBuf>,
}

#[allow(dead_code)] // consumed by the private cross-engine report in Milestone 4E
#[derive(Debug)]
pub(crate) struct SafariProfileExtraction {
  pub(crate) profile: SafariProfile,
  pub(crate) cookies: Vec<Cookie>,
  pub(crate) error: Option<String>,
}

#[allow(dead_code)] // consumed by the private cross-engine report in Milestone 4E
#[derive(Debug, Default)]
pub(crate) struct SafariExtractionOutcome {
  pub(crate) profiles: Vec<SafariProfileExtraction>,
  pub(crate) discovery_warning: Option<String>,
}

fn is_canonical_uuid(value: &str) -> bool {
  let bytes = value.as_bytes();
  bytes.len() == 36
    && [8, 13, 18, 23]
      .into_iter()
      .all(|index| bytes[index] == b'-')
    && bytes
      .iter()
      .enumerate()
      .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
}

fn profile_name(title: &str, uuid: &str) -> String {
  let cleaned = title
    .trim()
    .chars()
    .map(|character| match character {
      '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '\0'..='\u{1f}' => '_',
      character => character,
    })
    .collect::<String>();
  if cleaned.is_empty() {
    format!("profile-{}", uuid[..8].to_ascii_lowercase())
  } else {
    cleaned
  }
}

fn disambiguate_profile_names(profiles: &mut [SafariProfile]) {
  let mut used = std::collections::BTreeSet::new();
  for profile in profiles {
    let original = profile.name.clone();
    let mut candidate = original.clone();
    let mut suffix = 2usize;
    while used.contains(&candidate) {
      candidate = format!("{original}-{suffix}");
      suffix += 1;
    }
    used.insert(candidate.clone());
    profile.name = candidate;
  }
}

fn default_profile(library: &Path) -> SafariProfile {
  SafariProfile {
    name: "default".to_owned(),
    uuid: None,
    cookie_candidates: vec![
      library.join("Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies"),
      library.join("Cookies/Cookies.binarycookies"),
    ],
  }
}

fn named_profile(library: &Path, uuid: String, title: String) -> SafariProfile {
  let lower_uuid = uuid.to_ascii_lowercase();
  SafariProfile {
    name: profile_name(&title, &uuid),
    uuid: Some(uuid),
    cookie_candidates: vec![library.join(format!(
      "Containers/com.apple.Safari/Data/Library/WebKit/WebsiteDataStore/{lower_uuid}/Cookies/Cookies.binarycookies"
    ))],
  }
}

/// Returns a successful (including zero-row) profile DB result. The common
/// SQLite acquisition layer copies a live WAL pair, avoiding the silent
/// omission of recently-created profiles that immutable reads cause.
fn named_profiles_from_database(library: &Path) -> Result<Vec<(String, String)>> {
  let database = library
    .join("Containers/com.apple.Safari/Data/Library")
    .join(SAFARI_TABS_RELATIVE_PATH);
  sqlite::with_browser_database(database, |connection| {
    let mut statement = connection.prepare(
      "SELECT external_uuid, title FROM bookmarks \
       WHERE subtype = ?1 AND external_uuid != ?2 \
       ORDER BY external_uuid COLLATE BINARY, title COLLATE BINARY",
    )?;
    let mut rows = statement.query(rusqlite::params![
      SAFARI_PROFILE_SUBTYPE,
      DEFAULT_PROFILE_SENTINEL
    ])?;
    let mut profiles = Vec::new();
    while let Some(row) = rows.next()? {
      let uuid = row.get::<_, Option<String>>(0)?.unwrap_or_default();
      let title = row.get::<_, Option<String>>(1)?.unwrap_or_default();
      if is_canonical_uuid(&uuid) {
        profiles.push((uuid, title));
      } else if !uuid.is_empty() {
        log::warn!("Skipping Safari profile row with invalid external UUID {uuid:?}");
      }
    }
    Ok(profiles)
  })
  .map(|outcome| outcome.into_value())
}

fn named_profiles_from_directory(library: &Path) -> Vec<(String, String)> {
  let directory = library.join("Containers/com.apple.Safari/Data/Library/Safari/Profiles");
  let Ok(entries) = std::fs::read_dir(directory) else {
    return Vec::new();
  };
  let mut profiles = entries
    .filter_map(|entry| entry.ok())
    .filter_map(|entry| {
      entry
        .file_type()
        .ok()
        .filter(|kind| kind.is_dir())
        .map(|_| entry.file_name())
    })
    .filter_map(|name| name.into_string().ok())
    .filter(|name| is_canonical_uuid(name))
    .map(|uuid| (uuid, String::new()))
    .collect::<Vec<_>>();
  profiles.sort_by(|left, right| left.0.cmp(&right.0));
  profiles
}

/// Default profile is always first. A readable zero-row database is
/// authoritative; only absent, unreadable, or schema-incompatible databases
/// activate the deterministic directory fallback.
pub(crate) fn discover_safari_profiles(library: &Path) -> (Vec<SafariProfile>, Option<String>) {
  let mut profiles = vec![default_profile(library)];
  let (named, warning) = match named_profiles_from_database(library) {
    Ok(profiles) => (profiles, None),
    Err(error) => {
      let database = library
        .join("Containers/com.apple.Safari/Data/Library")
        .join(SAFARI_TABS_RELATIVE_PATH);
      (
        named_profiles_from_directory(library),
        Some(format!(
          "Safari profile database acquisition/query failed at {}; using directory fallback (Full Disk Access may be required): {error:#}",
          database.display()
        )),
      )
    }
  };
  let mut seen = std::collections::BTreeSet::new();
  profiles.extend(named.into_iter().filter_map(|(uuid, title)| {
    seen
      .insert(uuid.to_ascii_uppercase())
      .then(|| named_profile(library, uuid, title))
  }));
  disambiguate_profile_names(&mut profiles);
  (profiles, warning)
}

/// Crate-private generic adapter. It is intentionally separate from the
/// legacy API so a broken named profile cannot hide cookies selected by the
/// historical default-path-first `safari()` function.
#[allow(dead_code)] // retained as the private Safari-to-generic adapter
pub(crate) fn safari_outcome(
  library: &Path,
  domains: Option<Vec<String>>,
) -> SafariExtractionOutcome {
  let (profiles, discovery_warning) = discover_safari_profiles(library);
  let profiles = profiles
    .into_iter()
    .map(|profile| {
      let result = profile
        .cookie_candidates
        .iter()
        .find(|path| path.exists())
        .map(|path| safari_based(path.clone(), domains.clone()));
      match result {
        Some(Ok(cookies)) => SafariProfileExtraction {
          profile,
          cookies,
          error: None,
        },
        Some(Err(error)) => SafariProfileExtraction {
          profile,
          cookies: Vec::new(),
          error: Some(error.to_string()),
        },
        None => SafariProfileExtraction {
          profile,
          cookies: Vec::new(),
          error: Some("no Safari cookie source exists for profile".to_owned()),
        },
      }
    })
    .collect();
  SafariExtractionOutcome {
    profiles,
    discovery_warning,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::{
    fs,
    panic::{catch_unwind, UnwindSafe},
    time::{SystemTime, UNIX_EPOCH},
  };

  const COOKIE_HEADER_LEN: usize = 0x38;

  struct FixtureCookie<'a> {
    domain: &'a str,
    name: &'a str,
    path: &'a str,
    value: &'a str,
    flags: u32,
    expires: f64,
  }

  /// Build the same file/page/record framing used by Safari's
  /// `Cookies.binarycookies` store. Keeping this as a builder makes structural
  /// mutations explicit while the round-trip test remains a golden known-good
  /// blob.
  fn build_cookie_record(cookie: &FixtureCookie<'_>) -> Vec<u8> {
    let mut record = vec![0; COOKIE_HEADER_LEN];

    let domain_offset = record.len();
    record.extend_from_slice(cookie.domain.as_bytes());
    record.push(0);
    let name_offset = record.len();
    record.extend_from_slice(cookie.name.as_bytes());
    record.push(0);
    let path_offset = record.len();
    record.extend_from_slice(cookie.path.as_bytes());
    record.push(0);
    let value_offset = record.len();
    record.extend_from_slice(cookie.value.as_bytes());
    record.push(0);

    let record_len = u32::try_from(record.len()).expect("fixture record length");
    LittleEndian::write_u32(&mut record[0x00..0x04], record_len);
    LittleEndian::write_u32(&mut record[0x08..0x0c], cookie.flags);
    LittleEndian::write_u32(
      &mut record[0x10..0x14],
      u32::try_from(domain_offset).expect("fixture domain offset"),
    );
    LittleEndian::write_u32(
      &mut record[0x14..0x18],
      u32::try_from(name_offset).expect("fixture name offset"),
    );
    LittleEndian::write_u32(
      &mut record[0x18..0x1c],
      u32::try_from(path_offset).expect("fixture path offset"),
    );
    LittleEndian::write_u32(
      &mut record[0x1c..0x20],
      u32::try_from(value_offset).expect("fixture value offset"),
    );
    LittleEndian::write_f64(&mut record[0x28..0x30], cookie.expires);
    record
  }

  fn build_page(records: &[Vec<u8>]) -> Vec<u8> {
    let table_len = records.len().checked_mul(4).expect("fixture table length");
    let records_start = 8usize
      .checked_add(table_len)
      .and_then(|offset| offset.checked_add(4))
      .expect("fixture records offset");
    let mut page = vec![0; records_start];
    page[0..4].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]);
    LittleEndian::write_u32(
      &mut page[4..8],
      u32::try_from(records.len()).expect("fixture record count"),
    );

    for (index, record) in records.iter().enumerate() {
      let offset = page.len();
      let table_offset = 8 + index * 4;
      LittleEndian::write_u32(
        &mut page[table_offset..table_offset + 4],
        u32::try_from(offset).expect("fixture record offset"),
      );
      page.extend_from_slice(record);
    }

    page
  }

  fn build_file(pages: &[Vec<u8>]) -> Vec<u8> {
    let table_len = pages.len().checked_mul(4).expect("fixture page table");
    let mut file = vec![0; 8 + table_len];
    file[0..4].copy_from_slice(b"cook");
    BigEndian::write_u32(
      &mut file[4..8],
      u32::try_from(pages.len()).expect("fixture page count"),
    );

    for (index, page) in pages.iter().enumerate() {
      let table_offset = 8 + index * 4;
      BigEndian::write_u32(
        &mut file[table_offset..table_offset + 4],
        u32::try_from(page.len()).expect("fixture page length"),
      );
      file.extend_from_slice(page);
    }

    file
  }

  fn golden_fixture() -> Vec<u8> {
    let cookie = build_cookie_record(&FixtureCookie {
      domain: ".example.test",
      name: "session",
      path: "/account",
      value: "secret-value",
      flags: 0x01 | 0x04,
      expires: 750_000_000.0,
    });
    build_file(&[build_page(&[cookie])])
  }

  fn assert_error_without_panic<T, F>(case: &str, parse: F)
  where
    F: FnOnce() -> Result<T> + UnwindSafe,
  {
    let outcome = catch_unwind(parse);
    assert!(outcome.is_ok(), "{case} panicked");
    assert!(outcome.expect("checked above").is_err(), "{case} parsed");
  }

  fn page_start(file: &[u8]) -> usize {
    let page_count = usize::try_from(BigEndian::read_u32(&file[4..8])).expect("page count");
    8 + page_count * 4
  }

  fn record_start(file: &[u8], page_offset: usize, record_index: usize) -> usize {
    let table_offset = page_offset + 8 + record_index * 4;
    page_offset
      + usize::try_from(LittleEndian::read_u32(
        &file[table_offset..table_offset + 4],
      ))
      .expect("record offset")
  }

  #[test]
  fn test_slice_to_negative_length() {
    let data = b"hello world";
    let res = slice_to(data, 10, 5);
    assert!(res.is_err());
  }

  #[test]
  fn golden_binarycookies_fixture_round_trips_cookie_fields() {
    let cookies = parse_content(&golden_fixture()).expect("parse golden fixture");
    assert_eq!(cookies.len(), 1);

    let cookie = &cookies[0];
    assert_eq!(cookie.domain, ".example.test");
    assert_eq!(cookie.name, "session");
    assert_eq!(cookie.path, "/account");
    assert_eq!(cookie.value, "secret-value");
    assert!(cookie.secure);
    assert!(cookie.http_only);
    assert_eq!(cookie.expires, Some(1_728_307_200));
  }

  #[test]
  fn malformed_record_does_not_discard_valid_cookie() {
    let bad = build_cookie_record(&FixtureCookie {
      domain: ".bad.test",
      name: "bad",
      path: "/",
      value: "bad",
      flags: 0,
      expires: 0.0,
    });
    let good = build_cookie_record(&FixtureCookie {
      domain: ".good.test",
      name: "good",
      path: "/",
      value: "kept",
      flags: 0,
      expires: 0.0,
    });
    let mut page = build_page(&[bad, good]);
    let first_record =
      usize::try_from(LittleEndian::read_u32(&page[8..12])).expect("first record offset");
    LittleEndian::write_u32(&mut page[first_record..first_record + 4], u32::MAX);

    let cookies = parse_content(&build_file(&[page])).expect("retain good record");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "good");
    assert_eq!(cookies[0].value, "kept");
  }

  #[test]
  fn malformed_page_does_not_discard_cookie_from_another_page() {
    let mut bad_page = build_page(&[]);
    bad_page[0] = 0xff;
    let good_page = build_page(&[build_cookie_record(&FixtureCookie {
      domain: ".good.test",
      name: "good-page",
      path: "/",
      value: "kept",
      flags: 0,
      expires: 0.0,
    })]);

    let cookies = parse_content(&build_file(&[bad_page, good_page])).expect("retain good page");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "good-page");
  }

  #[test]
  fn all_malformed_records_return_the_last_error() {
    let first = build_cookie_record(&FixtureCookie {
      domain: ".first.test",
      name: "first",
      path: "/",
      value: "one",
      flags: 0,
      expires: 0.0,
    });
    let second = build_cookie_record(&FixtureCookie {
      domain: ".second.test",
      name: "second",
      path: "/",
      value: "two",
      flags: 0,
      expires: 0.0,
    });
    let mut page = build_page(&[first, second]);
    let first_offset =
      usize::try_from(LittleEndian::read_u32(&page[8..12])).expect("first record offset");
    let second_offset =
      usize::try_from(LittleEndian::read_u32(&page[12..16])).expect("second record offset");
    LittleEndian::write_u32(&mut page[first_offset..first_offset + 4], u32::MAX);
    LittleEndian::write_u32(&mut page[second_offset..second_offset + 4], 1);

    let error = parse_content(&build_file(&[page])).expect_err("all records are malformed");
    assert!(
      format!("{error:#}").contains("cookie record 1"),
      "expected final record error, got {error:#}"
    );
  }

  #[test]
  fn malformed_record_recovery_is_bounded_and_preserves_prior_cookies() {
    let good = build_cookie_record(&FixtureCookie {
      domain: ".good.test",
      name: "good-before-limit",
      path: "/",
      value: "kept",
      flags: 0,
      expires: 0.0,
    });
    let count = MAX_RECOVERABLE_RECORD_ERRORS_PER_PAGE + 1;
    let records_start = 8 + count * 4 + 4;
    let mut page = vec![0; records_start];
    page[0..4].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]);
    LittleEndian::write_u32(
      &mut page[4..8],
      u32::try_from(count).expect("fixture record count"),
    );
    LittleEndian::write_u32(
      &mut page[8..12],
      u32::try_from(records_start).expect("fixture record offset"),
    );
    for index in 1..count {
      let table_offset = 8 + index * 4;
      LittleEndian::write_u32(&mut page[table_offset..table_offset + 4], u32::MAX);
    }
    page.extend_from_slice(&good);

    let (cookies, error) = parse_page(&page).expect("page framing remains valid");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "good-before-limit");
    let error = error.expect("recovery limit should be reported");
    assert!(
      format!("{error:#}").contains("recovery limit reached after 1024 malformed records"),
      "unexpected recovery error: {error:#}"
    );
  }

  #[test]
  fn every_golden_fixture_truncation_returns_error_without_panicking() {
    let fixture = golden_fixture();
    for length in 0..fixture.len() {
      assert_error_without_panic(&format!("truncation at {length}"), || {
        parse_content(&fixture[..length])
      });
    }
  }

  #[test]
  fn malformed_offsets_and_lengths_return_error_without_panicking() {
    let fixture = golden_fixture();
    let page_offset = page_start(&fixture);
    let cookie_offset = record_start(&fixture, page_offset, 0);

    let mut excessive_page_count = fixture.clone();
    BigEndian::write_u32(&mut excessive_page_count[4..8], u32::MAX);

    let mut excessive_page_length = fixture.clone();
    BigEndian::write_u32(&mut excessive_page_length[8..12], u32::MAX);

    let mut excessive_record_offset = fixture.clone();
    LittleEndian::write_u32(
      &mut excessive_record_offset[page_offset + 8..page_offset + 12],
      u32::MAX,
    );

    let mut excessive_record_length = fixture.clone();
    LittleEndian::write_u32(
      &mut excessive_record_length[cookie_offset..cookie_offset + 4],
      u32::MAX,
    );

    let mut short_record = fixture.clone();
    LittleEndian::write_u32(&mut short_record[cookie_offset..cookie_offset + 4], 0x20);

    let mut inverted_string_offsets = fixture.clone();
    LittleEndian::write_u32(
      &mut inverted_string_offsets[cookie_offset + 0x10..cookie_offset + 0x14],
      0x38,
    );
    LittleEndian::write_u32(
      &mut inverted_string_offsets[cookie_offset + 0x14..cookie_offset + 0x18],
      0x20,
    );

    for (name, malformed) in [
      ("page count", excessive_page_count),
      ("page length", excessive_page_length),
      ("record offset", excessive_record_offset),
      ("record length", excessive_record_length),
      ("short record", short_record),
      ("inverted string offsets", inverted_string_offsets),
    ] {
      assert_error_without_panic(name, || parse_content(&malformed));
    }
  }

  #[test]
  fn checked_arithmetic_rejects_architecture_sized_overflow() {
    assert_error_without_panic("slice addition", || slice(&[], usize::MAX, 1));
    assert_error_without_panic("table multiplication", || {
      parse_table::<LittleEndian>(&[], usize::MAX / 4 + 1)
    });
  }

  #[test]
  fn file_larger_than_limit_is_rejected_before_reading() {
    let unique = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .expect("system clock")
      .as_nanos();
    let path = std::env::temp_dir().join(format!(
      "rookie-safari-size-limit-{}-{unique}.binarycookies",
      std::process::id()
    ));
    let file = File::create(&path).expect("create sparse fixture");
    file
      .set_len(MAX_BINARY_COOKIES_FILE_SIZE + 1)
      .expect("size sparse fixture");
    drop(file);

    let mut file = File::open(&path).expect("reopen sparse fixture");
    let error = read_stable_cookie_file(&mut file, &path).expect_err("oversized file should fail");
    fs::remove_file(&path).expect("remove sparse fixture");
    assert!(format!("{error:#}").contains("too large"));
  }

  #[cfg(unix)]
  #[test]
  fn stable_read_reopens_after_an_atomic_path_replacement() {
    let unique = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .expect("system clock")
      .as_nanos();
    let directory = std::env::temp_dir().join(format!(
      "rookie-safari-atomic-replace-{}-{unique}",
      std::process::id()
    ));
    fs::create_dir_all(&directory).expect("create fixture directory");
    let path = directory.join("Cookies.binarycookies");
    let replacement = directory.join("replacement.binarycookies");
    let old = golden_fixture();
    let mut new = golden_fixture();
    new.push(0);
    fs::write(&path, old).expect("write original image");
    fs::write(&replacement, &new).expect("write replacement image");

    let mut file = File::open(&path).expect("open original image");
    let mut replacement = Some(replacement);
    let image = read_stable_cookie_file_with(&mut file, &path, || {
      if let Some(replacement) = replacement.take() {
        fs::rename(replacement, &path).expect("atomically replace cookie image");
      }
    })
    .expect("reopen and acquire replacement image");
    assert_eq!(image, new);
    fs::remove_dir_all(&directory).expect("remove fixture directory");
  }

  fn temp_library(tag: &str) -> PathBuf {
    let unique = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .expect("system clock")
      .as_nanos();
    let library = std::env::temp_dir().join(format!(
      "rookie-safari-{tag}-{}-{unique}/Library",
      std::process::id()
    ));
    fs::create_dir_all(&library).expect("create library fixture");
    library
  }

  fn write_tabs_database(library: &Path, rows: &[(&str, &str)]) {
    let database = library.join("Containers/com.apple.Safari/Data/Library/Safari/SafariTabs.db");
    fs::create_dir_all(database.parent().expect("database parent"))
      .expect("create database parent");
    let connection = rusqlite::Connection::open(&database).expect("open SafariTabs fixture");
    connection
      .execute_batch("CREATE TABLE bookmarks (external_uuid TEXT, title TEXT, subtype INTEGER)")
      .expect("create bookmarks");
    for (uuid, title) in rows {
      connection
        .execute(
          "INSERT INTO bookmarks (external_uuid, title, subtype) VALUES (?1, ?2, 2)",
          rusqlite::params![uuid, title],
        )
        .expect("insert bookmark profile");
    }
  }

  #[test]
  fn safari_tabs_profiles_are_default_first_lowercase_and_disambiguated() {
    let library = temp_library("tabs-profiles");
    let first = "A0B1C2D3-1111-2222-3333-444444444444";
    let second = "B0B1C2D3-1111-2222-3333-444444444444";
    let third = "C0B1C2D3-1111-2222-3333-444444444444";
    write_tabs_database(
      &library,
      &[(third, "Work-2"), (second, "Work"), (first, "Work")],
    );

    let (profiles, warning) = discover_safari_profiles(&library);
    assert!(warning.is_none());
    assert_eq!(
      profiles
        .iter()
        .map(|profile| profile.name.as_str())
        .collect::<Vec<_>>(),
      vec!["default", "Work", "Work-2", "Work-2-2"]
    );
    assert_eq!(profiles[1].uuid.as_deref(), Some(first));
    assert!(profiles[1].cookie_candidates[0]
      .to_string_lossy()
      .contains(&first.to_ascii_lowercase()));
    fs::remove_dir_all(library.parent().expect("fixture root")).expect("remove fixture");
  }

  #[test]
  fn readable_zero_row_profile_database_is_authoritative() {
    let library = temp_library("zero-row-authority");
    write_tabs_database(&library, &[]);
    let uuid = "A0B1C2D3-1111-2222-3333-444444444444";
    fs::create_dir_all(library.join(format!(
      "Containers/com.apple.Safari/Data/Library/Safari/Profiles/{uuid}"
    )))
    .expect("create fallback profile");

    let (profiles, warning) = discover_safari_profiles(&library);
    assert!(warning.is_none());
    assert_eq!(
      profiles.len(),
      1,
      "directory fallback must not override a readable zero-row DB"
    );
    fs::remove_dir_all(library.parent().expect("fixture root")).expect("remove fixture");
  }

  #[test]
  fn missing_profile_database_uses_sorted_directory_fallback_with_warning() {
    let library = temp_library("directory-fallback");
    let first = "B0B1C2D3-1111-2222-3333-444444444444";
    let second = "A0B1C2D3-1111-2222-3333-444444444444";
    for uuid in [first, second] {
      fs::create_dir_all(library.join(format!(
        "Containers/com.apple.Safari/Data/Library/Safari/Profiles/{uuid}"
      )))
      .expect("create fallback profile");
    }

    let (profiles, warning) = discover_safari_profiles(&library);
    assert!(warning
      .as_deref()
      .is_some_and(|message| message.contains("directory fallback")));
    assert_eq!(profiles[0].name, "default");
    assert_eq!(profiles[1].uuid.as_deref(), Some(second));
    assert_eq!(profiles[2].uuid.as_deref(), Some(first));
    fs::remove_dir_all(library.parent().expect("fixture root")).expect("remove fixture");
  }
}
