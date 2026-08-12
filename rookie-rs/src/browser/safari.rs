use crate::common::{date, enums::*, utils};
use anyhow::{anyhow, bail, Context, Result};
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use std::{
  fs::File,
  io::Read,
  path::{Path, PathBuf},
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
  let bs = read_cookie_file(&mut file, &db_path)?;
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

fn read_cookie_file(file: &mut File, db_path: &Path) -> Result<Vec<u8>> {
  let advertised_len = file
    .metadata()
    .with_context(|| format!("Failed to inspect {}", db_path.display()))?
    .len();
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
    let error = read_cookie_file(&mut file, &path).expect_err("oversized file should fail");
    fs::remove_file(&path).expect("remove sparse fixture");
    assert!(format!("{error:#}").contains("too large"));
  }
}
