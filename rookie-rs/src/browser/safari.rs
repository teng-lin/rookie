#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

#[cfg(test)]
use crate::common::deadline::{Clock, Deadline};
use crate::common::{
  boundary::{Decoder, ReadOnlySource, RecordSink},
  date,
  deadline::{BoundaryRuntime, BoundaryStop, DeadlineEnforcement, SystemClock},
  diagnostic::REDACTED_PATH,
  enums::*,
  secret::{SecretBytes, SecretString},
  utils,
};
use anyhow::{anyhow, bail, Context, Result};
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use std::{
  fs::File,
  io::Read,
  path::{Path, PathBuf},
  time::SystemTime,
  vec::Vec,
};
use zeroize::Zeroize;

use super::cookie_record::{
  Attributes, CookieRecord, CookieValue, Observation, RawValue, SourceRef,
};
use super::report_core::{CookieSourceFormatId, CookieSourceRoleId};
use super::source::{AcquisitionPolicy, Source, SourceAcquisition, SourceCandidate, SourceStats};

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
// Only the macOS public surface calls this; other targets compile the parser
// under `cfg(test)` for fixtures alone.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[deprecated(
  since = "0.6.0",
  note = "use direct_path::cookies_from_path with DirectPathRequest"
)]
pub fn safari_based(db_path: PathBuf, domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  safari_based_with_runtime(db_path, domains, &runtime)
}

pub(crate) fn safari_based_with_runtime(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  let source =
    safari_based_outcome_with_runtime(direct_path_candidate(&db_path), domains, runtime)?;
  super::legacy::project_canonical_outcome_with_runtime(
    "safari",
    super::report_build::finalize_singleton_source(
      "safari",
      db_path.parent().unwrap_or(&db_path).to_path_buf(),
      vec![source],
      None,
      Some(runtime),
    )?,
    runtime,
  )
}

/// The candidate a direct-path Safari read is aimed at.
///
/// A caller who names a file has done no discovery, so there is no candidate to
/// clone. These are the values the direct-path report has always emitted for
/// such a source, including the frozen `StableFileImage`.
pub(crate) fn direct_path_candidate(db_path: &Path) -> SourceCandidate {
  SourceCandidate {
    path: db_path.to_path_buf(),
    role: CookieSourceRoleId::persistent(),
    format: CookieSourceFormatId::known("safari_binarycookies"),
    precedence: super::registry::PERSISTENT_SOURCE_PRECEDENCE,
    exists: true,
    selected: true,
    acquisition: SourceAcquisition::StableFileImage,
    policy: AcquisitionPolicy::Fixed,
  }
}

/// Row accounting for the private cross-engine report. The legacy
/// [`safari_based`] projection deliberately discards it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SafariExtractionStats {
  pub(crate) records_seen: usize,
  pub(crate) records_skipped: usize,
  pub(crate) records_rejected: usize,
}

/// Context attached to failures raised after acquisition succeeded, so the
/// report layer can distinguish a corrupt file from an unreadable one while
/// retaining any record accounting recovered before the failure.
#[derive(Debug)]
pub(crate) struct SafariParseFailure {
  pub(crate) stats: SafariExtractionStats,
}

impl std::fmt::Display for SafariParseFailure {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str("Safari cookie parsing failed")
  }
}

/// Attaches one Safari read to the candidate it came from.
///
/// The stats/records/row-error tuple this replaces was a fourth vocabulary for
/// facts `Source` already names; the adapter copied it field-by-field. Errors
/// stay on `Result`: an unreadable file is not a source outcome, and folding it
/// into `Source.failure` would reflow the acquisition message the public
/// `safari()` API returns.
pub(crate) fn safari_source(
  origin: SourceCandidate,
  records: Vec<CookieRecord>,
  stats: SafariExtractionStats,
  row_error: Option<String>,
  acquisition_attempts: u32,
) -> Source {
  let mut source = Source::new(origin.identity(), origin.selected, origin.acquisition);
  source.stats = SourceStats {
    rows_seen: stats.records_seen,
    cookies_emitted: records.len(),
    rows_skipped: stats.records_skipped,
    rows_rejected: stats.records_rejected,
    provider_failures: 0,
  };
  source.records = records;
  source.acquisition_attempts = acquisition_attempts;
  // After the stats, never before: the issue is keyed on `rows_skipped`.
  source.push_row_read_failed(row_error);
  source
}

#[cfg(test)]
type SafariParseResult = (
  Vec<Cookie>,
  Vec<CookieRecord>,
  SafariExtractionStats,
  Option<anyhow::Error>,
);

type SafariRecordParseResult = (
  Vec<CookieRecord>,
  SafariExtractionStats,
  Option<anyhow::Error>,
);

pub(crate) struct SafariReadOnlySource<'a> {
  pub(crate) bytes: &'a [u8],
}

impl ReadOnlySource for SafariReadOnlySource<'_> {}

pub(crate) struct SafariBoundaryDecoder;

#[derive(Debug)]
pub(crate) struct SafariDecodeSummary {
  pub(crate) stats: SafariExtractionStats,
  pub(crate) row_error: Option<anyhow::Error>,
}

impl Decoder<SafariReadOnlySource<'_>, CookieRecord> for SafariBoundaryDecoder {
  type Summary = SafariDecodeSummary;

  fn decode(
    &self,
    source: &SafariReadOnlySource<'_>,
    sink: &mut dyn RecordSink<CookieRecord>,
    runtime: &BoundaryRuntime<'_>,
  ) -> Result<Self::Summary> {
    let (mut records, stats, row_error) =
      parse_content_records_with_runtime(source.bytes, runtime)?;
    runtime.check()?;
    for (ordinal, record) in records.iter_mut().enumerate() {
      runtime.check()?;
      record.origin = SourceRef::pending(ordinal);
    }
    // No record crosses the sink boundary until every page and record has
    // decoded and the final deadline checkpoint has succeeded.
    for record in records {
      runtime.check()?;
      sink.emit(record)?;
    }
    runtime.check()?;
    Ok(SafariDecodeSummary { stats, row_error })
  }

  fn deadline_enforcement(&self) -> DeadlineEnforcement {
    DeadlineEnforcement::Cooperative
  }
}

pub(crate) fn safari_based_outcome(
  origin: SourceCandidate,
  domains: Option<Vec<String>>,
) -> Result<Source> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  safari_based_outcome_with_runtime(origin, domains, &runtime)
}

/// Reads one Safari `Cookies.binarycookies` and returns it as a [`Source`].
///
/// The caller hands over the candidate it selected, which becomes
/// `Source::origin` — path, role, format, and precedence are never rebuilt
/// here. `Err` still means the read did not produce a source at all, which the
/// adapter turns into a typed `Source.failure` and the compatibility API
/// surfaces verbatim.
pub(crate) fn safari_based_outcome_with_runtime(
  origin: SourceCandidate,
  domains: Option<Vec<String>>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Source> {
  let db_path = origin.path.clone();
  runtime.check()?;
  let mut file = File::open(&db_path).context(format!(
    "Failed to open {REDACTED_PATH}\n\
      Make sure you have full disk access for the current process.\n\
      For example, in VSCode or Terminal:\n\
      1. Open Settings\n\
      2. Privacy & Security\n\
      3. Full Disk Access\n\
      ---\n\
      You can also open the disk access page with: \n\
      open \"x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles\"\n\
      "
  ))?;
  runtime.check()?;
  let (bs, acquisition_attempts) =
    read_stable_cookie_file_with_runtime(&mut file, &db_path, || {}, runtime)?;
  // Tagged so the report can name the stage that actually failed instead of
  // flattening every Safari failure into acquisition.
  let source = SafariReadOnlySource { bytes: &bs };
  let decoder = SafariBoundaryDecoder;
  let mut records = Vec::new();
  let summary = crate::common::boundary::decode(
    &decoder,
    &source,
    &mut |record| {
      records.push(record);
      Ok(())
    },
    runtime,
  )
  .map_err(|error| {
    if error.downcast_ref::<SafariParseFailure>().is_some()
      || error.downcast_ref::<BoundaryStop>().is_some()
    {
      error
    } else {
      error.context(SafariParseFailure {
        stats: SafariExtractionStats::default(),
      })
    }
  })?;
  let mut stats = summary.stats;
  let row_error = summary.row_error;
  // Filter cookies by domain if domains are specified
  let records = match &domains {
    Some(domain_filters) => {
      let parsed = records.len();
      let records = records
        .into_iter()
        .filter(|record| utils::some_domain_in_host(Some(domain_filters), record.domain_raw()))
        .collect::<Vec<_>>();
      // Report counters describe request-relevant records. Successfully
      // decoded cookies excluded by the domain filter were never seen from
      // the caller's perspective; malformed records remain counted because
      // their domains could not necessarily be inspected.
      stats.records_seen = stats
        .records_seen
        .saturating_sub(parsed.saturating_sub(records.len()));
      records
    }
    None => records,
  };
  runtime.check()?;
  Ok(safari_source(
    origin,
    records,
    stats,
    row_error.map(|error| format!("{error:#}")),
    acquisition_attempts,
  ))
}

pub(crate) const STABLE_READ_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileImageMetadata {
  len: u64,
  modified: Option<SystemTime>,
  #[cfg(unix)]
  device: u64,
  #[cfg(unix)]
  inode: u64,
}

fn image_metadata(file: &File, _db_path: &Path) -> Result<FileImageMetadata> {
  file
    .metadata()
    .with_context(|| format!("Failed to inspect {REDACTED_PATH}"))
    .map(file_image_metadata)
}

fn path_image_metadata(db_path: &Path) -> Result<FileImageMetadata> {
  std::fs::metadata(db_path)
    .with_context(|| format!("Failed to inspect Safari cookie path {REDACTED_PATH}"))
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
/// Returns the stable image and how many acquisition attempts it took, so a
/// report can state the real attempt count instead of assuming one.
#[cfg(test)]
fn read_stable_cookie_file(file: &mut File, db_path: &Path) -> Result<(Vec<u8>, u32)> {
  read_stable_cookie_file_with(file, db_path, || {})
    .map(|(bytes, attempts)| (bytes.as_slice().to_vec(), attempts))
}

#[cfg(test)]
fn read_stable_cookie_file_with<F>(
  file: &mut File,
  db_path: &Path,
  after_read: F,
) -> Result<(SecretBytes, u32)>
where
  F: FnMut(),
{
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  read_stable_cookie_file_with_runtime(file, db_path, after_read, &runtime)
}

fn read_stable_cookie_file_with_runtime<F>(
  file: &mut File,
  db_path: &Path,
  mut after_read: F,
  runtime: &BoundaryRuntime<'_>,
) -> Result<(SecretBytes, u32)>
where
  F: FnMut(),
{
  let mut last_change = None;
  for attempt in 1..=STABLE_READ_ATTEMPTS {
    runtime.check()?;
    let fd_before = image_metadata(file, db_path)?;
    let path_before = path_image_metadata(db_path)?;
    let first_bytes = read_cookie_file_with_runtime(file, db_path, fd_before.len, runtime)?;
    after_read();
    runtime.check()?;
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
      // A writer can preserve metadata while rewriting in place. Reopen and
      // compare a second complete, bounded image before accepting either one.
      let mut verification =
        File::open(db_path).with_context(|| format!("Failed to reopen {REDACTED_PATH}"))?;
      let verification_before = image_metadata(&verification, db_path)?;
      let verification_path_before = path_image_metadata(db_path)?;
      let verification_bytes = read_cookie_file_with_runtime(
        &mut verification,
        db_path,
        verification_before.len,
        runtime,
      )?;
      runtime.check()?;
      let verification_after = image_metadata(&verification, db_path)?;
      let verification_path_after = path_image_metadata(db_path)?;
      if verification_before == verification_path_before
        && verification_after == verification_path_after
        && verification_before == verification_after
        && verification_path_before == verification_path_after
        && verification_before == fd_before
        && first_bytes == verification_bytes
      {
        *file = verification;
        runtime.check()?;
        return Ok((first_bytes, attempt as u32));
      }
      last_change = Some((
        fd_before,
        path_before,
        verification_before,
        verification_path_before,
        verification_after,
        verification_path_after,
      ));
    } else {
      last_change = Some((
        fd_before,
        path_before,
        fd_after.clone(),
        path_after.clone(),
        fd_after,
        path_after,
      ));
    }
    *file = File::open(db_path).with_context(|| format!("Failed to reopen {REDACTED_PATH}"))?;
    runtime.check()?;
  }
  bail!(
    "Safari cookie file {REDACTED_PATH} changed during each of {STABLE_READ_ATTEMPTS} acquisition attempts: {last_change:?}"
  )
}

fn read_cookie_file_with_runtime(
  file: &mut impl Read,
  _db_path: &Path,
  advertised_len: u64,
  runtime: &BoundaryRuntime<'_>,
) -> Result<SecretBytes> {
  runtime.check()?;
  if advertised_len > MAX_BINARY_COOKIES_FILE_SIZE {
    bail!(
      "Safari cookie file {REDACTED_PATH} is too large: {advertised_len} bytes exceeds the {} byte limit",
      MAX_BINARY_COOKIES_FILE_SIZE
    );
  }

  let initial_capacity = usize::try_from(advertised_len)
    .context("Safari cookie file size does not fit in memory address space")?;
  let mut bytes = Vec::new();
  bytes
    .try_reserve_exact(initial_capacity)
    .context("Failed to reserve memory for Safari cookie file")?;
  let mut bytes = SecretBytes::new(bytes);

  // `metadata` is only a snapshot. Limit the read as well in case the file is
  // replaced or grows between the size check and `read_to_end`.
  let mut remaining = MAX_BINARY_COOKIES_FILE_SIZE + 1;
  // The read frame can contain an entire cookie value. Wipe every completed
  // chunk immediately after copying it; SecretBytes' wiping Drop covers read
  // errors, deadline exits, and unwinds before the next checkpoint.
  let mut chunk = SecretBytes::new(vec![0_u8; 64 * 1024]);
  while remaining > 0 {
    runtime.check()?;
    let requested = usize::try_from(remaining.min(chunk.len() as u64)).unwrap_or(chunk.len());
    let read = file
      .read(&mut chunk.as_mut_slice()[..requested])
      .with_context(|| format!("Failed to read {REDACTED_PATH}"))?;
    if read == 0 {
      break;
    }
    bytes.extend_bounded(
      &chunk.as_slice()[..read],
      MAX_BINARY_COOKIES_FILE_SIZE as usize + 1,
    );
    chunk.as_mut_slice().zeroize();
    remaining = remaining.saturating_sub(read as u64);
  }
  if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_BINARY_COOKIES_FILE_SIZE {
    bail!(
      "Safari cookie file {REDACTED_PATH} grew beyond the {} byte limit while it was read",
      MAX_BINARY_COOKIES_FILE_SIZE
    );
  }
  runtime.check()?;
  Ok(bytes)
}

/// Parse one page and retain any valid records. The optional error is the last
/// malformed record encountered. The caller preserves it as a row diagnostic
/// even when another record on the page was valid.
#[cfg(test)]
fn parse_page(bs: &[u8]) -> Result<SafariParseResult> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  let (records, stats, row_error) = parse_page_records_with_runtime(bs, &runtime)?;
  Ok(project_safari_records(records, stats, row_error))
}

fn parse_page_records_with_runtime(
  bs: &[u8],
  runtime: &BoundaryRuntime<'_>,
) -> Result<SafariRecordParseResult> {
  runtime.check()?;
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

  let mut records: Vec<CookieRecord> = vec![];
  let mut last_error = None;
  let mut error_count = 0usize;
  let mut stats = SafariExtractionStats::default();
  for (index, raw_offset) in parsed_table.into_iter().enumerate() {
    runtime.check()?;
    stats.records_seen += 1;
    let result: Result<CookieRecord> = (|| {
      let offset = usize::try_from(raw_offset)
        .context("Safari cookie offset does not fit in memory address space")?;
      let length = usize::try_from(slice(bs, offset, 4).map(LittleEndian::read_u32)?)
        .context("Safari cookie length does not fit in memory address space")?;
      let record = slice(bs, offset, length)?;
      parse_cookie::<LittleEndian>(record)
    })()
    .with_context(|| format!("Failed to parse Safari cookie record {index}"));

    match result {
      Ok(record) => records.push(record),
      Err(error) => {
        error_count += 1;
        stats.records_skipped += 1;
        stats.records_rejected += 1;
        if error_count <= MAX_LOGGED_RECORD_ERRORS_PER_PAGE {
          log::warn!("Skipping malformed Safari cookie record {index}: {error:#}");
        } else if error_count == MAX_LOGGED_RECORD_ERRORS_PER_PAGE + 1 {
          log::warn!("Additional malformed Safari cookie records will be summarized for this page");
        }

        if error_count >= MAX_RECOVERABLE_RECORD_ERRORS_PER_PAGE {
          let remaining = count.saturating_sub(index + 1);
          stats.records_seen += remaining;
          stats.records_skipped += remaining;
          stats.records_rejected += remaining;
          let error = error.context(format!(
            "Safari page recovery limit reached after {error_count} malformed records; \
             {remaining} remaining record(s) were skipped without parsing"
          ));
          log::warn!("Stopping malformed Safari page recovery: {error:#}");
          last_error = Some(error);
          break;
        }

        last_error = Some(error);
      }
    }
  }
  runtime.check()?;
  Ok((records, stats, last_error))
}

fn parse_cookie<T: ByteOrder>(bs: &[u8]) -> Result<CookieRecord> {
  if bs.len() < 0x30 {
    bail!("cookie data underflow");
  }
  let flags = T::read_u32(&bs[0x08..0x0c]);

  let url_off = T::read_u32(&bs[0x10..0x14]) as usize;
  let name_off = T::read_u32(&bs[0x14..0x18]) as usize;
  let path_off = T::read_u32(&bs[0x18..0x1c]) as usize;
  let value_off = T::read_u32(&bs[0x1c..0x20]) as usize;

  // i/OS/X to Unix timestamp +(1 Jan 2001 epoch seconds).
  let raw_expires = T::read_f64(&bs[0x28..0x30]);
  let expires = date::safari_timestamp(raw_expires);

  let url = slice_to(bs, url_off, name_off).and_then(c_str)?;
  let name = slice_to(bs, name_off, path_off).and_then(c_str)?;
  let path = slice_to(bs, path_off, value_off).and_then(c_str)?;
  let value_slice = slice(bs, value_off, bs.len().saturating_sub(value_off))?;
  let value = c_str_value(value_slice)?;

  let is_secure = (flags & 0x01) == 0x01;
  let is_http_only = (flags & 0x04) == 0x04;

  let mut cookie = CookieRecord::from_legacy_fields(
    url,
    path,
    is_secure,
    expires,
    name,
    CookieValue::Plain(SecretString::new(value)),
    is_http_only,
    SAME_SITE_UNSPECIFIED,
    CookieContext::default(),
    0,
  );
  cookie.attributes = Attributes {
    secure: Observation::Known(is_secure),
    http_only: Observation::Known(is_http_only),
    expires: match expires {
      Some(expires) => Observation::Known(Some(expires)),
      None if raw_expires == 0.0 => Observation::Known(None),
      None => Observation::Unknown(RawValue::FloatBits(raw_expires.to_bits())),
    },
    raw_expires: Observation::Known(RawValue::FloatBits(raw_expires.to_bits())),
    // BinaryCookies does not encode SameSite. Retain absence and let the
    // compatibility projection supply SAME_SITE_UNSPECIFIED.
    same_site: Observation::Missing,
  };
  cookie.retain_raw("flags", RawValue::Unsigned(u64::from(flags)));
  Ok(cookie)
}

fn declared_page_record_count(page: &[u8]) -> Option<usize> {
  page
    .get(4..8)
    .map(LittleEndian::read_u32)
    .and_then(|count| usize::try_from(count).ok())
}

/// Account for a page that failed before record-level recovery could begin.
/// When its declared count is unreadable, the page itself is one skipped input
/// unit. This keeps the loss visible and preserves the report counter identity
/// instead of silently claiming a complete extraction.
fn record_page_failure(stats: &mut SafariExtractionStats, page: Option<&[u8]>) {
  let skipped = page.and_then(declared_page_record_count).unwrap_or(1);
  stats.records_seen = stats.records_seen.saturating_add(skipped);
  stats.records_skipped = stats.records_skipped.saturating_add(skipped);
  stats.records_rejected = stats.records_rejected.saturating_add(skipped);
}

#[cfg(test)]
fn parse_content(bs: &[u8]) -> Result<SafariParseResult> {
  let clock = SystemClock;
  parse_content_with_deadline(bs, &clock, Deadline::standard())
}

#[cfg(test)]
fn parse_content_with_deadline(
  bs: &[u8],
  clock: &dyn Clock,
  deadline: Deadline,
) -> Result<SafariParseResult> {
  let runtime = BoundaryRuntime::new(clock, deadline);
  let (records, stats, row_error) = parse_content_records_with_runtime(bs, &runtime)?;
  Ok(project_safari_records(records, stats, row_error))
}

fn parse_content_records_with_runtime(
  bs: &[u8],
  runtime: &BoundaryRuntime<'_>,
) -> Result<SafariRecordParseResult> {
  runtime.check()?;
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
  let mut records: Vec<CookieRecord> = vec![];
  let mut last_error = None;
  let mut stats = SafariExtractionStats::default();

  for (index, raw_length) in page_lengths.into_iter().enumerate() {
    runtime.check()?;
    let length = usize::try_from(raw_length)
      .context("Safari page length does not fit in memory address space")?;
    let next_offset = match offset.checked_add(length) {
      Some(next_offset) => next_offset,
      None => {
        let error = anyhow!("Safari page {index} end offset overflow");
        log::warn!("Skipping malformed Safari page {index}: {error:#}");
        record_page_failure(&mut stats, bs.get(offset..));
        last_error = Some(error);
        break;
      }
    };

    match slice(bs, offset, length)
      .with_context(|| format!("Failed to read Safari page {index}"))
      .and_then(|page| parse_page_records_with_runtime(page, runtime))
    {
      Ok((page_records, page_stats, page_error)) => {
        records.extend(page_records);
        stats.records_seen += page_stats.records_seen;
        stats.records_skipped += page_stats.records_skipped;
        stats.records_rejected += page_stats.records_rejected;
        if let Some(error) = page_error {
          last_error = Some(error);
        }
      }
      // A boundary stop is operation state, never malformed input. Returning
      // it immediately prevents a valid earlier page from turning a timeout
      // on a later page into partial success plus a bogus row diagnostic.
      Err(error) if error.downcast_ref::<BoundaryStop>().is_some() => return Err(error),
      Err(error) => {
        log::warn!("Skipping malformed Safari page {index}: {error:#}");
        record_page_failure(&mut stats, bs.get(offset..next_offset));
        last_error = Some(error);
      }
    }
    offset = next_offset;
  }

  runtime.check()?;
  if records.is_empty() {
    if let Some(error) = last_error {
      return Err(error.context(SafariParseFailure { stats }));
    }
  }

  runtime.check()?;
  Ok((records, stats, last_error))
}

#[cfg(test)]
fn project_safari_records(
  records: Vec<CookieRecord>,
  stats: SafariExtractionStats,
  row_error: Option<anyhow::Error>,
) -> SafariParseResult {
  let cookies = records
    .iter()
    .cloned()
    .map(|record| {
      record
        .into_cookie()
        .expect("Safari rows emit plaintext values")
    })
    .collect();
  (cookies, records, stats, row_error)
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
      if last != 0x00 {
        bail!("c string non null terminator")
      }
      if elements.contains(&0x00) {
        bail!("c string contains embedded NUL")
      }
      Ok(elements)
    })
    .and_then(|elements| {
      String::from_utf8(elements.to_vec()).map_err(|err| anyhow!(err.to_string()))
    })
}

fn c_str_value(bs: &[u8]) -> Result<String> {
  let nul_pos = bs
    .iter()
    .position(|&b| b == 0x00)
    .ok_or_else(|| anyhow!("c string non null terminator"))?;
  let elements = &bs[..nul_pos];
  let trailing = &bs[nul_pos + 1..];
  if !trailing.is_empty()
    && !trailing.starts_with(b"bplist00")
    && !trailing.iter().all(|&b| b == 0x00)
  {
    bail!("c string contains embedded NUL");
  }
  String::from_utf8(elements.to_vec()).map_err(|err| anyhow!(err.to_string()))
}

#[cfg(test)]
pub(crate) fn embedded_nul_test_fixture(field: &str, include_valid: bool) -> Vec<u8> {
  tests::embedded_nul_fixture(field, include_valid)
}

#[cfg(test)]
pub(crate) fn golden_binarycookies_test_fixture() -> Vec<u8> {
  tests::golden_fixture()
}

#[cfg(test)]
pub(super) fn malformed_decoder_gate_case(bytes: &[u8]) -> Result<()> {
  let source = SafariReadOnlySource { bytes };
  let decoder = SafariBoundaryDecoder;
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  let mut sink = |_record| Ok(());
  let _ = decoder.decode(&source, &mut sink, &runtime);
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::common::deadline::test_clock::ManualClock;
  use std::{
    fs,
    panic::{catch_unwind, UnwindSafe},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
  };

  const COOKIE_HEADER_LEN: usize = 0x38;

  struct ChunkWipeReader {
    step: u8,
    fail_after_first: bool,
  }

  impl Read for ChunkWipeReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
      assert!(
        buffer.iter().all(|byte| *byte == 0),
        "the previous Safari read chunk must be wiped before reuse"
      );
      match self.step {
        0 => {
          self.step = 1;
          buffer[..3].copy_from_slice(b"one");
          Ok(3)
        }
        1 if self.fail_after_first => {
          buffer[..3].copy_from_slice(b"two");
          Err(std::io::Error::other("scripted Safari read failure"))
        }
        1 => {
          self.step = 2;
          buffer[..3].copy_from_slice(b"two");
          Ok(3)
        }
        _ => Ok(0),
      }
    }
  }

  struct TickClock {
    base: Instant,
    ticks: AtomicU64,
  }

  impl Default for TickClock {
    fn default() -> Self {
      Self {
        base: Instant::now(),
        ticks: AtomicU64::new(0),
      }
    }
  }

  impl Clock for TickClock {
    fn now(&self) -> Instant {
      self.base + Duration::from_secs(self.ticks.fetch_add(1, Ordering::SeqCst))
    }

    fn sleep(&self, _duration: Duration) {}
  }

  #[test]
  fn stable_read_starts_no_verification_or_retry_after_deadline() {
    let directory = crate::utils::TempDir::new().expect("temporary directory");
    let path = directory.path().join("Cookies.binarycookies");
    fs::write(&path, golden_fixture()).expect("write Safari fixture");
    let mut file = File::open(&path).expect("open Safari fixture");
    let clock = ManualClock::default();
    let deadline = Deadline::after(&clock, std::time::Duration::from_secs(1));
    let runtime = BoundaryRuntime::new(&clock, deadline);
    let callbacks = std::cell::Cell::new(0_u32);

    let error = read_stable_cookie_file_with_runtime(
      &mut file,
      &path,
      || {
        callbacks.set(callbacks.get() + 1);
        clock.advance(std::time::Duration::from_secs(1));
      },
      &runtime,
    )
    .expect_err("deadline expires after the first chunked read");

    assert_eq!(
      error.downcast_ref::<BoundaryStop>(),
      Some(&BoundaryStop::TimedOut)
    );
    assert_eq!(callbacks.get(), 1);
    assert_eq!(deadline.remaining(&clock), std::time::Duration::ZERO);
  }

  #[test]
  fn safari_file_reader_wipes_each_completed_chunk_before_reuse() {
    let clock = ManualClock::default();
    let runtime = BoundaryRuntime::new(
      &clock,
      Deadline::after(&clock, std::time::Duration::from_secs(1)),
    );
    let mut reader = ChunkWipeReader {
      step: 0,
      fail_after_first: false,
    };

    let bytes =
      read_cookie_file_with_runtime(&mut reader, Path::new("Cookies.binarycookies"), 6, &runtime)
        .expect("scripted chunks are readable");

    assert_eq!(bytes.as_slice(), b"onetwo");
  }

  #[test]
  fn safari_file_reader_wipes_the_previous_chunk_before_a_read_error() {
    let clock = ManualClock::default();
    let runtime = BoundaryRuntime::new(
      &clock,
      Deadline::after(&clock, std::time::Duration::from_secs(1)),
    );
    let mut reader = ChunkWipeReader {
      step: 0,
      fail_after_first: true,
    };

    let error =
      read_cookie_file_with_runtime(&mut reader, Path::new("Cookies.binarycookies"), 6, &runtime)
        .expect_err("the scripted second read fails");

    assert!(format!("{error:#}").contains("scripted Safari read failure"));
  }

  #[test]
  fn pure_binarycookies_decoder_boundary_is_platform_neutral() {
    fn assert_source<T: ReadOnlySource>() {}
    fn assert_decoder<T: Decoder<SafariReadOnlySource<'static>, CookieRecord>>() {}
    assert_source::<SafariReadOnlySource<'static>>();
    assert_decoder::<SafariBoundaryDecoder>();
  }

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

  pub(super) fn golden_fixture() -> Vec<u8> {
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

  pub(super) fn embedded_nul_fixture(field: &str, include_valid: bool) -> Vec<u8> {
    let (domain, name, path, value) = match field {
      "domain" => (".example\0.test", "session", "/account", "secret-value"),
      "name" => (".example.test", "ses\0sion", "/account", "secret-value"),
      "path" => (".example.test", "session", "/acc\0ount", "secret-value"),
      "value" => (".example.test", "session", "/account", "secret\0-value"),
      _ => panic!("unsupported fixture field {field}"),
    };
    let cookie = build_cookie_record(&FixtureCookie {
      domain,
      name,
      path,
      value,
      flags: 0,
      expires: 0.0,
    });
    let bad_page = build_page(&[cookie]);
    if !include_valid {
      return build_file(&[bad_page]);
    }
    let good = build_cookie_record(&FixtureCookie {
      domain: ".good.test",
      name: "good",
      path: "/",
      value: "kept",
      flags: 0,
      expires: 0.0,
    });
    build_file(&[bad_page, build_page(&[good])])
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
    let (cookies, records, stats, row_error) =
      parse_content(&golden_fixture()).expect("parse golden fixture");
    assert_eq!(cookies.len(), 1);
    assert_eq!(stats.records_seen, 1);
    assert_eq!(stats.records_skipped, 0);
    assert!(row_error.is_none());

    let cookie = &cookies[0];
    assert_eq!(cookie.domain, ".example.test");
    assert_eq!(cookie.name, "session");
    assert_eq!(cookie.path, "/account");
    assert_eq!(cookie.value, "secret-value");
    assert!(cookie.secure);
    assert!(cookie.http_only);
    assert_eq!(cookie.expires, Some(1_728_307_200));
    assert_eq!(cookie.same_site, SAME_SITE_UNSPECIFIED);
    assert_eq!(records.len(), 1);
    assert!(matches!(
      records[0].attributes.raw_expires,
      crate::browser::cookie_record::Observation::Known(RawValue::FloatBits(_))
    ));
    assert!(matches!(
      records[0].raw.get("flags"),
      Some(RawValue::Unsigned(_))
    ));
    assert!(matches!(
      records[0].attributes.same_site,
      Observation::Missing
    ));
    assert_eq!(records[0].origin.ordinal, 0);
  }

  #[test]
  fn non_finite_expiry_is_unknown_metadata_not_a_malformed_record() {
    let record = build_cookie_record(&FixtureCookie {
      domain: ".expiry.test",
      name: "non-finite",
      path: "/",
      value: "protected",
      flags: 0,
      expires: f64::NAN,
    });
    let (cookies, records, stats, row_error) =
      parse_content(&build_file(&[build_page(&[record])])).expect("retain unknown expiry");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].expires, None);
    assert_eq!(stats.records_seen, 1);
    assert_eq!(stats.records_skipped, 0);
    assert!(row_error.is_none());
    assert!(matches!(
      records[0].attributes.expires,
      Observation::Unknown(RawValue::FloatBits(_))
    ));
  }

  #[test]
  fn timeout_after_valid_page_is_not_caught_as_malformed_later_input() {
    const SENTINEL: &str = "rookie-safari-timeout-sentinel";
    let page = |name: &'static str, value: &'static str| {
      build_page(&[build_cookie_record(&FixtureCookie {
        domain: ".deadline.test",
        name,
        path: "/",
        value,
        flags: 0,
        expires: 0.0,
      })])
    };
    let bytes = SecretBytes::new(build_file(&[page("first", SENTINEL), page("later", "two")]));
    let clock = TickClock::default();
    let runtime = BoundaryRuntime::new(&clock, Deadline::after(&clock, Duration::from_secs(6)));
    let error = parse_content_records_with_runtime(bytes.as_slice(), &runtime)
      .expect_err("the second page starts at the deadline");
    assert_eq!(
      error.downcast_ref::<BoundaryStop>(),
      Some(&BoundaryStop::TimedOut)
    );
    assert!(error.downcast_ref::<SafariParseFailure>().is_none());
    assert!(!format!("{error:#}").contains(SENTINEL));
  }

  #[test]
  fn final_deadline_check_prevents_success_after_last_valid_page() {
    let page = build_page(&[build_cookie_record(&FixtureCookie {
      domain: ".deadline.test",
      name: "only",
      path: "/",
      value: "protected",
      flags: 0,
      expires: 0.0,
    })]);
    let clock = TickClock::default();
    let runtime = BoundaryRuntime::new(&clock, Deadline::after(&clock, Duration::from_secs(6)));
    let error = parse_content_records_with_runtime(&build_file(&[page]), &runtime)
      .expect_err("the final checkpoint reaches the deadline");
    assert_eq!(
      error.downcast_ref::<BoundaryStop>(),
      Some(&BoundaryStop::TimedOut)
    );
  }

  #[test]
  fn domain_filtered_cookies_are_excluded_from_request_row_counters() {
    let directory = crate::utils::TempDir::new().expect("temporary Safari fixture directory");
    let path = directory.path().join("Cookies.binarycookies");
    fs::write(&path, golden_fixture()).expect("write Safari fixture");

    let extraction = safari_based_outcome(
      direct_path_candidate(&path),
      Some(vec!["not-the-cookie-domain.invalid".to_owned()]),
    )
    .expect("filter Safari fixture");
    assert!(extraction.cookies().is_empty());
    assert_eq!(extraction.stats.rows_seen, 0);
    assert_eq!(extraction.stats.rows_skipped, 0);
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

    let (cookies, _records, stats, row_error) =
      parse_content(&build_file(&[page])).expect("retain good record");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "good");
    assert_eq!(cookies[0].value, "kept");
    assert_eq!(stats.records_seen, 2);
    assert_eq!(stats.records_skipped, 1);
    assert_eq!(stats.records_rejected, 1);
    assert!(row_error.is_some());
  }

  #[test]
  fn embedded_nul_fields_are_rejected_as_malformed_records() {
    for field in ["domain", "name", "path", "value"] {
      let error = parse_content(&embedded_nul_fixture(field, false))
        .expect_err("an all-malformed Safari file follows the existing failure rule");
      let rendered = format!("{error:#}");
      assert!(
        rendered.contains("c string contains embedded NUL"),
        "unexpected {field} error: {rendered}"
      );
      let failure = error
        .downcast_ref::<SafariParseFailure>()
        .expect("malformed record retains row accounting");
      assert_eq!(failure.stats.records_seen, 1, "{field}");
      assert_eq!(failure.stats.records_skipped, 1, "{field}");
      assert_eq!(failure.stats.records_rejected, 1, "{field}");
    }
  }

  #[test]
  fn embedded_nul_record_does_not_discard_a_valid_cookie() {
    for field in ["domain", "name", "path", "value"] {
      let fixture = embedded_nul_fixture(field, true);
      let (cookies, _records, stats, row_error) =
        parse_content(&fixture).expect("retain the valid Safari record");
      assert_eq!(cookies.len(), 1, "{field}");
      assert_eq!(cookies[0].domain, ".good.test", "{field}");
      assert_eq!(cookies[0].name, "good", "{field}");
      assert_eq!(cookies[0].path, "/", "{field}");
      assert_eq!(cookies[0].value, "kept", "{field}");
      assert_eq!(stats.records_seen, 2, "{field}");
      assert_eq!(stats.records_skipped, 1, "{field}");
      assert_eq!(stats.records_rejected, 1, "{field}");
      assert!(
        row_error
          .expect("malformed record is reported")
          .to_string()
          .contains("Failed to parse Safari cookie record"),
        "{field}"
      );
    }
  }

  #[test]
  fn cookie_record_with_trailing_bplist_metadata_is_parsed_successfully() {
    let mut record = build_cookie_record(&FixtureCookie {
      domain: ".example.test",
      name: "session",
      path: "/account",
      value: "secret-value",
      flags: 0x01 | 0x04,
      expires: 750_000_000.0,
    });
    // Append bplist metadata as modern Safari does
    let bplist_payload = b"bplist00\xd1\x01\x02ZAccessTime#A\xc8\x19\xc3\x8d\xa4\xc3\xa0\x08\x0b\x16\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f";
    record.extend_from_slice(bplist_payload);
    let record_len = u32::try_from(record.len()).expect("record length");
    LittleEndian::write_u32(&mut record[0x00..0x04], record_len);

    let (cookies, _records, stats, row_error) =
      parse_content(&build_file(&[build_page(&[record])])).expect("parse cookie with bplist");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].value, "secret-value");
    assert_eq!(stats.records_seen, 1);
    assert_eq!(stats.records_skipped, 0);
    assert!(row_error.is_none());
  }

  #[test]
  fn cookie_record_with_trailing_null_padding_is_parsed_successfully() {
    let mut record = build_cookie_record(&FixtureCookie {
      domain: ".example.test",
      name: "session",
      path: "/account",
      value: "secret-value",
      flags: 0x01 | 0x04,
      expires: 750_000_000.0,
    });
    // Append 8 null padding bytes
    record.extend_from_slice(&[0; 8]);
    let record_len = u32::try_from(record.len()).expect("record length");
    LittleEndian::write_u32(&mut record[0x00..0x04], record_len);

    let (cookies, _records, stats, row_error) =
      parse_content(&build_file(&[build_page(&[record])])).expect("parse cookie with null padding");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].value, "secret-value");
    assert_eq!(stats.records_seen, 1);
    assert_eq!(stats.records_skipped, 0);
    assert!(row_error.is_none());
  }

  #[test]
  fn malformed_page_does_not_discard_cookie_from_another_page() {
    let bad_records = [
      build_cookie_record(&FixtureCookie {
        domain: ".bad-one.test",
        name: "bad-one",
        path: "/",
        value: "discarded",
        flags: 0,
        expires: 0.0,
      }),
      build_cookie_record(&FixtureCookie {
        domain: ".bad-two.test",
        name: "bad-two",
        path: "/",
        value: "discarded",
        flags: 0,
        expires: 0.0,
      }),
    ];
    let mut bad_page = build_page(&bad_records);
    bad_page[0] = 0xff;
    let good_page = build_page(&[build_cookie_record(&FixtureCookie {
      domain: ".good.test",
      name: "good-page",
      path: "/",
      value: "kept",
      flags: 0,
      expires: 0.0,
    })]);

    let (cookies, _records, stats, row_error) =
      parse_content(&build_file(&[bad_page, good_page])).expect("retain good page");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "good-page");
    assert_eq!(stats.records_seen, 3);
    assert_eq!(stats.records_skipped, 2);
    assert!(row_error.is_some());
  }

  #[test]
  fn page_too_short_for_a_record_count_is_still_counted_and_reported() {
    let truncated_page = vec![0x00, 0x00, 0x01, 0x00];
    let good_page = build_page(&[build_cookie_record(&FixtureCookie {
      domain: ".example.com",
      name: "good-page",
      path: "/",
      value: "kept",
      flags: 0,
      expires: 0.0,
    })]);

    let (cookies, _records, stats, row_error) =
      parse_content(&build_file(&[truncated_page, good_page]))
        .expect("a later valid page remains recoverable");
    assert_eq!(cookies.len(), 1);
    assert_eq!(stats.records_seen, 2);
    assert_eq!(stats.records_skipped, 1);
    assert!(row_error.is_some());
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
    let failure = error
      .downcast_ref::<SafariParseFailure>()
      .expect("parse failure retains record accounting");
    assert_eq!(failure.stats.records_seen, 2);
    assert_eq!(failure.stats.records_skipped, 2);
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
    let count = MAX_RECOVERABLE_RECORD_ERRORS_PER_PAGE + 11;
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

    let (cookies, _records, stats, error) = parse_page(&page).expect("page framing remains valid");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "good-before-limit");
    assert_eq!(stats.records_seen, count);
    assert_eq!(stats.records_skipped, count - 1);
    let error = error.expect("recovery limit should be reported");
    assert!(
      format!("{error:#}").contains("recovery limit reached after 1024 malformed records"),
      "unexpected recovery error: {error:#}"
    );
    assert!(
      format!("{error:#}").contains("10 remaining record(s) were skipped without parsing"),
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
    let diagnostic = format!("{error:#}");
    assert!(diagnostic.contains("too large"));
    assert!(diagnostic.contains(REDACTED_PATH));
    assert!(!diagnostic.contains(path.to_string_lossy().as_ref()));
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
    let (image, attempts) = image;
    assert_eq!(image.as_slice(), new);
    // The first attempt saw the file change underneath it, so the stable image
    // came from the retry -- the count the report must show.
    assert_eq!(attempts, 2);
    fs::remove_dir_all(&directory).expect("remove fixture directory");
  }

  #[test]
  fn stable_read_retries_same_length_in_place_rewrite_with_preserved_mtime() {
    let unique = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .expect("system clock")
      .as_nanos();
    let path = std::env::temp_dir().join(format!(
      "rookie-safari-in-place-rewrite-{}-{unique}.binarycookies",
      std::process::id()
    ));
    let old = golden_fixture();
    let mut new = old.clone();
    new[0] = b'X';
    fs::write(&path, &old).expect("write original image");
    let original_mtime = fs::metadata(&path)
      .expect("inspect original image")
      .modified()
      .expect("read original mtime");

    let mut file = File::open(&path).expect("open original image");
    let mut rewrite_once = true;
    let image = read_stable_cookie_file_with(&mut file, &path, || {
      if rewrite_once {
        rewrite_once = false;
        fs::write(&path, &new).expect("rewrite same-length image");
        File::options()
          .write(true)
          .open(&path)
          .expect("reopen rewritten image for metadata update")
          .set_times(fs::FileTimes::new().set_modified(original_mtime))
          .expect("restore original mtime");
      }
    })
    .expect("retry and acquire rewritten image");
    let (image, attempts) = image;
    assert_eq!(image.as_slice(), new);
    assert_eq!(attempts, 2);
    fs::remove_file(&path).expect("remove fixture");
  }
  #[cfg(target_os = "macos")]
  #[test]
  fn parses_real_safari_cookies_if_present() {
    if let Some(home) = std::env::var_os("HOME") {
      let path = PathBuf::from(home)
        .join("Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies");
      if path.exists() {
        if let Ok(data) = std::fs::read(&path) {
          let (_cookies, _records, stats, row_error) =
            parse_content(&data).expect("parse real safari cookies");
          assert_eq!(stats.records_skipped, 0);
          assert!(row_error.is_none());
        }
      }
    }
  }
}
