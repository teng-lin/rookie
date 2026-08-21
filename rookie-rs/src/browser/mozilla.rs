#[cfg(test)]
use crate::common::boundary::{Decoder, ReadOnlySource};
#[cfg(test)]
use crate::common::deadline::{Clock, Deadline};
use crate::common::{
  deadline::{BoundaryRuntime, BoundaryStop, SystemClock},
  enums::*,
  sqlite,
};
#[cfg(test)]
use anyhow::bail;
use anyhow::Result;
#[cfg(test)]
use serde_json::Value;
use std::path::{Path, PathBuf};

use super::cookie_record::CookieRecord;
#[cfg(test)]
use super::cookie_record::{Observation, RawValue};
pub(crate) use super::mozilla_persistent::query_persistent_cookies_with_runtime;
#[cfg(test)]
pub(crate) use super::mozilla_persistent::{
  query_persistent_cookies, query_persistent_cookies_mode, MozillaPersistentDecodeSummary,
  MozillaPersistentDecoder, MozillaPersistentReadOnlySource,
};
pub(crate) use super::mozilla_profiles::list_profiles_from_str;
pub use super::mozilla_profiles::MozillaProfile;
#[cfg(test)]
pub(crate) use super::mozilla_profiles::{list_profiles, select_profile};
#[cfg(test)]
pub(crate) use super::mozilla_session::{
  create_cookie_record, decompress_session_store, firefox_session_cookie_context,
  get_session_cookies, get_session_cookies_lz4, parse_legacy_session_cookies,
  parse_session_candidate_with, parse_session_candidate_with_runtime, parse_session_cookies_lz4,
  parse_session_json, parse_session_json_with_runtime, read_stable_session_file,
  session_cookie_expiry, MozillaSessionDecodeSummary, MozillaSessionDecoder,
  MozillaSessionReadOnlySource,
};
pub(crate) use super::mozilla_session::{
  is_missing_session_file, parse_session_path_with_runtime, SessionCookieParseDraft,
};
use super::registry::PERSISTENT_SOURCE_PRECEDENCE;
use super::report_core::{CookieSourceFormatId, CookieSourceRoleId};
use super::source::{
  Source, SourceAcquisition, SourceCandidate, SourceFailureStage, SourceIdentity, SourceStats,
};

// Firefox 142 migrated schema 15 to 16 by multiplying persistent cookie
// expiry values by 1000 (https://bugzilla.mozilla.org/show_bug.cgi?id=1972757).
pub(crate) const FIREFOX_MILLISECOND_EXPIRY_SCHEMA_VERSION: u32 = 16;

// Session state is untrusted profile data. Keep both the on-disk read and the
// mozLz4-advertised output below a size large enough for real Firefox profiles
// while preventing one corrupt four-byte size prefix from requesting gigabytes.
pub(crate) const MAX_SESSION_STORE_BYTES: usize = 64 * 1024 * 1024;

// Sessionstore has no schema/version field that identifies an expiry unit, and
// its unit cannot be inferred from cookies.sqlite: an observed Firefox 141
// profile used seconds in schema-15 SQLite rows while its recovery.jsonlz4 used
// milliseconds. Values through year 2286 remain plausible Unix seconds; values
// from 10^12 through the same upper instant are plausible Unix milliseconds.
// The scale gap is deliberately rejected instead of guessed. Missing/zero
// expiry is always a genuine session cookie.
pub(crate) const MAX_PLAUSIBLE_SESSION_EXPIRY_SECONDS: u64 = 9_999_999_999;
pub(crate) const MIN_PLAUSIBLE_SESSION_EXPIRY_MILLISECONDS: u64 = 1_000_000_000_000;
pub(crate) const MAX_PLAUSIBLE_SESSION_EXPIRY_MILLISECONDS: u64 =
  MAX_PLAUSIBLE_SESSION_EXPIRY_SECONDS * 1000 + 999;

/// Returns cookies from mozilla based browsers
#[deprecated(
  since = "0.6.0",
  note = "use direct_path::extract_from_path with PathExtractRequest"
)]
pub fn firefox_based(db_path: PathBuf, domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  firefox_based_with_runtime(db_path, domains, &runtime)
}

pub(crate) fn firefox_based_with_runtime(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  let outcome = query_cookies_engine_outcome_with_runtime(&db_path, domains.as_deref(), runtime);
  super::legacy::project_canonical_outcome_with_runtime(
    "firefox",
    super::report_build::finalize_singleton_source(
      "firefox",
      db_path.parent().unwrap_or(&db_path).to_path_buf(),
      outcome.sources,
      outcome.boundary_stop,
      Some(runtime),
    )?,
    runtime,
  )
}

/// Returns cookies from a Mozilla profile with container and origin attributes
/// preserved.
#[deprecated(
  since = "0.6.0",
  note = "the canonical direct-path API returns legacy Cookie values; this compatibility function remains through 0.6"
)]
pub fn firefox_based_detailed(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
) -> Result<Vec<DetailedCookie>> {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  firefox_based_detailed_with_runtime(db_path, domains, &runtime)
}

pub(crate) fn firefox_based_detailed_with_runtime(
  db_path: PathBuf,
  domains: Option<Vec<String>>,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<DetailedCookie>> {
  let outcome = query_cookies_engine_outcome_with_runtime(&db_path, domains.as_deref(), runtime);
  super::legacy::project_canonical_detailed_outcome_with_runtime(
    "firefox",
    super::report_build::finalize_singleton_source(
      "firefox",
      db_path.parent().unwrap_or(&db_path).to_path_buf(),
      outcome.sources,
      outcome.boundary_stop,
      Some(runtime),
    )?,
    runtime,
  )
}

pub(crate) fn firefox_cookie_context(origin_attributes: Option<String>) -> CookieContext {
  let mut context = CookieContext {
    origin_attributes,
    ..CookieContext::default()
  };
  let Some(attributes) = context.origin_attributes.as_deref() else {
    return context;
  };
  for (name, value) in url::form_urlencoded::parse(
    attributes
      .strip_prefix('^')
      .unwrap_or(attributes)
      .as_bytes(),
  ) {
    match name.as_ref() {
      "userContextId" => context.user_context_id = value.parse().ok(),
      "partitionKey" => context.partition_key = Some(value.into_owned()),
      "privateBrowsingId" => context.private_browsing_id = value.parse().ok(),
      _ => {}
    }
  }
  context
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionStoreFormat {
  JsonLz4,
  LegacyJson,
}

/// Source-format identifiers this engine can emit. They are declared once here
/// and asserted against the registry's declared capabilities, so an emitted
/// format can never drift away from what a browser definition claims.
pub(crate) const PERSISTENT_FORMAT_ID: &str = "mozilla_sqlite";
pub(crate) const SESSION_JSONLZ4_FORMAT_ID: &str = "firefox_session_jsonlz4";
pub(crate) const SESSION_JSON_FORMAT_ID: &str = "firefox_session_json";

impl SessionStoreFormat {
  pub(crate) fn format_id(self) -> &'static str {
    match self {
      Self::JsonLz4 => SESSION_JSONLZ4_FORMAT_ID,
      Self::LegacyJson => SESSION_JSON_FORMAT_ID,
    }
  }

  /// Recovers the parse format from a planted candidate's format id, so a
  /// candidate-driven caller can hand back exactly what listing planted from
  /// [`SESSION_CANDIDATES`] without carrying a parallel enum.
  pub(crate) fn from_format_id(format_id: &str) -> Option<Self> {
    match format_id {
      SESSION_JSONLZ4_FORMAT_ID => Some(Self::JsonLz4),
      SESSION_JSON_FORMAT_ID => Some(Self::LegacyJson),
      _ => None,
    }
  }
}

/// Section 7 session candidates in authoritative order (ADR 0001 §8, frozen),
/// as profile-relative paths. This is the single source of truth: registry
/// listing plants a [`SourceCandidate`] for each existing entry in this order,
/// extraction acquires them in this order, and the direct path walks the same
/// array, so a candidate can never be added to one and missed by the other.
pub(crate) const SESSION_CANDIDATES: [(&str, SessionStoreFormat); 5] = [
  (
    "sessionstore-backups/recovery.jsonlz4",
    SessionStoreFormat::JsonLz4,
  ),
  (
    "sessionstore-backups/recovery.baklz4",
    SessionStoreFormat::JsonLz4,
  ),
  ("sessionstore.jsonlz4", SessionStoreFormat::JsonLz4),
  ("sessionstore.js", SessionStoreFormat::LegacyJson),
  (
    "sessionstore-backups/previous.jsonlz4",
    SessionStoreFormat::JsonLz4,
  ),
];

/// Declared precedence of a session candidate at `index` in
/// [`SESSION_CANDIDATES`], so reports order attempted candidates by declaration
/// rather than by which ones happened to exist.
pub(crate) fn session_candidate_precedence(index: usize) -> u16 {
  SESSION_CANDIDATE_PRECEDENCE_STEP.saturating_mul(index as u16 + 1)
}

pub(crate) const SESSION_STORE_READ_ATTEMPTS: usize = 2;
const SESSION_CANDIDATE_PRECEDENCE_STEP: u16 = 10;
pub(crate) const MAX_SESSION_COOKIE_DIAGNOSTICS: usize = 8;

#[derive(Debug)]
pub(crate) struct SessionCandidateSuccess {
  pub(crate) parsed: SessionCookieParseDraft,
  pub(crate) attempts: u32,
  pub(crate) transient_errors: Vec<String>,
}

/// Failure counterpart of [`SessionCandidateSuccess`]. Retry diagnostics are
/// carried on both paths so a candidate that never succeeded still reports why
/// each attempt failed.
#[derive(Debug)]
pub(crate) struct SessionCandidateFailure {
  pub(crate) error: anyhow::Error,
  pub(crate) attempts: u32,
  pub(crate) transient_errors: Vec<String>,
}

/// File-private scratch for one acquired session candidate. It names the same
/// facts [`Source`] does, and [`session_source`] converts it at the engine
/// boundary; nothing outside this module sees it.
#[derive(Debug)]
struct MozillaSessionDraft {
  /// Declared candidate precedence from [`session_candidate_precedence`],
  /// retained so a report orders attempted candidates by declaration rather
  /// than by which ones happened to exist.
  selected: bool,
  records: Vec<CookieRecord>,
  rows_seen: usize,
  rows_skipped: usize,
  rows_rejected: usize,
  acquisition_attempts: u32,
  diagnostics: Vec<String>,
  error: Option<String>,
}

/// File-private scratch for one attempted persistent acquisition. It is
/// converted to a [`Source`] by [`persistent_source`]; a boundary stop before
/// the acquisition reached an atomic success or ordinary failure never
/// produces one of these, so a stop cannot turn into a successful zero-row
/// outcome.
#[derive(Debug, Default)]
struct MozillaPersistentDraft {
  records: Vec<CookieRecord>,
  rows_seen: usize,
  rows_skipped: usize,
  rows_rejected: usize,
  acquisition_strategy: Option<sqlite::DatabaseAcquisitionStrategy>,
  acquisition_attempts: u32,
  /// Acquisition, schema validation, or the query did not complete, so the
  /// source failed outright. A source that produced rows is never reported
  /// through this field, so a caller can tell total failure from partial
  /// success.
  error: Option<String>,
  /// Which of those it was, taken from the SQLite layer's typed failure rather
  /// than assumed.
  failure_kind: Option<sqlite::BrowserDatabaseFailureKind>,
  /// A row was seen and rejected while the source itself stayed readable.
  /// Section 5.7 counts this in `rows_skipped` and reports it as a row issue
  /// against a source that still succeeded, which is why it is deliberately
  /// separate from `error`.
  row_error: Option<String>,
}

/// The crate-visible result of acquiring one Mozilla source candidate.
///
/// `Missing` is deliberately not a `Source`: Section 7 makes a missing session
/// candidate silent, and a candidate that vanished between discovery and query
/// is missing however it got there -- its retry diagnostics are dropped on
/// purpose. Termination stays a typed boundary result rather than a fabricated
/// source or flattened diagnostic.
// One outcome exists per acquired candidate and is consumed immediately by
// selection; keeping the source inline avoids a heap allocation per source.
#[allow(clippy::large_enum_variant)]
pub(crate) enum MozillaCandidateOutcome {
  /// The candidate was read (successfully, `selected: true`) or was present
  /// but failed (`selected: false` with the failure recorded on the source).
  Source(Source),
  /// The candidate does not exist. Not an outcome: absence is normal.
  Missing,
  Stop(BoundaryStop),
}

/// The crate-visible result of extracting one Mozilla profile: the sources the
/// walk produced and any boundary stop it observed.
///
/// Sources are in walk order: the persistent source first, then each session
/// candidate in [`SESSION_CANDIDATES`] order.
///
/// The persistent source is present iff the query was attempted, which is all
/// this engine can know. It is *not* the same as "the profile has a persistent
/// store": a session-only profile with no `cookies.sqlite` still attempts the
/// query and so still gets a failed persistent source here. Whether that
/// survives into a report is the adapter's half of the decision --
/// [`super::registry::gecko::populate_gecko_sources`] drops it for a profile
/// that neither discovered a persistent store nor still has one on disk, which
/// is knowledge only the listing and the filesystem have. The direct path keeps
/// every source, because it has no discovery and "attempted" is its whole gate.
pub(crate) struct MozillaExtract {
  pub(crate) sources: Vec<Source>,
  pub(crate) boundary_stop: Option<BoundaryStop>,
}

/// Builds the persistent [`Source`] for a queried Gecko profile.
///
/// `selected: true` because a profile's authoritative persistent store is
/// always the selected source. Records are the only supply of finalized rows,
/// so `cookies_emitted` counts them rather than any cookie list.
fn persistent_source(origin: SourceIdentity, draft: MozillaPersistentDraft) -> Source {
  let acquisition: SourceAcquisition = draft.acquisition_strategy.into();
  let records = draft.records;
  let cookies_emitted = records.len();
  let mut source = Source {
    origin,
    // Effective, not inherited: a profile's authoritative persistent store is
    // always its selected source, even though the listing plants `false`.
    selected: true,
    acquisition,
    records,
    stats: SourceStats {
      rows_seen: draft.rows_seen,
      cookies_emitted,
      rows_skipped: draft.rows_skipped,
      rows_rejected: draft.rows_rejected,
      provider_failures: 0,
    },
    acquisition_attempts: draft.acquisition_attempts,
    // `diagnostics` carries acquisition retry notes, which a report renders as a
    // warning meaning "retried, then succeeded". A rejected row is neither a
    // retry nor a recovery — rows were lost — so it must not be reported that
    // way; `push_row_read_failed` raises it as an error-severity row failure.
    diagnostics: Vec::new(),
    failure: None,
    issues: Vec::new(),
  };
  if let Some(error) = draft.error {
    // The stage is taken from the SQLite layer's typed failure kind rather than
    // assumed: `stage` is a frozen report field consumers read to choose a
    // remedy, and a query that failed after the database opened is not an
    // acquisition failure.
    let stage = match draft.failure_kind {
      Some(sqlite::BrowserDatabaseFailureKind::Query) => SourceFailureStage::Query,
      _ => SourceFailureStage::Acquisition,
    };
    source.fail(stage, error);
  }
  source.push_row_read_failed(draft.row_error);
  source
}

/// Builds a session [`Source`] from one walked Mozilla session candidate.
///
/// A session candidate fails by being unreadable as JSON/LZ4, which is a parse
/// failure, not an acquisition one. Its rejected rows are already counted in
/// `rows_skipped` and described by `diagnostics`, so it carries no row error.
fn session_source(origin: SourceIdentity, session: MozillaSessionDraft) -> Source {
  let mut source = Source {
    origin,
    // Effective only: first-valid selection is decided by reading, so it must
    // never be written back as though discovery had decided it.
    selected: session.selected,
    acquisition: SourceAcquisition::StableFileImage,
    records: session.records,
    stats: SourceStats {
      rows_seen: session.rows_seen,
      cookies_emitted: 0,
      rows_skipped: session.rows_skipped,
      rows_rejected: session.rows_rejected,
      provider_failures: 0,
    },
    acquisition_attempts: session.acquisition_attempts,
    diagnostics: session.diagnostics,
    failure: None,
    issues: Vec::new(),
  };
  source.stats.cookies_emitted = source.records.len();
  // A session candidate never keeps a row error, but rows it rejected still
  // cost cookies. The issue is keyed on the count, not on the presence of an
  // error string: raising it only when an engine happened to keep one lets a
  // report claim `complete` while cookies were dropped. (invariants (b), (c))
  source.push_row_read_failed(None);
  if let Some(error) = session.error {
    source.fail(SourceFailureStage::Parse, error);
  }
  source
}

/// Extract a Mozilla profile with the same authoritative session ordering as
/// `firefox_based`, retaining diagnostics which the legacy API intentionally
/// only logs. Missing session candidates are not outcomes: absence is normal.
///
/// Production callers thread a runtime through
/// [`query_cookies_engine_outcome_with_runtime`]; this standard-runtime
/// wrapper remains for the walk's characterization tests.
#[cfg(test)]
pub(crate) fn query_cookies_engine_outcome(
  db_path: &Path,
  domains: Option<&[String]>,
) -> MozillaExtract {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  query_cookies_engine_outcome_with_runtime(db_path, domains, &runtime)
}

pub(crate) fn query_cookies_engine_outcome_with_runtime(
  db_path: &Path,
  domains: Option<&[String]>,
  runtime: &BoundaryRuntime<'_>,
) -> MozillaExtract {
  query_cookies_engine_outcome_with_session_probe(
    db_path,
    domains,
    runtime,
    parse_session_path_with_runtime,
  )
}

/// The direct-path walk: the persistent acquisition followed by first-valid
/// selection over every [`SESSION_CANDIDATES`] entry, each acquired as its own
/// [`Source`]. The registry path does not come through here -- it drives the
/// same per-candidate acquisitions from the candidates its listing planted
/// (`populate_gecko_sources`) -- but both share [`select_session_sources`], so
/// the first-valid rule cannot fork.
///
/// The persistent source is emitted first, then the session sources in
/// declared order. Both facts are load-bearing: the adapter completes the
/// persistent gate (see [`MozillaExtract`]), and the report orders sources by
/// role and precedence, so producing them out of walk order would reshuffle
/// equal keys under a stable sort.
fn query_cookies_engine_outcome_with_session_probe<P>(
  db_path: &Path,
  domains: Option<&[String]>,
  runtime: &BoundaryRuntime<'_>,
  mut probe_session: P,
) -> MozillaExtract
where
  P: FnMut(
    &Path,
    SessionStoreFormat,
    Option<&[String]>,
    &BoundaryRuntime<'_>,
  ) -> std::result::Result<SessionCandidateSuccess, SessionCandidateFailure>,
{
  let mut sources = Vec::new();
  // A direct path did no discovery, so there is no candidate to take an
  // identity from -- this states the one the named file implies. It is an
  // identity, not a synthetic candidate: there are no listing decisions to
  // invent, which is the whole reason `origin` narrowed.
  let persistent_origin = SourceIdentity {
    path: db_path.to_path_buf(),
    role: CookieSourceRoleId::persistent(),
    format: CookieSourceFormatId::known(PERSISTENT_FORMAT_ID),
    precedence: PERSISTENT_SOURCE_PRECEDENCE,
  };
  match acquire_persistent_source_with_runtime(persistent_origin, domains, runtime) {
    Ok(source) => sources.push(source),
    // A stop before the persistent acquisition reached an atomic success or
    // ordinary failure: nothing was attempted, so nothing is a source and the
    // session candidates are never reached.
    Err(stop) => {
      return MozillaExtract {
        sources,
        boundary_stop: Some(stop),
      }
    }
  }
  let cookies_dir = db_path.parent().unwrap_or_else(|| Path::new(""));
  let outcomes = SESSION_CANDIDATES
    .into_iter()
    .enumerate()
    .map(|(index, (relative, format))| {
      if let Err(stop) = runtime.check() {
        return MozillaCandidateOutcome::Stop(stop);
      }
      let path = cookies_dir.join(relative);
      let probed = probe_session(&path, format, domains, runtime);
      // Same identity keys the registry listing would have planted for this
      // relative path, so the wire join keys are unchanged.
      let origin = SourceIdentity {
        path,
        role: CookieSourceRoleId::session(),
        format: CookieSourceFormatId::known(format.format_id()),
        precedence: session_candidate_precedence(index),
      };
      session_outcome_from_probe(origin, probed)
    });
  let boundary_stop =
    select_session_sources(outcomes, &mut sources).or_else(|| runtime.check().err());
  MozillaExtract {
    sources,
    boundary_stop,
  }
}

/// The first-valid selection rule over session candidate outcomes, shared by
/// the direct-path walk and the registry's candidate-driven populate.
///
/// Failed-but-present candidates are pushed (`selected: false`) and iteration
/// continues; a missing candidate pushes nothing; the first successful
/// candidate (`selected: true`) is pushed and iteration stops **without
/// pulling further outcomes**, so later candidates are never acquired -- the
/// iterator must be lazy for that guarantee to mean anything. At most one
/// pushed source can therefore be selected. A boundary stop ends the selection
/// and is returned.
pub(crate) fn select_session_sources(
  outcomes: impl Iterator<Item = MozillaCandidateOutcome>,
  sources: &mut Vec<Source>,
) -> Option<BoundaryStop> {
  for outcome in outcomes {
    match outcome {
      MozillaCandidateOutcome::Source(source) => {
        let selected = source.selected;
        sources.push(source);
        if selected {
          return None;
        }
      }
      MozillaCandidateOutcome::Missing => {}
      MozillaCandidateOutcome::Stop(stop) => return Some(stop),
    }
  }
  None
}

/// Acquires a profile's persistent `cookies.sqlite` as its own [`Source`].
///
/// `Ok` means the acquisition was attempted -- the returned source may still
/// carry a failure. `Err` is a boundary stop observed before the attempt
/// reached an atomic success or ordinary failure; it must not become a
/// successful zero-row source.
pub(crate) fn acquire_persistent_source_with_runtime(
  origin: SourceIdentity,
  domains: Option<&[String]>,
  runtime: &BoundaryRuntime<'_>,
) -> std::result::Result<Source, BoundaryStop> {
  let db_path = origin.path.clone();
  let mut draft = MozillaPersistentDraft::default();
  match sqlite::with_browser_database_with_runtime(
    db_path.clone(),
    |connection| query_persistent_cookies_with_runtime(connection, domains, runtime),
    runtime,
  ) {
    Ok(database) => {
      draft.acquisition_strategy = Some(database.strategy());
      draft.acquisition_attempts = database.attempts();
      let persistent = database.into_value();
      draft.rows_seen = persistent.rows_seen;
      draft.rows_skipped = persistent.rows_skipped;
      draft.rows_rejected = persistent.rows_rejected;
      draft.row_error = persistent.last_row_error.map(|error| format!("{error:#}"));
      draft.records = persistent.records;
    }
    Err(error) => {
      if let Some(stop) = error.downcast_ref::<BoundaryStop>() {
        return Err(*stop);
      }
      if let Some(failure) = error.downcast_ref::<sqlite::BrowserDatabaseFailure>() {
        draft.acquisition_strategy = failure.strategy;
        draft.acquisition_attempts = failure.attempts;
        draft.failure_kind = Some(failure.kind);
      } else {
        draft.acquisition_attempts = 1;
      }
      draft.error = Some(format!("{error:#}"));
    }
  }
  Ok(persistent_source(origin, draft))
}

/// Acquires one session candidate as its own [`Source`].
///
/// The runtime is sampled before the read, matching the per-candidate check
/// the walk performs, so a stop between candidates is observed before the next
/// one is touched.
pub(crate) fn acquire_session_source_with_runtime(
  origin: SourceIdentity,
  format: SessionStoreFormat,
  domains: Option<&[String]>,
  runtime: &BoundaryRuntime<'_>,
) -> MozillaCandidateOutcome {
  if let Err(stop) = runtime.check() {
    return MozillaCandidateOutcome::Stop(stop);
  }
  let probed = parse_session_path_with_runtime(&origin.path, format, domains, runtime);
  session_outcome_from_probe(origin, probed)
}

/// Converts one probed session candidate into its [`MozillaCandidateOutcome`].
fn session_outcome_from_probe(
  origin: SourceIdentity,
  probed: std::result::Result<SessionCandidateSuccess, SessionCandidateFailure>,
) -> MozillaCandidateOutcome {
  match probed {
    Ok(success) => {
      let mut diagnostics = success.transient_errors;
      diagnostics.extend(success.parsed.diagnostics);
      MozillaCandidateOutcome::Source(session_source(
        origin,
        MozillaSessionDraft {
          selected: true,
          records: success.parsed.records,
          rows_seen: success.parsed.rows_seen,
          rows_skipped: success.parsed.rows_skipped,
          rows_rejected: success.parsed.rows_rejected,
          acquisition_attempts: success.attempts,
          diagnostics,
          error: None,
        },
      ))
    }
    // Section 7 makes a missing candidate silent, and a candidate whose final
    // state is "gone" is missing however it got there. Its retry diagnostics
    // are therefore dropped on purpose: a vanished candidate is not a source.
    Err(failure) if is_missing_session_file(&failure.error) => MozillaCandidateOutcome::Missing,
    Err(failure) => {
      if let Some(stop) = failure.error.downcast_ref::<BoundaryStop>() {
        return MozillaCandidateOutcome::Stop(*stop);
      }
      MozillaCandidateOutcome::Source(session_source(
        origin,
        MozillaSessionDraft {
          selected: false,
          records: Vec::new(),
          rows_seen: 0,
          rows_skipped: 0,
          rows_rejected: 0,
          acquisition_attempts: failure.attempts,
          diagnostics: failure.transient_errors,
          error: Some(format!("{:#}", failure.error)),
        },
      ))
    }
  }
}

/// Acquires one planted [`SourceCandidate`] as its own [`Source`], dispatching
/// on the candidate's role. This is the production query the candidate-driven
/// Gecko populate injects; only the candidate's path, role, format, and
/// precedence are read -- everything the resulting source reports is
/// re-derived from the read itself.
pub(crate) fn acquire_candidate_source(
  candidate: &SourceCandidate,
  domains: Option<&[String]>,
) -> MozillaCandidateOutcome {
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  acquire_candidate_source_with_runtime(candidate, domains, &runtime)
}

pub(crate) fn acquire_candidate_source_with_runtime(
  candidate: &SourceCandidate,
  domains: Option<&[String]>,
  runtime: &BoundaryRuntime<'_>,
) -> MozillaCandidateOutcome {
  if candidate.role == CookieSourceRoleId::persistent() {
    return match acquire_persistent_source_with_runtime(candidate.identity(), domains, runtime) {
      Ok(source) => MozillaCandidateOutcome::Source(source),
      Err(stop) => MozillaCandidateOutcome::Stop(stop),
    };
  }
  match SessionStoreFormat::from_format_id(candidate.format.as_str()) {
    Some(format) => {
      acquire_session_source_with_runtime(candidate.identity(), format, domains, runtime)
    }
    // Only this crate plants Mozilla candidates, and it plants exactly the
    // SESSION_CANDIDATES formats, so this is a programming error -- surfaced
    // as a failed source rather than silently skipped or panicked on.
    None => {
      let mut source = Source::new(
        candidate.identity(),
        candidate.selected,
        candidate.acquisition,
      );
      source.fail(
        SourceFailureStage::Parse,
        format!(
          "unrecognized Mozilla session store format {:?}",
          candidate.format.as_str()
        ),
      );
      MozillaCandidateOutcome::Source(source)
    }
  }
}

#[cfg(test)]
fn decode_persistent_gate_connection(
  connection: &rusqlite::Connection,
) -> Result<(MozillaPersistentDecodeSummary, Vec<CookieRecord>)> {
  let source = MozillaPersistentReadOnlySource {
    connection,
    domains: None,
  };
  let decoder = MozillaPersistentDecoder;
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  let mut records = Vec::new();
  let summary = decoder.decode(
    &source,
    &mut |record| {
      records.push(record);
      Ok(())
    },
    &runtime,
  )?;
  Ok((summary, records))
}

#[cfg(test)]
pub(super) fn structured_persistent_decoder_gate() -> Result<()> {
  use rusqlite::types::Value as SqlValue;

  const OPTIONAL_COLUMNS: [(&str, &str, usize); 6] = [
    ("path", "path", 1),
    ("isSecure", "secure", 2),
    ("expiry", "expiry", 3),
    ("isHttpOnly", "http_only", 6),
    ("sameSite", "same_site", 7),
    ("originAttributes", "origin_attributes", 8),
  ];
  let full_schema = "CREATE TABLE moz_cookies (
    host TEXT, path, isSecure, expiry, name TEXT, value TEXT,
    isHttpOnly, sameSite, originAttributes
  );";

  // Every row keeps the three required fields valid while exactly one
  // optional field changes shape. This reaches the raw-value branches and the
  // sink instead of having an early invalid `name` mask the rest of decoding.
  let connection = rusqlite::Connection::open_in_memory()?;
  connection.execute_batch(&format!("PRAGMA user_version = 15; {full_schema}"))?;
  let baseline = vec![
    SqlValue::Text(".example.com".to_owned()),
    SqlValue::Text("/".to_owned()),
    SqlValue::Integer(1),
    SqlValue::Integer(1_700_000_000),
    SqlValue::Text("baseline".to_owned()),
    SqlValue::Text("plain-value".to_owned()),
    SqlValue::Integer(1),
    SqlValue::Integer(1),
    SqlValue::Text("^userContextId=7".to_owned()),
  ];
  connection.execute(
    "INSERT INTO moz_cookies VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    rusqlite::params_from_iter(baseline.iter()),
  )?;
  for (index, (column, _, sqlite_index)) in OPTIONAL_COLUMNS.iter().enumerate() {
    let mut row = baseline.clone();
    row[4] = SqlValue::Text(format!("malformed-{column}"));
    row[*sqlite_index] = match *column {
      "path" | "expiry" => SqlValue::Blob(vec![0xff, index as u8]),
      "isSecure" => SqlValue::Text("sometimes".to_owned()),
      "isHttpOnly" => SqlValue::Real(0.5),
      "sameSite" => SqlValue::Integer(9),
      "originAttributes" => SqlValue::Integer(17),
      _ => unreachable!("the optional corpus is exhaustive"),
    };
    connection.execute(
      "INSERT INTO moz_cookies VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
      rusqlite::params_from_iter(row.iter()),
    )?;
  }
  let (summary, records) = decode_persistent_gate_connection(&connection)?;
  assert_eq!(summary.rows_seen, OPTIONAL_COLUMNS.len() + 1);
  assert_eq!(summary.rows_skipped, 0);
  assert_eq!(summary.rows_rejected, 0);
  assert_eq!(records.len(), OPTIONAL_COLUMNS.len() + 1);
  assert_eq!(records[0].name, "baseline");
  assert_eq!(records[0].origin.ordinal, 0);
  for (ordinal, (column, raw_key, _)) in OPTIONAL_COLUMNS.iter().enumerate() {
    let record = records
      .iter()
      .find(|record| record.name == format!("malformed-{column}"))
      .expect("each independently malformed optional field emits a record");
    assert_eq!(record.origin.ordinal, (ordinal + 1) as u64);
    match *column {
      "path" => assert!(record.raw.contains_key(*raw_key)),
      "isSecure" => assert!(matches!(record.attributes.secure, Observation::Unknown(_))),
      "expiry" => {
        assert!(matches!(record.attributes.expires, Observation::Unknown(_)));
        assert!(matches!(
          record.attributes.raw_expires,
          Observation::Unknown(_)
        ));
      }
      "isHttpOnly" => assert!(matches!(
        record.attributes.http_only,
        Observation::Unknown(_)
      )),
      "sameSite" => assert!(matches!(
        record.attributes.same_site,
        Observation::Unknown(_)
      )),
      "originAttributes" => {
        assert!(record.raw.contains_key(*raw_key));
        assert!(matches!(
          record.isolation.origin_attributes,
          Observation::Unknown(_)
        ));
      }
      _ => unreachable!("the optional corpus is exhaustive"),
    }
  }

  // Required fields never borrow the optional metadata policy. Keep one valid
  // sibling in every fixture, then vary exactly one required field through
  // NULL and a wrong SQLite storage class. The malformed row is rejected while
  // the sibling still reaches the sink.
  for (required, sqlite_index) in [("host", 0), ("name", 4), ("value", 5)] {
    for malformed in [SqlValue::Null, SqlValue::Blob(vec![0xff, 0x00])] {
      let connection = rusqlite::Connection::open_in_memory()?;
      connection.execute_batch(&format!("PRAGMA user_version = 15; {full_schema}"))?;
      connection.execute(
        "INSERT INTO moz_cookies VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params_from_iter(baseline.iter()),
      )?;
      let mut row = baseline.clone();
      row[sqlite_index] = malformed;
      if required != "name" {
        row[4] = SqlValue::Text(format!("malformed-required-{required}"));
      }
      connection.execute(
        "INSERT INTO moz_cookies VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params_from_iter(row.iter()),
      )?;

      let (summary, records) = decode_persistent_gate_connection(&connection)?;
      assert_eq!(summary.rows_seen, 2);
      assert_eq!(summary.rows_skipped, 1);
      assert_eq!(summary.rows_rejected, 1);
      assert_eq!(records.len(), 1);
      assert_eq!(records[0].name, "baseline");
      assert!(summary
        .last_row_error
        .as_ref()
        .is_some_and(|error| format!("{error:#}").contains(required)));
    }
  }

  // Omitting a required schema column is a source-level query failure, never
  // a zero-row success or an optional-column NULL projection.
  for missing in ["host", "name", "value"] {
    let connection = rusqlite::Connection::open_in_memory()?;
    let columns = [
      "host TEXT",
      "path",
      "isSecure",
      "expiry",
      "name TEXT",
      "value TEXT",
      "isHttpOnly",
      "sameSite",
      "originAttributes",
    ]
    .into_iter()
    .filter(|definition| !definition.starts_with(missing))
    .collect::<Vec<_>>()
    .join(", ");
    connection.execute_batch(&format!(
      "PRAGMA user_version = 15; CREATE TABLE moz_cookies ({columns});"
    ))?;
    let error = decode_persistent_gate_connection(&connection)
      .expect_err("a missing required SQLite column must fail the source query");
    assert!(format!("{error:#}").contains(missing));
  }

  // Probe every optional-column absence independently. Each schema still has
  // a valid host/name/value row and must reach the sink once.
  for (missing, _, _) in OPTIONAL_COLUMNS {
    let connection = rusqlite::Connection::open_in_memory()?;
    let optional_definitions = OPTIONAL_COLUMNS
      .iter()
      .filter(|(column, _, _)| *column != missing)
      .map(|(column, _, _)| *column)
      .collect::<Vec<_>>()
      .join(", ");
    connection.execute_batch(&format!(
      "PRAGMA user_version = 15;
       CREATE TABLE moz_cookies (host TEXT, name TEXT, value TEXT, {optional_definitions});
       INSERT INTO moz_cookies (host, name, value)
       VALUES ('.example.com', 'missing-{missing}', 'plain-value');"
    ))?;
    let (summary, records) = decode_persistent_gate_connection(&connection)?;
    assert_eq!(summary.rows_seen, 1);
    assert_eq!(summary.rows_rejected, 0);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].name, format!("missing-{missing}"));
  }

  // Firefox schema 15 stores seconds; schema 16 and later stores
  // milliseconds. Both paths preserve the raw integer while emitting the same
  // interpreted expiry.
  for (schema, raw_expiry) in [(15, 1_700_000_000_i64), (16, 1_700_000_000_999_i64)] {
    let connection = rusqlite::Connection::open_in_memory()?;
    connection.execute_batch(&format!("PRAGMA user_version = {schema}; {full_schema}"))?;
    connection.execute(
      "INSERT INTO moz_cookies VALUES (?1, '/', 0, ?2, ?3, ?4, 0, 0, NULL)",
      rusqlite::params![
        ".example.com",
        raw_expiry,
        format!("schema-{schema}"),
        "plain-value"
      ],
    )?;
    let (summary, records) = decode_persistent_gate_connection(&connection)?;
    assert_eq!(summary.rows_seen, 1);
    assert_eq!(records.len(), 1);
    assert_eq!(
      records[0]
        .clone()
        .into_cookie()
        .expect("persistent gate record is plaintext")
        .expires,
      Some(1_700_000_000)
    );
    assert_eq!(
      records[0].attributes.raw_expires,
      Observation::Known(RawValue::Signed(raw_expiry))
    );
  }
  Ok(())
}

#[cfg(test)]
fn encode_session_gate_case(json: &Value, format: SessionStoreFormat) -> Vec<u8> {
  let plain = serde_json::to_vec(json).expect("serialize structured session gate case");
  match format {
    SessionStoreFormat::LegacyJson => plain,
    SessionStoreFormat::JsonLz4 => {
      let mut encoded = b"mozLz40\0".to_vec();
      encoded.extend(lz4_flex::block::compress_prepend_size(&plain));
      encoded
    }
  }
}

#[cfg(test)]
fn decode_session_gate_case(
  json: &Value,
  format: SessionStoreFormat,
) -> Result<(MozillaSessionDecodeSummary, Vec<CookieRecord>)> {
  let bytes = encode_session_gate_case(json, format);
  let source = MozillaSessionReadOnlySource {
    bytes: &bytes,
    format,
    domains: None,
  };
  let decoder = MozillaSessionDecoder;
  let clock = SystemClock;
  let runtime = BoundaryRuntime::standard(&clock);
  let mut records = Vec::new();
  let summary = decoder.decode(
    &source,
    &mut |record| {
      records.push(record);
      Ok(())
    },
    &runtime,
  )?;
  Ok((summary, records))
}

#[cfg(test)]
fn structured_session_decoder_gate(format: SessionStoreFormat) -> Result<()> {
  let valid = serde_json::json!({
    "host": ".example.com",
    "path": "/",
    "secure": true,
    "name": "valid",
    "value": "plain-value",
    "httponly": true,
    "sameSite": 1,
    "expiry": 1_700_000_000_u64,
    "originAttributes": {"userContextId": 7, "partitionKey": "(https,example.com)"}
  });
  let optional_cases = [
    ("path", serde_json::json!({"future": true})),
    ("secure", serde_json::json!(2)),
    ("httponly", serde_json::json!("sometimes")),
    ("sameSite", serde_json::json!(9)),
    ("expiry", serde_json::json!("later")),
    ("originAttributes", serde_json::json!(["future"])),
  ];
  let mut optional_records_emitted = 0;
  for (field, malformed) in optional_cases {
    let mut changed = valid.clone();
    changed
      .as_object_mut()
      .expect("cookie fixture is an object")
      .insert(field.to_owned(), malformed);
    changed
      .as_object_mut()
      .expect("cookie fixture is an object")
      .insert(
        "name".to_owned(),
        Value::String(format!("malformed-{field}")),
      );
    let envelope = serde_json::json!({"windows": [{"cookies": [valid.clone(), changed]}]});
    let (summary, records) = decode_session_gate_case(&envelope, format)?;
    assert_eq!(summary.rows_seen, 2);
    assert_eq!(summary.rows_skipped, 0);
    assert_eq!(summary.rows_rejected, 0);
    assert!(summary.diagnostics.is_empty());
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].name, "valid");
    assert_eq!(records[0].origin.ordinal, 0);
    assert_eq!(records[1].name, format!("malformed-{field}"));
    assert_eq!(records[1].origin.ordinal, 1);
    assert_eq!(records[1].domain.raw(), ".example.com");
    match field {
      "path" => assert_eq!(records[1].path, "/"),
      "secure" => assert!(matches!(
        records[1].attributes.secure,
        Observation::Unknown(_)
      )),
      "httponly" => assert!(matches!(
        records[1].attributes.http_only,
        Observation::Unknown(_)
      )),
      "sameSite" => assert!(matches!(
        records[1].attributes.same_site,
        Observation::Unknown(_)
      )),
      "expiry" => {
        assert!(matches!(
          records[1].attributes.expires,
          Observation::Unknown(_)
        ));
        assert!(matches!(
          records[1].attributes.raw_expires,
          Observation::Unknown(_)
        ));
      }
      "originAttributes" => {
        assert!(records[1].raw.contains_key("origin_attributes"));
        assert!(matches!(
          records[1].isolation.origin_attributes,
          Observation::Unknown(_)
        ));
      }
      _ => unreachable!("the session optional corpus is exhaustive"),
    }
    optional_records_emitted += 1;
  }
  assert_eq!(optional_records_emitted, 6);

  let mut required_rejections = 0;
  for field in ["name", "value"] {
    let mut changed = valid.clone();
    changed
      .as_object_mut()
      .expect("cookie fixture is an object")
      .insert(field.to_owned(), serde_json::json!({"not": "text"}));
    let envelope = serde_json::json!({"windows": [{"cookies": [valid.clone(), changed]}]});
    let (summary, records) = decode_session_gate_case(&envelope, format)?;
    assert_eq!(summary.rows_seen, 2);
    assert_eq!(summary.rows_skipped, 1);
    assert_eq!(summary.rows_rejected, 1);
    assert_eq!(summary.diagnostics.len(), 1);
    assert_eq!(records.len(), 1, "the valid sibling still reaches the sink");
    assert_eq!(records[0].name, "valid");
    required_rejections += summary.rows_rejected;
  }
  assert_eq!(required_rejections, 2);
  Ok(())
}

#[cfg(test)]
pub(super) fn structured_legacy_session_decoder_gate() -> Result<()> {
  structured_session_decoder_gate(SessionStoreFormat::LegacyJson)
}

#[cfg(test)]
pub(super) fn structured_jsonlz4_session_decoder_gate() -> Result<()> {
  structured_session_decoder_gate(SessionStoreFormat::JsonLz4)?;

  // These bounded decompression failures exercise header, advertised-size,
  // and truncated-block stages without allocation proportional to input.
  let malformed = [
    b"mozLz40\0".to_vec(),
    [b"mozLz40\0".as_slice(), &u32::MAX.to_le_bytes()].concat(),
    [b"mozLz40\0".as_slice(), &[32, 0, 0, 0], b"truncated"].concat(),
  ];
  let mut rejected = 0;
  for bytes in malformed {
    let source = MozillaSessionReadOnlySource {
      bytes: &bytes,
      format: SessionStoreFormat::JsonLz4,
      domains: None,
    };
    let decoder = MozillaSessionDecoder;
    let clock = SystemClock;
    let runtime = BoundaryRuntime::standard(&clock);
    let mut sink_calls = 0;
    let error = decoder
      .decode(
        &source,
        &mut |_| {
          sink_calls += 1;
          Ok(())
        },
        &runtime,
      )
      .expect_err("malformed mozLz4 input must be rejected before the sink");
    assert!(!error.to_string().is_empty());
    assert_eq!(sink_calls, 0);
    rejected += 1;
  }
  assert_eq!(rejected, 3);
  Ok(())
}

#[cfg(test)]
mod tests;
