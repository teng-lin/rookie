//! Frozen cross-engine report contract (Milestone 4E).
//!
//! Every field here is the final shape of the Section 5.7 wire model. The
//! descriptor and report types are republished unchanged by [`crate::report`];
//! the engine adaptation layer and the counter/aggregation helpers around them
//! stay crate-private.
//!
//! Identifier vocabularies are deliberately open: each one is a validated
//! string newtype serialized as a snake_case string, never a closed enum, so a
//! new engine, cipher tier, or issue code cannot break a downstream consumer.

use crate::common::enums::Cookie;
use anyhow::{bail, Result};
use serde::{Deserialize, Deserializer, Serialize};
use std::str::FromStr;
use std::{cmp::Ordering, fmt};

/// Upper bound on retained samples per aggregated issue.
///
/// [`ExtractionIssue::occurrences`] counts every occurrence, but
/// [`ExtractionIssue::samples`] keeps at most this many, so a corrupt database
/// cannot dictate report size. A caller comparing the two lengths needs this
/// value to tell "all samples retained" from "truncated".
pub const MAX_ISSUE_SAMPLES: usize = 8;

fn validate_open_identifier(kind: &str, value: &str) -> Result<()> {
  let mut bytes = value.bytes();
  let valid = match bytes.next() {
    Some(first) if first.is_ascii_lowercase() => {
      bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    }
    _ => false,
  };
  if !valid {
    bail!("invalid {kind} identifier {value:?}")
  }
  Ok(())
}

fn validate_opaque_identifier(kind: &str, value: &str) -> Result<()> {
  if value.len() != 64
    || !value
      .bytes()
      .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
  {
    bail!("invalid {kind} identifier {value:?}")
  }
  Ok(())
}

#[cfg(feature = "dto-schema")]
fn lexical_string_schema(
  pattern: &'static str,
  min_length: u32,
  max_length: Option<u32>,
) -> schemars::schema::Schema {
  schemars::schema::SchemaObject {
    instance_type: Some(schemars::schema::InstanceType::String.into()),
    string: Some(Box::new(schemars::schema::StringValidation {
      max_length,
      min_length: Some(min_length),
      pattern: Some(pattern.to_owned()),
    })),
    ..Default::default()
  }
  .into()
}

#[cfg(feature = "dto-schema")]
fn open_identifier_schema() -> schemars::schema::Schema {
  lexical_string_schema("^[a-z][a-z0-9_]*$", 1, None)
}

#[cfg(feature = "dto-schema")]
fn opaque_identifier_schema() -> schemars::schema::Schema {
  lexical_string_schema("^[0-9a-f]{64}$", 64, Some(64))
}

macro_rules! string_identifier {
  ($name:ident, $kind:literal, $validate:ident, $schema:ident) => {
    #[doc = concat!("Open ", $kind, " identifier.")]
    ///
    /// The vocabulary is deliberately not a closed enum: a value this build
    /// does not know is still representable, so a new engine, cipher tier, or
    /// issue code cannot break a downstream match. Compare with
    /// [`Self::as_str`] and parse untrusted input with [`FromStr`].
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
    #[serde(transparent)]
    pub struct $name(String);

    impl $name {
      /// Constructs an identifier the crate itself produces.
      ///
      /// Vocabulary values are compile-time constants, so an invalid one is a
      /// crate bug rather than a runtime condition a caller can act on. Some
      /// identifiers only ever come from registry data through `FromStr`, so
      /// this stays unused for them.
      #[allow(dead_code)]
      pub(crate) fn known(value: &str) -> Self {
        debug_assert!(
          $validate($kind, value).is_ok(),
          "crate-produced {} identifier {value:?} is invalid",
          $kind
        );
        Self(value.to_owned())
      }

      /// Borrows the underlying identifier.
      pub fn as_str(&self) -> &str {
        &self.0
      }
    }

    impl AsRef<str> for $name {
      fn as_ref(&self) -> &str {
        &self.0
      }
    }

    impl fmt::Display for $name {
      fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
      }
    }

    impl FromStr for $name {
      type Err = anyhow::Error;

      fn from_str(value: &str) -> Result<Self> {
        $validate($kind, value)?;
        Ok(Self(value.to_owned()))
      }
    }

    impl<'de> Deserialize<'de> for $name {
      fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        $validate($kind, &value).map_err(serde::de::Error::custom)?;
        Ok(Self(value))
      }
    }

    #[cfg(feature = "dto-schema")]
    impl schemars::JsonSchema for $name {
      fn is_referenceable() -> bool {
        false
      }

      fn schema_name() -> String {
        stringify!($name).to_owned()
      }

      fn schema_id() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed(concat!(module_path!(), "::", stringify!($name)))
      }

      fn json_schema(_: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        $schema()
      }
    }
  };
}

string_identifier!(
  BrowserId,
  "browser",
  validate_open_identifier,
  open_identifier_schema
);
string_identifier!(
  EngineId,
  "engine",
  validate_open_identifier,
  open_identifier_schema
);
string_identifier!(
  CookieSourceRoleId,
  "cookie source role",
  validate_open_identifier,
  open_identifier_schema
);
string_identifier!(
  CookieSourceFormatId,
  "cookie source format",
  validate_open_identifier,
  open_identifier_schema
);
string_identifier!(
  CipherTierId,
  "cipher tier",
  validate_open_identifier,
  open_identifier_schema
);
string_identifier!(
  ReportStatusCode,
  "report status",
  validate_open_identifier,
  open_identifier_schema
);
string_identifier!(
  TerminationCode,
  "termination",
  validate_open_identifier,
  open_identifier_schema
);
string_identifier!(
  SourceStatusCode,
  "source status",
  validate_open_identifier,
  open_identifier_schema
);
string_identifier!(
  AcquisitionStrategyCode,
  "acquisition strategy",
  validate_open_identifier,
  open_identifier_schema
);
string_identifier!(
  IssueCode,
  "issue code",
  validate_open_identifier,
  open_identifier_schema
);
string_identifier!(
  ExtractionStageCode,
  "extraction stage",
  validate_open_identifier,
  open_identifier_schema
);
string_identifier!(
  IssueSeverityCode,
  "issue severity",
  validate_open_identifier,
  open_identifier_schema
);
string_identifier!(
  InstallationId,
  "installation",
  validate_opaque_identifier,
  opaque_identifier_schema
);
string_identifier!(
  ProfileId,
  "profile",
  validate_opaque_identifier,
  opaque_identifier_schema
);

/// Constructors for the vocabulary values Section 5.7 freezes.
///
/// They exist so downstream code can compare against a known value without
/// spelling the string, and never imply the vocabulary is closed: a report may
/// still carry a value this build has no constructor for.
macro_rules! vocabulary {
  ($name:ident { $($function:ident => $value:literal),+ $(,)? }) => {
    impl $name {
      $(
        #[doc = concat!("The `", $value, "` ", stringify!($name), " value.")]
        pub fn $function() -> Self {
          Self::known($value)
        }
      )+
    }
  };
}

vocabulary!(CookieSourceRoleId {
  persistent => "persistent",
  session => "session",
});

vocabulary!(ReportStatusCode {
  complete => "complete",
  partial => "partial",
  failed => "failed",
  no_sources => "no_sources",
});

vocabulary!(TerminationCode {
  completed => "completed",
  cancelled => "cancelled",
  timed_out => "timed_out",
  resource_exhausted => "resource_exhausted",
});

fn completed_termination() -> TerminationCode {
  TerminationCode::completed()
}

pub const EXTRACTION_REPORT_SCHEMA_VERSION: u32 = 1;

fn extraction_report_schema_version() -> u32 {
  EXTRACTION_REPORT_SCHEMA_VERSION
}

vocabulary!(SourceStatusCode {
  succeeded => "succeeded",
  failed => "failed",
});

vocabulary!(IssueSeverityCode {
  info => "info",
  warning => "warning",
  error => "error",
});

vocabulary!(ExtractionStageCode {
  registry => "registry",
  discovery => "discovery",
  acquisition => "acquisition",
  parse => "parse",
  decrypt => "decrypt",
  decode => "decode",
  query => "query",
});

vocabulary!(AcquisitionStrategyCode {
  live_read_only => "live_read_only",
  verified_wal_snapshot => "verified_wal_snapshot",
  verified_static_single_file => "verified_static_single_file",
  stable_file_image => "stable_file_image",
  ese_database => "ese_database",
  not_attempted => "not_attempted",
});

// The codes the report layer itself raises. Discovery-stage codes are supplied
// by each engine's registry and are deliberately not enumerated here: they
// change as engines are added, so a caller matches those with `as_str` or
// `FromStr` instead.
vocabulary!(IssueCode {
  browser_not_detected => "browser_not_detected",
  browser_discovery_failed => "browser_discovery_failed",
  profile_has_no_cookie_source => "profile_has_no_cookie_source",
  source_extraction_failed => "source_extraction_failed",
  source_read_retried => "source_read_retried",
  column_read_failed => "column_read_failed",
  decrypt_failed => "decrypt_failed",
  decode_failed => "decode_failed",
  provider_unavailable => "provider_unavailable",
  provider_failed => "provider_failed",
});

impl CookieSourceRoleId {
  /// Report ordering rank. Unknown future roles sort after the frozen ones and
  /// then lexicographically, so an added vocabulary value stays deterministic.
  fn order_rank(&self) -> (u8, &str) {
    match self.as_str() {
      "persistent" => (0, ""),
      "session" => (1, ""),
      other => (2, other),
    }
  }
}

/// What a registered browser claims it can do on this platform.
///
/// Declared tiers come from the registry; `available_decryption_tiers` narrows
/// them to the key providers actually compiled and enabled in this build, so it
/// is the set a `decryptable` claim refers to.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "dto-schema", derive(schemars::JsonSchema))]
pub struct BrowserCapabilitiesDescriptor {
  pub persistent_formats: Vec<CookieSourceFormatId>,
  pub session_formats: Vec<CookieSourceFormatId>,
  pub declared_decryption_tiers: Vec<CipherTierId>,
  pub available_decryption_tiers: Vec<CipherTierId>,
}

/// A browser registered for the running OS. Registration is not detection.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "dto-schema", derive(schemars::JsonSchema))]
pub struct BrowserDescriptor {
  pub id: BrowserId,
  pub aliases: Vec<String>,
  pub display_name: String,
  pub engine: EngineId,
  pub capabilities: BrowserCapabilitiesDescriptor,
}

/// Stable identity of one discovered profile.
///
/// `profile_id` is the selection key; `path` is a display value that may be
/// lossy on a non-UTF-8 filesystem, which `path_lossy` reports.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "dto-schema", derive(schemars::JsonSchema))]
pub struct ProfileIdentity {
  pub browser_id: BrowserId,
  pub installation_id: InstallationId,
  pub profile_id: ProfileId,
  pub display_name: String,
  pub path: String,
  pub path_lossy: bool,
}

/// A cookie source a profile exposes, before any extraction is attempted.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "dto-schema", derive(schemars::JsonSchema))]
pub struct CookieSourceDescriptor {
  pub role: CookieSourceRoleId,
  pub format: CookieSourceFormatId,
  pub path: String,
  pub path_lossy: bool,
  pub precedence: u16,
}

/// One discovered profile and its cookie sources.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "dto-schema", derive(schemars::JsonSchema))]
pub struct ProfileDescriptor {
  pub profile: ProfileIdentity,
  pub is_default: bool,
  pub sources: Vec<CookieSourceDescriptor>,
}

/// Identity of the source an extraction attempted.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "dto-schema", derive(schemars::JsonSchema))]
pub struct CookieSourceIdentity {
  pub role: CookieSourceRoleId,
  pub format: CookieSourceFormatId,
  pub path: String,
  pub path_lossy: bool,
  pub precedence: u16,
}

/// Row accounting for one source or profile.
///
/// `rows_skipped` counts relevant rows rejected after being seen because
/// parsing, decryption, or decoding failed. Every counter is `u32`; a count
/// that exceeded that range is clamped and sets `counters_saturated`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "dto-schema", derive(schemars::JsonSchema))]
pub struct ExtractionStats {
  /// Rows *relevant to the request*: those matching the domain filter, plus
  /// any that failed before relevance could be determined. Rows the filter
  /// excluded are not counted, so `rows_seen - rows_skipped == cookies_emitted`
  /// holds and a consumer can read "how much did this source lose?" directly.
  ///
  /// SQL engines reduce candidates in their `WHERE` clause and enforce the
  /// final host boundary before incrementing these counters. File decoders,
  /// including Safari, likewise apply the request filter before incrementing
  /// their relevant-row counters.
  pub rows_seen: u32,
  pub cookies_emitted: u32,
  pub rows_skipped: u32,
  /// Rows rejected because stored fields were malformed or a value could not
  /// be authenticated or decoded. This is a subset of `rows_skipped`.
  #[serde(default)]
  pub rows_rejected: u32,
  /// Distinct Chromium cipher tiers whose applicable credential provider
  /// failed. Aggregates sum the per-source distinct-tier counts.
  #[serde(default)]
  pub provider_failures: u32,
  pub acquisition_attempts: u32,
  pub counters_saturated: bool,
}

/// Request-wide totals, including browsers that were registered but absent.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "dto-schema", derive(schemars::JsonSchema))]
pub struct ReportStats {
  pub registered_browsers: u32,
  /// Browsers whose discovery established that an installation was present.
  pub browsers_detected: u32,
  /// Browsers whose discovery completed and established absence.
  ///
  /// A request stopped before discovery completed is in neither detection
  /// counter in schema v1. Its error-severity stop issue and non-completed
  /// termination distinguish that unattempted/unknown state from absence.
  pub browsers_not_detected: u32,
  pub installations_discovered: u32,
  pub profiles_discovered: u32,
  pub sources_succeeded: u32,
  pub sources_failed: u32,
  pub rows_seen: u32,
  pub cookies_emitted: u32,
  pub rows_skipped: u32,
  /// Sum of rejected rows across attempted sources.
  #[serde(default)]
  pub rows_rejected: u32,
  /// Sum of per-source distinct Chromium provider-tier failures.
  #[serde(default)]
  pub provider_failures: u32,
  pub counters_saturated: bool,
}

/// A diagnostic attached to the request, a profile, or a source.
///
/// Repeated row-level problems are aggregated by code and stage:
/// `occurrences` counts them all while `samples` keeps a bounded excerpt.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "dto-schema", derive(schemars::JsonSchema))]
pub struct ExtractionIssue {
  pub code: IssueCode,
  pub stage: ExtractionStageCode,
  pub severity: IssueSeverityCode,
  /// Stable machine-readable origin of the failure.
  #[serde(default)]
  pub cause: String,
  /// Credential/provider role when the cause originated at a provider seam.
  #[serde(default)]
  pub provider: Option<String>,
  /// Source-native cipher/provider tier, preserved without message parsing.
  #[serde(default)]
  pub tier: Option<String>,
  /// `retryable`, `not_retryable`, or `unknown`.
  #[serde(default = "unknown_retryability")]
  pub retryability: String,
  pub occurrences: u32,
  pub samples: Vec<String>,
  pub browser_id: Option<BrowserId>,
  pub installation_id: Option<InstallationId>,
  pub profile_id: Option<ProfileId>,
  pub message: String,
}

fn unknown_retryability() -> String {
  "unknown".to_owned()
}

/// One attempted cookie source and the cookies it produced.
///
/// Cookies live here rather than on the profile so provenance survives. A
/// profile-wide stream is the concatenation of the successful `selected`
/// sources in role/precedence order.
#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "dto-schema", derive(schemars::JsonSchema))]
pub struct SourceExtraction {
  pub source: CookieSourceIdentity,
  pub status: SourceStatusCode,
  pub selected: bool,
  pub acquisition_strategy: AcquisitionStrategyCode,
  pub cookies: Vec<Cookie>,
  pub stats: ExtractionStats,
  pub issues: Vec<ExtractionIssue>,
}

/// One profile's sources, totals, and profile-scoped diagnostics.
#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "dto-schema", derive(schemars::JsonSchema))]
pub struct ProfileExtraction {
  pub profile: ProfileIdentity,
  pub sources: Vec<SourceExtraction>,
  pub stats: ExtractionStats,
  pub issues: Vec<ExtractionIssue>,
}

/// A grouped extraction result.
///
/// `issues` holds only request-wide, registry, discovery, and installation
/// problems; anything narrower is attached to its profile or source.
#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "dto-schema", derive(schemars::JsonSchema))]
pub struct ExtractionReport {
  /// Wire discriminator. Missing values from pre-PR3 JSON deserialize as v1.
  #[serde(default = "extraction_report_schema_version")]
  pub schema_version: u32,
  pub status: ReportStatusCode,
  /// Why execution stopped. This is independent from `status`: a timed-out
  /// request may still contain complete source outcomes collected earlier.
  #[serde(default = "completed_termination")]
  pub termination: TerminationCode,
  pub summary: ReportStats,
  pub profiles: Vec<ProfileExtraction>,
  pub issues: Vec<ExtractionIssue>,
}

/// Wider-than-wire counters. Every public counter is `u32` so Node/TypeScript
/// can represent it exactly; counting happens in `u64` and saturates once.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CounterSet {
  pub(crate) rows_seen: u64,
  pub(crate) cookies_emitted: u64,
  pub(crate) rows_skipped: u64,
  pub(crate) rows_rejected: u64,
  pub(crate) provider_failures: u64,
  pub(crate) acquisition_attempts: u64,
}

fn saturate(value: u64, saturated: &mut bool) -> u32 {
  u32::try_from(value).unwrap_or_else(|_| {
    *saturated = true;
    u32::MAX
  })
}

impl CounterSet {
  pub(crate) fn into_stats(self) -> ExtractionStats {
    let mut counters_saturated = false;
    ExtractionStats {
      rows_seen: saturate(self.rows_seen, &mut counters_saturated),
      cookies_emitted: saturate(self.cookies_emitted, &mut counters_saturated),
      rows_skipped: saturate(self.rows_skipped, &mut counters_saturated),
      rows_rejected: saturate(self.rows_rejected, &mut counters_saturated),
      provider_failures: saturate(self.provider_failures, &mut counters_saturated),
      acquisition_attempts: saturate(self.acquisition_attempts, &mut counters_saturated),
      counters_saturated,
    }
  }
}

/// Re-widens already-narrowed stats so an aggregate cannot lose a saturation
/// that a lower level already recorded.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct StatsAccumulator {
  counters: CounterSet,
  saturated: bool,
}

impl StatsAccumulator {
  pub(crate) fn add(&mut self, stats: &ExtractionStats) {
    // Saturating rather than wrapping, for the same reason the wire counters
    // saturate: an aggregate that silently wrapped would read as a small exact
    // number. Reaching the `u64` ceiling from `u32` inputs takes 2^32 sources,
    // so this is contract consistency rather than a reachable case.
    let add = |counter: &mut u64, amount: u32| {
      *counter = counter.saturating_add(u64::from(amount));
    };
    add(&mut self.counters.rows_seen, stats.rows_seen);
    add(&mut self.counters.cookies_emitted, stats.cookies_emitted);
    add(&mut self.counters.rows_skipped, stats.rows_skipped);
    add(&mut self.counters.rows_rejected, stats.rows_rejected);
    add(
      &mut self.counters.provider_failures,
      stats.provider_failures,
    );
    add(
      &mut self.counters.acquisition_attempts,
      stats.acquisition_attempts,
    );
    self.saturated |= stats.counters_saturated;
  }

  pub(crate) fn into_stats(self) -> ExtractionStats {
    let mut stats = self.counters.into_stats();
    stats.counters_saturated |= self.saturated;
    stats
  }
}

pub(crate) fn issue(
  code: &str,
  stage: ExtractionStageCode,
  severity: IssueSeverityCode,
  message: impl Into<String>,
) -> ExtractionIssue {
  ExtractionIssue {
    code: IssueCode::known(code),
    stage,
    severity,
    cause: code.to_owned(),
    provider: None,
    tier: None,
    retryability: "unknown".to_owned(),
    occurrences: 1,
    samples: Vec::new(),
    browser_id: None,
    installation_id: None,
    profile_id: None,
    message: message.into(),
  }
}

/// Merges an issue into a bounded aggregate list, keyed by code, stage, and
/// the browser/installation/profile it is attributed to.
///
/// Row-level engine issues repeat per row; retaining every one would let a
/// corrupt database dictate report size. Context is part of the key because
/// this list is also the report-wide one: two browsers that fail discovery the
/// same way are two distinct failures, and merging them on code alone would
/// keep one browser's id and message while discarding the other's entirely.
pub(crate) fn push_aggregated(issues: &mut Vec<ExtractionIssue>, incoming: ExtractionIssue) {
  let Some(existing) = issues.iter_mut().find(|issue| {
    issue.code == incoming.code
      && issue.stage == incoming.stage
      && issue.severity == incoming.severity
      && issue.cause == incoming.cause
      && issue.provider == incoming.provider
      && issue.tier == incoming.tier
      && issue.retryability == incoming.retryability
      && issue.browser_id == incoming.browser_id
      && issue.installation_id == incoming.installation_id
      && issue.profile_id == incoming.profile_id
  }) else {
    issues.push(incoming);
    return;
  };
  existing.occurrences = existing.occurrences.saturating_add(incoming.occurrences);
  if existing.severity_rank() < incoming.severity_rank() {
    existing.severity = incoming.severity;
    existing.message = incoming.message;
  }
  for sample in incoming.samples {
    if existing.samples.len() >= MAX_ISSUE_SAMPLES {
      break;
    }
    existing.samples.push(sample);
  }
}

impl ExtractionIssue {
  fn severity_rank(&self) -> u8 {
    match self.severity.as_str() {
      "error" => 2,
      "warning" => 1,
      _ => 0,
    }
  }

  pub(crate) fn is_error(&self) -> bool {
    self.severity.as_str() == "error"
  }

  pub(crate) fn with_context(
    mut self,
    browser_id: Option<&BrowserId>,
    installation_id: Option<&InstallationId>,
    profile_id: Option<&ProfileId>,
  ) -> Self {
    self.browser_id = browser_id.cloned();
    self.installation_id = installation_id.cloned();
    self.profile_id = profile_id.cloned();
    self
  }

  pub(crate) fn with_samples(mut self, samples: Vec<String>) -> Self {
    self.samples = samples.into_iter().take(MAX_ISSUE_SAMPLES).collect();
    self
  }

  pub(crate) fn with_occurrences(mut self, occurrences: u32) -> Self {
    self.occurrences = occurrences;
    self
  }
}

pub(crate) fn sort_cookies(cookies: &mut [Cookie]) {
  cookies.sort_by(|left, right| {
    left
      .domain
      .cmp(&right.domain)
      .then_with(|| left.path.cmp(&right.path))
      .then_with(|| left.name.cmp(&right.name))
      .then_with(|| left.expires.cmp(&right.expires))
      .then_with(|| left.secure.cmp(&right.secure))
      .then_with(|| left.http_only.cmp(&right.http_only))
      .then_with(|| left.same_site.cmp(&right.same_site))
      .then_with(|| left.value.cmp(&right.value))
  });
}

pub(crate) fn sort_source_descriptors(sources: &mut [CookieSourceDescriptor]) {
  sources.sort_by(|left, right| {
    compare_source_order(&left.role, left.precedence, &right.role, right.precedence)
  });
}

pub(crate) fn compare_source_identity(
  left: &CookieSourceIdentity,
  right: &CookieSourceIdentity,
) -> Ordering {
  compare_source_order(&left.role, left.precedence, &right.role, right.precedence)
}

fn compare_source_order(
  left_role: &CookieSourceRoleId,
  left_precedence: u16,
  right_role: &CookieSourceRoleId,
  right_precedence: u16,
) -> Ordering {
  left_role
    .order_rank()
    .cmp(&right_role.order_rank())
    .then_with(|| left_precedence.cmp(&right_precedence))
}

/// A source succeeded when acquisition, parsing, and the filtered query all
/// completed, even when zero rows matched.
pub(crate) fn source_status(failed: bool) -> SourceStatusCode {
  if failed {
    SourceStatusCode::failed()
  } else {
    SourceStatusCode::succeeded()
  }
}

/// Section 5.7 report status. `discovery_failed` reports whether any detected
/// installation or root failed hard enough to prevent source enumeration.
///
/// An error-severity issue anywhere resolves to `partial` or `failed` and never
/// to `no_sources`, which Section 5.7 defines as discovery completing *without*
/// an error-severity failure. A profile that ended up with no sources because
/// something errored has not found "no sources"; it failed to look.
/// Wire paths are UTF-8 with an explicit lossy flag; selection always uses the
/// opaque IDs instead.
pub(crate) fn display_path(path: &std::path::Path) -> (String, bool) {
  match path.to_str() {
    Some(value) => (value.to_owned(), false),
    None => (path.to_string_lossy().into_owned(), true),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn open_identifiers_validate_snake_case_and_round_trip() {
    let code = IssueCode::from_str("future_engine_issue").expect("valid identifier");
    assert_eq!(code.as_str(), "future_engine_issue");
    assert_eq!(code.to_string(), "future_engine_issue");
    assert_eq!(AsRef::<str>::as_ref(&code), "future_engine_issue");
    assert_eq!(
      serde_json::to_string(&code).expect("serialize"),
      "\"future_engine_issue\""
    );
    assert_eq!(
      serde_json::from_str::<IssueCode>("\"future_engine_issue\"").expect("deserialize"),
      code
    );

    for invalid in ["", "Uppercase", "1leading", "has-dash", "has space"] {
      assert!(
        IssueCode::from_str(invalid).is_err(),
        "{invalid:?} must be rejected"
      );
      assert!(serde_json::from_str::<IssueCode>(&format!("\"{invalid}\"")).is_err());
    }
  }

  #[test]
  fn opaque_identifiers_require_lowercase_hex_digests() {
    let digest = "a".repeat(64);
    assert!(ProfileId::from_str(&digest).is_ok());
    assert!(InstallationId::from_str(&digest).is_ok());
    for invalid in ["a".repeat(63), "A".repeat(64), "g".repeat(64)] {
      assert!(ProfileId::from_str(&invalid).is_err());
    }
  }

  #[cfg(feature = "dto-schema")]
  fn generated_schema_accepts<T: schemars::JsonSchema>(value: &str) -> bool {
    let mut generator = schemars::r#gen::SchemaSettings::draft07().into_generator();
    let schema = T::json_schema(&mut generator);
    let schemars::schema::Schema::Object(schema) = schema else {
      return false;
    };
    let Some(validation) = schema.string else {
      return false;
    };
    let length = value.chars().count() as u32;
    if validation
      .min_length
      .is_some_and(|minimum| length < minimum)
      || validation
        .max_length
        .is_some_and(|maximum| length > maximum)
    {
      return false;
    }
    validation.pattern.as_ref().is_none_or(|pattern| {
      regex::Regex::new(pattern)
        .expect("generated identifier pattern is valid")
        .is_match(value)
    })
  }

  #[cfg(feature = "dto-schema")]
  #[test]
  fn generated_identifier_schemas_match_rust_lexical_validation() {
    for valid in ["future_browser", "vendor99_mode", "x"] {
      assert!(BrowserId::from_str(valid).is_ok());
      assert!(generated_schema_accepts::<BrowserId>(valid));
    }
    for invalid in ["", "Uppercase", "1leading", "has-dash", "has space"] {
      assert!(BrowserId::from_str(invalid).is_err());
      assert!(!generated_schema_accepts::<BrowserId>(invalid));
    }

    let valid_opaque = "0123456789abcdef".repeat(4);
    assert!(ProfileId::from_str(&valid_opaque).is_ok());
    assert!(generated_schema_accepts::<ProfileId>(&valid_opaque));
    for invalid in [
      "a".repeat(63),
      "a".repeat(65),
      "A".repeat(64),
      "g".repeat(64),
    ] {
      assert!(ProfileId::from_str(&invalid).is_err());
      assert!(!generated_schema_accepts::<ProfileId>(&invalid));
    }
  }

  #[test]
  fn counters_saturate_at_u32_max_and_propagate_through_aggregates() {
    let stats = CounterSet {
      rows_seen: u64::from(u32::MAX) + 1,
      cookies_emitted: 3,
      rows_skipped: 0,
      rows_rejected: u64::from(u32::MAX) + 2,
      provider_failures: 4,
      acquisition_attempts: 1,
    }
    .into_stats();
    assert_eq!(stats.rows_seen, u32::MAX);
    assert_eq!(stats.cookies_emitted, 3);
    assert_eq!(stats.rows_rejected, u32::MAX);
    assert_eq!(stats.provider_failures, 4);
    assert!(stats.counters_saturated);

    let mut accumulator = StatsAccumulator::default();
    accumulator.add(&stats);
    accumulator.add(&ExtractionStats {
      rows_seen: 10,
      ..ExtractionStats::default()
    });
    let aggregate = accumulator.into_stats();
    assert_eq!(aggregate.rows_seen, u32::MAX);
    assert_eq!(aggregate.cookies_emitted, 3);
    assert!(aggregate.counters_saturated);
  }

  #[test]
  fn new_chromium_counters_default_when_reading_older_report_json() {
    let extraction: ExtractionStats = serde_json::from_value(serde_json::json!({
      "rows_seen": 3,
      "cookies_emitted": 2,
      "rows_skipped": 1,
      "acquisition_attempts": 1,
      "counters_saturated": false
    }))
    .expect("older extraction stats remain readable");
    assert_eq!(extraction.rows_rejected, 0);
    assert_eq!(extraction.provider_failures, 0);

    let summary: ReportStats = serde_json::from_value(serde_json::json!({
      "registered_browsers": 1,
      "browsers_detected": 1,
      "browsers_not_detected": 0,
      "installations_discovered": 1,
      "profiles_discovered": 1,
      "sources_succeeded": 1,
      "sources_failed": 0,
      "rows_seen": 3,
      "cookies_emitted": 2,
      "rows_skipped": 1,
      "counters_saturated": false
    }))
    .expect("older report summary remains readable");
    assert_eq!(summary.rows_rejected, 0);
    assert_eq!(summary.provider_failures, 0);

    let wire = serde_json::to_value(ExtractionStats {
      rows_rejected: 2,
      provider_failures: 1,
      ..ExtractionStats::default()
    })
    .expect("serialize extraction stats");
    assert_eq!(wire["rows_rejected"], 2);
    assert_eq!(wire["provider_failures"], 1);
  }

  #[test]
  fn frozen_pre_pr3_report_json_defaults_new_wire_fields() {
    let opaque = "a".repeat(64);
    let report: ExtractionReport = serde_json::from_value(serde_json::json!({
      "status": "partial",
      "summary": {
        "registered_browsers": 1,
        "browsers_detected": 1,
        "browsers_not_detected": 0,
        "installations_discovered": 1,
        "profiles_discovered": 1,
        "sources_succeeded": 1,
        "sources_failed": 0,
        "rows_seen": 1,
        "cookies_emitted": 1,
        "rows_skipped": 0,
        "counters_saturated": false
      },
      "profiles": [{
        "profile": {
          "browser_id": "chrome",
          "installation_id": opaque,
          "profile_id": opaque,
          "display_name": "Default",
          "path": "display-only",
          "path_lossy": false
        },
        "sources": [{
          "source": {
            "role": "persistent",
            "format": "chromium_sqlite",
            "path": "display-only/Cookies",
            "path_lossy": false,
            "precedence": 10
          },
          "status": "succeeded",
          "selected": true,
          "acquisition_strategy": "live_read_only",
          "cookies": [{
            "domain": ".example.test",
            "path": "/",
            "secure": true,
            "expires": null,
            "name": "session",
            "value": "value",
            "http_only": true,
            "same_site": 1
          }],
          "stats": {
            "rows_seen": 1,
            "cookies_emitted": 1,
            "rows_skipped": 0,
            "acquisition_attempts": 1,
            "counters_saturated": false
          },
          "issues": [{
            "code": "decode_failed",
            "stage": "decode",
            "severity": "warning",
            "occurrences": 1,
            "samples": [],
            "browser_id": "chrome",
            "installation_id": opaque,
            "profile_id": opaque,
            "message": "legacy diagnostic"
          }]
        }],
        "stats": {
          "rows_seen": 1,
          "cookies_emitted": 1,
          "rows_skipped": 0,
          "acquisition_attempts": 1,
          "counters_saturated": false
        },
        "issues": []
      }],
      "issues": []
    }))
    .expect("the frozen pre-PR3 report remains readable");

    assert_eq!(report.schema_version, EXTRACTION_REPORT_SCHEMA_VERSION);
    assert_eq!(report.termination, TerminationCode::completed());
    assert_eq!(report.summary.rows_rejected, 0);
    assert_eq!(report.summary.provider_failures, 0);
    let issue = &report.profiles[0].sources[0].issues[0];
    assert_eq!(issue.cause, "");
    assert_eq!(issue.provider, None);
    assert_eq!(issue.tier, None);
    assert_eq!(issue.retryability, "unknown");
  }

  #[test]
  fn aggregated_issues_bound_samples_and_keep_severities_distinct() {
    let mut issues = Vec::new();
    for index in 0..MAX_ISSUE_SAMPLES + 4 {
      push_aggregated(
        &mut issues,
        issue(
          "decrypt_failed",
          ExtractionStageCode::decrypt(),
          IssueSeverityCode::warning(),
          "warning",
        )
        .with_samples(vec![format!("row {index}")]),
      );
    }
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].occurrences, MAX_ISSUE_SAMPLES as u32 + 4);
    assert_eq!(issues[0].samples.len(), MAX_ISSUE_SAMPLES);
    assert_eq!(issues[0].severity, IssueSeverityCode::warning());

    push_aggregated(
      &mut issues,
      issue(
        "decrypt_failed",
        ExtractionStageCode::decrypt(),
        IssueSeverityCode::error(),
        "escalated",
      ),
    );
    assert_eq!(issues.len(), 2);
    assert_eq!(issues[0].severity, IssueSeverityCode::warning());
    assert_eq!(issues[1].severity, IssueSeverityCode::error());
    assert_eq!(issues[1].message, "escalated");
  }

  fn cookie(domain: &str, path: &str, name: &str, value: &str) -> Cookie {
    Cookie {
      domain: domain.to_owned(),
      path: path.to_owned(),
      secure: false,
      expires: None,
      name: name.to_owned(),
      value: value.to_owned(),
      http_only: false,
      same_site: 0,
    }
  }

  #[test]
  fn public_report_debug_redacts_nested_cookie_values_without_changing_wire_output() {
    const SENTINEL: &str = "nested-report-cookie-value-sentinel";
    let source = SourceExtraction {
      source: CookieSourceIdentity {
        role: CookieSourceRoleId::persistent(),
        format: CookieSourceFormatId::known("chromium_sqlite"),
        path: "/tmp/source".to_owned(),
        path_lossy: false,
        precedence: 10,
      },
      status: SourceStatusCode::succeeded(),
      selected: true,
      acquisition_strategy: AcquisitionStrategyCode::live_read_only(),
      cookies: vec![cookie(".example.com", "/", "session", SENTINEL)],
      stats: ExtractionStats {
        rows_seen: 1,
        cookies_emitted: 1,
        ..ExtractionStats::default()
      },
      issues: Vec::new(),
    };

    let debug = format!("{source:?}");
    assert!(!debug.contains(SENTINEL));
    assert!(debug.contains("value: <redacted>"));
    assert!(debug.contains("session"));

    let wire = serde_json::to_value(&source).expect("serialize source extraction");
    assert_eq!(wire["cookies"][0]["value"], SENTINEL);
  }

  /// Report ordering must be stable across runs, so the cookie sort is total
  /// over every field rather than stopping at the domain.
  #[test]
  fn cookies_sort_by_domain_then_path_then_name_then_remaining_fields() {
    let mut cookies = vec![
      cookie(".b.test", "/", "a", "2"),
      cookie(".a.test", "/deep", "a", "1"),
      cookie(".a.test", "/", "z", "1"),
      cookie(".a.test", "/", "a", "2"),
      cookie(".a.test", "/", "a", "1"),
    ];
    let order = |cookies: &[Cookie]| {
      cookies
        .iter()
        .map(|cookie| {
          format!(
            "{} {} {} {}",
            cookie.domain, cookie.path, cookie.name, cookie.value
          )
        })
        .collect::<Vec<_>>()
    };
    sort_cookies(&mut cookies);
    let sorted = order(&cookies);
    assert_eq!(
      sorted,
      vec![
        ".a.test / a 1",
        ".a.test / a 2",
        ".a.test / z 1",
        ".a.test /deep a 1",
        ".b.test / a 2",
      ]
    );

    // Sorting an already-sorted list must not move anything.
    sort_cookies(&mut cookies);
    assert_eq!(sorted, order(&cookies));
  }

  #[test]
  fn source_descriptors_sort_persistent_before_session_then_by_precedence() {
    let descriptor = |role: CookieSourceRoleId, precedence: u16| CookieSourceDescriptor {
      role,
      format: CookieSourceFormatId::known("mozilla_sqlite"),
      path: "/profile/source".to_owned(),
      path_lossy: false,
      precedence,
    };
    let mut sources = vec![
      descriptor(CookieSourceRoleId::session(), 20),
      descriptor(CookieSourceRoleId::known("future_role"), 1),
      descriptor(CookieSourceRoleId::persistent(), 10),
      descriptor(CookieSourceRoleId::session(), 10),
    ];
    sort_source_descriptors(&mut sources);
    assert_eq!(
      sources
        .iter()
        .map(|source| (source.role.to_string(), source.precedence))
        .collect::<Vec<_>>(),
      vec![
        ("persistent".to_owned(), 10),
        ("session".to_owned(), 10),
        ("session".to_owned(), 20),
        // An unknown future role sorts after the frozen ones, never between.
        ("future_role".to_owned(), 1),
      ]
    );
  }
}
