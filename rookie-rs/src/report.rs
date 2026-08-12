//! Descriptors and grouped extraction reports.
//!
//! These are the types returned by [`supported_browsers`], [`browser_profiles`],
//! [`browser_report`], and [`load_report`]. They are additive: the legacy named
//! selectors and their flat `Vec<Cookie>` results are unchanged.
//!
//! Two properties are deliberate and worth knowing before matching on anything
//! here.
//!
//! Every struct is `#[non_exhaustive]`, so fields can be added without a major
//! release. Read fields directly; do not destructure exhaustively.
//!
//! Every identifier and code is an open string newtype rather than an enum, so
//! a browser, engine, cipher tier, or issue code this build has never heard of
//! is still representable. Compare with
//! [`as_str`](BrowserId::as_str) or against a frozen vocabulary value such as
//! [`ReportStatusCode::complete`], and always keep a fallback arm.
//!
//! ```no_run
//! let report = rookie_cookies::browser_report("chrome", None, None)?;
//! for profile in &report.profiles {
//!   for source in &profile.sources {
//!     if source.status == rookie_cookies::report::SourceStatusCode::succeeded() {
//!       println!("{} {} cookies", source.source.path, source.cookies.len());
//!     }
//!   }
//! }
//! # Ok::<(), rookie_cookies::anyhow::Error>(())
//! ```
//!
//! [`supported_browsers`]: crate::supported_browsers
//! [`browser_profiles`]: crate::browser_profiles
//! [`browser_report`]: crate::browser_report
//! [`load_report`]: crate::load_report

pub use crate::browser::report_core::{
  AcquisitionStrategyCode, BrowserCapabilitiesDescriptor, BrowserDescriptor, BrowserId,
  CipherTierId, CookieSourceDescriptor, CookieSourceFormatId, CookieSourceIdentity,
  CookieSourceRoleId, EngineId, ExtractionIssue, ExtractionReport, ExtractionStageCode,
  ExtractionStats, InstallationId, IssueCode, IssueSeverityCode, ProfileDescriptor,
  ProfileExtraction, ProfileId, ProfileIdentity, ReportStats, ReportStatusCode, SourceExtraction,
  SourceStatusCode,
};
