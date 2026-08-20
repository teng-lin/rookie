use super::*;
use crate::browser::chromium_crypto::{ChromiumKeyOutcome, ChromiumKeyOutcomes};
use crate::browser::registry::test_seams;
use crate::browser::report_core::ReportStatusCode;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct TempDir(PathBuf);

impl TempDir {
  fn new(tag: &str) -> Self {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!(
      "rookie-report-chain-{tag}-{}-{count}",
      std::process::id()
    ));
    std::fs::create_dir_all(&path).expect("create temporary directory");
    Self(path)
  }

  fn path(&self) -> &std::path::Path {
    &self.0
  }
}

impl Drop for TempDir {
  fn drop(&mut self) {
    let _ = std::fs::remove_dir_all(&self.0);
  }
}

fn no_keys() -> ChromiumKeyOutcomes {
  ChromiumKeyOutcomes {
    v10: ChromiumKeyOutcome::NotApplicable,
    v11: ChromiumKeyOutcome::NotApplicable,
    v20: ChromiumKeyOutcome::NotApplicable,
  }
}

#[test]
fn a_real_gecko_profile_reaches_the_frozen_report() {
  let temp = TempDir::new("gecko");
  let context = test_seams::current_context(temp.path().to_path_buf());
  let root = test_seams::primary_root_path(&context, "firefox");
  test_seams::seed_gecko_profile(&root.join("Profiles/default"));
  std::fs::write(
    root.join("profiles.ini"),
    "[Profile0]\nName=default\nPath=Profiles/default\nDefault=1\n",
  )
  .expect("write profiles.ini");

  let engine = test_seams::gecko_report(&context, "firefox", None, None).expect("gecko report");
  let browser = BrowserId::known("firefox");
  let outcome = engine_extract_outcome(&browser, engine).expect("adapt the engine outcome");
  let report = assemble(1, vec![outcome]);

  assert_eq!(report.status, ReportStatusCode::complete());
  assert_eq!(report.summary.profiles_discovered, 1);
  assert_eq!(report.summary.installations_discovered, 1);
  assert_eq!(report.summary.sources_succeeded, 1);
  let profile = &report.profiles[0];
  assert_eq!(profile.profile.browser_id.as_str(), "firefox");
  assert_eq!(profile.profile.display_name, "default");
  // Opaque ids, not display paths, are the selection keys.
  assert_eq!(profile.profile.profile_id.as_str().len(), 64);
  assert_eq!(profile.profile.installation_id.as_str().len(), 64);
  let source = &profile.sources[0];
  assert_eq!(source.source.format.as_str(), "mozilla_sqlite");
  assert_eq!(source.source.role.as_str(), "persistent");
  assert!(source.selected);
  assert_eq!(source.status, SourceStatusCode::succeeded());
}

#[test]
fn a_real_chromium_profile_reaches_the_frozen_report() {
  let temp = TempDir::new("chromium");
  let context = test_seams::current_context(temp.path().to_path_buf());
  let root = test_seams::primary_root_path(&context, "chrome");
  test_seams::seed_chromium_profile(&root, "Default", "Person 1");

  let registry_report = test_seams::chromium_report(&context, "chrome", None, None, no_keys())
    .expect("chromium report");
  let browser = BrowserId::known("chrome");
  let outcome =
    chromium_browser_outcome(&browser, registry_report).expect("adapt the chromium report");
  let report = assemble(1, vec![outcome]);

  assert_eq!(report.status, ReportStatusCode::complete());
  assert_eq!(report.summary.profiles_discovered, 1);
  assert_eq!(report.summary.sources_succeeded, 1);
  assert_eq!(report.summary.cookies_emitted, 1);
  let source = &report.profiles[0].sources[0];
  assert_eq!(source.source.format.as_str(), "chromium_sqlite");
  assert!(source.selected);
  assert_eq!(source.cookies[0].name, "seeded");
}

/// A registered browser with nothing on disk is `no_sources`, never `failed`.
#[test]
fn an_absent_installation_reaches_the_report_as_no_sources() {
  let temp = TempDir::new("absent");
  let context = test_seams::current_context(temp.path().to_path_buf());

  let engine = test_seams::gecko_report(&context, "firefox", None, None).expect("gecko report");
  assert!(engine.profiles.is_empty());
  let browser = BrowserId::known("firefox");
  let outcome = engine_extract_outcome(&browser, engine).expect("adapt the engine outcome");
  let report = assemble(1, vec![outcome]);

  assert_eq!(report.status, ReportStatusCode::no_sources());
  assert_eq!(report.summary.installations_discovered, 0);
}

#[test]
fn unreadable_non_chromium_roots_are_detected_failures_at_public_boundaries() {
  use crate::browser::registry::PlatformId;

  for (name, platform, browser_id) in [
    ("gecko", PlatformId::Linux, "firefox"),
    ("safari", PlatformId::Macos, "safari"),
    (
      "internet-explorer",
      PlatformId::Windows,
      "internet_explorer",
    ),
  ] {
    let temp = TempDir::new(&format!("{name}-metadata-denied-report"));
    let context = test_seams::context(platform, temp.path().to_path_buf());
    let root = test_seams::primary_root_path(&context, browser_id);
    let browser = BrowserId::known(browser_id);

    // All three non-Chromium engines share the listing tower now, so a
    // metadata-denied root produces one browser listing the same way.
    //
    // `discovery_failed`/`ReportStatusCode::failed()` propagation through
    // `finalize_outcomes` is a `BrowserDraft` concern and already covered by
    // `a_root_that_could_not_be_enumerated_is_failed_not_no_sources`; a
    // `BrowserListing` never reaches that pipeline, so this test only
    // exercises the listing tower's own two consumers: the issue it carries,
    // and the error `profile_descriptors_from_outcome` raises from it.
    let expected_sample = root.to_str().expect("temp path is valid utf-8").to_owned();
    let listing = test_seams::non_chromium_discovery_with_denied_root(&context, browser_id, root)
      .expect("discovery retains the metadata failure");
    let counters = listing.counters;
    let all_failed = listing.all_detected_roots_failed();
    let listing_outcome =
      engine_listing_outcome(&browser, listing).expect("adapt listing discovery");

    assert_eq!(counters.installations_detected, 1, "{name}");
    assert_eq!(counters.installations_discovered, 0, "{name}");
    assert_eq!(counters.installations_enumerated, 0, "{name}");
    assert!(all_failed, "{name}");

    assert!(listing_outcome.discovery_failed, "{name}");
    let issue = listing_outcome
      .issues
      .iter()
      .find(|issue| issue.code.as_str() == "installation_metadata_failed")
      .expect("stable root metadata issue");
    assert!(issue.is_error(), "{name}");
    // Unlike the extraction-report path, listing issues never pass through
    // `Failure`/`Diagnostic`, so nothing here redacts the sample path.
    assert_eq!(issue.samples, [expected_sample], "{name}");

    let error = profile_descriptors_from_outcome(browser_id, listing_outcome)
      .expect_err("an unreadable root must not become an empty profile list");
    assert!(
      error
        .to_string()
        .contains(&format!("every detected {browser_id} installation failed")),
      "{name}: {error:#}"
    );
  }
}

/// A session-only profile is admitted only because a session candidate
/// exists at discovery time (`gecko_profile_has_source`). If that candidate
/// is gone by the time extraction runs, the profile is not "nothing was
/// ever there" - it is "something was there and extraction failed to reach
/// it" - and Section 5.7 reserves `no_sources` for the former. Distinct from
/// `an_absent_installation_reaches_the_report_as_no_sources`: here the
/// profile itself is real and was discovered, only its one source raced
/// away, so `installations_discovered`/`profiles_discovered` stay 1.
#[test]
fn a_gecko_session_candidate_that_vanishes_before_query_is_failed_not_absent() {
  let temp = TempDir::new("gecko-session-vanishes-report");
  let context = test_seams::current_context(temp.path().to_path_buf());
  let root = test_seams::primary_root_path(&context, "firefox");
  let profile = root.join("Profiles/session-only");
  std::fs::create_dir_all(profile.join("sessionstore-backups")).expect("create profile");
  let session_file = profile.join("sessionstore-backups/recovery.jsonlz4");
  std::fs::write(&session_file, b"discoverable but will vanish before query")
    .expect("write session candidate");
  std::fs::write(
    root.join("profiles.ini"),
    "[Profile0]\nName=session\nPath=Profiles/session-only\nDefault=1\n",
  )
  .expect("write profiles.ini");

  let engine = test_seams::gecko_report_with_race(&context, "firefox", None, |_persistent| {
    let _ = std::fs::remove_file(&session_file);
  })
  .expect("gecko report");
  assert_eq!(
    engine.profiles.len(),
    1,
    "the profile itself was discovered"
  );

  let browser = BrowserId::known("firefox");
  let outcome = engine_extract_outcome(&browser, engine).expect("adapt the engine outcome");
  let report = assemble(1, vec![outcome]);

  assert_eq!(report.status, ReportStatusCode::failed());
  assert_eq!(report.summary.installations_discovered, 1);
  assert_eq!(report.summary.profiles_discovered, 1);
  let profile = &report.profiles[0];
  assert!(profile.sources.is_empty());
  let issue = profile
    .issues
    .iter()
    .find(|issue| issue.code.as_str() == "profile_extraction_failed")
    .expect("a failure signal, not silent absence");
  assert!(issue.is_error());
}

/// Safari and Internet Explorer are OS-gated in `collect_extraction`, so their
/// adapters cannot be reached through the dispatch on a Linux CI host. These
/// drive the same engine chain with an overridden platform context, so both
/// engines are still proven to reach the frozen contract.
#[test]
fn a_real_safari_profile_reaches_the_frozen_report() {
  use crate::browser::registry::PlatformId;

  let temp = TempDir::new("safari");
  let context = test_seams::context(PlatformId::Macos, temp.path().to_path_buf());
  let library = test_seams::primary_root_path(&context, "safari");
  let cookies = library.join("Containers/com.apple.Safari/Data/Library/Cookies");
  std::fs::create_dir_all(&cookies).expect("create Safari cookie directory");
  std::fs::write(
    cookies.join("Cookies.binarycookies"),
    b"cook\x00\x00\x00\x00",
  )
  .expect("seed Safari cookie file");

  let engine = test_seams::safari_report(&context, "safari", None, None).expect("safari report");
  let browser = BrowserId::known("safari");
  let outcome = engine_extract_outcome(&browser, engine).expect("adapt the engine outcome");
  let report = assemble(1, vec![outcome]);

  assert_eq!(report.summary.installations_discovered, 1);
  assert_eq!(report.summary.profiles_discovered, 1);
  let source = &report.profiles[0].sources[0];
  assert_eq!(source.source.format.as_str(), "safari_binarycookies");
  assert_eq!(source.source.role.as_str(), "persistent");
  assert!(source.selected);
  assert_eq!(
    source.acquisition_strategy,
    AcquisitionStrategyCode::stable_file_image()
  );
  assert_eq!(report.profiles[0].profile.browser_id.as_str(), "safari");
}

fn safari_report_from_embedded_nul_fixture(
  tag: &str,
  field: &str,
  include_valid: bool,
) -> ExtractionReport {
  use crate::browser::registry::PlatformId;

  let temp = TempDir::new(tag);
  let context = test_seams::context(PlatformId::Macos, temp.path().to_path_buf());
  let library = test_seams::primary_root_path(&context, "safari");
  let cookies = library.join("Containers/com.apple.Safari/Data/Library/Cookies");
  std::fs::create_dir_all(&cookies).expect("create Safari cookie directory");
  std::fs::write(
    cookies.join("Cookies.binarycookies"),
    crate::browser::safari::embedded_nul_test_fixture(field, include_valid),
  )
  .expect("seed Safari embedded-NUL fixture");

  let engine = test_seams::safari_report(&context, "safari", None, None).expect("safari report");
  let outcome =
    engine_extract_outcome(&BrowserId::known("safari"), engine).expect("adapt the Safari report");
  assemble(1, vec![outcome])
}

#[test]
fn mixed_safari_embedded_nul_fixture_is_partial_with_exact_row_accounting() {
  let report = safari_report_from_embedded_nul_fixture("safari-nul-mixed", "domain", true);
  let source = &report.profiles[0].sources[0];

  assert_eq!(report.status, ReportStatusCode::partial());
  assert_eq!(source.status, SourceStatusCode::succeeded());
  assert_eq!(source.stats.rows_seen, 2);
  assert_eq!(source.stats.rows_skipped, 1);
  assert_eq!(source.stats.cookies_emitted, 1);
  assert_eq!(source.cookies.len(), 1);
  assert_eq!(source.cookies[0].domain, ".good.test");
  assert_eq!(source.cookies[0].name, "good");
  assert_eq!(source.cookies[0].path, "/");
  assert_eq!(source.cookies[0].value, "kept");
  let issue = source
    .issues
    .iter()
    .find(|issue| issue.code.as_str() == "row_read_failed")
    .expect("malformed row issue");
  assert_eq!(issue.stage.as_str(), "parse");
  assert_eq!(issue.occurrences, 1);
}

#[test]
fn all_malformed_safari_embedded_nul_fixture_fails_with_counted_row() {
  let report = safari_report_from_embedded_nul_fixture("safari-nul-all-malformed", "value", false);
  let source = &report.profiles[0].sources[0];

  assert_eq!(report.status, ReportStatusCode::failed());
  assert_eq!(source.status, SourceStatusCode::failed());
  assert_eq!(source.stats.rows_seen, 1);
  assert_eq!(source.stats.rows_skipped, 1);
  assert_eq!(source.stats.cookies_emitted, 0);
  assert!(source.cookies.is_empty());
  assert!(source.issues.iter().any(|issue| {
    issue.code.as_str() == "row_read_failed"
      && issue.stage.as_str() == "parse"
      && issue.occurrences == 1
  }));
  assert!(source.issues.iter().any(|issue| {
    issue.code.as_str() == "source_extraction_failed" && issue.stage.as_str() == "parse"
  }));
}

/// `~/Library` belongs to macOS, not to Safari. Another browser's data under
/// it must not make Safari report itself detected and then degraded.
#[test]
fn a_library_without_safari_data_is_not_a_safari_installation() {
  use crate::browser::registry::PlatformId;

  let temp = TempDir::new("safari-absent");
  let context = test_seams::context(PlatformId::Macos, temp.path().to_path_buf());
  let library = test_seams::primary_root_path(&context, "safari");
  std::fs::create_dir_all(library.join("Application Support/Firefox/Profiles/other"))
    .expect("create an unrelated browser tree under the library root");

  let engine = test_seams::safari_report(&context, "safari", None, None).expect("safari report");
  let browser = BrowserId::known("safari");
  let outcome = engine_extract_outcome(&browser, engine).expect("adapt the engine outcome");
  let report = assemble(1, vec![outcome]);

  assert_eq!(report.summary.browsers_detected, 0);
  assert_eq!(report.summary.installations_discovered, 0);
  assert_eq!(report.status, ReportStatusCode::no_sources());
}

/// The detection gate must still admit the pre-sandbox layout, whose cookie
/// jar sits beside the Safari container rather than inside it.
#[test]
fn a_pre_sandbox_cookie_jar_is_still_a_safari_installation() {
  use crate::browser::registry::PlatformId;

  let temp = TempDir::new("safari-legacy");
  let context = test_seams::context(PlatformId::Macos, temp.path().to_path_buf());
  let cookies = test_seams::primary_root_path(&context, "safari").join("Cookies");
  std::fs::create_dir_all(&cookies).expect("create the pre-sandbox cookie directory");
  std::fs::write(
    cookies.join("Cookies.binarycookies"),
    b"cook\x00\x00\x00\x00",
  )
  .expect("seed Safari cookie file");

  let engine = test_seams::safari_report(&context, "safari", None, None).expect("safari report");
  let browser = BrowserId::known("safari");
  let outcome = engine_extract_outcome(&browser, engine).expect("adapt the engine outcome");
  let report = assemble(1, vec![outcome]);

  assert_eq!(report.summary.installations_discovered, 1);
  assert_eq!(report.summary.profiles_discovered, 1);
}

#[test]
fn a_real_internet_explorer_profile_reaches_the_frozen_report() {
  use crate::browser::registry::{extracted_internet_explorer_source, PlatformId};

  let temp = TempDir::new("ie");
  let context = test_seams::context(PlatformId::Windows, temp.path().to_path_buf());
  let root = test_seams::primary_root_path(&context, "internet_explorer");
  std::fs::create_dir_all(&root).expect("create WebCache root");
  std::fs::write(root.join("WebCacheV01.dat"), b"ese").expect("seed WebCache database");

  // The ESE reader is injected, so this exercises the adapter chain without
  // needing a real ESE database on a non-Windows host.
  let engine =
    test_seams::internet_explorer_report(&context, "internet_explorer", None, None, |origin, _| {
      Ok(extracted_internet_explorer_source(
        origin,
        vec![crate::browser::cookie_record::CookieRecord::from_cookie(
          crate::common::enums::Cookie {
            domain: ".example.com".to_owned(),
            path: "/".to_owned(),
            secure: false,
            expires: None,
            name: "ie-cookie".to_owned(),
            value: "value".to_owned(),
            http_only: false,
            same_site: 0,
          },
          crate::browser::cookie_record::SourceRef::pending(0),
        )],
        1,
        0,
        0,
        None,
      ))
    })
    .expect("internet explorer report");

  let browser = BrowserId::known("internet_explorer");
  let outcome = engine_extract_outcome(&browser, engine).expect("adapt the engine outcome");
  let report = assemble(1, vec![outcome]);

  assert_eq!(report.status, ReportStatusCode::complete());
  assert_eq!(report.summary.cookies_emitted, 1);
  let source = &report.profiles[0].sources[0];
  assert_eq!(source.source.format.as_str(), "internet_explorer_ese");
  assert_eq!(
    source.acquisition_strategy,
    AcquisitionStrategyCode::ese_database()
  );
  assert_eq!(source.cookies[0].name, "ie-cookie");
}

/// Ordinary absence, driven through the real registry rather than a
/// hand-built state. An installed browser whose profile has no cookie store
/// is `no_sources`.
///
/// Discovery, not extraction, is where this is decided: a profile with no
/// cookie database is filtered out of the installation and recorded as an
/// info-severity discovery issue. `ChromiumProfileFailure::NoSource` is the
/// defensive branch for a source that vanishes after discovery selected it,
/// which is why asserting absence against a fabricated extraction state
/// proved nothing about production.
#[test]
fn an_installed_chromium_profile_without_a_cookie_store_is_no_sources() {
  let temp = TempDir::new("chromium-absent-store");
  let context = test_seams::current_context(temp.path().to_path_buf());
  let root = test_seams::primary_root_path(&context, "chrome");
  // Declares a profile in Local State, but leaves it with no cookie database.
  test_seams::seed_chromium_profile(&root, "Default", "Person 1");
  std::fs::remove_file(root.join("Default/Cookies")).expect("remove the cookie database");

  let registry_report = test_seams::chromium_report(&context, "chrome", None, None, no_keys())
    .expect("chromium report");
  assert_eq!(registry_report.installations.len(), 1);
  assert!(registry_report.installations[0].profiles.is_empty());

  let outcome = chromium_browser_outcome(&BrowserId::known("chrome"), registry_report)
    .expect("adapt the chromium report");
  let report = assemble(1, vec![outcome]);

  assert_eq!(report.status, ReportStatusCode::no_sources());
  assert_eq!(report.summary.installations_discovered, 1);
  let issue = report
    .issues
    .iter()
    .find(|issue| issue.code.as_str() == "profile_has_no_cookie_source")
    .expect("an absence signal for the sourceless profile");
  assert!(!issue.is_error());
}

/// Section 5.7: a rejected row is counted and reported, but acquisition,
/// parsing, and the query all completed, so the source still succeeded. Gecko
/// used to fail the whole source on one bad row while Chromium did not.
#[test]
fn a_rejected_row_keeps_the_gecko_source_succeeded_and_the_report_partial() {
  let temp = TempDir::new("gecko-bad-row");
  let context = test_seams::current_context(temp.path().to_path_buf());
  let root = test_seams::primary_root_path(&context, "firefox");
  let profile = root.join("Profiles/default");
  test_seams::seed_gecko_profile(&profile);
  std::fs::write(
    root.join("profiles.ini"),
    "[Profile0]\nName=default\nPath=Profiles/default\nDefault=1\n",
  )
  .expect("write profiles.ini");

  // One readable row and one whose name column is not text.
  let connection =
    rusqlite::Connection::open(profile.join("cookies.sqlite")).expect("open Gecko database");
  connection
    .execute_batch(
      "INSERT INTO moz_cookies VALUES ('.example.com','/',0,0,'good','value',0,0);
       INSERT INTO moz_cookies VALUES ('.example.com','/',0,0,X'00ff','value',0,0);",
    )
    .expect("seed rows");
  drop(connection);

  let engine = test_seams::gecko_report(&context, "firefox", None, None).expect("gecko report");
  let outcome =
    engine_extract_outcome(&BrowserId::known("firefox"), engine).expect("adapt the engine outcome");
  let report = assemble(1, vec![outcome]);

  let source = &report.profiles[0].sources[0];
  assert_eq!(source.status, SourceStatusCode::succeeded());
  assert_eq!(source.stats.rows_skipped, 1);
  assert_eq!(source.cookies.len(), 1);
  assert_eq!(source.cookies[0].name, "good");
  // The mapping pairs `occurrences` with `rows_skipped` and the message with
  // `persistent_row_error`, which is only sound while the counter and the
  // error move together. A future rejection site that bumped one without the
  // other would silently under-report lost cookies, so pin the invariant:
  // rows skipped implies exactly one row issue counting exactly that many.
  let row_issues = source
    .issues
    .iter()
    .filter(|issue| issue.code.as_str() == "row_read_failed")
    .collect::<Vec<_>>();
  assert_eq!(row_issues.len(), 1);
  assert!(row_issues[0].is_error());
  assert_eq!(row_issues[0].occurrences, source.stats.rows_skipped);
  // Rows were lost, so the report is degraded -- but not to `failed`.
  assert_eq!(report.status, ReportStatusCode::partial());
  assert_eq!(report.summary.sources_succeeded, 1);
  assert_eq!(report.summary.sources_failed, 0);
  let diagnostics = source
    .issues
    .iter()
    .flat_map(|issue| {
      std::iter::once(issue.message.as_str()).chain(issue.samples.iter().map(String::as_str))
    })
    .collect::<Vec<_>>();
  assert!(diagnostics
    .iter()
    .all(|text| !text.contains("plaintext sentinel must not escape")));
  assert!(diagnostics
    .iter()
    .all(|text| text.len() <= crate::browser::outcome::MAX_DIAGNOSTIC_BYTES));
}

/// Selecting a profile narrows which installations are extracted, but must
/// not rewrite how many were discovered. Chromium filters installations
/// during extraction while the other engines filter profiles afterwards, so
/// deriving the count from the post-selection list made the same request
/// report different totals depending on the engine.
#[test]
fn selecting_a_chromium_profile_keeps_the_discovered_installation_count() {
  let temp = TempDir::new("chromium-profile-selection");
  let context = test_seams::current_context(temp.path().to_path_buf());
  let roots = test_seams::resolvable_root_paths(&context, "chrome");
  assert!(
    roots.len() >= 2,
    "chrome must declare at least two roots for this fixture"
  );
  test_seams::seed_chromium_profile(&roots[0], "Default", "Person 1");
  test_seams::seed_chromium_profile(&roots[1], "Default", "Person 2");

  let all = test_seams::chromium_report(&context, "chrome", None, None, no_keys())
    .expect("chromium report");
  assert_eq!(all.installations_discovered, 2);
  let selected_profile = all.installations[0].profiles[0].profile.profile_id.clone();

  let one = test_seams::chromium_report(
    &context,
    "chrome",
    Some(selected_profile.as_str()),
    None,
    no_keys(),
  )
  .expect("profile-selected chromium report");
  assert_eq!(one.installations.len(), 1);
  assert_eq!(one.installations_discovered, 2);

  let outcome =
    chromium_browser_outcome(&BrowserId::known("chrome"), one).expect("adapt the chromium report");
  let report = assemble(1, vec![outcome]);
  assert_eq!(report.summary.installations_discovered, 2);
  assert_eq!(report.summary.profiles_discovered, 1);
}

/// Section 5.7 freezes what a profile-selected report says, and pushing the
/// selection down into the engines changes only *when* the work happens. So
/// every one of these compares the profile-selected report against the report
/// the old build produced -- extract every profile, then drop the unwanted
/// ones -- and requires them to be identical field for field, issues and
/// counters included.
fn post_filtered_extract_report(
  browser: &BrowserId,
  extract: EngineExtract,
  profile_id: &str,
) -> ExtractionReport {
  let mut outcome = engine_extract_outcome(browser, extract).expect("adapt the engine outcome");
  outcome
    .profiles
    .retain(|profile| profile.profile.profile_id.as_str() == profile_id);
  assemble(1, vec![outcome])
}

fn selected_extract_report(browser: &BrowserId, extract: EngineExtract) -> ExtractionReport {
  assemble(
    1,
    vec![engine_extract_outcome(browser, extract).expect("adapt the engine outcome")],
  )
}

/// The serialized form is the observable contract, so comparing it compares
/// every frozen field rather than the handful a hand-written assertion would
/// remember to check.
fn wire(report: &ExtractionReport) -> serde_json::Value {
  serde_json::to_value(report).expect("serialize the report")
}

#[test]
fn a_profile_selected_gecko_report_says_what_the_post_filtered_report_said() {
  let temp = TempDir::new("gecko-profile-contract");
  let context = test_seams::current_context(temp.path().to_path_buf());
  let root = test_seams::primary_root_path(&context, "firefox");
  for (directory, rows) in [
    (
      "default",
      "INSERT INTO moz_cookies VALUES ('.example.com','/',0,0,'default-cookie','value',0,0);",
    ),
    // The selected profile loses a row, so the comparison covers a report
    // carrying an error-severity issue and a degraded status, not just a
    // clean one.
    (
      "other",
      "INSERT INTO moz_cookies VALUES ('.example.com','/',0,0,'other-cookie','value',0,0);
       INSERT INTO moz_cookies VALUES ('.example.com','/',0,0,X'00ff','value',0,0);",
    ),
  ] {
    let profile = root.join("Profiles").join(directory);
    test_seams::seed_gecko_profile(&profile);
    let connection =
      rusqlite::Connection::open(profile.join("cookies.sqlite")).expect("open Gecko database");
    connection.execute_batch(rows).expect("seed rows");
  }
  std::fs::write(
    root.join("profiles.ini"),
    "[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/default\nDefault=1\n\
     [Profile1]\nName=other\nIsRelative=1\nPath=Profiles/other\n",
  )
  .expect("write profiles.ini");

  let browser = BrowserId::known("firefox");
  let full = test_seams::gecko_report(&context, "firefox", None, None).expect("full report");
  assert_eq!(full.profiles.len(), 2);
  let selected = full.profiles[1].identity.profile_id.as_str().to_owned();
  let expected = post_filtered_extract_report(&browser, full, &selected);

  let engine = test_seams::gecko_report(&context, "firefox", Some(&selected), None)
    .expect("profile-selected report");
  let actual = selected_extract_report(&browser, engine);

  assert_eq!(actual.status, ReportStatusCode::partial());
  assert_eq!(actual.summary.cookies_emitted, 1);
  assert_eq!(wire(&actual), wire(&expected));
}

#[test]
fn a_profile_selected_safari_report_says_what_the_post_filtered_report_said() {
  use crate::browser::registry::PlatformId;

  let temp = TempDir::new("safari-profile-contract");
  let context = test_seams::context(PlatformId::Macos, temp.path().to_path_buf());
  let data = test_seams::primary_root_path(&context, "safari")
    .join("Containers/com.apple.Safari/Data/Library");
  let uuid = "01234567-89AB-CDEF-0123-456789ABCDEF";
  for directory in [
    data.join("Cookies"),
    data.join(format!(
      "WebKit/WebsiteDataStore/{}/WebsiteData/Cookies",
      uuid.to_ascii_lowercase()
    )),
  ] {
    std::fs::create_dir_all(&directory).expect("create Safari cookie directory");
    std::fs::write(
      directory.join("Cookies.binarycookies"),
      b"cook\x00\x00\x00\x00",
    )
    .expect("seed Safari cookie file");
  }
  std::fs::create_dir_all(data.join(format!("Safari/Profiles/{uuid}")))
    .expect("create Safari profile marker directory");

  let browser = BrowserId::known("safari");
  let full = test_seams::safari_report(&context, "safari", None, None).expect("full report");
  assert_eq!(full.profiles.len(), 2);
  let selected = full.profiles[1].identity.profile_id.as_str().to_owned();
  let expected = post_filtered_extract_report(&browser, full, &selected);

  let engine = test_seams::safari_report(&context, "safari", Some(&selected), None)
    .expect("profile-selected report");
  assert_eq!(
    wire(&selected_extract_report(&browser, engine)),
    wire(&expected)
  );
}

#[test]
fn a_profile_selected_internet_explorer_report_says_what_the_post_filtered_report_said() {
  use crate::browser::registry::{extracted_internet_explorer_source, PlatformId};

  let temp = TempDir::new("ie-profile-contract");
  let context = test_seams::context(PlatformId::Windows, temp.path().to_path_buf());
  let roots = test_seams::resolvable_root_paths(&context, "internet_explorer");
  assert_eq!(roots.len(), 2, "IE must declare two WebCache roots");
  for root in &roots {
    std::fs::create_dir_all(root).expect("create WebCache root");
    std::fs::write(root.join("WebCacheV01.dat"), b"ese").expect("seed WebCache database");
  }
  // Each root answers with its own cookie, so a report built from the wrong
  // profile could not pass by coincidence.
  let rows = |origin: crate::browser::registry::SourceCandidate, _: Option<&[String]>| {
    let name = format!("{}", origin.path.display());
    Ok(extracted_internet_explorer_source(
      origin,
      vec![crate::browser::cookie_record::CookieRecord::from_cookie(
        crate::common::enums::Cookie {
          domain: ".example.com".to_owned(),
          path: "/".to_owned(),
          secure: false,
          expires: None,
          name,
          value: "value".to_owned(),
          http_only: false,
          same_site: 0,
        },
        crate::browser::cookie_record::SourceRef::pending(0),
      )],
      1,
      0,
      0,
      None,
    ))
  };

  let browser = BrowserId::known("internet_explorer");
  let full = test_seams::internet_explorer_report(&context, "internet_explorer", None, None, rows)
    .expect("full report");
  assert_eq!(full.profiles.len(), 2);
  let selected = full.profiles[1].identity.profile_id.as_str().to_owned();
  let expected = post_filtered_extract_report(&browser, full, &selected);

  let engine = test_seams::internet_explorer_report(
    &context,
    "internet_explorer",
    Some(&selected),
    None,
    rows,
  )
  .expect("profile-selected report");
  let actual = selected_extract_report(&browser, engine);

  assert_eq!(actual.summary.cookies_emitted, 1);
  assert_eq!(wire(&actual), wire(&expected));
}

/// Reported against pre-round-3 4E: a Chromium row that could not be
/// decrypted took the whole source down with it, because "no row decoded"
/// became a source-level failure. Section 5.7 counts every seen-but-not-
/// emitted row in `rows_skipped` against a source that still succeeded, so
/// this pins the unavailable-provider scenario end-to-end on the real chain.
#[test]
fn an_undecryptable_row_does_not_fail_the_chromium_source() {
  let temp = TempDir::new("chromium-undecryptable-row");
  let context = test_seams::current_context(temp.path().to_path_buf());
  let root = test_seams::primary_root_path(&context, "chrome");
  test_seams::seed_chromium_profile(&root, "Default", "Person 1");

  // Replace the plaintext cookie with a dual-populated v10 row no provider
  // can open. The row is unavailable, and its alternate plaintext must not
  // reach the report.
  let database = root.join("Default/Cookies");
  let connection = rusqlite::Connection::open(&database).expect("open cookie database");
  connection
    .execute("DELETE FROM cookies", [])
    .expect("clear seeded cookie");
  connection
    .execute(
      "INSERT INTO cookies VALUES ('.example.com', '/', 0, 0, 'locked',
       'plaintext sentinel must not escape', ?1, 0, 0)",
      [b"v10undecryptable".to_vec()],
    )
    .expect("insert encrypted cookie");
  drop(connection);

  let registry_report = test_seams::chromium_report(&context, "chrome", None, None, no_keys())
    .expect("chromium report");
  assert!(
    registry_report.installations[0].profiles[0]
      .sources
      .iter()
      .flat_map(|source| source.issues.iter())
      .any(|issue| issue.code == SourceIssue::ALL_ROWS_REJECTED),
    "the legacy projection must retain its all-row error"
  );
  let outcome = chromium_browser_outcome(&BrowserId::known("chrome"), registry_report)
    .expect("adapt the chromium report");
  let report = assemble(1, vec![outcome]);

  let source = &report.profiles[0].sources[0];
  assert_eq!(source.status, SourceStatusCode::succeeded());
  assert_eq!(source.stats.rows_seen, 1);
  assert_eq!(source.stats.rows_skipped, 1);
  assert!(source.cookies.is_empty());
  assert!(
    source.issues.iter().any(|issue| issue.is_error()
      && matches!(
        issue.code.as_str(),
        "provider_unavailable" | "provider_failed" | "decrypt_failed"
      )),
    "the unavailable row must be reported: {:?}",
    source.issues
  );
  // Acquisition and the query completed, so nothing failed at source level.
  assert!(!source
    .issues
    .iter()
    .any(|issue| issue.code.as_str() == "source_extraction_failed"));
  assert_eq!(report.status, ReportStatusCode::partial());
  assert_eq!(report.summary.sources_succeeded, 1);
  assert_eq!(report.summary.sources_failed, 0);
}

/// A confidential-session provider failure is a typed row rejection. It
/// must neither degrade to provider absence nor get relabeled as a generic
/// decrypt failure while travelling through the registry/report adapters.
#[test]
fn a_confidential_provider_failure_keeps_its_exact_report_code() {
  let temp = TempDir::new("chromium-confidential-provider-failure");
  let context = test_seams::current_context(temp.path().to_path_buf());
  let root = test_seams::primary_root_path(&context, "chrome");
  test_seams::seed_chromium_profile(&root, "Default", "Person 1");

  let database = root.join("Default/Cookies");
  let connection = rusqlite::Connection::open(&database).expect("open cookie database");
  connection
    .execute("DELETE FROM cookies", [])
    .expect("clear seeded cookie");
  connection
    .execute(
      "INSERT INTO cookies VALUES ('.example.com', '/', 0, 0, 'locked', '', ?1, 0, 0)",
      [b"v11undecryptable".to_vec()],
    )
    .expect("insert encrypted cookie");
  drop(connection);

  let keys = ChromiumKeyOutcomes {
    v10: ChromiumKeyOutcome::NotApplicable,
    v11: ChromiumKeyOutcome::failure("Secret Service confidential-session negotiation failed"),
    v20: ChromiumKeyOutcome::NotApplicable,
  };
  let registry_report =
    test_seams::chromium_report(&context, "chrome", None, None, keys).expect("chromium report");
  let outcome = chromium_browser_outcome(&BrowserId::known("chrome"), registry_report)
    .expect("adapt the chromium report");
  let report = assemble(1, vec![outcome]);

  let source = &report.profiles[0].sources[0];
  assert_eq!(source.status, SourceStatusCode::succeeded());
  assert_eq!(source.stats.rows_seen, 1);
  assert_eq!(source.stats.rows_skipped, 1);
  assert!(source.cookies.is_empty());
  assert_eq!(source.issues.len(), 1);
  assert_eq!(source.issues[0].code.as_str(), "provider_failed");
  assert_eq!(source.issues[0].stage.as_str(), "decrypt");
  assert_eq!(source.issues[0].cause, "credential_provider");
  assert_eq!(
    source.issues[0].provider.as_deref(),
    Some("platform_key_provider")
  );
  assert_eq!(source.issues[0].tier.as_deref(), Some("v11"));
  assert_eq!(source.issues[0].retryability, "retryable");
  let wire = serde_json::to_value(&report).expect("provider failure serializes");
  let wire_issue = &wire["profiles"][0]["sources"][0]["issues"][0];
  for key in ["cause", "provider", "tier", "retryability"] {
    assert!(wire_issue.get(key).is_some(), "missing {key}: {wire_issue}");
  }
  assert_eq!(report.status, ReportStatusCode::partial());
}
