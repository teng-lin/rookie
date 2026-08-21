//! Deprecated crate-root named-browser APIs, and the `load` aggregator.
//!
//! These live here rather than in `lib.rs` for two reasons. `load` is a
//! concurrent aggregator over named browsers, which `browser/legacy.rs`'s
//! charter ("policy and result-shape compatibility only ... owns no browser
//! paths, credentials, discovery, acquisition, parsing, or decryption")
//! excludes. And `legacy_load_browsers` already listed every shim, so with the
//! shims in `lib.rs` the crate root and this module referred to each other.
//! `lib.rs` re-exports the names, so every public path is unchanged.

use super::legacy_load_browsers;
use crate::{browser, common, enums::Cookie, ExtractRequest, MozillaProfile};
use anyhow::Result;

/// Thin compatibility projection over registry-backed discovery/extraction.
pub(super) fn named_browser(name: &str, domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  browser(name, domains)
}

/// Returns cookies from Firefox
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::firefox(Some(domains));
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"firefox\", domains) or extract(ExtractRequest::browser(\"firefox\")) instead"
)]
pub fn firefox(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("firefox", domains)
}

/// Returns every Firefox profile that holds a cookie database.
///
/// [`firefox`] returns whichever profile it finds first, preferring the default
/// one; this lists them all so a caller can choose deliberately and pass the
/// choice to [`firefox_profile`].
///
/// Defaults are per-installation, so more than one profile can report
/// `is_default` when several Firefox installations are present.
///
/// # Examples
///
/// ```no_run
/// for profile in rookie_cookies::firefox_profiles()? {
///   println!("{} {} default={}", profile.name, profile.path.display(), profile.is_default);
/// }
/// # Ok::<(), rookie_cookies::anyhow::Error>(())
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use browser_profiles(\"firefox\") for ProfileDescriptor \
          (includes session-only profiles this list hides)"
)]
pub fn firefox_profiles() -> Result<Vec<MozillaProfile>> {
  browser::legacy::gecko_profiles("firefox")
}

/// Returns cookies from a specific Firefox profile.
///
/// # Arguments
///
/// * `profile` - The profile's name, directory name, or full path, as reported
///   by [`firefox_profiles`]
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::firefox_profile("default-release", Some(domains));
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use extract(ExtractRequest::browser(\"firefox\").profile(q)); \
          list with browser_profiles(\"firefox\")"
)]
pub fn firefox_profile(profile: &str, domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  // The bridge's Gecko profile selector has always included the profile's
  // declared session store, so it opts in explicitly now that the new surface
  // does not.
  crate::extract_inner(
    ExtractRequest::browser("firefox")
      .profile(profile)
      .domains(domains)
      .include_session()
      .execution(crate::legacy_execution()),
  )
}

/// Returns cookies from LibreWolf
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::librewolf(Some(domains));
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"librewolf\", domains) or extract(ExtractRequest::browser(\"librewolf\")) instead"
)]
pub fn librewolf(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("librewolf", domains)
}

/// Returns cookies from Cachy Browser (Linux only)
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::cachy(Some(domains));
/// ```
#[cfg(target_os = "linux")]
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"cachy\", domains) or extract(ExtractRequest::browser(\"cachy\")) instead"
)]
pub fn cachy(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("cachy", domains)
}

/// Returns cookies from Chrome
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::chrome(Some(domains));
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"chrome\", domains) or extract(ExtractRequest::browser(\"chrome\")) instead"
)]
pub fn chrome(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("chrome", domains)
}

/// Returns cookies from Chromium
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::chromium(Some(domains));
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"chromium\", domains) or extract(ExtractRequest::browser(\"chromium\")) instead"
)]
pub fn chromium(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("chromium", domains)
}

/// Returns cookies from Brave
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::brave(Some(domains));
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"brave\", domains) or extract(ExtractRequest::browser(\"brave\")) instead"
)]
pub fn brave(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("brave", domains)
}

/// Returns cookies from Arc
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::arc(Some(domains));
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"arc\", domains) or extract(ExtractRequest::browser(\"arc\")) instead"
)]
pub fn arc(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("arc", domains)
}

/// Returns cookies from Firefox
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::zen(Some(domains));
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"zen\", domains) or extract(ExtractRequest::browser(\"zen\")) instead"
)]
pub fn zen(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("zen", domains)
}

/// Returns cookies from Edge
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::edge(Some(domains));
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"edge\", domains) or extract(ExtractRequest::browser(\"edge\")) instead"
)]
pub fn edge(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("edge", domains)
}

/// Returns cookies from Vivaldi
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::vivaldi(Some(domains));
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"vivaldi\", domains) or extract(ExtractRequest::browser(\"vivaldi\")) instead"
)]
pub fn vivaldi(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("vivaldi", domains)
}

/// Returns cookies from Opera
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::opera(Some(domains));
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"opera\", domains) or extract(ExtractRequest::browser(\"opera\")) instead"
)]
pub fn opera(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("opera", domains)
}

/// Returns cookies from Opera GX
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::opera_gx(Some(domains));
/// ```
#[cfg_attr(
  any(target_os = "macos", target_os = "windows"),
  deprecated(
    since = "0.6.0",
    note = "use browser(\"opera_gx\", domains) or extract(ExtractRequest::browser(\"opera_gx\")) instead"
  )
)]
#[cfg_attr(
  not(any(target_os = "macos", target_os = "windows")),
  deprecated(
    since = "0.5.9",
    note = "Opera GX is unsupported on this target; this compatibility shim will be removed in 0.7"
  )
)]
pub fn opera_gx(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  super::opera_gx(domains)
}

/// Returns cookies from Octo Browser
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::octo_browser(Some(domains));
/// ```
#[cfg(target_os = "windows")]
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"octo_browser\", domains) or extract(ExtractRequest::browser(\"octo_browser\")) instead"
)]
pub fn octo_browser(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("octo_browser", domains)
}

/// Returns cookies from Safari (macOS only)
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::safari(Some(domains));
/// ```
#[cfg(target_os = "macos")]
#[deprecated(
  since = "0.6.0",
  note = "use browser(\"safari\", domains) or extract(ExtractRequest::browser(\"safari\")) instead"
)]
pub fn safari(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("safari", domains)
}

/// Returns cookies from Internet Explorer (Windows only)
///
/// Its cookie database uses the ESE (Extensible Storage Engine) format,
/// read here by linking an unmodified native C library (`libesedb`)
/// in-process with no process isolation, so a malformed or malicious
/// database can crash the whole host process rather than fail as a typed
/// error. Unlike this crate's bundled SQLite parser — pinned to an exact
/// version with its own tracked security inventory
/// (`docs/sqlite-security.md`) — `libesedb` carries no such inventory.
/// Containing that gap would mean running the parser in a sandboxed
/// subprocess; the Internet Explorer 11 browser app was discontinued in
/// 2022, and this crate is not planning to build that containment for it.
/// Internet Explorer support is deprecated for removal in a future major
/// version instead. `browser("internet_explorer", domains)` /
/// `extract(ExtractRequest::browser("internet_explorer"))` remain available for
/// the rest of the deprecation window.
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::internet_explorer(Some(domains));
/// ```
#[cfg(target_os = "windows")]
#[deprecated(
  since = "0.6.0",
  note = "Internet Explorer support is deprecated for removal; the Internet Explorer browser app was discontinued in 2022"
)]
pub fn internet_explorer(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  named_browser("internet_explorer", domains)
}

/// Folds one `fan_out` round's per-browser results into [`load`]'s answer.
///
/// Missing profiles were not extraction attempts. If at least one installed
/// browser failed and none succeeded, surface the real failures; a machine
/// with no supported browser installed legitimately has no cookies.
///
/// This is a separate function so the aggregation rules are reachable from a
/// test without a second implementation of them. The `#[cfg(test)]`
/// `load_from_browsers` that used to serve that purpose restated the rules
/// sequentially and never modelled either stop path, so its tests could stay
/// green while `load` regressed.
pub(crate) fn aggregate_load_results(
  names: &[&str],
  results: Vec<Result<Vec<Cookie>>>,
  runtime: &common::deadline::BoundaryRuntime<'_>,
) -> Result<Vec<Cookie>> {
  // `fan_out` silently stops claiming further browsers once the runtime
  // trips, so a shorter-than-`names` result set is itself evidence of a
  // stop even if no individual browser's own attempt happened to observe
  // and report it (e.g. every claimed browser was merely uninstalled).
  let attempted = results.len();
  let mut cookies = Vec::new();
  let mut errors = Vec::new();
  let mut terminal_stop = None;
  let mut successful_extractions = 0;
  for (browser_name, result) in names.iter().copied().zip(results) {
    match result {
      Ok(browser_cookies) => {
        successful_extractions += 1;
        cookies.extend(browser_cookies);
      }
      Err(error) if browser::legacy::is_browser_not_installed(&error) => {
        log::debug!("rookie_cookies::load skipping uninstalled {browser_name}: {error}");
      }
      Err(error) => {
        let stopped = error.chain().find_map(|cause| {
          cause
            .downcast_ref::<common::deadline::BoundaryStop>()
            .copied()
        });
        log::warn!("rookie_cookies::load skipping {browser_name}: {error}");
        errors.push(format!("{browser_name}: {error}"));
        if stopped.is_some() && terminal_stop.is_none() {
          terminal_stop = stopped;
        }
      }
    }
  }
  if attempted < names.len() && terminal_stop.is_none() {
    terminal_stop = runtime.check().err();
  }
  if successful_extractions == 0 && (!errors.is_empty() || terminal_stop.is_some()) {
    return Err(aggregate_load_failure(&errors, terminal_stop));
  }
  Ok(cookies)
}

pub(crate) fn aggregate_load_failure(
  errors: &[String],
  stop: Option<common::deadline::BoundaryStop>,
) -> anyhow::Error {
  let summary = if errors.is_empty() {
    // Reachable when the shared deadline/cancellation stopped `load()`
    // before any browser's own extraction attempt produced an error to
    // record -- e.g. every browser attempted before the stop was merely
    // uninstalled (not an "error"), and no browser was ever attempted after
    // it. `stop` (below) is always `Some` in this branch.
    "the operation stopped before any browser extraction reported an error".to_owned()
  } else {
    format!("all browser extractions failed:\n  {}", errors.join("\n  "))
  };
  match stop {
    Some(stop) => anyhow::Error::new(stop).context(summary),
    None => anyhow::anyhow!(summary),
  }
}

/// Returns cookies from all browsers
///
/// This is a best-effort aggregator: browsers are probed concurrently on a
/// small bounded worker pool sharing one deadline/cancellation budget, rather
/// than one at a time -- a slow or hung source no longer starves every other
/// source's share of that budget. Individual extraction failures are
/// surfaced via [`log::warn!`] but do not abort the load (a locked profile or
/// a decrypt failure on one browser should not lose cookies from the
/// others). Browsers without a discoverable profile are skipped normally. If
/// you need to know which browsers failed, hook a logger like
/// `tracing-subscriber` and watch for `rookie_cookies::load` warnings.
///
/// The returned cookies are grouped by browser in the same fixed order every
/// call attempts browsers in ([`crate::load_report`]'s browser ordering is tracked
/// separately, from the registry rather than this function's own list),
/// regardless of which browser's extraction actually finished first. Once
/// the shared deadline or cancellation trips, no not-yet-started browser is
/// attempted, but a browser already in flight at that moment still runs to
/// completion and its cookies are kept.
///
/// Returns `Err` only when at least one installed browser is found, every
/// attempted extraction fails, and none succeeds. The aggregate message lists
/// only genuine extraction failures. If no supported browser is installed,
/// returns an empty list.
///
/// # Arguments
///
/// * `domains` - A optional list that for getting specific domains only
///
/// # Examples
///
/// ```no_run
/// let domains = vec!["google.com".to_string()];
/// let cookies = rookie_cookies::load(Some(domains));
/// ```
#[deprecated(
  since = "0.6.0",
  note = "use read(ReadRequest::browser(...)) for snapshots or load_report for grouped multi-browser diagnostics"
)]
pub fn load(domains: Option<Vec<String>>) -> Result<Vec<Cookie>> {
  let browser_types = legacy_load_browsers();
  let names: Vec<&str> = browser_types.iter().map(|(name, _)| *name).collect();
  let clock = common::deadline::SystemClock;
  let runtime = common::deadline::BoundaryRuntime::standard(&clock);
  let results = common::concurrency::fan_out(
    &names,
    common::concurrency::DEFAULT_FAN_OUT_WIDTH,
    &runtime,
    |browser_name| {
      browser::legacy::browser_cookies_for_load_with_runtime(
        browser_name,
        domains.clone(),
        &runtime,
      )
    },
  );
  aggregate_load_results(&names, results, &runtime)
}
