//! Golden report snapshots — the executable freeze.
//!
//! Characterization tests pin behavior one assertion at a time, which leaves
//! the *shape* of a report unguarded: a refactor can move a field, drop an
//! issue, or reorder profiles without any single assertion noticing. These
//! snapshots pin the whole serialized report so a wire change is a red test,
//! not a silent regression.
//!
//! Reports are not byte-stable as captured. Two things move between runs:
//! absolute paths (tests run under a randomized temp root) and the opaque
//! `installation_id` / `profile_id`, which are SHA-256 over path bytes. Both
//! are normalized below. `source_digest` needs no handling — it never reaches
//! the wire.
//!
//! Goldens are per-target-OS because root-relative paths differ per platform,
//! the same way `public-api/*.txt` is already split.
//!
//! Regenerate with `UPDATE_GOLDENS=1 cargo test -p rookie-cookies --test
//! report_goldens`, then read the diff before committing it. A golden that
//! changes without an intended behavior change is a bug in the change, not in
//! the snapshot.

#![allow(deprecated)]

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

/// Discovery snapshots the process environment, so every capture holds this
/// for its duration.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Everything discovery reads to locate an installation root on any platform.
/// All are overridden together so a variable this host happens to set cannot
/// point discovery back outside the synthetic home.
const ISOLATED_VARS: &[&str] = &[
  "HOME",
  "USERPROFILE",
  "XDG_CONFIG_HOME",
  "CHROME_CONFIG_HOME",
  "LOCALAPPDATA",
  "APPDATA",
];

fn set_var(name: &str, value: &Path) {
  set_os_var(name, value.as_os_str());
}

fn set_os_var(name: &str, value: &OsStr) {
  // SAFETY: ENV_LOCK is held, so no other test thread reads or writes the
  // environment while it changes.
  unsafe {
    std::env::set_var(name, value);
  }
}

fn remove_var(name: &str) {
  // SAFETY: see `set_os_var`.
  unsafe {
    std::env::remove_var(name);
  }
}

/// A temporary home directory installed into the process environment.
///
/// Restores the previous values and removes the directory on drop, including
/// on unwind, and holds the environment lock until then.
struct SyntheticHome<'a> {
  home: PathBuf,
  restored: Vec<(&'static str, Option<OsString>)>,
  _lock: MutexGuard<'a, ()>,
}

impl SyntheticHome<'_> {
  fn new(tag: &str) -> Self {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let lock = ENV_LOCK
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    let home = std::env::temp_dir().join(format!(
      "rookie-goldens-{tag}-{}-{}",
      std::process::id(),
      COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&home).expect("create synthetic home");

    let restored = ISOLATED_VARS
      .iter()
      .map(|name| (*name, std::env::var_os(name)))
      .collect();
    let home = SyntheticHome {
      home,
      restored,
      _lock: lock,
    };
    set_var("HOME", &home.home);
    set_var("USERPROFILE", &home.home);
    set_var("XDG_CONFIG_HOME", &home.home.join(".config"));
    set_var("LOCALAPPDATA", &home.home.join("AppData/Local"));
    set_var("APPDATA", &home.home.join("AppData/Roaming"));
    remove_var("CHROME_CONFIG_HOME");
    home
  }

  fn chrome_root(&self) -> PathBuf {
    #[cfg(target_os = "macos")]
    return self.home.join("Library/Application Support/Google/Chrome");
    #[cfg(target_os = "windows")]
    return self.home.join("AppData/Local/Google/Chrome/User Data");
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    return self.home.join(".config/google-chrome");
  }

  #[cfg(target_os = "macos")]
  fn firefox_root(&self) -> PathBuf {
    #[cfg(target_os = "macos")]
    return self.home.join("Library/Application Support/Firefox");
    #[cfg(target_os = "windows")]
    return self.home.join("AppData/Roaming/Mozilla/Firefox");
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    return self.home.join(".mozilla/firefox");
  }

  #[cfg(target_os = "macos")]
  fn safari_cookie_dir(&self) -> PathBuf {
    self
      .home
      .join("Library/Containers/com.apple.Safari/Data/Library/Cookies")
  }

  /// Every spelling of the root that can reach a report: the path installed
  /// into the environment, and its realpath. On macOS `std::env::temp_dir()`
  /// is `/var/folders/...` whose realpath is `/private/var/folders/...`, and
  /// discovery canonicalizes installation roots.
  fn root_spellings(&self) -> Vec<String> {
    let mut roots = vec![self.home.to_string_lossy().into_owned()];
    if let Ok(canonical) = self.home.canonicalize() {
      roots.push(canonical.to_string_lossy().into_owned());
    }
    // Longest first: "/private/var/x" contains "/var/x", so replacing the
    // short spelling first would corrupt the long one.
    roots.sort_by_key(|root| std::cmp::Reverse(root.len()));
    roots.dedup();
    roots
  }
}

impl Drop for SyntheticHome<'_> {
  fn drop(&mut self) {
    for (name, value) in &self.restored {
      match value {
        Some(value) => set_os_var(name, value),
        None => remove_var(name),
      }
    }
    let _ = std::fs::remove_dir_all(&self.home);
  }
}

// ---------------------------------------------------------------- seeding --

fn seed_chromium_profile(root: &Path, profile: &str, name: &str, value: &str) {
  let database = root.join(profile).join("Network/Cookies");
  std::fs::create_dir_all(database.parent().expect("profile directory"))
    .expect("create profile directory");
  let connection = rusqlite::Connection::open(&database).expect("open cookie database");
  connection
    .execute_batch(
      "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
      INSERT INTO meta (key, value) VALUES ('version', '23');
      CREATE TABLE cookies (
        host_key TEXT NOT NULL,
        path TEXT NOT NULL,
        is_secure INTEGER NOT NULL,
        expires_utc INTEGER NOT NULL,
        name TEXT NOT NULL,
        value TEXT NOT NULL,
        encrypted_value BLOB NOT NULL,
        is_httponly INTEGER NOT NULL,
        samesite INTEGER NOT NULL
      );",
    )
    .expect("create cookies table");
  connection
    .execute(
      "INSERT INTO cookies VALUES ('.example.test', '/', 0, 0, ?1, ?2, ?3, 0, 0)",
      rusqlite::params![name, value, Vec::<u8>::new()],
    )
    .expect("insert cookie");
  std::fs::write(root.join("Local State"), b"{}").expect("write Local State");
}

/// Two profiles so the golden pins profile ordering and the shared
/// installation id, not just a single row.
fn seed_chrome(home: &SyntheticHome<'_>) {
  let root = home.chrome_root();
  seed_chromium_profile(&root, "Default", "session", "default-value");
  seed_chromium_profile(&root, "Profile 1", "session", "profile-value");
}

#[cfg(target_os = "macos")]
fn seed_firefox_profile(root: &Path, relative: &str, name: &str, value: &str) {
  let profile = root.join(relative);
  std::fs::create_dir_all(&profile).expect("create profile directory");
  let connection =
    rusqlite::Connection::open(profile.join("cookies.sqlite")).expect("open cookie database");
  connection
    .execute_batch(
      "PRAGMA user_version = 15;
      CREATE TABLE moz_cookies (
        host TEXT, path, isSecure, expiry, name TEXT, value TEXT,
        isHttpOnly, sameSite, originAttributes
      );",
    )
    .expect("create moz_cookies table");
  connection
    .execute(
      "INSERT INTO moz_cookies VALUES ('.example.test', '/', 0, 0, ?1, ?2, 0, 0, '')",
      rusqlite::params![name, value],
    )
    .expect("insert cookie");
}

/// Default-second in declaration order so the golden pins the default-first
/// listing sort rather than incidental ini order.
#[cfg(target_os = "macos")]
fn seed_firefox(home: &SyntheticHome<'_>) {
  let root = home.firefox_root();
  std::fs::create_dir_all(&root).expect("create firefox root");
  seed_firefox_profile(&root, "Profiles/other", "session", "other-value");
  seed_firefox_profile(&root, "Profiles/abc.default-release", "session", "default-value");
  std::fs::write(
    root.join("profiles.ini"),
    "[Profile0]\nName=other\nIsRelative=1\nPath=Profiles/other\nDefault=0\n\n\
     [Profile1]\nName=default\nIsRelative=1\nPath=Profiles/abc.default-release\nDefault=1\n",
  )
  .expect("write profiles.ini");
}

/// A valid, empty BinaryCookies file: the `cook` magic plus a zero page count.
/// Enough to reach the report as a succeeded source, which is what the freeze
/// is about; cookie decoding is pinned by the BinaryCookies unit tests.
#[cfg(target_os = "macos")]
fn seed_safari(home: &SyntheticHome<'_>) {
  let cookies = home.safari_cookie_dir();
  std::fs::create_dir_all(&cookies).expect("create Safari cookie directory");
  std::fs::write(cookies.join("Cookies.binarycookies"), b"cook\x00\x00\x00\x00")
    .expect("seed Safari cookie file");
}

// ----------------------------------------------------------- normalization --

/// Replace the synthetic root with a token, then replace every 64-character
/// lowercase-hex run — the opaque installation/profile ids, which are SHA-256
/// over path bytes — with its first-appearance rank.
///
/// Ranking rather than blanking keeps a real property under test: an id that
/// appears in two places must still be the same token in both, so a golden
/// notices if two profiles start sharing a profile id.
fn normalize(json: &str, roots: &[String]) -> String {
  let mut text = json.to_owned();
  for root in roots {
    text = text.replace(root.as_str(), "<ROOT>");
    // Windows serializes `\` as `\\` inside JSON strings.
    text = text.replace(&root.replace('\\', "\\\\"), "<ROOT>");
  }
  rank_opaque_ids(&text)
}

fn rank_opaque_ids(input: &str) -> String {
  let bytes = input.as_bytes();
  let mut out = String::with_capacity(input.len());
  let mut seen: Vec<&str> = Vec::new();
  let mut index = 0;

  while index < bytes.len() {
    if bytes[index].is_ascii_hexdigit() {
      let start = index;
      while index < bytes.len() && bytes[index].is_ascii_hexdigit() {
        index += 1;
      }
      let run = &input[start..index];
      let is_opaque_id = run.len() == 64
        && run
          .bytes()
          .all(|byte| byte.is_ascii_digit() || byte.is_ascii_lowercase());
      if is_opaque_id {
        let rank = match seen.iter().position(|candidate| *candidate == run) {
          Some(rank) => rank,
          None => {
            seen.push(run);
            seen.len() - 1
          }
        };
        out.push_str(&format!("<ID:{rank}>"));
      } else {
        out.push_str(run);
      }
    } else {
      let character = input[index..].chars().next().expect("char boundary");
      let width = character.len_utf8();
      out.push_str(&input[index..index + width]);
      index += width;
    }
  }
  out
}

// ------------------------------------------------------------- comparison --

// Golden comparison is compiled only for captured platforms; see the gates on
// the tests below.
#[cfg(target_os = "macos")]
fn golden_path(name: &str) -> PathBuf {
  Path::new(env!("CARGO_MANIFEST_DIR"))
    .join("tests/goldens")
    .join(std::env::consts::OS)
    .join(format!("{name}.json"))
}

#[cfg(target_os = "macos")]
fn updating() -> bool {
  std::env::var_os("UPDATE_GOLDENS").is_some_and(|value| !value.is_empty())
}

#[cfg(target_os = "macos")]
fn assert_golden(name: &str, actual: &str) {
  let path = golden_path(name);
  if updating() {
    std::fs::create_dir_all(path.parent().expect("golden directory"))
      .expect("create golden directory");
    std::fs::write(&path, actual).expect("write golden");
    return;
  }

  let expected = match std::fs::read_to_string(&path) {
    Ok(expected) => expected,
    Err(error) => panic!(
      "missing golden {}: {error}\nRegenerate with UPDATE_GOLDENS=1 cargo test -p \
       rookie-cookies --test report_goldens",
      path.display()
    ),
  };

  if expected == actual {
    return;
  }

  let divergence = expected
    .lines()
    .zip(actual.lines())
    .enumerate()
    .find(|(_, (expected, actual))| expected != actual);
  let detail = match divergence {
    Some((line, (expected, actual))) => format!(
      "first divergence at line {}:\n  golden: {expected}\n  actual: {actual}",
      line + 1
    ),
    None => format!(
      "same prefix, different length: golden {} lines, actual {} lines",
      expected.lines().count(),
      actual.lines().count()
    ),
  };
  panic!(
    "report golden {} no longer matches.\n{detail}\n\nIf this change is \
     intended, regenerate with UPDATE_GOLDENS=1 and explain the diff in the \
     commit message.",
    path.display()
  );
}

/// Capture one browser's listing and extract reports as one normalized
/// document. Both live in a single golden so a change that moves a source
/// between them cannot hide.
fn capture(browser_id: &str, home: &SyntheticHome<'_>) -> String {
  let listing = rookie_cookies::browser_profiles(browser_id).expect("listing");
  let extract = rookie_cookies::browser_report(browser_id, None, None).expect("extract report");

  let document = serde_json::json!({
    "listing": serde_json::to_value(&listing).expect("serialize listing"),
    "extract": serde_json::to_value(&extract).expect("serialize extract"),
  });
  let rendered = serde_json::to_string_pretty(&document).expect("render json");
  let normalized = normalize(&rendered, &home.root_spellings());

  assert!(
    !normalized.contains(&home.home.to_string_lossy().into_owned()),
    "a synthetic path survived normalization in the {browser_id} capture"
  );
  normalized
}

// ------------------------------------------------------------------ tests --

// Goldens are captured per target OS, and only macOS has been captured so far.
// The gates below say exactly that: on an uncaptured platform there is no
// golden to enforce, so the test does not exist rather than passing vacuously.
//
// To capture another platform, on a host of that platform:
//
//   UPDATE_GOLDENS=1 cargo test -p rookie-cookies --test report_goldens
//
// then commit `rookie-rs/tests/goldens/<os>/` and widen these gates to include
// it. `normalization_survives_a_different_synthetic_root` runs everywhere and
// already proves the harness itself is portable, so capturing is the only work
// involved.

#[cfg(target_os = "macos")]
#[test]
fn chrome_reports_match_the_golden() {
  let home = SyntheticHome::new("chrome");
  seed_chrome(&home);
  assert_golden("chrome", &capture("chrome", &home));
}

#[cfg(target_os = "macos")]
#[test]
fn firefox_reports_match_the_golden() {
  let home = SyntheticHome::new("firefox");
  seed_firefox(&home);
  assert_golden("firefox", &capture("firefox", &home));
}

#[cfg(target_os = "macos")]
#[test]
fn safari_reports_match_the_golden() {
  let home = SyntheticHome::new("safari");
  seed_safari(&home);
  assert_golden("safari", &capture("safari", &home));
}

/// The normalization is load-bearing: if it stopped firing, every golden
/// would still pass while pinning nothing. Two different roots must produce
/// the same normalized bytes, and the raw bytes must actually have differed.
#[test]
fn normalization_survives_a_different_synthetic_root() {
  let (first, first_raw) = {
    let home = SyntheticHome::new("norm-a");
    seed_chrome(&home);
    let raw = serde_json::to_string_pretty(
      &serde_json::to_value(rookie_cookies::browser_report("chrome", None, None).expect("report"))
        .expect("serialize"),
    )
    .expect("render");
    (capture("chrome", &home), raw)
  };
  let (second, second_raw) = {
    let home = SyntheticHome::new("norm-b");
    seed_chrome(&home);
    let raw = serde_json::to_string_pretty(
      &serde_json::to_value(rookie_cookies::browser_report("chrome", None, None).expect("report"))
        .expect("serialize"),
    )
    .expect("render");
    (capture("chrome", &home), raw)
  };

  assert_ne!(
    first_raw, second_raw,
    "raw reports were identical, so this proves nothing about normalization"
  );
  assert_eq!(
    first, second,
    "normalized reports differ between two synthetic roots"
  );
  assert!(first.contains("<ROOT>"), "no path was normalized");
  assert!(first.contains("<ID:0>"), "no opaque id was normalized");
}
