//! Whether a job may read a browser's separately declared session store.

/// Whether a snapshot or flat extract may acquire session-role sources.
///
/// This is orthogonal to profile selection. Before 0.6.0 the two were
/// conflated: passing a profile query was what made Gecko session JSON
/// eligible, so "I want that profile" and "I want session cookies" could not
/// be asked separately, and `read(ReadRequest::browser("firefox"))` could not
/// ask for session cookies at all.
///
/// # Where the gate lives
///
/// `IncludeSession` is an **acquire-time** rule, not a filter over the
/// returned cookies. Under [`PersistentOnly`](Self::PersistentOnly) the
/// session-role candidates are dropped from the plan before any lookup, so the
/// crate never opens `sessionstore.js` or `recovery.jsonlz4` — files a caller
/// choosing this policy has asked it not to touch. A post-projection filter
/// would return the same cookies and still have read them.
///
/// Chromium browsers declare no separate session source in the registry, so
/// the policy is a no-op there.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SessionPolicy {
  /// Acquire only persistent cookie stores.
  #[default]
  PersistentOnly,
  /// Also acquire the browser's declared session store.
  IncludeSession,
}
