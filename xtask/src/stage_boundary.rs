//! Fences the listing/extract stage boundary.
//!
//! The stage-boundary refactor's whole point is that a listing value cannot
//! carry the next stage's data: a `SourceCandidate` has no records, a
//! `DiscoveredProfile` has no `Vec<Source>`, and a `Source` has no cookies.
//! Today rustc enforces that, because the fields simply do not exist.
//!
//! Nothing stops a later change from adding one back, though, and the moment
//! it does the compiler stops being the reviewer and the rule quietly becomes
//! a social one again. This check keeps it mechanical: it parses the real
//! token tree and fails if a fenced type grows a forbidden field, including
//! under `#[cfg(test)]`.
//!
//! It is emphatically not a size lint. It looks at named struct fields only --
//! never at line counts, file lengths, or how many types a module holds.

use std::collections::BTreeSet;
use syn::visit::Visit;

/// A struct that must not gain a given field.
///
/// Bound to its defining file as well as its name: a bare name would let an
/// unrelated `struct Source` elsewhere in the tree satisfy the presence check,
/// and would aim this fence's violations at the wrong type.
struct Fence {
  /// Struct name, matched exactly.
  type_name: &'static str,
  /// Repository-relative path of the file that defines it.
  path: &'static str,
  /// Field names this struct must never declare.
  forbidden_fields: &'static [&'static str],
  /// Why, quoted back to whoever trips it.
  reason: &'static str,
}

const FENCES: &[Fence] = &[
  Fence {
    type_name: "SourceCandidate",
    path: "rookie-rs/src/browser/source.rs",
    // `failure` is here for the same reason as `records`: a candidate that
    // could hold one would be carrying the outcome of a read it never did.
    forbidden_fields: &[
      "cookies", "records", "stats", "issues", "sources", "failure",
    ],
    reason: "a candidate is what discovery found on disk; it must not carry \
             what reading it produced",
  },
  Fence {
    type_name: "Source",
    path: "rookie-rs/src/browser/source.rs",
    forbidden_fields: &["cookies", "profile_id", "installation_id", "display_name"],
    reason: "records are the only supply of finalized rows, and report identity \
             belongs to the profile that owns the source",
  },
  Fence {
    type_name: "DiscoveredProfile",
    path: "rookie-rs/src/browser/registry.rs",
    forbidden_fields: &["sources", "cookies", "records"],
    reason: "a listing profile must have nowhere to put an extraction result",
  },
  Fence {
    type_name: "EngineListing",
    path: "rookie-rs/src/browser/registry.rs",
    forbidden_fields: &["sources", "cookies", "records"],
    reason: "listing must not be able to return extract results",
  },
  Fence {
    type_name: "ChromiumProfile",
    path: "rookie-rs/src/browser/registry/chromium.rs",
    forbidden_fields: &["cookies", "records", "sources"],
    reason: "Chromium inventory stays cookie-free; extraction results live on \
             the extract bag",
  },
];

#[derive(Debug)]
pub(crate) struct Violation {
  pub(crate) file: String,
  pub(crate) type_name: String,
  pub(crate) field: String,
  pub(crate) line: usize,
  pub(crate) reason: &'static str,
}

impl std::fmt::Display for Violation {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      formatter,
      "{}:{}: `{}` declares forbidden field `{}` -- {}",
      self.file, self.line, self.type_name, self.field, self.reason
    )
  }
}

struct FenceVisitor<'a> {
  file: &'a str,
  violations: Vec<Violation>,
}

impl<'ast> Visit<'ast> for FenceVisitor<'_> {
  fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
    let name = item.ident.to_string();
    if let Some(fence) = FENCES
      .iter()
      .find(|fence| fence.type_name == name && fence.path == self.file)
    {
      for field in &item.fields {
        let Some(ident) = field.ident.as_ref() else {
          continue;
        };
        let field_name = ident.to_string();
        if fence.forbidden_fields.contains(&field_name.as_str()) {
          self.violations.push(Violation {
            file: self.file.to_owned(),
            type_name: name.clone(),
            field: field_name,
            line: ident.span().start().line,
            reason: fence.reason,
          });
        }
      }
    }
    syn::visit::visit_item_struct(self, item);
  }
}

/// Every fence, identified the way it is matched: by defining file and name.
pub(crate) fn fenced_types() -> BTreeSet<(&'static str, &'static str)> {
  FENCES
    .iter()
    .map(|fence| (fence.path, fence.type_name))
    .collect()
}

/// A fenced type as it was found on disk: `(repo-relative path, type name)`.
pub(crate) type FoundType = (String, String);

/// What one file yielded: its violations, and the fenced types it defines.
pub(crate) type FileScan = (Vec<Violation>, BTreeSet<FoundType>);

/// Returns the forbidden fields declared in one file, plus the fenced types it
/// defines -- each as `(path, type_name)`, so a same-named struct in another
/// file neither satisfies a fence nor attracts its violations.
pub(crate) fn scan_file(path: &str, source: &str) -> Result<FileScan, String> {
  let parsed =
    syn::parse_file(source).map_err(|error| format!("failed to parse {path}: {error}"))?;
  let mut visitor = FenceVisitor {
    file: path,
    violations: Vec::new(),
  };
  visitor.visit_file(&parsed);

  let mut defined = BTreeSet::new();
  collect_defined(path, &parsed.items, &mut defined);
  Ok((visitor.violations, defined))
}

fn collect_defined(path: &str, items: &[syn::Item], defined: &mut BTreeSet<FoundType>) {
  for item in items {
    match item {
      syn::Item::Struct(item) => {
        let name = item.ident.to_string();
        if FENCES
          .iter()
          .any(|fence| fence.type_name == name && fence.path == path)
        {
          defined.insert((path.to_owned(), name));
        }
      }
      syn::Item::Mod(module) => {
        if let Some((_, items)) = module.content.as_ref() {
          collect_defined(path, items, defined);
        }
      }
      _ => {}
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn a_clean_candidate_passes() {
    let source = r#"
      pub(crate) struct SourceCandidate {
        pub(crate) path: PathBuf,
        pub(crate) precedence: u16,
      }
    "#;
    let (violations, defined) =
      scan_file("rookie-rs/src/browser/source.rs", source).expect("parses");
    assert!(violations.is_empty());
    assert!(defined.contains(&(
      "rookie-rs/src/browser/source.rs".to_owned(),
      "SourceCandidate".to_owned()
    )));
  }

  /// `Source` owns `failure`; a candidate that could hold one would be
  /// carrying the outcome of a read it never performed.
  #[test]
  fn a_candidate_that_regrows_failure_fails() {
    let source = r#"
      pub(crate) struct SourceCandidate {
        pub(crate) path: PathBuf,
        pub(crate) failure: Option<SourceFailure>,
      }
    "#;
    let (violations, _) = scan_file("rookie-rs/src/browser/source.rs", source).expect("parses");
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].field, "failure");
  }

  /// A fence is bound to the file that defines its type. An unrelated struct
  /// that happens to share the name must neither attract the fence's
  /// violations nor satisfy its presence check -- otherwise renaming the real
  /// type away could be masked by any same-named struct elsewhere.
  #[test]
  fn a_same_named_struct_in_another_file_is_neither_fenced_nor_counted() {
    let source = r#"
      pub(crate) struct Source {
        pub(crate) cookies: Vec<Cookie>,
      }
    "#;
    let (violations, defined) =
      scan_file("rookie-rs/src/browser/unrelated.rs", source).expect("parses");
    assert!(
      violations.is_empty(),
      "an unrelated same-named struct must not attract the fence"
    );
    assert!(
      defined.is_empty(),
      "an unrelated same-named struct must not satisfy the presence check"
    );
  }

  #[test]
  fn a_candidate_that_regrows_records_fails() {
    let source = r#"
      pub(crate) struct SourceCandidate {
        pub(crate) path: PathBuf,
        pub(crate) records: Vec<CookieRecord>,
      }
    "#;
    let (violations, _) = scan_file("rookie-rs/src/browser/source.rs", source).expect("parses");
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].field, "records");
    assert_eq!(violations[0].type_name, "SourceCandidate");
  }

  /// The boundary is about representability, so a `cfg(test)`-only field
  /// counts: a test-only `cookies` field is exactly how the old drafts kept
  /// pretending a listing could hold results.
  #[test]
  fn a_cfg_test_only_field_still_fails() {
    let source = r#"
      pub(crate) struct Source {
        pub(crate) records: Vec<CookieRecord>,
        #[cfg(test)]
        pub(crate) cookies: Vec<Cookie>,
      }
    "#;
    let (violations, _) = scan_file("rookie-rs/src/browser/source.rs", source).expect("parses");
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].field, "cookies");
  }

  /// A `cookies()` method is fine and deliberately allowed -- projecting from
  /// records is how characterization tests read a source.
  #[test]
  fn a_cookies_method_is_not_a_field() {
    let source = r#"
      pub(crate) struct Source {
        pub(crate) records: Vec<CookieRecord>,
      }
      impl Source {
        #[cfg(test)]
        pub(crate) fn cookies(&self) -> Vec<Cookie> { Vec::new() }
      }
    "#;
    let (violations, _) = scan_file("rookie-rs/src/browser/source.rs", source).expect("parses");
    assert!(violations.is_empty());
  }

  #[test]
  fn a_listing_profile_that_regrows_sources_fails() {
    let source = r#"
      pub(crate) struct DiscoveredProfile {
        pub(crate) candidates: Vec<SourceCandidate>,
        pub(crate) sources: Vec<Source>,
      }
    "#;
    let (violations, _) = scan_file("rookie-rs/src/browser/registry.rs", source).expect("parses");
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].field, "sources");
  }

  #[test]
  fn an_unrelated_struct_is_ignored() {
    let source = r#"
      pub(crate) struct ExtractedProfile {
        pub(crate) sources: Vec<Source>,
      }
    "#;
    let (violations, _) = scan_file("rookie-rs/src/browser/registry.rs", source).expect("parses");
    assert!(
      violations.is_empty(),
      "extract profiles are supposed to hold sources"
    );
  }

  #[test]
  fn structs_nested_in_inline_modules_are_seen() {
    let source = r#"
      mod inner {
        pub(crate) struct SourceCandidate {
          pub(crate) cookies: Vec<Cookie>,
        }
      }
    "#;
    let (violations, defined) =
      scan_file("rookie-rs/src/browser/source.rs", source).expect("parses");
    assert_eq!(violations.len(), 1);
    assert!(defined.contains(&(
      "rookie-rs/src/browser/source.rs".to_owned(),
      "SourceCandidate".to_owned()
    )));
  }

  #[test]
  fn unparseable_source_fails_closed() {
    let error = scan_file("rookie-rs/src/browser/source.rs", "struct {")
      .expect_err("must not be silently skipped");
    assert!(error.contains("failed to parse"));
  }
}
