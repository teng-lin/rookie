//! Finds every platform-conditional `cfg`/`cfg_attr` attribute in a Rust
//! source file, using `syn` to walk the real token tree rather than
//! scanning raw text -- so a multi-line attribute, or `cfg` merely
//! mentioned inside a doc comment or string literal, can't produce a false
//! positive or a false negative the way a regex scan over source lines
//! could.
//!
//! Deliberately does not parse `cfg()`'s boolean predicate grammar (no
//! `any`/`all`/`not` structure, no `cfg-expr` dependency): every check here
//! only asks "does this attribute mention a platform identifier anywhere",
//! which is all issue #218's allowlist needs.

use proc_macro2::TokenTree;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::Attribute;

const PLATFORM_IDENTS: &[&str] = &[
  "target_os",
  "windows",
  "unix",
  "macos",
  "linux",
  "freebsd",
  "android",
  "ios",
];

#[derive(Debug, Clone)]
pub struct CfgHit {
  pub line: usize,
  pub column: usize,
  pub snippet: String,
}

#[derive(Default)]
struct CfgVisitor {
  hits: Vec<CfgHit>,
}

impl<'ast> Visit<'ast> for CfgVisitor {
  fn visit_attribute(&mut self, attr: &'ast Attribute) {
    if is_cfg_family(attr) && attribute_mentions_platform(attr) {
      let start = attr.span().start();
      self.hits.push(CfgHit {
        line: start.line,
        column: start.column,
        snippet: rendered(attr),
      });
    }
    syn::visit::visit_attribute(self, attr);
  }
}

fn is_cfg_family(attr: &Attribute) -> bool {
  attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr")
}

fn attribute_mentions_platform(attr: &Attribute) -> bool {
  match &attr.meta {
    syn::Meta::List(list) => tokens_mention_platform(list.tokens.clone()),
    _ => false,
  }
}

fn tokens_mention_platform(tokens: proc_macro2::TokenStream) -> bool {
  tokens.into_iter().any(|token| match token {
    TokenTree::Ident(ident) => PLATFORM_IDENTS.contains(&ident.to_string().as_str()),
    TokenTree::Group(group) => tokens_mention_platform(group.stream()),
    TokenTree::Punct(_) | TokenTree::Literal(_) => false,
  })
}

fn rendered(attr: &Attribute) -> String {
  use quote::ToTokens;
  let mut out = String::new();
  out.push_str(if matches!(attr.style, syn::AttrStyle::Inner(_)) {
    "#!["
  } else {
    "#["
  });
  out.push_str(&attr.meta.to_token_stream().to_string());
  out.push(']');
  out
}

/// Parses `source` and returns every platform-conditional `cfg`/`cfg_attr`
/// hit found in it, in source order. The caller already knows which file
/// `source` came from, so hits carry only their position within it.
pub fn scan_source(source: &str) -> Result<Vec<CfgHit>, syn::Error> {
  let parsed = syn::parse_file(source)?;
  let mut visitor = CfgVisitor::default();
  visitor.visit_file(&parsed);
  Ok(visitor.hits)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn hits(source: &str) -> Vec<CfgHit> {
    scan_source(source).expect("valid Rust source")
  }

  #[test]
  fn finds_a_simple_single_line_cfg() {
    let found = hits(
      r#"
      #[cfg(target_os = "windows")]
      fn windows_only() {}
      "#,
    );
    assert_eq!(found.len(), 1);
    assert!(found[0].snippet.contains("target_os"));
  }

  #[test]
  fn finds_a_multi_line_cfg_attribute() {
    let found = hits(
      r#"
      #[cfg(not(any(
        target_os = "macos",
        target_os = "windows"
      )))]
      mod other;
      "#,
    );
    assert_eq!(found.len(), 1);
  }

  #[test]
  fn finds_cfg_attr_form() {
    let found = hits(
      r#"
      #[cfg_attr(unix, derive(Debug))]
      struct Thing;
      "#,
    );
    assert_eq!(found.len(), 1);
  }

  #[test]
  fn ignores_platform_words_in_doc_comments_and_strings() {
    let found = hits(
      r#"
      /// This runs differently on target_os = "windows" than elsewhere.
      fn documented() {
        let message = "cfg(unix) is just a string here, not an attribute";
        let _ = message;
      }
      "#,
    );
    assert!(found.is_empty(), "expected no hits, got {found:?}");
  }

  #[test]
  fn ignores_non_platform_cfg() {
    let found = hits(
      r#"
      #[cfg(test)]
      mod tests {}

      #[cfg(feature = "appbound")]
      fn gated() {}
      "#,
    );
    assert!(found.is_empty(), "expected no hits, got {found:?}");
  }

  #[test]
  fn finds_inner_cfg_attribute() {
    let found = hits(
      r#"
      #![cfg(target_os = "linux")]
      fn linux_only() {}
      "#,
    );
    assert_eq!(found.len(), 1);
  }

  #[test]
  fn counts_two_attributes_on_one_item_separately() {
    let found = hits(
      r#"
      #[cfg(target_os = "macos")]
      #[cfg(test)]
      fn odd_combination() {}
      "#,
    );
    assert_eq!(found.len(), 1);
  }
}
