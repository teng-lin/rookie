pub(crate) mod chromium;
pub(crate) mod chromium_crypto;
#[cfg(any(target_os = "windows", test))]
pub(crate) mod chromium_database_acquisition;
pub(crate) mod chromium_decoder;
pub(crate) mod chromium_platform_keys;
pub(crate) mod cookie_record;
pub(crate) mod internet_explorer_model;
pub(crate) mod legacy;
pub(crate) mod mozilla;
pub(crate) mod outcome;
pub(crate) mod registry;
pub(crate) mod report_build;
pub(crate) mod report_core;
pub(crate) mod unseal;

#[cfg(target_os = "windows")]
pub(crate) mod internet_explorer;

pub(crate) mod safari;

#[cfg(test)]
mod decoder_malformed_gate {
  use super::{chromium_decoder, internet_explorer_model, mozilla, safari};
  use std::panic::{catch_unwind, AssertUnwindSafe};

  type MalformedCase = (&'static str, fn(&[u8]) -> anyhow::Result<()>);
  type StructuredCase = (&'static str, fn() -> anyhow::Result<()>);

  const CORPUS_SEED: u64 = 0x2255_7a11_c0de_f00d;
  const GENERATED_CASES: usize = 64;
  const CRAFTED_CASES: usize = 8;
  const MAX_CASE_BYTES: usize = 256;

  fn malformed_corpus() -> Vec<Vec<u8>> {
    let mut corpus = vec![
      Vec::new(),
      vec![0],
      vec![0xff],
      b"COOK".to_vec(),
      b"mozLz40\0".to_vec(),
      br#"{"windows":[{"cookies":[]}]}"#.to_vec(),
      vec![0; MAX_CASE_BYTES],
      vec![0xff; MAX_CASE_BYTES],
    ];
    let mut state = CORPUS_SEED;
    for case_index in 0..GENERATED_CASES {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      let len = (state as usize).wrapping_add(case_index) % (MAX_CASE_BYTES + 1);
      let mut bytes = Vec::with_capacity(len);
      for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.push(state as u8);
      }
      corpus.push(bytes);
    }
    corpus
  }

  #[test]
  fn every_engine_decoder_is_host_neutral_and_unwind_safe_for_malformed_input() {
    let cases: [MalformedCase; 3] = [
      ("chromium", chromium_decoder::malformed_decoder_gate_case),
      ("safari", safari::malformed_decoder_gate_case),
      (
        "internet_explorer",
        internet_explorer_model::malformed_decoder_gate_case,
      ),
    ];

    let corpus = malformed_corpus();
    assert_eq!(corpus.len(), GENERATED_CASES + CRAFTED_CASES);
    assert!(corpus.iter().all(|input| input.len() <= MAX_CASE_BYTES));

    for (case_index, input) in corpus.iter().enumerate() {
      for &(engine, case) in &cases {
        let result = catch_unwind(AssertUnwindSafe(|| case(input)));
        let result = result.unwrap_or_else(|_| {
          panic!(
            "{engine} decoder panicked on malformed corpus case {case_index} (seed {CORPUS_SEED:#x})"
          )
        });
        result.unwrap_or_else(|error| {
          panic!(
            "{engine} malformed corpus case {case_index} failed (seed {CORPUS_SEED:#x}): {error:#}"
          )
        });
      }
    }

    let structured: [StructuredCase; 3] = [
      (
        "mozilla_persistent_sqlite",
        mozilla::structured_persistent_decoder_gate,
      ),
      (
        "mozilla_session_legacy_json",
        mozilla::structured_legacy_session_decoder_gate,
      ),
      (
        "mozilla_session_jsonlz4",
        mozilla::structured_jsonlz4_session_decoder_gate,
      ),
    ];
    for (stage, case) in structured {
      let result = catch_unwind(AssertUnwindSafe(case));
      let result = result.unwrap_or_else(|_| panic!("{stage} structured decoder corpus panicked"));
      result.unwrap_or_else(|error| panic!("{stage} structured decoder corpus failed: {error:#}"));
    }
  }
}
