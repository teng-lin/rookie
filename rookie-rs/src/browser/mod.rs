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

  type MalformedCase = (&'static str, fn() -> anyhow::Result<()>);

  #[test]
  fn every_engine_decoder_is_host_neutral_and_unwind_safe_for_malformed_input() {
    let cases: [MalformedCase; 4] = [
      ("chromium", chromium_decoder::malformed_decoder_gate_case),
      ("mozilla", mozilla::malformed_decoder_gate_case),
      ("safari", safari::malformed_decoder_gate_case),
      (
        "internet_explorer",
        internet_explorer_model::malformed_decoder_gate_case,
      ),
    ];

    for (engine, case) in cases {
      let result = catch_unwind(AssertUnwindSafe(case));
      let result =
        result.unwrap_or_else(|_| panic!("{engine} decoder panicked on malformed input"));
      result.unwrap_or_else(|error| panic!("{engine} malformed-input gate failed: {error:#}"));
    }
  }
}
