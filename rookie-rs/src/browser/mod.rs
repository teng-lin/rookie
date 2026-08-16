pub(crate) mod chromium;
pub(crate) mod chromium_crypto;
#[cfg(any(target_os = "windows", test))]
pub(crate) mod chromium_database_acquisition;
pub(crate) mod chromium_decoder;
pub(crate) mod chromium_platform_keys;
pub(crate) mod cookie_record;
#[cfg(any(target_os = "windows", test))]
pub(crate) mod internet_explorer_model;
pub(crate) mod legacy;
pub(crate) mod mozilla;
pub(crate) mod registry;
pub(crate) mod report_build;
pub(crate) mod report_core;
pub(crate) mod unseal;

#[cfg(target_os = "windows")]
pub(crate) mod internet_explorer;

#[cfg(any(target_os = "macos", test))]
pub(crate) mod safari;
