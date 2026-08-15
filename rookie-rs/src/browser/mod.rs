pub(crate) mod chromium;
pub(crate) mod chromium_crypto;
pub(crate) mod chromium_platform_keys;
#[cfg(any(target_os = "windows", test))]
pub(crate) mod internet_explorer_model;
pub(crate) mod legacy;
pub(crate) mod mozilla;
pub(crate) mod registry;
pub(crate) mod report_build;
pub(crate) mod report_core;

#[cfg(target_os = "windows")]
pub(crate) mod internet_explorer;

#[cfg(any(target_os = "macos", test))]
pub(crate) mod safari;
