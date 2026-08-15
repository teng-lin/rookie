mod shared;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
pub(crate) use linux::{LinuxKeyOutcomeCache, LinuxPlatformKeyProvider};
#[cfg(target_os = "macos")]
pub(crate) use macos::MacosPlatformKeyProvider;
#[cfg(unix)]
pub(crate) use shared::create_pbkdf2_key;
#[cfg(target_os = "windows")]
pub(crate) use windows::WindowsPlatformKeyProvider;
