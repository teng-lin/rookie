pub fn chromium_timestamp(timestamp: u64) -> Option<u64> {
  if timestamp == 0 {
    return None;
  }
  let mut timestamp = timestamp.checked_sub(11_644_473_600_000_000)?;
  timestamp /= 1000000; // microseconds to seconds
  unix_timestamp(timestamp)
}

pub fn mozilla_timestamp(timestamp: u64) -> Option<u64> {
  unix_timestamp(timestamp)
}

fn unix_timestamp(timestamp: u64) -> Option<u64> {
  if timestamp == 0 {
    return None;
  }
  Some(timestamp)
}

#[cfg(any(target_os = "macos", test))]
pub fn safari_timestamp(timestamp: f64) -> Option<u64> {
  if timestamp == 0.0 || !timestamp.is_finite() {
    return None;
  }
  let unix_timestamp = timestamp + 978_307_200.0;
  if unix_timestamp < 0.0 || unix_timestamp > u64::MAX as f64 {
    return None;
  }
  Some(unix_timestamp as u64)
}
#[cfg(target_os = "windows")]
pub fn internet_explorer_timestamp(timestamp: u64) -> Option<u64> {
  if timestamp == 0 {
    return None;
  }
  let mut timestamp = timestamp.checked_sub(116_444_736_000_000_000)?;
  timestamp /= 10_000_000;
  unix_timestamp(timestamp)
}

#[cfg(test)]
mod tests {
  use super::*;

  // 1601-01-01 in microseconds since the WebKit epoch == Unix epoch 0.
  const CHROMIUM_EPOCH_OFFSET_US: u64 = 11_644_473_600_000_000;

  #[test]
  fn chromium_timestamp_zero_is_none() {
    assert_eq!(chromium_timestamp(0), None);
  }

  #[test]
  fn chromium_timestamp_converts_to_unix_seconds() {
    // 12345 seconds past Unix epoch, expressed in microseconds since WebKit epoch.
    let webkit_microseconds = CHROMIUM_EPOCH_OFFSET_US + 12_345 * 1_000_000;
    assert_eq!(chromium_timestamp(webkit_microseconds), Some(12_345));
  }

  #[test]
  fn chromium_timestamp_at_unix_epoch_is_none() {
    // The exact WebKit-epoch offset corresponds to Unix 0; the helper treats 0 as "unset".
    assert_eq!(chromium_timestamp(CHROMIUM_EPOCH_OFFSET_US), None);
  }

  #[test]
  fn mozilla_timestamp_zero_is_none() {
    assert_eq!(mozilla_timestamp(0), None);
  }

  #[test]
  fn mozilla_timestamp_is_passthrough() {
    assert_eq!(mozilla_timestamp(1_700_000_000), Some(1_700_000_000));
  }

  #[test]
  fn safari_timestamp_zero_is_none() {
    assert_eq!(safari_timestamp(0.0), None);
  }

  #[test]
  fn safari_timestamp_ieee754() {
    assert_eq!(safari_timestamp(750_000_000.0), Some(1_728_307_200));
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn internet_explorer_timestamp_zero_is_none() {
    assert_eq!(internet_explorer_timestamp(0), None);
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn internet_explorer_timestamp_converts_filetime_to_unix() {
    // FILETIME ticks at Unix epoch == 116_444_736_000_000_000; one second later is +10_000_000 ticks.
    const FILETIME_AT_UNIX_EPOCH: u64 = 116_444_736_000_000_000;
    let one_second_past_unix = FILETIME_AT_UNIX_EPOCH + 10_000_000;
    assert_eq!(internet_explorer_timestamp(one_second_past_unix), Some(1));
  }

  #[test]
  fn chromium_timestamp_underflow_is_none() {
    assert_eq!(chromium_timestamp(100), None);
  }

  #[cfg(target_os = "windows")]
  #[test]
  fn internet_explorer_timestamp_underflow_is_none() {
    assert_eq!(internet_explorer_timestamp(100), None);
  }
}
