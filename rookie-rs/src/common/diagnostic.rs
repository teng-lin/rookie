//! Central bounds and redaction for diagnostics that may cross public errors
//! or logs. Source descriptors carry paths explicitly; prose diagnostics do
//! not repeat them.

pub(crate) const MAX_DIAGNOSTIC_BYTES: usize = 512;
pub(crate) const REDACTED_PATH: &str = "<path>";

pub(crate) fn sanitize(message: &str) -> String {
  let mut sanitized = String::with_capacity(message.len().min(MAX_DIAGNOSTIC_BYTES));
  let bytes = message.as_bytes();
  let mut cursor = 0;
  while cursor < bytes.len() {
    let is_unix_boundary = cursor == 0
      || bytes.get(cursor - 1).is_some_and(|byte| {
        byte.is_ascii_whitespace()
          || matches!(byte, b'=' | b':' | b'\'' | b'"' | b'(' | b'[' | b'{')
      });
    let is_unix = bytes[cursor] == b'/'
      && is_unix_boundary
      && !(cursor >= 2 && &bytes[cursor - 2..cursor] == b":/");
    let is_drive = bytes
      .get(cursor..cursor.saturating_add(3))
      .is_some_and(|prefix| {
        prefix[0].is_ascii_alphabetic() && prefix[1] == b':' && matches!(prefix[2], b'/' | b'\\')
      });
    let is_unc = bytes
      .get(cursor..cursor.saturating_add(2))
      .is_some_and(|prefix| prefix == b"\\\\");
    if !(is_unix || is_drive || is_unc) {
      let character = message[cursor..]
        .chars()
        .next()
        .expect("cursor is a UTF-8 boundary");
      sanitized.push(character);
      cursor += character.len_utf8();
      continue;
    }

    sanitized.push_str(REDACTED_PATH);
    let quote = cursor
      .checked_sub(1)
      .and_then(|index| bytes.get(index).copied())
      .filter(|byte| matches!(byte, b'\'' | b'"'));
    cursor += if is_drive {
      3
    } else if is_unc {
      2
    } else {
      1
    };
    while cursor < bytes.len() {
      let byte = bytes[cursor];
      if quote.is_some_and(|quote| byte == quote)
        || (quote.is_none()
          && (matches!(byte, b',' | b';' | b')' | b']' | b'}' | b'\'' | b'"')
            || (byte == b':' && bytes.get(cursor + 1).is_some_and(u8::is_ascii_whitespace))))
      {
        break;
      }
      let character = message[cursor..]
        .chars()
        .next()
        .expect("cursor is a UTF-8 boundary");
      cursor += character.len_utf8();
    }
  }
  if sanitized.len() > MAX_DIAGNOSTIC_BYTES {
    let mut end = MAX_DIAGNOSTIC_BYTES;
    while !sanitized.is_char_boundary(end) {
      end -= 1;
    }
    sanitized.truncate(end);
  }
  sanitized
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn sanitizer_redacts_embedded_paths_and_truncates_on_utf8_boundaries() {
    let unix = "/private/secret folder/profile/Cookies";
    let windows = r"C:\Users\Secret User\Profile\Cookies";
    let unc = r"\\server\Secret Share\Profile\Cookies";
    let diagnostic = sanitize(&format!(
      "source={unix}, database='{windows}', provider path={unc}: failed {}",
      "🧪".repeat(200)
    ));
    assert!(!diagnostic.contains(unix));
    assert!(!diagnostic.contains(windows));
    assert!(!diagnostic.contains(unc));
    assert!(diagnostic.matches(REDACTED_PATH).count() >= 3);
    assert!(diagnostic.len() <= MAX_DIAGNOSTIC_BYTES);
    assert!(diagnostic.is_char_boundary(diagnostic.len()));
  }

  #[test]
  fn sanitizer_does_not_mistake_an_internal_slash_for_an_absolute_path() {
    let diagnostic = "session acquisition/parse attempt failed";
    assert_eq!(sanitize(diagnostic), diagnostic);
  }
}
