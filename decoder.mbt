// AegisBit Multi-Phase Payload Normalizer & Evasion Neutralizer
// Pure MoonBit implementation with zero external dependencies.

///|
/// Parses a single hex character (as UInt16 code) to integer value 0-15.
pub fn parse_hex_digit(ch : UInt16) -> Int {
  let val = ch.to_int()
  if val >= '0'.to_int() && val <= '9'.to_int() {
    val - '0'.to_int()
  } else if val >= 'a'.to_int() && val <= 'f'.to_int() {
    val - 'a'.to_int() + 10
  } else if val >= 'A'.to_int() && val <= 'F'.to_int() {
    val - 'A'.to_int() + 10
  } else {
    -1
  }
}

///|
/// Decodes a single layer of URL percent-encoded characters (e.g. %20 -> ' ', %27 -> '\'')
pub fn url_decode(input : String) -> String {
  let sb = StringBuilder()
  let len = input.length()
  let mut i = 0
  while i < len {
    let ch = input[i]
    if ch == '%'.to_int().to_uint16() && i + 2 < len {
      let hex1 = input[i + 1]
      let hex2 = input[i + 2]
      let val1 = parse_hex_digit(hex1)
      let val2 = parse_hex_digit(hex2)
      if val1 >= 0 && val2 >= 0 {
        let code = val1 * 16 + val2
        match code.to_char() {
          Some(c) => sb.write_char(c)
          None => ()
        }
        i = i + 3
        continue
      }
    }
    if ch == '+'.to_int().to_uint16() {
      sb.write_char(' ')
    } else {
      match ch.to_int().to_char() {
        Some(c) => sb.write_char(c)
        None => ()
      }
    }
    i = i + 1
  }
  sb.to_string()
}

///|
/// Recursively decodes multi-layer URL percent-encoded characters up to `max_depth` (default: 3).
/// This defeats double-encoding or nested-encoding WAF evasion techniques (e.g. `%2527` -> `%27` -> `'`).
pub fn url_decode_recursive(input : String, max_depth? : Int = 3) -> String {
  let mut current = input
  let mut depth = 0
  while depth < max_depth {
    let decoded = url_decode(current)
    if decoded == current {
      break
    }
    current = decoded
    depth = depth + 1
  }
  current
}

///|
/// Decodes IIS-specific %uXXXX unicode encoding (e.g. %u0027 -> ')
pub fn iis_percent_u_decode(input : String) -> String {
  let sb = StringBuilder()
  let len = input.length()
  let mut i = 0
  while i < len {
    if input[i] == '%'.to_int().to_uint16() &&
      i + 5 < len &&
      (
        input[i + 1] == 'u'.to_int().to_uint16() ||
        input[i + 1] == 'U'.to_int().to_uint16()
      ) {
      let h1 = parse_hex_digit(input[i + 2])
      let h2 = parse_hex_digit(input[i + 3])
      let h3 = parse_hex_digit(input[i + 4])
      let h4 = parse_hex_digit(input[i + 5])
      if h1 >= 0 && h2 >= 0 && h3 >= 0 && h4 >= 0 {
        let code = (h1 << 12) | (h2 << 8) | (h3 << 4) | h4
        match code.to_char() {
          Some(c) => sb.write_char(c)
          None => ()
        }
        i = i + 6
        continue
      }
    }
    match input[i].to_int().to_char() {
      Some(c) => sb.write_char(c)
      None => ()
    }
    i = i + 1
  }
  sb.to_string()
}

///|
/// Decodes hex escape sequences (e.g. \x27 -> ', \x3c -> <)
pub fn hex_escape_decode(input : String) -> String {
  let sb = StringBuilder()
  let len = input.length()
  let mut i = 0
  while i < len {
    if input[i] == '\\'.to_int().to_uint16() &&
      i + 3 < len &&
      (
        input[i + 1] == 'x'.to_int().to_uint16() ||
        input[i + 1] == 'X'.to_int().to_uint16()
      ) {
      let h1 = parse_hex_digit(input[i + 2])
      let h2 = parse_hex_digit(input[i + 3])
      if h1 >= 0 && h2 >= 0 {
        let code = (h1 << 4) | h2
        match code.to_char() {
          Some(c) => sb.write_char(c)
          None => ()
        }
        i = i + 4
        continue
      }
    }
    match input[i].to_int().to_char() {
      Some(c) => sb.write_char(c)
      None => ()
    }
    i = i + 1
  }
  sb.to_string()
}

///|
/// Decodes unicode escape sequences (e.g. \u003c -> <, \u0027 -> ')
pub fn unicode_escape_decode(input : String) -> String {
  let sb = StringBuilder()
  let len = input.length()
  let mut i = 0
  while i < len {
    if input[i] == '\\'.to_int().to_uint16() &&
      i + 5 < len &&
      (
        input[i + 1] == 'u'.to_int().to_uint16() ||
        input[i + 1] == 'U'.to_int().to_uint16()
      ) {
      let h1 = parse_hex_digit(input[i + 2])
      let h2 = parse_hex_digit(input[i + 3])
      let h3 = parse_hex_digit(input[i + 4])
      let h4 = parse_hex_digit(input[i + 5])
      if h1 >= 0 && h2 >= 0 && h3 >= 0 && h4 >= 0 {
        let code = (h1 << 12) | (h2 << 8) | (h3 << 4) | h4
        match code.to_char() {
          Some(c) => sb.write_char(c)
          None => ()
        }
        i = i + 6
        continue
      }
    }
    match input[i].to_int().to_char() {
      Some(c) => sb.write_char(c)
      None => ()
    }
    i = i + 1
  }
  sb.to_string()
}

///|
/// Decodes HTML decimal entities (e.g. &#60; -> <, &#39; -> ')
pub fn html_decimal_decode(input : String) -> String {
  let sb = StringBuilder()
  let len = input.length()
  let mut i = 0
  while i < len {
    if input[i] == '&'.to_int().to_uint16() &&
      i + 2 < len &&
      input[i + 1] == '#'.to_int().to_uint16() {
      // Find trailing semicolon
      let mut end_idx = i + 2
      let mut code = 0
      let mut is_num = true
      while end_idx < len && end_idx < i + 8 {
        let c = input[end_idx]
        if c == ';'.to_int().to_uint16() {
          break
        }
        let digit = c.to_int() - '0'.to_int()
        if digit >= 0 && digit <= 9 {
          code = code * 10 + digit
        } else {
          is_num = false
          break
        }
        end_idx = end_idx + 1
      }
      if is_num &&
        end_idx < len &&
        input[end_idx] == ';'.to_int().to_uint16() &&
        code > 0 &&
        code < 65536 {
        match code.to_char() {
          Some(ch) => sb.write_char(ch)
          None => ()
        }
        i = end_idx + 1
        continue
      }
    }
    match input[i].to_int().to_char() {
      Some(c) => sb.write_char(c)
      None => ()
    }
    i = i + 1
  }
  sb.to_string()
}

///|
/// Decodes common HTML entity representations into their raw character equivalents.
/// Foils XSS filter evasion using entity encoding (e.g. `&lt;script&gt;` -> `<script>`).
pub fn html_entity_decode(input : String) -> String {
  let step1 = html_decimal_decode(input)
  let mut s = step1
  s = replace_all(s, "&lt;", "<")
  s = replace_all(s, "&gt;", ">")
  s = replace_all(s, "&quot;", "\"")
  s = replace_all(s, "&#x27;", "'")
  s = replace_all(s, "&#39;", "'")
  s = replace_all(s, "&#x22;", "\"")
  s = replace_all(s, "&#60;", "<")
  s = replace_all(s, "&#62;", ">")
  s = replace_all(s, "&amp;", "&")
  s
}

///|
/// Normalizes fullwidth Unicode characters to standard ASCII equivalents.
/// Prevents fullwidth evasion techniques (e.g. `＜ｓｃｒｉｐｔ＞` -> `<script>`).
pub fn unicode_normalize(input : String) -> String {
  let sb = StringBuilder()
  let len = input.length()
  let mut i = 0
  while i < len {
    let code = input[i].to_int()
    // Fullwidth ASCII variants: U+FF01 ('！') to U+FF5E ('～')
    if code >= 0xFF01 && code <= 0xFF5E {
      let ascii_code = code - 0xFEE0
      match ascii_code.to_char() {
        Some(c) => sb.write_char(c)
        None => ()
      }
    } else if code == 0x3000 {
      // Fullwidth space -> regular space
      sb.write_char(' ')
    } else if code == 0x200B ||
      code == 0x200C ||
      code == 0x200D ||
      code == 0xFEFF {
      // Zero-width spaces / BOM frequently used in prompt injection evasion: strip them
      ()
    } else {
      match code.to_char() {
        Some(c) => sb.write_char(c)
        None => ()
      }
    }
    i = i + 1
  }
  sb.to_string()
}

///|
/// Strips inline SQL comments (/* ... */) that are commonly used to break up SQL keywords.
/// For example: `SEL/*foo*/ECT` -> `SELECT`.
pub fn strip_inline_comments(input : String) -> String {
  let sb = StringBuilder()
  let len = input.length()
  let mut i = 0
  while i < len {
    if input[i] == '/'.to_int().to_uint16() &&
      i + 1 < len &&
      input[i + 1] == '*'.to_int().to_uint16() {
      // Find closing */
      let mut end_idx = i + 2
      let mut found_close = false
      while end_idx + 1 < len {
        if input[end_idx] == '*'.to_int().to_uint16() &&
          input[end_idx + 1] == '/'.to_int().to_uint16() {
          found_close = true
          break
        }
        end_idx = end_idx + 1
      }
      if found_close {
        sb.write_char(' ')
        i = end_idx + 2
        continue
      }
    }
    match input[i].to_int().to_char() {
      Some(c) => sb.write_char(c)
      None => ()
    }
    i = i + 1
  }
  sb.to_string()
}

///|
/// Squeezes multiple consecutive whitespace and newline characters into a single space.
pub fn squeeze_whitespace(input : String) -> String {
  let sb = StringBuilder()
  let len = input.length()
  let mut in_space = false
  let mut i = 0
  while i < len {
    let c = input[i].to_int()
    if c == ' '.to_int() ||
      c == '\t'.to_int() ||
      c == '\r'.to_int() ||
      c == '\n'.to_int() {
      if !in_space {
        sb.write_char(' ')
        in_space = true
      }
    } else {
      match c.to_char() {
        Some(ch) => sb.write_char(ch)
        None => ()
      }
      in_space = false
    }
    i = i + 1
  }
  sb.to_string()
}

///|
/// Canonicalizes filesystem path representations by reducing redundant slashes and dots.
pub fn path_canonicalize(path : String) -> String {
  let mut s = replace_all(path, "\\", "/")
  // Collapse multiple consecutive slashes
  while string_contains(s, "//") {
    s = replace_all(s, "//", "/")
  }
  // Collapse /./ segments
  while string_contains(s, "/./") {
    s = replace_all(s, "/./", "/")
  }
  s
}

///|
/// Replaces all occurrences of `target` with `replacement` in `source`.
pub fn replace_all(
  source : String,
  target : String,
  replacement : String,
) -> String {
  let target_len = target.length()
  if target_len == 0 {
    return source
  }
  let source_len = source.length()
  let sb = StringBuilder()
  let mut i = 0
  while i < source_len {
    if i <= source_len - target_len && is_substr_at(source, target, i) {
      sb.write_string(replacement)
      i = i + target_len
    } else {
      match source[i].to_int().to_char() {
        Some(c) => sb.write_char(c)
        None => ()
      }
      i = i + 1
    }
  }
  sb.to_string()
}

///|
/// Checks if substring `sub` starts at index `pos` in string `src`.
fn is_substr_at(src : String, sub : String, pos : Int) -> Bool {
  let sub_len = sub.length()
  let mut j = 0
  while j < sub_len {
    if src[pos + j] != sub[j] {
      return false
    }
    j = j + 1
  }
  true
}

///|
/// Checks if string `target` contains substring `sub`.
pub fn string_contains(target : String, sub : String) -> Bool {
  let target_len = target.length()
  let sub_len = sub.length()
  if sub_len == 0 {
    return true
  }
  if sub_len > target_len {
    return false
  }
  let mut i = 0
  while i <= target_len - sub_len {
    if is_substr_at(target, sub, i) {
      return true
    }
    i = i + 1
  }
  false
}

///|
/// Returns index of first occurrence of `sub` in `target`, or -1 if not found.
pub fn string_index_of(target : String, sub : String) -> Int {
  let target_len = target.length()
  let sub_len = sub.length()
  if sub_len == 0 {
    return 0
  }
  if sub_len > target_len {
    return -1
  }
  let mut i = 0
  while i <= target_len - sub_len {
    if is_substr_at(target, sub, i) {
      return i
    }
    i = i + 1
  }
  -1
}

///|
/// Standard payload normalization: executes recursive URL decoding and lowercasing.
pub fn normalize_payload(input : String) -> String {
  let decoded = url_decode_recursive(input, max_depth=3)
  decoded.to_lower()
}

///|
/// Full-spectrum payload normalization pipeline:
/// Unicode normalization -> IIS percent decode -> Recursive URL decode ->
/// Hex escape decode -> Unicode escape decode -> HTML Entity decode ->
/// Strip inline comments -> Squeeze whitespace -> Lowercase -> Path canonicalization.
pub fn normalize_payload_full(input : String) -> String {
  let s1 = unicode_normalize(input)
  let s2 = iis_percent_u_decode(s1)
  let s3 = url_decode_recursive(s2, max_depth=3)
  let s4 = hex_escape_decode(s3)
  let s5 = unicode_escape_decode(s4)
  let s6 = html_entity_decode(s5)
  let s7 = strip_inline_comments(s6)
  let s8 = squeeze_whitespace(s7)
  let s9 = s8.to_lower()
  path_canonicalize(s9)
}

///|
/// Pure MoonBit Base64 decoder.
/// Useful for unpacking obfuscated payloads (e.g. `eval(base64_decode(...))`).
pub fn base64_decode(input : String) -> String {
  let sb = StringBuilder()
  let len = input.length()
  let mut buf = 0
  let mut bits = 0
  let mut i = 0
  while i < len {
    let ch = input[i]
    if ch == '='.to_int().to_uint16() {
      break
    }
    let val = base64_char_to_val(ch)
    if val >= 0 {
      buf = (buf << 6) | val
      bits = bits + 6
      if bits >= 8 {
        bits = bits - 8
        let byte_val = (buf >> bits) & 0xFF
        match byte_val.to_char() {
          Some(c) => sb.write_char(c)
          None => ()
        }
      }
    }
    i = i + 1
  }
  sb.to_string()
}

///|
/// Maps a base64 character code to 6-bit value (0-63).
fn base64_char_to_val(ch : UInt16) -> Int {
  let code = ch.to_int()
  if code >= 'A'.to_int() && code <= 'Z'.to_int() {
    code - 'A'.to_int()
  } else if code >= 'a'.to_int() && code <= 'z'.to_int() {
    code - 'a'.to_int() + 26
  } else if code >= '0'.to_int() && code <= '9'.to_int() {
    code - '0'.to_int() + 52
  } else if code == '+'.to_int() {
    62
  } else if code == '/'.to_int() {
    63
  } else {
    -1
  }
}

///|
/// ROT-13 cipher deobfuscator (reversibly transforms a-z and A-Z by 13 positions).
pub fn rot13(input : String) -> String {
  let sb = StringBuilder()
  let len = input.length()
  let mut i = 0
  while i < len {
    let c = input[i].to_int()
    if c >= 'a'.to_int() && c <= 'z'.to_int() {
      let shifted = (c - 'a'.to_int() + 13) % 26 + 'a'.to_int()
      match shifted.to_char() {
        Some(ch) => sb.write_char(ch)
        None => ()
      }
    } else if c >= 'A'.to_int() && c <= 'Z'.to_int() {
      let shifted = (c - 'A'.to_int() + 13) % 26 + 'A'.to_int()
      match shifted.to_char() {
        Some(ch) => sb.write_char(ch)
        None => ()
      }
    } else {
      match c.to_char() {
        Some(ch) => sb.write_char(ch)
        None => ()
      }
    }
    i = i + 1
  }
  sb.to_string()
}
