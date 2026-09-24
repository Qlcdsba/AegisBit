// Payload Decoder & Normalizer for MoonShield Prototype

///|
/// Decodes URL percent-encoded characters (e.g. %20 -> ' ', %27 -> '\'')
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
/// Parses a single hex character (as UInt16 code) to integer value 0-15.
fn parse_hex_digit(ch : UInt16) -> Int {
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
/// Normalizes payload by performing URL decoding and lowercasing.
/// This foils common WAF evasion tricks using mixed casing (e.g. `uNiOn sElEcT`).
pub fn normalize_payload(input : String) -> String {
  let decoded = url_decode(input)
  decoded.to_lower()
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
    let mut matched = true
    let mut j = 0
    while j < sub_len {
      if target[i + j] != sub[j] {
        matched = false
        break
      }
      j = j + 1
    }
    if matched {
      return true
    }
    i = i + 1
  }
  false
}
