// Whitebox unit tests verifying internal data structures and engine invariants.

///|
test "Whitebox: Aho-Corasick internal node transitions and failure links" {
  let ac = AcAutomaton::new()
  assert_eq(ac.nodes.length(), 1)
  assert_eq(ac.nodes[0].fail, 0)

  // Insert patterns
  ac.insert("abc", 101)
  ac.insert("bc", 102)
  ac.insert("c", 103)
  ac.build_failure_links()

  // Verify internal output propagation
  let matches = ac.matches("abc")
  assert_true(matches.length() >= 3)
}

///|
test "Whitebox: Hex parser boundary values" {
  assert_eq(parse_hex_digit('0'.to_int().to_uint16()), 0)
  assert_eq(parse_hex_digit('9'.to_int().to_uint16()), 9)
  assert_eq(parse_hex_digit('a'.to_int().to_uint16()), 10)
  assert_eq(parse_hex_digit('f'.to_int().to_uint16()), 15)
  assert_eq(parse_hex_digit('A'.to_int().to_uint16()), 10)
  assert_eq(parse_hex_digit('F'.to_int().to_uint16()), 15)
  assert_eq(parse_hex_digit('g'.to_int().to_uint16()), -1)
  assert_eq(parse_hex_digit('z'.to_int().to_uint16()), -1)
}

///|
test "Whitebox: Rot-13 mathematical involution symmetry" {
  let sample = "The Quick Brown Fox Jumps Over 1337 Lazy Dogs!"
  let enc = rot13(sample)
  let dec = rot13(enc)
  assert_eq(dec, sample)
}

///|
test "Whitebox: IIS %u unicode decode verification" {
  let raw = "%u003cscript%u003e"
  let decoded = iis_percent_u_decode(raw)
  assert_eq(decoded, "<script>")
}

///|
test "Whitebox: Hex and unicode escape sequence decoding" {
  let hex_str = "\\x3c\\x73\\x63\\x72\\x69\\x70\\x74\\x3e"
  assert_eq(hex_escape_decode(hex_str), "<script>")

  let uni_str = "\\u003c\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074\\u003e"
  assert_eq(unicode_escape_decode(uni_str), "<script>")
}

///|
test "Whitebox: Inline SQL comment stripping" {
  let obfuscated = "SEL/*foobar*/ECT * FR/*comment*/OM users"
  assert_eq(strip_inline_comments(obfuscated), "SEL ECT * FR OM users")
}

///|
test "Whitebox: Whitespace squeezing" {
  let spaced = "SELECT    *    \r\n\t  FROM   users"
  assert_eq(squeeze_whitespace(spaced), "SELECT * FROM users")
}

///|
test "Whitebox: IP Filter blacklist and whitelist isolation" {
  let ip_filter = IpFilter::new()
  ip_filter.add_blacklist("10.0.0.99")
  ip_filter.add_whitelist("192.168.1.1")

  assert_true(ip_filter.is_blacklisted("10.0.0.99"))
  assert_true(!ip_filter.is_blacklisted("192.168.1.1"))
  assert_true(ip_filter.is_whitelisted("192.168.1.1"))
  assert_true(!ip_filter.is_whitelisted("10.0.0.99"))
  assert_true(!ip_filter.is_whitelisted("8.8.8.8"))
}

///|
test "Whitebox: Sliding window RateLimiter tick threshold enforcement" {
  let limiter = RateLimiter::new(2)

  // In tick 100: 1st allowed, 2nd allowed, 3rd blocked
  assert_true(limiter.check_and_record("client_alpha", 100))
  assert_true(limiter.check_and_record("client_alpha", 100))
  assert_true(!limiter.check_and_record("client_alpha", 100))

  // Different client allowed in same tick
  assert_true(limiter.check_and_record("client_beta", 100))

  // New tick window resets quota
  assert_true(limiter.check_and_record("client_alpha", 101))
}

///|
test "Whitebox: Stream JSONL and CSV log formatters" {
  let engine = WafEngine::new(score_threshold=50)
  let res = engine.inspect_http("GET", "/api?q=union+select", "")

  let jsonl = format_jsonl_audit(res)
  assert_true(string_contains(jsonl, "\"blocked\":true"))
  assert_true(string_contains(jsonl, "\"score\":65"))

  let csv = format_csv_audit(res)
  assert_true(string_contains(csv, "\"GET\""))
  assert_true(string_contains(csv, ",1"))

  let alert = format_webhook_alert_json(res)
  assert_true(string_contains(alert, "CRITICAL THREAT BLOCKED"))
}
