// Unit tests for MoonShield Core Model & Payload Decoder

///|
test "URL percent decoding for SQLi and XSS payloads" {
  let raw_sqli = "%27%20OR%20%271%27%3D%271"
  assert_eq(@moonshield.url_decode(raw_sqli), "' OR '1'='1")

  let raw_xss = "%3Cscript%3Ealert(1)%3C%2Fscript%3E"
  assert_eq(@moonshield.url_decode(raw_xss), "<script>alert(1)</script>")

  let plus_encoded = "select+*+from+users"
  assert_eq(@moonshield.url_decode(plus_encoded), "select * from users")
}

///|
test "Payload normalization against WAF evasion techniques" {
  let mixed_case_sqli = "UnIoN+SeLeCt+NuLl%2C1"
  assert_eq(
    @moonshield.normalize_payload(mixed_case_sqli),
    "union select null,1",
  )

  let mixed_xss = "%3CsCrIpt%3Ealert(document.cookie)%3C%2FsCrIpT%3E"
  assert_eq(
    @moonshield.normalize_payload(mixed_xss),
    "<script>alert(document.cookie)</script>",
  )
}

///|
test "String substring search robustness" {
  let text = "get /api/v1/user?admin=true http/1.1"
  assert_true(@moonshield.string_contains(text, "admin=true"))
  assert_true(@moonshield.string_contains(text, "api/v1"))
  assert_true(!@moonshield.string_contains(text, "drop table"))
}

///|
test "Core threat model instantiation" {
  let rule : @moonshield.Rule = {
    id: "RULE-01",
    name: "Test Rule",
    category: SQLInjection,
    severity: High,
    pattern: "union select",
    score: 50,
  }
  let match_item : @moonshield.ThreatMatch = {
    rule_id: rule.id,
    rule_name: rule.name,
    category: PromptInjection,
    severity: Critical,
    matched_sample: "ignore previous instructions",
    score: 60,
  }
  let res : @moonshield.InspectionResult = {
    is_blocked: true,
    total_score: 60,
    matches: [match_item],
    sanitized_payload: "[BLOCKED]",
  }
  assert_true(res.is_blocked)
  assert_eq(res.total_score, 60)
  assert_eq(res.matches.length(), 1)
}
