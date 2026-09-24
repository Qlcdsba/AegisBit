// AegisBit: Experimental WAF and AI Agent Security Rule Detector Prototype
// Implemented in pure MoonBit.

///|
/// Threat severity levels for detected attack signatures.
pub(all) enum ThreatSeverity {
  Low
  Medium
  High
  Critical
} derive(Eq)

///|
/// Security attack categories covering basic Web Application threats and AI Agent threats.
pub(all) enum AttackCategory {
  SQLInjection
  XSS
  CommandInjection
  PathTraversal
  SSRF
  PromptInjection
  UnsafeToolCall
} derive(Eq)

///|
/// Security detection rule definition.
pub(all) struct Rule {
  id : String
  name : String
  category : AttackCategory
  severity : ThreatSeverity
  pattern : String
  score : Int
}

///|
/// Result of a single matched threat pattern.
pub(all) struct ThreatMatch {
  rule_id : String
  rule_name : String
  category : AttackCategory
  severity : ThreatSeverity
  matched_sample : String
  score : Int
}

///|
/// Overall security inspection result and mitigation verdict.
pub(all) struct InspectionResult {
  is_blocked : Bool
  total_score : Int
  matches : Array[ThreatMatch]
  sanitized_payload : String
}
