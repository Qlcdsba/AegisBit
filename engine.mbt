// MoonShield Core Inspection Engine Prototype

///|
/// WAF Security Engine holding active rules and inspection configuration.
pub(all) struct WafEngine {
  rules : Array[Rule]
  score_threshold : Int
}

///|
/// Creates a new `WafEngine` instance with default rules and a configurable score threshold.
pub fn WafEngine::new(score_threshold? : Int = 50) -> WafEngine {
  { rules: default_rules(), score_threshold, }
}

///|
/// Adds a custom rule to the engine at runtime.
pub fn WafEngine::add_rule(self : WafEngine, rule : Rule) -> Unit {
  self.rules.push(rule)
}

///|
/// Inspects a raw input payload against active threat rules and calculates risk scores.
pub fn WafEngine::inspect_payload(
  self : WafEngine,
  payload : String,
) -> InspectionResult {
  let normalized = normalize_payload(payload)
  let matches : Array[ThreatMatch] = []
  let mut total_score = 0

  let rules_len = self.rules.length()
  let mut i = 0
  while i < rules_len {
    let rule = self.rules[i]
    if string_contains(normalized, rule.pattern) {
      let threat : ThreatMatch = {
        rule_id: rule.id,
        rule_name: rule.name,
        category: rule.category,
        severity: rule.severity,
        matched_sample: rule.pattern,
        score: rule.score,
      }
      matches.push(threat)
      total_score = total_score + rule.score
    }
    i = i + 1
  }

  let is_blocked = total_score >= self.score_threshold
  let sanitized = if is_blocked { "[BLOCKED BY AEGISBIT WAF]" } else { payload }

  { is_blocked, total_score, matches, sanitized_payload: sanitized, }
}

///|
/// Inspects an incoming HTTP Request (http_method, URI, and body).
pub fn WafEngine::inspect_http(
  self : WafEngine,
  http_method : String,
  uri : String,
  body : String,
) -> InspectionResult {
  let combined = http_method + " " + uri + "\n" + body
  self.inspect_payload(combined)
}

///|
/// Inspects an AI Agent Prompt for prompt injection or jailbreak attempts.
pub fn WafEngine::inspect_agent_prompt(
  self : WafEngine,
  prompt : String,
) -> InspectionResult {
  self.inspect_payload(prompt)
}

///|
/// Inspects an AI Agent Tool Call for unsafe function execution.
pub fn WafEngine::inspect_tool_call(
  self : WafEngine,
  tool_name : String,
  args_json : String,
) -> InspectionResult {
  let combined = tool_name + " " + args_json
  self.inspect_payload(combined)
}
