// AegisBit Core Threat Inspection Engine
// Orchestrates multi-layer normalization, Aho-Corasick automaton matching, scoring, and verdict determination.

///|
/// WAF Security Engine holding active rules, compiled AC automaton, and thresholds.
pub(all) struct WafEngine {
  rules : Array[Rule]
  automaton : AcAutomaton
  score_threshold : Int
  monitor_threshold : Int
}

///|
/// Recompiles the internal Aho-Corasick automaton from current rules.
fn compile_rules_automaton(rules : Array[Rule]) -> AcAutomaton {
  let patterns : Array[String] = []
  let mut i = 0
  while i < rules.length() {
    patterns.push(rules[i].pattern)
    i = i + 1
  }
  AcAutomaton::compile(patterns)
}

///|
/// Creates a new WafEngine instance configured with default rules.
pub fn WafEngine::new(
  score_threshold? : Int = 50,
  monitor_threshold? : Int = 20,
) -> WafEngine {
  let rules = default_rules()
  let automaton = compile_rules_automaton(rules)
  { rules, automaton, score_threshold, monitor_threshold, }
}

///|
/// Creates a WafEngine instance initialized with custom rules.
pub fn WafEngine::with_rules(
  rules : Array[Rule],
  score_threshold? : Int = 50,
  monitor_threshold? : Int = 20,
) -> WafEngine {
  let automaton = compile_rules_automaton(rules)
  { rules, automaton, score_threshold, monitor_threshold, }
}

///|
/// Adds a custom rule to the engine at runtime and updates the automaton.
pub fn WafEngine::add_rule(self : WafEngine, rule : Rule) -> Unit {
  self.rules.push(rule)
  self.automaton.insert(rule.pattern, self.rules.length() - 1)
  self.automaton.build_failure_links()
}

///|
/// Inspects a raw input payload against active threat rules.
pub fn WafEngine::inspect_payload(
  self : WafEngine,
  payload : String,
  context? : InspectionContext = InspectionContext::default(),
) -> InspectionResult {
  let normalized = normalize_payload(payload)
  let raw_hits = self.automaton.matches(normalized)

  // Deduplicate hits by rule_id while aggregating scores
  let seen_rules : Array[String] = []
  let matches : Array[ThreatMatch] = []
  let mut total_score = 0

  let mut h_idx = 0
  while h_idx < raw_hits.length() {
    let hit = raw_hits[h_idx]
    let rule = self.rules[hit.rule_index]
    if rule.enabled {
      let mut already_seen = false
      let mut s_idx = 0
      while s_idx < seen_rules.length() {
        if seen_rules[s_idx] == rule.id {
          already_seen = true
          break
        }
        s_idx = s_idx + 1
      }

      if !already_seen {
        seen_rules.push(rule.id)
        let threat : ThreatMatch = {
          rule_id: rule.id,
          rule_name: rule.name,
          category: rule.category,
          cwe: rule.category.to_cwe(),
          severity: rule.severity,
          matched_sample: rule.pattern,
          score: rule.score,
          position: hit.end_pos,
        }
        matches.push(threat)
        total_score = total_score + rule.score
      }
    }
    h_idx = h_idx + 1
  }

  // Verdict decision logic
  let verdict = if total_score >= self.score_threshold {
    Block
  } else if total_score >= self.monitor_threshold {
    Monitor
  } else {
    Allow
  }

  let is_blocked = verdict == Block
  let sanitized = if is_blocked { "[BLOCKED BY AEGISBIT WAF]" } else { payload }

  {
    verdict,
    is_blocked,
    total_score,
    score_threshold: self.score_threshold,
    matches,
    sanitized_payload: sanitized,
    context,
  }
}

///|
/// Inspects an incoming HTTP Request structured representation.
pub fn WafEngine::inspect_http_request(
  self : WafEngine,
  req : HttpRequest,
  context? : InspectionContext = InspectionContext::default(),
) -> InspectionResult {
  let targets = req.inspection_targets()
  let seen_rules : Array[String] = []
  let matches : Array[ThreatMatch] = []
  let mut total_score = 0

  let mut t_idx = 0
  while t_idx < targets.length() {
    let (field_name, field_value) = targets[t_idx]
    let normalized = normalize_payload(field_value)
    let hits = self.automaton.matches(normalized)

    let mut h_idx = 0
    while h_idx < hits.length() {
      let hit = hits[h_idx]
      let rule = self.rules[hit.rule_index]
      if rule.enabled {
        let mut already_seen = false
        let mut s_idx = 0
        while s_idx < seen_rules.length() {
          if seen_rules[s_idx] == rule.id {
            already_seen = true
            break
          }
          s_idx = s_idx + 1
        }

        if !already_seen {
          seen_rules.push(rule.id)
          let threat : ThreatMatch = {
            rule_id: rule.id,
            rule_name: rule.name + " (in " + field_name + ")",
            category: rule.category,
            cwe: rule.category.to_cwe(),
            severity: rule.severity,
            matched_sample: rule.pattern,
            score: rule.score,
            position: hit.end_pos,
          }
          matches.push(threat)
          total_score = total_score + rule.score
        }
      }
      h_idx = h_idx + 1
    }
    t_idx = t_idx + 1
  }

  let verdict = if total_score >= self.score_threshold {
    Block
  } else if total_score >= self.monitor_threshold {
    Monitor
  } else {
    Allow
  }

  let is_blocked = verdict == Block
  let sanitized = if is_blocked {
    "[BLOCKED BY AEGISBIT WAF]"
  } else {
    req.body
  }

  let effective_context : InspectionContext = {
    trace_id: context.trace_id,
    client_ip: context.client_ip,
    user_agent: match req.get_header("User-Agent") {
      Some(ua) => ua
      None => context.user_agent
    },
    request_path: req.path,
    http_method: req.http_method,
    is_agent_call: false,
    timestamp: context.timestamp,
  }

  {
    verdict,
    is_blocked,
    total_score,
    score_threshold: self.score_threshold,
    matches,
    sanitized_payload: sanitized,
    context: effective_context,
  }
}

///|
/// Inspects an incoming HTTP Request wire stream directly.
pub fn WafEngine::inspect_http(
  self : WafEngine,
  http_method : String,
  uri : String,
  body : String,
) -> InspectionResult {
  let req = HttpRequest::new(http_method, uri, body~)
  self.inspect_http_request(req)
}

///|
/// Inspects an AI Agent Prompt for prompt injection or jailbreak attempts.
pub fn WafEngine::inspect_agent_prompt(
  self : WafEngine,
  prompt : String,
) -> InspectionResult {
  let ctx : InspectionContext = {
    trace_id: "agent-" + prompt.length().to_string(),
    client_ip: "agent://local",
    user_agent: "AegisBit-AgentGuard/1.0",
    request_path: "/v1/chat/completions",
    http_method: "POST",
    is_agent_call: true,
    timestamp: "2026-09-25T00:00:00Z",
  }
  self.inspect_payload(prompt, context=ctx)
}

///|
/// Inspects an AI Agent Tool Call for unsafe function execution.
pub fn WafEngine::inspect_tool_call(
  self : WafEngine,
  tool_name : String,
  args_json : String,
) -> InspectionResult {
  let combined = "tool_call: " + tool_name + "(" + args_json + ")"
  let ctx : InspectionContext = {
    trace_id: "tool-" + tool_name,
    client_ip: "agent://tool-dispatcher",
    user_agent: "AegisBit-AgentGuard/1.0",
    request_path: "/v1/tools/execute",
    http_method: "POST",
    is_agent_call: true,
    timestamp: "2026-09-25T00:00:00Z",
  }
  self.inspect_payload(combined, context=ctx)
}

///|
/// IP address access control filter (supports whitelist and blacklist).
pub(all) struct IpFilter {
  blacklist : Array[String]
  whitelist : Array[String]
}

///|
/// Creates a new empty IP filter.
pub fn IpFilter::new() -> IpFilter {
  { blacklist: [], whitelist: [], }
}

///|
/// Checks if an IP is explicitly blacklisted.
pub fn IpFilter::is_blacklisted(self : IpFilter, ip : String) -> Bool {
  let mut i = 0
  while i < self.blacklist.length() {
    if self.blacklist[i] == ip {
      return true
    }
    i = i + 1
  }
  false
}

///|
/// Checks if an IP is explicitly whitelisted.
pub fn IpFilter::is_whitelisted(self : IpFilter, ip : String) -> Bool {
  let mut i = 0
  while i < self.whitelist.length() {
    if self.whitelist[i] == ip {
      return true
    }
    i = i + 1
  }
  false
}

///|
/// Adds an IP to blacklist.
pub fn IpFilter::add_blacklist(self : IpFilter, ip : String) -> Unit {
  self.blacklist.push(ip)
}

///|
/// Adds an IP to whitelist.
pub fn IpFilter::add_whitelist(self : IpFilter, ip : String) -> Unit {
  self.whitelist.push(ip)
}

///|
/// Sliding window rate limiter entry.
pub(all) struct RateLimitEntry {
  client_id : String
  mut request_count : Int
  mut window_tick : Int
}

///|
/// In-memory rate limiter protecting against DDoS, credential stuffing, and scraping.
pub(all) struct RateLimiter {
  max_requests_per_window : Int
  entries : Array[RateLimitEntry]
}

///|
/// Creates a new RateLimiter with maximum allowed requests per window.
pub fn RateLimiter::new(max_requests_per_window : Int) -> RateLimiter {
  { max_requests_per_window, entries: [], }
}

///|
/// Records an access attempt and returns true if within rate limits, or false if exceeded.
pub fn RateLimiter::check_and_record(
  self : RateLimiter,
  client_id : String,
  current_tick : Int,
) -> Bool {
  let mut i = 0
  let len = self.entries.length()
  while i < len {
    let entry = self.entries[i]
    if entry.client_id == client_id {
      if entry.window_tick != current_tick {
        entry.window_tick = current_tick
        entry.request_count = 1
        return true
      }
      if entry.request_count >= self.max_requests_per_window {
        return false
      }
      entry.request_count = entry.request_count + 1
      return true
    }
    i = i + 1
  }

  // New client entry
  self.entries.push({ client_id, request_count: 1, window_tick: current_tick, })
  true
}
