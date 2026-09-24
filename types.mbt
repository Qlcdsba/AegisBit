// AegisBit Security Types & Domain Models
// Defines comprehensive data structures for Web WAF and AI Agent guardrails.

///|
/// Threat severity levels for detected attack signatures and security events.
pub(all) enum ThreatSeverity {
  Info
  Low
  Medium
  High
  Critical
} derive(Eq)

///|
pub extend ThreatSeverity with Eq::{not_equal, equal}

///|
/// Converts threat severity to numeric baseline weight.
pub fn ThreatSeverity::to_score(self : ThreatSeverity) -> Int {
  match self {
    Info => 5
    Low => 15
    Medium => 35
    High => 50
    Critical => 70
  }
}

///|
/// Converts threat severity to string representation.
pub fn ThreatSeverity::to_string(self : ThreatSeverity) -> String {
  match self {
    Info => "INFO"
    Low => "LOW"
    Medium => "MEDIUM"
    High => "HIGH"
    Critical => "CRITICAL"
  }
}

///|
/// Attack categories covering OWASP Top 10 Web threats and OWASP Top 10 for LLMs.
pub(all) enum AttackCategory {
  SQLInjection
  XSS
  CommandInjection
  PathTraversal
  SSRF
  XXE
  WebShell
  HeaderInjection
  Deserialization
  PromptInjection
  Jailbreak
  UnsafeToolCall
  DataLeakage
  SensitiveInfo
  NoSQLInjection
  TemplateInjection
  PrototypePollution
} derive(Eq)

///|
pub extend AttackCategory with Eq::{not_equal, equal}

///|
/// Returns human-readable label for attack category.
pub fn AttackCategory::to_string(self : AttackCategory) -> String {
  match self {
    SQLInjection => "SQL_INJECTION"
    XSS => "CROSS_SITE_SCRIPTING"
    CommandInjection => "COMMAND_INJECTION"
    PathTraversal => "PATH_TRAVERSAL"
    SSRF => "SERVER_SIDE_REQUEST_FORGERY"
    XXE => "XML_EXTERNAL_ENTITY"
    WebShell => "WEBSHELL_BACKDOOR"
    HeaderInjection => "HEADER_INJECTION"
    Deserialization => "INSECURE_DESERIALIZATION"
    PromptInjection => "PROMPT_INJECTION"
    Jailbreak => "JAILBREAK_ATTACK"
    UnsafeToolCall => "UNSAFE_TOOL_CALL"
    DataLeakage => "SENSITIVE_DATA_LEAKAGE"
    SensitiveInfo => "CREDENTIAL_EXPOSURE"
    NoSQLInjection => "NOSQL_INJECTION"
    TemplateInjection => "SERVER_SIDE_TEMPLATE_INJECTION"
    PrototypePollution => "PROTOTYPE_POLLUTION"
  }
}

///|
/// Maps category to international Common Weakness Enumeration (CWE) or OWASP identifier.
pub fn AttackCategory::to_cwe(self : AttackCategory) -> String {
  match self {
    SQLInjection => "CWE-89"
    XSS => "CWE-79"
    CommandInjection => "CWE-78"
    PathTraversal => "CWE-22"
    SSRF => "CWE-918"
    XXE => "CWE-611"
    WebShell => "CWE-94"
    HeaderInjection => "CWE-113"
    Deserialization => "CWE-502"
    PromptInjection => "OWASP-LLM-01"
    Jailbreak => "OWASP-LLM-01"
    UnsafeToolCall => "OWASP-LLM-08"
    DataLeakage => "OWASP-LLM-06"
    SensitiveInfo => "CWE-200"
    NoSQLInjection => "CWE-943"
    TemplateInjection => "CWE-1336"
    PrototypePollution => "CWE-1321"
  }
}

///|
/// Security action verdict decided by the inspection engine.
pub(all) enum ActionVerdict {
  Allow
  Monitor
  Sanitize
  Challenge
  Block
} derive(Eq)

///|
pub extend ActionVerdict with Eq::{not_equal, equal}

///|
/// Converts action verdict to string.
pub fn ActionVerdict::to_string(self : ActionVerdict) -> String {
  match self {
    Allow => "ALLOW"
    Monitor => "MONITOR"
    Sanitize => "SANITIZE"
    Challenge => "CHALLENGE"
    Block => "BLOCK"
  }
}

///|
/// Security detection rule definition with metadata and compliance tags.
pub(all) struct Rule {
  id : String
  name : String
  category : AttackCategory
  severity : ThreatSeverity
  pattern : String
  score : Int
  description : String
  enabled : Bool
}

///|
/// Creates a new rule with default enabled status.
pub fn Rule::new(
  id : String,
  name : String,
  category : AttackCategory,
  severity : ThreatSeverity,
  pattern : String,
  score : Int,
  description? : String = "",
) -> Rule {
  { id, name, category, severity, pattern, score, description, enabled: true, }
}

///|
/// Result of a single matched threat signature during inspection.
pub(all) struct ThreatMatch {
  rule_id : String
  rule_name : String
  category : AttackCategory
  cwe : String
  severity : ThreatSeverity
  matched_sample : String
  score : Int
  position : Int
}

///|
/// Execution context for an incoming request or agent interaction.
pub(all) struct InspectionContext {
  trace_id : String
  client_ip : String
  user_agent : String
  request_path : String
  http_method : String
  is_agent_call : Bool
  timestamp : String
}

///|
/// Creates a default inspection context.
pub fn InspectionContext::default() -> InspectionContext {
  {
    trace_id: "trace-00000000",
    client_ip: "127.0.0.1",
    user_agent: "AegisBit-Agent/1.0",
    request_path: "/",
    http_method: "GET",
    is_agent_call: false,
    timestamp: "2026-09-25T00:00:00Z",
  }
}

///|
/// Comprehensive security inspection result.
pub(all) struct InspectionResult {
  verdict : ActionVerdict
  is_blocked : Bool
  total_score : Int
  score_threshold : Int
  matches : Array[ThreatMatch]
  sanitized_payload : String
  context : InspectionContext
}

///|
/// Returns true if inspection produced any matched threats.
pub fn InspectionResult::has_threats(self : InspectionResult) -> Bool {
  self.matches.length() > 0
}

///|
/// Returns the highest severity among all matched threats.
pub fn InspectionResult::highest_severity(
  self : InspectionResult,
) -> ThreatSeverity {
  if self.matches.length() == 0 {
    return Info
  }
  let mut highest = Low
  let mut i = 0
  while i < self.matches.length() {
    let s = self.matches[i].severity
    if s == Critical {
      return Critical
    }
    if s == High {
      highest = High
    } else if s == Medium && highest == Low {
      highest = Medium
    }
    i = i + 1
  }
  highest
}
