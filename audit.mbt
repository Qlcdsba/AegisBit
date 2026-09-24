// SIEM Audit Logging and Compliance Exporter for AegisBit
// Generates standardized JSON, CEF, and Syslog audit events for enterprise SIEM integration.

///|
/// Escapes special characters for safe JSON serialization.
pub fn json_escape(s : String) -> String {
  let buf = StringBuilder()
  let len = s.length()
  let mut i = 0
  while i < len {
    let c = s[i]
    if c == '"' {
      buf.write_string("\\\"")
    } else if c == '\\' {
      buf.write_string("\\\\")
    } else if c == '\n' {
      buf.write_string("\\n")
    } else if c == '\r' {
      buf.write_string("\\r")
    } else if c == '\t' {
      buf.write_string("\\t")
    } else {
      match c.to_char() {
        Some(ch) => buf.write_char(ch)
        None => ()
      }
    }
    i = i + 1
  }
  buf.to_string()
}

///|
/// Converts an InspectionResult to a standard SIEM JSON audit log string.
pub fn format_json_audit(result : InspectionResult) -> String {
  let buf = StringBuilder()
  buf.write_string("{\n")
  buf.write_string(
    "  \"timestamp\": \"" + json_escape(result.context.timestamp) + "\",\n",
  )
  buf.write_string(
    "  \"trace_id\": \"" + json_escape(result.context.trace_id) + "\",\n",
  )
  buf.write_string(
    "  \"client_ip\": \"" + json_escape(result.context.client_ip) + "\",\n",
  )
  buf.write_string(
    "  \"http_method\": \"" + json_escape(result.context.http_method) + "\",\n",
  )
  buf.write_string(
    "  \"request_path\": \"" +
    json_escape(result.context.request_path) +
    "\",\n",
  )
  buf.write_string(
    "  \"user_agent\": \"" + json_escape(result.context.user_agent) + "\",\n",
  )
  buf.write_string(
    "  \"is_agent_call\": " +
    (if result.context.is_agent_call { "true" } else { "false" }) +
    ",\n",
  )
  buf.write_string("  \"verdict\": \"" + result.verdict.to_string() + "\",\n")
  buf.write_string(
    "  \"is_blocked\": " +
    (if result.is_blocked { "true" } else { "false" }) +
    ",\n",
  )
  buf.write_string(
    "  \"total_score\": " + result.total_score.to_string() + ",\n",
  )
  buf.write_string(
    "  \"score_threshold\": " + result.score_threshold.to_string() + ",\n",
  )
  buf.write_string(
    "  \"threat_count\": " + result.matches.length().to_string() + ",\n",
  )
  buf.write_string("  \"threats\": [")

  if result.matches.length() > 0 {
    buf.write_string("\n")
    let mut i = 0
    while i < result.matches.length() {
      let m = result.matches[i]
      buf.write_string("    {\n")
      buf.write_string(
        "      \"rule_id\": \"" + json_escape(m.rule_id) + "\",\n",
      )
      buf.write_string(
        "      \"rule_name\": \"" + json_escape(m.rule_name) + "\",\n",
      )
      buf.write_string(
        "      \"category\": \"" + m.category.to_string() + "\",\n",
      )
      buf.write_string("      \"cwe\": \"" + m.cwe + "\",\n")
      buf.write_string(
        "      \"severity\": \"" + m.severity.to_string() + "\",\n",
      )
      buf.write_string("      \"score\": " + m.score.to_string() + ",\n")
      buf.write_string("      \"position\": " + m.position.to_string() + ",\n")
      buf.write_string(
        "      \"matched_sample\": \"" + json_escape(m.matched_sample) + "\"\n",
      )
      if i + 1 < result.matches.length() {
        buf.write_string("    },\n")
      } else {
        buf.write_string("    }\n")
      }
      i = i + 1
    }
    buf.write_string("  ]\n")
  } else {
    buf.write_string("]\n")
  }

  buf.write_string("}")
  buf.to_string()
}

///|
/// Converts an InspectionResult to Common Event Format (CEF) log records.
pub fn format_cef_audit(result : InspectionResult) -> Array[String] {
  let cef_lines : Array[String] = []
  if result.matches.length() == 0 {
    let line = "CEF:0|Qlcdsba|AegisBit|0.1.0|AUDIT-ALLOW|Clean Request|1|src=" +
      result.context.client_ip +
      " request=" +
      result.context.request_path +
      " act=ALLOW score=" +
      result.total_score.to_string()
    cef_lines.push(line)
    return cef_lines
  }

  let mut i = 0
  while i < result.matches.length() {
    let m = result.matches[i]
    let sev_num = match m.severity {
      Info => "1"
      Low => "3"
      Medium => "5"
      High => "8"
      Critical => "10"
    }
    let line = "CEF:0|Qlcdsba|AegisBit|0.1.0|" +
      m.rule_id +
      "|" +
      m.rule_name +
      "|" +
      sev_num +
      "|src=" +
      result.context.client_ip +
      " request=" +
      result.context.request_path +
      " act=" +
      result.verdict.to_string() +
      " cs1=" +
      m.cwe +
      " cs1Label=CWE msg=" +
      json_escape(m.matched_sample)
    cef_lines.push(line)
    i = i + 1
  }
  cef_lines
}

///|
/// Formats a single-line Syslog message (RFC 5424 compliant header).
pub fn format_syslog_line(result : InspectionResult) -> String {
  let pri = if result.is_blocked { "<132>" } else { "<134>" }
  let tag = if result.context.is_agent_call {
    "aegisbit-agent"
  } else {
    "aegisbit-waf"
  }
  pri +
  "1 " +
  result.context.timestamp +
  " " +
  tag +
  " " +
  result.context.trace_id +
  " [event verdict=\"" +
  result.verdict.to_string() +
  "\" score=\"" +
  result.total_score.to_string() +
  "\" client=\"" +
  result.context.client_ip +
  "\"] " +
  (if result.is_blocked { "THREAT_BLOCKED" } else { "TRAFFIC_PASSED" })
}

///|
/// Aggregated inspection metrics for real-time telemetry and reporting.
pub(all) struct SecurityMetrics {
  mut total_inspected : Int
  mut total_blocked : Int
  mut total_monitored : Int
  mut total_allowed : Int
  mut total_threat_hits : Int
}

///|
/// Creates an empty security metrics collector.
pub fn SecurityMetrics::new() -> SecurityMetrics {
  {
    total_inspected: 0,
    total_blocked: 0,
    total_monitored: 0,
    total_allowed: 0,
    total_threat_hits: 0,
  }
}

///|
/// Records an inspection result into metric counters.
pub fn SecurityMetrics::record(
  self : SecurityMetrics,
  res : InspectionResult,
) -> Unit {
  self.total_inspected = self.total_inspected + 1
  self.total_threat_hits = self.total_threat_hits + res.matches.length()
  match res.verdict {
    Block => self.total_blocked = self.total_blocked + 1
    Monitor => self.total_monitored = self.total_monitored + 1
    Allow => self.total_allowed = self.total_allowed + 1
    _ => ()
  }
}

///|
/// Generates a summary string of security metrics.
pub fn SecurityMetrics::to_string(self : SecurityMetrics) -> String {
  "Inspected: " +
  self.total_inspected.to_string() +
  ", Blocked: " +
  self.total_blocked.to_string() +
  ", Monitored: " +
  self.total_monitored.to_string() +
  ", Allowed: " +
  self.total_allowed.to_string() +
  ", Threat Hits: " +
  self.total_threat_hits.to_string()
}

///|
/// Formats an inspection result as a single-line JSONL record for high-throughput stream log shipping.
pub fn format_jsonl_audit(result : InspectionResult) -> String {
  "{\"ts\":\"" +
  json_escape(result.context.timestamp) +
  "\",\"trace\":\"" +
  json_escape(result.context.trace_id) +
  "\",\"ip\":\"" +
  json_escape(result.context.client_ip) +
  "\",\"path\":\"" +
  json_escape(result.context.request_path) +
  "\",\"verdict\":\"" +
  result.verdict.to_string() +
  "\",\"score\":" +
  result.total_score.to_string() +
  ",\"blocked\":" +
  (if result.is_blocked { "true" } else { "false" }) +
  ",\"hits\":" +
  result.matches.length().to_string() +
  "}"
}

///|
/// Formats an inspection result as a comma-separated CSV record (ts,trace,ip,method,path,verdict,score,blocked).
pub fn format_csv_audit(result : InspectionResult) -> String {
  "\"" +
  json_escape(result.context.timestamp) +
  "\",\"" +
  json_escape(result.context.trace_id) +
  "\",\"" +
  json_escape(result.context.client_ip) +
  "\",\"" +
  json_escape(result.context.http_method) +
  "\",\"" +
  json_escape(result.context.request_path) +
  "\",\"" +
  result.verdict.to_string() +
  "\"," +
  result.total_score.to_string() +
  "," +
  (if result.is_blocked { "1" } else { "0" })
}

///|
/// Formats a webhook alert payload for incident response automation (e.g. Slack/Discord/PagerDuty).
pub fn format_webhook_alert_json(result : InspectionResult) -> String {
  let title = if result.is_blocked {
    "CRITICAL THREAT BLOCKED BY AEGISBIT"
  } else {
    "SECURITY EVENT MONITORED"
  }
  let mut text = "Trace: " +
    result.context.trace_id +
    " | Client: " +
    result.context.client_ip +
    " | Score: " +
    result.total_score.to_string() +
    " | Target: " +
    result.context.request_path
  if result.matches.length() > 0 {
    text = text + " | Rule: " + result.matches[0].rule_name
  }
  "{\"title\":\"" +
  json_escape(title) +
  "\",\"severity\":\"" +
  result.highest_severity().to_string() +
  "\",\"message\":\"" +
  json_escape(text) +
  "\"}"
}
