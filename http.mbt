// HTTP/1.1 Protocol Parser and Target Field Extractor for AegisBit WAF
// Deconstructs raw HTTP requests into inspectable AST components (URI, Query, Headers, Cookies, Body).

///|
/// Represents a structured HTTP request parsed from raw wire stream.
pub(all) struct HttpRequest {
  http_method : String
  uri : String
  path : String
  query_params : Array[(String, String)]
  headers : Array[(String, String)]
  cookies : Array[(String, String)]
  body : String
  raw : String
}

///|
/// Creates a synthetic HTTP request for testing and lightweight invocation.
pub fn HttpRequest::new(
  http_method : String,
  uri : String,
  body? : String = "",
  headers? : Array[(String, String)] = [],
) -> HttpRequest {
  let (path, query_params) = parse_uri(uri)
  let cookies = extract_cookies_from_headers(headers)
  { http_method, uri, path, query_params, headers, cookies, body, raw: "", }
}

///|
/// Trims leading and trailing ASCII whitespace.
fn trim_whitespace(s : String) -> String {
  let len = s.length()
  if len == 0 {
    return ""
  }
  let mut start = 0
  while start < len {
    let c = s[start]
    if c == ' '.to_int().to_uint16() ||
      c == '\t'.to_int().to_uint16() ||
      c == '\r'.to_int().to_uint16() ||
      c == '\n'.to_int().to_uint16() {
      start = start + 1
    } else {
      break
    }
  }
  let mut end = len
  while end > start {
    let c = s[end - 1]
    if c == ' '.to_int().to_uint16() ||
      c == '\t'.to_int().to_uint16() ||
      c == '\r'.to_int().to_uint16() ||
      c == '\n'.to_int().to_uint16() {
      end = end - 1
    } else {
      break
    }
  }
  if start >= end {
    ""
  } else {
    s[start:end].to_owned()
  }
}

///|
/// Splits URI into base path and parsed query parameters.
pub fn parse_uri(uri : String) -> (String, Array[(String, String)]) {
  let q_idx = string_index_of(uri, "?")
  if q_idx < 0 {
    return (uri, [])
  }
  let path = uri[0:q_idx].to_owned()
  let query_str = uri[q_idx + 1:uri.length()].to_owned()
  let params = parse_query_string(query_str)
  (path, params)
}

///|
/// Parses urlencoded query string (e.g. key1=val1&key2=val2) into key-value pairs.
pub fn parse_query_string(query : String) -> Array[(String, String)] {
  let results : Array[(String, String)] = []
  if query.length() == 0 {
    return results
  }
  let len = query.length()
  let mut seg_start = 0
  let mut i = 0
  while i <= len {
    if i == len ||
      query[i] == '&'.to_int().to_uint16() ||
      query[i] == ';'.to_int().to_uint16() {
      if i > seg_start {
        let seg = query[seg_start:i].to_owned()
        let eq_idx = string_index_of(seg, "=")
        if eq_idx >= 0 {
          let k = seg[0:eq_idx].to_owned()
          let v = seg[eq_idx + 1:seg.length()].to_owned()
          results.push((url_decode(k), url_decode(v)))
        } else {
          results.push((url_decode(seg), ""))
        }
      }
      seg_start = i + 1
    }
    i = i + 1
  }
  results
}

///|
/// Extracts cookies from Cookie headers.
fn extract_cookies_from_headers(
  headers : Array[(String, String)],
) -> Array[(String, String)] {
  let cookies : Array[(String, String)] = []
  let mut i = 0
  while i < headers.length() {
    let (name, val) = headers[i]
    if name.to_lower() == "cookie" {
      let parsed = parse_cookie_header(val)
      let mut j = 0
      while j < parsed.length() {
        cookies.push(parsed[j])
        j = j + 1
      }
    }
    i = i + 1
  }
  cookies
}

///|
/// Parses Cookie header value (name1=val1; name2=val2).
pub fn parse_cookie_header(cookie_header : String) -> Array[(String, String)] {
  let results : Array[(String, String)] = []
  let len = cookie_header.length()
  let mut seg_start = 0
  let mut i = 0
  while i <= len {
    if i == len || cookie_header[i] == ';'.to_int().to_uint16() {
      if i > seg_start {
        let seg = trim_whitespace(cookie_header[seg_start:i].to_owned())
        let eq_idx = string_index_of(seg, "=")
        if eq_idx >= 0 {
          let k = trim_whitespace(seg[0:eq_idx].to_owned())
          let v = trim_whitespace(seg[eq_idx + 1:seg.length()].to_owned())
          if k.length() > 0 {
            results.push((k, v))
          }
        }
      }
      seg_start = i + 1
    }
    i = i + 1
  }
  results
}

///|
/// Parses a complete raw HTTP/1.1 wire stream into an HttpRequest.
pub fn HttpRequest::parse(raw : String) -> HttpRequest? {
  if raw.length() == 0 {
    return None
  }

  // Split headers and body at double CRLF or double LF
  let mut body_start = -1
  let mut header_end_len = 0

  let crlf2 = "\r\n\r\n"
  let crlf2_idx = string_index_of(raw, crlf2)
  if crlf2_idx >= 0 {
    body_start = crlf2_idx + 4
    header_end_len = crlf2_idx
  } else {
    let lf2 = "\n\n"
    let lf2_idx = string_index_of(raw, lf2)
    if lf2_idx >= 0 {
      body_start = lf2_idx + 2
      header_end_len = lf2_idx
    } else {
      header_end_len = raw.length()
    }
  }

  let header_part = raw[0:header_end_len].to_owned()
  let body_part = if body_start >= 0 && body_start < raw.length() {
    raw[body_start:raw.length()].to_owned()
  } else {
    ""
  }

  // Parse request line and headers
  let lines : Array[String] = []
  let h_len = header_part.length()
  let mut line_start = 0
  let mut i = 0
  while i <= h_len {
    if i == h_len || header_part[i] == '\n'.to_int().to_uint16() {
      let mut line_end = i
      if line_end > line_start &&
        header_part[line_end - 1] == '\r'.to_int().to_uint16() {
        line_end = line_end - 1
      }
      lines.push(header_part[line_start:line_end].to_owned())
      line_start = i + 1
    }
    i = i + 1
  }

  if lines.length() == 0 {
    return None
  }

  // Request Line: METHOD URI HTTP/VERSION
  let req_line = trim_whitespace(lines[0])
  let sp1 = string_index_of(req_line, " ")
  if sp1 < 0 {
    return None
  }
  let verb = req_line[0:sp1].to_owned()
  let rem = trim_whitespace(req_line[sp1 + 1:req_line.length()].to_owned())
  let sp2 = string_index_of(rem, " ")
  let uri = if sp2 >= 0 { rem[0:sp2].to_owned() } else { rem }

  let (path, query_params) = parse_uri(uri)

  // Parse header key-values
  let headers : Array[(String, String)] = []
  let mut l_idx = 1
  while l_idx < lines.length() {
    let line = lines[l_idx]
    let colon = string_index_of(line, ":")
    if colon > 0 {
      let key = trim_whitespace(line[0:colon].to_owned())
      let val = trim_whitespace(line[colon + 1:line.length()].to_owned())
      headers.push((key, val))
    }
    l_idx = l_idx + 1
  }

  let cookies = extract_cookies_from_headers(headers)

  Some({
    http_method: verb,
    uri,
    path,
    query_params,
    headers,
    cookies,
    body: body_part,
    raw,
  })
}

///|
/// Retrieves a specific HTTP header by name (case-insensitive).
pub fn HttpRequest::get_header(self : HttpRequest, name : String) -> String? {
  let target = name.to_lower()
  let mut i = 0
  while i < self.headers.length() {
    let (k, v) = self.headers[i]
    if k.to_lower() == target {
      return Some(v)
    }
    i = i + 1
  }
  None
}

///|
/// Retrieves a specific query parameter by key.
pub fn HttpRequest::get_query_param(
  self : HttpRequest,
  key : String,
) -> String? {
  let mut i = 0
  while i < self.query_params.length() {
    let (k, v) = self.query_params[i]
    if k == key {
      return Some(v)
    }
    i = i + 1
  }
  None
}

///|
/// Retrieves a specific cookie value by cookie name.
pub fn HttpRequest::get_cookie(self : HttpRequest, name : String) -> String? {
  let mut i = 0
  while i < self.cookies.length() {
    let (k, v) = self.cookies[i]
    if k == name {
      return Some(v)
    }
    i = i + 1
  }
  None
}

///|
/// Flattens all inspectable request fields into (target_type, target_value) tuples.
pub fn HttpRequest::inspection_targets(
  self : HttpRequest,
) -> Array[(String, String)] {
  let targets : Array[(String, String)] = []

  // URI and Path targets
  targets.push(("URI", self.uri))
  if self.path != self.uri {
    targets.push(("PATH", self.path))
  }

  // Query parameters targets
  let mut i = 0
  while i < self.query_params.length() {
    let (k, v) = self.query_params[i]
    targets.push(("QUERY_PARAM:" + k, v))
    i = i + 1
  }

  // Headers targets
  let mut j = 0
  while j < self.headers.length() {
    let (k, v) = self.headers[j]
    targets.push(("HEADER:" + k, v))
    j = j + 1
  }

  // Cookies targets
  let mut c = 0
  while c < self.cookies.length() {
    let (k, v) = self.cookies[c]
    targets.push(("COOKIE:" + k, v))
    c = c + 1
  }

  // Body target
  if self.body.length() > 0 {
    targets.push(("BODY", self.body))
  }

  targets
}

///|
/// Represents an HTTP Response generated or modified by AegisBit WAF.
pub(all) struct HttpResponse {
  status_code : Int
  status_text : String
  headers : Array[(String, String)]
  body : String
}

///|
/// Creates a new generic HttpResponse.
pub fn HttpResponse::new(
  status_code : Int,
  status_text : String,
  body? : String = "",
  headers? : Array[(String, String)] = [],
) -> HttpResponse {
  { status_code, status_text, headers, body, }
}

///|
/// Constructs a standard 403 Forbidden blocking response for detected attacks.
pub fn HttpResponse::block_forbidden(trace_id : String) -> HttpResponse {
  let body = "{\"error\": \"Forbidden\", \"status\": 403, \"message\": \"Request blocked by AegisBit WAF\", \"trace_id\": \"" +
    trace_id +
    "\"}"
  let headers : Array[(String, String)] = [
    ("Content-Type", "application/json"),
    ("Content-Length", body.length().to_string()),
    ("X-AegisBit-Verdict", "BLOCKED"),
  ]
  HttpResponse::new(403, "Forbidden", body~, headers~).with_security_headers()
}

///|
/// Constructs a 429 Too Many Requests rate-limiting response.
pub fn HttpResponse::rate_limited() -> HttpResponse {
  let body = "{\"error\": \"Too Many Requests\", \"status\": 429, \"message\": \"Rate limit quota exceeded\"}"
  let headers : Array[(String, String)] = [
    ("Content-Type", "application/json"),
    ("Content-Length", body.length().to_string()),
    ("Retry-After", "60"),
  ]
  HttpResponse::new(429, "Too Many Requests", body~, headers~).with_security_headers()
}

///|
/// Constructs a standard 200 OK passed response.
pub fn HttpResponse::ok(body : String) -> HttpResponse {
  let headers : Array[(String, String)] = [
    ("Content-Type", "text/plain"),
    ("Content-Length", body.length().to_string()),
  ]
  HttpResponse::new(200, "OK", body~, headers~).with_security_headers()
}

///|
/// Injects OWASP recommended defensive security headers.
pub fn HttpResponse::with_security_headers(self : HttpResponse) -> HttpResponse {
  let new_headers : Array[(String, String)] = []
  let mut i = 0
  while i < self.headers.length() {
    new_headers.push(self.headers[i])
    i = i + 1
  }
  new_headers.push(("X-Content-Type-Options", "nosniff"))
  new_headers.push(("X-Frame-Options", "DENY"))
  new_headers.push(("X-XSS-Protection", "1; mode=block"))
  new_headers.push(("Content-Security-Policy", "default-src 'self'"))
  new_headers.push(
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
  )
  {
    status_code: self.status_code,
    status_text: self.status_text,
    headers: new_headers,
    body: self.body,
  }
}

///|
/// Formats HttpResponse to raw RFC 7230 HTTP/1.1 wire string.
pub fn HttpResponse::to_wire_format(self : HttpResponse) -> String {
  let buf = StringBuilder()
  buf.write_string(
    "HTTP/1.1 " + self.status_code.to_string() + " " + self.status_text + "\r\n",
  )
  let mut i = 0
  while i < self.headers.length() {
    let (k, v) = self.headers[i]
    buf.write_string(k + ": " + v + "\r\n")
    i = i + 1
  }
  buf.write_string("\r\n")
  if self.body.length() > 0 {
    buf.write_string(self.body)
  }
  buf.to_string()
}
