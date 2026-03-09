use serde::{Deserialize, Serialize};
use serde_json::Value;
use wasm_bindgen::JsValue;
use worker::D1Database;

const MAX_COT_CONTENT_LEN: usize = 8000;
const MAX_ARGS_LEN: usize = 3000;
const MAX_COT_STEPS: usize = 20;
const TRACE_TTL_MS: u64 = 7 * 24 * 3600 * 1000;
const MAX_TRACES_PER_LIST: usize = 100;

// ── Data Types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRecord {
    pub id: String,
    pub project_id: String,
    pub session_id: String,
    pub provider: String,
    pub model: String,
    pub path: String,
    pub timestamp_ms: u64,
    pub timing: Timing,
    pub cot_steps: Vec<CotStep>,
    pub tool_calls: Vec<ToolCallRecord>,
    pub tool_results: Vec<ToolResultRecord>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_msg: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Timing {
    pub gateway_ms: u64,
    pub upstream_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CotStep {
    pub index: usize,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallRecord {
    pub call_id: String,
    pub name: String,
    pub raw_args: String,
    pub is_sensitive: bool,
    pub sensitive_flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResultRecord {
    pub call_id: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectSummary {
    pub total_requests: u64,
    pub success_requests: u64,
    pub error_requests: u64,
    pub total_tool_calls: u64,
    pub sensitive_tool_calls: u64,
    pub total_cot_steps: u64,
    pub avg_gateway_ms: u64,
}

// ── Sensitivity Detection ───────────────────────────────────────────────────

const SENSITIVE_TOOL_NAMES: &[&str] = &[
    "bash", "shell", "execute_command", "run_command", "computer", "terminal",
    "read_file", "write_file", "edit_file", "delete_file", "create_file",
    "str_replace_editor", "str_replace_based_edit_tool",
    "list_directory", "glob", "grep",
];

struct SensitivePattern {
    pattern: &'static str,
    label: &'static str,
}

const SENSITIVE_CONTENT_PATTERNS: &[SensitivePattern] = &[
    SensitivePattern { pattern: "/etc/", label: "system directory access (/etc/)" },
    SensitivePattern { pattern: "/root/", label: "root directory access" },
    SensitivePattern { pattern: ".env", label: ".env file access" },
    SensitivePattern { pattern: ".ssh", label: ".ssh directory access" },
    SensitivePattern { pattern: "credential", label: "credential-related operation" },
    SensitivePattern { pattern: "password", label: "password field" },
    SensitivePattern { pattern: "api_key", label: "API key related" },
    SensitivePattern { pattern: "api-key", label: "API key related" },
    SensitivePattern { pattern: "secret", label: "secret/key related" },
    SensitivePattern { pattern: "sudo", label: "sudo privilege escalation" },
];

fn detect_sensitivity(name: &str, args: &str) -> (bool, Vec<String>) {
    let mut flags = Vec::new();
    let name_lower = name.to_ascii_lowercase();

    for &sensitive in SENSITIVE_TOOL_NAMES {
        if name_lower == sensitive
            || name_lower.starts_with(&format!("{sensitive}_"))
            || name_lower.ends_with(&format!("_{sensitive}"))
        {
            flags.push(format!("sensitive tool: {name}"));
            break;
        }
    }

    if (name_lower.contains("file") || name_lower.contains("exec") || name_lower.contains("system"))
        && !flags.iter().any(|f| f.starts_with("sensitive tool"))
    {
        flags.push(format!("high-privilege keyword in tool name: {name}"));
    }

    let args_lower = args.to_ascii_lowercase();
    for pat in SENSITIVE_CONTENT_PATTERNS {
        if args_lower.contains(pat.pattern) {
            flags.push(pat.label.to_string());
        }
    }

    let is_sensitive = !flags.is_empty();
    (is_sensitive, flags)
}

// ── SSE Parsing ─────────────────────────────────────────────────────────────

pub fn parse_response_telemetry(
    response_body: &[u8],
    content_type: &str,
    provider: &str,
) -> (Vec<CotStep>, Vec<ToolCallRecord>) {
    let ct_lower = content_type.to_ascii_lowercase();
    let is_sse = ct_lower.starts_with("text/event-stream");
    let is_json = ct_lower.contains("application/json");

    let text = match std::str::from_utf8(response_body) {
        Ok(t) => t,
        Err(_) => return (vec![], vec![]),
    };

    if is_sse {
        return parse_sse(text, provider);
    }

    if is_json {
        return parse_json_response(text, provider);
    }

    (vec![], vec![])
}

fn parse_sse(text: &str, provider: &str) -> (Vec<CotStep>, Vec<ToolCallRecord>) {
    match provider {
        "anthropic" => parse_anthropic_sse(text),
        "google" | "gemini" => parse_google_sse(text),
        _ => parse_openai_sse(text),
    }
}

fn parse_json_response(text: &str, provider: &str) -> (Vec<CotStep>, Vec<ToolCallRecord>) {
    let obj: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return (vec![], vec![]),
    };

    match provider {
        "anthropic" => parse_anthropic_json(&obj),
        "google" | "gemini" => parse_google_json(&obj),
        _ => parse_openai_json(&obj),
    }
}

// ── OpenAI / Compatible ─────────────────────────────────────────────────────

fn parse_openai_sse(text: &str) -> (Vec<CotStep>, Vec<ToolCallRecord>) {
    let mut cot_buf = String::new();
    let mut tool_map: Vec<(String, String, Vec<String>)> = Vec::new(); // (call_id, name, arg_chunks)

    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("data:") { continue; }
        let payload = trimmed[5..].trim();
        if payload == "[DONE]" { continue; }

        let obj: Value = match serde_json::from_str(payload) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if let Some(choices) = obj.get("choices").and_then(|c| c.as_array()) {
            for choice in choices {
                if let Some(delta) = choice.get("delta") {
                    if let Some(r) = delta.get("reasoning_content").and_then(|v| v.as_str()) {
                        cot_buf.push_str(r);
                    }
                    if let Some(r) = delta.get("thinking").and_then(|v| v.as_str()) {
                        cot_buf.push_str(r);
                    }

                    if let Some(tcs) = delta.get("tool_calls").and_then(|v| v.as_array()) {
                        for tc in tcs {
                            let idx = tc.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                            while tool_map.len() <= idx {
                                tool_map.push((String::new(), String::new(), Vec::new()));
                            }
                            if let Some(id) = tc.get("id").and_then(|v| v.as_str()) {
                                if !id.is_empty() { tool_map[idx].0 = id.to_string(); }
                            }
                            if let Some(f) = tc.get("function") {
                                if let Some(n) = f.get("name").and_then(|v| v.as_str()) {
                                    if !n.is_empty() { tool_map[idx].1 = n.to_string(); }
                                }
                                if let Some(a) = f.get("arguments").and_then(|v| v.as_str()) {
                                    tool_map[idx].2.push(a.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let cot_steps = split_cot_into_steps(&cot_buf);
    let tool_calls = finalize_tool_map(tool_map);
    (cot_steps, tool_calls)
}

fn parse_openai_json(obj: &Value) -> (Vec<CotStep>, Vec<ToolCallRecord>) {
    let mut cot_buf = String::new();
    let mut tool_calls = Vec::new();

    if let Some(choices) = obj.get("choices").and_then(|c| c.as_array()) {
        for choice in choices {
            if let Some(msg) = choice.get("message") {
                if let Some(r) = msg.get("reasoning_content").and_then(|v| v.as_str()) {
                    cot_buf.push_str(r);
                }
                if let Some(r) = msg.get("thinking").and_then(|v| v.as_str()) {
                    cot_buf.push_str(r);
                }
                if let Some(tcs) = msg.get("tool_calls").and_then(|v| v.as_array()) {
                    for tc in tcs {
                        let call_id = tc.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let name = tc.get("function").and_then(|f| f.get("name")).and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let raw_args = tc.get("function").and_then(|f| f.get("arguments")).and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let truncated_args = truncate_str(&raw_args, MAX_ARGS_LEN);
                        let (is_sensitive, sensitive_flags) = detect_sensitivity(&name, &truncated_args);
                        tool_calls.push(ToolCallRecord {
                            call_id,
                            name,
                            raw_args: truncated_args,
                            is_sensitive,
                            sensitive_flags,
                        });
                    }
                }
            }
        }
    }

    (split_cot_into_steps(&cot_buf), tool_calls)
}

// ── Anthropic ───────────────────────────────────────────────────────────────

fn parse_anthropic_sse(text: &str) -> (Vec<CotStep>, Vec<ToolCallRecord>) {
    let mut cot_buf = String::new();
    let mut tool_blocks: Vec<(usize, String, String, Vec<String>)> = Vec::new(); // (index, id, name, input_chunks)

    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("data:") { continue; }
        let payload = trimmed[5..].trim();

        let obj: Value = match serde_json::from_str(payload) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let event_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");

        match event_type {
            "content_block_start" => {
                let index = obj.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                if let Some(block) = obj.get("content_block") {
                    let block_type = block.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    if block_type == "tool_use" {
                        let id = block.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let name = block.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        tool_blocks.push((index, id, name, Vec::new()));
                    } else if block_type == "redacted_thinking" {
                        cot_buf.push_str("[redacted thinking]\n\n");
                    }
                }
            }
            "content_block_delta" => {
                let index = obj.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                if let Some(delta) = obj.get("delta") {
                    let delta_type = delta.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    if delta_type == "thinking_delta" {
                        if let Some(t) = delta.get("thinking").and_then(|v| v.as_str()) {
                            cot_buf.push_str(t);
                        }
                    } else if delta_type == "input_json_delta" {
                        if let Some(pj) = delta.get("partial_json").and_then(|v| v.as_str()) {
                            if let Some(entry) = tool_blocks.iter_mut().find(|(idx, _, _, _)| *idx == index) {
                                entry.3.push(pj.to_string());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let cot_steps = split_cot_into_steps(&cot_buf);
    let tool_calls: Vec<ToolCallRecord> = tool_blocks.into_iter().map(|(_, id, name, chunks)| {
        let raw_args = truncate_str(&chunks.join(""), MAX_ARGS_LEN);
        let (is_sensitive, sensitive_flags) = detect_sensitivity(&name, &raw_args);
        ToolCallRecord { call_id: id, name, raw_args, is_sensitive, sensitive_flags }
    }).collect();

    (cot_steps, tool_calls)
}

fn parse_anthropic_json(obj: &Value) -> (Vec<CotStep>, Vec<ToolCallRecord>) {
    let mut cot_buf = String::new();
    let mut tool_calls = Vec::new();

    if let Some(content) = obj.get("content").and_then(|c| c.as_array()) {
        for block in content {
            let block_type = block.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if block_type == "thinking" {
                if let Some(t) = block.get("thinking").and_then(|v| v.as_str()) {
                    cot_buf.push_str(t);
                }
            } else if block_type == "redacted_thinking" {
                cot_buf.push_str("[redacted thinking]\n\n");
            } else if block_type == "tool_use" {
                let id = block.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let name = block.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let raw_args = block.get("input").map(|v| truncate_str(&v.to_string(), MAX_ARGS_LEN)).unwrap_or_default();
                let (is_sensitive, sensitive_flags) = detect_sensitivity(&name, &raw_args);
                tool_calls.push(ToolCallRecord { call_id: id, name, raw_args, is_sensitive, sensitive_flags });
            }
        }
    }

    (split_cot_into_steps(&cot_buf), tool_calls)
}

// ── Google / Gemini ─────────────────────────────────────────────────────────

fn parse_google_sse(text: &str) -> (Vec<CotStep>, Vec<ToolCallRecord>) {
    let mut cot_buf = String::new();
    let mut tool_calls = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("data:") { continue; }
        let payload = trimmed[5..].trim();

        let obj: Value = match serde_json::from_str(payload) {
            Ok(v) => v,
            Err(_) => continue,
        };

        extract_google_parts(&obj, &mut cot_buf, &mut tool_calls);
    }

    (split_cot_into_steps(&cot_buf), tool_calls)
}

fn parse_google_json(obj: &Value) -> (Vec<CotStep>, Vec<ToolCallRecord>) {
    let mut cot_buf = String::new();
    let mut tool_calls = Vec::new();
    extract_google_parts(obj, &mut cot_buf, &mut tool_calls);
    (split_cot_into_steps(&cot_buf), tool_calls)
}

fn extract_google_parts(obj: &Value, cot_buf: &mut String, tool_calls: &mut Vec<ToolCallRecord>) {
    let candidates = match obj.get("candidates").and_then(|c| c.as_array()) {
        Some(c) => c,
        None => return,
    };

    for candidate in candidates {
        let parts = match candidate.get("content").and_then(|c| c.get("parts")).and_then(|p| p.as_array()) {
            Some(p) => p,
            None => continue,
        };

        for part in parts {
            if part.get("thought").and_then(|v| v.as_bool()) == Some(true) {
                if let Some(t) = part.get("text").and_then(|v| v.as_str()) {
                    cot_buf.push_str(t);
                }
            }

            if let Some(fc) = part.get("functionCall") {
                let name = fc.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let raw_args = fc.get("args").map(|v| truncate_str(&v.to_string(), MAX_ARGS_LEN)).unwrap_or_default();
                let (is_sensitive, sensitive_flags) = detect_sensitivity(&name, &raw_args);
                tool_calls.push(ToolCallRecord {
                    call_id: format!("fn_{}", tool_calls.len()),
                    name,
                    raw_args,
                    is_sensitive,
                    sensitive_flags,
                });
            }
        }
    }
}

// ── Request Body Parsing (tool results) ─────────────────────────────────────

pub fn parse_request_telemetry(request_body: &[u8], content_type: &str) -> (String, Vec<ToolResultRecord>) {
    if !content_type.to_ascii_lowercase().contains("application/json") {
        return (String::new(), vec![]);
    }

    let text = match std::str::from_utf8(request_body) {
        Ok(t) => t,
        Err(_) => return (String::new(), vec![]),
    };

    let obj: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return (String::new(), vec![]),
    };

    let model = obj.get("model").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let mut tool_results = Vec::new();

    // OpenAI format: messages array with role="tool"
    if let Some(messages) = obj.get("messages").and_then(|m| m.as_array()) {
        for msg in messages {
            if msg.get("role").and_then(|v| v.as_str()) == Some("tool") {
                let call_id = msg.get("tool_call_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let content = msg.get("content").and_then(|v| v.as_str())
                    .map(|s| truncate_str(s, MAX_ARGS_LEN))
                    .unwrap_or_default();
                tool_results.push(ToolResultRecord { call_id, content });
            }
        }
    }

    // Anthropic format: content array with type="tool_result"
    if let Some(content_arr) = obj.get("content").and_then(|c| c.as_array()) {
        for block in content_arr {
            if block.get("type").and_then(|v| v.as_str()) == Some("tool_result") {
                let call_id = block.get("tool_use_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let content = block.get("content").and_then(|v| v.as_str())
                    .or_else(|| block.get("content").map(|_| "").filter(|_| false))
                    .map(|s| truncate_str(s, MAX_ARGS_LEN))
                    .unwrap_or_else(|| {
                        block.get("content").map(|v| truncate_str(&v.to_string(), MAX_ARGS_LEN)).unwrap_or_default()
                    });
                tool_results.push(ToolResultRecord { call_id, content });
            }
        }
    }

    (model, tool_results)
}

// ── CoT Step Splitting ──────────────────────────────────────────────────────

fn split_cot_into_steps(raw: &str) -> Vec<CotStep> {
    let trimmed = truncate_str(raw.trim(), MAX_COT_CONTENT_LEN);
    if trimmed.is_empty() {
        return vec![];
    }

    // Prefer paragraph-level splits
    let paragraphs: Vec<&str> = trimmed.split("\n\n")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    let chunks: Vec<String> = if paragraphs.len() > 1 {
        paragraphs.iter().map(|s| s.to_string()).collect()
    } else {
        // Fall back to sentence boundaries
        trimmed.split(|c: char| ".!?\u{3002}\u{ff01}\u{ff1f}".contains(c))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };

    // Merge very short chunks
    let mut merged: Vec<String> = Vec::new();
    for chunk in chunks {
        if !merged.is_empty() && chunk.len() < 60 {
            let last = merged.last_mut().unwrap();
            last.push(' ');
            last.push_str(&chunk);
        } else {
            merged.push(chunk);
        }
    }

    merged.into_iter()
        .take(MAX_COT_STEPS)
        .enumerate()
        .map(|(i, content)| CotStep { index: i, content })
        .collect()
}

// ── D1 Storage ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct TraceRow {
    id: String,
    project_id: String,
    session_id: String,
    provider: String,
    model: String,
    path: String,
    timestamp_ms: f64,
    gateway_ms: f64,
    upstream_ms: f64,
    status: String,
    #[serde(default)]
    error_msg: Option<String>,
    cot_steps: String,
    tool_calls: String,
    tool_results: String,
}

#[derive(Deserialize)]
struct SummaryRow {
    total_requests: f64,
    success_requests: f64,
    error_requests: f64,
    total_tool_calls: f64,
    sensitive_tool_calls: f64,
    total_cot_steps: f64,
    avg_gateway_ms: f64,
}

pub async fn store_trace(db: &D1Database, record: &TraceRecord) -> Result<(), worker::Error> {
    let cot_json = serde_json::to_string(&record.cot_steps).unwrap_or_else(|_| "[]".into());
    let tools_json = serde_json::to_string(&record.tool_calls).unwrap_or_else(|_| "[]".into());
    let results_json = serde_json::to_string(&record.tool_results).unwrap_or_else(|_| "[]".into());
    let sensitive_count = record.tool_calls.iter().filter(|t| t.is_sensitive).count();

    let error_val = match &record.error_msg {
        Some(msg) => JsValue::from_str(msg),
        None => JsValue::NULL,
    };

    db.prepare(
        "INSERT INTO traces (id, project_id, session_id, provider, model, path, \
         timestamp_ms, gateway_ms, upstream_ms, status, error_msg, \
         cot_steps, tool_calls, tool_results, sensitive_tool_count) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)"
    )
    .bind(&[
        JsValue::from_str(&record.id),
        JsValue::from_str(&record.project_id),
        JsValue::from_str(&record.session_id),
        JsValue::from_str(&record.provider),
        JsValue::from_str(&record.model),
        JsValue::from_str(&record.path),
        JsValue::from_f64(record.timestamp_ms as f64),
        JsValue::from_f64(record.timing.gateway_ms as f64),
        JsValue::from_f64(record.timing.upstream_ms as f64),
        JsValue::from_str(&record.status),
        error_val,
        JsValue::from_str(&cot_json),
        JsValue::from_str(&tools_json),
        JsValue::from_str(&results_json),
        JsValue::from_f64(sensitive_count as f64),
    ])?
    .run()
    .await?;

    Ok(())
}

pub async fn list_traces(db: &D1Database, project_id: &str) -> Result<Vec<TraceRecord>, worker::Error> {
    let cutoff_ms = (js_sys::Date::now() as u64).saturating_sub(TRACE_TTL_MS);
    let _ = db.prepare("DELETE FROM traces WHERE timestamp_ms < ?1")
        .bind(&[JsValue::from_f64(cutoff_ms as f64)])?
        .run()
        .await;

    let rows: Vec<TraceRow> = db.prepare(
        "SELECT id, project_id, session_id, provider, model, path, \
         timestamp_ms, gateway_ms, upstream_ms, status, error_msg, \
         cot_steps, tool_calls, tool_results \
         FROM traces WHERE project_id = ?1 \
         ORDER BY timestamp_ms DESC LIMIT ?2"
    )
    .bind(&[
        JsValue::from_str(project_id),
        JsValue::from_f64(MAX_TRACES_PER_LIST as f64),
    ])?
    .all()
    .await?
    .results()?;

    Ok(rows.into_iter().map(|r| TraceRecord {
        id: r.id,
        project_id: r.project_id,
        session_id: r.session_id,
        provider: r.provider,
        model: r.model,
        path: r.path,
        timestamp_ms: r.timestamp_ms as u64,
        timing: Timing {
            gateway_ms: r.gateway_ms as u64,
            upstream_ms: r.upstream_ms as u64,
        },
        cot_steps: serde_json::from_str(&r.cot_steps).unwrap_or_default(),
        tool_calls: serde_json::from_str(&r.tool_calls).unwrap_or_default(),
        tool_results: serde_json::from_str(&r.tool_results).unwrap_or_default(),
        status: r.status,
        error_msg: r.error_msg,
    }).collect())
}

pub async fn compute_summary(db: &D1Database, project_id: &str) -> Result<ProjectSummary, worker::Error> {
    let row = db.prepare(
        "SELECT \
            COUNT(*) as total_requests, \
            COALESCE(SUM(CASE WHEN status = 'ok' THEN 1 ELSE 0 END), 0) as success_requests, \
            COALESCE(SUM(CASE WHEN status != 'ok' THEN 1 ELSE 0 END), 0) as error_requests, \
            COALESCE(SUM(json_array_length(tool_calls)), 0) as total_tool_calls, \
            COALESCE(SUM(sensitive_tool_count), 0) as sensitive_tool_calls, \
            COALESCE(SUM(json_array_length(cot_steps)), 0) as total_cot_steps, \
            COALESCE(CAST(AVG(CASE WHEN status = 'ok' AND gateway_ms > 0 THEN gateway_ms END) AS INTEGER), 0) as avg_gateway_ms \
         FROM traces WHERE project_id = ?1"
    )
    .bind(&[JsValue::from_str(project_id)])?
    .first::<SummaryRow>(None)
    .await?;

    Ok(match row {
        Some(r) => ProjectSummary {
            total_requests: r.total_requests as u64,
            success_requests: r.success_requests as u64,
            error_requests: r.error_requests as u64,
            total_tool_calls: r.total_tool_calls as u64,
            sensitive_tool_calls: r.sensitive_tool_calls as u64,
            total_cot_steps: r.total_cot_steps as u64,
            avg_gateway_ms: r.avg_gateway_ms as u64,
        },
        None => ProjectSummary::default(),
    })
}

// ── Provider Inference ──────────────────────────────────────────────────────

pub fn infer_provider_from_url(target_url: &str) -> String {
    let lower = target_url.to_ascii_lowercase();
    if lower.contains("api.openai.com") { return "openai".into(); }
    if lower.contains("generativelanguage.googleapis.com") { return "google".into(); }
    if lower.contains("api.anthropic.com") { return "anthropic".into(); }
    if lower.contains("openrouter.ai") { return "openrouter".into(); }
    if lower.contains("api.mistral.ai") { return "mistral".into(); }
    if lower.contains("api.groq.com") { return "groq".into(); }
    "unknown".into()
}

// ── Utility ─────────────────────────────────────────────────────────────────

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        s[..max_len].to_string()
    }
}

fn finalize_tool_map(tool_map: Vec<(String, String, Vec<String>)>) -> Vec<ToolCallRecord> {
    tool_map.into_iter()
        .enumerate()
        .map(|(i, (call_id, name, arg_chunks))| {
            let cid = if call_id.is_empty() { format!("call_{i}") } else { call_id };
            let n = if name.is_empty() { "(unknown)".to_string() } else { name };
            let raw_args = truncate_str(&arg_chunks.join(""), MAX_ARGS_LEN);
            let (is_sensitive, sensitive_flags) = detect_sensitivity(&n, &raw_args);
            ToolCallRecord { call_id: cid, name: n, raw_args, is_sensitive, sensitive_flags }
        })
        .collect()
}
