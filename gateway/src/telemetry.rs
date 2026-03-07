use serde::{Deserialize, Serialize};
use serde_json::Value;
use worker::kv::KvStore;

const MAX_COT_CONTENT_LEN: usize = 8000;
const MAX_ARGS_LEN: usize = 3000;
const MAX_COT_STEPS: usize = 20;
const TRACE_TTL_SECONDS: u64 = 7 * 24 * 3600;
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
                    if block.get("type").and_then(|v| v.as_str()) == Some("tool_use") {
                        let id = block.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let name = block.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        tool_blocks.push((index, id, name, Vec::new()));
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

// ── KV Helpers ──────────────────────────────────────────────────────────────

pub async fn store_trace(kv: &KvStore, record: &TraceRecord) -> Result<(), worker::Error> {
    let key = format!("trace:{}:{}", record.project_id, record.timestamp_ms);
    let json = serde_json::to_string(record)
        .map_err(|e| worker::Error::RustError(format!("json serialize error: {e}")))?;
    kv.put(&key, json)
        .map_err(|e| worker::Error::RustError(format!("kv put error: {e}")))?
        .expiration_ttl(TRACE_TTL_SECONDS)
        .execute()
        .await
        .map_err(|e| worker::Error::RustError(format!("kv execute error: {e}")))?;
    Ok(())
}

pub async fn list_traces(kv: &KvStore, project_id: &str) -> Result<Vec<TraceRecord>, worker::Error> {
    let prefix = format!("trace:{project_id}:");
    let list_result = kv.list()
        .prefix(prefix)
        .limit(MAX_TRACES_PER_LIST as u64)
        .execute()
        .await
        .map_err(|e| worker::Error::RustError(format!("kv list error: {e}")))?;

    let mut records = Vec::new();
    for key_entry in list_result.keys {
        let key_name = key_entry.name;
        if let Some(value) = kv.get(&key_name)
            .text()
            .await
            .map_err(|e| worker::Error::RustError(format!("kv get error: {e}")))?
        {
            if let Ok(record) = serde_json::from_str::<TraceRecord>(&value) {
                records.push(record);
            }
        }
    }

    // Return newest first
    records.sort_by(|a, b| b.timestamp_ms.cmp(&a.timestamp_ms));
    Ok(records)
}

pub fn compute_summary(records: &[TraceRecord]) -> ProjectSummary {
    let total = records.len() as u64;
    let ok = records.iter().filter(|r| r.status == "ok").count() as u64;
    let err = records.iter().filter(|r| r.status == "error").count() as u64;
    let tool_calls: u64 = records.iter().map(|r| r.tool_calls.len() as u64).sum();
    let sensitive: u64 = records.iter()
        .flat_map(|r| r.tool_calls.iter())
        .filter(|tc| tc.is_sensitive)
        .count() as u64;
    let cot_steps: u64 = records.iter().map(|r| r.cot_steps.len() as u64).sum();

    let gateway_ms_list: Vec<u64> = records.iter()
        .filter(|r| r.status == "ok" && r.timing.gateway_ms > 0)
        .map(|r| r.timing.gateway_ms)
        .collect();
    let avg_gateway = if gateway_ms_list.is_empty() {
        0
    } else {
        gateway_ms_list.iter().sum::<u64>() / gateway_ms_list.len() as u64
    };

    ProjectSummary {
        total_requests: total,
        success_requests: ok,
        error_requests: err,
        total_tool_calls: tool_calls,
        sensitive_tool_calls: sensitive,
        total_cot_steps: cot_steps,
        avg_gateway_ms: avg_gateway,
    }
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
