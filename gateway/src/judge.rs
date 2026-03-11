use serde::{Deserialize, Serialize};
use serde_json::Value;
use worker::*;

use crate::telemetry::{CotStep, ToolCallRecord};

const JUDGE_SYSTEM_PROMPT: &str = include_str!("skills/judge_audit.md");

const MAX_USER_CONTEXT_LEN: usize = 4000;
const MAX_COT_CONTEXT_LEN: usize = 4000;
const JUDGE_MAX_TOKENS: u32 = 512;

// ── Data Types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum JudgeAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeVerdict {
    pub action: JudgeAction,
    pub risk_level: String,
    pub reasoning: String,
}

// ── Provider Config ─────────────────────────────────────────────────────────

struct JudgeProviderConfig {
    model: &'static str,
    endpoint: &'static str,
}

fn judge_config_for_provider(provider: &str) -> JudgeProviderConfig {
    match provider {
        "anthropic" => JudgeProviderConfig {
            model: "claude-sonnet-4-6",
            endpoint: "https://api.anthropic.com/v1/messages",
        },
        "google" | "gemini" => JudgeProviderConfig {
            model: "gemini-3-flash-preview",
            endpoint: "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent",
        },
        "groq" => JudgeProviderConfig {
            model: "llama-3.1-8b-instant",
            endpoint: "https://api.groq.com/openai/v1/chat/completions",
        },
        // openai, openrouter, and all other providers use gpt-4.5 with high reasoning
        _ => JudgeProviderConfig {
            model: "gpt-4.5",
            endpoint: "https://api.openai.com/v1/chat/completions",
        },
    }
}

// ── Public Interface ────────────────────────────────────────────────────────

pub fn should_invoke_judge(tool_calls: &[ToolCallRecord]) -> bool {
    tool_calls.iter().any(|tc| tc.is_sensitive)
}

pub async fn invoke_judge(
    provider: &str,
    authorization: &str,
    request_headers: &[(String, String)],
    request_body: &[u8],
    cot_steps: &[CotStep],
    tool_calls: &[ToolCallRecord],
) -> Result<(JudgeVerdict, String)> {
    let config = judge_config_for_provider(provider);
    let user_prompt = build_judge_user_prompt(provider, request_body, cot_steps, tool_calls);

    let response_text = call_judge_model(
        provider,
        &config,
        authorization,
        request_headers,
        &user_prompt,
    )
    .await?;

    let verdict = parse_judge_response(&response_text)?;
    Ok((verdict, config.model.to_string()))
}

pub fn build_intervention_response(
    provider: &str,
    verdict: &JudgeVerdict,
    tool_calls: &[ToolCallRecord],
) -> Vec<u8> {
    let tool_names: Vec<&str> = tool_calls
        .iter()
        .filter(|tc| tc.is_sensitive)
        .map(|tc| tc.name.as_str())
        .collect();

    let message = format!(
        "[Claw Shield — Action Blocked]\n\n\
         The proposed action has been flagged and blocked by Claw Shield's security audit.\n\n\
         Blocked tools: {}\n\
         Risk level: {}\n\
         Reason: {}\n\n\
         Please reconsider your approach or ask the user for explicit confirmation \
         before attempting this action again.",
        tool_names.join(", "),
        verdict.risk_level,
        verdict.reasoning,
    );

    match provider {
        "anthropic" => build_anthropic_intervention(&message),
        "google" | "gemini" => build_google_intervention(&message),
        _ => build_openai_intervention(&message),
    }
}

// ── Judge Prompt Construction ───────────────────────────────────────────────

fn build_judge_user_prompt(
    provider: &str,
    request_body: &[u8],
    cot_steps: &[CotStep],
    tool_calls: &[ToolCallRecord],
) -> String {
    let user_context = extract_user_context(request_body);
    let cot_text = format_cot_steps(cot_steps);
    let actions_json = format_proposed_actions(tool_calls);

    let audit_input = serde_json::json!({
        "user_context": truncate(&user_context, MAX_USER_CONTEXT_LEN),
        "agent_cot": truncate(&cot_text, MAX_COT_CONTEXT_LEN),
        "proposed_actions": actions_json,
        "environment": {
            "provider": provider,
        }
    });

    serde_json::to_string_pretty(&audit_input).unwrap_or_else(|_| "{}".into())
}

fn extract_user_context(request_body: &[u8]) -> String {
    let text = match std::str::from_utf8(request_body) {
        Ok(t) => t,
        Err(_) => return String::new(),
    };

    let obj: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return String::new(),
    };

    let mut parts = Vec::new();

    // OpenAI / OpenRouter / Mistral / Groq format
    if let Some(messages) = obj.get("messages").and_then(|m| m.as_array()) {
        for msg in messages {
            let role = msg.get("role").and_then(|v| v.as_str()).unwrap_or("");
            if role == "system" || role == "user" {
                if let Some(content) = msg.get("content").and_then(|v| v.as_str()) {
                    parts.push(format!("[{role}]: {content}"));
                }
            }
        }
    }

    // Anthropic format
    if parts.is_empty() {
        if let Some(system) = obj.get("system").and_then(|v| v.as_str()) {
            parts.push(format!("[system]: {system}"));
        }
        if let Some(messages) = obj.get("messages").and_then(|m| m.as_array()) {
            for msg in messages {
                let role = msg.get("role").and_then(|v| v.as_str()).unwrap_or("");
                if role == "user" {
                    if let Some(content) = msg.get("content").and_then(|v| v.as_str()) {
                        parts.push(format!("[user]: {content}"));
                    }
                }
            }
        }
    }

    // Google format
    if parts.is_empty() {
        if let Some(contents) = obj.get("contents").and_then(|c| c.as_array()) {
            for content in contents {
                let role = content.get("role").and_then(|v| v.as_str()).unwrap_or("user");
                if role == "user" {
                    if let Some(parts_arr) = content.get("parts").and_then(|p| p.as_array()) {
                        for part in parts_arr {
                            if let Some(text) = part.get("text").and_then(|v| v.as_str()) {
                                parts.push(format!("[user]: {text}"));
                            }
                        }
                    }
                }
            }
        }
    }

    parts.join("\n")
}

fn format_cot_steps(steps: &[CotStep]) -> String {
    if steps.is_empty() {
        return "(no chain-of-thought captured)".into();
    }
    steps
        .iter()
        .map(|s| format!("Step {}: {}", s.index + 1, s.content))
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_proposed_actions(tool_calls: &[ToolCallRecord]) -> Value {
    let actions: Vec<Value> = tool_calls
        .iter()
        .filter(|tc| tc.is_sensitive)
        .map(|tc| {
            serde_json::json!({
                "name": tc.name,
                "arguments": tc.raw_args,
                "sensitive_flags": tc.sensitive_flags,
            })
        })
        .collect();
    Value::Array(actions)
}

// ── Provider-Specific API Calls ─────────────────────────────────────────────

async fn call_judge_model(
    provider: &str,
    config: &JudgeProviderConfig,
    authorization: &str,
    request_headers: &[(String, String)],
    user_prompt: &str,
) -> Result<String> {
    match provider {
        "anthropic" => call_anthropic_judge(config, authorization, request_headers, user_prompt).await,
        "google" | "gemini" => call_google_judge(config, authorization, request_headers, user_prompt).await,
        "openrouter" => call_openai_compatible_judge(
            &JudgeProviderConfig {
                model: "openai/gpt-4.5",
                endpoint: "https://openrouter.ai/api/v1/chat/completions",
            },
            authorization,
            user_prompt,
        ).await,
        _ => call_openai_compatible_judge(config, authorization, user_prompt).await,
    }
}

async fn call_openai_compatible_judge(
    config: &JudgeProviderConfig,
    authorization: &str,
    user_prompt: &str,
) -> Result<String> {
    let body = serde_json::json!({
        "model": config.model,
        "messages": [
            { "role": "system", "content": JUDGE_SYSTEM_PROMPT },
            { "role": "user", "content": user_prompt }
        ],
        "max_tokens": JUDGE_MAX_TOKENS,
        "reasoning_effort": "high",
    });

    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    headers.set("authorization", authorization)?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_headers(headers);
    init.with_body(Some(
        js_sys::JsString::from(body.to_string()).into(),
    ));

    let request = Request::new_with_init(config.endpoint, &init)?;
    let mut response = Fetch::Request(request).send().await?;

    if response.status_code() >= 400 {
        let err_body = response.text().await.unwrap_or_default();
        return Err(Error::RustError(format!(
            "judge API returned {}: {}",
            response.status_code(),
            truncate(&err_body, 500)
        )));
    }

    let obj: Value = response.json().await?;
    let content = obj
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(content)
}

async fn call_anthropic_judge(
    config: &JudgeProviderConfig,
    authorization: &str,
    request_headers: &[(String, String)],
    user_prompt: &str,
) -> Result<String> {
    let api_key = extract_anthropic_key(authorization, request_headers);

    let body = serde_json::json!({
        "model": config.model,
        "max_tokens": JUDGE_MAX_TOKENS,
        "system": JUDGE_SYSTEM_PROMPT,
        "messages": [
            { "role": "user", "content": user_prompt }
        ],
        "temperature": 0.0,
    });

    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    headers.set("x-api-key", &api_key)?;
    headers.set("anthropic-version", "2023-06-01")?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_headers(headers);
    init.with_body(Some(
        js_sys::JsString::from(body.to_string()).into(),
    ));

    let request = Request::new_with_init(config.endpoint, &init)?;
    let mut response = Fetch::Request(request).send().await?;

    if response.status_code() >= 400 {
        let err_body = response.text().await.unwrap_or_default();
        return Err(Error::RustError(format!(
            "judge API returned {}: {}",
            response.status_code(),
            truncate(&err_body, 500)
        )));
    }

    let obj: Value = response.json().await?;
    let content = obj
        .get("content")
        .and_then(|c| c.get(0))
        .and_then(|b| b.get("text"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(content)
}

async fn call_google_judge(
    config: &JudgeProviderConfig,
    _authorization: &str,
    request_headers: &[(String, String)],
    user_prompt: &str,
) -> Result<String> {
    let api_key = extract_google_key(request_headers);
    let endpoint = format!("{}?key={}", config.endpoint, api_key);

    let body = serde_json::json!({
        "system_instruction": {
            "parts": [{ "text": JUDGE_SYSTEM_PROMPT }]
        },
        "contents": [{
            "role": "user",
            "parts": [{ "text": user_prompt }]
        }],
        "generationConfig": {
            "maxOutputTokens": JUDGE_MAX_TOKENS,
            "temperature": 0.0,
        }
    });

    let headers = Headers::new();
    headers.set("content-type", "application/json")?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_headers(headers);
    init.with_body(Some(
        js_sys::JsString::from(body.to_string()).into(),
    ));

    let request = Request::new_with_init(&endpoint, &init)?;
    let mut response = Fetch::Request(request).send().await?;

    if response.status_code() >= 400 {
        let err_body = response.text().await.unwrap_or_default();
        return Err(Error::RustError(format!(
            "judge API returned {}: {}",
            response.status_code(),
            truncate(&err_body, 500)
        )));
    }

    let obj: Value = response.json().await?;
    let content = obj
        .get("candidates")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("content"))
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.get(0))
        .and_then(|p| p.get("text"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(content)
}

// ── Response Parsing ────────────────────────────────────────────────────────

fn parse_judge_response(raw: &str) -> Result<JudgeVerdict> {
    // Try direct JSON parse first
    if let Ok(v) = serde_json::from_str::<JudgeVerdict>(raw) {
        return Ok(v);
    }

    // Try extracting JSON from markdown code block
    let trimmed = raw.trim();
    if let Some(start) = trimmed.find('{') {
        if let Some(end) = trimmed.rfind('}') {
            let json_slice = &trimmed[start..=end];
            if let Ok(v) = serde_json::from_str::<JudgeVerdict>(json_slice) {
                return Ok(v);
            }
        }
    }

    // Fallback: couldn't parse → fail-open with warning
    Err(Error::RustError(format!(
        "failed to parse judge verdict from response: {}",
        truncate(raw, 300)
    )))
}

// ── Intervention Response Builders ──────────────────────────────────────────

fn build_openai_intervention(message: &str) -> Vec<u8> {
    serde_json::json!({
        "id": "claw-shield-judge",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": message
            },
            "finish_reason": "stop"
        }]
    })
    .to_string()
    .into_bytes()
}

fn build_anthropic_intervention(message: &str) -> Vec<u8> {
    serde_json::json!({
        "id": "claw-shield-judge",
        "type": "message",
        "role": "assistant",
        "content": [{
            "type": "text",
            "text": message
        }],
        "stop_reason": "end_turn"
    })
    .to_string()
    .into_bytes()
}

fn build_google_intervention(message: &str) -> Vec<u8> {
    serde_json::json!({
        "candidates": [{
            "content": {
                "role": "model",
                "parts": [{ "text": message }]
            },
            "finishReason": "STOP"
        }]
    })
    .to_string()
    .into_bytes()
}

// ── Utility ─────────────────────────────────────────────────────────────────

fn extract_anthropic_key(authorization: &str, headers: &[(String, String)]) -> String {
    // Prefer explicit x-api-key header
    for (name, value) in headers {
        if name == "x-api-key" && !value.is_empty() {
            return value.clone();
        }
    }
    // Fall back to Bearer token from authorization header
    strip_bearer(authorization)
}

fn extract_google_key(headers: &[(String, String)]) -> String {
    // Google API key may be in x-goog-api-key header
    for (name, value) in headers {
        if name == "x-goog-api-key" && !value.is_empty() {
            return value.clone();
        }
    }
    // Fall back to authorization header stripped of "Bearer "
    for (name, value) in headers {
        if name == "authorization" && !value.is_empty() {
            return strip_bearer(value);
        }
    }
    String::new()
}

fn strip_bearer(auth: &str) -> String {
    let trimmed = auth.trim();
    if trimmed.to_ascii_lowercase().starts_with("bearer ") {
        trimmed[7..].trim().to_string()
    } else {
        trimmed.to_string()
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}
