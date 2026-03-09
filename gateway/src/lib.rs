mod telemetry;

use std::io::Cursor;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use bhttp::{ControlData, Message, Mode, StatusCode};
use js_sys::Uint8Array;
use ohttp::{
    hpke::{Aead, Kdf, Kem},
    KeyConfig, Server, SymmetricSuite,
};
use tokio::sync::OnceCell;
use worker::*;

use crate::telemetry::{
    TraceRecord, Timing,
    parse_response_telemetry, parse_request_telemetry,
    infer_provider_from_url, store_trace, list_traces, compute_summary,
};

const OHTTP_REQ_CONTENT_TYPE: &str = "message/ohttp-req";
const OHTTP_RES_CONTENT_TYPE: &str = "message/ohttp-res";
const OHTTP_KEYS_CONTENT_TYPE: &str = "application/ohttp-keys";
const DEFAULT_UPSTREAM_BASE_URL: &str = "https://api.openai.com";
const RELAY_ALLOWLIST_HEADER: &str = "x-claw-shield-relay-token";
const PROJECT_ID_HEADER: &str = "x-claw-shield-project-id";
const SESSION_ID_HEADER: &str = "x-claw-shield-session-id";
const DASHBOARD_HTML: &str = include_str!("dashboard.html");
const WAITLIST_HTML: &str = include_str!("waitlist.html");

static GATEWAY_STATE: OnceCell<GatewayState> = OnceCell::const_new();

#[derive(Clone)]
struct GatewayState {
    server: Server,
    encoded_config_list: Vec<u8>,
}

#[derive(Debug)]
enum ParsedRequestError {
    Unauthorized(String),
    BadRequest(String),
}

#[derive(Debug)]
struct ParsedBhttpRequest {
    method: Method,
    path: String,
    target_url: String,
    content_type: Option<String>,
    authorization: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    project_id: Option<String>,
    session_id: Option<String>,
}

struct UpstreamResult {
    bhttp_encoded: Vec<u8>,
    raw_body: Vec<u8>,
    content_type: String,
    status_code: u16,
}

impl GatewayState {
    fn from_env(env: &Env) -> Result<Self> {
        ohttp::init();

        let key_seed_b64 = read_secret_or_var(env, "OHTTP_PRIVATE_KEY_SEED_B64")?;
        let key_seed = BASE64_STANDARD
            .decode(key_seed_b64.trim())
            .map_err(|e| Error::RustError(format!("failed to decode OHTTP_PRIVATE_KEY_SEED_B64: {e}")))?;
        if key_seed.len() < 32 {
            return Err(Error::RustError(
                "OHTTP_PRIVATE_KEY_SEED_B64 must decode to at least 32 bytes".into(),
            ));
        }

        let key_id = env
            .var("OHTTP_KEY_ID")
            .ok()
            .and_then(|v| v.to_string().parse::<u8>().ok())
            .unwrap_or(1);

        let symmetric_suites = vec![
            SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm),
            SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305),
        ];

        let key_config = KeyConfig::derive(key_id, Kem::X25519Sha256, symmetric_suites, &key_seed)
            .map_err(map_ohttp_error)?;
        let encoded_config_list = KeyConfig::encode_list(&[&key_config]).map_err(map_ohttp_error)?;
        let server = Server::new(key_config).map_err(map_ohttp_error)?;

        Ok(Self {
            server,
            encoded_config_list,
        })
    }
}

#[event(fetch)]
pub async fn fetch(mut req: Request, env: Env, ctx: Context) -> Result<Response> {
    let path = req.path();

    if req.method() == Method::Options {
        return cors_preflight();
    }

    match (req.method(), path.as_str()) {
        (Method::Get, "/.well-known/ohttp-keys") => handle_well_known_ohttp_keys(&env).await,
        (Method::Get, "/ohttp-configs") => handle_ohttp_configs(&env).await,
        (Method::Post, "/") | (Method::Post, "/gateway") | (Method::Post, "/ohttp") => {
            handle_ohttp_gateway(&mut req, &env, &ctx).await
        }
        (Method::Get, p) if p == "/dashboard" || p.starts_with("/dashboard/") => {
            handle_dashboard()
        }
        (Method::Get, "/api/traces") => handle_api_traces(&req, &env).await,
        (Method::Get, "/api/summary") => handle_api_summary(&req, &env).await,
        (Method::Get, "/waitlist") => handle_waitlist_page(),
        (Method::Post, "/api/waitlist") => handle_waitlist_post(&mut req, &env).await,
        _ => Response::error("Not Found", 404),
    }
}

async fn handle_ohttp_configs(env: &Env) -> Result<Response> {
    let state = gateway_state(env).await?;
    let encoded = BASE64_STANDARD.encode(&state.encoded_config_list);

    let mut response = Response::ok(encoded)?;
    response
        .headers_mut()
        .set("content-type", "text/plain; charset=utf-8")?;
    response.headers_mut().set("cache-control", "no-store")?;
    response
        .headers_mut()
        .set("x-ohttp-media-type", "application/ohttp-keys")?;
    Ok(response)
}

async fn handle_well_known_ohttp_keys(env: &Env) -> Result<Response> {
    let state = gateway_state(env).await?;

    let mut response = Response::from_bytes(state.encoded_config_list.clone())?;
    response
        .headers_mut()
        .set("content-type", OHTTP_KEYS_CONTENT_TYPE)?;
    response.headers_mut().set("cache-control", "no-store")?;
    Ok(response)
}

fn cors_preflight() -> Result<Response> {
    let mut resp = Response::empty()?;
    resp.headers_mut().set("access-control-allow-origin", "*")?;
    resp.headers_mut().set("access-control-allow-methods", "GET, POST, OPTIONS")?;
    resp.headers_mut().set("access-control-allow-headers", "content-type")?;
    resp.headers_mut().set("access-control-max-age", "86400")?;
    Ok(resp)
}

fn with_cors(mut resp: Response) -> Result<Response> {
    resp.headers_mut().set("access-control-allow-origin", "*")?;
    Ok(resp)
}

fn handle_dashboard() -> Result<Response> {
    let mut resp = Response::from_html(DASHBOARD_HTML)?;
    resp.headers_mut().set("cache-control", "no-store")?;
    Ok(resp)
}

fn handle_waitlist_page() -> Result<Response> {
    let mut resp = Response::from_html(WAITLIST_HTML)?;
    resp.headers_mut().set("cache-control", "no-store")?;
    Ok(resp)
}

async fn handle_waitlist_post(req: &mut Request, env: &Env) -> Result<Response> {
    let body: serde_json::Value = match req.json().await {
        Ok(v) => v,
        Err(_) => return with_cors(Response::error("Invalid JSON", 400)?),
    };

    let email = match body.get("email").and_then(|v| v.as_str()) {
        Some(e) if e.contains('@') && e.len() > 3 => e.to_string(),
        _ => return with_cors(Response::error("Invalid email", 400)?),
    };

    let kv = env.kv("WAITLIST")
        .map_err(|e| Error::RustError(format!("KV binding WAITLIST not found: {e}")))?;
    let key = format!("waitlist:{}", email.to_lowercase());
    let ts = worker::Date::now().as_millis();
    let val = serde_json::json!({ "email": email, "ts": ts }).to_string();
    kv.put(&key, &val)?.execute().await?;

    console_log!("[waitlist] {}", email);
    with_cors(Response::ok("{\"ok\":true}")?)
}

async fn handle_api_traces(req: &Request, env: &Env) -> Result<Response> {
    let project = extract_query_param(req, "project");
    let project = match project {
        Some(p) if !p.is_empty() => p,
        _ => return with_cors(Response::error("Missing ?project= parameter", 400)?),
    };

    let db = env.d1("TELEMETRY_DB")
        .map_err(|e| Error::RustError(format!("D1 binding TELEMETRY_DB not found: {e}")))?;
    let traces = list_traces(&db, &project).await?;
    let json = serde_json::to_string(&traces)
        .map_err(|e| Error::RustError(format!("json serialize: {e}")))?;

    let mut resp = Response::ok(json)?;
    resp.headers_mut().set("content-type", "application/json; charset=utf-8")?;
    resp.headers_mut().set("cache-control", "no-store")?;
    with_cors(resp)
}

async fn handle_api_summary(req: &Request, env: &Env) -> Result<Response> {
    let project = extract_query_param(req, "project");
    let project = match project {
        Some(p) if !p.is_empty() => p,
        _ => return with_cors(Response::error("Missing ?project= parameter", 400)?),
    };

    let db = env.d1("TELEMETRY_DB")
        .map_err(|e| Error::RustError(format!("D1 binding TELEMETRY_DB not found: {e}")))?;
    let summary = compute_summary(&db, &project).await?;
    let json = serde_json::to_string(&summary)
        .map_err(|e| Error::RustError(format!("json serialize: {e}")))?;

    let mut resp = Response::ok(json)?;
    resp.headers_mut().set("content-type", "application/json; charset=utf-8")?;
    resp.headers_mut().set("cache-control", "no-store")?;
    with_cors(resp)
}

fn extract_query_param(req: &Request, name: &str) -> Option<String> {
    let url = req.url().ok()?;
    url.query_pairs().find(|(k, _)| k == name).map(|(_, v)| v.to_string())
}

async fn handle_ohttp_gateway(req: &mut Request, env: &Env, ctx: &Context) -> Result<Response> {
    let gateway_start = js_sys::Date::now() as u64;

    let expected_relay_token = read_secret_or_var(env, "RELAY_SHARED_TOKEN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let expected_relay_token = match expected_relay_token {
        Some(token) => token,
        None => {
            console_log!("relay allowlist is not configured: missing RELAY_SHARED_TOKEN");
            return Response::error("Gateway allowlist is not configured", 500);
        }
    };

    let inbound_relay_token = req
        .headers()
        .get(RELAY_ALLOWLIST_HEADER)?
        .unwrap_or_default()
        .trim()
        .to_string();
    if inbound_relay_token != expected_relay_token {
        console_log!(
            "blocked non-allowlisted request: missing or invalid {}",
            RELAY_ALLOWLIST_HEADER
        );
        return Response::error("Forbidden", 403);
    }

    let content_type = req
        .headers()
        .get("content-type")?
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !content_type.starts_with(OHTTP_REQ_CONTENT_TYPE) {
        return Response::error("Unsupported Content-Type, expected message/ohttp-req", 415);
    }

    let state = gateway_state(env).await?;
    let encapsulated_request = req.bytes().await?;
    let (decapsulated_request, server_response) = match state.server.decapsulate(&encapsulated_request) {
        Ok(parts) => parts,
        Err(e) => {
            console_log!("decapsulate failed: {:?}", e);
            return Response::error(
                format!("Failed to decapsulate OHTTP request: {e:?}"),
                400,
            )
        }
    };

    let parsed_request = match parse_decapsulated_bhttp_request(decapsulated_request) {
        Ok(parsed) => parsed,
        Err(ParsedRequestError::Unauthorized(message)) => {
            console_log!("missing authorization header in decapsulated BHTTP request");
            return encapsulate_error_response(server_response, 401, &message);
        }
        Err(ParsedRequestError::BadRequest(message)) => {
            console_log!("invalid decapsulated BHTTP request: {}", message);
            return encapsulate_error_response(server_response, 400, &message);
        }
    };

    let redacted_path = redact_sensitive_query_params(&parsed_request.path);
    let redacted_target_url = redact_sensitive_query_params(&parsed_request.target_url);
    console_log!(
        "bhttp parsed method={} path={} target={} content_type={} auth={} project_id={}",
        parsed_request.method.as_ref(),
        redacted_path,
        redacted_target_url,
        parsed_request
            .content_type
            .as_deref()
            .unwrap_or("<missing>"),
        redact_authorization(&parsed_request.authorization),
        parsed_request.project_id.as_deref().unwrap_or("<none>")
    );

    let project_id = parsed_request.project_id.clone();
    let session_id = parsed_request.session_id.clone().unwrap_or_default();
    let request_body = parsed_request.body.clone();
    let request_content_type = parsed_request.content_type.clone().unwrap_or_default();
    let request_path = redact_sensitive_query_params(&parsed_request.path);
    let request_target_url = parsed_request.target_url.clone();

    let upstream_start = js_sys::Date::now() as u64;

    let (binary_response, upstream_result) = match forward_parsed_request_with_telemetry(parsed_request).await {
        Ok(result) => (result.bhttp_encoded.clone(), Some(result)),
        Err(err) => {
            let fallback = build_error_bhttp_response(502, &format!("upstream error: {err}"))?;
            (fallback, None)
        }
    };

    let upstream_ms = (js_sys::Date::now() as u64).saturating_sub(upstream_start);
    let gateway_ms = (js_sys::Date::now() as u64).saturating_sub(gateway_start);

    // Fire-and-forget telemetry capture
    if let Some(ref pid) = project_id {
        if let Ok(db) = env.d1("TELEMETRY_DB") {
            let trace_id = generate_trace_id();

            let provider = infer_provider_from_url(&request_target_url);
            let (model, tool_results) = parse_request_telemetry(
                &request_body,
                &request_content_type,
            );

            let (cot_steps, tool_calls) = if let Some(ref result) = upstream_result {
                parse_response_telemetry(
                    &result.raw_body,
                    &result.content_type,
                    &provider,
                )
            } else {
                (vec![], vec![])
            };

            let status = match &upstream_result {
                Some(r) if r.status_code < 400 => "ok".to_string(),
                Some(_) | None => "error".to_string(),
            };

            let error_msg = match &upstream_result {
                Some(r) if r.status_code >= 400 => {
                    Some(format!("upstream returned {}", r.status_code))
                }
                None => Some("upstream request failed".to_string()),
                _ => None,
            };

            let record = TraceRecord {
                id: trace_id,
                project_id: pid.clone(),
                session_id: session_id.clone(),
                provider,
                model,
                path: request_path,
                timestamp_ms: gateway_start,
                timing: Timing { gateway_ms, upstream_ms },
                cot_steps,
                tool_calls,
                tool_results,
                status,
                error_msg,
            };

            ctx.wait_until(async move {
                if let Err(e) = store_trace(&db, &record).await {
                    console_log!("telemetry store error: {:?}", e);
                }
            });
        }
    }

    let encapsulated_response = server_response
        .encapsulate(&binary_response)
        .map_err(map_ohttp_error)?;
    ohttp_binary_response(encapsulated_response)
}

fn parse_decapsulated_bhttp_request(binary_http_request: Vec<u8>) -> std::result::Result<ParsedBhttpRequest, ParsedRequestError> {
    let mut cursor = Cursor::new(binary_http_request);
    let bhttp_request = Message::read_bhttp(&mut cursor)
        .map_err(|e| ParsedRequestError::BadRequest(format!("failed to decode BHTTP: {e:?}")))?;

    parse_bhttp_request(&bhttp_request)
}

fn parse_bhttp_request(message: &Message) -> std::result::Result<ParsedBhttpRequest, ParsedRequestError> {
    let (method_raw, scheme_raw, authority_raw, path_raw) = match message.control() {
        ControlData::Request {
            method,
            scheme,
            authority,
            path,
        } => (
            method.as_slice(),
            scheme.as_slice(),
            authority.as_slice(),
            path.as_slice(),
        ),
        ControlData::Response(_) => {
            return Err(ParsedRequestError::BadRequest(
                "decapsulated payload is an HTTP response, expected HTTP request".into(),
            ));
        }
    };

    let method = parse_http_method(method_raw).map_err(|e| ParsedRequestError::BadRequest(e.to_string()))?;
    let path = parse_utf8(path_raw, "request path")
        .map_err(|e| ParsedRequestError::BadRequest(e.to_string()))?;
    let scheme = parse_non_empty_utf8(scheme_raw, "request scheme")
        .map_err(|e| ParsedRequestError::BadRequest(e.to_string()))?;
    let authority = parse_non_empty_utf8(authority_raw, "request authority")
        .map_err(|e| ParsedRequestError::BadRequest(e.to_string()))?;

    let mut headers = Vec::new();
    let mut authorization = None;
    let mut content_type = None;
    let mut explicit_target = None;
    let mut project_id = None;
    let mut session_id = None;

    for field in message.header().fields() {
        let name = parse_utf8(field.name(), "request header name")
            .map_err(|e| ParsedRequestError::BadRequest(e.to_string()))?
            .to_ascii_lowercase();
        let value = parse_utf8(field.value(), "request header value")
            .map_err(|e| ParsedRequestError::BadRequest(e.to_string()))?;

        match name.as_str() {
            "authorization" => authorization = Some(value.clone()),
            "content-type" => content_type = Some(value.clone()),
            "x-ohttp-target" | "x-target-url" => explicit_target = Some(value.clone()),
            n if n == PROJECT_ID_HEADER => project_id = Some(value.clone()),
            n if n == SESSION_ID_HEADER => session_id = Some(value.clone()),
            _ => {}
        }

        // Don't forward internal claw-shield headers upstream
        if name.starts_with("x-claw-shield-") {
            continue;
        }

        if should_forward_request_header(&name) {
            headers.push((name, value));
        }
    }

    let authorization = authorization.ok_or_else(|| {
        ParsedRequestError::Unauthorized("Unauthorized: missing Authorization header".into())
    })?;
    headers.push(("authorization".into(), authorization.clone()));

    let target_url = resolve_target_url(explicit_target.as_deref(), scheme.as_deref(), authority.as_deref(), &path)
        .map_err(|e| ParsedRequestError::BadRequest(e.to_string()))?;

    Ok(ParsedBhttpRequest {
        method,
        path,
        target_url,
        content_type,
        authorization,
        headers,
        body: message.content().to_vec(),
        project_id,
        session_id,
    })
}

async fn forward_parsed_request_with_telemetry(parsed: ParsedBhttpRequest) -> Result<UpstreamResult> {
    let outbound_headers = Headers::new();
    for (name, value) in &parsed.headers {
        outbound_headers.append(name, value)?;
    }

    let mut init = RequestInit::new();
    init.with_method(parsed.method);
    init.with_headers(outbound_headers);
    if !parsed.body.is_empty() {
        init.with_body(Some(Uint8Array::from(parsed.body.as_slice()).into()));
    }

    let outbound_request = Request::new_with_init(&parsed.target_url, &init)?;
    let mut upstream_response = Fetch::Request(outbound_request).send().await?;

    let status_code = upstream_response.status_code();
    let content_type = upstream_response
        .headers()
        .get("content-type")?
        .unwrap_or_default();

    let raw_body = upstream_response.bytes().await?;

    let status = StatusCode::try_from(status_code)
        .map_err(|_| Error::RustError(format!("invalid HTTP status from upstream: {status_code}")))?;
    let mut message = Message::response(status);

    for (name, value) in upstream_response.headers().entries() {
        if should_drop_response_header(&name) {
            continue;
        }
        message.put_header(name.into_bytes(), value.into_bytes());
    }

    if !raw_body.is_empty() {
        message.write_content(&raw_body);
    }

    let mut encoded = Vec::new();
    message
        .write_bhttp(Mode::KnownLength, &mut encoded)
        .map_err(map_bhttp_error)?;

    Ok(UpstreamResult {
        bhttp_encoded: encoded,
        raw_body,
        content_type,
        status_code,
    })
}

fn generate_trace_id() -> String {
    let timestamp = js_sys::Date::now() as u64;
    let random_part = (js_sys::Math::random() * 1e12) as u64;
    format!("{:x}-{:x}", timestamp, random_part)
}

fn build_error_bhttp_response(status_code: u16, message_text: &str) -> Result<Vec<u8>> {
    let status = StatusCode::try_from(status_code)
        .map_err(|_| Error::RustError(format!("invalid status code for synthetic response: {status_code}")))?;

    let mut message = Message::response(status);
    message.put_header("content-type", "text/plain; charset=utf-8");
    message.write_content(message_text.as_bytes());

    let mut encoded = Vec::new();
    message
        .write_bhttp(Mode::KnownLength, &mut encoded)
        .map_err(map_bhttp_error)?;
    Ok(encoded)
}

fn ohttp_binary_response(encapsulated_response: Vec<u8>) -> Result<Response> {
    let mut response = Response::from_bytes(encapsulated_response)?;
    response.headers_mut().set("content-type", OHTTP_RES_CONTENT_TYPE)?;
    response.headers_mut().set("cache-control", "no-store")?;
    Ok(response)
}

async fn gateway_state(env: &Env) -> Result<&'static GatewayState> {
    GATEWAY_STATE
        .get_or_try_init(|| async { GatewayState::from_env(env) })
        .await
}

fn should_forward_request_header(name: &str) -> bool {
    !matches!(
        name,
        "authorization"
            |
        "connection"
            | "proxy-connection"
            | "host"
            | "content-length"
            | "transfer-encoding"
            | "upgrade"
            | "via"
            | "forwarded"
            | "x-forwarded-for"
            | "x-forwarded-proto"
            | "x-forwarded-host"
            | "x-real-ip"
            | "cf-connecting-ip"
            | "cf-ray"
            | "x-ohttp-target"
            | "x-target-url"
    )
}

fn encapsulate_error_response(
    server_response: ohttp::ServerResponse,
    status_code: u16,
    error_message: &str,
) -> Result<Response> {
    let bhttp_error = build_error_bhttp_response(status_code, error_message)?;
    let encapsulated = server_response.encapsulate(&bhttp_error).map_err(map_ohttp_error)?;
    ohttp_binary_response(encapsulated)
}

fn resolve_target_url(
    explicit_target: Option<&str>,
    scheme: Option<&str>,
    authority: Option<&str>,
    path: &str,
) -> Result<String> {
    if let Some(target) = explicit_target {
        if target.starts_with("https://") || target.starts_with("http://") {
            return Ok(target.to_string());
        }
        return Err(Error::RustError(
            "x-ohttp-target / x-target-url must be an absolute http(s) URL".into(),
        ));
    }

    if path.starts_with("https://") || path.starts_with("http://") {
        return Ok(path.to_string());
    }

    let normalized_path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };

    if let (Some(s), Some(a)) = (scheme, authority) {
        return Ok(format!("{s}://{a}{normalized_path}"));
    }

    Ok(format!("{DEFAULT_UPSTREAM_BASE_URL}{normalized_path}"))
}

fn redact_authorization(raw_authorization: &str) -> String {
    let trimmed = raw_authorization.trim();
    if trimmed.is_empty() {
        return "<empty>".into();
    }

    let lower = trimmed.to_ascii_lowercase();
    if !lower.starts_with("bearer ") {
        return "<non-bearer>".into();
    }

    let token = trimmed[7..].trim();
    if token.len() <= 8 {
        return "Bearer ****".into();
    }

    let prefix = &token[..4];
    let suffix = &token[token.len() - 4..];
    format!("Bearer {prefix}...{suffix}")
}

fn redact_sensitive_query_params(raw: &str) -> String {
    let Some((prefix, query)) = raw.split_once('?') else {
        return raw.to_string();
    };

    let redacted_query = query
        .split('&')
        .map(|part| {
            if part.is_empty() {
                return String::new();
            }

            let (name, value) = part.split_once('=').map_or((part, ""), |(n, v)| (n, v));
            if is_sensitive_query_param(name) {
                format!("{name}={}", redact_secret_keep_last4(value))
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("&");

    format!("{prefix}?{redacted_query}")
}

fn is_sensitive_query_param(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "key" | "api_key" | "openai_api_key" | "token" | "access_token"
    )
}

fn redact_secret_keep_last4(raw: &str) -> String {
    let value = raw.trim();
    if value.is_empty() {
        return "****".into();
    }

    let chars: Vec<char> = value.chars().collect();
    let visible: String = chars
        .iter()
        .rev()
        .take(4)
        .copied()
        .collect::<Vec<char>>()
        .into_iter()
        .rev()
        .collect();

    format!("****{visible}")
}

fn parse_non_empty_utf8(bytes: &[u8], field_name: &str) -> Result<Option<String>> {
    if bytes.is_empty() {
        return Ok(None);
    }

    Ok(Some(parse_utf8(bytes, field_name)?))
}

fn should_drop_response_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "connection" | "proxy-connection" | "content-length" | "transfer-encoding"
    )
}

fn parse_http_method(method_raw: &[u8]) -> Result<Method> {
    let method = parse_utf8(method_raw, "request method")?.to_ascii_uppercase();
    match method.as_str() {
        "GET" => Ok(Method::Get),
        "POST" => Ok(Method::Post),
        "PUT" => Ok(Method::Put),
        "PATCH" => Ok(Method::Patch),
        "DELETE" => Ok(Method::Delete),
        "HEAD" => Ok(Method::Head),
        "OPTIONS" => Ok(Method::Options),
        _ => Err(Error::RustError(format!(
            "unsupported HTTP method in Binary HTTP payload: {method}"
        ))),
    }
}

fn parse_utf8(bytes: &[u8], field_name: &str) -> Result<String> {
    std::str::from_utf8(bytes)
        .map(|s| s.to_string())
        .map_err(|_| Error::RustError(format!("invalid UTF-8 for {field_name}")))
}

fn read_secret_or_var(env: &Env, key: &str) -> Result<String> {
    match env.secret(key) {
        Ok(secret) => Ok(secret.to_string()),
        Err(_) => env.var(key).map(|value| value.to_string()),
    }
}

fn map_ohttp_error(err: ohttp::Error) -> Error {
    Error::RustError(format!("ohttp error: {err:?}"))
}

fn map_bhttp_error(err: bhttp::Error) -> Error {
    Error::RustError(format!("bhttp error: {err:?}"))
}
