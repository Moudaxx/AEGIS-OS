// Copyright (c) 2025 Mouda. All Rights Reserved. AGPL-3.0
//! AEGIS OS HTTP server: REST + MCP endpoints behind token auth and RBAC.
//!
//! Security model
//! - No built-in credentials. Tokens come from `AEGIS_{ADMIN,OPERATOR,VIEWER,AGENT}_TOKEN`
//!   (min 24 chars). If none are set, a random admin token is generated at startup.
//!   The old public demo tokens are only accepted with `AEGIS_DEMO_TOKENS=1`.
//! - Tokens are sent as `Authorization: Bearer <token>` (the legacy JSON
//!   `auth_token` field is still accepted) and stored only as SHA-256 hashes.
//! - Only `/health`, `/version` and `/metrics` are public.
//! - Prompts are never written to the audit log; only a fingerprint (hash + length).

pub mod filter;

use axum::{
    extract::{DefaultBodyLimit, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_BODY_BYTES: usize = 64 * 1024;
const MIN_TOKEN_LEN: usize = 24;
const AUDIT_FILE: &str = "aegis-audit.log";

// ═══ RBAC ═══
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum UserRole {
    Admin,
    Operator,
    Viewer,
    Agent,
}

#[derive(Debug, Clone, Copy)]
pub enum Permission {
    View,
    RunAgents,
    StopAgents,
    Inference,
    RedTeam,
    Tools,
}

impl UserRole {
    pub fn allows(&self, p: Permission) -> bool {
        use Permission::*;
        use UserRole::*;
        match p {
            View => true,
            RunAgents | StopAgents => matches!(self, Admin | Operator),
            Inference | Tools => matches!(self, Admin | Operator | Agent),
            RedTeam => matches!(self, Admin),
        }
    }
}

// ═══ Request/Response Types ═══
#[derive(Debug, Deserialize)]
pub struct ToolCallRequest {
    pub tool: String,
    pub params: Option<HashMap<String, String>>,
    pub auth_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RunAgentRequest {
    pub name: String,
    pub provider: Option<String>,
    pub auth_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct InferenceRequest {
    pub prompt: String,
    pub provider: Option<String>,
    pub auth_token: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct AuthRequest {
    pub auth_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ToolListResponse {
    pub tools: Vec<ToolInfo>,
    pub total: usize,
}

#[derive(Debug, Serialize, Clone)]
pub struct ToolInfo {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Serialize)]
pub struct ToolCallResponse {
    pub success: bool,
    pub tool: String,
    pub result: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: u16,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_secs: u64,
}

#[derive(Debug, Serialize, Clone)]
pub struct AgentInfo {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub status: String,
    pub risk_score: f64,
}

#[derive(Debug, Serialize)]
pub struct AgentListResponse {
    pub agents: Vec<AgentInfo>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct InferenceResponse {
    pub success: bool,
    pub provider: String,
    pub model: String,
    pub response: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct ProbeResult {
    pub name: String,
    pub category: String,
    pub expected: String,
    pub outcome: String,
    pub passed: bool,
}

#[derive(Debug, Serialize)]
pub struct RedTeamResponse {
    pub total_tests: usize,
    pub attacks_blocked: usize,
    pub attacks_total: usize,
    pub false_positives: usize,
    pub vulnerabilities: usize,
    pub score: String,
    pub results: Vec<ProbeResult>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEntry {
    pub timestamp: String,
    pub agent_id: String,
    pub event_type: String,
    pub action: String,
    pub result: String,
}

#[derive(Debug, Serialize)]
pub struct DashboardData {
    pub version: String,
    pub uptime_secs: u64,
    pub agents_running: usize,
    pub total_requests: u64,
    pub total_blocked: u64,
    pub inference_calls: u64,
    pub policy_blocked: u64,
    pub auth_denied: u64,
    pub redteam_scans: u64,
    pub redteam_score: String,
    pub recent_audit: Vec<AuditEntry>,
    pub providers: Vec<ProviderStatus>,
    pub roles: Vec<RoleInfo>,
}

#[derive(Debug, Serialize)]
pub struct ProviderStatus {
    pub name: String,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct RoleInfo {
    pub role: String,
    pub permissions: Vec<String>,
}

// ═══ Shared App State ═══
#[derive(Clone)]
pub struct AppState {
    pub tools: Arc<RwLock<Vec<ToolInfo>>>,
    pub agents: Arc<RwLock<Vec<AgentInfo>>>,
    pub audit_log: Arc<RwLock<Vec<AuditEntry>>>,
    /// SHA-256(token) → role. Raw tokens are never kept in memory after startup.
    token_hashes: Arc<RwLock<HashMap<[u8; 32], UserRole>>>,
    pub metrics: Arc<RwLock<ServerMetrics>>,
    audit_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ServerMetrics {
    pub requests_total: u64,
    pub requests_blocked: u64,
    pub tool_calls: u64,
    pub inference_calls: u64,
    pub policy_blocked: u64,
    pub agents_started: u64,
    pub agents_stopped: u64,
    pub redteam_scans: u64,
    pub redteam_last_score: Option<f64>,
    pub auth_denied: u64,
    pub started_at: std::time::Instant,
}

fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// 256 bits from the OS CSPRNG (via uuid v4 / getrandom).
pub fn generate_token() -> String {
    format!(
        "aegis_{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// Short, non-reversible description of a prompt for audit logs.
pub fn prompt_fingerprint(prompt: &str) -> String {
    let h = Sha256::digest(prompt.as_bytes());
    let hex: String = h.iter().take(6).map(|b| format!("{:02x}", b)).collect();
    format!("prompt[sha256:{} len:{}]", hex, prompt.chars().count())
}

/// Load tokens from the environment. Returns (tokens, generated_admin_token).
fn tokens_from_env() -> (Vec<(String, UserRole)>, Option<String>) {
    let mut tokens = Vec::new();
    for (var, role) in [
        ("AEGIS_ADMIN_TOKEN", UserRole::Admin),
        ("AEGIS_OPERATOR_TOKEN", UserRole::Operator),
        ("AEGIS_VIEWER_TOKEN", UserRole::Viewer),
        ("AEGIS_AGENT_TOKEN", UserRole::Agent),
    ] {
        if let Ok(t) = std::env::var(var) {
            let t = t.trim().to_string();
            if t.len() < MIN_TOKEN_LEN {
                eprintln!("[AUTH] {} ignored: must be at least {} characters", var, MIN_TOKEN_LEN);
                continue;
            }
            tokens.push((t, role));
        }
    }

    if std::env::var("AEGIS_DEMO_TOKENS").as_deref() == Ok("1") {
        eprintln!("[AUTH] WARNING: AEGIS_DEMO_TOKENS=1 — public demo tokens enabled. Never use in production.");
        tokens.push(("aegis-admin-token".into(), UserRole::Admin));
        tokens.push(("aegis-operator-token".into(), UserRole::Operator));
        tokens.push(("aegis-viewer-token".into(), UserRole::Viewer));
        tokens.push(("aegis-agent-token".into(), UserRole::Agent));
    }

    if tokens.is_empty() {
        let t = generate_token();
        tokens.push((t.clone(), UserRole::Admin));
        return (tokens, Some(t));
    }
    (tokens, None)
}

fn default_tools() -> Vec<ToolInfo> {
    [
        ("aegis.run_agent", "Start a new agent"),
        ("aegis.stop_agent", "Stop a running agent"),
        ("aegis.agent_status", "Get agent status"),
        ("aegis.check_policy", "Check if action is allowed"),
        ("aegis.risk_score", "Get agent risk score"),
        ("aegis.audit_query", "Query audit logs"),
        ("aegis.red_team", "Start red team test"),
        ("aegis.list_tools", "List available tools"),
    ]
    .iter()
    .map(|(n, d)| ToolInfo { name: (*n).into(), description: (*d).into() })
    .collect()
}

impl AppState {
    /// Build state from the environment, persisting audit events to `aegis-audit.log`.
    pub fn from_env() -> (Self, Option<String>) {
        let (tokens, generated) = tokens_from_env();
        let state = Self::with_tokens(tokens, Some(PathBuf::from(AUDIT_FILE)));
        (state, generated)
    }

    /// Build state with explicit tokens. `audit_path = None` keeps the audit log in memory.
    pub fn with_tokens(tokens: Vec<(String, UserRole)>, audit_path: Option<PathBuf>) -> Self {
        let existing_audit = audit_path.as_deref().map(load_audit_from_file).unwrap_or_default();
        if !existing_audit.is_empty() {
            println!("[AUDIT] Loaded {} events from {}", existing_audit.len(), AUDIT_FILE);
        }
        let hashes = tokens.iter().map(|(t, r)| (hash_token(t), *r)).collect();

        AppState {
            tools: Arc::new(RwLock::new(default_tools())),
            agents: Arc::new(RwLock::new(Vec::new())),
            audit_log: Arc::new(RwLock::new(existing_audit)),
            token_hashes: Arc::new(RwLock::new(hashes)),
            metrics: Arc::new(RwLock::new(ServerMetrics {
                requests_total: 0,
                requests_blocked: 0,
                tool_calls: 0,
                inference_calls: 0,
                policy_blocked: 0,
                agents_started: 0,
                agents_stopped: 0,
                redteam_scans: 0,
                redteam_last_score: None,
                auth_denied: 0,
                started_at: std::time::Instant::now(),
            })),
            audit_path,
        }
    }

    fn log_audit(&self, agent_id: &str, event_type: &str, action: &str, result: &str) {
        let entry = AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            agent_id: agent_id.into(),
            event_type: event_type.into(),
            action: action.into(),
            result: result.into(),
        };
        if let Some(path) = &self.audit_path {
            if let Err(e) = append_to_file(path, &entry) {
                eprintln!("[AUDIT] Failed to persist event: {}", e);
            }
        }
        self.audit_log.write().unwrap().push(entry);
    }
}

fn append_to_file(path: &std::path::Path, entry: &AuditEntry) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    writeln!(file, "{}", serde_json::to_string(entry).unwrap_or_default())
}

fn load_audit_from_file(path: &std::path::Path) -> Vec<AuditEntry> {
    std::fs::read_to_string(path)
        .map(|c| c.lines().filter_map(|l| serde_json::from_str(l).ok()).collect())
        .unwrap_or_default()
}

// ═══ Auth + RBAC ═══
type ApiError = (StatusCode, Json<ErrorResponse>);

fn api_error(code: StatusCode, msg: impl Into<String>) -> ApiError {
    (code, Json(ErrorResponse { error: msg.into(), code: code.as_u16() }))
}

/// Prefer `Authorization: Bearer`, fall back to the legacy body field.
fn extract_token(headers: &HeaderMap, body_token: Option<&str>) -> Option<String> {
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")))
        .map(|t| t.trim().to_string())
        .or_else(|| body_token.map(String::from))
}

fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    body_token: Option<&str>,
    perm: Permission,
) -> Result<UserRole, ApiError> {
    let role = extract_token(headers, body_token)
        .and_then(|t| state.token_hashes.read().unwrap().get(&hash_token(&t)).copied());

    let Some(role) = role else {
        state.metrics.write().unwrap().auth_denied += 1;
        state.log_audit("unknown", "Auth", "Authentication failed", "DENIED");
        return Err(api_error(StatusCode::UNAUTHORIZED, "Invalid or missing auth token"));
    };
    if !role.allows(perm) {
        state.metrics.write().unwrap().auth_denied += 1;
        state.log_audit("unknown", "Auth", &format!("{:?} lacks {:?}", role, perm), "FORBIDDEN");
        return Err(api_error(StatusCode::FORBIDDEN, format!("Role {:?} cannot {:?}", role, perm)));
    }
    Ok(role)
}

fn block_input(state: &AppState, event: &str, input: &str) -> Result<(), ApiError> {
    match filter::check(input) {
        filter::FilterVerdict::Allow => Ok(()),
        filter::FilterVerdict::Block(reason) => {
            {
                let mut m = state.metrics.write().unwrap();
                m.policy_blocked += 1;
                m.requests_blocked += 1;
            }
            state.log_audit("system", event, &prompt_fingerprint(input), &format!("BLOCKED: {}", reason));
            Err(api_error(StatusCode::FORBIDDEN, format!("Blocked: {}", reason)))
        }
    }
}

// ═══ Handlers ═══

// GET /health
async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let m = state.metrics.read().unwrap();
    Json(HealthResponse {
        status: "healthy".into(),
        version: VERSION.into(),
        uptime_secs: m.started_at.elapsed().as_secs(),
    })
}

// GET /version
async fn version() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "name": "AEGIS OS",
        "version": VERSION,
        "ai_backends": ["nvidia", "claude", "gemini", "groq", "openai"],
        "protocols": ["MCP", "A2A", "REST"],
        "rbac_roles": ["admin", "operator", "viewer", "agent"]
    }))
}

// GET /api/v1/dashboard
async fn dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<DashboardData>, ApiError> {
    authorize(&state, &headers, None, Permission::View)?;
    let m = state.metrics.read().unwrap();
    let agents = state.agents.read().unwrap();
    let audit = state.audit_log.read().unwrap();
    let recent: Vec<AuditEntry> = audit.iter().rev().take(10).cloned().collect();

    let providers = [
        ("nvidia", "NVIDIA_NIM_API_KEY"),
        ("groq", "GROQ_API_KEY"),
        ("openai", "OPENAI_API_KEY"),
        ("gemini", "GOOGLE_AI_API_KEY"),
        ("claude", "ANTHROPIC_API_KEY"),
    ]
    .iter()
    .map(|(name, var)| ProviderStatus {
        name: (*name).into(),
        status: if std::env::var(var).is_ok() { "configured" } else { "not configured" }.into(),
    })
    .collect();

    let perms = |r: UserRole| -> Vec<String> {
        use Permission::*;
        [View, RunAgents, StopAgents, Inference, RedTeam, Tools]
            .into_iter()
            .filter(|p| r.allows(*p))
            .map(|p| format!("{:?}", p))
            .collect()
    };
    let roles = [UserRole::Admin, UserRole::Operator, UserRole::Viewer, UserRole::Agent]
        .into_iter()
        .map(|r| RoleInfo { role: format!("{:?}", r).to_lowercase(), permissions: perms(r) })
        .collect();

    Ok(Json(DashboardData {
        version: VERSION.into(),
        uptime_secs: m.started_at.elapsed().as_secs(),
        agents_running: agents.len(),
        total_requests: m.requests_total,
        total_blocked: m.requests_blocked,
        inference_calls: m.inference_calls,
        policy_blocked: m.policy_blocked,
        auth_denied: m.auth_denied,
        redteam_scans: m.redteam_scans,
        redteam_score: m
            .redteam_last_score
            .map(|s| format!("{:.0}%", s * 100.0))
            .unwrap_or_else(|| "not run".into()),
        recent_audit: recent,
        providers,
        roles,
    }))
}

// POST /mcp/tools/list
async fn tools_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ToolListResponse>, ApiError> {
    authorize(&state, &headers, None, Permission::View)?;
    let tools = state.tools.read().unwrap();
    Ok(Json(ToolListResponse { tools: tools.clone(), total: tools.len() }))
}

// POST /mcp/tools/call
async fn tools_call(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ToolCallRequest>,
) -> Result<Json<ToolCallResponse>, ApiError> {
    state.metrics.write().unwrap().requests_total += 1;
    let role = authorize(&state, &headers, req.auth_token.as_deref(), Permission::Tools)?;

    block_input(&state, "ToolCall", &req.tool)?;
    if let Some(params) = &req.params {
        for v in params.values() {
            block_input(&state, "ToolCall", v)?;
        }
    }

    let found = state.tools.read().unwrap().iter().find(|t| t.name == req.tool).cloned();
    match found {
        Some(t) => {
            state.metrics.write().unwrap().tool_calls += 1;
            state.log_audit("system", "ToolCall", &format!("{} (role: {:?})", t.name, role), "SUCCESS");
            Ok(Json(ToolCallResponse {
                success: true,
                tool: t.name,
                result: format!("Executed: {}", t.description),
            }))
        }
        None => Err(api_error(StatusCode::NOT_FOUND, format!("Tool '{}' not found", req.tool))),
    }
}

// POST /api/v1/agents/run
async fn agents_run(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RunAgentRequest>,
) -> Result<Json<AgentInfo>, ApiError> {
    state.metrics.write().unwrap().requests_total += 1;
    let role = authorize(&state, &headers, req.auth_token.as_deref(), Permission::RunAgents)?;
    block_input(&state, "AgentStart", &req.name)?;
    if req.name.chars().count() > 128 {
        return Err(api_error(StatusCode::BAD_REQUEST, "Agent name too long (max 128)"));
    }

    let provider = req.provider.unwrap_or_else(|| "groq".into());
    if model_for(&provider).is_none() {
        return Err(api_error(StatusCode::BAD_REQUEST, format!("Unknown provider: {}", provider)));
    }
    let agent = AgentInfo {
        id: uuid::Uuid::new_v4().to_string(),
        name: req.name.clone(),
        provider: provider.clone(),
        status: "running".into(),
        risk_score: 0.0,
    };

    state.agents.write().unwrap().push(agent.clone());
    state.metrics.write().unwrap().agents_started += 1;
    state.log_audit(&agent.id, "AgentStart", &format!("{} with {} (role: {:?})", req.name, provider, role), "SUCCESS");
    Ok(Json(agent))
}

// GET /api/v1/agents
async fn agents_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AgentListResponse>, ApiError> {
    authorize(&state, &headers, None, Permission::View)?;
    let agents = state.agents.read().unwrap();
    Ok(Json(AgentListResponse { total: agents.len(), agents: agents.clone() }))
}

// POST /api/v1/agents/stop
async fn agents_stop(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Option<Json<AuthRequest>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let role = authorize(&state, &headers, body.auth_token.as_deref(), Permission::StopAgents)?;

    let count = {
        let mut agents = state.agents.write().unwrap();
        let n = agents.len();
        agents.clear();
        n
    };
    state.metrics.write().unwrap().agents_stopped += count as u64;
    state.log_audit("system", "AgentStop", &format!("Stopped {} (role: {:?})", count, role), "SUCCESS");
    Ok(Json(serde_json::json!({ "stopped": count })))
}

fn model_for(provider: &str) -> Option<&'static str> {
    Some(match provider {
        "nvidia" => "meta/llama-3.1-8b-instruct",
        "claude" => "claude-haiku-4-5-20251001",
        "gemini" => "gemini-2.5-flash-lite",
        "groq" => "llama-3.3-70b-versatile",
        "openai" => "gpt-4o-mini",
        _ => return None,
    })
}

// POST /api/v1/inference — Real AI call
async fn inference(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<InferenceRequest>,
) -> Result<Json<InferenceResponse>, ApiError> {
    state.metrics.write().unwrap().requests_total += 1;
    let role = authorize(&state, &headers, req.auth_token.as_deref(), Permission::Inference)?;
    block_input(&state, "Inference", &req.prompt)?;

    let provider = req.provider.clone().unwrap_or_else(|| "groq".into());
    let model = model_for(&provider)
        .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, format!("Unknown provider: {}", provider)))?;

    let env_key = |v: &str| std::env::var(v).unwrap_or_default();
    let ai_response = match provider.as_str() {
        "groq" => call_openai_compatible("https://api.groq.com/openai/v1/chat/completions", &env_key("GROQ_API_KEY"), model, &req.prompt).await,
        "openai" => call_openai_compatible("https://api.openai.com/v1/chat/completions", &env_key("OPENAI_API_KEY"), model, &req.prompt).await,
        "nvidia" => call_openai_compatible("https://integrate.api.nvidia.com/v1/chat/completions", &env_key("NVIDIA_NIM_API_KEY"), model, &req.prompt).await,
        "gemini" => call_gemini_backend(&env_key("GOOGLE_AI_API_KEY"), model, &req.prompt).await,
        "claude" => call_claude_backend(&env_key("ANTHROPIC_API_KEY"), model, &req.prompt).await,
        _ => unreachable!("provider validated by model_for"),
    };
    state.metrics.write().unwrap().inference_calls += 1;
    let fp = prompt_fingerprint(&req.prompt);
    match ai_response {
        Ok(response) => {
            state.log_audit("system", "Inference", &format!("{}: {} (role: {:?})", provider, fp, role), "SUCCESS");
            Ok(Json(InferenceResponse { success: true, provider, model: model.into(), response }))
        }
        Err(e) => {
            state.log_audit("system", "Inference", &format!("{}: {}", provider, fp), "FAILED");
            Ok(Json(InferenceResponse { success: false, provider, model: model.into(), response: format!("Error: {}", e) }))
        }
    }
}

// ─── AI Backend Helpers ───
fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client")
    })
}

/// Upstream errors can echo request data; keep only a short, safe summary.
fn upstream_error(e: impl std::fmt::Display) -> String {
    let s = e.to_string();
    s.chars().take(200).collect()
}

async fn call_openai_compatible(url: &str, key: &str, model: &str, prompt: &str) -> Result<String, String> {
    if key.is_empty() {
        return Err("API key not configured".into());
    }
    let body = serde_json::json!({"model": model, "messages": [{"role": "user", "content": prompt}], "max_tokens": 1024});
    let resp = http_client()
        .post(url)
        .bearer_auth(key)
        .json(&body)
        .send()
        .await
        .map_err(upstream_error)?
        .json::<serde_json::Value>()
        .await
        .map_err(upstream_error)?;
    if let Some(err) = resp.get("error") {
        return Err(format!("API error: {}", upstream_error(err)));
    }
    resp["choices"][0]["message"]["content"].as_str().map(String::from).ok_or_else(|| "No response".into())
}

async fn call_gemini_backend(key: &str, model: &str, prompt: &str) -> Result<String, String> {
    if key.is_empty() {
        return Err("API key not configured".into());
    }
    // Key goes in a header, not the URL, so it never lands in proxy/access logs.
    let url = format!("https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent", model);
    let body = serde_json::json!({"contents": [{"parts": [{"text": prompt}]}]});
    let resp = http_client()
        .post(&url)
        .header("x-goog-api-key", key)
        .json(&body)
        .send()
        .await
        .map_err(upstream_error)?
        .json::<serde_json::Value>()
        .await
        .map_err(upstream_error)?;
    if let Some(err) = resp.get("error") {
        return Err(upstream_error(err));
    }
    resp["candidates"][0]["content"]["parts"][0]["text"].as_str().map(String::from).ok_or_else(|| "No response".into())
}

async fn call_claude_backend(key: &str, model: &str, prompt: &str) -> Result<String, String> {
    if key.is_empty() {
        return Err("API key not configured".into());
    }
    let body = serde_json::json!({"model": model, "max_tokens": 1024, "messages": [{"role": "user", "content": prompt}]});
    let resp = http_client()
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", key)
        .header("anthropic-version", "2023-06-01")
        .json(&body)
        .send()
        .await
        .map_err(upstream_error)?
        .json::<serde_json::Value>()
        .await
        .map_err(upstream_error)?;
    if let Some(err) = resp.get("error") {
        return Err(upstream_error(err));
    }
    resp["content"][0]["text"].as_str().map(String::from).ok_or_else(|| "No response".into())
}

// POST /api/v1/redteam — runs the real attack corpus against the live input filter
async fn redteam(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Option<Json<AuthRequest>>,
) -> Result<Json<RedTeamResponse>, ApiError> {
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let role = authorize(&state, &headers, body.auth_token.as_deref(), Permission::RedTeam)?;

    let report = run_redteam();
    {
        let mut m = state.metrics.write().unwrap();
        m.redteam_scans += 1;
        m.redteam_last_score = Some(report.passed_ratio());
    }
    state.log_audit(
        "system",
        "RedTeam",
        &format!("{} probes (role: {:?})", report.response.total_tests, role),
        &format!("score {}", report.response.score),
    );
    Ok(Json(report.response))
}

struct RedTeamRun {
    response: RedTeamResponse,
}

impl RedTeamRun {
    fn passed_ratio(&self) -> f64 {
        let r = &self.response;
        let passed = r.results.iter().filter(|p| p.passed).count();
        passed as f64 / r.total_tests.max(1) as f64
    }
}

fn run_redteam() -> RedTeamRun {
    let results: Vec<ProbeResult> = filter::redteam_corpus()
        .into_iter()
        .map(|p| {
            let blocked = matches!(filter::check(&p.payload), filter::FilterVerdict::Block(_));
            ProbeResult {
                name: p.name.into(),
                category: p.category.into(),
                expected: if p.expect_block { "block" } else { "allow" }.into(),
                outcome: if blocked { "blocked" } else { "allowed" }.into(),
                passed: blocked == p.expect_block,
            }
        })
        .collect();

    let attacks_total = results.iter().filter(|r| r.expected == "block").count();
    let attacks_blocked = results.iter().filter(|r| r.expected == "block" && r.passed).count();
    let false_positives = results.iter().filter(|r| r.expected == "allow" && !r.passed).count();
    let passed = results.iter().filter(|r| r.passed).count();
    let total = results.len();
    RedTeamRun {
        response: RedTeamResponse {
            total_tests: total,
            attacks_blocked,
            attacks_total,
            false_positives,
            vulnerabilities: attacks_total - attacks_blocked,
            score: format!("{:.0}%", passed as f64 / total.max(1) as f64 * 100.0),
            results,
        },
    }
}

// GET /api/v1/audit
async fn audit(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AuditEntry>>, ApiError> {
    authorize(&state, &headers, None, Permission::View)?;
    let log = state.audit_log.read().unwrap();
    // Most recent 1000 events — keeps responses bounded.
    let start = log.len().saturating_sub(1000);
    Ok(Json(log[start..].to_vec()))
}

// GET /metrics (Prometheus; aggregate counters only, no secrets)
async fn metrics(State(state): State<AppState>) -> String {
    let m = state.metrics.read().unwrap();
    let tools = state.tools.read().unwrap().len();
    let agents = state.agents.read().unwrap().len();
    let audit = state.audit_log.read().unwrap().len();
    let score = m.redteam_last_score.map(|s| s * 100.0).unwrap_or(0.0);
    let rows: [(&str, &str, String); 15] = [
        ("aegis_requests_total", "counter", m.requests_total.to_string()),
        ("aegis_requests_blocked", "counter", m.requests_blocked.to_string()),
        ("aegis_tool_calls_total", "counter", m.tool_calls.to_string()),
        ("aegis_inference_calls_total", "counter", m.inference_calls.to_string()),
        ("aegis_policy_blocked", "counter", m.policy_blocked.to_string()),
        ("aegis_auth_denied_total", "counter", m.auth_denied.to_string()),
        ("aegis_agents_started_total", "counter", m.agents_started.to_string()),
        ("aegis_agents_stopped_total", "counter", m.agents_stopped.to_string()),
        ("aegis_agents_running", "gauge", agents.to_string()),
        ("aegis_tools_available", "gauge", tools.to_string()),
        ("aegis_redteam_scans_total", "counter", m.redteam_scans.to_string()),
        ("aegis_redteam_score", "gauge", format!("{:.1}", score)),
        ("aegis_audit_events_total", "gauge", audit.to_string()),
        ("aegis_uptime_seconds", "gauge", m.started_at.elapsed().as_secs().to_string()),
        ("aegis_build_info", "gauge", "1".to_string()),
    ];
    let mut out = String::new();
    for (name, kind, val) in rows {
        if name == "aegis_build_info" {
            out.push_str(&format!("# TYPE {} {}\n{}{{version=\"{}\"}} {}\n", name, kind, name, VERSION, val));
        } else {
            out.push_str(&format!("# TYPE {} {}\n{} {}\n", name, kind, name, val));
        }
    }
    out
}

// ═══ Router ═══
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/metrics", get(metrics))
        .route("/mcp/tools/list", post(tools_list))
        .route("/mcp/tools/call", post(tools_call))
        .route("/api/v1/agents/run", post(agents_run))
        .route("/api/v1/agents/stop", post(agents_stop))
        .route("/api/v1/agents", get(agents_list))
        .route("/api/v1/inference", post(inference))
        .route("/api/v1/redteam", post(redteam))
        .route("/api/v1/audit", get(audit))
        .route("/api/v1/dashboard", get(dashboard))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

fn bind_addr(port: u16) -> String {
    let host = std::env::var("AEGIS_BIND").unwrap_or_else(|_| "0.0.0.0".into());
    format!("{}:{}", host, port)
}

fn print_banner(scheme: &str, addr: &str, generated: &Option<String>) {
    println!("⛊ AEGIS OS v{} — {} Server + RBAC", VERSION, scheme.to_uppercase());
    println!("═══════════════════════════════════════════");
    println!("[SERVER] Listening on {}://{}", scheme, addr);
    match generated {
        Some(t) => {
            println!("[AUTH] No AEGIS_*_TOKEN configured — generated a one-time admin token:");
            println!("[AUTH]   {}", t);
            println!("[AUTH] Set AEGIS_ADMIN_TOKEN to keep a stable token across restarts.");
        }
        None => println!("[AUTH] Tokens loaded from environment."),
    }
    println!("[AUTH] Send as header: Authorization: Bearer <token>");
    println!("[SERVER] Public: /health /version /metrics — everything else requires a token");
    println!("═══════════════════════════════════════════");
}

// ═══ Start Server ═══
pub async fn start_server(port: u16) {
    let (state, generated) = AppState::from_env();
    let app = create_router(state);
    let addr = bind_addr(port);
    print_banner("http", &addr, &generated);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {}: {}", addr, e));
    axum::serve(listener, app).await.expect("server error");
}

// ═══ Start TLS Server ═══
pub async fn start_tls_server(port: u16) {
    let cert_path = std::env::var("AEGIS_TLS_CERT").unwrap_or_else(|_| "certs/cert.pem".into());
    let key_path = std::env::var("AEGIS_TLS_KEY").unwrap_or_else(|_| "certs/key.pem".into());

    // Fail closed: a TLS request must never silently become plaintext HTTP.
    if !std::path::Path::new(&cert_path).exists() || !std::path::Path::new(&key_path).exists() {
        eprintln!("[SERVER] TLS cert/key not found ({} / {}). Refusing to start.", cert_path, key_path);
        eprintln!("[SERVER] Generate with:");
        eprintln!("[SERVER]   mkdir -p certs && openssl req -x509 -newkey rsa:2048 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes -subj /CN=localhost");
        std::process::exit(1);
    }

    let (state, generated) = AppState::from_env();
    let app = create_router(state);
    let addr = bind_addr(port);
    print_banner("https", &addr, &generated);

    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
        .await
        .expect("Failed to load TLS config");
    let sock: std::net::SocketAddr = addr.parse().expect("invalid AEGIS_BIND address");
    axum_server::bind_rustls(sock, tls_config)
        .serve(app.into_make_service())
        .await
        .expect("server error");
}

#[cfg(test)]
mod tests;
