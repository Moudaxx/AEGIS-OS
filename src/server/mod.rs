use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// ─── Request/Response Types ───
#[derive(Debug, Deserialize)]
pub struct ToolCallRequest {
    pub tool: String,
    pub params: Option<HashMap<String, String>>,
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
    pub layers: u8,
    pub tools: usize,
    pub ai_backends: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct MetricsResponse {
    pub agents_running: u64,
    pub inference_calls: u64,
    pub policy_blocked: u64,
    pub redteam_score: f64,
    pub uptime_secs: u64,
}

// ─── Shared App State ───
#[derive(Clone)]
pub struct AppState {
    pub tools: Arc<RwLock<Vec<ToolInfo>>>,
    pub valid_tokens: Arc<RwLock<Vec<String>>>,
    pub metrics: Arc<RwLock<ServerMetrics>>,
}

#[derive(Debug, Clone)]
pub struct ServerMetrics {
    pub requests_total: u64,
    pub requests_blocked: u64,
    pub tool_calls: u64,
    pub inference_calls: u64,
    pub policy_blocked: u64,
    pub started_at: std::time::Instant,
}

impl AppState {
    pub fn new() -> Self {
        let tools = vec![
            ToolInfo { name: "aegis.run_agent".into(), description: "Start a new agent".into() },
            ToolInfo { name: "aegis.stop_agent".into(), description: "Stop a running agent".into() },
            ToolInfo { name: "aegis.agent_status".into(), description: "Get agent status".into() },
            ToolInfo { name: "aegis.check_policy".into(), description: "Check if action is allowed".into() },
            ToolInfo { name: "aegis.risk_score".into(), description: "Get agent risk score".into() },
            ToolInfo { name: "aegis.audit_query".into(), description: "Query audit logs".into() },
            ToolInfo { name: "aegis.red_team".into(), description: "Start red team test".into() },
            ToolInfo { name: "aegis.list_tools".into(), description: "List available tools".into() },
        ];

        AppState {
            tools: Arc::new(RwLock::new(tools)),
            valid_tokens: Arc::new(RwLock::new(vec!["aegis-secret-token".into()])),
            metrics: Arc::new(RwLock::new(ServerMetrics {
                requests_total: 0,
                requests_blocked: 0,
                tool_calls: 0,
                inference_calls: 0,
                policy_blocked: 0,
                started_at: std::time::Instant::now(),
            })),
        }
    }
}

// ─── Auth Helper ───
fn check_auth(state: &AppState, token: &Option<String>) -> bool {
    match token {
        Some(t) => {
            let tokens = state.valid_tokens.read().unwrap();
            tokens.contains(t)
        }
        None => false,
    }
}

// ─── Handlers ───
async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let tools = state.tools.read().unwrap();
    Json(HealthResponse {
        status: "healthy".into(),
        version: "4.0.0".into(),
        layers: 12,
        tools: tools.len(),
        ai_backends: vec![
            "nvidia".into(), "claude".into(), "gemini".into(),
            "groq".into(), "openai".into(),
        ],
    })
}

async fn tools_list(State(state): State<AppState>) -> Json<ToolListResponse> {
    let tools = state.tools.read().unwrap();
    let total = tools.len();
    Json(ToolListResponse {
        tools: tools.clone(),
        total,
    })
}

async fn tools_call(
    State(state): State<AppState>,
    Json(req): Json<ToolCallRequest>,
) -> Result<Json<ToolCallResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Increment request count
    {
        let mut m = state.metrics.write().unwrap();
        m.requests_total += 1;
    }

    // Auth check
    if !check_auth(&state, &req.auth_token) {
        let mut m = state.metrics.write().unwrap();
        m.requests_blocked += 1;
        println!("[MCP-HTTP] 401: Unauthorized tool call attempt");
        return Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse {
            error: "Invalid or missing auth token".into(),
            code: 401,
        })));
    }

    // Input sanitization
    let dangerous = vec![
        "ignore previous", "system prompt", "admin override",
        "rm -rf", "drop table", "eval(",
    ];
    let tool_lower = req.tool.to_lowercase();
    for pattern in &dangerous {
        if tool_lower.contains(pattern) {
            let mut m = state.metrics.write().unwrap();
            m.policy_blocked += 1;
            println!("[MCP-HTTP] 403: Dangerous pattern in tool call: {}", pattern);
            return Err((StatusCode::FORBIDDEN, Json(ErrorResponse {
                error: format!("Blocked: dangerous pattern '{}'", pattern),
                code: 403,
            })));
        }
    }

    // Find tool
    let tools = state.tools.read().unwrap();
    let tool = tools.iter().find(|t| t.name == req.tool);

    match tool {
        Some(t) => {
            let mut m = state.metrics.write().unwrap();
            m.tool_calls += 1;
            println!("[MCP-HTTP] 200: Tool called: {} | Params: {:?}", t.name, req.params);
            Ok(Json(ToolCallResponse {
                success: true,
                tool: t.name.clone(),
                result: format!("Executed: {}", t.description),
            }))
        }
        None => {
            println!("[MCP-HTTP] 404: Tool not found: {}", req.tool);
            Err((StatusCode::NOT_FOUND, Json(ErrorResponse {
                error: format!("Tool '{}' not found", req.tool),
                code: 404,
            })))
        }
    }
}

async fn metrics(State(state): State<AppState>) -> String {
    let m = state.metrics.read().unwrap();
    let tools = state.tools.read().unwrap();
    let uptime = m.started_at.elapsed().as_secs();

    format!(
        "# HELP aegis_requests_total Total HTTP requests\n\
         # TYPE aegis_requests_total counter\n\
         aegis_requests_total {}\n\
         # HELP aegis_requests_blocked Blocked requests\n\
         # TYPE aegis_requests_blocked counter\n\
         aegis_requests_blocked {}\n\
         # HELP aegis_tool_calls_total Total tool calls\n\
         # TYPE aegis_tool_calls_total counter\n\
         aegis_tool_calls_total {}\n\
         # HELP aegis_policy_blocked Total policy blocks\n\
         # TYPE aegis_policy_blocked counter\n\
         aegis_policy_blocked {}\n\
         # HELP aegis_tools_available Available tools\n\
         # TYPE aegis_tools_available gauge\n\
         aegis_tools_available {}\n\
         # HELP aegis_uptime_seconds Server uptime\n\
         # TYPE aegis_uptime_seconds gauge\n\
         aegis_uptime_seconds {}\n",
        m.requests_total, m.requests_blocked, m.tool_calls,
        m.policy_blocked, tools.len(), uptime
    )
}

async fn version() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "name": "AEGIS OS",
        "version": "4.0.0",
        "layers": 12,
        "modules": 18,
        "ai_backends": ["nvidia", "claude", "gemini", "groq", "openai"],
        "protocols": ["MCP", "A2A", "REST"],
        "red_team_tests": 16,
        "security_tests": 75
    }))
}

// ─── Build Router ───
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/mcp/tools/list", post(tools_list))
        .route("/mcp/tools/call", post(tools_call))
        .route("/metrics", get(metrics))
        .with_state(state)
}

// ─── Start Server ───
pub async fn start_server(port: u16) {
    let state = AppState::new();
    let app = create_router(state);

    let addr = format!("0.0.0.0:{}", port);
    println!("[MCP-HTTP] Starting AEGIS MCP Server on {}", addr);
    println!("[MCP-HTTP] Endpoints:");
    println!("[MCP-HTTP]   GET  /health          — Health check");
    println!("[MCP-HTTP]   GET  /version          — Version info");
    println!("[MCP-HTTP]   POST /mcp/tools/list   — List tools");
    println!("[MCP-HTTP]   POST /mcp/tools/call   — Execute tool");
    println!("[MCP-HTTP]   GET  /metrics          — Prometheus metrics");

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}