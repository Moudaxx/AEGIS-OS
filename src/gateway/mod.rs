use std::collections::HashMap;
use std::time::Instant;
use uuid::Uuid;

// ─── API Request ───
#[derive(Debug, Clone)]
pub struct ApiRequest {
    pub id: String,
    pub method: String,
    pub path: String,
    pub auth_token: Option<String>,
    pub agent_id: Option<String>,
    pub body: Option<String>,
    pub timestamp: Instant,
}

impl ApiRequest {
    pub fn new(method: &str, path: &str) -> Self {
        ApiRequest {
            id: format!("req-{}", Uuid::new_v4()),
            method: method.to_string(),
            path: path.to_string(),
            auth_token: None,
            agent_id: None,
            body: None,
            timestamp: Instant::now(),
        }
    }

    pub fn with_auth(mut self, token: &str) -> Self {
        self.auth_token = Some(token.to_string());
        self
    }

    pub fn with_agent(mut self, agent_id: &str) -> Self {
        self.agent_id = Some(agent_id.to_string());
        self
    }

    pub fn with_body(mut self, body: &str) -> Self {
        self.body = Some(body.to_string());
        self
    }
}

// ─── API Response ───
#[derive(Debug)]
pub struct ApiResponse {
    pub status: u16,
    pub body: String,
    pub request_id: String,
}

impl ApiResponse {
    pub fn ok(request_id: &str, body: &str) -> Self {
        ApiResponse { status: 200, body: body.to_string(), request_id: request_id.to_string() }
    }
    pub fn unauthorized(request_id: &str) -> Self {
        ApiResponse { status: 401, body: "Unauthorized".to_string(), request_id: request_id.to_string() }
    }
    pub fn forbidden(request_id: &str, reason: &str) -> Self {
        ApiResponse { status: 403, body: format!("Forbidden: {}", reason), request_id: request_id.to_string() }
    }
    pub fn rate_limited(request_id: &str) -> Self {
        ApiResponse { status: 429, body: "Rate limit exceeded".to_string(), request_id: request_id.to_string() }
    }
    pub fn not_found(request_id: &str) -> Self {
        ApiResponse { status: 404, body: "Not found".to_string(), request_id: request_id.to_string() }
    }
}

// ─── Route ───
#[derive(Debug, Clone)]
pub struct Route {
    pub method: String,
    pub path: String,
    pub description: String,
    pub auth_required: bool,
    pub rate_limit: u32,
}

// ─── Rate Limiter ───
struct RateLimiter {
    requests: HashMap<String, Vec<Instant>>,
    window_secs: u64,
}

impl RateLimiter {
    fn new(window_secs: u64) -> Self {
        RateLimiter {
            requests: HashMap::new(),
            window_secs,
        }
    }

    fn check(&mut self, key: &str, max_requests: u32) -> bool {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs);
        let entries = self.requests.entry(key.to_string()).or_default();

        entries.retain(|t| now.duration_since(*t) < window);

        if entries.len() >= max_requests as usize {
            println!("[GATEWAY] Rate limited: {} ({}/{})", key, entries.len(), max_requests);
            return false;
        }
        entries.push(now);
        true
    }
}

// ─── API Gateway ───
pub struct ApiGateway {
    port: u16,
    routes: Vec<Route>,
    valid_tokens: Vec<String>,
    rate_limiter: RateLimiter,
    request_count: u64,
    blocked_count: u64,
    running: bool,
}

impl ApiGateway {
    pub fn new(port: u16) -> Self {
        let mut gw = ApiGateway {
            port,
            routes: Vec::new(),
            valid_tokens: Vec::new(),
            rate_limiter: RateLimiter::new(60),
            request_count: 0,
            blocked_count: 0,
            running: false,
        };
        gw.register_defaults();
        gw
    }

    fn register_defaults(&mut self) {
        let routes = vec![
            ("POST", "/api/v1/agents/run", "Start a new agent", true, 30),
            ("POST", "/api/v1/agents/stop", "Stop an agent", true, 30),
            ("GET", "/api/v1/agents", "List all agents", true, 60),
            ("GET", "/api/v1/agents/:id/status", "Agent status", true, 60),
            ("GET", "/api/v1/agents/:id/risk", "Agent risk score", true, 60),
            ("POST", "/api/v1/inference", "AI inference request", true, 60),
            ("POST", "/api/v1/tools/call", "Call a tool", true, 30),
            ("GET", "/api/v1/audit", "Query audit logs", true, 30),
            ("POST", "/api/v1/redteam/start", "Start red team scan", true, 10),
            ("GET", "/api/v1/health", "Health check", false, 120),
            ("GET", "/api/v1/version", "Version info", false, 120),
        ];

        for (method, path, desc, auth, rate) in routes {
            self.routes.push(Route {
                method: method.to_string(),
                path: path.to_string(),
                description: desc.to_string(),
                auth_required: auth,
                rate_limit: rate,
            });
        }
    }

    pub fn add_token(&mut self, token: &str) {
        self.valid_tokens.push(token.to_string());
    }

    pub fn start(&mut self) {
        self.running = true;
        println!("[GATEWAY] API Gateway started | Port: {} | Routes: {} | Auth tokens: {}",
            self.port, self.routes.len(), self.valid_tokens.len());
    }

    pub fn handle(&mut self, req: ApiRequest) -> ApiResponse {
        self.request_count += 1;

        if !self.running {
            return ApiResponse::forbidden(&req.id, "Gateway not running");
        }

        // Find matching route
        let route = match self.routes.iter().find(|r|
            r.method == req.method && self.path_matches(&r.path, &req.path))
        {
            Some(r) => r.clone(),
            None => {
                println!("[GATEWAY] 404: {} {}", req.method, req.path);
                return ApiResponse::not_found(&req.id);
            }
        };

        // Auth check
        if route.auth_required {
            match &req.auth_token {
                Some(token) if self.valid_tokens.contains(token) => {}
                Some(_) => {
                    self.blocked_count += 1;
                    println!("[GATEWAY] 401: Invalid token for {} {}", req.method, req.path);
                    return ApiResponse::unauthorized(&req.id);
                }
                None => {
                    self.blocked_count += 1;
                    println!("[GATEWAY] 401: No token for {} {}", req.method, req.path);
                    return ApiResponse::unauthorized(&req.id);
                }
            }
        }

        // Rate limit check
        let rate_key = format!("{}:{}", req.auth_token.as_deref().unwrap_or("anon"), req.path);
        if !self.rate_limiter.check(&rate_key, route.rate_limit) {
            self.blocked_count += 1;
            return ApiResponse::rate_limited(&req.id);
        }

        println!("[GATEWAY] 200: {} {} | ID: {}", req.method, req.path, req.id);
        ApiResponse::ok(&req.id, &format!("OK: {}", route.description))
    }

    fn path_matches(&self, pattern: &str, path: &str) -> bool {
        if pattern == path { return true; }
        // Simple :param matching
        let pat_parts: Vec<&str> = pattern.split('/').collect();
        let path_parts: Vec<&str> = path.split('/').collect();
        if pat_parts.len() != path_parts.len() { return false; }
        pat_parts.iter().zip(path_parts.iter()).all(|(p, a)| {
            p.starts_with(':') || p == a
        })
    }

    pub fn list_routes(&self) {
        println!("[GATEWAY] Routes ({}):", self.routes.len());
        for route in &self.routes {
            let auth = if route.auth_required { "AUTH" } else { "PUBLIC" };
            println!("[GATEWAY]   {} {} [{}] ({}rpm) — {}",
                route.method, route.path, auth, route.rate_limit, route.description);
        }
    }

    pub fn status(&self) {
        println!("[GATEWAY] Status: {} | Port: {} | Requests: {} | Blocked: {} | Routes: {}",
            if self.running { "RUNNING" } else { "STOPPED" },
            self.port, self.request_count, self.blocked_count, self.routes.len());
    }
}