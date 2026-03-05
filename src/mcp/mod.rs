use std::collections::HashMap;
use chrono::{DateTime, Utc};

// ─── MCP Tool Definition ───
#[derive(Debug, Clone)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    pub input_schema: String,
    pub server: String,
}

// ─── MCP Message ───
#[derive(Debug, Clone)]
pub struct McpMessage {
    pub id: String,
    pub method: String,
    pub params: HashMap<String, String>,
    pub timestamp: DateTime<Utc>,
}

impl McpMessage {
    pub fn new(method: &str, params: HashMap<String, String>) -> Self {
        McpMessage {
            id: format!("msg-{}", uuid::Uuid::new_v4()),
            method: method.to_string(),
            params,
            timestamp: Utc::now(),
        }
    }
}

// ─── MCP Response ───
#[derive(Debug)]
pub enum McpResponse {
    Success { id: String, result: String },
    Error { id: String, code: i32, message: String },
}

// ─── MCP Client (AEGIS connects to external MCP servers) ───
pub struct McpClient {
    server_url: String,
    server_name: String,
    tools: Vec<McpTool>,
    allowed_tools: Vec<String>,
    connected: bool,
}

impl McpClient {
    pub fn new(name: &str, url: &str) -> Self {
        println!("[MCP-CLIENT] Connecting to: {} ({})", name, url);
        McpClient {
            server_url: url.to_string(),
            server_name: name.to_string(),
            tools: Vec::new(),
            allowed_tools: Vec::new(),
            connected: false,
        }
    }

    pub fn connect(&mut self) -> bool {
        // Simulate connection
        println!("[MCP-CLIENT] Connected to: {}", self.server_name);
        self.connected = true;

        // Discover tools
        self.tools = self.discover_tools();
        println!("[MCP-CLIENT] Discovered {} tools from {}",
            self.tools.len(), self.server_name);
        true
    }

    fn discover_tools(&self) -> Vec<McpTool> {
        // Simulated tool discovery based on server name
        match self.server_name.as_str() {
            "github" => vec![
                McpTool {
                    name: "search_code".to_string(),
                    description: "Search code in repositories".to_string(),
                    input_schema: "{\"query\": \"string\"}".to_string(),
                    server: self.server_name.clone(),
                },
                McpTool {
                    name: "create_issue".to_string(),
                    description: "Create GitHub issue".to_string(),
                    input_schema: "{\"title\": \"string\", \"body\": \"string\"}".to_string(),
                    server: self.server_name.clone(),
                },
            ],
            "slack" => vec![
                McpTool {
                    name: "send_message".to_string(),
                    description: "Send Slack message".to_string(),
                    input_schema: "{\"channel\": \"string\", \"text\": \"string\"}".to_string(),
                    server: self.server_name.clone(),
                },
            ],
            _ => vec![],
        }
    }

    pub fn set_allowed_tools(&mut self, tools: Vec<String>) {
        self.allowed_tools = tools;
        println!("[MCP-CLIENT] Allowlist set: {:?}", self.allowed_tools);
    }

    pub fn call_tool(&self, tool_name: &str, params: HashMap<String, String>) -> McpResponse {
        if !self.connected {
            return McpResponse::Error {
                id: "none".to_string(),
                code: -1,
                message: "Not connected".to_string(),
            };
        }

        // Check allowlist
        if !self.allowed_tools.is_empty()
            && !self.allowed_tools.iter().any(|t| t == tool_name)
        {
            println!("[MCP-CLIENT] BLOCKED: tool '{}' not in allowlist", tool_name);
            return McpResponse::Error {
                id: "none".to_string(),
                code: 403,
                message: format!("Tool '{}' not allowed", tool_name),
            };
        }

        // Check tool exists
        if !self.tools.iter().any(|t| t.name == tool_name) {
            return McpResponse::Error {
                id: "none".to_string(),
                code: 404,
                message: format!("Tool '{}' not found", tool_name),
            };
        }

        let msg = McpMessage::new(&format!("tools/{}", tool_name), params);
        println!("[MCP-CLIENT] Calling: {}.{} | ID: {}", self.server_name, tool_name, msg.id);

        McpResponse::Success {
            id: msg.id,
            result: format!("Result from {}.{}", self.server_name, tool_name),
        }
    }

    pub fn list_tools(&self) {
        println!("[MCP-CLIENT] Tools from '{}':", self.server_name);
        for tool in &self.tools {
            let allowed = if self.allowed_tools.is_empty()
                || self.allowed_tools.contains(&tool.name) { "ALLOWED" } else { "BLOCKED" };
            println!("[MCP-CLIENT]   {} [{}] — {}", tool.name, allowed, tool.description);
        }
    }
}

// ─── MCP Server (AEGIS exposes tools to external agents) ───
pub struct McpServer {
    name: String,
    port: u16,
    tools: HashMap<String, McpTool>,
    auth_required: bool,
    running: bool,
}

impl McpServer {
    pub fn new(port: u16) -> Self {
        let mut server = McpServer {
            name: "aegis-mcp".to_string(),
            port,
            tools: HashMap::new(),
            auth_required: true,
            running: false,
        };
        server.register_defaults();
        server
    }

    fn register_defaults(&mut self) {
        let aegis_tools = vec![
            ("aegis.run_agent", "Start a new agent"),
            ("aegis.stop_agent", "Stop a running agent"),
            ("aegis.agent_status", "Get agent status"),
            ("aegis.check_policy", "Check if action is allowed"),
            ("aegis.risk_score", "Get agent risk score"),
            ("aegis.audit_query", "Query audit logs"),
            ("aegis.red_team", "Start red team test"),
            ("aegis.list_tools", "List available tools"),
        ];

        for (name, desc) in aegis_tools {
            self.tools.insert(name.to_string(), McpTool {
                name: name.to_string(),
                description: desc.to_string(),
                input_schema: "{}".to_string(),
                server: self.name.clone(),
            });
        }
    }

    pub fn start(&mut self) {
        self.running = true;
        println!("[MCP-SERVER] AEGIS MCP Server started on port {}", self.port);
        println!("[MCP-SERVER] Auth required: {}", self.auth_required);
        println!("[MCP-SERVER] Exposing {} tools", self.tools.len());
    }

    pub fn handle_request(&self, tool_name: &str, params: HashMap<String, String>,
                          auth_token: Option<&str>) -> McpResponse {
        if !self.running {
            return McpResponse::Error {
                id: "none".to_string(),
                code: -1,
                message: "Server not running".to_string(),
            };
        }

        // Auth check
        if self.auth_required && auth_token.is_none() {
            println!("[MCP-SERVER] REJECTED: no auth token");
            return McpResponse::Error {
                id: "none".to_string(),
                code: 401,
                message: "Authentication required".to_string(),
            };
        }

        // Find tool
        match self.tools.get(tool_name) {
            Some(tool) => {
                let msg = McpMessage::new(tool_name, params);
                println!("[MCP-SERVER] Executing: {} | ID: {}", tool_name, msg.id);
                McpResponse::Success {
                    id: msg.id,
                    result: format!("Executed: {}", tool.description),
                }
            }
            None => {
                println!("[MCP-SERVER] Tool not found: {}", tool_name);
                McpResponse::Error {
                    id: "none".to_string(),
                    code: 404,
                    message: format!("Tool '{}' not found", tool_name),
                }
            }
        }
    }

    pub fn list_tools(&self) {
        println!("[MCP-SERVER] AEGIS tools ({}):", self.tools.len());
        for tool in self.tools.values() {
            println!("[MCP-SERVER]   {} — {}", tool.name, tool.description);
        }
    }

    pub fn status(&self) {
        println!("[MCP-SERVER] Status: {} | Port: {} | Tools: {} | Auth: {}",
            if self.running { "RUNNING" } else { "STOPPED" },
            self.port, self.tools.len(), self.auth_required);
    }
}