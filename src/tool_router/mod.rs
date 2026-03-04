use std::collections::HashMap;

// ─── Tool Definition ───
#[derive(Debug, Clone)]
pub struct Tool {
    pub name: String,
    pub description: String,
    pub category: ToolCategory,
    pub required_capability: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ToolCategory {
    Inference,
    FileSystem,
    Network,
    Database,
    Security,
    Kali,
}

impl Tool {
    pub fn new(name: &str, desc: &str, category: ToolCategory, cap: &str) -> Self {
        Tool {
            name: name.to_string(),
            description: desc.to_string(),
            category,
            required_capability: cap.to_string(),
            enabled: true,
        }
    }
}

// ─── Route Result ───
#[derive(Debug)]
pub enum RouteResult {
    Allowed { tool: String, provider: String },
    Denied { tool: String, reason: String },
    NotFound { tool: String },
}

// ─── Tool Router ───
pub struct ToolRouter {
    tools: HashMap<String, Tool>,
    ai_providers: Vec<String>,
    default_provider: String,
}

impl ToolRouter {
    pub fn new(default_provider: &str) -> Self {
        let mut router = ToolRouter {
            tools: HashMap::new(),
            ai_providers: vec![
                "nvidia".to_string(),
                "claude".to_string(),
                "google".to_string(),
            ],
            default_provider: default_provider.to_string(),
        };
        router.register_defaults();
        router
    }

    fn register_defaults(&mut self) {
        // AI Inference tools
        self.register(Tool::new(
            "ai.chat", "Send chat completion request",
            ToolCategory::Inference, "inference.call"));
        self.register(Tool::new(
            "ai.embed", "Generate text embeddings",
            ToolCategory::Inference, "inference.embed"));
        self.register(Tool::new(
            "ai.analyze", "Analyze content with AI",
            ToolCategory::Inference, "inference.call"));

        // Filesystem tools
        self.register(Tool::new(
            "fs.read", "Read file contents",
            ToolCategory::FileSystem, "filesystem.read"));
        self.register(Tool::new(
            "fs.write", "Write file contents",
            ToolCategory::FileSystem, "filesystem.write"));
        self.register(Tool::new(
            "fs.list", "List directory contents",
            ToolCategory::FileSystem, "filesystem.read"));

        // Network tools
        self.register(Tool::new(
            "net.http", "Make HTTP request",
            ToolCategory::Network, "network.egress"));
        self.register(Tool::new(
            "net.dns", "DNS lookup",
            ToolCategory::Network, "network.egress"));

        // Database tools
        self.register(Tool::new(
            "db.query", "Execute database query",
            ToolCategory::Database, "database.query"));
        self.register(Tool::new(
            "db.insert", "Insert database record",
            ToolCategory::Database, "database.write"));

        // Security tools
        self.register(Tool::new(
            "sec.scan", "Security scan",
            ToolCategory::Security, "security.scan"));
        self.register(Tool::new(
            "sec.audit", "Audit log query",
            ToolCategory::Security, "security.audit"));

        // Kali Red Team tools
        self.register(Tool::new(
            "kali.nmap", "Network port scanner",
            ToolCategory::Kali, "redteam.scan"));
        self.register(Tool::new(
            "kali.nikto", "Web server scanner",
            ToolCategory::Kali, "redteam.scan"));
        self.register(Tool::new(
            "kali.sqlmap", "SQL injection tester",
            ToolCategory::Kali, "redteam.inject"));
    }

    pub fn register(&mut self, tool: Tool) {
        self.tools.insert(tool.name.clone(), tool);
    }

    pub fn route(&self, tool_name: &str, agent_caps: &[String]) -> RouteResult {
        // Find tool
        let tool = match self.tools.get(tool_name) {
            Some(t) => t,
            None => {
                println!("[ROUTER] Tool not found: {}", tool_name);
                return RouteResult::NotFound { tool: tool_name.to_string() };
            }
        };

        // Check if enabled
        if !tool.enabled {
            println!("[ROUTER] Tool disabled: {}", tool_name);
            return RouteResult::Denied {
                tool: tool_name.to_string(),
                reason: "tool disabled".to_string(),
            };
        }

        // Check capability
        let has_cap = agent_caps.iter().any(|c| {
            c == &tool.required_capability
            || c == "*"
            || (c.ends_with(".*") && tool.required_capability
                .starts_with(&c[..c.len()-2]))
        });

        if !has_cap {
            println!("[ROUTER] DENIED: {} (requires: {})", tool_name, tool.required_capability);
            return RouteResult::Denied {
                tool: tool_name.to_string(),
                reason: format!("missing capability: {}", tool.required_capability),
            };
        }

        // Determine provider for AI tools
        let provider = if tool.category == ToolCategory::Inference {
            self.default_provider.clone()
        } else {
            "local".to_string()
        };

        println!("[ROUTER] ALLOWED: {} -> {} | Cap: {}",
            tool_name, provider, tool.required_capability);

        RouteResult::Allowed {
            tool: tool_name.to_string(),
            provider,
        }
    }

    pub fn route_ai<'a>(&'a self, provider: &'a str) -> Option<&'a str> {
        if self.ai_providers.iter().any(|p| p == provider) {
            println!("[ROUTER] AI routed to: {}", provider);
            Some(provider)
        } else {
            println!("[ROUTER] Unknown AI provider: {} -> fallback: {}",
                provider, self.default_provider);
            Some(&self.default_provider)
        }
    }

    pub fn list_tools(&self) {
        println!("[ROUTER] Registered tools: {}", self.tools.len());
        let mut categories: HashMap<String, Vec<&Tool>> = HashMap::new();
        for tool in self.tools.values() {
            categories.entry(format!("{:?}", tool.category))
                .or_default().push(tool);
        }
        for (cat, tools) in &categories {
            println!("[ROUTER]   {} ({}):", cat, tools.len());
            for t in tools {
                let status = if t.enabled { "ON" } else { "OFF" };
                println!("[ROUTER]     {} [{}] — {}", t.name, status, t.description);
            }
        }
    }

    pub fn disable_tool(&mut self, name: &str) -> bool {
        if let Some(tool) = self.tools.get_mut(name) {
            tool.enabled = false;
            println!("[ROUTER] Disabled: {}", name);
            true
        } else { false }
    }

    pub fn enable_tool(&mut self, name: &str) -> bool {
        if let Some(tool) = self.tools.get_mut(name) {
            tool.enabled = true;
            println!("[ROUTER] Enabled: {}", name);
            true
        } else { false }
    }

    pub fn tools_by_category(&self, category: ToolCategory) -> Vec<&Tool> {
        self.tools.values()
            .filter(|t| t.category == category && t.enabled)
            .collect()
    }
}