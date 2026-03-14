use std::collections::HashMap;
use chrono::{DateTime, Utc};

// ─── Discovered Agent ───
#[derive(Debug, Clone)]
pub struct DiscoveredAgent {
    pub id: String,
    pub agent_type: AgentType,
    pub endpoint: String,
    pub port: u16,
    pub status: AgentStatus,
    pub risk_level: RiskLevel,
    pub discovered_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentType {
    OpenClaw,
    NanoClaw,
    AgentZero,
    Goose,
    ClaudeCode,
    AutoGPT,
    CrewAI,
    LangGraph,
    CustomMCP,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentStatus {
    Active,
    Inactive,
    Suspicious,
    Blocked,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RiskLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

// ─── Discovery Engine ───
pub struct DiscoveryEngine {
    agents: HashMap<String, DiscoveredAgent>,
    scan_history: Vec<ScanResult>,
    known_ports: Vec<(u16, AgentType)>,
    known_signatures: Vec<(String, AgentType)>,
    auto_scan_enabled: bool,
    scan_interval_secs: u64,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub timestamp: DateTime<Utc>,
    pub agents_found: usize,
    pub new_agents: usize,
    pub removed_agents: usize,
    pub scan_duration_ms: u64,
}

impl DiscoveryEngine {
    pub fn new() -> Self {
        println!("[DISCOVERY] Autonomous Discovery Engine initialized");
        DiscoveryEngine {
            agents: HashMap::new(),
            scan_history: Vec::new(),
            known_ports: vec![
                (18789, AgentType::OpenClaw),
                (18790, AgentType::NanoClaw),
                (8000, AgentType::AgentZero),
                (3001, AgentType::Goose),
                (8080, AgentType::ClaudeCode),
                (8484, AgentType::AutoGPT),
                (8401, AgentType::CustomMCP),
            ],
            known_signatures: vec![
                ("openclaw".into(), AgentType::OpenClaw),
                ("nanoclaw".into(), AgentType::NanoClaw),
                ("agent-zero".into(), AgentType::AgentZero),
                ("goose".into(), AgentType::Goose),
                ("claude-code".into(), AgentType::ClaudeCode),
                ("autogpt".into(), AgentType::AutoGPT),
                ("crewai".into(), AgentType::CrewAI),
                ("langgraph".into(), AgentType::LangGraph),
            ],
            auto_scan_enabled: true,
            scan_interval_secs: 300,
        }
    }

    // ═══ Port Scan — discover agents by port ═══
    pub fn scan_ports(&mut self, target: &str) -> Vec<DiscoveredAgent> {
        let start = std::time::Instant::now();
        let mut found = Vec::new();
        println!("[DISCOVERY] Scanning {} for AI agents...", target);

        for (port, agent_type) in &self.known_ports {
            let endpoint = format!("{}:{}", target, port);
            // Simulate port check (in production: actual TCP connect)
            let is_open = self.simulate_port_check(target, *port);

            if is_open {
                let agent = DiscoveredAgent {
                    id: format!("agent-{}-{}", target, port),
                    agent_type: agent_type.clone(),
                    endpoint: endpoint.clone(),
                    port: *port,
                    status: AgentStatus::Active,
                    risk_level: self.assess_initial_risk(agent_type),
                    discovered_at: Utc::now(),
                    last_seen: Utc::now(),
                    metadata: HashMap::new(),
                };
                println!("[DISCOVERY] FOUND: {:?} at {} (port {})",
                    agent_type, endpoint, port);
                found.push(agent);
            }
        }

        // Record scan result
        let new_count = found.iter()
            .filter(|a| !self.agents.contains_key(&a.id))
            .count();

        let result = ScanResult {
            timestamp: Utc::now(),
            agents_found: found.len(),
            new_agents: new_count,
            removed_agents: 0,
            scan_duration_ms: start.elapsed().as_millis() as u64,
        };

        // Update registry
        for agent in &found {
            self.agents.insert(agent.id.clone(), agent.clone());
        }

        println!("[DISCOVERY] Scan complete: {} found, {} new | {}ms",
            found.len(), new_count, result.scan_duration_ms);
        self.scan_history.push(result);
        found
    }

    // ═══ MCP Discovery — find MCP servers ═══
    pub fn scan_mcp(&mut self, target: &str) -> Vec<DiscoveredAgent> {
        let mut found = Vec::new();
        println!("[DISCOVERY] Scanning {} for MCP servers...", target);

        // Check common MCP ports
        let mcp_ports = vec![8401, 3000, 3001, 8080, 8443];
        for port in mcp_ports {
            let endpoint = format!("{}:{}", target, port);
            let has_mcp = self.simulate_mcp_check(target, port);

            if has_mcp {
                let agent = DiscoveredAgent {
                    id: format!("mcp-{}-{}", target, port),
                    agent_type: AgentType::CustomMCP,
                    endpoint,
                    port,
                    status: AgentStatus::Active,
                    risk_level: RiskLevel::Medium,
                    discovered_at: Utc::now(),
                    last_seen: Utc::now(),
                    metadata: {
                        let mut m = HashMap::new();
                        m.insert("protocol".into(), "MCP".into());
                        m
                    },
                };
                println!("[DISCOVERY] MCP Server found at {}:{}", target, port);
                found.push(agent.clone());
                self.agents.insert(agent.id.clone(), agent);
            }
        }
        found
    }

    // ═══ Docker Discovery — find containers ═══
    pub fn scan_docker(&mut self) -> Vec<DiscoveredAgent> {
        let mut found = Vec::new();
        println!("[DISCOVERY] Scanning Docker containers for AI agents...");

        // Simulate docker container discovery
        let containers = vec![
            ("openclaw-prod", AgentType::OpenClaw, 18789),
            ("nanoclaw-whatsapp", AgentType::NanoClaw, 18790),
        ];

        for (name, agent_type, port) in containers {
            let agent = DiscoveredAgent {
                id: format!("docker-{}", name),
                agent_type,
                endpoint: format!("container:{}:{}", name, port),
                port,
                status: AgentStatus::Active,
                risk_level: RiskLevel::High,
                discovered_at: Utc::now(),
                last_seen: Utc::now(),
                metadata: {
                    let mut m = HashMap::new();
                    m.insert("source".into(), "docker".into());
                    m.insert("container".into(), name.into());
                    m
                },
            };
            println!("[DISCOVERY] Docker: {:?} in container '{}'", agent.agent_type, name);
            found.push(agent.clone());
            self.agents.insert(agent.id.clone(), agent);
        }
        found
    }

    // ═══ Full Scan — all methods ═══
    pub fn full_scan(&mut self, target: &str) -> ScanResult {
        println!("[DISCOVERY] ═══ Full Autonomous Scan: {} ═══", target);
        let start = std::time::Instant::now();
        let before = self.agents.len();

        self.scan_ports(target);
        self.scan_mcp(target);
        self.scan_docker();

        let after = self.agents.len();
        let result = ScanResult {
            timestamp: Utc::now(),
            agents_found: after,
            new_agents: after.saturating_sub(before),
            removed_agents: 0,
            scan_duration_ms: start.elapsed().as_millis() as u64,
        };

        println!("[DISCOVERY] ═══ Full Scan Complete ═══");
        println!("[DISCOVERY] Total agents: {} | New: {} | Duration: {}ms",
            result.agents_found, result.new_agents, result.scan_duration_ms);
        self.scan_history.push(result.clone());
        result
    }

    // ═══ Risk Assessment ═══
    fn assess_initial_risk(&self, agent_type: &AgentType) -> RiskLevel {
        match agent_type {
            AgentType::OpenClaw => RiskLevel::Critical,  // 135K+ exposed, 9 CVEs
            AgentType::NanoClaw => RiskLevel::High,      // WhatsApp access
            AgentType::AgentZero => RiskLevel::High,     // Full system access
            AgentType::AutoGPT => RiskLevel::High,       // Autonomous execution
            AgentType::ClaudeCode => RiskLevel::Medium,  // Code execution
            AgentType::Goose => RiskLevel::Medium,       // MCP agent
            AgentType::CrewAI => RiskLevel::Medium,      // Multi-agent
            AgentType::LangGraph => RiskLevel::Low,      // Workflow agent
            AgentType::CustomMCP => RiskLevel::Medium,   // Unknown MCP
            AgentType::Unknown => RiskLevel::High,       // Unknown = suspicious
        }
    }

    // ═══ Get all agents ═══
    pub fn get_agents(&self) -> Vec<&DiscoveredAgent> {
        self.agents.values().collect()
    }

    pub fn get_critical(&self) -> Vec<&DiscoveredAgent> {
        self.agents.values()
            .filter(|a| a.risk_level == RiskLevel::Critical || a.risk_level == RiskLevel::High)
            .collect()
    }

    pub fn get_agent(&self, id: &str) -> Option<&DiscoveredAgent> {
        self.agents.get(id)
    }

    pub fn block_agent(&mut self, id: &str) {
        if let Some(agent) = self.agents.get_mut(id) {
            agent.status = AgentStatus::Blocked;
            println!("[DISCOVERY] BLOCKED: {} ({:?})", id, agent.agent_type);
        }
    }

    // Simulations (replace with real checks in production)
    fn simulate_port_check(&self, _target: &str, port: u16) -> bool {
        // In production: actual TCP connect
        matches!(port, 18789 | 8401 | 3001)
    }

    fn simulate_mcp_check(&self, _target: &str, port: u16) -> bool {
        // In production: HTTP GET /mcp/tools/list
        matches!(port, 8401 | 3001)
    }

    pub fn agent_count(&self) -> usize { self.agents.len() }
    pub fn scan_count(&self) -> usize { self.scan_history.len() }

    pub fn status(&self) {
        println!("[DISCOVERY] ═══ Engine Status ═══");
        println!("[DISCOVERY] Agents: {} | Scans: {} | Auto: {} | Interval: {}s",
            self.agents.len(), self.scan_history.len(),
            self.auto_scan_enabled, self.scan_interval_secs);
        let critical = self.get_critical().len();
        if critical > 0 {
            println!("[DISCOVERY] ⚠ {} HIGH/CRITICAL agents detected!", critical);
        }
    }
}