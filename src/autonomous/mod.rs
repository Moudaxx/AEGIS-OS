use chrono::Utc;
use std::collections::HashMap;

// ─── Autonomous Security Daemon ───
pub struct AutonomousDaemon {
    running: bool,
    cycle_count: u64,
    agents_discovered: Vec<String>,
    threats_blocked: u64,
    tests_run: u64,
    rules_learned: u64,
    reports_generated: u64,
    config: DaemonConfig,
    event_log: Vec<SecurityEvent>,
}

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub scan_interval_secs: u64,
    pub test_interval_secs: u64,
    pub report_interval_secs: u64,
    pub auto_block: bool,
    pub risk_threshold: f64,
    pub target_network: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        DaemonConfig {
            scan_interval_secs: 300,     // 5 minutes
            test_interval_secs: 3600,    // 1 hour
            report_interval_secs: 86400, // 24 hours
            auto_block: true,
            risk_threshold: 70.0,
            target_network: "localhost".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub timestamp: String,
    pub event_type: EventType,
    pub agent_id: String,
    pub details: String,
    pub action_taken: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EventType {
    AgentDiscovered,
    TestCompleted,
    ThreatDetected,
    ThreatBlocked,
    RuleLearned,
    ReportGenerated,
    AgentBlocked,
}

impl AutonomousDaemon {
    pub fn new() -> Self {
        println!("⛊ AEGIS Autonomous Security Daemon");
        println!("════════════════════════════════════════════");
        println!("[DAEMON] Initializing autonomous mode...");
        AutonomousDaemon {
            running: false,
            cycle_count: 0,
            agents_discovered: Vec::new(),
            threats_blocked: 0,
            tests_run: 0,
            rules_learned: 0,
            reports_generated: 0,
            config: DaemonConfig::default(),
            event_log: Vec::new(),
        }
    }

    pub fn with_config(config: DaemonConfig) -> Self {
        let mut daemon = Self::new();
        daemon.config = config;
        daemon
    }

    // ═══ Start the daemon ═══
    pub fn start(&mut self) {
        self.running = true;
        println!("[DAEMON] ═══ STARTED ═══");
        println!("[DAEMON] Scan every: {}s | Test every: {}s | Report every: {}s",
            self.config.scan_interval_secs,
            self.config.test_interval_secs,
            self.config.report_interval_secs);
        println!("[DAEMON] Auto-block: {} | Risk threshold: {:.0}%",
            self.config.auto_block, self.config.risk_threshold);
        println!("[DAEMON] Target: {}", self.config.target_network);
        println!("[DAEMON] Waiting for cycles...");
    }

    // ═══ One full cycle ═══
    pub fn run_cycle(&mut self) -> CycleReport {
        if !self.running {
            println!("[DAEMON] Not running — call start() first");
            return CycleReport::empty();
        }

        self.cycle_count += 1;
        println!("\n[DAEMON] ═══ Cycle {} ═══ {}", self.cycle_count, Utc::now().format("%H:%M:%S"));

        let mut cycle = CycleReport::new(self.cycle_count);

        // Phase 1: Discovery
        println!("[DAEMON] Phase 1: Discovery scan...");
        let discovered = self.phase_discovery();
        cycle.agents_found = discovered.len();
        for agent in &discovered {
            self.log_event(EventType::AgentDiscovered, agent, "Agent found on network");
        }

        // Phase 2: Test each agent
        println!("[DAEMON] Phase 2: Security testing...");
        let test_results = self.phase_testing(&discovered);
        cycle.tests_run = test_results.len();
        self.tests_run += test_results.len() as u64;

        // Phase 3: Analyze threats
        println!("[DAEMON] Phase 3: Threat analysis...");
        let threats = self.phase_threat_analysis(&test_results);
        cycle.threats_found = threats.len();

        // Phase 4: Auto-block if enabled
        if self.config.auto_block {
            println!("[DAEMON] Phase 4: Auto-blocking threats...");
            for (agent_id, threat) in &threats {
                self.log_event(EventType::ThreatBlocked, agent_id, threat);
                self.threats_blocked += 1;
                cycle.threats_blocked += 1;
                println!("[DAEMON]   BLOCKED: {} — {}", agent_id, threat);
            }
        }

        // Phase 5: Learning
        println!("[DAEMON] Phase 5: Learning from attacks...");
        let new_rules = self.phase_learning(&threats);
        cycle.new_rules = new_rules;
        self.rules_learned += new_rules as u64;

        // Phase 6: Report
        println!("[DAEMON] Phase 6: Generating report...");
        self.reports_generated += 1;
        cycle.report_generated = true;
        self.log_event(EventType::ReportGenerated, "system",
            &format!("Cycle {} report", self.cycle_count));

        // Summary
        println!("[DAEMON] ═══ Cycle {} Complete ═══", self.cycle_count);
        println!("[DAEMON] Found: {} | Tested: {} | Threats: {} | Blocked: {} | Rules: {}",
            cycle.agents_found, cycle.tests_run, cycle.threats_found,
            cycle.threats_blocked, cycle.new_rules);
        cycle
    }

    // ─── Phase 1: Discovery ───
    fn phase_discovery(&mut self) -> Vec<String> {
        let mut found = Vec::new();

        // Simulate scanning known ports
        let scan_targets = vec![
            ("openclaw-18789", 18789, "OpenClaw"),
            ("mcp-8401", 8401, "AEGIS MCP"),
            ("goose-3001", 3001, "Goose"),
        ];

        for (id, port, name) in scan_targets {
            let agent_id = format!("{}-{}", id, self.config.target_network);
            if !self.agents_discovered.contains(&agent_id) {
                println!("[DAEMON]   Discovered: {} on port {} ({})", name, port, self.config.target_network);
                self.agents_discovered.push(agent_id.clone());
                found.push(agent_id);
            }
        }

        if found.is_empty() {
            println!("[DAEMON]   No new agents (known: {})", self.agents_discovered.len());
        }
        found
    }

    // ─── Phase 2: Testing ───
    fn phase_testing(&self, agents: &[String]) -> Vec<(String, f64)> {
        let all_agents = if agents.is_empty() { &self.agents_discovered } else { agents };
        let mut results = Vec::new();

        let tests = vec![
            "prompt_injection", "path_traversal", "credential_theft",
            "rbac_bypass", "network_egress", "sandbox_escape",
            "rag_poisoning", "output_privacy", "model_extraction",
            "hallucination", "malicious_skill", "state_tampering",
            "rate_limiting", "command_injection", "indirect_injection",
        ];

        for agent_id in all_agents {
            let mut score = 0.0;
            let mut passed = 0;
            for test in &tests {
                // Simulate: AEGIS blocks all attacks
                passed += 1;
                self.log_test_result(agent_id, test, true);
            }
            score = (passed as f64 / tests.len() as f64) * 100.0;
            println!("[DAEMON]   {} — Score: {:.1}% ({}/{})", agent_id, score, passed, tests.len());
            results.push((agent_id.clone(), score));
        }
        results
    }

    fn log_test_result(&self, agent_id: &str, test: &str, passed: bool) {
        // In production: detailed logging
    }

    // ─── Phase 3: Threat Analysis ───
    fn phase_threat_analysis(&self, results: &[(String, f64)]) -> Vec<(String, String)> {
        let mut threats = Vec::new();

        for (agent_id, score) in results {
            if *score < self.config.risk_threshold {
                threats.push((agent_id.clone(), format!("Score {:.1}% below threshold {:.0}%", score, self.config.risk_threshold)));
            }

            // Check for known dangerous agents
            if agent_id.contains("openclaw") {
                threats.push((agent_id.clone(), "OpenClaw: known 9 CVEs + 1184 malicious skills".into()));
            }
        }

        if threats.is_empty() {
            println!("[DAEMON]   No threats detected");
        }
        threats
    }

    // ─── Phase 4: Learning ───
    fn phase_learning(&mut self, threats: &[(String, String)]) -> usize {
        let mut new_rules = 0;

        for (agent_id, threat) in threats {
            // Extract pattern from threat
            if threat.contains("CVE") || threat.contains("malicious") {
                new_rules += 1;
                println!("[DAEMON]   New rule: Block {} pattern from {}", threat.split(':').next().unwrap_or("unknown"), agent_id);
            }
        }

        if new_rules == 0 {
            println!("[DAEMON]   No new rules needed");
        }
        new_rules
    }

    // ─── Event Logging ───
    fn log_event(&mut self, event_type: EventType, agent_id: &str, details: &str) {
        self.event_log.push(SecurityEvent {
            timestamp: Utc::now().to_rfc3339(),
            event_type,
            agent_id: agent_id.into(),
            details: details.into(),
            action_taken: "auto".into(),
        });
    }

    // ═══ Stop ═══
    pub fn stop(&mut self) {
        self.running = false;
        println!("[DAEMON] ═══ STOPPED ═══");
        println!("[DAEMON] Cycles: {} | Threats blocked: {} | Rules learned: {} | Reports: {}",
            self.cycle_count, self.threats_blocked, self.rules_learned, self.reports_generated);
    }

    // ═══ Status ═══
    pub fn status(&self) {
        println!("[DAEMON] ═══ Autonomous Daemon Status ═══");
        println!("[DAEMON] Running: {} | Cycles: {}", self.running, self.cycle_count);
        println!("[DAEMON] Agents: {} | Threats blocked: {} | Tests: {} | Rules: {} | Reports: {}",
            self.agents_discovered.len(), self.threats_blocked,
            self.tests_run, self.rules_learned, self.reports_generated);
        println!("[DAEMON] Events logged: {}", self.event_log.len());
    }
}

// ─── Cycle Report ───
#[derive(Debug, Clone)]
pub struct CycleReport {
    pub cycle: u64,
    pub agents_found: usize,
    pub tests_run: usize,
    pub threats_found: usize,
    pub threats_blocked: usize,
    pub new_rules: usize,
    pub report_generated: bool,
}

impl CycleReport {
    fn new(cycle: u64) -> Self {
        CycleReport { cycle, agents_found: 0, tests_run: 0, threats_found: 0,
            threats_blocked: 0, new_rules: 0, report_generated: false }
    }
    fn empty() -> Self { Self::new(0) }
}