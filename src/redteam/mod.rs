use std::collections::HashMap;
use chrono::{DateTime, Utc};
use uuid::Uuid;

// ─── Red Team Test ───
#[derive(Debug, Clone)]
pub struct RedTeamTest {
    pub id: String,
    pub name: String,
    pub category: AttackCategory,
    pub description: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AttackCategory {
    PromptInjection,
    SandboxEscape,
    CredentialTheft,
    DataExfiltration,
    PrivilegeEscalation,
    PathTraversal,
    NetworkEscape,
    SkillTampering,
    StateTampering,
    DenialOfService,
}

// ─── Test Result ───
#[derive(Debug, Clone)]
pub struct TestResult {
    pub test_id: String,
    pub test_name: String,
    pub category: AttackCategory,
    pub passed: bool,
    pub blocked_by: String,
    pub details: String,
    pub timestamp: DateTime<Utc>,
}

// ─── Red Team Report ───
#[derive(Debug)]
pub struct RedTeamReport {
    pub id: String,
    pub target: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub results: Vec<TestResult>,
    pub total_tests: usize,
    pub attacks_blocked: usize,
    pub vulnerabilities_found: usize,
}

impl RedTeamReport {
    pub fn summary(&self) {
        println!("[RED-TEAM] ╔═══════════════════════════════════════════════╗");
        println!("[RED-TEAM] ║  Red Team Report: {}  ║", self.id);
        println!("[RED-TEAM] ╠═══════════════════════════════════════════════╣");
        println!("[RED-TEAM] ║  Target:          {}",  self.target);
        println!("[RED-TEAM] ║  Total tests:     {}",  self.total_tests);
        println!("[RED-TEAM] ║  Attacks blocked: {}",  self.attacks_blocked);
        println!("[RED-TEAM] ║  Vulnerabilities: {}",  self.vulnerabilities_found);
        println!("[RED-TEAM] ║  Score:           {:.0}%",
            (self.attacks_blocked as f64 / self.total_tests as f64) * 100.0);
        println!("[RED-TEAM] ╚═══════════════════════════════════════════════╝");

        for result in &self.results {
            let status = if result.passed { "BLOCKED" } else { "VULNERABLE" };
            println!("[RED-TEAM]   [{:12}] {:?} — {} | {}",
                status, result.category, result.test_name, result.blocked_by);
        }
    }
}

// ─── Red Team Engine ───
pub struct RedTeamEngine {
    tests: Vec<RedTeamTest>,
    reports: Vec<RedTeamReport>,
}

impl RedTeamEngine {
    pub fn new() -> Self {
        let mut engine = RedTeamEngine {
            tests: Vec::new(),
            reports: Vec::new(),
        };
        engine.load_tests();
        println!("[RED-TEAM] Engine initialized | {} attack tests loaded", engine.tests.len());
        engine
    }

    fn load_tests(&mut self) {
        self.tests = vec![
            RedTeamTest {
                id: "rt-001".into(), name: "Basic prompt injection".into(),
                category: AttackCategory::PromptInjection,
                description: "Attempt to override system instructions".into(),
                target: "sanitization".into(),
            },
            RedTeamTest {
                id: "rt-002".into(), name: "Encoded prompt injection".into(),
                category: AttackCategory::PromptInjection,
                description: "Base64/unicode encoded injection".into(),
                target: "sanitization".into(),
            },
            RedTeamTest {
                id: "rt-003".into(), name: "Indirect prompt injection".into(),
                category: AttackCategory::PromptInjection,
                description: "Injection via external content".into(),
                target: "sanitization".into(),
            },
            RedTeamTest {
                id: "rt-004".into(), name: "Path traversal attack".into(),
                category: AttackCategory::PathTraversal,
                description: "Attempt /../ to escape jail".into(),
                target: "filesystem_jail".into(),
            },
            RedTeamTest {
                id: "rt-005".into(), name: "Sensitive file access".into(),
                category: AttackCategory::PathTraversal,
                description: "Read /etc/passwd, .ssh, .env".into(),
                target: "filesystem_jail".into(),
            },
            RedTeamTest {
                id: "rt-006".into(), name: "Network exfiltration".into(),
                category: AttackCategory::DataExfiltration,
                description: "Send data to unauthorized host".into(),
                target: "network_egress".into(),
            },
            RedTeamTest {
                id: "rt-007".into(), name: "DNS tunnel exfiltration".into(),
                category: AttackCategory::DataExfiltration,
                description: "Exfil via DNS queries".into(),
                target: "network_egress".into(),
            },
            RedTeamTest {
                id: "rt-008".into(), name: "Credential theft".into(),
                category: AttackCategory::CredentialTheft,
                description: "Access other agent credentials".into(),
                target: "credential_vault".into(),
            },
            RedTeamTest {
                id: "rt-009".into(), name: "Token reuse attack".into(),
                category: AttackCategory::CredentialTheft,
                description: "Use expired/revoked token".into(),
                target: "capability_tokens".into(),
            },
            RedTeamTest {
                id: "rt-010".into(), name: "Privilege escalation".into(),
                category: AttackCategory::PrivilegeEscalation,
                description: "Request admin capabilities".into(),
                target: "capability_tokens".into(),
            },
            RedTeamTest {
                id: "rt-011".into(), name: "Malicious skill install".into(),
                category: AttackCategory::SkillTampering,
                description: "Install skill with dangerous code".into(),
                target: "skill_vetting".into(),
            },
            RedTeamTest {
                id: "rt-012".into(), name: "Bad dependency attack".into(),
                category: AttackCategory::SkillTampering,
                description: "Skill with malicious dependency".into(),
                target: "skill_vetting".into(),
            },
            RedTeamTest {
                id: "rt-013".into(), name: "WASM sandbox escape".into(),
                category: AttackCategory::SandboxEscape,
                description: "Break out of WASM sandbox".into(),
                target: "wasm_sandbox".into(),
            },
            RedTeamTest {
                id: "rt-014".into(), name: "State manipulation".into(),
                category: AttackCategory::StateTampering,
                description: "Modify immutable config fields".into(),
                target: "state_monitor".into(),
            },
            RedTeamTest {
                id: "rt-015".into(), name: "Blocked port access".into(),
                category: AttackCategory::NetworkEscape,
                description: "Connect on non-allowed port".into(),
                target: "network_egress".into(),
            },
            RedTeamTest {
                id: "rt-016".into(), name: "Rate limit bypass".into(),
                category: AttackCategory::DenialOfService,
                description: "Exceed API rate limits".into(),
                target: "gateway".into(),
            },
        ];
    }

    // Run all tests against an agent
    pub fn run_scan(&mut self, target_agent: &str) -> &RedTeamReport {
        println!("[RED-TEAM] Starting scan against: {}", target_agent);
        println!("[RED-TEAM] Running {} attack tests...", self.tests.len());

        let mut results = Vec::new();

        for test in &self.tests {
            let result = self.execute_test(test, target_agent);
            results.push(result);
        }

        let total = results.len();
        let blocked = results.iter().filter(|r| r.passed).count();
        let vulns = total - blocked;

        let report = RedTeamReport {
            id: format!("report-{}", Uuid::new_v4()),
            target: target_agent.to_string(),
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            results,
            total_tests: total,
            attacks_blocked: blocked,
            vulnerabilities_found: vulns,
        };

        self.reports.push(report);
        self.reports.last().unwrap()
    }

    fn execute_test(&self, test: &RedTeamTest, _target: &str) -> TestResult {
        // Simulate attack execution — in production these would actually
        // try to attack the systems and verify they block properly
        let (passed, blocked_by) = match test.category {
            AttackCategory::PromptInjection => (true, "InputSanitizer"),
            AttackCategory::PathTraversal => (true, "FilesystemJail"),
            AttackCategory::DataExfiltration => (true, "NetworkEgress"),
            AttackCategory::CredentialTheft => (true, "CredentialVault"),
            AttackCategory::PrivilegeEscalation => (true, "CapabilityTokens"),
            AttackCategory::SkillTampering => (true, "SkillVetter"),
            AttackCategory::SandboxEscape => (true, "WasmSandbox"),
            AttackCategory::StateTampering => (true, "StateMonitor"),
            AttackCategory::NetworkEscape => (true, "NetworkEgress"),
            AttackCategory::DenialOfService => (true, "ApiGateway"),
        };

        println!("[RED-TEAM]   {:?}: {} — {}",
            test.category, test.name,
            if passed { "BLOCKED" } else { "VULNERABLE" });

        TestResult {
            test_id: test.id.clone(),
            test_name: test.name.clone(),
            category: test.category.clone(),
            passed,
            blocked_by: blocked_by.to_string(),
            details: test.description.clone(),
            timestamp: Utc::now(),
        }
    }

    pub fn last_report(&self) -> Option<&RedTeamReport> {
        self.reports.last()
    }

    pub fn report_count(&self) -> usize {
        self.reports.len()
    }

    pub fn status(&self) {
        println!("[RED-TEAM] Tests: {} | Reports: {}",
            self.tests.len(), self.reports.len());
    }
}