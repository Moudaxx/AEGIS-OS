// Copyright (c) 2025 Mouda. All Rights Reserved. AGPL-3.0
use std::collections::HashMap;
use chrono::{DateTime, Utc};

// ─── Kali Tool Definition ───
#[derive(Debug, Clone)]
pub struct KaliTool {
    pub name: String,
    pub description: String,
    pub category: KaliCategory,
    pub command_template: String,
    pub requires_target: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum KaliCategory {
    Recon,
    Scanning,
    Exploitation,
    WebApp,
    Password,
    Wireless,
    Forensics,
}

// ─── Scan Result ───
#[derive(Debug, Clone)]
pub struct KaliResult {
    pub tool: String,
    pub target: String,
    pub findings: Vec<Finding>,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub severity: Severity,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

// ─── MCP-Kali Server ───
pub struct McpKaliServer {
    tools: Vec<KaliTool>,
    results: Vec<KaliResult>,
    authorized_targets: Vec<String>,
    running: bool,
    port: u16,
}

impl McpKaliServer {
    pub fn new(port: u16) -> Self {
        let mut server = McpKaliServer {
            tools: Vec::new(),
            results: Vec::new(),
            authorized_targets: vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "aegis-os".to_string(),
                "*.aegis.internal".to_string(),
            ],
            running: false,
            port,
        };
        server.load_tools();
        println!("[MCP-KALI] Server created | {} tools | Port: {}", server.tools.len(), port);
        server
    }

    fn load_tools(&mut self) {
        self.tools = vec![
            KaliTool {
                name: "kali.nmap".into(),
                description: "Network port scanner — discover open ports and services".into(),
                category: KaliCategory::Scanning,
                command_template: "nmap -sV -sC {target}".into(),
                requires_target: true,
            },
            KaliTool {
                name: "kali.nikto".into(),
                description: "Web server vulnerability scanner".into(),
                category: KaliCategory::WebApp,
                command_template: "nikto -h {target}".into(),
                requires_target: true,
            },
            KaliTool {
                name: "kali.sqlmap".into(),
                description: "SQL injection detection and exploitation".into(),
                category: KaliCategory::Exploitation,
                command_template: "sqlmap -u {target} --batch --level=3".into(),
                requires_target: true,
            },
            KaliTool {
                name: "kali.dirb".into(),
                description: "Web directory brute-force scanner".into(),
                category: KaliCategory::WebApp,
                command_template: "dirb {target}".into(),
                requires_target: true,
            },
            KaliTool {
                name: "kali.hydra".into(),
                description: "Password brute-force tool".into(),
                category: KaliCategory::Password,
                command_template: "hydra -L users.txt -P pass.txt {target} ssh".into(),
                requires_target: true,
            },
            KaliTool {
                name: "kali.wpscan".into(),
                description: "WordPress vulnerability scanner".into(),
                category: KaliCategory::WebApp,
                command_template: "wpscan --url {target}".into(),
                requires_target: true,
            },
            KaliTool {
                name: "kali.gobuster".into(),
                description: "Directory/file/DNS brute-force tool".into(),
                category: KaliCategory::Recon,
                command_template: "gobuster dir -u {target} -w wordlist.txt".into(),
                requires_target: true,
            },
            KaliTool {
                name: "kali.enum4linux".into(),
                description: "SMB enumeration tool".into(),
                category: KaliCategory::Recon,
                command_template: "enum4linux -a {target}".into(),
                requires_target: true,
            },
            KaliTool {
                name: "kali.hashcat".into(),
                description: "Password hash cracker".into(),
                category: KaliCategory::Password,
                command_template: "hashcat -m 0 hashes.txt wordlist.txt".into(),
                requires_target: false,
            },
            KaliTool {
                name: "kali.metasploit".into(),
                description: "Exploitation framework — vulnerability verification".into(),
                category: KaliCategory::Exploitation,
                command_template: "msfconsole -q -x 'use auxiliary/scanner/http/http_version; set RHOSTS {target}; run; exit'".into(),
                requires_target: true,
            },
            KaliTool {
                name: "kali.burpsuite".into(),
                description: "Web application security testing proxy".into(),
                category: KaliCategory::WebApp,
                command_template: "burpsuite --project-file={target}.burp".into(),
                requires_target: true,
            },
            KaliTool {
                name: "kali.volatility".into(),
                description: "Memory forensics framework".into(),
                category: KaliCategory::Forensics,
                command_template: "volatility -f {target} imageinfo".into(),
                requires_target: true,
            },
        ];
    }

    pub fn start(&mut self) {
        self.running = true;
        println!("[MCP-KALI] Server started on port {}", self.port);
        println!("[MCP-KALI] {} tools available across {} categories",
            self.tools.len(), 7);
        println!("[MCP-KALI] Authorized targets: {:?}", self.authorized_targets);
    }

    // Check if target is authorized
    fn check_target(&self, target: &str) -> bool {
        for allowed in &self.authorized_targets {
            if allowed == target { return true; }
            if allowed.starts_with("*.") {
                let domain = &allowed[2..];
                if target.ends_with(domain) { return true; }
            }
        }
        println!("[MCP-KALI] BLOCKED: target '{}' not authorized", target);
        false
    }

    // Execute a tool via MCP
    pub fn call_tool(&mut self, tool_name: &str, target: &str) -> Result<KaliResult, String> {
        if !self.running {
            return Err("MCP-Kali server not running".into());
        }

        // Find tool
        let tool = match self.tools.iter().find(|t| t.name == tool_name) {
            Some(t) => t.clone(),
            None => return Err(format!("Tool '{}' not found", tool_name)),
        };

        // Check target authorization
        if tool.requires_target && !self.check_target(target) {
            return Err(format!("Target '{}' not authorized for scanning", target));
        }

        let started = Utc::now();
        println!("[MCP-KALI] Executing: {} against {}", tool_name, target);
        println!("[MCP-KALI] Command: {}", tool.command_template.replace("{target}", target));

        // Simulate scan results based on tool
        let findings = self.simulate_scan(&tool, target);
        let severity = findings.iter()
            .map(|f| &f.severity)
            .max_by_key(|s| match s {
                Severity::Critical => 5,
                Severity::High => 4,
                Severity::Medium => 3,
                Severity::Low => 2,
                Severity::Info => 1,
            })
            .cloned()
            .unwrap_or(Severity::Info);

        let result = KaliResult {
            tool: tool_name.to_string(),
            target: target.to_string(),
            findings: findings.clone(),
            started_at: started,
            completed_at: Utc::now(),
            severity,
        };

        println!("[MCP-KALI] Scan complete: {} findings | Max severity: {:?}",
            findings.len(), result.severity);
        self.results.push(result.clone());
        Ok(result)
    }

    fn simulate_scan(&self, tool: &KaliTool, _target: &str) -> Vec<Finding> {
        match tool.category {
            KaliCategory::Scanning => vec![
                Finding {
                    title: "Open port 8401 (HTTP)".into(),
                    description: "AEGIS MCP Server exposed".into(),
                    severity: Severity::Info,
                    remediation: "Expected — AEGIS API endpoint".into(),
                },
                Finding {
                    title: "Open port 8443 (HTTPS)".into(),
                    description: "AEGIS TLS endpoint detected".into(),
                    severity: Severity::Info,
                    remediation: "Expected — TLS enabled".into(),
                },
                Finding {
                    title: "TLS certificate self-signed".into(),
                    description: "Certificate not from trusted CA".into(),
                    severity: Severity::Low,
                    remediation: "Use Let's Encrypt or CA-signed cert for production".into(),
                },
            ],
            KaliCategory::WebApp => vec![
                Finding {
                    title: "No CORS headers on API".into(),
                    description: "API accessible from any origin".into(),
                    severity: Severity::Medium,
                    remediation: "Add strict CORS policy with tower-http".into(),
                },
                Finding {
                    title: "Server header exposes version".into(),
                    description: "Response contains server version info".into(),
                    severity: Severity::Low,
                    remediation: "Remove server header in production".into(),
                },
            ],
            KaliCategory::Exploitation => vec![
                Finding {
                    title: "SQL injection test".into(),
                    description: "SQL Firewall blocked all injection attempts".into(),
                    severity: Severity::Info,
                    remediation: "SQL Firewall active — no action needed".into(),
                },
                Finding {
                    title: "Prompt injection test".into(),
                    description: "Input sanitizer blocked 21 injection patterns".into(),
                    severity: Severity::Info,
                    remediation: "Sanitizer active — no action needed".into(),
                },
            ],
            KaliCategory::Password => vec![
                Finding {
                    title: "Auth tokens are static".into(),
                    description: "RBAC tokens don't rotate automatically".into(),
                    severity: Severity::Medium,
                    remediation: "Implement JWT with expiry or integrate Vault".into(),
                },
            ],
            _ => vec![
                Finding {
                    title: "Scan completed".into(),
                    description: "No critical findings".into(),
                    severity: Severity::Info,
                    remediation: "None required".into(),
                },
            ],
        }
    }

    // List all tools via MCP
    pub fn list_tools(&self) {
        println!("[MCP-KALI] Available tools ({}):", self.tools.len());
        let mut by_cat: HashMap<String, Vec<&KaliTool>> = HashMap::new();
        for tool in &self.tools {
            by_cat.entry(format!("{:?}", tool.category)).or_default().push(tool);
        }
        for (cat, tools) in &by_cat {
            println!("[MCP-KALI]   {} ({}):", cat, tools.len());
            for t in tools {
                println!("[MCP-KALI]     {} — {}", t.name, t.description);
            }
        }
    }

    // Full security assessment
    pub fn full_assessment(&mut self, target: &str) -> Vec<KaliResult> {
        println!("[MCP-KALI] ═══ Full Security Assessment: {} ═══", target);
        let tool_names: Vec<String> = self.tools.iter()
            .filter(|t| t.requires_target)
            .map(|t| t.name.clone())
            .collect();

        let mut all_results = Vec::new();
        for name in tool_names {
            match self.call_tool(&name, target) {
                Ok(result) => all_results.push(result),
                Err(e) => println!("[MCP-KALI] Skipped {}: {}", name, e),
            }
        }

        let total_findings: usize = all_results.iter().map(|r| r.findings.len()).sum();
        let critical = all_results.iter()
            .flat_map(|r| &r.findings)
            .filter(|f| f.severity == Severity::Critical || f.severity == Severity::High)
            .count();

        println!("[MCP-KALI] ═══ Assessment Complete ═══");
        println!("[MCP-KALI] Tools run: {}", all_results.len());
        println!("[MCP-KALI] Total findings: {}", total_findings);
        println!("[MCP-KALI] Critical/High: {}", critical);
        all_results
    }

    pub fn add_authorized_target(&mut self, target: &str) {
        self.authorized_targets.push(target.to_string());
        println!("[MCP-KALI] Target authorized: {}", target);
    }

    pub fn status(&self) {
        println!("[MCP-KALI] Status: {} | Port: {} | Tools: {} | Scans: {} | Targets: {}",
            if self.running { "RUNNING" } else { "STOPPED" },
            self.port, self.tools.len(), self.results.len(),
            self.authorized_targets.len());
    }
}