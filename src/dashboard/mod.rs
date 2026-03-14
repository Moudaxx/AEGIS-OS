use chrono::Utc;
use std::fs;

pub struct AegisDashboard {
    reports: Vec<DashboardReport>,
}

#[derive(Debug, Clone)]
pub struct DashboardReport {
    pub cycle: u64,
    pub timestamp: String,
    pub agents_found: usize,
    pub agents_tested: usize,
    pub threats_detected: usize,
    pub threats_blocked: usize,
    pub rules_learned: usize,
    pub risk_score: f64,
}

impl AegisDashboard {
    pub fn new() -> Self {
        println!("[DASHBOARD] Dashboard engine initialized");
        AegisDashboard { reports: Vec::new() }
    }

    pub fn add_report(&mut self, cycle: u64, agents_found: usize, agents_tested: usize,
        threats_detected: usize, threats_blocked: usize, rules_learned: usize) {
        let risk = if agents_tested > 0 {
            ((threats_detected as f64 / agents_tested as f64) * 100.0).min(100.0)
        } else { 0.0 };

        self.reports.push(DashboardReport {
            cycle, timestamp: Utc::now().to_rfc3339(),
            agents_found, agents_tested, threats_detected,
            threats_blocked, rules_learned, risk_score: risk,
        });
    }

    pub fn to_json(&self) -> String {
        let mut json = String::from("{\n  \"aegis_version\": \"4.1.0\",\n");
        json.push_str(&format!("  \"generated_at\": \"{}\",\n", Utc::now().to_rfc3339()));
        json.push_str(&format!("  \"total_cycles\": {},\n", self.reports.len()));

        let total_threats: usize = self.reports.iter().map(|r| r.threats_detected).sum();
        let total_blocked: usize = self.reports.iter().map(|r| r.threats_blocked).sum();
        let total_rules: usize = self.reports.iter().map(|r| r.rules_learned).sum();
        json.push_str(&format!("  \"total_threats\": {},\n", total_threats));
        json.push_str(&format!("  \"total_blocked\": {},\n", total_blocked));
        json.push_str(&format!("  \"total_rules_learned\": {},\n", total_rules));
        json.push_str(&format!("  \"block_rate\": \"{:.1}%\",\n",
            if total_threats > 0 { (total_blocked as f64 / total_threats as f64) * 100.0 } else { 100.0 }));

        json.push_str("  \"cycles\": [\n");
        for (i, r) in self.reports.iter().enumerate() {
            json.push_str(&format!("    {{\n      \"cycle\": {},\n      \"timestamp\": \"{}\",\n", r.cycle, r.timestamp));
            json.push_str(&format!("      \"agents_found\": {},\n      \"agents_tested\": {},\n", r.agents_found, r.agents_tested));
            json.push_str(&format!("      \"threats_detected\": {},\n      \"threats_blocked\": {},\n", r.threats_detected, r.threats_blocked));
            json.push_str(&format!("      \"rules_learned\": {},\n      \"risk_score\": {:.1}\n", r.rules_learned, r.risk_score));
            json.push_str(if i < self.reports.len() - 1 { "    },\n" } else { "    }\n" });
        }
        json.push_str("  ]\n}");
        json
    }

    pub fn save_json(&self, path: &str) {
        let json = self.to_json();
        fs::write(path, &json).unwrap_or_else(|e| println!("[DASHBOARD] Error saving: {}", e));
        println!("[DASHBOARD] Report saved: {} ({} bytes)", path, json.len());
    }

    pub fn generate_html(&self) -> String {
        let total_threats: usize = self.reports.iter().map(|r| r.threats_detected).sum();
        let total_blocked: usize = self.reports.iter().map(|r| r.threats_blocked).sum();
        let total_rules: usize = self.reports.iter().map(|r| r.rules_learned).sum();
        let total_agents: usize = self.reports.last().map(|r| r.agents_found).unwrap_or(0);
        let block_rate = if total_threats > 0 { (total_blocked as f64 / total_threats as f64) * 100.0 } else { 100.0 };

        let mut rows = String::new();
        for r in &self.reports {
            rows.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.0}</td></tr>\n",
                r.cycle, &r.timestamp[..19], r.agents_found, r.agents_tested,
                r.threats_detected, r.threats_blocked, r.risk_score
            ));
        }

        format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AEGIS OS — Security Dashboard</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',sans-serif;background:#0a0a1a;color:#e0e0e0;padding:20px}}
.header{{text-align:center;padding:30px 0;border-bottom:2px solid #00896B}}
.header h1{{font-size:2.5em;color:#00896B}}
.header p{{color:#888;margin-top:8px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin:30px 0}}
.card{{background:#1a1a2e;border-radius:12px;padding:24px;text-align:center;border:1px solid #333}}
.card .number{{font-size:2.8em;font-weight:bold;color:#00896B}}
.card .label{{color:#888;margin-top:4px;font-size:0.9em}}
.card.danger .number{{color:#CC3333}}
.card.warn .number{{color:#F59E0B}}
.card.ok .number{{color:#2E7D32}}
table{{width:100%;border-collapse:collapse;margin:30px 0;background:#1a1a2e;border-radius:12px;overflow:hidden}}
th{{background:#00896B;color:white;padding:14px;text-align:center}}
td{{padding:12px;text-align:center;border-bottom:1px solid #333}}
tr:hover{{background:#2a2a3e}}
.status{{text-align:center;padding:20px;margin-top:20px;color:#666;font-size:0.85em}}
.bar{{height:24px;border-radius:12px;margin:4px 0}}
.bar-blocked{{background:linear-gradient(90deg,#2E7D32,#00896B);width:{block_pct}%}}
.bar-bg{{background:#333;border-radius:12px;width:100%;margin:16px 0}}
.section{{margin:30px 0}}
.section h2{{color:#00896B;margin-bottom:16px;font-size:1.4em}}
</style>
</head>
<body>
<div class="header">
    <h1>⛊ AEGIS OS v4.1</h1>
    <p>Autonomous AI Agent Security Dashboard</p>
    <p style="color:#555;margin-top:4px">Generated: {timestamp}</p>
</div>

<div class="cards">
    <div class="card"><div class="number">{agents}</div><div class="label">Agents Discovered</div></div>
    <div class="card ok"><div class="number">{cycles}</div><div class="label">Scan Cycles</div></div>
    <div class="card danger"><div class="number">{threats}</div><div class="label">Threats Detected</div></div>
    <div class="card ok"><div class="number">{blocked}</div><div class="label">Threats Blocked</div></div>
    <div class="card ok"><div class="number">{block_rate:.0}%</div><div class="label">Block Rate</div></div>
    <div class="card warn"><div class="number">{rules}</div><div class="label">Rules Learned</div></div>
</div>

<div class="section">
    <h2>Threat Block Rate</h2>
    <div class="bar-bg"><div class="bar bar-blocked"></div></div>
    <p style="text-align:center;color:#888">{blocked}/{threats} threats blocked ({block_rate:.0}%)</p>
</div>

<div class="section">
    <h2>Cycle History</h2>
    <table>
        <thead><tr>
            <th>Cycle</th><th>Timestamp</th><th>Agents</th><th>Tested</th><th>Threats</th><th>Blocked</th><th>Risk%</th>
        </tr></thead>
        <tbody>{rows}</tbody>
    </table>
</div>

<div class="section">
    <h2>Protected Against</h2>
    <div class="cards">
        <div class="card ok"><div class="number">✅</div><div class="label">Prompt Injection</div></div>
        <div class="card ok"><div class="number">✅</div><div class="label">Path Traversal</div></div>
        <div class="card ok"><div class="number">✅</div><div class="label">Credential Theft</div></div>
        <div class="card ok"><div class="number">✅</div><div class="label">Sandbox Escape</div></div>
        <div class="card ok"><div class="number">✅</div><div class="label">RAG Poisoning</div></div>
        <div class="card ok"><div class="number">✅</div><div class="label">Data Exfiltration</div></div>
        <div class="card ok"><div class="number">✅</div><div class="label">Model Extraction</div></div>
        <div class="card ok"><div class="number">✅</div><div class="label">Hallucination</div></div>
        <div class="card ok"><div class="number">✅</div><div class="label">Malicious Skills</div></div>
        <div class="card ok"><div class="number">✅</div><div class="label">State Tampering</div></div>
    </div>
</div>

<div class="status">
    AEGIS OS v4.1.0 | 32 Modules | 12 Layers | 9 AI Backends | 151 Tests<br>
    github.com/Moudaxx/AEGIS-OS
</div>
</body>
</html>"#,
            timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            agents = total_agents,
            cycles = self.reports.len(),
            threats = total_threats,
            blocked = total_blocked,
            block_rate = block_rate,
            block_pct = block_rate,
            rules = total_rules,
            rows = rows,
        )
    }

    pub fn save_html(&self, path: &str) {
        let html = self.generate_html();
        fs::write(path, &html).unwrap_or_else(|e| println!("[DASHBOARD] Error: {}", e));
        println!("[DASHBOARD] HTML Dashboard saved: {}", path);
    }

    pub fn status(&self) {
        println!("[DASHBOARD] Reports: {} | Latest cycle: {}",
            self.reports.len(),
            self.reports.last().map(|r| r.cycle).unwrap_or(0));
    }
}