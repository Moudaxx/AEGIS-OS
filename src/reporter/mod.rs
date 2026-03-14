use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct SecurityReport {
    pub report_id: String,
    pub report_type: ReportType,
    pub timestamp: DateTime<Utc>,
    pub summary: String,
    pub agents_scanned: usize,
    pub threats_detected: usize,
    pub threats_blocked: usize,
    pub new_vulnerabilities: usize,
    pub risk_score: f64,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReportType {
    Daily,
    Weekly,
    Incident,
    OnDemand,
}

pub struct AutonomousReporter {
    reports: Vec<SecurityReport>,
    report_count: u32,
}

impl AutonomousReporter {
    pub fn new() -> Self {
        println!("[REPORTER] Autonomous Reporter initialized");
        AutonomousReporter { reports: Vec::new(), report_count: 0 }
    }

    pub fn generate_report(
        &mut self,
        report_type: ReportType,
        agents_scanned: usize,
        threats_detected: usize,
        threats_blocked: usize,
        new_vulns: usize,
        risk_score: f64,
    ) -> SecurityReport {
        self.report_count += 1;
        let type_str = match &report_type {
            ReportType::Daily => "daily",
            ReportType::Weekly => "weekly",
            ReportType::Incident => "incident",
            ReportType::OnDemand => "on-demand",
        };

        let mut recommendations = Vec::new();
        if threats_detected > 0 {
            recommendations.push(format!("Review {} detected threats", threats_detected));
        }
        if new_vulns > 0 {
            recommendations.push(format!("Patch {} new vulnerabilities", new_vulns));
        }
        if risk_score > 70.0 {
            recommendations.push("URGENT: High risk score — consider pausing agents".into());
        }
        if threats_detected > threats_blocked {
            recommendations.push("WARNING: Some threats were not blocked — update rules".into());
        }
        if agents_scanned == 0 {
            recommendations.push("No agents scanned — check discovery engine".into());
        }

        let blocked_pct = if threats_detected > 0 {
            (threats_blocked as f64 / threats_detected as f64) * 100.0
        } else { 100.0 };

        let summary = format!(
            "AEGIS {} Report #{}: {} agents scanned, {} threats ({:.0}% blocked), risk: {:.1}",
            type_str, self.report_count, agents_scanned,
            threats_detected, blocked_pct, risk_score
        );

        let report = SecurityReport {
            report_id: format!("RPT-{:04}", self.report_count),
            report_type,
            timestamp: Utc::now(),
            summary: summary.clone(),
            agents_scanned,
            threats_detected,
            threats_blocked,
            new_vulnerabilities: new_vulns,
            risk_score,
            recommendations,
        };

        println!("[REPORTER] ═══ {} ═══", summary);
        for rec in &report.recommendations {
            println!("[REPORTER]   → {}", rec);
        }

        self.reports.push(report.clone());
        report
    }

    pub fn generate_incident_report(&mut self, agent_id: &str, threat: &str, action: &str) -> SecurityReport {
        self.generate_report(
            ReportType::Incident, 1,1,
            if action == "BLOCKED" { 1 } else { 0 },
            1, 80.0,
        )
    }

    pub fn get_latest(&self) -> Option<&SecurityReport> {
        self.reports.last()
    }

    pub fn report_count(&self) -> u32 { self.report_count }

    pub fn status(&self) {
        println!("[REPORTER] Reports generated: {} | Latest: {}",
            self.report_count,
            self.reports.last().map(|r| r.report_id.as_str()).unwrap_or("none"));
    }
}