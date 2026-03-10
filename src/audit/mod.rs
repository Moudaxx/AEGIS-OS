// Copyright (c) 2025 Mouda. All Rights Reserved. AGPL-3.0
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use uuid::Uuid;

// ─── Audit Event ───
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
    pub event_type: AuditEventType,
    pub action: String,
    pub result: AuditResult,
    pub details: HashMap<String, String>,
    pub risk_score: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuditEventType {
    AgentStart,
    AgentStop,
    InferenceCall,
    ToolCall,
    PolicyCheck,
    CapabilityCheck,
    CredentialAccess,
    SkillVetting,
    InputSanitization,
    FilesystemAccess,
    NetworkEgress,
    McpRequest,
    A2aMessage,
    RiskAlert,
    ConfigChange,
    RedTeamScan,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuditResult {
    Success,
    Denied,
    Blocked,
    Failed,
    Warning,
}

impl AuditEvent {
    pub fn new(
        agent_id: &str,
        event_type: AuditEventType,
        action: &str,
        result: AuditResult,
    ) -> Self {
        AuditEvent {
            id: format!("audit-{}", Uuid::new_v4()),
            timestamp: Utc::now(),
            agent_id: agent_id.to_string(),
            event_type,
            action: action.to_string(),
            result,
            details: HashMap::new(),
            risk_score: None,
        }
    }

    pub fn with_detail(mut self, key: &str, value: &str) -> Self {
        self.details.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_risk(mut self, score: f64) -> Self {
        self.risk_score = Some(score);
        self
    }

    // Format as JSON for SIEM export
    pub fn to_json(&self) -> String {
        let details_str: Vec<String> = self.details.iter()
            .map(|(k, v)| format!("\"{}\":\"{}\"", k, v))
            .collect();

        format!(
            "{{\"id\":\"{}\",\"ts\":\"{}\",\"agent\":\"{}\",\"type\":\"{:?}\",\"action\":\"{}\",\"result\":\"{:?}\",\"risk\":{},\"details\":{{{}}}}}",
            self.id, self.timestamp.to_rfc3339(), self.agent_id,
            self.event_type, self.action, self.result,
            self.risk_score.map(|s| format!("{:.1}", s)).unwrap_or("null".to_string()),
            details_str.join(",")
        )
    }

    // Format as syslog for Sentinel/SecOps
    pub fn to_syslog(&self) -> String {
        format!(
            "<14>{} aegis-os {}: agent={} type={:?} action={} result={:?} risk={}",
            self.timestamp.format("%b %d %H:%M:%S"),
            self.id, self.agent_id, self.event_type,
            self.action, self.result,
            self.risk_score.map(|s| format!("{:.1}", s)).unwrap_or("none".to_string())
        )
    }
}

// ─── SIEM Target ───
#[derive(Debug, Clone, PartialEq)]
pub enum SiemTarget {
    Sentinel,
    SecOps,
    Splunk,
    Stdout,
    File(String),
}

// ─── Audit Logger ───
pub struct AuditLogger {
    events: Vec<AuditEvent>,
    siem_targets: Vec<SiemTarget>,
    max_events: usize,
    log_ai_calls: bool,
}

impl AuditLogger {
    pub fn new() -> Self {
        println!("[AUDIT] Logger initialized");
        AuditLogger {
            events: Vec::new(),
            siem_targets: vec![SiemTarget::Stdout],
            max_events: 10000,
            log_ai_calls: true,
        }
    }

    pub fn add_siem_target(&mut self, target: SiemTarget) {
        println!("[AUDIT] SIEM target added: {:?}", target);
        self.siem_targets.push(target);
    }

    pub fn log(&mut self, event: AuditEvent) {
        // Skip AI calls if disabled
        if !self.log_ai_calls && event.event_type == AuditEventType::InferenceCall {
            return;
        }

        // Export to SIEM targets
        for target in &self.siem_targets {
            match target {
                SiemTarget::Stdout => {
                    println!("[AUDIT] {} | {:?} | {} | {:?} | {}",
                        event.agent_id, event.event_type, event.action,
                        event.result,
                        event.risk_score.map(|s| format!("risk={:.1}", s))
                            .unwrap_or_default());
                }
                SiemTarget::Sentinel => {
                    // Would send to Microsoft Sentinel via API
                    println!("[AUDIT->SENTINEL] {}", event.to_syslog());
                }
                SiemTarget::SecOps => {
                    // Would send to Google SecOps
                    println!("[AUDIT->SECOPS] {}", event.to_json());
                }
                SiemTarget::Splunk => {
                    println!("[AUDIT->SPLUNK] {}", event.to_json());
                }
                SiemTarget::File(path) => {
                    println!("[AUDIT->FILE:{}] {}", path, event.to_json());
                }
            }
        }

        // Store event
        self.events.push(event);

        // Rotate if too many
        if self.events.len() > self.max_events {
            let drain = self.events.len() - self.max_events;
            self.events.drain(0..drain);
        }
    }

    // Query events
    pub fn query_by_agent(&self, agent_id: &str) -> Vec<&AuditEvent> {
        self.events.iter()
            .filter(|e| e.agent_id == agent_id)
            .collect()
    }

    pub fn query_by_type(&self, event_type: AuditEventType) -> Vec<&AuditEvent> {
        self.events.iter()
            .filter(|e| e.event_type == event_type)
            .collect()
    }

    pub fn query_blocked(&self) -> Vec<&AuditEvent> {
        self.events.iter()
            .filter(|e| e.result == AuditResult::Blocked || e.result == AuditResult::Denied)
            .collect()
    }

    pub fn query_high_risk(&self, threshold: f64) -> Vec<&AuditEvent> {
        self.events.iter()
            .filter(|e| e.risk_score.map(|s| s >= threshold).unwrap_or(false))
            .collect()
    }

    // Statistics
    pub fn stats(&self) {
        let total = self.events.len();
        let blocked = self.events.iter()
            .filter(|e| e.result == AuditResult::Blocked).count();
        let denied = self.events.iter()
            .filter(|e| e.result == AuditResult::Denied).count();
        let high_risk = self.events.iter()
            .filter(|e| e.risk_score.map(|s| s >= 35.0).unwrap_or(false)).count();

        let agents: Vec<&str> = self.events.iter()
            .map(|e| e.agent_id.as_str())
            .collect::<std::collections::HashSet<_>>()
            .into_iter().collect();

        println!("[AUDIT] ┌─ Audit Statistics ─────────────────");
        println!("[AUDIT] │ Total events:    {}", total);
        println!("[AUDIT] │ Blocked:         {}", blocked);
        println!("[AUDIT] │ Denied:          {}", denied);
        println!("[AUDIT] │ High risk:       {}", high_risk);
        println!("[AUDIT] │ Unique agents:   {}", agents.len());
        println!("[AUDIT] │ SIEM targets:    {}", self.siem_targets.len());
        println!("[AUDIT] │ Max capacity:    {}", self.max_events);
        println!("[AUDIT] └──────────────────────────────────");
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn clear(&mut self) {
        self.events.clear();
        println!("[AUDIT] Log cleared");
    }
}