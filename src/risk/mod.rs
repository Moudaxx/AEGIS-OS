use std::collections::HashMap;
use chrono::{DateTime, Utc};

// ─── Risk Event ───
#[derive(Debug, Clone)]
pub struct RiskEvent {
    pub event_type: String,
    pub agent_id: String,
    pub description: String,
    pub dimension: RiskDimension,
    pub score_impact: f64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RiskDimension {
    Identity,
    Execution,
    Persistence,
    Exfiltration,
}

// ─── Risk Action ───
#[derive(Debug, Clone, PartialEq)]
pub enum RiskAction {
    Normal,
    Warning,
    Pause,
    Kill,
}

// ─── Agent Risk Profile ───
#[derive(Debug, Clone)]
pub struct AgentRisk {
    pub agent_id: String,
    pub identity: f64,
    pub execution: f64,
    pub persistence: f64,
    pub exfiltration: f64,
    pub events: Vec<RiskEvent>,
    pub last_updated: DateTime<Utc>,
}

impl AgentRisk {
    pub fn new(agent_id: &str) -> Self {
        AgentRisk {
            agent_id: agent_id.to_string(),
            identity: 0.0,
            execution: 0.0,
            persistence: 0.0,
            exfiltration: 0.0,
            events: Vec::new(),
            last_updated: Utc::now(),
        }
    }

    pub fn total_score(&self) -> f64 {
        (self.identity + self.execution + self.persistence + self.exfiltration) / 4.0
    }

    pub fn max_dimension(&self) -> f64 {
        self.identity.max(self.execution).max(self.persistence).max(self.exfiltration)
    }

    pub fn action(&self) -> RiskAction {
        let total = self.total_score();
        let max_dim = self.max_dimension();

        // Kill if any single dimension is critical
        if max_dim >= 90.0 { return RiskAction::Kill; }
        if total >= 50.0 { return RiskAction::Kill; }
        if total >= 35.0 { return RiskAction::Pause; }
        if total >= 15.0 { return RiskAction::Warning; }
        RiskAction::Normal
    }
}

// ─── Risk Scorer ───
pub struct RiskScorer {
    agents: HashMap<String, AgentRisk>,
    thresholds: RiskThresholds,
    event_scores: HashMap<String, (RiskDimension, f64)>,
}

#[derive(Debug, Clone)]
pub struct RiskThresholds {
    pub warning: f64,
    pub pause: f64,
    pub kill: f64,
    pub dimension_critical: f64,
}

impl Default for RiskThresholds {
    fn default() -> Self {
        RiskThresholds {
            warning: 15.0,
            pause: 35.0,
            kill: 50.0,
            dimension_critical: 90.0,
        }
    }
}

impl RiskScorer {
    pub fn new() -> Self {
        let mut event_scores = HashMap::new();

        // Identity events
        event_scores.insert("unusual_capability_request".to_string(),
            (RiskDimension::Identity, 20.0));
        event_scores.insert("admin_access_attempt".to_string(),
            (RiskDimension::Identity, 35.0));
        event_scores.insert("credential_access".to_string(),
            (RiskDimension::Identity, 15.0));
        event_scores.insert("token_reuse_attempt".to_string(),
            (RiskDimension::Identity, 25.0));
        event_scores.insert("impersonation_attempt".to_string(),
            (RiskDimension::Identity, 40.0));

        // Execution events
        event_scores.insert("dangerous_tool_call".to_string(),
            (RiskDimension::Execution, 25.0));
        event_scores.insert("sandbox_escape_attempt".to_string(),
            (RiskDimension::Execution, 50.0));
        event_scores.insert("unauthorized_code_exec".to_string(),
            (RiskDimension::Execution, 35.0));
        event_scores.insert("blocked_skill_install".to_string(),
            (RiskDimension::Execution, 20.0));

        // Persistence events
        event_scores.insert("config_modification".to_string(),
            (RiskDimension::Persistence, 30.0));
        event_scores.insert("new_scheduled_task".to_string(),
            (RiskDimension::Persistence, 25.0));
        event_scores.insert("state_tampering".to_string(),
            (RiskDimension::Persistence, 40.0));
        event_scores.insert("auto_restart_attempt".to_string(),
            (RiskDimension::Persistence, 20.0));

        // Exfiltration events
        event_scores.insert("external_data_send".to_string(),
            (RiskDimension::Exfiltration, 20.0));
        event_scores.insert("large_data_transfer".to_string(),
            (RiskDimension::Exfiltration, 40.0));
        event_scores.insert("blocked_egress_attempt".to_string(),
            (RiskDimension::Exfiltration, 30.0));
        event_scores.insert("credential_exfil_attempt".to_string(),
            (RiskDimension::Exfiltration, 50.0));

        println!("[RISK] Scorer initialized | {} event types | Thresholds: W={} P={} K={}",
            event_scores.len(),
            RiskThresholds::default().warning,
            RiskThresholds::default().pause,
            RiskThresholds::default().kill);

        RiskScorer {
            agents: HashMap::new(),
            thresholds: RiskThresholds::default(),
            event_scores,
        }
    }

    pub fn record_event(&mut self, agent_id: &str, event_type: &str, description: &str) -> RiskAction {
        let (dimension, score) = match self.event_scores.get(event_type) {
            Some((d, s)) => (d.clone(), *s),
            None => {
                println!("[RISK] Unknown event type: {}", event_type);
                return RiskAction::Normal;
            }
        };

        let risk = self.agents.entry(agent_id.to_string())
            .or_insert_with(|| AgentRisk::new(agent_id));

        // Apply score to dimension
        match dimension {
            RiskDimension::Identity => risk.identity = (risk.identity + score).min(100.0),
            RiskDimension::Execution => risk.execution = (risk.execution + score).min(100.0),
            RiskDimension::Persistence => risk.persistence = (risk.persistence + score).min(100.0),
            RiskDimension::Exfiltration => risk.exfiltration = (risk.exfiltration + score).min(100.0),
        }

        risk.last_updated = Utc::now();

        let event = RiskEvent {
            event_type: event_type.to_string(),
            agent_id: agent_id.to_string(),
            description: description.to_string(),
            dimension: dimension.clone(),
            score_impact: score,
            timestamp: Utc::now(),
        };
        risk.events.push(event);

        let action = risk.action();
        println!("[RISK] Event: {} | Agent: {} | {:?} +{:.0} | Total: {:.1} | Action: {:?}",
            event_type, agent_id, dimension, score, risk.total_score(), action);

        action
    }

    pub fn get_risk(&self, agent_id: &str) -> Option<&AgentRisk> {
        self.agents.get(agent_id)
    }

    pub fn report(&self, agent_id: &str) {
        match self.agents.get(agent_id) {
            Some(risk) => {
                println!("[RISK] ┌─ Risk Report: {} ─────────────────", agent_id);
                println!("[RISK] │ Identity:     {:5.1}/100", risk.identity);
                println!("[RISK] │ Execution:    {:5.1}/100", risk.execution);
                println!("[RISK] │ Persistence:  {:5.1}/100", risk.persistence);
                println!("[RISK] │ Exfiltration: {:5.1}/100", risk.exfiltration);
                println!("[RISK] │ ─────────────────────────────────");
                println!("[RISK] │ TOTAL:        {:5.1}/100", risk.total_score());
                println!("[RISK] │ MAX DIM:      {:5.1}/100", risk.max_dimension());
                println!("[RISK] │ ACTION:       {:?}", risk.action());
                println!("[RISK] │ EVENTS:       {}", risk.events.len());
                println!("[RISK] └──────────────────────────────────");
            }
            None => println!("[RISK] No data for agent: {}", agent_id),
        }
    }

    pub fn reset_agent(&mut self, agent_id: &str) {
        self.agents.remove(agent_id);
        println!("[RISK] Reset: {}", agent_id);
    }

    pub fn high_risk_agents(&self) -> Vec<&str> {
        self.agents.iter()
            .filter(|(_, r)| r.action() == RiskAction::Pause || r.action() == RiskAction::Kill)
            .map(|(id, _)| id.as_str())
            .collect()
    }

    pub fn status(&self) {
        let high = self.high_risk_agents().len();
        println!("[RISK] Monitoring: {} agents | {} high risk",
            self.agents.len(), high);
    }
}