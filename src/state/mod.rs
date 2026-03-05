use std::collections::HashMap;
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};

// ─── State Snapshot ───
#[derive(Debug, Clone)]
pub struct StateSnapshot {
    pub snapshot_id: String,
    pub agent_id: String,
    pub state_hash: String,
    pub config_hash: String,
    pub data: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
}

// ─── Drift Event ───
#[derive(Debug, Clone)]
pub struct DriftEvent {
    pub agent_id: String,
    pub field: String,
    pub expected: String,
    pub actual: String,
    pub severity: DriftSeverity,
    pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DriftSeverity {
    Low,
    Medium,
    High,
    Critical,
}

// ─── State Integrity Monitor ───
pub struct StateMonitor {
    snapshots: HashMap<String, Vec<StateSnapshot>>,
    drift_log: Vec<DriftEvent>,
    max_snapshots: usize,
    immutable_fields: Vec<String>,
}

impl StateMonitor {
    pub fn new() -> Self {
        println!("[STATE] Integrity Monitor initialized");
        StateMonitor {
            snapshots: HashMap::new(),
            drift_log: Vec::new(),
            max_snapshots: 100,
            immutable_fields: vec![
                "agent_id".to_string(),
                "isolation_mode".to_string(),
                "capabilities".to_string(),
                "max_runtime".to_string(),
                "credential_scope".to_string(),
            ],
        }
    }

    fn compute_hash(data: &HashMap<String, String>) -> String {
        let mut hasher = Sha256::new();
        let mut keys: Vec<&String> = data.keys().collect();
        keys.sort();
        for key in keys {
            hasher.update(key.as_bytes());
            hasher.update(data.get(key).unwrap().as_bytes());
        }
        format!("{:x}", hasher.finalize())[..16].to_string()
    }

    // Take a snapshot of agent state
    pub fn take_snapshot(&mut self, agent_id: &str, data: HashMap<String, String>) -> String {
        let state_hash = Self::compute_hash(&data);
        let config_hash = {
            let config_data: HashMap<String, String> = data.iter()
                .filter(|(k, _)| self.immutable_fields.contains(k))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            Self::compute_hash(&config_data)
        };

        let snapshot = StateSnapshot {
            snapshot_id: format!("snap-{}", state_hash),
            agent_id: agent_id.to_string(),
            state_hash: state_hash.clone(),
            config_hash,
            data,
            created_at: Utc::now(),
        };

        println!("[STATE] Snapshot: {} | Agent: {} | Hash: {}",
            snapshot.snapshot_id, agent_id, state_hash);

        let snaps = self.snapshots.entry(agent_id.to_string()).or_default();
        snaps.push(snapshot);

        // Keep only last N snapshots
        if snaps.len() > self.max_snapshots {
            snaps.remove(0);
        }

        state_hash
    }

    // Check for drift against last snapshot
    pub fn check_drift(&mut self, agent_id: &str, current: &HashMap<String, String>) -> Vec<DriftEvent> {
        let mut events = Vec::new();

        let last = match self.snapshots.get(agent_id).and_then(|s| s.last()) {
            Some(s) => s.clone(),
            None => {
                println!("[STATE] No previous snapshot for: {}", agent_id);
                return events;
            }
        };

        // Check each field
        for (key, old_value) in &last.data {
            match current.get(key) {
                Some(new_value) if new_value != old_value => {
                    let severity = if self.immutable_fields.contains(key) {
                        DriftSeverity::Critical
                    } else {
                        DriftSeverity::Low
                    };

                    let event = DriftEvent {
                        agent_id: agent_id.to_string(),
                        field: key.clone(),
                        expected: old_value.clone(),
                        actual: new_value.clone(),
                        severity: severity.clone(),
                        detected_at: Utc::now(),
                    };

                    println!("[STATE] DRIFT [{:?}]: {} | '{}' -> '{}'",
                        severity, key, old_value, new_value);
                    events.push(event);
                }
                None => {
                    let event = DriftEvent {
                        agent_id: agent_id.to_string(),
                        field: key.clone(),
                        expected: old_value.clone(),
                        actual: "[MISSING]".to_string(),
                        severity: DriftSeverity::High,
                        detected_at: Utc::now(),
                    };
                    println!("[STATE] DRIFT [High]: field '{}' missing!", key);
                    events.push(event);
                }
                _ => {}
            }
        }

        // Check for new unexpected fields
        for key in current.keys() {
            if !last.data.contains_key(key) {
                let event = DriftEvent {
                    agent_id: agent_id.to_string(),
                    field: key.clone(),
                    expected: "[NOT_EXIST]".to_string(),
                    actual: current.get(key).unwrap().clone(),
                    severity: DriftSeverity::Medium,
                    detected_at: Utc::now(),
                };
                println!("[STATE] DRIFT [Medium]: unexpected field '{}'", key);
                events.push(event);
            }
        }

        self.drift_log.extend(events.clone());

        if events.is_empty() {
            println!("[STATE] No drift detected for: {}", agent_id);
        }
        events
    }

    // Verify config integrity
    pub fn verify_config(&self, agent_id: &str, current: &HashMap<String, String>) -> bool {
        let last = match self.snapshots.get(agent_id).and_then(|s| s.last()) {
            Some(s) => s,
            None => return true,
        };

        let current_config: HashMap<String, String> = current.iter()
            .filter(|(k, _)| self.immutable_fields.contains(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let current_hash = Self::compute_hash(&current_config);

        if current_hash == last.config_hash {
            println!("[STATE] Config integrity VERIFIED: {}", agent_id);
            true
        } else {
            println!("[STATE] Config integrity FAILED: {} | Expected: {} | Got: {}",
                agent_id, last.config_hash, current_hash);
            false
        }
    }

    pub fn snapshot_count(&self, agent_id: &str) -> usize {
        self.snapshots.get(agent_id).map(|s| s.len()).unwrap_or(0)
    }

    pub fn drift_count(&self) -> usize {
        self.drift_log.len()
    }

    pub fn critical_drifts(&self) -> Vec<&DriftEvent> {
        self.drift_log.iter()
            .filter(|d| d.severity == DriftSeverity::Critical)
            .collect()
    }

    pub fn status(&self) {
        let total_snaps: usize = self.snapshots.values().map(|s| s.len()).sum();
        println!("[STATE] Monitor: {} agents | {} snapshots | {} drift events | {} critical",
            self.snapshots.len(), total_snaps, self.drift_log.len(),
            self.critical_drifts().len());
    }
}