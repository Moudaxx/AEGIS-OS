// Copyright (c) 2025 Mouda. All Rights Reserved. AGPL-3.0
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum AgentStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Terminated,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum IsolationMode {
    Wasm,
    Container,
    MicroVm,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Agent {
    pub id: Uuid,
    pub name: String,
    pub status: AgentStatus,
    pub isolation: IsolationMode,
    pub created_at: DateTime<Utc>,
    pub max_runtime_secs: u64,
    pub provider: String,
    pub ephemeral: bool,
}

impl Agent {
    pub fn new(name: &str, provider: &str) -> Self {
        Agent {
            id: Uuid::new_v4(),
            name: name.to_string(),
            status: AgentStatus::Pending,
            isolation: IsolationMode::Wasm,
            created_at: Utc::now(),
            max_runtime_secs: 1800,
            provider: provider.to_string(),
            ephemeral: true,
        }
    }

    pub fn start(&mut self) {
        self.status = AgentStatus::Running;
        println!("[AEGIS] Agent {} started | ID: {}", self.name, self.id);
    }

    pub fn terminate(&mut self) {
        self.status = AgentStatus::Terminated;
        println!("[AEGIS] Agent {} terminated | ID: {}", self.name, self.id);
        if self.ephemeral {
            println!("[AEGIS] Ephemeral agent destroyed | ID: {}", self.id);
        }
    }

    pub fn is_expired(&self) -> bool {
        let elapsed = Utc::now()
            .signed_duration_since(self.created_at)
            .num_seconds() as u64;
        elapsed > self.max_runtime_secs
    }

    pub fn summary(&self) {
        println!(
            "[AEGIS] Agent: {} | Status: {:?} | Provider: {} | Ephemeral: {} | ID: {}",
            self.name, self.status, self.provider, self.ephemeral, self.id
        );
    }
}