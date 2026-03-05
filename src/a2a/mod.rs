use std::collections::HashMap;
use chrono::{DateTime, Utc};
use uuid::Uuid;

// ─── Agent Card (A2A Identity) ───
#[derive(Debug, Clone)]
pub struct AgentCard {
    pub agent_id: String,
    pub name: String,
    pub description: String,
    pub capabilities: Vec<String>,
    pub trust_level: TrustLevel,
    pub endpoint: String,
    pub registered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TrustLevel {
    Internal,
    Trusted,
    Restricted,
    Untrusted,
}

// ─── A2A Message ───
#[derive(Debug, Clone)]
pub struct A2aMessage {
    pub id: String,
    pub from: String,
    pub to: String,
    pub msg_type: A2aMessageType,
    pub payload: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum A2aMessageType {
    TaskRequest,
    TaskResponse,
    StatusQuery,
    StatusResponse,
    Capability,
    Error,
}

impl A2aMessage {
    pub fn new(from: &str, to: &str, msg_type: A2aMessageType, payload: &str) -> Self {
        A2aMessage {
            id: format!("a2a-{}", Uuid::new_v4()),
            from: from.to_string(),
            to: to.to_string(),
            msg_type,
            payload: payload.to_string(),
            timestamp: Utc::now(),
        }
    }
}

// ─── A2A Policy Check Result ───
#[derive(Debug, PartialEq)]
pub enum A2aResult {
    Allowed,
    Blocked { reason: String },
}

// ─── A2A Gateway ───
pub struct A2aGateway {
    port: u16,
    agents: HashMap<String, AgentCard>,
    message_log: Vec<A2aMessage>,
    max_message_size: usize,
    running: bool,
}

impl A2aGateway {
    pub fn new(port: u16) -> Self {
        println!("[A2A] Gateway created on port {}", port);
        A2aGateway {
            port,
            agents: HashMap::new(),
            message_log: Vec::new(),
            max_message_size: 65536,
            running: false,
        }
    }

    pub fn start(&mut self) {
        self.running = true;
        println!("[A2A] Gateway started | Port: {} | Agents: {}",
            self.port, self.agents.len());
    }

    // Register an agent
    pub fn register_agent(&mut self, card: AgentCard) {
        println!("[A2A] Agent registered: {} ({}) | Trust: {:?}",
            card.name, card.agent_id, card.trust_level);
        self.agents.insert(card.agent_id.clone(), card);
    }

    // Policy check before routing message
    fn check_policy(&self, msg: &A2aMessage) -> A2aResult {
        // Check sender exists
        let sender = match self.agents.get(&msg.from) {
            Some(a) => a,
            None => return A2aResult::Blocked {
                reason: format!("Unknown sender: {}", msg.from),
            },
        };

        // Check receiver exists
        if !self.agents.contains_key(&msg.to) {
            return A2aResult::Blocked {
                reason: format!("Unknown receiver: {}", msg.to),
            };
        }

        // Check trust level
        if sender.trust_level == TrustLevel::Untrusted {
            return A2aResult::Blocked {
                reason: format!("Sender {} is untrusted", msg.from),
            };
        }

        // Restricted agents can only send StatusQuery
        if sender.trust_level == TrustLevel::Restricted
            && msg.msg_type != A2aMessageType::StatusQuery
        {
            return A2aResult::Blocked {
                reason: format!("Restricted agent {} can only query status", msg.from),
            };
        }

        // Message size check
        if msg.payload.len() > self.max_message_size {
            return A2aResult::Blocked {
                reason: format!("Message too large: {} bytes", msg.payload.len()),
            };
        }

        A2aResult::Allowed
    }

    // Route message between agents
    pub fn route_message(&mut self, msg: A2aMessage) -> A2aResult {
        if !self.running {
            return A2aResult::Blocked { reason: "Gateway not running".to_string() };
        }

        println!("[A2A] Routing: {} -> {} | Type: {:?}",
            msg.from, msg.to, msg.msg_type);

        // Policy check
        let result = self.check_policy(&msg);
        match &result {
            A2aResult::Allowed => {
                println!("[A2A] ALLOWED: {} -> {}", msg.from, msg.to);
                self.message_log.push(msg);
            }
            A2aResult::Blocked { reason } => {
                println!("[A2A] BLOCKED: {} -> {} | {}", msg.from, msg.to, reason);
            }
        }
        result
    }

    // List registered agents
    pub fn list_agents(&self) {
        println!("[A2A] Registered agents: {}", self.agents.len());
        for agent in self.agents.values() {
            println!("[A2A]   {} ({}) | Trust: {:?} | Caps: {:?}",
                agent.name, agent.agent_id, agent.trust_level, agent.capabilities);
        }
    }

    pub fn message_count(&self) -> usize {
        self.message_log.len()
    }

    pub fn status(&self) {
        println!("[A2A] Status: {} | Port: {} | Agents: {} | Messages: {}",
            if self.running { "RUNNING" } else { "STOPPED" },
            self.port, self.agents.len(), self.message_log.len());
    }
}