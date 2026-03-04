use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration};
use sha2::{Sha256, Digest};

#[derive(Debug, Clone)]
pub struct Credential {
    pub key: String,
    pub value: String,
    pub expires_at: DateTime<Utc>,
}

impl Credential {
    pub fn new(key: &str, value: &str, ttl_minutes: i64) -> Self {
        Credential {
            key: key.to_string(),
            value: value.to_string(),
            expires_at: Utc::now() + Duration::minutes(ttl_minutes),
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

pub struct CredentialVault {
    store: HashMap<String, Credential>,
}

impl CredentialVault {
    pub fn new() -> Self {
        CredentialVault {
            store: HashMap::new(),
        }
    }

    pub fn store(&mut self, key: &str, value: &str, ttl_minutes: i64) {
        let cred = Credential::new(key, value, ttl_minutes);
        println!("[AEGIS] Credential stored: {} | TTL: {}m", key, ttl_minutes);
        self.store.insert(key.to_string(), cred);
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        if let Some(cred) = self.store.get(key) {
            if cred.is_expired() {
                println!("[AEGIS] Credential expired: {}", key);
                return None;
            }
            return Some(&cred.value);
        }
        None
    }

    pub fn revoke(&mut self, key: &str) {
        self.store.remove(key);
        println!("[AEGIS] Credential revoked: {}", key);
    }
}

#[derive(Debug, Clone)]
pub struct CapabilityToken {
    pub token_id: String,
    pub agent_id: String,
    pub capabilities: Vec<String>,
    pub expires_at: DateTime<Utc>,
}

impl CapabilityToken {
    pub fn new(agent_id: &str, capabilities: Vec<String>, ttl_minutes: i64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(agent_id.as_bytes());
        hasher.update(Utc::now().to_string().as_bytes());
        let token_id = format!("{:x}", hasher.finalize())[..16].to_string();

        CapabilityToken {
            token_id,
            agent_id: agent_id.to_string(),
            capabilities,
            expires_at: Utc::now() + Duration::minutes(ttl_minutes),
        }
    }

    pub fn has_capability(&self, cap: &str) -> bool {
        if Utc::now() > self.expires_at {
            println!("[AEGIS] Token expired: {}", self.token_id);
            return false;
        }
        self.capabilities.contains(&cap.to_string())
    }

    pub fn summary(&self) {
        println!("[AEGIS] Token: {} | Agent: {} | Caps: {:?}",
            self.token_id, self.agent_id, self.capabilities);
    }
}