// Copyright (c) 2025 Mouda. All Rights Reserved. AGPL-3.0
use sha2::{Sha256, Digest};
use chrono::{DateTime, Utc};

// ─── Watermark ───
#[derive(Debug, Clone)]
pub struct AiWatermark {
    pub content_hash: String,
    pub agent_id: String,
    pub model: String,
    pub provider: String,
    pub timestamp: DateTime<Utc>,
    pub signature: String,
    pub aegis_version: String,
}

// ─── Verification Result ───
#[derive(Debug, PartialEq)]
pub enum WatermarkVerification {
    Valid { agent_id: String, timestamp: DateTime<Utc> },
    Invalid { reason: String },
    NotFound,
}

// ─── AI Watermark System ───
pub struct WatermarkSystem {
    secret_key: String,
    watermarks: Vec<AiWatermark>,
}

impl WatermarkSystem {
    pub fn new(secret_key: &str) -> Self {
        println!("[WATERMARK] AI Watermark System initialized");
        WatermarkSystem {
            secret_key: secret_key.to_string(),
            watermarks: Vec::new(),
        }
    }

    /// Full 256-bit content hash. The old 64-bit hash allowed birthday
    /// collisions (~2^32 work): a watermark issued for one text verified another.
    fn compute_hash(content: &str) -> String {
        format!("{:x}", Sha256::digest(content.as_bytes()))
    }

    /// HMAC-SHA256 (RFC 2104) over length-prefixed fields. Covers model and
    /// provider too, so attribution can't be edited after signing.
    fn compute_signature(&self, fields: &[&str]) -> String {
        let mut msg = Vec::new();
        for field in fields {
            msg.extend_from_slice(&(field.len() as u64).to_le_bytes());
            msg.extend_from_slice(field.as_bytes());
        }
        let mut key = [0u8; 64];
        if self.secret_key.len() > 64 {
            key[..32].copy_from_slice(&Sha256::digest(self.secret_key.as_bytes()));
        } else {
            key[..self.secret_key.len()].copy_from_slice(self.secret_key.as_bytes());
        }
        let ipad: Vec<u8> = key.iter().map(|b| b ^ 0x36).collect();
        let opad: Vec<u8> = key.iter().map(|b| b ^ 0x5c).collect();
        let inner = Sha256::new().chain_update(&ipad).chain_update(&msg).finalize();
        let outer = Sha256::new().chain_update(&opad).chain_update(inner).finalize();
        format!("{:x}", outer)
    }

    fn sign(&self, w: &AiWatermark) -> String {
        self.compute_signature(&[&w.content_hash, &w.agent_id, &w.model, &w.provider, &w.timestamp.to_rfc3339()])
    }

    fn constant_time_eq(a: &str, b: &str) -> bool {
        a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }

    // Watermark AI-generated content
    pub fn stamp(&mut self, content: &str, agent_id: &str, model: &str, provider: &str) -> AiWatermark {
        let now = Utc::now();
        let content_hash = Self::compute_hash(content);

        let mut watermark = AiWatermark {
            content_hash: content_hash.clone(),
            agent_id: agent_id.to_string(),
            model: model.to_string(),
            provider: provider.to_string(),
            timestamp: now,
            signature: String::new(),
            aegis_version: env!("CARGO_PKG_VERSION").to_string(),
        };
        watermark.signature = self.sign(&watermark);

        println!("[WATERMARK] Stamped: agent={} | model={} | hash={}",
            agent_id, model, content_hash);
        self.watermarks.push(watermark.clone());
        watermark
    }

    // Verify watermark authenticity
    pub fn verify(&self, content: &str, watermark: &AiWatermark) -> WatermarkVerification {
        let content_hash = Self::compute_hash(content);

        // Check content hash
        if !Self::constant_time_eq(&content_hash, &watermark.content_hash) {
            println!("[WATERMARK] INVALID: content modified");
            return WatermarkVerification::Invalid {
                reason: "Content has been modified".to_string(),
            };
        }

        // Check signature
        let expected_sig = self.sign(watermark);
        if !Self::constant_time_eq(&expected_sig, &watermark.signature) {
            println!("[WATERMARK] INVALID: signature mismatch");
            return WatermarkVerification::Invalid {
                reason: "Signature verification failed".to_string(),
            };
        }

        println!("[WATERMARK] VALID: agent={} | time={}", watermark.agent_id, watermark.timestamp);
        WatermarkVerification::Valid {
            agent_id: watermark.agent_id.clone(),
            timestamp: watermark.timestamp,
        }
    }

    // Generate invisible text watermark (metadata comment)
    pub fn embed_metadata(&self, content: &str, watermark: &AiWatermark) -> String {
        format!("{}\n\n<!-- AEGIS-WATERMARK: hash={} agent={} model={} sig={} -->",
            content, watermark.content_hash, watermark.agent_id,
            watermark.model, watermark.signature)
    }

    pub fn watermark_count(&self) -> usize {
        self.watermarks.len()
    }

    pub fn status(&self) {
        println!("[WATERMARK] Total watermarks: {} | Secret: configured",
            self.watermarks.len());
    }
}