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

    fn compute_hash(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())[..16].to_string()
    }

    fn compute_signature(&self, content_hash: &str, agent_id: &str, timestamp: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!("{}:{}:{}:{}", self.secret_key, content_hash, agent_id, timestamp).as_bytes());
        format!("{:x}", hasher.finalize())[..32].to_string()
    }

    // Watermark AI-generated content
    pub fn stamp(&mut self, content: &str, agent_id: &str, model: &str, provider: &str) -> AiWatermark {
        let now = Utc::now();
        let content_hash = Self::compute_hash(content);
        let signature = self.compute_signature(&content_hash, agent_id, &now.to_rfc3339());

        let watermark = AiWatermark {
            content_hash: content_hash.clone(),
            agent_id: agent_id.to_string(),
            model: model.to_string(),
            provider: provider.to_string(),
            timestamp: now,
            signature,
            aegis_version: "4.0.0".to_string(),
        };

        println!("[WATERMARK] Stamped: agent={} | model={} | hash={}",
            agent_id, model, content_hash);
        self.watermarks.push(watermark.clone());
        watermark
    }

    // Verify watermark authenticity
    pub fn verify(&self, content: &str, watermark: &AiWatermark) -> WatermarkVerification {
        let content_hash = Self::compute_hash(content);

        // Check content hash
        if content_hash != watermark.content_hash {
            println!("[WATERMARK] INVALID: content modified");
            return WatermarkVerification::Invalid {
                reason: "Content has been modified".to_string(),
            };
        }

        // Check signature
        let expected_sig = self.compute_signature(
            &content_hash, &watermark.agent_id, &watermark.timestamp.to_rfc3339());
        if expected_sig != watermark.signature {
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