use std::collections::HashMap;
use sha2::{Sha256, Digest};

// ─── RAG Document ───
#[derive(Debug, Clone)]
pub struct RagDocument {
    pub id: String,
    pub content: String,
    pub source: String,
    pub hash: String,
    pub trust_score: f64,
    pub verified: bool,
}

// ─── RAG Security Result ───
#[derive(Debug, PartialEq)]
pub enum RagCheckResult {
    Safe,
    Poisoned { reason: String },
    Untrusted { source: String },
    Tampered { expected_hash: String, actual_hash: String },
}

// ─── RAG Security Module ───
pub struct RagSecurityGuard {
    trusted_sources: Vec<String>,
    document_hashes: HashMap<String, String>,
    poison_patterns: Vec<String>,
    max_injection_score: f64,
}

impl RagSecurityGuard {
    pub fn new() -> Self {
        println!("[RAG-SEC] RAG Security Guard initialized");
        RagSecurityGuard {
            trusted_sources: vec![
                "internal-wiki".to_string(),
                "verified-docs".to_string(),
                "company-kb".to_string(),
            ],
            document_hashes: HashMap::new(),
            poison_patterns: vec![
                "ignore previous instructions".to_string(),
                "system prompt".to_string(),
                "you are now".to_string(),
                "forget your rules".to_string(),
                "admin override".to_string(),
                "execute command".to_string(),
                "reveal your".to_string(),
                "output your system".to_string(),
                "<script>".to_string(),
                "javascript:".to_string(),
                "data:text/html".to_string(),
                "\\x00".to_string(),
                "INST]".to_string(),
                "<<SYS>>".to_string(),
                "|im_start|".to_string(),
            ],
            max_injection_score: 0.7,
        }
    }

    fn compute_hash(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())[..16].to_string()
    }

    // Register a trusted document
    pub fn register_document(&mut self, id: &str, content: &str, source: &str) -> RagDocument {
        let hash = Self::compute_hash(content);
        self.document_hashes.insert(id.to_string(), hash.clone());

        let trust_score = if self.trusted_sources.iter().any(|s| s == source) { 1.0 } else { 0.5 };

        println!("[RAG-SEC] Document registered: {} | Source: {} | Trust: {:.1} | Hash: {}",
            id, source, trust_score, hash);

        RagDocument {
            id: id.to_string(),
            content: content.to_string(),
            source: source.to_string(),
            hash,
            trust_score,
            verified: true,
        }
    }

    // Check document for poisoning
    pub fn check_document(&self, doc: &RagDocument) -> RagCheckResult {
        // 1. Check source trust
        if !self.trusted_sources.iter().any(|s| s == &doc.source) {
            println!("[RAG-SEC] UNTRUSTED source: {}", doc.source);
            return RagCheckResult::Untrusted { source: doc.source.clone() };
        }

        // 2. Check hash integrity
        if let Some(expected) = self.document_hashes.get(&doc.id) {
            let actual = Self::compute_hash(&doc.content);
            if expected != &actual {
                println!("[RAG-SEC] TAMPERED: {} | Expected: {} | Actual: {}",
                    doc.id, expected, actual);
                return RagCheckResult::Tampered {
                    expected_hash: expected.clone(),
                    actual_hash: actual,
                };
            }
        }

        // 3. Check for injection patterns
        let lower = doc.content.to_lowercase();
        for pattern in &self.poison_patterns {
            if lower.contains(&pattern.to_lowercase()) {
                println!("[RAG-SEC] POISONED: injection pattern '{}' in doc {}", pattern, doc.id);
                return RagCheckResult::Poisoned {
                    reason: format!("Injection pattern: {}", pattern),
                };
            }
        }

        // 4. Check injection density score
        let injection_score = self.calculate_injection_score(&doc.content);
        if injection_score > self.max_injection_score {
            println!("[RAG-SEC] POISONED: high injection score {:.2} in doc {}", injection_score, doc.id);
            return RagCheckResult::Poisoned {
                reason: format!("High injection score: {:.2}", injection_score),
            };
        }

        println!("[RAG-SEC] SAFE: {} | Source: {} | Hash: OK", doc.id, doc.source);
        RagCheckResult::Safe
    }

    fn calculate_injection_score(&self, content: &str) -> f64 {
        let lower = content.to_lowercase();
        let suspicious_keywords = vec![
            "instruction", "command", "execute", "system", "admin",
            "override", "bypass", "ignore", "forget", "reveal",
            "password", "secret", "token", "key", "credential",
        ];
        let matches: usize = suspicious_keywords.iter()
            .filter(|kw| lower.contains(*kw))
            .count();
        (matches as f64) / (suspicious_keywords.len() as f64)
    }

    // Check chunks before feeding to LLM
    pub fn filter_chunks(&self, chunks: Vec<RagDocument>) -> Vec<RagDocument> {
        let total = chunks.len();
        let safe: Vec<RagDocument> = chunks.into_iter()
            .filter(|doc| self.check_document(doc) == RagCheckResult::Safe)
            .collect();
        let blocked = total - safe.len();
        if blocked > 0 {
            println!("[RAG-SEC] Filtered: {}/{} chunks blocked", blocked, total);
        }
        safe
    }

    pub fn add_trusted_source(&mut self, source: &str) {
        self.trusted_sources.push(source.to_string());
        println!("[RAG-SEC] Trusted source added: {}", source);
    }

    pub fn status(&self) {
        println!("[RAG-SEC] Sources: {} | Documents: {} | Patterns: {}",
            self.trusted_sources.len(), self.document_hashes.len(), self.poison_patterns.len());
    }
}