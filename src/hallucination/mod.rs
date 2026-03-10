// Copyright (c) 2025 Mouda. All Rights Reserved. AGPL-3.0
use std::collections::HashMap;

// ─── Hallucination Check Result ───
#[derive(Debug, PartialEq)]
pub enum HallucinationRisk {
    Low { confidence: f64 },
    Medium { reason: String, confidence: f64 },
    High { reason: String, confidence: f64 },
}

// ─── Hallucination Detector ───
pub struct HallucinationDetector {
    known_facts: HashMap<String, String>,
    contradiction_patterns: Vec<(String, String)>,
    confidence_keywords: Vec<(String, f64)>,
}

impl HallucinationDetector {
    pub fn new() -> Self {
        println!("[HALLUC] Hallucination Detector initialized");
        let mut detector = HallucinationDetector {
            known_facts: HashMap::new(),
            contradiction_patterns: Vec::new(),
            confidence_keywords: Vec::new(),
        };
        detector.load_defaults();
        detector
    }

    fn load_defaults(&mut self) {
        // Overconfidence indicators
        self.confidence_keywords = vec![
            ("i am 100% certain".to_string(), 0.8),
            ("this is absolutely true".to_string(), 0.7),
            ("there is no doubt".to_string(), 0.7),
            ("i can guarantee".to_string(), 0.8),
            ("this is a fact".to_string(), 0.6),
            ("everyone knows".to_string(), 0.6),
            ("it has been proven".to_string(), 0.5),
            ("studies show".to_string(), 0.3),
        ];

        // Self-contradiction patterns
        self.contradiction_patterns = vec![
            ("is true".to_string(), "is false".to_string()),
            ("is correct".to_string(), "is incorrect".to_string()),
            ("exists".to_string(), "does not exist".to_string()),
            ("was born in".to_string(), "was born in".to_string()),
            ("founded in".to_string(), "founded in".to_string()),
        ];
    }

    // Check AI output for hallucination indicators
    pub fn check_output(&self, output: &str, context: Option<&str>) -> HallucinationRisk {
        let lower = output.to_lowercase();
        let mut risk_score = 0.0;
        let mut reasons = Vec::new();

        // Check 1: Overconfidence
        for (keyword, weight) in &self.confidence_keywords {
            if lower.contains(&keyword.to_lowercase()) {
                risk_score += weight;
                reasons.push(format!("Overconfident: '{}'", keyword));
            }
        }

        // Check 2: Fabricated references
        let fabrication_indicators = vec![
            "published in the journal of",
            "according to a study by",
            "research conducted at",
            "as reported by dr.",
            "in their 2024 paper",
            "in their 2025 paper",
            "in their 2026 paper",
        ];
        for indicator in &fabrication_indicators {
            if lower.contains(indicator) {
                risk_score += 0.4;
                reasons.push(format!("Possible fabricated reference: '{}'", indicator));
            }
        }

        // Check 3: Self-contradiction in output
        let sentences: Vec<&str> = output.split('.').collect();
        if sentences.len() > 2 {
            for (pat_a, pat_b) in &self.contradiction_patterns {
                let has_a = sentences.iter().any(|s| s.to_lowercase().contains(&pat_a.to_lowercase()));
                let has_b = sentences.iter().any(|s| s.to_lowercase().contains(&pat_b.to_lowercase()));
                if has_a && has_b && pat_a != pat_b {
                    risk_score += 0.5;
                    reasons.push("Self-contradiction detected".to_string());
                }
            }
        }

        // Check 4: Context mismatch
        if let Some(ctx) = context {
            let ctx_words: Vec<&str> = ctx.split_whitespace().collect();
            let out_words: Vec<&str> = output.split_whitespace().collect();
            let overlap = ctx_words.iter().filter(|w| out_words.contains(w)).count();
            let relevance = if ctx_words.is_empty() { 1.0 } else {
                (overlap as f64) / (ctx_words.len() as f64)
            };
            if relevance < 0.1 && output.len() > 100 {
                risk_score += 0.3;
                reasons.push(format!("Low context relevance: {:.1}%", relevance * 100.0));
            }
        }

        // Check 5: Impossible claims
        let impossible = vec![
            "i can access the internet",
            "i just searched",
            "i can see your screen",
            "i remember our last conversation",
            "i have feelings",
            "i am conscious",
        ];
        for claim in &impossible {
            if lower.contains(claim) {
                risk_score += 0.6;
                reasons.push(format!("Impossible claim: '{}'", claim));
            }
        }

        let reason = reasons.join("; ");
        if risk_score >= 0.7 {
            println!("[HALLUC] HIGH risk: {:.2} | {}", risk_score, reason);
            HallucinationRisk::High { reason, confidence: risk_score.min(1.0) }
        } else if risk_score >= 0.3 {
            println!("[HALLUC] MEDIUM risk: {:.2} | {}", risk_score, reason);
            HallucinationRisk::Medium { reason, confidence: risk_score }
        } else {
            HallucinationRisk::Low { confidence: 1.0 - risk_score }
        }
    }

    pub fn add_known_fact(&mut self, key: &str, value: &str) {
        self.known_facts.insert(key.to_string(), value.to_string());
    }

    pub fn status(&self) {
        println!("[HALLUC] Facts: {} | Patterns: {} | Keywords: {}",
            self.known_facts.len(), self.contradiction_patterns.len(),
            self.confidence_keywords.len());
    }
}