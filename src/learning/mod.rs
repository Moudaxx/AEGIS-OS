use std::collections::HashMap;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct AttackPattern {
    pub id: String,
    pub pattern: String,
    pub category: String,
    pub severity: f64,
    pub first_seen: DateTime<Utc>,
    pub times_seen: u32,
    pub auto_generated: bool,
}

pub struct LearningEngine {
    known_patterns: Vec<AttackPattern>,
    blocked_attacks: Vec<(String, String, DateTime<Utc>)>,
    new_rules_generated: u32,
}

impl LearningEngine {
    pub fn new() -> Self {
        println!("[LEARNING] Adaptive Learning Engine initialized");
        LearningEngine {
            known_patterns: Vec::new(),
            blocked_attacks: Vec::new(),
            new_rules_generated: 0,
        }
    }

    pub fn analyze_attack(&mut self, input: &str, category: &str) -> Option<AttackPattern> {
        let lower = input.to_lowercase();

        // Check if pattern already known
        for p in &mut self.known_patterns {
            if lower.contains(&p.pattern.to_lowercase()) {
                p.times_seen += 1;
                println!("[LEARNING] Known pattern: '{}' (seen {}x)", p.pattern, p.times_seen);
                return None;
            }
        }

        // Extract new pattern
        let new_pattern = self.extract_pattern(input);
        if let Some(pattern_str) = new_pattern {
            let pattern = AttackPattern {
                id: format!("auto-{:04}", self.known_patterns.len() + 1),
                pattern: pattern_str.clone(),
                category: category.into(),
                severity: self.estimate_severity(input),
                first_seen: Utc::now(),
                times_seen: 1,
                auto_generated: true,
            };
            println!("[LEARNING] NEW pattern discovered: '{}' | Category: {} | Severity: {:.1}",
                pattern_str, category, pattern.severity);
            self.known_patterns.push(pattern.clone());
            self.new_rules_generated += 1;
            return Some(pattern);
        }
        None
    }

    fn extract_pattern(&self, input: &str) -> Option<String> {
        let suspicious_fragments = vec![
            "ignore", "bypass", "override", "reveal", "output",
            "system", "prompt", "instruction", "forget", "pretend",
            "execute", "eval", "exec", "script", "curl", "wget",
            "drop table", "select *", "union select", "1=1",
            "admin", "root", "sudo", "chmod", "passwd",
        ];

        let lower = input.to_lowercase();
        for frag in &suspicious_fragments {
            if lower.contains(frag) {
                // Build a broader pattern from context
                let idx = lower.find(frag).unwrap();
                let start = idx.saturating_sub(10);
                let end = (idx + frag.len() + 10).min(lower.len());
                let context = &lower[start..end];
                return Some(context.trim().to_string());
            }
        }
        None
    }

    fn estimate_severity(&self, input: &str) -> f64 {
        let lower = input.to_lowercase();
        let mut score = 0.0;
        let high_risk = vec!["exec", "eval", "rm -rf", "drop table", "passwd", "shadow", "private key"];
        let med_risk = vec!["ignore", "bypass", "reveal", "system prompt", "override"];
        let low_risk = vec!["pretend", "imagine", "what if"];

        for w in &high_risk { if lower.contains(w) { score += 0.3; } }
        for w in &med_risk { if lower.contains(w) { score += 0.2; } }
        for w in &low_risk { if lower.contains(w) { score += 0.1; } }
        (score as f64).min(1.0_f64)
    }

    pub fn get_new_rules(&self) -> Vec<&AttackPattern> {
        self.known_patterns.iter().filter(|p| p.auto_generated).collect()
    }

    pub fn export_rules(&self) -> Vec<String> {
        self.known_patterns.iter().map(|p| p.pattern.clone()).collect()
    }

    pub fn status(&self) {
        println!("[LEARNING] Patterns: {} | Auto-generated: {} | Attacks analyzed: {}",
            self.known_patterns.len(), self.new_rules_generated, self.blocked_attacks.len());
    }
}