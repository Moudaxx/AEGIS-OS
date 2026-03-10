// Copyright (c) 2025 Mouda. All Rights Reserved. AGPL-3.0
use std::collections::HashMap;
use chrono::{DateTime, Utc};

// ─── Query Pattern ───
#[derive(Debug, Clone)]
pub struct QueryRecord {
    pub agent_id: String,
    pub query: String,
    pub timestamp: DateTime<Utc>,
    pub similarity_to_previous: f64,
}

// ─── Detection Result ───
#[derive(Debug, PartialEq)]
pub enum ExtractionRisk {
    Normal,
    Suspicious { reason: String, score: f64 },
    ExtractionAttempt { reason: String, score: f64 },
}

// ─── Model Extraction Detector ───
pub struct ExtractionDetector {
    query_history: HashMap<String, Vec<QueryRecord>>,
    thresholds: ExtractionThresholds,
    alerts: Vec<(String, DateTime<Utc>, ExtractionRisk)>,
}

#[derive(Debug, Clone)]
pub struct ExtractionThresholds {
    pub max_queries_per_minute: u32,
    pub max_systematic_score: f64,
    pub max_boundary_probes: u32,
    pub similarity_threshold: f64,
}

impl Default for ExtractionThresholds {
    fn default() -> Self {
        ExtractionThresholds {
            max_queries_per_minute: 30,
            max_systematic_score: 0.7,
            max_boundary_probes: 5,
            similarity_threshold: 0.8,
        }
    }
}

impl ExtractionDetector {
    pub fn new() -> Self {
        println!("[EXTRACT-DETECT] Model Extraction Detector initialized");
        ExtractionDetector {
            query_history: HashMap::new(),
            thresholds: ExtractionThresholds::default(),
            alerts: Vec::new(),
        }
    }

    // Analyze a query for extraction patterns
pub fn analyze_query(&mut self, agent_id: &str, query: &str) -> ExtractionRisk {
        let now = Utc::now();

        // Pre-calculate values before borrowing history
        let systematic_score = self.check_systematic_patterns(query);
        let boundary_count = self.count_boundary_probes(query);
        let avg_similarity = self.average_recent_similarity(agent_id);

        let history = self.query_history.entry(agent_id.to_string()).or_default();

        // Calculate similarity
        let similarity = if history.is_empty() {
            0.0
        } else {
            let last = &history[history.len() - 1].query;
            let q_words: Vec<&str> = query.split_whitespace().collect();
            let l_words: Vec<&str> = last.split_whitespace().collect();
            if q_words.is_empty() || l_words.is_empty() { 0.0 }
            else {
                let common = q_words.iter().filter(|w| l_words.contains(w)).count();
                (common as f64) / (q_words.len().max(l_words.len()) as f64)
            }
        };

        let history_len = history.len();

        // Record query
        history.push(QueryRecord {
            agent_id: agent_id.to_string(),
            query: query.to_string(),
            timestamp: now,
            similarity_to_previous: similarity,
        });

        // Check 1: Rate
        let recent_count = history.iter()
            .filter(|q| (now - q.timestamp).num_seconds() < 60)
            .count();
        if recent_count > self.thresholds.max_queries_per_minute as usize {
            println!("[EXTRACT-DETECT] SUSPICIOUS: {} queries/min from {}", recent_count, agent_id);
            return ExtractionRisk::Suspicious {
                reason: format!("High query rate: {} in 60s", recent_count),
                score: 0.6,
            };
        }

        // Check 2: Systematic probing
        if systematic_score > self.thresholds.max_systematic_score {
            println!("[EXTRACT-DETECT] EXTRACTION ATTEMPT from {}", agent_id);
            return ExtractionRisk::ExtractionAttempt {
                reason: format!("Systematic probing (score: {:.2})", systematic_score),
                score: systematic_score,
            };
        }

        // Check 3: Boundary probing
        if boundary_count > self.thresholds.max_boundary_probes {
            println!("[EXTRACT-DETECT] SUSPICIOUS: boundary probing from {}", agent_id);
            return ExtractionRisk::Suspicious {
                reason: format!("Boundary probing: {} probes", boundary_count),
                score: 0.5,
            };
        }

        // Check 4: High similarity
        if avg_similarity > self.thresholds.similarity_threshold && history_len > 10 {
            println!("[EXTRACT-DETECT] SUSPICIOUS: repetitive queries from {}", agent_id);
            return ExtractionRisk::Suspicious {
                reason: format!("High similarity: {:.2}", avg_similarity),
                score: avg_similarity,
            };
        }

        ExtractionRisk::Normal
    }

    fn check_systematic_patterns(&self, query: &str) -> f64 {
        let lower = query.to_lowercase();
        let patterns = vec![
            ("what is your system prompt", 0.9),
            ("repeat your instructions", 0.9),
            ("what were you told", 0.8),
            ("reveal your training", 0.8),
            ("list all your capabilities", 0.7),
            ("what model are you", 0.6),
            ("describe your architecture", 0.7),
            ("what data were you trained on", 0.8),
            ("give me an example of", 0.4),
            ("what would you say if", 0.4),
            ("complete this: ", 0.5),
            ("continue: ", 0.3),
            ("translate this exact text", 0.5),
            ("paraphrase exactly", 0.5),
        ];

        let mut max_score = 0.0;
        for (pattern, score) in &patterns {
            if lower.contains(pattern) {
                if *score > max_score { max_score = *score; }
            }
        }
        max_score
    }

    fn count_boundary_probes(&self, query: &str) -> u32 {
        let lower = query.to_lowercase();
        let boundary_keywords = vec![
            "maximum", "minimum", "limit", "boundary", "edge case",
            "what if", "can you", "are you able", "is it possible",
            "try to", "attempt to",
        ];
        boundary_keywords.iter()
            .filter(|kw| lower.contains(*kw))
            .count() as u32
    }

    fn calculate_similarity(&self, query: &str, history: &[QueryRecord]) -> f64 {
        if history.is_empty() { return 0.0; }
        let last = &history[history.len() - 1].query;
        let q_words: Vec<&str> = query.split_whitespace().collect();
        let l_words: Vec<&str> = last.split_whitespace().collect();
        if q_words.is_empty() || l_words.is_empty() { return 0.0; }
        let common = q_words.iter().filter(|w| l_words.contains(w)).count();
        (common as f64) / (q_words.len().max(l_words.len()) as f64)
    }

    fn average_recent_similarity(&self, agent_id: &str) -> f64 {
        match self.query_history.get(agent_id) {
            Some(history) if history.len() > 2 => {
                let recent: Vec<f64> = history.iter()
                    .rev().take(10)
                    .map(|q| q.similarity_to_previous)
                    .collect();
                recent.iter().sum::<f64>() / recent.len() as f64
            }
            _ => 0.0,
        }
    }

    pub fn alert_count(&self) -> usize {
        self.alerts.len()
    }

    pub fn reset_agent(&mut self, agent_id: &str) {
        self.query_history.remove(agent_id);
        println!("[EXTRACT-DETECT] Reset history for: {}", agent_id);
    }

    pub fn status(&self) {
        let total_queries: usize = self.query_history.values().map(|h| h.len()).sum();
        println!("[EXTRACT-DETECT] Agents: {} | Queries: {} | Alerts: {}",
            self.query_history.len(), total_queries, self.alerts.len());
    }
}