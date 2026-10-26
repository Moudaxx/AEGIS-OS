// AEGIS OS — Alert System
// Copyright (c) 2025 AEGIS OS Contributors
// SPDX-License-Identifier: MIT OR AGPL-3.0

use chrono::Utc;
use std::collections::VecDeque;

/// Multi-channel alert system for security events.
pub struct AlertSystem {
    channels: Vec<AlertChannel>,
    history: VecDeque<Alert>,
    max_history: usize,
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub id: String,
    pub timestamp: String,
    pub severity: AlertSeverity,
    pub title: String,
    pub message: String,
    pub source: String,
    pub delivered_to: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    Info,
    Warning,
    High,
    Critical,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Info => write!(f, "INFO"),
            AlertSeverity::Warning => write!(f, "WARNING"),
            AlertSeverity::High => write!(f, "HIGH"),
            AlertSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum AlertChannel {
    Console,
    Webhook { url: String },
    Slack { webhook_url: String },
    Email { smtp_host: String, to: String },
}

impl std::fmt::Display for AlertChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertChannel::Console => write!(f, "console"),
            AlertChannel::Webhook { url } => write!(f, "webhook:{}", url),
            AlertChannel::Slack { .. } => write!(f, "slack"),
            AlertChannel::Email { to, .. } => write!(f, "email:{}", to),
        }
    }
}

impl AlertSystem {
    pub fn new() -> Self {
        println!("[ALERTS] Alert system initialized (console)");
        AlertSystem {
            channels: vec![AlertChannel::Console],
            history: VecDeque::new(),
            max_history: 500,
        }
    }

    pub fn add_channel(&mut self, channel: AlertChannel) {
        println!("[ALERTS] Added channel: {}", channel);
        self.channels.push(channel);
    }

    pub fn send(&mut self, severity: AlertSeverity, title: &str, message: &str, source: &str) {
        let alert_id = format!("ALT-{}", Utc::now().timestamp_millis());
        let mut delivered = Vec::new();

        for ch in &self.channels {
            match ch {
                AlertChannel::Console => {
                    let prefix = match severity {
                        AlertSeverity::Critical => "\x1b[31m[CRITICAL]\x1b[0m",
                        AlertSeverity::High     => "\x1b[33m[HIGH]\x1b[0m",
                        AlertSeverity::Warning  => "\x1b[93m[WARNING]\x1b[0m",
                        AlertSeverity::Info     => "\x1b[32m[INFO]\x1b[0m",
                    };
                    println!("{} {} — {} (src: {})", prefix, title, message, source);
                    delivered.push("console".to_string());
                }
                AlertChannel::Webhook { url } => {
                    // In production: POST JSON to url
                    println!("[ALERTS] Would POST to webhook: {}", url);
                    delivered.push(format!("webhook:{}", url));
                }
                AlertChannel::Slack { webhook_url } => {
                    // In production: POST Slack payload
                    println!("[ALERTS] Would POST to Slack: {}", webhook_url);
                    delivered.push("slack".to_string());
                }
                AlertChannel::Email { to, .. } => {
                    // In production: send SMTP email
                    println!("[ALERTS] Would email to: {}", to);
                    delivered.push(format!("email:{}", to));
                }
            }
        }

        if self.history.len() >= self.max_history {
            self.history.pop_front();
        }
        self.history.push_back(Alert {
            id: alert_id,
            timestamp: Utc::now().to_rfc3339(),
            severity,
            title: title.to_string(),
            message: message.to_string(),
            source: source.to_string(),
            delivered_to: delivered,
        });
    }

    /// Convenience methods
    pub fn critical(&mut self, title: &str, msg: &str, source: &str) {
        self.send(AlertSeverity::Critical, title, msg, source);
    }

    pub fn high(&mut self, title: &str, msg: &str, source: &str) {
        self.send(AlertSeverity::High, title, msg, source);
    }

    pub fn warning(&mut self, title: &str, msg: &str, source: &str) {
        self.send(AlertSeverity::Warning, title, msg, source);
    }

    pub fn info(&mut self, title: &str, msg: &str, source: &str) {
        self.send(AlertSeverity::Info, title, msg, source);
    }

    pub fn recent_alerts(&self, count: usize) -> Vec<&Alert> {
        self.history.iter().rev().take(count).collect()
    }

    pub fn alerts_by_severity(&self, min_severity: &AlertSeverity) -> Vec<&Alert> {
        self.history.iter().filter(|a| &a.severity >= min_severity).collect()
    }

    pub fn alert_count(&self) -> usize {
        self.history.len()
    }
}
