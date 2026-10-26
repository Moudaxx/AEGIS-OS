// AEGIS OS — WebSocket Live Dashboard
// Copyright (c) 2025 AEGIS OS Contributors
// SPDX-License-Identifier: MIT OR AGPL-3.0

use chrono::Utc;
use std::collections::VecDeque;
use std::fs;

/// Real-time WebSocket dashboard for live security monitoring.
pub struct WsDashboard {
    metrics: LiveMetrics,
    events: VecDeque<LiveEvent>,
    max_events: usize,
}

#[derive(Debug, Clone)]
pub struct LiveMetrics {
    pub active_agents: usize,
    pub threats_per_minute: f64,
    pub block_rate: f64,
    pub uptime_secs: u64,
    pub last_scan: String,
    pub risk_level: String,
}

#[derive(Debug, Clone)]
pub struct LiveEvent {
    pub timestamp: String,
    pub severity: EventSeverity,
    pub source: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EventSeverity {
    Info,
    Warning,
    High,
    Critical,
}

impl std::fmt::Display for EventSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventSeverity::Info => write!(f, "INFO"),
            EventSeverity::Warning => write!(f, "WARN"),
            EventSeverity::High => write!(f, "HIGH"),
            EventSeverity::Critical => write!(f, "CRIT"),
        }
    }
}

impl WsDashboard {
    pub fn new() -> Self {
        println!("[WS-DASHBOARD] Live dashboard engine initialized");
        WsDashboard {
            metrics: LiveMetrics {
                active_agents: 0,
                threats_per_minute: 0.0,
                block_rate: 0.0,
                uptime_secs: 0,
                last_scan: "never".to_string(),
                risk_level: "LOW".to_string(),
            },
            events: VecDeque::new(),
            max_events: 100,
        }
    }

    pub fn update_metrics(&mut self, active_agents: usize, threats_per_min: f64,
                          block_rate: f64, uptime: u64) {
        self.metrics.active_agents = active_agents;
        self.metrics.threats_per_minute = threats_per_min;
        self.metrics.block_rate = block_rate;
        self.metrics.uptime_secs = uptime;
        self.metrics.last_scan = Utc::now().to_rfc3339();
        self.metrics.risk_level = if threats_per_min > 10.0 {
            "CRITICAL".to_string()
        } else if threats_per_min > 5.0 {
            "HIGH".to_string()
        } else if threats_per_min > 1.0 {
            "MEDIUM".to_string()
        } else {
            "LOW".to_string()
        };
    }

    pub fn push_event(&mut self, severity: EventSeverity, source: &str, message: &str) {
        if self.events.len() >= self.max_events {
            self.events.pop_front();
        }
        self.events.push_back(LiveEvent {
            timestamp: Utc::now().to_rfc3339(),
            severity,
            source: source.to_string(),
            message: message.to_string(),
        });
    }

    pub fn get_metrics(&self) -> &LiveMetrics {
        &self.metrics
    }

    pub fn recent_events(&self, count: usize) -> Vec<&LiveEvent> {
        self.events.iter().rev().take(count).collect()
    }

    /// Generate a live HTML dashboard page with auto-refresh.
    pub fn generate_live_html(&self) -> String {
        let severity_color = |s: &EventSeverity| -> &str {
            match s {
                EventSeverity::Info => "#4ade80",
                EventSeverity::Warning => "#fbbf24",
                EventSeverity::High => "#f97316",
                EventSeverity::Critical => "#ef4444",
            }
        };

        let mut events_html = String::new();
        for ev in self.events.iter().rev().take(20) {
            events_html.push_str(&format!(
                "<tr><td>{}</td><td style=\"color:{}\">{}</td><td>{}</td><td>{}</td></tr>\n",
                &ev.timestamp[11..19],
                severity_color(&ev.severity),
                ev.severity,
                ev.source,
                ev.message,
            ));
        }

        format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<title>AEGIS OS — Live Dashboard</title>
<style>
  body {{ background:#0a0a0a; color:#e0e0e0; font-family:'Segoe UI',sans-serif; margin:20px; }}
  h1 {{ color:#00ff88; }}
  .live {{ color:#00ff88; animation:blink 1s infinite; }}
  @keyframes blink {{ 50% {{ opacity:0.3; }} }}
  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:16px; margin:20px 0; }}
  .card {{ background:#1a1a2e; border-radius:12px; padding:20px; text-align:center; }}
  .card .value {{ font-size:2em; font-weight:bold; color:#00ff88; }}
  .card .label {{ color:#888; margin-top:8px; }}
  table {{ width:100%; border-collapse:collapse; margin-top:20px; }}
  th,td {{ padding:8px 12px; text-align:left; border-bottom:1px solid #222; }}
  th {{ color:#00ff88; }}
</style>
</head>
<body>
<h1>AEGIS OS <span class="live">LIVE</span></h1>
<div class="cards">
  <div class="card"><div class="value">{}</div><div class="label">Active Agents</div></div>
  <div class="card"><div class="value">{:.1}/min</div><div class="label">Threats</div></div>
  <div class="card"><div class="value">{:.1}%</div><div class="label">Block Rate</div></div>
  <div class="card"><div class="value">{}</div><div class="label">Risk Level</div></div>
  <div class="card"><div class="value">{}s</div><div class="label">Uptime</div></div>
</div>
<h2>Recent Events</h2>
<table>
<tr><th>Time</th><th>Severity</th><th>Source</th><th>Message</th></tr>
{}
</table>
<p style="color:#555;margin-top:30px;">Auto-refresh: 5s | AEGIS OS v4.1</p>
</body>
</html>"#,
            self.metrics.active_agents,
            self.metrics.threats_per_minute,
            self.metrics.block_rate,
            self.metrics.risk_level,
            self.metrics.uptime_secs,
            events_html,
        )
    }

    pub fn save_live_html(&self, path: &str) {
        let html = self.generate_live_html();
        if let Err(e) = fs::write(path, &html) {
            eprintln!("[WS-DASHBOARD] Failed to write live HTML: {}", e);
        } else {
            println!("[WS-DASHBOARD] Live dashboard saved to {}", path);
        }
    }
}
