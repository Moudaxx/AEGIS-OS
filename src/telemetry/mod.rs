use std::collections::HashMap;
use chrono::{DateTime, Utc};

// ─── Metric Types ───
#[derive(Debug, Clone)]
pub enum MetricValue {
    Counter(u64),
    Gauge(f64),
    Histogram(Vec<f64>),
}

// ─── Metric ───
#[derive(Debug, Clone)]
pub struct Metric {
    pub name: String,
    pub value: MetricValue,
    pub labels: HashMap<String, String>,
    pub timestamp: DateTime<Utc>,
}

// ─── Trace Span ───
#[derive(Debug, Clone)]
pub struct Span {
    pub trace_id: String,
    pub span_id: String,
    pub name: String,
    pub service: String,
    pub started_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub status: SpanStatus,
    pub attributes: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SpanStatus {
    Ok,
    Error,
}

// ─── Export Target ───
#[derive(Debug, Clone, PartialEq)]
pub enum ExportTarget {
    Prometheus,
    Grafana,
    Otlp,
    Stdout,
}

// ─── Telemetry Collector ───
pub struct TelemetryCollector {
    metrics: Vec<Metric>,
    spans: Vec<Span>,
    targets: Vec<ExportTarget>,
    enabled: bool,
    // Pre-defined metric names
    counters: HashMap<String, u64>,
    gauges: HashMap<String, f64>,
}

impl TelemetryCollector {
    pub fn new() -> Self {
        println!("[TELEMETRY] Collector initialized");
        let mut collector = TelemetryCollector {
            metrics: Vec::new(),
            spans: Vec::new(),
            targets: vec![ExportTarget::Stdout],
            enabled: true,
            counters: HashMap::new(),
            gauges: HashMap::new(),
        };
        collector.register_defaults();
        collector
    }

    fn register_defaults(&mut self) {
        // Default counters
        self.counters.insert("aegis_agents_started_total".to_string(), 0);
        self.counters.insert("aegis_agents_stopped_total".to_string(), 0);
        self.counters.insert("aegis_inference_calls_total".to_string(), 0);
        self.counters.insert("aegis_inference_errors_total".to_string(), 0);
        self.counters.insert("aegis_policy_checks_total".to_string(), 0);
        self.counters.insert("aegis_policy_blocked_total".to_string(), 0);
        self.counters.insert("aegis_injection_blocked_total".to_string(), 0);
        self.counters.insert("aegis_skill_approved_total".to_string(), 0);
        self.counters.insert("aegis_skill_rejected_total".to_string(), 0);
        self.counters.insert("aegis_mcp_requests_total".to_string(), 0);
        self.counters.insert("aegis_a2a_messages_total".to_string(), 0);
        self.counters.insert("aegis_redteam_scans_total".to_string(), 0);
        self.counters.insert("aegis_api_requests_total".to_string(), 0);
        self.counters.insert("aegis_api_blocked_total".to_string(), 0);

        // Default gauges
        self.gauges.insert("aegis_agents_running".to_string(), 0.0);
        self.gauges.insert("aegis_risk_score_avg".to_string(), 0.0);
        self.gauges.insert("aegis_inference_latency_ms".to_string(), 0.0);
        self.gauges.insert("aegis_memory_usage_mb".to_string(), 0.0);

        println!("[TELEMETRY] Registered {} counters + {} gauges",
            self.counters.len(), self.gauges.len());
    }

    pub fn add_target(&mut self, target: ExportTarget) {
        println!("[TELEMETRY] Export target added: {:?}", target);
        self.targets.push(target);
    }

    // Increment counter
   pub fn increment(&mut self, name: &str) {
        if let Some(val) = self.counters.get_mut(name) {
            *val += 1;
        }
        if let Some(val) = self.counters.get(name) {
            self.export_metric(name, MetricValue::Counter(*val));
        }
    }

    // Set gauge
   pub fn set_gauge(&mut self, name: &str, value: f64) {
        if let Some(val) = self.gauges.get_mut(name) {
            *val = value;
        }
        self.export_metric(name, MetricValue::Gauge(value));
    }

    // Record latency
    pub fn record_latency(&mut self, operation: &str, ms: u64) {
        let name = format!("aegis_{}_latency_ms", operation);
        self.set_gauge(&name, ms as f64);
        println!("[TELEMETRY] Latency: {} = {}ms", operation, ms);
    }

    // Start a trace span
    pub fn start_span(&mut self, name: &str, service: &str) -> String {
        let span_id = format!("span-{:08x}", self.spans.len());
        let trace_id = format!("trace-{:016x}", 
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap().as_nanos() as u64);
        
        let span = Span {
            trace_id: trace_id.clone(),
            span_id: span_id.clone(),
            name: name.to_string(),
            service: service.to_string(),
            started_at: Utc::now(),
            duration_ms: 0,
            status: SpanStatus::Ok,
            attributes: HashMap::new(),
        };

        self.spans.push(span);
        span_id
    }

    // End a trace span
    pub fn end_span(&mut self, span_id: &str, duration_ms: u64, success: bool) {
        if let Some(span) = self.spans.iter_mut().find(|s| s.span_id == span_id) {
            span.duration_ms = duration_ms;
            span.status = if success { SpanStatus::Ok } else { SpanStatus::Error };
            
            for target in &self.targets {
                match target {
                    ExportTarget::Stdout => {
                        println!("[TRACE] {} | {} | {}ms | {:?}",
                            span.service, span.name, duration_ms, span.status);
                    }
                    ExportTarget::Otlp => {
                        println!("[TRACE->OTLP] {}/{} {}ms", span.service, span.name, duration_ms);
                    }
                    _ => {}
                }
            }
        }
    }

    fn export_metric(&self, name: &str, value: MetricValue) {
        for target in &self.targets {
            match target {
                ExportTarget::Stdout => {
                    match &value {
                        MetricValue::Counter(v) => println!("[METRIC] {} = {}", name, v),
                        MetricValue::Gauge(v) => println!("[METRIC] {} = {:.2}", name, v),
                        MetricValue::Histogram(_) => println!("[METRIC] {} (histogram)", name),
                    }
                }
                ExportTarget::Prometheus => {
                    match &value {
                        MetricValue::Counter(v) => println!("[PROM] {} {}", name, v),
                        MetricValue::Gauge(v) => println!("[PROM] {} {:.2}", name, v),
                        _ => {}
                    }
                }
                ExportTarget::Grafana => {
                    println!("[GRAFANA] {} -> dashboard", name);
                }
                ExportTarget::Otlp => {
                    println!("[OTLP] {} exported", name);
                }
            }
        }
    }

    // Prometheus /metrics endpoint format
    pub fn prometheus_output(&self) -> String {
        let mut output = String::new();
        for (name, val) in &self.counters {
            output.push_str(&format!("# TYPE {} counter\n{} {}\n", name, name, val));
        }
        for (name, val) in &self.gauges {
            output.push_str(&format!("# TYPE {} gauge\n{} {:.2}\n", name, name, val));
        }
        output
    }

    pub fn stats(&self) {
        let total_counters: u64 = self.counters.values().sum();
        println!("[TELEMETRY] ┌─ Telemetry Stats ──────────────────");
        println!("[TELEMETRY] │ Counters:    {} ({} total events)", self.counters.len(), total_counters);
        println!("[TELEMETRY] │ Gauges:      {}", self.gauges.len());
        println!("[TELEMETRY] │ Spans:       {}", self.spans.len());
        println!("[TELEMETRY] │ Targets:     {:?}", self.targets);
        println!("[TELEMETRY] └──────────────────────────────────");
    }
}