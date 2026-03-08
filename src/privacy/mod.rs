use std::collections::HashMap;

// ─── Detection Result ───
#[derive(Debug, Clone)]
pub struct PrivacyViolation {
    pub violation_type: ViolationType,
    pub content: String,
    pub position: usize,
    pub severity: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ViolationType {
    Email,
    Phone,
    CreditCard,
    SSN,
    ApiKey,
    PrivateKey,
    Password,
    IpAddress,
    AwsSecret,
    JwtToken,
    CustomPii,
}

#[derive(Debug, PartialEq)]
pub enum FilterAction {
    Pass,
    Redact(String),
    Block(String),
}

// ─── Output Privacy Filter ───
pub struct PrivacyFilter {
    patterns: Vec<(ViolationType, String, String)>,
    block_on_detection: bool,
    redaction_char: char,
    violation_log: Vec<PrivacyViolation>,
}

impl PrivacyFilter {
    pub fn new() -> Self {
        println!("[PRIVACY] Output Privacy Filter initialized");
        let mut filter = PrivacyFilter {
            patterns: Vec::new(),
            block_on_detection: false,
            redaction_char: '*',
            violation_log: Vec::new(),
        };
        filter.load_patterns();
        filter
    }

    fn load_patterns(&mut self) {
        self.patterns = vec![
            // API Keys
            (ViolationType::ApiKey, "nvapi-".to_string(), "NVIDIA API Key".to_string()),
            (ViolationType::ApiKey, "sk-ant-".to_string(), "Anthropic API Key".to_string()),
            (ViolationType::ApiKey, "sk-proj-".to_string(), "OpenAI API Key".to_string()),
            (ViolationType::ApiKey, "gsk_".to_string(), "Groq API Key".to_string()),
            (ViolationType::ApiKey, "AIzaSy".to_string(), "Google API Key".to_string()),
            (ViolationType::ApiKey, "xoxb-".to_string(), "Slack Bot Token".to_string()),
            (ViolationType::ApiKey, "ghp_".to_string(), "GitHub Token".to_string()),
            (ViolationType::ApiKey, "glpat-".to_string(), "GitLab Token".to_string()),

            // AWS
            (ViolationType::AwsSecret, "AKIA".to_string(), "AWS Access Key".to_string()),
            (ViolationType::AwsSecret, "aws_secret_access_key".to_string(), "AWS Secret".to_string()),

            // Private Keys
            (ViolationType::PrivateKey, "BEGIN RSA PRIVATE".to_string(), "RSA Private Key".to_string()),
            (ViolationType::PrivateKey, "BEGIN OPENSSH PRIVATE".to_string(), "SSH Private Key".to_string()),
            (ViolationType::PrivateKey, "BEGIN EC PRIVATE".to_string(), "EC Private Key".to_string()),

            // Passwords
            (ViolationType::Password, "password=".to_string(), "Password in plaintext".to_string()),
            (ViolationType::Password, "passwd=".to_string(), "Password in plaintext".to_string()),
            (ViolationType::Password, "pwd=".to_string(), "Password in plaintext".to_string()),

            // PII patterns (simple string matching)
            (ViolationType::SSN, "social security".to_string(), "SSN reference".to_string()),
            (ViolationType::CreditCard, "credit card".to_string(), "Credit card reference".to_string()),

            // JWT
            (ViolationType::JwtToken, "eyJhbG".to_string(), "JWT Token".to_string()),
        ];
        println!("[PRIVACY] Loaded {} detection patterns", self.patterns.len());
    }

    // Scan output for privacy violations
    pub fn scan(&mut self, output: &str) -> Vec<PrivacyViolation> {
        let mut violations = Vec::new();
        let lower = output.to_lowercase();

        for (vtype, pattern, desc) in &self.patterns {
            let pattern_lower = pattern.to_lowercase();
            if let Some(pos) = lower.find(&pattern_lower) {
                let violation = PrivacyViolation {
                    violation_type: vtype.clone(),
                    content: desc.clone(),
                    position: pos,
                    severity: match vtype {
                        ViolationType::PrivateKey | ViolationType::AwsSecret => "CRITICAL".to_string(),
                        ViolationType::ApiKey | ViolationType::JwtToken => "HIGH".to_string(),
                        ViolationType::Password | ViolationType::SSN | ViolationType::CreditCard => "HIGH".to_string(),
                        _ => "MEDIUM".to_string(),
                    },
                };
                println!("[PRIVACY] VIOLATION: {} | Type: {:?} | Severity: {}",
                    desc, vtype, violation.severity);
                violations.push(violation);
            }
        }

        self.violation_log.extend(violations.clone());
        violations
    }

    // Filter output — redact or block
    pub fn filter(&mut self, output: &str) -> FilterAction {
        let violations = self.scan(output);

        if violations.is_empty() {
            return FilterAction::Pass;
        }

        if self.block_on_detection || violations.iter().any(|v| v.severity == "CRITICAL") {
            let reasons: Vec<String> = violations.iter().map(|v| v.content.clone()).collect();
            println!("[PRIVACY] BLOCKED: {} violations detected", violations.len());
            return FilterAction::Block(reasons.join(", "));
        }

        // Redact sensitive content
        let mut redacted = output.to_string();
        for (_, pattern, _) in &self.patterns {
            if let Some(start) = redacted.to_lowercase().find(&pattern.to_lowercase()) {
                let end = (start + 20).min(redacted.len());
                let replacement: String = std::iter::repeat(self.redaction_char).take(end - start).collect();
                redacted.replace_range(start..end, &replacement);
            }
        }
        println!("[PRIVACY] REDACTED: {} patterns masked", violations.len());
        FilterAction::Redact(redacted)
    }

    pub fn set_block_mode(&mut self, block: bool) {
        self.block_on_detection = block;
        println!("[PRIVACY] Block mode: {}", block);
    }

    pub fn violation_count(&self) -> usize {
        self.violation_log.len()
    }

    pub fn status(&self) {
        println!("[PRIVACY] Patterns: {} | Violations logged: {} | Block mode: {}",
            self.patterns.len(), self.violation_log.len(), self.block_on_detection);
    }
}