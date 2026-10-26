// Copyright (c) 2025 Mouda. All Rights Reserved. AGPL-3.0
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

        // Actual card numbers (13–19 digits, Luhn-valid), not just the phrase "credit card".
        if let Some(pos) = find_card_number(output) {
            println!("[PRIVACY] DETECTED: Card number [HIGH]");
            violations.push(PrivacyViolation {
                violation_type: ViolationType::CreditCard,
                content: "Card number".to_string(),
                position: pos,
                severity: "HIGH".to_string(),
            });
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

        // Redact sensitive content.
        // The old code took byte offsets from a lowercased copy and masked a
        // fixed 20 bytes: it panicked on multi-byte text (e.g. Arabic after a
        // key), masked only the first occurrence, and left the tail of long
        // secrets (a 40-char GitHub token leaked half its characters).
        let redacted = self.redact(output);
        println!("[PRIVACY] REDACTED: {} patterns masked", violations.len());
        FilterAction::Redact(redacted)
    }

    /// Mask every token (whitespace-delimited word) that contains a sensitive
    /// pattern, plus Luhn-valid card numbers. Works on chars, never byte offsets.
    pub fn redact(&self, output: &str) -> String {
        let patterns: Vec<String> = self.patterns.iter().map(|(_, p, _)| p.to_lowercase()).collect();
        let mut out = String::with_capacity(output.len());
        let mut word = String::new();
        let flush = |word: &mut String, out: &mut String| {
            if word.is_empty() { return; }
            let lower = word.to_lowercase();
            let sensitive = patterns.iter().any(|p| lower.contains(p.as_str())) || find_card_number(word).is_some();
            if sensitive {
                out.extend(std::iter::repeat(self.redaction_char).take(word.chars().count()));
            } else {
                out.push_str(word);
            }
            word.clear();
        };
        for c in output.chars() {
            if c.is_whitespace() {
                flush(&mut word, &mut out);
                out.push(c);
            } else {
                word.push(c);
            }
        }
        flush(&mut word, &mut out);
        // Card numbers written with spaces ("4111 1111 1111 1111") span words.
        mask_spaced_cards(&out, self.redaction_char)
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
// ─── Card number detection (Luhn) ───

fn luhn_valid(digits: &[u32]) -> bool {
    let sum: u32 = digits.iter().rev().enumerate().map(|(i, &d)| {
        if i % 2 == 1 { let x = d * 2; if x > 9 { x - 9 } else { x } } else { d }
    }).sum();
    sum % 10 == 0
}

/// Char ranges of 13–19 digit, Luhn-valid runs; digits may be separated by
/// single spaces or dashes ("4111 1111 1111 1111", "4111-1111-1111-1111").
fn card_ranges(chars: &[char]) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if !chars[i].is_ascii_digit() || (i > 0 && chars[i - 1].is_ascii_digit()) {
            i += 1;
            continue;
        }
        let start = i;
        let mut digits = Vec::new();
        let mut end = i;
        let mut j = i;
        while j < chars.len() {
            let c = chars[j];
            if let Some(d) = c.to_digit(10).filter(|_| c.is_ascii_digit()) {
                digits.push(d);
                end = j + 1;
                j += 1;
            } else if (c == ' ' || c == '-') && j + 1 < chars.len() && chars[j + 1].is_ascii_digit() && digits.len() < 19 {
                j += 1;
            } else {
                break;
            }
        }
        if (13..=19).contains(&digits.len()) && luhn_valid(&digits) {
            ranges.push((start, end));
        }
        i = end.max(i + 1);
    }
    ranges
}

/// Byte offset of the first card number, if any.
pub fn find_card_number(text: &str) -> Option<usize> {
    let chars: Vec<char> = text.chars().collect();
    card_ranges(&chars).first().map(|(s, _)| chars[..*s].iter().map(|c| c.len_utf8()).sum())
}

fn mask_spaced_cards(text: &str, mask: char) -> String {
    let mut chars: Vec<char> = text.chars().collect();
    for (s, e) in card_ranges(&chars) {
        for c in &mut chars[s..e] {
            if c.is_ascii_digit() { *c = mask; }
        }
    }
    chars.into_iter().collect()
}
