use std::collections::HashMap;

// ─── Policy Rule ───
#[derive(Debug, Clone)]
pub struct PolicyRule {
    pub name: String,
    pub description: String,
    pub rule_type: RuleType,
    pub action: PolicyAction,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuleType {
    MaxTokens(usize),
    BlockedTopics(Vec<String>),
    AllowedModels(Vec<String>),
    RateLimit { max_calls: u32, window_secs: u64 },
    ContentFilter(Vec<String>),
    OutputCheck(Vec<String>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyAction {
    Allow,
    Block,
    Warn,
    Log,
}

#[derive(Debug, PartialEq)]
pub enum PolicyResult {
    Passed,
    Blocked { rule: String, reason: String },
    Warning { rule: String, reason: String },
}

// ─── Policy Engine ───
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
    call_counts: HashMap<String, Vec<std::time::Instant>>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        let mut engine = PolicyEngine {
            rules: Vec::new(),
            call_counts: HashMap::new(),
        };
        engine.load_defaults();
        engine
    }

    fn load_defaults(&mut self) {
        // Max token limit
        self.add_rule(PolicyRule {
            name: "max_tokens".to_string(),
            description: "Limit max tokens per request".to_string(),
            rule_type: RuleType::MaxTokens(4096),
            action: PolicyAction::Block,
            enabled: true,
        });

        // Blocked topics
        self.add_rule(PolicyRule {
            name: "blocked_topics".to_string(),
            description: "Block dangerous topics".to_string(),
            rule_type: RuleType::BlockedTopics(vec![
                "weapons".to_string(),
                "explosives".to_string(),
                "malware creation".to_string(),
                "hack into".to_string(),
                "bypass security".to_string(),
                "steal credentials".to_string(),
                "social engineering attack".to_string(),
            ]),
            action: PolicyAction::Block,
            enabled: true,
        });

        // Allowed models
        self.add_rule(PolicyRule {
            name: "allowed_models".to_string(),
            description: "Only allow approved AI models".to_string(),
            rule_type: RuleType::AllowedModels(vec![
                "meta/llama-3.1-8b-instruct".to_string(),
                "claude-haiku-4-5-20251001".to_string(),
                "claude-sonnet-4-5-20250929".to_string(),
                "gemini-2.5-flash-lite".to_string(),
                "gemini-2.0-flash".to_string(),
                "llama-3.3-70b-versatile".to_string(),
                "llama-3.1-8b-instant".to_string(),
                "gpt-4o-mini".to_string(),
                "gpt-4o".to_string(),
            ]),
            action: PolicyAction::Block,
            enabled: true,
        });

        // Rate limit
        self.add_rule(PolicyRule {
            name: "rate_limit".to_string(),
            description: "Max 60 AI calls per minute".to_string(),
            rule_type: RuleType::RateLimit { max_calls: 60, window_secs: 60 },
            action: PolicyAction::Block,
            enabled: true,
        });

        // Content filter for output
        self.add_rule(PolicyRule {
            name: "output_filter".to_string(),
            description: "Filter dangerous content in AI output".to_string(),
            rule_type: RuleType::OutputCheck(vec![
                "rm -rf".to_string(),
                "DROP TABLE".to_string(),
                "sudo rm".to_string(),
                "format c:".to_string(),
                ":(){ :|:& };:".to_string(),
                "private_key".to_string(),
                "BEGIN RSA PRIVATE".to_string(),
            ]),
            action: PolicyAction::Block,
            enabled: true,
        });
    }

    pub fn add_rule(&mut self, rule: PolicyRule) {
        println!("[POLICY] Rule added: {} ({})", rule.name, rule.description);
        self.rules.push(rule);
    }

    // Check input before sending to AI
    pub fn check_input(&self, input: &str, model: &str, token_count: usize) -> PolicyResult {
        for rule in &self.rules {
            if !rule.enabled { continue; }

            match &rule.rule_type {
                RuleType::MaxTokens(max) => {
                    if token_count > *max {
                        println!("[POLICY] BLOCKED: {} tokens > {} max", token_count, max);
                        return PolicyResult::Blocked {
                            rule: rule.name.clone(),
                            reason: format!("tokens {} exceeds max {}", token_count, max),
                        };
                    }
                }
                RuleType::BlockedTopics(topics) => {
                    let lower = input.to_lowercase();
                    for topic in topics {
                        if lower.contains(&topic.to_lowercase()) {
                            println!("[POLICY] BLOCKED: topic '{}'", topic);
                            return PolicyResult::Blocked {
                                rule: rule.name.clone(),
                                reason: format!("blocked topic: {}", topic),
                            };
                        }
                    }
                }
                RuleType::AllowedModels(models) => {
                    if !models.iter().any(|m| m == model) {
                        println!("[POLICY] BLOCKED: model '{}' not allowed", model);
                        return PolicyResult::Blocked {
                            rule: rule.name.clone(),
                            reason: format!("model not allowed: {}", model),
                        };
                    }
                }
                _ => {}
            }
        }
        PolicyResult::Passed
    }

    // Check output from AI
    pub fn check_output(&self, output: &str) -> PolicyResult {
        for rule in &self.rules {
            if !rule.enabled { continue; }

            if let RuleType::OutputCheck(patterns) = &rule.rule_type {
                let lower = output.to_lowercase();
                for pattern in patterns {
                    if lower.contains(&pattern.to_lowercase()) {
                        println!("[POLICY] OUTPUT BLOCKED: pattern '{}'", pattern);
                        return PolicyResult::Blocked {
                            rule: rule.name.clone(),
                            reason: format!("dangerous output: {}", pattern),
                        };
                    }
                }
            }
        }
        PolicyResult::Passed
    }

    // Check rate limit
    pub fn check_rate_limit(&mut self, agent_id: &str) -> PolicyResult {
        let now = std::time::Instant::now();

        for rule in &self.rules {
            if !rule.enabled { continue; }

            if let RuleType::RateLimit { max_calls, window_secs } = &rule.rule_type {
                let window = std::time::Duration::from_secs(*window_secs);
                let calls = self.call_counts.entry(agent_id.to_string()).or_default();

                // Remove old calls outside window
                calls.retain(|t| now.duration_since(*t) < window);

                if calls.len() >= *max_calls as usize {
                    println!("[POLICY] RATE LIMITED: {} ({} calls in {}s)",
                        agent_id, calls.len(), window_secs);
                    return PolicyResult::Blocked {
                        rule: rule.name.clone(),
                        reason: format!("rate limit: {} calls in {}s", calls.len(), window_secs),
                    };
                }

                // Record this call
                calls.push(now);
            }
        }
        PolicyResult::Passed
    }

    // Full pipeline check
    pub fn enforce(&mut self, agent_id: &str, input: &str, model: &str, tokens: usize) -> PolicyResult {
        // Step 1: Rate limit
        let rate = self.check_rate_limit(agent_id);
        if rate != PolicyResult::Passed { return rate; }

        // Step 2: Input check
        let input_check = self.check_input(input, model, tokens);
        if input_check != PolicyResult::Passed { return input_check; }

        println!("[POLICY] PASSED: agent={} model={} tokens={}", agent_id, model, tokens);
        PolicyResult::Passed
    }

    pub fn list_rules(&self) {
        println!("[POLICY] Active rules: {}", self.rules.iter().filter(|r| r.enabled).count());
        for rule in &self.rules {
            let status = if rule.enabled { "ON" } else { "OFF" };
            println!("[POLICY]   [{}] {} — {}", status, rule.name, rule.description);
        }
    }

    pub fn disable_rule(&mut self, name: &str) -> bool {
        for rule in &mut self.rules {
            if rule.name == name {
                rule.enabled = false;
                println!("[POLICY] Disabled: {}", name);
                return true;
            }
        }
        false
    }
}