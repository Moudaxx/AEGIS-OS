// Copyright (c) 2025 Mouda. All Rights Reserved. AGPL-3.0
pub struct InputSanitizer;

impl InputSanitizer {
    pub fn new() -> Self {
        InputSanitizer
    }

    pub fn sanitize(&self, input: &str) -> Result<String, String> {
        // Check for prompt injection patterns
        let injection_patterns = vec![
            "ignore previous instructions",
            "ignore all instructions",
            "ignore all previous",
            "disregard your instructions",
            "you are now",
            "new instructions:",
            "system prompt:",
            "forget everything",
            "jailbreak",
            "dan mode",
            "developer mode",
            "pretend you are",
            "act as if",
            "reveal your",
            "output your system",
            "sudo mode",
            "ADMIN OVERRIDE",
            "<<SYS>>",
            "<|im_start|>",
            "[INST]",
            "```system",
        ];

        let input_lower = input.to_lowercase();

        for pattern in &injection_patterns {
            if input_lower.contains(&pattern.to_lowercase()) {
                return Err(format!(
                    "[AEGIS] Prompt injection detected: '{}'", pattern
                ));
            }
        }

        // Check length
        if input.len() > 10000 {
            return Err("[AEGIS] Input too long (max 10000 chars)".to_string());
        }

        // Check for hidden control characters
        if input.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
            return Err("[AEGIS] Hidden control characters detected".to_string());
        }

        // Strip dangerous characters
        let sanitized = input
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('\0', "");

        Ok(sanitized)
    }

    pub fn check_output(&self, output: &str) -> bool {
        let dangerous = vec![
            "rm -rf",
            "sudo",
            "password",
            "private key",
            "secret key",
            "/etc/passwd",
            "/etc/shadow",
            "AWS_SECRET",
            "PRIVATE_KEY",
        ];

        let output_lower = output.to_lowercase();
        for pattern in &dangerous {
            if output_lower.contains(&pattern.to_lowercase()) {
                println!("[AEGIS] WARNING: Dangerous pattern in output: '{}'", pattern);
                return false;
            }
        }
        true
    }
}