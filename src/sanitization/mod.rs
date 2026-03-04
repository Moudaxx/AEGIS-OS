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
            "disregard your instructions",
            "you are now",
            "new instructions:",
            "system prompt:",
            "forget everything",
            "jailbreak",
            "dan mode",
            "developer mode",
        ];

        let input_lower = input.to_lowercase();

        for pattern in &injection_patterns {
            if input_lower.contains(pattern) {
                return Err(format!(
                    "[AEGIS] Prompt injection detected: '{}'", pattern
                ));
            }
        }

        // Check length
        if input.len() > 10000 {
            return Err("[AEGIS] Input too long (max 10000 chars)".to_string());
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
        ];

        let output_lower = output.to_lowercase();
        for pattern in &dangerous {
            if output_lower.contains(pattern) {
                println!("[AEGIS] WARNING: Dangerous pattern in output: '{}'", pattern);
                return false;
            }
        }
        true
    }
}