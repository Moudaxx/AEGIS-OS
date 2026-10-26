// Copyright (c) 2025 Mouda. All Rights Reserved. AGPL-3.0
use sha2::{Sha256, Digest};

#[derive(Debug, Clone, PartialEq)]
pub enum VettingStatus {
    Approved,
    Rejected,
    Pending,
}

#[derive(Debug, Clone)]
pub struct Skill {
    pub name: String,
    pub code: String,
    pub hash: String,
    pub status: VettingStatus,
    /// True only if the skill actually executed in the WASM sandbox.
    /// Non-WASM skills get static checks only — and callers can see that here.
    pub sandbox_tested: bool,
}

impl Skill {
    pub fn new(name: &str, code: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(code.as_bytes());
        let hash = format!("{:x}", hasher.finalize())[..16].to_string();

        Skill {
            name: name.to_string(),
            code: code.to_string(),
            hash,
            status: VettingStatus::Pending,
            sandbox_tested: false,
        }
    }
}

pub struct SkillVetter;

impl SkillVetter {
    pub fn new() -> Self {
        SkillVetter
    }

    pub fn vet(&self, skill: &mut Skill) -> bool {
        println!("[AEGIS] Vetting skill: '{}' | Hash: {}", skill.name, skill.hash);

        // Static analysis
        if !self.static_analysis(&skill.code) {
            skill.status = VettingStatus::Rejected;
            return false;
        }

        // Dependency check
        if !self.dependency_check(&skill.code) {
            skill.status = VettingStatus::Rejected;
            return false;
        }

        // Sandbox test
        match self.sandbox_test(&skill.code) {
            Some(false) => {
                skill.status = VettingStatus::Rejected;
                return false;
            }
            Some(true) => skill.sandbox_tested = true,
            None => {
                skill.sandbox_tested = false;
                println!("[AEGIS] Sandbox test SKIPPED: '{}' is not WASM (static checks only)", skill.name);
            }
        }

        skill.status = VettingStatus::Approved;
        println!("[AEGIS] Skill '{}' APPROVED ✓ | Hash: {}", skill.name, skill.hash);
        true
    }

    fn static_analysis(&self, code: &str) -> bool {
        // Patterns are matched against code lowercased with all whitespace
        // removed, so "EVAL (x)" or "rm   -rf" can't slip through.
        let dangerous = vec![
            "rm-rf",
            "exec(",
            "eval(",
            "system(",
            "subprocess",
            "__import__",
            "os.popen",
            "child_process",
            "|sh",
            "|bash",
        ];
        let squashed: String = code.to_lowercase().chars().filter(|c| !c.is_whitespace()).collect();

        for pattern in &dangerous {
            if squashed.contains(pattern) {
                println!("[AEGIS] Static analysis FAILED: dangerous pattern '{}'", pattern);
                return false;
            }
        }
        println!("[AEGIS] Static analysis PASSED ✓");
        true
    }

    fn dependency_check(&self, code: &str) -> bool {
        let banned_deps = vec!["malware", "cryptominer", "backdoor"];
        let lower = code.to_lowercase();
        for dep in &banned_deps {
            if lower.contains(dep) {
                println!("[AEGIS] Dependency check FAILED: banned dep '{}'", dep);
                return false;
            }
        }
        println!("[AEGIS] Dependency check PASSED ✓");
        true
    }

    /// Execute WASM/WAT skills in the sandbox (no host imports, fuel-limited).
    /// Returns None for non-WASM skills. Previously this returned true for
    /// every skill without running anything.
    fn sandbox_test(&self, code: &str) -> Option<bool> {
        let is_wasm = code.trim_start().starts_with("(module") || code.as_bytes().starts_with(b"\0asm");
        if !is_wasm {
            return None;
        }
        let sandbox = match crate::isolation::WasmSandbox::new() {
            Ok(s) => s,
            Err(_) => return Some(false), // fail closed
        };
        match sandbox.run_untrusted(code, crate::isolation::WasmSandbox::DEFAULT_FUEL) {
            Ok(()) => {
                println!("[AEGIS] Sandbox test PASSED ✓ (executed in WASM)");
                Some(true)
            }
            Err(e) => {
                println!("[AEGIS] Sandbox test FAILED: {}", e);
                Some(false)
            }
        }
    }
}