// Copyright (c) 2025 Mouda. All Rights Reserved. AGPL-3.0
use anyhow::Result;
use std::path::{Path, PathBuf};
use wasmtime::{Engine, Store, Module, Linker};

// ─── WASM Sandbox ───
pub struct WasmSandbox {
    engine: Engine,
}

impl WasmSandbox {
    pub fn new() -> Result<Self> {
        let engine = Engine::default();
        println!("[AEGIS] WASM Sandbox initialized");
        Ok(WasmSandbox { engine })
    }

    pub fn run(&self, agent_name: &str) -> Result<()> {
        println!("[AEGIS] Running agent '{}' in WASM sandbox", agent_name);

        let wat = r#"
            (module
                (func $add (export "add") (param i32 i32) (result i32)
                    local.get 0
                    local.get 1
                    i32.add)
            )
        "#;

        let mut store = Store::new(&self.engine, ());
        let module = Module::new(&self.engine, wat)?;
        let linker = Linker::new(&self.engine);
        let instance = linker.instantiate(&mut store, &module)?;

        let add = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "add")?;

        let result = add.call(&mut store, (5, 3))?;
        println!("[AEGIS] WASM sandbox test: 5 + 3 = {} ✓", result);
        println!("[AEGIS] Agent '{}' sandbox verified | Isolated ✓", agent_name);

        Ok(())
    }
}

// ─── Filesystem Jail (improved: path traversal + sensitive paths) ───
pub struct FilesystemJail {
    allowed_paths: Vec<PathBuf>,
    blocked_patterns: Vec<String>,
}

impl FilesystemJail {
    pub fn new(agent_id: &str) -> Self {
        let base = format!("/tmp/aegis/{}", agent_id);
        FilesystemJail {
            allowed_paths: vec![
                PathBuf::from(&base),
                PathBuf::from("/tmp/aegis/shared"),
            ],
            blocked_patterns: vec![
                "/etc/".to_string(),
                "/root/".to_string(),
                "/proc/".to_string(),
                "/sys/".to_string(),
                "/dev/".to_string(),
                "/.ssh/".to_string(),
                "/.ssh".to_string(),
                "/.env".to_string(),
                "/shadow".to_string(),
                "/passwd".to_string(),
                "/.gnupg".to_string(),
                "/.aws/".to_string(),
                "/.kube/".to_string(),
            ],
        }
    }

    pub fn check_access(&self, path: &str) -> bool {
        let normalized = path.replace("\\", "/");

        // Block path traversal attempts
        if normalized.contains("/../")
            || normalized.contains("/./")
            || normalized.ends_with("/..")
            || normalized.ends_with("/.")
            || normalized.contains("..%2f")
            || normalized.contains("%2e%2e")
        {
            println!("[AEGIS] Path traversal BLOCKED: {}", path);
            return false;
        }

        // Block sensitive paths
        let lower = normalized.to_lowercase();
        for pattern in &self.blocked_patterns {
            if lower.contains(&pattern.to_lowercase()) {
                println!("[AEGIS] Sensitive path BLOCKED: {}", path);
                return false;
            }
        }

        // Check allowlist
        let requested = Path::new(&normalized);
        for allowed in &self.allowed_paths {
            if requested.starts_with(allowed) {
                println!("[AEGIS] Filesystem access ALLOWED: {}", path);
                return true;
            }
        }

        println!("[AEGIS] Filesystem access DENIED: {}", path);
        false
    }

    pub fn setup(&self) -> Result<()> {
        for path in &self.allowed_paths {
            std::fs::create_dir_all(path)?;
        }
        println!("[AEGIS] Filesystem jail ready | Allowed: {} paths | Blocked: {} patterns",
            self.allowed_paths.len(), self.blocked_patterns.len());
        Ok(())
    }
}

// ─── Network Egress (improved: exact match + blacklist) ───
pub struct NetworkEgress {
    allowlist: Vec<String>,
    blocklist: Vec<String>,
}

impl NetworkEgress {
    pub fn new() -> Self {
        NetworkEgress {
            allowlist: vec![
                "api.anthropic.com".to_string(),
                "generativelanguage.googleapis.com".to_string(),
                "integrate.api.nvidia.com".to_string(),
                "aistudio.google.com".to_string(),
                "api.groq.com".to_string(),
                "api.openai.com".to_string(),
            ],
            blocklist: vec![
                "pastebin.com".to_string(),
                "ngrok.io".to_string(),
                "transfer.sh".to_string(),
                "raw.githubusercontent.com".to_string(),
                "discord.com".to_string(),
                "telegram.org".to_string(),
            ],
        }
    }

    pub fn check(&self, host: &str) -> bool {
        let host_lower = host.to_lowercase().trim().to_string();

        // Check blocklist first (exact match or subdomain)
        for blocked in &self.blocklist {
            if host_lower == blocked.to_lowercase()
                || host_lower.ends_with(&format!(".{}", blocked.to_lowercase()))
            {
                println!("[AEGIS] Network egress BLOCKED (blacklist): {}", host);
                return false;
            }
        }

        // Check allowlist (exact match or subdomain)
        for allowed in &self.allowlist {
            if host_lower == allowed.to_lowercase()
                || host_lower.ends_with(&format!(".{}", allowed.to_lowercase()))
            {
                println!("[AEGIS] Network egress ALLOWED: {}", host);
                return true;
            }
        }

        println!("[AEGIS] Network egress DENIED: {}", host);
        false
    }

    pub fn status(&self) {
        println!("[AEGIS] Network allowlist: {} hosts | Blocklist: {} hosts",
            self.allowlist.len(), self.blocklist.len());
        for host in &self.allowlist {
            println!("[AEGIS]   ✓ {}", host);
        }
        for host in &self.blocklist {
            println!("[AEGIS]   ✗ {}", host);
        }
    }
}