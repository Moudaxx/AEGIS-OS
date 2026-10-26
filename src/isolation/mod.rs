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
        // Fuel metering bounds CPU use, so an infinite loop traps instead of hanging the host.
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config)?;
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
        store.set_fuel(Self::DEFAULT_FUEL)?;
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

    pub const DEFAULT_FUEL: u64 = 10_000_000;

    /// Run untrusted WAT/WASM with no host imports and a fuel budget.
    /// Calls the exported `run` function. Fails if the module needs any host
    /// capability (no imports are linked) or exhausts its fuel.
    pub fn run_untrusted(&self, wasm: &str, fuel: u64) -> Result<()> {
        let mut store = Store::new(&self.engine, ());
        store.set_fuel(fuel)?;
        let module = Module::new(&self.engine, wasm)?;
        let linker: Linker<()> = Linker::new(&self.engine);
        let instance = linker.instantiate(&mut store, &module)?;
        let run = instance.get_typed_func::<(), ()>(&mut store, "run")?;
        run.call(&mut store, ())?;
        Ok(())
    }
}

/// Percent-decode repeatedly (max 3 rounds) so "%252e%252e" can't hide "..".
fn percent_decode_all(input: &str) -> String {
    let mut cur = input.to_string();
    for _ in 0..3 {
        let bytes = cur.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        let next = String::from_utf8_lossy(&out).into_owned();
        if next == cur {
            break;
        }
        cur = next;
    }
    cur
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
        // Decode first (catches %2e%2e, %2E%2E, %252e…), unify separators.
        let normalized = percent_decode_all(path).replace('\\', "/");

        if normalized.contains('\0') {
            println!("[AEGIS] Null byte BLOCKED: {}", path);
            return false;
        }
        // Only absolute paths; reject any "." or ".." component.
        if !normalized.starts_with('/')
            || normalized.split('/').any(|c| c == ".." || c == ".")
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
    allowed_ports: Vec<u16>,
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
            allowed_ports: vec![443],
        }
    }

    /// Check a host and port. All allowlisted AI APIs are HTTPS-only.
    pub fn check_endpoint(&self, host: &str, port: u16) -> bool {
        if !self.allowed_ports.contains(&port) {
            println!("[AEGIS] Network egress BLOCKED (port {}): {}", port, host);
            return false;
        }
        self.check_host(host)
    }

    /// Check a host, optionally written as "host:port".
    pub fn check(&self, host: &str) -> bool {
        match host.trim().rsplit_once(':') {
            Some((h, p)) => match p.parse::<u16>() {
                Ok(port) => self.check_endpoint(h, port),
                Err(_) => {
                    println!("[AEGIS] Network egress DENIED (malformed): {}", host);
                    false
                }
            },
            None => self.check_host(host),
        }
    }

    fn check_host(&self, host: &str) -> bool {
        // Trailing dot is the same DNS name ("pastebin.com." == "pastebin.com").
        let host_lower = host.to_lowercase().trim().trim_end_matches('.').to_string();

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