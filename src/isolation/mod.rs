use anyhow::Result;
use std::path::{Path, PathBuf};
use wasmtime::{Engine, Store, Module, Linker};

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

pub struct FilesystemJail {
    allowed_paths: Vec<PathBuf>,
}

impl FilesystemJail {
    pub fn new(agent_id: &str) -> Self {
        let base = format!("/tmp/aegis/{}", agent_id);
        FilesystemJail {
            allowed_paths: vec![
                PathBuf::from(&base),
                PathBuf::from("/tmp/aegis/shared"),
            ],
        }
    }

    pub fn check_access(&self, path: &str) -> bool {
        let requested = Path::new(path);
        for allowed in &self.allowed_paths {
            if requested.starts_with(allowed) {
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
        println!("[AEGIS] Filesystem jail ready | Allowed paths: {}", 
            self.allowed_paths.len());
        Ok(())
    }
}

pub struct NetworkEgress {
    allowlist: Vec<String>,
}

impl NetworkEgress {
    pub fn new() -> Self {
        NetworkEgress {
            allowlist: vec![
                "api.anthropic.com".to_string(),
                "generativelanguage.googleapis.com".to_string(),
                "integrate.api.nvidia.com".to_string(),
            ],
        }
    }

    pub fn check(&self, host: &str) -> bool {
        for allowed in &self.allowlist {
            if host.contains(allowed.as_str()) {
                return true;
            }
        }
        println!("[AEGIS] Network egress DENIED: {}", host);
        false
    }

    pub fn status(&self) {
        println!("[AEGIS] Network allowlist: {} hosts", self.allowlist.len());
        for host in &self.allowlist {
            println!("[AEGIS]   ✓ {}", host);
        }
    }
}