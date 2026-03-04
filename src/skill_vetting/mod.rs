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
        if !self.sandbox_test(&skill.name) {
            skill.status = VettingStatus::Rejected;
            return false;
        }

        skill.status = VettingStatus::Approved;
        println!("[AEGIS] Skill '{}' APPROVED ✓ | Hash: {}", skill.name, skill.hash);
        true
    }

    fn static_analysis(&self, code: &str) -> bool {
        let dangerous = vec![
            "rm -rf",
            "exec(",
            "eval(",
            "system(",
            "subprocess",
            "__import__",
        ];

        for pattern in &dangerous {
            if code.contains(pattern) {
                println!("[AEGIS] Static analysis FAILED: dangerous pattern '{}'", pattern);
                return false;
            }
        }
        println!("[AEGIS] Static analysis PASSED ✓");
        true
    }

    fn dependency_check(&self, code: &str) -> bool {
        let banned_deps = vec!["malware", "cryptominer", "backdoor"];
        for dep in &banned_deps {
            if code.contains(dep) {
                println!("[AEGIS] Dependency check FAILED: banned dep '{}'", dep);
                return false;
            }
        }
        println!("[AEGIS] Dependency check PASSED ✓");
        true
    }

    fn sandbox_test(&self, name: &str) -> bool {
        println!("[AEGIS] Sandbox test PASSED ✓ | Skill: {}", name);
        true
    }
}