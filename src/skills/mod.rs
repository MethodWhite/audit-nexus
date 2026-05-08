//! Skill Registry with Seniority System
//!
//! Skills define what an agent can do. Each skill has a level that
//! determines the depth and sophistication of analysis.
//!
//! Seniority levels:
//!   Junior (1)    - Basic pattern matching, known signature detection
//!   Mid (2)       - Contextual analysis, correlation, basic heuristics  
//!   Senior (3)    - Advanced heuristics, multi-vector analysis, CVE research
//!   Expert (4)    - Novel exploit detection, zero-day analysis, advanced RE
//!   Principal (5) - Architecture-level security review, threat modeling, APT analysis

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Seniority {
    Junior = 1,
    Mid = 2,
    Senior = 3,
    Expert = 4,
    Principal = 5,
}

impl Seniority {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "junior" | "jr" | "1" => Some(Self::Junior),
            "mid" | "2" => Some(Self::Mid),
            "senior" | "sr" | "3" => Some(Self::Senior),
            "expert" | "4" => Some(Self::Expert),
            "principal" | "5" => Some(Self::Principal),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Skill {
    pub id: String,
    pub name: String,
    pub category: SkillCategory,
    pub description: String,
    pub min_seniority: Seniority,
    pub tools: Vec<String>,
    pub methodology: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SkillCategory {
    #[serde(rename = "audit")]
    Audit,
    #[serde(rename = "reversing")]
    Reversing,
    #[serde(rename = "pentest")]
    Pentest,
    #[serde(rename = "forensics")]
    Forensics,
    #[serde(rename = "crypto")]
    Crypto,
    #[serde(rename = "malware")]
    Malware,
    #[serde(rename = "network")]
    Network,
    #[serde(rename = "osint")]
    Osint,
    #[serde(rename = "general")]
    General,
}

pub struct SkillRegistry {
    skills: Arc<RwLock<HashMap<String, Skill>>>,
    agent_skills: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl SkillRegistry {
    pub fn new() -> Self {
        let registry = Self {
            skills: Arc::new(RwLock::new(HashMap::new())),
            agent_skills: Arc::new(RwLock::new(HashMap::new())),
        };
        registry.load_defaults();
        registry
    }

    fn load_defaults(&self) {
        let defaults = vec![
            // === AUDIT ===
            Skill {
                id: "code-audit-jr".into(),
                name: "Code Auditor (Junior)".into(),
                category: SkillCategory::Audit,
                description: "Basic code review: hardcoded secrets, dangerous functions, missing error handling".into(),
                min_seniority: Seniority::Junior,
                tools: vec!["audit_code".into(), "audit_secrets".into()],
                methodology: "1. Scan for patterns 2. Classify severity 3. Report findings".into(),
                enabled: true,
            },
            Skill {
                id: "code-audit-sr".into(),
                name: "Code Auditor (Senior)".into(),
                category: SkillCategory::Audit,
                description: "Advanced code review: injection vectors, race conditions, logic flaws, auth bypass".into(),
                min_seniority: Seniority::Senior,
                tools: vec!["audit_code".into(), "audit_secrets".into(), "audit_deps".into(), "audit_injection".into()],
                methodology: "1. Threat model 2. Data flow analysis 3. Vulnerability chaining 4. Exploitability assessment".into(),
                enabled: true,
            },
            Skill {
                id: "config-audit".into(),
                name: "Configuration Auditor".into(),
                category: SkillCategory::Audit,
                description: "Audit configs: Docker, K8s, nginx, SSH, systemd. Check hardening, misconfigurations, exposed services.".into(),
                min_seniority: Seniority::Mid,
                tools: vec!["audit_config".into(), "audit_docker".into(), "audit_hardening".into()],
                methodology: "1. Enumerate configs 2. Check against CIS/STIG 3. Score hardening 4. Recommend fixes".into(),
                enabled: true,
            },
            Skill {
                id: "dep-audit".into(),
                name: "Dependency Auditor".into(),
                category: SkillCategory::Audit,
                description: "Audit dependencies: known CVEs, outdated packages, supply chain risks, SBOM analysis".into(),
                min_seniority: Seniority::Senior,
                tools: vec!["audit_deps".into(), "audit_cve".into(), "audit_supply_chain".into()],
                methodology: "1. Parse deps 2. Cross-ref CVE DB 3. Risk score 4. Remediation plan".into(),
                enabled: true,
            },

            // === REVERSING ===
            Skill {
                id: "re-jr".into(),
                name: "Reverse Engineer (Junior)".into(),
                category: SkillCategory::Reversing,
                description: "Basic binary analysis: strings, hex dump, file type identification, entropy analysis".into(),
                min_seniority: Seniority::Junior,
                tools: vec!["re_strings".into(), "re_hexdump".into(), "re_filetype".into(), "re_entropy".into()],
                methodology: "1. Identify file 2. Extract strings 3. Entropy check 4. Preliminary report".into(),
                enabled: true,
            },
            Skill {
                id: "re-sr".into(),
                name: "Reverse Engineer (Senior)".into(),
                category: SkillCategory::Reversing,
                description: "Advanced RE: packer detection, anti-debug analysis, control flow, cryptographic constant identification".into(),
                min_seniority: Seniority::Senior,
                tools: vec!["re_strings".into(), "re_hexdump".into(), "re_packer".into(), "re_crypto_constants".into(), "re_anti_debug".into()],
                methodology: "1. Triage 2. Unpack 3. Disassemble patterns 4. Identify crypto 5. Document findings".into(),
                enabled: true,
            },
            Skill {
                id: "re-expert".into(),
                name: "Reverse Engineer (Expert)".into(),
                category: SkillCategory::Reversing,
                description: "Expert RE: custom unpacking, VM-based obfuscation, protocol reversing, forensic carving".into(),
                min_seniority: Seniority::Expert,
                tools: vec!["re_strings".into(), "re_hexdump".into(), "re_packer".into(), "re_protocol".into(), "re_carving".into(), "re_obfuscation".into()],
                methodology: "1. Behavioral analysis 2. Unpack/Obfuscate 3. Protocol RE 4. Forensic extraction 5. Full report".into(),
                enabled: true,
            },

            // === PENTEST ===
            Skill {
                id: "pentest-jr".into(),
                name: "Penetration Tester (Junior)".into(),
                category: SkillCategory::Pentest,
                description: "Basic pentest: port scanning analysis, service enumeration, known exploit matching".into(),
                min_seniority: Seniority::Junior,
                tools: vec!["pentest_recon".into(), "pentest_services".into(), "pentest_cve_match".into()],
                methodology: "1. Recon 2. Enumeration 3. CVE matching 4. Basic report".into(),
                enabled: true,
            },
            Skill {
                id: "pentest-sr".into(),
                name: "Penetration Tester (Senior)".into(),
                category: SkillCategory::Pentest,
                description: "Advanced pentest: custom exploit analysis, privilege escalation paths, lateral movement vectors, persistence".into(),
                min_seniority: Seniority::Senior,
                tools: vec!["pentest_recon".into(), "pentest_services".into(), "pentest_exploit".into(), "pentest_priv_esc".into(), "pentest_lateral".into()],
                methodology: "1. Full recon 2. Vuln discovery 3. Exploit chain 4. Priv esc path 5. Lateral vectors 6. Full report".into(),
                enabled: true,
            },

            // === FORENSICS ===
            Skill {
                id: "forensics-mid".into(),
                name: "Forensic Analyst".into(),
                category: SkillCategory::Forensics,
                description: "Digital forensics: log analysis, timeline reconstruction, IOC extraction, artifact correlation".into(),
                min_seniority: Seniority::Mid,
                tools: vec!["forensics_logs".into(), "forensics_timeline".into(), "forensics_ioc".into()],
                methodology: "1. Acquire evidence 2. Timeline 3. IOC extraction 4. Correlation 5. Report".into(),
                enabled: true,
            },
            Skill {
                id: "forensics-expert".into(),
                name: "Forensic Analyst (Expert)".into(),
                category: SkillCategory::Forensics,
                description: "Expert forensics: memory analysis, filesystem carving, registry forensics, anti-forensics detection".into(),
                min_seniority: Seniority::Expert,
                tools: vec!["forensics_logs".into(), "forensics_timeline".into(), "forensics_ioc".into(), "forensics_memory".into(), "forensics_carving".into()],
                methodology: "1. Full acquisition 2. Memory dump analysis 3. Filesystem carving 4. Timeline + correlation 5. Expert report".into(),
                enabled: true,
            },

            // === CRYPTO ===
            Skill {
                id: "crypto-auditor".into(),
                name: "Cryptographic Auditor".into(),
                category: SkillCategory::Crypto,
                description: "Crypto audit: weak algorithms, hardcoded keys, insecure RNG, certificate validation, TLS configuration".into(),
                min_seniority: Seniority::Senior,
                tools: vec!["crypto_audit".into(), "crypto_weakness".into(), "crypto_cert".into(), "crypto_tls".into()],
                methodology: "1. Algorithm inventory 2. Key management audit 3. RNG audit 4. TLS config check 5. Report".into(),
                enabled: true,
            },

            // === MALWARE ===
            Skill {
                id: "malware-analyst".into(),
                name: "Malware Analyst".into(),
                category: SkillCategory::Malware,
                description: "Malware analysis: YARA rule generation, behavior analysis, C2 detection, sandbox evasion detection".into(),
                min_seniority: Seniority::Expert,
                tools: vec!["malware_yara".into(), "malware_behavior".into(), "malware_c2".into(), "malware_evasion".into()],
                methodology: "1. Static analysis 2. Behavioral indicators 3. YARA generation 4. C2 extraction 5. Threat intel report".into(),
                enabled: true,
            },

            // === NETWORK ===
            Skill {
                id: "network-auditor".into(),
                name: "Network Security Auditor".into(),
                category: SkillCategory::Network,
                description: "Network audit: firewall rules, IDS/IPS config, segmentation, encryption in transit, exposed services".into(),
                min_seniority: Seniority::Mid,
                tools: vec!["network_audit".into(), "network_firewall".into(), "network_exposure".into()],
                methodology: "1. Topology discovery 2. Rule audit 3. Exposure scan 4. Segmentation review 5. Report".into(),
                enabled: true,
            },

            // === OSINT ===
            Skill {
                id: "osint-analyst".into(),
                name: "OSINT Analyst".into(),
                category: SkillCategory::Osint,
                description: "Open-source intelligence: domain recon, email/username search, exposed credentials, data breach correlation".into(),
                min_seniority: Seniority::Mid,
                tools: vec!["osint_domain".into(), "osint_email".into(), "osint_breach".into()],
                methodology: "1. Domain/email enumeration 2. Breach DB check 3. Digital footprint mapping 4. Risk report".into(),
                enabled: true,
            },

            // === GENERAL ===
            Skill {
                id: "security-generalist".into(),
                name: "Security Generalist".into(),
                category: SkillCategory::General,
                description: "General security: threat modeling, risk assessment, security architecture review, compliance check".into(),
                min_seniority: Seniority::Junior,
                tools: vec!["audit_code".into(), "audit_secrets".into(), "audit_config".into(), "pentest_recon".into(), "re_strings".into(), "forensics_logs".into(), "osint_email".into(), "osint_domain".into()],
                methodology: "1. Scope definition 2. Multi-angle assessment 3. Risk scoring 4. Prioritized recommendations".into(),
                enabled: true,
            },
        ];

        let mut skills = self.skills.write().unwrap();
        for skill in defaults {
            skills.insert(skill.id.clone(), skill);
        }
    }

    pub fn get_all(&self) -> Vec<Skill> {
        self.skills.read().unwrap().values().cloned().collect()
    }

    pub fn get_by_category(&self, category: SkillCategory) -> Vec<Skill> {
        self.skills
            .read()
            .unwrap()
            .values()
            .filter(|s| s.category == category)
            .cloned()
            .collect()
    }

    pub fn get_for_seniority(&self, level: Seniority) -> Vec<Skill> {
        self.skills
            .read()
            .unwrap()
            .values()
            .filter(|s| s.min_seniority <= level)
            .cloned()
            .collect()
    }

    pub fn get_skill(&self, id: &str) -> Option<Skill> {
        self.skills.read().unwrap().get(id).cloned()
    }

    #[allow(dead_code)]
    pub fn register_skill(&self, skill: Skill) {
        self.skills.write().unwrap().insert(skill.id.clone(), skill);
    }

    pub fn assign_skill_to_agent(&self, agent_id: &str, skill_id: &str) {
        self.agent_skills
            .write()
            .unwrap()
            .entry(agent_id.to_string())
            .or_default()
            .push(skill_id.to_string());
    }

    #[allow(dead_code)]
    pub fn get_agent_skills(&self, agent_id: &str) -> Vec<Skill> {
        let agent_skills = self.agent_skills.read().unwrap();
        let skill_ids = agent_skills.get(agent_id).cloned().unwrap_or_default();
        let all_skills = self.skills.read().unwrap();
        skill_ids
            .iter()
            .filter_map(|id| all_skills.get(id).cloned())
            .collect()
    }

    pub fn can_use_tool(&self, agent_id: &str, tool_name: &str) -> bool {
        let agent_skills = self.agent_skills.read().unwrap();
        let skill_ids = agent_skills.get(agent_id).cloned().unwrap_or_default();
        let all_skills = self.skills.read().unwrap();
        skill_ids.iter().any(|sid| {
            all_skills
                .get(sid)
                .map(|s| s.tools.contains(&tool_name.to_string()))
                .unwrap_or(false)
        })
    }

    /// Registered skills that can be dynamically added
    pub fn register_custom(&self, skill: Skill) {
        self.skills.write().unwrap().insert(skill.id.clone(), skill);
    }

    #[allow(dead_code)]
    pub fn toggle_skill(&self, skill_id: &str, enabled: bool) -> bool {
        if let Some(skill) = self.skills.write().unwrap().get_mut(skill_id) {
            skill.enabled = enabled;
            true
        } else {
            false
        }
    }
}
