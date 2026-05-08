//! AUDIT-Nexus MCP Server
//!
//! Cybersecurity MCP server for OpenCode with skill-based seniority system.
//! Provides 25+ audit, reverse engineering, pentest, forensics, and crypto tools.
//!
//! ## Usage with OpenCode
//!
//! Add to OpenCode's MCP config:
//! ```json
//! { "mcpServers": { "audit-nexus": { "type": "stdio", "command": "audit-nexus" } } }
//! ```
//!
//! ## Skills System
//! - Junior: Basic pattern matching, known signature detection
//! - Mid: Contextual analysis, correlation, basic heuristics
//! - Senior: Advanced heuristics, multi-vector analysis, CVE research
//! - Expert: Novel exploit detection, zero-day analysis, advanced RE
//! - Principal: Architecture-level security review, threat modeling, APT analysis

use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::sync::Arc;

mod skills;
mod tools;

use skills::{Seniority, Skill, SkillCategory, SkillRegistry};
use tools as t;

struct AuditServer {
    skills: Arc<SkillRegistry>,
    current_agent_id: Arc<std::sync::RwLock<String>>,
    current_seniority: Arc<std::sync::RwLock<Seniority>>,
}

impl AuditServer {
    fn new() -> Self {
        Self {
            skills: Arc::new(SkillRegistry::new()),
            current_agent_id: Arc::new(std::sync::RwLock::new("anonymous".to_string())),
            current_seniority: Arc::new(std::sync::RwLock::new(Seniority::Senior)),
        }
    }

    fn run(&self) -> anyhow::Result<()> {
        let stdin = io::stdin();
        let mut stdout = io::stdout();
        let mut reader = io::BufReader::new(stdin.lock());

        eprintln!("╔══════════════════════════════════════════════════════════╗");
        eprintln!(
            "║  AUDIT-Nexus v{} - Cybersecurity MCP Server           ║",
            env!("CARGO_PKG_VERSION")
        );
        eprintln!("║  Skills: 20 | Tools: 25+ | Seniority: Jr→Principal    ║");
        eprintln!("╚══════════════════════════════════════════════════════════╝");
        eprintln!();

        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                break;
            }
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if let Some(response) = self.handle_message(line) {
                writeln!(stdout, "{}", response)?;
                stdout.flush()?;
            }
        }
        Ok(())
    }

    fn handle_message(&self, message: &str) -> Option<String> {
        let request: Value = match serde_json::from_str(message) {
            Ok(v) => v,
            Err(_) => {
                return Some(
                    json!({
                        "jsonrpc": "2.0",
                        "error": {"code": -32700, "message": "Invalid JSON"}
                    })
                    .to_string(),
                )
            }
        };

        let method = request["method"].as_str().unwrap_or("");
        let id = &request["id"];
        let params = &request["params"];

        let is_notification = id.is_null();

        let result = match method {
            "initialize" => {
                let client_name = params["clientInfo"]["name"]
                    .as_str()
                    .unwrap_or("mcp-client");
                *self.current_agent_id.write().unwrap() = client_name.to_string();
                // Auto-assign default security-generalist skill so agent can use tools immediately
                self.skills
                    .assign_skill_to_agent(client_name, "security-generalist");
                Ok(json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": {
                        "protocolVersion": params["protocolVersion"].as_str().unwrap_or("2024-11-05"),
                        "capabilities": { "tools": { "listChanged": true }, "resources": { "listChanged": true } },
                        "serverInfo": { "name": "audit-nexus", "version": env!("CARGO_PKG_VERSION") }
                    }
                }))
            }
            "initialized" => Ok(json!(null)),
            "shutdown" => {
                std::process::exit(0);
            }
            "tools/list" => Ok(self.list_tools(id)),
            "tools/call" => self.call_tool(id, params),
            _ => Ok(json!({
                "jsonrpc": "2.0", "id": id,
                "error": {"code": -32601, "message": format!("Method not found: {}", method)}
            })),
        };

        match result {
            Ok(resp) => {
                if is_notification {
                    None
                } else {
                    serde_json::to_string(&resp).ok()
                }
            }
            Err(e) => {
                if is_notification {
                    None
                } else {
                    serde_json::to_string(&json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": {"code": -32603, "message": e}
                    }))
                    .ok()
                }
            }
        }
    }

    fn list_tools(&self, id: &Value) -> Value {
        json!({
            "jsonrpc": "2.0", "id": id,
            "result": {
                "tools": [
                    // ── Skills Management ──
                    { "name": "skills_list", "description": "List all audit/security skills with their seniority levels, categories, and methodologies.",
                      "inputSchema": { "type": "object", "properties": { "category": { "type": "string", "enum": ["audit","reversing","pentest","forensics","crypto","malware","network","osint","general"] }, "seniority": { "type": "string", "enum": ["junior","mid","senior","expert","principal"] } } } },
                    { "name": "skills_assign", "description": "Assign a skill to the current agent at a given seniority level.",
                      "inputSchema": { "type": "object", "properties": { "skill_id": { "type": "string" } }, "required": ["skill_id"] } },
                    { "name": "skills_register", "description": "Register a custom skill with tools, category, and seniority requirement.",
                      "inputSchema": { "type": "object", "properties": { "name": { "type": "string" }, "category": { "type": "string" }, "description": { "type": "string" }, "min_seniority": { "type": "string", "enum": ["junior","mid","senior","expert","principal"] }, "tools": { "type": "array", "items": { "type": "string" } }, "methodology": { "type": "string" } }, "required": ["name"] } },
                    { "name": "seniority_set", "description": "Set the agent's current seniority level (determines available skills).",
                      "inputSchema": { "type": "object", "properties": { "level": { "type": "string", "enum": ["junior","mid","senior","expert","principal"] } }, "required": ["level"] } },
                    { "name": "seniority_get", "description": "Get current agent's seniority and available skills.",
                      "inputSchema": { "type": "object", "properties": {} } },

                    // ── Audit Tools ──
                    { "name": "audit_code", "description": "Audit source code for vulnerabilities: secrets, dangerous functions, injection vectors, missing error handling. Supports C/C++, Python, JS/TS, Rust, Go.",
                      "inputSchema": { "type": "object", "properties": { "code": { "type": "string", "description": "Source code to audit" }, "language": { "type": "string", "enum": ["c","cpp","python","javascript","typescript","rust","go","java"] } }, "required": ["code", "language"] } },
                    { "name": "audit_secrets", "description": "Scan for hardcoded secrets: API keys, tokens, passwords, private keys, JWT tokens, cloud credentials.",
                      "inputSchema": { "type": "object", "properties": { "source": { "type": "string", "description": "Text to scan for secrets" } }, "required": ["source"] } },
                    { "name": "audit_deps", "description": "Audit dependencies for known CVEs and vulnerable versions. Supports npm, pip, cargo, go.mod, Maven.",
                      "inputSchema": { "type": "object", "properties": { "deps_text": { "type": "string", "description": "Dependency file content" }, "ecosystem": { "type": "string", "enum": ["npm","pypi","cargo","go","maven"] } }, "required": ["deps_text", "ecosystem"] } },
                    { "name": "audit_config", "description": "Audit configuration files for hardening issues: Docker, K8s, nginx, SSH, systemd.",
                      "inputSchema": { "type": "object", "properties": { "config_text": { "type": "string", "description": "Configuration file content" }, "config_type": { "type": "string", "enum": ["docker","kubernetes","nginx","ssh","systemd","apache","mysql","postgres"] } }, "required": ["config_text", "config_type"] } },
                    { "name": "audit_comprehensive", "description": "Full codebase audit: combines code, secrets, deps, and config auditing in one call.",
                      "inputSchema": { "type": "object", "properties": { "code": { "type": "string" }, "language": { "type": "string" }, "deps_text": { "type": "string" }, "ecosystem": { "type": "string" }, "config_text": { "type": "string" }, "config_type": { "type": "string" } }, "required": ["code", "language"] } },

                    // ── Reverse Engineering ──
                    { "name": "re_strings", "description": "Extract printable strings from binary data. Returns top 50 strings + suspicious strings (URLs, keys, commands).",
                      "inputSchema": { "type": "object", "properties": { "hex_data": { "type": "string", "description": "Hex-encoded binary data" }, "min_length": { "type": "integer", "default": 4 } }, "required": ["hex_data"] } },
                    { "name": "re_hexdump", "description": "Hex dump of binary data with ASCII representation. Useful for examining binary headers, offsets, and structure.",
                      "inputSchema": { "type": "object", "properties": { "hex_data": { "type": "string" }, "offset": { "type": "integer", "default": 0 }, "length": { "type": "integer", "default": 256 } }, "required": ["hex_data"] } },
                    { "name": "re_entropy", "description": "Analyze entropy of binary data. High entropy (>7.0) indicates encryption/compression. Low entropy (<3.0) suggests text/code.",
                      "inputSchema": { "type": "object", "properties": { "hex_data": { "type": "string" } }, "required": ["hex_data"] } },
                    { "name": "re_packer", "description": "Detect packers and obfuscation: UPX, ASPack, VMProtect, Themida, custom packers. Checks entropy and known signatures.",
                      "inputSchema": { "type": "object", "properties": { "hex_data": { "type": "string" } }, "required": ["hex_data"] } },

                    // ── Pentest ──
                    { "name": "pentest_service", "description": "Analyze a service for known vulnerabilities based on name and version. Checks against CVE database references.",
                      "inputSchema": { "type": "object", "properties": { "service_name": { "type": "string" }, "version": { "type": "string" } }, "required": ["service_name", "version"] } },
                    { "name": "pentest_exploit_chain", "description": "Build an exploit chain from multiple vulnerabilities, showing privilege escalation and lateral movement paths.",
                      "inputSchema": { "type": "object", "properties": { "target": { "type": "string" }, "entry_points": { "type": "array", "items": { "type": "object" } } }, "required": ["target", "entry_points"] } },
                    { "name": "pentest_checklist", "description": "Generate a pentest checklist for a given target type (webapp, api, network, mobile, cloud, container).",
                      "inputSchema": { "type": "object", "properties": { "target_type": { "type": "string", "enum": ["webapp","api","network","mobile","cloud","container","desktop"] } }, "required": ["target_type"] } },

                    // ── Forensics ──
                    { "name": "forensics_logs", "description": "Analyze log files for IOCs: suspicious IPs, error patterns, timestamps, attack signatures.",
                      "inputSchema": { "type": "object", "properties": { "logs": { "type": "string", "description": "Log content to analyze" } }, "required": ["logs"] } },

                    // ── Crypto Audit ──
                    { "name": "crypto_audit", "description": "Audit cryptographic usage: detect weak algorithms (DES, MD5, SHA-1), hardcoded keys, insecure RNG, bad TLS config.",
                      "inputSchema": { "type": "object", "properties": { "source_text": { "type": "string", "description": "Source code or config to audit for crypto weaknesses" } }, "required": ["source_text"] } },

                    // ── Malware Analysis ──
                    { "name": "malware_yara", "description": "Generate YARA rules from indicators (strings, hex patterns, behavioral IOCs). Outputs ready-to-use YARA rule file.",
                      "inputSchema": { "type": "object", "properties": { "malware_name": { "type": "string" }, "indicators": { "type": "object", "properties": { "strings": { "type": "array" }, "hex_patterns": { "type": "array" } } } }, "required": ["malware_name", "indicators"] } },

                    // ── Network ──
                    { "name": "network_audit", "description": "Audit firewall rules for risky exposures, open ports to internet, missing default deny, SSH exposure.",
                      "inputSchema": { "type": "object", "properties": { "rules_text": { "type": "string", "description": "Firewall rules (iptables/nftables/ufw syntax)" } }, "required": ["rules_text"] } },

                    // ── OSINT ──
                    { "name": "osint_email", "description": "Analyze email address: domain check, breach exposure risk, associated accounts search methodology.",
                      "inputSchema": { "type": "object", "properties": { "email": { "type": "string" } }, "required": ["email"] } },
                    { "name": "osint_domain", "description": "Reconnaissance on a domain: WHOIS lookup, DNS records, SSL certificate info, subdomain enumeration hints.",
                      "inputSchema": { "type": "object", "properties": { "domain": { "type": "string" } }, "required": ["domain"] } },
                ]
            }
        })
    }

    fn call_tool(&self, id: &Value, params: &Value) -> Result<Value, String> {
        let name = params["name"].as_str().unwrap_or("");
        let args = &params["arguments"];
        let agent_id = self.current_agent_id.read().unwrap().clone();

        // Skill-based access control
        if !self.skills.can_use_tool(&agent_id, name) && !self.is_management_tool(name) {
            return Ok(json!({
                "jsonrpc": "2.0", "id": id,
                "error": { "code": -32001, "message": format!("Agent '{}' lacks required skill for tool '{}'. Assign a skill that includes this tool first.", agent_id, name) }
            }));
        }

        let result = match name {
            // ── Skills ──
            "skills_list" => self.cmd_skills_list(args),
            "skills_assign" => self.cmd_skills_assign(args),
            "skills_register" => self.cmd_skills_register(args),
            "seniority_set" => self.cmd_seniority_set(args),
            "seniority_get" => self.cmd_seniority_get(),

            // ── Audit ──
            "audit_code" => self.cmd_audit_code(args),
            "audit_secrets" => self.cmd_audit_secrets(args),
            "audit_deps" => self.cmd_audit_deps(args),
            "audit_config" => self.cmd_audit_config(args),
            "audit_comprehensive" => self.cmd_audit_comprehensive(args),

            // ── RE ──
            "re_strings" => self.cmd_re_strings(args),
            "re_hexdump" => self.cmd_re_hexdump(args),
            "re_entropy" => self.cmd_re_entropy(args),
            "re_packer" => self.cmd_re_packer(args),

            // ── Pentest ──
            "pentest_service" => self.cmd_pentest_service(args),
            "pentest_exploit_chain" => self.cmd_pentest_exploit_chain(args),
            "pentest_checklist" => self.cmd_pentest_checklist(args),

            // ── Forensics ──
            "forensics_logs" => self.cmd_forensics_logs(args),

            // ── Crypto ──
            "crypto_audit" => self.cmd_crypto_audit(args),

            // ── Malware ──
            "malware_yara" => self.cmd_malware_yara(args),

            // ── Network ──
            "network_audit" => self.cmd_network_audit(args),

            // ── OSINT ──
            "osint_email" => self.cmd_osint_email(args),
            "osint_domain" => self.cmd_osint_domain(args),

            _ => {
                return Ok(
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": format!("Unknown tool: {}", name) } }),
                )
            }
        };

        Ok(
            json!({ "jsonrpc": "2.0", "id": id, "result": { "content": [{ "type": "text", "text": serde_json::to_string_pretty(&result).unwrap_or_default() }] } }),
        )
    }

    fn is_management_tool(&self, name: &str) -> bool {
        matches!(
            name,
            "skills_list" | "skills_assign" | "skills_register" | "seniority_set" | "seniority_get"
        )
    }

    // ══════════════════════════════════════════════════
    // SKILL MANAGEMENT HANDLERS
    // ══════════════════════════════════════════════════

    fn cmd_skills_list(&self, args: &Value) -> Value {
        let mut skills = self.skills.get_all();
        if let Some(cat) = args.get("category").and_then(|v| v.as_str()) {
            if let Ok(cat) = serde_json::from_value::<SkillCategory>(json!(cat)) {
                skills = self.skills.get_by_category(cat);
            }
        }
        if let Some(level) = args.get("seniority").and_then(|v| v.as_str()) {
            if let Some(s) = Seniority::from_str(level) {
                skills.retain(|sk| sk.min_seniority <= s);
            }
        }
        json!({ "skills": skills, "count": skills.len(), "categories": ["audit","reversing","pentest","forensics","crypto","malware","network","osint","general"] })
    }

    fn cmd_skills_assign(&self, args: &Value) -> Value {
        let skill_id = args["skill_id"].as_str().unwrap_or("");
        let agent_id = self.current_agent_id.read().unwrap().clone();
        if let Some(skill) = self.skills.get_skill(skill_id) {
            self.skills.assign_skill_to_agent(&agent_id, skill_id);
            json!({ "assigned": true, "agent_id": agent_id, "skill": skill })
        } else {
            json!({ "error": format!("Skill '{}' not found", skill_id) })
        }
    }

    fn cmd_skills_register(&self, args: &Value) -> Value {
        let name = args["name"].as_str().unwrap_or("Unnamed").to_string();
        let category = args["category"].as_str().unwrap_or("general");
        let min_seniority = Seniority::from_str(args["min_seniority"].as_str().unwrap_or("mid"))
            .unwrap_or(Seniority::Mid);
        let tools: Vec<String> = args["tools"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let skill = Skill {
            id: format!("custom-{}", name.to_lowercase().replace(' ', "-")),
            name,
            category: serde_json::from_value::<SkillCategory>(json!(category))
                .unwrap_or(SkillCategory::General),
            description: args["description"]
                .as_str()
                .unwrap_or("Custom skill")
                .to_string(),
            min_seniority,
            tools,
            methodology: args["methodology"]
                .as_str()
                .unwrap_or("Custom methodology")
                .to_string(),
            enabled: true,
        };
        let skill_id = skill.id.clone();
        self.skills.register_custom(skill);
        json!({ "registered": true, "skill_id": skill_id })
    }

    fn cmd_seniority_set(&self, args: &Value) -> Value {
        if let Some(level) = Seniority::from_str(args["level"].as_str().unwrap_or("mid")) {
            *self.current_seniority.write().unwrap() = level;
            let available = self.skills.get_for_seniority(level);
            json!({ "seniority": format!("{:?}", level), "level": level as u8, "available_skills": available.len() })
        } else {
            json!({ "error": "Invalid seniority level" })
        }
    }

    fn cmd_seniority_get(&self) -> Value {
        let level = *self.current_seniority.read().unwrap();
        let available = self.skills.get_for_seniority(level);
        let all = self.skills.get_all();
        json!({ "seniority": format!("{:?}", level), "level": level as u8, "available_skills": available.len(), "total_skills": all.len(), "available": available })
    }

    // ══════════════════════════════════════════════════
    // AUDIT HANDLERS
    // ══════════════════════════════════════════════════

    fn cmd_audit_code(&self, args: &Value) -> Value {
        let code = args["code"].as_str().unwrap_or("");
        let lang = args["language"].as_str().unwrap_or("generic");
        t::audit_code(code, lang)
    }

    fn cmd_audit_secrets(&self, args: &Value) -> Value {
        t::audit_secrets(args["source"].as_str().unwrap_or(""))
    }

    fn cmd_audit_deps(&self, args: &Value) -> Value {
        t::audit_deps(
            args["deps_text"].as_str().unwrap_or(""),
            args["ecosystem"].as_str().unwrap_or("generic"),
        )
    }

    fn cmd_audit_config(&self, args: &Value) -> Value {
        let config_text = args["config_text"].as_str().unwrap_or("");
        let config_type = args["config_type"].as_str().unwrap_or("generic");
        // Basic config audit - check for common hardening issues
        let mut findings = Vec::new();
        let hardening_checks = [
            ("password.*root", "Root password in config"),
            ("PermitRootLogin.*yes", "SSH root login enabled"),
            ("PasswordAuthentication.*yes", "SSH password auth enabled"),
            ("bind.*0\\.0\\.0\\.0", "Service binding to all interfaces"),
            ("privileged.*true", "Container running in privileged mode"),
            (":latest", "Using :latest tag (no version pinning)"),
            ("ssl.*false|tls.*false", "TLS/SSL disabled"),
            ("DEBUG.*true", "Debug mode enabled in production"),
        ];
        for (pattern, desc) in &hardening_checks {
            if let Ok(re) = regex::Regex::new(&format!("(?i){}", pattern)) {
                if re.is_match(config_text) {
                    findings.push(json!({"pattern": desc, "severity": "high"}));
                }
            }
        }
        json!({ "config_type": config_type, "findings": findings, "total_issues": findings.len() })
    }

    fn cmd_audit_comprehensive(&self, args: &Value) -> Value {
        let code_audit = self.cmd_audit_code(args);
        let secrets_audit = t::audit_secrets(args["code"].as_str().unwrap_or(""));
        let deps_audit = if args.get("deps_text").is_some() {
            Some(t::audit_deps(
                args["deps_text"].as_str().unwrap_or(""),
                args["ecosystem"].as_str().unwrap_or("generic"),
            ))
        } else {
            None
        };
        let config_audit = if args.get("config_text").is_some() {
            Some(self.cmd_audit_config(args))
        } else {
            None
        };

        json!({
            "code_audit": code_audit,
            "secrets_audit": secrets_audit,
            "deps_audit": deps_audit,
            "config_audit": config_audit,
            "overall_risk": "See individual audit sections for detailed findings"
        })
    }

    // ══════════════════════════════════════════════════
    // REVERSE ENGINEERING HANDLERS
    // ══════════════════════════════════════════════════

    fn decode_hex(args: &Value) -> Option<Vec<u8>> {
        let hex_str = args["hex_data"].as_str()?;
        hex::decode(hex_str).ok()
    }

    fn cmd_re_strings(&self, args: &Value) -> Value {
        match Self::decode_hex(args) {
            Some(data) => t::re_strings(&data, args["min_length"].as_u64().unwrap_or(4) as usize),
            None => json!({"error": "Invalid hex data"}),
        }
    }

    fn cmd_re_hexdump(&self, args: &Value) -> Value {
        match Self::decode_hex(args) {
            Some(data) => t::re_hexdump(
                &data,
                args["offset"].as_u64().unwrap_or(0) as usize,
                args["length"].as_u64().unwrap_or(256) as usize,
            ),
            None => json!({"error": "Invalid hex data"}),
        }
    }

    fn cmd_re_entropy(&self, args: &Value) -> Value {
        match Self::decode_hex(args) {
            Some(data) => t::re_entropy(&data),
            None => json!({"error": "Invalid hex data"}),
        }
    }

    fn cmd_re_packer(&self, args: &Value) -> Value {
        match Self::decode_hex(args) {
            Some(data) => t::re_packer(&data),
            None => json!({"error": "Invalid hex data"}),
        }
    }

    // ══════════════════════════════════════════════════
    // PENTEST HANDLERS
    // ══════════════════════════════════════════════════

    fn cmd_pentest_service(&self, args: &Value) -> Value {
        t::pentest_analyze_service(
            args["service_name"].as_str().unwrap_or(""),
            args["version"].as_str().unwrap_or(""),
        )
    }

    fn cmd_pentest_exploit_chain(&self, args: &Value) -> Value {
        let entry_points = args["entry_points"].as_array().cloned().unwrap_or_default();
        t::pentest_exploit_chain(args["target"].as_str().unwrap_or(""), &entry_points)
    }

    fn cmd_pentest_checklist(&self, args: &Value) -> Value {
        let target_type = args["target_type"].as_str().unwrap_or("webapp");
        let checklist: Vec<&str> = match target_type {
            "webapp" => vec![
                "OWASP Top 10 (2021) audit",
                "Authentication bypass (JWT, session, OAuth)",
                "Authorization (IDOR, privilege escalation)",
                "Injection (SQL, NoSQL, Command, SSTI)",
                "XSS (reflected, stored, DOM)",
                "CSRF",
                "File upload (path traversal, RCE via upload)",
                "SSRF",
                "XXE",
                "API endpoint enumeration",
                "CORS misconfig",
                "Rate limiting bypass",
            ],
            "api" => vec![
                "Authentication (API keys, JWT, OAuth2)",
                "Rate limiting",
                "BOLA/IDOR",
                "Mass assignment",
                "Excessive data exposure",
                "GraphQL introspection",
                "REST API versioning issues",
                "Input validation bypass",
                "HTTP method override",
            ],
            "network" => vec![
                "Nmap scan (all ports)",
                "Service version enumeration",
                "Firewall rule audit",
                "DNS zone transfer attempt",
                "SNMP enumeration",
                "SMB share enumeration",
                "VLAN hopping check",
                "ARP spoofing detection",
                "Rogue DHCP detection",
            ],
            "cloud" => vec![
                "S3 bucket permissions",
                "IAM role enumeration",
                "Security group audit",
                "CloudTrail logging enabled",
                "KMS key rotation",
                "Lambda environment variables",
                "RDS public accessibility",
                "EBS encryption",
                "VPC flow logs",
            ],
            "container" => vec![
                "Privileged mode check",
                "Capabilities audit",
                "Read-only root filesystem",
                "Resource limits (CPU/memory)",
                "Seccomp/AppArmor profiles",
                "Image vulnerability scan",
                "Docker socket exposure",
                "Network mode (host)",
                "Rootless mode",
            ],
            _ => vec![
                "Reconnaissance",
                "Enumeration",
                "Vulnerability identification",
                "Exploitation",
                "Post-exploitation",
            ],
        };
        json!({ "target_type": target_type, "checklist": checklist, "phases": ["Recon", "Enumeration", "Exploitation", "Privilege Escalation", "Persistence", "Cleanup"] })
    }

    // ══════════════════════════════════════════════════
    // FORENSICS HANDLERS
    // ══════════════════════════════════════════════════

    fn cmd_forensics_logs(&self, args: &Value) -> Value {
        t::forensics_analyze_logs(args["logs"].as_str().unwrap_or(""))
    }

    // ══════════════════════════════════════════════════
    // CRYPTO HANDLERS
    // ══════════════════════════════════════════════════

    fn cmd_crypto_audit(&self, args: &Value) -> Value {
        t::crypto_audit_keys(args["source_text"].as_str().unwrap_or(""))
    }

    // ══════════════════════════════════════════════════
    // MALWARE HANDLERS
    // ══════════════════════════════════════════════════

    fn cmd_malware_yara(&self, args: &Value) -> Value {
        let indicators = json!({
            "name": args["malware_name"].as_str().unwrap_or("Unknown"),
            "strings": args["indicators"]["strings"].as_array().cloned(),
            "hex_patterns": args["indicators"]["hex_patterns"].as_array().cloned(),
        });
        t::malware_generate_yara(&indicators)
    }

    // ══════════════════════════════════════════════════
    // NETWORK HANDLERS
    // ══════════════════════════════════════════════════

    fn cmd_network_audit(&self, args: &Value) -> Value {
        t::network_audit_firewall(args["rules_text"].as_str().unwrap_or(""))
    }

    // ══════════════════════════════════════════════════
    // OSINT HANDLERS
    // ══════════════════════════════════════════════════

    fn cmd_osint_email(&self, args: &Value) -> Value {
        t::osint_email_analyze(args["email"].as_str().unwrap_or(""))
    }

    fn cmd_osint_domain(&self, args: &Value) -> Value {
        t::osint_domain_recon(args["domain"].as_str().unwrap_or(""))
    }
}

fn main() -> anyhow::Result<()> {
    let server = AuditServer::new();
    server.run()
}
