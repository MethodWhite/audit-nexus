//! Audit Nexus Tools - Specialized cybersecurity tooling
//!
//! Each tool implements a specific cybersecurity capability.
//! Tools are gated by skill seniority levels from the SkillRegistry.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::process::Command;

// ═══════════════════════════════════════════════════════════
// AUDIT TOOLS
// ═══════════════════════════════════════════════════════════

pub fn audit_code(source: &str, language: &str) -> Value {
    let mut findings = Vec::new();
    let mut score: u32 = 100;

    // Hardcoded secrets patterns
    let secret_patterns = [
        (
            "API key",
            r#"(?i)(api[_-]?key|apikey|api_secret)\s*[:=]\s*['"][^'"]{8,}['"]"#,
        ),
        (
            "Password",
            r#"(?i)(password|passwd|pwd)\s*[:=]\s*['"][^'"]+"#,
        ),
        (
            "Token",
            r#"(?i)(token|secret|jwt)\s*[:=]\s*['"][^'"]{8,}['"]"#,
        ),
        (
            "Private key",
            r#"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"#,
        ),
        ("AWS key", r#"(?i)(AKIA[0-9A-Z]{16}|aws_access_key_id)"#),
    ];

    for (name, pattern) in &secret_patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if re.is_match(source) {
                findings.push(json!({
                    "type": "hardcoded_secret",
                    "severity": "critical",
                    "name": name,
                    "description": format!("Hardcoded {} detected in source code.", name.to_lowercase())
                }));
                score = score.saturating_sub(20);
            }
        }
    }

    // Dangerous functions by language
    let dangerous: &[(&str, &str, &str)] = match language {
        "c" | "cpp" | "c++" => &[
            (
                "strcpy",
                "critical",
                "Buffer overflow risk - use strncpy or strlcpy",
            ),
            ("gets", "critical", "Buffer overflow - use fgets instead"),
            (
                "sprintf",
                "high",
                "Format string vulnerability - use snprintf",
            ),
            ("system", "high", "Command injection risk - sanitize input"),
            ("popen", "high", "Command injection risk"),
            ("malloc", "low", "Check for NULL return"),
        ],
        "python" => &[
            (
                "eval(",
                "critical",
                "Code injection - never eval() user input",
            ),
            (
                "exec(",
                "critical",
                "Code injection - never exec() user input",
            ),
            (
                "pickle.loads",
                "critical",
                "Deserialization RCE - use json instead",
            ),
            (
                "os.system",
                "high",
                "Command injection risk - use subprocess.run with list",
            ),
            (
                "subprocess.call.*shell=True",
                "high",
                "Shell injection risk",
            ),
            ("hashlib.md5", "low", "Weak hash - use SHA256+"),
        ],
        "javascript" | "typescript" => &[
            ("eval(", "critical", "Code injection"),
            ("new Function(", "critical", "Code injection"),
            ("innerHTML", "high", "XSS risk - use textContent"),
            ("document.write", "high", "XSS risk"),
            ("dangerouslySetInnerHTML", "high", "React XSS risk"),
        ],
        "rust" => &[
            ("unsafe", "high", "Unsafe block - audit manually"),
            ("unwrap()", "low", "Consider proper error handling"),
            (
                "std::process::Command",
                "medium",
                "Command execution - sanitize input",
            ),
        ],
        "go" => &[
            ("exec.Command", "high", "Command injection risk"),
            ("unsafe.Pointer", "high", "Unsafe memory access"),
            ("template.HTML", "medium", "XSS risk in templates"),
        ],
        _ => &[],
    };

    for (func, severity, desc) in dangerous {
        if source.contains(func) {
            findings.push(json!({
                "type": "dangerous_function",
                "severity": severity,
                "function": func,
                "description": desc
            }));
            let penalty = match *severity {
                "critical" => 15,
                "high" => 8,
                "medium" => 4,
                _ => 2,
            };
            score = score.saturating_sub(penalty);
        }
    }

    // Missing error handling
    if language == "python" && !source.contains("try:") && !source.contains("except") {
        if source.len() > 200 {
            findings.push(json!({
                "type": "missing_error_handling",
                "severity": "medium",
                "description": "No try/except blocks found. Add error handling."
            }));
            score = score.saturating_sub(5);
        }
    }

    json!({
        "score": score.min(100),
        "grade": match score { 90..=100 => "A", 75..=89 => "B", 60..=74 => "C", 40..=59 => "D", _ => "F" },
        "findings": findings,
        "total_findings": findings.len(),
        "language": language
    })
}

pub fn audit_secrets(source: &str) -> Value {
    let patterns = [
        ("AWS Access Key", r#"AKIA[0-9A-Z]{16}"#),
        (
            "AWS Secret Key",
            r#"(?i)aws.{0,5}secret.{0,10}[=:]\s*['"][^'"]{16,}['"]"#,
        ),
        ("GitHub Token", r#"gh[pousr]_[A-Za-z0-9_]{36}"#),
        ("GitHub PAT", r#"github_pat_[A-Za-z0-9_]{22,}"#),
        (
            "JWT Token",
            r#"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"#,
        ),
        ("Slack Token", r#"xox[baprs]-[0-9A-Za-z-]{10,50}"#),
        (
            "SSH Private Key",
            r#"-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----"#,
        ),
        (
            "Generic API Key",
            r#"(?i)(api.key|secret|token|password).{0,10}[:=]\s*['"][A-Za-z0-9+/=]{20,}['"]"#,
        ),
        (
            "IP Address (internal)",
            r#"\b(10\.\d{1,3}|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"#,
        ),
        (
            "Email Address",
            r#"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"#,
        ),
    ];

    let mut found = Vec::new();
    for (name, pattern) in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            for m in re.find_iter(source) {
                let matched = m.as_str();
                if matched.len() > 30 {
                    found.push(json!({
                        "type": *name,
                        "value_preview": format!("{}...", &matched[..30.min(matched.len())])
                    }));
                } else {
                    found.push(json!({
                        "type": *name,
                        "value_preview": matched
                    }));
                }
            }
        }
    }

    json!({
        "secrets_found": found.len(),
        "severity": if found.is_empty() { "clean" } else { "critical" },
        "secrets": found
    })
}

pub fn audit_deps(deps_text: &str, ecosystem: &str) -> Value {
    let mut findings = Vec::new();

    let known_vuln_patterns = [
        ("log4j", "CVE-2021-44228", "critical", "Log4Shell RCE"),
        ("struts2", "CVE-2017-5638", "critical", "Struts2 RCE"),
        (
            "spring4shell|spring-beans.*5\\.3\\.",
            "CVE-2022-22965",
            "critical",
            "Spring4Shell RCE",
        ),
        (
            "fastjson.*1\\.2\\.[0-7]",
            "CVE-2022-25845",
            "critical",
            "Fastjson RCE",
        ),
        (
            "openssl.*1\\.1\\.[0-1][a-l]",
            "CVE-2022-3602",
            "high",
            "OpenSSL buffer overflow",
        ),
        (
            "jackson-databind.*2\\.1[0-2]\\.",
            "CVE-2020-36518",
            "high",
            "Jackson DoS",
        ),
        (
            "requests.*2\\.[0-2][0-7]\\.",
            "CVE-2023-32681",
            "medium",
            "Requests proxy leak",
        ),
    ];

    for (pat, cve, severity, desc) in &known_vuln_patterns {
        if let Ok(re) = regex::Regex::new(&format!("(?i){}", pat)) {
            if re.is_match(deps_text) {
                findings.push(json!({
                    "cve": cve,
                    "severity": severity,
                    "description": desc,
                    "ecosystem": ecosystem
                }));
            }
        }
    }

    json!({
        "ecosystem": ecosystem,
        "vulnerable_deps": findings.len(),
        "findings": findings
    })
}

// ═══════════════════════════════════════════════════════════
// REVERSE ENGINEERING TOOLS
// ═══════════════════════════════════════════════════════════

pub fn re_strings(data: &[u8], min_len: usize) -> Value {
    let mut strings = Vec::new();
    let mut current = Vec::new();

    for &byte in data {
        if byte.is_ascii_graphic() || byte == b' ' {
            current.push(byte);
        } else {
            if current.len() >= min_len {
                strings.push(String::from_utf8_lossy(&current).to_string());
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        strings.push(String::from_utf8_lossy(&current).to_string());
    }

    strings.sort();
    strings.dedup();

    let suspicious: Vec<&str> = strings
        .iter()
        .filter(|s| {
            s.contains("http://")
                || s.contains("https://")
                || s.contains("key")
                || s.contains("pass")
                || s.contains("secret")
                || s.contains(".exe")
                || s.contains(".dll")
                || s.contains(".so")
                || s.contains("/bin/")
                || s.contains("cmd")
                || s.contains("shell")
                || s.contains("HACK")
                || s.contains("ADMIN")
                || s.contains("root")
        })
        .map(|s| s.as_str())
        .collect();

    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hex::encode(hasher.finalize());

    json!({
        "sha256": hash,
        "total_size": data.len(),
        "strings_count": strings.len(),
        "suspicious_strings": suspicious.len(),
        "top_strings": strings.iter().take(50).collect::<Vec<_>>(),
        "suspicious": suspicious.iter().take(30).collect::<Vec<_>>()
    })
}

pub fn re_hexdump(data: &[u8], offset: usize, length: usize) -> Value {
    let start = offset.min(data.len());
    let end = (offset + length).min(data.len());
    let slice = &data[start..end];

    let mut hex_lines = Vec::new();
    for (i, chunk) in slice.chunks(16).enumerate() {
        let addr = start + i * 16;
        let hex: String = chunk
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|p| p.join(""))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        hex_lines.push(format!("{:08x}  {:48}  |{}|", addr, hex, ascii));
    }

    json!({
        "offset": start,
        "length": slice.len(),
        "total_size": data.len(),
        "hexdump": hex_lines
    })
}

pub fn re_entropy(data: &[u8]) -> Value {
    let len = data.len() as f64;
    if len == 0.0 {
        return json!({ "entropy": 0.0, "verdict": "empty", "distribution": [] });
    }

    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }

    let entropy: f64 = freq
        .iter()
        .filter(|&&f| f > 0)
        .map(|&f| {
            let p = f as f64 / len;
            -p * p.log2()
        })
        .sum();

    let distribution: Vec<u64> = freq.iter().take(16).copied().collect();

    let verdict = if entropy > 7.5 {
        "likely_encrypted_or_compressed"
    } else if entropy > 5.0 {
        "likely_binary"
    } else if entropy > 3.0 {
        "likely_text_or_code"
    } else {
        "likely_plaintext"
    };

    json!({
        "entropy": (entropy * 100.0).round() / 100.0,
        "verdict": verdict,
        "max_entropy": 8.0,
        "distribution_sample": distribution
    })
}

pub fn re_packer(data: &[u8]) -> Value {
    let mut indicators: Vec<String> = Vec::new();

    let packer_sigs: &[(&[u8], &str)] = &[
        (b"UPX", "UPX packer"),
        (b"ASPack", "ASPack"),
        (b"PECompact", "PECompact"),
        (b"petite", "Petite"),
        (b"FSG!", "FSG"),
        (b"MPRESS", "MPRESS"),
        (b"VMProtect", "VMProtect"),
        (b"Themida", "Themida"),
        (b".enigma", "Enigma Protector"),
        (b"obsidium", "Obsidium"),
        (b"yoda's", "yoda's Protector"),
    ];

    let window_size = 1024usize;
    for (sig, name) in packer_sigs {
        for window in data.windows(window_size) {
            if window.windows(sig.len()).any(|w| w == *sig) {
                indicators.push(name.to_string());
                break;
            }
        }
    }

    let entropy = re_entropy(data);
    if entropy["entropy"].as_f64().unwrap_or(0.0) > 7.0 {
        indicators.push("high_entropy_sections".to_string());
    }

    let section_count = data
        .windows(2)
        .filter(|w| w == b".text" || w == b".data" || w == b".rdata" || w == b".rsrc")
        .count();

    json!({
        "packer_detected": !indicators.is_empty(),
        "indicators": indicators,
        "section_markers_found": section_count,
        "recommendation": if !indicators.is_empty() {
            "Binary appears packed/obfuscated. Manual unpacking may be required."
        } else {
            "No known packer signatures detected. Binary may be unpacked or custom-packed."
        }
    })
}

// ═══════════════════════════════════════════════════════════
// PENTEST TOOLS
// ═══════════════════════════════════════════════════════════

pub fn pentest_analyze_service(service_name: &str, version: &str) -> Value {
    let mut vulns = Vec::new();
    let mut score = 0u32;

    let known = [
        (
            "ssh",
            "7.0",
            "high",
            "Older SSH - check for weak ciphers, check CVE-2016-0777",
        ),
        (
            "apache",
            "2.4.49",
            "critical",
            "CVE-2021-41773 - Path traversal RCE",
        ),
        (
            "apache",
            "2.4.50",
            "critical",
            "CVE-2021-42013 - Path traversal RCE",
        ),
        (
            "nginx",
            "1.20",
            "medium",
            "Check for HTTP request smuggling",
        ),
        (
            "mysql",
            "5.7",
            "high",
            "Check for CVE-2021-2022, authentication bypass",
        ),
        ("postgresql", "12", "medium", "Check for CVE-2020-25695"),
        ("redis", "5.0", "high", "Check if exposed without auth"),
        (
            "tomcat",
            "9.0",
            "high",
            "Check for CVE-2025-24813, CVE-2020-9484",
        ),
        ("vsftpd", "2.3.4", "critical", "Backdoor (CVE-2011-2523)"),
        ("opensmtpd", "6.6", "critical", "CVE-2020-7247 - Root RCE"),
        ("drupal", "7", "critical", "Drupalgeddon (CVE-2018-7600)"),
        (
            "wordpress",
            "5",
            "high",
            "Check for plugin vulnerabilities, CVE-2020-35489",
        ),
    ];

    for (svc, ver, severity, desc) in &known {
        if service_name.to_lowercase().contains(*svc) && version.contains(*ver) {
            vulns.push(json!({"cve": desc.split(" - ").next().unwrap_or(""), "severity": severity, "description": desc}));
            score += match *severity {
                "critical" => 40,
                "high" => 25,
                "medium" => 10,
                _ => 5,
            };
        }
    }

    json!({
        "service": service_name,
        "version": version,
        "risk_score": score.min(100),
        "vulnerabilities": vulns,
        "recommendation": if score > 50 { "IMMEDIATE PATCH REQUIRED" } else if score > 20 { "Update recommended" } else { "Monitor for new CVEs" }
    })
}

pub fn pentest_exploit_chain(target: &str, entry_points: &[Value]) -> Value {
    let severity_order = ["critical", "high", "medium", "low"];
    let mut chains = Vec::new();
    let mut sorted_points: Vec<&Value> = entry_points.iter().collect();
    sorted_points.sort_by(|a, b| {
        let sa = a["severity"].as_str().unwrap_or("low");
        let sb = b["severity"].as_str().unwrap_or("low");
        let ia = severity_order.iter().position(|&s| s == sa).unwrap_or(99);
        let ib = severity_order.iter().position(|&s| s == sb).unwrap_or(99);
        ia.cmp(&ib)
    });

    for (i, point) in sorted_points.iter().enumerate() {
        let severity = point["severity"].as_str().unwrap_or("low");
        let vuln_type = point["type"].as_str().unwrap_or("unknown");
        let desc = point["description"].as_str().unwrap_or("No description");

        let chain = json!({
            "step": i + 1,
            "entry": point,
            "exploitation": match severity {
                "critical" => format!("Direct exploitation likely: {}. Immediate action required.", desc),
                "high" => format!("Exploitable with moderate effort: {}. Patch within 48h.", desc),
                "medium" => format!("Exploitation possible with chaining: {}. Patch within 30 days.", desc),
                _ => format!("Low severity: {}. Monitor and patch in regular cycle.", desc)
            },
            "privilege_escalation": match vuln_type {
                "rce" | "code_execution" => "Direct code execution → possible root/system access",
                "sqli" => "SQL injection → database access → potential credential theft → lateral movement",
                "xss" => "XSS → session hijacking → privilege escalation to victim's level",
                "ssrf" => "SSRF → internal network access → pivot to internal services",
                _ => "Evaluate for chaining opportunities"
            },
            "lateral_movement": if i < sorted_points.len() - 1 {
                "Chain to next vulnerability for expanded access"
            } else {
                "Endpoint: maximum access achieved for this chain"
            }
        });
        chains.push(chain);
    }

    json!({
        "target": target,
        "attack_surface": entry_points.len(),
        "exploit_chain": chains,
        "overall_risk": if entry_points.iter().any(|e| e["severity"] == "critical") {
            "CRITICAL - Immediate exploitation risk"
        } else if entry_points.iter().any(|e| e["severity"] == "high") {
            "HIGH - High exploitation risk within 48h"
        } else {
            "MODERATE - Treat within standard patch cycle"
        }
    })
}

// ═══════════════════════════════════════════════════════════
// FORENSICS TOOLS
// ═══════════════════════════════════════════════════════════

pub fn forensics_analyze_logs(logs: &str) -> Value {
    let mut iocs = Vec::new();
    let mut timeline = Vec::new();

    let ip_pattern = regex::Regex::new(r#"\b(?:\d{1,3}\.){3}\d{1,3}\b"#).unwrap();
    let timestamp_pattern = regex::Regex::new(r#"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"#).unwrap();
    let error_pattern =
        regex::Regex::new(r#"(?i)(error|fail|denied|blocked|unauthorized|invalid|attack|exploit)"#)
            .unwrap();

    for line in logs.lines() {
        let mut event = json!({"raw": line, "type": "info"});

        if error_pattern.is_match(line) {
            event["type"] = json!("suspicious");
            iocs.push(json!({
                "type": "suspicious_log_entry",
                "entry": line,
                "matched": "error/attack pattern"
            }));
        }

        for ip in ip_pattern.find_iter(line) {
            let ip_str = ip.as_str();
            if !ip_str.starts_with("10.")
                && !ip_str.starts_with("192.168.")
                && !ip_str.starts_with("172.16.")
            {
                iocs.push(json!({
                    "type": "ip_address",
                    "ip": ip_str,
                    "context": line
                }));
            }
        }

        if let Some(ts) = timestamp_pattern.find(line) {
            event["timestamp"] = json!(ts.as_str());
        }

        timeline.push(event);
    }

    let unique_ips: std::collections::HashSet<&str> =
        ip_pattern.find_iter(logs).map(|m| m.as_str()).collect();

    json!({
        "total_lines": logs.lines().count(),
        "suspicious_events": iocs.iter().filter(|i| i["type"] == "suspicious_log_entry").count(),
        "unique_ips": unique_ips.len(),
        "iocs": iocs,
        "timeline_summary": format!("{} events analyzed, {} suspicious", timeline.len(), iocs.len())
    })
}

// ═══════════════════════════════════════════════════════════
// CRYPTO TOOLS
// ═══════════════════════════════════════════════════════════

pub fn crypto_audit_keys(source: &str) -> Value {
    let mut weak_keys = Vec::new();

    let weak_algorithms = [
        ("DES", "Obsolete symmetric cipher - use AES-256"),
        ("3DES", "Deprecated - use AES-256-GCM"),
        ("RC4", "Broken stream cipher - use ChaCha20"),
        ("MD4", "Completely broken hash - use SHA-256"),
        ("MD5", "Collision-vulnerable hash - use SHA-256"),
        ("SHA-1", "Deprecated hash - use SHA-256 or SHA-3"),
        (
            "RSA.*512",
            "RSA <2048 bits is broken - use RSA-4096 or Ed25519",
        ),
        ("RSA.*1024", "RSA <2048 bits is weak - use RSA-4096"),
        ("EC.*P-192", "Weak curve - use P-256 or curve25519"),
        ("EC.*secp192", "Weak curve - use curve25519"),
    ];

    for (algo, desc) in &weak_algorithms {
        if let Ok(re) = regex::Regex::new(&format!("(?i){}", algo)) {
            if re.is_match(source) {
                weak_keys.push(json!({"algorithm": algo, "risk": desc}));
            }
        }
    }

    json!({
        "weak_crypto_count": weak_keys.len(),
        "findings": weak_keys,
        "recommendation": if !weak_keys.is_empty() {
            "Replace weak cryptographic algorithms immediately. Use AES-256-GCM for symmetric, SHA-256/SHA-3 for hashing, Ed25519 or RSA-4096 for asymmetric."
        } else {
            "No weak cryptographic algorithms detected in provided source."
        }
    })
}

// ═══════════════════════════════════════════════════════════
// OSINT TOOLS
// ═══════════════════════════════════════════════════════════

pub fn osint_email_analyze(email: &str) -> Value {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return json!({"error": "Invalid email format", "email": email});
    }

    let domain = parts[1];
    let common_domains = [
        "gmail.com",
        "yahoo.com",
        "outlook.com",
        "hotmail.com",
        "proton.me",
        "protonmail.com",
    ];

    json!({
        "email": email,
        "username": parts[0],
        "domain": domain,
        "is_free_provider": common_domains.contains(&domain.to_lowercase().as_str()),
        "risk_indicators": [
            "Check haveibeenpwned.com for breach exposure",
            "Search username across platforms",
            "Check domain WHOIS for registration date",
            "Look for associated accounts on GitHub/GitLab",
            "Check for email in public dumps"
        ]
    })
}

pub fn osint_domain_recon(domain: &str) -> Value {
    let whois_result = Command::new("whois")
        .arg(domain)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok());

    json!({
        "domain": domain,
        "whois_available": whois_result.is_some(),
        "whois_summary": whois_result.map(|w| {
            let lines: Vec<&str> = w.lines()
                .filter(|l| l.contains("Creation") || l.contains("Registrar") || l.contains("Name Server") || l.contains("Expir"))
                .collect();
            lines.join("\n")
        }).unwrap_or_else(|| "whois not available".to_string()),
        "dns_checks": [
            format!("dig {} A", domain),
            format!("dig {} MX", domain),
            format!("dig {} TXT", domain),
            format!("dig {} NS", domain),
            format!("dig {} CAA", domain),
        ],
        "ssl_check": format!("echo | openssl s_client -connect {}:443 -servername {} 2>/dev/null | openssl x509 -noout -dates", domain, domain),
    })
}

// ═══════════════════════════════════════════════════════════
// MALWARE TOOLS
// ═══════════════════════════════════════════════════════════

pub fn malware_generate_yara(indicators: &Value) -> Value {
    let name = indicators["name"].as_str().unwrap_or("unknown_malware");
    let mut yara_rule = format!("rule {} {{\n", name.replace(' ', "_").to_uppercase());
    yara_rule.push_str("    meta:\n");
    yara_rule.push_str(&format!(
        "        description = \"Auto-generated YARA rule for {}\"\n",
        name
    ));
    yara_rule.push_str("        author = \"AUDIT-Nexus MCP\"\n");
    yara_rule.push_str(&format!(
        "        date = \"{}\"\n",
        chrono::Local::now().format("%Y-%m-%d")
    ));
    yara_rule.push_str("        severity = \"high\"\n");
    yara_rule.push_str("    strings:\n");

    let mut string_idx = 0;
    if let Some(strings) = indicators["strings"].as_array() {
        for s in strings {
            string_idx += 1;
            let s_str = s.as_str().unwrap_or("");
            if s_str.len() <= 128 {
                yara_rule.push_str(&format!(
                    "        $s{} = \"{}\"\n",
                    string_idx,
                    s_str.escape_default()
                ));
            } else {
                yara_rule.push_str(&format!(
                    "        $s{} = {{ {} }}\n",
                    string_idx,
                    hex::encode(s_str.as_bytes())
                ));
            }
        }
    }

    if let Some(hex_patterns) = indicators["hex_patterns"].as_array() {
        for hp in hex_patterns {
            string_idx += 1;
            yara_rule.push_str(&format!(
                "        $h{} = {{ {} }}\n",
                string_idx,
                hp.as_str().unwrap_or("")
            ));
        }
    }

    yara_rule.push_str("    condition:\n");
    if string_idx == 1 {
        yara_rule.push_str("        any of them\n");
    } else if string_idx > 1 {
        let conditions: Vec<String> = (1..=string_idx).map(|i| format!("$s{}", i)).collect();
        yara_rule.push_str(&format!(
            "        {} of ({})\n",
            (string_idx / 2).max(1),
            conditions.join(", ")
        ));
    }

    yara_rule.push('}');

    json!({
        "yara_rule": yara_rule,
        "usage": format!("yara -r {}.yar target_file", name.replace(' ', "_").to_lowercase()),
        "strings_count": string_idx
    })
}

// ═══════════════════════════════════════════════════════════
// NETWORK TOOLS
// ═══════════════════════════════════════════════════════════

pub fn network_audit_firewall(rules_text: &str) -> Value {
    let open_ports: Vec<&str> = rules_text
        .lines()
        .filter(|l| l.contains("ACCEPT") || l.contains("allow") || l.contains("permit"))
        .collect();

    let has_default_deny = rules_text.contains("DROP")
        || rules_text.contains("REJECT")
        || rules_text.contains("deny all");

    let mut risky_rules = Vec::new();
    for rule in &open_ports {
        if rule.contains("0.0.0.0/0") || rule.contains("any") {
            risky_rules.push(json!({
                "rule": *rule,
                "risk": "Exposed to internet (0.0.0.0/0)",
                "recommendation": "Restrict to specific IP ranges"
            }));
        }
        if rule.contains("22") || rule.contains("ssh") {
            risky_rules.push(json!({
                "rule": *rule,
                "risk": "SSH exposed - ensure key-only auth, fail2ban enabled",
                "recommendation": "Use VPN or bastion host for SSH access"
            }));
        }
    }

    json!({
        "total_rules": rules_text.lines().count(),
        "open_rules": open_ports.len(),
        "has_default_deny": has_default_deny,
        "risky_rules": risky_rules,
        "score": if has_default_deny && risky_rules.is_empty() { "GOOD" } else if has_default_deny { "FAIR" } else { "POOR - No default deny!" }
    })
}
