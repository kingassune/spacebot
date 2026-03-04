//! Platform scanner for enumerating skills, plugins, and Rust modules.

use std::path::{Path, PathBuf};

/// A scanned skill entry from a SKILL.md file.
#[derive(Debug, Clone)]
pub struct SkillEntry {
    pub name: String,
    pub path: PathBuf,
    pub plugin: Option<String>,
    pub description: String,
}

/// A scanned Rust module entry.
#[derive(Debug, Clone)]
pub struct ModuleEntry {
    pub name: String,
    pub path: PathBuf,
    pub public_items: Vec<String>,
}

/// A coverage gap relative to a security framework.
#[derive(Debug, Clone)]
pub struct CoverageGap {
    pub framework: String,
    pub category: String,
    pub description: String,
}

/// Manifest produced by a full platform scan.
#[derive(Debug, Clone)]
pub struct PlatformManifest {
    pub skills: Vec<SkillEntry>,
    pub modules: Vec<ModuleEntry>,
    pub gaps: Vec<CoverageGap>,
}

/// Scans the James platform to enumerate capabilities and identify gaps.
#[derive(Debug, Clone)]
pub struct PlatformScanner {
    /// Root directory of the repository.
    pub root: PathBuf,
}

impl PlatformScanner {
    /// Create a scanner rooted at the given directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Enumerate all SKILL.md files in `skills/` and `plugins/`.
    pub fn scan_skills(&self) -> Vec<SkillEntry> {
        let mut entries = Vec::new();
        let skills_dir = self.root.join("skills");
        collect_skill_entries(&skills_dir, None, &mut entries);

        let plugins_dir = self.root.join("plugins");
        if let Ok(read) = std::fs::read_dir(&plugins_dir) {
            for plugin_entry in read.flatten() {
                let plugin_name = plugin_entry.file_name().to_string_lossy().into_owned();
                let skills_subdir = plugin_entry.path().join("skills");
                collect_skill_entries(&skills_subdir, Some(&plugin_name), &mut entries);
            }
        }

        entries
    }

    /// Enumerate Rust security modules under `src/`.
    pub fn scan_modules(&self) -> Vec<ModuleEntry> {
        let mut entries = Vec::new();
        let security_dirs = [
            "red_team",
            "blue_team",
            "exploit_engine",
            "pentest",
            "blockchain_security",
            "meta_agent",
        ];

        for dir_name in &security_dirs {
            let dir = self.root.join("src").join(dir_name);
            if let Ok(read) = std::fs::read_dir(&dir) {
                for file_entry in read.flatten() {
                    let path = file_entry.path();
                    if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                        let name = path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_string();
                        let public_items = extract_pub_items(&path);
                        entries.push(ModuleEntry {
                            name: format!("{dir_name}::{name}"),
                            path,
                            public_items,
                        });
                    }
                }
            }
        }

        entries
    }

    /// Identify coverage gaps by comparing scanned capabilities against the given framework.
    ///
    /// Supported frameworks: `"mitre-attack"`, `"owasp"`, `"nist-csf"`.
    pub fn identify_gaps(&self, framework: &str) -> Vec<CoverageGap> {
        let skills = self.scan_skills();
        let skill_names: Vec<String> = skills.iter().map(|s| s.name.clone()).collect();

        required_categories(framework)
            .into_iter()
            .filter(|(category, _)| {
                !skill_names
                    .iter()
                    .any(|name| name.to_lowercase().contains(&category.to_lowercase()))
            })
            .map(|(category, description)| CoverageGap {
                framework: framework.to_string(),
                category: category.to_string(),
                description: description.to_string(),
            })
            .collect()
    }

    /// Run a full platform scan and return a combined manifest.
    ///
    /// Gaps are identified against the `"mitre-attack"` framework by default.
    /// Use [`identify_gaps`] directly to scan against `"owasp"` or `"nist-csf"`.
    pub fn full_scan(&self) -> PlatformManifest {
        let skills = self.scan_skills();
        let modules = self.scan_modules();
        let gaps = self.identify_gaps("mitre-attack");
        PlatformManifest {
            skills,
            modules,
            gaps,
        }
    }
}

impl Default for PlatformScanner {
    fn default() -> Self {
        Self::new(".")
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn collect_skill_entries(dir: &Path, plugin: Option<&str>, entries: &mut Vec<SkillEntry>) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let skill_md = entry.path().join("SKILL.md");
        if skill_md.exists() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let description = read_description(&skill_md);
            entries.push(SkillEntry {
                name,
                path: skill_md,
                plugin: plugin.map(str::to_owned),
                description,
            });
        }
    }
}

fn read_description(path: &Path) -> String {
    let Ok(content) = std::fs::read_to_string(path) else {
        return String::new();
    };
    // Extract the `description:` field from YAML frontmatter.
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("description:") {
            return rest.trim().trim_matches('"').to_owned();
        }
    }
    String::new()
}

fn extract_pub_items(path: &Path) -> Vec<String> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("pub ") || trimmed.starts_with("pub(crate) ") {
                // Grab the identifier after `pub fn`, `pub struct`, etc.
                let rest = trimmed
                    .trim_start_matches("pub(crate) ")
                    .trim_start_matches("pub ");
                let ident = rest
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("")
                    .trim_end_matches('{')
                    .trim_end_matches('(')
                    .to_owned();
                if !ident.is_empty() {
                    return Some(ident);
                }
            }
            None
        })
        .collect()
}

fn required_categories(framework: &str) -> Vec<(&'static str, &'static str)> {
    match framework {
        "mitre-attack" => vec![
            ("recon", "Reconnaissance techniques (TA0043)"),
            ("initial-access", "Initial Access techniques (TA0001)"),
            ("execution", "Execution techniques (TA0002)"),
            ("persistence", "Persistence techniques (TA0003)"),
            ("privilege-escalation", "Privilege Escalation (TA0004)"),
            ("defense-evasion", "Defense Evasion (TA0005)"),
            ("credential-access", "Credential Access (TA0006)"),
            ("lateral-movement", "Lateral Movement (TA0008)"),
            ("collection", "Collection techniques (TA0009)"),
            ("exfiltration", "Exfiltration techniques (TA0010)"),
            ("command-and-control", "Command and Control (TA0011)"),
        ],
        "owasp" => vec![
            ("injection", "A03:2021 – Injection"),
            ("broken-access-control", "A01:2021 – Broken Access Control"),
            (
                "cryptographic-failures",
                "A02:2021 – Cryptographic Failures",
            ),
            ("insecure-design", "A04:2021 – Insecure Design"),
            (
                "security-misconfiguration",
                "A05:2021 – Security Misconfiguration",
            ),
            (
                "vulnerable-components",
                "A06:2021 – Vulnerable and Outdated Components",
            ),
            (
                "authentication-failures",
                "A07:2021 – Identification and Authentication Failures",
            ),
            (
                "software-integrity-failures",
                "A08:2021 – Software and Data Integrity Failures",
            ),
            (
                "logging-monitoring",
                "A09:2021 – Security Logging and Monitoring Failures",
            ),
            ("ssrf", "A10:2021 – Server-Side Request Forgery"),
        ],
        "nist-csf" => vec![
            ("identify", "NIST CSF – Identify (ID)"),
            ("protect", "NIST CSF – Protect (PR)"),
            ("detect", "NIST CSF – Detect (DE)"),
            ("respond", "NIST CSF – Respond (RS)"),
            ("recover", "NIST CSF – Recover (RC)"),
        ],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_new_stores_root() {
        let scanner = PlatformScanner::new("/some/path");
        assert_eq!(scanner.root, PathBuf::from("/some/path"));
    }

    #[test]
    fn identify_gaps_returns_gaps_for_unknown_framework() {
        let scanner = PlatformScanner::new("/nonexistent");
        let gaps = scanner.identify_gaps("unknown-framework");
        // Unknown frameworks return no required categories, so no gaps.
        assert!(gaps.is_empty());
    }

    #[test]
    fn identify_gaps_mitre_attack_on_empty_dir() {
        let scanner = PlatformScanner::new("/nonexistent");
        let gaps = scanner.identify_gaps("mitre-attack");
        // All categories are gaps when the directory doesn't exist.
        assert!(!gaps.is_empty());
    }

    #[test]
    fn required_categories_mitre_attack() {
        let cats = required_categories("mitre-attack");
        assert!(!cats.is_empty());
        assert!(cats.iter().any(|(c, _)| *c == "recon"));
    }

    #[test]
    fn required_categories_owasp() {
        let cats = required_categories("owasp");
        assert!(!cats.is_empty());
        assert!(cats.iter().any(|(c, _)| *c == "injection"));
    }

    #[test]
    fn required_categories_nist_csf() {
        let cats = required_categories("nist-csf");
        assert_eq!(cats.len(), 5);
    }
}
