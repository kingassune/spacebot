//! System hardening checklists and compliance frameworks for blue team defensive operations.
//!
//! Covers CIS benchmarks, STIG compliance, OS hardening, and network hardening aligned
//! with authorised defensive security engagements.

use serde::{Deserialize, Serialize};

/// Compliance framework that defines the hardening standard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ComplianceFramework {
    /// Center for Internet Security benchmark.
    CisBenchmark,
    /// Security Technical Implementation Guide (DoD).
    Stig,
    /// NIST SP 800-53 controls.
    Nist80053,
    /// Payment Card Industry Data Security Standard.
    PciDss,
    /// Health Insurance Portability and Accountability Act.
    Hipaa,
    /// Custom organisational policy.
    Custom(String),
}

/// Operating system target for hardening.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OsTarget {
    LinuxRhel,
    LinuxDebian,
    LinuxUbuntu,
    WindowsServer2019,
    WindowsServer2022,
    MacOs,
}

/// A single hardening check with its expected and observed state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningCheck {
    /// Unique rule identifier (e.g. "CIS 1.1.1").
    pub rule_id: String,
    /// Short title.
    pub title: String,
    /// Description of what is being checked.
    pub description: String,
    /// Recommended remediation if the check fails.
    pub remediation: String,
    /// Whether the check passed.
    pub passed: bool,
    /// Severity if the check fails.
    pub severity: HardeningSeverity,
}

/// Severity of a failing hardening check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HardeningSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

/// Configuration for a hardening assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningConfig {
    /// Framework to evaluate against.
    pub framework: ComplianceFramework,
    /// Target operating system.
    pub os_target: OsTarget,
    /// Whether to include network hardening checks.
    pub include_network: bool,
    /// Whether to include application hardening checks.
    pub include_applications: bool,
}

impl Default for HardeningConfig {
    fn default() -> Self {
        Self {
            framework: ComplianceFramework::CisBenchmark,
            os_target: OsTarget::LinuxUbuntu,
            include_network: true,
            include_applications: true,
        }
    }
}

/// A full hardening profile with all checks and overall score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningProfile {
    /// Configuration used for this profile.
    pub config: HardeningConfig,
    /// All evaluated checks.
    pub checks: Vec<HardeningCheck>,
    /// Percentage of checks that passed (0–100).
    pub compliance_score: f64,
}

impl HardeningProfile {
    /// Create a new empty profile for the given configuration.
    pub fn new(config: HardeningConfig) -> Self {
        Self {
            config,
            checks: Vec::new(),
            compliance_score: 0.0,
        }
    }

    /// Recalculate the compliance score from the current checks.
    pub fn recalculate_score(&mut self) {
        if self.checks.is_empty() {
            self.compliance_score = 100.0;
            return;
        }
        let passed = self.checks.iter().filter(|c| c.passed).count();
        self.compliance_score = (passed as f64 / self.checks.len() as f64) * 100.0;
    }

    /// Return only the failing checks.
    pub fn failing_checks(&self) -> Vec<&HardeningCheck> {
        self.checks.iter().filter(|c| !c.passed).collect()
    }

    /// Return checks filtered by minimum severity.
    pub fn checks_by_severity(&self, severity: &HardeningSeverity) -> Vec<&HardeningCheck> {
        self.checks
            .iter()
            .filter(|c| &c.severity == severity)
            .collect()
    }
}

/// Network hardening check categories.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NetworkHardeningCategory {
    FirewallRules,
    TlsConfiguration,
    SshHardening,
    Dnsecurity,
    NetworkSegmentation,
    PortReduction,
}

/// A single network hardening check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHardeningCheck {
    pub category: NetworkHardeningCategory,
    pub title: String,
    pub description: String,
    pub passed: bool,
    pub recommendation: String,
}

/// Build a default CIS benchmark hardening profile with representative checks.
pub fn build_cis_profile(os: &OsTarget) -> HardeningProfile {
    let config = HardeningConfig {
        framework: ComplianceFramework::CisBenchmark,
        os_target: os.clone(),
        include_network: true,
        include_applications: true,
    };

    let checks = vec![
        HardeningCheck {
            rule_id: "CIS 1.1.1".to_string(),
            title: "Ensure /tmp is configured".to_string(),
            description: "Separate /tmp partition reduces risk from world-writable directories."
                .to_string(),
            remediation: "Configure /tmp as a separate partition with nodev,nosuid,noexec."
                .to_string(),
            passed: true,
            severity: HardeningSeverity::Medium,
        },
        HardeningCheck {
            rule_id: "CIS 1.5.1".to_string(),
            title: "Ensure core dumps are restricted".to_string(),
            description: "Core dumps can expose sensitive data to unprivileged users.".to_string(),
            remediation: "Set 'hard core 0' in /etc/security/limits.conf.".to_string(),
            passed: false,
            severity: HardeningSeverity::High,
        },
        HardeningCheck {
            rule_id: "CIS 2.2.1".to_string(),
            title: "Ensure X Window System is not installed".to_string(),
            description: "X Window increases attack surface on server systems.".to_string(),
            remediation: "Remove xorg or xserver-xorg packages.".to_string(),
            passed: true,
            severity: HardeningSeverity::Low,
        },
        HardeningCheck {
            rule_id: "CIS 4.1.1".to_string(),
            title: "Ensure auditd is installed".to_string(),
            description: "System auditing provides accountability and detection capability."
                .to_string(),
            remediation: "Install auditd and enable the service.".to_string(),
            passed: false,
            severity: HardeningSeverity::High,
        },
        HardeningCheck {
            rule_id: "CIS 5.2.1".to_string(),
            title: "Ensure SSH Protocol is 2".to_string(),
            description: "SSHv1 has known cryptographic weaknesses.".to_string(),
            remediation: "Set 'Protocol 2' in /etc/ssh/sshd_config.".to_string(),
            passed: true,
            severity: HardeningSeverity::Critical,
        },
    ];

    let mut profile = HardeningProfile {
        config,
        checks,
        compliance_score: 0.0,
    };
    profile.recalculate_score();
    profile
}

/// Build a STIG hardening profile with representative DoD checks.
pub fn build_stig_profile(os: &OsTarget) -> HardeningProfile {
    let config = HardeningConfig {
        framework: ComplianceFramework::Stig,
        os_target: os.clone(),
        include_network: true,
        include_applications: false,
    };

    let checks = vec![
        HardeningCheck {
            rule_id: "RHEL-07-010010".to_string(),
            title: "Cryptographic mechanisms used to protect file integrity".to_string(),
            description: "Without cryptographic integrity protections, system executables can be altered by unauthorized users.".to_string(),
            remediation: "Install AIDE and configure it for the system.".to_string(),
            passed: false,
            severity: HardeningSeverity::High,
        },
        HardeningCheck {
            rule_id: "RHEL-07-010060".to_string(),
            title: "Require re-authentication for privilege escalation via sudo".to_string(),
            description: "Requiring re-authentication reduces risk from unattended sessions."
                .to_string(),
            remediation: "Remove NOPASSWD from sudoers entries.".to_string(),
            passed: true,
            severity: HardeningSeverity::Medium,
        },
    ];

    let mut profile = HardeningProfile {
        config,
        checks,
        compliance_score: 0.0,
    };
    profile.recalculate_score();
    profile
}

/// Run network hardening checks and return findings.
pub fn run_network_hardening_checks() -> Vec<NetworkHardeningCheck> {
    vec![
        NetworkHardeningCheck {
            category: NetworkHardeningCategory::FirewallRules,
            title: "Default deny inbound".to_string(),
            description: "Firewall should deny all inbound connections by default.".to_string(),
            passed: true,
            recommendation: "Ensure ufw/iptables default policy is DROP.".to_string(),
        },
        NetworkHardeningCheck {
            category: NetworkHardeningCategory::SshHardening,
            title: "SSH root login disabled".to_string(),
            description: "Root login over SSH increases risk of brute-force compromise."
                .to_string(),
            passed: false,
            recommendation: "Set 'PermitRootLogin no' in /etc/ssh/sshd_config.".to_string(),
        },
        NetworkHardeningCheck {
            category: NetworkHardeningCategory::TlsConfiguration,
            title: "TLS 1.0 and 1.1 disabled".to_string(),
            description: "Legacy TLS versions are vulnerable to downgrade attacks.".to_string(),
            passed: true,
            recommendation: "Configure services to only accept TLS 1.2 and 1.3.".to_string(),
        },
    ]
}
