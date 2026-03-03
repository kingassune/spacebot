//! Cryptocurrency wallet security audit and transaction simulation.

/// Wallet implementation classification.
#[derive(Debug, Clone, PartialEq)]
pub enum WalletType {
    Eoa,
    Multisig,
    SmartWallet,
    Mpc,
    Hardware,
    Social,
    CustodialExchange,
}

/// Vulnerability classes relevant to wallet security.
#[derive(Debug, Clone, PartialEq)]
pub enum WalletVulnerability {
    WeakEntropy,
    KeyLeakage,
    ReplayAttack,
    PhishingApproval,
    InfiniteApproval,
    DustAttack,
    AddressPoisoning,
    SignatureMallability,
}

/// A single ERC-20 approval record.
#[derive(Debug, Clone)]
pub struct ApprovalRecord {
    pub token: String,
    pub spender: String,
    pub amount_wei: u64,
    pub is_unlimited: bool,
    pub block_number: u64,
}

/// Comprehensive wallet security report.
#[derive(Debug, Clone)]
pub struct WalletSecurityReport {
    pub wallet_address: String,
    pub wallet_type: WalletType,
    pub vulnerabilities: Vec<WalletVulnerability>,
    pub unlimited_approvals: Vec<ApprovalRecord>,
    pub security_score: u8,
    pub recommendations: Vec<String>,
}

/// Audit a wallet address and return a security report with type-specific guidance.
pub fn audit_wallet(wallet_address: &str, wallet_type: &WalletType) -> WalletSecurityReport {
    let mut vulnerabilities = Vec::new();
    let mut recommendations = Vec::new();

    match wallet_type {
        WalletType::Eoa => {
            recommendations.push(
                "Consider migrating to a smart wallet or hardware wallet for improved security."
                    .into(),
            );
            recommendations.push("Regularly rotate approvals and revoke unused allowances.".into());
        }
        WalletType::Multisig => {
            recommendations
                .push("Ensure signing keys are held on separate hardware devices.".into());
            recommendations.push("Use a time-lock on high-value transactions.".into());
        }
        WalletType::SmartWallet => {
            recommendations.push("Audit the wallet contract for upgradeability risks.".into());
            recommendations.push("Verify social-recovery guardian configuration.".into());
        }
        WalletType::Mpc => {
            recommendations.push("Confirm key-share refresh is performed periodically.".into());
            recommendations.push("Ensure secure channels between MPC participants.".into());
        }
        WalletType::Hardware => {
            recommendations.push("Keep firmware updated and verify device authenticity.".into());
            recommendations.push(
                "Store the recovery phrase offline in a geographically diverse location.".into(),
            );
        }
        WalletType::Social => {
            vulnerabilities.push(WalletVulnerability::PhishingApproval);
            recommendations.push("Guardian accounts should each use hardware wallets.".into());
            recommendations.push("Add a recovery time-lock to resist social engineering.".into());
        }
        WalletType::CustodialExchange => {
            vulnerabilities.push(WalletVulnerability::KeyLeakage);
            recommendations.push("Enable withdrawal address whitelisting.".into());
            recommendations.push("Use hardware 2FA (FIDO2/YubiKey) rather than SMS.".into());
        }
    }

    let deduction = (vulnerabilities.len() as u8).saturating_mul(10);
    let security_score = 100_u8.saturating_sub(deduction);

    WalletSecurityReport {
        wallet_address: wallet_address.to_string(),
        wallet_type: wallet_type.clone(),
        vulnerabilities,
        unlimited_approvals: Vec::new(),
        security_score,
        recommendations,
    }
}

/// Identify unlimited-approval vulnerabilities from an approval list.
pub fn check_approvals(approvals: &[ApprovalRecord]) -> Vec<WalletVulnerability> {
    if approvals.iter().any(|a| a.is_unlimited) {
        vec![WalletVulnerability::InfiniteApproval]
    } else {
        Vec::new()
    }
}

/// Return whether the entropy source is considered strong.
pub fn assess_entropy_strength(entropy_source: &str) -> bool {
    matches!(entropy_source, "hardware" | "csprng")
}

/// Return a human-readable transaction simulation summary.
pub fn simulate_transaction(from: &str, to: &str, value_wei: u64, data: &str) -> String {
    if data.is_empty() || data == "0x" {
        format!("Transfer of {} wei from {} to {}.", value_wei, from, to)
    } else {
        format!(
            "Contract interaction from {} to {} with {} wei and {} bytes of calldata.",
            from,
            to,
            value_wei,
            data.len() / 2,
        )
    }
}
