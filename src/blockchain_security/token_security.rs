//! Token security analysis for ERC-20/ERC-721/ERC-1155 contracts.

/// ERC token standard classification.
#[derive(Debug, Clone, PartialEq)]
pub enum TokenStandard {
    Erc20,
    Erc721,
    Erc1155,
    Unknown,
}

/// Known token-specific vulnerability classes.
#[derive(Debug, Clone, PartialEq)]
pub enum TokenVulnerability {
    FeeOnTransfer,
    RebasingSupply,
    Blacklist,
    Pausable,
    UpgradeableProxy,
    ApprovalRace,
    InfiniteApproval,
    MissingReturnValue,
    PhantomFunction,
}

/// A token security finding.
#[derive(Debug, Clone)]
pub struct TokenFinding {
    pub vulnerability: TokenVulnerability,
    pub severity: String,
    pub description: String,
    pub recommendation: String,
}

/// Aggregated result of a token security audit.
#[derive(Debug, Clone)]
pub struct TokenAuditResult {
    pub standard: TokenStandard,
    pub contract_name: String,
    pub findings: Vec<TokenFinding>,
    pub risk_score: u8,
    pub summary: String,
}

/// Analyzes ERC token contracts for standard-specific vulnerabilities.
pub struct TokenSecurityAnalyzer;

impl TokenSecurityAnalyzer {
    /// Detect the token standard from source code markers.
    pub fn detect_standard(source: &str) -> TokenStandard {
        if source.contains("IERC1155")
            || source.contains("ERC1155")
            || source.contains("balanceOfBatch")
        {
            TokenStandard::Erc1155
        } else if source.contains("IERC721")
            || source.contains("ERC721")
            || source.contains("ownerOf(")
        {
            TokenStandard::Erc721
        } else if source.contains("IERC20")
            || source.contains("ERC20")
            || source.contains("totalSupply()")
        {
            TokenStandard::Erc20
        } else {
            TokenStandard::Unknown
        }
    }

    /// Analyze a token contract source for standard-specific vulnerabilities.
    pub fn analyze(source: &str, contract_name: &str) -> TokenAuditResult {
        let standard = Self::detect_standard(source);
        let mut findings = Vec::new();

        // Fee-on-transfer: transfer reduces amount (common in deflationary tokens)
        if source.contains("_fee")
            || source.contains("taxRate")
            || source.contains("burnOnTransfer")
        {
            findings.push(TokenFinding {
                vulnerability: TokenVulnerability::FeeOnTransfer,
                severity: "High".into(),
                description: "Fee-on-transfer pattern detected; many DeFi protocols are incompatible with this.".into(),
                recommendation: "Document fee mechanism clearly and test integration with DEX routers and lending protocols.".into(),
            });
        }

        // Rebasing supply
        if source.contains("rebase(")
            || source.contains("_rebase")
            || source.contains("_totalSupply =")
        {
            findings.push(TokenFinding {
                vulnerability: TokenVulnerability::RebasingSupply,
                severity: "High".into(),
                description: "Rebasing supply detected; balance changes without transfer events break accounting.".into(),
                recommendation: "Use wrapper tokens (like wstETH) for DeFi composability; document rebase mechanism.".into(),
            });
        }

        // Blacklist
        if source.contains("blacklist")
            || source.contains("isBlacklisted")
            || source.contains("_blocked")
        {
            findings.push(TokenFinding {
                vulnerability: TokenVulnerability::Blacklist,
                severity: "Medium".into(),
                description: "Blacklist mechanism present; token holders can be frozen without notice.".into(),
                recommendation: "Document blacklist criteria and governance process; consider time-locked blacklisting.".into(),
            });
        }

        // Pausable
        if source.contains("Pausable") || source.contains("pause()") || source.contains("_paused") {
            findings.push(TokenFinding {
                vulnerability: TokenVulnerability::Pausable,
                severity: "Medium".into(),
                description: "Contract is pausable; all transfers can be halted by admin.".into(),
                recommendation: "Restrict pause to multi-sig governance with a time-lock; document emergency criteria.".into(),
            });
        }

        // Upgradeable proxy
        if source.contains("upgradeTo(")
            || source.contains("UUPSUpgradeable")
            || source.contains("TransparentUpgradeableProxy")
        {
            findings.push(TokenFinding {
                vulnerability: TokenVulnerability::UpgradeableProxy,
                severity: "High".into(),
                description: "Upgradeable proxy pattern: token logic can be changed by the upgrader.".into(),
                recommendation: "Gate upgrades with multi-sig + time-lock; use storage layout compatibility checks.".into(),
            });
        }

        // Approval race (ERC-20 specific)
        if standard == TokenStandard::Erc20
            && !source.contains("increaseAllowance")
            && !source.contains("decreaseAllowance")
            && source.contains("approve(")
        {
            findings.push(TokenFinding {
                vulnerability: TokenVulnerability::ApprovalRace,
                severity: "Low".into(),
                description: "Standard approve() without increaseAllowance/decreaseAllowance; front-run double-spend possible.".into(),
                recommendation: "Implement increaseAllowance and decreaseAllowance helpers as per OpenZeppelin ERC20.".into(),
            });
        }

        // Missing return value on transfer (ERC-20 defect)
        if standard == TokenStandard::Erc20
            && source.contains("function transfer(")
            && !source.contains("returns (bool)")
            && !source.contains("return true")
        {
            findings.push(TokenFinding {
                vulnerability: TokenVulnerability::MissingReturnValue,
                severity: "High".into(),
                description: "transfer() does not return bool; callers expecting ERC-20 compliance will revert.".into(),
                recommendation: "Add 'returns (bool)' and 'return true' to transfer and transferFrom.".into(),
            });
        }

        let risk_score = compute_token_risk_score(&findings);
        let summary = format!(
            "{:?} token '{}': {} finding(s), risk score {}/100.",
            standard,
            contract_name,
            findings.len(),
            risk_score
        );

        TokenAuditResult {
            standard,
            contract_name: contract_name.to_string(),
            findings,
            risk_score,
            summary,
        }
    }
}

fn compute_token_risk_score(findings: &[TokenFinding]) -> u8 {
    let deduction: u8 = findings
        .iter()
        .map(|f| match f.severity.as_str() {
            "High" => 25,
            "Medium" => 15,
            "Low" => 5,
            _ => 0,
        })
        .sum();
    100_u8.saturating_sub(deduction)
}
