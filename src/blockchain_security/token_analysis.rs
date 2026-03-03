//! Deep ERC-20/ERC-721/ERC-1155 token security analysis.

use serde::{Deserialize, Serialize};

/// ERC token standard classification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TokenStandard {
    Erc20,
    Erc721,
    Erc1155,
    Custom,
    Unknown,
}

impl TokenStandard {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Erc20 => "ERC-20",
            Self::Erc721 => "ERC-721",
            Self::Erc1155 => "ERC-1155",
            Self::Custom => "Custom Token",
            Self::Unknown => "Unknown",
        }
    }
}

/// Vulnerability classes specific to token contracts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TokenVulnerability {
    /// Unbounded approval (allowance set to `type(uint256).max`).
    InfiniteApproval,
    /// Approve + transferFrom race condition.
    ApprovalRaceCondition,
    /// Missing return value on ERC-20 transfer/approve (non-standard tokens).
    MissingReturnValue,
    /// Fee charged on every transfer (breaks integrations).
    FeeOnTransfer,
    /// Supply can rebase, breaking accounting assumptions.
    RebasingToken,
    /// Token can be paused, blocking transfers.
    Pausable,
    /// Blacklist functionality can freeze funds.
    Blacklistable,
    /// Contract is upgradeable, allowing logic changes.
    UpgradeableProxy,
    /// ERC-721 `approve` does not check operator permissions.
    UnrestrictedApproval,
    /// Missing `safeTransferFrom` checks on ERC-721/1155.
    UnsafeTransfer,
}

/// A node in the token approval graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalChain {
    /// Token owner address.
    pub owner: String,
    /// Approved spender address.
    pub spender: String,
    /// Approval amount (hex).
    pub amount: String,
    /// Whether this is an infinite approval.
    pub is_infinite: bool,
    /// Whether the spender is a verified/known contract.
    pub spender_verified: bool,
}

/// A single token security finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenFinding {
    pub vulnerability: TokenVulnerability,
    pub severity: String,
    pub description: String,
    pub recommendation: String,
}

/// Aggregated result of a deep token security analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAnalysisResult {
    pub standard: TokenStandard,
    pub contract_name: String,
    pub findings: Vec<TokenFinding>,
    pub approval_chains: Vec<ApprovalChain>,
    pub risk_score: u8,
    pub compliance_issues: Vec<String>,
    pub summary: String,
}

/// Run a comprehensive token security analysis.
pub fn analyze_token_contract(source: &str, contract_name: &str) -> TokenAnalysisResult {
    let standard = detect_standard(source);
    let findings = detect_approval_vulnerabilities(source, &standard);
    let compliance_issues = check_standard_compliance(source, &standard);
    let approval_chains = extract_approval_patterns(source);

    let risk_score = calculate_risk_score(&findings);
    let summary = build_summary(contract_name, &standard, &findings, risk_score);

    TokenAnalysisResult {
        standard,
        contract_name: contract_name.to_string(),
        findings,
        approval_chains,
        risk_score,
        compliance_issues,
        summary,
    }
}

/// Detect approval-related vulnerabilities in a token contract.
pub fn detect_approval_vulnerabilities(
    source: &str,
    standard: &TokenStandard,
) -> Vec<TokenFinding> {
    let mut findings = Vec::new();

    // Infinite approval
    if source.contains("type(uint256).max") || source.contains("2**256 - 1") {
        findings.push(TokenFinding {
            vulnerability: TokenVulnerability::InfiniteApproval,
            severity: "High".to_string(),
            description: "Contract supports infinite approvals (type(uint256).max), \
                          exposing users to full token loss if the spender is compromised."
                .to_string(),
            recommendation:
                "Encourage time-limited or amount-limited approvals. Implement permit() (EIP-2612)."
                    .to_string(),
        });
    }

    // Approval race condition
    if source.contains("approve(") && !source.contains("increaseAllowance") {
        findings.push(TokenFinding {
            vulnerability: TokenVulnerability::ApprovalRaceCondition,
            severity: "Medium".to_string(),
            description:
                "approve() without increaseAllowance/decreaseAllowance is susceptible to the \
                          ERC-20 approval race condition."
                    .to_string(),
            recommendation:
                "Implement increaseAllowance() and decreaseAllowance(), or use EIP-2612 permits."
                    .to_string(),
        });
    }

    // Missing return value — check that transfer function declaration includes return type
    if source.contains("function transfer(") && !transfer_fn_has_bool_return(source) {
        findings.push(TokenFinding {
            vulnerability: TokenVulnerability::MissingReturnValue,
            severity: "Medium".to_string(),
            description: "transfer() may not return a boolean, breaking integrations that expect \
                          the ERC-20 return value."
                .to_string(),
            recommendation: "Ensure transfer() and approve() return bool per ERC-20 spec."
                .to_string(),
        });
    }

    // Fee on transfer
    if source.contains("_taxFee") || source.contains("fee") && source.contains("_transfer") {
        findings.push(TokenFinding {
            vulnerability: TokenVulnerability::FeeOnTransfer,
            severity: "Low".to_string(),
            description: "Token deducts a fee on every transfer, which breaks AMM and lending protocol integrations.".to_string(),
            recommendation: "Document fee-on-transfer behavior prominently. Integrators must account for it.".to_string(),
        });
    }

    // Pausable
    if source.contains("Pausable") || source.contains("_pause()") {
        findings.push(TokenFinding {
            vulnerability: TokenVulnerability::Pausable,
            severity: "Medium".to_string(),
            description: "Contract owner can pause all transfers, which may freeze user funds."
                .to_string(),
            recommendation:
                "Limit pause authority to multi-sig with timelock, or remove pause capability."
                    .to_string(),
        });
    }

    // Blacklist
    if source.contains("blacklist") || source.contains("isBlacklisted") {
        findings.push(TokenFinding {
            vulnerability: TokenVulnerability::Blacklistable,
            severity: "Medium".to_string(),
            description: "Contract has a blacklist mechanism that can freeze individual addresses."
                .to_string(),
            recommendation:
                "Clearly disclose blacklist functionality. Use governance controls for changes."
                    .to_string(),
        });
    }

    // ERC-721 unsafe transfer
    if *standard == TokenStandard::Erc721
        && source.contains("transferFrom(")
        && !source.contains("safeTransferFrom(")
    {
        findings.push(TokenFinding {
            vulnerability: TokenVulnerability::UnsafeTransfer,
            severity: "High".to_string(),
            description: "ERC-721 transferFrom used without safeTransferFrom; tokens may be \
                          permanently locked in contracts that don't implement onERC721Received."
                .to_string(),
            recommendation: "Prefer safeTransferFrom() for all NFT transfers."
                .to_string(),
        });
    }

    findings
}

/// Check compliance with the relevant ERC standard.
pub fn check_standard_compliance(source: &str, standard: &TokenStandard) -> Vec<String> {
    let mut issues = Vec::new();

    match standard {
        TokenStandard::Erc20 => {
            let required = [
                "transfer(",
                "transferFrom(",
                "approve(",
                "allowance(",
                "balanceOf(",
                "totalSupply()",
            ];
            for func in &required {
                if !source.contains(func) {
                    issues.push(format!("Missing ERC-20 required function: {func}"));
                }
            }
        }
        TokenStandard::Erc721 => {
            let required = [
                "ownerOf(",
                "safeTransferFrom(",
                "approve(",
                "getApproved(",
                "setApprovalForAll(",
                "isApprovedForAll(",
            ];
            for func in &required {
                if !source.contains(func) {
                    issues.push(format!("Missing ERC-721 required function: {func}"));
                }
            }
        }
        TokenStandard::Erc1155 => {
            let required = [
                "safeTransferFrom(",
                "safeBatchTransferFrom(",
                "balanceOf(",
                "balanceOfBatch(",
                "setApprovalForAll(",
                "isApprovedForAll(",
            ];
            for func in &required {
                if !source.contains(func) {
                    issues.push(format!("Missing ERC-1155 required function: {func}"));
                }
            }
        }
        _ => {}
    }

    issues
}

// — Internal helpers —

fn detect_standard(source: &str) -> TokenStandard {
    if source.contains("ERC1155") || source.contains("IERC1155") {
        TokenStandard::Erc1155
    } else if source.contains("ERC721") || source.contains("IERC721") {
        TokenStandard::Erc721
    } else if source.contains("ERC20")
        || source.contains("IERC20")
        || (source.contains("transfer(") && source.contains("totalSupply"))
    {
        TokenStandard::Erc20
    } else if source.contains("contract ") {
        TokenStandard::Custom
    } else {
        TokenStandard::Unknown
    }
}

fn extract_approval_patterns(source: &str) -> Vec<ApprovalChain> {
    let mut chains = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.contains("approve(") && trimmed.contains("type(uint256).max") {
            chains.push(ApprovalChain {
                owner: "msg.sender".to_string(),
                spender: "extracted_from_source".to_string(),
                amount: "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    .to_string(),
                is_infinite: true,
                spender_verified: false,
            });
        }
    }
    chains
}

fn calculate_risk_score(findings: &[TokenFinding]) -> u8 {
    let base: u32 = findings
        .iter()
        .map(|f| match f.severity.as_str() {
            "Critical" => 30,
            "High" => 20,
            "Medium" => 10,
            "Low" => 5,
            _ => 2,
        })
        .sum();
    base.min(100) as u8
}

fn build_summary(
    contract_name: &str,
    standard: &TokenStandard,
    findings: &[TokenFinding],
    risk_score: u8,
) -> String {
    format!(
        "Token analysis for '{}' ({}): {} finding(s) identified. Risk score: {}/100.",
        contract_name,
        standard.label(),
        findings.len(),
        risk_score
    )
}

/// Returns true if the `transfer` function declaration in the source includes a bool return type.
fn transfer_fn_has_bool_return(source: &str) -> bool {
    let mut in_transfer = false;
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("function transfer(") {
            in_transfer = true;
        }
        if in_transfer {
            if trimmed.contains("returns") && trimmed.contains("bool") {
                return true;
            }
            // End of function signature block (opening brace)
            if trimmed.contains('{') {
                return false;
            }
        }
    }
    false
}
