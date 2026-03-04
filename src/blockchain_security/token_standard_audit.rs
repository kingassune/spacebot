//! Comprehensive token standard compliance auditor.
//!
//! Covers ERC-20, ERC-721, ERC-1155, and ERC-4626 compliance checking,
//! approval vulnerability detection, rebasing/fee-on-transfer edge cases,
//! and cross-standard interaction vulnerabilities.

use serde::{Deserialize, Serialize};

/// Token standard identifier.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TokenStandard {
    /// Fungible token standard.
    Erc20,
    /// Non-fungible token standard.
    Erc721,
    /// Multi-token standard (fungible + non-fungible).
    Erc1155,
    /// Tokenised vault standard (yield-bearing vaults).
    Erc4626,
    /// Unknown or non-standard token.
    Unknown,
}

impl std::fmt::Display for TokenStandard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Erc20 => "ERC-20",
            Self::Erc721 => "ERC-721",
            Self::Erc1155 => "ERC-1155",
            Self::Erc4626 => "ERC-4626",
            Self::Unknown => "Unknown",
        };
        formatter.write_str(label)
    }
}

/// Category of compliance violation or vulnerability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ComplianceViolationKind {
    /// Required interface function is missing.
    MissingRequiredFunction,
    /// Function exists but does not emit the required event.
    MissingRequiredEvent,
    /// Return value is missing where the standard mandates one.
    MissingReturnValue,
    /// Infinite or unbounded token approval is granted.
    InfiniteApproval,
    /// Approval can be front-run between two non-zero values.
    ApprovalRacingCondition,
    /// Token transfer silently deducts a fee from the transferred amount.
    FeeOnTransfer,
    /// Token supply rebases automatically, breaking balance assumptions.
    RebasingSupply,
    /// Interactions between different token standards produce unsafe behaviour.
    CrossStandardInteraction,
    /// ERC-4626 vault share manipulation attack surface.
    VaultShareManipulation,
    /// Token contract is upgradeable without timelock protection.
    UnprotectedUpgrade,
}

/// A single compliance or security finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFinding {
    /// Standard to which the finding applies.
    pub standard: TokenStandard,
    /// Kind of violation discovered.
    pub kind: ComplianceViolationKind,
    /// Severity level: "Critical", "High", "Medium", "Low", or "Informational".
    pub severity: String,
    /// Human-readable description of the finding.
    pub description: String,
    /// Recommended remediation action.
    pub recommendation: String,
    /// Relevant ERC section or EIP reference.
    pub eip_reference: String,
}

/// Compliance status for a single required interface element.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceCheckResult {
    /// Name of the function or event being checked.
    pub element: String,
    /// Whether the element is present.
    pub present: bool,
    /// Optional note about the finding.
    pub note: String,
}

/// Full audit result for a token contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenStandardAuditResult {
    /// Name of the audited contract.
    pub contract_name: String,
    /// Detected (or specified) token standard.
    pub detected_standard: TokenStandard,
    /// All compliance and security findings.
    pub findings: Vec<ComplianceFinding>,
    /// Interface element check results.
    pub interface_checks: Vec<InterfaceCheckResult>,
    /// Overall compliance score (0–100).
    pub compliance_score: u8,
    /// Whether the contract passes the minimum compliance bar for its standard.
    pub is_compliant: bool,
    /// Human-readable executive summary.
    pub summary: String,
}

/// Audits a token contract for ERC standard compliance and security issues.
pub struct TokenStandardAuditor;

impl TokenStandardAuditor {
    /// Detect the most likely token standard from source code markers.
    pub fn detect_standard(source: &str) -> TokenStandard {
        if source.contains("convertToShares")
            || source.contains("convertToAssets")
            || source.contains("ERC4626")
        {
            TokenStandard::Erc4626
        } else if source.contains("balanceOfBatch")
            || source.contains("safeTransferFrom")
            || source.contains("ERC1155")
        {
            TokenStandard::Erc1155
        } else if source.contains("ownerOf(")
            || source.contains("tokenURI")
            || source.contains("ERC721")
        {
            TokenStandard::Erc721
        } else if source.contains("totalSupply()")
            || source.contains("allowance(")
            || source.contains("ERC20")
        {
            TokenStandard::Erc20
        } else {
            TokenStandard::Unknown
        }
    }

    /// Run a full compliance audit against the detected (or supplied) standard.
    pub fn audit(source: &str, contract_name: &str) -> TokenStandardAuditResult {
        let standard = Self::detect_standard(source);
        Self::audit_with_standard(source, contract_name, standard)
    }

    /// Run a full compliance audit against an explicitly specified standard.
    pub fn audit_with_standard(
        source: &str,
        contract_name: &str,
        standard: TokenStandard,
    ) -> TokenStandardAuditResult {
        let mut findings: Vec<ComplianceFinding> = Vec::new();
        let mut interface_checks: Vec<InterfaceCheckResult> = Vec::new();

        match &standard {
            TokenStandard::Erc20 => {
                check_erc20_interface(source, &mut interface_checks, &mut findings);
            }
            TokenStandard::Erc721 => {
                check_erc721_interface(source, &mut interface_checks, &mut findings);
            }
            TokenStandard::Erc1155 => {
                check_erc1155_interface(source, &mut interface_checks, &mut findings);
            }
            TokenStandard::Erc4626 => {
                check_erc4626_interface(source, &mut interface_checks, &mut findings);
            }
            TokenStandard::Unknown => {}
        }

        // Universal checks applied regardless of standard.
        check_approval_vulnerabilities(source, &standard, &mut findings);
        check_rebasing_fee_on_transfer(source, &standard, &mut findings);
        check_cross_standard_interactions(source, &standard, &mut findings);
        check_upgrade_patterns(source, &standard, &mut findings);

        let compliance_score = compute_compliance_score(&interface_checks, &findings);
        let critical_count = findings.iter().filter(|f| f.severity == "Critical").count();
        let high_count = findings.iter().filter(|f| f.severity == "High").count();
        let is_compliant = critical_count == 0 && high_count == 0 && compliance_score >= 70;

        let summary = format!(
            "{contract_name} ({standard}) — compliance score: {compliance_score}/100. \
             {} finding(s) total ({} critical, {} high). {}",
            findings.len(),
            critical_count,
            high_count,
            if is_compliant {
                "Passes minimum compliance bar."
            } else {
                "Does NOT meet minimum compliance requirements."
            }
        );

        TokenStandardAuditResult {
            contract_name: contract_name.to_string(),
            detected_standard: standard,
            findings,
            interface_checks,
            compliance_score,
            is_compliant,
            summary,
        }
    }
}

// — ERC-20 interface checks —

fn check_erc20_interface(
    source: &str,
    checks: &mut Vec<InterfaceCheckResult>,
    findings: &mut Vec<ComplianceFinding>,
) {
    let required_functions = [
        "totalSupply",
        "balanceOf",
        "transfer",
        "transferFrom",
        "approve",
        "allowance",
    ];
    let required_events = ["Transfer", "Approval"];

    for func in required_functions {
        let fn_sig = format!("function {func}");
        let fn_call = format!("{func}(");
        let present = source.contains(&fn_sig) || source.contains(&fn_call);
        checks.push(InterfaceCheckResult {
            element: format!("{func}()"),
            present,
            note: if present {
                String::new()
            } else {
                format!("ERC-20 requires {func}() — EIP-20 §2")
            },
        });
        if !present {
            findings.push(ComplianceFinding {
                standard: TokenStandard::Erc20,
                kind: ComplianceViolationKind::MissingRequiredFunction,
                severity: "High".into(),
                description: format!("ERC-20 required function `{func}` is absent."),
                recommendation: format!("Implement `{func}` per EIP-20 specification."),
                eip_reference: "EIP-20 §2".into(),
            });
        }
    }

    for event in required_events {
        let event_sig = format!("event {event}");
        let present = source.contains(&event_sig);
        checks.push(InterfaceCheckResult {
            element: format!("event {event}"),
            present,
            note: if present {
                String::new()
            } else {
                format!("ERC-20 requires event {event} — EIP-20 §3")
            },
        });
        if !present {
            findings.push(ComplianceFinding {
                standard: TokenStandard::Erc20,
                kind: ComplianceViolationKind::MissingRequiredEvent,
                severity: "Medium".into(),
                description: format!("ERC-20 required event `{event}` is absent."),
                recommendation: format!("Emit `{event}` per EIP-20 specification."),
                eip_reference: "EIP-20 §3".into(),
            });
        }
    }

    // Check that transfer() returns bool.
    if source.contains("function transfer(") && !source.contains("returns (bool)") {
        findings.push(ComplianceFinding {
            standard: TokenStandard::Erc20,
            kind: ComplianceViolationKind::MissingReturnValue,
            severity: "High".into(),
            description: "`transfer()` must return a bool per EIP-20.".into(),
            recommendation: "Declare `function transfer(...) external returns (bool)`.".into(),
            eip_reference: "EIP-20 §2".into(),
        });
    }
}

// — ERC-721 interface checks —

fn check_erc721_interface(
    source: &str,
    checks: &mut Vec<InterfaceCheckResult>,
    findings: &mut Vec<ComplianceFinding>,
) {
    let required_functions = [
        "balanceOf",
        "ownerOf",
        "safeTransferFrom",
        "transferFrom",
        "approve",
        "setApprovalForAll",
        "getApproved",
        "isApprovedForAll",
    ];
    let required_events = ["Transfer", "Approval", "ApprovalForAll"];

    for func in required_functions {
        let fn_sig = format!("function {func}");
        let fn_call = format!("{func}(");
        let present = source.contains(&fn_sig) || source.contains(&fn_call);
        checks.push(InterfaceCheckResult {
            element: format!("{func}()"),
            present,
            note: if present {
                String::new()
            } else {
                format!("ERC-721 requires {func}() — EIP-721 §4")
            },
        });
        if !present {
            findings.push(ComplianceFinding {
                standard: TokenStandard::Erc721,
                kind: ComplianceViolationKind::MissingRequiredFunction,
                severity: "High".into(),
                description: format!("ERC-721 required function `{func}` is absent."),
                recommendation: format!("Implement `{func}` per EIP-721 specification."),
                eip_reference: "EIP-721 §4".into(),
            });
        }
    }

    for event in required_events {
        let event_sig = format!("event {event}");
        let present = source.contains(&event_sig);
        checks.push(InterfaceCheckResult {
            element: format!("event {event}"),
            present,
            note: if present {
                String::new()
            } else {
                format!("ERC-721 requires event {event} — EIP-721 §5")
            },
        });
        if !present {
            findings.push(ComplianceFinding {
                standard: TokenStandard::Erc721,
                kind: ComplianceViolationKind::MissingRequiredEvent,
                severity: "Medium".into(),
                description: format!("ERC-721 required event `{event}` is absent."),
                recommendation: format!("Emit `{event}` per EIP-721 specification."),
                eip_reference: "EIP-721 §5".into(),
            });
        }
    }
}

// — ERC-1155 interface checks —

fn check_erc1155_interface(
    source: &str,
    checks: &mut Vec<InterfaceCheckResult>,
    findings: &mut Vec<ComplianceFinding>,
) {
    let required_functions = [
        "safeTransferFrom",
        "safeBatchTransferFrom",
        "balanceOf",
        "balanceOfBatch",
        "setApprovalForAll",
        "isApprovedForAll",
    ];
    let required_events = ["TransferSingle", "TransferBatch", "ApprovalForAll"];

    for func in required_functions {
        let fn_sig = format!("function {func}");
        let fn_call = format!("{func}(");
        let present = source.contains(&fn_sig) || source.contains(&fn_call);
        checks.push(InterfaceCheckResult {
            element: format!("{func}()"),
            present,
            note: if present {
                String::new()
            } else {
                format!("ERC-1155 requires {func}() — EIP-1155 §5")
            },
        });
        if !present {
            findings.push(ComplianceFinding {
                standard: TokenStandard::Erc1155,
                kind: ComplianceViolationKind::MissingRequiredFunction,
                severity: "High".into(),
                description: format!("ERC-1155 required function `{func}` is absent."),
                recommendation: format!("Implement `{func}` per EIP-1155 specification."),
                eip_reference: "EIP-1155 §5".into(),
            });
        }
    }

    for event in required_events {
        let event_sig = format!("event {event}");
        let present = source.contains(&event_sig);
        checks.push(InterfaceCheckResult {
            element: format!("event {event}"),
            present,
            note: if present {
                String::new()
            } else {
                format!("ERC-1155 requires event {event} — EIP-1155 §6")
            },
        });
        if !present {
            findings.push(ComplianceFinding {
                standard: TokenStandard::Erc1155,
                kind: ComplianceViolationKind::MissingRequiredEvent,
                severity: "Medium".into(),
                description: format!("ERC-1155 required event `{event}` is absent."),
                recommendation: format!("Emit `{event}` per EIP-1155 specification."),
                eip_reference: "EIP-1155 §6".into(),
            });
        }
    }
}

// — ERC-4626 interface checks —

fn check_erc4626_interface(
    source: &str,
    checks: &mut Vec<InterfaceCheckResult>,
    findings: &mut Vec<ComplianceFinding>,
) {
    let required_functions = [
        "asset",
        "totalAssets",
        "convertToShares",
        "convertToAssets",
        "maxDeposit",
        "previewDeposit",
        "deposit",
        "maxMint",
        "previewMint",
        "mint",
        "maxWithdraw",
        "previewWithdraw",
        "withdraw",
        "maxRedeem",
        "previewRedeem",
        "redeem",
    ];

    for func in required_functions {
        let fn_sig = format!("function {func}");
        let fn_call = format!("{func}(");
        let present = source.contains(&fn_sig) || source.contains(&fn_call);
        checks.push(InterfaceCheckResult {
            element: format!("{func}()"),
            present,
            note: if present {
                String::new()
            } else {
                format!("ERC-4626 requires {func}() — EIP-4626 §4")
            },
        });
        if !present {
            findings.push(ComplianceFinding {
                standard: TokenStandard::Erc4626,
                kind: ComplianceViolationKind::MissingRequiredFunction,
                severity: "High".into(),
                description: format!("ERC-4626 required function `{func}` is absent."),
                recommendation: format!("Implement `{func}` per EIP-4626 specification."),
                eip_reference: "EIP-4626 §4".into(),
            });
        }
    }

    // Vault inflation attack: first depositor can manipulate share price.
    // Only flag if BOTH _mint( AND MINIMUM_SHARES are absent — having either is a mitigation signal.
    if !source.contains("_mint(") && !source.contains("MINIMUM_SHARES") {
        findings.push(ComplianceFinding {
            standard: TokenStandard::Erc4626,
            kind: ComplianceViolationKind::VaultShareManipulation,
            severity: "Critical".into(),
            description:
                "ERC-4626 vault may be vulnerable to share-price inflation attack. A first depositor \
                 can donate assets to push the share price, causing subsequent depositors to receive \
                 fewer shares than expected."
                    .into(),
            recommendation:
                "Mint a small number of shares (dead shares) to the zero address on the first \
                 deposit, or enforce MINIMUM_SHARES to prevent share-price manipulation."
                    .into(),
            eip_reference: "EIP-4626 Security Considerations".into(),
        });
    }
}

// — Universal approval vulnerability checks —

fn check_approval_vulnerabilities(
    source: &str,
    standard: &TokenStandard,
    findings: &mut Vec<ComplianceFinding>,
) {
    // Infinite approval pattern: approve(type(uint256).max) or approve(MAX_UINT)
    if source.contains("type(uint256).max")
        || source.contains("2**256 - 1")
        || source.contains("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
    {
        findings.push(ComplianceFinding {
            standard: standard.clone(),
            kind: ComplianceViolationKind::InfiniteApproval,
            severity: "Medium".into(),
            description:
                "Infinite approval (uint256.max) is granted or supported. Compromised spenders \
                 can drain all tokens from every address that approved them."
                    .into(),
            recommendation:
                "Use time-limited or amount-bounded approvals. Consider implementing EIP-2612 \
                 permit() for gasless scoped approvals."
                    .into(),
            eip_reference: "EIP-20 Security Considerations; EIP-2612".into(),
        });
    }

    // ERC-20 approval race: changing allowance from non-zero to non-zero.
    if matches!(standard, TokenStandard::Erc20)
        && source.contains("function approve(")
        && !source.contains("increaseAllowance")
        && !source.contains("decreaseAllowance")
    {
        findings.push(ComplianceFinding {
            standard: standard.clone(),
            kind: ComplianceViolationKind::ApprovalRacingCondition,
            severity: "Low".into(),
            description:
                "ERC-20 approve() is susceptible to the well-known approval race condition. An \
                 attacker who monitors the mempool can spend both the old and new allowance when \
                 the owner attempts to change a non-zero allowance."
                    .into(),
            recommendation:
                "Add `increaseAllowance` / `decreaseAllowance` helpers (OpenZeppelin pattern), \
                 or require the allowance to be set to zero before changing it."
                    .into(),
            eip_reference: "EIP-20 §3 (note on approve)".into(),
        });
    }
}

// — Rebasing and fee-on-transfer edge case checks —

fn check_rebasing_fee_on_transfer(
    source: &str,
    standard: &TokenStandard,
    findings: &mut Vec<ComplianceFinding>,
) {
    let has_fee = source.contains("_fee")
        || source.contains("taxRate")
        || source.contains("burnOnTransfer")
        || source.contains("reflectionFee");

    let has_rebase = source.contains("rebase(")
        || source.contains("_rebase")
        || source.contains("elastic")
        || source.contains("gonsPerFragment");

    if has_fee {
        findings.push(ComplianceFinding {
            standard: standard.clone(),
            kind: ComplianceViolationKind::FeeOnTransfer,
            severity: "High".into(),
            description:
                "Token deducts a fee from transferred amounts. DeFi integrations that assume \
                 `transfer(amount)` delivers exactly `amount` to the recipient will malfunction \
                 (e.g., DEX pools, lending protocols, bridges)."
                    .into(),
            recommendation: "Document fee-on-transfer behaviour clearly. Integrators must use \
                 `balanceOf(recipient)` before and after transfers to compute the actual received \
                 amount."
                .into(),
            eip_reference: "EIP-20 Security Considerations".into(),
        });
    }

    if has_rebase {
        findings.push(ComplianceFinding {
            standard: standard.clone(),
            kind: ComplianceViolationKind::RebasingSupply,
            severity: "High".into(),
            description:
                "Token supply rebases automatically. Protocols that snapshot balances will hold \
                 stale values after a rebase event, leading to accounting errors and potential \
                 fund loss."
                    .into(),
            recommendation:
                "Consider wrapping the rebasing token into a static-balance wrapper (e.g., \
                 stETH → wstETH pattern). Ensure all DeFi integrations read live `balanceOf` \
                 rather than caching balances."
                    .into(),
            eip_reference: "EIP-20 Security Considerations".into(),
        });
    }
}

// — Cross-standard interaction vulnerability checks —

fn check_cross_standard_interactions(
    source: &str,
    standard: &TokenStandard,
    findings: &mut Vec<ComplianceFinding>,
) {
    // An ERC-1155 contract that also inherits ERC-20 creates ambiguous transfer semantics.
    if matches!(standard, TokenStandard::Erc1155)
        && (source.contains("IERC20") || source.contains("ERC20"))
    {
        findings.push(ComplianceFinding {
            standard: standard.clone(),
            kind: ComplianceViolationKind::CrossStandardInteraction,
            severity: "High".into(),
            description: "Contract inherits or implements both ERC-1155 and ERC-20 interfaces. \
                 Ambiguous transfer semantics can cause integrators to invoke the wrong transfer \
                 function, leading to incorrect token handling."
                .into(),
            recommendation:
                "Separate ERC-1155 and ERC-20 concerns into distinct contracts, or explicitly \
                 document which interface takes precedence and add input guards."
                    .into(),
            eip_reference: "EIP-1155 §7".into(),
        });
    }

    // ERC-4626 that also implements ERC-721 (e.g., position NFTs) must handle dual balances.
    if matches!(standard, TokenStandard::Erc4626)
        && (source.contains("ownerOf(") || source.contains("ERC721"))
    {
        findings.push(ComplianceFinding {
            standard: standard.clone(),
            kind: ComplianceViolationKind::CrossStandardInteraction,
            severity: "Medium".into(),
            description:
                "ERC-4626 vault also implements ERC-721 position tokens. Share accounting and \
                 NFT ownership must remain consistent — transferring the NFT should atomically \
                 transfer the underlying vault position."
                    .into(),
            recommendation:
                "Override `transferFrom` and `safeTransferFrom` so that NFT transfer also \
                 migrates the vault position. Add invariant tests to verify consistency."
                    .into(),
            eip_reference: "EIP-4626 Security Considerations; EIP-721 §6".into(),
        });
    }
}

// — Upgrade pattern checks —

fn check_upgrade_patterns(
    source: &str,
    standard: &TokenStandard,
    findings: &mut Vec<ComplianceFinding>,
) {
    let is_upgradeable = source.contains("upgradeTo(")
        || source.contains("UUPSUpgradeable")
        || source.contains("TransparentUpgradeableProxy")
        || source.contains("ProxyAdmin");

    if is_upgradeable && !source.contains("TimelockController") && !source.contains("timelock") {
        findings.push(ComplianceFinding {
            standard: standard.clone(),
            kind: ComplianceViolationKind::UnprotectedUpgrade,
            severity: "High".into(),
            description:
                "Token contract is upgradeable but no timelock is detected. A compromised owner \
                 key can immediately upgrade the implementation to arbitrary code, rugging all \
                 token holders."
                    .into(),
            recommendation:
                "Wrap the upgrade function behind a `TimelockController` with at least 48 h \
                 delay, or renounce upgrade capability once the contract is stable."
                    .into(),
            eip_reference: "EIP-1967; OpenZeppelin Security Advisories".into(),
        });
    }
}

// — Scoring helper —

fn compute_compliance_score(
    interface_checks: &[InterfaceCheckResult],
    findings: &[ComplianceFinding],
) -> u8 {
    if interface_checks.is_empty() {
        return 50;
    }

    let present_count = interface_checks.iter().filter(|c| c.present).count();
    let interface_score = (present_count * 70) / interface_checks.len();

    let deductions: usize = findings
        .iter()
        .map(|f| match f.severity.as_str() {
            "Critical" => 20,
            "High" => 10,
            "Medium" => 5,
            "Low" => 2,
            _ => 0,
        })
        .sum();

    let raw = (interface_score + 30).saturating_sub(deductions);
    raw.min(100) as u8
}
