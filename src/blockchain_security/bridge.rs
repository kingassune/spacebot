//! Cross-chain bridge security audit framework.

/// Architectural classification of cross-chain bridges.
#[derive(Debug, Clone, PartialEq)]
pub enum BridgeType {
    LockAndMint,
    BurnAndMint,
    Liquidity,
    MessagePassing,
    Optimistic,
    ZkBridge,
    TrustedRelay,
}

/// Known vulnerability classes for bridge contracts.
#[derive(Debug, Clone, PartialEq)]
pub enum BridgeVulnerability {
    SignatureForge,
    MessageReplay,
    Censorship,
    ValidatorCollusion,
    OracleManipulation,
    UnboundedMint,
    IncompleteVerification,
    MissingNonceCheck,
    FrontrunningAttack,
    ExitWindowBypass,
}

/// A cross-chain message with associated metadata.
#[derive(Debug, Clone)]
pub struct CrossChainMessage {
    pub source_chain: String,
    pub dest_chain: String,
    pub message_hash: String,
    pub nonce: u64,
    pub validator_signatures: Vec<String>,
}

/// Comprehensive result of a bridge contract audit.
#[derive(Debug, Clone)]
pub struct BridgeAuditResult {
    pub bridge_type: BridgeType,
    pub vulnerabilities: Vec<BridgeVulnerability>,
    pub security_score: u8,
    pub findings: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Audit a bridge contract source for known vulnerability patterns.
pub fn analyze_bridge_contract(
    source: &str,
    bridge_type: &BridgeType,
) -> anyhow::Result<BridgeAuditResult> {
    let mut vulnerabilities = Vec::new();
    let mut findings = Vec::new();
    let mut recommendations = Vec::new();

    // Nonce / replay checks
    if !source.contains("nonce") && !source.contains("messageId") {
        vulnerabilities.push(BridgeVulnerability::MissingNonceCheck);
        findings.push(
            "No nonce or message-ID deduplication found; replay attacks are possible.".into(),
        );
        recommendations
            .push("Maintain a consumed-nonce mapping and reject duplicate messages.".into());
    }

    // Signature verification
    if source.contains("ecrecover")
        && !source.contains("require(signer")
        && !source.contains("_verify(")
    {
        vulnerabilities.push(BridgeVulnerability::SignatureForge);
        findings.push("ecrecover result is not validated against an expected signer set.".into());
        recommendations
            .push("Compare ecrecover output against the authorised validator set.".into());
    }

    // Unbounded mint
    if (source.contains("mint(") || source.contains("_mint(")) && !source.contains("totalSupply") {
        vulnerabilities.push(BridgeVulnerability::UnboundedMint);
        findings.push("Mint function detected without supply cap; unlimited issuance risk.".into());
        recommendations
            .push("Enforce a supply cap tied to the locked collateral on the source chain.".into());
    }

    // Message verification completeness
    if matches!(
        bridge_type,
        BridgeType::MessagePassing | BridgeType::Optimistic
    ) && !source.contains("verifyMessage")
        && !source.contains("_checkMessage")
    {
        vulnerabilities.push(BridgeVulnerability::IncompleteVerification);
        findings.push("Message passing bridge lacks explicit message verification routine.".into());
        recommendations
            .push("Implement verifyMessage with merkle-proof or ZK verification.".into());
    }

    // Optimistic exit window
    if matches!(bridge_type, BridgeType::Optimistic) && !source.contains("challengePeriod") {
        vulnerabilities.push(BridgeVulnerability::ExitWindowBypass);
        findings.push("Optimistic bridge has no challengePeriod enforced on-chain.".into());
        recommendations
            .push("Enforce a minimum 7-day challenge window before finalising exits.".into());
    }

    let deduction = (vulnerabilities.len() as u8).saturating_mul(12);
    let security_score = 100_u8.saturating_sub(deduction);

    Ok(BridgeAuditResult {
        bridge_type: bridge_type.clone(),
        vulnerabilities,
        security_score,
        findings,
        recommendations,
    })
}

/// Validate a cross-chain message for basic integrity.
pub fn verify_cross_chain_message(msg: &CrossChainMessage) -> bool {
    msg.nonce > 0 && !msg.message_hash.is_empty()
}

/// Return whether the validator set meets the required threshold.
pub fn check_validator_set(validators: &[String], threshold: usize) -> bool {
    validators.len() >= threshold
}

/// Generate an audit checklist appropriate for the bridge type.
pub fn generate_bridge_checklist(bridge_type: &BridgeType) -> Vec<String> {
    let mut checklist = vec![
        "Verify nonce/message-ID deduplication prevents replay attacks.".into(),
        "Confirm validator signature threshold and key management procedures.".into(),
        "Review emergency pause and recovery mechanisms.".into(),
        "Audit event emission for off-chain monitoring.".into(),
    ];

    match bridge_type {
        BridgeType::LockAndMint => {
            checklist.push("Ensure locked assets cannot exceed minted supply.".into());
            checklist.push("Verify unlock is gated on verified burn proof.".into());
        }
        BridgeType::BurnAndMint => {
            checklist.push("Confirm burn is irreversible before mint is triggered.".into());
            checklist.push("Validate cross-chain message authenticity before minting.".into());
        }
        BridgeType::Liquidity => {
            checklist.push("Assess liquidity pool imbalance and incentive alignment.".into());
            checklist.push("Check for flash-loan attack surface on liquidity provision.".into());
        }
        BridgeType::MessagePassing => {
            checklist.push("Verify message format and encoding cannot be manipulated.".into());
            checklist.push("Confirm destination contract validates message origin.".into());
        }
        BridgeType::Optimistic => {
            checklist.push("Enforce minimum 7-day challenge window.".into());
            checklist.push("Review fraud-proof submission and bond slashing logic.".into());
        }
        BridgeType::ZkBridge => {
            checklist.push("Audit ZK circuit for soundness and completeness.".into());
            checklist.push("Review trusted setup ceremony participants and process.".into());
        }
        BridgeType::TrustedRelay => {
            checklist.push("Assess relayer key management and rotation procedures.".into());
            checklist.push(
                "Implement multi-relayer consensus to reduce single point of failure.".into(),
            );
        }
    }

    checklist
}

// ── Protocol-Specific Bridge Analyzes ─────────────────────────────────────

/// LayerZero-specific vulnerability analysis.
#[derive(Debug, Clone)]
pub struct LayerZeroAnalysis {
    pub findings: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Check a contract for LayerZero-specific vulnerabilities.
pub fn analyze_layerzero(source: &str) -> LayerZeroAnalysis {
    let mut findings = Vec::new();
    let mut recommendations = Vec::new();

    if source.contains("lzReceive")
        && !source.contains("onlyEndpoint")
        && !source.contains("_msgSender() == lzEndpoint")
    {
        findings.push(
            "lzReceive is not restricted to the LayerZero endpoint; spoofing possible.".into(),
        );
        recommendations
            .push("Gate lzReceive with: require(_msgSender() == address(lzEndpoint)).".into());
    }

    if source.contains("retryPayload") && !source.contains("hasStoredPayload") {
        findings.push("retryPayload called without hasStoredPayload check; unsafe retry.".into());
        recommendations.push("Verify hasStoredPayload before retrying blocked payloads.".into());
    }

    if !source.contains("trustedRemote") && source.contains("lzReceive") {
        findings.push("No trustedRemote mapping found; arbitrary source chain acceptance.".into());
        recommendations.push(
            "Maintain a trustedRemoteLookup mapping and validate src chain + address.".into(),
        );
    }

    LayerZeroAnalysis {
        findings,
        recommendations,
    }
}

/// Wormhole-specific vulnerability analysis.
#[derive(Debug, Clone)]
pub struct WormholeAnalysis {
    pub findings: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Check a contract for Wormhole-specific vulnerabilities.
pub fn analyze_wormhole(source: &str) -> WormholeAnalysis {
    let mut findings = Vec::new();
    let mut recommendations = Vec::new();

    if source.contains("parseAndVerifyVM") && !source.contains("require(valid") {
        findings
            .push("Wormhole VM not validated after parsing; forged VAAs may be accepted.".into());
        recommendations
            .push("Check the bool return of parseAndVerifyVM and revert on invalid.".into());
    }

    if source.contains("emitterAddress") && !source.contains("require(emitterAddress") {
        findings.push(
            "emitterAddress not validated against trusted set; arbitrary origin accepted.".into(),
        );
        recommendations
            .push("Maintain a whitelist of trusted emitterAddress values per chain.".into());
    }

    WormholeAnalysis {
        findings,
        recommendations,
    }
}

/// Hyperlane-specific vulnerability analysis.
#[derive(Debug, Clone)]
pub struct HyperlaneAnalysis {
    pub findings: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Check a contract for Hyperlane-specific vulnerabilities.
pub fn analyze_hyperlane(source: &str) -> HyperlaneAnalysis {
    let mut findings = Vec::new();
    let mut recommendations = Vec::new();

    if source.contains("handle(") && !source.contains("onlyMailbox") {
        findings
            .push("handle() not gated by onlyMailbox modifier; spoofed messages accepted.".into());
        recommendations.push("Add onlyMailbox modifier to handle() function.".into());
    }

    if source.contains("interchainSecurityModule") && source.contains("address(0)") {
        findings.push("ISM set to zero address; no message security verification.".into());
        recommendations.push("Configure a non-zero ISM for all message routes.".into());
    }

    HyperlaneAnalysis {
        findings,
        recommendations,
    }
}

/// Relayer centralisation risk assessment.
#[derive(Debug, Clone)]
pub struct RelayerSecurityCheck {
    pub relayer_count: u32,
    pub is_permissioned: bool,
    pub has_rotation: bool,
    pub risks: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Assess relayer security from a bridge contract source.
pub fn check_relayer_security(source: &str) -> RelayerSecurityCheck {
    let mut risks = Vec::new();
    let mut recommendations = Vec::new();

    let is_permissioned = source.contains("onlyRelayer") || source.contains("relayerRole");
    let has_rotation = source.contains("rotateRelayer") || source.contains("setRelayer");
    let relayer_count = if source.contains("relayers.length") || source.contains("_relayers[") {
        0
    } else {
        1
    };

    if relayer_count <= 1 && !source.contains("IRelayerRegistry") {
        risks.push("Single relayer detected; single point of failure and censorship risk.".into());
        recommendations.push(
            "Implement a relayer registry with multiple participants and economic incentives."
                .into(),
        );
    }

    if !has_rotation {
        risks.push("No relayer rotation mechanism; compromised key cannot be replaced.".into());
        recommendations.push("Add relayer rotation with time-lock and multisig approval.".into());
    }

    RelayerSecurityCheck {
        relayer_count,
        is_permissioned,
        has_rotation,
        risks,
        recommendations,
    }
}
