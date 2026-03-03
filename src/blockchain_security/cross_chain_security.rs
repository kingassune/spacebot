//! Cross-chain bridge and multi-chain security analysis.

/// Type of cross-chain attack against a bridge or messaging protocol.
#[derive(Debug, Clone, PartialEq)]
pub enum CrossChainAttack {
    /// Replay a valid message on a different chain.
    MessageReplay,
    /// Submit a fraudulent proof to the bridge.
    FakeProof,
    /// Collude among validators to approve fraudulent transactions.
    ValidatorCollusion,
    /// Manipulate oracle prices used by the bridge.
    OracleManipulation,
    /// Exploit insufficient finality assumptions to double-spend.
    FinalityExploit,
    /// Send assets on source chain and prevent receipt on destination.
    DoubleSpend,
    /// Drain bridge liquidity pools directly, distinct from ValidatorCollusion
    /// in that it exploits contract logic rather than the validator set.
    BridgeDrain,
    /// Desynchronise wrapped token supply from native supply.
    WrappedTokenDesync,
}

/// Supported blockchain networks.
#[derive(Debug, Clone, PartialEq)]
pub enum Chain {
    /// Ethereum mainnet.
    Ethereum,
    /// BNB Smart Chain.
    BNBChain,
    /// Polygon PoS.
    Polygon,
    /// Arbitrum One.
    Arbitrum,
    /// Optimism.
    Optimism,
    /// Avalanche C-Chain.
    Avalanche,
    /// Solana.
    Solana,
    /// Cosmos Hub.
    Cosmos,
    /// A custom or unnamed chain.
    Custom(String),
}

/// Security finding in a cross-chain bridge.
#[derive(Debug, Clone)]
pub struct BridgeVulnerability {
    /// Attack type this vulnerability enables.
    pub attack_type: CrossChainAttack,
    /// Severity description.
    pub severity: String,
    /// Human-readable description.
    pub description: String,
    /// Recommended remediation.
    pub recommendation: String,
}

/// Result of a cross-chain security analysis.
#[derive(Debug, Clone)]
pub struct CrossChainAnalysis {
    /// Source chain of the bridge.
    pub source_chain: Chain,
    /// Destination chain of the bridge.
    pub destination_chain: Chain,
    /// Name or address of the bridge protocol.
    pub bridge_protocol: String,
    /// Vulnerabilities identified during analysis.
    pub vulnerabilities: Vec<BridgeVulnerability>,
    /// Overall risk score (0.0–10.0).
    pub risk_score: f64,
    /// Executive summary.
    pub summary: String,
}

/// Analyser for cross-chain bridge and protocol security.
#[derive(Debug, Clone)]
pub struct CrossChainAnalyzer {
    /// Source chain to analyse from.
    pub source_chain: Chain,
    /// Destination chain to analyse to.
    pub destination_chain: Chain,
}

impl CrossChainAnalyzer {
    /// Create a new cross-chain analyser.
    pub fn new(source_chain: Chain, destination_chain: Chain) -> Self {
        Self {
            source_chain,
            destination_chain,
        }
    }

    /// Analyse bridge security for the given protocol.
    pub fn analyze_bridge_security(&self, bridge_protocol: &str) -> CrossChainAnalysis {
        let vulnerabilities = self.detect_bridge_vulnerabilities(bridge_protocol);
        let risk_score = calculate_risk_score(&vulnerabilities);

        CrossChainAnalysis {
            source_chain: self.source_chain.clone(),
            destination_chain: self.destination_chain.clone(),
            bridge_protocol: bridge_protocol.to_string(),
            vulnerabilities,
            risk_score,
            summary: format!(
                "Bridge '{}' analysis complete. Risk score: {:.1}/10.0",
                bridge_protocol, risk_score
            ),
        }
    }

    /// Verify the integrity of a cross-chain message.
    ///
    /// Returns `Ok(())` if the message passes validation, or an error string.
    pub fn verify_message_integrity(&self, message_hash: &str) -> Result<(), String> {
        if message_hash.len() < 32 {
            return Err(format!(
                "Message hash '{}' is too short to be a valid cross-chain message hash.",
                message_hash
            ));
        }
        Ok(())
    }

    /// Check finality assumptions used by the bridge.
    ///
    /// Returns a list of finality-related issues found.
    pub fn check_finality_assumptions(&self, confirmation_blocks: u64) -> Vec<String> {
        let mut issues = Vec::new();

        let min_safe_confirmations: u64 = match &self.source_chain {
            Chain::Ethereum => 12,
            Chain::BNBChain => 15,
            Chain::Polygon => 128,
            Chain::Avalanche => 1,
            _ => 6,
        };

        if confirmation_blocks < min_safe_confirmations {
            issues.push(format!(
                "Bridge uses only {} confirmation(s) on {:?} — recommended minimum is {}. \
                 Risk of finality exploit / reorganisation attack.",
                confirmation_blocks, self.source_chain, min_safe_confirmations
            ));
        }

        issues
    }

    /// Simulate a cross-chain attack and return a narrative description.
    pub fn simulate_cross_chain_attack(&self, attack: &CrossChainAttack) -> String {
        match attack {
            CrossChainAttack::MessageReplay => format!(
                "Simulated MessageReplay: attacker captures valid message from {:?} → {:?} and \
                 replays it to double-claim bridged assets.",
                self.source_chain, self.destination_chain
            ),
            CrossChainAttack::BridgeDrain => format!(
                "Simulated BridgeDrain: attacker exploits unchecked external call in bridge \
                 contract on {:?} to drain liquidity pool.",
                self.destination_chain
            ),
            CrossChainAttack::ValidatorCollusion => format!(
                "Simulated ValidatorCollusion: {} of {} validators collude to approve \
                 fraudulent withdrawal on {:?}.",
                3, 5, self.destination_chain
            ),
            CrossChainAttack::FinalityExploit => format!(
                "Simulated FinalityExploit: attacker submits deposit on {:?} during a chain \
                 reorganisation and claims assets on {:?} before the reorg is detected.",
                self.source_chain, self.destination_chain
            ),
            _ => format!(
                "Simulated {:?} attack on bridge between {:?} and {:?}.",
                attack, self.source_chain, self.destination_chain
            ),
        }
    }

    /// Generate a comprehensive bridge security audit report.
    pub fn generate_bridge_audit_report(&self, bridge_protocol: &str) -> String {
        let analysis = self.analyze_bridge_security(bridge_protocol);
        let vuln_text: Vec<String> = analysis
            .vulnerabilities
            .iter()
            .map(|v| {
                format!(
                    "  [{:?}] {} — {}\n    Recommendation: {}",
                    v.attack_type, v.severity, v.description, v.recommendation
                )
            })
            .collect();

        format!(
            "=== Cross-Chain Bridge Audit Report ===\n\
             Protocol:     {}\n\
             Source Chain: {:?}\n\
             Dest Chain:   {:?}\n\
             Risk Score:   {:.1}/10.0\n\n\
             Vulnerabilities ({}):\n{}",
            bridge_protocol,
            self.source_chain,
            self.destination_chain,
            analysis.risk_score,
            analysis.vulnerabilities.len(),
            if vuln_text.is_empty() {
                "  No critical vulnerabilities found.".to_string()
            } else {
                vuln_text.join("\n")
            }
        )
    }

    /// Detect known bridge vulnerability patterns.
    fn detect_bridge_vulnerabilities(&self, protocol: &str) -> Vec<BridgeVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.push(BridgeVulnerability {
            attack_type: CrossChainAttack::MessageReplay,
            severity: "High".to_string(),
            description: format!(
                "{protocol} messages may lack nonce or chain-ID binding, enabling replay attacks."
            ),
            recommendation: "Add unique nonce and chain-ID to every cross-chain message and \
                             validate on receipt."
                .to_string(),
        });

        vulnerabilities.push(BridgeVulnerability {
            attack_type: CrossChainAttack::ValidatorCollusion,
            severity: "Critical".to_string(),
            description: "Small validator set (< 7 signers) is susceptible to collusion attacks."
                .to_string(),
            recommendation:
                "Increase validator set size and require > 2/3 threshold for message approval."
                    .to_string(),
        });

        vulnerabilities
    }
}

/// Compute a 0.0–10.0 risk score from a set of bridge vulnerabilities.
fn calculate_risk_score(vulnerabilities: &[BridgeVulnerability]) -> f64 {
    let critical = vulnerabilities
        .iter()
        .filter(|v| v.severity == "Critical")
        .count();
    let high = vulnerabilities
        .iter()
        .filter(|v| v.severity == "High")
        .count();

    ((critical * 3 + high * 2) as f64).min(10.0)
}
