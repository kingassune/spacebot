//! DAO and on-chain governance security analysis.

/// Type of governance attack against a DAO or protocol.
#[derive(Debug, Clone, PartialEq)]
pub enum GovernanceAttack {
    /// Use flash-loaned tokens to pass a malicious proposal.
    FlashLoanVoting,
    /// Spam governance queue with bad proposals to block legitimate ones.
    ProposalGriefing,
    /// Accumulate votes to push quorum below a critical threshold.
    QuorumManipulation,
    /// Exploit timing gaps to bypass the timelock.
    TimelockBypass,
    /// Sybil-delegate votes through sock-puppet wallets.
    DelegateManipulation,
    /// Pass a malicious proposal to drain the protocol treasury.
    TreasuryDrain,
    /// Exploit vote-escrowed token mechanics for disproportionate votes.
    VeTokenExploit,
    /// Pay voters off-chain to vote for a harmful proposal.
    BriberyAttack,
}

/// On-chain voting mechanism used by the governance system.
#[derive(Debug, Clone, PartialEq)]
pub enum VotingMechanism {
    /// Simple token-weight voting.
    TokenWeighted,
    /// Vote-escrowed tokens with time-weighted power.
    VeToken,
    /// Quadratic voting to reduce whale dominance.
    Quadratic,
    /// Time-weighted average balance.
    TWAB,
    /// Off-chain Snapshot voting with on-chain execution.
    Snapshot,
    /// Multi-sig controlled governance.
    MultiSig,
}

/// A specific attack surface entry point in the governance system.
#[derive(Debug, Clone)]
pub struct GovernanceAttackSurface {
    /// Attack type associated with this surface.
    pub attack_type: GovernanceAttack,
    /// Severity classification.
    pub severity: String,
    /// Description of the attack surface.
    pub description: String,
}

/// Governance security analysis results.
#[derive(Debug, Clone)]
pub struct GovernanceAnalysis {
    /// Protocol name or address.
    pub protocol: String,
    /// Voting mechanism in use.
    pub voting_mechanism: VotingMechanism,
    /// Identified attack surfaces.
    pub attack_surface: Vec<GovernanceAttackSurface>,
    /// Specific security recommendations.
    pub recommendations: Vec<String>,
    /// Overall governance health score (0.0–100.0).
    pub health_score: f64,
}

/// Governance attack simulation result.
#[derive(Debug, Clone)]
pub struct GovernanceSimResult {
    /// Attack type simulated.
    pub attack_type: GovernanceAttack,
    /// Whether the attack succeeded.
    pub success: bool,
    /// Estimated tokens required to execute the attack.
    pub tokens_required: u64,
    /// Estimated cost in USD.
    pub cost_usd: f64,
    /// Narrative of the simulation.
    pub narrative: String,
}

/// Analyser for DAO and on-chain governance security.
#[derive(Debug, Clone)]
pub struct GovernanceAnalyzer {
    /// Protocol being analysed.
    pub protocol: String,
    /// Voting mechanism in use.
    pub voting_mechanism: VotingMechanism,
}

impl GovernanceAnalyzer {
    /// Create a new governance analyser.
    pub fn new(protocol: impl Into<String>, voting_mechanism: VotingMechanism) -> Self {
        Self {
            protocol: protocol.into(),
            voting_mechanism,
        }
    }

    /// Perform a full governance security analysis.
    pub fn analyze_governance_security(&self) -> GovernanceAnalysis {
        let attack_surface = self.identify_attack_surfaces();
        let recommendations = self.generate_recommendations(&attack_surface);
        let health_score = calculate_health_score(&attack_surface);

        GovernanceAnalysis {
            protocol: self.protocol.clone(),
            voting_mechanism: self.voting_mechanism.clone(),
            attack_surface,
            recommendations,
            health_score,
        }
    }

    /// Simulate a specific governance attack.
    pub fn simulate_governance_attack(
        &self,
        attack: &GovernanceAttack,
        total_supply: u64,
    ) -> GovernanceSimResult {
        let (tokens_required, cost_usd) = match attack {
            GovernanceAttack::FlashLoanVoting => (total_supply / 2, 50_000.0),
            GovernanceAttack::QuorumManipulation => (total_supply / 10, 10_000.0),
            GovernanceAttack::TreasuryDrain => (total_supply / 3, 100_000.0),
            // Bribery is an off-chain purchase of votes; no token ownership required.
            GovernanceAttack::BriberyAttack => (0, 250_000.0),
            _ => (total_supply / 20, 5_000.0),
        };

        let success = match self.voting_mechanism {
            VotingMechanism::TokenWeighted => true,
            VotingMechanism::Snapshot => {
                matches!(attack, GovernanceAttack::FlashLoanVoting)
                    || matches!(attack, GovernanceAttack::TreasuryDrain)
            }
            VotingMechanism::MultiSig => false,
            _ => !matches!(attack, GovernanceAttack::FlashLoanVoting),
        };

        GovernanceSimResult {
            attack_type: attack.clone(),
            success,
            tokens_required,
            cost_usd,
            narrative: format!(
                "{:?} simulation against '{}' ({:?} voting): {}. \
                 Estimated cost: ${:.0}. Tokens needed: {}.",
                attack,
                self.protocol,
                self.voting_mechanism,
                if success { "SUCCEEDED" } else { "FAILED" },
                cost_usd,
                tokens_required
            ),
        }
    }

    /// Verify timelock configuration and identify bypass risks.
    pub fn check_timelock_configuration(&self, timelock_delay_hours: u64) -> Vec<String> {
        let mut issues = Vec::new();

        if timelock_delay_hours < 24 {
            issues.push(format!(
                "Timelock delay of {} hours is too short — recommend minimum 48 hours for \
                 treasury-affecting proposals.",
                timelock_delay_hours
            ));
        }

        if timelock_delay_hours == 0 {
            issues.push(
                "No timelock enforced — proposals can be executed immediately after passing."
                    .to_string(),
            );
        }

        if issues.is_empty() {
            issues.push(format!(
                "Timelock configuration ({timelock_delay_hours}h) meets minimum security \
                 requirements."
            ));
        }

        issues
    }

    /// Assess voting power concentration risk.
    ///
    /// `top_holder_pct` is the percentage of total supply held by the largest holder.
    pub fn assess_voting_power_concentration(&self, top_holder_pct: f64) -> String {
        let risk = if top_holder_pct >= 51.0 {
            "CRITICAL — single entity controls majority voting power"
        } else if top_holder_pct >= 33.0 {
            "HIGH — single entity can block any proposal requiring 2/3 quorum"
        } else if top_holder_pct >= 20.0 {
            "MEDIUM — concentrated power, whale manipulation possible"
        } else {
            "LOW — voting power appears reasonably distributed"
        };

        format!("Voting power concentration: top holder holds {top_holder_pct:.1}% — Risk: {risk}")
    }

    /// Generate a comprehensive governance security report.
    pub fn generate_governance_report(&self) -> String {
        let analysis = self.analyze_governance_security();
        let surface_text: Vec<String> = analysis
            .attack_surface
            .iter()
            .map(|s| format!("  [{:?}] {}: {}", s.attack_type, s.severity, s.description))
            .collect();
        let rec_text: Vec<String> = analysis
            .recommendations
            .iter()
            .map(|r| format!("  - {r}"))
            .collect();

        format!(
            "=== Governance Security Report ===\n\
             Protocol:          {}\n\
             Voting Mechanism:  {:?}\n\
             Health Score:      {:.1}/100\n\n\
             Attack Surface ({}):\n{}\n\n\
             Recommendations:\n{}",
            self.protocol,
            self.voting_mechanism,
            analysis.health_score,
            analysis.attack_surface.len(),
            if surface_text.is_empty() {
                "  No critical issues found.".to_string()
            } else {
                surface_text.join("\n")
            },
            rec_text.join("\n")
        )
    }

    /// Identify attack surfaces based on the voting mechanism.
    fn identify_attack_surfaces(&self) -> Vec<GovernanceAttackSurface> {
        let mut surfaces = Vec::new();

        if matches!(self.voting_mechanism, VotingMechanism::TokenWeighted) {
            surfaces.push(GovernanceAttackSurface {
                attack_type: GovernanceAttack::FlashLoanVoting,
                severity: "Critical".to_string(),
                description:
                    "Token-weighted voting is vulnerable to flash-loan governance attacks \
                              if snapshot is taken at vote time."
                        .to_string(),
            });
        }

        surfaces.push(GovernanceAttackSurface {
            attack_type: GovernanceAttack::TreasuryDrain,
            severity: "Critical".to_string(),
            description: "Governance proposals can target treasury contracts without spending \
                          limits."
                .to_string(),
        });

        surfaces.push(GovernanceAttackSurface {
            attack_type: GovernanceAttack::ProposalGriefing,
            severity: "Medium".to_string(),
            description: "No minimum token threshold to submit proposals allows spam attacks."
                .to_string(),
        });

        surfaces
    }

    /// Generate recommendations based on identified attack surfaces.
    fn generate_recommendations(&self, surfaces: &[GovernanceAttackSurface]) -> Vec<String> {
        let mut recs = vec![
            "Implement a voting snapshot taken at proposal creation, not vote time.".to_string(),
            "Require a meaningful token threshold to submit proposals.".to_string(),
            "Apply a per-proposal spending cap on treasury withdrawals.".to_string(),
            "Enforce a minimum 48-hour timelock for all executable proposals.".to_string(),
        ];

        for surface in surfaces {
            if surface.attack_type == GovernanceAttack::FlashLoanVoting {
                recs.push(
                    "Use vote-locked tokens (veToken model) to prevent flash-loan governance attacks."
                        .to_string(),
                );
            }
        }

        recs
    }
}

/// Compute a governance health score (0.0–100.0) from attack surface findings.
fn calculate_health_score(surfaces: &[GovernanceAttackSurface]) -> f64 {
    let critical = surfaces.iter().filter(|s| s.severity == "Critical").count();
    let high = surfaces.iter().filter(|s| s.severity == "High").count();

    let deduction = (critical * 20 + high * 10) as f64;
    (100.0 - deduction).max(0.0)
}
