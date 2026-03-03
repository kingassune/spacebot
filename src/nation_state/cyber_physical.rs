//! ICS/SCADA/OT cyber-physical attack simulation.

/// Industrial control system communication protocol.
#[derive(Debug, Clone, PartialEq)]
pub enum IndustrialProtocol {
    /// Modbus serial/TCP communication protocol.
    Modbus,
    /// DNP3 protocol for SCADA communications.
    DNP3,
    /// OPC Unified Architecture.
    OpcUa,
    /// EtherNet/IP industrial Ethernet protocol.
    EthernetIP,
    /// BACnet building automation protocol.
    BACnet,
    /// PROFINET industrial Ethernet standard.
    Profinet,
    /// IEC 61850 substation automation standard.
    IEC61850,
    /// Siemens S7 communication protocol.
    S7Comm,
}

/// Category of critical infrastructure targeted.
#[derive(Debug, Clone, PartialEq)]
pub enum CriticalInfrastructure {
    /// Electric power generation and distribution.
    PowerGrid,
    /// Municipal water treatment and distribution.
    WaterTreatment,
    /// Nuclear power generation facility.
    NuclearFacility,
    /// Road, rail, or aviation transport systems.
    TransportNetwork,
    /// Telephone and data communications networks.
    TelecomNetwork,
    /// Banking and payments infrastructure.
    FinancialSystem,
    /// Hospital and healthcare services.
    HealthcareSystem,
    /// Industrial manufacturing plant.
    ManufacturingPlant,
}

/// Physical safety impact classification.
#[derive(Debug, Clone, PartialEq)]
pub enum SafetyImpact {
    /// No safety impact.
    None,
    /// Minor operational disruption only.
    Minor,
    /// Equipment damage or significant service loss.
    Moderate,
    /// Threat to human life or widespread outages.
    Severe,
    /// Catastrophic — mass casualties or national-level disruption.
    Catastrophic,
}

/// Assessment of safety and operational impact.
#[derive(Debug, Clone)]
pub struct ImpactAssessment {
    /// Classification of safety risk.
    pub safety_impact: SafetyImpact,
    /// Estimated number of people affected.
    pub estimated_affected_population: u64,
    /// Estimated recovery time in hours.
    pub recovery_time_hours: u64,
    /// Estimated economic cost in USD.
    pub economic_cost_usd: u64,
    /// Narrative description of the impact.
    pub narrative: String,
}

/// Simulation result for an ICS/SCADA attack.
#[derive(Debug, Clone)]
pub struct IcsAttackResult {
    /// Whether the simulated attack achieved its objective.
    pub success: bool,
    /// Impact assessment for the attack.
    pub impact: ImpactAssessment,
    /// Attack techniques observed in the simulation.
    pub techniques_used: Vec<String>,
    /// Recommended defensive measures.
    pub mitigations: Vec<String>,
}

/// Cyber-physical attack simulation against ICS/OT environments.
#[derive(Debug, Clone)]
pub struct CyberPhysicalAttack {
    /// Industrial protocol exploited in the attack.
    pub protocol: IndustrialProtocol,
    /// Target critical infrastructure sector.
    pub target_system: CriticalInfrastructure,
    /// Pre-computed impact assessment.
    pub impact_assessment: ImpactAssessment,
}

impl CyberPhysicalAttack {
    /// Create a new cyber-physical attack scenario.
    pub fn new(protocol: IndustrialProtocol, target_system: CriticalInfrastructure) -> Self {
        let impact_assessment = estimate_impact(&protocol, &target_system);
        Self {
            protocol,
            target_system,
            impact_assessment,
        }
    }

    /// Simulate an ICS attack and return the result.
    pub fn simulate_ics_attack(&self) -> IcsAttackResult {
        let techniques = vec![
            format!("Protocol enumeration via {:?}", self.protocol),
            "PLC firmware reconnaissance".to_string(),
            "Ladder logic modification simulation".to_string(),
            "Safety system bypass analysis".to_string(),
        ];

        let mitigations = self.generate_ot_mitigations();

        IcsAttackResult {
            success: true,
            impact: self.impact_assessment.clone(),
            techniques_used: techniques,
            mitigations,
        }
    }

    /// Analyse simulated PLC firmware for known vulnerability patterns.
    pub fn analyze_plc_firmware(&self) -> Vec<String> {
        vec![
            format!(
                "Checking {:?} protocol implementation for known CVEs...",
                self.protocol
            ),
            "Scanning for hardcoded credentials in firmware image...".to_string(),
            "Analysing memory layout for buffer overflow vectors...".to_string(),
            "Checking for unsigned firmware update validation...".to_string(),
        ]
    }

    /// Assess physical safety impact of the attack.
    pub fn assess_safety_impact(&self) -> &ImpactAssessment {
        &self.impact_assessment
    }

    /// Generate a full OT attack report.
    pub fn generate_ot_report(&self) -> String {
        let result = self.simulate_ics_attack();
        let mitigation_text = result.mitigations.join("\n  - ");

        format!(
            "=== OT/ICS Attack Simulation Report ===\n\
             Protocol:     {:?}\n\
             Target:       {:?}\n\
             Safety Impact: {:?}\n\
             Affected Pop: {}\n\
             Recovery:     {} hours\n\
             Econ. Cost:   ${} USD\n\n\
             Impact Narrative:\n  {}\n\n\
             Recommended Mitigations:\n  - {}",
            self.protocol,
            self.target_system,
            self.impact_assessment.safety_impact,
            self.impact_assessment.estimated_affected_population,
            self.impact_assessment.recovery_time_hours,
            self.impact_assessment.economic_cost_usd,
            self.impact_assessment.narrative,
            mitigation_text
        )
    }

    /// Generate OT-specific defensive mitigations.
    fn generate_ot_mitigations(&self) -> Vec<String> {
        let mut mitigations = vec![
            "Segment OT network from IT with one-way data diodes.".to_string(),
            "Implement protocol-aware deep packet inspection.".to_string(),
            "Deploy anomaly detection on all ICS traffic baselines.".to_string(),
            "Enforce strict change management on PLC configurations.".to_string(),
        ];

        match self.target_system {
            CriticalInfrastructure::PowerGrid => {
                mitigations
                    .push("Apply NERC CIP standards for bulk electric system assets.".to_string());
            }
            CriticalInfrastructure::WaterTreatment => {
                mitigations.push(
                    "Apply AWIA 2018 requirements and manual override capabilities.".to_string(),
                );
            }
            CriticalInfrastructure::NuclearFacility => {
                mitigations.push("Enforce air-gap isolation per NRC RG 5.71.".to_string());
            }
            _ => {}
        }

        mitigations
    }
}

/// Estimate the physical impact of an attack on the given target via the given protocol.
fn estimate_impact(
    protocol: &IndustrialProtocol,
    target: &CriticalInfrastructure,
) -> ImpactAssessment {
    let (safety, population, recovery_hours, cost) = match target {
        CriticalInfrastructure::PowerGrid => {
            (SafetyImpact::Severe, 500_000u64, 72u64, 50_000_000u64)
        }
        CriticalInfrastructure::WaterTreatment => (SafetyImpact::Severe, 100_000, 96, 10_000_000),
        CriticalInfrastructure::NuclearFacility => {
            (SafetyImpact::Catastrophic, 1_000_000, 720, 1_000_000_000)
        }
        CriticalInfrastructure::TransportNetwork => {
            (SafetyImpact::Moderate, 200_000, 48, 20_000_000)
        }
        CriticalInfrastructure::TelecomNetwork => {
            (SafetyImpact::Moderate, 1_000_000, 24, 100_000_000)
        }
        CriticalInfrastructure::FinancialSystem => (SafetyImpact::Minor, 5_000_000, 8, 500_000_000),
        CriticalInfrastructure::HealthcareSystem => (SafetyImpact::Severe, 50_000, 168, 5_000_000),
        CriticalInfrastructure::ManufacturingPlant => {
            (SafetyImpact::Moderate, 1_000, 72, 5_000_000)
        }
    };

    ImpactAssessment {
        safety_impact: safety,
        estimated_affected_population: population,
        recovery_time_hours: recovery_hours,
        economic_cost_usd: cost,
        narrative: format!(
            "Attack via {:?} on {:?} infrastructure could disrupt services for {} people with estimated recovery of {} hours.",
            protocol, target, population, recovery_hours
        ),
    }
}
