//! Attack infrastructure management for nation-state operations.

/// Protocol used by a C2 server.
#[derive(Debug, Clone, PartialEq)]
pub enum C2Protocol {
    /// HTTPS-based C2 traffic.
    Https,
    /// DNS tunnelling C2.
    Dns,
    /// Custom binary protocol.
    Custom,
    /// WebSocket-based C2.
    WebSocket,
    /// ICMP-based covert channel.
    Icmp,
}

/// A command-and-control server node.
#[derive(Debug, Clone)]
pub struct C2Node {
    /// IP address or hostname of the C2 server.
    pub address: String,
    /// Communication protocol.
    pub protocol: C2Protocol,
    /// Whether traffic is encrypted.
    pub encrypted: bool,
    /// Beacon interval in seconds.
    pub beacon_interval: u64,
}

/// Type of HTTP redirector.
#[derive(Debug, Clone, PartialEq)]
pub enum RedirectType {
    /// Apache mod_rewrite redirector.
    Apache,
    /// Nginx proxy pass redirector.
    Nginx,
    /// Amazon CloudFront CDN.
    CloudFront,
    /// Azure CDN.
    AzureCDN,
    /// Fastly CDN.
    FastlyCDN,
}

/// A traffic redirector node that proxies C2 communications.
#[derive(Debug, Clone)]
pub struct Redirector {
    /// IP address or hostname of the redirector.
    pub address: String,
    /// Type of redirection mechanism.
    pub redirect_type: RedirectType,
}

/// A domain used for C2 or staging operations.
#[derive(Debug, Clone)]
pub struct Domain {
    /// The registered domain name.
    pub name: String,
    /// Whether the domain is currently active.
    pub active: bool,
    /// Age of the domain in days (older = more trusted).
    pub age_days: u64,
}

/// A VPN hop in an anonymisation chain.
#[derive(Debug, Clone)]
pub struct VpnHop {
    /// IP address of the VPN exit node.
    pub address: String,
    /// Country or region of the exit node.
    pub region: String,
    /// VPN provider name.
    pub provider: String,
}

/// Domain-fronting configuration using a CDN provider.
#[derive(Debug, Clone)]
pub struct DomainFrontConfig {
    /// The CDN-fronted domain presented in SNI.
    pub front_domain: String,
    /// The actual backend domain receiving traffic.
    pub real_domain: String,
    /// CDN provider facilitating the fronting.
    pub cdn_provider: String,
}

/// Health status of a single infrastructure component.
#[derive(Debug, Clone, PartialEq)]
pub enum ComponentHealth {
    /// Component is operational.
    Healthy,
    /// Component is experiencing issues.
    Degraded,
    /// Component is unreachable.
    Down,
    /// Component health is unknown.
    Unknown,
}

/// Overall health report for attack infrastructure.
#[derive(Debug, Clone)]
pub struct InfrastructureHealth {
    /// Health of each C2 server (address → health).
    pub c2_health: Vec<(String, ComponentHealth)>,
    /// Health of each redirector (address → health).
    pub redirector_health: Vec<(String, ComponentHealth)>,
    /// Number of active/healthy domains.
    pub active_domains: usize,
    /// Overall infrastructure readiness score (0.0–1.0).
    pub readiness_score: f64,
}

/// Full attack infrastructure for a nation-state operation.
#[derive(Debug, Clone)]
pub struct AttackInfrastructure {
    /// Unique identifier for this infrastructure set.
    pub id: String,
    /// C2 server nodes.
    pub c2_servers: Vec<C2Node>,
    /// Traffic redirectors.
    pub redirectors: Vec<Redirector>,
    /// Operational domains.
    pub domains: Vec<Domain>,
    /// VPN anonymisation chain.
    pub vpn_chain: Vec<VpnHop>,
    /// Domain-fronting configurations.
    pub domain_fronting_configs: Vec<DomainFrontConfig>,
}

impl AttackInfrastructure {
    /// Create a new empty infrastructure set.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            c2_servers: Vec::new(),
            redirectors: Vec::new(),
            domains: Vec::new(),
            vpn_chain: Vec::new(),
            domain_fronting_configs: Vec::new(),
        }
    }

    /// Deploy the infrastructure (simulation — records that deployment occurred).
    pub fn deploy_infrastructure(&mut self) {
        // Simulation: mark all domains as active.
        for domain in &mut self.domains {
            domain.active = true;
        }
    }

    /// Rotate to the next available C2 server, removing the current primary.
    ///
    /// Returns the new primary C2 address, or `None` if no servers remain.
    pub fn rotate_c2(&mut self) -> Option<String> {
        if self.c2_servers.len() > 1 {
            self.c2_servers.remove(0);
            self.c2_servers.first().map(|n| n.address.clone())
        } else {
            self.c2_servers.first().map(|n| n.address.clone())
        }
    }

    /// Burn all current infrastructure and reinitialise with fresh components.
    ///
    /// Clears all servers, redirectors, and domains. Operators must repopulate
    /// before the infrastructure is operational again.
    pub fn burn_and_rebuild(&mut self) {
        self.c2_servers.clear();
        self.redirectors.clear();
        self.domains.clear();
        self.domain_fronting_configs.clear();
    }

    /// Perform a health check across all infrastructure components.
    pub fn check_infrastructure_health(&self) -> InfrastructureHealth {
        let c2_health = self
            .c2_servers
            .iter()
            .map(|n| {
                let health = if n.beacon_interval > 0 {
                    ComponentHealth::Healthy
                } else {
                    ComponentHealth::Degraded
                };
                (n.address.clone(), health)
            })
            .collect();

        let redirector_health = self
            .redirectors
            .iter()
            .map(|r| (r.address.clone(), ComponentHealth::Healthy))
            .collect();

        let active_domains = self.domains.iter().filter(|d| d.active).count();
        let total = self.c2_servers.len() + self.redirectors.len() + active_domains;
        let readiness_score = if total == 0 {
            0.0
        } else {
            (self.c2_servers.len() as f64 + self.redirectors.len() as f64 / 2.0)
                / (total as f64).max(1.0)
        };

        InfrastructureHealth {
            c2_health,
            redirector_health,
            active_domains,
            readiness_score: readiness_score.min(1.0),
        }
    }

    /// Generate a textual map of the infrastructure topology.
    pub fn generate_infrastructure_map(&self) -> String {
        let mut map = format!("=== Infrastructure Map: {} ===\n", self.id);

        map.push_str(&format!("C2 Servers ({}):\n", self.c2_servers.len()));
        for node in &self.c2_servers {
            map.push_str(&format!(
                "  {} ({:?}) — encrypted: {}, beacon: {}s\n",
                node.address, node.protocol, node.encrypted, node.beacon_interval
            ));
        }

        map.push_str(&format!("Redirectors ({}):\n", self.redirectors.len()));
        for redirector in &self.redirectors {
            map.push_str(&format!(
                "  {} ({:?})\n",
                redirector.address, redirector.redirect_type
            ));
        }

        map.push_str(&format!("VPN Chain ({} hops):\n", self.vpn_chain.len()));
        for (i, hop) in self.vpn_chain.iter().enumerate() {
            map.push_str(&format!(
                "  Hop {}: {} ({})\n",
                i + 1,
                hop.region,
                hop.provider
            ));
        }

        map.push_str(&format!(
            "Domain Fronting Configs ({}):\n",
            self.domain_fronting_configs.len()
        ));
        for config in &self.domain_fronting_configs {
            map.push_str(&format!(
                "  {} → {} via {}\n",
                config.front_domain, config.real_domain, config.cdn_provider
            ));
        }

        map
    }
}
