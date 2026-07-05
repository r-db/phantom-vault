//! Network egress filtering for sandboxed processes.
//!
//! Provides per-process network filtering to prevent secret
//! exfiltration through network connections.

use crate::SandboxResult;
use std::net::IpAddr;
use tracing::{debug, warn};

/// Network filter configuration.
#[derive(Debug, Clone)]
pub struct NetworkFilter {
    /// Default policy.
    pub default_policy: NetworkPolicy,
    /// Allowed destinations.
    pub allow_rules: Vec<NetworkRule>,
    /// Blocked destinations.
    pub deny_rules: Vec<NetworkRule>,
}

/// Default network policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkPolicy {
    /// Allow all by default.
    Allow,
    /// Deny all by default.
    Deny,
}

/// A network filtering rule.
#[derive(Debug, Clone)]
pub struct NetworkRule {
    /// Rule name for logging.
    pub name: String,
    /// Destination match.
    pub destination: DestinationMatch,
    /// Ports to match.
    pub ports: PortMatch,
    /// Protocol to match.
    pub protocol: ProtocolMatch,
}

/// Destination matching.
#[derive(Debug, Clone)]
pub enum DestinationMatch {
    /// Any destination.
    Any,
    /// Specific IP address.
    Ip(IpAddr),
    /// CIDR range.
    Cidr { addr: IpAddr, prefix: u8 },
    /// Hostname (resolved at filter creation).
    Hostname(String),
    /// Localhost only.
    Localhost,
}

/// Port matching.
#[derive(Debug, Clone)]
pub enum PortMatch {
    /// Any port.
    Any,
    /// Specific port.
    Port(u16),
    /// Port range.
    Range { start: u16, end: u16 },
    /// List of ports.
    List(Vec<u16>),
}

/// Protocol matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolMatch {
    /// Any protocol.
    Any,
    /// TCP only.
    Tcp,
    /// UDP only.
    Udp,
}

impl NetworkFilter {
    /// Create a filter that denies all network access.
    pub fn deny_all() -> Self {
        Self {
            default_policy: NetworkPolicy::Deny,
            allow_rules: Vec::new(),
            deny_rules: Vec::new(),
        }
    }

    /// Create a filter that allows all network access.
    pub fn allow_all() -> Self {
        Self {
            default_policy: NetworkPolicy::Allow,
            allow_rules: Vec::new(),
            deny_rules: Vec::new(),
        }
    }

    /// Create a filter that only allows localhost.
    pub fn localhost_only() -> Self {
        Self {
            default_policy: NetworkPolicy::Deny,
            allow_rules: vec![NetworkRule {
                name: "localhost".to_string(),
                destination: DestinationMatch::Localhost,
                ports: PortMatch::Any,
                protocol: ProtocolMatch::Any,
            }],
            deny_rules: Vec::new(),
        }
    }

    /// Add an allow rule.
    pub fn allow(&mut self, rule: NetworkRule) -> &mut Self {
        self.allow_rules.push(rule);
        self
    }

    /// Add a deny rule.
    pub fn deny(&mut self, rule: NetworkRule) -> &mut Self {
        self.deny_rules.push(rule);
        self
    }

    /// Check if a connection is allowed.
    pub fn check(&self, dest: IpAddr, port: u16, protocol: ProtocolMatch) -> bool {
        // Check deny rules first (explicit deny takes precedence)
        for rule in &self.deny_rules {
            if self.rule_matches(rule, dest, port, &protocol) {
                debug!(
                    "Connection to {}:{} denied by rule '{}'",
                    dest, port, rule.name
                );
                return false;
            }
        }

        // Check allow rules
        for rule in &self.allow_rules {
            if self.rule_matches(rule, dest, port, &protocol) {
                debug!(
                    "Connection to {}:{} allowed by rule '{}'",
                    dest, port, rule.name
                );
                return true;
            }
        }

        // Fall back to default policy
        match self.default_policy {
            NetworkPolicy::Allow => true,
            NetworkPolicy::Deny => false,
        }
    }

    /// Check if a rule matches the given parameters.
    fn rule_matches(
        &self,
        rule: &NetworkRule,
        dest: IpAddr,
        port: u16,
        protocol: &ProtocolMatch,
    ) -> bool {
        // Check protocol
        if !self.protocol_matches(&rule.protocol, protocol) {
            return false;
        }

        // Check port
        if !self.port_matches(&rule.ports, port) {
            return false;
        }

        // Check destination
        self.destination_matches(&rule.destination, dest)
    }

    /// Check if protocol matches.
    fn protocol_matches(&self, rule_protocol: &ProtocolMatch, actual: &ProtocolMatch) -> bool {
        match rule_protocol {
            ProtocolMatch::Any => true,
            _ => rule_protocol == actual,
        }
    }

    /// Check if port matches.
    fn port_matches(&self, rule_ports: &PortMatch, port: u16) -> bool {
        match rule_ports {
            PortMatch::Any => true,
            PortMatch::Port(p) => *p == port,
            PortMatch::Range { start, end } => port >= *start && port <= *end,
            PortMatch::List(ports) => ports.contains(&port),
        }
    }

    /// Check if destination matches.
    fn destination_matches(&self, rule_dest: &DestinationMatch, dest: IpAddr) -> bool {
        match rule_dest {
            DestinationMatch::Any => true,
            DestinationMatch::Ip(ip) => *ip == dest,
            DestinationMatch::Localhost => dest.is_loopback(),
            DestinationMatch::Cidr { addr, prefix } => {
                self.cidr_matches(*addr, *prefix, dest)
            }
            DestinationMatch::Hostname(_host) => {
                // Hostname matching requires DNS resolution
                // For now, we'll return false and log a warning
                warn!("Hostname matching not implemented, denying");
                false
            }
        }
    }

    /// Check if an IP matches a CIDR range.
    fn cidr_matches(&self, network: IpAddr, prefix: u8, addr: IpAddr) -> bool {
        match (network, addr) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                if prefix > 32 {
                    return false;
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    !0u32 << (32 - prefix)
                };
                let net_bits = u32::from(net) & mask;
                let ip_bits = u32::from(ip) & mask;
                net_bits == ip_bits
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                if prefix > 128 {
                    return false;
                }
                let net_bits = u128::from(net);
                let ip_bits = u128::from(ip);
                let mask = if prefix == 0 {
                    0
                } else {
                    !0u128 << (128 - prefix)
                };
                (net_bits & mask) == (ip_bits & mask)
            }
            _ => false, // IPv4 and IPv6 don't match
        }
    }

    /// Apply the filter to a process.
    ///
    /// Note: This is a no-op on most platforms without root privileges.
    /// Network filtering requires either:
    /// - macOS: sandbox-exec profile or pf rules (requires root)
    /// - Linux: network namespaces (requires CAP_NET_ADMIN) or seccomp
    pub fn apply(&self, _pid: u32) -> SandboxResult<()> {
        warn!(
            "Network filtering not fully implemented. \
             Connections will be allowed but logged for audit."
        );
        Ok(())
    }

    /// Remove the filter from a process.
    pub fn remove(&self, _pid: u32) -> SandboxResult<()> {
        // No-op for now
        Ok(())
    }

    /// Create a builder for constructing filters.
    pub fn builder() -> NetworkFilterBuilder {
        NetworkFilterBuilder::new()
    }
}

/// Builder for constructing network filters.
pub struct NetworkFilterBuilder {
    filter: NetworkFilter,
}

impl NetworkFilterBuilder {
    /// Create a new builder with deny-all default.
    pub fn new() -> Self {
        Self {
            filter: NetworkFilter::deny_all(),
        }
    }

    /// Set the default policy.
    pub fn default_policy(mut self, policy: NetworkPolicy) -> Self {
        self.filter.default_policy = policy;
        self
    }

    /// Allow localhost connections.
    pub fn allow_localhost(mut self) -> Self {
        self.filter.allow_rules.push(NetworkRule {
            name: "localhost".to_string(),
            destination: DestinationMatch::Localhost,
            ports: PortMatch::Any,
            protocol: ProtocolMatch::Any,
        });
        self
    }

    /// Allow a specific host on specific ports.
    pub fn allow_host(mut self, name: &str, host: IpAddr, ports: PortMatch) -> Self {
        self.filter.allow_rules.push(NetworkRule {
            name: name.to_string(),
            destination: DestinationMatch::Ip(host),
            ports,
            protocol: ProtocolMatch::Any,
        });
        self
    }

    /// Allow a CIDR range.
    pub fn allow_cidr(mut self, name: &str, network: IpAddr, prefix: u8) -> Self {
        self.filter.allow_rules.push(NetworkRule {
            name: name.to_string(),
            destination: DestinationMatch::Cidr {
                addr: network,
                prefix,
            },
            ports: PortMatch::Any,
            protocol: ProtocolMatch::Any,
        });
        self
    }

    /// Deny a specific host.
    pub fn deny_host(mut self, name: &str, host: IpAddr) -> Self {
        self.filter.deny_rules.push(NetworkRule {
            name: name.to_string(),
            destination: DestinationMatch::Ip(host),
            ports: PortMatch::Any,
            protocol: ProtocolMatch::Any,
        });
        self
    }

    /// Build the filter.
    pub fn build(self) -> NetworkFilter {
        self.filter
    }
}

impl Default for NetworkFilterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_deny_all() {
        let filter = NetworkFilter::deny_all();
        assert!(!filter.check(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            443,
            ProtocolMatch::Tcp
        ));
    }

    #[test]
    fn test_allow_all() {
        let filter = NetworkFilter::allow_all();
        assert!(filter.check(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            443,
            ProtocolMatch::Tcp
        ));
    }

    #[test]
    fn test_localhost_only() {
        let filter = NetworkFilter::localhost_only();

        // Localhost should be allowed
        assert!(filter.check(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            8080,
            ProtocolMatch::Tcp
        ));

        // External should be denied
        assert!(!filter.check(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            443,
            ProtocolMatch::Tcp
        ));
    }

    #[test]
    fn test_port_matching() {
        let mut filter = NetworkFilter::deny_all();
        filter.allow(NetworkRule {
            name: "https".to_string(),
            destination: DestinationMatch::Any,
            ports: PortMatch::Port(443),
            protocol: ProtocolMatch::Tcp,
        });

        assert!(filter.check(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            443,
            ProtocolMatch::Tcp
        ));
        assert!(!filter.check(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            80,
            ProtocolMatch::Tcp
        ));
    }

    #[test]
    fn test_port_range() {
        let mut filter = NetworkFilter::deny_all();
        filter.allow(NetworkRule {
            name: "high-ports".to_string(),
            destination: DestinationMatch::Any,
            ports: PortMatch::Range {
                start: 1024,
                end: 65535,
            },
            protocol: ProtocolMatch::Any,
        });

        assert!(filter.check(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            8080,
            ProtocolMatch::Tcp
        ));
        assert!(!filter.check(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            80,
            ProtocolMatch::Tcp
        ));
    }

    #[test]
    fn test_cidr_matching_v4() {
        let mut filter = NetworkFilter::deny_all();
        filter.allow(NetworkRule {
            name: "private".to_string(),
            destination: DestinationMatch::Cidr {
                addr: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
                prefix: 16,
            },
            ports: PortMatch::Any,
            protocol: ProtocolMatch::Any,
        });

        assert!(filter.check(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            80,
            ProtocolMatch::Tcp
        ));
        assert!(!filter.check(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            80,
            ProtocolMatch::Tcp
        ));
    }

    #[test]
    fn test_cidr_matching_v6() {
        let mut filter = NetworkFilter::deny_all();
        filter.allow(NetworkRule {
            name: "ipv6-local".to_string(),
            destination: DestinationMatch::Cidr {
                addr: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)),
                prefix: 10,
            },
            ports: PortMatch::Any,
            protocol: ProtocolMatch::Any,
        });

        assert!(filter.check(
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            80,
            ProtocolMatch::Tcp
        ));
    }

    #[test]
    fn test_deny_takes_precedence() {
        let mut filter = NetworkFilter::allow_all();
        filter.deny(NetworkRule {
            name: "block-evil".to_string(),
            destination: DestinationMatch::Ip(IpAddr::V4(Ipv4Addr::new(6, 6, 6, 6))),
            ports: PortMatch::Any,
            protocol: ProtocolMatch::Any,
        });

        assert!(!filter.check(
            IpAddr::V4(Ipv4Addr::new(6, 6, 6, 6)),
            80,
            ProtocolMatch::Tcp
        ));
        assert!(filter.check(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            80,
            ProtocolMatch::Tcp
        ));
    }

    #[test]
    fn test_builder() {
        let filter = NetworkFilter::builder()
            .allow_localhost()
            .allow_host(
                "dns",
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                PortMatch::Port(53),
            )
            .build();

        assert!(filter.check(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            8080,
            ProtocolMatch::Tcp
        ));
        assert!(filter.check(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            ProtocolMatch::Udp
        ));
        assert!(!filter.check(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            443,
            ProtocolMatch::Tcp
        ));
    }
}
