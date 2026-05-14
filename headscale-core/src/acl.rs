//! Access Control List (ACL) system for mesh networking.
//!
//! This module implements a Tailscale-style ACL policy system that controls:
//! - L3 access: Which nodes can communicate with which other nodes
//! - Route distribution: Which routes are shared with which nodes
//! - Service access: Which services a node can access (for L7 gateway integration)
//!
//! # Policy Format
//!
//! Policies use a JSON format similar to Tailscale's ACL policy:
//!
//! ```json
//! {
//!   "hosts": {
//!     "gateway": "100.64.0.1",
//!     "inference-cluster": ["100.64.0.10", "100.64.0.11"]
//!   },
//!   "groups": {
//!     "admins": ["user:alice", "user:bob"],
//!     "gpu-providers": ["tag:gpu"]
//!   },
//!   "acls": [
//!     {"action": "accept", "src": ["*"], "dst": ["*:*"]},
//!   ],
//!   "tagOwners": {
//!     "tag:gpu": ["group:admins"]
//!   }
//! }
//! ```
//!
//! # Default Policy
//!
//! By default, all traffic within the fleet is allowed (allow-fleet).
//! External rentals require explicit ACL rules.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// ACL policy errors.
#[derive(Debug, Error)]
pub enum AclError {
    #[error("Invalid policy: {0}")]
    InvalidPolicy(String),

    #[error("Invalid host definition: {0}")]
    InvalidHost(String),

    #[error("Invalid group: {0}")]
    InvalidGroup(String),

    #[error("Invalid ACL rule: {0}")]
    InvalidRule(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Unknown reference: {0}")]
    UnknownReference(String),
}

/// ACL action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Accept,
    Deny,
}

impl Default for Action {
    fn default() -> Self {
        Action::Deny
    }
}

/// A single ACL rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclRule {
    /// Action to take if rule matches.
    pub action: Action,
    /// Source specifications (users, groups, tags, IPs, "*").
    pub src: Vec<String>,
    /// Destination specifications ("host:port" or "host:*").
    pub dst: Vec<String>,
    /// Optional protocol filter (tcp, udp, icmp, or "*").
    #[serde(default)]
    pub proto: Option<String>,
}

/// Tag ownership definition.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TagOwners {
    /// Map of tag -> list of owners who can assign that tag.
    #[serde(flatten)]
    pub owners: HashMap<String, Vec<String>>,
}

/// Complete ACL policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclPolicy {
    /// Named hosts or host groups.
    #[serde(default)]
    pub hosts: HashMap<String, HostSpec>,

    /// Named groups of users/nodes.
    #[serde(default)]
    pub groups: HashMap<String, Vec<String>>,

    /// ACL rules evaluated in order.
    #[serde(default)]
    pub acls: Vec<AclRule>,

    /// Tag ownership definitions.
    #[serde(default, rename = "tagOwners")]
    pub tag_owners: HashMap<String, Vec<String>>,

    /// Auto-approvers for specific actions.
    #[serde(default, rename = "autoApprovers")]
    pub auto_approvers: AutoApprovers,

    /// SSH access rules (optional).
    #[serde(default)]
    pub ssh: Vec<SshRule>,
}

/// Host specification - can be a single IP or list of IPs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HostSpec {
    Single(String),
    Multiple(Vec<String>),
}

impl HostSpec {
    /// Get all IPs from this host spec.
    pub fn ips(&self) -> Vec<IpAddr> {
        match self {
            HostSpec::Single(s) => s.parse().ok().into_iter().collect(),
            HostSpec::Multiple(v) => v.iter().filter_map(|s| s.parse().ok()).collect(),
        }
    }
}

/// Auto-approvers for routes and exit nodes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AutoApprovers {
    /// Routes that are auto-approved.
    #[serde(default)]
    pub routes: HashMap<String, Vec<String>>,
    /// Exit node providers that are auto-approved.
    #[serde(default, rename = "exitNode")]
    pub exit_node: Vec<String>,
}

/// SSH access rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshRule {
    pub action: Action,
    pub src: Vec<String>,
    pub dst: Vec<String>,
    #[serde(default)]
    pub users: Vec<String>,
}

impl Default for AclPolicy {
    /// Default policy: allow all traffic within fleet.
    fn default() -> Self {
        Self {
            hosts: HashMap::new(),
            groups: HashMap::new(),
            acls: vec![AclRule {
                action: Action::Accept,
                src: vec!["*".to_string()],
                dst: vec!["*:*".to_string()],
                proto: None,
            }],
            tag_owners: HashMap::new(),
            auto_approvers: AutoApprovers::default(),
            ssh: Vec::new(),
        }
    }
}

impl AclPolicy {
    /// Create an empty deny-all policy.
    pub fn deny_all() -> Self {
        Self {
            hosts: HashMap::new(),
            groups: HashMap::new(),
            acls: Vec::new(), // No rules = deny all
            tag_owners: HashMap::new(),
            auto_approvers: AutoApprovers::default(),
            ssh: Vec::new(),
        }
    }

    /// Parse policy from JSON string.
    pub fn from_json(json: &str) -> Result<Self, AclError> {
        serde_json::from_str(json).map_err(|e| AclError::ParseError(e.to_string()))
    }

    /// Serialize policy to JSON string.
    pub fn to_json(&self) -> Result<String, AclError> {
        serde_json::to_string_pretty(self).map_err(|e| AclError::ParseError(e.to_string()))
    }

    /// Validate the policy for consistency.
    pub fn validate(&self) -> Result<(), AclError> {
        // Validate all group references exist
        for rule in &self.acls {
            for src in &rule.src {
                self.validate_reference(src)?;
            }
            for dst in &rule.dst {
                // dst is "host:port", extract host part
                let host = dst.split(':').next().unwrap_or(dst);
                if host != "*" {
                    self.validate_reference(host)?;
                }
            }
        }

        // Validate tag owners reference valid groups
        for (tag, owners) in &self.tag_owners {
            if !tag.starts_with("tag:") {
                return Err(AclError::InvalidPolicy(format!(
                    "Tag owner key must start with 'tag:': {}",
                    tag
                )));
            }
            for owner in owners {
                self.validate_reference(owner)?;
            }
        }

        Ok(())
    }

    /// Validate a reference (user, group, tag, host, or wildcard).
    fn validate_reference(&self, reference: &str) -> Result<(), AclError> {
        if reference == "*" || reference == "autogroup:internet" {
            return Ok(());
        }

        if let Some(group_name) = reference.strip_prefix("group:") {
            if !self.groups.contains_key(group_name) {
                return Err(AclError::UnknownReference(format!(
                    "Unknown group: {}",
                    group_name
                )));
            }
        } else if reference.starts_with("tag:") {
            // Tags are always valid (they're assigned at runtime)
            return Ok(());
        } else if reference.starts_with("user:") {
            // Users are always valid
            return Ok(());
        } else if self.hosts.contains_key(reference) {
            // Named host
            return Ok(());
        } else if reference.parse::<IpAddr>().is_ok() {
            // Raw IP
            return Ok(());
        } else if IpNet::from_str(reference).is_ok() {
            // CIDR
            return Ok(());
        }

        // Check if it's a valid IP or CIDR (allow raw IPs in rules)
        if reference.contains('/') || reference.parse::<IpAddr>().is_ok() {
            return Ok(());
        }

        Ok(()) // Be permissive for now - unknown refs might be resolved later
    }
}

/// Evaluation context for ACL decisions.
#[derive(Debug)]
pub struct AclContext {
    /// Source identifier (user, tag, or IP).
    pub src: String,
    /// Source IP address.
    pub src_ip: Option<IpAddr>,
    /// Source tags.
    pub src_tags: HashSet<String>,
    /// Source groups (resolved).
    pub src_groups: HashSet<String>,
}

impl AclContext {
    /// Create a context from a node ID and IP.
    pub fn from_node(node_id: &str, ip: IpAddr) -> Self {
        Self {
            src: format!("user:{}", node_id),
            src_ip: Some(ip),
            src_tags: HashSet::new(),
            src_groups: HashSet::new(),
        }
    }

    /// Add a tag to the context.
    pub fn with_tag(mut self, tag: &str) -> Self {
        self.src_tags.insert(format!("tag:{}", tag));
        self
    }

    /// Add multiple tags.
    pub fn with_tags(mut self, tags: impl IntoIterator<Item = String>) -> Self {
        for tag in tags {
            if tag.starts_with("tag:") {
                self.src_tags.insert(tag);
            } else {
                self.src_tags.insert(format!("tag:{}", tag));
            }
        }
        self
    }

    /// Add a group membership.
    pub fn with_group(mut self, group: &str) -> Self {
        self.src_groups.insert(format!("group:{}", group));
        self
    }
}

/// Destination specification for evaluation.
#[derive(Debug)]
pub struct AclDestination {
    /// Destination identifier (host name or IP).
    pub dst: String,
    /// Destination IP address.
    pub dst_ip: Option<IpAddr>,
    /// Destination port (None for any).
    pub port: Option<u16>,
    /// Protocol (None for any).
    pub proto: Option<String>,
}

impl AclDestination {
    /// Create from IP and port.
    pub fn new(ip: IpAddr, port: Option<u16>) -> Self {
        Self {
            dst: ip.to_string(),
            dst_ip: Some(ip),
            port,
            proto: None,
        }
    }

    /// Create from IP only.
    pub fn ip_only(ip: IpAddr) -> Self {
        Self {
            dst: ip.to_string(),
            dst_ip: Some(ip),
            port: None,
            proto: None,
        }
    }
}

/// ACL evaluator.
pub struct AclEvaluator {
    policy: AclPolicy,
}

impl AclEvaluator {
    /// Create a new evaluator with the given policy.
    pub fn new(policy: AclPolicy) -> Self {
        Self { policy }
    }

    /// Create with default allow-fleet policy.
    pub fn allow_fleet() -> Self {
        Self::new(AclPolicy::default())
    }

    /// Create with deny-all policy.
    pub fn deny_all() -> Self {
        Self::new(AclPolicy::deny_all())
    }

    /// Get the underlying policy.
    pub fn policy(&self) -> &AclPolicy {
        &self.policy
    }

    /// Update the policy (for hot reload).
    pub fn update_policy(&mut self, policy: AclPolicy) {
        self.policy = policy;
    }

    /// Evaluate whether traffic is allowed.
    pub fn evaluate(&self, ctx: &AclContext, dst: &AclDestination) -> Action {
        // Rules are evaluated in order; first match wins
        for rule in &self.policy.acls {
            if self.matches_rule(rule, ctx, dst) {
                return rule.action;
            }
        }

        // No rule matched - default deny
        Action::Deny
    }

    /// Check if context can reach any port on destination IP.
    pub fn can_reach(&self, ctx: &AclContext, dst_ip: IpAddr) -> bool {
        let dst = AclDestination::ip_only(dst_ip);
        self.evaluate(ctx, &dst) == Action::Accept
    }

    /// Check if context can reach specific port on destination IP.
    pub fn can_reach_port(&self, ctx: &AclContext, dst_ip: IpAddr, port: u16) -> bool {
        let dst = AclDestination::new(dst_ip, Some(port));
        self.evaluate(ctx, &dst) == Action::Accept
    }

    /// Check if a rule matches the given context and destination.
    fn matches_rule(&self, rule: &AclRule, ctx: &AclContext, dst: &AclDestination) -> bool {
        // Check source matches
        let src_matches = rule.src.iter().any(|s| self.matches_source(s, ctx));
        if !src_matches {
            return false;
        }

        // Check destination matches
        let dst_matches = rule.dst.iter().any(|d| self.matches_destination(d, dst));
        if !dst_matches {
            return false;
        }

        // Check protocol if specified
        if let Some(ref rule_proto) = rule.proto {
            if rule_proto != "*" {
                if let Some(ref dst_proto) = dst.proto {
                    if rule_proto != dst_proto {
                        return false;
                    }
                }
            }
        }

        true
    }

    /// Check if source specification matches context.
    fn matches_source(&self, spec: &str, ctx: &AclContext) -> bool {
        // Wildcard matches everything
        if spec == "*" {
            return true;
        }

        // Check direct user match
        if spec == ctx.src {
            return true;
        }

        // Check tag match
        if spec.starts_with("tag:") && ctx.src_tags.contains(spec) {
            return true;
        }

        // Check group match
        if let Some(group_name) = spec.strip_prefix("group:") {
            if let Some(members) = self.policy.groups.get(group_name) {
                // Check if context is a member of this group
                if members.contains(&ctx.src) {
                    return true;
                }
                // Check if any of context's tags are in the group
                for tag in &ctx.src_tags {
                    if members.contains(tag) {
                        return true;
                    }
                }
            }
            // Also check resolved groups
            if ctx.src_groups.contains(&format!("group:{}", group_name)) {
                return true;
            }
        }

        // Check IP match
        if let Some(src_ip) = ctx.src_ip {
            if let Ok(ip) = spec.parse::<IpAddr>() {
                if ip == src_ip {
                    return true;
                }
            }
            if let Ok(cidr) = IpNet::from_str(spec) {
                if cidr.contains(&src_ip) {
                    return true;
                }
            }
        }

        // Check named host match
        if let Some(host_spec) = self.policy.hosts.get(spec) {
            if let Some(src_ip) = ctx.src_ip {
                if host_spec.ips().contains(&src_ip) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if destination specification matches destination.
    fn matches_destination(&self, spec: &str, dst: &AclDestination) -> bool {
        // Parse "host:port" format
        let (host_part, port_part) = if let Some(idx) = spec.rfind(':') {
            (&spec[..idx], &spec[idx + 1..])
        } else {
            (spec, "*")
        };

        // Check port match
        if port_part != "*" {
            if let Ok(rule_port) = port_part.parse::<u16>() {
                match dst.port {
                    Some(p) if p != rule_port => return false,
                    None => {} // No port in dst means any port
                    _ => {}
                }
            }
        }

        // Check host match
        if host_part == "*" {
            return true;
        }

        // Special group: internet (all non-RFC1918)
        if host_part == "autogroup:internet" {
            if let Some(ip) = dst.dst_ip {
                return !is_private_ip(ip);
            }
            return false;
        }

        // Check direct IP match
        if let Some(dst_ip) = dst.dst_ip {
            if let Ok(ip) = host_part.parse::<IpAddr>() {
                if ip == dst_ip {
                    return true;
                }
            }
            if let Ok(cidr) = IpNet::from_str(host_part) {
                if cidr.contains(&dst_ip) {
                    return true;
                }
            }
        }

        // Check named host match
        if let Some(host_spec) = self.policy.hosts.get(host_part) {
            if let Some(dst_ip) = dst.dst_ip {
                if host_spec.ips().contains(&dst_ip) {
                    return true;
                }
            }
        }

        // Check string match on dst identifier
        if host_part == dst.dst {
            return true;
        }

        false
    }

    /// Check if a route should be distributed to a node.
    pub fn should_distribute_route(&self, route: IpNet, to_node: &AclContext) -> bool {
        // Check auto-approvers
        let route_str = route.to_string();
        for (pattern, approvers) in &self.policy.auto_approvers.routes {
            if pattern == &route_str || pattern == "*" {
                // Check if this node is an approver
                for approver in approvers {
                    if self.matches_source(approver, to_node) {
                        return true;
                    }
                }
            }
        }

        // Default: distribute routes to all fleet members
        // (actual filtering happens at packet level)
        true
    }

    /// Check if a node can be an exit node.
    pub fn can_be_exit_node(&self, node: &AclContext) -> bool {
        for approver in &self.policy.auto_approvers.exit_node {
            if self.matches_source(approver, node) {
                return true;
            }
        }
        false
    }
}

/// Check if an IP is in RFC1918 private range.
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            octets[0] == 10 ||
            // 172.16.0.0/12
            (octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31)) ||
            // 192.168.0.0/16
            (octets[0] == 192 && octets[1] == 168) ||
            // 100.64.0.0/10 (CGNAT, used for mesh)
            (octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127)) ||
            // 127.0.0.0/8 (loopback)
            octets[0] == 127 ||
            // 169.254.0.0/16 (link-local)
            (octets[0] == 169 && octets[1] == 254)
        }
        IpAddr::V6(v6) => {
            // Link-local
            v6.segments()[0] == 0xfe80 ||
            // Unique local (fc00::/7)
            (v6.segments()[0] & 0xfe00) == 0xfc00 ||
            // Loopback
            v6.is_loopback()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> AclPolicy {
        AclPolicy {
            hosts: {
                let mut h = HashMap::new();
                h.insert("gateway".to_string(), HostSpec::Single("100.64.0.1".to_string()));
                h.insert("servers".to_string(), HostSpec::Multiple(vec![
                    "100.64.0.10".to_string(),
                    "100.64.0.11".to_string(),
                ]));
                h
            },
            groups: {
                let mut g = HashMap::new();
                g.insert("admins".to_string(), vec!["user:alice".to_string(), "user:bob".to_string()]);
                g.insert("gpu-nodes".to_string(), vec!["tag:gpu".to_string()]);
                g
            },
            acls: vec![
                AclRule {
                    action: Action::Accept,
                    src: vec!["group:admins".to_string()],
                    dst: vec!["*:*".to_string()],
                    proto: None,
                },
                AclRule {
                    action: Action::Accept,
                    src: vec!["*".to_string()],
                    dst: vec!["gateway:443".to_string()],
                    proto: None,
                },
                AclRule {
                    action: Action::Deny,
                    src: vec!["*".to_string()],
                    dst: vec!["servers:*".to_string()],
                    proto: None,
                },
            ],
            tag_owners: {
                let mut t = HashMap::new();
                t.insert("tag:gpu".to_string(), vec!["group:admins".to_string()]);
                t
            },
            auto_approvers: AutoApprovers::default(),
            ssh: Vec::new(),
        }
    }

    #[test]
    fn test_default_policy_allows_all() {
        let evaluator = AclEvaluator::allow_fleet();
        let ctx = AclContext::from_node("node1", "100.64.0.1".parse().unwrap());
        let dst = AclDestination::new("100.64.0.2".parse().unwrap(), Some(22));

        assert_eq!(evaluator.evaluate(&ctx, &dst), Action::Accept);
    }

    #[test]
    fn test_deny_all_policy() {
        let evaluator = AclEvaluator::deny_all();
        let ctx = AclContext::from_node("node1", "100.64.0.1".parse().unwrap());
        let dst = AclDestination::new("100.64.0.2".parse().unwrap(), Some(22));

        assert_eq!(evaluator.evaluate(&ctx, &dst), Action::Deny);
    }

    #[test]
    fn test_admin_can_access_all() {
        let evaluator = AclEvaluator::new(test_policy());
        let ctx = AclContext {
            src: "user:alice".to_string(),
            src_ip: Some("100.64.0.5".parse().unwrap()),
            src_tags: HashSet::new(),
            src_groups: HashSet::new(),
        };
        let dst = AclDestination::new("100.64.0.10".parse().unwrap(), Some(22));

        assert_eq!(evaluator.evaluate(&ctx, &dst), Action::Accept);
    }

    #[test]
    fn test_non_admin_blocked_from_servers() {
        let evaluator = AclEvaluator::new(test_policy());
        let ctx = AclContext {
            src: "user:eve".to_string(),
            src_ip: Some("100.64.0.99".parse().unwrap()),
            src_tags: HashSet::new(),
            src_groups: HashSet::new(),
        };
        let dst = AclDestination::new("100.64.0.10".parse().unwrap(), Some(22));

        // Eve is not an admin, and servers:* is denied
        assert_eq!(evaluator.evaluate(&ctx, &dst), Action::Deny);
    }

    #[test]
    fn test_anyone_can_access_gateway_443() {
        let evaluator = AclEvaluator::new(test_policy());
        let ctx = AclContext {
            src: "user:anyone".to_string(),
            src_ip: Some("100.64.0.99".parse().unwrap()),
            src_tags: HashSet::new(),
            src_groups: HashSet::new(),
        };
        let dst = AclDestination::new("100.64.0.1".parse().unwrap(), Some(443));

        assert_eq!(evaluator.evaluate(&ctx, &dst), Action::Accept);
    }

    #[test]
    fn test_tag_based_access() {
        let policy = AclPolicy {
            acls: vec![AclRule {
                action: Action::Accept,
                src: vec!["tag:trusted".to_string()],
                dst: vec!["*:*".to_string()],
                proto: None,
            }],
            ..Default::default()
        };
        let evaluator = AclEvaluator::new(policy);

        // Node with tag
        let ctx_with_tag = AclContext::from_node("node1", "100.64.0.1".parse().unwrap())
            .with_tag("trusted");
        let dst = AclDestination::new("100.64.0.2".parse().unwrap(), Some(22));
        assert_eq!(evaluator.evaluate(&ctx_with_tag, &dst), Action::Accept);

        // Node without tag
        let ctx_without_tag = AclContext::from_node("node2", "100.64.0.3".parse().unwrap());
        assert_eq!(evaluator.evaluate(&ctx_without_tag, &dst), Action::Deny);
    }

    #[test]
    fn test_cidr_matching() {
        let policy = AclPolicy {
            acls: vec![AclRule {
                action: Action::Accept,
                src: vec!["100.64.0.0/24".to_string()],
                dst: vec!["10.0.0.0/8:*".to_string()],
                proto: None,
            }],
            ..AclPolicy::deny_all()
        };
        let evaluator = AclEvaluator::new(policy);

        // Source in allowed range
        let ctx = AclContext::from_node("node1", "100.64.0.50".parse().unwrap());
        let dst = AclDestination::new("10.1.2.3".parse().unwrap(), Some(80));
        assert_eq!(evaluator.evaluate(&ctx, &dst), Action::Accept);

        // Source outside range
        let ctx2 = AclContext::from_node("node2", "100.64.1.50".parse().unwrap());
        assert_eq!(evaluator.evaluate(&ctx2, &dst), Action::Deny);

        // Destination outside range
        let dst2 = AclDestination::new("192.168.1.1".parse().unwrap(), Some(80));
        assert_eq!(evaluator.evaluate(&ctx, &dst2), Action::Deny);
    }

    #[test]
    fn test_is_private_ip() {
        assert!(is_private_ip("10.0.0.1".parse().unwrap()));
        assert!(is_private_ip("172.16.0.1".parse().unwrap()));
        assert!(is_private_ip("192.168.1.1".parse().unwrap()));
        assert!(is_private_ip("100.64.0.1".parse().unwrap()));
        assert!(is_private_ip("127.0.0.1".parse().unwrap()));

        assert!(!is_private_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn test_policy_validation() {
        let policy = test_policy();
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_policy_from_json() {
        let json = r#"{
            "hosts": {
                "gateway": "100.64.0.1"
            },
            "groups": {
                "admins": ["user:alice"]
            },
            "acls": [
                {"action": "accept", "src": ["group:admins"], "dst": ["*:*"]}
            ],
            "tagOwners": {
                "tag:test": ["group:admins"]
            }
        }"#;

        let policy = AclPolicy::from_json(json).unwrap();
        assert!(policy.hosts.contains_key("gateway"));
        assert!(policy.groups.contains_key("admins"));
        assert_eq!(policy.acls.len(), 1);
    }

    #[test]
    fn test_can_reach_convenience() {
        let evaluator = AclEvaluator::allow_fleet();
        let ctx = AclContext::from_node("node1", "100.64.0.1".parse().unwrap());

        assert!(evaluator.can_reach(&ctx, "100.64.0.2".parse().unwrap()));
        assert!(evaluator.can_reach_port(&ctx, "100.64.0.2".parse().unwrap(), 22));
    }

    #[test]
    fn test_internet_autogroup() {
        let policy = AclPolicy {
            acls: vec![AclRule {
                action: Action::Accept,
                src: vec!["*".to_string()],
                dst: vec!["autogroup:internet:*".to_string()],
                proto: None,
            }],
            ..AclPolicy::deny_all()
        };
        let evaluator = AclEvaluator::new(policy);
        let ctx = AclContext::from_node("node1", "100.64.0.1".parse().unwrap());

        // Public IP should be allowed
        let dst_public = AclDestination::new("8.8.8.8".parse().unwrap(), Some(53));
        assert_eq!(evaluator.evaluate(&ctx, &dst_public), Action::Accept);

        // Private IP should be denied
        let dst_private = AclDestination::new("10.0.0.1".parse().unwrap(), Some(80));
        assert_eq!(evaluator.evaluate(&ctx, &dst_private), Action::Deny);
    }
}

/// Property-based tests for ACL system.
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use std::net::Ipv4Addr;

    /// Strategy for generating arbitrary IPv4 addresses.
    fn arb_ipv4() -> impl Strategy<Value = Ipv4Addr> {
        (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
            .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d))
    }

    /// Strategy for generating valid node identifiers.
    fn arb_node_id() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9_-]{0,15}".prop_map(|s| format!("node:{}", s))
    }

    /// Strategy for generating valid tag names.
    fn arb_tag() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9_-]{0,10}".prop_map(|s| format!("tag:{}", s))
    }

    proptest! {
        /// Property: allow_fleet should accept all mesh traffic.
        #[test]
        fn prop_allow_fleet_accepts_all(
            src_ip in arb_ipv4(),
            dst_ip in arb_ipv4(),
            port in any::<u16>(),
            node_id in arb_node_id(),
        ) {
            let evaluator = AclEvaluator::allow_fleet();
            let ctx = AclContext::from_node(&node_id, IpAddr::V4(src_ip));
            let dst = AclDestination::new(IpAddr::V4(dst_ip), Some(port));

            prop_assert_eq!(evaluator.evaluate(&ctx, &dst), Action::Accept);
        }

        /// Property: deny_all should deny all traffic.
        #[test]
        fn prop_deny_all_denies_all(
            src_ip in arb_ipv4(),
            dst_ip in arb_ipv4(),
            port in any::<u16>(),
            node_id in arb_node_id(),
        ) {
            let evaluator = AclEvaluator::deny_all();
            let ctx = AclContext::from_node(&node_id, IpAddr::V4(src_ip));
            let dst = AclDestination::new(IpAddr::V4(dst_ip), Some(port));

            prop_assert_eq!(evaluator.evaluate(&ctx, &dst), Action::Deny);
        }

        /// Property: is_private_ip is consistent with CIDR ranges.
        #[test]
        fn prop_private_ip_consistency(ip in arb_ipv4()) {
            let addr = IpAddr::V4(ip);
            let octets = ip.octets();
            let is_priv = is_private_ip(addr);

            // Check known private ranges
            let expected_private =
                octets[0] == 10 ||
                (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
                (octets[0] == 192 && octets[1] == 168) ||
                (octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127) ||
                octets[0] == 127 ||
                (octets[0] == 169 && octets[1] == 254);

            prop_assert_eq!(is_priv, expected_private, "IP {} private check mismatch", ip);
        }

        /// Property: Wildcard source matches everything.
        #[test]
        fn prop_wildcard_src_matches_all(
            src_ip in arb_ipv4(),
            dst_ip in arb_ipv4(),
            port in any::<u16>(),
            node_id in arb_node_id(),
            tags in proptest::collection::vec(arb_tag(), 0..5),
        ) {
            let policy = AclPolicy {
                acls: vec![AclRule {
                    action: Action::Accept,
                    src: vec!["*".to_string()],
                    dst: vec!["*:*".to_string()],
                    proto: None,
                }],
                ..Default::default()
            };
            let evaluator = AclEvaluator::new(policy);

            let mut ctx = AclContext::from_node(&node_id, IpAddr::V4(src_ip));
            ctx = ctx.with_tags(tags.into_iter().map(|t| t.trim_start_matches("tag:").to_string()));

            let dst = AclDestination::new(IpAddr::V4(dst_ip), Some(port));

            prop_assert_eq!(evaluator.evaluate(&ctx, &dst), Action::Accept);
        }

        /// Property: Tag-based rules only match nodes with the tag.
        #[test]
        fn prop_tag_matching(
            src_ip in arb_ipv4(),
            dst_ip in arb_ipv4(),
            port in any::<u16>(),
            node_id in arb_node_id(),
            has_tag in any::<bool>(),
        ) {
            let policy = AclPolicy {
                acls: vec![AclRule {
                    action: Action::Accept,
                    src: vec!["tag:special".to_string()],
                    dst: vec!["*:*".to_string()],
                    proto: None,
                }],
                ..AclPolicy::deny_all()
            };
            let evaluator = AclEvaluator::new(policy);

            let ctx = if has_tag {
                AclContext::from_node(&node_id, IpAddr::V4(src_ip))
                    .with_tag("special")
            } else {
                AclContext::from_node(&node_id, IpAddr::V4(src_ip))
            };

            let dst = AclDestination::new(IpAddr::V4(dst_ip), Some(port));
            let result = evaluator.evaluate(&ctx, &dst);

            if has_tag {
                prop_assert_eq!(result, Action::Accept, "Node with tag should be accepted");
            } else {
                prop_assert_eq!(result, Action::Deny, "Node without tag should be denied");
            }
        }

        /// Property: Port-specific rules only match the specified port.
        #[test]
        fn prop_port_matching(
            src_ip in arb_ipv4(),
            dst_ip in arb_ipv4(),
            rule_port in 1u16..=65534,
            test_port in any::<u16>(),
            node_id in arb_node_id(),
        ) {
            let policy = AclPolicy {
                acls: vec![AclRule {
                    action: Action::Accept,
                    src: vec!["*".to_string()],
                    dst: vec![format!("*:{}", rule_port)],
                    proto: None,
                }],
                ..AclPolicy::deny_all()
            };
            let evaluator = AclEvaluator::new(policy);

            let ctx = AclContext::from_node(&node_id, IpAddr::V4(src_ip));
            let dst = AclDestination::new(IpAddr::V4(dst_ip), Some(test_port));
            let result = evaluator.evaluate(&ctx, &dst);

            if test_port == rule_port {
                prop_assert_eq!(result, Action::Accept, "Matching port should be accepted");
            } else {
                prop_assert_eq!(result, Action::Deny, "Non-matching port should be denied");
            }
        }

        /// Property: Policy serialization round-trip preserves structure.
        #[test]
        fn prop_policy_roundtrip(
            num_rules in 0usize..5,
            has_hosts in any::<bool>(),
            has_groups in any::<bool>(),
        ) {
            let mut policy = AclPolicy::default();

            if has_hosts {
                policy.hosts.insert("test-host".to_string(), HostSpec::Single("100.64.0.1".to_string()));
            }

            if has_groups {
                policy.groups.insert("test-group".to_string(), vec!["user:alice".to_string()]);
            }

            for i in 0..num_rules {
                policy.acls.push(AclRule {
                    action: if i % 2 == 0 { Action::Accept } else { Action::Deny },
                    src: vec!["*".to_string()],
                    dst: vec![format!("*:{}", 1000 + i)],
                    proto: None,
                });
            }

            let json = policy.to_json().expect("Serialization should succeed");
            let parsed = AclPolicy::from_json(&json).expect("Deserialization should succeed");

            prop_assert_eq!(policy.acls.len(), parsed.acls.len());
            prop_assert_eq!(policy.hosts.len(), parsed.hosts.len());
            prop_assert_eq!(policy.groups.len(), parsed.groups.len());
        }

        /// Property: CIDR matching is consistent with IP containment.
        #[test]
        fn prop_cidr_consistency(
            base_ip in 0u32..=255,
            test_offset in 0u32..=255,
        ) {
            // Create a /24 CIDR
            let cidr_str = format!("100.64.{}.0/24", base_ip);

            let policy = AclPolicy {
                acls: vec![AclRule {
                    action: Action::Accept,
                    src: vec![cidr_str.clone()],
                    dst: vec!["*:*".to_string()],
                    proto: None,
                }],
                ..AclPolicy::deny_all()
            };
            let evaluator = AclEvaluator::new(policy);

            // Test IP in same /24
            let test_ip_same = Ipv4Addr::new(100, 64, base_ip as u8, test_offset as u8);
            let ctx_same = AclContext::from_node("test", IpAddr::V4(test_ip_same));
            let dst = AclDestination::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), Some(80));

            prop_assert_eq!(
                evaluator.evaluate(&ctx_same, &dst),
                Action::Accept,
                "IP in CIDR range should be accepted"
            );

            // Test IP in different /24 (if different)
            let other_base = (base_ip + 1) % 256;
            if other_base != base_ip {
                let test_ip_diff = Ipv4Addr::new(100, 64, other_base as u8, test_offset as u8);
                let ctx_diff = AclContext::from_node("test", IpAddr::V4(test_ip_diff));

                prop_assert_eq!(
                    evaluator.evaluate(&ctx_diff, &dst),
                    Action::Deny,
                    "IP outside CIDR range should be denied"
                );
            }
        }
    }
}
