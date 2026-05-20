//! Serde mirror of `octravpn_mesh::acl::AclDoc`. Duplicated here on
//! purpose: `octravpn-mesh` already depends on `headscale-api`, so
//! a reverse dep would form a cycle. The on-wire shape is the
//! contract — we keep both definitions byte-compatible (see
//! `PolicyDoc::canonical_bytes` mirroring `AclDoc::canonical_bytes`).
//!
//! ## Upstream parity surface (`juanfont/headscale@main:hscontrol/policy/v2/`)
//!
//! The fields below mirror the upstream `policy/v2/types.go::Policy`
//! struct insofar as headscale-rs implements the corresponding
//! feature. Specifically:
//!
//! * `groups` / `tag_owners` / `hosts` / `ipsets` — definition tables.
//! * `auto_approvers` (`routes` + `exit_node`) — route + exit-node
//!   auto-approval. Driven by [`PolicyDoc::auto_approves_route`] /
//!   [`PolicyDoc::auto_approves_exit_node`] when deciding whether to
//!   flip a node's route-enable bits without manual operator action.
//! * `node_attrs` — per-target capability flags
//!   (`funnel`/`exit-node`/`ssh`/…) emitted into `MapResponse` so
//!   stock `tailscale` honours them client-side.
//! * `ssh` — SSH grant block, parsed and stored but not yet wired
//!   into a compiled SSHPolicy (parity follow-up).

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// `accept` vs `deny`. Matches `octravpn_mesh::acl::AclAction` byte for
/// byte on the wire.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    Accept,
    Deny,
}

/// One rule in the policy document. `src` / `dst` carry either an
/// explicit principal (`oct…` address), a group reference
/// (`group:<name>`), or the wildcard `*`. Ports follow the
/// `<proto>/<port>` form (`tcp/22`, `udp/*`, `*/*`). The legacy
/// `*:tcp/22` form is also accepted for backward compat with the
/// OctraVPN ACL parser.
///
/// `#[serde(deny_unknown_fields)]` matches the OctraVPN engine — a
/// misspelled rule field is a loud error, not a silently permissive
/// ACL.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub action: PolicyAction,
    pub src: Vec<String>,
    pub dst: Vec<String>,
    #[serde(default)]
    pub ports: Vec<String>,
}

/// One `nodeAttrs` grant. Mirrors upstream `NodeAttrGrant` (sans the
/// `ipPool` field, which the upstream allocator wires through the
/// IP allocator and which we don't yet ship).
#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeAttrGrant {
    pub target: Vec<String>,
    #[serde(default)]
    pub attr: Vec<String>,
}

/// `autoApprovers` block. Upstream calls this `AutoApproverPolicy`.
#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoApprovers {
    #[serde(default)]
    pub routes: BTreeMap<String, Vec<String>>,
    #[serde(default, rename = "exit_node", alias = "exitNode")]
    pub exit_node: Vec<String>,
}

/// SSH grant — parsed and round-tripped, but the SSH compiler isn't
/// wired into `MapResponse.SSHPolicy` yet.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SshRule {
    pub action: String,
    pub src: Vec<String>,
    pub dst: Vec<String>,
    #[serde(default)]
    pub users: Vec<String>,
}

/// Top-level policy document. `version = 1` matches the on-chain
/// `acl_policy` hash. Unknown fields reject — same as
/// `octravpn_mesh::acl::AclDoc`.
#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDoc {
    pub version: u32,
    #[serde(default)]
    pub groups: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
    /// `tag_owners` mirrors upstream `tagOwners`.
    #[serde(default, alias = "tagOwners")]
    pub tag_owners: BTreeMap<String, Vec<String>>,
    /// `hosts`: named single-CIDR aliases. Referenced as `host:<name>`.
    #[serde(default)]
    pub hosts: BTreeMap<String, String>,
    /// `ipsets`: named multi-CIDR aliases. Referenced as `ipset:<name>`.
    #[serde(default)]
    pub ipsets: BTreeMap<String, Vec<String>>,
    /// `auto_approvers` / `autoApprovers`.
    #[serde(default, alias = "autoApprovers")]
    pub auto_approvers: AutoApprovers,
    /// `node_attrs` / `nodeAttrs`.
    #[serde(default, alias = "nodeAttrs")]
    pub node_attrs: Vec<NodeAttrGrant>,
    /// `ssh` grants. Parsed only — not yet compiled into `SSHPolicy`.
    #[serde(default)]
    pub ssh: Vec<SshRule>,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

/// Per-node identity facets for principal / autogroup matching.
#[derive(Clone, Debug, Default)]
pub struct NodeView<'a> {
    pub addr: Option<&'a str>,
    pub user: Option<&'a str>,
    pub tags: &'a [String],
}

impl<'a> NodeView<'a> {
    pub fn new(addr: &'a str) -> Self {
        Self {
            addr: Some(addr),
            user: None,
            tags: &[],
        }
    }
    pub fn with_user(mut self, user: &'a str) -> Self {
        self.user = Some(user);
        self
    }
    pub fn with_tags(mut self, tags: &'a [String]) -> Self {
        self.tags = tags;
        self
    }
}

impl PolicyDoc {
    /// Empty doc, version 1, no rules.
    pub fn empty() -> Self {
        Self {
            version: 1,
            ..Default::default()
        }
    }

    /// Expand a principal token into FilterRule SrcIP entries.
    pub fn expand_principal(&self, token: &str) -> Vec<String> {
        if token == "*" {
            return vec!["*".to_string()];
        }
        if let Some(g) = token.strip_prefix("group:") {
            if let Some(members) = self.groups.get(g) {
                return members.clone();
            }
            return Vec::new();
        }
        if let Some(h) = token.strip_prefix("host:") {
            if let Some(cidr) = self.hosts.get(h) {
                return vec![cidr.clone()];
            }
            return Vec::new();
        }
        if let Some(s) = token.strip_prefix("ipset:") {
            if let Some(cidrs) = self.ipsets.get(s) {
                return cidrs.clone();
            }
            return Vec::new();
        }
        if let Some(ag) = token.strip_prefix("autogroup:") {
            if ag == "internet" || ag == "member" {
                return vec!["*".to_string()];
            }
            return Vec::new();
        }
        vec![token.to_string()]
    }

    /// Capability flags `node` should receive per the `node_attrs`
    /// block. Stable order, deduped.
    pub fn node_attrs_for(&self, node: &NodeView<'_>) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for grant in &self.node_attrs {
            if principal_set_matches(&grant.target, node, None, &self.groups) {
                for a in &grant.attr {
                    if !out.contains(a) {
                        out.push(a.clone());
                    }
                }
            }
        }
        out.sort();
        out
    }

    /// True iff `node` should have a route covering `prefix`
    /// auto-approved.
    pub fn auto_approves_route(&self, node: &NodeView<'_>, prefix: &str) -> bool {
        let Some(advertised) = parse_cidr(prefix) else {
            return false;
        };
        for (key, principals) in &self.auto_approvers.routes {
            let Some(approver_net) = parse_cidr(key) else {
                continue;
            };
            if !covers(&approver_net, &advertised) {
                continue;
            }
            if principal_set_matches(principals, node, None, &self.groups) {
                return true;
            }
        }
        false
    }

    /// True iff `node` is auto-approved as an exit-node.
    pub fn auto_approves_exit_node(&self, node: &NodeView<'_>) -> bool {
        if self.auto_approvers.exit_node.is_empty() {
            return false;
        }
        principal_set_matches(&self.auto_approvers.exit_node, node, None, &self.groups)
    }
}

fn principal_set_matches(
    set: &[String],
    principal: &NodeView<'_>,
    peer: Option<&NodeView<'_>>,
    groups: &BTreeMap<String, Vec<String>>,
) -> bool {
    set.iter()
        .any(|e| principal_one_matches(e, principal, peer, groups))
}

fn principal_one_matches(
    entry: &str,
    principal: &NodeView<'_>,
    peer: Option<&NodeView<'_>>,
    groups: &BTreeMap<String, Vec<String>>,
) -> bool {
    if entry == "*" {
        return true;
    }
    if let Some(group) = entry.strip_prefix("group:") {
        if let Some(members) = groups.get(group) {
            return members.iter().any(|m| identity_matches(m, principal));
        }
        return false;
    }
    if let Some(tag) = entry.strip_prefix("tag:") {
        return principal.tags.iter().any(|t| t == tag);
    }
    if let Some(ag) = entry.strip_prefix("autogroup:") {
        return autogroup_matches(ag, principal, peer);
    }
    if entry.contains('/') {
        return addr_in_cidr(principal.addr, entry);
    }
    identity_matches(entry, principal)
}

fn identity_matches(entry: &str, principal: &NodeView<'_>) -> bool {
    if let Some(a) = principal.addr {
        if entry == a {
            return true;
        }
    }
    if let Some(u) = principal.user {
        if entry == u {
            return true;
        }
    }
    false
}

fn autogroup_matches(kind: &str, principal: &NodeView<'_>, peer: Option<&NodeView<'_>>) -> bool {
    if kind == "internet" || kind == "member" {
        return true;
    }
    if kind == "nonroot" {
        return principal.tags.is_empty();
    }
    if kind == "tagged" {
        return !principal.tags.is_empty();
    }
    if let Some(tag) = kind.strip_prefix("tag:") {
        return principal.tags.iter().any(|t| t == tag);
    }
    if kind == "self" {
        let Some(peer) = peer else {
            return false;
        };
        if let (Some(a), Some(b)) = (principal.addr, peer.addr) {
            return a == b;
        }
        if let (Some(a), Some(b)) = (principal.user, peer.user) {
            return a == b;
        }
        return false;
    }
    false
}

pub(crate) fn parse_cidr(s: &str) -> Option<IpNet> {
    if let Ok(n) = s.parse::<IpNet>() {
        return Some(n);
    }
    if let Ok(addr) = s.parse::<IpAddr>() {
        return IpNet::new(addr, if addr.is_ipv4() { 32 } else { 128 }).ok();
    }
    None
}

fn covers(outer: &IpNet, inner: &IpNet) -> bool {
    match (outer, inner) {
        (IpNet::V4(o), IpNet::V4(i)) => {
            if o.prefix_len() > i.prefix_len() {
                return false;
            }
            o.contains(&i.network())
        }
        (IpNet::V6(o), IpNet::V6(i)) => {
            if o.prefix_len() > i.prefix_len() {
                return false;
            }
            o.contains(&i.network())
        }
        _ => false,
    }
}

fn addr_in_cidr(addr: Option<&str>, cidr: &str) -> bool {
    let Some(addr) = addr else {
        return false;
    };
    let Some(net) = parse_cidr(cidr) else {
        return false;
    };
    let Ok(parsed) = addr.parse::<IpAddr>() else {
        return false;
    };
    net.contains(&parsed)
}
