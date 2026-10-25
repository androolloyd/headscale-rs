//! Packet filters compiled by the production policy runtime.
//!
//! The differential harness used to carry its own filter compiler, so a green
//! run said nothing about what the server emits. This module builds the same
//! inputs the server has at startup (a `MachineRegistry` of nodes plus the
//! user list) and asks the production code for the result:
//!
//! - global filter: `PolicyStore::filter_rules`, the compiled runtime's
//!   `Filter()` equivalent;
//! - per-node filter: the `PacketFilters["base"]` a `/machine/map` response
//!   carries, computed by `tailscale_wire::map::base_packet_filter_for_node`
//!   over the node projection the map handlers use.
//!
//! The file is shared: `main.rs` includes it for the Go differential and
//! `headscale-api/tests/packet_filter_golden.rs` includes it by path for the
//! golden test that runs under `cargo test`.

use std::net::{Ipv4Addr, Ipv6Addr};

use chrono::Utc;
use headscale_api::{
    policy::{PacketFilterNode, PolicyStore, PolicyUser},
    tailscale_wire::{
        MachineRecord, MachineRegistry,
        map::{base_packet_filter_for_node, packet_filter_nodes_for_registry},
        wire::FilterRule,
    },
};
use serde_json::{Map, Value, json};

/// One scenario node, reduced to what a headscale node row carries.
#[derive(Debug, Clone)]
pub struct ParityNode {
    pub id: u64,
    /// Zero means "no owner", as the Go harness treats `user_id: 0` plus no
    /// matching user.
    pub user_id: u64,
    /// `User.Username()` of the owner: email when set, otherwise name.
    pub user: Option<String>,
    pub ipv4: String,
    pub ipv6: String,
    pub tags: Vec<String>,
    pub announced_routes: Vec<String>,
    pub approved_routes: Vec<String>,
}

/// How [`normalized_json`] orders the lists inside a rule.
///
/// The Go harness sorts `SrcIPs`, `DstPorts`, `IPProto`, `CapGrant` and the
/// caps inside a grant before printing, so by default so does this side:
/// the comparison is then insensitive to the order of those lists, while the
/// order of the *rules* themselves is compared exactly. [`Self::AsEmitted`]
/// keeps the compiler's own order for every list the Go harness lets us keep
/// (`CapGrant.Dsts` is always sorted on the Go side), to measure what the
/// sorting hides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListOrder {
    SortedLikeGoHarness,
    AsEmitted,
}

pub struct ProductionFilters {
    policy: PolicyStore,
    nodes: Vec<PacketFilterNode>,
}

impl ProductionFilters {
    /// Build startup state for `policy_json` and compile through production.
    /// `Err` carries the policy-manager error text.
    pub fn compile(
        policy_json: &[u8],
        users: Vec<PolicyUser>,
        nodes: &[ParityNode],
    ) -> Result<Self, String> {
        let registry = MachineRegistry::new();
        for node in nodes {
            registry.upsert(node_key(node.id), machine_record(node)?);
        }
        let policy = PolicyStore::from_initial_registry_bytes(
            Some((policy_json.to_vec(), 0)),
            users,
            &registry,
        )?;
        Ok(Self {
            policy,
            nodes: packet_filter_nodes_for_registry(&registry),
        })
    }

    /// Global compiled filter (`PolicyManager.Filter()` on the Go side). A
    /// policy without `acls`/`grants` yields the allow-all rule, as in Go.
    pub fn global(&self) -> Vec<FilterRule> {
        self.policy.filter_rules()
    }

    /// The base packet filter the server sends to `node_id`.
    pub fn for_node(&self, node_id: u64) -> Vec<FilterRule> {
        base_packet_filter_for_node(&self.policy, &self.nodes, node_id)
    }
}

fn node_key(id: u64) -> String {
    format!("{id:064x}")
}

fn machine_record(node: &ParityNode) -> Result<MachineRecord, String> {
    let ipv4 = parse_optional::<Ipv4Addr>(&node.ipv4)
        .map_err(|error| format!("node {} IPv4: {error}", node.id))?;
    let ipv6 = parse_optional::<Ipv6Addr>(&node.ipv6)
        .map_err(|error| format!("node {} IPv6: {error}", node.id))?;
    let mut record = MachineRecord::new_at_with_addresses(
        Utc::now(),
        node_key(node.id),
        format!("{:064x}", node.id + (1 << 40)),
        node.user.clone().unwrap_or_default(),
        format!("node-{}", node.id),
        ipv4,
        ipv6,
        false,
    );
    record.node_id = Some(node.id);
    record.user_id = (node.user_id != 0).then_some(node.user_id);
    record.forced_tags.clone_from(&node.tags);
    record.available_routes.clone_from(&node.announced_routes);
    record.approved_routes.clone_from(&node.approved_routes);
    Ok(record)
}

fn parse_optional<T: std::str::FromStr>(raw: &str) -> Result<Option<T>, T::Err> {
    if raw.is_empty() {
        Ok(None)
    } else {
        raw.parse().map(Some)
    }
}

/// Render rules in the JSON shape the Go harness prints (`filterRuleOut`),
/// without de-duplicating anything: a duplicate the compiler emits must show.
pub fn normalized_json(rules: &[FilterRule], order: ListOrder) -> Value {
    Value::Array(rules.iter().map(|rule| rule_json(rule, order)).collect())
}

fn rule_json(rule: &FilterRule, order: ListOrder) -> Value {
    let sorted = order == ListOrder::SortedLikeGoHarness;
    let mut src_ips = rule.src_ips.clone();
    let mut dst_ports = rule
        .dst_ports
        .iter()
        .map(|dst| (dst.ip.clone(), dst.ports.first, dst.ports.last))
        .collect::<Vec<_>>();
    let mut ip_proto = rule.ip_proto.clone();
    if sorted {
        src_ips.sort();
        dst_ports.sort();
        ip_proto.sort_unstable();
    }
    let mut out = Map::new();
    out.insert(
        "SrcIPs".into(),
        if src_ips.is_empty() {
            Value::Null
        } else {
            json!(src_ips)
        },
    );
    out.insert(
        "DstPorts".into(),
        Value::Array(
            dst_ports
                .into_iter()
                .map(|(ip, first, last)| json!({"IP": ip, "Ports": {"First": first, "Last": last}}))
                .collect(),
        ),
    );
    if !ip_proto.is_empty() {
        out.insert("IPProto".into(), json!(ip_proto));
    }
    let mut cap_grants = rule
        .cap_grant
        .iter()
        .map(|grant| cap_grant_json(grant, sorted))
        .collect::<Vec<_>>();
    if sorted {
        cap_grants.sort_by_key(cap_grant_sort_key);
    }
    if !cap_grants.is_empty() {
        out.insert("CapGrant".into(), Value::Array(cap_grants));
    }
    Value::Object(out)
}

fn cap_grant_json(grant: &headscale_api::tailscale_wire::wire::CapGrant, sorted: bool) -> Value {
    // The Go harness always sorts the destination prefixes it prints.
    let mut dsts = grant.dsts.clone();
    dsts.sort();
    let mut caps = grant.caps.clone();
    if sorted {
        caps.sort();
    }
    let mut out = Map::new();
    if !dsts.is_empty() {
        out.insert("Dsts".into(), json!(dsts));
    }
    if !caps.is_empty() {
        out.insert("Caps".into(), json!(caps));
    }
    if !grant.cap_map.is_empty() {
        out.insert(
            "CapMap".into(),
            serde_json::to_value(&grant.cap_map).unwrap_or(Value::Null),
        );
    }
    Value::Object(out)
}

fn cap_grant_sort_key(grant: &Value) -> (String, String, String) {
    let joined = |key: &str| {
        grant[key]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("\u{0}")
            })
            .unwrap_or_default()
    };
    (
        joined("Dsts"),
        joined("Caps"),
        grant
            .get("CapMap")
            .map(Value::to_string)
            .unwrap_or_default(),
    )
}
