// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause

//! [`PolicyDoc`] → `Vec<FilterRule>` translation.
//!
//! Lives in `headscale-api` (not the leaf `headscale-api-acl` crate)
//! because [`FilterRule`] is a Tailscale-wire type owned by the
//! `tailscale_wire` module here. The canonical eval engine in
//! `headscale-api-acl` is wire-agnostic; this layer is the
//! headscale-specific adapter.
//!
//! ## Translation semantics
//!
//! `accept` ACL rules and policy v2 grants generate `FilterRule`
//! entries. The Tailscale `filter` matcher treats the list as a
//! deny-by-default allowlist — the canonical ACL engine encodes the
//! same semantics, so the ACL mapping is:
//!
//! ```text
//! AclAction::Accept { src, dst, ports }
//!   →  FilterRule {
//!         SrcIPs:   expand_principal(src),
//!         DstPorts: [{ IP: dst_i, Ports: { first, last } } for each dst, port],
//!         IPProto:  protocol_numbers(ports)
//!      }
//! ```
//!
//! `deny` rules are dropped. The canonical engine evaluates
//! top-to-bottom and stops at the first match; encoding that into a
//! deny-by-default FilterRule list is a translation we do NOT
//! attempt here. The current contract is "operators write
//! accept-only ACLs; explicit denies are caught by the on-host
//! `headscale-api-acl` evaluator but never reach the Tailscale
//! daemon's packet filter".
//!
//! ## Static-vs-dynamic principal expansion
//!
//! Identity aliases resolve through the retained user/node snapshot. Self and
//! via grants also receive the current recipient for their deferred filter.
//! The shared resolver retains an optional partial IP set and its errors:
//! packet-filter aliases accept usable partial sets, CapGrant/via destinations
//! skip errored aliases, and nodeAttrs aborts its refresh on any target error.

use std::{collections::BTreeMap, net::IpAddr};

use super::lifecycle::GrantAppShape;
use ipnet::IpNet;

use super::{CapabilityMap, GrantRule, PolicyAction, PolicyDoc};
use crate::tailscale_wire::wire::{CapGrant, FilterRule, NetPortRange, PortRange};

/// Node facts needed to compile/reduce a headscale-go-style packet
/// filter for one map recipient.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketFilterNode {
    pub id: u64,
    pub user_id: Option<u64>,
    pub user: Option<String>,
    pub addrs: Vec<String>,
    pub tags: Vec<String>,
    pub routes: Vec<String>,
}

impl PacketFilterNode {
    pub(super) fn view(&self) -> super::NodeView<'_> {
        super::NodeView {
            user_id: self.user_id,
            user: self.user.as_deref(),
            addr: self.addrs.first().map(String::as_str),
            addrs: &self.addrs,
            tags: &self.tags,
        }
    }
}

pub(super) fn resolve_owner_ips(
    doc: &PolicyDoc,
    aliases: &[String],
    nodes: &[PacketFilterNode],
) -> Vec<String> {
    super::resolution::owners(doc, aliases, nodes).partial()
}

pub(super) fn resolved_source_cidrs(
    doc: &PolicyDoc,
    aliases: &[String],
    nodes: &[PacketFilterNode],
) -> Vec<String> {
    resolve_principals(doc, aliases, nodes, None, PrincipalPosition::Source)
        .iter()
        .flat_map(|ip| {
            if ip == "*" {
                headscale_api_acl::wildcard_filter_cidrs()
            } else {
                ipset_string_to_cidrs(ip)
            }
        })
        .collect()
}

pub(super) fn any_ip_matches(prefixes: &[String], node: &super::NodeView<'_>) -> bool {
    node.addrs
        .iter()
        .map(String::as_str)
        .chain(node.addr)
        .any(|addr| {
            prefixes
                .iter()
                .any(|prefix| ipset_string_contains_addr(prefix, addr))
        })
}

pub(super) fn prefix_covers_route(prefix: &str, route: &str) -> bool {
    match (parse_ip_net(prefix), parse_ip_net(route)) {
        (Some(prefix), Some(route)) => {
            prefix.prefix_len() <= route.prefix_len()
                && net_contains_addr(&prefix, &route.addr().to_string())
        }
        _ => false,
    }
}

/// Admission/category portion of Go compileOneGrant/compileOneViaGrant. Source
/// resolution is shared with the packet-filter compiler; an unresolved alias
/// must not turn an inert self/via grant into a per-node policy.
pub(super) fn has_per_node_filters(
    doc: &PolicyDoc,
    nodes: &[PacketFilterNode],
    apps: &[GrantAppShape],
) -> bool {
    filter_grants(doc, apps).iter().any(|grant| {
        if grant.via.is_empty() {
            grant.destinations.iter().any(|dst| dst == "autogroup:self")
                && regular_grant_is_admitted(doc, grant, nodes)
        } else {
            !grant.ports.is_empty() && !source_strings(doc, grant.sources, nodes, false).is_empty()
        }
    })
}

fn sources_have_resolved_alias(
    doc: &PolicyDoc,
    aliases: &[String],
    nodes: &[PacketFilterNode],
) -> bool {
    !aliases.iter().any(|alias| alias == "autogroup:self")
        && aliases
            .iter()
            .any(|alias| super::resolution::alias(doc, alias, nodes).ips.is_some())
}

/// Go compileNodeAttrs resolves each target once and stamps every matching
/// node IP. Shared addresses do not turn this into an ownership comparison.
pub(super) fn compile_node_attrs(
    doc: &PolicyDoc,
    nodes: &[PacketFilterNode],
) -> Result<BTreeMap<u64, Vec<String>>, String> {
    let mut attrs: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    if doc.randomize_client_port {
        for node in nodes {
            attrs
                .entry(node.id)
                .or_default()
                .push("randomize-client-port".into());
        }
    }
    for grant in &doc.node_attrs {
        if grant.attr.is_empty() {
            continue;
        }
        // Generic Alias.Resolve's wildcard excludes the ChromeOS range and
        // has no approved-route expansion (that is a filter-only addon).
        let targets = super::resolution::aliases(doc, &grant.target, nodes)
            .checked()
            .map_err(|error| {
                format!(
                    "compiling nodeAttrs: nodeAttrs target [{}]: {error}",
                    grant.target.join(" ")
                )
            })?;
        for node in nodes {
            if any_ip_matches(&targets, &node.view()) {
                attrs
                    .entry(node.id)
                    .or_default()
                    .extend(grant.attr.iter().cloned());
            }
        }
    }
    for values in attrs.values_mut() {
        values.sort();
        values.dedup();
    }
    Ok(attrs)
}

pub fn allow_all_filter_rules() -> Vec<FilterRule> {
    vec![FilterRule {
        src_ips: vec!["*".to_string()],
        dst_ports: vec![NetPortRange {
            ip: "*".to_string(),
            ports: PortRange {
                first: 0,
                last: 65535,
            },
            ..NetPortRange::default()
        }],
        ip_proto: Vec::new(),
        ..FilterRule::default()
    }]
}

pub fn raw_policy_omits_packet_filter_rules(raw: &str) -> bool {
    headscale_api_acl::go_policy_shape::packet_filter_default_allow(raw)
}

/// Translate a parsed [`PolicyDoc`] into the on-wire
/// `tailcfg.FilterRule` list the stock Tailscale daemon consumes.
///
/// An empty result is significant: it means the policy
/// default-denies everything. The wire layer pins this to an empty
/// `packet_filter` field, which causes the stock daemon to reject
/// every inter-peer packet with `unknown peer` — the intended
/// behaviour for deny-all policies.
pub fn acl_to_filter_rules(doc: &PolicyDoc) -> Vec<FilterRule> {
    acl_to_global_filter_rules(doc, &[])
}

pub(super) fn acl_to_global_filter_rules(
    doc: &PolicyDoc,
    nodes: &[PacketFilterNode],
) -> Vec<FilterRule> {
    acl_to_global_filter_rules_with_apps(doc, nodes, &[])
}

pub(super) fn acl_to_global_filter_rules_with_apps(
    doc: &PolicyDoc,
    nodes: &[PacketFilterNode],
    apps: &[GrantAppShape],
) -> Vec<FilterRule> {
    let mut out = Vec::new();
    for grant in filter_grants(doc, apps) {
        append_grant_rules(&mut out, doc, &grant, nodes, None);
    }
    coalesce_filter_rules(out)
}

/// Compile the `PacketFilters["base"]` rules for `node_id`.
///
/// Headscale-go does not send the global policy filter verbatim in a
/// map response. It resolves users/tags against the current node set
/// and reduces the result to destinations relevant to the receiving
/// node.
pub fn acl_to_filter_rules_for_node(
    doc: &PolicyDoc,
    nodes: &[PacketFilterNode],
    node_id: u64,
) -> Vec<FilterRule> {
    let Some(self_node) = nodes.iter().find(|node| node.id == node_id) else {
        return Vec::new();
    };
    acl_to_filter_rules_for_receiver(doc, nodes, self_node)
}

/// Alias expansion reads the retained compiler inputs; final reduction reads
/// the requesting node, as Go FilterForNode does on a cache miss.
pub(super) fn acl_to_filter_rules_for_receiver(
    doc: &PolicyDoc,
    nodes: &[PacketFilterNode],
    self_node: &PacketFilterNode,
) -> Vec<FilterRule> {
    acl_to_filter_rules_for_receiver_with_apps(doc, nodes, self_node, &[])
}

pub(super) fn acl_to_filter_rules_for_receiver_with_apps(
    doc: &PolicyDoc,
    nodes: &[PacketFilterNode],
    self_node: &PacketFilterNode,
    apps: &[GrantAppShape],
) -> Vec<FilterRule> {
    let mut out = unreduced_filter_rules_for_receiver(doc, nodes, self_node, apps);
    append_exit_node_self_rules(&mut out, doc, nodes, self_node, apps);
    reduce_filter_rules_for_node(out, self_node)
}

type PortGroup = (Vec<i32>, Vec<PortRange>);

struct FilterGrant<'a> {
    sources: &'a [String],
    destinations: &'a [String],
    ports: Vec<PortGroup>,
    via: &'a [String],
    app: Option<&'a CapabilityMap>,
    app_shape: Option<&'a GrantAppShape>,
}

/// Compile original grants first, then each ACL destination in aclToGrants
/// order. Synthetic parser rows are a public-model projection, not grants.
fn filter_grants<'a>(doc: &'a PolicyDoc, apps: &'a [GrantAppShape]) -> Vec<FilterGrant<'a>> {
    let mut grants = doc
        .grants
        .iter()
        .enumerate()
        .map(|(index, grant)| {
            let app_shape = apps.get(index);
            FilterGrant {
                sources: &grant.src,
                destinations: &grant.dst,
                ports: compile_grant_port_groups(&grant.ip),
                via: &grant.via,
                app: (!grant.app.is_empty() || app_shape.is_some_and(|shape| shape.non_nil))
                    .then_some(&grant.app),
                app_shape,
            }
        })
        .collect::<Vec<_>>();
    let projected = projected_network_grant_indices(&doc.grants).len();
    for rule in doc.rules.iter().skip(projected) {
        if !matches!(rule.action, PolicyAction::Accept) {
            continue;
        }
        let mut destinations = rule.dst.iter().collect::<Vec<_>>();
        if destinations.iter().any(|dst| {
            headscale_api_acl::go_policy_shape::alias_kind(dst)
                != Some(headscale_api_acl::go_policy_shape::AliasKind::AutoGroup)
        }) {
            destinations.sort_by_key(|dst| dst.as_str() == "autogroup:self");
        }
        for destination in destinations {
            grants.push(FilterGrant {
                sources: &rule.src,
                destinations: std::slice::from_ref(destination),
                ports: compile_port_groups(&rule.ports),
                via: &[],
                app: None,
                app_shape: None,
            });
        }
    }
    grants
}

fn regular_grant_is_admitted(
    doc: &PolicyDoc,
    grant: &FilterGrant<'_>,
    nodes: &[PacketFilterNode],
) -> bool {
    !grant.sources.is_empty()
        && !grant.destinations.is_empty()
        && !grant
            .sources
            .iter()
            .any(|source| source == "autogroup:self")
        && (grant.app.is_some() || sources_have_resolved_alias(doc, grant.sources, nodes))
}

fn append_grant_rules(
    out: &mut Vec<FilterRule>,
    doc: &PolicyDoc,
    grant: &FilterGrant<'_>,
    nodes: &[PacketFilterNode],
    receiver: Option<&PacketFilterNode>,
) {
    if !grant.via.is_empty() {
        let Some(receiver) = receiver else {
            return;
        };
        if grant.ports.is_empty() || !grant.via.iter().any(|tag| receiver.tags.contains(tag)) {
            return;
        }
        // Via grants use srcIPsWithRoutes, without buildSrcIPStrings' later
        // non-wildcard alias appends.
        let src = source_strings(doc, grant.sources, nodes, false);
        let dst = resolve_via_destinations_for_node(doc, grant.destinations, nodes, receiver);
        append_filter_rules(out, &src, &dst, &grant.ports, true);
        return;
    }
    if !regular_grant_is_admitted(doc, grant, nodes) {
        return;
    }
    let sources = resolve_sources(doc, grant.sources, nodes);
    let raw_source_prefixes = resolve_companion_sources(doc, grant.sources, nodes);
    let other_destinations = grant
        .destinations
        .iter()
        .filter(|dst| dst.as_str() != "autogroup:self")
        .cloned()
        .collect::<Vec<_>>();
    if !other_destinations.is_empty() {
        let destinations = resolve_principals(
            doc,
            &other_destinations,
            nodes,
            None,
            PrincipalPosition::Destination,
        );
        append_filter_rules(out, &sources, &destinations, &grant.ports, false);
        if let Some(app) = grant.app {
            append_cap_grant_rules(
                out,
                doc,
                nodes,
                &sources,
                &raw_source_prefixes,
                &other_destinations,
                app,
                grant.app_shape,
            );
        }
    }
    if grant.destinations.iter().any(|dst| dst == "autogroup:self")
        && let Some(receiver) = receiver.filter(|node| node.tags.is_empty())
    {
        let user_nodes = same_user_untagged_nodes(nodes, receiver);
        append_self_rules(out, grant, &raw_source_prefixes, &user_nodes);
    }
}

pub(super) fn unreduced_filter_rules_for_receiver(
    doc: &PolicyDoc,
    nodes: &[PacketFilterNode],
    self_node: &PacketFilterNode,
    apps: &[GrantAppShape],
) -> Vec<FilterRule> {
    let mut out = Vec::new();
    for grant in filter_grants(doc, apps) {
        append_grant_rules(&mut out, doc, &grant, nodes, Some(self_node));
    }
    coalesce_filter_rules(out)
}

fn append_exit_node_self_rules(
    out: &mut Vec<FilterRule>,
    doc: &PolicyDoc,
    nodes: &[PacketFilterNode],
    self_node: &PacketFilterNode,
    apps: &[GrantAppShape],
) {
    if !self_node.routes.iter().any(|route| is_exit_route(route)) {
        return;
    }
    let mut by_user: BTreeMap<NodeOwnerKey<'_>, Vec<&PacketFilterNode>> = BTreeMap::new();
    for node in nodes.iter().filter(|node| is_untagged_user_owned(node)) {
        if let Some(owner) = node_owner_key(node) {
            by_user.entry(owner).or_default().push(node);
        }
    }
    for grant in filter_grants(doc, apps) {
        if !grant.via.is_empty()
            || !grant.destinations.iter().any(|dst| dst == "autogroup:self")
            || !regular_grant_is_admitted(doc, &grant, nodes)
        {
            continue;
        }
        let sources = resolve_companion_sources(doc, grant.sources, nodes);
        for (owner, user_nodes) in &by_user {
            if self_node.tags.is_empty() && node_owner_key(self_node).as_ref() == Some(owner) {
                continue;
            }
            // Go appends these after the merged recipient rules; do not merge
            // the extra per-user rules into one another or the earlier batch.
            append_self_rules(out, &grant, &sources, user_nodes);
        }
    }
}

fn append_self_rules(
    out: &mut Vec<FilterRule>,
    grant: &FilterGrant<'_>,
    source_prefixes: &[String],
    user_nodes: &[&PacketFilterNode],
) {
    let sources = nodes_matching_prefixes(user_nodes, source_prefixes);
    if sources.is_empty() {
        return;
    }
    let node_addresses = user_nodes
        .iter()
        .map(|node| node_ip_strings(node))
        .collect::<Vec<_>>();
    for (protocol, ports) in &grant.ports {
        let mut destinations = Vec::new();
        // compileSelfForUser walks node, port, address (regular destinations
        // instead walk prefix, port). Retain dual-stack and duplicate order.
        for addresses in &node_addresses {
            for port in ports {
                for ip in addresses {
                    destinations.push(NetPortRange {
                        ip: ip.clone(),
                        ports: port.clone(),
                        ..NetPortRange::default()
                    });
                }
            }
        }
        if !destinations.is_empty() {
            out.push(FilterRule {
                src_ips: sources.clone(),
                dst_ports: destinations,
                ip_proto: protocol.clone(),
                ..FilterRule::default()
            });
        }
    }
    if let Some(app) = grant.app {
        let cap_grant = user_nodes
            .iter()
            .map(|node| CapGrant {
                dsts: node_addr_prefixes(node),
                cap_map: wire_cap_map(app, grant.app_shape),
                ..CapGrant::default()
            })
            .collect::<Vec<_>>();
        if !cap_grant.is_empty() {
            out.push(FilterRule {
                src_ips: sources.clone(),
                cap_grant,
                ..FilterRule::default()
            });
            let destinations = node_addresses.iter().flatten().cloned().collect::<Vec<_>>();
            append_companion_cap_grant_rules(out, &destinations, &sources, app);
        }
    }
}

fn node_ip_strings(node: &PacketFilterNode) -> Vec<String> {
    node.addrs
        .iter()
        .map(|address| {
            headscale_api_acl::go_netip::parse_addr(address).map_or_else(
                |_| "invalid IP".to_owned(),
                |(ip, zone)| zone.map_or_else(|| ip.to_string(), |zone| format!("{ip}%{zone}")),
            )
        })
        .collect()
}

fn projected_network_grant_indices(grants: &[GrantRule]) -> Vec<usize> {
    grants
        .iter()
        .enumerate()
        .filter_map(|(index, grant)| {
            (grant.via.is_empty() && !grant.ip.is_empty()).then_some(index)
        })
        .collect()
}

fn resolve_companion_sources(
    doc: &PolicyDoc,
    tokens: &[String],
    nodes: &[PacketFilterNode],
) -> Vec<String> {
    tokens
        .iter()
        .flat_map(|token| {
            let resolved = super::resolution::alias(doc, token, nodes).partial();
            super::matcher::IpSet::from_strings(resolved.iter().map(String::as_str)).prefixes()
        })
        .collect()
}

fn append_cap_grant_rules(
    out: &mut Vec<FilterRule>,
    doc: &PolicyDoc,
    nodes: &[PacketFilterNode],
    src_ips: &[String],
    companion_src: &[String],
    dsts: &[String],
    app: &CapabilityMap,
    shape: Option<&GrantAppShape>,
) {
    let mut cap_grants: Vec<CapGrant> = Vec::new();
    let mut dst_ip_strings = Vec::new();
    for dst in dsts {
        if let Some(dst_prefixes) = resolve_cap_grant_dst(doc, dst, nodes) {
            dst_ip_strings.extend(
                super::matcher::IpSet::from_strings(dst_prefixes.iter().map(String::as_str))
                    .strings(),
            );
            cap_grants.push(CapGrant {
                dsts: dst_prefixes,
                cap_map: wire_cap_map(app, shape),
                ..CapGrant::default()
            });
        }
    }

    if cap_grants.is_empty() {
        return;
    }

    let rule = FilterRule {
        src_ips: src_ips.to_vec(),
        cap_grant: cap_grants,
        ..FilterRule::default()
    };
    append_coalesced_filter_rule(out, rule);

    if dsts.iter().any(|dst| dst == "*") {
        dst_ip_strings.extend(approved_subnet_routes(nodes));
    }
    append_companion_cap_grant_rules(out, &dst_ip_strings, companion_src, app);
}

fn wire_cap_map(
    app: &CapabilityMap,
    shape: Option<&GrantAppShape>,
) -> BTreeMap<String, Option<Vec<serde_json::Value>>> {
    app.iter()
        .map(|(cap, values)| {
            (
                cap.clone(),
                if values.is_empty()
                    && shape.is_some_and(|shape| shape.nil_capabilities.contains(cap))
                {
                    None
                } else {
                    Some(values.clone())
                },
            )
        })
        .collect()
}

fn companion_cap_map(cap: &str) -> BTreeMap<String, Option<Vec<serde_json::Value>>> {
    BTreeMap::from([(cap.to_string(), None)])
}

fn companion_cap(cap: &str) -> Option<&'static str> {
    match cap {
        "tailscale.com/cap/drive" => Some("tailscale.com/cap/drive-sharer"),
        "tailscale.com/cap/relay" => Some("tailscale.com/cap/relay-target"),
        _ => None,
    }
}

fn append_companion_cap_grant_rules(
    out: &mut Vec<FilterRule>,
    dst_ip_strings: &[String],
    src_ips: &[String],
    app: &CapabilityMap,
) {
    let src_prefixes = src_ips
        .iter()
        .flat_map(|src| ipset_string_to_cidrs(src))
        .collect::<Vec<_>>();
    let mut caps = app
        .keys()
        .filter_map(|cap| companion_cap(cap))
        .collect::<Vec<_>>();
    caps.sort_unstable();
    for cap in caps {
        let rule = FilterRule {
            src_ips: dst_ip_strings.to_vec(),
            cap_grant: vec![CapGrant {
                dsts: src_prefixes.clone(),
                cap_map: companion_cap_map(cap),
                ..CapGrant::default()
            }],
            ..FilterRule::default()
        };
        append_coalesced_filter_rule(out, rule);
    }
}

fn append_filter_rules(
    out: &mut Vec<FilterRule>,
    src_ips: &[String],
    dst_ips: &[String],
    groups: &[PortGroup],
    keep_prefixes: bool,
) {
    if src_ips.is_empty() || dst_ips.is_empty() {
        return;
    }
    for (ip_proto, port_ranges) in groups {
        let mut dst_ports = Vec::new();
        for ip in dst_ips {
            for range in port_ranges {
                dst_ports.push(NetPortRange {
                    ip: if keep_prefixes {
                        ip.clone()
                    } else {
                        dst_port_ip_string(ip)
                    },
                    ports: range.clone(),
                    ..NetPortRange::default()
                });
            }
        }
        let rule = FilterRule {
            src_ips: src_ips.to_vec(),
            dst_ports,
            ip_proto: ip_proto.clone(),
            ..FilterRule::default()
        };
        out.push(rule);
    }
}

fn resolve_principals(
    doc: &PolicyDoc,
    tokens: &[String],
    nodes: &[PacketFilterNode],
    self_node: Option<&PacketFilterNode>,
    position: PrincipalPosition,
) -> Vec<String> {
    if position == PrincipalPosition::Source {
        return resolve_sources(doc, tokens, nodes);
    }
    let mut out = Vec::new();
    for token in tokens {
        if token == "*" {
            out.push("*".to_owned());
        } else {
            let resolved = resolve_principal(doc, token, nodes, self_node, position);
            out.extend(
                super::matcher::IpSet::from_strings(resolved.iter().map(String::as_str)).prefixes(),
            );
        }
    }
    out
}

fn resolve_sources(doc: &PolicyDoc, tokens: &[String], nodes: &[PacketFilterNode]) -> Vec<String> {
    source_strings(doc, tokens, nodes, true)
}

fn source_strings(
    doc: &PolicyDoc,
    tokens: &[String],
    nodes: &[PacketFilterNode],
    preserve_nonwildcard: bool,
) -> Vec<String> {
    if tokens.iter().any(|token| token == "autogroup:self") {
        return Vec::new();
    }
    let aliases = tokens
        .iter()
        .map(|token| super::resolution::alias(doc, token, nodes).partial())
        .collect::<Vec<_>>();
    let mut out =
        super::matcher::IpSet::from_strings(aliases.iter().flatten().map(String::as_str)).strings();
    if out.is_empty() {
        return out;
    }
    let wildcard = tokens.iter().any(|token| token == "*");
    if tokens.iter().any(|token| token == "autogroup:danger-all") {
        out = vec!["*".to_owned()];
    } else if wildcard {
        // Routes are distinct entries even when covered by a merged source.
        out.extend(approved_subnet_routes(nodes));
    }
    if wildcard && preserve_nonwildcard {
        for (token, resolved) in tokens.iter().zip(&aliases) {
            if token != "*" {
                for source in
                    super::matcher::IpSet::from_strings(resolved.iter().map(String::as_str))
                        .strings()
                {
                    push_unique_string(&mut out, source);
                }
            }
        }
    }
    out
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrincipalPosition {
    Source,
    Destination,
}

fn resolve_principal(
    doc: &PolicyDoc,
    token: &str,
    nodes: &[PacketFilterNode],
    self_node: Option<&PacketFilterNode>,
    position: PrincipalPosition,
) -> Vec<String> {
    if token == "*" {
        return match position {
            PrincipalPosition::Source => headscale_api_acl::tailnet_filter_srcs(),
            PrincipalPosition::Destination => vec!["*".to_string()],
        };
    }
    if token == "autogroup:danger-all" && position == PrincipalPosition::Source {
        return vec!["*".into()];
    }
    if token == "autogroup:self" {
        return self_node
            .filter(|node| node.tags.is_empty())
            .map(|node| same_user_untagged_nodes(nodes, node))
            .unwrap_or_default()
            .iter()
            .flat_map(|node| node_addr_prefixes(node))
            .collect();
    }
    super::resolution::alias(doc, token, nodes).partial()
}

fn resolve_cap_grant_dst(
    doc: &PolicyDoc,
    token: &str,
    nodes: &[PacketFilterNode],
) -> Option<Vec<String>> {
    let resolved = super::resolution::alias(doc, token, nodes);
    if resolved.errors.is_empty() {
        resolved.ips.map(|ips| {
            super::matcher::IpSet::from_strings(ips.iter().map(String::as_str)).prefixes()
        })
    } else {
        None
    }
}

fn resolve_via_destinations_for_node(
    doc: &PolicyDoc,
    dsts: &[String],
    nodes: &[PacketFilterNode],
    node: &PacketFilterNode,
) -> Vec<String> {
    let mut out = Vec::new();
    let node_subnet_routes = node
        .routes
        .iter()
        .filter(|route| !is_exit_route(route))
        .collect::<Vec<_>>();
    let mut internet = false;
    for destination in dsts {
        if destination == "autogroup:internet" {
            internet = true;
            continue;
        }
        let resolved = super::resolution::alias(doc, destination, nodes);
        if !resolved.errors.is_empty() {
            continue;
        }
        if let Some(ips) = resolved.ips {
            for prefix in
                super::matcher::IpSet::from_strings(ips.iter().map(String::as_str)).prefixes()
            {
                if node_subnet_routes
                    .iter()
                    .any(|route| prefixes_overlap(&prefix, route))
                {
                    out.push(prefix);
                }
            }
        }
    }
    // compileViaForNode appends TheInternet once, after resolved subnet
    // destinations, regardless of where internet aliases appeared.
    if internet && node.routes.iter().any(|route| is_exit_route(route)) {
        let prefixes = headscale_api_acl::internet_filter_cidrs();
        out.extend(
            super::matcher::IpSet::from_strings(prefixes.iter().map(String::as_str)).prefixes(),
        );
    }
    out
}

fn same_user_untagged_nodes<'a>(
    nodes: &'a [PacketFilterNode],
    node: &PacketFilterNode,
) -> Vec<&'a PacketFilterNode> {
    let Some(owner) = node_owner_key(node) else {
        return Vec::new();
    };

    nodes
        .iter()
        .filter(|candidate| is_untagged_user_owned(candidate))
        .filter(|candidate| node_owner_key(candidate).as_ref() == Some(&owner))
        .collect()
}

fn is_untagged_user_owned(node: &PacketFilterNode) -> bool {
    node.tags.is_empty() && node_owner_key(node).is_some()
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum NodeOwnerKey<'a> {
    Id(u64),
    User(&'a str),
}

fn node_owner_key(node: &PacketFilterNode) -> Option<NodeOwnerKey<'_>> {
    node.user_id.map(NodeOwnerKey::Id).or_else(|| {
        node.user
            .as_deref()
            .filter(|user| !user.is_empty())
            .map(NodeOwnerKey::User)
    })
}

fn nodes_matching_prefixes(nodes: &[&PacketFilterNode], prefixes: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for node in nodes {
        if node.addrs.iter().any(|addr| {
            prefixes
                .iter()
                .any(|prefix| ipset_string_contains_addr(prefix, addr))
        }) {
            // Go adds both pointers of a matched node. A typed invalid IP
            // records a builder error, suppressing this entire self expansion.
            if node
                .addrs
                .iter()
                .any(|addr| headscale_api_acl::go_netip::parse_addr(addr).is_err())
            {
                return Vec::new();
            }
            out.extend(node_addr_prefixes(node));
        }
    }
    aggregate_prefixes(&out)
}

fn approved_subnet_routes(nodes: &[PacketFilterNode]) -> Vec<String> {
    let mut out = Vec::new();
    for node in nodes {
        for route in &node.routes {
            if !is_exit_route(route) {
                push_unique_string(&mut out, route.clone());
            }
        }
    }
    out
}

fn node_addr_prefixes(node: &PacketFilterNode) -> Vec<String> {
    node.addrs
        .iter()
        .filter_map(|addr| headscale_api_acl::go_netip::parse_addr(addr).ok())
        .map(|(addr, _)| format!("{addr}/{}", if addr.is_ipv4() { 32 } else { 128 }))
        .collect()
}

pub(super) fn reduce_filter_rules_for_node(
    rules: Vec<FilterRule>,
    node: &PacketFilterNode,
) -> Vec<FilterRule> {
    let mut out = Vec::new();
    for mut rule in rules {
        if !rule.cap_grant.is_empty() {
            if let Some(reduced) = reduce_cap_grant_rule_for_node(&rule, node) {
                out.push(reduced);
            }
            continue;
        }

        rule.dst_ports.retain(|destination| {
            let Some(expanded) = super::matcher::IpSet::from_filter_string(&destination.ip) else {
                return false;
            };
            // Go checks node identity, approved subnets and approved exits
            // against the same parsed set. Even wildcard needs one match.
            expanded.contains_node(node)
                || node
                    .routes
                    .iter()
                    .any(|route| expanded.overlaps_prefix(route))
        });
        if rule.dst_ports.is_empty() {
            continue;
        }
        out.push(rule);
    }
    out
}

fn reduce_cap_grant_rule_for_node(
    rule: &FilterRule,
    node: &PacketFilterNode,
) -> Option<FilterRule> {
    let mut cap_grant = Vec::new();
    for grant in &rule.cap_grant {
        let mut dsts = Vec::new();

        for dst in &grant.dsts {
            let Some(dst_net) = parse_prefix_net(dst) else {
                continue;
            };
            if is_single_ip(&dst_net) {
                if node
                    .addrs
                    .iter()
                    .any(|addr| net_contains_addr(&dst_net, addr))
                {
                    push_unique_string(&mut dsts, dst_net.to_string());
                }
                continue;
            }

            for addr in &node.addrs {
                if net_contains_addr(&dst_net, addr)
                    && let Some(prefix) = addr_prefix_string(addr)
                {
                    push_unique_string(&mut dsts, prefix);
                }
            }
        }

        for dst in &grant.dsts {
            let Some(prefix) = parse_prefix_net(dst) else {
                continue;
            };
            if node
                .routes
                .iter()
                .filter(|route| !is_exit_route(route))
                .any(|route| {
                    parse_prefix_net(route).is_some_and(|route| nets_overlap(&prefix, &route))
                })
            {
                push_unique_string(&mut dsts, prefix.to_string());
            }
        }

        if !dsts.is_empty() {
            dsts.sort_by(|a, b| {
                headscale_api_acl::go_netip::prefix_compare(a, b).unwrap_or_else(|| a.cmp(b))
            });
            cap_grant.push(CapGrant {
                dsts,
                cap_map: grant.cap_map.clone(),
                ..CapGrant::default()
            });
        }
    }

    if cap_grant.is_empty() {
        return None;
    }

    let out = FilterRule {
        src_ips: rule.src_ips.clone(),
        cap_grant,
        ..FilterRule::default()
    };
    Some(out)
}

fn addr_prefix_string(addr: &str) -> Option<String> {
    let (addr, _) = headscale_api_acl::go_netip::parse_addr(addr).ok()?;
    IpNet::new(addr, if addr.is_ipv4() { 32 } else { 128 })
        .ok()
        .map(|net| net.to_string())
}

fn dst_port_ip_string(ip: &str) -> String {
    parse_ip_net(ip).map_or_else(
        || ip.to_string(),
        |net| {
            if is_single_ip(&net) {
                net.addr().to_string()
            } else {
                net.to_string()
            }
        },
    )
}

fn parse_ip_net(value: &str) -> Option<IpNet> {
    if value.contains('/') {
        return parse_prefix_net(value);
    }
    let (ip, _) = headscale_api_acl::go_netip::parse_addr(value).ok()?;
    IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 }).ok()
}

fn parse_prefix_net(value: &str) -> Option<IpNet> {
    let (ip, bits) = headscale_api_acl::go_netip::parse_prefix(value).ok()?;
    IpNet::new(ip, bits).ok()
}

fn is_exit_route(route: &str) -> bool {
    matches!(route, "0.0.0.0/0" | "::/0")
}

fn prefix_contains_addr(prefix: &str, addr: &str) -> bool {
    parse_ip_net(prefix).is_some_and(|net| net_contains_addr(&net, addr))
}

fn ipset_string_contains_addr(ipset: &str, addr: &str) -> bool {
    if prefix_contains_addr(ipset, addr) {
        return true;
    }
    let Some((start, end)) = ipset.split_once('-') else {
        return false;
    };
    let Ok((addr, None)) = headscale_api_acl::go_netip::parse_addr(addr) else {
        return false;
    };
    match (
        headscale_api_acl::go_netip::parse_addr(start).map(|(ip, _)| ip),
        headscale_api_acl::go_netip::parse_addr(end).map(|(ip, _)| ip),
        addr,
    ) {
        (Ok(IpAddr::V4(start)), Ok(IpAddr::V4(end)), IpAddr::V4(addr)) => {
            u32::from(start) <= u32::from(addr) && u32::from(addr) <= u32::from(end)
        }
        (Ok(IpAddr::V6(start)), Ok(IpAddr::V6(end)), IpAddr::V6(addr)) => {
            u128::from(start) <= u128::from(addr) && u128::from(addr) <= u128::from(end)
        }
        _ => false,
    }
}

pub(super) fn ipset_string_to_cidrs(ipset: &str) -> Vec<String> {
    if let Some(net) = parse_ip_net(ipset) {
        return vec![net.to_string()];
    }
    let Some((start, end)) = ipset.split_once('-') else {
        return Vec::new();
    };
    match (
        headscale_api_acl::go_netip::parse_addr(start).map(|(ip, _)| ip),
        headscale_api_acl::go_netip::parse_addr(end).map(|(ip, _)| ip),
    ) {
        (Ok(IpAddr::V4(start)), Ok(IpAddr::V4(end))) => {
            cidrs_for_interval(u32::from(start) as u128, u32::from(end) as u128, 32)
        }
        (Ok(IpAddr::V6(start)), Ok(IpAddr::V6(end))) => {
            cidrs_for_interval(u128::from(start), u128::from(end), 128)
        }
        _ => Vec::new(),
    }
}

pub(super) fn prefixes_overlap(a: &str, b: &str) -> bool {
    match (parse_ip_net(a), parse_ip_net(b)) {
        (Some(a), Some(b)) => nets_overlap(&a, &b),
        _ => false,
    }
}

fn net_contains_addr(net: &IpNet, addr: &str) -> bool {
    let Ok((addr, zone)) = headscale_api_acl::go_netip::parse_addr(addr) else {
        return false;
    };
    if zone.is_some() {
        return false;
    }
    match (net, addr) {
        (IpNet::V4(v4), IpAddr::V4(addr)) => v4.contains(&addr),
        (IpNet::V6(v6), IpAddr::V6(addr)) => v6.contains(&addr),
        _ => false,
    }
}

fn nets_overlap(a: &IpNet, b: &IpNet) -> bool {
    let (a_bits, a_start, a_end) = ipnet_interval(a);
    let (b_bits, b_start, b_end) = ipnet_interval(b);
    a_bits == b_bits && a_start <= b_end && b_start <= a_end
}

fn is_single_ip(net: &IpNet) -> bool {
    match net {
        IpNet::V4(v4) => v4.prefix_len() == 32,
        IpNet::V6(v6) => v6.prefix_len() == 128,
    }
}

fn append_coalesced_filter_rule(out: &mut Vec<FilterRule>, rule: FilterRule) {
    // Go mergeFilterRules keys the ordered SrcIPs/IPProto slices, appends
    // DstPorts unchanged and passes CapGrant rules through unchanged.
    if !rule.cap_grant.is_empty() {
        out.push(rule);
        return;
    }
    if let Some(existing) = out.iter_mut().find(|existing| {
        existing.cap_grant.is_empty()
            && existing.src_ips == rule.src_ips
            && existing.ip_proto == rule.ip_proto
    }) {
        existing.dst_ports.extend(rule.dst_ports);
    } else {
        out.push(rule);
    }
}

pub(super) fn coalesce_filter_rules(rules: Vec<FilterRule>) -> Vec<FilterRule> {
    let mut out = Vec::new();
    for rule in rules {
        append_coalesced_filter_rule(&mut out, rule);
    }
    out
}

fn aggregate_prefixes(values: &[String]) -> Vec<String> {
    super::matcher::IpSet::from_strings(values.iter().map(String::as_str)).strings()
}

pub(super) fn ipnet_interval(net: &IpNet) -> (u8, u128, u128) {
    match net {
        IpNet::V4(v4) => {
            let start = u32::from(v4.network()) as u128;
            let host_bits = 32 - v4.prefix_len();
            let size = 1u128 << host_bits;
            (32, start, start + size - 1)
        }
        IpNet::V6(v6) => {
            let start = u128::from(v6.network());
            if v6.prefix_len() == 0 {
                (128, 0, u128::MAX)
            } else {
                let host_bits = 128 - v6.prefix_len();
                let size = 1u128 << host_bits;
                (128, start, start + size - 1)
            }
        }
    }
}

pub(super) fn interval_ipset_string(start: u128, end: u128, bits: u8) -> String {
    if start == end {
        return interval_addr_string(start, bits);
    }
    let cidrs = cidrs_for_interval(start, end, bits);
    if cidrs.len() == 1 {
        return cidrs.into_iter().next().unwrap();
    }
    format!(
        "{}-{}",
        interval_addr_string(start, bits),
        interval_addr_string(end, bits)
    )
}

pub(super) fn cidrs_for_interval(mut start: u128, end: u128, bits: u8) -> Vec<String> {
    if bits == 128 && start == 0 && end == u128::MAX {
        return vec!["::/0".to_string()];
    }
    let mut out = Vec::new();
    while start <= end {
        let mut chosen_prefix = bits;
        for prefix_len in 0..=bits {
            let Some(size) = block_size(bits, prefix_len) else {
                continue;
            };
            if start.is_multiple_of(size) && start.saturating_add(size - 1) <= end {
                chosen_prefix = prefix_len;
                break;
            }
        }
        let size = block_size(bits, chosen_prefix).unwrap_or(1);
        out.push(interval_prefix_string(start, bits, chosen_prefix));
        if end - start < size {
            break;
        }
        start += size;
    }
    out
}

fn block_size(bits: u8, prefix_len: u8) -> Option<u128> {
    let host_bits = bits - prefix_len;
    if host_bits == 128 {
        None
    } else {
        Some(1u128 << host_bits)
    }
}

fn interval_prefix_string(start: u128, bits: u8, prefix_len: u8) -> String {
    let addr = interval_addr(start, bits);
    IpNet::new(addr, prefix_len)
        .expect("valid aggregate prefix")
        .to_string()
}

fn interval_addr_string(value: u128, bits: u8) -> String {
    interval_addr(value, bits).to_string()
}

fn interval_addr(value: u128, bits: u8) -> IpAddr {
    if bits == 32 {
        IpAddr::V4((value as u32).into())
    } else {
        IpAddr::V6(value.into())
    }
}

fn push_unique_string(out: &mut Vec<String>, value: String) {
    if !out.contains(&value) {
        out.push(value);
    }
}

fn normalize_grant_ip_specs(specs: &[String]) -> Vec<String> {
    specs
        .iter()
        .flat_map(|spec| {
            headscale_api_acl::go_policy_shape::grant_ip_patterns(spec).unwrap_or_default()
        })
        .collect()
}

/// Map an ACL port pattern (`tcp/22`, `udp/*`, `*/*`, or the legacy
/// `*:tcp/22`) onto a Tailscale `PortRange`.
///
/// Returns `None` for syntactically invalid patterns — the caller
/// drops the entry, keeping the policy strictly less permissive
/// than the operator intended (default-deny on garbage).
fn port_pattern_to_range(pat: &str) -> Option<PortRange> {
    let pat = pat.strip_prefix("*:").unwrap_or(pat);
    let (_proto, port_part) = pat.split_once('/').unwrap_or((pat, "*"));
    if port_part == "*" {
        return Some(PortRange {
            first: 0,
            last: 65535,
        });
    }
    if let Some((lo, hi)) = port_part.split_once('-') {
        let lo: u16 = lo.parse().ok()?;
        let hi: u16 = hi.parse().ok()?;
        if hi < lo {
            return None;
        }
        return Some(PortRange {
            first: lo,
            last: hi,
        });
    }
    let p: u16 = port_part.parse().ok()?;
    Some(PortRange { first: p, last: p })
}

fn compile_port_groups(ports: &[String]) -> Vec<(Vec<i32>, Vec<PortRange>)> {
    if ports.is_empty() {
        return vec![(
            Vec::new(),
            vec![PortRange {
                first: 0,
                last: 65535,
            }],
        )];
    }

    let mut groups: Vec<PortGroup> = Vec::new();
    for pattern in ports {
        let (Some(range), Some(protocol)) = (
            port_pattern_to_range(pattern),
            ip_proto_for_pattern(pattern),
        ) else {
            continue;
        };
        if let Some((_, ranges)) = groups.iter_mut().find(|(proto, _)| *proto == protocol) {
            ranges.push(range);
        } else {
            groups.push((protocol, vec![range]));
        }
    }
    groups
}

fn compile_grant_port_groups(specs: &[String]) -> Vec<PortGroup> {
    specs
        .iter()
        .flat_map(|spec| {
            let ports = normalize_grant_ip_specs(std::slice::from_ref(spec));
            if ports.is_empty() {
                Vec::new()
            } else {
                compile_port_groups(&ports)
            }
        })
        .collect()
}

fn ip_proto_for_pattern(pat: &str) -> Option<Vec<i32>> {
    let pat = pat.strip_prefix("*:").unwrap_or(pat);
    let (proto_part, _port_part) = pat.split_once('/').unwrap_or((pat, "*"));
    if proto_part == "*" {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    append_protocol_numbers(proto_part, &mut out)?;
    Some(out)
}

fn append_protocol_numbers(proto: &str, out: &mut Vec<i32>) -> Option<()> {
    let lower = proto.to_ascii_lowercase();
    let nums: &[i32] = match lower.as_str() {
        "" => &[],
        "icmp" => &[1],
        "igmp" => &[2],
        "ipv4" | "ip-in-ip" => &[4],
        "tcp" => &[6],
        "egp" => &[8],
        "igp" => &[9],
        "udp" => &[17],
        "gre" => &[47],
        "esp" => &[50],
        "ah" => &[51],
        "ipv6-icmp" => &[58],
        "sctp" => &[132],
        "fc" => &[133],
        _ => {
            let n: i32 = lower.parse().ok()?;
            if !(0..=255).contains(&n) {
                return None;
            }
            push_unique(out, n);
            return Some(());
        }
    };
    for n in nums {
        push_unique(out, *n);
    }
    Some(())
}

fn push_unique(out: &mut Vec<i32>, n: i32) {
    if !out.contains(&n) {
        out.push(n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{AutoApprovers, PolicyAction, PolicyDoc, PolicyRule};
    use std::collections::BTreeMap;

    fn doc(rules: Vec<PolicyRule>, groups: BTreeMap<String, Vec<String>>) -> PolicyDoc {
        PolicyDoc {
            users: None,
            version: 1,
            groups,
            tags: BTreeMap::new(),
            tag_owners: BTreeMap::new(),
            hosts: BTreeMap::new(),
            auto_approvers: AutoApprovers::default(),
            node_attrs: Vec::new(),
            grants: Vec::new(),
            randomize_client_port: false,
            ssh: Vec::new(),
            tests: Vec::new(),
            ssh_tests: Vec::new(),
            rules,
        }
    }

    #[test]
    fn allow_all_emits_wildcard_rule() {
        let d = doc(
            vec![PolicyRule {
                action: PolicyAction::Accept,
                src: vec!["*".into()],
                dst: vec!["*".into()],
                ports: vec!["*/*".into()],
            }],
            BTreeMap::new(),
        );
        let rs = acl_to_filter_rules(&d);
        assert_eq!(rs.len(), 1);
        // headscale-go v0.29.5 renders the wildcard source IPSet with
        // ipSetToStrings over IPSet.Ranges(), i.e. ascending address order
        // (policy/v2/filter_test.go expects exactly this order).
        assert_eq!(
            rs[0].src_ips,
            vec![
                "100.64.0.0-100.115.91.255",
                "100.115.94.0-100.127.255.255",
                "fd7a:115c:a1e0::/48",
            ]
        );
        assert_eq!(rs[0].dst_ports.len(), 1);
        assert_eq!(rs[0].dst_ports[0].ip, "*");
        assert_eq!(rs[0].dst_ports[0].ports.first, 0);
        assert_eq!(rs[0].dst_ports[0].ports.last, 65535);
        assert!(rs[0].ip_proto.is_empty());
    }

    #[test]
    fn tcp_udp_ports_emit_headscale_go_default_ip_proto() {
        let d = doc(
            vec![PolicyRule {
                action: PolicyAction::Accept,
                src: vec!["100.64.0.1/32".into()],
                dst: vec!["100.64.0.2/32".into()],
                ports: vec!["tcp/22".into(), "udp/22".into()],
            }],
            BTreeMap::new(),
        );
        let rs = acl_to_filter_rules(&d);
        // headscale-go v0.29.5 emits one FilterRule per protocol
        // (compileOtherDests: IPProto = ipp.Protocol.toIANAProtocolNumbers())
        // and mergeFilterRules only merges rules whose SrcIPs *and* IPProto
        // match, so tcp:22 + udp:22 stay two rules. Confirmed with the
        // differential harness's Go side (grant `ip: ["tcp:22", "udp:22"]`
        // and two single-proto ACLs both yield [6] and [17] rules).
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[0].dst_ports.len(), 1);
        assert_eq!(rs[0].dst_ports[0].ip, "100.64.0.2");
        assert_eq!(rs[0].dst_ports[0].ports.first, 22);
        assert_eq!(rs[0].dst_ports[0].ports.last, 22);
        assert_eq!(rs[0].ip_proto, vec![6]);
        assert_eq!(rs[1].dst_ports.len(), 1);
        assert_eq!(rs[1].dst_ports[0].ip, "100.64.0.2");
        assert_eq!(rs[1].dst_ports[0].ports.first, 22);
        assert_eq!(rs[1].dst_ports[0].ports.last, 22);
        assert_eq!(rs[1].ip_proto, vec![17]);
    }

    #[test]
    fn mixed_protocol_ports_do_not_cross_apply() {
        let d = doc(
            vec![PolicyRule {
                action: PolicyAction::Accept,
                src: vec!["100.64.0.1/32".into()],
                dst: vec!["100.64.0.2/32".into()],
                ports: vec!["tcp/22".into(), "udp/53".into()],
            }],
            BTreeMap::new(),
        );
        let rs = acl_to_filter_rules(&d);
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[0].ip_proto, vec![6]);
        assert_eq!(rs[0].dst_ports[0].ports.first, 22);
        assert_eq!(rs[1].ip_proto, vec![17]);
        assert_eq!(rs[1].dst_ports[0].ports.first, 53);
    }

    #[test]
    fn deny_all_emits_empty_list() {
        let d = doc(
            vec![PolicyRule {
                action: PolicyAction::Deny,
                src: vec!["*".into()],
                dst: vec!["*".into()],
                ports: vec!["*/*".into()],
            }],
            BTreeMap::new(),
        );
        let rs = acl_to_filter_rules(&d);
        assert!(rs.is_empty(), "deny rules do not emit FilterRule entries");
    }

    #[test]
    fn src_by_tag_expands_via_group() {
        let mut groups = BTreeMap::new();
        groups.insert(
            "admins".to_string(),
            vec!["100.64.0.10".to_string(), "100.64.0.11".to_string()],
        );
        let d = doc(
            vec![PolicyRule {
                action: PolicyAction::Accept,
                src: vec!["group:admins".into()],
                dst: vec!["*".into()],
                ports: vec!["tcp/22".into()],
            }],
            groups,
        );
        let rs = acl_to_filter_rules(&d);
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].src_ips, vec!["100.64.0.10/31"]);
        assert_eq!(rs[0].dst_ports[0].ports.first, 22);
        assert_eq!(rs[0].dst_ports[0].ports.last, 22);
    }

    #[test]
    fn dst_by_port_range_emits_range_ports() {
        let d = doc(
            vec![PolicyRule {
                action: PolicyAction::Accept,
                src: vec!["*".into()],
                dst: vec!["*".into()],
                ports: vec!["tcp/8000-9000".into()],
            }],
            BTreeMap::new(),
        );
        let rs = acl_to_filter_rules(&d);
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].dst_ports[0].ports.first, 8000);
        assert_eq!(rs[0].dst_ports[0].ports.last, 9000);
    }

    #[test]
    fn dst_by_cidr_round_trips_literal_string() {
        let d = doc(
            vec![PolicyRule {
                action: PolicyAction::Accept,
                src: vec!["*".into()],
                dst: vec!["100.64.0.0/10".into()],
                ports: vec!["tcp/443".into()],
            }],
            BTreeMap::new(),
        );
        let rs = acl_to_filter_rules(&d);
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].dst_ports[0].ip, "100.64.0.0/10");
    }

    #[test]
    fn autogroup_danger_all_acl_source_emits_wildcard_src_ips() {
        let d = crate::policy::parse_hujson_policy(
            r#"{
                "acls": [{
                    "action": "accept",
                    "src": ["autogroup:danger-all"],
                    "dst": ["100.64.0.2:443"]
                }]
            }"#,
        )
        .unwrap();
        let nodes = vec![PacketFilterNode {
            id: 2,
            user_id: Some(2),
            user: Some("server".into()),
            addrs: vec!["100.64.0.2".into()],
            tags: Vec::new(),
            routes: Vec::new(),
        }];

        let rs = acl_to_filter_rules_for_node(&d, &nodes, 2);
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].src_ips, vec!["*"]);
        assert_eq!(rs[0].dst_ports[0].ip, "100.64.0.2");
        assert_eq!(rs[0].dst_ports[0].ports.first, 443);
        assert_eq!(rs[0].dst_ports[0].ports.last, 443);
    }

    #[test]
    fn src_by_user_passes_through_literal() {
        let d = doc(
            vec![PolicyRule {
                action: PolicyAction::Accept,
                src: vec!["octABC123".into()],
                dst: vec!["*".into()],
                ports: vec![],
            }],
            BTreeMap::new(),
        );
        let rs = acl_to_filter_rules(&d);
        assert!(rs.is_empty());
    }

    #[test]
    fn unknown_group_drops_rule() {
        let d = doc(
            vec![PolicyRule {
                action: PolicyAction::Accept,
                src: vec!["group:not_defined".into()],
                dst: vec!["*".into()],
                ports: vec!["*/*".into()],
            }],
            BTreeMap::new(),
        );
        let rs = acl_to_filter_rules(&d);
        assert!(rs.is_empty());
    }

    #[test]
    fn multi_rule_preserves_order() {
        let d = doc(
            vec![
                PolicyRule {
                    action: PolicyAction::Accept,
                    src: vec!["100.64.0.1".into()],
                    dst: vec!["100.64.0.2".into()],
                    ports: vec!["tcp/22".into()],
                },
                PolicyRule {
                    action: PolicyAction::Accept,
                    src: vec!["100.64.0.3".into()],
                    dst: vec!["100.64.0.4".into()],
                    ports: vec!["tcp/80".into()],
                },
            ],
            BTreeMap::new(),
        );
        let rs = acl_to_filter_rules(&d);
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[0].src_ips, vec!["100.64.0.1"]);
        assert_eq!(rs[1].src_ips, vec!["100.64.0.3"]);
    }

    #[test]
    fn app_grants_follow_grant_order_around_projected_network_grants() {
        let d = crate::policy::parse_hujson_policy(
            r#"{
                "grants": [
                    {
                        "src": ["100.64.0.10/32"],
                        "dst": ["100.64.0.2/32"],
                        "app": {"example.com/cap/first": [{}]}
                    },
                    {
                        "src": ["100.64.0.11/32"],
                        "dst": ["100.64.0.3/32"],
                        "ip": ["tcp:80"],
                        "app": {"example.com/cap/second": [{}]}
                    },
                    {
                        "src": ["100.64.0.12/32"],
                        "dst": ["100.64.0.4/32"],
                        "ip": ["tcp:443"]
                    },
                    {
                        "src": ["100.64.0.13/32"],
                        "dst": ["100.64.0.5/32"],
                        "app": {"example.com/cap/third": [{}]}
                    }
                ]
            }"#,
        )
        .unwrap();

        let rs = acl_to_filter_rules(&d);

        assert_eq!(rs.len(), 5);
        assert!(
            rs[0].cap_grant[0]
                .cap_map
                .contains_key("example.com/cap/first")
        );
        assert_eq!(rs[1].dst_ports[0].ports.first, 80);
        assert!(
            rs[2].cap_grant[0]
                .cap_map
                .contains_key("example.com/cap/second")
        );
        assert_eq!(rs[3].dst_ports[0].ports.first, 443);
        assert!(
            rs[4].cap_grant[0]
                .cap_map
                .contains_key("example.com/cap/third")
        );
    }

    #[test]
    fn userless_nodes_do_not_match_member_or_self_packet_filters() {
        let d = doc(
            vec![
                PolicyRule {
                    action: PolicyAction::Accept,
                    src: vec!["autogroup:member".into()],
                    dst: vec!["autogroup:member".into()],
                    ports: vec!["tcp/22".into()],
                },
                PolicyRule {
                    action: PolicyAction::Accept,
                    src: vec!["autogroup:member".into()],
                    dst: vec!["autogroup:self".into()],
                    ports: vec!["tcp/443".into()],
                },
            ],
            BTreeMap::new(),
        );
        let nodes = vec![
            PacketFilterNode {
                id: 1,
                user_id: Some(1),
                user: Some("alice".into()),
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
                routes: Vec::new(),
            },
            PacketFilterNode {
                id: 2,
                user_id: None,
                user: None,
                addrs: vec!["100.64.0.2".into()],
                tags: Vec::new(),
                routes: Vec::new(),
            },
        ];

        // headscale-go v0.29.5 (policy/v2/types.go AutoGroupMember) treats
        // every untagged node as a member, whether or not it has a user, so
        // the userless node is a member source/destination. autogroup:self
        // (compileAutogroupSelf / buildUserNodeIndex) only expands for nodes
        // with a valid user. Confirmed with the differential harness's Go
        // side (a node with no user: alice gets both rules, the userless
        // node only the member rule).
        let rule_shape = |rules: &[FilterRule]| {
            rules
                .iter()
                .map(|rule| {
                    (
                        rule.src_ips.clone(),
                        rule.dst_ports
                            .iter()
                            .map(|dst| (dst.ip.clone(), dst.ports.first, dst.ports.last))
                            .collect::<Vec<_>>(),
                        rule.ip_proto.clone(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let alice_rules = acl_to_filter_rules_for_node(&d, &nodes, 1);
        assert_eq!(
            rule_shape(&alice_rules),
            vec![
                (
                    vec!["100.64.0.1-100.64.0.2".to_string()],
                    vec![("100.64.0.1".to_string(), 22, 22)],
                    vec![6],
                ),
                (
                    vec!["100.64.0.1".to_string()],
                    vec![("100.64.0.1".to_string(), 443, 443)],
                    vec![6],
                ),
            ]
        );

        let userless_rules = acl_to_filter_rules_for_node(&d, &nodes, 2);
        assert_eq!(
            rule_shape(&userless_rules),
            vec![(
                vec!["100.64.0.1-100.64.0.2".to_string()],
                vec![("100.64.0.2".to_string(), 22, 22)],
                vec![6],
            )]
        );
    }

    #[test]
    fn renamed_user_gains_group_scoped_self_filter() {
        let d = doc(
            vec![PolicyRule {
                action: PolicyAction::Accept,
                src: vec!["group:a".into()],
                dst: vec!["autogroup:self".into()],
                ports: vec!["*/*".into()],
            }],
            BTreeMap::from([("group:a".into(), vec!["u1@".into(), "u3@".into()])]),
        );
        let mut nodes = vec![
            PacketFilterNode {
                id: 1,
                user_id: Some(1),
                user: Some("u1".into()),
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
                routes: Vec::new(),
            },
            PacketFilterNode {
                id: 2,
                user_id: Some(2),
                user: Some("x3".into()),
                addrs: vec!["100.64.0.2".into()],
                tags: Vec::new(),
                routes: Vec::new(),
            },
        ];

        assert!(acl_to_filter_rules_for_node(&d, &nodes, 2).is_empty());
        nodes[1].user = Some("u3".into());
        let rules = acl_to_filter_rules_for_node(&d, &nodes, 2);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].src_ips, vec!["100.64.0.2"]);
        assert_eq!(rules[0].dst_ports[0].ip, "100.64.0.2");
    }

    #[test]
    fn autogroup_self_uses_user_id_when_login_name_is_unhydrated() {
        let d = doc(
            vec![PolicyRule {
                action: PolicyAction::Accept,
                src: vec!["autogroup:member".into()],
                dst: vec!["autogroup:self".into()],
                ports: vec!["tcp/22".into()],
            }],
            BTreeMap::new(),
        );
        let nodes = vec![
            PacketFilterNode {
                id: 1,
                user_id: Some(7),
                user: None,
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
                routes: Vec::new(),
            },
            PacketFilterNode {
                id: 2,
                user_id: Some(7),
                user: None,
                addrs: vec!["100.64.0.2".into()],
                tags: Vec::new(),
                routes: Vec::new(),
            },
            PacketFilterNode {
                id: 3,
                user_id: Some(8),
                user: None,
                addrs: vec!["100.64.0.3".into()],
                tags: Vec::new(),
                routes: Vec::new(),
            },
        ];

        let first_rules = acl_to_filter_rules_for_node(&d, &nodes, 1);
        assert_eq!(first_rules.len(), 1);
        assert_eq!(first_rules[0].src_ips, vec!["100.64.0.1-100.64.0.2"]);
        assert_eq!(first_rules[0].dst_ports[0].ip, "100.64.0.1");
        assert_eq!(first_rules[0].dst_ports[0].ports.first, 22);

        let second_rules = acl_to_filter_rules_for_node(&d, &nodes, 2);
        assert_eq!(second_rules.len(), 1);
        assert_eq!(second_rules[0].src_ips, vec!["100.64.0.1-100.64.0.2"]);
        assert_eq!(second_rules[0].dst_ports[0].ip, "100.64.0.2");
    }

    #[test]
    fn app_grant_emits_reduced_cap_grant_for_destination_node() {
        let d = crate::policy::parse_hujson_policy(
            r#"{
                "tagOwners": {"tag:server": ["ops@"]},
                "grants": [{
                    "src": ["client@"],
                    "dst": ["tag:server"],
                    "app": {"example.com/cap/use": [{"mode":"rw"}]}
                }]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            PacketFilterNode {
                id: 1,
                user_id: Some(1),
                user: Some("client".into()),
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
                routes: Vec::new(),
            },
            PacketFilterNode {
                id: 2,
                user_id: Some(2),
                user: Some("ops".into()),
                addrs: vec!["100.64.0.2".into()],
                tags: vec!["tag:server".into()],
                routes: Vec::new(),
            },
        ];

        let rs = acl_to_filter_rules_for_node(&d, &nodes, 2);
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].src_ips, vec!["100.64.0.1"]);
        assert!(rs[0].dst_ports.is_empty());
        assert_eq!(rs[0].cap_grant.len(), 1);
        assert_eq!(rs[0].cap_grant[0].dsts, vec!["100.64.0.2/32"]);
        assert!(
            rs[0].cap_grant[0]
                .cap_map
                .contains_key("example.com/cap/use")
        );
    }

    #[test]
    fn app_grant_star_destination_reduces_to_target_node_caps() {
        let d = crate::policy::parse_hujson_policy(
            r#"{
                "grants": [{
                    "src": ["*"],
                    "dst": ["*"],
                    "app": {"example.com/cap/basic": [{}]}
                }]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            PacketFilterNode {
                id: 1,
                user_id: Some(1),
                user: Some("client".into()),
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
                routes: Vec::new(),
            },
            PacketFilterNode {
                id: 2,
                user_id: Some(2),
                user: Some("server".into()),
                addrs: vec!["100.110.61.78".into(), "fd7a:115c:a1e0::7937:3d4e".into()],
                tags: Vec::new(),
                routes: Vec::new(),
            },
        ];

        let rs = acl_to_filter_rules_for_node(&d, &nodes, 2);

        assert_eq!(rs.len(), 1);
        assert!(rs[0].dst_ports.is_empty());
        assert_eq!(rs[0].cap_grant.len(), 1);
        assert_eq!(
            rs[0].cap_grant[0].dsts,
            vec![
                "100.110.61.78/32".to_string(),
                "fd7a:115c:a1e0::7937:3d4e/128".to_string(),
            ]
        );
        assert!(
            rs[0].cap_grant[0]
                .cap_map
                .contains_key("example.com/cap/basic")
        );
    }

    #[test]
    fn app_grant_emits_upstream_companion_cap_grants() {
        let d = crate::policy::parse_hujson_policy(
            r#"{
                "grants": [{
                    "src": ["client@"],
                    "dst": ["server@"],
                    "app": {
                        "tailscale.com/cap/drive": [{}],
                        "tailscale.com/cap/relay": []
                    }
                }]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            PacketFilterNode {
                id: 1,
                user_id: Some(1),
                user: Some("client".into()),
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
                routes: Vec::new(),
            },
            PacketFilterNode {
                id: 2,
                user_id: Some(2),
                user: Some("server".into()),
                addrs: vec!["100.64.0.2".into()],
                tags: Vec::new(),
                routes: Vec::new(),
            },
        ];

        let server_rules = acl_to_filter_rules_for_node(&d, &nodes, 2);
        assert_eq!(server_rules.len(), 1);
        assert!(
            server_rules[0].cap_grant[0]
                .cap_map
                .contains_key("tailscale.com/cap/drive")
        );
        assert!(
            server_rules[0].cap_grant[0]
                .cap_map
                .contains_key("tailscale.com/cap/relay")
        );

        let client_rules = acl_to_filter_rules_for_node(&d, &nodes, 1);
        let companion_caps = client_rules
            .iter()
            .flat_map(|rule| &rule.cap_grant)
            .flat_map(|grant| grant.cap_map.keys())
            .cloned()
            .collect::<Vec<_>>();
        assert!(companion_caps.contains(&"tailscale.com/cap/drive-sharer".to_string()));
        assert!(companion_caps.contains(&"tailscale.com/cap/relay-target".to_string()));
        assert!(
            client_rules
                .iter()
                .flat_map(|rule| &rule.cap_grant)
                .all(|grant| grant.cap_map.values().all(Option::is_none))
        );
    }

    #[test]
    fn via_grant_emits_per_node_route_filter_for_matching_router() {
        let d = crate::policy::parse_hujson_policy(
            r#"{
                "tagOwners": {"tag:router": ["router@"]},
                "grants": [{
                    "src": ["client@"],
                    "dst": ["10.10.0.0/16"],
                    "ip": ["tcp:443"],
                    "via": ["tag:router"]
                }]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            PacketFilterNode {
                id: 1,
                user_id: Some(1),
                user: Some("client".into()),
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
                routes: Vec::new(),
            },
            PacketFilterNode {
                id: 2,
                user_id: Some(2),
                user: Some("router".into()),
                addrs: vec!["100.64.0.2".into()],
                tags: vec!["tag:router".into()],
                routes: vec!["10.10.1.0/24".into()],
            },
        ];

        let router_rules = acl_to_filter_rules_for_node(&d, &nodes, 2);
        assert_eq!(router_rules.len(), 1);
        assert_eq!(router_rules[0].src_ips, vec!["100.64.0.1"]);
        assert_eq!(router_rules[0].ip_proto, vec![6]);
        assert_eq!(router_rules[0].dst_ports[0].ip, "10.10.0.0/16");
        assert_eq!(router_rules[0].dst_ports[0].ports.first, 443);

        let client_rules = acl_to_filter_rules_for_node(&d, &nodes, 1);
        assert!(client_rules.is_empty());
    }

    #[test]
    fn autogroup_danger_all_via_grant_source_emits_wildcard_src_ips() {
        let d = crate::policy::parse_hujson_policy(
            r#"{
                "tagOwners": {"tag:router": ["router@"]},
                "grants": [{
                    "src": ["autogroup:danger-all"],
                    "dst": ["10.10.0.0/16"],
                    "ip": ["tcp:443"],
                    "via": ["tag:router"]
                }]
            }"#,
        )
        .unwrap();
        let nodes = vec![PacketFilterNode {
            id: 2,
            user_id: Some(2),
            user: Some("router".into()),
            addrs: vec!["100.64.0.2".into()],
            tags: vec!["tag:router".into()],
            routes: vec!["10.10.1.0/24".into()],
        }];

        let router_rules = acl_to_filter_rules_for_node(&d, &nodes, 2);
        assert_eq!(router_rules.len(), 1);
        assert_eq!(router_rules[0].src_ips, vec!["*"]);
        assert_eq!(router_rules[0].dst_ports[0].ip, "10.10.0.0/16");
        assert_eq!(router_rules[0].dst_ports[0].ports.first, 443);
    }
}
