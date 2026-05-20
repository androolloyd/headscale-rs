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
//! Only `accept` rules generate `FilterRule` entries. The Tailscale
//! `filter` matcher treats the list as a deny-by-default allowlist —
//! the canonical ACL engine encodes the same semantics, so the
//! mapping is:
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
//! `expand_principal` (on the canonical [`PolicyDoc`]) handles the
//! SrcIP / DstIP token expansion for groups, hosts, ipsets, and the
//! flattenable autogroups (`internet`, `member`). The
//! non-flattenable autogroups (`self`, `nonroot`, `tagged`, `tag:*`)
//! need per-evaluation NodeView context and cannot be expressed in
//! a static `FilterRule.SrcIPs` list — they're silently dropped from
//! this layer and enforced only by the on-host
//! `headscale-api-acl` evaluator.

use super::{PolicyAction, PolicyDoc};
use crate::tailscale_wire::wire::{FilterRule, NetPortRange, PortRange};

/// Translate a parsed [`PolicyDoc`] into the on-wire
/// `tailcfg.FilterRule` list the stock Tailscale daemon consumes.
///
/// An empty result is significant: it means the policy
/// default-denies everything. The wire layer pins this to an empty
/// `packet_filter` field, which causes the stock daemon to reject
/// every inter-peer packet with `unknown peer` — the intended
/// behaviour for deny-all policies.
pub fn acl_to_filter_rules(doc: &PolicyDoc) -> Vec<FilterRule> {
    let mut out: Vec<FilterRule> = Vec::new();
    for rule in &doc.rules {
        if !matches!(rule.action, PolicyAction::Accept) {
            continue;
        }
        let mut src_ips: Vec<String> = Vec::new();
        for token in &rule.src {
            for entry in doc.expand_principal(token) {
                if !src_ips.contains(&entry) {
                    src_ips.push(entry);
                }
            }
        }
        if src_ips.is_empty() {
            continue;
        }

        let mut dst_ips: Vec<String> = Vec::new();
        for token in &rule.dst {
            for entry in doc.expand_principal(token) {
                if !dst_ips.contains(&entry) {
                    dst_ips.push(entry);
                }
            }
        }
        if dst_ips.is_empty() {
            continue;
        }

        let port_groups = compile_port_groups(&rule.ports);
        if port_groups.is_empty() {
            continue;
        }

        for (ip_proto, port_ranges) in port_groups {
            let mut dst_ports: Vec<NetPortRange> = Vec::new();
            for ip in &dst_ips {
                for r in &port_ranges {
                    dst_ports.push(NetPortRange {
                        ip: ip.clone(),
                        ports: r.clone(),
                    });
                }
            }

            out.push(FilterRule {
                src_ips: src_ips.clone(),
                dst_ports,
                ip_proto,
            });
        }
    }
    out
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

    let mut compiled: Vec<(PortRange, Vec<i32>)> = Vec::new();
    for pat in ports {
        let (Some(range), Some(ip_proto)) = (port_pattern_to_range(pat), ip_proto_for_pattern(pat))
        else {
            continue;
        };

        if let Some((_, existing_proto)) = compiled
            .iter_mut()
            .find(|(existing_range, _)| same_port_range(existing_range, &range))
        {
            merge_ip_proto(existing_proto, &ip_proto);
        } else {
            compiled.push((range, ip_proto));
        }
    }

    let mut groups: Vec<(Vec<i32>, Vec<PortRange>)> = Vec::new();
    for (range, ip_proto) in compiled {
        if let Some((_, ranges)) = groups
            .iter_mut()
            .find(|(existing_proto, _)| *existing_proto == ip_proto)
        {
            ranges.push(range);
        } else {
            groups.push((ip_proto, vec![range]));
        }
    }
    groups
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

fn same_port_range(a: &PortRange, b: &PortRange) -> bool {
    a.first == b.first && a.last == b.last
}

fn merge_ip_proto(existing: &mut Vec<i32>, incoming: &[i32]) {
    if existing.is_empty() || incoming.is_empty() {
        existing.clear();
        return;
    }
    for n in incoming {
        push_unique(existing, *n);
    }
}

fn append_protocol_numbers(proto: &str, out: &mut Vec<i32>) -> Option<()> {
    let lower = proto.to_ascii_lowercase();
    let nums: &[i32] = match lower.as_str() {
        "" => &[6, 17],
        "icmp" => &[1, 58],
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
            if !(1..=255).contains(&n) {
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
            version: 1,
            groups,
            tags: BTreeMap::new(),
            tag_owners: BTreeMap::new(),
            hosts: BTreeMap::new(),
            ipsets: BTreeMap::new(),
            auto_approvers: AutoApprovers::default(),
            node_attrs: Vec::new(),
            ssh: Vec::new(),
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
        assert_eq!(rs[0].src_ips, vec!["*"]);
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
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].dst_ports.len(), 1);
        assert_eq!(rs[0].ip_proto, vec![6, 17]);
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
        assert_eq!(rs[0].src_ips, vec!["100.64.0.10", "100.64.0.11"]);
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
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].src_ips, vec!["octABC123"]);
        assert_eq!(rs[0].dst_ports[0].ports.first, 0);
        assert_eq!(rs[0].dst_ports[0].ports.last, 65535);
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
                    src: vec!["octA".into()],
                    dst: vec!["octB".into()],
                    ports: vec!["tcp/22".into()],
                },
                PolicyRule {
                    action: PolicyAction::Accept,
                    src: vec!["octC".into()],
                    dst: vec!["octD".into()],
                    ports: vec!["tcp/80".into()],
                },
            ],
            BTreeMap::new(),
        );
        let rs = acl_to_filter_rules(&d);
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[0].src_ips, vec!["octA"]);
        assert_eq!(rs[1].src_ips, vec!["octC"]);
    }
}
