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
//!         IPProto:  []  // empty ⇒ all protocols
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
//! ## Fields intentionally left empty
//!
//! * `IPProto` — the ACL `ports` syntax is `<proto>/<port>` but
//!   stock `tailcfg.FilterRule.IPProto` is a list of IANA protocol
//!   *numbers*. Empty `IPProto` = all protocols, which is what `*/*`
//!   wants. Per-proto filtering is a follow-up.
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

        let port_ranges: Vec<PortRange> = if rule.ports.is_empty() {
            vec![PortRange {
                first: 0,
                last: 65535,
            }]
        } else {
            rule.ports
                .iter()
                .filter_map(|p| port_pattern_to_range(p))
                .collect()
        };
        if port_ranges.is_empty() {
            continue;
        }

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
            src_ips,
            dst_ports,
            ip_proto: Vec::new(),
        });
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
