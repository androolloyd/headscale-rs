// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause

//! MatchFromFilterRule and Node.CanAccess{,Route} at Headscale v0.29.5.
//! Peer visibility ignores ports/protocols and includes CapGrant destinations.

use std::net::IpAddr;

use ipnet::IpNet;

use super::{NodeView, PacketFilterNode, filter};
use crate::tailscale_wire::wire::FilterRule;

type Span = (u8, u128, u128);

#[derive(Clone, Default, Eq, PartialEq)]
pub(super) struct IpSet(Vec<Span>);

fn prefix_span(value: &str) -> Option<Span> {
    let (ip, bits) = headscale_api_acl::go_netip::parse_prefix(value).ok()?;
    Some(filter::ipnet_interval(&IpNet::new(ip, bits).ok()?))
}

fn address_span(ip: IpAddr) -> Span {
    let (family, address) = match ip {
        IpAddr::V4(ip) => (32, u128::from(u32::from(ip))),
        IpAddr::V6(ip) => (128, u128::from(ip)),
    };
    (family, address, address)
}

impl IpSet {
    pub(super) fn from_strings<'a>(values: impl Iterator<Item = &'a str>) -> Self {
        let mut spans = Vec::new();
        for value in values {
            if value == "*" {
                spans.push((32, 0, u128::from(u32::MAX)));
                spans.push((128, 0, u128::MAX));
            } else {
                spans.extend(
                    filter::ipset_string_to_cidrs(value)
                        .iter()
                        .filter_map(|prefix| prefix_span(prefix)),
                );
            }
        }
        Self::from_spans(spans)
    }

    fn from_spans(mut spans: Vec<Span>) -> Self {
        spans.sort_unstable();
        let mut merged: Vec<Span> = Vec::new();
        for (family, start, end) in spans {
            if let Some(last) = merged.last_mut()
                && last.0 == family
                && start <= last.2.saturating_add(1)
            {
                last.2 = last.2.max(end);
            } else {
                merged.push((family, start, end));
            }
        }
        Self(merged)
    }

    /// util.ParseIPSet(value, nil), distinct from typed Prefix/AddPrefix.
    /// Filter CIDRs reject host bits; range endpoints are untrimmed, and Go's
    /// slash/range/address branch order also applies to scoped IPv6 strings.
    pub(super) fn from_filter_string(value: &str) -> Option<Self> {
        if value == "*" {
            return Some(Self(vec![
                (32, 0, u128::from(u32::MAX)),
                (128, 0, u128::MAX),
            ]));
        }
        if value.contains('/') {
            let (ip, bits) = headscale_api_acl::go_netip::parse_prefix(value).ok()?;
            let prefix = IpNet::new(ip, bits).ok()?;
            if prefix.addr() != prefix.network() {
                return None;
            }
            return Some(Self(vec![filter::ipnet_interval(&prefix)]));
        }
        if value.bytes().filter(|byte| *byte == b'-').count() == 1 {
            let (start, end) = value.split_once('-')?;
            let (start, _) = headscale_api_acl::go_netip::parse_addr(start).ok()?;
            let (end, _) = headscale_api_acl::go_netip::parse_addr(end).ok()?;
            let (family, start, _) = address_span(start);
            let (end_family, end, _) = address_span(end);
            if family != end_family || start > end {
                return None;
            }
            return Some(Self(vec![(family, start, end)]));
        }
        let (ip, _) = headscale_api_acl::go_netip::parse_addr(value).ok()?;
        Some(Self(vec![address_span(ip)]))
    }

    fn from_filter_strings<'a>(values: impl Iterator<Item = &'a str>) -> Self {
        Self::from_spans(
            values
                .filter_map(Self::from_filter_string)
                .flat_map(|set| set.0)
                .collect(),
        )
    }

    fn from_prefix_strings<'a>(values: impl Iterator<Item = &'a str>) -> Self {
        Self::from_spans(values.filter_map(prefix_span).collect())
    }

    fn union(mut self, other: Self) -> Self {
        self.0.extend(other.0);
        Self::from_spans(self.0)
    }

    pub(super) fn prefixes(&self) -> Vec<String> {
        self.0
            .iter()
            .flat_map(|&(family, start, end)| filter::cidrs_for_interval(start, end, family))
            .collect()
    }

    pub(super) fn strings(&self) -> Vec<String> {
        self.0
            .iter()
            .map(|&(family, start, end)| filter::interval_ipset_string(start, end, family))
            .collect()
    }

    pub(super) fn contains_ip(&self, address: &str) -> bool {
        let Ok((ip, zone)) = headscale_api_acl::go_netip::parse_addr(address) else {
            return false;
        };
        if zone.is_some() {
            return false;
        }
        let (family, address, _) = address_span(ip);
        self.0
            .iter()
            .any(|&(bits, start, end)| bits == family && start <= address && address <= end)
    }

    pub(super) fn intersects(&self, other: &Self) -> bool {
        let (mut left, mut right) = (0, 0);
        while let (Some(&(family, start, end)), Some(&(bits, lo, hi))) =
            (self.0.get(left), other.0.get(right))
        {
            if family < bits || (family == bits && end < lo) {
                left += 1;
            } else if bits < family || hi < start {
                right += 1;
            } else {
                return true;
            }
        }
        false
    }

    /// Find the first uncovered address without expanding CIDRs into hosts.
    /// Both sets contain sorted, merged intervals, with IPv4 before IPv6.
    pub(super) fn first_not_in(&self, other: &Self) -> Option<String> {
        let address_string = |family: u8, address: u128| {
            if family == 32 {
                IpAddr::V4((address as u32).into()).to_string()
            } else {
                IpAddr::V6(address.into()).to_string()
            }
        };
        let mut right = 0;
        for &(family, start, end) in &self.0 {
            let mut next = start;
            loop {
                let Some(&(bits, lo, hi)) = other.0.get(right) else {
                    return Some(address_string(family, next));
                };
                if bits < family || (bits == family && hi < next) {
                    right += 1;
                    continue;
                }
                if bits > family || lo > next {
                    return Some(address_string(family, next));
                }
                if hi >= end {
                    break;
                }
                // hi < end, so even an IPv6 interval cannot overflow here.
                next = hi + 1;
                right += 1;
            }
        }
        None
    }

    pub(super) fn overlaps_prefix(&self, prefix: &str) -> bool {
        let Some((family, start, end)) = prefix_span(prefix) else {
            return false;
        };
        self.0
            .iter()
            .any(|&(bits, lo, hi)| bits == family && start <= hi && lo <= end)
    }

    fn contains_prefix(&self, prefix: &str) -> bool {
        let Some((family, start, end)) = prefix_span(prefix) else {
            return false;
        };
        self.0
            .iter()
            .any(|&(bits, lo, hi)| bits == family && lo <= start && end <= hi)
    }

    pub(super) fn contains_node(&self, node: &PacketFilterNode) -> bool {
        node.addrs.iter().any(|address| self.contains_ip(address))
    }

    pub(super) fn contains_view(&self, node: &NodeView<'_>) -> bool {
        node.addrs
            .iter()
            .map(String::as_str)
            .chain(node.addr)
            .any(|address| self.contains_ip(address))
    }

    fn overlaps_subnets(&self, node: &PacketFilterNode) -> bool {
        node.routes
            .iter()
            .filter(|route| !is_exit(route))
            .any(|route| self.overlaps_prefix(route))
    }
}

fn is_exit(route: &str) -> bool {
    matches!(route, "0.0.0.0/0" | "::/0")
}

#[derive(Clone)]
pub(super) struct RuleMatcher {
    sources: IpSet,
    destinations: IpSet,
    internet: bool,
}

impl RuleMatcher {
    pub(super) fn from_rules(rules: &[FilterRule]) -> Vec<Self> {
        rules
            .iter()
            .map(|rule| {
                let sources = IpSet::from_filter_strings(rule.src_ips.iter().map(String::as_str));
                let destinations = IpSet::from_filter_strings(
                    rule.dst_ports
                        .iter()
                        .map(|destination| destination.ip.as_str()),
                )
                .union(IpSet::from_prefix_strings(
                    rule.cap_grant
                        .iter()
                        .flat_map(|grant| grant.dsts.iter().map(String::as_str)),
                ));
                let internet = destinations.contains_prefix("0.0.0.0/0")
                    || destinations.contains_prefix("::/0")
                    || headscale_api_acl::internet_filter_cidrs()
                        .iter()
                        .all(|prefix| destinations.contains_prefix(prefix));
                Self {
                    sources,
                    destinations,
                    internet,
                }
            })
            .collect()
    }

    pub(super) fn can_access(
        matchers: &[Self],
        source: &PacketFilterNode,
        target: &PacketFilterNode,
    ) -> bool {
        matchers.iter().any(|matcher| {
            (matcher.sources.contains_node(source) || matcher.sources.overlaps_subnets(source))
                && (matcher.destinations.contains_node(target)
                    || matcher.destinations.overlaps_subnets(target)
                    || (matcher.internet && target.routes.iter().any(|route| is_exit(route))))
        })
    }

    pub(super) fn can_access_route(
        matchers: &[Self],
        source: &PacketFilterNode,
        route: &str,
    ) -> bool {
        matchers.iter().any(|matcher| {
            (matcher.sources.contains_node(source) && matcher.destinations.overlaps_prefix(route))
                || (matcher.sources.overlaps_prefix(route)
                    && matcher.destinations.contains_node(source))
                || (matcher.sources.overlaps_subnets(source)
                    && matcher.destinations.overlaps_prefix(route))
                || (matcher.sources.overlaps_prefix(route)
                    && matcher.destinations.overlaps_subnets(source))
        })
    }
}
