// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause

//! Native v0.29.5 PolicyManager.ViaRoutesForPeer. Resolve each alias against
//! retained policy nodes, then apply ordered steering/election/fallback passes.

use super::{
    PacketFilterNode, PolicyAction, PolicyDoc, PolicyRule, ViaRouteGrantResult, filter,
    matcher::IpSet, resolution,
};

struct Grant<'a> {
    via: &'a [String],
    sources: &'a [String],
    destinations: &'a [String],
}

struct ResolvedGrant<'a> {
    via: &'a [String],
    viewer_matches: bool,
    destinations: Vec<String>,
    internet: bool,
    reaches_internet: bool,
}

fn is_exit(route: &str) -> bool {
    matches!(route, "0.0.0.0/0" | "::/0")
}

pub(super) fn routes_for_peer(
    doc: &PolicyDoc,
    source_acl_rules: &[PolicyRule],
    retained_nodes: &[PacketFilterNode],
    viewer: &PacketFilterNode,
    peer: &PacketFilterNode,
) -> ViaRouteGrantResult {
    let mut result = ViaRouteGrantResult::default();
    if viewer.id == peer.id || !doc.grants.iter().any(|grant| !grant.via.is_empty()) {
        return result;
    }
    // Grants are appended to below, so the collection is needed (stable
    // clippy's `needless_collect` does not see the pushes in between).
    #[allow(clippy::needless_collect)]
    let mut grants = doc
        .grants
        .iter()
        .map(|grant| Grant {
            via: &grant.via,
            sources: &grant.src,
            destinations: &grant.dst,
        })
        .collect::<Vec<_>>();
    // The policy store retains original source ACLs beside public synthetic
    // network-grant projections. Direct typed rules remain explicit ACLs.
    for rule in source_acl_rules
        .iter()
        .filter(|rule| matches!(rule.action, PolicyAction::Accept))
    {
        let non_autogroup = rule.dst.iter().any(|destination| {
            headscale_api_acl::go_policy_shape::alias_kind(destination)
                != Some(headscale_api_acl::go_policy_shape::AliasKind::AutoGroup)
        });
        if non_autogroup {
            for destination in rule
                .dst
                .iter()
                .filter(|destination| destination.as_str() != "autogroup:self")
            {
                grants.push(Grant {
                    via: &[],
                    sources: &rule.src,
                    destinations: std::slice::from_ref(destination),
                });
            }
            for destination in rule
                .dst
                .iter()
                .filter(|destination| destination.as_str() == "autogroup:self")
            {
                grants.push(Grant {
                    via: &[],
                    sources: &rule.src,
                    destinations: std::slice::from_ref(destination),
                });
            }
        } else {
            for destination in &rule.dst {
                grants.push(Grant {
                    via: &[],
                    sources: &rule.src,
                    destinations: std::slice::from_ref(destination),
                });
            }
        }
    }
    let grants = grants
        .into_iter()
        .map(|grant| {
            let viewer_matches = grant.sources.iter().any(|source| {
                let resolved = resolution::alias(doc, source, retained_nodes);
                resolved.errors.is_empty()
                    && resolved.ips.is_some_and(|ips| {
                        IpSet::from_strings(ips.iter().map(String::as_str))
                            .contains_view(&viewer.view())
                    })
            });
            let mut destinations = Vec::new();
            let mut internet = false;
            for destination in grant.destinations {
                if destination == "autogroup:internet" {
                    internet = true;
                    continue;
                }
                let resolved = resolution::alias(doc, destination, retained_nodes);
                if resolved.errors.is_empty()
                    && let Some(ips) = resolved.ips
                {
                    destinations
                        .extend(IpSet::from_strings(ips.iter().map(String::as_str)).prefixes());
                }
            }
            ResolvedGrant {
                via: grant.via,
                viewer_matches,
                destinations,
                internet,
                reaches_internet: grant
                    .destinations
                    .iter()
                    .any(|destination| matches!(destination.as_str(), "*" | "autogroup:internet")),
            }
        })
        .collect::<Vec<_>>();
    // Emit routing facts in destination, then announcement order. Grant dsts
    // authorize a route; the advertised prefix itself is the emitted fact.
    for grant in grants
        .iter()
        .filter(|grant| !grant.via.is_empty() && grant.viewer_matches)
    {
        let mut matched = Vec::new();
        for destination in &grant.destinations {
            for route in peer.routes.iter().filter(|route| !is_exit(route)) {
                if filter::prefixes_overlap(destination, route) {
                    matched.push(route.clone());
                }
            }
        }
        if grant.internet {
            matched.extend(peer.routes.iter().filter(|route| is_exit(route)).cloned());
        }
        let target = if grant.via.iter().any(|tag| peer.tags.contains(tag)) {
            &mut result.include
        } else {
            &mut result.exclude
        };
        target.extend(matched);
    }
    if result.include.is_empty() && result.exclude.is_empty() {
        return result;
    }
    // Lowest-ID election is scoped to via tags and non-exit advertisements.
    // Zero is Go's sentinel, so preserve its update rule rather than min().
    for grant in grants
        .iter()
        .filter(|grant| !grant.via.is_empty() && grant.viewer_matches)
    {
        for destination in &grant.destinations {
            for included in result.include.clone() {
                if !filter::prefixes_overlap(destination, &included) {
                    continue;
                }
                let mut primary = 0;
                for tag in grant.via {
                    for node in retained_nodes {
                        if node.tags.contains(tag)
                            && node
                                .routes
                                .iter()
                                .any(|route| !is_exit(route) && route == &included)
                            && (primary == 0 || node.id < primary)
                        {
                            primary = node.id;
                        }
                    }
                }
                if primary != 0 && peer.id != primary {
                    result.include.retain(|route| route != &included);
                    if !result.exclude.contains(&included) {
                        result.exclude.push(included);
                    }
                }
            }
        }
    }
    // Non-via grants follow via grants, then ACL-to-grant conversions. Keep
    // UsePrimary's first-match order and only relax exit exclusions for an
    // explicit wildcard/internet alias, not an arbitrary overlapping prefix.
    for grant in grants
        .iter()
        .filter(|grant| grant.via.is_empty() && grant.viewer_matches)
    {
        for destination in &grant.destinations {
            for route in &result.include {
                if filter::prefixes_overlap(destination, route)
                    && !result.use_primary.contains(route)
                {
                    result.use_primary.push(route.clone());
                }
            }
            result
                .exclude
                .retain(|route| is_exit(route) || !filter::prefixes_overlap(destination, route));
        }
        if grant.reaches_internet {
            result.exclude.retain(|route| !is_exit(route));
        }
    }
    result
}
