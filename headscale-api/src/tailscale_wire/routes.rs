//! Route normalization and primary-route selection shared by the
//! upstream gRPC node slice and tailcfg map emission.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::policy::{NodeView, PolicyStore};
use serde::{Deserialize, Serialize};

fn is_exit_route(prefix: &ipnet::IpNet) -> bool {
    match prefix {
        ipnet::IpNet::V4(net) => net.addr() == Ipv4Addr::UNSPECIFIED && net.prefix_len() == 0,
        ipnet::IpNet::V6(net) => net.addr() == Ipv6Addr::UNSPECIFIED && net.prefix_len() == 0,
    }
}

fn normalize_route_set<I, S>(routes: I, expand_exit_routes: bool) -> Result<Vec<String>, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out = Vec::new();
    for route in routes {
        let route = route.as_ref();
        let prefix = route.parse::<ipnet::IpNet>().map_err(|e| e.to_string())?;
        if expand_exit_routes && is_exit_route(&prefix) {
            out.push("0.0.0.0/0".to_string());
            out.push("::/0".to_string());
        } else {
            out.push(prefix.to_string());
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Normalize operator-supplied route approvals to the canonical form
/// used by Headscale.
///
/// Either default route expands to both IPv4 and IPv6 defaults because
/// Tailscale clients use the pair to mark a node as an exit node.
pub fn normalize_routes<I, S>(routes: I) -> Result<Vec<String>, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    normalize_route_set(routes, true)
}

/// Normalize client-advertised or stored route prefixes without
/// synthesizing the other exit-route family. Headscale-go stores
/// Hostinfo.RoutableIPs exactly as the client reports them; only
/// admin approval expands exit defaults to the pair.
pub fn normalize_advertised_routes<I, S>(routes: I) -> Result<Vec<String>, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    normalize_route_set(routes, false)
}

fn normalize_primary_routes<I, S>(routes: I) -> Result<BTreeSet<String>, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out = BTreeSet::new();
    for route in routes {
        let route = route.as_ref();
        let prefix = route.parse::<ipnet::IpNet>().map_err(|e| e.to_string())?;
        if !is_exit_route(&prefix) {
            out.insert(prefix.to_string());
        }
    }
    Ok(out)
}

fn is_exit_route_str(route: &str) -> bool {
    match route.parse::<ipnet::IpNet>() {
        Ok(prefix) => is_exit_route(&prefix),
        Err(_) => false,
    }
}

/// Stateful primary route selector matching headscale-go's
/// `routes.PrimaryRoutes`.
///
/// Primary route ownership is sticky: when the current primary still
/// advertises and is approved for a prefix, adding a lower-ID node does
/// not steal that prefix. A new primary is selected only when the
/// current primary disappears from the prefix's active route set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrimaryRouteState {
    routes: BTreeMap<u64, BTreeSet<String>>,
    primaries: BTreeMap<String, u64>,
    unhealthy: BTreeSet<u64>,
}

/// Structured primary-route state exposed by headscale-go's
/// `/debug/routes` endpoint.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugRoutes {
    pub available_routes: BTreeMap<u64, Vec<String>>,
    pub primary_routes: BTreeMap<String, u64>,
}

impl PrimaryRouteState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the active routes for one node and return whether the
    /// primary-route assignments changed.
    pub fn set_routes<I, S>(&mut self, node_id: u64, routes: I) -> Result<bool, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let routes = normalize_primary_routes(routes)?;
        if routes.is_empty() {
            self.routes.remove(&node_id);
            self.unhealthy.remove(&node_id);
        } else {
            self.routes.insert(node_id, routes);
        }
        Ok(self.update_primary_locked())
    }

    /// Replace the full active route table while preserving current
    /// primaries that are still valid.
    pub fn sync_routes<I, R, S>(&mut self, nodes: I) -> Result<bool, String>
    where
        I: IntoIterator<Item = (u64, R)>,
        R: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut routes = BTreeMap::new();
        for (node_id, node_routes) in nodes {
            let normalized = normalize_primary_routes(node_routes)?;
            if !normalized.is_empty() {
                routes.insert(node_id, normalized);
            }
        }
        self.routes = routes;
        self.unhealthy
            .retain(|node_id| self.routes.contains_key(node_id));
        Ok(self.update_primary_locked())
    }

    pub fn primary_routes(&self, node_id: u64) -> Vec<String> {
        self.primaries
            .iter()
            .filter_map(|(route, primary)| {
                if *primary == node_id {
                    Some(route.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn primary_route_for(&self, route: &str) -> Option<u64> {
        let route = normalize_primary_routes([route]).ok()?.into_iter().next()?;
        self.primaries.get(&route).copied()
    }

    pub fn debug_routes(&self) -> DebugRoutes {
        DebugRoutes {
            available_routes: self
                .routes
                .iter()
                .map(|(node_id, routes)| (*node_id, routes.iter().cloned().collect()))
                .collect(),
            primary_routes: self.primaries.clone(),
        }
    }

    /// Mark a route candidate healthy or unhealthy and return whether
    /// the primary-route assignments changed.
    pub fn set_node_health(&mut self, node_id: u64, healthy: bool) -> bool {
        let health_changed = if healthy {
            self.unhealthy.remove(&node_id)
        } else {
            self.unhealthy.insert(node_id)
        };

        if !health_changed {
            return false;
        }

        self.update_primary_locked()
    }

    /// Apply several health flips before recalculating primaries.
    pub fn set_node_health_batch<I>(&mut self, updates: I) -> bool
    where
        I: IntoIterator<Item = (u64, bool)>,
    {
        let mut health_changed = false;
        for (node_id, healthy) in updates {
            let changed = if healthy {
                self.unhealthy.remove(&node_id)
            } else {
                self.unhealthy.insert(node_id)
            };
            health_changed |= changed;
        }

        if !health_changed {
            return false;
        }

        self.update_primary_locked()
    }

    /// Clear a stale unhealthy mark without recalculating primaries.
    /// Reconnect paths use this to give a fresh session a clean slate
    /// while preserving sticky ownership by the current healthy primary.
    pub fn clear_unhealthy(&mut self, node_id: u64) {
        self.unhealthy.remove(&node_id);
    }

    pub fn is_node_healthy(&self, node_id: u64) -> bool {
        !self.unhealthy.contains(&node_id)
    }

    pub fn has_routes(&self, node_id: u64) -> bool {
        self.routes
            .get(&node_id)
            .is_some_and(|routes| !routes.is_empty())
    }

    pub fn debug_string(&self) -> String {
        let mut out = String::new();
        for (route, node_id) in &self.primaries {
            let _ = writeln!(out, "{route}: {node_id}");
        }
        out
    }

    fn update_primary_locked(&mut self) -> bool {
        let mut available_by_route: BTreeMap<String, Vec<u64>> = BTreeMap::new();
        for (node_id, routes) in &self.routes {
            for route in routes {
                available_by_route
                    .entry(route.clone())
                    .or_default()
                    .push(*node_id);
            }
        }

        let mut changed = false;
        for (route, nodes) in &available_by_route {
            if let Some(current) = self.primaries.get(route)
                && nodes.contains(current)
                && (!self.unhealthy.contains(current)
                    || nodes.iter().all(|node_id| self.unhealthy.contains(node_id)))
            {
                continue;
            }

            let new_primary = nodes
                .iter()
                .find(|node_id| !self.unhealthy.contains(node_id))
                .or_else(|| {
                    self.primaries
                        .get(route)
                        .filter(|current| nodes.contains(current))
                });
            if let Some(new_primary) = new_primary {
                self.primaries.insert(route.clone(), *new_primary);
                changed = true;
            } else if self.primaries.remove(route).is_some() {
                changed = true;
            }
        }

        let stale: Vec<String> = self
            .primaries
            .keys()
            .filter(|route| !available_by_route.contains_key(*route))
            .cloned()
            .collect();
        for route in stale {
            self.primaries.remove(&route);
            changed = true;
        }

        changed
    }
}

/// Return the approved exit routes that are also currently advertised
/// by a node. Headscale treats exit routes separately from primary
/// subnet routes: they are included in `AllowedIPs`/gRPC serving-route
/// output but never in `PrimaryRoutes`.
pub fn active_exit_routes(available_routes: &[String], approved_routes: &[String]) -> Vec<String> {
    let available = normalize_advertised_routes_lossy(available_routes)
        .into_iter()
        .filter(|route| is_exit_route_str(route))
        .collect::<BTreeSet<_>>();
    normalize_advertised_routes_lossy(approved_routes)
        .into_iter()
        .filter(|route| is_exit_route_str(route) && available.contains(route))
        .collect()
}

/// Return the approved routes that are also currently advertised by a
/// node. Headscale uses this intersection for the active route set.
pub fn active_approved_routes(
    available_routes: &[String],
    approved_routes: &[String],
) -> Vec<String> {
    let available = normalize_advertised_routes_lossy(available_routes)
        .into_iter()
        .collect::<BTreeSet<_>>();
    normalize_advertised_routes_lossy(approved_routes)
        .into_iter()
        .filter(|route| available.contains(route))
        .collect()
}

/// Return active approved subnet routes. Exit routes are served
/// separately from primary-route election.
pub fn active_primary_routes(
    available_routes: &[String],
    approved_routes: &[String],
) -> Vec<String> {
    active_approved_routes(available_routes, approved_routes)
        .into_iter()
        .filter(|route| !is_exit_route_str(route))
        .collect()
}

/// Preserve existing approved routes and add newly announced routes
/// that the loaded policy auto-approves for this node.
///
/// Mirrors headscale-go `policy.ApproveRoutesWithPolicy`: existing
/// approvals are never removed here; only an explicit operator action
/// clears them.
pub(crate) fn auto_approved_routes_for_node(
    policy: &PolicyStore,
    addr: &str,
    user: Option<&str>,
    tags: &[String],
    current_approved: &[String],
    announced_routes: &[String],
) -> Result<Vec<String>, String> {
    let mut approved = normalize_advertised_routes(current_approved)?;
    let announced = normalize_advertised_routes(announced_routes)?;
    let view = NodeView {
        addr: Some(addr),
        addrs: &[],
        user,
        tags,
    };

    for route in announced {
        if approved.contains(&route) {
            continue;
        }
        let can_approve = if is_exit_route_str(&route) {
            policy.auto_approves_exit_node(&view)
        } else {
            policy.auto_approves_route(&view, &route)
        };
        if can_approve {
            approved.push(route);
        }
    }

    approved.sort();
    approved.dedup();
    Ok(approved)
}

/// Compute the active primary subnet routes per node from a fresh
/// snapshot. This helper is deterministic for stateless callers; live
/// runtime code should hold a [`PrimaryRouteState`] so promotion stays
/// sticky across updates.
pub fn primary_routes_by_node<'a, I>(nodes: I) -> BTreeMap<String, Vec<String>>
where
    I: IntoIterator<Item = (&'a str, u64, &'a [String], &'a [String])>,
{
    let mut keys_by_id = BTreeMap::<u64, String>::new();
    let mut active_by_id = Vec::new();

    for (node_key, node_id, available_routes, approved_routes) in nodes {
        keys_by_id
            .entry(node_id)
            .or_insert_with(|| node_key.to_string());
        active_by_id.push((
            node_id,
            active_primary_routes(available_routes, approved_routes),
        ));
    }

    let mut state = PrimaryRouteState::new();
    if state.sync_routes(active_by_id).is_err() {
        return BTreeMap::new();
    }

    keys_by_id
        .into_iter()
        .filter_map(|(node_id, node_key)| {
            let routes = state.primary_routes(node_id);
            if routes.is_empty() {
                None
            } else {
                Some((node_key, routes))
            }
        })
        .collect()
}

fn normalize_advertised_routes_lossy(routes: &[String]) -> Vec<String> {
    normalize_advertised_routes(routes).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(routes: &[&str]) -> Vec<String> {
        routes.iter().map(|route| (*route).to_string()).collect()
    }

    fn stored_routes(state: &PrimaryRouteState) -> BTreeMap<u64, Vec<String>> {
        state
            .routes
            .iter()
            .map(|(node_id, routes)| (*node_id, routes.iter().cloned().collect()))
            .collect()
    }

    fn primaries(state: &PrimaryRouteState) -> BTreeMap<String, u64> {
        state.primaries.clone()
    }

    fn unhealthy(state: &PrimaryRouteState) -> Vec<u64> {
        state.unhealthy.iter().copied().collect()
    }

    fn map(entries: &[(u64, &[&str])]) -> BTreeMap<u64, Vec<String>> {
        entries
            .iter()
            .map(|(node_id, routes)| (*node_id, p(routes)))
            .collect()
    }

    fn primary_map(entries: &[(&str, u64)]) -> BTreeMap<String, u64> {
        entries
            .iter()
            .map(|(route, node_id)| ((*route).to_string(), *node_id))
            .collect()
    }

    fn assert_primary_state_invariants(
        state: &PrimaryRouteState,
        expected_primaries: &[(&str, u64)],
    ) {
        let expected = primary_map(expected_primaries);
        assert_eq!(primaries(state), expected);

        let debug = state.debug_routes();
        let mut expected_by_node = BTreeMap::<u64, Vec<String>>::new();
        for (route, node_id) in &expected {
            let available = debug
                .available_routes
                .get(node_id)
                .unwrap_or_else(|| panic!("primary node {node_id} missing available routes"));
            assert!(
                available.contains(route),
                "primary node {node_id} no longer advertises {route}"
            );
            expected_by_node
                .entry(*node_id)
                .or_default()
                .push(route.clone());
        }

        for routes in expected_by_node.values_mut() {
            routes.sort();
        }

        let node_ids = [1, 2, 3];
        for node_id in node_ids {
            assert_eq!(
                state.primary_routes(node_id),
                expected_by_node.remove(&node_id).unwrap_or_default(),
                "PrimaryRoutesForNode-style reverse lookup mismatch for node {node_id}"
            );
        }
        assert!(expected_by_node.is_empty());
    }

    #[test]
    fn normalize_routes_expands_exit_routes_and_dedupes() {
        let routes = normalize_routes(["::/0", "0.0.0.0/0", "10.0.0.0/24"]).unwrap();
        assert_eq!(routes, vec!["0.0.0.0/0", "10.0.0.0/24", "::/0"]);
    }

    #[test]
    fn normalize_routes_rejects_empty_or_whitespace_members_like_headscale_go() {
        assert!(normalize_routes([""]).is_err());
        assert!(normalize_routes([" 10.0.0.0/24 "]).is_err());
    }

    #[test]
    fn normalize_advertised_routes_preserves_single_exit_family() {
        assert_eq!(
            normalize_advertised_routes(["0.0.0.0/0"]).unwrap(),
            p(&["0.0.0.0/0"])
        );
        assert_eq!(normalize_advertised_routes(["::/0"]).unwrap(), p(&["::/0"]));
    }

    #[test]
    fn active_routes_intersects_advertised_and_approved() {
        let available = vec!["10.0.0.0/24".to_string()];
        let approved = vec!["10.0.0.0/24".to_string(), "10.1.0.0/24".to_string()];
        assert_eq!(
            active_approved_routes(&available, &approved),
            vec!["10.0.0.0/24"]
        );
    }

    #[test]
    fn auto_approvals_preserve_current_unadvertised_approvals() {
        let policy = PolicyStore::new();
        let approved = auto_approved_routes_for_node(
            &policy,
            "100.64.0.8",
            Some("alice"),
            &[],
            &p(&["10.99.0.0/24"]),
            &p(&["10.40.0.0/24"]),
        )
        .unwrap();

        assert_eq!(approved, p(&["10.99.0.0/24"]));
    }

    #[test]
    fn auto_approvals_compact_duplicate_current_approvals_and_keep_empty_inputs() {
        let policy = PolicyStore::new();
        let approved = auto_approved_routes_for_node(
            &policy,
            "100.64.0.8",
            Some("alice"),
            &[],
            &p(&["10.99.0.0/24", "10.99.0.0/24"]),
            &[],
        )
        .unwrap();

        assert_eq!(approved, p(&["10.99.0.0/24"]));
        assert_eq!(
            auto_approved_routes_for_node(&policy, "100.64.0.8", Some("alice"), &[], &[], &[])
                .unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn active_exit_routes_are_separate_from_primary_routes() {
        let available = p(&["0.0.0.0/0", "::/0", "10.0.0.0/24"]);
        let approved = p(&["0.0.0.0/0", "10.0.0.0/24"]);
        assert_eq!(active_exit_routes(&available, &approved), p(&["0.0.0.0/0"]));

        let mut state = PrimaryRouteState::new();
        let changed = state
            .set_routes(1, active_approved_routes(&available, &approved))
            .unwrap();
        assert!(changed);
        assert_eq!(state.primary_routes(1), p(&["10.0.0.0/24"]));
    }

    #[test]
    fn primary_routes_choose_lowest_node_id_for_conflict() {
        let available = vec!["10.0.0.0/24".to_string()];
        let approved = vec!["10.0.0.0/24".to_string()];
        let primary = primary_routes_by_node([
            ("node-b", 20, available.as_slice(), approved.as_slice()),
            ("node-a", 10, available.as_slice(), approved.as_slice()),
        ]);
        assert_eq!(
            primary.get("node-a").cloned().unwrap_or_default(),
            vec!["10.0.0.0/24"]
        );
        assert!(!primary.contains_key("node-b"));
    }

    #[test]
    fn primary_route_for_normalizes_subnet_and_rejects_exit_routes() {
        let mut state = PrimaryRouteState::new();
        state
            .sync_routes([
                (20, p(&["10.0.0.0/24", "0.0.0.0/0"])),
                (10, p(&["10.0.0.0/24"])),
            ])
            .unwrap();

        assert_eq!(state.primary_route_for("10.0.0.0/24"), Some(10));
        assert_eq!(state.primary_route_for(" 10.0.0.0/24 "), None);
        assert_eq!(state.primary_route_for("0.0.0.0/0"), None);
        assert_eq!(state.primary_route_for("not-a-prefix"), None);
    }

    #[test]
    fn primary_route_state_matches_headscale_go_cases() {
        struct Case {
            name: &'static str,
            ops: &'static [(u64, &'static [&'static str])],
            expected_change: bool,
            expected_routes: BTreeMap<u64, Vec<String>>,
            expected_primaries: BTreeMap<String, u64>,
        }

        let cases = vec![
            Case {
                name: "single-node-registers-single-route",
                ops: &[(1, &["192.168.1.0/24"])],
                expected_change: true,
                expected_routes: map(&[(1, &["192.168.1.0/24"])]),
                expected_primaries: primary_map(&[("192.168.1.0/24", 1)]),
            },
            Case {
                name: "multiple-nodes-register-different-routes",
                ops: &[(1, &["192.168.1.0/24"]), (2, &["192.168.2.0/24"])],
                expected_change: true,
                expected_routes: map(&[(1, &["192.168.1.0/24"]), (2, &["192.168.2.0/24"])]),
                expected_primaries: primary_map(&[("192.168.1.0/24", 1), ("192.168.2.0/24", 2)]),
            },
            Case {
                name: "multiple-nodes-register-overlapping-routes",
                ops: &[(1, &["192.168.1.0/24"]), (2, &["192.168.1.0/24"])],
                expected_change: false,
                expected_routes: map(&[(1, &["192.168.1.0/24"]), (2, &["192.168.1.0/24"])]),
                expected_primaries: primary_map(&[("192.168.1.0/24", 1)]),
            },
            Case {
                name: "node-deregisters-a-route",
                ops: &[(1, &["192.168.1.0/24"]), (1, &[])],
                expected_change: true,
                expected_routes: BTreeMap::new(),
                expected_primaries: BTreeMap::new(),
            },
            Case {
                name: "node-deregisters-one-of-multiple-routes",
                ops: &[
                    (1, &["192.168.1.0/24", "192.168.2.0/24"]),
                    (1, &["192.168.2.0/24"]),
                ],
                expected_change: true,
                expected_routes: map(&[(1, &["192.168.2.0/24"])]),
                expected_primaries: primary_map(&[("192.168.2.0/24", 1)]),
            },
            Case {
                name: "node-registers-and-deregisters-routes-in-sequence",
                ops: &[
                    (1, &["192.168.1.0/24"]),
                    (2, &["192.168.2.0/24"]),
                    (1, &[]),
                    (1, &["192.168.3.0/24"]),
                ],
                expected_change: true,
                expected_routes: map(&[(1, &["192.168.3.0/24"]), (2, &["192.168.2.0/24"])]),
                expected_primaries: primary_map(&[("192.168.2.0/24", 2), ("192.168.3.0/24", 1)]),
            },
            Case {
                name: "multiple-nodes-register-same-route",
                ops: &[
                    (1, &["192.168.1.0/24"]),
                    (2, &["192.168.1.0/24"]),
                    (3, &["192.168.1.0/24"]),
                ],
                expected_change: false,
                expected_routes: map(&[
                    (1, &["192.168.1.0/24"]),
                    (2, &["192.168.1.0/24"]),
                    (3, &["192.168.1.0/24"]),
                ]),
                expected_primaries: primary_map(&[("192.168.1.0/24", 1)]),
            },
            Case {
                name: "register-multiple-routes-shift-primary-check-primary",
                ops: &[
                    (1, &["192.168.1.0/24"]),
                    (2, &["192.168.1.0/24"]),
                    (3, &["192.168.1.0/24"]),
                    (1, &[]),
                ],
                expected_change: true,
                expected_routes: map(&[(2, &["192.168.1.0/24"]), (3, &["192.168.1.0/24"])]),
                expected_primaries: primary_map(&[("192.168.1.0/24", 2)]),
            },
            Case {
                name: "primary-route-map-is-cleared-up",
                ops: &[
                    (1, &["192.168.1.0/24"]),
                    (2, &["192.168.1.0/24"]),
                    (3, &["192.168.1.0/24"]),
                    (1, &[]),
                    (2, &[]),
                ],
                expected_change: true,
                expected_routes: map(&[(3, &["192.168.1.0/24"])]),
                expected_primaries: primary_map(&[("192.168.1.0/24", 3)]),
            },
            Case {
                name: "primary-route-map-is-cleared-up-all-no-primary",
                ops: &[
                    (1, &["192.168.1.0/24"]),
                    (2, &["192.168.1.0/24"]),
                    (3, &["192.168.1.0/24"]),
                    (1, &[]),
                    (2, &[]),
                    (3, &[]),
                ],
                expected_change: true,
                expected_routes: BTreeMap::new(),
                expected_primaries: BTreeMap::new(),
            },
            Case {
                name: "primary-route-no-flake",
                ops: &[
                    (1, &["192.168.1.0/24"]),
                    (2, &["192.168.1.0/24"]),
                    (3, &["192.168.1.0/24"]),
                    (1, &[]),
                    (1, &["192.168.1.0/24"]),
                ],
                expected_change: false,
                expected_routes: map(&[
                    (1, &["192.168.1.0/24"]),
                    (2, &["192.168.1.0/24"]),
                    (3, &["192.168.1.0/24"]),
                ]),
                expected_primaries: primary_map(&[("192.168.1.0/24", 2)]),
            },
            Case {
                name: "primary-route-no-flake-full-integration",
                ops: &[
                    (1, &["192.168.1.0/24"]),
                    (2, &["192.168.1.0/24"]),
                    (3, &["192.168.1.0/24"]),
                    (1, &[]),
                    (2, &[]),
                    (1, &["192.168.1.0/24"]),
                    (2, &["192.168.1.0/24"]),
                    (1, &[]),
                    (1, &["192.168.1.0/24"]),
                ],
                expected_change: false,
                expected_routes: map(&[
                    (1, &["192.168.1.0/24"]),
                    (2, &["192.168.1.0/24"]),
                    (3, &["192.168.1.0/24"]),
                ]),
                expected_primaries: primary_map(&[("192.168.1.0/24", 3)]),
            },
            Case {
                name: "multiple-nodes-register-same-route-and-exit",
                ops: &[
                    (1, &["0.0.0.0/0", "192.168.1.0/24"]),
                    (2, &["192.168.1.0/24"]),
                ],
                expected_change: false,
                expected_routes: map(&[(1, &["192.168.1.0/24"]), (2, &["192.168.1.0/24"])]),
                expected_primaries: primary_map(&[("192.168.1.0/24", 1)]),
            },
            Case {
                name: "deregister-non-existent-route",
                ops: &[(1, &[])],
                expected_change: false,
                expected_routes: BTreeMap::new(),
                expected_primaries: BTreeMap::new(),
            },
            Case {
                name: "exit-nodes",
                ops: &[
                    (1, &["10.0.0.0/16", "0.0.0.0/0", "::/0"]),
                    (3, &["0.0.0.0/0", "::/0"]),
                    (2, &["0.0.0.0/0", "::/0"]),
                ],
                expected_change: false,
                expected_routes: map(&[(1, &["10.0.0.0/16"])]),
                expected_primaries: primary_map(&[("10.0.0.0/16", 1)]),
            },
        ];

        for case in cases {
            let mut state = PrimaryRouteState::new();
            let mut changed = false;
            for (node_id, routes) in case.ops {
                changed = state.set_routes(*node_id, routes.iter().copied()).unwrap();
            }
            assert_eq!(changed, case.expected_change, "{}", case.name);
            assert_eq!(stored_routes(&state), case.expected_routes, "{}", case.name);
            assert_eq!(primaries(&state), case.expected_primaries, "{}", case.name);
        }
    }

    #[test]
    fn unhealthy_current_primary_fails_over() {
        let mut state = PrimaryRouteState::new();
        assert!(state.set_routes(1, ["10.0.0.0/24"]).unwrap());
        assert!(!state.set_routes(2, ["10.0.0.0/24"]).unwrap());

        assert!(state.set_node_health(1, false));

        assert_eq!(state.primary_routes(1), Vec::<String>::new());
        assert_eq!(state.primary_routes(2), p(&["10.0.0.0/24"]));
        assert_eq!(primaries(&state), primary_map(&[("10.0.0.0/24", 2)]));
        assert_eq!(unhealthy(&state), vec![1]);
    }

    #[test]
    fn recovered_lower_id_router_does_not_steal_healthy_sticky_primary() {
        let mut state = PrimaryRouteState::new();
        assert!(state.set_routes(1, ["10.0.0.0/24"]).unwrap());
        assert!(!state.set_routes(2, ["10.0.0.0/24"]).unwrap());
        assert!(state.set_node_health(1, false));
        assert_eq!(state.primary_routes(2), p(&["10.0.0.0/24"]));

        assert!(!state.set_node_health(1, true));

        assert_eq!(state.primary_routes(1), Vec::<String>::new());
        assert_eq!(state.primary_routes(2), p(&["10.0.0.0/24"]));
        assert!(unhealthy(&state).is_empty());
    }

    #[test]
    fn all_unhealthy_candidates_retain_last_known_primary() {
        let mut state = PrimaryRouteState::new();
        assert!(state.set_routes(1, ["10.0.0.0/24"]).unwrap());
        assert!(!state.set_routes(2, ["10.0.0.0/24"]).unwrap());
        assert!(state.set_node_health(1, false));
        assert_eq!(state.primary_routes(2), p(&["10.0.0.0/24"]));

        assert!(!state.set_node_health(2, false));

        assert_eq!(state.primary_routes(1), Vec::<String>::new());
        assert_eq!(state.primary_routes(2), p(&["10.0.0.0/24"]));
        assert_eq!(primaries(&state), primary_map(&[("10.0.0.0/24", 2)]));
        assert_eq!(unhealthy(&state), vec![1, 2]);
    }

    #[test]
    fn recovered_secondary_router_keeps_primary_after_all_unhealthy_window() {
        let mut state = PrimaryRouteState::new();
        assert!(state.set_routes(1, ["10.0.0.0/24"]).unwrap());
        assert!(!state.set_routes(2, ["10.0.0.0/24"]).unwrap());
        assert!(state.set_node_health(1, false));
        assert!(!state.set_node_health(2, false));
        assert_eq!(state.primary_routes(2), p(&["10.0.0.0/24"]));

        assert!(!state.set_node_health(2, true));

        assert_eq!(state.primary_routes(1), Vec::<String>::new());
        assert_eq!(state.primary_routes(2), p(&["10.0.0.0/24"]));
        assert_eq!(primaries(&state), primary_map(&[("10.0.0.0/24", 2)]));
        assert_eq!(unhealthy(&state), vec![1]);
    }

    #[test]
    fn all_unhealthy_candidates_after_primary_withdraw_do_not_keep_stale_primary() {
        let mut state = PrimaryRouteState::new();
        assert!(state.set_routes(1, ["10.0.0.0/24"]).unwrap());
        assert!(!state.set_routes(2, ["10.0.0.0/24"]).unwrap());
        assert!(!state.set_node_health(2, false));

        assert!(state.set_routes(1, Vec::<String>::new()).unwrap());

        assert_eq!(state.primary_routes(1), Vec::<String>::new());
        assert_eq!(state.primary_routes(2), Vec::<String>::new());
        assert_eq!(primaries(&state), BTreeMap::new());
        assert_eq!(unhealthy(&state), vec![2]);
    }

    #[test]
    fn all_unhealthy_candidates_for_new_prefix_do_not_elect_primary() {
        let mut state = PrimaryRouteState::new();
        assert!(!state.set_node_health_batch([(1, false), (2, false)]));

        assert!(!state.set_routes(1, ["10.0.0.0/24"]).unwrap());
        assert!(!state.set_routes(2, ["10.0.0.0/24"]).unwrap());

        assert_eq!(state.primary_routes(1), Vec::<String>::new());
        assert_eq!(state.primary_routes(2), Vec::<String>::new());
        assert_eq!(primaries(&state), BTreeMap::new());
        assert_eq!(unhealthy(&state), vec![1, 2]);
    }

    #[test]
    fn primary_route_sequence_preserves_go_property_invariants() {
        let mut state = PrimaryRouteState::new();

        assert!(state.set_routes(1, ["10.0.0.0/24", "10.0.1.0/24"]).unwrap());
        assert_primary_state_invariants(&state, &[("10.0.0.0/24", 1), ("10.0.1.0/24", 1)]);

        assert!(!state.set_routes(2, ["10.0.0.0/24"]).unwrap());
        assert_primary_state_invariants(&state, &[("10.0.0.0/24", 1), ("10.0.1.0/24", 1)]);

        assert!(state.set_node_health(1, false));
        assert_primary_state_invariants(&state, &[("10.0.0.0/24", 2), ("10.0.1.0/24", 1)]);

        assert!(state.set_routes(3, ["10.0.1.0/24"]).unwrap());
        assert_primary_state_invariants(&state, &[("10.0.0.0/24", 2), ("10.0.1.0/24", 3)]);

        assert!(!state.set_node_health(1, true));
        assert_primary_state_invariants(&state, &[("10.0.0.0/24", 2), ("10.0.1.0/24", 3)]);

        assert!(state.set_routes(2, Vec::<String>::new()).unwrap());
        assert_primary_state_invariants(&state, &[("10.0.0.0/24", 1), ("10.0.1.0/24", 3)]);

        assert!(state.set_routes(1, ["10.0.1.0/24"]).unwrap());
        assert_primary_state_invariants(&state, &[("10.0.1.0/24", 3)]);
        assert_eq!(state.primary_route_for("10.0.0.0/24"), None);
    }

    #[test]
    fn debug_routes_reflects_primary_route_state_and_filters_exit_routes() {
        let mut state = PrimaryRouteState::new();
        state
            .sync_routes([
                (2, p(&["10.0.0.0/24", "0.0.0.0/0"])),
                (1, p(&["10.0.0.0/24", "10.1.0.0/24"])),
            ])
            .unwrap();

        assert_eq!(
            state.debug_routes(),
            DebugRoutes {
                available_routes: BTreeMap::from([
                    (1, p(&["10.0.0.0/24", "10.1.0.0/24"])),
                    (2, p(&["10.0.0.0/24"])),
                ]),
                primary_routes: primary_map(&[("10.0.0.0/24", 1), ("10.1.0.0/24", 1)]),
            }
        );
        assert_eq!(state.debug_string(), "10.0.0.0/24: 1\n10.1.0.0/24: 1\n");
    }
}
