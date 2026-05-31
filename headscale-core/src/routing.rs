//! CIDR-aware routing with longest prefix match (LPM).
//!
//! This module provides a routing table that supports subnet routes and
//! longest-prefix-match lookups, enabling exit nodes and subnet routing.

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::collections::HashMap;
use std::net::IpAddr;

/// A route entry in the routing table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// The network prefix this route covers.
    pub prefix: IpNet,
    /// The peer that handles this route.
    pub peer_id: String,
    /// Route priority (lower = higher priority for same prefix length).
    pub priority: u32,
    /// Whether this route was approved by admin.
    pub approved: bool,
    /// Whether this is an advertised route (vs a peer's mesh IP).
    pub advertised: bool,
}

/// A routing table with longest-prefix-match support.
///
/// Routes are stored in a simple structure optimized for correctness.
/// For high-performance routing with thousands of routes, consider
/// replacing with a proper trie (e.g., `ip_network_table` crate).
#[derive(Debug, Default)]
pub struct RoutingTable {
    /// IPv4 routes, sorted by prefix length (longest first).
    ipv4_routes: Vec<Route>,
    /// IPv6 routes, sorted by prefix length (longest first).
    ipv6_routes: Vec<Route>,
    /// Sticky primary peer per exact route prefix.
    ///
    /// Mirrors headscale-go primary route election: an incumbent keeps a route
    /// while it remains approved at the best priority for that prefix. A new
    /// peer is elected only when there is no valid incumbent.
    primary_routes: HashMap<IpNet, String>,
}

impl RoutingTable {
    /// Create a new empty routing table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a route to the table.
    ///
    /// If `approved` is false, the route will be stored but not used for routing.
    pub fn add_route(&mut self, route: Route) {
        let prefix = route.prefix;
        // Add to appropriate list and re-sort
        // Sort by: prefix_len descending (longest first), priority ascending
        // (lower first), then peer ID for deterministic conflict handling.
        match &route.prefix {
            IpNet::V4(_) => {
                self.ipv4_routes.push(route);
                self.ipv4_routes.sort_by(route_order);
            }
            IpNet::V6(_) => {
                self.ipv6_routes.push(route);
                self.ipv6_routes.sort_by(route_order);
            }
        }
        self.recompute_primary_for_prefix(&prefix);
    }

    /// Remove all routes for a peer.
    pub fn remove_peer_routes(&mut self, peer_id: &str) {
        let affected_prefixes: Vec<IpNet> = self
            .all_routes()
            .filter(|r| r.peer_id == peer_id)
            .map(|r| r.prefix)
            .collect();

        self.ipv4_routes.retain(|r| r.peer_id != peer_id);
        self.ipv6_routes.retain(|r| r.peer_id != peer_id);

        for prefix in affected_prefixes {
            self.recompute_primary_for_prefix(&prefix);
        }
    }

    /// Remove a specific route.
    pub fn remove_route(&mut self, prefix: &IpNet, peer_id: &str) {
        match prefix {
            IpNet::V4(_) => {
                self.ipv4_routes
                    .retain(|r| !(r.prefix == *prefix && r.peer_id == peer_id));
            }
            IpNet::V6(_) => {
                self.ipv6_routes
                    .retain(|r| !(r.prefix == *prefix && r.peer_id == peer_id));
            }
        }
        self.recompute_primary_for_prefix(prefix);
    }

    /// Look up the peer that should handle a destination IP.
    ///
    /// Uses longest-prefix-match: the most specific matching route wins.
    /// Among routes with the same prefix length, lower priority wins. Equal
    /// prefix/priority candidates keep the current primary peer when it is
    /// still valid, matching headscale-go's anti-flap primary-route behavior.
    pub fn lookup(&self, dst: IpAddr) -> Option<&str> {
        let routes = match dst {
            IpAddr::V4(_) => &self.ipv4_routes,
            IpAddr::V6(_) => &self.ipv6_routes,
        };

        routes
            .iter()
            .filter(|route| route.approved && route.prefix.contains(&dst))
            .max_by(|a, b| self.route_precedence(a, b))
            .map(|route| route.peer_id.as_str())
    }

    /// Get all routes in the table.
    pub fn all_routes(&self) -> impl Iterator<Item = &Route> {
        self.ipv4_routes.iter().chain(self.ipv6_routes.iter())
    }

    /// Get routes for a specific peer.
    pub fn routes_for_peer(&self, peer_id: &str) -> Vec<&Route> {
        self.all_routes().filter(|r| r.peer_id == peer_id).collect()
    }

    /// Get all approved routes (for distribution to peers).
    pub fn approved_routes(&self) -> impl Iterator<Item = &Route> {
        self.all_routes().filter(|r| r.approved)
    }

    /// Return the elected primary peer for an exact prefix.
    pub fn primary_route_for(&self, prefix: &IpNet) -> Option<&str> {
        self.primary_routes
            .get(prefix)
            .map(std::string::String::as_str)
    }

    /// Approve or revoke an existing advertised route.
    ///
    /// Returns `false` when the peer has not advertised the exact prefix.
    pub fn set_route_approved(&mut self, prefix: &IpNet, peer_id: &str, approved: bool) -> bool {
        let mut found = false;
        {
            let routes = match prefix {
                IpNet::V4(_) => &mut self.ipv4_routes,
                IpNet::V6(_) => &mut self.ipv6_routes,
            };

            for route in routes {
                if route.prefix == *prefix && route.peer_id == peer_id && route.advertised {
                    route.approved = approved;
                    found = true;
                }
            }
        }

        if found {
            self.recompute_primary_for_prefix(prefix);
        }

        found
    }

    /// Check if a route would conflict with an existing route.
    ///
    /// A conflict exists if two different peers have overlapping routes
    /// with the same prefix length.
    pub fn has_conflict(&self, prefix: &IpNet, peer_id: &str) -> Option<&Route> {
        let routes = match prefix {
            IpNet::V4(_) => &self.ipv4_routes,
            IpNet::V6(_) => &self.ipv6_routes,
        };

        routes.iter().find(|r| {
            r.prefix.prefix_len() == prefix.prefix_len()
                && r.peer_id != peer_id
                && (r.prefix.contains(&prefix.addr()) || prefix.contains(&r.prefix.addr()))
        })
    }

    /// Get the number of routes.
    pub fn len(&self) -> usize {
        self.ipv4_routes.len() + self.ipv6_routes.len()
    }

    /// Check if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.ipv4_routes.is_empty() && self.ipv6_routes.is_empty()
    }

    fn route_precedence(&self, a: &Route, b: &Route) -> std::cmp::Ordering {
        a.prefix
            .prefix_len()
            .cmp(&b.prefix.prefix_len())
            .then_with(|| b.priority.cmp(&a.priority))
            .then_with(|| self.primary_precedence(a, b))
            .then_with(|| b.peer_id.cmp(&a.peer_id))
    }

    fn primary_precedence(&self, a: &Route, b: &Route) -> std::cmp::Ordering {
        if a.prefix != b.prefix || a.priority != b.priority {
            return std::cmp::Ordering::Equal;
        }

        match self.primary_route_for(&a.prefix) {
            Some(primary) if primary == a.peer_id && primary != b.peer_id => {
                std::cmp::Ordering::Greater
            }
            Some(primary) if primary == b.peer_id && primary != a.peer_id => {
                std::cmp::Ordering::Less
            }
            _ => std::cmp::Ordering::Equal,
        }
    }

    fn recompute_primary_for_prefix(&mut self, prefix: &IpNet) {
        let routes = match prefix {
            IpNet::V4(_) => &self.ipv4_routes,
            IpNet::V6(_) => &self.ipv6_routes,
        };

        let best_priority = routes
            .iter()
            .filter(|route| route.prefix == *prefix && route.approved)
            .map(|route| route.priority)
            .min();

        let Some(best_priority) = best_priority else {
            self.primary_routes.remove(prefix);
            return;
        };

        if let Some(current) = self.primary_routes.get(prefix)
            && routes.iter().any(|route| {
                route.prefix == *prefix
                    && route.approved
                    && route.priority == best_priority
                    && route.peer_id == *current
            })
        {
            return;
        }

        let selected = routes
            .iter()
            .filter(|route| {
                route.prefix == *prefix && route.approved && route.priority == best_priority
            })
            .min_by(|a, b| a.peer_id.cmp(&b.peer_id))
            .map(|route| route.peer_id.clone());

        if let Some(peer_id) = selected {
            self.primary_routes.insert(*prefix, peer_id);
        } else {
            self.primary_routes.remove(prefix);
        }
    }
}

fn route_order(a: &Route, b: &Route) -> std::cmp::Ordering {
    b.prefix
        .prefix_len()
        .cmp(&a.prefix.prefix_len())
        .then_with(|| a.priority.cmp(&b.priority))
        .then_with(|| a.peer_id.cmp(&b.peer_id))
}

/// Parse a CIDR string into an IpNet.
pub fn parse_cidr(s: &str) -> Result<IpNet, ipnet::AddrParseError> {
    s.parse()
}

/// Create a host route (/32 for IPv4, /128 for IPv6).
pub fn host_route(ip: IpAddr) -> IpNet {
    match ip {
        IpAddr::V4(addr) => IpNet::V4(Ipv4Net::new(addr, 32).unwrap()),
        IpAddr::V6(addr) => IpNet::V6(Ipv6Net::new(addr, 128).unwrap()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn make_route(prefix: &str, peer_id: &str, priority: u32) -> Route {
        Route {
            prefix: prefix.parse().unwrap(),
            peer_id: peer_id.to_string(),
            priority,
            approved: true,
            advertised: false,
        }
    }

    #[test]
    fn test_exact_host_route() {
        let mut table = RoutingTable::new();
        table.add_route(make_route("10.0.0.5/32", "peer-a", 0));

        assert_eq!(
            table.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            Some("peer-a")
        );
        assert_eq!(table.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6))), None);
    }

    #[test]
    fn test_subnet_route() {
        let mut table = RoutingTable::new();
        table.add_route(make_route("192.168.1.0/24", "peer-b", 0));

        // Should match any IP in the subnet
        assert_eq!(
            table.lookup(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))),
            Some("peer-b")
        );
        assert_eq!(
            table.lookup(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255))),
            Some("peer-b")
        );
        // Should not match outside
        assert_eq!(
            table.lookup(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))),
            None
        );
    }

    #[test]
    fn test_longest_prefix_match() {
        let mut table = RoutingTable::new();

        // Add routes: default, /16, /24, /32
        table.add_route(make_route("0.0.0.0/0", "exit-node", 0));
        table.add_route(make_route("10.0.0.0/8", "peer-a", 0));
        table.add_route(make_route("10.0.1.0/24", "peer-b", 0));
        table.add_route(make_route("10.0.1.5/32", "peer-c", 0));

        // Most specific wins
        assert_eq!(
            table.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5))),
            Some("peer-c")
        );
        assert_eq!(
            table.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 100))),
            Some("peer-b")
        );
        assert_eq!(
            table.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1))),
            Some("peer-a")
        );
        assert_eq!(
            table.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            Some("exit-node")
        );
    }

    #[test]
    fn test_default_route() {
        let mut table = RoutingTable::new();
        table.add_route(make_route("0.0.0.0/0", "exit", 0));

        // Everything should route to exit
        assert_eq!(
            table.lookup(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            Some("exit")
        );
        assert_eq!(
            table.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            Some("exit")
        );
    }

    #[test]
    fn test_ipv6_routes() {
        let mut table = RoutingTable::new();
        table.add_route(make_route("2001:db8::/32", "peer-v6", 0));
        table.add_route(make_route("::/0", "exit-v6", 0));

        assert_eq!(
            table.lookup(IpAddr::V6("2001:db8::1".parse().unwrap())),
            Some("peer-v6")
        );
        assert_eq!(
            table.lookup(IpAddr::V6("2001:4860:4860::8888".parse().unwrap())),
            Some("exit-v6")
        );
    }

    #[test]
    fn test_unapproved_routes_ignored() {
        let mut table = RoutingTable::new();
        table.add_route(Route {
            prefix: "10.0.0.0/8".parse().unwrap(),
            peer_id: "unapproved-peer".to_string(),
            priority: 0,
            approved: false,
            advertised: true,
        });

        // Unapproved route should not match
        assert_eq!(table.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))), None);
    }

    #[test]
    fn test_remove_peer_routes() {
        let mut table = RoutingTable::new();
        table.add_route(make_route("10.0.0.0/24", "peer-a", 0));
        table.add_route(make_route("10.0.1.0/24", "peer-a", 0));
        table.add_route(make_route("10.0.2.0/24", "peer-b", 0));

        assert_eq!(table.len(), 3);

        table.remove_peer_routes("peer-a");

        assert_eq!(table.len(), 1);
        assert_eq!(table.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))), None);
        assert_eq!(
            table.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1))),
            Some("peer-b")
        );
    }

    #[test]
    fn test_priority_same_prefix_length() {
        let mut table = RoutingTable::new();
        table.add_route(make_route("0.0.0.0/0", "low-priority", 100));
        table.add_route(make_route("0.0.0.0/0", "high-priority", 10));

        // Lower priority number wins
        assert_eq!(
            table.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            Some("high-priority")
        );
    }

    #[test]
    fn test_equal_priority_keeps_existing_primary() {
        let mut table = RoutingTable::new();
        table.add_route(make_route("0.0.0.0/0", "peer-b", 0));
        table.add_route(make_route("0.0.0.0/0", "peer-a", 0));

        let prefix = "0.0.0.0/0".parse().unwrap();
        assert_eq!(
            table.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            Some("peer-b")
        );
        assert_eq!(table.primary_route_for(&prefix), Some("peer-b"));

        table.remove_route(&prefix, "peer-b");
        assert_eq!(
            table.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            Some("peer-a")
        );
        assert_eq!(table.primary_route_for(&prefix), Some("peer-a"));
    }

    #[test]
    fn test_host_route_priority_and_removal() {
        let mut table = RoutingTable::new();

        table.add_route(make_route("10.0.0.5/32", "peer-lower-priority", 10));
        table.add_route(make_route("10.0.0.5/32", "peer-higher-priority", 0));

        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(table.lookup(addr), Some("peer-higher-priority"));

        table.remove_route(&"10.0.0.5/32".parse().unwrap(), "peer-higher-priority");
        assert_eq!(table.lookup(addr), Some("peer-lower-priority"));

        table.remove_peer_routes("peer-lower-priority");
        assert_eq!(table.lookup(addr), None);
    }

    #[test]
    fn test_host_route_helper() {
        let v4 = host_route(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(v4.prefix_len(), 32);

        let v6 = host_route(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(v6.prefix_len(), 128);
    }

    #[test]
    fn test_route_approval_requires_advertised_route() {
        let mut table = RoutingTable::new();
        let prefix = "0.0.0.0/0".parse().unwrap();

        assert!(!table.set_route_approved(&prefix, "exit-peer", true));
        assert_eq!(table.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))), None);

        table.add_route(Route {
            prefix,
            peer_id: "exit-peer".to_string(),
            priority: 100,
            approved: false,
            advertised: true,
        });

        assert!(table.set_route_approved(&prefix, "exit-peer", true));
        assert_eq!(
            table.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            Some("exit-peer")
        );

        table.add_route(Route {
            prefix: "10.0.0.5/32".parse().unwrap(),
            peer_id: "host-peer".to_string(),
            priority: 0,
            approved: true,
            advertised: false,
        });

        assert!(!table.set_route_approved(&"10.0.0.5/32".parse().unwrap(), "host-peer", false));
        assert_eq!(
            table.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            Some("host-peer")
        );
    }

    #[test]
    fn test_later_approved_equal_route_does_not_steal_primary() {
        let mut table = RoutingTable::new();
        let prefix = "10.10.0.0/24".parse().unwrap();
        let route_ip = IpAddr::V4(Ipv4Addr::new(10, 10, 0, 7));

        table.add_route(Route {
            prefix,
            peer_id: "peer-b".to_string(),
            priority: 100,
            approved: true,
            advertised: true,
        });
        table.add_route(Route {
            prefix,
            peer_id: "peer-a".to_string(),
            priority: 100,
            approved: false,
            advertised: true,
        });

        assert_eq!(table.lookup(route_ip), Some("peer-b"));
        assert_eq!(table.primary_route_for(&prefix), Some("peer-b"));

        assert!(table.set_route_approved(&prefix, "peer-a", true));
        assert_eq!(table.lookup(route_ip), Some("peer-b"));
        assert_eq!(table.primary_route_for(&prefix), Some("peer-b"));

        assert!(table.set_route_approved(&prefix, "peer-b", false));
        assert_eq!(table.lookup(route_ip), Some("peer-a"));
        assert_eq!(table.primary_route_for(&prefix), Some("peer-a"));
    }
}

/// Property-based tests for routing table.
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

    /// Strategy for generating valid peer identifiers.
    fn arb_peer_id() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9_-]{0,15}".prop_map(|s| format!("peer-{s}"))
    }

    proptest! {
        /// Property: A host route always matches its own IP exactly.
        #[test]
        fn prop_host_route_matches_self(ip in arb_ipv4(), peer_id in arb_peer_id()) {
            let mut table = RoutingTable::new();
            let prefix = host_route(IpAddr::V4(ip));
            table.add_route(Route {
                prefix,
                peer_id: peer_id.clone(),
                priority: 0,
                approved: true,
                advertised: false,
            });

            prop_assert_eq!(table.lookup(IpAddr::V4(ip)), Some(peer_id.as_str()));
        }

        /// Property: Default route (0.0.0.0/0) matches any IPv4 address.
        #[test]
        fn prop_default_route_matches_all(
            test_ip in arb_ipv4(),
            peer_id in arb_peer_id(),
        ) {
            let mut table = RoutingTable::new();
            table.add_route(Route {
                prefix: "0.0.0.0/0".parse().unwrap(),
                peer_id: peer_id.clone(),
                priority: 0,
                approved: true,
                advertised: false,
            });

            prop_assert_eq!(
                table.lookup(IpAddr::V4(test_ip)),
                Some(peer_id.as_str()),
                "Default route should match any IP"
            );
        }

        /// Property: Longer prefix always beats shorter prefix.
        #[test]
        fn prop_longer_prefix_wins(
            base_octet in 0u8..=255,
            host_octet in 0u8..=255,
        ) {
            let mut table = RoutingTable::new();

            // Add /8 route
            let prefix8 = format!("{base_octet}.0.0.0/8");
            table.add_route(Route {
                prefix: prefix8.parse().unwrap(),
                peer_id: "peer-8".to_string(),
                priority: 0,
                approved: true,
                advertised: false,
            });

            // Add /24 route within the /8
            let prefix24 = format!("{base_octet}.0.0.0/24");
            table.add_route(Route {
                prefix: prefix24.parse().unwrap(),
                peer_id: "peer-24".to_string(),
                priority: 0,
                approved: true,
                advertised: false,
            });

            // Add /32 route within the /24
            let ip = Ipv4Addr::new(base_octet, 0, 0, host_octet);
            let prefix32 = format!("{ip}/32");
            table.add_route(Route {
                prefix: prefix32.parse().unwrap(),
                peer_id: "peer-32".to_string(),
                priority: 0,
                approved: true,
                advertised: false,
            });

            // The /32 should win for its exact IP
            prop_assert_eq!(
                table.lookup(IpAddr::V4(ip)),
                Some("peer-32"),
                "/32 route should win for exact IP"
            );

            // A different IP in the /24 should match /24
            if host_octet < 255 {
                let other_ip = Ipv4Addr::new(base_octet, 0, 0, host_octet.wrapping_add(1));
                // This would match /24, not /32
                let result = table.lookup(IpAddr::V4(other_ip));
                // Either /24 or /32 (if it exists for that IP)
                prop_assert!(result.is_some(), "Should match either /24 or /32");
            }
        }

        /// Property: Lower priority wins when prefix lengths are equal.
        #[test]
        fn prop_lower_priority_wins(
            test_ip in arb_ipv4(),
            low_prio in 0u32..50,
            high_prio in 51u32..100,
        ) {
            let mut table = RoutingTable::new();

            // Add high priority number (lower precedence)
            table.add_route(Route {
                prefix: "0.0.0.0/0".parse().unwrap(),
                peer_id: "low-precedence".to_string(),
                priority: high_prio,
                approved: true,
                advertised: false,
            });

            // Add low priority number (higher precedence)
            table.add_route(Route {
                prefix: "0.0.0.0/0".parse().unwrap(),
                peer_id: "high-precedence".to_string(),
                priority: low_prio,
                approved: true,
                advertised: false,
            });

            prop_assert_eq!(
                table.lookup(IpAddr::V4(test_ip)),
                Some("high-precedence"),
                "Lower priority number should win"
            );
        }

        /// Property: Unapproved routes are never matched.
        #[test]
        fn prop_unapproved_routes_ignored(
            test_ip in arb_ipv4(),
            peer_id in arb_peer_id(),
        ) {
            let mut table = RoutingTable::new();
            table.add_route(Route {
                prefix: "0.0.0.0/0".parse().unwrap(),
                peer_id,
                priority: 0,
                approved: false, // NOT approved
                advertised: true,
            });

            prop_assert_eq!(
                table.lookup(IpAddr::V4(test_ip)),
                None,
                "Unapproved routes should not match"
            );
        }

        /// Property: Removing a peer removes all its routes.
        #[test]
        fn prop_remove_peer_routes(
            num_routes in 1usize..10,
            peer_id in arb_peer_id(),
        ) {
            let mut table = RoutingTable::new();

            // Add multiple routes for the peer
            for i in 0..num_routes {
                let prefix = format!("10.{}.0.0/16", i % 256);
                table.add_route(Route {
                    prefix: prefix.parse().unwrap(),
                    peer_id: peer_id.clone(),
                    priority: 0,
                    approved: true,
                    advertised: false,
                });
            }

            prop_assert_eq!(table.len(), num_routes);

            // Remove all routes for the peer
            table.remove_peer_routes(&peer_id);

            prop_assert!(table.is_empty(), "All routes should be removed");
        }

        /// Property: Adding and removing the same route restores state.
        #[test]
        fn prop_add_remove_idempotent(
            ip in arb_ipv4(),
            peer_id in arb_peer_id(),
        ) {
            let mut table = RoutingTable::new();
            let prefix = host_route(IpAddr::V4(ip));

            // Initially empty
            prop_assert!(table.is_empty());

            // Add route
            table.add_route(Route {
                prefix,
                peer_id: peer_id.clone(),
                priority: 0,
                approved: true,
                advertised: false,
            });
            prop_assert_eq!(table.len(), 1);

            // Remove route
            table.remove_route(&prefix, &peer_id);
            prop_assert!(table.is_empty());
        }

        /// Property: Route containment is consistent with lookup.
        #[test]
        fn prop_containment_consistency(
            base_octet in 0u8..=255,
            subnet_octet in 0u8..=255,
            host_octet in 0u8..=255,
        ) {
            let mut table = RoutingTable::new();

            // Add a /24 route
            let prefix = format!("{base_octet}.{subnet_octet}.0.0/24");
            let net: IpNet = prefix.parse().unwrap();

            table.add_route(Route {
                prefix: net,
                peer_id: "test-peer".to_string(),
                priority: 0,
                approved: true,
                advertised: false,
            });

            // Test IP in the subnet
            let test_ip = IpAddr::V4(Ipv4Addr::new(base_octet, subnet_octet, 0, host_octet));

            // If the IP is contained in the prefix, lookup should succeed
            if net.contains(&test_ip) {
                prop_assert_eq!(
                    table.lookup(test_ip),
                    Some("test-peer"),
                    "IP in subnet should match route"
                );
            }

            // Test IP outside the subnet (different second octet)
            let outside_ip = IpAddr::V4(Ipv4Addr::new(
                base_octet,
                subnet_octet.wrapping_add(1),
                0,
                host_octet,
            ));

            if !net.contains(&outside_ip) {
                prop_assert_eq!(
                    table.lookup(outside_ip),
                    None,
                    "IP outside subnet should not match"
                );
            }
        }

        /// Property: host_route creates correct prefix length.
        #[test]
        fn prop_host_route_prefix_len(ip in arb_ipv4()) {
            let route = host_route(IpAddr::V4(ip));
            prop_assert_eq!(route.prefix_len(), 32, "IPv4 host route should be /32");
        }

        /// Property: Route table length is correct after operations.
        #[test]
        fn prop_length_tracking(
            operations in proptest::collection::vec(
                (arb_peer_id(), 0u8..=255),
                0..20
            )
        ) {
            let mut table = RoutingTable::new();
            let mut expected_len = 0;

            for (peer_id, octet) in operations {
                let prefix = format!("10.0.{octet}.0/24");
                table.add_route(Route {
                    prefix: prefix.parse().unwrap(),
                    peer_id,
                    priority: 0,
                    approved: true,
                    advertised: false,
                });
                expected_len += 1;
            }

            prop_assert_eq!(table.len(), expected_len);
        }
    }
}
