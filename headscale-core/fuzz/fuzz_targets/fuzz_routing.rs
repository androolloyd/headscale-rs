#![no_main]

use arbitrary::Arbitrary;
use headscale_core::routing::{Route, RoutingTable};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Arbitrary, Clone, Debug)]
enum RouteSpec {
    V4 {
        addr: [u8; 4],
        prefix_len: u8,
        peer_id: String,
        priority: u32,
        approved: bool,
        advertised: bool,
    },
    V6 {
        segments: [u16; 8],
        prefix_len: u8,
        peer_id: String,
        priority: u32,
        approved: bool,
        advertised: bool,
    },
}

#[derive(Arbitrary, Debug)]
enum RoutingOp {
    Add(RouteSpec),
    RemovePeer(String),
    RemoveRoute(RouteSpec),
    LookupV4([u8; 4]),
    LookupV6([u16; 8]),
    HasConflict(RouteSpec),
}

#[derive(Arbitrary, Debug)]
struct RoutingFuzzInput {
    ops: Vec<RoutingOp>,
}

fuzz_target!(|input: RoutingFuzzInput| {
    let mut table = RoutingTable::new();

    for op in input.ops.into_iter().take(128) {
        match op {
            RoutingOp::Add(spec) => {
                table.add_route(route_from_spec(spec));
                assert_table_invariants(&table);
            }
            RoutingOp::RemovePeer(peer_id) => {
                table.remove_peer_routes(&peer_id);
                assert!(table.routes_for_peer(&peer_id).is_empty());
                assert_table_invariants(&table);
            }
            RoutingOp::RemoveRoute(spec) => {
                let route = route_from_spec(spec);
                table.remove_route(&route.prefix, &route.peer_id);
                assert!(table
                    .all_routes()
                    .all(|r| r.prefix != route.prefix || r.peer_id != route.peer_id));
                assert_table_invariants(&table);
            }
            RoutingOp::LookupV4(addr) => {
                let ip = IpAddr::V4(Ipv4Addr::from(addr));
                assert_eq!(table.lookup(ip), expected_lookup(&table, ip));
            }
            RoutingOp::LookupV6(segments) => {
                let ip = IpAddr::V6(Ipv6Addr::from(segments));
                assert_eq!(table.lookup(ip), expected_lookup(&table, ip));
            }
            RoutingOp::HasConflict(spec) => {
                let route = route_from_spec(spec);
                if let Some(conflict) = table.has_conflict(&route.prefix, &route.peer_id) {
                    assert_ne!(conflict.peer_id, route.peer_id);
                    assert_eq!(conflict.prefix.prefix_len(), route.prefix.prefix_len());
                }
            }
        }
    }
});

fn route_from_spec(spec: RouteSpec) -> Route {
    match spec {
        RouteSpec::V4 {
            addr,
            prefix_len,
            peer_id,
            priority,
            approved,
            advertised,
        } => Route {
            prefix: IpNet::V4(Ipv4Net::new(Ipv4Addr::from(addr), prefix_len % 33).unwrap()),
            peer_id,
            priority,
            approved,
            advertised,
        },
        RouteSpec::V6 {
            segments,
            prefix_len,
            peer_id,
            priority,
            approved,
            advertised,
        } => Route {
            prefix: IpNet::V6(Ipv6Net::new(Ipv6Addr::from(segments), prefix_len % 129).unwrap()),
            peer_id,
            priority,
            approved,
            advertised,
        },
    }
}

fn expected_lookup(table: &RoutingTable, dst: IpAddr) -> Option<&str> {
    table
        .all_routes()
        .filter(|route| route.approved && route.prefix.contains(&dst))
        .max_by(|a, b| {
            a.prefix
                .prefix_len()
                .cmp(&b.prefix.prefix_len())
                .then_with(|| b.priority.cmp(&a.priority))
        })
        .map(|route| route.peer_id.as_str())
}

fn assert_table_invariants(table: &RoutingTable) {
    assert_eq!(table.len() == 0, table.is_empty());
    assert_eq!(table.len(), table.all_routes().count());
    assert!(table.approved_routes().all(|route| route.approved));

    for route in table.all_routes() {
        for peer_route in table.routes_for_peer(&route.peer_id) {
            assert_eq!(peer_route.peer_id, route.peer_id);
        }

        if route.approved {
            assert_eq!(
                table.lookup(route.prefix.addr()),
                expected_lookup(table, route.prefix.addr())
            );
        }
    }
}
