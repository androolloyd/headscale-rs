//! Go's implemented RFC6724 destination-ordering rules.
//!
//! The source-address probe uses UDP connect/local_addr without sending data,
//! as Go's net package does. Deprecated/home/native-transport preferences are
//! omitted by the pinned Go implementation too.

use std::cmp::Ordering;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use tokio::net::UdpSocket;

pub(super) async fn sort_addresses(addresses: &mut [IpAddr]) {
    if addresses.len() < 2 {
        return;
    }
    let mut candidates = Vec::with_capacity(addresses.len());
    for (index, address) in addresses.iter().copied().enumerate() {
        let source = source_address(address).await;
        candidates.push(Candidate {
            destination: address,
            destination_attr: attributes(address),
            source,
            source_attr: source.map(attributes).unwrap_or_default(),
        });
        // Keep the surrounding resolver/command deadline observable even
        // when every local socket operation completes immediately.
        if index % 32 == 31 {
            tokio::task::yield_now().await;
        }
    }
    // Stable sorting is rule 10: otherwise keep the resolver's initial order.
    candidates.sort_by(compare);
    for (address, candidate) in addresses.iter_mut().zip(candidates) {
        *address = candidate.destination;
    }
}

async fn source_address(destination: IpAddr) -> Option<IpAddr> {
    // Go's UDP network selects IPv4 for IPv4-mapped destinations too.
    let destination = canonical(destination);
    let socket = UdpSocket::bind(if destination.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await
    .ok()?;
    socket
        .connect(SocketAddr::new(destination, 53))
        .await
        .ok()?;
    Some(socket.local_addr().ok()?.ip())
}

#[derive(Clone, Copy, Default)]
struct Attributes {
    scope: u8,
    precedence: u8,
    label: u8,
}

struct Candidate {
    destination: IpAddr,
    destination_attr: Attributes,
    source: Option<IpAddr>,
    source_attr: Attributes,
}

fn compare(a: &Candidate, b: &Candidate) -> Ordering {
    // Rule 1. If neither has a source, all later comparisons are skipped.
    match (a.source, b.source) {
        (None, None) => return Ordering::Equal,
        (Some(_), None) => return Ordering::Less,
        (None, Some(_)) => return Ordering::Greater,
        (Some(_), Some(_)) => {}
    }
    // Rules 2, 5, 6, 8. Matching scope/label and higher precedence win;
    // smaller destination scope wins. Go does not implement rules 3, 4, 7.
    let order = (b.destination_attr.scope == b.source_attr.scope)
        .cmp(&(a.destination_attr.scope == a.source_attr.scope))
        .then_with(|| {
            (b.destination_attr.label == b.source_attr.label)
                .cmp(&(a.destination_attr.label == a.source_attr.label))
        })
        .then_with(|| {
            b.destination_attr
                .precedence
                .cmp(&a.destination_attr.precedence)
        })
        .then_with(|| a.destination_attr.scope.cmp(&b.destination_attr.scope));
    if order != Ordering::Equal {
        return order;
    }
    // Rule 9 applies only when both destinations are genuine IPv6 addresses.
    // Go limits the comparison to the first 64 bits, excluding interface IDs.
    if let (IpAddr::V6(a_destination), IpAddr::V6(b_destination)) =
        (canonical(a.destination), canonical(b.destination))
    {
        return prefix_length(b.source, b_destination).cmp(&prefix_length(a.source, a_destination));
    }
    Ordering::Equal
}

fn attributes(address: IpAddr) -> Attributes {
    let ip = match address {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => ip,
    };
    let bytes = ip.octets();
    // Longest-prefix policy-table order from Go's RFC6724 implementation.
    let (precedence, label) = if ip == Ipv6Addr::LOCALHOST {
        (50, 0)
    } else if ip.to_ipv4_mapped().is_some() {
        (35, 4)
    } else if bytes[..12].iter().all(|byte| *byte == 0) {
        (1, 3)
    } else if bytes[..4] == [0x20, 0x01, 0, 0] {
        (5, 5)
    } else if bytes[..2] == [0x20, 0x02] {
        (30, 2)
    } else if bytes[..2] == [0x3f, 0xfe] {
        (1, 12)
    } else if bytes[0] == 0xfe && bytes[1] & 0xc0 == 0xc0 {
        (1, 11)
    } else if bytes[0] & 0xfe == 0xfc {
        (3, 13)
    } else {
        (40, 1)
    };
    Attributes {
        scope: scope(address),
        precedence,
        label,
    }
}

fn scope(address: IpAddr) -> u8 {
    match canonical(address) {
        IpAddr::V4(ip) if ip.is_loopback() || ip.is_link_local() => 2,
        IpAddr::V6(ip) if ip.is_loopback() || ip.is_unicast_link_local() => 2,
        IpAddr::V6(ip) if ip.is_multicast() => ip.octets()[1] & 15,
        IpAddr::V6(ip) if ip.octets()[0] == 0xfe && ip.octets()[1] & 0xc0 == 0xc0 => 5,
        _ => 14,
    }
}

fn canonical(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

fn prefix_length(source: Option<IpAddr>, destination: Ipv6Addr) -> u32 {
    let Some(IpAddr::V6(source)) = source else {
        return 0;
    };
    let source = (u128::from(source) >> 64) as u64;
    let destination = (u128::from(destination) >> 64) as u64;
    (source ^ destination).leading_zeros()
}
