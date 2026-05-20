//! Forward-path authorization helper.
//!
//! Thin module that combines [`crate::acl::AclEvaluator`] with the
//! [`crate::routing::RoutingTable`] so callers (`packet.rs`) can decide
//! whether to forward a packet *and* which peer to send it to in one
//! call. Extracted from `packet.rs` so the policy decision is testable
//! without spinning up a full WireGuard tunnel.
//!
//! ## Decision shape
//!
//! * [`ForwardDecision::Allow { peer_id }`] — ACL says yes AND the
//!   routing table has a matching peer.
//! * [`ForwardDecision::NoRoute`] — ACL says yes but no peer covers
//!   the destination prefix.
//! * [`ForwardDecision::Deny`] — ACL says no.
//!
//! NOTE: this module was missing from a previous commit that left
//! `packet.rs` referencing `crate::authorization::*` with no
//! supporting file. The preauth-feature-parity branch adds it back as
//! the minimum stub needed to compile + ship the policy contract test
//! at the bottom of `packet.rs`. Production behaviour matches what the
//! test asserts: ACL allow + exact peer match ⇒ forward to that peer.

use std::net::IpAddr;

use crate::acl::{AclContext, AclDestination, AclEvaluator, Action};
use crate::routing::RoutingTable;

/// Outcome of [`authorize_forward`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardDecision {
    /// Forward the packet to `peer_id`.
    Allow {
        /// Peer ID extracted from the routing table.
        peer_id: String,
    },
    /// Policy allows the destination but no peer in the routing table
    /// covers it. Caller should drop (or route to default-gateway if
    /// one exists — out of scope here).
    NoRoute,
    /// Policy denies the destination. Caller MUST drop the packet.
    Deny,
}

/// Combine ACL evaluation with peer-lookup in a single call. Used by
/// the policy-aware packet router.
pub fn authorize_forward(
    acl: &AclEvaluator,
    routes: &RoutingTable,
    ctx: &AclContext,
    dst: &AclDestination,
) -> ForwardDecision {
    if acl.evaluate(ctx, dst) != Action::Accept {
        return ForwardDecision::Deny;
    }
    let Some(dst_ip) = dst.dst_ip else {
        return ForwardDecision::NoRoute;
    };
    match routes.lookup(dst_ip) {
        Some(peer_id) => ForwardDecision::Allow {
            peer_id: peer_id.to_string(),
        },
        None => ForwardDecision::NoRoute,
    }
}

/// Convenience: authorize against an IP-only destination.
pub fn authorize_ip_forward(
    acl: &AclEvaluator,
    routes: &RoutingTable,
    ctx: &AclContext,
    dst_ip: IpAddr,
) -> ForwardDecision {
    let dst = AclDestination::ip_only(dst_ip);
    authorize_forward(acl, routes, ctx, &dst)
}
