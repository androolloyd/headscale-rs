//! Tailscale wire-protocol compatibility layer.
//!
//! Migrated from `octravpn-mesh::tailscale_wire` in 2026-05-19 — this
//! module is where the Rust port of headscale-go's control plane
//! actually belongs. Downstream callers (e.g. OctraVPN's
//! `octravpn-mesh`) bridge their preauth / IP-allocation policy into
//! the wire layer via the [`PreauthRedeemer`] and [`IpAllocator`]
//! traits.
//!
//! Implements just enough of the Tailscale coordination protocol for
//! a stock `tailscale up` client to make progress against a
//! headscale-rs-derived node. See `docs/tailscale-interop-blocker.md`
//! in the OctraVPN repo for the four-PR plan
//! (`/key` → `/ts2021` → `/register` → `/map`) this module is built
//! against.
//!
//! ## What ships in this commit
//!
//! - **`GET /key`** ([`key_handler`]) — returns the node's long-term
//!   Noise X25519 public key as a Tailscale-shape
//!   `OverTLSPublicKeyResponse` JSON.
//! - **`POST /ts2021`** ([`noise`]) — `Upgrade:
//!   tailscale-control-protocol` handler. Drives the Noise IK responder
//!   on the hijacked socket + spins up h2 inside the Noise transport.
//! - **`POST /machine/{node_key}/register`** ([`register`]) — decodes a
//!   JSON `RegisterRequest`, redeems the presented authkey via the
//!   injected [`PreauthRedeemer`], allocates a tailnet IP via the
//!   injected [`IpAllocator`].
//! - **`POST /machine/{node_key}/map`** ([`map`]) — long-poll peer map.
//!
//! See the upstream OctraVPN module's decision log (preserved in git
//! history) for the rationale behind each wire choice.

use std::net::Ipv4Addr;
use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    routing::{get, post},
    Router,
};
use parking_lot::RwLock;
use std::collections::HashMap;
use thiserror::Error;
use tokio::sync::Notify;

pub mod be_transport;
pub mod controlbase;
pub mod derp_config;
pub mod key_handler;
pub mod map;
pub mod noise;
pub mod raw_tls;
pub mod register;
pub mod serve;
pub mod tls;
pub mod wire;

pub use noise::ServerNoiseKey;
pub use wire::{
    DerpMap, DerpRegion, DerpRegionNode, MachineRecord, MapRequest, MapResponse, RegisterRequest,
    RegisterResponse,
};

/// Error type for the Tailscale-wire handlers.
#[derive(Debug, Error)]
pub enum WireError {
    #[error("authkey rejected: {0}")]
    AuthKeyRejected(String),
    #[error("invalid request body: {0}")]
    InvalidBody(String),
    #[error("noise handshake: {0}")]
    Noise(String),
    #[error("internal: {0}")]
    Internal(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Why a preauth redemption failed.
///
/// Lifted from the original `octravpn-mesh::headscale_bridge::RedeemError`
/// so the wire layer can stay free of OctraVPN-specific concerns.
/// Downstream impls of [`PreauthRedeemer`] map their native errors into
/// these variants — the register handler turns each into a 401 with a
/// canonical Tailscale-shape `{"error": "..."}` body.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RedeemError {
    /// Token doesn't match any minted key (or was already consumed).
    #[error("preauth: unknown key")]
    Unknown,
    /// Token was valid at some point but its TTL has passed.
    #[error("preauth: key expired")]
    Expired,
}

/// Why an IP allocation failed.
///
/// The current OctraVPN allocator never fails (it's a deterministic
/// hash → 32-bit slot mapping), so the variant set is intentionally
/// small. Future allocators that talk to a real IPAM service can grow
/// this enum without rippling through the handler signatures.
#[derive(Debug, Error)]
pub enum AllocError {
    #[error("ip allocator exhausted")]
    Exhausted,
    #[error("ip allocator internal: {0}")]
    Internal(String),
}

/// Redeems Tailscale preauth tokens against whatever policy / billing
/// surface the embedding host enforces.
///
/// The wire layer hands a token string off to this trait and receives
/// either a bound `user` label (which lands in the `MachineRecord` +
/// `RegisterResponse`) or a [`RedeemError`].
///
/// Async because production impls may need to talk to a database or
/// rate-limit service; the in-tree OctraVPN bridge is sync but adopts
/// the async signature trivially.
#[async_trait]
pub trait PreauthRedeemer: Send + Sync {
    async fn redeem(&self, key: &str) -> Result<String, RedeemError>;
}

/// Allocates a tailnet IPv4 for a registering node.
///
/// Implementations are expected to be deterministic given
/// `node_key_hex` (the in-tree OctraVPN allocator hashes
/// `(tailnet_id, member_addr, ip_salt)` into the CGNAT host space), but
/// the trait does not mandate determinism — a stateful allocator that
/// rotates assignments on each call is also valid.
pub trait IpAllocator: Send + Sync {
    fn allocate(&self, node_key_hex: &str) -> Result<Ipv4Addr, AllocError>;
}

/// Shared state for every handler under [`router`].
///
/// Cheap to clone: every field is an `Arc`. Construct once at node
/// startup and hand to both the wire router and any place that needs
/// to inspect peers (e.g. an admin UI).
#[derive(Clone)]
pub struct WireState {
    /// The node's long-term Noise X25519 keypair. Same key across
    /// reboots; persisted under `state_dir`. Public key is what
    /// `GET /key` returns.
    pub server_noise_key: Arc<ServerNoiseKey>,
    /// Preauth redeemer so `register` can validate presented authkeys
    /// against whatever policy the embedding host enforces.
    pub preauth: Arc<dyn PreauthRedeemer>,
    /// IP allocator for the (single) tailnet the wire surface serves.
    pub ip_allocator: Arc<dyn IpAllocator>,
    /// node_key (hex) → machine record. Map long-poll reads this to
    /// build the peer list; register writes to it on success.
    pub machines: Arc<MachineRegistry>,
    /// DERP map served on `/machine/map`. `Arc` because it's shared
    /// across every map handler invocation and never mutated after
    /// startup. Defaults to empty (`DerpMap::default()`) — non-interop
    /// deployments rely on the public Tailscale DERP fleet, which our
    /// stock-client interop test can't use because the daemon refuses
    /// to dial out from a sealed docker network. The interop harness
    /// sets `OCTRAVPN_DERP_MAP_PATH` and the loader populates this
    /// field with a one-region fixture pointing at the `derp-1` sidecar.
    /// See [`derp_config`] + `docs/tailscale-interop-blocker.md` 2026-
    /// 05-19 §"Wall 6 closed".
    pub derp_map: Arc<wire::DerpMap>,
}

/// In-memory machine registry. Each successful `register` inserts here;
/// `map` reads here.
#[derive(Default)]
pub struct MachineRegistry {
    inner: RwLock<HashMap<String, MachineRecord>>,
    /// Wakes pending `/map` long-polls when a new machine registers.
    pub(crate) notify: Arc<Notify>,
}

impl MachineRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a machine record. Wakes every pending
    /// `/map` long-poll.
    pub fn upsert(&self, node_key_hex: String, rec: MachineRecord) {
        let mut g = self.inner.write();
        g.insert(node_key_hex, rec);
        drop(g);
        self.notify.notify_waiters();
    }

    /// Snapshot all known machines. Used by `/map` to build the peer
    /// list.
    pub fn all(&self) -> Vec<(String, MachineRecord)> {
        let g = self.inner.read();
        g.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    /// Look up a single machine by its hex-encoded node key.
    pub fn get(&self, node_key_hex: &str) -> Option<MachineRecord> {
        self.inner.read().get(node_key_hex).cloned()
    }

    /// Number of registered machines.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// True if no machines are registered.
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

/// Build the Tailscale-wire router.
///
/// Mount under the same axum app as the rest of the node's control
/// plane. The four routes here are intentionally unauthenticated at
/// the HTTP layer — authorization happens via the presented authkey
/// (for `register`) or via possession of a registered node-key (for
/// `map`).
pub fn router(state: WireState) -> Router {
    Router::new()
        .route("/key", get(key_handler::handle_key))
        .route("/ts2021", post(noise::handle_ts2021_post))
        .route(
            "/machine/:node_key/register",
            post(register::handle_register),
        )
        .route("/machine/:node_key/map", post(map::handle_map))
        // Flat v1.78+ paths — extract NodeKey from the request body.
        // See `docs/tailscale-interop-blocker.md` 2026-05-19 §"Wire-format
        // surprise". Both shapes coexist deliberately so older clients
        // and our own integration tests keep working.
        .route("/machine/register", post(register::handle_register_flat))
        .route("/machine/map", post(map::handle_map_flat))
        .with_state(state)
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Shared test fixtures: `MockRedeemer` + `MockIpAllocator` that
    //! the per-module unit tests use instead of OctraVPN's
    //! `PreauthMinter` + `TailnetIpAllocator`.
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    /// In-memory preauth redeemer: keys → user labels.
    ///
    /// Single-use: a successful redeem removes the key from the map so
    /// the second redeem of the same token returns
    /// [`RedeemError::Unknown`] — matches the OctraVPN minter's
    /// non-reusable default.
    #[derive(Default, Clone)]
    pub struct MockRedeemer {
        pub inner: Arc<parking_lot::RwLock<HashMap<String, String>>>,
    }

    impl MockRedeemer {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn insert(&self, key: impl Into<String>, user: impl Into<String>) {
            self.inner.write().insert(key.into(), user.into());
        }
        pub fn contains(&self, key: &str) -> bool {
            self.inner.read().contains_key(key)
        }
    }

    #[async_trait]
    impl PreauthRedeemer for MockRedeemer {
        async fn redeem(&self, key: &str) -> Result<String, RedeemError> {
            let mut g = self.inner.write();
            match g.remove(key) {
                Some(user) => Ok(user),
                None => Err(RedeemError::Unknown),
            }
        }
    }

    /// Deterministic-ish allocator for tests. Hashes the input string
    /// with FNV-1a into the CGNAT /10 host space — same first-octet
    /// invariant the OctraVPN allocator preserves, but with a much
    /// simpler implementation so the test fixture has no transitive
    /// deps.
    pub struct MockIpAllocator;

    impl IpAllocator for MockIpAllocator {
        fn allocate(&self, node_key_hex: &str) -> Result<Ipv4Addr, AllocError> {
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            for b in node_key_hex.as_bytes() {
                h ^= *b as u64;
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
            // Map into 100.64.0.0/10 host space, skipping a couple of
            // reserved low slots so we never collide with the router IP.
            let host = ((h as u32) % ((1u32 << 22) - 3)) + 2;
            const CGNAT_BASE: u32 = 0x6440_0000;
            Ok(Ipv4Addr::from((CGNAT_BASE | host).to_be_bytes()))
        }
    }
}
