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
    Router,
    routing::{get, post},
};
use parking_lot::RwLock;
use std::collections::HashMap;
use thiserror::Error;
use tokio::sync::Notify;

pub mod be_transport;
pub mod controlbase;
pub mod derp_config;
pub mod key_handler;
pub mod knock;
pub mod map;
pub mod noise;
pub mod raw_tls;
pub mod register;
pub mod serve;
pub mod tls;
pub mod wire;

pub use knock::{KnockConfig, KNOCK_HEADER, KNOCK_PATH_PREFIX, NGINX_404_BODY};
pub use noise::ServerNoiseKey;
pub use wire::{
    DerpMap, DerpRegion, DerpRegionNode, MachineRecord, MapRequest, MapResponse, MapResponseDebug,
    PeerChange, PingRequest, RegisterRequest, RegisterResponse, SSHAction, SSHPolicy, SSHPrincipal,
    SSHRule, UserProfile,
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
    /// Live policy store. `/map` reads
    /// [`crate::policy::PolicyStore::filter_rules`] to populate
    /// `MapResponse.PacketFilter`; the admin PUT route mutates the
    /// store and the store's `Notify` wakes every parked long-poller
    /// so stock daemons get the new filter on their next chunk
    /// (< 1 s in the common case).
    ///
    /// Defaults to an empty store ⇒ the wire layer falls back to the
    /// open `allow_all_packet_filter` recipe for backward compat with
    /// the interop test (which predates the policy surface).
    pub policy: Arc<crate::policy::PolicyStore>,
    /// PSK-gated handshake config — third layer of the four-layer
    /// active-probe shield. When `enabled = true`, every request to
    /// the wire surface must carry a valid knock cookie (either as the
    /// `X-OctraVPN-Knock` header or as a `/k/<knock_hex>/<path>` URL
    /// prefix); otherwise the request receives a canonical nginx 404
    /// indistinguishable from "this host runs nginx and the path is
    /// unknown". See [`knock`] for the rationale + math. Defaults to
    /// disabled so existing deployments keep working unchanged.
    pub knock: KnockConfig,
    /// Static MapResponse metadata: SSH policy expansion +
    /// `CollectServices` switch + optional `Debug` block + optional
    /// `PingRequest`. None of these touch the registry / packet
    /// filter; they're surfaced on every MapResponse so operator-side
    /// defaults stick.
    ///
    /// Defaults to [`MapMetaConfig::default`] which omits every field
    /// on the wire — reproducing the pre-feature MapResponse shape
    /// byte-for-byte.
    pub map_meta: Arc<MapMetaConfig>,
}

/// Static MapResponse metadata read once at server startup and held
/// by reference on every `/map` invocation.
///
/// Operator-supplied content surfaced on each MapResponse that *isn't*
/// derived from the live `MachineRegistry` / `PolicyStore`:
///
/// * `ssh_policy` — full `SSHPolicy` block. Empty rules ⇒ field
///   omitted on the wire (matches upstream `omitempty`).
/// * `collect_services_disabled` — true ⇒ `MapResponse.CollectServices
///   = "false"`. False ⇒ field omitted.
/// * `debug` — optional `tailcfg.MapResponse.Debug`. `None` ⇒ omitted.
/// * `ping_request` — optional one-shot ping target. `None` ⇒ omitted.
///   We don't expose an admin "force-ping" route yet; this is wired
///   for downstream consumers that want to set the field directly on
///   `WireState` at startup (e.g. a probe-suite harness).
///
/// All fields default to their zero-value ⇒ wire output is identical
/// to a pre-feature MapResponse.
#[derive(Clone, Default)]
pub struct MapMetaConfig {
    /// SSH policy expanded to wire rules. Empty rules list ⇒ the
    /// MapResponse omits the `SSHPolicy` field entirely.
    pub ssh_policy: wire::SSHPolicy,
    /// True ⇒ MapResponse carries `CollectServices = "false"`. False
    /// ⇒ field omitted ⇒ client default.
    pub collect_services_disabled: bool,
    /// Optional debug block surfaced via `MapResponse.Debug`.
    pub debug: Option<wire::MapResponseDebug>,
    /// One-shot ping request. `None` ⇒ no ping requested.
    pub ping_request: Option<wire::PingRequest>,
}

/// In-memory machine registry.
///
/// # Storage shape (#238: `all()` no-clone)
///
/// Internally backed by a copy-on-write `Arc<HashMap<…>>` swapped under
/// a short-lived `RwLock`. Reads (`snapshot`, `get`, `len`, `is_empty`)
/// take the read lock for one Arc clone or one HashMap lookup; writes
/// (`upsert`) take the write lock just long enough to clone the inner
/// map, insert, and swap the new Arc in.
///
/// The previous `all() -> Vec<(String, MachineRecord)>` shape allocated
/// one `String` + one full `MachineRecord` clone *per machine* on every
/// `/machine/map` rebuild (and again on every long-poll wake). With
/// `disco_key` + `endpoints` now landed on the record (Wall 7), each
/// clone allocates ≥ 7 strings and a `Vec<String>` — measurable
/// pressure on the steady-state allocator under a populated tailnet.
///
/// The new `snapshot()` accessor returns `Arc<HashMap<String,
/// MachineRecord>>` — one Arc-bump per call, zero per-record clones.
/// Callers iterate the borrowed map directly. The map-building hot path
/// in [`map::map_inner`] consumes this shape.
#[derive(Default)]
pub struct MachineRegistry {
    /// COW: write paths clone the map, mutate, and swap a new `Arc` in.
    /// Read paths take a read lock just long enough to bump the Arc's
    /// strong count.
    inner: RwLock<Arc<HashMap<String, MachineRecord>>>,
    /// Wakes pending `/map` long-polls when a new machine registers.
    pub(crate) notify: Arc<Notify>,
}

impl MachineRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a machine record. Wakes every pending
    /// `/map` long-poll.
    ///
    /// Writes are O(n) in the map size — we clone the underlying map
    /// once per write — but registration is rare relative to map reads
    /// in steady state, so this trade is the right one.
    pub fn upsert(&self, node_key_hex: String, rec: MachineRecord) {
        {
            let mut g = self.inner.write();
            let mut next = (**g).clone();
            next.insert(node_key_hex, rec);
            *g = Arc::new(next);
        }
        self.notify.notify_waiters();
    }

    /// Snapshot all known machines as a single `Arc<HashMap>`. The
    /// snapshot is a point-in-time view: subsequent `upsert` calls
    /// publish a new Arc; existing snapshots stay valid (and unchanged)
    /// for as long as their holder keeps them alive.
    ///
    /// One Arc clone, zero per-record clones — replaces the legacy
    /// `all()` accessor that cloned every record into a `Vec`.
    pub fn snapshot(&self) -> Arc<HashMap<String, MachineRecord>> {
        self.inner.read().clone()
    }

    /// Look up a single machine by its hex-encoded node key.
    ///
    /// Still returns an owned `MachineRecord` — call sites read the
    /// record outside of any borrow against the registry, so the clone
    /// is the cleanest shape. Use `snapshot()` if you need cross-record
    /// iteration without per-record allocation.
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

#[cfg(test)]
mod registry_tests {
    //! #238: documents the new `snapshot()` allocation profile.
    //!
    //! The legacy `all()` shape returned `Vec<(String, MachineRecord)>` —
    //! one Vec, N Strings, N full `MachineRecord` clones (each
    //! `MachineRecord` itself owns 5 Strings + a `Vec<String>` of
    //! endpoints, so the per-record cost climbs as `disco_key` /
    //! `endpoints` populate). The new `snapshot()` returns an `Arc<…>`
    //! — one strong-count bump, zero record clones.
    //!
    //! A criterion-style microbench would add a new dev-dep just for
    //! one number; the `--ignored` test below exposes a wall-clock
    //! comparison on demand without changing the dep graph.
    use super::*;
    use std::net::Ipv4Addr;

    fn mk_record(host: u32) -> MachineRecord {
        MachineRecord {
            node_key_hex: format!("nodekey-{host:08x}"),
            machine_key_hex: format!("mkey-{host:08x}"),
            user: "alice".to_string(),
            hostname: format!("host-{host}"),
            ipv4: Ipv4Addr::new(100, 64, (host >> 8) as u8, host as u8),
            disco_key: Some(format!("disco-{host:08x}")),
            endpoints: vec![format!("198.51.100.{}:41641", host & 0xff)],
        }
    }

    #[test]
    fn snapshot_returns_arc_pointer_equal_until_write() {
        let reg = MachineRegistry::new();
        for i in 0u32..16 {
            reg.upsert(format!("nk-{i}"), mk_record(i));
        }
        let s1 = reg.snapshot();
        let s2 = reg.snapshot();
        // Two snapshots taken without any intervening write share the
        // same backing allocation — pointer equality, not deep clone.
        assert!(Arc::ptr_eq(&s1, &s2), "snapshots between writes must alias");
        assert_eq!(s1.len(), 16);

        // After an upsert the snapshots diverge — the writer publishes
        // a fresh Arc, but the existing s1/s2 keep their old view.
        reg.upsert("nk-99".to_string(), mk_record(99));
        let s3 = reg.snapshot();
        assert!(!Arc::ptr_eq(&s1, &s3));
        assert_eq!(s1.len(), 16, "old snapshot unchanged");
        assert_eq!(s3.len(), 17, "new snapshot sees the write");
    }

    #[test]
    fn snapshot_cow_isolates_concurrent_readers() {
        // The whole point of COW: a long-running map handler that
        // captured a snapshot can iterate forever without blocking
        // writes, and writes don't tear the reader's view.
        let reg = MachineRegistry::new();
        for i in 0u32..8 {
            reg.upsert(format!("nk-{i}"), mk_record(i));
        }
        let snap = reg.snapshot();
        for i in 100u32..200 {
            reg.upsert(format!("nk-{i}"), mk_record(i));
        }
        assert_eq!(snap.len(), 8, "old snapshot must not see new writes");
        assert_eq!(reg.snapshot().len(), 108);
    }

    /// Microbench: 1000 iterations of "snapshot then walk every
    /// peer-MapNode-shaped field" against a 256-machine registry.
    /// Compares the new `snapshot()` path against a manual emulation of
    /// the old `all()` shape so an operator can verify the win locally
    /// with
    /// `cargo test -p headscale-api -- --ignored --nocapture
    /// snapshot_vs_legacy_all_microbench`.
    #[test]
    #[ignore = "wall-clock microbench; opt in with --ignored"]
    fn snapshot_vs_legacy_all_microbench() {
        use std::time::Instant;
        let reg = MachineRegistry::new();
        for i in 0u32..256 {
            reg.upsert(format!("nk-{i:04}"), mk_record(i));
        }
        let iters = 1000u32;

        let t0 = Instant::now();
        let mut sink = 0u64;
        for _ in 0..iters {
            let snap = reg.snapshot();
            for (k, v) in snap.iter() {
                sink ^= k.len() as u64;
                sink ^= v.endpoints.len() as u64;
                sink ^= v.disco_key.as_ref().map_or(0, String::len) as u64;
            }
        }
        let snap_elapsed = t0.elapsed();

        let t0 = Instant::now();
        for _ in 0..iters {
            // Emulate the legacy `all()` shape: one Vec of cloned pairs.
            let snap = reg.snapshot();
            let cloned: Vec<(String, MachineRecord)> =
                snap.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            for (k, v) in &cloned {
                sink ^= k.len() as u64;
                sink ^= v.endpoints.len() as u64;
                sink ^= v.disco_key.as_ref().map_or(0, String::len) as u64;
            }
        }
        let legacy_elapsed = t0.elapsed();
        eprintln!(
            "registry-snapshot microbench (256 machines × {iters} iters):\n  snapshot()       {snap_elapsed:?}\n  legacy all() emu {legacy_elapsed:?}\n  sink={sink:#x}"
        );
        // Per-iter allocation count:
        //   snapshot()       : 1 Arc strong-count bump (zero heap allocs)
        //   legacy all() emu : 1 Vec + 256 String clones + 256 record
        //                      clones (each itself ~5 strings + 1 Vec)
        // i.e. ~1538 heap allocs per call vs 0 on the new path.
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
    let knock_cfg = state.knock.clone();
    let inner = Router::new()
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
        .with_state(state);

    // PSK-gated handshake — third layer of the active-probe shield.
    // Default-off (KnockConfig::disabled()) → exact pass-through.
    // When enabled, requests must carry a valid knock cookie or get a
    // canonical nginx 404. See `tailscale_wire::knock` for the math.
    knock::wrap_router(inner, knock_cfg)
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
