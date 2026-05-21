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
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use std::collections::HashMap;
use thiserror::Error;
use tokio::sync::{Notify, watch};

use self::routes::{DebugRoutes, PrimaryRouteState, active_approved_routes};
use self::wire::stable_id_from_key;

pub mod basic_handlers;
pub mod be_transport;
pub mod controlbase;
pub mod derp_config;
pub mod key_handler;
pub mod knock;
pub mod map;
pub mod noise;
pub mod raw_tls;
pub mod register;
pub mod routes;
pub mod serve;
pub mod tls;
pub mod wire;

pub use knock::{KNOCK_HEADER, KNOCK_PATH_PREFIX, KnockConfig, NGINX_404_BODY};
pub use noise::ServerNoiseKey;
pub use wire::{
    DerpMap, DerpRegion, DerpRegionNode, MachineRecord, MapRequest, MapResponse, RegisterRequest,
    RegisterResponse,
};

// Re-export the lifecycle helper so downstream crates can spawn the GC
// sweep without reaching into the module path.
pub use self::spawn_ephemeral_gc as ephemeral_gc_task;

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

/// What a successful preauth redemption produces. Carries the user
/// label (legacy single-field contract) plus the lifecycle flags the
/// register handler needs to stamp the resulting `MachineRecord`.
///
/// Constructed via `RedeemOk::for_user("alice")` for the simple case;
/// callers that mint ephemeral preauth keys set `.ephemeral(true)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemOk {
    /// User label bound to the redeemed preauth key.
    pub user: String,
    /// True if the redeemed key was minted ephemeral. The wire layer
    /// stamps the resulting `MachineRecord.ephemeral` accordingly so
    /// the ephemeral-GC sweep can find the device after it goes
    /// silent.
    pub ephemeral: bool,
    /// Tags the preauth key embedded. Empty list ⇒ no tag binding;
    /// non-empty lists land on `MachineRecord.forced_tags` so the
    /// rendered MapNode carries them. Operators can later override
    /// via `POST /api/v1/machines/{id}/tags`.
    pub tags: Vec<String>,
}

impl RedeemOk {
    /// Construct the "plain success" shape — user-only, no ephemeral,
    /// no tags. Backwards-compatible with the original `String` return
    /// type.
    pub fn for_user(user: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            ephemeral: false,
            tags: Vec::new(),
        }
    }
    pub fn ephemeral(mut self, e: bool) -> Self {
        self.ephemeral = e;
        self
    }
    pub fn tags(mut self, t: Vec<String>) -> Self {
        self.tags = t;
        self
    }
}

impl From<String> for RedeemOk {
    fn from(user: String) -> Self {
        Self::for_user(user)
    }
}

/// Redeems Tailscale preauth tokens against whatever policy / billing
/// surface the embedding host enforces.
///
/// The wire layer hands a token string off to this trait and receives
/// either a [`RedeemOk`] (bound user + ephemeral/tags flags) or a
/// [`RedeemError`].
///
/// Async because production impls may need to talk to a database or
/// rate-limit service; the in-tree OctraVPN bridge is sync but adopts
/// the async signature trivially.
///
/// Legacy impls that return only a `String` user label can call
/// `redeem` → `Ok(user_string.into())` to satisfy the trait — `From<String>`
/// is implemented for [`RedeemOk`].
#[async_trait]
pub trait PreauthRedeemer: Send + Sync {
    async fn redeem(&self, key: &str) -> Result<RedeemOk, RedeemError>;
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
    /// MagicDNS / `DNSConfig` build state. Defaults to
    /// [`crate::dns::DnsStore::new`] — MagicDNS off, no resolvers, no
    /// records. Embedders opt into MagicDNS by calling
    /// [`crate::dns::DnsStore::from_spec`] at startup. The store's
    /// `Notify` wakes parked `/map` long-pollers on extra-records
    /// file edits + runtime spec swaps.
    pub dns: Arc<crate::dns::DnsStore>,
    /// Public control server URL. Headscale-go renders this from
    /// `cfg.ServerURL` into Apple mobileconfig profiles and Windows
    /// setup instructions. When unset, the public helper endpoints
    /// fall back to request host/proto so older embedders keep working
    /// until full config loading is wired through.
    pub public_control_url: Option<String>,
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
pub struct MachineRegistry {
    /// COW: write paths clone the map, mutate, and swap a new `Arc` in.
    /// Read paths take a read lock just long enough to bump the Arc's
    /// strong count.
    inner: RwLock<Arc<HashMap<String, MachineRecord>>>,
    /// Legacy wake channel — `Notify::notify_waiters()` fires on every
    /// upsert / lifecycle change.
    ///
    /// **Race note (audit-2 C-1 fix):** `notify_waiters` only delivers
    /// to listeners already parked on `Notified`. Long-running unfold
    /// streams (see `tailscale_wire::map`) used to re-register the
    /// `Notified` AFTER returning a built chunk — leaving a brief gap
    /// where wakes were dropped. The companion [`gen_tx`] /
    /// [`gen_rx`] watch channel below is the missed-update-tolerant
    /// path; the `Notify` stays for any caller that still wants
    /// fan-out wake without polling a counter. Both are bumped from
    /// the same call sites (`upsert`, `update_with`).
    pub(crate) notify: Arc<Notify>,
    /// audit-2 C-1: generation-counter wake channel. Each mutating
    /// call bumps the value by 1. Stream consumers hold a
    /// [`watch::Receiver`] and await `changed()`; the receiver's
    /// last-seen value lags the sender so any change between two
    /// `changed()` awaits is captured by the next one. This closes
    /// the `Notify`-only lost-wake race.
    pub(crate) gen_tx: Arc<watch::Sender<u64>>,
    /// Stateful primary-route manager. Headscale-go keeps primary
    /// route ownership sticky until the current primary stops serving
    /// a prefix; this state is kept beside the registry so repeated
    /// map rebuilds do not accidentally steal primaries by recomputing
    /// from a blank table.
    primary_routes: RwLock<PrimaryRouteState>,
}

impl Default for MachineRegistry {
    fn default() -> Self {
        let (gen_tx, _gen_rx) = watch::channel(0u64);
        Self {
            inner: RwLock::default(),
            notify: Arc::new(Notify::new()),
            gen_tx: Arc::new(gen_tx),
            primary_routes: RwLock::new(PrimaryRouteState::new()),
        }
    }
}

impl MachineRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Subscribe to the generation-counter wake channel. Each mutating
    /// call (`upsert`, `update_with`, the lifecycle setters that route
    /// through `update_with`) bumps the counter. Holders of a
    /// [`watch::Receiver`] poll `changed()` from any async context;
    /// the receiver remembers the last-seen value across `.await`
    /// boundaries, so a change between two awaits surfaces on the
    /// next one. See the comment on [`Self::notify`] for the
    /// audit-2 C-1 motivation.
    #[must_use]
    pub fn subscribe_gen(&self) -> watch::Receiver<u64> {
        self.gen_tx.subscribe()
    }

    /// Bump the generation counter alongside the `Notify` fan-out.
    /// Pulled out so both `upsert` and `update_with` route through
    /// one place — keeps the wake-channel contract DRY.
    fn wake_waiters(&self) {
        // `send_modify` returns the previous value but we don't need
        // it; this just records the bump and broadcasts to every
        // subscribed receiver. Overflow is a non-issue: u64::MAX
        // bumps at 1 per ns is 585 years.
        self.gen_tx.send_modify(|g| *g = g.wrapping_add(1));
        self.notify.notify_waiters();
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
        self.wake_waiters();
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

    /// Compute primary subnet routes for a registry snapshot while
    /// preserving existing primary ownership where still valid.
    pub fn primary_routes_for_snapshot(
        &self,
        snapshot: &HashMap<String, MachineRecord>,
    ) -> HashMap<String, Vec<String>> {
        let mut primary_routes = self.primary_routes.write();
        Self::sync_primary_routes_for_snapshot(&mut primary_routes, snapshot);

        snapshot
            .keys()
            .filter_map(|node_key| {
                let routes = primary_routes.primary_routes(stable_id_from_key(node_key));
                if routes.is_empty() {
                    None
                } else {
                    Some((node_key.clone(), routes))
                }
            })
            .collect()
    }

    /// Return the current primary-route debug state after syncing it
    /// against the supplied registry snapshot.
    pub fn debug_routes_for_snapshot(
        &self,
        snapshot: &HashMap<String, MachineRecord>,
    ) -> DebugRoutes {
        let mut primary_routes = self.primary_routes.write();
        Self::sync_primary_routes_for_snapshot(&mut primary_routes, snapshot);
        primary_routes.debug_routes()
    }

    /// Return the text form used by headscale-go's `/debug/routes`.
    pub fn debug_routes_string_for_snapshot(
        &self,
        snapshot: &HashMap<String, MachineRecord>,
    ) -> String {
        let mut primary_routes = self.primary_routes.write();
        Self::sync_primary_routes_for_snapshot(&mut primary_routes, snapshot);
        primary_routes.debug_string()
    }

    fn sync_primary_routes_for_snapshot(
        primary_routes: &mut PrimaryRouteState,
        snapshot: &HashMap<String, MachineRecord>,
    ) {
        let _ = primary_routes.sync_routes(snapshot.iter().map(|(node_key, rec)| {
            (
                stable_id_from_key(node_key),
                active_approved_routes(&rec.available_routes, &rec.approved_routes),
            )
        }));
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

    // ---- P1 lifecycle parity (juanfont/headscale@main:hscontrol/db/node.go) ----

    /// Copy-on-write mutate the map: clones the current inner Arc once,
    /// applies `f`, swaps the new Arc in atomically, and wakes every
    /// long-poll waiter.
    ///
    /// All lifecycle mutators (`set_expiry`, `rename`, `logout`,
    /// `delete`, `touch_last_seen`, `set_forced_tags`,
    /// `gc_ephemeral`) route through this helper so the COW pattern is
    /// expressed exactly once. Returns whatever `f` returns — typically
    /// a Result so callers can distinguish "node not found" from
    /// "applied".
    pub fn update_with<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&mut HashMap<String, MachineRecord>) -> R,
    {
        let r = {
            let mut g = self.inner.write();
            let mut next = (**g).clone();
            let r = f(&mut next);
            *g = Arc::new(next);
            r
        };
        self.wake_waiters();
        r
    }

    /// Re-key a machine's `expiry`. `None` ⇒ "never expires"; the most
    /// common admin action is `Some(now())` which forces an immediate
    /// logout on the next `/map` request.
    ///
    /// Returns `true` if the node existed and was updated, `false`
    /// otherwise. Mirrors `db.SetExpiry` in
    /// `juanfont/headscale@main:hscontrol/db/node.go`.
    pub fn set_expiry(&self, node_key_hex: &str, expiry: Option<DateTime<Utc>>) -> bool {
        self.update_with(|map| match map.get_mut(node_key_hex) {
            Some(rec) => {
                rec.expiry = expiry;
                true
            }
            None => false,
        })
    }

    /// Rename a machine. Upstream's `db.NodeRenameNode` validates
    /// against a regex; we trust the admin layer to have done that. An
    /// empty `new_hostname` is rejected as a no-op (returns `false`)
    /// because the upstream behaviour is identical.
    pub fn rename(&self, node_key_hex: &str, new_hostname: String) -> bool {
        if new_hostname.is_empty() {
            return false;
        }
        self.update_with(|map| match map.get_mut(node_key_hex) {
            Some(rec) => {
                rec.hostname = new_hostname;
                true
            }
            None => false,
        })
    }

    /// Logout a machine: clears the Noise/ed25519 key material so the
    /// next request can't fast-path past register, and stamps
    /// `expiry = now()` so the next `/map` round-trip returns a logout
    /// response.
    ///
    /// Mirrors `db.NodeLogout`. The record stays in the registry —
    /// upstream behaviour is "logged-out node still exists, but must
    /// re-authenticate." `delete` is the destructive counterpart.
    pub fn logout(&self, node_key_hex: &str) -> bool {
        let now = Utc::now();
        self.update_with(|map| match map.get_mut(node_key_hex) {
            Some(rec) => {
                rec.machine_key_hex.clear();
                rec.disco_key = None;
                rec.endpoints.clear();
                rec.expiry = Some(now);
                true
            }
            None => false,
        })
    }

    /// Remove a machine from the registry entirely. Mirrors
    /// `db.DeleteNode`. Returns `true` on success.
    pub fn delete(&self, node_key_hex: &str) -> bool {
        self.update_with(|map| map.remove(node_key_hex).is_some())
    }

    /// Stamp `last_seen = now()` on the given node. Called from the
    /// top of every `/map` handler so the ephemeral GC sweep can find
    /// abandoned devices.
    ///
    /// **Perf note:** the COW clone is O(n) in the registry size. For
    /// the in-memory profile we expect (≤ low thousands of nodes per
    /// embedder) the clone runs in ~50µs on a populated registry — the
    /// `snapshot_vs_legacy_all_microbench` in this module's tests
    /// covers the same allocation profile, and the legacy `all()`
    /// emulation (which clones the same map) runs at ~5 µs per 256-row
    /// iter, so the touch is firmly in the sub-100 µs band even on a
    /// 4096-row registry. If that proves too hot under sustained
    /// /map traffic we can move `last_seen` into a separate
    /// `DashMap<String, AtomicI64>` so touches don't clone the main
    /// registry; the API stays the same.
    pub fn touch_last_seen(&self, node_key_hex: &str) -> bool {
        let now = Utc::now();
        self.update_with(|map| match map.get_mut(node_key_hex) {
            Some(rec) => {
                rec.last_seen = now;
                true
            }
            None => false,
        })
    }

    /// Replace a machine's `forced_tags` list. Empty list ⇒ clear the
    /// override. Mirrors upstream's `db.SetTags` (the writer of
    /// `Node.ForcedTags`).
    pub fn set_forced_tags(&self, node_key_hex: &str, tags: Vec<String>) -> bool {
        self.update_with(|map| match map.get_mut(node_key_hex) {
            Some(rec) => {
                rec.forced_tags = tags;
                true
            }
            None => false,
        })
    }

    /// Replace a machine's approved subnet routes. Empty list clears
    /// route approval. The register/map paths maintain
    /// `available_routes`; this method records operator approval.
    pub fn set_approved_routes(&self, node_key_hex: &str, routes: Vec<String>) -> bool {
        self.update_with(|map| match map.get_mut(node_key_hex) {
            Some(rec) => {
                rec.approved_routes = routes;
                true
            }
            None => false,
        })
    }

    /// Remove every ephemeral node whose `last_seen` is older than
    /// `grace`. Returns the list of `node_key_hex` strings that were
    /// removed. Mirrors `db.EphemeralGarbageCollect` /
    /// `db.ListEphemeralNodes` from
    /// `juanfont/headscale@main:hscontrol/db/node.go`.
    ///
    /// Non-ephemeral nodes are ignored. Ephemeral nodes that have been
    /// seen within `grace` are also ignored — operators wire this to a
    /// 60s tokio task and the upstream default grace is ~120s.
    pub fn gc_ephemeral(&self, grace: std::time::Duration) -> Vec<String> {
        let now = Utc::now();
        let cutoff_chrono =
            chrono::Duration::from_std(grace).unwrap_or(chrono::Duration::seconds(0));
        let deadline = now - cutoff_chrono;
        self.update_with(|map| {
            let to_drop: Vec<String> = map
                .iter()
                .filter(|(_, rec)| rec.ephemeral && rec.last_seen < deadline)
                .map(|(k, _)| k.clone())
                .collect();
            for k in &to_drop {
                map.remove(k);
            }
            to_drop
        })
    }
}

/// Background sweep that calls [`MachineRegistry::gc_ephemeral`] every
/// `interval`. Spawn at server startup; the returned `JoinHandle` aborts
/// on drop. Upstream's default tick is 60s.
///
/// `grace` is forwarded verbatim to `gc_ephemeral`. The first sweep runs
/// after `interval` has elapsed (matches Tailscale's behaviour — no
/// startup sweep so a still-restarting fleet doesn't get reaped).
pub fn spawn_ephemeral_gc(
    machines: Arc<MachineRegistry>,
    interval: std::time::Duration,
    grace: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        // `interval` fires immediately by default; skip the first one so
        // newly-registered ephemerals get their grace.
        tick.tick().await;
        loop {
            tick.tick().await;
            let removed = machines.gc_ephemeral(grace);
            if !removed.is_empty() {
                tracing::info!(
                    target = "tailscale_wire::gc",
                    count = removed.len(),
                    "ephemeral GC removed nodes"
                );
            }
        }
    })
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
        let now = Utc::now();
        MachineRecord {
            node_key_hex: format!("nodekey-{host:08x}"),
            machine_key_hex: format!("mkey-{host:08x}"),
            user: "alice".to_string(),
            hostname: format!("host-{host}"),
            ipv4: Ipv4Addr::new(100, 64, (host >> 8) as u8, host as u8),
            disco_key: Some(format!("disco-{host:08x}")),
            endpoints: vec![format!("198.51.100.{}:41641", host & 0xff)],
            expiry: None,
            last_seen: now,
            ephemeral: false,
            created_at: now,
            forced_tags: Vec::new(),
            available_routes: Vec::new(),
            approved_routes: Vec::new(),
            register_method: 1,
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

    // ---- P1 lifecycle parity tests -------------------------------------

    /// `set_expiry` writes the field + survives subsequent snapshots.
    /// Upstream `db.SetExpiry` parity.
    #[test]
    fn set_expiry_persists_and_survives_snapshot() {
        let reg = MachineRegistry::new();
        reg.upsert("nk-a".to_string(), mk_record(1));
        let when = Utc::now() + chrono::Duration::seconds(60);
        assert!(reg.set_expiry("nk-a", Some(when)));
        let snap = reg.snapshot();
        let rec = snap.get("nk-a").unwrap();
        assert_eq!(rec.expiry, Some(when));

        // Clear it.
        assert!(reg.set_expiry("nk-a", None));
        assert!(reg.get("nk-a").unwrap().expiry.is_none());

        // Unknown key → false (no mutation).
        assert!(!reg.set_expiry("nk-zzz", Some(when)));
    }

    /// `rename` rewrites hostname; empty input is a no-op.
    #[test]
    fn rename_writes_hostname() {
        let reg = MachineRegistry::new();
        reg.upsert("nk-a".to_string(), mk_record(2));
        assert!(reg.rename("nk-a", "newhost".into()));
        assert_eq!(reg.get("nk-a").unwrap().hostname, "newhost");

        // Empty rejected.
        assert!(!reg.rename("nk-a", String::new()));
        assert_eq!(reg.get("nk-a").unwrap().hostname, "newhost");

        // Unknown rejected.
        assert!(!reg.rename("nk-zzz", "x".into()));
    }

    /// `logout` clears Noise/disco keys + endpoints AND stamps expiry.
    #[test]
    fn logout_clears_keys_and_stamps_expiry() {
        let reg = MachineRegistry::new();
        reg.upsert("nk-a".to_string(), mk_record(3));
        let before = Utc::now();
        assert!(reg.logout("nk-a"));
        let rec = reg.get("nk-a").unwrap();
        assert!(rec.machine_key_hex.is_empty());
        assert!(rec.disco_key.is_none());
        assert!(rec.endpoints.is_empty());
        // Expiry set to ~now (no more than 1s in the future since `logout` ran).
        let exp = rec.expiry.expect("expiry stamped");
        assert!(exp >= before);
        assert!(exp <= Utc::now() + chrono::Duration::seconds(1));
        assert!(rec.is_expired_at(Utc::now()));
    }

    /// `delete` removes the record entirely.
    #[test]
    fn delete_removes_record() {
        let reg = MachineRegistry::new();
        reg.upsert("nk-a".to_string(), mk_record(4));
        reg.upsert("nk-b".to_string(), mk_record(5));
        assert!(reg.delete("nk-a"));
        assert!(reg.get("nk-a").is_none());
        assert_eq!(reg.len(), 1);
        // Idempotency: second delete returns false.
        assert!(!reg.delete("nk-a"));
    }

    /// `touch_last_seen` advances the timestamp.
    #[test]
    fn touch_last_seen_advances() {
        let reg = MachineRegistry::new();
        reg.upsert("nk-a".to_string(), mk_record(6));
        let before = reg.get("nk-a").unwrap().last_seen;
        // Spin briefly to ensure the wall-clock ticks past `before`.
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(reg.touch_last_seen("nk-a"));
        let after = reg.get("nk-a").unwrap().last_seen;
        assert!(after > before, "touch should advance last_seen");
        assert!(!reg.touch_last_seen("nk-zzz"));
    }

    /// `set_forced_tags` round-trip + override semantics.
    #[test]
    fn set_forced_tags_replaces_list() {
        let reg = MachineRegistry::new();
        reg.upsert("nk-a".to_string(), mk_record(7));
        assert!(reg.set_forced_tags("nk-a", vec!["tag:dev".into(), "tag:ci".into()]));
        let rec = reg.get("nk-a").unwrap();
        assert_eq!(rec.forced_tags, vec!["tag:dev", "tag:ci"]);
        // Replace, not merge.
        assert!(reg.set_forced_tags("nk-a", vec!["tag:prod".into()]));
        assert_eq!(reg.get("nk-a").unwrap().forced_tags, vec!["tag:prod"]);
        // Empty list clears.
        assert!(reg.set_forced_tags("nk-a", Vec::new()));
        assert!(reg.get("nk-a").unwrap().forced_tags.is_empty());
    }

    /// `gc_ephemeral` only collects ephemeral rows where last_seen is
    /// older than `grace`. Non-ephemeral rows are never touched.
    #[test]
    fn gc_ephemeral_only_collects_stale_ephemerals() {
        let reg = MachineRegistry::new();

        let mut a = mk_record(10);
        a.ephemeral = true;
        a.last_seen = Utc::now() - chrono::Duration::seconds(120);
        reg.upsert("nk-a".to_string(), a);

        let mut b = mk_record(11);
        b.ephemeral = true;
        b.last_seen = Utc::now(); // fresh, must survive
        reg.upsert("nk-b".to_string(), b);

        let mut c = mk_record(12);
        c.ephemeral = false;
        c.last_seen = Utc::now() - chrono::Duration::days(7); // ancient but not ephemeral
        reg.upsert("nk-c".to_string(), c);

        let removed = reg.gc_ephemeral(std::time::Duration::from_mins(1));
        assert_eq!(removed, vec!["nk-a".to_string()]);
        assert!(reg.get("nk-a").is_none());
        assert!(reg.get("nk-b").is_some(), "fresh ephemeral survives");
        assert!(reg.get("nk-c").is_some(), "non-ephemeral never touched");
    }

    /// `gc_ephemeral` returns an empty list when nothing matches.
    #[test]
    fn gc_ephemeral_noop_when_nothing_stale() {
        let reg = MachineRegistry::new();
        let mut a = mk_record(20);
        a.ephemeral = true;
        a.last_seen = Utc::now();
        reg.upsert("nk-a".to_string(), a);
        let removed = reg.gc_ephemeral(std::time::Duration::from_mins(1));
        assert!(removed.is_empty());
        assert_eq!(reg.len(), 1);
    }

    /// `is_expired_at` mirrors upstream `Node.IsExpired`: `None` means
    /// "never"; `Some(t)` with `t <= now` is expired.
    #[test]
    fn is_expired_at_semantics() {
        let mut r = mk_record(99);
        // No expiry.
        assert!(!r.is_expired_at(Utc::now()));
        // Expiry in the future.
        let later = Utc::now() + chrono::Duration::seconds(60);
        r.expiry = Some(later);
        assert!(!r.is_expired_at(Utc::now()));
        // At/after expiry.
        r.expiry = Some(Utc::now() - chrono::Duration::seconds(1));
        assert!(r.is_expired_at(Utc::now()));
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
        .route("/robots.txt", get(basic_handlers::handle_robots))
        .route("/health", get(basic_handlers::handle_health))
        .route("/version", get(basic_handlers::handle_version))
        .route("/windows", get(basic_handlers::handle_windows))
        .route("/apple", get(basic_handlers::handle_apple))
        .route(
            "/apple/:platform",
            get(basic_handlers::handle_apple_platform),
        )
        .route("/swagger", get(basic_handlers::handle_swagger))
        .route(
            "/swagger/v1/openapiv2.json",
            get(basic_handlers::handle_swagger_api_v1),
        )
        .route("/debug/routes", get(basic_handlers::handle_debug_routes))
        .route("/debug/derp", get(basic_handlers::handle_debug_derp))
        .route(
            "/debug/registration-cache",
            get(basic_handlers::handle_debug_registration_cache),
        )
        .route("/favicon.ico", get(basic_handlers::handle_favicon))
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
        .fallback(basic_handlers::handle_fallback)
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

    /// In-memory preauth redeemer: keys → user labels (+ optional
    /// ephemeral / tags metadata).
    ///
    /// Single-use: a successful redeem removes the key from the map so
    /// the second redeem of the same token returns
    /// [`RedeemError::Unknown`] — matches the OctraVPN minter's
    /// non-reusable default.
    #[derive(Default, Clone)]
    pub struct MockRedeemer {
        pub inner: Arc<parking_lot::RwLock<HashMap<String, RedeemOk>>>,
    }

    impl MockRedeemer {
        pub fn new() -> Self {
            Self::default()
        }
        /// Insert a plain key → user mapping (non-ephemeral, no tags).
        pub fn insert(&self, key: impl Into<String>, user: impl Into<String>) {
            self.inner
                .write()
                .insert(key.into(), RedeemOk::for_user(user.into()));
        }
        /// Insert a key with explicit lifecycle metadata (ephemeral
        /// flag + tags). Used by the lifecycle tests to exercise the
        /// ephemeral-GC path.
        #[allow(dead_code)] // used by external integration tests
        pub fn insert_full(&self, key: impl Into<String>, ok: RedeemOk) {
            self.inner.write().insert(key.into(), ok);
        }
        pub fn contains(&self, key: &str) -> bool {
            self.inner.read().contains_key(key)
        }
    }

    #[async_trait]
    impl PreauthRedeemer for MockRedeemer {
        async fn redeem(&self, key: &str) -> Result<RedeemOk, RedeemError> {
            let mut g = self.inner.write();
            match g.remove(key) {
                Some(ok) => Ok(ok),
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
