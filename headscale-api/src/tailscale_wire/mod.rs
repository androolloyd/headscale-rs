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
//! - **Noise-inner `POST /machine/{node_key}/register`** ([`register`]) —
//!   decodes a JSON `RegisterRequest`, redeems the presented authkey via
//!   the injected [`PreauthRedeemer`], allocates a tailnet IP via the
//!   injected [`IpAllocator`].
//! - **Noise-inner `POST /machine/{node_key}/map`** ([`map`]) — long-poll
//!   peer map.
//!
//! See the upstream OctraVPN module's decision log (preserved in git
//! history) for the rationale behind each wire choice.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::{
    Router,
    extract::Request,
    middleware::{self, Next},
    response::Response as AxumResponse,
    routing::{any, get, head, post},
};
use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use thiserror::Error;
use tokio::sync::{Notify, oneshot, watch};

use self::routes::{
    DebugRoutes, PrimaryRouteState, active_primary_routes, auto_approved_routes_for_node,
};
use self::wire::stable_id_from_key;

/// Headscale-go default: pending interactive registrations are valid
/// for 15 minutes before the registration cache can evict them.
pub const REGISTRATION_CACHE_EXPIRATION: Duration = Duration::from_secs(15 * 60);
/// Headscale-go default cleanup tick for the registration cache.
pub const REGISTRATION_CACHE_CLEANUP: Duration = Duration::from_secs(20 * 60);
const PING_ID_LENGTH: usize = 16;
const PING_ID_URLSAFE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
const REGISTER_METHOD_OIDC: i32 = 3;
const STREAM_OFFLINE_GRACE: Duration = Duration::from_secs(10);

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

pub use basic_handlers::DebugConfigInfo as RuntimeConfigSnapshot;
pub use knock::{KNOCK_HEADER, KNOCK_PATH_PREFIX, KnockConfig, NGINX_404_BODY};
pub use noise::ServerNoiseKey;
pub use wire::{
    DerpMap, DerpRegion, DerpRegionNode, MachineRecord, MapRequest, MapResponse, NetInfo,
    PingRequest, RegisterRequest, RegisterResponse,
};

// Re-export the lifecycle helper so downstream crates can spawn the GC
// sweep without reaching into the module path.
pub use self::spawn_ephemeral_gc as ephemeral_gc_task;
pub use self::spawn_node_expiry_waker as node_expiry_waker_task;

/// Runtime DERP map store.
///
/// Headscale-go can refresh configured DERP map URLs while the server is
/// running. The wire runtime therefore cannot treat the map as immutable after
/// startup: `/map` handlers need a cheap current snapshot, and long-polling map
/// streams need a wake signal when config refreshes replace the map.
pub struct DerpMapStore {
    current: RwLock<wire::DerpMap>,
    notify: Notify,
    gen_tx: watch::Sender<u64>,
}

impl DerpMapStore {
    pub fn new(map: wire::DerpMap) -> Self {
        let (gen_tx, _) = watch::channel(0);
        Self {
            current: RwLock::new(map),
            notify: Notify::new(),
            gen_tx,
        }
    }

    pub fn shared(map: wire::DerpMap) -> Arc<Self> {
        Arc::new(Self::new(map))
    }

    pub fn snapshot(&self) -> wire::DerpMap {
        self.current.read().clone()
    }

    pub fn set(&self, map: wire::DerpMap) {
        *self.current.write() = map;
        let current_generation = *self.gen_tx.borrow();
        let next_generation = current_generation.wrapping_add(1);
        let _ = self.gen_tx.send(next_generation);
        self.notify.notify_waiters();
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.gen_tx.subscribe()
    }

    pub async fn wait_for_change(&self) {
        self.notify.notified().await;
    }
}

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
#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum RedeemError {
    /// Token doesn't match any minted key.
    #[error("preauth: unknown key")]
    Unknown,
    /// Token was valid at some point but its TTL has passed.
    #[error("preauth: key expired")]
    Expired,
    /// Token is valid, but a non-reusable key has already been
    /// consumed.
    #[error("preauth: key already used")]
    AlreadyUsed,
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
    /// Numeric `pre_auth_keys.id` when the redeemer is backed by the
    /// headscale-go-shaped SQLite table. Volatile redeemers leave this
    /// empty, but persistent wire registration uses it to preserve
    /// `nodes.auth_key_id` like upstream.
    pub auth_key_id: Option<i64>,
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
            auth_key_id: None,
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
    pub fn auth_key_id(mut self, id: i64) -> Self {
        self.auth_key_id = Some(id);
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

    /// Return key metadata without consuming or validating it.
    ///
    /// Headscale-go first fetches the pre-auth key row and then
    /// skips `Validate` for an already-registered same-machine,
    /// same-user, same-node-key re-registration. Stores that can
    /// locate used/expired keys should override this method; legacy
    /// one-shot redeemers can keep the default and will retain their
    /// previous strict behavior.
    async fn lookup(&self, _key: &str) -> Option<RedeemOk> {
        None
    }
}

/// Allocates tailnet addresses for a registering node.
///
/// Implementations are expected to be deterministic given
/// `node_key_hex` (the in-tree OctraVPN allocator hashes
/// `(tailnet_id, member_addr, ip_salt)` into the CGNAT host space), but
/// the trait does not mandate determinism — a stateful allocator that
/// rotates assignments on each call is also valid.
pub trait IpAllocator: Send + Sync {
    fn allocate(&self, node_key_hex: &str) -> Result<Ipv4Addr, AllocError>;

    /// Whether IPv4 is enabled in the current prefix config.
    ///
    /// Existing embedders are IPv4-first, so the default remains
    /// enabled. Production headscale-rs overrides this from loaded
    /// `prefixes` config.
    fn ipv4_enabled(&self) -> bool {
        true
    }

    /// Optionally allocate an IPv6 address for the same node.
    ///
    /// The default preserves the original IPv4-only embedder contract.
    /// Production headscale-rs overrides this when an upstream-style
    /// `prefixes.v6` is configured.
    fn allocate_ipv6(&self, _node_key_hex: &str) -> Result<Option<Ipv6Addr>, AllocError> {
        Ok(None)
    }

    /// Whether IPv6 is enabled in the current prefix config.
    ///
    /// The default is conservative for third-party allocators that
    /// already have IPv6 rows they want to preserve. The production
    /// allocator returns false when `prefixes.v6` is unset so
    /// `BackfillNodeIPs` can mirror headscale-go's destructive
    /// disabled-family cleanup.
    fn ipv6_enabled(&self) -> bool {
        true
    }
}

/// Result of persisting a wire registration into the durable node store.
#[derive(Debug, Clone)]
pub struct PersistedMachineRegistration {
    pub record: MachineRecord,
    pub replaced_node_key_hex: Option<String>,
}

/// Optional persistence hook for wire registration.
///
/// The wire layer still owns the live [`MachineRegistry`] projection
/// used by `/map`; this trait lets embedders make the durable
/// headscale-go-shaped `nodes` table canonical for registration
/// writes, then project the persisted row back into that live
/// registry.
#[async_trait]
pub trait MachineRegistrationStore: Send + Sync {
    async fn create_or_update_auth_key_registration(
        &self,
        record: MachineRecord,
        policy: &crate::policy::PolicyStore,
        auth_key_id: Option<i64>,
    ) -> Result<PersistedMachineRegistration, String>;

    async fn sync_runtime_machine_state(
        &self,
        record: MachineRecord,
        _policy: &crate::policy::PolicyStore,
    ) -> Result<PersistedMachineRegistration, String> {
        Ok(PersistedMachineRegistration {
            record,
            replaced_node_key_hex: None,
        })
    }

    async fn delete_machine_registration(&self, _node_key_hex: &str) -> Result<(), String> {
        Ok(())
    }
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
    /// Optional durable registration store. When set, auth-key
    /// registration writes to this store first and treats
    /// [`Self::machines`] as a projection of the persisted row.
    pub registration_store: Option<Arc<dyn MachineRegistrationStore>>,
    /// DERP map served on `/machine/map`. The store gives each map
    /// handler a cheap cloned snapshot and wakes long-poll streams when
    /// runtime DERP refresh replaces it.
    pub derp_map: Arc<DerpMapStore>,
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
    /// Loaded runtime configuration serialized by `/debug/config`.
    ///
    /// Headscale-go returns its loaded `types.Config` directly from this
    /// endpoint. Keep static operator settings here and let the handler overlay
    /// live DNS/DERP stores that can change after startup.
    pub runtime_config: Arc<RuntimeConfigSnapshot>,
    /// Pending web/CLI registration cache. Headscale-go stores nodes
    /// that reached the interactive registration flow here, keyed by
    /// the 24-byte registration ID shown in `/register/{id}`. The
    /// gRPC `RegisterNode` RPC consumes the same entry, which lets a
    /// browser/CLI approval complete the wire client's follow-up
    /// registration.
    pub registration_cache: Arc<RegistrationCache>,
    /// Correlates outbound `MapResponse.PingRequest` callbacks with
    /// public `HEAD /machine/ping-response?id=...` responses.
    pub pings: Arc<PingTracker>,
}

impl WireState {
    /// Register a pending ping for `node_id`. Callers should dispatch
    /// the returned ID with [`Self::dispatch_ping_request`] and then
    /// await the receiver with their own timeout.
    pub fn register_ping(&self, node_id: u64) -> (String, oneshot::Receiver<Duration>) {
        self.pings.register(node_id)
    }

    /// Queue a headscale-go style URL callback ping for the target node.
    ///
    /// The returned request is cloned into the outbound queue and is
    /// provided for tests/debug callers that want to inspect the exact
    /// wire shape.
    pub fn dispatch_ping_request(
        &self,
        node_id: u64,
        ping_id: &str,
        log: bool,
        url_is_noise: bool,
    ) -> PingRequest {
        let request = PingRequest {
            url: self.ping_response_url(ping_id),
            url_is_noise,
            log,
            ..PingRequest::default()
        };
        self.pings.enqueue(node_id, request.clone());
        request
    }

    fn ping_response_url(&self, ping_id: &str) -> String {
        match self.public_control_url.as_deref() {
            Some(url) if !url.is_empty() => {
                format!(
                    "{}/machine/ping-response?id={ping_id}",
                    url.trim_end_matches('/')
                )
            }
            _ => format!("/machine/ping-response?id={ping_id}"),
        }
    }
}

/// Result metadata returned when a pending ping callback is correlated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingCompletion {
    pub node_id: u64,
    pub latency: Duration,
}

/// In-memory PingRequest tracker.
///
/// It mirrors headscale-go's bounded lifecycle for this parity slice:
/// callers register an unguessable ID, enqueue a `PingRequest` to a
/// node's map stream, and the public callback completes the matching ID.
/// There is intentionally no server-side TTL yet; callers own timeout
/// and cancellation just like upstream's `state.pingTracker`.
pub struct PingTracker {
    inner: Mutex<PingTrackerInner>,
    gen_tx: Arc<watch::Sender<u64>>,
}

struct PingTrackerInner {
    pending: BTreeMap<String, PendingPing>,
    outbound: BTreeMap<u64, VecDeque<PingRequest>>,
    generation: u64,
}

struct PendingPing {
    node_id: u64,
    start_time: Instant,
    response_tx: oneshot::Sender<Duration>,
}

impl PingTracker {
    pub fn new() -> Self {
        let (gen_tx, _gen_rx) = watch::channel(0u64);
        Self {
            inner: Mutex::new(PingTrackerInner {
                pending: BTreeMap::new(),
                outbound: BTreeMap::new(),
                generation: 0,
            }),
            gen_tx: Arc::new(gen_tx),
        }
    }

    pub fn register(&self, node_id: u64) -> (String, oneshot::Receiver<Duration>) {
        loop {
            let ping_id = new_ping_id();
            let (tx, rx) = oneshot::channel();
            let mut inner = self.inner.lock();
            if inner.pending.contains_key(&ping_id) {
                continue;
            }
            inner.pending.insert(
                ping_id.clone(),
                PendingPing {
                    node_id,
                    start_time: Instant::now(),
                    response_tx: tx,
                },
            );
            return (ping_id, rx);
        }
    }

    pub fn enqueue(&self, node_id: u64, request: PingRequest) {
        let generation = {
            let mut inner = self.inner.lock();
            inner
                .outbound
                .entry(node_id)
                .or_default()
                .push_back(request);
            bump_ping_generation(&mut inner)
        };
        let _ = self.gen_tx.send(generation);
    }

    pub fn complete(&self, ping_id: &str) -> Option<PingCompletion> {
        let pending = self.inner.lock().pending.remove(ping_id)?;
        let latency = pending.start_time.elapsed();
        let _ = pending.response_tx.send(latency);
        Some(PingCompletion {
            node_id: pending.node_id,
            latency,
        })
    }

    pub fn cancel(&self, ping_id: &str) -> bool {
        self.inner.lock().pending.remove(ping_id).is_some()
    }

    pub fn pending_len(&self) -> usize {
        self.inner.lock().pending.len()
    }

    pub fn queued_len(&self) -> usize {
        self.inner.lock().outbound.values().map(VecDeque::len).sum()
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.gen_tx.subscribe()
    }

    pub(crate) fn pop_next_for_node(&self, node_id: u64) -> Option<PingRequest> {
        let (request, generation) = {
            let mut inner = self.inner.lock();
            let queue = inner.outbound.get_mut(&node_id)?;
            let request = queue.pop_front();
            let more_pending = !queue.is_empty();
            if queue.is_empty() {
                inner.outbound.remove(&node_id);
            }
            let generation = more_pending.then(|| bump_ping_generation(&mut inner));
            (request, generation)
        };

        if let Some(generation) = generation {
            let _ = self.gen_tx.send(generation);
        }
        request
    }
}

impl Default for PingTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteHealthProbeResult {
    pub node_id: u64,
    pub healthy: bool,
    pub latency: Option<Duration>,
}

#[derive(Debug)]
pub struct RouteHealthProbeHandle {
    task: tokio::task::JoinHandle<()>,
}

impl RouteHealthProbeHandle {
    pub fn abort(&self) {
        self.task.abort();
    }
}

/// Start periodic route-candidate health probes.
///
/// Candidates are online, non-expired nodes that currently advertise and
/// are approved for at least one subnet route. Exit routes are excluded
/// from this probe path because they do not participate in primary-route
/// election.
pub fn spawn_route_health_probe(
    state: WireState,
    probe_interval: Duration,
    probe_timeout: Duration,
) -> Option<RouteHealthProbeHandle> {
    if probe_interval.is_zero() || probe_timeout.is_zero() {
        return None;
    }

    Some(RouteHealthProbeHandle {
        task: tokio::spawn(async move {
            loop {
                tokio::time::sleep(probe_interval).await;
                let _ = run_route_health_probe_once(&state, probe_timeout).await;
            }
        }),
    })
}

pub(crate) async fn run_route_health_probe_once(
    state: &WireState,
    probe_timeout: Duration,
) -> Vec<RouteHealthProbeResult> {
    let candidates = route_health_probe_candidates(&state.machines);
    futures_util::future::join_all(
        candidates
            .into_iter()
            .map(|node_id| probe_route_candidate(state, node_id, probe_timeout)),
    )
    .await
}

pub(crate) fn route_health_probe_candidates(machines: &MachineRegistry) -> Vec<u64> {
    let snapshot = machines.snapshot();
    let online_states = machines.online_states();
    let now = Utc::now();
    let mut candidates = snapshot
        .iter()
        .filter_map(|(node_key, rec)| {
            let node_id = stable_id_from_key(node_key);
            if rec.is_expired_at(now) || !online_states.get(&node_id).copied().unwrap_or(false) {
                return None;
            }
            (!active_primary_routes(&rec.available_routes, &rec.approved_routes).is_empty())
                .then_some(node_id)
        })
        .collect::<Vec<_>>();
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

async fn probe_route_candidate(
    state: &WireState,
    node_id: u64,
    probe_timeout: Duration,
) -> RouteHealthProbeResult {
    let (ping_id, rx) = state.register_ping(node_id);
    state.dispatch_ping_request(node_id, &ping_id, false, false);

    if let Ok(Ok(latency)) = tokio::time::timeout(probe_timeout, rx).await {
        state.machines.set_route_candidate_health(node_id, true);
        RouteHealthProbeResult {
            node_id,
            healthy: true,
            latency: Some(latency),
        }
    } else {
        state.pings.cancel(&ping_id);
        state.machines.set_route_candidate_health(node_id, false);
        RouteHealthProbeResult {
            node_id,
            healthy: false,
            latency: None,
        }
    }
}

fn bump_ping_generation(inner: &mut PingTrackerInner) -> u64 {
    inner.generation = inner.generation.wrapping_add(1);
    inner.generation
}

fn new_ping_id() -> String {
    use rand_core::RngCore;

    let mut raw = [0u8; PING_ID_LENGTH];
    rand_core::OsRng.fill_bytes(&mut raw);
    raw.into_iter()
        .map(|b| PING_ID_URLSAFE[(b & 0b0011_1111) as usize] as char)
        .collect()
}

/// Shared pending registration cache keyed by headscale-go's
/// 24-character registration ID.
pub struct RegistrationCache {
    inner: RwLock<BTreeMap<String, Arc<RegistrationEntry>>>,
    expiration: Duration,
    cleanup: Duration,
}

#[derive(Debug)]
struct RegistrationEntry {
    record: MachineRecord,
    expires_at: Instant,
    outcome: Mutex<Option<RegistrationOutcome>>,
    notify: Notify,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
enum RegistrationOutcome {
    Registered(MachineRecord),
    ApprovedWithoutNode,
    Rejected(String),
    Expired,
}

/// Result of waiting for a pending web/CLI registration to finish.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum RegistrationWaitOutcome {
    Registered(MachineRecord),
    ApprovedWithoutNode,
    Rejected(String),
    Expired,
    Missing,
}

impl RegistrationCache {
    pub fn new() -> Self {
        Self::with_tuning(REGISTRATION_CACHE_EXPIRATION, REGISTRATION_CACHE_CLEANUP)
    }

    pub fn with_tuning(expiration: Duration, cleanup: Duration) -> Self {
        Self {
            inner: RwLock::new(BTreeMap::new()),
            expiration,
            cleanup,
        }
    }

    pub fn insert(&self, registration_id: String, record: MachineRecord) {
        self.prune_expired();
        let entry = Arc::new(RegistrationEntry::new(record, self.expiration));
        if let Some(old) = self.inner.write().insert(registration_id, entry) {
            old.expire();
        }
    }

    pub fn get(&self, registration_id: &str) -> Option<MachineRecord> {
        self.get_entry(registration_id)
            .map(|entry| entry.record.clone())
    }

    pub fn remove(&self, registration_id: &str) -> Option<MachineRecord> {
        let entry = self.inner.write().remove(registration_id)?;
        entry.expire();
        Some(entry.record.clone())
    }

    pub fn complete(&self, registration_id: &str, registered: MachineRecord) -> bool {
        let entry = self.inner.write().remove(registration_id);
        match entry {
            Some(entry) => {
                entry.complete(registered);
                true
            }
            None => false,
        }
    }

    pub fn approve_without_node(&self, registration_id: &str) -> bool {
        let entry = self.inner.write().remove(registration_id);
        match entry {
            Some(entry) => {
                entry.approve_without_node();
                true
            }
            None => false,
        }
    }

    pub fn reject(&self, registration_id: &str, reason: impl Into<String>) -> bool {
        let entry = self.inner.write().remove(registration_id);
        match entry {
            Some(entry) => {
                entry.reject(reason.into());
                true
            }
            None => false,
        }
    }

    pub async fn wait_for_registration(&self, registration_id: &str) -> RegistrationWaitOutcome {
        let Some(entry) = self.get_entry(registration_id) else {
            return RegistrationWaitOutcome::Missing;
        };

        loop {
            let notified = entry.notify.notified();
            tokio::pin!(notified);

            match entry.outcome() {
                Some(RegistrationOutcome::Registered(record)) => {
                    return RegistrationWaitOutcome::Registered(record);
                }
                Some(RegistrationOutcome::ApprovedWithoutNode) => {
                    return RegistrationWaitOutcome::ApprovedWithoutNode;
                }
                Some(RegistrationOutcome::Rejected(reason)) => {
                    return RegistrationWaitOutcome::Rejected(reason);
                }
                Some(RegistrationOutcome::Expired) => return RegistrationWaitOutcome::Expired,
                None => {}
            }

            let now = Instant::now();
            if now >= entry.expires_at {
                self.expire_if_current(registration_id, &entry);
                continue;
            }

            tokio::select! {
                () = &mut notified => {}
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(entry.expires_at)) => {
                    self.expire_if_current(registration_id, &entry);
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.prune_expired();
        self.inner.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.prune_expired();
        self.inner.read().is_empty()
    }

    pub fn contains_node_key(&self, node_key_hex: &str) -> bool {
        self.prune_expired();
        self.inner
            .read()
            .values()
            .any(|entry| entry.record.node_key_hex == node_key_hex)
    }

    pub fn expiration(&self) -> Duration {
        self.expiration
    }

    pub fn cleanup_interval(&self) -> Duration {
        self.cleanup
    }

    pub fn prune_expired(&self) -> usize {
        let now = Instant::now();
        let mut expired = Vec::new();
        {
            let mut inner = self.inner.write();
            let expired_ids = inner
                .iter()
                .filter(|&(_id, entry)| now >= entry.expires_at)
                .map(|(id, _entry)| id.clone())
                .collect::<Vec<_>>();

            for id in expired_ids {
                if let Some(entry) = inner.remove(&id) {
                    expired.push(entry);
                }
            }
        }

        let count = expired.len();
        for entry in expired {
            entry.expire();
        }
        count
    }

    fn get_entry(&self, registration_id: &str) -> Option<Arc<RegistrationEntry>> {
        self.prune_expired();
        self.inner.read().get(registration_id).cloned()
    }

    fn expire_if_current(&self, registration_id: &str, target: &Arc<RegistrationEntry>) -> bool {
        let removed = {
            let mut inner = self.inner.write();
            match inner.get(registration_id) {
                Some(current) if Arc::ptr_eq(current, target) => inner.remove(registration_id),
                _ => None,
            }
        };

        match removed {
            Some(entry) => {
                entry.expire();
                true
            }
            None => false,
        }
    }
}

impl Default for RegistrationCache {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistrationEntry {
    fn new(record: MachineRecord, expiration: Duration) -> Self {
        Self {
            record,
            expires_at: Instant::now() + expiration,
            outcome: Mutex::new(None),
            notify: Notify::new(),
        }
    }

    fn outcome(&self) -> Option<RegistrationOutcome> {
        self.outcome.lock().clone()
    }

    fn complete(&self, record: MachineRecord) {
        let mut outcome = self.outcome.lock();
        if outcome.is_none() {
            *outcome = Some(RegistrationOutcome::Registered(record));
            self.notify.notify_waiters();
        }
    }

    fn approve_without_node(&self) {
        let mut outcome = self.outcome.lock();
        if outcome.is_none() {
            *outcome = Some(RegistrationOutcome::ApprovedWithoutNode);
            self.notify.notify_waiters();
        }
    }

    fn reject(&self, reason: String) {
        let mut outcome = self.outcome.lock();
        if outcome.is_none() {
            *outcome = Some(RegistrationOutcome::Rejected(reason));
            self.notify.notify_waiters();
        }
    }

    fn expire(&self) {
        let mut outcome = self.outcome.lock();
        if outcome.is_none() {
            *outcome = Some(RegistrationOutcome::Expired);
            self.notify.notify_waiters();
        }
    }
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
    /// Batcher connection state by stable node ID. The count is the
    /// current active `Stream:true` map-response connection count, and
    /// zero-count entries are retained after disconnect to match
    /// headscale-go's `/debug/batcher` rapid-reconnect state.
    active_connections: RwLock<BTreeMap<u64, usize>>,
    /// Volatile headscale-go `Node.IsOnline` equivalent. This is kept
    /// separate from persisted machine records: startup/default state
    /// is offline until a streaming map session marks the node online.
    online_states: RwLock<BTreeMap<u64, bool>>,
    /// Monotonic per-node stream generation used to suppress stale
    /// delayed-offline tasks after a rapid reconnect.
    connection_generations: RwLock<BTreeMap<u64, u64>>,
    /// Upstream-shaped ephemeral-node lifecycle manager. When
    /// configured by production startup it cancels per-node deletion
    /// timers on stream connect and schedules them after disconnect.
    ephemeral_gc: RwLock<Option<Arc<EphemeralNodeGc>>>,
    /// Prometheus-compatible counters for the Tailscale wire surface.
    metrics: WireMetrics,
}

#[derive(Default)]
struct WireMetrics {
    mapresponse_endpoint_updates: RwLock<BTreeMap<String, u64>>,
    mapresponse_ended: RwLock<BTreeMap<String, u64>>,
    mapresponse_generated: RwLock<BTreeMap<String, u64>>,
    mapresponse_sent: RwLock<BTreeMap<(String, String), u64>>,
    mapresponse_last_sent: RwLock<BTreeMap<(String, String), f64>>,
    http_requests: RwLock<BTreeMap<(String, String, String), u64>>,
    http_duration: RwLock<BTreeMap<String, HistogramMetric>>,
    nodestore_operations: RwLock<BTreeMap<String, u64>>,
    nodestore_operation_duration: RwLock<BTreeMap<String, HistogramMetric>>,
    nodestore_batch_size: RwLock<HistogramMetric>,
    nodestore_batch_duration: RwLock<HistogramMetric>,
    nodestore_snapshot_build_duration: RwLock<HistogramMetric>,
    nodestore_peers_calculation_duration: RwLock<HistogramMetric>,
}

pub(crate) const PROMETHEUS_DEFAULT_BUCKETS: &[(f64, &str)] = &[
    (0.005, "0.005"),
    (0.01, "0.01"),
    (0.025, "0.025"),
    (0.05, "0.05"),
    (0.1, "0.1"),
    (0.25, "0.25"),
    (0.5, "0.5"),
    (1.0, "1"),
    (2.5, "2.5"),
    (5.0, "5"),
    (10.0, "10"),
];

pub(crate) const NODESTORE_BATCH_SIZE_BUCKETS: &[(f64, &str)] = &[
    (1.0, "1"),
    (2.0, "2"),
    (5.0, "5"),
    (10.0, "10"),
    (20.0, "20"),
    (50.0, "50"),
    (100.0, "100"),
];

#[derive(Debug, Clone, Default)]
pub(crate) struct HistogramMetric {
    pub buckets: BTreeMap<String, u64>,
    pub count: u64,
    pub sum: f64,
}

impl HistogramMetric {
    fn observe(&mut self, buckets: &[(f64, &str)], value: f64) {
        self.count += 1;
        self.sum += value;
        for (upper_bound, label) in buckets {
            if value <= *upper_bound {
                *self.buckets.entry((*label).to_string()).or_insert(0) += 1;
            }
        }
    }

    pub(crate) fn bucket(&self, label: &str) -> u64 {
        self.buckets.get(label).copied().unwrap_or(0)
    }
}

impl Default for MachineRegistry {
    fn default() -> Self {
        let (gen_tx, _gen_rx) = watch::channel(0u64);
        Self {
            inner: RwLock::default(),
            notify: Arc::new(Notify::new()),
            gen_tx: Arc::new(gen_tx),
            primary_routes: RwLock::new(PrimaryRouteState::new()),
            active_connections: RwLock::new(BTreeMap::new()),
            online_states: RwLock::new(BTreeMap::new()),
            connection_generations: RwLock::new(BTreeMap::new()),
            ephemeral_gc: RwLock::new(None),
            metrics: WireMetrics::default(),
        }
    }
}

impl MachineRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable upstream-shaped ephemeral node garbage collection for
    /// this live registry projection.
    ///
    /// Headscale-go uses per-node timers: existing ephemeral nodes are
    /// scheduled at startup, active map streams cancel their timer,
    /// and disconnect schedules a new deletion timer. The returned
    /// handle owns no listener task; it controls the timers installed
    /// in this registry.
    pub fn configure_ephemeral_gc(
        self: &Arc<Self>,
        registration_store: Option<Weak<dyn MachineRegistrationStore>>,
        inactivity_timeout: Duration,
    ) -> EphemeralGcHandle {
        let gc = Arc::new(EphemeralNodeGc {
            machines: Arc::downgrade(self),
            registration_store,
            inactivity_timeout,
            timers: Mutex::new(BTreeMap::new()),
            closed: AtomicBool::new(false),
        });
        if let Some(previous) = self.ephemeral_gc.write().replace(gc.clone()) {
            previous.abort_all();
        }
        EphemeralGcHandle { inner: gc }
    }

    fn ephemeral_gc(&self) -> Option<Arc<EphemeralNodeGc>> {
        self.ephemeral_gc.read().clone()
    }

    fn ephemeral_node_key_by_id(&self, node_id: u64) -> Option<String> {
        self.snapshot().iter().find_map(|(node_key, rec)| {
            (rec.ephemeral && stable_id_from_key(node_key) == node_id).then(|| node_key.clone())
        })
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

    /// Headscale-go `State.ExpireExpiredNodes` parity: find nodes whose
    /// key-expiry crossed since the previous scheduler pass and wake
    /// active map streams so they rebuild with `KeyExpiry`/`Expired`.
    ///
    /// This is intentionally notification-only. Expired nodes stay in
    /// the registry and persistent store; auth/register paths decide
    /// what a client must do next.
    pub fn expire_expired_nodes_since(
        &self,
        last_check: DateTime<Utc>,
    ) -> (DateTime<Utc>, Vec<String>) {
        let started = Utc::now();
        let expired = self.wake_expired_nodes_between(last_check, started);
        (started, expired)
    }

    fn wake_expired_nodes_between(
        &self,
        last_check: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Vec<String> {
        let start = Instant::now();
        let expired: Vec<String> = self
            .snapshot()
            .iter()
            .filter_map(|(node_key, rec)| match rec.expiry {
                Some(expiry) if expiry > last_check && expiry <= now => Some(node_key.clone()),
                _ => None,
            })
            .collect();
        if expired.is_empty() {
            return expired;
        }

        let elapsed = start.elapsed();
        self.record_nodestore_operation("expire", elapsed);
        self.record_nodestore_batch(expired.len(), elapsed);
        self.wake_waiters();
        expired
    }

    /// Insert or replace a machine record. Wakes every pending
    /// `/map` long-poll.
    ///
    /// Writes are O(n) in the map size — we clone the underlying map
    /// once per write — but registration is rare relative to map reads
    /// in steady state, so this trade is the right one.
    pub fn upsert(&self, node_key_hex: String, rec: MachineRecord) {
        let start = Instant::now();
        {
            let mut g = self.inner.write();
            let mut next = (**g).clone();
            next.insert(node_key_hex, rec);
            *g = Arc::new(next);
        }
        let elapsed = start.elapsed();
        self.record_nodestore_operation("put", elapsed);
        self.record_nodestore_batch(1, elapsed);
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
        self.sync_primary_routes_for_snapshot(&mut primary_routes, snapshot);

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
        self.sync_primary_routes_for_snapshot(&mut primary_routes, snapshot);
        primary_routes.debug_routes()
    }

    /// Return the text form used by headscale-go's `/debug/routes`.
    pub fn debug_routes_string_for_snapshot(
        &self,
        snapshot: &HashMap<String, MachineRecord>,
    ) -> String {
        let mut primary_routes = self.primary_routes.write();
        self.sync_primary_routes_for_snapshot(&mut primary_routes, snapshot);
        primary_routes.debug_string()
    }

    /// Mark a live route candidate healthy or unhealthy. Unhealthy
    /// marks only stick for online, non-expired nodes that currently
    /// have approved advertised routes in the primary-route table.
    /// Returns true when primary-route ownership changed.
    pub fn set_route_candidate_health(&self, node_id: u64, healthy: bool) -> bool {
        let snapshot = self.snapshot();
        let mut primary_routes = self.primary_routes.write();
        self.sync_primary_routes_for_snapshot(&mut primary_routes, &snapshot);

        if !healthy && !primary_routes.has_routes(node_id) {
            return false;
        }

        let changed = primary_routes.set_node_health(node_id, healthy);
        if changed {
            self.wake_waiters();
        }
        changed
    }

    pub fn is_route_candidate_healthy(&self, node_id: u64) -> bool {
        self.primary_routes.read().is_node_healthy(node_id)
    }

    fn sync_primary_routes_for_snapshot(
        &self,
        primary_routes: &mut PrimaryRouteState,
        snapshot: &HashMap<String, MachineRecord>,
    ) {
        let now = Utc::now();
        let online_states = self.online_states.read().clone();
        let _ = primary_routes.sync_routes(
            snapshot
                .iter()
                .filter(|&(node_key, rec)| {
                    let node_id = stable_id_from_key(node_key);
                    !rec.is_expired_at(now) && online_states.get(&node_id).copied().unwrap_or(false)
                })
                .map(|(node_key, rec)| {
                    (
                        stable_id_from_key(node_key),
                        active_primary_routes(&rec.available_routes, &rec.approved_routes),
                    )
                }),
        );
    }

    /// Start tracking one active streaming map-response connection for
    /// `node_id`. The returned guard decrements the count when the
    /// response body is dropped.
    #[doc(hidden)]
    pub fn track_stream_connection(machines: Arc<Self>, node_id: u64) -> StreamConnectionGuard {
        Self::track_stream_connection_with_grace(machines, node_id, STREAM_OFFLINE_GRACE)
    }

    pub(crate) fn track_stream_connection_with_grace(
        machines: Arc<Self>,
        node_id: u64,
        offline_grace: Duration,
    ) -> StreamConnectionGuard {
        if let Some(node_key) = machines.ephemeral_node_key_by_id(node_id)
            && let Some(gc) = machines.ephemeral_gc()
        {
            gc.cancel(&node_key);
        }
        {
            let mut active = machines.active_connections.write();
            *active.entry(node_id).or_insert(0) += 1;
        }
        {
            let mut generations = machines.connection_generations.write();
            let generation = generations
                .get(&node_id)
                .copied()
                .unwrap_or(0)
                .wrapping_add(1);
            generations.insert(node_id, generation);
        }
        let online_changed = {
            let mut online = machines.online_states.write();
            let was_online = online.get(&node_id).copied().unwrap_or(false);
            online.insert(node_id, true);
            !was_online
        };
        if online_changed {
            machines.wake_waiters();
        }
        machines.primary_routes.write().clear_unhealthy(node_id);
        StreamConnectionGuard {
            machines,
            node_id,
            offline_grace,
        }
    }

    fn release_stream_connection(&self, node_id: u64) -> Option<u64> {
        let mut active = self.active_connections.write();
        let became_idle = if let Some(count) = active.get_mut(&node_id) {
            let was_active = *count > 0;
            *count = count.saturating_sub(1);
            was_active && *count == 0
        } else {
            false
        };
        drop(active);
        if !became_idle {
            return None;
        }
        let mut generations = self.connection_generations.write();
        let generation = generations
            .get(&node_id)
            .copied()
            .unwrap_or(0)
            .wrapping_add(1);
        generations.insert(node_id, generation);
        Some(generation)
    }

    fn schedule_stream_offline_if_idle(
        machines: Arc<Self>,
        node_id: u64,
        generation: u64,
        offline_grace: Duration,
    ) {
        if offline_grace.is_zero() {
            machines.mark_stream_offline_if_idle(node_id, generation);
            return;
        }

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                tokio::time::sleep(offline_grace).await;
                machines.mark_stream_offline_if_idle(node_id, generation);
            });
        } else {
            machines.mark_stream_offline_if_idle(node_id, generation);
        }
    }

    fn mark_stream_offline_if_idle(&self, node_id: u64, generation: u64) {
        let still_idle = self
            .active_connections
            .read()
            .get(&node_id)
            .copied()
            .unwrap_or(0)
            == 0
            && self
                .connection_generations
                .read()
                .get(&node_id)
                .copied()
                .unwrap_or(0)
                == generation;
        if !still_idle {
            return;
        }

        let online_changed = {
            let mut online = self.online_states.write();
            let was_online = online.get(&node_id).copied().unwrap_or(false);
            online.insert(node_id, false);
            was_online
        };
        if !online_changed {
            return;
        }

        self.primary_routes.write().clear_unhealthy(node_id);
        let now = Utc::now();
        self.update_with_operation("update", |map| {
            if let Some((_node_key, rec)) = map
                .iter_mut()
                .find(|(node_key, _rec)| stable_id_from_key(node_key) == node_id)
            {
                rec.last_seen = now;
            }
        });
    }

    /// Snapshot batcher connection state by stable node ID.
    pub fn active_connections(&self) -> BTreeMap<u64, usize> {
        self.active_connections.read().clone()
    }

    /// Snapshot volatile `Node.IsOnline` state by stable node ID.
    pub(crate) fn online_states(&self) -> BTreeMap<u64, bool> {
        self.online_states.read().clone()
    }

    pub(crate) fn record_mapresponse_endpoint_update(&self, status: &str) {
        let mut updates = self.metrics.mapresponse_endpoint_updates.write();
        *updates.entry(status.to_string()).or_insert(0) += 1;
    }

    pub(crate) fn record_mapresponse_ended(&self, reason: &str) {
        let mut ended = self.metrics.mapresponse_ended.write();
        *ended.entry(reason.to_string()).or_insert(0) += 1;
    }

    pub(crate) fn record_mapresponse_generated(&self, response_type: &str) {
        let mut generated = self.metrics.mapresponse_generated.write();
        *generated.entry(response_type.to_string()).or_insert(0) += 1;
    }

    pub(crate) fn record_mapresponse_sent(&self, status: &str, response_type: &str) {
        let mut sent = self.metrics.mapresponse_sent.write();
        *sent
            .entry((status.to_string(), response_type.to_string()))
            .or_insert(0) += 1;
    }

    #[allow(clippy::cast_precision_loss)]
    pub(crate) fn record_mapresponse_sent_for_node(
        &self,
        status: &str,
        response_type: &str,
        node_id: u64,
    ) {
        self.record_mapresponse_sent(status, response_type);
        if debug_high_cardinality_metrics_enabled() {
            let mut last_sent = self.metrics.mapresponse_last_sent.write();
            last_sent.insert(
                (response_type.to_string(), node_id.to_string()),
                chrono::Utc::now().timestamp() as f64,
            );
        }
    }

    pub(crate) fn record_http_request(
        &self,
        code: u16,
        method: &str,
        path: &str,
        duration: Duration,
    ) {
        {
            let mut requests = self.metrics.http_requests.write();
            *requests
                .entry((code.to_string(), method.to_string(), path.to_string()))
                .or_insert(0) += 1;
        }

        let seconds = duration.as_secs_f64();
        let mut durations = self.metrics.http_duration.write();
        let sample = durations.entry(path.to_string()).or_default();
        sample.observe(PROMETHEUS_DEFAULT_BUCKETS, seconds);
    }

    fn record_nodestore_operation(&self, operation: &str, duration: Duration) {
        {
            let mut operations = self.metrics.nodestore_operations.write();
            *operations.entry(operation.to_string()).or_insert(0) += 1;
        }

        let seconds = duration.as_secs_f64();
        let mut durations = self.metrics.nodestore_operation_duration.write();
        durations
            .entry(operation.to_string())
            .or_default()
            .observe(PROMETHEUS_DEFAULT_BUCKETS, seconds);
    }

    #[allow(clippy::cast_precision_loss)]
    fn record_nodestore_batch(&self, size: usize, duration: Duration) {
        let seconds = duration.as_secs_f64();
        self.metrics
            .nodestore_batch_size
            .write()
            .observe(NODESTORE_BATCH_SIZE_BUCKETS, size as f64);
        self.metrics
            .nodestore_batch_duration
            .write()
            .observe(PROMETHEUS_DEFAULT_BUCKETS, seconds);
        self.metrics
            .nodestore_snapshot_build_duration
            .write()
            .observe(PROMETHEUS_DEFAULT_BUCKETS, seconds);
    }

    pub fn mapresponse_endpoint_update_metrics(&self) -> BTreeMap<String, u64> {
        self.metrics.mapresponse_endpoint_updates.read().clone()
    }

    pub fn mapresponse_ended_metrics(&self) -> BTreeMap<String, u64> {
        self.metrics.mapresponse_ended.read().clone()
    }

    pub fn mapresponse_generated_metrics(&self) -> BTreeMap<String, u64> {
        self.metrics.mapresponse_generated.read().clone()
    }

    pub fn mapresponse_sent_metrics(&self) -> BTreeMap<(String, String), u64> {
        self.metrics.mapresponse_sent.read().clone()
    }

    pub(crate) fn mapresponse_last_sent_metrics(&self) -> BTreeMap<(String, String), f64> {
        self.metrics.mapresponse_last_sent.read().clone()
    }

    pub(crate) fn http_request_metrics(&self) -> BTreeMap<(String, String, String), u64> {
        self.metrics.http_requests.read().clone()
    }

    pub(crate) fn http_duration_metrics(&self) -> BTreeMap<String, HistogramMetric> {
        self.metrics.http_duration.read().clone()
    }

    pub(crate) fn nodestore_operation_metrics(&self) -> BTreeMap<String, u64> {
        self.metrics.nodestore_operations.read().clone()
    }

    pub(crate) fn nodestore_operation_duration_metrics(&self) -> BTreeMap<String, HistogramMetric> {
        self.metrics.nodestore_operation_duration.read().clone()
    }

    pub(crate) fn nodestore_batch_size_metrics(&self) -> HistogramMetric {
        self.metrics.nodestore_batch_size.read().clone()
    }

    pub(crate) fn nodestore_batch_duration_metrics(&self) -> HistogramMetric {
        self.metrics.nodestore_batch_duration.read().clone()
    }

    pub(crate) fn nodestore_snapshot_build_duration_metrics(&self) -> HistogramMetric {
        self.metrics
            .nodestore_snapshot_build_duration
            .read()
            .clone()
    }

    pub(crate) fn nodestore_peers_calculation_duration_metrics(&self) -> HistogramMetric {
        self.metrics
            .nodestore_peers_calculation_duration
            .read()
            .clone()
    }

    /// Look up a single machine by its hex-encoded node key.
    ///
    /// Still returns an owned `MachineRecord` — call sites read the
    /// record outside of any borrow against the registry, so the clone
    /// is the cleanest shape. Use `snapshot()` if you need cross-record
    /// iteration without per-record allocation.
    pub fn get(&self, node_key_hex: &str) -> Option<MachineRecord> {
        let start = Instant::now();
        let result = self.inner.read().get(node_key_hex).cloned();
        self.record_nodestore_operation("get_by_key", start.elapsed());
        result
    }

    /// Look up a machine by the TS2021 machine key and user label.
    ///
    /// Headscale-go's registration state keeps a secondary
    /// `(MachineKey, UserID)` index so a client that rotates its
    /// NodeKey but proves the same MachineKey can update the existing
    /// node instead of creating a duplicate. The in-memory registry is
    /// small enough that a snapshot scan is sufficient until the
    /// persisted node store becomes the default.
    pub fn get_by_machine_key_for_user(
        &self,
        machine_key_hex: &str,
        user: &str,
    ) -> Option<(String, MachineRecord)> {
        if machine_key_hex.is_empty() || user.is_empty() {
            return None;
        }

        let start = Instant::now();
        let result = self
            .inner
            .read()
            .iter()
            .find(|(_, rec)| rec.machine_key_hex == machine_key_hex && rec.user == user)
            .map(|(node_key, rec)| (node_key.clone(), rec.clone()));
        self.record_nodestore_operation("get_by_machine_key", start.elapsed());
        result
    }

    /// Replace a record's node-key index while preserving the record
    /// body. This is the wire-registry equivalent of headscale-go's
    /// `UpdateNode` path during node-key rotation.
    pub fn replace_node_key(
        &self,
        old_node_key_hex: &str,
        new_node_key_hex: String,
        rec: MachineRecord,
    ) {
        let key_changed = old_node_key_hex != new_node_key_hex;
        self.update_with_operation("replace_key", |map| {
            if key_changed {
                map.remove(old_node_key_hex);
            }
            map.insert(new_node_key_hex, rec);
        });
        if key_changed {
            let old_id = stable_id_from_key(old_node_key_hex);
            self.active_connections.write().remove(&old_id);
            self.online_states.write().remove(&old_id);
            self.connection_generations.write().remove(&old_id);
            if let Some(gc) = self.ephemeral_gc() {
                gc.cancel(old_node_key_hex);
            }
        }
    }

    /// Complete a web/CLI registration for `user`.
    ///
    /// If the pending record proves the same MachineKey as an existing
    /// node for that user, update that node in-place and move it to the
    /// pending NodeKey. This mirrors headscale-go reauth: web auth with
    /// empty `Hostinfo.RequestTags` clears a tagged node back to a
    /// user-owned node instead of creating a duplicate.
    pub fn complete_web_registration(
        &self,
        mut pending: MachineRecord,
        user: &str,
        register_method: i32,
    ) -> MachineRecord {
        pending.user = user.to_string();
        pending.register_method = register_method;

        if let Some((old_node_key, existing)) =
            self.get_by_machine_key_for_user(&pending.machine_key_hex, user)
        {
            pending.ipv4 = existing.ipv4;
            pending.ipv6 = existing.ipv6;
            pending.created_at = existing.created_at;
            pending.ephemeral = existing.ephemeral;
            pending.disco_key = existing.disco_key;
            pending.endpoints = existing.endpoints;
            pending.home_derp = existing.home_derp;
            if pending.hostname.is_empty() {
                pending.hostname = existing.hostname;
            }
            if pending.os.is_empty() {
                pending.os = existing.os;
            }
            if pending.os_version.is_empty() {
                pending.os_version = existing.os_version;
            }

            let mut approved_routes = existing
                .approved_routes
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>();
            approved_routes.extend(pending.approved_routes);
            pending.approved_routes = approved_routes.into_iter().collect();

            self.replace_node_key(&old_node_key, pending.node_key_hex.clone(), pending.clone());
        } else {
            self.upsert(pending.node_key_hex.clone(), pending.clone());
        }

        pending
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
        self.update_with_operation("update", f)
    }

    fn update_with_operation<R, F>(&self, operation: &str, f: F) -> R
    where
        F: FnOnce(&mut HashMap<String, MachineRecord>) -> R,
    {
        let start = Instant::now();
        let r = {
            let mut g = self.inner.write();
            let mut next = (**g).clone();
            let r = f(&mut next);
            *g = Arc::new(next);
            r
        };
        let elapsed = start.elapsed();
        self.record_nodestore_operation(operation, elapsed);
        self.record_nodestore_batch(1, elapsed);
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

    /// Logout a machine: stamps `expiry = now()` so the next `/map`
    /// round-trip returns a logout response while preserving the
    /// machine key that the Noise session is bound to.
    ///
    /// Mirrors `db.NodeLogout`. The record stays in the registry —
    /// upstream behaviour is "logged-out node still exists, but must
    /// re-authenticate." `delete` is the destructive counterpart.
    pub fn logout(&self, node_key_hex: &str) -> bool {
        let now = Utc::now();
        self.update_with(|map| match map.get_mut(node_key_hex) {
            Some(rec) => {
                rec.expiry = Some(now);
                true
            }
            None => false,
        })
    }

    /// Remove a machine from the registry entirely. Mirrors
    /// `db.DeleteNode`. Returns `true` on success.
    pub fn delete(&self, node_key_hex: &str) -> bool {
        let removed =
            self.update_with_operation("delete", |map| map.remove(node_key_hex).is_some());
        if removed {
            let node_id = stable_id_from_key(node_key_hex);
            self.active_connections.write().remove(&node_id);
            self.online_states.write().remove(&node_id);
            self.connection_generations.write().remove(&node_id);
            if let Some(gc) = self.ephemeral_gc() {
                gc.cancel(node_key_hex);
            }
        }
        removed
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

    /// Replace a machine's advertised subnet routes. Empty list clears
    /// advertised routes while preserving operator approvals.
    pub fn set_available_routes(&self, node_key_hex: &str, routes: Vec<String>) -> bool {
        self.update_with(|map| match map.get_mut(node_key_hex) {
            Some(rec) => {
                rec.available_routes = routes;
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
        let active_connections = self.active_connections.read().clone();
        let online_states = self.online_states.read().clone();
        let removed = self.update_with(|map| {
            let to_drop: Vec<String> = map
                .iter()
                .filter(|(node_key, rec)| {
                    let node_id = stable_id_from_key(node_key);
                    rec.ephemeral
                        && rec.last_seen < deadline
                        && active_connections.get(&node_id).copied().unwrap_or(0) == 0
                        && !online_states.get(&node_id).copied().unwrap_or(false)
                })
                .map(|(k, _)| k.clone())
                .collect();
            for k in &to_drop {
                map.remove(k);
            }
            to_drop
        });
        if !removed.is_empty() {
            let mut active = self.active_connections.write();
            let mut online = self.online_states.write();
            let mut generations = self.connection_generations.write();
            for node_key_hex in &removed {
                let node_id = stable_id_from_key(node_key_hex);
                active.remove(&node_id);
                online.remove(&node_id);
                generations.remove(&node_id);
            }
        }
        removed
    }
}

#[doc(hidden)]
pub struct StreamConnectionGuard {
    machines: Arc<MachineRegistry>,
    node_id: u64,
    offline_grace: Duration,
}

#[derive(Clone)]
pub struct EphemeralGcHandle {
    inner: Arc<EphemeralNodeGc>,
}

impl EphemeralGcHandle {
    /// Schedule every currently known ephemeral node for deletion.
    /// Production startup calls this after hydrating persisted nodes;
    /// reconnecting clients cancel their own timers when their stream
    /// opens.
    pub fn schedule_existing(&self) -> usize {
        self.inner.schedule_existing()
    }

    /// Cancel all outstanding timers and prevent future scheduling.
    pub fn abort(&self) {
        self.inner.abort_all();
    }

    pub fn inactivity_timeout(&self) -> Duration {
        self.inner.inactivity_timeout
    }
}

struct EphemeralNodeGc {
    machines: Weak<MachineRegistry>,
    registration_store: Option<Weak<dyn MachineRegistrationStore>>,
    inactivity_timeout: Duration,
    timers: Mutex<BTreeMap<String, tokio::task::JoinHandle<()>>>,
    closed: AtomicBool,
}

impl EphemeralNodeGc {
    fn schedule_existing(self: &Arc<Self>) -> usize {
        if self.closed.load(Ordering::SeqCst) {
            return 0;
        }
        let Some(machines) = self.machines.upgrade() else {
            return 0;
        };
        let active = machines.active_connections.read().clone();
        let node_keys: Vec<String> = machines
            .snapshot()
            .iter()
            .filter(|(node_key, rec)| {
                rec.ephemeral
                    && active
                        .get(&stable_id_from_key(node_key))
                        .copied()
                        .unwrap_or(0)
                        == 0
            })
            .map(|(node_key, _)| node_key.clone())
            .collect();
        let count = node_keys.len();
        for node_key in node_keys {
            self.schedule(node_key);
        }
        count
    }

    fn schedule(self: &Arc<Self>, node_key_hex: String) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let Some(machines) = self.machines.upgrade() else {
            return;
        };
        let Some(rec) = machines.get(&node_key_hex) else {
            return;
        };
        if !rec.ephemeral {
            self.cancel(&node_key_hex);
            return;
        }
        let node_id = stable_id_from_key(&node_key_hex);
        if machines
            .active_connections
            .read()
            .get(&node_id)
            .copied()
            .unwrap_or(0)
            > 0
        {
            self.cancel(&node_key_hex);
            return;
        }

        let timeout = self.inactivity_timeout;
        let gc = Arc::downgrade(self);
        let task_node_key = node_key_hex.clone();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            if let Some(gc) = gc.upgrade() {
                gc.fire(task_node_key).await;
            }
        });
        if let Some(previous) = self.timers.lock().insert(node_key_hex, handle) {
            previous.abort();
        }
    }

    fn cancel(&self, node_key_hex: &str) {
        if let Some(handle) = self.timers.lock().remove(node_key_hex) {
            handle.abort();
        }
    }

    fn abort_all(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let timers = std::mem::take(&mut *self.timers.lock());
        for (_node_key, handle) in timers {
            handle.abort();
        }
    }

    async fn fire(self: Arc<Self>, node_key_hex: String) {
        self.timers.lock().remove(&node_key_hex);
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let Some(machines) = self.machines.upgrade() else {
            return;
        };
        let node_id = stable_id_from_key(&node_key_hex);
        if machines
            .active_connections
            .read()
            .get(&node_id)
            .copied()
            .unwrap_or(0)
            > 0
        {
            return;
        }
        match machines.get(&node_key_hex) {
            Some(rec) if rec.ephemeral => {}
            _ => return,
        }

        if let Some(store) = self
            .registration_store
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            && let Err(error) = store.delete_machine_registration(&node_key_hex).await
        {
            tracing::warn!(
                target = "tailscale_wire::gc",
                node_key = %node_key_hex,
                %error,
                "ephemeral GC failed to delete persisted node"
            );
            return;
        }

        if machines.delete(&node_key_hex) {
            tracing::info!(
                target = "tailscale_wire::gc",
                node_key = %node_key_hex,
                "ephemeral GC removed node"
            );
        }
    }
}

impl Drop for StreamConnectionGuard {
    fn drop(&mut self) {
        if let Some(generation) = self.machines.release_stream_connection(self.node_id) {
            if let Some(node_key) = self.machines.ephemeral_node_key_by_id(self.node_id)
                && let Some(gc) = self.machines.ephemeral_gc()
            {
                gc.schedule(node_key);
            }
            MachineRegistry::schedule_stream_offline_if_idle(
                self.machines.clone(),
                self.node_id,
                generation,
                self.offline_grace,
            );
        }
        self.machines.record_mapresponse_ended("done");
    }
}

/// Legacy/background sweep that calls [`MachineRegistry::gc_ephemeral`]
/// every `interval`. Production startup uses
/// [`MachineRegistry::configure_ephemeral_gc`] for upstream-shaped
/// per-node timers; this helper remains for embedders that explicitly
/// want a periodic sweep. The returned `JoinHandle` aborts on drop.
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

/// Spawn headscale-go's scheduled node-expiry notifier.
///
/// The task mirrors `hscontrol.Headscale.scheduledTasks`: every tick it
/// scans the live node store for expiries that crossed after the
/// previous pass, wakes map streams, and leaves the node rows intact.
pub fn spawn_node_expiry_waker(
    machines: Arc<MachineRegistry>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        let mut last_check = unix_epoch_utc();
        tick.tick().await;
        loop {
            tick.tick().await;
            let (next_check, expired) = machines.expire_expired_nodes_since(last_check);
            last_check = next_check;
            if !expired.is_empty() {
                tracing::trace!(
                    target = "tailscale_wire::expiry",
                    count = expired.len(),
                    nodes = ?expired,
                    "expiring nodes"
                );
            }
        }
    })
}

fn unix_epoch_utc() -> DateTime<Utc> {
    DateTime::from_timestamp(0, 0).expect("Unix epoch timestamp is valid")
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
    use crate::oidc::OidcRegistrationHandler;
    use std::net::Ipv4Addr;
    use test_support::{MockIpAllocator, MockRedeemer};
    use tower::ServiceExt;

    fn mk_record(host: u32) -> MachineRecord {
        let now = Utc::now();
        MachineRecord {
            node_key_hex: format!("nodekey-{host:08x}"),
            machine_key_hex: format!("mkey-{host:08x}"),
            user: "alice".to_string(),
            hostname: format!("host-{host}"),
            os: "linux".to_string(),
            os_version: "test".to_string(),
            host_info: wire::HostInfo {
                hostname: format!("host-{host}"),
                os: "linux".to_string(),
                os_version: "test".to_string(),
                ..wire::HostInfo::default()
            },
            ipv4: Some(Ipv4Addr::new(100, 64, (host >> 8) as u8, host as u8)),
            ipv6: None,
            disco_key: Some(format!("disco-{host:08x}")),
            endpoints: vec![format!("198.51.100.{}:41641", host & 0xff)],
            home_derp: 0,
            expiry: None,
            last_seen: now,
            ephemeral: false,
            created_at: now,
            forced_tags: Vec::new(),
            available_routes: Vec::new(),
            approved_routes: Vec::new(),
            ssh_host_keys: Vec::new(),
            register_method: 1,
        }
    }

    fn route_record(node_key: &str, host: u32, route: &str) -> MachineRecord {
        let mut rec = mk_record(host);
        rec.node_key_hex = node_key.to_string();
        rec.available_routes = vec![route.to_string()];
        rec.approved_routes = vec![route.to_string()];
        rec
    }

    fn stable_sorted_keys(keys: &[&str]) -> Vec<String> {
        let mut keys: Vec<String> = keys.iter().map(|key| (*key).to_string()).collect();
        keys.sort_by_key(|key| stable_id_from_key(key));
        keys
    }

    fn ping_id_from_url(url: &str) -> String {
        url.split("id=")
            .nth(1)
            .and_then(|id| id.split('&').next())
            .expect("ping URL contains id query")
            .to_string()
    }

    async fn complete_next_pending_ping_for_node(state: &WireState, node_id: u64) -> String {
        for _ in 0..20 {
            if let Some(request) = state.pings.pop_next_for_node(node_id) {
                let ping_id = ping_id_from_url(&request.url);
                if state.pings.complete(&ping_id).is_some() {
                    return ping_id;
                }
            }
            tokio::task::yield_now().await;
        }
        panic!("no pending ping request for node {node_id}");
    }

    fn test_state() -> WireState {
        let dir = tempfile::tempdir().unwrap();
        WireState {
            server_noise_key: Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap()),
            preauth: Arc::new(MockRedeemer::new()),
            ip_allocator: Arc::new(MockIpAllocator),
            machines: Arc::new(MachineRegistry::new()),
            registration_store: None,
            derp_map: DerpMapStore::shared(wire::DerpMap::default()),
            policy: Arc::new(crate::policy::PolicyStore::new()),
            knock: KnockConfig::disabled(),
            dns: Arc::new(crate::dns::DnsStore::new()),
            public_control_url: None,
            runtime_config: Arc::new(RuntimeConfigSnapshot::default()),
            registration_cache: Arc::new(RegistrationCache::new()),
            pings: Arc::new(PingTracker::new()),
        }
    }

    fn oidc_test_user() -> crate::oidc::OidcStoredUser {
        crate::oidc::OidcStoredUser {
            id: 7,
            name: "alice@example.com".into(),
            display_name: "Alice Smith".into(),
            email: "alice@example.com".into(),
            provider_identifier: "https://issuer.example/subject".into(),
            provider: crate::oidc::REGISTER_METHOD_OIDC.into(),
            profile_pic_url: String::new(),
        }
    }

    #[tokio::test]
    async fn public_ping_response_head_route_is_successful() {
        let state = test_state();
        let (ping_id, response) = state.register_ping(42);
        let app = router(state.clone());
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::HEAD)
                    .uri(format!("/machine/ping-response?id={ping_id}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        assert!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .is_none()
        );
        assert!(
            resp.headers()
                .get(axum::http::header::CONTENT_LENGTH)
                .is_none()
        );
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert!(body.is_empty());
        let latency = response.await.expect("ping response completed");
        assert!(latency <= std::time::Duration::from_secs(5));
        assert_eq!(state.pings.pending_len(), 0);
    }

    #[tokio::test]
    async fn public_ping_response_rejects_missing_and_unknown_ids() {
        let app = router(test_state());

        for (uri, status) in [
            (
                "/machine/ping-response",
                axum::http::StatusCode::BAD_REQUEST,
            ),
            (
                "/machine/ping-response?id=",
                axum::http::StatusCode::BAD_REQUEST,
            ),
            (
                "/machine/ping-response?id=unknown",
                axum::http::StatusCode::NOT_FOUND,
            ),
        ] {
            let resp = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method(axum::http::Method::HEAD)
                        .uri(uri)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(resp.status(), status, "{uri}");
            let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
            assert!(body.is_empty(), "{uri}");
        }
    }

    #[tokio::test]
    async fn public_ping_response_does_not_open_adjacent_machine_paths() {
        let app = router(test_state());

        for uri in [
            "/machine/ping",
            "/machine/ping-response/",
            "/machine/ping-response/extra",
            "/machine/ping-responses",
        ] {
            let resp = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method(axum::http::Method::HEAD)
                        .uri(uri)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND, "{uri}");
            let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
            assert!(body.is_empty(), "{uri}");
        }
    }

    #[tokio::test]
    async fn registration_cache_completion_notifies_waiting_followups() {
        let cache = Arc::new(RegistrationCache::with_tuning(
            Duration::from_secs(60),
            Duration::from_secs(120),
        ));
        let registration_id = "a".repeat(24);
        cache.insert(registration_id.clone(), mk_record(1));

        let waiter = {
            let cache = cache.clone();
            let registration_id = registration_id.clone();
            tokio::spawn(async move { cache.wait_for_registration(&registration_id).await })
        };
        tokio::task::yield_now().await;

        let mut registered = mk_record(2);
        registered.user = "alice".into();
        registered.register_method = 2;
        assert!(cache.complete(&registration_id, registered));

        let outcome = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter should be notified")
            .expect("waiter task should not panic");
        match outcome {
            RegistrationWaitOutcome::Registered(record) => {
                assert_eq!(record.user, "alice");
                assert_eq!(record.register_method, 2);
            }
            other => panic!("expected registered outcome, got {other:?}"),
        }
        assert!(cache.is_empty());
    }

    #[tokio::test]
    async fn public_router_does_not_mount_machine_control_paths() {
        let state = test_state();
        let app = router(state.clone());
        let node_key_hex = "aa".repeat(32);
        let body = serde_json::json!({
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Auth": { "AuthKey": "hskey-auth-public-route-regression" },
        });

        for (method, uri) in [
            (
                axum::http::Method::POST,
                format!("/machine/nodekey:{node_key_hex}/register"),
            ),
            (axum::http::Method::POST, "/machine/register".to_string()),
            (
                axum::http::Method::POST,
                format!("/machine/nodekey:{node_key_hex}/map"),
            ),
            (axum::http::Method::POST, "/machine/map".to_string()),
            (axum::http::Method::GET, "/machine/whoami".to_string()),
            (axum::http::Method::POST, "/machine/set-dns".to_string()),
            (
                axum::http::Method::PATCH,
                "/machine/set-device-attr".to_string(),
            ),
            (axum::http::Method::POST, "/machine".to_string()),
        ] {
            let resp = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method(method)
                        .uri(uri)
                        .header(axum::http::header::CONTENT_TYPE, "application/json")
                        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
            let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
            assert!(body.is_empty());
        }

        assert!(state.machines.is_empty());
    }

    #[tokio::test]
    async fn inner_flat_machine_routes_require_noise_machine_key() {
        let state = test_state();
        let app = super::noise::inner_router(state.clone());

        for uri in ["/machine/register", "/machine/map"] {
            let resp = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method(axum::http::Method::POST)
                        .uri(uri)
                        .body(axum::body::Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
            let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["error"], "missing Noise machine key");
        }

        assert!(state.machines.is_empty());
    }

    #[tokio::test]
    async fn wire_oidc_registration_handler_completes_pending_registration() {
        let state = test_state();
        let registration_id = "o".repeat(24);
        let mut pending = mk_record(10);
        pending.user.clear();
        pending.expiry = None;
        state
            .registration_cache
            .insert(registration_id.clone(), pending.clone());

        let waiter = {
            let cache = state.registration_cache.clone();
            let registration_id = registration_id.clone();
            tokio::spawn(async move { cache.wait_for_registration(&registration_id).await })
        };
        tokio::task::yield_now().await;

        let expiry = Utc::now() + chrono::Duration::hours(2);
        let handler = WireOidcRegistrationHandler {
            state: state.clone(),
        };
        let user = oidc_test_user();
        let result = handler
            .complete_oidc_registration(&registration_id, &user, Some(expiry))
            .await
            .unwrap();

        assert!(result.new_node);
        let registered = state.machines.get(&pending.node_key_hex).unwrap();
        assert_eq!(registered.user, "alice@example.com");
        assert_eq!(registered.register_method, REGISTER_METHOD_OIDC);
        assert_eq!(registered.expiry, Some(expiry));
        assert!(state.registration_cache.get(&registration_id).is_none());

        let outcome = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("wire follow-up should be notified")
            .expect("waiter task should not panic");
        match outcome {
            RegistrationWaitOutcome::Registered(record) => {
                assert_eq!(record.user, "alice@example.com");
                assert_eq!(record.register_method, REGISTER_METHOD_OIDC);
                assert_eq!(record.expiry, Some(expiry));
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[tokio::test]
    async fn wire_oidc_registration_handler_prefers_email_for_owner_identity() {
        let state = test_state();
        let registration_id = "i".repeat(24);
        let mut pending = mk_record(13);
        pending.user.clear();
        state
            .registration_cache
            .insert(registration_id.clone(), pending.clone());

        let handler = WireOidcRegistrationHandler {
            state: state.clone(),
        };
        let user = crate::oidc::OidcStoredUser {
            id: 8,
            name: "preferred".into(),
            display_name: "Preferred User".into(),
            email: "preferred@example.com".into(),
            provider_identifier: "https://issuer.example/preferred".into(),
            provider: crate::oidc::REGISTER_METHOD_OIDC.into(),
            profile_pic_url: String::new(),
        };
        handler
            .complete_oidc_registration(&registration_id, &user, None)
            .await
            .unwrap();

        let registered = state.machines.get(&pending.node_key_hex).unwrap();
        assert_eq!(registered.user, "preferred@example.com");
    }

    #[tokio::test]
    async fn wire_oidc_registration_handler_preserves_pending_expiry_without_provider_expiry() {
        let state = test_state();
        let registration_id = "e".repeat(24);
        let mut pending = mk_record(11);
        pending.user.clear();
        let pending_expiry = Utc::now() + chrono::Duration::hours(3);
        pending.expiry = Some(pending_expiry);
        state
            .registration_cache
            .insert(registration_id.clone(), pending.clone());

        let handler = WireOidcRegistrationHandler {
            state: state.clone(),
        };
        let user = oidc_test_user();
        let result = handler
            .complete_oidc_registration(&registration_id, &user, None)
            .await
            .unwrap();

        assert!(result.new_node);
        let registered = state.machines.get(&pending.node_key_hex).unwrap();
        assert_eq!(registered.user, "alice@example.com");
        assert_eq!(registered.register_method, REGISTER_METHOD_OIDC);
        assert_eq!(registered.expiry, Some(pending_expiry));
        assert!(state.registration_cache.get(&registration_id).is_none());
    }

    #[tokio::test]
    async fn wire_oidc_registration_handler_clears_tagged_expiry() {
        let state = test_state();
        let registration_id = "t".repeat(24);
        let mut pending = mk_record(12);
        pending.user.clear();
        pending.forced_tags = vec!["tag:server".into()];
        pending.expiry = Some(Utc::now() + chrono::Duration::hours(3));
        state
            .registration_cache
            .insert(registration_id.clone(), pending.clone());

        let token_expiry = Utc::now() + chrono::Duration::hours(1);
        let handler = WireOidcRegistrationHandler {
            state: state.clone(),
        };
        let user = oidc_test_user();
        let result = handler
            .complete_oidc_registration(&registration_id, &user, Some(token_expiry))
            .await
            .unwrap();

        assert!(result.new_node);
        let registered = state.machines.get(&pending.node_key_hex).unwrap();
        assert_eq!(registered.forced_tags, vec!["tag:server"]);
        assert_eq!(registered.expiry, None);
    }

    #[tokio::test]
    async fn wire_oidc_registration_handler_reports_expired_sessions() {
        let handler = WireOidcRegistrationHandler {
            state: test_state(),
        };
        let user = oidc_test_user();
        let registration_id = "missing".repeat(4);
        let err = handler
            .complete_oidc_registration(&registration_id, &user, Some(Utc::now()))
            .await
            .unwrap_err();

        assert_eq!(err, crate::oidc::OidcRegistrationError::SessionExpired);
    }

    #[tokio::test]
    async fn registration_cache_expiry_notifies_waiting_followups() {
        let cache =
            RegistrationCache::with_tuning(Duration::from_millis(10), Duration::from_millis(20));
        let registration_id = "b".repeat(24);
        cache.insert(registration_id.clone(), mk_record(1));

        let outcome = tokio::time::timeout(
            Duration::from_secs(1),
            cache.wait_for_registration(&registration_id),
        )
        .await
        .expect("waiter should finish at cache expiry");
        assert!(matches!(outcome, RegistrationWaitOutcome::Expired));
        assert!(cache.is_empty());
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

    #[test]
    fn expire_expired_nodes_since_wakes_once_and_preserves_records() {
        let reg = MachineRegistry::new();
        let base = Utc::now();
        let expiry = base + chrono::Duration::seconds(10);
        let mut rec = mk_record(1);
        rec.expiry = Some(expiry);
        reg.upsert("nk-a".to_string(), rec);
        let mut gen_rx = reg.subscribe_gen();

        assert!(
            reg.wake_expired_nodes_between(base, expiry - chrono::Duration::milliseconds(1))
                .is_empty()
        );
        assert!(!gen_rx.has_changed().unwrap());

        assert_eq!(
            reg.wake_expired_nodes_between(base, expiry),
            vec!["nk-a".to_string()]
        );
        assert!(gen_rx.has_changed().unwrap());
        gen_rx.borrow_and_update();
        let stored = reg.get("nk-a").expect("expired node remains registered");
        assert_eq!(stored.expiry, Some(expiry));
        assert!(stored.is_expired_at(expiry));

        assert!(
            reg.wake_expired_nodes_between(expiry, expiry + chrono::Duration::seconds(1))
                .is_empty(),
            "strict last_check matching avoids duplicate expiry notifications"
        );
        assert!(!gen_rx.has_changed().unwrap());
    }

    #[tokio::test]
    async fn node_expiry_waker_emits_future_expiry_generation() {
        let reg = Arc::new(MachineRegistry::new());
        let mut rec = mk_record(2);
        rec.expiry = Some(Utc::now() + chrono::Duration::milliseconds(40));
        reg.upsert("nk-a".to_string(), rec);
        let mut gen_rx = reg.subscribe_gen();

        let handle = spawn_node_expiry_waker(reg.clone(), Duration::from_millis(5));
        let changed = tokio::time::timeout(Duration::from_secs(2), gen_rx.changed()).await;
        handle.abort();

        changed
            .expect("expiry waker should notify before timeout")
            .expect("generation channel should remain open");
        let stored = reg.get("nk-a").expect("expired node remains registered");
        assert!(stored.is_expired_at(Utc::now()));
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

    /// `logout` preserves the Noise machine key and stamps expiry.
    #[test]
    fn logout_preserves_machine_key_and_stamps_expiry() {
        let reg = MachineRegistry::new();
        reg.upsert("nk-a".to_string(), mk_record(3));
        let original = reg.get("nk-a").unwrap();
        let machine_key_hex = original.machine_key_hex;
        let disco_key = original.disco_key;
        let endpoints = original.endpoints;
        let before = Utc::now();
        assert!(reg.logout("nk-a"));
        let rec = reg.get("nk-a").unwrap();
        assert_eq!(rec.machine_key_hex, machine_key_hex);
        assert_eq!(rec.disco_key, disco_key);
        assert_eq!(rec.endpoints, endpoints);
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

    #[derive(Default)]
    struct RecordingDeletionStore {
        deleted: Arc<parking_lot::Mutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl MachineRegistrationStore for RecordingDeletionStore {
        async fn create_or_update_auth_key_registration(
            &self,
            record: MachineRecord,
            _policy: &crate::policy::PolicyStore,
            _auth_key_id: Option<i64>,
        ) -> Result<PersistedMachineRegistration, String> {
            Ok(PersistedMachineRegistration {
                record,
                replaced_node_key_hex: None,
            })
        }

        async fn delete_machine_registration(&self, node_key_hex: &str) -> Result<(), String> {
            self.deleted.lock().push(node_key_hex.to_string());
            Ok(())
        }
    }

    #[tokio::test]
    async fn ephemeral_gc_cancels_while_stream_connected_and_deletes_after_disconnect() {
        let reg = Arc::new(MachineRegistry::new());
        let mut rec = mk_record(4);
        rec.ephemeral = true;
        reg.upsert("nk-a".to_string(), rec);

        let gc = reg.configure_ephemeral_gc(None, Duration::from_millis(25));
        assert_eq!(gc.schedule_existing(), 1);
        let node_id = stable_id_from_key("nk-a");
        let guard = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_id,
            Duration::ZERO,
        );

        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(
            reg.get("nk-a").is_some(),
            "active stream must cancel the startup deletion timer"
        );

        drop(guard);
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(
            reg.get("nk-a").is_none(),
            "disconnect should schedule upstream-style ephemeral deletion"
        );
        gc.abort();
    }

    #[tokio::test]
    async fn ephemeral_gc_deletes_persistent_row_before_live_record() {
        let reg = Arc::new(MachineRegistry::new());
        let mut rec = mk_record(5);
        rec.ephemeral = true;
        reg.upsert("nk-a".to_string(), rec);
        let deleted = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let store: Arc<dyn MachineRegistrationStore> = Arc::new(RecordingDeletionStore {
            deleted: deleted.clone(),
        });

        let gc =
            reg.configure_ephemeral_gc(Some(Arc::downgrade(&store)), Duration::from_millis(25));
        assert_eq!(gc.schedule_existing(), 1);

        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(&*deleted.lock(), &vec!["nk-a".to_string()]);
        assert!(reg.get("nk-a").is_none());
        gc.abort();
    }

    #[test]
    fn batcher_connection_state_keeps_disconnect_until_node_delete() {
        let reg = Arc::new(MachineRegistry::new());
        reg.upsert("nk-a".to_string(), mk_record(4));
        let node_id = stable_id_from_key("nk-a");

        let guard = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_id,
            Duration::ZERO,
        );
        assert_eq!(reg.active_connections().get(&node_id), Some(&1));
        assert_eq!(reg.online_states().get(&node_id), Some(&true));

        drop(guard);
        assert_eq!(reg.active_connections().get(&node_id), Some(&0));
        assert_eq!(reg.online_states().get(&node_id), Some(&false));

        assert!(reg.delete("nk-a"));
        assert!(!reg.active_connections().contains_key(&node_id));
        assert!(!reg.online_states().contains_key(&node_id));
    }

    #[tokio::test(start_paused = true)]
    async fn stream_connection_offline_grace_suppresses_rapid_reconnect() {
        let reg = Arc::new(MachineRegistry::new());
        reg.upsert("nk-a".to_string(), mk_record(4));
        let node_id = stable_id_from_key("nk-a");
        let before = reg.get("nk-a").unwrap().last_seen;

        let first = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_id,
            Duration::from_secs(10),
        );
        assert_eq!(reg.online_states().get(&node_id), Some(&true));
        drop(first);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(9)).await;
        assert_eq!(reg.online_states().get(&node_id), Some(&true));

        let second = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_id,
            Duration::from_secs(10),
        );
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(
            reg.online_states().get(&node_id),
            Some(&true),
            "stale offline task must not win after reconnect"
        );

        drop(second);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        assert_eq!(reg.online_states().get(&node_id), Some(&false));
        assert!(reg.get("nk-a").unwrap().last_seen > before);
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

    #[test]
    fn set_available_routes_replaces_routes_without_clearing_approval() {
        let reg = MachineRegistry::new();
        let mut rec = mk_record(8);
        rec.available_routes = vec!["10.0.0.0/24".into()];
        rec.approved_routes = vec!["10.0.0.0/24".into()];
        reg.upsert("nk-a".to_string(), rec);

        assert!(reg.set_available_routes("nk-a", vec!["10.1.0.0/24".into()]));
        let updated = reg.get("nk-a").unwrap();
        assert_eq!(updated.available_routes, vec!["10.1.0.0/24"]);
        assert_eq!(updated.approved_routes, vec!["10.0.0.0/24"]);
        assert!(!reg.set_available_routes("nk-zzz", Vec::new()));
    }

    #[test]
    fn set_approved_routes_empty_clears_active_primary_but_keeps_advertisement() {
        let reg = Arc::new(MachineRegistry::new());
        let node_key = "route-clear-approval";
        let route = "10.0.0.0/24";
        reg.upsert(node_key.to_string(), route_record(node_key, 8, route));
        let _guard = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            stable_id_from_key(node_key),
            Duration::ZERO,
        );

        let before = reg.primary_routes_for_snapshot(&reg.snapshot());
        assert_eq!(
            before.get(node_key).cloned().unwrap_or_default(),
            vec![route]
        );

        assert!(reg.set_approved_routes(node_key, Vec::new()));
        let updated = reg.get(node_key).unwrap();
        assert_eq!(updated.available_routes, vec![route]);
        assert!(updated.approved_routes.is_empty());

        let after = reg.primary_routes_for_snapshot(&reg.snapshot());
        assert!(!after.contains_key(node_key));
        assert!(
            reg.debug_routes_for_snapshot(&reg.snapshot())
                .primary_routes
                .is_empty()
        );
    }

    #[test]
    fn debug_routes_excludes_expired_nodes() {
        let reg = Arc::new(MachineRegistry::new());
        let mut rec = mk_record(8);
        rec.available_routes = vec!["10.0.0.0/24".into()];
        rec.approved_routes = vec!["10.0.0.0/24".into()];
        rec.expiry = Some(Utc::now() - chrono::Duration::seconds(1));
        reg.upsert("nk-a".to_string(), rec);
        let _guard = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            stable_id_from_key("nk-a"),
            Duration::ZERO,
        );

        let primary = reg.primary_routes_for_snapshot(&reg.snapshot());
        assert!(primary.is_empty());
        let routes = reg.debug_routes_for_snapshot(&reg.snapshot());
        assert!(routes.available_routes.is_empty());
        assert!(routes.primary_routes.is_empty());
    }

    #[test]
    fn registry_route_health_excludes_unhealthy_online_primary() {
        let reg = Arc::new(MachineRegistry::new());
        let keys = stable_sorted_keys(&["route-health-a", "route-health-b"]);
        let route = "10.0.0.0/24";
        reg.upsert(keys[0].clone(), route_record(&keys[0], 10, route));
        reg.upsert(keys[1].clone(), route_record(&keys[1], 11, route));
        let _guard_a = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            stable_id_from_key(&keys[0]),
            Duration::ZERO,
        );
        let _guard_b = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            stable_id_from_key(&keys[1]),
            Duration::ZERO,
        );

        let first = reg.primary_routes_for_snapshot(&reg.snapshot());
        assert_eq!(
            first.get(&keys[0]).cloned().unwrap_or_default(),
            vec![route]
        );

        assert!(reg.set_route_candidate_health(stable_id_from_key(&keys[0]), false));

        let failed_over = reg.primary_routes_for_snapshot(&reg.snapshot());
        assert_eq!(
            failed_over.get(&keys[1]).cloned().unwrap_or_default(),
            vec![route]
        );
        assert!(!failed_over.contains_key(&keys[0]));
        assert!(!reg.is_route_candidate_healthy(stable_id_from_key(&keys[0])));
    }

    #[test]
    fn route_health_probe_candidates_require_online_active_subnet_routes() {
        let state = test_state();
        let route = "10.0.0.0/24";
        let active = "route-health-active";
        let offline = "route-health-offline";
        let exit_only = "route-health-exit";
        let unapproved = "route-health-unapproved";

        state
            .machines
            .upsert(active.to_string(), route_record(active, 10, route));
        state
            .machines
            .upsert(offline.to_string(), route_record(offline, 11, route));

        let mut exit = route_record(exit_only, 12, "0.0.0.0/0");
        exit.available_routes = vec!["0.0.0.0/0".into(), "::/0".into()];
        exit.approved_routes = exit.available_routes.clone();
        state.machines.upsert(exit_only.to_string(), exit);

        let mut advertised = route_record(unapproved, 13, route);
        advertised.approved_routes.clear();
        state.machines.upsert(unapproved.to_string(), advertised);

        let _active_guard = MachineRegistry::track_stream_connection_with_grace(
            state.machines.clone(),
            stable_id_from_key(active),
            Duration::ZERO,
        );
        let _exit_guard = MachineRegistry::track_stream_connection_with_grace(
            state.machines.clone(),
            stable_id_from_key(exit_only),
            Duration::ZERO,
        );
        let _unapproved_guard = MachineRegistry::track_stream_connection_with_grace(
            state.machines.clone(),
            stable_id_from_key(unapproved),
            Duration::ZERO,
        );

        assert_eq!(
            route_health_probe_candidates(&state.machines),
            vec![stable_id_from_key(active)]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn route_health_probe_timeout_fails_over_and_recovery_stays_sticky() {
        let state = test_state();
        let keys = stable_sorted_keys(&["route-health-probe-a", "route-health-probe-b"]);
        let route = "10.0.0.0/24";
        state
            .machines
            .upsert(keys[0].clone(), route_record(&keys[0], 10, route));
        state
            .machines
            .upsert(keys[1].clone(), route_record(&keys[1], 11, route));
        let _guard_a = MachineRegistry::track_stream_connection_with_grace(
            state.machines.clone(),
            stable_id_from_key(&keys[0]),
            Duration::ZERO,
        );
        let _guard_b = MachineRegistry::track_stream_connection_with_grace(
            state.machines.clone(),
            stable_id_from_key(&keys[1]),
            Duration::ZERO,
        );
        let node_a = stable_id_from_key(&keys[0]);
        let node_b = stable_id_from_key(&keys[1]);

        let first = state
            .machines
            .primary_routes_for_snapshot(&state.machines.snapshot());
        assert_eq!(
            first.get(&keys[0]).cloned().unwrap_or_default(),
            vec![route]
        );

        let probe = tokio::spawn({
            let state = state.clone();
            async move { run_route_health_probe_once(&state, Duration::from_secs(5)).await }
        });
        complete_next_pending_ping_for_node(&state, node_b).await;
        tokio::time::advance(Duration::from_secs(5)).await;
        let results = probe.await.unwrap();

        assert!(
            results
                .iter()
                .any(|result| result.node_id == node_a && !result.healthy)
        );
        assert!(
            results
                .iter()
                .any(|result| result.node_id == node_b && result.healthy)
        );
        assert!(!state.machines.is_route_candidate_healthy(node_a));
        assert!(state.machines.is_route_candidate_healthy(node_b));
        let failed_over = state
            .machines
            .primary_routes_for_snapshot(&state.machines.snapshot());
        assert_eq!(
            failed_over.get(&keys[1]).cloned().unwrap_or_default(),
            vec![route]
        );

        let recovery_probe = tokio::spawn({
            let state = state.clone();
            async move { run_route_health_probe_once(&state, Duration::from_secs(5)).await }
        });
        complete_next_pending_ping_for_node(&state, node_a).await;
        complete_next_pending_ping_for_node(&state, node_b).await;
        let recovery_results = recovery_probe.await.unwrap();

        assert!(
            recovery_results
                .iter()
                .any(|result| result.node_id == node_a && result.healthy)
        );
        assert!(state.machines.is_route_candidate_healthy(node_a));
        let sticky = state
            .machines
            .primary_routes_for_snapshot(&state.machines.snapshot());
        assert_eq!(
            sticky.get(&keys[1]).cloned().unwrap_or_default(),
            vec![route]
        );
        assert!(!sticky.contains_key(&keys[0]));
    }

    #[test]
    fn simultaneous_online_route_candidates_choose_lowest_stable_id() {
        let reg = Arc::new(MachineRegistry::new());
        let keys = stable_sorted_keys(&["route-simultaneous-b", "route-simultaneous-a"]);
        let route = "10.0.0.0/24";
        reg.upsert(keys[0].clone(), route_record(&keys[0], 10, route));
        reg.upsert(keys[1].clone(), route_record(&keys[1], 11, route));
        let _guard_a = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            stable_id_from_key(&keys[0]),
            Duration::ZERO,
        );
        let _guard_b = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            stable_id_from_key(&keys[1]),
            Duration::ZERO,
        );

        let primary = reg.primary_routes_for_snapshot(&reg.snapshot());
        assert_eq!(
            primary.get(&keys[0]).cloned().unwrap_or_default(),
            vec![route]
        );
        assert!(!primary.contains_key(&keys[1]));
    }

    #[test]
    fn offline_router_is_removed_from_primary_routes_until_it_returns() {
        let reg = Arc::new(MachineRegistry::new());
        let keys = stable_sorted_keys(&["route-offline-b", "route-offline-a"]);
        let route = "10.0.0.0/24";
        reg.upsert(keys[0].clone(), route_record(&keys[0], 10, route));
        reg.upsert(keys[1].clone(), route_record(&keys[1], 11, route));
        let guard_a = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            stable_id_from_key(&keys[0]),
            Duration::ZERO,
        );
        let _guard_b = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            stable_id_from_key(&keys[1]),
            Duration::ZERO,
        );

        let first = reg.primary_routes_for_snapshot(&reg.snapshot());
        assert_eq!(
            first.get(&keys[0]).cloned().unwrap_or_default(),
            vec![route]
        );

        drop(guard_a);
        let failed_over = reg.primary_routes_for_snapshot(&reg.snapshot());
        assert_eq!(
            failed_over.get(&keys[1]).cloned().unwrap_or_default(),
            vec![route]
        );
        assert!(!failed_over.contains_key(&keys[0]));

        let _guard_a = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            stable_id_from_key(&keys[0]),
            Duration::ZERO,
        );
        let returned = reg.primary_routes_for_snapshot(&reg.snapshot());
        assert_eq!(
            returned.get(&keys[1]).cloned().unwrap_or_default(),
            vec![route]
        );
        assert!(!returned.contains_key(&keys[0]));
    }

    #[test]
    fn ephemeral_router_gc_removes_primary_candidate_state() {
        let reg = Arc::new(MachineRegistry::new());
        let node_key = "route-ephemeral-router";
        let route = "10.0.0.0/24";
        let mut rec = route_record(node_key, 12, route);
        rec.ephemeral = true;
        reg.upsert(node_key.to_string(), rec);
        let guard = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            stable_id_from_key(node_key),
            Duration::ZERO,
        );

        let before = reg.primary_routes_for_snapshot(&reg.snapshot());
        assert_eq!(
            before.get(node_key).cloned().unwrap_or_default(),
            vec![route]
        );

        drop(guard);
        reg.update_with(|map| {
            map.get_mut(node_key).unwrap().last_seen = Utc::now() - chrono::Duration::seconds(120);
        });
        let removed = reg.gc_ephemeral(std::time::Duration::from_mins(1));
        assert_eq!(removed, vec![node_key.to_string()]);
        assert!(reg.get(node_key).is_none());
        assert!(reg.primary_routes_for_snapshot(&reg.snapshot()).is_empty());
        assert!(
            reg.debug_routes_for_snapshot(&reg.snapshot())
                .available_routes
                .is_empty()
        );
    }

    #[test]
    fn complete_web_registration_rekeys_same_machine_and_clears_tags() {
        let reg = MachineRegistry::new();
        let mut existing = mk_record(8);
        existing.node_key_hex = "old-node".into();
        existing.machine_key_hex = "same-machine".into();
        existing.user = "alice".into();
        existing.forced_tags = vec!["tag:server".into()];
        existing.approved_routes = vec!["10.0.0.0/24".into(), "10.99.0.0/24".into()];
        existing.available_routes = vec!["10.0.0.0/24".into(), "10.99.0.0/24".into()];
        let old_ip = existing.ipv4;
        let old_created_at = existing.created_at;
        reg.upsert("old-node".to_string(), existing);

        let mut pending = mk_record(9);
        pending.node_key_hex = "new-node".into();
        pending.machine_key_hex = "same-machine".into();
        pending.user = String::new();
        pending.forced_tags = Vec::new();
        pending.available_routes = vec!["10.0.0.0/24".into(), "10.1.0.0/24".into()];
        pending.approved_routes = vec!["10.1.0.0/24".into()];

        let registered = reg.complete_web_registration(pending, "alice", 2);
        assert_eq!(registered.node_key_hex, "new-node");
        assert_eq!(registered.machine_key_hex, "same-machine");
        assert_eq!(registered.user, "alice");
        assert!(registered.forced_tags.is_empty());
        assert_eq!(registered.ipv4, old_ip);
        assert_eq!(registered.created_at, old_created_at);
        assert_eq!(
            registered.approved_routes,
            vec!["10.0.0.0/24", "10.1.0.0/24", "10.99.0.0/24"]
        );
        assert_eq!(registered.register_method, 2);

        assert_eq!(reg.len(), 1, "reauth must not duplicate the node");
        assert!(reg.get("old-node").is_none());
        let stored = reg.get("new-node").unwrap();
        assert!(stored.forced_tags.is_empty());
        assert_eq!(stored.ipv4, old_ip);
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

    #[test]
    fn gc_ephemeral_cleans_batcher_connection_state() {
        let reg = Arc::new(MachineRegistry::new());
        let mut rec = mk_record(10);
        rec.ephemeral = true;
        rec.last_seen = Utc::now() - chrono::Duration::seconds(120);
        reg.upsert("nk-a".to_string(), rec);
        let node_id = stable_id_from_key("nk-a");

        let guard = MachineRegistry::track_stream_connection(reg.clone(), node_id);
        drop(guard);
        assert_eq!(reg.active_connections().get(&node_id), Some(&0));
        reg.update_with(|map| {
            map.get_mut("nk-a").unwrap().last_seen = Utc::now() - chrono::Duration::seconds(120);
        });

        let removed = reg.gc_ephemeral(std::time::Duration::from_mins(1));
        assert_eq!(removed, vec!["nk-a".to_string()]);
        assert!(!reg.active_connections().contains_key(&node_id));
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

/// Build the combined Tailscale-wire router.
///
/// This remains useful for unit tests and small embedded harnesses.
/// Production serving should use [`control_router`] and
/// [`metrics_debug_router`] on separate listeners to match
/// headscale-go's `listen_addr` / `metrics_listen_addr` split.
pub fn router(state: WireState) -> Router {
    combined_router_with_optional_oidc(state, None)
}

/// Build the combined wire router with the OIDC auth provider mounted.
///
/// This mirrors headscale-go's routing switch: when OIDC is configured,
/// `/register/{registration_id}` starts the OIDC auth-code flow instead
/// of rendering the CLI registration instruction page, and
/// `/oidc/callback` is present on the public control listener.
pub fn router_with_oidc(state: WireState, oidc: crate::oidc::OidcAuthRuntime) -> Router {
    combined_router_with_optional_oidc(state, Some(oidc))
}

/// Build only the public control listener routes.
///
/// Metrics and `/debug/*` intentionally live in
/// [`metrics_debug_router`] so production can bind them to
/// `metrics_listen_addr` instead of exposing them on `listen_addr`.
pub fn control_router(state: WireState) -> Router {
    control_router_with_optional_oidc(state, None)
}

/// Build only the public control listener routes with OIDC mounted.
pub fn control_router_with_oidc(state: WireState, oidc: crate::oidc::OidcAuthRuntime) -> Router {
    control_router_with_optional_oidc(state, Some(oidc))
}

fn combined_router_with_optional_oidc(
    state: WireState,
    oidc: Option<crate::oidc::OidcAuthRuntime>,
) -> Router {
    let knock_cfg = state.knock.clone();
    let inner = control_router_with_optional_oidc_inner(state.clone(), oidc, false)
        .merge(metrics_debug_router(state));
    knock::wrap_router(inner, knock_cfg)
}

#[derive(Clone)]
struct WireOidcRegistrationHandler {
    state: WireState,
}

#[async_trait]
impl crate::oidc::OidcRegistrationHandler for WireOidcRegistrationHandler {
    async fn complete_oidc_registration(
        &self,
        registration_id: &str,
        user: &crate::oidc::OidcStoredUser,
        node_expiry: Option<DateTime<Utc>>,
    ) -> Result<crate::oidc::OidcRegistrationResult, crate::oidc::OidcRegistrationError> {
        let user_name = oidc_wire_user_name(user);
        let mut pending = self
            .state
            .registration_cache
            .get(registration_id)
            .ok_or(crate::oidc::OidcRegistrationError::SessionExpired)?;
        pending.expiry = if pending.forced_tags.is_empty() {
            node_expiry.or(pending.expiry)
        } else {
            None
        };

        pending.approved_routes = auto_approved_routes_for_node(
            &self.state.policy,
            &pending.primary_addr_string().unwrap_or_default(),
            Some(&user_name),
            &pending.forced_tags,
            &pending.approved_routes,
            &pending.available_routes,
        )
        .map_err(crate::oidc::OidcRegistrationError::Store)?;

        let new_node = self
            .state
            .machines
            .get_by_machine_key_for_user(&pending.machine_key_hex, &user_name)
            .is_none();
        let registered = self.state.machines.complete_web_registration(
            pending,
            &user_name,
            REGISTER_METHOD_OIDC,
        );
        if self
            .state
            .registration_cache
            .complete(registration_id, registered)
        {
            Ok(crate::oidc::OidcRegistrationResult { new_node })
        } else {
            Err(crate::oidc::OidcRegistrationError::SessionExpired)
        }
    }
}

fn oidc_wire_user_name(user: &crate::oidc::OidcStoredUser) -> String {
    user.username()
}

fn control_router_with_optional_oidc(
    state: WireState,
    oidc: Option<crate::oidc::OidcAuthRuntime>,
) -> Router {
    control_router_with_optional_oidc_inner(state, oidc, true)
}

fn control_router_with_optional_oidc_inner(
    state: WireState,
    oidc: Option<crate::oidc::OidcAuthRuntime>,
    wrap_knock: bool,
) -> Router {
    let knock_cfg = state.knock.clone();
    let metrics_registry = Arc::clone(&state.machines);
    let mut inner = Router::new()
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
        .route("/verify", post(basic_handlers::handle_verify))
        .route("/derp/probe", any(basic_handlers::handle_derp_probe))
        .route(
            "/derp/latency-check",
            any(basic_handlers::handle_derp_probe),
        )
        .route(
            "/bootstrap-dns",
            any(basic_handlers::handle_derp_bootstrap_dns),
        )
        .route("/favicon.ico", get(basic_handlers::handle_favicon))
        .route("/key", get(key_handler::handle_key))
        .route(
            "/machine/ping-response",
            head(basic_handlers::handle_ping_response),
        );

    inner = if let Some(oidc) = oidc {
        let oidc = oidc.with_registration_handler_if_unset(Arc::new(WireOidcRegistrationHandler {
            state: state.clone(),
        }));
        let register_oidc = oidc.clone();
        let callback_oidc = oidc;
        inner
            .route(
                "/register/:registration_id",
                get(move |axum::extract::Path(registration_id): axum::extract::Path<String>| {
                    let oidc = register_oidc.clone();
                    async move { crate::oidc::handle_register(oidc, registration_id).await }
                }),
            )
            .route(
                "/oidc/callback",
                get(
                    move |headers: axum::http::HeaderMap,
                          query: axum::extract::Query<crate::oidc::OidcCallbackQuery>| {
                        let oidc = callback_oidc.clone();
                        async move { crate::oidc::handle_callback(oidc, headers, query).await }
                    },
                ),
            )
    } else {
        inner.route(
            "/register/:registration_id",
            get(basic_handlers::handle_web_register),
        )
    };

    let inner = inner
        .route("/ts2021", post(noise::handle_ts2021_post))
        .fallback(basic_handlers::handle_fallback)
        .with_state(state)
        .layer(middleware::from_fn(move |req: Request, next: Next| {
            let metrics_registry = Arc::clone(&metrics_registry);
            async move { record_http_metrics(metrics_registry, req, next).await }
        }));

    if wrap_knock {
        // PSK-gated handshake — third layer of the active-probe shield.
        // Default-off (KnockConfig::disabled()) → exact pass-through.
        // When enabled, requests must carry a valid knock cookie or get a
        // canonical nginx 404. See `tailscale_wire::knock` for the math.
        knock::wrap_router(inner, knock_cfg)
    } else {
        inner
    }
}

/// Build the metrics/debug listener router.
///
/// This mirrors headscale-go's dedicated metrics listener: `/metrics`
/// and `/debug/*` are operator-facing diagnostics, not public control
/// listener routes.
pub fn metrics_debug_router(state: WireState) -> Router {
    let metrics_registry = Arc::clone(&state.machines);
    Router::new()
        .route("/metrics", get(basic_handlers::handle_metrics))
        .route("/debug", get(basic_handlers::handle_debug_redirect))
        .route("/debug/", get(basic_handlers::handle_debug_index))
        .route("/debug/vars", get(basic_handlers::handle_debug_vars))
        .route("/debug/varz", get(basic_handlers::handle_metrics))
        .route(
            "/debug/pprof",
            get(basic_handlers::handle_debug_pprof_redirect),
        )
        .route(
            "/debug/pprof/",
            get(basic_handlers::handle_debug_pprof_index),
        )
        .route(
            "/debug/pprof/cmdline",
            any(basic_handlers::handle_debug_pprof_cmdline),
        )
        .route(
            "/debug/pprof/profile",
            any(basic_handlers::handle_debug_pprof_cpu_profile),
        )
        .route(
            "/debug/pprof/symbol",
            any(basic_handlers::handle_debug_pprof_symbol),
        )
        .route(
            "/debug/pprof/trace",
            any(basic_handlers::handle_debug_pprof_trace),
        )
        .route(
            "/debug/pprof/:profile",
            any(basic_handlers::handle_debug_pprof_profile),
        )
        .route("/debug/gc", get(basic_handlers::handle_debug_gc))
        .route(
            "/debug/statsviz",
            get(basic_handlers::handle_debug_statsviz_redirect),
        )
        .route(
            "/debug/statsviz/",
            get(basic_handlers::handle_debug_statsviz_index),
        )
        .route(
            "/debug/statsviz/ws",
            any(basic_handlers::handle_debug_statsviz_ws),
        )
        .route(
            "/debug/overview",
            get(basic_handlers::handle_debug_overview),
        )
        .route("/debug/config", get(basic_handlers::handle_debug_config))
        .route("/debug/routes", get(basic_handlers::handle_debug_routes))
        .route("/debug/derp", get(basic_handlers::handle_debug_derp))
        .route(
            "/debug/registration-cache",
            get(basic_handlers::handle_debug_registration_cache),
        )
        .route("/debug/filter", get(basic_handlers::handle_debug_filter))
        .route("/debug/policy", get(basic_handlers::handle_debug_policy))
        .route("/debug/ssh", get(basic_handlers::handle_debug_ssh))
        .route(
            "/debug/nodestore",
            get(basic_handlers::handle_debug_nodestore),
        )
        .route(
            "/debug/mapresponses",
            get(basic_handlers::handle_debug_mapresponses),
        )
        .route("/debug/batcher", get(basic_handlers::handle_debug_batcher))
        .route(
            "/debug/policy-manager",
            get(basic_handlers::handle_debug_policy_manager),
        )
        .with_state(state)
        .layer(middleware::from_fn(move |req: Request, next: Next| {
            let metrics_registry = Arc::clone(&metrics_registry);
            async move { record_http_metrics(metrics_registry, req, next).await }
        }))
}

async fn record_http_metrics(
    machines: Arc<MachineRegistry>,
    req: Request,
    next: Next,
) -> AxumResponse {
    let method = req.method().as_str().to_string();
    let metric_path = prometheus_http_path(req.uri().path()).map(str::to_string);

    let Some(metric_path) = metric_path else {
        return next.run(req).await;
    };

    let start = Instant::now();
    let response = next.run(req).await;
    let code = response.status().as_u16();
    machines.record_http_request(code, &method, &metric_path, start.elapsed());
    response
}

fn prometheus_http_path(path: &str) -> Option<&'static str> {
    match path {
        "/ts2021"
        | "/machine/map"
        | "/derp"
        | "/derp/probe"
        | "/derp/latency-check"
        | "/bootstrap-dns"
        | "/metrics"
        | "/debug" => None,
        path if path.starts_with("/debug/") => None,
        "/robots.txt" => Some("/robots.txt"),
        "/health" => Some("/health"),
        "/version" => Some("/version"),
        "/key" => Some("/key"),
        "/verify" => Some("/verify"),
        "/apple" => Some("/apple"),
        "/windows" => Some("/windows"),
        "/swagger" => Some("/swagger"),
        "/swagger/v1/openapiv2.json" => Some("/swagger/v1/openapiv2.json"),
        "/favicon.ico" => Some("/favicon.ico"),
        "/machine/register" => Some("/machine/register"),
        path if is_single_segment_after(path, "/apple/") => Some("/apple/{platform}"),
        path if is_single_segment_after(path, "/register/") => Some("/register/{registration_id}"),
        path if is_machine_subpath(path, "register") => Some("/machine/{node_key}/register"),
        path if is_machine_subpath(path, "map") => None,
        _ => Some("/"),
    }
}

pub(crate) fn debug_high_cardinality_metrics_enabled() -> bool {
    #[cfg(test)]
    if DEBUG_HIGH_CARDINALITY_METRICS_FOR_TESTS.load(std::sync::atomic::Ordering::SeqCst) {
        return true;
    }

    std::env::var("HEADSCALE_DEBUG_HIGH_CARDINALITY_METRICS")
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "t" | "true" | "y" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

#[cfg(test)]
static DEBUG_HIGH_CARDINALITY_METRICS_FOR_TESTS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
pub(crate) fn set_debug_high_cardinality_metrics_for_tests(enabled: bool) {
    DEBUG_HIGH_CARDINALITY_METRICS_FOR_TESTS.store(enabled, std::sync::atomic::Ordering::SeqCst);
}

fn is_single_segment_after(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|rest| !rest.is_empty() && !rest.contains('/'))
}

fn is_machine_subpath(path: &str, suffix: &str) -> bool {
    let suffix = format!("/{suffix}");
    path.strip_prefix("/machine/")
        .and_then(|rest| rest.strip_suffix(&suffix))
        .is_some_and(|node_key| !node_key.is_empty() && !node_key.contains('/'))
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
        pub used: Arc<parking_lot::RwLock<HashMap<String, RedeemOk>>>,
        pub expired: Arc<parking_lot::RwLock<HashMap<String, RedeemOk>>>,
    }

    impl MockRedeemer {
        pub fn new() -> Self {
            Self::default()
        }
        /// Insert a plain key → user mapping (non-ephemeral, no tags).
        pub fn insert(&self, key: impl Into<String>, user: impl Into<String>) {
            self.insert_full(key, RedeemOk::for_user(user.into()));
        }
        /// Insert a key with explicit lifecycle metadata (ephemeral
        /// flag + tags). Used by the lifecycle tests to exercise the
        /// ephemeral-GC path.
        #[allow(dead_code)] // used by external integration tests
        pub fn insert_full(&self, key: impl Into<String>, ok: RedeemOk) {
            let key = key.into();
            self.used.write().remove(&key);
            self.expired.write().remove(&key);
            self.inner.write().insert(key, ok);
        }
        pub fn insert_expired(&self, key: impl Into<String>, ok: RedeemOk) {
            let key = key.into();
            self.inner.write().remove(&key);
            self.used.write().remove(&key);
            self.expired.write().insert(key, ok);
        }
        pub fn expire(&self, key: &str) -> bool {
            let ok = self
                .inner
                .write()
                .remove(key)
                .or_else(|| self.used.write().remove(key));
            match ok {
                Some(ok) => {
                    self.expired.write().insert(key.to_string(), ok);
                    true
                }
                None => false,
            }
        }
        pub fn contains(&self, key: &str) -> bool {
            self.inner.read().contains_key(key)
        }
    }

    #[async_trait]
    impl PreauthRedeemer for MockRedeemer {
        async fn redeem(&self, key: &str) -> Result<RedeemOk, RedeemError> {
            let mut g = self.inner.write();
            if let Some(ok) = g.remove(key) {
                self.used.write().insert(key.to_string(), ok.clone());
                return Ok(ok);
            }
            if self.expired.read().contains_key(key) {
                return Err(RedeemError::Expired);
            }
            if self.used.read().contains_key(key) {
                return Err(RedeemError::AlreadyUsed);
            }
            Err(RedeemError::Unknown)
        }

        async fn lookup(&self, key: &str) -> Option<RedeemOk> {
            if let Some(ok) = self.inner.read().get(key).cloned() {
                return Some(ok);
            }
            if let Some(ok) = self.used.read().get(key).cloned() {
                return Some(ok);
            }
            self.expired.read().get(key).cloned()
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
