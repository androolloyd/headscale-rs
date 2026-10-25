//! Tailscale wire-protocol compatibility layer.
//!
//! This module owns the Rust port of headscale-go's Tailscale wire
//! control plane. Downstream callers bridge their preauth and
//! IP-allocation policy into the wire layer via the [`PreauthRedeemer`]
//! and [`IpAllocator`] traits.
//!
//! Implements the Tailscale coordination endpoints required by
//! headscale-go-compatible clients: `/key`, `/ts2021`, `/register`,
//! `/map`, and the related auth/SSH/debug control routes.
//!
//! ## What ships in this commit
//!
//! - **`GET /key`** ([`key_handler`]) — returns the node's long-term
//!   Noise X25519 public key as a Tailscale-shape
//!   `OverTLSPublicKeyResponse` JSON.
//! - **`POST /ts2021`** ([`noise`]) — `Upgrade:
//!   tailscale-control-protocol` handler. Drives the Noise IK responder
//!   on the hijacked socket + spins up h2 inside the Noise transport.
//! - **`GET /ts2021`** ([`noise`]) — browser/WASM WebSocket upgrade
//!   with the deferred Noise initiation in the query string and encrypted
//!   h2 over binary WebSocket messages.
//! - **Noise-inner `POST /machine/{node_key}/register`** ([`register`]) —
//!   decodes a JSON `RegisterRequest`, redeems the presented authkey via
//!   the injected [`PreauthRedeemer`], allocates a tailnet IP via the
//!   injected [`IpAllocator`].
//! - **Noise-inner `POST /machine/{node_key}/map`** ([`map`]) — long-poll
//!   peer map.
//!
//! Headscale-go and Tailscale client behavior define compatibility
//! here; downstream product policy is injected at the trait boundary.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering},
    mpsc as std_mpsc,
};
use std::thread;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::{
    Router,
    extract::{ConnectInfo, Request},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response as AxumResponse},
    routing::{any, get, head, post},
};
use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use thiserror::Error;
use tokio::sync::{Notify, broadcast, oneshot, watch};

use self::routes::{DebugRoutes, PrimaryRouteState, active_approved_routes, active_primary_routes};
use self::wire::{auto_given_name_base, stable_id_from_key, valid_given_name_label};

/// Headscale-go default: pending interactive registrations are valid
/// for 15 minutes before the registration cache can evict them.
pub const REGISTRATION_CACHE_EXPIRATION: Duration = Duration::from_secs(15 * 60);
/// Headscale-go default cleanup tick for the registration cache.
pub const REGISTRATION_CACHE_CLEANUP: Duration = Duration::from_secs(20 * 60);
/// Headscale-go default upper bound for pending auth/registration requests.
pub const REGISTRATION_CACHE_MAX_ENTRIES: usize = 1024;
/// How many unconsumed, unexpired registration entries one
/// [`RegistrationSource`] may hold at once. headscale-go has no such limit
/// (its `authCache` is a plain LRU), so an unauthenticated peer can push
/// every pending admin approval out of the 1024-entry cache with tiny
/// Register requests (F-REGCACHE). 64 is 1/16 of the Go cache bound: it takes
/// at least 16 distinct sources to occupy the whole default cache, while 64
/// simultaneously unapproved sign-ins from one address (a NAT'd office, CGNAT,
/// a reverse proxy) inside the 15 minute expiry window is far beyond what
/// people running `tailscale up` and waiting for approval produce. A source
/// over this limit loses only its own least recently used pending entries.
pub const REGISTRATION_CACHE_MAX_PENDING_PER_SOURCE: usize = 64;
/// Upstream debug knob that enables on-disk MapResponse dumps.
pub const MAPRESPONSE_DEBUG_DUMP_ENV: &str = "HEADSCALE_DEBUG_DUMP_MAPRESPONSE_PATH";
const PING_ID_LENGTH: usize = 16;
const PING_ID_URLSAFE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
const REGISTER_METHOD_OIDC: i32 = 3;
const STREAM_OFFLINE_GRACE: Duration = Duration::from_secs(10);
/// Headscale-go batcher cleanup cadence for long-offline nodes.
pub const BATCHER_OFFLINE_CLEANUP_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Headscale-go retains disconnected batcher entries for rapid reconnects.
pub const BATCHER_OFFLINE_CLEANUP_THRESHOLD: Duration = Duration::from_secs(15 * 60);
const MAP_BATCH_EVENT_BUFFER: usize = 30;
const MAP_CHANGE_HISTORY_LIMIT: usize = 128;
const TS_ALLOW_DEBUG_IP_ENV: &str = "TS_ALLOW_DEBUG_IP";
const TS_DEBUG_KEY_PATH_ENV: &str = "TS_DEBUG_KEY_PATH";
const TS_DEBUG_TRUSTED_CIDRS_ENV: &str = "TS_DEBUG_TRUSTED_CIDRS";

pub mod acme;
pub mod basic_handlers;
pub mod be_transport;
pub mod controlbase;
pub mod database_health;
mod debug_filters;
mod debug_float;
mod debug_json;
mod debug_nodes;
mod debug_schema;
#[cfg(feature = "full")]
pub mod derp;
pub mod derp_config;
mod go_time;
pub(crate) mod hostinfo;
mod http_shutdown;
pub mod key_handler;
pub mod knock;
mod machine_snapshot;
pub mod map;
mod map_json;
#[doc(hidden)]
pub mod native_derp;
mod native_methods;
mod native_shutdown;
pub(super) mod request_log;
mod snapshot_map;
pub(crate) use machine_snapshot::MachineSnapshot;
use snapshot_map::SnapshotMap;
pub mod noise;
mod query;
pub mod raw_tls;
pub mod register;
mod register_json;
mod request_json;
pub mod routes;
pub mod serve;
pub mod ssh;
mod ssh_url;
pub mod tls;
mod web_registration;
pub mod wire;
mod wire_ids;

pub use basic_handlers::DebugConfigInfo as RuntimeConfigSnapshot;
pub use database_health::DatabaseHealthCheck;
pub use knock::{KNOCK_HEADER, KNOCK_PATH_PREFIX, KnockConfig, NGINX_404_BODY};
pub use noise::ServerNoiseKey;
pub use web_registration::{CompletedWebRegistration, WebRegistrationError, WebRegistrationUser};
pub use wire::{
    DerpMap, DerpRegion, DerpRegionNode, MachineRecord, MapRequest, MapResponse, NetInfo,
    PingRequest, RegisterRequest, RegisterResponse,
};

/// Once a durable mutation begins, finish its database/live-state publication
/// even if the requesting HTTP/2 stream or callback disconnects. The future
/// owns its mutation guard; dropping the caller's join handle does not abort
/// the worker. Runtime shutdown and process failure remain separate concerns.
pub(crate) async fn complete_state_mutation<F, T>(mutation: F) -> Result<T, tokio::task::JoinError>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    tokio::spawn(mutation).await
}

// Re-export the lifecycle helper so downstream crates can spawn the GC
// sweep without reaching into the module path.
pub use self::spawn_ephemeral_gc as ephemeral_gc_task;
pub use self::spawn_node_expiry_waker as node_expiry_waker_task;

/// Distinguish rejected input from policy resolution after a live mutation.
/// A policy error does not roll back the already published NodeStore write.
#[derive(Debug, thiserror::Error)]
pub enum RegistryMutationError {
    #[error("{0}")]
    Invalid(std::borrow::Cow<'static, str>),
    #[error("{0}")]
    Policy(String),
}

impl From<&'static str> for RegistryMutationError {
    fn from(message: &'static str) -> Self {
        Self::Invalid(message.into())
    }
}

impl From<String> for RegistryMutationError {
    fn from(message: String) -> Self {
        Self::Invalid(message.into())
    }
}

impl RegistryMutationError {
    fn legacy_message(self) -> &'static str {
        match self {
            Self::Invalid(std::borrow::Cow::Borrowed(message)) => message,
            error => {
                tracing::error!(%error, "finishing registry mutation");
                "updating policy manager nodes"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum MapChangeReason {
    FullUpdate,
    NodeAdded,
    NodeUpdated,
    TagUpdate,
    PeersRemoved,
    NodeOnline,
    NodeOffline,
    SubnetRouterOnline,
    SubnetRouterOffline,
    UserRemoved,
    SelfUpdate,
    EndpointDerpUpdate,
    NodeKeyRotated,
    KeyExpiry,
    PolicyChange,
    DnsConfigUpdate,
    DerpMapUpdate,
    PingNode,
    FullSelfUpdate,
    RouteUpdate,
    RouteHealthUpdate,
}

impl MapChangeReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FullUpdate => "full update",
            Self::NodeAdded => "node added",
            Self::NodeUpdated => "node updated",
            Self::TagUpdate => "tag update",
            Self::PeersRemoved => "peers removed",
            Self::NodeOnline => "node online",
            Self::NodeOffline => "node offline",
            Self::SubnetRouterOnline => "subnet router online",
            Self::SubnetRouterOffline => "subnet router offline",
            Self::UserRemoved => "user removed",
            Self::SelfUpdate => "self update",
            Self::EndpointDerpUpdate => "endpoint/DERP update",
            Self::NodeKeyRotated => "node key rotated (relogin)",
            Self::KeyExpiry => "key expiry",
            Self::PolicyChange => "policy change",
            Self::DnsConfigUpdate => "DNS config update",
            Self::DerpMapUpdate => "DERP map update",
            Self::PingNode => "ping node",
            Self::FullSelfUpdate => "full self update",
            Self::RouteUpdate => "route update",
            Self::RouteHealthUpdate => "route health update",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MapChangeContent {
    pub include_self: bool,
    pub include_derp_map: bool,
    pub include_dns: bool,
    pub include_domain: bool,
    pub include_policy: bool,
    pub peers_changed: Vec<u64>,
    pub peers_removed: Vec<u64>,
    pub peer_patches: Vec<u64>,
    pub send_all_peers: bool,
    pub requires_runtime_peer_computation: bool,
    pub ping_request: bool,
}

impl MapChangeContent {
    fn full() -> Self {
        Self {
            include_self: true,
            include_derp_map: true,
            include_dns: true,
            include_domain: true,
            include_policy: true,
            send_all_peers: true,
            ..Self::default()
        }
    }

    fn for_reason(reason: MapChangeReason, node_id: Option<u64>) -> Self {
        let mut content = Self::default();
        match reason {
            MapChangeReason::FullUpdate
            | MapChangeReason::FullSelfUpdate
            | MapChangeReason::SubnetRouterOnline
            | MapChangeReason::SubnetRouterOffline
            | MapChangeReason::UserRemoved => {
                content = Self::full();
            }
            MapChangeReason::SelfUpdate => {
                content.include_self = true;
                content.include_dns = true;
            }
            MapChangeReason::NodeAdded
            | MapChangeReason::NodeUpdated
            | MapChangeReason::RouteUpdate => {
                if let Some(node_id) = node_id {
                    content.peers_changed.push(node_id);
                } else {
                    content.send_all_peers = true;
                }
            }
            MapChangeReason::PeersRemoved => {
                if let Some(node_id) = node_id {
                    content.peers_removed.push(node_id);
                } else {
                    content.send_all_peers = true;
                }
            }
            MapChangeReason::NodeOnline
            | MapChangeReason::NodeOffline
            | MapChangeReason::EndpointDerpUpdate
            | MapChangeReason::NodeKeyRotated
            | MapChangeReason::KeyExpiry => {
                if let Some(node_id) = node_id {
                    content.peer_patches.push(node_id);
                } else {
                    content.send_all_peers = true;
                }
            }
            MapChangeReason::PolicyChange
            | MapChangeReason::TagUpdate
            | MapChangeReason::RouteHealthUpdate => {
                content.include_policy = true;
                content.requires_runtime_peer_computation = true;
            }
            MapChangeReason::DnsConfigUpdate => {
                content.include_dns = true;
            }
            MapChangeReason::DerpMapUpdate => {
                content.include_derp_map = true;
            }
            MapChangeReason::PingNode => {
                content.ping_request = true;
            }
        }
        content
    }

    fn merge(&mut self, other: Self) {
        self.include_self |= other.include_self;
        self.include_derp_map |= other.include_derp_map;
        self.include_dns |= other.include_dns;
        self.include_domain |= other.include_domain;
        self.include_policy |= other.include_policy;
        self.send_all_peers |= other.send_all_peers;
        self.requires_runtime_peer_computation |= other.requires_runtime_peer_computation;
        self.ping_request |= other.ping_request;
        append_unique(&mut self.peers_changed, other.peers_changed);
        append_unique(&mut self.peers_removed, other.peers_removed);
        append_unique(&mut self.peer_patches, other.peer_patches);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MapChange {
    pub generation: u64,
    pub reasons: Vec<MapChangeReason>,
    pub target_node_id: Option<u64>,
    pub origin_node_id: Option<u64>,
    pub content: MapChangeContent,
}

pub type MapChangeBatch = Arc<BTreeMap<u64, Vec<MapChange>>>;

impl MapChange {
    #[must_use]
    pub fn full_update(generation: u64) -> Self {
        PendingMapChange::global(MapChangeReason::FullUpdate).into_change(generation)
    }

    #[must_use]
    pub fn full_self(generation: u64, node_id: u64) -> Self {
        PendingMapChange::target(MapChangeReason::FullSelfUpdate, node_id).into_change(generation)
    }

    #[must_use]
    pub fn reason_label(&self) -> &'static str {
        self.reasons
            .first()
            .map_or("unknown", |reason| reason.as_str())
    }

    #[must_use]
    pub fn reason_labels(&self) -> Vec<&'static str> {
        self.reasons.iter().map(|reason| reason.as_str()).collect()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        let content = &self.content;
        !content.include_self
            && !content.include_derp_map
            && !content.include_dns
            && !content.include_domain
            && !content.include_policy
            && !content.send_all_peers
            && !content.requires_runtime_peer_computation
            && !content.ping_request
            && content.peers_changed.is_empty()
            && content.peers_removed.is_empty()
            && content.peer_patches.is_empty()
    }

    #[must_use]
    pub fn is_self_only(&self) -> bool {
        self.target_node_id.is_some()
            && self.content.include_self
            && !self.content.send_all_peers
            && self.content.peers_changed.is_empty()
            && self.content.peers_removed.is_empty()
            && self.content.peer_patches.is_empty()
    }

    #[must_use]
    pub fn is_full(&self) -> bool {
        self.content.send_all_peers
            && self.content.include_self
            && self.content.include_derp_map
            && self.content.include_dns
            && self.content.include_domain
            && self.content.include_policy
    }

    #[must_use]
    pub fn change_type(&self) -> &'static str {
        if self.is_full() {
            return "full";
        }
        if self.is_self_only() {
            return "self";
        }
        if self.content.requires_runtime_peer_computation {
            return "policy";
        }
        if !self.content.peer_patches.is_empty()
            && self.content.peers_changed.is_empty()
            && self.content.peers_removed.is_empty()
            && !self.content.send_all_peers
        {
            return "patch";
        }
        if !self.content.peers_changed.is_empty()
            || !self.content.peers_removed.is_empty()
            || self.content.send_all_peers
        {
            return "peers";
        }
        if self.content.include_derp_map
            || self.content.include_dns
            || self.content.include_domain
            || self.content.include_policy
        {
            return "config";
        }
        if self.content.ping_request {
            return "ping";
        }
        "unknown"
    }

    #[must_use]
    pub fn should_send_to_node(&self, node_id: u64) -> bool {
        self.target_node_id
            .is_none_or(|target_node_id| target_node_id == node_id)
    }

    #[must_use]
    pub fn merge(mut self, other: Self) -> Self {
        if let (Some(left), Some(right)) = (self.target_node_id, other.target_node_id) {
            assert_eq!(
                left, right,
                "cannot merge map changes with different target nodes"
            );
        }
        self.generation = self.generation.max(other.generation);
        if self.target_node_id.is_none() {
            self.target_node_id = other.target_node_id;
        }
        if self.origin_node_id.is_none() {
            self.origin_node_id = other.origin_node_id;
        }
        append_unique(&mut self.reasons, other.reasons);
        self.content.merge(other.content);
        self
    }
}

fn append_unique<T>(target: &mut Vec<T>, values: Vec<T>)
where
    T: PartialEq,
{
    for value in values {
        if !target.contains(&value) {
            target.push(value);
        }
    }
}

fn record_is_subnet_router(rec: &MachineRecord) -> bool {
    !active_primary_routes(&rec.available_routes, &rec.approved_routes).is_empty()
}

fn record_needs_peer_recompute(
    record: &MachineRecord,
    policy: Option<&crate::policy::PolicyStore>,
) -> bool {
    if record_is_subnet_router(record) {
        return true;
    }
    let Some(policy) = policy else {
        return false;
    };
    let addresses = record.address_strings();
    policy.is_relay_or_via_target(&crate::policy::NodeView {
        addr: None,
        addrs: &addresses,
        user: (!record.user.is_empty()).then_some(record.user.as_str()),
        user_id: record.user_id,
        tags: &record.forced_tags,
    })
}

fn update_online_after_expiry(
    record: &MachineRecord,
    node_id: u64,
    state_sessions: &RwLock<BTreeMap<u64, usize>>,
    online_states: &RwLock<BTreeMap<u64, bool>>,
) -> bool {
    let active = state_sessions.read();
    let should_be_online =
        active.get(&node_id).copied().unwrap_or(0) > 0 && !record.is_expired_at(Utc::now());
    let mut online = online_states.write();
    let was_online = online.get(&node_id).copied().unwrap_or(false);
    online.insert(node_id, should_be_online);
    was_online != should_be_online
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingMapChange {
    reason: MapChangeReason,
    companion_reasons: Vec<MapChangeReason>,
    target_node_id: Option<u64>,
    origin_node_id: Option<u64>,
    content: MapChangeContent,
}

impl PendingMapChange {
    fn with_content_node(
        reason: MapChangeReason,
        target_node_id: Option<u64>,
        origin_node_id: Option<u64>,
        content_node_id: Option<u64>,
    ) -> Self {
        Self {
            reason,
            companion_reasons: Vec::new(),
            target_node_id,
            origin_node_id,
            content: MapChangeContent::for_reason(reason, content_node_id),
        }
    }

    fn new(
        reason: MapChangeReason,
        target_node_id: Option<u64>,
        origin_node_id: Option<u64>,
    ) -> Self {
        Self::with_content_node(
            reason,
            target_node_id,
            origin_node_id,
            target_node_id.or(origin_node_id),
        )
    }

    fn global(reason: MapChangeReason) -> Self {
        Self::new(reason, None, None)
    }

    fn target(reason: MapChangeReason, target_node_id: u64) -> Self {
        Self::new(reason, Some(target_node_id), None)
    }

    fn origin(reason: MapChangeReason, origin_node_id: u64) -> Self {
        Self::new(reason, None, Some(origin_node_id))
    }

    fn broadcast_peer(reason: MapChangeReason, node_id: u64) -> Self {
        Self::with_content_node(reason, None, None, Some(node_id))
    }

    fn lifecycle_peer(reason: MapChangeReason, node_id: u64, recompute: bool) -> Self {
        debug_assert!(matches!(
            reason,
            MapChangeReason::NodeOnline | MapChangeReason::NodeOffline | MapChangeReason::NodeAdded
        ));
        let change = Self::with_content_node(
            reason,
            None,
            (reason == MapChangeReason::NodeAdded).then_some(node_id),
            Some(node_id),
        );
        if recompute {
            change.with_companion_reason(MapChangeReason::PolicyChange)
        } else {
            change
        }
    }

    fn peers_removed(node_ids: Vec<u64>) -> Self {
        Self {
            reason: MapChangeReason::PeersRemoved,
            companion_reasons: Vec::new(),
            target_node_id: None,
            origin_node_id: None,
            content: MapChangeContent {
                peers_removed: node_ids,
                ..MapChangeContent::default()
            },
        }
    }

    fn with_companion_reason(mut self, reason: MapChangeReason) -> Self {
        if self.reason != reason && !self.companion_reasons.contains(&reason) {
            self.companion_reasons.push(reason);
            self.content
                .merge(MapChangeContent::for_reason(reason, None));
        }
        self
    }

    fn into_change(self, generation: u64) -> MapChange {
        let mut reasons = vec![self.reason];
        append_unique(&mut reasons, self.companion_reasons);
        MapChange {
            generation,
            reasons,
            target_node_id: self.target_node_id,
            origin_node_id: self.origin_node_id,
            content: self.content,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MapResponseDebugType {
    Full,
    SelfNode,
    Change,
    Policy,
}

impl MapResponseDebugType {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::SelfNode => "self",
            Self::Change => "change",
            Self::Policy => "policy",
        }
    }
}

/// Optional headscale-go compatible MapResponse debug dump store.
///
/// When enabled, responses are written under
/// `HEADSCALE_DEBUG_DUMP_MAPRESPONSE_PATH/<node-id>/<timestamp>-<type>.json`
/// and `/debug/mapresponses` reads the directory back as a node-id keyed JSON
/// map, matching upstream's operator endpoint.
#[derive(Clone, Debug, Default)]
pub struct MapResponseDebugStore {
    root: Option<Arc<PathBuf>>,
}

impl MapResponseDebugStore {
    pub fn disabled() -> Self {
        Self { root: None }
    }

    pub fn from_env() -> Self {
        std::env::var_os(MAPRESPONSE_DEBUG_DUMP_ENV)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .map_or_else(Self::disabled, Self::with_path)
    }

    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            root: Some(Arc::new(path.into())),
        }
    }

    pub fn enabled(&self) -> bool {
        self.root.is_some()
    }

    pub fn record(
        &self,
        node_id: u64,
        debug_type: MapResponseDebugType,
        response: &wire::MapResponse,
    ) -> io::Result<Option<PathBuf>> {
        self.record_serializable(node_id, debug_type, response)
    }

    fn record_serializable(
        &self,
        node_id: u64,
        debug_type: MapResponseDebugType,
        response: &impl serde::Serialize,
    ) -> io::Result<Option<PathBuf>> {
        if !self.enabled() {
            return Ok(None);
        }
        let body = serde_json::to_vec_pretty(response)
            .map_err(|err| io::Error::other(format!("encode MapResponse JSON: {err}")))?;
        self.record_body(node_id, debug_type, &body)
    }

    pub(crate) fn record_json(
        &self,
        node_id: u64,
        debug_type: MapResponseDebugType,
        json: &[u8],
    ) -> io::Result<Option<PathBuf>> {
        if !self.enabled() {
            return Ok(None);
        }
        let body = headscale_api_acl::go_json_output::indent(json).map_err(io::Error::other)?;
        self.record_body(node_id, debug_type, &body)
    }

    fn record_body(
        &self,
        node_id: u64,
        debug_type: MapResponseDebugType,
        body: &[u8],
    ) -> io::Result<Option<PathBuf>> {
        let Some(root) = self.root.as_deref() else {
            return Ok(None);
        };
        let node_dir = root.join(node_id.to_string());
        let mut directory = fs::DirBuilder::new();
        directory.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            directory.mode(0o755);
        }
        directory.create(&node_dir)?;
        let now = chrono::Local::now();
        let mut timestamp = now.format("%Y-%m-%dT%H-%M-%S").to_string();
        let nanos = now.timestamp_subsec_nanos();
        if nanos != 0 {
            timestamp.push('.');
            timestamp.push_str(format!("{nanos:09}").trim_end_matches('0'));
        }
        let path = node_dir.join(format!("{timestamp}-{}.json", debug_type.as_str()));
        let mut file = fs::OpenOptions::new();
        file.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            file.mode(0o755);
        }
        use std::io::Write as _;
        file.open(&path)?.write_all(body)?;

        Ok(Some(path))
    }

    pub fn read(&self) -> io::Result<Option<BTreeMap<u64, Vec<wire::MapResponse>>>> {
        let Some(root) = self.root.as_deref() else {
            return Ok(None);
        };

        read_mapresponses_from_directory(root).map(Some)
    }

    pub(crate) fn read_json(&self) -> io::Result<Option<Vec<u8>>> {
        let Some(root) = self.root.as_deref() else {
            return Ok(None);
        };
        debug_json::read(root).map(Some)
    }
}

fn read_mapresponses_from_directory(
    root: &Path,
) -> io::Result<BTreeMap<u64, Vec<wire::MapResponse>>> {
    read_mapresponses_with(root, |body| {
        serde_json::from_slice(body).map_err(io::Error::other)
    })
}

fn read_mapresponses_with<T>(
    root: &Path,
    decode: impl Fn(&[u8]) -> io::Result<T>,
) -> io::Result<BTreeMap<u64, Vec<T>>> {
    let mut responses = BTreeMap::new();
    let mut entries = fs::read_dir(root)?.collect::<io::Result<Vec<_>>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let Ok(file_type) = entry.file_type() else {
            tracing::error!(path = %entry.path().display(), "stat mapresponse debug entry");
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }

        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            tracing::error!(path = %entry.path().display(), "mapresponse debug node directory is not UTF-8");
            continue;
        };
        let node_id = name
            .parse::<u64>()
            .ok()
            .filter(|_| name.bytes().all(|byte| byte.is_ascii_digit()));
        let Some(node_id) = node_id else {
            tracing::error!(node = %name, "parsing mapresponse debug node id");
            continue;
        };

        let mut files = match fs::read_dir(entry.path())
            .and_then(std::iter::Iterator::collect::<io::Result<Vec<_>>>)
        {
            Ok(files) => files,
            Err(err) => {
                tracing::error!(error = %err, path = %entry.path().display(), "reading mapresponse debug node directory");
                continue;
            }
        };
        files.sort_by_key(fs::DirEntry::file_name);

        for file in files {
            let Ok(file_type) = file.file_type() else {
                tracing::error!(path = %file.path().display(), "stat mapresponse debug file");
                continue;
            };
            if file_type.is_dir() || !file.file_name().as_encoded_bytes().ends_with(b".json") {
                continue;
            }

            let body = match fs::read(file.path()) {
                Ok(body) => body,
                Err(err) => {
                    tracing::error!(error = %err, path = %file.path().display(), "reading mapresponse debug file");
                    continue;
                }
            };
            let response = match decode(&body) {
                Ok(response) => response,
                Err(err) => {
                    tracing::error!(error = %err, path = %file.path().display(), "unmarshalling mapresponse debug file");
                    continue;
                }
            };
            responses
                .entry(node_id)
                .or_insert_with(Vec::new)
                .push(response);
        }
    }

    Ok(responses)
}

/// Runtime DERP map store.
///
/// Headscale-go can refresh configured DERP map URLs while the server is
/// running. The wire runtime therefore cannot treat the map as immutable after
/// startup: `/map` handlers need a cheap current snapshot, and long-polling map
/// streams need a wake signal when config refreshes replace the map.
pub struct DerpMapStore {
    current: RwLock<native_derp::Snapshot>,
    notify: Notify,
    gen_tx: watch::Sender<u64>,
}

impl DerpMapStore {
    pub fn new(map: wire::DerpMap) -> Self {
        let (gen_tx, _) = watch::channel(0);
        Self {
            current: RwLock::new(native_derp::Snapshot {
                projection: map,
                native: None,
            }),
            notify: Notify::new(),
            gen_tx,
        }
    }

    pub fn shared(map: wire::DerpMap) -> Arc<Self> {
        Arc::new(Self::new(map))
    }

    pub fn snapshot(&self) -> wire::DerpMap {
        self.current.read().projection.clone()
    }

    pub fn set(&self, map: wire::DerpMap) {
        *self.current.write() = native_derp::Snapshot {
            projection: map,
            native: None,
        };
        self.notify_change();
    }

    #[doc(hidden)]
    pub fn set_native(&self, map: native_derp::NativeDerpMap) {
        let projection = map.projection();
        *self.current.write() = native_derp::Snapshot {
            projection,
            native: Some(Arc::new(map)),
        };
        self.notify_change();
    }

    fn paired_snapshot(&self) -> native_derp::Snapshot {
        let current = self.current.read();
        native_derp::Snapshot {
            projection: current.projection.clone(),
            native: current.native.clone(),
        }
    }

    #[doc(hidden)]
    pub fn json_snapshot(&self) -> serde_json::Result<serde_json::Value> {
        let snapshot = self.paired_snapshot();
        match snapshot.native {
            Some(native) => native.json_value(),
            None => serde_json::to_value(snapshot.projection),
        }
    }

    fn notify_change(&self) {
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
/// Normalized errors from whichever pre-auth-key store backs
/// [`PreauthRedeemer`]. Downstream impls map their native errors into
/// these variants. Registration reports rejection through the Error field
/// of an HTTP 200 tailcfg RegisterResponse, following pinned headscale-go.
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

/// Registration diagnostic kept alongside the stable redeemer error kind.
/// Persistent adapters can retain Go's parse/verification error wording
/// without changing the existing redeem/validate interface for embedders.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct RegistrationRedeemError {
    pub kind: RedeemError,
    pub message: String,
}

impl From<RedeemError> for RegistrationRedeemError {
    fn from(kind: RedeemError) -> Self {
        let message = match kind {
            RedeemError::Unknown => "invalid pre auth key",
            RedeemError::Expired => "authkey expired",
            RedeemError::AlreadyUsed => "authkey already used",
        }
        .to_owned();
        Self { kind, message }
    }
}

/// Why an IP allocation failed.
///
/// The variant set is intentionally small. Stateful allocators that
/// talk to a real IPAM service can grow this enum without rippling
/// through the handler signatures.
#[derive(Debug, Error)]
pub enum AllocError {
    #[error("failed to allocate IP")]
    Exhausted,
    #[error("{0}")]
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
    /// Canonical database owner. Display names and emails can be ambiguous
    /// across OIDC identities and must not be resolved again as credentials.
    pub user_id: Option<u64>,
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
            user_id: None,
            ephemeral: false,
            tags: Vec::new(),
            auth_key_id: None,
        }
    }
    pub fn ephemeral(mut self, e: bool) -> Self {
        self.ephemeral = e;
        self
    }
    pub fn user_id(mut self, id: Option<u64>) -> Self {
        self.user_id = id;
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

/// One credential lookup. Built-in native stores retain private loaded
/// associations; existing wire-only and custom redeemers keep metadata alone.
#[derive(Clone)]
pub struct PreauthLookup {
    pub metadata: RedeemOk,
    #[cfg(feature = "admin")]
    pub(crate) native: Option<crate::admin::machines::NativeAuthKey>,
    #[cfg(feature = "admin")]
    pub(crate) native_save: Option<Arc<headscale_db::preauth_keys::RegistrationKey>>,
}

impl PreauthLookup {
    pub fn metadata_only(metadata: RedeemOk) -> Self {
        Self {
            metadata,
            #[cfg(feature = "admin")]
            native: None,
            #[cfg(feature = "admin")]
            native_save: None,
        }
    }

    #[cfg(feature = "admin")]
    pub(crate) fn from_native(
        metadata: RedeemOk,
        native: crate::admin::machines::NativeAuthKey,
        material: headscale_db::preauth_keys::RegistrationKey,
    ) -> Self {
        Self {
            metadata,
            native: Some(native),
            native_save: Some(Arc::new(material)),
        }
    }

    // Without `admin` there is no native auth key to validate, but the call sites
    // are feature-independent.
    #[cfg_attr(not(feature = "admin"), allow(clippy::unused_self))]
    pub(crate) fn validation_result(&self) -> Option<Result<(), RegistrationRedeemError>> {
        #[cfg(feature = "admin")]
        if let Some(key) = &self.native {
            if key.expiration.is_some_and(|expiry| expiry < Utc::now()) {
                return Some(Err(RedeemError::Expired.into()));
            }
            if !key.reusable && key.used() {
                return Some(Err(RedeemError::AlreadyUsed.into()));
            }
            return Some(Ok(()));
        }
        None
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
/// rate-limit service; simple in-memory impls can adopt the async
/// signature trivially.
///
/// Legacy impls that return only a `String` user label can call
/// `redeem` → `Ok(user_string.into())` to satisfy the trait — `From<String>`
/// is implemented for [`RedeemOk`].
#[async_trait]
pub trait PreauthRedeemer: Send + Sync {
    async fn redeem(&self, key: &str) -> Result<RedeemOk, RedeemError>;

    async fn redeem_for_registration(
        &self,
        key: &str,
    ) -> Result<RedeemOk, RegistrationRedeemError> {
        self.redeem(key).await.map_err(Into::into)
    }

    /// The persistent registration store will consume this credential in
    /// the same transaction as the node write when both sides opt in.
    fn supports_deferred_redemption(&self) -> bool {
        false
    }

    async fn validate(&self, _key: &str) -> Result<RedeemOk, RedeemError> {
        Err(RedeemError::Unknown)
    }

    async fn validate_for_registration(
        &self,
        key: &str,
    ) -> Result<RedeemOk, RegistrationRedeemError> {
        self.validate(key).await.map_err(Into::into)
    }

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

    async fn lookup_for_registration(
        &self,
        key: &str,
    ) -> Result<Option<PreauthLookup>, RegistrationRedeemError> {
        Ok(self.lookup(key).await.map(PreauthLookup::metadata_only))
    }
}

/// Allocates tailnet addresses for a registering node.
///
/// Headscale-go uses a stateful prefix allocator; the production implementation
/// mirrors that behavior. The node-key input also permits deterministic custom
/// embedders. Registration completion reuses existing addresses before asking
/// the allocator for a fresh node.
pub trait IpAllocator: Send + Sync {
    /// Release a deleted node's addresses. Production mirrors Go FreeIPs;
    /// existing stateless/custom allocators can keep this default no-op.
    fn release_addresses(&self, _ipv4: Option<Ipv4Addr>, _ipv6: Option<Ipv6Addr>) {}

    fn allocate(&self, node_key_hex: &str) -> Result<Ipv4Addr, AllocError>;

    /// Allocate both enabled families as one operation. Stateful production
    /// allocators override this to hold the same lock across the pair, like
    /// Go IPAllocator.Next; existing custom allocators retain their methods.
    fn allocate_addresses(
        &self,
        node_key_hex: &str,
    ) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>), String> {
        let ipv4 = if self.ipv4_enabled() {
            Some(
                self.allocate(node_key_hex)
                    .map_err(|error| format!("allocating IPv4 address: {error}"))?,
            )
        } else {
            None
        };
        let ipv6 = self
            .allocate_ipv6(node_key_hex)
            .map_err(|error| format!("allocating IPv6 address: {error}"))?;
        Ok((ipv4, ipv6))
    }

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

/// Allocate only after an authenticated registration has selected a fresh node.
pub(crate) fn allocate_registration_addresses(
    allocator: &dyn IpAllocator,
    node_key_hex: &str,
) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>), String> {
    let (ipv4, ipv6) = allocator
        .allocate_addresses(node_key_hex)
        .map_err(|error| format!("allocating IPs: {error}"))?;
    if ipv4.is_none() && ipv6.is_none() {
        return Err("allocating IPs: no IP prefixes enabled".into());
    }
    Ok((ipv4, ipv6))
}

/// Historical fallback for embedders that do not supply an IP allocator.
/// The production runtime always supplies its configured prefix allocator.
#[cfg(any(feature = "admin", feature = "full"))]
pub(crate) fn legacy_registration_ipv4(key: &str) -> Ipv4Addr {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in key.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let host = ((hash as u32) % ((1u32 << 22) - 3)) + 2;
    Ipv4Addr::from((0x6440_0000 | host).to_be_bytes())
}

/// Result of persisting a wire registration into the durable node store.
#[derive(Debug, Clone)]
pub struct PersistedMachineRegistration {
    pub record: MachineRecord,
    pub replaced_node_key_hex: Option<String>,
}

#[derive(Debug, Error)]
pub enum AuthKeyRegistrationError {
    #[error(transparent)]
    Credential(#[from] RedeemError),
    #[error("{0}")]
    Storage(String),
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
    /// Liveness of the database behind this store, which `GET /health`
    /// reports as headscale-go does (`State.PingDB`). Stores that are not
    /// backed by a database keep the default and always report healthy.
    async fn ping_database(&self) -> Result<(), String> {
        Ok(())
    }

    fn supports_atomic_auth_key_registration(&self) -> bool {
        false
    }

    async fn create_or_update_auth_key_registration_atomic(
        &self,
        _record: MachineRecord,
        _policy: &crate::policy::PolicyStore,
        _candidate: &str,
        _auth_key_id: Option<i64>,
        _require_fresh: bool,
    ) -> Result<PersistedMachineRegistration, AuthKeyRegistrationError> {
        Err(AuthKeyRegistrationError::Storage(
            "atomic auth-key registration is not supported".into(),
        ))
    }

    async fn create_or_update_auth_key_registration(
        &self,
        record: MachineRecord,
        policy: &crate::policy::PolicyStore,
        auth_key_id: Option<i64>,
    ) -> Result<PersistedMachineRegistration, String>;

    /// Optional native Hostinfo companion. Existing embedders keep their wire
    /// projection contract; built-in stores preserve the decoded Go shapes.
    async fn create_or_update_auth_key_registration_with_hostinfo(
        &self,
        record: MachineRecord,
        policy: &crate::policy::PolicyStore,
        auth_key_id: Option<i64>,
        _hostinfo: Option<serde_json::Value>,
    ) -> Result<PersistedMachineRegistration, String> {
        self.create_or_update_auth_key_registration(record, policy, auth_key_id)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_or_update_auth_key_registration_atomic_with_hostinfo(
        &self,
        record: MachineRecord,
        policy: &crate::policy::PolicyStore,
        candidate: &str,
        auth_key_id: Option<i64>,
        require_fresh: bool,
        _hostinfo: Option<serde_json::Value>,
    ) -> Result<PersistedMachineRegistration, AuthKeyRegistrationError> {
        self.create_or_update_auth_key_registration_atomic(
            record,
            policy,
            candidate,
            auth_key_id,
            require_fresh,
        )
        .await
    }

    /// Carry a verified lookup to native persistence without changing the
    /// existing record or custom-store entry points.
    #[allow(clippy::too_many_arguments)]
    async fn create_or_update_auth_key_registration_atomic_with_lookup(
        &self,
        record: MachineRecord,
        policy: &crate::policy::PolicyStore,
        candidate: &str,
        auth_key_id: Option<i64>,
        require_fresh: bool,
        hostinfo: Option<serde_json::Value>,
        _lookup: Option<PreauthLookup>,
    ) -> Result<PersistedMachineRegistration, AuthKeyRegistrationError> {
        self.create_or_update_auth_key_registration_atomic_with_hostinfo(
            record,
            policy,
            candidate,
            auth_key_id,
            require_fresh,
            hostinfo,
        )
        .await
    }

    /// Native attached stores return the current, already published NodeStore
    /// snapshot. The map caller must not reapply that record after SQL. Legacy
    /// custom/headless backends keep the publication step by default.
    fn runtime_sync_returns_live_snapshot(&self) -> bool {
        false
    }

    /// Persist client map fields while preserving server-managed node fields.
    /// The map caller has applied its live delta and holds the per-machine
    /// mutation guard. Native attached stores re-read that live snapshot;
    /// adapters must not acquire the same machine guard again.
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

    /// Best-effort disconnect persistence without a policy refresh. Native
    /// stores re-read the latest NodeStore snapshot under the save mutex and
    /// write its selected columns, omitting Expiry, as Go persistNode does.
    /// The timestamp-only default interface remains available to adapters.
    async fn persist_last_seen(&self, _node_id: u64, _at: DateTime<Utc>) -> Result<(), String> {
        Ok(())
    }

    /// Save a wire logout while the caller holds the machine guard. For an
    /// expiry logout the caller has already made the quiet live edit, including
    /// online state. Save without applying it again; dispatch follows success.
    /// Ephemeral deletion remains database-first. Adapters must not acquire
    /// the same machine guard again.
    async fn persist_wire_logout(
        &self,
        _record: &MachineRecord,
        _at: DateTime<Utc>,
    ) -> Result<(), String> {
        Ok(())
    }

    async fn delete_machine_registration(&self, _node_key_hex: &str) -> Result<(), String> {
        Ok(())
    }

    fn supports_guarded_ephemeral_deletion(&self) -> bool {
        false
    }

    /// Called with the machine guard held. Implementations must delete only
    /// the supplied node identity and must not reacquire the guard.
    async fn delete_ephemeral_registration(&self, _record: &MachineRecord) -> Result<(), String> {
        Err("guarded ephemeral deletion is not supported".into())
    }
}

/// What the wire layer knows about a node asking to register.
///
/// Passed to [`RegistrationGate::admit`] before any record, address or
/// netmap entry exists for the key.
#[derive(Debug, Clone, Copy)]
pub struct RegistrationAdmission<'a> {
    /// Node key (hex, no `nodekey:` prefix) the client is registering.
    pub node_key_hex: &'a str,
    /// Noise machine key (hex) the request arrived under.
    pub machine_key_hex: &'a str,
    /// Hostname the client reported, when it sent hostinfo. Advisory —
    /// client-supplied and unauthenticated; useful in refusal logs, not
    /// as an admission input.
    pub hostname: Option<&'a str>,
}

/// Decides whether a node key may hold a registration at all.
///
/// The wire layer carries no opinion about *why* a key is admissible;
/// the implementation owns that policy (OctraVPN gates on its
/// chain-anchored member set). `None` on
/// [`WireState::registration_gate`] admits every key — the behaviour
/// before this hook existed.
///
/// This is a hard gate, not a filter: a refused key never gets a
/// record, an address, or a place in any peer's netmap. Contrast
/// [`crate::policy::PolicyStore`], which admits the node and then drops
/// its packets — visible peer, no connectivity.
///
/// The gate runs on every register path except logout: a node being
/// deregistered must always be able to finish, even after its
/// admission was revoked.
#[async_trait]
pub trait RegistrationGate: Send + Sync {
    /// `Ok(())` admits. `Err(reason)` refuses, and `reason` is returned
    /// to the client in `RegisterResponse.error` — stock `tailscale up`
    /// prints it — so write it for whoever is running the client.
    async fn admit(&self, req: RegistrationAdmission<'_>) -> Result<(), String>;
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
    /// Optional admission gate for registration. `None` ⇒ every node key
    /// that clears the preauth/interactive flow may register. See
    /// [`RegistrationGate`].
    pub registration_gate: Option<Arc<dyn RegistrationGate>>,
    /// DERP map served on `/machine/map`. The store gives each map
    /// handler a cheap cloned snapshot and wakes long-poll streams when
    /// runtime DERP refresh replaces it.
    pub derp_map: Arc<DerpMapStore>,
    /// Optional native DERP relay runtime. When absent, `/derp` remains
    /// unmounted so sidecar-backed deployments keep their existing route
    /// ownership.
    #[cfg(feature = "full")]
    pub native_derp: Option<Arc<derp::NativeDerpRuntime>>,
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
    /// Optional headscale-go compatible on-disk MapResponse dumps read by
    /// `/debug/mapresponses`.
    pub mapresponse_debug: Arc<MapResponseDebugStore>,
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
        self.machines
            .record_observed_map_change(MapChangeReason::PingNode, Some(node_id), None);
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
        let (pending, generation) = {
            let mut inner = self.inner.lock();
            let pending = inner.pending.remove(ping_id)?;
            let generation = remove_queued_ping_request(&mut inner, ping_id)
                .then(|| bump_ping_generation(&mut inner));
            (pending, generation)
        };
        if let Some(generation) = generation {
            let _ = self.gen_tx.send(generation);
        }
        let latency = pending.start_time.elapsed();
        let _ = pending.response_tx.send(latency);
        Some(PingCompletion {
            node_id: pending.node_id,
            latency,
        })
    }

    pub fn cancel(&self, ping_id: &str) -> bool {
        let (removed, generation) = {
            let mut inner = self.inner.lock();
            let removed_pending = inner.pending.remove(ping_id).is_some();
            let removed_queued = remove_queued_ping_request(&mut inner, ping_id);
            let generation = removed_queued.then(|| bump_ping_generation(&mut inner));
            (removed_pending || removed_queued, generation)
        };
        if let Some(generation) = generation {
            let _ = self.gen_tx.send(generation);
        }
        removed
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

fn remove_queued_ping_request(inner: &mut PingTrackerInner, ping_id: &str) -> bool {
    let mut removed = false;
    inner.outbound.retain(|_, queue| {
        let before = queue.len();
        queue.retain(|request| !ping_request_matches_id(request, ping_id));
        removed |= queue.len() != before;
        !queue.is_empty()
    });
    removed
}

fn ping_request_matches_id(request: &PingRequest, ping_id: &str) -> bool {
    request.url.split_once('?').is_some_and(|(_, query)| {
        query
            .split('&')
            .filter_map(|part| part.split_once('='))
            .any(|(key, value)| key == "id" && value == ping_id)
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteHealthProbeResult {
    pub node_id: u64,
    pub healthy: bool,
    pub latency: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RouteHealthProbeOutcome {
    Result(RouteHealthProbeResult),
    Deferred,
    Skipped,
}

#[derive(Debug)]
pub struct RouteHealthProbeHandle {
    task: tokio::task::JoinHandle<()>,
}

impl RouteHealthProbeHandle {
    pub fn abort(&self) {
        self.task.abort();
    }

    /// A detached handle, for callers that stop scheduled work together
    /// without owning the `JoinHandle`.
    pub fn abort_handle(&self) -> tokio::task::AbortHandle {
        self.task.abort_handle()
    }
}

/// Start periodic route-candidate health probes.
///
/// Candidates are online, non-expired nodes that currently advertise and
/// are approved for at least one HA subnet route. Exit routes and
/// singleton subnet routers are excluded from this probe path because
/// upstream only sends route-health pings when 2+ nodes serve the same
/// prefix.
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
    state
        .machines
        .retain_route_health_sessions(candidates.iter().copied());
    let outcomes = futures_util::future::join_all(
        candidates
            .into_iter()
            .map(|node_id| probe_route_candidate(state, node_id, probe_timeout)),
    )
    .await;

    let deferred = outcomes
        .iter()
        .any(|outcome| matches!(outcome, RouteHealthProbeOutcome::Deferred));
    let results = outcomes
        .into_iter()
        .filter_map(|outcome| match outcome {
            RouteHealthProbeOutcome::Result(result) => Some(result),
            RouteHealthProbeOutcome::Deferred | RouteHealthProbeOutcome::Skipped => None,
        })
        .collect::<Vec<_>>();

    if !deferred {
        let updates = results
            .iter()
            .map(|result| (result.node_id, result.healthy));
        state.machines.set_route_candidate_health_batch(updates);
    }

    results
}

pub(crate) fn route_health_probe_candidates(machines: &MachineRegistry) -> Vec<u64> {
    let snapshot = machines.snapshot();
    let online_states = machines.online_states();
    let now = Utc::now();
    let mut nodes_by_route: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();

    for (node_key, rec) in snapshot.iter() {
        let node_id = rec.stable_node_id_for_key(node_key);
        if rec.is_expired_at(now) || !online_states.get(&node_id).copied().unwrap_or(false) {
            continue;
        }

        for route in active_primary_routes(&rec.available_routes, &rec.approved_routes) {
            nodes_by_route.entry(route).or_default().insert(node_id);
        }
    }

    let mut candidates = BTreeSet::new();
    for node_ids in nodes_by_route.into_values() {
        if node_ids.len() > 1 {
            candidates.extend(node_ids);
        }
    }

    candidates.into_iter().collect()
}

async fn probe_route_candidate(
    state: &WireState,
    node_id: u64,
    probe_timeout: Duration,
) -> RouteHealthProbeOutcome {
    let Some(probe_generation) = state.machines.connection_generation(node_id) else {
        state.machines.forget_route_health_session(node_id);
        return RouteHealthProbeOutcome::Skipped;
    };
    if !state.machines.is_stream_connected(node_id) {
        state.machines.forget_route_health_session(node_id);
        return RouteHealthProbeOutcome::Skipped;
    }

    let stable_session = state
        .machines
        .mark_route_health_session_stable(node_id, probe_generation);
    let (ping_id, rx) = state.register_ping(node_id);
    state.dispatch_ping_request(node_id, &ping_id, false, false);

    if let Ok(Ok(latency)) = tokio::time::timeout(probe_timeout, rx).await {
        RouteHealthProbeOutcome::Result(RouteHealthProbeResult {
            node_id,
            healthy: true,
            latency: Some(latency),
        })
    } else {
        state.pings.cancel(&ping_id);

        if !state.machines.is_stream_connected(node_id) {
            state.machines.forget_route_health_session(node_id);
            return RouteHealthProbeOutcome::Skipped;
        }

        if state.machines.connection_generation(node_id) != Some(probe_generation) {
            return RouteHealthProbeOutcome::Deferred;
        }

        if !stable_session {
            return RouteHealthProbeOutcome::Deferred;
        }

        RouteHealthProbeOutcome::Result(RouteHealthProbeResult {
            node_id,
            healthy: false,
            latency: None,
        })
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

/// Network identity a pending registration is accounted against.
///
/// The key is the peer address the Noise connection resolved to (the TCP peer,
/// or the client address a trusted proxy forwarded), reduced to the part one
/// host cannot cheaply multiply: an IPv4 address is kept whole, an IPv6
/// address is reduced to its /64, because a single host is routinely handed a
/// whole /64 and could otherwise rotate through 2^64 source addresses to
/// dodge a per-address quota. IPv4-mapped IPv6 addresses count as the IPv4
/// address they carry. The port is never part of the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RegistrationSource {
    /// The connection carried no usable peer address (in-process drivers, an
    /// unparsable address). Every such request shares this one bucket, so a
    /// missing address is never a way around the quota.
    Unknown,
    V4(Ipv4Addr),
    /// The upper 64 bits of an IPv6 address.
    V6Prefix(u64),
}

impl RegistrationSource {
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::V4(v4),
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or_else(
                || {
                    let [s0, s1, s2, s3, ..] = v6.segments();
                    Self::V6Prefix(
                        (u64::from(s0) << 48)
                            | (u64::from(s1) << 32)
                            | (u64::from(s2) << 16)
                            | u64::from(s3),
                    )
                },
                Self::V4,
            ),
        }
    }

    /// Parse the textual peer address the request logger carries: `ip:port`,
    /// `[ipv6]:port`, or a bare address that may carry a `%zone`.
    pub fn from_remote_addr(text: &str) -> Option<Self> {
        let text = text.trim();
        if let Ok(addr) = text.parse::<SocketAddr>() {
            return Some(Self::from_ip(addr.ip()));
        }
        let host = text.split_once('%').map_or(text, |(host, _zone)| host);
        host.trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .ok()
            .map(Self::from_ip)
    }
}

/// Shared pending registration cache keyed by headscale-go's
/// 24-character registration ID.
///
/// Entries created by unauthenticated Register requests are also accounted
/// per [`RegistrationSource`] (see
/// [`REGISTRATION_CACHE_MAX_PENDING_PER_SOURCE`]). The per-source count is
/// derived from the map itself while the map's write guard is held, so it
/// cannot leak when an entry is consumed, completed, expired, replaced or
/// evicted, and concurrent inserts cannot race past the quota.
pub struct RegistrationCache {
    inner: RwLock<BTreeMap<String, Arc<RegistrationEntry>>>,
    last_ssh_auth: RwLock<BTreeMap<SshCheckPair, SshAuthRecord>>,
    expiration: Duration,
    cleanup: Duration,
    max_entries: usize,
    max_pending_per_source: usize,
    access_counter: AtomicU64,
}

#[derive(Debug)]
struct RegistrationEntry {
    record: Option<MachineRecord>,
    hostinfo: Option<serde_json::Value>,
    /// Who created this entry; `None` for internal callers (gRPC
    /// `debug create-node`, SSH-check requests from authenticated nodes,
    /// tests), which are exempt from per-source accounting.
    source: Option<RegistrationSource>,
    ssh_binding: Option<SshCheckBinding>,
    oidc_confirmation: Mutex<Option<crate::oidc::OidcPendingRegistrationConfirmation>>,
    expires_at: Instant,
    last_used: AtomicU64,
    outcome: Mutex<Option<RegistrationOutcome>>,
    ssh_verdict_consumed: AtomicBool,
    notify: Notify,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct SshCheckBinding {
    pub src_node_id: u64,
    pub dst_node_id: u64,
    pub local_user: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
struct SshCheckPair {
    src_node_id: u64,
    dst_node_id: u64,
}

impl SshCheckBinding {
    fn pair(&self) -> SshCheckPair {
        SshCheckPair {
            src_node_id: self.src_node_id,
            dst_node_id: self.dst_node_id,
        }
    }

    pub fn matches_pair(&self, other: &Self) -> bool {
        self.pair() == other.pair()
    }
}

#[derive(Debug, Clone)]
struct SshAuthRecord {
    at: Instant,
    policy_updated_at: Option<i64>,
    policy_stamp: Option<crate::policy::SshPolicyStamp>,
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

/// Result of waiting for a generic auth request to finish.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AuthWaitOutcome {
    Accepted,
    Rejected(String),
    Expired,
    Missing,
}

/// Type of pending auth request currently stored for an auth ID.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AuthRequestKind {
    Registration,
    SshCheck(SshCheckBinding),
}

/// The original auth entry retained by an admitted completion, as Go retains
/// its *AuthRequest across the registration lock and database work. Eviction
/// may finish its verdict first; it must never redirect completion to a newer
/// entry installed under the same auth ID.
pub(crate) struct RegistrationCompletion {
    registration_id: String,
    entry: Arc<RegistrationEntry>,
}

impl RegistrationCache {
    pub fn new() -> Self {
        Self::with_tuning_and_max_entries(
            REGISTRATION_CACHE_EXPIRATION,
            REGISTRATION_CACHE_CLEANUP,
            REGISTRATION_CACHE_MAX_ENTRIES,
        )
    }

    pub fn with_tuning(expiration: Duration, cleanup: Duration) -> Self {
        Self::with_tuning_and_max_entries(expiration, cleanup, REGISTRATION_CACHE_MAX_ENTRIES)
    }

    pub fn with_tuning_and_max_entries(
        expiration: Duration,
        cleanup: Duration,
        max_entries: usize,
    ) -> Self {
        Self {
            inner: RwLock::new(BTreeMap::new()),
            last_ssh_auth: RwLock::new(BTreeMap::new()),
            expiration,
            cleanup,
            max_entries: if max_entries == 0 {
                REGISTRATION_CACHE_MAX_ENTRIES
            } else {
                max_entries
            },
            max_pending_per_source: REGISTRATION_CACHE_MAX_PENDING_PER_SOURCE,
            access_counter: AtomicU64::new(0),
        }
    }

    #[cfg(test)]
    fn with_max_pending_per_source(mut self, quota: usize) -> Self {
        self.max_pending_per_source = quota.max(1);
        self
    }

    /// Insert a pending registration with no source: exempt from per-source
    /// accounting. For internal callers (gRPC `debug create-node`, tests).
    pub fn insert(&self, registration_id: String, record: MachineRecord) {
        self.insert_with_hostinfo(registration_id, record, None);
    }

    pub(crate) fn insert_with_hostinfo(
        &self,
        registration_id: String,
        record: MachineRecord,
        hostinfo: Option<serde_json::Value>,
    ) {
        self.insert_from_source(registration_id, record, hostinfo, None);
    }

    /// Insert a pending registration created by an unauthenticated Register
    /// request. A `Some` source is held to
    /// [`REGISTRATION_CACHE_MAX_PENDING_PER_SOURCE`] pending entries: going
    /// over drops that source's own least recently used pending entries, never
    /// another source's. `None` is exempt, exactly like [`Self::insert`].
    pub(crate) fn insert_from_source(
        &self,
        registration_id: String,
        record: MachineRecord,
        hostinfo: Option<serde_json::Value>,
        source: Option<RegistrationSource>,
    ) {
        self.prune_expired();
        let mut entry =
            RegistrationEntry::new_registration(record, self.expiration, self.next_access());
        entry.hostinfo = hostinfo;
        entry.source = source;
        self.insert_entry(registration_id, Arc::new(entry));
    }

    /// Pending (unexpired, no verdict yet) entries currently held for `source`.
    pub fn pending_from_source(&self, source: RegistrationSource) -> usize {
        self.prune_expired();
        let now = Instant::now();
        self.inner
            .read()
            .values()
            .filter(|entry| entry.source == Some(source) && entry.is_pending(now))
            .count()
    }

    pub fn insert_ssh_check(&self, auth_id: String, binding: SshCheckBinding) {
        self.prune_expired();
        let entry = Arc::new(RegistrationEntry::new_ssh_check(
            binding,
            self.expiration,
            self.next_access(),
        ));
        self.insert_entry(auth_id, entry);
    }

    pub fn get(&self, registration_id: &str) -> Option<MachineRecord> {
        self.get_entry(registration_id)
            .and_then(|entry| entry.record.clone())
    }

    pub fn get_pending_registration(&self, registration_id: &str) -> Option<MachineRecord> {
        self.pending_registration_with_hostinfo(registration_id)
            .map(|(record, _)| record)
    }

    pub(crate) fn pending_registration_with_hostinfo(
        &self,
        registration_id: &str,
    ) -> Option<(MachineRecord, Option<serde_json::Value>)> {
        let entry = self.get_entry(registration_id)?;
        if entry.outcome().is_some() {
            return None;
        }
        Some((entry.record.clone()?, entry.hostinfo.clone()))
    }

    pub(crate) fn pending_registration_completion(
        &self,
        registration_id: &str,
    ) -> Option<(
        MachineRecord,
        Option<serde_json::Value>,
        RegistrationCompletion,
    )> {
        let entry = self.get_entry(registration_id)?;
        if entry.outcome().is_some() {
            return None;
        }
        Some((
            entry.record.clone()?,
            entry.hostinfo.clone(),
            RegistrationCompletion {
                registration_id: registration_id.to_owned(),
                entry,
            },
        ))
    }

    pub(crate) fn finish_registration(
        &self,
        completion: RegistrationCompletion,
        registered: MachineRecord,
    ) {
        // FinishAuth is first-verdict-wins. A prior eviction remains expired,
        // while the already admitted mutation can still return its SQL result.
        let RegistrationCompletion {
            registration_id,
            entry,
        } = completion;
        entry.complete(registered);
        self.expire_if_current(&registration_id, &entry);
    }

    pub fn ssh_binding(&self, auth_id: &str) -> Option<SshCheckBinding> {
        self.get_entry(auth_id)
            .and_then(|entry| entry.ssh_binding.clone())
    }

    pub fn auth_request_kind(&self, auth_id: &str) -> Option<AuthRequestKind> {
        let entry = self.get_entry(auth_id)?;
        if let Some(binding) = entry.ssh_binding.clone() {
            return Some(AuthRequestKind::SshCheck(binding));
        }
        entry
            .record
            .is_some()
            .then_some(AuthRequestKind::Registration)
    }

    pub fn store_oidc_confirmation(
        &self,
        registration_id: &str,
        pending: crate::oidc::OidcPendingRegistrationConfirmation,
    ) -> bool {
        if pending.registration_id != registration_id {
            return false;
        }
        let Some(entry) = self.get_entry(registration_id) else {
            return false;
        };
        if entry.record.is_none() {
            return false;
        }
        entry.store_oidc_confirmation(pending);
        true
    }

    pub fn oidc_confirmation(
        &self,
        registration_id: &str,
    ) -> Option<crate::oidc::OidcPendingRegistrationConfirmation> {
        let entry = self.get_entry(registration_id)?;
        entry.record.as_ref()?;
        entry.oidc_confirmation()
    }

    pub fn remove_oidc_confirmation(
        &self,
        registration_id: &str,
    ) -> Option<crate::oidc::OidcPendingRegistrationConfirmation> {
        let entry = self.get_entry(registration_id)?;
        entry.remove_oidc_confirmation()
    }

    pub fn remove(&self, registration_id: &str) -> Option<MachineRecord> {
        let entry = {
            let mut inner = self.inner.write();
            match inner.get(registration_id) {
                Some(entry) if entry.record.is_some() => inner.remove(registration_id),
                _ => None,
            }
        }?;
        entry.expire();
        entry.record.clone()
    }

    pub fn complete(&self, registration_id: &str, registered: MachineRecord) -> bool {
        let entry = {
            let mut inner = self.inner.write();
            match inner.get(registration_id) {
                Some(entry) if entry.record.is_some() => inner.remove(registration_id),
                _ => None,
            }
        };
        match entry {
            Some(entry) => {
                entry.complete(registered);
                true
            }
            None => false,
        }
    }

    pub fn approve_without_node(&self, registration_id: &str) -> bool {
        let Some(entry) = self.get_entry(registration_id) else {
            return false;
        };
        entry.approve_without_node();
        true
    }

    pub fn reject(&self, registration_id: &str, reason: impl Into<String>) -> bool {
        let Some(entry) = self.get_entry(registration_id) else {
            return false;
        };
        entry.reject(reason.into());
        true
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

    pub async fn wait_for_auth(&self, auth_id: &str) -> AuthWaitOutcome {
        self.wait_for_auth_inner(auth_id, false).await
    }

    pub async fn wait_for_ssh_auth(&self, auth_id: &str) -> AuthWaitOutcome {
        self.wait_for_auth_inner(auth_id, true).await
    }

    async fn wait_for_auth_inner(
        &self,
        auth_id: &str,
        consume_ssh_verdict: bool,
    ) -> AuthWaitOutcome {
        let Some(entry) = self.get_entry(auth_id) else {
            return AuthWaitOutcome::Missing;
        };

        loop {
            let notified = entry.notify.notified();
            tokio::pin!(notified);

            let outcome = entry.outcome();
            if outcome.is_some()
                && consume_ssh_verdict
                && entry.ssh_verdict_consumed.swap(true, Ordering::AcqRel)
            {
                return AuthWaitOutcome::Missing;
            }
            match outcome {
                Some(
                    RegistrationOutcome::Registered(_) | RegistrationOutcome::ApprovedWithoutNode,
                ) => {
                    return AuthWaitOutcome::Accepted;
                }
                Some(RegistrationOutcome::Rejected(reason)) => {
                    return AuthWaitOutcome::Rejected(reason);
                }
                Some(RegistrationOutcome::Expired) => return AuthWaitOutcome::Expired,
                None => {}
            }

            let now = Instant::now();
            if now >= entry.expires_at {
                self.expire_if_current(auth_id, &entry);
                continue;
            }

            tokio::select! {
                () = &mut notified => {}
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(entry.expires_at)) => {
                    self.expire_if_current(auth_id, &entry);
                }
            }
        }
    }

    pub fn record_ssh_auth(
        &self,
        binding: &SshCheckBinding,
        now: Instant,
        policy_updated_at: Option<i64>,
    ) {
        self.last_ssh_auth.write().insert(
            binding.pair(),
            SshAuthRecord {
                at: now,
                policy_updated_at,
                policy_stamp: None,
            },
        );
    }

    pub fn last_ssh_auth(
        &self,
        binding: &SshCheckBinding,
        policy_updated_at: Option<i64>,
    ) -> Option<Instant> {
        self.last_ssh_auth
            .read()
            .get(&binding.pair())
            .filter(|record| record.policy_updated_at == policy_updated_at)
            .map(|record| record.at)
    }

    /// Seed an approval against the live policy identity rather than its
    /// persisted timestamp. Legacy timestamp helpers remain available, but
    /// do not grant an approval to the production SSH action handler.
    pub fn record_ssh_auth_for_policy(
        &self,
        binding: &SshCheckBinding,
        now: Instant,
        policy: &crate::policy::PolicyStore,
    ) {
        policy.with_ssh_auth_stamp(|stamp| self.record_ssh_auth_with_stamp(binding, now, stamp));
    }

    pub(crate) fn record_ssh_auth_with_stamp(
        &self,
        binding: &SshCheckBinding,
        now: Instant,
        stamp: crate::policy::SshPolicyStamp,
    ) {
        self.last_ssh_auth.write().insert(
            binding.pair(),
            SshAuthRecord {
                at: now,
                policy_updated_at: stamp.updated_at,
                policy_stamp: Some(stamp),
            },
        );
    }

    pub(crate) fn last_ssh_auth_with_stamp(
        &self,
        binding: &SshCheckBinding,
        stamp: &crate::policy::SshPolicyStamp,
    ) -> Option<Instant> {
        self.last_ssh_auth
            .read()
            .get(&binding.pair())
            .filter(|record| record.policy_stamp.as_ref() == Some(stamp))
            .map(|record| record.at)
    }

    pub fn clear_ssh_auth(&self) {
        self.last_ssh_auth.write().clear();
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
        self.inner.read().values().any(|entry| {
            entry
                .record
                .as_ref()
                .is_some_and(|record| record.node_key_hex == node_key_hex)
        })
    }

    pub fn expiration(&self) -> Duration {
        self.expiration
    }

    pub fn cleanup_interval(&self) -> Duration {
        self.cleanup
    }

    pub fn max_entries(&self) -> usize {
        self.max_entries
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
        let entry = self.inner.read().get(registration_id).cloned();
        if let Some(entry) = &entry {
            entry.touch(self.next_access());
        }
        entry
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

    fn insert_entry(&self, id: String, entry: Arc<RegistrationEntry>) {
        let now = Instant::now();
        // The entry being inserted is never an eviction victim.
        let keep = Arc::clone(&entry);
        let mut expired = Vec::new();
        {
            // The insert, the per-source count and every eviction below share
            // this one write guard: concurrent registrations from a source
            // serialise here and cannot both slip past the quota.
            let mut inner = self.inner.write();
            if let Some(old) = inner.insert(id, entry) {
                expired.push(old);
            }
            if let Some(source) = keep.source {
                // The quota only protects somebody when pending entries from
                // another party exist. If every pending entry shares one
                // source (typically every client behind a reverse proxy
                // without `trusted_proxies`) the bucket cannot tell the
                // attacker from the users, so trimming it at the quota would
                // make the flood easier than Go's plain LRU; fall back to the
                // global LRU there. A lone flooder that arrived first is still
                // the first victim: `eviction_victim` takes from the heaviest
                // source once anyone else holds an entry.
                if Self::other_party_pending(&inner, source, now) {
                    self.evict_over_source_quota(&mut inner, &keep, source, now, &mut expired);
                }
            }
            while inner.len() > self.max_entries {
                let Some(evict_id) = eviction_victim(&inner, &keep, now) else {
                    break;
                };
                if let Some(evicted) = inner.remove(&evict_id) {
                    expired.push(evicted);
                }
            }
        }

        for entry in expired {
            entry.expire();
        }
    }

    /// Whether any pending entry belongs to a party other than `source`:
    /// another source, or an exempt internal entry such as one created over
    /// gRPC.
    fn other_party_pending(
        inner: &BTreeMap<String, Arc<RegistrationEntry>>,
        source: RegistrationSource,
        now: Instant,
    ) -> bool {
        inner
            .values()
            .any(|entry| entry.source != Some(source) && entry.is_pending(now))
    }

    /// Drop `source`'s own least recently used pending entries until it holds
    /// at most `max_pending_per_source`, never touching `keep` (the entry just
    /// inserted) or any other source's entries.
    fn evict_over_source_quota(
        &self,
        inner: &mut BTreeMap<String, Arc<RegistrationEntry>>,
        keep: &Arc<RegistrationEntry>,
        source: RegistrationSource,
        now: Instant,
        expired: &mut Vec<Arc<RegistrationEntry>>,
    ) {
        // `held` counts `keep` too; only the other entries can be dropped.
        let mut held = 0_usize;
        let mut droppable = Vec::new();
        for (id, entry) in inner.iter() {
            if entry.source != Some(source) || !entry.is_pending(now) {
                continue;
            }
            held += 1;
            if !Arc::ptr_eq(entry, keep) {
                droppable.push((entry.last_used(), id.clone()));
            }
        }
        let excess = held.saturating_sub(self.max_pending_per_source);
        if excess == 0 {
            return;
        }
        droppable.sort_unstable();
        tracing::debug!(
            target: "tailscale_wire::registration_cache",
            ?source,
            quota = self.max_pending_per_source,
            dropped = excess,
            "per-source pending registration quota reached; dropping the source's own oldest entries"
        );
        for (_used, id) in droppable.into_iter().take(excess) {
            if let Some(evicted) = inner.remove(&id) {
                expired.push(evicted);
            }
        }
    }

    fn next_access(&self) -> u64 {
        self.access_counter.fetch_add(1, Ordering::Relaxed) + 1
    }
}

impl Default for RegistrationCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Choose what to drop when the cache is over `max_entries`, never `keep`
/// (the entry just inserted). Go's LRU drops the least recently used entry
/// whatever it is; here, in order:
///
/// 1. an entry that already has a verdict or has expired: nothing is waiting
///    on it any more (waiters hold their own `Arc`), so it is the cheapest to
///    lose;
/// 2. the least recently used entry of the source holding the most pending
///    entries (ties go to the source whose entry is oldest), provided that
///    source holds more than one: a flooding source pays for its own flood and
///    the entries other sources are waiting on survive;
/// 3. otherwise every sourced entry is alone in its bucket and the plain
///    least recently used entry goes, exactly as in Go.
fn eviction_victim(
    inner: &BTreeMap<String, Arc<RegistrationEntry>>,
    keep: &Arc<RegistrationEntry>,
    now: Instant,
) -> Option<String> {
    let candidates = || {
        inner
            .iter()
            .filter(|(_id, entry)| !Arc::ptr_eq(entry, keep))
    };

    if let Some((id, _entry)) = candidates()
        .filter(|(_id, entry)| !entry.is_pending(now))
        .min_by_key(|(_id, entry)| entry.last_used())
    {
        return Some(id.clone());
    }

    let mut per_source = BTreeMap::<RegistrationSource, usize>::new();
    for source in inner.values().filter_map(|entry| entry.source) {
        *per_source.entry(source).or_default() += 1;
    }
    let heaviest = candidates()
        .filter_map(|(id, entry)| {
            let held = *per_source.get(&entry.source?)?;
            (held > 1).then_some((held, entry.last_used(), id))
        })
        .max_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1)));
    if let Some((_held, _used, id)) = heaviest {
        return Some(id.clone());
    }

    candidates()
        .min_by_key(|(_id, entry)| entry.last_used())
        .map(|(id, _entry)| id.clone())
}

impl RegistrationEntry {
    fn new_registration(record: MachineRecord, expiration: Duration, last_used: u64) -> Self {
        Self {
            record: Some(record),
            hostinfo: None,
            source: None,
            ssh_binding: None,
            oidc_confirmation: Mutex::new(None),
            expires_at: Instant::now() + expiration,
            last_used: AtomicU64::new(last_used),
            outcome: Mutex::new(None),
            ssh_verdict_consumed: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    fn new_ssh_check(binding: SshCheckBinding, expiration: Duration, last_used: u64) -> Self {
        Self {
            record: None,
            hostinfo: None,
            source: None,
            ssh_binding: Some(binding),
            oidc_confirmation: Mutex::new(None),
            expires_at: Instant::now() + expiration,
            last_used: AtomicU64::new(last_used),
            outcome: Mutex::new(None),
            ssh_verdict_consumed: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    fn touch(&self, last_used: u64) {
        self.last_used.store(last_used, Ordering::Relaxed);
    }

    fn last_used(&self) -> u64 {
        self.last_used.load(Ordering::Relaxed)
    }

    fn outcome(&self) -> Option<RegistrationOutcome> {
        self.outcome.lock().clone()
    }

    /// Still waiting on a verdict and not yet expired: the only entries that
    /// count against a source's quota.
    fn is_pending(&self, now: Instant) -> bool {
        now < self.expires_at && self.outcome.lock().is_none()
    }

    fn store_oidc_confirmation(&self, pending: crate::oidc::OidcPendingRegistrationConfirmation) {
        *self.oidc_confirmation.lock() = Some(pending);
    }

    fn oidc_confirmation(&self) -> Option<crate::oidc::OidcPendingRegistrationConfirmation> {
        self.oidc_confirmation.lock().clone()
    }

    fn remove_oidc_confirmation(&self) -> Option<crate::oidc::OidcPendingRegistrationConfirmation> {
        self.oidc_confirmation.lock().take()
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

#[derive(Eq, PartialEq, Hash)]
enum RegistrationLockKey {
    Machine(String),
    Node(String),
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
    // PolicyStore owns data snapshots only, so this binding has no registry
    // back-reference/cycle. Public wire records and their feature graph stay
    // unchanged. One serving registry binds one policy store.
    policy_store: RwLock<Option<crate::policy::PolicyStore>>,
    native_policy_persistence: AtomicBool,
    // Go Hostinfo values retain nil slices and opt.Bool's explicit unset even
    // when the stable public HostInfo projection cannot express those shapes.
    hostinfo_snapshots: Arc<SnapshotMap<u64, hostinfo::HostInfoSnapshot>>,
    pending_self_refreshes: Mutex<BTreeSet<u64>>,
    #[cfg(feature = "admin")]
    pending_native_hostinfo: PendingNativeHostinfoMap,
    #[cfg(feature = "admin")]
    pending_native_registrations: Arc<RwLock<HashMap<u64, NativeRegistrationPublication>>>,
    #[cfg(feature = "admin")]
    native_registration_revision: AtomicU64,
    #[cfg(feature = "admin")]
    native_persistence: Arc<SnapshotMap<u64, crate::admin::machines::NativeNodePersistence>>,
    #[cfg(feature = "admin")]
    pending_native_rows: Arc<RwLock<HashMap<u64, StagedNativeRow>>>,
    #[cfg(feature = "admin")]
    native_persist_lock: Arc<tokio::sync::Mutex<()>>,
    // Weak entries serialize live registrations without retaining every
    // historical machine key. An owned guard retains the active mutex.
    registration_locks: Mutex<HashMap<RegistrationLockKey, Weak<tokio::sync::Mutex<()>>>>,
    registration_expiry_nanos: AtomicI64,
    given_name_domain: RwLock<String>,
    ip_allocator: RwLock<Option<Weak<dyn IpAllocator>>>,
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
    active_connections: Arc<RwLock<BTreeMap<u64, usize>>>,
    /// State.Connect sessions include handlers waiting through reconnect grace.
    /// Every acquired session is released exactly once; batcher removal alone
    /// does not decrement this count.
    state_sessions: Arc<RwLock<BTreeMap<u64, usize>>>,
    /// Volatile headscale-go `Node.IsOnline` equivalent. This is kept
    /// separate from persisted machine records: startup/default state
    /// is offline until a streaming map session marks the node online.
    online_states: Arc<RwLock<BTreeMap<u64, bool>>>,
    /// Go's process-local SessionEpoch, advanced only by Connect. Disconnect
    /// releases its owned session regardless of newer epochs.
    connection_generations: Arc<RwLock<BTreeMap<u64, u64>>>,
    /// Ownership identity for the current incarnation of a node's stream
    /// counters. Rekeys retain it; actual retirement replaces it.
    stream_session_epochs: Arc<RwLock<BTreeMap<u64, Arc<()>>>>,
    /// Per-active-stream cancellation flags. Headscale-go reports
    /// server-side batcher shutdown separately from client context
    /// completion in `mapresponse_ended_total`.
    stream_cancel_flags: Arc<RwLock<BTreeMap<u64, Vec<Arc<AtomicBool>>>>>,
    native_shutdown: Arc<native_shutdown::NativeShutdown>,
    /// Timestamp captured when the final stream for a node disconnects.
    /// Long-offline zero-count entries are cleaned on the upstream batcher
    /// cadence to prevent unbounded debug/runtime state growth.
    disconnected_at: Arc<RwLock<BTreeMap<u64, Instant>>>,
    /// Per-node route-health session generation observed in the
    /// previous probe cycle. A timeout on a fresh or replaced session
    /// is deferred to match headscale-go's HA prober.
    route_health_stable_sessions: RwLock<BTreeMap<u64, u64>>,
    /// Bounded canonical map-change reasons. This gives the Rust
    /// runtime an owned counterpart to headscale-go's change reason
    /// layer without exposing free-form labels through Prometheus.
    map_changes: RwLock<VecDeque<MapChange>>,
    /// Per-node pending map changes awaiting a batch tick. This mirrors
    /// headscale-go's mapper batcher add-to-batch semantics before stream
    /// delivery is switched over to tick-drained batches.
    pending_map_changes: RwLock<BTreeMap<u64, Vec<MapChange>>>,
    /// Last tick-drained map-change batch. Streaming map responses consume
    /// this watch channel when the batch task is enabled.
    map_batch_tx: Arc<watch::Sender<MapChangeBatch>>,
    /// Ordered tick-drained batches for active map streams. The watch channel
    /// above exposes the latest snapshot for tests/debugging; streams need the
    /// per-session queue semantics of headscale-go's buffered map channel.
    map_batch_event_tx: Arc<broadcast::Sender<MapChangeBatch>>,
    /// Whether the headscale-go-style batch tick task is active for
    /// this registry. Streams use this to prefer delayed batch delivery
    /// while preserving immediate generation wakes for embedders/tests
    /// that have not spawned the task.
    map_batcher_enabled: AtomicBool,
    /// Upstream-shaped ephemeral-node lifecycle manager. When
    /// configured by production startup it cancels per-node deletion
    /// timers on stream connect and schedules them after disconnect.
    ephemeral_gc: RwLock<Option<Arc<EphemeralNodeGc>>>,
    /// Disconnect persistence does not depend on enabling ephemeral timers.
    /// Keep a weak edge because native stores can own this same registry.
    registration_store: RwLock<Option<Weak<dyn MachineRegistrationStore>>>,
    /// Optional headscale-go-style write worker for NodeStore put paths.
    nodestore_write_queue: RwLock<Option<NodeStoreWriteQueue>>,
    nodestore_write_queue_next_id: AtomicU64,
    /// Prometheus-compatible counters for the Tailscale wire surface.
    metrics: WireMetrics,
}

type GoHttpRequestLabels = (String, String, String, String, String);

/// Staged native hostinfo keyed by node id: `(revision, node key, snapshot)`.
#[cfg(feature = "admin")]
type PendingNativeHostinfoMap =
    Arc<RwLock<HashMap<u64, (u64, String, hostinfo::HostInfoSnapshot)>>>;

#[derive(Default)]
struct WireMetrics {
    mapresponse_endpoint_updates: RwLock<BTreeMap<String, u64>>,
    mapresponse_ended: RwLock<BTreeMap<String, u64>>,
    mapresponse_generated: RwLock<BTreeMap<String, u64>>,
    mapresponse_sent: RwLock<BTreeMap<(String, String), u64>>,
    mapresponse_last_sent: RwLock<BTreeMap<(String, String), f64>>,
    http_requests: RwLock<BTreeMap<(String, String, String), u64>>,
    http_duration: RwLock<BTreeMap<String, HistogramMetric>>,
    /// go-chi/metrics labels from the pinned v0.29.5 control router.
    http_requests_go: RwLock<BTreeMap<GoHttpRequestLabels, u64>>,
    http_duration_go: RwLock<BTreeMap<(String, String), HistogramMetric>>,
    nodestore_operations: RwLock<BTreeMap<String, u64>>,
    nodestore_operation_duration: RwLock<BTreeMap<String, HistogramMetric>>,
    nodestore_batch_size: RwLock<HistogramMetric>,
    nodestore_batch_duration: RwLock<HistogramMetric>,
    nodestore_snapshot_build_duration: RwLock<HistogramMetric>,
    nodestore_peers_calculation_duration: RwLock<HistogramMetric>,
    nodestore_queue_depth: AtomicUsize,
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

pub(crate) const HTTP_GO_BUCKETS: &[(f64, &str)] = &[
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
    (25.0, "25"),
    (50.0, "50"),
    (100.0, "100"),
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
        let (map_batch_tx, _map_batch_rx) =
            watch::channel(Arc::new(BTreeMap::<u64, Vec<MapChange>>::new()));
        let (map_batch_event_tx, _map_batch_event_rx) = broadcast::channel(MAP_BATCH_EVENT_BUFFER);
        Self {
            policy_store: RwLock::new(None),
            native_policy_persistence: AtomicBool::new(false),
            hostinfo_snapshots: Arc::new(SnapshotMap::default()),
            pending_self_refreshes: Mutex::new(BTreeSet::new()),
            #[cfg(feature = "admin")]
            pending_native_hostinfo: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "admin")]
            pending_native_registrations: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "admin")]
            native_registration_revision: AtomicU64::new(0),
            #[cfg(feature = "admin")]
            native_persistence: Arc::new(SnapshotMap::default()),
            #[cfg(feature = "admin")]
            pending_native_rows: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "admin")]
            native_persist_lock: Arc::new(tokio::sync::Mutex::new(())),
            registration_locks: Mutex::new(HashMap::new()),
            registration_expiry_nanos: AtomicI64::new(0),
            given_name_domain: RwLock::new(String::new()),
            ip_allocator: RwLock::new(None),
            inner: RwLock::default(),
            notify: Arc::new(Notify::new()),
            gen_tx: Arc::new(gen_tx),
            primary_routes: RwLock::new(PrimaryRouteState::new()),
            active_connections: Arc::new(RwLock::new(BTreeMap::new())),
            state_sessions: Arc::new(RwLock::new(BTreeMap::new())),
            online_states: Arc::new(RwLock::new(BTreeMap::new())),
            connection_generations: Arc::new(RwLock::new(BTreeMap::new())),
            stream_session_epochs: Arc::new(RwLock::new(BTreeMap::new())),
            stream_cancel_flags: Arc::new(RwLock::new(BTreeMap::new())),
            native_shutdown: Arc::new(native_shutdown::NativeShutdown::default()),
            disconnected_at: Arc::new(RwLock::new(BTreeMap::new())),
            route_health_stable_sessions: RwLock::new(BTreeMap::new()),
            map_changes: RwLock::new(VecDeque::new()),
            pending_map_changes: RwLock::new(BTreeMap::new()),
            map_batch_tx: Arc::new(map_batch_tx),
            map_batch_event_tx: Arc::new(map_batch_event_tx),
            map_batcher_enabled: AtomicBool::new(false),
            ephemeral_gc: RwLock::new(None),
            registration_store: RwLock::new(None),
            nodestore_write_queue: RwLock::new(None),
            nodestore_write_queue_next_id: AtomicU64::new(1),
            metrics: WireMetrics::default(),
        }
    }
}

#[derive(Clone)]
struct NodeStoreWriteQueue {
    id: u64,
    tx: std_mpsc::Sender<NodeStoreWriteWork>,
}

type NodeStoreBoolUpdateFn =
    Box<dyn FnOnce(&mut HashMap<String, MachineRecord>) -> NodeStoreBoolUpdateOutcome + Send>;
type NodeStoreManyUpdateFn =
    Box<dyn FnOnce(&mut HashMap<String, MachineRecord>) -> NodeStoreManyUpdateOutcome + Send>;

#[derive(Debug)]
struct NodeStoreBoolUpdateOutcome {
    applied: bool,
    publish_snapshot: bool,
    change: Option<PendingMapChange>,
    clear_unhealthy_route_state: Option<u64>,
    final_presence_node_id: Option<u64>,
}

impl NodeStoreBoolUpdateOutcome {
    fn unchanged(applied: bool) -> Self {
        Self {
            applied,
            publish_snapshot: false,
            change: None,
            clear_unhealthy_route_state: None,
            final_presence_node_id: None,
        }
    }

    fn quiet(applied: bool) -> Self {
        Self {
            applied,
            publish_snapshot: applied,
            change: None,
            clear_unhealthy_route_state: None,
            final_presence_node_id: None,
        }
    }

    fn mark_absent_after_batch(&mut self) {
        self.applied = false;
        self.publish_snapshot = false;
        self.change = None;
        self.clear_unhealthy_route_state = None;
    }
}

#[derive(Debug)]
struct NodeStoreManyUpdateOutcome {
    applied: usize,
    publish_snapshot: bool,
    change: Option<PendingMapChange>,
    clear_unhealthy_route_states: Vec<u64>,
    missing_node_keys: Vec<String>,
    affected_node_keys: Vec<String>,
    affected_node_ids: Vec<u64>,
    final_presence_node_ids: Vec<u64>,
}

impl NodeStoreManyUpdateOutcome {
    fn unchanged() -> Self {
        Self {
            applied: 0,
            publish_snapshot: false,
            change: None,
            clear_unhealthy_route_states: Vec::new(),
            missing_node_keys: Vec::new(),
            affected_node_keys: Vec::new(),
            affected_node_ids: Vec::new(),
            final_presence_node_ids: Vec::new(),
        }
    }

    fn revalidate_final_presence_after_batch(
        &mut self,
        final_snapshot: &HashMap<String, MachineRecord>,
    ) {
        if self.final_presence_node_ids.is_empty() {
            return;
        }

        let present = self
            .final_presence_node_ids
            .iter()
            .copied()
            .filter(|node_id| {
                final_snapshot
                    .iter()
                    .any(|(node_key, rec)| rec.stable_node_id_for_key(node_key) == *node_id)
            })
            .collect::<BTreeSet<_>>();
        if present.is_empty() {
            self.mark_absent_after_batch();
            return;
        }

        self.applied = self.applied.min(present.len());
        self.clear_unhealthy_route_states
            .retain(|node_id| present.contains(node_id));
        self.final_presence_node_ids
            .retain(|node_id| present.contains(node_id));
    }

    fn mark_absent_after_batch(&mut self) {
        self.applied = 0;
        self.publish_snapshot = false;
        self.change = None;
        self.clear_unhealthy_route_states.clear();
    }
}

/// The identity and addresses accepted by a NodeStore deletion. Address release
/// belongs to the caller's state phase, after native persistence is unlocked.
#[derive(Clone, Copy)]
pub(crate) struct RemovedNode {
    pub(crate) id: u64,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
}

impl RemovedNode {
    fn from_record(key: &str, record: &MachineRecord) -> Self {
        Self {
            id: record.stable_node_id_for_key(key),
            ipv4: record.ipv4,
            ipv6: record.ipv6,
        }
    }
}

enum NodeStoreWriteWork {
    Upsert {
        node_key_hex: String,
        rec: Box<MachineRecord>,
        result_tx: std_mpsc::Sender<bool>,
    },
    Delete {
        node_key_hex: String,
        result_tx: std_mpsc::Sender<Option<RemovedNode>>,
    },
    UpdateBool {
        operation: &'static str,
        update: NodeStoreBoolUpdateFn,
        result_tx: std_mpsc::Sender<NodeStoreBoolUpdateOutcome>,
    },
    UpdateMany {
        operation: &'static str,
        update: NodeStoreManyUpdateFn,
        result_tx: std_mpsc::Sender<NodeStoreManyUpdateOutcome>,
    },
    Rekey {
        old_node_key_hex: String,
        new_node_key_hex: String,
        rec: Box<MachineRecord>,
        changes: Vec<PendingMapChange>,
        final_presence_node_id: Option<u64>,
        result_tx: std_mpsc::Sender<()>,
    },
}

enum NodeStoreWriteCompletion {
    Bool {
        operation: &'static str,
        result_tx: std_mpsc::Sender<bool>,
        result: bool,
    },
    Delete {
        operation: &'static str,
        result_tx: std_mpsc::Sender<Option<RemovedNode>>,
        removed: Option<RemovedNode>,
    },
    UpdateBool {
        operation: &'static str,
        result_tx: std_mpsc::Sender<NodeStoreBoolUpdateOutcome>,
        outcome: NodeStoreBoolUpdateOutcome,
    },
    UpdateMany {
        operation: &'static str,
        result_tx: std_mpsc::Sender<NodeStoreManyUpdateOutcome>,
        outcome: NodeStoreManyUpdateOutcome,
    },
    Unit {
        operation: &'static str,
        result_tx: std_mpsc::Sender<()>,
        changes: Vec<PendingMapChange>,
        final_presence_node_id: Option<u64>,
    },
}

/// Owns the optional NodeStore write worker installed on a [`MachineRegistry`].
///
/// Dropping the handle removes the registry sender, closes this handle's sender,
/// and joins the worker after any caller-owned sender clones finish. This keeps
/// test and production shutdown deterministic without making readers block.
pub struct NodeStoreWriteBatcherHandle {
    id: u64,
    machines: Weak<MachineRegistry>,
    tx: Option<std_mpsc::Sender<NodeStoreWriteWork>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Drop for NodeStoreWriteBatcherHandle {
    fn drop(&mut self) {
        if let Some(machines) = self.machines.upgrade() {
            let mut queue = machines.nodestore_write_queue.write();
            if queue.as_ref().is_some_and(|current| current.id == self.id) {
                queue.take();
            }
        }
        self.tx.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run_nodestore_write_worker(
    machines: &Arc<MachineRegistry>,
    rx: &std_mpsc::Receiver<NodeStoreWriteWork>,
    batch_size: usize,
    batch_timeout: Duration,
) {
    let batch_size = batch_size.max(1);
    let batch_timeout = batch_timeout.max(Duration::from_millis(1));

    while let Ok(first) = rx.recv() {
        let mut batch = Vec::with_capacity(batch_size);
        batch.push(first);
        while batch.len() < batch_size {
            match rx.recv_timeout(batch_timeout) {
                Ok(work) => batch.push(work),
                Err(
                    std_mpsc::RecvTimeoutError::Timeout | std_mpsc::RecvTimeoutError::Disconnected,
                ) => break,
            }
        }
        machines.apply_nodestore_write_batch(batch);
    }
}

#[cfg(feature = "admin")]
struct StagedNativeRow {
    revision: u64,
    record: MachineRecord,
    native: crate::admin::machines::NativeNodePersistence,
}

#[cfg(feature = "admin")]
#[derive(Clone)]
pub(crate) struct NativeRegistrationUpdate {
    pub(crate) before: MachineRecord,
    pub(crate) after: MachineRecord,
    pub(crate) hostinfo_before: hostinfo::HostInfoSnapshot,
    pub(crate) hostinfo_after: hostinfo::HostInfoSnapshot,
    pub(crate) native_before: Option<crate::admin::machines::NativeNodePersistence>,
}

#[cfg(feature = "admin")]
#[derive(Clone)]
enum NativeRegistrationPublication {
    Updated {
        revision: u64,
        update: Box<NativeRegistrationUpdate>,
    },
    Created {
        revision: u64,
        record: Box<MachineRecord>,
    },
}

#[cfg(feature = "admin")]
impl NativeRegistrationPublication {
    fn after(&self) -> &MachineRecord {
        match self {
            Self::Updated { update, .. } => &update.after,
            Self::Created { record, .. } => record.as_ref(),
        }
    }

    fn before(&self) -> Option<&MachineRecord> {
        match self {
            Self::Updated { update, .. } => Some(&update.before),
            Self::Created { .. } => None,
        }
    }

    fn revision(&self) -> u64 {
        match self {
            Self::Updated { revision, .. } | Self::Created { revision, .. } => *revision,
        }
    }
}

/// Owns private publication bookkeeping through a registration completion.
/// Declare after the machine/node-key guards so cleanup runs before unlocking.
/// It neither reverts live/durable nodes nor sends a successful change on error.
#[cfg(feature = "admin")]
pub(crate) struct RegistrationPublicationScope {
    registry: Weak<MachineRegistry>,
    machine_key: String,
    node_key: String,
    revision: u64,
}

#[cfg(feature = "admin")]
fn registration_revision_after(value: u64, before: u64) -> bool {
    let distance = value.wrapping_sub(before);
    distance != 0 && distance < (1u64 << 63)
}

#[cfg(feature = "admin")]
impl Drop for RegistrationPublicationScope {
    fn drop(&mut self) {
        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        registry
            .pending_native_registrations
            .write()
            .retain(|_, pending| {
                let record = pending.after();
                !(record.machine_key_hex == self.machine_key
                    && record.node_key_hex == self.node_key
                    && registration_revision_after(pending.revision(), self.revision))
            });
        registry.pending_native_rows.write().retain(|_, staged| {
            !(staged.record.machine_key_hex == self.machine_key
                && staged.record.node_key_hex == self.node_key
                && registration_revision_after(staged.revision, self.revision))
        });
        // Pending Hostinfo has not yet become a live snapshot. Node-key guards
        // serialize its producer and consumer for this completion too.
        registry
            .pending_native_hostinfo
            .write()
            .retain(|_, (revision, key, _)| {
                !(key == &self.node_key && registration_revision_after(*revision, self.revision))
            });
    }
}

impl MachineRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(feature = "admin")]
    pub(crate) fn require_native_policy_persistence(&self) {
        self.native_policy_persistence
            .store(true, Ordering::Release);
    }

    pub(crate) fn policy_routes_require_persistence(&self) -> bool {
        self.native_policy_persistence.load(Ordering::Acquire)
    }

    /// Bind policy-manager input tracking after initial node hydration. Reusing
    /// the same store (for another listener/router) does not reset its snapshot.
    pub fn configure_policy(self: &Arc<Self>, policy: &crate::policy::PolicyStore) {
        if let Err(error) = self.try_configure_policy(policy) {
            tracing::error!(%error, "initializing policy manager nodes");
        }
    }

    /// Bind policy and propagate initial resolution failure to startup.
    pub fn try_configure_policy(
        self: &Arc<Self>,
        policy: &crate::policy::PolicyStore,
    ) -> Result<(), String> {
        let mut bound = self.policy_store.write();
        if bound
            .as_ref()
            .is_some_and(|current| current.same_store(policy))
        {
            return policy.compilation_result();
        }
        *bound = Some(policy.clone());
        drop(bound);
        policy.bind_registry(Arc::downgrade(self));
        policy.initialize_node_inputs(self.policy_node_inputs())
    }

    /// Legacy single-record lookups retain the public record model. Internal
    /// response/policy builders keep their MachineSnapshot for the whole read.
    #[cfg(feature = "admin")]
    #[allow(clippy::option_option)] // tri-state: unset / explicit nil Go association / loaded user
    pub(crate) fn cached_native_user(
        &self,
        record: &MachineRecord,
    ) -> Option<Option<crate::admin::users::UserRecord>> {
        self.snapshot_with_metadata().cached_native_user(record)
    }

    pub(crate) fn policy_node_inputs(&self) -> Vec<crate::policy::lifecycle::NodeInput> {
        let snapshot = self.snapshot_with_metadata();
        let mut nodes = snapshot
            .iter()
            .map(|(key, record)| {
                let id = record.stable_node_id_for_key(key);
                let input = crate::policy::lifecycle::NodeInput::from_record(id, record);
                #[cfg(feature = "admin")]
                let input = if let Some(native) = snapshot.native.get(&id) {
                    let mut input = input;
                    (input.owner_id, input.addrs) = native.policy_owner_and_addresses(record);
                    if let Some(user) = native.user_association(record) {
                        input.set_native_association(user.map(|user| user.id));
                    }
                    input
                } else {
                    input
                };
                input
            })
            .collect::<Vec<_>>();
        nodes.sort_by_key(|node| node.id);
        nodes
    }

    /// Called at Go's policy refresh boundaries, after successful persistence.
    /// Failed quiet writes leave the earlier policy inputs intact for retries.
    pub(crate) fn refresh_policy_node_inputs(&self) -> Option<bool> {
        self.try_refresh_policy_node_inputs()
            .unwrap_or_else(|error| {
                tracing::error!(%error, "updating policy manager nodes");
                Some(false)
            })
    }

    pub(crate) fn try_refresh_policy_node_inputs(&self) -> Result<Option<bool>, String> {
        let Some(policy) = self.policy_store.read().clone() else {
            return Ok(None);
        };
        policy
            .try_replace_node_inputs(self.policy_node_inputs())
            .map(Some)
    }

    /// Refresh the bound policy manager after a trusted raw registry update.
    /// Returns whether policy inputs changed; the embedding caller owns the
    /// subsequent policy notification. Serving adapters do this themselves.
    pub fn refresh_policy_nodes(&self) -> bool {
        self.refresh_policy_node_inputs().unwrap_or(false)
    }

    /// Fallible raw-update refresh. On error SetNodes retains the new inputs
    /// and the successful phases preceding the rejected nodeAttrs compilation.
    pub fn try_refresh_policy_nodes(&self) -> Result<bool, String> {
        self.try_refresh_policy_node_inputs()
            .map(|changed| changed.unwrap_or(false))
    }

    #[cfg(feature = "admin")]
    pub(crate) fn registration_publication_scope(
        self: &Arc<Self>,
        record: &MachineRecord,
    ) -> RegistrationPublicationScope {
        RegistrationPublicationScope {
            registry: Arc::downgrade(self),
            machine_key: record.machine_key_hex.clone(),
            node_key: record.node_key_hex.clone(),
            revision: self.native_registration_revision.load(Ordering::SeqCst),
        }
    }

    /// Go creates the ID in SQL, then PutNode resolves the original GivenName
    /// against all earlier writer operations. The bumped name is initially
    /// live-only; a later cached save persists it.
    #[cfg(feature = "admin")]
    pub(crate) fn put_new_native_registration(
        &self,
        mut record: MachineRecord,
        hostinfo: serde_json::Value,
        native: crate::admin::machines::NativeNodePersistence,
    ) -> Result<MachineRecord, String> {
        let id = record
            .node_id
            .filter(|id| *id > 0)
            .ok_or("invalid new node identity")?;
        let result = Arc::new(Mutex::new(None));
        let completed = result.clone();
        let pending = self.pending_native_registrations.clone();
        let revision = self
            .native_registration_revision
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1);
        let hostinfos = self.hostinfo_snapshots.clone();
        let natives = self.native_persistence.clone();
        let pending_hostinfos = self.pending_native_hostinfo.clone();
        let outcome = self.apply_nodestore_bool_update(
            "put",
            Box::new(move |records| {
                if let Some(existing) = records.get(&record.node_key_hex)
                    && existing.stable_node_id() != id
                {
                    *completed.lock() = Some(Err("node key already exists".into()));
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                }
                let base = if record.hostname.is_empty() {
                    "node"
                } else {
                    &record.hostname
                };
                let taken = records
                    .iter()
                    .filter(|(key, node)| node.stable_node_id_for_key(key) != id)
                    .map(|(_, node)| node.hostname.as_str())
                    .collect::<std::collections::HashSet<_>>();
                let mut name = base.to_owned();
                for suffix in 1.. {
                    if !taken.contains(name.as_str()) {
                        break;
                    }
                    name = format!("{base}-{suffix}");
                }
                drop(taken);
                record.hostname = name;
                records.retain(|key, node| node.stable_node_id_for_key(key) != id);
                records.insert(record.node_key_hex.clone(), record.clone());
                hostinfos.write().insert(
                    id,
                    hostinfo::HostInfoSnapshot {
                        projection: record.host_info_for_node(),
                        value: hostinfo,
                    },
                );
                natives.write().insert(id, native);
                pending_hostinfos.write().remove(&id);
                pending.write().insert(
                    id,
                    NativeRegistrationPublication::Created {
                        revision,
                        record: Box::new(record.clone()),
                    },
                );
                *completed.lock() = Some(Ok(record));
                NodeStoreBoolUpdateOutcome {
                    final_presence_node_id: Some(id),
                    ..NodeStoreBoolUpdateOutcome::quiet(true)
                }
            }),
        );
        let result = result.lock().take();
        if !outcome.applied {
            return result.unwrap_or_else(|| Err("node changed during new registration".into()));
        }
        result.unwrap_or_else(|| Err("node changed during new registration".into()))
    }

    /// Existing-node auth mutates NodeStore quietly before its SQL write. The
    /// caller owns the machine/node-key guards and native persistence mutex.
    #[cfg(feature = "admin")]
    pub(crate) fn begin_native_registration(
        &self,
        id: u64,
        prepare: impl FnOnce(
            &MachineRecord,
            Option<&crate::admin::machines::NativeNodePersistence>,
        ) -> Result<
            crate::admin::machines::PreparedNativeRegistration,
            crate::admin::machines::MachineAdminError,
        > + Send
        + 'static,
    ) -> Result<
        (
            NativeRegistrationUpdate,
            headscale_db::headscale_nodes::CachedNodeRegistration,
        ),
        crate::admin::machines::MachineAdminError,
    > {
        use crate::admin::machines::MachineAdminError;
        let completed = Arc::new(Mutex::new(None));
        let result = completed.clone();
        let hostinfos = self.hostinfo_snapshots.clone();
        let natives = self.native_persistence.clone();
        let pending_hostinfos = self.pending_native_hostinfo.clone();
        let outcome = self.apply_nodestore_bool_update(
            "update",
            Box::new(move |records| {
                let mut matches = records
                    .iter()
                    .filter(|(key, record)| record.stable_node_id_for_key(key) == id);
                let Some((old_key, before)) = matches.next() else {
                    *result.lock() = Some(Err(MachineAdminError::BadRequest(
                        "node no longer exists in NodeStore".into(),
                    )));
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                };
                if matches.next().is_some() {
                    *result.lock() = Some(Err(MachineAdminError::BadRequest(
                        "ambiguous node identity".into(),
                    )));
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                }
                let before = before.clone();
                let old_key = old_key.clone();
                let before_projection = before.host_info_for_node();
                let previous_value = match hostinfos.read().get(&id).map_or_else(
                    || serde_json::to_value(&before_projection),
                    |snapshot| snapshot.value_for(&before_projection),
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        *result.lock() = Some(Err(MachineAdminError::Storage(error.to_string())));
                        return NodeStoreBoolUpdateOutcome::unchanged(false);
                    }
                };
                let hostinfo_before = hostinfo::HostInfoSnapshot {
                    projection: before_projection,
                    value: previous_value,
                };
                let mut native_before = natives.read().get(&id).cloned();
                if let Some(native) = &mut native_before {
                    native.replace_hostinfo_snapshot(hostinfo_before.clone());
                }
                let prepared = match prepare(&before, native_before.as_ref()) {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        *result.lock() = Some(Err(error));
                        return NodeStoreBoolUpdateOutcome::unchanged(false);
                    }
                };
                let mut proposed = prepared.record;
                if proposed.machine_key_hex != before.machine_key_hex {
                    *result.lock() = Some(Err(MachineAdminError::BadRequest(
                        "ambiguous node identity".into(),
                    )));
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                }
                if let Some(other) = records.get(&proposed.node_key_hex)
                    && other.stable_node_id_for_key(&proposed.node_key_hex) != id
                {
                    *result.lock() = Some(Err(MachineAdminError::BadRequest(
                        "node key already exists".into(),
                    )));
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                }
                proposed.node_id = Some(id);
                proposed.hostname.clone_from(&before.hostname);
                let update = NativeRegistrationUpdate {
                    hostinfo_before,
                    hostinfo_after: prepared.native.hostinfo_snapshot(),
                    native_before,
                    before,
                    after: proposed.clone(),
                };
                records.remove(&old_key);
                records.insert(proposed.node_key_hex.clone(), proposed);
                hostinfos.write().insert(id, update.hostinfo_after.clone());
                natives.write().insert(id, prepared.native);
                pending_hostinfos.write().remove(&id);
                *result.lock() = Some(Ok((update, prepared.registration)));
                NodeStoreBoolUpdateOutcome {
                    final_presence_node_id: Some(id),
                    ..NodeStoreBoolUpdateOutcome::quiet(true)
                }
            }),
        );
        let result = completed.lock().take();
        if !outcome.applied {
            return result.unwrap_or_else(|| {
                Err(MachineAdminError::BadRequest(
                    "node changed during registration".into(),
                ))
            });
        }
        result.unwrap_or_else(|| {
            Err(MachineAdminError::BadRequest(
                "node changed during registration".into(),
            ))
        })
    }

    #[cfg(feature = "admin")]
    pub(crate) fn rollback_native_registration(
        &self,
        update: &NativeRegistrationUpdate,
    ) -> Result<(), String> {
        let update = update.clone();
        let id = update.before.stable_node_id();
        let hostinfos = self.hostinfo_snapshots.clone();
        let natives = self.native_persistence.clone();
        let pending_hostinfos = self.pending_native_hostinfo.clone();
        let outcome = self.apply_nodestore_bool_update(
            "put",
            Box::new(move |records| {
                let current = records.get(&update.after.node_key_hex);
                if !current.is_some_and(|record| {
                    record.stable_node_id() == id
                        && record.machine_key_hex == update.after.machine_key_hex
                }) || records
                    .get(&update.before.node_key_hex)
                    .is_some_and(|record| record.stable_node_id() != id)
                {
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                }
                records.remove(&update.after.node_key_hex);
                records.insert(update.before.node_key_hex.clone(), update.before);
                hostinfos.write().insert(id, update.hostinfo_before);
                pending_hostinfos.write().remove(&id);
                let mut native = natives.write();
                if let Some(before) = update.native_before {
                    native.insert(id, before);
                } else {
                    native.remove(&id);
                }
                NodeStoreBoolUpdateOutcome {
                    final_presence_node_id: Some(id),
                    ..NodeStoreBoolUpdateOutcome::quiet(true)
                }
            }),
        );
        if outcome.applied {
            Ok(())
        } else {
            Err("node changed before registration rollback".into())
        }
    }

    #[cfg(feature = "admin")]
    pub(crate) fn defer_native_registration_publication(&self, update: NativeRegistrationUpdate) {
        let revision = self
            .native_registration_revision
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1);
        self.pending_native_registrations.write().insert(
            update.after.stable_node_id(),
            NativeRegistrationPublication::Updated {
                revision,
                update: Box::new(update),
            },
        );
    }

    #[cfg(feature = "admin")]
    pub(crate) fn native_registration_record(&self, id: u64) -> Option<MachineRecord> {
        let pending = self.pending_native_registrations.read().get(&id)?.clone();
        self.get(&pending.after().node_key_hex)
            .filter(|record| record.stable_node_id() == id)
    }

    #[cfg(feature = "admin")]
    fn finish_native_registration_publication(
        &self,
        proposed: &MachineRecord,
    ) -> Result<bool, String> {
        let id = proposed.stable_node_id();
        let mut pending = self.pending_native_registrations.write();
        let Some(update) = pending.get(&id) else {
            return Ok(false);
        };
        if update.after().node_key_hex != proposed.node_key_hex {
            return Ok(false);
        }
        let update = pending.remove(&id).expect("pending registration exists");
        drop(pending);
        // CLI/OIDC may hydrate canonical account fields after the native save.
        // Merge that metadata without reapplying SQL/client snapshots.
        let metadata = proposed.clone();
        self.apply_nodestore_bool_update(
            "update",
            Box::new(move |records| {
                let Some(current) = records.get_mut(&metadata.node_key_hex) else {
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                };
                if current.stable_node_id() != id
                    || current.user_id != metadata.user_id
                    || current.user != metadata.user
                {
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                }
                let changed = current.user_display_name != metadata.user_display_name
                    || current.user_profile_pic_url != metadata.user_profile_pic_url
                    || current.user_provider != metadata.user_provider
                    || current.user_created_at != metadata.user_created_at;
                current.user_display_name = metadata.user_display_name;
                current.user_profile_pic_url = metadata.user_profile_pic_url;
                current.user_provider = metadata.user_provider;
                current.user_created_at = metadata.user_created_at;
                NodeStoreBoolUpdateOutcome::quiet(changed)
            }),
        );
        let Some(current) = self
            .get(&update.after().node_key_hex)
            .filter(|record| record.stable_node_id() == id)
        else {
            return Ok(true);
        };
        let mut changes = Self::auth_completion_pending_changes_with_policy(
            update.before(),
            &current,
            id,
            self.try_refresh_policy_node_inputs()?,
        );
        let current_hostinfo = self
            .map_hostinfo_value(&current)
            .expect("HostInfo serializes primitive JSON fields");
        if changes
            .first()
            .is_some_and(|change| change.reason == MapChangeReason::NodeKeyRotated)
            && let NativeRegistrationPublication::Updated { update: prior, .. } = &update
            && !headscale_api_acl::go_tailcfg_json::peer_hostinfo_equal(
                &prior.hostinfo_before.value,
                &current_hostinfo,
            )
        {
            changes[0] = PendingMapChange::origin(MapChangeReason::NodeAdded, id);
        }
        if let Some(before) = update.before()
            && before.node_key_hex != current.node_key_hex
            && let Some(gc) = self.ephemeral_gc()
        {
            gc.cancel(&before.node_key_hex);
        }
        self.wake_waiters_with_many(changes);
        Ok(true)
    }

    #[cfg(feature = "admin")]
    pub(crate) async fn lock_native_persistence(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.native_persist_lock.clone().lock_owned().await
    }

    /// SQL row conversion stages metadata until the matching wire record is
    /// actually published. A read-only projection cannot replace live pointers.
    #[cfg(feature = "admin")]
    pub(crate) fn stage_native_row(
        &self,
        record: MachineRecord,
        native: crate::admin::machines::NativeNodePersistence,
    ) {
        let revision = self
            .native_registration_revision
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1);
        self.pending_native_rows.write().insert(
            record.stable_node_id(),
            StagedNativeRow {
                revision,
                record,
                native,
            },
        );
    }

    /// Invoke only from a NodeStore writer, before publishing its record map.
    /// Exact record comparison prevents a staged projection from attaching to
    /// a different concurrent record for the same ID/key.
    #[cfg(feature = "admin")]
    fn native_row_installer(&self) -> impl Fn(&MachineRecord) + Send + 'static {
        let pending = self.pending_native_rows.clone();
        let native = self.native_persistence.clone();
        let hostinfo = self.hostinfo_snapshots.clone();
        let pending_hostinfo = self.pending_native_hostinfo.clone();
        move |record| {
            let id = record.stable_node_id();
            let staged = {
                let mut pending = pending.write();
                if !pending
                    .get(&id)
                    .is_some_and(|staged| &staged.record == record)
                {
                    return;
                }
                pending.remove(&id).map(|staged| staged.native)
            };
            if let Some(staged) = staged {
                pending_hostinfo.write().remove(&id);
                hostinfo.write().insert(id, staged.hostinfo_snapshot());
                native.write().insert(id, staged);
            }
        }
    }

    #[cfg(feature = "admin")]
    pub(crate) fn remember_native_persistence(
        &self,
        id: u64,
        captured: &MachineSnapshot,
        value: crate::admin::machines::NativeNodePersistence,
    ) {
        let records = self.inner.write();
        if !Arc::ptr_eq(&records, &captured.records)
            || !Arc::ptr_eq(&self.hostinfo_snapshots.read(), &captured.hostinfo)
            || !Arc::ptr_eq(&self.native_persistence.read(), &captured.native)
        {
            // A completed SQL save must not replace metadata from a newer
            // live record or a same-projection raw/association update.
            return;
        }
        self.pending_native_hostinfo.write().remove(&id);
        self.hostinfo_snapshots
            .write()
            .insert(id, value.hostinfo_snapshot());
        self.native_persistence.write().insert(id, value);
    }

    #[cfg(feature = "admin")]
    pub(crate) fn take_native_registration_hostinfo(
        &self,
        id: u64,
        record: &MachineRecord,
    ) -> Option<hostinfo::HostInfoSnapshot> {
        let mut pending = self.pending_native_hostinfo.write();
        let (_, key, snapshot) = pending.get(&id)?;
        if key != &record.node_key_hex || snapshot.projection != record.host_info_for_node() {
            return None;
        }
        pending.remove(&id).map(|(_, _, snapshot)| snapshot)
    }

    pub(crate) fn map_hostinfo_value(
        &self,
        record: &MachineRecord,
    ) -> Result<serde_json::Value, serde_json::Error> {
        self.snapshot_with_metadata().map_hostinfo_value(record)
    }

    /// Apply a native admin edit in the NodeStore writer without dispatching
    /// a change before its database save. Name reservation shares the writer
    /// with create/rekey, so collision validation and assignment are atomic.
    #[cfg(feature = "admin")]
    pub(crate) fn mutate_native_node_with_view(
        &self,
        id: u64,
        new_name: Option<String>,
        metadata: Option<crate::admin::machines::NativeNodeMetadataEdit>,
        update: impl FnOnce(&mut MachineRecord) -> bool + Send + 'static,
    ) -> Result<Option<crate::admin::machines::MachineAdminView>, String> {
        if let Some(name) = &new_name {
            self.validate_given_name(name)?;
        }
        let error = Arc::new(Mutex::new(None));
        let writer_error = error.clone();
        let captured_view = Arc::new(Mutex::new(None));
        let writer_view = captured_view.clone();
        let natives = self.native_persistence.clone();
        let hostinfos = self.hostinfo_snapshots.clone();
        let operation = if new_name.is_some() {
            "set_name"
        } else {
            "update"
        };
        let outcome = self.apply_nodestore_bool_update(
            operation,
            Box::new(move |map| {
                let keys = map
                    .iter()
                    .filter(|(key, record)| record.stable_node_id_for_key(key) == id)
                    .take(2)
                    .map(|(key, _)| key.clone())
                    .collect::<Vec<_>>();
                let Some(key) = keys.first() else {
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                };
                if keys.len() != 1 {
                    *writer_error.lock() = Some("ambiguous node identity".to_string());
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                }
                if new_name.as_ref().is_some_and(|name| {
                    map.iter()
                        .any(|(other, record)| other != key && record.hostname == *name)
                }) {
                    *writer_error.lock() =
                        Some("given name already in use by another node".to_string());
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                }
                let record = map
                    .get_mut(key)
                    .expect("selected node remains in the writer snapshot");
                let clear_unhealthy = update(record);
                let metadata = metadata
                    .filter(|edit| !edit.require_native || natives.read().contains_key(&id));
                if let Some(metadata) = metadata {
                    use crate::admin::machines::NativeNodePersistence;
                    let mut prior = natives.read().get(&id).cloned();
                    let hostinfo = hostinfos.read().get(&id).cloned();
                    if let (Some(prior), Some(hostinfo)) = (&mut prior, &hostinfo) {
                        prior.replace_hostinfo_snapshot(hostinfo.clone());
                    }
                    let captured = (|| {
                        let mut fields =
                            NativeNodePersistence::snapshot(id, record, prior.as_ref())?;
                        if prior.is_none()
                            && let Some(hostinfo) = hostinfo
                        {
                            let value = hostinfo.value_for(&record.host_info_for_node()).map_err(
                                |error| {
                                    crate::admin::machines::MachineAdminError::Storage(
                                        error.to_string(),
                                    )
                                },
                            )?;
                            fields.host_info = (!value.is_null()).then_some(value);
                        }
                        if metadata.nil_user {
                            fields.user_id = None;
                        }
                        if metadata.nil_routes {
                            fields.approved_routes = None;
                        }
                        Ok::<_, crate::admin::machines::MachineAdminError>(
                            NativeNodePersistence::from_snapshot(record, &fields, prior.as_ref()),
                        )
                    })();
                    match captured {
                        Ok(native) => {
                            hostinfos.write().insert(id, native.hostinfo_snapshot());
                            natives.write().insert(id, native);
                        }
                        Err(error) => {
                            // Go has already changed NodeStore when SQL JSON
                            // encoding fails; keep that live mutation too.
                            *writer_error.lock() =
                                Some(crate::admin::machines::native_save_error(error).to_string());
                        }
                    }
                }
                let native = natives.read().get(&id).cloned();
                *writer_view.lock() = Some(crate::admin::machines::MachineAdminView::from_wire(
                    key,
                    record,
                    native.as_ref(),
                    false,
                ));
                NodeStoreBoolUpdateOutcome {
                    final_presence_node_id: Some(id),
                    clear_unhealthy_route_state: clear_unhealthy.then_some(id),
                    ..NodeStoreBoolUpdateOutcome::quiet(true)
                }
            }),
        );
        let result = error.lock().take();
        match result {
            Some(error) => Err(error),
            None => Ok(if outcome.applied {
                captured_view.lock().take()
            } else {
                None
            }),
        }
    }

    fn discard_absent_native_persistence(&self, ids: &[u64]) {
        let snapshot = self.snapshot();
        let live = snapshot
            .iter()
            .map(|(key, record)| record.stable_node_id_for_key(key))
            .collect::<BTreeSet<_>>();
        let mut hostinfo = self.hostinfo_snapshots.write();
        #[cfg(feature = "admin")]
        let mut native = self.native_persistence.write();
        #[cfg(feature = "admin")]
        let mut pending = self.pending_native_hostinfo.write();
        for id in ids {
            if !live.contains(id) {
                hostinfo.remove(id);
                #[cfg(feature = "admin")]
                native.remove(id);
                #[cfg(feature = "admin")]
                pending.remove(id);
                #[cfg(feature = "admin")]
                self.pending_native_registrations.write().remove(id);
                #[cfg(feature = "admin")]
                self.pending_native_rows.write().remove(id);
            }
        }
    }

    /// Register the allocator used by this registry. Weak ownership avoids a
    /// cycle with embedding allocators; the serving state owns the allocator.
    pub fn configure_ip_allocator(&self, allocator: &Arc<dyn IpAllocator>) {
        *self.ip_allocator.write() = Some(Arc::downgrade(allocator));
    }

    fn release_addresses(&self, ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>) {
        let allocator = self.ip_allocator.read().as_ref().and_then(Weak::upgrade);
        if let Some(allocator) = allocator {
            allocator.release_addresses(ipv4, ipv6);
        }
    }

    /// Configure the same base domain used by map FQDN generation. Empty
    /// preserves the no-domain embedding contract; production sets it at boot.
    pub fn configure_given_name_domain(&self, base_domain: &str) {
        base_domain.clone_into(&mut self.given_name_domain.write());
    }

    pub(crate) fn validate_given_name(&self, name: &str) -> Result<(), String> {
        headscale_api_acl::go_dnsname::validate_given_name(name, &self.given_name_domain.read())
            .map_err(|error| format!("renaming node: {error}"))
    }

    /// Configure the default lifetime for user-owned registrations. Go stores
    /// node.expiry as signed nanoseconds; nonpositive values disable defaults.
    pub fn configure_registration_expiry(&self, nanos: i64) {
        self.registration_expiry_nanos
            .store(nanos, Ordering::Relaxed);
    }

    pub(crate) fn registration_expiry(
        &self,
        expiry: Option<DateTime<Utc>>,
        tagged: bool,
        now: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        let missing = expiry.is_none_or(|expiry| {
            expiry.timestamp() == -62_135_596_800 && expiry.timestamp_subsec_nanos() == 0
        });
        let nanos = self.registration_expiry_nanos.load(Ordering::Relaxed);
        if tagged || !missing || nanos <= 0 {
            return expiry;
        }
        Some(
            now.checked_add_signed(chrono::Duration::nanoseconds(nanos))
                .unwrap_or(DateTime::<Utc>::MAX_UTC),
        )
    }

    pub(crate) async fn lock_registration(
        &self,
        machine_key: &str,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        self.lock_registration_key(RegistrationLockKey::Machine(machine_key.to_owned()))
            .await
    }

    /// Acquire after the machine guard and retain through persistence and
    /// publication. Different machines may otherwise race to claim one key.
    pub(crate) async fn lock_node_key_registration(
        &self,
        node_key: &str,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        self.lock_registration_key(RegistrationLockKey::Node(node_key.to_owned()))
            .await
    }

    pub(crate) fn validate_registration_node_key(
        &self,
        node_key: &str,
        machine_key: &str,
    ) -> Result<(), &'static str> {
        if self
            .get(node_key)
            .is_some_and(|record| record.machine_key_hex != machine_key)
        {
            return Err("node key already in use by another machine");
        }
        Ok(())
    }

    async fn lock_registration_key(
        &self,
        key: RegistrationLockKey,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.registration_locks.lock();
            locks.retain(|_, lock| lock.strong_count() > 0);
            if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
                lock
            } else {
                let lock = Arc::new(tokio::sync::Mutex::new(()));
                locks.insert(key, Arc::downgrade(&lock));
                lock
            }
        };
        lock.lock_owned().await
    }

    /// Enable headscale-go-style NodeStore write batching for registry mutations.
    ///
    /// Callers still block until their write has been committed; the worker
    /// batches concurrent writes so a burst clones and publishes the COW
    /// snapshot once instead of once per caller.
    pub fn configure_nodestore_write_batcher(
        self: &Arc<Self>,
        batch_size: usize,
        batch_timeout: Duration,
    ) -> NodeStoreWriteBatcherHandle {
        let id = self
            .nodestore_write_queue_next_id
            .fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = std_mpsc::channel();
        self.nodestore_write_queue
            .write()
            .replace(NodeStoreWriteQueue { id, tx: tx.clone() });

        let machines = Arc::clone(self);
        let worker = thread::Builder::new()
            .name("headscale-nodestore-write-batcher".to_string())
            .spawn(move || run_nodestore_write_worker(&machines, &rx, batch_size, batch_timeout))
            .expect("spawn NodeStore write batcher");

        NodeStoreWriteBatcherHandle {
            id,
            machines: Arc::downgrade(self),
            tx: Some(tx),
            worker: Some(worker),
        }
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
        if let Some(store) = &registration_store {
            *self.registration_store.write() = Some(store.clone());
        }
        let gc = Arc::new(EphemeralNodeGc {
            machines: Arc::downgrade(self),
            registration_store,
            inactivity_timeout,
            timers: Mutex::new(BTreeMap::new()),
            next_generation: AtomicU64::new(1),
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

    fn bind_registration_store(&self, store: Option<&Arc<dyn MachineRegistrationStore>>) {
        if let Some(store) = store {
            *self.registration_store.write() = Some(Arc::downgrade(store));
        }
    }

    fn ephemeral_node_key_by_id(&self, node_id: u64) -> Option<String> {
        self.snapshot().iter().find_map(|(node_key, rec)| {
            (rec.ephemeral && rec.stable_node_id_for_key(node_key) == node_id)
                .then(|| node_key.clone())
        })
    }

    pub(crate) fn stable_node_id_for_key(&self, node_key_hex: &str) -> u64 {
        self.inner.read().get(node_key_hex).map_or_else(
            || stable_id_from_key(node_key_hex),
            |rec| rec.stable_node_id_for_key(node_key_hex),
        )
    }

    fn node_key_still_maps_to_node_id(&self, node_key_hex: &str, node_id: u64) -> bool {
        self.inner
            .read()
            .get(node_key_hex)
            .is_some_and(|rec| rec.stable_node_id_for_key(node_key_hex) == node_id)
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

    #[must_use]
    pub fn subscribe_map_batches(&self) -> watch::Receiver<MapChangeBatch> {
        self.map_batch_tx.subscribe()
    }

    #[must_use]
    pub fn subscribe_map_batch_events(&self) -> broadcast::Receiver<MapChangeBatch> {
        self.map_batch_event_tx.subscribe()
    }

    #[must_use]
    pub fn map_batcher_enabled(&self) -> bool {
        self.map_batcher_enabled.load(Ordering::SeqCst)
    }

    fn enable_map_batcher(&self) {
        self.map_batcher_enabled.store(true, Ordering::SeqCst);
    }

    #[must_use]
    pub fn map_change_history(&self) -> Vec<MapChange> {
        self.map_changes.read().iter().cloned().collect()
    }

    #[must_use]
    pub fn pending_map_changes(&self) -> BTreeMap<u64, Vec<MapChange>> {
        self.pending_map_changes.read().clone()
    }

    pub(crate) fn has_pending_full_map_change_for_node(&self, node_id: u64) -> bool {
        self.pending_map_changes
            .read()
            .get(&node_id)
            .is_some_and(|changes| changes.iter().any(MapChange::is_full))
    }

    #[must_use]
    pub fn drain_pending_map_changes(&self) -> BTreeMap<u64, Vec<MapChange>> {
        std::mem::take(&mut *self.pending_map_changes.write())
    }

    pub fn publish_pending_map_changes(&self) -> Option<MapChangeBatch> {
        let pending = self.drain_pending_map_changes();
        if pending.is_empty() {
            return None;
        }
        let batch = Arc::new(pending);
        self.map_batch_tx.send_replace(batch.clone());
        let _ = self.map_batch_event_tx.send(batch.clone());
        Some(batch)
    }

    fn push_map_change(&self, change: MapChange) {
        let mut changes = self.map_changes.write();
        changes.push_back(change);
        while changes.len() > MAP_CHANGE_HISTORY_LIMIT {
            changes.pop_front();
        }
    }

    fn batcher_node_ids(&self) -> Vec<u64> {
        self.active_connections.read().keys().copied().collect()
    }

    fn enqueue_map_change(&self, change: MapChange) {
        let removed = change.content.peers_removed.clone();
        let batcher_node_ids = self.batcher_node_ids();
        let mut pending = self.pending_map_changes.write();
        for node_id in &removed {
            pending.remove(node_id);
        }

        if change.is_full() && change.target_node_id.is_none() {
            for node_id in batcher_node_ids {
                pending.insert(node_id, vec![change.clone()]);
            }
            return;
        }

        if let Some(target_node_id) = change.target_node_id {
            if removed.contains(&target_node_id) || !batcher_node_ids.contains(&target_node_id) {
                return;
            }
            pending.entry(target_node_id).or_default().push(change);
            return;
        }

        for node_id in batcher_node_ids {
            if removed.contains(&node_id) {
                continue;
            }
            if change.should_send_to_node(node_id) {
                pending.entry(node_id).or_default().push(change.clone());
            }
        }
    }

    pub(crate) fn record_observed_map_change(
        &self,
        reason: MapChangeReason,
        target_node_id: Option<u64>,
        origin_node_id: Option<u64>,
    ) {
        let generation = *self.gen_tx.borrow();
        let change =
            PendingMapChange::new(reason, target_node_id, origin_node_id).into_change(generation);
        self.push_map_change(change.clone());
        self.enqueue_map_change(change);
    }

    pub(crate) fn record_unbatched_map_change(
        &self,
        reason: MapChangeReason,
        target_node_id: Option<u64>,
        origin_node_id: Option<u64>,
    ) {
        let generation = *self.gen_tx.borrow();
        let change =
            PendingMapChange::new(reason, target_node_id, origin_node_id).into_change(generation);
        self.push_map_change(change);
    }

    fn wake_waiters_with(&self, change: PendingMapChange) {
        self.wake_waiters_with_many(vec![change]);
    }

    fn wake_waiters_with_many(&self, mut changes: Vec<PendingMapChange>) {
        // Headscale.Change drains State's retained self-refresh list on every
        // dispatch, including an otherwise empty successful map result. A
        // failed database save leaves this queue for the next dispatch.
        let mut self_refreshes = std::mem::take(&mut *self.pending_self_refreshes.lock());
        let policy = self.policy_store.read().clone();
        if let Some(policy) = policy {
            self_refreshes.extend(policy.drain_changed_node_attrs());
        }
        changes.extend(
            self_refreshes
                .into_iter()
                .map(|id| PendingMapChange::target(MapChangeReason::SelfUpdate, id)),
        );
        if changes.is_empty() {
            return;
        }

        // One upstream event can contain more than one semantic change, for
        // example auth completion followed by route auto-approval. Bump the
        // stream generation once, then preserve the ordered change list.
        let mut generation = 0;
        self.gen_tx.send_modify(|g| {
            *g = g.wrapping_add(1);
            generation = *g;
        });
        for change in changes {
            let change = change.into_change(generation);
            self.push_map_change(change.clone());
            self.enqueue_map_change(change);
        }
        self.notify.notify_waiters();
    }

    /// Headscale-go `State.ExpireExpiredNodes` parity: find nodes whose
    /// key-expiry crossed since the previous scheduler pass. Revalidate in
    /// one writer batch and clear their online state before announcing them.
    /// Nodes and their already-persisted expiry remain in the database.
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
        let candidates = self
            .snapshot()
            .iter()
            .filter(|(_, record)| {
                record.is_expired_at(now) && record.expiry.is_some_and(|expiry| expiry > last_check)
            })
            .map(|(key, record)| record.stable_node_id_for_key(key))
            .collect::<BTreeSet<_>>();
        if candidates.is_empty() {
            return Vec::new();
        }
        let online = self.online_states.clone();
        let policy = self.policy_store.read().clone();
        let changes = Arc::new(Mutex::new(Vec::new()));
        let pending = changes.clone();
        let outcome = self.apply_nodestore_many_update(
            "expire",
            Box::new(move |records| {
                let mut outcome = NodeStoreManyUpdateOutcome::unchanged();
                let mut online = online.write();
                let mut changes = pending.lock();
                for (key, record) in records {
                    let node_id = record.stable_node_id_for_key(key);
                    // An expiry restoration/rekey/deletion may have happened
                    // after candidate selection. Never overwrite that edit.
                    if !candidates.contains(&node_id)
                        || !record.is_expired_at(now)
                        || record.expiry.is_none_or(|expiry| expiry <= last_check)
                    {
                        continue;
                    }
                    let was_online = online.insert(node_id, false).unwrap_or(false);
                    changes.push(PendingMapChange::lifecycle_peer(
                        MapChangeReason::NodeAdded,
                        node_id,
                        was_online && record_needs_peer_recompute(record, policy.as_ref()),
                    ));
                    outcome.affected_node_keys.push(key.clone());
                    outcome.affected_node_ids.push(node_id);
                    outcome.final_presence_node_ids.push(node_id);
                }
                outcome.applied = outcome.affected_node_ids.len();
                outcome.publish_snapshot = outcome.applied != 0;
                outcome
            }),
        );
        let mut changes = std::mem::take(&mut *changes.lock());
        if outcome.applied == 0 {
            return Vec::new();
        }
        let present = outcome
            .final_presence_node_ids
            .into_iter()
            .collect::<BTreeSet<_>>();
        changes.retain(|change| {
            change
                .origin_node_id
                .is_some_and(|node_id| present.contains(&node_id))
        });
        self.wake_waiters_with_many(changes);
        outcome
            .affected_node_keys
            .into_iter()
            .zip(outcome.affected_node_ids)
            .filter_map(|(key, node_id)| present.contains(&node_id).then_some(key))
            .collect()
    }

    /// Insert or replace a machine record. Wakes every pending
    /// `/map` long-poll.
    ///
    /// Writes are O(n) in the map size — we clone the underlying map
    /// once per write — but registration is rare relative to map reads
    /// in steady state, so this trade is the right one.
    pub fn upsert(&self, node_key_hex: String, rec: MachineRecord) {
        self.upsert_with_reason(node_key_hex, rec, None);
    }

    /// Publish a record without waking map streams. Production map updates go
    /// through `apply_map_runtime_update`; this is a test seam only.
    #[cfg(test)]
    pub(crate) fn upsert_quiet(&self, node_key_hex: String, rec: MachineRecord) {
        self.upsert_record(node_key_hex, rec);
    }

    /// Headscale's post-backfill PutNode refresh is by stable ID, retaining
    /// live Hostinfo and preferring a persisted NetInfo when present. Online
    /// state is held separately by the stream connection tracker. Merge inside
    /// one NodeStore writer so a full reload requires only one COW map copy.
    #[cfg(feature = "admin")]
    pub(crate) fn refresh_nodes_after_ip_backfill(
        &self,
        mut records: Vec<MachineRecord>,
        native: Vec<(u64, crate::admin::machines::NativeNodePersistence)>,
    ) {
        if records.is_empty() {
            return;
        }
        let mut native = native.into_iter().collect::<HashMap<_, _>>();
        let natives = self.native_persistence.clone();
        let hostinfos = self.hostinfo_snapshots.clone();
        let pending = self.pending_native_hostinfo.clone();
        self.apply_nodestore_many_update(
            "put_multi",
            Box::new(move |map| {
                {
                    let existing_by_id = map
                        .iter()
                        .map(|(key, record)| (record.stable_node_id_for_key(key), record))
                        .collect::<HashMap<_, _>>();
                    for record in &mut records {
                        let node_id = record.stable_node_id_for_key(&record.node_key_hex);
                        if let Some(existing) = existing_by_id.get(&node_id) {
                            let mut hostinfo = existing.host_info_for_node();
                            hostinfo.net_info =
                                record.host_info_for_node().net_info.or(hostinfo.net_info);
                            // Hostname is a separate persisted Node field in Go.
                            let hostname = record.raw_hostname.clone();
                            record.replace_host_info(hostinfo);
                            record.raw_hostname = hostname;
                        }
                    }
                }
                let refreshed_ids = records
                    .iter()
                    .map(|record| record.stable_node_id_for_key(&record.node_key_hex))
                    .collect::<BTreeSet<_>>();
                // A database node can have a new key. Replace its old ID slot;
                // Go's ID-keyed store has only one slot for that same node.
                map.retain(|key, record| {
                    !refreshed_ids.contains(&record.stable_node_id_for_key(key))
                });
                let applied = records.len();
                for record in records {
                    let id = record.stable_node_id_for_key(&record.node_key_hex);
                    if let Some(mut captured) = native.remove(&id) {
                        let projection = record.host_info_for_node();
                        let snapshot = captured.hostinfo_snapshot();
                        if let Ok(value) = snapshot.value_for(&projection) {
                            captured.replace_hostinfo_snapshot(hostinfo::HostInfoSnapshot {
                                projection,
                                value,
                            });
                        }
                        hostinfos.write().insert(id, captured.hostinfo_snapshot());
                        natives.write().insert(id, captured);
                        pending.write().remove(&id);
                    }
                    map.insert(record.node_key_hex.clone(), record);
                }
                // Go's BackfillNodeIPs does not enqueue a map notification or
                // a policy refresh for these PutNode calls.
                NodeStoreManyUpdateOutcome {
                    applied,
                    publish_snapshot: true,
                    ..NodeStoreManyUpdateOutcome::unchanged()
                }
            }),
        );
    }

    /// Create an admin record with the uniqueness checks and insertion in one
    /// NodeStore write. A snapshot check followed by upsert can replace a node
    /// registered by another machine while the create was being prepared.
    #[cfg(feature = "admin")]
    pub(crate) fn insert_volatile_admin_record(
        &self,
        mut record: MachineRecord,
    ) -> Result<MachineRecord, RegistryMutationError> {
        let node_key = record.node_key_hex.clone();
        let node_id = record.stable_node_id_for_key(&node_key);
        record.node_id = Some(node_id);
        let result = Arc::new(Mutex::new(None));
        let completed = result.clone();
        let outcome = self.apply_nodestore_bool_update(
            "put",
            Box::new(move |map| {
                let conflict = if map.contains_key(&node_key) {
                    Some("node already exists".to_owned())
                } else {
                    map.iter().find_map(|(key, existing)| {
                        if existing.stable_node_id_for_key(key) == node_id {
                            Some("node ID already exists".to_owned())
                        } else if record.ipv4.is_some() && existing.ipv4 == record.ipv4 {
                            record
                                .ipv4
                                .map(|ip| format!("IPv4 address {ip} already in use"))
                        } else if record.ipv6.is_some() && existing.ipv6 == record.ipv6 {
                            record
                                .ipv6
                                .map(|ip| format!("IPv6 address {ip} already in use"))
                        } else if existing.hostname == record.hostname {
                            Some("name already exists".to_owned())
                        } else {
                            None
                        }
                    })
                };
                if let Some(error) = conflict {
                    *completed.lock() = Some(Err(error));
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                }
                map.insert(node_key, record.clone());
                *completed.lock() = Some(Ok(record));
                NodeStoreBoolUpdateOutcome {
                    final_presence_node_id: Some(node_id),
                    ..NodeStoreBoolUpdateOutcome::quiet(true)
                }
            }),
        );
        let record = result
            .lock()
            .take()
            .ok_or("node creation changed during publication")??;
        if !outcome.applied {
            return Err("node creation changed during publication".into());
        }
        self.finish_volatile_node_update(&outcome, MapChangeReason::NodeAdded)
            .map_err(RegistryMutationError::Policy)?;
        Ok(record)
    }

    /// Merge only client-owned map fields into the current node. A snapshot
    /// taken before an async store write must not restore old authorization,
    /// owner metadata, IP assignments, or an administratively renamed node.
    pub(crate) fn apply_runtime_update(
        &self,
        before: &MachineRecord,
        proposed: MachineRecord,
        reason: Option<MapChangeReason>,
    ) -> Option<MachineRecord> {
        self.apply_map_runtime_update(before, proposed, reason, None)
    }

    pub(crate) fn apply_map_runtime_update(
        &self,
        before: &MachineRecord,
        proposed: MachineRecord,
        reason: Option<MapChangeReason>,
        hostinfo: Option<serde_json::Value>,
    ) -> Option<MachineRecord> {
        let key = before.node_key_hex.clone();
        if proposed.node_key_hex != key {
            return None;
        }
        let before = before.clone();
        let hostinfo_snapshots = self.hostinfo_snapshots.clone();
        let key_for_update = key.clone();
        let outcome = self.apply_nodestore_bool_update(
            "update",
            Box::new(move |records| {
                let Some(current) = records.get(&key_for_update) else {
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                };
                if current.machine_key_hex != before.machine_key_hex
                    || (current.node_id.is_some()
                        && before.node_id.is_some()
                        && current.node_id != before.node_id)
                {
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                }
                let mut next = current.clone();
                next.disco_key.clone_from(&proposed.disco_key);
                next.endpoints.clone_from(&proposed.endpoints);
                next.replace_host_info(proposed.host_info_for_node());
                if current.raw_hostname == before.raw_hostname {
                    next.raw_hostname.clone_from(&proposed.raw_hostname);
                } else {
                    next.raw_hostname.clone_from(&current.raw_hostname);
                }
                next.os.clone_from(&proposed.os);
                next.os_version.clone_from(&proposed.os_version);
                next.home_derp = proposed.home_derp;
                next.available_routes.clone_from(&proposed.available_routes);
                next.ssh_host_keys.clone_from(&proposed.ssh_host_keys);
                if current.hostname == before.hostname
                    && current.raw_hostname == before.raw_hostname
                {
                    next.hostname.clone_from(&proposed.hostname);
                    if next.raw_hostname != current.raw_hostname
                        && !next.raw_hostname.is_empty()
                        && wire::is_auto_derived_given_name(
                            &current.hostname,
                            &current.raw_hostname,
                        )
                    {
                        // NodeStore.UpdateNode reserves an automatic name in
                        // its writer. A snapshot-only lookup can lose a race
                        // to another registration or an admin rename.
                        next.hostname = Self::resolve_auto_given_name_from_snapshot(
                            records,
                            &key_for_update,
                            None,
                            &next.raw_hostname,
                        );
                    }
                }
                if !Self::policy_identity_without_routes_changed(current, &before)
                    && current.approved_routes == before.approved_routes
                {
                    next.approved_routes.clone_from(&proposed.approved_routes);
                }
                if next.node_id.is_none() {
                    next.node_id = proposed.node_id;
                }
                next.last_seen = current.last_seen.max(proposed.last_seen);
                let changed = hostinfo.is_some()
                    || current.disco_key != next.disco_key
                    || current.endpoints != next.endpoints
                    || current.host_info_for_node() != next.host_info_for_node()
                    || current.hostname != next.hostname
                    || current.raw_hostname != next.raw_hostname
                    || current.available_routes != next.available_routes
                    || current.approved_routes != next.approved_routes
                    || current.ssh_host_keys != next.ssh_host_keys
                    || current.node_id != next.node_id;
                let publish = changed || current.last_seen != next.last_seen;
                let node_id = next.stable_node_id_for_key(&key_for_update);
                let clear_unhealthy =
                    active_approved_routes(&next.available_routes, &next.approved_routes)
                        .is_empty();
                if let Some(value) = hostinfo {
                    hostinfo_snapshots.write().insert(
                        node_id,
                        hostinfo::HostInfoSnapshot {
                            projection: next.host_info_for_node(),
                            value,
                        },
                    );
                }
                records.insert(key_for_update.clone(), next);
                NodeStoreBoolUpdateOutcome {
                    applied: true,
                    publish_snapshot: publish,
                    change: reason
                        .filter(|_| changed)
                        .map(|reason| PendingMapChange::origin(reason, node_id)),
                    clear_unhealthy_route_state: clear_unhealthy.then_some(node_id),
                    final_presence_node_id: None,
                }
            }),
        );
        outcome.applied.then(|| self.get(&key)).flatten()
    }

    pub(crate) fn upsert_with_reason(
        &self,
        node_key_hex: String,
        rec: MachineRecord,
        reason: Option<MapChangeReason>,
    ) {
        let node_id = rec.stable_node_id_for_key(&node_key_hex);
        let node_key_for_presence = node_key_hex.clone();
        let existed = self.upsert_record(node_key_hex, rec);
        if !self.node_key_still_maps_to_node_id(&node_key_for_presence, node_id) {
            return;
        }
        let reason = reason.unwrap_or(if existed {
            MapChangeReason::NodeUpdated
        } else {
            MapChangeReason::NodeAdded
        });
        self.wake_waiters_with(PendingMapChange::origin(reason, node_id));
    }

    #[cfg(test)]
    pub(crate) fn upsert_auth_completion(&self, node_key_hex: String, rec: MachineRecord) {
        self.try_upsert_auth_completion(node_key_hex, rec)
            .expect("auth completion policy resolves");
    }

    pub(crate) fn try_upsert_auth_completion(
        &self,
        node_key_hex: String,
        rec: MachineRecord,
    ) -> Result<(), String> {
        #[cfg(feature = "admin")]
        if self.finish_native_registration_publication(&rec)? {
            return Ok(());
        }
        let node_id = rec.stable_node_id_for_key(&node_key_hex);
        let existing = self.get(&node_key_hex);
        let node_key_for_presence = node_key_hex.clone();
        let published = rec.clone();
        self.upsert_record(node_key_hex, rec);
        if !self.node_key_still_maps_to_node_id(&node_key_for_presence, node_id) {
            return Ok(());
        }
        let changes = Self::auth_completion_pending_changes_with_policy(
            existing.as_ref(),
            &published,
            node_id,
            self.try_refresh_policy_node_inputs()?,
        );
        self.wake_waiters_with_many(changes);
        Ok(())
    }

    #[cfg(feature = "admin")]
    pub(crate) fn publish_saved_admin_record(&self, record: MachineRecord) -> Result<(), String> {
        let key = record.node_key_hex.clone();
        let id = record.stable_node_id_for_key(&key);
        self.upsert_record(key.clone(), record);
        if self.node_key_still_maps_to_node_id(&key, id) {
            if self.try_refresh_policy_node_inputs()? == Some(true) {
                self.wake_policy_change(None);
            } else {
                self.wake_node_change(MapChangeReason::NodeAdded, id);
            }
        }
        Ok(())
    }

    /// Publish a volatile auth result with the node-key binding checked in
    /// the same NodeStore write as insertion/rekey. Per-machine registration
    /// locks alone cannot exclude a different machine claiming the same key.
    pub(crate) fn commit_volatile_auth_registration_with_hostinfo(
        &self,
        previous_node_key: Option<&str>,
        mut record: MachineRecord,
        hostinfo: Option<serde_json::Value>,
    ) -> Result<MachineRecord, RegistryMutationError> {
        let previous = previous_node_key.map(str::to_owned);
        let new_key = record.node_key_hex.clone();
        let published_key = new_key.clone();
        let operation = if previous.is_some() {
            "replace_key"
        } else {
            "put"
        };
        let committed = Arc::new(Mutex::new(None));
        let completed = committed.clone();
        let hostinfo_snapshots = self.hostinfo_snapshots.clone();
        #[cfg(feature = "admin")]
        let install_native = self.native_row_installer();
        let outcome = self.apply_nodestore_bool_update(
            operation,
            Box::new(move |map| {
                let existing = previous.as_ref().and_then(|key| map.get(key)).cloned();
                if previous.is_some() && existing.is_none() {
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                }
                let old_id = existing
                    .as_ref()
                    .zip(previous.as_ref())
                    .map(|(old, key)| old.stable_node_id_for_key(key));
                if let Some(old) = &existing {
                    if old.machine_key_hex != record.machine_key_hex
                        || old.created_at != record.created_at
                        || record.node_id.is_some_and(|id| Some(id) != old_id)
                    {
                        return NodeStoreBoolUpdateOutcome::unchanged(false);
                    }
                    record.node_id = old_id;
                }
                let node_id = record.stable_node_id_for_key(&new_key);
                if let Some(target) = map.get(&new_key)
                    && (old_id.is_none()
                        || target.machine_key_hex != record.machine_key_hex
                        || Some(target.stable_node_id_for_key(&new_key)) != old_id)
                {
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                }
                // Other machine registrations and admin renames use the same
                // NodeStore writer. Resolve a generated label here so two
                // snapshots cannot both reserve the same DNS name.
                record.hostname = if let Some(old) = existing.as_ref() {
                    old.hostname.clone()
                } else {
                    Self::resolve_auto_given_name_from_snapshot(
                        map,
                        &new_key,
                        previous.as_deref(),
                        &record.raw_hostname,
                    )
                };
                record.node_id = Some(node_id);
                let local_policy_change =
                    Self::auth_completion_map_change_reason(existing.as_ref(), &record, None)
                        == MapChangeReason::PolicyChange;
                let mut changes = Self::auth_completion_pending_changes_with_policy(
                    existing.as_ref(),
                    &record,
                    node_id,
                    Some(false),
                );
                if changes
                    .first()
                    .is_some_and(|change| change.reason == MapChangeReason::NodeKeyRotated)
                    && let (Some(existing), Some(next_hostinfo)) =
                        (existing.as_ref(), hostinfo.as_ref())
                {
                    let projection = existing.host_info_for_node();
                    let previous_hostinfo = hostinfo_snapshots
                        .read()
                        .get(&node_id)
                        .map_or_else(
                            || serde_json::to_value(&projection),
                            |snapshot| snapshot.value_for(&projection),
                        )
                        .expect("HostInfo serializes primitive JSON fields");
                    if !headscale_api_acl::go_tailcfg_json::peer_hostinfo_equal(
                        &previous_hostinfo,
                        next_hostinfo,
                    ) {
                        changes[0] = PendingMapChange::origin(MapChangeReason::NodeAdded, node_id);
                    }
                }
                if let Some(previous) = &previous
                    && previous != &new_key
                {
                    map.remove(previous);
                }
                if let Some(value) = hostinfo {
                    hostinfo_snapshots.write().insert(
                        node_id,
                        hostinfo::HostInfoSnapshot {
                            projection: record.host_info_for_node(),
                            value,
                        },
                    );
                }
                #[cfg(feature = "admin")]
                install_native(&record);
                map.insert(new_key, record.clone());
                *completed.lock() = Some((record, changes, local_policy_change));
                NodeStoreBoolUpdateOutcome {
                    final_presence_node_id: Some(node_id),
                    ..NodeStoreBoolUpdateOutcome::quiet(true)
                }
            }),
        );
        if !outcome.applied {
            return Err("node key already exists".into());
        }
        let (record, mut changes, local_policy_change) = committed
            .lock()
            .take()
            .ok_or("registration changed during publication")?;
        // Binding changes retire their old stream/timer ownership inside the
        // NodeStore writer, before another registration can acquire it.
        if self.node_key_still_maps_to_node_id(
            &published_key,
            record.stable_node_id_for_key(&published_key),
        ) {
            if self
                .try_refresh_policy_node_inputs()
                .map_err(RegistryMutationError::Policy)?
                .unwrap_or(local_policy_change)
            {
                changes = vec![PendingMapChange::global(MapChangeReason::PolicyChange)];
            }
            self.wake_waiters_with_many(changes);
        }
        Ok(record)
    }

    fn auth_completion_map_change_reason(
        existing: Option<&MachineRecord>,
        rec: &MachineRecord,
        policy_changed: Option<bool>,
    ) -> MapChangeReason {
        let local_policy_change = || {
            existing.is_none_or(|existing| {
                Self::policy_identity_without_routes_changed(existing, rec)
                    || Self::auth_completion_active_approved_routes_changed(Some(existing), rec)
            })
        };
        if policy_changed.unwrap_or_else(local_policy_change) {
            return MapChangeReason::PolicyChange;
        }
        let Some(existing) = existing else {
            return MapChangeReason::NodeAdded;
        };
        let now = Utc::now();
        if existing.is_expired_at(now) == rec.is_expired_at(now)
            && existing.hostname == rec.hostname
            && map::peer_hostinfo_equal(&existing.host_info_for_node(), &rec.host_info_for_node())
        {
            MapChangeReason::NodeKeyRotated
        } else {
            MapChangeReason::NodeAdded
        }
    }

    fn policy_identity_without_routes_changed(
        before: &MachineRecord,
        after: &MachineRecord,
    ) -> bool {
        before.user_id != after.user_id
            // Preserve label-only embedding identities. Native records carry
            // the numeric owner instead of the synthetic tagged wire user.
            || (before.user_id.is_none()
                && after.user_id.is_none()
                && before.user != after.user)
            || before.ipv4 != after.ipv4
            || before.ipv6 != after.ipv6
            // NodeView.HasPolicyChange uses SliceEqual for Tags: order and
            // duplicate count are significant; nil and empty are equivalent.
            || before.forced_tags != after.forced_tags
    }

    fn auth_completion_active_approved_routes_changed(
        existing: Option<&MachineRecord>,
        rec: &MachineRecord,
    ) -> bool {
        // SubnetRoutes and ExitRoutes iterate the announcement slice and keep
        // duplicates. Their unordered comparison must not reduce it to a set.
        let active = |record: &MachineRecord| {
            let mut routes = record
                .available_routes
                .iter()
                .filter(|route| record.approved_routes.contains(route))
                .cloned()
                .collect::<Vec<_>>();
            routes.sort();
            routes
        };
        let after = active(rec);
        match existing {
            Some(existing) => active(existing) != after,
            None => !after.is_empty(),
        }
    }

    fn auth_completion_pending_changes_with_policy(
        existing: Option<&MachineRecord>,
        rec: &MachineRecord,
        node_id: u64,
        policy_changed: Option<bool>,
    ) -> Vec<PendingMapChange> {
        let reason = Self::auth_completion_map_change_reason(existing, rec, policy_changed);
        vec![Self::auth_completion_pending_change(reason, node_id)]
    }

    fn auth_completion_pending_change(reason: MapChangeReason, node_id: u64) -> PendingMapChange {
        match reason {
            MapChangeReason::PolicyChange => {
                PendingMapChange::global(MapChangeReason::PolicyChange)
            }
            reason => PendingMapChange::origin(reason, node_id),
        }
    }

    fn upsert_record(&self, node_key_hex: String, rec: MachineRecord) -> bool {
        if let Some(queue) = self.nodestore_write_queue.read().clone() {
            return self.enqueue_nodestore_upsert(&queue, node_key_hex, rec);
        }
        self.apply_nodestore_upsert_direct(node_key_hex, rec)
    }

    fn enqueue_nodestore_upsert(
        &self,
        queue: &NodeStoreWriteQueue,
        node_key_hex: String,
        rec: MachineRecord,
    ) -> bool {
        let fallback_node_key_hex = node_key_hex.clone();
        let fallback_rec = rec.clone();
        let (result_tx, result_rx) = std_mpsc::channel();
        self.metrics
            .nodestore_queue_depth
            .fetch_add(1, Ordering::SeqCst);
        let result = match queue.tx.send(NodeStoreWriteWork::Upsert {
            node_key_hex,
            rec: Box::new(rec),
            result_tx,
        }) {
            Ok(()) => result_rx.recv().unwrap_or_else(|_| {
                self.apply_nodestore_upsert_direct(fallback_node_key_hex, fallback_rec)
            }),
            Err(std_mpsc::SendError(NodeStoreWriteWork::Upsert {
                node_key_hex, rec, ..
            })) => self.apply_nodestore_upsert_direct(node_key_hex, *rec),
            Err(std_mpsc::SendError(
                NodeStoreWriteWork::Delete { .. }
                | NodeStoreWriteWork::UpdateBool { .. }
                | NodeStoreWriteWork::UpdateMany { .. }
                | NodeStoreWriteWork::Rekey { .. },
            )) => unreachable!(),
        };
        self.metrics
            .nodestore_queue_depth
            .fetch_sub(1, Ordering::SeqCst);
        result
    }

    fn apply_nodestore_upsert_direct(&self, node_key_hex: String, rec: MachineRecord) -> bool {
        let existed;
        let retired;
        let start = Instant::now();
        {
            let mut g = self.inner.write();
            let mut next = (**g).clone();
            existed = next.contains_key(&node_key_hex);
            #[cfg(feature = "admin")]
            self.native_row_installer()(&rec);
            next.insert(node_key_hex, rec);
            retired = self.retire_absent_stream_state(&next);
            *g = Arc::new(next);
        }
        self.notify_retired_streams(retired);
        let elapsed = start.elapsed();
        self.record_nodestore_operation("put", elapsed);
        self.record_nodestore_batch(1, elapsed);
        existed
    }

    fn enqueue_nodestore_delete(
        &self,
        queue: &NodeStoreWriteQueue,
        node_key_hex: String,
    ) -> Option<RemovedNode> {
        let fallback_node_key_hex = node_key_hex.clone();
        let (result_tx, result_rx) = std_mpsc::channel();
        self.metrics
            .nodestore_queue_depth
            .fetch_add(1, Ordering::SeqCst);
        let result = match queue.tx.send(NodeStoreWriteWork::Delete {
            node_key_hex,
            result_tx,
        }) {
            Ok(()) => result_rx
                .recv()
                .unwrap_or_else(|_| self.apply_nodestore_delete_direct(&fallback_node_key_hex)),
            Err(std_mpsc::SendError(NodeStoreWriteWork::Delete { node_key_hex, .. })) => {
                self.apply_nodestore_delete_direct(&node_key_hex)
            }
            Err(std_mpsc::SendError(
                NodeStoreWriteWork::Upsert { .. }
                | NodeStoreWriteWork::UpdateBool { .. }
                | NodeStoreWriteWork::UpdateMany { .. }
                | NodeStoreWriteWork::Rekey { .. },
            )) => unreachable!(),
        };
        self.metrics
            .nodestore_queue_depth
            .fetch_sub(1, Ordering::SeqCst);
        result
    }

    fn apply_nodestore_delete_direct(&self, node_key_hex: &str) -> Option<RemovedNode> {
        let start = Instant::now();
        let retired;
        let removed = {
            let mut g = self.inner.write();
            let mut next = (**g).clone();
            let removed = next.remove(node_key_hex);
            retired = self.retire_absent_stream_state(&next);
            *g = Arc::new(next);
            removed
        };
        self.notify_retired_streams(retired);
        let elapsed = start.elapsed();
        self.record_nodestore_operation("delete", elapsed);
        self.record_nodestore_batch(1, elapsed);
        removed.map(|record| RemovedNode::from_record(node_key_hex, &record))
    }

    fn enqueue_nodestore_bool_update(
        &self,
        queue: &NodeStoreWriteQueue,
        operation: &'static str,
        update: NodeStoreBoolUpdateFn,
    ) -> NodeStoreBoolUpdateOutcome {
        let (result_tx, result_rx) = std_mpsc::channel();
        self.metrics
            .nodestore_queue_depth
            .fetch_add(1, Ordering::SeqCst);
        let result = match queue.tx.send(NodeStoreWriteWork::UpdateBool {
            operation,
            update,
            result_tx,
        }) {
            Ok(()) => result_rx
                .recv()
                .unwrap_or_else(|_| NodeStoreBoolUpdateOutcome::unchanged(false)),
            Err(std_mpsc::SendError(NodeStoreWriteWork::UpdateBool {
                operation, update, ..
            })) => self.apply_nodestore_bool_update_direct(operation, update),
            Err(std_mpsc::SendError(
                NodeStoreWriteWork::Upsert { .. }
                | NodeStoreWriteWork::Delete { .. }
                | NodeStoreWriteWork::UpdateMany { .. }
                | NodeStoreWriteWork::Rekey { .. },
            )) => unreachable!(),
        };
        self.metrics
            .nodestore_queue_depth
            .fetch_sub(1, Ordering::SeqCst);
        result
    }

    fn apply_nodestore_bool_update_direct(
        &self,
        operation: &'static str,
        update: NodeStoreBoolUpdateFn,
    ) -> NodeStoreBoolUpdateOutcome {
        let start = Instant::now();
        let mut retired = false;
        let outcome = {
            let mut g = self.inner.write();
            let mut next = (**g).clone();
            let outcome = update(&mut next);
            if outcome.publish_snapshot {
                retired = self.retire_absent_stream_state(&next);
                *g = Arc::new(next);
            }
            outcome
        };
        self.notify_retired_streams(retired);
        let elapsed = start.elapsed();
        self.record_nodestore_operation(operation, elapsed);
        if outcome.publish_snapshot {
            self.record_nodestore_batch(1, elapsed);
        }
        if let Some(change) = outcome.change.clone() {
            self.wake_waiters_with(change);
        }
        outcome
    }

    fn apply_nodestore_bool_update(
        &self,
        operation: &'static str,
        update: NodeStoreBoolUpdateFn,
    ) -> NodeStoreBoolUpdateOutcome {
        let queue = self.nodestore_write_queue.read().clone();
        let outcome = if let Some(queue) = queue.as_ref() {
            self.enqueue_nodestore_bool_update(queue, operation, update)
        } else {
            self.apply_nodestore_bool_update_direct(operation, update)
        };
        if let Some(node_id) = outcome.clear_unhealthy_route_state {
            self.primary_routes.write().clear_unhealthy(node_id);
        }
        outcome
    }

    fn enqueue_nodestore_many_update(
        &self,
        queue: &NodeStoreWriteQueue,
        operation: &'static str,
        update: NodeStoreManyUpdateFn,
    ) -> NodeStoreManyUpdateOutcome {
        let (result_tx, result_rx) = std_mpsc::channel();
        self.metrics
            .nodestore_queue_depth
            .fetch_add(1, Ordering::SeqCst);
        let result = match queue.tx.send(NodeStoreWriteWork::UpdateMany {
            operation,
            update,
            result_tx,
        }) {
            Ok(()) => result_rx
                .recv()
                .unwrap_or_else(|_| NodeStoreManyUpdateOutcome::unchanged()),
            Err(std_mpsc::SendError(NodeStoreWriteWork::UpdateMany {
                operation, update, ..
            })) => self.apply_nodestore_many_update_direct(operation, update),
            Err(std_mpsc::SendError(
                NodeStoreWriteWork::Upsert { .. }
                | NodeStoreWriteWork::Delete { .. }
                | NodeStoreWriteWork::UpdateBool { .. }
                | NodeStoreWriteWork::Rekey { .. },
            )) => unreachable!(),
        };
        self.metrics
            .nodestore_queue_depth
            .fetch_sub(1, Ordering::SeqCst);
        result
    }

    fn apply_nodestore_many_update_direct(
        &self,
        operation: &'static str,
        update: NodeStoreManyUpdateFn,
    ) -> NodeStoreManyUpdateOutcome {
        let start = Instant::now();
        let mut retired = false;
        let outcome = {
            let mut g = self.inner.write();
            let mut next = (**g).clone();
            let outcome = update(&mut next);
            if outcome.publish_snapshot {
                retired = self.retire_absent_stream_state(&next);
                *g = Arc::new(next);
            }
            outcome
        };
        self.notify_retired_streams(retired);
        let elapsed = start.elapsed();
        self.record_nodestore_operation(operation, elapsed);
        if outcome.publish_snapshot {
            self.record_nodestore_batch(1, elapsed);
        }
        if let Some(change) = outcome.change.clone() {
            self.wake_waiters_with(change);
        }
        outcome
    }

    fn apply_nodestore_many_update(
        &self,
        operation: &'static str,
        update: NodeStoreManyUpdateFn,
    ) -> NodeStoreManyUpdateOutcome {
        let queue = self.nodestore_write_queue.read().clone();
        let outcome = if let Some(queue) = queue.as_ref() {
            self.enqueue_nodestore_many_update(queue, operation, update)
        } else {
            self.apply_nodestore_many_update_direct(operation, update)
        };
        if !outcome.clear_unhealthy_route_states.is_empty() {
            let mut routes = self.primary_routes.write();
            for node_id in &outcome.clear_unhealthy_route_states {
                routes.clear_unhealthy(*node_id);
            }
        }
        outcome
    }

    fn enqueue_nodestore_rekey(
        &self,
        queue: &NodeStoreWriteQueue,
        old_node_key_hex: String,
        new_node_key_hex: String,
        rec: MachineRecord,
        changes: Vec<PendingMapChange>,
        final_presence_node_id: Option<u64>,
    ) {
        let fallback_old_node_key_hex = old_node_key_hex.clone();
        let fallback_new_node_key_hex = new_node_key_hex.clone();
        let fallback_rec = rec.clone();
        let fallback_changes = changes.clone();
        let (result_tx, result_rx) = std_mpsc::channel();
        self.metrics
            .nodestore_queue_depth
            .fetch_add(1, Ordering::SeqCst);
        match queue.tx.send(NodeStoreWriteWork::Rekey {
            old_node_key_hex,
            new_node_key_hex,
            rec: Box::new(rec),
            changes,
            final_presence_node_id,
            result_tx,
        }) {
            Ok(()) => {
                if result_rx.recv().is_err() {
                    self.apply_nodestore_rekey_direct(
                        &fallback_old_node_key_hex,
                        fallback_new_node_key_hex,
                        fallback_rec,
                        fallback_changes,
                    );
                }
            }
            Err(std_mpsc::SendError(NodeStoreWriteWork::Rekey {
                old_node_key_hex,
                new_node_key_hex,
                rec,
                changes,
                ..
            })) => {
                self.apply_nodestore_rekey_direct(
                    &old_node_key_hex,
                    new_node_key_hex,
                    *rec,
                    changes,
                );
            }
            Err(std_mpsc::SendError(
                NodeStoreWriteWork::Upsert { .. }
                | NodeStoreWriteWork::Delete { .. }
                | NodeStoreWriteWork::UpdateBool { .. }
                | NodeStoreWriteWork::UpdateMany { .. },
            )) => unreachable!(),
        }
        self.metrics
            .nodestore_queue_depth
            .fetch_sub(1, Ordering::SeqCst);
    }

    fn apply_nodestore_rekey_direct(
        &self,
        old_node_key_hex: &str,
        new_node_key_hex: String,
        rec: MachineRecord,
        changes: Vec<PendingMapChange>,
    ) {
        let start = Instant::now();
        let retired;
        {
            let mut g = self.inner.write();
            let mut next = (**g).clone();
            if old_node_key_hex != new_node_key_hex {
                next.remove(old_node_key_hex);
            }
            next.insert(new_node_key_hex, rec);
            retired = self.retire_absent_stream_state(&next);
            *g = Arc::new(next);
        }
        self.notify_retired_streams(retired);
        let elapsed = start.elapsed();
        self.record_nodestore_operation("replace_key", elapsed);
        self.record_nodestore_batch(1, elapsed);
        if !changes.is_empty() {
            self.wake_waiters_with_many(changes);
        }
    }

    fn apply_nodestore_write_batch(&self, batch: Vec<NodeStoreWriteWork>) {
        if batch.is_empty() {
            return;
        }

        let start = Instant::now();
        let mut completions = Vec::with_capacity(batch.len());
        let mut publish_snapshot = false;
        let mut retired = false;
        {
            let mut g = self.inner.write();
            let mut next = (**g).clone();
            for work in batch {
                match work {
                    NodeStoreWriteWork::Upsert {
                        node_key_hex,
                        rec,
                        result_tx,
                    } => {
                        let existed = next.contains_key(&node_key_hex);
                        #[cfg(feature = "admin")]
                        self.native_row_installer()(&rec);
                        next.insert(node_key_hex, *rec);
                        publish_snapshot = true;
                        completions.push(NodeStoreWriteCompletion::Bool {
                            operation: "put",
                            result_tx,
                            result: existed,
                        });
                    }
                    NodeStoreWriteWork::Delete {
                        node_key_hex,
                        result_tx,
                    } => {
                        let removed = next
                            .remove(&node_key_hex)
                            .map(|record| RemovedNode::from_record(&node_key_hex, &record));
                        publish_snapshot = true;
                        completions.push(NodeStoreWriteCompletion::Delete {
                            operation: "delete",
                            result_tx,
                            removed,
                        });
                    }
                    NodeStoreWriteWork::UpdateBool {
                        operation,
                        update,
                        result_tx,
                    } => {
                        let outcome = update(&mut next);
                        publish_snapshot |= outcome.publish_snapshot;
                        completions.push(NodeStoreWriteCompletion::UpdateBool {
                            operation,
                            result_tx,
                            outcome,
                        });
                    }
                    NodeStoreWriteWork::UpdateMany {
                        operation,
                        update,
                        result_tx,
                    } => {
                        let outcome = update(&mut next);
                        publish_snapshot |= outcome.publish_snapshot;
                        completions.push(NodeStoreWriteCompletion::UpdateMany {
                            operation,
                            result_tx,
                            outcome,
                        });
                    }
                    NodeStoreWriteWork::Rekey {
                        old_node_key_hex,
                        new_node_key_hex,
                        rec,
                        changes,
                        final_presence_node_id,
                        result_tx,
                    } => {
                        if old_node_key_hex != new_node_key_hex {
                            next.remove(&old_node_key_hex);
                        }
                        next.insert(new_node_key_hex, *rec);
                        publish_snapshot = true;
                        completions.push(NodeStoreWriteCompletion::Unit {
                            operation: "replace_key",
                            result_tx,
                            changes,
                            final_presence_node_id,
                        });
                    }
                }
                // Retire before the next queued operation can acquire a new
                // incarnation, including delete/reinsert in the same batch.
                retired |= self.retire_absent_stream_state(&next);
            }
            for completion in &mut completions {
                if let NodeStoreWriteCompletion::UpdateBool { outcome, .. } = completion
                    && let Some(node_id) = outcome.final_presence_node_id
                    && !next
                        .iter()
                        .any(|(node_key, rec)| rec.stable_node_id_for_key(node_key) == node_id)
                {
                    outcome.mark_absent_after_batch();
                }
                if let NodeStoreWriteCompletion::Unit {
                    changes,
                    final_presence_node_id: Some(node_id),
                    ..
                } = completion
                    && !next
                        .iter()
                        .any(|(node_key, rec)| rec.stable_node_id_for_key(node_key) == *node_id)
                {
                    changes.clear();
                }
                if let NodeStoreWriteCompletion::UpdateMany { outcome, .. } = completion {
                    outcome.revalidate_final_presence_after_batch(&next);
                }
            }
            if publish_snapshot {
                *g = Arc::new(next);
            }
        }
        self.notify_retired_streams(retired);

        let elapsed = start.elapsed();
        for completion in &completions {
            let operation = match completion {
                NodeStoreWriteCompletion::Bool { operation, .. }
                | NodeStoreWriteCompletion::Delete { operation, .. }
                | NodeStoreWriteCompletion::UpdateBool { operation, .. }
                | NodeStoreWriteCompletion::UpdateMany { operation, .. }
                | NodeStoreWriteCompletion::Unit { operation, .. } => operation,
            };
            self.record_nodestore_operation(operation, elapsed);
        }
        self.record_nodestore_batch(completions.len(), elapsed);
        for completion in completions {
            match completion {
                NodeStoreWriteCompletion::Bool {
                    result_tx, result, ..
                } => {
                    let _ = result_tx.send(result);
                }
                NodeStoreWriteCompletion::Delete {
                    result_tx, removed, ..
                } => {
                    // A vanished caller cannot take responsibility for release.
                    if let Err(std_mpsc::SendError(Some(removed))) = result_tx.send(removed) {
                        self.release_removed_node_addresses(removed);
                    }
                }
                NodeStoreWriteCompletion::UpdateBool {
                    result_tx, outcome, ..
                } => {
                    if let Some(change) = outcome.change.clone() {
                        self.wake_waiters_with(change);
                    }
                    let _ = result_tx.send(outcome);
                }
                NodeStoreWriteCompletion::UpdateMany {
                    result_tx, outcome, ..
                } => {
                    if let Some(change) = outcome.change.clone() {
                        self.wake_waiters_with(change);
                    }
                    let _ = result_tx.send(outcome);
                }
                NodeStoreWriteCompletion::Unit {
                    result_tx, changes, ..
                } => {
                    if !changes.is_empty() {
                        self.wake_waiters_with_many(changes);
                    }
                    let _ = result_tx.send(());
                }
            }
        }
    }

    pub(crate) fn wake_node_change(&self, reason: MapChangeReason, node_id: u64) {
        self.wake_waiters_with(PendingMapChange::origin(reason, node_id));
    }

    fn finish_volatile_node_update(
        &self,
        outcome: &NodeStoreBoolUpdateOutcome,
        reason: MapChangeReason,
    ) -> Result<bool, String> {
        if outcome.applied
            && let Some(id) = outcome.final_presence_node_id
        {
            let policy_changed = self.try_refresh_policy_node_inputs()?;
            match reason {
                MapChangeReason::TagUpdate if policy_changed.is_some() => {
                    if policy_changed == Some(true) {
                        self.wake_policy_change(Some(id));
                    } else {
                        self.wake_node_change(MapChangeReason::NodeAdded, id);
                    }
                }
                MapChangeReason::PolicyChange => self.wake_policy_change(None),
                _ if policy_changed == Some(true) => self.wake_policy_change(None),
                MapChangeReason::RouteUpdate => {
                    self.wake_waiters_with(PendingMapChange::broadcast_peer(reason, id));
                }
                _ => self.wake_node_change(reason, id),
            }
        }
        Ok(outcome.applied)
    }

    pub(crate) fn wake_policy_change(&self, origin: Option<u64>) {
        let mut change = PendingMapChange::global(MapChangeReason::PolicyChange);
        change.origin_node_id = origin;
        self.wake_waiters_with(change);
    }

    pub(crate) fn wake_node_expiry_change(
        &self,
        node_id: u64,
        policy_changed: bool,
        online_changed: bool,
    ) {
        let added = PendingMapChange::origin(MapChangeReason::NodeAdded, node_id);
        let change = if policy_changed {
            // SetNodeExpiry merges NodeAdded into a preceding policy change,
            // retaining its origin and explicit peer ID in one change.
            let mut change = PendingMapChange::global(MapChangeReason::PolicyChange);
            change.origin_node_id = added.origin_node_id;
            change.content.merge(added.content);
            change.companion_reasons.push(MapChangeReason::NodeAdded);
            change
        } else if online_changed && self.node_needs_peer_recompute(node_id) {
            added.with_companion_reason(MapChangeReason::PolicyChange)
        } else {
            added
        };
        self.wake_waiters_with(change);
    }

    pub(crate) fn queue_self_refresh(&self, node_id: u64) {
        self.pending_self_refreshes.lock().insert(node_id);
    }

    pub(crate) fn dispatch_map_change(&self, change: Option<(MapChangeReason, u64)>) {
        self.wake_waiters_with_many(
            change
                .into_iter()
                .map(|(reason, id)| {
                    if reason == MapChangeReason::PolicyChange {
                        PendingMapChange::global(reason)
                    } else {
                        PendingMapChange::origin(reason, id)
                    }
                })
                .collect(),
        );
    }

    /// Wake all live map streams with an upstream-style `user removed`
    /// full update.
    pub fn wake_user_removed_full_update(&self) {
        self.wake_waiters_with(PendingMapChange::global(MapChangeReason::UserRemoved));
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

    /// Capture records and their retained side tables while the NodeStore
    /// writer is excluded. Side tables use COW, so response rebuilds retain
    /// raw Hostinfo and loaded associations without per-record copies.
    pub(crate) fn snapshot_with_metadata(&self) -> MachineSnapshot {
        let records = self.inner.read();
        let hostinfo = self.hostinfo_snapshots.read();
        #[cfg(feature = "admin")]
        let native = self.native_persistence.read();
        MachineSnapshot {
            records: records.clone(),
            hostinfo: hostinfo.clone(),
            node_attrs: None,
            #[cfg(feature = "admin")]
            native: native.clone(),
        }
    }

    pub(crate) fn primary_route_assignments(&self) -> BTreeMap<String, u64> {
        let snapshot = self.snapshot();
        let mut primary_routes = self.primary_routes.write();
        self.sync_primary_routes_for_snapshot(&mut primary_routes, &snapshot);
        primary_routes.primary_assignments()
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
                let rec = snapshot.get(node_key)?;
                let routes = primary_routes.primary_routes(rec.stable_node_id_for_key(node_key));
                if routes.is_empty() {
                    None
                } else {
                    Some((node_key.clone(), routes))
                }
            })
            .collect()
    }

    fn sort_machine_records_by_node_id(records: &mut [(String, MachineRecord)]) {
        records.sort_by(|(left_key, left), (right_key, right)| {
            left.stable_node_id_for_key(left_key)
                .cmp(&right.stable_node_id_for_key(right_key))
                .then_with(|| left_key.cmp(right_key))
        });
    }

    /// Return the first node matching a machine key regardless of user.
    ///
    /// Headscale-go keeps a secondary `MachineKey -> UserID -> Node`
    /// index for this lookup. The runtime registry remains scan-backed;
    /// when more than one user has the same machine key, choosing the
    /// lowest stable node ID gives deterministic behavior for the Go
    /// API's otherwise unspecified map iteration order.
    pub fn get_by_machine_key_any_user(
        &self,
        machine_key_hex: &str,
    ) -> Option<(String, MachineRecord)> {
        if machine_key_hex.is_empty() {
            return None;
        }

        let start = Instant::now();
        let result = {
            let mut matches = self
                .inner
                .read()
                .iter()
                .filter(|(_, rec)| rec.machine_key_hex == machine_key_hex)
                .map(|(node_key, rec)| (node_key.clone(), rec.clone()))
                .collect::<Vec<_>>();
            Self::sort_machine_records_by_node_id(&mut matches);
            matches.into_iter().next()
        };
        self.record_nodestore_operation("get_by_machine_key_any_user", start.elapsed());
        result
    }

    /// Return user-owned nodes for a user ID.
    ///
    /// Tagged nodes are owned by tags rather than their registering
    /// user, so they are intentionally excluded just like
    /// headscale-go's `nodesByUser` snapshot index.
    pub fn list_nodes_by_user_id(&self, user_id: u64) -> Vec<(String, MachineRecord)> {
        let start = Instant::now();
        let mut nodes = self
            .inner
            .read()
            .iter()
            .filter(|(_, rec)| rec.user_id == Some(user_id) && !rec.is_tagged())
            .map(|(node_key, rec)| (node_key.clone(), rec.clone()))
            .collect::<Vec<_>>();
        Self::sort_machine_records_by_node_id(&mut nodes);
        self.record_nodestore_operation("list_by_user", start.elapsed());
        nodes
    }

    /// Return policyless runtime peers for a node ID.
    ///
    /// The map stream applies policy-aware peer visibility in
    /// `tailscale_wire::map`. This read helper mirrors the registry's
    /// open-default peer set by returning every other node when the
    /// source node exists, and an empty list when it does not.
    pub fn list_peers_for(&self, node_id: u64) -> Vec<(String, MachineRecord)> {
        let start = Instant::now();
        let mut source_exists = false;
        let mut peers = Vec::new();
        for (node_key, rec) in self.inner.read().iter() {
            if rec.stable_node_id_for_key(node_key) == node_id {
                source_exists = true;
            } else {
                peers.push((node_key.clone(), rec.clone()));
            }
        }

        let result = if source_exists {
            Self::sort_machine_records_by_node_id(&mut peers);
            peers
        } else {
            Vec::new()
        };
        self.record_nodestore_operation("list_peers", start.elapsed());
        result
    }

    /// Return the current primary advertiser for a subnet prefix.
    pub fn primary_route_for(&self, route: &str) -> Option<u64> {
        let start = Instant::now();
        let snapshot = self.snapshot();
        let result = {
            let mut primary_routes = self.primary_routes.write();
            self.sync_primary_routes_for_snapshot(&mut primary_routes, &snapshot);
            primary_routes.primary_route_for(route)
        };
        self.record_nodestore_operation("primary_route_for", start.elapsed());
        result
    }

    /// Return HA route candidates: non-exit prefixes with at least two
    /// online, non-expired nodes actively advertising and approved for
    /// the route.
    pub fn ha_nodes(&self) -> BTreeMap<String, Vec<u64>> {
        let start = Instant::now();
        let snapshot = self.snapshot();
        let online_states = self.online_states.read().clone();
        let now = Utc::now();
        let mut advertisers = BTreeMap::<String, Vec<u64>>::new();

        for (node_key, rec) in snapshot.iter() {
            let node_id = rec.stable_node_id_for_key(node_key);
            if rec.is_expired_at(now) || !online_states.get(&node_id).copied().unwrap_or(false) {
                continue;
            }

            for route in active_primary_routes(&rec.available_routes, &rec.approved_routes) {
                advertisers.entry(route).or_default().push(node_id);
            }
        }

        advertisers.retain(|_, node_ids| {
            node_ids.sort_unstable();
            node_ids.dedup();
            node_ids.len() >= 2
        });
        self.record_nodestore_operation("ha_nodes", start.elapsed());
        advertisers
    }

    /// Return the current primary-route debug state after syncing it
    /// against the supplied registry snapshot.
    pub fn debug_routes_for_snapshot(
        &self,
        snapshot: &HashMap<String, MachineRecord>,
    ) -> DebugRoutes {
        let mut primary_routes = self.primary_routes.write();
        self.sync_primary_routes_for_snapshot(&mut primary_routes, snapshot);
        let mut routes = primary_routes.debug_routes();
        routes.available_routes = self.debug_available_routes_for_snapshot(snapshot);
        routes
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
            self.wake_waiters_with(PendingMapChange::broadcast_peer(
                MapChangeReason::RouteHealthUpdate,
                node_id,
            ));
        }
        changed
    }

    pub fn set_route_candidate_health_batch<I>(&self, updates: I) -> bool
    where
        I: IntoIterator<Item = (u64, bool)>,
    {
        let snapshot = self.snapshot();
        let mut primary_routes = self.primary_routes.write();
        self.sync_primary_routes_for_snapshot(&mut primary_routes, &snapshot);

        let gated_updates = updates
            .into_iter()
            .filter(|(node_id, healthy)| *healthy || primary_routes.has_routes(*node_id))
            .collect::<Vec<_>>();
        if gated_updates.is_empty() {
            return false;
        }

        let changed = primary_routes.set_node_health_batch(gated_updates);
        if changed {
            self.wake_waiters_with(PendingMapChange::global(MapChangeReason::RouteHealthUpdate));
        }
        changed
    }

    pub fn is_route_candidate_healthy(&self, node_id: u64) -> bool {
        self.primary_routes.read().is_node_healthy(node_id)
    }

    fn debug_available_routes_for_snapshot(
        &self,
        snapshot: &HashMap<String, MachineRecord>,
    ) -> BTreeMap<u64, Vec<String>> {
        let now = Utc::now();
        let online_states = self.online_states.read().clone();
        snapshot
            .iter()
            .filter_map(|(node_key, rec)| {
                let node_id = rec.stable_node_id_for_key(node_key);
                if rec.is_expired_at(now) || !online_states.get(&node_id).copied().unwrap_or(false)
                {
                    return None;
                }

                let mut routes =
                    active_approved_routes(&rec.available_routes, &rec.approved_routes);
                if routes.is_empty() {
                    None
                } else {
                    // Go State.DebugRoutes: slices.SortFunc(approved, netip.Prefix.Compare).
                    routes.sort_by(|a, b| {
                        headscale_api_acl::go_netip::prefix_compare(a, b)
                            .unwrap_or_else(|| a.cmp(b))
                    });
                    Some((node_id, routes))
                }
            })
            .collect()
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
                    let node_id = rec.stable_node_id_for_key(node_key);
                    !rec.is_expired_at(now) && online_states.get(&node_id).copied().unwrap_or(false)
                })
                .map(|(node_key, rec)| {
                    (
                        rec.stable_node_id_for_key(node_key),
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
        let (mut connection, change) =
            Self::acquire_stream_connection(machines, node_id, offline_grace, false);
        connection.record_ended = true;
        connection
            .machines
            .dispatch_stream_connection_change(&connection, change);
        connection
    }

    fn track_stream_connection_quiet(
        machines: Arc<Self>,
        node_id: u64,
    ) -> (StreamConnectionGuard, Option<PendingMapChange>) {
        Self::acquire_stream_connection(machines, node_id, STREAM_OFFLINE_GRACE, true)
    }

    fn acquire_stream_connection(
        machines: Arc<Self>,
        node_id: u64,
        offline_grace: Duration,
        native: bool,
    ) -> (StreamConnectionGuard, Option<PendingMapChange>) {
        let native_work = native.then(|| machines.native_shutdown.begin()).flatten();
        let shutdown = machines.native_shutdown.clone();
        let active = machines.active_connections.clone();
        let sessions = machines.state_sessions.clone();
        let online = machines.online_states.clone();
        let generations = machines.connection_generations.clone();
        let epochs = machines.stream_session_epochs.clone();
        let disconnected = machines.disconnected_at.clone();
        let flags = machines.stream_cancel_flags.clone();
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancel_flag = cancelled.clone();
        let result = Arc::new(Mutex::new(None));
        let captured = result.clone();
        let outcome = machines.apply_nodestore_bool_update(
            "update",
            Box::new(move |records| {
                if native && shutdown.is_closing() {
                    cancel_flag.store(true, Ordering::SeqCst);
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                }
                let Some((_, record)) = records
                    .iter()
                    .find(|(key, record)| record.stable_node_id_for_key(key) == node_id)
                else {
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                };
                // Acquire state and batcher ownership in the same writer
                // operation as expiry/online selection. A missing node owns
                // no session, flag, generation or synthetic online entry.
                let mut epochs = epochs.write();
                let epoch = epochs
                    .entry(node_id)
                    .or_insert_with(|| Arc::new(()))
                    .clone();
                let mut active = active.write();
                *active.entry(node_id).or_default() += 1;
                *sessions.write().entry(node_id).or_default() += 1;
                let generation = {
                    let mut generations = generations.write();
                    let next = generations
                        .get(&node_id)
                        .copied()
                        .unwrap_or(0)
                        .wrapping_add(1);
                    generations.insert(node_id, next);
                    next
                };
                disconnected.write().remove(&node_id);
                let should_be_online = !record.is_expired_at(Utc::now());
                online.write().insert(node_id, should_be_online);
                flags.write().entry(node_id).or_default().push(cancel_flag);
                *captured.lock() = Some((record.clone(), generation, should_be_online, epoch));
                NodeStoreBoolUpdateOutcome {
                    final_presence_node_id: Some(node_id),
                    clear_unhealthy_route_state: Some(node_id),
                    ..NodeStoreBoolUpdateOutcome::quiet(true)
                }
            }),
        );
        let acquired = result.lock().take();
        let generation = acquired
            .as_ref()
            .map_or(0, |(_, generation, _, _)| *generation);
        let epoch = acquired
            .as_ref()
            .map_or_else(|| Arc::new(()), |(_, _, _, epoch)| epoch.clone());
        let mut change = None;
        if let Some((record, _, should_be_online, _)) = &acquired {
            // Acquire the stream before cancelling GC. A timer already waiting
            // behind the machine guard must observe this acquired stream.
            if let Some(node_key) = machines.ephemeral_node_key_by_id(node_id)
                && let Some(gc) = machines.ephemeral_gc()
            {
                gc.cancel(&node_key);
            }
            if outcome.applied {
                let policy = machines.policy_store.read().clone();
                change = Some(PendingMapChange::lifecycle_peer(
                    if *should_be_online {
                        MapChangeReason::NodeOnline
                    } else {
                        MapChangeReason::NodeAdded
                    },
                    node_id,
                    record_needs_peer_recompute(record, policy.as_ref()),
                ));
            }
        }
        (
            StreamConnectionGuard {
                machines,
                node_id,
                generation,
                epoch,
                acquired: acquired.is_some(),
                record_ended: false,
                native_work,
                offline_grace,
                cancelled,
            },
            change,
        )
    }

    fn dispatch_stream_connection_change(
        &self,
        connection: &StreamConnectionGuard,
        change: Option<PendingMapChange>,
    ) {
        let Some(change) = change else {
            return;
        };
        self.with_current_stream_connection(connection, || self.wake_waiters_with(change));
    }

    fn dispatch_initial_stream_changes(
        &self,
        connection: &StreamConnectionGuard,
        request_change: Option<(MapChangeReason, u64)>,
        connection_change: Option<PendingMapChange>,
    ) {
        self.with_current_stream_connection(connection, || {
            self.dispatch_map_change(request_change);
            if let Some(change) = connection_change {
                self.wake_waiters_with(change);
            }
        });
    }

    fn with_current_stream_connection(
        &self,
        connection: &StreamConnectionGuard,
        publish: impl FnOnce(),
    ) {
        // Retirement shares the NodeStore writer. Do not publish an acquired
        // session's change after its node incarnation has been replaced.
        let records = self.inner.read();
        if connection.acquired
            && self.stream_epoch_matches(connection.node_id, Some(&connection.epoch))
            && records
                .iter()
                .any(|(key, record)| record.stable_node_id_for_key(key) == connection.node_id)
        {
            publish();
        }
    }

    /// Stop native map work and wait for owned mutations, transports and
    /// disconnect persistence. Stop GC timers first, while retaining the
    /// batcher and database until all owned map cleanup is complete.
    #[doc(hidden)]
    pub async fn shutdown_native_streams(&self) {
        if let Some(gc) = self.ephemeral_gc() {
            // Go closes ephemeral GC before closing the map batcher. Its
            // closed flag also prevents disconnect cleanup from rearming it.
            gc.abort_all();
        }
        {
            // Stream acquisition uses this writer too, so no native session
            // can register a new flag after shutdown's cancellation sweep.
            let _records = self.inner.write();
            self.native_shutdown.mark_closing();
            for flags in self.stream_cancel_flags.read().values() {
                for flag in flags {
                    flag.store(true, Ordering::SeqCst);
                }
            }
        }
        self.native_shutdown.wake();
        self.gen_tx.send_modify(|_| {});
        self.native_shutdown.drained().await;
    }

    fn begin_native_work(&self) -> Option<native_shutdown::NativeWork> {
        self.native_shutdown.begin()
    }

    async fn native_shutdown_started(&self) {
        self.native_shutdown.closing().await;
    }

    pub fn connection_generation(&self, node_id: u64) -> Option<u64> {
        self.connection_generations.read().get(&node_id).copied()
    }

    pub fn is_stream_connected(&self, node_id: u64) -> bool {
        self.active_connections
            .read()
            .get(&node_id)
            .copied()
            .unwrap_or(0)
            > 0
    }

    fn mark_route_health_session_stable(&self, node_id: u64, generation: u64) -> bool {
        let mut sessions = self.route_health_stable_sessions.write();
        let previous = sessions.insert(node_id, generation);
        previous == Some(generation)
    }

    fn forget_route_health_session(&self, node_id: u64) {
        self.route_health_stable_sessions.write().remove(&node_id);
    }

    fn retain_route_health_sessions<I>(&self, node_ids: I)
    where
        I: IntoIterator<Item = u64>,
    {
        let keep = node_ids.into_iter().collect::<BTreeSet<_>>();
        self.route_health_stable_sessions
            .write()
            .retain(|node_id, _generation| keep.contains(node_id));
    }

    /// Batcher.RemoveNode: remove the channel now, leaving state ownership
    /// for the handler's deferred Disconnect after reconnect grace.
    fn release_stream_connection(&self, node_id: u64, epoch: &Arc<()>) -> Option<bool> {
        let epochs = self.stream_session_epochs.read();
        if !epochs
            .get(&node_id)
            .is_some_and(|current| Arc::ptr_eq(current, epoch))
        {
            return None;
        }
        let mut active = self.active_connections.write();
        let Some(count) = active.get_mut(&node_id) else {
            return Some(false);
        };
        *count = count.saturating_sub(1);
        let still_connected = *count > 0;
        if !still_connected {
            self.disconnected_at.write().insert(node_id, Instant::now());
        }
        Some(still_connected)
    }

    fn cancel_stream_connections(&self, node_id: u64) {
        let flags = self.stream_cancel_flags.read();
        if let Some(flags) = flags.get(&node_id) {
            for flag in flags {
                flag.store(true, Ordering::SeqCst);
            }
        }
    }

    /// Remove long-offline zero-count batcher entries without deleting nodes.
    ///
    /// Headscale-go keeps disconnected entries in the batcher for quick
    /// reconnects, then evicts only the in-memory batcher state after the
    /// node has stayed offline for [`BATCHER_OFFLINE_CLEANUP_THRESHOLD`].
    /// This mirrors that behavior for `/debug/batcher` and volatile
    /// stream-session bookkeeping.
    pub fn cleanup_offline_connections(&self, threshold: Duration) -> Vec<u64> {
        let now = Instant::now();
        let candidates = self
            .disconnected_at
            .read()
            .iter()
            .filter_map(|(node_id, disconnected_at)| {
                (now.saturating_duration_since(*disconnected_at) >= threshold).then_some(*node_id)
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Vec::new();
        }

        let mut active = self.active_connections.write();
        let mut disconnected_at = self.disconnected_at.write();
        let mut route_health_sessions = self.route_health_stable_sessions.write();
        let mut cleaned = Vec::new();

        for node_id in candidates {
            if active.get(&node_id).copied().unwrap_or(0) != 0 {
                continue;
            }
            let Some(disconnected) = disconnected_at.get(&node_id).copied() else {
                continue;
            };
            if now.saturating_duration_since(disconnected) < threshold {
                continue;
            }

            active.remove(&node_id);
            disconnected_at.remove(&node_id);
            route_health_sessions.remove(&node_id);
            self.pending_map_changes.write().remove(&node_id);
            cleaned.push(node_id);
        }

        cleaned
    }

    fn schedule_state_session_release(
        machines: Arc<Self>,
        node_id: u64,
        generation: u64,
        epoch: Arc<()>,
        still_connected: bool,
        offline_grace: Duration,
        native_work: Option<native_shutdown::NativeWork>,
    ) {
        let may_reconnect = machines.inner.read().iter().any(|(key, record)| {
            record.stable_node_id_for_key(key) == node_id && !record.is_expired_at(Utc::now())
        });
        // A replacement stream, missing node or expired key skips grace, but
        // never skips releasing the session acquired by this particular guard.
        if still_connected || !may_reconnect || offline_grace.is_zero() {
            machines.release_state_session_in_epoch(node_id, generation, Some(epoch), native_work);
            return;
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let start = tokio::time::Instant::now();
                let deadline = start + offline_grace;
                let mut ticker = tokio::time::interval_at(
                    start + Duration::from_secs(1),
                    Duration::from_secs(1),
                );
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    if machines.is_stream_connected(node_id)
                        || tokio::time::Instant::now() >= deadline
                    {
                        break;
                    }
                    tokio::select! {
                        _ = ticker.tick() => {}
                        () = tokio::time::sleep_until(deadline) => break,
                    }
                }
                machines.release_state_session_in_epoch(
                    node_id,
                    generation,
                    Some(epoch),
                    native_work,
                );
            });
        } else {
            machines.release_state_session_in_epoch(node_id, generation, Some(epoch), native_work);
        }
    }

    #[cfg(test)]
    fn release_state_session(self: &Arc<Self>, node_id: u64, generation: u64) {
        // Preserve existing synthetic NodeStore callers without introducing
        // unowned releases into the production guard path.
        self.release_state_session_in_epoch(node_id, generation, None, None);
    }

    fn release_state_session_in_epoch(
        self: &Arc<Self>,
        node_id: u64,
        generation: u64,
        epoch: Option<Arc<()>>,
        native_work: Option<native_shutdown::NativeWork>,
    ) {
        let sessions = self.state_sessions.clone();
        let online = self.online_states.clone();
        let epochs = self.stream_session_epochs.clone();
        let writer_epoch = epoch.clone();
        let disconnected = Arc::new(Mutex::new(None));
        let captured = disconnected.clone();
        let outcome = self.apply_nodestore_bool_update(
            "update",
            Box::new(move |records| {
                let epochs = epochs.read();
                if let Some(epoch) = &writer_epoch
                    && !epochs
                        .get(&node_id)
                        .is_some_and(|current| Arc::ptr_eq(current, epoch))
                {
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                }
                let Some((_, record)) = records
                    .iter_mut()
                    .find(|(key, record)| record.stable_node_id_for_key(key) == node_id)
                else {
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                };
                let mut sessions = sessions.write();
                let remaining = sessions.entry(node_id).or_default();
                *remaining = remaining.saturating_sub(1);
                if *remaining > 0 {
                    return NodeStoreBoolUpdateOutcome {
                        final_presence_node_id: Some(node_id),
                        ..NodeStoreBoolUpdateOutcome::quiet(true)
                    };
                }
                // Releasing the last state session still stamps LastSeen and
                // dispatches offline when expiry already made IsOnline=false.
                let now = Utc::now();
                online.write().insert(node_id, false);
                record.last_seen = now;
                *captured.lock() = Some((record.clone(), now));
                NodeStoreBoolUpdateOutcome {
                    final_presence_node_id: Some(node_id),
                    clear_unhealthy_route_state: Some(node_id),
                    ..NodeStoreBoolUpdateOutcome::quiet(true)
                }
            }),
        );
        let disconnected = disconnected.lock().take();
        if !outcome.applied {
            return;
        }
        let Some((record, now)) = disconnected else {
            tracing::debug!(
                node_id,
                disconnect_epoch = generation,
                "session released, other control sessions remain"
            );
            return;
        };
        let store = self
            .registration_store
            .read()
            .as_ref()
            .and_then(Weak::upgrade);
        if let Some(store) = store
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let machines = self.clone();
            runtime.spawn(async move {
                let _native_work = native_work;
                if !machines.stream_epoch_matches(node_id, epoch.as_ref()) {
                    return;
                }
                // NodeStore is already offline. Go attempts this best-effort
                // save before Change dispatch and ephemeral timer scheduling.
                if let Err(error) = store.persist_last_seen(node_id, now).await {
                    tracing::warn!(node_id, %error, "failed to persist disconnect LastSeen");
                }
                machines.dispatch_state_disconnect(node_id, &record, epoch.as_ref());
            });
        } else {
            self.dispatch_state_disconnect(node_id, &record, epoch.as_ref());
        }
    }

    fn stream_epoch_matches(&self, node_id: u64, epoch: Option<&Arc<()>>) -> bool {
        epoch.is_none_or(|epoch| {
            self.stream_session_epochs
                .read()
                .get(&node_id)
                .is_some_and(|current| Arc::ptr_eq(current, epoch))
        })
    }

    fn dispatch_state_disconnect(
        &self,
        node_id: u64,
        disconnected_record: &MachineRecord,
        epoch: Option<&Arc<()>>,
    ) {
        // Retirement linearizes under the NodeStore writer. Keep this read
        // guard through synchronous publication and owned timer insertion;
        // epoch locks themselves are released before either operation.
        let records = self.inner.read();
        if !self.stream_epoch_matches(node_id, epoch) {
            return;
        }
        let Some((node_key, record)) = records
            .iter()
            .find(|(key, record)| record.stable_node_id_for_key(key) == node_id)
        else {
            return;
        };
        let policy = self.policy_store.read().clone();
        self.wake_waiters_with(PendingMapChange::lifecycle_peer(
            MapChangeReason::NodeOffline,
            node_id,
            record_needs_peer_recompute(disconnected_record, policy.as_ref()),
        ));
        if let Some(gc) = self.ephemeral_gc() {
            gc.schedule_owned(self, node_key.clone(), record, epoch.cloned());
        }
    }

    pub fn active_connections(&self) -> BTreeMap<u64, usize> {
        self.active_connections.read().clone()
    }

    /// Snapshot volatile `Node.IsOnline` state by stable node ID.
    pub(crate) fn online_states(&self) -> BTreeMap<u64, bool> {
        self.online_states.read().clone()
    }

    #[cfg(feature = "admin")]
    pub(crate) fn update_online_for_expiry(&self, node_id: u64, record: &MachineRecord) -> bool {
        update_online_after_expiry(record, node_id, &self.state_sessions, &self.online_states)
    }

    fn node_needs_peer_recompute(&self, node_id: u64) -> bool {
        let record = self
            .inner
            .read()
            .iter()
            .find(|(key, record)| record.stable_node_id_for_key(key) == node_id)
            .map(|(_, record)| record.clone());
        let policy = self.policy_store.read().clone();
        record
            .as_ref()
            .is_some_and(|record| record_needs_peer_recompute(record, policy.as_ref()))
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
        proto: &str,
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

        let status = code.to_string();
        let endpoint = format!("{method} {path}");
        *self
            .metrics
            .http_requests_go
            .write()
            .entry((
                String::new(),
                status.clone(),
                endpoint.clone(),
                proto.to_string(),
                String::new(),
            ))
            .or_insert(0) += 1;
        self.metrics
            .http_duration_go
            .write()
            .entry((status, endpoint))
            .or_default()
            .observe(HTTP_GO_BUCKETS, seconds);
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

    pub(crate) fn http_request_go_metrics(
        &self,
    ) -> BTreeMap<(String, String, String, String, String), u64> {
        self.metrics.http_requests_go.read().clone()
    }

    pub(crate) fn http_duration_go_metrics(&self) -> BTreeMap<(String, String), HistogramMetric> {
        self.metrics.http_duration_go.read().clone()
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

    pub(crate) fn nodestore_queue_depth(&self) -> usize {
        self.metrics.nodestore_queue_depth.load(Ordering::SeqCst)
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

    fn node_key_by_id(&self, node_id: u64) -> Option<String> {
        self.inner
            .read()
            .iter()
            .find(|(key, record)| record.stable_node_id_for_key(key) == node_id)
            .map(|(key, _)| key.clone())
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

    fn resolve_auto_given_name_from_snapshot(
        snapshot: &HashMap<String, MachineRecord>,
        node_key_hex: &str,
        also_exclude_node_key_hex: Option<&str>,
        raw_hostname: &str,
    ) -> String {
        let base = auto_given_name_base(raw_hostname);
        let mut candidate = base.clone();
        for suffix in 1.. {
            let taken = snapshot.iter().any(|(key, rec)| {
                key != node_key_hex
                    && Some(key.as_str()) != also_exclude_node_key_hex
                    && rec.hostname == candidate
            });
            if !taken {
                return candidate;
            }
            candidate = format!("{base}-{suffix}");
        }
        unreachable!("unbounded suffix search always returns")
    }

    /// Resolve the DNS GivenName for a raw client Hostinfo hostname.
    ///
    /// This mirrors headscale-go's NodeStore collision handling for
    /// registration/update paths: sanitize the raw hostname, fall back to
    /// `node` when nothing survives, then suffix `-1`, `-2`, ... until the
    /// label is unused. The current node key and an optional replaced node
    /// key are excluded so same-machine reauth keeps its existing label.
    pub fn resolve_auto_given_name(
        &self,
        node_key_hex: &str,
        raw_hostname: &str,
        also_exclude_node_key_hex: Option<&str>,
    ) -> String {
        let snapshot = self.inner.read();
        Self::resolve_auto_given_name_from_snapshot(
            snapshot.as_ref(),
            node_key_hex,
            also_exclude_node_key_hex,
            raw_hostname,
        )
    }

    /// Replace a record's node-key index while preserving the record
    /// body. This is the wire-registry equivalent of headscale-go's
    /// `UpdateNode` path during node-key rotation.
    pub fn replace_node_key(
        &self,
        old_node_key_hex: &str,
        new_node_key_hex: String,
        mut rec: MachineRecord,
    ) {
        self.inherit_rekey_node_id(old_node_key_hex, &mut rec);
        let new_id = rec.stable_node_id_for_key(&new_node_key_hex);
        self.replace_node_key_with_change(
            old_node_key_hex,
            new_node_key_hex,
            rec,
            Some(PendingMapChange::target(
                MapChangeReason::FullSelfUpdate,
                new_id,
            )),
        );
    }

    pub(crate) fn try_replace_node_key_auth_completion(
        &self,
        old_node_key_hex: &str,
        new_node_key_hex: String,
        mut rec: MachineRecord,
    ) -> Result<(), String> {
        #[cfg(feature = "admin")]
        if self.finish_native_registration_publication(&rec)? {
            return Ok(());
        }
        let existing = self.get(old_node_key_hex);
        if rec.node_id.is_none() {
            rec.node_id = existing
                .as_ref()
                .map(|record| record.stable_node_id_for_key(old_node_key_hex));
        }
        let new_id = rec.stable_node_id_for_key(&new_node_key_hex);
        let node_key_for_presence = new_node_key_hex.clone();
        self.replace_node_key_with_changes_and_presence(
            old_node_key_hex,
            new_node_key_hex,
            rec,
            Vec::new(),
            Some(new_id),
        );
        let Some(current) = self
            .get(&node_key_for_presence)
            .filter(|node| node.stable_node_id() == new_id)
        else {
            return Ok(());
        };
        let changes = Self::auth_completion_pending_changes_with_policy(
            existing.as_ref(),
            &current,
            new_id,
            self.try_refresh_policy_node_inputs()?,
        );
        self.wake_waiters_with_many(changes);
        Ok(())
    }

    pub(crate) fn replace_node_key_quiet(
        &self,
        old_node_key_hex: &str,
        new_node_key_hex: String,
        mut rec: MachineRecord,
    ) {
        self.inherit_rekey_node_id(old_node_key_hex, &mut rec);
        self.replace_node_key_with_change(old_node_key_hex, new_node_key_hex, rec, None);
    }

    fn inherit_rekey_node_id(&self, old_node_key_hex: &str, record: &mut MachineRecord) {
        if record.node_id.is_none() {
            record.node_id = self
                .inner
                .read()
                .get(old_node_key_hex)
                .map(|old| old.stable_node_id_for_key(old_node_key_hex));
        }
    }

    fn replace_node_key_with_change(
        &self,
        old_node_key_hex: &str,
        new_node_key_hex: String,
        rec: MachineRecord,
        change: Option<PendingMapChange>,
    ) {
        self.replace_node_key_with_changes(
            old_node_key_hex,
            new_node_key_hex,
            rec,
            change.into_iter().collect(),
        );
    }

    fn replace_node_key_with_changes(
        &self,
        old_node_key_hex: &str,
        new_node_key_hex: String,
        rec: MachineRecord,
        changes: Vec<PendingMapChange>,
    ) {
        let final_presence_node_id =
            (!changes.is_empty()).then(|| rec.stable_node_id_for_key(&new_node_key_hex));
        self.replace_node_key_with_changes_and_presence(
            old_node_key_hex,
            new_node_key_hex,
            rec,
            changes,
            final_presence_node_id,
        );
    }

    fn replace_node_key_with_changes_and_presence(
        &self,
        old_node_key_hex: &str,
        new_node_key_hex: String,
        mut rec: MachineRecord,
        changes: Vec<PendingMapChange>,
        final_presence_node_id: Option<u64>,
    ) {
        rec.node_key_hex.clone_from(&new_node_key_hex);
        let queue = self.nodestore_write_queue.read().clone();
        if let Some(queue) = queue.as_ref() {
            self.enqueue_nodestore_rekey(
                queue,
                old_node_key_hex.to_string(),
                new_node_key_hex,
                rec,
                changes,
                final_presence_node_id,
            );
        } else {
            self.apply_nodestore_rekey_direct(old_node_key_hex, new_node_key_hex, rec, changes);
        }
    }

    /// Complete a web/CLI registration for `user`.
    ///
    /// If the pending record proves the same MachineKey as an existing
    /// node for that user, update that node in-place and move it to the
    /// pending NodeKey. This mirrors headscale-go reauth: web auth with
    /// empty `Hostinfo.RequestTags` clears a tagged node back to a
    /// user-owned node instead of creating a duplicate.
    pub(crate) fn auth_path_existing_machine(
        &self,
        machine_key_hex: &str,
        user: &str,
        user_id: Option<u64>,
    ) -> Result<Option<(String, MachineRecord)>, &'static str> {
        let snapshot = self.snapshot();
        let matches = snapshot
            .iter()
            .filter(|(_, node)| node.machine_key_hex == machine_key_hex)
            .map(|(key, node)| (key.clone(), node.clone()))
            .collect::<Vec<_>>();
        let user_owned = matches
            .iter()
            .filter(|(_, node)| {
                node.forced_tags.is_empty()
                    && user_id.map_or_else(|| node.user == user, |id| node.user_id == Some(id))
            })
            .cloned()
            .collect::<Vec<_>>();
        let tagged = matches
            .iter()
            .filter(|(_, node)| !node.forced_tags.is_empty())
            .cloned()
            .collect::<Vec<_>>();
        if user_owned.len() > 1
            || tagged.len() > 1
            || (!user_owned.is_empty() && !tagged.is_empty())
            || (tagged.len() == 1 && matches.len() > 1)
        {
            return Err("machine key maps to ambiguous node ownership");
        }
        Ok(user_owned
            .into_iter()
            .next()
            .or_else(|| tagged.into_iter().next()))
    }

    pub fn complete_web_registration(
        &self,
        pending: MachineRecord,
        user: &str,
        register_method: i32,
    ) -> Result<MachineRecord, &'static str> {
        self.complete_web_registration_with_hostinfo(pending, user, register_method, None)
            .map_err(RegistryMutationError::legacy_message)
    }

    /// Complete a registration while retaining a late policy-resolution error.
    pub fn try_complete_web_registration(
        &self,
        pending: MachineRecord,
        user: &str,
        register_method: i32,
    ) -> Result<MachineRecord, RegistryMutationError> {
        self.complete_web_registration_with_hostinfo(pending, user, register_method, None)
    }

    pub(crate) fn complete_web_registration_with_hostinfo(
        &self,
        mut pending: MachineRecord,
        user: &str,
        register_method: i32,
        requested_hostinfo: Option<serde_json::Value>,
    ) -> Result<MachineRecord, RegistryMutationError> {
        self.validate_registration_node_key(&pending.node_key_hex, &pending.machine_key_hex)?;
        pending.user = user.to_string();
        pending.register_method = register_method;

        // A cached auth payload is a new registration snapshot, so even an
        // empty reported hostname replaces nodes.hostname on this path.
        pending.raw_hostname.clone_from(&pending.host_info.hostname);
        let mut replaced_node_key = None;
        let mut preserved_netinfo = None;
        if let Some((old_node_key, existing)) =
            self.auth_path_existing_machine(&pending.machine_key_hex, user, pending.user_id)?
        {
            preserved_netinfo = self
                .map_hostinfo_value(&existing)
                .map_err(|_| "encoding existing Hostinfo")?
                .get("NetInfo")
                .cloned();
            let was_tagged = !existing.forced_tags.is_empty();
            let existing_net_info = existing.host_info_for_node().net_info;
            pending.node_id = Some(existing.stable_node_id_for_key(&old_node_key));
            replaced_node_key = Some(old_node_key);
            pending.ipv4 = existing.ipv4;
            pending.ipv6 = existing.ipv6;
            pending.user_id = pending.user_id.or(existing.user_id);
            if pending.user_display_name.is_empty() {
                pending.user_display_name = existing.user_display_name;
            }
            if pending.user_profile_pic_url.is_empty() {
                pending.user_profile_pic_url = existing.user_profile_pic_url;
            }
            pending.created_at = existing.created_at;
            pending.ephemeral = if was_tagged && pending.forced_tags.is_empty() {
                false
            } else {
                existing.ephemeral
            };
            pending.auth_key_id = if was_tagged && pending.forced_tags.is_empty() {
                None
            } else {
                pending.auth_key_id.or(existing.auth_key_id)
            };
            if !(was_tagged && pending.forced_tags.is_empty()) {
                pending.register_method = existing.register_method;
            }
            if was_tagged && !pending.forced_tags.is_empty() {
                pending.expiry = existing.expiry.filter(|expiry| *expiry >= Utc::now());
            }
            if pending.endpoints.is_empty() {
                pending.endpoints = existing.endpoints;
            }
            if pending.host_info.net_info.is_none() {
                pending.host_info.net_info = existing_net_info;
            }
            pending.home_derp = pending
                .host_info
                .net_info
                .as_ref()
                .map_or(0, |info| info.preferred_derp);

            pending.approved_routes = existing.approved_routes;
        } else if pending.host_info.net_info.is_none() {
            // Different-account auth creates a new node. Carry only NetInfo
            // from another user on this same proven machine, as Go does.
            let snapshot = self.snapshot();
            let previous = snapshot
                .iter()
                .filter(|(_, node)| {
                    node.machine_key_hex == pending.machine_key_hex
                        && node.forced_tags.is_empty()
                        && pending
                            .user_id
                            .map_or_else(|| node.user != user, |id| node.user_id != Some(id))
                })
                .min_by_key(|(key, node)| node.stable_node_id_for_key(key));
            if let Some((_, node)) = previous {
                pending.host_info.net_info = node.host_info_for_node().net_info;
                preserved_netinfo = self
                    .map_hostinfo_value(node)
                    .map_err(|_| "encoding existing Hostinfo")?
                    .get("NetInfo")
                    .cloned();
            }
        }

        if !pending.forced_tags.is_empty() {
            pending.clear_user_identity();
        }
        pending.home_derp = pending
            .host_info
            .net_info
            .as_ref()
            .map_or(0, |info| info.preferred_derp);
        let now = Utc::now();
        if replaced_node_key.is_none() {
            pending.approved_routes.clear();
            pending.created_at = now;
            pending.ephemeral = false;
            pending.auth_key_id = None;
            if !pending.forced_tags.is_empty() {
                pending.compact_fresh_web_request_tags();
            }
        }
        pending.last_seen = now;
        pending.expiry = self.registration_expiry(pending.expiry, pending.is_tagged(), now);
        let hostinfo = requested_hostinfo
            .map(|requested| {
                hostinfo::registration_value(
                    &requested,
                    &pending.host_info_for_node(),
                    preserved_netinfo.as_ref(),
                )
            })
            .transpose()
            .map_err(|_| "encoding registration Hostinfo")?;
        self.commit_volatile_auth_registration_with_hostinfo(
            replaced_node_key.as_deref(),
            pending,
            hostinfo,
        )
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
    /// Most lifecycle mutators (`set_expiry`, `rename`, `logout`,
    /// `delete`, `set_forced_tags`) route through this helper so the
    /// COW pattern is expressed exactly once. `touch_last_seen` uses a
    /// quiet variant because timestamp-only map bookkeeping is not
    /// peer-visible state and should not wake long-poll streams.
    /// Returns whatever `f` returns — typically a Result so callers can
    /// distinguish "node not found" from "applied".
    pub fn update_with<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&mut HashMap<String, MachineRecord>) -> R,
    {
        self.update_with_operation("update", f)
    }

    /// Refresh live node profiles after a user rename and queue a durable
    /// policy map change. A plain NodeUpdated wake can be processed before a
    /// separate policy notification, leaving autogroup:self filters stale.
    pub fn refresh_user_identity(
        &self,
        user_id: u64,
        login_name: String,
        display_name: String,
        profile_pic_url: String,
    ) -> usize {
        self.update_with_operation_and_optional_change("user identity", move |records| {
            let mut updated = 0;
            for record in records.values_mut() {
                if record.user_id == Some(user_id) {
                    record.set_user_identity(
                        Some(user_id),
                        login_name.clone(),
                        display_name.clone(),
                        profile_pic_url.clone(),
                    );
                    updated += 1;
                }
            }
            (
                updated,
                (updated > 0).then(|| PendingMapChange::global(MapChangeReason::PolicyChange)),
            )
        })
    }

    fn update_with_operation<R, F>(&self, operation: &str, f: F) -> R
    where
        F: FnOnce(&mut HashMap<String, MachineRecord>) -> R,
    {
        self.update_with_operation_and_wake(
            operation,
            Some(PendingMapChange::global(MapChangeReason::NodeUpdated)),
            f,
        )
    }

    fn update_with_operation_and_optional_change<R, F>(&self, operation: &str, f: F) -> R
    where
        F: FnOnce(&mut HashMap<String, MachineRecord>) -> (R, Option<PendingMapChange>),
    {
        let start = Instant::now();
        let mut retired = false;
        let (r, change) = {
            let mut g = self.inner.write();
            let mut next = (**g).clone();
            let (r, change) = f(&mut next);
            // `None` means the caller observed no lifecycle mutation, so keep
            // the current snapshot/generation intact.
            if change.is_some() {
                retired = self.retire_absent_stream_state(&next);
                *g = Arc::new(next);
            }
            (r, change)
        };
        self.notify_retired_streams(retired);
        let elapsed = start.elapsed();
        self.record_nodestore_operation(operation, elapsed);
        if let Some(change) = change {
            self.record_nodestore_batch(1, elapsed);
            self.wake_waiters_with(change);
        }
        r
    }

    fn update_with_operation_and_wake<R, F>(
        &self,
        operation: &str,
        change: Option<PendingMapChange>,
        f: F,
    ) -> R
    where
        F: FnOnce(&mut HashMap<String, MachineRecord>) -> R,
    {
        let start = Instant::now();
        let retired;
        let r = {
            let mut g = self.inner.write();
            let mut next = (**g).clone();
            let r = f(&mut next);
            retired = self.retire_absent_stream_state(&next);
            *g = Arc::new(next);
            r
        };
        self.notify_retired_streams(retired);
        let elapsed = start.elapsed();
        self.record_nodestore_operation(operation, elapsed);
        self.record_nodestore_batch(1, elapsed);
        if let Some(change) = change {
            self.wake_waiters_with(change);
        }
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
        self.try_set_expiry(node_key_hex, expiry)
            .unwrap_or_else(|error| {
                tracing::error!(%error, "updating policy manager after expiry");
                false
            })
    }

    /// State.SetNodeExpiry's live phase, for callers that must persist before
    /// policy refresh/dispatch. Retain both the accepted view and the original
    /// online transition instead of applying a second expiry edit after SQL.
    pub(crate) fn set_node_expiry_quiet(
        &self,
        node_id: u64,
        expiry: Option<DateTime<Utc>>,
    ) -> Option<(MachineRecord, bool)> {
        let sessions = self.state_sessions.clone();
        let online = self.online_states.clone();
        let result = Arc::new(Mutex::new(None));
        let captured = result.clone();
        let outcome = self.apply_nodestore_bool_update(
            "update",
            Box::new(move |records| {
                let Some((_, record)) = records
                    .iter_mut()
                    .find(|(key, record)| record.stable_node_id_for_key(key) == node_id)
                else {
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                };
                record.expiry = expiry;
                let changed = update_online_after_expiry(record, node_id, &sessions, &online);
                *captured.lock() = Some((record.clone(), changed));
                NodeStoreBoolUpdateOutcome {
                    final_presence_node_id: Some(node_id),
                    ..NodeStoreBoolUpdateOutcome::quiet(true)
                }
            }),
        );
        let result = result.lock().take();
        outcome.applied.then_some(result).flatten()
    }

    /// Set expiry and report a subsequent policy-manager refresh failure.
    pub fn try_set_expiry(
        &self,
        node_key_hex: &str,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<bool, String> {
        let node_key_hex = node_key_hex.to_string();
        let online = self.online_states.clone();
        let active = self.state_sessions.clone();
        let changed = Arc::new(AtomicBool::new(false));
        let online_changed = changed.clone();
        let outcome = self.apply_nodestore_bool_update(
            "update",
            Box::new(move |map| match map.get_mut(&node_key_hex) {
                Some(rec) => {
                    let node_id = rec.stable_node_id_for_key(&node_key_hex);
                    rec.expiry = expiry;
                    online_changed.store(
                        update_online_after_expiry(rec, node_id, &active, &online),
                        Ordering::SeqCst,
                    );
                    NodeStoreBoolUpdateOutcome {
                        final_presence_node_id: Some(node_id),
                        ..NodeStoreBoolUpdateOutcome::quiet(true)
                    }
                }
                None => NodeStoreBoolUpdateOutcome::unchanged(false),
            }),
        );
        if outcome.applied
            && let Some(node_id) = outcome.final_presence_node_id
        {
            self.wake_node_expiry_change(
                node_id,
                self.try_refresh_policy_node_inputs()? == Some(true),
                changed.load(Ordering::SeqCst),
            );
        }
        Ok(outcome.applied)
    }

    /// Rename a machine. Upstream's `db.NodeRenameNode` validates
    /// against `dnsname.ValidLabel` and rejects duplicate GivenNames
    /// without auto-suffixing.
    pub fn rename(&self, node_key_hex: &str, new_hostname: String) -> bool {
        self.try_rename(node_key_hex, new_hostname)
            .unwrap_or_else(|error| {
                tracing::error!(%error, "updating policy manager after rename");
                false
            })
    }

    /// Rename and report any subsequent policy-refresh error.
    pub fn try_rename(&self, node_key_hex: &str, new_hostname: String) -> Result<bool, String> {
        if self.validate_given_name(&new_hostname).is_err() {
            return Ok(false);
        }
        let node_key_hex = node_key_hex.to_string();
        let outcome = self.apply_nodestore_bool_update(
            "set_name",
            Box::new(move |map| {
                if !valid_given_name_label(&new_hostname) {
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                }
                if map
                    .iter()
                    .any(|(key, rec)| key != &node_key_hex && rec.hostname == new_hostname)
                {
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                }
                match map.get_mut(&node_key_hex) {
                    Some(rec) => {
                        let node_id = rec.stable_node_id_for_key(&node_key_hex);
                        rec.hostname = new_hostname;
                        NodeStoreBoolUpdateOutcome {
                            final_presence_node_id: Some(node_id),
                            ..NodeStoreBoolUpdateOutcome::quiet(true)
                        }
                    }
                    None => NodeStoreBoolUpdateOutcome::unchanged(false),
                }
            }),
        );
        self.finish_volatile_node_update(&outcome, MapChangeReason::NodeAdded)
    }

    /// Logout a machine: stamps `expiry = now()` so the next `/map`
    /// round-trip returns a logout response while preserving the
    /// machine key that the Noise session is bound to.
    ///
    /// Mirrors `db.NodeLogout`. The record stays in the registry —
    /// upstream behaviour is "logged-out node still exists, but must
    /// re-authenticate." `delete` is the destructive counterpart.
    pub fn logout(&self, node_key_hex: &str) -> bool {
        self.set_expiry(node_key_hex, Some(Utc::now()))
    }

    /// Remove a machine from the registry entirely. Mirrors
    /// `db.DeleteNode`. Returns `true` on success.
    pub fn delete(&self, node_key_hex: &str) -> bool {
        self.try_delete(node_key_hex).unwrap_or_else(|error| {
            tracing::error!(%error, "updating policy manager after node deletion");
            false
        })
    }

    /// Delete and report a subsequent policy-manager refresh failure. Cache,
    /// sessions and address release are not rolled back after that late error.
    pub fn try_delete(&self, node_key_hex: &str) -> Result<bool, String> {
        let Some(removed) = self.remove_node_quiet(node_key_hex) else {
            return Ok(false);
        };
        let node_id = removed.id;
        self.release_removed_node_addresses(removed);
        self.finish_node_removal(node_id)?;
        Ok(true)
    }

    /// Durable native deletion keeps its save mutex through this cache phase,
    /// then releases it before address release, policy refresh and dispatch.
    pub(crate) fn remove_node_quiet(&self, node_key_hex: &str) -> Option<RemovedNode> {
        if !self.inner.read().contains_key(node_key_hex) {
            return None;
        }

        let queue = self.nodestore_write_queue.read().clone();
        let removed = if let Some(queue) = queue.as_ref() {
            self.enqueue_nodestore_delete(queue, node_key_hex.to_string())
        } else {
            self.apply_nodestore_delete_direct(node_key_hex)
        };
        if let Some(removed) = &removed {
            self.discard_absent_native_persistence(&[removed.id]);
        }
        removed
    }

    pub(crate) fn release_removed_node_addresses(&self, removed: RemovedNode) {
        self.release_addresses(removed.ipv4, removed.ipv6);
    }

    fn try_delete_gc_owned(
        &self,
        node_key: &str,
        node_id: u64,
        machine_key: &str,
        epoch: Option<Arc<()>>,
    ) -> Result<bool, String> {
        let key = node_key.to_owned();
        let machine_key = machine_key.to_owned();
        let epochs = self.stream_session_epochs.clone();
        let removed = Arc::new(Mutex::new(None));
        let captured = removed.clone();
        self.apply_nodestore_bool_update(
            "delete",
            Box::new(move |records| {
                let epochs = epochs.read();
                if let Some(epoch) = &epoch
                    && !epochs
                        .get(&node_id)
                        .is_some_and(|current| Arc::ptr_eq(current, epoch))
                {
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                }
                if !records.get(&key).is_some_and(|record| {
                    record.stable_node_id_for_key(&key) == node_id
                        && record.machine_key_hex == machine_key
                }) {
                    return NodeStoreBoolUpdateOutcome::unchanged(false);
                }
                if let Some(record) = records.remove(&key) {
                    *captured.lock() = Some(RemovedNode::from_record(&key, &record));
                    NodeStoreBoolUpdateOutcome::quiet(true)
                } else {
                    NodeStoreBoolUpdateOutcome::unchanged(false)
                }
            }),
        );
        let Some(removed) = removed.lock().take() else {
            return Ok(false);
        };
        self.discard_absent_native_persistence(&[node_id]);
        self.release_removed_node_addresses(removed);
        self.finish_node_removal(node_id)?;
        Ok(true)
    }

    pub(crate) fn finish_node_removal(&self, node_id: u64) -> Result<(), String> {
        let mut changes = vec![PendingMapChange::peers_removed(vec![node_id])];
        match self.try_refresh_policy_node_inputs() {
            Ok(Some(true)) => changes.push(PendingMapChange::global(MapChangeReason::PolicyChange)),
            Ok(_) => {}
            Err(error) => {
                self.wake_waiters_with_many(changes);
                return Err(format!(
                    "updating policy manager after node deletion: {error}"
                ));
            }
        }
        self.wake_waiters_with_many(changes);
        Ok(())
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
        let node_key_hex = node_key_hex.to_string();
        self.apply_nodestore_bool_update(
            "touch_last_seen",
            Box::new(move |map| match map.get_mut(&node_key_hex) {
                Some(rec) => {
                    rec.last_seen = now;
                    NodeStoreBoolUpdateOutcome::quiet(true)
                }
                None => NodeStoreBoolUpdateOutcome::unchanged(false),
            }),
        )
        .applied
    }

    /// Replace a machine's `forced_tags` list. Empty-list admin
    /// updates are rejected, matching upstream's `db.SetTags` /
    /// `State.SetNodeTags` boundary.
    pub fn set_forced_tags(&self, node_key_hex: &str, tags: Vec<String>) -> bool {
        self.try_set_forced_tags(node_key_hex, tags)
            .unwrap_or_else(|error| {
                tracing::error!(%error, "updating policy manager after tags");
                false
            })
    }

    /// Set tags and report any subsequent policy-refresh error.
    pub fn try_set_forced_tags(
        &self,
        node_key_hex: &str,
        mut tags: Vec<String>,
    ) -> Result<bool, String> {
        if tags.is_empty() {
            return Ok(false);
        }
        tags.sort();
        tags.dedup();
        let node_key_hex = node_key_hex.to_string();
        let outcome = self.apply_nodestore_bool_update(
            "update",
            Box::new(move |map| match map.get_mut(&node_key_hex) {
                Some(rec) => {
                    let node_id = rec.stable_node_id_for_key(&node_key_hex);
                    rec.forced_tags = tags;
                    rec.clear_user_identity();
                    NodeStoreBoolUpdateOutcome {
                        final_presence_node_id: Some(node_id),
                        ..NodeStoreBoolUpdateOutcome::quiet(true)
                    }
                }
                None => NodeStoreBoolUpdateOutcome::unchanged(false),
            }),
        );
        self.finish_volatile_node_update(&outcome, MapChangeReason::TagUpdate)
    }

    /// Replace a machine's approved subnet routes. Empty list clears
    /// route approval. The register/map paths maintain
    /// `available_routes`; this method records operator approval.
    pub fn set_approved_routes(&self, node_key_hex: &str, routes: Vec<String>) -> bool {
        self.try_set_approved_routes(node_key_hex, routes)
            .unwrap_or_else(|error| {
                tracing::error!(%error, "updating policy manager after route approval");
                false
            })
    }

    /// Set approved routes and report any subsequent policy-refresh error.
    pub fn try_set_approved_routes(
        &self,
        node_key_hex: &str,
        routes: Vec<String>,
    ) -> Result<bool, String> {
        let node_key_hex = node_key_hex.to_string();
        let outcome = self.apply_nodestore_bool_update(
            "update",
            Box::new(move |map| match map.get_mut(&node_key_hex) {
                Some(rec) => {
                    let node_id = rec.stable_node_id_for_key(&node_key_hex);
                    rec.approved_routes = routes;
                    let clear_unhealthy =
                        active_approved_routes(&rec.available_routes, &rec.approved_routes)
                            .is_empty();
                    NodeStoreBoolUpdateOutcome {
                        final_presence_node_id: Some(node_id),
                        clear_unhealthy_route_state: clear_unhealthy.then_some(node_id),
                        ..NodeStoreBoolUpdateOutcome::quiet(true)
                    }
                }
                None => NodeStoreBoolUpdateOutcome::unchanged(false),
            }),
        );
        self.finish_volatile_node_update(&outcome, MapChangeReason::PolicyChange)
    }

    /// Go policy auto-approval updates stable IDs in one quiet NodeStore batch,
    /// then persists still-present nodes. Concurrently absent IDs are skipped.
    pub(crate) fn apply_policy_route_approvals(
        &self,
        updates: Vec<(u64, Vec<String>)>,
    ) -> Vec<u64> {
        if updates.is_empty() {
            return Vec::new();
        }
        let mut updates = updates.into_iter().collect::<HashMap<_, _>>();
        let outcome = self.apply_nodestore_many_update(
            "update_multi",
            Box::new(move |map| {
                let mut ids = Vec::new();
                let mut clear_unhealthy_route_states = Vec::new();
                for (key, record) in map.iter_mut() {
                    let id = record.stable_node_id_for_key(key);
                    if let Some(routes) = updates.remove(&id) {
                        record.approved_routes = routes;
                        if active_approved_routes(&record.available_routes, &record.approved_routes)
                            .is_empty()
                        {
                            clear_unhealthy_route_states.push(id);
                        }
                        ids.push(id);
                    }
                }
                ids.sort_unstable();
                NodeStoreManyUpdateOutcome {
                    applied: ids.len(),
                    publish_snapshot: !ids.is_empty(),
                    clear_unhealthy_route_states,
                    final_presence_node_ids: ids,
                    ..NodeStoreManyUpdateOutcome::unchanged()
                }
            }),
        );
        outcome.final_presence_node_ids
    }

    /// Replace approved routes on multiple machines as one atomic NodeStore
    /// writer item. This mirrors headscale-go `NodeStore.UpdateNodes` for
    /// policy auto-approval fan-out: callers see either the old snapshot or the
    /// fully updated route set, never an intermediate per-node approval.
    pub fn set_approved_routes_many(
        &self,
        updates: Vec<(String, Vec<String>)>,
    ) -> (usize, Vec<String>) {
        self.try_set_approved_routes_many(updates)
            .unwrap_or_else(|error| {
                tracing::error!(%error, "updating policy manager after batch route approval");
                (0, Vec::new())
            })
    }

    /// Batch route approval with a fallible post-mutation policy refresh.
    pub fn try_set_approved_routes_many(
        &self,
        updates: Vec<(String, Vec<String>)>,
    ) -> Result<(usize, Vec<String>), String> {
        if updates.is_empty() {
            return Ok((0, Vec::new()));
        }

        let outcome = self.apply_nodestore_many_update(
            "update_multi",
            Box::new(move |map| {
                let missing_node_keys = updates
                    .iter()
                    .filter(|(node_key_hex, _routes)| !map.contains_key(node_key_hex))
                    .map(|(node_key_hex, _routes)| node_key_hex.clone())
                    .collect::<Vec<_>>();
                if !missing_node_keys.is_empty() {
                    return NodeStoreManyUpdateOutcome {
                        missing_node_keys,
                        ..NodeStoreManyUpdateOutcome::unchanged()
                    };
                }

                let mut applied = 0usize;
                let mut clear_unhealthy_route_states = Vec::new();
                let mut final_presence_node_ids = Vec::new();

                for (node_key_hex, routes) in updates {
                    let Some(rec) = map.get_mut(&node_key_hex) else {
                        continue;
                    };
                    if rec.approved_routes != routes {
                        let node_id = rec.stable_node_id_for_key(&node_key_hex);
                        rec.approved_routes = routes;
                        if active_approved_routes(&rec.available_routes, &rec.approved_routes)
                            .is_empty()
                        {
                            clear_unhealthy_route_states.push(node_id);
                        }
                        final_presence_node_ids.push(node_id);
                        applied += 1;
                    }
                }

                NodeStoreManyUpdateOutcome {
                    applied,
                    publish_snapshot: applied > 0,
                    change: None,
                    clear_unhealthy_route_states,
                    missing_node_keys: Vec::new(),
                    affected_node_keys: Vec::new(),
                    affected_node_ids: Vec::new(),
                    final_presence_node_ids,
                }
            }),
        );

        if outcome.applied > 0 {
            self.try_refresh_policy_node_inputs()?;
            self.wake_policy_change(None);
        }
        Ok((outcome.applied, outcome.missing_node_keys))
    }

    /// Replace a machine's advertised subnet routes. Empty list clears
    /// advertised routes while preserving operator approvals.
    pub fn set_available_routes(&self, node_key_hex: &str, routes: Vec<String>) -> bool {
        self.try_set_available_routes(node_key_hex, routes)
            .unwrap_or_else(|error| {
                tracing::error!(%error, "updating policy manager after advertised routes");
                false
            })
    }

    /// Set advertised routes and report any subsequent policy-refresh error.
    pub fn try_set_available_routes(
        &self,
        node_key_hex: &str,
        routes: Vec<String>,
    ) -> Result<bool, String> {
        let node_key_hex = node_key_hex.to_string();
        let outcome = self.apply_nodestore_bool_update(
            "update",
            Box::new(move |map| match map.get_mut(&node_key_hex) {
                Some(rec) => {
                    if rec.available_routes == routes {
                        return NodeStoreBoolUpdateOutcome::unchanged(true);
                    }
                    let node_id = rec.stable_node_id_for_key(&node_key_hex);
                    rec.available_routes = routes;
                    NodeStoreBoolUpdateOutcome {
                        final_presence_node_id: Some(node_id),
                        ..NodeStoreBoolUpdateOutcome::quiet(true)
                    }
                }
                None => NodeStoreBoolUpdateOutcome::unchanged(false),
            }),
        );
        self.finish_volatile_node_update(&outcome, MapChangeReason::RouteUpdate)
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
        self.try_gc_ephemeral(grace).unwrap_or_else(|error| {
            tracing::error!(%error, "updating policy manager after ephemeral GC");
            Vec::new()
        })
    }

    /// Sweep ephemeral nodes and propagate late policy resolution failure.
    /// Removed records, address release and connection cleanup remain applied.
    pub fn try_gc_ephemeral(&self, grace: std::time::Duration) -> Result<Vec<String>, String> {
        let now = Utc::now();
        let cutoff_chrono =
            chrono::Duration::from_std(grace).unwrap_or(chrono::Duration::seconds(0));
        let deadline = now - cutoff_chrono;
        let state_sessions = self.state_sessions.clone();
        let online_states = self.online_states.clone();
        let released_addresses = Arc::new(Mutex::new(Vec::new()));
        let writer_releases = released_addresses.clone();
        let outcome = self.apply_nodestore_many_update(
            "delete_multi",
            Box::new(move |map| {
                let state_sessions = state_sessions.read();
                let online_states = online_states.read();
                let to_drop: Vec<(String, u64)> = map
                    .iter()
                    .filter(|(node_key, rec)| {
                        let node_id = rec.stable_node_id_for_key(node_key);
                        rec.ephemeral
                            && rec.last_seen < deadline
                            && state_sessions.get(&node_id).copied().unwrap_or(0) == 0
                            && !online_states.get(&node_id).copied().unwrap_or(false)
                    })
                    .map(|(k, rec)| (k.clone(), rec.stable_node_id_for_key(k)))
                    .collect();

                if to_drop.is_empty() {
                    return NodeStoreManyUpdateOutcome::unchanged();
                }

                for (node_key_hex, _node_id) in &to_drop {
                    if let Some(record) = map.remove(node_key_hex) {
                        writer_releases.lock().push((record.ipv4, record.ipv6));
                    }
                }

                let affected_node_keys = to_drop
                    .iter()
                    .map(|(node_key_hex, _node_id)| node_key_hex.clone())
                    .collect::<Vec<_>>();
                let affected_node_ids = to_drop
                    .iter()
                    .map(|(_node_key_hex, node_id)| *node_id)
                    .collect::<Vec<_>>();
                NodeStoreManyUpdateOutcome {
                    applied: to_drop.len(),
                    publish_snapshot: true,
                    change: None,
                    clear_unhealthy_route_states: Vec::new(),
                    missing_node_keys: Vec::new(),
                    affected_node_keys,
                    affected_node_ids,
                    final_presence_node_ids: Vec::new(),
                }
            }),
        );
        if outcome.applied == 0 {
            return Ok(Vec::new());
        }

        let releases = std::mem::take(&mut *released_addresses.lock());
        for (ipv4, ipv6) in releases {
            self.release_addresses(ipv4, ipv6);
        }
        let removed_keys = outcome.affected_node_keys;
        let removed_ids = outcome.affected_node_ids;
        self.discard_absent_native_persistence(&removed_ids);
        let mut changes = vec![PendingMapChange::peers_removed(removed_ids)];
        let refreshed = self.try_refresh_policy_node_inputs();
        if refreshed? == Some(true) {
            changes.push(PendingMapChange::global(MapChangeReason::PolicyChange));
        }
        self.wake_waiters_with_many(changes);
        Ok(removed_keys)
    }

    /// Called only with the NodeStore writer held. No NodeStore acquisition or
    /// notification is allowed while the epoch retirement lock is held.
    fn retire_absent_stream_state(&self, records: &HashMap<String, MachineRecord>) -> bool {
        if let Some(gc) = self.ephemeral_gc() {
            gc.retire_absent_timers(records);
        }
        let mut epochs = self.stream_session_epochs.write();
        if epochs.is_empty() {
            return false;
        }
        let live_ids = records
            .iter()
            .map(|(key, record)| record.stable_node_id_for_key(key))
            .collect::<std::collections::HashSet<_>>();
        let removed = epochs
            .keys()
            .filter(|id| !live_ids.contains(id))
            .copied()
            .collect::<Vec<_>>();
        for node_id in &removed {
            epochs.remove(node_id);
            self.cancel_stream_connections(*node_id);
            self.stream_cancel_flags.write().remove(node_id);
            self.active_connections.write().remove(node_id);
            self.state_sessions.write().remove(node_id);
            self.online_states.write().remove(node_id);
            self.connection_generations.write().remove(node_id);
            self.disconnected_at.write().remove(node_id);
            self.route_health_stable_sessions.write().remove(node_id);
            self.pending_map_changes.write().remove(node_id);
        }
        !removed.is_empty()
    }

    fn notify_retired_streams(&self, retired: bool) {
        if retired {
            // Wake sticky deletion watchers after releasing the NodeStore and
            // epoch locks, without inventing another semantic map change.
            self.gen_tx.send_modify(|_| {});
        }
    }

    fn forget_stream_cancel_flag(&self, node_id: u64, cancelled: &Arc<AtomicBool>) {
        let mut flags = self.stream_cancel_flags.write();
        if let Some(node_flags) = flags.get_mut(&node_id) {
            node_flags.retain(|flag| !Arc::ptr_eq(flag, cancelled));
            if node_flags.is_empty() {
                flags.remove(&node_id);
            }
        }
    }
}

#[doc(hidden)]
pub struct StreamConnectionGuard {
    machines: Arc<MachineRegistry>,
    node_id: u64,
    generation: u64,
    epoch: Arc<()>,
    acquired: bool,
    record_ended: bool,
    native_work: Option<native_shutdown::NativeWork>,
    offline_grace: Duration,
    cancelled: Arc<AtomicBool>,
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
    timers: Mutex<BTreeMap<String, EphemeralGcTimer>>,
    next_generation: AtomicU64,
    closed: AtomicBool,
}

struct EphemeralGcTimer {
    generation: u64,
    node_id: u64,
    machine_key_hex: String,
    epoch: Option<Arc<()>>,
    task: tokio::task::JoinHandle<()>,
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
                        .get(&rec.stable_node_id_for_key(node_key))
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
        let Some(machines) = self.machines.upgrade() else {
            return;
        };
        let records = machines.inner.read();
        let Some(rec) = records.get(&node_key_hex) else {
            return;
        };
        let node_id = rec.stable_node_id_for_key(&node_key_hex);
        let epoch = Some(
            machines
                .stream_session_epochs
                .write()
                .entry(node_id)
                .or_insert_with(|| Arc::new(()))
                .clone(),
        );
        self.schedule_owned(&machines, node_key_hex, rec, epoch);
    }

    /// Caller holds the NodeStore read guard through timer installation, so a
    /// writer cannot retire/rebind the selected node between lookup and insert.
    fn schedule_owned(
        self: &Arc<Self>,
        machines: &MachineRegistry,
        node_key_hex: String,
        rec: &MachineRecord,
        mut epoch: Option<Arc<()>>,
    ) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        if !rec.ephemeral {
            self.cancel(&node_key_hex);
            return;
        }
        let node_id = rec.stable_node_id_for_key(&node_key_hex);
        if !machines.stream_epoch_matches(node_id, epoch.as_ref()) {
            return;
        }
        if epoch.is_none() {
            epoch = Some(
                machines
                    .stream_session_epochs
                    .write()
                    .entry(node_id)
                    .or_insert_with(|| Arc::new(()))
                    .clone(),
            );
        }
        if machines
            .state_sessions
            .read()
            .get(&node_id)
            .copied()
            .unwrap_or(0)
            > 0
        {
            self.cancel(&node_key_hex);
            return;
        }

        let mut timers = self.timers.lock();
        // Close sets the flag before taking this same lock. A scheduler that
        // passed the early check must not install a timer after close drained it.
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let timeout = self.inactivity_timeout;
        let gc = Arc::downgrade(self);
        let task_node_key = node_key_hex.clone();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            if let Some(gc) = gc.upgrade() {
                gc.fire(task_node_key, generation).await;
            }
        });
        if let Some(previous) = timers.insert(
            node_key_hex,
            EphemeralGcTimer {
                generation,
                node_id,
                machine_key_hex: rec.machine_key_hex.clone(),
                epoch,
                task: handle,
            },
        ) {
            previous.task.abort();
        }
    }

    /// The NodeStore writer retires old bindings before any subsequent writer
    /// can insert or acquire their replacements. This does not read NodeStore.
    fn retire_absent_timers(&self, records: &HashMap<String, MachineRecord>) {
        self.timers.lock().retain(|key, timer| {
            let retained = records.get(key).is_some_and(|record| {
                record.stable_node_id_for_key(key) == timer.node_id
                    && record.machine_key_hex == timer.machine_key_hex
            });
            if !retained {
                timer.task.abort();
            }
            retained
        });
    }

    fn cancel(&self, node_key_hex: &str) {
        if let Some(timer) = self.timers.lock().remove(node_key_hex) {
            timer.task.abort();
        }
    }

    fn abort_all(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let timers = std::mem::take(&mut *self.timers.lock());
        for (_node_key, timer) in timers {
            timer.task.abort();
        }
    }

    fn claim_timer(&self, node_key: &str, generation: u64) -> bool {
        let mut timers = self.timers.lock();
        if timers
            .get(node_key)
            .is_some_and(|timer| timer.generation == generation)
        {
            timers.remove(node_key);
            true
        } else {
            false
        }
    }

    async fn fire(self: Arc<Self>, node_key_hex: String, generation: u64) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let Some(machines) = self.machines.upgrade() else {
            self.claim_timer(&node_key_hex, generation);
            return;
        };
        let expected = self.timers.lock().get(&node_key_hex).and_then(|timer| {
            (timer.generation == generation).then(|| {
                (
                    timer.node_id,
                    timer.machine_key_hex.clone(),
                    timer.epoch.clone(),
                )
            })
        });
        let Some((expected_id, expected_machine_key, epoch)) = expected else {
            return;
        };
        // Leave the timer cancellable while waiting behind a reconnect,
        // registration or admin mutation. Claim its generation only once
        // this callback owns the machine's mutation step.
        let registration = machines.lock_registration(&expected_machine_key).await;
        let record = {
            let records = machines.inner.read();
            let current = self.claim_timer(&node_key_hex, generation);
            if !current
                || self.closed.load(Ordering::SeqCst)
                || !machines.stream_epoch_matches(expected_id, epoch.as_ref())
            {
                return;
            }
            let Some(record) = records.get(&node_key_hex) else {
                return;
            };
            if record.machine_key_hex != expected_machine_key
                || record.stable_node_id_for_key(&node_key_hex) != expected_id
            {
                return;
            }
            record.clone()
        };
        let node_id = record.stable_node_id_for_key(&node_key_hex);
        if machines
            .active_connections
            .read()
            .get(&node_id)
            .copied()
            .unwrap_or(0)
            > 0
            || !record.ephemeral
        {
            return;
        }
        let store = self
            .registration_store
            .as_ref()
            .and_then(std::sync::Weak::upgrade);
        if let Some(store) = store
            .as_ref()
            .filter(|store| !store.supports_guarded_ephemeral_deletion())
        {
            // Preserve the original hook contract for custom adapters. They
            // may acquire the machine guard themselves; only explicitly
            // opted-in stores can be called while this guard is held.
            drop(registration);
            if let Err(error) = store.delete_machine_registration(&node_key_hex).await {
                tracing::warn!(target: "tailscale_wire::gc", node_key = %node_key_hex, %error,
                    "ephemeral GC failed to delete persisted node");
                return;
            }
            if let Err(error) = machines.try_delete_gc_owned(
                &node_key_hex,
                expected_id,
                &expected_machine_key,
                epoch.clone(),
            ) {
                tracing::warn!(target: "tailscale_wire::gc", node_key = %node_key_hex, %error,
                    "ephemeral GC failed after cache deletion");
            }
            return;
        }
        if let Err(error) = complete_state_mutation(async move {
            let _registration = registration;
            if let Some(store) = store
                && let Err(error) = store.delete_ephemeral_registration(&record).await
            {
                tracing::warn!(target: "tailscale_wire::gc", node_key = %node_key_hex, %error,
                    "ephemeral GC failed to delete persisted node");
                return;
            }
            match machines.try_delete_gc_owned(
                &node_key_hex,
                expected_id,
                &expected_machine_key,
                epoch,
            ) {
                Ok(true) => tracing::info!(target: "tailscale_wire::gc", node_key = %node_key_hex,
                    "ephemeral GC removed node"),
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(target: "tailscale_wire::gc", node_key = %node_key_hex, %error,
                    "ephemeral GC failed after cache deletion");
                }
            }
        })
        .await
        {
            tracing::warn!(target: "tailscale_wire::gc", %error, "ephemeral GC mutation task failed");
        }
    }
}

impl Drop for StreamConnectionGuard {
    fn drop(&mut self) {
        if !self.acquired {
            return;
        }
        let end_reason = if self.cancelled.load(Ordering::SeqCst) {
            "cancelled"
        } else {
            "done"
        };
        let still_connected = self
            .machines
            .release_stream_connection(self.node_id, &self.epoch);
        self.machines
            .forget_stream_cancel_flag(self.node_id, &self.cancelled);
        if let Some(still_connected) = still_connected {
            MachineRegistry::schedule_state_session_release(
                self.machines.clone(),
                self.node_id,
                self.generation,
                self.epoch.clone(),
                still_connected,
                self.offline_grace,
                self.native_work.take(),
            );
        }
        if self.record_ended {
            self.machines.record_mapresponse_ended(end_reason);
        }
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
            let removed = match machines.try_gc_ephemeral(grace) {
                Ok(removed) => removed,
                Err(error) => {
                    tracing::error!(%error, "ephemeral GC policy refresh failed");
                    continue;
                }
            };
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

/// Spawn headscale-go's long-offline batcher-entry cleanup loop.
///
/// The first cleanup runs after `interval`, matching the Go batcher's
/// ticker-driven cleanup rather than deleting entries immediately after a
/// disconnect. Node records are not deleted; only volatile connection state
/// used by `/debug/batcher`, online tracking, and route-health sessions is
/// evicted.
pub fn spawn_offline_connection_cleanup(
    machines: Arc<MachineRegistry>,
    interval: Duration,
    threshold: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.tick().await;
        loop {
            tick.tick().await;
            let cleaned = machines.cleanup_offline_connections(threshold);
            if !cleaned.is_empty() {
                tracing::info!(
                    target = "tailscale_wire::batcher",
                    count = cleaned.len(),
                    nodes = ?cleaned,
                    "cleaned long-offline batcher connection state"
                );
            }
        }
    })
}

/// Spawn headscale-go's map-change batcher tick.
///
/// Mutators enqueue per-node changes immediately, but this task publishes the
/// drained batch on the configured `BatchChangeDelay` cadence so stream
/// delivery can consume one ordered work item per node.
pub fn spawn_map_change_batcher(
    machines: Arc<MachineRegistry>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    machines.enable_map_batcher();
    tokio::spawn(async move {
        let interval = std::cmp::max(interval, Duration::from_millis(1));
        let mut tick = tokio::time::interval(interval);
        tick.tick().await;
        loop {
            tick.tick().await;
            let Some(batch) = machines.publish_pending_map_changes() else {
                continue;
            };
            tracing::trace!(
                target = "tailscale_wire::batcher",
                nodes = batch.len(),
                changes = batch.values().map(Vec::len).sum::<usize>(),
                "published map-change batch"
            );
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
            node_id: None,
            auth_key_id: None,
            node_key_hex: format!("nodekey-{host:08x}"),
            machine_key_hex: format!("mkey-{host:08x}"),
            user: "alice".to_string(),
            user_id: None,
            user_display_name: String::new(),
            user_profile_pic_url: String::new(),
            user_provider: String::new(),
            user_created_at: None,
            hostname: format!("host-{host}"),
            raw_hostname: format!("host-{host}"),
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
            registration_gate: None,
            derp_map: DerpMapStore::shared(wire::DerpMap::default()),
            #[cfg(feature = "full")]
            native_derp: None,
            policy: Arc::new(crate::policy::PolicyStore::new()),
            knock: KnockConfig::disabled(),
            dns: Arc::new(crate::dns::DnsStore::new()),
            public_control_url: None,
            runtime_config: Arc::new(RuntimeConfigSnapshot::default()),
            registration_cache: Arc::new(RegistrationCache::new()),
            pings: Arc::new(PingTracker::new()),
            mapresponse_debug: Arc::new(MapResponseDebugStore::disabled()),
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

    fn oidc_pending_confirmation(
        registration_id: &str,
        csrf: &str,
    ) -> crate::oidc::OidcPendingRegistrationConfirmation {
        crate::oidc::OidcPendingRegistrationConfirmation {
            registration_id: registration_id.to_string(),
            user: oidc_test_user(),
            node_expiry: None,
            csrf: csrf.to_string(),
            device: crate::oidc::OidcRegistrationConfirmInfo {
                hostname: "oidc-client".into(),
                os: "linux".into(),
                machine_key: "[abcdef]".into(),
            },
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
    async fn public_ping_response_only_accepts_head_callbacks() {
        let state = test_state();
        let (ping_id, response) = state.register_ping(42);
        let app = router(state.clone());

        for method in [axum::http::Method::GET, axum::http::Method::POST] {
            let resp = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method(method.clone())
                        .uri(format!("/machine/ping-response?id={ping_id}"))
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(
                resp.status(),
                axum::http::StatusCode::METHOD_NOT_ALLOWED,
                "{method} should not complete public ping callbacks"
            );
            let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
            assert!(body.is_empty(), "{method}");
        }

        assert_eq!(state.pings.pending_len(), 1);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), response)
                .await
                .is_err(),
            "non-HEAD requests must leave the callback waiter pending"
        );
    }

    #[tokio::test]
    async fn control_router_default_mounts_headscale_health_route() {
        let app = control_router(test_state());
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/health+json; charset=utf-8")
        );
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "pass");
    }

    #[tokio::test]
    async fn control_router_options_can_omit_health_without_losing_stock_routes() {
        let state = test_state();
        let (ping_id, response) = state.register_ping(42);
        let app = control_router_with_options(
            state.clone(),
            ControlRouterOptions::without_health_route(),
        )
        .merge(Router::new().route(
            "/health",
            get(|| async {
                (
                    StatusCode::ACCEPTED,
                    [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                    "host health\n",
                )
            }),
        ));

        let health = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::ACCEPTED);
        let body = axum::body::to_bytes(health.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(&body[..], b"host health\n");

        let version = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/version")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(version.status(), StatusCode::OK);

        let key = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/key?v=138")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(key.status(), StatusCode::OK);

        let ping = app
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::HEAD)
                    .uri(format!("/machine/ping-response?id={ping_id}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ping.status(), StatusCode::OK);
        let latency = response.await.expect("ping response completed");
        assert!(latency <= std::time::Duration::from_secs(5));
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
    async fn registration_cache_approval_keeps_entry_until_completion() {
        let cache = Arc::new(RegistrationCache::with_tuning(
            Duration::from_secs(60),
            Duration::from_secs(120),
        ));
        let registration_id = "d".repeat(24);
        let pending = mk_record(3);
        cache.insert(registration_id.clone(), pending.clone());

        let waiter = {
            let cache = cache.clone();
            let registration_id = registration_id.clone();
            tokio::spawn(async move { cache.wait_for_registration(&registration_id).await })
        };
        tokio::task::yield_now().await;

        assert!(cache.approve_without_node(&registration_id));

        let outcome = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter should be notified")
            .expect("waiter task should not panic");
        assert!(matches!(
            outcome,
            RegistrationWaitOutcome::ApprovedWithoutNode
        ));

        let cached = cache
            .get(&registration_id)
            .expect("approved registration remains cached");
        assert_eq!(cached.node_key_hex, pending.node_key_hex);
        assert_eq!(cache.len(), 1);

        let registered = mk_record(4);
        assert!(cache.complete(&registration_id, registered));
        assert!(
            cache.get(&registration_id).is_none(),
            "registration completion consumes the cached auth session"
        );
    }

    #[tokio::test]
    async fn registration_cache_registration_wait_tracks_ssh_auth_request_lifecycle() {
        let cache = Arc::new(RegistrationCache::with_tuning(
            Duration::from_secs(60),
            Duration::from_secs(120),
        ));
        let approve_id = "s".repeat(24);
        let binding = SshCheckBinding {
            src_node_id: 101,
            dst_node_id: 202,
            local_user: "root".into(),
        };
        cache.insert_ssh_check(approve_id.clone(), binding.clone());

        let approve_waiter = {
            let cache = cache.clone();
            let approve_id = approve_id.clone();
            tokio::spawn(async move { cache.wait_for_registration(&approve_id).await })
        };
        tokio::task::yield_now().await;
        assert!(
            !approve_waiter.is_finished(),
            "SSH-check auth requests should wait instead of looking missing"
        );

        assert!(cache.approve_without_node(&approve_id));
        let outcome = tokio::time::timeout(Duration::from_secs(1), approve_waiter)
            .await
            .expect("approved SSH auth wait should finish")
            .expect("waiter task should not panic");
        assert!(matches!(
            outcome,
            RegistrationWaitOutcome::ApprovedWithoutNode
        ));

        let reject_id = "t".repeat(24);
        cache.insert_ssh_check(reject_id.clone(), binding.clone());
        assert!(cache.reject(&reject_id, "auth request rejected"));
        match cache.wait_for_registration(&reject_id).await {
            RegistrationWaitOutcome::Rejected(reason) => {
                assert_eq!(reason, "auth request rejected");
            }
            other => panic!("expected rejected outcome, got {other:?}"),
        }

        let expiring =
            RegistrationCache::with_tuning(Duration::from_millis(10), Duration::from_millis(20));
        let expired_id = "u".repeat(24);
        expiring.insert_ssh_check(expired_id.clone(), binding);
        let outcome = tokio::time::timeout(
            Duration::from_secs(1),
            expiring.wait_for_registration(&expired_id),
        )
        .await
        .expect("expired SSH auth wait should finish");
        assert!(matches!(outcome, RegistrationWaitOutcome::Expired));
    }

    #[tokio::test]
    async fn registration_cache_oidc_confirmation_shares_auth_entry_lifecycle() {
        let cache = RegistrationCache::with_tuning_and_max_entries(
            Duration::from_millis(15),
            Duration::from_millis(30),
            1,
        );

        let evicted_id = "v".repeat(24);
        cache.insert(evicted_id.clone(), mk_record(40));
        assert!(cache.store_oidc_confirmation(
            &evicted_id,
            oidc_pending_confirmation(&evicted_id, "csrf-evicted"),
        ));
        assert_eq!(
            cache.oidc_confirmation(&evicted_id).unwrap().csrf,
            "csrf-evicted"
        );

        let replacement_id = "w".repeat(24);
        cache.insert(replacement_id.clone(), mk_record(41));
        assert!(cache.get(&evicted_id).is_none());
        assert!(cache.oidc_confirmation(&evicted_id).is_none());

        assert!(cache.store_oidc_confirmation(
            &replacement_id,
            oidc_pending_confirmation(&replacement_id, "csrf-expiring"),
        ));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(cache.oidc_confirmation(&replacement_id).is_none());
        assert!(cache.get(&replacement_id).is_none());
    }

    #[tokio::test]
    async fn registration_cache_rejection_keeps_entry_until_expiry() {
        let cache =
            RegistrationCache::with_tuning(Duration::from_millis(200), Duration::from_millis(400));
        let registration_id = "r".repeat(24);
        let pending = mk_record(5);
        cache.insert(registration_id.clone(), pending.clone());

        assert!(cache.reject(&registration_id, "auth request rejected"));
        match cache.wait_for_registration(&registration_id).await {
            RegistrationWaitOutcome::Rejected(reason) => {
                assert_eq!(reason, "auth request rejected");
            }
            other => panic!("expected rejected outcome, got {other:?}"),
        }

        let cached = cache
            .get(&registration_id)
            .expect("rejected registration remains cached");
        assert_eq!(cached.node_key_hex, pending.node_key_hex);

        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(cache.prune_expired(), 1);
        assert!(
            cache.get(&registration_id).is_none(),
            "expired rejected auth session is evicted by cache expiry"
        );
    }

    fn registration_source(text: &str) -> RegistrationSource {
        RegistrationSource::from_remote_addr(text).expect("test address parses")
    }

    fn insert_pending_from(cache: &RegistrationCache, id: &str, host: u32, source: &str) {
        cache.insert_from_source(
            id.to_owned(),
            mk_record(host),
            None,
            Some(registration_source(source)),
        );
    }

    fn pending(cache: &RegistrationCache, id: &str) -> bool {
        cache.get_pending_registration(id).is_some()
    }

    #[test]
    fn registration_source_ignores_ports_and_groups_ipv6_by_prefix() {
        // The port is never part of the key.
        assert_eq!(
            registration_source("203.0.113.7:1111"),
            registration_source("203.0.113.7:2222")
        );
        assert_eq!(
            registration_source("203.0.113.7"),
            registration_source("203.0.113.7:2222")
        );
        assert_ne!(
            registration_source("203.0.113.7:1"),
            registration_source("203.0.113.8:1")
        );
        // A whole /64 is one source; the next /64 is another.
        assert_eq!(
            registration_source("[2001:db8:1:2::1]:443"),
            registration_source("[2001:db8:1:2:ffff:ffff:ffff:ffff]:80")
        );
        assert_eq!(
            registration_source("2001:db8:1:2::1"),
            registration_source("[2001:db8:1:2::9]:443")
        );
        assert_ne!(
            registration_source("2001:db8:1:2::1"),
            registration_source("2001:db8:1:3::1")
        );
        // The forwarded-address rendering may carry a zone.
        assert_eq!(
            registration_source("fe80::1%eth0"),
            registration_source("[fe80::2]:5")
        );
        // An IPv4-mapped IPv6 address is the IPv4 address it carries.
        assert_eq!(
            registration_source("[::ffff:203.0.113.7]:9"),
            registration_source("203.0.113.7:9")
        );
        // IPv4 and IPv6 buckets never collide, nor does the missing-address one.
        assert_ne!(
            registration_source("0.0.0.1:1"),
            registration_source("[::1]:1")
        );
        assert_ne!(registration_source("[::]:1"), RegistrationSource::Unknown);
        assert_eq!(RegistrationSource::from_remote_addr("not an address"), None);
        assert_eq!(RegistrationSource::from_remote_addr(""), None);
    }

    /// Negative control for F-REGCACHE: entries that carry no source are not
    /// accounted, so a flood of them still pushes the earlier pending entry out
    /// of the default 1024-entry cache, exactly as in headscale-go.
    #[test]
    fn unaccounted_flood_evicts_an_earlier_pending_entry() {
        let cache = RegistrationCache::new();
        assert_eq!(cache.max_entries(), REGISTRATION_CACHE_MAX_ENTRIES);

        cache.insert("victim".to_owned(), mk_record(1));
        for i in 0..cache.max_entries() {
            cache.insert(
                format!("flood-{i}"),
                mk_record(100 + u32::try_from(i).unwrap()),
            );
        }
        assert!(
            !pending(&cache, "victim"),
            "without per-source accounting the flood evicts the earlier entry"
        );
        assert_eq!(cache.len(), cache.max_entries());
    }

    #[test]
    fn default_cache_flood_from_one_source_cannot_evict_another_sources_pending_entry() {
        let cache = RegistrationCache::new();
        insert_pending_from(&cache, "victim", 1, "203.0.113.7:4000");

        let flooder = registration_source("198.51.100.9:1");
        for i in 0..(2 * cache.max_entries()) {
            // A new ephemeral port per request: the port is not the source.
            insert_pending_from(
                &cache,
                &format!("flood-{i}"),
                100 + u32::try_from(i).unwrap(),
                &format!("198.51.100.9:{}", 1024 + i),
            );
        }

        assert!(
            pending(&cache, "victim"),
            "the other source's entry survives"
        );
        assert_eq!(
            cache.pending_from_source(flooder),
            REGISTRATION_CACHE_MAX_PENDING_PER_SOURCE
        );
        assert_eq!(cache.len(), 1 + REGISTRATION_CACHE_MAX_PENDING_PER_SOURCE);
    }

    #[tokio::test]
    async fn per_source_quota_drops_only_the_flooding_sources_own_oldest_entries() {
        let cache = Arc::new(
            RegistrationCache::with_tuning_and_max_entries(
                Duration::from_secs(60),
                Duration::from_secs(120),
                100,
            )
            .with_max_pending_per_source(3),
        );
        insert_pending_from(&cache, "victim", 1, "203.0.113.7:1");
        insert_pending_from(&cache, "flood-0", 100, "198.51.100.9:1");
        let oldest_waiter = {
            let cache = cache.clone();
            tokio::spawn(async move { cache.wait_for_registration("flood-0").await })
        };
        tokio::task::yield_now().await;
        for i in 1..10 {
            insert_pending_from(&cache, &format!("flood-{i}"), 100 + i, "198.51.100.9:2");
        }

        assert!(pending(&cache, "victim"));
        assert_eq!(
            cache.pending_from_source(registration_source("198.51.100.9:3")),
            3
        );
        for i in 0..7 {
            assert!(!pending(&cache, &format!("flood-{i}")), "flood-{i} dropped");
        }
        for i in 7..10 {
            assert!(pending(&cache, &format!("flood-{i}")), "flood-{i} kept");
        }
        assert_eq!(cache.len(), 4);
        // The dropped entry's waiter is told it expired, as for an LRU eviction.
        let outcome = tokio::time::timeout(Duration::from_secs(1), oldest_waiter)
            .await
            .expect("waiter finishes")
            .expect("waiter task");
        assert!(matches!(outcome, RegistrationWaitOutcome::Expired));
    }

    #[test]
    fn sources_are_counted_per_ipv6_prefix_not_per_address() {
        let cache = RegistrationCache::with_tuning_and_max_entries(
            Duration::from_secs(60),
            Duration::from_secs(120),
            100,
        )
        .with_max_pending_per_source(2);
        // The quota only applies while another party holds a pending entry.
        insert_pending_from(&cache, "other-prefix", 20, "[2001:db8:0:1::1]:1");
        for (i, source) in ["[2001:db8::1]:1", "[2001:db8::2]:1", "[2001:db8::3]:1"]
            .into_iter()
            .enumerate()
        {
            insert_pending_from(
                &cache,
                &format!("same-prefix-{i}"),
                10 + u32::try_from(i).unwrap(),
                source,
            );
        }

        assert_eq!(
            cache.pending_from_source(registration_source("2001:db8::9")),
            2
        );
        assert!(!pending(&cache, "same-prefix-0"));
        assert!(pending(&cache, "same-prefix-1"));
        assert!(pending(&cache, "same-prefix-2"));
        assert!(pending(&cache, "other-prefix"));
    }

    #[test]
    fn a_single_shared_source_falls_back_to_the_plain_lru_like_go() {
        // Every client behind a reverse proxy without `trusted_proxies` shares
        // one source. Trimming that bucket at the quota would make a flood
        // easier than Go's 1024-entry LRU, so the quota stands down until some
        // other party holds a pending entry.
        let cache = RegistrationCache::with_tuning_and_max_entries(
            Duration::from_secs(60),
            Duration::from_secs(120),
            10,
        )
        .with_max_pending_per_source(2);
        for i in 0..12_u32 {
            insert_pending_from(&cache, &format!("shared-{i}"), i, "203.0.113.7:1");
        }
        assert_eq!(cache.len(), 10);
        assert_eq!(
            cache.pending_from_source(registration_source("203.0.113.7:1")),
            10,
            "the quota must not trim a bucket nobody else shares"
        );
        assert!(!pending(&cache, "shared-0") && !pending(&cache, "shared-1"));
        assert!(pending(&cache, "shared-2") && pending(&cache, "shared-11"));
    }

    #[test]
    fn the_quota_applies_as_soon_as_another_party_holds_an_entry() {
        let cache = RegistrationCache::with_tuning_and_max_entries(
            Duration::from_secs(60),
            Duration::from_secs(120),
            100,
        )
        .with_max_pending_per_source(2);
        for i in 0..5_u32 {
            insert_pending_from(&cache, &format!("a{i}"), i, "198.51.100.1:1");
        }
        assert_eq!(cache.len(), 5, "no other party yet: nothing is trimmed");

        insert_pending_from(&cache, "b0", 50, "198.51.100.2:1");
        insert_pending_from(&cache, "a5", 5, "198.51.100.1:1");
        assert_eq!(
            cache.pending_from_source(registration_source("198.51.100.1:1")),
            2,
            "the flooder is cut back to its quota"
        );
        assert!(pending(&cache, "b0"), "the bystander is untouched");
        assert!(pending(&cache, "a4") && pending(&cache, "a5"));
    }

    #[test]
    fn a_flooder_that_arrived_first_is_still_the_first_victim() {
        let cache = RegistrationCache::with_tuning_and_max_entries(
            Duration::from_secs(60),
            Duration::from_secs(120),
            6,
        )
        .with_max_pending_per_source(2);
        for i in 0..6_u32 {
            insert_pending_from(&cache, &format!("a{i}"), i, "198.51.100.1:1");
        }
        assert_eq!(cache.len(), 6, "the cache is full of one source");

        // A user from a different source arrives at the full cache: the
        // flooder pays, not the newcomer or anybody else.
        insert_pending_from(&cache, "user", 50, "198.51.100.2:1");
        assert!(pending(&cache, "user"));
        assert!(!pending(&cache, "a0"));
        assert_eq!(cache.len(), 6);
    }

    #[test]
    fn global_eviction_takes_from_the_heaviest_source_first() {
        let cache = RegistrationCache::with_tuning_and_max_entries(
            Duration::from_secs(60),
            Duration::from_secs(120),
            6,
        )
        .with_max_pending_per_source(4);
        insert_pending_from(&cache, "b1", 10, "198.51.100.2:1");
        insert_pending_from(&cache, "c1", 11, "198.51.100.3:1");
        for i in 1..=4 {
            insert_pending_from(&cache, &format!("a{i}"), i, "198.51.100.1:1");
        }
        assert_eq!(cache.len(), 6);

        // b1 and c1 are the two least recently used entries, yet plain LRU is
        // not what runs: the heaviest source pays for each new arrival.
        insert_pending_from(&cache, "d1", 12, "198.51.100.4:1");
        assert!(!pending(&cache, "a1"));
        insert_pending_from(&cache, "e1", 13, "198.51.100.5:1");
        assert!(!pending(&cache, "a2"));
        for id in ["a3", "a4", "b1", "c1", "d1", "e1"] {
            assert!(pending(&cache, id), "{id} survives");
        }
    }

    #[test]
    fn global_eviction_falls_back_to_lru_when_no_source_holds_two_entries() {
        let cache = RegistrationCache::with_tuning_and_max_entries(
            Duration::from_secs(60),
            Duration::from_secs(120),
            3,
        );
        insert_pending_from(&cache, "x", 1, "198.51.100.1:1");
        insert_pending_from(&cache, "y", 2, "198.51.100.2:1");
        cache.insert("z".to_owned(), mk_record(3));
        assert!(pending(&cache, "x"), "touching x makes y the least recent");
        insert_pending_from(&cache, "w", 4, "198.51.100.4:1");

        assert!(!pending(&cache, "y"));
        for id in ["x", "z", "w"] {
            assert!(pending(&cache, id), "{id} survives");
        }
    }

    #[test]
    fn global_eviction_prefers_entries_that_already_have_a_verdict() {
        let cache = RegistrationCache::with_tuning_and_max_entries(
            Duration::from_secs(60),
            Duration::from_secs(120),
            3,
        );
        insert_pending_from(&cache, "rejected", 1, "198.51.100.1:1");
        insert_pending_from(&cache, "second", 2, "198.51.100.2:1");
        insert_pending_from(&cache, "third", 3, "198.51.100.3:1");
        assert!(cache.reject("rejected", "auth request rejected"));
        assert!(cache.get("rejected").is_some(), "touch: most recently used");

        insert_pending_from(&cache, "fourth", 4, "198.51.100.4:1");
        assert!(
            cache.get("rejected").is_none(),
            "the finished entry goes before the least recently used pending one"
        );
        for id in ["second", "third", "fourth"] {
            assert!(pending(&cache, id), "{id} survives");
        }
    }

    #[test]
    fn sourceless_entries_are_exempt_from_the_per_source_quota() {
        let cache = RegistrationCache::with_tuning_and_max_entries(
            Duration::from_secs(60),
            Duration::from_secs(120),
            100,
        )
        .with_max_pending_per_source(2);
        for i in 0..10 {
            cache.insert(format!("internal-{i}"), mk_record(i));
        }
        insert_pending_from(&cache, "s1", 50, "203.0.113.7:1");
        insert_pending_from(&cache, "s2", 51, "203.0.113.7:1");
        assert_eq!(cache.len(), 12);
        assert_eq!(
            cache.pending_from_source(registration_source("203.0.113.7:1")),
            2
        );
    }

    #[test]
    fn reinserting_an_id_does_not_double_count_its_source() {
        let cache = RegistrationCache::with_tuning_and_max_entries(
            Duration::from_secs(60),
            Duration::from_secs(120),
            100,
        )
        .with_max_pending_per_source(2);
        for host in 0..3 {
            insert_pending_from(&cache, "dup", host, "203.0.113.7:1");
        }
        insert_pending_from(&cache, "other", 9, "203.0.113.7:1");
        assert_eq!(
            cache.pending_from_source(registration_source("203.0.113.7:1")),
            2
        );
        assert!(pending(&cache, "dup"));
        assert!(pending(&cache, "other"));
    }

    #[test]
    fn per_source_quota_is_released_when_entries_leave_the_cache() {
        let cache = RegistrationCache::with_tuning_and_max_entries(
            Duration::from_secs(60),
            Duration::from_secs(120),
            100,
        )
        .with_max_pending_per_source(2);
        let source = registration_source("203.0.113.7:1");
        // The quota only applies while another party holds a pending entry.
        insert_pending_from(&cache, "bystander", 99, "198.51.100.99:1");

        insert_pending_from(&cache, "e1", 1, "203.0.113.7:1");
        insert_pending_from(&cache, "e2", 2, "203.0.113.7:1");
        assert_eq!(cache.pending_from_source(source), 2);

        // Completed (consumed by an admin approval): released.
        assert!(cache.complete("e1", mk_record(1)));
        assert_eq!(cache.pending_from_source(source), 1);
        insert_pending_from(&cache, "e3", 3, "203.0.113.7:1");
        assert!(
            pending(&cache, "e2") && pending(&cache, "e3"),
            "nothing dropped"
        );

        // Rejected: still cached for followups, but no longer pending.
        assert!(cache.reject("e2", "auth request rejected"));
        assert_eq!(cache.pending_from_source(source), 1);
        insert_pending_from(&cache, "e4", 4, "203.0.113.7:1");
        assert!(
            cache.get("e2").is_some(),
            "the quota never drops a finished entry"
        );
        assert!(pending(&cache, "e3") && pending(&cache, "e4"));

        // Removed: released.
        assert!(cache.remove("e3").is_some());
        assert_eq!(cache.pending_from_source(source), 1);

        // Over the quota again: the source's own oldest goes, the count stays at 2.
        insert_pending_from(&cache, "e5", 5, "203.0.113.7:1");
        insert_pending_from(&cache, "e6", 6, "203.0.113.7:1");
        assert_eq!(cache.pending_from_source(source), 2);
        assert!(!pending(&cache, "e4"));

        // Everything consumed: the source is back to a clean slate, not locked out.
        assert!(cache.complete("e5", mk_record(5)));
        assert!(cache.complete("e6", mk_record(6)));
        assert_eq!(cache.pending_from_source(source), 0);
        insert_pending_from(&cache, "e7", 7, "203.0.113.7:1");
        insert_pending_from(&cache, "e8", 8, "203.0.113.7:1");
        assert!(pending(&cache, "e7") && pending(&cache, "e8"));
    }

    #[tokio::test]
    async fn per_source_quota_ignores_expired_entries() {
        let cache = RegistrationCache::with_tuning_and_max_entries(
            Duration::from_millis(150),
            Duration::from_millis(300),
            100,
        )
        .with_max_pending_per_source(2);
        let source = registration_source("203.0.113.7:1");
        insert_pending_from(&cache, "old1", 1, "203.0.113.7:1");
        insert_pending_from(&cache, "old2", 2, "203.0.113.7:1");
        tokio::time::sleep(Duration::from_millis(200)).await;

        insert_pending_from(&cache, "fresh", 3, "203.0.113.7:1");
        assert_eq!(cache.pending_from_source(source), 1);
        assert_eq!(cache.len(), 1);
        assert!(pending(&cache, "fresh"));
    }

    #[test]
    fn concurrent_inserts_from_one_source_cannot_race_past_the_quota() {
        let quota = 5;
        let cache = RegistrationCache::with_tuning_and_max_entries(
            Duration::from_secs(60),
            Duration::from_secs(120),
            10_000,
        )
        .with_max_pending_per_source(quota);
        // The quota only applies while another party holds a pending entry.
        insert_pending_from(&cache, "bystander", 9_999_999, "198.51.100.99:1");
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            for thread in 0..8_u32 {
                let cache = &cache;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    for i in 0..100_u32 {
                        insert_pending_from(
                            cache,
                            &format!("race-{thread}-{i}"),
                            thread * 1000 + i,
                            "203.0.113.7:1",
                        );
                    }
                });
            }
        });
        assert_eq!(
            cache.pending_from_source(registration_source("203.0.113.7:1")),
            quota
        );
        assert_eq!(cache.len(), quota + 1);
        assert!(pending(&cache, "bystander"));
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
            (axum::http::Method::POST, "/machine/audit-log".to_string()),
            (axum::http::Method::POST, "/machine/id-token".to_string()),
            (
                axum::http::Method::POST,
                "/machine/feature/query".to_string(),
            ),
            (
                axum::http::Method::POST,
                "/machine/update-health".to_string(),
            ),
            (axum::http::Method::POST, "/machine/c2n".to_string()),
            (axum::http::Method::GET, "/machine/webclient".to_string()),
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

    // oidc.go handleRegistration runs State.AutoApproveRoutes right after
    // HandleNodeFromAuthPath; SetApprovedRoutes yields change.PolicyChange(),
    // sent after the registration's own change.
    #[tokio::test]
    async fn wire_oidc_registration_handler_auto_approves_policy_routes() {
        let state = test_state();
        let raw_policy = r#"{"autoApprovers":{"routes":{"10.81.0.0/16":["alice@example.com"]}}}"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(raw_policy).unwrap(),
            raw_policy.to_string(),
        );
        let registration_id = "a".repeat(24);
        let mut pending = mk_record(14);
        pending.user.clear();
        pending.available_routes = vec!["10.81.1.0/24".into(), "10.99.0.0/24".into()];
        state
            .registration_cache
            .insert(registration_id.clone(), pending.clone());
        let history_len = state.machines.map_change_history().len();

        let handler = WireOidcRegistrationHandler {
            state: state.clone(),
        };
        handler
            .complete_oidc_registration(&registration_id, &oidc_test_user(), None)
            .await
            .unwrap();

        let registered = state.machines.get(&pending.node_key_hex).unwrap();
        assert_eq!(registered.user, "alice@example.com");
        assert_eq!(
            registered.available_routes,
            vec!["10.81.1.0/24", "10.99.0.0/24"]
        );
        assert_eq!(registered.approved_routes, vec!["10.81.1.0/24"]);
        let changes = state.machines.map_change_history();
        let last = changes[history_len..]
            .last()
            .expect("registration records map changes");
        assert_eq!(last.reason_labels(), vec!["policy change"]);
        assert!(last.content.include_policy);
    }

    #[tokio::test]
    async fn wire_oidc_registration_handler_without_matching_approver_approves_nothing() {
        let state = test_state();
        let raw_policy =
            r#"{"autoApprovers":{"routes":{"10.81.0.0/16":["someone-else@example.com"]}}}"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(raw_policy).unwrap(),
            raw_policy.to_string(),
        );
        let registration_id = "b".repeat(24);
        let mut pending = mk_record(15);
        pending.user.clear();
        pending.available_routes = vec!["10.81.1.0/24".into()];
        state
            .registration_cache
            .insert(registration_id.clone(), pending.clone());
        let history_len = state.machines.map_change_history().len();

        let handler = WireOidcRegistrationHandler {
            state: state.clone(),
        };
        handler
            .complete_oidc_registration(&registration_id, &oidc_test_user(), None)
            .await
            .unwrap();

        let registered = state.machines.get(&pending.node_key_hex).unwrap();
        assert!(registered.approved_routes.is_empty());
        // Only the registration's own change; an unchanged approval adds no
        // SetApprovedRoutes PolicyChange.
        assert_eq!(state.machines.map_change_history()[history_len..].len(), 1);
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
        let raw_policy = r#"{"tagOwners":{"tag:server":["alice@example.com"]}}"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(raw_policy).unwrap(),
            raw_policy.to_string(),
        );
        let registration_id = "t".repeat(24);
        let mut pending = mk_record(12);
        pending.user.clear();
        pending.forced_tags = vec!["tag:server".into(), "tag:server".into()];
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
    async fn wire_oidc_registration_handler_rejects_unowned_requested_tags() {
        let state = test_state();
        let raw_policy = r#"{"tagOwners":{"tag:server":["alice@example.com"]}}"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(raw_policy).unwrap(),
            raw_policy.to_string(),
        );
        let registration_id = "u".repeat(24);
        let mut pending = mk_record(14);
        pending.user.clear();
        pending.forced_tags = vec!["tag:db".into()];
        state
            .registration_cache
            .insert(registration_id.clone(), pending.clone());

        let handler = WireOidcRegistrationHandler {
            state: state.clone(),
        };
        let err = handler
            .complete_oidc_registration(&registration_id, &oidc_test_user(), None)
            .await
            .unwrap_err();

        assert!(matches!(err, crate::oidc::OidcRegistrationError::Store(_)));
        assert!(err.to_string().contains("requested tags [tag:db]"));
        assert!(state.registration_cache.get(&registration_id).is_some());
        assert!(state.machines.get(&pending.node_key_hex).is_none());
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
    async fn wire_oidc_registration_handler_classifies_auth_request_kind() {
        let state = test_state();
        let registration_id = "q".repeat(24);
        state
            .registration_cache
            .insert(registration_id.clone(), mk_record(20));
        let ssh_id = "s".repeat(24);
        state.registration_cache.insert_ssh_check(
            ssh_id.clone(),
            SshCheckBinding {
                src_node_id: 1,
                dst_node_id: 2,
                local_user: "root".into(),
            },
        );
        let handler = WireOidcRegistrationHandler { state };

        assert!(handler.oidc_registration_exists(&registration_id));
        assert_eq!(
            handler.oidc_auth_request_kind(&registration_id),
            Some(crate::oidc::OidcAuthRequestKind::Registration)
        );
        assert!(!handler.oidc_registration_exists(&ssh_id));
        assert_eq!(
            handler.oidc_auth_request_kind(&ssh_id),
            Some(crate::oidc::OidcAuthRequestKind::SshCheck)
        );
        assert_eq!(handler.oidc_auth_request_kind("missing"), None);
    }

    #[tokio::test]
    async fn wire_oidc_registration_handler_stores_confirmation_on_auth_request() {
        let state = test_state();
        let registration_id = "y".repeat(24);
        state
            .registration_cache
            .insert(registration_id.clone(), mk_record(27));
        let handler = WireOidcRegistrationHandler {
            state: state.clone(),
        };
        let pending = oidc_pending_confirmation(&registration_id, "csrf-live");

        assert!(handler.store_oidc_registration_confirmation(pending.clone()));
        assert_eq!(
            state
                .registration_cache
                .oidc_confirmation(&registration_id)
                .unwrap(),
            pending
        );
        assert_eq!(
            handler
                .oidc_pending_registration_confirmation(&registration_id)
                .unwrap()
                .csrf,
            "csrf-live"
        );
        assert_eq!(
            handler
                .remove_oidc_registration_confirmation(&registration_id)
                .unwrap()
                .csrf,
            "csrf-live"
        );
        assert!(
            handler
                .oidc_pending_registration_confirmation(&registration_id)
                .is_none()
        );
    }

    #[tokio::test]
    async fn wire_oidc_auth_request_approves_owned_ssh_check() {
        let state = test_state();
        let mut src = mk_record(21);
        src.node_key_hex = "ssh-src".into();
        src.user_id = Some(7);
        state.machines.upsert(src.node_key_hex.clone(), src.clone());
        let mut dst = mk_record(22);
        dst.node_key_hex = "ssh-dst".into();
        state.machines.upsert(dst.node_key_hex.clone(), dst.clone());

        let raw_auth_id = "a".repeat(24);
        let binding = SshCheckBinding {
            src_node_id: src.stable_node_id_for_key(&src.node_key_hex),
            dst_node_id: dst.stable_node_id_for_key(&dst.node_key_hex),
            local_user: "root".into(),
        };
        state
            .registration_cache
            .insert_ssh_check(raw_auth_id.clone(), binding);

        let handler = WireOidcRegistrationHandler {
            state: state.clone(),
        };
        let history_len = state.machines.map_change_history().len();
        handler
            .complete_oidc_auth_request(&raw_auth_id, &oidc_test_user())
            .await
            .unwrap();

        assert_eq!(
            state.registration_cache.wait_for_auth(&raw_auth_id).await,
            AuthWaitOutcome::Accepted
        );
        assert_eq!(
            state.machines.map_change_history().len(),
            history_len,
            "SSH-check auth approval must not emit node map changes"
        );
    }

    #[tokio::test]
    async fn wire_oidc_auth_request_rejects_wrong_source_owner() {
        let state = test_state();
        let mut src = mk_record(23);
        src.node_key_hex = "ssh-src-owner".into();
        src.user_id = Some(99);
        state.machines.upsert(src.node_key_hex.clone(), src.clone());
        let dst = mk_record(24);
        state.machines.upsert(dst.node_key_hex.clone(), dst.clone());

        let raw_auth_id = "b".repeat(24);
        state.registration_cache.insert_ssh_check(
            raw_auth_id.clone(),
            SshCheckBinding {
                src_node_id: src.stable_node_id_for_key(&src.node_key_hex),
                dst_node_id: dst.stable_node_id_for_key(&dst.node_key_hex),
                local_user: "root".into(),
            },
        );

        let handler = WireOidcRegistrationHandler { state };
        let err = handler
            .complete_oidc_auth_request(&raw_auth_id, &oidc_test_user())
            .await
            .unwrap_err();

        assert_eq!(err, crate::oidc::OidcAuthError::UserNotSourceOwner);
    }

    #[tokio::test]
    async fn wire_oidc_auth_request_rejects_tagged_source_node() {
        let state = test_state();
        let mut src = mk_record(25);
        src.node_key_hex = "ssh-src-tagged".into();
        src.user_id = Some(7);
        src.forced_tags = vec!["tag:server".into()];
        state.machines.upsert(src.node_key_hex.clone(), src.clone());
        let dst = mk_record(26);
        state.machines.upsert(dst.node_key_hex.clone(), dst.clone());

        let raw_auth_id = "c".repeat(24);
        state.registration_cache.insert_ssh_check(
            raw_auth_id.clone(),
            SshCheckBinding {
                src_node_id: src.stable_node_id_for_key(&src.node_key_hex),
                dst_node_id: dst.stable_node_id_for_key(&dst.node_key_hex),
                local_user: "root".into(),
            },
        );

        let handler = WireOidcRegistrationHandler { state };
        let err = handler
            .complete_oidc_auth_request(&raw_auth_id, &oidc_test_user())
            .await
            .unwrap_err();

        assert_eq!(err, crate::oidc::OidcAuthError::SourceNodeNoUserOwner);
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

    #[tokio::test]
    async fn registration_cache_lru_eviction_notifies_waiting_followups() {
        let cache = Arc::new(RegistrationCache::with_tuning_and_max_entries(
            Duration::from_secs(60),
            Duration::from_secs(120),
            2,
        ));
        let first_id = "a".repeat(24);
        let second_id = "b".repeat(24);
        let third_id = "c".repeat(24);
        cache.insert(first_id.clone(), mk_record(1));
        cache.insert(second_id.clone(), mk_record(2));

        let waiter = {
            let cache = cache.clone();
            let second_id = second_id.clone();
            tokio::spawn(async move { cache.wait_for_registration(&second_id).await })
        };
        tokio::task::yield_now().await;
        assert!(cache.get(&first_id).is_some(), "first entry becomes MRU");

        cache.insert(third_id.clone(), mk_record(3));

        let outcome = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("LRU eviction should notify waiter")
            .expect("waiter task should not panic");
        assert!(matches!(outcome, RegistrationWaitOutcome::Expired));
        assert!(cache.get(&first_id).is_some());
        assert!(cache.get(&second_id).is_none());
        assert!(cache.get(&third_id).is_some());
        assert_eq!(cache.len(), 2);
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

    #[test]
    fn nodestore_write_batcher_batches_concurrent_upserts() {
        let reg = Arc::new(MachineRegistry::new());
        let _handle = reg.configure_nodestore_write_batcher(2, Duration::from_secs(5));

        let first_reg = reg.clone();
        let first = std::thread::spawn(move || {
            let mut rec = mk_record(1);
            rec.node_key_hex = "node-batched-1".into();
            first_reg.upsert(rec.node_key_hex.clone(), rec);
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        while reg.nodestore_queue_depth() == 0 {
            assert!(
                Instant::now() < deadline,
                "first upsert did not enqueue before the deadline"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            reg.len(),
            0,
            "first write should wait for another item or the timeout"
        );

        let mut second = mk_record(2);
        second.node_key_hex = "node-batched-2".into();
        reg.upsert(second.node_key_hex.clone(), second);
        first.join().expect("first upsert thread should finish");

        assert_eq!(reg.len(), 2);
        assert_eq!(reg.nodestore_queue_depth(), 0);
        assert_eq!(
            reg.nodestore_operation_metrics()
                .get("put")
                .copied()
                .unwrap_or_default(),
            2
        );

        let batch_size = reg.nodestore_batch_size_metrics();
        assert_eq!(batch_size.count, 1);
        assert_eq!(batch_size.bucket("2"), 1);
    }

    #[test]
    fn nodestore_write_batcher_upsert_deleted_same_batch_emits_only_delete_change() {
        let reg = Arc::new(MachineRegistry::new());
        let mut rec = mk_record(1);
        rec.node_key_hex = "node-upsert-delete".into();
        rec.hostname = "before-upsert-delete".into();
        let node_id = rec.stable_node_id_for_key(&rec.node_key_hex);
        reg.upsert(rec.node_key_hex.clone(), rec);
        let history_len = reg.map_change_history().len();
        let _handle = reg.configure_nodestore_write_batcher(2, Duration::from_secs(5));
        let batch_size_before = reg.nodestore_batch_size_metrics();

        let first_reg = reg.clone();
        let first = std::thread::spawn(move || {
            let mut rec = first_reg
                .get("node-upsert-delete")
                .expect("existing node before queued upsert");
            rec.hostname = "after-upsert-delete".into();
            first_reg.upsert("node-upsert-delete".into(), rec);
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        while reg.nodestore_queue_depth() == 0 {
            assert!(
                Instant::now() < deadline,
                "first upsert did not enqueue before the deadline"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            reg.get("node-upsert-delete").map(|rec| rec.hostname),
            Some("before-upsert-delete".into()),
            "first upsert should wait for another item or the timeout"
        );

        assert!(reg.delete("node-upsert-delete"));
        first.join().expect("first upsert thread should finish");

        assert!(reg.get("node-upsert-delete").is_none());
        assert_eq!(reg.nodestore_queue_depth(), 0);
        assert_eq!(
            reg.nodestore_operation_metrics()
                .get("put")
                .copied()
                .unwrap_or_default(),
            2
        );
        assert_eq!(
            reg.nodestore_operation_metrics()
                .get("delete")
                .copied()
                .unwrap_or_default(),
            1
        );

        let batch_size = reg.nodestore_batch_size_metrics();
        assert_eq!(batch_size.count, batch_size_before.count + 1);
        assert_eq!(batch_size.bucket("2"), batch_size_before.bucket("2") + 1);

        let changes = reg.map_change_history();
        let new_changes = &changes[history_len..];
        assert_eq!(new_changes.len(), 1, "{new_changes:?}");
        assert_eq!(new_changes[0].reason_label(), "peers removed");
        assert_eq!(new_changes[0].content.peers_removed, vec![node_id]);
        assert!(new_changes[0].content.peers_changed.is_empty());
        assert!(new_changes[0].content.peer_patches.is_empty());
    }

    #[test]
    fn nodestore_write_batcher_flushes_partial_batch_after_timeout() {
        let reg = Arc::new(MachineRegistry::new());
        let _handle = reg.configure_nodestore_write_batcher(2, Duration::from_millis(200));
        let before = reg.snapshot();

        let first_reg = reg.clone();
        let first = std::thread::spawn(move || {
            let mut rec = mk_record(1);
            rec.node_key_hex = "node-timeout-flush".into();
            first_reg.upsert(rec.node_key_hex.clone(), rec);
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        while reg.nodestore_queue_depth() == 0 {
            assert!(
                Instant::now() < deadline,
                "first upsert did not enqueue before the deadline"
            );
            std::thread::yield_now();
        }

        let queued = reg.snapshot();
        assert!(
            Arc::ptr_eq(&before, &queued),
            "partial batch should not publish before its timeout"
        );
        assert_eq!(
            reg.len(),
            0,
            "partial batch should wait for another item or the timeout"
        );
        assert_eq!(
            reg.nodestore_operation_metrics()
                .get("put")
                .copied()
                .unwrap_or_default(),
            0
        );
        assert_eq!(reg.nodestore_batch_size_metrics().count, 0);

        let deadline = Instant::now() + Duration::from_secs(2);
        while reg.nodestore_queue_depth() != 0 {
            assert!(
                Instant::now() < deadline,
                "partial batch did not flush after the timeout"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        first.join().expect("first upsert thread should finish");

        assert_eq!(reg.len(), 1);
        assert_eq!(reg.nodestore_queue_depth(), 0);
        assert_eq!(
            reg.nodestore_operation_metrics()
                .get("put")
                .copied()
                .unwrap_or_default(),
            1
        );

        let batch_size = reg.nodestore_batch_size_metrics();
        assert_eq!(batch_size.count, 1);
        assert_eq!(batch_size.bucket("1"), 1);

        let after = reg.snapshot();
        assert!(
            !Arc::ptr_eq(&before, &after),
            "timeout flush should publish one fresh snapshot"
        );
        assert!(
            Arc::ptr_eq(&after, &reg.snapshot()),
            "snapshot pointer should stay stable after the timeout flush drains"
        );
    }

    #[test]
    fn nodestore_write_batcher_batches_concurrent_deletes() {
        let reg = Arc::new(MachineRegistry::new());
        for idx in 1..=2 {
            let mut rec = mk_record(idx);
            rec.node_key_hex = format!("node-delete-{idx}");
            reg.upsert(rec.node_key_hex.clone(), rec);
        }
        let _handle = reg.configure_nodestore_write_batcher(2, Duration::from_secs(5));
        let batch_size_before = reg.nodestore_batch_size_metrics();

        let first_reg = reg.clone();
        let first = std::thread::spawn(move || first_reg.delete("node-delete-1"));

        let deadline = Instant::now() + Duration::from_secs(2);
        while reg.nodestore_queue_depth() == 0 {
            assert!(
                Instant::now() < deadline,
                "first delete did not enqueue before the deadline"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            reg.len(),
            2,
            "first delete should wait for another item or the timeout"
        );

        assert!(reg.delete("node-delete-2"));
        assert!(first.join().expect("first delete thread should finish"));

        assert_eq!(reg.len(), 0);
        assert_eq!(reg.nodestore_queue_depth(), 0);
        assert_eq!(
            reg.nodestore_operation_metrics()
                .get("delete")
                .copied()
                .unwrap_or_default(),
            2
        );

        let batch_size = reg.nodestore_batch_size_metrics();
        assert_eq!(batch_size.count, batch_size_before.count + 1);
        assert_eq!(batch_size.bucket("2"), batch_size_before.bucket("2") + 1);
    }

    #[test]
    fn nodestore_write_batcher_batches_concurrent_updates() {
        let reg = Arc::new(MachineRegistry::new());
        for idx in 1..=2 {
            let mut rec = mk_record(idx);
            rec.node_key_hex = format!("node-update-{idx}");
            reg.upsert(rec.node_key_hex.clone(), rec);
        }
        let _handle = reg.configure_nodestore_write_batcher(2, Duration::from_secs(5));
        let batch_size_before = reg.nodestore_batch_size_metrics();
        let expiry = Utc::now() + chrono::Duration::hours(1);

        let first_reg = reg.clone();
        let first = std::thread::spawn(move || first_reg.set_expiry("node-update-1", Some(expiry)));

        let deadline = Instant::now() + Duration::from_secs(2);
        while reg.nodestore_queue_depth() == 0 {
            assert!(
                Instant::now() < deadline,
                "first update did not enqueue before the deadline"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            reg.get("node-update-1").and_then(|rec| rec.expiry),
            None,
            "first update should wait for another item or the timeout"
        );

        assert!(reg.set_expiry("node-update-2", Some(expiry)));
        assert!(first.join().expect("first update thread should finish"));

        assert_eq!(
            reg.get("node-update-1").and_then(|rec| rec.expiry),
            Some(expiry)
        );
        assert_eq!(
            reg.get("node-update-2").and_then(|rec| rec.expiry),
            Some(expiry)
        );
        assert_eq!(reg.nodestore_queue_depth(), 0);
        assert_eq!(
            reg.nodestore_operation_metrics()
                .get("update")
                .copied()
                .unwrap_or_default(),
            2
        );

        let batch_size = reg.nodestore_batch_size_metrics();
        assert_eq!(batch_size.count, batch_size_before.count + 1);
        assert_eq!(batch_size.bucket("2"), batch_size_before.bucket("2") + 1);
    }

    #[test]
    fn nodestore_write_batcher_update_deleted_same_batch_returns_false() {
        let reg = Arc::new(MachineRegistry::new());
        let mut rec = mk_record(1);
        rec.node_key_hex = "node-update-delete".into();
        let node_id = rec.stable_node_id_for_key(&rec.node_key_hex);
        reg.upsert(rec.node_key_hex.clone(), rec);
        let history_len = reg.map_change_history().len();
        let _handle = reg.configure_nodestore_write_batcher(2, Duration::from_secs(5));
        let batch_size_before = reg.nodestore_batch_size_metrics();
        let expiry = Utc::now() + chrono::Duration::hours(1);

        let first_reg = reg.clone();
        let first =
            std::thread::spawn(move || first_reg.set_expiry("node-update-delete", Some(expiry)));

        let deadline = Instant::now() + Duration::from_secs(2);
        while reg.nodestore_queue_depth() == 0 {
            assert!(
                Instant::now() < deadline,
                "first update did not enqueue before the deadline"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            reg.get("node-update-delete").is_some(),
            "first update should wait for another item or the timeout"
        );

        assert!(reg.delete("node-update-delete"));
        assert!(
            !first.join().expect("first update thread should finish"),
            "update completion should reflect final absence after same-batch delete"
        );

        assert!(reg.get("node-update-delete").is_none());
        assert_eq!(reg.nodestore_queue_depth(), 0);
        assert_eq!(
            reg.nodestore_operation_metrics()
                .get("update")
                .copied()
                .unwrap_or_default(),
            1
        );
        assert_eq!(
            reg.nodestore_operation_metrics()
                .get("delete")
                .copied()
                .unwrap_or_default(),
            1
        );

        let batch_size = reg.nodestore_batch_size_metrics();
        assert_eq!(batch_size.count, batch_size_before.count + 1);
        assert_eq!(batch_size.bucket("2"), batch_size_before.bucket("2") + 1);

        let changes = reg.map_change_history();
        let new_changes = &changes[history_len..];
        assert_eq!(new_changes.len(), 1, "{new_changes:?}");
        assert_eq!(new_changes[0].reason_label(), "peers removed");
        assert_eq!(new_changes[0].content.peers_removed, vec![node_id]);
        assert!(new_changes[0].content.peer_patches.is_empty());
    }

    #[test]
    fn nodestore_write_batcher_set_name_checks_collision_inside_batch() {
        let reg = Arc::new(MachineRegistry::new());
        for idx in 1..=2 {
            let mut rec = mk_record(idx);
            rec.node_key_hex = format!("node-rename-{idx}");
            rec.hostname = format!("rename-{idx}");
            reg.upsert(rec.node_key_hex.clone(), rec);
        }
        let _handle = reg.configure_nodestore_write_batcher(2, Duration::from_secs(5));
        let batch_size_before = reg.nodestore_batch_size_metrics();

        let first_reg = reg.clone();
        let first =
            std::thread::spawn(move || first_reg.rename("node-rename-1", "shared-name".into()));

        let deadline = Instant::now() + Duration::from_secs(2);
        while reg.nodestore_queue_depth() == 0 {
            assert!(
                Instant::now() < deadline,
                "first rename did not enqueue before the deadline"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            reg.get("node-rename-1").map(|rec| rec.hostname),
            Some("rename-1".into()),
            "first rename should wait for another item or the timeout"
        );

        assert!(!reg.rename("node-rename-2", "shared-name".into()));
        assert!(first.join().expect("first rename thread should finish"));

        assert_eq!(
            reg.get("node-rename-1").map(|rec| rec.hostname),
            Some("shared-name".into())
        );
        assert_eq!(
            reg.get("node-rename-2").map(|rec| rec.hostname),
            Some("rename-2".into())
        );
        assert_eq!(reg.nodestore_queue_depth(), 0);
        assert_eq!(
            reg.nodestore_operation_metrics()
                .get("set_name")
                .copied()
                .unwrap_or_default(),
            2
        );

        let batch_size = reg.nodestore_batch_size_metrics();
        assert_eq!(batch_size.count, batch_size_before.count + 1);
        assert_eq!(batch_size.bucket("2"), batch_size_before.bucket("2") + 1);
    }

    #[test]
    fn nodestore_write_batcher_noop_update_does_not_publish_snapshot() {
        let reg = Arc::new(MachineRegistry::new());
        let mut rec = mk_record(1);
        rec.node_key_hex = "node-noop-update".into();
        reg.upsert(rec.node_key_hex.clone(), rec);
        let _handle = reg.configure_nodestore_write_batcher(1, Duration::from_secs(5));

        let before = reg.snapshot();
        assert!(reg.set_available_routes("node-noop-update", Vec::new()));
        let after = reg.snapshot();

        assert!(
            Arc::ptr_eq(&before, &after),
            "unchanged update should not publish a new snapshot"
        );
        assert_eq!(
            reg.nodestore_operation_metrics()
                .get("update")
                .copied()
                .unwrap_or_default(),
            1
        );
        assert_eq!(reg.nodestore_batch_size_metrics().count, 2);
    }

    #[test]
    fn nodestore_write_batcher_batches_concurrent_rekeys() {
        let reg = Arc::new(MachineRegistry::new());
        for idx in 1..=2 {
            let mut rec = mk_record(idx);
            rec.node_key_hex = format!("node-rekey-old-{idx}");
            rec.machine_key_hex = format!("machine-rekey-{idx}");
            reg.upsert(rec.node_key_hex.clone(), rec);
        }
        let _handle = reg.configure_nodestore_write_batcher(2, Duration::from_secs(5));
        let batch_size_before = reg.nodestore_batch_size_metrics();

        let first_reg = reg.clone();
        let first = std::thread::spawn(move || {
            let mut rec = first_reg.get("node-rekey-old-1").unwrap();
            rec.node_key_hex = "node-rekey-new-1".into();
            first_reg.replace_node_key_quiet("node-rekey-old-1", "node-rekey-new-1".into(), rec);
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        while reg.nodestore_queue_depth() == 0 {
            assert!(
                Instant::now() < deadline,
                "first rekey did not enqueue before the deadline"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            reg.get("node-rekey-new-1").is_none(),
            "first rekey should wait for another item or the timeout"
        );

        let mut second = reg.get("node-rekey-old-2").unwrap();
        second.node_key_hex = "node-rekey-new-2".into();
        reg.replace_node_key_quiet("node-rekey-old-2", "node-rekey-new-2".into(), second);
        first.join().expect("first rekey thread should finish");

        assert!(reg.get("node-rekey-old-1").is_none());
        assert!(reg.get("node-rekey-old-2").is_none());
        assert!(reg.get("node-rekey-new-1").is_some());
        assert!(reg.get("node-rekey-new-2").is_some());
        assert_eq!(reg.nodestore_queue_depth(), 0);
        assert_eq!(
            reg.nodestore_operation_metrics()
                .get("replace_key")
                .copied()
                .unwrap_or_default(),
            2
        );

        let batch_size = reg.nodestore_batch_size_metrics();
        assert_eq!(batch_size.count, batch_size_before.count + 1);
        assert_eq!(batch_size.bucket("2"), batch_size_before.bucket("2") + 1);
    }

    #[test]
    fn nodestore_write_batcher_batches_concurrent_offline_updates() {
        let reg = Arc::new(MachineRegistry::new());
        let before = Utc::now() - chrono::Duration::minutes(5);
        for idx in 1..=2 {
            let mut rec = mk_record(idx);
            rec.node_key_hex = format!("node-offline-{idx}");
            rec.last_seen = before;
            reg.upsert(rec.node_key_hex.clone(), rec);
            let node_id = reg.stable_node_id_for_key(&format!("node-offline-{idx}"));
            reg.active_connections.write().insert(node_id, 0);
            reg.online_states.write().insert(node_id, true);
            reg.connection_generations.write().insert(node_id, 1);
        }
        let first_id = reg.stable_node_id_for_key("node-offline-1");
        let second_id = reg.stable_node_id_for_key("node-offline-2");
        let _handle = reg.configure_nodestore_write_batcher(2, Duration::from_secs(5));
        let batch_size_before = reg.nodestore_batch_size_metrics();

        let first_reg = reg.clone();
        let first = std::thread::spawn(move || first_reg.release_state_session(first_id, 1));

        let deadline = Instant::now() + Duration::from_secs(2);
        while reg.nodestore_queue_depth() == 0 {
            assert!(
                Instant::now() < deadline,
                "first offline update did not enqueue before the deadline"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            reg.get("node-offline-1").unwrap().last_seen,
            before,
            "first offline update should wait for another item or the timeout"
        );

        reg.release_state_session(second_id, 1);
        first
            .join()
            .expect("first offline update thread should finish");

        assert!(reg.get("node-offline-1").unwrap().last_seen > before);
        assert!(reg.get("node-offline-2").unwrap().last_seen > before);
        assert_eq!(reg.nodestore_queue_depth(), 0);
        assert_eq!(
            reg.nodestore_operation_metrics()
                .get("update")
                .copied()
                .unwrap_or_default(),
            2
        );

        let batch_size = reg.nodestore_batch_size_metrics();
        assert_eq!(batch_size.count, batch_size_before.count + 1);
        assert_eq!(batch_size.bucket("2"), batch_size_before.bucket("2") + 1);
    }

    #[test]
    fn nodestore_write_batcher_update_many_sets_approved_routes_atomically() {
        let reg = Arc::new(MachineRegistry::new());
        for idx in 1..=2 {
            let mut rec = mk_record(idx);
            rec.node_key_hex = format!("node-update-many-{idx}");
            rec.available_routes = vec![format!("10.{idx}.0.0/24")];
            reg.upsert(rec.node_key_hex.clone(), rec);
        }
        let _handle = reg.configure_nodestore_write_batcher(1, Duration::from_secs(5));
        let batch_size_before = reg.nodestore_batch_size_metrics();

        let (changed, missing) = reg.set_approved_routes_many(vec![
            ("node-update-many-1".into(), vec!["10.1.0.0/24".into()]),
            ("node-update-many-2".into(), vec!["10.2.0.0/24".into()]),
        ]);

        assert_eq!(changed, 2);
        assert!(missing.is_empty());
        assert_eq!(
            reg.get("node-update-many-1").unwrap().approved_routes,
            vec!["10.1.0.0/24"]
        );
        assert_eq!(
            reg.get("node-update-many-2").unwrap().approved_routes,
            vec!["10.2.0.0/24"]
        );
        assert_eq!(
            reg.nodestore_operation_metrics()
                .get("update_multi")
                .copied()
                .unwrap_or_default(),
            1
        );
        assert_eq!(
            reg.nodestore_operation_metrics()
                .get("update")
                .copied()
                .unwrap_or_default(),
            0
        );

        let batch_size = reg.nodestore_batch_size_metrics();
        assert_eq!(batch_size.count, batch_size_before.count + 1);
        assert_eq!(batch_size.bucket("1"), batch_size_before.bucket("1") + 1);
    }

    #[test]
    fn nodestore_write_batcher_update_many_route_noops_stay_quiet() {
        let reg = Arc::new(MachineRegistry::new());
        for idx in 1..=2 {
            let mut rec = mk_record(idx);
            rec.node_key_hex = format!("node-update-many-noop-{idx}");
            rec.available_routes = vec![format!("10.{idx}.0.0/24")];
            rec.approved_routes = rec.available_routes.clone();
            reg.upsert(rec.node_key_hex.clone(), rec);
        }
        let history_len = reg.map_change_history().len();
        let snapshot = reg.snapshot();
        let generation = reg.subscribe_gen();
        let _handle = reg.configure_nodestore_write_batcher(1, Duration::from_secs(5));

        let (changed, missing) = reg.set_approved_routes_many(vec![
            ("node-update-many-noop-1".into(), vec!["10.1.0.0/24".into()]),
            ("node-update-many-noop-2".into(), vec!["10.2.0.0/24".into()]),
        ]);

        assert_eq!(changed, 0);
        assert!(missing.is_empty());
        assert_eq!(
            reg.map_change_history().len(),
            history_len,
            "replayed policy auto-approval should not record map churn"
        );
        assert!(
            reg.pending_map_changes().is_empty(),
            "replayed policy auto-approval should not enqueue stream deltas"
        );
        assert!(
            !generation.has_changed().unwrap(),
            "replayed policy auto-approval should not wake map streams"
        );
        assert!(
            Arc::ptr_eq(&snapshot, &reg.snapshot()),
            "replayed policy auto-approval should not publish a fresh NodeStore snapshot"
        );
    }

    #[test]
    fn nodestore_write_batcher_update_many_missing_node_is_atomic() {
        let reg = Arc::new(MachineRegistry::new());
        let mut rec = mk_record(1);
        rec.node_key_hex = "node-update-many-present".into();
        reg.upsert(rec.node_key_hex.clone(), rec);
        let _handle = reg.configure_nodestore_write_batcher(1, Duration::from_secs(5));

        let (changed, missing) = reg.set_approved_routes_many(vec![
            (
                "node-update-many-present".into(),
                vec!["10.1.0.0/24".into()],
            ),
            (
                "node-update-many-missing".into(),
                vec!["10.2.0.0/24".into()],
            ),
        ]);

        assert_eq!(changed, 0);
        assert_eq!(missing, vec!["node-update-many-missing"]);
        assert!(
            reg.get("node-update-many-present")
                .unwrap()
                .approved_routes
                .is_empty()
        );
        assert_eq!(
            reg.nodestore_operation_metrics()
                .get("update_multi")
                .copied()
                .unwrap_or_default(),
            1
        );
    }

    #[test]
    fn nodestore_write_batcher_update_many_deleted_same_batch_returns_zero() {
        let reg = Arc::new(MachineRegistry::new());
        let mut rec = mk_record(1);
        rec.node_key_hex = "node-update-many-delete".into();
        rec.available_routes = vec!["10.9.0.0/24".into()];
        let node_id = rec.stable_node_id_for_key(&rec.node_key_hex);
        reg.upsert(rec.node_key_hex.clone(), rec);
        let history_len = reg.map_change_history().len();
        let _handle = reg.configure_nodestore_write_batcher(2, Duration::from_secs(5));
        let batch_size_before = reg.nodestore_batch_size_metrics();

        let first_reg = reg.clone();
        let first = std::thread::spawn(move || {
            first_reg.set_approved_routes_many(vec![(
                "node-update-many-delete".into(),
                vec!["10.9.0.0/24".into()],
            )])
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        while reg.nodestore_queue_depth() == 0 {
            assert!(
                Instant::now() < deadline,
                "first update-many did not enqueue before the deadline"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            reg.get("node-update-many-delete")
                .unwrap()
                .approved_routes
                .is_empty(),
            "first update-many should wait for another item or the timeout"
        );

        assert!(reg.delete("node-update-many-delete"));
        let (changed, missing) = first
            .join()
            .expect("queued update-many should finish after same-batch delete");
        assert_eq!(
            changed, 0,
            "update-many completion should reflect final absence after same-batch delete"
        );
        assert!(missing.is_empty());

        assert!(reg.get("node-update-many-delete").is_none());
        assert_eq!(reg.nodestore_queue_depth(), 0);
        assert_eq!(
            reg.nodestore_operation_metrics()
                .get("update_multi")
                .copied()
                .unwrap_or_default(),
            1
        );
        assert_eq!(
            reg.nodestore_operation_metrics()
                .get("delete")
                .copied()
                .unwrap_or_default(),
            1
        );

        let batch_size = reg.nodestore_batch_size_metrics();
        assert_eq!(batch_size.count, batch_size_before.count + 1);
        assert_eq!(batch_size.bucket("2"), batch_size_before.bucket("2") + 1);

        let changes = reg.map_change_history();
        let new_changes = &changes[history_len..];
        assert_eq!(new_changes.len(), 1, "{new_changes:?}");
        assert_eq!(new_changes[0].reason_label(), "peers removed");
        assert_eq!(new_changes[0].content.peers_removed, vec![node_id]);
        assert!(new_changes[0].content.peers_changed.is_empty());
        assert!(new_changes[0].content.peer_patches.is_empty());
    }

    #[test]
    fn nodestore_write_batcher_gc_ephemeral_uses_delete_multi() {
        let reg = Arc::new(MachineRegistry::new());
        for idx in 1..=3 {
            let mut rec = mk_record(idx);
            rec.node_key_hex = format!("node-gc-{idx}");
            rec.ephemeral = true;
            rec.last_seen = if idx == 3 {
                Utc::now()
            } else {
                Utc::now() - chrono::Duration::minutes(5)
            };
            reg.upsert(rec.node_key_hex.clone(), rec);
        }
        let _handle = reg.configure_nodestore_write_batcher(1, Duration::from_secs(5));
        let batch_size_before = reg.nodestore_batch_size_metrics();

        let mut removed = reg.gc_ephemeral(Duration::from_secs(60));
        removed.sort();

        assert_eq!(removed, vec!["node-gc-1", "node-gc-2"]);
        assert!(reg.get("node-gc-1").is_none());
        assert!(reg.get("node-gc-2").is_none());
        assert!(reg.get("node-gc-3").is_some());
        assert_eq!(
            reg.nodestore_operation_metrics()
                .get("delete_multi")
                .copied()
                .unwrap_or_default(),
            1
        );
        assert_eq!(
            reg.nodestore_operation_metrics()
                .get("update")
                .copied()
                .unwrap_or_default(),
            0
        );

        let batch_size = reg.nodestore_batch_size_metrics();
        assert_eq!(batch_size.count, batch_size_before.count + 1);
        assert_eq!(batch_size.bucket("1"), batch_size_before.bucket("1") + 1);
    }

    #[test]
    fn nodestore_read_helper_finds_machine_key_across_users() {
        let reg = MachineRegistry::new();

        let mut alice = mk_record(1);
        alice.node_id = Some(20);
        alice.node_key_hex = "node-alice".into();
        alice.machine_key_hex = "machine-shared".into();
        alice.user = "alice".into();
        alice.user_id = Some(7);
        reg.upsert(alice.node_key_hex.clone(), alice);

        let mut bob = mk_record(2);
        bob.node_id = Some(10);
        bob.node_key_hex = "node-bob".into();
        bob.machine_key_hex = "machine-shared".into();
        bob.user = "bob".into();
        bob.user_id = Some(8);
        reg.upsert(bob.node_key_hex.clone(), bob);

        let (node_key, rec) = reg
            .get_by_machine_key_any_user("machine-shared")
            .expect("machine key found across users");
        assert_eq!(node_key, "node-bob");
        assert_eq!(rec.user_id, Some(8));
        assert!(reg.get_by_machine_key_any_user("").is_none());
        assert!(reg.get_by_machine_key_any_user("missing").is_none());
    }

    #[test]
    fn nodestore_read_helper_lists_user_owned_nodes_only() {
        let reg = MachineRegistry::new();

        let mut owned = mk_record(1);
        owned.node_id = Some(1);
        owned.node_key_hex = "node-owned".into();
        owned.user_id = Some(7);
        reg.upsert(owned.node_key_hex.clone(), owned);

        let mut tagged = mk_record(2);
        tagged.node_id = Some(2);
        tagged.node_key_hex = "node-tagged".into();
        tagged.user_id = Some(7);
        tagged.forced_tags = vec!["tag:server".into()];
        reg.upsert(tagged.node_key_hex.clone(), tagged);

        let mut other_user = mk_record(3);
        other_user.node_id = Some(3);
        other_user.node_key_hex = "node-other-user".into();
        other_user.user_id = Some(8);
        reg.upsert(other_user.node_key_hex.clone(), other_user);

        let node_keys = reg
            .list_nodes_by_user_id(7)
            .into_iter()
            .map(|(node_key, _)| node_key)
            .collect::<Vec<_>>();
        assert_eq!(node_keys, vec!["node-owned"]);
        assert!(reg.list_nodes_by_user_id(99).is_empty());
    }

    #[test]
    fn nodestore_read_helper_lists_policyless_peers_for_existing_node() {
        let reg = MachineRegistry::new();
        for (node_id, node_key) in [(1, "node-a"), (2, "node-b"), (3, "node-c")] {
            let mut rec = mk_record(node_id as u32);
            rec.node_id = Some(node_id);
            rec.node_key_hex = node_key.into();
            reg.upsert(rec.node_key_hex.clone(), rec);
        }

        let node_keys = reg
            .list_peers_for(2)
            .into_iter()
            .map(|(node_key, _)| node_key)
            .collect::<Vec<_>>();
        assert_eq!(node_keys, vec!["node-a", "node-c"]);
        assert!(reg.list_peers_for(99).is_empty());
    }

    #[test]
    fn nodestore_read_helpers_report_primary_route_and_ha_nodes() {
        let reg = Arc::new(MachineRegistry::new());
        let route = "10.0.0.0/24";

        let mut first = route_record("router-a", 10, route);
        first.node_id = Some(1);
        reg.upsert(first.node_key_hex.clone(), first);

        let mut second = route_record("router-b", 11, route);
        second.node_id = Some(2);
        reg.upsert(second.node_key_hex.clone(), second);

        let mut offline = route_record("router-offline", 12, route);
        offline.node_id = Some(3);
        reg.upsert(offline.node_key_hex.clone(), offline);

        let mut expired = route_record("router-expired", 13, route);
        expired.node_id = Some(4);
        expired.expiry = Some(Utc::now() - chrono::Duration::seconds(1));
        reg.upsert(expired.node_key_hex.clone(), expired);

        let mut exit = route_record("router-exit", 14, "0.0.0.0/0");
        exit.node_id = Some(5);
        exit.available_routes = vec!["0.0.0.0/0".into(), "::/0".into()];
        exit.approved_routes = exit.available_routes.clone();
        reg.upsert(exit.node_key_hex.clone(), exit);

        let first_guard =
            MachineRegistry::track_stream_connection_with_grace(reg.clone(), 1, Duration::ZERO);
        let _second_guard =
            MachineRegistry::track_stream_connection_with_grace(reg.clone(), 2, Duration::ZERO);
        let _expired_guard =
            MachineRegistry::track_stream_connection_with_grace(reg.clone(), 4, Duration::ZERO);
        let _exit_guard =
            MachineRegistry::track_stream_connection_with_grace(reg.clone(), 5, Duration::ZERO);

        assert_eq!(reg.primary_route_for(route), Some(1));
        assert_eq!(reg.primary_route_for("0.0.0.0/0"), None);
        assert_eq!(
            reg.ha_nodes(),
            BTreeMap::from([(route.to_string(), vec![1, 2])])
        );

        drop(first_guard);
        assert_eq!(reg.primary_route_for(route), Some(2));
        assert!(reg.ha_nodes().is_empty());
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
    fn unknown_lifecycle_mutators_do_not_emit_ghost_map_changes() {
        let reg = MachineRegistry::new();
        let generation = reg.subscribe_gen();
        let snapshot = reg.snapshot();
        let when = Utc::now() + chrono::Duration::seconds(60);

        assert!(!reg.set_expiry("nk-missing", Some(when)));
        assert!(!reg.logout("nk-missing"));
        assert!(!reg.rename("nk-missing", "renamed".into()));
        assert!(!reg.delete("nk-missing"));
        assert!(!reg.set_forced_tags("nk-missing", vec!["tag:dev".into()]));
        assert!(!reg.set_approved_routes("nk-missing", vec!["10.1.0.0/24".into()]));
        assert!(!reg.set_available_routes("nk-missing", vec!["10.1.0.0/24".into()]));

        assert!(
            !generation.has_changed().unwrap(),
            "unknown lifecycle requests should not wake map streams"
        );
        assert!(
            reg.map_change_history().is_empty(),
            "unknown lifecycle requests should not record synthetic map changes"
        );
        assert!(
            Arc::ptr_eq(&snapshot, &reg.snapshot()),
            "unknown lifecycle requests should not publish a fresh NodeStore snapshot"
        );
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
            reg.wake_expired_nodes_between(base, expiry + chrono::Duration::nanoseconds(1)),
            vec!["nk-a".to_string()]
        );
        assert!(gen_rx.has_changed().unwrap());
        gen_rx.borrow_and_update();
        let stored = reg.get("nk-a").expect("expired node remains registered");
        assert_eq!(stored.expiry, Some(expiry));
        assert!(stored.is_expired_at(expiry + chrono::Duration::nanoseconds(1)));

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

    #[test]
    fn resolve_auto_given_name_sanitizes_fallbacks_and_suffixes() {
        let reg = MachineRegistry::new();
        let mut existing = mk_record(1);
        existing.hostname = "peer-one".into();
        existing.host_info.hostname = "Peer.One!".into();
        reg.upsert("nk-existing".into(), existing);

        assert_eq!(
            reg.resolve_auto_given_name("nk-new", "Peer.One!", None),
            "peer-one-1"
        );
        assert_eq!(reg.resolve_auto_given_name("nk-new", "!!!", None), "node");

        let long_hostname = "node".repeat(20);
        let expected_base = "node".repeat(15) + "nod";
        let mut long_existing = mk_record(2);
        long_existing.hostname.clone_from(&expected_base);
        reg.upsert("nk-long".into(), long_existing);
        assert_eq!(
            reg.resolve_auto_given_name("nk-new", &long_hostname, None),
            format!("{expected_base}-1")
        );
    }

    #[test]
    fn complete_web_registration_resolves_pending_raw_hostname() {
        let reg = MachineRegistry::new();
        let mut existing = mk_record(1);
        existing.hostname = "peer-one".into();
        existing.host_info.hostname = "Peer.One!".into();
        reg.upsert("nk-existing".into(), existing);

        let mut pending = mk_record(2);
        pending.node_key_hex = "nk-pending".into();
        pending.machine_key_hex = "mkey-pending".into();
        pending.hostname = "Peer.One!".into();
        pending.host_info.hostname = "Peer.One!".into();

        let completed = reg.complete_web_registration(pending, "alice", 2).unwrap();
        assert_eq!(completed.hostname, "peer-one-1");
        assert_eq!(reg.get("nk-pending").unwrap().hostname, "peer-one-1");
    }

    #[test]
    fn complete_web_registration_preserves_admin_renamed_given_name() {
        let reg = MachineRegistry::new();
        let mut existing = mk_record(1);
        existing.node_key_hex = "nk-existing".into();
        existing.machine_key_hex = "mkey-same".into();
        existing.hostname = "admin-name".into();
        existing.host_info.hostname = "old-host".into();
        reg.upsert("nk-existing".into(), existing);

        let mut pending = mk_record(2);
        pending.node_key_hex = "nk-pending".into();
        pending.machine_key_hex = "mkey-same".into();
        pending.hostname = "client-new-host".into();
        pending.host_info.hostname = "client-new-host".into();

        let completed = reg.complete_web_registration(pending, "alice", 2).unwrap();
        assert_eq!(completed.hostname, "admin-name");
        assert!(reg.get("nk-existing").is_none());
        let stored = reg.get("nk-pending").unwrap();
        assert_eq!(stored.hostname, "admin-name");
        assert_eq!(stored.host_info_for_node().hostname, "client-new-host");
    }

    #[test]
    fn complete_web_registration_rekey_preserves_ids_and_node_added_reason() {
        let reg = MachineRegistry::new();
        let mut existing = mk_record(1);
        existing.node_id = Some(777);
        existing.user_id = Some(7);
        existing.node_key_hex = "nk-existing".into();
        existing.machine_key_hex = "mkey-same".into();
        reg.upsert(existing.node_key_hex.clone(), existing);
        let history_len = reg.map_change_history().len();

        let mut pending = mk_record(2);
        pending.node_key_hex = "nk-pending".into();
        pending.machine_key_hex = "mkey-same".into();
        pending.hostname = "client-new-host".into();
        pending.host_info.hostname = "client-new-host".into();

        let completed = reg.complete_web_registration(pending, "alice", 2).unwrap();
        assert_eq!(completed.node_id, Some(777));
        assert_eq!(completed.user_id, Some(7));
        assert!(reg.get("nk-existing").is_none());
        let stored = reg.get("nk-pending").unwrap();
        assert_eq!(stored.node_id, Some(777));
        assert_eq!(stored.user_id, Some(7));

        let changes = reg.map_change_history();
        let new_changes = &changes[history_len..];
        assert_eq!(new_changes.len(), 1);
        assert_eq!(new_changes[0].reason_labels(), vec!["node added"]);
        assert_eq!(new_changes[0].change_type(), "peers");
        assert_eq!(new_changes[0].origin_node_id, Some(777));
        assert_eq!(new_changes[0].content.peers_changed, vec![777]);
        assert!(!new_changes[0].content.include_policy);
        assert!(!new_changes[0].content.requires_runtime_peer_computation);
    }

    /// `rename` rewrites the explicit GivenName; invalid or duplicate labels are rejected.
    #[test]
    fn rename_writes_hostname() {
        let reg = MachineRegistry::new();
        reg.upsert("nk-a".to_string(), mk_record(2));
        assert!(reg.rename("nk-a", "newhost".into()));
        assert_eq!(reg.get("nk-a").unwrap().hostname, "newhost");
        assert!(reg.rename("nk-a", "A".into()));
        assert_eq!(reg.get("nk-a").unwrap().hostname, "A");

        // Invalid labels are rejected.
        assert!(!reg.rename("nk-a", String::new()));
        assert!(!reg.rename("nk-a", "bad.name".into()));
        assert_eq!(reg.get("nk-a").unwrap().hostname, "A");

        let mut taken = mk_record(3);
        taken.hostname = "taken".into();
        reg.upsert("nk-b".to_string(), taken);
        assert!(!reg.rename("nk-a", "taken".into()));

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
    async fn ephemeral_gc_cancel_or_reschedule_discards_queued_deletion() {
        let reg = Arc::new(MachineRegistry::new());
        let mut rec = mk_record(4);
        rec.ephemeral = true;
        reg.upsert("nk-a".to_string(), rec);
        let deleted = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let store: Arc<dyn MachineRegistrationStore> = Arc::new(RecordingDeletionStore {
            deleted: deleted.clone(),
        });
        let gc = reg.configure_ephemeral_gc(Some(Arc::downgrade(&store)), Duration::from_secs(60));
        assert_eq!(gc.schedule_existing(), 1);
        let first_generation = gc.inner.timers.lock()["nk-a"].generation;

        // The timer has fired and its callback is queued, but the node
        // reconnects before the callback is run.
        gc.inner.cancel("nk-a");
        gc.inner
            .clone()
            .fire("nk-a".to_string(), first_generation)
            .await;
        assert!(reg.get("nk-a").is_some());
        assert!(deleted.lock().is_empty());

        // A later disconnect arms a new timer. The old callback must neither
        // remove that timer nor delete the newly reconnected node.
        gc.inner.schedule("nk-a".to_string());
        let second_generation = gc.inner.timers.lock()["nk-a"].generation;
        assert_ne!(first_generation, second_generation);
        gc.inner
            .clone()
            .fire("nk-a".to_string(), first_generation)
            .await;
        assert_eq!(gc.inner.timers.lock()["nk-a"].generation, second_generation);
        assert!(reg.get("nk-a").is_some());
        assert!(deleted.lock().is_empty());
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

    #[tokio::test]
    async fn ephemeral_gc_timer_does_not_delete_node_that_reauths_as_persistent() {
        let reg = Arc::new(MachineRegistry::new());
        let mut ephemeral = mk_record(6);
        ephemeral.ephemeral = true;
        reg.upsert("nk-a".to_string(), ephemeral);

        let gc = reg.configure_ephemeral_gc(None, Duration::from_millis(25));
        assert_eq!(gc.schedule_existing(), 1);

        let mut persistent = reg.get("nk-a").unwrap();
        persistent.ephemeral = false;
        persistent.node_key_hex = "nk-a".to_string();
        reg.upsert("nk-a".to_string(), persistent);

        tokio::time::sleep(Duration::from_millis(60)).await;
        let stored = reg
            .get("nk-a")
            .expect("persistent reauth must survive stale ephemeral timer");
        assert!(
            !stored.ephemeral,
            "stale ephemeral timer must observe the latest persistent node state"
        );
        gc.abort();
    }

    #[tokio::test]
    async fn explicit_ephemeral_delete_cancels_pending_persistent_gc_timer() {
        let reg = Arc::new(MachineRegistry::new());
        let mut rec = mk_record(7);
        rec.ephemeral = true;
        reg.upsert("nk-a".to_string(), rec);
        let deleted = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let store: Arc<dyn MachineRegistrationStore> = Arc::new(RecordingDeletionStore {
            deleted: deleted.clone(),
        });

        let gc =
            reg.configure_ephemeral_gc(Some(Arc::downgrade(&store)), Duration::from_millis(25));
        assert_eq!(gc.schedule_existing(), 1);
        assert!(reg.delete("nk-a"));

        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(
            deleted.lock().is_empty(),
            "explicit delete must cancel the pending ephemeral GC store deletion"
        );
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

    #[test]
    fn stream_connection_guard_records_cancelled_reason_when_node_is_deleted() {
        let reg = Arc::new(MachineRegistry::new());
        reg.upsert("nk-a".to_string(), mk_record(4));
        let node_id = stable_id_from_key("nk-a");

        let guard = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_id,
            Duration::ZERO,
        );
        assert_eq!(reg.active_connections().get(&node_id), Some(&1));

        assert!(reg.delete("nk-a"));
        drop(guard);

        let ended = reg.mapresponse_ended_metrics();
        assert_eq!(ended.get("cancelled"), Some(&1));
        assert_eq!(ended.get("done"), None);
        assert!(!reg.active_connections().contains_key(&node_id));
        assert!(!reg.online_states().contains_key(&node_id));
    }

    #[test]
    fn map_change_history_records_canonical_node_churn_reasons() {
        let reg = Arc::new(MachineRegistry::new());
        reg.upsert("nk-a".to_string(), mk_record(4));
        let node_id = stable_id_from_key("nk-a");

        assert!(reg.set_available_routes("nk-a", vec!["10.1.0.0/24".into()]));
        assert!(reg.set_expiry("nk-a", Some(Utc::now())));

        let guard = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_id,
            Duration::ZERO,
        );
        drop(guard);
        assert!(reg.delete("nk-a"));

        let changes = reg.map_change_history();
        let labels = changes
            .iter()
            .map(MapChange::reason_label)
            .collect::<Vec<_>>();
        // headscale-go v0.29.5 State.Connect: the node's key is expired
        // (set_expiry(now)), so ShouldBeOnline() is false and Connect emits
        // change.NodeAdded(id) instead of NodeOnline; Disconnect emits
        // change.NodeOffline(id). Neither adds a PolicyChange because the
        // node is not a subnet router (its route is announced, not approved),
        // relay target or via target (PolicyManager.NodeNeedsPeerRecompute).
        assert_eq!(
            labels,
            vec![
                "node added",
                "route update",
                "node added",
                "node added",
                "node offline",
                "peers removed",
            ]
        );
        let types = changes
            .iter()
            .map(MapChange::change_type)
            .collect::<Vec<_>>();
        assert_eq!(
            types,
            vec!["peers", "peers", "peers", "peers", "patch", "peers"]
        );
        assert!(
            changes
                .windows(2)
                .all(|pair| pair[0].generation < pair[1].generation),
            "{changes:?}"
        );
        assert_eq!(changes[0].origin_node_id, Some(node_id));
        assert_eq!(changes[0].target_node_id, None);
        assert_eq!(changes[0].content.peers_changed, vec![node_id]);
        assert_eq!(changes[1].target_node_id, None);
        assert_eq!(changes[1].origin_node_id, None);
        assert_eq!(changes[1].content.peers_changed, vec![node_id]);
        assert_eq!(changes[2].origin_node_id, Some(node_id));
        assert_eq!(changes[2].target_node_id, None);
        assert_eq!(changes[2].content.peers_changed, vec![node_id]);
        assert_eq!(changes[3].target_node_id, None);
        // change.NodeAdded: PeersChanged [id], OriginNode id.
        assert_eq!(changes[3].reason_labels(), vec!["node added"]);
        assert!(!changes[3].content.include_policy);
        assert!(!changes[3].content.requires_runtime_peer_computation);
        assert_eq!(changes[3].origin_node_id, Some(node_id));
        assert_eq!(changes[3].content.peers_changed, vec![node_id]);
        assert_eq!(changes[4].target_node_id, None);
        // change.NodeOffline: a PeerPatches entry, no OriginNode.
        assert_eq!(changes[4].reason_labels(), vec!["node offline"]);
        assert!(!changes[4].content.include_policy);
        assert!(!changes[4].content.requires_runtime_peer_computation);
        assert_eq!(changes[4].origin_node_id, None);
        assert_eq!(changes[4].content.peer_patches, vec![node_id]);
        assert_eq!(changes[5].target_node_id, None);
        assert_eq!(changes[5].content.peers_removed, vec![node_id]);
    }

    #[test]
    fn map_change_type_matches_upstream_bounded_categories() {
        let node_id = 42;
        let full_self_change =
            PendingMapChange::target(MapChangeReason::FullSelfUpdate, node_id).into_change(1);
        assert_eq!(full_self_change.change_type(), "full");
        assert!(full_self_change.should_send_to_node(node_id));
        assert!(!full_self_change.should_send_to_node(node_id + 1));

        let self_change =
            PendingMapChange::target(MapChangeReason::SelfUpdate, node_id).into_change(1);
        assert_eq!(self_change.reason_labels(), vec!["self update"]);
        assert_eq!(self_change.change_type(), "self");
        assert!(self_change.should_send_to_node(node_id));
        assert!(!self_change.should_send_to_node(node_id + 1));

        let patch_change =
            PendingMapChange::broadcast_peer(MapChangeReason::NodeOnline, node_id).into_change(2);
        assert_eq!(patch_change.change_type(), "patch");

        let peers_change =
            PendingMapChange::broadcast_peer(MapChangeReason::RouteUpdate, node_id).into_change(3);
        assert_eq!(peers_change.change_type(), "peers");

        let config_change =
            PendingMapChange::global(MapChangeReason::DnsConfigUpdate).into_change(4);
        assert_eq!(config_change.change_type(), "config");

        let user_removed_change =
            PendingMapChange::global(MapChangeReason::UserRemoved).into_change(8);
        assert_eq!(user_removed_change.reason_labels(), vec!["user removed"]);
        assert_eq!(user_removed_change.change_type(), "full");
        assert!(user_removed_change.is_full());

        let policy_change = PendingMapChange::global(MapChangeReason::PolicyChange).into_change(5);
        assert_eq!(policy_change.change_type(), "policy");
        assert!(!policy_change.content.include_dns);
        assert!(policy_change.content.include_policy);

        let route_health_change =
            PendingMapChange::broadcast_peer(MapChangeReason::RouteHealthUpdate, node_id)
                .into_change(9);
        assert_eq!(
            route_health_change.reason_labels(),
            vec!["route health update"]
        );
        assert_eq!(route_health_change.change_type(), "policy");
        assert!(route_health_change.content.peers_changed.is_empty());
        assert!(route_health_change.content.include_policy);
        assert!(
            route_health_change
                .content
                .requires_runtime_peer_computation
        );

        let tag_change = PendingMapChange::global(MapChangeReason::TagUpdate).into_change(6);
        assert_eq!(tag_change.reason_labels(), vec!["tag update"]);
        assert_eq!(tag_change.change_type(), "policy");
        assert!(tag_change.content.requires_runtime_peer_computation);

        let ping_change =
            PendingMapChange::target(MapChangeReason::PingNode, node_id).into_change(7);
        assert_eq!(ping_change.change_type(), "ping");
    }

    #[test]
    fn map_change_content_flags_match_upstream_constructors() {
        let node_id = 42;
        let full = PendingMapChange::global(MapChangeReason::FullUpdate).into_change(1);
        assert!(full.content.include_self);
        assert!(full.content.include_derp_map);
        assert!(full.content.include_dns);
        assert!(full.content.include_domain);
        assert!(full.content.include_policy);
        assert!(full.content.send_all_peers);
        assert!(full.is_full());

        let full_self =
            PendingMapChange::target(MapChangeReason::FullSelfUpdate, node_id).into_change(2);
        assert!(full_self.is_full());
        assert_eq!(full_self.target_node_id, Some(node_id));
        assert!(full_self.should_send_to_node(node_id));
        assert!(!full_self.should_send_to_node(node_id + 1));

        let self_only =
            PendingMapChange::target(MapChangeReason::SelfUpdate, node_id).into_change(3);
        assert!(self_only.content.include_self);
        assert!(!self_only.content.include_derp_map);
        assert!(self_only.content.include_dns);
        assert!(!self_only.content.include_domain);
        assert!(!self_only.content.include_policy);
        assert!(self_only.is_self_only());

        let policy = PendingMapChange::global(MapChangeReason::PolicyChange).into_change(4);
        assert!(policy.content.include_policy);
        assert!(policy.content.requires_runtime_peer_computation);
        assert!(!policy.content.include_dns);

        let dns = PendingMapChange::global(MapChangeReason::DnsConfigUpdate).into_change(5);
        assert!(dns.content.include_dns);
        assert!(!dns.content.include_derp_map);
        assert!(!dns.content.include_domain);

        let derp = PendingMapChange::global(MapChangeReason::DerpMapUpdate).into_change(6);
        assert!(derp.content.include_derp_map);
        assert!(!derp.content.include_dns);
        assert!(!derp.content.include_domain);

        let ping = PendingMapChange::target(MapChangeReason::PingNode, node_id).into_change(7);
        assert!(ping.content.ping_request);
        assert_eq!(ping.target_node_id, Some(node_id));
        assert!(ping.should_send_to_node(node_id));
        assert!(!ping.should_send_to_node(node_id + 1));
    }

    #[test]
    fn map_change_merge_combines_reasons_and_state() {
        let node_id = 42;
        let peers =
            PendingMapChange::broadcast_peer(MapChangeReason::RouteUpdate, node_id).into_change(1);
        let patch =
            PendingMapChange::broadcast_peer(MapChangeReason::NodeOnline, node_id).into_change(2);
        let merged = peers.merge(patch);

        assert_eq!(merged.generation, 2);
        assert_eq!(merged.target_node_id, None);
        assert_eq!(merged.reason_labels(), vec!["route update", "node online"]);
        assert_eq!(merged.change_type(), "peers");
        assert_eq!(merged.content.peers_changed, vec![node_id]);
        assert_eq!(merged.content.peer_patches, vec![node_id]);
    }

    #[test]
    fn map_change_batcher_full_update_supersedes_pending() {
        let reg = Arc::new(MachineRegistry::new());
        let node_a = 1001;
        let node_b = 1002;
        for (id, host) in [(node_a, 1), (node_b, 2)] {
            let mut record = mk_record(host);
            record.node_id = Some(id);
            record.node_key_hex = format!("batcher-{id}");
            reg.upsert(record.node_key_hex.clone(), record);
        }
        let _guard_a = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_a,
            Duration::ZERO,
        );
        let _guard_b = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_b,
            Duration::ZERO,
        );

        reg.enqueue_map_change(
            PendingMapChange::broadcast_peer(MapChangeReason::NodeOnline, node_a).into_change(1),
        );
        reg.enqueue_map_change(
            PendingMapChange::global(MapChangeReason::DnsConfigUpdate).into_change(2),
        );
        reg.enqueue_map_change(MapChange::full_update(3));

        let pending = reg.pending_map_changes();
        assert_eq!(pending.len(), 2);
        for node_id in [node_a, node_b] {
            let changes = pending.get(&node_id).expect("node has pending change");
            assert_eq!(changes.len(), 1);
            assert_eq!(changes[0].reason_labels(), vec!["full update"]);
            assert_eq!(changes[0].change_type(), "full");
        }
    }

    #[tokio::test]
    async fn subnet_router_stream_lifecycle_queues_policy_recompute() {
        let reg = Arc::new(MachineRegistry::new());
        let observer_key = "subnet-observer";
        let router_key = "subnet-router";
        let route = "10.200.0.0/24";
        reg.upsert(observer_key.to_string(), mk_record(10));
        reg.upsert(router_key.to_string(), route_record(router_key, 11, route));
        let observer_id = stable_id_from_key(observer_key);
        let router_id = stable_id_from_key(router_key);

        let _observer_guard = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            observer_id,
            Duration::ZERO,
        );
        let _ = reg.drain_pending_map_changes();

        let router_guard = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            router_id,
            Duration::ZERO,
        );
        let online = reg
            .map_change_history()
            .pop()
            .expect("router online records a map change");
        assert_eq!(online.reason_labels(), vec!["node online", "policy change"]);
        assert_eq!(online.change_type(), "policy");
        assert_eq!(online.origin_node_id, None);
        assert!(!online.is_full());
        assert!(online.content.requires_runtime_peer_computation);
        let pending = reg.pending_map_changes();
        assert!(
            pending
                .get(&observer_id)
                .expect("observer receives subnet-router online change")
                .iter()
                .any(|change| change.content.requires_runtime_peer_computation)
        );
        let _ = reg.drain_pending_map_changes();

        drop(router_guard);
        tokio::task::yield_now().await;
        let offline = reg
            .map_change_history()
            .pop()
            .expect("router offline records a map change");
        assert_eq!(
            offline.reason_labels(),
            vec!["node offline", "policy change"]
        );
        assert_eq!(offline.change_type(), "policy");
        assert_eq!(offline.origin_node_id, None);
        assert!(!offline.is_full());
        assert!(offline.content.requires_runtime_peer_computation);
        let pending = reg.pending_map_changes();
        assert!(
            pending
                .get(&observer_id)
                .expect("observer receives subnet-router offline change")
                .iter()
                .any(|change| change.content.requires_runtime_peer_computation)
        );
    }

    #[test]
    fn user_removed_queues_full_update_for_live_streams() {
        let reg = Arc::new(MachineRegistry::new());
        let node_a = stable_id_from_key("user-removed-a");
        let node_b = stable_id_from_key("user-removed-b");
        reg.upsert("user-removed-a".into(), mk_record(1));
        reg.upsert("user-removed-b".into(), mk_record(2));
        let _guard_a = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_a,
            Duration::ZERO,
        );
        let _guard_b = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_b,
            Duration::ZERO,
        );
        let history_len = reg.map_change_history().len();
        let _ = reg.drain_pending_map_changes();

        reg.wake_user_removed_full_update();

        let changes = reg.map_change_history();
        let change = &changes[history_len];
        assert_eq!(change.reason_labels(), vec!["user removed"]);
        assert_eq!(change.change_type(), "full");
        assert!(change.is_full());

        let pending = reg.pending_map_changes();
        for node_id in [node_a, node_b] {
            let changes = pending.get(&node_id).expect("stream receives full update");
            assert_eq!(changes.len(), 1);
            assert_eq!(changes[0].reason_labels(), vec!["user removed"]);
            assert!(changes[0].is_full());
        }
    }

    #[test]
    fn map_change_batcher_splits_targeted_and_broadcast() {
        let reg = Arc::new(MachineRegistry::new());
        let node_a = 2001;
        let node_b = 2002;
        for (id, host) in [(node_a, 1), (node_b, 2)] {
            let mut record = mk_record(host);
            record.node_id = Some(id);
            record.node_key_hex = format!("batcher-{id}");
            reg.upsert(record.node_key_hex.clone(), record);
        }
        let _guard_a = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_a,
            Duration::ZERO,
        );
        let _guard_b = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_b,
            Duration::ZERO,
        );
        let _ = reg.drain_pending_map_changes();

        reg.enqueue_map_change(
            PendingMapChange::target(MapChangeReason::PingNode, node_a).into_change(1),
        );
        reg.enqueue_map_change(
            PendingMapChange::global(MapChangeReason::PolicyChange).into_change(2),
        );

        let pending = reg.pending_map_changes();
        let node_a_changes = pending
            .get(&node_a)
            .expect("target node has pending changes");
        assert_eq!(node_a_changes.len(), 2);
        assert!(node_a_changes[0].content.ping_request);
        assert!(!node_a_changes[0].content.include_policy);
        assert!(node_a_changes[1].content.include_policy);
        assert!(node_a_changes[1].content.requires_runtime_peer_computation);
        let node_a_labels = node_a_changes
            .iter()
            .flat_map(MapChange::reason_labels)
            .collect::<Vec<_>>();
        assert_eq!(node_a_labels, vec!["ping node", "policy change"]);

        let node_b_changes = pending
            .get(&node_b)
            .expect("broadcast node has pending changes");
        assert_eq!(node_b_changes.len(), 1);
        assert!(!node_b_changes[0].content.ping_request);
        assert!(node_b_changes[0].content.include_policy);
        assert!(node_b_changes[0].content.requires_runtime_peer_computation);
        let node_b_labels = node_b_changes
            .iter()
            .flat_map(MapChange::reason_labels)
            .collect::<Vec<_>>();
        assert_eq!(node_b_labels, vec!["policy change"]);
    }

    #[test]
    fn map_change_batcher_preserves_targeted_self_only_update() {
        let reg = Arc::new(MachineRegistry::new());
        let node_a = 2101;
        let node_b = 2102;
        for (id, host) in [(node_a, 1), (node_b, 2)] {
            let mut record = mk_record(host);
            record.node_id = Some(id);
            record.node_key_hex = format!("batcher-{id}");
            reg.upsert(record.node_key_hex.clone(), record);
        }
        let _guard_a = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_a,
            Duration::ZERO,
        );
        let _guard_b = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_b,
            Duration::ZERO,
        );
        let _ = reg.drain_pending_map_changes();

        reg.enqueue_map_change(
            PendingMapChange::target(MapChangeReason::SelfUpdate, node_a).into_change(1),
        );

        let pending = reg.pending_map_changes();
        let node_a_changes = pending
            .get(&node_a)
            .expect("target node receives self update");
        assert_eq!(node_a_changes.len(), 1);
        assert!(node_a_changes[0].is_self_only());
        assert_eq!(node_a_changes[0].change_type(), "self");
        assert!(node_a_changes[0].content.include_self);
        assert!(node_a_changes[0].content.peers_changed.is_empty());
        assert!(node_a_changes[0].content.peers_removed.is_empty());
        assert!(node_a_changes[0].content.peer_patches.is_empty());
        assert!(
            !pending.contains_key(&node_b),
            "self-only changes must not leak to broadcast observers"
        );
    }

    #[test]
    fn map_change_batcher_deletion_removes_deleted_node_pending_state() {
        let reg = Arc::new(MachineRegistry::new());
        let node_a = stable_id_from_key("nk-a");
        let node_b = stable_id_from_key("nk-b");
        // A map stream only exists for a node in the NodeStore (Go's poll
        // path validates the node before State.Connect / Batcher.AddNode), and
        // the registry deliberately gives a missing node no session or
        // batcher entry. Register both nodes before their streams connect.
        reg.upsert("nk-a".to_string(), mk_record(1));
        reg.upsert("nk-b".to_string(), mk_record(2));
        let _guard_a = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_a,
            Duration::ZERO,
        );
        let _guard_b = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_b,
            Duration::ZERO,
        );
        let _ = reg.drain_pending_map_changes();

        reg.enqueue_map_change(
            PendingMapChange::broadcast_peer(MapChangeReason::NodeOnline, node_b).into_change(10),
        );
        assert!(reg.pending_map_changes().contains_key(&node_b));

        assert!(reg.delete("nk-b"));

        let pending = reg.pending_map_changes();
        assert!(!pending.contains_key(&node_b));
        assert!(!reg.active_connections().contains_key(&node_b));
        assert_eq!(
            pending
                .get(&node_a)
                .and_then(|changes| changes.last())
                .map(|change| change.content.peers_removed.as_slice()),
            Some([node_b].as_slice())
        );
    }

    #[test]
    fn map_change_batcher_full_update_then_delete_prunes_deleted_stream() {
        let reg = Arc::new(MachineRegistry::new());
        let node_a = stable_id_from_key("nk-a");
        let node_b = stable_id_from_key("nk-b");
        reg.upsert("nk-a".to_string(), mk_record(1));
        reg.upsert("nk-b".to_string(), mk_record(2));
        let _guard_a = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_a,
            Duration::ZERO,
        );
        let _guard_b = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_b,
            Duration::ZERO,
        );
        let _ = reg.drain_pending_map_changes();

        reg.enqueue_map_change(MapChange::full_update(10));
        let pending = reg.pending_map_changes();
        assert_eq!(
            pending
                .get(&node_b)
                .and_then(|changes| changes.last())
                .map(MapChange::reason_labels),
            Some(vec!["full update"])
        );

        assert!(reg.delete("nk-b"));

        let pending = reg.pending_map_changes();
        assert!(
            !pending.contains_key(&node_b),
            "deleted streams must not retain stale full-update batches"
        );
        assert!(!reg.active_connections().contains_key(&node_b));
        assert_eq!(
            pending
                .get(&node_a)
                .expect("observer keeps pending changes")
                .iter()
                .flat_map(MapChange::reason_labels)
                .collect::<Vec<_>>(),
            vec!["full update", "peers removed"]
        );
    }

    #[test]
    fn map_change_batcher_publish_drains_pending_and_updates_watch() {
        let reg = Arc::new(MachineRegistry::new());
        let node_a = 3001;
        let node_b = 3002;
        for (id, host) in [(node_a, 1), (node_b, 2)] {
            let mut record = mk_record(host);
            record.node_id = Some(id);
            record.node_key_hex = format!("batcher-{id}");
            reg.upsert(record.node_key_hex.clone(), record);
        }
        let _guard_a = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_a,
            Duration::ZERO,
        );
        let _guard_b = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_b,
            Duration::ZERO,
        );

        let mut batch_rx = reg.subscribe_map_batches();
        let _ = reg.drain_pending_map_changes();
        reg.enqueue_map_change(
            PendingMapChange::global(MapChangeReason::PolicyChange).into_change(1),
        );

        let batch = reg
            .publish_pending_map_changes()
            .expect("pending changes publish");
        assert!(reg.pending_map_changes().is_empty());
        assert_eq!(batch.len(), 2);
        assert_eq!(
            batch
                .get(&node_a)
                .expect("node A batch")
                .iter()
                .flat_map(MapChange::reason_labels)
                .collect::<Vec<_>>(),
            vec!["policy change"]
        );
        assert!(batch_rx.has_changed().unwrap());
        assert_eq!(batch_rx.borrow_and_update().len(), 2);
        assert!(!batch_rx.has_changed().unwrap());
        assert!(reg.publish_pending_map_changes().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn map_change_batcher_tick_publishes_pending_batch() {
        let reg = Arc::new(MachineRegistry::new());
        let node_id = 4001;
        let mut record = mk_record(1);
        record.node_id = Some(node_id);
        record.node_key_hex = "batcher-4001".into();
        reg.upsert(record.node_key_hex.clone(), record);
        let _guard = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_id,
            Duration::ZERO,
        );
        let mut batch_rx = reg.subscribe_map_batches();
        let _handle = spawn_map_change_batcher(reg.clone(), Duration::from_millis(10));
        tokio::task::yield_now().await;
        let _ = reg.drain_pending_map_changes();

        reg.enqueue_map_change(
            PendingMapChange::broadcast_peer(MapChangeReason::RouteUpdate, node_id).into_change(1),
        );
        assert!(!batch_rx.has_changed().unwrap());

        tokio::time::advance(Duration::from_millis(10)).await;
        batch_rx.changed().await.unwrap();
        let batch = batch_rx.borrow_and_update().clone();
        assert_eq!(
            batch
                .get(&node_id)
                .expect("node batch")
                .iter()
                .flat_map(MapChange::reason_labels)
                .collect::<Vec<_>>(),
            vec!["route update"]
        );
        assert!(reg.pending_map_changes().is_empty());
    }

    #[test]
    #[should_panic(expected = "cannot merge map changes with different target nodes")]
    fn map_change_merge_rejects_different_targets() {
        let left = PendingMapChange::target(MapChangeReason::PingNode, 1).into_change(1);
        let right = PendingMapChange::target(MapChangeReason::PingNode, 2).into_change(2);
        let _ = left.merge(right);
    }

    #[test]
    fn map_change_history_is_bounded() {
        let reg = MachineRegistry::new();
        for i in 0..(MAP_CHANGE_HISTORY_LIMIT + 3) {
            let node_key = format!("nk-{i}");
            reg.upsert(node_key, mk_record(i as u32));
        }

        let changes = reg.map_change_history();
        assert_eq!(changes.len(), MAP_CHANGE_HISTORY_LIMIT);
        assert_eq!(
            changes.last().map(|change| change.generation),
            Some((MAP_CHANGE_HISTORY_LIMIT + 3) as u64)
        );
        assert_eq!(changes.first().map(|change| change.generation), Some(4));
    }

    #[test]
    fn batcher_cleanup_offline_connections_keeps_recent_disconnect() {
        let reg = Arc::new(MachineRegistry::new());
        reg.upsert("nk-a".to_string(), mk_record(4));
        let node_id = stable_id_from_key("nk-a");
        let guard = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_id,
            Duration::ZERO,
        );
        let generation = reg.connection_generation(node_id).unwrap();
        reg.mark_route_health_session_stable(node_id, generation);

        drop(guard);
        assert_eq!(reg.active_connections().get(&node_id), Some(&0));
        assert_eq!(reg.online_states().get(&node_id), Some(&false));
        assert!(reg.disconnected_at.read().contains_key(&node_id));

        let cleaned = reg.cleanup_offline_connections(Duration::from_secs(60));
        assert!(cleaned.is_empty());
        assert_eq!(reg.active_connections().get(&node_id), Some(&0));
        assert_eq!(reg.online_states().get(&node_id), Some(&false));
        assert!(reg.disconnected_at.read().contains_key(&node_id));
        assert!(
            reg.route_health_stable_sessions
                .read()
                .contains_key(&node_id)
        );
        assert!(reg.get("nk-a").is_some());
    }

    #[test]
    fn batcher_cleanup_offline_connections_removes_stale_zero_count_entry() {
        let reg = Arc::new(MachineRegistry::new());
        reg.upsert("nk-a".to_string(), mk_record(4));
        let node_id = stable_id_from_key("nk-a");
        let guard = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_id,
            Duration::ZERO,
        );
        let generation = reg.connection_generation(node_id).unwrap();
        reg.mark_route_health_session_stable(node_id, generation);

        drop(guard);
        let cleaned = reg.cleanup_offline_connections(Duration::ZERO);
        assert_eq!(cleaned, vec![node_id]);
        assert!(!reg.active_connections().contains_key(&node_id));
        assert_eq!(reg.online_states().get(&node_id), Some(&false));
        assert_eq!(reg.connection_generation(node_id), Some(generation));
        assert!(!reg.disconnected_at.read().contains_key(&node_id));
        assert!(
            !reg.route_health_stable_sessions
                .read()
                .contains_key(&node_id)
        );
        assert!(reg.get("nk-a").is_some());
        assert!(reg.cleanup_offline_connections(Duration::ZERO).is_empty());
    }

    #[test]
    fn stream_connection_multi_connection_drop_keeps_node_online_until_last_guard() {
        let reg = Arc::new(MachineRegistry::new());
        reg.upsert("nk-a".to_string(), mk_record(4));
        let node_id = stable_id_from_key("nk-a");

        let first = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_id,
            Duration::ZERO,
        );
        let history_len = reg.map_change_history().len();
        let second = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_id,
            Duration::ZERO,
        );
        assert_eq!(reg.active_connections().get(&node_id), Some(&2));
        assert_eq!(reg.online_states().get(&node_id), Some(&true));
        assert_eq!(
            reg.map_change_history().len(),
            history_len + 1,
            "headscale-go Connect of another channel emits its lightweight online change"
        );

        drop(second);
        assert_eq!(reg.active_connections().get(&node_id), Some(&1));
        assert_eq!(reg.online_states().get(&node_id), Some(&true));
        assert!(!reg.disconnected_at.read().contains_key(&node_id));
        assert_eq!(
            reg.map_change_history().len(),
            history_len + 1,
            "headscale-go RemoveNode reports still connected while another channel remains"
        );

        drop(first);
        assert_eq!(reg.active_connections().get(&node_id), Some(&0));
        assert_eq!(reg.online_states().get(&node_id), Some(&false));
        assert!(reg.disconnected_at.read().contains_key(&node_id));
        let changes = reg.map_change_history();
        let final_change = changes
            .last()
            .expect("last connection drop records offline churn");
        assert!(final_change.reason_labels().contains(&"node offline"));
    }

    #[test]
    fn stream_connection_reconnect_clears_stale_offline_cleanup_state() {
        let reg = Arc::new(MachineRegistry::new());
        reg.upsert("nk-a".to_string(), mk_record(4));
        let node_id = stable_id_from_key("nk-a");

        let first = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_id,
            Duration::ZERO,
        );
        drop(first);
        assert_eq!(reg.active_connections().get(&node_id), Some(&0));
        assert_eq!(reg.online_states().get(&node_id), Some(&false));
        assert!(reg.disconnected_at.read().contains_key(&node_id));

        let second = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_id,
            Duration::ZERO,
        );
        assert_eq!(reg.active_connections().get(&node_id), Some(&1));
        assert_eq!(reg.online_states().get(&node_id), Some(&true));
        assert!(
            !reg.disconnected_at.read().contains_key(&node_id),
            "rapid reconnect must remove the old disconnect timestamp before cleanup runs"
        );
        assert!(
            reg.cleanup_offline_connections(Duration::ZERO).is_empty(),
            "cleanup must not prune a freshly reconnected session"
        );
        assert_eq!(reg.active_connections().get(&node_id), Some(&1));
        assert_eq!(reg.online_states().get(&node_id), Some(&true));

        drop(second);
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
        let generation = reg.subscribe_gen();
        // Spin briefly to ensure the wall-clock ticks past `before`.
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(reg.touch_last_seen("nk-a"));
        let after = reg.get("nk-a").unwrap().last_seen;
        assert!(after > before, "touch should advance last_seen");
        assert!(
            !generation.has_changed().unwrap(),
            "touch should not wake map streams"
        );
        assert!(!reg.touch_last_seen("nk-zzz"));
    }

    /// `set_forced_tags` round-trip + override semantics.
    #[test]
    fn set_forced_tags_replaces_list() {
        let reg = MachineRegistry::new();
        reg.upsert("nk-a".to_string(), mk_record(7));
        assert!(reg.set_forced_tags("nk-a", vec!["tag:dev".into(), "tag:ci".into()]));
        let rec = reg.get("nk-a").unwrap();
        assert_eq!(rec.forced_tags, vec!["tag:ci", "tag:dev"]);
        // Replace, not merge.
        assert!(reg.set_forced_tags("nk-a", vec!["tag:prod".into()]));
        assert_eq!(reg.get("nk-a").unwrap().forced_tags, vec!["tag:prod"]);
        // Empty list is rejected like upstream `SetNodeTags`.
        assert!(!reg.set_forced_tags("nk-a", Vec::new()));
        assert_eq!(reg.get("nk-a").unwrap().forced_tags, vec!["tag:prod"]);
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
    fn nodestore_write_batcher_route_noops_do_not_emit_map_churn() {
        let reg = Arc::new(MachineRegistry::new());
        let observer_key = "route-noop-observer";
        let router_key = "route-noop-router";
        let route = "10.77.0.0/24";
        reg.upsert(observer_key.to_string(), mk_record(77));
        reg.upsert(router_key.to_string(), route_record(router_key, 78, route));
        let _guard = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            stable_id_from_key(observer_key),
            Duration::ZERO,
        );
        let _ = reg.drain_pending_map_changes();
        let history_len = reg.map_change_history().len();
        let snapshot = reg.snapshot();
        let generation = reg.subscribe_gen();
        let _handle = reg.configure_nodestore_write_batcher(1, Duration::from_secs(5));

        // An unchanged route announcement (Go: UpdateNodeFromMapRequest with
        // no route/hostinfo delta) is a true no-op.
        assert!(reg.set_available_routes(router_key, vec![route.into()]));
        assert_eq!(
            reg.map_change_history().len(),
            history_len,
            "unchanged route state should not record map changes"
        );
        assert!(
            reg.pending_map_changes().is_empty(),
            "unchanged route state should not enqueue stream deltas"
        );
        assert!(
            !generation.has_changed().unwrap(),
            "unchanged route state should not bump the map generation"
        );
        assert!(
            Arc::ptr_eq(&snapshot, &reg.snapshot()),
            "unchanged route state should not publish a fresh NodeStore snapshot"
        );

        // headscale-go v0.29.5 State.SetApprovedRoutes always runs
        // NodeStore.UpdateNode and always returns a change: when
        // persistNodeAndRefreshPolicy's change is not full it is replaced by
        // change.PolicyChange(), even if the approved set is unchanged. So
        // re-approving the same routes emits exactly one global policy change.
        assert!(reg.set_approved_routes(router_key, vec![route.into()]));

        let updated = reg.get(router_key).expect("router remains registered");
        assert_eq!(updated.available_routes, vec![route]);
        assert_eq!(updated.approved_routes, vec![route]);
        let changes = reg.map_change_history();
        let new_changes = &changes[history_len..];
        assert_eq!(new_changes.len(), 1, "{new_changes:?}");
        assert_eq!(new_changes[0].reason_labels(), vec!["policy change"]);
        assert_eq!(new_changes[0].origin_node_id, None);
        assert_eq!(new_changes[0].target_node_id, None);
        assert!(new_changes[0].content.include_policy);
        assert!(new_changes[0].content.requires_runtime_peer_computation);
        assert!(
            reg.pending_map_changes()
                .contains_key(&stable_id_from_key(observer_key)),
            "the policy change reaches the connected observer"
        );
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
    fn set_approved_routes_empty_clears_stale_unhealthy_mark() {
        let reg = Arc::new(MachineRegistry::new());
        let node_key = "route-clear-unhealthy";
        let node_id = stable_id_from_key(node_key);
        let route = "10.0.0.0/24";
        reg.upsert(node_key.to_string(), route_record(node_key, 9, route));
        let _guard = MachineRegistry::track_stream_connection_with_grace(
            reg.clone(),
            node_id,
            Duration::ZERO,
        );

        let _ = reg.set_route_candidate_health(node_id, false);
        assert!(!reg.is_route_candidate_healthy(node_id));

        assert!(reg.set_approved_routes(node_key, Vec::new()));
        assert!(reg.is_route_candidate_healthy(node_id));
    }

    #[test]
    fn set_approved_routes_records_policy_change_reason() {
        let reg = MachineRegistry::new();
        let node_key = "route-approval-policy-change";
        let route = "10.0.0.0/24";
        reg.upsert(node_key.to_string(), route_record(node_key, 10, route));
        let history_len = reg.map_change_history().len();

        assert!(reg.set_approved_routes(node_key, Vec::new()));

        let changes = reg.map_change_history();
        let change = changes
            .get(history_len)
            .expect("route approval mutation records a map change");
        assert_eq!(change.reason_labels(), vec!["policy change"]);
        assert_eq!(change.change_type(), "policy");
        assert!(change.content.include_policy);
        assert!(change.content.requires_runtime_peer_computation);
        assert!(change.content.peers_changed.is_empty());
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
    fn route_health_probe_candidates_require_online_active_ha_subnet_routes() {
        let state = test_state();
        let singleton_route = "10.99.0.0/24";
        let ha_route = "10.0.0.0/24";
        let singleton = "route-health-singleton";
        let ha_a = "route-health-ha-a";
        let ha_b = "route-health-ha-b";
        let offline = "route-health-offline";
        let exit_only = "route-health-exit";
        let unapproved = "route-health-unapproved";

        state.machines.upsert(
            singleton.to_string(),
            route_record(singleton, 10, singleton_route),
        );
        state
            .machines
            .upsert(ha_a.to_string(), route_record(ha_a, 11, ha_route));
        state
            .machines
            .upsert(ha_b.to_string(), route_record(ha_b, 12, ha_route));
        state
            .machines
            .upsert(offline.to_string(), route_record(offline, 13, ha_route));

        let mut exit = route_record(exit_only, 14, "0.0.0.0/0");
        exit.available_routes = vec!["0.0.0.0/0".into(), "::/0".into()];
        exit.approved_routes = exit.available_routes.clone();
        state.machines.upsert(exit_only.to_string(), exit);

        let mut advertised = route_record(unapproved, 15, ha_route);
        advertised.approved_routes.clear();
        state.machines.upsert(unapproved.to_string(), advertised);

        let _singleton_guard = MachineRegistry::track_stream_connection_with_grace(
            state.machines.clone(),
            stable_id_from_key(singleton),
            Duration::ZERO,
        );
        let _ha_a_guard = MachineRegistry::track_stream_connection_with_grace(
            state.machines.clone(),
            stable_id_from_key(ha_a),
            Duration::ZERO,
        );
        let _ha_b_guard = MachineRegistry::track_stream_connection_with_grace(
            state.machines.clone(),
            stable_id_from_key(ha_b),
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

        let mut expected = vec![stable_id_from_key(ha_a), stable_id_from_key(ha_b)];
        expected.sort_unstable();
        assert_eq!(route_health_probe_candidates(&state.machines), expected);
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

        let prime_probe = tokio::spawn({
            let state = state.clone();
            async move { run_route_health_probe_once(&state, Duration::from_secs(5)).await }
        });
        complete_next_pending_ping_for_node(&state, node_a).await;
        complete_next_pending_ping_for_node(&state, node_b).await;
        let prime_results = prime_probe.await.unwrap();
        assert_eq!(prime_results.len(), 2);
        assert!(state.machines.is_route_candidate_healthy(node_a));
        assert!(state.machines.is_route_candidate_healthy(node_b));

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

    #[tokio::test(start_paused = true)]
    async fn route_health_probe_all_unhealthy_retains_last_known_primary() {
        let state = test_state();
        let keys = stable_sorted_keys(&[
            "route-health-all-unhealthy-a",
            "route-health-all-unhealthy-b",
        ]);
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
        assert!(!first.contains_key(&keys[1]));

        let prime_probe = tokio::spawn({
            let state = state.clone();
            async move { run_route_health_probe_once(&state, Duration::from_secs(5)).await }
        });
        complete_next_pending_ping_for_node(&state, node_a).await;
        complete_next_pending_ping_for_node(&state, node_b).await;
        let prime_results = prime_probe.await.unwrap();
        assert_eq!(prime_results.len(), 2);

        let probe = tokio::spawn({
            let state = state.clone();
            async move { run_route_health_probe_once(&state, Duration::from_secs(5)).await }
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(5)).await;
        let results = probe.await.unwrap();

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|result| !result.healthy));
        assert!(!state.machines.is_route_candidate_healthy(node_a));
        assert!(!state.machines.is_route_candidate_healthy(node_b));

        let retained = state
            .machines
            .primary_routes_for_snapshot(&state.machines.snapshot());
        assert_eq!(
            retained.get(&keys[0]).cloned().unwrap_or_default(),
            vec![route]
        );
        assert!(!retained.contains_key(&keys[1]));

        let debug_routes = state
            .machines
            .debug_routes_for_snapshot(&state.machines.snapshot());
        assert_eq!(
            debug_routes.available_routes.get(&node_a).cloned(),
            Some(vec![route.to_string()])
        );
        assert_eq!(
            debug_routes.available_routes.get(&node_b).cloned(),
            Some(vec![route.to_string()])
        );
        assert_eq!(
            debug_routes.primary_routes.get(route).copied(),
            Some(node_a)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn route_health_probe_fresh_session_timeout_defers_one_cycle() {
        let state = test_state();
        let keys = stable_sorted_keys(&["route-health-fresh-a", "route-health-fresh-b"]);
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

        let probe = tokio::spawn({
            let state = state.clone();
            async move { run_route_health_probe_once(&state, Duration::from_secs(5)).await }
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(5)).await;
        let results = probe.await.unwrap();

        assert!(results.is_empty());
        assert!(state.machines.is_route_candidate_healthy(node_a));
        assert!(state.machines.is_route_candidate_healthy(node_b));
        let primary = state
            .machines
            .primary_routes_for_snapshot(&state.machines.snapshot());
        assert_eq!(
            primary.get(&keys[0]).cloned().unwrap_or_default(),
            vec![route]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn route_health_probe_reconnect_during_probe_keeps_node_healthy() {
        let state = test_state();
        let keys = stable_sorted_keys(&["route-health-reconnect-a", "route-health-reconnect-b"]);
        let route = "10.0.0.0/24";
        state
            .machines
            .upsert(keys[0].clone(), route_record(&keys[0], 10, route));
        state
            .machines
            .upsert(keys[1].clone(), route_record(&keys[1], 11, route));
        let guard_a = MachineRegistry::track_stream_connection_with_grace(
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

        let prime_probe = tokio::spawn({
            let state = state.clone();
            async move { run_route_health_probe_once(&state, Duration::from_secs(5)).await }
        });
        complete_next_pending_ping_for_node(&state, node_a).await;
        complete_next_pending_ping_for_node(&state, node_b).await;
        assert_eq!(prime_probe.await.unwrap().len(), 2);

        let probe = tokio::spawn({
            let state = state.clone();
            async move { run_route_health_probe_once(&state, Duration::from_secs(5)).await }
        });
        complete_next_pending_ping_for_node(&state, node_b).await;
        drop(guard_a);
        let _guard_a_reconnected = MachineRegistry::track_stream_connection_with_grace(
            state.machines.clone(),
            node_a,
            Duration::ZERO,
        );
        tokio::time::advance(Duration::from_secs(5)).await;
        let results = probe.await.unwrap();

        assert!(results.iter().any(|result| result.node_id == node_b));
        assert!(!results.iter().any(|result| result.node_id == node_a));
        assert!(state.machines.is_route_candidate_healthy(node_a));
        let primary = state
            .machines
            .primary_routes_for_snapshot(&state.machines.snapshot());
        assert_eq!(
            primary.get(&keys[0]).cloned().unwrap_or_default(),
            vec![route]
        );
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
    fn persisted_route_candidates_choose_lowest_persisted_node_id() {
        let reg = Arc::new(MachineRegistry::new());
        let keys = stable_sorted_keys(&["persisted-route-a", "persisted-route-b"]);
        let route = "10.0.0.0/24";
        let mut higher_db_id = route_record(&keys[0], 10, route);
        higher_db_id.node_id = Some(2);
        let mut lower_db_id = route_record(&keys[1], 11, route);
        lower_db_id.node_id = Some(1);
        reg.upsert(keys[0].clone(), higher_db_id);
        reg.upsert(keys[1].clone(), lower_db_id);
        let _guard_higher =
            MachineRegistry::track_stream_connection_with_grace(reg.clone(), 2, Duration::ZERO);
        let _guard_lower =
            MachineRegistry::track_stream_connection_with_grace(reg.clone(), 1, Duration::ZERO);

        let primary = reg.primary_routes_for_snapshot(&reg.snapshot());

        assert_eq!(
            primary.get(&keys[1]).cloned().unwrap_or_default(),
            vec![route]
        );
        assert!(!primary.contains_key(&keys[0]));
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
        existing.auth_key_id = Some(7);
        existing.forced_tags = vec!["tag:server".into()];
        existing.approved_routes = vec!["10.0.0.0/24".into(), "10.99.0.0/24".into()];
        existing.available_routes = vec!["10.0.0.0/24".into(), "10.99.0.0/24".into()];
        let old_ip = existing.ipv4;
        let old_created_at = existing.created_at;
        reg.upsert("old-node".to_string(), existing);
        let history_len = reg.map_change_history().len();

        let mut pending = mk_record(9);
        pending.node_key_hex = "new-node".into();
        pending.machine_key_hex = "same-machine".into();
        pending.user = String::new();
        pending.forced_tags = Vec::new();
        pending.available_routes = vec!["10.0.0.0/24".into(), "10.1.0.0/24".into()];
        pending.approved_routes = vec!["10.1.0.0/24".into()];

        let registered = reg.complete_web_registration(pending, "alice", 2).unwrap();
        assert_eq!(registered.node_key_hex, "new-node");
        assert_eq!(registered.machine_key_hex, "same-machine");
        assert_eq!(registered.user, "alice");
        assert_eq!(registered.auth_key_id, None);
        assert!(registered.forced_tags.is_empty());
        assert_eq!(registered.ipv4, old_ip);
        assert_eq!(registered.created_at, old_created_at);
        // headscale-go v0.29.5 applyAuthNodeUpdate (HandleNodeFromAuthPath)
        // never touches ApprovedRoutes on re-auth: the existing node keeps its
        // approved set and the cached registration's routes are not merged in.
        // Route approval happens afterwards in the caller's AutoApproveRoutes
        // (policy auto-approvers only).
        assert_eq!(
            registered.approved_routes,
            vec!["10.0.0.0/24", "10.99.0.0/24"]
        );
        assert_eq!(registered.register_method, 2);

        assert_eq!(reg.len(), 1, "reauth must not duplicate the node");
        assert!(reg.get("old-node").is_none());
        let stored = reg.get("new-node").unwrap();
        assert_eq!(stored.auth_key_id, None);
        assert!(stored.forced_tags.is_empty());
        assert_eq!(stored.ipv4, old_ip);

        let changes = reg.map_change_history();
        assert_eq!(changes.len(), history_len + 1);
        assert_eq!(
            changes[history_len].reasons,
            vec![MapChangeReason::PolicyChange]
        );
        assert!(changes[history_len].content.include_policy);
        assert!(
            changes[history_len]
                .content
                .requires_runtime_peer_computation
        );
    }

    #[test]
    fn complete_web_registration_reclaims_null_owner_tagged_node_in_place() {
        let reg = MachineRegistry::new();
        let mut existing = mk_record(8);
        existing.node_id = Some(42);
        existing.node_key_hex = "old-tagged-node".into();
        existing.machine_key_hex = "tagged-machine".into();
        existing.user.clear();
        existing.user_id = None;
        existing.forced_tags = vec!["tag:server".into()];
        existing.auth_key_id = Some(7);
        existing.ephemeral = true;
        existing.expiry = Some(Utc::now() - chrono::Duration::hours(1));
        existing.register_method = 1;
        let ip = existing.ipv4;
        reg.upsert(existing.node_key_hex.clone(), existing);

        let mut readvertised = mk_record(9);
        readvertised.node_key_hex = "readvertised-node".into();
        readvertised.machine_key_hex = "tagged-machine".into();
        readvertised.user_id = Some(10);
        readvertised.forced_tags = vec!["tag:server".into()];
        let tagged = reg
            .complete_web_registration(readvertised, "alice", 3)
            .unwrap();
        assert_eq!(reg.len(), 1);
        assert!(reg.get("old-tagged-node").is_none());
        assert_eq!(tagged.node_id, Some(42));
        assert_eq!(tagged.ipv4, ip);
        assert!(tagged.user.is_empty());
        assert_eq!(tagged.user_id, None);
        assert_eq!(tagged.auth_key_id, Some(7));
        assert_eq!(tagged.expiry, None);
        assert_eq!(tagged.register_method, 1);

        let mut untagged = mk_record(10);
        untagged.node_key_hex = "personal-node".into();
        untagged.machine_key_hex = "tagged-machine".into();
        untagged.user_id = Some(10);
        let future_expiry = Utc::now() + chrono::Duration::hours(1);
        untagged.expiry = Some(future_expiry);
        let personal = reg.complete_web_registration(untagged, "alice", 3).unwrap();
        assert_eq!(reg.len(), 1);
        assert!(reg.get("readvertised-node").is_none());
        assert_eq!(personal.node_id, Some(42));
        assert_eq!(personal.ipv4, ip);
        assert_eq!(personal.user, "alice");
        assert_eq!(personal.user_id, Some(10));
        assert!(personal.forced_tags.is_empty());
        assert_eq!(personal.auth_key_id, None);
        assert!(!personal.ephemeral);
        assert_eq!(personal.expiry, Some(future_expiry));
    }

    #[test]
    fn auth_completion_same_key_update_records_node_added_reason() {
        let reg = MachineRegistry::new();
        let mut existing = mk_record(30);
        existing.node_key_hex = "same-node".into();
        existing.machine_key_hex = "same-machine".into();
        existing.user = "alice".into();
        existing.user_id = Some(7);
        reg.upsert(existing.node_key_hex.clone(), existing.clone());
        let history_len = reg.map_change_history().len();

        let mut updated = existing;
        updated.hostname = "same-node-updated".into();
        updated.host_info.hostname = updated.hostname.clone();
        updated.last_seen = Utc::now();
        reg.upsert_auth_completion(updated.node_key_hex.clone(), updated.clone());

        let changes = reg.map_change_history();
        assert_eq!(changes.len(), history_len + 1);
        assert_eq!(
            changes[history_len].reasons,
            vec![MapChangeReason::NodeAdded]
        );
        assert_eq!(
            changes[history_len].origin_node_id,
            Some(updated.stable_node_id_for_key(&updated.node_key_hex))
        );
        assert!(!changes[history_len].content.include_policy);
        assert!(
            changes[history_len]
                .content
                .peers_changed
                .contains(&updated.stable_node_id_for_key(&updated.node_key_hex))
        );
    }

    #[test]
    fn auth_completion_same_key_non_route_policy_identity_change_records_policy_change() {
        let reg = MachineRegistry::new();
        let mut existing = mk_record(31);
        existing.node_key_hex = "same-node-policy".into();
        existing.machine_key_hex = "same-machine-policy".into();
        existing.user = "alice".into();
        existing.user_id = Some(7);
        reg.upsert(existing.node_key_hex.clone(), existing.clone());
        let history_len = reg.map_change_history().len();

        let mut updated = existing;
        updated.user_id = Some(8);
        reg.upsert_auth_completion(updated.node_key_hex.clone(), updated);

        let changes = reg.map_change_history();
        assert_eq!(changes.len(), history_len + 1);
        assert_eq!(
            changes[history_len].reasons,
            vec![MapChangeReason::PolicyChange]
        );
        assert_eq!(changes[history_len].origin_node_id, None);
        assert!(changes[history_len].content.include_policy);
        assert!(
            changes[history_len]
                .content
                .requires_runtime_peer_computation
        );
    }

    #[test]
    fn auth_completion_new_approved_route_records_lifecycle_plus_policy_change() {
        let reg = MachineRegistry::new();
        let mut rec = mk_record(32);
        rec.node_key_hex = "new-route-node".into();
        rec.machine_key_hex = "new-route-machine".into();
        rec.user = "router".into();
        rec.available_routes = vec!["10.32.0.0/24".into()];
        rec.approved_routes = vec!["10.32.0.0/24".into()];

        reg.upsert_auth_completion(rec.node_key_hex.clone(), rec);

        // headscale-go v0.29.5 HandleNodeFromPreAuthKey returns ONE change,
        // reauthChange(node, keysOnly, policyChanged): a new node always
        // changes the policy manager's node set (SetNodes ->
        // nodesHavePolicyAffectingChanges on a length change), so the result
        // is a global change.PolicyChange(), not NodeAdded plus a second
        // route-scoped PolicyChange. (AutoApproveRoutes' own change is emitted
        // separately by the auth handler, not by the auth completion.)
        let changes = reg.map_change_history();
        assert_eq!(changes.len(), 1, "{changes:?}");
        assert_eq!(changes[0].reason_labels(), vec!["policy change"]);
        assert_eq!(changes[0].change_type(), "policy");
        assert_eq!(changes[0].origin_node_id, None);
        assert!(changes[0].content.include_policy);
        assert!(changes[0].content.requires_runtime_peer_computation);
    }

    #[test]
    fn auth_completion_same_key_approved_route_records_lifecycle_plus_policy_change() {
        let reg = MachineRegistry::new();
        let mut existing = mk_record(33);
        existing.node_key_hex = "same-node-route".into();
        existing.machine_key_hex = "same-machine-route".into();
        existing.user = "router".into();
        existing.available_routes = vec!["10.33.0.0/24".into()];
        existing.approved_routes = Vec::new();
        reg.upsert(existing.node_key_hex.clone(), existing.clone());
        let history_len = reg.map_change_history().len();

        let mut updated = existing;
        updated.approved_routes = vec!["10.33.0.0/24".into()];
        reg.upsert_auth_completion(updated.node_key_hex.clone(), updated);

        // headscale-go v0.29.5: a change in the node's active approved
        // routes (SubnetRoutes/ExitRoutes) is a NodeView.HasPolicyChange, so
        // SetNodes reports a policy change and reauthChange returns a single
        // global change.PolicyChange().
        let changes = reg.map_change_history();
        let new_changes = &changes[history_len..];
        assert_eq!(new_changes.len(), 1, "{new_changes:?}");
        assert_eq!(new_changes[0].reason_labels(), vec!["policy change"]);
        assert_eq!(new_changes[0].origin_node_id, None);
        assert!(new_changes[0].content.include_policy);
        assert!(new_changes[0].content.requires_runtime_peer_computation);
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
/// `/register/{auth_id}` starts the OIDC auth-code flow instead
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

/// Options for building the public control listener router.
///
/// Defaults mirror headscale-go's standalone listener. Embedders that already
/// own host-level routes can opt out of individual public-control endpoints
/// before merging the router into a larger application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlRouterOptions {
    /// Mount the stock headscale-go-compatible `/health` handler.
    ///
    /// This defaults to `true`. Set it to `false` when embedding the control
    /// router behind an application that provides its own `/health` route.
    pub include_health_route: bool,
}

impl Default for ControlRouterOptions {
    fn default() -> Self {
        Self {
            include_health_route: true,
        }
    }
}

impl ControlRouterOptions {
    /// Build options that leave `/health` available for the host application.
    pub const fn without_health_route() -> Self {
        Self {
            include_health_route: false,
        }
    }
}

/// Build only the public control listener routes with custom mount options.
pub fn control_router_with_options(state: WireState, options: ControlRouterOptions) -> Router {
    control_router_with_optional_oidc_inner(state, None, true, options)
}

/// Build only the public control listener routes with OIDC and custom options.
pub fn control_router_with_oidc_and_options(
    state: WireState,
    oidc: crate::oidc::OidcAuthRuntime,
    options: ControlRouterOptions,
) -> Router {
    control_router_with_optional_oidc_inner(state, Some(oidc), true, options)
}

fn combined_router_with_optional_oidc(
    state: WireState,
    oidc: Option<crate::oidc::OidcAuthRuntime>,
) -> Router {
    let knock_cfg = state.knock.clone();
    let inner = control_router_with_optional_oidc_inner(
        state.clone(),
        oidc,
        false,
        ControlRouterOptions::default(),
    )
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
        let completed = self
            .state
            .complete_volatile_web_registration(
                registration_id,
                WebRegistrationUser {
                    id: Some(user.id),
                    name: oidc_wire_user_name(user),
                    display_name: user.display_name.clone(),
                    profile_pic_url: user.profile_pic_url.clone(),
                    provider: user.provider.clone(),
                    created_at: None,
                },
                node_expiry,
                REGISTER_METHOD_OIDC,
            )
            .await
            .map_err(|error| match error {
                WebRegistrationError::SessionExpired => {
                    crate::oidc::OidcRegistrationError::SessionExpired
                }
                WebRegistrationError::Store(error) => {
                    crate::oidc::OidcRegistrationError::Store(error)
                }
            })?;
        Ok(crate::oidc::OidcRegistrationResult {
            new_node: completed.new_node,
        })
    }

    async fn complete_oidc_auth_request(
        &self,
        auth_id: &str,
        user: &crate::oidc::OidcStoredUser,
    ) -> Result<(), crate::oidc::OidcAuthError> {
        let Some(binding) = self.state.registration_cache.ssh_binding(auth_id) else {
            if self.state.registration_cache.get(auth_id).is_some() {
                tracing::warn!(
                    auth_id = %format_args!("hskey-authreq-{auth_id}"),
                    "OIDC callback hit non-registration path with auth request that is not an SSH check binding"
                );
                return Err(crate::oidc::OidcAuthError::NotSshCheck);
            }
            tracing::debug!(
                auth_id = %format_args!("hskey-authreq-{auth_id}"),
                "auth session expired before authorization completed"
            );
            return Err(crate::oidc::OidcAuthError::SessionExpired);
        };

        let snapshot = self.state.machines.snapshot();
        let Some((_node_key, src_node)) = snapshot.iter().find(|(node_key, record)| {
            record.stable_node_id_for_key(node_key) == binding.src_node_id
        }) else {
            tracing::warn!(
                auth_id = %format_args!("hskey-authreq-{auth_id}"),
                src_node_id = binding.src_node_id,
                "SSH check src node no longer exists"
            );
            return Err(crate::oidc::OidcAuthError::SourceNodeMissing);
        };

        if src_node.is_tagged() || src_node.user_id.is_none() {
            tracing::warn!(
                auth_id = %format_args!("hskey-authreq-{auth_id}"),
                src_node_id = binding.src_node_id,
                src_is_tagged = src_node.is_tagged(),
                oidc_user = %user.username(),
                "SSH check rejected: src node has no user owner"
            );
            return Err(crate::oidc::OidcAuthError::SourceNodeNoUserOwner);
        }

        if src_node.user_id != Some(user.id) {
            tracing::warn!(
                auth_id = %format_args!("hskey-authreq-{auth_id}"),
                src_node_id = binding.src_node_id,
                src_owner_id = src_node.user_id.expect("user owner checked above"),
                oidc_user_id = user.id,
                oidc_user = %user.username(),
                "SSH check rejected: OIDC user is not the owner of src node"
            );
            return Err(crate::oidc::OidcAuthError::UserNotSourceOwner);
        }

        if self.state.registration_cache.approve_without_node(auth_id) {
            Ok(())
        } else {
            Err(crate::oidc::OidcAuthError::SessionExpired)
        }
    }

    fn oidc_registration_exists(&self, registration_id: &str) -> bool {
        matches!(
            self.state
                .registration_cache
                .auth_request_kind(registration_id),
            Some(AuthRequestKind::Registration)
        )
    }

    fn oidc_auth_request_kind(&self, auth_id: &str) -> Option<crate::oidc::OidcAuthRequestKind> {
        match self.state.registration_cache.auth_request_kind(auth_id)? {
            AuthRequestKind::Registration => Some(crate::oidc::OidcAuthRequestKind::Registration),
            AuthRequestKind::SshCheck(_) => Some(crate::oidc::OidcAuthRequestKind::SshCheck),
        }
    }

    fn oidc_registration_confirmation_info(
        &self,
        registration_id: &str,
    ) -> Option<crate::oidc::OidcRegistrationConfirmInfo> {
        let record = self.state.registration_cache.get(registration_id)?;
        Some(oidc_registration_confirm_info_from_record(&record))
    }

    fn store_oidc_registration_confirmation(
        &self,
        pending: crate::oidc::OidcPendingRegistrationConfirmation,
    ) -> bool {
        let registration_id = pending.registration_id.clone();
        self.state
            .registration_cache
            .store_oidc_confirmation(&registration_id, pending)
    }

    fn oidc_pending_registration_confirmation(
        &self,
        registration_id: &str,
    ) -> Option<crate::oidc::OidcPendingRegistrationConfirmation> {
        self.state
            .registration_cache
            .oidc_confirmation(registration_id)
    }

    fn remove_oidc_registration_confirmation(
        &self,
        registration_id: &str,
    ) -> Option<crate::oidc::OidcPendingRegistrationConfirmation> {
        self.state
            .registration_cache
            .remove_oidc_confirmation(registration_id)
    }
}

fn oidc_registration_confirm_info_from_record(
    record: &MachineRecord,
) -> crate::oidc::OidcRegistrationConfirmInfo {
    crate::oidc::OidcRegistrationConfirmInfo {
        hostname: record.hostname.clone(),
        os: record.os.clone(),
        machine_key: short_machine_key(&record.machine_key_hex),
    }
}

fn short_machine_key(machine_key_hex: &str) -> String {
    if let Ok(bytes) = hex::decode(machine_key_hex)
        && bytes.len() == 32
    {
        if bytes.iter().all(|&byte| byte == 0) {
            return String::new();
        }
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes[..4]);
        return format!("[{}]", &encoded[..5]);
    }
    let short = machine_key_hex.chars().take(12).collect::<String>();
    if short.is_empty() {
        "unknown".to_string()
    } else {
        format!("[{short}]")
    }
}

fn oidc_wire_user_name(user: &crate::oidc::OidcStoredUser) -> String {
    user.username()
}

fn control_router_with_optional_oidc(
    state: WireState,
    oidc: Option<crate::oidc::OidcAuthRuntime>,
) -> Router {
    control_router_with_optional_oidc_inner(state, oidc, true, ControlRouterOptions::default())
}

fn control_router_with_optional_oidc_inner(
    state: WireState,
    oidc: Option<crate::oidc::OidcAuthRuntime>,
    wrap_knock: bool,
    options: ControlRouterOptions,
) -> Router {
    state
        .machines
        .bind_registration_store(state.registration_store.as_ref());
    state.machines.configure_policy(&state.policy);
    state
        .machines
        .configure_registration_expiry(state.runtime_config.node.expiry);
    state
        .machines
        .configure_given_name_domain(&state.runtime_config.base_domain);
    state.machines.configure_ip_allocator(&state.ip_allocator);
    let knock_cfg = state.knock.clone();
    let metrics_registry = Arc::clone(&state.machines);
    let native_methods = state.machines.policy_routes_require_persistence();
    let include_derp_routes = !native_methods || state.runtime_config.derp.server_enabled;
    #[cfg(feature = "full")]
    let include_derp_routes = include_derp_routes || state.native_derp.is_some();
    let mut inner = Router::new()
        .route("/robots.txt", get(basic_handlers::handle_robots))
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
        .route("/favicon.ico", get(basic_handlers::handle_favicon))
        .route("/key", get(key_handler::handle_key))
        .route(
            "/machine/ping-response",
            head(basic_handlers::handle_ping_response),
        );

    if include_derp_routes {
        inner = inner
            .route("/derp/probe", any(basic_handlers::handle_derp_probe))
            .route(
                "/derp/latency-check",
                any(basic_handlers::handle_derp_probe),
            )
            .route(
                "/bootstrap-dns",
                any(basic_handlers::handle_derp_bootstrap_dns),
            );
    }

    if options.include_health_route {
        inner = inner.route("/health", get(basic_handlers::handle_health));
    }

    #[cfg(feature = "full")]
    if state.native_derp.is_some() {
        inner = inner.route("/derp", any(derp::handle_derp));
    }

    inner = if let Some(oidc) = oidc {
        let oidc = oidc.with_registration_handler_if_unset(Arc::new(WireOidcRegistrationHandler {
            state: state.clone(),
        }));
        let register_oidc = oidc.clone();
        let auth_oidc = oidc.clone();
        let callback_oidc = oidc.clone();
        let confirm_get_oidc = oidc.clone();
        let confirm_oidc = oidc;
        inner
            .route(
                "/register/:registration_id",
                get(move |axum::extract::Path(registration_id): axum::extract::Path<String>,
                          tls: Option<axum::extract::Extension<raw_tls::TlsRequest>>| {
                    let oidc = register_oidc.clone();
                    async move {
                        crate::oidc::handle_register_with_request_security(
                            oidc,
                            registration_id,
                            tls.is_some(),
                        )
                        .await
                    }
                }),
            )
            .route(
                "/auth/:auth_id",
                get(move |axum::extract::Path(auth_id): axum::extract::Path<String>,
                          tls: Option<axum::extract::Extension<raw_tls::TlsRequest>>| {
                    let oidc = auth_oidc.clone();
                    async move {
                        crate::oidc::handle_auth_with_request_security(
                            oidc,
                            auth_id,
                            tls.is_some(),
                        )
                        .await
                    }
                }),
            )
            .route(
                "/oidc/callback",
                get(
                    move |headers: axum::http::HeaderMap,
                          tls: Option<axum::extract::Extension<raw_tls::TlsRequest>>,
                          axum::extract::RawQuery(query): axum::extract::RawQuery| {
                        let oidc = callback_oidc.clone();
                        async move {
                            crate::oidc::handle_callback_with_raw_query(
                                oidc,
                                headers,
                                query,
                                tls.is_some(),
                            )
                            .await
                        }
                    },
                ),
            )
            .route(
                "/register/confirm/:auth_id",
                get(
                    move |axum::extract::Path(auth_id): axum::extract::Path<String>,
                          headers: axum::http::HeaderMap| {
                        let oidc = confirm_get_oidc.clone();
                        async move {
                            crate::oidc::handle_register_confirm_get_with_user_refresh(
                                &oidc, &auth_id, &headers,
                            )
                            .await
                        }
                    },
                )
                .post(
                    move |axum::extract::Path(auth_id): axum::extract::Path<String>,
                          headers: axum::http::HeaderMap,
                          tls: Option<axum::extract::Extension<raw_tls::TlsRequest>>,
                          axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
                          body: axum::body::Bytes| {
                        let oidc = confirm_oidc.clone();
                        async move {
                            crate::oidc::handle_register_confirm_with_request_security_and_query(
                                oidc,
                                auth_id,
                                headers,
                                body,
                                tls.is_some(),
                                uri.query(),
                            )
                            .await
                        }
                    },
                ),
            )
    } else {
        inner
            .route(
                "/register/:registration_id",
                get(basic_handlers::handle_web_register),
            )
            .route("/auth/:auth_id", get(basic_handlers::handle_web_auth))
    };

    let inner = inner.route(
        "/ts2021",
        get(noise::handle_ts2021_websocket).post(noise::handle_ts2021_post),
    );
    let inner = if native_methods {
        inner
            .route("/", get(basic_handlers::handle_blank))
            .fallback(native_methods::not_found)
            .layer(middleware::from_fn(native_methods::admit))
    } else {
        inner.fallback(basic_handlers::handle_fallback)
    };
    let inner =
        inner
            .with_state(state)
            .layer(middleware::from_fn(move |req: Request, next: Next| {
                let metrics_registry = Arc::clone(&metrics_registry);
                async move { record_http_metrics(metrics_registry, req, next, true).await }
            }));

    let inner = if native_methods {
        Router::new()
            .fallback_service(inner)
            .layer(middleware::from_fn(native_methods::finalize))
    } else {
        inner
    };

    let inner = if wrap_knock {
        // PSK-gated handshake — third layer of the active-probe shield.
        // Default-off (KnockConfig::disabled()) → exact pass-through.
        // When enabled, requests must carry a valid knock cookie or get a
        // canonical nginx 404. See `tailscale_wire::knock` for the math.
        knock::wrap_router(inner, knock_cfg)
    } else {
        inner
    };

    inner.layer(middleware::from_fn(security_headers))
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
        .route("/debug/gc", any(basic_handlers::handle_debug_gc))
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
            "/debug/ping",
            get(basic_handlers::handle_debug_ping_get).post(basic_handlers::handle_debug_ping_post),
        )
        .route(
            "/debug/policy-manager",
            get(basic_handlers::handle_debug_policy_manager),
        )
        .with_state(state)
        .layer(middleware::from_fn(move |req: Request, next: Next| {
            let metrics_registry = Arc::clone(&metrics_registry);
            async move { record_http_metrics(metrics_registry, req, next, false).await }
        }))
        .layer(middleware::from_fn(debug_access_control))
        .layer(middleware::from_fn(security_headers))
}

async fn debug_access_control(req: Request, next: Next) -> AxumResponse {
    let path = req.uri().path();
    if is_debug_path(path) && !allow_debug_access_for_path(&req, path) {
        return (
            StatusCode::FORBIDDEN,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "debug access denied\n",
        )
            .into_response();
    }

    next.run(req).await
}

fn is_debug_path(path: &str) -> bool {
    path == "/debug" || path.starts_with("/debug/")
}

fn allow_debug_access_for_path(req: &Request, path: &str) -> bool {
    if allow_debug_access_with_key(req) {
        return true;
    }

    let allow_private_statsviz = is_statsviz_path(path);

    if req
        .headers()
        .get("x-forwarded-for")
        .is_some_and(|value| !value.as_bytes().is_empty())
    {
        return allow_private_statsviz && debug_peer_private_ip(req);
    }

    let peer_ip = debug_peer_ip(req);
    #[cfg(test)]
    let peer_ip = peer_ip.or(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));

    let Some(ip) = peer_ip else {
        return false;
    };

    is_tailscale_ip(ip)
        || ip.is_loopback()
        || std::env::var(TS_ALLOW_DEBUG_IP_ENV).is_ok_and(|allowed| allowed == ip.to_string())
        || debug_trusted_cidrs_contains(ip)
        || (allow_private_statsviz && is_private_debug_ip(ip))
}

fn is_statsviz_path(path: &str) -> bool {
    path == "/debug/statsviz" || path == "/debug/statsviz/" || path.starts_with("/debug/statsviz/")
}

fn debug_peer_private_ip(req: &Request) -> bool {
    debug_peer_ip(req).is_some_and(is_private_debug_ip)
}

fn allow_debug_access_with_key(req: &Request) -> bool {
    if req.method() != axum::http::Method::GET {
        return false;
    }

    let Some(debug_key) = req.uri().query().and_then(debug_key_from_query) else {
        return false;
    };
    let Ok(key_path) = std::env::var(TS_DEBUG_KEY_PATH_ENV) else {
        return false;
    };
    if key_path.is_empty() {
        return false;
    }

    fs::read_to_string(key_path).is_ok_and(|contents| contents.trim() == debug_key)
}

fn debug_key_from_query(query: &str) -> Option<String> {
    String::from_utf8(self::query::first_value(query, "debugkey")?)
        .ok()
        .filter(|value| !value.is_empty())
}

fn debug_peer_ip(req: &Request) -> Option<IpAddr> {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|connect_info| connect_info.0.ip())
}

fn is_tailscale_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            let in_cgnat = octets[0] == 100 && (64..=127).contains(&octets[1]);
            let in_chromeos_vm_range =
                octets[0] == 100 && octets[1] == 115 && matches!(octets[2], 92 | 93);
            in_cgnat && !in_chromeos_vm_range
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            segments[0] == 0xfd7a && segments[1] == 0x115c && segments[2] == 0xa1e0
        }
    }
}

fn is_private_debug_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private(),
        IpAddr::V6(ip) => ip.is_unique_local(),
    }
}

fn debug_trusted_cidrs_contains(ip: IpAddr) -> bool {
    let Ok(raw) = std::env::var(TS_DEBUG_TRUSTED_CIDRS_ENV) else {
        return false;
    };

    raw.split(',').map(str::trim).any(|value| {
        !value.is_empty()
            && value
                .parse::<ipnet::IpNet>()
                .is_ok_and(|cidr| cidr.contains(&ip))
    })
}

/// Apply the same browser-facing hardening headers that headscale-go attaches
/// to public HTTP responses.
pub async fn security_headers(req: Request, next: Next) -> AxumResponse {
    let mut response = next.run(req).await;
    apply_security_headers(response.headers_mut());
    response
}

pub fn apply_security_headers(headers: &mut HeaderMap) {
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("frame-ancestors 'none'"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
}

async fn record_http_metrics(
    machines: Arc<MachineRegistry>,
    mut req: Request,
    next: Next,
    log_requests: bool,
) -> AxumResponse {
    let method = req.method().as_str().to_string();
    let event = if log_requests && machines.policy_routes_require_persistence() {
        request_log::start(&mut req)
    } else {
        None
    };
    // headscale-go v0.29.5's chi metrics collector skips preflight requests,
    // while recording normal control-plane traffic (including /ts2021).
    if method == "OPTIONS" {
        return request_log::wrap(event, next.run(req).await);
    }
    let metric_path = prometheus_http_path(req.uri().path()).map(str::to_string);
    let mut proto = format!("{:?}", req.version());
    let websocket_upgrade = req
        .headers()
        .get("connection")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().contains("upgrade"))
        && req
            .headers()
            .get("upgrade")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    if websocket_upgrade {
        proto.push_str(" WebSocket");
    }

    let Some(metric_path) = metric_path else {
        return request_log::wrap(event, next.run(req).await);
    };

    let start = Instant::now();
    let response = next.run(req).await;
    let code = response.status().as_u16();
    machines.record_http_request(code, &method, &metric_path, &proto, start.elapsed());
    request_log::wrap(event, response)
}

fn prometheus_http_path(path: &str) -> Option<&'static str> {
    match path {
        "/metrics" | "/debug" => None,
        path if path.starts_with("/debug/") => None,
        "/ts2021" => Some("/ts2021"),
        "/machine/map" => Some("/machine/map"),
        "/derp" => Some("/derp"),
        "/derp/probe" => Some("/derp/probe"),
        "/derp/latency-check" => Some("/derp/latency-check"),
        "/bootstrap-dns" => Some("/bootstrap-dns"),
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
        "/oidc/callback" => Some("/oidc/callback"),
        path if is_single_segment_after(path, "/apple/") => Some("/apple/{platform}"),
        path if is_single_segment_after(path, "/register/") => Some("/register/{auth_id}"),
        path if is_single_segment_after(path, "/register/confirm/") => {
            Some("/register/confirm/{auth_id}")
        }
        path if is_machine_subpath(path, "register") => Some("/machine/{node_key}/register"),
        path if is_machine_subpath(path, "map") => Some("/machine/{node_key}/map"),
        _ => Some("/"),
    }
}

pub(crate) fn debug_high_cardinality_metrics_enabled() -> bool {
    #[cfg(test)]
    if DEBUG_HIGH_CARDINALITY_METRICS_FOR_TESTS.load(std::sync::atomic::Ordering::SeqCst) {
        return true;
    }

    std::env::var("HEADSCALE_DEBUG_HIGH_CARDINALITY_METRICS").is_ok_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "t" | "true" | "y" | "yes" | "on"
        )
    })
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
    //! the per-module unit tests use instead of a downstream preauth
    //! minter or production address allocator.
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    /// In-memory preauth redeemer: keys → user labels (+ optional
    /// ephemeral / tags metadata).
    ///
    /// Single-use: a successful redeem removes the key from the map so
    /// the second redeem of the same token returns
    /// [`RedeemError::Unknown`] — matches the non-reusable preauth-key
    /// behavior exercised by the wire registration path.
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
    /// with FNV-1a into the CGNAT /10 host space with a simple
    /// implementation so the test fixture has no transitive deps.
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
