//! Wire-protocol JSON shapes for the Tailscale coordination plane.
//!
//! These types mirror a deliberately-small subset of `tailcfg`:
//!
//! - `MachinePublic`-prefixed encoding (`mkey:<hex>`,
//!   `nodekey:<hex>`, `discokey:<hex>`) for keys.
//! - `RegisterRequest` / `RegisterResponse`: the JSON the client posts
//!   to `/machine/{node_key}/register`, and what we return on success.
//! - `MapRequest` / `MapResponse`: the long-poll request/response on
//!   `/machine/{node_key}/map`.
//!
//! ## Decision log
//!
//! - **We model the fields stock `tailscale up` requires plus the
//!   parity-critical policy surfaces now covered by the headscale-go
//!   differential harness.** Incremental peer deltas, key-rotation
//!   fields, and most debug-only fields are still intentionally omitted
//!   until a parity scenario or real-client test needs them.
//! - **Field names match `tailscale/tailcfg/tailcfg.go` verbatim.**
//!   We use `#[serde(rename = "…")]` only when Rust naming conventions
//!   would otherwise diverge (e.g. `NodeKey` instead of `node_key`).
//!   The upstream uses Go's default JSON encoder, which preserves
//!   field names as written — they're capitalised.
//! - **Key fields are typed `String` with the `mkey:`/`nodekey:`
//!   prefix included.** We don't decode to `[u8; 32]` at the serde
//!   layer because the prefix is part of the on-wire identity. A
//!   helper `strip_key_prefix` lives below for handlers that need the
//!   raw bytes.
//! - **`MapResponse.Peers` is the first-snapshot peer-emission path.**
//!   Streaming registry updates use the current tailcfg delta fields
//!   (`PeersChanged`, `PeersRemoved`, and packet-filter deltas) so
//!   long-poll behavior can move toward headscale-go's map batcher.

use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Headscale-go special user ID used for tagged nodes in Tailscale
/// protocol responses.
pub const TAGGED_DEVICES_USER_ID: u64 = 2_147_455_555;
pub const TAGGED_DEVICES_LOGIN_NAME: &str = "tagged-devices";
pub const TAGGED_DEVICES_DISPLAY_NAME: &str = "Tagged Devices";
/// Mirrors upstream headscale-go `capver.MinSupportedCapabilityVersion`.
pub const MIN_SUPPORTED_CAPABILITY_VERSION: u32 = 113;
pub(crate) const ZERO_NODE_KEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

pub(crate) fn is_supported_capability_version(version: u32) -> bool {
    version >= MIN_SUPPORTED_CAPABILITY_VERSION
}

pub(crate) fn zero_node_key() -> String {
    format!("nodekey:{ZERO_NODE_KEY_HEX}")
}

pub(crate) fn unsupported_client_error(version: u32) -> String {
    format!(
        "unsupported client version: {} ({version})",
        tailscale_version_for_capability(version).unwrap_or("")
    )
}

fn tailscale_version_for_capability(version: u32) -> Option<&'static str> {
    match version {
        113 => Some("v1.80"),
        _ => None,
    }
}

/// One registered machine's state, kept in the in-memory
/// `MachineRegistry` after a successful `register`.
///
/// ## Lifecycle fields (P1 parity with upstream `juanfont/headscale`)
///
/// Upstream models the node lifecycle as a Postgres-backed
/// `gorm.Model`. `MachineRecord` mirrors the subset that affects
/// wire-layer behaviour:
///
/// | upstream `hscontrol/types/node.go::Node`         | Rust field         |
/// |-------------------------------------------------|--------------------|
/// | `Expiry *time.Time`                              | `expiry`           |
/// | `LastSeen *time.Time`                            | `last_seen`        |
/// | `RegisterMethod == "authkey-ephemeral"`          | `ephemeral`        |
/// | `CreatedAt time.Time`                            | `created_at`       |
/// | `ForcedTags []string`                            | `forced_tags`      |
/// | `Hostinfo`                                       | `host_info` plus compatibility projections |
/// | `Hostinfo.sshHostKeys`                           | `ssh_host_keys`    |
///
/// `Expiry` is reflected into map-node `KeyExpiry`/`Expired` state.
/// Stock clients derive their own `NeedsLogin` transition from the
/// self node's expired key state, while `LastSeen` is refreshed on
/// every `/map` arrival so the ephemeral GC sweep can identify
/// abandoned devices.
#[derive(Clone, Debug)]
pub struct MachineRecord {
    /// Upstream `nodes.id` when this record is backed by the
    /// headscale-go-compatible database. In-memory embedders leave it
    /// unset and fall back to a deterministic node-key-derived ID.
    pub node_id: Option<u64>,
    /// Upstream `nodes.auth_key_id` for auth-key registrations.
    ///
    /// Used during same-node re-registration to mirror headscale-go:
    /// a used/expired preauth key may be accepted only by the node
    /// that originally registered with that key.
    pub auth_key_id: Option<i64>,
    /// Hex-encoded (no prefix) Tailscale `NodeKey`. The map endpoint
    /// path `/machine/{node_key}/map` carries the raw hex.
    pub node_key_hex: String,
    /// Hex-encoded (no prefix) machine key (X25519) bound to the
    /// node's Noise identity.
    pub machine_key_hex: String,
    /// User the preauth key was minted for.
    pub user: String,
    /// Upstream user ID for `tailcfg.Node.User` and `UserProfile.ID`.
    ///
    /// Persistent stores populate this from `nodes.user_id`; in-memory
    /// embedders fall back to the deterministic legacy user hash.
    pub user_id: Option<u64>,
    /// Display metadata from the owner user row. Empty falls back to
    /// `user`, mirroring headscale-go `User.Display()`.
    pub user_display_name: String,
    /// Owner profile picture URL, if supplied by OIDC.
    pub user_profile_pic_url: String,
    /// Hostname the client advertised in HostInfo (best-effort; may
    /// be empty).
    pub hostname: String,
    /// Client operating system from `Hostinfo.OS`.
    pub os: String,
    /// Client operating system version from `Hostinfo.OSVersion`.
    pub os_version: String,
    /// Full Hostinfo snapshot last supplied by register/map. The scalar
    /// fields below remain as compatibility projections for existing admin
    /// paths, but peer map responses and persistent `host_info` writes should
    /// use this richer value.
    pub host_info: HostInfo,
    /// Optional allocated tailnet IPv4 in the CGNAT range.
    ///
    /// Headscale-go supports disabling either configured prefix family.
    /// Keeping this optional lets the Rust wire model represent
    /// IPv6-only deployments without inventing a sentinel IPv4 address.
    pub ipv4: Option<std::net::Ipv4Addr>,
    /// Optional allocated tailnet IPv6.
    ///
    /// Headscale-go stores IPv4 and IPv6 independently and emits both
    /// as host prefixes in `tailcfg.Node.Addresses`. This remains
    /// optional so embedders that still only implement the legacy
    /// IPv4 allocator contract keep their current behavior.
    pub ipv6: Option<std::net::Ipv6Addr>,
    /// Wall 7: client's `DiscoKey` (`discokey:<hex>` X25519 public).
    /// Populated from `MapRequest.disco_key` on every `/machine/map`
    /// call (the client refreshes it on each map round-trip). `None`
    /// before the first map call has landed; once present, every peer
    /// MapNode emits it so magicsock can shim disco probes.
    ///
    /// Upstream JSON tag is `DiscoKey` (`tailcfg.Node.DiscoKey`).
    /// Without it `wgengine.Reconfig` runs at `0/0 peers` and
    /// `tailscale ping` returns `unknown peer`.
    pub disco_key: Option<String>,
    /// Wall 7: client's NAT-traversal endpoint candidates as
    /// `"ip:port"` strings. Populated from `MapRequest.endpoints` on
    /// every `/machine/map` call. Empty before the first map call has
    /// landed (or if the client advertises only DERP routing).
    ///
    /// Upstream JSON tag is `Endpoints` (`tailcfg.Node.Endpoints`).
    pub endpoints: Vec<String>,
    /// Client's preferred DERP/home region from
    /// `Hostinfo.NetInfo.PreferredDERP`. Kept separately from the reduced
    /// `HostInfo` model so map responses can emit `MapNode.HomeDERP`
    /// and `PeerChange.DERPRegion` like headscale-go.
    pub home_derp: i32,
    /// P1 (lifecycle): node-key expiry. When `Some(t)` and `t <=
    /// now()`, map responses expose this through the self node's
    /// `KeyExpiry`/`Expired` fields (mirrors upstream
    /// `Node.IsExpired()` semantics). `None` means "never expires" —
    /// the default for fresh registrations from non-ephemeral preauth
    /// keys.
    pub expiry: Option<DateTime<Utc>>,
    /// P1 (lifecycle): last `/map` arrival timestamp. Touched at the
    /// top of every map handler so the ephemeral GC sweep can find
    /// abandoned devices. Set to `created_at` on initial register.
    pub last_seen: DateTime<Utc>,
    /// P1 (lifecycle): `true` if the registering preauth key was
    /// marked ephemeral. The GC sweep
    /// ([`super::MachineRegistry::gc_ephemeral`]) only collects rows
    /// where this is `true` AND `last_seen` is older than the
    /// configured grace period.
    pub ephemeral: bool,
    /// P1 (lifecycle): wall-clock when the record was first inserted
    /// into the registry. Stable across rewrites — `set_expiry`,
    /// `rename`, `touch_last_seen`, etc. preserve the original value.
    pub created_at: DateTime<Utc>,
    /// P1 (lifecycle): operator-set tags that override whatever the
    /// registration request advertised. Empty list ⇒ no override;
    /// upstream's `Node.ForcedTags` semantics. The admin
    /// `POST /api/v1/machines/{id}/tags` route writes here.
    pub forced_tags: Vec<String>,
    /// Routes advertised by the node in `HostInfo.RoutableIPs`.
    pub available_routes: Vec<String>,
    /// Routes currently approved by an operator/policy. These are
    /// emitted as `MapNode.AllowedIPs` in addition to the node's own
    /// `/32` address.
    pub approved_routes: Vec<String>,
    /// Tailscale SSH host keys advertised by the client in
    /// `Hostinfo.sshHostKeys`. Peers need these in their MapNode
    /// Hostinfo for strict host-key checks before `tailscale ssh`
    /// can evaluate SSH policy.
    pub ssh_host_keys: Vec<String>,
    /// Upstream `headscale.v1.RegisterMethod` numeric value. Auth-key
    /// registration is the normal wire path default.
    pub register_method: i32,
}

fn is_dns_label_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

fn is_dns_label_char(byte: u8) -> bool {
    is_dns_label_alphanumeric(byte) || byte == b'-'
}

pub fn valid_given_name_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    if !is_dns_label_alphanumeric(bytes[0]) || !is_dns_label_alphanumeric(bytes[bytes.len() - 1]) {
        return false;
    }
    bytes.len() <= 2
        || bytes[1..bytes.len() - 1]
            .iter()
            .all(|byte| is_dns_label_char(*byte))
}

fn trim_common_hostname_suffixes(hostname: &str) -> &str {
    let hostname = hostname.strip_suffix(".local").unwrap_or(hostname);
    let hostname = hostname.strip_suffix(".localdomain").unwrap_or(hostname);
    hostname.strip_suffix(".lan").unwrap_or(hostname)
}

pub fn sanitize_hostname_for_given_name(hostname: &str) -> String {
    let hostname = trim_common_hostname_suffixes(hostname);
    let bytes = hostname.as_bytes();
    let mut start = 0usize;
    let mut end = bytes.len().min(63);

    while start < end && !is_dns_label_alphanumeric(bytes[start]) {
        start += 1;
    }
    while start < end && !is_dns_label_alphanumeric(bytes[end - 1]) {
        end -= 1;
    }

    let mut out = String::with_capacity(end.saturating_sub(start));
    for (offset, byte) in bytes[start..end].iter().enumerate() {
        let absolute = start + offset;
        let boundary = absolute == start || absolute == end - 1;
        match *byte {
            b' ' | b'.' | b'@' | b'_' if !boundary => out.push('-'),
            b'a'..=b'z' | b'0'..=b'9' | b'-' => out.push(char::from(*byte)),
            b'A'..=b'Z' => out.push(char::from(byte.to_ascii_lowercase())),
            _ => {}
        }
    }
    out
}

pub fn auto_given_name_base(hostname: &str) -> String {
    let sanitized = sanitize_hostname_for_given_name(hostname);
    if sanitized.is_empty() {
        "node".to_string()
    } else {
        sanitized
    }
}

pub fn is_auto_derived_given_name(given_name: &str, hostname: &str) -> bool {
    let base = sanitize_hostname_for_given_name(hostname);
    if given_name == base {
        return true;
    }
    let Some(suffix) = given_name.strip_prefix(&format!("{base}-")) else {
        return false;
    };
    suffix.parse::<isize>().is_ok()
}

impl MachineRecord {
    pub fn stable_node_id(&self) -> u64 {
        self.node_id
            .unwrap_or_else(|| stable_id_from_key(&self.node_key_hex))
    }

    pub fn stable_node_id_for_key(&self, node_key_hex: &str) -> u64 {
        self.node_id
            .unwrap_or_else(|| stable_id_from_key(node_key_hex))
    }

    pub fn address_strings(&self) -> Vec<String> {
        let mut addrs = Vec::new();
        if let Some(ipv4) = self.ipv4 {
            addrs.push(ipv4.to_string());
        }
        if let Some(ipv6) = self.ipv6 {
            addrs.push(ipv6.to_string());
        }
        addrs
    }

    pub fn address_prefixes(&self) -> Vec<String> {
        let mut addrs = Vec::new();
        if let Some(ipv4) = self.ipv4 {
            addrs.push(format!("{ipv4}/32"));
        }
        if let Some(ipv6) = self.ipv6 {
            addrs.push(format!("{ipv6}/128"));
        }
        addrs
    }

    pub fn primary_addr_string(&self) -> Option<String> {
        self.ipv4
            .map(|addr| addr.to_string())
            .or_else(|| self.ipv6.map(|addr| addr.to_string()))
    }

    /// True when the node is owned by tags instead of its registering user.
    pub fn is_tagged(&self) -> bool {
        !self.forced_tags.is_empty()
    }

    /// User ID to place in `tailcfg.Node.User`.
    ///
    /// Headscale-go uses a special synthetic user for tagged nodes;
    /// tags are the node identity and the original preauth user should
    /// not appear as the owner in the Tailscale protocol.
    pub fn tailscale_user_id(&self) -> u64 {
        if self.is_tagged() {
            TAGGED_DEVICES_USER_ID
        } else {
            self.user_id
                .unwrap_or_else(|| stable_id_from_key(&self.user))
        }
    }

    /// User profile row referenced by `MapNode.User`.
    pub fn tailscale_user_profile(&self) -> UserProfile {
        if self.is_tagged() {
            UserProfile {
                id: TAGGED_DEVICES_USER_ID,
                login_name: TAGGED_DEVICES_LOGIN_NAME.to_string(),
                display_name: TAGGED_DEVICES_DISPLAY_NAME.to_string(),
                profile_pic_url: String::new(),
                groups: Vec::new(),
            }
        } else {
            UserProfile {
                id: self.tailscale_user_id(),
                login_name: self.user.clone(),
                display_name: self.user_display_name(),
                profile_pic_url: self.user_profile_pic_url.clone(),
                groups: Vec::new(),
            }
        }
    }

    pub fn set_user_identity(
        &mut self,
        user_id: Option<u64>,
        login_name: String,
        display_name: String,
        profile_pic_url: String,
    ) {
        self.user_id = user_id;
        self.user = login_name;
        self.user_display_name = display_name;
        self.user_profile_pic_url = profile_pic_url;
    }

    fn user_display_name(&self) -> String {
        if self.user_display_name.is_empty() {
            self.user.clone()
        } else {
            self.user_display_name.clone()
        }
    }

    /// True if `expiry` is set and has elapsed against `now`. Mirrors
    /// upstream `Node.IsExpired()` from
    /// `juanfont/headscale@main:hscontrol/types/node.go`.
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        match self.expiry {
            Some(t) => now >= t,
            None => false,
        }
    }

    /// Build a record with the lifecycle fields stamped at `now`.
    /// Used by [`super::register::register_inner`] + every test that
    /// inserts a `MachineRecord` synthetically.
    pub fn new_at(
        now: DateTime<Utc>,
        node_key_hex: String,
        machine_key_hex: String,
        user: String,
        hostname: String,
        ipv4: std::net::Ipv4Addr,
        ephemeral: bool,
    ) -> Self {
        Self::new_at_with_addresses(
            now,
            node_key_hex,
            machine_key_hex,
            user,
            hostname,
            Some(ipv4),
            None,
            ephemeral,
        )
    }

    pub fn new_at_with_addresses(
        now: DateTime<Utc>,
        node_key_hex: String,
        machine_key_hex: String,
        user: String,
        hostname: String,
        ipv4: Option<std::net::Ipv4Addr>,
        ipv6: Option<std::net::Ipv6Addr>,
        ephemeral: bool,
    ) -> Self {
        Self {
            node_id: None,
            auth_key_id: None,
            node_key_hex,
            machine_key_hex,
            user,
            user_id: None,
            user_display_name: String::new(),
            user_profile_pic_url: String::new(),
            hostname: hostname.clone(),
            os: String::new(),
            os_version: String::new(),
            host_info: HostInfo {
                hostname,
                ..HostInfo::default()
            },
            ipv4,
            ipv6,
            disco_key: None,
            endpoints: Vec::new(),
            home_derp: 0,
            expiry: None,
            last_seen: now,
            ephemeral,
            created_at: now,
            forced_tags: Vec::new(),
            available_routes: Vec::new(),
            approved_routes: Vec::new(),
            ssh_host_keys: Vec::new(),
            register_method: 1,
        }
    }

    /// Replace the stored Hostinfo snapshot and refresh compatibility
    /// projections that older admin/runtime paths still read directly.
    pub fn replace_host_info(&mut self, host_info: HostInfo) {
        self.os.clone_from(&host_info.os);
        self.os_version.clone_from(&host_info.os_version);
        self.available_routes.clone_from(&host_info.routable_ips);
        self.ssh_host_keys.clone_from(&host_info.ssh_host_keys);
        self.home_derp = host_info
            .net_info
            .as_ref()
            .map(|net_info| net_info.preferred_derp)
            .unwrap_or_default();
        self.host_info = host_info;
    }

    /// Hostinfo as emitted to clients and persisted to the Go-shaped
    /// `nodes.host_info` column. This keeps the full client-supplied snapshot
    /// while reflecting route/SSH/DERP projections that may be updated by
    /// admin or map code.
    pub fn host_info_for_node(&self) -> HostInfo {
        let mut host_info = self.host_info.clone();
        if host_info.hostname.is_empty() {
            host_info.hostname.clone_from(&self.hostname);
        }
        if host_info.os.is_empty() {
            host_info.os.clone_from(&self.os);
        }
        if host_info.os_version.is_empty() {
            host_info.os_version.clone_from(&self.os_version);
        }
        host_info.routable_ips.clone_from(&self.available_routes);
        host_info.ssh_host_keys.clone_from(&self.ssh_host_keys);
        if self.home_derp != 0 {
            host_info
                .net_info
                .get_or_insert_with(NetInfo::default)
                .preferred_derp = self.home_derp;
        }
        host_info
    }
}

/// Body of `POST /machine/{node_key}/register`.
///
/// Fields are a minimal subset of `tailcfg.RegisterRequest`. The real
/// upstream type carries ~25 fields including timestamps, OS info,
/// expiry preferences, and follow-up auth state. The minimum stock
/// `tailscale up` requires us to be able to *parse* on the happy path
/// is: a presented authkey + a node key.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterRequest {
    /// Client capability version when using the Noise transport.
    #[serde(default)]
    pub version: u32,
    /// `nodekey:` prefixed hex string. The path parameter and this
    /// field both carry the same value in upstream Tailscale; we
    /// trust the body's copy.
    #[serde(default = "zero_node_key")]
    pub node_key: String,
    /// Previous node key during node-key rotation.
    #[serde(default)]
    pub old_node_key: String,
    /// Network-lock public key. Upstream's JSON field is `NLKey`, not
    /// `NlKey`, so it needs an explicit serde spelling.
    #[serde(default, rename = "NLKey")]
    pub nl_key: String,
    /// Preauth token the client presents (`Auth.AuthKey` in the
    /// upstream `tailcfg.RegisterRequest`). Tailscale models this as
    /// a nested `Auth { AuthKey, ... }`; we flatten it because the
    /// stock client always sends a flat key during interop.
    #[serde(default)]
    pub auth: Option<RegisterAuth>,
    /// Hostname / OS / etc. the client advertises. Not required for
    /// the interop test; kept here so future fields can extend
    /// without a breaking change.
    #[serde(default)]
    pub hostinfo: Option<HostInfo>,
    /// Optional follow-up flag if the client is presenting a fresh
    /// auth attempt rather than re-using a stored one. Modelled to
    /// silence "missing field" deserialise errors on edge cases.
    #[serde(default)]
    pub followup: Option<String>,
    /// Optional tailnet recommendation or requirement string.
    #[serde(default)]
    pub tailnet: String,
    /// Whether the client requests ephemeral registration. Upstream
    /// `tailcfg.RegisterRequest.Ephemeral` is a plain bool.
    #[serde(default)]
    pub ephemeral: bool,
    /// Requested node-key expiry. We do not currently honor the
    /// client-supplied value in the register handler, but accepting it
    /// keeps the wire shape aligned with `tailcfg`.
    #[serde(default)]
    pub expiry: Option<DateTime<Utc>>,
    /// Network-lock signature over the node key. Go encodes this
    /// `tkatype.MarshaledSignature` byte slice as a base64 JSON string,
    /// but older/no-signature requests may carry it as JSON null.
    #[serde(
        default,
        rename = "NodeKeySignature",
        skip_serializing_if = "Option::is_none"
    )]
    pub node_key_signature: Option<String>,
    /// Device-signature scheme used by recent Tailscale clients
    /// (`signature-v1`, `signature-v2`, etc.).
    #[serde(
        default,
        rename = "SignatureType",
        skip_serializing_if = "String::is_empty"
    )]
    pub signature_type: String,
    /// Request creation time used by signed registration requests.
    #[serde(default, rename = "Timestamp", skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<DateTime<Utc>>,
    /// X.509 device certificate. Go encodes the `[]byte` as base64,
    /// while absent values may be omitted or null.
    #[serde(
        default,
        rename = "DeviceCert",
        skip_serializing_if = "Option::is_none"
    )]
    pub device_cert: Option<String>,
    /// Signature bytes described by `SignatureType`, base64 encoded by
    /// Go's JSON encoder.
    #[serde(default, rename = "Signature", skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterAuth {
    /// Preauth bearer token (e.g. `hskey-auth-<prefix>-<secret>`). On the
    /// upstream wire this is `AuthKey`.
    #[serde(default)]
    pub auth_key: String,
    /// Legacy OAuth2 token payload used by old Android clients. Current
    /// headscale-rs auth-key registration ignores it, but keeping the field
    /// round-trippable matches `tailcfg.RegisterResponseAuth`.
    #[serde(
        default,
        rename = "Oauth2Token",
        skip_serializing_if = "Option::is_none"
    )]
    pub oauth2_token: Option<Oauth2Token>,
}

/// `tailcfg.Oauth2Token`.
#[derive(Debug, Deserialize, Serialize, Default, Clone, Eq, PartialEq)]
pub struct Oauth2Token {
    #[serde(default, rename = "access_token")]
    pub access_token: String,
    #[serde(
        default,
        rename = "token_type",
        skip_serializing_if = "String::is_empty"
    )]
    pub token_type: String,
    #[serde(
        default,
        rename = "refresh_token",
        skip_serializing_if = "String::is_empty"
    )]
    pub refresh_token: String,
    #[serde(default, rename = "expiry", skip_serializing_if = "Option::is_none")]
    pub expiry: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct NetInfo {
    /// NAT mappings vary by destination IP.
    #[serde(
        default,
        rename = "MappingVariesByDestIP",
        skip_serializing_if = "Option::is_none"
    )]
    pub mapping_varies_by_dest_ip: Option<bool>,
    /// Whether the host has working IPv6 connectivity.
    #[serde(
        default,
        rename = "WorkingIPv6",
        skip_serializing_if = "Option::is_none"
    )]
    pub working_ipv6: Option<bool>,
    /// Whether the OS supports IPv6 at all.
    #[serde(default, rename = "OSHasIPv6", skip_serializing_if = "Option::is_none")]
    pub os_has_ipv6: Option<bool>,
    /// Whether UDP appears usable.
    #[serde(
        default,
        rename = "WorkingUDP",
        skip_serializing_if = "Option::is_none"
    )]
    pub working_udp: Option<bool>,
    /// Whether ICMPv4 appears usable.
    #[serde(
        default,
        rename = "WorkingICMPv4",
        skip_serializing_if = "Option::is_none"
    )]
    pub working_icmp_v4: Option<bool>,
    /// `tailcfg.NetInfo.PreferredDERP`; zero means disconnected or
    /// unknown and is omitted by tailcfg.
    #[serde(default, rename = "PreferredDERP", skip_serializing_if = "is_zero_i32")]
    pub preferred_derp: i32,
    /// Whether the client currently has an active port-map.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub have_port_map: bool,
    #[serde(default, rename = "UPnP", skip_serializing_if = "Option::is_none")]
    pub upnp: Option<bool>,
    #[serde(default, rename = "PMP", skip_serializing_if = "Option::is_none")]
    pub pmp: Option<bool>,
    #[serde(default, rename = "PCP", skip_serializing_if = "Option::is_none")]
    pub pcp: Option<bool>,
    /// Current link type, if known (`wired`, `wifi`, `mobile`, ...).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub link_type: String,
    /// Recent DERP latency measurements in seconds, keyed by region/probe.
    #[serde(
        default,
        rename = "DERPLatency",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub derp_latency: BTreeMap<String, f64>,
    /// Linux firewall mode/debug reason string.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub firewall_mode: String,
}

/// `tailcfg.Service`, the legacy per-node service advertisement list in
/// `Hostinfo.Services`.
#[derive(Debug, Deserialize, Serialize, Default, Clone, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct HostInfoService {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proto: String,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub port: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

/// `tailcfg.Location`, optional geolocation metadata advertised in
/// `Hostinfo.Location`.
#[derive(Debug, Deserialize, Serialize, Default, Clone, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct HostInfoLocation {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub country: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub country_code: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub city: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub city_code: String,
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub latitude: f64,
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub longitude: f64,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub priority: i32,
}

/// `tailcfg.TPMInfo`, optional TPM 2.0 metadata advertised in
/// `Hostinfo.TPM`.
#[derive(Debug, Deserialize, Serialize, Default, Clone, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct TpmInfo {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub manufacturer: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vendor: String,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub model: i32,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub firmware_version: u64,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub spec_revision: i32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub family_indicator: String,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct HostInfo {
    /// Tailscale client version string.
    #[serde(
        default,
        rename = "IPNVersion",
        skip_serializing_if = "String::is_empty"
    )]
    pub ipn_version: String,
    #[serde(
        default,
        rename = "FrontendLogID",
        skip_serializing_if = "String::is_empty"
    )]
    pub frontend_log_id: String,
    #[serde(
        default,
        rename = "BackendLogID",
        skip_serializing_if = "String::is_empty"
    )]
    pub backend_log_id: String,
    #[serde(default)]
    pub hostname: String,
    /// Upstream JSON tag is `OS` (all-caps). PascalCase would produce
    /// `Os` — wrong.
    #[serde(default, rename = "OS")]
    pub os: String,
    /// Upstream calls this `OSVersion`; PascalCase rename keeps the
    /// wire byte-identical.
    #[serde(default, rename = "OSVersion")]
    pub os_version: String,
    /// Optional bools map to Tailscale's `opt.Bool`: absent/null is
    /// unset, while both true and false are meaningful when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<bool>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub env: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub distro: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub distro_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub distro_code_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub app: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desktop: Option<bool>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub package: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device_model: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub push_device_token: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub shields_up: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sharee_node: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_logs_no_support: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub wire_ingress: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ingress_enabled: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allows_update: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub machine: String,
    #[serde(default, rename = "GoArch", skip_serializing_if = "String::is_empty")]
    pub go_arch: String,
    #[serde(
        default,
        rename = "GoArchVar",
        skip_serializing_if = "String::is_empty"
    )]
    pub go_arch_var: String,
    #[serde(
        default,
        rename = "GoVersion",
        skip_serializing_if = "String::is_empty"
    )]
    pub go_version: String,
    /// Subnet routes advertised by the client.
    #[serde(default, rename = "RoutableIPs", skip_serializing_if = "Vec::is_empty")]
    pub routable_ips: Vec<String>,
    /// ACL tags requested by the client, e.g. `tailscale up
    /// --advertise-tags=tag:server`.
    #[serde(default, rename = "RequestTags", skip_serializing_if = "Vec::is_empty")]
    pub request_tags: Vec<String>,
    /// Wake-on-LAN MAC addresses.
    #[serde(default, rename = "WoLMACs", skip_serializing_if = "Vec::is_empty")]
    pub wol_macs: Vec<String>,
    /// Legacy services advertised by this machine.
    #[serde(default, rename = "Services", skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<HostInfoService>,
    /// Tailscale SSH host keys. Upstream uses a lower-camel legacy JSON name.
    #[serde(default, rename = "sshHostKeys", skip_serializing_if = "Vec::is_empty")]
    pub ssh_host_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cloud: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userspace: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userspace_router: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_connector: Option<bool>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub services_hash: String,
    /// Whether this client is willing to relay traffic for other peers.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub peer_relay: bool,
    #[serde(
        default,
        rename = "ExitNodeID",
        skip_serializing_if = "String::is_empty"
    )]
    pub exit_node_id: String,
    #[serde(default, rename = "Location", skip_serializing_if = "Option::is_none")]
    pub location: Option<HostInfoLocation>,
    #[serde(default, rename = "TPM", skip_serializing_if = "Option::is_none")]
    pub tpm: Option<TpmInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_encrypted: Option<bool>,
    /// NAT/check results advertised by the client. We currently persist
    /// the preferred DERP field for map-node and stream-patch parity.
    #[serde(default, rename = "NetInfo", skip_serializing_if = "Option::is_none")]
    pub net_info: Option<NetInfo>,
}

/// Response to a successful `register`.
///
/// We always return `Login` (a synthetic user record) and an empty
/// `AuthURL` — the latter telling the client "no follow-up browser
/// flow is needed, the key was good." `MachineAuthorized = true` is
/// what flips the client into "registered" state.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterResponse {
    /// User record bound into the machine. We synthesise this from
    /// the preauth's user label.
    pub user: SimpleUser,
    /// Display name of the user; lowercased login by default.
    pub login: SimpleLogin,
    /// Empty for preauth flows (no browser follow-up needed).
    #[serde(default)]
    pub node_key_expired: bool,
    /// Browser URL for OIDC/web auth. Empty on preauth-success path.
    /// Upstream JSON tag is `AuthURL` (all-caps URL); PascalCase
    /// `auth_url` would emit `AuthUrl` — wrong, and a non-empty
    /// `AuthUrl`-shaped field is parsed as "extra unknown" by
    /// upstream's Go decoder, causing the client to fall into the
    /// "needs browser auth" branch instead of "preauth success."
    #[serde(default, rename = "AuthURL")]
    pub auth_url: String,
    /// Per-machine flag the client polls for in subsequent `/map`
    /// calls. True ⇒ "you're admitted into the tailnet."
    pub machine_authorized: bool,
    /// Upstream error string for denied or follow-up register flows.
    #[serde(default)]
    pub error: String,
    /// Current node-key signature that the client must re-sign when
    /// rotating its node key. Go encodes the byte slice as base64 and
    /// may emit null for the zero value.
    #[serde(
        default,
        rename = "NodeKeySignature",
        skip_serializing_if = "Option::is_none"
    )]
    pub node_key_signature: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SimpleUser {
    /// 64-bit stable user ID. We hash the preauth user label into a
    /// u64 — this is fine for the interop test (no cross-process
    /// reconciliation) but is a known weak link for production use.
    #[serde(rename = "ID")]
    pub id: u64,
    pub display_name: String,
    #[serde(
        default,
        rename = "ProfilePicURL",
        skip_serializing_if = "String::is_empty"
    )]
    pub profile_pic_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SimpleLogin {
    #[serde(rename = "ID")]
    pub id: u64,
    pub provider: String,
    pub login_name: String,
    pub display_name: String,
    #[serde(
        default,
        rename = "ProfilePicURL",
        skip_serializing_if = "String::is_empty"
    )]
    pub profile_pic_url: String,
}

/// Body of `POST /machine/{node_key}/map`.
///
/// The upstream `tailcfg.MapRequest` carries ~15 fields. We model only
/// the few that affect whether the client continues to poll. The
/// `Stream` flag in particular is critical: when true, the client
/// expects an HTTP stream of length-prefixed map updates rather than a
/// single response body.
#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct MapRequest {
    /// Client's capability version. Pinned at >=39 for TS2021.
    #[serde(default)]
    pub version: u32,
    /// Whether the client wants the long-poll stream. We ignore this
    /// only for non-streaming test paths; runtime map handling emits
    /// upstream-style framed chunks when this is true.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stream: bool,
    /// Whether the client wants the response in compressed form.
    /// Upstream currently recognizes `"zstd"`; absent or unknown values
    /// still use the length-prefixed frame but leave the JSON body
    /// uncompressed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub compress: String,
    /// Whether the server should include keepalive frames in a stream.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub keep_alive: bool,
    /// HostInfo the client wants to update on this map call.
    #[serde(default)]
    pub hostinfo: Option<HostInfo>,
    /// `OmitPeers` true ⇒ client just wants a poke / heartbeat.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub omit_peers: bool,
    /// `nodekey:` prefixed hex string. Present on v1.78+ flat-path
    /// requests (`POST /machine/map`) where there's no URL parameter.
    /// Empty on the keyed-path variant (caller takes the value from the
    /// URL instead).
    #[serde(default)]
    pub node_key: String,
    /// Opaque stream resume handle supplied by newer clients.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub map_session_handle: String,
    /// Last stream sequence processed for `MapSessionHandle` resume.
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub map_session_seq: i64,
    /// Wall 7: client's `DiscoKey` (`discokey:<hex>` X25519 public).
    /// Stock `tailscale` v1.78+ includes this on every MapRequest;
    /// the server must persist + fan it back out on every peer's
    /// `MapNode.DiscoKey` for `wgengine.Reconfig` to add the peer.
    /// Optional because older clients (and our own test fixtures that
    /// don't model a real disco key) may omit it.
    ///
    /// Upstream JSON tag is `DiscoKey` (`tailcfg.MapRequest.DiscoKey`).
    #[serde(default, rename = "DiscoKey", skip_serializing_if = "Option::is_none")]
    pub disco_key: Option<String>,
    /// Public hardware-attestation identity key, if the client has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardware_attestation_key: Option<String>,
    /// Go encodes this `[]byte` signature as a base64 JSON string.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hardware_attestation_key_signature: String,
    /// Timestamp prepended to the attested node-key signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardware_attestation_key_signature_timestamp: Option<DateTime<Utc>>,
    /// Wall 7: NAT-traversal endpoint candidates the client wants peers
    /// to try (`"ip:port"` strings). Upstream `tailcfg.MapRequest`
    /// historically carried `Endpoints []string`; v1.78+ added a typed
    /// `[]netip.AddrPort` shape but the JSON wire still encodes as a
    /// `[]string`. Optional ⇒ empty list when absent.
    #[serde(
        default,
        rename = "Endpoints",
        skip_serializing_if = "option_vec_is_none_or_empty"
    )]
    pub endpoints: Option<Vec<String>>,
    /// Parallel endpoint source-type list (`tailcfg.EndpointType`).
    #[serde(
        default,
        rename = "EndpointTypes",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub endpoint_types: Vec<i32>,
    /// Legacy read-only map fetch bit. Deprecated upstream but still
    /// accepted for parity with older clients.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub read_only: bool,
    /// Latest local tailnet key authority head hash.
    #[serde(default, rename = "TKAHead", skip_serializing_if = "String::is_empty")]
    pub tka_head: String,
    /// Debug/development feature flags sent by the client.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub debug_flags: Vec<String>,
    /// Test/debug connection handle carried by upstream clients. It has
    /// no control-plane semantics, but accepting and preserving it keeps
    /// the map request shape aligned with tailcfg.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub connection_handle_for_test: String,
}

/// Response to `/machine/{node_key}/map`.
///
/// `tailcfg.MapResponse` is both the initial netmap snapshot and the
/// long-poll delta envelope. Runtime paths still mostly emit full
/// snapshots, but the wire model accepts and can serialise the current
/// delta/debug fields so fixtures and compatibility tests can cover the
/// same surface as headscale-go.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct MapResponse {
    /// Opaque stream-resume handle for stateful long-poll sessions.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub map_session_handle: String,
    /// Sequence number within `MapSessionHandle`.
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub seq: i64,
    /// Empty stream message that keeps the long-poll connection alive.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub keep_alive: bool,
    /// Control-plane request for the client to prove liveness.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ping_request: Option<PingRequest>,
    /// URL the client should open for an interactive follow-up action.
    #[serde(
        default,
        rename = "PopBrowserURL",
        skip_serializing_if = "String::is_empty"
    )]
    pub pop_browser_url: String,
    /// Own node record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<MapNode>,
    /// Other peers in the tailnet. Empty list is valid (e.g. a
    /// peer-A joining before peer-B does); the long-poll waits for a
    /// second registration to flesh this out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<MapNode>,
    /// Full node records that changed in an incremental map response.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers_changed: Vec<MapNode>,
    /// Node IDs removed from the peer list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers_removed: Vec<u64>,
    /// Lightweight peer mutation patches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers_changed_patch: Vec<PeerChange>,
    /// Peer last-seen/online edge notifications.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub peer_seen_change: BTreeMap<u64, bool>,
    /// Peer online-state updates.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub online_change: BTreeMap<u64, bool>,
    /// User profile rows referenced by `Node.User` and `Peers[*].User`.
    /// Upstream sends these in initial maps and in later deltas when a
    /// profile changes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_profiles: Vec<UserProfile>,
    /// Synthetic empty DNS config — present so the client doesn't
    /// reject the response for missing fields. Upstream JSON tag is
    /// `DNSConfig` (all-caps DNS), not `DnsConfig`.
    #[serde(default, rename = "DNSConfig", skip_serializing_if = "Option::is_none")]
    pub dns_config: Option<DnsConfig>,
    /// Synthetic empty DERPMap — peers will fall back to direct
    /// connections on the docker bridge. Upstream JSON tag is
    /// `DERPMap`, not `DerpMap`.
    #[serde(default, rename = "DERPMap", skip_serializing_if = "Option::is_none")]
    pub derp_map: Option<DerpMap>,
    /// Domain string the client treats as the tailnet's MagicDNS root.
    /// Runtime map responses derive this from the configured DNS base
    /// domain.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
    /// Whether the tailnet asks clients to include service discovery
    /// data in HostInfo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collect_services: Option<bool>,
    /// Wall 7 (post-Wall-6): `tailcfg.MapResponse.PacketFilter`. Stock
    /// `tailscale` v1.78+ default-denies inter-peer traffic if this
    /// list is empty/null — the daemon reports "unknown peer" on
    /// `tailscale ping <peer-IP>` even though the netmap holds the
    /// target. We emit the canonical "allow everything to everywhere"
    /// rule for the interop tailnet; production deployments will
    /// derive this from the embedded ACL surface.
    ///
    /// Upstream JSON tag is `PacketFilter`; the type is `[]FilterRule`.
    /// We model only the fields the matcher actually reads — `SrcIPs`
    /// and `DstPorts`. The IPProto field is omitted ⇒ all protocols.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packet_filter: Vec<FilterRule>,
    /// Incremental packet-filter updates keyed by server-assigned name.
    /// A null value deletes that named filter; `"*": null` clears all.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub packet_filters: BTreeMap<String, Option<Vec<FilterRule>>>,
    /// Control-plane health strings. `Some(vec![])` explicitly clears
    /// previous health warnings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<Vec<String>>,
    /// Structured GUI/display health patches.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub display_messages: BTreeMap<String, Option<DisplayMessage>>,
    /// `tailcfg.MapResponse.SSHPolicy`. When present, updates the
    /// client's incoming Tailscale SSH policy for this node.
    #[serde(default, rename = "SSHPolicy", skip_serializing_if = "Option::is_none")]
    pub ssh_policy: Option<SshPolicy>,
    /// Control server wall-clock time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_time: Option<DateTime<Utc>>,
    /// Tailnet key-authority state.
    #[serde(default, rename = "TKAInfo", skip_serializing_if = "Option::is_none")]
    pub tka_info: Option<TkaInfo>,
    /// Per-tailnet data-plane audit log ID.
    #[serde(
        default,
        rename = "DomainDataPlaneAuditLogID",
        skip_serializing_if = "String::is_empty"
    )]
    pub domain_data_plane_audit_log_id: String,
    /// Declarative/imperative debug settings still carried by tailcfg.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debug: Option<DebugConfig>,
    /// Instructions for reconnecting to the control server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_dial_plan: Option<ControlDialPlan>,
    /// Latest-client-version notification payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_version: Option<ClientVersion>,
    /// Deprecated tailnet default auto-update bit.
    #[serde(
        default,
        rename = "DefaultAutoUpdate",
        skip_serializing_if = "Option::is_none"
    )]
    pub deprecated_default_auto_update: Option<bool>,
}

/// `tailcfg.PingRequest`.
#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct PingRequest {
    #[serde(rename = "URL")]
    pub url: String,
    #[serde(
        default,
        rename = "URLIsNoise",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub url_is_noise: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub log: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub types: String,
    #[serde(default, rename = "IP", skip_serializing_if = "String::is_empty")]
    pub ip: String,
    /// Go encodes `[]byte` as a base64 JSON string.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub payload: String,
}

/// `tailcfg.PingResponse`.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct PingResponse {
    /// Ping type, such as `TSMP`, `disco`, `ICMP`, or `peerapi`.
    #[serde(default, rename = "Type")]
    pub ping_type: String,
    #[serde(default, rename = "IP", skip_serializing_if = "String::is_empty")]
    pub ip: String,
    #[serde(default, rename = "NodeIP", skip_serializing_if = "String::is_empty")]
    pub node_ip: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub node_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub err: String,
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub latency_seconds: f64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub peer_relay: String,
    #[serde(default, rename = "DERPRegionID", skip_serializing_if = "is_zero_i32")]
    pub derp_region_id: i32,
    #[serde(
        default,
        rename = "DERPRegionCode",
        skip_serializing_if = "String::is_empty"
    )]
    pub derp_region_code: String,
    #[serde(default, rename = "PeerAPIPort", skip_serializing_if = "is_zero_u16")]
    pub peer_api_port: u16,
    #[serde(
        default,
        rename = "IsLocalIP",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub is_local_ip: bool,
}

/// `tailcfg.PeerChange`.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct PeerChange {
    #[serde(rename = "NodeID")]
    pub node_id: u64,
    #[serde(default, rename = "DERPRegion", skip_serializing_if = "is_zero_i32")]
    pub derp_region: i32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cap: u32,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cap_map: BTreeMap<String, Vec<Value>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Go encodes `[]byte` as a base64 JSON string.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_signature: String,
    #[serde(default, rename = "DiscoKey", skip_serializing_if = "Option::is_none")]
    pub disco_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_expiry: Option<DateTime<Utc>>,
}

/// `tailcfg.DisplayMessage`.
#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct DisplayMessage {
    pub title: String,
    pub text: String,
    pub severity: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub impacts_connectivity: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_action: Option<DisplayMessageAction>,
}

/// `tailcfg.DisplayMessageAction`.
#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct DisplayMessageAction {
    #[serde(rename = "URL")]
    pub url: String,
    pub label: String,
}

/// `tailcfg.TKAInfo`.
#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct TkaInfo {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub head: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
}

/// `tailcfg.Debug`.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct DebugConfig {
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub sleep_seconds: f64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_log_tail: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<i32>,
}

/// `tailcfg.ControlDialPlan`.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct ControlDialPlan {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<ControlIpCandidate>,
}

/// `tailcfg.ControlIPCandidate`.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct ControlIpCandidate {
    #[serde(default, rename = "IP", skip_serializing_if = "String::is_empty")]
    pub ip: String,
    #[serde(default, rename = "ACEHost", skip_serializing_if = "String::is_empty")]
    pub ace_host: String,
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub dial_start_delay_sec: f64,
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub dial_timeout_sec: f64,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub priority: i32,
}

/// `tailcfg.ClientVersion`.
#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct ClientVersion {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub running_latest: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub latest_version: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub urgent_security_update: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub notify: bool,
    #[serde(
        default,
        rename = "NotifyURL",
        skip_serializing_if = "String::is_empty"
    )]
    pub notify_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notify_text: String,
}

/// `tailcfg.UserProfile` display metadata for a user referenced by a
/// map node.
#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct UserProfile {
    #[serde(rename = "ID")]
    pub id: u64,
    pub login_name: String,
    pub display_name: String,
    #[serde(
        default,
        rename = "ProfilePicURL",
        skip_serializing_if = "String::is_empty"
    )]
    pub profile_pic_url: String,
    /// Optional SCIM/policy groups reported to the client for WhoIs/UI data.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

/// `tailcfg.FilterRule`. The default zero-value here is unreachable —
/// every rule must carry at least one SrcIP / DstPort entry to be
/// matchable. We never construct empty rules; the only call site is
/// [`crate::tailscale_wire::map::allow_all_packet_filter`] which
/// returns the "allow everything" recipe.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct FilterRule {
    /// Source IPs / CIDRs / `*`. Upstream tag is `SrcIPs`.
    #[serde(rename = "SrcIPs", default)]
    pub src_ips: Vec<String>,
    /// Deprecated upstream CIDR mask companion for `SrcIPs`.
    #[serde(default, rename = "SrcBits", skip_serializing_if = "Vec::is_empty")]
    pub src_bits: Vec<i32>,
    /// Per-destination port range entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dst_ports: Vec<NetPortRange>,
    /// IP protocol restrictions. Empty ⇒ all protocols allowed.
    #[serde(default, rename = "IPProto", skip_serializing_if = "Vec::is_empty")]
    pub ip_proto: Vec<i32>,
    /// Application capability grants. Mutually exclusive with `DstPorts`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cap_grant: Vec<CapGrant>,
}

/// `tailcfg.CapGrant`.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CapGrant {
    /// Destination prefixes this capability grant matches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dsts: Vec<String>,
    /// Deprecated capability list. Upstream element type is `PeerCapability`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caps: Vec<String>,
    /// Modern capability map (`tailcfg.PeerCapMap`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cap_map: BTreeMap<String, Option<Vec<Value>>>,
}

/// `tailcfg.NetPortRange`.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct NetPortRange {
    #[serde(rename = "IP")]
    pub ip: String,
    /// Deprecated upstream CIDR mask for `IP`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bits: Option<i32>,
    pub ports: PortRange,
}

/// `tailcfg.PortRange`.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct PortRange {
    pub first: u16,
    pub last: u16,
}

/// `tailcfg.SSHPolicy`.
#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
pub struct SshPolicy {
    #[serde(default)]
    pub rules: Vec<SshRule>,
}

/// `tailcfg.SSHRule`.
#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SshRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_expires: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principals: Vec<SshPrincipal>,
    #[serde(
        default,
        rename = "sshUsers",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub ssh_users: BTreeMap<String, String>,
    #[serde(default)]
    pub action: SshAction,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accept_env: Vec<String>,
}

/// `tailcfg.SSHPrincipal`.
#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SshPrincipal {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub node: String,
    #[serde(default, rename = "nodeIP", skip_serializing_if = "String::is_empty")]
    pub node_ip: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user_login: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub any: bool,
    /// Deprecated public-key SSH principal stub retained upstream so the JSON
    /// field name is not reused with different semantics.
    #[serde(default, rename = "pubKeys", skip_serializing_if = "Vec::is_empty")]
    pub unused_pub_keys: Vec<String>,
}

/// `tailcfg.SSHAction`.
#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SshAction {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reject: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub accept: bool,
    /// Go `time.Duration`, encoded by tailcfg as integer nanoseconds.
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub session_duration: i64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_agent_forwarding: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hold_and_delegate: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_local_port_forwarding: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_remote_port_forwarding: bool,
    /// SSH session recorder endpoints as `ip:port` strings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recorders: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_recording_failure: Option<SshRecorderFailureAction>,
}

/// `tailcfg.SSHRecorderFailureAction`.
#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct SshRecorderFailureAction {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reject_session_with_message: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub terminate_session_with_message: String,
    #[serde(
        default,
        rename = "NotifyURL",
        skip_serializing_if = "String::is_empty"
    )]
    pub notify_url: String,
}

/// `tailcfg.SSHEventNotifyRequest`.
#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct SshEventNotifyRequest {
    #[serde(default)]
    pub event_type: i32,
    #[serde(default, rename = "ConnectionID")]
    pub connection_id: String,
    #[serde(default)]
    pub cap_version: u32,
    #[serde(default)]
    pub node_key: String,
    #[serde(default)]
    pub src_node: u64,
    #[serde(default, rename = "SSHUser")]
    pub ssh_user: String,
    #[serde(default)]
    pub local_user: String,
    #[serde(default)]
    pub recording_attempts: Option<Vec<SshRecordingAttempt>>,
}

/// `tailcfg.SSHRecordingAttempt`.
#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct SshRecordingAttempt {
    #[serde(default)]
    pub recorder: String,
    #[serde(default)]
    pub failure_message: String,
}

/// A single node record inside a `MapResponse`.
///
/// Field set + JSON names track `tailscale/tailcfg/tailcfg.go::Node`.
/// The fields without `omitempty`/`omitzero` upstream are emitted on
/// every node record:
///
/// - `ID` (NodeID — required, no omitempty)
/// - `StableID` (StableNodeID — required, no omitempty)
/// - `Name` (MagicDNS-style hostname — required)
/// - `User` (UserID — required)
/// - `Key` (NodePublic — required)
/// - `Machine` (MachinePublic — required, `omitzero` but always non-zero in practice)
/// - `Addresses` (`[]netip.Prefix` — required)
/// - `Hostinfo` (HostinfoView — `omitzero`, present)
///
/// `User` is the field that broke Wall 5 here: stock `tailscale`
/// `mapSession.decodeMsg` calls `json.Unmarshal(b, v)` on the full
/// MapResponse and then the netmap-builder dereferences `n.User`
/// expecting a `UserID`. With our pre-fix MapNode omitting `User`,
/// the decode succeeded but the downstream state-machine couldn't
/// build a usable netmap for the node it had just been told it was.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct MapNode {
    /// Stable per-tailnet node ID. We use the FNV hash of the node
    /// key bytes — deterministic for a given key, fits in u64.
    #[serde(rename = "ID")]
    pub id: u64,
    /// `StableNodeID` — same value-domain as `ID` but a string. We
    /// derive it as the decimal node ID string to match
    /// headscale-go's `types.NodeID.StableID()` convention.
    #[serde(rename = "StableID")]
    pub stable_id: String,
    /// MagicDNS-style stable name (`<hostname>.<domain>`). Same value
    /// as `name` (which is the legacy field we kept around for the
    /// keyed-path tests); upstream calls this `Name`. Serialised
    /// first since older clients seek it.
    pub name: String,
    /// User who owns this node. We synthesise a 64-bit user ID from
    /// the preauth user label (see `register::register_inner`).
    #[serde(rename = "User")]
    pub user: u64,
    /// User who shared this node, if different from `User`.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub sharer: u64,
    /// `nodekey:` prefixed hex.
    pub key: String,
    /// Tailnet key-authority signature over `Key`. Go encodes the
    /// underlying bytes as a base64 JSON string.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_signature: String,
    /// `mkey:` prefixed hex. Upstream `Node.Machine` is tagged
    /// `omitzero`; `tailscale` v1.78+ rejects a literal `"mkey:"`
    /// (zero-length hex) with `PollNetMap: response: key hex has the
    /// wrong size, got 0 want 64`. We make this `Option<String>` so an
    /// empty machine_key (no Noise IK static-key seen yet) is OMITTED
    /// rather than emitted as a degenerate prefix-only value.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub machine: Option<String>,
    /// Tailnet IPv4 + IPv6 addresses (we only emit the v4).
    pub addresses: Vec<String>,
    /// CIDR ranges the node accepts traffic for. Same as `Addresses`
    /// for a pure mesh peer. Upstream JSON tag is `AllowedIPs`
    /// (all-caps IPs).
    #[serde(rename = "AllowedIPs")]
    pub allowed_ips: Vec<String>,
    /// Routes for which this node is currently the selected primary
    /// subnet router.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub primary_routes: Vec<String>,
    /// Hostname the node advertised.
    pub hostinfo: HostInfo,
    /// Node creation timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>,
    /// Node key expiry timestamp, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_expiry: Option<DateTime<Utc>>,
    /// Client capability version.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cap: u32,
    /// ACL tags applied to this node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Last time this node was seen online.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,
    /// Online state; `None` means unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
    /// Mirrors upstream `tailcfg.Node.MachineAuthorized` (line 433 of
    /// `tailcfg/tailcfg.go`). The control client's
    /// `netmap.NetworkMap.GetMachineStatus()` reads this off
    /// `SelfNode`; without it the daemon stalls in `NeedsMachineAuth`
    /// (BackendState 3) even after `RegisterResponse.MachineAuthorized
    /// = true`. Wall 5 sequel: register-time auth is necessary but
    /// not sufficient — the netmap must carry the same bit.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub machine_authorized: bool,
    /// Deprecated upstream capability list. Kept for clients and
    /// parity fixtures that still consume the legacy field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// Modern node capability map (`tailcfg.Node.CapMap`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cap_map: BTreeMap<String, Vec<Value>>,
    /// Whether the node key is expired from the control plane's view.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub expired: bool,
    /// Modern DERP home region.
    #[serde(default, rename = "HomeDERP", skip_serializing_if = "is_zero_i32")]
    pub home_derp: i32,
    /// Wall 7: `tailcfg.Node.DiscoKey` (`discokey:<hex>` X25519 public).
    /// Without this `wgcfg.NewFromIPs` rejects the node and
    /// `wgengine.Reconfig` runs at `0/0 peers` — `tailscale ping`
    /// returns `unknown peer` even though the netmap holds the
    /// target. Upstream JSON tag is `DiscoKey`. Optional; omitted when
    /// the matching `MachineRecord` hasn't seen a MapRequest with a
    /// DiscoKey yet (e.g. immediately after register but before the
    /// first map call).
    #[serde(rename = "DiscoKey", default, skip_serializing_if = "Option::is_none")]
    pub disco_key: Option<String>,
    /// Wall 7: `tailcfg.Node.Endpoints` — NAT-traversal candidate
    /// addresses as `"ip:port"` strings. Empty list ⇒ DERP-only
    /// routing (upstream still accepts the peer in that mode, but the
    /// derp-1 sidecar must be reachable). Empty list is serialised as
    /// an empty JSON array.
    #[serde(rename = "Endpoints", default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    /// Deprecated DERP-in-IP:port string (`127.3.3.40:<region>`).
    #[serde(default, rename = "DERP", skip_serializing_if = "String::is_empty")]
    pub legacy_derp_string: String,
    /// Unsigned peerapi-only node bit.
    #[serde(
        default,
        rename = "UnsignedPeerAPIOnly",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub unsigned_peer_api_only: bool,
    /// Display names computed by the client/control path.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub computed_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub computed_name_with_host: String,
    /// Per-node data-plane audit log ID.
    #[serde(
        default,
        rename = "DataPlaneAuditLogID",
        skip_serializing_if = "String::is_empty"
    )]
    pub data_plane_audit_log_id: String,
    /// Peer-specific masquerade addresses.
    #[serde(
        default,
        rename = "SelfNodeV4MasqAddrForThisPeer",
        skip_serializing_if = "Option::is_none"
    )]
    pub self_node_v4_masq_addr_for_this_peer: Option<String>,
    #[serde(
        default,
        rename = "SelfNodeV6MasqAddrForThisPeer",
        skip_serializing_if = "Option::is_none"
    )]
    pub self_node_v6_masq_addr_for_this_peer: Option<String>,
    /// Non-Tailscale WireGuard peer and jailed-node flags.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_wire_guard_only: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_jailed: bool,
    /// DNS resolvers attached to a WireGuard-only exit node.
    #[serde(
        default,
        rename = "ExitNodeDNSResolvers",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub exit_node_dns_resolvers: Vec<DnsResolver>,
}

/// `tailcfg.DNSConfig`. Mirrors the upstream Go struct field-for-field
/// using the canonical PascalCase JSON encoding the stock daemon
/// expects on the wire.
///
/// All fields are `omitempty` / `omitzero` upstream — we mirror that
/// with `skip_serializing_if` so an unconfigured field never lands in
/// the JSON body. The empty default (all fields zero/empty) serialises
/// to `{}` and is byte-identical to the pre-MagicDNS shape.
///
/// Field set verified against `tailscale/tailcfg/tailcfg.go::DNSConfig`.
/// `AuthoritativeSuffixes` is **non-stock**: a headscale-rs operator
/// extension allowing embedders to assert "the control plane is
/// authoritative for these suffixes; do not ask the upstream
/// resolver." Stock clients ignore unknown fields, so emitting it is
/// safe; the runtime builder only emits it when explicitly configured.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct DnsConfig {
    /// `tailcfg.DNSConfig.Resolvers` — default resolvers MagicDNS
    /// uses for any name not covered by `Routes`. Empty ⇒ client
    /// falls back to system DNS.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolvers: Vec<DnsResolver>,
    /// `tailcfg.DNSConfig.Routes` — split-DNS / restricted-resolver
    /// table. Suffix → resolver list. Empty ⇒ no split DNS.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub routes: HashMap<String, Vec<DnsResolver>>,
    /// `tailcfg.DNSConfig.FallbackResolvers` — last-resort resolvers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallback_resolvers: Vec<DnsResolver>,
    /// `tailcfg.DNSConfig.Domains` — search-domain list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
    /// `tailcfg.DNSConfig.Proxied` — MagicDNS enable bit.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub proxied: bool,
    /// `tailcfg.DNSConfig.Nameservers` — legacy field (deprecated).
    /// String form of `[]netip.Addr`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nameservers: Vec<String>,
    /// `tailcfg.DNSConfig.CertDomains` — TLS-cert SAN list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cert_domains: Vec<String>,
    /// `tailcfg.DNSConfig.ExtraRecords` — operator-supplied static
    /// A / AAAA / CNAME records merged into MagicDNS responses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_records: Vec<DnsRecord>,
    /// `tailcfg.DNSConfig.ExitNodeFilteredSet` — DNS suffixes the
    /// client must not resolve through an exit node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exit_node_filtered_set: Vec<String>,
    /// `tailcfg.DNSConfig.TempCorpIssue13969` — upstream temporary
    /// DNS-blocklist prototype field. It remains part of the pinned
    /// tailcfg JSON contract, so keep it round-trippable.
    #[serde(
        default,
        rename = "TempCorpIssue13969",
        skip_serializing_if = "String::is_empty"
    )]
    pub temp_corp_issue_13969: String,
    /// **Non-stock field.** Operator-grade extension: suffixes the
    /// control plane is authoritative for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authoritative_suffixes: Vec<String>,
}

/// `tailscale/types/dnstype/dnstype.go::Resolver`. JSON tags are
/// `omitempty` upstream — every field is `skip_serializing_if` here
/// so the wire stays byte-identical.
#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct DnsResolver {
    /// `IP[:port]` or `https://…/dns-query`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub addr: String,
    /// IPs the client uses to bootstrap-resolve `Addr` (DoH/DoT).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bootstrap_resolution: Vec<String>,
    /// `true` ⇒ keep using this resolver even with exit node selected.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub use_with_exit_node: bool,
}

/// `tailcfg.DNSRecord`. Operator-supplied A/AAAA/CNAME entries.
#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct DnsRecord {
    /// FQDN. Trailing dot optional.
    #[serde(alias = "name")]
    pub name: String,
    /// Record type — `""` ⇒ A or AAAA inferred from `Value`,
    /// `"CNAME"`, `"AAAA"`, `"A"`.
    #[serde(
        default,
        rename = "Type",
        alias = "type",
        skip_serializing_if = "String::is_empty"
    )]
    pub record_type: String,
    /// Record value (IP literal for A/AAAA; hostname for CNAME).
    #[serde(alias = "value")]
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct DerpMap {
    /// `tailcfg.DERPMap.HomeParams` — optional server-side tuning for
    /// home DERP selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_params: Option<DerpHomeParams>,
    /// region_id → region info. Empty for non-interop deployments;
    /// the interop test populates a single region via
    /// `OCTRAVPN_DERP_MAP_PATH` → [`derp_config::load_derp_map`].
    #[serde(default)]
    pub regions: HashMap<u16, DerpRegion>,
    /// Discovered upstream as `omitDefaultRegions` — when true, the
    /// client must NOT augment our DERPMap with the public Tailscale
    /// region list. We always emit `true` for the interop test so the
    /// client only ever talks to our sidecar.
    #[serde(default, rename = "omitDefaultRegions", alias = "OmitDefaultRegions")]
    pub omit_default_regions: bool,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct DerpHomeParams {
    /// `tailcfg.DERPHomeParams.RegionScore` — region ID → weighting
    /// factor used by clients when selecting home DERP.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub region_score: HashMap<u16, f64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct DerpRegion {
    /// Numeric region ID. Must match the map key in `DerpMap.regions`.
    /// Upstream `tailcfg.DERPRegion.RegionID` is an `int`; we serialise
    /// as a plain integer.
    #[serde(rename = "RegionID")]
    pub region_id: u16,
    pub region_code: String,
    pub region_name: String,
    /// Optional geographic coordinates.
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub latitude: f64,
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub longitude: f64,
    /// Whether the region should be skipped for new sessions. Defaults
    /// to false (region is healthy).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub avoid: bool,
    /// Upstream replacement for deprecated `Avoid`: do not measure
    /// this region or select it as home unless needed for a peer there.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_measure_no_home: bool,
    pub nodes: Vec<DerpRegionNode>,
}

/// Mirrors `tailscale/tailcfg/derpmap.go::DERPNode`. Only the fields
/// the interop test needs to bootstrap a derper sidecar are non-
/// optional; everything else is `Option<…> + skip_serializing_if`.
///
/// Field-for-field shape verified against upstream commit at the time
/// of Wall 6 closure: `HostName`, `IPv4`, `IPv6`, `DERPPort`,
/// `STUNPort`, `STUNOnly`, `InsecureForTests` are all `omitempty` on
/// the Go side; emitting them as `None` produces a byte-identical
/// payload to omitting them.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct DerpRegionNode {
    pub name: String,
    #[serde(rename = "RegionID")]
    pub region_id: u16,
    pub host_name: String,
    /// Expected TLS certificate name/hash. Empty means `HostName`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cert_name: String,
    /// Upstream JSON tag is `IPv4` (all-caps); PascalCase rename keeps
    /// the wire byte-identical (camel-to-pascal mishandles single-letter
    /// prefixes).
    #[serde(default, rename = "IPv4", skip_serializing_if = "String::is_empty")]
    pub ipv4: String,
    #[serde(default, rename = "IPv6", skip_serializing_if = "String::is_empty")]
    pub ipv6: String,
    /// DERP HTTPS port. `0` ⇒ omit ⇒ client defaults to 443.
    #[serde(rename = "DERPPort", default, skip_serializing_if = "is_zero_u16")]
    pub derp_port: u16,
    /// STUN UDP port. `0` ⇒ omit ⇒ client defaults to 3478.
    #[serde(rename = "STUNPort", default, skip_serializing_if = "is_zero_i32")]
    pub stun_port: i32,
    /// `true` ⇒ the node serves STUN only, no DERP. Defaults to false.
    #[serde(
        rename = "STUNOnly",
        default,
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub stun_only: bool,
    /// `true` ⇒ accept a self-signed TLS certificate on the DERP HTTPS
    /// endpoint. Required for the docker-network sidecar — we mint a
    /// fresh cert at `run-interop.sh` time and don't bind it to any
    /// public CA.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub insecure_for_tests: bool,
    /// Test-only override for the STUN server IP.
    #[serde(
        rename = "STUNTestIP",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub stun_test_ip: String,
    /// Whether this node is reachable over HTTP on port 80.
    #[serde(
        rename = "CanPort80",
        default,
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub can_port80: bool,
}

fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}
fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}
fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}
fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}
fn is_zero_f64(v: &f64) -> bool {
    *v == 0.0
}
#[allow(clippy::ref_option)]
fn option_vec_is_none_or_empty<T>(v: &Option<Vec<T>>) -> bool {
    match v {
        None => true,
        Some(v) => v.is_empty(),
    }
}

/// Strip a Tailscale key prefix (`mkey:`, `nodekey:`, `discokey:`)
/// and return the hex-encoded body. Returns `None` if no recognised
/// prefix is present, in which case the caller can treat the input as
/// raw hex.
pub fn strip_key_prefix(s: &str) -> Option<&str> {
    for p in ["mkey:", "nodekey:", "discokey:"] {
        if let Some(rest) = s.strip_prefix(p) {
            return Some(rest);
        }
    }
    None
}

/// Deterministic positive 63-bit ID from a hex string. Used to derive
/// `ID` fields in `MapNode` / `SimpleUser`. Not cryptographic.
///
/// Upstream `tailcfg.NodeID` is a Go `int64`; emitting a `u64` value
/// above `i64::MAX` triggers
/// `json: cannot unmarshal number X into … NodeID of type tailcfg.NodeID`
/// on the client. We mask the top bit out so the value always fits in
/// a positive signed 63-bit integer.
pub fn stable_id_from_key(hex_str: &str) -> u64 {
    // FNV-1a 64-bit. Inlined to avoid pulling in a fnv crate.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in hex_str.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // Clear the sign bit so the value round-trips through Go's int64.
    h & 0x7fff_ffff_ffff_ffff
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_known_prefixes() {
        assert_eq!(strip_key_prefix("mkey:abcd"), Some("abcd"));
        assert_eq!(strip_key_prefix("nodekey:1234"), Some("1234"));
        assert_eq!(strip_key_prefix("discokey:beef"), Some("beef"));
        assert_eq!(strip_key_prefix("plainhex"), None);
    }

    #[test]
    fn given_name_helpers_match_tailscale_dnsname_edges() {
        assert_eq!(sanitize_hostname_for_given_name("Peer.One!"), "peer-one");
        assert_eq!(sanitize_hostname_for_given_name("HOST_NAME"), "host-name");
        assert_eq!(sanitize_hostname_for_given_name("---a---"), "a");
        assert_eq!(sanitize_hostname_for_given_name("node.local"), "node");
        assert_eq!(
            sanitize_hostname_for_given_name("node.localdomain.local"),
            "node"
        );
        assert_eq!(
            sanitize_hostname_for_given_name("node.lan.localdomain"),
            "node"
        );
        assert_eq!(sanitize_hostname_for_given_name("!!!"), "");
        assert_eq!(auto_given_name_base("!!!"), "node");
        assert!(!is_auto_derived_given_name("node", "!!!"));
        assert!(is_auto_derived_given_name("", "!!!"));
        assert!(is_auto_derived_given_name("-1", "!!!"));
        assert!(!is_auto_derived_given_name("admin-name", "!!!"));

        assert!(valid_given_name_label("a"));
        assert!(valid_given_name_label("Alice"));
        assert!(valid_given_name_label("node-1"));
        assert!(!valid_given_name_label(""));
        assert!(!valid_given_name_label("alice.laptop"));
        assert!(!valid_given_name_label("alice_laptop"));
        assert!(!valid_given_name_label("-alice"));
        assert!(!valid_given_name_label("alice-"));
        assert!(!valid_given_name_label(&"a".repeat(64)));
    }

    #[test]
    fn replace_host_info_preserves_stored_given_name_projection() {
        let now = chrono::Utc::now();
        let mut record = MachineRecord::new_at(
            now,
            "node".into(),
            "machine".into(),
            "alice".into(),
            "admin-name".into(),
            "100.64.0.1".parse().unwrap(),
            false,
        );

        record.replace_host_info(HostInfo {
            hostname: "raw-client-name".into(),
            os: "linux".into(),
            ..HostInfo::default()
        });

        assert_eq!(record.hostname, "admin-name");
        assert_eq!(record.host_info_for_node().hostname, "raw-client-name");
    }

    #[test]
    fn register_request_round_trip() {
        let r = RegisterRequest {
            version: 96,
            node_key: "nodekey:deadbeef".into(),
            old_node_key: "nodekey:feedface".into(),
            nl_key: "nlpub:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            auth: Some(RegisterAuth {
                auth_key: "hskey-auth-abc".into(),
                oauth2_token: None,
            }),
            hostinfo: Some(HostInfo {
                hostname: "peer-a".into(),
                os: "linux".into(),
                os_version: "6.6".into(),
                routable_ips: Vec::new(),
                request_tags: Vec::new(),
                net_info: None,
                ..HostInfo::default()
            }),
            followup: None,
            tailnet: "required:example.com".into(),
            ephemeral: false,
            expiry: None,
            node_key_signature: Some("bm9kZS1zaWduYXR1cmU=".into()),
            signature_type: "signature-v2".into(),
            timestamp: Some("2026-06-01T00:00:01Z".parse().unwrap()),
            device_cert: Some("ZGV2aWNlLWNlcnQ=".into()),
            signature: Some("cmVnaXN0ZXItc2lnbmF0dXJl".into()),
        };
        let j = serde_json::to_string(&r).unwrap();
        // Field names PascalCased on the wire.
        assert!(j.contains("\"Version\""));
        assert!(j.contains("\"NodeKey\""));
        assert!(j.contains("\"OldNodeKey\""));
        assert!(j.contains("\"NLKey\""));
        assert!(j.contains("\"Auth\""));
        assert!(j.contains("\"AuthKey\""));
        assert!(j.contains("\"OSVersion\""));
        assert!(j.contains("\"Tailnet\""));
        assert!(j.contains("\"NodeKeySignature\""));
        assert!(j.contains("\"SignatureType\""));
        assert!(j.contains("\"Timestamp\""));
        assert!(j.contains("\"DeviceCert\""));
        assert!(j.contains("\"Signature\""));
        let back: RegisterRequest = serde_json::from_str(&j).unwrap();
        assert_eq!(back.node_key, "nodekey:deadbeef");
        assert_eq!(back.old_node_key, "nodekey:feedface");
        assert_eq!(
            back.nl_key,
            "nlpub:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(back.tailnet, "required:example.com");
        assert_eq!(
            back.node_key_signature.as_deref(),
            Some("bm9kZS1zaWduYXR1cmU=")
        );
        assert_eq!(back.signature_type, "signature-v2");
        assert!(back.timestamp.is_some());
        assert_eq!(back.device_cert.as_deref(), Some("ZGV2aWNlLWNlcnQ="));
        assert_eq!(back.signature.as_deref(), Some("cmVnaXN0ZXItc2lnbmF0dXJl"));
    }

    #[test]
    fn stable_id_is_deterministic() {
        assert_eq!(stable_id_from_key("abcd"), stable_id_from_key("abcd"));
        assert_ne!(stable_id_from_key("abcd"), stable_id_from_key("dcba"));
    }
}
