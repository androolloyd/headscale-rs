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
//! - **We only model the fields stock `tailscale up` actually requires
//!   to reach "registered" and emit a single MapResponse.** Anything
//!   beyond that (ACLs, SSH attributes, DERPRegion, DNSConfig
//!   extensions, key-rotation fields) is **omitted on purpose** — the
//!   blocker doc rules them out for the interop test, and including
//!   them risks drift against the upstream `tailcfg` package.
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
//! - **`MapResponse.Peers` is the *only* peer-emission path we use.**
//!   Tailscale's incremental update mechanism
//!   (`PeersChanged{,Patch}`, `PeerSeenChange`) is intentionally not
//!   modelled — the interop test only needs the first full snapshot.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
///
/// `Expiry` is checked on every `/map` request: an elapsed expiry
/// causes the server to emit a logout response (upstream behaviour at
/// `hscontrol/poll.go::handlePoll`). `LastSeen` is refreshed on every
/// `/map` arrival so the ephemeral GC sweep can identify abandoned
/// devices.
#[derive(Clone, Debug)]
pub struct MachineRecord {
    /// Hex-encoded (no prefix) Tailscale `NodeKey`. The map endpoint
    /// path `/machine/{node_key}/map` carries the raw hex.
    pub node_key_hex: String,
    /// Hex-encoded (no prefix) machine key (X25519). May be empty if
    /// the registrant only presented a NodeKey.
    pub machine_key_hex: String,
    /// User the preauth key was minted for.
    pub user: String,
    /// Hostname the client advertised in HostInfo (best-effort; may
    /// be empty).
    pub hostname: String,
    /// Allocated tailnet IPv4 in the CGNAT range.
    pub ipv4: std::net::Ipv4Addr,
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
    /// P1 (lifecycle): node-key expiry. When `Some(t)` and `t <=
    /// now()`, the `/map` handler MUST return a logout response
    /// (mirrors upstream `Node.IsExpired()` semantics). `None` means
    /// "never expires" — the default for fresh registrations from
    /// non-ephemeral preauth keys.
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
}

impl MachineRecord {
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
        Self {
            node_key_hex,
            machine_key_hex,
            user,
            hostname,
            ipv4,
            disco_key: None,
            endpoints: Vec::new(),
            expiry: None,
            last_seen: now,
            ephemeral,
            created_at: now,
            forced_tags: Vec::new(),
        }
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
    /// `nodekey:` prefixed hex string. The path parameter and this
    /// field both carry the same value in upstream Tailscale; we
    /// trust the body's copy.
    pub node_key: String,
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
    /// Whether the client requests ephemeral registration. Upstream
    /// `tailcfg.RegisterRequest.Ephemeral` is a plain bool.
    #[serde(default)]
    pub ephemeral: bool,
    /// Requested node-key expiry. We do not currently honor the
    /// client-supplied value in the register handler, but accepting it
    /// keeps the wire shape aligned with `tailcfg`.
    #[serde(default)]
    pub expiry: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterAuth {
    /// Preauth bearer token (e.g. `octrapreauth-<hex>`). On the
    /// upstream wire this is `AuthKey`.
    #[serde(default)]
    pub auth_key: String,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct HostInfo {
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
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SimpleUser {
    /// 64-bit stable user ID. We hash the preauth user label into a
    /// u64 — this is fine for the interop test (no cross-process
    /// reconciliation) but is a known weak link for production use.
    #[serde(rename = "ID")]
    pub id: u64,
    pub login_name: String,
    pub display_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SimpleLogin {
    #[serde(rename = "ID")]
    pub id: u64,
    pub provider: String,
    pub login_name: String,
    pub display_name: String,
}

/// Body of `POST /machine/{node_key}/map`.
///
/// The upstream `tailcfg.MapRequest` carries ~15 fields. We model only
/// the few that affect whether the client continues to poll. The
/// `Stream` flag in particular is critical: when true, the client
/// expects an HTTP chunked / NDJSON stream of map updates rather than
/// a single response body.
///
/// **Decision:** we always return a single-response body (Stream=false
/// behaviour) regardless of the request flag. This is wrong long-term
/// — the stock client *does* set Stream=true — but it lets us return
/// a usable MapResponse for the interop test without spinning a
/// streaming-writer task. Marked as a follow-up in the blocker doc.
#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct MapRequest {
    /// Client's capability version. Pinned at >=39 for TS2021.
    #[serde(default)]
    pub version: u32,
    /// Whether the client wants the long-poll stream. We ignore this
    /// (see note above) but accept it on the wire.
    #[serde(default)]
    pub stream: bool,
    /// Whether the client wants the response in compressed form.
    /// Currently ignored.
    #[serde(default)]
    pub compress: String,
    /// HostInfo the client wants to update on this map call.
    #[serde(default)]
    pub hostinfo: Option<HostInfo>,
    /// `OmitPeers` true ⇒ client just wants a poke / heartbeat.
    #[serde(default)]
    pub omit_peers: bool,
    /// `nodekey:` prefixed hex string. Present on v1.78+ flat-path
    /// requests (`POST /machine/map`) where there's no URL parameter.
    /// Empty on the keyed-path variant (caller takes the value from the
    /// URL instead).
    #[serde(default)]
    pub node_key: String,
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
    /// Wall 7: NAT-traversal endpoint candidates the client wants peers
    /// to try (`"ip:port"` strings). Upstream `tailcfg.MapRequest`
    /// historically carried `Endpoints []string`; v1.78+ added a typed
    /// `[]netip.AddrPort` shape but the JSON wire still encodes as a
    /// `[]string`. Optional ⇒ empty list when absent.
    #[serde(default, rename = "Endpoints")]
    pub endpoints: Option<Vec<String>>,
}

/// Response to `/machine/{node_key}/map`.
///
/// We return only the fields needed for a fresh peer to learn its
/// own assigned addresses and the (one) other peer in the test
/// tailnet. `DERPMap`, `ACLs`, `DNSConfig`, key-rotation fields,
/// SSH attributes, `Domain`, etc. are all elided.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MapResponse {
    /// `key_expiry_extension` in upstream; unused here, kept for shape.
    #[serde(default)]
    pub key_expiry_extension: u64,
    /// Own node record.
    pub node: MapNode,
    /// Other peers in the tailnet. Empty list is valid (e.g. a
    /// peer-A joining before peer-B does); the long-poll waits for a
    /// second registration to flesh this out.
    pub peers: Vec<MapNode>,
    /// Synthetic empty DNS config — present so the client doesn't
    /// reject the response for missing fields. Upstream JSON tag is
    /// `DNSConfig` (all-caps DNS), not `DnsConfig`.
    #[serde(rename = "DNSConfig")]
    pub dns_config: DnsConfig,
    /// Synthetic empty DERPMap — peers will fall back to direct
    /// connections on the docker bridge. Upstream JSON tag is
    /// `DERPMap`, not `DerpMap`.
    #[serde(rename = "DERPMap")]
    pub derp_map: DerpMap,
    /// Domain string the client treats as the tailnet's MagicDNS root.
    /// We hard-code `octra.test` for the interop run.
    pub domain: String,
    /// Whether the client should keep polling. `true` matches stock
    /// expectations.
    pub keep_alive: bool,
    /// P1 lifecycle: mirrors `tailcfg.MapResponse.NodeKeyExpired`. When
    /// `true` the stock daemon treats the response as a forced
    /// logout — it tears down its session and falls back to a fresh
    /// register/login flow. We emit `true` here only when the server
    /// detected an elapsed `MachineRecord.expiry` at the top of the
    /// `/map` handler; the normal happy path stays `false` (omitted by
    /// `skip_serializing_if`).
    #[serde(
        default,
        rename = "NodeKeyExpired",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub node_key_expired: bool,
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
    /// Per-destination port range entries.
    #[serde(default)]
    pub dst_ports: Vec<NetPortRange>,
    /// IP protocol restrictions. Empty ⇒ all protocols allowed.
    #[serde(default, rename = "IPProto", skip_serializing_if = "Vec::is_empty")]
    pub ip_proto: Vec<i32>,
}

/// `tailcfg.NetPortRange`.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct NetPortRange {
    #[serde(rename = "IP")]
    pub ip: String,
    pub ports: PortRange,
}

/// `tailcfg.PortRange`.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct PortRange {
    pub first: u16,
    pub last: u16,
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
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct MapNode {
    /// Stable per-tailnet node ID. We use the FNV hash of the node
    /// key bytes — deterministic for a given key, fits in u64.
    #[serde(rename = "ID")]
    pub id: u64,
    /// `StableNodeID` — same value-domain as `ID` but a string. We
    /// derive it as `"n{ID}"` (matches headscale-go's
    /// `fmt.Sprintf("n%d", id)` convention).
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
    /// `nodekey:` prefixed hex.
    pub key: String,
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
    /// Hostname the node advertised.
    pub hostinfo: HostInfo,
    /// Mirrors upstream `tailcfg.Node.MachineAuthorized` (line 433 of
    /// `tailcfg/tailcfg.go`). The control client's
    /// `netmap.NetworkMap.GetMachineStatus()` reads this off
    /// `SelfNode`; without it the daemon stalls in `NeedsMachineAuth`
    /// (BackendState 3) even after `RegisterResponse.MachineAuthorized
    /// = true`. Wall 5 sequel: register-time auth is necessary but
    /// not sufficient — the netmap must carry the same bit.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub machine_authorized: bool,
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
/// Field set verified against
/// `tailscale/tailcfg/tailcfg.go::DNSConfig` at upstream `main` as of
/// 2026-05-19. `TempCorpIssue13969` is intentionally omitted (upstream
/// debug-only field).
///
/// `AuthoritativeSuffixes` is **non-stock**: a headscale-rs operator
/// extension allowing embedders to assert "the control plane is
/// authoritative for these suffixes; do not ask the upstream
/// resolver." Stock clients ignore unknown fields, so emitting it is
/// safe; servers that don't set it never emit it.
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
    pub name: String,
    /// Record type — `""` ⇒ A or AAAA inferred from `Value`,
    /// `"CNAME"`, `"AAAA"`, `"A"`.
    #[serde(default, rename = "Type", skip_serializing_if = "String::is_empty")]
    pub record_type: String,
    /// Record value (IP literal for A/AAAA; hostname for CNAME).
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct DerpMap {
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
    /// Whether the region should be skipped for new sessions. Defaults
    /// to false (region is healthy).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub avoid: bool,
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
}

fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}
fn is_zero_i32(v: &i32) -> bool {
    *v == 0
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
    fn register_request_round_trip() {
        let r = RegisterRequest {
            node_key: "nodekey:deadbeef".into(),
            auth: Some(RegisterAuth {
                auth_key: "octrapreauth-abc".into(),
            }),
            hostinfo: Some(HostInfo {
                hostname: "peer-a".into(),
                os: "linux".into(),
                os_version: "6.6".into(),
            }),
            followup: None,
            ephemeral: false,
            expiry: None,
        };
        let j = serde_json::to_string(&r).unwrap();
        // Field names PascalCased on the wire.
        assert!(j.contains("\"NodeKey\""));
        assert!(j.contains("\"Auth\""));
        assert!(j.contains("\"AuthKey\""));
        assert!(j.contains("\"OSVersion\""));
        let back: RegisterRequest = serde_json::from_str(&j).unwrap();
        assert_eq!(back.node_key, "nodekey:deadbeef");
    }

    #[test]
    fn stable_id_is_deterministic() {
        assert_eq!(stable_id_from_key("abcd"), stable_id_from_key("abcd"));
        assert_ne!(stable_id_from_key("abcd"), stable_id_from_key("dcba"));
    }
}
