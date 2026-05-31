//! MagicDNS / `tailcfg.DNSConfig` build + hot-reload.
//!
//! Closes the P1 entry in `docs/headscale-gap-analysis.md` (§MagicDNS):
//! before this module shipped, `MapResponse.DNSConfig` was an empty
//! object, so stock `tailscale up` never installed its in-process
//! MagicDNS resolver and `ssh peer-1` couldn't resolve peer hostnames
//! from the netmap.
//!
//! ## What we mirror from upstream Go
//!
//! - `juanfont/headscale@main:hscontrol/dns/dns.go` — `NewDNSConfig` /
//!   `FullResolvers` / `SplitResolvers` build path.
//! - `juanfont/headscale@main:hscontrol/dns/extrarecords.go` — file-
//!   watcher for operator-supplied A/AAAA/CNAME records.
//! - `tailscale/tailcfg/tailcfg.go::DNSConfig` — the wire shape, see
//!   [`crate::tailscale_wire::wire::DnsConfig`].
//!
//! ## Hot-reload mechanism
//!
//! We poll the extra-records file's `mtime` every
//! [`EXTRA_RECORDS_POLL_INTERVAL`] (default 5s) rather than pulling in
//! the `notify` crate. Reasons:
//!
//! - The constraint set on this PR says "no new heavy deps; mtime poll
//!   is OK."
//! - `notify`'s cross-platform abstraction (inotify on Linux, kqueue
//!   on macOS, ReadDirectoryChangesW on Windows) is mostly useful for
//!   high-frequency edits — operator-edited DNS records change once
//!   per ops session, where a 5s polling lag is invisible.
//! - mtime polling has zero filesystem-event-loss failure modes; the
//!   `notify` crate is famously lossy on macOS and across bind mounts
//!   (see issue tracker history).
//!
//! On every detected change we (1) re-read the file, (2) parse to a
//! `Vec<DnsRecord>`, (3) swap it into the store, (4)
//! `notify_waiters()` so parked `/map` long-pollers wake and emit a
//! refreshed `MapResponse`.
//!
//! ## MagicDNS host records
//!
//! Headscale-go does not synthesize per-node `DNSConfig.ExtraRecords`.
//! Peer names come from `MapNode.Name` plus `MapResponse.Domain`, and
//! `ExtraRecords` stays limited to operator-supplied A/AAAA/CNAME
//! records. Keeping those surfaces separate matters for live clients:
//! `tailscale debug netmap` should show only configured extra records
//! under `DNS.ExtraRecords`, while peers remain visible through the
//! normal node list.

#![allow(clippy::module_name_repetitions)]

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    hash::{Hash, Hasher},
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};

use parking_lot::RwLock;
use serde::{Deserialize, Deserializer, Serialize};
use tokio::sync::Notify;

use crate::tailscale_wire::wire::{DnsConfig, DnsRecord, DnsResolver};
use ipnet::{Ipv4Net, Ipv6Net};

const NEXTDNS_DOH_PREFIX: &str = "https://dns.nextdns.io";
const NEXTDNS_ATTR_PREFIX: &str = "nextdns:";
const NEXTDNS_ATTR_NO_DEVICE_INFO: &str = "nextdns:no-device-info";

type ResolverAddrs = Vec<String>;
type ResolverObjects = Vec<DnsResolver>;
type SplitResolverAddrs = HashMap<String, ResolverAddrs>;
type SplitResolverObjects = HashMap<String, ResolverObjects>;
type NameserverParts = (
    ResolverAddrs,
    ResolverObjects,
    SplitResolverAddrs,
    SplitResolverObjects,
);

/// How often the background poller checks the extra-records file's
/// `mtime`. Operators expect "edit a JSON file; new records appear
/// within a few seconds" — 5s is the same cadence the upstream Go
/// `ExtraRecordsMan` debounces redundant updates to.
pub const EXTRA_RECORDS_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Operator-supplied DNS configuration block. Parses from the `[dns]`
/// table in `node.toml` (or any other serde-driven config surface);
/// the wire layer consumes a [`DnsStore`] derived from this spec.
///
/// Defaults follow headscale-go v0.28: MagicDNS defaults on, but the
/// base domain defaults empty and must be supplied by the operator
/// before MagicDNS can be used.
#[derive(Debug, Clone, Serialize)]
pub struct DnsConfigSpec {
    /// Enable MagicDNS. Matches headscale-go's default of `true`; call
    /// [`Self::validate`] or [`DnsStore::try_from_spec`] before runtime
    /// use so an empty `base_domain` is rejected.
    pub magic_dns: bool,
    /// MagicDNS root domain. Hostnames are emitted as
    /// `<hostname>.<base_domain>` → tailnet IP. Operators typically
    /// pick a sub-domain of an org-owned name (e.g.
    /// `tailnet.example.org`). Defaults to empty, matching
    /// headscale-go config defaults.
    pub base_domain: String,
    /// Whether Headscale's global resolvers replace the client's
    /// local DNS settings. Upstream headscale-go defaults this to
    /// `true`; when set to `false`, global resolvers are emitted as
    /// `FallbackResolvers` instead.
    pub override_local_dns: bool,
    /// Default resolver(s) — DNS-over-UDP `IP[:port]` literals or
    /// DNS-over-HTTPS URLs. Empty ⇒ no `Resolvers` field on the wire,
    /// the client falls back to system DNS. The deserializer accepts
    /// both the older flat list and upstream headscale's
    /// `nameservers.global` shape.
    pub nameservers: Vec<String>,
    /// Structured form of [`Self::nameservers`]. This is populated by
    /// the permissive deserializer when config uses resolver objects
    /// instead of bare strings, preserving tailcfg metadata such as
    /// `BootstrapResolution` and `UseWithExitNode`.
    pub nameserver_resolvers: Vec<DnsResolver>,
    /// Per-suffix restricted resolvers (split DNS). Key is a DNS
    /// suffix (e.g. `"corp.internal"`), value is the resolver list to
    /// use for that suffix. Empty ⇒ no `Routes` field on the wire.
    /// The deserializer accepts both this historical field and
    /// upstream headscale's `nameservers.split` table.
    pub restricted_nameservers: HashMap<String, Vec<String>>,
    /// Structured form of [`Self::restricted_nameservers`], retaining
    /// resolver metadata for split-DNS routes.
    pub restricted_resolvers: HashMap<String, Vec<DnsResolver>>,
    /// Inline operator records that land in
    /// `DNSConfig.ExtraRecords`. Upstream headscale names this field
    /// `extra_records` and uses a top-level array of
    /// `{name, type, value}` objects.
    pub extra_records: Vec<DnsRecord>,
    /// Optional path to a JSON file of `[{name, type, value}]`
    /// records. The file is hot-reloaded (mtime poll, see
    /// [`EXTRA_RECORDS_POLL_INTERVAL`]); changes wake every parked
    /// `/map` long-poller. For compatibility with the previous
    /// headscale-rs shape, `extra_records = "/path/to/file.json"`
    /// also deserializes into this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_records_path: Option<PathBuf>,
    /// Search-domain list emitted in `DNSConfig.Domains`. The base
    /// domain is always prepended at build time; this list extends
    /// it.
    pub search_domains: Vec<String>,
    /// Last-resort resolvers (`FallbackResolvers`).
    pub fallback_nameservers: Vec<String>,
    /// Structured form of [`Self::fallback_nameservers`], retaining
    /// resolver metadata.
    pub fallback_resolvers: Vec<DnsResolver>,
    /// Client certificate domains emitted in `DNSConfig.CertDomains`.
    /// Headscale-go does not derive these from the control-plane HTTPS
    /// listener, so the runtime only emits explicitly configured
    /// values.
    pub cert_domains: Vec<String>,
    /// `ExitNodeFilteredSet` — suffixes the client should not flow
    /// through an exit node.
    pub exit_node_filtered_set: Vec<String>,
    /// Override the `AuthoritativeSuffixes` list. When `None`
    /// (default), the store derives it from `[base_domain]` plus the
    /// keys of `restricted_nameservers`. Set to `Some(vec![])` to
    /// emit an empty list.
    pub authoritative_suffixes: Option<Vec<String>>,
}

const fn default_true() -> bool {
    true
}

fn default_base_domain() -> String {
    String::new()
}

impl Default for DnsConfigSpec {
    /// Headscale-go-compatible defaults: MagicDNS on, empty base
    /// domain, no resolvers / records / search domains. An operator
    /// config must set `base_domain` or disable MagicDNS before
    /// passing validation.
    fn default() -> Self {
        Self {
            magic_dns: default_true(),
            base_domain: default_base_domain(),
            override_local_dns: default_true(),
            nameservers: Vec::new(),
            nameserver_resolvers: Vec::new(),
            restricted_nameservers: HashMap::new(),
            restricted_resolvers: HashMap::new(),
            extra_records: Vec::new(),
            extra_records_path: None,
            search_domains: Vec::new(),
            fallback_nameservers: Vec::new(),
            fallback_resolvers: Vec::new(),
            cert_domains: Vec::new(),
            exit_node_filtered_set: Vec::new(),
            authoritative_suffixes: None,
        }
    }
}

impl<'de> Deserialize<'de> for DnsConfigSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawDnsConfigSpec::deserialize(deserializer)?;
        if raw.extra_records.is_some() && raw.extra_records_path.is_some() {
            return Err(serde::de::Error::custom(
                "dns.extra_records and dns.extra_records_path are mutually exclusive",
            ));
        }
        let (
            nameservers,
            nameserver_resolvers,
            mut restricted_nameservers,
            mut restricted_resolvers,
        ) = raw.nameservers.into_parts();
        for (suffix, resolvers) in raw.restricted_nameservers {
            let (addrs, structured) = raw_resolvers_into_parts(resolvers);
            restricted_nameservers.insert(suffix.clone(), addrs);
            restricted_resolvers.insert(suffix, structured);
        }
        let (fallback_nameservers, fallback_resolvers) =
            raw_resolvers_into_parts(raw.fallback_nameservers);

        let (extra_records, extra_records_path_from_legacy_key) = match raw.extra_records {
            Some(RawExtraRecords::Records(records)) => {
                (records.into_iter().map(Into::into).collect(), None)
            }
            Some(RawExtraRecords::Path(path)) => (Vec::new(), Some(path)),
            None => (Vec::new(), None),
        };

        Ok(Self {
            magic_dns: raw.magic_dns,
            base_domain: raw.base_domain,
            override_local_dns: raw.override_local_dns,
            nameservers,
            nameserver_resolvers,
            restricted_nameservers,
            restricted_resolvers,
            extra_records,
            extra_records_path: raw
                .extra_records_path
                .or(extra_records_path_from_legacy_key),
            search_domains: raw.search_domains,
            fallback_nameservers,
            fallback_resolvers,
            cert_domains: raw.cert_domains,
            exit_node_filtered_set: raw.exit_node_filtered_set,
            authoritative_suffixes: raw.authoritative_suffixes,
        })
    }
}

#[derive(Deserialize)]
#[serde(default)]
struct RawDnsConfigSpec {
    magic_dns: bool,
    base_domain: String,
    override_local_dns: bool,
    nameservers: RawNameservers,
    restricted_nameservers: HashMap<String, Vec<RawResolver>>,
    extra_records: Option<RawExtraRecords>,
    extra_records_path: Option<PathBuf>,
    search_domains: Vec<String>,
    fallback_nameservers: Vec<RawResolver>,
    #[serde(alias = "CertDomains")]
    cert_domains: Vec<String>,
    exit_node_filtered_set: Vec<String>,
    authoritative_suffixes: Option<Vec<String>>,
}

impl Default for RawDnsConfigSpec {
    fn default() -> Self {
        Self {
            magic_dns: default_true(),
            base_domain: default_base_domain(),
            override_local_dns: default_true(),
            nameservers: RawNameservers::default(),
            restricted_nameservers: HashMap::new(),
            extra_records: None,
            extra_records_path: None,
            search_domains: Vec::new(),
            fallback_nameservers: Vec::new(),
            cert_domains: Vec::new(),
            exit_node_filtered_set: Vec::new(),
            authoritative_suffixes: None,
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawNameservers {
    Flat(Vec<RawResolver>),
    Upstream {
        #[serde(default)]
        global: Vec<RawResolver>,
        #[serde(default)]
        split: HashMap<String, Vec<RawResolver>>,
    },
}

impl RawNameservers {
    fn into_parts(self) -> NameserverParts {
        match self {
            Self::Flat(global) => {
                let (global_addrs, global_resolvers) = raw_resolvers_into_parts(global);
                (
                    global_addrs,
                    global_resolvers,
                    HashMap::new(),
                    HashMap::new(),
                )
            }
            Self::Upstream { global, split } => {
                let (global_addrs, global_resolvers) = raw_resolvers_into_parts(global);
                let mut split_addrs = HashMap::new();
                let mut split_resolvers = HashMap::new();
                for (suffix, resolvers) in split {
                    let (addrs, structured) = raw_resolvers_into_parts(resolvers);
                    split_addrs.insert(suffix.clone(), addrs);
                    split_resolvers.insert(suffix, structured);
                }
                (global_addrs, global_resolvers, split_addrs, split_resolvers)
            }
        }
    }
}

impl Default for RawNameservers {
    fn default() -> Self {
        Self::Upstream {
            global: Vec::new(),
            split: HashMap::new(),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawResolver {
    Addr(String),
    Resolver(RawResolverObject),
}

#[derive(Deserialize)]
struct RawResolverObject {
    #[serde(alias = "Addr")]
    addr: String,
    #[serde(default, alias = "BootstrapResolution")]
    bootstrap_resolution: Vec<String>,
    #[serde(default, alias = "UseWithExitNode")]
    use_with_exit_node: bool,
}

impl From<RawResolver> for DnsResolver {
    fn from(raw: RawResolver) -> Self {
        match raw {
            RawResolver::Addr(addr) => resolver_from_addr(&addr),
            RawResolver::Resolver(raw) => Self {
                addr: raw.addr,
                bootstrap_resolution: raw.bootstrap_resolution,
                use_with_exit_node: raw.use_with_exit_node,
            },
        }
    }
}

fn raw_resolvers_into_parts(raw: Vec<RawResolver>) -> (Vec<String>, Vec<DnsResolver>) {
    let resolvers: Vec<DnsResolver> = raw.into_iter().map(Into::into).collect();
    let addrs = resolvers
        .iter()
        .map(|resolver| resolver.addr.clone())
        .collect();
    (addrs, resolvers)
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawExtraRecords {
    Path(PathBuf),
    Records(Vec<LooseDnsRecord>),
}

#[derive(Deserialize)]
struct LooseDnsRecord {
    #[serde(alias = "Name")]
    name: String,
    #[serde(rename = "type", alias = "Type", default)]
    record_type: Option<String>,
    #[serde(alias = "Value")]
    value: String,
}

impl From<LooseDnsRecord> for DnsRecord {
    fn from(record: LooseDnsRecord) -> Self {
        Self {
            name: record.name,
            record_type: record.record_type.unwrap_or_default(),
            value: record.value,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsConfigError {
    MissingBaseDomainForMagicDns,
    MissingGlobalNameserversForOverride,
    InvalidMagicDnsIpv4Prefix,
    InvalidMagicDnsIpv6Prefix,
}

impl std::fmt::Display for DnsConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingBaseDomainForMagicDns => {
                f.write_str("dns.base_domain must be set when using MagicDNS")
            }
            Self::MissingGlobalNameserversForOverride => f.write_str(
                "dns.nameservers.global must be set when dns.override_local_dns is true",
            ),
            Self::InvalidMagicDnsIpv4Prefix => {
                f.write_str("server.mesh_cidr is not a valid IPv4 prefix")
            }
            Self::InvalidMagicDnsIpv6Prefix => {
                f.write_str("server.mesh_cidr_v6 is not a valid IPv6 prefix")
            }
        }
    }
}

impl std::error::Error for DnsConfigError {}

impl DnsConfigSpec {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if self.magic_dns && self.base_domain.trim().is_empty() {
            return Err(DnsConfigError::MissingBaseDomainForMagicDns);
        }
        if self.override_local_dns
            && self.nameservers.is_empty()
            && self.nameserver_resolvers.is_empty()
        {
            return Err(DnsConfigError::MissingGlobalNameserversForOverride);
        }

        Ok(())
    }
}

/// One machine's record-set input. Wire layer hands these to
/// [`DnsStore::build`] every time it rebuilds a `MapResponse` so the
/// MagicDNS A records always reflect the current registry. The store
/// itself doesn't cache the machine list — it's cheap to walk on
/// each rebuild and the registry already lives behind a COW Arc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineDnsRecord {
    pub hostname: String,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    /// Stable per-tailnet node ID. Kept for compatibility with older
    /// helper code that materializes synthetic records.
    pub node_id: u64,
}

/// Requester-specific DNS rendering inputs.
///
/// Headscale-go v0.29 applies policy `nodeAttrs` to the requester
/// before placing `DNSConfig` in its `MapResponse`: `nextdns:<profile>`
/// rewrites NextDNS DoH resolver profile paths, and
/// `nextdns:no-device-info` suppresses the metadata query string.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsRequester {
    pub hostname: String,
    pub os: String,
    pub primary_ip: Option<String>,
    pub node_attrs: Vec<String>,
}

/// Configured tailnet prefixes used to generate MagicDNS reverse-DNS
/// route roots. These become empty-resolver entries in
/// `DNSConfig.Routes`, matching headscale-go's "resolve this through
/// MagicDNS" representation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MagicDnsReversePrefixes {
    pub ipv4: Option<Ipv4Net>,
    pub ipv6: Option<Ipv6Net>,
}

/// Runtime store. Cheap to clone (every field is an `Arc`).
///
/// The store owns:
/// * the parsed [`DnsConfigSpec`],
/// * the most-recently-loaded `ExtraRecords` (swapped via
///   `notify_waiters` on every reload),
/// * a [`Notify`] that fans out to every parked `/map` long-poller.
///
/// `/map` long-pollers register a `notified()` future in their
/// `select!` loop next to the existing machine-registry / policy
/// notifies; an extra-records file edit wakes the same fan-out.
#[derive(Clone, Default)]
pub struct DnsStore {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    spec: RwLock<Arc<DnsConfigSpec>>,
    extra_records: RwLock<Arc<Vec<DnsRecord>>>,
    magic_dns_reverse_prefixes: RwLock<MagicDnsReversePrefixes>,
    /// Wakes parked `/map` long-pollers on extra-records edits.
    notify: Notify,
}

impl DnsStore {
    /// Construct an empty store. The default spec disables MagicDNS
    /// (matches the pre-MagicDNS wire shape) — embedders that want
    /// MagicDNS on call [`Self::from_spec`].
    pub fn new() -> Self {
        // Truly empty: MagicDNS off, base_domain empty, no
        // search_domains, no authoritative-suffix override. Building
        // a DnsConfig from this store produces `{}` byte-for-byte —
        // preserves the pre-MagicDNS wire shape.
        Self::from_spec(DnsConfigSpec {
            magic_dns: false,
            base_domain: String::new(),
            override_local_dns: true,
            nameservers: Vec::new(),
            nameserver_resolvers: Vec::new(),
            restricted_nameservers: HashMap::new(),
            restricted_resolvers: HashMap::new(),
            extra_records: Vec::new(),
            extra_records_path: None,
            search_domains: Vec::new(),
            fallback_nameservers: Vec::new(),
            fallback_resolvers: Vec::new(),
            cert_domains: Vec::new(),
            exit_node_filtered_set: Vec::new(),
            authoritative_suffixes: Some(Vec::new()),
        })
    }

    /// Construct from a parsed [`DnsConfigSpec`]. ExtraRecords start
    /// with the spec's inline records; the caller can either
    /// `set_extra_records` synchronously or
    /// `spawn_extra_records_watcher` to start the mtime poller for an
    /// external records file.
    pub fn from_spec(spec: DnsConfigSpec) -> Self {
        let extra_records = Arc::new(spec.extra_records.clone());
        Self {
            inner: Arc::new(Inner {
                spec: RwLock::new(Arc::new(spec)),
                extra_records: RwLock::new(extra_records),
                magic_dns_reverse_prefixes: RwLock::new(MagicDnsReversePrefixes::default()),
                notify: Notify::new(),
            }),
        }
    }

    /// Construct from a parsed [`DnsConfigSpec`] after applying
    /// headscale-go-compatible DNS validation.
    pub fn try_from_spec(spec: DnsConfigSpec) -> Result<Self, DnsConfigError> {
        spec.validate()?;
        Ok(Self::from_spec(spec))
    }

    /// Snapshot the current spec. Cheap (Arc clone).
    pub fn spec(&self) -> Arc<DnsConfigSpec> {
        self.inner.spec.read().clone()
    }

    /// Replace the spec at runtime (e.g. on a `SIGHUP`-driven config
    /// reload). Wakes every parked `/map` long-poller.
    pub fn set_spec(&self, spec: DnsConfigSpec) {
        let extra_records = Arc::new(spec.extra_records.clone());
        *self.inner.spec.write() = Arc::new(spec);
        *self.inner.extra_records.write() = extra_records;
        self.inner.notify.notify_waiters();
    }

    /// Snapshot the current extra-records list. Cheap (Arc clone).
    pub fn extra_records(&self) -> Arc<Vec<DnsRecord>> {
        self.inner.extra_records.read().clone()
    }

    /// Replace the configured tailnet prefixes used for MagicDNS
    /// reverse-DNS route roots. Wakes map streams because `Routes`
    /// changes in subsequent `DNSConfig` payloads.
    pub fn set_magic_dns_reverse_prefixes(&self, prefixes: MagicDnsReversePrefixes) {
        *self.inner.magic_dns_reverse_prefixes.write() = prefixes;
        self.inner.notify.notify_waiters();
    }

    /// Parse and set MagicDNS reverse-DNS prefixes from server config
    /// strings.
    pub fn set_magic_dns_reverse_prefixes_from_str(
        &self,
        ipv4: Option<&str>,
        ipv6: Option<&str>,
    ) -> Result<(), DnsConfigError> {
        let ipv4 = ipv4
            .filter(|value| !value.trim().is_empty())
            .map(str::parse::<Ipv4Net>)
            .transpose()
            .map_err(|_| DnsConfigError::InvalidMagicDnsIpv4Prefix)?;
        let ipv6 = ipv6
            .filter(|value| !value.trim().is_empty())
            .map(str::parse::<Ipv6Net>)
            .transpose()
            .map_err(|_| DnsConfigError::InvalidMagicDnsIpv6Prefix)?;
        self.set_magic_dns_reverse_prefixes(MagicDnsReversePrefixes { ipv4, ipv6 });
        Ok(())
    }

    pub fn magic_dns_reverse_prefixes(&self) -> MagicDnsReversePrefixes {
        self.inner.magic_dns_reverse_prefixes.read().clone()
    }

    /// Replace the extra-records list. Wakes every parked `/map`
    /// long-poller (so the next chunk carries the new entries). Used
    /// by both the synchronous test path and the file-watcher.
    pub fn set_extra_records(&self, records: Vec<DnsRecord>) {
        *self.inner.extra_records.write() = Arc::new(records);
        self.inner.notify.notify_waiters();
    }

    /// Wait for the next DnsStore change (extra-records edit OR
    /// spec swap). Used by the `/map` streaming select! loop next to
    /// the registry / policy notifies.
    pub async fn wait_for_change(&self) {
        self.inner.notify.notified().await;
    }

    /// Returns a notify handle. The returned `Arc` holds a strong ref
    /// to the underlying `Inner` so the notify never drops while a
    /// `/map` poller is parked on it.
    pub fn notify_handle(&self) -> DnsNotifyHandle {
        DnsNotifyHandle {
            inner: self.inner.clone(),
        }
    }

    /// Build the wire-shape [`DnsConfig`] from the live spec, the
    /// extra-records snapshot, and the current registry machine set.
    ///
    /// Pure function modulo the snapshots — no I/O. Called on every
    /// `MapResponse` rebuild.
    pub fn build(&self, _machines: &[MachineDnsRecord]) -> DnsConfig {
        let spec = self.spec();
        let extra = self.extra_records();
        let reverse_prefixes = self.magic_dns_reverse_prefixes();
        build_dns_config_with_reverse_prefixes(&spec, extra.as_slice(), &reverse_prefixes)
    }

    /// Build the wire-shape [`DnsConfig`] for a specific MapResponse
    /// requester. When `requester` is present, NextDNS resolver URLs
    /// are rewritten and annotated using the same nodeAttrs-driven
    /// rules as upstream headscale-go v0.29.
    pub fn build_for_requester(
        &self,
        machines: &[MachineDnsRecord],
        requester: Option<&DnsRequester>,
    ) -> DnsConfig {
        let mut config = self.build(machines);
        if let Some(requester) = requester {
            apply_nextdns_requester_config(&mut config, requester);
        }
        config
    }
}

/// Notify handle returned by [`DnsStore::notify_handle`].
pub struct DnsNotifyHandle {
    inner: Arc<Inner>,
}

impl DnsNotifyHandle {
    pub async fn changed(&self) {
        self.inner.notify.notified().await;
    }
}

impl std::fmt::Debug for DnsStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsStore")
            .field("spec", &*self.spec())
            .field("extra_records_count", &self.extra_records().len())
            .finish()
    }
}

/// Build a `DnsConfig` from the spec + machine list + extra records.
///
/// Decision table for each output field:
///
/// | Output                      | Source                                   |
/// |-----------------------------|------------------------------------------|
/// | `Resolvers`                 | `spec.nameservers` when `override_local_dns` is true |
/// | `Routes`                    | `spec.restricted_nameservers` (split DNS)|
/// | `FallbackResolvers`         | `spec.nameservers` when `override_local_dns` is false, plus `fallback_nameservers` |
/// | `Domains`                   | `[base_domain] ++ spec.search_domains` when base is set |
/// | `Proxied`                   | `spec.magic_dns && base_domain is set`    |
/// | `ExtraRecords`              | `extra` only (operator-supplied records) |
/// | `CertDomains`               | `spec.cert_domains` only                  |
/// | `ExitNodeFilteredSet`       | `spec.exit_node_filtered_set`             |
/// | `AuthoritativeSuffixes`     | `spec.authoritative_suffixes`, when explicitly set |
///
/// `Nameservers` is left empty by the runtime builder because it is
/// deprecated. `CertDomains` is not synthesized from the control-plane
/// HTTPS listener; only explicit config values are emitted.
pub fn build_dns_config(
    spec: &DnsConfigSpec,
    _machines: &[MachineDnsRecord],
    extra: &[DnsRecord],
) -> DnsConfig {
    build_dns_config_with_reverse_prefixes(spec, extra, &MagicDnsReversePrefixes::default())
}

fn build_dns_config_with_reverse_prefixes(
    spec: &DnsConfigSpec,
    extra: &[DnsRecord],
    reverse_prefixes: &MagicDnsReversePrefixes,
) -> DnsConfig {
    let base_domain = normalise_domain(&spec.base_domain);
    let base_domain_set = !base_domain.is_empty();
    let magic_dns_enabled = spec.magic_dns && base_domain_set;
    let global_resolvers = effective_global_resolvers(spec);
    let mut routes = effective_split_resolvers(spec);
    if magic_dns_enabled {
        for route in magic_dns_reverse_route_domains(reverse_prefixes) {
            routes.entry(route).or_default();
        }
    }
    let mut fallback_resolvers = Vec::new();
    if !spec.override_local_dns {
        fallback_resolvers.extend(global_resolvers.iter().cloned());
    }
    fallback_resolvers.extend(effective_fallback_resolvers(spec));
    let resolvers = if spec.override_local_dns {
        global_resolvers
    } else {
        Vec::new()
    };

    // Domains: the base_domain is always first — search-resolution
    // order matters to the daemon (it walks left-to-right). Operator-
    // supplied search_domains follow. An empty base_domain (e.g. the
    // `DnsStore::new()` empty-default) drops the leading entry so the
    // wire output is `{}` byte-for-byte.
    let mut domains = Vec::with_capacity(1 + spec.search_domains.len());
    if base_domain_set {
        domains.push(base_domain.clone());
    }
    for d in &spec.search_domains {
        let domain = normalise_domain(d);
        if !domain.is_empty() && domain != base_domain && !domains.contains(&domain) {
            domains.push(domain);
        }
    }

    let authoritative = spec
        .authoritative_suffixes
        .as_ref()
        .map_or_else(Vec::new, |suffixes| normalise_domain_list(suffixes));

    DnsConfig {
        resolvers,
        routes,
        fallback_resolvers,
        domains,
        proxied: magic_dns_enabled,
        nameservers: Vec::new(),
        cert_domains: normalise_domain_list(&spec.cert_domains),
        extra_records: extra.to_vec(),
        exit_node_filtered_set: spec.exit_node_filtered_set.clone(),
        temp_corp_issue_13969: String::new(),
        authoritative_suffixes: authoritative,
    }
}

pub fn magic_dns_reverse_route_domains(prefixes: &MagicDnsReversePrefixes) -> Vec<String> {
    let mut domains = Vec::new();
    if let Some(prefix) = prefixes.ipv4 {
        domains.extend(ipv4_reverse_route_domains(prefix));
    }
    if let Some(prefix) = prefixes.ipv6 {
        domains.extend(ipv6_reverse_route_domains(prefix));
    }
    domains
}

fn ipv4_reverse_route_domains(prefix: Ipv4Net) -> Vec<String> {
    let octets = prefix.network().octets();
    let prefix_len = prefix.prefix_len();
    if prefix_len >= 32 {
        return vec![format!(
            "{}.{}.{}.{}.in-addr.arpa",
            octets[3], octets[2], octets[1], octets[0]
        )];
    }

    let last_octet = usize::from(prefix_len / 8);
    let wildcard_bits = 8 - (prefix_len % 8);
    let min = u16::from(octets[last_octet]);
    let max = min + (1u16 << wildcard_bits) - 1;
    let base = octets[..last_octet]
        .iter()
        .rev()
        .map(u8::to_string)
        .chain(std::iter::once("in-addr.arpa".to_string()))
        .collect::<Vec<_>>()
        .join(".");

    (min..=max).map(|octet| format!("{octet}.{base}")).collect()
}

fn ipv6_reverse_route_domains(prefix: Ipv6Net) -> Vec<String> {
    let prefix_len = prefix.prefix_len();
    let mut expanded = String::with_capacity(32);
    for byte in prefix.network().octets() {
        use std::fmt::Write as _;
        write!(&mut expanded, "{byte:02x}").expect("writing to String cannot fail");
    }
    let constant_nibbles = usize::from(prefix_len / 4);
    let constant = expanded
        .as_bytes()
        .iter()
        .take(constant_nibbles)
        .rev()
        .map(|byte| char::from(*byte).to_string())
        .collect::<Vec<_>>();

    let domain_for = |variable: Option<String>| {
        let mut labels = Vec::new();
        if let Some(variable) = variable {
            labels.push(variable);
        }
        labels.extend(constant.clone());
        labels.push("ip6".to_string());
        labels.push("arpa".to_string());
        labels.join(".")
    };

    let remainder = prefix_len % 4;
    if remainder == 0 {
        vec![domain_for(None)]
    } else {
        let count = 1u8 << remainder;
        (0..count)
            .map(|nibble| domain_for(Some(format!("{nibble:x}"))))
            .collect()
    }
}

pub fn try_build_dns_config(
    spec: &DnsConfigSpec,
    machines: &[MachineDnsRecord],
    extra: &[DnsRecord],
) -> Result<DnsConfig, DnsConfigError> {
    spec.validate()?;
    Ok(build_dns_config(spec, machines, extra))
}

pub fn apply_nextdns_requester_config(config: &mut DnsConfig, requester: &DnsRequester) {
    if let Some(profile) = nextdns_profile_from_attrs(&requester.node_attrs) {
        apply_nextdns_profile(&mut config.resolvers, &profile);
        apply_nextdns_profile(&mut config.fallback_resolvers, &profile);
        for resolvers in config.routes.values_mut() {
            apply_nextdns_profile(resolvers, &profile);
        }
    }

    if requester
        .node_attrs
        .iter()
        .any(|attr| attr == NEXTDNS_ATTR_NO_DEVICE_INFO)
    {
        return;
    }

    add_nextdns_metadata(&mut config.resolvers, requester);
    add_nextdns_metadata(&mut config.fallback_resolvers, requester);
    for resolvers in config.routes.values_mut() {
        add_nextdns_metadata(resolvers, requester);
    }
}

fn nextdns_profile_from_attrs(attrs: &[String]) -> Option<String> {
    let mut candidates = attrs
        .iter()
        .filter_map(|attr| {
            let profile = attr.strip_prefix(NEXTDNS_ATTR_PREFIX)?;
            if profile.is_empty()
                || attr == NEXTDNS_ATTR_NO_DEVICE_INFO
                || !valid_nextdns_profile(profile)
            {
                return None;
            }
            Some(profile.to_string())
        })
        .collect::<Vec<_>>();

    candidates.sort();
    candidates.into_iter().next()
}

fn valid_nextdns_profile(profile: &str) -> bool {
    !profile.is_empty()
        && profile.len() <= 64
        && profile
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn is_nextdns_doh_addr(addr: &str) -> bool {
    addr == NEXTDNS_DOH_PREFIX
        || addr
            .strip_prefix(NEXTDNS_DOH_PREFIX)
            .is_some_and(|rest| rest.starts_with('/') || rest.starts_with('?'))
}

fn apply_nextdns_profile(resolvers: &mut [DnsResolver], profile: &str) {
    for resolver in resolvers {
        if is_nextdns_doh_addr(&resolver.addr) {
            resolver.addr = format!("{NEXTDNS_DOH_PREFIX}/{profile}");
        }
    }
}

fn add_nextdns_metadata(resolvers: &mut [DnsResolver], requester: &DnsRequester) {
    for resolver in resolvers {
        if is_nextdns_doh_addr(&resolver.addr) {
            resolver.addr = add_nextdns_metadata_to_addr(&resolver.addr, requester);
        }
    }
}

fn add_nextdns_metadata_to_addr(addr: &str, requester: &DnsRequester) -> String {
    let (without_fragment, fragment) = split_once(addr, '#');
    let (base, query) = split_once(without_fragment, '?');
    let mut params = parse_query(query.unwrap_or_default());
    params.insert("device_name".to_string(), vec![requester.hostname.clone()]);
    params.insert("device_model".to_string(), vec![requester.os.clone()]);
    if let Some(ip) = requester.primary_ip.as_ref() {
        params.insert("device_ip".to_string(), vec![ip.clone()]);
    }

    let query = encode_query(&params);
    let mut out = if query.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{query}")
    };
    if let Some(fragment) = fragment {
        out.push('#');
        out.push_str(fragment);
    }
    out
}

fn split_once(input: &str, delimiter: char) -> (&str, Option<&str>) {
    input
        .split_once(delimiter)
        .map_or((input, None), |(left, right)| (left, Some(right)))
}

fn parse_query(query: &str) -> BTreeMap<String, Vec<String>> {
    let mut params = BTreeMap::new();
    for part in query.split('&').filter(|part| !part.is_empty()) {
        let (key, value) = split_once(part, '=');
        params
            .entry(percent_decode_query(key))
            .or_insert_with(Vec::new)
            .push(percent_decode_query(value.unwrap_or_default()));
    }
    params
}

fn percent_decode_query(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = hex_value(bytes[i + 1]);
                let lo = hex_value(bytes[i + 2]);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn encode_query(params: &BTreeMap<String, Vec<String>>) -> String {
    params
        .iter()
        .flat_map(|(key, values)| {
            values.iter().map(move |value| {
                format!(
                    "{}={}",
                    percent_encode_query(key),
                    percent_encode_query(value)
                )
            })
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn percent_encode_query(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.push('%');
                out.push(HEX[(byte >> 4) as usize] as char);
                out.push(HEX[(byte & 0x0f) as usize] as char);
            }
        }
    }
    out
}

fn resolver_from_addr(s: &str) -> DnsResolver {
    DnsResolver {
        addr: s.to_string(),
        bootstrap_resolution: Vec::new(),
        use_with_exit_node: false,
    }
}

fn effective_global_resolvers(spec: &DnsConfigSpec) -> Vec<DnsResolver> {
    if spec.nameserver_resolvers.is_empty() {
        spec.nameservers
            .iter()
            .map(|addr| resolver_from_addr(addr))
            .collect()
    } else {
        spec.nameserver_resolvers.clone()
    }
}

fn effective_fallback_resolvers(spec: &DnsConfigSpec) -> Vec<DnsResolver> {
    if spec.fallback_resolvers.is_empty() {
        spec.fallback_nameservers
            .iter()
            .map(|addr| resolver_from_addr(addr))
            .collect()
    } else {
        spec.fallback_resolvers.clone()
    }
}

fn effective_split_resolvers(spec: &DnsConfigSpec) -> HashMap<String, Vec<DnsResolver>> {
    let mut keys = std::collections::BTreeSet::new();
    keys.extend(spec.restricted_nameservers.keys());
    keys.extend(spec.restricted_resolvers.keys());

    let mut routes = HashMap::new();
    for suffix in keys {
        let normalised_suffix = normalise_domain(suffix);
        if normalised_suffix.is_empty() {
            continue;
        }
        let resolvers = spec
            .restricted_resolvers
            .get(suffix)
            .cloned()
            .unwrap_or_else(|| {
                spec.restricted_nameservers
                    .get(suffix)
                    .into_iter()
                    .flatten()
                    .map(|addr| resolver_from_addr(addr))
                    .collect()
            });
        routes.insert(normalised_suffix, resolvers);
    }
    routes
}

pub fn normalise_domain(input: &str) -> String {
    input.trim().trim_matches('.').to_ascii_lowercase()
}

fn normalise_domain_list(input: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(input.len());
    for suffix in input {
        let suffix = normalise_domain(suffix);
        if !suffix.is_empty() && seen.insert(suffix.clone()) {
            out.push(suffix);
        }
    }
    out
}

/// Generate the per-machine A/AAAA records that make `ssh peer-1` work.
///
/// This helper is retained for compatibility with embedders that used
/// the old synthetic-record API. Runtime `DNSConfig` parity with
/// headscale-go does not use it; peer MagicDNS names come from
/// `MapNode.Name` and `MapResponse.Domain`.
///
/// Each record is `<hostname>.<base_domain>` to node addresses. The
/// hostname is normalised (lowercased, ASCII-only, dot-stripped) so
/// DNS labels stay legal even if the client advertised a quirky name.
///
/// Collision handling: if N machines advertise the same normalised
/// hostname, the first (lowest node-id) keeps the canonical name and
/// the rest get a `-n{id}` suffix. Sorting by `node_id` gives a
/// stable, reproducible ordering across rebuilds.
pub fn magic_dns_records(base_domain: &str, machines: &[MachineDnsRecord]) -> Vec<DnsRecord> {
    let base_domain = normalise_domain(base_domain);
    if base_domain.is_empty() {
        return Vec::new();
    }

    // Walk in node-id order so collision suffixes are deterministic.
    let mut sorted: Vec<&MachineDnsRecord> = machines.iter().collect();
    sorted.sort_by_key(|m| m.node_id);

    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::with_capacity(sorted.len() * 2);
    for m in sorted {
        let normalised = normalise_hostname(&m.hostname);
        let label = if normalised.is_empty() {
            // Hostname is empty after normalisation (e.g. all symbols).
            // Use `n{id}` as the label so the record still lands.
            seen.insert(format!("n{}", m.node_id));
            format!("n{}", m.node_id)
        } else if seen.contains(&normalised) {
            collision_label(&normalised, m.node_id)
        } else {
            normalised.clone()
        };
        seen.insert(label.clone());
        let name = format!("{label}.{base_domain}");
        if let Some(ipv4) = m.ipv4 {
            out.push(DnsRecord {
                name: name.clone(),
                record_type: "A".into(),
                value: ipv4.to_string(),
            });
        }
        if let Some(ipv6) = m.ipv6 {
            out.push(DnsRecord {
                name,
                record_type: "AAAA".into(),
                value: ipv6.to_string(),
            });
        }
    }
    out
}

fn collision_label(base: &str, node_id: u64) -> String {
    let suffix = format!("-n{node_id}");
    let max_base_len = 63usize.saturating_sub(suffix.len());
    let mut base = base.chars().take(max_base_len).collect::<String>();
    while base.ends_with('-') {
        base.pop();
    }
    if base.is_empty() {
        format!("n{node_id}")
    } else {
        format!("{base}{suffix}")
    }
}

/// Reduce an arbitrary hostname to a single DNS label. Lowercases,
/// keeps only `[a-z0-9-]`, and trims leading/trailing hyphens. Spaces
/// and dots collapse to `-`.
///
/// Returns `""` if nothing survives normalisation — the caller falls
/// back to `n{node_id}`.
pub fn normalise_hostname(input: &str) -> String {
    let mut s = String::with_capacity(input.len());
    let mut last_was_dash = false;
    for ch in input.chars() {
        let mapped = match ch {
            'a'..='z' | '0'..='9' | '-' => Some(ch),
            'A'..='Z' => Some(ch.to_ascii_lowercase()),
            // Internal separators collapse to `-`.
            '.' | ' ' | '_' => Some('-'),
            _ => None,
        };
        if let Some(m) = mapped {
            if m == '-' {
                if last_was_dash || s.is_empty() {
                    continue;
                }
                last_was_dash = true;
            } else {
                last_was_dash = false;
            }
            s.push(m);
        }
    }
    while s.ends_with('-') {
        s.pop();
    }
    if s.len() > 63 {
        s.truncate(63);
        while s.ends_with('-') {
            s.pop();
        }
    }
    s
}

/// Parse an extra-records JSON file. The file is a top-level array of
/// `{name, type, value}` records — same shape upstream
/// `juanfont/headscale` accepts. Empty file ⇒ empty record list for
/// startup validation; hot reload treats empty reads as transient and
/// keeps the previous record set.
///
/// The file format intentionally accepts both `type` (canonical) and
/// `Type` (PascalCase) as the type-field key, because operators tend
/// to copy paste from tailcfg dumps which use PascalCase. We match by
/// custom deserialisation through the `ExtraRecordsFile` wrapper.
pub fn parse_extra_records(bytes: &[u8]) -> Result<Vec<DnsRecord>, serde_json::Error> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    // Accept both lowercase and PascalCase keys via the same
    // permissive wrapper used for config-file inline extra records.
    let loose: Vec<LooseDnsRecord> = serde_json::from_slice(bytes)?;
    Ok(loose.into_iter().map(Into::into).collect())
}

/// Spawn a background task that polls the extra-records file's
/// `mtime` and replaces the store's record list whenever it changes.
///
/// Returns immediately; the watcher runs until the returned join
/// handle is dropped (or aborted). On parse errors we leave the
/// previous record set in place and log a warning — operators get a
/// clear signal that their edit didn't land, but the running tailnet
/// keeps the previous MagicDNS state.
///
/// `interval` defaults to [`EXTRA_RECORDS_POLL_INTERVAL`] when
/// `None` is passed.
pub fn spawn_extra_records_watcher(
    store: DnsStore,
    path: PathBuf,
    interval: Option<Duration>,
) -> tokio::task::JoinHandle<()> {
    let poll = interval.unwrap_or(EXTRA_RECORDS_POLL_INTERVAL);
    tokio::spawn(async move {
        let mut last_mtime: Option<SystemTime> = None;
        let mut last_fingerprint: Option<u64> = None;
        // Best-effort: load the file once at start so the initial
        // `/map` response carries the operator's records without
        // waiting one poll-interval.
        if let Some(load) = load_and_apply(&store, &path, true, None).await {
            last_mtime = Some(load.mtime);
            last_fingerprint = load.fingerprint;
        }
        loop {
            tokio::time::sleep(poll).await;
            match tokio::fs::metadata(&path).await {
                Ok(meta) => match meta.modified() {
                    Ok(m) if Some(m) != last_mtime => {
                        if let Some(load) =
                            load_and_apply(&store, &path, false, last_fingerprint).await
                        {
                            last_mtime = Some(load.mtime);
                            last_fingerprint = load.fingerprint;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!(?path, ?e, "extra-records mtime read failed"),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Match headscale-go's ExtraRecordsMan: remove/
                    // rename events do not clear the live record set.
                    // The manager keeps serving the last good records
                    // while it waits for the file to reappear.
                    if last_mtime.take().is_some() {
                        tracing::warn!(
                            ?path,
                            "extra-records file disappeared; keeping previous set"
                        );
                    }
                }
                Err(e) => tracing::warn!(?path, ?e, "extra-records stat failed"),
            }
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExtraRecordsLoad {
    mtime: SystemTime,
    fingerprint: Option<u64>,
}

async fn load_and_apply(
    store: &DnsStore,
    path: &Path,
    apply_empty: bool,
    previous_fingerprint: Option<u64>,
) -> Option<ExtraRecordsLoad> {
    let bytes = match tokio::fs::read(path).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(?path, ?e, "extra-records read failed");
            return None;
        }
    };
    let meta = tokio::fs::metadata(path).await.ok()?;
    let mtime = meta.modified().ok()?;
    if !apply_empty && bytes.iter().all(u8::is_ascii_whitespace) {
        tracing::warn!(
            ?path,
            "extra-records reload read empty file; keeping previous set"
        );
        return Some(ExtraRecordsLoad {
            mtime,
            fingerprint: previous_fingerprint,
        });
    }
    let fingerprint = Some(extra_records_fingerprint(&bytes));
    if !apply_empty && fingerprint == previous_fingerprint {
        return Some(ExtraRecordsLoad { mtime, fingerprint });
    }
    match parse_extra_records(&bytes) {
        Ok(records) => {
            store.set_extra_records(records);
            Some(ExtraRecordsLoad { mtime, fingerprint })
        }
        Err(e) => {
            tracing::warn!(
                ?path,
                ?e,
                "extra-records parse failed; keeping previous set"
            );
            None
        }
    }
}

fn extra_records_fingerprint(bytes: &[u8]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine(host: &str, last: u8, id: u64) -> MachineDnsRecord {
        MachineDnsRecord {
            hostname: host.into(),
            ipv4: Some(Ipv4Addr::new(100, 64, 0, last)),
            ipv6: None,
            node_id: id,
        }
    }

    fn magic_spec() -> DnsConfigSpec {
        DnsConfigSpec {
            base_domain: "headscale.test".into(),
            override_local_dns: false,
            ..DnsConfigSpec::default()
        }
    }

    fn record(name: &str, record_type: &str, value: &str) -> DnsRecord {
        DnsRecord {
            name: name.into(),
            record_type: record_type.into(),
            value: value.into(),
        }
    }

    fn nextdns_requester(attrs: &[&str]) -> DnsRequester {
        DnsRequester {
            hostname: "node1".into(),
            os: "linux".into(),
            primary_ip: Some("100.64.0.1".into()),
            node_attrs: attrs.iter().map(|attr| (*attr).to_string()).collect(),
        }
    }

    #[test]
    fn default_spec_matches_headscale_go_dns_defaults() {
        let s = DnsConfigSpec::default();
        assert!(s.magic_dns);
        assert_eq!(s.base_domain, "");
        assert!(s.override_local_dns);
        assert!(s.nameservers.is_empty());
    }

    #[test]
    fn default_spec_requires_base_domain_before_runtime_use() {
        assert_eq!(
            DnsConfigSpec::default().validate(),
            Err(DnsConfigError::MissingBaseDomainForMagicDns)
        );
        assert!(DnsStore::try_from_spec(DnsConfigSpec::default()).is_err());
    }

    #[test]
    fn override_local_dns_requires_global_nameservers() {
        let spec = DnsConfigSpec {
            magic_dns: false,
            override_local_dns: true,
            nameservers: Vec::new(),
            ..DnsConfigSpec::default()
        };

        assert_eq!(
            spec.validate(),
            Err(DnsConfigError::MissingGlobalNameserversForOverride)
        );
    }

    #[test]
    fn empty_store_emits_no_proxied_no_records() {
        let store = DnsStore::new();
        let cfg = store.build(&[]);
        assert!(!cfg.proxied);
        assert!(cfg.extra_records.is_empty());
    }

    #[test]
    fn invalid_magic_dns_spec_is_safe_if_validation_is_bypassed() {
        let cfg = DnsStore::from_spec(DnsConfigSpec::default()).build(&[machine("peer", 1, 1)]);
        assert!(!cfg.proxied);
        assert!(cfg.domains.is_empty());
        assert!(cfg.extra_records.is_empty());
    }

    #[test]
    fn store_from_spec_emits_proxied_and_base_domain_search() {
        let store = DnsStore::try_from_spec(magic_spec()).expect("valid dns spec");
        let cfg = store.build(&[]);
        assert!(cfg.proxied);
        assert_eq!(cfg.domains, vec!["headscale.test".to_string()]);
        assert!(cfg.authoritative_suffixes.is_empty());
    }

    #[test]
    fn dnsconfig_extra_records_are_operator_supplied_only() {
        let machines = [machine("peer-1", 11, 1), machine("peer-2", 22, 2)];
        let store = DnsStore::from_spec(magic_spec());
        store.set_extra_records(vec![record("ops.headscale.test", "A", "100.64.0.50")]);
        let cfg = store.build(&machines);

        assert_eq!(
            cfg.extra_records,
            vec![record("ops.headscale.test", "A", "100.64.0.50")]
        );
        assert!(
            !cfg.extra_records
                .iter()
                .any(|r| r.name.starts_with("peer-"))
        );
    }

    #[test]
    fn nextdns_metadata_is_added_for_requester() {
        let spec = DnsConfigSpec {
            magic_dns: false,
            override_local_dns: true,
            nameservers: vec!["https://dns.nextdns.io/abc?existing=1&existing=2".into()],
            ..DnsConfigSpec::default()
        };
        let store = DnsStore::from_spec(spec);
        let cfg = store.build_for_requester(&[], Some(&nextdns_requester(&[])));

        assert_eq!(
            cfg.resolvers[0].addr,
            "https://dns.nextdns.io/abc?device_ip=100.64.0.1&device_model=linux&device_name=node1&existing=1&existing=2"
        );
    }

    #[test]
    fn nextdns_profile_rewrites_all_resolver_sets_and_can_suppress_metadata() {
        let mut restricted = HashMap::new();
        restricted.insert(
            "corp.example".to_string(),
            vec!["https://dns.nextdns.io/split".to_string()],
        );
        let spec = DnsConfigSpec {
            magic_dns: false,
            override_local_dns: true,
            nameservers: vec!["https://dns.nextdns.io/global".into()],
            fallback_nameservers: vec!["https://dns.nextdns.io/fallback".into()],
            restricted_nameservers: restricted,
            ..DnsConfigSpec::default()
        };
        let store = DnsStore::from_spec(spec);
        let requester = nextdns_requester(&[
            "nextdns:z-profile",
            "nextdns:a-profile",
            "nextdns:no-device-info",
        ]);
        let cfg = store.build_for_requester(&[], Some(&requester));

        assert_eq!(cfg.resolvers[0].addr, "https://dns.nextdns.io/a-profile");
        assert_eq!(
            cfg.fallback_resolvers[0].addr,
            "https://dns.nextdns.io/a-profile"
        );
        assert_eq!(
            cfg.routes["corp.example"][0].addr,
            "https://dns.nextdns.io/a-profile"
        );
    }

    #[test]
    fn nextdns_invalid_profiles_and_non_nextdns_resolvers_are_ignored() {
        let spec = DnsConfigSpec {
            magic_dns: false,
            override_local_dns: true,
            nameservers: vec![
                "https://dns.nextdns.io/global".into(),
                "https://dns.nextdns.io.attacker.example/global".into(),
            ],
            ..DnsConfigSpec::default()
        };
        let store = DnsStore::from_spec(spec);
        let requester = nextdns_requester(&["nextdns:bad/profile"]);
        let cfg = store.build_for_requester(&[], Some(&requester));

        assert!(cfg.resolvers[0].addr.starts_with(
            "https://dns.nextdns.io/global?device_ip=100.64.0.1&device_model=linux&device_name=node1"
        ));
        assert_eq!(
            cfg.resolvers[1].addr,
            "https://dns.nextdns.io.attacker.example/global"
        );
    }

    #[test]
    fn synthetic_magic_dns_record_helper_emits_per_machine_a_records() {
        let machines = [machine("peer-1", 11, 1), machine("peer-2", 22, 2)];
        let records = magic_dns_records("headscale.test", &machines);
        assert_eq!(records.len(), 2);
        assert!(records.contains(&record("peer-1.headscale.test", "A", "100.64.0.11")));
        assert!(records.contains(&record("peer-2.headscale.test", "A", "100.64.0.22")));
    }

    #[test]
    fn synthetic_magic_dns_record_helper_emits_aaaa_for_ipv6_only_machine() {
        let machines = [MachineDnsRecord {
            hostname: "v6-only".into(),
            ipv4: None,
            ipv6: Some("fd7a:115c:a1e0::66".parse().unwrap()),
            node_id: 66,
        }];

        let records = magic_dns_records("headscale.test", &machines);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "v6-only.headscale.test");
        assert_eq!(records[0].record_type, "AAAA");
        assert_eq!(records[0].value, "fd7a:115c:a1e0::66");
    }

    #[test]
    fn synthetic_magic_dns_record_helper_follows_prefix_family_presence() {
        let machines = [
            MachineDnsRecord {
                hostname: "v4-only".into(),
                ipv4: Some(Ipv4Addr::new(100, 64, 0, 4)),
                ipv6: None,
                node_id: 4,
            },
            MachineDnsRecord {
                hostname: "v6-only".into(),
                ipv4: None,
                ipv6: Some("fd7a:115c:a1e0::6".parse().unwrap()),
                node_id: 6,
            },
            MachineDnsRecord {
                hostname: "dual".into(),
                ipv4: Some(Ipv4Addr::new(100, 64, 0, 46)),
                ipv6: Some("fd7a:115c:a1e0::46".parse().unwrap()),
                node_id: 46,
            },
        ];

        let records = magic_dns_records("headscale.test", &machines);

        assert!(records.contains(&record("v4-only.headscale.test", "A", "100.64.0.4",)));
        assert!(records.contains(&record(
            "v6-only.headscale.test",
            "AAAA",
            "fd7a:115c:a1e0::6",
        )));
        assert!(records.contains(&record("dual.headscale.test", "A", "100.64.0.46")));
        assert!(records.contains(&record("dual.headscale.test", "AAAA", "fd7a:115c:a1e0::46",)));
        assert!(
            !records
                .iter()
                .any(|r| r.name == "v4-only.headscale.test" && r.record_type == "AAAA")
        );
        assert!(
            !records
                .iter()
                .any(|r| r.name == "v6-only.headscale.test" && r.record_type == "A")
        );
    }

    #[test]
    fn hostname_collision_lowest_node_id_keeps_canonical_name() {
        let machines = [
            machine("dup", 11, 42), // higher id ⇒ collision-suffixed
            machine("dup", 22, 7),  // lower id ⇒ keeps canonical name
        ];
        let names: Vec<String> = magic_dns_records("headscale.test", &machines)
            .iter()
            .map(|r| r.name.clone())
            .collect();
        assert!(names.contains(&"dup.headscale.test".to_string()));
        assert!(names.contains(&"dup-n42.headscale.test".to_string()));
    }

    #[test]
    fn three_way_collision_suffixes_with_node_id() {
        let machines = [
            machine("dup", 11, 100),
            machine("dup", 22, 200),
            machine("dup", 33, 50),
        ];
        let names: Vec<String> = magic_dns_records("headscale.test", &machines)
            .iter()
            .map(|r| r.name.clone())
            .collect();
        assert!(names.contains(&"dup.headscale.test".to_string()));
        assert!(names.contains(&"dup-n100.headscale.test".to_string()));
        assert!(names.contains(&"dup-n200.headscale.test".to_string()));
    }

    #[test]
    fn hostname_normalisation_lowercases_and_strips_symbols() {
        assert_eq!(normalise_hostname("Peer.One!"), "peer-one");
        assert_eq!(normalise_hostname("HOST_NAME"), "host-name");
        assert_eq!(normalise_hostname("---a---"), "a");
        assert_eq!(normalise_hostname(""), "");
        assert_eq!(normalise_hostname("!!!"), "");
    }

    #[test]
    fn hostname_normalisation_caps_dns_label_length_before_collision_suffix() {
        let long = "node".repeat(20);
        assert_eq!(normalise_hostname(&long).len(), 63);

        let machines = [
            MachineDnsRecord {
                hostname: long.clone(),
                ipv4: Some(Ipv4Addr::new(100, 64, 0, 1)),
                ipv6: None,
                node_id: 1,
            },
            MachineDnsRecord {
                hostname: long,
                ipv4: Some(Ipv4Addr::new(100, 64, 0, 2)),
                ipv6: None,
                node_id: 2,
            },
        ];
        let collision = magic_dns_records("headscale.test", &machines)
            .into_iter()
            .find(|record| record.value == "100.64.0.2")
            .expect("collision record")
            .name
            .split('.')
            .next()
            .unwrap()
            .to_string();
        assert!(collision.ends_with("-n2"));
        assert!(collision.len() <= 63);
    }

    #[test]
    fn empty_hostname_falls_back_to_node_id_label() {
        let machines = [MachineDnsRecord {
            hostname: "!!!".into(),
            ipv4: Some(Ipv4Addr::new(100, 64, 0, 9)),
            ipv6: None,
            node_id: 99,
        }];
        let records = magic_dns_records("headscale.test", &machines);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "n99.headscale.test");
    }

    #[test]
    fn split_dns_routes_serialised_per_suffix() {
        let mut restricted = HashMap::new();
        restricted.insert(
            "corp.internal".to_string(),
            vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()],
        );
        let spec = DnsConfigSpec {
            restricted_nameservers: restricted,
            ..magic_spec()
        };
        let cfg = DnsStore::from_spec(spec).build(&[]);
        let route = cfg.routes.get("corp.internal").expect("route present");
        assert_eq!(route.len(), 2);
        assert_eq!(route[0].addr, "10.0.0.1");
        assert_eq!(route[1].addr, "10.0.0.2");
    }

    #[test]
    fn magic_dns_reverse_routes_are_added_for_configured_prefixes() {
        let mut restricted = HashMap::new();
        restricted.insert("corp.internal".to_string(), vec!["10.0.0.53".to_string()]);
        let store = DnsStore::from_spec(DnsConfigSpec {
            restricted_nameservers: restricted,
            ..magic_spec()
        });
        store
            .set_magic_dns_reverse_prefixes_from_str(
                Some("100.64.0.0/10"),
                Some("fd7a:115c:a1e0::/48"),
            )
            .unwrap();

        let cfg = store.build(&[]);

        assert_eq!(cfg.routes["corp.internal"][0].addr, "10.0.0.53");
        assert!(cfg.routes["64.100.in-addr.arpa"].is_empty());
        assert!(cfg.routes["100.100.in-addr.arpa"].is_empty());
        assert!(cfg.routes["127.100.in-addr.arpa"].is_empty());
        assert!(cfg.routes["0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa"].is_empty());
    }

    #[test]
    fn magic_dns_reverse_routes_follow_upstream_prefix_generation() {
        let v4 = "172.16.0.0/16".parse().unwrap();
        let v6 = "fd7a:115c:a1e0::/50".parse().unwrap();
        let domains = magic_dns_reverse_route_domains(&MagicDnsReversePrefixes {
            ipv4: Some(v4),
            ipv6: Some(v6),
        });

        assert!(domains.contains(&"0.16.172.in-addr.arpa".to_string()));
        assert!(domains.contains(&"255.16.172.in-addr.arpa".to_string()));
        assert!(domains.contains(&"0.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa".to_string()));
        assert!(domains.contains(&"1.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa".to_string()));
        assert!(domains.contains(&"2.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa".to_string()));
        assert!(domains.contains(&"3.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa".to_string()));
    }

    #[test]
    fn magic_dns_reverse_routes_require_proxied_magic_dns() {
        let store = DnsStore::from_spec(DnsConfigSpec {
            magic_dns: false,
            ..magic_spec()
        });
        store
            .set_magic_dns_reverse_prefixes_from_str(Some("100.64.0.0/10"), None)
            .unwrap();

        let cfg = store.build(&[]);

        assert!(cfg.routes.is_empty());
        assert!(!cfg.proxied);
    }

    #[test]
    fn authoritative_suffixes_default_empty_for_headscale_go_wire_parity() {
        let mut restricted = HashMap::new();
        restricted.insert("corp.internal".to_string(), vec!["10.0.0.1".to_string()]);
        restricted.insert("ops.internal".to_string(), vec!["10.0.0.2".to_string()]);
        let spec = DnsConfigSpec {
            restricted_nameservers: restricted,
            ..magic_spec()
        };
        let cfg = DnsStore::from_spec(spec).build(&[]);
        assert!(cfg.authoritative_suffixes.is_empty());
    }

    #[test]
    fn authoritative_suffixes_override_is_emitted() {
        let spec = DnsConfigSpec {
            authoritative_suffixes: Some(vec!["only.this".to_string()]),
            ..magic_spec()
        };
        let cfg = DnsStore::from_spec(spec).build(&[]);
        assert_eq!(cfg.authoritative_suffixes, vec!["only.this".to_string()]);
    }

    #[test]
    fn parse_extra_records_accepts_lowercase_keys() {
        let body = br#"[{"name":"foo.example.org","type":"A","value":"1.2.3.4"}]"#;
        let recs = parse_extra_records(body).expect("parses");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].name, "foo.example.org");
        assert_eq!(recs[0].record_type, "A");
        assert_eq!(recs[0].value, "1.2.3.4");
    }

    #[test]
    fn parse_extra_records_accepts_pascalcase_keys() {
        let body = br#"[{"Name":"foo.example.org","Type":"CNAME","Value":"bar.example.org"}]"#;
        let recs = parse_extra_records(body).expect("parses");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].name, "foo.example.org");
        assert_eq!(recs[0].record_type, "CNAME");
        assert_eq!(recs[0].value, "bar.example.org");
    }

    #[test]
    fn parse_extra_records_preserves_aaaa_and_cname_records() {
        let body = br#"[
          {"Name":"v6.example.org","Type":"AAAA","Value":"fd7a:115c:a1e0::53"},
          {"Name":"alias.example.org","Type":"CNAME","Value":"v6.example.org"}
        ]"#;

        let recs = parse_extra_records(body).expect("parses");

        assert_eq!(
            recs,
            vec![
                record("v6.example.org", "AAAA", "fd7a:115c:a1e0::53"),
                record("alias.example.org", "CNAME", "v6.example.org"),
            ]
        );
    }

    #[test]
    fn parse_extra_records_empty_and_whitespace_ok() {
        assert!(parse_extra_records(b"").unwrap().is_empty());
        assert!(parse_extra_records(b"  \n\t ").unwrap().is_empty());
        assert!(parse_extra_records(b"[]").unwrap().is_empty());
    }

    #[test]
    fn parse_extra_records_omits_type_default() {
        // Missing `type` ⇒ empty string (matches upstream `omitzero`).
        let body = br#"[{"name":"foo","value":"1.2.3.4"}]"#;
        let recs = parse_extra_records(body).expect("parses");
        assert_eq!(recs[0].record_type, "");
    }

    #[test]
    fn parse_extra_records_invalid_json_errors() {
        assert!(parse_extra_records(b"not json").is_err());
        assert!(parse_extra_records(b"{not array}").is_err());
    }

    #[test]
    fn extra_records_land_in_dnsconfig() {
        let store = DnsStore::from_spec(magic_spec());
        store.set_extra_records(vec![DnsRecord {
            name: "static.example.org".into(),
            record_type: "A".into(),
            value: "9.9.9.9".into(),
        }]);
        let cfg = store.build(&[]);
        assert!(
            cfg.extra_records
                .iter()
                .any(|r| r.name == "static.example.org" && r.value == "9.9.9.9")
        );
    }

    #[test]
    fn inline_extra_records_seed_dnsstore() {
        let spec = DnsConfigSpec {
            extra_records: vec![DnsRecord {
                name: "inline.example.org".into(),
                record_type: "A".into(),
                value: "100.64.0.99".into(),
            }],
            ..magic_spec()
        };
        let cfg = DnsStore::from_spec(spec).build(&[]);
        assert!(
            cfg.extra_records
                .iter()
                .any(|r| r.name == "inline.example.org" && r.value == "100.64.0.99")
        );
    }

    #[test]
    fn nameservers_become_resolvers_in_wire_shape() {
        let spec = DnsConfigSpec {
            override_local_dns: true,
            nameservers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            ..magic_spec()
        };
        let cfg = DnsStore::from_spec(spec).build(&[]);
        assert_eq!(cfg.resolvers.len(), 2);
        assert_eq!(cfg.resolvers[0].addr, "1.1.1.1");
        assert_eq!(cfg.resolvers[1].addr, "8.8.8.8");
        // None of these should set `use_with_exit_node` by default.
        assert!(!cfg.resolvers[0].use_with_exit_node);
    }

    #[test]
    fn override_local_dns_false_moves_global_resolvers_to_fallbacks() {
        let spec = DnsConfigSpec {
            override_local_dns: false,
            nameservers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            ..magic_spec()
        };

        let cfg = DnsStore::from_spec(spec).build(&[]);

        assert!(cfg.resolvers.is_empty());
        assert_eq!(cfg.fallback_resolvers.len(), 2);
        assert_eq!(cfg.fallback_resolvers[0].addr, "1.1.1.1");
        assert_eq!(cfg.fallback_resolvers[1].addr, "8.8.8.8");
    }

    #[test]
    fn fallback_resolvers_populated() {
        let spec = DnsConfigSpec {
            fallback_nameservers: vec!["9.9.9.9".to_string()],
            ..magic_spec()
        };
        let cfg = DnsStore::from_spec(spec).build(&[]);
        assert_eq!(cfg.fallback_resolvers.len(), 1);
        assert_eq!(cfg.fallback_resolvers[0].addr, "9.9.9.9");
    }

    #[test]
    fn exit_node_filtered_set_propagates() {
        let spec = DnsConfigSpec {
            exit_node_filtered_set: vec!["bank.example".to_string()],
            ..magic_spec()
        };
        let cfg = DnsStore::from_spec(spec).build(&[]);
        assert_eq!(cfg.exit_node_filtered_set, vec!["bank.example".to_string()]);
    }

    #[test]
    fn magic_dns_disabled_emits_no_proxied_no_authoritative_default() {
        let spec = DnsConfigSpec {
            magic_dns: false,
            ..magic_spec()
        };
        let cfg = DnsStore::from_spec(spec).build(&[]);
        assert!(!cfg.proxied);
        assert!(cfg.authoritative_suffixes.is_empty());
    }

    #[test]
    fn search_domains_appended_after_base_domain() {
        let spec = DnsConfigSpec {
            search_domains: vec!["aux.example.org".to_string()],
            ..magic_spec()
        };
        let cfg = DnsStore::from_spec(spec).build(&[]);
        assert_eq!(cfg.domains.len(), 2);
        assert_eq!(cfg.domains[0], "headscale.test");
        assert_eq!(cfg.domains[1], "aux.example.org");
    }

    #[test]
    fn search_domain_equal_to_base_is_not_duplicated() {
        let spec = DnsConfigSpec {
            search_domains: vec!["headscale.test".to_string()],
            ..magic_spec()
        };
        let cfg = DnsStore::from_spec(spec).build(&[]);
        assert_eq!(cfg.domains.len(), 1);
    }

    #[test]
    fn domains_and_route_suffixes_are_normalised_and_deduplicated() {
        let spec = DnsConfigSpec {
            base_domain: "HeadScale.Test.".into(),
            search_domains: vec![
                "headscale.test".into(),
                "Corp.Example.".into(),
                "corp.example".into(),
            ],
            restricted_nameservers: HashMap::from([(
                "Corp.Internal.".to_string(),
                vec!["10.0.0.53".to_string()],
            )]),
            ..magic_spec()
        };
        let cfg = DnsStore::from_spec(spec).build(&[]);

        assert_eq!(cfg.domains, vec!["headscale.test", "corp.example"]);
        assert!(cfg.routes.contains_key("corp.internal"));
        assert!(cfg.authoritative_suffixes.is_empty());
        assert!(cfg.proxied);
    }

    #[test]
    fn authoritative_suffix_override_is_normalised_and_deduplicated() {
        let spec = DnsConfigSpec {
            authoritative_suffixes: Some(vec![
                "Tail.Example.".to_string(),
                "tail.example".to_string(),
                "Corp.Example".to_string(),
            ]),
            ..magic_spec()
        };
        let cfg = DnsStore::from_spec(spec).build(&[]);
        assert_eq!(
            cfg.authoritative_suffixes,
            vec!["tail.example", "corp.example"]
        );
    }

    #[test]
    fn dns_config_serialises_to_pascalcase_json() {
        let spec = DnsConfigSpec {
            override_local_dns: true,
            nameservers: vec!["1.1.1.1".to_string()],
            ..magic_spec()
        };
        let cfg = DnsStore::from_spec(spec).build(&[]);
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("\"Resolvers\":"));
        assert!(json.contains("\"Domains\":"));
        assert!(json.contains("\"Proxied\":true"));
        // PascalCase fields, not snake_case.
        assert!(!json.contains("\"resolvers\""));
    }

    #[test]
    fn dns_record_serialises_with_capital_type_key() {
        let r = DnsRecord {
            name: "host".into(),
            record_type: "A".into(),
            value: "1.1.1.1".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"Type\":\"A\""));
        assert!(json.contains("\"Name\":\"host\""));
        assert!(json.contains("\"Value\":\"1.1.1.1\""));
    }

    #[test]
    fn empty_dns_record_omits_type_field() {
        let r = DnsRecord {
            name: "host".into(),
            record_type: String::new(),
            value: "1.1.1.1".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("\"Type\""));
    }

    #[tokio::test]
    async fn store_wait_for_change_wakes_on_set_extra_records() {
        let store = DnsStore::from_spec(magic_spec());
        let store2 = store.clone();
        let join = tokio::spawn(async move {
            store2.wait_for_change().await;
        });
        // Yield so the waiter parks before we notify.
        tokio::task::yield_now().await;
        store.set_extra_records(vec![DnsRecord {
            name: "x".into(),
            record_type: "A".into(),
            value: "1.1.1.1".into(),
        }]);
        tokio::time::timeout(Duration::from_secs(2), join)
            .await
            .expect("wake within 2s")
            .expect("join ok");
    }

    #[tokio::test]
    async fn store_wait_for_change_wakes_on_set_spec() {
        let store = DnsStore::from_spec(magic_spec());
        let store2 = store.clone();
        let join = tokio::spawn(async move {
            store2.wait_for_change().await;
        });
        tokio::task::yield_now().await;
        store.set_spec(DnsConfigSpec {
            base_domain: "another.example.org".into(),
            ..magic_spec()
        });
        tokio::time::timeout(Duration::from_secs(2), join)
            .await
            .expect("wake within 2s")
            .expect("join ok");
    }

    #[tokio::test]
    async fn extra_records_reload_empty_file_keeps_previous_but_json_empty_clears() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("extra-records.json");
        let store = DnsStore::from_spec(magic_spec());
        std::fs::write(
            &path,
            br#"[{"name":"ops.headscale.test","type":"A","value":"100.64.0.50"}]"#,
        )
        .unwrap();

        let initial = load_and_apply(&store, &path, true, None)
            .await
            .expect("initial load");
        assert_eq!(store.extra_records().len(), 1);

        std::fs::write(&path, b"  \n\t ").unwrap();
        let empty_reload = load_and_apply(&store, &path, false, initial.fingerprint)
            .await
            .expect("empty reload advances mtime");
        assert_eq!(store.extra_records().len(), 1);

        std::fs::write(&path, b"[]").unwrap();
        load_and_apply(&store, &path, false, empty_reload.fingerprint)
            .await
            .expect("json empty reload");
        assert!(store.extra_records().is_empty());
    }

    #[tokio::test]
    async fn extra_records_reload_same_bytes_does_not_wake_waiters() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("extra-records.json");
        let store = DnsStore::from_spec(magic_spec());
        let body = br#"[{"name":"ops.headscale.test","type":"A","value":"100.64.0.50"}]"#;
        std::fs::write(&path, body).unwrap();

        let initial = load_and_apply(&store, &path, true, None)
            .await
            .expect("initial load");
        assert_eq!(store.extra_records().len(), 1);

        let waiter_store = store.clone();
        let mut waiter = tokio::spawn(async move {
            waiter_store.wait_for_change().await;
        });
        tokio::task::yield_now().await;

        std::fs::write(&path, body).unwrap();
        let same = load_and_apply(&store, &path, false, initial.fingerprint)
            .await
            .expect("same-content reload");

        assert_eq!(same.fingerprint, initial.fingerprint);
        tokio::select! {
            res = &mut waiter => panic!("same-content reload unexpectedly woke waiter: {res:?}"),
            () = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
        waiter.abort();
    }

    #[test]
    fn config_spec_accepts_upstream_toml_shape() {
        let toml_src = r#"
magic_dns = true
base_domain = "test.example.org"
override_local_dns = false
search_domains = ["aux.example.org"]
exit_node_filtered_set = ["bank.example"]
cert_domains = ["Node.Test.Example.Org."]
extra_records = [
  { name = "ops.test.example.org", type = "A", value = "100.64.0.50" },
  { Name = "alias.test.example.org", Type = "CNAME", Value = "ops.test.example.org" },
]

[nameservers]
global = ["1.1.1.1", "8.8.8.8"]

[nameservers.split]
"corp.internal" = ["10.0.0.1", "10.0.0.2"]
"#;
        let spec: DnsConfigSpec = toml::from_str(toml_src).expect("toml parse");
        assert!(spec.magic_dns);
        assert_eq!(spec.base_domain, "test.example.org");
        assert!(!spec.override_local_dns);
        assert_eq!(spec.nameservers, vec!["1.1.1.1", "8.8.8.8"]);
        assert_eq!(
            spec.restricted_nameservers.get("corp.internal").unwrap(),
            &vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()]
        );
        assert_eq!(spec.search_domains, vec!["aux.example.org"]);
        assert_eq!(spec.exit_node_filtered_set, vec!["bank.example"]);
        assert_eq!(spec.cert_domains, vec!["Node.Test.Example.Org."]);
        assert_eq!(spec.extra_records.len(), 2);
        assert_eq!(spec.extra_records[0].name, "ops.test.example.org");
        assert_eq!(spec.extra_records[1].record_type, "CNAME");
    }

    #[test]
    fn config_spec_preserves_structured_resolver_metadata() {
        let toml_src = r#"
magic_dns = true
base_domain = "Tail.Example."
override_local_dns = true
fallback_nameservers = [
  { addr = "9.9.9.9", use_with_exit_node = true },
]

[nameservers]
global = [
  { addr = "https://dns.example/dns-query", bootstrap_resolution = ["203.0.113.53"], use_with_exit_node = true },
]

[nameservers.split]
"Corp.Internal." = [
  { Addr = "tls://dns.corp.example", BootstrapResolution = ["2001:db8::53"], UseWithExitNode = true },
]
"#;
        let spec: DnsConfigSpec = toml::from_str(toml_src).expect("toml parse");
        assert_eq!(spec.nameservers, vec!["https://dns.example/dns-query"]);
        assert_eq!(
            spec.restricted_nameservers.get("Corp.Internal.").unwrap(),
            &vec!["tls://dns.corp.example".to_string()]
        );

        let cfg = build_dns_config(&spec, &[], &[]);
        assert_eq!(cfg.domains, vec!["tail.example"]);
        assert_eq!(cfg.resolvers.len(), 1);
        assert_eq!(cfg.resolvers[0].addr, "https://dns.example/dns-query");
        assert_eq!(cfg.resolvers[0].bootstrap_resolution, vec!["203.0.113.53"]);
        assert!(cfg.resolvers[0].use_with_exit_node);

        let route = cfg.routes.get("corp.internal").expect("split route");
        assert_eq!(route[0].addr, "tls://dns.corp.example");
        assert_eq!(route[0].bootstrap_resolution, vec!["2001:db8::53"]);
        assert!(route[0].use_with_exit_node);
        assert_eq!(cfg.fallback_resolvers[0].addr, "9.9.9.9");
        assert!(cfg.fallback_resolvers[0].use_with_exit_node);
    }

    #[test]
    fn config_spec_rejects_inline_extra_records_with_path() {
        let toml_src = r#"
magic_dns = false
extra_records_path = "/etc/headscale/extra-records.json"
extra_records = [
  { name = "ops.test.example.org", type = "A", value = "100.64.0.50" },
]
"#;
        let err = toml::from_str::<DnsConfigSpec>(toml_src).unwrap_err();

        assert!(
            err.to_string()
                .contains("dns.extra_records and dns.extra_records_path are mutually exclusive"),
            "{err}"
        );
    }

    #[test]
    fn config_spec_accepts_legacy_flat_resolvers_and_extra_records_path() {
        let toml_src = r#"
magic_dns = false
nameservers = ["1.1.1.1"]
extra_records = "/etc/headscale/extra-records.json"

[restricted_nameservers]
"corp.internal" = ["10.0.0.1"]
"#;
        let spec: DnsConfigSpec = toml::from_str(toml_src).expect("toml parse");
        assert!(!spec.magic_dns);
        assert_eq!(spec.nameservers, vec!["1.1.1.1"]);
        assert_eq!(
            spec.restricted_nameservers.get("corp.internal").unwrap(),
            &vec!["10.0.0.1".to_string()]
        );
        assert!(spec.extra_records.is_empty());
        assert_eq!(
            spec.extra_records_path.as_deref(),
            Some(Path::new("/etc/headscale/extra-records.json"))
        );
    }
}
