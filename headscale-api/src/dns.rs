// Copyright 2009 The Go Authors. All rights reserved.
// Copyright (c) 2020, Juan Font
// Selected query/receiver behavior adapts Go 1.26.9 net/url and Headscale
// v0.29.5; BSD terms are retained in LICENSE-GO-STDLIB/NOTICE-GO-STDLIB.
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
//! Linux and supported BSD/Apple filesystem events wake the loader immediately. Every platform also
//! reads and fingerprints the current path at the configured polling interval,
//! so timestamp-preserving writes, replacements and missed events cannot leave
//! the live records stale indefinitely. Invalid or nil updates keep the last
//! accepted records; an empty JSON array clears them.
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
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use parking_lot::RwLock;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Notify, watch};

use crate::tailscale_wire::wire::{DnsConfig, DnsRecord, DnsResolver};
use ipnet::{Ipv4Net, Ipv6Net};

#[path = "dns/watch.rs"]
mod extra_records_watch;

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

/// Fallback content-check interval for extra records. Supported file events also
/// trigger immediate reads; no modification timestamp gates a reload.
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
    /// it. Runtime emission preserves configured values exactly,
    /// matching headscale-go's `dnsToTailcfgDNS`.
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
    /// (default), nothing is emitted, matching headscale-go.
    /// Set to `Some(vec![])` to explicitly keep the list empty.
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
/// * the most-recently-loaded `ExtraRecords`,
/// * a retained watch channel for `/map` connections, and
/// * a [`Notify`] for existing one-shot waiters.
///
/// Map connections subscribe before their initial snapshot and keep the
/// receiver between frames, including while encoding and yielding bytes.
#[derive(Clone, Default)]
pub struct DnsStore {
    inner: Arc<Inner>,
}

struct Inner {
    spec: RwLock<Arc<DnsConfigSpec>>,
    extra_records: RwLock<Arc<Vec<DnsRecord>>>,
    magic_dns_reverse_prefixes: RwLock<MagicDnsReversePrefixes>,
    /// Wakes parked `/map` long-pollers on extra-records edits.
    notify: Notify,
    /// Retains changes while a map stream is encoding or yielding a frame.
    changes: watch::Sender<()>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            spec: RwLock::default(),
            extra_records: RwLock::default(),
            magic_dns_reverse_prefixes: RwLock::default(),
            notify: Notify::new(),
            changes: watch::channel(()).0,
        }
    }
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
                changes: watch::channel(()).0,
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
        self.notify_changed();
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
        self.notify_changed();
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
        self.notify_changed();
    }

    fn notify_changed(&self) {
        self.inner.changes.send_replace(());
        self.inner.notify.notify_waiters();
    }

    /// Subscribe before building an initial map, then retain this receiver
    /// for the connection's lifetime so updates between frames are observed.
    pub(crate) fn subscribe_changes(&self) -> watch::Receiver<()> {
        self.inner.changes.subscribe()
    }

    /// Wait for the next DnsStore change (extra-records edit OR
    /// spec swap). This one-shot API observes only notifications sent after
    /// its future is registered; map connections use a retained receiver.
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
        self.build_for_requester_with_hostinfo(machines, requester, true)
    }

    pub(crate) fn build_for_requester_with_hostinfo(
        &self,
        machines: &[MachineDnsRecord],
        requester: Option<&DnsRequester>,
        has_hostinfo: bool,
    ) -> DnsConfig {
        let mut config = self.build(machines);
        if let Some(requester) = requester {
            apply_nextdns_requester_config_with_hostinfo(&mut config, requester, has_hostinfo);
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
    let base_domain_set = !spec.base_domain.is_empty();
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

    // Domains: headscale-go v0.28 copies BaseDomain and SearchDomains
    // directly into tailcfg.DNSConfig. Preserve case, trailing dots,
    // duplicates, empty search-domain entries, and order here because
    // this is stock-client wire configuration.
    let mut domains = Vec::with_capacity(1 + spec.search_domains.len());
    if base_domain_set {
        domains.push(spec.base_domain.clone());
    }
    domains.extend(spec.search_domains.iter().cloned());

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
        // headscale-go v0.29.4+ lowercases operator record names before
        // putting them on the client wire. Record values keep their case.
        extra_records: extra
            .iter()
            .cloned()
            .map(|mut record| {
                record.name = record.name.to_lowercase();
                record
            })
            .collect(),
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
    apply_nextdns_requester_config_with_hostinfo(config, requester, true);
}

fn apply_nextdns_requester_config_with_hostinfo(
    config: &mut DnsConfig,
    requester: &DnsRequester,
    has_hostinfo: bool,
) {
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

    add_nextdns_metadata(&mut config.resolvers, requester, has_hostinfo);
    add_nextdns_metadata(&mut config.fallback_resolvers, requester, has_hostinfo);
    for resolvers in config.routes.values_mut() {
        add_nextdns_metadata(resolvers, requester, has_hostinfo);
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

fn add_nextdns_metadata(
    resolvers: &mut [DnsResolver],
    requester: &DnsRequester,
    has_hostinfo: bool,
) {
    for resolver in resolvers {
        if is_nextdns_doh_addr(&resolver.addr) {
            resolver.addr = nextdns_metadata_to_addr(&resolver.addr, requester, has_hostinfo);
        }
    }
}

fn nextdns_metadata_to_addr(addr: &str, requester: &DnsRequester, has_hostinfo: bool) -> String {
    let Ok(mut url) = crate::go_url::Url::parse(addr) else {
        return addr.to_owned();
    };
    let mut params = parse_query_bytes(url.raw_query());
    params.insert(
        b"device_name".to_vec(),
        vec![requester.hostname.as_bytes().to_vec()],
    );
    if has_hostinfo {
        params.insert(
            b"device_model".to_vec(),
            vec![requester.os.as_bytes().to_vec()],
        );
    }
    if let Some(ip) = requester.primary_ip.as_ref() {
        params.insert(b"device_ip".to_vec(), vec![ip.as_bytes().to_vec()]);
    }
    url.set_raw_query(encode_query_bytes(&params).into_bytes());
    // Parse receives UTF-8 and String escapes all decoded non-UTF-8 bytes.
    String::from_utf8(url.as_bytes())
        .expect("URL.String preserves UTF-8 source and escapes components")
}

// net/url.ParseQuery drops malformed pairs, preserves arbitrary decoded bytes,
// and rejects a raw semicolon in a pair. Values.Encode sorts byte strings.
fn parse_query_bytes(query: &[u8]) -> BTreeMap<Vec<u8>, Vec<Vec<u8>>> {
    let mut params = BTreeMap::new();
    // The number of `&`-separated pairs is the number of `&` plus one.
    if !crate::go_url::query_params_within_max(query.split(|byte| *byte == b'&').count()) {
        return params;
    }
    for pair in query.split(|byte| *byte == b'&') {
        if pair.is_empty() || pair.contains(&b';') {
            continue;
        }
        let (key, value) = pair
            .iter()
            .position(|byte| *byte == b'=')
            .map_or((pair, &[][..]), |at| (&pair[..at], &pair[at + 1..]));
        let (Some(key), Some(value)) = (decode_query_bytes(key), decode_query_bytes(value)) else {
            continue;
        };
        params.entry(key).or_insert_with(Vec::new).push(value);
    }
    params
}

fn decode_query_bytes(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut at = 0;
    while at < input.len() {
        match input[at] {
            b'+' => out.push(b' '),
            b'%' => {
                let high = hex_value(*input.get(at + 1)?)?;
                let low = hex_value(*input.get(at + 2)?)?;
                out.push(high << 4 | low);
                at += 2;
            }
            byte => out.push(byte),
        }
        at += 1;
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn encode_query_bytes(params: &BTreeMap<Vec<u8>, Vec<Vec<u8>>>) -> String {
    let mut output = String::new();
    for (key, values) in params {
        for value in values {
            if !output.is_empty() {
                output.push('&');
            }
            encode_query_part(key, &mut output);
            output.push('=');
            encode_query_part(value, &mut output);
        }
    }
    output
}

fn encode_query_part(input: &[u8], output: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in input.iter().copied() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(byte as char);
            }
            b' ' => output.push('+'),
            _ => {
                output.push('%');
                output.push(HEX[(byte >> 4) as usize] as char);
                output.push(HEX[(byte & 15) as usize] as char);
            }
        }
    }
}

fn resolver_from_addr(s: &str) -> DnsResolver {
    DnsResolver {
        addr: s.to_string(),
        bootstrap_resolution: Vec::new(),
        use_with_exit_node: false,
    }
}

fn effective_global_resolvers(spec: &DnsConfigSpec) -> Vec<DnsResolver> {
    let resolvers: Vec<DnsResolver> = if spec.nameserver_resolvers.is_empty() {
        spec.nameservers
            .iter()
            .map(|addr| resolver_from_addr(addr))
            .collect()
    } else {
        spec.nameserver_resolvers.clone()
    };
    resolvers
        .into_iter()
        .filter(go_accepts_resolver_address)
        .collect()
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
        let resolvers: Vec<DnsResolver> = spec
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
        routes.insert(
            suffix.clone(),
            resolvers
                .into_iter()
                .filter(go_accepts_resolver_address)
                .collect(),
        );
    }
    routes
}

fn go_accepts_resolver_address(resolver: &DnsResolver) -> bool {
    headscale_api_acl::go_netip::parse_addr(&resolver.addr).is_ok()
        || crate::go_url::Url::parse(&resolver.addr).is_ok()
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
/// startup validation; hot reload treats zero-byte reads as transient
/// and keeps the previous record set. Whitespace-only files are not
/// special-cased; they fail JSON parsing like upstream Go.
///
/// Fields use Go's case folding, duplicate assignment, scalar-null and legacy
/// Unicode replacement rules. Missing strings and null array elements retain
/// the zero-value record.
pub fn parse_extra_records(bytes: &[u8]) -> Result<Vec<DnsRecord>, serde_json::Error> {
    Ok(parse_extra_records_value(bytes)?.unwrap_or_default())
}

// A nil slice is accepted at startup but ignored by updateRecords. An empty,
// non-nil array deliberately clears the live records.
fn parse_extra_records_value(bytes: &[u8]) -> Result<Option<Vec<DnsRecord>>, serde_json::Error> {
    use headscale_api_acl::{
        go_json,
        go_tailcfg_json::{self, Kind},
    };
    fn error(message: impl std::fmt::Display) -> serde_json::Error {
        <serde_json::Error as serde::de::Error>::custom(message)
    }
    if bytes.is_empty() {
        return Ok(None);
    }
    go_json::check_valid(bytes).map_err(error)?;
    if go_json::trim(bytes) == b"null" {
        return Ok(None);
    }
    let mut records = Vec::new();
    for raw in go_json::array(bytes).map_err(error)? {
        let value = go_tailcfg_json::struct_value(
            raw.get(),
            &[
                ("Name", Kind::String),
                ("Type", Kind::String),
                ("Value", Kind::String),
            ],
        )
        .map_err(error)?;
        let field = |name: &str| {
            value
                .get(name)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        records.push(DnsRecord {
            name: field("Name"),
            record_type: field("Type"),
            value: field("Value"),
        });
    }
    dedupe_extra_records(&mut records);
    Ok(Some(records))
}

fn dedupe_extra_records(records: &mut Vec<DnsRecord>) {
    // headscale-go's ExtraRecordsMan stores file-backed records in
    // set.Set[tailcfg.DNSRecord], which collapses exact duplicates
    // and leaves iteration order undefined. Keep Rust deterministic
    // by retaining the first occurrence of each exact record.
    let mut seen = HashSet::new();
    records.retain(|record| {
        seen.insert((
            record.name.clone(),
            record.record_type.clone(),
            record.value.clone(),
        ))
    });
}

/// Spawn an event-driven (Linux/Android/BSD/Apple) and content-polled records loader.
///
/// Invalid, absent or nil updates retain the last accepted record set. The
/// returned task owns its event descriptor; aborting it releases the watch.
/// `interval` controls fallback content checks on every platform.
pub fn spawn_extra_records_watcher(
    store: DnsStore,
    path: PathBuf,
    interval: Option<Duration>,
) -> tokio::task::JoinHandle<()> {
    let poll = interval.unwrap_or(EXTRA_RECORDS_POLL_INTERVAL);
    tokio::spawn(async move {
        // Arm before the initial read so edits racing that read also wake us.
        let mut events = extra_records_watch::Events::new(&path);
        let mut fingerprint = load_and_apply(&store, &path, true, None)
            .await
            .and_then(|load| load.fingerprint);
        let mut deadline = tokio::time::Instant::now() + poll;
        loop {
            let event = async {
                match events.as_ref() {
                    Some(events) => events.changed().await,
                    None => std::future::pending().await,
                }
            };
            let event_failed = tokio::select! {
                result = event => result.is_err(),
                () = tokio::time::sleep_until(deadline) => false,
            };
            // A timer independent of event traffic guarantees content fallback
            // even under a busy parent directory or a lost/overflowed watch.
            if tokio::time::Instant::now() >= deadline {
                deadline = tokio::time::Instant::now() + poll;
            }
            if event_failed {
                events = None;
            }
            if let Some(events) = &mut events {
                events.refresh();
            } else {
                events = extra_records_watch::Events::new(&path);
            }
            if let Some(next) = load_and_apply(&store, &path, false, fingerprint).await {
                fingerprint = next.fingerprint;
            }
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExtraRecordsLoad {
    fingerprint: Option<[u8; 32]>,
}

async fn load_and_apply(
    store: &DnsStore,
    path: &Path,
    apply_nil: bool,
    previous_fingerprint: Option<[u8; 32]>,
) -> Option<ExtraRecordsLoad> {
    let bytes = match tokio::fs::read(path).await {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(
                ?path,
                ?error,
                "extra-records read failed; keeping previous set"
            );
            return None;
        }
    };
    let fingerprint = extra_records_fingerprint(&bytes);
    if Some(fingerprint) == previous_fingerprint {
        return Some(ExtraRecordsLoad {
            fingerprint: Some(fingerprint),
        });
    }
    match parse_extra_records_value(&bytes) {
        Ok(Some(records)) => {
            store.set_extra_records(records);
            Some(ExtraRecordsLoad {
                fingerprint: Some(fingerprint),
            })
        }
        Ok(None) if apply_nil => {
            store.set_extra_records(Vec::new());
            Some(ExtraRecordsLoad {
                fingerprint: Some(fingerprint),
            })
        }
        // Go updateRecords ignores a nil slice without updating its hash.
        Ok(None) => Some(ExtraRecordsLoad {
            fingerprint: previous_fingerprint,
        }),
        Err(error) => {
            tracing::warn!(
                ?path,
                ?error,
                "extra-records parse failed; keeping previous set"
            );
            None
        }
    }
}

fn extra_records_fingerprint(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
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
        assert_eq!(s.nameservers, [] as [String; 0]);
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
        assert_eq!(cfg.extra_records.len(), 0);
    }

    #[test]
    fn invalid_magic_dns_spec_is_safe_if_validation_is_bypassed() {
        let cfg = DnsStore::from_spec(DnsConfigSpec::default()).build(&[machine("peer", 1, 1)]);
        assert!(!cfg.proxied);
        assert_eq!(cfg.domains, [] as [String; 0]);
        assert_eq!(cfg.extra_records.len(), 0);
    }

    #[test]
    fn store_from_spec_emits_proxied_and_base_domain_search() {
        let store = DnsStore::try_from_spec(magic_spec()).expect("valid dns spec");
        let cfg = store.build(&[]);
        assert!(cfg.proxied);
        assert_eq!(cfg.domains, vec!["headscale.test".to_string()]);
        assert_eq!(cfg.authoritative_suffixes, [] as [String; 0]);
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
    fn dnsconfig_lowercases_operator_record_names() {
        let store = DnsStore::from_spec(magic_spec());
        store.set_extra_records(vec![record(
            "MiXeD.Headscale.Test",
            "CNAME",
            "Host.Example",
        )]);
        let cfg = store.build(&[]);
        assert_eq!(
            cfg.extra_records,
            vec![record("mixed.headscale.test", "CNAME", "Host.Example")]
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
        assert_eq!(cfg.routes["64.100.in-addr.arpa"].len(), 0);
        assert_eq!(cfg.routes["100.100.in-addr.arpa"].len(), 0);
        assert_eq!(cfg.routes["127.100.in-addr.arpa"].len(), 0);
        assert_eq!(cfg.routes["0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa"].len(), 0);
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
        assert_eq!(cfg.authoritative_suffixes, [] as [String; 0]);
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
    fn parse_extra_records_deduplicates_exact_file_records() {
        let body = br#"[
          {"Name":"dup.example.org","Type":"A","Value":"100.64.0.10"},
          {"Name":"unique.example.org","Type":"AAAA","Value":"fd7a:115c:a1e0::53"},
          {"Name":"dup.example.org","Type":"A","Value":"100.64.0.10"},
          {"Name":"dup.example.org","Type":"AAAA","Value":"fd7a:115c:a1e0::10"}
        ]"#;

        let recs = parse_extra_records(body).expect("parses");

        assert_eq!(
            recs,
            vec![
                record("dup.example.org", "A", "100.64.0.10"),
                record("unique.example.org", "AAAA", "fd7a:115c:a1e0::53"),
                record("dup.example.org", "AAAA", "fd7a:115c:a1e0::10"),
            ]
        );
    }

    #[test]
    fn parse_extra_records_empty_file_ok_but_whitespace_errors() {
        assert_eq!(parse_extra_records(b"").unwrap().len(), 0);
        assert!(parse_extra_records(b"  \n\t ").is_err());
        assert_eq!(parse_extra_records(b"[]").unwrap().len(), 0);
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

        assert_eq!(cfg.resolvers.len(), 0);
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
        assert_eq!(cfg.authoritative_suffixes, [] as [String; 0]);
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
    fn search_domain_equal_to_base_is_preserved_like_headscale_go() {
        let spec = DnsConfigSpec {
            search_domains: vec!["headscale.test".to_string(), String::new()],
            ..magic_spec()
        };
        let cfg = DnsStore::from_spec(spec).build(&[]);
        assert_eq!(
            cfg.domains,
            vec![
                "headscale.test".to_string(),
                "headscale.test".to_string(),
                String::new()
            ]
        );
    }

    #[test]
    fn domains_and_route_suffixes_preserve_configured_values_like_headscale_go() {
        let spec = DnsConfigSpec {
            base_domain: "HeadScale.Test.".into(),
            search_domains: vec![
                "headscale.test".into(),
                "Corp.Example.".into(),
                "corp.example".into(),
                "Corp.Example.".into(),
            ],
            restricted_nameservers: HashMap::from([(
                "Corp.Internal.".to_string(),
                vec!["10.0.0.53".to_string()],
            )]),
            ..magic_spec()
        };
        let cfg = DnsStore::from_spec(spec).build(&[]);

        assert_eq!(
            cfg.domains,
            vec![
                "HeadScale.Test.".to_string(),
                "headscale.test".to_string(),
                "Corp.Example.".to_string(),
                "corp.example".to_string(),
                "Corp.Example.".to_string(),
            ]
        );
        assert!(cfg.routes.contains_key("Corp.Internal."));
        assert_eq!(cfg.authoritative_suffixes, [] as [String; 0]);
        assert!(cfg.proxied);
    }

    #[test]
    fn numeric_resolver_with_port_is_ignored_like_headscale_go() {
        let spec = DnsConfigSpec {
            nameservers: vec!["192.0.2.10:5353".into(), "192.0.2.11".into()],
            restricted_nameservers: HashMap::from([(
                "corp.example".to_string(),
                vec!["192.0.2.12:5353".into(), "192.0.2.13".into()],
            )]),
            ..magic_spec()
        };
        let cfg = DnsStore::from_spec(spec).build(&[]);
        assert_eq!(
            cfg.fallback_resolvers
                .iter()
                .map(|resolver| resolver.addr.as_str())
                .collect::<Vec<_>>(),
            vec!["192.0.2.11"]
        );
        assert_eq!(
            cfg.routes["corp.example"]
                .iter()
                .map(|resolver| resolver.addr.as_str())
                .collect::<Vec<_>>(),
            vec!["192.0.2.13"]
        );
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
    async fn extra_records_reload_empty_file_keeps_previous_whitespace_errors_json_empty_clears() {
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

        std::fs::write(&path, b"").unwrap();
        let empty_reload = load_and_apply(&store, &path, false, initial.fingerprint)
            .await
            .expect("empty reload advances mtime");
        assert_eq!(store.extra_records().len(), 1);

        std::fs::write(&path, b"  \n\t ").unwrap();
        let whitespace_reload =
            load_and_apply(&store, &path, false, empty_reload.fingerprint).await;
        assert!(
            whitespace_reload.is_none(),
            "whitespace-only reload must fail JSON parsing like headscale-go"
        );
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

    #[tokio::test]
    async fn extra_records_reload_reordered_bytes_still_updates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("extra-records.json");
        let store = DnsStore::from_spec(magic_spec());
        let first = br#"[
          {"name":"a.headscale.test","type":"A","value":"100.64.0.10"},
          {"name":"b.headscale.test","type":"A","value":"100.64.0.11"}
        ]"#;
        std::fs::write(&path, first).unwrap();

        let initial = load_and_apply(&store, &path, true, None)
            .await
            .expect("initial load");
        assert_eq!(
            store.extra_records().as_slice(),
            &[
                record("a.headscale.test", "A", "100.64.0.10"),
                record("b.headscale.test", "A", "100.64.0.11"),
            ]
        );

        let waiter_store = store.clone();
        let mut waiter = tokio::spawn(async move {
            waiter_store.wait_for_change().await;
        });
        tokio::task::yield_now().await;

        let reordered = br#"[
          {"name":"b.headscale.test","type":"A","value":"100.64.0.11"},
          {"name":"a.headscale.test","type":"A","value":"100.64.0.10"}
        ]"#;
        std::fs::write(&path, reordered).unwrap();
        let changed = load_and_apply(&store, &path, false, initial.fingerprint)
            .await
            .expect("reordered reload");

        assert_ne!(changed.fingerprint, initial.fingerprint);
        tokio::time::timeout(Duration::from_secs(2), &mut waiter)
            .await
            .expect("raw-byte reorder wakes waiters")
            .expect("join ok");
        assert_eq!(
            store.extra_records().as_slice(),
            &[
                record("b.headscale.test", "A", "100.64.0.11"),
                record("a.headscale.test", "A", "100.64.0.10"),
            ]
        );
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
        assert_eq!(cfg.domains, vec!["Tail.Example."]);
        assert_eq!(cfg.resolvers.len(), 1);
        assert_eq!(cfg.resolvers[0].addr, "https://dns.example/dns-query");
        assert_eq!(cfg.resolvers[0].bootstrap_resolution, vec!["203.0.113.53"]);
        assert!(cfg.resolvers[0].use_with_exit_node);

        let route = cfg.routes.get("Corp.Internal.").expect("split route");
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
        assert_eq!(spec.extra_records.len(), 0);
        assert_eq!(
            spec.extra_records_path.as_deref(),
            Some(Path::new("/etc/headscale/extra-records.json"))
        );
    }
}
