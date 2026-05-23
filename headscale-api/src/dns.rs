//! MagicDNS / `tailcfg.DNSConfig` build + hot-reload.
//!
//! Closes the P1 entry in `docs/headscale-gap-analysis.md` (§MagicDNS):
//! before this module shipped, `MapResponse.DNSConfig` was an empty
//! object, so stock `tailscale up` never installed its in-process
//! MagicDNS resolver and `ssh peer-1` couldn't resolve peer hostnames
//! to `100.64.x.x` tailnet addresses.
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
//! ## Hostname-collision handling
//!
//! Two MachineRecords can advertise the same hostname (the client
//! controls it; nothing enforces uniqueness on register). When we
//! emit MagicDNS A records, the second collision gets a `-<n{id}>`
//! suffix appended before the base domain (e.g. `peer-1.headscale.test`
//! -> `peer-1-n42.headscale.test`). The first-seen hostname keeps the
//! collision-free name; ordering is stable because we iterate the
//! registry by sorted node-id. This is deterministic and matches what
//! `juanfont/headscale` does in its `normalizeToFQDNRules` path.

#![allow(clippy::module_name_repetitions)]

use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};

use parking_lot::RwLock;
use serde::{Deserialize, Deserializer, Serialize};
use tokio::sync::Notify;

use crate::tailscale_wire::wire::{DnsConfig, DnsRecord, DnsResolver};

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
    /// Per-suffix restricted resolvers (split DNS). Key is a DNS
    /// suffix (e.g. `"corp.internal"`), value is the resolver list to
    /// use for that suffix. Empty ⇒ no `Routes` field on the wire.
    /// The deserializer accepts both this historical field and
    /// upstream headscale's `nameservers.split` table.
    pub restricted_nameservers: HashMap<String, Vec<String>>,
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
            restricted_nameservers: HashMap::new(),
            extra_records: Vec::new(),
            extra_records_path: None,
            search_domains: Vec::new(),
            fallback_nameservers: Vec::new(),
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
        let (nameservers, mut restricted_nameservers) = raw.nameservers.into_parts();
        restricted_nameservers.extend(raw.restricted_nameservers);

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
            restricted_nameservers,
            extra_records,
            extra_records_path: raw
                .extra_records_path
                .or(extra_records_path_from_legacy_key),
            search_domains: raw.search_domains,
            fallback_nameservers: raw.fallback_nameservers,
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
    restricted_nameservers: HashMap<String, Vec<String>>,
    extra_records: Option<RawExtraRecords>,
    extra_records_path: Option<PathBuf>,
    search_domains: Vec<String>,
    fallback_nameservers: Vec<String>,
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
            exit_node_filtered_set: Vec::new(),
            authoritative_suffixes: None,
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawNameservers {
    Flat(Vec<String>),
    Upstream {
        #[serde(default)]
        global: Vec<String>,
        #[serde(default)]
        split: HashMap<String, Vec<String>>,
    },
}

impl RawNameservers {
    fn into_parts(self) -> (Vec<String>, HashMap<String, Vec<String>>) {
        match self {
            Self::Flat(global) => (global, HashMap::new()),
            Self::Upstream { global, split } => (global, split),
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
        }
    }
}

impl std::error::Error for DnsConfigError {}

impl DnsConfigSpec {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if self.magic_dns && self.base_domain.trim().is_empty() {
            return Err(DnsConfigError::MissingBaseDomainForMagicDns);
        }
        if self.override_local_dns && self.nameservers.is_empty() {
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
    /// Stable per-tailnet node ID. Used as the collision-suffix when
    /// two machines advertise the same hostname.
    pub node_id: u64,
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
            restricted_nameservers: HashMap::new(),
            extra_records: Vec::new(),
            extra_records_path: None,
            search_domains: Vec::new(),
            fallback_nameservers: Vec::new(),
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
    pub fn build(&self, machines: &[MachineDnsRecord]) -> DnsConfig {
        let spec = self.spec();
        let extra = self.extra_records();
        build_dns_config(&spec, machines, extra.as_slice())
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
/// | `ExtraRecords`              | `extra` ++ MagicDNS A records when base is set |
/// | `ExitNodeFilteredSet`       | `spec.exit_node_filtered_set`             |
/// | `AuthoritativeSuffixes`     | `spec.authoritative_suffixes` OR derived |
///
/// `Nameservers` / `CertDomains` are left empty — they're either
/// deprecated (Nameservers) or out-of-scope for the P1 deliverable
/// (CertDomains; we don't run an HTTPS MagicDNS endpoint yet).
pub fn build_dns_config(
    spec: &DnsConfigSpec,
    machines: &[MachineDnsRecord],
    extra: &[DnsRecord],
) -> DnsConfig {
    let base_domain_set = !spec.base_domain.trim().is_empty();
    let magic_dns_enabled = spec.magic_dns && base_domain_set;
    let global_resolvers: Vec<DnsResolver> = spec
        .nameservers
        .iter()
        .map(|s| string_to_resolver(s))
        .collect();
    let routes: HashMap<String, Vec<DnsResolver>> = spec
        .restricted_nameservers
        .iter()
        .map(|(suffix, addrs)| {
            (
                suffix.clone(),
                addrs.iter().map(|s| string_to_resolver(s)).collect(),
            )
        })
        .collect();
    let mut fallback_resolvers = Vec::new();
    if !spec.override_local_dns {
        fallback_resolvers.extend(global_resolvers.iter().cloned());
    }
    fallback_resolvers.extend(
        spec.fallback_nameservers
            .iter()
            .map(|s| string_to_resolver(s)),
    );
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
        domains.push(spec.base_domain.clone());
    }
    for d in &spec.search_domains {
        if d != &spec.base_domain {
            domains.push(d.clone());
        }
    }

    let magic_records = if magic_dns_enabled {
        magic_dns_records(&spec.base_domain, machines)
    } else {
        Vec::new()
    };
    let mut combined: Vec<DnsRecord> = Vec::with_capacity(extra.len() + magic_records.len());
    combined.extend_from_slice(extra);
    combined.extend(magic_records);

    let authoritative = spec
        .authoritative_suffixes
        .clone()
        .unwrap_or_else(|| derive_authoritative_suffixes(spec));

    DnsConfig {
        resolvers,
        routes,
        fallback_resolvers,
        domains,
        proxied: magic_dns_enabled,
        nameservers: Vec::new(),
        cert_domains: Vec::new(),
        extra_records: combined,
        exit_node_filtered_set: spec.exit_node_filtered_set.clone(),
        temp_corp_issue_13969: String::new(),
        authoritative_suffixes: authoritative,
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

fn string_to_resolver(s: &str) -> DnsResolver {
    DnsResolver {
        addr: s.to_string(),
        bootstrap_resolution: Vec::new(),
        use_with_exit_node: false,
    }
}

/// Default authoritative-suffix list — the base domain plus every
/// split-DNS suffix the operator has restricted. Operators can
/// override this via `[dns].authoritative_suffixes` in node.toml.
fn derive_authoritative_suffixes(spec: &DnsConfigSpec) -> Vec<String> {
    let mut out = Vec::with_capacity(1 + spec.restricted_nameservers.len());
    if !spec.base_domain.trim().is_empty() {
        out.push(spec.base_domain.clone());
    }
    // Sorted for determinism — HashMap iteration order is otherwise
    // non-deterministic and our tests would flake. BTreeSet is the
    // zero-value-friendly form of the BTreeMap<K, ()> pattern.
    let sorted: std::collections::BTreeSet<&String> = spec.restricted_nameservers.keys().collect();
    for k in &sorted {
        if k.as_str() != spec.base_domain {
            out.push((*k).clone());
        }
    }
    out
}

/// Generate the per-machine A/AAAA records that make `ssh peer-1` work.
///
/// Each record is `<hostname>.<base_domain> → node addresses`. The
/// hostname is normalised (lowercased, ASCII-only, dot-stripped) so
/// DNS labels stay legal even if the client advertised a quirky name.
///
/// Collision handling: if N machines advertise the same normalised
/// hostname, the first (lowest node-id) keeps the canonical name and
/// the rest get a `-n{id}` suffix. Sorting by `node_id` gives a
/// stable, reproducible ordering across rebuilds.
pub fn magic_dns_records(base_domain: &str, machines: &[MachineDnsRecord]) -> Vec<DnsRecord> {
    if base_domain.trim().is_empty() {
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
            format!("{normalised}-n{}", m.node_id)
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
    s
}

/// Parse an extra-records JSON file. The file is a top-level array of
/// `{name, type, value}` records — same shape upstream
/// `juanfont/headscale` accepts. Empty file ⇒ empty record list.
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
        // Best-effort: load the file once at start so the initial
        // `/map` response carries the operator's records without
        // waiting one poll-interval.
        if let Some(mtime) = load_and_apply(&store, &path).await {
            last_mtime = Some(mtime);
        }
        loop {
            tokio::time::sleep(poll).await;
            match tokio::fs::metadata(&path).await {
                Ok(meta) => match meta.modified() {
                    Ok(m) if Some(m) != last_mtime => {
                        if let Some(new) = load_and_apply(&store, &path).await {
                            last_mtime = Some(new);
                        }
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!(?path, ?e, "extra-records mtime read failed"),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // File disappeared — clear the record set, log,
                    // and keep polling for it to reappear.
                    if last_mtime.is_some() || !store.extra_records().is_empty() {
                        store.set_extra_records(Vec::new());
                        last_mtime = None;
                    }
                }
                Err(e) => tracing::warn!(?path, ?e, "extra-records stat failed"),
            }
        }
    })
}

async fn load_and_apply(store: &DnsStore, path: &Path) -> Option<SystemTime> {
    let bytes = match tokio::fs::read(path).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(?path, ?e, "extra-records read failed");
            return None;
        }
    };
    let meta = tokio::fs::metadata(path).await.ok()?;
    let mtime = meta.modified().ok()?;
    match parse_extra_records(&bytes) {
        Ok(records) => {
            store.set_extra_records(records);
            Some(mtime)
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
        // Default authoritative-suffix list contains the base domain.
        assert!(
            cfg.authoritative_suffixes
                .contains(&"headscale.test".to_string())
        );
    }

    #[test]
    fn magic_dns_records_emit_per_machine_a_records() {
        let machines = [machine("peer-1", 11, 1), machine("peer-2", 22, 2)];
        let store = DnsStore::from_spec(magic_spec());
        let cfg = store.build(&machines);
        assert_eq!(cfg.extra_records.len(), 2);
        assert!(
            cfg.extra_records
                .iter()
                .any(|r| r.name == "peer-1.headscale.test" && r.value == "100.64.0.11")
        );
        assert!(
            cfg.extra_records
                .iter()
                .any(|r| r.name == "peer-2.headscale.test" && r.value == "100.64.0.22")
        );
    }

    #[test]
    fn magic_dns_records_emit_aaaa_for_ipv6_only_machine() {
        let machines = [MachineDnsRecord {
            hostname: "v6-only".into(),
            ipv4: None,
            ipv6: Some("fd7a:115c:a1e0::66".parse().unwrap()),
            node_id: 66,
        }];

        let cfg = DnsStore::from_spec(magic_spec()).build(&machines);

        assert_eq!(cfg.extra_records.len(), 1);
        assert_eq!(cfg.extra_records[0].name, "v6-only.headscale.test");
        assert_eq!(cfg.extra_records[0].record_type, "AAAA");
        assert_eq!(cfg.extra_records[0].value, "fd7a:115c:a1e0::66");
    }

    #[test]
    fn hostname_collision_lowest_node_id_keeps_canonical_name() {
        let machines = [
            machine("dup", 11, 42), // higher id ⇒ collision-suffixed
            machine("dup", 22, 7),  // lower id ⇒ keeps canonical name
        ];
        let cfg = DnsStore::from_spec(magic_spec()).build(&machines);
        let names: Vec<String> = cfg.extra_records.iter().map(|r| r.name.clone()).collect();
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
        let cfg = DnsStore::from_spec(magic_spec()).build(&machines);
        let names: Vec<String> = cfg.extra_records.iter().map(|r| r.name.clone()).collect();
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
    fn empty_hostname_falls_back_to_node_id_label() {
        let machines = [MachineDnsRecord {
            hostname: "!!!".into(),
            ipv4: Some(Ipv4Addr::new(100, 64, 0, 9)),
            ipv6: None,
            node_id: 99,
        }];
        let cfg = DnsStore::from_spec(magic_spec()).build(&machines);
        assert_eq!(cfg.extra_records.len(), 1);
        assert_eq!(cfg.extra_records[0].name, "n99.headscale.test");
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
    fn authoritative_suffixes_default_includes_base_and_split_keys() {
        let mut restricted = HashMap::new();
        restricted.insert("corp.internal".to_string(), vec!["10.0.0.1".to_string()]);
        restricted.insert("ops.internal".to_string(), vec!["10.0.0.2".to_string()]);
        let spec = DnsConfigSpec {
            restricted_nameservers: restricted,
            ..magic_spec()
        };
        let cfg = DnsStore::from_spec(spec).build(&[]);
        // base_domain + 2 suffixes, sorted (deterministic).
        assert_eq!(cfg.authoritative_suffixes.len(), 3);
        assert_eq!(cfg.authoritative_suffixes[0], "headscale.test");
        assert!(
            cfg.authoritative_suffixes
                .contains(&"corp.internal".to_string())
        );
        assert!(
            cfg.authoritative_suffixes
                .contains(&"ops.internal".to_string())
        );
    }

    #[test]
    fn authoritative_suffixes_override_replaces_default() {
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
        // Authoritative suffixes are still derived from base_domain
        // even when MagicDNS is off — they're an independent operator
        // signal ("don't ask upstream for these names").
        assert!(
            cfg.authoritative_suffixes
                .contains(&"headscale.test".to_string())
        );
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

    #[test]
    fn config_spec_accepts_upstream_toml_shape() {
        let toml_src = r#"
magic_dns = true
base_domain = "test.example.org"
override_local_dns = false
search_domains = ["aux.example.org"]
exit_node_filtered_set = ["bank.example"]
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
        assert_eq!(spec.extra_records.len(), 2);
        assert_eq!(spec.extra_records[0].name, "ops.test.example.org");
        assert_eq!(spec.extra_records[1].record_type, "CNAME");
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
