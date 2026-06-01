//! Configuration file handling for the CLI.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use headscale_api::dns::{DnsConfigSpec, parse_extra_records};
use headscale_core::config::{EmbeddedDerpConfig, OidcConfig};
use headscale_db::DatabaseBackend;
use serde::{Deserialize, Deserializer, Serialize, de};

use crate::derp_config::DerpConfig;

const DEFAULT_CONFIG_FILENAMES: &[&str] =
    &["config.yaml", "config.yml", "config.json", "config.toml"];
const DEFAULT_CLI_TIMEOUT_SECS: u64 = 5;
const DEFAULT_NODE_ROUTES_HA_PROBE_INTERVAL_SECS: u64 = 10;
const DEFAULT_NODE_ROUTES_HA_PROBE_TIMEOUT_SECS: u64 = 5;
const MISSING_NOISE_PRIVATE_KEY_PATH_ERROR: &str = "Fatal config error: headscale now requires a new `noise.private_key_path` field in the config file for the Tailscale v2 protocol";

/// Top-level CLI configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct CliConfig {
    /// Server mode configuration
    pub server: Option<ServerConfig>,
    /// Upstream top-level `server_url`.
    #[serde(default, skip_serializing)]
    pub(crate) server_url: Option<String>,
    /// Upstream top-level `listen_addr`.
    #[serde(default, skip_serializing)]
    pub(crate) listen_addr: Option<String>,
    /// Upstream top-level `metrics_listen_addr`.
    #[serde(default, skip_serializing)]
    #[allow(clippy::option_option)]
    pub(crate) metrics_listen_addr: Option<Option<String>>,
    /// Upstream top-level `grpc_listen_addr`.
    #[serde(default, skip_serializing)]
    pub(crate) grpc_listen_addr: Option<String>,
    /// Upstream top-level `grpc_allow_insecure`.
    #[serde(default, skip_serializing)]
    pub(crate) grpc_allow_insecure: Option<bool>,
    /// Upstream/top-level `trusted_proxies` CIDR list. Runtime serving keeps
    /// forwarded headers only when the direct peer is in this set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) trusted_proxies: Vec<String>,
    /// Upstream top-level update-check switch. Parsed and projected in
    /// debug config; headscale-rs does not implement release checks.
    #[serde(default, skip_serializing_if = "is_false")]
    pub(crate) disable_check_updates: bool,
    /// Upstream top-level `ephemeral_node_inactivity_timeout`.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_duration_secs_from_int_or_string",
        skip_serializing
    )]
    pub(crate) ephemeral_node_inactivity_timeout: Option<u64>,
    /// Upstream top-level Unix-socket permission.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_u32_from_int_or_string",
        skip_serializing
    )]
    pub(crate) unix_socket_permission: Option<u32>,
    /// Upstream top-level `noise` block.
    #[serde(default, skip_serializing)]
    pub(crate) noise: Option<UpstreamNoiseConfig>,
    /// Upstream top-level `prefixes` block.
    #[serde(default, skip_serializing)]
    pub(crate) prefixes: Option<UpstreamPrefixesConfig>,
    /// Upstream top-level `database` block.
    #[serde(default, skip_serializing)]
    pub(crate) database: Option<UpstreamDatabaseConfig>,
    /// Upstream top-level `derp` block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) derp: Option<DerpConfig>,
    /// Upstream top-level TLS/ACME fields used by config validation.
    #[serde(default, skip_serializing)]
    pub(crate) acme_url: Option<String>,
    #[serde(default, skip_serializing)]
    pub(crate) acme_email: Option<String>,
    #[serde(default, skip_serializing)]
    pub(crate) tls_letsencrypt_hostname: Option<String>,
    #[serde(default, skip_serializing)]
    pub(crate) tls_letsencrypt_cache_dir: Option<PathBuf>,
    #[serde(default, skip_serializing)]
    pub(crate) tls_letsencrypt_listen: Option<String>,
    #[serde(default, skip_serializing)]
    pub(crate) tls_cert_path: Option<PathBuf>,
    #[serde(default, skip_serializing)]
    pub(crate) tls_key_path: Option<PathBuf>,
    #[serde(default, skip_serializing)]
    pub(crate) tls_letsencrypt_challenge_type: Option<String>,
    /// Upstream-compatible operator CLI gRPC settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cli: Option<AdminCliConfig>,
    /// Upstream-compatible local gRPC Unix socket path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unix_socket: Option<PathBuf>,
    /// Node mode configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<NodeConfig>,
    /// Logging configuration
    #[serde(default, alias = "log", skip_serializing_if = "Option::is_none")]
    pub logging: Option<LoggingConfig>,
    /// Top-level headscale-compatible DNS configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsConfigSpec>,
    /// Upstream-compatible ACL policy serving mode.
    #[serde(default, skip_serializing_if = "policy_config_is_default")]
    pub(crate) policy: PolicyConfig,
    /// Upstream-compatible Taildrop/file-sharing switch.
    #[serde(default, skip_serializing_if = "taildrop_config_is_default")]
    pub(crate) taildrop: TaildropConfig,
    /// Upstream-compatible Logtail switch. Parsed, projected in `/debug/config`,
    /// and used to drive `MapResponse.Debug.DisableLogTail`.
    #[serde(default, skip_serializing_if = "enabled_config_is_default")]
    pub(crate) logtail: EnabledConfig,
    /// Upstream-compatible default client auto-update switch. Parsed,
    /// projected in `/debug/config`, and emitted in map-response
    /// default auto-update capabilities.
    #[serde(default, skip_serializing_if = "enabled_config_is_default")]
    pub(crate) auto_update: EnabledConfig,
    /// OpenID Connect configuration
    #[serde(default, skip_serializing_if = "oidc_config_is_default")]
    pub oidc: OidcConfig,
    /// Upstream-compatible advanced tuning block. Parsed and projected
    /// for `/debug/config`; only fields already explicitly wired by the
    /// Rust runtime affect behaviour.
    #[serde(default, skip_serializing_if = "tuning_config_is_default")]
    pub(crate) tuning: TuningConfig,
}

/// Operator CLI configuration used by upstream `headscale` admin commands.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct AdminCliConfig {
    /// Remote gRPC address. Empty means use the local Unix socket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// API key used for remote gRPC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// Disable TLS certificate verification for remote gRPC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
    /// Upstream operator CLI request timeout in seconds.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_duration_secs_from_int_or_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub timeout: Option<u64>,
}

/// Server (control plane) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ServerConfig {
    /// Listen address for the API
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Database path
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,
    /// Mesh network CIDR
    #[serde(default = "default_mesh_cidr")]
    pub mesh_cidr: String,
    /// Optional IPv6 mesh network CIDR.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_cidr_v6: Option<String>,
    /// Upstream `prefixes.allocation` strategy.
    #[serde(default = "default_ip_allocation")]
    pub ip_allocation: String,
    /// Public control server URL used for client helper pages and OIDC redirects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
    /// State directory for the Tailscale wire noise key and TLS material.
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    /// Optional HTTPS bind address for the Tailscale wire listener.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https_listen: Option<String>,
    /// Metrics/debug bind address. `None` disables the listener.
    #[serde(
        default = "default_metrics_listen_addr",
        skip_serializing_if = "Option::is_none"
    )]
    pub metrics_listen_addr: Option<String>,
    /// Optional TLS certificate DNS SAN. Defaults to the host in `server_url`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_hostname: Option<String>,
    /// Local gRPC Unix socket used by upstream-shaped admin clients.
    #[serde(default = "default_unix_socket")]
    pub unix_socket: PathBuf,
    /// Filesystem permission applied to the local gRPC Unix socket.
    #[serde(
        default = "default_unix_socket_permission",
        deserialize_with = "deserialize_u32_from_int_or_string"
    )]
    pub unix_socket_permission: u32,
    /// Optional remote gRPC TCP listen address.
    #[serde(default = "default_grpc_listen_addr")]
    pub grpc_listen_addr: String,
    /// Allow remote gRPC without TLS.
    #[serde(default)]
    pub grpc_allow_insecure: bool,
    /// DERP relay servers
    #[serde(default)]
    pub derp_servers: Vec<DerpServerConfig>,
    /// Embedded DERP/STUN runtime.
    #[serde(default, skip_serializing_if = "embedded_derp_config_is_default")]
    pub embedded_derp: EmbeddedDerpConfig,
    /// Seconds an ephemeral node may remain disconnected before deletion.
    #[serde(
        default = "default_ephemeral_node_inactivity_timeout_secs",
        rename = "ephemeral_node_inactivity_timeout",
        deserialize_with = "deserialize_duration_secs_from_int_or_string"
    )]
    pub ephemeral_node_inactivity_timeout_secs: u64,
}

/// DERP server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DerpServerConfig {
    /// Server name
    pub name: String,
    /// Server hostname
    pub hostname: String,
    /// Region name
    pub region: String,
    /// Enable STUN
    #[serde(default = "default_true")]
    pub stun_enabled: bool,
}

/// Node mode configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct NodeConfig {
    /// Control plane URL
    #[serde(default)]
    pub server: String,
    /// Node name
    #[serde(default)]
    pub name: Option<String>,
    /// WireGuard interface name
    #[serde(default = "default_wg_interface")]
    pub wg_interface: String,
    /// WireGuard listen port
    #[serde(default = "default_wg_port")]
    pub wg_port: u16,
    /// Path to identity file
    #[serde(default = "default_identity_file")]
    pub identity_file: PathBuf,
    /// Node capabilities
    #[serde(default)]
    pub capabilities: NodeCapabilities,
    /// Upstream `node.expiry` default key lifetime for non-tagged nodes.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_duration_secs_from_int_or_string"
    )]
    pub expiry: Option<u64>,
    /// Upstream ephemeral-node lifecycle settings.
    #[serde(default)]
    pub ephemeral: NodeEphemeralConfig,
    /// Upstream route lifecycle settings.
    #[serde(default)]
    pub routes: NodeRoutesConfig,
}

/// What resources this node can provide.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct NodeCapabilities {
    /// Can relay traffic for other nodes
    #[serde(default)]
    pub relay: bool,
    /// Can provide inference compute
    #[serde(default)]
    pub inference: bool,
    /// Can provide storage
    #[serde(default)]
    pub storage: bool,
    /// Can provide general compute
    #[serde(default)]
    pub compute: bool,
    /// Is a seed node
    #[serde(default)]
    pub seed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct NodeEphemeralConfig {
    #[serde(
        default,
        deserialize_with = "deserialize_optional_duration_secs_from_int_or_string"
    )]
    pub inactivity_timeout: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct NodeRoutesConfig {
    #[serde(default)]
    pub ha: NodeRoutesHaConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct NodeRoutesHaConfig {
    #[serde(
        default,
        deserialize_with = "deserialize_optional_duration_secs_from_int_or_string"
    )]
    pub probe_interval: Option<u64>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_duration_secs_from_int_or_string"
    )]
    pub probe_timeout: Option<u64>,
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LoggingConfig {
    /// Log level
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Log format
    #[serde(default = "default_log_format")]
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct UpstreamNoiseConfig {
    #[serde(default)]
    private_key_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct UpstreamPrefixesConfig {
    #[serde(default)]
    v4: Option<String>,
    #[serde(default)]
    v6: Option<String>,
    #[serde(default)]
    allocation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct UpstreamDatabaseConfig {
    #[serde(default, rename = "type")]
    database_type: Option<String>,
    #[serde(default)]
    debug: bool,
    #[serde(default)]
    gorm: UpstreamGormConfig,
    #[serde(default)]
    sqlite: Option<UpstreamSqliteConfig>,
    #[serde(default)]
    postgres: UpstreamPostgresConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub(crate) struct UpstreamGormConfig {
    #[serde(skip_serializing_if = "is_false")]
    debug: bool,
    #[serde(deserialize_with = "deserialize_duration_nanos_from_millis_or_string")]
    slow_threshold: u64,
    skip_err_record_not_found: bool,
    parameterized_queries: bool,
    prepare_stmt: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub(crate) struct UpstreamSqliteConfig {
    #[serde(default)]
    path: Option<PathBuf>,
    write_ahead_log: bool,
    wal_autocheckpoint: i32,
}

impl Default for UpstreamSqliteConfig {
    fn default() -> Self {
        Self {
            path: None,
            write_ahead_log: true,
            wal_autocheckpoint: 1000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub(crate) struct UpstreamPostgresConfig {
    host: String,
    port: i32,
    name: String,
    user: String,
    #[serde(skip_serializing, default)]
    pass: String,
    #[serde(deserialize_with = "deserialize_string_from_string_or_bool")]
    ssl: String,
    max_open_conns: i32,
    max_idle_conns: i32,
    conn_max_idle_time_secs: i32,
}

impl Default for UpstreamPostgresConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 0,
            name: String::new(),
            user: String::new(),
            pass: String::new(),
            ssl: "false".to_string(),
            max_open_conns: 10,
            max_idle_conns: 10,
            conn_max_idle_time_secs: 3600,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub(crate) struct EnabledConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub(crate) struct TuningConfig {
    #[serde(deserialize_with = "deserialize_duration_nanos_from_duration_string")]
    pub notifier_send_timeout: u64,
    #[serde(deserialize_with = "deserialize_duration_nanos_from_duration_string")]
    pub batch_change_delay: u64,
    pub node_mapsession_buffered_chan_size: i32,
    pub batcher_workers: usize,
    #[serde(deserialize_with = "deserialize_duration_nanos_from_duration_string")]
    pub register_cache_expiration: u64,
    pub register_cache_max_entries: i32,
    pub node_store_batch_size: i32,
    #[serde(deserialize_with = "deserialize_duration_nanos_from_duration_string")]
    pub node_store_batch_timeout: u64,
}

impl Default for TuningConfig {
    fn default() -> Self {
        Self {
            notifier_send_timeout: 800_000_000,
            batch_change_delay: 800_000_000,
            node_mapsession_buffered_chan_size: 30,
            batcher_workers: default_batcher_workers(),
            register_cache_expiration: 0,
            register_cache_max_entries: 0,
            node_store_batch_size: 100,
            node_store_batch_timeout: 500_000_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub(crate) struct TaildropConfig {
    pub enabled: bool,
}

impl Default for TaildropConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub(crate) struct PolicyConfig {
    pub mode: String,
    pub path: PathBuf,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            mode: "file".to_string(),
            path: PathBuf::new(),
        }
    }
}

impl PolicyConfig {
    #[cfg(test)]
    pub(crate) fn database() -> Self {
        Self {
            mode: "database".to_string(),
            path: PathBuf::new(),
        }
    }

    pub(crate) fn mode(&self) -> &str {
        self.mode.trim()
    }

    pub(crate) fn is_file_mode(&self) -> bool {
        self.mode() == "file"
    }

    #[cfg(test)]
    pub(crate) fn is_database_mode(&self) -> bool {
        self.mode() == "database"
    }

    pub(crate) fn path_if_non_empty(&self) -> Option<&Path> {
        (!self.path.as_os_str().is_empty()).then_some(self.path.as_path())
    }
}

impl CliConfig {
    /// Load configuration from a file.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let mut config = Self::parse(&contents, ConfigFormat::from_path(path))?;
        if let Some(parent) = path.parent() {
            config.resolve_config_relative_paths(parent);
        }
        config.normalize_upstream_aliases();
        config.apply_oidc_env_overrides_from(std::env::vars())?;
        config.apply_node_env_overrides_from(std::env::vars())?;
        config.apply_taildrop_env_overrides_from(std::env::vars())?;
        config.apply_dns_env_overrides_from(std::env::vars())?;
        config.apply_policy_env_overrides_from(std::env::vars());
        config.apply_server_transport_env_overrides_from(std::env::vars())?;
        config.apply_cli_env_overrides_from(std::env::vars())?;
        config.resolve_oidc_client_secret()?;
        Ok(config)
    }

    /// Load the upstream default config search path, returning defaults when
    /// no config file exists.
    pub(crate) fn load_default() -> Result<Self> {
        Self::load_default_from_dirs(default_config_dirs())
    }

    pub(crate) fn load_default_from_dirs<I, P>(dirs: I) -> Result<Self>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        for dir in dirs {
            let dir = dir.as_ref();
            for filename in DEFAULT_CONFIG_FILENAMES {
                let candidate = dir.join(filename);
                if candidate.is_file() {
                    return Self::load(&candidate).with_context(|| {
                        format!("failed to load config file {}", candidate.display())
                    });
                }
            }
        }

        let mut config = Self::default();
        config.normalize_upstream_aliases();
        config.apply_oidc_env_overrides_from(std::env::vars())?;
        config.apply_node_env_overrides_from(std::env::vars())?;
        config.apply_taildrop_env_overrides_from(std::env::vars())?;
        config.apply_dns_env_overrides_from(std::env::vars())?;
        config.apply_policy_env_overrides_from(std::env::vars());
        config.apply_server_transport_env_overrides_from(std::env::vars())?;
        config.apply_cli_env_overrides_from(std::env::vars())?;
        config.resolve_oidc_client_secret()?;
        Ok(config)
    }

    fn parse(contents: &str, format: ConfigFormat) -> Result<Self> {
        let mut config: Self = match format {
            ConfigFormat::Toml => toml::from_str(contents).context("failed to parse TOML config"),
            ConfigFormat::Yaml => {
                serde_yaml::from_str(contents).context("failed to parse YAML config")
            }
            ConfigFormat::Json => {
                serde_json::from_str(contents).context("failed to parse JSON config")
            }
        }?;
        config.normalize_upstream_aliases();
        reject_removed_config_keys(contents, format)?;
        Ok(config)
    }

    fn apply_oidc_env_overrides_from<I, K, V>(&mut self, vars: I) -> Result<()>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let vars = vars
            .into_iter()
            .map(|(key, value)| (key.as_ref().to_string(), value.as_ref().to_string()))
            .collect::<Vec<_>>();
        reject_removed_oidc_env_keys(&vars)?;
        self.oidc
            .apply_headscale_env_overrides_from(vars)
            .context("failed to apply OIDC environment overrides")
    }

    fn apply_taildrop_env_overrides_from<I, K, V>(&mut self, vars: I) -> Result<()>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        for (key, value) in vars {
            if key.as_ref() == "HEADSCALE_TAILDROP_ENABLED" {
                self.taildrop.enabled = parse_env_bool(value.as_ref())
                    .with_context(|| format!("invalid {key}", key = key.as_ref()))?;
            }
        }
        Ok(())
    }

    fn apply_node_env_overrides_from<I, K, V>(&mut self, vars: I) -> Result<()>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        for (key, value) in vars {
            if key.as_ref() == "HEADSCALE_NODE_EXPIRY" {
                let expiry = parse_duration_secs_str(value.as_ref())
                    .map_err(|err| anyhow::anyhow!("invalid {}: {err}", key.as_ref()))?;
                self.node.get_or_insert_with(NodeConfig::default).expiry = Some(expiry);
            }
        }
        Ok(())
    }

    fn apply_dns_env_overrides_from<I, K, V>(&mut self, vars: I) -> Result<()>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut saw_extra_records_env = false;
        for (key, value) in vars {
            let key = key.as_ref();
            let value = value.as_ref();
            if value.is_empty() {
                continue;
            }

            match key {
                "HEADSCALE_DNS_MAGIC_DNS" => {
                    self.dns
                        .get_or_insert_with(DnsConfigSpec::default)
                        .magic_dns =
                        parse_env_bool(value).with_context(|| format!("invalid {key}"))?;
                }
                "HEADSCALE_DNS_BASE_DOMAIN" => {
                    self.dns
                        .get_or_insert_with(DnsConfigSpec::default)
                        .base_domain = value.to_string();
                }
                "HEADSCALE_DNS_OVERRIDE_LOCAL_DNS" => {
                    self.dns
                        .get_or_insert_with(DnsConfigSpec::default)
                        .override_local_dns =
                        parse_env_bool(value).with_context(|| format!("invalid {key}"))?;
                }
                "HEADSCALE_DNS_NAMESERVERS_GLOBAL" => {
                    let dns = self.dns.get_or_insert_with(DnsConfigSpec::default);
                    dns.nameservers = parse_env_string_slice(value);
                    dns.nameserver_resolvers.clear();
                }
                "HEADSCALE_DNS_NAMESERVERS_SPLIT" => {
                    let dns = self.dns.get_or_insert_with(DnsConfigSpec::default);
                    dns.restricted_nameservers = parse_env_string_map_string_slice(value)
                        .with_context(|| format!("invalid {key}"))?;
                    dns.restricted_resolvers.clear();
                }
                "HEADSCALE_DNS_SEARCH_DOMAINS" => {
                    self.dns
                        .get_or_insert_with(DnsConfigSpec::default)
                        .search_domains = parse_env_string_slice(value);
                }
                "HEADSCALE_DNS_EXTRA_RECORDS" => {
                    let dns = self.dns.get_or_insert_with(DnsConfigSpec::default);
                    dns.extra_records = parse_extra_records(value.as_bytes())
                        .with_context(|| format!("invalid {key}"))?;
                    saw_extra_records_env = true;
                }
                "HEADSCALE_DNS_EXTRA_RECORDS_PATH" => {
                    self.dns
                        .get_or_insert_with(DnsConfigSpec::default)
                        .extra_records_path = Some(PathBuf::from(value));
                }
                _ => {}
            }
        }

        if let Some(dns) = &self.dns
            && dns.extra_records_path.is_some()
            && (saw_extra_records_env || !dns.extra_records.is_empty())
        {
            bail!(
                "fatal config error: dns.extra_records and dns.extra_records_path are mutually exclusive"
            );
        }

        Ok(())
    }

    fn apply_policy_env_overrides_from<I, K, V>(&mut self, vars: I)
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        for (key, value) in vars {
            let key = key.as_ref();
            let value = value.as_ref();
            if value.is_empty() {
                continue;
            }

            match key {
                "HEADSCALE_POLICY_MODE" => {
                    self.policy.mode = value.to_string();
                }
                "HEADSCALE_POLICY_PATH" => {
                    self.policy.path = PathBuf::from(value);
                }
                _ => {}
            }
        }
    }

    fn apply_cli_env_overrides_from<I, K, V>(&mut self, vars: I) -> Result<()>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        for (key, value) in vars {
            match key.as_ref() {
                "HEADSCALE_CLI_TIMEOUT" => {
                    let timeout = parse_duration_secs_str(value.as_ref())
                        .map_err(|err| anyhow::anyhow!("invalid {}: {err}", key.as_ref()))?;
                    self.cli.get_or_insert_with(AdminCliConfig::default).timeout = Some(timeout);
                }
                "HEADSCALE_CLI_ADDRESS" => {
                    self.cli.get_or_insert_with(AdminCliConfig::default).address =
                        Some(value.as_ref().to_string());
                }
                "HEADSCALE_CLI_API_KEY" => {
                    self.cli.get_or_insert_with(AdminCliConfig::default).api_key =
                        Some(value.as_ref().to_string());
                }
                "HEADSCALE_CLI_INSECURE" => {
                    let insecure = parse_env_bool(value.as_ref())
                        .with_context(|| format!("invalid {}", key.as_ref()))?;
                    self.cli
                        .get_or_insert_with(AdminCliConfig::default)
                        .insecure = Some(insecure);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn apply_server_transport_env_overrides_from<I, K, V>(&mut self, vars: I) -> Result<()>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        for (key, value) in vars {
            let key = key.as_ref();
            let value = value.as_ref();
            if value.is_empty() {
                continue;
            }

            match key {
                "HEADSCALE_SERVER_URL" => {
                    self.server
                        .get_or_insert_with(ServerConfig::default)
                        .server_url = Some(value.to_string());
                }
                "HEADSCALE_LISTEN_ADDR" => {
                    self.server.get_or_insert_with(ServerConfig::default).listen =
                        value.to_string();
                }
                "HEADSCALE_METRICS_LISTEN_ADDR" => {
                    self.server
                        .get_or_insert_with(ServerConfig::default)
                        .metrics_listen_addr = Some(value.to_string());
                }
                "HEADSCALE_GRPC_LISTEN_ADDR" => {
                    self.server
                        .get_or_insert_with(ServerConfig::default)
                        .grpc_listen_addr = value.to_string();
                }
                "HEADSCALE_GRPC_ALLOW_INSECURE" => {
                    let allow_insecure =
                        parse_env_bool(value).with_context(|| format!("invalid {key}"))?;
                    self.server
                        .get_or_insert_with(ServerConfig::default)
                        .grpc_allow_insecure = allow_insecure;
                }
                "HEADSCALE_UNIX_SOCKET" => {
                    let path = PathBuf::from(value);
                    self.unix_socket = Some(path.clone());
                    self.server
                        .get_or_insert_with(ServerConfig::default)
                        .unix_socket = path;
                }
                "HEADSCALE_UNIX_SOCKET_PERMISSION" => {
                    let permission = parse_u32_repr(U32Repr::String(value.to_string()))
                        .map_err(|err| anyhow::anyhow!("invalid {key}: {err}"))?;
                    self.unix_socket_permission = Some(permission);
                    self.server
                        .get_or_insert_with(ServerConfig::default)
                        .unix_socket_permission = permission;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn resolve_oidc_client_secret(&mut self) -> Result<()> {
        self.oidc
            .resolve_client_secret()
            .context("failed to resolve OIDC client secret")
    }

    fn normalize_upstream_aliases(&mut self) {
        let had_server_block = self.server.is_some();
        let has_server_alias = self.server_url.is_some()
            || self.listen_addr.is_some()
            || self.metrics_listen_addr.is_some()
            || self.grpc_listen_addr.is_some()
            || self.grpc_allow_insecure.is_some()
            || self.ephemeral_node_inactivity_timeout.is_some()
            || self
                .node
                .as_ref()
                .and_then(|node| node.ephemeral.inactivity_timeout)
                .is_some()
            || self.unix_socket.is_some()
            || self.unix_socket_permission.is_some()
            || self
                .noise
                .as_ref()
                .is_some_and(|noise| noise.private_key_path.is_some())
            || self.prefixes.as_ref().is_some_and(|prefixes| {
                prefixes.v4.is_some() || prefixes.v6.is_some() || prefixes.allocation.is_some()
            })
            || self
                .database
                .as_ref()
                .is_some_and(|database| database.sqlite_path().is_some())
            || self.derp.as_ref().is_some_and(|derp| derp.server.enabled);

        if !has_server_alias {
            return;
        }

        let mut server = self.server.take().unwrap_or_default();
        if let Some(server_url) = non_empty_clone(self.server_url.as_ref()) {
            server.server_url = Some(server_url);
        }
        if let Some(listen_addr) = non_empty_clone(self.listen_addr.as_ref()) {
            server.listen = listen_addr;
        }
        if let Some(metrics_listen_addr) = &self.metrics_listen_addr {
            server.metrics_listen_addr.clone_from(metrics_listen_addr);
        }
        if let Some(grpc_listen_addr) = non_empty_clone(self.grpc_listen_addr.as_ref()) {
            server.grpc_listen_addr = grpc_listen_addr;
        }
        if let Some(grpc_allow_insecure) = self.grpc_allow_insecure {
            server.grpc_allow_insecure = grpc_allow_insecure;
        }
        if let Some(timeout) = self.ephemeral_node_inactivity_timeout {
            server.ephemeral_node_inactivity_timeout_secs = timeout;
        }
        if let Some(timeout) = self
            .node
            .as_ref()
            .and_then(|node| node.ephemeral.inactivity_timeout)
        {
            server.ephemeral_node_inactivity_timeout_secs = timeout;
        }
        if !had_server_block && let Some(unix_socket) = self.unix_socket.clone() {
            server.unix_socket = unix_socket;
        }
        if !had_server_block && let Some(unix_socket_permission) = self.unix_socket_permission {
            server.unix_socket_permission = unix_socket_permission;
        }
        if let Some(noise_private_key_path) = self
            .noise
            .as_ref()
            .and_then(|noise| noise.private_key_path.as_ref())
        {
            server.state_dir = state_dir_from_noise_private_key(noise_private_key_path);
        }
        if let Some(prefixes) = &self.prefixes {
            let prefix_v4 = non_empty_clone(prefixes.v4.as_ref());
            let prefix_v6 = non_empty_clone(prefixes.v6.as_ref());
            if let Some(prefix_v4) = prefix_v4 {
                server.mesh_cidr = prefix_v4;
            } else if prefixes.v4.is_some() || prefix_v6.is_some() {
                server.mesh_cidr.clear();
            }
            if let Some(prefix_v6) = prefix_v6 {
                server.mesh_cidr_v6 = Some(prefix_v6);
            } else if prefixes.v6.is_some() {
                server.mesh_cidr_v6 = None;
            }
        }
        if let Some(allocation) = self
            .prefixes
            .as_ref()
            .and_then(|prefixes| prefixes.allocation.as_ref())
            && !allocation.trim().is_empty()
        {
            server.ip_allocation.clone_from(allocation);
        }
        if let Some(sqlite_path) = self
            .database
            .as_ref()
            .and_then(UpstreamDatabaseConfig::sqlite_path)
            && (!had_server_block || server.db_path == default_db_path())
        {
            server.db_path = sqlite_path;
        }
        if let Some(derp) = &self.derp
            && derp.server.enabled
            && embedded_derp_config_is_default(&server.embedded_derp)
        {
            server.embedded_derp.enabled = true;
            server.embedded_derp.region_id = derp.server.region_id;
            server
                .embedded_derp
                .region_code
                .clone_from(&derp.server.region_code);
            server
                .embedded_derp
                .region_name
                .clone_from(&derp.server.region_name);
            server.embedded_derp.stun_addr = derp.server.stun_listen_addr;
            server.embedded_derp.stun_only = true;
            server.embedded_derp.verify_clients = derp.server.verify_clients;
            server
                .embedded_derp
                .derper_config_path
                .clone_from(&derp.server.private_key_path);
            server.embedded_derp.ipv4 = derp.server.ipv4.clone().unwrap_or_default();
            server.embedded_derp.ipv6 = derp.server.ipv6.clone().unwrap_or_default();
            let (host, port) = server
                .server_url
                .as_deref()
                .and_then(host_port_from_url)
                .unwrap_or_default();
            server.embedded_derp.host_name = host;
            server.embedded_derp.derp_port = port;
        }

        self.server = Some(server);
    }

    fn resolve_config_relative_paths(&mut self, config_dir: &Path) {
        resolve_optional_path(config_dir, &mut self.tls_cert_path);
        resolve_optional_path(config_dir, &mut self.tls_key_path);
        resolve_optional_path(config_dir, &mut self.tls_letsencrypt_cache_dir);
        if let Some(noise) = &mut self.noise {
            resolve_optional_path(config_dir, &mut noise.private_key_path);
        }
        if let Some(database) = &mut self.database
            && let Some(sqlite) = &mut database.sqlite
        {
            resolve_optional_path(config_dir, &mut sqlite.path);
        }
        if let Some(derp) = &mut self.derp {
            resolve_path(config_dir, &mut derp.server.private_key_path);
        }
        if let Some(dns) = &mut self.dns {
            resolve_optional_path(config_dir, &mut dns.extra_records_path);
        }
        if let Some(server) = &mut self.server {
            resolve_path(config_dir, &mut server.db_path);
            resolve_path(config_dir, &mut server.state_dir);
            resolve_path(config_dir, &mut server.embedded_derp.derper_config_path);
        }
        if self.policy.is_file_mode() && !self.policy.path.as_os_str().is_empty() {
            resolve_path(config_dir, &mut self.policy.path);
        }
    }

    /// Save configuration to a file.
    #[allow(dead_code)]
    pub(crate) fn save(&self, path: &Path) -> Result<()> {
        let contents = toml::to_string_pretty(self)?;
        std::fs::write(path, contents)?;
        Ok(())
    }

    /// Validate the loaded config enough to catch startup-time errors without
    /// binding listeners or opening long-running services.
    pub(crate) fn validate_for_configtest(&self) -> Result<()> {
        self.oidc.validate().context("invalid OIDC configuration")?;
        self.validate_trusted_proxies()?;
        self.validate_upstream_database_config()?;
        self.validate_policy_config()?;

        let default_server = ServerConfig::default();
        let server = self.server.as_ref().unwrap_or(&default_server);
        let server_url = server.server_url.as_deref().unwrap_or("");
        self.validate_upstream_fatal_config(server, server_url)?;
        self.validate_manual_tls_paths()?;
        parse_server_url_parts(server_url)?;
        validate_socket_addr(&server.listen, "listen_addr")?;
        if let Some(https_listen) = server.https_listen.as_deref() {
            validate_socket_addr(https_listen, "https_listen")?;
        }
        validate_optional_socket_addr(
            server.metrics_listen_addr.as_deref(),
            "metrics_listen_addr",
        )?;
        validate_socket_addr(&server.grpc_listen_addr, "grpc_listen_addr")?;
        if server.ephemeral_node_inactivity_timeout_secs <= 65 {
            bail!(
                "ephemeral_node_inactivity_timeout ({}s) is set too low, must be more than 65s",
                server.ephemeral_node_inactivity_timeout_secs
            );
        }
        if !matches!(server.ip_allocation.as_str(), "" | "sequential" | "random") {
            bail!(
                "config error, prefixes.allocation is set to {}, which is not a valid strategy, allowed options: sequential, random",
                server.ip_allocation
            );
        }
        if server.mesh_cidr.trim().is_empty()
            && server
                .mesh_cidr_v6
                .as_deref()
                .is_none_or(|prefix| prefix.trim().is_empty())
        {
            bail!("config error, at least one of prefixes.v4 or prefixes.v6 must be set");
        }

        if let Some(dns) = &self.dns {
            dns.validate().context("invalid DNS configuration")?;
            validate_server_url_base_domain(server_url, &dns.base_domain)?;
        }
        if let Some(derp) = &self.derp {
            crate::derp_config::validate_static_derp_config(derp)
                .context("invalid static DERP configuration")?;
        }

        if server.embedded_derp.enabled {
            if server.embedded_derp.host_name.trim().is_empty() {
                bail!("server.embedded_derp.host_name is required when embedded DERP is enabled");
            }
            if server.embedded_derp.stun_addr.is_none() {
                bail!("server.embedded_derp.stun_addr is required when embedded DERP is enabled");
            }
            if server.embedded_derp.relay_enabled()
                && server.embedded_derp.derper_binary.as_os_str().is_empty()
            {
                bail!(
                    "server.embedded_derp.derper_binary is required when embedded DERP relay is enabled"
                );
            }
        }

        Ok(())
    }

    fn validate_trusted_proxies(&self) -> Result<()> {
        for (i, raw) in self.trusted_proxies.iter().enumerate() {
            let (addr, bits) =
                parse_ip_prefix(raw).with_context(|| format!("trusted_proxies[{i}] {raw:?}"))?;
            if bits == 0 {
                bail!("trusted_proxies[{i}] {raw:?}: 0.0.0.0/0 and ::/0 are not allowed");
            }
            let max_bits = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if bits > max_bits {
                bail!("trusted_proxies[{i}] {raw:?}: prefix length {bits} exceeds {max_bits}");
            }
        }
        Ok(())
    }

    fn validate_policy_config(&self) -> Result<()> {
        match self.policy.mode() {
            "file" => {
                let Some(path) = self.policy.path_if_non_empty() else {
                    return Ok(());
                };
                let raw = std::fs::read_to_string(path)
                    .with_context(|| format!("read policy.path {}", path.display()))?;
                headscale_api::policy::parse_hujson_policy(&raw)
                    .with_context(|| format!("parse policy.path {}", path.display()))?;
                Ok(())
            }
            "database" => Ok(()),
            mode => bail!("policy.mode must be either file or database, got {mode:?}"),
        }
    }

    fn validate_upstream_database_config(&self) -> Result<()> {
        let Some(database) = &self.database else {
            return Ok(());
        };
        let Some(database_type) = database.database_type.as_deref() else {
            bail!(
                "database.type is required when database is configured; supported values are sqlite, sqlite3, postgres"
            );
        };
        match database_type {
            "sqlite" | "sqlite3" => {
                if database.sqlite.as_ref().is_some_and(|sqlite| {
                    sqlite.wal_autocheckpoint < -1
                        || sqlite
                            .path
                            .as_ref()
                            .is_some_and(|p| p.as_os_str().is_empty())
                }) {
                    bail!(
                        "database.sqlite.path must be non-empty and database.sqlite.wal_autocheckpoint must be >= -1"
                    );
                }
                Ok(())
            }
            "postgres" => {
                if database.postgres.max_open_conns < 0
                    || database.postgres.max_idle_conns < 0
                    || database.postgres.conn_max_idle_time_secs < 0
                {
                    bail!("database.postgres connection pool fields must be >= 0");
                }
                Ok(())
            }
            other => bail!(
                "database.type {other:?} is invalid; supported values are sqlite, sqlite3, postgres"
            ),
        }
    }

    fn validate_upstream_fatal_config(
        &self,
        server: &ServerConfig,
        server_url: &str,
    ) -> Result<()> {
        let mut errors = Vec::new();

        let letsencrypt_hostname = self
            .tls_letsencrypt_hostname
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        let cert_path = self
            .tls_cert_path
            .as_ref()
            .is_some_and(|value| !value.as_os_str().is_empty());
        let key_path = self
            .tls_key_path
            .as_ref()
            .is_some_and(|value| !value.as_os_str().is_empty());
        if letsencrypt_hostname && (cert_path || key_path) {
            errors.push(
                "Fatal config error: set either tls_letsencrypt_hostname or tls_cert_path/tls_key_path, not both"
                    .to_string(),
            );
        }

        if self
            .noise
            .as_ref()
            .and_then(|noise| noise.private_key_path.as_ref())
            .is_none_or(|path| path.as_os_str().is_empty())
        {
            errors.push(MISSING_NOISE_PRIVATE_KEY_PATH_ERROR.to_string());
        }

        if let Some(challenge_type) = self
            .tls_letsencrypt_challenge_type
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            && challenge_type != "HTTP-01"
            && challenge_type != "TLS-ALPN-01"
        {
            errors.push(
                "Fatal config error: the only supported values for tls_letsencrypt_challenge_type are HTTP-01 and TLS-ALPN-01"
                    .to_string(),
            );
        }

        if !server_url.trim().starts_with("http://") && !server_url.trim().starts_with("https://") {
            errors
                .push("Fatal config error: server_url must start with https:// or http://".into());
        }

        if server.ephemeral_node_inactivity_timeout_secs <= 65 {
            errors.push(format!(
                "Fatal config error: node.ephemeral.inactivity_timeout ({}s) is set too low, must be more than 65s",
                server.ephemeral_node_inactivity_timeout_secs
            ));
        }

        let default_dns = DnsConfigSpec::default();
        let dns = self.dns.as_ref().unwrap_or(&default_dns);
        if dns.override_local_dns
            && dns.nameservers.is_empty()
            && dns.nameserver_resolvers.is_empty()
        {
            errors.push(
                "Fatal config error: dns.nameservers.global must be set when dns.override_local_dns is true"
                    .into(),
            );
        }

        if let Some(node) = &self.node
            && (node.routes.ha.probe_interval.is_some() || node.routes.ha.probe_timeout.is_some())
        {
            let interval = node
                .routes
                .ha
                .probe_interval
                .unwrap_or(DEFAULT_NODE_ROUTES_HA_PROBE_INTERVAL_SECS);
            if interval > 0 {
                if interval < 2 {
                    errors.push(format!(
                        "Fatal config error: node.routes.ha.probe_interval ({}) must be >= 2s",
                        format_go_duration_secs(interval)
                    ));
                }
                let timeout = node
                    .routes
                    .ha
                    .probe_timeout
                    .unwrap_or(DEFAULT_NODE_ROUTES_HA_PROBE_TIMEOUT_SECS);
                if timeout < 1 {
                    errors.push(format!(
                        "Fatal config error: node.routes.ha.probe_timeout ({}) must be >= 1s",
                        format_go_duration_secs(timeout)
                    ));
                }
                if timeout >= interval {
                    errors.push(format!(
                        "Fatal config error: node.routes.ha.probe_timeout ({}) must be less than node.routes.ha.probe_interval ({})",
                        format_go_duration_secs(timeout),
                        format_go_duration_secs(interval)
                    ));
                }
            }
        }

        if self.tuning.node_store_batch_size <= 0 {
            errors.push(format!(
                "Fatal config error: tuning.node_store_batch_size must be positive, got {}",
                self.tuning.node_store_batch_size
            ));
        }
        if self.tuning.node_store_batch_timeout == 0 {
            errors.push(format!(
                "Fatal config error: tuning.node_store_batch_timeout must be positive, got {}",
                format_go_duration_nanos(self.tuning.node_store_batch_timeout)
            ));
        }

        if !errors.is_empty() {
            bail!("{}", errors.join("\n"));
        }

        Ok(())
    }

    fn validate_manual_tls_paths(&self) -> Result<()> {
        let cert_path = self
            .tls_cert_path
            .as_ref()
            .is_some_and(|value| !value.as_os_str().is_empty());
        let key_path = self
            .tls_key_path
            .as_ref()
            .is_some_and(|value| !value.as_os_str().is_empty());
        if cert_path != key_path {
            bail!("tls_cert_path and tls_key_path must both be set");
        }

        Ok(())
    }
}

impl UpstreamDatabaseConfig {
    pub(crate) fn runtime_backend(&self) -> Option<DatabaseBackend> {
        match self.database_type.as_deref() {
            Some("sqlite" | "sqlite3") => Some(DatabaseBackend::Sqlite),
            Some("postgres") => Some(DatabaseBackend::Postgres),
            _ => None,
        }
    }

    fn sqlite_path(&self) -> Option<PathBuf> {
        self.sqlite
            .as_ref()
            .and_then(|sqlite| sqlite.path.as_ref())
            .filter(|path| !path.as_os_str().is_empty())
            .cloned()
    }

    pub(crate) fn debug_type(&self) -> String {
        match self.database_type.as_deref() {
            Some("sqlite") => "sqlite3".to_string(),
            Some(value) => value.to_string(),
            None => String::new(),
        }
    }

    pub(crate) fn debug_enabled(&self) -> bool {
        self.debug
    }

    pub(crate) fn debug_gorm(&self) -> &UpstreamGormConfig {
        &self.gorm
    }

    pub(crate) fn debug_sqlite(&self) -> UpstreamSqliteConfig {
        self.sqlite.clone().unwrap_or_default()
    }

    pub(crate) fn debug_postgres(&self) -> &UpstreamPostgresConfig {
        &self.postgres
    }
}

impl UpstreamGormConfig {
    pub(crate) fn debug(&self, database_debug: bool) -> bool {
        database_debug || self.debug
    }

    pub(crate) fn slow_threshold_nanos(&self) -> u64 {
        self.slow_threshold
    }

    pub(crate) fn skip_err_record_not_found(&self) -> bool {
        self.skip_err_record_not_found
    }

    pub(crate) fn parameterized_queries(&self) -> bool {
        self.parameterized_queries
    }

    pub(crate) fn prepare_stmt(&self) -> bool {
        self.prepare_stmt
    }
}

impl UpstreamSqliteConfig {
    pub(crate) fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub(crate) fn write_ahead_log(&self) -> bool {
        self.write_ahead_log
    }

    pub(crate) fn wal_autocheckpoint(&self) -> i32 {
        self.wal_autocheckpoint
    }
}

impl UpstreamPostgresConfig {
    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) fn port(&self) -> i32 {
        self.port
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn user(&self) -> &str {
        &self.user
    }

    #[cfg(feature = "postgres-sqlx")]
    pub(crate) fn pass(&self) -> &str {
        &self.pass
    }

    pub(crate) fn ssl(&self) -> &str {
        &self.ssl
    }

    pub(crate) fn max_open_conns(&self) -> i32 {
        self.max_open_conns
    }

    pub(crate) fn max_idle_conns(&self) -> i32 {
        self.max_idle_conns
    }

    pub(crate) fn conn_max_idle_time_secs(&self) -> i32 {
        self.conn_max_idle_time_secs
    }
}

#[derive(Debug, Clone, Copy)]
enum ConfigFormat {
    Toml,
    Yaml,
    Json,
}

impl ConfigFormat {
    fn from_path(path: &Path) -> Self {
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("yaml" | "yml") => Self::Yaml,
            Some("json") => Self::Json,
            _ => Self::Toml,
        }
    }
}

fn default_config_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from("/etc/headscale")];
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join(".headscale"));
    }
    dirs.push(PathBuf::from("."));
    dirs
}

fn non_empty_clone(value: Option<&String>) -> Option<String> {
    value.filter(|value| !value.trim().is_empty()).cloned()
}

fn resolve_optional_path(config_dir: &Path, path: &mut Option<PathBuf>) {
    let Some(value) = path else {
        return;
    };
    resolve_path(config_dir, value);
}

fn resolve_path(config_dir: &Path, path: &mut PathBuf) {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return;
    }
    *path = config_dir.join(&*path);
}

fn state_dir_from_noise_private_key(path: &Path) -> PathBuf {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServerUrlParts {
    host: String,
    port: u16,
}

fn parse_server_url_parts(raw: &str) -> Result<ServerUrlParts> {
    let raw = raw.trim();
    if !raw.starts_with("http://") && !raw.starts_with("https://") {
        bail!("server.server_url must start with https:// or http://");
    }

    let parsed = url::Url::parse(raw)
        .with_context(|| format!("server.server_url must be a valid URL: {raw:?}"))?;
    let host = parsed
        .host()
        .map(|host| match host {
            url::Host::Domain(domain) => domain.to_string(),
            url::Host::Ipv4(addr) => addr.to_string(),
            url::Host::Ipv6(addr) => addr.to_string(),
        })
        .filter(|host| !host.trim().is_empty())
        .with_context(|| format!("server.server_url must include a host: {raw:?}"))?;
    let port = parsed
        .port_or_known_default()
        .with_context(|| format!("server.server_url must include a valid port: {raw:?}"))?;

    Ok(ServerUrlParts { host, port })
}

pub(crate) fn validate_server_url_base_domain(server_url: &str, base_domain: &str) -> Result<()> {
    let base_domain = base_domain.trim();
    if base_domain.is_empty() {
        return Ok(());
    }

    parse_server_url_parts(server_url)?;
    let (server_host, server_hostname) = raw_server_url_hosts(server_url)
        .with_context(|| format!("server.server_url must include a host: {server_url:?}"))?;

    if server_hostname == base_domain {
        bail!(
            "server_url cannot use the same domain as base_domain in a way that could make the DERP and headscale server unreachable"
        );
    }

    let server_domain_parts: Vec<_> = server_host.split('.').collect();
    let base_domain_parts: Vec<_> = base_domain.split('.').collect();
    if server_domain_parts.len() <= base_domain_parts.len() {
        return Ok(());
    }

    for i in 0..base_domain_parts.len() {
        if server_domain_parts[server_domain_parts.len() - i - 1]
            != base_domain_parts[base_domain_parts.len() - i - 1]
        {
            return Ok(());
        }
    }

    bail!(
        "server_url cannot be part of base_domain in a way that could make the DERP and headscale server unreachable"
    );
}

fn raw_server_url_hosts(raw: &str) -> Option<(String, String)> {
    let raw = raw.trim();
    let after_scheme = raw
        .strip_prefix("http://")
        .or_else(|| raw.strip_prefix("https://"))?;
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or(authority);
    if host.is_empty() {
        return None;
    }

    let hostname = if let Some(without_open_bracket) = host.strip_prefix('[') {
        without_open_bracket
            .split_once(']')
            .map(|(hostname, _)| hostname.to_string())?
    } else if let Some((hostname, _)) = host.rsplit_once(':') {
        hostname.to_string()
    } else {
        host.to_string()
    };

    if hostname.is_empty() {
        return None;
    }

    Some((host.to_string(), hostname))
}

fn validate_socket_addr(value: &str, field: &str) -> Result<()> {
    let normalized;
    let value = if value.starts_with(':') {
        normalized = format!("0.0.0.0{value}");
        normalized.as_str()
    } else {
        value
    };
    value
        .parse::<SocketAddr>()
        .with_context(|| format!("Invalid {field} address: {value}"))?;
    Ok(())
}

fn validate_optional_socket_addr(value: Option<&str>, field: &str) -> Result<()> {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        validate_socket_addr(value, field)?;
    }
    Ok(())
}

pub(crate) fn server_url_hostname(raw: &str) -> Option<String> {
    parse_server_url_parts(raw).ok().map(|parts| parts.host)
}

fn host_port_from_url(url: &str) -> Option<(String, u16)> {
    parse_server_url_parts(url)
        .ok()
        .map(|parts| (parts.host, parts.port))
}

#[derive(Clone, Copy)]
struct RemovedConfigKey {
    path: &'static [&'static str],
    display: &'static str,
    replacement: Option<&'static str>,
    hint: Option<&'static str>,
}

const REMOVED_CONFIG_KEYS: &[RemovedConfigKey] = &[
    RemovedConfigKey {
        path: &["acl_policy_path"],
        display: "acl_policy_path",
        replacement: Some("policy.path"),
        hint: None,
    },
    RemovedConfigKey {
        path: &["dns_config", "magic_dns"],
        display: "dns_config.magic_dns",
        replacement: Some("dns.magic_dns"),
        hint: None,
    },
    RemovedConfigKey {
        path: &["dns_config", "base_domain"],
        display: "dns_config.base_domain",
        replacement: Some("dns.base_domain"),
        hint: None,
    },
    RemovedConfigKey {
        path: &["dns_config", "override_local_dns"],
        display: "dns_config.override_local_dns",
        replacement: Some("dns.override_local_dns"),
        hint: None,
    },
    RemovedConfigKey {
        path: &["dns_config", "nameservers"],
        display: "dns_config.nameservers",
        replacement: Some("dns.nameservers.global"),
        hint: None,
    },
    RemovedConfigKey {
        path: &["dns_config", "restricted_nameservers"],
        display: "dns_config.restricted_nameservers",
        replacement: Some("dns.nameservers.split"),
        hint: None,
    },
    RemovedConfigKey {
        path: &["dns_config", "domains"],
        display: "dns_config.domains",
        replacement: Some("dns.search_domains"),
        hint: None,
    },
    RemovedConfigKey {
        path: &["dns_config", "extra_records"],
        display: "dns_config.extra_records",
        replacement: Some("dns.extra_records"),
        hint: None,
    },
    RemovedConfigKey {
        path: &["dns", "use_username_in_magic_dns"],
        display: "dns.use_username_in_magic_dns",
        replacement: None,
        hint: None,
    },
    RemovedConfigKey {
        path: &["dns_config", "use_username_in_magic_dns"],
        display: "dns_config.use_username_in_magic_dns",
        replacement: None,
        hint: None,
    },
    RemovedConfigKey {
        path: &["oidc", "strip_email_domain"],
        display: "oidc.strip_email_domain",
        replacement: None,
        hint: None,
    },
    RemovedConfigKey {
        path: &["oidc", "map_legacy_users"],
        display: "oidc.map_legacy_users",
        replacement: None,
        hint: None,
    },
    RemovedConfigKey {
        path: &["oidc", "expiry"],
        display: "oidc.expiry",
        replacement: Some("node.expiry"),
        hint: None,
    },
    RemovedConfigKey {
        path: &["randomize_client_port"],
        display: "randomize_client_port",
        replacement: None,
        hint: Some(
            r#"Set "randomizeClientPort": true at the top level of your policy file (see policy.path / policy.mode), or grant the cap per-node via a "nodeAttrs" entry. See CHANGELOG.md (BREAKING / Configuration)."#,
        ),
    },
];

const REMOVED_OIDC_ENV_KEYS: &[(&str, &str)] = &[(
    "HEADSCALE_OIDC_EXPIRY",
    "oidc.expiry was removed; use node.expiry instead",
)];

fn reject_removed_config_keys(contents: &str, format: ConfigFormat) -> Result<()> {
    match format {
        ConfigFormat::Toml => {
            let value: toml::Value =
                toml::from_str(contents).context("failed to parse TOML config")?;
            for key in REMOVED_CONFIG_KEYS {
                if toml_has_path(&value, key.path) {
                    bail!("{}", removed_config_key_message(*key));
                }
            }
        }
        ConfigFormat::Yaml => {
            let value: serde_yaml::Value =
                serde_yaml::from_str(contents).context("failed to parse YAML config")?;
            for key in REMOVED_CONFIG_KEYS {
                if yaml_has_path(&value, key.path) {
                    bail!("{}", removed_config_key_message(*key));
                }
            }
        }
        ConfigFormat::Json => {
            let value: serde_json::Value =
                serde_json::from_str(contents).context("failed to parse JSON config")?;
            for key in REMOVED_CONFIG_KEYS {
                if json_has_path(&value, key.path) {
                    bail!("{}", removed_config_key_message(*key));
                }
            }
        }
    }

    Ok(())
}

fn reject_removed_oidc_env_keys(vars: &[(String, String)]) -> Result<()> {
    for (key, _) in vars {
        if let Some((_, message)) = REMOVED_OIDC_ENV_KEYS
            .iter()
            .find(|(removed_key, _)| key == removed_key)
        {
            bail!("{message}");
        }
    }

    Ok(())
}

fn removed_config_key_message(key: RemovedConfigKey) -> String {
    match (key.replacement, key.hint) {
        (Some(replacement), Some(hint)) => format!(
            "The \"{}\" configuration key has been removed. Please use \"{}\" instead. {}",
            key.display, replacement, hint
        ),
        (Some(replacement), None) => format!(
            "The \"{}\" configuration key has been removed. Please use \"{}\" instead.",
            key.display, replacement
        ),
        (None, Some(hint)) => format!(
            "The \"{}\" configuration key has been removed. {}",
            key.display, hint
        ),
        (None, None) => format!(
            "The \"{}\" configuration key has been removed. Please see the changelog for more details.",
            key.display
        ),
    }
}

fn toml_has_path(value: &toml::Value, path: &[&str]) -> bool {
    let Some((first, rest)) = path.split_first() else {
        return true;
    };
    value
        .get(*first)
        .is_some_and(|value| toml_has_path(value, rest))
}

fn json_has_path(value: &serde_json::Value, path: &[&str]) -> bool {
    let Some((first, rest)) = path.split_first() else {
        return true;
    };
    value
        .get(*first)
        .is_some_and(|value| json_has_path(value, rest))
}

fn yaml_has_path(value: &serde_yaml::Value, path: &[&str]) -> bool {
    let Some((first, rest)) = path.split_first() else {
        return true;
    };
    let serde_yaml::Value::Mapping(mapping) = value else {
        return false;
    };
    mapping
        .get(serde_yaml::Value::String((*first).to_string()))
        .is_some_and(|value| yaml_has_path(value, rest))
}

fn deserialize_u32_from_int_or_string<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let value = U32Repr::deserialize(deserializer)?;
    parse_u32_repr(value).map_err(de::Error::custom)
}

fn deserialize_optional_u32_from_int_or_string<'de, D>(
    deserializer: D,
) -> Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(value) = Option::<U32Repr>::deserialize(deserializer)? else {
        return Ok(None);
    };
    parse_u32_repr(value).map(Some).map_err(de::Error::custom)
}

pub(crate) fn deserialize_duration_secs_from_int_or_string<'de, D>(
    deserializer: D,
) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = DurationRepr::deserialize(deserializer)?;
    parse_duration_secs_repr(value).map_err(de::Error::custom)
}

fn deserialize_optional_duration_secs_from_int_or_string<'de, D>(
    deserializer: D,
) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(value) = Option::<DurationRepr>::deserialize(deserializer)? else {
        return Ok(None);
    };
    parse_duration_secs_repr(value)
        .map(Some)
        .map_err(de::Error::custom)
}

fn deserialize_duration_nanos_from_millis_or_string<'de, D>(
    deserializer: D,
) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = DurationRepr::deserialize(deserializer)?;
    parse_duration_nanos_repr(value, NumericDurationUnit::Millis).map_err(de::Error::custom)
}

fn deserialize_duration_nanos_from_duration_string<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = DurationRepr::deserialize(deserializer)?;
    parse_duration_nanos_repr(value, NumericDurationUnit::Nanos).map_err(de::Error::custom)
}

fn deserialize_string_from_string_or_bool<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrBool {
        String(String),
        Bool(bool),
    }

    match StringOrBool::deserialize(deserializer)? {
        StringOrBool::String(value) => Ok(value),
        StringOrBool::Bool(value) => Ok(value.to_string()),
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum U32Repr {
    Int(u32),
    String(String),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DurationRepr {
    Int(u64),
    String(String),
}

fn parse_u32_repr(value: U32Repr) -> Result<u32, String> {
    match value {
        U32Repr::Int(value) => Ok(value),
        U32Repr::String(value) => {
            let trimmed = value.trim();
            if let Some(octal) = trimmed
                .strip_prefix("0o")
                .or_else(|| trimmed.strip_prefix("0O"))
            {
                u32::from_str_radix(octal, 8)
                    .map_err(|err| format!("invalid octal permission {trimmed:?}: {err}"))
            } else if trimmed.starts_with('0')
                && trimmed.len() > 1
                && trimmed.chars().all(|ch| matches!(ch, '0'..='7'))
            {
                u32::from_str_radix(trimmed, 8)
                    .map_err(|err| format!("invalid octal permission {trimmed:?}: {err}"))
            } else {
                trimmed
                    .parse::<u32>()
                    .map_err(|err| format!("invalid integer permission {trimmed:?}: {err}"))
            }
        }
    }
}

fn parse_duration_secs_repr(value: DurationRepr) -> Result<u64, String> {
    match value {
        DurationRepr::Int(value) => Ok(value),
        DurationRepr::String(value) => parse_duration_secs_str(&value),
    }
}

#[derive(Clone, Copy)]
enum NumericDurationUnit {
    Nanos,
    Millis,
}

fn parse_duration_nanos_repr(
    value: DurationRepr,
    numeric_unit: NumericDurationUnit,
) -> Result<u64, String> {
    match value {
        DurationRepr::Int(value) => match numeric_unit {
            NumericDurationUnit::Nanos => Ok(value),
            NumericDurationUnit::Millis => value
                .checked_mul(1_000_000)
                .ok_or_else(|| format!("duration {value}ms overflows u64 nanoseconds")),
        },
        DurationRepr::String(value) => parse_duration_nanos_str(&value),
    }
}

fn parse_duration_nanos_str(value: &str) -> Result<u64, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("duration cannot be empty".into());
    }
    let (number, multiplier) = if let Some(number) = trimmed.strip_suffix("ms") {
        (number, 1_000_000)
    } else if let Some(number) = trimmed.strip_suffix('s') {
        (number, 1_000_000_000)
    } else if let Some(number) = trimmed.strip_suffix('m') {
        (number, 60_000_000_000)
    } else if let Some(number) = trimmed.strip_suffix('h') {
        (number, 3_600_000_000_000)
    } else if let Some(number) = trimmed.strip_suffix('d') {
        (number, 86_400_000_000_000)
    } else {
        return trimmed
            .parse::<u64>()
            .map_err(|err| format!("invalid duration {trimmed:?}: {err}"));
    };
    let n = number
        .parse::<u64>()
        .map_err(|err| format!("invalid duration magnitude {number:?}: {err}"))?;
    n.checked_mul(multiplier)
        .ok_or_else(|| format!("duration {trimmed:?} overflows u64 nanoseconds"))
}

fn format_go_duration_secs(seconds: u64) -> String {
    format!("{seconds}s")
}

fn format_go_duration_nanos(nanos: u64) -> String {
    if nanos == 0 {
        return "0s".to_string();
    }
    if nanos.is_multiple_of(1_000_000_000) {
        return format!("{}s", nanos / 1_000_000_000);
    }
    if nanos.is_multiple_of(1_000_000) {
        return format!("{}ms", nanos / 1_000_000);
    }
    format!("{nanos}ns")
}

pub(crate) fn parse_duration_secs_str(value: &str) -> Result<u64, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("duration cannot be empty".into());
    }
    let (number, multiplier) = if let Some(number) = trimmed.strip_suffix("ms") {
        let value = number
            .parse::<u64>()
            .map_err(|err| format!("invalid duration magnitude {number:?}: {err}"))?;
        if value % 1000 != 0 {
            return Err("duration must resolve to whole seconds".into());
        }
        return Ok(value / 1000);
    } else if let Some(number) = trimmed.strip_suffix('s') {
        (number, 1)
    } else if let Some(number) = trimmed.strip_suffix('m') {
        (number, 60)
    } else if let Some(number) = trimmed.strip_suffix('h') {
        (number, 3_600)
    } else if let Some(number) = trimmed.strip_suffix('d') {
        (number, 86_400)
    } else {
        return trimmed
            .parse::<u64>()
            .map_err(|err| format!("invalid duration {trimmed:?}: {err}"));
    };
    let n = number
        .parse::<u64>()
        .map_err(|err| format!("invalid duration magnitude {number:?}: {err}"))?;
    n.checked_mul(multiplier)
        .ok_or_else(|| format!("duration {trimmed:?} overflows u64 seconds"))
}

fn parse_ip_prefix(raw: &str) -> Result<(IpAddr, u8)> {
    let (addr, bits) = raw
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("missing prefix length"))?;
    let addr: IpAddr = addr
        .parse()
        .with_context(|| format!("invalid IP address {addr:?}"))?;
    let bits: u8 = bits
        .parse()
        .with_context(|| format!("invalid prefix length {bits:?}"))?;
    Ok((addr, bits))
}

fn parse_env_bool(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "t" | "true" | "y" | "yes" | "on" => Ok(true),
        "0" | "f" | "false" | "n" | "no" | "off" => Ok(false),
        value => bail!("invalid boolean value {value:?}"),
    }
}

fn parse_env_string_slice(value: &str) -> Vec<String> {
    value.split_whitespace().map(ToString::to_string).collect()
}

fn parse_env_string_map_string_slice(
    value: &str,
) -> Result<std::collections::HashMap<String, Vec<String>>> {
    let value: serde_json::Value = serde_json::from_str(value).context("expected JSON object")?;
    let Some(object) = value.as_object() else {
        bail!("expected JSON object");
    };

    let mut out = std::collections::HashMap::new();
    for (key, value) in object {
        let values = match value {
            serde_json::Value::Array(values) => values.iter().map(json_value_to_string).collect(),
            other => vec![json_value_to_string(other)],
        };
        out.insert(key.clone(), values);
    }
    Ok(out)
}

fn json_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => value.to_string(),
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn oidc_config_is_default(config: &OidcConfig) -> bool {
    config == &OidcConfig::default()
}

fn taildrop_config_is_default(config: &TaildropConfig) -> bool {
    config == &TaildropConfig::default()
}

fn enabled_config_is_default(config: &EnabledConfig) -> bool {
    config == &EnabledConfig::default()
}

fn tuning_config_is_default(config: &TuningConfig) -> bool {
    config == &TuningConfig::default()
}

fn policy_config_is_default(config: &PolicyConfig) -> bool {
    config == &PolicyConfig::default()
}

fn embedded_derp_config_is_default(config: &EmbeddedDerpConfig) -> bool {
    config == &EmbeddedDerpConfig::default()
}

// Default value functions for serde
fn default_listen() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_db_path() -> PathBuf {
    PathBuf::from("/var/lib/headscale/db.sqlite")
}

fn default_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/headscale")
}

fn default_unix_socket() -> PathBuf {
    PathBuf::from("/var/run/headscale/headscale.sock")
}

fn default_unix_socket_permission() -> u32 {
    0o770
}

fn default_grpc_listen_addr() -> String {
    ":50443".to_string()
}

fn default_metrics_listen_addr() -> Option<String> {
    None
}

fn default_ephemeral_node_inactivity_timeout_secs() -> u64 {
    120
}

pub(crate) fn default_cli_timeout_secs() -> u64 {
    DEFAULT_CLI_TIMEOUT_SECS
}

fn default_mesh_cidr() -> String {
    "100.64.0.0/10".to_string()
}

fn default_ip_allocation() -> String {
    "sequential".to_string()
}

fn default_wg_interface() -> String {
    "wg0".to_string()
}

fn default_wg_port() -> u16 {
    51820
}

fn default_identity_file() -> PathBuf {
    PathBuf::from("identity.json")
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "text".to_string()
}

fn default_true() -> bool {
    true
}

fn default_batcher_workers() -> usize {
    std::thread::available_parallelism().map_or(1, |cpus| (cpus.get() * 3 / 4).max(1))
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            db_path: default_db_path(),
            mesh_cidr: default_mesh_cidr(),
            mesh_cidr_v6: None,
            ip_allocation: default_ip_allocation(),
            server_url: None,
            state_dir: default_state_dir(),
            https_listen: None,
            metrics_listen_addr: default_metrics_listen_addr(),
            tls_hostname: None,
            unix_socket: default_unix_socket(),
            unix_socket_permission: default_unix_socket_permission(),
            grpc_listen_addr: default_grpc_listen_addr(),
            grpc_allow_insecure: false,
            derp_servers: Vec::new(),
            embedded_derp: EmbeddedDerpConfig::default(),
            ephemeral_node_inactivity_timeout_secs: default_ephemeral_node_inactivity_timeout_secs(
            ),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn cli_config_includes_upstream_oidc_defaults() {
        let config = CliConfig::default();

        assert_eq!(LoggingConfig::default().format, "text");
        assert!(config.taildrop.enabled);
        assert!(config.oidc.only_start_if_oidc_is_available);
        assert_eq!(config.oidc.scope, ["openid", "profile", "email"]);
        assert!(config.oidc.email_verified_required);
        assert!(!config.oidc.use_expiry_from_token);
        assert!(!config.oidc.pkce.enabled);
        assert_eq!(config.oidc.pkce.method, "S256");
    }

    #[test]
    fn loads_upstream_taildrop_config() {
        let source = r"
taildrop:
  enabled: false
";

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();

        assert!(!config.taildrop.enabled);
    }

    #[test]
    fn applies_headscale_taildrop_env_override_to_cli_config() {
        let mut config = CliConfig::default();

        config
            .apply_taildrop_env_overrides_from([("HEADSCALE_TAILDROP_ENABLED", "false")])
            .unwrap();

        assert!(!config.taildrop.enabled);

        let err = config
            .apply_taildrop_env_overrides_from([("HEADSCALE_TAILDROP_ENABLED", "maybe")])
            .unwrap_err();

        assert!(format!("{err:#}").contains("invalid HEADSCALE_TAILDROP_ENABLED"));
    }

    #[test]
    fn loads_upstream_node_lifecycle_config_without_node_mode_server() {
        let source = r#"
server_url: "https://headscale.example"

node:
  expiry: 180d
  ephemeral:
    inactivity_timeout: 30m
  routes:
    ha:
      probe_interval: 15s
      probe_timeout: 4s
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let node = config.node.as_ref().expect("node block parsed");
        assert_eq!(node.server, "");
        assert_eq!(node.expiry, Some(180 * 24 * 60 * 60));
        assert_eq!(node.ephemeral.inactivity_timeout, Some(30 * 60));
        assert_eq!(node.routes.ha.probe_interval, Some(15));
        assert_eq!(node.routes.ha.probe_timeout, Some(4));
        assert_eq!(
            config
                .server
                .as_ref()
                .unwrap()
                .ephemeral_node_inactivity_timeout_secs,
            30 * 60
        );
    }

    #[test]
    fn node_expiry_zero_disables_default_expiry() {
        let source = r"
[node]
expiry = 0
";

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();

        assert_eq!(config.node.as_ref().unwrap().expiry, Some(0));
    }

    #[test]
    fn applies_headscale_node_expiry_env_override_to_cli_config() {
        let mut config = CliConfig::default();

        config
            .apply_node_env_overrides_from([("HEADSCALE_NODE_EXPIRY", "14d")])
            .unwrap();

        assert_eq!(
            config.node.as_ref().unwrap().expiry,
            Some(14 * 24 * 60 * 60)
        );

        let err = config
            .apply_node_env_overrides_from([("HEADSCALE_NODE_EXPIRY", "1ms")])
            .unwrap_err();

        assert!(format!("{err:#}").contains("invalid HEADSCALE_NODE_EXPIRY"));
    }

    #[test]
    fn applies_headscale_dns_env_overrides_to_cli_config() {
        let mut config = CliConfig::default();

        config
            .apply_dns_env_overrides_from([
                ("HEADSCALE_DNS_MAGIC_DNS", "false"),
                ("HEADSCALE_DNS_BASE_DOMAIN", "tail.example.org"),
                ("HEADSCALE_DNS_OVERRIDE_LOCAL_DNS", "true"),
                (
                    "HEADSCALE_DNS_NAMESERVERS_GLOBAL",
                    "1.1.1.1 https://dns.example/dns-query",
                ),
                (
                    "HEADSCALE_DNS_NAMESERVERS_SPLIT",
                    r#"{"corp.example.org":["10.0.0.53"],"dev.example.org":"10.0.0.54"}"#,
                ),
                (
                    "HEADSCALE_DNS_SEARCH_DOMAINS",
                    "corp.example.org dev.example.org",
                ),
                (
                    "HEADSCALE_DNS_EXTRA_RECORDS",
                    r#"[{"name":"app.tail.example.org","type":"A","value":"100.64.0.50"}]"#,
                ),
            ])
            .unwrap();

        let dns = config.dns.as_ref().unwrap();
        assert!(!dns.magic_dns);
        assert_eq!(dns.base_domain, "tail.example.org");
        assert!(dns.override_local_dns);
        assert_eq!(
            dns.nameservers,
            ["1.1.1.1", "https://dns.example/dns-query"]
        );
        assert!(dns.nameserver_resolvers.is_empty());
        assert_eq!(
            dns.restricted_nameservers.get("corp.example.org").unwrap(),
            &vec!["10.0.0.53".to_string()]
        );
        assert_eq!(
            dns.restricted_nameservers.get("dev.example.org").unwrap(),
            &vec!["10.0.0.54".to_string()]
        );
        assert!(dns.restricted_resolvers.is_empty());
        assert_eq!(dns.search_domains, ["corp.example.org", "dev.example.org"]);
        assert_eq!(dns.extra_records.len(), 1);
        assert_eq!(dns.extra_records[0].name, "app.tail.example.org");
        assert_eq!(dns.extra_records[0].record_type, "A");
        assert_eq!(dns.extra_records[0].value, "100.64.0.50");

        let mut config = CliConfig::default();
        config
            .apply_dns_env_overrides_from([(
                "HEADSCALE_DNS_EXTRA_RECORDS_PATH",
                "/etc/headscale/records.json",
            )])
            .unwrap();
        assert_eq!(
            config.dns.unwrap().extra_records_path.as_deref(),
            Some(Path::new("/etc/headscale/records.json"))
        );
    }

    #[test]
    fn rejects_invalid_headscale_dns_env_overrides() {
        let mut config = CliConfig::default();

        let err = config
            .apply_dns_env_overrides_from([("HEADSCALE_DNS_MAGIC_DNS", "maybe")])
            .unwrap_err();

        assert!(format!("{err:#}").contains("invalid HEADSCALE_DNS_MAGIC_DNS"));

        let err = config
            .apply_dns_env_overrides_from([("HEADSCALE_DNS_NAMESERVERS_SPLIT", "not-json")])
            .unwrap_err();

        assert!(format!("{err:#}").contains("invalid HEADSCALE_DNS_NAMESERVERS_SPLIT"));
    }

    #[test]
    fn configtest_rejects_invalid_node_route_ha_timing() {
        let source = r#"
server_url: "https://headscale.example"

node:
  routes:
    ha:
      probe_interval: 5s
      probe_timeout: 5s
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let err = config.validate_for_configtest().unwrap_err();

        assert!(format!("{err:#}").contains("node.routes.ha.probe_timeout"));
    }

    #[test]
    fn configtest_rejects_timeout_only_node_route_ha_timing_against_defaults() {
        for (timeout, expected) in [
            ("0s", "node.routes.ha.probe_timeout (0s) must be >= 1s"),
            (
                "10s",
                "node.routes.ha.probe_timeout (10s) must be less than node.routes.ha.probe_interval (10s)",
            ),
        ] {
            let source = format!(
                r#"
server_url: "https://headscale.example"

node:
  routes:
    ha:
      probe_timeout: {timeout}
"#
            );

            let config = CliConfig::parse(&source, ConfigFormat::Yaml).unwrap();
            let err = config.validate_for_configtest().unwrap_err();
            let message = format!("{err:#}");

            assert!(
                message.contains(expected),
                "expected {expected:?} in {message:?}"
            );
        }
    }

    #[test]
    fn loads_remaining_current_upstream_schema_fields() {
        let source = r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
trusted_proxies:
  - "127.0.0.1/32"
  - "fd7a:115c:a1e0::/48"
disable_check_updates: true

logtail:
  enabled: true

auto_update:
  enabled: true

tuning:
  notifier_send_timeout: 900ms
  batch_change_delay: 700ms
  node_mapsession_buffered_chan_size: 42
  batcher_workers: 2
  register_cache_expiration: 5m
  register_cache_max_entries: 2048
  node_store_batch_size: 128
  node_store_batch_timeout: 250ms

database:
  type: sqlite
  debug: true
  gorm:
    prepare_stmt: true
    parameterized_queries: true
    skip_err_record_not_found: true
    slow_threshold: 1000
  sqlite:
    path: "/srv/headscale/db.sqlite"
    write_ahead_log: false
    wal_autocheckpoint: 250
  postgres:
    host: localhost
    port: 5432
    name: headscale
    user: headscale
    pass: secret
    ssl: verify-full
    max_open_conns: 11
    max_idle_conns: 7
    conn_max_idle_time_secs: 120
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        config.validate_for_configtest().unwrap();

        assert_eq!(
            config.trusted_proxies,
            ["127.0.0.1/32", "fd7a:115c:a1e0::/48"]
        );
        assert!(config.disable_check_updates);
        assert!(config.logtail.enabled);
        assert!(config.auto_update.enabled);
        assert_eq!(config.tuning.notifier_send_timeout, 900_000_000);
        assert_eq!(config.tuning.node_mapsession_buffered_chan_size, 42);
        assert_eq!(config.tuning.register_cache_max_entries, 2048);
        assert_eq!(config.tuning.node_store_batch_timeout, 250_000_000);

        let database = config.database.as_ref().unwrap();
        assert_eq!(database.runtime_backend(), Some(DatabaseBackend::Sqlite));
        assert_eq!(database.debug_type(), "sqlite3");
        assert!(database.debug_enabled());
        assert_eq!(database.debug_gorm().slow_threshold_nanos(), 1_000_000_000);
        assert!(database.debug_gorm().prepare_stmt());
        assert!(!database.debug_sqlite().write_ahead_log());
        assert_eq!(database.debug_sqlite().wal_autocheckpoint(), 250);
        assert_eq!(database.debug_postgres().ssl(), "verify-full");
        assert_eq!(database.debug_postgres().max_open_conns(), 11);
    }

    #[test]
    fn configtest_rejects_unsafe_or_malformed_trusted_proxies() {
        let config = CliConfig::parse(
            r#"
server_url: "https://headscale.example"
trusted_proxies:
  - "0.0.0.0/0"
"#,
            ConfigFormat::Yaml,
        )
        .unwrap();

        let err = config.validate_for_configtest().unwrap_err();
        assert!(format!("{err:#}").contains("trusted_proxies[0]"));

        let config = CliConfig::parse(
            r#"
server_url: "https://headscale.example"
trusted_proxies:
  - "127.0.0.1"
"#,
            ConfigFormat::Yaml,
        )
        .unwrap();

        let err = config.validate_for_configtest().unwrap_err();
        assert!(format!("{err:#}").contains("missing prefix length"));
    }

    #[test]
    fn loads_upstream_oidc_toml_and_resolves_secret_path() {
        let dir = tempfile::tempdir().unwrap();
        let secret_path = dir.path().join("oidc-client-secret");
        fs::write(&secret_path, "  super-secret\n").unwrap();

        let source = format!(
            r#"
[oidc]
only_start_if_oidc_is_available = false
issuer = "https://issuer.example"
client_id = "headscale-rs"
client_secret_path = "{}"
use_expiry_from_token = true
scope = ["openid", "profile", "email", "groups"]
allowed_domains = ["example.com"]
allowed_users = ["alice@example.com"]
allowed_groups = ["/headscale"]
email_verified_required = false

[oidc.extra_params]
domain_hint = "example.com"

[oidc.pkce]
enabled = true
method = "plain"
"#,
            secret_path.display()
        );

        let mut config = CliConfig::parse(&source, ConfigFormat::Toml).unwrap();
        config.resolve_oidc_client_secret().unwrap();

        assert!(!config.oidc.only_start_if_oidc_is_available);
        assert_eq!(config.oidc.issuer, "https://issuer.example");
        assert_eq!(config.oidc.client_id, "headscale-rs");
        assert_eq!(config.oidc.client_secret, "super-secret");
        assert!(config.oidc.client_secret_path.is_none());
        assert_eq!(config.oidc.scope, ["openid", "profile", "email", "groups"]);
        assert_eq!(config.oidc.allowed_domains, ["example.com"]);
        assert_eq!(config.oidc.allowed_users, ["alice@example.com"]);
        assert_eq!(config.oidc.allowed_groups, ["/headscale"]);
        assert_eq!(
            config
                .oidc
                .extra_params
                .get("domain_hint")
                .map(String::as_str),
            Some("example.com")
        );
        assert!(!config.oidc.email_verified_required);
        assert!(config.oidc.use_expiry_from_token);
        assert!(config.oidc.pkce.enabled);
        assert_eq!(config.oidc.pkce.method, "plain");
    }

    #[test]
    fn loads_server_wire_runtime_fields() {
        let source = r#"
unix_socket = "/run/headscale/admin.sock"

[server]
listen = "127.0.0.1:51821"
https_listen = "0.0.0.0:443"
metrics_listen_addr = "127.0.0.1:9090"
server_url = "https://headscale.example"
state_dir = "/srv/headscale"
tls_hostname = "headscale.example"
unix_socket = "/srv/headscale/headscale.sock"
unix_socket_permission = 448
grpc_listen_addr = "127.0.0.1:50443"
grpc_allow_insecure = true
ephemeral_node_inactivity_timeout = "5m"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        assert_eq!(
            config.unix_socket.as_deref(),
            Some(Path::new("/run/headscale/admin.sock"))
        );
        let server = config.server.unwrap();

        assert_eq!(server.listen, "127.0.0.1:51821");
        assert_eq!(server.https_listen.as_deref(), Some("0.0.0.0:443"));
        assert_eq!(
            server.metrics_listen_addr.as_deref(),
            Some("127.0.0.1:9090")
        );
        assert_eq!(
            server.server_url.as_deref(),
            Some("https://headscale.example")
        );
        assert_eq!(server.state_dir, PathBuf::from("/srv/headscale"));
        assert_eq!(server.tls_hostname.as_deref(), Some("headscale.example"));
        assert_eq!(
            server.unix_socket,
            PathBuf::from("/srv/headscale/headscale.sock")
        );
        assert_eq!(server.unix_socket_permission, 0o700);
        assert_eq!(server.grpc_listen_addr, "127.0.0.1:50443");
        assert!(server.grpc_allow_insecure);
        assert_eq!(server.ephemeral_node_inactivity_timeout_secs, 300);
    }

    #[test]
    fn loads_upstream_top_level_server_yaml_into_runtime_config() {
        let source = r#"
server_url: "https://headscale.example"
listen_addr: "127.0.0.1:8080"
metrics_listen_addr: "127.0.0.1:9090"
grpc_listen_addr: "127.0.0.1:50443"
grpc_allow_insecure: true
ephemeral_node_inactivity_timeout: 3m
unix_socket: "/run/headscale/headscale.sock"
unix_socket_permission: "0o760"

noise:
  private_key_path: "/srv/headscale/noise_private.key"

prefixes:
  v4: "100.100.0.0/16"
  v6: "fd7a:115c:a1e0::/48"
  allocation: random

database:
  type: sqlite
  sqlite:
    path: "/srv/headscale/db.sqlite"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let server = config.server.unwrap();

        assert_eq!(
            server.server_url.as_deref(),
            Some("https://headscale.example")
        );
        assert_eq!(server.listen, "127.0.0.1:8080");
        assert_eq!(
            server.metrics_listen_addr.as_deref(),
            Some("127.0.0.1:9090")
        );
        assert_eq!(server.grpc_listen_addr, "127.0.0.1:50443");
        assert!(server.grpc_allow_insecure);
        assert_eq!(server.ephemeral_node_inactivity_timeout_secs, 180);
        assert_eq!(
            server.unix_socket,
            PathBuf::from("/run/headscale/headscale.sock")
        );
        assert_eq!(server.unix_socket_permission, 0o760);
        assert_eq!(server.state_dir, PathBuf::from("/srv/headscale"));
        assert_eq!(server.mesh_cidr, "100.100.0.0/16");
        assert_eq!(server.mesh_cidr_v6.as_deref(), Some("fd7a:115c:a1e0::/48"));
        assert_eq!(server.ip_allocation, "random");
        assert_eq!(server.db_path, PathBuf::from("/srv/headscale/db.sqlite"));
    }

    #[test]
    fn server_db_path_overrides_upstream_sqlite_path_alias() {
        let source = r#"
server:
  server_url: "https://headscale.example"
  db_path: "/srv/headscale/rust.sqlite"

database:
  type: sqlite
  sqlite:
    path: "/srv/headscale/upstream.sqlite"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let server = config.server.unwrap();

        assert_eq!(server.db_path, PathBuf::from("/srv/headscale/rust.sqlite"));
    }

    #[test]
    fn upstream_sqlite_path_alias_applies_to_server_block_without_db_path() {
        let source = r#"
server:
  server_url: "https://headscale.example"

database:
  type: sqlite
  sqlite:
    path: "/srv/headscale/upstream.sqlite"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let server = config.server.unwrap();

        assert_eq!(
            server.db_path,
            PathBuf::from("/srv/headscale/upstream.sqlite")
        );
    }

    #[test]
    fn loads_upstream_policy_yaml_and_resolves_relative_file_path() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("policy.hujson"),
            r#"{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}"#,
        )
        .unwrap();
        let config_path = dir.path().join("config.yaml");
        fs::write(
            &config_path,
            r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
policy:
  mode: file
  path: policy.hujson
"#,
        )
        .unwrap();

        let config = CliConfig::load(&config_path).unwrap();

        assert_eq!(config.policy.mode(), "file");
        assert_eq!(config.policy.path, dir.path().join("policy.hujson"));
        config.validate_for_configtest().unwrap();
    }

    #[test]
    fn loads_upstream_database_policy_mode() {
        let source = r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
policy:
  mode: database
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();

        assert!(config.policy.is_database_mode());
        config.validate_for_configtest().unwrap();
    }

    #[test]
    fn applies_headscale_policy_env_overrides_to_cli_config() {
        let mut config = CliConfig {
            policy: PolicyConfig {
                mode: "file".to_string(),
                path: PathBuf::from("configured-policy.hujson"),
            },
            ..CliConfig::default()
        };

        config.apply_policy_env_overrides_from([
            ("HEADSCALE_POLICY_MODE", "database"),
            ("HEADSCALE_POLICY_PATH", "/etc/headscale/policy.hujson"),
        ]);

        assert_eq!(config.policy.mode(), "database");
        assert_eq!(
            config.policy.path,
            PathBuf::from("/etc/headscale/policy.hujson")
        );
    }

    #[test]
    fn configtest_rejects_invalid_policy_mode() {
        let source = r#"
server_url: "https://headscale.example"
policy:
  mode: consul
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let err = config.validate_for_configtest().unwrap_err();

        assert!(format!("{err:#}").contains("policy.mode"));
    }

    #[test]
    fn configtest_rejects_invalid_policy_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("policy.hujson"), "{").unwrap();
        let config_path = dir.path().join("config.yaml");
        fs::write(
            &config_path,
            r#"
server_url: "https://headscale.example"
policy:
  mode: file
  path: policy.hujson
"#,
        )
        .unwrap();

        let config = CliConfig::load(&config_path).unwrap();
        let err = config.validate_for_configtest().unwrap_err();

        assert!(format!("{err:#}").contains("parse policy.path"));
    }

    #[test]
    fn upstream_metrics_listen_addr_can_be_disabled() {
        let omitted = CliConfig::parse(
            r#"
server_url: "https://headscale.example"
"#,
            ConfigFormat::Yaml,
        )
        .unwrap()
        .server
        .unwrap();
        assert!(omitted.metrics_listen_addr.is_none());

        let empty = CliConfig::parse(
            r#"
server_url: "https://headscale.example"
metrics_listen_addr: ""
"#,
            ConfigFormat::Yaml,
        )
        .unwrap()
        .server
        .unwrap();
        assert_eq!(empty.metrics_listen_addr.as_deref(), Some(""));

        let null = CliConfig::parse(
            r#"
server_url: "https://headscale.example"
metrics_listen_addr: null
"#,
            ConfigFormat::Yaml,
        )
        .unwrap()
        .server
        .unwrap();
        assert!(null.metrics_listen_addr.is_none());
    }

    #[test]
    fn upstream_v6_only_prefix_disables_default_ipv4_prefix() {
        let source = r#"
server_url: "https://headscale.example"
prefixes:
  v6: "fd7a:115c:a1e0::/48"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let server = config.server.unwrap();

        assert_eq!(server.mesh_cidr, "");
        assert_eq!(server.mesh_cidr_v6.as_deref(), Some("fd7a:115c:a1e0::/48"));
    }

    #[test]
    fn configtest_rejects_minimal_upstream_yaml_with_default_dns() {
        let source = r#"
noise:
  private_key_path: "private_key.pem"
server_url: "https://derp.no"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let err = config.validate_for_configtest().unwrap_err();

        assert!(format!("{err:#}").contains("dns.nameservers.global"));
        let server = config.server.unwrap();
        assert_eq!(server.server_url.as_deref(), Some("https://derp.no"));
        assert_eq!(server.state_dir, PathBuf::from("."));
    }

    #[test]
    fn parses_pinned_headscale_go_v0_28_config_example_fixture() {
        let source = include_str!("../tests/fixtures/headscale-go-v0.28-config-example.yaml");

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();

        config.validate_for_configtest().unwrap();
        assert_eq!(
            config.acme_url.as_deref(),
            Some("https://acme-v02.api.letsencrypt.org/directory")
        );
        assert_eq!(
            config.tls_letsencrypt_challenge_type.as_deref(),
            Some("HTTP-01")
        );
        assert_eq!(
            config.database.as_ref().unwrap().debug_postgres().ssl(),
            "false"
        );
        assert_eq!(
            config.server.as_ref().unwrap().unix_socket_permission,
            0o770
        );
    }

    #[test]
    fn configtest_rejects_invalid_prefix_allocation_strategy() {
        let source = r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
prefixes:
  v4: "100.64.0.0/10"
  allocation: "hash"
dns:
  magic_dns: false
  override_local_dns: false
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let err = config.validate_for_configtest().unwrap_err().to_string();

        assert!(err.contains("prefixes.allocation"));
        assert!(err.contains("sequential"));
        assert!(err.contains("random"));
    }

    #[test]
    fn configtest_rejects_config_with_no_prefix_families() {
        let source = r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
prefixes:
  v4: ""
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let err = config.validate_for_configtest().unwrap_err().to_string();

        assert!(err.contains("at least one of prefixes.v4 or prefixes.v6"));
    }

    #[test]
    fn configtest_accepts_postgres_config() {
        let source = r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: postgres
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();

        config.validate_for_configtest().unwrap();
    }

    #[test]
    fn configtest_rejects_invalid_postgres_pool_config() {
        let source = r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
database:
  type: postgres
  postgres:
    max_open_conns: -1
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let err = config.validate_for_configtest().unwrap_err();

        assert!(
            format!("{err:#}").contains("database.postgres connection pool fields must be >= 0")
        );
    }

    #[test]
    fn configtest_accepts_upstream_sqlite_wal_default_marker() {
        let source = r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
  sqlite:
    wal_autocheckpoint: -1
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();

        config.validate_for_configtest().unwrap();
        assert_eq!(
            config.database.as_ref().unwrap().runtime_backend(),
            Some(DatabaseBackend::Sqlite)
        );
        assert_eq!(
            config.database.unwrap().debug_sqlite().wal_autocheckpoint(),
            -1
        );
    }

    #[test]
    fn postgres_database_config_maps_to_runtime_backend_without_serving_it() {
        let source = r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: postgres
  postgres:
    host: localhost
    port: 5432
    name: headscale
    user: foo
    pass: bar
    ssl: false
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();

        config.validate_for_configtest().unwrap();
        assert_eq!(
            config.database.as_ref().unwrap().runtime_backend(),
            Some(DatabaseBackend::Postgres)
        );
    }

    #[test]
    fn configtest_rejects_database_block_without_type() {
        for source in [
            r#"
server_url: "https://headscale.example"
database:
  postgres:
    host: localhost
    port: 5432
"#,
            r#"
server_url: "https://headscale.example"
database:
  sqlite:
    path: /var/lib/headscale/db.sqlite
"#,
        ] {
            let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
            let err = config.validate_for_configtest().unwrap_err();

            assert!(format!("{err:#}").contains("database.type is required"));
        }
    }

    #[test]
    fn configtest_rejects_postgresql_database_type_alias() {
        let source = r#"
server_url: "https://headscale.example"
database:
  type: postgresql
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let err = config.validate_for_configtest().unwrap_err();
        let message = format!("{err:#}");

        assert!(message.contains("database.type \"postgresql\" is invalid"));
        assert!(message.contains("sqlite, sqlite3, postgres"));
    }

    #[test]
    fn configtest_rejects_upstream_tls_conflicts() {
        let source = r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
tls_letsencrypt_hostname: "headscale.example"
tls_cert_path: "/etc/headscale/cert.pem"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let err = config.validate_for_configtest().unwrap_err();

        assert_eq!(
            format!("{err:#}"),
            "Fatal config error: set either tls_letsencrypt_hostname or tls_cert_path/tls_key_path, not both"
        );
    }

    #[test]
    fn loads_upstream_tls_acme_keys() {
        let source = r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
acme_url: "https://acme.example/directory"
acme_email: "ops@example.com"
tls_letsencrypt_hostname: "headscale.example"
tls_letsencrypt_cache_dir: "/var/lib/headscale/cache"
tls_letsencrypt_listen: ":http"
tls_letsencrypt_challenge_type: "TLS-ALPN-01"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();

        assert_eq!(
            config.acme_url.as_deref(),
            Some("https://acme.example/directory")
        );
        assert_eq!(config.acme_email.as_deref(), Some("ops@example.com"));
        assert_eq!(
            config.tls_letsencrypt_hostname.as_deref(),
            Some("headscale.example")
        );
        assert_eq!(
            config.tls_letsencrypt_cache_dir.as_deref(),
            Some(Path::new("/var/lib/headscale/cache"))
        );
        assert_eq!(config.tls_letsencrypt_listen.as_deref(), Some(":http"));
        assert_eq!(
            config.tls_letsencrypt_challenge_type.as_deref(),
            Some("TLS-ALPN-01")
        );
        config.validate_for_configtest().unwrap();
    }

    #[test]
    fn configtest_accepts_http01_acme_cache_and_listener_context() {
        let source = r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
tls_letsencrypt_hostname: "headscale.example"
tls_letsencrypt_cache_dir: "/var/lib/headscale/acme-cache"
tls_letsencrypt_listen: ":http"
tls_letsencrypt_challenge_type: "HTTP-01"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        config.validate_for_configtest().unwrap();
    }

    #[test]
    fn configtest_rejects_incomplete_manual_tls_paths() {
        let source = r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
tls_cert_path: "/etc/headscale/cert.pem"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let err = config.validate_for_configtest().unwrap_err();

        assert!(format!("{err:#}").contains("tls_cert_path and tls_key_path must both be set"));
    }

    #[test]
    fn load_resolves_relative_tls_paths_from_config_file_dir() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        fs::write(
            &config_path,
            r#"
server_url: "https://headscale.example"
tls_cert_path: "certs/headscale.crt"
tls_key_path: "certs/headscale.key"
tls_letsencrypt_cache_dir: "cache/acme"
"#,
        )
        .unwrap();

        let config = CliConfig::load(&config_path).unwrap();

        assert_eq!(
            config.tls_cert_path.as_deref(),
            Some(dir.path().join("certs/headscale.crt").as_path())
        );
        assert_eq!(
            config.tls_key_path.as_deref(),
            Some(dir.path().join("certs/headscale.key").as_path())
        );
        assert_eq!(
            config.tls_letsencrypt_cache_dir.as_deref(),
            Some(dir.path().join("cache/acme").as_path())
        );
    }

    #[test]
    fn load_resolves_upstream_relative_config_paths_from_config_file_dir() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        fs::write(
            &config_path,
            r#"
server_url: "https://headscale.example"

noise:
  private_key_path: "keys/noise.key"

database:
  type: sqlite
  sqlite:
    path: "data/db.sqlite"

derp:
  paths:
    - "derp/map.yaml"
  server:
    private_key_path: "keys/derp.key"

dns:
  magic_dns: false
  override_local_dns: false
  extra_records_path: "dns/extra-records.json"
"#,
        )
        .unwrap();

        let config = CliConfig::load(&config_path).unwrap();
        let server = config.server.as_ref().unwrap();
        let derp = config.derp.as_ref().unwrap();
        let dns = config.dns.as_ref().unwrap();

        assert_eq!(
            config.noise.as_ref().unwrap().private_key_path.as_deref(),
            Some(dir.path().join("keys/noise.key").as_path())
        );
        assert_eq!(server.state_dir, dir.path().join("keys"));
        assert_eq!(server.db_path, dir.path().join("data/db.sqlite"));
        assert_eq!(
            config
                .database
                .as_ref()
                .unwrap()
                .sqlite
                .as_ref()
                .unwrap()
                .path
                .as_deref(),
            Some(dir.path().join("data/db.sqlite").as_path())
        );
        assert_eq!(
            derp.server.private_key_path,
            dir.path().join("keys/derp.key")
        );
        assert_eq!(derp.paths, [PathBuf::from("derp/map.yaml")]);
        assert_eq!(
            dns.extra_records_path.as_deref(),
            Some(dir.path().join("dns/extra-records.json").as_path())
        );
    }

    #[test]
    fn configtest_rejects_too_low_ephemeral_timeout() {
        let source = r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
ephemeral_node_inactivity_timeout: "65s"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let err = config.validate_for_configtest().unwrap_err();

        assert!(format!("{err:#}").contains("node.ephemeral.inactivity_timeout"));
    }

    #[test]
    fn loads_upstream_cli_grpc_toml() {
        let source = r#"
[cli]
address = "headscale.example:50443"
api_key = "hskey-api-abcdefghijkl-secret"
insecure = true
timeout = "7s"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        let cli = config.cli.unwrap();

        assert_eq!(cli.address.as_deref(), Some("headscale.example:50443"));
        assert_eq!(
            cli.api_key.as_deref(),
            Some("hskey-api-abcdefghijkl-secret")
        );
        assert_eq!(cli.insecure, Some(true));
        assert_eq!(cli.timeout, Some(7));
    }

    #[test]
    fn applies_headscale_cli_env_overrides_to_cli_config() {
        let mut config = CliConfig::default();

        config
            .apply_cli_env_overrides_from([
                ("HEADSCALE_CLI_ADDRESS", "env.example:50443"),
                ("HEADSCALE_CLI_API_KEY", "hskey-api-env-secret"),
                ("HEADSCALE_CLI_INSECURE", "true"),
                ("HEADSCALE_CLI_TIMEOUT", "9s"),
            ])
            .unwrap();

        let cli = config.cli.unwrap();
        assert_eq!(cli.address.as_deref(), Some("env.example:50443"));
        assert_eq!(cli.api_key.as_deref(), Some("hskey-api-env-secret"));
        assert_eq!(cli.insecure, Some(true));
        assert_eq!(cli.timeout, Some(9));
    }

    #[test]
    fn rejects_invalid_headscale_cli_timeout_env_override() {
        let mut config = CliConfig::default();

        let err = config
            .apply_cli_env_overrides_from([("HEADSCALE_CLI_TIMEOUT", "1500ms")])
            .unwrap_err();

        assert!(format!("{err:#}").contains("invalid HEADSCALE_CLI_TIMEOUT"));
    }

    #[test]
    fn applies_headscale_server_transport_env_overrides_to_runtime_config() {
        let mut config = CliConfig::default();

        config
            .apply_server_transport_env_overrides_from([
                ("HEADSCALE_SERVER_URL", "https://env-headscale.example"),
                ("HEADSCALE_LISTEN_ADDR", "127.0.0.1:18080"),
                ("HEADSCALE_METRICS_LISTEN_ADDR", "127.0.0.1:19090"),
                ("HEADSCALE_GRPC_LISTEN_ADDR", "127.0.0.1:150443"),
                ("HEADSCALE_GRPC_ALLOW_INSECURE", "true"),
                ("HEADSCALE_UNIX_SOCKET", "/tmp/headscale-env.sock"),
                ("HEADSCALE_UNIX_SOCKET_PERMISSION", "0o760"),
            ])
            .unwrap();

        let server = config.server.as_ref().unwrap();
        assert_eq!(
            server.server_url.as_deref(),
            Some("https://env-headscale.example")
        );
        assert_eq!(server.listen, "127.0.0.1:18080");
        assert_eq!(
            server.metrics_listen_addr.as_deref(),
            Some("127.0.0.1:19090")
        );
        assert_eq!(server.grpc_listen_addr, "127.0.0.1:150443");
        assert!(server.grpc_allow_insecure);
        assert_eq!(server.unix_socket, PathBuf::from("/tmp/headscale-env.sock"));
        assert_eq!(server.unix_socket_permission, 0o760);
        assert_eq!(
            config.unix_socket.as_deref(),
            Some(Path::new("/tmp/headscale-env.sock"))
        );
        assert_eq!(config.unix_socket_permission, Some(0o760));
    }

    #[test]
    fn rejects_invalid_headscale_server_transport_env_overrides() {
        let mut config = CliConfig::default();

        let err = config
            .apply_server_transport_env_overrides_from([(
                "HEADSCALE_UNIX_SOCKET_PERMISSION",
                "not-a-permission",
            )])
            .unwrap_err();

        assert!(format!("{err:#}").contains("invalid HEADSCALE_UNIX_SOCKET_PERMISSION"));
    }

    #[test]
    fn default_config_search_uses_upstream_order() {
        let etc_dir = tempfile::tempdir().unwrap();
        let home_dir = tempfile::tempdir().unwrap();
        let cwd_dir = tempfile::tempdir().unwrap();

        fs::write(
            cwd_dir.path().join("config.toml"),
            r#"
[cli]
address = "cwd.example:50443"
"#,
        )
        .unwrap();
        fs::write(
            home_dir.path().join("config.json"),
            r#"{"cli":{"address":"home.example:50443"}}"#,
        )
        .unwrap();
        fs::write(
            etc_dir.path().join("config.yaml"),
            r#"
cli:
  address: "etc.example:50443"
"#,
        )
        .unwrap();

        let config =
            CliConfig::load_default_from_dirs([etc_dir.path(), home_dir.path(), cwd_dir.path()])
                .unwrap();

        assert_eq!(
            config.cli.unwrap().address.as_deref(),
            Some("etc.example:50443")
        );
    }

    #[test]
    fn default_config_search_returns_defaults_when_no_file_exists() {
        let config = CliConfig::load_default_from_dirs([tempfile::tempdir().unwrap().path()])
            .expect("load defaults");

        assert!(config.server.is_none());
        assert!(config.cli.is_none());
        assert!(config.oidc.only_start_if_oidc_is_available);
    }

    #[test]
    fn parses_upstream_json_config() {
        let config = CliConfig::parse(
            r#"{"cli":{"address":"json.example:50443","insecure":true}}"#,
            ConfigFormat::Json,
        )
        .unwrap();

        let cli = config.cli.unwrap();
        assert_eq!(cli.address.as_deref(), Some("json.example:50443"));
        assert_eq!(cli.insecure, Some(true));
    }

    #[test]
    fn loads_top_level_upstream_dns_toml() {
        let source = r#"
[dns]
magic_dns = true
base_domain = "tail.example.org"
search_domains = ["corp.example.org"]
extra_records = [
  { name = "ops.tail.example.org", type = "A", value = "100.64.0.50" },
]

[dns.nameservers]
global = ["1.1.1.1", "https://dns.example/dns-query"]

[dns.nameservers.split]
"corp.example.org" = ["10.0.0.53"]
"#;

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        let dns = config.dns.unwrap();

        assert!(dns.magic_dns);
        assert_eq!(dns.base_domain, "tail.example.org");
        assert_eq!(
            dns.nameservers,
            [
                "1.1.1.1".to_string(),
                "https://dns.example/dns-query".to_string()
            ]
        );
        assert_eq!(
            dns.restricted_nameservers.get("corp.example.org").unwrap(),
            &vec!["10.0.0.53".to_string()]
        );
        assert_eq!(dns.search_domains, ["corp.example.org"]);
        assert_eq!(dns.extra_records[0].name, "ops.tail.example.org");
    }

    #[test]
    fn loads_embedded_derp_runtime_fields() {
        let source = r#"
[server]
server_url = "https://headscale.example"

[server.embedded_derp]
enabled = true
host_name = "derp.example.com"
region_id = 901
region_code = "test"
region_name = "Test DERP"
derp_port = 8443
stun_addr = "0.0.0.0:3478"
stun_only = true
omit_default_regions = true
insecure_for_tests = true
derper_binary = "/usr/local/bin/derper"
derper_listen_addr = "127.0.0.1:8443"
derper_config_path = "/var/lib/headscale/derper.key"
derper_cert_mode = "manual"
derper_cert_dir = "/var/lib/headscale/certs"
verify_client_url = "https://headscale.example/verify"
verify_clients = true
"#;

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        let embedded = config.server.unwrap().embedded_derp;

        assert!(embedded.enabled);
        assert_eq!(embedded.host_name, "derp.example.com");
        assert_eq!(embedded.region_id, 901);
        assert_eq!(embedded.region_code, "test");
        assert_eq!(embedded.region_name, "Test DERP");
        assert_eq!(embedded.derp_port, 8443);
        assert_eq!(embedded.stun_addr, Some("0.0.0.0:3478".parse().unwrap()));
        assert!(embedded.stun_only);
        assert!(embedded.omit_default_regions);
        assert!(embedded.insecure_for_tests);
        assert_eq!(
            embedded.derper_binary,
            PathBuf::from("/usr/local/bin/derper")
        );
        assert_eq!(
            embedded.derper_listen_addr,
            "127.0.0.1:8443".parse().unwrap()
        );
        assert_eq!(
            embedded.derper_config_path,
            PathBuf::from("/var/lib/headscale/derper.key")
        );
        assert_eq!(embedded.derper_cert_mode, "manual");
        assert_eq!(
            embedded.derper_cert_dir,
            Some(PathBuf::from("/var/lib/headscale/certs"))
        );
        assert_eq!(
            embedded.verify_client_url.as_deref(),
            Some("https://headscale.example/verify")
        );
        assert!(embedded.verify_clients);
    }

    #[test]
    fn configtest_rejects_embedded_derp_without_stun_addr() {
        let source = r#"
[server]
server_url = "https://headscale.example"

[noise]
private_key_path = "/var/lib/headscale/noise_private.key"

[dns]
magic_dns = false
override_local_dns = false

[server.embedded_derp]
enabled = true
host_name = "derp.example.com"
stun_only = true
"#;

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        let err = config.validate_for_configtest().unwrap_err();

        assert!(
            format!("{err:#}").contains(
                "server.embedded_derp.stun_addr is required when embedded DERP is enabled"
            ),
            "{err:#}"
        );
    }

    #[test]
    fn loads_upstream_v028_top_level_derp_yaml() {
        let source = r#"
server_url: "https://headscale.example"
derp:
  server:
    enabled: true
    region_id: 999
    region_code: headscale
    region_name: Headscale Embedded DERP
    verify_clients: true
    stun_listen_addr: "0.0.0.0:3478"
    private_key_path: /var/lib/headscale/derp_server_private.key
    automatically_add_embedded_derp_region: true
    ipv4: 198.51.100.1
    ipv6: 2001:db8::1
  urls:
    - https://controlplane.tailscale.com/derpmap/default
  paths:
    - /etc/headscale/derp.yaml
  auto_update_enabled: true
  update_frequency: 3h
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let derp = config.derp.as_ref().unwrap();

        assert!(derp.server.enabled);
        assert_eq!(derp.server.region_id, 999);
        assert_eq!(derp.server.region_code, "headscale");
        assert_eq!(derp.server.region_name, "Headscale Embedded DERP");
        assert!(derp.server.verify_clients);
        assert_eq!(
            derp.server.stun_listen_addr,
            Some("0.0.0.0:3478".parse().unwrap())
        );
        assert_eq!(
            derp.server.private_key_path,
            PathBuf::from("/var/lib/headscale/derp_server_private.key")
        );
        assert!(derp.server.automatically_add_embedded_derp_region);
        assert_eq!(derp.server.ipv4.as_deref(), Some("198.51.100.1"));
        assert_eq!(derp.server.ipv6.as_deref(), Some("2001:db8::1"));
        assert_eq!(
            derp.urls,
            ["https://controlplane.tailscale.com/derpmap/default"]
        );
        assert_eq!(derp.paths, [PathBuf::from("/etc/headscale/derp.yaml")]);
        assert!(derp.auto_update_enabled);
        assert_eq!(derp.update_frequency, 10_800);

        let embedded = config.server.unwrap().embedded_derp;
        assert!(embedded.enabled);
        assert_eq!(embedded.region_id, 999);
        assert_eq!(embedded.region_code, "headscale");
        assert_eq!(embedded.region_name, "Headscale Embedded DERP");
        assert_eq!(embedded.host_name, "headscale.example");
        assert_eq!(embedded.stun_addr, Some("0.0.0.0:3478".parse().unwrap()));
        assert!(embedded.stun_only);
        assert!(embedded.verify_clients);
        assert_eq!(
            embedded.derper_config_path,
            PathBuf::from("/var/lib/headscale/derp_server_private.key")
        );
        assert_eq!(embedded.ipv4, "198.51.100.1");
        assert_eq!(embedded.ipv6, "2001:db8::1");
    }

    #[test]
    fn upstream_derp_does_not_override_rust_embedded_derp_block() {
        let source = r#"
server_url = "https://headscale.example"

[server.embedded_derp]
enabled = true
host_name = "rust-derp.example"
region_id = 901
region_code = "rust"
region_name = "Rust DERP"
stun_only = true

[derp.server]
enabled = true
region_id = 999
region_code = "headscale"
region_name = "Headscale Embedded DERP"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        let embedded = config.server.unwrap().embedded_derp;

        assert_eq!(embedded.host_name, "rust-derp.example");
        assert_eq!(embedded.region_id, 901);
        assert_eq!(embedded.region_code, "rust");
        assert_eq!(embedded.region_name, "Rust DERP");
        assert!(embedded.stun_only);
    }

    #[test]
    fn upstream_derp_applies_when_server_block_has_no_rust_embedded_derp() {
        let source = r#"
server_url = "https://headscale.example"

[server]
listen = "127.0.0.1:8080"

[derp.server]
enabled = true
region_id = 999
region_code = "headscale"
region_name = "Headscale Embedded DERP"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        let embedded = config.server.unwrap().embedded_derp;

        assert!(embedded.enabled);
        assert_eq!(embedded.host_name, "headscale.example");
        assert_eq!(embedded.region_id, 999);
        assert_eq!(embedded.region_code, "headscale");
        assert!(embedded.stun_only);
    }

    #[test]
    fn upstream_derp_derives_non_default_server_url_port() {
        let source = r#"
server_url = "https://headscale.example:8443"

[derp.server]
enabled = true
"#;

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        let embedded = config.server.unwrap().embedded_derp;

        assert_eq!(embedded.host_name, "headscale.example");
        assert_eq!(embedded.derp_port, 8443);
    }

    #[test]
    fn upstream_derp_derives_tls_server_url_default_port() {
        let source = r#"
server_url = "https://headscale.example"

[derp.server]
enabled = true
"#;

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        let embedded = config.server.unwrap().embedded_derp;

        assert_eq!(embedded.host_name, "headscale.example");
        assert_eq!(embedded.derp_port, 443);
    }

    #[test]
    fn upstream_derp_derives_plain_server_url_default_port() {
        let source = r#"
server_url = "http://headscale.example"

[derp.server]
enabled = true
"#;

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        let embedded = config.server.unwrap().embedded_derp;

        assert_eq!(embedded.host_name, "headscale.example");
        assert_eq!(embedded.derp_port, 80);
    }

    #[test]
    fn upstream_derp_derives_server_url_ipv6_and_ignores_userinfo() {
        let source = r#"
server_url = "https://user:pass@[2001:db8::1]:8443"

[derp.server]
enabled = true
"#;

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        let embedded = config.server.unwrap().embedded_derp;

        assert_eq!(embedded.host_name, "2001:db8::1");
        assert_eq!(embedded.derp_port, 8443);
    }

    #[test]
    fn configtest_rejects_bad_server_url_port_before_derp_startup() {
        let source = r#"
server_url = "https://headscale.example:notaport"

[noise]
private_key_path = "noise_private.key"

[dns]
magic_dns = false
override_local_dns = false

[derp.server]
enabled = true
"#;

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        let err = config.validate_for_configtest().unwrap_err();

        assert!(format!("{err:#}").contains("server.server_url must be a valid URL"));
    }

    #[test]
    fn configtest_rejects_server_url_matching_dns_base_domain() {
        let source = r#"
server_url = "https://tail.example.org"

[noise]
private_key_path = "noise_private.key"

[dns]
magic_dns = true
override_local_dns = false
base_domain = "tail.example.org"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        let err = config.validate_for_configtest().unwrap_err();

        assert!(format!("{err:#}").contains(
            "server_url cannot use the same domain as base_domain in a way that could make the DERP and headscale server unreachable"
        ));
    }

    #[test]
    fn configtest_rejects_server_url_under_dns_base_domain() {
        let source = r#"
server_url = "https://login.tail.example.org"

[noise]
private_key_path = "noise_private.key"

[dns]
magic_dns = true
override_local_dns = false
base_domain = "tail.example.org"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        let err = config.validate_for_configtest().unwrap_err();

        assert!(format!("{err:#}").contains(
            "server_url cannot be part of base_domain in a way that could make the DERP and headscale server unreachable"
        ));
    }

    #[test]
    fn configtest_matches_upstream_explicit_port_suffix_boundary() {
        let source = r#"
server_url = "https://login.tail.example.org:443"

[noise]
private_key_path = "noise_private.key"

[dns]
magic_dns = true
override_local_dns = false
base_domain = "tail.example.org"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();

        config.validate_for_configtest().unwrap();
    }

    #[test]
    fn configtest_rejects_disabled_embedded_derp_injection_without_path_map() {
        let source = r#"
server_url = "https://headscale.example"

[noise]
private_key_path = "noise_private.key"

[dns]
magic_dns = false
override_local_dns = false

[derp.server]
enabled = true
automatically_add_embedded_derp_region = false
"#;

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        let err = config.validate_for_configtest().unwrap_err();

        assert!(
            format!("{err:#}").contains("requires at least one derp.paths entry"),
            "{err:#}"
        );
    }

    #[test]
    fn loads_upstream_oidc_yaml_with_defaults() {
        let source = r"
oidc:
  issuer: https://issuer.example
  client_id: yaml-client
  allowed_domains:
    - example.com
";

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();

        assert_eq!(config.oidc.issuer, "https://issuer.example");
        assert_eq!(config.oidc.client_id, "yaml-client");
        assert_eq!(config.oidc.allowed_domains, ["example.com"]);
        assert_eq!(config.oidc.scope, ["openid", "profile", "email"]);
        assert!(config.oidc.only_start_if_oidc_is_available);
    }

    #[test]
    fn loads_top_level_upstream_dns_yaml() {
        let source = r"
dns:
  magic_dns: true
  base_domain: tail.example.org
  override_local_dns: false
  nameservers:
    global:
      - 1.1.1.1
    split:
      corp.example.org:
        - 10.0.0.53
  search_domains:
    - corp.example.org
  extra_records:
    - name: ops.tail.example.org
      type: A
      value: 100.64.0.50
";

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let dns = config.dns.unwrap();

        assert_eq!(dns.base_domain, "tail.example.org");
        assert!(!dns.override_local_dns);
        assert_eq!(dns.nameservers, ["1.1.1.1"]);
        assert_eq!(
            dns.restricted_nameservers.get("corp.example.org").unwrap(),
            &vec!["10.0.0.53".to_string()]
        );
        assert_eq!(dns.extra_records[0].value, "100.64.0.50");
    }

    #[test]
    fn configtest_rejects_dns_override_without_global_nameservers() {
        let source = r#"
server_url: "https://headscale.example"
dns:
  magic_dns: false
  override_local_dns: true
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let err = config.validate_for_configtest().unwrap_err();

        assert!(format!("{err:#}").contains("dns.nameservers.global"));
    }

    #[test]
    fn configtest_rejects_missing_noise_private_key_path() {
        let source = r#"
server_url: "https://headscale.example"
dns:
  magic_dns: false
  override_local_dns: false
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let err = config.validate_for_configtest().unwrap_err();

        assert!(format!("{err:#}").contains(MISSING_NOISE_PRIVATE_KEY_PATH_ERROR));
    }

    #[test]
    fn rejects_dns_extra_records_and_path_together() {
        let err = CliConfig::parse(
            r#"
server_url: "https://headscale.example"
dns:
  magic_dns: false
  override_local_dns: false
  extra_records_path: "/etc/headscale/extra-records.json"
  extra_records:
    - name: "ops.tail.example.org"
      type: "A"
      value: "100.64.0.50"
"#,
            ConfigFormat::Yaml,
        )
        .unwrap_err();

        assert!(
            format!("{err:#}")
                .contains("dns.extra_records and dns.extra_records_path are mutually exclusive")
        );
    }

    #[test]
    fn applies_headscale_oidc_env_overrides_to_cli_config() {
        let mut config = CliConfig::default();

        config
            .apply_oidc_env_overrides_from([
                ("HEADSCALE_OIDC_ISSUER", "https://env-issuer.example"),
                ("HEADSCALE_OIDC_CLIENT_ID", "env-client"),
                ("HEADSCALE_OIDC_SCOPE", r#"["openid","profile","groups"]"#),
                (
                    "HEADSCALE_OIDC_ALLOWED_USERS",
                    "alice@example.com,bob@example.com",
                ),
                ("HEADSCALE_OIDC_EMAIL_VERIFIED_REQUIRED", "false"),
                ("HEADSCALE_OIDC_PKCE_ENABLED", "true"),
            ])
            .unwrap();

        assert_eq!(config.oidc.issuer, "https://env-issuer.example");
        assert_eq!(config.oidc.client_id, "env-client");
        assert_eq!(config.oidc.scope, ["openid", "profile", "groups"]);
        assert_eq!(
            config.oidc.allowed_users,
            ["alice@example.com", "bob@example.com"]
        );
        assert!(!config.oidc.email_verified_required);
        assert!(config.oidc.pkce.enabled);
    }

    #[test]
    fn rejects_removed_oidc_expiry_config_key() {
        let err = CliConfig::parse(
            r#"
[oidc]
expiry = "14d"
"#,
            ConfigFormat::Toml,
        )
        .unwrap_err();
        let err = format!("{err:#}");

        assert!(err.contains("oidc.expiry"));
        assert!(err.contains("node.expiry"));
    }

    #[test]
    fn rejects_removed_oidc_strip_email_domain_config_key() {
        let err = CliConfig::parse(
            r"
oidc:
  strip_email_domain: true
",
            ConfigFormat::Yaml,
        )
        .unwrap_err();
        let err = format!("{err:#}");

        assert!(err.contains("oidc.strip_email_domain"));
        assert!(err.contains("removed"));
    }

    #[test]
    fn rejects_removed_randomize_client_port_config_key() {
        let err =
            CliConfig::parse(r#"{"randomize_client_port":true}"#, ConfigFormat::Json).unwrap_err();
        let err = format!("{err:#}");

        assert!(err.contains("randomize_client_port"));
        assert!(err.contains("randomizeClientPort"));
        assert!(err.contains("nodeAttrs"));
    }

    #[test]
    fn rejects_removed_acl_policy_path_config_key() {
        let err = CliConfig::parse(
            r#"
acl_policy_path: "/etc/headscale/policy.hujson"
"#,
            ConfigFormat::Yaml,
        )
        .unwrap_err();
        let err = format!("{err:#}");

        assert!(err.contains("acl_policy_path"));
        assert!(err.contains("policy.path"));
    }

    #[test]
    fn rejects_removed_dns_config_keys() {
        let err = CliConfig::parse(
            r#"
dns_config:
  nameservers:
    - "1.1.1.1"
"#,
            ConfigFormat::Yaml,
        )
        .unwrap_err();
        let err = format!("{err:#}");

        assert!(err.contains("dns_config.nameservers"));
        assert!(err.contains("dns.nameservers.global"));
    }

    #[test]
    fn rejects_removed_dns_username_magic_dns_key() {
        let err = CliConfig::parse(
            r"
dns:
  use_username_in_magic_dns: true
",
            ConfigFormat::Yaml,
        )
        .unwrap_err();
        let err = format!("{err:#}");

        assert!(err.contains("dns.use_username_in_magic_dns"));
        assert!(err.contains("removed"));
    }

    #[test]
    fn rejects_removed_oidc_expiry_env_override() {
        let mut config = CliConfig::default();

        let err = config
            .apply_oidc_env_overrides_from([("HEADSCALE_OIDC_EXPIRY", "7d")])
            .unwrap_err();
        let err = format!("{err:#}");

        assert!(err.contains("oidc.expiry"));
        assert!(err.contains("node.expiry"));
    }

    #[test]
    fn rejects_mutually_exclusive_oidc_client_secret_sources() {
        let source = r#"
[oidc]
client_secret = "inline"
client_secret_path = "/run/secret"
"#;

        let mut config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        let err = config.resolve_oidc_client_secret().unwrap_err();
        let err = format!("{err:#}");

        assert!(err.contains("mutually exclusive"));
    }

    #[test]
    fn rejects_invalid_oidc_pkce_method() {
        let source = r#"
[oidc.pkce]
method = "S384"
"#;

        let mut config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        let err = config.resolve_oidc_client_secret().unwrap_err();
        let err = format!("{err:#}");

        assert!(err.contains("pkce.method"));
    }
}
