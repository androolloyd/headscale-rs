//! Configuration file handling for the CLI.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use headscale_api::dns::{DnsConfigSpec, parse_extra_records};
use headscale_core::config::{ConfigError, EmbeddedDerpConfig, EmbeddedDerpRelayMode, OidcConfig};
use headscale_db::DatabaseBackend;
use serde::{Deserialize, Deserializer, Serialize, de};

use crate::derp_config::DerpConfig;

#[cfg(feature = "postgres-sqlx")]
mod postgres;
mod prefix_warning;
mod secret_file;

const DEFAULT_CONFIG_FILENAMES: &[&str] =
    &["config.yaml", "config.yml", "config.json", "config.toml"];
const DEFAULT_CLI_TIMEOUT_SECS: u64 = 5;
const DEFAULT_NODE_ROUTES_HA_PROBE_INTERVAL_SECS: u64 = 10;
const DEFAULT_NODE_ROUTES_HA_PROBE_TIMEOUT_SECS: u64 = 5;
const MISSING_NOISE_PRIVATE_KEY_PATH_ERROR: &str = "Fatal config error: headscale now requires a new `noise.private_key_path` field in the config file for the Tailscale v2 protocol";
pub(crate) const DEPRECATED_EPHEMERAL_TIMEOUT_WARNING: &str = "WARN: The \"ephemeral_node_inactivity_timeout\" configuration key is deprecated. Please use \"node.ephemeral.inactivity_timeout\" instead. \"ephemeral_node_inactivity_timeout\" has been removed.";
pub(crate) const TLS_ALPN_ACME_PORT_WARNING: &str = "Warning: when using tls_letsencrypt_hostname with TLS-ALPN-01 as challenge type, headscale must be reachable on port 443, i.e. listen_addr should probably end in :443";

/// Top-level CLI configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct CliConfig {
    #[serde(skip)]
    pub(crate) deprecation_warnings: Vec<String>,
    #[serde(skip)]
    pub(crate) dns_extra_records_is_set: bool,
    #[serde(skip)]
    pub(crate) dns_extra_records_path_is_set: bool,
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
    #[serde(
        default,
        deserialize_with = "deserialize_optional_cli_dns",
        skip_serializing_if = "Option::is_none"
    )]
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

pub(crate) struct DefaultConfigLoad {
    pub(crate) config: CliConfig,
    pub(crate) used_defaults: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("{log_message}")]
pub(crate) struct ConfigDeprecationError {
    pub(crate) log_message: String,
}

#[derive(Debug, thiserror::Error)]
#[error("{log_message}")]
pub(crate) struct ConfigFatalError {
    pub(crate) log_message: String,
    pub(crate) before_log_config: bool,
}

/// Own the initial file snapshot through command selection. The source can
/// contain secrets; do not derive Debug or include it in diagnostics.
pub(crate) struct InitialConfigLoad {
    pub(crate) config: CliConfig,
    source: Option<(PathBuf, String)>,
}

impl InitialConfigLoad {
    pub(crate) fn used_defaults(&self) -> bool {
        self.source.is_none()
    }

    pub(crate) fn into_config(self, full: bool) -> Result<CliConfig> {
        if !full {
            return Ok(self.config);
        }
        match self.source {
            Some((path, contents)) => CliConfig::load_source_unresolved(&path, &contents),
            None => CliConfig::server_defaults_unresolved(),
        }
    }
}

/// Viper's CLI loader reads only these settings. Ignore unrelated server
/// values while decoding, including values that the typed server config
/// would reject, rather than loading secrets or validating server options.
#[derive(Default)]
struct AdminConfigProjection {
    values: std::collections::BTreeMap<String, serde_json::Value>,
}

impl<'de> Deserialize<'de> for AdminConfigProjection {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ProjectionVisitor;

        impl<'de> de::Visitor<'de> for ProjectionVisitor {
            type Value = AdminConfigProjection;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a configuration mapping")
            }

            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(AdminConfigProjection::default())
            }

            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                self.visit_unit()
            }

            fn visit_map<M: de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut projection = AdminConfigProjection::default();
                while let Some(key) = map.next_key::<String>()? {
                    let key = key.to_ascii_lowercase();
                    if matches!(
                        key.split('.').next(),
                        Some(
                            "cli"
                                | "unix_socket"
                                | "log"
                                | "logging"
                                | "disable_check_updates"
                                | "server"
                        )
                    ) {
                        projection.values.insert(key, map.next_value()?);
                    } else {
                        map.next_value::<de::IgnoredAny>()?;
                    }
                }
                Ok(projection)
            }
        }

        deserializer.deserialize_any(ProjectionVisitor)
    }
}

impl AdminConfigProjection {
    fn get(&self, path: &str) -> Option<&serde_json::Value> {
        if let Some(value) = self.values.get(path) {
            return (!value.is_null()).then_some(value);
        }
        let (root, mut path) = path.split_once('.')?;
        let mut value = self.values.get(root)?;
        loop {
            let object = value.as_object()?;
            if let Some((_, value)) = object
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(path))
            {
                return (!value.is_null()).then_some(value);
            }
            let (component, remaining) = path.split_once('.')?;
            value = object
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(component))?
                .1;
            path = remaining;
        }
    }

    fn to_config(&self) -> CliConfig {
        let logging = LoggingConfig {
            level: self
                .get("log.level")
                .or_else(|| self.get("logging.level"))
                .map_or_else(default_log_level, cast_cli_string),
            format: self
                .get("log.format")
                .or_else(|| self.get("logging.format"))
                .map_or_else(default_log_format, cast_cli_string),
        };
        CliConfig {
            cli: Some(AdminCliConfig {
                address: self.get("cli.address").map(cast_cli_string),
                api_key: self.get("cli.api_key").map(cast_cli_string),
                insecure: self.get("cli.insecure").map(cast_cli_bool),
                timeout: self.get("cli.timeout").map(cast_cli_duration_value),
            }),
            unix_socket: self
                .get("unix_socket")
                .map(cast_cli_string)
                .map(PathBuf::from),
            // Preserve the Rust nested-socket extension without decoding any
            // other server fields or performing server normalization.
            server: self.get("server.unix_socket").map(|value| ServerConfig {
                unix_socket: PathBuf::from(cast_cli_string(value)),
                ..ServerConfig::default()
            }),
            disable_check_updates: self.get("disable_check_updates").is_some_and(cast_cli_bool),
            logging: Some(logging),
            ..CliConfig::default()
        }
    }
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
    /// Upstream operator CLI request timeout in signed Go nanoseconds.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_cli_duration_nanos",
        skip_serializing_if = "Option::is_none"
    )]
    pub timeout: Option<i64>,
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
    /// Configured Tailscale Noise key file. Upstream uses a `privkey:` text key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noise_private_key_path: Option<PathBuf>,
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
    /// headscale-rs extension (headscale-go has no `policy.ssh` block and
    /// ignores it). Omitted from the config dump while unset so the dump
    /// stays comparable with upstream's.
    #[serde(skip_serializing_if = "policy_ssh_config_is_default")]
    pub ssh: PolicySshConfig,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            mode: "file".to_string(),
            path: PathBuf::new(),
            ssh: PolicySshConfig::default(),
        }
    }
}

/// `policy.ssh`: operator opt-out for the forwarding permissions on SSH
/// actions. headscale-go grants all three on every accepted SSH rule and
/// check action with no way to turn them off; the defaults here keep that
/// behaviour, and setting one to false makes headscale-rs emit the flag as
/// false everywhere. See `docs/HARDENING.md`.
///
/// Unknown keys are rejected: a misspelled `allow_*` key that was silently
/// ignored would leave forwarding enabled while the operator believes it is
/// off.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct PolicySshConfig {
    pub allow_agent_forwarding: bool,
    pub allow_local_port_forwarding: bool,
    pub allow_remote_port_forwarding: bool,
}

impl Default for PolicySshConfig {
    fn default() -> Self {
        Self {
            allow_agent_forwarding: true,
            allow_local_port_forwarding: true,
            allow_remote_port_forwarding: true,
        }
    }
}

impl PolicySshConfig {
    pub(crate) const fn forwarding(self) -> headscale_api::policy::SshForwarding {
        headscale_api::policy::SshForwarding {
            agent: self.allow_agent_forwarding,
            local_port: self.allow_local_port_forwarding,
            remote_port: self.allow_remote_port_forwarding,
        }
    }
}

impl PolicyConfig {
    #[cfg(test)]
    pub(crate) fn database() -> Self {
        Self {
            mode: "database".to_string(),
            path: PathBuf::new(),
            ssh: PolicySshConfig::default(),
        }
    }

    pub(crate) fn mode(&self) -> &str {
        self.mode.as_str()
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
    pub(crate) fn load_initial(path: Option<&Path>) -> Result<InitialConfigLoad> {
        let path = path.map(Path::to_path_buf).or_else(|| {
            default_config_dirs()
                .into_iter()
                .flat_map(|directory| {
                    DEFAULT_CONFIG_FILENAMES
                        .iter()
                        .map(move |filename| directory.join(filename))
                })
                .find(|candidate| candidate.is_file())
        });
        if let Some(path) = path {
            let contents = std::fs::read_to_string(&path).map_err(|error| {
                anyhow::anyhow!(crate::go_style_open_error(
                    "fatal error reading config file",
                    &path,
                    &error,
                ))
            })?;
            let config = Self::parse_admin(&contents, ConfigFormat::from_path(&path))
                .context("fatal error reading config file")?;
            Ok(InitialConfigLoad {
                config,
                source: Some((path, contents)),
            })
        } else {
            let mut config = Self::default();
            config.apply_admin_env_overrides_from(std::env::vars());
            Ok(InitialConfigLoad {
                config,
                source: None,
            })
        }
    }

    pub(crate) fn load_admin(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        Self::parse_admin(&contents, ConfigFormat::from_path(path))
    }

    fn parse_admin(contents: &str, format: ConfigFormat) -> Result<Self> {
        let projection: AdminConfigProjection = match format {
            ConfigFormat::Toml => toml::from_str(contents).context("failed to parse TOML config"),
            ConfigFormat::Yaml => {
                headscale_cli::yaml::from_str(contents).context("failed to parse YAML config")
            }
            ConfigFormat::Json => {
                serde_json::from_str(contents).context("failed to parse JSON config")
            }
        }?;
        let mut config = projection.to_config();
        config.apply_admin_env_overrides_from(std::env::vars());
        Ok(config)
    }

    fn apply_admin_env_overrides_from<I, K, V>(&mut self, vars: I)
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
            self.apply_cli_env_overrides_from(std::iter::once((key, value)));
            self.apply_logging_env_overrides_from(std::iter::once((key, value)));
            match key {
                "HEADSCALE_UNIX_SOCKET" => self.unix_socket = Some(PathBuf::from(value)),
                "HEADSCALE_DISABLE_CHECK_UPDATES" => {
                    self.disable_check_updates = cast_cli_bool_string(value);
                }
                _ => {}
            }
        }
    }

    /// Load configuration from a file.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        Self::load_source(path, &contents)
    }

    fn load_source(path: &Path, contents: &str) -> Result<Self> {
        let mut config = Self::load_source_unresolved(path, contents)?;
        config.resolve_oidc_client_secret()?;
        Ok(config)
    }

    fn load_source_unresolved(path: &Path, contents: &str) -> Result<Self> {
        let mut config =
            Self::parse_with_deprecations(contents, ConfigFormat::from_path(path), true)?;
        crate::print_config_deprecation_warnings(&config);
        let config_dir = path.parent().map(Path::to_path_buf);
        if let Some(parent) = config_dir.as_deref() {
            config.resolve_config_relative_paths(parent);
        }
        config.normalize_upstream_aliases();
        let should_refresh_derp_projection = config.embedded_derp_matches_upstream_projection();
        config.apply_node_env_overrides_from(std::env::vars())?;
        config.apply_taildrop_env_overrides_from(std::env::vars())?;
        config.apply_runtime_feature_env_overrides_from(std::env::vars())?;
        config.apply_database_env_overrides_from(std::env::vars())?;
        config.apply_dns_env_overrides_from(std::env::vars())?;
        config.apply_derp_env_overrides_from(std::env::vars())?;
        config.apply_tuning_env_overrides_from(std::env::vars())?;
        config.apply_logging_env_overrides_from(std::env::vars());
        config.apply_tls_acme_env_overrides_from(std::env::vars());
        config.apply_policy_env_overrides_from(std::env::vars())?;
        config.apply_server_transport_env_overrides_from(std::env::vars())?;
        config.apply_cli_env_overrides_from(std::env::vars());
        if let Some(parent) = config_dir.as_deref() {
            config.resolve_config_relative_paths(parent);
        }
        if should_refresh_derp_projection {
            config.reset_embedded_derp_projection();
        }
        config.normalize_upstream_aliases();
        Ok(config)
    }

    /// Load the upstream default config search path, returning defaults when
    /// no config file exists.
    #[allow(dead_code)]
    pub(crate) fn load_default() -> Result<Self> {
        Ok(Self::load_default_with_source()?.config)
    }

    #[allow(dead_code)]
    pub(crate) fn load_default_from_dirs<I, P>(dirs: I) -> Result<Self>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        Ok(Self::load_default_with_source_from_dirs(dirs)?.config)
    }

    pub(crate) fn load_default_with_source() -> Result<DefaultConfigLoad> {
        Self::load_default_with_source_from_dirs(default_config_dirs())
    }

    pub(crate) fn load_default_admin_with_source() -> Result<DefaultConfigLoad> {
        Self::load_default_with_source_from_dirs_for_profile(default_config_dirs(), true)
    }

    pub(crate) fn load_default_with_source_from_dirs<I, P>(dirs: I) -> Result<DefaultConfigLoad>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        Self::load_default_with_source_from_dirs_for_profile(dirs, false)
    }

    fn load_default_with_source_from_dirs_for_profile<I, P>(
        dirs: I,
        admin_only: bool,
    ) -> Result<DefaultConfigLoad>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        for dir in dirs {
            let dir = dir.as_ref();
            for filename in DEFAULT_CONFIG_FILENAMES {
                let candidate = dir.join(filename);
                if candidate.is_file() {
                    let load = if admin_only {
                        Self::load_admin
                    } else {
                        Self::load
                    };
                    let config = load(&candidate).with_context(|| {
                        format!("failed to load config file {}", candidate.display())
                    })?;
                    return Ok(DefaultConfigLoad {
                        config,
                        used_defaults: false,
                    });
                }
            }
        }

        let mut config = Self::default();
        if admin_only {
            config.apply_admin_env_overrides_from(std::env::vars());
            return Ok(DefaultConfigLoad {
                config,
                used_defaults: true,
            });
        }
        Ok(DefaultConfigLoad {
            config: Self::server_defaults_from_env()?,
            used_defaults: true,
        })
    }

    fn server_defaults_from_env() -> Result<Self> {
        let mut config = Self::server_defaults_unresolved()?;
        config.resolve_oidc_client_secret()?;
        Ok(config)
    }

    fn server_defaults_unresolved() -> Result<Self> {
        let mut config = Self::default();
        config.prepare_oidc_for_server()?;
        let (warnings, records, records_path) = collect_config_input_metadata(|_| false, true)?;
        config.deprecation_warnings = warnings;
        config.dns_extra_records_is_set = records;
        config.dns_extra_records_path_is_set = records_path;
        crate::print_config_deprecation_warnings(&config);
        config.normalize_upstream_aliases();
        config.apply_node_env_overrides_from(std::env::vars())?;
        config.apply_taildrop_env_overrides_from(std::env::vars())?;
        config.apply_runtime_feature_env_overrides_from(std::env::vars())?;
        config.apply_database_env_overrides_from(std::env::vars())?;
        config.apply_dns_env_overrides_from(std::env::vars())?;
        config.apply_derp_env_overrides_from(std::env::vars())?;
        config.apply_tuning_env_overrides_from(std::env::vars())?;
        config.apply_logging_env_overrides_from(std::env::vars());
        config.apply_tls_acme_env_overrides_from(std::env::vars());
        config.apply_policy_env_overrides_from(std::env::vars())?;
        config.apply_server_transport_env_overrides_from(std::env::vars())?;
        config.apply_cli_env_overrides_from(std::env::vars());
        config.normalize_upstream_aliases();
        Ok(config)
    }

    #[cfg(test)]
    fn parse(contents: &str, format: ConfigFormat) -> Result<Self> {
        Self::parse_with_deprecations(contents, format, false)
    }

    fn parse_with_deprecations(
        contents: &str,
        format: ConfigFormat,
        include_env: bool,
    ) -> Result<Self> {
        let config: Option<Self> = match format {
            ConfigFormat::Toml => toml::from_str(contents).context("failed to parse TOML config"),
            ConfigFormat::Yaml => {
                headscale_cli::yaml::from_str(contents).context("failed to parse YAML config")
            }
            ConfigFormat::Json => {
                serde_json::from_str(contents).context("failed to parse JSON config")
            }
        }?;
        let mut config = config.unwrap_or_default();
        config.normalize_upstream_aliases();
        if include_env {
            config.prepare_oidc_for_server()?;
        }
        let (warnings, records, records_path) =
            config_input_metadata(contents, format, include_env)?;
        config.deprecation_warnings = warnings;
        config.dns_extra_records_is_set = records;
        config.dns_extra_records_path_is_set = records_path;
        Ok(config)
    }

    fn prepare_oidc_for_server(&mut self) -> Result<()> {
        self.oidc.apply_headscale_env_overrides_unchecked_from(
            std::env::vars().filter(|(key, _)| key != "HEADSCALE_OIDC_EXPIRY"),
        )?;
        // Pinned Go validates an activated provider before logging removed
        // keys. This does not resolve the client-secret file or discover it.
        self.validate_native_oidc()?;
        Ok(())
    }

    fn validate_native_oidc(&self) -> Result<()> {
        let oidc = &self.oidc;
        if oidc.issuer.is_empty() {
            // Retain the optional Rust enabled-key extension when no issuer
            // activates the native provider.
            return oidc.validate().map_err(Into::into);
        }
        // validateOIDCConfig checks these in this order. Use net/url grammar
        // at this CLI boundary: WHATWG URL parsing trims control/space input
        // and rejects some Go-accepted host forms before discovery can run.
        if !matches!(oidc.pkce.method.as_str(), "plain" | "S256") {
            return Err(ConfigError::InvalidPkceMethod.into());
        }
        if !instant_acme::go_is_oidc_issuer_url(&oidc.issuer) {
            bail!(
                "oidc.issuer must be a valid http(s) URL: got {}",
                crate::logging::quote(&oidc.issuer)
            );
        }
        if oidc.client_id.is_empty() {
            return Err(ConfigError::OidcClientIdRequired.into());
        }
        if oidc.client_secret.is_empty()
            && oidc
                .client_secret_path
                .as_ref()
                .is_none_or(|path| path.as_os_str().is_empty())
        {
            return Err(ConfigError::OidcClientSecretRequired.into());
        }
        Ok(())
    }

    pub(crate) fn upstream_deprecation_warnings(&self) -> Vec<String> {
        let mut warnings = self.deprecation_warnings.clone();
        let ephemeral = DEPRECATED_EPHEMERAL_TIMEOUT_WARNING.trim_start_matches("WARN: ");
        if self.ephemeral_node_inactivity_timeout.is_some()
            && !warnings.iter().any(|warning| warning == ephemeral)
        {
            warnings.push(ephemeral.to_string());
        }
        warnings
    }

    #[cfg(test)]
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
            .apply_headscale_env_overrides_unchecked_from(vars)
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

    fn apply_runtime_feature_env_overrides_from<I, K, V>(&mut self, vars: I) -> Result<()>
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
            if key == "HEADSCALE_RANDOMIZE_CLIENT_PORT" {
                bail!(
                    "{}",
                    removed_config_key_message(removed_config_key_by_display(
                        "randomize_client_port"
                    ))
                );
            }

            match key {
                "HEADSCALE_DISABLE_CHECK_UPDATES" => {
                    self.disable_check_updates =
                        parse_env_bool(value).with_context(|| format!("invalid {key}"))?;
                }
                "HEADSCALE_LOGTAIL_ENABLED" => {
                    self.logtail.enabled =
                        parse_env_bool(value).with_context(|| format!("invalid {key}"))?;
                }
                "HEADSCALE_AUTO_UPDATE_ENABLED" => {
                    self.auto_update.enabled =
                        parse_env_bool(value).with_context(|| format!("invalid {key}"))?;
                }
                _ => {}
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
            let key = key.as_ref();
            let value = value.as_ref();
            match key {
                "HEADSCALE_NODE_EXPIRY" => {
                    let expiry = parse_duration_secs_str(value)
                        .map_err(|err| anyhow::anyhow!("invalid {key}: {err}"))?;
                    self.node.get_or_insert_with(NodeConfig::default).expiry = Some(expiry);
                }
                "HEADSCALE_NODE_EPHEMERAL_INACTIVITY_TIMEOUT" => {
                    let timeout = parse_duration_secs_str(value)
                        .map_err(|err| anyhow::anyhow!("invalid {key}: {err}"))?;
                    self.node
                        .get_or_insert_with(NodeConfig::default)
                        .ephemeral
                        .inactivity_timeout = Some(timeout);
                }
                "HEADSCALE_NODE_ROUTES_HA_PROBE_INTERVAL" => {
                    let interval = parse_duration_secs_str(value)
                        .map_err(|err| anyhow::anyhow!("invalid {key}: {err}"))?;
                    self.node
                        .get_or_insert_with(NodeConfig::default)
                        .routes
                        .ha
                        .probe_interval = Some(interval);
                }
                "HEADSCALE_NODE_ROUTES_HA_PROBE_TIMEOUT" => {
                    let timeout = parse_duration_secs_str(value)
                        .map_err(|err| anyhow::anyhow!("invalid {key}: {err}"))?;
                    self.node
                        .get_or_insert_with(NodeConfig::default)
                        .routes
                        .ha
                        .probe_timeout = Some(timeout);
                }
                "HEADSCALE_EPHEMERAL_NODE_INACTIVITY_TIMEOUT" => {
                    let timeout = parse_duration_secs_str(value)
                        .map_err(|err| anyhow::anyhow!("invalid {key}: {err}"))?;
                    self.ephemeral_node_inactivity_timeout = Some(timeout);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn apply_database_env_overrides_from<I, K, V>(&mut self, vars: I) -> Result<()>
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
                "HEADSCALE_DATABASE_TYPE" => {
                    self.database
                        .get_or_insert_with(UpstreamDatabaseConfig::default)
                        .database_type = Some(value.to_string());
                }
                "HEADSCALE_DATABASE_DEBUG" => {
                    self.database
                        .get_or_insert_with(UpstreamDatabaseConfig::default)
                        .debug = parse_env_bool(value).with_context(|| format!("invalid {key}"))?;
                }
                "HEADSCALE_DATABASE_GORM_DEBUG" => {
                    self.database
                        .get_or_insert_with(UpstreamDatabaseConfig::default)
                        .gorm
                        .debug = parse_env_bool(value).with_context(|| format!("invalid {key}"))?;
                }
                "HEADSCALE_DATABASE_GORM_SLOW_THRESHOLD" => {
                    self.database
                        .get_or_insert_with(UpstreamDatabaseConfig::default)
                        .gorm
                        .slow_threshold = value
                        .parse::<u64>()
                        .with_context(|| format!("invalid {key}"))?
                        .saturating_mul(1_000_000);
                }
                "HEADSCALE_DATABASE_GORM_SKIP_ERR_RECORD_NOT_FOUND" => {
                    self.database
                        .get_or_insert_with(UpstreamDatabaseConfig::default)
                        .gorm
                        .skip_err_record_not_found =
                        parse_env_bool(value).with_context(|| format!("invalid {key}"))?;
                }
                "HEADSCALE_DATABASE_GORM_PARAMETERIZED_QUERIES" => {
                    self.database
                        .get_or_insert_with(UpstreamDatabaseConfig::default)
                        .gorm
                        .parameterized_queries =
                        parse_env_bool(value).with_context(|| format!("invalid {key}"))?;
                }
                "HEADSCALE_DATABASE_GORM_PREPARE_STMT" => {
                    self.database
                        .get_or_insert_with(UpstreamDatabaseConfig::default)
                        .gorm
                        .prepare_stmt =
                        parse_env_bool(value).with_context(|| format!("invalid {key}"))?;
                }
                "HEADSCALE_DATABASE_SQLITE_PATH" => {
                    self.database
                        .get_or_insert_with(UpstreamDatabaseConfig::default)
                        .sqlite
                        .get_or_insert_with(UpstreamSqliteConfig::default)
                        .path = Some(PathBuf::from(value));
                }
                "HEADSCALE_DATABASE_SQLITE_WRITE_AHEAD_LOG" => {
                    self.database
                        .get_or_insert_with(UpstreamDatabaseConfig::default)
                        .sqlite
                        .get_or_insert_with(UpstreamSqliteConfig::default)
                        .write_ahead_log =
                        parse_env_bool(value).with_context(|| format!("invalid {key}"))?;
                }
                "HEADSCALE_DATABASE_SQLITE_WAL_AUTOCHECKPOINT" => {
                    self.database
                        .get_or_insert_with(UpstreamDatabaseConfig::default)
                        .sqlite
                        .get_or_insert_with(UpstreamSqliteConfig::default)
                        .wal_autocheckpoint =
                        value.parse().with_context(|| format!("invalid {key}"))?;
                }
                "HEADSCALE_DATABASE_POSTGRES_HOST" => {
                    self.database
                        .get_or_insert_with(UpstreamDatabaseConfig::default)
                        .postgres
                        .host = value.to_string();
                }
                "HEADSCALE_DATABASE_POSTGRES_PORT" => {
                    self.database
                        .get_or_insert_with(UpstreamDatabaseConfig::default)
                        .postgres
                        .port = value.parse().with_context(|| format!("invalid {key}"))?;
                }
                "HEADSCALE_DATABASE_POSTGRES_NAME" => {
                    self.database
                        .get_or_insert_with(UpstreamDatabaseConfig::default)
                        .postgres
                        .name = value.to_string();
                }
                "HEADSCALE_DATABASE_POSTGRES_USER" => {
                    self.database
                        .get_or_insert_with(UpstreamDatabaseConfig::default)
                        .postgres
                        .user = value.to_string();
                }
                "HEADSCALE_DATABASE_POSTGRES_PASS" => {
                    self.database
                        .get_or_insert_with(UpstreamDatabaseConfig::default)
                        .postgres
                        .pass = value.to_string();
                }
                "HEADSCALE_DATABASE_POSTGRES_SSL" => {
                    self.database
                        .get_or_insert_with(UpstreamDatabaseConfig::default)
                        .postgres
                        .ssl = value.to_string();
                }
                "HEADSCALE_DATABASE_POSTGRES_MAX_OPEN_CONNS" => {
                    self.database
                        .get_or_insert_with(UpstreamDatabaseConfig::default)
                        .postgres
                        .max_open_conns =
                        value.parse().with_context(|| format!("invalid {key}"))?;
                }
                "HEADSCALE_DATABASE_POSTGRES_MAX_IDLE_CONNS" => {
                    self.database
                        .get_or_insert_with(UpstreamDatabaseConfig::default)
                        .postgres
                        .max_idle_conns =
                        value.parse().with_context(|| format!("invalid {key}"))?;
                }
                "HEADSCALE_DATABASE_POSTGRES_CONN_MAX_IDLE_TIME_SECS" => {
                    self.database
                        .get_or_insert_with(UpstreamDatabaseConfig::default)
                        .postgres
                        .conn_max_idle_time_secs =
                        value.parse().with_context(|| format!("invalid {key}"))?;
                }
                _ => {}
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
        if self.dns_extra_records_is_set && self.dns_extra_records_path_is_set {
            // Go rejects presence before decoding either source. Runtime
            // metadata already includes file and nonempty environment keys.
            return Ok(());
        }
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
                    self.dns_extra_records_is_set = true;
                }
                "HEADSCALE_DNS_EXTRA_RECORDS_PATH" => {
                    self.dns_extra_records_path_is_set = true;
                    self.dns
                        .get_or_insert_with(DnsConfigSpec::default)
                        .extra_records_path = Some(PathBuf::from(value));
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn apply_derp_env_overrides_from<I, K, V>(&mut self, vars: I) -> Result<()>
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
                "HEADSCALE_DERP_SERVER_ENABLED" => {
                    self.derp
                        .get_or_insert_with(DerpConfig::default)
                        .server
                        .enabled =
                        parse_env_bool(value).with_context(|| format!("invalid {key}"))?;
                }
                "HEADSCALE_DERP_SERVER_REGION_ID" => {
                    self.derp
                        .get_or_insert_with(DerpConfig::default)
                        .server
                        .region_id = value
                        .parse::<i64>()
                        .with_context(|| format!("invalid {key}"))?;
                }
                "HEADSCALE_DERP_SERVER_REGION_CODE" => {
                    self.derp
                        .get_or_insert_with(DerpConfig::default)
                        .server
                        .region_code = value.to_string();
                }
                "HEADSCALE_DERP_SERVER_REGION_NAME" => {
                    self.derp
                        .get_or_insert_with(DerpConfig::default)
                        .server
                        .region_name = value.to_string();
                }
                "HEADSCALE_DERP_SERVER_VERIFY_CLIENTS" => {
                    self.derp
                        .get_or_insert_with(DerpConfig::default)
                        .server
                        .verify_clients =
                        parse_env_bool(value).with_context(|| format!("invalid {key}"))?;
                }
                "HEADSCALE_DERP_SERVER_STUN_LISTEN_ADDR" => {
                    self.derp
                        .get_or_insert_with(DerpConfig::default)
                        .server
                        .stun_listen_addr =
                        Some(value.parse().with_context(|| format!("invalid {key}"))?);
                }
                "HEADSCALE_DERP_SERVER_PRIVATE_KEY_PATH" => {
                    self.derp
                        .get_or_insert_with(DerpConfig::default)
                        .server
                        .private_key_path = PathBuf::from(value);
                }
                "HEADSCALE_DERP_SERVER_IPV4" => {
                    self.derp
                        .get_or_insert_with(DerpConfig::default)
                        .server
                        .ipv4 = Some(value.to_string());
                }
                "HEADSCALE_DERP_SERVER_IPV6" => {
                    self.derp
                        .get_or_insert_with(DerpConfig::default)
                        .server
                        .ipv6 = Some(value.to_string());
                }
                "HEADSCALE_DERP_SERVER_AUTOMATICALLY_ADD_EMBEDDED_DERP_REGION" => {
                    self.derp
                        .get_or_insert_with(DerpConfig::default)
                        .server
                        .automatically_add_embedded_derp_region =
                        parse_env_bool(value).with_context(|| format!("invalid {key}"))?;
                }
                "HEADSCALE_DERP_URLS" => {
                    self.derp.get_or_insert_with(DerpConfig::default).urls =
                        parse_env_string_slice(value);
                }
                "HEADSCALE_DERP_PATHS" => {
                    self.derp.get_or_insert_with(DerpConfig::default).paths =
                        parse_env_string_slice(value)
                            .into_iter()
                            .map(PathBuf::from)
                            .collect();
                }
                "HEADSCALE_DERP_AUTO_UPDATE_ENABLED" => {
                    self.derp
                        .get_or_insert_with(DerpConfig::default)
                        .auto_update_enabled =
                        parse_env_bool(value).with_context(|| format!("invalid {key}"))?;
                }
                "HEADSCALE_DERP_UPDATE_FREQUENCY" => {
                    self.derp
                        .get_or_insert_with(DerpConfig::default)
                        .update_frequency = parse_duration_secs_str(value)
                        .map_err(|err| anyhow::anyhow!("invalid {key}: {err}"))?;
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn apply_policy_env_overrides_from<I, K, V>(&mut self, vars: I) -> Result<()>
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
                // headscale-rs extension. An unparseable value is an error,
                // not a skip: ignoring it would leave forwarding enabled
                // while the operator believes it is off.
                "HEADSCALE_POLICY_SSH_ALLOW_AGENT_FORWARDING" => {
                    self.policy.ssh.allow_agent_forwarding =
                        parse_env_bool(value).with_context(|| format!("invalid {key}"))?;
                }
                "HEADSCALE_POLICY_SSH_ALLOW_LOCAL_PORT_FORWARDING" => {
                    self.policy.ssh.allow_local_port_forwarding =
                        parse_env_bool(value).with_context(|| format!("invalid {key}"))?;
                }
                "HEADSCALE_POLICY_SSH_ALLOW_REMOTE_PORT_FORWARDING" => {
                    self.policy.ssh.allow_remote_port_forwarding =
                        parse_env_bool(value).with_context(|| format!("invalid {key}"))?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn apply_tuning_env_overrides_from<I, K, V>(&mut self, vars: I) -> Result<()>
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
                "HEADSCALE_TUNING_NODE_STORE_BATCH_SIZE" => {
                    self.tuning.node_store_batch_size =
                        value.parse().with_context(|| format!("invalid {key}"))?;
                }
                "HEADSCALE_TUNING_NODE_STORE_BATCH_TIMEOUT" => {
                    self.tuning.node_store_batch_timeout = parse_duration_nanos_str(value)
                        .map_err(|err| anyhow::anyhow!("invalid {key}: {err}"))?;
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn apply_logging_env_overrides_from<I, K, V>(&mut self, vars: I)
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
                "HEADSCALE_LOG_LEVEL" => {
                    self.logging
                        .get_or_insert_with(LoggingConfig::default)
                        .level = value.to_string();
                }
                "HEADSCALE_LOG_FORMAT" => {
                    self.logging
                        .get_or_insert_with(LoggingConfig::default)
                        .format = value.to_string();
                }
                _ => {}
            }
        }
    }

    fn apply_tls_acme_env_overrides_from<I, K, V>(&mut self, vars: I)
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
                "HEADSCALE_ACME_URL" => {
                    self.acme_url = Some(value.to_string());
                }
                "HEADSCALE_ACME_EMAIL" => {
                    self.acme_email = Some(value.to_string());
                }
                "HEADSCALE_TLS_LETSENCRYPT_HOSTNAME" => {
                    self.tls_letsencrypt_hostname = Some(value.to_string());
                }
                "HEADSCALE_TLS_LETSENCRYPT_CACHE_DIR" => {
                    self.tls_letsencrypt_cache_dir = Some(PathBuf::from(value));
                }
                "HEADSCALE_TLS_LETSENCRYPT_LISTEN" => {
                    self.tls_letsencrypt_listen = Some(value.to_string());
                }
                "HEADSCALE_TLS_LETSENCRYPT_CHALLENGE_TYPE" => {
                    self.tls_letsencrypt_challenge_type = Some(value.to_string());
                }
                "HEADSCALE_TLS_CERT_PATH" => {
                    self.tls_cert_path = Some(PathBuf::from(value));
                }
                "HEADSCALE_TLS_KEY_PATH" => {
                    self.tls_key_path = Some(PathBuf::from(value));
                }
                _ => {}
            }
        }
    }

    fn apply_cli_env_overrides_from<I, K, V>(&mut self, vars: I)
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        for (key, value) in vars {
            if value.as_ref().is_empty() {
                continue;
            }
            match key.as_ref() {
                "HEADSCALE_CLI_TIMEOUT" => {
                    let timeout = cast_cli_duration_string(value.as_ref());
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
                    self.cli
                        .get_or_insert_with(AdminCliConfig::default)
                        .insecure = Some(cast_cli_bool_string(value.as_ref()));
                }
                _ => {}
            }
        }
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

    pub(crate) fn resolve_oidc_client_secret(&mut self) -> Result<()> {
        self.validate_dns_record_sources()?;
        secret_file::resolve(&mut self.oidc)
    }

    fn embedded_derp_matches_upstream_projection(&self) -> bool {
        let Some(server) = &self.server else {
            return false;
        };
        let Some(derp) = &self.derp else {
            return false;
        };
        if !derp.server.enabled || !server.embedded_derp.enabled {
            return false;
        }

        let (host_name, derp_port) = server
            .server_url
            .as_deref()
            .and_then(host_port_from_url)
            .unwrap_or_default();

        server.embedded_derp.region_id == u16::try_from(derp.server.region_id).unwrap_or_default()
            && server.embedded_derp.region_code == derp.server.region_code
            && server.embedded_derp.region_name == derp.server.region_name
            && server.embedded_derp.stun_addr == derp.server.stun_listen_addr
            && !server.embedded_derp.stun_only
            && server.embedded_derp.relay_mode == EmbeddedDerpRelayMode::Native
            && server.embedded_derp.verify_clients == derp.server.verify_clients
            && server.embedded_derp.derper_config_path == derp.server.private_key_path
            && server.embedded_derp.ipv4 == derp.server.ipv4.clone().unwrap_or_default()
            && server.embedded_derp.ipv6 == derp.server.ipv6.clone().unwrap_or_default()
            && server.embedded_derp.host_name == host_name
            && server.embedded_derp.derp_port == derp_port
    }

    fn reset_embedded_derp_projection(&mut self) {
        if let Some(server) = &mut self.server {
            server.embedded_derp = EmbeddedDerpConfig::default();
        }
    }

    fn normalize_upstream_aliases(&mut self) {
        let had_server_block = self.server.is_some();
        let has_server_alias = self.server_url.is_some()
            || self.listen_addr.is_some()
            || self.metrics_listen_addr.is_some()
            || self.grpc_listen_addr.is_some()
            || self.grpc_allow_insecure.is_some()
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
        if let Some(timeout) = self
            .node
            .as_ref()
            .and_then(|node| node.ephemeral.inactivity_timeout)
        {
            server.ephemeral_node_inactivity_timeout_secs = timeout;
        }
        // The top-level keys are the only form headscale-go has, so they apply
        // unless a Rust `server:` block set its own socket. An extension block
        // that only tunes something else (e.g. `https_listen`) must not discard
        // them: its unset socket still holds the serde default.
        if (!had_server_block || server.unix_socket == default_unix_socket())
            && let Some(unix_socket) = self.unix_socket.clone()
        {
            server.unix_socket = unix_socket;
        }
        if (!had_server_block || server.unix_socket_permission == default_unix_socket_permission())
            && let Some(unix_socket_permission) = self.unix_socket_permission
        {
            server.unix_socket_permission = unix_socket_permission;
        }
        if let Some(noise_private_key_path) = self
            .noise
            .as_ref()
            .and_then(|noise| noise.private_key_path.as_ref())
        {
            server.state_dir = state_dir_from_noise_private_key(noise_private_key_path);
            server.noise_private_key_path = Some(noise_private_key_path.clone());
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
            // The core embedding extension keeps its public u16 field. The
            // native source ID remains in `derp` and is never derived from
            // this compatibility view when constructing the advertised map.
            server.embedded_derp.region_id =
                u16::try_from(derp.server.region_id).unwrap_or_default();
            server
                .embedded_derp
                .region_code
                .clone_from(&derp.server.region_code);
            server
                .embedded_derp
                .region_name
                .clone_from(&derp.server.region_name);
            server.embedded_derp.stun_addr = derp.server.stun_listen_addr;
            server.embedded_derp.stun_only = false;
            server.embedded_derp.relay_mode = EmbeddedDerpRelayMode::Native;
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
        // dns.extra_records_path is deliberately absent: headscale-go hands
        // the configured string to the extra-records manager unchanged
        // (hscontrol/types/config.go:913, hscontrol/app.go:687), so a relative
        // value is relative to the working directory, not the config file.
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

    fn validate_dns_record_sources(&self) -> Result<()> {
        if self.dns_extra_records_is_set && self.dns_extra_records_path_is_set {
            return Err(ConfigFatalError {
                log_message: "fatal config error: dns.extra_records and dns.extra_records_path are mutually exclusive. Please remove one of them from your config file".into(),
                before_log_config: true,
            }.into());
        }
        Ok(())
    }

    /// Complete the typed server load before constructing persistent state.
    /// Keep file I/O after aggregate/prefix/DERP validation, matching Go's
    /// LoadServerConfig rather than checking late fatal fields up front.
    pub(crate) fn complete_server_config_load(&mut self) -> Result<()> {
        self.validate_dns_record_sources()?;
        let server = self.server.clone().unwrap_or_default();
        let server_url = server.server_url.as_deref().unwrap_or_default();
        crate::print_config_warnings(self);
        self.validate_upstream_fatal_config(&server, server_url)?;
        crate::print_invalid_log_format(self);

        let (prefix_v4, prefix_v6) = if let Some(prefixes) = &self.prefixes {
            (
                prefixes.v4.as_deref().unwrap_or_default(),
                prefixes.v6.as_deref().unwrap_or_default(),
            )
        } else if self.server_url.is_some() {
            ("", "")
        } else {
            // Keep the nested Rust server configuration extension.
            (
                server.mesh_cidr.as_str(),
                server.mesh_cidr_v6.as_deref().unwrap_or_default(),
            )
        };
        validate_config_prefix(prefix_v4, "IPv4")?;
        validate_config_prefix(prefix_v6, "IPv6")?;
        self.validate_trusted_proxies()?;
        if prefix_v4.is_empty() && prefix_v6.is_empty() {
            return Err(ConfigError::NoPrefixConfigured.into());
        }
        prefix_warning::warn_if_nonstandard(self, prefix_v4, prefix_v6);
        if !matches!(server.ip_allocation.as_str(), "sequential" | "random") {
            bail!(
                "invalid prefix allocation strategy: {}, allowed options: sequential, random",
                crate::logging::quote(&server.ip_allocation)
            );
        }

        if let Some(derp) = &mut self.derp {
            crate::derp_config::normalize_native_urls(derp)?;
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
            if server.embedded_derp.sidecar_relay_enabled()
                && server.embedded_derp.derper_binary.as_os_str().is_empty()
            {
                bail!(
                    "server.embedded_derp.derper_binary is required when embedded DERP relay is enabled"
                );
            }
        }

        self.resolve_oidc_client_secret()?;
        if let Some(dns) = &self.dns {
            validate_server_url_base_domain(server_url, &dns.base_domain)?;
        }
        if let Some(log_message) = self.upstream_fatal_log_message() {
            return Err(ConfigFatalError {
                log_message,
                before_log_config: false,
            }
            .into());
        }
        Ok(())
    }

    /// Validate the loaded config enough to catch startup-time errors without
    /// binding listeners or opening long-running services.
    #[cfg(test)]
    pub(crate) fn validate_for_configtest(&self) -> Result<()> {
        self.validate_native_oidc()?;
        self.validate_trusted_proxies()?;
        self.validate_policy_config()?;

        if self.server_url.is_some()
            && self.prefixes.as_ref().is_none_or(|prefixes| {
                prefixes
                    .v4
                    .as_deref()
                    .is_none_or(|prefix| prefix.trim().is_empty())
                    && prefixes
                        .v6
                        .as_deref()
                        .is_none_or(|prefix| prefix.trim().is_empty())
            })
        {
            return Err(ConfigError::NoPrefixConfigured.into());
        }

        let default_server = ServerConfig::default();
        let server = self.server.as_ref().unwrap_or(&default_server);
        let server_url = server.server_url.as_deref().unwrap_or("");
        self.validate_upstream_fatal_config(server, server_url)?;
        self.validate_manual_tls_paths()?;
        self.validate_tls_acme_listener()?;
        parse_server_url_parts(server_url)?;
        if let Some(https_listen) = server.https_listen.as_deref() {
            validate_socket_addr(https_listen, "https_listen")?;
        }
        if server.ephemeral_node_inactivity_timeout_secs <= 65 {
            bail!(
                "ephemeral_node_inactivity_timeout ({}s) is set too low, must be more than 1m5s",
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
        validate_config_prefix(&server.mesh_cidr, "IPv4")?;
        if let Some(mesh_cidr_v6) = server.mesh_cidr_v6.as_deref() {
            validate_config_prefix(mesh_cidr_v6, "IPv6")?;
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
            if server.embedded_derp.sidecar_relay_enabled()
                && server.embedded_derp.derper_binary.as_os_str().is_empty()
            {
                bail!(
                    "server.embedded_derp.derper_binary is required when embedded DERP relay is enabled"
                );
            }
        }

        self.validate_upstream_database_config()?;

        Ok(())
    }

    /// Listener syntax is checked when serving. Pinned Go's `configtest`
    /// accepts these values because no listeners are bound by that command.
    pub(crate) fn validate_listener_addresses(&self) -> Result<()> {
        self.validate_manual_tls_paths()?;
        self.validate_tls_acme_listener()?;
        let default_server = ServerConfig::default();
        let server = self.server.as_ref().unwrap_or(&default_server);
        if let Some(https_listen) = server.https_listen.as_deref() {
            validate_socket_addr(https_listen, "https_listen")?;
        }
        validate_socket_addr(&server.listen, "listen_addr")?;
        validate_optional_socket_addr(
            server.metrics_listen_addr.as_deref(),
            "metrics_listen_addr",
        )?;
        validate_socket_addr(&server.grpc_listen_addr, "grpc_listen_addr")?;
        Ok(())
    }

    /// Upstream terminates these checks through zerolog before Cobra formats
    /// a command error.
    pub(crate) fn upstream_fatal_log_message(&self) -> Option<String> {
        let kind = self
            .database
            .as_ref()
            .and_then(|database| database.database_type.as_deref())
            .unwrap_or_default();
        if !matches!(kind, "sqlite" | "sqlite3" | "postgres") {
            return Some(format!(
                "invalid database type {}, must be sqlite, sqlite3 or postgres",
                crate::logging::quote(kind)
            ));
        }
        self.dns
            .as_ref()
            .filter(|dns| dns.magic_dns && dns.base_domain.is_empty())
            .map(|_| "dns.base_domain must be set when using MagicDNS (dns.magic_dns)".into())
    }

    pub(crate) fn upstream_nonfatal_config_warnings(&self) -> Vec<&'static str> {
        let default_server = ServerConfig::default();
        let server = self.server.as_ref().unwrap_or(&default_server);
        let mut warnings = Vec::new();

        if self.should_warn_tls_alpn_acme_non_443(server) {
            warnings.push(TLS_ALPN_ACME_PORT_WARNING);
        }

        warnings
    }

    fn should_warn_tls_alpn_acme_non_443(&self, server: &ServerConfig) -> bool {
        self.tls_letsencrypt_hostname
            .as_deref()
            .is_some_and(|value| !value.is_empty())
            && self.tls_letsencrypt_challenge_type.as_deref() == Some("TLS-ALPN-01")
            && !server.listen.ends_with(":443")
    }

    fn validate_trusted_proxies(&self) -> Result<()> {
        for (i, raw) in self.trusted_proxies.iter().enumerate() {
            let (_, bits) = parse_ip_prefix(raw)
                .with_context(|| format!("trusted_proxies[{i}] {}", crate::logging::quote(raw)))?;
            if bits == 0 {
                bail!(
                    "trusted_proxies[{i}] {}: 0.0.0.0/0 and ::/0 are not allowed",
                    crate::logging::quote(raw)
                );
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn validate_policy_config(&self) -> Result<()> {
        match self.policy.mode() {
            "file" => {
                let Some(path) = self.policy.path_if_non_empty() else {
                    return Ok(());
                };
                let raw = std::fs::read_to_string(path)
                    .with_context(|| format!("read policy.path {}", path.display()))?;
                if raw.is_empty() {
                    return Ok(());
                }
                headscale_api::policy::parse_hujson_policy(&raw)
                    .with_context(|| format!("parse policy.path {}", path.display()))?;
                Ok(())
            }
            // Go loads an empty policy for unrecognized modes and can start;
            // the policy admin RPCs report the unsupported mode when used.
            _ => Ok(()),
        }
    }

    #[cfg(test)]
    fn validate_upstream_database_config(&self) -> Result<()> {
        let Some(database) = &self.database else {
            bail!("database.type is required; supported values are sqlite, sqlite3, postgres");
        };
        let Some(database_type) = database.database_type.as_deref() else {
            bail!("database.type is required; supported values are sqlite, sqlite3, postgres");
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
        let mut ephemeral_error_index = None;

        let letsencrypt_hostname = self
            .tls_letsencrypt_hostname
            .as_deref()
            .is_some_and(|value| !value.is_empty());
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

        if let Some(challenge_type) = self.tls_letsencrypt_challenge_type.as_deref()
            && challenge_type != "HTTP-01"
            && challenge_type != "TLS-ALPN-01"
        {
            errors.push(
                "Fatal config error: the only supported values for tls_letsencrypt_challenge_type are HTTP-01 and TLS-ALPN-01"
                    .to_string(),
            );
        }

        if !server_url.starts_with("http://") && !server_url.starts_with("https://") {
            errors
                .push("Fatal config error: server_url must start with https:// or http://".into());
        }

        if server.ephemeral_node_inactivity_timeout_secs <= 65 {
            ephemeral_error_index = Some(errors.len());
            errors.push(format!(
                "Fatal config error: node.ephemeral.inactivity_timeout ({}) is set too low, must be more than 1m5s",
                format_go_duration_secs(server.ephemeral_node_inactivity_timeout_secs)
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
            let mut error_text = String::new();
            for (index, error) in errors.iter().enumerate() {
                // Pinned Go appends the ephemeral-timeout error without a
                // newline, including when another validation error follows.
                if index > 0 && ephemeral_error_index != Some(index - 1) {
                    error_text.push('\n');
                }
                error_text.push_str(error);
            }
            bail!("{error_text}");
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

    fn validate_tls_acme_listener(&self) -> Result<()> {
        let letsencrypt_enabled = self
            .tls_letsencrypt_hostname
            .as_deref()
            .is_some_and(|value| !value.is_empty());
        if !letsencrypt_enabled {
            return Ok(());
        }

        let challenge_type = self
            .tls_letsencrypt_challenge_type
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("HTTP-01");
        if challenge_type == "HTTP-01" {
            let listen = self
                .tls_letsencrypt_listen
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or(":http");
            validate_acme_http01_listen_addr(listen)?;
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

    #[cfg(feature = "postgres-sqlx")]
    pub(crate) fn ssl_mode(&self) -> Option<&str> {
        // headscale-go uses strconv.ParseBool before passing the value to
        // pgx. True omits the setting; false disables TLS. An empty setting
        // must still be emitted into Go's raw keyword/value string.
        match self.ssl.as_str() {
            "1" | "t" | "T" | "TRUE" | "true" | "True" => None,
            "0" | "f" | "F" | "FALSE" | "false" | "False" => Some("disable"),
            value => Some(value),
        }
    }

    #[cfg(feature = "postgres-sqlx")]
    pub(crate) fn connection_url(&self) -> Result<String> {
        postgres::connection_url(self)
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
    // viper absolutizes each search directory, so a config found in the
    // working directory resolves its relative paths to absolute ones.
    dirs.push(std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
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

/// `util.AbsolutePathFromConfigPath`: a relative path is joined onto the
/// directory of the config file in use with `filepath.Join`, which also cleans
/// it (`./a/../b` collapses). When the config was named without a directory the
/// path is left exactly as written.
///
/// Resolution runs both before and after the environment overrides, so a path
/// that already carries the (relative) config directory must not gain it again.
fn resolve_path(config_dir: &Path, path: &mut PathBuf) {
    if path.as_os_str().is_empty() || path.is_absolute() || config_dir.as_os_str().is_empty() {
        return;
    }
    let dir = go_clean_path(config_dir);
    if dir.is_relative() && dir != Path::new(".") && path.starts_with(&dir) {
        return;
    }
    *path = go_clean_path(&config_dir.join(&*path));
}

/// Lexical `filepath.Clean` for Unix paths: drops `.` elements and duplicate
/// separators, folds `..` into the preceding element, and yields `.` for an
/// empty result.
fn go_clean_path(path: &Path) -> PathBuf {
    use std::path::Component;
    let rooted = path.has_root();
    let mut parts: Vec<std::ffi::OsString> = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                if parts.last().is_some_and(|last| last != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push("..".into());
                }
            }
            Component::Normal(part) => parts.push(part.to_owned()),
        }
    }
    // Start from the root itself; `push("/")` on an empty buffer would be the
    // same, but reads like an overwrite of an earlier component.
    let mut cleaned = if rooted {
        PathBuf::from("/")
    } else {
        PathBuf::new()
    };
    for part in parts {
        cleaned.push(part);
    }
    if cleaned.as_os_str().is_empty() {
        cleaned.push(".");
    }
    cleaned
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

fn validate_acme_http01_listen_addr(value: &str) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case(":http") || trimmed.eq_ignore_ascii_case("http") {
        return Ok(());
    }
    validate_socket_addr(trimmed, "tls_letsencrypt_listen")
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

#[cfg(test)]
const REMOVED_OIDC_ENV_KEYS: &[(&str, &str)] = &[(
    "HEADSCALE_OIDC_EXPIRY",
    "oidc.expiry was removed; use node.expiry instead",
)];

fn config_input_metadata(
    contents: &str,
    format: ConfigFormat,
    include_env: bool,
) -> Result<(Vec<String>, bool, bool)> {
    match format {
        ConfigFormat::Toml => {
            let value: toml::Value =
                toml::from_str(contents).context("failed to parse TOML config")?;
            collect_config_input_metadata(|path| toml_has_path(&value, path), include_env)
        }
        ConfigFormat::Yaml => {
            let value: headscale_cli::yaml::Presence =
                headscale_cli::yaml::from_str(contents).context("failed to parse YAML config")?;
            collect_config_input_metadata(|path| value.is_set_path(path), include_env)
        }
        ConfigFormat::Json => {
            let value: serde_json::Value =
                serde_json::from_str(contents).context("failed to parse JSON config")?;
            collect_config_input_metadata(|path| json_has_path(&value, path), include_env)
        }
    }
}

fn config_key_is_set(
    file_is_set: &impl Fn(&[&str]) -> bool,
    path: &[&str],
    include_env: bool,
) -> bool {
    let env_is_set = include_env
        && std::env::var_os(format!("HEADSCALE_{}", path.join("_").to_ascii_uppercase()))
            .is_some_and(|value| !value.is_empty());
    env_is_set || file_is_set(path)
}

fn collect_config_input_metadata(
    file_is_set: impl Fn(&[&str]) -> bool,
    include_env: bool,
) -> Result<(Vec<String>, bool, bool)> {
    let records = config_key_is_set(&file_is_set, &["dns", "extra_records"], include_env);
    let records_path = config_key_is_set(&file_is_set, &["dns", "extra_records_path"], include_env);
    let warnings = collect_config_deprecations(file_is_set, include_env)?;
    Ok((warnings, records, records_path))
}

fn collect_config_deprecations(
    file_is_set: impl Fn(&[&str]) -> bool,
    include_env: bool,
) -> Result<Vec<String>> {
    let is_set = |path: &[&str]| config_key_is_set(&file_is_set, path, include_env);
    let mut warnings = Vec::new();
    let mut fatals = Vec::new();
    for key in REMOVED_CONFIG_KEYS {
        if !is_set(key.path) {
            continue;
        }
        let message = removed_config_key_message(*key);
        let replacement_is_set = key.replacement.is_some_and(|replacement| {
            // These defaults participate in Viper IsSet even when their
            // values are empty. Other replacements have no default.
            matches!(
                replacement,
                "dns.magic_dns"
                    | "dns.base_domain"
                    | "dns.override_local_dns"
                    | "dns.nameservers.global"
                    | "dns.nameservers.split"
                    | "dns.search_domains"
            ) || is_set(&replacement.split('.').collect::<Vec<_>>())
        });
        if key.display != "oidc.expiry" && replacement_is_set {
            warnings.push(message);
        } else {
            fatals.push(message);
        }
    }
    if is_set(&["ephemeral_node_inactivity_timeout"]) {
        warnings.push(
            DEPRECATED_EPHEMERAL_TIMEOUT_WARNING
                .trim_start_matches("WARN: ")
                .to_string(),
        );
    }
    if fatals.is_empty() {
        return Ok(warnings);
    }
    // Go's sets do not guarantee multi-message order. Keep the same warning
    // and fatal groups, in declaration order, without dropping any entries.
    let mut log_message = String::from("\n");
    for warning in warnings {
        log_message.push_str("WARN: ");
        log_message.push_str(&warning);
        log_message.push('\n');
    }
    for fatal in fatals {
        log_message.push_str("FATAL: ");
        log_message.push_str(&fatal);
        log_message.push('\n');
    }
    Err(ConfigDeprecationError { log_message }.into())
}

#[cfg(test)]
fn reject_removed_oidc_env_keys(vars: &[(String, String)]) -> Result<()> {
    for (key, value) in vars {
        if value.is_empty() {
            continue;
        }
        if let Some((_, message)) = REMOVED_OIDC_ENV_KEYS
            .iter()
            .find(|(removed_key, _)| key == removed_key)
        {
            bail!("{message}");
        }
    }

    Ok(())
}

fn removed_config_key_by_display(display: &str) -> RemovedConfigKey {
    REMOVED_CONFIG_KEYS
        .iter()
        .copied()
        .find(|key| key.display == display)
        .expect("removed config key is registered")
}

fn removed_config_key_message(key: RemovedConfigKey) -> String {
    match (key.replacement, key.hint) {
        (Some(replacement), Some(hint)) => format!(
            "The \"{}\" configuration key has been removed. Please use \"{}\" instead. {}",
            key.display, replacement, hint
        ),
        (Some(replacement), None) if key.display == "oidc.expiry" => format!(
            "The \"{}\" configuration key has been removed. Please use \"{}\" instead.",
            key.display, replacement
        ),
        (Some(replacement), None) => format!(
            "The \"{}\" configuration key is deprecated. Please use \"{}\" instead. \"{}\" has been removed.",
            key.display, replacement, key.display
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
    let Some(table) = value.as_table() else {
        return false;
    };
    let dotted = path.join(".");
    if table.keys().any(|key| key.eq_ignore_ascii_case(&dotted)) {
        return true;
    }
    table
        .iter()
        .any(|(key, value)| key.eq_ignore_ascii_case(first) && toml_has_path(value, rest))
}

fn json_has_path(value: &serde_json::Value, path: &[&str]) -> bool {
    let Some((first, rest)) = path.split_first() else {
        return !value.is_null();
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    let dotted = path.join(".");
    if let Some((_, value)) = object
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(&dotted))
    {
        return !value.is_null();
    }
    object
        .iter()
        .any(|(key, value)| key.eq_ignore_ascii_case(first) && json_has_path(value, rest))
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

fn deserialize_optional_cli_dns<'de, D>(deserializer: D) -> Result<Option<DnsConfigSpec>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(mut value) = Option::<serde_json::Value>::deserialize(deserializer)? else {
        return Ok(None);
    };
    if let Some(object) = value.as_object_mut()
        && object
            .get("extra_records")
            .is_some_and(|value| !value.is_null())
        && object
            .get("extra_records_path")
            .is_some_and(|value| !value.is_null())
    {
        // Presence metadata rejects this configuration before either source
        // is decoded or opened. Leave the public DnsConfigSpec decoder strict;
        // only this private CLI boundary defers the conflict to Go's fatal
        // validation phase, after OIDC validation and removed-key reporting.
        object.remove("extra_records");
        object.remove("extra_records_path");
    }
    serde_json::from_value(value)
        .map(Some)
        .map_err(de::Error::custom)
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

fn deserialize_optional_cli_duration_nanos<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.as_ref().map(cast_cli_duration_value))
}

fn cast_cli_duration_value(value: &serde_json::Value) -> i64 {
    match value {
        serde_json::Value::String(value) => cast_cli_duration_string(value),
        serde_json::Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                value
            } else if let Some(value) = value.as_u64() {
                // spf13/cast converts integer types directly to int64.
                value as i64
            } else {
                let value = value.as_f64().unwrap_or_default();
                if !value.is_finite()
                    || !(-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&value)
                {
                    i64::MIN
                } else {
                    value as i64
                }
            }
        }
        // Viper's GetDuration intentionally discards cast errors and returns
        // zero for unsupported values, creating an expired command context.
        _ => 0,
    }
}

fn cast_cli_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) if value.is_f64() => {
            // cast uses strconv.FormatFloat with 'f', never exponent notation.
            value.as_f64().unwrap_or_default().to_string()
        }
        serde_json::Value::Number(value) => value.to_string(),
        _ => String::new(),
    }
}

fn cast_cli_bool(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Bool(value) => *value,
        serde_json::Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        serde_json::Value::String(value) => cast_cli_bool_string(value),
        _ => false,
    }
}

fn cast_cli_bool_string(value: &str) -> bool {
    // strconv.ParseBool accepts these exact spellings; Viper discards errors.
    matches!(value, "1" | "t" | "T" | "true" | "TRUE" | "True")
}

fn cast_cli_duration_string(value: &str) -> i64 {
    let value_with_unit;
    let duration = if value.contains(['n', 's', 'u', 'µ', 'm', 'h']) {
        value
    } else {
        value_with_unit = format!("{value}ns");
        &value_with_unit
    };
    headscale_cli::admin::duration::parse_go_duration_nanos(duration).unwrap_or_default()
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
    headscale_api_acl::go_netip::parse_prefix(raw).map_err(anyhow::Error::msg)
}

fn validate_config_prefix(raw: &str, label: &str) -> Result<()> {
    if raw.is_empty() {
        return Ok(());
    }
    headscale_api_acl::go_netip::parse_prefix(raw)
        .map(|_| ())
        .map_err(|error| anyhow::anyhow!("parsing {label} prefix from config: {error}"))
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

fn policy_ssh_config_is_default(config: &PolicySshConfig) -> bool {
    config == &PolicySshConfig::default()
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

pub(crate) fn default_cli_timeout_nanos() -> i64 {
    (DEFAULT_CLI_TIMEOUT_SECS * 1_000_000_000) as i64
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
            noise_private_key_path: None,
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

    impl CliConfig {
        // Most unit fixtures exercise a different validation rule. Give those
        // upstream-shaped fixtures the prefix Go requires before validating.
        fn validate_test_fixture(&self) -> Result<()> {
            let mut fixture = self.clone();
            if fixture.server_url.is_some() && fixture.prefixes.is_none() {
                fixture.prefixes = Some(UpstreamPrefixesConfig {
                    v4: Some("100.64.0.0/10".to_string()),
                    ..Default::default()
                });
            }
            fixture.validate_for_configtest()
        }
    }

    #[test]
    fn cli_config_includes_upstream_oidc_defaults() {
        let config = CliConfig::default();

        assert_eq!(LoggingConfig::default().format, "text");
        assert!(config.taildrop.enabled);
        assert!(!config.oidc.enabled);
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
    fn applies_headscale_runtime_feature_env_overrides_to_cli_config() {
        let mut config = CliConfig::default();

        config
            .apply_runtime_feature_env_overrides_from([
                ("HEADSCALE_DISABLE_CHECK_UPDATES", "true"),
                ("HEADSCALE_LOGTAIL_ENABLED", "true"),
                ("HEADSCALE_AUTO_UPDATE_ENABLED", "true"),
            ])
            .unwrap();

        assert!(config.disable_check_updates);
        assert!(config.logtail.enabled);
        assert!(config.auto_update.enabled);

        config
            .apply_runtime_feature_env_overrides_from([
                ("HEADSCALE_LOGTAIL_ENABLED", "false"),
                ("HEADSCALE_AUTO_UPDATE_ENABLED", "false"),
            ])
            .unwrap();

        assert!(!config.logtail.enabled);
        assert!(!config.auto_update.enabled);
    }

    #[test]
    fn applies_headscale_database_env_overrides_to_cli_config() {
        let mut config = CliConfig::default();

        config
            .apply_database_env_overrides_from([
                ("HEADSCALE_DATABASE_TYPE", "postgres"),
                ("HEADSCALE_DATABASE_DEBUG", "true"),
                ("HEADSCALE_DATABASE_GORM_DEBUG", "true"),
                ("HEADSCALE_DATABASE_GORM_SLOW_THRESHOLD", "1500"),
                ("HEADSCALE_DATABASE_GORM_SKIP_ERR_RECORD_NOT_FOUND", "true"),
                ("HEADSCALE_DATABASE_GORM_PARAMETERIZED_QUERIES", "true"),
                ("HEADSCALE_DATABASE_GORM_PREPARE_STMT", "true"),
                (
                    "HEADSCALE_DATABASE_SQLITE_PATH",
                    "/srv/headscale/env.sqlite",
                ),
                ("HEADSCALE_DATABASE_SQLITE_WRITE_AHEAD_LOG", "false"),
                ("HEADSCALE_DATABASE_SQLITE_WAL_AUTOCHECKPOINT", "250"),
                ("HEADSCALE_DATABASE_POSTGRES_HOST", "pg.example"),
                ("HEADSCALE_DATABASE_POSTGRES_PORT", "5433"),
                ("HEADSCALE_DATABASE_POSTGRES_NAME", "headscale_env"),
                ("HEADSCALE_DATABASE_POSTGRES_USER", "headscale"),
                ("HEADSCALE_DATABASE_POSTGRES_PASS", "secret"),
                ("HEADSCALE_DATABASE_POSTGRES_SSL", "verify-full"),
                ("HEADSCALE_DATABASE_POSTGRES_MAX_OPEN_CONNS", "11"),
                ("HEADSCALE_DATABASE_POSTGRES_MAX_IDLE_CONNS", "7"),
                ("HEADSCALE_DATABASE_POSTGRES_CONN_MAX_IDLE_TIME_SECS", "120"),
            ])
            .unwrap();

        let database = config.database.as_ref().unwrap();
        assert_eq!(database.runtime_backend(), Some(DatabaseBackend::Postgres));
        assert_eq!(database.debug_type(), "postgres");
        assert!(database.debug_enabled());
        assert!(database.debug_gorm().debug(false));
        assert_eq!(database.debug_gorm().slow_threshold_nanos(), 1_500_000_000);
        assert!(database.debug_gorm().skip_err_record_not_found());
        assert!(database.debug_gorm().parameterized_queries());
        assert!(database.debug_gorm().prepare_stmt());
        assert_eq!(
            database.debug_sqlite().path(),
            Some(Path::new("/srv/headscale/env.sqlite"))
        );
        assert!(!database.debug_sqlite().write_ahead_log());
        assert_eq!(database.debug_sqlite().wal_autocheckpoint(), 250);
        let postgres = database.debug_postgres();
        assert_eq!(postgres.host(), "pg.example");
        assert_eq!(postgres.port(), 5433);
        assert_eq!(postgres.name(), "headscale_env");
        assert_eq!(postgres.user(), "headscale");
        assert_eq!(postgres.ssl(), "verify-full");
        assert_eq!(postgres.max_open_conns(), 11);
        assert_eq!(postgres.max_idle_conns(), 7);
        assert_eq!(postgres.conn_max_idle_time_secs(), 120);
    }

    #[test]
    fn rejects_invalid_headscale_database_env_overrides() {
        let invalid_cases = [
            ("HEADSCALE_DATABASE_DEBUG", "maybe"),
            ("HEADSCALE_DATABASE_GORM_SLOW_THRESHOLD", "not-a-number"),
            ("HEADSCALE_DATABASE_SQLITE_WRITE_AHEAD_LOG", "maybe"),
            (
                "HEADSCALE_DATABASE_SQLITE_WAL_AUTOCHECKPOINT",
                "not-a-number",
            ),
            ("HEADSCALE_DATABASE_POSTGRES_PORT", "not-a-number"),
            ("HEADSCALE_DATABASE_POSTGRES_MAX_OPEN_CONNS", "not-a-number"),
        ];

        for (key, value) in invalid_cases {
            let mut config = CliConfig::default();
            let err = config
                .apply_database_env_overrides_from([(key, value)])
                .unwrap_err();
            assert!(
                format!("{err:#}").contains(&format!("invalid {key}")),
                "error for {key}: {err:#}"
            );
        }
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
    fn applies_headscale_ephemeral_env_overrides_to_cli_config() {
        let mut config = CliConfig::default();

        config
            .apply_node_env_overrides_from([("HEADSCALE_EPHEMERAL_NODE_INACTIVITY_TIMEOUT", "5m")])
            .unwrap();
        config.normalize_upstream_aliases();

        assert_eq!(config.ephemeral_node_inactivity_timeout, Some(300));
        assert!(config.server.is_none());

        config
            .apply_node_env_overrides_from([("HEADSCALE_NODE_EPHEMERAL_INACTIVITY_TIMEOUT", "6m")])
            .unwrap();
        config.normalize_upstream_aliases();

        assert_eq!(
            config
                .server
                .as_ref()
                .unwrap()
                .ephemeral_node_inactivity_timeout_secs,
            360
        );

        let err = config
            .apply_node_env_overrides_from([(
                "HEADSCALE_NODE_EPHEMERAL_INACTIVITY_TIMEOUT",
                "1500ms",
            )])
            .unwrap_err();

        assert!(format!("{err:#}").contains("invalid HEADSCALE_NODE_EPHEMERAL_INACTIVITY_TIMEOUT"));
    }

    #[test]
    fn applies_headscale_node_route_ha_env_overrides_to_cli_config() {
        let mut config = CliConfig::default();

        config
            .apply_node_env_overrides_from([
                ("HEADSCALE_NODE_ROUTES_HA_PROBE_INTERVAL", "15s"),
                ("HEADSCALE_NODE_ROUTES_HA_PROBE_TIMEOUT", "4s"),
            ])
            .unwrap();

        let node = config.node.as_ref().expect("node config created");
        assert_eq!(node.routes.ha.probe_interval, Some(15));
        assert_eq!(node.routes.ha.probe_timeout, Some(4));

        let err = config
            .apply_node_env_overrides_from([("HEADSCALE_NODE_ROUTES_HA_PROBE_INTERVAL", "1500ms")])
            .unwrap_err();

        assert!(format!("{err:#}").contains("invalid HEADSCALE_NODE_ROUTES_HA_PROBE_INTERVAL"));
    }

    #[test]
    fn configtest_validates_node_route_ha_env_overrides_against_upstream_defaults() {
        let source = r#"
server_url: "https://headscale.example"
"#;
        let mut config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();

        config
            .apply_node_env_overrides_from([("HEADSCALE_NODE_ROUTES_HA_PROBE_TIMEOUT", "10s")])
            .unwrap();
        let err = config.validate_test_fixture().unwrap_err();
        let message = format!("{err:#}");

        assert!(
            message.contains(
                "node.routes.ha.probe_timeout (10s) must be less than node.routes.ha.probe_interval (10s)"
            ),
            "unexpected validation error: {message}"
        );
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
        assert_eq!(
            dns.nameserver_resolvers,
            [] as [headscale_api::tailscale_wire::wire::DnsResolver; 0]
        );
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
    fn applies_headscale_derp_env_overrides_to_cli_config() {
        let mut config = CliConfig::default();

        config
            .apply_derp_env_overrides_from([
                ("HEADSCALE_DERP_SERVER_ENABLED", "true"),
                ("HEADSCALE_DERP_SERVER_REGION_ID", "901"),
                ("HEADSCALE_DERP_SERVER_REGION_CODE", "env"),
                ("HEADSCALE_DERP_SERVER_REGION_NAME", "Env DERP"),
                ("HEADSCALE_DERP_SERVER_VERIFY_CLIENTS", "false"),
                ("HEADSCALE_DERP_SERVER_STUN_LISTEN_ADDR", "127.0.0.1:3479"),
                (
                    "HEADSCALE_DERP_SERVER_PRIVATE_KEY_PATH",
                    "/tmp/headscale-env-derp.key",
                ),
                ("HEADSCALE_DERP_SERVER_IPV4", "198.51.100.25"),
                ("HEADSCALE_DERP_SERVER_IPV6", "2001:db8::25"),
                (
                    "HEADSCALE_DERP_SERVER_AUTOMATICALLY_ADD_EMBEDDED_DERP_REGION",
                    "false",
                ),
                (
                    "HEADSCALE_DERP_URLS",
                    "https://derp.example/map.json https://derp2.example/map.json",
                ),
                (
                    "HEADSCALE_DERP_PATHS",
                    "/etc/headscale/derp.yaml /etc/headscale/private-derp.yaml",
                ),
                ("HEADSCALE_DERP_AUTO_UPDATE_ENABLED", "true"),
                ("HEADSCALE_DERP_UPDATE_FREQUENCY", "45m"),
            ])
            .unwrap();
        config
            .apply_server_transport_env_overrides_from([(
                "HEADSCALE_SERVER_URL",
                "https://env-headscale.example:8443",
            )])
            .unwrap();
        config.normalize_upstream_aliases();

        let derp = config.derp.as_ref().unwrap();
        assert!(derp.server.enabled);
        assert_eq!(derp.server.region_id, 901);
        assert_eq!(derp.server.region_code, "env");
        assert_eq!(derp.server.region_name, "Env DERP");
        assert!(!derp.server.verify_clients);
        assert_eq!(
            derp.server.stun_listen_addr,
            Some("127.0.0.1:3479".parse().unwrap())
        );
        assert_eq!(
            derp.server.private_key_path,
            PathBuf::from("/tmp/headscale-env-derp.key")
        );
        assert_eq!(derp.server.ipv4.as_deref(), Some("198.51.100.25"));
        assert_eq!(derp.server.ipv6.as_deref(), Some("2001:db8::25"));
        assert!(!derp.server.automatically_add_embedded_derp_region);
        assert_eq!(
            derp.urls,
            [
                "https://derp.example/map.json".to_string(),
                "https://derp2.example/map.json".to_string()
            ]
        );
        assert_eq!(
            derp.paths,
            [
                PathBuf::from("/etc/headscale/derp.yaml"),
                PathBuf::from("/etc/headscale/private-derp.yaml")
            ]
        );
        assert!(derp.auto_update_enabled);
        assert_eq!(derp.update_frequency, 2_700);

        let embedded = &config.server.as_ref().unwrap().embedded_derp;
        assert!(embedded.enabled);
        assert_eq!(embedded.host_name, "env-headscale.example");
        assert_eq!(embedded.derp_port, 8443);
        assert_eq!(embedded.region_id, 901);
        assert_eq!(embedded.region_code, "env");
        assert_eq!(embedded.region_name, "Env DERP");
        assert_eq!(embedded.stun_addr, Some("127.0.0.1:3479".parse().unwrap()));
        assert!(!embedded.stun_only);
        assert_eq!(embedded.relay_mode, EmbeddedDerpRelayMode::Native);
        assert!(!embedded.verify_clients);
        assert_eq!(
            embedded.derper_config_path,
            PathBuf::from("/tmp/headscale-env-derp.key")
        );
        assert_eq!(embedded.ipv4, "198.51.100.25");
        assert_eq!(embedded.ipv6, "2001:db8::25");
    }

    #[test]
    fn rejects_invalid_headscale_derp_env_overrides() {
        let mut config = CliConfig::default();

        let err = config
            .apply_derp_env_overrides_from([("HEADSCALE_DERP_SERVER_ENABLED", "maybe")])
            .unwrap_err();
        assert!(format!("{err:#}").contains("invalid HEADSCALE_DERP_SERVER_ENABLED"));

        let err = config
            .apply_derp_env_overrides_from([("HEADSCALE_DERP_SERVER_REGION_ID", "not-a-number")])
            .unwrap_err();
        assert!(format!("{err:#}").contains("invalid HEADSCALE_DERP_SERVER_REGION_ID"));

        // Go's RegionID is an int, so ids beyond u16 are valid configuration.
        config
            .apply_derp_env_overrides_from([("HEADSCALE_DERP_SERVER_REGION_ID", "70000")])
            .unwrap();
        assert_eq!(config.derp.as_ref().unwrap().server.region_id, 70_000);

        let err = config
            .apply_derp_env_overrides_from([(
                "HEADSCALE_DERP_SERVER_STUN_LISTEN_ADDR",
                "not-a-socket",
            )])
            .unwrap_err();
        assert!(format!("{err:#}").contains("invalid HEADSCALE_DERP_SERVER_STUN_LISTEN_ADDR"));

        let err = config
            .apply_derp_env_overrides_from([("HEADSCALE_DERP_UPDATE_FREQUENCY", "1500ms")])
            .unwrap_err();
        assert!(format!("{err:#}").contains("invalid HEADSCALE_DERP_UPDATE_FREQUENCY"));
    }

    #[test]
    fn applies_headscale_tuning_env_overrides_to_cli_config() {
        let mut config = CliConfig::default();

        config
            .apply_tuning_env_overrides_from([
                ("HEADSCALE_TUNING_NODE_STORE_BATCH_SIZE", "256"),
                ("HEADSCALE_TUNING_NODE_STORE_BATCH_TIMEOUT", "250ms"),
            ])
            .unwrap();

        assert_eq!(config.tuning.node_store_batch_size, 256);
        assert_eq!(config.tuning.node_store_batch_timeout, 250_000_000);

        config
            .apply_tuning_env_overrides_from([
                ("HEADSCALE_TUNING_NODE_STORE_BATCH_SIZE", "0"),
                ("HEADSCALE_TUNING_NODE_STORE_BATCH_TIMEOUT", "0s"),
            ])
            .unwrap();

        assert_eq!(config.tuning.node_store_batch_size, 0);
        assert_eq!(config.tuning.node_store_batch_timeout, 0);
    }

    #[test]
    fn rejects_invalid_headscale_tuning_env_overrides() {
        let mut config = CliConfig::default();

        let err = config
            .apply_tuning_env_overrides_from([(
                "HEADSCALE_TUNING_NODE_STORE_BATCH_SIZE",
                "not-a-number",
            )])
            .unwrap_err();
        assert!(format!("{err:#}").contains("invalid HEADSCALE_TUNING_NODE_STORE_BATCH_SIZE"));

        let err = config
            .apply_tuning_env_overrides_from([(
                "HEADSCALE_TUNING_NODE_STORE_BATCH_TIMEOUT",
                "not-a-duration",
            )])
            .unwrap_err();
        assert!(format!("{err:#}").contains("invalid HEADSCALE_TUNING_NODE_STORE_BATCH_TIMEOUT"));
    }

    #[test]
    fn applies_headscale_logging_env_overrides_to_cli_config() {
        let mut config = CliConfig::default();

        config.apply_logging_env_overrides_from([
            ("HEADSCALE_LOG_LEVEL", "debug"),
            ("HEADSCALE_LOG_FORMAT", "json"),
        ]);

        let logging = config.logging.unwrap();
        assert_eq!(logging.level, "debug");
        assert_eq!(logging.format, "json");
    }

    #[test]
    fn applies_headscale_tls_acme_env_overrides_to_cli_config() {
        let mut config = CliConfig::default();

        config.apply_tls_acme_env_overrides_from([
            ("HEADSCALE_ACME_URL", "https://acme.example/directory"),
            ("HEADSCALE_ACME_EMAIL", "ops@example.com"),
            ("HEADSCALE_TLS_LETSENCRYPT_HOSTNAME", "headscale.example"),
            (
                "HEADSCALE_TLS_LETSENCRYPT_CACHE_DIR",
                "/var/lib/headscale/acme",
            ),
            ("HEADSCALE_TLS_LETSENCRYPT_LISTEN", "127.0.0.1:8080"),
            ("HEADSCALE_TLS_LETSENCRYPT_CHALLENGE_TYPE", "TLS-ALPN-01"),
            ("HEADSCALE_TLS_CERT_PATH", "/etc/headscale/cert.pem"),
            ("HEADSCALE_TLS_KEY_PATH", "/etc/headscale/key.pem"),
        ]);

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
            Some(Path::new("/var/lib/headscale/acme"))
        );
        assert_eq!(
            config.tls_letsencrypt_listen.as_deref(),
            Some("127.0.0.1:8080")
        );
        assert_eq!(
            config.tls_letsencrypt_challenge_type.as_deref(),
            Some("TLS-ALPN-01")
        );
        assert_eq!(
            config.tls_cert_path.as_deref(),
            Some(Path::new("/etc/headscale/cert.pem"))
        );
        assert_eq!(
            config.tls_key_path.as_deref(),
            Some(Path::new("/etc/headscale/key.pem"))
        );
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
        let err = config.validate_test_fixture().unwrap_err();

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
            let err = config.validate_test_fixture().unwrap_err();
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
        config.validate_test_fixture().unwrap();

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

        let err = config.validate_test_fixture().unwrap_err();
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

        let err = config.validate_test_fixture().unwrap_err();
        assert!(format!("{err:#}").contains("netip.ParsePrefix(\"127.0.0.1\"): no '/'"));
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
        assert_eq!(server.ephemeral_node_inactivity_timeout_secs, 120);
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
database:
  type: sqlite
policy:
  mode: file
  path: policy.hujson
"#,
        )
        .unwrap();

        let config = CliConfig::load(&config_path).unwrap();

        assert_eq!(config.policy.mode(), "file");
        assert_eq!(config.policy.path, dir.path().join("policy.hujson"));
        config.validate_test_fixture().unwrap();
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
database:
  type: sqlite
policy:
  mode: database
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();

        assert!(config.policy.is_database_mode());
        config.validate_test_fixture().unwrap();
    }

    #[test]
    fn applies_headscale_policy_env_overrides_to_cli_config() {
        let mut config = CliConfig {
            policy: PolicyConfig {
                mode: "file".to_string(),
                path: PathBuf::from("configured-policy.hujson"),
                ssh: PolicySshConfig::default(),
            },
            ..CliConfig::default()
        };

        config
            .apply_policy_env_overrides_from([
                ("HEADSCALE_POLICY_MODE", "database"),
                ("HEADSCALE_POLICY_PATH", "/etc/headscale/policy.hujson"),
            ])
            .unwrap();

        assert_eq!(config.policy.mode(), "database");
        assert_eq!(
            config.policy.path,
            PathBuf::from("/etc/headscale/policy.hujson")
        );
    }

    const POLICY_SSH_BASE_YAML: &str = r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
"#;

    fn forwarding_of(config: &CliConfig) -> [bool; 3] {
        let forwarding = config.policy.ssh.forwarding();
        [
            forwarding.agent,
            forwarding.local_port,
            forwarding.remote_port,
        ]
    }

    #[test]
    fn policy_ssh_forwarding_defaults_to_allow_all_and_stays_out_of_the_dump() {
        let config = CliConfig::parse(POLICY_SSH_BASE_YAML, ConfigFormat::Yaml).unwrap();
        assert_eq!(forwarding_of(&config), [true, true, true]);
        assert_eq!(config.policy.ssh, PolicySshConfig::default());

        // A Go-valid `policy:` block with no `ssh` key loads unchanged and
        // dumps exactly as it did before the setting existed.
        let with_policy = format!("{POLICY_SSH_BASE_YAML}policy:\n  mode: database\n");
        let config = CliConfig::parse(&with_policy, ConfigFormat::Yaml).unwrap();
        assert_eq!(forwarding_of(&config), [true, true, true]);
        let dump = headscale_cli::yaml::to_string(&config).unwrap();
        assert!(dump.contains("mode: database"), "{dump}");
        assert!(!dump.contains("ssh"), "{dump}");
        assert!(!dump.contains("forwarding"), "{dump}");

        let default_dump = headscale_cli::yaml::to_string(
            &CliConfig::parse(POLICY_SSH_BASE_YAML, ConfigFormat::Yaml).unwrap(),
        )
        .unwrap();
        assert!(!default_dump.contains("policy"), "{default_dump}");
    }

    #[test]
    fn policy_ssh_forwarding_loads_each_flag_from_every_config_format() {
        for (flag, want) in [
            ("allow_agent_forwarding", [false, true, true]),
            ("allow_local_port_forwarding", [true, false, true]),
            ("allow_remote_port_forwarding", [true, true, false]),
        ] {
            let yaml = format!("{POLICY_SSH_BASE_YAML}policy:\n  ssh:\n    {flag}: false\n");
            let config = CliConfig::parse(&yaml, ConfigFormat::Yaml).unwrap();
            assert_eq!(forwarding_of(&config), want, "yaml {flag}");
            // The block stays file-mode like Go's default.
            assert_eq!(config.policy.mode(), "file");

            let toml = format!(
                "server_url = \"https://headscale.example\"\n\
                 [noise]\nprivate_key_path = \"noise_private.key\"\n\
                 [dns]\nmagic_dns = false\noverride_local_dns = false\n\
                 [database]\ntype = \"sqlite\"\n\
                 [policy.ssh]\n{flag} = false\n"
            );
            let config = CliConfig::parse(&toml, ConfigFormat::Toml).unwrap();
            assert_eq!(forwarding_of(&config), want, "toml {flag}");

            let json = format!(
                r#"{{"server_url":"https://headscale.example","noise":{{"private_key_path":"noise_private.key"}},"dns":{{"magic_dns":false,"override_local_dns":false}},"database":{{"type":"sqlite"}},"policy":{{"ssh":{{"{flag}":false}}}}}}"#
            );
            let config = CliConfig::parse(&json, ConfigFormat::Json).unwrap();
            assert_eq!(forwarding_of(&config), want, "json {flag}");
        }

        let all_off = format!(
            "{POLICY_SSH_BASE_YAML}policy:\n  mode: database\n  ssh:\n    \
             allow_agent_forwarding: false\n    allow_local_port_forwarding: false\n    \
             allow_remote_port_forwarding: false\n"
        );
        let config = CliConfig::parse(&all_off, ConfigFormat::Yaml).unwrap();
        assert_eq!(forwarding_of(&config), [false, false, false]);
        assert!(config.policy.is_database_mode());

        // An explicit setting is operator-visible in the config dump.
        let dump = headscale_cli::yaml::to_string(&config).unwrap();
        assert!(dump.contains("allow_agent_forwarding: false"), "{dump}");
    }

    #[test]
    fn policy_ssh_forwarding_rejects_non_booleans_and_unknown_keys() {
        // The YAML reader reports a wrong-typed value by line and column
        // rather than by key name.
        for body in [
            "allow_agent_forwarding: maybe",
            "allow_local_port_forwarding: 0",
            "allow_remote_port_forwarding: [false]",
        ] {
            let yaml = format!("{POLICY_SSH_BASE_YAML}policy:\n  ssh:\n    {body}\n");
            let err = CliConfig::parse(&yaml, ConfigFormat::Yaml).expect_err(body);
            let chain = format!("{err:#}");
            assert!(
                chain.starts_with("failed to parse YAML config: "),
                "{body}: {chain}"
            );
        }

        // A misspelling must not be silently ignored: that would leave
        // forwarding on while the operator believes it is off.
        for key in ["allow_agent_forwading", "allow_forwarding"] {
            let yaml = format!("{POLICY_SSH_BASE_YAML}policy:\n  ssh:\n    {key}: false\n");
            let err = CliConfig::parse(&yaml, ConfigFormat::Yaml).expect_err(key);
            let chain = format!("{err:#}");
            assert!(
                chain.contains(key),
                "{key}: error should name the unknown key, got: {chain}"
            );
        }

        let toml_with = |value: &str| {
            format!(
                "server_url = \"https://headscale.example\"\n\
                 [noise]\nprivate_key_path = \"noise_private.key\"\n\
                 [dns]\nmagic_dns = false\noverride_local_dns = false\n\
                 [database]\ntype = \"sqlite\"\n\
                 [policy.ssh]\nallow_agent_forwarding = {value}\n"
            )
        };
        // Same document, only the value's type differs: a string is not a bool.
        assert!(CliConfig::parse(&toml_with("false"), ConfigFormat::Toml).is_ok());
        assert!(CliConfig::parse(&toml_with("\"false\""), ConfigFormat::Toml).is_err());
    }

    #[test]
    fn policy_ssh_forwarding_env_overrides_are_validated() {
        let mut config = CliConfig::default();
        config
            .apply_policy_env_overrides_from([
                ("HEADSCALE_POLICY_SSH_ALLOW_AGENT_FORWARDING", "false"),
                ("HEADSCALE_POLICY_SSH_ALLOW_LOCAL_PORT_FORWARDING", "0"),
                ("HEADSCALE_POLICY_SSH_ALLOW_REMOTE_PORT_FORWARDING", "true"),
            ])
            .unwrap();
        assert_eq!(forwarding_of(&config), [false, false, true]);

        // Empty values are treated as unset, like the other policy variables.
        let mut config = CliConfig::default();
        config
            .apply_policy_env_overrides_from([("HEADSCALE_POLICY_SSH_ALLOW_AGENT_FORWARDING", "")])
            .unwrap();
        assert_eq!(forwarding_of(&config), [true, true, true]);

        let mut config = CliConfig::default();
        let err = config
            .apply_policy_env_overrides_from([(
                "HEADSCALE_POLICY_SSH_ALLOW_AGENT_FORWARDING",
                "disable",
            )])
            .expect_err("a typo'd boolean must not leave forwarding enabled");
        assert!(
            format!("{err:#}").contains("HEADSCALE_POLICY_SSH_ALLOW_AGENT_FORWARDING"),
            "{err:#}"
        );
    }

    #[test]
    fn configtest_accepts_unknown_policy_mode_like_go() {
        let source = r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
policy:
  mode: consul
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        config.validate_test_fixture().unwrap();
    }

    #[test]
    fn configtest_policy_file_allows_empty_and_rejects_malformed() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("policy.hujson"), "{").unwrap();
        let config_path = dir.path().join("config.yaml");
        fs::write(
            &config_path,
            r#"
server_url: "https://headscale.example"
noise:
  private_key_path: noise_private.key
database:
  type: sqlite
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
        let err = config.validate_test_fixture().unwrap_err();

        assert!(format!("{err:#}").contains("parse policy.path"));
        fs::write(dir.path().join("policy.hujson"), "").unwrap();
        config.validate_test_fixture().unwrap();
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
prefixes:
  v4: "100.64.0.0/10"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let err = config.validate_test_fixture().unwrap_err();

        assert!(format!("{err:#}").contains("dns.nameservers.global"));
        let server = config.server.unwrap();
        assert_eq!(server.server_url.as_deref(), Some("https://derp.no"));
        assert_eq!(server.state_dir, PathBuf::from("."));
    }

    #[test]
    fn parses_pinned_headscale_go_v0_28_config_example_fixture() {
        let source = include_str!("../tests/fixtures/headscale-go-v0.28-config-example.yaml");

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();

        config.validate_test_fixture().unwrap();
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
        let err = config.validate_test_fixture().unwrap_err().to_string();

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
        let err = config.validate_test_fixture().unwrap_err().to_string();

        assert!(err.contains("no IPv4 or IPv6 prefix configured"));
    }

    #[test]
    fn configtest_rejects_malformed_prefixes_like_upstream() {
        for (field, raw, expected) in [
            (
                "v4",
                r#"v4: "not-a-cidr""#,
                "parsing IPv4 prefix from config",
            ),
            (
                "v6",
                r#"v6: "not-a-cidr""#,
                "parsing IPv6 prefix from config",
            ),
            ("v4", r#"v4: "100.64.0.0/99""#, "prefix length out of range"),
        ] {
            let source = format!(
                r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
prefixes:
  {raw}
dns:
  magic_dns: false
  override_local_dns: false
"#
            );

            let config = CliConfig::parse(&source, ConfigFormat::Yaml).unwrap();
            let err = config.validate_test_fixture().unwrap_err().to_string();

            assert!(
                err.contains(expected),
                "{field} should contain {expected:?}, got {err:?}"
            );
        }
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

        config.validate_test_fixture().unwrap();
    }

    #[test]
    fn configtest_rejects_invalid_postgres_pool_config() {
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
    max_open_conns: -1
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let err = config.validate_test_fixture().unwrap_err();

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

        config.validate_test_fixture().unwrap();
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

        config.validate_test_fixture().unwrap();
        assert_eq!(
            config.database.as_ref().unwrap().runtime_backend(),
            Some(DatabaseBackend::Postgres)
        );
    }

    #[test]
    fn configtest_rejects_missing_database_type() {
        for source in [
            r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
"#,
            r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  postgres:
    host: localhost
    port: 5432
"#,
            r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  sqlite:
    path: /var/lib/headscale/db.sqlite
"#,
        ] {
            let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
            let err = config.validate_test_fixture().unwrap_err();

            assert!(format!("{err:#}").contains("database.type is required"));
        }
    }

    #[test]
    fn configtest_rejects_postgresql_database_type_alias() {
        let source = r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: postgresql
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let err = config.validate_test_fixture().unwrap_err();
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
        let err = config.validate_test_fixture().unwrap_err();

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
database:
  type: sqlite
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
        config.validate_test_fixture().unwrap();
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
database:
  type: sqlite
tls_letsencrypt_hostname: "headscale.example"
tls_letsencrypt_cache_dir: "/var/lib/headscale/acme-cache"
tls_letsencrypt_listen: ":http"
tls_letsencrypt_challenge_type: "HTTP-01"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        config.validate_test_fixture().unwrap();
    }

    #[test]
    fn configtest_rejects_explicit_empty_acme_challenge_type() {
        let source = r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
tls_letsencrypt_hostname: "headscale.example"
tls_letsencrypt_challenge_type: ""
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let err = config.validate_test_fixture().unwrap_err();

        assert_eq!(
            format!("{err:#}"),
            "Fatal config error: the only supported values for tls_letsencrypt_challenge_type are HTTP-01 and TLS-ALPN-01"
        );
    }

    #[test]
    fn configtest_rejects_invalid_http01_acme_listener() {
        let source = r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
tls_letsencrypt_hostname: "headscale.example"
tls_letsencrypt_listen: "not-a-socket"
tls_letsencrypt_challenge_type: "HTTP-01"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let err = config.validate_test_fixture().unwrap_err();

        assert!(
            format!("{err:#}").contains("Invalid tls_letsencrypt_listen address"),
            "{err:#}"
        );
    }

    #[test]
    fn configtest_ignores_http01_listener_for_tls_alpn_acme() {
        let source = r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
tls_letsencrypt_hostname: "headscale.example"
tls_letsencrypt_listen: "not-a-socket"
tls_letsencrypt_challenge_type: "TLS-ALPN-01"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();

        config.validate_test_fixture().unwrap();
    }

    #[test]
    fn configtest_warns_for_tls_alpn_acme_non_443_listen_addr() {
        let source = r#"
server_url: "https://headscale.example"
listen_addr: "127.0.0.1:8443"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
tls_letsencrypt_hostname: "headscale.example"
tls_letsencrypt_challenge_type: "TLS-ALPN-01"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();

        config.validate_test_fixture().unwrap();
        assert_eq!(
            config.upstream_nonfatal_config_warnings(),
            vec![TLS_ALPN_ACME_PORT_WARNING]
        );
    }

    #[test]
    fn configtest_does_not_warn_for_tls_alpn_acme_443_listen_addr() {
        let source = r#"
server_url: "https://headscale.example"
listen_addr: "127.0.0.1:443"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
tls_letsencrypt_hostname: "headscale.example"
tls_letsencrypt_challenge_type: "TLS-ALPN-01"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();

        config.validate_test_fixture().unwrap();
        assert_eq!(
            config.upstream_nonfatal_config_warnings(),
            Vec::<&str>::new()
        );
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
        let err = config.validate_test_fixture().unwrap_err();

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
        // Unlike the keys above, Go never passes dns.extra_records_path
        // through util.AbsolutePathFromConfigPath: config.go:913 stores the
        // raw string and app.go:687 opens it as given, so it stays relative to
        // the working directory (a pinned v0.29.5 oracle run from another
        // directory fails with "stat rel-extra.json: no such file or
        // directory" even though the file is next to the config).
        assert_eq!(
            dns.extra_records_path.as_deref(),
            Some(Path::new("dns/extra-records.json"))
        );
    }

    #[test]
    fn load_keeps_relative_dns_extra_records_path_as_written() {
        // headscale-go passes dns.extra_records_path through unchanged
        // (hscontrol/types/config.go:913 -> hscontrol/app.go:687), so a
        // relative value is relative to the process working directory, not
        // the config file. A pinned v0.29.5 oracle started from another
        // directory with the file beside its config fails with
        // "stat rel-extra.json: no such file or directory".
        let dir = tempfile::tempdir().unwrap();
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
  extra_records_path: "rel-extra.json"
database:
  type: sqlite
"#,
        )
        .unwrap();

        let config = CliConfig::load(&config_path).unwrap();
        assert_eq!(
            config.dns.as_ref().unwrap().extra_records_path.as_deref(),
            Some(Path::new("rel-extra.json"))
        );
        // Keys that Go passes through util.AbsolutePathFromConfigPath still
        // resolve against the config directory.
        assert_eq!(
            config.noise.as_ref().unwrap().private_key_path.as_deref(),
            Some(dir.path().join("noise_private.key").as_path())
        );

        // The environment override goes through the same resolution pass.
        let mut config = CliConfig::default();
        config
            .apply_dns_env_overrides_from([("HEADSCALE_DNS_EXTRA_RECORDS_PATH", "env/extra.json")])
            .unwrap();
        config.resolve_config_relative_paths(Path::new("/etc/headscale"));
        assert_eq!(
            config.dns.as_ref().unwrap().extra_records_path.as_deref(),
            Some(Path::new("env/extra.json"))
        );
    }

    #[test]
    fn configtest_rejects_too_low_node_ephemeral_timeout() {
        let source = r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
node:
  ephemeral:
    inactivity_timeout: "65s"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let err = config.validate_test_fixture().unwrap_err();

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
        assert_eq!(cli.timeout, Some(7_000_000_000));
    }

    #[test]
    fn applies_headscale_cli_env_overrides_to_cli_config() {
        let mut config = CliConfig::default();

        config.apply_cli_env_overrides_from([
            ("HEADSCALE_CLI_ADDRESS", "env.example:50443"),
            ("HEADSCALE_CLI_API_KEY", "hskey-api-env-secret"),
            ("HEADSCALE_CLI_INSECURE", "true"),
            ("HEADSCALE_CLI_TIMEOUT", "9s"),
        ]);

        let cli = config.cli.unwrap();
        assert_eq!(cli.address.as_deref(), Some("env.example:50443"));
        assert_eq!(cli.api_key.as_deref(), Some("hskey-api-env-secret"));
        assert_eq!(cli.insecure, Some(true));
        assert_eq!(cli.timeout, Some(9_000_000_000));
    }

    #[test]
    fn preserves_fractional_headscale_cli_timeout_env_override() {
        let mut config = CliConfig::default();

        config.apply_cli_env_overrides_from([("HEADSCALE_CLI_TIMEOUT", "1500ms")]);

        assert_eq!(config.cli.unwrap().timeout, Some(1_500_000_000));
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
relay_mode = "sidecar"
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
        assert_eq!(embedded.relay_mode, EmbeddedDerpRelayMode::Sidecar);
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

[database]
type = "sqlite"

[dns]
magic_dns = false
override_local_dns = false

[server.embedded_derp]
enabled = true
host_name = "derp.example.com"
stun_only = true
"#;

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        let err = config.validate_test_fixture().unwrap_err();

        assert!(
            format!("{err:#}").contains(
                "server.embedded_derp.stun_addr is required when embedded DERP is enabled"
            ),
            "{err:#}"
        );
    }

    #[test]
    fn configtest_accepts_native_embedded_derp_without_sidecar_binary() {
        let source = r#"
[server]
server_url = "https://headscale.example"

[noise]
private_key_path = "/var/lib/headscale/noise_private.key"

[database]
type = "sqlite"

[dns]
magic_dns = false
override_local_dns = false

[server.embedded_derp]
enabled = true
host_name = "headscale.example"
stun_addr = "127.0.0.1:3478"
relay_mode = "native"
derper_config_path = "/var/lib/headscale/derp_server_private.key"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();

        config.validate_test_fixture().unwrap();
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
        assert!(!embedded.stun_only);
        assert_eq!(embedded.relay_mode, EmbeddedDerpRelayMode::Native);
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
        assert!(!embedded.stun_only);
        assert_eq!(embedded.relay_mode, EmbeddedDerpRelayMode::Native);
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
        let err = config.validate_test_fixture().unwrap_err();

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

[database]
type = "sqlite"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        let err = config.validate_test_fixture().unwrap_err();

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

[database]
type = "sqlite"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        let err = config.validate_test_fixture().unwrap_err();

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

[database]
type = "sqlite"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();

        config.validate_test_fixture().unwrap();
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
        let err = config.validate_test_fixture().unwrap_err();

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
        assert!(!config.oidc.enabled);
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
        let err = config.validate_test_fixture().unwrap_err();

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
        let err = config.validate_test_fixture().unwrap_err();

        assert!(format!("{err:#}").contains(MISSING_NOISE_PRIVATE_KEY_PATH_ERROR));
    }

    #[test]
    fn rejects_dns_extra_records_and_path_together() {
        let mut config = CliConfig::parse(
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
        .unwrap();
        let err = config.complete_server_config_load().unwrap_err();

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
    fn rejects_removed_randomize_client_port_env_override() {
        let mut config = CliConfig::default();

        let err = config
            .apply_runtime_feature_env_overrides_from([("HEADSCALE_RANDOMIZE_CLIENT_PORT", "true")])
            .unwrap_err();
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
    fn warns_for_removed_dns_nameservers_when_replacement_default_is_set() {
        let config = CliConfig::parse(
            r#"
dns_config:
  nameservers:
    - "1.1.1.1"
"#,
            ConfigFormat::Yaml,
        )
        .unwrap();
        let warnings = config.upstream_deprecation_warnings().join("\n");
        assert!(warnings.contains("dns_config.nameservers"));
        assert!(warnings.contains("dns.nameservers.global"));
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
    fn configtest_accepts_invalid_oidc_pkce_method_when_oidc_enabled_is_absent() {
        let source = r#"
server_url = "https://headscale.example"

[noise]
private_key_path = "noise_private.key"

[dns]
magic_dns = false
override_local_dns = false

[database]
type = "sqlite"

[oidc.pkce]
method = "S384"
"#;

        let mut config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        config.resolve_oidc_client_secret().unwrap();
        config.validate_test_fixture().unwrap();
    }

    #[test]
    fn configtest_accepts_invalid_oidc_pkce_method_when_oidc_disabled() {
        let source = r#"
server_url = "https://headscale.example"

[noise]
private_key_path = "noise_private.key"

[dns]
magic_dns = false
override_local_dns = false

[database]
type = "sqlite"

[oidc]
enabled = false

[oidc.pkce]
method = "S384"
"#;

        let mut config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        config.resolve_oidc_client_secret().unwrap();
        config.validate_test_fixture().unwrap();
    }

    #[test]
    fn configtest_rejects_invalid_oidc_pkce_method_when_oidc_enabled() {
        let source = r#"
server_url = "https://headscale.example"

[noise]
private_key_path = "noise_private.key"

[dns]
magic_dns = false
override_local_dns = false

[database]
type = "sqlite"

[oidc]
enabled = true

[oidc.pkce]
method = "S384"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        let err = config.validate_test_fixture().unwrap_err();
        let err = format!("{err:#}");

        assert!(err.contains("pkce.method"));
    }
}
