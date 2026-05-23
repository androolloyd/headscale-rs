//! Configuration file handling for the CLI.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use headscale_api::dns::DnsConfigSpec;
use headscale_core::config::{EmbeddedDerpConfig, OidcConfig};
use serde::{Deserialize, Deserializer, Serialize, de};

const DEFAULT_CONFIG_FILENAMES: &[&str] =
    &["config.yaml", "config.yml", "config.json", "config.toml"];

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
    /// Upstream top-level `grpc_listen_addr`.
    #[serde(default, skip_serializing)]
    pub(crate) grpc_listen_addr: Option<String>,
    /// Upstream top-level `grpc_allow_insecure`.
    #[serde(default, skip_serializing)]
    pub(crate) grpc_allow_insecure: Option<bool>,
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
    /// Upstream top-level TLS/ACME fields used by config validation.
    #[serde(default, skip_serializing)]
    pub(crate) tls_letsencrypt_hostname: Option<String>,
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
    pub node: Option<NodeConfig>,
    /// Logging configuration
    pub logging: Option<LoggingConfig>,
    /// Top-level headscale-compatible DNS configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsConfigSpec>,
    /// OpenID Connect configuration
    #[serde(default, skip_serializing_if = "oidc_config_is_default")]
    pub oidc: OidcConfig,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct NodeConfig {
    /// Control plane URL
    pub server: String,
    /// Node name
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
    sqlite: Option<UpstreamSqliteConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct UpstreamSqliteConfig {
    #[serde(default)]
    path: Option<PathBuf>,
}

impl CliConfig {
    /// Load configuration from a file.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let mut config = Self::parse(&contents, ConfigFormat::from_path(path))?;
        config.normalize_upstream_aliases();
        config.apply_oidc_env_overrides_from(std::env::vars())?;
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

    fn resolve_oidc_client_secret(&mut self) -> Result<()> {
        self.oidc
            .resolve_client_secret()
            .context("failed to resolve OIDC client secret")
    }

    fn normalize_upstream_aliases(&mut self) {
        let had_server_block = self.server.is_some();
        let has_server_alias = self.server_url.is_some()
            || self.listen_addr.is_some()
            || self.grpc_listen_addr.is_some()
            || self.grpc_allow_insecure.is_some()
            || self.ephemeral_node_inactivity_timeout.is_some()
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
                .is_some_and(|database| database.sqlite_path().is_some());

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
        if let Some(grpc_listen_addr) = non_empty_clone(self.grpc_listen_addr.as_ref()) {
            server.grpc_listen_addr = grpc_listen_addr;
        }
        if let Some(grpc_allow_insecure) = self.grpc_allow_insecure {
            server.grpc_allow_insecure = grpc_allow_insecure;
        }
        if let Some(timeout) = self.ephemeral_node_inactivity_timeout {
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
        {
            server.db_path = sqlite_path;
        }

        self.server = Some(server);
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
        self.validate_upstream_database_config()?;
        self.validate_upstream_tls_config()?;

        let server = self.server.as_ref().context(
            "server.server_url is required so clients receive absolute registration URLs",
        )?;
        let server_url = server
            .server_url
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .context(
                "server.server_url is required so clients receive absolute registration URLs",
            )?;
        if !server_url.starts_with("http://") && !server_url.starts_with("https://") {
            bail!("server.server_url must start with https:// or http://");
        }
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
        }

        if server.embedded_derp.enabled {
            if server.embedded_derp.host_name.trim().is_empty() {
                bail!("server.embedded_derp.host_name is required when embedded DERP is enabled");
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

    fn validate_upstream_database_config(&self) -> Result<()> {
        let Some(database) = &self.database else {
            return Ok(());
        };
        let Some(database_type) = database.database_type.as_deref() else {
            return Ok(());
        };
        if matches!(database_type, "sqlite" | "sqlite3") {
            return Ok(());
        }
        bail!("database.type {database_type:?} is not supported yet; only sqlite is wired");
    }

    fn validate_upstream_tls_config(&self) -> Result<()> {
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
            bail!("set either tls_letsencrypt_hostname or tls_cert_path/tls_key_path, not both");
        }

        if let Some(challenge_type) = self
            .tls_letsencrypt_challenge_type
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            && challenge_type != "HTTP-01"
            && challenge_type != "TLS-ALPN-01"
        {
            bail!(
                "the only supported values for tls_letsencrypt_challenge_type are HTTP-01 and TLS-ALPN-01"
            );
        }

        Ok(())
    }
}

impl UpstreamDatabaseConfig {
    fn sqlite_path(&self) -> Option<PathBuf> {
        self.sqlite
            .as_ref()
            .and_then(|sqlite| sqlite.path.as_ref())
            .filter(|path| !path.as_os_str().is_empty())
            .cloned()
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

fn state_dir_from_noise_private_key(path: &Path) -> PathBuf {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
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
        replacement: Some("randomizeClientPort"),
        hint: Some(
            r#"Set "randomizeClientPort": true at the top level of your policy file, or grant the cap per-node via a "nodeAttrs" entry."#,
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
            "config key {} was removed; use {} instead. {}",
            key.display, replacement, hint
        ),
        (Some(replacement), None) => format!(
            "config key {} was removed; use {} instead",
            key.display, replacement
        ),
        (None, Some(hint)) => format!("config key {} was removed. {}", key.display, hint),
        (None, None) => format!("config key {} was removed", key.display),
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

fn deserialize_duration_secs_from_int_or_string<'de, D>(deserializer: D) -> Result<u64, D::Error>
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

fn parse_duration_secs_str(value: &str) -> Result<u64, String> {
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

fn oidc_config_is_default(config: &OidcConfig) -> bool {
    config == &OidcConfig::default()
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

fn default_ephemeral_node_inactivity_timeout_secs() -> u64 {
    120
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
    "pretty".to_string()
}

fn default_true() -> bool {
    true
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

        assert!(config.oidc.only_start_if_oidc_is_available);
        assert_eq!(config.oidc.scope, ["openid", "profile", "email"]);
        assert!(config.oidc.email_verified_required);
        assert!(!config.oidc.use_expiry_from_token);
        assert!(!config.oidc.pkce.enabled);
        assert_eq!(config.oidc.pkce.method, "S256");
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
    fn configtest_accepts_minimal_upstream_yaml() {
        let source = r#"
noise:
  private_key_path: "private_key.pem"
server_url: "https://derp.no"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();

        config.validate_for_configtest().unwrap();
        let server = config.server.unwrap();
        assert_eq!(server.server_url.as_deref(), Some("https://derp.no"));
        assert_eq!(server.state_dir, PathBuf::from("."));
    }

    #[test]
    fn configtest_rejects_invalid_prefix_allocation_strategy() {
        let source = r#"
server_url: "https://headscale.example"
prefixes:
  v4: "100.64.0.0/10"
  allocation: "hash"
dns:
  magic_dns: false
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
prefixes:
  v4: ""
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let err = config.validate_for_configtest().unwrap_err().to_string();

        assert!(err.contains("at least one of prefixes.v4 or prefixes.v6"));
    }

    #[test]
    fn configtest_rejects_unsupported_postgres_config() {
        let source = r#"
server_url: "https://headscale.example"
database:
  type: postgres
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let err = config.validate_for_configtest().unwrap_err();

        assert!(format!("{err:#}").contains("database.type \"postgres\" is not supported"));
    }

    #[test]
    fn configtest_rejects_upstream_tls_conflicts() {
        let source = r#"
server_url: "https://headscale.example"
tls_letsencrypt_hostname: "headscale.example"
tls_cert_path: "/etc/headscale/cert.pem"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let err = config.validate_for_configtest().unwrap_err();

        assert!(
            format!("{err:#}")
                .contains("set either tls_letsencrypt_hostname or tls_cert_path/tls_key_path")
        );
    }

    #[test]
    fn configtest_rejects_too_low_ephemeral_timeout() {
        let source = r#"
server_url: "https://headscale.example"
ephemeral_node_inactivity_timeout: "65s"
"#;

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();
        let err = config.validate_for_configtest().unwrap_err();

        assert!(format!("{err:#}").contains("ephemeral_node_inactivity_timeout"));
    }

    #[test]
    fn loads_upstream_cli_grpc_toml() {
        let source = r#"
[cli]
address = "headscale.example:50443"
api_key = "hskey-api-abcdefghijkl-secret"
insecure = true
"#;

        let config = CliConfig::parse(source, ConfigFormat::Toml).unwrap();
        let cli = config.cli.unwrap();

        assert_eq!(cli.address.as_deref(), Some("headscale.example:50443"));
        assert_eq!(
            cli.api_key.as_deref(),
            Some("hskey-api-abcdefghijkl-secret")
        );
        assert_eq!(cli.insecure, Some(true));
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
        assert_eq!(dns.nameservers, ["1.1.1.1"]);
        assert_eq!(
            dns.restricted_nameservers.get("corp.example.org").unwrap(),
            &vec!["10.0.0.53".to_string()]
        );
        assert_eq!(dns.extra_records[0].value, "100.64.0.50");
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
        assert!(err.contains("policy file"));
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
