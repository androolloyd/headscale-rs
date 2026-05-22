//! Configuration file handling for the CLI.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use headscale_api::dns::DnsConfigSpec;
use headscale_core::config::{EmbeddedDerpConfig, OidcConfig};
use serde::{Deserialize, Serialize};

const DEFAULT_CONFIG_FILENAMES: &[&str] =
    &["config.yaml", "config.yml", "config.json", "config.toml"];

/// Top-level CLI configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct CliConfig {
    /// Server mode configuration
    pub server: Option<ServerConfig>,
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
    #[serde(default = "default_unix_socket_permission")]
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

impl CliConfig {
    /// Load configuration from a file.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let mut config = Self::parse(&contents, ConfigFormat::from_path(path))?;
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
        config.apply_oidc_env_overrides_from(std::env::vars())?;
        config.resolve_oidc_client_secret()?;
        Ok(config)
    }

    fn parse(contents: &str, format: ConfigFormat) -> Result<Self> {
        match format {
            ConfigFormat::Toml => toml::from_str(contents).context("failed to parse TOML config"),
            ConfigFormat::Yaml => {
                serde_yaml::from_str(contents).context("failed to parse YAML config")
            }
            ConfigFormat::Json => {
                serde_json::from_str(contents).context("failed to parse JSON config")
            }
        }
    }

    fn apply_oidc_env_overrides_from<I, K, V>(&mut self, vars: I) -> Result<()>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        self.oidc
            .apply_headscale_env_overrides_from(vars)
            .context("failed to apply OIDC environment overrides")
    }

    fn resolve_oidc_client_secret(&mut self) -> Result<()> {
        self.oidc
            .resolve_client_secret()
            .context("failed to resolve OIDC client secret")
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

fn default_mesh_cidr() -> String {
    "100.64.0.0/10".to_string()
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
    use std::time::Duration;

    use super::*;

    #[test]
    fn cli_config_includes_upstream_oidc_defaults() {
        let config = CliConfig::default();

        assert!(config.oidc.only_start_if_oidc_is_available);
        assert_eq!(config.oidc.scope, ["openid", "profile", "email"]);
        assert!(config.oidc.email_verified_required);
        assert_eq!(config.oidc.expiry, Duration::from_secs(180 * 24 * 60 * 60));
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
expiry = "0"
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
  expiry: 14d
  allowed_domains:
    - example.com
";

        let config = CliConfig::parse(source, ConfigFormat::Yaml).unwrap();

        assert_eq!(config.oidc.issuer, "https://issuer.example");
        assert_eq!(config.oidc.client_id, "yaml-client");
        assert_eq!(config.oidc.expiry, Duration::from_secs(14 * 24 * 60 * 60));
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
                ("HEADSCALE_OIDC_EXPIRY", "7d"),
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
        assert_eq!(config.oidc.expiry, Duration::from_secs(7 * 24 * 60 * 60));
        assert!(config.oidc.pkce.enabled);
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
