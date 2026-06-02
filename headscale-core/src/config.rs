//! Configuration for headscale-rs core.

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};
use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;

const DEFAULT_OIDC_EXPIRY: Duration = Duration::from_secs(180 * 24 * 60 * 60);
const OIDC_NO_EXPIRY: Duration = Duration::from_nanos(i64::MAX as u64);
const PKCE_METHOD_PLAIN: &str = "plain";
const PKCE_METHOD_S256: &str = "S256";

/// Core configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Listen address for control plane
    pub listen_addr: SocketAddr,
    /// Database path
    pub db_path: PathBuf,
    /// WireGuard interface name
    pub wg_interface: String,
    /// WireGuard listen port
    pub wg_port: u16,
    /// DERP server URL for NAT traversal
    pub derp_url: Option<String>,
    /// Embedded DERP/STUN runtime configuration.
    #[serde(default)]
    pub embedded_derp: EmbeddedDerpConfig,
    /// OpenID Connect authentication configuration
    #[serde(default)]
    pub oidc: OidcConfig,
    /// Enable IPv6
    pub ipv6: bool,
    /// Mesh network CIDR
    pub mesh_cidr: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8080".parse().unwrap(),
            db_path: PathBuf::from("/var/lib/headscale/db.sqlite"),
            wg_interface: "wg0".to_string(),
            wg_port: 51820,
            derp_url: None,
            embedded_derp: EmbeddedDerpConfig::default(),
            oidc: OidcConfig::default(),
            ipv6: true,
            mesh_cidr: "100.64.0.0/10".to_string(),
        }
    }
}

/// Embedded DERP/STUN runtime configuration.
///
/// This mirrors the operator-facing slice that headscale-go exposes for its
/// embedded DERP server, while leaving the actual DERP relay protocol to the
/// upstream `derper` binary. Native Rust owns the STUN responder and the DERP
/// map shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct EmbeddedDerpConfig {
    /// Master switch. Disabled by default so existing deployments keep using
    /// the empty DERP map unless explicitly configured.
    pub enabled: bool,
    /// Public DERP hostname advertised in the DERP map.
    pub host_name: String,
    /// Public DERP HTTPS port. `443` is omitted on the wire.
    pub derp_port: u16,
    /// UDP STUN bind address. `None` disables the embedded STUN listener.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stun_addr: Option<SocketAddr>,
    /// Run a STUN-only DERP-map node without spawning a DERP relay process.
    pub stun_only: bool,
    /// Numeric DERP region ID advertised to clients.
    pub region_id: u16,
    /// Short region code advertised to clients.
    pub region_code: String,
    /// Human-readable region name advertised to clients.
    pub region_name: String,
    /// Whether clients should omit the public Tailscale DERP fleet.
    pub omit_default_regions: bool,
    /// Test-only DERP map escape hatch for self-signed sidecar TLS.
    pub insecure_for_tests: bool,
    /// Optional public IPv4 hint advertised for the embedded DERP node.
    pub ipv4: String,
    /// Optional public IPv6 hint advertised for the embedded DERP node.
    pub ipv6: String,
    /// Path to the upstream `derper` binary. Required unless `stun_only = true`.
    pub derper_binary: PathBuf,
    /// TCP bind address passed to `derper -a`.
    pub derper_listen_addr: SocketAddr,
    /// Path passed to `derper -c`. If empty, the CLI server resolves it under
    /// the server state directory before starting the runtime.
    pub derper_config_path: PathBuf,
    /// Certificate mode passed to `derper -certmode`.
    pub derper_cert_mode: String,
    /// Optional certificate directory passed to `derper -certdir`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derper_cert_dir: Option<PathBuf>,
    /// Optional DERP admission-controller callback URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_client_url: Option<String>,
    /// Ask `derper` to verify clients through a local tailscaled instance.
    pub verify_clients: bool,
}

impl Default for EmbeddedDerpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host_name: String::new(),
            derp_port: 443,
            stun_addr: None,
            stun_only: false,
            region_id: 900,
            region_code: "embedded".to_string(),
            region_name: "Embedded headscale-rs DERP".to_string(),
            omit_default_regions: false,
            insecure_for_tests: false,
            ipv4: String::new(),
            ipv6: String::new(),
            derper_binary: PathBuf::new(),
            derper_listen_addr: "127.0.0.1:8443".parse().unwrap(),
            derper_config_path: PathBuf::new(),
            derper_cert_mode: "letsencrypt".to_string(),
            derper_cert_dir: None,
            verify_client_url: None,
            verify_clients: false,
        }
    }
}

impl EmbeddedDerpConfig {
    /// Disabled config helper for call sites that want an explicit value.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Whether this config should spawn a DERP relay process.
    pub fn relay_enabled(&self) -> bool {
        self.enabled && !self.stun_only
    }

    /// Resolve the `derper -c` config path against the server state directory.
    pub fn with_default_derper_config_path(mut self, state_dir: &std::path::Path) -> Self {
        if self.derper_config_path.as_os_str().is_empty() {
            self.derper_config_path = state_dir.join("derper.key");
        }
        self
    }
}

/// OpenID Connect configuration, matching the headscale-go v0.28 server config
/// keys.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct OidcConfig {
    /// Config-only validation guard used by headscale-go for OIDC-specific
    /// validation. Runtime OIDC enablement is still derived from `issuer`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,
    /// Block startup until the OIDC provider is reachable.
    #[serde(default = "default_true")]
    pub only_start_if_oidc_is_available: bool,
    /// OIDC issuer URL.
    pub issuer: String,
    /// OIDC client ID.
    pub client_id: String,
    /// Resolved OIDC client secret.
    pub client_secret: String,
    /// Optional file containing the OIDC client secret. This is resolved and
    /// cleared by [`OidcConfig::resolve_client_secret`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_path: Option<PathBuf>,
    /// OIDC scopes requested during login.
    #[serde(default = "default_oidc_scope")]
    pub scope: Vec<String>,
    /// Extra authorization-endpoint parameters.
    pub extra_params: BTreeMap<String, String>,
    /// Accepted email domains.
    pub allowed_domains: Vec<String>,
    /// Accepted email addresses.
    pub allowed_users: Vec<String>,
    /// Accepted OIDC groups.
    pub allowed_groups: Vec<String>,
    /// Require `email_verified: true` before synchronizing a profile email.
    #[serde(default = "default_true")]
    pub email_verified_required: bool,
    /// OIDC login lifetime. A configured value of `0` means no expiry.
    #[serde(
        default = "default_oidc_expiry",
        deserialize_with = "deserialize_oidc_expiry",
        serialize_with = "serialize_oidc_expiry"
    )]
    pub expiry: Duration,
    /// Use the token expiry from the identity provider instead of `expiry`.
    pub use_expiry_from_token: bool,
    /// PKCE configuration.
    pub pkce: PkceConfig,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            only_start_if_oidc_is_available: true,
            issuer: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            client_secret_path: None,
            scope: default_oidc_scope(),
            extra_params: BTreeMap::new(),
            allowed_domains: Vec::new(),
            allowed_users: Vec::new(),
            allowed_groups: Vec::new(),
            email_verified_required: true,
            expiry: DEFAULT_OIDC_EXPIRY,
            use_expiry_from_token: false,
            pkce: PkceConfig::default(),
        }
    }
}

impl OidcConfig {
    /// Apply headscale-go style environment overrides.
    ///
    /// Upstream uses Viper with the `headscale` prefix and replaces dots with
    /// underscores, so `oidc.client_id` becomes `HEADSCALE_OIDC_CLIENT_ID`.
    pub fn apply_headscale_env_overrides(&mut self) -> Result<(), ConfigError> {
        self.apply_headscale_env_overrides_from(env::vars())
    }

    /// Apply `HEADSCALE_OIDC_*` overrides from an injected iterator. This keeps
    /// tests deterministic without mutating process-global environment state.
    pub fn apply_headscale_env_overrides_from<I, K, V>(
        &mut self,
        vars: I,
    ) -> Result<(), ConfigError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        for (key, value) in vars {
            let key = key.as_ref();
            let value = value.as_ref();

            match key {
                "HEADSCALE_OIDC_ENABLED" => {
                    self.enabled = parse_bool_env(key, value)?;
                }
                "HEADSCALE_OIDC_ONLY_START_IF_OIDC_IS_AVAILABLE" => {
                    self.only_start_if_oidc_is_available = parse_bool_env(key, value)?;
                }
                "HEADSCALE_OIDC_ISSUER" => self.issuer = value.to_string(),
                "HEADSCALE_OIDC_CLIENT_ID" => self.client_id = value.to_string(),
                "HEADSCALE_OIDC_CLIENT_SECRET" => self.client_secret = value.to_string(),
                "HEADSCALE_OIDC_CLIENT_SECRET_PATH" => {
                    self.client_secret_path = Some(PathBuf::from(value));
                }
                "HEADSCALE_OIDC_SCOPE" => self.scope = parse_string_list_env(key, value)?,
                "HEADSCALE_OIDC_EXTRA_PARAMS" => {
                    self.extra_params = parse_string_map_env(key, value)?;
                }
                "HEADSCALE_OIDC_ALLOWED_DOMAINS" => {
                    self.allowed_domains = parse_string_list_env(key, value)?;
                }
                "HEADSCALE_OIDC_ALLOWED_USERS" => {
                    self.allowed_users = parse_string_list_env(key, value)?;
                }
                "HEADSCALE_OIDC_ALLOWED_GROUPS" => {
                    self.allowed_groups = parse_string_list_env(key, value)?;
                }
                "HEADSCALE_OIDC_EMAIL_VERIFIED_REQUIRED" => {
                    self.email_verified_required = parse_bool_env(key, value)?;
                }
                "HEADSCALE_OIDC_EXPIRY" => {
                    self.expiry = parse_oidc_expiry_or_default(value);
                }
                "HEADSCALE_OIDC_USE_EXPIRY_FROM_TOKEN" => {
                    self.use_expiry_from_token = parse_bool_env(key, value)?;
                }
                "HEADSCALE_OIDC_PKCE_ENABLED" => {
                    self.pkce.enabled = parse_bool_env(key, value)?;
                }
                "HEADSCALE_OIDC_PKCE_METHOD" => self.pkce.method = value.to_string(),
                _ => {}
            }
        }

        self.validate()
    }

    /// Resolve `client_secret_path`, mirroring headscale-go's mutual exclusion
    /// check and whitespace trimming.
    pub fn resolve_client_secret(&mut self) -> Result<(), ConfigError> {
        if self.client_secret_path.is_some() && !self.client_secret.is_empty() {
            return Err(ConfigError::OidcClientSecretConflict);
        }

        if let Some(path) = self.client_secret_path.take() {
            let raw_path = path.to_string_lossy();
            let expanded_path = expand_env_vars(&raw_path);
            let secret =
                fs::read(&expanded_path).map_err(|source| ConfigError::ReadOidcClientSecret {
                    path: expanded_path.clone(),
                    source,
                })?;
            self.client_secret = String::from_utf8_lossy(&secret).trim().to_string();
        }

        self.validate()
    }

    /// Validate the OIDC config values that headscale-go validates at config
    /// load time.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.enabled {
            validate_pkce_method(&self.pkce.method)?;
        }

        Ok(())
    }
}

/// PKCE configuration for OIDC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PkceConfig {
    /// Enable PKCE for the authorization-code flow.
    pub enabled: bool,
    /// PKCE method. headscale-go v0.28 accepts `plain` and `S256`.
    #[serde(default = "default_pkce_method")]
    pub method: String,
}

impl Default for PkceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            method: default_pkce_method(),
        }
    }
}

/// Configuration load errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// `oidc.client_secret` and `oidc.client_secret_path` cannot both be set.
    #[error("oidc_client_secret and oidc_client_secret_path are mutually exclusive")]
    OidcClientSecretConflict,
    /// Failed to read the configured OIDC client secret file.
    #[error("failed to read oidc.client_secret_path {path}: {source}")]
    ReadOidcClientSecret {
        /// Expanded secret path.
        path: String,
        /// I/O source error.
        #[source]
        source: std::io::Error,
    },
    /// Invalid PKCE method.
    #[error("pkce.method must be either 'plain' or 'S256'")]
    InvalidPkceMethod,
    /// Invalid boolean environment override.
    #[error("failed to parse {key}={value:?} as a boolean")]
    InvalidBool {
        /// Environment key.
        key: String,
        /// Environment value.
        value: String,
    },
    /// Invalid string-list environment override.
    #[error("failed to parse {key}={value:?} as a string list: {reason}")]
    InvalidStringList {
        /// Environment key.
        key: String,
        /// Environment value.
        value: String,
        /// Parse failure details.
        reason: String,
    },
    /// Invalid string-map environment override.
    #[error("failed to parse {key}={value:?} as a string map: {reason}")]
    InvalidStringMap {
        /// Environment key.
        key: String,
        /// Environment value.
        value: String,
        /// Parse failure details.
        reason: String,
    },
}

fn default_true() -> bool {
    true
}

fn default_oidc_scope() -> Vec<String> {
    vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
    ]
}

fn default_oidc_expiry() -> Duration {
    DEFAULT_OIDC_EXPIRY
}

fn default_pkce_method() -> String {
    PKCE_METHOD_S256.to_string()
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn validate_pkce_method(method: &str) -> Result<(), ConfigError> {
    if method == PKCE_METHOD_PLAIN || method == PKCE_METHOD_S256 {
        Ok(())
    } else {
        Err(ConfigError::InvalidPkceMethod)
    }
}

fn parse_bool_env(key: &str, value: &str) -> Result<bool, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "t" | "true" | "yes" | "y" | "on" => Ok(true),
        "0" | "f" | "false" | "no" | "n" | "off" => Ok(false),
        _ => Err(ConfigError::InvalidBool {
            key: key.to_string(),
            value: value.to_string(),
        }),
    }
}

fn parse_string_list_env(key: &str, value: &str) -> Result<Vec<String>, ConfigError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(Vec::new());
    }

    if value.starts_with('[') {
        return serde_json::from_str(value).map_err(|err| ConfigError::InvalidStringList {
            key: key.to_string(),
            value: value.to_string(),
            reason: err.to_string(),
        });
    }

    Ok(value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

fn parse_string_map_env(key: &str, value: &str) -> Result<BTreeMap<String, String>, ConfigError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(BTreeMap::new());
    }

    if value.starts_with('{') {
        return serde_json::from_str(value).map_err(|err| ConfigError::InvalidStringMap {
            key: key.to_string(),
            value: value.to_string(),
            reason: err.to_string(),
        });
    }

    let mut map = BTreeMap::new();
    for entry in value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let Some((entry_key, entry_value)) = entry.split_once('=') else {
            return Err(ConfigError::InvalidStringMap {
                key: key.to_string(),
                value: value.to_string(),
                reason: format!("missing '=' in {entry:?}"),
            });
        };
        map.insert(entry_key.trim().to_string(), entry_value.trim().to_string());
    }

    Ok(map)
}

fn parse_oidc_expiry(value: &str) -> Result<Duration, ()> {
    let value = value.trim();
    if value == "0" {
        return Ok(OIDC_NO_EXPIRY);
    }

    let mut rest = value;
    let mut total_nanos = 0_u128;
    while !rest.is_empty() {
        let number_len = rest
            .char_indices()
            .take_while(|(_, ch)| ch.is_ascii_digit())
            .map(|(idx, ch)| idx + ch.len_utf8())
            .last()
            .ok_or(())?;
        let number = rest[..number_len].parse::<u128>().map_err(|_| ())?;
        rest = &rest[number_len..];

        let (unit_nanos, next_rest) = duration_unit(rest).ok_or(())?;
        total_nanos = total_nanos
            .checked_add(number.checked_mul(unit_nanos).ok_or(())?)
            .ok_or(())?;
        rest = next_rest;
    }

    let nanos = u64::try_from(total_nanos).map_err(|_| ())?;
    Ok(Duration::from_nanos(nanos))
}

fn parse_oidc_expiry_or_default(value: &str) -> Duration {
    parse_oidc_expiry(value).unwrap_or_else(|()| {
        tracing::warn!("failed to parse oidc.expiry, defaulting back to 180 days");
        DEFAULT_OIDC_EXPIRY
    })
}

fn duration_unit(value: &str) -> Option<(u128, &str)> {
    const NANOS_PER_MICROSECOND: u128 = 1_000;
    const NANOS_PER_MILLISECOND: u128 = 1_000_000;
    const NANOS_PER_SECOND: u128 = 1_000_000_000;
    const NANOS_PER_MINUTE: u128 = 60 * NANOS_PER_SECOND;
    const NANOS_PER_HOUR: u128 = 60 * NANOS_PER_MINUTE;
    const NANOS_PER_DAY: u128 = 24 * NANOS_PER_HOUR;
    const NANOS_PER_WEEK: u128 = 7 * NANOS_PER_DAY;
    const NANOS_PER_YEAR: u128 = 365 * NANOS_PER_DAY;

    for (suffix, nanos) in [
        ("ms", NANOS_PER_MILLISECOND),
        ("us", NANOS_PER_MICROSECOND),
        ("µs", NANOS_PER_MICROSECOND),
        ("ns", 1),
        ("s", NANOS_PER_SECOND),
        ("m", NANOS_PER_MINUTE),
        ("h", NANOS_PER_HOUR),
        ("d", NANOS_PER_DAY),
        ("w", NANOS_PER_WEEK),
        ("y", NANOS_PER_YEAR),
    ] {
        if let Some(rest) = value.strip_prefix(suffix) {
            return Some((nanos, rest));
        }
    }

    None
}

fn serialize_oidc_expiry<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format_oidc_expiry(*duration))
}

fn deserialize_oidc_expiry<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(OidcExpiryVisitor)
}

struct OidcExpiryVisitor;

impl Visitor<'_> for OidcExpiryVisitor {
    type Value = Duration;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Prometheus-style duration string, or 0 for no expiry")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(parse_oidc_expiry_or_default(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value == 0 {
            Ok(OIDC_NO_EXPIRY)
        } else {
            Ok(Duration::from_secs(value))
        }
    }
}

fn format_oidc_expiry(duration: Duration) -> String {
    if duration == OIDC_NO_EXPIRY {
        return "0".to_string();
    }

    let seconds = duration.as_secs();
    if duration.subsec_nanos() == 0 {
        if seconds.is_multiple_of(24 * 60 * 60) {
            return format!("{}d", seconds / (24 * 60 * 60));
        }
        if seconds.is_multiple_of(60 * 60) {
            return format!("{}h", seconds / (60 * 60));
        }
        if seconds.is_multiple_of(60) {
            return format!("{}m", seconds / 60);
        }
        return format!("{seconds}s");
    }

    format!("{}ns", duration.as_nanos())
}

fn expand_env_vars(value: &str) -> String {
    expand_env_vars_with(value, |name| env::var(name).ok())
}

fn expand_env_vars_with<F>(value: &str, mut get_env: F) -> String
where
    F: FnMut(&str) -> Option<String>,
{
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '$' {
            output.push(ch);
            continue;
        }

        if matches!(chars.peek(), Some('{')) {
            chars.next();
            let mut name = String::new();
            for next in chars.by_ref() {
                if next == '}' {
                    break;
                }
                name.push(next);
            }
            if let Some(replacement) = get_env(&name) {
                output.push_str(&replacement);
            }
            continue;
        }

        let mut name = String::new();
        while let Some(next) = chars.peek().copied() {
            if next == '_' || next.is_ascii_alphanumeric() {
                chars.next();
                name.push(next);
            } else {
                break;
            }
        }

        if name.is_empty() {
            output.push('$');
        } else if let Some(replacement) = get_env(&name) {
            output.push_str(&replacement);
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidc_defaults_match_headscale_go_v028() {
        let oidc = OidcConfig::default();

        assert!(!oidc.enabled);
        assert!(oidc.only_start_if_oidc_is_available);
        assert_eq!(oidc.scope, ["openid", "profile", "email"]);
        assert!(oidc.email_verified_required);
        assert_eq!(oidc.expiry, DEFAULT_OIDC_EXPIRY);
        assert!(!oidc.use_expiry_from_token);
        assert!(!oidc.pkce.enabled);
        assert_eq!(oidc.pkce.method, PKCE_METHOD_S256);
    }

    #[test]
    fn embedded_derp_defaults_are_disabled_and_non_destructive() {
        let cfg = EmbeddedDerpConfig::default();

        assert!(!cfg.enabled);
        assert!(!cfg.relay_enabled());
        assert_eq!(cfg.derp_port, 443);
        assert_eq!(cfg.region_id, 900);
        assert!(cfg.derper_binary.as_os_str().is_empty());
        assert!(cfg.derper_config_path.as_os_str().is_empty());
    }

    #[test]
    fn oidc_env_overrides_follow_headscale_prefix() {
        let mut oidc = OidcConfig::default();

        oidc.apply_headscale_env_overrides_from([
            ("HEADSCALE_OIDC_ENABLED", "true"),
            ("HEADSCALE_OIDC_ISSUER", "https://issuer.example"),
            ("HEADSCALE_OIDC_CLIENT_ID", "client-id"),
            ("HEADSCALE_OIDC_SCOPE", "openid,profile,email,groups"),
            ("HEADSCALE_OIDC_ALLOWED_DOMAINS", "example.com,example.org"),
            ("HEADSCALE_OIDC_ALLOWED_USERS", "alice@example.com"),
            ("HEADSCALE_OIDC_ALLOWED_GROUPS", r#"["/headscale","/ops"]"#),
            (
                "HEADSCALE_OIDC_EXTRA_PARAMS",
                "domain_hint=example.com,prompt=login",
            ),
            ("HEADSCALE_OIDC_EMAIL_VERIFIED_REQUIRED", "false"),
            ("HEADSCALE_OIDC_EXPIRY", "90d"),
            ("HEADSCALE_OIDC_USE_EXPIRY_FROM_TOKEN", "true"),
            ("HEADSCALE_OIDC_PKCE_ENABLED", "true"),
            ("HEADSCALE_OIDC_PKCE_METHOD", "plain"),
        ])
        .unwrap();

        assert!(oidc.enabled);
        assert_eq!(oidc.issuer, "https://issuer.example");
        assert_eq!(oidc.client_id, "client-id");
        assert_eq!(oidc.scope, ["openid", "profile", "email", "groups"]);
        assert_eq!(oidc.allowed_domains, ["example.com", "example.org"]);
        assert_eq!(oidc.allowed_users, ["alice@example.com"]);
        assert_eq!(oidc.allowed_groups, ["/headscale", "/ops"]);
        assert_eq!(
            oidc.extra_params.get("domain_hint").map(String::as_str),
            Some("example.com")
        );
        assert!(!oidc.email_verified_required);
        assert_eq!(oidc.expiry, Duration::from_secs(90 * 24 * 60 * 60));
        assert!(oidc.use_expiry_from_token);
        assert!(oidc.pkce.enabled);
        assert_eq!(oidc.pkce.method, PKCE_METHOD_PLAIN);
    }

    #[test]
    fn oidc_expiry_zero_means_no_expiry() {
        assert_eq!(parse_oidc_expiry("0").unwrap(), OIDC_NO_EXPIRY);
    }

    #[test]
    fn oidc_invalid_expiry_defaults_like_headscale_go() {
        assert_eq!(
            parse_oidc_expiry_or_default("not-a-duration"),
            DEFAULT_OIDC_EXPIRY
        );

        let mut oidc = OidcConfig::default();
        oidc.apply_headscale_env_overrides_from([("HEADSCALE_OIDC_EXPIRY", "not-a-duration")])
            .unwrap();
        assert_eq!(oidc.expiry, DEFAULT_OIDC_EXPIRY);
    }

    #[test]
    fn oidc_client_secret_path_expands_environment_style_variables() {
        let expanded =
            expand_env_vars_with("${CREDENTIALS_DIRECTORY}/oidc_client_secret", |name| {
                (name == "CREDENTIALS_DIRECTORY").then(|| "/run/creds".to_string())
            });

        assert_eq!(expanded, "/run/creds/oidc_client_secret");
    }

    #[test]
    fn oidc_accepts_invalid_pkce_method_when_disabled() {
        let oidc = OidcConfig {
            pkce: PkceConfig {
                method: "S384".to_string(),
                ..PkceConfig::default()
            },
            ..OidcConfig::default()
        };

        oidc.validate().unwrap();
    }

    #[test]
    fn oidc_rejects_invalid_pkce_method_when_enabled() {
        let oidc = OidcConfig {
            enabled: true,
            pkce: PkceConfig {
                method: "S384".to_string(),
                ..PkceConfig::default()
            },
            ..OidcConfig::default()
        };

        assert!(matches!(
            oidc.validate(),
            Err(ConfigError::InvalidPkceMethod)
        ));
    }
}
