//! Self-signed TLS termination for the Tailscale wire surface.
//!
//! Stock `tailscale up` v1.78+ forces a parallel HTTPS-on-443 dial
//! ("`controlhttp: forcing port 443 dial due to recent noise dial`")
//! and refuses to fall back to plain HTTP even when the login-server URL
//! is `http://`. To clear that wall on the docker-bridge interop
//! harness we mint a self-signed cert at startup, cache it under
//! `<state_dir>/tls.{crt,key}` so restarts don't churn the trust
//! anchor, and present it on `:443`.
//!
//! The cert is **only** suitable for the interop harness — peers trust
//! it by copying the PEM into their `update-ca-certificates` store.
//! Production deployments are expected to feed a real
//! `rustls::ServerConfig` from outside.
//!
//! ## Decision log
//!
//! - **rcgen** is the de facto Rust cert-minting crate; pulling it in
//!   here is the single new dep (per the task brief). We use it only
//!   at startup — no per-request cost.
//! - **Cached under `<state_dir>/tls.{crt,key}`** so a restart of the
//!   mesh-control container doesn't invalidate the peer containers'
//!   trust store. Idempotent: subsequent loads parse the cached PEM
//!   instead of regenerating.
//! - **`CN=headscale.local`, SAN includes the configured hostname +
//!   `localhost` + loopback IPs.** Matches the SAN list the docker
//!   harness needs to satisfy `tailscale up`'s SNI-on-443 verification.

use std::{
    collections::HashMap,
    fs,
    io::{ErrorKind, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use chrono::{DateTime, Utc};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use sha2::{Digest, Sha256};

use super::WireError;

/// Filename for the persisted cert (PEM).
pub const TLS_CERT_FILENAME: &str = "tls.crt";
/// Filename for the persisted private key (PEM).
pub const TLS_KEY_FILENAME: &str = "tls.key";
/// ALPN protocol required by ACME TLS-ALPN-01 challenge handshakes.
pub const ACME_TLS_ALPN_PROTOCOL: &[u8] = b"acme-tls/1";

/// Materialized TLS material — the PEM-encoded cert + key (so callers
/// can copy them into a peer's trust store) plus a ready-to-bind
/// [`rustls::ServerConfig`].
#[derive(Clone)]
pub struct TlsMaterial {
    /// PEM-encoded certificate. Safe to publish — it's the cert
    /// peers need to trust.
    pub cert_pem: String,
    /// PEM-encoded private key. **Secret** — never log, never expose
    /// over the wire.
    pub key_pem: String,
    /// Cert path on disk (under `state_dir`).
    pub cert_path: PathBuf,
    /// Key path on disk (under `state_dir`).
    pub key_path: PathBuf,
    /// Ready-to-use rustls config for the raw-tls listener in
    /// `raw_tls::serve_raw_tls`.
    pub server_config: Arc<ServerConfig>,
    /// Dynamic resolver used when ACME TLS-ALPN-01 challenge certs can be
    /// presented on the same public TLS listener as normal control traffic.
    pub acme_tls_alpn_resolver: Option<Arc<AcmeTlsAlpnChallengeResolver>>,
    /// Expiry of the first certificate in `cert_pem`, which is the served
    /// leaf certificate.
    pub expires_at: DateTime<Utc>,
}

/// Thread-safe holder for TLS server configuration that can be swapped after
/// ACME renewal without dropping the listener.
#[derive(Clone)]
pub struct ReloadableServerConfig {
    current: Arc<RwLock<Arc<ServerConfig>>>,
}

impl ReloadableServerConfig {
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self {
            current: Arc::new(RwLock::new(config)),
        }
    }

    pub fn current(&self) -> Arc<ServerConfig> {
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn replace(&self, config: Arc<ServerConfig>) {
        *self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = config;
    }
}

/// Dynamic rustls certificate resolver for ACME TLS-ALPN-01.
///
/// Normal control-plane handshakes receive the default certificate. ACME
/// validation handshakes receive a challenge certificate only when both the SNI
/// hostname matches an installed challenge and the client offers `acme-tls/1`.
#[derive(Debug)]
pub struct AcmeTlsAlpnChallengeResolver {
    default_cert: RwLock<Arc<CertifiedKey>>,
    challenges: RwLock<HashMap<String, Arc<CertifiedKey>>>,
}

impl AcmeTlsAlpnChallengeResolver {
    pub fn new(default_cert: Arc<CertifiedKey>) -> Arc<Self> {
        Arc::new(Self {
            default_cert: RwLock::new(default_cert),
            challenges: RwLock::new(HashMap::new()),
        })
    }

    pub fn replace_default_certificate(
        &self,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<(), WireError> {
        let cert = Arc::new(certified_key_from_pem(cert_pem, key_pem)?);
        *self
            .default_cert
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = cert;
        Ok(())
    }

    pub fn set_challenge_certificate(
        &self,
        hostname: impl Into<String>,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<(), WireError> {
        let cert = Arc::new(certified_key_from_pem_without_webpki_checks(
            cert_pem, key_pem,
        )?);
        self.challenges
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(hostname.into(), cert);
        Ok(())
    }

    pub fn clear_challenge_certificate(&self, hostname: &str) {
        self.challenges
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(hostname);
    }

    pub fn has_challenge_certificate(&self, hostname: &str) -> bool {
        self.challenges
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(hostname)
    }
}

impl ResolvesServerCert for AcmeTlsAlpnChallengeResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if client_offers_acme_tls_alpn(&client_hello) {
            let hostname = client_hello.server_name()?;
            return self
                .challenges
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(hostname)
                .cloned();
        }
        Some(
            self.default_cert
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        )
    }
}

/// Source for public-control TLS material.
#[derive(Clone, Debug)]
pub enum TlsMaterialSource {
    /// Interop harness mode: persist a generated self-signed pair under
    /// `state_dir`.
    SelfSigned { state_dir: PathBuf, sans: SanConfig },
    /// Upstream manual TLS mode: load operator-provided PEM files from
    /// `tls_cert_path` and `tls_key_path`.
    Files {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
    /// ACME/autocert cache mode: load a Go-compatible autocert DirCache entry
    /// named after the configured Let's Encrypt hostname. The cache file stores
    /// the private key followed by the certificate chain.
    AcmeAutocertCache {
        cache_dir: PathBuf,
        hostname: String,
    },
    /// ACME/autocert cache mode with a dynamic TLS-ALPN-01 challenge
    /// certificate resolver on the public TLS config.
    AcmeAutocertCacheWithTlsAlpn {
        cache_dir: PathBuf,
        hostname: String,
    },
}

impl TlsMaterialSource {
    pub fn load(&self) -> Result<TlsMaterial, WireError> {
        match self {
            Self::SelfSigned { state_dir, sans } => load_or_generate(state_dir, sans),
            Self::Files {
                cert_path,
                key_path,
            } => load_from_files(cert_path, key_path),
            Self::AcmeAutocertCache {
                cache_dir,
                hostname,
            } => load_from_autocert_cache(cache_dir, hostname),
            Self::AcmeAutocertCacheWithTlsAlpn {
                cache_dir,
                hostname,
            } => load_from_autocert_cache_with_tls_alpn_or_bootstrap(cache_dir, hostname),
        }
    }
}

/// Subject Alternative Name set for the minted cert.
///
/// All entries are accepted by `tailscale up`'s SNI verification: the
/// client connects to whatever hostname the login-server URL resolves
/// to, so the cert's SAN list must include both the docker-service
/// DNS name (`tsi-mesh-control`) and the loopback fallbacks for
/// host-side curl probes.
#[derive(Clone, Debug)]
pub struct SanConfig {
    /// Primary hostname (typically the docker service name, e.g.
    /// `tsi-mesh-control`).
    pub primary: String,
    /// Extra DNS SANs beyond `primary`. Always includes `localhost`
    /// by default.
    pub extra_dns: Vec<String>,
    /// IP SANs. Defaults to `127.0.0.1` + `::1`.
    pub extra_ips: Vec<String>,
}

impl SanConfig {
    /// Build a SAN config for the given hostname; populates loopback +
    /// `localhost` defaults.
    pub fn with_hostname(hostname: impl Into<String>) -> Self {
        Self {
            primary: hostname.into(),
            extra_dns: vec!["localhost".into()],
            extra_ips: vec!["127.0.0.1".into(), "::1".into()],
        }
    }

    fn all_dns(&self) -> Vec<String> {
        let mut v = Vec::with_capacity(1 + self.extra_dns.len());
        v.push(self.primary.clone());
        for d in &self.extra_dns {
            if d != &self.primary {
                v.push(d.clone());
            }
        }
        v
    }
}

/// Load TLS material from `<state_dir>/tls.{crt,key}`, generating +
/// persisting a fresh self-signed pair if either file is absent.
///
/// `state_dir` is created if it doesn't exist. The cert is minted with
/// `CN=headscale.local` and SANs drawn from `sans`.
pub fn load_or_generate(
    state_dir: impl AsRef<Path>,
    sans: &SanConfig,
) -> Result<TlsMaterial, WireError> {
    let dir: PathBuf = state_dir.as_ref().into();
    fs::create_dir_all(&dir)?;
    let cert_path = dir.join(TLS_CERT_FILENAME);
    let key_path = dir.join(TLS_KEY_FILENAME);

    let (cert_pem, key_pem) = match (read_pem(&cert_path), read_pem(&key_path)) {
        (Ok(c), Ok(k)) => (c, k),
        _ => mint_and_persist(&cert_path, &key_path, sans)?,
    };

    let expires_at = leaf_certificate_not_after(&cert_pem)?;
    let server_config = build_server_config(&cert_pem, &key_pem)?;
    Ok(TlsMaterial {
        cert_pem,
        key_pem,
        cert_path,
        key_path,
        server_config: Arc::new(server_config),
        acme_tls_alpn_resolver: None,
        expires_at,
    })
}

/// Load manual PEM material from configured files.
pub fn load_from_files(
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
) -> Result<TlsMaterial, WireError> {
    let cert_path = cert_path.as_ref().to_path_buf();
    let key_path = key_path.as_ref().to_path_buf();
    let cert_pem = read_pem(&cert_path)?;
    let key_pem = read_pem(&key_path)?;
    let expires_at = leaf_certificate_not_after(&cert_pem)?;
    let server_config = build_server_config(&cert_pem, &key_pem)?;
    Ok(TlsMaterial {
        cert_pem,
        key_pem,
        cert_path,
        key_path,
        server_config: Arc::new(server_config),
        acme_tls_alpn_resolver: None,
        expires_at,
    })
}

/// Load a Go `autocert.DirCache` certificate entry for `hostname`.
///
/// Go stores the default ECDSA certificate at `<cache_dir>/<hostname>` as a
/// single PEM blob containing the private key first and then the certificate
/// chain. This loader lets headscale-rs serve an already-provisioned upstream
/// cache while full online issuance/renewal is implemented in the server
/// runtime.
pub fn load_from_autocert_cache(
    cache_dir: impl AsRef<Path>,
    hostname: &str,
) -> Result<TlsMaterial, WireError> {
    load_from_autocert_cache_inner(cache_dir, hostname, false)
}

/// Load a Go `autocert.DirCache` entry and enable TLS-ALPN-01 challenge
/// certificate resolution on the returned rustls config.
pub fn load_from_autocert_cache_with_tls_alpn(
    cache_dir: impl AsRef<Path>,
    hostname: &str,
) -> Result<TlsMaterial, WireError> {
    load_from_autocert_cache_inner(cache_dir, hostname, true)
}

/// Load an ACME cache entry for TLS-ALPN mode, or bootstrap with an in-memory
/// self-signed cert so the public TLS listener can come up and answer the ACME
/// validation handshake that produces the real cache entry.
pub fn load_from_autocert_cache_with_tls_alpn_or_bootstrap(
    cache_dir: impl AsRef<Path>,
    hostname: &str,
) -> Result<TlsMaterial, WireError> {
    let cache_dir = cache_dir.as_ref().to_path_buf();
    match load_from_autocert_cache_with_tls_alpn(&cache_dir, hostname) {
        Ok(material) => Ok(material),
        Err(err) => {
            tracing::info!(
                hostname = %hostname,
                cache_dir = %cache_dir.display(),
                error = %err,
                "ACME TLS-ALPN cache entry missing or invalid; bootstrapping listener with temporary self-signed material"
            );
            bootstrap_tls_alpn_material(&cache_dir, hostname)
        }
    }
}

fn load_from_autocert_cache_inner(
    cache_dir: impl AsRef<Path>,
    hostname: &str,
    enable_tls_alpn: bool,
) -> Result<TlsMaterial, WireError> {
    let cache_dir = cache_dir.as_ref().to_path_buf();
    let cache_path = autocert_cache_path(&cache_dir, hostname);
    let combined_pem = read_pem(&cache_path).map_err(|err| {
        WireError::Internal(format!(
            "load ACME cache entry {} for hostname {hostname}: {err}",
            cache_path.display()
        ))
    })?;
    let (key_pem, cert_pem) = split_autocert_pem(&combined_pem).map_err(|err| {
        WireError::Internal(format!(
            "parse ACME cache entry {} for hostname {hostname}: {err}",
            cache_path.display()
        ))
    })?;
    let expires_at = leaf_certificate_not_after(&cert_pem)?;
    let (server_config, acme_tls_alpn_resolver) = if enable_tls_alpn {
        let (server_config, resolver) =
            build_server_config_with_acme_tls_alpn_resolver(&cert_pem, &key_pem)?;
        (server_config, Some(resolver))
    } else {
        (build_server_config(&cert_pem, &key_pem)?, None)
    };
    Ok(TlsMaterial {
        cert_pem,
        key_pem,
        cert_path: cache_path.clone(),
        key_path: cache_path,
        server_config: Arc::new(server_config),
        acme_tls_alpn_resolver,
        expires_at,
    })
}

fn bootstrap_tls_alpn_material(cache_dir: &Path, hostname: &str) -> Result<TlsMaterial, WireError> {
    let cache_path = autocert_cache_path(cache_dir, hostname);
    let sans = SanConfig::with_hostname(hostname);
    let (cert_pem, key_pem) = mint_self_signed(&sans)?;
    let expires_at = leaf_certificate_not_after(&cert_pem)?;
    let (server_config, resolver) =
        build_server_config_with_acme_tls_alpn_resolver(&cert_pem, &key_pem)?;
    Ok(TlsMaterial {
        cert_pem,
        key_pem,
        cert_path: cache_path.clone(),
        key_path: cache_path,
        server_config: Arc::new(server_config),
        acme_tls_alpn_resolver: Some(resolver),
        expires_at,
    })
}

/// Parse the `notAfter` timestamp from the first certificate PEM block.
pub fn leaf_certificate_not_after(cert_pem: &str) -> Result<DateTime<Utc>, WireError> {
    let leaf = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .next()
        .ok_or_else(|| WireError::Internal("no certificates in cert pem".into()))?
        .map_err(|e| WireError::Internal(format!("parse leaf certificate pem: {e}")))?;
    let (_remaining, cert) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|e| WireError::Internal(format!("parse leaf certificate x509: {e}")))?;
    let timestamp = cert.validity().not_after.timestamp();
    DateTime::from_timestamp(timestamp, 0).ok_or_else(|| {
        WireError::Internal(format!(
            "leaf certificate notAfter is out of range: {timestamp}"
        ))
    })
}

fn autocert_cache_path(cache_dir: &Path, hostname: &str) -> PathBuf {
    let clean = hostname
        .trim()
        .trim_start_matches('/')
        .split('/')
        .filter(|part| !part.is_empty() && *part != "." && *part != "..")
        .collect::<Vec<_>>()
        .join("/");
    cache_dir.join(clean)
}

fn split_autocert_pem(combined: &str) -> Result<(String, String), &'static str> {
    let mut rest = combined;
    let mut key_pem = String::new();
    let mut cert_pem = String::new();
    while let Some(begin) = rest.find("-----BEGIN ") {
        rest = &rest[begin..];
        let Some(label_end) = rest["-----BEGIN ".len()..].find("-----") else {
            return Err("malformed PEM begin marker");
        };
        let label = &rest["-----BEGIN ".len().."-----BEGIN ".len() + label_end];
        let end_marker = format!("-----END {label}-----");
        let Some(end) = rest.find(&end_marker) else {
            return Err("missing PEM end marker");
        };
        let block_end = end + end_marker.len();
        let mut block = rest[..block_end].to_string();
        block.push('\n');
        if label.contains("PRIVATE KEY") {
            key_pem.push_str(&block);
        } else if label == "CERTIFICATE" {
            cert_pem.push_str(&block);
        }
        rest = &rest[block_end..];
    }

    if key_pem.is_empty() {
        return Err("missing private key PEM block");
    }
    if cert_pem.is_empty() {
        return Err("missing certificate PEM block");
    }
    Ok((key_pem, cert_pem))
}

fn read_pem(p: &Path) -> Result<String, std::io::Error> {
    let mut f = fs::File::open(p)?;
    let mut s = String::new();
    f.read_to_string(&mut s)?;
    if s.is_empty() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "empty pem file",
        ));
    }
    Ok(s)
}

fn mint_and_persist(
    cert_path: &Path,
    key_path: &Path,
    sans: &SanConfig,
) -> Result<(String, String), WireError> {
    let (cert_pem, key_pem) = mint_self_signed(sans)?;

    // Atomic-ish writes — tmp + rename. Avoids partial files mid-crash.
    write_atomic(cert_path, cert_pem.as_bytes(), 0o644)?;
    write_atomic(key_path, key_pem.as_bytes(), 0o600)?;

    Ok((cert_pem, key_pem))
}

fn mint_self_signed(sans: &SanConfig) -> Result<(String, String), WireError> {
    let mut params = rcgen::CertificateParams::new(sans.all_dns())
        .map_err(|e| WireError::Internal(format!("rcgen params: {e}")))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "headscale.local");
    for ip in &sans.extra_ips {
        let parsed: std::net::IpAddr = ip
            .parse()
            .map_err(|e| WireError::Internal(format!("invalid ip SAN {ip}: {e}")))?;
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(parsed));
    }
    let key = rcgen::KeyPair::generate()
        .map_err(|e| WireError::Internal(format!("rcgen keypair: {e}")))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| WireError::Internal(format!("rcgen self_signed: {e}")))?;
    Ok((cert.pem(), key.serialize_pem()))
}

fn write_atomic(p: &Path, bytes: &[u8], mode: u32) -> Result<(), WireError> {
    let tmp = p.with_extension(format!(
        "{}.tmp",
        p.extension().and_then(|e| e.to_str()).unwrap_or("pem")
    ));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(&tmp)?.permissions();
        perm.set_mode(mode);
        fs::set_permissions(&tmp, perm)?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    fs::rename(&tmp, p)?;
    Ok(())
}

pub fn build_grpc_server_config(cert_pem: &str, key_pem: &str) -> Result<ServerConfig, WireError> {
    build_server_config_with_alpn(cert_pem, key_pem, vec![b"h2".to_vec()])
}

/// Build a TLS config for an ACME TLS-ALPN-01 challenge certificate.
///
/// This does not issue or select challenge certificates by SNI; it is the
/// rustls capability ACME issuance will need once certificate provisioning is
/// wired in.
pub fn build_acme_tls_alpn_server_config(
    cert_pem: &str,
    key_pem: &str,
) -> Result<ServerConfig, WireError> {
    build_server_config_with_alpn(cert_pem, key_pem, vec![ACME_TLS_ALPN_PROTOCOL.to_vec()])
}

pub fn build_server_config_with_acme_tls_alpn_resolver(
    cert_pem: &str,
    key_pem: &str,
) -> Result<(ServerConfig, Arc<AcmeTlsAlpnChallengeResolver>), WireError> {
    let default_cert = Arc::new(certified_key_from_pem(cert_pem, key_pem)?);
    let resolver = AcmeTlsAlpnChallengeResolver::new(default_cert);
    build_server_config_with_existing_acme_tls_alpn_resolver(cert_pem, key_pem, resolver)
}

pub fn build_server_config_with_existing_acme_tls_alpn_resolver(
    cert_pem: &str,
    key_pem: &str,
    resolver: Arc<AcmeTlsAlpnChallengeResolver>,
) -> Result<(ServerConfig, Arc<AcmeTlsAlpnChallengeResolver>), WireError> {
    resolver.replace_default_certificate(cert_pem, key_pem)?;
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver.clone());
    cfg.alpn_protocols = vec![b"http/1.1".to_vec(), ACME_TLS_ALPN_PROTOCOL.to_vec()];
    Ok((cfg, resolver))
}

pub fn build_acme_tls_alpn_challenge_certificate(
    hostname: &str,
    key_authorization: &str,
) -> Result<(String, String), WireError> {
    let digest = Sha256::digest(key_authorization.as_bytes());
    let mut params = rcgen::CertificateParams::new(vec![hostname.to_string()])
        .map_err(|e| WireError::Internal(format!("rcgen params: {e}")))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, hostname);
    params
        .custom_extensions
        .push(rcgen::CustomExtension::new_acme_identifier(&digest));
    let key = rcgen::KeyPair::generate()
        .map_err(|e| WireError::Internal(format!("rcgen keypair: {e}")))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| WireError::Internal(format!("rcgen self_signed: {e}")))?;
    Ok((cert.pem(), key.serialize_pem()))
}

fn build_server_config(cert_pem: &str, key_pem: &str) -> Result<ServerConfig, WireError> {
    build_server_config_with_alpn(cert_pem, key_pem, vec![b"http/1.1".to_vec()])
}

fn certified_key_from_pem(cert_pem: &str, key_pem: &str) -> Result<CertifiedKey, WireError> {
    let certs = certificates_from_pem(cert_pem)?;
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| WireError::Internal(format!("parse key pem: {e}")))?;
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = provider.clone().install_default();
    CertifiedKey::from_der(certs, key, &provider)
        .map_err(|e| WireError::Internal(format!("rustls certified key: {e}")))
}

fn certified_key_from_pem_without_webpki_checks(
    cert_pem: &str,
    key_pem: &str,
) -> Result<CertifiedKey, WireError> {
    let certs = certificates_from_pem(cert_pem)?;
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| WireError::Internal(format!("parse key pem: {e}")))?;
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = provider.clone().install_default();
    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|e| WireError::Internal(format!("rustls signing key: {e}")))?;
    Ok(CertifiedKey::new(certs, signing_key))
}

fn certificates_from_pem(cert_pem: &str) -> Result<Vec<CertificateDer<'static>>, WireError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|e| WireError::Internal(format!("parse cert pem: {e}")))?;
    if certs.is_empty() {
        return Err(WireError::Internal("no certificates in cert pem".into()));
    }
    Ok(certs)
}

fn client_offers_acme_tls_alpn(client_hello: &ClientHello<'_>) -> bool {
    client_hello
        .alpn()
        .into_iter()
        .flatten()
        .any(|protocol| protocol == ACME_TLS_ALPN_PROTOCOL)
}

fn build_server_config_with_alpn(
    cert_pem: &str,
    key_pem: &str,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<ServerConfig, WireError> {
    let certs = certificates_from_pem(cert_pem)?;
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| WireError::Internal(format!("parse key pem: {e}")))?;

    // Install a default crypto provider if one isn't set. Cheap and
    // idempotent (`install_default` returns Err on a second install,
    // which we ignore).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| WireError::Internal(format!("rustls server config: {e}")))?;
    // ALPN: advertise HTTP/1.1 only.
    //
    // Stock `tailscale up` does its TS2021 noise handshake over a
    // plain `Upgrade: tailscale-control-protocol` request (HTTP/1.1
    // semantics) and then runs HTTP/2 *inside* the Noise transport
    // — see `noise.rs::drive_ts2021`. If the TLS layer negotiates
    // HTTP/2 via ALPN, the client can no longer send an Upgrade
    // header (RFC 7540 forbids it) and the noise dial fails with
    // `early eof` on the server side.
    cfg.alpn_protocols = alpn_protocols;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn mint_and_reload_yields_same_pem() {
        let dir = tempdir().unwrap();
        let sans = SanConfig::with_hostname("test-host");
        let a = load_or_generate(dir.path(), &sans).unwrap();
        let b = load_or_generate(dir.path(), &sans).unwrap();
        assert_eq!(a.cert_pem, b.cert_pem, "cert must persist across loads");
        assert_eq!(a.key_pem, b.key_pem, "key must persist across loads");
        assert!(a.cert_path.exists());
        assert!(a.key_path.exists());
    }

    #[test]
    fn mint_includes_primary_hostname_san() {
        let dir = tempdir().unwrap();
        let sans = SanConfig::with_hostname("tsi-mesh-control");
        let m = load_or_generate(dir.path(), &sans).unwrap();
        // The PEM contains the hostname somewhere in the encoded SAN
        // extension; a substring search is enough for the smoke test
        // (we're not parsing X.509 here).
        assert!(
            m.cert_pem.contains("BEGIN CERTIFICATE"),
            "expected PEM-encoded cert"
        );
        assert!(
            m.key_pem.contains("BEGIN PRIVATE KEY") || m.key_pem.contains("BEGIN EC PRIVATE KEY"),
            "expected PEM-encoded private key"
        );
    }

    #[test]
    fn load_from_files_reuses_manual_pem_paths() {
        let dir = tempdir().unwrap();
        let sans = SanConfig::with_hostname("manual.example");
        let generated = load_or_generate(dir.path(), &sans).unwrap();

        let loaded = load_from_files(&generated.cert_path, &generated.key_path).unwrap();

        assert_eq!(loaded.cert_pem, generated.cert_pem);
        assert_eq!(loaded.key_pem, generated.key_pem);
        assert_eq!(loaded.cert_path, generated.cert_path);
        assert_eq!(loaded.key_path, generated.key_path);
    }

    #[test]
    fn load_from_autocert_cache_reads_go_dircache_combined_pem() {
        let dir = tempdir().unwrap();
        let source_dir = dir.path().join("source");
        let cache_dir = dir.path().join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();
        let sans = SanConfig::with_hostname("headscale.example");
        let generated = load_or_generate(&source_dir, &sans).unwrap();
        std::fs::write(
            cache_dir.join("headscale.example"),
            format!("{}{}", generated.key_pem, generated.cert_pem),
        )
        .unwrap();

        let loaded = load_from_autocert_cache(&cache_dir, "headscale.example").unwrap();

        assert_eq!(loaded.cert_pem, generated.cert_pem);
        assert_eq!(loaded.key_pem, generated.key_pem);
        assert_eq!(loaded.cert_path, cache_dir.join("headscale.example"));
        assert_eq!(loaded.key_path, cache_dir.join("headscale.example"));
        assert_eq!(loaded.expires_at, generated.expires_at);
    }

    #[test]
    fn load_from_autocert_cache_reports_missing_entry() {
        let dir = tempdir().unwrap();

        let Err(err) = load_from_autocert_cache(dir.path(), "headscale.example") else {
            panic!("expected missing ACME cache entry to fail");
        };

        assert!(err.to_string().contains("load ACME cache entry"));
    }

    #[test]
    fn leaf_certificate_not_after_parses_first_certificate() {
        let (leaf_pem, leaf_not_after) = test_cert_pem("leaf.example", 2030, 1, 2);
        let (issuer_pem, _issuer_not_after) = test_cert_pem("issuer.example", 2040, 1, 2);

        let parsed = leaf_certificate_not_after(&format!("{leaf_pem}{issuer_pem}")).unwrap();

        assert_eq!(parsed.timestamp(), leaf_not_after);
    }

    #[test]
    fn reloadable_server_config_swaps_current_config() {
        let dir = tempdir().unwrap();
        let sans = SanConfig::with_hostname("reload.example");
        let generated = load_or_generate(dir.path(), &sans).unwrap();
        let http = Arc::clone(&generated.server_config);
        let grpc = Arc::new(
            build_grpc_server_config(&generated.cert_pem, &generated.key_pem)
                .expect("gRPC TLS config"),
        );
        let reloadable = ReloadableServerConfig::new(http);

        assert_eq!(
            reloadable.current().alpn_protocols,
            vec![b"http/1.1".to_vec()]
        );
        reloadable.replace(grpc);
        assert_eq!(reloadable.current().alpn_protocols, vec![b"h2".to_vec()]);
    }

    #[test]
    fn acme_tls_alpn_config_advertises_acme_protocol_only() {
        let dir = tempdir().unwrap();
        let sans = SanConfig::with_hostname("acme.example");
        let generated = load_or_generate(dir.path(), &sans).unwrap();

        let cfg = build_acme_tls_alpn_server_config(&generated.cert_pem, &generated.key_pem)
            .expect("ACME TLS-ALPN rustls config");

        assert_eq!(cfg.alpn_protocols, vec![ACME_TLS_ALPN_PROTOCOL.to_vec()]);
    }

    #[test]
    fn acme_tls_alpn_autocert_cache_enables_dynamic_resolver() {
        let dir = tempdir().unwrap();
        let source_dir = dir.path().join("source");
        let cache_dir = dir.path().join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();
        let generated =
            load_or_generate(&source_dir, &SanConfig::with_hostname("headscale.example")).unwrap();
        std::fs::write(
            cache_dir.join("headscale.example"),
            format!("{}{}", generated.key_pem, generated.cert_pem),
        )
        .unwrap();

        let loaded =
            load_from_autocert_cache_with_tls_alpn(&cache_dir, "headscale.example").unwrap();

        assert!(loaded.acme_tls_alpn_resolver.is_some());
        assert_eq!(
            loaded.server_config.alpn_protocols,
            vec![b"http/1.1".to_vec(), ACME_TLS_ALPN_PROTOCOL.to_vec()]
        );
    }

    #[test]
    fn acme_tls_alpn_bootstrap_material_does_not_create_cache_entry() {
        let dir = tempdir().unwrap();
        let cache_dir = dir.path().join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();

        let loaded =
            load_from_autocert_cache_with_tls_alpn_or_bootstrap(&cache_dir, "headscale.example")
                .unwrap();

        assert!(loaded.acme_tls_alpn_resolver.is_some());
        assert_eq!(loaded.cert_path, cache_dir.join("headscale.example"));
        assert_eq!(loaded.key_path, cache_dir.join("headscale.example"));
        assert!(!cache_dir.join("headscale.example").exists());
        assert_eq!(
            loaded.server_config.alpn_protocols,
            vec![b"http/1.1".to_vec(), ACME_TLS_ALPN_PROTOCOL.to_vec()]
        );
    }

    #[test]
    fn acme_tls_alpn_challenge_certificate_has_required_identifier_extension() {
        let key_authorization = "token.example-thumbprint";
        let (cert_pem, key_pem) =
            build_acme_tls_alpn_challenge_certificate("headscale.example", key_authorization)
                .unwrap();
        let default = load_or_generate(
            tempdir().unwrap().path(),
            &SanConfig::with_hostname("headscale.example"),
        )
        .unwrap();
        let (_server_config, resolver) =
            build_server_config_with_acme_tls_alpn_resolver(&default.cert_pem, &default.key_pem)
                .unwrap();

        resolver
            .set_challenge_certificate("headscale.example", &cert_pem, &key_pem)
            .unwrap();
        assert!(resolver.has_challenge_certificate("headscale.example"));
        let leaf = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(leaf.as_ref()).unwrap();
        let extension = cert
            .extensions()
            .iter()
            .find(|extension| extension.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
            .expect("acmeIdentifier extension");
        let digest = Sha256::digest(key_authorization.as_bytes());
        let mut expected = vec![0x04, 0x20];
        expected.extend_from_slice(&digest);

        assert!(extension.critical);
        assert_eq!(extension.value, expected.as_slice());
    }

    #[tokio::test]
    async fn acme_tls_alpn_resolver_selects_challenge_cert_for_matching_sni_and_alpn() {
        let dir = tempdir().unwrap();
        let normal = load_or_generate(
            dir.path().join("normal"),
            &SanConfig::with_hostname("acme.example"),
        )
        .unwrap();
        let challenge = load_or_generate(
            dir.path().join("challenge"),
            &SanConfig::with_hostname("acme.example"),
        )
        .unwrap();
        let (server_config, resolver) =
            build_server_config_with_acme_tls_alpn_resolver(&normal.cert_pem, &normal.key_pem)
                .unwrap();
        resolver
            .set_challenge_certificate("acme.example", &challenge.cert_pem, &challenge.key_pem)
            .unwrap();

        let peer_cert = tls_peer_leaf_for_test(
            Arc::new(server_config),
            "acme.example",
            vec![ACME_TLS_ALPN_PROTOCOL.to_vec()],
            &challenge.cert_pem,
        )
        .await;

        assert_eq!(
            peer_cert,
            first_certificate_der_for_test(&challenge.cert_pem)
        );
    }

    #[tokio::test]
    async fn acme_tls_alpn_resolver_uses_default_cert_for_normal_alpn() {
        let dir = tempdir().unwrap();
        let normal = load_or_generate(
            dir.path().join("normal"),
            &SanConfig::with_hostname("acme.example"),
        )
        .unwrap();
        let challenge = load_or_generate(
            dir.path().join("challenge"),
            &SanConfig::with_hostname("acme.example"),
        )
        .unwrap();
        let (server_config, resolver) =
            build_server_config_with_acme_tls_alpn_resolver(&normal.cert_pem, &normal.key_pem)
                .unwrap();
        resolver
            .set_challenge_certificate("acme.example", &challenge.cert_pem, &challenge.key_pem)
            .unwrap();

        let peer_cert = tls_peer_leaf_for_test(
            Arc::new(server_config),
            "acme.example",
            vec![b"http/1.1".to_vec()],
            &normal.cert_pem,
        )
        .await;

        assert_eq!(peer_cert, first_certificate_der_for_test(&normal.cert_pem));
    }

    #[tokio::test]
    async fn acme_tls_alpn_resolver_replaces_default_cert_without_losing_challenge_cert() {
        let dir = tempdir().unwrap();
        let normal = load_or_generate(
            dir.path().join("normal"),
            &SanConfig::with_hostname("acme.example"),
        )
        .unwrap();
        let renewed = load_or_generate(
            dir.path().join("renewed"),
            &SanConfig::with_hostname("acme.example"),
        )
        .unwrap();
        let challenge = load_or_generate(
            dir.path().join("challenge"),
            &SanConfig::with_hostname("acme.example"),
        )
        .unwrap();
        let (_server_config, resolver) =
            build_server_config_with_acme_tls_alpn_resolver(&normal.cert_pem, &normal.key_pem)
                .unwrap();
        resolver
            .set_challenge_certificate("acme.example", &challenge.cert_pem, &challenge.key_pem)
            .unwrap();
        let (server_config, same_resolver) =
            build_server_config_with_existing_acme_tls_alpn_resolver(
                &renewed.cert_pem,
                &renewed.key_pem,
                resolver.clone(),
            )
            .unwrap();

        assert!(Arc::ptr_eq(&resolver, &same_resolver));
        assert!(resolver.has_challenge_certificate("acme.example"));
        let server_config = Arc::new(server_config);
        let normal_peer_cert = tls_peer_leaf_for_test(
            server_config.clone(),
            "acme.example",
            vec![b"http/1.1".to_vec()],
            &renewed.cert_pem,
        )
        .await;
        let challenge_peer_cert = tls_peer_leaf_for_test(
            server_config,
            "acme.example",
            vec![ACME_TLS_ALPN_PROTOCOL.to_vec()],
            &challenge.cert_pem,
        )
        .await;

        assert_eq!(
            normal_peer_cert,
            first_certificate_der_for_test(&renewed.cert_pem)
        );
        assert_eq!(
            challenge_peer_cert,
            first_certificate_der_for_test(&challenge.cert_pem)
        );
    }

    fn test_cert_pem(dns_name: &str, year: i32, month: u8, day: u8) -> (String, i64) {
        let not_after = rcgen::date_time_ymd(year, month, day);
        let mut params = rcgen::CertificateParams::new(vec![dns_name.to_string()]).unwrap();
        params.not_after = not_after;
        let key = rcgen::KeyPair::generate().unwrap();
        (
            params.self_signed(&key).unwrap().pem(),
            not_after.unix_timestamp(),
        )
    }

    async fn tls_peer_leaf_for_test(
        server_config: Arc<ServerConfig>,
        server_name: &str,
        client_alpn: Vec<Vec<u8>>,
        trusted_cert_pem: &str,
    ) -> Vec<u8> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            acceptor.accept(tcp).await.unwrap();
        });

        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(first_certificate_der_for_test(
                trusted_cert_pem,
            )))
            .unwrap();
        let mut client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config.alpn_protocols = client_alpn;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string()).unwrap();
        let stream = connector.connect(server_name, tcp).await.unwrap();
        let peer_cert = stream
            .get_ref()
            .1
            .peer_certificates()
            .unwrap()
            .first()
            .unwrap()
            .as_ref()
            .to_vec();
        server.await.unwrap();
        peer_cert
    }

    fn first_certificate_der_for_test(cert_pem: &str) -> Vec<u8> {
        CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap()
            .as_ref()
            .to_vec()
    }
}
