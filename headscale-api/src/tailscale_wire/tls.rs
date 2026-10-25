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
    io::{self, ErrorKind, Read, Write},
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

#[cfg(feature = "full")]
use std::{future::Future, pin::Pin};

#[cfg(feature = "full")]
mod acme_cache;
#[cfg(feature = "full")]
mod acme_hostname;
#[cfg(feature = "full")]
mod acme_token_cache;

/// Filename for the persisted cert (PEM).
pub const TLS_CERT_FILENAME: &str = "tls.crt";
/// Filename for the persisted private key (PEM).
pub const TLS_KEY_FILENAME: &str = "tls.key";
/// ALPN protocol required by ACME TLS-ALPN-01 challenge handshakes.
pub const ACME_TLS_ALPN_PROTOCOL: &[u8] = b"acme-tls/1";

/// Materialized TLS material — the PEM-encoded cert + key (so callers
/// can copy them into a peer's trust store) plus a ready-to-bind
/// [`rustls::ServerConfig`]. Lazy native ACME initial material has empty PEMs
/// and Go zero expiry until its provider selects an ordinary certificate.
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
    #[cfg(feature = "full")]
    certificate_provider: Arc<RwLock<Option<Arc<dyn AcmeCertificateProvider>>>>,
}

impl ReloadableServerConfig {
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self {
            current: Arc::new(RwLock::new(config)),
            #[cfg(feature = "full")]
            certificate_provider: Arc::new(RwLock::new(None)),
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

    /// Install the native async ACME provider before accepting connections.
    #[cfg(feature = "full")]
    pub fn set_certificate_provider(&self, provider: Arc<dyn AcmeCertificateProvider>) {
        *self
            .certificate_provider
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(provider);
    }

    #[cfg(feature = "full")]
    pub fn certificate_provider(&self) -> Option<Arc<dyn AcmeCertificateProvider>> {
        self.certificate_provider
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// Ordinary autocert key identity. The token cache has an independent key kind.
#[cfg(feature = "full")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AcmeCertificateKind {
    Ecdsa,
    Rsa,
}

/// Owned certificate request captured at the native TLS certificate phase.
/// Original SNI and optional signature offers survive suite filtering; resumed
/// TLS 1.3 connections complete this phase without preparing a certificate.
#[cfg(feature = "full")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcmeHandshakeRequest {
    pub hostname: String,
    pub kind: AcmeCertificateKind,
    pub token: bool,
}

#[cfg(feature = "full")]
impl AcmeHandshakeRequest {
    pub fn from_client_hello(hello: &ClientHello<'_>) -> Result<Self, WireError> {
        let hostname = acme_hostname::server_name_bytes(
            hello
                .raw_server_name()
                .or_else(|| hello.server_name().map(str::as_bytes)),
        )?;
        let token = client_offers_acme_tls_alpn(hello);
        let kind = if token || supports_ecdsa(hello) {
            AcmeCertificateKind::Ecdsa
        } else {
            AcmeCertificateKind::Rsa
        };
        Ok(Self {
            hostname,
            kind,
            token,
        })
    }

    pub fn allowed_for_hostname(&self, configured: &str) -> bool {
        self.token || acme_hostname::HostPolicy::new(configured).allows(&self.hostname)
    }
}

/// Async native certificate preparation; public embedding defaults have none.
/// The prepared configuration supplies its certificate resolver. The listener's
/// baseline configuration owns protocol/session policy throughout the handshake.
#[cfg(feature = "full")]
pub trait AcmeCertificateProvider: Send + Sync {
    fn initial_material(&self) -> Result<TlsMaterial, WireError>;
    fn prepare(
        &self,
        request: AcmeHandshakeRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<ServerConfig>, WireError>> + Send + 'static>>;
}

#[cfg(feature = "full")]
fn supports_ecdsa(hello: &ClientHello<'_>) -> bool {
    // Selected autocert.supportsECDSA examines the raw extension, then P-256
    // named-group support, then these exact legacy ECDSA cipher identifiers.
    // A missing extension does not restrict Go's ECDSA selection. It remains
    // absent; the native TLS state machine decides later whether a full or
    // resumed handshake can proceed, without synthesizing signature offers.
    if hello.original_signature_schemes().is_some_and(|schemes| {
        !schemes
            .iter()
            .any(|scheme| matches!(u16::from(*scheme), 0x0203 | 0x0403 | 0x0503 | 0x0603))
    }) {
        return false;
    }
    if let Some(groups) = hello.named_groups()
        && !groups.iter().any(|group| u16::from(*group) == 23)
    {
        return false;
    }
    hello.cipher_suites().iter().any(|suite| {
        matches!(
            u16::from(*suite),
            0xc007 | 0xc009 | 0xc00a | 0xc023 | 0xc02b | 0xc02c | 0xcca9
        )
    })
}

/// Dynamic rustls certificate resolver for ACME TLS-ALPN-01.
///
/// Normal control-plane handshakes receive the default certificate. ACME
/// validation handshakes receive a challenge certificate when the SNI hostname
/// matches an installed challenge (or native persisted token) and the client
/// offers only `acme-tls/1`.
#[derive(Debug)]
pub struct AcmeTlsAlpnChallengeResolver {
    default_cert: RwLock<Option<Arc<CertifiedKey>>>,
    challenges: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    #[cfg(feature = "full")]
    host_policy: Option<acme_hostname::HostPolicy>,
    #[cfg(feature = "full")]
    token_cache: Option<acme_token_cache::TokenCache>,
}

impl AcmeTlsAlpnChallengeResolver {
    pub fn new(default_cert: Arc<CertifiedKey>) -> Arc<Self> {
        Arc::new(Self {
            default_cert: RwLock::new(Some(default_cert)),
            challenges: RwLock::new(HashMap::new()),
            #[cfg(feature = "full")]
            host_policy: None,
            #[cfg(feature = "full")]
            token_cache: None,
        })
    }

    #[cfg(feature = "full")]
    fn for_hostname(
        default_cert: Arc<CertifiedKey>,
        hostname: &str,
        cache_dir: &Path,
    ) -> Arc<Self> {
        Self::for_native(Some(default_cert), hostname, cache_dir)
    }

    #[cfg(feature = "full")]
    fn for_native(
        default_cert: Option<Arc<CertifiedKey>>,
        hostname: &str,
        cache_dir: &Path,
    ) -> Arc<Self> {
        Arc::new(Self {
            default_cert: RwLock::new(default_cert),
            challenges: RwLock::new(HashMap::new()),
            host_policy: Some(acme_hostname::HostPolicy::new(hostname)),
            token_cache: Some(acme_token_cache::TokenCache::new(cache_dir.to_path_buf())),
        })
    }

    // Without `full` there is no host policy to consult, so `self` is unused and
    // the lookup cannot fail; the signature stays shared across feature sets.
    #[cfg_attr(
        not(feature = "full"),
        allow(clippy::unused_self, clippy::unnecessary_wraps)
    )]
    fn challenge_key(&self, hostname: &str) -> Option<String> {
        #[cfg(feature = "full")]
        if self.host_policy.is_some() {
            return acme_hostname::lookup(hostname);
        }
        Some(hostname.to_owned())
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
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(cert);
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
        let hostname = hostname.into();
        let hostname = self.challenge_key(&hostname).ok_or_else(|| {
            WireError::Internal("ACME hostname contains invalid character".into())
        })?;
        let mut challenges = self
            .challenges
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(feature = "full")]
        challenges.insert(hostname.clone(), cert);
        #[cfg(not(feature = "full"))]
        challenges.insert(hostname, cert);
        #[cfg(feature = "full")]
        if let Some(cache) = &self.token_cache {
            // Go holds challengeMu while publishing memory and best-effort
            // Cache.Put. Cache failures do not undo the installed challenge.
            let _ = cache.put(&hostname, cert_pem, key_pem);
        }
        drop(challenges);
        Ok(())
    }

    pub fn clear_challenge_certificate(&self, hostname: &str) {
        let Some(hostname) = self.challenge_key(hostname) else {
            return;
        };
        let mut challenges = self
            .challenges
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        challenges.remove(&hostname);
        #[cfg(feature = "full")]
        if let Some(cache) = &self.token_cache {
            cache.delete(&hostname);
        }
        drop(challenges);
    }

    pub fn has_challenge_certificate(&self, hostname: &str) -> bool {
        let Some(hostname) = self.challenge_key(hostname) else {
            return false;
        };
        self.challenges
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(&hostname)
    }
}

impl ResolvesServerCert for AcmeTlsAlpnChallengeResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        #[cfg(feature = "full")]
        let hostname = if self.host_policy.is_some() {
            Some(
                acme_hostname::server_name_bytes(
                    client_hello
                        .raw_server_name()
                        .or_else(|| client_hello.server_name().map(str::as_bytes)),
                )
                .ok()?,
            )
        } else {
            client_hello.server_name().map(str::to_owned)
        };
        #[cfg(not(feature = "full"))]
        let hostname = client_hello.server_name().map(str::to_owned);
        if client_offers_acme_tls_alpn(&client_hello) {
            let hostname = hostname?;
            let challenges = self
                .challenges
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(cert) = challenges.get(&hostname) {
                return Some(cert.clone());
            }
            #[cfg(feature = "full")]
            if let Some(cache) = &self.token_cache {
                // Keep the map read lock across cache fallback like Go's
                // GetCertificate. Disk hits are not promoted into memory.
                let cert = cache.read(&hostname);
                drop(challenges);
                return cert;
            }
            return None;
        }
        #[cfg(feature = "full")]
        if let Some(policy) = &self.host_policy
            && !policy.allows(hostname.as_deref()?)
        {
            return None;
        }
        self.default_cert
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
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
    /// ACME/autocert cache mode for HTTP-01. When the cache is missing, use an
    /// in-memory self-signed certificate so all listeners can bind before the
    /// issuer makes any public-CA network request.
    AcmeAutocertCacheWithHttp01Bootstrap {
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
            Self::AcmeAutocertCacheWithHttp01Bootstrap {
                cache_dir,
                hostname,
            } => load_from_autocert_cache_or_bootstrap(cache_dir, hostname),
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

/// Parsed, eligible native ordinary cache entry, independent of TLS selection.
#[cfg(feature = "full")]
#[derive(Clone)]
pub struct AcmeCachedCertificate {
    pub key_pem: String,
    pub cert_pem: String,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub cache_path: PathBuf,
}

#[cfg(feature = "full")]
pub fn autocert_cache_path_for_kind(
    cache_dir: impl AsRef<Path>,
    hostname: &str,
    kind: AcmeCertificateKind,
) -> Result<PathBuf, WireError> {
    let hostname = autocert_cache_hostname(hostname)?;
    let filename = match kind {
        AcmeCertificateKind::Ecdsa => hostname,
        AcmeCertificateKind::Rsa => format!("{hostname}+rsa"),
    };
    let mut components = Path::new(&filename).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(WireError::Internal(
            "invalid ACME certificate cache name".into(),
        ));
    }
    Ok(cache_dir.as_ref().join(filename))
}

#[cfg(feature = "full")]
pub fn load_autocert_certificate(
    cache_dir: impl AsRef<Path>,
    hostname: &str,
    kind: AcmeCertificateKind,
) -> Result<AcmeCachedCertificate, WireError> {
    let cache_path = autocert_cache_path_for_kind(cache_dir, hostname, kind)?;
    let bytes = fs::read(&cache_path).map_err(|err| {
        WireError::Internal(format!(
            "load ACME cache entry {} for hostname {hostname}: {err}",
            cache_path.display()
        ))
    })?;
    let (key_pem, cert_pem, expires_at) = acme_cache::load_normal(&bytes, hostname, kind)?;
    cached_certificate_from_parts(cache_path, key_pem, cert_pem, expires_at)
}

/// Lookup with selected autocert error classes: absent/invalid certificate is
/// a miss, while non-NotFound filesystem and private-key parse errors propagate.
#[cfg(feature = "full")]
pub fn lookup_autocert_certificate(
    cache_dir: impl AsRef<Path>,
    hostname: &str,
    kind: AcmeCertificateKind,
) -> Result<Option<AcmeCachedCertificate>, WireError> {
    let cache_path = autocert_cache_path_for_kind(cache_dir, hostname, kind)?;
    let bytes = match fs::read(&cache_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(WireError::Internal(format!(
                "load ACME cache entry {} for hostname {hostname}: {error}",
                cache_path.display()
            )));
        }
    };
    let Some((key_pem, cert_pem, expires_at)) = acme_cache::lookup_normal(&bytes, hostname, kind)?
    else {
        return Ok(None);
    };
    cached_certificate_from_parts(cache_path, key_pem, cert_pem, expires_at).map(Some)
}

/// Validate newly issued ordinary material without accessing the filesystem.
/// First issuance can serve this material even when the best-effort cache write
/// fails; renewal publication retains its separate successful-write boundary.
#[cfg(feature = "full")]
pub fn validate_autocert_certificate(
    cache_dir: impl AsRef<Path>,
    hostname: &str,
    kind: AcmeCertificateKind,
    key_pem: &str,
    cert_pem: &str,
) -> Result<AcmeCachedCertificate, WireError> {
    let cache_path = autocert_cache_path_for_kind(cache_dir, hostname, kind)?;
    let combined = acme_cache::encode_entry(key_pem, cert_pem)?;
    let (key_pem, cert_pem, expires_at) =
        acme_cache::load_normal(combined.as_bytes(), hostname, kind)?;
    cached_certificate_from_parts(cache_path, key_pem, cert_pem, expires_at)
}

#[cfg(feature = "full")]
fn cached_certificate_from_parts(
    cache_path: PathBuf,
    key_pem: String,
    cert_pem: String,
    expires_at: DateTime<Utc>,
) -> Result<AcmeCachedCertificate, WireError> {
    let leaf = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .next()
        .ok_or_else(|| WireError::Internal("no certificates in cert pem".into()))?
        .map_err(|err| WireError::Internal(format!("parse leaf certificate pem: {err}")))?;
    let (_, cert) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|err| WireError::Internal(format!("parse leaf certificate x509: {err}")))?;
    let not_before = DateTime::from_timestamp(cert.validity().not_before.timestamp(), 0)
        .ok_or_else(|| WireError::Internal("leaf certificate notBefore is out of range".into()))?;
    Ok(AcmeCachedCertificate {
        key_pem,
        cert_pem,
        not_before,
        expires_at,
        cache_path,
    })
}

/// Construct native ACME listener material without reading a cache, generating
/// a key, or issuing a certificate. Ordinary handshakes need the async provider;
/// token handshakes use the bound in-memory/durable challenge resolver.
#[cfg(feature = "full")]
pub fn load_lazy_acme_material(
    cache_dir: impl AsRef<Path>,
    hostname: &str,
) -> Result<TlsMaterial, WireError> {
    let cache_dir = cache_dir.as_ref();
    let resolver = AcmeTlsAlpnChallengeResolver::for_native(None, hostname, cache_dir);
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let server_config = acme_server_config_with_resolver(resolver.clone());
    let cache_path = autocert_cache_path(cache_dir, hostname);
    let expires_at = DateTime::from_timestamp(-62_135_596_800, 0)
        .ok_or_else(|| WireError::Internal("Go zero time is out of range".into()))?;
    Ok(TlsMaterial {
        cert_pem: String::new(),
        key_pem: String::new(),
        cert_path: cache_path.clone(),
        key_path: cache_path,
        server_config: Arc::new(server_config),
        acme_tls_alpn_resolver: Some(resolver),
        expires_at,
    })
}

/// Build the already-selected ordinary ACME certificate configuration. Token
/// requests must use the initial bound resolver instead of this configuration.
#[cfg(feature = "full")]
pub fn build_acme_selected_server_config(
    cert_pem: &str,
    key_pem: &str,
) -> Result<ServerConfig, WireError> {
    build_server_config_with_alpn(
        cert_pem,
        key_pem,
        vec![
            b"h2".to_vec(),
            b"http/1.1".to_vec(),
            ACME_TLS_ALPN_PROTOCOL.to_vec(),
        ],
    )
}

/// Load an ACME cache entry, or bootstrap with in-memory self-signed material
/// while HTTP-01 startup issuance produces the real cache entry.
pub fn load_from_autocert_cache_or_bootstrap(
    cache_dir: impl AsRef<Path>,
    hostname: &str,
) -> Result<TlsMaterial, WireError> {
    let cache_dir = cache_dir.as_ref().to_path_buf();
    match load_from_autocert_cache(&cache_dir, hostname) {
        Ok(material) => Ok(material),
        Err(err) => {
            tracing::info!(
                hostname = %hostname,
                cache_dir = %cache_dir.display(),
                error = %err,
                "ACME HTTP-01 cache entry missing or invalid; bootstrapping listener with temporary self-signed material"
            );
            bootstrap_acme_material(&cache_dir, hostname, false)
        }
    }
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
            bootstrap_acme_material(&cache_dir, hostname, true)
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
    #[cfg(feature = "full")]
    let combined_pem = fs::read(&cache_path);
    #[cfg(not(feature = "full"))]
    let combined_pem = read_pem(&cache_path);
    let combined_pem = combined_pem.map_err(|err| {
        WireError::Internal(format!(
            "load ACME cache entry {} for hostname {hostname}: {err}",
            cache_path.display()
        ))
    })?;
    #[cfg(feature = "full")]
    let (key_pem, cert_pem, expires_at) =
        acme_cache::load(&combined_pem, hostname).map_err(|err| {
            WireError::Internal(format!(
                "parse ACME cache entry {} for hostname {hostname}: {err}",
                cache_path.display()
            ))
        })?;
    #[cfg(not(feature = "full"))]
    let (key_pem, cert_pem) = split_autocert_pem(&combined_pem).map_err(|err| {
        WireError::Internal(format!(
            "parse ACME cache entry {} for hostname {hostname}: {err}",
            cache_path.display()
        ))
    })?;
    #[cfg(not(feature = "full"))]
    let expires_at = leaf_certificate_not_after(&cert_pem)?;
    let (server_config, acme_tls_alpn_resolver) = if enable_tls_alpn {
        let (server_config, resolver) =
            build_acme_server_config_for_hostname(&cert_pem, &key_pem, hostname, &cache_dir)?;
        (server_config, Some(resolver))
    } else {
        (
            build_acme_server_config(&cert_pem, &key_pem, hostname, &cache_dir)?,
            None,
        )
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

fn bootstrap_acme_material(
    cache_dir: &Path,
    hostname: &str,
    enable_tls_alpn: bool,
) -> Result<TlsMaterial, WireError> {
    let cache_path = autocert_cache_path(cache_dir, hostname);
    #[cfg(feature = "full")]
    let certificate_hostname =
        acme_hostname::lookup(hostname).unwrap_or_else(|| hostname.to_owned());
    #[cfg(not(feature = "full"))]
    let certificate_hostname = hostname.to_owned();
    let sans = SanConfig::with_hostname(certificate_hostname);
    let (cert_pem, key_pem) = mint_self_signed(&sans)?;
    let expires_at = leaf_certificate_not_after(&cert_pem)?;
    let (server_config, resolver) = if enable_tls_alpn {
        let (server_config, resolver) =
            build_acme_server_config_for_hostname(&cert_pem, &key_pem, hostname, cache_dir)?;
        (server_config, Some(resolver))
    } else {
        (
            build_acme_server_config(&cert_pem, &key_pem, hostname, cache_dir)?,
            None,
        )
    };
    Ok(TlsMaterial {
        cert_pem,
        key_pem,
        cert_path: cache_path.clone(),
        key_path: cache_path,
        server_config: Arc::new(server_config),
        acme_tls_alpn_resolver: resolver,
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
    #[cfg(feature = "full")]
    if let Ok(hostname) = autocert_cache_hostname(hostname) {
        return cache_dir.join(hostname);
    }
    // Invalid configured names form an empty native HostWhitelist. Retain the
    // existing loader/bootstrap error boundary instead of making binding the
    // otherwise-denying host policy a new eager configuration failure.
    let clean = hostname
        .trim()
        .trim_start_matches('/')
        .split('/')
        .filter(|part| !part.is_empty() && *part != "." && *part != "..")
        .collect::<Vec<_>>()
        .join("/");
    cache_dir.join(clean)
}

/// The form autocert's `HostWhitelist` stores a configured name in
/// (`idna.Lookup.ToASCII`) and compares request hosts against. `None` for a
/// name the whitelist silently omits, which then admits nothing.
#[cfg(feature = "full")]
pub(crate) fn host_whitelist_name(hostname: &str) -> Option<String> {
    acme_hostname::lookup(hostname)
}

/// Normalize a configured ACME certificate-cache name with the selected
/// Lookup profile, then remove one trailing root dot for the cache key.
/// HostWhitelist comparison retains that dot and uses a separate value.
#[cfg(feature = "full")]
pub fn autocert_cache_hostname(hostname: &str) -> Result<String, WireError> {
    acme_hostname::cache_hostname(hostname)
        .ok_or_else(|| WireError::Internal("ACME hostname contains invalid character".into()))
}

/// Encode native ACME certificate output as a canonical combined cache entry.
/// Certificate PEM extraction follows the selected Go ACME response decoder;
/// cache eligibility is checked separately when the entry is loaded.
#[cfg(feature = "full")]
pub fn autocert_cache_entry(key_pem: &str, cert_pem: &str) -> Result<String, WireError> {
    acme_cache::encode_entry(key_pem, cert_pem)
}

/// Prepare and validate an issued native certificate before replacing its cache.
/// Selected autocert validates the issued leaf before publishing or caching it.
#[cfg(feature = "full")]
pub fn autocert_cache_entry_for_hostname(
    hostname: &str,
    key_pem: &str,
    cert_pem: &str,
) -> Result<String, WireError> {
    autocert_cache_entry_for_kind(hostname, AcmeCertificateKind::Ecdsa, key_pem, cert_pem)
}

#[cfg(feature = "full")]
pub fn autocert_cache_entry_for_kind(
    hostname: &str,
    kind: AcmeCertificateKind,
    key_pem: &str,
    cert_pem: &str,
) -> Result<String, WireError> {
    let combined = autocert_cache_entry(key_pem, cert_pem)?;
    acme_cache::load_normal(combined.as_bytes(), hostname, kind)?;
    Ok(combined)
}

#[cfg(not(feature = "full"))]
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

/// Persist generated key/certificate material without following a predictable
/// temporary symlink or exposing a private key before a later chmod.
pub(super) fn write_atomic(p: &Path, bytes: &[u8], mode: u32) -> Result<(), WireError> {
    use rand_core::RngCore;

    let mut nonce = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut nonce);
    let mut name = p
        .file_name()
        .ok_or_else(|| io::Error::other("key path has no filename"))?
        .to_os_string();
    name.push(format!(".{}.tmp", hex::encode(nonce)));
    let tmp = p.with_file_name(name);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    let mut file = options.open(&tmp)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, p)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map_err(Into::into)
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
    Ok((acme_server_config_with_resolver(resolver.clone()), resolver))
}

fn acme_server_config_with_resolver(resolver: Arc<AcmeTlsAlpnChallengeResolver>) -> ServerConfig {
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
        ACME_TLS_ALPN_PROTOCOL.to_vec(),
    ];
    cfg
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

fn build_acme_server_config(
    cert_pem: &str,
    key_pem: &str,
    hostname: &str,
    cache_dir: &Path,
) -> Result<ServerConfig, WireError> {
    // ALPN/challenge selection follows x/crypto/acme/autocert (Go Authors,
    // copyright 2016); see LICENSE-GO-STDLIB and NOTICE-GO-STDLIB.
    // autocert advertises both ordinary HTTP protocols and TLS-ALPN-01 even
    // when HTTP-01 is configured. Without an installed challenge, a sole
    // acme-tls/1 offer must not receive the ordinary certificate.
    build_acme_server_config_for_hostname(cert_pem, key_pem, hostname, cache_dir)
        .map(|(config, _)| config)
}

fn build_acme_server_config_for_hostname(
    cert_pem: &str,
    key_pem: &str,
    hostname: &str,
    cache_dir: &Path,
) -> Result<(ServerConfig, Arc<AcmeTlsAlpnChallengeResolver>), WireError> {
    #[cfg(feature = "full")]
    {
        let cert = Arc::new(certified_key_from_pem(cert_pem, key_pem)?);
        let resolver = AcmeTlsAlpnChallengeResolver::for_hostname(cert, hostname, cache_dir);
        build_server_config_with_existing_acme_tls_alpn_resolver(cert_pem, key_pem, resolver)
    }
    #[cfg(not(feature = "full"))]
    {
        let _ = (hostname, cache_dir);
        build_server_config_with_acme_tls_alpn_resolver(cert_pem, key_pem)
    }
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
    let Some(mut protocols) = client_hello.alpn() else {
        return false;
    };
    protocols.next() == Some(ACME_TLS_ALPN_PROTOCOL) && protocols.next().is_none()
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
    // Static control TLS keeps HTTP/1.1 for Noise's HTTP Upgrade. ACME
    // matches autocert's additional ordinary HTTP/2 negotiation; Noise
    // clients still select HTTP/1.1 for that upgrade. gRPC selects h2 only.
    cfg.alpn_protocols = alpn_protocols;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[cfg(unix)]
    #[test]
    fn generated_keys_ignore_legacy_temp_symlinks_and_are_private() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = tempdir().unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, b"unchanged").unwrap();
        let tls_key = dir.path().join(TLS_KEY_FILENAME);
        let tls_tmp = tls_key.with_extension("key.tmp");
        symlink(&victim, &tls_tmp).unwrap();
        write_atomic(&tls_key, b"tls private key", 0o600).unwrap();

        let noise_tmp = dir
            .path()
            .join("noise_static.key")
            .with_extension("key.tmp");
        symlink(&victim, &noise_tmp).unwrap();
        super::super::noise::ServerNoiseKey::load_or_generate(dir.path()).unwrap();
        let noise_key = dir
            .path()
            .join(super::super::noise::NOISE_STATIC_KEY_FILENAME);
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
        assert_eq!(fs::read(&tls_key).unwrap(), b"tls private key");
        for path in [&tls_key, &noise_key] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(
            fs::symlink_metadata(tls_tmp)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            fs::symlink_metadata(noise_tmp)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 5);
    }

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
            vec![
                b"h2".to_vec(),
                b"http/1.1".to_vec(),
                ACME_TLS_ALPN_PROTOCOL.to_vec()
            ]
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
            vec![
                b"h2".to_vec(),
                b"http/1.1".to_vec(),
                ACME_TLS_ALPN_PROTOCOL.to_vec()
            ]
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
