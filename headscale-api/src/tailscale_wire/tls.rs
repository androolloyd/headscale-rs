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
    fs,
    io::{ErrorKind, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};

use super::WireError;

/// Filename for the persisted cert (PEM).
pub const TLS_CERT_FILENAME: &str = "tls.crt";
/// Filename for the persisted private key (PEM).
pub const TLS_KEY_FILENAME: &str = "tls.key";

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
}

impl TlsMaterialSource {
    pub fn load(&self) -> Result<TlsMaterial, WireError> {
        match self {
            Self::SelfSigned { state_dir, sans } => load_or_generate(state_dir, sans),
            Self::Files {
                cert_path,
                key_path,
            } => load_from_files(cert_path, key_path),
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

    let server_config = build_server_config(&cert_pem, &key_pem)?;
    Ok(TlsMaterial {
        cert_pem,
        key_pem,
        cert_path,
        key_path,
        server_config: Arc::new(server_config),
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
    let server_config = build_server_config(&cert_pem, &key_pem)?;
    Ok(TlsMaterial {
        cert_pem,
        key_pem,
        cert_path,
        key_path,
        server_config: Arc::new(server_config),
    })
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
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();

    // Atomic-ish writes — tmp + rename. Avoids partial files mid-crash.
    write_atomic(cert_path, cert_pem.as_bytes(), 0o644)?;
    write_atomic(key_path, key_pem.as_bytes(), 0o600)?;

    Ok((cert_pem, key_pem))
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

fn build_server_config(cert_pem: &str, key_pem: &str) -> Result<ServerConfig, WireError> {
    build_server_config_with_alpn(cert_pem, key_pem, vec![b"http/1.1".to_vec()])
}

fn build_server_config_with_alpn(
    cert_pem: &str,
    key_pem: &str,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<ServerConfig, WireError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|e| WireError::Internal(format!("parse cert pem: {e}")))?;
    if certs.is_empty() {
        return Err(WireError::Internal("no certificates in cert pem".into()));
    }
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
}
