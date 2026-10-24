#![allow(dead_code)]

use std::path::PathBuf;

use crate::error::Error;
use crate::net::socket::WithSocket;
use crate::net::Socket;

#[cfg(feature = "_tls-rustls")]
mod tls_rustls;

#[cfg(feature = "_tls-native-tls")]
mod tls_native_tls;

#[cfg(feature = "go-pem-compat")]
mod go_pem;
mod util;

/// X.509 Certificate input, either a file path or a PEM encoded inline certificate(s).
#[derive(Clone)]
pub enum CertificateInput {
    /// PEM encoded certificate(s)
    Inline(Vec<u8>),
    /// Path to a file containing PEM encoded certificate(s)
    File(PathBuf),
    /// A root CA file that replaces built-in trust anchors for this handshake.
    /// The native headscale-go bridge uses pgx's configured-root semantics.
    ExclusiveFile(PathBuf),
    /// OS trust anchors selected explicitly by the native pgx bridge.
    System,
    /// Immutable in-memory material used by the native configuration snapshot.
    SharedInline(std::sync::Arc<[u8]>),
    /// Validated configured-only CA snapshot.
    ExclusiveInline(std::sync::Arc<[u8]>),
}

impl std::fmt::Debug for CertificateInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inline(_) | Self::SharedInline(_) => f.write_str("Inline(<redacted>)"),
            Self::ExclusiveInline(_) => f.write_str("ExclusiveInline(<redacted>)"),
            Self::File(path) => f.debug_tuple("File").field(path).finish(),
            Self::ExclusiveFile(path) => f.debug_tuple("ExclusiveFile").field(path).finish(),
            Self::System => f.write_str("System"),
        }
    }
}

impl From<String> for CertificateInput {
    fn from(value: String) -> Self {
        // Leading and trailing whitespace/newlines
        let trimmed = value.trim();

        // Heuristic for PEM encoded inputs:
        // https://tools.ietf.org/html/rfc7468
        if trimmed.starts_with("-----BEGIN") && trimmed.ends_with("-----") {
            CertificateInput::Inline(value.as_bytes().to_vec())
        } else {
            CertificateInput::File(PathBuf::from(value))
        }
    }
}

impl CertificateInput {
    async fn data(&self) -> Result<Vec<u8>, std::io::Error> {
        use crate::fs;
        match self {
            CertificateInput::Inline(v) => Ok(v.clone()),
            CertificateInput::SharedInline(v) | CertificateInput::ExclusiveInline(v) => {
                Ok(v.to_vec())
            }
            CertificateInput::File(path) | CertificateInput::ExclusiveFile(path) => {
                fs::read(path).await
            }
            CertificateInput::System => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "system roots are loaded by the TLS backend",
            )),
        }
    }
}

impl std::fmt::Display for CertificateInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertificateInput::Inline(_)
            | CertificateInput::SharedInline(_)
            | CertificateInput::ExclusiveInline(_) => {
                f.write_str("inline certificate material (<redacted>)")
            }
            CertificateInput::File(path) | CertificateInput::ExclusiveFile(path) => {
                write!(f, "file: {}", path.display())
            }
            CertificateInput::System => f.write_str("system certificates"),
        }
    }
}

/// Validate/canonicalize configured CA material before a native connection
/// attempt. Ordinary SQLx constructors continue loading their existing inputs.
pub fn prepare_headscale_go_ca(data: &[u8]) -> crate::Result<Vec<u8>> {
    #[cfg(feature = "_tls-rustls")]
    {
        tls_rustls::prepare_go_ca(data)
    }
    #[cfg(not(feature = "_tls-rustls"))]
    {
        let _ = data;
        Err(Error::tls("native Go TLS preflight requires Rustls"))
    }
}

/// Parse and check a client key/certificate pair without network I/O.
pub fn prepare_headscale_go_client(cert: &[u8], key: &[u8]) -> crate::Result<(Vec<u8>, Vec<u8>)> {
    #[cfg(feature = "_tls-rustls")]
    {
        tls_rustls::prepare_go_client(cert, key)
    }
    #[cfg(not(feature = "_tls-rustls"))]
    {
        let _ = (cert, key);
        Err(Error::tls("native Go TLS preflight requires Rustls"))
    }
}

/// Native Go key loaders identify a private-key PEM label, then infer the
/// actual PKCS#1/PKCS#8/SEC1 format from its DER rather than trusting the label.
pub fn prepare_headscale_go_client_der(
    cert: &[u8],
    key: &[u8],
) -> crate::Result<(Vec<u8>, Vec<u8>)> {
    #[cfg(feature = "_tls-rustls")]
    {
        tls_rustls::prepare_go_client_der(cert, key)
    }
    #[cfg(not(feature = "_tls-rustls"))]
    {
        let _ = (cert, key);
        Err(Error::tls("native Go TLS preflight requires Rustls"))
    }
}

/// Decrypt an operator-configured legacy RFC 1423 PEM block. This is not a
/// TLS cipher selector; the native bridge invokes it before any dialing.
pub fn decrypt_headscale_go_pem(
    algorithm: &str,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> crate::Result<Vec<u8>> {
    #[cfg(feature = "go-pem-compat")]
    {
        go_pem::decrypt(algorithm, key, iv, ciphertext)
    }
    #[cfg(not(feature = "go-pem-compat"))]
    {
        let _ = (algorithm, key, iv, ciphertext);
        Err(Error::tls("native Go encrypted PEM requires go-pem-compat"))
    }
}

pub struct TlsConfig<'a> {
    pub accept_invalid_certs: bool,
    pub accept_invalid_hostnames: bool,
    pub hostname: &'a str,
    pub root_cert_path: Option<&'a CertificateInput>,
    pub client_cert_path: Option<&'a CertificateInput>,
    pub client_key_path: Option<&'a CertificateInput>,
}

pub async fn handshake<S, Ws>(
    socket: S,
    config: TlsConfig<'_>,
    with_socket: Ws,
) -> crate::Result<Ws::Output>
where
    S: Socket,
    Ws: WithSocket,
{
    #[cfg(feature = "_tls-native-tls")]
    return Ok(with_socket
        .with_socket(tls_native_tls::handshake(socket, config).await?)
        .await);

    #[cfg(all(feature = "_tls-rustls", not(feature = "_tls-native-tls")))]
    return Ok(with_socket
        .with_socket(tls_rustls::handshake(socket, config).await?)
        .await);

    #[cfg(not(any(feature = "_tls-native-tls", feature = "_tls-rustls")))]
    {
        drop((socket, config, with_socket));
        panic!("one of the `runtime-*-native-tls` or `runtime-*-rustls` features must be enabled")
    }
}

/// Native pgx bridge: use the same Rustls backend as configuration preflight,
/// even if another SQLx consumer also enables native-tls. SNI suppression
/// does not disable certificate hostname verification.
pub async fn handshake_headscale_go<S, Ws>(
    socket: S,
    config: TlsConfig<'_>,
    with_socket: Ws,
    enable_sni: bool,
    direct: bool,
) -> crate::Result<Ws::Output>
where
    S: Socket,
    Ws: WithSocket,
{
    #[cfg(feature = "_tls-rustls")]
    {
        let socket = tls_rustls::handshake_options(socket, config, enable_sni, direct).await?;
        Ok(with_socket.with_socket(socket).await)
    }
    #[cfg(not(feature = "_tls-rustls"))]
    {
        let _ = (socket, config, with_socket, enable_sni, direct);
        Err(Error::tls("native Go TLS handshake requires Rustls"))
    }
}

pub fn available() -> bool {
    cfg!(any(feature = "_tls-native-tls", feature = "_tls-rustls"))
}

pub fn error_if_unavailable() -> crate::Result<()> {
    if !available() {
        return Err(Error::tls(
            "TLS upgrade required by connect options \
                    but SQLx was built without TLS support enabled",
        ));
    }

    Ok(())
}
