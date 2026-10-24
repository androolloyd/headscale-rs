use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::{fmt, io};

use http::Uri;
use hyper::rt;
use hyper_util::client::legacy::connect::Connection;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;
use tower_service::Service;

use crate::stream::MaybeHttpsStream;

pub(crate) mod builder;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A Connector for the `https` scheme.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    force_https: bool,
    http: T,
    tls_config: Arc<rustls::ClientConfig>,
    server_name_resolver: Arc<dyn ResolveServerName + Sync + Send>,
    #[cfg(feature = "go-native-http-proxy")]
    go_handshake_timeout: Option<std::time::Duration>,
    #[cfg(feature = "go-native-http-proxy")]
    go_record_eof: bool,
}

impl<T> HttpsConnector<T> {
    /// Creates a [`crate::HttpsConnectorBuilder`] to configure a `HttpsConnector`.
    ///
    /// This is the same as [`crate::HttpsConnectorBuilder::new()`].
    pub fn builder() -> builder::ConnectorBuilder<builder::WantsTlsConfig> {
        builder::ConnectorBuilder::new()
    }

    /// Creates a new `HttpsConnector`.
    ///
    /// The recommended way to create a `HttpsConnector` is to use a [`crate::HttpsConnectorBuilder`]. See [`HttpsConnector::builder()`].
    pub fn new(
        http: T,
        tls_config: impl Into<Arc<rustls::ClientConfig>>,
        force_https: bool,
        server_name_resolver: Arc<dyn ResolveServerName + Send + Sync>,
    ) -> Self {
        Self {
            http,
            tls_config: tls_config.into(),
            force_https,
            server_name_resolver,
            #[cfg(feature = "go-native-http-proxy")]
            go_handshake_timeout: None,
            #[cfg(feature = "go-native-http-proxy")]
            go_record_eof: false,
        }
    }

    /// Force the use of HTTPS when connecting.
    ///
    /// If a URL is not `https` when connecting, an error is returned.
    pub fn enforce_https(&mut self) {
        self.force_https = true;
    }

    /// Replace only the owned lower-level connector, preserving TLS policy.
    /// Used by the explicitly selected native HTTP proxy adapter.
    #[cfg(feature = "go-native-http-proxy")]
    #[doc(hidden)]
    pub fn go_map_http_connector<U>(self, map: impl FnOnce(T) -> U) -> HttpsConnector<U> {
        HttpsConnector {
            force_https: self.force_https,
            http: map(self.http),
            tls_config: self.tls_config,
            server_name_resolver: self.server_name_resolver,
            #[cfg(feature = "go-native-http-proxy")]
            go_handshake_timeout: self.go_handshake_timeout,
            #[cfg(feature = "go-native-http-proxy")]
            go_record_eof: self.go_record_eof,
        }
    }

    /// Set a timeout for TLS handshakes on explicitly native HTTP connections.
    /// The timeout begins after the lower-level connection has completed.
    #[cfg(feature = "go-native-http-proxy")]
    #[doc(hidden)]
    pub fn go_with_tls_handshake_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.go_handshake_timeout = Some(timeout);
        self
    }

    /// Select Go's record-boundary EOF handling on native TLS connections.
    #[cfg(feature = "go-native-http-proxy")]
    #[doc(hidden)]
    pub fn go_with_record_boundary_eof(mut self) -> Self {
        self.go_record_eof = true;
        self
    }
}

impl<T> Service<Uri> for HttpsConnector<T>
where
    T: Service<Uri>,
    T::Response: Connection + rt::Read + rt::Write + Send + Unpin + 'static,
    T::Future: Send + 'static,
    T::Error: Into<BoxError>,
{
    type Response = MaybeHttpsStream<T::Response>;
    type Error = BoxError;

    #[allow(clippy::type_complexity)]
    type Future =
        Pin<Box<dyn Future<Output = Result<MaybeHttpsStream<T::Response>, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.http.poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        // dst.scheme() would need to derive Eq to be matchable;
        // use an if cascade instead
        match dst.scheme() {
            Some(scheme) if scheme == &http::uri::Scheme::HTTP && !self.force_https => {
                let future = self.http.call(dst);
                return Box::pin(async move {
                    Ok(MaybeHttpsStream::Http(future.await.map_err(Into::into)?))
                });
            }
            Some(scheme) if scheme != &http::uri::Scheme::HTTPS => {
                let message = format!("unsupported scheme {scheme}");
                return Box::pin(async move { Err(io::Error::other(message).into()) });
            }
            Some(_) => {}
            None => return Box::pin(async move { Err(io::Error::other("missing scheme").into()) }),
        };

        let cfg = self.tls_config.clone();
        let hostname = match self.server_name_resolver.resolve(&dst) {
            Ok(hostname) => hostname,
            Err(e) => {
                return Box::pin(async move { Err(e) });
            }
        };

        let connecting_future = self.http.call(dst);
        #[cfg(feature = "go-native-http-proxy")]
        let handshake_timeout = self.go_handshake_timeout;
        #[cfg(feature = "go-native-http-proxy")]
        let go_record_eof = self.go_record_eof;
        Box::pin(async move {
            let tcp = connecting_future.await.map_err(Into::into)?;
            let connector = TlsConnector::from(cfg);
            let transport = TokioIo::new(tcp);
            #[cfg(feature = "go-native-http-proxy")]
            let mut eof_observer = None;
            #[cfg(feature = "go-native-http-proxy")]
            let handshake = if go_record_eof {
                connector.connect_with(hostname, transport, |connection| {
                    connection.go_record_boundary_eof(true);
                    eof_observer = Some(connection.go_record_eof_observer());
                })
            } else {
                connector.connect(hostname, transport)
            };
            #[cfg(not(feature = "go-native-http-proxy"))]
            let handshake = connector.connect(hostname, transport);
            #[cfg(feature = "go-native-http-proxy")]
            let tls = match handshake_timeout {
                Some(timeout) => tokio::time::timeout(timeout, handshake)
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "net/http: TLS handshake timeout")
                    })?,
                None => handshake.await,
            }
            .map_err(|error| {
                let close_notify_eof = go_record_eof
                    && eof_observer
                        .as_ref()
                        .is_some_and(rustls::GoClientEof::received_close_notify)
                    && error.kind() == io::ErrorKind::InvalidData
                    && error.get_ref().is_some_and(|cause| {
                        matches!(
                            cause.downcast_ref::<rustls::Error>(),
                            Some(rustls::Error::AlertReceived(
                                rustls::AlertDescription::CloseNotify
                            ))
                        )
                    });
                let error = if close_notify_eof {
                    io::Error::new(io::ErrorKind::Other, "EOF")
                } else if go_record_eof && error.kind() == io::ErrorKind::UnexpectedEof {
                    match eof_observer
                        .as_ref()
                        .and_then(rustls::GoClientEof::at_record_boundary)
                    {
                        Some(true) => io::Error::new(io::ErrorKind::Other, "EOF"),
                        Some(false) => {
                            io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
                        }
                        None => error,
                    }
                } else {
                    error
                };
                io::Error::new(io::ErrorKind::Other, error)
            })?;
            #[cfg(not(feature = "go-native-http-proxy"))]
            let tls = handshake
                .await
                .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;
            Ok(MaybeHttpsStream::Https(TokioIo::new(tls)))
        })
    }
}

impl<H, C> From<(H, C)> for HttpsConnector<H>
where
    C: Into<Arc<rustls::ClientConfig>>,
{
    fn from((http, cfg): (H, C)) -> Self {
        Self {
            force_https: false,
            http,
            tls_config: cfg.into(),
            server_name_resolver: Arc::new(DefaultServerNameResolver::default()),
            #[cfg(feature = "go-native-http-proxy")]
            go_handshake_timeout: None,
            #[cfg(feature = "go-native-http-proxy")]
            go_record_eof: false,
        }
    }
}

impl<T> fmt::Debug for HttpsConnector<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpsConnector")
            .field("force_https", &self.force_https)
            .finish()
    }
}

/// The default server name resolver, which uses the hostname in the URI.
#[derive(Default)]
pub struct DefaultServerNameResolver(());

impl ResolveServerName for DefaultServerNameResolver {
    fn resolve(
        &self,
        uri: &Uri,
    ) -> Result<ServerName<'static>, Box<dyn std::error::Error + Sync + Send>> {
        let mut hostname = uri.host().unwrap_or_default();

        // Remove square brackets around IPv6 address.
        if let Some(trimmed) = hostname.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            hostname = trimmed;
        }

        ServerName::try_from(hostname.to_string()).map_err(|e| Box::new(e) as _)
    }
}

/// A server name resolver which always returns the same fixed name.
pub struct FixedServerNameResolver {
    name: ServerName<'static>,
}

impl FixedServerNameResolver {
    /// Creates a new resolver returning the specified name.
    pub fn new(name: ServerName<'static>) -> Self {
        Self { name }
    }
}

impl ResolveServerName for FixedServerNameResolver {
    fn resolve(
        &self,
        _: &Uri,
    ) -> Result<ServerName<'static>, Box<dyn std::error::Error + Sync + Send>> {
        Ok(self.name.clone())
    }
}

impl<F, E> ResolveServerName for F
where
    F: Fn(&Uri) -> Result<ServerName<'static>, E>,
    E: Into<Box<dyn std::error::Error + Sync + Send>>,
{
    fn resolve(
        &self,
        uri: &Uri,
    ) -> Result<ServerName<'static>, Box<dyn std::error::Error + Sync + Send>> {
        self(uri).map_err(Into::into)
    }
}

/// A trait implemented by types that can resolve a [`ServerName`] for a request.
pub trait ResolveServerName {
    /// Maps a [`Uri`] into a [`ServerName`].
    fn resolve(
        &self,
        uri: &Uri,
    ) -> Result<ServerName<'static>, Box<dyn std::error::Error + Sync + Send>>;
}

#[cfg(all(
    test,
    any(feature = "ring", feature = "aws-lc-rs"),
    any(
        feature = "rustls-native-certs",
        feature = "webpki-roots",
        feature = "rustls-platform-verifier",
    )
))]
mod tests {
    use std::future::poll_fn;

    use http::Uri;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpStream;
    use tower_service::Service;

    use super::*;
    use crate::{ConfigBuilderExt, HttpsConnectorBuilder, MaybeHttpsStream};

    #[tokio::test]
    async fn connects_https() {
        connect(Allow::Any, Scheme::Https).await.unwrap();
    }

    #[tokio::test]
    async fn connects_http() {
        connect(Allow::Any, Scheme::Http).await.unwrap();
    }

    #[tokio::test]
    async fn connects_https_only() {
        connect(Allow::Https, Scheme::Https).await.unwrap();
    }

    #[tokio::test]
    async fn enforces_https_only() {
        let message = connect(Allow::Https, Scheme::Http)
            .await
            .unwrap_err()
            .to_string();

        assert_eq!(message, "unsupported scheme http");
    }

    async fn connect(
        allow: Allow,
        scheme: Scheme,
    ) -> Result<MaybeHttpsStream<TokioIo<TcpStream>>, BoxError> {
        let config_builder = rustls::ClientConfig::builder();
        cfg_if::cfg_if! {
            if #[cfg(feature = "rustls-platform-verifier")] {
                let config_builder = config_builder.try_with_platform_verifier()?;
            } else if #[cfg(feature = "rustls-native-certs")] {
                let config_builder = config_builder.with_native_roots().unwrap();
            } else if #[cfg(feature = "webpki-roots")] {
                let config_builder = config_builder.with_webpki_roots();
            }
        }
        let config = config_builder.with_no_client_auth();

        let builder = HttpsConnectorBuilder::new().with_tls_config(config);
        let mut service = match allow {
            Allow::Https => builder.https_only(),
            Allow::Any => builder.https_or_http(),
        }
        .enable_http1()
        .build();

        poll_fn(|cx| service.poll_ready(cx)).await?;
        service
            .call(Uri::from_static(match scheme {
                Scheme::Https => "https://google.com",
                Scheme::Http => "http://google.com",
            }))
            .await
    }

    enum Allow {
        Https,
        Any,
    }

    enum Scheme {
        Https,
        Http,
    }
}
