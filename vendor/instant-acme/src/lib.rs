//! Async pure-Rust ACME (RFC 8555) client.

#![warn(missing_docs)]
#![cfg_attr(instant_acme_docsrs, feature(doc_cfg))]

use std::convert::Infallible;
use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use http::header::{CONTENT_TYPE, RETRY_AFTER, USER_AGENT};
use http::{Method, Request, Response, StatusCode};
use http_body::{Frame, SizeHint};
use http_body_util::BodyExt;
use httpdate::HttpDate;
#[cfg(feature = "hyper-rustls")]
use hyper::body::Incoming;
#[cfg(feature = "hyper-rustls")]
use hyper_rustls::HttpsConnectorBuilder;
#[cfg(feature = "hyper-rustls")]
use hyper_rustls::builderstates::WantsSchemes;
#[cfg(feature = "hyper-rustls")]
use hyper_util::client::legacy::Client as HyperClient;
#[cfg(feature = "hyper-rustls")]
use hyper_util::client::legacy::connect::{Connect, HttpConnector};
#[cfg(feature = "hyper-rustls")]
use hyper_util::rt::TokioExecutor;
use serde::Serialize;

mod account;
pub use account::Key;
pub use account::{Account, AccountBuilder, ExternalAccountKey};
#[cfg(feature = "go-native-client")]
mod go_native;
#[cfg(all(feature = "go-native-client", feature = "hyper-rustls"))]
#[doc(hidden)]
pub use go_native::transport::go_http_get;
#[cfg(feature = "go-native-client")]
#[doc(hidden)]
pub use go_native::transport::{NativeHttpObserver, go_is_oidc_issuer_url, go_parse_url};
mod order;
#[cfg(feature = "go-native-client")]
pub use go_native::{
    NativeAccountKey, NativeAuthorization, NativeChallenge, NativeIdentifier, NativeNewOrder,
    NativeOrderResource, NativePoll, NativeProblem, NativeResponseError, NativeResponseSubproblem,
    NativeSubproblem,
};
pub use order::{
    AuthorizationHandle, Authorizations, ChallengeHandle, Identifiers, KeyAuthorization, Order,
    RetryPolicy,
};
mod types;
pub use types::{
    AccountCredentials, Authorization, AuthorizationState, AuthorizationStatus,
    AuthorizedIdentifier, CertificateIdentifier, Challenge, ChallengeStatus, ChallengeType,
    DeviceAttestation, Error, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderState,
    OrderStatus, Problem, ProfileMeta, RevocationReason, RevocationRequest, Subproblem, ZeroSsl,
};
use types::{Directory, JoseJson, Signer};
#[cfg(feature = "time")]
pub use types::{RenewalInfo, SuggestedWindow};

struct Client {
    http: Box<dyn HttpClient>,
    directory: Directory,
    directory_url: Option<String>,
    #[cfg(feature = "go-native-client")]
    go_native: Option<go_native::account_client::NativeClientState>,
}

impl Client {
    async fn new(directory_url: String, http: Box<dyn HttpClient>) -> Result<Self, Error> {
        let request = Request::builder()
            .uri(&directory_url)
            .header(USER_AGENT, CRATE_USER_AGENT)
            .body(BodyWrapper::default())
            .expect("infallible error should not occur");
        let rsp = http.request(request).await?;
        let body = rsp.body().await.map_err(Error::Other)?;
        Ok(Self {
            http,
            directory: serde_json::from_slice(&body)?,
            directory_url: Some(directory_url),
            #[cfg(feature = "go-native-client")]
            go_native: None,
        })
    }

    async fn post(
        &self,
        payload: Option<&impl Serialize>,
        mut nonce: Option<String>,
        signer: &impl Signer,
        url: &str,
    ) -> Result<BytesResponse, Error> {
        let mut retries = 3;
        loop {
            let mut response = self
                .post_attempt(payload, nonce.clone(), signer, url)
                .await?;
            if response.parts.status != StatusCode::BAD_REQUEST {
                return Ok(response);
            }
            let body = response.body.into_bytes().await.map_err(Error::Other)?;
            let problem = serde_json::from_slice::<Problem>(&body)?;
            if let Some("urn:ietf:params:acme:error:badNonce") = problem.r#type.as_deref() {
                retries -= 1;
                if retries != 0 {
                    // Retrieve the new nonce. If it isn't there (it
                    // should be, the spec requires it) then we will
                    // manually refresh a new one in `post_attempt`
                    // due to `nonce` being `None` but getting it from
                    // the response saves us making that request.
                    nonce = nonce_from_response(&response);
                    continue;
                }
            }

            return Ok(BytesResponse {
                parts: response.parts,
                body: Box::new(body),
            });
        }
    }

    async fn post_attempt(
        &self,
        payload: Option<&impl Serialize>,
        nonce: Option<String>,
        signer: &impl Signer,
        url: &str,
    ) -> Result<BytesResponse, Error> {
        let nonce = self.nonce(nonce).await?;
        let body = JoseJson::new(payload, signer.header(Some(&nonce), url), signer)?;
        let request = Request::builder()
            .method(Method::POST)
            .uri(url)
            .header(USER_AGENT, CRATE_USER_AGENT)
            .header(CONTENT_TYPE, JOSE_JSON)
            .body(BodyWrapper::from(serde_json::to_vec(&body)?))?;

        self.http.request(request).await
    }

    async fn nonce(&self, nonce: Option<String>) -> Result<String, Error> {
        if let Some(nonce) = nonce {
            return Ok(nonce);
        }

        let request = Request::builder()
            .method(Method::HEAD)
            .uri(&self.directory.new_nonce)
            .header(USER_AGENT, CRATE_USER_AGENT)
            .body(BodyWrapper::default())
            .expect("infallible error should not occur");

        let rsp = self.http.request(request).await?;
        // https://datatracker.ietf.org/doc/html/rfc8555#section-7.2
        // "The server's response MUST include a Replay-Nonce header field containing a fresh
        // nonce and SHOULD have status code 200 (OK)."
        if rsp.parts.status != StatusCode::OK {
            return Err("error response from newNonce resource".into());
        }

        match nonce_from_response(&rsp) {
            Some(nonce) => Ok(nonce),
            None => Err("no nonce found in newNonce response".into()),
        }
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("client", &"..")
            .field("directory", &self.directory)
            .finish()
    }
}

fn nonce_from_response(rsp: &BytesResponse) -> Option<String> {
    rsp.parts
        .headers
        .get(REPLAY_NONCE)
        .and_then(|hv| String::from_utf8(hv.as_ref().to_vec()).ok())
}

/// Parse the `Retry-After` header from the response
///
/// <https://httpwg.org/specs/rfc9110.html#field.retry-after>
///
/// # Syntax
///
/// Retry-After = HTTP-date / delay-seconds
/// delay-seconds  = 1*DIGIT
fn retry_after(rsp: &BytesResponse) -> Option<SystemTime> {
    let value = rsp.parts.headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    if value.is_empty() {
        return None;
    }

    Some(match u64::from_str(value) {
        // `delay-seconds` is a number of seconds to wait
        Ok(secs) => SystemTime::now() + Duration::from_secs(secs),
        // `HTTP-date` looks like `Fri, 31 Dec 1999 23:59:59 GMT`
        Err(_) => SystemTime::from(HttpDate::from_str(value).ok()?),
    })
}

#[cfg(feature = "hyper-rustls")]
struct DefaultClient(
    HyperClient<hyper_rustls::HttpsConnector<HttpConnector>, BodyWrapper<Bytes>>,
    #[cfg(feature = "go-native-client")] NativeTransport,
);

#[cfg(all(feature = "hyper-rustls", feature = "go-native-client"))]
type NativeConnector = hyper_rustls::HttpsConnector<go_native::transport::proxy::ProxyConnector>;

#[cfg(all(feature = "hyper-rustls", feature = "go-native-client"))]
type NativeHttpClient = HyperClient<NativeConnector, BodyWrapper<Bytes>>;

#[cfg(all(feature = "hyper-rustls", feature = "go-native-client"))]
#[derive(Clone)]
enum NativeTransport {
    SharedDefault(NativeConnector),
    Isolated(NativeHttpClient),
}

#[cfg(all(feature = "hyper-rustls", feature = "go-native-client"))]
fn native_http_client(connector: NativeConnector) -> NativeHttpClient {
    HyperClient::builder(TokioExecutor::new())
        .http1_max_buf_size(10 << 20)
        // Even an empty-value one-byte header needs four wire bytes.
        // Scratch allocation is bounded by the received line count in Hyper.
        .http1_max_headers((10 << 20) / 4)
        .http1_allow_obsolete_multiline_headers_in_responses(true)
        .http2_max_header_list_size(10 << 20)
        .pool_max_idle_per_host(2)
        .go_pool_max_idle_total(100)
        .go_native_idle_timeout(Duration::from_secs(90))
        .go_reset_ping_payload(native_reset_ping_payload)
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_timer(hyper_util::rt::TokioTimer::new())
        .build(connector)
}

#[cfg(all(feature = "hyper-rustls", feature = "go-native-client"))]
fn native_reset_ping_payload() -> [u8; 8] {
    let mut payload = [0; 8];
    // Constructing the TLS connector installs its crypto provider before the
    // native HTTP client. Go's writeStreamReset also ignores rand.Read's error.
    let provider = rustls::crypto::CryptoProvider::get_default()
        .expect("TLS provider initialized before native HTTP client");
    let _ = provider.secure_random.fill(&mut payload);
    payload
}

#[cfg(all(feature = "hyper-rustls", feature = "go-native-client"))]
struct NativePoolEntry {
    client: NativeHttpClient,
    lifetime: std::sync::Arc<()>,
}

#[cfg(all(feature = "hyper-rustls", feature = "go-native-client"))]
type NativePools = std::sync::Mutex<std::collections::HashMap<tokio::runtime::Id, NativePoolEntry>>;

#[cfg(all(feature = "hyper-rustls", feature = "go-native-client"))]
fn native_pools() -> &'static NativePools {
    static POOLS: std::sync::OnceLock<NativePools> = std::sync::OnceLock::new();
    POOLS.get_or_init(NativePools::default)
}

#[cfg(all(feature = "hyper-rustls", feature = "go-native-client"))]
struct NativePoolLifetime {
    runtime: tokio::runtime::Id,
    lifetime: std::sync::Arc<()>,
}

#[cfg(all(feature = "hyper-rustls", feature = "go-native-client"))]
impl Drop for NativePoolLifetime {
    fn drop(&mut self) {
        let removed = {
            let mut pools = native_pools()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if pools
                .get(&self.runtime)
                .is_some_and(|entry| std::sync::Arc::ptr_eq(&entry.lifetime, &self.lifetime))
            {
                pools.remove(&self.runtime)
            } else {
                None
            }
        };
        // Drop the client and its idle-task notifier outside the registry lock.
        drop(removed);
    }
}

#[cfg(all(feature = "hyper-rustls", feature = "go-native-client"))]
fn shared_native_http_client(connector: NativeConnector) -> Result<NativeHttpClient, Error> {
    // Go's nil Client.HTTPClient uses the process default transport. Tokio's
    // drivers and idle-task sleeps belong to their runtime, so share defaults
    // across native accounts within each runtime rather than reuse an open but
    // undriven connection from another live current-thread runtime.
    // Construction outside a runtime remains valid: this runs on the first
    // poll of go_request, not Account::builder or the synchronous request hook.
    let handle =
        tokio::runtime::Handle::try_current().map_err(|error| Error::Other(Box::new(error)))?;
    let runtime = handle.id();
    let (client, lifetime) = {
        let mut pools = native_pools()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(entry) = pools.get(&runtime) {
            return Ok(entry.client.clone());
        }
        let client = native_http_client(connector);
        let lifetime = std::sync::Arc::new(());
        pools.insert(
            runtime,
            NativePoolEntry {
                client: client.clone(),
                lifetime: lifetime.clone(),
            },
        );
        (client, NativePoolLifetime { runtime, lifetime })
    };
    // Construct the guard before spawning, so even a task that is never polled
    // removes its entry when the owning runtime shuts down. No Handle is stored
    // in the process registry, and cleanup matches the entry's generation.
    // Release the mutex first: shutdown can drop a newly spawned task at once.
    drop(handle.spawn(async move {
        let _lifetime = lifetime;
        std::future::pending::<()>().await;
    }));
    Ok(client)
}

#[cfg(feature = "hyper-rustls")]
impl DefaultClient {
    fn try_new() -> Result<Self, Error> {
        Ok(Self::new(
            HttpsConnectorBuilder::new()
                .try_with_platform_verifier()
                .map_err(|e| Error::Other(Box::new(e)))?,
            true,
        ))
    }

    fn with_roots(roots: rustls::RootCertStore) -> Result<Self, Error> {
        Ok(Self::new(
            HttpsConnectorBuilder::new().with_tls_config(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            ),
            false,
        ))
    }

    fn new(builder: HttpsConnectorBuilder<WantsSchemes>, shared_native: bool) -> Self {
        #[cfg(not(feature = "go-native-client"))]
        let _ = shared_native;
        let connector = builder
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let mut https_only = connector.clone();
        https_only.enforce_https();
        #[cfg(feature = "go-native-client")]
        let native_connector = {
            let proxy_tls = connector
                .clone()
                .go_with_tls_handshake_timeout(Duration::from_secs(10))
                .go_with_record_boundary_eof();
            connector
                .go_map_http_connector(|http| {
                    go_native::transport::proxy::ProxyConnector::new(http, proxy_tls)
                })
                .go_with_tls_handshake_timeout(Duration::from_secs(10))
                .go_with_record_boundary_eof()
        };
        Self(
            HyperClient::builder(TokioExecutor::new()).build(https_only),
            #[cfg(feature = "go-native-client")]
            if shared_native {
                NativeTransport::SharedDefault(native_connector)
            } else {
                NativeTransport::Isolated(native_http_client(native_connector))
            },
        )
    }
}

#[cfg(feature = "hyper-rustls")]
impl HttpClient for DefaultClient {
    fn request(
        &self,
        req: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>> {
        let fut = self.0.request(req);
        Box::pin(async move { BytesResponse::try_from(fut.await) })
    }

    #[cfg(feature = "go-native-client")]
    fn go_request(
        &self,
        req: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>> {
        let transport = self.1.clone();
        Box::pin(async move {
            let client = match transport {
                NativeTransport::SharedDefault(connector) => shared_native_http_client(connector)?,
                NativeTransport::Isolated(client) => client,
            };
            go_native::transport::request(client, req).await
        })
    }
}

/// A HTTP client abstraction
pub trait HttpClient: Send + Sync + 'static {
    /// Send the given request and return the response
    fn request(
        &self,
        req: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>>;

    /// Send an explicitly native request. External clients retain their
    /// configured transport policy unless they override this additive hook.
    /// The selected built-in client follows native HTTP redirect behavior.
    #[cfg(feature = "go-native-client")]
    fn go_request(
        &self,
        req: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>> {
        self.request(req)
    }

    /// Observe a native transport rejection before backend URI construction.
    /// Ordinary/custom clients retain their existing policy by default.
    #[cfg(feature = "go-native-client")]
    #[doc(hidden)]
    fn go_transport_error(&self, _url: &str, _error: &str) {}
}

#[cfg(feature = "hyper-rustls")]
impl<C: Connect + Clone + Send + Sync + 'static> HttpClient for HyperClient<C, BodyWrapper<Bytes>> {
    fn request(
        &self,
        req: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>> {
        let fut = self.request(req);
        Box::pin(async move { BytesResponse::try_from(fut.await) })
    }
}

/// Response with object safe body type
pub struct BytesResponse {
    /// Response status and header
    pub parts: http::response::Parts,
    /// Response body
    pub body: Box<dyn BytesBody>,
}

impl BytesResponse {
    #[cfg(feature = "hyper-rustls")]
    fn try_from(
        result: Result<Response<Incoming>, hyper_util::client::legacy::Error>,
    ) -> Result<Self, Error> {
        match result {
            Ok(rsp) => Ok(Self::from(rsp)),
            Err(e) => Err(Error::Other(Box::new(e))),
        }
    }

    pub(crate) async fn body(mut self) -> Result<Bytes, Box<dyn StdError + Send + Sync + 'static>> {
        self.body.into_bytes().await
    }
}

impl<B> From<Response<B>> for BytesResponse
where
    B: http_body::Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn StdError + Send + Sync + 'static>>,
{
    fn from(rsp: Response<B>) -> Self {
        let (parts, body) = rsp.into_parts();
        Self {
            parts,
            body: Box::new(BodyWrapper { inner: Some(body) }),
        }
    }
}

/// A simple HTTP body wrapper type
#[derive(Default)]
pub struct BodyWrapper<B> {
    inner: Option<B>,
}

#[async_trait]
impl<B> BytesBody for BodyWrapper<B>
where
    B: http_body::Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn StdError + Send + Sync + 'static>>,
{
    async fn into_bytes(&mut self) -> Result<Bytes, Box<dyn StdError + Send + Sync + 'static>> {
        let Some(body) = self.inner.take() else {
            return Ok(Bytes::new());
        };

        match body.collect().await {
            Ok(body) => Ok(body.to_bytes()),
            Err(e) => Err(e.into()),
        }
    }

    #[cfg(feature = "go-native-client")]
    async fn into_bytes_limited(
        &mut self,
        limit: usize,
    ) -> Result<Bytes, Box<dyn StdError + Send + Sync + 'static>> {
        let Some(mut body) = self.inner.take() else {
            return Ok(Bytes::new());
        };
        let mut output = Vec::with_capacity(limit.min(16 * 1024));
        while output.len() < limit {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(mut data) = frame.into_data() {
                        let take = data.remaining().min(limit - output.len());
                        output.extend_from_slice(&data.copy_to_bytes(take));
                    }
                }
                Some(Err(error)) => return Err(error.into()),
                None => break,
            }
        }
        Ok(Bytes::from(output))
    }

    #[cfg(feature = "go-native-client")]
    async fn into_first_json_value(
        &mut self,
    ) -> Result<Bytes, Box<dyn StdError + Send + Sync + 'static>> {
        let Some(mut body) = self.inner.take() else {
            return Ok(Bytes::new());
        };
        let mut scanner = go_native::json_prefix::Scanner::new();
        let mut output = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = match frame {
                Ok(frame) => frame,
                Err(error) => return Err(error.into()),
            };
            if let Ok(mut data) = frame.into_data() {
                while data.has_remaining() {
                    let chunk = data.chunk();
                    if let Some(length) = scanner.feed(chunk) {
                        output.extend_from_slice(&chunk[..length]);
                        return Ok(Bytes::from(output));
                    }
                    let length = chunk.len();
                    output.extend_from_slice(chunk);
                    data.advance(length);
                }
            }
        }
        // EOF completes scalar roots; truncated values remain typed decode
        // errors. A non-EOF body error above is never treated as a delimiter.
        Ok(Bytes::from(output))
    }

    #[cfg(feature = "go-native-client")]
    async fn into_bytes_partial(&mut self) -> Bytes {
        let Some(mut body) = self.inner.take() else {
            return Bytes::new();
        };
        let mut output = Vec::new();
        while let Some(frame) = body.frame().await {
            let Ok(frame) = frame else {
                break;
            };
            if let Ok(mut data) = frame.into_data() {
                while data.has_remaining() {
                    let chunk = data.chunk();
                    let length = chunk.len();
                    output.extend_from_slice(chunk);
                    data.advance(length);
                }
            }
        }
        Bytes::from(output)
    }
}

impl http_body::Body for BodyWrapper<Bytes> {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.inner.take().map(|d| Ok(Frame::data(d))))
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        match self.inner.as_ref() {
            Some(data) => SizeHint::with_exact(u64::try_from(data.remaining()).unwrap()),
            None => SizeHint::with_exact(0),
        }
    }
}

impl From<Vec<u8>> for BodyWrapper<Bytes> {
    fn from(data: Vec<u8>) -> Self {
        Self {
            inner: Some(Bytes::from(data)),
        }
    }
}

#[async_trait]
impl BytesBody for Bytes {
    async fn into_bytes(&mut self) -> Result<Self, Box<dyn StdError + Send + Sync + 'static>> {
        Ok(self.to_owned())
    }

    #[cfg(feature = "go-native-client")]
    async fn into_bytes_limited(
        &mut self,
        limit: usize,
    ) -> Result<Bytes, Box<dyn StdError + Send + Sync + 'static>> {
        Ok(self.slice(..self.len().min(limit)))
    }
}

/// Object safe body trait
#[async_trait]
pub trait BytesBody: Send {
    /// Convert the body into [`Bytes`]
    ///
    /// This consumes the body. The behavior for calling this method multiple times is undefined.
    #[allow(clippy::wrong_self_convention)] // async_trait doesn't support taking `self`
    async fn into_bytes(&mut self) -> Result<Bytes, Box<dyn StdError + Send + Sync + 'static>>;

    /// Read at most `limit` bytes for native certificate downloads.
    /// The default preserves external body implementations; selected streaming
    /// HTTP bodies override it to stop reading and retain only this prefix.
    #[cfg(feature = "go-native-client")]
    #[allow(clippy::wrong_self_convention)]
    async fn into_bytes_limited(
        &mut self,
        limit: usize,
    ) -> Result<Bytes, Box<dyn StdError + Send + Sync + 'static>> {
        let bytes = self.into_bytes().await?;
        Ok(bytes.slice(..bytes.len().min(limit)))
    }

    /// Discard a native redirect prefix using CopyN's requested read sizes.
    /// Custom bodies retain their existing limited-read fallback.
    #[cfg(feature = "go-native-client")]
    async fn discard_bytes_limited(
        &mut self,
        limit: usize,
    ) -> Result<(), Box<dyn StdError + Send + Sync + 'static>> {
        self.into_bytes_limited(limit).await.map(|_| ())
    }

    /// Finish native transport body cleanup; custom bodies keep their fallback.
    #[cfg(feature = "go-native-client")]
    async fn close_native(&mut self) -> Result<(), Box<dyn StdError + Send + Sync + 'static>> {
        Ok(())
    }

    /// Read the first native JSON value without waiting for a body suffix.
    /// The default retains compatibility for custom body implementations and
    /// may collect their whole body. The selected streaming wrapper overrides
    /// it with incremental first-value framing and no arbitrary byte-size cap.
    #[cfg(feature = "go-native-client")]
    #[allow(clippy::wrong_self_convention)]
    async fn into_first_json_value(
        &mut self,
    ) -> Result<Bytes, Box<dyn StdError + Send + Sync + 'static>> {
        self.into_bytes().await
    }

    /// Native HTTP error-body ReadAll, retaining received bytes on read error.
    /// Custom implementations retain their historical whole-body fallback;
    /// selected streaming bodies preserve the prefix even when reads fail.
    #[cfg(feature = "go-native-client")]
    #[allow(clippy::wrong_self_convention)]
    async fn into_bytes_partial(&mut self) -> Bytes {
        self.into_bytes().await.unwrap_or_default()
    }
}

mod crypto {
    #[cfg(feature = "aws-lc-rs")]
    pub(crate) use aws_lc_rs as ring_like;
    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    pub(crate) use ring as ring_like;

    pub(crate) use ring_like::digest::{Digest, SHA256, digest};
    pub(crate) use ring_like::hmac;
    pub(crate) use ring_like::rand::SystemRandom;
    pub(crate) use ring_like::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
    pub(crate) use ring_like::signature::{KeyPair, Signature};

    use super::Error;

    #[cfg(feature = "aws-lc-rs")]
    pub(crate) fn p256_key_pair_from_pkcs8(
        pkcs8: &[u8],
        _: &SystemRandom,
    ) -> Result<EcdsaKeyPair, Error> {
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8)
            .map_err(|_| Error::KeyRejected)
    }

    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    pub(crate) fn p256_key_pair_from_pkcs8(
        pkcs8: &[u8],
        rng: &SystemRandom,
    ) -> Result<EcdsaKeyPair, Error> {
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, rng)
            .map_err(|_| Error::KeyRejected)
    }
}

const CRATE_USER_AGENT: &str = concat!("instant-acme/", env!("CARGO_PKG_VERSION"));
const JOSE_JSON: &str = "application/jose+json";
const REPLAY_NONCE: &str = "Replay-Nonce";

#[cfg(all(test, feature = "hyper-rustls"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn deserialize_old_credentials() -> Result<(), Error> {
        const CREDENTIALS: &str = r#"{"id":"id","key_pkcs8":"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJVWC_QzOTCS5vtsJp2IG-UDc8cdDfeoKtxSZxaznM-mhRANCAAQenCPoGgPFTdPJ7VLLKt56RxPlYT1wNXnHc54PEyBg3LxKaH0-sJkX0mL8LyPEdsfL_Oz4TxHkWLJGrXVtNhfH","urls":{"newNonce":"new-nonce","newAccount":"new-acct","newOrder":"new-order", "revokeCert": "revoke-cert"}}"#;
        Account::builder()?
            .from_credentials(serde_json::from_str::<AccountCredentials>(CREDENTIALS)?)
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn deserialize_new_credentials() -> Result<(), Error> {
        const CREDENTIALS: &str = r#"{"id":"id","key_pkcs8":"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJVWC_QzOTCS5vtsJp2IG-UDc8cdDfeoKtxSZxaznM-mhRANCAAQenCPoGgPFTdPJ7VLLKt56RxPlYT1wNXnHc54PEyBg3LxKaH0-sJkX0mL8LyPEdsfL_Oz4TxHkWLJGrXVtNhfH","directory":"https://acme-staging-v02.api.letsencrypt.org/directory"}"#;
        Account::builder()?
            .from_credentials(serde_json::from_str::<AccountCredentials>(CREDENTIALS)?)
            .await?;
        Ok(())
    }
}
