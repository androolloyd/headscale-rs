// Copyright 2009, 2011 The Go Authors. All rights reserved.
// Native no-Jar redirects follow Go 1.26.9 net/http/client.go; see LICENSE-GO.

use http::Uri;

use super::native_error;
use crate::Error;

#[cfg(feature = "hyper-rustls")]
mod gzip;
#[cfg(feature = "hyper-rustls")]
pub(crate) mod proxy;
mod url;

/// Observer for selected native per-attempt ACME transport failures.
#[doc(hidden)]
pub trait NativeHttpObserver: Send + Sync + 'static {
    fn transport_error(&self, url: &str, error: &str);
    fn response_error(&self, url: &str, status: u16, body: &[u8]);
}

#[derive(Clone)]
struct RequestObserver(std::sync::Arc<dyn NativeHttpObserver>);

pub(crate) struct ObservedClient {
    pub(crate) inner: Box<dyn crate::HttpClient>,
    pub(crate) observer: std::sync::Arc<dyn NativeHttpObserver>,
}

impl crate::HttpClient for ObservedClient {
    fn request(
        &self,
        request: http::Request<crate::BodyWrapper<bytes::Bytes>>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<crate::BytesResponse, Error>> + Send>,
    > {
        self.inner.request(request)
    }

    fn go_request(
        &self,
        mut request: http::Request<crate::BodyWrapper<bytes::Bytes>>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<crate::BytesResponse, Error>> + Send>,
    > {
        if request.extensions().get::<RequestObserver>().is_none() {
            request
                .extensions_mut()
                .insert(RequestObserver(self.observer.clone()));
        }
        self.inner.go_request(request)
    }

    fn go_transport_error(&self, url: &str, error: &str) {
        self.observer.transport_error(url, error);
    }
}

/// Original Go URL metadata, before the backend URI projection removes auth
/// and fragments. Stored in native requests; never changes SDK request paths.
#[derive(Clone)]
pub(crate) struct RequestUrl(url::Url);

/// Parse and render a URL using the selected native Go URL grammar.
#[doc(hidden)]
pub fn go_parse_url(raw: &str) -> Result<String, Error> {
    String::from_utf8(url::Url::parse(raw)?.as_bytes())
        .map_err(|error| native_error(format!("native URL string: {error}")))
}

/// Validate the native OIDC issuer URL without WHATWG input normalization.
#[doc(hidden)]
pub fn go_is_oidc_issuer_url(raw: &str) -> bool {
    url::Url::parse(raw)
        .is_ok_and(|url| matches!(url.scheme(), "http" | "https") && !url.host().is_empty())
}

/// Selected native GET/ReadAll/Close used by Headscale DERP source loading.
#[cfg(feature = "hyper-rustls")]
#[doc(hidden)]
pub async fn go_http_get(raw: &str, timeout: std::time::Duration) -> Result<Vec<u8>, Error> {
    use crate::HttpClient;
    let client = crate::DefaultClient::try_new()?;
    let (uri, url) = prepare_url(&client, "GET", raw)?;
    let original = url.0.clone();
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri(uri)
        .extension(url)
        .extension(hyper_util::client::legacy::GoAutoUserAgent)
        .body(crate::BodyWrapper::<bytes::Bytes>::default())?;
    let mut reading_body = false;
    let result = tokio::time::timeout(timeout, async {
        let mut response = client.go_request(request).await?;
        reading_body = true;
        let body = response.body.into_bytes().await;
        // Headscale defers Close and ignores its result after ReadAll.
        let _ = response.body.close_native().await;
        body.map(|body| body.to_vec()).map_err(Error::Other)
    })
    .await;
    match result {
        Ok(result) => result,
        Err(_) if reading_body => Err(native_error("context deadline exceeded")),
        Err(_) => Err(url_error("Get", &original, "context deadline exceeded")),
    }
}

/// Parse in the NewRequest phase, then render backend failures with the method
/// and redacted URL that Client.Do would have used. No placeholder is sent.
pub(crate) fn prepare_url(
    client: &dyn crate::HttpClient,
    method: &str,
    raw: &str,
) -> Result<(Uri, RequestUrl), Error> {
    let mut url = url::Url::parse(raw)?;
    url.remove_empty_port();
    let uri = wire_uri(&url).map_err(|error| {
        client.go_transport_error(
            &String::from_utf8_lossy(&url.as_bytes()),
            &error.to_string(),
        );
        url_error(&operation(method), &url, error)
    })?;
    Ok((uri, RequestUrl(url)))
}

fn operation(method: &str) -> String {
    if method.is_empty() {
        return "Get".to_owned();
    }
    if !method.is_ascii() {
        return method.to_owned();
    }
    let mut operation = method.to_ascii_lowercase();
    operation.replace_range(..1, &method[..1]);
    operation
}

fn url_error(operation: &str, url: &url::Url, cause: impl std::fmt::Display) -> Error {
    native_error(format!(
        "{operation} {}: {cause}",
        super::quote::quote_bytes(&url.redacted())
    ))
}

fn wire_uri(url: &url::Url) -> Result<Uri, Error> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(native_error(format!(
            "unsupported protocol scheme {}",
            super::quote::quote(url.scheme())
        )));
    }
    if url.host().is_empty() {
        return Err(native_error("http: no Host in request URL"));
    }
    url.wire_uri()
}

#[cfg(feature = "hyper-rustls")]
mod redirects {
    use std::{future::Future, pin::Pin};

    use base64::prelude::{BASE64_STANDARD, Engine};
    use bytes::Bytes;
    use http::{
        HeaderMap, HeaderValue, Method, Request, StatusCode,
        header::{AUTHORIZATION, CONTENT_ENCODING, CONTENT_LENGTH, HOST, LOCATION, REFERER},
    };
    use http_body::Body;
    use hyper_util::client::legacy::{
        Client as HyperClient, GoAutoGzip, GoAutoUserAgent, GoH2Identity, GoPoolIdentity,
        GoRequestedGzip, connect::Connect,
    };

    use super::{
        RequestObserver, RequestUrl, gzip::NativeBody, operation, url, url_error, wire_uri,
    };
    use crate::{BodyWrapper, BytesBody, BytesResponse, Error};

    pub(crate) fn request<C>(
        client: HyperClient<C, BodyWrapper<Bytes>>,
        request: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>>
    where
        C: Connect + Clone + Send + Sync + 'static,
    {
        Box::pin(run(client, request))
    }

    async fn run<C>(
        client: HyperClient<C, BodyWrapper<Bytes>>,
        mut request: Request<BodyWrapper<Bytes>>,
    ) -> Result<BytesResponse, Error>
    where
        C: Connect + Clone + Send + Sync + 'static,
    {
        let observer = request.extensions().get::<RequestObserver>().cloned();
        let auto_user_agent = request.extensions().get::<GoAutoUserAgent>().is_some();
        let initial_url = match request.extensions().get::<RequestUrl>() {
            Some(url) => url.0.clone(),
            None => url::Url::parse(&request.uri().to_string())?,
        };
        let op = operation(request.method().as_str());
        let original_headers = request.headers().clone();
        let original_body = request.body().inner.clone();
        let mut current = initial_url.clone();
        let mut custom_host = request
            .headers()
            .get(HOST)
            .filter(|host| host.as_bytes() != current.host())
            .cloned();
        let mut include_body = true;
        let mut strip_sensitive = false;
        let mut sent = 0;

        loop {
            // URI conversion is immediately before the actual send, including
            // redirect targets. Unsupported backend URLs never reach Hyper.
            *request.uri_mut() = wire_uri(&current).map_err(|error| {
                observe_transport_error(observer.as_ref(), &current, &error);
                url_error(&op, &current, error)
            })?;
            add_url_auth(request.headers_mut(), &current);
            let method = request.method().clone();
            // The selected connection decides the different HTTP/1 and
            // HTTP/2 gzip guards after ALPN, outside the original snapshot.
            request.extensions_mut().insert(GoAutoGzip);
            if auto_user_agent {
                request.extensions_mut().insert(GoAutoUserAgent);
            }
            let identity = super::proxy::pool_identity(&current).map_err(|error| {
                observe_transport_error(observer.as_ref(), &current, &error);
                url_error(&op, &current, error)
            })?;
            request.extensions_mut().insert(GoPoolIdentity(identity));
            request
                .extensions_mut()
                .insert(GoH2Identity(current.h2_authority_addr()));
            super::proxy::apply_request_proxy_auth(&mut request).map_err(|error| {
                observe_transport_error(observer.as_ref(), &current, &error);
                url_error(&op, &current, error)
            })?;
            let response = match client.request(request).await {
                Ok(response) => response,
                Err(error) => {
                    observe_transport_error(observer.as_ref(), &current, &error);
                    return Err(url_error(&op, &current, error));
                }
            };
            let decode = response.body().go_body_is_transport()
                && response
                    .extensions()
                    .get::<GoRequestedGzip>()
                    .is_some_and(|requested| requested.0)
                && response
                    .headers()
                    .get(CONTENT_ENCODING)
                    .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"gzip"));
            let mut response = response.map(|body| NativeBody::new(body, decode));
            if decode {
                response.headers_mut().remove(CONTENT_ENCODING);
                response.headers_mut().remove(CONTENT_LENGTH);
            }
            if response.status().as_u16() >= 400 {
                if let Some(observer) = &observer {
                    // Go's logging RoundTripper ignores read errors, closes
                    // the original body and restores the captured prefix.
                    let body = response.body_mut().into_bytes_partial().await;
                    observer.0.response_error(
                        &String::from_utf8_lossy(&current.as_bytes()),
                        response.status().as_u16(),
                        &body,
                    );
                    *response.body_mut() = NativeBody::buffered(body);
                }
            }
            sent += 1;
            let method = match response.status() {
                StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND | StatusCode::SEE_OTHER => {
                    include_body = false;
                    if method == Method::GET || method == Method::HEAD {
                        method
                    } else {
                        Method::GET
                    }
                }
                StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT => method,
                _ => return Ok(response_to_bytes(response)),
            };
            let Some(location) = response
                .headers()
                .get(LOCATION)
                .filter(|location| !location.as_bytes().is_empty())
            else {
                return Ok(response_to_bytes(response));
            };
            let location = location.as_bytes().to_vec();
            let next = current.resolve_bytes(&location).map_err(|error| {
                url_error(
                    &op,
                    &current,
                    format!(
                        "failed to parse Location header {}: {error}",
                        super::super::quote::quote_bytes(&location)
                    ),
                )
            })?;
            // A custom Request.Host survives relative references, including a
            // scheme-relative //host reference, because Go tests IsAbs only.
            if custom_host
                .as_ref()
                .is_some_and(|host| host.as_bytes() == current.host())
                || custom_host.is_some()
                    && url::Url::parse_bytes(&location).is_ok_and(|url| url.is_absolute())
            {
                custom_host = None;
            }
            if !strip_sensitive
                && initial_url.host() != next.host()
                && !trusted(&initial_url, &next)
            {
                strip_sensitive = true;
            }
            let mut headers = copied_headers(&original_headers, strip_sensitive, !include_body);
            // Host and ContentLength are request fields in Go, independent of
            // the copied Header map. Project Host explicitly; Hyper derives
            // ContentLength from the selected replay/empty body.
            headers.remove(HOST);
            headers.remove(CONTENT_LENGTH);
            if let Some(host) = &custom_host {
                headers.insert(HOST, host.clone());
            }
            if !(current.scheme() == "https" && next.scheme() == "http") {
                let explicit = headers
                    .get(REFERER)
                    .filter(|value| !value.as_bytes().is_empty())
                    .cloned();
                let referer = match explicit {
                    Some(value) => Some(value),
                    None => {
                        let value = current.referer();
                        if value.is_empty() {
                            None
                        } else {
                            Some(
                                HeaderValue::from_bytes(&value)
                                    .map_err(|error| url_error(&op, &current, error))?,
                            )
                        }
                    }
                };
                if let Some(referer) = referer {
                    headers.insert(REFERER, referer);
                }
            }

            // Parse and prepare headers before CheckRedirect. Its default
            // ten-request error still closes/slurps the previous response.
            slurp(&mut response).await;
            if sent >= 10 {
                return Err(super::super::native_error(format!(
                    "{op} {}: stopped after 10 redirects",
                    super::super::quote::quote_bytes(&location)
                )));
            }
            let body = if include_body {
                original_body.clone()
            } else {
                None
            };
            request = Request::new(BodyWrapper { inner: body });
            *request.method_mut() = method;
            *request.headers_mut() = headers;
            request.extensions_mut().insert(RequestUrl(next.clone()));
            // Request::new's local default URI is never sent: the top of the
            // loop renders `next` and returns errors before client.request.
            current = next;
        }
    }

    fn observe_transport_error(
        observer: Option<&RequestObserver>,
        url: &url::Url,
        error: &impl std::fmt::Display,
    ) {
        if let Some(observer) = observer {
            observer.0.transport_error(
                &String::from_utf8_lossy(&url.as_bytes()),
                &error.to_string(),
            );
        }
    }

    fn response_to_bytes(response: hyper::Response<NativeBody>) -> BytesResponse {
        let (parts, body) = response.into_parts();
        BytesResponse {
            parts,
            body: Box::new(body),
        }
    }

    fn add_url_auth(headers: &mut HeaderMap, url: &url::Url) {
        if headers
            .get(AUTHORIZATION)
            .is_some_and(|value| !value.as_bytes().is_empty())
        {
            return;
        }
        let Some((user, password)) = url.credentials() else {
            return;
        };
        let mut bytes = user;
        bytes.push(b':');
        bytes.extend_from_slice(&password);
        let value = format!("Basic {}", BASE64_STANDARD.encode(bytes));
        // Base64 and the fixed prefix are always valid HTTP field bytes.
        if let Ok(value) = HeaderValue::from_str(&value) {
            headers.insert(AUTHORIZATION, value);
        }
    }

    fn copied_headers(original: &HeaderMap, strip_sensitive: bool, strip_body: bool) -> HeaderMap {
        let mut headers = original.clone();
        if strip_sensitive {
            for name in [
                "authorization",
                "www-authenticate",
                "cookie",
                "cookie2",
                "proxy-authorization",
                "proxy-authenticate",
            ] {
                headers.remove(name);
            }
        }
        if strip_body {
            for name in [
                "content-encoding",
                "content-language",
                "content-location",
                "content-type",
            ] {
                headers.remove(name);
            }
        }
        headers
    }

    fn trusted(initial: &url::Url, next: &url::Url) -> bool {
        let parent = initial.ascii_hostname_bytes();
        let child = next.ascii_hostname_bytes();
        if child == parent {
            return true;
        }
        if child.iter().any(|byte| matches!(byte, b':' | b'%')) || !child.ends_with(&parent) {
            return false;
        }
        child
            .len()
            .checked_sub(parent.len() + 1)
            .and_then(|index| child.get(index))
            == Some(&b'.')
    }

    async fn slurp(response: &mut hyper::Response<NativeBody>) {
        const LIMIT: u64 = 2 << 10;
        if response
            .body()
            .size_hint()
            .exact()
            .is_some_and(|length| length > LIMIT)
        {
            let _ = response.body_mut().close_native().await;
            return;
        }
        let _ = response
            .body_mut()
            .discard_bytes_limited(LIMIT as usize)
            .await;
        let _ = response.body_mut().close_native().await;
    }
}

#[cfg(feature = "hyper-rustls")]
pub(crate) use redirects::request;
