// Copyright 2015, 2018, 2019 The Go Authors. All rights reserved.
// Native polling/retry phases adapt x/crypto/acme; see LICENSE-GO and
// LICENSE-GO-NOTICE. Existing SDK APIs do not select this behavior.

//! Explicit native request and polling phases. Typed JSON fields, transport and
//! diagnostics retain selected Rust library boundaries; this is not a complete
//! Go ACME client or JSON decoder port.

use std::time::{Duration, SystemTime};

use http::{
    StatusCode,
    header::{LOCATION, RETRY_AFTER},
};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    Account, AuthorizationState, BytesResponse, Client, Error, NewOrder, Order, OrderStatus,
    Signer, crypto, nonce_from_response,
    types::{Empty, FinalizeRequest},
};

pub(crate) mod account_client;
pub(crate) mod account_key;
mod godebug;
mod http_date;
mod json_time;
mod legacy_json;
mod resource_decode;
mod response_error;
pub(crate) mod transport;
pub use account_key::NativeAccountKey;
pub use response_error::{NativeResponseError, NativeResponseSubproblem};
pub(crate) mod json_prefix;
mod pem;
mod quote;
mod resource;
use resource::NativeOrderWire;
pub use resource::{NativeIdentifier, NativeOrderResource, NativeProblem, NativeSubproblem};

#[derive(Debug)]
struct NativeMessage(String);

impl std::fmt::Display for NativeMessage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for NativeMessage {}

fn native_error(message: impl Into<String>) -> Error {
    Error::Other(Box::new(NativeMessage(message.into())))
}

/// A decoded native new-order resource before enum-based SDK interpretation.
/// Raw authorization URLs remain available for cleanup even for unknown status.
pub struct NativeNewOrder {
    /// Original, case-sensitive status string; null/missing is empty.
    pub status: String,
    /// Every decoded authorization URL on the resource.
    pub authorization_urls: Vec<String>,
    /// Location header used for the resource URI, including absent/empty.
    pub location: String,
    /// Typed SDK order for a known status, otherwise an interpretation error.
    pub order: Result<Order, Error>,
}

fn null_string<'de, D: Deserializer<'de>>(decoder: D) -> Result<String, D::Error> {
    Option::<String>::deserialize(decoder).map(Option::unwrap_or_default)
}

fn null_vec<'de, D, T>(decoder: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Option::<Vec<Option<T>>>::deserialize(decoder).map(|values| {
        values
            .unwrap_or_default()
            .into_iter()
            .map(Option::unwrap_or_default)
            .collect()
    })
}

/// An initial native authorization with string status and challenge types.
/// Unknown non-pending statuses can be skipped without interpreting challenges
/// as SDK enums. Existing AuthorizationState semantics are unchanged.
#[derive(Default, Debug, Deserialize)]
#[non_exhaustive]
pub struct NativeAuthorization {
    /// Original, case-sensitive authorization status.
    #[serde(default, deserialize_with = "null_string")]
    pub status: String,
    /// Decoded challenges, retaining unknown type/status strings.
    #[serde(default, deserialize_with = "null_vec")]
    pub challenges: Vec<NativeChallenge>,
    identifier: Option<NativeIdentifier>,
    wildcard: Option<bool>,
    #[serde(default)]
    pub(super) expires: Option<String>,
    #[serde(default)]
    pub(super) combinations: Vec<Vec<i64>>,
    #[serde(default)]
    pub(super) error: Option<NativeProblem>,
}

/// String-valued native challenge representation used for initial selection.
#[derive(Default, Debug, Deserialize)]
#[non_exhaustive]
pub struct NativeChallenge {
    /// Original challenge type, including unknown types.
    #[serde(rename = "type", default, deserialize_with = "null_string")]
    pub kind: String,
    /// RFC URL, or legacy URI when the URL was empty.
    #[serde(default, deserialize_with = "null_string")]
    pub url: String,
    /// Authorization token.
    #[serde(default, deserialize_with = "null_string")]
    pub token: String,
    /// Original status; missing/empty is projected to pending.
    #[serde(default, deserialize_with = "null_string")]
    pub status: String,
    #[serde(default, deserialize_with = "null_string")]
    uri: String,
    error: Option<NativeProblem>,
    #[serde(default)]
    pub(super) validated: Option<String>,
}

/// One native polling response, separating HTTP failures from JSON/body decode.
/// An outer request error is terminal; an inner decode error can be retried at
/// the same URL by the selected Go authorization/order polling loops.
#[derive(Debug)]
pub struct NativePoll<T> {
    /// Decoded first JSON value, or its body/JSON decoding error.
    pub decoded: Result<T, Error>,
    /// The first Retry-After field, before trimming or UTF-8 projection.
    pub retry_after: Option<Vec<u8>>,
}

impl<T> NativePoll<T> {
    /// Selected polling delay: invalid/zero means one second, negative is due.
    pub fn retry_delay(&self) -> Duration {
        let nanos = self.retry_after.as_deref().map_or(0, retry_after_nanos);
        if nanos == 0 {
            Duration::from_secs(1)
        } else {
            positive_duration(nanos)
        }
    }
}

fn positive_duration(nanos: i64) -> Duration {
    Duration::from_nanos(nanos.max(0) as u64)
}

fn retry_after_nanos(raw: &[u8]) -> i64 {
    let text = match std::str::from_utf8(raw) {
        Ok(text) => text,
        Err(_) => return 0,
    };
    // Go Atoi accepts a leading sign and no surrounding whitespace. Duration
    // multiplication wraps as signed int64 on the selected 64-bit baseline.
    if let Ok(seconds) = text.parse::<i64>() {
        return seconds.wrapping_mul(1_000_000_000);
    }
    let date = match http_date::parse(raw) {
        Some(date) => date,
        None => return 0,
    };
    match date.duration_since(SystemTime::now()) {
        Ok(delta) => delta.as_nanos().min(i64::MAX as u128) as i64,
        Err(error) => -(error.duration().as_nanos().min(i64::MAX as u128 + 1) as i128) as i64,
    }
}

fn first_retry_after(rsp: &BytesResponse) -> Option<Vec<u8>> {
    rsp.parts
        .headers
        .get(RETRY_AFTER)
        .map(|value| value.as_bytes().to_vec())
}

fn order_decode_error(error: Error) -> Error {
    native_error(format!("acme: error reading order: {error}"))
}

fn invalid_response_error(error: Error) -> Error {
    native_error(format!("acme: invalid response: {error}"))
}

async fn decode<T: resource_decode::NativeDecode>(mut rsp: BytesResponse) -> NativePoll<T> {
    let retry_after = first_retry_after(&rsp);
    let decoded = match rsp.body.into_first_json_value().await {
        Ok(body) => {
            // Decode one Go v1 value, including legacy string bytes. The
            // scanner validates syntax before typed assignments, without
            // Serde's UTF8/surrogate policy changing the first failure.
            match legacy_json::scanner::first_raw_value(&body) {
                Ok(Some(raw)) => T::native_decode(raw),
                Ok(None) => Err(native_error("EOF")),
                Err(error) => Err(native_error(error)),
            }
        }
        Err(error) => Err(Error::Other(error)),
    };
    NativePoll {
        decoded,
        retry_after,
    }
}

fn jitter_nanos() -> i64 {
    use crypto::ring_like::rand::SecureRandom;
    let rng = crypto::SystemRandom::new();
    loop {
        let mut bytes = [0; 2];
        if rng.fill(&mut bytes).is_err() {
            return 0;
        }
        let value = u16::from_be_bytes(bytes);
        if value < 65_000 {
            return (1 + i64::from(value % 1000)) * 1_000_000;
        }
    }
}

impl Client {
    pub(crate) async fn post_go(
        &self,
        payload: Option<&impl Serialize>,
        mut nonce: Option<String>,
        signer: &impl Signer,
        url: &str,
        accepted: &[StatusCode],
    ) -> Result<BytesResponse, Error> {
        let mut attempt = 0u32;
        loop {
            // Signing, nonce acquisition and transport errors are not HTTP
            // retries. Keep their stage outside response-error classification.
            let mut rsp = if self.go_native.is_some() {
                signer.go_prepare().await;
                account_client::post_attempt(self, payload, signer, url).await?
            } else {
                self.post_attempt(payload, nonce.take(), signer, url)
                    .await?
            };
            if accepted.contains(&rsp.parts.status) {
                return Ok(rsp);
            }
            let status = rsp.parts.status;
            let retry_after = first_retry_after(&rsp);
            nonce = nonce_from_response(&rsp);
            let headers = rsp.parts.headers.clone();
            let body = rsp.body.into_bytes_partial().await;
            let issue = response_error::parse(status, &body).with_headers(headers);
            let bad_nonce = issue.is_bad_nonce();
            if bad_nonce {
                // x/crypto clears every cached nonce, including the response
                // nonce it just collected, before trying the request again.
                nonce = None;
                if let Some(state) = &self.go_native {
                    state.clear_nonces().await;
                }
            }
            let retriable = status.as_u16() <= 399
                || status.as_u16() >= 500
                || status == StatusCode::TOO_MANY_REQUESTS;
            if !bad_nonce && !retriable {
                return Err(issue.into_error());
            }
            attempt = attempt.saturating_add(1);
            let jitter = jitter_nanos();
            let delay = match retry_after {
                Some(raw) => retry_after_nanos(&raw).wrapping_add(jitter),
                None => ((1i64 << attempt.clamp(1, 30).saturating_sub(1)) * 1_000_000_000 + jitter)
                    .min(10_000_000_000),
            };
            if delay <= 0 {
                return Err(issue.into_error());
            }
            tokio::time::sleep(positive_duration(delay)).await;
        }
    }
}

impl Account {
    /// Decode native resource metadata before attempting SDK status conversion.
    /// Callers can register cleanup before rejecting unknown status strings.
    pub async fn go_new_order_resource(
        &self,
        request: &NewOrder<'_>,
    ) -> Result<NativeNewOrder, Error> {
        let inner = self.go_inner();
        let rsp = inner
            .post_go(
                Some(request),
                None,
                &inner.go_new_order_url().await?,
                &[StatusCode::CREATED],
            )
            .await?;
        let nonce = nonce_from_response(&rsp);
        let location = rsp
            .parts
            .headers
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let mut wire = decode::<Option<NativeOrderWire>>(rsp)
            .await
            .decoded
            .map_err(order_decode_error)?
            .unwrap_or_default();
        wire.location = location.clone();
        let status = wire.status.clone();
        let authorization_urls = wire.authorizations.clone();
        let order = wire.project_state().map(|state| Order {
            account: inner.clone(),
            nonce,
            retry_after: None,
            url: location.clone(),
            state,
            go_problem: wire.error.clone(),
            go_resource: Some(wire),
        });
        Ok(NativeNewOrder {
            status,
            authorization_urls,
            location,
            order,
        })
    }

    /// Fetch initial authorization strings without SDK enum interpretation.
    pub async fn go_authorization_resource(&self, url: &str) -> Result<NativeAuthorization, Error> {
        let rsp = self
            .go_inner()
            .post_go(None::<&Empty>, None, url, &[StatusCode::OK])
            .await?;
        let mut authorization = decode::<Option<NativeAuthorization>>(rsp)
            .await
            .decoded
            .map_err(invalid_response_error)?
            .unwrap_or_default();
        for challenge in &mut authorization.challenges {
            if challenge.url.is_empty() {
                challenge.url = std::mem::take(&mut challenge.uri);
            }
            if challenge.status.is_empty() {
                challenge.status = "pending".into();
            }
        }
        Ok(authorization)
    }

    /// Native new-order HTTP phases; other SDK methods retain their defaults.
    pub async fn go_new_order(&self, order: &NewOrder<'_>) -> Result<Order, Error> {
        let inner = self.go_inner();
        let rsp = inner
            .post_go(
                Some(order),
                None,
                &inner.go_new_order_url().await?,
                &[StatusCode::CREATED],
            )
            .await?;
        let nonce = nonce_from_response(&rsp);
        let url = rsp
            .parts
            .headers
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let mut wire = decode::<Option<NativeOrderWire>>(rsp)
            .await
            .decoded
            .map_err(order_decode_error)?
            .unwrap_or_default();
        wire.location = url.clone();
        let state = wire.project_state()?;
        Ok(Order {
            account: inner.clone(),
            nonce,
            retry_after: None,
            state,
            go_problem: wire.error.clone(),
            go_resource: Some(wire),
            url,
        })
    }

    /// Fetch an authorization directly by URL with the GetAuthorization status.
    pub async fn go_authorization(&self, url: &str) -> Result<AuthorizationState, Error> {
        self.go_authorization_resource(url).await?.into_state()
    }

    /// Poll an authorization, retaining Retry-After across JSON/body failures.
    pub async fn go_poll_authorization(
        &self,
        url: &str,
    ) -> Result<NativePoll<AuthorizationState>, Error> {
        let response = self.go_poll_authorization_resource(url).await?;
        Ok(NativePoll {
            decoded: response.decoded.and_then(NativeAuthorization::into_state),
            retry_after: response.retry_after,
        })
    }

    /// Poll a native authorization without interpreting SDK identifier/status
    /// enums. Unknown identifier types do not prevent native final-status use.
    pub async fn go_poll_authorization_resource(
        &self,
        url: &str,
    ) -> Result<NativePoll<NativeAuthorization>, Error> {
        let rsp = self
            .go_inner()
            .post_go(
                None::<&Empty>,
                None,
                url,
                &[StatusCode::OK, StatusCode::ACCEPTED],
            )
            .await?;
        let response = decode::<Option<NativeAuthorization>>(rsp).await;
        Ok(NativePoll {
            decoded: response.decoded.map(Option::unwrap_or_default),
            retry_after: response.retry_after,
        })
    }

    /// Accept a challenge with Go's 200/202 HTTP and decode-only body behavior.
    pub async fn go_accept_challenge(&self, url: &str) -> Result<(), Error> {
        let rsp = self
            .go_inner()
            .post_go(
                Some(&Empty {}),
                None,
                url,
                &[StatusCode::OK, StatusCode::ACCEPTED],
            )
            .await?;
        let _: Option<NativeChallenge> =
            decode(rsp).await.decoded.map_err(invalid_response_error)?;
        Ok(())
    }

    /// Directly fetch this URL, then deactivate only a pending authorization.
    /// No order fetch or mutation of a valid authorization is performed.
    pub async fn go_deactivate_pending_authorization(&self, url: &str) -> Result<(), Error> {
        if self.go_authorization_resource(url).await?.status != "pending" {
            return Ok(());
        }
        #[derive(Serialize)]
        struct Deactivate {
            resource: &'static str,
            status: &'static str,
            delete: bool,
        }
        let payload = Deactivate {
            resource: "authz",
            status: "deactivated",
            delete: true,
        };
        let mut rsp = self
            .go_inner()
            .post_go(Some(&payload), None, url, &[StatusCode::OK])
            .await?;
        let _ = rsp.body.close_native().await;
        Ok(())
    }
}

impl Order {
    /// Latest successfully decoded native order resource, including unknown
    /// statuses and operational URLs. `state()` retains the last representable
    /// SDK view when a newer status has no SDK enum variant. Default SDK
    /// response methods do not update this native-only sidecar.
    pub fn go_resource(&self) -> Option<&NativeOrderResource> {
        self.go_resource.as_ref()
    }

    /// Raw metadata from the last successfully decoded native order
    /// response. SDK `state().error` is present only when representable without
    /// losing identifier types or narrowing its status. Default SDK response
    /// methods do not update this native-only sidecar.
    pub fn go_problem(&self) -> Option<&NativeProblem> {
        self.go_problem.as_ref()
    }

    /// Poll this order, updating state only after successful JSON decoding.
    pub async fn go_poll(&mut self) -> Result<NativePoll<OrderStatus>, Error> {
        let rsp = self
            .account
            .post_go(
                None::<&Empty>,
                self.nonce.take(),
                &self.url,
                &[StatusCode::OK],
            )
            .await?;
        self.nonce = nonce_from_response(&rsp);
        let location = rsp
            .parts
            .headers
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let response = decode::<Option<NativeOrderWire>>(rsp).await;
        let decoded = response
            .decoded
            .map_err(order_decode_error)
            .and_then(|wire| {
                let mut wire = wire.unwrap_or_default();
                wire.location = location;
                let projected = wire.project_state();
                self.go_problem = wire.error.clone();
                self.go_resource = Some(wire);
                projected.map(|state| {
                    let status = state.status;
                    self.state = state;
                    status
                })
            });
        Ok(NativePoll {
            decoded,
            retry_after: response.retry_after,
        })
    }

    /// Submit the prepared CSR without changing default finalize semantics.
    pub async fn go_finalize_csr(&mut self, csr: &[u8]) -> Result<(), Error> {
        let rsp = self
            .account
            .post_go(
                Some(&FinalizeRequest::new(csr)),
                self.nonce.take(),
                self.go_resource
                    .as_ref()
                    .map_or(self.state.finalize.as_str(), |wire| wire.finalize.as_str()),
                &[StatusCode::OK],
            )
            .await?;
        self.nonce = nonce_from_response(&rsp);
        let url = rsp
            .parts
            .headers
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let mut wire = decode::<Option<NativeOrderWire>>(rsp)
            .await
            .decoded
            .map_err(order_decode_error)?
            .unwrap_or_default();
        wire.location = url.clone();
        if let Ok(state) = wire.project_state() {
            self.state = state;
        }
        self.go_problem = wire.error.clone();
        self.go_resource = Some(wire);
        // CreateOrderCert polls the URI returned by responseOrder for this
        // finalize response, including an absent Location becoming empty.
        self.url = url;
        Ok(())
    }

    /// Download the certificate of a valid order without an extra poll/backoff.
    pub async fn go_certificate(&mut self) -> Result<String, Error> {
        let (valid, certificate) = match self.go_resource.as_ref() {
            Some(wire) => (
                wire.status == "valid",
                // Go's plain certificate string is empty for missing/null;
                // let the request layer handle that URL in the native path.
                Some(wire.certificate.as_deref().unwrap_or_default()),
            ),
            None => (
                self.state.status == OrderStatus::Valid,
                self.state.certificate.as_deref(),
            ),
        };
        if !valid {
            return Err(Error::Str("invalid order state"));
        }
        let url = certificate.ok_or(Error::Str("no certificate URL found"))?;
        let mut rsp = self
            .account
            .post_go(None::<&Empty>, self.nonce.take(), url, &[StatusCode::OK])
            .await?;
        self.nonce = nonce_from_response(&rsp);
        // Selected Go fetchCertRFC reads max+1 through LimitReader, then
        // decodes at most five CERTIFICATE PEM blocks. Stop before a later
        // stream error once the limiting prefix has already been received.
        const MAX_CHAIN: usize = 5 * (1 << 20);
        const MAX_BODY: usize = MAX_CHAIN + MAX_CHAIN / 33;
        let body = rsp
            .body
            .into_bytes_limited(MAX_BODY + 1)
            .await
            .map_err(|error| native_error(format!("acme: fetch cert response stream: {error}")))?;
        if body.len() > MAX_BODY {
            return Err(native_error("acme: certificate chain is too big"));
        }
        let mut rest = body.as_ref();
        let mut count = 0;
        let mut output = String::new();
        while let Some((block, next)) = pem::decode(rest) {
            if block.label != b"CERTIFICATE" {
                return Err(native_error(format!(
                    "acme: invalid PEM cert type {}",
                    quote::quote_bytes(block.label)
                )));
            }
            count += 1;
            if count > 5 {
                return Err(native_error("acme: certificate chain is too long"));
            }
            output.push_str(&pem::encode("CERTIFICATE", &block.bytes));
            rest = next;
        }
        if count == 0 {
            return Err(native_error("acme: certificate chain is empty"));
        }
        Ok(output)
    }
}
