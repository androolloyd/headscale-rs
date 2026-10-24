// Copyright 2015, 2018 The Go Authors. All rights reserved.
// Native directory/account/nonce phases follow x/crypto/acme; see LICENSE-GO.

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
use http::{
    Method, Request, StatusCode,
    header::{CONTENT_TYPE, LOCATION, USER_AGENT},
};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    sync::{Mutex, OnceLock},
};
use tokio::sync::Mutex as AsyncMutex;

use super::{NativeAccountKey, decode, legacy_json as json, native_error, response_error};
use crate::{BodyWrapper, BytesResponse, Client, Directory, Error, HttpClient, Signer};

const USER_AGENT_VALUE: &str = "autocert golang.org/x/crypto/acme@v0.53.0";

#[derive(Default)]
pub(crate) struct NativeClientState {
    nonces: AsyncMutex<BTreeSet<Vec<u8>>>,
    kid: Mutex<String>,
    account_lookup: AsyncMutex<()>,
    directory: OnceLock<NativeDirectory>,
    discovery: AsyncMutex<()>,
}

struct NativeDirectory {
    directory: Directory,
    terms: String,
}

impl NativeClientState {
    pub(crate) async fn clear_nonces(&self) {
        self.nonces.lock().await.clear();
    }
    pub(crate) fn kid(&self) -> String {
        self.kid.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    fn set_kid(&self, kid: String) {
        *self.kid.lock().unwrap_or_else(|e| e.into_inner()) = kid;
    }
    // Takes the extracted nonce, not the response: a `BytesResponse` is only
    // `Send`, so holding a reference to it across the lock would make every
    // caller's future non-`Send`.
    async fn add_nonce(&self, nonce: Option<Vec<u8>>) {
        if let Some(nonce) = nonce.filter(|nonce| !nonce.is_empty()) {
            let mut pool = self.nonces.lock().await;
            if pool.len() < 100 {
                pool.insert(nonce);
            }
        }
    }
}

pub(crate) async fn post_attempt(
    client: &Client,
    payload: Option<&impl Serialize>,
    signer: &impl Signer,
    url: &str,
) -> Result<BytesResponse, Error> {
    let state = client
        .go_native
        .as_ref()
        .ok_or(Error::Str("native client state unavailable"))?;
    // Discover can add a nonce while holding its serialization lock. Resolve
    // this immutable snapshot before acquiring the nonce lock, never inside it.
    let nonce_url = ensure_directory(client).await?.directory.new_nonce.clone();
    let nonce = {
        // The selected Go nonce mutex covers the HEAD request too.
        let mut pool = state.nonces.lock().await;
        if let Some(nonce) = pool.pop_first() {
            nonce
        } else if !nonce_url.is_empty() {
            fetch_nonce(client, &nonce_url).await?
        } else {
            let directory = client
                .directory_url
                .as_deref()
                .unwrap_or(crate::LetsEncrypt::Production.url());
            match fetch_nonce(client, directory).await {
                Ok(nonce) => nonce,
                Err(_) if directory != url => fetch_nonce(client, url).await?,
                Err(error) => return Err(error),
            }
        }
    };
    // Go strings retain raw header bytes in the nonce set; only JSON encoding
    // replaces invalid UTF8. Preserve raw identity until signing the header.
    let nonce = json::lossy(&nonce);
    let body = native_jws(payload, signer, &nonce, url)?;
    let (uri, request_url) = super::transport::prepare_url(client.http.as_ref(), "POST", url)?;
    let request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .extension(request_url)
        .header(USER_AGENT, USER_AGENT_VALUE)
        .header(CONTENT_TYPE, crate::JOSE_JSON)
        .body(BodyWrapper::from(body))?;
    let response = client.http.go_request(request).await?;
    state.add_nonce(native_nonce(&response)).await;
    Ok(response)
}

fn native_jws(
    payload: Option<&impl Serialize>,
    signer: &impl Signer,
    nonce: &str,
    url: &str,
) -> Result<Vec<u8>, Error> {
    let protected = BASE64_URL_SAFE_NO_PAD.encode(go_marshal(&signer.header(Some(nonce), url))?);
    let payload = payload
        .map(go_marshal)
        .transpose()?
        .map(|bytes| BASE64_URL_SAFE_NO_PAD.encode(bytes))
        .unwrap_or_default();
    let signature = signer.sign(format!("{protected}.{payload}").as_bytes())?;
    #[derive(Serialize)]
    struct Jws {
        protected: String,
        payload: String,
        signature: String,
    }
    Ok(serde_json::to_vec(&Jws {
        protected,
        payload,
        signature: BASE64_URL_SAFE_NO_PAD.encode(signature.as_ref()),
    })?)
}

fn go_marshal(value: &impl Serialize) -> Result<Vec<u8>, serde_json::Error> {
    let bytes = serde_json::to_vec(value)?;
    let mut output = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'<' => output.extend_from_slice(b"\\u003c"),
            b'>' => output.extend_from_slice(b"\\u003e"),
            b'&' => output.extend_from_slice(b"\\u0026"),
            0xe2 if bytes.get(at + 1) == Some(&0x80)
                && matches!(bytes.get(at + 2), Some(0xa8 | 0xa9)) =>
            {
                output.extend_from_slice(if bytes[at + 2] == 0xa8 {
                    b"\\u2028"
                } else {
                    b"\\u2029"
                });
                at += 2;
            }
            byte => output.push(byte),
        }
        at += 1;
    }
    Ok(output)
}

async fn fetch_nonce(client: &Client, url: &str) -> Result<Vec<u8>, Error> {
    let (uri, request_url) = super::transport::prepare_url(client.http.as_ref(), "HEAD", url)?;
    let request = Request::builder()
        .method(Method::HEAD)
        .uri(uri)
        .extension(request_url)
        .header(USER_AGENT, USER_AGENT_VALUE)
        .body(BodyWrapper::default())?;
    let mut response = client.http.go_request(request).await?;
    if let Some(nonce) = native_nonce(&response).filter(|nonce| !nonce.is_empty()) {
        let _ = response.body.close_native().await;
        return Ok(nonce);
    }
    if response.parts.status.as_u16() > 299 {
        let status = response.parts.status;
        let headers = response.parts.headers.clone();
        let body = response.body.into_bytes_partial().await;
        return Err(response_error::parse(status, &body)
            .with_headers(headers)
            .into_error());
    }
    let _ = response.body.close_native().await;
    Err(native_error("acme: nonce not found"))
}

async fn get_directory(client: &Client, url: &str) -> Result<BytesResponse, Error> {
    let mut attempt = 0u32;
    loop {
        let (uri, request_url) = super::transport::prepare_url(client.http.as_ref(), "GET", url)?;
        let request = Request::builder()
            .uri(uri)
            .extension(request_url)
            .header(USER_AGENT, USER_AGENT_VALUE)
            .body(BodyWrapper::default())?;
        let mut response = client.http.go_request(request).await?;
        let status = response.parts.status;
        if status == StatusCode::OK {
            return Ok(response);
        }
        let retry_after = super::first_retry_after(&response);
        let headers = response.parts.headers.clone();
        let body = response.body.into_bytes_partial().await;
        let issue = response_error::parse(status, &body).with_headers(headers);
        if !(status.as_u16() <= 399
            || status.as_u16() >= 500
            || status == StatusCode::TOO_MANY_REQUESTS)
        {
            return Err(issue.into_error());
        }
        attempt = attempt.saturating_add(1);
        let jitter = super::jitter_nanos();
        let delay = match retry_after {
            Some(raw) => super::retry_after_nanos(&raw).wrapping_add(jitter),
            None => ((1i64 << attempt.clamp(1, 30).saturating_sub(1)) * 1_000_000_000 + jitter)
                .min(10_000_000_000),
        };
        if delay <= 0 {
            return Err(issue.into_error());
        }
        tokio::time::sleep(super::positive_duration(delay)).await;
    }
}

async fn ensure_directory(client: &Client) -> Result<&NativeDirectory, Error> {
    let state = client
        .go_native
        .as_ref()
        .ok_or(Error::Str("native client state unavailable"))?;
    if let Some(directory) = state.directory.get() {
        return Ok(directory);
    }
    let _guard = state.discovery.lock().await;
    if let Some(directory) = state.directory.get() {
        return Ok(directory);
    }
    let url = client
        .directory_url
        .as_deref()
        .unwrap_or(crate::LetsEncrypt::Production.url());
    let response = get_directory(client, url).await?;
    state.add_nonce(native_nonce(&response)).await;
    let wire = decode::<Option<DirectoryWire>>(response)
        .await
        .decoded?
        .unwrap_or_default();
    if wire.order.is_empty() {
        return Err(native_error(
            "acme: server does not support the RFC 8555 version of ACME",
        ));
    }
    let directory = Directory {
        new_nonce: wire.nonce,
        new_account: wire.account,
        new_order: wire.order,
        new_authz: Some(wire.authz),
        revoke_cert: Some(wire.revoke),
        key_change: Some(wire.key_change),
        renewal_info: None,
        meta: crate::types::Meta::default(),
    };
    let _ = state.directory.set(NativeDirectory {
        directory,
        terms: wire.terms,
    });
    state
        .directory
        .get()
        .ok_or(Error::Str("native directory was not published"))
}

pub(crate) async fn discover(client: &Client) -> Result<(), Error> {
    if client.go_native.is_some() {
        ensure_directory(client).await?;
    }
    Ok(())
}

pub(crate) async fn new_order_url(client: &Client) -> Result<String, Error> {
    match &client.go_native {
        Some(_) => Ok(ensure_directory(client).await?.directory.new_order.clone()),
        None => Ok(client.directory.new_order.clone()),
    }
}

fn account_exists(error: &Error) -> bool {
    matches!(error, Error::Other(error) if error.downcast_ref::<super::NativeResponseError>().is_some_and(|error| error.status == 409))
}

pub(crate) async fn register(
    http: Box<dyn HttpClient>,
    key: &NativeAccountKey,
    directory_url: String,
    email: Option<&str>,
) -> Result<(Client, String), Error> {
    let directory_url = if directory_url.is_empty() {
        crate::LetsEncrypt::Production.url().to_owned()
    } else {
        directory_url
    };
    let mut client = Client {
        http,
        directory: Directory {
            new_nonce: String::new(),
            new_account: String::new(),
            new_order: String::new(),
            new_authz: None,
            revoke_cert: None,
            key_change: None,
            renewal_info: None,
            meta: crate::types::Meta::default(),
        },
        directory_url: Some(directory_url.clone()),
        go_native: Some(NativeClientState::default()),
    };
    let (directory, terms_agreed) = match ensure_directory(&client).await {
        Ok(directory) => (directory.directory.clone(), !directory.terms.is_empty()),
        // Manager accepts an existing-account error originating from Discover
        // too. Keep this client unset; its next operation discovers again.
        Err(error) if account_exists(&error) => return Ok((client, String::new())),
        Err(error) => return Err(error),
    };
    client.directory = directory;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Registration {
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        terms_of_service_agreed: bool,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        contact: Vec<String>,
    }
    let contact = email
        .filter(|value| !value.is_empty())
        .map(|email| vec![format!("mailto:{email}")])
        .unwrap_or_default();
    let payload = Registration {
        terms_of_service_agreed: terms_agreed,
        contact,
    };
    let response = match client
        .post_go(
            Some(&payload),
            None,
            key,
            &client.directory.new_account,
            &[StatusCode::OK, StatusCode::CREATED],
        )
        .await
    {
        Ok(response) => response,
        Err(error) if account_exists(&error) => {
            return Ok((client, String::new()));
        }
        Err(error) => return Err(error),
    };
    let id = location(&response);
    let _ = decode::<Option<AccountWire>>(response)
        .await
        .decoded
        .map_err(|error| native_error(format!("acme: invalid account response: {error}")))?;
    client.go_native.as_ref().unwrap().set_kid(id.clone());
    Ok((client, id))
}

pub(crate) async fn ensure_kid(client: &Client, key: &NativeAccountKey) {
    let Some(state) = &client.go_native else {
        return;
    };
    if !state.kid().is_empty() {
        return;
    }
    let Ok(directory) = ensure_directory(client).await else {
        return;
    };
    let account_url = directory.directory.new_account.clone();
    let _guard = state.account_lookup.lock().await;
    if !state.kid().is_empty() {
        return;
    }
    #[derive(Serialize)]
    struct Lookup {
        #[serde(rename = "onlyReturnExisting")]
        only_return_existing: bool,
    }
    // Go accountKID suppresses lookup errors and uses JWK form on failure.
    if let Ok(response) = client
        .post_go(
            Some(&Lookup {
                only_return_existing: true,
            }),
            None,
            key,
            &account_url,
            &[StatusCode::OK],
        )
        .await
    {
        let id = location(&response);
        if decode::<Option<AccountWire>>(response)
            .await
            .decoded
            .is_ok()
        {
            state.set_kid(id);
        }
    }
}

fn location(response: &BytesResponse) -> String {
    response
        .parts
        .headers
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

fn native_nonce(response: &BytesResponse) -> Option<Vec<u8>> {
    response
        .parts
        .headers
        .get(crate::REPLAY_NONCE)
        .map(|value| value.as_bytes().to_vec())
}

#[derive(Default)]
struct DirectoryWire {
    account: String,
    authz: String,
    order: String,
    revoke: String,
    nonce: String,
    key_change: String,
    terms: String,
}
#[derive(Default)]
struct AccountWire;

// The selected Go declarations are anonymous structs. reflect.Type.String
// includes their original field names, declaration order and quoted tags.
const DIRECTORY_TYPE: &str = r#"struct { Reg string "json:\"newAccount\""; Authz string "json:\"newAuthz\""; Order string "json:\"newOrder\""; Revoke string "json:\"revokeCert\""; Nonce string "json:\"newNonce\""; KeyChange string "json:\"keyChange\""; Meta struct { Terms string "json:\"termsOfService\""; Website string "json:\"website\""; CAA []string "json:\"caaIdentities\""; ExternalAcct bool "json:\"externalAccountRequired\"" } }"#;
const METADATA_TYPE: &str = r#"struct { Terms string "json:\"termsOfService\""; Website string "json:\"website\""; CAA []string "json:\"caaIdentities\""; ExternalAcct bool "json:\"externalAccountRequired\"" }"#;
const ACCOUNT_TYPE: &str = "struct { Status string; Contact []string; Orders string }";

fn type_error(raw: &[u8], path: &str, expected: &str) -> Error {
    native_error(super::resource_decode::type_error(raw, "", path, expected))
}

impl super::resource_decode::NativeDecode for Option<DirectoryWire> {
    fn native_decode(bytes: &[u8]) -> Result<Self, Error> {
        if json::trim(bytes) == b"null" {
            return Ok(None);
        }
        let mut wire = DirectoryWire::default();
        let mut saved = None;
        for (name, raw) in
            json::object(bytes).ok_or_else(|| type_error(bytes, "", DIRECTORY_TYPE))?
        {
            let raw = raw.get();
            let target = if json::field(&name, "newAccount") {
                Some((&mut wire.account, "newAccount"))
            } else if json::field(&name, "newAuthz") {
                Some((&mut wire.authz, "newAuthz"))
            } else if json::field(&name, "newOrder") {
                Some((&mut wire.order, "newOrder"))
            } else if json::field(&name, "revokeCert") {
                Some((&mut wire.revoke, "revokeCert"))
            } else if json::field(&name, "newNonce") {
                Some((&mut wire.nonce, "newNonce"))
            } else if json::field(&name, "keyChange") {
                Some((&mut wire.key_change, "keyChange"))
            } else {
                None
            };
            let result = if let Some((target, path)) = target {
                string(target, raw, path)
            } else if json::field(&name, "meta") {
                metadata(&mut wire.terms, raw)
            } else {
                Ok(())
            };
            if saved.is_none() {
                saved = result.err();
            }
        }
        if let Some(error) = saved {
            return Err(error);
        }
        Ok(Some(wire))
    }
}

impl super::resource_decode::NativeDecode for Option<AccountWire> {
    fn native_decode(bytes: &[u8]) -> Result<Self, Error> {
        if json::trim(bytes) == b"null" {
            return Ok(None);
        }
        let mut saved = None;
        let mut status = String::new();
        let mut orders = String::new();
        let mut contact = Vec::new();
        for (name, raw) in json::object(bytes).ok_or_else(|| type_error(bytes, "", ACCOUNT_TYPE))? {
            let result = if json::field(&name, "status") {
                string(&mut status, raw.get(), "Status")
            } else if json::field(&name, "orders") {
                string(&mut orders, raw.get(), "Orders")
            } else if json::field(&name, "contact") {
                strings(&mut contact, raw.get(), "Contact")
            } else {
                Ok(())
            };
            if saved.is_none() {
                saved = result.err();
            }
        }
        if let Some(error) = saved {
            return Err(error);
        }
        Ok(Some(AccountWire))
    }
}

fn metadata(terms: &mut String, raw: &[u8]) -> Result<(), Error> {
    if json::trim(raw) == b"null" {
        return Ok(());
    }
    let mut saved = None;
    let mut website = String::new();
    let mut caa = Vec::new();
    for (name, raw) in json::object(raw).ok_or_else(|| type_error(raw, "Meta", METADATA_TYPE))? {
        let result = if json::field(&name, "termsOfService") {
            string(terms, raw.get(), "Meta.termsOfService")
        } else if json::field(&name, "website") {
            string(&mut website, raw.get(), "Meta.website")
        } else if json::field(&name, "caaIdentities") {
            strings(&mut caa, raw.get(), "Meta.caaIdentities")
        } else if json::field(&name, "externalAccountRequired")
            && !matches!(json::trim(raw.get()), b"true" | b"false" | b"null")
        {
            Err(type_error(
                raw.get(),
                "Meta.externalAccountRequired",
                "bool",
            ))
        } else {
            Ok(())
        };
        if saved.is_none() {
            saved = result.err();
        }
    }
    saved.map_or(Ok(()), Err)
}

fn string(target: &mut String, raw: &[u8], path: &str) -> Result<(), Error> {
    if json::trim(raw) == b"null" {
        return Ok(());
    }
    *target = json::unquote(raw).ok_or_else(|| type_error(raw, path, "string"))?;
    Ok(())
}
fn strings(target: &mut Vec<String>, raw: &[u8], path: &str) -> Result<(), Error> {
    if json::trim(raw) == b"null" {
        target.clear();
        return Ok(());
    }
    let values = json::array(raw).ok_or_else(|| type_error(raw, path, "[]string"))?;
    target.clear();
    let mut saved = None;
    for raw in values {
        let mut value = String::new();
        let result = string(&mut value, raw.get(), path);
        target.push(value);
        if saved.is_none() {
            saved = result.err();
        }
    }
    saved.map_or(Ok(()), Err)
}
