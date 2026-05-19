//! DID-based authentication for control-plane node operations.

use std::collections::HashMap;
use std::sync::RwLock;

use axum::http::HeaderMap;
use base64::prelude::*;
use headscale_core::node::RegisterRequest;
use headscale_identity::{Did, KeyPair};
use serde::{Deserialize, Serialize};

pub const DID_HEADER: &str = "X-DID";
pub const DID_SIGNATURE_HEADER: &str = "X-DID-Signature";
pub const DID_TIMESTAMP_HEADER: &str = "X-DID-Timestamp";
pub const DID_NONCE_HEADER: &str = "X-DID-Nonce";

const SIGNATURE_WINDOW_MILLIS: u64 = 5 * 60 * 1000;

/// Node registration request with the DID proof needed by the public HTTP API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRegisterRequest {
    #[serde(flatten)]
    pub request: RegisterRequest,
    pub signature: String,
    pub timestamp_millis: u64,
    pub nonce: String,
}

/// Signed payer-authorized transfer request for the public HTTP API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransferRequest {
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub description: String,
    pub signature: String,
    pub timestamp_millis: u64,
    pub nonce: String,
}

/// In-memory replay protection for signed control-plane requests.
#[derive(Default)]
pub struct NonceStore {
    nonces: RwLock<HashMap<String, HashMap<String, u64>>>,
}

impl NonceStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn check_and_store(&self, did: &str, nonce: &str, timestamp_millis: u64) -> bool {
        if !is_valid_nonce(nonce) {
            return false;
        }

        let mut nonces = self.nonces.write().unwrap_or_else(|e| e.into_inner());
        let did_nonces = nonces.entry(did.to_string()).or_default();
        let oldest_allowed = timestamp_millis.saturating_sub(SIGNATURE_WINDOW_MILLIS);
        did_nonces.retain(|_, seen_at| *seen_at >= oldest_allowed);

        if did_nonces.contains_key(nonce) {
            return false;
        }

        did_nonces.insert(nonce.to_string(), timestamp_millis);
        true
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ControlAuthError {
    #[error("missing signature header")]
    MissingSignature,
    #[error("invalid signature format")]
    InvalidFormat,
    #[error("signature timestamp is outside the allowed window")]
    TimestampOutOfWindow,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("signature nonce was already used")]
    NonceReplay,
    #[error("signed identity does not match requested node")]
    IdentityMismatch,
}

pub fn verify_node_registration(
    req: &SignedRegisterRequest,
    nonces: &NonceStore,
) -> Result<(), ControlAuthError> {
    verify_signature(
        &req.request.id,
        req.timestamp_millis,
        &req.nonce,
        &req.signature,
        &canonical_node_register_message(&req.request, req.timestamp_millis, &req.nonce),
        nonces,
    )
}

pub fn verify_transfer(
    req: &SignedTransferRequest,
    nonces: &NonceStore,
) -> Result<(), ControlAuthError> {
    verify_signature(
        &req.from,
        req.timestamp_millis,
        &req.nonce,
        &req.signature,
        &canonical_transfer_message(req),
        nonces,
    )
}

pub fn verify_node_heartbeat(
    headers: &HeaderMap,
    method: &str,
    path_and_query: &str,
    node_id: &str,
    nonces: &NonceStore,
) -> Result<(), ControlAuthError> {
    let did = header_str(headers, DID_HEADER)?;
    if did != node_id {
        return Err(ControlAuthError::IdentityMismatch);
    }

    let timestamp_millis = header_str(headers, DID_TIMESTAMP_HEADER)?
        .parse()
        .map_err(|_| ControlAuthError::InvalidFormat)?;
    let nonce = header_str(headers, DID_NONCE_HEADER)?;
    let signature = header_str(headers, DID_SIGNATURE_HEADER)?;

    verify_signature(
        did,
        timestamp_millis,
        nonce,
        signature,
        &canonical_node_heartbeat_message(method, path_and_query, node_id, timestamp_millis, nonce),
        nonces,
    )
}

pub fn canonical_node_register_message(
    req: &RegisterRequest,
    timestamp_millis: u64,
    nonce: &str,
) -> Vec<u8> {
    let mut out = b"headscale-control-register-v1\n".to_vec();
    append_field(&mut out, &req.id);
    append_field(&mut out, &req.name);
    append_field(&mut out, &req.wg_pubkey);
    append_field(&mut out, &req.endpoints.len().to_string());
    for endpoint in &req.endpoints {
        append_field(&mut out, endpoint);
    }
    append_field(&mut out, bool_field(req.capabilities.relay));
    append_field(&mut out, bool_field(req.capabilities.inference));
    append_field(&mut out, bool_field(req.capabilities.storage));
    append_field(&mut out, bool_field(req.capabilities.compute));
    append_field(&mut out, bool_field(req.capabilities.seed));
    append_field(&mut out, &timestamp_millis.to_string());
    append_field(&mut out, nonce);
    out
}

pub fn canonical_node_heartbeat_message(
    method: &str,
    path_and_query: &str,
    node_id: &str,
    timestamp_millis: u64,
    nonce: &str,
) -> Vec<u8> {
    let mut out = b"headscale-control-heartbeat-v1\n".to_vec();
    append_field(&mut out, method);
    append_field(&mut out, path_and_query);
    append_field(&mut out, node_id);
    append_field(&mut out, &timestamp_millis.to_string());
    append_field(&mut out, nonce);
    out
}

pub fn canonical_transfer_message(req: &SignedTransferRequest) -> Vec<u8> {
    let mut out = b"headscale-control-transfer-v1\n".to_vec();
    append_field(&mut out, &req.from);
    append_field(&mut out, &req.to);
    append_field(&mut out, &req.amount.to_string());
    append_field(&mut out, &req.description);
    append_field(&mut out, &req.timestamp_millis.to_string());
    append_field(&mut out, &req.nonce);
    out
}

pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn verify_signature(
    did: &str,
    timestamp_millis: u64,
    nonce: &str,
    signature: &str,
    message: &[u8],
    nonces: &NonceStore,
) -> Result<(), ControlAuthError> {
    if !is_valid_nonce(nonce) {
        return Err(ControlAuthError::InvalidFormat);
    }

    let now = now_millis();
    if timestamp_millis > now.saturating_add(SIGNATURE_WINDOW_MILLIS)
        || now.saturating_sub(timestamp_millis) > SIGNATURE_WINDOW_MILLIS
    {
        return Err(ControlAuthError::TimestampOutOfWindow);
    }

    let did = Did::parse(did).map_err(|_| ControlAuthError::InvalidFormat)?;
    let public_key = did
        .public_key()
        .map_err(|_| ControlAuthError::InvalidFormat)?;
    let sig_bytes = BASE64_STANDARD
        .decode(signature)
        .map_err(|_| ControlAuthError::InvalidSignature)?;
    let signature: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ControlAuthError::InvalidSignature)?;

    if !KeyPair::verify(&public_key, message, &signature) {
        return Err(ControlAuthError::InvalidSignature);
    }

    if !nonces.check_and_store(did.as_str(), nonce, timestamp_millis) {
        return Err(ControlAuthError::NonceReplay);
    }

    Ok(())
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, ControlAuthError> {
    headers
        .get(name)
        .ok_or(ControlAuthError::MissingSignature)?
        .to_str()
        .map_err(|_| ControlAuthError::InvalidFormat)
}

fn append_field(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(value.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(value.as_bytes());
    out.push(b'\n');
}

fn bool_field(value: bool) -> &'static str {
    if value { "1" } else { "0" }
}

fn is_valid_nonce(nonce: &str) -> bool {
    !nonce.is_empty() && nonce.len() <= 128 && nonce.bytes().all(|b| b.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use headscale_core::node::NodeCapabilities;

    fn signed_registration(keypair: &KeyPair, nonce: &str) -> SignedRegisterRequest {
        let request = RegisterRequest {
            id: keypair.did().to_string(),
            name: "node".to_string(),
            wg_pubkey: "bXlwdWJsaWNrZXltYXRlcmlhbC1tdXN0LWJlLTMyYg==".to_string(),
            endpoints: vec!["127.0.0.1:51820".to_string()],
            capabilities: NodeCapabilities::default(),
        };
        let timestamp_millis = now_millis();
        let message = canonical_node_register_message(&request, timestamp_millis, nonce);
        let signature = BASE64_STANDARD.encode(keypair.sign(&message));
        SignedRegisterRequest {
            request,
            signature,
            timestamp_millis,
            nonce: nonce.to_string(),
        }
    }

    #[test]
    fn registration_signature_verifies_once() {
        let keypair = KeyPair::generate();
        let store = NonceStore::new();
        let req = signed_registration(&keypair, "register-nonce");

        assert!(verify_node_registration(&req, &store).is_ok());
        assert!(matches!(
            verify_node_registration(&req, &store),
            Err(ControlAuthError::NonceReplay)
        ));
    }

    #[test]
    fn registration_signature_binds_node_id() {
        let keypair = KeyPair::generate();
        let store = NonceStore::new();
        let mut req = signed_registration(&keypair, "register-nonce-2");
        req.request.id = KeyPair::generate().did().to_string();

        assert!(matches!(
            verify_node_registration(&req, &store),
            Err(ControlAuthError::InvalidSignature)
        ));
    }

    #[test]
    fn heartbeat_signature_binds_path_and_node() {
        let keypair = KeyPair::generate();
        let store = NonceStore::new();
        let node_id = keypair.did().to_string();
        let timestamp_millis = now_millis();
        let nonce = "heartbeat-nonce";
        let path = format!("/api/v1/nodes/{node_id}/heartbeat");
        let message =
            canonical_node_heartbeat_message("POST", &path, &node_id, timestamp_millis, nonce);
        let signature = BASE64_STANDARD.encode(keypair.sign(&message));

        let mut headers = HeaderMap::new();
        headers.insert(DID_HEADER, HeaderValue::from_str(&node_id).unwrap());
        headers.insert(
            DID_TIMESTAMP_HEADER,
            HeaderValue::from_str(&timestamp_millis.to_string()).unwrap(),
        );
        headers.insert(DID_NONCE_HEADER, HeaderValue::from_static(nonce));
        headers.insert(
            DID_SIGNATURE_HEADER,
            HeaderValue::from_str(&signature).unwrap(),
        );

        assert!(verify_node_heartbeat(&headers, "POST", &path, &node_id, &store).is_ok());
        assert!(matches!(
            verify_node_heartbeat(&headers, "POST", "/wrong", &node_id, &store),
            Err(ControlAuthError::InvalidSignature | ControlAuthError::NonceReplay)
        ));
    }

    #[test]
    fn transfer_signature_binds_payer() {
        let keypair = KeyPair::generate();
        let store = NonceStore::new();
        let mut req = SignedTransferRequest {
            from: keypair.did().to_string(),
            to: KeyPair::generate().did().to_string(),
            amount: 42,
            description: "test".to_string(),
            signature: String::new(),
            timestamp_millis: now_millis(),
            nonce: "transfer-nonce".to_string(),
        };
        let message = canonical_transfer_message(&req);
        req.signature = BASE64_STANDARD.encode(keypair.sign(&message));

        assert!(verify_transfer(&req, &store).is_ok());

        let mut tampered = req.clone();
        tampered.from = KeyPair::generate().did().to_string();
        tampered.nonce = "transfer-nonce-2".to_string();
        assert!(matches!(
            verify_transfer(&tampered, &store),
            Err(ControlAuthError::InvalidSignature)
        ));
    }
}
