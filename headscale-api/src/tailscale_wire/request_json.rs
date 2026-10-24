//! Fresh control requests decoded with Go's tailcfg struct semantics first.
//!
//! Public wire field types stay unchanged. The shared decoder scans unknown
//! values, folds field names and resolves nulls/duplicates before projection.

use headscale_api_acl::{
    go_key::PublicKeyKind,
    go_tailcfg_json::{self, Field, HOST_INFO, Kind},
};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use super::go_time::json_time;
use super::wire::{MapRequest, RegisterRequest};

const OAUTH_TOKEN: &[Field] = &[
    ("access_token", Kind::String),
    ("token_type", Kind::String),
    ("refresh_token", Kind::String),
    ("expiry", Kind::JsonText(json_time)),
];

const REGISTER_AUTH: &[Field] = &[
    ("AuthKey", Kind::String),
    ("Oauth2Token", Kind::Struct(OAUTH_TOKEN)),
];

const REGISTER_REQUEST: &[Field] = &[
    ("Version", Kind::Int),
    ("NodeKey", Kind::Key(PublicKeyKind::Node)),
    ("OldNodeKey", Kind::Key(PublicKeyKind::Node)),
    ("NLKey", Kind::Key(PublicKeyKind::NodeLock)),
    ("Auth", Kind::Struct(REGISTER_AUTH)),
    ("Expiry", Kind::JsonText(json_time)),
    ("Followup", Kind::String),
    ("Hostinfo", Kind::Struct(HOST_INFO)),
    ("Ephemeral", Kind::Bool),
    ("NodeKeySignature", Kind::Bytes),
    // The wire projection applies SignatureType's non-idempotent Go text
    // conversion once, after duplicate/null field handling has completed.
    ("SignatureType", Kind::String),
    ("Timestamp", Kind::OptionalJsonText(json_time)),
    ("DeviceCert", Kind::Bytes),
    ("Signature", Kind::Bytes),
    ("Tailnet", Kind::String),
];

const MAP_REQUEST: &[Field] = &[
    ("Version", Kind::Int),
    ("Compress", Kind::String),
    ("KeepAlive", Kind::Bool),
    ("NodeKey", Kind::Key(PublicKeyKind::Node)),
    ("DiscoKey", Kind::Key(PublicKeyKind::Disco)),
    (
        "HardwareAttestationKey",
        Kind::Key(PublicKeyKind::HardwareAttestation),
    ),
    ("HardwareAttestationKeySignature", Kind::Bytes),
    (
        "HardwareAttestationKeySignatureTimestamp",
        Kind::JsonText(json_time),
    ),
    ("Stream", Kind::Bool),
    ("Hostinfo", Kind::Struct(HOST_INFO)),
    ("MapSessionHandle", Kind::String),
    ("MapSessionSeq", Kind::Int),
    ("Endpoints", Kind::Endpoints),
    ("EndpointTypes", Kind::Ints),
    ("TKAHead", Kind::String),
    ("ReadOnly", Kind::Bool),
    ("OmitPeers", Kind::Bool),
    ("DebugFlags", Kind::Strings),
    ("ConnectionHandleForTest", Kind::String),
];

pub(super) struct RequestError {
    pub(super) version: u32,
    pub(super) message: String,
}

fn request_value(source: &[u8], fields: &[Field]) -> Result<Value, RequestError> {
    let mut value =
        go_tailcfg_json::struct_value(source, fields).map_err(|error| RequestError {
            version: error
                .version()
                .and_then(|version| u32::try_from(version).ok())
                .unwrap_or_default(),
            message: error.to_string(),
        })?;
    // JSON null into a fresh non-pointer Go request leaves its zero struct.
    if value.is_null() {
        value = Value::Object(Map::new());
    }
    Ok(value)
}

fn project<T: DeserializeOwned>(value: Value) -> Result<T, RequestError> {
    let version = value
        .get("Version")
        .and_then(Value::as_u64)
        .and_then(|version| u32::try_from(version).ok())
        .unwrap_or_default();
    serde_json::from_value(value).map_err(|_| RequestError {
        version,
        // Wider Go ints can exceed this public projection. Do not turn a
        // projection failure into a default or echo auth/token fields.
        message: "control request cannot be represented by the wire projection".into(),
    })
}

pub(super) fn register(source: &[u8]) -> Result<(RegisterRequest, Value), RequestError> {
    let value = request_value(source, REGISTER_REQUEST)?;
    let hostinfo = value.get("Hostinfo").cloned().unwrap_or(Value::Null);
    Ok((project(value)?, hostinfo))
}

pub(super) fn map(source: &[u8]) -> Result<(MapRequest, Option<Value>), String> {
    let value = request_value(source, MAP_REQUEST).map_err(|error| error.message)?;
    let hostinfo = value.get("Hostinfo").cloned();
    let request = project(value).map_err(|error| error.message)?;
    Ok((request, hostinfo))
}
