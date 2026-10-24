// Copyright (c) Tailscale Inc & contributors
// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause

//! Pinned tailcfg JSON schemas and Go struct decoding for database and wire use.
//!
//! The pinned tailcfg schema is bounded; unknown subtrees are scanned, never
//! materialized. Known fields retain Go's input ordering, case folding, null
//! rules and duplicate-object merge behavior. Built-in errors do not echo field values.

use std::collections::HashMap;

use serde_json::{Map, Number, Value};

use base64::{
    Engine as _,
    engine::{
        DecodePaddingMode,
        general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD},
    },
};
use thiserror::Error;

use crate::{go_json, go_key::PublicKeyKind};

#[derive(Debug, Error)]
#[error("{message}")]
pub struct DecodeError {
    message: String,
    fatal: bool,
    version: Option<i64>,
}

impl DecodeError {
    fn new(message: String, fatal: bool) -> Self {
        Self {
            message,
            fatal,
            version: None,
        }
    }

    fn fatal(message: String) -> Self {
        Self::new(message, true)
    }

    /// Version reached by Go's decoder before it returned this error. Ordinary
    /// type failures are saved while decoding continues; custom unmarshaler
    /// errors stop immediately and supersede an earlier saved type failure.
    pub fn version(&self) -> Option<i64> {
        self.version
    }
}

type Result<T> = std::result::Result<T, DecodeError>;

#[derive(Clone, Copy)]
pub enum Kind {
    String,
    OptionalString,
    JsonText(fn(&[u8]) -> std::result::Result<String, String>),
    OptionalJsonText(fn(&[u8]) -> std::result::Result<String, String>),
    Bool,
    OptBool,
    Int,
    Uint,
    Port,
    Float,
    Strings,
    Ints,
    Prefixes,
    Endpoints,
    Services,
    Bytes,
    Key(PublicKeyKind),
    FloatMap,
    Struct(&'static [Field]),
}

pub type Field = (&'static str, Kind);

/// Pinned SignatureType.UnmarshalText followed by String on a 64-bit Go host.
/// Its fmt.Sscanf success branch intentionally selects SignatureUnknown;
/// a scan error retains the value assigned before a missing/mismatched ')'.
/// This operation is not idempotent and must run only once during decoding.
pub fn signature_type_text(input: &str) -> String {
    fn fmt_space(ch: char) -> bool {
        matches!(ch, '\u{0009}' | '\u{000b}'..='\u{000d}' | ' ' | '\u{0085}'
            | '\u{00a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}'
            | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}')
    }

    let value = match input {
        "signature-none" => 0,
        "signature-v1" => 2,
        "signature-v2" => 3,
        _ => {
            let Some(input) = input.strip_prefix("signature-unknown(") else {
                return "signature-none".into();
            };
            // Sscanf's SkipSpace rejects newline; all its other whitespace
            // ranges are accepted before the signed decimal conversion.
            let input = input.trim_start_matches(fmt_space);
            let bytes = input.as_bytes();
            let start = usize::from(matches!(bytes.first(), Some(b'+' | b'-')));
            let mut end = start;
            while bytes.get(end).is_some_and(u8::is_ascii_digit) {
                end += 1;
            }
            if end == start {
                return "signature-none".into();
            }
            let Ok(value) = input[..end].parse::<i64>() else {
                return "signature-none".into();
            };
            if bytes.get(end) == Some(&b')') {
                1
            } else {
                value
            }
        }
    };
    match value {
        0 => "signature-none".into(),
        1 => "signature-unknown".into(),
        2 => "signature-v1".into(),
        3 => "signature-v2".into(),
        _ => format!("signature-unknown({value})"),
    }
}

const SERVICE: &[Field] = &[
    ("Proto", Kind::String),
    ("Port", Kind::Port),
    ("Description", Kind::String),
];

const LOCATION: &[Field] = &[
    ("Country", Kind::String),
    ("CountryCode", Kind::String),
    ("City", Kind::String),
    ("CityCode", Kind::String),
    ("Latitude", Kind::Float),
    ("Longitude", Kind::Float),
    ("Priority", Kind::Int),
];

const TPM: &[Field] = &[
    ("Manufacturer", Kind::String),
    ("Vendor", Kind::String),
    ("Model", Kind::Int),
    ("FirmwareVersion", Kind::Uint),
    ("SpecRevision", Kind::Int),
    ("FamilyIndicator", Kind::String),
];

const NET_INFO: &[Field] = &[
    ("MappingVariesByDestIP", Kind::OptBool),
    ("WorkingIPv6", Kind::OptBool),
    ("OSHasIPv6", Kind::OptBool),
    ("WorkingUDP", Kind::OptBool),
    ("WorkingICMPv4", Kind::OptBool),
    ("HavePortMap", Kind::Bool),
    ("UPnP", Kind::OptBool),
    ("PMP", Kind::OptBool),
    ("PCP", Kind::OptBool),
    ("PreferredDERP", Kind::Int),
    ("LinkType", Kind::String),
    ("DERPLatency", Kind::FloatMap),
    ("FirewallMode", Kind::String),
];

pub const HOST_INFO: &[Field] = &[
    ("IPNVersion", Kind::String),
    ("FrontendLogID", Kind::String),
    ("BackendLogID", Kind::String),
    ("OS", Kind::String),
    ("OSVersion", Kind::String),
    ("Container", Kind::OptBool),
    ("Env", Kind::String),
    ("Distro", Kind::String),
    ("DistroVersion", Kind::String),
    ("DistroCodeName", Kind::String),
    ("App", Kind::String),
    ("Desktop", Kind::OptBool),
    ("Package", Kind::String),
    ("DeviceModel", Kind::String),
    ("PushDeviceToken", Kind::String),
    ("Hostname", Kind::String),
    ("ShieldsUp", Kind::Bool),
    ("ShareeNode", Kind::Bool),
    ("NoLogsNoSupport", Kind::Bool),
    ("WireIngress", Kind::Bool),
    ("IngressEnabled", Kind::Bool),
    ("AllowsUpdate", Kind::Bool),
    ("Machine", Kind::String),
    ("GoArch", Kind::String),
    ("GoArchVar", Kind::String),
    ("GoVersion", Kind::String),
    ("RoutableIPs", Kind::Prefixes),
    ("RequestTags", Kind::Strings),
    ("WoLMACs", Kind::Strings),
    ("Services", Kind::Services),
    ("NetInfo", Kind::Struct(NET_INFO)),
    ("sshHostKeys", Kind::Strings),
    ("Cloud", Kind::String),
    ("Userspace", Kind::OptBool),
    ("UserspaceRouter", Kind::OptBool),
    ("AppConnector", Kind::OptBool),
    ("ServicesHash", Kind::String),
    ("PeerRelay", Kind::Bool),
    ("ExitNodeID", Kind::String),
    ("Location", Kind::Struct(LOCATION)),
    ("TPM", Kind::Struct(TPM)),
    ("StateEncrypted", Kind::OptBool),
];

fn invalid() -> DecodeError {
    DecodeError::new("invalid JSON field value".into(), false)
}

pub fn folded_equal(left: &str, right: &str) -> bool {
    super::go_unicode::equal_fold(left, right)
}

fn float(source: &[u8]) -> Result<Value> {
    let value = std::str::from_utf8(source)
        .map_err(|_| invalid())?
        .parse::<f64>()
        .map_err(|_| invalid())?;
    Number::from_f64(value)
        .map(Value::Number)
        .ok_or_else(invalid)
}

fn scalar(source: &[u8], kind: Kind) -> Result<Value> {
    let text = || std::str::from_utf8(source).map_err(|_| invalid());
    match kind {
        Kind::String | Kind::OptionalString => go_json::unquote(source)
            .map(Value::String)
            .map_err(|_| invalid()),
        Kind::JsonText(decode) | Kind::OptionalJsonText(decode) => decode(source)
            .map(Value::String)
            .map_err(DecodeError::fatal),
        Kind::Key(kind) => {
            let input = go_json::unquote(source).map_err(|_| invalid())?;
            kind.parse_text(&input)
                .map(Value::String)
                .map_err(|error| DecodeError::fatal(error.to_string()))
        }
        Kind::Bool | Kind::OptBool => match source {
            b"true" => Ok(Value::Bool(true)),
            b"false" => Ok(Value::Bool(false)),
            _ if matches!(kind, Kind::OptBool) => {
                Err(DecodeError::fatal("invalid opt.Bool JSON value".into()))
            }
            _ => Err(invalid()),
        },
        Kind::Int => text()?
            .parse::<i64>()
            .map(Value::from)
            .map_err(|_| invalid()),
        Kind::Uint => text()?
            .parse::<u64>()
            .map(Value::from)
            .map_err(|_| invalid()),
        Kind::Port => text()?
            .parse::<u16>()
            .map(Value::from)
            .map_err(|_| invalid()),
        Kind::Float => float(source),
        _ => Err(invalid()),
    }
}

#[derive(Default)]
struct ObjectState {
    value: Map<String, Value>,
    // Keep slots beyond the current length until an empty array/null resets
    // the slice, just as encoding/json reuses Go's backing array.
    slice_buffers: HashMap<&'static str, Vec<Value>>,
    nested: HashMap<&'static str, Self>,
}

fn byte_slice(source: &[u8], buffer: &mut Vec<Value>) -> Result<Value> {
    let bytes = if source.first() == Some(&b'"') {
        let text = go_json::unquote(source).map_err(|_| invalid())?;
        // Go StdEncoding ignores CR/LF and permits non-zero unused bits.
        // It still requires padding for an incomplete final quantum.
        let text = text
            .bytes()
            .filter(|byte| !matches!(byte, b'\r' | b'\n'))
            .collect::<Vec<_>>();
        let engine = GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            GeneralPurposeConfig::new()
                .with_decode_allow_trailing_bits(true)
                .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
        );
        let bytes = engine
            .decode(text)
            .map_err(|_| DecodeError::new("invalid base64 JSON value".into(), false))?;
        *buffer = bytes.iter().copied().map(Value::from).collect();
        bytes
    } else {
        let input = go_json::array(source).map_err(|_| invalid())?;
        if input.is_empty() {
            buffer.clear();
        }
        for (index, raw) in input.iter().enumerate() {
            if index == buffer.len() {
                buffer.push(Value::from(0u8));
            }
            if raw.get() != b"null" {
                let value = std::str::from_utf8(raw.get())
                    .map_err(|_| invalid())?
                    .parse::<u8>()
                    .map_err(|_| invalid())?;
                buffer[index] = Value::from(value);
            }
        }
        buffer[..input.len()]
            .iter()
            .map(|value| {
                value
                    .as_u64()
                    .and_then(|value| u8::try_from(value).ok())
                    .ok_or_else(invalid)
            })
            .collect::<Result<Vec<_>>>()?
    };
    Ok(Value::String(STANDARD.encode(bytes)))
}

#[derive(Default)]
struct DecodeContext {
    saved_error: Option<DecodeError>,
}

impl DecodeContext {
    fn remember(&mut self, error: DecodeError) -> Result<()> {
        if error.fatal {
            return Err(error);
        }
        if self.saved_error.is_none() {
            self.saved_error = Some(error);
        }
        Ok(())
    }
}

fn field_value(
    source: &[u8],
    name: &'static str,
    kind: Kind,
    state: &mut ObjectState,
    context: &mut DecodeContext,
) -> Result<()> {
    if source == b"null" {
        match kind {
            Kind::OptBool => {
                state.value.insert(name.into(), Value::Null);
            }
            Kind::Strings
            | Kind::Ints
            | Kind::Prefixes
            | Kind::Endpoints
            | Kind::Services
            | Kind::Bytes
            | Kind::FloatMap
            | Kind::Struct(_)
            | Kind::OptionalString
            | Kind::OptionalJsonText(_) => {
                state.value.remove(name);
                state.slice_buffers.remove(name);
                state.nested.remove(name);
            }
            // Null leaves ordinary scalar/TextUnmarshaler values intact.
            _ => {}
        }
        return Ok(());
    }
    match kind {
        Kind::Struct(fields) => {
            let nested = state.nested.entry(name).or_default();
            struct_fields(source, fields, nested, context)?;
            state
                .value
                .insert(name.into(), Value::Object(nested.value.clone()));
        }
        Kind::FloatMap => {
            let nested = state
                .value
                .entry(name)
                .or_insert_with(|| Value::Object(Map::new()));
            let nested = nested.as_object_mut().ok_or_else(invalid)?;
            for (key, raw) in go_json::object(source).map_err(|_| invalid())? {
                let number = if raw.get() == b"null" {
                    Value::from(0.0)
                } else {
                    match float(raw.get()) {
                        Ok(value) => value,
                        Err(error) => {
                            context.remember(error)?;
                            // Go decodes every map value into a fresh slot.
                            Value::from(0.0)
                        }
                    }
                };
                nested.insert(key, number);
            }
        }
        Kind::Bytes => {
            let buffer = state.slice_buffers.entry(name).or_default();
            state.value.insert(name.into(), byte_slice(source, buffer)?);
        }
        Kind::Strings | Kind::Ints | Kind::Prefixes | Kind::Endpoints | Kind::Services => {
            let input = go_json::array(source).map_err(|_| invalid())?;
            let buffer = state.slice_buffers.entry(name).or_default();
            if input.is_empty() {
                buffer.clear();
            }
            for (index, raw) in input.iter().enumerate() {
                if index == buffer.len() {
                    buffer.push(match kind {
                        Kind::Services => Value::Object(Map::new()),
                        Kind::Ints => Value::from(0i64),
                        _ => Value::String(String::new()),
                    });
                }
                if raw.get() == b"null" {
                    continue;
                }
                let result = (|| {
                    if matches!(kind, Kind::Services) {
                        let value = buffer[index].as_object().ok_or_else(invalid)?.clone();
                        let mut item = ObjectState {
                            value,
                            ..ObjectState::default()
                        };
                        struct_fields(raw.get(), SERVICE, &mut item, context)?;
                        Ok(Value::Object(item.value))
                    } else if matches!(kind, Kind::Ints) {
                        scalar(raw.get(), Kind::Int)
                    } else {
                        let text = go_json::unquote(raw.get()).map_err(|_| invalid())?;
                        let text = match kind {
                            Kind::Prefixes => crate::go_netip::prefix_text(&text),
                            Kind::Endpoints => crate::go_netip::addr_port_text(&text),
                            _ => Some(text),
                        }
                        .ok_or_else(|| DecodeError::fatal("invalid JSON network text".into()))?;
                        Ok(Value::String(text))
                    }
                })();
                match result {
                    Ok(value) => buffer[index] = value,
                    Err(error) => context.remember(error)?,
                }
            }
            state
                .value
                .insert(name.into(), Value::Array(buffer[..input.len()].to_vec()));
        }
        _ => {
            state.value.insert(name.into(), scalar(source, kind)?);
        }
    }
    Ok(())
}

fn struct_fields(
    source: &[u8],
    fields: &[Field],
    state: &mut ObjectState,
    context: &mut DecodeContext,
) -> Result<()> {
    for (input_name, raw) in go_json::object(source).map_err(|_| invalid())? {
        let field = fields
            .iter()
            .find(|(name, _)| *name == input_name)
            .or_else(|| {
                fields
                    .iter()
                    .find(|(name, _)| folded_equal(&input_name, name))
            });
        if let Some(&(name, kind)) = field
            && let Err(error) = field_value(raw.get(), name, kind, state, context)
        {
            context.remember(error)?;
        }
    }
    Ok(())
}

/// Decode a fresh struct/pointer value while scanning unknown subtrees.
pub fn struct_value(source: &[u8], fields: &[Field]) -> Result<Value> {
    if go_json::trim(source) == b"null" {
        return Ok(Value::Null);
    }
    let mut state = ObjectState::default();
    let mut context = DecodeContext::default();
    let error = struct_fields(source, fields, &mut state, &mut context)
        .err()
        .or(context.saved_error);
    if let Some(mut error) = error {
        error.version = state.value.get("Version").and_then(Value::as_i64);
        Err(error)
    } else {
        Ok(Value::Object(state.value))
    }
}

/// Gorm does not unmarshal SQL NULL or present zero-length JSON text.
pub fn hostinfo_value(source: &[u8]) -> Result<Value> {
    if source.is_empty() {
        return Ok(Value::Null);
    }
    struct_value(source, HOST_INFO)
}

fn marshaled_fields(values: &Map<String, Value>, fields: &[Field], service: bool) -> Result<Value> {
    let mut output = Map::new();
    for &(name, kind) in fields {
        let required = service && matches!(name, "Proto" | "Port");
        let default;
        let value = match values.get(name) {
            Some(value) => value,
            None if required => {
                default = if name == "Proto" {
                    Value::String(String::new())
                } else {
                    Value::from(0u16)
                };
                &default
            }
            None => continue,
        };
        let omit = match kind {
            Kind::String => value.as_str().is_some_and(str::is_empty),
            Kind::Bool => value == &Value::Bool(false),
            Kind::Int | Kind::Uint | Kind::Port | Kind::Float => value.as_f64() == Some(0.0),
            Kind::Strings | Kind::Prefixes | Kind::Services => {
                value.as_array().is_some_and(Vec::is_empty)
            }
            Kind::FloatMap => value.as_object().is_some_and(Map::is_empty),
            // Explicitly unset opt.Bool marshals null and is not a zero string;
            // structs are never omitted by this rule.
            _ => false,
        };
        if omit && !required {
            continue;
        }
        let value = match kind {
            Kind::Struct(schema) => {
                marshaled_fields(value.as_object().ok_or_else(invalid)?, schema, false)?
            }
            Kind::Services => Value::Array(
                value
                    .as_array()
                    .ok_or_else(invalid)?
                    .iter()
                    .map(|value| {
                        marshaled_fields(value.as_object().ok_or_else(invalid)?, SERVICE, true)
                    })
                    .collect::<Result<Vec<_>>>()?,
            ),
            _ => value.clone(),
        };
        output.insert(name.into(), value);
    }
    Ok(Value::Object(output))
}

/// Typed Hostinfo JSON emission: scalar zero fields omit, non-nil nested
/// pointers retain {}, opt.Bool explicit unset retains null, and Service's
/// Proto/Port fields remain present. SQL nil is represented by Value::Null.
pub fn marshal_hostinfo_value(value: &Value) -> Result<Value> {
    let bytes = serde_json::to_vec(value).map_err(|_| invalid())?;
    let value = hostinfo_value(&bytes)?;
    if value.is_null() {
        Ok(Value::Null)
    } else {
        marshaled_fields(value.as_object().ok_or_else(invalid)?, HOST_INFO, false)
    }
}

// These comparisons consume values already decoded with this module's schema.
// Missing scalar fields are Go zero values, while a missing slice/map/pointer
// is nil. In particular, opt.Bool's zero string and explicit "unset" (JSON
// null) are distinct even though both project to Rust Option<bool>::None.
// Floats compare exactly because Go's `==` on float64 does.
#[allow(clippy::float_cmp)]
fn equal_field(kind: Kind, left: Option<&Value>, right: Option<&Value>) -> bool {
    match kind {
        Kind::String => {
            left.and_then(Value::as_str).unwrap_or_default()
                == right.and_then(Value::as_str).unwrap_or_default()
        }
        Kind::Bool => {
            left.and_then(Value::as_bool).unwrap_or_default()
                == right.and_then(Value::as_bool).unwrap_or_default()
        }
        Kind::Int | Kind::Port => {
            left.and_then(Value::as_i64).unwrap_or_default()
                == right.and_then(Value::as_i64).unwrap_or_default()
        }
        Kind::Uint => {
            left.and_then(Value::as_u64).unwrap_or_default()
                == right.and_then(Value::as_u64).unwrap_or_default()
        }
        Kind::Float => {
            left.and_then(Value::as_f64).unwrap_or_default()
                == right.and_then(Value::as_f64).unwrap_or_default()
        }
        Kind::Struct(fields) => equal_struct(
            left.unwrap_or(&Value::Null),
            right.unwrap_or(&Value::Null),
            fields,
        ),
        Kind::Services => match (left, right) {
            (Some(Value::Array(left)), Some(Value::Array(right))) => {
                left.len() == right.len()
                    && left
                        .iter()
                        .zip(right)
                        .all(|(left, right)| equal_struct(left, right, SERVICE))
            }
            _ => left == right,
        },
        _ => left == right,
    }
}

fn equal_struct(left: &Value, right: &Value, fields: &[Field]) -> bool {
    match (left.as_object(), right.as_object()) {
        (Some(left), Some(right)) => fields
            .iter()
            .all(|(name, kind)| equal_field(*kind, left.get(*name), right.get(*name))),
        _ => left.is_null() && right.is_null(),
    }
}

/// Node.Equal uses full reflect-style Hostinfo equality, including NetInfo
/// fields ignored by the incoming map-update comparison below. Inputs are
/// already decoded with HOST_INFO; nil views remain Value::Null.
pub fn node_hostinfo_equal(left: &Value, right: &Value) -> bool {
    equal_struct(left, right, HOST_INFO)
}

/// Pinned headscale map Hostinfo comparison. Reflect-style equality outside
/// NetInfo retains nil-versus-empty slices/maps; NetInfo.BasicallyEqual skips
/// DERP latency, and headscale compares PreferredDERP separately.
pub fn map_hostinfo_equal(left: &Value, right: &Value) -> bool {
    let (Some(left), Some(right)) = (left.as_object(), right.as_object()) else {
        return left.is_null() && right.is_null();
    };
    HOST_INFO.iter().all(|(name, kind)| {
        if *name != "NetInfo" {
            return equal_field(*kind, left.get(*name), right.get(*name));
        }
        let (left, right) = (left.get(*name), right.get(*name));
        match (
            left.and_then(Value::as_object),
            right.and_then(Value::as_object),
        ) {
            (Some(left), Some(right)) => NET_INFO.iter().all(|(name, kind)| {
                matches!(*name, "PreferredDERP" | "DERPLatency")
                    || equal_field(*kind, left.get(*name), right.get(*name))
            }),
            _ => left.is_none() && right.is_none(),
        }
    })
}

/// Hostinfo fields read by peers. Go views.SliceEqual and servicesEqual treat
/// nil and empty slices alike here; the full storage comparison above does not.
pub fn peer_hostinfo_equal(left: &Value, right: &Value) -> bool {
    let (Some(left), Some(right)) = (left.as_object(), right.as_object()) else {
        return left.is_null() && right.is_null();
    };
    [
        "Hostname",
        "OS",
        "Services",
        "sshHostKeys",
        "Location",
        "AppConnector",
        "RoutableIPs",
    ]
    .into_iter()
    .all(|name| {
        let kind = HOST_INFO.iter().find(|field| field.0 == name).unwrap().1;
        let (left, right) = (left.get(name), right.get(name));
        if matches!(kind, Kind::Strings | Kind::Prefixes | Kind::Services)
            && left.and_then(Value::as_array).is_none_or(Vec::is_empty)
            && right.and_then(Value::as_array).is_none_or(Vec::is_empty)
        {
            return true;
        }
        equal_field(kind, left, right)
    })
}
