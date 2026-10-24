// Copyright (c) 2020, Juan Font
// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
// Pinned tailcfg declaration order at headscale-go's live map boundary.
// See UPSTREAM.md and retained upstream licenses.

//! Encode native fields in declaration order with Go zero/empty omission.
//! Named empty filter updates and existing extension fields remain. Captured raw
//! filters bypass Value encoding and occupy their declared response position.

use std::io;

use headscale_api_acl::{go_json_output, go_tailcfg_json};
use serde_json::Value;

use super::{
    debug_filters::{field, json},
    debug_nodes::{
        Kind, MapKey, MapValue, NODE, Omit, PATCH, RESOLVER, RESPONSE_VALUES, Spec,
        ordered_hostinfo,
    },
    go_time::DebugTime,
};

pub(super) fn encode(value: &Value, packet_filters: Option<&[u8]>) -> io::Result<Vec<u8>> {
    encode_with_derp(value, packet_filters, None)
}

pub(super) fn encode_with_derp(
    value: &Value,
    packet_filters: Option<&[u8]>,
    native_derp: Option<&Value>,
) -> io::Result<Vec<u8>> {
    let values = value
        .as_object()
        .ok_or_else(|| io::Error::other("map response is not an object"))?;
    let mut out = vec![b'{'];
    for &name in super::debug_json::FIELDS {
        let Some(value) = values.get(name) else {
            continue;
        };
        let value = if name == "DERPMap" {
            native_derp.unwrap_or(value)
        } else {
            value
        };
        let bytes = match name {
            "Node" => record(value, NODE, Some(false))?,
            "Peers" | "PeersChanged" => records(value, NODE, Some(true))?,
            "PeersChangedPatch" => records(value, PATCH, Some(true))?,
            "PacketFilter" => filters(value)?,
            "PacketFilters" => match packet_filters {
                Some(raw) => raw.to_vec(),
                None => named_filters(value)?,
            },
            _ => {
                let (_, kind, omit) = RESPONSE_VALUES
                    .iter()
                    .find(|(field, _, _)| *field == name)
                    .copied()
                    .ok_or_else(|| io::Error::other("unsupported map field"))?;
                if omitted(value, kind, omit)? {
                    continue;
                }
                encode_kind(value, kind)?
            }
        };
        field(&mut out, name, &bytes)?;
    }
    for (name, value) in values {
        if !super::debug_json::FIELDS.contains(&name.as_str()) {
            field(&mut out, name, &json(value)?)?;
        }
    }
    out.push(b'}');
    go_json_output::compact_html(&out).map_err(io::Error::other)
}

/// SSHActionHandler uses the same tailcfg action declaration and Go JSON
/// escaping as embedded map SSH rules, followed by Encoder.Encode's newline.
pub(super) fn encode_ssh_action(action: &super::wire::SshAction) -> io::Result<Vec<u8>> {
    let value = serde_json::to_value(action).map_err(io::Error::other)?;
    let encoded = record(&value, super::debug_schema::SSH_ACTION, None)?;
    let mut encoded = go_json_output::compact_html(&encoded).map_err(io::Error::other)?;
    encoded.push(b'\n');
    Ok(encoded)
}

fn record(value: &Value, schema: &[Spec], node: Option<bool>) -> io::Result<Vec<u8>> {
    let Some(values) = value.as_object() else {
        return json(value);
    };
    let mut out = vec![b'{'];
    for &(name, kind, omit) in schema {
        let default;
        let value = match values.get(name) {
            Some(value) => value,
            None if matches!(omit, Omit::Never) => {
                default = zero(kind);
                &default
            }
            None => continue,
        };
        if omitted(value, kind, omit)? {
            continue;
        }
        let bytes = if name == "CapMap" && node.is_some() {
            node_cap_map(value, node == Some(true))?
        } else {
            encode_kind(value, kind)?
        };
        field(&mut out, name, &bytes)?;
    }
    for (name, value) in values {
        if !schema.iter().any(|(field, _, _)| *field == name.as_str()) {
            field(&mut out, name, &json(value)?)?;
        }
    }
    out.push(b'}');
    Ok(out)
}

fn records(value: &Value, schema: &[Spec], node: Option<bool>) -> io::Result<Vec<u8>> {
    let Some(values) = value.as_array() else {
        return json(value);
    };
    let mut out = vec![b'['];
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            out.push(b',');
        }
        out.extend(record(value, schema, node)?);
    }
    out.push(b']');
    Ok(out)
}

fn encode_kind(value: &Value, kind: Kind) -> io::Result<Vec<u8>> {
    match kind {
        Kind::Int | Kind::OptionalInt => signed_integer(value),
        Kind::Ints => array(value, signed_integer),
        Kind::IDBoolMap => {
            let Some(values) = value.as_object() else {
                return json(value);
            };
            let normalized = values
                .iter()
                .map(|(name, value)| (signed_key(name), value))
                .collect::<std::collections::BTreeMap<_, _>>();
            json(&normalized)
        }
        Kind::Struct(schema) => record(value, schema, None),
        Kind::Records(schema, _) => records(value, schema, None),
        Kind::Resolvers => records(value, RESOLVER, None),
        Kind::Map(key, element) => {
            let Some(values) = value.as_object() else {
                return json(value);
            };
            let mut out = vec![b'{'];
            let values = values
                .iter()
                .map(|(name, value)| {
                    (
                        if matches!(key, MapKey::Int) {
                            signed_key(name)
                        } else {
                            name.clone()
                        },
                        value,
                    )
                })
                .collect::<std::collections::BTreeMap<_, _>>();
            for (name, value) in values {
                let bytes = match element {
                    MapValue::Record(schema) => record(value, schema, None)?,
                    MapValue::Records(schema, _) => records(value, schema, None)?,
                    MapValue::Float => super::debug_float::value(value)?,
                    MapValue::Text => json(value)?,
                };
                field(&mut out, &name, &bytes)?;
            }
            out.push(b'}');
            Ok(out)
        }
        Kind::Hostinfo if value.is_object() => ordered_hostinfo(value, go_tailcfg_json::HOST_INFO),
        Kind::Time | Kind::OptionalTime if value.is_string() => {
            let time = DebugTime::decode(&json(value)?).map_err(io::Error::other)?;
            json(&time.text().map_err(io::Error::other)?)
        }
        Kind::Float => super::debug_float::value(value),
        // Capability payloads are raw-message data, never typed float values.
        _ => json(value),
    }
}

fn signed_integer(value: &Value) -> io::Result<Vec<u8>> {
    // Headscale's stored NodeID/UserID are unsigned, while tailcfg uses
    // int64. Go's conversion retains the low 64 bits even above MaxInt64.
    if let Some(value) = value.as_u64() {
        json(&(value as i64))
    } else {
        json(value)
    }
}

fn signed_key(value: &str) -> String {
    value
        .parse::<u64>()
        .map_or_else(|_| value.to_owned(), |value| (value as i64).to_string())
}

fn zero(kind: Kind) -> Value {
    match kind {
        Kind::Text | Kind::Addr => Value::String(String::new()),
        Kind::Int => Value::from(0i64),
        Kind::Float => Value::from(0.0),
        Kind::Bool => Value::Bool(false),
        Kind::Key(kind) => Value::String(kind.zero_text().into()),
        Kind::Time => Value::String("0001-01-01T00:00:00Z".into()),
        _ => Value::Null,
    }
}

fn omitted(value: &Value, kind: Kind, omit: Omit) -> io::Result<bool> {
    if matches!(omit, Omit::Never) {
        return Ok(false);
    }
    if value.is_null() {
        return Ok(!matches!(kind, Kind::OptBool));
    }
    if matches!(omit, Omit::Nil) {
        return Ok(false);
    }
    if matches!(omit, Omit::Zero) {
        return Ok(match kind {
            Kind::Time | Kind::OptionalTime => DebugTime::decode(&json(value)?)
                .map_err(io::Error::other)?
                .is_zero(),
            Kind::Key(kind) | Kind::OptionalKey(kind) => value.as_str() == Some(kind.zero_text()),
            // Pointers to ordinary bool/int/address values have no IsZero
            // method. A non-nil pointer stays nonzero even if it points to 0.
            Kind::OptionalBool
            | Kind::OptionalInt
            | Kind::OptionalAddr
            | Kind::Struct(_)
            | Kind::Hostinfo
            | Kind::Prefixes
            | Kind::Strings
            | Kind::Records(_, _) => false,
            _ => {
                value.as_bool() == Some(false)
                    || value.as_f64() == Some(0.0)
                    || value.as_str() == Some("")
            }
        });
    }
    Ok(match kind {
        // Both explicit true and false are nonempty underlying opt.Bool
        // strings. Its explicit-unset case was retained above as null.
        Kind::OptBool => value.as_str() == Some(""),
        Kind::OptionalBool
        | Kind::OptionalInt
        | Kind::OptionalAddr
        | Kind::OptionalKey(_)
        | Kind::Time
        | Kind::OptionalTime
        | Kind::Struct(_)
        | Kind::Hostinfo => false,
        _ => {
            value.as_bool() == Some(false)
                || value.as_f64() == Some(0.0)
                || value.as_str() == Some("")
                || value.as_array().is_some_and(Vec::is_empty)
                || value.as_object().is_some_and(serde_json::Map::is_empty)
        }
    })
}

fn node_cap_map(value: &Value, peer: bool) -> io::Result<Vec<u8>> {
    let Some(values) = value.as_object() else {
        return json(value);
    };
    let mut out = vec![b'{'];
    for (name, value) in values {
        // PeerCapMap's no-argument capability values are nil. Self flags
        // already carry exact nilness from the captured policy attributes;
        // preserve TailNode's explicit empty baseline slices here.
        let nil = peer && value.as_array().is_some_and(Vec::is_empty);
        let bytes = if nil { b"null".to_vec() } else { json(value)? };
        field(&mut out, name, &bytes)?;
    }
    out.push(b'}');
    Ok(out)
}

pub(super) fn filters(value: &Value) -> io::Result<Vec<u8>> {
    let Some(values) = value.as_array() else {
        return json(value);
    };
    let mut out = vec![b'['];
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            out.push(b',');
        }
        out.extend(filter_rule(value)?);
    }
    out.push(b']');
    Ok(out)
}

fn filter_rule(value: &Value) -> io::Result<Vec<u8>> {
    ordered(
        value,
        &["SrcIPs", "SrcBits", "DstPorts", "IPProto", "CapGrant"],
        |name, value| match name {
            "DstPorts" => array(value, |value| {
                ordered(value, &["IP", "Bits", "Ports"], |name, value| {
                    if name == "Ports" {
                        ordered(value, &["First", "Last"], |_, value| json(value))
                    } else {
                        json(value)
                    }
                })
            }),
            "CapGrant" => array(value, |value| {
                ordered(value, &["Dsts", "Caps", "CapMap"], |_, value| json(value))
            }),
            _ => json(value),
        },
    )
}

fn named_filters(value: &Value) -> io::Result<Vec<u8>> {
    let Some(values) = value.as_object() else {
        return json(value);
    };
    let mut out = vec![b'{'];
    for (name, value) in values {
        field(&mut out, name, &filters(value)?)?;
    }
    out.push(b'}');
    Ok(out)
}

fn array(value: &Value, encode: impl Fn(&Value) -> io::Result<Vec<u8>>) -> io::Result<Vec<u8>> {
    let Some(values) = value.as_array() else {
        return json(value);
    };
    let mut out = vec![b'['];
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            out.push(b',');
        }
        out.extend(encode(value)?);
    }
    out.push(b']');
    Ok(out)
}

fn ordered(
    value: &Value,
    names: &[&str],
    encode: impl Fn(&str, &Value) -> io::Result<Vec<u8>>,
) -> io::Result<Vec<u8>> {
    let Some(values) = value.as_object() else {
        return json(value);
    };
    let mut out = vec![b'{'];
    for &name in names {
        if let Some(value) = values.get(name) {
            field(&mut out, name, &encode(name, value)?)?;
        }
    }
    for (name, value) in values {
        if !names.contains(&name.as_str()) {
            field(&mut out, name, &json(value)?)?;
        }
    }
    out.push(b'}');
    Ok(out)
}
