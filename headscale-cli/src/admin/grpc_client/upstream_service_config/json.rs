// Copyright 2010 The Go Authors. All rights reserved.
// Copyright 2017 gRPC authors.
// Typed JSON field handling adapts Go encoding/json/decode.go and grpc-go
// v1.81.1 service_config.go, resolver/dns and codes/codes.go. BSD and Apache
// notices are retained in LICENSE-GO-STDLIB and LICENSE-GRPC-GO/NOTICE-GRPC-GO.

//! Decode known struct fields in source order before reducing them to values.
//! Go validates every duplicate occurrence, folds incoming field names, merges
//! repeated struct pointers, and distinguishes pointer null from scalar null.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::{balancer_name, duration_nanos, invalid, retry_code};

mod scan;

pub(super) struct Choice {
    pub(super) value: Value,
    pub(super) service_config: Option<Vec<u8>>,
}

struct Fields<'a>(Vec<(String, scan::Raw<'a>)>);

#[derive(Clone, Copy)]
enum Schema {
    Choice,
    Config,
    Method,
    Name,
    Retry,
    Throttle,
    Health,
    PickFirst,
}

#[derive(Clone, Copy)]
enum Kind {
    String,
    Bool,
    Int,
    Int64,
    Float,
    Duration,
    Code,
    Raw,
    Struct(Schema),
    Array(&'static Self),
}

struct Field {
    name: &'static str,
    kind: Kind,
    reset_null: bool,
}

impl Field {
    const fn pointer(name: &'static str, kind: Kind) -> Self {
        Self {
            name,
            kind,
            reset_null: true,
        }
    }
    const fn scalar(name: &'static str, kind: Kind) -> Self {
        Self {
            name,
            kind,
            reset_null: false,
        }
    }
}

fn fields(schema: Schema) -> &'static [Field] {
    use Kind::{Array, Bool, Code, Duration, Float, Int, Int64, Raw, String, Struct};
    const CHOICE: &[Field] = &[
        Field::pointer("clientLanguage", Array(&String)),
        Field::pointer("clientHostName", Array(&String)),
        Field::pointer("percentage", Int),
        Field::pointer("serviceConfig", Raw),
    ];
    const CONFIG: &[Field] = &[
        Field::pointer("loadBalancingPolicy", String),
        Field::pointer("loadBalancingConfig", Raw),
        Field::pointer("methodConfig", Array(&Struct(Schema::Method))),
        Field::pointer("retryThrottling", Struct(Schema::Throttle)),
        Field::pointer("healthCheckConfig", Struct(Schema::Health)),
    ];
    const METHOD: &[Field] = &[
        Field::pointer("name", Array(&Struct(Schema::Name))),
        Field::pointer("waitForReady", Bool),
        Field::pointer("timeout", Duration),
        Field::pointer("maxRequestMessageBytes", Int64),
        Field::pointer("maxResponseMessageBytes", Int64),
        Field::pointer("retryPolicy", Struct(Schema::Retry)),
    ];
    const NAME: &[Field] = &[
        Field::scalar("service", String),
        Field::scalar("method", String),
    ];
    const RETRY: &[Field] = &[
        Field::scalar("maxAttempts", Int),
        Field::scalar("initialBackoff", Duration),
        Field::scalar("maxBackoff", Duration),
        Field::scalar("backoffMultiplier", Float),
        Field::pointer("retryableStatusCodes", Array(&Code)),
    ];
    const THROTTLE: &[Field] = &[
        Field::scalar("maxTokens", Float),
        Field::scalar("tokenRatio", Float),
    ];
    const HEALTH: &[Field] = &[Field::scalar("serviceName", String)];
    const PICKFIRST: &[Field] = &[Field::scalar("shuffleAddressList", Bool)];
    match schema {
        Schema::Choice => CHOICE,
        Schema::Config => CONFIG,
        Schema::Method => METHOD,
        Schema::Name => NAME,
        Schema::Retry => RETRY,
        Schema::Throttle => THROTTLE,
        Schema::Health => HEALTH,
        Schema::PickFirst => PICKFIRST,
    }
}

fn matches_field(input: &str, expected: &str) -> bool {
    // All known fields are ASCII. These are the only non-ASCII SimpleFold
    // cycles which reach ASCII in Go's encoding/json/fold.go.
    input
        .chars()
        .map(|ch| match ch {
            '\u{017f}' => 'S',
            '\u{212a}' => 'K',
            ch => ch.to_ascii_uppercase(),
        })
        .eq(expected.chars().map(|ch| ch.to_ascii_uppercase()))
}

fn object(raw: &[u8]) -> Result<Fields<'_>, String> {
    scan::object(raw).map(Fields)
}

enum Decoded {
    Scalar(Value),
    Object(BTreeMap<String, Self>),
    Array { slots: Vec<Self>, length: usize },
}

impl Decoded {
    fn into_value(self) -> Value {
        match self {
            Self::Scalar(value) => value,
            Self::Object(fields) => Value::Object(
                fields
                    .into_iter()
                    .map(|(name, value)| (name, value.into_value()))
                    .collect(),
            ),
            Self::Array { slots, length } => Value::Array(
                slots
                    .into_iter()
                    .take(length)
                    .map(Self::into_value)
                    .collect(),
            ),
        }
    }
}

fn normalize(raw: &[u8], kind: Kind, previous: Option<Decoded>) -> Result<Decoded, String> {
    let raw = scan::trim(raw);
    match kind {
        Kind::Struct(schema) => {
            if raw == b"null" {
                return Ok(previous.unwrap_or_else(|| Decoded::Object(BTreeMap::new())));
            }
            let mut result = match previous {
                Some(Decoded::Object(map)) => map,
                _ => BTreeMap::new(),
            };
            for (name, value) in object(raw)?.0 {
                let Some(field) = fields(schema)
                    .iter()
                    .find(|field| matches_field(&name, field.name))
                else {
                    continue;
                };
                if value.get() == b"null" {
                    if field.reset_null {
                        result.insert(field.name.into(), Decoded::Scalar(Value::Null));
                    } else if matches!(field.kind, Kind::Duration) {
                        return Err(invalid());
                    }
                    continue;
                }
                let old = result.remove(field.name);
                result.insert(field.name.into(), normalize(value.get(), field.kind, old)?);
            }
            Ok(Decoded::Object(result))
        }
        Kind::Array(item) => {
            if raw == b"null" {
                return Ok(Decoded::Scalar(Value::Null));
            }
            let values = scan::array(raw)?;
            let length = values.len();
            let mut slots = match previous {
                Some(Decoded::Array { slots, .. }) if length != 0 => slots,
                _ => Vec::new(),
            };
            // encoding/json decodes into existing backing elements before
            // truncating the slice. Keep hidden suffix slots across shrink/
            // regrow; an empty [] or null resets them. Exact Go capacity need
            // not be modeled: growth visits every old slot before reallocating.
            for (index, value) in values.into_iter().enumerate() {
                let old = slots
                    .get_mut(index)
                    .map(|slot| std::mem::replace(slot, Decoded::Scalar(Value::Null)));
                let value = normalize(value.get(), *item, old)?;
                if index < slots.len() {
                    slots[index] = value;
                } else {
                    slots.push(value);
                }
            }
            Ok(Decoded::Array { slots, length })
        }
        _ => scalar(raw, kind, previous),
    }
}

fn scalar(raw: &[u8], kind: Kind, previous: Option<Decoded>) -> Result<Decoded, String> {
    if raw == b"null" && !matches!(kind, Kind::Duration) {
        let zero = match kind {
            Kind::String => Value::String(String::new()),
            Kind::Bool => Value::Bool(false),
            Kind::Int | Kind::Int64 | Kind::Float | Kind::Code => Value::from(0),
            _ => Value::Null,
        };
        return Ok(previous.unwrap_or(Decoded::Scalar(zero)));
    }
    let value = match kind {
        Kind::Raw => Value::Null, // RawMessage bytes are retained separately.
        Kind::Duration => {
            let value = scan::unquote(raw)?;
            duration_nanos(&value)?;
            Value::String(value)
        }
        Kind::Code => {
            // Code.UnmarshalJSON accepts only raw ASCII names or unsigned
            // integer tokens. Escapes and numeric -0 are not accepted.
            let text = std::str::from_utf8(raw).map_err(|_| invalid())?;
            let value = if text.starts_with('"') {
                let name = text
                    .strip_prefix('"')
                    .and_then(|text| text.strip_suffix('"'))
                    .ok_or_else(invalid)?;
                Value::String(name.into())
            } else {
                Value::from(text.parse::<u32>().map_err(|_| invalid())?)
            };
            retry_code(&value)?;
            value
        }
        Kind::Int | Kind::Int64 => {
            let value = std::str::from_utf8(raw)
                .map_err(|_| invalid())?
                .parse::<i64>()
                .map_err(|_| invalid())?;
            if matches!(kind, Kind::Int) && isize::try_from(value).is_err() {
                return Err(invalid());
            }
            Value::from(value)
        }
        Kind::String => Value::String(scan::unquote(raw)?),
        Kind::Bool => match raw {
            b"true" => Value::Bool(true),
            b"false" => Value::Bool(false),
            _ => return Err(invalid()),
        },
        Kind::Float => {
            let value = std::str::from_utf8(raw)
                .map_err(|_| invalid())?
                .parse::<f64>()
                .map_err(|_| invalid())?;
            Value::Number(serde_json::Number::from_f64(value).ok_or_else(invalid)?)
        }
        Kind::Struct(_) | Kind::Array(_) => return Err(invalid()),
    };
    Ok(Decoded::Scalar(value))
}

pub(super) fn choices(source: &[u8]) -> Result<Vec<Choice>, String> {
    if scan::trim(source) == b"null" {
        return Ok(Vec::new());
    }
    let values = scan::array(source)?;
    values
        .into_iter()
        .map(|raw| {
            let value = normalize(raw.get(), Kind::Struct(Schema::Choice), None)?.into_value();
            let mut service_config = None;
            if raw.get() != b"null" {
                for (name, raw) in object(raw.get())?.0 {
                    if matches_field(&name, "serviceConfig") {
                        service_config = (raw.get() != b"null").then(|| raw.get().to_vec());
                    }
                }
            }
            Ok(Choice {
                value,
                service_config,
            })
        })
        .collect()
}

pub(super) fn config(source: &[u8]) -> Result<Value, String> {
    let mut result = normalize(source, Kind::Struct(Schema::Config), None)?.into_value();
    let mut balancing = None;
    if scan::trim(source) != b"null" {
        for (name, raw) in object(source)?.0 {
            if matches_field(&name, "loadBalancingConfig") {
                balancing = (raw.get() != b"null").then_some(raw);
            }
        }
    }
    // RawMessage fields are interpreted only after the complete outer typed
    // decode. An earlier invalid-shaped RawMessage may be overwritten.
    if let Some(raw) = balancing {
        let value = balancers(raw.get())?;
        if let Some(fields) = result.as_object_mut() {
            fields.insert("loadBalancingConfig".into(), value);
        }
    }
    Ok(result)
}

fn balancers(raw: &[u8]) -> Result<Value, String> {
    let entries = scan::array(raw)?;
    // Go first unmarshals the whole []map[string]RawMessage, even if the first
    // policy is supported. Invalid later element types still reject the list.
    let entries = entries
        .into_iter()
        .map(|entry| {
            if entry.get() == b"null" {
                return Ok(BTreeMap::new());
            }
            Ok(object(entry.get())?
                .0
                .into_iter()
                .collect::<BTreeMap<_, _>>())
        })
        .collect::<Result<Vec<_>, String>>()?;
    let mut selected = false;
    let mut result = Vec::with_capacity(entries.len());
    for entry in entries {
        let single = entry.len() == 1;
        let mut normalized = Map::new();
        for (name, raw) in entry {
            let policy = balancer_name(&name);
            let value = if !selected && single && policy == "pick_first" {
                selected = true;
                normalize(raw.get(), Kind::Struct(Schema::PickFirst), None)?.into_value()
            } else {
                if !selected && single && policy == "round_robin" {
                    selected = true;
                }
                // Unselected/unknown configurations are opaque RawMessages.
                Value::Null
            };
            normalized.insert(name, value);
        }
        result.push(Value::Object(normalized));
    }
    Ok(Value::Array(result))
}
