// Copyright (c) Tailscale Inc & contributors
// Copyright 2010 The Go Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// Pinned tailcfg Node/PeerChange/HostinfoView and Go encoding/json semantics.
// See UPSTREAM.md and retained upstream licenses.

//! Native debug nodes and nested response records keep pointer/slice/map state
//! outside the public wire types.

use std::{collections::BTreeMap, io};

use base64::{
    Engine as _,
    engine::{
        DecodePaddingMode,
        general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD},
    },
};
use headscale_api_acl::{go_json, go_key::PublicKeyKind, go_netip, go_tailcfg_json};
use serde_json::{Number, Value};

use super::{
    debug_filters::{CapabilityMap, Element, Integer, Prefix, Slice, Text, field, json},
    go_time::DebugTime,
};

#[derive(Clone, Copy)]
pub(super) enum Kind {
    Text,
    Int,
    Float,
    Bool,
    OptBool,
    Key(PublicKeyKind),
    Time,
    OptionalKey(PublicKeyKind),
    OptionalTime,
    OptionalBool,
    OptionalInt,
    OptionalAddr,
    Addr,
    Strings,
    Ints,
    IDBoolMap,
    Prefixes,
    Endpoints,
    Addresses,
    Bytes,
    Hostinfo,
    CapMap,
    Resolvers,
    Struct(&'static [Spec]),
    Records(&'static [Spec], bool),
    Map(MapKey, MapValue),
}

#[derive(Clone, Copy)]
pub(super) enum MapKey {
    Text,
    Int,
}

#[derive(Clone, Copy)]
pub(super) enum MapValue {
    Text,
    Float,
    Record(&'static [Spec]),
    Records(&'static [Spec], bool),
}

#[derive(Clone, Copy)]
pub(super) enum Omit {
    Never,
    Zero,
    Nil,
    Empty,
}

pub(super) type Spec = (&'static str, Kind, Omit);

// Declaration order and JSON tags from pinned tailcfg, including signed IDs
// and CapabilityVersion/int values on the pinned 64-bit Go targets.
pub(super) const NODE: &[Spec] = &[
    ("ID", Kind::Int, Omit::Never),
    ("StableID", Kind::Text, Omit::Never),
    ("Name", Kind::Text, Omit::Never),
    ("User", Kind::Int, Omit::Never),
    ("Sharer", Kind::Int, Omit::Zero),
    ("Key", Kind::Key(PublicKeyKind::Node), Omit::Never),
    ("KeyExpiry", Kind::Time, Omit::Zero),
    ("KeySignature", Kind::Bytes, Omit::Empty),
    ("Machine", Kind::Key(PublicKeyKind::Machine), Omit::Zero),
    ("DiscoKey", Kind::Key(PublicKeyKind::Disco), Omit::Zero),
    ("Addresses", Kind::Prefixes, Omit::Never),
    ("AllowedIPs", Kind::Prefixes, Omit::Nil),
    ("Endpoints", Kind::Endpoints, Omit::Empty),
    ("DERP", Kind::Text, Omit::Zero),
    ("HomeDERP", Kind::Int, Omit::Zero),
    ("Hostinfo", Kind::Hostinfo, Omit::Zero),
    ("Created", Kind::Time, Omit::Zero),
    ("Cap", Kind::Int, Omit::Zero),
    ("Tags", Kind::Strings, Omit::Empty),
    ("PrimaryRoutes", Kind::Prefixes, Omit::Empty),
    ("LastSeen", Kind::OptionalTime, Omit::Nil),
    ("Online", Kind::OptionalBool, Omit::Nil),
    ("MachineAuthorized", Kind::Bool, Omit::Empty),
    ("Capabilities", Kind::Strings, Omit::Empty),
    ("CapMap", Kind::CapMap, Omit::Empty),
    ("UnsignedPeerAPIOnly", Kind::Bool, Omit::Zero),
    ("ComputedName", Kind::Text, Omit::Zero),
    ("ComputedNameWithHost", Kind::Text, Omit::Zero),
    ("DataPlaneAuditLogID", Kind::Text, Omit::Zero),
    ("Expired", Kind::Bool, Omit::Zero),
    (
        "SelfNodeV4MasqAddrForThisPeer",
        Kind::OptionalAddr,
        Omit::Nil,
    ),
    (
        "SelfNodeV6MasqAddrForThisPeer",
        Kind::OptionalAddr,
        Omit::Nil,
    ),
    ("IsWireGuardOnly", Kind::Bool, Omit::Zero),
    ("IsJailed", Kind::Bool, Omit::Zero),
    ("ExitNodeDNSResolvers", Kind::Resolvers, Omit::Empty),
];

pub(super) const PATCH: &[Spec] = &[
    ("NodeID", Kind::Int, Omit::Never),
    ("DERPRegion", Kind::Int, Omit::Zero),
    ("Cap", Kind::Int, Omit::Zero),
    ("CapMap", Kind::CapMap, Omit::Empty),
    ("Endpoints", Kind::Endpoints, Omit::Empty),
    ("Key", Kind::OptionalKey(PublicKeyKind::Node), Omit::Zero),
    ("KeySignature", Kind::Bytes, Omit::Empty),
    (
        "DiscoKey",
        Kind::OptionalKey(PublicKeyKind::Disco),
        Omit::Zero,
    ),
    ("Online", Kind::OptionalBool, Omit::Nil),
    ("LastSeen", Kind::OptionalTime, Omit::Zero),
    ("KeyExpiry", Kind::OptionalTime, Omit::Zero),
];

pub(super) const RESOLVER: &[Spec] = &[
    ("Addr", Kind::Text, Omit::Empty),
    ("BootstrapResolution", Kind::Addresses, Omit::Empty),
    ("UseWithExitNode", Kind::Bool, Omit::Empty),
];

pub(super) const RESPONSE_VALUES: &[Spec] = &[
    ("MapSessionHandle", Kind::Text, Omit::Empty),
    ("Seq", Kind::Int, Omit::Empty),
    ("KeepAlive", Kind::Bool, Omit::Empty),
    (
        "PingRequest",
        Kind::Struct(super::debug_schema::PING),
        Omit::Nil,
    ),
    ("PopBrowserURL", Kind::Text, Omit::Empty),
    (
        "DERPMap",
        Kind::Struct(super::debug_schema::DERP),
        Omit::Nil,
    ),
    ("PeersRemoved", Kind::Ints, Omit::Empty),
    ("PeerSeenChange", Kind::IDBoolMap, Omit::Empty),
    ("OnlineChange", Kind::IDBoolMap, Omit::Empty),
    (
        "DNSConfig",
        Kind::Struct(super::debug_schema::DNS),
        Omit::Nil,
    ),
    ("Domain", Kind::Text, Omit::Empty),
    ("CollectServices", Kind::OptBool, Omit::Empty),
    (
        "UserProfiles",
        Kind::Records(super::debug_schema::PROFILE, false),
        Omit::Empty,
    ),
    ("Health", Kind::Strings, Omit::Empty),
    (
        "DisplayMessages",
        Kind::Map(MapKey::Text, MapValue::Record(super::debug_schema::DISPLAY)),
        Omit::Empty,
    ),
    (
        "SSHPolicy",
        Kind::Struct(super::debug_schema::SSH_POLICY),
        Omit::Nil,
    ),
    ("ControlTime", Kind::OptionalTime, Omit::Nil),
    ("TKAInfo", Kind::Struct(super::debug_schema::TKA), Omit::Nil),
    ("DomainDataPlaneAuditLogID", Kind::Text, Omit::Empty),
    ("Debug", Kind::Struct(super::debug_schema::DEBUG), Omit::Nil),
    (
        "ControlDialPlan",
        Kind::Struct(super::debug_schema::DIAL_PLAN),
        Omit::Nil,
    ),
    (
        "ClientVersion",
        Kind::Struct(super::debug_schema::CLIENT_VERSION),
        Omit::Nil,
    ),
    ("DefaultAutoUpdate", Kind::OptBool, Omit::Empty),
];

#[derive(Default)]
struct Address(Text);

impl Element for Address {
    fn decode(&mut self, source: &[u8]) -> io::Result<()> {
        if source != b"null" {
            let text = go_json::unquote(source).map_err(io::Error::other)?;
            self.0.0 = go_netip::addr_text(&text)
                .ok_or_else(|| io::Error::other("invalid JSON network text"))?;
        }
        Ok(())
    }

    fn encode(&self) -> io::Result<Vec<u8>> {
        self.0.encode()
    }
}

#[derive(Default)]
struct Endpoint(Text);

impl Element for Endpoint {
    fn decode(&mut self, source: &[u8]) -> io::Result<()> {
        if source != b"null" {
            let text = go_json::unquote(source).map_err(io::Error::other)?;
            self.0.0 = go_netip::addr_port_text(&text)
                .ok_or_else(|| io::Error::other("invalid JSON network text"))?;
        }
        Ok(())
    }

    fn encode(&self) -> io::Result<Vec<u8>> {
        self.0.encode()
    }
}

#[derive(Default)]
struct Bytes {
    slots: Vec<u8>,
    len: usize,
}

impl Bytes {
    fn decode(&mut self, source: &[u8]) -> io::Result<()> {
        match source.first() {
            Some(b'n') => *self = Self::default(),
            Some(b'"') => {
                let text = go_json::unquote(source).map_err(io::Error::other)?;
                let text = text
                    .bytes()
                    .filter(|b| !matches!(b, b'\r' | b'\n'))
                    .collect::<Vec<_>>();
                let engine = GeneralPurpose::new(
                    &base64::alphabet::STANDARD,
                    GeneralPurposeConfig::new()
                        .with_decode_allow_trailing_bits(true)
                        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
                );
                self.slots = engine.decode(text).map_err(io::Error::other)?;
                self.len = self.slots.len();
            }
            _ => {
                let input = go_json::array(source).map_err(io::Error::other)?;
                if input.is_empty() {
                    self.slots = Vec::new();
                }
                for (index, raw) in input.iter().enumerate() {
                    if index == self.slots.len() {
                        self.slots.push(0);
                    }
                    if raw.get() != b"null" {
                        self.slots[index] = std::str::from_utf8(raw.get())
                            .map_err(io::Error::other)?
                            .parse()
                            .map_err(io::Error::other)?;
                    }
                }
                self.len = input.len();
            }
        }
        Ok(())
    }

    fn encode(&self) -> io::Result<Vec<u8>> {
        json(&STANDARD.encode(&self.slots[..self.len]))
    }
}

enum State {
    Scalar(Value),
    Time(Option<DebugTime>),
    Strings(Slice<Text>),
    Ints(Slice<Integer>),
    IDBoolMap(BTreeMap<i64, bool>),
    Prefixes(Slice<Prefix>),
    Endpoints(Slice<Endpoint>),
    Addresses(Slice<Address>),
    Bytes(Bytes),
    Hostinfo(Option<Value>),
    CapMap(CapabilityMap),
    Resolvers(Slice<Pointer<Resolver>>),
    Struct(Option<Box<Record>>),
    Records(Records),
    Map(MapState),
}

impl State {
    fn new(kind: Kind) -> Self {
        match kind {
            Kind::Text | Kind::OptBool | Kind::Addr => Self::Scalar(Value::String(String::new())),
            Kind::Int => Self::Scalar(Value::from(0i64)),
            Kind::Float => Self::Scalar(Value::Number(Number::from_f64(0.0).expect("finite zero"))),
            Kind::Bool => Self::Scalar(Value::Bool(false)),
            Kind::Key(kind) => Self::Scalar(Value::String(kind.zero_text().into())),
            Kind::OptionalKey(_) | Kind::OptionalAddr | Kind::OptionalBool | Kind::OptionalInt => {
                Self::Scalar(Value::Null)
            }
            Kind::Time => Self::Time(Some(DebugTime::default())),
            Kind::OptionalTime => Self::Time(None),
            Kind::Strings => Self::Strings(Slice::default()),
            Kind::Ints => Self::Ints(Slice::default()),
            Kind::IDBoolMap => Self::IDBoolMap(BTreeMap::new()),
            Kind::Prefixes => Self::Prefixes(Slice::default()),
            Kind::Endpoints => Self::Endpoints(Slice::default()),
            Kind::Addresses => Self::Addresses(Slice::default()),
            Kind::Bytes => Self::Bytes(Bytes::default()),
            Kind::Hostinfo => Self::Hostinfo(None),
            Kind::CapMap => Self::CapMap(CapabilityMap::default()),
            Kind::Resolvers => Self::Resolvers(Slice::default()),
            Kind::Struct(_) => Self::Struct(None),
            Kind::Records(schema, pointers) => Self::Records(Records::new(schema, pointers)),
            Kind::Map(key, value) => Self::Map(MapState::new(key, value)),
        }
    }

    fn decode(&mut self, kind: Kind, source: &[u8]) -> io::Result<()> {
        match self {
            Self::Scalar(value) => {
                if source == b"null" {
                    if matches!(
                        kind,
                        Kind::OptionalKey(_)
                            | Kind::OptionalAddr
                            | Kind::OptionalBool
                            | Kind::OptionalInt
                            | Kind::OptBool
                    ) {
                        *value = Value::Null;
                    }
                    return Ok(());
                }
                *value = match kind {
                    Kind::Text => {
                        Value::String(go_json::unquote(source).map_err(io::Error::other)?)
                    }
                    Kind::Int | Kind::OptionalInt => Value::from(
                        std::str::from_utf8(source)
                            .map_err(io::Error::other)?
                            .parse::<i64>()
                            .map_err(io::Error::other)?,
                    ),
                    Kind::Float => float(source)?,
                    Kind::Bool | Kind::OptionalBool | Kind::OptBool => match source {
                        b"true" => Value::Bool(true),
                        b"false" => Value::Bool(false),
                        _ => return Err(io::Error::other("invalid JSON boolean")),
                    },
                    Kind::Key(kind) | Kind::OptionalKey(kind) => {
                        let text = go_json::unquote(source).map_err(io::Error::other)?;
                        Value::String(kind.parse_text(&text).map_err(io::Error::other)?)
                    }
                    Kind::OptionalAddr | Kind::Addr => {
                        let text = go_json::unquote(source).map_err(io::Error::other)?;
                        Value::String(
                            go_netip::addr_text(&text)
                                .ok_or_else(|| io::Error::other("invalid JSON network text"))?,
                        )
                    }
                    _ => unreachable!("scalar field kind"),
                };
            }
            Self::Time(value) => {
                if source == b"null" {
                    if matches!(kind, Kind::OptionalTime) {
                        *value = None;
                    }
                } else {
                    *value = Some(DebugTime::decode(source).map_err(io::Error::other)?);
                }
            }
            Self::Strings(value) => value.decode(source)?,
            Self::Ints(value) => value.decode(source)?,
            Self::IDBoolMap(value) => {
                if source == b"null" {
                    value.clear();
                } else {
                    for (name, raw) in go_json::object(source).map_err(io::Error::other)? {
                        let id = name.parse::<i64>().map_err(io::Error::other)?;
                        let next = match raw.get() {
                            b"true" => true,
                            b"false" | b"null" => false,
                            _ => return Err(io::Error::other("invalid JSON boolean")),
                        };
                        value.insert(id, next);
                    }
                }
            }
            Self::Prefixes(value) => value.decode(source)?,
            Self::Endpoints(value) => value.decode(source)?,
            Self::Addresses(value) => value.decode(source)?,
            Self::Bytes(value) => value.decode(source)?,
            Self::Hostinfo(value) => {
                if value.is_some() {
                    return Err(io::Error::other("already initialized"));
                }
                // HostinfoView always installs a valid *Hostinfo on success,
                // even when null was decoded into the fresh ordinary struct.
                let decoded = go_tailcfg_json::hostinfo_value(source).map_err(io::Error::other)?;
                *value = Some(if decoded.is_null() {
                    Value::Object(serde_json::Map::default())
                } else {
                    decoded
                });
            }
            Self::CapMap(value) => value.decode(source)?,
            Self::Resolvers(value) => value.decode(source)?,
            Self::Struct(value) => {
                if source == b"null" {
                    *value = None;
                } else {
                    let Kind::Struct(schema) = kind else {
                        unreachable!("struct schema")
                    };
                    value
                        .get_or_insert_with(|| Box::new(Record::new(schema)))
                        .decode(source)?;
                }
            }
            Self::Records(value) => value.decode(source)?,
            Self::Map(value) => value.decode(source)?,
        }
        Ok(())
    }

    fn omitted(&self, kind: Kind, omit: Omit) -> bool {
        if matches!(omit, Omit::Never) {
            return false;
        }
        match self {
            Self::Scalar(value) => {
                if value.is_null() {
                    // opt.Bool's explicit unset is a nonempty underlying
                    // string and marshals null even with omitempty.
                    return !matches!(kind, Kind::OptBool);
                }
                if matches!(omit, Omit::Nil) {
                    return false;
                }
                match kind {
                    Kind::Key(kind) | Kind::OptionalKey(kind) => {
                        value.as_str() == Some(kind.zero_text())
                    }
                    Kind::OptBool => value.as_str() == Some(""),
                    Kind::Float => value.as_f64() == Some(0.0),
                    _ => {
                        value == &Value::Bool(false)
                            || value.as_i64() == Some(0)
                            || value.as_str() == Some("")
                    }
                }
            }
            Self::Time(value) => value
                .as_ref()
                .is_none_or(|value| !matches!(omit, Omit::Nil) && value.is_zero()),
            Self::Strings(value) => value.is_empty(),
            Self::Ints(value) => value.is_empty(),
            Self::IDBoolMap(value) => value.is_empty(),
            Self::Prefixes(value) => {
                if matches!(omit, Omit::Nil) {
                    value.is_nil()
                } else {
                    value.is_empty()
                }
            }
            Self::Endpoints(value) => value.is_empty(),
            Self::Addresses(value) => value.is_empty(),
            Self::Bytes(value) => value.len == 0,
            Self::Hostinfo(value) => value.is_none(),
            Self::CapMap(value) => value.is_empty(),
            Self::Resolvers(value) => value.is_empty(),
            Self::Struct(value) => value.is_none(),
            Self::Records(value) => {
                if matches!(omit, Omit::Nil) {
                    value.len.is_none()
                } else {
                    value.is_empty()
                }
            }
            Self::Map(value) => {
                if matches!(omit, Omit::Nil) {
                    value.nil
                } else {
                    value.values.is_empty()
                }
            }
        }
    }

    fn encode(&self) -> io::Result<Vec<u8>> {
        match self {
            Self::Scalar(value) => super::debug_float::value(value),
            Self::Time(Some(value)) => json(&value.text().map_err(io::Error::other)?),
            Self::Time(None) | Self::Hostinfo(None) => Ok(b"null".to_vec()),
            Self::Strings(value) => value.encode(),
            Self::Ints(value) => value.encode(),
            Self::IDBoolMap(value) => json(
                &value
                    .iter()
                    .map(|(id, online)| (id.to_string(), *online))
                    .collect::<BTreeMap<_, _>>(),
            ),
            Self::Prefixes(value) => value.encode(),
            Self::Endpoints(value) => value.encode(),
            Self::Addresses(value) => value.encode(),
            Self::Bytes(value) => value.encode(),
            Self::Hostinfo(Some(value)) => {
                let value =
                    go_tailcfg_json::marshal_hostinfo_value(value).map_err(io::Error::other)?;
                ordered_hostinfo(&value, go_tailcfg_json::HOST_INFO)
            }
            Self::CapMap(value) => value.encode(),
            Self::Resolvers(value) => value.encode(),
            Self::Struct(value) => value
                .as_ref()
                .map_or_else(|| Ok(b"null".to_vec()), |value| value.encode()),
            Self::Records(value) => value.encode(),
            Self::Map(value) => value.encode(),
        }
    }
}

pub(super) fn ordered_hostinfo(
    value: &Value,
    schema: &[go_tailcfg_json::Field],
) -> io::Result<Vec<u8>> {
    let mut out = vec![b'{'];
    for &(name, kind) in schema {
        let Some(value) = value.get(name) else {
            continue;
        };
        let bytes = match kind {
            go_tailcfg_json::Kind::Struct(fields) => ordered_hostinfo(value, fields)?,
            go_tailcfg_json::Kind::Services => {
                const FIELDS: &[go_tailcfg_json::Field] = &[
                    ("Proto", go_tailcfg_json::Kind::String),
                    ("Port", go_tailcfg_json::Kind::Port),
                    ("Description", go_tailcfg_json::Kind::String),
                ];
                let mut bytes = vec![b'['];
                for (index, service) in value
                    .as_array()
                    .ok_or_else(|| io::Error::other("invalid typed services"))?
                    .iter()
                    .enumerate()
                {
                    if index != 0 {
                        bytes.push(b',');
                    }
                    bytes.extend(ordered_hostinfo(service, FIELDS)?);
                }
                bytes.push(b']');
                bytes
            }
            _ => super::debug_float::value(value)?,
        };
        field(&mut out, name, &bytes)?;
    }
    out.push(b'}');
    Ok(out)
}

fn float(source: &[u8]) -> io::Result<Value> {
    let value = std::str::from_utf8(source)
        .map_err(io::Error::other)?
        .parse::<f64>()
        .map_err(io::Error::other)?;
    Number::from_f64(value)
        .map(Value::Number)
        .ok_or_else(|| io::Error::other("invalid JSON float"))
}

struct Records {
    schema: &'static [Spec],
    pointers: bool,
    slots: Vec<Option<Record>>,
    len: Option<usize>,
}

impl Records {
    fn new(schema: &'static [Spec], pointers: bool) -> Self {
        Self {
            schema,
            pointers,
            slots: Vec::new(),
            len: None,
        }
    }

    fn is_empty(&self) -> bool {
        self.len.unwrap_or_default() == 0
    }

    fn decode(&mut self, source: &[u8]) -> io::Result<()> {
        if source == b"null" {
            self.slots = Vec::new();
            self.len = None;
            return Ok(());
        }
        let input = go_json::array(source).map_err(io::Error::other)?;
        if input.is_empty() {
            self.slots = Vec::new();
        }
        for (index, raw) in input.iter().enumerate() {
            if index == self.slots.len() {
                self.slots.push(if self.pointers {
                    None
                } else {
                    Some(Record::new(self.schema))
                });
            }
            if self.pointers && raw.get() == b"null" {
                self.slots[index] = None;
            } else {
                self.slots[index]
                    .get_or_insert_with(|| Record::new(self.schema))
                    .decode(raw.get())?;
            }
        }
        self.len = Some(input.len());
        Ok(())
    }

    fn encode(&self) -> io::Result<Vec<u8>> {
        let Some(len) = self.len else {
            return Ok(b"null".to_vec());
        };
        let mut out = vec![b'['];
        for (index, slot) in self.slots[..len].iter().enumerate() {
            if index != 0 {
                out.push(b',');
            }
            if let Some(value) = slot {
                out.extend(value.encode()?);
            } else {
                out.extend_from_slice(b"null");
            }
        }
        out.push(b']');
        Ok(out)
    }
}

struct MapState {
    key: MapKey,
    value: MapValue,
    nil: bool,
    values: BTreeMap<String, State>,
}

impl MapState {
    fn new(key: MapKey, value: MapValue) -> Self {
        Self {
            key,
            value,
            nil: true,
            values: BTreeMap::new(),
        }
    }

    fn decode(&mut self, source: &[u8]) -> io::Result<()> {
        if source == b"null" {
            self.values.clear();
            self.nil = true;
            return Ok(());
        }
        self.nil = false;
        for (name, raw) in go_json::object(source).map_err(io::Error::other)? {
            let name = match self.key {
                MapKey::Text => name,
                MapKey::Int => name.parse::<i64>().map_err(io::Error::other)?.to_string(),
            };
            let kind = match self.value {
                MapValue::Text => Kind::Text,
                MapValue::Float => Kind::Float,
                MapValue::Record(schema) => Kind::Struct(schema),
                MapValue::Records(schema, pointers) => Kind::Records(schema, pointers),
            };
            // Go decodes each map entry into a fresh zero value. Repeated
            // outer objects merge keys, while repeated keys replace values.
            let mut value = State::new(kind);
            value.decode(kind, raw.get())?;
            self.values.insert(name, value);
        }
        Ok(())
    }

    fn encode(&self) -> io::Result<Vec<u8>> {
        if self.nil {
            return Ok(b"null".to_vec());
        }
        let mut out = vec![b'{'];
        for (name, value) in &self.values {
            field(&mut out, name, &value.encode()?)?;
        }
        out.push(b'}');
        Ok(out)
    }
}

struct Record {
    schema: &'static [Spec],
    fields: BTreeMap<&'static str, State>,
}

impl Record {
    fn new(schema: &'static [Spec]) -> Self {
        Self {
            schema,
            fields: BTreeMap::new(),
        }
    }

    fn decode(&mut self, source: &[u8]) -> io::Result<()> {
        if source == b"null" {
            return Ok(());
        }
        for (input, raw) in go_json::object(source).map_err(io::Error::other)? {
            let spec = self
                .schema
                .iter()
                .find(|(name, _, _)| *name == input)
                .or_else(|| {
                    self.schema
                        .iter()
                        .find(|(name, _, _)| go_tailcfg_json::folded_equal(&input, name))
                });
            if let Some(&(name, kind, _)) = spec {
                self.fields
                    .entry(name)
                    .or_insert_with(|| State::new(kind))
                    .decode(kind, raw.get())?;
            }
        }
        Ok(())
    }

    fn encode_fields(&self) -> io::Result<BTreeMap<String, Vec<u8>>> {
        let mut out = BTreeMap::new();
        for &(name, kind, omit) in self.schema {
            let default;
            let value = match self.fields.get(name) {
                Some(value) => value,
                None if matches!(omit, Omit::Never) => {
                    default = State::new(kind);
                    &default
                }
                None => continue,
            };
            if !value.omitted(kind, omit) {
                out.insert(name.into(), value.encode()?);
            }
        }
        Ok(out)
    }

    fn encode(&self) -> io::Result<Vec<u8>> {
        let values = self.encode_fields()?;
        let mut out = vec![b'{'];
        for &(name, _, _) in self.schema {
            if let Some(value) = values.get(name) {
                field(&mut out, name, value)?;
            }
        }
        out.push(b'}');
        Ok(out)
    }
}

pub(super) struct ResponseValues(Record);

impl Default for ResponseValues {
    fn default() -> Self {
        Self(Record::new(RESPONSE_VALUES))
    }
}

impl ResponseValues {
    pub(super) fn decode(&mut self, name: &str, source: &[u8]) -> io::Result<()> {
        let Some(&(name, kind, _)) = RESPONSE_VALUES.iter().find(|(field, _, _)| *field == name)
        else {
            return Err(io::Error::other("unsupported native response field"));
        };
        self.0
            .fields
            .entry(name)
            .or_insert_with(|| State::new(kind))
            .decode(kind, source)?;
        Ok(())
    }

    pub(super) fn encode_fields(&self) -> io::Result<BTreeMap<String, Vec<u8>>> {
        self.0.encode_fields()
    }
}

macro_rules! record {
    ($ty:ident, $schema:ident) => {
        struct $ty(Record);
        impl Default for $ty {
            fn default() -> Self {
                Self(Record::new($schema))
            }
        }
        impl Element for $ty {
            fn decode(&mut self, source: &[u8]) -> io::Result<()> {
                self.0.decode(source)
            }
            fn encode(&self) -> io::Result<Vec<u8>> {
                self.0.encode()
            }
        }
    };
}

record!(Node, NODE);
record!(Patch, PATCH);
record!(Resolver, RESOLVER);

#[derive(Default)]
struct Pointer<T>(Option<T>);

impl<T: Element> Element for Pointer<T> {
    fn decode(&mut self, source: &[u8]) -> io::Result<()> {
        if source == b"null" {
            self.0 = None;
            Ok(())
        } else {
            self.0.get_or_insert_with(T::default).decode(source)
        }
    }

    fn encode(&self) -> io::Result<Vec<u8>> {
        self.0
            .as_ref()
            .map_or_else(|| Ok(b"null".to_vec()), Element::encode)
    }
}

#[derive(Default)]
pub(super) struct Nodes {
    node: Pointer<Node>,
    peers: Slice<Pointer<Node>>,
    changed: Slice<Pointer<Node>>,
    patches: Slice<Pointer<Patch>>,
}

impl Nodes {
    pub(super) fn decode(&mut self, name: &str, source: &[u8]) -> io::Result<()> {
        match name {
            "Node" => self.node.decode(source),
            "Peers" => self.peers.decode(source),
            "PeersChanged" => self.changed.decode(source),
            "PeersChangedPatch" => self.patches.decode(source),
            _ => unreachable!("native node field"),
        }
    }

    // Encode after directory decoding has finished. A validly decoded Go time
    // can fail marshaling; that fails the HTTP response instead of skipping a
    // dump file as if it had failed to decode.
    pub(super) fn encode_fields(&self) -> io::Result<BTreeMap<String, Vec<u8>>> {
        let mut out = BTreeMap::new();
        if self.node.0.is_some() {
            out.insert("Node".into(), self.node.encode()?);
        }
        if !self.peers.is_empty() {
            out.insert("Peers".into(), self.peers.encode()?);
        }
        if !self.changed.is_empty() {
            out.insert("PeersChanged".into(), self.changed.encode()?);
        }
        if !self.patches.is_empty() {
            out.insert("PeersChangedPatch".into(), self.patches.encode()?);
        }
        Ok(out)
    }
}
