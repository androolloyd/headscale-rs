// Copyright (c) Tailscale Inc & contributors
// Copyright 2010 The Go Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// Pinned tailcfg filter schemas and Go encoding/json decoding semantics.
// See UPSTREAM.md and the retained upstream licenses.

//! Private filter state for native debug readback. The public wire structs
//! cannot represent nil slices or Go's 64-bit int fields. Keep those shapes,
//! reused slice elements, and opaque capability payloads outside that projection.

use std::{collections::BTreeMap, io};

use headscale_api_acl::{go_json, go_netip, go_tailcfg_json::folded_equal};

pub(super) fn json<T: serde::Serialize + ?Sized>(value: &T) -> io::Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(io::Error::other)
}

pub(super) fn name<'a>(input: &str, fields: &'a [&str]) -> Option<&'a str> {
    fields
        .iter()
        .find(|field| **field == input)
        .or_else(|| fields.iter().find(|field| folded_equal(input, field)))
        .copied()
}

pub(super) fn field(out: &mut Vec<u8>, name: &str, value: &[u8]) -> io::Result<()> {
    if out.len() > 1 {
        out.push(b',');
    }
    out.extend(json(name)?);
    out.push(b':');
    out.extend_from_slice(value);
    Ok(())
}

pub(super) trait Element: Default {
    fn decode(&mut self, source: &[u8]) -> io::Result<()>;
    fn encode(&self) -> io::Result<Vec<u8>>;
}

pub(super) struct Slice<T> {
    // A shorter nonempty decode retains the backing slots for later fields.
    // null and [] both discard that backing state, but marshal differently.
    slots: Vec<T>,
    len: Option<usize>,
}

impl<T> Default for Slice<T> {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            len: None,
        }
    }
}

impl<T: Element> Slice<T> {
    pub(super) fn is_empty(&self) -> bool {
        self.len.unwrap_or_default() == 0
    }

    pub(super) fn is_nil(&self) -> bool {
        self.len.is_none()
    }

    pub(super) fn decode(&mut self, source: &[u8]) -> io::Result<()> {
        if go_json::trim(source) == b"null" {
            *self = Self::default();
            return Ok(());
        }
        let input = go_json::array(source).map_err(io::Error::other)?;
        if input.is_empty() {
            self.slots = Vec::new();
        }
        for (index, raw) in input.iter().enumerate() {
            if index == self.slots.len() {
                self.slots.push(T::default());
            }
            self.slots[index].decode(raw.get())?;
        }
        self.len = Some(input.len());
        Ok(())
    }

    pub(super) fn encode(&self) -> io::Result<Vec<u8>> {
        let Some(len) = self.len else {
            return Ok(b"null".to_vec());
        };
        let mut out = vec![b'['];
        for (index, value) in self.slots[..len].iter().enumerate() {
            if index != 0 {
                out.push(b',');
            }
            out.extend(value.encode()?);
        }
        out.push(b']');
        Ok(out)
    }
}

#[derive(Default)]
pub(super) struct Text(pub(super) String);

impl Element for Text {
    fn decode(&mut self, source: &[u8]) -> io::Result<()> {
        if go_json::trim(source) != b"null" {
            self.0 = go_json::unquote(source).map_err(io::Error::other)?;
        }
        Ok(())
    }

    fn encode(&self) -> io::Result<Vec<u8>> {
        json(&self.0)
    }
}

#[derive(Default)]
pub(super) struct Prefix(Text);

impl Element for Prefix {
    fn decode(&mut self, source: &[u8]) -> io::Result<()> {
        if go_json::trim(source) != b"null" {
            let text = go_json::unquote(source).map_err(io::Error::other)?;
            self.0.0 = if text.is_empty() {
                text
            } else {
                go_netip::parse_prefix_text(&text).map_err(io::Error::other)?
            };
        }
        Ok(())
    }

    fn encode(&self) -> io::Result<Vec<u8>> {
        self.0.encode()
    }
}

#[derive(Default)]
pub(super) struct Integer(i64);

impl Element for Integer {
    fn decode(&mut self, source: &[u8]) -> io::Result<()> {
        if go_json::trim(source) != b"null" {
            self.0 = std::str::from_utf8(source)
                .map_err(io::Error::other)?
                .parse()
                .map_err(io::Error::other)?;
        }
        Ok(())
    }

    fn encode(&self) -> io::Result<Vec<u8>> {
        json(&self.0)
    }
}

#[derive(Default)]
struct PortRange {
    first: u16,
    last: u16,
}

impl Element for PortRange {
    fn decode(&mut self, source: &[u8]) -> io::Result<()> {
        if go_json::trim(source) == b"null" {
            return Ok(());
        }
        for (input, raw) in go_json::object(source).map_err(io::Error::other)? {
            let target = match name(&input, &["First", "Last"]) {
                Some("First") => &mut self.first,
                Some("Last") => &mut self.last,
                _ => continue,
            };
            if raw.get() != b"null" {
                *target = std::str::from_utf8(raw.get())
                    .map_err(io::Error::other)?
                    .parse()
                    .map_err(io::Error::other)?;
            }
        }
        Ok(())
    }

    fn encode(&self) -> io::Result<Vec<u8>> {
        let mut out = vec![b'{'];
        field(&mut out, "First", &json(&self.first)?)?;
        field(&mut out, "Last", &json(&self.last)?)?;
        out.push(b'}');
        Ok(out)
    }
}

#[derive(Default)]
struct NetPortRange {
    ip: Text,
    bits: Option<Integer>,
    ports: PortRange,
}

impl Element for NetPortRange {
    fn decode(&mut self, source: &[u8]) -> io::Result<()> {
        if go_json::trim(source) == b"null" {
            return Ok(());
        }
        for (input, raw) in go_json::object(source).map_err(io::Error::other)? {
            match name(&input, &["IP", "Bits", "Ports"]) {
                Some("IP") => self.ip.decode(raw.get())?,
                Some("Bits") => {
                    if raw.get() == b"null" {
                        self.bits = None;
                    } else {
                        self.bits
                            .get_or_insert_with(Integer::default)
                            .decode(raw.get())?;
                    }
                }
                Some("Ports") => self.ports.decode(raw.get())?,
                _ => {}
            }
        }
        Ok(())
    }

    fn encode(&self) -> io::Result<Vec<u8>> {
        let mut out = vec![b'{'];
        field(&mut out, "IP", &self.ip.encode()?)?;
        if let Some(bits) = &self.bits {
            field(&mut out, "Bits", &bits.encode()?)?;
        }
        field(&mut out, "Ports", &self.ports.encode()?)?;
        out.push(b'}');
        Ok(out)
    }
}

#[derive(Default)]
pub(super) struct CapabilityMap(BTreeMap<String, Vec<u8>>);

impl CapabilityMap {
    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(super) fn decode(&mut self, source: &[u8]) -> io::Result<()> {
        if go_json::trim(source) == b"null" {
            self.0.clear();
            return Ok(());
        }
        for (name, raw) in go_json::object(source).map_err(io::Error::other)? {
            // Each map value is a fresh []RawMessage, even if the key already
            // exists. Payload elements themselves never become Serde Values.
            if raw.get() != b"null" {
                go_json::array(raw.get()).map_err(io::Error::other)?;
            }
            self.0.insert(name, raw.get().to_vec());
        }
        Ok(())
    }

    pub(super) fn encode(&self) -> io::Result<Vec<u8>> {
        let mut out = vec![b'{'];
        for (name, raw) in &self.0 {
            field(&mut out, name, raw)?;
        }
        out.push(b'}');
        Ok(out)
    }
}

#[derive(Default)]
struct Grant {
    dsts: Slice<Prefix>,
    caps: Slice<Text>,
    cap_map: CapabilityMap,
}

impl Element for Grant {
    fn decode(&mut self, source: &[u8]) -> io::Result<()> {
        if go_json::trim(source) == b"null" {
            return Ok(());
        }
        for (input, raw) in go_json::object(source).map_err(io::Error::other)? {
            match name(&input, &["Dsts", "Caps", "CapMap"]) {
                Some("Dsts") => self.dsts.decode(raw.get())?,
                Some("Caps") => self.caps.decode(raw.get())?,
                Some("CapMap") => self.cap_map.decode(raw.get())?,
                _ => {}
            }
        }
        Ok(())
    }

    fn encode(&self) -> io::Result<Vec<u8>> {
        let mut out = vec![b'{'];
        field(&mut out, "Dsts", &self.dsts.encode()?)?;
        if !self.caps.is_empty() {
            field(&mut out, "Caps", &self.caps.encode()?)?;
        }
        if !self.cap_map.0.is_empty() {
            field(&mut out, "CapMap", &self.cap_map.encode()?)?;
        }
        out.push(b'}');
        Ok(out)
    }
}

#[derive(Default)]
struct Rule {
    src_ips: Slice<Text>,
    src_bits: Slice<Integer>,
    dst_ports: Slice<NetPortRange>,
    ip_proto: Slice<Integer>,
    cap_grant: Slice<Grant>,
}

impl Element for Rule {
    fn decode(&mut self, source: &[u8]) -> io::Result<()> {
        if go_json::trim(source) == b"null" {
            return Ok(());
        }
        for (input, raw) in go_json::object(source).map_err(io::Error::other)? {
            match name(
                &input,
                &["SrcIPs", "SrcBits", "DstPorts", "IPProto", "CapGrant"],
            ) {
                Some("SrcIPs") => self.src_ips.decode(raw.get())?,
                Some("SrcBits") => self.src_bits.decode(raw.get())?,
                Some("DstPorts") => self.dst_ports.decode(raw.get())?,
                Some("IPProto") => self.ip_proto.decode(raw.get())?,
                Some("CapGrant") => self.cap_grant.decode(raw.get())?,
                _ => {}
            }
        }
        Ok(())
    }

    fn encode(&self) -> io::Result<Vec<u8>> {
        let mut out = vec![b'{'];
        field(&mut out, "SrcIPs", &self.src_ips.encode()?)?;
        if !self.src_bits.is_empty() {
            field(&mut out, "SrcBits", &self.src_bits.encode()?)?;
        }
        if !self.dst_ports.is_empty() {
            field(&mut out, "DstPorts", &self.dst_ports.encode()?)?;
        }
        if !self.ip_proto.is_empty() {
            field(&mut out, "IPProto", &self.ip_proto.encode()?)?;
        }
        if !self.cap_grant.is_empty() {
            field(&mut out, "CapGrant", &self.cap_grant.encode()?)?;
        }
        out.push(b'}');
        Ok(out)
    }
}

#[derive(Default)]
pub(super) struct Filters {
    legacy: Slice<Rule>,
    named: BTreeMap<String, Slice<Rule>>,
}

impl Filters {
    pub(super) fn decode(&mut self, name: &str, source: &[u8]) -> io::Result<()> {
        if name == "PacketFilter" {
            return self.legacy.decode(source);
        }
        if go_json::trim(source) == b"null" {
            self.named.clear();
        } else {
            for (name, raw) in go_json::object(source).map_err(io::Error::other)? {
                // encoding/json creates a fresh value for each map entry;
                // repeated PacketFilters objects retain other named filters.
                let mut rules = Slice::<Rule>::default();
                rules.decode(raw.get())?;
                self.named.insert(name, rules);
            }
        }
        Ok(())
    }

    pub(super) fn encode_fields(&self) -> io::Result<BTreeMap<String, Vec<u8>>> {
        let mut fields = BTreeMap::new();
        if !self.legacy.is_empty() {
            fields.insert("PacketFilter".into(), self.legacy.encode()?);
        }
        if self.named.is_empty() {
            return Ok(fields);
        }
        let mut out = vec![b'{'];
        for (name, rules) in &self.named {
            field(&mut out, name, &rules.encode()?)?;
        }
        out.push(b'}');
        fields.insert("PacketFilters".into(), out);
        Ok(fields)
    }
}
