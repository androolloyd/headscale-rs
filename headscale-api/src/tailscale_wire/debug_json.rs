// Copyright (c) 2020, Juan Font
// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
// headscale-go v0.29.5 mapper/debug readback and tailcfg RawMessage maps.
// See UPSTREAM.md and retained upstream licenses.

//! Native nodes and filters retain private Go-shaped state during directory
//! readback. Decode errors skip a dump; encoding errors fail the final body.
//! Typed debug schemas avoid the public wire projection throughout readback.

use std::{collections::BTreeMap, io, path::Path};

use headscale_api_acl::{go_json, go_json_output};

use super::{
    debug_filters::{Filters, field, json, name},
    debug_nodes::{Nodes, ResponseValues},
};

// Pinned tailcfg.MapResponse declaration order, including its one renamed
// field. Canonicalize recognized names before typed decoding;
// unknown fields are scanned without materializing their subtrees.
pub(super) const FIELDS: &[&str] = &[
    "MapSessionHandle",
    "Seq",
    "KeepAlive",
    "PingRequest",
    "PopBrowserURL",
    "Node",
    "DERPMap",
    "Peers",
    "PeersChanged",
    "PeersRemoved",
    "PeersChangedPatch",
    "PeerSeenChange",
    "OnlineChange",
    "DNSConfig",
    "Domain",
    "CollectServices",
    "PacketFilter",
    "PacketFilters",
    "UserProfiles",
    "Health",
    "DisplayMessages",
    "SSHPolicy",
    "ControlTime",
    "TKAInfo",
    "DomainDataPlaneAuditLogID",
    "Debug",
    "ControlDialPlan",
    "ClientVersion",
    "DefaultAutoUpdate",
];

struct Response {
    nodes: Nodes,
    filters: Filters,
    values: ResponseValues,
}

impl Response {
    fn encode(&self) -> io::Result<Vec<u8>> {
        let mut fields = BTreeMap::new();
        fields.extend(self.nodes.encode_fields()?);
        fields.extend(self.filters.encode_fields()?);
        fields.extend(self.values.encode_fields()?);
        let mut out = vec![b'{'];
        for &name in FIELDS {
            if let Some(value) = fields.get(name) {
                field(&mut out, name, value)?;
            }
        }
        out.push(b'}');
        Ok(out)
    }
}

fn response(source: &[u8]) -> io::Result<Response> {
    let mut nodes = Nodes::default();
    let mut filters = Filters::default();
    let mut values = ResponseValues::default();
    if go_json::trim(source) != b"null" {
        for (input, raw) in go_json::object(source).map_err(io::Error::other)? {
            let Some(name) = name(&input, FIELDS) else {
                continue;
            };
            match name {
                "Node" | "Peers" | "PeersChanged" | "PeersChangedPatch" => {
                    nodes.decode(name, raw.get())?;
                }
                "PacketFilter" | "PacketFilters" => filters.decode(name, raw.get())?,
                _ => {
                    values.decode(name, raw.get())?;
                }
            }
        }
    }
    Ok(Response {
        nodes,
        filters,
        values,
    })
}

pub(super) fn read(root: &Path) -> io::Result<Vec<u8>> {
    let responses = super::read_mapresponses_with(root, response)?;
    let mut nodes = responses
        .into_iter()
        .map(|(id, values)| (id.to_string(), values))
        .collect::<Vec<_>>();
    // encoding/json sorts integer map keys by their encoded decimal strings.
    nodes.sort_by(|left, right| left.0.cmp(&right.0));
    let mut out = vec![b'{'];
    for (index, (id, values)) in nodes.into_iter().enumerate() {
        if index != 0 {
            out.push(b',');
        }
        out.extend(json(&id)?);
        out.extend_from_slice(b":[");
        for (index, value) in values.into_iter().enumerate() {
            if index != 0 {
                out.push(b',');
            }
            out.extend(value.encode()?);
        }
        out.push(b']');
    }
    out.push(b'}');
    go_json_output::indent(&out).map_err(io::Error::other)
}
