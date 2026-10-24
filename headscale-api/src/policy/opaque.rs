// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause

//! Private filter compilation keeps opaque payload text separate from public
//! serde JSON values. These private payload strings are emitted as raw JSON.

use super::{PolicyDoc, lifecycle::GrantAppShape};
use crate::tailscale_wire::wire::{CapGrant, FilterRule};
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;

#[derive(Clone, Default, PartialEq)]
pub(super) struct OpaqueFilter(pub(super) Vec<FilterRule>);

#[derive(Clone)]
pub(crate) struct FilterSnapshot {
    pub(crate) rules: Vec<FilterRule>,
    opaque: Arc<OpaqueFilter>,
}

pub(super) fn document(doc: &PolicyDoc, apps: &[GrantAppShape]) -> PolicyDoc {
    let mut opaque = doc.clone();
    for (index, grant) in opaque.grants.iter_mut().enumerate() {
        for (capability, values) in &mut grant.app {
            let retained = apps
                .get(index)
                .and_then(|shape| shape.raw_values.get(capability))
                .and_then(Option::as_ref)
                .filter(|raw| {
                    raw.len() == values.len()
                        && raw.iter().zip(values.iter()).all(|(raw, value)| {
                            headscale_api_acl::go_json::value(raw.as_bytes())
                                .is_ok_and(|projected| projected == *value)
                        })
                });
            let raw = retained.cloned().unwrap_or_else(|| {
                values
                    .iter()
                    .map(|value| {
                        serde_json::to_string(value).expect("policy JSON value serializes")
                    })
                    .collect()
            });
            *values = raw.into_iter().map(Value::String).collect();
        }
    }
    opaque
}

impl FilterSnapshot {
    pub(super) fn new(rules: Vec<FilterRule>, opaque: OpaqueFilter) -> Self {
        Self {
            rules,
            opaque: Arc::new(opaque),
        }
    }

    pub(crate) fn allow_all() -> Self {
        let rules = super::filter::allow_all_filter_rules();
        Self {
            opaque: Arc::new(OpaqueFilter(rules.clone())),
            rules,
        }
    }

    pub(crate) fn base_json(&self) -> Result<Vec<u8>, std::io::Error> {
        self.opaque.json()
    }
}

impl OpaqueFilter {
    pub(super) fn json(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut out = vec![b'['];
        for (index, rule) in self.0.iter().enumerate() {
            if index != 0 {
                out.push(b',');
            }
            // encoding/json emits a struct's declared fields in order. A
            // Value map would sort SrcIPs behind the optional rule fields.
            let mut body = vec![b'{'];
            field(&mut body, "SrcIPs", &rule.src_ips)?;
            if !rule.src_bits.is_empty() {
                field(&mut body, "SrcBits", &rule.src_bits)?;
            }
            if !rule.dst_ports.is_empty() {
                field(&mut body, "DstPorts", &rule.dst_ports)?;
            }
            if !rule.ip_proto.is_empty() {
                field(&mut body, "IPProto", &rule.ip_proto)?;
            }
            if !rule.cap_grant.is_empty() {
                field_name(&mut body, "CapGrant")?;
                body.push(b'[');
                for (index, grant) in rule.cap_grant.iter().enumerate() {
                    if index != 0 {
                        body.push(b',');
                    }
                    body.extend(grant_json(grant)?);
                }
                body.push(b']');
            }
            body.push(b'}');
            out.extend(body);
        }
        out.push(b']');
        headscale_api_acl::go_json_output::compact_html(&out).map_err(std::io::Error::other)
    }
}

fn field_name(body: &mut Vec<u8>, name: &str) -> Result<(), std::io::Error> {
    if body.len() > 1 {
        body.push(b',');
    }
    body.extend(serde_json::to_vec(name).map_err(std::io::Error::other)?);
    body.push(b':');
    Ok(())
}

fn field<T: Serialize + ?Sized>(
    body: &mut Vec<u8>,
    name: &str,
    value: &T,
) -> Result<(), std::io::Error> {
    field_name(body, name)?;
    body.extend(serde_json::to_vec(value).map_err(std::io::Error::other)?);
    Ok(())
}

fn grant_json(grant: &CapGrant) -> Result<Vec<u8>, std::io::Error> {
    let mut out = vec![b'{'];
    // Dsts is required. Compiler-produced empty IP sets are non-nil slices.
    field(&mut out, "Dsts", &grant.dsts)?;
    if !grant.caps.is_empty() {
        field(&mut out, "Caps", &grant.caps)?;
    }
    if !grant.cap_map.is_empty() {
        field_name(&mut out, "CapMap")?;
        let mut map = vec![b'{'];
        for (name, values) in &grant.cap_map {
            field_name(&mut map, name)?;
            match values {
                None => map.extend_from_slice(b"null"),
                Some(values) => {
                    map.push(b'[');
                    for (index, value) in values.iter().enumerate() {
                        if index != 0 {
                            map.push(b',');
                        }
                        let raw = value.as_str().ok_or_else(|| {
                            std::io::Error::other("opaque filter payload is not raw JSON")
                        })?;
                        map.extend_from_slice(raw.as_bytes());
                    }
                    map.push(b']');
                }
            }
        }
        map.push(b'}');
        out.extend(map);
    }
    out.push(b'}');
    Ok(out)
}
