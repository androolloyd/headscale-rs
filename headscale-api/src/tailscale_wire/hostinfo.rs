// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause

//! Native Hostinfo shapes hidden by the stable public wire projection.

use serde_json::Value;

use super::{
    MachineRegistry,
    wire::{HostInfo, MapResponse},
};

#[derive(Clone)]
pub(crate) struct HostInfoSnapshot {
    pub(crate) projection: HostInfo,
    pub(crate) value: Value,
}

impl HostInfoSnapshot {
    pub(crate) fn value_for(&self, current: &HostInfo) -> Result<Value, serde_json::Error> {
        if &self.projection == current {
            return Ok(self.value.clone());
        }
        let before = serde_json::to_value(&self.projection)?;
        let after = serde_json::to_value(current)?;
        let mut value = self.value.clone();
        merge_projection(&mut value, &before, &after);
        Ok(value)
    }
}

/// Auth completion always constructs a valid Hostinfo, even for a nil request.
/// Preserve the original request shapes while applying producer-side edits
/// (for example fresh web tag compaction) and the selected node's NetInfo.
pub(crate) fn registration_value(
    requested: &Value,
    current: &HostInfo,
    preserved_netinfo: Option<&Value>,
) -> Result<Value, std::io::Error> {
    let requested = if requested.is_null() {
        Value::Object(serde_json::Map::new())
    } else {
        requested.clone()
    };
    let projection = serde_json::from_value(requested.clone()).map_err(std::io::Error::other)?;
    let carries_netinfo = requested.get("NetInfo").is_none();
    let mut value = HostInfoSnapshot {
        projection,
        value: requested,
    }
    .value_for(current)
    .map_err(std::io::Error::other)?;
    if carries_netinfo && let Some(netinfo) = preserved_netinfo {
        value["NetInfo"] = netinfo.clone();
    }
    Ok(value)
}

/// Encode private shapes at the control boundary without adding fields to the
/// public MapNode/HostInfo types. Node.Hostinfo is omitzero in pinned tailcfg:
/// a nil view omits the field; a valid pointer to an empty Hostinfo emits {}.
pub(super) fn response_value(
    response: &MapResponse,
    _registry: &MachineRegistry,
    snapshot: &super::MachineSnapshot,
) -> Result<Value, std::io::Error> {
    let records = snapshot
        .iter()
        .map(|(key, record)| (record.stable_node_id_for_key(key), record))
        .collect::<std::collections::HashMap<_, _>>();
    let mut value = serde_json::to_value(response).map_err(std::io::Error::other)?;
    let encode_node = |node: &mut Value| -> Result<(), std::io::Error> {
        let Some(node) = node.as_object_mut() else {
            return Ok(());
        };
        let Some(record) = node
            .get("ID")
            .and_then(Value::as_u64)
            .and_then(|id| records.get(&id))
        else {
            return Ok(());
        };
        // Prefixes returns nil only without IP pointers; a filtered non-nil
        // slice can be empty. slices.Concat returns nil for any empty result.
        if snapshot.policy_addresses(record).is_empty() {
            node.insert("Addresses".into(), Value::Null);
        }
        if node
            .get("AllowedIPs")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        {
            node.remove("AllowedIPs");
        }
        // The same immutable attribute capture drove map construction.
        // Policy flags overlay baseline/runtime capability values as nil
        // argument slices, including keys also present in the baseline.
        if let Some(attrs) = snapshot.policy_node_attrs(record.stable_node_id())
            && let Some(caps) = node.get_mut("CapMap").and_then(Value::as_object_mut)
        {
            for attr in attrs {
                if let Some(value) = caps.get_mut(attr) {
                    *value = Value::Null;
                }
            }
        }
        let hostinfo = snapshot
            .map_hostinfo_value(record)
            .map_err(std::io::Error::other)?;
        let hostinfo = headscale_api_acl::go_tailcfg_json::marshal_hostinfo_value(&hostinfo)
            .map_err(std::io::Error::other)?;
        if hostinfo.is_null() {
            node.remove("Hostinfo");
        } else {
            node.insert("Hostinfo".into(), hostinfo);
        }
        Ok(())
    };
    if let Some(node) = value.get_mut("Node") {
        encode_node(node)?;
    }
    for field in ["Peers", "PeersChanged"] {
        if let Some(nodes) = value.get_mut(field).and_then(Value::as_array_mut) {
            for node in nodes {
                encode_node(node)?;
            }
        }
    }
    Ok(value)
}

// Admin edits change individual projected fields. Preserve native values
// hidden by Option/Vec in every other field. Map replacements bypass this
// merge and install the entire decoded request snapshot instead.
pub(crate) fn merge_projection(native: &mut Value, before: &Value, after: &Value) {
    if before == after {
        return;
    }
    let (Some(before), Some(after)) = (before.as_object(), after.as_object()) else {
        *native = after.clone();
        return;
    };
    if !native.is_object() {
        *native = Value::Object(serde_json::Map::new());
    }
    let output = native.as_object_mut().expect("Hostinfo object initialized");
    for name in before.keys().chain(after.keys()) {
        if before.get(name) == after.get(name) {
            continue;
        }
        match after.get(name) {
            None => {
                output.remove(name);
            }
            Some(value) => {
                if let Some(previous) = before.get(name) {
                    merge_projection(
                        output.entry(name.clone()).or_insert(Value::Null),
                        previous,
                        value,
                    );
                } else {
                    output.insert(name.clone(), value.clone());
                }
            }
        }
    }
}
