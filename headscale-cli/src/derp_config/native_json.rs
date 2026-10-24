// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license.
// Selected finite decoder adaptation; see LICENSE-GO-STDLIB and UPSTREAM.md.
//! Native DERP-map JSON assignments follow Go 1.26.9 encoding/json and
//! tailscale.com v1.101.0-pre/tailcfg/derpmap.go. Unknown subtrees stay raw.

use super::{NativeDerpNode as DerpRegionNode, NativeDerpRegion as DerpRegion, SourceDerpMap};
use headscale_api_acl::{go_json as json, go_unicode::equal_fold};

pub(super) fn parse(raw: &[u8]) -> Result<SourceDerpMap, String> {
    // Unmarshal checks all syntax before assigning fields. These finite DERP
    // receivers have no custom unmarshaler: subsequent failures are saved
    // type errors. This Result API exposes no partially assigned map, so it
    // can return the first such error immediately in decoder traversal order.
    json::check_valid(raw)?;
    let mut result = SourceDerpMap::default();
    if null(raw) {
        return Ok(result);
    }
    for (name, raw) in object(raw, None, "tailcfg.DERPMap")? {
        if equal_fold(&name, "Regions") {
            if null(raw.get()) {
                result.regions.clear();
                continue;
            }
            for (id, value) in object(
                raw.get(),
                Some("DERPMap.Regions"),
                "map[int]*tailcfg.DERPRegion",
            )? {
                let region = if null(value.get()) {
                    None
                } else {
                    Some(region(value.get())?)
                };
                // encoding/json decodes the map value before converting its
                // key, so a value's type error takes precedence over a bad key.
                let id = map_id(&id, "DERPMap.Regions")?;
                result.regions.insert(id, region);
            }
        } else if equal_fold(&name, "omitDefaultRegions") {
            boolean(&mut false, raw.get(), "DERPMap.omitDefaultRegions")?;
        } else if equal_fold(&name, "HomeParams") && !null(raw.get()) {
            for (name, value) in object(
                raw.get(),
                Some("DERPMap.HomeParams"),
                "tailcfg.DERPHomeParams",
            )? {
                if equal_fold(&name, "RegionScore") && !null(value.get()) {
                    for (id, score) in object(
                        value.get(),
                        Some("DERPHomeParams.HomeParams.RegionScore"),
                        "map[int]float64",
                    )? {
                        // HomeParams is validated but discarded by Go's merge;
                        // its map keys need not fit the public region-ID type.
                        float(
                            &mut 0.0,
                            score.get(),
                            "DERPHomeParams.HomeParams.RegionScore",
                        )?;
                        map_id(&id, "DERPHomeParams.HomeParams.RegionScore")?;
                    }
                }
            }
        }
    }
    Ok(result)
}

fn region(raw: &[u8]) -> Result<DerpRegion, String> {
    let mut value = DerpRegion {
        region_id: 0,
        region_code: String::new(),
        region_name: String::new(),
        latitude: 0.0,
        longitude: 0.0,
        avoid: false,
        no_measure_no_home: false,
        nodes: None,
    };
    let mut nodes: Vec<Option<DerpRegionNode>> = Vec::new();
    let mut nodes_len = None;
    for (name, raw) in object(raw, Some("DERPMap.Regions"), "tailcfg.DERPRegion")? {
        let raw = raw.get();
        if equal_fold(&name, "RegionID") {
            integer(&mut value.region_id, raw, "DERPRegion.Regions.RegionID")?;
        } else if equal_fold(&name, "RegionCode") {
            string(&mut value.region_code, raw, "DERPRegion.Regions.RegionCode")?;
        } else if equal_fold(&name, "RegionName") {
            string(&mut value.region_name, raw, "DERPRegion.Regions.RegionName")?;
        } else if equal_fold(&name, "Latitude") {
            float(&mut value.latitude, raw, "DERPRegion.Regions.Latitude")?;
        } else if equal_fold(&name, "Longitude") {
            float(&mut value.longitude, raw, "DERPRegion.Regions.Longitude")?;
        } else if equal_fold(&name, "Avoid") {
            boolean(&mut value.avoid, raw, "DERPRegion.Regions.Avoid")?;
        } else if equal_fold(&name, "NoMeasureNoHome") {
            boolean(
                &mut value.no_measure_no_home,
                raw,
                "DERPRegion.Regions.NoMeasureNoHome",
            )?;
        } else if equal_fold(&name, "Nodes") {
            if null(raw) {
                nodes.clear();
                nodes_len = None;
                continue;
            }
            let array = array(raw, "DERPRegion.Regions.Nodes", "[]*tailcfg.DERPNode")?;
            if array.is_empty() {
                nodes.clear();
            }
            for (index, raw) in array.iter().enumerate() {
                if index == nodes.len() {
                    nodes.push(None);
                }
                if null(raw.get()) {
                    nodes[index] = None;
                } else {
                    node(nodes[index].get_or_insert_with(empty_node), raw.get())?;
                }
            }
            nodes_len = Some(array.len());
        }
    }
    value.nodes = nodes_len.map(|len| nodes.into_iter().take(len).collect());
    Ok(value)
}

fn empty_node() -> DerpRegionNode {
    DerpRegionNode {
        name: String::new(),
        region_id: 0,
        host_name: String::new(),
        cert_name: String::new(),
        ipv4: String::new(),
        ipv6: String::new(),
        derp_port: 0,
        stun_port: 0,
        stun_only: false,
        insecure_for_tests: false,
        stun_test_ip: String::new(),
        can_port80: false,
    }
}

fn node(value: &mut DerpRegionNode, raw: &[u8]) -> Result<(), String> {
    for (name, raw) in object(raw, Some("DERPRegion.Regions.Nodes"), "tailcfg.DERPNode")? {
        let raw = raw.get();
        macro_rules! field {
            ($name:literal, $field:ident, $parse:ident) => {
                if equal_fold(&name, $name) {
                    $parse(
                        &mut value.$field,
                        raw,
                        concat!("DERPNode.Regions.Nodes.", $name),
                    )?;
                    continue;
                }
            };
        }
        field!("Name", name, string);
        field!("RegionID", region_id, integer);
        field!("HostName", host_name, string);
        field!("CertName", cert_name, string);
        field!("IPv4", ipv4, string);
        field!("IPv6", ipv6, string);
        field!("DERPPort", derp_port, integer);
        field!("STUNPort", stun_port, integer);
        field!("STUNOnly", stun_only, boolean);
        field!("InsecureForTests", insecure_for_tests, boolean);
        field!("STUNTestIP", stun_test_ip, string);
        // The last field needs no `continue`: nothing follows it in the loop.
        if equal_fold(&name, "CanPort80") {
            boolean(
                &mut value.can_port80,
                raw,
                "DERPNode.Regions.Nodes.CanPort80",
            )?;
        }
    }
    Ok(())
}

fn null(raw: &[u8]) -> bool {
    json::trim(raw) == b"null"
}

fn kind(raw: &[u8]) -> &'static str {
    match json::trim(raw).first() {
        Some(b'"') => "string",
        Some(b'{') => "object",
        Some(b'[') => "array",
        Some(b't' | b'f') => "bool",
        _ => "number",
    }
}

fn type_error(value: &str, field: Option<&str>, ty: &str) -> String {
    match field {
        Some(field) => {
            format!("json: cannot unmarshal {value} into Go struct field {field} of type {ty}")
        }
        None => format!("json: cannot unmarshal {value} into Go value of type {ty}"),
    }
}

fn mismatch(raw: &[u8], field: &str, ty: &str) -> String {
    type_error(kind(raw), Some(field), ty)
}

fn number_error(raw: &[u8], field: &str, ty: &str) -> String {
    // Valid numeric JSON tokens are ASCII; check_valid already ran globally.
    let number = std::str::from_utf8(json::trim(raw)).expect("validated numeric JSON token");
    type_error(&format!("number {number}"), Some(field), ty)
}

fn object<'a>(
    raw: &'a [u8],
    field: Option<&str>,
    ty: &str,
) -> Result<Vec<(String, json::Raw<'a>)>, String> {
    if json::trim(raw).first() != Some(&b'{') {
        return Err(type_error(kind(raw), field, ty));
    }
    json::object(raw)
}

fn array<'a>(raw: &'a [u8], field: &str, ty: &str) -> Result<Vec<json::Raw<'a>>, String> {
    if json::trim(raw).first() != Some(&b'[') {
        return Err(mismatch(raw, field, ty));
    }
    json::array(raw)
}

fn string(value: &mut String, raw: &[u8], field: &str) -> Result<(), String> {
    if null(raw) {
        return Ok(());
    }
    if json::trim(raw).first() != Some(&b'"') {
        return Err(mismatch(raw, field, "string"));
    }
    *value = json::unquote(raw)?;
    Ok(())
}

fn boolean(value: &mut bool, raw: &[u8], field: &str) -> Result<(), String> {
    match json::trim(raw) {
        b"null" => {}
        b"true" => *value = true,
        b"false" => *value = false,
        _ => return Err(mismatch(raw, field, "bool")),
    }
    Ok(())
}

fn float(value: &mut f64, raw: &[u8], field: &str) -> Result<(), String> {
    if null(raw) {
        return Ok(());
    }
    if kind(raw) != "number" {
        return Err(mismatch(raw, field, "float64"));
    }
    let text = std::str::from_utf8(json::trim(raw)).map_err(|_| mismatch(raw, field, "float64"))?;
    let parsed: f64 = text
        .parse()
        .map_err(|_| number_error(raw, field, "float64"))?;
    if !parsed.is_finite() {
        return Err(number_error(raw, field, "float64"));
    }
    *value = parsed;
    Ok(())
}

fn integer(value: &mut i64, raw: &[u8], field: &str) -> Result<(), String> {
    if null(raw) {
        return Ok(());
    }
    if kind(raw) != "number" {
        return Err(mismatch(raw, field, "int"));
    }
    let text = std::str::from_utf8(json::trim(raw)).map_err(|_| mismatch(raw, field, "int"))?;
    *value = text.parse().map_err(|_| number_error(raw, field, "int"))?;
    Ok(())
}

fn map_id(raw: &str, field: &str) -> Result<i64, String> {
    raw.parse()
        .map_err(|_| type_error(&format!("number {raw}"), Some(field), "int"))
}
