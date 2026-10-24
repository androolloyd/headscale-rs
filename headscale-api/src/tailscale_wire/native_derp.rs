// Copyright (c) Tailscale Inc & contributors
// Selected float-error ordering follows Go encoding/json; Copyright 2010 The Go Authors.
// Original BSD terms are retained in LICENSE-GO-STDLIB.
// SPDX-License-Identifier: BSD-3-Clause
//! Native tailcfg DERP values. The existing public wire types retain their
//! narrower embedding contract; these owned values never use that projection
//! as an identity or as the source of native response encoding.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::wire;

#[doc(hidden)]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct NativeDerpMap {
    // Configuration metadata belongs to this canonical owner, not to its
    // narrowed compatibility view. It is not a tailcfg DERPMap field.
    #[serde(skip)]
    server_region_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_params: Option<NativeDerpHomeParams>,
    pub regions: BTreeMap<i64, Option<NativeDerpRegion>>,
    #[serde(
        rename = "omitDefaultRegions",
        alias = "OmitDefaultRegions",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub omit_default_regions: bool,
}

#[doc(hidden)]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct NativeDerpHomeParams {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub region_score: BTreeMap<i64, f64>,
}

#[doc(hidden)]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct NativeDerpRegion {
    #[serde(rename = "RegionID")]
    pub region_id: i64,
    pub region_code: String,
    pub region_name: String,
    #[serde(skip_serializing_if = "zero_float")]
    pub latitude: f64,
    #[serde(skip_serializing_if = "zero_float")]
    pub longitude: f64,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub avoid: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub no_measure_no_home: bool,
    pub nodes: Option<Vec<Option<NativeDerpNode>>>,
}

#[doc(hidden)]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct NativeDerpNode {
    pub name: String,
    #[serde(rename = "RegionID")]
    pub region_id: i64,
    pub host_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cert_name: String,
    #[serde(rename = "IPv4", skip_serializing_if = "String::is_empty")]
    pub ipv4: String,
    #[serde(rename = "IPv6", skip_serializing_if = "String::is_empty")]
    pub ipv6: String,
    #[serde(rename = "DERPPort", skip_serializing_if = "zero_int")]
    pub derp_port: i64,
    #[serde(rename = "STUNPort", skip_serializing_if = "zero_int")]
    pub stun_port: i64,
    #[serde(rename = "STUNOnly", skip_serializing_if = "std::ops::Not::not")]
    pub stun_only: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub insecure_for_tests: bool,
    #[serde(rename = "STUNTestIP", skip_serializing_if = "String::is_empty")]
    pub stun_test_ip: String,
    #[serde(rename = "CanPort80", skip_serializing_if = "std::ops::Not::not")]
    pub can_port80: bool,
}

fn zero_float(value: &f64) -> bool {
    *value == 0.0
}
fn zero_int(value: &i64) -> bool {
    *value == 0
}

impl NativeDerpMap {
    #[doc(hidden)]
    pub fn set_server_region_id(&mut self, id: i64) {
        self.server_region_id = Some(id);
    }

    pub(super) fn server_region_id(&self) -> Option<i64> {
        self.server_region_id
    }

    /// Lift an embedding map without changing its values or slice presence.
    pub fn from_projection(map: &wire::DerpMap) -> Self {
        Self {
            server_region_id: None,
            home_params: map.home_params.as_ref().map(|home| NativeDerpHomeParams {
                region_score: home
                    .region_score
                    .iter()
                    .map(|(&id, &score)| (i64::from(id), score))
                    .collect(),
            }),
            regions: map
                .regions
                .iter()
                .map(|(&id, region)| {
                    (
                        i64::from(id),
                        Some(NativeDerpRegion {
                            region_id: i64::from(region.region_id),
                            region_code: region.region_code.clone(),
                            region_name: region.region_name.clone(),
                            latitude: region.latitude,
                            longitude: region.longitude,
                            avoid: region.avoid,
                            no_measure_no_home: region.no_measure_no_home,
                            nodes: Some(
                                region
                                    .nodes
                                    .iter()
                                    .map(|node| {
                                        Some(NativeDerpNode {
                                            name: node.name.clone(),
                                            region_id: i64::from(node.region_id),
                                            host_name: node.host_name.clone(),
                                            cert_name: node.cert_name.clone(),
                                            ipv4: node.ipv4.clone(),
                                            ipv6: node.ipv6.clone(),
                                            derp_port: i64::from(node.derp_port),
                                            stun_port: i64::from(node.stun_port),
                                            stun_only: node.stun_only,
                                            insecure_for_tests: node.insecure_for_tests,
                                            stun_test_ip: node.stun_test_ip.clone(),
                                            can_port80: node.can_port80,
                                        })
                                    })
                                    .collect(),
                            ),
                        }),
                    )
                })
                .collect(),
            omit_default_regions: map.omit_default_regions,
        }
    }

    /// Compatibility view for the original embedding API. Unrepresentable
    /// entries are omitted, never narrowed or used to identify native values.
    pub fn projection(&self) -> wire::DerpMap {
        wire::DerpMap {
            home_params: self.home_params.as_ref().map(|home| wire::DerpHomeParams {
                region_score: home
                    .region_score
                    .iter()
                    .filter_map(|(&id, &score)| Some((id.try_into().ok()?, score)))
                    .collect(),
            }),
            regions: self
                .regions
                .iter()
                .filter_map(|(&id, region)| {
                    let region = region.as_ref()?;
                    Some((
                        id.try_into().ok()?,
                        wire::DerpRegion {
                            region_id: region.region_id.try_into().ok()?,
                            region_code: region.region_code.clone(),
                            region_name: region.region_name.clone(),
                            latitude: region.latitude,
                            longitude: region.longitude,
                            avoid: region.avoid,
                            no_measure_no_home: region.no_measure_no_home,
                            nodes: region
                                .nodes
                                .iter()
                                .flatten()
                                .filter_map(|node| {
                                    let node = node.as_ref()?;
                                    Some(wire::DerpRegionNode {
                                        name: node.name.clone(),
                                        region_id: node.region_id.try_into().ok()?,
                                        host_name: node.host_name.clone(),
                                        cert_name: node.cert_name.clone(),
                                        ipv4: node.ipv4.clone(),
                                        ipv6: node.ipv6.clone(),
                                        derp_port: node.derp_port.try_into().ok()?,
                                        stun_port: node.stun_port.try_into().ok()?,
                                        stun_only: node.stun_only,
                                        insecure_for_tests: node.insecure_for_tests,
                                        stun_test_ip: node.stun_test_ip.clone(),
                                        can_port80: node.can_port80,
                                    })
                                })
                                .collect(),
                        },
                    ))
                })
                .collect(),
            omit_default_regions: self.omit_default_regions,
        }
    }

    pub fn json_value(&self) -> serde_json::Result<serde_json::Value> {
        // serde_json::Value otherwise turns nonfinite floats into null. Go's
        // encoder rejects them in declaration order, with map keys sorted by
        // their encoded decimal strings rather than their numeric values.
        if let Some((_, score)) = self.home_params.as_ref().and_then(|home| {
            home.region_score
                .iter()
                .filter(|(_, score)| !score.is_finite())
                .min_by_key(|(id, _)| id.to_string())
        }) {
            return Err(nonfinite_error(*score));
        }
        if let Some((_, region)) = self
            .regions
            .iter()
            .filter_map(|(id, region)| Some((id, region.as_ref()?)))
            .filter(|(_, region)| !region.latitude.is_finite() || !region.longitude.is_finite())
            .min_by_key(|(id, _)| id.to_string())
        {
            return Err(nonfinite_error(if region.latitude.is_finite() {
                region.longitude
            } else {
                region.latitude
            }));
        }
        serde_json::to_value(self)
    }
}

fn nonfinite_error(value: f64) -> serde_json::Error {
    let value = if value.is_nan() {
        "NaN"
    } else if value.is_sign_negative() {
        "-Inf"
    } else {
        "+Inf"
    };
    <serde_json::Error as serde::ser::Error>::custom(format!("json: unsupported value: {value}"))
}

/// Both views are captured under the same store lock, then carried explicitly
/// to the encoder. A concurrent refresh cannot substitute a different map.
pub(super) struct Snapshot {
    pub projection: wire::DerpMap,
    pub native: Option<std::sync::Arc<NativeDerpMap>>,
}
