use std::{collections::HashMap, env, fs, path::PathBuf};

use anyhow::{Context, Result, bail};
use headscale_api::{
    policy::{NodeView, acl_to_filter_rules, parse_hujson_policy},
    tailscale_wire::wire::{
        DerpMap, DnsConfig, HostInfo, MapNode, MapResponse, RegisterRequest, RegisterResponse,
    },
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct Scenario {
    name: String,
    policy: Value,
    #[serde(default)]
    users: Vec<ScenarioUser>,
    #[serde(default)]
    nodes: Vec<ScenarioNode>,
    #[serde(default)]
    route_checks: Vec<RouteCheck>,
    #[serde(default)]
    wire: Option<WireScenario>,
}

#[derive(Debug, Deserialize)]
struct ScenarioUser {
    id: u64,
    name: String,
    #[serde(default)]
    email: String,
}

#[derive(Debug, Deserialize)]
struct ScenarioNode {
    id: u64,
    user_id: u64,
    ipv4: String,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RouteCheck {
    name: String,
    node_id: u64,
    #[serde(default)]
    current_approved: Vec<String>,
    #[serde(default)]
    announced_routes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct WireScenario {
    #[serde(default)]
    dns_config: Option<Value>,
    #[serde(default)]
    derp_map: Option<Value>,
    #[serde(default)]
    register_request: Option<Value>,
    #[serde(default)]
    register_response: Option<Value>,
    #[serde(default)]
    map_response: Option<Value>,
}

#[derive(Debug, Serialize)]
struct ScenarioOutput {
    engine: &'static str,
    name: String,
    filter: Vec<FilterRuleOut>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    route_approvals: Vec<RouteApprovalOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wire: Option<WireOutput>,
}

#[derive(Debug, Serialize)]
struct RouteApprovalOut {
    name: String,
    approved_routes: Vec<String>,
    changed: bool,
}

#[derive(Debug, Serialize, Default)]
struct WireOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    dns_config: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    derp_map: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    register_request: Option<RegisterRequestSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    register_response: Option<RegisterResponseSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    map_response: Option<MapResponseSummary>,
}

#[derive(Debug, Serialize)]
struct RegisterRequestSummary {
    node_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    auth_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostinfo: Option<HostInfoSummary>,
    #[serde(skip_serializing_if = "String::is_empty")]
    followup: String,
}

#[derive(Debug, Serialize)]
struct RegisterResponseSummary {
    user: UserSummary,
    login: LoginSummary,
    node_key_expired: bool,
    auth_url: String,
    machine_authorized: bool,
}

#[derive(Debug, Serialize)]
struct UserSummary {
    id: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    display_name: String,
}

#[derive(Debug, Serialize)]
struct LoginSummary {
    id: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    provider: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    login_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    display_name: String,
}

#[derive(Debug, Serialize)]
struct MapResponseSummary {
    keep_alive: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    node: Option<MapNodeSummary>,
    peer_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    packet_filter: Vec<FilterRuleOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns_config: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    derp_map: Option<Value>,
}

#[derive(Debug, Serialize)]
struct MapNodeSummary {
    id: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    stable_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    name: String,
    user: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    machine: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    disco_key: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    addresses: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    allowed_ips: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    endpoints: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostinfo: Option<HostInfoSummary>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    machine_authorized: bool,
}

#[derive(Debug, Serialize)]
struct HostInfoSummary {
    #[serde(skip_serializing_if = "String::is_empty")]
    hostname: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    os: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    os_version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct FilterRuleOut {
    #[serde(rename = "SrcIPs")]
    src_ips: Vec<String>,
    dst_ports: Vec<NetPortRangeOut>,
    #[serde(rename = "IPProto", skip_serializing_if = "Vec::is_empty")]
    ip_proto: Vec<i32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct NetPortRangeOut {
    #[serde(rename = "IP")]
    ip: String,
    ports: PortRangeOut,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct PortRangeOut {
    first: u16,
    last: u16,
}

fn main() -> Result<()> {
    let paths = scenario_paths()?;
    let mut out = Vec::with_capacity(paths.len());

    for path in paths {
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("reading scenario {}", path.display()))?;
        let scenario: Scenario = serde_json::from_str(&raw)
            .with_context(|| format!("parsing scenario {}", path.display()))?;
        let policy = serde_json::to_string(&scenario.policy)?;
        let doc = parse_hujson_policy(&policy)
            .with_context(|| format!("headscale-rs parsing policy for {}", scenario.name))?;
        out.push(ScenarioOutput {
            engine: "headscale-rs",
            name: scenario.name.clone(),
            filter: acl_to_filter_rules(&doc)
                .into_iter()
                .map(|rule| FilterRuleOut {
                    src_ips: rule.src_ips,
                    dst_ports: rule
                        .dst_ports
                        .into_iter()
                        .map(|dst| NetPortRangeOut {
                            ip: dst.ip,
                            ports: PortRangeOut {
                                first: dst.ports.first,
                                last: dst.ports.last,
                            },
                        })
                        .collect(),
                    ip_proto: rule.ip_proto,
                })
                .collect(),
            route_approvals: run_route_checks(&scenario, &doc)?,
            wire: normalize_wire(scenario.wire)?,
        });
    }

    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn run_route_checks(
    scenario: &Scenario,
    doc: &headscale_api::policy::PolicyDoc,
) -> Result<Vec<RouteApprovalOut>> {
    if scenario.route_checks.is_empty() {
        return Ok(Vec::new());
    }

    let users = scenario
        .users
        .iter()
        .map(|user| (user.id, user))
        .collect::<HashMap<_, _>>();
    let nodes = scenario
        .nodes
        .iter()
        .map(|node| (node.id, node))
        .collect::<HashMap<_, _>>();

    let mut out = Vec::with_capacity(scenario.route_checks.len());
    for check in &scenario.route_checks {
        let node = nodes.get(&check.node_id).with_context(|| {
            format!(
                "route check {} references unknown node {}",
                check.name, check.node_id
            )
        })?;
        let user = users.get(&node.user_id).map(|user| {
            if user.email.is_empty() {
                user.name.as_str()
            } else {
                user.email.as_str()
            }
        });
        let view = NodeView {
            addr: Some(node.ipv4.as_str()),
            user,
            tags: &node.tags,
        };

        let mut approved = normalize_prefixes(&check.current_approved)
            .with_context(|| format!("route check {} current_approved", check.name))?;
        let before = approved.clone();
        for route in normalize_prefixes(&check.announced_routes)
            .with_context(|| format!("route check {} announced_routes", check.name))?
        {
            if approved.contains(&route) {
                continue;
            }
            let can_approve = if is_default_route(&route)? {
                doc.auto_approves_exit_node(&view)
            } else {
                doc.auto_approves_route(&view, &route)
            };
            if can_approve {
                approved.push(route);
            }
        }
        approved.sort();
        approved.dedup();
        out.push(RouteApprovalOut {
            name: check.name.clone(),
            changed: approved != before,
            approved_routes: approved,
        });
    }

    Ok(out)
}

fn normalize_prefixes(raw: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(raw.len());
    for route in raw {
        let parsed = route
            .parse::<IpNet>()
            .with_context(|| format!("parse prefix {route}"))?;
        out.push(parsed.to_string());
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn is_default_route(route: &str) -> Result<bool> {
    let parsed = route
        .parse::<IpNet>()
        .with_context(|| format!("parse prefix {route}"))?;
    Ok(parsed.prefix_len() == 0)
}

fn normalize_wire(wire: Option<WireScenario>) -> Result<Option<WireOutput>> {
    let Some(wire) = wire else {
        return Ok(None);
    };
    let mut out = WireOutput::default();
    if let Some(value) = wire.dns_config {
        let parsed: DnsConfig = serde_json::from_value(value)?;
        out.dns_config = Some(serde_json::to_value(parsed)?);
    }
    if let Some(value) = wire.derp_map {
        let parsed: DerpMap = serde_json::from_value(value)?;
        out.derp_map = Some(serde_json::to_value(parsed)?);
    }
    if let Some(value) = wire.register_request {
        let parsed: RegisterRequest = serde_json::from_value(value)?;
        out.register_request = Some(summarize_register_request(parsed));
    }
    if let Some(value) = wire.register_response {
        let parsed: RegisterResponse = serde_json::from_value(value)?;
        out.register_response = Some(summarize_register_response(parsed));
    }
    if let Some(value) = wire.map_response {
        let parsed: MapResponse = serde_json::from_value(value)?;
        out.map_response = Some(summarize_map_response(parsed)?);
    }
    Ok(Some(out))
}

fn summarize_register_request(req: RegisterRequest) -> RegisterRequestSummary {
    RegisterRequestSummary {
        node_key: req.node_key,
        auth_key: req.auth.map(|auth| auth.auth_key).unwrap_or_default(),
        hostinfo: req.hostinfo.map(summarize_hostinfo),
        followup: req.followup.unwrap_or_default(),
    }
}

fn summarize_register_response(resp: RegisterResponse) -> RegisterResponseSummary {
    RegisterResponseSummary {
        user: UserSummary {
            id: resp.user.id,
            display_name: resp.user.display_name,
        },
        login: LoginSummary {
            id: resp.login.id,
            provider: resp.login.provider,
            login_name: resp.login.login_name,
            display_name: resp.login.display_name,
        },
        node_key_expired: resp.node_key_expired,
        auth_url: resp.auth_url,
        machine_authorized: resp.machine_authorized,
    }
}

fn summarize_map_response(resp: MapResponse) -> Result<MapResponseSummary> {
    Ok(MapResponseSummary {
        keep_alive: resp.keep_alive,
        domain: resp.domain,
        node: Some(summarize_map_node(resp.node)),
        peer_count: resp.peers.len(),
        packet_filter: resp
            .packet_filter
            .into_iter()
            .map(filter_rule_out)
            .collect(),
        dns_config: Some(serde_json::to_value(resp.dns_config)?),
        derp_map: Some(serde_json::to_value(resp.derp_map)?),
    })
}

fn summarize_map_node(node: MapNode) -> MapNodeSummary {
    let mut addresses = node.addresses;
    addresses.sort();
    let mut allowed_ips = node.allowed_ips;
    allowed_ips.sort();
    let mut endpoints = node.endpoints;
    endpoints.sort();
    MapNodeSummary {
        id: node.id,
        stable_id: node.stable_id,
        name: node.name,
        user: node.user,
        key: node.key,
        machine: node.machine.unwrap_or_default(),
        disco_key: node.disco_key.unwrap_or_default(),
        addresses,
        allowed_ips,
        endpoints,
        hostinfo: Some(summarize_hostinfo(node.hostinfo)),
        machine_authorized: node.machine_authorized,
    }
}

fn summarize_hostinfo(hostinfo: HostInfo) -> HostInfoSummary {
    HostInfoSummary {
        hostname: hostinfo.hostname,
        os: hostinfo.os,
        os_version: hostinfo.os_version,
    }
}

fn filter_rule_out(rule: headscale_api::tailscale_wire::wire::FilterRule) -> FilterRuleOut {
    FilterRuleOut {
        src_ips: rule.src_ips,
        dst_ports: rule
            .dst_ports
            .into_iter()
            .map(|dst| NetPortRangeOut {
                ip: dst.ip,
                ports: PortRangeOut {
                    first: dst.ports.first,
                    last: dst.ports.last,
                },
            })
            .collect(),
        ip_proto: rule.ip_proto,
    }
}

fn scenario_paths() -> Result<Vec<PathBuf>> {
    let mut args = env::args_os()
        .skip(1)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if args.is_empty() {
        bail!("usage: headscale-rs-parity <scenario.json> [scenario.json ...]");
    }
    args.sort();
    Ok(args)
}
