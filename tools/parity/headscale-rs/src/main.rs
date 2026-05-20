use std::{env, fs, path::PathBuf};

use anyhow::{Context, Result, bail};
use headscale_api::policy::{acl_to_filter_rules, parse_hujson_policy};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct Scenario {
    name: String,
    policy: Value,
}

#[derive(Debug, Serialize)]
struct ScenarioOutput {
    engine: &'static str,
    name: String,
    filter: Vec<FilterRuleOut>,
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
            name: scenario.name,
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
        });
    }

    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
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
