//! Golden test: the production packet-filter compiler against headscale-go.
//!
//! `tools/parity/golden/headscale-go-v0.29.5.json` is the output of the real
//! v0.29.5 policy manager for every scenario in `tools/parity/scenarios/`
//! (`scripts/headscale_go_diff.sh` refuses to pass unless the pinned Go
//! module still produces exactly that file). This test feeds the same scenarios
//! to the code the server runs for `MapResponse.PacketFilters["base"]` and to
//! the global compiled filter, and requires the same output.
//!
//! What is compared, per scenario: the global filter, the filter of every
//! node (not only the nodes the scenario names), and the named
//! `filter_node_checks`. The order of the rules is compared exactly. The
//! lists inside a rule (`SrcIPs`, `DstPorts`, `IPProto`, grant caps, the
//! `CapGrant` list) are compared after sorting, because the Go harness sorts
//! them before printing; running `scripts/headscale_go_diff.sh` with
//! `PARITY_FILTER_ORDER=emitted` compares them unsorted against live Go.
//! Policies Go rejects (`expect_policy_error`) are not compiled here.

use std::{collections::BTreeMap, fs, path::PathBuf};

use headscale_api::policy::PolicyUser;
use serde::Deserialize;
use serde_json::Value;

#[allow(dead_code)]
#[path = "../../tools/parity/headscale-rs/src/production_filter.rs"]
mod production_filter;

use production_filter::{ListOrder, ParityNode, ProductionFilters, normalized_json};

#[derive(Deserialize)]
struct Scenario {
    name: String,
    policy: Value,
    #[serde(default)]
    users: Vec<ScenarioUser>,
    #[serde(default)]
    nodes: Vec<ScenarioNode>,
    #[serde(default)]
    filter_node_checks: Vec<FilterNodeCheck>,
    #[serde(default)]
    expect_policy_error: Option<String>,
}

#[derive(Deserialize)]
struct ScenarioUser {
    id: u64,
    name: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    provider_identifier: Option<String>,
}

#[derive(Deserialize)]
struct ScenarioNode {
    id: u64,
    user_id: u64,
    ipv4: String,
    #[serde(default)]
    ipv6: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    routes: Vec<String>,
    #[serde(default)]
    approved_routes: Vec<String>,
}

#[derive(Deserialize)]
struct FilterNodeCheck {
    name: String,
    node_id: u64,
}

fn parity_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tools/parity")
}

fn load_scenarios() -> Vec<Scenario> {
    let dir = parity_dir().join("scenarios");
    let mut paths = fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("reading {}: {error}", dir.display()))
        .map(|entry| entry.expect("scenario directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect::<Vec<_>>();
    paths.sort();
    paths
        .iter()
        .map(|path| {
            let raw = fs::read_to_string(path).expect("scenario is readable");
            serde_json::from_str(&raw)
                .unwrap_or_else(|error| panic!("parsing {}: {error}", path.display()))
        })
        .collect()
}

fn policy_users(scenario: &Scenario) -> Vec<PolicyUser> {
    scenario
        .users
        .iter()
        .map(|user| PolicyUser {
            id: user.id,
            name: user.name.clone(),
            email: user.email.clone(),
            provider_identifier: user.provider_identifier.clone(),
        })
        .collect()
}

fn parity_nodes(scenario: &Scenario) -> Vec<ParityNode> {
    let owners = scenario
        .users
        .iter()
        .map(|user| {
            let name = if user.email.is_empty() {
                user.name.clone()
            } else {
                user.email.clone()
            };
            (user.id, name)
        })
        .collect::<BTreeMap<_, _>>();
    scenario
        .nodes
        .iter()
        .map(|node| ParityNode {
            id: node.id,
            user_id: node.user_id,
            user: owners.get(&node.user_id).cloned(),
            ipv4: node.ipv4.clone(),
            ipv6: node.ipv6.clone(),
            tags: node.tags.clone(),
            announced_routes: node.routes.clone(),
            approved_routes: node.approved_routes.clone(),
        })
        .collect()
}

#[test]
fn production_packet_filters_match_the_headscale_go_golden() {
    let golden_path = parity_dir().join("golden/headscale-go-v0.29.5.json");
    let golden: Vec<Value> =
        serde_json::from_str(&fs::read_to_string(&golden_path).expect("golden is readable"))
            .expect("golden parses");
    let golden = golden
        .iter()
        .map(|entry| {
            (
                entry["name"].as_str().expect("golden name").to_owned(),
                entry,
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut compared = 0usize;
    let mut global_rules = 0usize;
    let mut node_filters = 0usize;
    let mut node_filter_rules = 0usize;
    let mut checked = 0usize;
    for scenario in load_scenarios() {
        let want = golden
            .get(&scenario.name)
            .unwrap_or_else(|| panic!("{} is missing from the golden", scenario.name));
        if scenario.expect_policy_error.is_some() {
            continue;
        }
        let policy = serde_json::to_vec(&scenario.policy).expect("policy serializes");
        let production =
            ProductionFilters::compile(&policy, policy_users(&scenario), &parity_nodes(&scenario))
                .unwrap_or_else(|error| {
                    panic!(
                        "{}: production rejected a policy Go accepts: {error}",
                        scenario.name
                    )
                });
        let order = ListOrder::SortedLikeGoHarness;

        let global = normalized_json(&production.global(), order);
        assert_eq!(
            global, want["filter"],
            "{}: global filter differs from headscale-go",
            scenario.name
        );
        global_rules += global.as_array().map_or(0, Vec::len);

        let golden_nodes = want
            .get("node_filters")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        assert_eq!(
            golden_nodes.len(),
            scenario.nodes.len(),
            "{}: golden has no per-node filters; refresh it with PARITY_UPDATE_GOLDEN=1",
            scenario.name
        );
        for node in golden_nodes {
            let id = node["node_id"].as_u64().expect("golden node_id");
            let got = normalized_json(&production.for_node(id), order);
            assert_eq!(
                got, node["rules"],
                "{}: packet filter for node {id} differs from headscale-go",
                scenario.name
            );
            node_filters += 1;
            node_filter_rules += got.as_array().map_or(0, Vec::len);
        }

        let golden_checks = want
            .get("filter_for_nodes")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        assert_eq!(golden_checks.len(), scenario.filter_node_checks.len());
        for (check, golden_check) in scenario.filter_node_checks.iter().zip(golden_checks) {
            assert_eq!(golden_check["name"], check.name.as_str());
            assert_eq!(
                normalized_json(&production.for_node(check.node_id), order),
                golden_check["rules"],
                "{}: filter check {} differs from headscale-go",
                scenario.name,
                check.name
            );
            checked += 1;
        }
        compared += 1;
    }

    eprintln!(
        "compared {compared} scenarios: {global_rules} global rules, {node_filters} node filters \
         ({node_filter_rules} rules), {checked} named checks"
    );
    // Guard against the test going vacuous (empty directory, empty golden).
    assert!(compared >= 55, "only {compared} scenarios were compared");
    assert!(
        global_rules >= 40,
        "only {global_rules} global rules compared"
    );
    assert!(
        node_filters >= 140,
        "only {node_filters} node filters compared"
    );
    assert!(
        node_filter_rules >= 100,
        "only {node_filter_rules} node filter rules compared"
    );
    assert!(checked >= 25, "only {checked} named filter checks compared");
}
