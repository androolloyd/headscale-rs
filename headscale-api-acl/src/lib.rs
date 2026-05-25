//! Canonical tailnet ACL document, parser, canonicalisation, and
//! evaluator — shared by `headscale-api` and `octravpn-mesh`.
//!
//! ## Why this crate exists
//!
//! Before the 2026-05-20 consolidation the ACL evaluator lived twice:
//!
//! * `octravpn-mesh::acl` — the battle-tested evaluator (51 tests),
//!   plus the OctraVPN-specific `SignedAclDoc` carrying the on-chain
//!   `acl_policy` hash binding.
//! * `headscale-api::policy::{doc,filter,hujson}` — the admin-facade
//!   copy: parser, NodeView access helpers, FilterRule translator.
//!
//! `octravpn-mesh` already depends on `headscale-api`
//! (`tailscale_wire` migrated 2026-05-19), so a back-edge from
//! `headscale-api → octravpn-mesh` is a cycle. This crate is the leaf
//! both repos consume; `headscale-api::policy` becomes a thin facade
//! over re-exports + the `PolicyStore` admin shell + the
//! `FilterRule` translator (which depends on wire types). The
//! OctraVPN extensions (`SignedAclDoc`, owner-key signing) stay in
//! `octravpn-mesh::acl`.
//!
//! ## On-chain hash binding
//!
//! The `acl_policy` field of an OctraVPN tailnet is the SHA-256 of
//! the canonicalised ACL document. The full document is distributed
//! off-chain (HTTPS, IPFS, gossip), and every member fetches it,
//! verifies the hash matches what's on-chain, then enforces the
//! decisions at the data plane. See [`AclDoc::policy_hash`].
//!
//! ## Headscale-go compatibility
//!
//! This evaluator mirrors features of upstream `juanfont/headscale`
//! `hscontrol/policy/v2/`:
//!
//! * `groups` / `tagOwners` / `hosts` definitions.
//! * `autogroup:*` expansion — `internet`, `member`, `nonroot`,
//!   `tagged`, `tag:<x>`, `self`.
//! * `autoApprovers` — route + exit-node auto-approval queried via
//!   [`AclDoc::auto_approves_route`] / [`AclDoc::auto_approves_exit_node`].
//!
//! ## Document shape
//!
//! TOML for the OctraVPN off-chain distribution; HuJSON for the
//! headscale admin PUT endpoint. Both parse to the same [`AclDoc`].
//!
//! The HuJSON parser is intentionally strict to match headscale-go:
//! upstream top-level names only (`groups`, `hosts`, `tagOwners`,
//! `acls`, `grants`, `nodeAttrs`, `autoApprovers`, `ssh`),
//! ACL `action` must be `accept`, and ports live in `dst` entries
//! (`host:22`), not a rule-level `ports` field. TOML keeps the
//! canonical/internal field names used by OctraVPN (`rules`,
//! `tag_owners`, `node_attrs`, ...).

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

// =====================================================================
// Types
// =====================================================================

/// Policy decision action. HuJSON/TOML policy parsing accepts only
/// upstream's `"accept"` action; `Deny` is retained for default-deny
/// evaluation results and programmatically constructed internal docs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AclAction {
    Accept,
    Deny,
}

impl<'de> Deserialize<'de> for AclAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let action = String::deserialize(deserializer)?;
        match action.as_str() {
            "accept" => Ok(Self::Accept),
            other => Err(serde::de::Error::custom(format!(
                "invalid action {other:?}, must be \"accept\""
            ))),
        }
    }
}

/// A single ACL rule. Sources and destinations name groups
/// (`group:<name>`), explicit addresses (`oct...`), or the wildcard
/// `*`. Parsed HuJSON follows upstream and puts ports in `dst`
/// entries (`*:22`, `tag:web:80,443`); the HuJSON entrypoint rejects
/// a rule-level `ports` field. Internally, normalized ports use the
/// `<proto>/<port>` form (`tcp/22`, `udp/*`, `*/*`; also accepted
/// programmatically: `*:tcp/22`).
///
/// `#[serde(deny_unknown_fields)]`: a misspelled rule field is a
/// loud error, not a silently permissive ACL.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AclRule {
    pub action: AclAction,
    pub src: Vec<String>,
    pub dst: Vec<String>,
    #[serde(default)]
    pub ports: Vec<String>,
}

impl<'de> Deserialize<'de> for AclRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawRule {
            action: AclAction,
            #[serde(default)]
            proto: Option<String>,
            src: Vec<String>,
            dst: Vec<String>,
            #[serde(default)]
            ports: Vec<String>,
            #[serde(flatten)]
            extra: BTreeMap<String, serde_json::Value>,
        }

        let raw = RawRule::deserialize(deserializer)?;
        if let Some(key) = raw.extra.keys().find(|key| !key.starts_with('#')) {
            return Err(serde::de::Error::unknown_field(
                key,
                &["action", "proto", "src", "dst", "ports"],
            ));
        }
        let proto = raw.proto.as_deref().map(|p| p.trim().to_ascii_lowercase());
        if let Some(proto) = proto.as_deref() {
            validate_upstream_proto(proto).map_err(serde::de::Error::custom)?;
        }
        let legacy_proto = proto.as_deref().unwrap_or("*");
        let upstream_proto = proto.as_deref().unwrap_or("");
        let mut dst = Vec::with_capacity(raw.dst.len());
        let mut ports = Vec::new();

        for port in raw.ports {
            validate_proto_port_compat(legacy_proto, &port).map_err(serde::de::Error::custom)?;
            ports.extend(normalize_port_spec(legacy_proto, &port));
        }

        for raw_dst in raw.dst {
            if let Some((alias, port_spec)) =
                split_upstream_dst_ports(&raw_dst).map_err(serde::de::Error::custom)?
            {
                validate_proto_port_compat(upstream_proto, port_spec)
                    .map_err(serde::de::Error::custom)?;
                dst.push(alias.to_string());
                ports.extend(normalize_port_spec(upstream_proto, port_spec));
            } else {
                dst.push(raw_dst);
            }
        }

        Ok(Self {
            action: raw.action,
            src: raw.src,
            dst,
            ports,
        })
    }
}

/// One `nodeAttrs` grant. Mirrors upstream
/// `juanfont/headscale@main:hscontrol/policy/v2/types.go::NodeAttrGrant`.
///
/// `target` lists principal tokens the attrs apply to. `attr` is the
/// list of capability flags the matching nodes receive — strings like
/// `"funnel"`, `"exit-node"`, `"ssh"`.
#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeAttrGrant {
    pub target: Vec<String>,
    #[serde(default)]
    pub attr: Vec<String>,
    #[serde(default)]
    pub app: CapabilityMap,
    #[serde(default, rename = "ip_pool", alias = "ipPool")]
    pub ip_pool: Vec<String>,
}

/// Application-layer capability map used by public `grants[].app`
/// and `nodeAttrs[].app` policy entries.
pub type CapabilityMap = BTreeMap<String, Vec<serde_json::Value>>;

/// One public `grants` rule. Grants have an implied accept action and
/// can carry network-layer `ip` allowances, application-layer `app`
/// capabilities, and optional route-filtering `via` tags.
#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRule {
    #[serde(default)]
    pub src: Vec<String>,
    #[serde(default)]
    pub dst: Vec<String>,
    #[serde(default, rename = "ip")]
    pub ip: Vec<String>,
    #[serde(default)]
    pub app: CapabilityMap,
    #[serde(default)]
    pub via: Vec<String>,
}

/// `autoApprovers` block — route + exit-node auto-approval.
#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoApprovers {
    #[serde(default)]
    pub routes: BTreeMap<String, Vec<String>>,
    #[serde(default, rename = "exit_node", alias = "exitNode")]
    pub exit_node: Vec<String>,
}

/// SSH grant. Minimal mirror of upstream `SSH` rule — `action`,
/// `src`, `dst`, `users`, optional `checkPeriod`, and optional
/// `acceptEnv`.
/// `deny_unknown_fields` mirrors the rest of the schema; unknown SSH
/// keys are loud parse errors.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshRule {
    pub action: String,
    pub src: Vec<String>,
    pub dst: Vec<String>,
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default, rename = "check_period", alias = "checkPeriod")]
    pub check_period: Option<String>,
    #[serde(default, rename = "accept_env", alias = "acceptEnv")]
    pub accept_env: Vec<String>,
}

/// One upstream `tests` entry. These are operator assertions checked
/// against live nodes at the gRPC write/validate boundary.
#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTest {
    pub src: String,
    #[serde(default)]
    pub proto: String,
    #[serde(default)]
    pub accept: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

/// One upstream `sshTests` entry. The parser validates shape, while
/// `headscale-api` owns semantic evaluation because it needs live
/// node state and compiled SSH policies.
#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshPolicyTest {
    pub src: String,
    #[serde(default)]
    pub dst: Vec<String>,
    #[serde(default)]
    pub accept: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub check: Vec<String>,
}

/// Top-level ACL document.
///
/// `#[serde(deny_unknown_fields)]`: unknown top-level keys are
/// rejected. Forward-compat is handled explicitly via the `version`
/// field — bump that and the parser plus this struct in lockstep.
#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AclDoc {
    #[serde(default = "default_policy_version")]
    pub version: u32,
    #[serde(default)]
    pub groups: BTreeMap<String, Vec<String>>,
    /// Legacy short-form alias (tag_name → description). Kept for
    /// backward compatibility with v1 docs.
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
    /// `tag_owners` mirrors upstream `tagOwners`.
    #[serde(default, alias = "tagOwners")]
    pub tag_owners: BTreeMap<String, Vec<String>>,
    /// `hosts`: named single-CIDR aliases. Referenced as
    /// `host:<name>`.
    #[serde(default)]
    pub hosts: BTreeMap<String, String>,
    /// `auto_approvers` / `autoApprovers`.
    #[serde(default, alias = "autoApprovers")]
    pub auto_approvers: AutoApprovers,
    /// `node_attrs` / `nodeAttrs`.
    #[serde(default, alias = "nodeAttrs")]
    pub node_attrs: Vec<NodeAttrGrant>,
    /// Public `grants` policy entries. During HuJSON parsing these
    /// are also projected into accept rules for the existing evaluator
    /// and packet-filter compiler.
    #[serde(default)]
    pub grants: Vec<GrantRule>,
    /// Upstream `randomizeClientPort`: tailnet-wide shorthand for
    /// stamping the `randomize-client-port` node attribute on every
    /// node.
    #[serde(default, alias = "randomizeClientPort")]
    pub randomize_client_port: bool,
    /// `ssh` grants. Parsed, validated, round-tripped, and compiled by
    /// `headscale-api` into a wire SSHPolicy.
    #[serde(default)]
    pub ssh: Vec<SshRule>,
    /// Upstream policy `tests` block.
    #[serde(default)]
    pub tests: Vec<PolicyTest>,
    /// Upstream policy `sshTests` block.
    #[serde(default, rename = "ssh_tests", alias = "sshTests")]
    pub ssh_tests: Vec<SshPolicyTest>,
    /// Rule list. Upstream `juanfont/headscale` calls this field
    /// `acls`; OctraVPN calls it `rules`. The `alias = "acls"` makes
    /// either spelling acceptable.
    #[serde(default, alias = "acls")]
    pub rules: Vec<AclRule>,
}

const fn default_policy_version() -> u32 {
    1
}

/// A node's identity facets used during principal / autogroup
/// matching. All fields optional — an empty `NodeView` matches only
/// `*` / `autogroup:member` (and `autogroup:nonroot` if no tags).
#[derive(Clone, Debug, Default)]
pub struct NodeView<'a> {
    pub addr: Option<&'a str>,
    pub user: Option<&'a str>,
    pub tags: &'a [String],
}

impl<'a> NodeView<'a> {
    pub fn new(addr: &'a str) -> Self {
        Self {
            addr: Some(addr),
            user: None,
            tags: &[],
        }
    }
    pub fn with_user(mut self, user: &'a str) -> Self {
        self.user = Some(user);
        self
    }
    pub fn with_tags(mut self, tags: &'a [String]) -> Self {
        self.tags = tags;
        self
    }
}

/// Reference into a (proto, port) decision. Wildcards: pass
/// `proto = None` or `port = None` to mean "any".
#[derive(Clone, Copy, Debug)]
pub struct PortRef<'a> {
    pub proto: Option<&'a str>,
    pub port: Option<u16>,
}

impl<'a> PortRef<'a> {
    pub fn new(proto: &'a str, port: u16) -> Self {
        Self {
            proto: Some(proto),
            port: Some(port),
        }
    }
    pub fn any() -> Self {
        Self {
            proto: None,
            port: None,
        }
    }
}

// =====================================================================
// Parse + canonical bytes
// =====================================================================

/// Errors emitted by [`parse_hujson_policy`] / [`AclDoc::from_toml`].
#[derive(Debug, Error)]
pub enum PolicyParseError {
    /// The byte stream didn't even parse as JSON after stripping
    /// hujson decorations.
    #[error("policy hujson did not parse as JSON: {0}")]
    Json(String),
    /// JSON-shape was valid but the document violated one of the
    /// schema constraints (`version`, unknown field, missing
    /// `action`, etc.).
    #[error("policy document failed schema validation: {0}")]
    Schema(String),
}

impl AclDoc {
    /// Empty doc, version 1, no rules.
    pub fn empty() -> Self {
        Self {
            version: 1,
            ..Default::default()
        }
    }

    /// Parse a TOML document. Unknown top-level fields and unknown
    /// rule fields are rejected.
    pub fn from_toml(input: &str) -> Result<Self, PolicyParseError> {
        let doc: Self =
            toml::from_str(input).map_err(|e| PolicyParseError::Schema(e.to_string()))?;
        validate_policy(&doc).map_err(PolicyParseError::Schema)?;
        Ok(doc)
    }

    /// Parse a hujson document. See [`parse_hujson_policy`].
    pub fn parse_hujson(raw: &str) -> Result<Self, PolicyParseError> {
        parse_hujson_policy(raw)
    }

    /// Canonical byte form: stable across irrelevant edits
    /// (whitespace, comment changes, key ordering). The on-chain
    /// hash is the SHA-256 of this form.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.canonical_value()).unwrap_or_default()
    }

    fn canonical_value(&self) -> serde_json::Value {
        let groups_sorted = sort_map_of_vecs(&self.groups);
        let mut tags_sorted: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in &self.tags {
            tags_sorted.insert(k.clone(), v.clone());
        }
        let tag_owners_sorted = sort_map_of_vecs(&self.tag_owners);
        let mut hosts_sorted: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in &self.hosts {
            hosts_sorted.insert(k.clone(), v.clone());
        }
        let auto_approver_routes = sort_map_of_vecs(&self.auto_approvers.routes);
        let mut exit_node_sorted = self.auto_approvers.exit_node.clone();
        exit_node_sorted.sort();
        let node_attrs_sorted: Vec<serde_json::Value> = self
            .node_attrs
            .iter()
            .map(|n| {
                let mut tgt = n.target.clone();
                let mut atr = n.attr.clone();
                let mut ip_pool = n.ip_pool.clone();
                tgt.sort();
                atr.sort();
                ip_pool.sort();
                serde_json::json!({
                    "target": tgt,
                    "attr": atr,
                    "app": n.app,
                    "ip_pool": ip_pool,
                })
            })
            .collect();
        let grants_sorted: Vec<serde_json::Value> = self
            .grants
            .iter()
            .map(|g| {
                let mut src = g.src.clone();
                let mut dst = g.dst.clone();
                let mut ip = g.ip.clone();
                let mut via = g.via.clone();
                src.sort();
                dst.sort();
                ip.sort();
                via.sort();
                serde_json::json!({
                    "src": src,
                    "dst": dst,
                    "ip": ip,
                    "app": g.app,
                    "via": via,
                })
            })
            .collect();
        let ssh_sorted: Vec<serde_json::Value> = self
            .ssh
            .iter()
            .map(|s| {
                let mut src = s.src.clone();
                let mut dst = s.dst.clone();
                let mut users = s.users.clone();
                let mut accept_env = s.accept_env.clone();
                src.sort();
                dst.sort();
                users.sort();
                accept_env.sort();
                let mut value = serde_json::Map::new();
                value.insert("action".to_string(), serde_json::json!(s.action));
                value.insert("src".to_string(), serde_json::json!(src));
                value.insert("dst".to_string(), serde_json::json!(dst));
                value.insert("users".to_string(), serde_json::json!(users));
                if let Some(check_period) = &s.check_period {
                    value.insert("check_period".to_string(), serde_json::json!(check_period));
                }
                if !accept_env.is_empty() {
                    value.insert("accept_env".to_string(), serde_json::json!(accept_env));
                }
                serde_json::Value::Object(value)
            })
            .collect();
        let mut value = serde_json::json!({
            "version": self.version,
            "groups": groups_sorted,
            "tags": tags_sorted,
            "tag_owners": tag_owners_sorted,
            "hosts": hosts_sorted,
            "auto_approvers": {
                "routes": auto_approver_routes,
                "exit_node": exit_node_sorted,
            },
            "node_attrs": node_attrs_sorted,
            "grants": grants_sorted,
            "ssh": ssh_sorted,
            "tests": self.tests,
            "ssh_tests": self.ssh_tests,
            "rules": self.rules.iter().map(|r| {
                let mut src = r.src.clone();
                let mut dst = r.dst.clone();
                let mut ports = r.ports.clone();
                src.sort();
                dst.sort();
                ports.sort();
                serde_json::json!({
                    "action": match r.action {
                        AclAction::Accept => "accept",
                        AclAction::Deny => "deny",
                    },
                    "src": src,
                    "dst": dst,
                    "ports": ports,
                })
            }).collect::<Vec<_>>(),
        });
        if self.randomize_client_port {
            value["randomize_client_port"] = serde_json::Value::Bool(true);
        }
        value
    }

    /// SHA-256 of `canonical_bytes`. Matches the on-chain
    /// `acl_policy` field for the OctraVPN tailnet that owns this
    /// document.
    pub fn policy_hash(&self) -> [u8; 32] {
        let bytes = self.canonical_bytes();
        let mut h = Sha256::new();
        h.update(&bytes);
        let out = h.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        arr
    }
}

fn sort_map_of_vecs(m: &BTreeMap<String, Vec<String>>) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for (k, v) in m {
        let mut sorted = v.clone();
        sorted.sort();
        out.insert(k.clone(), sorted);
    }
    out
}

/// Strip hujson decorations + parse as an [`AclDoc`]. The
/// `headscale-api` admin layer drives this through
/// `POST /api/v1/policy/validate` and `PUT /api/v1/policy`.
pub fn parse_hujson_policy(raw: &str) -> Result<AclDoc, PolicyParseError> {
    let stripped = strip_hujson(raw);
    let value: serde_json::Value =
        serde_json::from_str(&stripped).map_err(|e| PolicyParseError::Json(e.to_string()))?;
    let value = normalize_go_policy_top_level(value)?;
    let mut doc = serde_json::from_value::<AclDoc>(value)
        .map_err(|e| PolicyParseError::Schema(e.to_string()))?;
    let grant_rules = acl_rules_from_grants(&doc.grants).map_err(PolicyParseError::Schema)?;
    doc.rules.extend(grant_rules);
    validate_policy(&doc).map_err(PolicyParseError::Schema)?;
    Ok(doc)
}

fn normalize_go_policy_top_level(
    value: serde_json::Value,
) -> Result<serde_json::Value, PolicyParseError> {
    let serde_json::Value::Object(object) = value else {
        return Ok(value);
    };

    let mut normalized = serde_json::Map::new();
    for (key, value) in object {
        let Some(canonical) = go_policy_field_name(&key) else {
            return Err(PolicyParseError::Schema(format!("unknown field {key:?}")));
        };
        if canonical == "groups" {
            validate_go_policy_groups(&value)?;
        }
        if canonical == "acls" {
            validate_go_acl_rules(&value)?;
        }
        if normalized.insert(canonical.to_string(), value).is_some() {
            return Err(PolicyParseError::Schema(format!(
                "duplicate field {canonical:?}"
            )));
        }
    }

    Ok(serde_json::Value::Object(normalized))
}

fn validate_go_policy_groups(value: &serde_json::Value) -> Result<(), PolicyParseError> {
    let serde_json::Value::Object(groups) = value else {
        return Ok(());
    };

    for (group, members) in groups {
        if !group.starts_with("group:") {
            return Err(PolicyParseError::Schema(format!(
                r#"Group has to start with "group:", got: {group:?}"#
            )));
        }

        let serde_json::Value::Array(members) = members else {
            return Ok(());
        };
        for member in members {
            let Some(member) = member.as_str() else {
                continue;
            };
            if member.starts_with("group:") {
                return Err(PolicyParseError::Schema(format!(
                    r"Nested groups are not allowed, found {member:?} inside {group:?}"
                )));
            }
            if !member.contains('@') {
                return Err(PolicyParseError::Schema(format!(
                    "Username has to contain @, got: {member:?}"
                )));
            }
        }
    }

    Ok(())
}

fn go_policy_field_name(field: &str) -> Option<&'static str> {
    match field.to_ascii_lowercase().as_str() {
        "groups" => Some("groups"),
        "hosts" => Some("hosts"),
        "tagowners" => Some("tagOwners"),
        "acls" => Some("acls"),
        "grants" => Some("grants"),
        "nodeattrs" => Some("nodeAttrs"),
        "autoapprovers" => Some("autoApprovers"),
        "randomizeclientport" => Some("randomizeClientPort"),
        "ssh" => Some("ssh"),
        "tests" => Some("tests"),
        "sshtests" => Some("sshTests"),
        _ => None,
    }
}

fn validate_go_acl_rules(value: &serde_json::Value) -> Result<(), PolicyParseError> {
    let serde_json::Value::Array(rules) = value else {
        return Ok(());
    };

    for rule in rules {
        let serde_json::Value::Object(fields) = rule else {
            continue;
        };
        for key in fields.keys().filter(|key| !key.starts_with('#')) {
            if go_acl_field_name(key).is_none() {
                return Err(PolicyParseError::Schema(format!("unknown field {key:?}")));
            }
        }
        validate_go_acl_destinations(fields)?;
    }

    Ok(())
}

fn go_acl_field_name(field: &str) -> Option<&'static str> {
    match field.to_ascii_lowercase().as_str() {
        "action" => Some("action"),
        "proto" => Some("proto"),
        "src" => Some("src"),
        "dst" => Some("dst"),
        _ => None,
    }
}

fn validate_go_acl_destinations(
    fields: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), PolicyParseError> {
    let Some(serde_json::Value::Array(destinations)) = fields.get("dst") else {
        return Ok(());
    };

    for destination in destinations {
        let Some(destination) = destination.as_str() else {
            continue;
        };
        let (alias, port_spec) =
            split_go_destination_and_port(destination).map_err(PolicyParseError::Schema)?;
        validate_upstream_port_spec(port_spec).map_err(PolicyParseError::Schema)?;
        validate_go_acl_alias_syntax(alias).map_err(PolicyParseError::Schema)?;
    }

    Ok(())
}

fn split_go_destination_and_port(input: &str) -> Result<(&str, &str), String> {
    let Some((destination, port)) = input.rsplit_once(':') else {
        return Err(r#"hostport must contain a colon (":")"#.to_string());
    };
    if destination.is_empty() {
        return Err("input cannot start with a colon character".to_string());
    }
    if port.is_empty() {
        return Err("input cannot end with a colon character".to_string());
    }
    Ok((destination, port))
}

fn validate_go_acl_alias_syntax(alias: &str) -> Result<(), String> {
    if alias == "*"
        || alias.contains('@')
        || alias.starts_with("group:")
        || alias.starts_with("tag:")
        || alias.starts_with("autogroup:")
        || parse_cidr(alias).is_some()
        || is_go_host_alias(alias)
    {
        return Ok(());
    }

    Err(format!(
        r"Invalid alias {alias:?}. An alias must be one of the supported upstream policy alias types"
    ))
}

fn is_go_host_alias(alias: &str) -> bool {
    !alias.contains(':')
}

fn acl_rules_from_grants(grants: &[GrantRule]) -> Result<Vec<AclRule>, String> {
    let mut out = Vec::new();
    for grant in grants {
        if grant.ip.is_empty() || !grant.via.is_empty() {
            continue;
        }
        let mut ports = Vec::new();
        for spec in &grant.ip {
            ports.extend(normalize_grant_ip_spec(spec)?);
        }
        if ports.is_empty() {
            continue;
        }
        out.push(AclRule {
            action: AclAction::Accept,
            src: grant.src.clone(),
            dst: grant.dst.clone(),
            ports,
        });
    }
    Ok(out)
}

fn validate_policy(doc: &AclDoc) -> Result<(), String> {
    let mut errs = Vec::new();

    for grant in &doc.grants {
        validate_grant_rule(doc, grant, &mut errs);
    }
    for rule in &doc.rules {
        validate_acl_rule(doc, rule, &mut errs);
    }
    for grant in &doc.node_attrs {
        validate_node_attr_grant(doc, grant, &mut errs);
    }
    for ssh in &doc.ssh {
        validate_ssh_rule(doc, ssh, &mut errs);
    }
    validate_policy_tests(doc, &doc.tests, &mut errs);
    validate_ssh_tests(doc, &doc.ssh_tests, &mut errs);
    for owners in doc.tag_owners.values() {
        for owner in owners {
            validate_owner_ref(doc, owner, &mut errs);
        }
    }
    for approvers in doc.auto_approvers.routes.values() {
        for approver in approvers {
            validate_approver_ref(doc, approver, &mut errs);
        }
    }
    for approver in &doc.auto_approvers.exit_node {
        validate_approver_ref(doc, approver, &mut errs);
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join("; "))
    }
}

fn validate_grant_rule(doc: &AclDoc, grant: &GrantRule, errs: &mut Vec<String>) {
    if grant.ip.is_empty() && grant.app.is_empty() {
        errs.push("ip and app can not both be empty".to_string());
    }

    for cap in grant.app.keys() {
        if let Err(err) = validate_capability_name(cap) {
            errs.push(err);
        }
    }

    if !grant.app.is_empty() && grant.dst.iter().any(|dst| dst == "autogroup:internet") {
        errs.push("cannot use app grants with autogroup:internet".to_string());
    }

    for src in &grant.src {
        validate_grant_src_alias(src, errs);
        validate_acl_ref(doc, src, errs);
    }
    for dst in &grant.dst {
        validate_acl_dst_alias(dst, errs);
        validate_acl_ref(doc, dst, errs);
        if parse_cidr(dst).is_some_and(|net| is_default_route(&net)) {
            errs.push(format!(
                "dst {dst:?}: to allow all IP addresses, use \"*\" or \"autogroup:internet\""
            ));
        }
    }

    for via in &grant.via {
        if !via.starts_with("tag:") {
            errs.push("via can only be a tag".to_string());
        } else if !tag_defined(doc, via) {
            errs.push(format!("tag {via:?} not found"));
        }
    }

    if grant.dst.iter().any(|dst| dst == "autogroup:self") {
        for src in &grant.src {
            let allowed =
                src.contains('@') || src.starts_with("group:") || src == "autogroup:member";
            if !allowed {
                errs.push(
                    "autogroup:self can only be used with users, groups, or supported autogroups"
                        .to_string(),
                );
                break;
            }
        }
    }
}

fn validate_node_attr_grant(doc: &AclDoc, grant: &NodeAttrGrant, errs: &mut Vec<String>) {
    for cap in grant.app.keys() {
        if let Err(err) = validate_capability_name(cap) {
            errs.push(err);
        }
    }
    for target in &grant.target {
        if let Some(ag) = target.strip_prefix("autogroup:")
            && !matches!(ag, "member" | "tagged")
        {
            errs.push(format!(
                "nodeAttrs target does not support this autogroup: {target:?}"
            ));
        }
        validate_acl_ref(doc, target, errs);
    }
    for pool in &grant.ip_pool {
        let Some(net) = parse_cidr(pool) else {
            errs.push(format!("nodeAttrs ipPool contains invalid prefix {pool:?}"));
            continue;
        };
        if !cgnat_range().contains(&net.network()) || net.prefix_len() < 10 {
            errs.push(format!(
                "nodeAttrs ipPool must be within 100.64.0.0/10: {pool:?}"
            ));
        }
    }
}

fn validate_acl_rule(doc: &AclDoc, rule: &AclRule, errs: &mut Vec<String>) {
    for src in &rule.src {
        validate_acl_src_alias(src, errs);
        validate_acl_ref(doc, src, errs);
    }
    for dst in &rule.dst {
        validate_acl_dst_alias(dst, errs);
        validate_acl_ref(doc, dst, errs);
    }
}

fn validate_grant_src_alias(alias: &str, errs: &mut Vec<String>) {
    if alias == "autogroup:danger-all" {
        return;
    }
    validate_acl_src_alias(alias, errs);
}

fn validate_acl_src_alias(alias: &str, errs: &mut Vec<String>) {
    let Some(ag) = alias.strip_prefix("autogroup:") else {
        return;
    };
    match ag {
        "internet" => errs.push(
            r#""autogroup:internet" used in source, it can only be used in ACL destinations"#
                .to_string(),
        ),
        "self" => errs.push(
            r#""autogroup:self" used in source, it can only be used in ACL destinations"#
                .to_string(),
        ),
        "member" | "tagged" => {}
        "nonroot" => errs.push(format!(
            "autogroup {alias:?} is not supported for ACL sources, can be [autogroup:member autogroup:tagged]"
        )),
        _ => errs.push(format!(
            "AutoGroup is invalid, got: {alias:?}, must be one of [autogroup:internet autogroup:member autogroup:nonroot autogroup:tagged autogroup:self]"
        )),
    }
}

fn validate_acl_dst_alias(alias: &str, errs: &mut Vec<String>) {
    let Some(ag) = alias.strip_prefix("autogroup:") else {
        return;
    };
    match ag {
        "internet" | "member" | "tagged" | "self" => {}
        "nonroot" => errs.push(format!(
            "autogroup {alias:?} is not supported for ACL destinations, can be [autogroup:internet autogroup:member autogroup:tagged autogroup:self]"
        )),
        _ => errs.push(format!(
            "AutoGroup is invalid, got: {alias:?}, must be one of [autogroup:internet autogroup:member autogroup:nonroot autogroup:tagged autogroup:self]"
        )),
    }
}

fn validate_ssh_rule(doc: &AclDoc, rule: &SshRule, errs: &mut Vec<String>) {
    match rule.action.as_str() {
        "accept" | "check" => {}
        other => errs.push(format!(
            "invalid SSH action {other:?}, must be one of: accept, check"
        )),
    }

    if rule.users.is_empty() {
        errs.push("users must be specified".to_string());
    }

    if let Some(period) = rule.check_period.as_deref() {
        if rule.action == "check" {
            match parse_duration_nanos(period) {
                Some(nanos) if nanos <= SSH_CHECK_PERIOD_MAX_NANOS => {}
                Some(nanos) => errs.push(format!(
                    "checkPeriod {} is above the max (168h)",
                    format_duration_nanos(nanos)
                )),
                None => errs.push(format!("not a valid duration string: {period:?}")),
            }
        } else {
            errs.push("checkPeriod is only valid with action \"check\"".to_string());
        }
    }

    for user in &rule.users {
        if matches!(user.as_str(), "" | "*") {
            errs.push(format!("user {user:?} is not a valid SSH user"));
        }
    }

    for env in &rule.accept_env {
        if env.is_empty() {
            errs.push("acceptEnv values cannot be empty".to_string());
        }
    }

    for src in &rule.src {
        validate_ssh_src_alias(src, errs);
        validate_group_ref(doc, src, errs);
        validate_tag_ref(doc, src, errs);
        validate_ssh_source_group_recursion(doc, src, errs);
    }
    for dst in &rule.dst {
        validate_ssh_dst_alias(doc, dst, errs);
        validate_tag_ref(doc, dst, errs);
    }
    validate_ssh_src_dst_combination(&rule.src, &rule.dst, errs);
}

fn validate_policy_tests(doc: &AclDoc, tests: &[PolicyTest], errs: &mut Vec<String>) {
    for (index, test) in tests.iter().enumerate() {
        if test.accept.is_empty() && test.deny.is_empty() {
            errs.push(format!(
                "test {index}: tests entry must include at least one accept or deny assertion"
            ));
        }

        let proto = test.proto.trim().to_ascii_lowercase();
        if !proto.is_empty() && !matches!(proto.as_str(), "tcp" | "udp" | "sctp") {
            errs.push(format!(
                "test {index}: protocol {proto:?} is not allowed in policy tests"
            ));
        }

        for dst in &test.accept {
            if let Err(err) = validate_policy_test_destination(doc, dst) {
                errs.push(format!("test {index}, accept {dst:?}: {err}"));
            }
        }
        for dst in &test.deny {
            if let Err(err) = validate_policy_test_destination(doc, dst) {
                errs.push(format!("test {index}, deny {dst:?}: {err}"));
            }
        }
    }
}

fn validate_policy_test_destination(doc: &AclDoc, dst: &str) -> Result<(), String> {
    let (alias, port) = split_upstream_dst_ports(dst)?
        .ok_or_else(|| "tests destination must include one explicit port".to_string())?;
    if alias == "autogroup:internet" {
        return Err("autogroup:internet is not allowed as a tests destination".to_string());
    }
    if alias.contains('/') {
        return Err("CIDR ranges are not allowed as tests destinations".to_string());
    }
    if port == "*" || port.contains(',') || port.contains('-') {
        return Err("tests destination must include exactly one port".to_string());
    }
    let parsed = parse_upstream_port(port)?;
    if parsed == 0 {
        return Err("first port must be >0, or use '*' for wildcard".to_string());
    }
    let host = alias.strip_prefix("host:").unwrap_or(alias);
    if let Some(prefix) = doc.hosts.get(host)
        && parse_cidr(prefix)
            .is_some_and(|cidr| cidr.prefix_len() < if cidr.addr().is_ipv4() { 32 } else { 128 })
    {
        return Err("host aliases used in tests must resolve to one address".to_string());
    }
    Ok(())
}

fn validate_ssh_tests(doc: &AclDoc, tests: &[SshPolicyTest], errs: &mut Vec<String>) {
    for (index, test) in tests.iter().enumerate() {
        if test.src.trim().is_empty() {
            errs.push(format!(
                "sshTest {index}: SSH tests entry must have a non-empty src"
            ));
        }
        if test.dst.is_empty() {
            errs.push(format!(
                "sshTest {index}: SSH tests entry must have at least one dst"
            ));
        }
        for dst in &test.dst {
            if let Err(err) = validate_ssh_test_destination(doc, dst) {
                errs.push(format!("sshTest {index}: {err}"));
            }
        }
    }
}

fn validate_ssh_test_destination(doc: &AclDoc, dst: &str) -> Result<(), String> {
    if split_upstream_dst_ports(dst)?.is_some() {
        return Err(format!("SSH tests dst contains disallowed element {dst:?}"));
    }
    if dst == "autogroup:internet" {
        return Err(format!("SSH tests dst contains disallowed element {dst:?}"));
    }
    if let Some(cidr) = parse_cidr(dst)
        && cidr.prefix_len() < if cidr.addr().is_ipv4() { 32 } else { 128 }
    {
        return Err(format!("SSH tests dst contains disallowed element {dst:?}"));
    }
    let host = dst.strip_prefix("host:").unwrap_or(dst);
    if let Some(prefix) = doc.hosts.get(host)
        && parse_cidr(prefix)
            .is_some_and(|cidr| cidr.prefix_len() < if cidr.addr().is_ipv4() { 32 } else { 128 })
    {
        return Err(format!("SSH tests dst contains disallowed element {dst:?}"));
    }
    if dst.starts_with("tag:") && !tag_defined(doc, dst) {
        return Err(format!("SSH tests dst contains unknown tag {dst:?}"));
    }
    Ok(())
}

fn validate_acl_ref(doc: &AclDoc, alias: &str, errs: &mut Vec<String>) {
    validate_group_ref(doc, alias, errs);
    validate_tag_ref(doc, alias, errs);

    if alias.starts_with("ipset:") {
        errs.push("ipset aliases are not supported by headscale-go policy".to_string());
        return;
    }

    if let Some(host) = alias.strip_prefix("host:") {
        if !host_defined(doc, host) {
            errs.push(format!(
                "Host {host:?} is not defined in the Policy, please define or remove the reference to it"
            ));
        }
        return;
    }

    if is_bare_host_alias(alias) && !host_defined(doc, alias) {
        errs.push(format!(
            "Host {alias:?} is not defined in the Policy, please define or remove the reference to it"
        ));
    }
}

fn validate_owner_ref(doc: &AclDoc, owner: &str, errs: &mut Vec<String>) {
    validate_group_ref(doc, owner, errs);
    if owner.starts_with("tag:") {
        validate_tag_ref(doc, owner, errs);
    }
}

fn validate_approver_ref(doc: &AclDoc, approver: &str, errs: &mut Vec<String>) {
    validate_group_ref(doc, approver, errs);
    validate_tag_ref(doc, approver, errs);
}

fn validate_group_ref(doc: &AclDoc, alias: &str, errs: &mut Vec<String>) {
    if alias.starts_with("group:") && !group_defined(doc, alias) {
        errs.push(format!(
            "Group {alias:?} is not defined in the Policy, please define or remove the reference to it"
        ));
    }
}

fn validate_tag_ref(doc: &AclDoc, alias: &str, errs: &mut Vec<String>) {
    if alias.starts_with("tag:") && !tag_defined(doc, alias) {
        errs.push(format!(
            "Tag {alias:?} is not defined in the Policy, please define or remove the reference to it"
        ));
    }
}

fn group_defined(doc: &AclDoc, group: &str) -> bool {
    doc.groups.contains_key(group)
        || group
            .strip_prefix("group:")
            .is_some_and(|short| doc.groups.contains_key(short))
}

fn group_members<'a>(doc: &'a AclDoc, group: &str) -> Option<&'a Vec<String>> {
    if let Some(short) = group.strip_prefix("group:") {
        return doc.groups.get(short).or_else(|| doc.groups.get(group));
    }
    doc.groups.get(group)
}

fn canonical_group_ref(group: &str) -> String {
    if group.starts_with("group:") {
        group.to_string()
    } else {
        format!("group:{group}")
    }
}

fn validate_ssh_source_group_recursion(doc: &AclDoc, src: &str, errs: &mut Vec<String>) {
    if !src.starts_with("group:") {
        return;
    }

    let mut visiting = BTreeSet::new();
    let mut chain = Vec::new();
    validate_ssh_source_group_chain(doc, src, &mut visiting, &mut chain, errs);
}

fn validate_ssh_source_group_chain(
    doc: &AclDoc,
    group: &str,
    visiting: &mut BTreeSet<String>,
    chain: &mut Vec<String>,
    errs: &mut Vec<String>,
) {
    let group_ref = canonical_group_ref(group);
    if visiting.contains(&group_ref) {
        let cycle_start = chain
            .iter()
            .position(|entry| entry == &group_ref)
            .unwrap_or(0);
        let mut cycle = chain[cycle_start..].to_vec();
        cycle.sort();
        errs.push(format!(
            "circular group reference detected in SSH source: {}",
            cycle.join(" -> ")
        ));
        return;
    }

    let Some(members) = group_members(doc, group) else {
        return;
    };

    visiting.insert(group_ref.clone());
    chain.push(group_ref.clone());

    for member in members {
        if member.starts_with("group:") {
            validate_ssh_source_group_chain(doc, member, visiting, chain, errs);
        }
    }

    chain.pop();
    visiting.remove(&group_ref);
}

fn tag_defined(doc: &AclDoc, tag: &str) -> bool {
    doc.tag_owners.contains_key(tag)
        || doc.tags.contains_key(tag)
        || tag
            .strip_prefix("tag:")
            .is_some_and(|short| doc.tag_owners.contains_key(short) || doc.tags.contains_key(short))
}

fn host_defined(doc: &AclDoc, host: &str) -> bool {
    doc.hosts.contains_key(host)
}

fn is_bare_host_alias(alias: &str) -> bool {
    alias != "*"
        && !alias.contains('@')
        && !alias.contains(':')
        && !alias.starts_with("group:")
        && !alias.starts_with("tag:")
        && !alias.starts_with("autogroup:")
        && parse_cidr(alias).is_none()
}

fn validate_ssh_src_alias(alias: &str, errs: &mut Vec<String>) {
    if alias == "*" {
        errs.push("alias v2.Asterix is not supported for SSH source".to_string());
        return;
    }

    let Some(ag) = alias.strip_prefix("autogroup:") else {
        return;
    };
    match ag {
        "internet" => errs.push(
            r#""autogroup:internet" used in SSH source, it can only be used in ACL destinations"#
                .to_string(),
        ),
        "member" | "tagged" => {}
        "nonroot" | "self" => errs.push(format!(
            "autogroup {alias:?} is not supported for SSH sources, can be [autogroup:member autogroup:tagged]"
        )),
        _ => errs.push(format!(
            "AutoGroup is invalid, got: {alias:?}, must be one of [autogroup:internet autogroup:member autogroup:nonroot autogroup:tagged autogroup:self]"
        )),
    }
}

fn validate_ssh_dst_alias(doc: &AclDoc, alias: &str, errs: &mut Vec<String>) {
    if alias == "*" {
        errs.push(
            "wildcard (*) is not supported as SSH destination; use 'autogroup:member' for user-owned devices, 'autogroup:tagged' for tagged devices, or specific tags/users"
                .to_string(),
        );
        return;
    }

    if alias.starts_with("host:") || host_defined(doc, alias) {
        errs.push(format!("invalid dst {alias:?}"));
        return;
    }

    let Some(ag) = alias.strip_prefix("autogroup:") else {
        return;
    };
    match ag {
        "internet" => errs.push(
            r#""autogroup:internet" used in SSH destination, it can only be used in ACL destinations"#
                .to_string(),
        ),
        "member" | "tagged" | "self" => {}
        "nonroot" => errs.push(format!(
            "autogroup {alias:?} is not supported for SSH sources, can be [autogroup:member autogroup:tagged autogroup:self]"
        )),
        _ => errs.push(format!(
            "AutoGroup is invalid, got: {alias:?}, must be one of [autogroup:internet autogroup:member autogroup:nonroot autogroup:tagged autogroup:self]"
        )),
    }
}

fn validate_ssh_src_dst_combination(srcs: &[String], dsts: &[String], errs: &mut Vec<String>) {
    let mut src_has_tagged_entities = false;
    let mut src_has_groups = false;
    let mut src_usernames: Vec<&str> = Vec::new();

    for src in srcs {
        if src.starts_with("tag:") || src == "autogroup:tagged" {
            src_has_tagged_entities = true;
        } else if src.starts_with("group:") || src == "autogroup:member" {
            src_has_groups = true;
        } else if src.contains('@') && !src_usernames.contains(&src.as_str()) {
            src_usernames.push(src.as_str());
        }
    }

    for dst in dsts {
        if dst.contains('@') {
            if src_has_tagged_entities {
                errs.push(format!(
                    "tags in SSH source cannot access user-owned devices ({dst}); use autogroup:tagged or specific tags as destinations instead"
                ));
            }
            if src_has_groups || src_usernames.len() != 1 || src_usernames[0] != dst.as_str() {
                errs.push(format!(
                    "user destination requires source to contain only that same user {dst:?}; use autogroup:self instead for same-user SSH access"
                ));
            }
        } else if dst == "autogroup:self" && src_has_tagged_entities {
            errs.push(
                "autogroup:self destination requires source to contain only users or groups, not tags or autogroup:tagged"
                    .to_string(),
            );
        } else if dst == "autogroup:member" && src_has_tagged_entities {
            errs.push(
                "tags in SSH source cannot access autogroup:member (user-owned devices)"
                    .to_string(),
            );
        }
    }
}

const SSH_CHECK_PERIOD_MAX_NANOS: i64 = 168 * 60 * 60 * 1_000_000_000;

fn parse_duration_nanos(input: &str) -> Option<i64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed == "always" {
        return Some(0);
    }
    if trimmed == "0" {
        return Some(0);
    }

    let bytes = trimmed.as_bytes();
    let mut pos = 0usize;
    let mut total: i128 = 0;
    while pos < bytes.len() {
        if !bytes[pos].is_ascii_digit() {
            return None;
        }
        let start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        let value: i128 = trimmed[start..pos].parse().ok()?;
        let unit_start = pos;
        while pos < bytes.len() && !bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        let unit = &trimmed[unit_start..pos];
        let multiplier: i128 = match unit {
            "ns" => 1,
            "us" | "µs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60 * 1_000_000_000,
            "h" => 60 * 60 * 1_000_000_000,
            "d" => 24 * 60 * 60 * 1_000_000_000,
            "w" => 7 * 24 * 60 * 60 * 1_000_000_000,
            "y" => 365 * 24 * 60 * 60 * 1_000_000_000,
            _ => return None,
        };
        total = total.checked_add(value.checked_mul(multiplier)?)?;
    }
    i64::try_from(total).ok()
}

fn format_duration_nanos(nanos: i64) -> String {
    if nanos % (60 * 60 * 1_000_000_000) == 0 {
        return format!("{}h", nanos / (60 * 60 * 1_000_000_000));
    }
    format!("{nanos}ns")
}

/// Strip `//` + `/* … */` comments and trailing commas. Preserves
/// every byte inside string literals (so a URL like
/// `http://x/y//z` survives intact). Same state machine as the
/// `headscale-cli::admin::policy::strip_hujson` helper — keep the
/// two in sync.
pub fn strip_hujson(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let mut in_str = false;
    let mut esc = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_str {
            out.push(c as char);
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        if c == b'"' {
            in_str = true;
            out.push('"');
            i += 1;
            continue;
        }
        if c == b',' {
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j] as char).is_whitespace() {
                j += 1;
            }
            if j < bytes.len() && (bytes[j] == b']' || bytes[j] == b'}') {
                i += 1;
                continue;
            }
        }
        out.push(c as char);
        i += 1;
    }
    out
}

// =====================================================================
// Evaluation
// =====================================================================

impl AclDoc {
    /// Evaluate a (src, dst, port) tuple. Returns the action of the
    /// first matching rule, or `Deny` if no rule matched
    /// (default-deny).
    pub fn decide(&self, src: &str, dst: &str, port: PortRef<'_>) -> AclAction {
        let src_view = NodeView::new(src);
        let dst_view = NodeView::new(dst);
        self.evaluate_with(&src_view, &dst_view, port)
    }

    /// Evaluate using full NodeViews so the matcher can resolve
    /// `autogroup:self`, `autogroup:member`, `autogroup:nonroot`,
    /// `autogroup:tagged`, `autogroup:tag:<x>`, and
    /// `host:` aliases.
    pub fn evaluate_with(
        &self,
        src: &NodeView<'_>,
        dst: &NodeView<'_>,
        port: PortRef<'_>,
    ) -> AclAction {
        for rule in &self.rules {
            if self.matches(rule, src, dst, port) {
                return rule.action.clone();
            }
        }
        AclAction::Deny
    }

    /// Return true when `src` can reach `dst` itself or a route served
    /// by `dst`. This mirrors headscale-go's peer visibility check,
    /// where a peer is visible if a matcher allows the peer node IP,
    /// one of its subnet routes, or its default-route exit-node
    /// prefixes.
    pub fn can_access_node(
        &self,
        src: &NodeView<'_>,
        dst: &NodeView<'_>,
        dst_routes: &[String],
        port: PortRef<'_>,
    ) -> bool {
        for rule in &self.rules {
            if self.matches_node_or_route(rule, src, dst, dst_routes, port) {
                return rule.action == AclAction::Accept;
            }
        }
        self.grants
            .iter()
            .any(|grant| self.grant_matches_node_or_route(grant, src, dst, dst_routes, port))
    }

    /// Return the routes that `peer` should include or exclude for
    /// `viewer` because of upstream `grants[*].via` route steering.
    pub fn via_routes_for_peer(
        &self,
        viewer: &NodeView<'_>,
        peer: &NodeView<'_>,
        peer_routes: &[String],
    ) -> ViaRouteGrantResult {
        self.via_routes_for_peer_with_candidates(viewer, 0, peer, 0, peer_routes, &[])
    }

    /// Return the routes that `peer` should include, exclude, or defer
    /// to global primary-route election for `viewer` because of upstream
    /// `grants[*].via` route steering.
    pub fn via_routes_for_peer_with_candidates(
        &self,
        viewer: &NodeView<'_>,
        viewer_id: u64,
        peer: &NodeView<'_>,
        peer_id: u64,
        peer_routes: &[String],
        candidates: &[ViaRouteCandidate<'_>],
    ) -> ViaRouteGrantResult {
        let mut result = ViaRouteGrantResult::default();
        if viewer_id != 0 && viewer_id == peer_id {
            return result;
        }

        for grant in &self.grants {
            if grant.via.is_empty()
                || !self.grant_src_matches(grant, viewer)
                || !grant_port_matches(grant, PortRef::any())
            {
                continue;
            }

            let matched = peer_routes
                .iter()
                .filter(|route| self.grant_dsts_overlap_route(grant, route))
                .cloned()
                .collect::<Vec<_>>();
            if matched.is_empty() {
                continue;
            }

            let peer_has_via = grant.via.iter().any(|via| {
                via.strip_prefix("tag:")
                    .is_some_and(|tag| peer.tags.iter().any(|peer_tag| tag_matches(peer_tag, tag)))
            });
            let target = if peer_has_via {
                &mut result.include
            } else {
                &mut result.exclude
            };
            for route in matched {
                if !target.contains(&route) {
                    target.push(route);
                }
            }
        }

        if !result.include.is_empty() || !result.exclude.is_empty() {
            for grant in &self.grants {
                if grant.via.is_empty()
                    || !self.grant_src_matches(grant, viewer)
                    || !grant_port_matches(grant, PortRef::any())
                {
                    continue;
                }

                for included in result.include.clone() {
                    if !self.grant_dsts_overlap_route(grant, &included) {
                        continue;
                    }

                    let via_primary_id = candidates
                        .iter()
                        .filter(|node| {
                            grant.via.iter().any(|via| {
                                via.strip_prefix("tag:").is_some_and(|tag| {
                                    node.tags.iter().any(|node_tag| tag_matches(node_tag, tag))
                                })
                            }) && node.routes.iter().any(|route| route == &included)
                        })
                        .map(|node| node.id)
                        .min();

                    if via_primary_id.is_some_and(|id| id != peer_id) {
                        result.include.retain(|route| route != &included);
                        push_unique(&mut result.exclude, included);
                    }
                }
            }

            for route in result.include.clone() {
                if self.regular_policy_allows_route(viewer, peer, &route) {
                    push_unique(&mut result.use_primary, route);
                }
            }

            result
                .exclude
                .retain(|route| !self.regular_policy_allows_route(viewer, peer, route));
        }

        result.include.sort();
        result.include.dedup();
        result.exclude.sort();
        result.exclude.dedup();
        result.use_primary.sort();
        result.use_primary.dedup();
        result
    }

    fn regular_policy_allows_route(
        &self,
        viewer: &NodeView<'_>,
        peer: &NodeView<'_>,
        route: &str,
    ) -> bool {
        let routes = vec![route.to_string()];
        for rule in &self.rules {
            if self.principal_matches(&rule.src, viewer, Some(peer))
                && self.principals_overlap_routes(&rule.dst, &routes)
                && (rule.ports.is_empty()
                    || rule.ports.iter().any(|p| port_matches(p, PortRef::any())))
            {
                return rule.action == AclAction::Accept;
            }
        }
        self.grants.iter().any(|grant| {
            grant.via.is_empty()
                && self.grant_src_matches(grant, viewer)
                && grant_port_matches(grant, PortRef::any())
                && self.principals_overlap_routes(&grant.dst, &routes)
        })
    }

    fn grant_matches_node_or_route(
        &self,
        grant: &GrantRule,
        src: &NodeView<'_>,
        dst: &NodeView<'_>,
        dst_routes: &[String],
        port: PortRef<'_>,
    ) -> bool {
        if !self.grant_src_matches(grant, src) || !grant_port_matches(grant, port) {
            return false;
        }
        if grant.via.is_empty() {
            return self.principal_matches(&grant.dst, dst, Some(src))
                || self.principals_overlap_routes(&grant.dst, dst_routes);
        }
        let peer_has_via = grant.via.iter().any(|via| {
            via.strip_prefix("tag:")
                .is_some_and(|tag| dst.tags.iter().any(|dst_tag| tag_matches(dst_tag, tag)))
        });
        peer_has_via
            && dst_routes
                .iter()
                .any(|route| self.grant_dsts_overlap_route(grant, route))
    }

    fn grant_src_matches(&self, grant: &GrantRule, src: &NodeView<'_>) -> bool {
        self.principal_matches(&grant.src, src, None)
    }

    fn grant_dsts_overlap_route(&self, grant: &GrantRule, route: &str) -> bool {
        let Some(route) = parse_cidr(route) else {
            return false;
        };
        grant.dst.iter().any(|dst| {
            self.expand_principal(dst).iter().any(|expanded| {
                parse_cidr(expanded).is_some_and(|allowed| nets_overlap(&allowed, &route))
            })
        })
    }

    fn matches(
        &self,
        rule: &AclRule,
        src: &NodeView<'_>,
        dst: &NodeView<'_>,
        port: PortRef<'_>,
    ) -> bool {
        self.principal_matches(&rule.src, src, Some(dst))
            && self.principal_matches(&rule.dst, dst, Some(src))
            && (rule.ports.is_empty() || rule.ports.iter().any(|p| port_matches(p, port)))
    }

    fn matches_node_or_route(
        &self,
        rule: &AclRule,
        src: &NodeView<'_>,
        dst: &NodeView<'_>,
        dst_routes: &[String],
        port: PortRef<'_>,
    ) -> bool {
        self.principal_matches(&rule.src, src, Some(dst))
            && (self.principal_matches(&rule.dst, dst, Some(src))
                || self.principals_overlap_routes(&rule.dst, dst_routes))
            && (rule.ports.is_empty() || rule.ports.iter().any(|p| port_matches(p, port)))
    }

    fn principals_overlap_routes(&self, principals: &[String], routes: &[String]) -> bool {
        routes.iter().any(|route| {
            let Some(route) = parse_cidr(route) else {
                return false;
            };
            principals.iter().any(|principal| {
                self.expand_principal(principal).iter().any(|expanded| {
                    parse_cidr(expanded).is_some_and(|allowed| nets_overlap(&allowed, &route))
                })
            })
        })
    }

    /// Returns the NodeAttr capability flags that apply to `node`.
    /// Stable order, deduped.
    pub fn attrs_for(&self, node: &NodeView<'_>) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if self.randomize_client_port {
            out.push("randomize-client-port".to_string());
        }
        for grant in &self.node_attrs {
            if self.principal_matches(&grant.target, node, None) {
                for a in &grant.attr {
                    if !out.contains(a) {
                        out.push(a.clone());
                    }
                }
            }
        }
        out.sort();
        out
    }

    /// Headscale facade alias for [`Self::attrs_for`].
    pub fn node_attrs_for(&self, node: &NodeView<'_>) -> Vec<String> {
        self.attrs_for(node)
    }

    /// True if the loaded `tagOwners` policy permits `node` to claim
    /// `tag` during client-requested registration tagging.
    pub fn node_can_have_tag(&self, node: &NodeView<'_>, tag: &str) -> bool {
        let Some(owners) = self.tag_owners.get(tag) else {
            return false;
        };
        let mut visiting = BTreeSet::new();
        owners
            .iter()
            .any(|owner| self.tag_owner_matches(node, owner, &mut visiting))
    }

    fn tag_owner_matches(
        &self,
        node: &NodeView<'_>,
        owner: &str,
        visiting: &mut BTreeSet<String>,
    ) -> bool {
        if owner.contains('@') {
            return node.user.is_some_and(|user| user_matches(owner, user));
        }
        if let Some(group) = owner.strip_prefix("group:") {
            let Some(members) = self.groups.get(owner).or_else(|| self.groups.get(group)) else {
                return false;
            };
            return members
                .iter()
                .any(|member| self.tag_owner_matches(node, member, visiting));
        }
        if let Some(tag) = owner.strip_prefix("tag:") {
            let owner_tag = format!("tag:{tag}");
            if !visiting.insert(owner_tag.clone()) {
                return false;
            }
            let result = self.tag_owners.get(&owner_tag).is_some_and(|owners| {
                owners
                    .iter()
                    .any(|owner| self.tag_owner_matches(node, owner, visiting))
            });
            visiting.remove(&owner_tag);
            return result;
        }
        false
    }

    /// True if `node` should have a route covering `prefix`
    /// auto-approved per the `autoApprovers.routes` map.
    pub fn auto_approves_route(&self, node: &NodeView<'_>, prefix: &str) -> bool {
        let Some(advertised) = parse_cidr(prefix) else {
            return false;
        };
        if is_default_route(&advertised) {
            return false;
        }
        for (key, principals) in &self.auto_approvers.routes {
            let Some(approver_net) = parse_cidr(key) else {
                continue;
            };
            if !covers(&approver_net, &advertised) {
                continue;
            }
            if self.principal_matches(principals, node, None) {
                return true;
            }
        }
        false
    }

    /// True if `node` should be auto-approved as an exit-node per
    /// `autoApprovers.exit_node`.
    pub fn auto_approves_exit_node(&self, node: &NodeView<'_>) -> bool {
        if self.auto_approvers.exit_node.is_empty() {
            return false;
        }
        self.principal_matches(&self.auto_approvers.exit_node, node, None)
    }

    /// Expand a principal token into a context-free list of literal
    /// strings. This helper is used by route-overlap and legacy
    /// callers; packet-filter compilation has source/destination
    /// specific wildcard handling.
    pub fn expand_principal(&self, token: &str) -> Vec<String> {
        if token == "*" {
            return wildcard_filter_cidrs();
        }
        if token.starts_with("group:") {
            let mut visiting = BTreeSet::new();
            return self.expand_group_members(token, &mut visiting);
        }
        if let Some(h) = token.strip_prefix("host:") {
            if let Some(cidr) = self.hosts.get(h) {
                return vec![cidr.clone()];
            }
            return Vec::new();
        }
        if let Some(ag) = token.strip_prefix("autogroup:") {
            if ag == "internet" {
                return internet_filter_cidrs();
            }
            if ag == "member" {
                return wildcard_filter_cidrs();
            }
            return Vec::new();
        }
        if let Some(cidr) = self.hosts.get(token) {
            return vec![cidr.clone()];
        }
        vec![token.to_string()]
    }

    fn expand_group_members(&self, group: &str, visiting: &mut BTreeSet<String>) -> Vec<String> {
        let group_ref = canonical_group_ref(group);
        if !visiting.insert(group_ref.clone()) {
            return Vec::new();
        }

        let Some(members) = group_members(self, group) else {
            visiting.remove(&group_ref);
            return Vec::new();
        };

        let mut out = Vec::new();
        for member in members {
            if member.starts_with("group:") {
                for expanded in self.expand_group_members(member, visiting) {
                    out.push(expanded);
                }
            } else {
                out.push(member.clone());
            }
        }

        visiting.remove(&group_ref);
        out
    }

    fn principal_matches(
        &self,
        set: &[String],
        principal: &NodeView<'_>,
        peer: Option<&NodeView<'_>>,
    ) -> bool {
        for entry in set {
            if self.principal_matches_one(entry, principal, peer) {
                return true;
            }
        }
        false
    }

    fn principal_matches_one(
        &self,
        entry: &str,
        principal: &NodeView<'_>,
        peer: Option<&NodeView<'_>>,
    ) -> bool {
        if entry == "*" {
            return true;
        }
        if entry.starts_with("group:") {
            let mut visiting = BTreeSet::new();
            return self.group_principal_matches(entry, principal, &mut visiting);
        }
        if let Some(tag) = entry.strip_prefix("tag:") {
            return principal.tags.iter().any(|t| tag_matches(t, tag));
        }
        if let Some(ag) = entry.strip_prefix("autogroup:") {
            return autogroup_matches(ag, principal, peer);
        }
        if let Some(host) = entry.strip_prefix("host:") {
            if let Some(cidr) = self.hosts.get(host) {
                return addr_in_cidr(principal.addr, cidr);
            }
            return false;
        }
        if let Some(cidr) = self.hosts.get(entry) {
            return addr_in_cidr(principal.addr, cidr);
        }
        if entry.contains('/') {
            return addr_in_cidr(principal.addr, entry);
        }
        identity_matches(entry, principal)
    }

    fn group_principal_matches(
        &self,
        group: &str,
        principal: &NodeView<'_>,
        visiting: &mut BTreeSet<String>,
    ) -> bool {
        let group_ref = canonical_group_ref(group);
        if !visiting.insert(group_ref.clone()) {
            return false;
        }

        let Some(members) = group_members(self, group) else {
            visiting.remove(&group_ref);
            return false;
        };

        let mut matched = false;
        for member in members {
            if member.starts_with("group:") {
                if self.group_principal_matches(member, principal, visiting) {
                    matched = true;
                    break;
                }
            } else if identity_matches(member, principal) {
                matched = true;
                break;
            }
        }

        visiting.remove(&group_ref);
        matched
    }
}

/// Route effects from `grants[*].via` for one viewer/peer pair.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ViaRouteGrantResult {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub use_primary: Vec<String>,
}

/// Candidate route advertiser used for upstream `grants[*].via`
/// primary election.
#[derive(Clone, Copy, Debug)]
pub struct ViaRouteCandidate<'a> {
    pub id: u64,
    pub tags: &'a [String],
    pub routes: &'a [String],
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

pub fn wildcard_filter_cidrs() -> Vec<String> {
    vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
}

pub fn tailnet_filter_srcs() -> Vec<String> {
    vec![
        "100.115.94.0-100.127.255.255".to_string(),
        "100.64.0.0-100.115.91.255".to_string(),
        "fd7a:115c:a1e0::/48".to_string(),
    ]
}

pub fn internet_filter_cidrs() -> Vec<String> {
    vec![
        "0.0.0.0/5".to_string(),
        "8.0.0.0/7".to_string(),
        "11.0.0.0/8".to_string(),
        "12.0.0.0/6".to_string(),
        "16.0.0.0/4".to_string(),
        "32.0.0.0/3".to_string(),
        "64.0.0.0/3".to_string(),
        "96.0.0.0/6".to_string(),
        "100.0.0.0/10".to_string(),
        "100.128.0.0/9".to_string(),
        "101.0.0.0/8".to_string(),
        "102.0.0.0/7".to_string(),
        "104.0.0.0/5".to_string(),
        "112.0.0.0/4".to_string(),
        "128.0.0.0/3".to_string(),
        "160.0.0.0/5".to_string(),
        "168.0.0.0/8".to_string(),
        "169.0.0.0/9".to_string(),
        "169.128.0.0/10".to_string(),
        "169.192.0.0/11".to_string(),
        "169.224.0.0/12".to_string(),
        "169.240.0.0/13".to_string(),
        "169.248.0.0/14".to_string(),
        "169.252.0.0/15".to_string(),
        "169.255.0.0/16".to_string(),
        "170.0.0.0/7".to_string(),
        "172.0.0.0/12".to_string(),
        "172.32.0.0/11".to_string(),
        "172.64.0.0/10".to_string(),
        "172.128.0.0/9".to_string(),
        "173.0.0.0/8".to_string(),
        "174.0.0.0/7".to_string(),
        "176.0.0.0/4".to_string(),
        "192.0.0.0/9".to_string(),
        "192.128.0.0/11".to_string(),
        "192.160.0.0/13".to_string(),
        "192.169.0.0/16".to_string(),
        "192.170.0.0/15".to_string(),
        "192.172.0.0/14".to_string(),
        "192.176.0.0/12".to_string(),
        "192.192.0.0/10".to_string(),
        "193.0.0.0/8".to_string(),
        "194.0.0.0/7".to_string(),
        "196.0.0.0/6".to_string(),
        "200.0.0.0/5".to_string(),
        "208.0.0.0/4".to_string(),
        "224.0.0.0/3".to_string(),
        "2000::/3".to_string(),
    ]
}

fn identity_matches(entry: &str, principal: &NodeView<'_>) -> bool {
    if let Some(addr) = principal.addr
        && entry == addr
    {
        return true;
    }
    if principal.tags.is_empty()
        && let Some(user) = principal.user
        && user_matches(entry, user)
    {
        return true;
    }
    false
}

fn user_matches(entry: &str, user: &str) -> bool {
    entry == user || entry.strip_suffix('@') == Some(user) || user.strip_suffix('@') == Some(entry)
}

fn tag_matches(node_tag: &str, policy_tag_without_prefix: &str) -> bool {
    node_tag == policy_tag_without_prefix
        || node_tag.strip_prefix("tag:") == Some(policy_tag_without_prefix)
}

fn autogroup_matches(kind: &str, principal: &NodeView<'_>, peer: Option<&NodeView<'_>>) -> bool {
    if kind == "internet" {
        return true;
    }
    if kind == "member" {
        return principal.tags.is_empty();
    }
    if kind == "nonroot" {
        return principal.tags.is_empty();
    }
    if kind == "tagged" {
        return !principal.tags.is_empty();
    }
    if let Some(tag) = kind.strip_prefix("tag:") {
        return principal.tags.iter().any(|t| tag_matches(t, tag));
    }
    if kind == "self" {
        let Some(peer) = peer else {
            return false;
        };
        if let (Some(a), Some(b)) = (principal.addr, peer.addr)
            && a == b
        {
            return true;
        }
        if let (Some(a), Some(b)) = (principal.user, peer.user) {
            return principal.tags.is_empty() && peer.tags.is_empty() && a == b;
        }
        return false;
    }
    false
}

fn is_default_route(net: &IpNet) -> bool {
    match net {
        IpNet::V4(v4) => v4.prefix_len() == 0,
        IpNet::V6(v6) => v6.prefix_len() == 0,
    }
}

/// Parse a CIDR or bare-address string into an `IpNet`. A bare
/// address is treated as a /32 (v4) or /128 (v6).
pub fn parse_cidr(s: &str) -> Option<IpNet> {
    if let Ok(n) = s.parse::<IpNet>() {
        return Some(n);
    }
    if let Ok(addr) = s.parse::<IpAddr>() {
        return IpNet::new(addr, if addr.is_ipv4() { 32 } else { 128 }).ok();
    }
    None
}

fn cgnat_range() -> IpNet {
    "100.64.0.0/10".parse().expect("static CGNAT range")
}

fn covers(outer: &IpNet, inner: &IpNet) -> bool {
    match (outer, inner) {
        (IpNet::V4(o), IpNet::V4(i)) => {
            if o.prefix_len() > i.prefix_len() {
                return false;
            }
            o.contains(&i.network())
        }
        (IpNet::V6(o), IpNet::V6(i)) => {
            if o.prefix_len() > i.prefix_len() {
                return false;
            }
            o.contains(&i.network())
        }
        _ => false,
    }
}

fn nets_overlap(a: &IpNet, b: &IpNet) -> bool {
    covers(a, b) || covers(b, a)
}

fn addr_in_cidr(addr: Option<&str>, cidr: &str) -> bool {
    let Some(addr) = addr else {
        return false;
    };
    let Some(net) = parse_cidr(cidr) else {
        return false;
    };
    let Ok(parsed) = addr.parse::<IpAddr>() else {
        return false;
    };
    net.contains(&parsed)
}

fn split_upstream_dst_ports(dst: &str) -> Result<Option<(&str, &str)>, String> {
    let Some((alias, port_spec)) = dst.rsplit_once(':') else {
        return Ok(None);
    };
    if alias.is_empty() || alias.ends_with(':') || is_namespaced_alias_without_port(dst) {
        return Ok(None);
    }
    validate_upstream_port_spec(port_spec)?;
    Ok(Some((alias, port_spec)))
}

fn normalize_port_spec(proto: &str, spec: &str) -> Vec<String> {
    if spec.contains('/') || spec.starts_with("*:") {
        return vec![spec.to_string()];
    }
    let mut out = Vec::new();
    for part in spec.split(',').map(str::trim) {
        if validate_upstream_port_spec(part).is_err() {
            continue;
        }
        if proto.is_empty() {
            out.push(format!("*/{part}"));
        } else {
            out.push(format!("{proto}/{part}"));
        }
    }
    out
}

fn normalize_grant_ip_spec(spec: &str) -> Result<Vec<String>, String> {
    let trimmed = spec.trim();
    if trimmed == "*" {
        return Ok(vec!["*/*".to_string()]);
    }
    let (proto, ports) = if let Some((proto, ports)) = trimmed.split_once(':') {
        if ports.contains(':') {
            return Err("expected only one colon in Internet protocol and port type".to_string());
        }
        let proto = proto.trim().to_ascii_lowercase();
        validate_upstream_proto(&proto)?;
        (proto, ports.trim())
    } else {
        ("*".to_string(), trimmed)
    };
    validate_proto_port_compat(&proto, ports)?;
    Ok(normalize_port_spec(&proto, ports))
}

fn validate_upstream_proto(proto: &str) -> Result<(), String> {
    match proto {
        "" | "icmp" | "igmp" | "ipv4" | "ip-in-ip" | "tcp" | "egp" | "igp" | "udp" | "gre"
        | "esp" | "ah" | "sctp" => Ok(()),
        "*" => Err(
            "proto name \"*\" not known; use protocol number 0-255 or protocol name (icmp, tcp, udp, etc.)"
                .to_string(),
        ),
        other => {
            if other == "0" || (other.len() > 1 && other.starts_with('0')) {
                return Err(format!(
                    "leading 0 not permitted in protocol number \"{other}\""
                ));
            }
            match other.parse::<u16>() {
                Ok(1..=255) => Ok(()),
                Ok(n) => Err(format!("protocol number {n} out of range (0-255)")),
                Err(_) => Err(format!(
                    "invalid protocol {other:?}: must be a known protocol name or valid protocol number 0-255"
                )),
            }
        }
    }
}

fn validate_capability_name(name: &str) -> Result<(), String> {
    if name.contains("://") || !name.contains('/') {
        return Err("capability name must have the form {domain}/{path}".to_string());
    }
    if name.starts_with("tailscale.com/") && !tailscale_cap_allowlisted(name) {
        return Err("capability name must not be in the tailscale.com domain".to_string());
    }
    Ok(())
}

fn tailscale_cap_allowlisted(name: &str) -> bool {
    matches!(
        name,
        "tailscale.com/cap/drive"
            | "tailscale.com/cap/relay"
            | "tailscale.com/cap/webui"
            | "tailscale.com/cap/kubernetes"
            | "tailscale.com/cap/tsidp"
    )
}

fn validate_proto_port_compat(proto: &str, spec: &str) -> Result<(), String> {
    if matches!(proto, "" | "*" | "tcp" | "udp" | "sctp") || spec.contains('/') {
        return Ok(());
    }
    let has_specific_port = spec.split(',').map(str::trim).any(|part| part != "*");
    if has_specific_port {
        return Err(format!(
            "protocol {proto:?} does not support specific ports; only \"*\" is allowed"
        ));
    }
    Ok(())
}

fn is_namespaced_alias_without_port(dst: &str) -> bool {
    ["tag:", "group:", "autogroup:", "host:"]
        .iter()
        .any(|prefix| dst.starts_with(prefix) && !dst[prefix.len()..].contains(':'))
}

fn validate_upstream_port_spec(spec: &str) -> Result<(), String> {
    if spec == "*" {
        return Ok(());
    }
    for part in spec.split(',').map(str::trim) {
        if part.contains('-') {
            let range_parts: Vec<&str> = part.split('-').filter(|part| !part.is_empty()).collect();
            if range_parts.len() != 2 {
                return Err("invalid port range format".to_string());
            }
            let first = parse_upstream_port(range_parts[0])?;
            let last = parse_upstream_port(range_parts[1])?;
            if first > last {
                return Err("invalid port range: first port is greater than last port".to_string());
            }
        } else {
            let port = parse_upstream_port(part)?;
            if port < 1 {
                return Err("first port must be >0, or use '*' for wildcard".to_string());
            }
        }
    }
    Ok(())
}

fn parse_upstream_port(port: &str) -> Result<u16, String> {
    let parsed: i64 = port
        .parse()
        .map_err(|_| "invalid port number".to_string())?;
    if !(0..=65_535).contains(&parsed) {
        return Err("port number out of range".to_string());
    }
    Ok(parsed as u16)
}

fn port_matches(pattern: &str, port: PortRef<'_>) -> bool {
    let pat = pattern.strip_prefix("*:").unwrap_or(pattern);
    let (proto_part, port_part) = pat.split_once('/').unwrap_or((pat, "*"));
    let proto_ok = proto_part == "*" || port.proto.is_none_or(|p| proto_matches(proto_part, p));
    let port_ok = port_part == "*" || port.port.is_none_or(|p| port_part_matches(port_part, p));
    proto_ok && port_ok
}

fn grant_port_matches(grant: &GrantRule, port: PortRef<'_>) -> bool {
    grant.ip.is_empty()
        || grant.ip.iter().any(|spec| {
            normalize_grant_ip_spec(spec).is_ok_and(|patterns| {
                patterns
                    .iter()
                    .any(|pattern| port_matches(pattern.as_str(), port))
            })
        })
}

fn proto_matches(pattern: &str, actual: &str) -> bool {
    if pattern.eq_ignore_ascii_case(actual) {
        return true;
    }
    let Some(pattern_nums) = proto_numbers(pattern) else {
        return false;
    };
    let Some(actual_nums) = proto_numbers(actual) else {
        return false;
    };
    pattern_nums.iter().any(|p| actual_nums.contains(p))
}

fn proto_numbers(proto: &str) -> Option<Vec<u16>> {
    let lower = proto.to_ascii_lowercase();
    let nums: &[u16] = match lower.as_str() {
        "icmp" => &[1],
        "igmp" => &[2],
        "ipv4" | "ip-in-ip" => &[4],
        "tcp" => &[6],
        "egp" => &[8],
        "igp" => &[9],
        "udp" => &[17],
        "gre" => &[47],
        "esp" => &[50],
        "ah" => &[51],
        "ipv6-icmp" => &[58],
        "sctp" => &[132],
        "fc" => &[133],
        _ => {
            let n: u16 = lower.parse().ok()?;
            if !(1..=255).contains(&n) {
                return None;
            }
            return Some(vec![n]);
        }
    };
    Some(nums.to_vec())
}

fn port_part_matches(port_part: &str, port: u16) -> bool {
    if let Some((lo, hi)) = port_part.split_once('-') {
        let (Ok(lo), Ok(hi)) = (lo.parse::<u16>(), hi.parse::<u16>()) else {
            return false;
        };
        return lo <= port && port <= hi;
    }
    port_part.parse::<u16>().is_ok_and(|want| port == want)
}

// =====================================================================
// Tests — ported from `octravpn-mesh::acl` (51 cases) plus the unit
// blocks from `headscale-api::policy::{doc,filter,hujson}`.
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Parse + canonical bytes -----------------------------------

    #[test]
    fn parses_minimal_doc() {
        let src = r#"
            version = 1
            [[rules]]
            action = "accept"
            src = ["*"]
            dst = ["*"]
        "#;
        let doc = AclDoc::from_toml(src).unwrap();
        assert_eq!(doc.version, 1);
        assert_eq!(doc.rules.len(), 1);
    }

    #[test]
    fn canonical_form_is_stable_across_key_order() {
        let a = AclDoc::from_toml(
            r#"
            version = 1
            [groups]
            admins = ["oct2", "oct1"]
            eng    = ["oct3"]
            [[rules]]
            action = "accept"
            src = ["group:admins"]
            dst = ["*"]
        "#,
        )
        .unwrap();
        let b = AclDoc::from_toml(
            r#"
            version = 1
            [groups]
            eng    = ["oct3"]
            admins = ["oct1", "oct2"]
            [[rules]]
            action = "accept"
            dst = ["*"]
            src = ["group:admins"]
        "#,
        )
        .unwrap();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        assert_eq!(a.policy_hash(), b.policy_hash());
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let src = r#"
            version = 1
            policy_owner = "octATTACKER"
            [[rules]]
            action = "accept"
            src = ["*"]
            dst = ["*"]
        "#;
        let err = AclDoc::from_toml(src).expect_err("unknown top-level key must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("policy_owner") || msg.contains("unknown field"),
            "error should name the offending field, got: {msg}"
        );
    }

    #[test]
    fn rejects_unknown_rule_field() {
        let src = r#"
            version = 1
            [[rules]]
            action = "accept"
            src = ["*"]
            dst = ["*"]
            permit_all = true
        "#;
        let err = AclDoc::from_toml(src).expect_err("unknown rule key must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("permit_all") || msg.contains("unknown field"),
            "error should name the offending field, got: {msg}"
        );
    }

    #[test]
    fn rejects_misspelled_action_field() {
        let src = r#"
            version = 1
            [[rules]]
            actoin = "accept"
            src = ["*"]
            dst = ["*"]
        "#;
        let err = AclDoc::from_toml(src).expect_err("typo'd action must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("actoin") || msg.contains("action") || msg.contains("unknown field"),
            "error should reference the typo or missing field, got: {msg}"
        );
    }

    #[test]
    fn hujson_accepts_headscale_go_policy_without_version() {
        let raw =
            r#"{"acls":[{"action":"accept","src":["100.64.0.1/32"],"dst":["100.64.0.2/32:22"]}]}"#;
        let doc = parse_hujson_policy(raw).unwrap();
        assert_eq!(doc.version, 1);
        assert_eq!(doc.rules.len(), 1);
        assert_eq!(doc.rules[0].dst, vec!["100.64.0.2/32"]);
        assert_eq!(doc.rules[0].ports, vec!["*/22"]);
    }

    #[test]
    fn hujson_accepts_headscale_go_dst_ports_for_tag_and_proto() {
        let raw = r#"{
            "tagOwners": {
                "tag:client": ["alice@"],
                "tag:server": ["alice@"]
            },
            "acls": [
                {"action":"accept","proto":"tcp","src":["tag:client"],"dst":["tag:server:80,443"]}
            ]
        }"#;
        let doc = parse_hujson_policy(raw).unwrap();
        assert_eq!(doc.rules[0].dst, vec!["tag:server"]);
        assert_eq!(doc.rules[0].ports, vec!["tcp/80", "tcp/443"]);
    }

    #[test]
    fn hujson_accepts_headscale_go_dst_ports_for_bare_host_alias() {
        let raw = r#"{
            "hosts": {"server": "100.64.0.2/32"},
            "acls": [
                {"action":"accept","proto":"tcp","src":["100.64.0.1/32"],"dst":["server:22"]}
            ]
        }"#;
        let doc = parse_hujson_policy(raw).unwrap();
        assert_eq!(doc.rules[0].dst, vec!["server"]);
        assert_eq!(doc.rules[0].ports, vec!["tcp/22"]);
    }

    #[test]
    fn hujson_accepts_upstream_policy_tests_and_ssh_tests() {
        let raw = r#"{
            "tagOwners": {"tag:server": ["alice@"]},
            "acls": [
                {"action":"accept","proto":"tcp","src":["alice@"],"dst":["tag:server:22"]}
            ],
            "tests": [
                {"src":"alice@","proto":"tcp","accept":["tag:server:22"],"deny":["tag:server:80"]}
            ],
            "ssh": [
                {"action":"accept","src":["alice@"],"dst":["autogroup:self"],"users":["root"]}
            ],
            "sshTests": [
                {"src":"alice@","dst":["autogroup:self"],"accept":["root"],"deny":["ubuntu"],"check":["admin"]}
            ]
        }"#;
        let doc = parse_hujson_policy(raw).unwrap();
        assert_eq!(doc.tests.len(), 1);
        assert_eq!(doc.tests[0].src, "alice@");
        assert_eq!(doc.tests[0].accept, vec!["tag:server:22"]);
        assert_eq!(doc.ssh_tests.len(), 1);
        assert_eq!(doc.ssh_tests[0].dst, vec!["autogroup:self"]);
        assert_eq!(doc.ssh_tests[0].check, vec!["admin"]);
    }

    #[test]
    fn hujson_rejects_malformed_policy_tests() {
        let raw = r#"{
            "tests": [
                {"src":"alice@","proto":"icmp","accept":["100.64.0.2:22"]},
                {"src":"alice@","accept":["100.64.0.0/24:22"]},
                {"src":"alice@","deny":["100.64.0.2:22,80"]},
                {"src":"alice@"}
            ]
        }"#;
        let err = parse_hujson_policy(raw).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("protocol"));
        assert!(msg.contains("CIDR"));
        assert!(msg.contains("exactly one port"));
        assert!(msg.contains("accept or deny"));
    }

    #[test]
    fn hujson_rejects_malformed_ssh_tests() {
        let raw = r#"{
            "tagOwners": {"tag:server": ["alice@"]},
            "sshTests": [
                {"src":"","dst":["tag:missing"]},
                {"src":"alice@","dst":["100.64.0.0/24"]},
                {"src":"alice@","dst":["tag:server:22"]},
                {"src":"alice@","dst":[]}
            ]
        }"#;
        let err = parse_hujson_policy(raw).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("non-empty src"));
        assert!(msg.contains("unknown tag"));
        assert!(msg.contains("disallowed element"));
        assert!(msg.contains("at least one dst"));
    }

    #[test]
    fn hujson_rejects_acl_destinations_without_ports_like_headscale_go() {
        for (dst, expected) in [
            ("*", "hostport must contain a colon"),
            ("tag:server", "invalid port number"),
            ("autogroup:internet", "invalid port number"),
        ] {
            let raw = format!(
                r#"{{
                    "tagOwners": {{"tag:server": ["alice@"]}},
                    "acls": [
                        {{"action":"accept","src":["*"],"dst":["{dst}"]}}
                    ]
                }}"#
            );
            let err = parse_hujson_policy(&raw).unwrap_err();
            assert!(
                format!("{err}").contains(expected),
                "{dst} should contain {expected:?}, got {err}"
            );
        }
    }

    #[test]
    fn hujson_rejects_bare_ipv6_acl_destination_like_headscale_go() {
        let raw = r#"{
            "acls": [
                {"action":"accept","src":["*"],"dst":["fd7a:115c:a1e0::1"]}
            ]
        }"#;
        let err = parse_hujson_policy(raw).unwrap_err();
        assert!(format!("{err}").contains("Invalid alias"));
    }

    #[test]
    fn hujson_ignores_acl_metadata_fields_starting_with_hash() {
        let raw = r##"{
            "acls": [
                {
                    "#comment": "admin UI metadata",
                    "#ui": {"row": 1},
                    "action": "accept",
                    "src": ["100.64.0.1/32"],
                    "dst": ["100.64.0.2/32:22"]
                }
            ]
        }"##;
        let doc = parse_hujson_policy(raw).unwrap();
        assert_eq!(doc.rules.len(), 1);
        assert_eq!(doc.rules[0].ports, vec!["*/22"]);
    }

    #[test]
    fn hujson_rejects_headscale_go_proto_wildcard() {
        let raw = r#"{
            "acls": [
                {"action":"accept","proto":"*","src":["*"],"dst":["*:22"]}
            ]
        }"#;
        let err = parse_hujson_policy(raw).unwrap_err();
        assert!(format!("{err}").contains("proto name"));
    }

    #[test]
    fn hujson_rejects_headscale_go_icmp_specific_port() {
        let raw = r#"{
            "acls": [
                {"action":"accept","proto":"icmp","src":["*"],"dst":["*:22"]}
            ]
        }"#;
        let err = parse_hujson_policy(raw).unwrap_err();
        assert!(format!("{err}").contains("does not support specific ports"));
    }

    #[test]
    fn hujson_rejects_headscale_go_invalid_dst_ports() {
        for (dst, expected) in [
            ("*:0", "first port must be >0"),
            ("*:65536", "port number out of range"),
            (
                "*:22-10",
                "invalid port range: first port is greater than last port",
            ),
            ("*:abc", "invalid port number"),
        ] {
            let raw = format!(
                r#"{{
                    "acls": [
                        {{"action":"accept","src":["*"],"dst":["{dst}"]}}
                    ]
                }}"#
            );
            let err = parse_hujson_policy(&raw).unwrap_err();
            assert!(
                format!("{err}").contains(expected),
                "{dst} should contain {expected:?}, got {err}"
            );
        }
    }

    // --- Evaluate --------------------------------------------------

    #[test]
    fn default_deny_when_no_rule_matches() {
        let doc = AclDoc {
            version: 1,
            rules: vec![AclRule {
                action: AclAction::Accept,
                src: vec!["oct1".into()],
                dst: vec!["oct2".into()],
                ports: vec![],
            }],
            ..Default::default()
        };
        assert_eq!(doc.decide("octX", "octY", PortRef::any()), AclAction::Deny);
    }

    #[test]
    fn group_expansion_matches_member() {
        let doc = AclDoc {
            version: 1,
            groups: std::iter::once(("admins".to_string(), vec!["octA".into(), "octB".into()]))
                .collect(),
            rules: vec![AclRule {
                action: AclAction::Accept,
                src: vec!["group:admins".into()],
                dst: vec!["*".into()],
                ports: vec![],
            }],
            ..Default::default()
        };
        assert_eq!(
            doc.decide("octA", "anything", PortRef::any()),
            AclAction::Accept
        );
        assert_eq!(
            doc.decide("octC", "anything", PortRef::any()),
            AclAction::Deny
        );
    }

    #[test]
    fn first_match_wins_even_if_later_would_accept() {
        let doc = AclDoc {
            version: 1,
            rules: vec![
                AclRule {
                    action: AclAction::Deny,
                    src: vec!["octA".into()],
                    dst: vec!["octB".into()],
                    ports: vec![],
                },
                AclRule {
                    action: AclAction::Accept,
                    src: vec!["*".into()],
                    dst: vec!["*".into()],
                    ports: vec![],
                },
            ],
            ..Default::default()
        };
        assert_eq!(doc.decide("octA", "octB", PortRef::any()), AclAction::Deny);
        assert_eq!(
            doc.decide("octZ", "octB", PortRef::any()),
            AclAction::Accept
        );
    }

    #[test]
    fn port_pattern_tcp_22_matches() {
        let doc = AclDoc {
            version: 1,
            rules: vec![AclRule {
                action: AclAction::Accept,
                src: vec!["*".into()],
                dst: vec!["*".into()],
                ports: vec!["tcp/22".into()],
            }],
            ..Default::default()
        };
        assert_eq!(
            doc.decide("a", "b", PortRef::new("tcp", 22)),
            AclAction::Accept
        );
        assert_eq!(
            doc.decide("a", "b", PortRef::new("tcp", 80)),
            AclAction::Deny
        );
        assert_eq!(
            doc.decide("a", "b", PortRef::new("udp", 22)),
            AclAction::Deny
        );
    }

    #[test]
    fn port_range_matches_inside_bounds() {
        let doc = AclDoc {
            version: 1,
            rules: vec![AclRule {
                action: AclAction::Accept,
                src: vec!["*".into()],
                dst: vec!["*".into()],
                ports: vec!["tcp/8000-9000".into()],
            }],
            ..Default::default()
        };
        assert_eq!(
            doc.decide("a", "b", PortRef::new("tcp", 8443)),
            AclAction::Accept
        );
        assert_eq!(
            doc.decide("a", "b", PortRef::new("tcp", 9443)),
            AclAction::Deny
        );
    }

    #[test]
    fn numeric_proto_matches_named_port_ref() {
        let doc = AclDoc {
            version: 1,
            rules: vec![AclRule {
                action: AclAction::Accept,
                src: vec!["*".into()],
                dst: vec!["*".into()],
                ports: vec!["6/443".into()],
            }],
            ..Default::default()
        };
        assert_eq!(
            doc.decide("a", "b", PortRef::new("tcp", 443)),
            AclAction::Accept
        );
        assert_eq!(
            doc.decide("a", "b", PortRef::new("udp", 443)),
            AclAction::Deny
        );
    }

    #[test]
    fn legacy_port_pattern_star_colon_tcp_22() {
        let doc = AclDoc {
            version: 1,
            rules: vec![AclRule {
                action: AclAction::Accept,
                src: vec!["*".into()],
                dst: vec!["*".into()],
                ports: vec!["*:tcp/22".into()],
            }],
            ..Default::default()
        };
        assert_eq!(
            doc.decide("a", "b", PortRef::new("tcp", 22)),
            AclAction::Accept
        );
    }

    // --- Autogroup expansion ---------------------------------------

    fn doc_with_rule(src: &[&str], dst: &[&str]) -> AclDoc {
        AclDoc {
            version: 1,
            rules: vec![AclRule {
                action: AclAction::Accept,
                src: src.iter().map(|s| (*s).to_string()).collect(),
                dst: dst.iter().map(|s| (*s).to_string()).collect(),
                ports: vec![],
            }],
            ..Default::default()
        }
    }

    #[test]
    fn autogroup_internet_matches_anything() {
        let doc = doc_with_rule(&["*"], &["autogroup:internet"]);
        let s = NodeView::new("100.64.0.1");
        let d = NodeView::new("8.8.8.8");
        assert_eq!(doc.evaluate_with(&s, &d, PortRef::any()), AclAction::Accept);
    }

    #[test]
    fn autogroup_member_matches_untagged_nodes() {
        let doc = doc_with_rule(&["autogroup:member"], &["*"]);
        let s = NodeView::new("100.64.0.1");
        let d = NodeView::new("100.64.0.2");
        let tags = vec!["tag:router".to_string()];
        let tagged = NodeView::new("100.64.0.3").with_tags(&tags);
        assert_eq!(doc.evaluate_with(&s, &d, PortRef::any()), AclAction::Accept);
        assert_eq!(
            doc.evaluate_with(&tagged, &d, PortRef::any()),
            AclAction::Deny
        );
    }

    #[test]
    fn autogroup_nonroot_only_matches_untagged() {
        let doc = doc_with_rule(&["autogroup:nonroot"], &["*"]);
        let tagged: Vec<String> = vec!["router".into()];
        let untagged = NodeView::new("100.64.0.1");
        let tagged_view = NodeView::new("100.64.0.2").with_tags(&tagged);
        let dst = NodeView::new("100.64.0.5");
        assert_eq!(
            doc.evaluate_with(&untagged, &dst, PortRef::any()),
            AclAction::Accept
        );
        assert_eq!(
            doc.evaluate_with(&tagged_view, &dst, PortRef::any()),
            AclAction::Deny
        );
    }

    #[test]
    fn autogroup_tagged_only_matches_tagged() {
        let doc = doc_with_rule(&["autogroup:tagged"], &["*"]);
        let tags: Vec<String> = vec!["exit".into()];
        let tagged_view = NodeView::new("100.64.0.1").with_tags(&tags);
        let untagged = NodeView::new("100.64.0.2");
        let dst = NodeView::new("100.64.0.5");
        assert_eq!(
            doc.evaluate_with(&tagged_view, &dst, PortRef::any()),
            AclAction::Accept
        );
        assert_eq!(
            doc.evaluate_with(&untagged, &dst, PortRef::any()),
            AclAction::Deny
        );
    }

    #[test]
    fn autogroup_tag_specific_matches_only_that_tag() {
        let doc = doc_with_rule(&["autogroup:tag:router"], &["*"]);
        let router_tags = vec!["router".into()];
        let exit_tags = vec!["exit".into()];
        let router = NodeView::new("100.64.0.1").with_tags(&router_tags);
        let exit = NodeView::new("100.64.0.2").with_tags(&exit_tags);
        let dst = NodeView::new("100.64.0.5");
        assert_eq!(
            doc.evaluate_with(&router, &dst, PortRef::any()),
            AclAction::Accept
        );
        assert_eq!(
            doc.evaluate_with(&exit, &dst, PortRef::any()),
            AclAction::Deny
        );
    }

    #[test]
    fn autogroup_self_matches_same_addr() {
        let doc = doc_with_rule(&["autogroup:member"], &["autogroup:self"]);
        let alice = NodeView::new("100.64.0.1");
        let bob = NodeView::new("100.64.0.2");
        assert_eq!(
            doc.evaluate_with(&alice, &alice.clone(), PortRef::any()),
            AclAction::Accept,
        );
        assert_eq!(
            doc.evaluate_with(&alice, &bob, PortRef::any()),
            AclAction::Deny,
        );
    }

    #[test]
    fn autogroup_self_matches_same_user_when_addr_unknown() {
        let doc = doc_with_rule(&["autogroup:member"], &["autogroup:self"]);
        let user = "alice".to_string();
        let s = NodeView {
            addr: None,
            user: Some(&user),
            tags: &[],
        };
        let d = NodeView {
            addr: None,
            user: Some(&user),
            tags: &[],
        };
        let s2 = NodeView {
            addr: None,
            user: Some("bob"),
            tags: &[],
        };
        assert_eq!(doc.evaluate_with(&s, &d, PortRef::any()), AclAction::Accept);
        assert_eq!(doc.evaluate_with(&s, &s2, PortRef::any()), AclAction::Deny);
    }

    #[test]
    fn autogroup_self_matches_same_user_with_different_addrs() {
        let doc = doc_with_rule(&["autogroup:member"], &["autogroup:self"]);
        let user = "alice".to_string();
        let s = NodeView::new("100.64.0.1").with_user(&user);
        let d = NodeView::new("100.64.0.2").with_user(&user);
        let bob = NodeView::new("100.64.0.3").with_user("bob");
        assert_eq!(doc.evaluate_with(&s, &d, PortRef::any()), AclAction::Accept);
        assert_eq!(doc.evaluate_with(&s, &bob, PortRef::any()), AclAction::Deny);
    }

    #[test]
    fn bare_tag_prefix_matches_tagged_principal() {
        let doc = doc_with_rule(&["tag:router"], &["*"]);
        let tags: Vec<String> = vec!["router".into()];
        let router = NodeView::new("100.64.0.1").with_tags(&tags);
        let plain = NodeView::new("100.64.0.2");
        let dst = NodeView::new("100.64.0.5");
        assert_eq!(
            doc.evaluate_with(&router, &dst, PortRef::any()),
            AclAction::Accept
        );
        assert_eq!(
            doc.evaluate_with(&plain, &dst, PortRef::any()),
            AclAction::Deny
        );
    }

    // --- Hosts -----------------------------------------------------

    #[test]
    fn host_alias_matches_address_inside_cidr() {
        let mut doc = doc_with_rule(&["*"], &["host:office"]);
        doc.hosts.insert("office".into(), "10.0.0.0/8".into());
        let s = NodeView::new("100.64.0.1");
        let inside = NodeView::new("10.5.5.5");
        let outside = NodeView::new("8.8.8.8");
        assert_eq!(
            doc.evaluate_with(&s, &inside, PortRef::any()),
            AclAction::Accept
        );
        assert_eq!(
            doc.evaluate_with(&s, &outside, PortRef::any()),
            AclAction::Deny
        );
    }

    #[test]
    fn bare_host_alias_matches_address_inside_cidr() {
        let mut doc = doc_with_rule(&["*"], &["office"]);
        doc.hosts.insert("office".into(), "10.0.0.0/8".into());
        let s = NodeView::new("100.64.0.1");
        let inside = NodeView::new("10.5.5.5");
        let outside = NodeView::new("8.8.8.8");
        assert_eq!(
            doc.evaluate_with(&s, &inside, PortRef::any()),
            AclAction::Accept
        );
        assert_eq!(
            doc.evaluate_with(&s, &outside, PortRef::any()),
            AclAction::Deny
        );
    }

    #[test]
    fn unknown_host_alias_is_deny() {
        let doc = doc_with_rule(&["*"], &["host:noexist"]);
        let s = NodeView::new("100.64.0.1");
        let d = NodeView::new("10.0.0.5");
        assert_eq!(doc.evaluate_with(&s, &d, PortRef::any()), AclAction::Deny);
    }

    #[test]
    fn cidr_literal_in_dst_matches_address_inside() {
        let doc = doc_with_rule(&["*"], &["10.0.0.0/8"]);
        let s = NodeView::new("100.64.0.1");
        let d_in = NodeView::new("10.5.5.5");
        let d_out = NodeView::new("8.8.8.8");
        assert_eq!(
            doc.evaluate_with(&s, &d_in, PortRef::any()),
            AclAction::Accept
        );
        assert_eq!(
            doc.evaluate_with(&s, &d_out, PortRef::any()),
            AclAction::Deny
        );
    }

    // --- NodeAttrs -------------------------------------------------

    #[test]
    fn attrs_for_collects_matching_grants() {
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.node_attrs.push(NodeAttrGrant {
            target: vec!["*".into()],
            attr: vec!["funnel".into()],
            ..Default::default()
        });
        doc.node_attrs.push(NodeAttrGrant {
            target: vec!["tag:exit".into()],
            attr: vec!["exit-node".into()],
            ..Default::default()
        });
        let exit_tags = vec!["exit".into()];
        let exit_node = NodeView::new("100.64.0.1").with_tags(&exit_tags);
        let plain = NodeView::new("100.64.0.2");
        assert_eq!(doc.attrs_for(&exit_node), vec!["exit-node", "funnel"]);
        assert_eq!(doc.attrs_for(&plain), vec!["funnel"]);
    }

    #[test]
    fn attrs_for_dedupes_repeated_capabilities() {
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.node_attrs.push(NodeAttrGrant {
            target: vec!["*".into()],
            attr: vec!["ssh".into()],
            ..Default::default()
        });
        doc.node_attrs.push(NodeAttrGrant {
            target: vec!["autogroup:member".into()],
            attr: vec!["ssh".into(), "funnel".into()],
            ..Default::default()
        });
        let n = NodeView::new("100.64.0.1");
        let out = doc.attrs_for(&n);
        assert_eq!(out, vec!["funnel", "ssh"]);
    }

    #[test]
    fn attrs_for_empty_when_no_grant_matches() {
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.node_attrs.push(NodeAttrGrant {
            target: vec!["tag:exit".into()],
            attr: vec!["exit-node".into()],
            ..Default::default()
        });
        let n = NodeView::new("100.64.0.1");
        assert!(doc.attrs_for(&n).is_empty());
    }

    #[test]
    fn attrs_for_user_target() {
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.node_attrs.push(NodeAttrGrant {
            target: vec!["alice".into()],
            attr: vec!["funnel".into()],
            ..Default::default()
        });
        let alice = NodeView::new("100.64.0.1").with_user("alice");
        let bob = NodeView::new("100.64.0.2").with_user("bob");
        assert_eq!(doc.attrs_for(&alice), vec!["funnel"]);
        assert!(doc.attrs_for(&bob).is_empty());
    }

    #[test]
    fn attrs_for_randomize_client_port_applies_to_every_node() {
        let doc = AclDoc {
            version: 1,
            randomize_client_port: true,
            ..Default::default()
        };

        let tagged = vec!["tag:server".into()];
        let user_node = NodeView::new("100.64.0.1").with_user("alice@example.com");
        let tagged_node = NodeView::new("100.64.0.2").with_tags(&tagged);

        assert_eq!(doc.attrs_for(&user_node), vec!["randomize-client-port"]);
        assert_eq!(doc.attrs_for(&tagged_node), vec!["randomize-client-port"]);
    }

    #[test]
    fn attrs_for_randomize_client_port_merges_with_node_attrs() {
        let mut doc = AclDoc {
            version: 1,
            randomize_client_port: true,
            ..Default::default()
        };
        doc.node_attrs.push(NodeAttrGrant {
            target: vec!["tag:server".into()],
            attr: vec![
                "randomize-client-port".into(),
                "disable-captive-portal-detection".into(),
            ],
            ..Default::default()
        });

        let tags = vec!["tag:server".into()];
        let node = NodeView::new("100.64.0.1").with_tags(&tags);

        assert_eq!(
            doc.attrs_for(&node),
            vec!["disable-captive-portal-detection", "randomize-client-port"]
        );
    }

    // --- autoApprovers ---------------------------------------------

    #[test]
    fn auto_approve_route_matches_exact_prefix() {
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.auto_approvers
            .routes
            .insert("10.0.0.0/8".into(), vec!["tag:router".into()]);
        let tags = vec!["router".into()];
        let router = NodeView::new("100.64.0.1").with_tags(&tags);
        let plain = NodeView::new("100.64.0.2");
        assert!(doc.auto_approves_route(&router, "10.0.0.0/8"));
        assert!(!doc.auto_approves_route(&plain, "10.0.0.0/8"));
    }

    #[test]
    fn auto_approve_route_accepts_prefixed_node_tags() {
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.auto_approvers
            .routes
            .insert("10.0.0.0/8".into(), vec!["tag:router".into()]);
        let tags = vec!["tag:router".into()];
        let router = NodeView::new("100.64.0.1").with_tags(&tags);
        assert!(doc.auto_approves_route(&router, "10.0.0.0/8"));
    }

    #[test]
    fn auto_approve_route_rejects_default_route_without_exit_node() {
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.groups.insert("admins".into(), vec!["alice@".into()]);
        doc.auto_approvers
            .routes
            .insert("0.0.0.0/0".into(), vec!["group:admins".into()]);
        doc.auto_approvers
            .routes
            .insert("::/0".into(), vec!["group:admins".into()]);
        let alice = NodeView::new("100.64.0.1").with_user("alice");
        assert!(!doc.auto_approves_route(&alice, "0.0.0.0/0"));
        assert!(!doc.auto_approves_route(&alice, "::/0"));
    }

    #[test]
    fn auto_approve_route_matches_subprefix() {
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.auto_approvers
            .routes
            .insert("10.0.0.0/8".into(), vec!["tag:router".into()]);
        let tags = vec!["router".into()];
        let router = NodeView::new("100.64.0.1").with_tags(&tags);
        assert!(doc.auto_approves_route(&router, "10.5.0.0/16"));
    }

    #[test]
    fn auto_approve_route_rejects_superprefix() {
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.auto_approvers
            .routes
            .insert("10.0.0.0/8".into(), vec!["tag:router".into()]);
        let tags = vec!["router".into()];
        let router = NodeView::new("100.64.0.1").with_tags(&tags);
        assert!(!doc.auto_approves_route(&router, "10.0.0.0/4"));
    }

    #[test]
    fn auto_approve_route_rejects_outside_prefix() {
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.auto_approvers
            .routes
            .insert("10.0.0.0/8".into(), vec!["tag:router".into()]);
        let tags = vec!["router".into()];
        let router = NodeView::new("100.64.0.1").with_tags(&tags);
        assert!(!doc.auto_approves_route(&router, "8.8.8.0/24"));
    }

    #[test]
    fn auto_approve_route_via_group_member() {
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.groups
            .insert("admins".into(), vec!["alice".into(), "bob".into()]);
        doc.auto_approvers
            .routes
            .insert("172.16.0.0/12".into(), vec!["group:admins".into()]);
        let alice = NodeView::new("100.64.0.1").with_user("alice");
        let carol = NodeView::new("100.64.0.2").with_user("carol");
        assert!(doc.auto_approves_route(&alice, "172.16.0.0/16"));
        assert!(!doc.auto_approves_route(&carol, "172.16.0.0/16"));
    }

    #[test]
    fn auto_approve_route_matches_legacy_user_suffix() {
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.groups.insert("admins".into(), vec!["alice@".into()]);
        doc.auto_approvers
            .routes
            .insert("172.16.0.0/12".into(), vec!["group:admins".into()]);
        let alice = NodeView::new("100.64.0.1").with_user("alice");
        assert!(doc.auto_approves_route(&alice, "172.16.0.0/16"));
    }

    #[test]
    fn auto_approve_exit_node_matches_prefixed_group_key() {
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.groups
            .insert("group:admins".into(), vec!["alice@".into()]);
        doc.auto_approvers.exit_node = vec!["group:admins".into()];
        let alice = NodeView::new("100.64.0.1").with_user("alice");
        assert!(doc.auto_approves_exit_node(&alice));
    }

    #[test]
    fn auto_approve_exit_node_matches_tag() {
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.auto_approvers.exit_node.push("tag:exit".into());
        let exit_tags = vec!["exit".into()];
        let exit = NodeView::new("100.64.0.1").with_tags(&exit_tags);
        let plain = NodeView::new("100.64.0.2");
        assert!(doc.auto_approves_exit_node(&exit));
        assert!(!doc.auto_approves_exit_node(&plain));
    }

    #[test]
    fn auto_approve_exit_node_empty_list_is_no() {
        let doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        let n = NodeView::new("100.64.0.1");
        assert!(!doc.auto_approves_exit_node(&n));
    }

    // --- TOML round-trip --------------------------------------------

    #[test]
    fn parses_node_attrs_from_toml() {
        let doc = AclDoc::from_toml(
            r#"
            version = 1
            [tag_owners]
            "tag:exit" = ["alice@"]

            [[node_attrs]]
            target = ["*"]
            attr = ["funnel"]

            [[node_attrs]]
            target = ["tag:exit"]
            attr = ["exit-node"]
        "#,
        )
        .unwrap();
        assert_eq!(doc.node_attrs.len(), 2);
        assert_eq!(doc.node_attrs[0].attr, vec!["funnel"]);
        assert_eq!(doc.node_attrs[1].target, vec!["tag:exit"]);
    }

    #[test]
    fn parses_randomize_client_port_from_toml() {
        let doc = AclDoc::from_toml(
            r"
            version = 1
            randomizeClientPort = true
        ",
        )
        .unwrap();
        assert!(doc.randomize_client_port);
        assert_eq!(
            doc.attrs_for(&NodeView::new("100.64.0.1")),
            vec!["randomize-client-port"]
        );
    }

    #[test]
    fn parses_auto_approvers_from_toml() {
        let doc = AclDoc::from_toml(
            r#"
            version = 1
            [groups]
            admins = ["alice@"]
            [auto_approvers]
            exit_node = ["tag:exit", "tag:router"]
            [auto_approvers.routes]
            "10.0.0.0/8" = ["tag:router"]
            "172.16.0.0/12" = ["group:admins"]
            [tag_owners]
            "tag:exit" = ["group:admins"]
            "tag:router" = ["group:admins"]
        "#,
        )
        .unwrap();
        assert_eq!(doc.auto_approvers.exit_node.len(), 2);
        assert_eq!(doc.auto_approvers.routes.len(), 2);
        assert!(doc.auto_approvers.routes.contains_key("10.0.0.0/8"));
    }

    #[test]
    fn parses_hosts_from_toml() {
        let doc = AclDoc::from_toml(
            r#"
            version = 1
            [hosts]
            office = "10.0.0.0/8"
        "#,
        )
        .unwrap();
        assert_eq!(doc.hosts["office"], "10.0.0.0/8");
    }

    #[test]
    fn parses_tag_owners_from_toml() {
        let doc = AclDoc::from_toml(
            r#"
            version = 1
            [groups]
            admins = ["alice@"]
            [tag_owners]
            "tag:router" = ["group:admins"]
        "#,
        )
        .unwrap();
        assert_eq!(doc.tag_owners["tag:router"], vec!["group:admins"]);
    }

    #[test]
    fn parses_ssh_block_from_toml() {
        let doc = AclDoc::from_toml(
            r#"
            version = 1
            [groups]
            admins = ["alice@"]
            [[ssh]]
            action = "accept"
            src = ["group:admins"]
            dst = ["autogroup:tagged"]
            users = ["root"]
        "#,
        )
        .unwrap();
        assert_eq!(doc.ssh.len(), 1);
        assert_eq!(doc.ssh[0].action, "accept");
        assert_eq!(doc.ssh[0].users, vec!["root"]);
    }

    #[test]
    fn ssh_source_rejects_circular_group_references() {
        let err = AclDoc::from_toml(
            r#"
              [groups]
              admins = ["group:ops"]
              ops = ["group:admins"]

              [[ssh]]
              action = "accept"
              src = ["group:admins"]
              dst = ["autogroup:tagged"]
              users = ["root"]
            "#,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains(
            "circular group reference detected in SSH source: group:admins -> group:ops"
        ));
    }

    #[test]
    fn hujson_rejects_nested_groups_like_headscale_go() {
        let err = parse_hujson_policy(
            r#"{
              "groups": {
                "group:admins": ["group:ops", "carol@"],
                "group:ops": ["alice@"]
              }
            }"#,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("Nested groups are not allowed"));
    }

    #[test]
    fn hujson_rejects_invalid_group_names_and_members_like_headscale_go() {
        for (name, raw, expected) in [
            (
                "short-group-name",
                r#"{"groups":{"admins":["alice@"]}}"#,
                "Group has to start",
            ),
            (
                "non-user-member",
                r#"{"groups":{"group:admins":["100.64.0.1"]}}"#,
                "Username has to contain @",
            ),
        ] {
            let err = parse_hujson_policy(raw).expect_err(name).to_string();
            assert!(
                err.contains(expected),
                "{name} should contain {expected:?}, got: {err}"
            );
        }
    }

    #[test]
    fn rejects_invalid_ssh_action_like_headscale_go() {
        let err = parse_hujson_policy(
            r#"{
              "ssh": [{
                "action": "invalid",
                "src": ["alice@"],
                "dst": ["autogroup:self"],
                "users": ["root"]
              }]
            }"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("invalid SSH action"));
    }

    #[test]
    fn accepts_ssh_check_period_always_like_headscale_go() {
        parse_hujson_policy(
            r#"{
              "ssh": [{
                "action": "check",
                "checkPeriod": "always",
                "src": ["alice@"],
                "dst": ["autogroup:self"],
                "users": ["root"]
              }]
            }"#,
        )
        .unwrap();
    }

    #[test]
    fn rejects_ssh_check_period_above_max_like_headscale_go() {
        let err = parse_hujson_policy(
            r#"{
              "ssh": [{
                "action": "check",
                "checkPeriod": "169h",
                "src": ["alice@"],
                "dst": ["autogroup:self"],
                "users": ["root"]
              }]
            }"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("above the max (168h)"));
    }

    #[test]
    fn rejects_ssh_check_period_on_accept_like_headscale_go() {
        let err = parse_hujson_policy(
            r#"{
              "ssh": [{
                "action": "accept",
                "checkPeriod": "12h",
                "src": ["alice@"],
                "dst": ["autogroup:self"],
                "users": ["root"]
              }]
            }"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("checkPeriod is only valid with action"));
    }

    #[test]
    fn parses_ssh_accept_env_like_headscale_go() {
        let doc = parse_hujson_policy(
            r#"{
              "ssh": [{
                "action": "accept",
                "acceptEnv": ["LANG", "LC_*", "*", "**"],
                "src": ["alice@"],
                "dst": ["autogroup:self"],
                "users": ["root"]
              }]
            }"#,
        )
        .unwrap();
        assert_eq!(doc.ssh[0].accept_env, vec!["LANG", "LC_*", "*", "**"]);
    }

    #[test]
    fn rejects_empty_ssh_accept_env_like_headscale_go() {
        let err = parse_hujson_policy(
            r#"{
              "ssh": [{
                "action": "accept",
                "acceptEnv": [""],
                "src": ["alice@"],
                "dst": ["autogroup:self"],
                "users": ["root"]
              }]
            }"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("acceptEnv values cannot be empty"));
    }

    #[test]
    fn rejects_missing_or_wildcard_ssh_users_like_headscale_go() {
        let missing = parse_hujson_policy(
            r#"{
              "ssh": [{
                "action": "accept",
                "src": ["alice@"],
                "dst": ["autogroup:self"]
              }]
            }"#,
        )
        .unwrap_err()
        .to_string();
        assert!(missing.contains("users must be specified"));

        let wildcard = parse_hujson_policy(
            r#"{
              "ssh": [{
                "action": "accept",
                "src": ["alice@"],
                "dst": ["autogroup:self"],
                "users": ["*"]
              }]
            }"#,
        )
        .unwrap_err()
        .to_string();
        assert!(wildcard.contains(r#"user "*" is not a valid SSH user"#));
    }

    #[test]
    fn rejects_acl_autogroup_internet_source_like_headscale_go() {
        let err = parse_hujson_policy(
            r#"{
              "acls": [{
                "action": "accept",
                "src": ["autogroup:internet"],
                "dst": ["10.0.0.1:*"]
              }]
            }"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains(r#""autogroup:internet" used in source"#));
    }

    #[test]
    fn rejects_acl_autogroup_self_source_like_headscale_go() {
        let err = parse_hujson_policy(
            r#"{
              "acls": [{
                "action": "accept",
                "src": ["autogroup:self"],
                "dst": ["10.0.0.1:*"]
              }]
            }"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains(r#""autogroup:self" used in source"#));
    }

    #[test]
    fn rejects_ssh_wildcard_destination_like_headscale_go() {
        let err = parse_hujson_policy(
            r#"{
              "ssh": [{
                "action": "accept",
                "src": ["alice@"],
                "dst": ["*"],
                "users": ["root"]
              }]
            }"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("wildcard (*) is not supported as SSH destination"));
    }

    #[test]
    fn rejects_ssh_host_destination_like_current_head() {
        let err = parse_hujson_policy(
            r#"{
              "hosts": {"server": "100.64.0.4/32"},
              "ssh": [{
                "action": "accept",
                "src": ["alice@"],
                "dst": ["server"],
                "users": ["root"]
              }]
            }"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains(r#"invalid dst "server""#));

        let err = parse_hujson_policy(
            r#"{
              "hosts": {"server": "100.64.0.4/32"},
              "ssh": [{
                "action": "accept",
                "src": ["alice@"],
                "dst": ["host:server"],
                "users": ["root"]
              }]
            }"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains(r#"invalid dst "host:server""#));
    }

    #[test]
    fn rejects_tagged_ssh_sources_to_user_destinations_like_headscale_go() {
        let err = parse_hujson_policy(
            r#"{
              "tagOwners": {"tag:client": ["alice@"]},
              "ssh": [{
                "action": "accept",
                "src": ["tag:client"],
                "dst": ["alice@"],
                "users": ["root"]
              }]
            }"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("tags in SSH source cannot access user-owned devices"));
    }

    #[test]
    fn accepts_ssh_localpart_like_user_literals_like_headscale_go() {
        parse_hujson_policy(
            r#"{
              "tagOwners": {"tag:server": ["alice@example.com"]},
              "ssh": [{
                "action": "accept",
                "src": ["autogroup:member"],
                "dst": ["tag:server"],
                "users": ["localpart:*@example.com", "localpart:alice@example.com", "localpart:*@"]
              }]
            }"#,
        )
        .unwrap();
    }

    #[test]
    fn hujson_rejects_non_upstream_top_level_fields_like_headscale_go() {
        for (field, raw) in [
            ("version", r#"{"version":1,"acls":[]}"#),
            ("rules", r#"{"rules":[]}"#),
        ] {
            let err = parse_hujson_policy(raw).expect_err(field);
            let msg = err.to_string();
            assert!(
                msg.contains(field) && msg.contains("unknown field"),
                "{field} should be rejected as unknown, got: {msg}"
            );
        }
    }

    #[test]
    fn hujson_rejects_acl_deny_action_like_headscale_go() {
        let err = parse_hujson_policy(
            r#"{
              "acls": [{
                "action": "deny",
                "src": ["*"],
                "dst": ["*:*"]
              }]
            }"#,
        )
        .expect_err("deny action must reject")
        .to_string();
        assert!(err.contains("invalid action"));
        assert!(err.contains("accept"));
    }

    #[test]
    fn hujson_rejects_acl_ports_field_like_headscale_go() {
        let err = parse_hujson_policy(
            r#"{
              "acls": [{
                "action": "accept",
                "src": ["*"],
                "dst": ["*"],
                "ports": ["*/*"]
              }]
            }"#,
        )
        .expect_err("rule-level ports field must reject")
        .to_string();
        assert!(
            err.contains("ports") && err.contains("unknown field"),
            "ports should be rejected as unknown, got: {err}"
        );
    }

    #[test]
    fn hujson_accepts_randomize_client_port_like_upstream_main() {
        let doc = parse_hujson_policy(
            r#"{
              "randomizeClientPort": true,
              "tagOwners": {"tag:server": ["alice@example.com"]},
              "acls": []
            }"#,
        )
        .unwrap();

        assert!(doc.randomize_client_port);
        assert_eq!(
            doc.attrs_for(&NodeView::new("100.64.0.1")),
            vec!["randomize-client-port"]
        );
    }

    #[test]
    fn hujson_acl_and_grant_network_rules_are_equivalent() {
        let acl_doc = parse_hujson_policy(
            r#"{
              "groups": {"group:eng": ["alice@example.com"]},
              "tagOwners": {"tag:web": ["group:eng"]},
              "acls": [{
                "action": "accept",
                "proto": "tcp",
                "src": ["group:eng"],
                "dst": ["tag:web:443"]
              }]
            }"#,
        )
        .unwrap();
        let grant_doc = parse_hujson_policy(
            r#"{
              "groups": {"group:eng": ["alice@example.com"]},
              "tagOwners": {"tag:web": ["group:eng"]},
              "grants": [{
                "src": ["group:eng"],
                "dst": ["tag:web"],
                "ip": ["tcp:443"]
              }]
            }"#,
        )
        .unwrap();

        assert_eq!(acl_doc.rules, grant_doc.rules);
        assert_eq!(grant_doc.grants.len(), 1);
    }

    #[test]
    fn hujson_grants_with_via_are_not_flattened_into_acl_rules() {
        let doc = parse_hujson_policy(
            r#"{
              "tagOwners": {
                "tag:client": ["alice@"],
                "tag:router-a": ["router@"],
                "tag:router-b": ["router@"]
              },
              "grants": [{
                "src": ["tag:client"],
                "dst": ["10.0.0.0/24"],
                "ip": ["*"],
                "via": ["tag:router-a"]
              }]
            }"#,
        )
        .unwrap();

        assert!(
            doc.rules.is_empty(),
            "via grants need grant-aware route checks, not flattened ACL rules"
        );

        let client_tags = vec!["tag:client".to_string()];
        let router_a_tags = vec!["tag:router-a".to_string()];
        let router_b_tags = vec!["tag:router-b".to_string()];
        let client = NodeView::new("100.64.0.10").with_tags(&client_tags);
        let router_a = NodeView::new("100.64.0.1").with_tags(&router_a_tags);
        let router_b = NodeView::new("100.64.0.2").with_tags(&router_b_tags);
        let routes = vec!["10.0.0.0/24".to_string()];

        assert!(doc.can_access_node(&client, &router_a, &routes, PortRef::any()));
        assert!(!doc.can_access_node(&client, &router_b, &routes, PortRef::any()));
    }

    #[test]
    fn hujson_rejects_public_ipsets_like_headscale_go() {
        let err = parse_hujson_policy(
            r#"{
              "ipsets": {"office": ["10.0.0.0/8", "192.168.0.0/16"]},
              "acls": []
            }"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains(r#"unknown field "ipsets""#));
    }

    #[test]
    fn rejects_ipset_aliases_like_headscale_go() {
        let err = parse_hujson_policy(
            r#"{
              "acls": [{
                "action": "accept",
                "src": ["*"],
                "dst": ["ipset:office:*"]
              }]
            }"#,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("ipset:office"),
            "ipset alias should be rejected, got: {err}"
        );
    }

    #[test]
    fn hujson_accepts_public_node_attrs_app_maps() {
        let doc = parse_hujson_policy(
            r#"{
              "hosts": {"office": "10.0.0.0/8"},
              "nodeAttrs": [{
                "target": ["*"],
                "attr": ["randomize-client-port"],
                "app": {
                  "example.com/cap/connector": [{"name": "prod"}]
                },
                "ipPool": ["100.81.0.0/16"]
              }],
              "grants": [{
                "src": ["*"],
                "dst": ["office"],
                "ip": ["udp:53"]
              }]
            }"#,
        )
        .unwrap();

        assert_eq!(doc.node_attrs[0].attr, vec!["randomize-client-port"]);
        assert_eq!(
            doc.node_attrs[0].app["example.com/cap/connector"][0]["name"],
            "prod"
        );
        assert_eq!(doc.node_attrs[0].ip_pool, vec!["100.81.0.0/16"]);
        assert_eq!(doc.rules[0].dst, vec!["office"]);
        assert_eq!(doc.rules[0].ports, vec!["udp/53"]);
    }

    #[test]
    fn hujson_rejects_invalid_grant_app_cap_and_via() {
        for (name, raw, want) in [
            (
                "missing-ip-and-app",
                r#"{"grants":[{"src":["*"],"dst":["*"]}]}"#,
                "ip and app can not both be empty",
            ),
            (
                "app-to-internet",
                r#"{"grants":[{"src":["*"],"dst":["autogroup:internet"],"app":{"example.com/cap/use":[]}}]}"#,
                "cannot use app grants with autogroup:internet",
            ),
            (
                "bad-cap-url",
                r#"{"grants":[{"src":["*"],"dst":["*"],"app":{"https://example.com/cap/use":[]}}]}"#,
                "capability name must have the form",
            ),
            (
                "bad-tailscale-cap",
                r#"{"grants":[{"src":["*"],"dst":["*"],"app":{"tailscale.com/cap/funnel":[]}}]}"#,
                "capability name must not be in the tailscale.com domain",
            ),
            (
                "via-not-tag",
                r#"{"grants":[{"src":["*"],"dst":["*"],"ip":["*"],"via":["group:routers"]}]}"#,
                "via can only be a tag",
            ),
            (
                "via-undefined-tag",
                r#"{"grants":[{"src":["*"],"dst":["*"],"ip":["*"],"via":["tag:router"]}]}"#,
                "tag \"tag:router\" not found",
            ),
        ] {
            let err = parse_hujson_policy(raw).expect_err(name).to_string();
            assert!(
                err.contains(want),
                "{name} should contain {want:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn hujson_nil_acl_and_grants_default_deny() {
        for raw in ["{}", r#"{"acls":[]}"#, r#"{"grants":[]}"#] {
            let doc = parse_hujson_policy(raw).unwrap();
            assert!(doc.rules.is_empty());
            assert!(doc.grants.is_empty());
            assert_eq!(
                doc.decide("100.64.0.1", "100.64.0.2", PortRef::any()),
                AclAction::Deny
            );
        }
    }

    #[test]
    fn canonical_form_includes_new_fields() {
        let mut a = AclDoc {
            version: 1,
            ..Default::default()
        };
        a.auto_approvers
            .routes
            .insert("10.0.0.0/8".into(), vec!["tag:b".into(), "tag:a".into()]);
        let mut b = AclDoc {
            version: 1,
            ..Default::default()
        };
        b.auto_approvers
            .routes
            .insert("10.0.0.0/8".into(), vec!["tag:a".into(), "tag:b".into()]);
        assert_eq!(a.policy_hash(), b.policy_hash());
    }

    #[test]
    fn camelcase_alias_for_auto_approvers_accepted() {
        let doc = AclDoc::from_toml(
            r#"
            version = 1
            [tagOwners]
            "tag:exit" = ["alice@"]
            [autoApprovers]
            exitNode = ["tag:exit"]
            "#,
        )
        .unwrap();
        assert_eq!(doc.auto_approvers.exit_node, vec!["tag:exit"]);
    }

    #[test]
    fn camelcase_alias_for_node_attrs_accepted() {
        let doc = AclDoc::from_toml(
            r#"
            version = 1
            [[nodeAttrs]]
            target = ["*"]
            attr = ["funnel"]
            "#,
        )
        .unwrap();
        assert_eq!(doc.node_attrs.len(), 1);
    }

    // --- NodeView rule semantics -----------------------------------

    #[test]
    fn evaluate_with_user_principal_match() {
        let doc = doc_with_rule(&["alice"], &["*"]);
        let alice = NodeView {
            addr: None,
            user: Some("alice"),
            tags: &[],
        };
        let bob = NodeView {
            addr: None,
            user: Some("bob"),
            tags: &[],
        };
        let dst = NodeView::new("100.64.0.5");
        assert_eq!(
            doc.evaluate_with(&alice, &dst, PortRef::any()),
            AclAction::Accept
        );
        assert_eq!(
            doc.evaluate_with(&bob, &dst, PortRef::any()),
            AclAction::Deny
        );
    }

    #[test]
    fn evaluate_with_group_referring_to_user_matches() {
        let mut doc = doc_with_rule(&["group:admins"], &["*"]);
        doc.groups.insert("admins".into(), vec!["alice".into()]);
        let alice = NodeView {
            addr: None,
            user: Some("alice"),
            tags: &[],
        };
        let dst = NodeView::new("100.64.0.5");
        assert_eq!(
            doc.evaluate_with(&alice, &dst, PortRef::any()),
            AclAction::Accept
        );
    }

    #[test]
    fn tagged_node_does_not_match_user_or_group_identity() {
        let mut doc = doc_with_rule(&["group:admins"], &["*"]);
        doc.groups.insert("admins".into(), vec!["alice".into()]);
        let tags = vec!["tag:router".to_string()];
        let tagged = NodeView {
            addr: None,
            user: Some("alice"),
            tags: &tags,
        };
        let dst = NodeView::new("100.64.0.5");
        assert_eq!(
            doc.evaluate_with(&tagged, &dst, PortRef::any()),
            AclAction::Deny
        );

        let direct = doc_with_rule(&["alice"], &["*"]);
        assert_eq!(
            direct.evaluate_with(&tagged, &dst, PortRef::any()),
            AclAction::Deny
        );
    }

    #[test]
    fn parse_cidr_handles_bare_address() {
        let n = parse_cidr("10.0.0.5").unwrap();
        assert_eq!(n.prefix_len(), 32);
    }

    #[test]
    fn parse_cidr_handles_ipv6_bare_address() {
        let n = parse_cidr("::1").unwrap();
        assert_eq!(n.prefix_len(), 128);
    }

    #[test]
    fn parse_cidr_rejects_garbage() {
        assert!(parse_cidr("not-an-ip").is_none());
    }

    // --- hujson stripper -------------------------------------------

    #[test]
    fn hujson_parses_minimal_doc() {
        let raw = r#"{
            // tiny allow-all
            "acls": [
                {"action":"accept","src":["*"],"dst":["*:*"]},
            ]
        }"#;
        let doc = parse_hujson_policy(raw).unwrap();
        assert_eq!(doc.version, 1);
        assert_eq!(doc.rules.len(), 1);
    }

    #[test]
    fn hujson_rejects_unknown_field() {
        let raw = r#"{"policy_owner":"oct1","acls":[]}"#;
        let err = parse_hujson_policy(raw).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("policy_owner") || msg.contains("unknown field"),
            "error should name the field, got: {msg}"
        );
    }

    #[test]
    fn hujson_rejects_garbage() {
        assert!(parse_hujson_policy("not json {").is_err());
    }

    #[test]
    fn hujson_block_comments_and_trailing_commas() {
        let raw = r#"{
            /* block comment */
            "acls": [
                {"action":"accept","src":["*"],"dst":["*:*"],},
            ],
        }"#;
        let doc = parse_hujson_policy(raw).unwrap();
        assert_eq!(doc.rules.len(), 1);
    }

    #[test]
    fn hujson_strings_with_slashes_are_preserved() {
        let raw = r#"{
            "ssh": [{
                "action": "accept",
                "src": ["alice@"],
                "dst": ["autogroup:self"],
                "users": ["oct://node1//net"]
            }]
        }"#;
        let doc = parse_hujson_policy(raw).unwrap();
        assert_eq!(doc.ssh[0].users, vec!["oct://node1//net"]);
    }

    #[test]
    fn hujson_accepts_acls_alias() {
        let raw = r#"{
            "acls": [{"action":"accept","src":["*"],"dst":["*:*"]}]
        }"#;
        let doc = parse_hujson_policy(raw).unwrap();
        assert_eq!(doc.rules.len(), 1);
    }

    // --- expand_principal ------------------------------------------

    #[test]
    fn expand_principal_wildcard_returns_default_cidrs() {
        let d = AclDoc::empty();
        assert_eq!(d.expand_principal("*"), vec!["0.0.0.0/0", "::/0"]);
    }

    #[test]
    fn expand_principal_unknown_group_returns_empty_vec() {
        let d = AclDoc::empty();
        assert_eq!(d.expand_principal("group:nope"), Vec::<String>::new());
    }

    #[test]
    fn expand_principal_known_group_returns_members() {
        let mut d = AclDoc::empty();
        d.groups
            .insert("admins".to_string(), vec!["a".to_string(), "b".to_string()]);
        assert_eq!(d.expand_principal("group:admins"), vec!["a", "b"]);
    }

    #[test]
    fn expand_principal_prefixed_group_key_returns_members() {
        let mut d = AclDoc::empty();
        d.groups.insert(
            "group:admins".to_string(),
            vec!["a".to_string(), "b".to_string()],
        );
        assert_eq!(d.expand_principal("group:admins"), vec!["a", "b"]);
    }

    #[test]
    fn ssh_source_expansion_skips_circular_group_edges() {
        let mut d = AclDoc::empty();
        d.groups.insert(
            "admins".to_string(),
            vec!["group:ops".to_string(), "alice@".to_string()],
        );
        d.groups.insert(
            "ops".to_string(),
            vec!["group:admins".to_string(), "bob@".to_string()],
        );

        assert_eq!(d.expand_principal("group:admins"), vec!["bob@", "alice@"]);
    }

    #[test]
    fn expand_principal_bare_host_returns_cidr() {
        let mut d = AclDoc::empty();
        d.hosts
            .insert("server".to_string(), "100.64.0.2/32".to_string());
        assert_eq!(d.expand_principal("server"), vec!["100.64.0.2/32"]);
    }

    #[test]
    fn expand_principal_literal_returns_itself() {
        let d = AclDoc::empty();
        assert_eq!(d.expand_principal("oct1xyz"), vec!["oct1xyz"]);
    }

    #[test]
    fn node_can_have_tag_allows_direct_user_owner() {
        let mut d = AclDoc::empty();
        d.tag_owners
            .insert("tag:router".into(), vec!["alice@".into()]);
        let node = NodeView {
            addr: None,
            user: Some("alice"),
            tags: &[],
        };

        assert!(d.node_can_have_tag(&node, "tag:router"));
    }

    #[test]
    fn node_can_have_tag_allows_group_owner() {
        let mut d = AclDoc::empty();
        d.groups
            .insert("group:admins".into(), vec!["alice@".into()]);
        d.tag_owners
            .insert("tag:db".into(), vec!["group:admins".into()]);
        let node = NodeView {
            addr: None,
            user: Some("alice"),
            tags: &[],
        };

        assert!(d.node_can_have_tag(&node, "tag:db"));
    }

    #[test]
    fn node_can_have_tag_flattens_nested_tag_owners() {
        let mut d = AclDoc::empty();
        d.groups.insert("group:ops".into(), vec!["carol@".into()]);
        d.tag_owners
            .insert("tag:base".into(), vec!["alice@".into()]);
        d.tag_owners
            .insert("tag:derived".into(), vec!["tag:base".into()]);
        d.tag_owners
            .insert("tag:deep".into(), vec!["tag:derived".into()]);
        d.tag_owners.insert(
            "tag:mixed".into(),
            vec!["bob@".into(), "tag:derived".into(), "group:ops".into()],
        );

        let alice = NodeView {
            addr: None,
            user: Some("alice"),
            tags: &[],
        };
        let bob = NodeView {
            addr: None,
            user: Some("bob"),
            tags: &[],
        };
        let carol = NodeView {
            addr: None,
            user: Some("carol"),
            tags: &[],
        };
        let dave = NodeView {
            addr: None,
            user: Some("dave"),
            tags: &[],
        };

        assert!(d.node_can_have_tag(&alice, "tag:derived"));
        assert!(d.node_can_have_tag(&alice, "tag:deep"));
        assert!(d.node_can_have_tag(&alice, "tag:mixed"));
        assert!(d.node_can_have_tag(&bob, "tag:mixed"));
        assert!(d.node_can_have_tag(&carol, "tag:mixed"));
        assert!(!d.node_can_have_tag(&dave, "tag:derived"));
    }

    #[test]
    fn parsing_allows_tag_owner_cycles_and_runtime_denies_unbacked_cycle() {
        let doc = parse_hujson_policy(
            r#"{
              "tagOwners": {
                "tag:a": ["tag:b"],
                "tag:b": ["tag:a"]
              }
            }"#,
        )
        .unwrap();
        let node = NodeView {
            addr: None,
            user: Some("alice"),
            tags: &[],
        };

        assert!(!doc.node_can_have_tag(&node, "tag:a"));
    }

    #[test]
    fn parsing_rejects_undefined_nested_tag_owner() {
        let err = parse_hujson_policy(
            r#"{
              "tagOwners": {
                "tag:a": ["tag:missing"]
              }
            }"#,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains(r#"Tag "tag:missing" is not defined"#));
    }

    #[test]
    fn node_can_have_tag_denies_wrong_user_missing_policy_and_tag_owners() {
        let mut d = AclDoc::empty();
        d.tag_owners
            .insert("tag:router".into(), vec!["alice@".into()]);
        d.tag_owners
            .insert("tag:ops".into(), vec!["tag:router".into()]);
        let tags = vec!["tag:router".to_string()];
        let node = NodeView {
            addr: None,
            user: Some("bob"),
            tags: &tags,
        };

        assert!(!d.node_can_have_tag(&node, "tag:router"));
        assert!(!d.node_can_have_tag(&node, "tag:missing"));
        assert!(!d.node_can_have_tag(&node, "tag:ops"));
    }
}
