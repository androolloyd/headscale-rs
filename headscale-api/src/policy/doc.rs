//! Serde mirror of `octravpn_mesh::acl::AclDoc`. Duplicated here on
//! purpose: `octravpn-mesh` already depends on `headscale-api`, so
//! a reverse dep would form a cycle. The on-wire shape is the
//! contract — we keep both definitions byte-compatible (see
//! `PolicyDoc::canonical_bytes` mirroring `AclDoc::canonical_bytes`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// `accept` vs `deny`. Matches `octravpn_mesh::acl::AclAction` byte for
/// byte on the wire.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    Accept,
    Deny,
}

/// One rule in the policy document. `src` / `dst` carry either an
/// explicit principal (`oct…` address), a group reference
/// (`group:<name>`), or the wildcard `*`. Ports follow the
/// `<proto>/<port>` form (`tcp/22`, `udp/*`, `*/*`). The legacy
/// `*:tcp/22` form is also accepted for backward compat with the
/// OctraVPN ACL parser.
///
/// `#[serde(deny_unknown_fields)]` matches the OctraVPN engine — a
/// misspelled rule field is a loud error, not a silently permissive
/// ACL.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub action: PolicyAction,
    pub src: Vec<String>,
    pub dst: Vec<String>,
    #[serde(default)]
    pub ports: Vec<String>,
}

/// Top-level policy document. `version = 1` matches the on-chain
/// `acl_policy` hash. Unknown fields reject — same as
/// `octravpn_mesh::acl::AclDoc`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDoc {
    pub version: u32,
    #[serde(default)]
    pub groups: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

impl PolicyDoc {
    /// Empty doc, version 1, no rules. The wire layer treats this as
    /// "default deny" — equivalent to no policy loaded for the
    /// fallback case, but distinguishable via `PolicyStore::is_loaded`.
    pub fn empty() -> Self {
        Self {
            version: 1,
            groups: BTreeMap::new(),
            tags: BTreeMap::new(),
            rules: Vec::new(),
        }
    }

    /// Expand a principal token (`*`, `group:foo`, `oct…`) into the
    /// concrete list of `SrcIPs` / dest spec strings the FilterRule
    /// matcher accepts.
    pub fn expand_principal(&self, token: &str) -> Vec<String> {
        if token == "*" {
            return vec!["*".to_string()];
        }
        if let Some(g) = token.strip_prefix("group:") {
            if let Some(members) = self.groups.get(g) {
                return members.clone();
            }
            // Unknown group reference: emit nothing rather than a
            // bogus literal. The default-deny path will catch the
            // intent — the operator gets a non-match instead of a
            // mis-match.
            return Vec::new();
        }
        vec![token.to_string()]
    }
}
