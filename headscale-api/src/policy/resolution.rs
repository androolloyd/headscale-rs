// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause

//! Alias.resolve can return both an IP set and an error. Consumers choose
//! whether to use that partial set; an empty non-nil set is not a nil result.

use std::{collections::BTreeSet, fmt::Write as _};

use super::{PacketFilterNode, PolicyDoc, filter};
use headscale_api_acl::{go_netip, go_policy_shape, go_strconv};

#[derive(Default)]
pub(super) struct ResolvedAlias {
    pub(super) ips: Option<Vec<String>>,
    pub(super) errors: Vec<String>,
}

impl ResolvedAlias {
    fn set(ips: Vec<String>) -> Self {
        Self {
            ips: Some(ips),
            errors: Vec::new(),
        }
    }

    fn failed(error: String) -> Self {
        Self {
            ips: None,
            errors: vec![error],
        }
    }

    pub(super) fn partial(self) -> Vec<String> {
        self.ips.unwrap_or_default()
    }

    pub(super) fn checked(self) -> Result<Vec<String>, String> {
        match self.errors.len() {
            0 => Ok(self.partial()),
            1 => Err(self.errors.into_iter().next().unwrap()),
            _ => Err(format!("multiple errors:\n\t{}", self.errors.join("\n\t"))),
        }
    }

    fn append(&mut self, other: Self) {
        self.ips
            .get_or_insert_with(Vec::new)
            .extend(other.ips.unwrap_or_default());
        self.errors.extend(other.errors);
    }
}

fn node_addresses<'a>(nodes: impl Iterator<Item = &'a PacketFilterNode>) -> ResolvedAlias {
    let mut result = ResolvedAlias::set(Vec::new());
    for node in nodes {
        for address in &node.addrs {
            match go_netip::parse_addr(address) {
                Ok((ip, _zone)) => {
                    // IPSetBuilder.Add strips zones while Contains rejects a
                    // zoned query. Address family (including mapped v6) stays.
                    let bits = if ip.is_ipv4() { 32 } else { 128 };
                    result.ips.as_mut().unwrap().push(format!("{ip}/{bits}"));
                }
                Err(_) => result.errors.push("Add(IP{})".into()),
            }
        }
    }
    result
}

pub(super) fn aliases(
    doc: &PolicyDoc,
    aliases: &[String],
    nodes: &[PacketFilterNode],
) -> ResolvedAlias {
    let mut result = ResolvedAlias::set(Vec::new());
    for token in aliases {
        result.append(alias(doc, token, nodes));
    }
    result
}

// Owners and auto-approvers use their own decoder: Username wins over
// group/tag prefixes and whitespace is retained. Group values are Usernames.
pub(super) fn owners(
    doc: &PolicyDoc,
    aliases: &[String],
    nodes: &[PacketFilterNode],
) -> ResolvedAlias {
    let mut result = ResolvedAlias::set(Vec::new());
    for token in aliases {
        result.append(if token.contains('@') {
            username(doc, token, nodes)
        } else {
            alias(doc, token, nodes)
        });
    }
    result
}

fn username(doc: &PolicyDoc, token: &str, nodes: &[PacketFilterNode]) -> ResolvedAlias {
    let Some(users) = doc.users.as_ref() else {
        return node_addresses(nodes.iter().filter(|node| {
            node.tags.is_empty() && doc.user_matches(token, node.user_id, node.user.as_deref())
        }));
    };
    let name = token.strip_suffix('@').unwrap_or(token);
    let provider = users
        .iter()
        .find(|user| user.provider_identifier.as_deref() == Some(name));
    let matches = users
        .iter()
        .filter(|user| user.email == name || user.name == name)
        .collect::<Vec<_>>();
    let (id, error) = if let Some(user) = provider {
        (user.id, None)
    } else if matches.len() == 1 {
        (matches[0].id, None)
    } else if matches.is_empty() {
        // Missing users are an empty usable set, so one absent group
        // member does not make that group fail.
        return ResolvedAlias::set(Vec::new());
    } else {
        let found = matches.iter().fold(String::new(), |mut found, user| {
            let _ = write!(found, "{}: {}, ", user.id, user.name);
            found
        });
        (
            0,
            Some(format!(
                "multiple users found: token {} found: [ {found} ]",
                go_strconv::quote(token)
            )),
        )
    };
    // Username.resolve continues with a zero User on an ambiguous alias.
    // A loaded association with ID zero can therefore supply a partial set.
    let mut result = node_addresses(
        nodes
            .iter()
            .filter(|node| node.tags.is_empty() && node.user_id == Some(id)),
    );
    if let Some(error) = error {
        result.errors.insert(0, error);
    }
    result
}

pub(super) fn alias(doc: &PolicyDoc, token: &str, nodes: &[PacketFilterNode]) -> ResolvedAlias {
    resolve(doc, token, nodes, &mut BTreeSet::new())
}

fn resolve(
    doc: &PolicyDoc,
    token: &str,
    nodes: &[PacketFilterNode],
    visiting: &mut BTreeSet<String>,
) -> ResolvedAlias {
    // parseAlias tries Prefix.parseString first, then Username before every
    // namespace prefix. A hosts entry cannot override a literal IP alias.
    if let Some(prefix) = go_policy_shape::alias_prefix(token) {
        return ResolvedAlias::set(filter::ipset_string_to_cidrs(&prefix));
    }
    if go_policy_shape::alias_kind(token) == Some(go_policy_shape::AliasKind::Username) {
        return username(doc, token, nodes);
    }
    match token {
        "*" => return ResolvedAlias::set(headscale_api_acl::tailnet_filter_srcs()),
        "autogroup:danger-all" => {
            return ResolvedAlias::set(vec!["0.0.0.0/0".into(), "::/0".into()]);
        }
        "autogroup:internet" => {
            return ResolvedAlias::set(headscale_api_acl::internet_filter_cidrs());
        }
        "autogroup:member" => {
            return node_addresses(nodes.iter().filter(|node| node.tags.is_empty()));
        }
        "autogroup:tagged" => {
            return node_addresses(nodes.iter().filter(|node| !node.tags.is_empty()));
        }
        "autogroup:self" => return ResolvedAlias::failed(
            "autogroup:self requires per-node resolution and cannot be resolved in this context"
                .into(),
        ),
        _ => {}
    }
    if token.starts_with("autogroup:") {
        return ResolvedAlias::failed(format!("unknown autogroup: {}", go_strconv::quote(token)));
    }
    if let Some(group) = token.strip_prefix("group:") {
        if !visiting.insert(token.to_owned()) {
            // Parsed Go policy forbids group recursion. Keep direct typed
            // embedding from recursing without a bound as well.
            return ResolvedAlias::failed("group members cannot be recursive".into());
        }
        let mut result = ResolvedAlias::set(Vec::new());
        if let Some(members) = doc.groups.get(token).or_else(|| doc.groups.get(group)) {
            for member in members {
                result.append(if member.contains('@') {
                    username(doc, member, nodes)
                } else {
                    resolve(doc, member, nodes, visiting)
                });
            }
        }
        visiting.remove(token);
        return result;
    }
    if token.starts_with("tag:") {
        return node_addresses(
            nodes
                .iter()
                .filter(|node| node.tags.iter().any(|tag| tag == token)),
        );
    }
    let host = token.strip_prefix("host:").unwrap_or(token);
    if let Some(prefix) = doc.hosts.get(host) {
        let ips = filter::ipset_string_to_cidrs(prefix);
        return if ips.is_empty() {
            ResolvedAlias::failed(format!("invalid prefix: {}", go_strconv::quote(prefix)))
        } else {
            ResolvedAlias::set(ips)
        };
    }
    let ips = filter::ipset_string_to_cidrs(token);
    if !ips.is_empty() {
        return ResolvedAlias::set(ips);
    }
    ResolvedAlias::failed(format!("error resolving host: {}", go_strconv::quote(host)))
}
