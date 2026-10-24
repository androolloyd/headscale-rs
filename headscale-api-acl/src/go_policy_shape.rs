// Copyright 2020 The Go Authors. All rights reserved.
// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause

//! Go policy source shapes and private compilation projections.

use std::collections::{BTreeMap, BTreeSet};

/// The result of policy/v2.parseAlias, before position-specific validation.
/// Parsing a literal address/prefix takes precedence over every string kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AliasKind {
    Prefix,
    Wildcard,
    Username,
    Group,
    Tag,
    AutoGroup,
    Host,
}

/// Prefix.parseString accepts a bare address (discarding its zone) or a
/// slash prefix (retaining host bits). Empty text is a Host, not a Prefix.
pub fn alias_prefix(value: &str) -> Option<String> {
    if value.contains('/') {
        crate::go_netip::parse_prefix_text(value).ok()
    } else {
        crate::go_netip::addr_host_prefix_text(value).filter(|prefix| !prefix.is_empty())
    }
}

/// Classify an already decoded alias without trimming it. AliasEnc trims at
/// its boundary; ACL AliasWithPorts passes its destination through unchanged.
pub fn alias_kind(value: &str) -> Option<AliasKind> {
    Some(if alias_prefix(value).is_some() {
        AliasKind::Prefix
    } else if value == "*" {
        AliasKind::Wildcard
    } else if value.contains('@') {
        AliasKind::Username
    } else if value.starts_with("group:") {
        AliasKind::Group
    } else if value.starts_with("tag:") {
        AliasKind::Tag
    } else if value.starts_with("autogroup:") {
        AliasKind::AutoGroup
    } else if !value.contains(':') {
        AliasKind::Host
    } else {
        return None;
    })
}

/// Preserve the typed Go alias's text when projecting into string fields.
pub fn canonical_alias(value: &str) -> Result<String, String> {
    if let Some(prefix) = alias_prefix(value) {
        return Ok(prefix);
    }
    if alias_kind(value).is_some() {
        Ok(value.to_owned())
    } else {
        Err(format!(
            "invalid alias format: {}",
            crate::go_strconv::quote(value),
        ))
    }
}

/// Typed AliasWithPorts used by policy tests after their extra JSON parse.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestDestination {
    pub alias: String,
    pub ports: Vec<(u16, u16)>,
}

/// policy/v2.parseDestinationAlias literally surrounds the already decoded
/// destination with quotes. Backslashes are therefore decoded once more;
/// embedded unescaped quotes/control bytes fail at that JSON boundary.
pub fn parse_test_destination(destination: &str) -> Result<TestDestination, String> {
    let quoted = format!("\"{destination}\"");
    let decoded: String = serde_json::from_str(&quoted).map_err(|error| error.to_string())?;
    if !decoded.contains(':') {
        return Err("hostport must contain a colon".to_owned());
    }
    let (alias, port) = crate::split_go_destination_and_port(&decoded)?;
    let ports = crate::parse_go_port_ranges(&port).map_err(|error| {
        format!(
            "dst={}: port range {}: {error}",
            crate::go_strconv::quote(&decoded),
            crate::go_strconv::quote(&port)
        )
    })?;
    crate::validate_go_acl_alias_syntax(&alias)?;
    Ok(TestDestination {
        alias: canonical_alias(&alias)?,
        ports,
    })
}

/// Container nilness retained beside the public Vec/BTreeMap projection.
/// Paths name typed fields/map entries, rather than JSON spelling or order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PolicyContainerShape {
    non_nil: BTreeSet<Vec<String>>,
}

type ContainerSchema = (
    &'static str,
    fn(&str) -> Option<&'static str>,
    &'static [&'static str],
    &'static [&'static str],
);

fn policy_fields(
    value: &serde_json::Value,
    name: fn(&str) -> Option<&'static str>,
) -> BTreeMap<&'static str, &serde_json::Value> {
    value
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(key, value)| name(key).map(|key| (key, value)))
        .collect()
}

fn container_fields(
    shape: &mut PolicyContainerShape,
    path: &[String],
    fields: &BTreeMap<&str, &serde_json::Value>,
    custom: &[&str],
    ordinary: &[&str],
) {
    for name in custom
        .iter()
        .filter(|name| fields.contains_key(**name))
        .chain(ordinary.iter().filter(|name| {
            fields
                .get(**name)
                .is_some_and(|value| value.is_array() || value.is_object())
        }))
    {
        let mut path = path.to_vec();
        path.push((*name).to_owned());
        shape.non_nil.insert(path);
    }
}

/// Capture Go nil/empty distinctions only for the complete matching native
/// projection. User-directory attachment is independent of the policy source.
/// This augments typed values and original ACL/app identities; it is not a
/// replacement for Go's full filterAndPolicy deephash.
pub fn policy_container_shape(raw: &str, supplied: &crate::AclDoc) -> Option<PolicyContainerShape> {
    let mut parsed = crate::parse_hujson_policy(raw).ok()?;
    let mut supplied = supplied.clone();
    parsed.users = None;
    supplied.users = None;
    if parsed != supplied {
        return None;
    }
    let prepared = crate::go_policy_json::prepare(raw).ok()?;
    let value = crate::go_json::value(&prepared).ok()?;
    let root = policy_fields(&value, crate::go_policy_field_name);
    let mut shape = PolicyContainerShape::default();
    // Groups and Hosts allocate maps even on explicit null. Ordinary Go
    // maps/slices remain nil on null and allocate on {} or [].
    container_fields(
        &mut shape,
        &[],
        &root,
        &["groups", "hosts"],
        &[
            "tagOwners",
            "acls",
            "grants",
            "nodeAttrs",
            "ssh",
            "tests",
            "sshTests",
        ],
    );
    let schemas: &[ContainerSchema] = &[
        ("acls", crate::go_acl_field_name, &["src"], &["dst"]),
        (
            "grants",
            crate::go_grant_field_name,
            &["src", "dst"],
            &["ip", "via", "app"],
        ),
        (
            "nodeAttrs",
            crate::go_node_attr_field_name,
            &["target"],
            &["attr", "ipPool"],
        ),
        (
            "ssh",
            crate::go_ssh_field_name,
            &["src", "dst"],
            &["users", "acceptEnv"],
        ),
        (
            "tests",
            crate::go_policy_test_field_name,
            &[],
            &["accept", "deny"],
        ),
        (
            "sshTests",
            crate::go_ssh_test_field_name,
            &["dst"],
            &["accept", "deny", "check"],
        ),
    ];
    for &(name, schema, custom, ordinary) in schemas {
        if let Some(entries) = root.get(name).and_then(|value| value.as_array()) {
            for (index, entry) in entries.iter().enumerate() {
                let path = vec![name.to_owned(), index.to_string()];
                let fields = policy_fields(entry, schema);
                container_fields(&mut shape, &path, &fields, custom, ordinary);
                if name == "grants"
                    && let Some(app) = fields.get("app").and_then(|value| value.as_object())
                {
                    for (capability, values) in app {
                        if values.is_array() {
                            let mut path = path.clone();
                            path.extend(["app".to_owned(), capability.clone()]);
                            shape.non_nil.insert(path);
                        }
                    }
                }
            }
        }
    }
    if let Some(approvers) = root.get("autoApprovers") {
        let fields = policy_fields(approvers, crate::go_auto_approvers_field_name);
        container_fields(
            &mut shape,
            &["autoApprovers".to_owned()],
            &fields,
            &["exitNode"],
            &["routes"],
        );
        if let Some(routes) = fields.get("routes").and_then(|value| value.as_object()) {
            for prefix in routes.keys() {
                // AutoApprovers.UnmarshalJSON always makes its result slice.
                shape.non_nil.insert(vec![
                    "autoApprovers".to_owned(),
                    "routes".to_owned(),
                    prefix.clone(),
                ]);
            }
        }
    }
    if let Some(owners) = root.get("tagOwners").and_then(|value| value.as_object()) {
        for tag in owners.keys() {
            // Owners.UnmarshalJSON likewise makes an empty slice for null.
            shape
                .non_nil
                .insert(vec!["tagOwners".to_owned(), tag.clone()]);
        }
    }
    // Groups builds each value by appending to a nil Usernames slice, so an
    // empty member list stays nil (unlike Owners/AutoApprovers/Aliases).
    if let Some(groups) = root.get("groups").and_then(|value| value.as_object()) {
        for (group, members) in groups {
            if members
                .as_array()
                .is_some_and(|members| !members.is_empty())
            {
                shape
                    .non_nil
                    .insert(vec!["groups".to_owned(), group.clone()]);
            }
        }
    }
    Some(shape)
}

/// JSON v2's case-insensitive key for the ASCII policy schema. Delimiters
/// are ignored; long-s and Kelvin are the Unicode folds entering ASCII.
pub fn folded_name(name: &str) -> String {
    name.chars()
        .filter(|ch| !matches!(ch, '-' | '_'))
        .map(|ch| match ch {
            '\u{017f}' => 's',
            '\u{212a}' => 'k',
            _ => ch.to_ascii_lowercase(),
        })
        .collect()
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GrantAppShape {
    pub non_nil: bool,
    pub nil_capabilities: BTreeSet<String>,
    /// Prepared raw payload values, retained independently of typed JSON values.
    pub raw_values: BTreeMap<String, Option<Vec<String>>>,
}

fn literal_app_sources(raw: &str) -> Vec<Option<String>> {
    use crate::go_json::{array, object};
    let standardized = crate::strip_hujson(raw);
    let Ok(fields) = object(standardized.as_bytes()) else {
        return Vec::new();
    };
    let Some((_, grants)) = fields.iter().find(|(key, _)| folded_name(key) == "grants") else {
        return Vec::new();
    };
    let Ok(grants) = array(grants.get()) else {
        return Vec::new();
    };
    grants
        .into_iter()
        .map(|grant| {
            object(grant.get()).ok().and_then(|fields| {
                fields
                    .into_iter()
                    .find(|(key, _)| key == "app")
                    .map(|(_, value)| {
                        String::from_utf8(value.get().to_vec()).expect("policy input is UTF-8")
                    })
            })
        })
        .collect()
}

/// Retain map nilness and nil capability values alongside a parsed policy.
/// Opaque capability payloads are never decoded or rewritten here.
pub fn grant_app_shapes(raw: &str) -> Vec<GrantAppShape> {
    use crate::go_json::{array, object, trim};

    let Ok(prepared) = crate::go_policy_json::prepare(raw) else {
        return Vec::new();
    };
    let Ok(fields) = object(&prepared) else {
        return Vec::new();
    };
    let Some((_, grants)) = fields
        .iter()
        .rev()
        .find(|(key, _)| folded_name(key) == "grants")
    else {
        return Vec::new();
    };
    let Ok(grants) = array(grants.get()) else {
        return Vec::new();
    };
    let literal_apps = literal_app_sources(raw);
    grants
        .into_iter()
        .enumerate()
        .map(|(index, grant)| {
            let mut shape = GrantAppShape::default();
            if let Ok(fields) = object(grant.get()) {
                for (name, app) in fields.iter().filter(|(key, _)| folded_name(key) == "app") {
                    if trim(app.get()) == b"null" {
                        shape = GrantAppShape::default();
                    } else if let Ok(capabilities) = object(if name == "app" {
                        literal_apps
                            .get(index)
                            .and_then(Option::as_deref)
                            .map_or(app.get(), str::as_bytes)
                    } else {
                        app.get()
                    }) {
                        shape.non_nil = true;
                        for (capability, value) in capabilities {
                            if trim(value.get()) == b"null" {
                                shape.nil_capabilities.insert(capability.clone());
                                shape.raw_values.insert(capability, None);
                            } else {
                                shape.nil_capabilities.remove(&capability);
                                if let Ok(values) = array(value.get()) {
                                    shape.raw_values.insert(
                                        capability,
                                        Some(
                                            values
                                                .into_iter()
                                                .map(|value| {
                                                    String::from_utf8(value.get().to_vec())
                                                        .expect("prepared policy is UTF-8")
                                                })
                                                .collect(),
                                        ),
                                    );
                                }
                            }
                        }
                    }
                }
            }
            shape
        })
        .collect()
}

/// Go's no-filter default distinguishes nil ACL/grant slices from [] even
/// though the public parsed document represents both with empty vectors.
pub fn packet_filter_default_allow(raw: &str) -> bool {
    use crate::go_json::{object, trim};
    let Ok(prepared) = crate::go_policy_json::prepare(raw) else {
        return false;
    };
    if trim(&prepared) == b"null" {
        return true;
    }
    let Ok(fields) = object(&prepared) else {
        return false;
    };
    !fields.iter().any(|(name, value)| {
        matches!(folded_name(name).as_str(), "acls" | "rules" | "grants")
            && trim(value.get()) != b"null"
    })
}

/// SSHRule.AcceptEnv participates in reflect.DeepEqual even when omitempty
/// suppresses both nil and []. Retain its shape beside the public Vec field.
pub fn ssh_accept_env_nil(raw: &str) -> Vec<bool> {
    use crate::go_json::{array, object, trim};
    let Ok(prepared) = crate::go_policy_json::prepare(raw) else {
        return Vec::new();
    };
    let Ok(fields) = object(&prepared) else {
        return Vec::new();
    };
    let Some((_, rules)) = fields
        .iter()
        .rev()
        .find(|(key, _)| folded_name(key) == "ssh")
    else {
        return Vec::new();
    };
    let Ok(rules) = array(rules.get()) else {
        return Vec::new();
    };
    rules
        .into_iter()
        .map(|rule| {
            object(rule.get())
                .ok()
                .and_then(|fields| {
                    fields
                        .into_iter()
                        .rev()
                        .find(|(key, _)| folded_name(key) == "acceptenv")
                        .map(|(_, value)| trim(value.get()) == b"null")
                })
                .unwrap_or(true)
        })
        .collect()
}

/// Recover the original ACL rows only when this source's full grant/rule
/// projection matches the supplied document. Programmatic documents can
/// otherwise treat all their explicit rules as ACLs without a guessed skip.
pub fn original_acl_rules(raw: &str, supplied: &crate::AclDoc) -> Option<Vec<crate::AclRule>> {
    original_acl_shape(raw, supplied).map(|shape| shape.rules)
}

/// Original ACL aliases preserve each source once per source ACL, before
/// destination splitting/reordering in the public packet-rule projection.
#[derive(Clone, Debug)]
pub struct OriginalAclShape {
    pub rules: Vec<crate::AclRule>,
    pub user_aliases: Vec<String>,
}

/// Recover ACL compilation rows and validation aliases only when this raw
/// source's complete grant/rule projection matches the supplied document.
pub fn original_acl_shape(raw: &str, supplied: &crate::AclDoc) -> Option<OriginalAclShape> {
    original_acl_details(raw, supplied).map(|(shape, _identity)| shape)
}

/// Original typed ACL structure lost when destinations become separate rows.
/// None preserves the nil ACL slice; Some([]) preserves an explicit empty one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalAclIdentity {
    pub entries: Option<Vec<OriginalAclEntry>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalAclEntry {
    /// Omitted Action is Go's empty string, independently of effective accept.
    pub action: String,
    pub protocol: String,
    pub sources: Option<Vec<String>>,
    /// Original destination order and each destination's own normalized ports.
    pub destinations: Option<Vec<(String, Vec<String>)>>,
}

/// Capture compilation, validation and original ACL identity in one source
/// pass. Cosmetic JSON differences and field-name aliases do not enter the
/// retained identity. As above, source grant/rule projection must match.
pub fn original_acl_details(
    raw: &str,
    supplied: &crate::AclDoc,
) -> Option<(OriginalAclShape, OriginalAclIdentity)> {
    let prepared = crate::go_policy_json::prepare(raw).ok()?;
    let mut value = crate::go_json::value(&prepared).ok()?;
    crate::strip_metadata_members(&mut value);
    let mut user_aliases = Vec::new();
    let mut entries = None;
    if let Some(acls) = value.as_object().and_then(|fields| {
        fields.iter().find_map(|(name, value)| {
            (crate::go_policy_field_name(name) == Some("acls")).then_some(value)
        })
    }) && !acls.is_null()
    {
        let mut original_entries = Vec::new();
        for acl in acls.as_array()? {
            let original_fields = match acl {
                serde_json::Value::Null => serde_json::Map::new(),
                serde_json::Value::Object(fields) => fields.clone(),
                _ => return None,
            };
            let present = |field| {
                original_fields
                    .iter()
                    .any(|(name, value)| folded_name(name) == field && !value.is_null())
            };
            // Aliases.UnmarshalJSON makes a non-nil empty slice even
            // for explicit null. Only an omitted Sources field is nil.
            let sources_present = original_fields
                .keys()
                .any(|name| folded_name(name) == "src");
            let destinations_present = present("dst");
            let acl = crate::normalize_go_policy_object_fields(
                acl.clone(),
                "acls",
                crate::go_acl_field_name,
                true,
            )
            .ok()?;
            let fields = acl.as_object()?;
            let action = original_fields
                .iter()
                .find_map(|(name, value)| (folded_name(name) == "action").then_some(value))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let protocol = fields
                .get("proto")
                .and_then(serde_json::Value::as_str)
                .map(crate::canonical_upstream_proto)
                .transpose()
                .ok()?
                .unwrap_or_default();
            let rule: crate::AclRule = serde_json::from_value(acl.clone()).ok()?;
            let mut destinations = Vec::new();
            if let Some(values) = fields.get("dst").and_then(serde_json::Value::as_array) {
                for destination in values {
                    let mut single = fields.clone();
                    single.insert(
                        "dst".into(),
                        serde_json::Value::Array(vec![destination.clone()]),
                    );
                    let destination: crate::AclRule =
                        serde_json::from_value(serde_json::Value::Object(single)).ok()?;
                    destinations.push((destination.dst.into_iter().next()?, destination.ports));
                }
            }
            user_aliases.extend(rule.src.iter().cloned());
            user_aliases.extend(rule.dst);
            original_entries.push(OriginalAclEntry {
                action,
                protocol,
                sources: sources_present.then_some(rule.src),
                destinations: destinations_present.then_some(destinations),
            });
        }
        entries = Some(original_entries);
    }
    let value = crate::normalize_go_policy_top_level(value).ok()?;
    let original = crate::deserialize_go_policy_value(value).ok()?;
    if original.grants != supplied.grants {
        return None;
    }
    let projected = crate::acl_rules_from_grants(&original.grants).ok()?;
    if !projected
        .iter()
        .chain(&original.rules)
        .eq(supplied.rules.iter())
    {
        return None;
    }
    Some((
        OriginalAclShape {
            rules: original.rules,
            user_aliases,
        },
        OriginalAclIdentity { entries },
    ))
}

/// Build the grant-prefix representation expected by the packet-filter
/// compiler from explicit ACL rows. Parsed documents already contain that
/// prefix; callers must recover their original rows before using this helper.
/// The supplied public document remains unchanged.
pub fn packet_filter_document(
    supplied: &crate::AclDoc,
    source_acl_rules: &[crate::AclRule],
) -> Result<crate::AclDoc, String> {
    let mut rules = crate::acl_rules_from_grants(&supplied.grants)?;
    rules.extend_from_slice(source_acl_rules);
    let mut compiled = supplied.clone();
    compiled.rules = rules;
    Ok(compiled)
}

/// ProtocolPort's normalized packet patterns, retaining literal protocol
/// validation and every parsed port range in source order.
pub fn grant_ip_patterns(spec: &str) -> Result<Vec<String>, String> {
    crate::normalize_grant_ip_spec(spec)
}
