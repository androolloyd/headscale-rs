// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause

//! User aliases may name an OIDC provider identity, an email, or a login name.
//! Upstream permits a missing user but rejects an alias matching multiple rows.

use super::{PolicyDoc, PolicyRule};
use std::fmt::Write as _;

pub use headscale_api_acl::PolicyUser;

/// Mirror v0.29.5's policy-manager user-reference validation. Provider IDs take
/// precedence over email/name matches, including a CLI name equal to an OIDC ID.
pub fn validate_policy_user_references(
    doc: &PolicyDoc,
    users: &[PolicyUser],
) -> Result<(), String> {
    // This legacy entrypoint accepts the parser's public projection. Native
    // writes with raw source use the source-aware entrypoint below instead.
    let projected = doc
        .grants
        .iter()
        .filter(|grant| !grant.ip.is_empty() && grant.via.is_empty())
        .count();
    let aliases = acl_user_aliases(doc.rules.get(projected..).unwrap_or_default());
    validate_policy_user_references_with_acl_aliases(doc, users, &aliases)
}

/// Validate original source ACLs, without repeating sources for each expanded
/// destination or treating a guessed prefix of explicit typed ACLs as grants.
/// Source metadata is used only when its full rule/grant projection matches.
pub fn validate_policy_user_references_for_source(
    doc: &PolicyDoc,
    raw: &str,
    users: &[PolicyUser],
) -> Result<(), String> {
    let aliases = headscale_api_acl::go_policy_shape::original_acl_shape(raw, doc)
        .map_or_else(|| acl_user_aliases(&doc.rules), |shape| shape.user_aliases);
    validate_policy_user_references_with_acl_aliases(doc, users, &aliases)
}

pub(super) fn acl_user_aliases(rules: &[PolicyRule]) -> Vec<String> {
    rules
        .iter()
        .flat_map(|rule| rule.src.iter().chain(&rule.dst))
        .cloned()
        .collect()
}

pub(super) fn validate_policy_user_references_with_acl_aliases(
    doc: &PolicyDoc,
    users: &[PolicyUser],
    acl_aliases: &[String],
) -> Result<(), String> {
    let mut aliases = Vec::new();
    // Groups contain Username values; OwnerEnc/AutoApproverEnc choose users
    // before group/tag prefixes. General aliases first try a literal Prefix,
    // including scoped IPv6 whose zone may itself contain an @ character.
    aliases.extend(doc.groups.values().flatten().map(|alias| (alias, true)));
    aliases.extend(doc.tag_owners.values().flatten().map(|alias| (alias, true)));
    aliases.extend(
        doc.auto_approvers
            .routes
            .values()
            .flatten()
            .map(|alias| (alias, true)),
    );
    aliases.extend(
        doc.auto_approvers
            .exit_node
            .iter()
            .map(|alias| (alias, true)),
    );
    aliases.extend(acl_aliases.iter().map(|alias| (alias, false)));
    for rule in &doc.ssh {
        aliases.extend(rule.src.iter().map(|alias| (alias, false)));
        aliases.extend(rule.dst.iter().map(|alias| (alias, false)));
    }

    let errors = aliases
        .into_iter()
        .filter_map(|(alias, owner_or_username)| {
            let is_username = if owner_or_username {
                alias.contains('@')
            } else {
                headscale_api_acl::go_policy_shape::alias_kind(alias)
                    == Some(headscale_api_acl::go_policy_shape::AliasKind::Username)
            };
            if !is_username {
                return None;
            }
            let token = alias.strip_suffix('@').unwrap_or(alias);
            if users
                .iter()
                .any(|user| user.provider_identifier.as_deref() == Some(token))
            {
                return None;
            }
            let matches = users
                .iter()
                .filter(|user| user.email == token || user.name == token)
                .collect::<Vec<_>>();
            if matches.len() <= 1 {
                return None;
            }
            let mut found = String::new();
            for user in matches {
                let _ = write!(found, "{}: {}, ", user.id, user.name);
            }
            Some(format!(
                "multiple users found: token {} found: [ {found} ]",
                headscale_api_acl::go_strconv::quote(alias),
            ))
        })
        .collect::<Vec<_>>();
    match errors.len() {
        0 => Ok(()),
        1 => Err(errors.into_iter().next().unwrap()),
        _ => Err(format!("multiple errors:\n\t{}", errors.join("\n\t"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::parse_hujson_policy;

    #[test]
    fn duplicate_alias_is_rejected_but_missing_and_provider_id_aliases_are_allowed() {
        let mut users = vec![
            PolicyUser {
                id: 2,
                name: "yala".into(),
                email: String::new(),
                provider_identifier: None,
            },
            PolicyUser {
                id: 7,
                name: "yala".into(),
                email: "yala@yala.yala".into(),
                provider_identifier: Some("https://idp.test/subject".into()),
            },
        ];
        let doc = parse_hujson_policy(r#"{"groups":{"group:admins":["yala@"]},"acls":[{"action":"accept","src":["group:admins"],"dst":["*:*"]}]}"#).unwrap();
        assert_eq!(
            validate_policy_user_references(&doc, &users).unwrap_err(),
            "multiple users found: token \"yala@\" found: [ 2: yala, 7: yala,  ]"
        );
        assert!(validate_policy_user_references(&doc, &[]).is_ok());
        users[1].provider_identifier = Some("yala".into());
        assert!(validate_policy_user_references(&doc, &users).is_ok());
    }
}
